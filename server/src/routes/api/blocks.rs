//! Block-storage routes — `GET`/`PUT`/`DELETE /api/blocks/{id}` (Phase 4,
//! spec FR-016..018, contracts/http.md).
//!
//! ## Side-channel discipline (FR-019, FR-022, FR-023, FR-031, FR-016a)
//!
//! Every response is built by one of five constant constructors —
//! `respond_block_200`, `respond_block_204`, `respond_block_400`,
//! `respond_block_404`, `respond_block_503` — that emit exactly the
//! headers enumerated in `contracts/http.md`. The byte-identical-shape
//! invariants for 404 and 503 live in those constructors.
//!
//! ## Method-mismatch handling (FR-019, R7)
//!
//! All three routes register via `axum::routing::any(handler)` so axum
//! 0.8 suppresses the `Allow` header on method mismatch — the byte-
//! identical 404 contract requires that suppression. Each handler
//! dispatches on `method` internally and falls through to
//! `respond_block_404()` for any method other than its intended one.
//!
//! ## Storage access
//!
//! The `Arc<dyn StorageProvider>` is plumbed in via `Extension`,
//! mirroring how the vault guard injects `VaultSubjectExtension` and
//! the proxy-trust layer injects `EffectiveAddress`.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, Method, Request as HttpRequest, StatusCode, header};
use axum::response::Response;
use axum::routing::any;
use bytes::Bytes;

use crate::app::AppState;
use crate::auth::context::OidcContext;
use crate::auth::middleware::vault_guard;
use crate::auth::replay::JtiReplayStore;
use crate::auth::subject::VaultSubjectExtension;
use crate::logging::events::{
    BLOCK_ID_MALFORMED, emit_block_delete_backend_failed, emit_block_delete_ok,
    emit_block_get_backend_failed, emit_block_get_hit, emit_block_get_miss,
    emit_block_put_backend_failed, emit_block_put_ok,
};
use crate::proxy_trust::EffectiveAddress;
use crate::storage::{BlockId, StorageError, StorageProvider};

/// Planning-time `Retry-After` value emitted on the byte-identical 503
/// (spec FR-031, research.md R3, contracts/http.md §"503 ...").
const RETRY_AFTER_SECONDS: &str = "5";

/// Build the block-routes subtree (`/api/blocks/{id}`).
///
/// The storage `Arc` is layered as an `Extension` so the handlers can
/// extract it; the vault `AuthLayer` is layered AFTER the extension so
/// the auth pipeline runs first (auth failure → byte-identical 401
/// before any block-route logic executes). FR-020.
pub fn routes(
    vault_ctx: Arc<OidcContext>,
    replay_store: Arc<JtiReplayStore>,
    storage: Arc<dyn StorageProvider>,
) -> Router<AppState> {
    // Block routes accept GET / PUT / DELETE. Tell the guard to auth all
    // three (vs the Phase 3 whoami default of GET-only). Other methods
    // bypass auth and fall through to the in-handler 404 — preserving
    // the FR-030 leak-prevention pattern for POST / PATCH / etc.
    let guard = vault_guard(vault_ctx, replay_store).with_methods([
        Method::GET,
        Method::PUT,
        Method::DELETE,
    ]);
    Router::new()
        .route("/api/blocks/{id}", any(handle_block))
        .layer(guard)
        .layer(Extension(storage))
}

/// Single entry point for all three block routes. Dispatches on `method`
/// internally so the byte-identical 404 (FR-019) is the single fallthrough
/// for any unsupported method. Reading the body is deferred to the PUT
/// branch — GET and DELETE never touch `request.into_body()`.
async fn handle_block(
    Extension(storage): Extension<Arc<dyn StorageProvider>>,
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    request: HttpRequest<Body>,
) -> Response {
    let method = request.method().clone();
    let subject = subject_from_request(&request);
    let address = address_from_request(&request);

    // FR-014: validate block-ID format BEFORE any storage call.
    let id = match BlockId::parse(&id_str) {
        Some(id) => id,
        None => {
            // Malformed ID → byte-identical 404 (FR-022).
            // Log uses the malformed sentinel — the bytes themselves are
            // not echoed (FR-025).
            emit_block_get_miss(BLOCK_ID_MALFORMED, &subject, address);
            return respond_block_404();
        }
    };

    match method {
        Method::GET => handle_get(storage.as_ref(), &id, &subject, address).await,
        Method::PUT => {
            let block_size_bytes = state.config.block_size_bytes;
            handle_put(
                storage.as_ref(),
                &id,
                &subject,
                address,
                block_size_bytes,
                request,
            )
            .await
        }
        Method::DELETE => handle_delete(storage.as_ref(), &id, &subject, address).await,
        _ => {
            // Unsupported method → byte-identical 404 (FR-019).
            emit_block_get_miss(id.as_str(), &subject, address);
            respond_block_404()
        }
    }
}

async fn handle_get(
    storage: &dyn StorageProvider,
    id: &BlockId,
    subject: &str,
    address: std::net::IpAddr,
) -> Response {
    match storage.get(id).await {
        Ok(payload) => {
            emit_block_get_hit(id.as_str(), subject, address);
            respond_block_200(payload)
        }
        Err(StorageError::NotFound) => {
            emit_block_get_miss(id.as_str(), subject, address);
            respond_block_404()
        }
        Err(StorageError::Backend { cause, .. }) => {
            emit_block_get_backend_failed(id.as_str(), subject, address, cause.as_str());
            respond_block_503()
        }
    }
}

async fn handle_put(
    storage: &dyn StorageProvider,
    id: &BlockId,
    subject: &str,
    address: std::net::IpAddr,
    block_size_bytes: u64,
    request: HttpRequest<Body>,
) -> Response {
    // Two-layer FR-024 enforcement (research.md R9):
    //   (1) Pre-check `Content-Length` if present; reject 400 without
    //       consuming the body.
    //   (2) Cap the body read at `block_size_bytes + 1`; reject 400 if
    //       the actual length differs.
    if let Some(declared) = content_length(&request)
        && declared != block_size_bytes
    {
        return respond_block_400();
    }

    let limit = match block_size_bytes.checked_add(1) {
        Some(n) => n as usize,
        // Astronomically large `block_size_bytes` would overflow usize on
        // 32-bit. Treat as misconfiguration: reject the PUT. We do not
        // panic; the size check is at request scope.
        None => return respond_block_400(),
    };
    // `axum::body::to_bytes(body, limit)` errors out as soon as the body
    // exceeds `limit`. Combined with the post-collect exact-size check
    // below, this gives the FR-024 streaming-cap behaviour.
    let bytes = match to_bytes(request.into_body(), limit).await {
        Ok(b) => b,
        Err(_) => return respond_block_400(),
    };
    if bytes.len() as u64 != block_size_bytes {
        return respond_block_400();
    }

    match storage.put(id, bytes).await {
        Ok(()) => {
            emit_block_put_ok(id.as_str(), subject, address, block_size_bytes);
            respond_block_204()
        }
        Err(StorageError::Backend { cause, .. }) => {
            emit_block_put_backend_failed(id.as_str(), subject, address, cause.as_str());
            respond_block_503()
        }
        Err(StorageError::NotFound) => {
            // Production `put` never returns NotFound; defensive fallthrough
            // to 503 keeps the response shape predictable.
            respond_block_503()
        }
    }
}

async fn handle_delete(
    storage: &dyn StorageProvider,
    id: &BlockId,
    subject: &str,
    address: std::net::IpAddr,
) -> Response {
    match storage.delete(id).await {
        Ok(()) => {
            emit_block_delete_ok(id.as_str(), subject, address);
            respond_block_204()
        }
        Err(StorageError::Backend { cause, .. }) => {
            emit_block_delete_backend_failed(id.as_str(), subject, address, cause.as_str());
            respond_block_503()
        }
        Err(StorageError::NotFound) => {
            // FR-004: provider should map NotFound → Ok internally, but
            // defensive fallthrough handles a hypothetical
            // strict-NotFound provider too.
            emit_block_delete_ok(id.as_str(), subject, address);
            respond_block_204()
        }
    }
}

// ───────────────────────── Response constructors ─────────────────────────

/// 200 OK with payload (contracts/http.md §"200 OK").
fn respond_block_200(payload: Bytes) -> Response {
    let len = payload.len();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(payload))
        .expect("respond_block_200 response construction is infallible")
}

/// 204 No Content (contracts/http.md §"204 No Content").
fn respond_block_204() -> Response {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .expect("respond_block_204 response construction is infallible")
}

/// 400 Bad Request, empty body, `Content-Length: 0` (contracts/http.md §"400 ...").
fn respond_block_400() -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("respond_block_400 response construction is infallible")
}

/// Byte-identical 404 (contracts/http.md §"404 Not Found"). The fixed
/// `Content-Length: 0` keeps the empty-body status unambiguous to all
/// HTTP intermediaries.
fn respond_block_404() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("respond_block_404 response construction is infallible")
}

/// Byte-identical 503 (contracts/http.md §"503 Service Unavailable"). The
/// `Retry-After` value is the planning-time constant from research.md R3.
fn respond_block_503() -> Response {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(header::CONTENT_LENGTH, "0")
        .header(
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECONDS),
        )
        .body(Body::empty())
        .expect("respond_block_503 response construction is infallible")
}

// ───────────────────────── Helpers ─────────────────────────

fn subject_from_request(request: &HttpRequest<Body>) -> String {
    request
        .extensions()
        .get::<VaultSubjectExtension>()
        .map(|ext| ext.0.clone().into_string())
        .unwrap_or_else(|| "<unauthenticated>".to_string())
}

fn address_from_request(request: &HttpRequest<Body>) -> std::net::IpAddr {
    request
        .extensions()
        .get::<EffectiveAddress>()
        .map(|e| e.addr)
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn content_length(request: &HttpRequest<Body>) -> Option<u64> {
    request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

//! `/api/whoami` handler (FR-027, FR-030, contracts/http.md §Vault success).
//!
//! Returns `200 OK` with body `{"sub":"<vault subject>"}` when the
//! request is `GET` and has passed the vault guard's token + DPoP
//! validation. Non-GET methods (POST, HEAD, OPTIONS, …) return `404 Not
//! Found` with no Allow header and no WWW-Authenticate — byte-shape-
//! identical to a true path-not-found 404. The vault guard
//! short-circuits to pass-through for non-GET methods (see
//! `auth::middleware::VaultGuardService::call`), so the auth pipeline
//! never runs for non-GET and there is no `401` to leak the route's
//! existence.
//!
//! ## Why `any(...)` + in-handler dispatch (FR-030, PR #4 review-cycle round 2)
//!
//! Three earlier designs in this PR all leaked the route's existence:
//!
//!   1. `get(handler)` — axum returns `405 Method Not Allowed` with
//!      `Allow: GET` on non-GET methods. Leak.
//!   2. `get(handler).layer(guard)` + `method_not_allowed_fallback` —
//!      the fallback runs but axum's MethodRouter still tacks on
//!      `Allow: GET` after the handler returns (see axum's
//!      `set_allow_header` in `routing/route.rs`). Leak.
//!   3. `on(MethodFilter::GET, handler).layer(guard)` — same as #2:
//!      the MethodRouter knows GET is registered and emits Allow on
//!      method-mismatch responses regardless of the fallback.
//!
//! The working design mirrors `health.rs`: register with `any(handler)`
//! (which sets `AllowHeader::Skip` on the MethodRouter, suppressing
//! the Allow header machinery entirely) and dispatch on method inside
//! the handler. The guard is layered on `any(handler)`, so it sees
//! every method — but its `call()` short-circuits for non-GET methods
//! and passes through to the handler unchanged. The non-GET path
//! reaches the handler without the auth pipeline running, the handler
//! returns 404, and the response has no Allow / no WWW-Authenticate /
//! empty body — byte-identical to a path-mismatch 404.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde::Serialize;

use crate::app::AppState;
use crate::auth::VaultSubject;
use crate::auth::context::OidcContext;
use crate::auth::middleware::vault_guard;
use crate::auth::replay::JtiReplayStore;
use crate::auth::subject::VaultSubjectExtension;
use crate::logging::events::emit_request_rejected;
use crate::proxy_trust::EffectiveAddress;

#[derive(Serialize)]
struct WhoamiResponse {
    sub: String,
}

/// Entry point registered with `any(...)`. For GET, extracts the
/// `VaultSubject` from request extensions (the vault guard inserted it
/// during the auth pass) and returns the JSON body. For every other
/// method, returns the byte-shape-identical 404. The type-fence
/// guarantee from FR-024/FR-025 still holds: the handler asks for a
/// `VaultSubject` (not `AdminSubject`), and only the vault guard ever
/// inserts the matching extension key.
async fn handle_whoami(method: Method, request: Request) -> Response {
    if method != Method::GET {
        return method_mismatch_404(&method, request).await;
    }
    // For GET, the vault guard ran the auth pipeline and inserted the
    // VaultSubjectExtension on success. If the extension is missing,
    // the guard short-circuited to 401 before reaching here, so this
    // arm should never fire — but if it ever did, we'd fall through to
    // 401 (a 200 with no sub would be a worse leak).
    let Some(ext) = request.extensions().get::<VaultSubjectExtension>() else {
        return crate::auth::respond_401();
    };
    let subject: VaultSubject = ext.0.clone();
    Json(WhoamiResponse {
        sub: subject.into_string(),
    })
    .into_response()
}

/// 404 returned for any non-GET method. Mirrors the byte-shape of
/// `routes::mod::fallback_404` so that POST/HEAD/OPTIONS `/api/whoami`
/// is indistinguishable from POST `/api/anything-else` (FR-030).
/// Emits the `request.rejected` event for observability.
async fn method_mismatch_404(method: &Method, request: Request) -> Response {
    let effective_addr = request
        .extensions()
        .get::<EffectiveAddress>()
        .map(|e| e.addr)
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    emit_request_rejected(method, request.uri().path(), effective_addr);
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("404 response is infallible")
}

/// Build the vault-route subtree. The guard is layered on the route;
/// the guard itself short-circuits for non-GET methods (see
/// `VaultGuardService::call`'s FR-030 leak-prevention branch), so the
/// auth pipeline runs only on GET requests.
pub fn vault_routes(
    vault_ctx: Arc<OidcContext>,
    replay_store: Arc<JtiReplayStore>,
) -> Router<AppState> {
    let guard = vault_guard(vault_ctx, replay_store);
    Router::new().route("/api/whoami", any(handle_whoami).layer(guard))
}

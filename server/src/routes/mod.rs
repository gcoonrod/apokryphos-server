//! HTTP router assembly (FR-019..022, Clarify-Q1, invariants R1..R7).
//!
//! Exactly one route is *registered*: `/health`. The handler dispatches on
//! method internally — `GET` returns the JSON body, every other method
//! falls through to a 404 that is byte-identical to the path-mismatch
//! fallback (Clarify-Q1).
//!
//! ## Why `any(...)` instead of `get(...)` for `/health` (R13 amendment)
//!
//! axum 0.8's `MethodRouter` unconditionally inserts an `Allow: GET` header
//! on method-mismatch responses unless `AllowHeader::Skip` is set — and
//! `Skip` is set *only* by `any()` / `any_service()`. The 404-fallback
//! contract (contracts/http.md "specifically forbidden response patterns")
//! prohibits `Allow` headers on every 404. Using `any` + an in-handler
//! method check is the structural way to comply; the plan's prohibition
//! on `any` was based on a misreading of axum 0.8's actual API.

mod health;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode, Uri};
use axum::middleware;
use axum::response::Response;
use axum::routing::any;
use axum::Router;

use crate::app::AppState;
use crate::logging::events::emit_request_rejected;
use crate::proxy_trust::{self, EffectiveAddress};

/// Build the production router. Composes the proxy-trust layer (so the
/// `request.rejected` event carries the effective address) and registers
/// only `/health` (via `any`). Every other path falls through to
/// `fallback_404`. Every other method on `/health` is rejected inside
/// `health::handle_health`.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", any(health::handle_health))
        .fallback(fallback_404)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            proxy_trust::middleware,
        ))
        .with_state(state)
}

/// Path-mismatch catch-all (e.g., `GET /xyzzy`). Fires `request.rejected`
/// (FR-014d) and returns a byte-for-byte identical response for every input.
async fn fallback_404(method: Method, uri: Uri, request: Request) -> Response {
    let effective_addr = request
        .extensions()
        .get::<EffectiveAddress>()
        .map(|e| e.addr)
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    emit_request_rejected(&method, uri.path(), effective_addr);

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("fallback_404 response construction is infallible")
}

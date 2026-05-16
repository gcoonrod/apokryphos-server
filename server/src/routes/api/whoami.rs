//! `GET /api/whoami` handler (FR-027, FR-030, contracts/http.md §Vault success).
//!
//! Returns `200 OK` with body `{"sub":"<vault subject>"}` when the request
//! has passed the vault guard's token + DPoP validation. The handler's
//! signature is the compile-time structural fence: substituting
//! `AdminSubject` here produces a type error (the vault guard inserts
//! only `VaultSubjectExtension` into request extensions, and
//! `AdminSubject::from_request_parts` looks for `AdminSubjectExtension`
//! which the vault guard never installs).
//!
//! ## Method-mismatch handling (FR-030, addressed in PR #4 review)
//!
//! axum's default method-router behavior for a route registered with
//! `get(handler)` is to return `405 Method Not Allowed` with an
//! `Allow: GET` header when a non-GET method arrives. That LEAKS the
//! route's existence and method set, violating FR-030's "MUST NOT reveal
//! that the route exists" rule. We close the leak by:
//!
//!   1. Layering `vault_guard` on the `get(get_whoami)` method
//!      specifically (via `MethodRouter::layer`) so the guard ONLY
//!      runs for GET. This means non-GET methods never invoke the
//!      validation pipeline — important for FR-030 because a guard
//!      that returns `401 + WWW-Authenticate: DPoP` for non-GET requests
//!      *also* leaks route existence (a truly nonexistent path returns
//!      404, never 401).
//!   2. Setting `method_not_allowed_fallback` on the Router to a
//!      handler that returns `404` with an empty body and no `Allow`
//!      header, matching the Phase 2 path-mismatch fallback shape.
//!
//! Result: GET /api/whoami runs through the guard → 200 or 401. POST
//! /api/whoami (with or without auth) returns 404 — byte-shape-identical
//! to GET /nonexistent.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use serde::Serialize;

use crate::app::AppState;
use crate::auth::VaultSubject;
use crate::auth::context::OidcContext;
use crate::auth::middleware::vault_guard;
use crate::auth::replay::JtiReplayStore;
use crate::logging::events::emit_request_rejected;
use crate::proxy_trust::EffectiveAddress;

#[derive(Serialize)]
struct WhoamiResponse {
    sub: String,
}

async fn get_whoami(subject: VaultSubject) -> Json<WhoamiResponse> {
    Json(WhoamiResponse {
        sub: subject.into_string(),
    })
}

/// 405→404 conversion for `/api/whoami`. Mirrors the byte-shape of
/// `routes::mod::fallback_404` so that POST /api/whoami is
/// indistinguishable from POST /api/anything-else (FR-030).
async fn method_mismatch_404(method: Method, request: Request) -> Response {
    let effective_addr = request
        .extensions()
        .get::<EffectiveAddress>()
        .map(|e| e.addr)
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    emit_request_rejected(&method, request.uri().path(), effective_addr);
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("404 response is infallible")
}

/// Build the vault-route subtree. The guard is layered on the GET method
/// only — non-GET methods are caught by `method_not_allowed_fallback` and
/// return 404 without ever invoking the validation pipeline.
pub fn vault_routes(
    vault_ctx: Arc<OidcContext>,
    replay_store: Arc<JtiReplayStore>,
) -> Router<AppState> {
    let guard = vault_guard(vault_ctx, replay_store);
    Router::new()
        .route("/api/whoami", get(get_whoami).layer(guard))
        .method_not_allowed_fallback(method_mismatch_404)
}

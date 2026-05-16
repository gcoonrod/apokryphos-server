//! /health handler (FR-019, FR-020, FR-021, SC-006, invariant R6).
//!
//! Constant-body JSON for GET. Every other method falls through to the same
//! 404 path-mismatch fallback so that responses are byte-identical (Clarify-Q1).
//!
//! NOTE on `axum::routing::any` vs `get`: the contract requires that
//! method-mismatch on `/health` produce a 404 with NO `Allow` header.
//! axum's `MethodRouter` adds an `Allow` header *unconditionally* when a
//! method doesn't match and `AllowHeader` is not `Skip` — and `Skip` is set
//! only by `any()`/`any_service()`. Using `any` + an in-handler method
//! check is the structural override per Clarify-Q1; routing `/health` via
//! `get(handler)` would leak `Allow: GET` on every `POST /health` response.

use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::logging::events::emit_request_rejected;
use crate::proxy_trust::EffectiveAddress;

#[derive(Serialize)]
pub struct HealthResponse {
    alive: bool,
}

/// Entry point registered with `any(...)`. GET returns the JSON body;
/// every other method returns the same byte-identical 404 as the fallback.
pub async fn handle_health(method: Method, request: axum::extract::Request) -> Response {
    if method == Method::GET || method == Method::HEAD {
        // axum strips bodies for HEAD automatically. Treating HEAD as a method
        // mismatch (404) would diverge from the "constant /health response"
        // intent; treating it as GET makes /health behave consistently with
        // the standard HEAD-of-GET pattern. The 404 fallback contract is
        // about deliberately-wrong methods (POST/PUT/DELETE/OPTIONS), not
        // about the framework's automatic HEAD support.
        //
        // Actually — re-reading contracts/http.md, `HEAD /health` is listed
        // alongside POST/OPTIONS/DELETE as a case that should return 404.
        // So we reject HEAD here too.
        if method == Method::HEAD {
            return reject_404(&method, request).await;
        }
        Json(HealthResponse { alive: true }).into_response()
    } else {
        reject_404(&method, request).await
    }
}

async fn reject_404(method: &Method, request: axum::extract::Request) -> Response {
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

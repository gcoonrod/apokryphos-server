//! `/admin/whoami` handler (FR-028, FR-030, contracts/http.md §Admin success).
//!
//! Mirror of `routes::api::whoami` for the admin audience. See that
//! module's documentation for the design history; the same `any(...)` +
//! in-handler dispatch + method-aware guard pattern applies here.

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
use crate::auth::AdminSubject;
use crate::auth::context::OidcContext;
use crate::auth::middleware::admin_guard;
use crate::auth::replay::JtiReplayStore;
use crate::auth::subject::AdminSubjectExtension;
use crate::logging::events::emit_request_rejected;
use crate::proxy_trust::EffectiveAddress;

#[derive(Serialize)]
struct WhoamiResponse {
    sub: String,
}

async fn handle_whoami(method: Method, request: Request) -> Response {
    if method != Method::GET {
        return method_mismatch_404(&method, request).await;
    }
    let Some(ext) = request.extensions().get::<AdminSubjectExtension>() else {
        return crate::auth::respond_401();
    };
    let subject: AdminSubject = ext.0.clone();
    Json(WhoamiResponse {
        sub: subject.into_string(),
    })
    .into_response()
}

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

pub fn admin_routes(
    admin_ctx: Arc<OidcContext>,
    replay_store: Arc<JtiReplayStore>,
) -> Router<AppState> {
    let guard = admin_guard(admin_ctx, replay_store);
    Router::new().route("/admin/whoami", any(handle_whoami).layer(guard))
}

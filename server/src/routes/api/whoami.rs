//! `GET /api/whoami` handler (FR-027, contracts/http.md §Vault success).
//!
//! Returns `200 OK` with body `{"sub":"<vault subject>"}` when the request
//! has passed the vault guard's token + DPoP validation. The handler's
//! signature is the compile-time structural fence: substituting
//! `AdminSubject` here produces a type error (the vault guard inserts
//! only `VaultSubjectExtension` into request extensions, and
//! `AdminSubject::from_request_parts` looks for `AdminSubjectExtension`
//! which the vault guard never installs).

use axum::Json;
use axum::Router;
use axum::routing::get;
use serde::Serialize;

use crate::app::AppState;
use crate::auth::VaultSubject;

#[derive(Serialize)]
struct WhoamiResponse {
    sub: String,
}

async fn get_whoami(subject: VaultSubject) -> Json<WhoamiResponse> {
    Json(WhoamiResponse {
        sub: subject.into_string(),
    })
}

/// Build the vault-route subtree. The caller wraps this in the
/// `VaultGuard` layer when mounting onto the top-level router.
pub fn vault_routes() -> Router<AppState> {
    Router::new().route("/api/whoami", get(get_whoami))
}

//! Vault-audience routes (`/api/*`).
//!
//! Phase 3 ships `GET /api/whoami` (FR-027). Phase 4 adds
//! `GET`/`PUT`/`DELETE /api/blocks/{id}` (FR-016..018) under the same
//! vault auth layer; block routes are mounted only when the caller
//! supplies a `StorageProvider` (Phase 2/3 fixtures with
//! `storage_backend = "none"` pass `None` and the block subtree is
//! omitted entirely).

mod blocks;
mod whoami;

use std::sync::Arc;

use axum::Router;

use crate::app::AppState;
use crate::auth::context::OidcContext;
use crate::auth::replay::JtiReplayStore;
use crate::storage::StorageProvider;

/// Build the vault-audience route subtree.
///
/// `storage` is `Some(provider)` when the deployment has selected a
/// concrete storage backend (Phase 4 `storage_backend = "local_fs"`).
/// When `None`, only the existing `/api/whoami` route mounts; `/api/blocks/{id}`
/// falls through to the global 404 fallback (Phase 2/3 fixtures).
pub fn vault_routes(
    vault_ctx: Arc<OidcContext>,
    replay_store: Arc<JtiReplayStore>,
    storage: Option<Arc<dyn StorageProvider>>,
) -> Router<AppState> {
    let mut router = whoami::vault_routes(Arc::clone(&vault_ctx), Arc::clone(&replay_store));
    if let Some(storage) = storage {
        router = router.merge(blocks::routes(vault_ctx, replay_store, storage));
    }
    router
}

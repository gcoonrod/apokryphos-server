//! Block storage abstraction (spec FR-001..006, FR-027, FR-030).
//!
//! Public surface:
//!   - `StorageProvider` trait — the only legal interface between route
//!     handlers and any concrete backend.
//!   - `BlockId` — validated 43-char base64url-no-padding identifier.
//!   - `StorageError`, `BackendFailureCause`, `StorageInitError` — failure
//!     modes surfaced to callers.
//!   - `LocalFsProvider` — Phase 4's first concrete implementation.
//!   - `init_from_config` — bootstrap entry point invoked from `app::run`.
//!
//! This module is the sole owner of raw filesystem I/O for blocks. Direct
//! `std::fs::*`, `tokio::fs::*`, `std::os::unix::fs::*`, and `tempfile::*`
//! calls from outside `server/src/storage/` are prohibited per FR-012 and
//! enforced by `server/tests/no_direct_fs.rs` (SC-008).

mod block_id;
mod local_fs;
mod path;
mod provider;

use std::sync::Arc;

pub use local_fs::LocalFsProvider;
pub use provider::{BackendFailureCause, BlockId, StorageError, StorageInitError, StorageProvider};

use crate::config::{ServerConfig, StorageBackend};

/// Construct the configured `StorageProvider` and run its startup probe.
///
/// Invoked from `app::run` between auth-context init and router build (see
/// plan.md §"Bootstrap order"). A failure here exits the process before the
/// listener binds (FR-011) with the structured `storage.startup.failed`
/// event identifying the configured `block_root`.
///
/// Returns `Ok(None)` when `storage_backend = "none"` — the Phase 2
/// placeholder. In that case the block routes are NOT mounted; requests
/// to `/api/blocks/{id}` fall through to the global 404 fallback. Returns
/// `Ok(Some(provider))` for any concrete backend; the caller threads the
/// `Arc` into `routes::build_router`.
pub async fn init_from_config(
    cfg: &ServerConfig,
) -> Result<Option<Arc<dyn StorageProvider>>, StorageInitError> {
    match &cfg.storage_backend {
        StorageBackend::None => Ok(None),
        StorageBackend::LocalFs { root } => {
            let provider = LocalFsProvider::init(root.clone()).await?;
            Ok(Some(Arc::new(provider)))
        }
    }
}

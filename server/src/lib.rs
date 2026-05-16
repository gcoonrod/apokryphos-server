//! Library surface for `apokryphos-server`.
//!
//! `main.rs` is the only binary entry point; integration tests under `server/tests/`
//! consume this lib surface to exercise modules without spawning the binary.
//!
//! `auth/` and `storage/` are intentionally NOT re-exported. They are Phase 1
//! placeholders held for Phase 3 (FAPI 2.0 + DPoP) and Phase 4 (storage backend).
//! A future PR introducing public items there must update this comment.

pub mod config;
pub mod logging;
pub mod proxy_trust;
pub mod routes;
pub mod shutdown;

mod app;

pub use app::{AppError, AppState, run};

#[cfg(any(test, feature = "test-utils"))]
pub use app::serve_with_shutdown;

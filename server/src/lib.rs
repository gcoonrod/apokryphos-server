//! Library surface for `apokryphos-server`.
//!
//! `main.rs` is the only binary entry point; integration tests under `server/tests/`
//! consume this lib surface to exercise modules without spawning the binary.
//!
//! `auth/` and `storage/` are intentionally NOT re-exported. They are Phase 1
//! placeholders held for Phase 3 (FAPI 2.0 + DPoP) and Phase 4 (storage backend).
//! A future PR introducing public items there must update this comment.
//!
//! ## Target platform
//!
//! This crate is Unix-only. Graceful shutdown (`shutdown/mod.rs`) relies on
//! POSIX SIGINT/SIGTERM/SIGHUP via `tokio::signal::unix`, which has no
//! portable equivalent on Windows — there is no SIGTERM or SIGHUP to map to,
//! and substituting `ctrl_c()` would silently change the shutdown contract.
//! The supported deployment surface (self-hosted with a process supervisor)
//! is Unix by design, so the failure mode is declared explicitly rather than
//! producing a confusing `tokio::signal::unix` missing-item error downstream.

#[cfg(not(unix))]
compile_error!(
    "apokryphos-server requires a Unix target: POSIX SIGINT/SIGTERM/SIGHUP \
     are used for graceful shutdown and have no portable equivalent on \
     non-Unix platforms. See the crate-level docs for rationale."
);

pub mod config;
pub mod logging;
pub mod proxy_trust;
pub mod routes;
pub mod shutdown;

mod app;

pub use app::{AppError, AppState, run};

#[cfg(any(test, feature = "test-utils"))]
pub use app::serve_with_shutdown;

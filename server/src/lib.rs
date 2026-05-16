//! Library surface for `apokryphos-server`.
//!
//! `main.rs` is the only binary entry point; integration tests under `server/tests/`
//! consume this lib surface to exercise modules without spawning the binary.
//!
//! ## Module status
//!
//! - `auth/` (Phase 3): live. Hosts the FAPI 2.0 + DPoP authentication
//!   core. Phase 2 lands the scaffolding (`crypto`, `failure`, `subject`,
//!   `replay`, `testing`); Phase 3 fills in `context`, `discovery`, `dpop`,
//!   `jwks`, `middleware`, `token`. See `specs/003-fapi-dpop-auth-core/`.
//! - `cli/` (Phase 3): live. Hosts the `--log-level` CLI flag (FR-033a).
//! - `storage/` (Phase 4): still a placeholder, NOT re-exported.
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

pub mod auth;
pub mod cli;
pub mod config;
pub mod logging;
pub mod proxy_trust;
pub mod routes;
pub mod shutdown;

mod app;

pub use app::{AppError, AppState, run};

#[cfg(any(test, feature = "test-utils"))]
pub use app::serve_with_shutdown;

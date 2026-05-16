//! Logging: global subscriber install, mandatory event helpers, and `Sensitive<T>`.
//!
//! The subscriber is installed exactly once at process start, immediately
//! after `cli::Cli::parse()` and before any configuration code runs
//! (Phase 2 Clarify-Q3 + Phase 3 FR-033a). `RUST_LOG` is deliberately not
//! honored — the `env-filter` feature is not compiled in (R6) — so the
//! four mandatory events cannot be silenced via env vars.
//!
//! ## Level resolution (Phase 3)
//!
//! The level is supplied by the caller (`main` reads `cli.log_level`). See
//! spec FR-033a + plan §Implementation Approach for the bootstrap ordering.
//!
//! ## Phase 2 events still emit at their original levels
//!
//! `server.started`, `server.shutdown.initiated`, `server.shutdown.completed`
//! remain at `INFO`; `request.rejected` remains at `DEBUG` (Phase 2 FR-014a–d,
//! preserved by FR-033b). Under the default `--log-level INFO`, the three
//! INFO events are visible and `request.rejected` is suppressed; under
//! `--log-level DEBUG` all four are visible.

pub mod events;
mod sensitive;

pub use sensitive::Sensitive;

use tracing::Level;
use tracing_subscriber::fmt;

/// Install the process-wide `tracing` subscriber. Must be called exactly
/// once, immediately after `cli::Cli::parse()` and before any other code
/// touches configuration or environment. Writes to stderr at the
/// caller-supplied max-level.
///
/// Panicking is the documented exception to the "no panics" rule (see
/// `contracts/internal.md` §"Error types"): at this point in startup there
/// is no logger to emit through, so a panic is the only signal available.
pub fn install_global_subscriber(max_level: Level) {
    let subscriber = fmt()
        .with_writer(std::io::stderr)
        .with_max_level(max_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("logging::install_global_subscriber called more than once");
}

//! Logging: global subscriber install, mandatory event helpers, and `Sensitive<T>`.
//!
//! The subscriber is installed exactly once at process start, before any
//! configuration code runs (Clarify-Q3, FR-011, invariants L1/L2/L3).
//! `RUST_LOG` is deliberately not honored — the `env-filter` feature is not
//! compiled in (R6) — so the four mandatory events cannot be silenced.

pub mod events;
mod sensitive;

pub use sensitive::Sensitive;

use tracing::Level;
use tracing_subscriber::fmt;

/// Install the process-wide `tracing` subscriber. Must be called exactly once,
/// as the first statement in `main`. Writes to stderr at DEBUG max-level so
/// `request.rejected` (FR-014d, DEBUG) reaches the writer.
///
/// Panicking is the documented exception to the "no panics" rule (see
/// `contracts/internal.md` §"Error types"): at this point in startup there is
/// no logger to emit through, so a panic is the only signal available.
pub fn install_global_subscriber() {
    let subscriber = fmt()
        .with_writer(std::io::stderr)
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("logging::install_global_subscriber called more than once");
}

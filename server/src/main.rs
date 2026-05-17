//! Binary entry point (R3, Clarify-Q3, FR-033a).
//!
//! Bootstrap ordering:
//!   1. `cli::Cli::parse()` — read `argv` (clap; exits non-zero on invalid
//!      `--log-level` value BEFORE the tracing subscriber installs, per
//!      FR-033a and SC-013(c)).
//!   2. `logging::install_global_subscriber(level)` — install the global
//!      subscriber at the level resolved from the CLI flag (default `INFO`).
//!      This satisfies both Phase 2 FR-011 ("single deterministic
//!      subscriber, installed before configuration loading") and Phase 3
//!      FR-033a ("level is fixed for the process lifetime once installed").
//!   3. Construct the tokio runtime and dispatch to `apokryphos_server::run`.
//!
//! The runtime is built explicitly via `tokio::runtime::Builder` (rather
//! than `#[tokio::main]`) so steps 1–2 happen synchronously, before any
//! async context exists.

use std::process::ExitCode;

use apokryphos_server::cli::Cli;

fn main() -> ExitCode {
    // Step 1: parse the CLI. `clap` exits non-zero on invalid input.
    let cli = Cli::from_args();

    // Step 2: install the global tracing subscriber at the resolved level.
    // Phase 2 FR-011 invariants L1/L2 preserved: exactly one global
    // subscriber, fixed for the process lifetime.
    apokryphos_server::logging::install_global_subscriber(cli.log_level.as_tracing_level());

    // Step 3: build the runtime and run the server. (Unchanged from Phase 2.)
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "failed to construct tokio runtime");
            return ExitCode::from(1);
        }
    };

    rt.block_on(async move {
        match apokryphos_server::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "fatal server error");
                ExitCode::from(1)
            }
        }
    })
}

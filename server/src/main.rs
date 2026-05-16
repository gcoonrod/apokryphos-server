//! Binary entry point (R3, Clarify-Q3).
//!
//! The global `tracing` subscriber is installed as the first statement of
//! `main`, before any code that touches configuration or environment
//! variables (FR-011, L1/L2 invariants). The runtime is built explicitly
//! with `tokio::runtime::Builder` rather than `#[tokio::main]` so we
//! retain ordering guarantees around subscriber install.

use std::process::ExitCode;

fn main() -> ExitCode {
    apokryphos_server::logging::install_global_subscriber();

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

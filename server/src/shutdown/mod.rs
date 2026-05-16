//! Shutdown signal listeners (R12, invariants S1/S2/S4).
//!
//! Production: await `SIGINT`, `SIGTERM`, or `SIGHUP` — whichever arrives
//! first. All three trigger the same graceful-drain path; the only
//! difference is the `signal` field on the emitted `server.shutdown.initiated`
//! event.
//!
//! Tests: await a `oneshot` channel so the test can trigger shutdown without
//! sending real signals to the test process (which would kill the test
//! runner).
//!
//! Both helpers emit `server.shutdown.initiated` (FR-014b) before returning,
//! so the event fires exactly when the bootstrap actually begins draining.
//!
//! ## Note on SIGHUP semantics (Principle III)
//!
//! SIGHUP is treated as a third shutdown signal, NOT as "reload configuration"
//! per the nginx/sshd/systemd-unit convention. The constitution's Principle III
//! ("Stateless, Self-Hosted Architecture") requires that configuration changes
//! be applied by restarting the process — there is no facility for swapping a
//! live `Arc<ServerConfig>` for a freshly validated one without re-binding the
//! listener, and adding one would re-introduce mutable global state that R7
//! deliberately forecloses. Any future PR that interprets SIGHUP as
//! "reload config" must first amend the constitution.

use std::io;
use std::time::Duration;

use tokio::signal::unix::{Signal, SignalKind, signal};
#[cfg(any(test, feature = "test-utils"))]
use tokio::sync::oneshot;

use crate::logging::events::emit_server_shutdown_initiated;

/// SIGINT/SIGTERM/SIGHUP handles, installed eagerly during bootstrap so the
/// process cannot be killed by the default disposition during the window
/// between listener bind and axum's first poll of the shutdown future.
pub struct InstalledSignals {
    sigint: Signal,
    sigterm: Signal,
    sighup: Signal,
}

/// Synchronously install SIGINT, SIGTERM, and SIGHUP handlers. Returns
/// `io::Result` so the caller can propagate failure as `AppError::SignalSetup`
/// — this runs after the global tracing subscriber is up, where panicking
/// is forbidden (contracts/internal.md).
pub fn install_signals() -> io::Result<InstalledSignals> {
    let sigint = signal(SignalKind::interrupt())?;
    let sigterm = signal(SignalKind::terminate())?;
    let sighup = signal(SignalKind::hangup())?;
    Ok(InstalledSignals { sigint, sigterm, sighup })
}

/// Production: await whichever of the pre-installed signal streams fires
/// first. Emit `server.shutdown.initiated` with the matching `signal` field,
/// then return.
pub async fn wait_for_signal(mut signals: InstalledSignals, drain_timeout: Duration) {
    let signal_name = tokio::select! {
        _ = signals.sigint.recv() => "SIGINT",
        _ = signals.sigterm.recv() => "SIGTERM",
        _ = signals.sighup.recv() => "SIGHUP",
    };

    emit_server_shutdown_initiated(signal_name, drain_timeout);
}

/// Test entry point: await a oneshot channel, then emit the same event.
/// Gated by `test-utils` so it does not appear in the release binary.
#[cfg(any(test, feature = "test-utils"))]
pub async fn signal_listener_from_channel(rx: oneshot::Receiver<()>, drain_timeout: Duration) {
    let _ = rx.await;
    emit_server_shutdown_initiated("test_trigger", drain_timeout);
}

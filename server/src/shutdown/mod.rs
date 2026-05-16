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

use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};
#[cfg(any(test, feature = "test-utils"))]
use tokio::sync::oneshot;

use crate::logging::events::emit_server_shutdown_initiated;

/// Production: await SIGINT, SIGTERM, or SIGHUP. Emit
/// `server.shutdown.initiated` with the matching `signal` field, then return.
pub async fn signal_listener_for_signals(drain_timeout: Duration) {
    let mut sigint = signal(SignalKind::interrupt())
        .expect("failed to install SIGINT listener");
    let mut sigterm = signal(SignalKind::terminate())
        .expect("failed to install SIGTERM listener");
    let mut sighup = signal(SignalKind::hangup())
        .expect("failed to install SIGHUP listener");

    let signal_name = tokio::select! {
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
        _ = sighup.recv() => "SIGHUP",
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

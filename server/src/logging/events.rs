//! The four mandatory `tracing` events (FR-014a–d, Clarify-Q2, R10).
//!
//! Every emission of these events MUST go through one of the helpers below so
//! field names stay consistent and cross-module invariant **X4** is verifiable
//! by grep on the event-name constants.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const SERVER_STARTED: &str = "server.started";
pub const SERVER_SHUTDOWN_INITIATED: &str = "server.shutdown.initiated";
pub const SERVER_SHUTDOWN_COMPLETED: &str = "server.shutdown.completed";
pub const REQUEST_REJECTED: &str = "request.rejected";

/// Emitted once per process, immediately after the listener binds. INFO level.
pub fn emit_server_started(bound_addr: SocketAddr) {
    tracing::info!(
        event = SERVER_STARTED,
        bound_addr = %bound_addr,
    );
}

/// Emitted once when SIGINT, SIGTERM, or SIGHUP (or the test trigger) arrives.
/// INFO level. The `signal` field is one of `"SIGINT"`, `"SIGTERM"`,
/// `"SIGHUP"`, or `"test_trigger"`.
pub fn emit_server_shutdown_initiated(signal: &'static str, drain_timeout: Duration) {
    tracing::info!(
        event = SERVER_SHUTDOWN_INITIATED,
        signal = signal,
        drain_timeout_secs = drain_timeout.as_secs(),
    );
}

/// Emitted once after drain completes (clean or forced). INFO level.
pub fn emit_server_shutdown_completed(drained_cleanly: bool) {
    tracing::info!(
        event = SERVER_SHUTDOWN_COMPLETED,
        drained_cleanly = drained_cleanly,
    );
}

/// Emitted per request answered by the 404 fallback. DEBUG level.
pub fn emit_request_rejected(method: &axum::http::Method, path: &str, effective_addr: IpAddr) {
    tracing::debug!(
        event = REQUEST_REJECTED,
        method = method.as_str(),
        path = path,
        effective_addr = %effective_addr,
    );
}

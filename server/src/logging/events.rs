//! Mandatory `tracing` events for Phase 2 (Clarify-Q2, R10) and Phase 4
//! (data-model.md §"Log-event schema").
//!
//! Every emission MUST go through one of the helpers below so field names
//! stay consistent and the event-name constants are greppable.
//!
//! Phase 4 storage events forbid the following fields under FR-025:
//! `payload`, `payload_prefix`, `payload_hash`, `error.message` (the raw
//! `io::Error::to_string()`), `file_path` (the on-disk path). Only
//! `block_id` (43-char canonical OR the `BLOCK_ID_MALFORMED` sentinel),
//! `subject`, `address`, and the per-event categorized `cause` /
//! `size_bytes` fields may appear.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const SERVER_STARTED: &str = "server.started";
pub const SERVER_SHUTDOWN_INITIATED: &str = "server.shutdown.initiated";
pub const SERVER_SHUTDOWN_COMPLETED: &str = "server.shutdown.completed";
pub const REQUEST_REJECTED: &str = "request.rejected";

// Phase 4 — block-storage structural events.
pub const STORAGE_STARTUP_READY: &str = "storage.startup.ready";
pub const STORAGE_STARTUP_FAILED: &str = "storage.startup.failed";
pub const STORAGE_PUT_OK: &str = "storage.put.ok";
pub const STORAGE_PUT_BACKEND_FAILED: &str = "storage.put.backend_failed";
pub const STORAGE_GET_HIT: &str = "storage.get.hit";
pub const STORAGE_GET_MISS: &str = "storage.get.miss";
pub const STORAGE_GET_BACKEND_FAILED: &str = "storage.get.backend_failed";
pub const STORAGE_DELETE_OK: &str = "storage.delete.ok";
pub const STORAGE_DELETE_BACKEND_FAILED: &str = "storage.delete.backend_failed";

/// Sentinel logged as `block_id` when the client supplied an ID that failed
/// `BlockId::parse`. Keeps the log discipline uniform (block_id field always
/// present) without echoing the malformed bytes themselves.
pub const BLOCK_ID_MALFORMED: &str = "<malformed>";

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

// ───────────────────────────────────────────────────────────────────────────
// Phase 4 — block-storage emitters (FR-011, FR-025, data-model.md
// §"Log-event schema").

/// Emitted once after the FR-011 startup probe succeeds. INFO level.
pub fn emit_storage_startup_ready(root_path: &str) {
    tracing::info!(event = STORAGE_STARTUP_READY, root_path = root_path,);
}

/// Emitted on any `StorageInitError` from `storage::init_from_config`.
/// ERROR level. `step` is one of `"metadata"`, `"is_dir"`, `"probe_write"`;
/// `cause` is the categorized `BackendFailureCause::as_str()` value.
pub fn emit_storage_startup_failed(root_path: &str, step: &'static str, cause: &'static str) {
    tracing::error!(
        event = STORAGE_STARTUP_FAILED,
        root_path = root_path,
        step = step,
        cause = cause,
    );
}

/// Emitted after a successful `PUT` returning 204. INFO level.
pub fn emit_block_put_ok(block_id: &str, subject: &str, address: IpAddr, size_bytes: u64) {
    tracing::info!(
        event = STORAGE_PUT_OK,
        block_id = block_id,
        subject = subject,
        address = %address,
        size_bytes = size_bytes,
    );
}

/// Emitted after a `PUT` maps to 503 (categorized backend failure). WARN level.
pub fn emit_block_put_backend_failed(
    block_id: &str,
    subject: &str,
    address: IpAddr,
    cause: &'static str,
) {
    tracing::warn!(
        event = STORAGE_PUT_BACKEND_FAILED,
        block_id = block_id,
        subject = subject,
        address = %address,
        cause = cause,
    );
}

/// Emitted after a successful `GET` returning 200. INFO level.
pub fn emit_block_get_hit(block_id: &str, subject: &str, address: IpAddr) {
    tracing::info!(
        event = STORAGE_GET_HIT,
        block_id = block_id,
        subject = subject,
        address = %address,
    );
}

/// Emitted after a `GET` returning 404, regardless of cause (absent /
/// malformed / wrong method). INFO level. The malformed-ID case uses the
/// `BLOCK_ID_MALFORMED` sentinel as the `block_id` field.
pub fn emit_block_get_miss(block_id: &str, subject: &str, address: IpAddr) {
    tracing::info!(
        event = STORAGE_GET_MISS,
        block_id = block_id,
        subject = subject,
        address = %address,
    );
}

/// Emitted after a `GET` maps to 503 (categorized backend failure). WARN level.
pub fn emit_block_get_backend_failed(
    block_id: &str,
    subject: &str,
    address: IpAddr,
    cause: &'static str,
) {
    tracing::warn!(
        event = STORAGE_GET_BACKEND_FAILED,
        block_id = block_id,
        subject = subject,
        address = %address,
        cause = cause,
    );
}

/// Emitted after any `DELETE` returning 204. INFO level.
pub fn emit_block_delete_ok(block_id: &str, subject: &str, address: IpAddr) {
    tracing::info!(
        event = STORAGE_DELETE_OK,
        block_id = block_id,
        subject = subject,
        address = %address,
    );
}

/// Emitted after a `DELETE` maps to 503 (any non-NotFound backend error). WARN level.
pub fn emit_block_delete_backend_failed(
    block_id: &str,
    subject: &str,
    address: IpAddr,
    cause: &'static str,
) {
    tracing::warn!(
        event = STORAGE_DELETE_BACKEND_FAILED,
        block_id = block_id,
        subject = subject,
        address = %address,
        cause = cause,
    );
}

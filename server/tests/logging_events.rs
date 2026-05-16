//! T010, T035, T044: tests for the four mandatory tracing events
//! (FR-014a–d, SC-010, R10). Each test exercises the public `events::*`
//! helpers under a scoped subscriber so we can assert on the rendered output.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use apokryphos_server::logging::events::{
    emit_request_rejected, emit_server_shutdown_completed, emit_server_shutdown_initiated,
    emit_server_started,
};

use crate::common::with_captured_logs;

// ─────────────────── FR-014a: server.started ─────────────────────────────

#[test]
fn server_started_emits_one_info_event_with_bound_addr() {
    let (logs, _) = with_captured_logs(|| {
        emit_server_started("127.0.0.1:12345".parse().unwrap());
    });
    assert_eq!(
        logs.matches("server.started").count(),
        1,
        "exactly one server.started event expected; captured:\n{logs}"
    );
    assert!(logs.contains("127.0.0.1:12345"));
    assert!(logs.contains("INFO"));
}

// ─────────────────── FR-014b/c: shutdown event sequence ──────────────────

#[test]
fn shutdown_event_sequence_emits_each_event_once_in_order() {
    let (logs, _) = with_captured_logs(|| {
        emit_server_started("127.0.0.1:12345".parse().unwrap());
        emit_server_shutdown_initiated("SIGTERM", Duration::from_secs(30));
        emit_server_shutdown_completed(true);
    });

    assert_eq!(logs.matches("server.started").count(), 1);
    assert_eq!(logs.matches("server.shutdown.initiated").count(), 1);
    assert_eq!(logs.matches("server.shutdown.completed").count(), 1);

    let started_pos = logs.find("server.started").unwrap();
    let initiated_pos = logs.find("server.shutdown.initiated").unwrap();
    let completed_pos = logs.find("server.shutdown.completed").unwrap();
    assert!(started_pos < initiated_pos);
    assert!(initiated_pos < completed_pos);

    assert!(logs.contains("signal=\"SIGTERM\"") || logs.contains("signal=SIGTERM"));
    assert!(logs.contains("drain_timeout_secs=30"));
    assert!(logs.contains("drained_cleanly=true"));
}

#[test]
fn shutdown_completed_reports_drained_cleanly_false_for_forced_close() {
    let (logs, _) = with_captured_logs(|| {
        emit_server_shutdown_completed(false);
    });
    assert!(logs.contains("drained_cleanly=false"));
}

// ─────────────────── FR-014d: request.rejected ───────────────────────────

#[test]
fn request_rejected_is_debug_level_with_required_fields() {
    let (logs, _) = with_captured_logs(|| {
        let m = axum::http::Method::POST;
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        emit_request_rejected(&m, "/health", addr);
    });
    assert_eq!(logs.matches("request.rejected").count(), 1);
    assert!(logs.contains("DEBUG"));
    assert!(logs.contains("method=\"POST\"") || logs.contains("method=POST"));
    assert!(logs.contains("/health"));
    assert!(logs.contains("203.0.113.7"));
}

#[test]
fn each_404_emits_one_request_rejected_event() {
    let (logs, _) = with_captured_logs(|| {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        emit_request_rejected(&axum::http::Method::POST, "/health", addr);
        emit_request_rejected(&axum::http::Method::GET, "/anything-else", addr);
        emit_request_rejected(&axum::http::Method::DELETE, "/heaIth", addr); // typo
    });
    assert_eq!(logs.matches("request.rejected").count(), 3);
}

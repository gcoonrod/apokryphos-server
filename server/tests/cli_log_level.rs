//! T007 — integration test for the `--log-level` CLI flag (FR-033a, SC-013).
//!
//! Most of the parse-level behavior is also covered by inline unit tests in
//! `src/cli/mod.rs`. This binary additionally validates:
//!
//!   - SC-013(c): the *process* (not just `try_parse_from`) exits non-zero
//!     before any tracing subscriber installs when given an invalid level.
//!     Verified by spawning the `apokryphos-server` binary itself with a
//!     deliberate invalid value and asserting on its exit code + stderr.
//!   - SC-013(d): the chosen level actually filters the four Phase 2
//!     structural events the way FR-033b promises — at `WARN` the three
//!     `INFO` lifecycle events are suppressed; at `INFO` they remain
//!     visible. Verified via a scoped subscriber.
//!
//! ## SC-013 coverage matrix
//!
//! | Sub-clause                                          | Where covered                                 |
//! |-----------------------------------------------------|-----------------------------------------------|
//! | (a) absence of `--log-level` defaults to INFO       | `cli::tests::default_log_level_is_info` + this binary's `default_yields_info` |
//! | (b) each permitted value installs that level        | `cli::tests::each_permitted_value_parses` + this binary's `each_value_maps_correctly` |
//! | (c) invalid value rejected, process exits non-zero  | this binary's `invalid_value_exits_nonzero_with_diagnostic` |
//! | (d) FR-014a–c visibility under WARN vs INFO         | this binary's `info_events_*_at_*` pair      |

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apokryphos_server::cli::{Cli, LogLevel};
use apokryphos_server::logging::events::{
    emit_server_shutdown_completed, emit_server_shutdown_initiated, emit_server_started,
};
use clap::Parser;
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

// ───────────────── SC-013(a) + (b): parse semantics ──────────────────────

#[test]
fn default_yields_info() {
    let cli = Cli::parse_from(["apokryphos-server"]);
    assert_eq!(cli.log_level, LogLevel::Info);
    assert_eq!(cli.log_level.as_tracing_level(), Level::INFO);
}

#[test]
fn each_value_maps_correctly() {
    for (input, expected) in [
        ("TRACE", Level::TRACE),
        ("DEBUG", Level::DEBUG),
        ("INFO", Level::INFO),
        ("WARN", Level::WARN),
        ("ERROR", Level::ERROR),
    ] {
        let cli = Cli::parse_from(["apokryphos-server", "--log-level", input]);
        assert_eq!(
            cli.log_level.as_tracing_level(),
            expected,
            "input {input:?} should map to {expected:?}"
        );
    }
}

// ─────────────── SC-013(c): invalid value subprocess invocation ──────────

#[test]
fn invalid_value_exits_nonzero_with_diagnostic() {
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests so they can
    // invoke the package's binary. The server's main() exits *before* the
    // tracing subscriber installs when clap rejects the flag value, so
    // this test does not need any config or network setup.
    let binary_path = env!("CARGO_BIN_EXE_apokryphos-server");
    let output = std::process::Command::new(binary_path)
        .arg("--log-level")
        .arg("VERBOSE")
        .output()
        .expect("failed to spawn apokryphos-server for invalid-value test");

    let code = output.status.code().expect("subprocess exited via signal");
    assert_ne!(code, 0, "invalid --log-level value MUST exit non-zero");
    assert_eq!(
        code, 2,
        "clap's parse-error exit code is 2 (got {code}); a change here would be a behavioral regression"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr is not UTF-8");
    assert!(
        stderr.contains("VERBOSE"),
        "stderr must name the offending value; got:\n{stderr}"
    );
    assert!(
        stderr.contains("TRACE") && stderr.contains("INFO"),
        "stderr must list the permitted set; got:\n{stderr}"
    );
}

// ─────────────── SC-013(d): visibility filter behavior ───────────────────

#[derive(Clone, Default)]
struct CapturingBuffer(Arc<Mutex<Vec<u8>>>);

impl CapturingBuffer {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturingBuffer {
    type Writer = CapturingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CapturingWriter(self.0.clone())
    }
}

fn capture_with_max_level<F: FnOnce()>(max_level: Level, f: F) -> String {
    let buffer = CapturingBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(max_level)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    buffer.contents()
}

#[test]
fn info_events_visible_at_info() {
    // Under --log-level INFO, the three Phase 2 INFO lifecycle events
    // MUST be visible (FR-033b).
    let bound: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let logs = capture_with_max_level(Level::INFO, || {
        emit_server_started(bound);
        emit_server_shutdown_initiated("SIGTERM", Duration::from_secs(30));
        emit_server_shutdown_completed(true);
    });

    assert!(
        logs.contains("server.started"),
        "server.started MUST be visible at INFO; got:\n{logs}"
    );
    assert!(
        logs.contains("server.shutdown.initiated"),
        "server.shutdown.initiated MUST be visible at INFO; got:\n{logs}"
    );
    assert!(
        logs.contains("server.shutdown.completed"),
        "server.shutdown.completed MUST be visible at INFO; got:\n{logs}"
    );
}

#[test]
fn info_events_suppressed_at_warn() {
    // Under --log-level WARN, the three INFO lifecycle events MUST be
    // filtered out (their level is below the configured floor). This is
    // the intentional consequence of FR-033b — the events keep their
    // original INFO level, and operators who want them in production
    // must run at `--log-level INFO` (the default) or below.
    let bound: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let logs = capture_with_max_level(Level::WARN, || {
        emit_server_started(bound);
        emit_server_shutdown_initiated("SIGTERM", Duration::from_secs(30));
        emit_server_shutdown_completed(true);
    });

    assert!(
        !logs.contains("server.started"),
        "server.started MUST be suppressed at WARN; got:\n{logs}"
    );
    assert!(
        !logs.contains("server.shutdown.initiated"),
        "server.shutdown.initiated MUST be suppressed at WARN; got:\n{logs}"
    );
    assert!(
        !logs.contains("server.shutdown.completed"),
        "server.shutdown.completed MUST be suppressed at WARN; got:\n{logs}"
    );
}

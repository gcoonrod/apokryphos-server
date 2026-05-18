//! T028: SC-005 — `Sensitive<T>` redaction tests.
//!
//! Each test installs a scoped tracing subscriber, emits an event through
//! one of the supported rendering paths, and asserts the wrapped string
//! does NOT appear in captured output and `<redacted>` does.
//!
//! T029's compile_fail doctest is inline in `src/logging/sensitive.rs` and
//! verified by `cargo test --doc`.

mod common;

use apokryphos_server::logging::Sensitive;

use crate::common::with_captured_logs;

const SECRET: &str = "hunter2-very-secret";

#[test]
fn debug_path_redacts() {
    let s = Sensitive::new(SECRET.to_string());
    let (logs, _) = with_captured_logs(|| {
        tracing::info!(token = ?s, "debug-path test");
    });
    assert!(
        logs.contains("<redacted>"),
        "expected <redacted> in:\n{logs}"
    );
    assert!(!logs.contains(SECRET), "secret leaked in:\n{logs}");
}

#[test]
fn display_path_redacts() {
    let s = Sensitive::new(SECRET.to_string());
    let (logs, _) = with_captured_logs(|| {
        tracing::info!(token = %s, "display-path test");
    });
    assert!(logs.contains("<redacted>"));
    assert!(!logs.contains(SECRET));
}

#[test]
fn format_macro_redacts() {
    let s = Sensitive::new(SECRET.to_string());
    let display_form = format!("{s}");
    let debug_form = format!("{s:?}");
    assert_eq!(display_form, "<redacted>");
    assert_eq!(debug_form, "<redacted>");
    assert!(!display_form.contains(SECRET));
    assert!(!debug_form.contains(SECRET));
}

#[test]
fn expose_secret_returns_inner_for_explicit_unwrap() {
    let s = Sensitive::new(SECRET.to_string());
    assert_eq!(s.expose_secret(), SECRET);
}

#[test]
fn redacted_marker_constant_is_stable() {
    assert_eq!(Sensitive::<()>::REDACTED_MARKER, "<redacted>");
}

//! `Sensitive<T>` — structural redaction wrapper (R4, Clarify-Q5, FR-012/014, L4).
//!
//! Implements `Debug` and `Display` to emit the literal string `<redacted>`.
//! Deliberately does **not** implement `tracing::field::Value`, `serde::Serialize`,
//! `valuable::Valuable`, `Clone`, or `Copy` — every path that would otherwise
//! reveal the wrapped value is a compile error.
//!
//! ## Compile-time fence (T029)
//!
//! The bare structured-field path through `tracing::info!(token = wrapped)` —
//! without `?` (Debug) or `%` (Display) — must NOT compile, because
//! `Sensitive<T>` does not implement `tracing::field::Value`. The doctest
//! below asserts this:
//!
//! ```compile_fail
//! use apokryphos_server::logging::Sensitive;
//! let s = Sensitive::new("secret".to_string());
//! tracing::info!(token = s, "this must not compile");
//! ```

use std::fmt;

pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    pub const REDACTED_MARKER: &'static str = "<redacted>";

    #[inline]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    #[inline]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::REDACTED_MARKER)
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::REDACTED_MARKER)
    }
}

// DELIBERATELY NOT IMPLEMENTED (R4, L4 invariant):
// - serde::Serialize  → bare structured field via serde would defeat the fence
// - tracing::field::Value → bare `field = sensitive` syntax must be a compile error
// - valuable::Valuable → forecloses the valuable serialization path
// - Clone, Copy → keeps the default closed; callers opt in per use site

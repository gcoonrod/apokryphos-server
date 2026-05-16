//! Command-line argument parsing (FR-033a, research R11).
//!
//! The single supported flag is `--log-level <LEVEL>` whose `<LEVEL>` must
//! be exactly one of `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`. When
//! absent, the level defaults to `INFO`. Any other value causes `clap` to
//! print a one-line diagnostic to stderr (naming the offending value and
//! the permitted set) and exit with code 2 — **before** the tracing
//! subscriber installs, satisfying SC-013(c).
//!
//! ## Phase 2 FR-011 narrow refinement
//!
//! Phase 2 FR-011 says the subscriber's level is "fixed at compile time
//! and NOT parameterized by operator-supplied configuration." The CLI flag
//! is a narrow refinement: it is parsed at the binary entry point BEFORE
//! the tracing subscriber installs, and the level is fixed for the
//! process lifetime once installed. Phase 2 FR-011's intent ("a single
//! deterministic global subscriber, level unchangeable post-install") is
//! preserved. See spec.md §Clarifications + FR-033a for the full record.

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "apokryphos-server",
    about = "FAPI 2.0 + DPoP authenticated blind-storage server",
    long_about = None,
    version
)]
pub struct Cli {
    /// Operational log level for the global `tracing` subscriber.
    /// Parsed once at startup; fixed for the process lifetime.
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,
}

/// Subset of `tracing::Level` permitted on the `--log-level` flag. The
/// enum's `value_enum` derive gives clap the canonical names and emits
/// the rejected-value diagnostic SC-013 requires.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "UPPER")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Map to the corresponding `tracing::Level`.
    pub fn as_tracing_level(self) -> tracing::Level {
        match self {
            Self::Trace => tracing::Level::TRACE,
            Self::Debug => tracing::Level::DEBUG,
            Self::Info => tracing::Level::INFO,
            Self::Warn => tracing::Level::WARN,
            Self::Error => tracing::Level::ERROR,
        }
    }
}

impl Cli {
    /// Parse argv via `clap::Parser::parse`. Exits non-zero on invalid
    /// input (clap's default).
    pub fn from_args() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn default_log_level_is_info() {
        let cli = Cli::parse_from(["apokryphos-server"]);
        assert_eq!(cli.log_level, LogLevel::Info);
        assert_eq!(cli.log_level.as_tracing_level(), tracing::Level::INFO);
    }

    #[test]
    fn each_permitted_value_parses() {
        for (input, expected) in [
            ("TRACE", LogLevel::Trace),
            ("DEBUG", LogLevel::Debug),
            ("INFO", LogLevel::Info),
            ("WARN", LogLevel::Warn),
            ("ERROR", LogLevel::Error),
        ] {
            let cli = Cli::parse_from(["apokryphos-server", "--log-level", input]);
            assert_eq!(cli.log_level, expected, "input {input:?}");
        }
    }

    #[test]
    fn lowercase_input_rejected() {
        // We deliberately require uppercase canonical names (rename_all =
        // "UPPER"); lowercase variants are NOT accepted. Any future request
        // to accept case-insensitively must be a deliberate spec change.
        let result = Cli::try_parse_from(["apokryphos-server", "--log-level", "debug"]);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_value_is_rejected_with_listing() {
        let result = Cli::try_parse_from(["apokryphos-server", "--log-level", "VERBOSE"]);
        let err = result.expect_err("invalid value should fail to parse");
        let rendered = err.to_string();
        // SC-013(c) requires the rejection diagnostic to name the offending
        // value AND list the permitted set. clap's default `InvalidValue`
        // diagnostic does both.
        assert!(rendered.contains("VERBOSE"), "diagnostic must name offending value: {rendered}");
        // The diagnostic lists permitted values via clap's "possible values"
        // line — spot-check a couple.
        assert!(rendered.contains("TRACE"), "diagnostic must list permitted set: {rendered}");
        assert!(rendered.contains("INFO"), "diagnostic must list permitted set: {rendered}");
    }
}

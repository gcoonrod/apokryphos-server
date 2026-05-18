//! T035 — direct-FS-access lint (spec FR-012 / SC-008 / research.md R11).
//!
//! Enforces the Principle III "all block-storage backend I/O goes through
//! the `StorageProvider` trait" guarantee at the test-suite level. Greps
//! `server/src/` for any reference to `std::fs::*`, `tokio::fs::*`,
//! `std::os::unix::fs::*`, `nix::fs::*`, or `tempfile::*` and fails if
//! any match falls outside `server/src/storage/` (or `server/src/config/`,
//! which legitimately reads the config TOML at startup).
//!
//! Comment-only matches are filtered so internal documentation (and this
//! file itself) can name the forbidden APIs without tripping the test.

use std::process::Command;

/// Substring `match_line` returns to indicate this file's path appears.
/// We exempt `server/src/storage/`, plus `server/src/config/` (which
/// reads the config TOML at startup — a non-block-storage filesystem
/// access deliberately scoped to one module).
const ALLOWED_PREFIXES: &[&str] = &[
    "server/src/storage/",
    // Config file reads sit outside the StorageProvider trait by design.
    // The TOML config is not user-encrypted block data; it's operator
    // configuration loaded once at startup. See FR-012 intent in spec.
    "server/src/config/",
];

#[test]
fn no_direct_fs_calls_outside_storage_module() {
    // Run grep from the workspace root so its output paths are
    // workspace-relative.
    let workspace_root = std::env::current_dir()
        .expect("test cwd must be readable")
        .parent()
        .expect("server/ should have a parent (workspace root)")
        .to_path_buf();

    let output = Command::new("grep")
        .arg("-rnE")
        .arg("std::fs::|tokio::fs::|std::os::unix::fs::|nix::fs::|tempfile::")
        .arg("server/src/")
        .current_dir(&workspace_root)
        .output()
        .expect("grep must execute (is it installed?)");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut violations: Vec<&str> = Vec::new();

    for line in stdout.lines() {
        // Strip the "path:lineno:content" prefix to inspect the content.
        // grep -n output looks like: `server/src/foo.rs:123:    use std::fs;`
        let Some((location, content)) = line.split_once(':').and_then(|(p, rest)| {
            rest.split_once(':').map(|(lineno, content)| {
                let location = format!("{p}:{lineno}");
                (location, content)
            })
        }) else {
            continue;
        };

        // Filter out matches inside allowed module trees.
        if ALLOWED_PREFIXES
            .iter()
            .any(|prefix| location.starts_with(prefix))
        {
            continue;
        }

        // Filter out comment-only lines (// ... or //! ...). Crude but
        // effective: if the matching text is preceded only by whitespace
        // and a `//`, it's a comment.
        let trimmed = content.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }

        violations.push(line);
    }

    assert!(
        violations.is_empty(),
        "FR-012 violation: direct filesystem access detected outside \
         server/src/storage/ (and the allowed config/ exception).\n\
         Move the call into a `StorageProvider` method or fix the lint \
         exception in tests/no_direct_fs.rs.\n\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

//! Configuration loading, validation, and merging (FR-001..006, FR-011a, R14).
//!
//! Public surface (contracts/internal.md §"Module: config"):
//!   - ServerConfig, OidcAudienceConfig, StorageBackend
//!   - ConfigError
//!   - load() -> Result<ServerConfig, ConfigError>
//!   - load_from(env, toml_text) -> Result<ServerConfig, ConfigError>  [test-only]
//!
//! This module is the sole owner of env-var + filesystem access. No other
//! module reads `std::env` or the filesystem.

mod env;
mod error;
mod file;
mod merge;
mod server_config;
mod validate;

pub use error::ConfigError;
pub use server_config::{AuthConfig, OidcAudienceConfig, ServerConfig, StorageBackend};

pub(crate) use env::collect_env;
pub(crate) use file::load_optional_file;
pub(crate) use merge::env_overrides_file;
pub(crate) use validate::validate;

/// Production entry point: read env vars, optionally read TOML at
/// `APOK_CONFIG_PATH`, merge with env-overrides-file precedence, validate.
pub fn load() -> Result<ServerConfig, ConfigError> {
    let env_map = collect_apok_env()?;
    let env_partial = collect_env(&env_map);
    let toml_path = env_map
        .get("APOK_CONFIG_PATH")
        .cloned()
        .filter(|s| !s.is_empty());
    let file_partial = load_optional_file(toml_path.as_deref())?;
    let merged = env_overrides_file(env_partial, file_partial);
    validate(merged)
}

/// Collect `APOK_*` environment variables into a `BTreeMap`, using `vars_os`
/// so an unrelated non-UTF-8 variable elsewhere in the process environment
/// cannot panic startup. Non-UTF-8 keys are silently skipped (they cannot be
/// `APOK_*` since the prefix is ASCII); non-UTF-8 values on `APOK_*` keys
/// produce a `ConfigError::NonUnicodeEnv`.
fn collect_apok_env() -> Result<std::collections::BTreeMap<String, String>, ConfigError> {
    let mut map = std::collections::BTreeMap::new();
    for (key_os, val_os) in std::env::vars_os() {
        let Some(key) = key_os.to_str() else { continue };
        if !key.starts_with("APOK_") {
            continue;
        }
        let value = val_os
            .into_string()
            .map_err(|_| ConfigError::NonUnicodeEnv { key: key.to_string() })?;
        map.insert(key.to_string(), value);
    }
    Ok(map)
}

/// Test entry point. Accepts explicit env-var and TOML-text inputs so unit
/// tests need not touch the process environment or the filesystem.
/// Gated by `test-utils` so it does not appear in the release binary.
#[cfg(any(test, feature = "test-utils"))]
pub fn load_from(
    env: std::collections::BTreeMap<String, String>,
    toml_text: Option<&str>,
) -> Result<ServerConfig, ConfigError> {
    let env_partial = collect_env(&env);
    let file_partial = match toml_text {
        Some(text) => toml::from_str(text).map_err(|e| ConfigError::TomlParse { source: e })?,
        None => env::PartialConfig::default(),
    };
    let merged = env_overrides_file(env_partial, file_partial);
    validate(merged)
}

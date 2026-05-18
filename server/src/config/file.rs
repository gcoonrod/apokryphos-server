//! Optional TOML config file discovery via `APOK_CONFIG_PATH` (R14, invariant C7).

use std::path::Path;

use super::env::PartialConfig;
use super::error::ConfigError;

/// Load the optional TOML config file. Behavior matrix:
///
/// | `APOK_CONFIG_PATH` | Outcome |
/// |---|---|
/// | unset / empty (`None` here) | `Ok(PartialConfig::default())` — no file consulted |
/// | set, file exists, parses | `Ok(parsed_partial)` |
/// | set, file exists, malformed | `Err(ConfigError::TomlParse)` |
/// | set, nonexistent / unreadable | `Err(ConfigError::FileRead)` |
///
/// Silent-fallback on a typoed `APOK_CONFIG_PATH` would be a footgun (R14),
/// so a set-but-nonexistent path is a hard error.
pub fn load_optional_file(path: Option<&str>) -> Result<PartialConfig, ConfigError> {
    let Some(path_str) = path else {
        return Ok(PartialConfig::default());
    };
    let path = Path::new(path_str);
    let content = std::fs::read_to_string(path).map_err(|source| ConfigError::FileRead {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed: PartialConfig =
        toml::from_str(&content).map_err(|e| ConfigError::TomlParse { source: e })?;
    Ok(parsed)
}

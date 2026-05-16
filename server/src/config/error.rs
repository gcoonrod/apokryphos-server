//! `ConfigError` — every variant carries the offending key/value so the
//! operator-facing `Display` impl (consumed by `tracing::error!`) can name
//! it (FR-011a, invariant C2).

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required key {key} is absent from both env and TOML")]
    Missing { key: &'static str },

    #[error("invalid bind_address {value:?}: {source}")]
    InvalidBindAddress {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },

    #[error("block_size_bytes must be a positive integer, got {value:?}")]
    InvalidBlockSize { value: String },

    #[error("storage_backend must be \"none\" in this phase, got {value:?}")]
    InvalidStorageBackend { value: String },

    #[error("trusted_proxies entry {entry:?} at position {position} is not a valid CIDR: {source}")]
    InvalidCidr {
        entry: String,
        position: usize,
        #[source]
        source: ipnet::AddrParseError,
    },

    #[error("{audience}_oidc.issuer_url {value:?} is not a valid URL: {source}")]
    InvalidIssuerUrl {
        audience: &'static str,
        value: String,
        #[source]
        source: url::ParseError,
    },

    #[error("{audience}_oidc.audience is empty")]
    EmptyAudience { audience: &'static str },

    #[error("vault and admin audiences MUST be distinct (both = {value:?})")]
    DuplicateAudience { value: String },

    #[error("drain_timeout_secs must be a positive integer, got {value:?}")]
    InvalidDrainTimeout { value: String },

    #[error("failed to read config file at {path:?}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config file as TOML: {source}")]
    TomlParse {
        #[from]
        source: toml::de::Error,
    },

    #[error("environment variable {key} contains non-UTF-8 data")]
    NonUnicodeEnv { key: String },
}

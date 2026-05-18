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

    #[error("storage_backend must be \"none\" or \"local_fs\", got {value:?}")]
    InvalidStorageBackend { value: String },

    #[error(
        "storage_backend = \"local_fs\" requires [storage.local_fs] root = \"<path>\" (or APOK_STORAGE_LOCAL_FS_ROOT)"
    )]
    LocalFsRootMissing,

    #[error("storage.local_fs.root must be an absolute path, got {value:?}")]
    LocalFsRootNotAbsolute { value: PathBuf },

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

    #[error(
        "{audience}_oidc.issuer_url {value:?} must use scheme \"https\" per OIDC Discovery 1.0, got {scheme:?}"
    )]
    InvalidIssuerUrlScheme {
        audience: &'static str,
        value: String,
        scheme: String,
    },

    #[error(
        "{audience}_oidc.issuer_url {value:?} must not include a {component} component per OIDC Discovery 1.0"
    )]
    IssuerUrlHasComponent {
        audience: &'static str,
        value: String,
        component: &'static str,
    },

    #[error("{audience}_oidc.audience is empty")]
    EmptyAudience { audience: &'static str },

    #[error("vault and admin audiences MUST be distinct (both = {value:?})")]
    DuplicateAudience { value: String },

    #[error("drain_timeout_secs must be a positive integer, got {value:?}")]
    InvalidDrainTimeout { value: String },

    #[error("auth.{key} must be a positive integer, got {value:?}")]
    InvalidAuthDurationSecs { key: &'static str, value: String },

    #[error("auth.max_replay_entries must be an integer >= 1024, got {value:?}")]
    InvalidAuthMaxReplayEntries { value: String },

    #[error(
        "auth.jti_replay_window_secs ({window}) must be >= auth.dpop_freshness_secs ({freshness}) + auth.clock_skew_secs ({skew}) = {required}"
    )]
    AuthReplayWindowTooSmall {
        window: u64,
        freshness: u64,
        skew: u64,
        required: u64,
    },

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

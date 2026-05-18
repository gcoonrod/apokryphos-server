//! Typed, validated configuration entities (data-model.md §1, §2).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use super::error::ConfigError;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
    pub block_size_bytes: u64,
    pub storage_backend: StorageBackend,
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub vault_oidc: OidcAudienceConfig,
    pub admin_oidc: OidcAudienceConfig,
    pub drain_timeout: Duration,
    /// Phase 3 (FAPI 2.0 + DPoP) tuning knobs. Optional in TOML/env; defaults
    /// apply when the entire `[auth]` block is absent.
    pub auth: AuthConfig,
}

/// Phase 3 authentication tuning knobs. Seven configurable values, all
/// optional with sensible defaults. See data-model.md §AuthConfig +
/// spec §Assumptions for the rationale per field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// Maximum acceptable clock-skew (seconds) between this server and the
    /// OIDC issuer when validating `exp`/`nbf`/`iat`. Default 60.
    pub clock_skew_secs: u64,
    /// DPoP proof `iat` freshness window in seconds. Default 30.
    pub dpop_freshness_secs: u64,
    /// JWKS scheduled refresh interval in seconds. Default 3600 (1 hour).
    pub jwks_refresh_secs: u64,
    /// OIDC discovery document refresh interval in seconds. Independent of
    /// the JWKS timer (FR-003a). Default 86400 (24 hours).
    pub discovery_refresh_secs: u64,
    /// Minimum interval in seconds between on-demand JWKS refresh attempts
    /// for a given context (FR-004 rate limit). Default 30.
    pub on_demand_refresh_min_interval_secs: u64,
    /// DPoP `jti` replay-window duration in seconds. Default 90 (= 30 + 60
    /// when both freshness and skew use their defaults). Must satisfy
    /// `jti_replay_window_secs >= dpop_freshness_secs + clock_skew_secs`.
    pub jti_replay_window_secs: u64,
    /// In-process `JtiReplayStore` memory budget — maximum number of
    /// concurrent in-window entries before the FR-021 memory-pressure
    /// response (503) kicks in. Default 100_000.
    pub max_replay_entries: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        let clock_skew_secs = 60;
        let dpop_freshness_secs = 30;
        AuthConfig {
            clock_skew_secs,
            dpop_freshness_secs,
            jwks_refresh_secs: 3600,
            discovery_refresh_secs: 86_400,
            on_demand_refresh_min_interval_secs: 30,
            jti_replay_window_secs: dpop_freshness_secs + clock_skew_secs,
            max_replay_entries: 100_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackend {
    /// Phase 2 placeholder; constructable only in tests that mock at the
    /// trait level. Production configuration never resolves to this variant
    /// once Phase 4 ships.
    None,

    /// Phase 4 — local-filesystem backend. The `root` is validated at
    /// config-load (must be absolute) and re-validated at runtime startup
    /// (must exist, must be a directory, must accept a probe-write).
    /// See `storage::init_from_config` and spec FR-007/FR-011.
    LocalFs { root: PathBuf },
    // Phase 6: `S3 { bucket, region, endpoint_url, credentials_source }` — reserved.
}

#[derive(Debug, Clone)]
pub struct OidcAudienceConfig {
    pub issuer_url: url::Url,
    pub audience: String,
}

impl OidcAudienceConfig {
    /// Construct an OIDC audience config. `audience_name` is `"vault"` or
    /// `"admin"` — used only to label error messages so operators know which
    /// block is malformed (FR-004).
    ///
    /// Per OpenID Connect Discovery 1.0 §2 (and RFC 8414 §2), an issuer URL
    /// MUST use the `https` scheme and MUST NOT contain query or fragment
    /// components. Those constraints are enforced here so a malformed config
    /// fails at startup rather than at first-discovery-fetch in Phase 3.
    pub fn new(
        audience_name: &'static str,
        issuer_url: String,
        audience: String,
    ) -> Result<Self, ConfigError> {
        let parsed =
            url::Url::parse(&issuer_url).map_err(|source| ConfigError::InvalidIssuerUrl {
                audience: audience_name,
                value: issuer_url.clone(),
                source,
            })?;
        if parsed.scheme() != "https" {
            return Err(ConfigError::InvalidIssuerUrlScheme {
                audience: audience_name,
                value: issuer_url,
                scheme: parsed.scheme().to_string(),
            });
        }
        if parsed.query().is_some() {
            return Err(ConfigError::IssuerUrlHasComponent {
                audience: audience_name,
                value: issuer_url,
                component: "query",
            });
        }
        if parsed.fragment().is_some() {
            return Err(ConfigError::IssuerUrlHasComponent {
                audience: audience_name,
                value: issuer_url,
                component: "fragment",
            });
        }
        if audience.is_empty() {
            return Err(ConfigError::EmptyAudience {
                audience: audience_name,
            });
        }
        Ok(Self {
            issuer_url: parsed,
            audience,
        })
    }
}

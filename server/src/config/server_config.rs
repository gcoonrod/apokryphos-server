//! Typed, validated configuration entities (data-model.md §1, §2).

use std::net::SocketAddr;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    None,
    // S3, LocalFs — reserved for Phase 4. Not constructable in Phase 2.
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
        let parsed = url::Url::parse(&issuer_url).map_err(|source| ConfigError::InvalidIssuerUrl {
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

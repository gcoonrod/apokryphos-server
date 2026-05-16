//! Validation: turn a fully-merged `PartialConfig` into a `ServerConfig`
//! or return a `ConfigError` naming the offending key (FR-002..006, FR-005,
//! FR-011a, Clarify-Q4).

use std::net::SocketAddr;
use std::time::Duration;

use super::env::{PartialConfig, PartialOidc, TrustedProxiesSource};
use super::error::ConfigError;
use super::server_config::{OidcAudienceConfig, ServerConfig, StorageBackend};

const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;

pub fn validate(p: PartialConfig) -> Result<ServerConfig, ConfigError> {
    let bind_address = parse_bind_address(p.bind_address)?;
    let block_size_bytes = parse_positive_u64(
        "APOK_BLOCK_SIZE_BYTES",
        p.block_size_bytes,
        |v| ConfigError::InvalidBlockSize { value: v },
    )?
    .ok_or(ConfigError::Missing {
        key: "block_size_bytes",
    })?;
    let storage_backend = parse_storage_backend(p.storage_backend)?;
    let trusted_proxies = parse_trusted_proxies(p.trusted_proxies)?;
    let drain_timeout = parse_drain_timeout(p.drain_timeout_secs)?;
    let vault_oidc = parse_oidc("vault", p.vault_oidc)?;
    let admin_oidc = parse_oidc("admin", p.admin_oidc)?;

    if vault_oidc.audience == admin_oidc.audience {
        return Err(ConfigError::DuplicateAudience {
            value: vault_oidc.audience,
        });
    }

    Ok(ServerConfig {
        bind_address,
        block_size_bytes,
        storage_backend,
        trusted_proxies,
        vault_oidc,
        admin_oidc,
        drain_timeout,
    })
}

fn parse_bind_address(value: Option<String>) -> Result<SocketAddr, ConfigError> {
    let v = value.ok_or(ConfigError::Missing { key: "bind_address" })?;
    v.parse::<SocketAddr>().map_err(|source| ConfigError::InvalidBindAddress { value: v, source })
}

/// Parse a TOML scalar (integer or string) as a positive `u64`. Returns `None`
/// only if the input was `None`; the caller decides whether absence is allowed.
fn parse_positive_u64(
    _env_name: &'static str,
    value: Option<toml::Value>,
    invalid: impl FnOnce(String) -> ConfigError,
) -> Result<Option<u64>, ConfigError> {
    let Some(v) = value else { return Ok(None) };
    let parsed: u64 = match &v {
        toml::Value::Integer(n) if *n > 0 => *n as u64,
        toml::Value::Integer(n) => return Err(invalid(n.to_string())),
        toml::Value::String(s) => s
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| invalid(s.clone()))?,
        other => return Err(invalid(other.to_string())),
    };
    Ok(Some(parsed))
}

fn parse_storage_backend(value: Option<String>) -> Result<StorageBackend, ConfigError> {
    let v = value.ok_or(ConfigError::Missing {
        key: "storage_backend",
    })?;
    match v.as_str() {
        "none" => Ok(StorageBackend::None),
        _ => Err(ConfigError::InvalidStorageBackend { value: v }),
    }
}

fn parse_trusted_proxies(value: Option<TrustedProxiesSource>) -> Result<Vec<ipnet::IpNet>, ConfigError> {
    let entries: Vec<String> = match value {
        // The key must be present (FR-006) — but both an empty array and an
        // empty CSV are valid empty lists per R14/C8.
        None => return Err(ConfigError::Missing { key: "trusted_proxies" }),
        Some(TrustedProxiesSource::List(v)) => v,
        Some(TrustedProxiesSource::Csv(s)) if s.is_empty() => Vec::new(),
        Some(TrustedProxiesSource::Csv(s)) => s.split(',').map(|e| e.trim().to_string()).collect(),
    };

    let mut nets = Vec::with_capacity(entries.len());
    for (position, entry) in entries.iter().enumerate() {
        if entry.is_empty() {
            return Err(ConfigError::InvalidCidr {
                entry: entry.clone(),
                position,
                source: "".parse::<ipnet::IpNet>().unwrap_err(),
            });
        }
        let net = entry.parse::<ipnet::IpNet>().map_err(|source| ConfigError::InvalidCidr {
            entry: entry.clone(),
            position,
            source,
        })?;
        nets.push(net);
    }
    Ok(nets)
}

fn parse_drain_timeout(value: Option<toml::Value>) -> Result<Duration, ConfigError> {
    let secs = parse_positive_u64(
        "APOK_DRAIN_TIMEOUT_SECS",
        value,
        |v| ConfigError::InvalidDrainTimeout { value: v },
    )?
    .unwrap_or(DEFAULT_DRAIN_TIMEOUT_SECS);
    Ok(Duration::from_secs(secs))
}

fn parse_oidc(
    audience_name: &'static str,
    value: Option<PartialOidc>,
) -> Result<OidcAudienceConfig, ConfigError> {
    let Some(o) = value else {
        return Err(ConfigError::Missing {
            key: oidc_missing_key(audience_name, "issuer_url"),
        });
    };
    let issuer = o.issuer_url.ok_or(ConfigError::Missing {
        key: oidc_missing_key(audience_name, "issuer_url"),
    })?;
    let audience = o.audience.ok_or(ConfigError::Missing {
        key: oidc_missing_key(audience_name, "audience"),
    })?;
    OidcAudienceConfig::new(audience_name, issuer, audience)
}

fn oidc_missing_key(audience_name: &'static str, field: &'static str) -> &'static str {
    match (audience_name, field) {
        ("vault", "issuer_url") => "vault_oidc.issuer_url",
        ("vault", "audience") => "vault_oidc.audience",
        ("admin", "issuer_url") => "admin_oidc.issuer_url",
        ("admin", "audience") => "admin_oidc.audience",
        _ => unreachable!("oidc_missing_key: unexpected audience/field combination"),
    }
}

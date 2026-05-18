//! Validation: turn a fully-merged `PartialConfig` into a `ServerConfig`
//! or return a `ConfigError` naming the offending key (FR-002..006, FR-005,
//! FR-011a, Clarify-Q4).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use super::env::{PartialAuth, PartialConfig, PartialOidc, PartialStorage, TrustedProxiesSource};
use super::error::ConfigError;
use super::server_config::{AuthConfig, OidcAudienceConfig, ServerConfig, StorageBackend};

const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;
const MIN_REPLAY_ENTRIES: usize = 1024;

pub fn validate(p: PartialConfig) -> Result<ServerConfig, ConfigError> {
    let bind_address = parse_bind_address(p.bind_address)?;
    let block_size_bytes = parse_positive_u64("APOK_BLOCK_SIZE_BYTES", p.block_size_bytes, |v| {
        ConfigError::InvalidBlockSize { value: v }
    })?
    .ok_or(ConfigError::Missing {
        key: "block_size_bytes",
    })?;
    let storage_backend = parse_storage_backend(p.storage_backend, p.storage)?;
    let trusted_proxies = parse_trusted_proxies(p.trusted_proxies)?;
    let drain_timeout = parse_drain_timeout(p.drain_timeout_secs)?;
    let vault_oidc = parse_oidc("vault", p.vault_oidc)?;
    let admin_oidc = parse_oidc("admin", p.admin_oidc)?;

    if vault_oidc.audience == admin_oidc.audience {
        return Err(ConfigError::DuplicateAudience {
            value: vault_oidc.audience,
        });
    }

    let auth = parse_auth(p.auth)?;

    Ok(ServerConfig {
        bind_address,
        block_size_bytes,
        storage_backend,
        trusted_proxies,
        vault_oidc,
        admin_oidc,
        drain_timeout,
        auth,
    })
}

/// Resolve the `[auth]` block to a fully-validated `AuthConfig`. The block
/// is optional; absent → `AuthConfig::default()`. Each field is also
/// individually optional within the block. Per-field validation runs
/// before the cross-field invariant.
fn parse_auth(partial: Option<PartialAuth>) -> Result<AuthConfig, ConfigError> {
    let defaults = AuthConfig::default();
    let Some(p) = partial else {
        return Ok(defaults);
    };

    let clock_skew_secs = parse_auth_positive_u64("clock_skew_secs", p.clock_skew_secs)?
        .unwrap_or(defaults.clock_skew_secs);
    let dpop_freshness_secs =
        parse_auth_positive_u64("dpop_freshness_secs", p.dpop_freshness_secs)?
            .unwrap_or(defaults.dpop_freshness_secs);
    let jwks_refresh_secs = parse_auth_positive_u64("jwks_refresh_secs", p.jwks_refresh_secs)?
        .unwrap_or(defaults.jwks_refresh_secs);
    let discovery_refresh_secs =
        parse_auth_positive_u64("discovery_refresh_secs", p.discovery_refresh_secs)?
            .unwrap_or(defaults.discovery_refresh_secs);
    let on_demand_refresh_min_interval_secs = parse_auth_positive_u64(
        "on_demand_refresh_min_interval_secs",
        p.on_demand_refresh_min_interval_secs,
    )?
    .unwrap_or(defaults.on_demand_refresh_min_interval_secs);
    // Cross-field invariant: replay window must cover freshness + skew.
    // Use `checked_add` to surface adversarial env values
    // (e.g. APOK_AUTH_DPOP_FRESHNESS_SECS=18446744073709551615) as a
    // typed ConfigError rather than panicking (debug) or wrapping
    // (release). The same sum is the default for `jti_replay_window_secs`
    // when the operator omits that key, so we compute it once and reuse.
    let required = dpop_freshness_secs.checked_add(clock_skew_secs).ok_or(
        ConfigError::AuthReplayWindowTooSmall {
            window: 0,
            freshness: dpop_freshness_secs,
            skew: clock_skew_secs,
            required: u64::MAX, // signals "overflow"; Display impl shows the offending sum
        },
    )?;
    let jti_replay_window_secs =
        parse_auth_positive_u64("jti_replay_window_secs", p.jti_replay_window_secs)?
            .unwrap_or(required);
    let max_replay_entries =
        parse_max_replay_entries(p.max_replay_entries)?.unwrap_or(defaults.max_replay_entries);

    if jti_replay_window_secs < required {
        return Err(ConfigError::AuthReplayWindowTooSmall {
            window: jti_replay_window_secs,
            freshness: dpop_freshness_secs,
            skew: clock_skew_secs,
            required,
        });
    }

    Ok(AuthConfig {
        clock_skew_secs,
        dpop_freshness_secs,
        jwks_refresh_secs,
        discovery_refresh_secs,
        on_demand_refresh_min_interval_secs,
        jti_replay_window_secs,
        max_replay_entries,
    })
}

fn parse_auth_positive_u64(
    key: &'static str,
    value: Option<toml::Value>,
) -> Result<Option<u64>, ConfigError> {
    parse_positive_u64(key, value, move |v| ConfigError::InvalidAuthDurationSecs {
        key,
        value: v,
    })
}

fn parse_max_replay_entries(value: Option<toml::Value>) -> Result<Option<usize>, ConfigError> {
    let Some(v) = value else { return Ok(None) };
    let parsed: u64 = match &v {
        toml::Value::Integer(n) if *n >= MIN_REPLAY_ENTRIES as i64 => *n as u64,
        toml::Value::Integer(n) => {
            return Err(ConfigError::InvalidAuthMaxReplayEntries {
                value: n.to_string(),
            });
        }
        toml::Value::String(s) => s
            .parse::<u64>()
            .ok()
            .filter(|n| *n >= MIN_REPLAY_ENTRIES as u64)
            .ok_or_else(|| ConfigError::InvalidAuthMaxReplayEntries { value: s.clone() })?,
        other => {
            return Err(ConfigError::InvalidAuthMaxReplayEntries {
                value: other.to_string(),
            });
        }
    };
    // `parsed as usize` silently truncates on 32-bit Unix targets — a
    // value like 4_294_967_296 passes the u64 >= 1024 check but maps to
    // 0 as usize, causing the replay store to reject every insert as
    // memory pressure. Use a checked conversion so misconfiguration
    // becomes a typed ConfigError instead.
    let as_usize =
        usize::try_from(parsed).map_err(|_| ConfigError::InvalidAuthMaxReplayEntries {
            value: parsed.to_string(),
        })?;
    Ok(Some(as_usize))
}

fn parse_bind_address(value: Option<String>) -> Result<SocketAddr, ConfigError> {
    let v = value.ok_or(ConfigError::Missing {
        key: "bind_address",
    })?;
    v.parse::<SocketAddr>()
        .map_err(|source| ConfigError::InvalidBindAddress { value: v, source })
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

fn parse_storage_backend(
    discriminator: Option<String>,
    storage_block: Option<PartialStorage>,
) -> Result<StorageBackend, ConfigError> {
    let v = discriminator.ok_or(ConfigError::Missing {
        key: "storage_backend",
    })?;
    match v.as_str() {
        "none" => Ok(StorageBackend::None),
        "local_fs" => {
            let root = storage_block
                .and_then(|s| s.local_fs)
                .and_then(|lfs| lfs.root)
                .ok_or(ConfigError::LocalFsRootMissing)?;
            let path = PathBuf::from(root);
            if !path.is_absolute() {
                return Err(ConfigError::LocalFsRootNotAbsolute { value: path });
            }
            Ok(StorageBackend::LocalFs { root: path })
        }
        _ => Err(ConfigError::InvalidStorageBackend { value: v }),
    }
}

fn parse_trusted_proxies(
    value: Option<TrustedProxiesSource>,
) -> Result<Vec<ipnet::IpNet>, ConfigError> {
    let entries: Vec<String> = match value {
        // The key must be present (FR-006) — but both an empty array and an
        // empty CSV are valid empty lists per R14/C8.
        None => {
            return Err(ConfigError::Missing {
                key: "trusted_proxies",
            });
        }
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
        let net = entry
            .parse::<ipnet::IpNet>()
            .map_err(|source| ConfigError::InvalidCidr {
                entry: entry.clone(),
                position,
                source,
            })?;
        nets.push(net);
    }
    Ok(nets)
}

fn parse_drain_timeout(value: Option<toml::Value>) -> Result<Duration, ConfigError> {
    let secs = parse_positive_u64("APOK_DRAIN_TIMEOUT_SECS", value, |v| {
        ConfigError::InvalidDrainTimeout { value: v }
    })?
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

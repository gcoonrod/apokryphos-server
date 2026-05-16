//! Env-var ↔ TOML key mapping (R14, invariants C2/C8/C9).
//!
//! The canonical key form is the TOML form: lowercase, snake_case, dot-separated.
//! The env-var form is derived by: uppercase + replace `.` with `_` + prefix `APOK_`.
//! Lookup is case-sensitive — `apok_bind_address=...` is treated as absent (C9).

use std::collections::BTreeMap;

use serde::Deserialize;

/// In-memory partial configuration. All fields are `Option<_>` so that
/// "absent" can be distinguished from "present but invalid". The TOML
/// deserializer populates this, env vars populate a separate instance,
/// and `merge` combines them with env-overrides-file precedence.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PartialConfig {
    pub bind_address: Option<String>,
    pub block_size_bytes: Option<toml::Value>,
    pub storage_backend: Option<String>,
    pub trusted_proxies: Option<TrustedProxiesSource>,
    pub drain_timeout_secs: Option<toml::Value>,
    pub vault_oidc: Option<PartialOidc>,
    pub admin_oidc: Option<PartialOidc>,
    /// Phase 3 — optional `[auth]` block carrying tuning knobs for the
    /// FAPI 2.0 + DPoP authentication core. Absent → all defaults apply.
    pub auth: Option<PartialAuth>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PartialOidc {
    pub issuer_url: Option<String>,
    pub audience: Option<String>,
}

/// Partial `[auth]` block. Every field is optional; absent → use the
/// corresponding `AuthConfig::default()` value. Values come in as
/// `toml::Value` so the env-form (string) and TOML-form (integer) paths
/// can both be parsed by the same validator.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PartialAuth {
    pub clock_skew_secs: Option<toml::Value>,
    pub dpop_freshness_secs: Option<toml::Value>,
    pub jwks_refresh_secs: Option<toml::Value>,
    pub discovery_refresh_secs: Option<toml::Value>,
    pub on_demand_refresh_min_interval_secs: Option<toml::Value>,
    pub jti_replay_window_secs: Option<toml::Value>,
    pub max_replay_entries: Option<toml::Value>,
}

/// `trusted_proxies` accepts either a TOML array (file form) or a
/// comma-separated string (env form). `validate` converts to `Vec<IpNet>`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TrustedProxiesSource {
    /// TOML array form: `trusted_proxies = ["192.168.1.0/24"]`.
    List(Vec<String>),
    /// Env or TOML-as-string form: `"192.168.1.0/24,10.0.0.5/32"`.
    /// The literal empty string means "no proxy is trusted" (R14).
    Csv(String),
}

/// Collect env vars into a `PartialConfig` following the R14 mapping rule.
/// The case-sensitive uppercase canonical names are matched verbatim.
pub fn collect_env(env: &BTreeMap<String, String>) -> PartialConfig {
    let mut p = PartialConfig::default();

    if let Some(v) = env.get("APOK_BIND_ADDRESS") {
        p.bind_address = Some(v.clone());
    }
    if let Some(v) = env.get("APOK_BLOCK_SIZE_BYTES") {
        p.block_size_bytes = Some(toml::Value::String(v.clone()));
    }
    if let Some(v) = env.get("APOK_STORAGE_BACKEND") {
        p.storage_backend = Some(v.clone());
    }
    if let Some(v) = env.get("APOK_TRUSTED_PROXIES") {
        // Env form is comma-separated; empty string = empty list (R14, C8).
        p.trusted_proxies = Some(TrustedProxiesSource::Csv(v.clone()));
    }
    if let Some(v) = env.get("APOK_DRAIN_TIMEOUT_SECS") {
        p.drain_timeout_secs = Some(toml::Value::String(v.clone()));
    }

    let mut vault = PartialOidc::default();
    if let Some(v) = env.get("APOK_VAULT_OIDC_ISSUER_URL") {
        vault.issuer_url = Some(v.clone());
    }
    if let Some(v) = env.get("APOK_VAULT_OIDC_AUDIENCE") {
        vault.audience = Some(v.clone());
    }
    if vault.issuer_url.is_some() || vault.audience.is_some() {
        p.vault_oidc = Some(vault);
    }

    let mut admin = PartialOidc::default();
    if let Some(v) = env.get("APOK_ADMIN_OIDC_ISSUER_URL") {
        admin.issuer_url = Some(v.clone());
    }
    if let Some(v) = env.get("APOK_ADMIN_OIDC_AUDIENCE") {
        admin.audience = Some(v.clone());
    }
    if admin.issuer_url.is_some() || admin.audience.is_some() {
        p.admin_oidc = Some(admin);
    }

    // Phase 3 — `[auth]` block (FAPI 2.0 + DPoP tuning knobs).
    // Env vars map under the `APOK_AUTH_*` prefix per the Phase 2 R14 rule.
    let mut auth = PartialAuth::default();
    let mut any_auth_field = false;
    for (env_key, target) in [
        ("APOK_AUTH_CLOCK_SKEW_SECS", &mut auth.clock_skew_secs),
        ("APOK_AUTH_DPOP_FRESHNESS_SECS", &mut auth.dpop_freshness_secs),
        ("APOK_AUTH_JWKS_REFRESH_SECS", &mut auth.jwks_refresh_secs),
        ("APOK_AUTH_DISCOVERY_REFRESH_SECS", &mut auth.discovery_refresh_secs),
        (
            "APOK_AUTH_ON_DEMAND_REFRESH_MIN_INTERVAL_SECS",
            &mut auth.on_demand_refresh_min_interval_secs,
        ),
        (
            "APOK_AUTH_JTI_REPLAY_WINDOW_SECS",
            &mut auth.jti_replay_window_secs,
        ),
        ("APOK_AUTH_MAX_REPLAY_ENTRIES", &mut auth.max_replay_entries),
    ] {
        if let Some(v) = env.get(env_key) {
            *target = Some(toml::Value::String(v.clone()));
            any_auth_field = true;
        }
    }
    if any_auth_field {
        p.auth = Some(auth);
    }

    p
}

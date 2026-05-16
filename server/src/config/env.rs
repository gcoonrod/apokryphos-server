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
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PartialOidc {
    pub issuer_url: Option<String>,
    pub audience: Option<String>,
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

    p
}

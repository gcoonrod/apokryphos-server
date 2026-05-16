//! T009: Config-load test matrix covering FR-002..006, FR-005, FR-011a, and
//! R14's env/TOML mapping rule. Every test calls `config::load_from` with
//! explicit inputs so the process environment and filesystem are not touched.

mod common;

use std::collections::BTreeMap;

use apokryphos_server::config::{ConfigError, load_from};

/// All eight required keys present and valid. Other tests start from this.
fn full_env() -> BTreeMap<String, String> {
    let mut e = BTreeMap::new();
    e.insert("APOK_BIND_ADDRESS".into(), "127.0.0.1:8080".into());
    e.insert("APOK_BLOCK_SIZE_BYTES".into(), "1048576".into());
    e.insert("APOK_STORAGE_BACKEND".into(), "none".into());
    e.insert("APOK_TRUSTED_PROXIES".into(), "".into());
    e.insert(
        "APOK_VAULT_OIDC_ISSUER_URL".into(),
        "https://issuer.example.invalid/vault".into(),
    );
    e.insert("APOK_VAULT_OIDC_AUDIENCE".into(), "apokryphos-vault".into());
    e.insert(
        "APOK_ADMIN_OIDC_ISSUER_URL".into(),
        "https://issuer.example.invalid/admin".into(),
    );
    e.insert("APOK_ADMIN_OIDC_AUDIENCE".into(), "apokryphos-admin".into());
    e
}

#[test]
fn full_env_validates() {
    let cfg = load_from(full_env(), None).expect("full env should validate");
    assert_eq!(cfg.bind_address.to_string(), "127.0.0.1:8080");
    assert_eq!(cfg.block_size_bytes, 1_048_576);
    assert_eq!(cfg.drain_timeout.as_secs(), 30); // Clarify-Q4 default
    assert!(cfg.trusted_proxies.is_empty());
    assert_eq!(cfg.vault_oidc.audience, "apokryphos-vault");
    assert_eq!(cfg.admin_oidc.audience, "apokryphos-admin");
}

// ─────────────────── FR-002 missing-key matrix (SC-002) ──────────────────

fn assert_missing_key(removed: &str, expected_key: &str) {
    let mut env = full_env();
    env.remove(removed);
    let err = load_from(env, None).expect_err("expected ConfigError for missing key");
    match err {
        ConfigError::Missing { key } => {
            assert_eq!(key, expected_key, "wrong key reported for missing {removed}")
        }
        other => panic!("expected ConfigError::Missing for {removed}, got {other:?}"),
    }
}

#[test]
fn missing_bind_address() {
    assert_missing_key("APOK_BIND_ADDRESS", "bind_address");
}

#[test]
fn missing_block_size_bytes() {
    assert_missing_key("APOK_BLOCK_SIZE_BYTES", "block_size_bytes");
}

#[test]
fn missing_storage_backend() {
    assert_missing_key("APOK_STORAGE_BACKEND", "storage_backend");
}

#[test]
fn missing_trusted_proxies() {
    assert_missing_key("APOK_TRUSTED_PROXIES", "trusted_proxies");
}

#[test]
fn missing_vault_issuer_url() {
    assert_missing_key("APOK_VAULT_OIDC_ISSUER_URL", "vault_oidc.issuer_url");
}

#[test]
fn missing_vault_audience() {
    assert_missing_key("APOK_VAULT_OIDC_AUDIENCE", "vault_oidc.audience");
}

#[test]
fn missing_admin_issuer_url() {
    assert_missing_key("APOK_ADMIN_OIDC_ISSUER_URL", "admin_oidc.issuer_url");
}

#[test]
fn missing_admin_audience() {
    assert_missing_key("APOK_ADMIN_OIDC_AUDIENCE", "admin_oidc.audience");
}

// ─────────────────── FR-005 distinctness ─────────────────────────────────

#[test]
fn duplicate_audiences_rejected() {
    let mut env = full_env();
    env.insert("APOK_VAULT_OIDC_AUDIENCE".into(), "shared".into());
    env.insert("APOK_ADMIN_OIDC_AUDIENCE".into(), "shared".into());
    let err = load_from(env, None).expect_err("duplicate audience should fail");
    assert!(matches!(err, ConfigError::DuplicateAudience { .. }));
}

#[test]
fn shared_issuer_distinct_audiences_validates() {
    // spec Edge Case: a single provider may issue tokens for two audiences.
    let mut env = full_env();
    env.insert(
        "APOK_VAULT_OIDC_ISSUER_URL".into(),
        "https://issuer.example.invalid/shared".into(),
    );
    env.insert(
        "APOK_ADMIN_OIDC_ISSUER_URL".into(),
        "https://issuer.example.invalid/shared".into(),
    );
    let cfg = load_from(env, None).expect("shared issuer, distinct audiences must validate");
    assert_eq!(cfg.vault_oidc.issuer_url, cfg.admin_oidc.issuer_url);
    assert_ne!(cfg.vault_oidc.audience, cfg.admin_oidc.audience);
}

// ─────────────────── FR-006 CIDR list parsing ────────────────────────────

#[test]
fn trusted_proxies_csv_parses() {
    let mut env = full_env();
    env.insert(
        "APOK_TRUSTED_PROXIES".into(),
        "192.168.1.0/24, 10.0.0.5/32".into(),
    );
    let cfg = load_from(env, None).expect("valid CIDR list should validate");
    assert_eq!(cfg.trusted_proxies.len(), 2);
}

#[test]
fn trusted_proxies_empty_string_yields_empty_list() {
    let mut env = full_env();
    env.insert("APOK_TRUSTED_PROXIES".into(), "".into());
    let cfg = load_from(env, None).expect("empty trusted_proxies is valid");
    assert!(cfg.trusted_proxies.is_empty());
}

#[test]
fn invalid_cidr_rejected_with_position() {
    let mut env = full_env();
    env.insert(
        "APOK_TRUSTED_PROXIES".into(),
        "192.168.1.0/24,not-a-cidr".into(),
    );
    let err = load_from(env, None).expect_err("invalid CIDR should fail");
    match err {
        ConfigError::InvalidCidr { entry, position, .. } => {
            assert_eq!(entry, "not-a-cidr");
            assert_eq!(position, 1);
        }
        other => panic!("expected InvalidCidr, got {other:?}"),
    }
}

// ─────────────────── R14 env-overrides-TOML precedence ───────────────────

#[test]
fn env_overrides_toml() {
    let toml = r#"
bind_address = "10.0.0.1:9090"
block_size_bytes = 4096
storage_backend = "none"
trusted_proxies = []

[vault_oidc]
issuer_url = "https://toml-vault.invalid"
audience = "toml-vault"

[admin_oidc]
issuer_url = "https://toml-admin.invalid"
audience = "toml-admin"
"#;
    let env = full_env(); // Sets APOK_BIND_ADDRESS=127.0.0.1:8080
    let cfg = load_from(env, Some(toml)).expect("env-overrides-toml must validate");
    // Env wins for bind_address despite TOML setting 10.0.0.1:9090
    assert_eq!(cfg.bind_address.to_string(), "127.0.0.1:8080");
}

// ─────────────────── Validation: invalid scalar values ───────────────────

#[test]
fn invalid_bind_address_rejected() {
    let mut env = full_env();
    env.insert("APOK_BIND_ADDRESS".into(), "not-an-address".into());
    let err = load_from(env, None).expect_err("malformed bind_address should fail");
    assert!(matches!(err, ConfigError::InvalidBindAddress { .. }));
}

#[test]
fn zero_block_size_rejected() {
    let mut env = full_env();
    env.insert("APOK_BLOCK_SIZE_BYTES".into(), "0".into());
    let err = load_from(env, None).expect_err("zero block size should fail");
    assert!(matches!(err, ConfigError::InvalidBlockSize { .. }));
}

#[test]
fn non_none_storage_backend_rejected() {
    let mut env = full_env();
    env.insert("APOK_STORAGE_BACKEND".into(), "s3".into());
    let err = load_from(env, None).expect_err("non-none storage_backend should fail");
    assert!(matches!(err, ConfigError::InvalidStorageBackend { .. }));
}

#[test]
fn empty_vault_audience_rejected() {
    let mut env = full_env();
    env.insert("APOK_VAULT_OIDC_AUDIENCE".into(), "".into());
    let err = load_from(env, None).expect_err("empty audience should fail");
    assert!(matches!(err, ConfigError::EmptyAudience { audience: "vault" }));
}

#[test]
fn invalid_issuer_url_rejected() {
    let mut env = full_env();
    env.insert("APOK_VAULT_OIDC_ISSUER_URL".into(), "not a url".into());
    let err = load_from(env, None).expect_err("malformed URL should fail");
    assert!(matches!(err, ConfigError::InvalidIssuerUrl { audience: "vault", .. }));
}

#[test]
fn invalid_drain_timeout_rejected() {
    let mut env = full_env();
    env.insert("APOK_DRAIN_TIMEOUT_SECS".into(), "0".into());
    let err = load_from(env, None).expect_err("zero drain timeout should fail");
    assert!(matches!(err, ConfigError::InvalidDrainTimeout { .. }));
}

#[test]
fn drain_timeout_optional_defaults_to_30() {
    let cfg = load_from(full_env(), None).expect("config should validate");
    assert_eq!(cfg.drain_timeout.as_secs(), 30);
}

#[test]
fn drain_timeout_explicit_value_honored() {
    let mut env = full_env();
    env.insert("APOK_DRAIN_TIMEOUT_SECS".into(), "15".into());
    let cfg = load_from(env, None).expect("explicit drain timeout should validate");
    assert_eq!(cfg.drain_timeout.as_secs(), 15);
}

// ─────────────────── R14 case-sensitivity ────────────────────────────────

#[test]
fn lowercase_env_name_is_treated_as_absent() {
    let mut env = full_env();
    env.remove("APOK_BIND_ADDRESS");
    env.insert("apok_bind_address".into(), "127.0.0.1:8080".into());
    let err = load_from(env, None).expect_err("lowercase env is not recognized");
    assert!(matches!(err, ConfigError::Missing { key: "bind_address" }));
}

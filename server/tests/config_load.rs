//! T009: Config-load test matrix covering FR-002..006, FR-005, FR-011a, and
//! R14's env/TOML mapping rule. Every test calls `config::load_from` with
//! explicit inputs so the process environment and filesystem are not touched.

mod common;

use std::collections::BTreeMap;

use apokryphos_server::config::{AuthConfig, ConfigError, load_from};

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
            assert_eq!(
                key, expected_key,
                "wrong key reported for missing {removed}"
            )
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
        ConfigError::InvalidCidr {
            entry, position, ..
        } => {
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
    assert!(matches!(
        err,
        ConfigError::EmptyAudience { audience: "vault" }
    ));
}

#[test]
fn invalid_issuer_url_rejected() {
    let mut env = full_env();
    env.insert("APOK_VAULT_OIDC_ISSUER_URL".into(), "not a url".into());
    let err = load_from(env, None).expect_err("malformed URL should fail");
    assert!(matches!(
        err,
        ConfigError::InvalidIssuerUrl {
            audience: "vault",
            ..
        }
    ));
}

#[test]
fn issuer_url_http_scheme_rejected() {
    let mut env = full_env();
    env.insert(
        "APOK_VAULT_OIDC_ISSUER_URL".into(),
        "http://issuer.invalid/v".into(),
    );
    let err = load_from(env, None).expect_err("http scheme should fail per OIDC Discovery 1.0");
    assert!(matches!(
        err,
        ConfigError::InvalidIssuerUrlScheme { audience: "vault", ref scheme, .. } if scheme == "http"
    ));
}

#[test]
fn issuer_url_mailto_scheme_rejected() {
    let mut env = full_env();
    env.insert(
        "APOK_VAULT_OIDC_ISSUER_URL".into(),
        "mailto:issuer@example.com".into(),
    );
    let err = load_from(env, None).expect_err("non-https scheme should fail");
    assert!(matches!(
        err,
        ConfigError::InvalidIssuerUrlScheme { audience: "vault", ref scheme, .. } if scheme == "mailto"
    ));
}

#[test]
fn issuer_url_with_query_rejected() {
    let mut env = full_env();
    env.insert(
        "APOK_VAULT_OIDC_ISSUER_URL".into(),
        "https://issuer.invalid/v?foo=bar".into(),
    );
    let err = load_from(env, None).expect_err("query component should fail");
    assert!(matches!(
        err,
        ConfigError::IssuerUrlHasComponent {
            audience: "vault",
            component: "query",
            ..
        }
    ));
}

#[test]
fn issuer_url_with_fragment_rejected() {
    let mut env = full_env();
    env.insert(
        "APOK_ADMIN_OIDC_ISSUER_URL".into(),
        "https://issuer.invalid/a#frag".into(),
    );
    let err = load_from(env, None).expect_err("fragment component should fail");
    assert!(matches!(
        err,
        ConfigError::IssuerUrlHasComponent {
            audience: "admin",
            component: "fragment",
            ..
        }
    ));
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
    assert!(matches!(
        err,
        ConfigError::Missing {
            key: "bind_address"
        }
    ));
}

// ─────────────────── Phase 3 [auth] block coverage ───────────────────────
//
// Added in PR #4 review (Copilot) to close the test-coverage gap on the
// new `[auth]` config surface. The seven tests below mirror the pattern
// the rest of this file uses for the other config sections: positive
// control, per-field positive integer parsing, per-field rejection,
// `max_replay_entries` minimum, cross-field invariant, env-overrides-TOML.

#[test]
fn auth_block_absent_yields_defaults() {
    // Full env, no TOML, no [auth] keys → AuthConfig::default() applied.
    let cfg = load_from(full_env(), None).expect("absent [auth] block should be valid");
    assert_eq!(cfg.auth, AuthConfig::default());
}

#[test]
fn auth_duration_field_positive_toml() {
    let toml = r#"
        bind_address = "127.0.0.1:8080"
        block_size_bytes = 1048576
        storage_backend = "none"
        trusted_proxies = []

        [vault_oidc]
        issuer_url = "https://issuer.example.invalid/vault"
        audience = "apokryphos-vault"

        [admin_oidc]
        issuer_url = "https://issuer.example.invalid/admin"
        audience = "apokryphos-admin"

        [auth]
        clock_skew_secs = 120
        dpop_freshness_secs = 45
    "#;
    let cfg =
        load_from(BTreeMap::new(), Some(toml)).expect("auth TOML with overrides should validate");
    assert_eq!(cfg.auth.clock_skew_secs, 120);
    assert_eq!(cfg.auth.dpop_freshness_secs, 45);
    // Other fields keep their defaults.
    assert_eq!(cfg.auth.jwks_refresh_secs, 3600);
    assert_eq!(cfg.auth.discovery_refresh_secs, 86_400);
}

#[test]
fn auth_duration_field_zero_rejected() {
    let mut env = full_env();
    env.insert("APOK_AUTH_CLOCK_SKEW_SECS".into(), "0".into());
    let err = load_from(env, None).expect_err("zero duration should be rejected");
    match err {
        ConfigError::InvalidAuthDurationSecs { key, value } => {
            assert_eq!(key, "clock_skew_secs");
            assert_eq!(value, "0");
        }
        other => panic!("expected InvalidAuthDurationSecs, got {other:?}"),
    }
}

#[test]
fn auth_max_replay_entries_below_minimum_rejected() {
    let mut env = full_env();
    env.insert("APOK_AUTH_MAX_REPLAY_ENTRIES".into(), "512".into());
    let err = load_from(env, None).expect_err("max_replay_entries below floor should be rejected");
    assert!(matches!(
        err,
        ConfigError::InvalidAuthMaxReplayEntries { .. }
    ));
}

#[test]
fn auth_max_replay_entries_at_minimum_accepted() {
    let mut env = full_env();
    env.insert("APOK_AUTH_MAX_REPLAY_ENTRIES".into(), "1024".into());
    let cfg = load_from(env, None).expect("max_replay_entries at floor should be accepted");
    assert_eq!(cfg.auth.max_replay_entries, 1024);
}

#[test]
fn auth_replay_window_below_freshness_plus_skew_rejected() {
    // 60 + 30 = 90; window of 89 should fail the cross-field invariant.
    let mut env = full_env();
    env.insert("APOK_AUTH_CLOCK_SKEW_SECS".into(), "60".into());
    env.insert("APOK_AUTH_DPOP_FRESHNESS_SECS".into(), "30".into());
    env.insert("APOK_AUTH_JTI_REPLAY_WINDOW_SECS".into(), "89".into());
    let err =
        load_from(env, None).expect_err("replay window < freshness + skew should be rejected");
    match err {
        ConfigError::AuthReplayWindowTooSmall {
            window,
            freshness,
            skew,
            required,
        } => {
            assert_eq!(window, 89);
            assert_eq!(freshness, 30);
            assert_eq!(skew, 60);
            assert_eq!(required, 90);
        }
        other => panic!("expected AuthReplayWindowTooSmall, got {other:?}"),
    }
}

#[test]
fn auth_env_overrides_toml() {
    let toml = r#"
        bind_address = "127.0.0.1:8080"
        block_size_bytes = 1048576
        storage_backend = "none"
        trusted_proxies = []

        [vault_oidc]
        issuer_url = "https://issuer.example.invalid/vault"
        audience = "apokryphos-vault"

        [admin_oidc]
        issuer_url = "https://issuer.example.invalid/admin"
        audience = "apokryphos-admin"

        [auth]
        clock_skew_secs = 999
    "#;
    let mut env = BTreeMap::new();
    env.insert("APOK_AUTH_CLOCK_SKEW_SECS".into(), "7".into());
    // Replay window must satisfy `>= dpop_freshness_secs + clock_skew_secs`.
    // Defaults give freshness = 30; our env override sets skew = 7. Because
    // jti_replay_window_secs is omitted from both TOML and env, `parse_auth`
    // resolves it to `freshness + skew = 37` (NOT the AuthConfig::default()
    // value of 90), and the cross-field invariant trivially holds at 37 >= 37.
    let cfg = load_from(env, Some(toml)).expect("env should override TOML for auth keys");
    assert_eq!(cfg.auth.clock_skew_secs, 7, "env wins over TOML");
    // Assert the resolved replay window matches the freshness+skew rule,
    // not the AuthConfig::default() value — this is what the spec
    // §Assumptions says ("`jti` replay window (default 90 s = freshness +
    // skew)") and what parse_auth actually computes.
    assert_eq!(
        cfg.auth.jti_replay_window_secs, 37,
        "resolved replay window = dpop_freshness_secs (30) + clock_skew_secs (7)"
    );
}

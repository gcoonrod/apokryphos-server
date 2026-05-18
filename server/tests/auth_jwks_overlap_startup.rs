//! T041 — startup-time JWKS overlap rejection (SC-007, FR-006).
//!
//! Two `MockOidcProvider`s deliberately share one ES256 key (same RFC 7638
//! thumbprint). `init_contexts` must:
//!
//!   1. Return `Err(ContextInitError::JwksOverlap { context_with_extra_key: Admin })`
//!      — admin is the b-side of the disjointness check, so the duplicate
//!      key is reported as "an extra key in admin" (FR-006 / R12).
//!   2. The `Display` of the error MUST name the offending audience but
//!      MUST NOT contain any substring of the shared key's `x`, `y`, `n`,
//!      or `e` byte material (constitution Principle IV: no key material
//!      in logs / diagnostics).
//!
//! The test does not bind a listener — `init_contexts` itself returns the
//! error, which `app::run` propagates as `AppError::Auth`, which `main`
//! exits non-zero on. Asserting on `app::run` behaviour requires a full
//! signal-handling fixture; here we exercise the failure point directly,
//! which is the structural guarantee SC-007 cares about.

use std::time::Duration;

use apokryphos_server::auth::AudienceTag;
use apokryphos_server::auth::context::{ContextInitError, init_contexts};
use apokryphos_server::auth::testing::{
    MockOidcProvider, deterministic_rng, es256_public_jwk, es256_thumbprint_b64url,
    generate_es256_keypair,
};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig, ServerConfig, StorageBackend};
use openidconnect::reqwest;
use serde_json::{Value, json};

#[tokio::test]
async fn init_contexts_rejects_jwks_overlap_at_startup() {
    let mut rng = deterministic_rng(101);
    // Three keys: vault-only, admin-only, and one shared between them.
    // The shared key is the one that should trigger the overlap rejection.
    let vault_only = generate_es256_keypair(&mut rng);
    let admin_only = generate_es256_keypair(&mut rng);
    let shared = generate_es256_keypair(&mut rng);

    let vault_jwk = es256_public_jwk(vault_only.verifying_key(), Some("vault-only"));
    let admin_jwk = es256_public_jwk(admin_only.verifying_key(), Some("admin-only"));
    let shared_jwk = es256_public_jwk(shared.verifying_key(), Some("shared"));

    let vault_jwks_doc = json!({ "keys": [&vault_jwk, &shared_jwk] });
    let admin_jwks_doc = json!({ "keys": [&admin_jwk, &shared_jwk] });

    let vault_mock = MockOidcProvider::start(vault_jwks_doc).await;
    let admin_mock = MockOidcProvider::start(admin_jwks_doc).await;

    let cfg = make_config(vault_mock.issuer_url(), admin_mock.issuer_url());
    let http_client = reqwest::Client::new();

    let result = init_contexts(&cfg, &http_client).await;
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("init_contexts must reject overlapping JWKS"),
    };

    // Discriminator check: JwksOverlap naming admin (the b-side audience
    // in the vault-first check_disjoint_jwks call from init_contexts).
    match &err {
        ContextInitError::JwksOverlap {
            context_with_extra_key: AudienceTag::Admin,
        } => {}
        other => panic!("expected ContextInitError::JwksOverlap {{ Admin }}, got: {other}"),
    }

    // Constitution Principle IV: diagnostic MUST NOT leak any byte of the
    // shared key's public-key material (the JWK's `x` and `y` base64url
    // coordinates, in this ES256 case).
    let diagnostic = err.to_string();
    assert!(
        diagnostic.contains("admin"),
        "diagnostic must name the offending audience: {diagnostic}"
    );
    if let Value::String(x) = &shared_jwk["x"] {
        assert!(
            !diagnostic.contains(x.as_str()),
            "diagnostic must NOT contain JWK x coordinate (key material): {diagnostic}"
        );
    }
    if let Value::String(y) = &shared_jwk["y"] {
        assert!(
            !diagnostic.contains(y.as_str()),
            "diagnostic must NOT contain JWK y coordinate (key material): {diagnostic}"
        );
    }
    // No raw thumbprint leakage either. The shared key's RFC 7638
    // thumbprint (base64url-encoded SHA-256) is the most likely shape a
    // future regression could leak — it's what the parser already
    // computes per key. Asserting its absence catches a future variant
    // extension that adds a thumbprint field to the Display surface.
    let shared_thumbprint = es256_thumbprint_b64url(shared.verifying_key());
    assert!(
        !diagnostic.contains(&shared_thumbprint),
        "diagnostic must NOT contain the shared key's RFC 7638 thumbprint: {diagnostic}"
    );
}

fn make_config(vault_issuer: url::Url, admin_issuer: url::Url) -> ServerConfig {
    ServerConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        block_size_bytes: 1024 * 1024,
        storage_backend: StorageBackend::None,
        trusted_proxies: vec![],
        // Direct struct construction bypasses OidcAudienceConfig::new's
        // HTTPS validator — the mocks serve over HTTP loopback.
        vault_oidc: OidcAudienceConfig {
            issuer_url: vault_issuer,
            audience: "test-vault-aud".to_string(),
        },
        admin_oidc: OidcAudienceConfig {
            issuer_url: admin_issuer,
            audience: "test-admin-aud".to_string(),
        },
        drain_timeout: Duration::from_secs(5),
        auth: AuthConfig::default(),
    }
}

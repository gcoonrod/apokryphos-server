//! T055 — auth log redaction (FR-031, FR-032, Story 5 Acceptance #2-#3).
//!
//! Drives each negative case through the assembled router with a scoped
//! tracing subscriber capturing every record emitted, then asserts:
//!
//!   (a) No raw access-token substring appears in any captured byte sequence.
//!   (b) No raw DPoP proof substring appears.
//!   (c) No raw `jti` value appears.
//!   (d) No JWK private-material field substring (`"d":`, `"p":`, `"q":`)
//!       appears. (Defense in depth — production code never has access to
//!       private key material, but a careless future change could leak it.)
//!
//! Positive assertions (so the test doesn't trivially pass with empty logs):
//!
//!   (e) On every failure, the FR-033 `auth.failure` event is emitted
//!       carrying the failure category AND the audience tag (`"vault"` /
//!       `"admin"`) so operators can filter per-route-group.
//!
//! ## Subscriber installation
//!
//! `tracing::subscriber::set_default` returns a `DefaultGuard` that scopes
//! the subscriber to the current thread for the guard's lifetime. The test
//! is `#[tokio::test]` (single-threaded current_thread runtime by default),
//! so async polls happen on the same thread and the subscriber applies
//! throughout the request lifecycle.

mod common;

use std::sync::Arc;

use apokryphos_server::AppState;
use apokryphos_server::auth::JtiReplayStore;
use apokryphos_server::auth::context::init_contexts;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig, ServerConfig, StorageBackend};
use apokryphos_server::routes::build_router;
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, header};
use openidconnect::reqwest;
use tower::ServiceExt;
use tracing::Level;

use crate::common::{CapturingBuffer, minimal_valid_config};

const VAULT_KID: &str = "redact-vault-key";
const ADMIN_KID: &str = "redact-admin-key";
const VAULT_AUD: &str = "apokryphos-redact-vault";
const ADMIN_AUD: &str = "apokryphos-redact-admin";
const VAULT_HTU: &str = "http://127.0.0.1/api/whoami";

struct Fixture {
    router: axum::Router,
    vault_signing: p256::ecdsa::SigningKey,
    rogue_signing: p256::ecdsa::SigningKey,
    vault_issuer: url::Url,
    _vault_mock: MockOidcProvider,
    _admin_mock: MockOidcProvider,
}

async fn setup_fixture() -> Fixture {
    let mut rng = deterministic_rng(55);
    let vault_signing = generate_es256_keypair(&mut rng);
    let admin_signing = generate_es256_keypair(&mut rng);
    let rogue_signing = generate_es256_keypair(&mut rng);

    let vault_jwks = serde_json::json!({
        "keys": [es256_public_jwk(vault_signing.verifying_key(), Some(VAULT_KID))]
    });
    let admin_jwks = serde_json::json!({
        "keys": [es256_public_jwk(admin_signing.verifying_key(), Some(ADMIN_KID))]
    });
    let vault_mock = MockOidcProvider::start(vault_jwks).await;
    let admin_mock = MockOidcProvider::start(admin_jwks).await;
    let vault_issuer = vault_mock.issuer_url();
    let admin_issuer = admin_mock.issuer_url();

    let cfg = ServerConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        block_size_bytes: 1024 * 1024,
        storage_backend: StorageBackend::None,
        trusted_proxies: vec![],
        vault_oidc: OidcAudienceConfig {
            issuer_url: vault_issuer.clone(),
            audience: VAULT_AUD.to_string(),
        },
        admin_oidc: OidcAudienceConfig {
            issuer_url: admin_issuer.clone(),
            audience: ADMIN_AUD.to_string(),
        },
        drain_timeout: std::time::Duration::from_secs(5),
        auth: AuthConfig::default(),
    };
    let http_client = reqwest::Client::new();
    let (vault_ctx, admin_ctx) = init_contexts(&cfg, &http_client)
        .await
        .expect("init_contexts must succeed against disjoint mocks");

    let auth_cfg = Arc::new(cfg.auth.clone());
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(state, Some(vault_ctx), Some(admin_ctx), Some(replay_store));

    Fixture {
        router,
        vault_signing,
        rogue_signing,
        vault_issuer,
        _vault_mock: vault_mock,
        _admin_mock: admin_mock,
    }
}

fn iss_str(issuer: &url::Url) -> String {
    issuer.as_str().trim_end_matches('/').to_string()
}

fn mint_vault_token(fx: &Fixture, sub: &str) -> String {
    let now = now_unix_secs();
    let claims = MintTokenClaims {
        sub: sub.to_string(),
        aud: VAULT_AUD.to_string(),
        iss: iss_str(&fx.vault_issuer),
        iat: now,
        exp: now + 3600,
        nbf: None,
        cnf_jkt: es256_thumbprint_b64url(fx.vault_signing.verifying_key()),
    };
    mint_es256_token(&claims, &fx.vault_signing, Some(VAULT_KID), false)
}

fn install_capturing_subscriber() -> (CapturingBuffer, tracing::subscriber::DefaultGuard) {
    let buffer = CapturingBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (buffer, guard)
}

/// Assert the captured-log text does NOT contain any of the redaction-
/// sensitive substrings.
fn assert_redacted(logs: &str, token: &str, proof: &str, jti: &str, label: &str) {
    assert!(
        !logs.contains(token),
        "FR-031: raw access token appears in logs at case {label}",
    );
    for seg in token.split('.') {
        // Skip very short segments — assertion becomes meaningless and
        // false-positives are likely. 16+ chars of base64url is unique.
        if seg.len() >= 16 {
            assert!(
                !logs.contains(seg),
                "FR-031: access-token segment of length {} appears in logs at case {label}",
                seg.len(),
            );
        }
    }
    assert!(
        !logs.contains(proof),
        "FR-031: raw DPoP proof appears in logs at case {label}",
    );
    for seg in proof.split('.') {
        if seg.len() >= 16 {
            assert!(
                !logs.contains(seg),
                "FR-031: DPoP-proof segment of length {} appears in logs at case {label}",
                seg.len(),
            );
        }
    }
    assert!(
        !logs.contains(jti),
        "FR-032: raw `jti` value appears in logs at case {label}; jti={jti:?}",
    );
    for needle in [r#""d":"#, r#""p":"#, r#""q":"#] {
        assert!(
            !logs.contains(needle),
            "FR-031: JWK private-material field {needle:?} appears in logs at case {label}",
        );
    }
}

#[tokio::test]
async fn vault_failure_logs_redact_token_proof_jti() {
    let fixture = setup_fixture().await;

    // Use a token whose signature won't verify so we drive the negative
    // path. Every variant of AuthFailure routes through the same
    // `log_failure` helper — exercising one is sufficient for the
    // redaction assertion.
    let now = now_unix_secs();
    let claims = MintTokenClaims {
        sub: "log-redact-vault-user".to_string(),
        aud: VAULT_AUD.to_string(),
        iss: iss_str(&fixture.vault_issuer),
        iat: now,
        exp: now + 3600,
        nbf: None,
        cnf_jkt: es256_thumbprint_b64url(fixture.rogue_signing.verifying_key()),
    };
    let token = mint_es256_token(&claims, &fixture.rogue_signing, Some(VAULT_KID), false);
    let jti = "redact-test-vault-jti-A";
    let proof = mint_es256_dpop_proof(
        &fixture.rogue_signing,
        "GET",
        VAULT_HTU,
        now,
        jti,
        Some(&token),
    );
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", token)).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(&proof).unwrap())
        .body(Body::empty())
        .unwrap();

    let (buffer, _guard) = install_capturing_subscriber();
    let resp = fixture.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    let logs = buffer.contents();

    assert_redacted(&logs, &token, &proof, jti, "vault_bad_sig");

    assert!(
        logs.contains("auth.failure"),
        "FR-033: the auth.failure event must be emitted on the failure \
         path so the test isn't a trivial pass on zero output. logs={logs}",
    );
    assert!(
        logs.contains("auth.token.bad_signature"),
        "FR-033: the failure category must be present in the log. logs={logs}",
    );
    // Match the exact `tracing_subscriber::fmt` shape for a `&'static str`
    // field: `audience="vault"` (Debug-quoted). A bare `.contains("vault")`
    // would false-pass because VAULT_AUD ("apokryphos-redact-vault") also
    // contains "vault" and may surface in logs from other call sites.
    assert!(
        logs.contains(r#"audience="vault""#),
        "FR-033: the audience tag (audience=\"vault\") must be present on \
         the failure event so operators can filter per-audience. logs={logs}",
    );
}

#[tokio::test]
async fn admin_failure_logs_emit_admin_audience_tag() {
    let fixture = setup_fixture().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .body(Body::empty())
        .unwrap();

    let (buffer, _guard) = install_capturing_subscriber();
    let resp = fixture.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    let logs = buffer.contents();

    assert!(
        logs.contains("auth.failure"),
        "auth.failure event must be emitted. logs={logs}",
    );
    assert!(
        logs.contains("auth.token.missing"),
        "missing-token category must appear. logs={logs}",
    );
    // Same rationale as the vault test above: match the
    // `tracing_subscriber::fmt` field shape `audience="admin"` exactly,
    // since the bare substring "admin" appears in ADMIN_AUD,
    // `/admin/whoami`, the issuer URL, etc.
    assert!(
        logs.contains(r#"audience="admin""#),
        "FR-033: the audience tag (audience=\"admin\") must be present on \
         the failure event. logs={logs}",
    );
}

#[tokio::test]
async fn vault_success_logs_do_not_leak_token_or_proof() {
    let fixture = setup_fixture().await;

    let sub = "log-redact-success-user";
    let token = mint_vault_token(&fixture, sub);
    let now = now_unix_secs();
    let jti = "redact-test-success-jti";
    let proof = mint_es256_dpop_proof(
        &fixture.vault_signing,
        "GET",
        VAULT_HTU,
        now,
        jti,
        Some(&token),
    );
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", token)).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(&proof).unwrap())
        .body(Body::empty())
        .unwrap();

    let (buffer, _guard) = install_capturing_subscriber();
    let resp = fixture.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let logs = buffer.contents();

    // The `sub` MAY appear (FR-033: authenticated sub values MAY be
    // logged). Phase 3 doesn't currently emit a per-request access event,
    // so we don't require its presence; the important assertion is that
    // token/proof/jti are absent — covered by `assert_redacted` below.
    assert_redacted(&logs, &token, &proof, jti, "vault_success");
}

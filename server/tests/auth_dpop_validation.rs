//! T026 — DPoP proof validation negative matrix (SC-005).
//!
//! Drives `GET /api/whoami` with a known-good ES256 vault-audience token
//! plus a deliberately-malformed DPoP proof. Each negative case must
//! produce a 401 (the uniform-401 contract erases category at the wire
//! level). A positive control verifies the fixture is sound — a fresh
//! valid proof yields `200 OK`.

mod common;

use std::sync::Arc;

use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::auth::{AudienceTag, JtiReplayStore, init_single_context};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig};
use apokryphos_server::routes::build_router;
use apokryphos_server::AppState;
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const TEST_KID: &str = "vault-key-1";
const VAULT_AUD: &str = "apokryphos-test-vault";
const REQUEST_HTU: &str = "http://127.0.0.1/api/whoami";

struct Fixture {
    mock: MockOidcProvider,
    router: axum::Router,
    signing_key: p256::ecdsa::SigningKey,
    token: String,
}

async fn setup_fixture(seed: u64) -> Fixture {
    let mut rng = deterministic_rng(seed);
    let signing_key = generate_es256_keypair(&mut rng);
    let jwks_doc = serde_json::json!({
        "keys": [es256_public_jwk(signing_key.verifying_key(), Some(TEST_KID))]
    });
    let mock = MockOidcProvider::start(jwks_doc).await;
    let auth_cfg = Arc::new(AuthConfig::default());
    let http_client = openidconnect::reqwest::Client::new();
    let vault_ctx = init_single_context(
        AudienceTag::Vault,
        &OidcAudienceConfig {
            issuer_url: mock.issuer_url(),
            audience: VAULT_AUD.to_string(),
        },
        Arc::clone(&auth_cfg),
        &http_client,
    )
    .await
    .expect("init must succeed");
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));
    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(state, Some(vault_ctx), Some(replay_store));

    // Pre-mint the access token; all DPoP tests reuse the same token,
    // varying only the proof. cnf.jkt is bound to the signing key's
    // public thumbprint.
    let cnf_jkt = es256_thumbprint_b64url(signing_key.verifying_key());
    let iss = mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    let token = mint_es256_token(
        &MintTokenClaims {
            sub: "vault-dpop-test".to_string(),
            aud: VAULT_AUD.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &signing_key,
        Some(TEST_KID),
        false,
    );

    Fixture {
        mock,
        router,
        signing_key,
        token,
    }
}

async fn drive(router: &axum::Router, token: &str, proof: &str) -> StatusCode {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(proof).unwrap())
        .body(Body::empty())
        .unwrap();
    router
        .clone()
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

// ─────────────────────── Positive control ───────────────────────────────

#[tokio::test]
async fn positive_valid_dpop_succeeds() {
    let fx = setup_fixture(1).await;
    let proof = mint_es256_dpop_proof(
        &fx.signing_key,
        "GET",
        REQUEST_HTU,
        now_unix_secs(),
        "jti-pos",
    );
    assert_eq!(drive(&fx.router, &fx.token, &proof).await, StatusCode::OK);
}

// ───────────── SC-005(a): wrong htm ─────────────────────────────────────

#[tokio::test]
async fn negative_wrong_htm_rejected() {
    let fx = setup_fixture(2).await;
    let proof = mint_es256_dpop_proof(
        &fx.signing_key,
        "POST", // request is GET
        REQUEST_HTU,
        now_unix_secs(),
        "jti-htm",
    );
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-005(b): wrong htu (different path) ────────────────────

#[tokio::test]
async fn negative_wrong_htu_rejected() {
    let fx = setup_fixture(3).await;
    let proof = mint_es256_dpop_proof(
        &fx.signing_key,
        "GET",
        "http://127.0.0.1/api/somewhere-else",
        now_unix_secs(),
        "jti-htu",
    );
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-005(c): stale iat ─────────────────────────────────────

#[tokio::test]
async fn negative_stale_iat_rejected() {
    let fx = setup_fixture(4).await;
    let now = now_unix_secs();
    // Default freshness 30s + skew 60s = 90s window. Use now - 600 to be
    // unambiguously stale (10 minutes past).
    let proof = mint_es256_dpop_proof(
        &fx.signing_key,
        "GET",
        REQUEST_HTU,
        now.saturating_sub(600),
        "jti-stale",
    );
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-005(d): replayed jti ──────────────────────────────────
//
// (Covered by `whoami_vault_replayed_dpop_jti_returns_401` in
// tests/whoami_vault_happy_path.rs — replicated here for SC-005
// completeness.)

#[tokio::test]
async fn negative_replayed_jti_rejected() {
    let fx = setup_fixture(5).await;
    let proof = mint_es256_dpop_proof(
        &fx.signing_key,
        "GET",
        REQUEST_HTU,
        now_unix_secs(),
        "jti-replay",
    );
    // First: accepted.
    assert_eq!(drive(&fx.router, &fx.token, &proof).await, StatusCode::OK);
    // Second: rejected.
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-005(e): jkt mismatch ──────────────────────────────────

#[tokio::test]
async fn negative_jkt_mismatch_rejected() {
    let fx = setup_fixture(6).await;
    // Mint the DPoP proof with a DIFFERENT key — its embedded JWK's
    // thumbprint won't match the token's cnf.jkt.
    let mut rng = deterministic_rng(7777);
    let other_key = generate_es256_keypair(&mut rng);
    let proof = mint_es256_dpop_proof(
        &other_key,
        "GET",
        REQUEST_HTU,
        now_unix_secs(),
        "jti-jkt",
    );
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-005(f): missing proof ─────────────────────────────────
//
// (Covered by `whoami_vault_no_dpop_returns_uniform_401` — included here
// for self-contained SC-005 coverage.)

#[tokio::test]
async fn negative_missing_proof_rejected() {
    let fx = setup_fixture(8).await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", fx.token)).unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let status = fx.router.clone().oneshot(request).await.unwrap().status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ───────────── SC-005(g): bad signature (key mismatch in jwk header) ────

#[tokio::test]
async fn negative_bad_signature_rejected() {
    let fx = setup_fixture(9).await;
    // Construct a proof where the embedded JWK is the FIXTURE's public
    // key (so jkt would match if signature verification were skipped),
    // but the signature is computed with a different private key. The
    // signature won't verify against the embedded jwk → FR-017 rejects.
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::pkcs8::EncodePrivateKey;
    let mut rng = deterministic_rng(11111);
    let attacker_key = generate_es256_keypair(&mut rng);
    let fixture_public_jwk = es256_public_jwk(fx.signing_key.verifying_key(), None);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_value(fixture_public_jwk).unwrap());
    let claims = serde_json::json!({
        "htm": "GET",
        "htu": REQUEST_HTU,
        "iat": now_unix_secs(),
        "jti": "jti-bad-sig",
    });
    let pem = attacker_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
    let proof = encode(&header, &claims, &key).unwrap();
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

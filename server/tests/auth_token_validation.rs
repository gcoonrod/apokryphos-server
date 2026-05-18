//! T025 — access-token validation negative matrix (SC-006, validate-plan G1).
//!
//! Drives `GET /api/whoami` through the full router with deliberately-
//! malformed tokens. SC-006 only requires that each negative cause
//! produces a 401 (the uniform-401 contract erases category at the wire
//! level). The two positive controls (with and without `nbf`) verify
//! that a happy-path token still works and that FR-014's forward-skew
//! acceptance fires when `nbf` is set to `now + 30s` (well within the
//! default 60s `clock_skew_secs`).

mod common;

use std::sync::Arc;

use apokryphos_server::AppState;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::auth::{AudienceTag, JtiReplayStore, init_single_context};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig};
use apokryphos_server::routes::build_router;
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const TEST_KID: &str = "vault-key-1";
const VAULT_AUD: &str = "apokryphos-test-vault";

struct Fixture {
    mock: MockOidcProvider,
    router: axum::Router,
    signing_key: p256::ecdsa::SigningKey,
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
    let router = build_router(state, Some(vault_ctx), None, Some(replay_store));
    Fixture {
        mock,
        router,
        signing_key,
    }
}

fn base_claims(fixture: &Fixture, sub: &str) -> MintTokenClaims {
    let cnf_jkt = es256_thumbprint_b64url(fixture.signing_key.verifying_key());
    let iss = fixture
        .mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    MintTokenClaims {
        sub: sub.to_string(),
        aud: VAULT_AUD.to_string(),
        iss,
        iat: now,
        exp: now + 3600,
        nbf: None,
        cnf_jkt,
    }
}

fn mint_proof(fixture: &Fixture, token: &str, jti: &str) -> String {
    mint_es256_dpop_proof(
        &fixture.signing_key,
        "GET",
        "http://127.0.0.1/api/whoami",
        now_unix_secs(),
        jti,
        Some(token),
    )
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
    router.clone().oneshot(request).await.unwrap().status()
}

// ─────────────── Positive controls (G1 + happy path) ────────────────────

#[tokio::test]
async fn positive_token_with_no_nbf_succeeds() {
    let fx = setup_fixture(1).await;
    let token = mint_es256_token(
        &base_claims(&fx, "vault-pos-1"),
        &fx.signing_key,
        Some(TEST_KID),
        false,
    );
    let proof = mint_proof(&fx, &token, "jti-pos-1");
    assert_eq!(drive(&fx.router, &token, &proof).await, StatusCode::OK);
}

#[tokio::test]
async fn positive_token_with_nbf_within_skew_succeeds() {
    // FR-014 forward-skew acceptance (G1): nbf = now + 30s is within the
    // default 60s clock_skew_secs and MUST be accepted.
    let fx = setup_fixture(2).await;
    let mut claims = base_claims(&fx, "vault-pos-nbf");
    claims.nbf = Some(now_unix_secs() + 30);
    let token = mint_es256_token(&claims, &fx.signing_key, Some(TEST_KID), false);
    let proof = mint_proof(&fx, &token, "jti-pos-nbf");
    assert_eq!(drive(&fx.router, &token, &proof).await, StatusCode::OK);
}

// ───────────── SC-006(a): wrong audience (cross-audience) ────────────────

#[tokio::test]
async fn negative_wrong_audience_rejected() {
    let fx = setup_fixture(3).await;
    let mut claims = base_claims(&fx, "vault-x-aud");
    claims.aud = "apokryphos-test-admin".to_string(); // the other audience
    let token = mint_es256_token(&claims, &fx.signing_key, Some(TEST_KID), false);
    let proof = mint_proof(&fx, &token, "jti-neg-aud");
    assert_eq!(
        drive(&fx.router, &token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-006(b): expired token ─────────────────────────────────

#[tokio::test]
async fn negative_expired_token_rejected() {
    let fx = setup_fixture(4).await;
    let mut claims = base_claims(&fx, "vault-x-exp");
    // Shift the entire lifecycle into the deep past so `exp` is far
    // outside the 60s clock-skew leeway. iat = -2 hours, exp = -1 hour.
    let now = claims.iat;
    claims.iat = now - 7200;
    claims.exp = now - 3600;
    let token = mint_es256_token(&claims, &fx.signing_key, Some(TEST_KID), false);
    let proof = mint_proof(&fx, &token, "jti-neg-exp");
    assert_eq!(
        drive(&fx.router, &token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-006(c): bad signature (wrong key) ─────────────────────

#[tokio::test]
async fn negative_bad_signature_rejected() {
    let fx = setup_fixture(5).await;
    // Sign the token with a DIFFERENT key whose public is NOT in the JWKS.
    let mut rng = deterministic_rng(999);
    let attacker_key = generate_es256_keypair(&mut rng);
    let claims = base_claims(&fx, "vault-x-sig");
    // Use mint_es256_token with the attacker's key — the signature won't
    // verify against the mock's JWKS.
    let token = mint_es256_token(&claims, &attacker_key, Some(TEST_KID), false);
    let proof = mint_proof(&fx, &token, "jti-neg-sig");
    assert_eq!(
        drive(&fx.router, &token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-006(d): missing cnf.jkt ───────────────────────────────

#[tokio::test]
async fn negative_missing_cnf_jkt_rejected() {
    let fx = setup_fixture(6).await;
    let claims = base_claims(&fx, "vault-x-cnf");
    let token = mint_es256_token(&claims, &fx.signing_key, Some(TEST_KID), true);
    let proof = mint_proof(&fx, &token, "jti-neg-cnf");
    assert_eq!(
        drive(&fx.router, &token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-006(e): wrong issuer ──────────────────────────────────

#[tokio::test]
async fn negative_wrong_issuer_rejected() {
    let fx = setup_fixture(7).await;
    let mut claims = base_claims(&fx, "vault-x-iss");
    claims.iss = "https://attacker.invalid".to_string();
    let token = mint_es256_token(&claims, &fx.signing_key, Some(TEST_KID), false);
    let proof = mint_proof(&fx, &token, "jti-neg-iss");
    assert_eq!(
        drive(&fx.router, &token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────── SC-006(f): disallowed alg (RS256) — FR-010a ─────────────

#[tokio::test]
async fn negative_disallowed_alg_rs256_rejected() {
    let fx = setup_fixture(8).await;
    // Mint a token with alg=RS256 using a fresh RSA key. The JWKS only
    // serves ES256, so this would fail signature verification anyway —
    // but FR-010a says it MUST be rejected at the FIRST gate (alg
    // allowlist), BEFORE any signature work. We can't directly observe
    // "first gate" from outside, but a 401 confirms the rejection path
    // fires regardless of which subsystem rejects it.
    let mut rng = deterministic_rng(10);
    let rsa_key = apokryphos_server::auth::testing::generate_ps256_keypair(&mut rng);
    use rsa::pkcs8::EncodePrivateKey;
    let pem = rsa_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let claims = base_claims(&fx, "vault-x-rs256");
    let claims_json = serde_json::json!({
        "sub": claims.sub,
        "aud": claims.aud,
        "iss": claims.iss,
        "iat": claims.iat,
        "exp": claims.exp,
        "cnf": { "jkt": claims.cnf_jkt },
    });
    let token = encode(&header, &claims_json, &encoding_key).unwrap();
    let proof = mint_proof(&fx, &token, "jti-neg-rs256");
    assert_eq!(
        drive(&fx.router, &token, &proof).await,
        StatusCode::UNAUTHORIZED
    );
}

//! T026 — DPoP proof validation negative matrix (SC-005).
//!
//! Drives `GET /api/whoami` with a known-good ES256 vault-audience token
//! plus a deliberately-malformed DPoP proof. Each negative case must
//! produce a 401 (the uniform-401 contract erases category at the wire
//! level). A positive control verifies the fixture is sound — a fresh
//! valid proof yields `200 OK`.

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
    let router = build_router(state, Some(vault_ctx), None, Some(replay_store), None);

    // Pre-mint the access token; all DPoP tests reuse the same token,
    // varying only the proof. cnf.jkt is bound to the signing key's
    // public thumbprint.
    let cnf_jkt = es256_thumbprint_b64url(signing_key.verifying_key());
    let iss = mock.issuer_url().as_str().trim_end_matches('/').to_string();
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
    router.clone().oneshot(request).await.unwrap().status()
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
        Some(&fx.token),
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
        Some(&fx.token),
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
        Some(&fx.token),
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
        Some(&fx.token),
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
        Some(&fx.token),
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
        Some(&fx.token),
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

// ───────────── SC-005(i): ath mismatch (proof-to-token substitution) ─────
//
// FR-022a (RFC 9449 §4.2): a proof minted against a DIFFERENT access
// token's bytes — even if every other property is valid — MUST be
// rejected. This is the substitution-resistance defense; without it,
// a captured DPoP proof can be paired with any access token that
// happens to share the same DPoP key.

#[tokio::test]
async fn negative_ath_mismatch_rejected() {
    let fx = setup_fixture(10).await;
    // Mint a SECOND token (with a different sub) using the same key —
    // this gives us a valid-but-different access token whose wire-form
    // bytes differ from fx.token. The proof binds to the second token's
    // bytes via ath, but the request presents fx.token in Authorization.
    let cnf_jkt =
        apokryphos_server::auth::testing::es256_thumbprint_b64url(fx.signing_key.verifying_key());
    let iss = fx
        .mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    let other_token = apokryphos_server::auth::testing::mint_es256_token(
        &MintTokenClaims {
            sub: "vault-other".to_string(),
            aud: VAULT_AUD.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &fx.signing_key,
        Some(TEST_KID),
        false,
    );
    let proof = mint_es256_dpop_proof(
        &fx.signing_key,
        "GET",
        REQUEST_HTU,
        now_unix_secs(),
        "jti-ath-mismatch",
        Some(&other_token), // binds proof to other_token, NOT fx.token
    );
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED,
        "proof bound to a different token's bytes MUST be rejected"
    );
}

// ───────────── SC-005(j): missing ath claim ─────────────────────────────
//
// FR-022a forbids bearer-token-style DPoP proofs (key+method+URI bound
// but not token-bound). A proof that omits `ath` entirely MUST be
// rejected even if everything else is valid.

#[tokio::test]
async fn negative_missing_ath_rejected() {
    let fx = setup_fixture(11).await;
    let proof = mint_es256_dpop_proof(
        &fx.signing_key,
        "GET",
        REQUEST_HTU,
        now_unix_secs(),
        "jti-ath-missing",
        None, // omit the ath claim
    );
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED,
        "proof without ath MUST be rejected (no bearer-style DPoP)"
    );
}

// ───────────── SC-005 supplement: RFC 9449 §4.2 `typ` header ────────────
//
// Verifies the Step 1b guard in `validate_proof` (added during the
// case-insensitive-scheme + typ-header amendment): a JWS whose JOSE
// `typ` header is missing or not exactly `"dpop+jwt"` MUST be rejected
// before any signature work — even if every other property would
// otherwise validate.

#[tokio::test]
async fn negative_wrong_typ_rejected() {
    let fx = setup_fixture(12).await;
    // Build a proof manually with typ="JWT" (the bare-JWT placeholder)
    // instead of "dpop+jwt". Use the fixture's own key + the correct
    // ath so the failure can only be the typ check.
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::pkcs8::EncodePrivateKey;
    let fixture_public_jwk =
        apokryphos_server::auth::testing::es256_public_jwk(fx.signing_key.verifying_key(), None);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string()); // INTENTIONALLY WRONG
    header.jwk = Some(serde_json::from_value(fixture_public_jwk).unwrap());
    let ath = apokryphos_server::auth::testing::compute_ath_for_test(&fx.token);
    let claims = serde_json::json!({
        "htm": "GET",
        "htu": REQUEST_HTU,
        "iat": now_unix_secs(),
        "jti": "jti-wrong-typ",
        "ath": ath,
    });
    let pem = fx
        .signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
    let proof = encode(&header, &claims, &key).unwrap();
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED,
        "RFC 9449 §4.2: proof with typ != 'dpop+jwt' MUST be rejected at Step 1b"
    );
}

#[tokio::test]
async fn negative_missing_typ_rejected() {
    let fx = setup_fixture(13).await;
    // typ omitted entirely. Same construction as above but header.typ = None.
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::pkcs8::EncodePrivateKey;
    let fixture_public_jwk =
        apokryphos_server::auth::testing::es256_public_jwk(fx.signing_key.verifying_key(), None);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = None;
    header.jwk = Some(serde_json::from_value(fixture_public_jwk).unwrap());
    let ath = apokryphos_server::auth::testing::compute_ath_for_test(&fx.token);
    let claims = serde_json::json!({
        "htm": "GET",
        "htu": REQUEST_HTU,
        "iat": now_unix_secs(),
        "jti": "jti-missing-typ",
        "ath": ath,
    });
    let pem = fx
        .signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
    let proof = encode(&header, &claims, &key).unwrap();
    assert_eq!(
        drive(&fx.router, &fx.token, &proof).await,
        StatusCode::UNAUTHORIZED,
        "RFC 9449 §4.2: proof without typ MUST be rejected"
    );
}

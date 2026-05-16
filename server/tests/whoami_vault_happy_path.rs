//! T027 — vault-audience end-to-end happy-path (SC-001, Story 1 Acceptance #1).
//!
//! Drives `GET /api/whoami` through the assembled router via
//! `tower::ServiceExt::oneshot`. Asserts:
//!
//!   - With a valid ES256 vault-audience token + a fresh DPoP proof
//!     bound to that token, the response is `200 OK` with `Content-Type:
//!     application/json` and body `{"sub":"<token sub>"}`. No other field
//!     appears in the JSON body.
//!   - With no `Authorization` header: `401 Unauthorized` with empty body
//!     and the fixed `WWW-Authenticate: DPoP algs="PS256 ES256"`.
//!   - With an `Authorization` header but no `DPoP` header: same 401.

mod common;

use std::sync::Arc;

use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::auth::{
    AudienceTag, JtiReplayStore, init_single_context,
};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig};
use apokryphos_server::routes::build_router;
use apokryphos_server::AppState;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const TEST_KID: &str = "vault-key-1";
const VAULT_AUD: &str = "apokryphos-test-vault";

/// Helper struct binding the test fixture together. Lives for the test's
/// duration; the `MockOidcProvider`'s background task is aborted on drop.
struct Fixture {
    mock: MockOidcProvider,
    router: axum::Router,
    signing_key: p256::ecdsa::SigningKey,
}

async fn setup_fixture() -> Fixture {
    let mut rng = deterministic_rng(42);
    let signing_key = generate_es256_keypair(&mut rng);
    let verifying = signing_key.verifying_key();

    // Build the JWKS the mock serves: one ES256 public key with our kid.
    let jwks_doc = serde_json::json!({
        "keys": [es256_public_jwk(verifying, Some(TEST_KID))]
    });
    let mock = MockOidcProvider::start(jwks_doc).await;

    // Construct an OidcContext pointing at the mock.
    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: VAULT_AUD.to_string(),
    };
    let auth_cfg = Arc::new(AuthConfig::default());
    let http_client = openidconnect::reqwest::Client::new();
    let vault_ctx = init_single_context(
        AudienceTag::Vault,
        &oidc_cfg,
        Arc::clone(&auth_cfg),
        &http_client,
    )
    .await
    .expect("init_single_context against MockOidcProvider must succeed");

    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(state, Some(vault_ctx), Some(replay_store));

    Fixture {
        mock,
        router,
        signing_key,
    }
}

fn mint_token(fixture: &Fixture, sub: &str) -> String {
    let verifying = fixture.signing_key.verifying_key();
    let cnf_jkt = es256_thumbprint_b64url(verifying);
    let issuer = fixture.mock.issuer_url();
    // The middleware compares iss with the issuer_url with trailing slash
    // stripped — match that form when minting.
    let iss = issuer.as_str().trim_end_matches('/').to_string();

    let now = now_unix_secs();
    let claims = MintTokenClaims {
        sub: sub.to_string(),
        aud: VAULT_AUD.to_string(),
        iss,
        iat: now,
        exp: now + 3600,
        nbf: None,
        cnf_jkt,
    };
    mint_es256_token(&claims, &fixture.signing_key, Some(TEST_KID), false)
}

fn mint_proof(fixture: &Fixture, htm: &str, htu: &str, jti: &str) -> String {
    let now = now_unix_secs();
    mint_es256_dpop_proof(&fixture.signing_key, htm, htu, now, jti)
}

// ─────────────────────── Positive control (SC-001) ───────────────────────

#[tokio::test]
async fn whoami_vault_happy_path_returns_200_with_sub() {
    let fixture = setup_fixture().await;

    let token = mint_token(&fixture, "vault-user-42");
    // The middleware constructs `effective_uri` from the request URI; for
    // a tower::oneshot test there's no real network, so the URI is what
    // we put in the request line. We use http://127.0.0.1/api/whoami to
    // match what the middleware's build_effective_uri produces given the
    // default EffectiveScheme::Http + the request's Host header.
    let proof_htu = "http://127.0.0.1/api/whoami";
    let proof = mint_proof(&fixture, "GET", proof_htu, "jti-happy-1");

    let request = Request::builder()
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

    let response = fixture
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("oneshot must complete");

    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();
    let body_json: Value = serde_json::from_str(&body_text)
        .unwrap_or_else(|_| panic!("body is not valid JSON: status={status} body={body_text:?}"));

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 OK; body was {body_text:?}"
    );
    assert_eq!(
        content_type.as_deref(),
        Some("application/json"),
        "FR-027 requires Content-Type: application/json"
    );

    let obj = body_json.as_object().expect("body must be a JSON object");
    assert_eq!(obj.len(), 1, "FR-027: body MUST contain exactly one field (sub); got {body_json}");
    assert_eq!(
        obj.get("sub").and_then(Value::as_str),
        Some("vault-user-42"),
        "sub must match the token claim"
    );
}

// ─────────────── Negative control: no Authorization header ───────────────

#[tokio::test]
async fn whoami_vault_no_auth_returns_uniform_401() {
    let fixture = setup_fixture().await;

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .body(Body::empty())
        .unwrap();

    let response = fixture.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string());
    assert_eq!(
        www_auth.as_deref(),
        Some(r#"DPoP algs="PS256 ES256""#),
        "FR-029: fixed WWW-Authenticate value"
    );
    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body.is_empty(), "FR-029: 401 body MUST be empty");
}

// ──────────────────── Negative: no DPoP header ───────────────────────────

#[tokio::test]
async fn whoami_vault_no_dpop_returns_uniform_401() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "vault-user-42");

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", token)).unwrap(),
        )
        .body(Body::empty())
        .unwrap();

    let response = fixture.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body.is_empty());
}

// ────────────────── Negative: replayed DPoP jti ──────────────────────────

#[tokio::test]
async fn whoami_vault_replayed_dpop_jti_returns_401() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "vault-user-42");
    let proof_htu = "http://127.0.0.1/api/whoami";
    let proof = mint_proof(&fixture, "GET", proof_htu, "jti-replay-test");

    let build_req = || {
        Request::builder()
            .method(Method::GET)
            .uri("/api/whoami")
            .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
            .header(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("DPoP {}", token)).unwrap(),
            )
            .header("dpop", HeaderValue::from_str(&proof).unwrap())
            .body(Body::empty())
            .unwrap()
    };

    // First request: accepted.
    let response1 = fixture.router.clone().oneshot(build_req()).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);

    // Second request with the same proof: replay rejected (FR-021).
    let response2 = fixture.router.clone().oneshot(build_req()).await.unwrap();
    assert_eq!(
        response2.status(),
        StatusCode::UNAUTHORIZED,
        "second presentation of the same jti MUST be rejected"
    );
}

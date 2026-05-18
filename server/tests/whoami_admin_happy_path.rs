//! T043 — admin-audience end-to-end happy-path (mirror of T027, FR-028).
//!
//! Drives `GET /admin/whoami` through the assembled router with a valid
//! ES256 admin-audience token + fresh DPoP proof. Asserts the response is
//! `200 OK` with `Content-Type: application/json` and body
//! `{"sub":"<token sub>"}`. The structural symmetry with the vault path
//! is the load-bearing property: any divergence in shape between the
//! two audience surfaces would be a regression on FR-027/FR-028 parity.

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
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const TEST_KID: &str = "admin-key-1";
const ADMIN_AUD: &str = "apokryphos-test-admin";

struct Fixture {
    mock: MockOidcProvider,
    router: axum::Router,
    signing_key: p256::ecdsa::SigningKey,
}

async fn setup_fixture() -> Fixture {
    let mut rng = deterministic_rng(43);
    let signing_key = generate_es256_keypair(&mut rng);
    let jwks_doc = serde_json::json!({
        "keys": [es256_public_jwk(signing_key.verifying_key(), Some(TEST_KID))]
    });
    let mock = MockOidcProvider::start(jwks_doc).await;

    // Wire just the admin context. T044 covers the dual-context byte-
    // identical-401 contract; here we focus on the admin happy path.
    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: ADMIN_AUD.to_string(),
    };
    let auth_cfg = Arc::new(AuthConfig::default());
    let http_client = openidconnect::reqwest::Client::new();
    let admin_ctx = init_single_context(
        AudienceTag::Admin,
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
    let router = build_router(state, None, Some(admin_ctx), Some(replay_store), None);

    Fixture {
        mock,
        router,
        signing_key,
    }
}

fn mint_admin_token(fixture: &Fixture, sub: &str) -> String {
    let cnf_jkt = es256_thumbprint_b64url(fixture.signing_key.verifying_key());
    let iss = fixture
        .mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    let claims = MintTokenClaims {
        sub: sub.to_string(),
        aud: ADMIN_AUD.to_string(),
        iss,
        iat: now,
        exp: now + 3600,
        nbf: None,
        cnf_jkt,
    };
    mint_es256_token(&claims, &fixture.signing_key, Some(TEST_KID), false)
}

fn mint_proof(fixture: &Fixture, token: &str, htm: &str, htu: &str, jti: &str) -> String {
    let now = now_unix_secs();
    mint_es256_dpop_proof(&fixture.signing_key, htm, htu, now, jti, Some(token))
}

#[tokio::test]
async fn whoami_admin_happy_path_returns_200_with_sub() {
    let fixture = setup_fixture().await;
    let token = mint_admin_token(&fixture, "admin-root");
    let proof_htu = "http://127.0.0.1/admin/whoami";
    let proof = mint_proof(&fixture, &token, "GET", proof_htu, "jti-admin-happy-1");

    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", token)).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(&proof).unwrap())
        .body(Body::empty())
        .unwrap();

    let response = fixture.router.clone().oneshot(request).await.unwrap();
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
        "FR-028 requires Content-Type: application/json"
    );

    let obj = body_json.as_object().expect("body must be a JSON object");
    assert_eq!(
        obj.len(),
        1,
        "FR-028: body MUST contain exactly one field (sub); got {body_json}"
    );
    assert_eq!(
        obj.get("sub").and_then(Value::as_str),
        Some("admin-root"),
        "sub must match the admin token claim"
    );
}

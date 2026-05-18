//! T019 — US1 round-trip integration test (spec FR-016..018, SC-001).
//!
//! Drives `PUT → GET → re-PUT → GET → DELETE → GET-404` through the
//! assembled router via `tower::ServiceExt::oneshot`. Each request mints
//! a fresh DPoP proof (the replay store rejects duplicate `jti` values
//! per Phase 3 FR-021).

mod common;

use std::sync::Arc;

use apokryphos_server::AppState;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::auth::{AudienceTag, JtiReplayStore, init_single_context};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig, StorageBackend};
use apokryphos_server::routes::build_router;
use apokryphos_server::storage::{LocalFsProvider, StorageProvider};
use axum::body::{Body, HttpBody, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use tempfile::TempDir;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const TEST_KID: &str = "vault-key-1";
const VAULT_AUD: &str = "apokryphos-test-vault";

/// Small test block size (the planning-time default is 1 MiB; tests use
/// 256 bytes to keep payloads cheap to generate and ship through oneshot).
const TEST_BLOCK_SIZE: u64 = 256;

/// 43-character canonical base64url block ID used as the round-trip target.
const TEST_BLOCK_ID: &str = "RoundTripBlockIdSuitableFor043CharsTestsX_-";

struct Fixture {
    mock: MockOidcProvider,
    _block_root: TempDir,
    router: axum::Router,
    signing_key: p256::ecdsa::SigningKey,
}

async fn setup_fixture() -> Fixture {
    let mut rng = deterministic_rng(42);
    let signing_key = generate_es256_keypair(&mut rng);
    let verifying = signing_key.verifying_key();

    let jwks_doc = serde_json::json!({
        "keys": [es256_public_jwk(verifying, Some(TEST_KID))]
    });
    let mock = MockOidcProvider::start(jwks_doc).await;

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
    .expect("init_single_context must succeed");

    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let block_root = tempfile::tempdir().expect("create tempdir for block root");
    let storage: Arc<dyn StorageProvider> = Arc::new(LocalFsProvider::new_unchecked(
        block_root.path().to_path_buf(),
    ));

    let mut cfg = minimal_valid_config();
    cfg.block_size_bytes = TEST_BLOCK_SIZE;
    cfg.storage_backend = StorageBackend::LocalFs {
        root: block_root.path().to_path_buf(),
    };

    let state = AppState {
        config: Arc::new(cfg),
    };
    let router = build_router(
        state,
        Some(vault_ctx),
        None,
        Some(replay_store),
        Some(storage),
    );

    Fixture {
        mock,
        _block_root: block_root,
        router,
        signing_key,
    }
}

fn mint_token(fixture: &Fixture, sub: &str) -> String {
    let verifying = fixture.signing_key.verifying_key();
    let cnf_jkt = es256_thumbprint_b64url(verifying);
    let issuer = fixture.mock.issuer_url();
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

fn mint_proof(fixture: &Fixture, token: &str, htm: &str, htu: &str, jti: &str) -> String {
    let now = now_unix_secs();
    mint_es256_dpop_proof(&fixture.signing_key, htm, htu, now, jti, Some(token))
}

fn block_request(
    method: Method,
    block_id: &str,
    token: &str,
    proof: &str,
    body: Body,
) -> Request<Body> {
    let uri = format!("/api/blocks/{block_id}");
    let cl = body.size_hint().exact();
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(proof).unwrap());
    if let Some(cl) = cl {
        req = req.header(header::CONTENT_LENGTH, cl.to_string());
    }
    req.body(body).unwrap()
}

#[tokio::test]
async fn put_get_delete_round_trip_returns_byte_identical_payload() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "round-trip-user");

    let payload_a: Vec<u8> = (0..TEST_BLOCK_SIZE).map(|i| (i & 0xff) as u8).collect();
    let payload_b: Vec<u8> = (0..TEST_BLOCK_SIZE)
        .map(|i| ((i * 7) & 0xff) as u8)
        .collect();
    let htu = format!("http://127.0.0.1/api/blocks/{TEST_BLOCK_ID}");

    // 1. PUT payload A → 204.
    let proof = mint_proof(&fixture, &token, "PUT", &htu, "jti-rt-1");
    let response = fixture
        .router
        .clone()
        .oneshot(block_request(
            Method::PUT,
            TEST_BLOCK_ID,
            &token,
            &proof,
            Body::from(payload_a.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "first PUT must succeed"
    );

    // 2. GET → 200 with payload A.
    let proof = mint_proof(&fixture, &token, "GET", &htu, "jti-rt-2");
    let response = fixture
        .router
        .clone()
        .oneshot(block_request(
            Method::GET,
            TEST_BLOCK_ID,
            &token,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = to_bytes(response.into_body(), TEST_BLOCK_SIZE as usize * 2)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), payload_a.as_slice());

    // 3. Re-PUT payload B → 204 (overwrite).
    let proof = mint_proof(&fixture, &token, "PUT", &htu, "jti-rt-3");
    let response = fixture
        .router
        .clone()
        .oneshot(block_request(
            Method::PUT,
            TEST_BLOCK_ID,
            &token,
            &proof,
            Body::from(payload_b.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "re-PUT must succeed"
    );

    // 4. GET → 200 with payload B.
    let proof = mint_proof(&fixture, &token, "GET", &htu, "jti-rt-4");
    let response = fixture
        .router
        .clone()
        .oneshot(block_request(
            Method::GET,
            TEST_BLOCK_ID,
            &token,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), TEST_BLOCK_SIZE as usize * 2)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), payload_b.as_slice());

    // 5. DELETE → 204.
    let proof = mint_proof(&fixture, &token, "DELETE", &htu, "jti-rt-5");
    let response = fixture
        .router
        .clone()
        .oneshot(block_request(
            Method::DELETE,
            TEST_BLOCK_ID,
            &token,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 6. GET → 404 (block absent after DELETE).
    let proof = mint_proof(&fixture, &token, "GET", &htu, "jti-rt-6");
    let response = fixture
        .router
        .clone()
        .oneshot(block_request(
            Method::GET,
            TEST_BLOCK_ID,
            &token,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        response.headers().get(header::ALLOW).is_none(),
        "byte-identical 404 must not emit Allow header"
    );
}

#[tokio::test]
async fn delete_absent_id_returns_204() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "absent-delete-user");
    let id = "DeleteAbsentBlockId000000000000000000000ABC";
    assert_eq!(id.len(), 43);
    let htu = format!("http://127.0.0.1/api/blocks/{id}");
    let proof = mint_proof(&fixture, &token, "DELETE", &htu, "jti-delete-absent");
    let response = fixture
        .router
        .clone()
        .oneshot(block_request(
            Method::DELETE,
            id,
            &token,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "FR-004: idempotent delete returns 204 for absent ID"
    );
}

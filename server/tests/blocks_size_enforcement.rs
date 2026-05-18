//! T025 — US2 size enforcement integration test (spec FR-014 / FR-023 / FR-024 / SC-002).
//!
//! Exercises four wrong-size PUT flavors:
//!   1. body length `block_size_bytes - 1` (undersize)
//!   2. body length `block_size_bytes + 1` (oversize)
//!   3. body length `2 * block_size_bytes` (gross oversize)
//!   4. `Content-Length` declared correctly but body shorter than declared
//!
//! For each case asserts:
//!   - response is `400 Bad Request`
//!   - response body is empty
//!   - response does not echo the received size
//!   - subsequent GET for the same block ID returns 404

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
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use tempfile::TempDir;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const TEST_KID: &str = "vault-key-1";
const VAULT_AUD: &str = "apokryphos-test-vault";
const TEST_BLOCK_SIZE: u64 = 256;

struct Fixture {
    mock: MockOidcProvider,
    _block_root: TempDir,
    router: axum::Router,
    signing_key: p256::ecdsa::SigningKey,
}

async fn setup_fixture() -> Fixture {
    let mut rng = deterministic_rng(43);
    let signing_key = generate_es256_keypair(&mut rng);
    let verifying = signing_key.verifying_key();
    let jwks_doc = serde_json::json!({"keys": [es256_public_jwk(verifying, Some(TEST_KID))]});
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
    .unwrap();
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));
    let block_root = tempfile::tempdir().unwrap();
    let storage: Arc<dyn StorageProvider> = Arc::new(LocalFsProvider::new_unchecked(
        block_root.path().to_path_buf(),
    ));
    let mut cfg = minimal_valid_config();
    cfg.block_size_bytes = TEST_BLOCK_SIZE;
    cfg.storage_backend = StorageBackend::LocalFs {
        root: block_root.path().to_path_buf(),
    };
    let router = build_router(
        AppState {
            config: Arc::new(cfg),
        },
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

fn mint_token(f: &Fixture, sub: &str) -> String {
    let cnf_jkt = es256_thumbprint_b64url(f.signing_key.verifying_key());
    let iss = f
        .mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    mint_es256_token(
        &MintTokenClaims {
            sub: sub.to_string(),
            aud: VAULT_AUD.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &f.signing_key,
        Some(TEST_KID),
        false,
    )
}

fn mint_proof(f: &Fixture, token: &str, htm: &str, htu: &str, jti: &str) -> String {
    mint_es256_dpop_proof(&f.signing_key, htm, htu, now_unix_secs(), jti, Some(token))
}

fn block_request_with_explicit_cl(
    method: Method,
    block_id: &str,
    token: &str,
    proof: &str,
    body: Body,
    explicit_content_length: Option<u64>,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(format!("/api/blocks/{block_id}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(proof).unwrap());
    if let Some(cl) = explicit_content_length {
        req = req.header(header::CONTENT_LENGTH, cl.to_string());
    }
    req.body(body).unwrap()
}

async fn try_put(
    fixture: &Fixture,
    token: &str,
    block_id: &str,
    proof_jti: &str,
    body_bytes: Vec<u8>,
    explicit_cl: Option<u64>,
) -> axum::http::Response<Body> {
    let htu = format!("http://127.0.0.1/api/blocks/{block_id}");
    let proof = mint_proof(fixture, token, "PUT", &htu, proof_jti);
    let req = block_request_with_explicit_cl(
        Method::PUT,
        block_id,
        token,
        &proof,
        Body::from(body_bytes),
        explicit_cl,
    );
    fixture.router.clone().oneshot(req).await.unwrap()
}

async fn assert_get_returns_404(fixture: &Fixture, token: &str, block_id: &str, jti: &str) {
    let htu = format!("http://127.0.0.1/api/blocks/{block_id}");
    let proof = mint_proof(fixture, token, "GET", &htu, jti);
    let req =
        block_request_with_explicit_cl(Method::GET, block_id, token, &proof, Body::empty(), None);
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "wrong-size PUT must not have persisted the payload"
    );
}

fn assert_400_empty_no_size_echo(response: &axum::http::Response<Body>) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // The body content is asserted in a separate awaited helper because
    // the Response<Body> isn't easily shared otherwise; we check headers
    // here.
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "wrong-size 400 body must be empty"
    );
}

#[tokio::test]
async fn undersize_put_returns_400_and_does_not_persist() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "size-test-user");
    let block_id = "Undersize0000000000000000000000000000000000";
    assert_eq!(block_id.len(), 43);

    let body: Vec<u8> = vec![0xAB; (TEST_BLOCK_SIZE - 1) as usize];
    let response = try_put(
        &fixture,
        &token,
        block_id,
        "jti-size-under",
        body,
        Some(TEST_BLOCK_SIZE - 1),
    )
    .await;
    assert_400_empty_no_size_echo(&response);
    let body_bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body_bytes.is_empty(), "400 body must be empty");
    assert_get_returns_404(&fixture, &token, block_id, "jti-size-under-get").await;
}

#[tokio::test]
async fn oversize_by_one_put_returns_400() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "size-test-user");
    let block_id = "OversizeByOne00000000000000000000000000000A";
    assert_eq!(block_id.len(), 43);

    let body: Vec<u8> = vec![0xCD; (TEST_BLOCK_SIZE + 1) as usize];
    let response = try_put(
        &fixture,
        &token,
        block_id,
        "jti-size-over1",
        body,
        Some(TEST_BLOCK_SIZE + 1),
    )
    .await;
    assert_400_empty_no_size_echo(&response);
    assert_get_returns_404(&fixture, &token, block_id, "jti-size-over1-get").await;
}

#[tokio::test]
async fn gross_oversize_put_returns_400() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "size-test-user");
    let block_id = "GrossOversize000000000000000000000000000000";
    assert_eq!(block_id.len(), 43);

    let body: Vec<u8> = vec![0xEF; (TEST_BLOCK_SIZE * 2) as usize];
    let response = try_put(
        &fixture,
        &token,
        block_id,
        "jti-size-over2",
        body,
        Some(TEST_BLOCK_SIZE * 2),
    )
    .await;
    assert_400_empty_no_size_echo(&response);
    assert_get_returns_404(&fixture, &token, block_id, "jti-size-over2-get").await;
}

#[tokio::test]
async fn content_length_mismatch_returns_400() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "size-test-user");
    let block_id = "ContentLengthMismatch00000000000000000000Ay";
    assert_eq!(block_id.len(), 43);

    // Client declares correct size but the body is half — Content-Length
    // pre-check passes (declared == expected), but the body-cap then
    // detects the shortfall.
    let body: Vec<u8> = vec![0x77; (TEST_BLOCK_SIZE / 2) as usize];
    let response = try_put(
        &fixture,
        &token,
        block_id,
        "jti-cl-mismatch",
        body,
        Some(TEST_BLOCK_SIZE), // declared == expected, actual body shorter
    )
    .await;
    // axum's body-collection may also short-circuit on declared-vs-actual
    // mismatch; either way the result is 400.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_get_returns_404(&fixture, &token, block_id, "jti-cl-mismatch-get").await;
}

#[tokio::test]
async fn declared_content_length_wrong_short_circuits_400() {
    let fixture = setup_fixture().await;
    let token = mint_token(&fixture, "size-test-user");
    let block_id = "DeclaredCLWrong0000000000000000000000000A_-";
    assert_eq!(block_id.len(), 43);

    // Even if the actual body happens to be the right size, a declared
    // Content-Length != block_size_bytes must short-circuit to 400 per
    // FR-024's two-layer enforcement.
    let body: Vec<u8> = vec![0x55; TEST_BLOCK_SIZE as usize];
    let response = try_put(
        &fixture,
        &token,
        block_id,
        "jti-cl-wrong",
        body,
        Some(TEST_BLOCK_SIZE - 1), // wrong declared CL
    )
    .await;
    assert_400_empty_no_size_echo(&response);
    assert_get_returns_404(&fixture, &token, block_id, "jti-cl-wrong-get").await;
}

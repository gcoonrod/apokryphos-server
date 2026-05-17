//! T046 — memory-pressure 503 edge case (FR-021, spec edge case,
//! contracts/http.md §Memory-pressure response, validate-plan G2).
//!
//! Fills a `JtiReplayStore` to its `max_replay_entries` budget with
//! synthetic in-window entries, then issues a fully valid vault
//! `/api/whoami` request (new token, new DPoP proof, fresh jti). The
//! contract is:
//!
//!   - The response is `503 Service Unavailable` with `Content-Length: 0`,
//!     no `Content-Type`, no `Retry-After`, and an empty body. (This is
//!     the byte-shape from `auth::failure::respond_503_memory_pressure`.)
//!   - No previously-inserted jti is silently evicted. Re-inserting any
//!     of the four pre-filled jtis returns `InsertError::Replayed` —
//!     proof that FR-021's "no eviction" guarantee held.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use apokryphos_server::AppState;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::auth::{
    AudienceTag, JtiKey, JtiReplayStore, ReplayInsertError, init_single_context,
};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig};
use apokryphos_server::routes::build_router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const TEST_KID: &str = "memory-pressure-key";
const VAULT_AUD: &str = "apokryphos-memory-pressure-vault";

#[tokio::test]
async fn memory_pressure_returns_503_without_evicting_in_window_entries() {
    // ── Setup: vault context against a one-key mock + shared store. ─────
    let mut rng = deterministic_rng(503);
    let signing_key = generate_es256_keypair(&mut rng);
    let jwks_doc = serde_json::json!({
        "keys": [es256_public_jwk(signing_key.verifying_key(), Some(TEST_KID))]
    });
    let mock = MockOidcProvider::start(jwks_doc).await;

    // Tight budget so the test is fast: 4 entries fill the store.
    let mut auth = AuthConfig::default();
    auth.max_replay_entries = 4;
    let auth_cfg = Arc::new(auth);

    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: VAULT_AUD.to_string(),
    };
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

    // ── Pre-fill the replay store with 4 synthetic in-window jtis. ──────
    // Deadlines are well in the future so they remain "in window" for
    // the duration of the test; FR-021 forbids silent eviction of these.
    let prefilled_jtis = ["jti-prefill-a", "jti-prefill-b", "jti-prefill-c", "jti-prefill-d"];
    let far_future = Instant::now() + Duration::from_secs(3600);
    for raw_jti in &prefilled_jtis {
        let key = JtiKey::new(AudienceTag::Vault.as_jti_key_byte(), raw_jti);
        replay_store
            .try_insert(key, far_future)
            .expect("synthetic prefill must insert cleanly");
    }
    assert_eq!(
        replay_store.len(),
        4,
        "store should now be at max_replay_entries"
    );

    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(
        state,
        Some(vault_ctx),
        None,
        Some(Arc::clone(&replay_store)),
    );

    // ── Mint a fully valid token + DPoP proof with a NEW jti. ───────────
    let cnf_jkt = es256_thumbprint_b64url(signing_key.verifying_key());
    let iss = mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    let token = mint_es256_token(
        &MintTokenClaims {
            sub: "mp-user".to_string(),
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
    let proof = mint_es256_dpop_proof(
        &signing_key,
        "GET",
        "http://127.0.0.1/api/whoami",
        now,
        "jti-fresh-pressure",
        Some(&token),
    );

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

    let response = router.clone().oneshot(request).await.unwrap();

    // ── Assert the exact 503 byte-shape (contracts/http.md). ────────────
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response.headers().get(header::CONTENT_TYPE).is_none(),
        "503 MUST NOT carry Content-Type"
    );
    assert!(
        response.headers().get(header::RETRY_AFTER).is_none(),
        "503 MUST NOT carry Retry-After — even though it would be useful, \
         the contract is byte-shape-fixed"
    );
    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|v| v.to_str().unwrap().to_string());
    assert_eq!(
        content_length.as_deref(),
        Some("0"),
        "503 MUST carry Content-Length: 0"
    );
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body.is_empty(), "503 body MUST be empty");

    // ── FR-021 no-eviction guarantee. Each prefilled jti must still be
    // present — proof: re-inserting returns Replayed (not Ok). ──────────
    for raw_jti in &prefilled_jtis {
        let key = JtiKey::new(AudienceTag::Vault.as_jti_key_byte(), raw_jti);
        let outcome = replay_store.try_insert(key, far_future);
        match outcome {
            Err(ReplayInsertError::Replayed) => {} // expected
            Err(other) => panic!("expected Replayed for {raw_jti}, got {other}"),
            Ok(()) => panic!(
                "FR-021 violation: jti {raw_jti} was silently evicted under memory pressure"
            ),
        }
    }
}

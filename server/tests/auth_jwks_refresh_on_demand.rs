//! T053 — on-demand JWKS refresh rate-limiting + post-rotation success
//! (SC-009, Story 4 Acceptance #3, R6).
//!
//! Two focused real-time tests against the dual-audience router. The
//! `on_demand_refresh` helper tracks its rate-limit window via
//! `std::time::SystemTime::now()`, which is unaffected by
//! `tokio::time::pause`/`advance`. Each test runs under a real-time
//! multi-thread runtime.
//!
//!   1. **`storm_collapses_to_at_most_one_fetch`** — verifies SC-009.
//!      The storm fires 1000 concurrent requests with a token signed
//!      by a key not in any JWKS; the lock-free CAS + Notify in
//!      `on_demand_refresh` consolidates all 1000 to AT MOST one fetch
//!      per rate-limit window. We use the production-default 30s
//!      window so the entire storm fits in one window and the upper
//!      bound is exactly `baseline + 1`.
//!
//!   2. **`refresh_succeeds_after_window_elapses_with_rotation`** —
//!      uses a 2-second window so the wall-clock wait between phases
//!      stays small. A single failed-signature request fires an
//!      initial on-demand fetch (against the unchanged JWKS, so the
//!      retry still 401s); after `set_jwks` rotates the served JWKS
//!      to include the formerly-missing key and the rate-limit
//!      window elapses, a fresh request triggers a second on-demand
//!      fetch that installs the rotated JWKS and the retry succeeds.

mod common;

use std::sync::Arc;
use std::time::Duration;

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
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use openidconnect::reqwest;
use tokio::task::JoinSet;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const VAULT_KID: &str = "od-vault-key";
const ADMIN_KID: &str = "od-admin-key";
const BAD_KID: &str = "od-bad-key";
const VAULT_AUD: &str = "apokryphos-od-vault";
const ADMIN_AUD: &str = "apokryphos-od-admin";

const STORM_SIZE: usize = 1000;

/// Fixture for both tests. The caller passes `on_demand_interval_secs`
/// so each test picks its own window size.
struct Fixture {
    vault_mock: MockOidcProvider,
    bad_signing: p256::ecdsa::SigningKey,
    bad_jwk: serde_json::Value,
    bad_token: String,
    router: axum::Router,
}

async fn setup(on_demand_interval_secs: u64, rng_seed: u64) -> Fixture {
    let mut rng = deterministic_rng(rng_seed);
    let vault_signing = generate_es256_keypair(&mut rng);
    let admin_signing = generate_es256_keypair(&mut rng);
    let bad_signing = generate_es256_keypair(&mut rng);

    let vault_jwk = es256_public_jwk(vault_signing.verifying_key(), Some(VAULT_KID));
    let admin_jwk = es256_public_jwk(admin_signing.verifying_key(), Some(ADMIN_KID));
    let bad_jwk = es256_public_jwk(bad_signing.verifying_key(), Some(BAD_KID));

    let vault_mock =
        MockOidcProvider::start(serde_json::json!({ "keys": [vault_jwk.clone()] })).await;
    let admin_mock = MockOidcProvider::start(serde_json::json!({ "keys": [admin_jwk] })).await;

    let mut auth = AuthConfig::default();
    auth.on_demand_refresh_min_interval_secs = on_demand_interval_secs;
    let auth_cfg = Arc::new(auth.clone());

    let cfg = ServerConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        block_size_bytes: 1024 * 1024,
        storage_backend: StorageBackend::None,
        trusted_proxies: vec![],
        vault_oidc: OidcAudienceConfig {
            issuer_url: vault_mock.issuer_url(),
            audience: VAULT_AUD.to_string(),
        },
        admin_oidc: OidcAudienceConfig {
            issuer_url: admin_mock.issuer_url(),
            audience: ADMIN_AUD.to_string(),
        },
        drain_timeout: Duration::from_secs(5),
        auth,
    };
    let http_client = reqwest::Client::new();
    let (vault_ctx, admin_ctx) = init_contexts(&cfg, &http_client)
        .await
        .expect("init_contexts must succeed against disjoint mocks");
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(state, Some(vault_ctx), Some(admin_ctx), Some(replay_store));

    // Token signed with the bad key, cnf.jkt also references the bad
    // key — so once the bad key is rotated into the JWKS, the
    // signature + jkt-match both succeed.
    let cnf_jkt = es256_thumbprint_b64url(bad_signing.verifying_key());
    let iss = vault_mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    let bad_token = mint_es256_token(
        &MintTokenClaims {
            sub: "od-user".to_string(),
            aud: VAULT_AUD.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &bad_signing,
        Some(BAD_KID),
        false,
    );

    // Drop the admin mock — its server task is no longer needed.
    // The admin context's JWKS was already fetched and stored in
    // its ArcSwap; the test never triggers an admin-side refresh.
    drop(admin_mock);

    Fixture {
        vault_mock,
        bad_signing,
        bad_jwk,
        bad_token,
        router,
    }
}

fn build_request(fixture: &Fixture, jti: &str) -> Request<Body> {
    let proof = mint_es256_dpop_proof(
        &fixture.bad_signing,
        "GET",
        "http://127.0.0.1/api/whoami",
        now_unix_secs(),
        jti,
        Some(&fixture.bad_token),
    );
    Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", fixture.bad_token)).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(&proof).unwrap())
        .body(Body::empty())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storm_collapses_to_at_most_one_fetch_within_rate_limit_window() {
    // Production-default 30s window so the entire 1000-request storm
    // definitely fits in a single window. SC-009 then bounds the
    // result to exactly `baseline + 1` fetches.
    let fixture = setup(30, 909).await;
    let baseline = fixture.vault_mock.jwks_fetch_count();
    assert_eq!(baseline, 1);

    let mut storm = JoinSet::new();
    for i in 0..STORM_SIZE {
        let router_clone = fixture.router.clone();
        let req = build_request(&fixture, &format!("od-storm-{i:04}"));
        storm.spawn(async move { router_clone.oneshot(req).await.unwrap().status() });
    }
    let mut statuses = Vec::with_capacity(STORM_SIZE);
    while let Some(joined) = storm.join_next().await {
        statuses.push(joined.unwrap());
    }
    assert_eq!(statuses.len(), STORM_SIZE);
    for (i, s) in statuses.iter().enumerate() {
        assert_eq!(*s, StatusCode::UNAUTHORIZED, "storm request {i} must 401");
    }

    let after = fixture.vault_mock.jwks_fetch_count();
    assert!(
        after <= baseline + 1,
        "storm produced {after} fetches; SC-009 caps at baseline {baseline} + 1 \
         (= {})",
        baseline + 1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_succeeds_after_window_elapses_with_rotation() {
    // 2-second window so the rotation wait costs only ~3s of real time.
    let fixture = setup(2, 910).await;

    // Phase 1: fire one request to consume the rate-limit window.
    // The cached JWKS lacks bad_key, so the request 401s — but the
    // on-demand refresh did run, advancing last_on_demand_refresh.
    let resp = fixture
        .router
        .clone()
        .oneshot(build_request(&fixture, "od-rotation-prime"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Phase 2: rotate the served JWKS to include the bad key.
    fixture
        .vault_mock
        .set_jwks(serde_json::json!({ "keys": [fixture.bad_jwk.clone()] }));

    // Phase 3: wait past the rate-limit window so a fresh on-demand
    // refresh can fire. on_demand_refresh uses SystemTime::now(), so
    // tokio's virtual clock can't substitute for the wall-clock wait.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Phase 4: a fresh request triggers on-demand refresh against
    // the rotated JWKS; install_refreshed_jwks's overlap check passes
    // (admin's key is unchanged); the retry validates → 200.
    let resp2 = fixture
        .router
        .clone()
        .oneshot(build_request(&fixture, "od-rotation-after"))
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "after JWKS rotation + window elapse, the same token must validate"
    );
}

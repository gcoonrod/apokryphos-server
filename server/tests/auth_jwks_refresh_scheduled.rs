//! T052 — scheduled JWKS refresh (SC-008, Story 4 Acceptance #1–#2,
//! FR-003a, FR-004 scheduled side).
//!
//! Three nested scenarios, each spawning a real `jwks::scheduled_refresh_task`
//! against a `MockOidcProvider` under `tokio::time::pause()`:
//!
//!   1. **Baseline cadence**: `init_single_context` makes one JWKS fetch
//!      at startup. After spawning the task with `jwks_refresh_secs=60`,
//!      advancing time by 61s produces exactly one more fetch. Inducing
//!      a 500 on the next request and advancing again produces another
//!      fetch *attempt* (counter advances) but does not evict the
//!      cached JWKS (a token signed with the cached key still validates).
//!   2. **Empty-JWKS-on-refresh** (analyze-findings G2): the mock returns
//!      a `{"keys": []}` body on the next refresh. The parser surfaces
//!      `JwksFetchError::Empty`; the task logs `jwks.scheduled_refresh_failed`
//!      with no key material; the previously-cached non-empty JWKS still
//!      serves a token-validation request (no eviction, FR-003a).
//!   3. **jwks_uri change propagation** (analyze-findings G3): after the
//!      mock's discovery doc is reconfigured to advertise `/jwks-v2.json`
//!      and time advances past one discovery refresh + one JWKS refresh,
//!      the alternate endpoint's counter shows exactly one hit and the
//!      original `/jwks.json` counter is unchanged from before the swap.
//!
//! Each scenario is its own `#[tokio::test]` so a failure isolates to
//! the specific behavior under test.

#![allow(clippy::field_reassign_with_default)]
mod common;

use std::sync::Arc;
use std::time::Duration;

use apokryphos_server::AppState;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::auth::{AudienceTag, JtiReplayStore, init_single_context};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig};
use apokryphos_server::routes::build_router;
use apokryphos_server::shutdown::ShutdownRx;
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use serde_json::json;
use tokio::sync::watch;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const VAULT_KID: &str = "scheduled-refresh-key";
const VAULT_AUD: &str = "apokryphos-sched-vault";

/// `tokio::time::advance` yields once, but the spawned refresh task
/// also awaits an HTTP round-trip to the in-process mock — completion
/// requires multiple runtime polls. Pump the executor with N yields so
/// every queued task has a chance to make progress before the test
/// asserts. 50 is empirically generous; HTTP locally takes <10 polls.
async fn pump_tasks() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

/// Tight AuthConfig: 60s JWKS refresh, 24h discovery refresh (kept high
/// so it doesn't fire during sub-cases that don't want it).
fn tight_auth() -> AuthConfig {
    let mut auth = AuthConfig::default();
    auth.jwks_refresh_secs = 60;
    auth
}

struct Fixture {
    mock: MockOidcProvider,
    signing_key: p256::ecdsa::SigningKey,
    ctx: Arc<apokryphos_server::auth::OidcContext>,
    router: axum::Router,
    shutdown_tx: watch::Sender<bool>,
    _shutdown_rx_keepalive: ShutdownRx,
}

async fn setup() -> Fixture {
    let mut rng = deterministic_rng(708);
    let signing_key = generate_es256_keypair(&mut rng);
    let jwk = es256_public_jwk(signing_key.verifying_key(), Some(VAULT_KID));
    let mock = MockOidcProvider::start(json!({ "keys": [jwk] })).await;

    let auth_cfg = Arc::new(tight_auth());
    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: VAULT_AUD.to_string(),
    };
    let http_client = openidconnect::reqwest::Client::new();
    let ctx = init_single_context(
        AudienceTag::Vault,
        &oidc_cfg,
        Arc::clone(&auth_cfg),
        &http_client,
    )
    .await
    .expect("init_single_context must succeed against mock");

    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(state, Some(Arc::clone(&ctx)), None, Some(replay_store));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    Fixture {
        mock,
        signing_key,
        ctx,
        router,
        shutdown_tx,
        _shutdown_rx_keepalive: shutdown_rx,
    }
}

fn mint_request(fixture: &Fixture, jti: &str) -> Request<Body> {
    let cnf_jkt = es256_thumbprint_b64url(fixture.signing_key.verifying_key());
    let iss = fixture
        .mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    let token = mint_es256_token(
        &MintTokenClaims {
            sub: "sched-user".to_string(),
            aud: VAULT_AUD.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &fixture.signing_key,
        Some(VAULT_KID),
        false,
    );
    let proof = mint_es256_dpop_proof(
        &fixture.signing_key,
        "GET",
        "http://127.0.0.1/api/whoami",
        now,
        jti,
        Some(&token),
    );
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
}

#[tokio::test(start_paused = true)]
async fn scheduled_refresh_ticks_and_retains_cache_on_failure() {
    let fixture = setup().await;
    assert_eq!(
        fixture.mock.jwks_fetch_count(),
        1,
        "init_single_context made the startup fetch"
    );

    // Spawn the refresh task, then pump the executor so the task body
    // actually starts. The interval is created INSIDE the task at the
    // current virtual time — if we advanced time before pumping, the
    // interval's first scheduled tick would land in the future and the
    // test would deadlock at the assertion. Always: spawn → pump →
    // advance → pump.
    let rx = fixture._shutdown_rx_keepalive.clone();
    let task = tokio::spawn(apokryphos_server::auth::jwks::scheduled_refresh_task(
        Arc::clone(&fixture.ctx),
        rx,
    ));
    pump_tasks().await;

    tokio::time::advance(Duration::from_secs(61)).await;
    pump_tasks().await;
    assert_eq!(
        fixture.mock.jwks_fetch_count(),
        2,
        "one refresh tick after 61s of virtual time"
    );

    // Induce a 500 on the next /jwks.json. Advance another interval —
    // the refresh attempt fires (counter advances) but the cached JWKS
    // is retained, so a token signed with the original key still works.
    fixture.mock.set_jwks_status_override(500);
    tokio::time::advance(Duration::from_secs(61)).await;
    pump_tasks().await;
    assert_eq!(
        fixture.mock.jwks_fetch_count(),
        3,
        "failed-refresh attempt also advances the counter"
    );
    // Clear the override before issuing the validation request — the
    // request itself doesn't fetch JWKS (cache hit), but a follow-on
    // on-demand refresh shouldn't trip the override either.
    fixture.mock.set_jwks_status_override(0);

    // Cached JWKS is still valid: a fresh request validates.
    let response = fixture
        .router
        .clone()
        .oneshot(mint_request(&fixture, "jti-after-fail"))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "cached JWKS must still serve after a failed refresh (FR-003a)"
    );

    let _ = fixture.shutdown_tx.send(true);
    let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn scheduled_refresh_with_empty_jwks_retains_cache() {
    let fixture = setup().await;
    assert_eq!(fixture.mock.jwks_fetch_count(), 1);

    let rx = fixture._shutdown_rx_keepalive.clone();
    let task = tokio::spawn(apokryphos_server::auth::jwks::scheduled_refresh_task(
        Arc::clone(&fixture.ctx),
        rx,
    ));
    pump_tasks().await; // let the task create its interval at t=0

    // Swap the served JWKS to an empty key set. Parser will return
    // JwksFetchError::Empty; the task logs warn and retains cache.
    fixture.mock.set_jwks(json!({ "keys": [] }));
    tokio::time::advance(Duration::from_secs(61)).await;
    pump_tasks().await;

    // The refresh ran (counter incremented) but produced no install.
    assert_eq!(fixture.mock.jwks_fetch_count(), 2);

    // The cached JWKS still serves a real validation request. Restore
    // the served JWKS first so any on-demand refresh triggered by the
    // request (it shouldn't be, but defensive) wouldn't drain it.
    let original_jwk = es256_public_jwk(fixture.signing_key.verifying_key(), Some(VAULT_KID));
    fixture.mock.set_jwks(json!({ "keys": [original_jwk] }));
    let response = fixture
        .router
        .clone()
        .oneshot(mint_request(&fixture, "jti-empty-refresh-after"))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "empty-JWKS refresh response MUST NOT evict the cached non-empty JWKS"
    );

    let _ = fixture.shutdown_tx.send(true);
    let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn jwks_uri_change_propagates_through_scheduled_discovery_refresh() {
    // Stagger the intervals so discovery fires BEFORE the JWKS refresh
    // task observes the updated `jwks_uri`. With equal intervals, both
    // tasks tick at the same virtual time and the ordering is
    // non-deterministic — JWKS could fetch the old URL before discovery
    // had a chance to swap the cache. Using discovery=60s, JWKS=120s:
    //   t=60: discovery fires, swaps ctx.discovery to advertise /jwks-v2.json.
    //   t=120: JWKS task fires, reads ctx.discovery, fetches /jwks-v2.json.
    let mut auth = AuthConfig::default();
    auth.jwks_refresh_secs = 120;
    auth.discovery_refresh_secs = 60;
    let auth_cfg = Arc::new(auth);

    let mut rng = deterministic_rng(709);
    let signing_key = generate_es256_keypair(&mut rng);
    let jwk = es256_public_jwk(signing_key.verifying_key(), Some(VAULT_KID));
    let mock = MockOidcProvider::start(json!({ "keys": [jwk] })).await;
    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: VAULT_AUD.to_string(),
    };
    let http_client = openidconnect::reqwest::Client::new();
    let ctx = init_single_context(
        AudienceTag::Vault,
        &oidc_cfg,
        Arc::clone(&auth_cfg),
        &http_client,
    )
    .await
    .expect("init_single_context must succeed");

    // Baseline: startup did one /jwks.json fetch, no /jwks-v2.json yet.
    let baseline_jwks = mock.jwks_fetch_count();
    assert_eq!(baseline_jwks, 1);
    assert_eq!(mock.jwks_v2_fetch_count(), 0);

    // Flip the discovery doc's jwks_uri BEFORE spawning the tasks, so
    // the next discovery refresh (after one interval) immediately
    // advertises the new URL.
    mock.set_discovery_jwks_uri("/jwks-v2.json");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let discovery_task = tokio::spawn(apokryphos_server::auth::discovery::scheduled_refresh_task(
        Arc::clone(&ctx),
        shutdown_rx.clone(),
    ));
    let jwks_task = tokio::spawn(apokryphos_server::auth::jwks::scheduled_refresh_task(
        Arc::clone(&ctx),
        shutdown_rx,
    ));
    pump_tasks().await; // both tasks create their intervals at t=0

    // Advance past one discovery interval first — that pulls the new
    // jwks_uri into the cached discovery doc.
    tokio::time::advance(Duration::from_secs(61)).await;
    pump_tasks().await;
    // Then advance to past one JWKS interval (total elapsed ≈ 121s) so
    // the JWKS task fetches using the updated discovery doc's URL.
    tokio::time::advance(Duration::from_secs(60)).await;
    pump_tasks().await;

    assert_eq!(
        mock.jwks_v2_fetch_count(),
        1,
        "scheduled JWKS refresh after the discovery flip must hit /jwks-v2.json"
    );
    assert_eq!(
        mock.jwks_fetch_count(),
        baseline_jwks,
        "the old /jwks.json must not have been hit again — FR-003a's edge case"
    );

    // Signal shutdown and await the background tasks so the test
    // deterministically tears down. Dropping the JoinHandles would
    // detach them — they'd keep running until the runtime exits, and
    // could in principle interfere with subsequent tests sharing the
    // process.
    let _ = shutdown_tx.send(true);
    let _ = discovery_task.await;
    let _ = jwks_task.await;
}

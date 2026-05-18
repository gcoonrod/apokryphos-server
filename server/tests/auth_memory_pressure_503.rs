//! T046 — memory-pressure 503 edge case (FR-021, spec edge case,
//! contracts/http.md §Memory-pressure response, validate-plan G2).
//!
//! Fills a `JtiReplayStore` to its `max_replay_entries` budget with
//! synthetic in-window entries, then issues a fully valid whoami
//! request through the *matching* guard (vault → `/api/whoami`,
//! admin → `/admin/whoami`). The contract is:
//!
//!   - The response is `503 Service Unavailable` with `Content-Length: 0`,
//!     no `Content-Type`, no `Retry-After`, and an empty body. (This is
//!     the byte-shape from `auth::failure::respond_503_memory_pressure`.)
//!   - No previously-inserted jti is silently evicted. Re-inserting any
//!     of the four pre-filled jtis returns `InsertError::Replayed` —
//!     proof that FR-021's "no eviction" guarantee held.
//!
//! Both `VaultGuardService::call` and `AdminGuardService::call` carry
//! their own `match AuthFailure::MemoryPressure => respond_503_memory_pressure()`
//! arm — the two guard types do not share that dispatch (they share
//! only `authenticate_common`). Each #[tokio::test] below drives one
//! of those arms end-to-end so both are exercised.

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
use axum::http::{HeaderValue, Method, Request, Response, StatusCode, header};
use tower::ServiceExt;

use crate::common::minimal_valid_config;

#[tokio::test]
async fn vault_memory_pressure_returns_503_without_evicting() {
    drive_memory_pressure_scenario(Scenario {
        audience: AudienceTag::Vault,
        rng_seed: 503,
        kid: "vault-mp-key",
        audience_str: "apokryphos-mp-vault",
        sub: "vault-mp-user",
        path: "/api/whoami",
        jti_prefix: "jti-vault-mp",
        fresh_jti: "jti-vault-fresh",
    })
    .await;
}

#[tokio::test]
async fn admin_memory_pressure_returns_503_without_evicting() {
    drive_memory_pressure_scenario(Scenario {
        audience: AudienceTag::Admin,
        rng_seed: 504,
        kid: "admin-mp-key",
        audience_str: "apokryphos-mp-admin",
        sub: "admin-mp-root",
        path: "/admin/whoami",
        jti_prefix: "jti-admin-mp",
        fresh_jti: "jti-admin-fresh",
    })
    .await;
}

struct Scenario {
    audience: AudienceTag,
    rng_seed: u64,
    kid: &'static str,
    audience_str: &'static str,
    sub: &'static str,
    path: &'static str,
    jti_prefix: &'static str,
    fresh_jti: &'static str,
}

async fn drive_memory_pressure_scenario(s: Scenario) {
    // ── Setup: per-audience context against a one-key mock + shared store. ─
    let mut rng = deterministic_rng(s.rng_seed);
    let signing_key = generate_es256_keypair(&mut rng);
    let jwks_doc = serde_json::json!({
        "keys": [es256_public_jwk(signing_key.verifying_key(), Some(s.kid))]
    });
    let mock = MockOidcProvider::start(jwks_doc).await;

    // Tight budget so the test is fast: 4 entries fill the store.
    let mut auth = AuthConfig::default();
    auth.max_replay_entries = 4;
    let auth_cfg = Arc::new(auth);

    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: s.audience_str.to_string(),
    };
    let http_client = openidconnect::reqwest::Client::new();
    let ctx = init_single_context(s.audience, &oidc_cfg, Arc::clone(&auth_cfg), &http_client)
        .await
        .expect("init_single_context against MockOidcProvider must succeed");

    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    // ── Pre-fill the replay store with 4 synthetic in-window jtis. ──────
    // Tag the keys with the matching audience byte so they're in the
    // same "subspace" as the request we're about to issue. Deadlines
    // far in the future — FR-021 forbids silent eviction of these.
    let prefilled_jtis: [String; 4] = std::array::from_fn(|i| format!("{}-{}", s.jti_prefix, i));
    let far_future = Instant::now() + Duration::from_secs(3600);
    for raw_jti in &prefilled_jtis {
        let key = JtiKey::new(s.audience.as_jti_key_byte(), raw_jti);
        replay_store
            .try_insert(key, far_future)
            .expect("synthetic prefill must insert cleanly");
    }
    assert_eq!(replay_store.len(), 4);

    // Mount only the audience under test on the router. The other slot
    // stays `None` — there's only one guard's translation arm we're
    // exercising per call.
    let (vault_ctx, admin_ctx) = match s.audience {
        AudienceTag::Vault => (Some(ctx), None),
        AudienceTag::Admin => (None, Some(ctx)),
    };
    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(state, vault_ctx, admin_ctx, Some(Arc::clone(&replay_store)));

    // ── Mint a fully valid token + DPoP proof with a fresh jti. ─────────
    let cnf_jkt = es256_thumbprint_b64url(signing_key.verifying_key());
    let iss = mock.issuer_url().as_str().trim_end_matches('/').to_string();
    let now = now_unix_secs();
    let token = mint_es256_token(
        &MintTokenClaims {
            sub: s.sub.to_string(),
            aud: s.audience_str.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &signing_key,
        Some(s.kid),
        false,
    );
    let proof = mint_es256_dpop_proof(
        &signing_key,
        "GET",
        &format!("http://127.0.0.1{}", s.path),
        now,
        s.fresh_jti,
        Some(&token),
    );

    let request = Request::builder()
        .method(Method::GET)
        .uri(s.path)
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", token)).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(&proof).unwrap())
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_503_byte_shape(response).await;

    // ── FR-021 no-eviction guarantee. Each prefilled jti must still be
    // present — re-inserting returns Replayed (not Ok). ─────────────────
    for raw_jti in &prefilled_jtis {
        let key = JtiKey::new(s.audience.as_jti_key_byte(), raw_jti);
        match replay_store.try_insert(key, far_future) {
            Err(ReplayInsertError::Replayed) => {} // expected
            Err(other) => panic!(
                "expected Replayed for {raw_jti} ({:?}), got {other}",
                s.audience
            ),
            Ok(()) => panic!(
                "FR-021 violation: jti {raw_jti} was silently evicted under memory pressure \
                 (audience {:?})",
                s.audience
            ),
        }
    }
}

async fn assert_503_byte_shape(response: Response<Body>) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response.headers().get(header::CONTENT_TYPE).is_none(),
        "503 MUST NOT carry Content-Type"
    );
    assert!(
        response.headers().get(header::RETRY_AFTER).is_none(),
        "503 MUST NOT carry Retry-After — the byte-shape is fixed"
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
}

//! T044 — cross-audience byte-identical 401 (SC-002, Story 2 Acceptance #3).
//!
//! Builds the full dual-context router with two `MockOidcProvider`s
//! serving disjoint JWKS. Then drives the following requests and captures
//! `(status, headers, body)` from each:
//!
//!   (a) `GET /api/whoami` with no Authorization header (vault no-auth)
//!   (b) `GET /api/whoami` with a valid admin-audience token + proof
//!       (audience-mismatch at the vault guard)
//!   (c) `GET /admin/whoami` with a valid vault-audience token + proof
//!       (audience-mismatch at the admin guard)
//!   (d) `GET /admin/whoami` with no Authorization header (admin no-auth)
//!
//! The contract: (a) ≡ (b) ≡ (c) ≡ (d) byte-for-byte. Any leak between
//! the four cases — different `Content-Length`, different header
//! ordering, different `WWW-Authenticate` value, anything observable —
//! breaks SC-002 because an attacker probing /api/whoami with an admin
//! token could distinguish "wrong audience" from "no token at all" and
//! confirm the route exists.
//!
//! This test is structurally important: byte-identity here is the only
//! guarantee that token validation timing or error category cannot leak
//! the audience binding to an attacker. We use deterministic-order
//! comparison: collect headers into a sorted Vec<(name, value)> and
//! compare the canonicalized sequence.

mod common;

use std::sync::Arc;

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
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, Response, StatusCode, header};
use openidconnect::reqwest;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const VAULT_KID: &str = "vault-iso-key";
const ADMIN_KID: &str = "admin-iso-key";
const VAULT_AUD: &str = "apokryphos-iso-vault";
const ADMIN_AUD: &str = "apokryphos-iso-admin";

struct Fixture {
    router: axum::Router,
    vault_signing: p256::ecdsa::SigningKey,
    admin_signing: p256::ecdsa::SigningKey,
    vault_issuer: url::Url,
    admin_issuer: url::Url,
    // Mocks held so their background tasks aren't aborted until the
    // fixture drops at test end.
    _vault_mock: MockOidcProvider,
    _admin_mock: MockOidcProvider,
}

async fn setup_fixture() -> Fixture {
    let mut rng = deterministic_rng(44);
    let vault_signing = generate_es256_keypair(&mut rng);
    let admin_signing = generate_es256_keypair(&mut rng);

    let vault_jwks = serde_json::json!({
        "keys": [es256_public_jwk(vault_signing.verifying_key(), Some(VAULT_KID))]
    });
    let admin_jwks = serde_json::json!({
        "keys": [es256_public_jwk(admin_signing.verifying_key(), Some(ADMIN_KID))]
    });
    let vault_mock = MockOidcProvider::start(vault_jwks).await;
    let admin_mock = MockOidcProvider::start(admin_jwks).await;
    let vault_issuer = vault_mock.issuer_url();
    let admin_issuer = admin_mock.issuer_url();

    let cfg = ServerConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        block_size_bytes: 1024 * 1024,
        storage_backend: StorageBackend::None,
        trusted_proxies: vec![],
        vault_oidc: OidcAudienceConfig {
            issuer_url: vault_issuer.clone(),
            audience: VAULT_AUD.to_string(),
        },
        admin_oidc: OidcAudienceConfig {
            issuer_url: admin_issuer.clone(),
            audience: ADMIN_AUD.to_string(),
        },
        drain_timeout: std::time::Duration::from_secs(5),
        auth: AuthConfig::default(),
    };
    let http_client = reqwest::Client::new();
    let (vault_ctx, admin_ctx) = init_contexts(&cfg, &http_client)
        .await
        .expect("init_contexts must succeed against disjoint mocks");

    let auth_cfg = Arc::new(cfg.auth.clone());
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(state, Some(vault_ctx), Some(admin_ctx), Some(replay_store));

    Fixture {
        router,
        vault_signing,
        admin_signing,
        vault_issuer,
        admin_issuer,
        _vault_mock: vault_mock,
        _admin_mock: admin_mock,
    }
}

/// Mint a token signed by `signing` for audience `aud`, issued by `issuer`.
fn mint_token(
    signing: &p256::ecdsa::SigningKey,
    kid: &str,
    aud: &str,
    issuer: &url::Url,
    sub: &str,
) -> String {
    let cnf_jkt = es256_thumbprint_b64url(signing.verifying_key());
    let iss = issuer.as_str().trim_end_matches('/').to_string();
    let now = now_unix_secs();
    let claims = MintTokenClaims {
        sub: sub.to_string(),
        aud: aud.to_string(),
        iss,
        iat: now,
        exp: now + 3600,
        nbf: None,
        cnf_jkt,
    };
    mint_es256_token(&claims, signing, Some(kid), false)
}

fn mint_proof(
    signing: &p256::ecdsa::SigningKey,
    htm: &str,
    htu: &str,
    jti: &str,
    token: &str,
) -> String {
    let now = now_unix_secs();
    mint_es256_dpop_proof(signing, htm, htu, now, jti, Some(token))
}

/// Captured wire image of a response: status code + sorted header list +
/// body bytes. Header comparison is order-insensitive (per HTTP/1.1) so
/// we don't false-fail on axum's internal header-emission order.
#[derive(Debug, PartialEq, Eq)]
struct WireImage {
    status: StatusCode,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

async fn capture(response: Response<Body>) -> WireImage {
    let status = response.status();
    let mut headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    WireImage {
        status,
        headers,
        body,
    }
}

#[tokio::test]
async fn cross_audience_attempts_byte_identical_401() {
    let fixture = setup_fixture().await;

    // (a) Vault no-auth.
    let req_a = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .body(Body::empty())
        .unwrap();

    // (b) Admin token at vault route — must be rejected at the vault
    // guard's audience check, with the same byte image as (a).
    let admin_token = mint_token(
        &fixture.admin_signing,
        ADMIN_KID,
        ADMIN_AUD,
        &fixture.admin_issuer,
        "admin-root",
    );
    let admin_proof_at_vault = mint_proof(
        &fixture.admin_signing,
        "GET",
        "http://127.0.0.1/api/whoami",
        "jti-b-1",
        &admin_token,
    );
    let req_b = Request::builder()
        .method(Method::GET)
        .uri("/api/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", admin_token)).unwrap(),
        )
        .header(
            "dpop",
            HeaderValue::from_str(&admin_proof_at_vault).unwrap(),
        )
        .body(Body::empty())
        .unwrap();

    // (c) Vault token at admin route — must be rejected at the admin
    // guard's audience check.
    let vault_token = mint_token(
        &fixture.vault_signing,
        VAULT_KID,
        VAULT_AUD,
        &fixture.vault_issuer,
        "vault-user-1",
    );
    let vault_proof_at_admin = mint_proof(
        &fixture.vault_signing,
        "GET",
        "http://127.0.0.1/admin/whoami",
        "jti-c-1",
        &vault_token,
    );
    let req_c = Request::builder()
        .method(Method::GET)
        .uri("/admin/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", vault_token)).unwrap(),
        )
        .header(
            "dpop",
            HeaderValue::from_str(&vault_proof_at_admin).unwrap(),
        )
        .body(Body::empty())
        .unwrap();

    // (d) Admin no-auth — symmetric mirror of (a).
    let req_d = Request::builder()
        .method(Method::GET)
        .uri("/admin/whoami")
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .body(Body::empty())
        .unwrap();

    let resp_a = fixture.router.clone().oneshot(req_a).await.unwrap();
    let resp_b = fixture.router.clone().oneshot(req_b).await.unwrap();
    let resp_c = fixture.router.clone().oneshot(req_c).await.unwrap();
    let resp_d = fixture.router.clone().oneshot(req_d).await.unwrap();

    let img_a = capture(resp_a).await;
    let img_b = capture(resp_b).await;
    let img_c = capture(resp_c).await;
    let img_d = capture(resp_d).await;

    assert_eq!(img_a.status, StatusCode::UNAUTHORIZED, "(a) must be 401");
    // SC-002: every cross-audience or no-auth attempt yields the same
    // wire image. Pairwise equality is sufficient.
    assert_eq!(
        img_a, img_b,
        "vault no-auth vs admin-token-at-vault diverged"
    );
    assert_eq!(
        img_a, img_c,
        "vault no-auth vs vault-token-at-admin diverged"
    );
    assert_eq!(img_a, img_d, "vault no-auth vs admin no-auth diverged");
}

//! Phase 3 conformance harness — Stories 1-3 smoke tests.
//!
//! These three tests cover the Phase 3 user stories at the smoke-test level:
//!
//!   - Story 1: vault audience happy path (`GET /api/whoami` → 200 + sub).
//!   - Story 2: cross-audience isolation (admin token at vault route → 401).
//!   - Story 3: DPoP replay rejection (same proof presented twice → second 401).
//!
//! All tests drive the router through `TestServer`'s public API only —
//! no `pub(crate)` or `pub(in crate::auth)` reach-through. That isolation
//! is the point of the conformance harness: Phase 7 will extend this matrix
//! to the full FAPI 2.0 + DPoP profile suite, and the deeper the helper-API
//! surface stays, the more invariant Phase 3's internal refactors are to
//! Phase 7's test code.

use crate::helpers::{Audience, TestServer};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use serde_json::Value;

const VAULT_URI: &str = "/api/whoami";
const ADMIN_URI: &str = "/admin/whoami";
const VAULT_HTU: &str = "http://127.0.0.1/api/whoami";
const ADMIN_HTU: &str = "http://127.0.0.1/admin/whoami";

fn req(method: Method, uri: &str, token: &str, proof: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", token)).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(proof).unwrap())
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn test_story_1_vault_happy_path() {
    let server = TestServer::start().await;

    let sub = "conformance-vault-user-1";
    let token = server.mint_vault_token(sub);
    let proof = server.mint_dpop_proof(Audience::Vault, &token, "GET", VAULT_HTU, "smoke-1-jti");

    let resp = server
        .oneshot(req(Method::GET, VAULT_URI, &token, &proof))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).expect("JSON body");
    let obj = body.as_object().expect("object body");
    assert_eq!(obj.len(), 1, "FR-027: body MUST contain exactly one field");
    assert_eq!(
        obj.get("sub").and_then(Value::as_str),
        Some(sub),
        "sub must round-trip from the token claim",
    );
}

#[tokio::test]
async fn test_story_2_cross_audience_isolation() {
    let server = TestServer::start().await;

    // Mint an admin-audience token and proof, present them at the vault
    // route. The vault guard's audience check rejects with the uniform 401.
    let admin_token = server.mint_admin_token("conformance-admin-root");
    let admin_proof_at_vault = server.mint_dpop_proof(
        Audience::Admin,
        &admin_token,
        "GET",
        VAULT_HTU,
        "smoke-2-jti",
    );

    let resp = server
        .oneshot(req(
            Method::GET,
            VAULT_URI,
            &admin_token,
            &admin_proof_at_vault,
        ))
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "admin token at vault route MUST be rejected (cross-audience isolation)",
    );
    let www_auth = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string());
    assert_eq!(
        www_auth.as_deref(),
        Some(r#"DPoP algs="PS256 ES256""#),
        "FR-029: fixed WWW-Authenticate value on 401",
    );
    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(body.is_empty(), "401 body MUST be empty");
}

#[tokio::test]
async fn test_story_3_dpop_replay() {
    let server = TestServer::start().await;

    let token = server.mint_vault_token("conformance-replay-user");
    let proof = server.mint_dpop_proof(
        Audience::Vault,
        &token,
        "GET",
        VAULT_HTU,
        "smoke-3-replayed-jti",
    );

    // First presentation: success.
    let resp1 = server
        .oneshot(req(Method::GET, VAULT_URI, &token, &proof))
        .await;
    assert_eq!(
        resp1.status(),
        StatusCode::OK,
        "first presentation of a fresh proof must succeed",
    );

    // Second presentation of the same proof: replay rejected.
    let resp2 = server
        .oneshot(req(Method::GET, VAULT_URI, &token, &proof))
        .await;
    assert_eq!(
        resp2.status(),
        StatusCode::UNAUTHORIZED,
        "replayed jti MUST be rejected (FR-021)",
    );
}

#[tokio::test]
async fn test_admin_happy_path() {
    // Bonus coverage: the admin mirror of test_story_1. Not strictly one
    // of the three smoke tests T057 names, but it validates the admin-side
    // of TestServer's helper API which Phase 7 will lean on heavily.
    let server = TestServer::start().await;

    let sub = "conformance-admin-user-1";
    let token = server.mint_admin_token(sub);
    let proof =
        server.mint_dpop_proof(Audience::Admin, &token, "GET", ADMIN_HTU, "smoke-admin-jti");

    let resp = server
        .oneshot(req(Method::GET, ADMIN_URI, &token, &proof))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).expect("JSON body");
    let obj = body.as_object().expect("object body");
    assert_eq!(obj.len(), 1);
    assert_eq!(obj.get("sub").and_then(Value::as_str), Some(sub));
}

//! T034 — 401 + admin-fence regression test (spec FR-020 / FR-021 / SC-004).
//!
//! Asserts:
//!   - GET / PUT / DELETE `/api/blocks/{id}` with no auth header → 401
//!     with the Phase 3 frozen contract (`WWW-Authenticate: DPoP
//!     algs="PS256 ES256"`, empty body)
//!   - GET / PUT / DELETE `/api/blocks/{id}` with no DPoP header → same 401
//!   - The admin auth tree does NOT expose `/api/blocks/{id}` — admin
//!     tokens cannot reach block routes regardless of validity (the route
//!     simply does not exist on the admin subtree, so requests fall
//!     through to the 404 fallback or to a vault-guard 401).

mod common;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use tower::ServiceExt;

use crate::common::{block_fixture_request, build_block_fixture};

const BLOCK_ID: &str = "Auth401RegressionTestBlock00000000000000000";

fn unauthenticated_request(method: Method, block_id: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(format!("/api/blocks/{block_id}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .body(Body::empty())
        .unwrap()
}

async fn assert_phase3_401(response: axum::http::Response<Body>) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some(r#"DPoP algs="PS256 ES256""#),
        "FR-029: fixed WWW-Authenticate value"
    );
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body.is_empty(), "FR-029: 401 body MUST be empty");
}

#[tokio::test]
async fn block_get_without_auth_returns_phase3_401() {
    let fixture = build_block_fixture(34).await;
    assert_eq!(BLOCK_ID.len(), 43);
    let response = fixture
        .router
        .clone()
        .oneshot(unauthenticated_request(Method::GET, BLOCK_ID))
        .await
        .unwrap();
    assert_phase3_401(response).await;
}

#[tokio::test]
async fn block_put_without_auth_returns_phase3_401() {
    let fixture = build_block_fixture(34).await;
    let body: Vec<u8> = vec![0u8; fixture.block_size_bytes as usize];
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/blocks/{BLOCK_ID}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap();
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    assert_phase3_401(response).await;
}

#[tokio::test]
async fn block_delete_without_auth_returns_phase3_401() {
    let fixture = build_block_fixture(34).await;
    let response = fixture
        .router
        .clone()
        .oneshot(unauthenticated_request(Method::DELETE, BLOCK_ID))
        .await
        .unwrap();
    assert_phase3_401(response).await;
}

#[tokio::test]
async fn block_get_with_garbage_authorization_returns_401() {
    let fixture = build_block_fixture(34).await;
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/blocks/{BLOCK_ID}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_static("DPoP not-a-real-jwt"),
        )
        .body(Body::empty())
        .unwrap();
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    assert_phase3_401(response).await;
}

#[tokio::test]
async fn block_get_with_authorization_but_no_dpop_returns_401() {
    let fixture = build_block_fixture(34).await;
    // Non-token garbage in the Authorization header + no DPoP header — vault
    // guard rejects. A token-shaped JWT placeholder is deliberately avoided
    // (would trip secret-scanners); this string is shaped to exercise the
    // same parser-rejects path without resembling a real credential.
    let garbage = "NOT-A-TOKEN-NOR-A-JWT-NOR-A-DPoP-VALUE";
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/blocks/{BLOCK_ID}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {garbage}")).unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    assert_phase3_401(response).await;
}

#[tokio::test]
async fn admin_subtree_does_not_expose_blocks() {
    // The block fixture mounts only the vault subtree; the admin subtree
    // is None. `/admin/blocks/{id}` therefore falls through to the
    // global 404 fallback — admin tokens (if presented at all) cannot
    // reach block routes by construction (FR-021).
    let fixture = build_block_fixture(34).await;
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/admin/blocks/{BLOCK_ID}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .body(Body::empty())
        .unwrap();
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    // Without admin context the route doesn't exist → 404 fallback.
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "FR-021: admin tree does NOT expose /admin/blocks/{{id}}"
    );
    assert!(
        response.headers().get(header::ALLOW).is_none(),
        "404 fallback must not leak Allow header"
    );
}

#[tokio::test]
async fn block_routes_not_at_root() {
    // Sanity: `/blocks/{id}` without `/api` prefix is not a real route.
    let fixture = build_block_fixture(34).await;
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/blocks/{BLOCK_ID}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .body(Body::empty())
        .unwrap();
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn block_get_method_through_fixture_request_helper_still_401_unauth() {
    // Belt-and-braces: ensure the shared request-builder helper doesn't
    // accidentally inject auth headers somewhere.
    let fixture = build_block_fixture(34).await;
    let resp = fixture
        .router
        .clone()
        .oneshot(block_fixture_request(
            Method::GET,
            BLOCK_ID,
            "DOES_NOT_MATTER_TOKEN",
            "DOES_NOT_MATTER_PROOF",
            Body::empty(),
        ))
        .await
        .unwrap();
    // The token/proof are garbage — vault guard rejects → 401.
    assert_phase3_401(resp).await;
}

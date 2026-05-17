//! T040-T043: SC-006, Clarify-Q1, FR-019..022 — the `/health` contract and
//! the 404 fallback semantics.

mod common;

use std::sync::Arc;

use apokryphos_server::routes::build_router;
use apokryphos_server::AppState;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

use crate::common::minimal_valid_config;

fn router() -> axum::Router {
    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    // Phase 3 T023: build_router gained optional vault context + replay store
    // parameters. Phase 2's liveness tests exercise /health (unauthenticated)
    // and the path-mismatch fallback only — neither needs the vault chain,
    // so pass None / None to skip vault-route mounting.
    build_router(state, None, None)
}

/// T040: `GET /health` returns 200 + exact 15-byte body.
#[tokio::test]
async fn get_health_returns_200_and_constant_body() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let res = router().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("content-type").map(|v| v.to_str().unwrap()),
        Some("application/json")
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], br#"{"alive":true}"#);
    // Plan docs say "15 bytes" but the literal is 14 chars; this is a
    // documentation off-by-one. Body bytes are constant either way.
    assert_eq!(body.len(), 14);
}

/// T041: SC-006 part 2 — body contains none of the configured strings.
#[tokio::test]
async fn body_contains_no_configured_values() {
    // `minimal_valid_config` uses recognizable values; assert none appear.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let res = router().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();

    for needle in [
        "test-issuer",
        "vault-7a4f",
        "admin-c8d2",
        "apokryphos-test",
        "127.0.0.1",
    ] {
        assert!(
            !text.contains(needle),
            "configured value {needle:?} leaked into /health body: {text:?}"
        );
    }
}

/// T042: Clarify-Q1 — non-GET on /health is 404, NOT 405. No `Allow` header.
#[tokio::test]
async fn non_get_health_returns_404_not_405_no_allow_header() {
    for method in [Method::POST, Method::HEAD, Method::OPTIONS, Method::DELETE, Method::PUT] {
        let req = Request::builder()
            .method(method.clone())
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let res = router().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "{method} /health should be 404"
        );
        assert!(
            res.headers().get("allow").is_none(),
            "{method} /health must not emit Allow header (Clarify-Q1)"
        );
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty(), "{method} /health body must be empty");
    }
}

/// T043: Clarify-Q1 — unknown path and method-mismatch return byte-identical 404s.
#[tokio::test]
async fn unknown_path_and_method_mismatch_are_indistinguishable() {
    let post_health = Request::builder()
        .method(Method::POST)
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let get_xyzzy = Request::builder()
        .method(Method::GET)
        .uri("/xyzzy")
        .body(Body::empty())
        .unwrap();

    let res_a = router().oneshot(post_health).await.unwrap();
    let res_b = router().oneshot(get_xyzzy).await.unwrap();

    assert_eq!(res_a.status(), res_b.status());
    // Compare header-set equality (ignoring transient values like `date`).
    let names_a: Vec<_> = res_a.headers().keys().collect();
    let names_b: Vec<_> = res_b.headers().keys().collect();
    assert_eq!(names_a, names_b, "404 header sets must match");

    let body_a = axum::body::to_bytes(res_a.into_body(), usize::MAX).await.unwrap();
    let body_b = axum::body::to_bytes(res_b.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body_a, body_b, "404 bodies must be byte-identical");
}

/// SC-006 + fingerprinting defense: 404 has no Server / X-* identification.
#[tokio::test]
async fn no_diagnostic_headers_in_404() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/anywhere")
        .body(Body::empty())
        .unwrap();
    let res = router().oneshot(req).await.unwrap();
    for header in ["server", "x-version", "x-powered-by", "x-build", "x-request-id"] {
        assert!(
            res.headers().get(header).is_none(),
            "diagnostic header {header} should not be present"
        );
    }
}

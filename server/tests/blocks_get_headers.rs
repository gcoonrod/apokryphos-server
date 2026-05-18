//! T031 — GET response header discipline (Clarify-Q5 / spec FR-016a / SC-013).
//!
//! A successful `GET /api/blocks/{id}` (200 OK) response MUST emit
//! exactly: `Content-Type: application/octet-stream`, `Content-Length`,
//! `Cache-Control: no-store`, `Date`. It MUST NOT emit `ETag`,
//! `Last-Modified`, `Age`, `Vary`, `Expires`, or any other freshness /
//! caching metadata.

mod common;

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use tower::ServiceExt;

use crate::common::{
    block_fixture_mint_proof, block_fixture_mint_token, block_fixture_request, build_block_fixture,
};

const BLOCK_ID: &str = "GetHeadersTestBlockId00000000000000000000-_";

#[tokio::test]
async fn get_200_response_emits_only_minimal_headers() {
    let fixture = build_block_fixture(31).await;
    assert_eq!(BLOCK_ID.len(), 43);

    let token = block_fixture_mint_token(&fixture, "headers-test-user");
    let size = fixture.block_size_bytes as usize;
    let payload: Vec<u8> = vec![0xA5; size];
    let htu = format!("http://127.0.0.1/api/blocks/{BLOCK_ID}");

    // Seed: PUT the block.
    let proof = block_fixture_mint_proof(&fixture, &token, "PUT", &htu, "jti-headers-put");
    let resp = fixture
        .router
        .clone()
        .oneshot(block_fixture_request(
            Method::PUT,
            BLOCK_ID,
            &token,
            &proof,
            Body::from(payload.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET and inspect headers.
    let proof = block_fixture_mint_proof(&fixture, &token, "GET", &htu, "jti-headers-get");
    let resp = fixture
        .router
        .clone()
        .oneshot(block_fixture_request(
            Method::GET,
            BLOCK_ID,
            &token,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let headers = resp.headers();
    // Required-present.
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap()),
        Some("application/octet-stream"),
        "FR-016a: Content-Type must be application/octet-stream"
    );
    assert_eq!(
        headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok()),
        Some(fixture.block_size_bytes),
        "Content-Length must equal block_size_bytes"
    );
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap()),
        Some("no-store"),
        "FR-016a: Cache-Control must be no-store"
    );

    // Required-absent: every freshness/caching metadata header forbidden by Clarify-Q5.
    for forbidden in [
        header::ETAG,
        header::LAST_MODIFIED,
        header::AGE,
        header::VARY,
        header::EXPIRES,
    ] {
        assert!(
            headers.get(&forbidden).is_none(),
            "FR-016a: {forbidden:?} MUST NOT be present"
        );
    }
}

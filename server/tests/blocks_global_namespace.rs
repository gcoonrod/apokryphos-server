//! T029 — global namespace test (Clarify-Q2 / spec FR-030).
//!
//! Two distinct vault subjects PUT the same block ID with different
//! payloads. Assertions:
//!   - both PUTs return 204
//!   - subject A's subsequent GET returns subject B's payload (the later
//!     writer wins; last-write-wins per Clarify-Q1)
//!   - subject B's GET also returns its own payload (single global key)
//!
//! Verifies the storage layer keys by `(block_id)` alone, without a
//! per-subject column or per-subject directory.

mod common;

use axum::body::{Body, to_bytes};
use axum::http::{Method, StatusCode};
use tower::ServiceExt;

use crate::common::{
    block_fixture_mint_proof, block_fixture_mint_token, block_fixture_request, build_block_fixture,
};

const SHARED_BLOCK_ID: &str = "GlobalNamespaceSharedBlockId00000000000000A";

#[tokio::test]
async fn cross_subject_writes_share_one_global_key() {
    let fixture = build_block_fixture(29).await;
    assert_eq!(SHARED_BLOCK_ID.len(), 43);

    let token_a = block_fixture_mint_token(&fixture, "subject-alpha");
    let token_b = block_fixture_mint_token(&fixture, "subject-beta");

    let size = fixture.block_size_bytes as usize;
    let payload_a: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
    let payload_b: Vec<u8> = (0..size).map(|i| ((i * 13) & 0xff) as u8).collect();
    let htu = format!("http://127.0.0.1/api/blocks/{SHARED_BLOCK_ID}");

    // Subject A: PUT payload_a.
    let proof = block_fixture_mint_proof(&fixture, &token_a, "PUT", &htu, "jti-gn-a-put");
    let resp = fixture
        .router
        .clone()
        .oneshot(block_fixture_request(
            Method::PUT,
            SHARED_BLOCK_ID,
            &token_a,
            &proof,
            Body::from(payload_a.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Subject B: PUT payload_b under the SAME id — overwrites A.
    let proof = block_fixture_mint_proof(&fixture, &token_b, "PUT", &htu, "jti-gn-b-put");
    let resp = fixture
        .router
        .clone()
        .oneshot(block_fixture_request(
            Method::PUT,
            SHARED_BLOCK_ID,
            &token_b,
            &proof,
            Body::from(payload_b.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Subject A's GET sees subject B's payload (global namespace).
    let proof = block_fixture_mint_proof(&fixture, &token_a, "GET", &htu, "jti-gn-a-get");
    let resp = fixture
        .router
        .clone()
        .oneshot(block_fixture_request(
            Method::GET,
            SHARED_BLOCK_ID,
            &token_a,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), size * 2).await.unwrap();
    assert_eq!(
        body.as_ref(),
        payload_b.as_slice(),
        "FR-030: subject A sees the later writer's payload — no per-subject namespace"
    );

    // Subject B's GET also sees its own payload.
    let proof = block_fixture_mint_proof(&fixture, &token_b, "GET", &htu, "jti-gn-b-get");
    let resp = fixture
        .router
        .clone()
        .oneshot(block_fixture_request(
            Method::GET,
            SHARED_BLOCK_ID,
            &token_b,
            &proof,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), size * 2).await.unwrap();
    assert_eq!(body.as_ref(), payload_b.as_slice());
}

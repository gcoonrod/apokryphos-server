//! T027 — US3 uniform 404 byte-identity test
//! (spec FR-019 / FR-022 / SC-003).
//!
//! Captures the `WireImage` of every 404-producing request and asserts
//! all hashes are equal. Five causes covered:
//!   1. canonical but absent ID
//!   2. wrong-length ID
//!   3. wrong-alphabet ID
//!   4. path-traversal-character ID
//!   5. unsupported HTTP method on a valid path

mod common;

use std::collections::BTreeMap;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Response, StatusCode, header};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::common::{
    BlockTestFixture, block_fixture_mint_proof, block_fixture_mint_token, block_fixture_request,
    build_block_fixture,
};

/// Wire-image hash of (status, sorted headers excluding Date, body).
/// Used to assert byte-identical 404 across causes per contracts/http.md
/// §"Wire-image hashing".
async fn wire_image(response: Response<Body>) -> [u8; 32] {
    let status = response.status();
    let mut headers: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, value) in response.headers() {
        if name == header::DATE {
            continue;
        }
        headers
            .entry(name.as_str().to_ascii_lowercase())
            .or_default()
            .extend_from_slice(value.as_bytes());
    }
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    let mut h = Sha256::new();
    h.update(status.as_u16().to_be_bytes());
    for (name, value) in &headers {
        h.update(name.as_bytes());
        h.update(b":");
        h.update(value);
        h.update(b"\n");
    }
    h.update(&body);
    h.finalize().into()
}

async fn drive_get_404(fixture: &BlockTestFixture, block_id: &str, jti: &str) -> [u8; 32] {
    let token = block_fixture_mint_token(fixture, "uniform-404-user");
    let htu = format!("http://127.0.0.1/api/blocks/{block_id}");
    let proof = block_fixture_mint_proof(fixture, &token, "GET", &htu, jti);
    let req = block_fixture_request(Method::GET, block_id, &token, &proof, Body::empty());
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    wire_image(response).await
}

async fn drive_method_404(fixture: &BlockTestFixture, method: Method, jti: &str) -> [u8; 32] {
    let token = block_fixture_mint_token(fixture, "uniform-404-user");
    let block_id = "AbsentButCanonicalIdForMethodMismatchTestB1";
    assert_eq!(block_id.len(), 43);
    let htu = format!("http://127.0.0.1/api/blocks/{block_id}");
    let proof = block_fixture_mint_proof(fixture, &token, method.as_str(), &htu, jti);
    let req = block_fixture_request(method, block_id, &token, &proof, Body::empty());
    let response = fixture.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "method-mismatch must return 404, not 405"
    );
    wire_image(response).await
}

#[tokio::test]
async fn uniform_404_across_absent_malformed_and_method_mismatch() {
    let fixture = build_block_fixture(27).await;

    // 1. Canonical but absent (43 chars exactly).
    let absent_id = "CanonicalButAbsentBlock0000000000000000000A";
    assert_eq!(absent_id.len(), 43);
    let h_absent = drive_get_404(&fixture, absent_id, "jti-u404-1").await;

    // 2. Wrong-length IDs.
    let h_short = drive_get_404(&fixture, "tooshort", "jti-u404-2").await;
    let h_long = drive_get_404(
        &fixture,
        "ThisIdIsWayTooLongAndDefinitelyNotFortyThreeCharactersLong",
        "jti-u404-3",
    )
    .await;

    // 3. Wrong-alphabet ID (43 chars, contains forbidden `+`).
    let bad_plus = "AAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(bad_plus.len(), 43);
    let h_alphabet = drive_get_404(&fixture, bad_plus, "jti-u404-4").await;

    // 4. Path-traversal character (contains `.`).
    let bad_dot = "AAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(bad_dot.len(), 43);
    let h_dot = drive_get_404(&fixture, bad_dot, "jti-u404-5").await;

    // 5. Method mismatch on valid path.
    let h_post = drive_method_404(&fixture, Method::POST, "jti-u404-6").await;
    let h_patch = drive_method_404(&fixture, Method::PATCH, "jti-u404-7").await;

    let all = [
        h_absent, h_short, h_long, h_alphabet, h_dot, h_post, h_patch,
    ];
    let first = all[0];
    for (i, hash) in all.iter().enumerate() {
        assert_eq!(
            *hash, first,
            "wire-image #{i} differs from baseline — FR-022 byte-identity violated"
        );
    }
}

//! T030 — byte-identical 503 across backend failures (spec FR-031 / SC-012).
//!
//! Injects a `FailingProvider` mock that returns
//! `StorageError::Backend { cause, source }` for every method call,
//! cycling through `DiskFull` / `PermissionDenied` / `IoError`. Captures
//! the `WireImage` of each PUT response and asserts all three hashes are
//! equal (byte-identical 503 contract). Assertion details:
//!   - status `503 Service Unavailable`
//!   - body empty (`Content-Length: 0`)
//!   - `Retry-After: 5` (planning-time constant from research.md R3)
//!   - no headers vary between causes

mod common;

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use apokryphos_server::AppState;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::auth::{AudienceTag, JtiReplayStore, init_single_context};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig, StorageBackend};
use apokryphos_server::routes::build_router;
use apokryphos_server::storage::{BackendFailureCause, BlockId, StorageError, StorageProvider};
use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, Response, StatusCode, header};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::common::minimal_valid_config;

/// Always-failing storage provider, configurable cause per instance.
#[derive(Debug)]
struct FailingProvider {
    cause: BackendFailureCause,
}

#[async_trait]
impl StorageProvider for FailingProvider {
    async fn put(&self, _id: &BlockId, _payload: Bytes) -> Result<(), StorageError> {
        Err(self.make_error())
    }
    async fn get(&self, _id: &BlockId) -> Result<Bytes, StorageError> {
        Err(self.make_error())
    }
    async fn delete(&self, _id: &BlockId) -> Result<(), StorageError> {
        Err(self.make_error())
    }
    async fn exists(&self, _id: &BlockId) -> Result<bool, StorageError> {
        Err(self.make_error())
    }
}

impl FailingProvider {
    fn make_error(&self) -> StorageError {
        let source = match self.cause {
            BackendFailureCause::DiskFull => {
                io::Error::new(io::ErrorKind::StorageFull, "simulated disk full")
            }
            BackendFailureCause::PermissionDenied => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "simulated permission denied",
            ),
            BackendFailureCause::IoError => io::Error::other("simulated I/O error"),
        };
        StorageError::Backend {
            cause: self.cause,
            source,
        }
    }
}

const TEST_KID: &str = "vault-key-1";
const VAULT_AUD: &str = "apokryphos-test-vault";
const TEST_BLOCK_SIZE: u64 = 256;

async fn build_router_with(
    provider: Arc<dyn StorageProvider>,
) -> (axum::Router, p256::ecdsa::SigningKey, MockOidcProvider) {
    let mut rng = deterministic_rng(30);
    let signing_key = generate_es256_keypair(&mut rng);
    let verifying = signing_key.verifying_key();
    let jwks_doc = serde_json::json!({"keys": [es256_public_jwk(verifying, Some(TEST_KID))]});
    let mock = MockOidcProvider::start(jwks_doc).await;
    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: VAULT_AUD.to_string(),
    };
    let auth_cfg = Arc::new(AuthConfig::default());
    let http_client = openidconnect::reqwest::Client::new();
    let vault_ctx = init_single_context(
        AudienceTag::Vault,
        &oidc_cfg,
        Arc::clone(&auth_cfg),
        &http_client,
    )
    .await
    .unwrap();
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));
    let mut cfg = minimal_valid_config();
    cfg.block_size_bytes = TEST_BLOCK_SIZE;
    cfg.storage_backend = StorageBackend::LocalFs {
        root: std::path::PathBuf::from("/unused-but-must-be-absolute"),
    };
    let router = build_router(
        AppState {
            config: Arc::new(cfg),
        },
        Some(vault_ctx),
        None,
        Some(replay_store),
        Some(provider),
    );
    (router, signing_key, mock)
}

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

async fn put_against_provider(cause: BackendFailureCause, jti: &str) -> Response<Body> {
    let provider: Arc<dyn StorageProvider> = Arc::new(FailingProvider { cause });
    let (router, signing_key, mock) = build_router_with(provider).await;

    let cnf_jkt = es256_thumbprint_b64url(signing_key.verifying_key());
    let iss = mock.issuer_url().as_str().trim_end_matches('/').to_string();
    let now = now_unix_secs();
    let token = mint_es256_token(
        &MintTokenClaims {
            sub: "503-test-user".to_string(),
            aud: VAULT_AUD.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &signing_key,
        Some(TEST_KID),
        false,
    );
    let block_id = "FailingProviderBlockId00000000000000000000A";
    assert_eq!(block_id.len(), 43);
    let htu = format!("http://127.0.0.1/api/blocks/{block_id}");
    let proof = mint_es256_dpop_proof(
        &signing_key,
        "PUT",
        &htu,
        now_unix_secs(),
        jti,
        Some(&token),
    );
    let body: Vec<u8> = vec![0u8; TEST_BLOCK_SIZE as usize];
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/blocks/{block_id}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(&proof).unwrap())
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap();
    router.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn byte_identical_503_across_backend_failure_causes() {
    let r_disk = put_against_provider(BackendFailureCause::DiskFull, "jti-503-disk").await;
    assert_eq!(r_disk.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        r_disk.headers().get(header::RETRY_AFTER).unwrap(),
        "5",
        "FR-031: Retry-After must be the planning-time constant"
    );
    let h_disk = wire_image(r_disk).await;

    let r_perm = put_against_provider(BackendFailureCause::PermissionDenied, "jti-503-perm").await;
    assert_eq!(r_perm.status(), StatusCode::SERVICE_UNAVAILABLE);
    let h_perm = wire_image(r_perm).await;

    let r_io = put_against_provider(BackendFailureCause::IoError, "jti-503-io").await;
    assert_eq!(r_io.status(), StatusCode::SERVICE_UNAVAILABLE);
    let h_io = wire_image(r_io).await;

    assert_eq!(
        h_disk, h_perm,
        "SC-012: disk-full and permission-denied 503 responses must be byte-identical"
    );
    assert_eq!(
        h_disk, h_io,
        "SC-012: disk-full and generic-io 503 responses must be byte-identical"
    );
}

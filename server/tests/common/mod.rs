//! Shared test helpers (R5, R6).
//!
//! `CapturingBuffer` lets tests capture `tracing` output into an in-memory
//! buffer without disturbing the global subscriber. `with_captured_logs`
//! installs a scoped subscriber for the closure's lifetime.
//!
//! `minimal_valid_config` returns a `ServerConfig` with known-distinct
//! audiences and an empty trusted_proxies list, suitable for any test that
//! needs to build a router or driver run() without re-deriving validation
//! rules in every test.

#![allow(dead_code)] // not every test file uses every helper

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apokryphos_server::config::{OidcAudienceConfig, ServerConfig, StorageBackend};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
pub struct CapturingBuffer(pub Arc<Mutex<Vec<u8>>>);

impl CapturingBuffer {
    pub fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

pub struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturingBuffer {
    type Writer = CapturingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CapturingWriter(self.0.clone())
    }
}

/// Run `f` with a scoped subscriber that captures every record into a buffer.
/// Returns `(captured_text, f's_return)`. The global subscriber is untouched.
pub fn with_captured_logs<F, R>(f: F) -> (String, R)
where
    F: FnOnce() -> R,
{
    let buffer = CapturingBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    (buffer.contents(), result)
}

/// Minimal known-valid `ServerConfig` for tests that don't care about specific
/// field values. Uses recognizable issuer URLs and audiences so SC-006-style
/// tests can assert these strings are absent from `/health` responses.
pub fn minimal_valid_config() -> ServerConfig {
    ServerConfig {
        bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        block_size_bytes: 1024 * 1024,
        storage_backend: StorageBackend::None,
        trusted_proxies: Vec::new(),
        vault_oidc: OidcAudienceConfig::new(
            "vault",
            "https://test-issuer.invalid/vault-7a4f".to_string(),
            "apokryphos-test-vault-7a4f".to_string(),
        )
        .expect("test fixture: vault OIDC config"),
        admin_oidc: OidcAudienceConfig::new(
            "admin",
            "https://test-issuer.invalid/admin-c8d2".to_string(),
            "apokryphos-test-admin-c8d2".to_string(),
        )
        .expect("test fixture: admin OIDC config"),
        drain_timeout: Duration::from_secs(30),
        // Phase 3 (T008): AuthConfig defaults — every Phase 2 fixture
        // uses production-correct defaults, so callers that don't care
        // about auth tuning inherit them transparently. Tests that need
        // shorter values (e.g. `auth_jwks_refresh_*`) override via the
        // builder pattern.
        auth: apokryphos_server::config::AuthConfig::default(),
    }
}

/// Trait-like builder extension for short drain timeouts in shutdown tests.
pub trait ConfigBuilderExt {
    fn with_drain_timeout(self, timeout: Duration) -> Self;
}

impl ConfigBuilderExt for ServerConfig {
    fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }
}

// ──────────────────── Phase 4 block-storage test fixture ────────────────────

/// Shared block-test fixture: vault context against a `MockOidcProvider`,
/// `LocalFsProvider` over a `TempDir`, assembled `axum::Router`, and the
/// ES256 signing key for minting tokens + DPoP proofs.
///
/// Used by Phase 4 integration tests (`blocks_*`, `no_direct_fs`, etc.) so
/// each test file declares only its own scenarios, not the auth wiring.
pub struct BlockTestFixture {
    pub mock: apokryphos_server::auth::testing::MockOidcProvider,
    pub block_root: tempfile::TempDir,
    pub router: axum::Router,
    pub signing_key: p256::ecdsa::SigningKey,
    pub vault_aud: &'static str,
    pub kid: &'static str,
    pub block_size_bytes: u64,
}

pub const BLOCK_FIXTURE_KID: &str = "vault-key-1";
pub const BLOCK_FIXTURE_AUD: &str = "apokryphos-test-vault";
pub const BLOCK_FIXTURE_SIZE: u64 = 256;

/// Build a `BlockTestFixture` with a fresh tempdir-backed `LocalFsProvider`.
/// The block routes are mounted (vault subtree) but the admin subtree is
/// absent — block tests that need admin-token coverage build their own
/// admin context inline.
pub async fn build_block_fixture(seed: u64) -> BlockTestFixture {
    use std::sync::Arc;

    use apokryphos_server::AppState;
    use apokryphos_server::auth::testing::{
        MockOidcProvider, deterministic_rng, es256_public_jwk, generate_es256_keypair,
    };
    use apokryphos_server::auth::{AudienceTag, JtiReplayStore, init_single_context};
    use apokryphos_server::config::{AuthConfig, OidcAudienceConfig, StorageBackend};
    use apokryphos_server::routes::build_router;
    use apokryphos_server::storage::{LocalFsProvider, StorageProvider};

    let mut rng = deterministic_rng(seed);
    let signing_key = generate_es256_keypair(&mut rng);
    let verifying = signing_key.verifying_key();
    let jwks_doc = serde_json::json!({
        "keys": [es256_public_jwk(verifying, Some(BLOCK_FIXTURE_KID))]
    });
    let mock = MockOidcProvider::start(jwks_doc).await;

    let oidc_cfg = OidcAudienceConfig {
        issuer_url: mock.issuer_url(),
        audience: BLOCK_FIXTURE_AUD.to_string(),
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
    .expect("init_single_context");
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let block_root = tempfile::tempdir().expect("tempdir");
    let storage: Arc<dyn StorageProvider> = Arc::new(LocalFsProvider::new_unchecked(
        block_root.path().to_path_buf(),
    ));

    let mut cfg = minimal_valid_config();
    cfg.block_size_bytes = BLOCK_FIXTURE_SIZE;
    cfg.storage_backend = StorageBackend::LocalFs {
        root: block_root.path().to_path_buf(),
    };

    let router = build_router(
        AppState {
            config: Arc::new(cfg),
        },
        Some(vault_ctx),
        None,
        Some(replay_store),
        Some(storage),
    );

    BlockTestFixture {
        mock,
        block_root,
        router,
        signing_key,
        vault_aud: BLOCK_FIXTURE_AUD,
        kid: BLOCK_FIXTURE_KID,
        block_size_bytes: BLOCK_FIXTURE_SIZE,
    }
}

/// Mint a vault access token bound to the fixture's `signing_key`.
pub fn block_fixture_mint_token(f: &BlockTestFixture, sub: &str) -> String {
    use apokryphos_server::auth::testing::{
        MintTokenClaims, es256_thumbprint_b64url, mint_es256_token, now_unix_secs,
    };
    let cnf_jkt = es256_thumbprint_b64url(f.signing_key.verifying_key());
    let iss = f
        .mock
        .issuer_url()
        .as_str()
        .trim_end_matches('/')
        .to_string();
    let now = now_unix_secs();
    mint_es256_token(
        &MintTokenClaims {
            sub: sub.to_string(),
            aud: f.vault_aud.to_string(),
            iss,
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt,
        },
        &f.signing_key,
        Some(f.kid),
        false,
    )
}

/// Mint a fresh DPoP proof (`jti` should be unique per request — the
/// Phase 3 replay store rejects duplicates).
pub fn block_fixture_mint_proof(
    f: &BlockTestFixture,
    token: &str,
    htm: &str,
    htu: &str,
    jti: &str,
) -> String {
    use apokryphos_server::auth::testing::{mint_es256_dpop_proof, now_unix_secs};
    mint_es256_dpop_proof(&f.signing_key, htm, htu, now_unix_secs(), jti, Some(token))
}

/// Construct an authenticated block-route request (any method).
/// `body` may be empty for GET/DELETE.
pub fn block_fixture_request(
    method: axum::http::Method,
    block_id: &str,
    token: &str,
    proof: &str,
    body: axum::body::Body,
) -> axum::http::Request<axum::body::Body> {
    use axum::body::HttpBody;
    use axum::http::{HeaderValue, Request, header};

    let cl = body.size_hint().exact();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("/api/blocks/{block_id}"))
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"))
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
        )
        .header("dpop", HeaderValue::from_str(proof).unwrap());
    if let Some(cl) = cl {
        req = req.header(header::CONTENT_LENGTH, cl.to_string());
    }
    req.body(body).unwrap()
}

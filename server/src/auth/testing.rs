//! Test helpers for Phase 3: ephemeral keypair generation, token/proof
//! minting, and the in-process `MockOidcProvider`.
//!
//! This module is gated by `#[cfg(any(test, feature = "test-utils"))]` so
//! it does NOT compile into the release binary (R1, R15). Production never
//! generates cryptographic keys; only tests do.
//!
//! ## Current scope (Phase 2 foundational + Phase 3 US1 first step)
//!
//! - `deterministic_rng` — reproducible-seed `ChaCha8Rng` factory.
//! - `generate_ps256_keypair` — RSA-2048 private key for PS256.
//! - `generate_es256_keypair` — P-256 signing key for ES256.
//! - `MockOidcProvider` — in-process axum server bound to 127.0.0.1:0
//!   serving `/.well-known/openid-configuration` + `/jwks.json` with
//!   observable per-endpoint request counters. Used by `init_single_context`
//!   integration tests + the upcoming SC-007/008/009 tests.
//!
//! ## Phase 3 scope (TODO — lands in T019/T020/T025/T026)
//!
//! - `mint_vault_token(claims, key, alg) -> String` and
//!   `mint_admin_token(...)` helpers using `jsonwebtoken::encode`.
//! - `mint_dpop_proof(htm, htu, iat, jti, key, alg) -> String` helper.

use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

/// Deterministically-seeded RNG for reproducible test failures. Wraps
/// `ChaCha8Rng` which is `CryptoRng` (suitable for the `rsa` and `p256`
/// crates' `random` constructors).
pub fn deterministic_rng(seed: u64) -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(seed)
}

/// Generate an ephemeral PS256 (RSA-2048) private key for tests. Returns
/// the RSA private key; tests derive a public JWK from it as needed.
///
/// Note: RSA-2048 key generation is slow (~50–200 ms). Tests that need a
/// keypair should generate it once per fixture (lazy_static or `OnceLock`),
/// not per `#[test]` function.
pub fn generate_ps256_keypair(rng: &mut ChaCha8Rng) -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::new(rng, 2048).expect("test RSA key generation must succeed")
}

/// Generate an ephemeral ES256 (P-256) private signing key for tests. Much
/// faster than RSA generation (~µs).
pub fn generate_es256_keypair(rng: &mut ChaCha8Rng) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::random(rng)
}

// ─────────────────────── MockOidcProvider ────────────────────────────────

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
// `to_encoded_point` is reachable via `p256::ecdsa::VerifyingKey`'s inherent
// methods + trait re-exports; no explicit `use` needed.
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

/// Convert an ES256 verifying (public) key into the `jsonwebtoken::jwk::Jwk`
/// JSON shape the mock JWKS endpoint serves. Returns a `serde_json::Value`
/// for cheap composition into the JWKS response.
pub fn es256_public_jwk(
    verifying_key: &p256::ecdsa::VerifyingKey,
    kid: Option<&str>,
) -> Value {
    let point = verifying_key.to_encoded_point(false);
    let x = point.x().expect("p256 uncompressed encoding has x");
    let y = point.y().expect("p256 uncompressed encoding has y");
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "x": engine.encode(x),
        "y": engine.encode(y),
    });
    if let Some(k) = kid {
        jwk.as_object_mut().unwrap().insert("kid".into(), json!(k));
    }
    jwk
}

/// Per-mock state — the JWKS the provider serves plus per-endpoint
/// request counters that tests assert on.
#[derive(Clone)]
struct MockState {
    jwks: Arc<Value>,
    discovery_fetches: Arc<AtomicU64>,
    jwks_fetches: Arc<AtomicU64>,
    base_url: Arc<Url>,
}

/// In-process OIDC fixture: a tiny `axum::Router` bound to 127.0.0.1:0 that
/// serves `/.well-known/openid-configuration` and `/jwks.json` with the
/// caller-supplied key material. Per-endpoint counters let tests assert
/// on fetch frequency (SC-008, SC-009 in later phases).
///
/// Drop the handle (or call `shutdown()`) to terminate the background task.
pub struct MockOidcProvider {
    state: MockState,
    task: JoinHandle<()>,
    addr: SocketAddr,
}

impl MockOidcProvider {
    /// Start the mock. `jwks` is a `serde_json::Value` representing the
    /// `{"keys":[...]}` document; use `es256_public_jwk` (or the future
    /// `ps256_public_jwk`) helpers to compose it.
    ///
    /// Returns the running mock. The bound base URL is `http://127.0.0.1:<port>`
    /// (HTTP, not HTTPS — sufficient because `auth::discovery::fetch_discovery`
    /// relaxes the HTTPS check under `cfg(any(test, feature = "test-utils"))`).
    pub async fn start(jwks: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("MockOidcProvider must bind a port");
        let addr = listener.local_addr().expect("local_addr after bind");
        let base_url = Url::parse(&format!("http://{}", addr)).expect("valid base URL");

        let state = MockState {
            jwks: Arc::new(jwks),
            discovery_fetches: Arc::new(AtomicU64::new(0)),
            jwks_fetches: Arc::new(AtomicU64::new(0)),
            base_url: Arc::new(base_url),
        };

        let router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(serve_discovery),
            )
            .route("/jwks.json", get(serve_jwks))
            .with_state(state.clone());

        let server = axum::serve(listener, router.into_make_service());
        let task = tokio::spawn(async move {
            // Errors here are ignored — the fixture lives only for the test's
            // lifetime, and the test asserts on observable HTTP responses.
            let _ = server.await;
        });

        MockOidcProvider { state, task, addr }
    }

    /// The mock's bound URL — `http://127.0.0.1:<port>`. Use as the
    /// `issuer_url` when constructing an `OidcAudienceConfig` for tests.
    pub fn issuer_url(&self) -> Url {
        (*self.state.base_url).clone()
    }

    /// Number of `/.well-known/openid-configuration` requests served.
    pub fn discovery_fetch_count(&self) -> u64 {
        self.state.discovery_fetches.load(Ordering::SeqCst)
    }

    /// Number of `/jwks.json` requests served.
    pub fn jwks_fetch_count(&self) -> u64 {
        self.state.jwks_fetches.load(Ordering::SeqCst)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Abort the background server task. Idempotent.
    pub fn shutdown(&self) {
        self.task.abort();
    }
}

impl Drop for MockOidcProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_discovery(State(state): State<MockState>) -> Json<Value> {
    state.discovery_fetches.fetch_add(1, Ordering::SeqCst);
    let jwks_uri = state
        .base_url
        .join("/jwks.json")
        .expect("static path joins cleanly");
    Json(json!({
        "issuer": state.base_url.to_string(),
        "jwks_uri": jwks_uri.to_string(),
        // Other discovery fields the spec wants but we don't consume:
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256", "PS256"],
    }))
}

async fn serve_jwks(State(state): State<MockState>) -> Json<Value> {
    state.jwks_fetches.fetch_add(1, Ordering::SeqCst);
    Json((*state.jwks).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_rng_is_reproducible() {
        use rand_chacha::rand_core::RngCore;
        let mut rng_a = deterministic_rng(42);
        let mut rng_b = deterministic_rng(42);
        for _ in 0..16 {
            assert_eq!(rng_a.next_u64(), rng_b.next_u64());
        }
    }

    #[test]
    fn es256_keypair_generates_distinct_keys_with_distinct_seeds() {
        let mut rng_a = deterministic_rng(1);
        let mut rng_b = deterministic_rng(2);
        let k_a = generate_es256_keypair(&mut rng_a);
        let k_b = generate_es256_keypair(&mut rng_b);
        // Compare by verifying-key bytes — the SigningKey type is opaque.
        let vk_a = k_a.verifying_key().to_encoded_point(false);
        let vk_b = k_b.verifying_key().to_encoded_point(false);
        assert_ne!(vk_a.as_bytes(), vk_b.as_bytes());
    }

    // PS256 keypair generation test is deliberately omitted from the
    // default suite (RSA-2048 generation is slow). The conformance harness
    // (T056) and the per-test fixtures will exercise it lazily.
}

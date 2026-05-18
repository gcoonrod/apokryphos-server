//! Test helpers for Phase 3: ephemeral keypair generation, token/proof
//! minting, and the in-process `MockOidcProvider`.
//!
//! This module is gated by `#[cfg(feature = "test-utils")]` (feature only
//! — NOT `cfg(test)`) so it does NOT compile into the release binary and
//! does NOT compile into the lib under plain `cargo test`. The optional
//! crypto dependencies (rsa, p256, rand, rand_chacha) are activated only
//! when the feature is on, and the gate matches that activation. See the
//! `[features]` block in `Cargo.toml`.
//!
//! ## Current scope (Phase 3 US1 + post-PR-review enforcement)
//!
//! - `deterministic_rng` — reproducible-seed `ChaCha8Rng` factory.
//! - `generate_ps256_keypair` — RSA-2048 private key for PS256.
//! - `generate_es256_keypair` — P-256 signing key for ES256.
//! - `MockOidcProvider` — in-process axum server bound to 127.0.0.1:0
//!   serving `/.well-known/openid-configuration` + `/jwks.json` with
//!   observable per-endpoint request counters. Used by `init_single_context`
//!   integration tests + the upcoming SC-007/008/009 tests.
//! - `mint_es256_token(claims, key, kid, omit_cnf_jkt) -> String` and
//!   `mint_es256_dpop_proof(key, htm, htu, iat, jti, ath_for) -> String`
//!   — JWS minters used by all Phase 3 negative/positive matrix tests.
//!   The `ath_for: Option<&str>` parameter supports both the FR-022a
//!   positive control (Some) and the missing-`ath` negative test (None).
//! - `compute_ath_for_test(raw_token) -> String` — RFC 9449 §4.2 helper
//!   for tests that need to construct an `ath`-mismatch fixture.
//!
//! Phase 3 US2 will add `mint_admin_token` + PS256-signed mint paths
//! alongside the dual-context tests (T028+).

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
pub fn es256_public_jwk(verifying_key: &p256::ecdsa::VerifyingKey, kid: Option<&str>) -> Value {
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
/// request counters that tests assert on. `jwks` is held inside an
/// `ArcSwap` so a test can swap it mid-run (T042's FR-007 runtime
/// overlap fixture relies on this). Reads stay lock-free; writers
/// observe the swap atomically on the next request.
#[derive(Clone)]
struct MockState {
    jwks: Arc<arc_swap::ArcSwap<Value>>,
    discovery_fetches: Arc<AtomicU64>,
    jwks_fetches: Arc<AtomicU64>,
    /// Counter for the alternate `/jwks-v2.json` endpoint. T052
    /// sub-case (j) (jwks_uri-change propagation) reconfigures
    /// discovery to advertise this path and asserts the counter
    /// advances on the next scheduled JWKS fetch.
    jwks_v2_fetches: Arc<std::sync::atomic::AtomicU64>,
    base_url: Arc<Url>,
    /// Discovery-doc `jwks_uri` override. Set via `set_discovery_jwks_uri`;
    /// initialised to the mock's own `/jwks.json` path. T052 sub-case (j)
    /// flips this to `/jwks-v2.json` to test propagation through
    /// `discovery::scheduled_refresh_task` → `jwks::scheduled_refresh_task`.
    discovery_jwks_uri: Arc<arc_swap::ArcSwap<String>>,
    /// HTTP status code to return on the next `/jwks.json` request.
    /// `0` means "no override, return 200 OK". Non-zero values serve
    /// that status code (with empty body, no JWKS doc). T052 uses this
    /// to simulate transient JWKS failures and assert that the cached
    /// JWKS is retained per FR-003a.
    jwks_status_override: Arc<std::sync::atomic::AtomicU16>,
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
            jwks: Arc::new(arc_swap::ArcSwap::from_pointee(jwks)),
            discovery_fetches: Arc::new(AtomicU64::new(0)),
            jwks_fetches: Arc::new(AtomicU64::new(0)),
            jwks_v2_fetches: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            base_url: Arc::new(base_url),
            discovery_jwks_uri: Arc::new(arc_swap::ArcSwap::from_pointee("/jwks.json".to_string())),
            jwks_status_override: Arc::new(std::sync::atomic::AtomicU16::new(0)),
        };

        let router = Router::new()
            .route("/.well-known/openid-configuration", get(serve_discovery))
            .route("/jwks.json", get(serve_jwks))
            .route("/jwks-v2.json", get(serve_jwks_v2))
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

    /// Swap the JWKS served at `/jwks.json` to a new document. Subsequent
    /// requests (including scheduled or on-demand JWKS refreshes from
    /// the system under test) observe the new value atomically. Used by
    /// T042 to simulate a runtime overlap: the vault provider's JWKS
    /// changes to include a key already in the admin context's JWKS,
    /// and the FR-007 contract is that `install_refreshed_jwks` refuses
    /// the new value rather than exiting the process.
    pub fn set_jwks(&self, new_jwks: Value) {
        self.state.jwks.store(Arc::new(new_jwks));
    }

    /// Set a *persistent* HTTP status override for `/jwks.json`. Once
    /// set, every subsequent `/jwks.json` request returns that status
    /// with no body until the caller resets it. Pass `0` to clear the
    /// override (restoring the default 200 + JWKS-body behaviour).
    /// Used by T052 to simulate transient provider failures and verify
    /// FR-003a (cached JWKS retained on refresh failure).
    pub fn set_jwks_status_override(&self, status: u16) {
        self.state
            .jwks_status_override
            .store(status, std::sync::atomic::Ordering::SeqCst);
    }

    /// Reconfigure the discovery doc's advertised `jwks_uri`. Subsequent
    /// `/.well-known/openid-configuration` fetches return a document
    /// pointing at this path (joined onto the mock's base URL).
    /// Default after `start` is `/jwks.json`. T052 sub-case (j) flips
    /// this to `/jwks-v2.json` to test propagation.
    pub fn set_discovery_jwks_uri(&self, path: &str) {
        self.state
            .discovery_jwks_uri
            .store(Arc::new(path.to_string()));
    }

    /// Number of `/jwks-v2.json` requests served. Initially 0; advances
    /// after the system under test fetches from the alternate path
    /// (typically after `set_discovery_jwks_uri("/jwks-v2.json")` +
    /// a discovery refresh + a JWKS refresh).
    pub fn jwks_v2_fetch_count(&self) -> u64 {
        self.state
            .jwks_v2_fetches
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for MockOidcProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_discovery(State(state): State<MockState>) -> Json<Value> {
    state.discovery_fetches.fetch_add(1, Ordering::SeqCst);
    let path = state.discovery_jwks_uri.load_full();
    let jwks_uri = state
        .base_url
        .join(path.as_str())
        .expect("discovery_jwks_uri must be a valid path");
    Json(json!({
        "issuer": state.base_url.to_string(),
        "jwks_uri": jwks_uri.to_string(),
        // Other discovery fields the spec wants but we don't consume:
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256", "PS256"],
    }))
}

async fn serve_jwks(
    State(state): State<MockState>,
) -> Result<Json<Value>, (axum::http::StatusCode, &'static str)> {
    state.jwks_fetches.fetch_add(1, Ordering::SeqCst);
    let override_status = state.jwks_status_override.load(Ordering::SeqCst);
    if override_status != 0 {
        // Caller asked for a non-200 response. Return the status with a
        // brief literal body so the client sees a definitive error.
        let code = axum::http::StatusCode::from_u16(override_status)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        return Err((code, "mock /jwks.json status override"));
    }
    Ok(Json((*state.jwks.load_full()).clone()))
}

/// Alternate JWKS endpoint at `/jwks-v2.json`. Used by T052 sub-case (j)
/// to verify that a `jwks_uri` change in the discovery doc is honored
/// by the next scheduled JWKS refresh. Serves the same `state.jwks`
/// payload — the *URL* is what's under test, not the body.
async fn serve_jwks_v2(State(state): State<MockState>) -> Json<Value> {
    state.jwks_v2_fetches.fetch_add(1, Ordering::SeqCst);
    Json((*state.jwks.load_full()).clone())
}

// ────────────────────── Token + DPoP mint helpers ────────────────────────

/// Strongly-typed claims accepted by `mint_es256_token`. All fields are
/// required by FR-015 (`sub`, `aud`, `iss`, `exp`, `iat`, `cnf.jkt`) except
/// `nbf` which is optional. Tests construct deliberately-malformed values
/// to exercise specific FR-011..FR-016 negative cases by overriding fields
/// individually.
#[derive(Debug, Clone)]
pub struct MintTokenClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub nbf: Option<u64>,
    /// Base64url-encoded SHA-256 JWK thumbprint of the DPoP proof key.
    /// Empty string allowed for the FR-015 "missing cnf.jkt" negative test.
    pub cnf_jkt: String,
}

/// Mint an ES256-signed JWT with the supplied claims. Used by token-
/// validation tests + the whoami happy-path test. `omit_cnf_jkt = true`
/// suppresses the `cnf.jkt` field entirely (for FR-015 negative tests);
/// otherwise the `cnf.jkt` field is included with the value from
/// `claims.cnf_jkt`.
pub fn mint_es256_token(
    claims: &MintTokenClaims,
    signing_key: &p256::ecdsa::SigningKey,
    kid: Option<&str>,
    omit_cnf_jkt: bool,
) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::pkcs8::EncodePrivateKey;

    let mut header = Header::new(Algorithm::ES256);
    if let Some(k) = kid {
        header.kid = Some(k.to_string());
    }

    let mut claims_json = serde_json::json!({
        "sub": claims.sub,
        "aud": claims.aud,
        "iss": claims.iss,
        "iat": claims.iat,
        "exp": claims.exp,
    });
    if let Some(nbf) = claims.nbf {
        claims_json
            .as_object_mut()
            .unwrap()
            .insert("nbf".into(), serde_json::json!(nbf));
    }
    if !omit_cnf_jkt {
        claims_json
            .as_object_mut()
            .unwrap()
            .insert("cnf".into(), serde_json::json!({ "jkt": claims.cnf_jkt }));
    }

    let pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("p256 to_pkcs8_pem must succeed for in-memory key");
    let key = EncodingKey::from_ec_pem(pem.as_bytes())
        .expect("jsonwebtoken from_ec_pem must accept p256 PKCS#8 PEM");
    encode(&header, &claims_json, &key).expect("test token mint must succeed")
}

/// Mint a DPoP proof JWS per RFC 9449. The JOSE header embeds the
/// signing key's *public* JWK via the `jwk` parameter; the payload
/// carries `htm` / `htu` / `iat` / `jti` and (per FR-022a) the `ath`
/// claim binding the proof to a specific access token.
///
/// Arguments:
///   - `ath_for`: `Some(raw_token)` includes `ath = base64url(SHA-256(raw_token))`
///     in the claims (the normal case for protected-resource use, RFC
///     9449 §4.2). `None` omits the `ath` field entirely — used by the
///     FR-022a "missing ath" negative test to verify the validator
///     rejects bearer-token-style proofs.
///
/// Test code injects deliberately-malformed values (wrong `htm`, stale
/// `iat`, mismatched `ath`, etc.) by overriding the inputs.
pub fn mint_es256_dpop_proof(
    signing_key: &p256::ecdsa::SigningKey,
    htm: &str,
    htu: &str,
    iat: u64,
    jti: &str,
    ath_for: Option<&str>,
) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::pkcs8::EncodePrivateKey;

    // RFC 9449 §4.1: typ MUST be "dpop+jwt"; alg is the JWS signing
    // algorithm; jwk carries the public key.
    let public_jwk_value = es256_public_jwk(signing_key.verifying_key(), None);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    // The `jwk` field on jsonwebtoken::Header is `Option<jwk::Jwk>`. We
    // deserialize our `Value` representation back into the typed form so
    // jsonwebtoken's serialization emits a well-formed JOSE header.
    header.jwk = Some(
        serde_json::from_value(public_jwk_value)
            .expect("es256_public_jwk produces a valid Jwk shape"),
    );

    let mut claims = serde_json::json!({
        "htm": htm,
        "htu": htu,
        "iat": iat,
        "jti": jti,
    });
    if let Some(raw_token) = ath_for {
        claims.as_object_mut().unwrap().insert(
            "ath".into(),
            serde_json::json!(compute_ath_for_test(raw_token)),
        );
    }

    let pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("p256 to_pkcs8_pem must succeed for in-memory key");
    let key = EncodingKey::from_ec_pem(pem.as_bytes())
        .expect("jsonwebtoken from_ec_pem must accept p256 PKCS#8 PEM");
    encode(&header, &claims, &key).expect("test dpop proof mint must succeed")
}

/// Compute the FR-022a `ath` value (base64url SHA-256 of an access
/// token's wire-form bytes) for use in test fixtures. Mirrors
/// `auth::dpop::compute_ath` but available without crate-internal
/// visibility for integration tests under `tests/`.
pub fn compute_ath_for_test(raw_token: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(raw_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Compute the RFC 7638 thumbprint (base64url-encoded) of an ES256
/// public key. Convenience for setting `cnf.jkt` in `MintTokenClaims`.
pub fn es256_thumbprint_b64url(verifying_key: &p256::ecdsa::VerifyingKey) -> String {
    use crate::auth::crypto::{JwkThumbprintInput, jwk_thumbprint_b64url};
    let point = verifying_key.to_encoded_point(false);
    let x = point.x().expect("p256 uncompressed encoding has x");
    let y = point.y().expect("p256 uncompressed encoding has y");
    let mut x_arr = [0u8; 32];
    let mut y_arr = [0u8; 32];
    x_arr.copy_from_slice(x);
    y_arr.copy_from_slice(y);
    jwk_thumbprint_b64url(JwkThumbprintInput::EcP256 {
        x: &x_arr,
        y: &y_arr,
    })
}

/// Current Unix timestamp in seconds. Tests pin time relative to this
/// for `iat`/`exp` computation.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
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

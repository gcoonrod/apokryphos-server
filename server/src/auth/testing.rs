//! Test helpers for Phase 3: ephemeral keypair generation, token/proof
//! minting, and the in-process `MockOidcProvider`.
//!
//! This module is gated by `#[cfg(any(test, feature = "test-utils"))]` so
//! it does NOT compile into the release binary (R1, R15). Production never
//! generates cryptographic keys; only tests do.
//!
//! ## Phase 2 scope (current)
//!
//! - Deterministic-seeded RNG factory for reproducible test failures.
//! - PS256 (RSA-2048) keypair generation.
//! - ES256 (P-256) keypair generation.
//!
//! ## Phase 3 scope (TODO)
//!
//! - `JwkPublic` shape exposing the public-key material for serving via
//!   the mock JWKS endpoint.
//! - `mint_vault_token(claims, key, alg) -> String` and
//!   `mint_admin_token(...)` helpers using `jsonwebtoken::encode`.
//! - `mint_dpop_proof(htm, htu, iat, jti, key, alg) -> String` helper.
//! - `MockOidcProvider` — an `axum::Router` bound to `127.0.0.1:0` serving
//!   `/.well-known/openid-configuration` and `/jwks.json` with an observable
//!   request counter (consumed by SC-008 / SC-009 tests).

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

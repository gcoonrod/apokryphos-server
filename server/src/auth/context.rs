//! OIDC audience context (FR-001, FR-002, FR-005, FR-006, FR-007).
//!
//! `OidcContext` is the per-audience runtime carrier:
//!
//!   - configured `issuer_url` + `audience` (from `vault_oidc` / `admin_oidc`)
//!   - atomic-swap-held `Jwks` and `Discovery` caches
//!   - shared `AuthConfig` for timings (clock skew, refresh intervals)
//!   - `AudienceTag` (Vault | Admin) for the `JtiKey` cross-context fence
//!   - `Weak<OidcContext>` cross-reach to the *other* context for the
//!     runtime overlap check (T030, US2 — initialized after both contexts
//!     are constructed, before refresh tasks are spawned).
//!
//! Phase 2 / Phase 3 first-step scope: this module lands the type +
//! `init_single_context`. The dual-context `init_contexts`, the cross-reach
//! wiring, `check_disjoint_jwks`, and `install_refreshed_jwks` arrive in
//! US2 (T028–T030).

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::AtomicU64;

use arc_swap::ArcSwap;
use openidconnect::reqwest;
use url::Url;

use crate::auth::discovery::{Discovery, DiscoveryFetchError, fetch_discovery};
use crate::auth::jwks::{Jwks, JwksFetchError, fetch_jwks};
use crate::config::{AuthConfig, OidcAudienceConfig};

/// Audience discriminator. Used by `OidcContext` for the cross-context
/// `JtiKey` fence (replay.rs's `audience_tag` byte) and for diagnostic
/// messages that need to name the offending audience without exposing
/// key material.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum AudienceTag {
    Vault,
    Admin,
}

impl AudienceTag {
    /// Byte used as the first component of `JtiKey` to make cross-audience
    /// replay structurally impossible (`auth::replay::JtiKey::new`).
    pub fn as_jti_key_byte(self) -> u8 {
        match self {
            AudienceTag::Vault => 0x01,
            AudienceTag::Admin => 0x02,
        }
    }

    /// Human-readable name for log/diagnostic fields. Public information
    /// (neither audience tag is a secret).
    pub fn name(self) -> &'static str {
        match self {
            AudienceTag::Vault => "vault",
            AudienceTag::Admin => "admin",
        }
    }
}

/// Per-audience OIDC context: configuration + caches + cross-reach.
///
/// Field visibility:
///   - `pub`: `tag`, `issuer_url`, `audience`, `jwks`, `discovery`,
///     `auth_config` — read by `auth::token` and `auth::dpop` validation
///     paths (US1) and by the dual-context check (US2).
///   - private: `last_on_demand_refresh` (used by R6 rate limit, T031),
///     `other` (cross-reach set by US2's `init_contexts`).
pub struct OidcContext {
    pub tag: AudienceTag,
    pub issuer_url: Url,
    pub audience: String,
    pub jwks: ArcSwap<Jwks>,
    pub discovery: ArcSwap<Discovery>,
    pub auth_config: Arc<AuthConfig>,

    /// R6 on-demand-refresh rate limit: seconds-since-Unix-epoch of the
    /// last attempt. Initialized to 0 (no prior attempt). Updated via
    /// `compare_exchange` so multiple in-flight requests collapse to one
    /// fetch per rate-limit window. Wired up in T031 (US2).
    #[allow(dead_code)]
    last_on_demand_refresh: AtomicU64,

    /// Cross-context reach (US2 / T028–T030). `Weak` breaks the
    /// `Arc<OidcContext> ⇌ Arc<OidcContext>` cycle that two strong
    /// references would create. Set by `init_contexts` AFTER both
    /// contexts are constructed but BEFORE any refresh task runs;
    /// `set()` is one-shot (`OnceLock::set` returns `Err` on second call).
    ///
    /// Phase 3 single-context scope: this field exists but is never set.
    /// US2 (T028) wires both directions in `init_contexts`.
    #[allow(dead_code)]
    other: OnceLock<Weak<OidcContext>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ContextInitError {
    #[error("oidc context {audience}: discovery fetch failed: {source}")]
    DiscoveryFetch {
        audience: AudienceTag,
        #[source]
        source: DiscoveryFetchError,
    },
    #[error("oidc context {audience}: jwks fetch failed: {source}")]
    JwksFetch {
        audience: AudienceTag,
        #[source]
        source: JwksFetchError,
    },
    #[error("oidc context {audience}: jwks is empty (no FR-010a-compliant keys)")]
    EmptyJwks { audience: AudienceTag },
    /// Future US2 variant (T028–T030): both contexts share signing keys.
    #[error(
        "oidc contexts share signing keys (constitution principle IV); audience {context_with_extra_key} contains a key already present in the other context"
    )]
    JwksOverlap { context_with_extra_key: AudienceTag },
}

impl std::fmt::Display for AudienceTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Construct a single `OidcContext` by fetching discovery + JWKS. The
/// dual-context variant (`init_contexts`, with cross-reach wiring + the
/// FR-006 disjoint-JWKS check) lands in US2 (T028).
///
/// This single-context constructor is enough to exercise the
/// fetch-cache-swap path in tests and to ground the single-vault MVP path
/// when US1's `app.rs` integration lands (T024).
pub async fn init_single_context(
    tag: AudienceTag,
    oidc_cfg: &OidcAudienceConfig,
    auth_cfg: Arc<AuthConfig>,
    http_client: &reqwest::Client,
) -> Result<Arc<OidcContext>, ContextInitError> {
    let discovery = fetch_discovery(http_client, &oidc_cfg.issuer_url)
        .await
        .map_err(|source| ContextInitError::DiscoveryFetch {
            audience: tag,
            source,
        })?;

    let jwks = fetch_jwks(http_client, &discovery.jwks_uri)
        .await
        .map_err(|source| {
            // Map the parser's `Empty` variant to the typed startup error
            // so the caller's exit-non-zero path (FR-002) names it cleanly.
            if matches!(source, JwksFetchError::Empty) {
                ContextInitError::EmptyJwks { audience: tag }
            } else {
                ContextInitError::JwksFetch {
                    audience: tag,
                    source,
                }
            }
        })?;

    Ok(Arc::new(OidcContext {
        tag,
        issuer_url: oidc_cfg.issuer_url.clone(),
        audience: oidc_cfg.audience.clone(),
        jwks: ArcSwap::from_pointee(jwks),
        discovery: ArcSwap::from_pointee(discovery),
        auth_config: auth_cfg,
        last_on_demand_refresh: AtomicU64::new(0),
        other: OnceLock::new(),
    }))
}

// The inline test module is split in two: the audience-tag tests are
// `cfg(test)`-only because they need no external crates, while the
// init_single_context smoke tests require `auth::testing` (and thus the
// optional crypto deps activated by `test-utils`). Splitting like this
// means `cargo test` without `--features test-utils` still compiles and
// runs the audience-tag tests.

#[cfg(test)]
mod tests_no_feature {
    use super::*;

    #[test]
    fn audience_tag_distinct_jti_bytes() {
        assert_ne!(
            AudienceTag::Vault.as_jti_key_byte(),
            AudienceTag::Admin.as_jti_key_byte(),
            "cross-audience replay fence depends on distinct tag bytes"
        );
    }

    #[test]
    fn audience_tag_display_is_lowercase_name() {
        assert_eq!(AudienceTag::Vault.to_string(), "vault");
        assert_eq!(AudienceTag::Admin.to_string(), "admin");
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::auth::testing::{MockOidcProvider, deterministic_rng, es256_public_jwk, generate_es256_keypair};
    use crate::config::OidcAudienceConfig;
    use p256::ecdsa::SigningKey;
    use serde_json::json;

    /// End-to-end smoke for the OIDC context lifecycle: spin up an
    /// in-process `MockOidcProvider` serving a JWKS with one ES256 key,
    /// run `init_single_context`, assert that:
    ///   1. The discovery endpoint was fetched exactly once.
    ///   2. The JWKS endpoint was fetched exactly once.
    ///   3. The resulting context holds a non-empty `Jwks` whose
    ///      thumbprint matches what the mock served.
    ///   4. `OidcContext::audience` and `issuer_url` are preserved
    ///      verbatim from the supplied `OidcAudienceConfig`.
    ///
    /// This verifies T016 + T017 + T018 end-to-end against a real HTTP
    /// flow (over loopback), which is the integration surface that
    /// production touches when fetching from a live OIDC provider.
    #[tokio::test]
    async fn init_single_context_fetches_discovery_and_jwks() {
        let mut rng = deterministic_rng(42);
        let key: SigningKey = generate_es256_keypair(&mut rng);
        let verifying = key.verifying_key();
        let public_jwk = es256_public_jwk(verifying, Some("test-key-1"));

        let jwks_doc = json!({ "keys": [public_jwk] });
        let mock = MockOidcProvider::start(jwks_doc).await;

        // Build a config pointing at the mock. The OidcAudienceConfig
        // constructor enforces HTTPS — but the mock binds HTTP. For the
        // test path, we bypass via direct struct construction (this is
        // a test-only escape hatch; production always uses the validating
        // constructor).
        let oidc_cfg = OidcAudienceConfig {
            issuer_url: mock.issuer_url(),
            audience: "apokryphos-test-vault".to_string(),
        };
        let auth_cfg = Arc::new(AuthConfig::default());
        let http_client = reqwest::Client::new();

        let ctx = init_single_context(
            AudienceTag::Vault,
            &oidc_cfg,
            auth_cfg,
            &http_client,
        )
        .await
        .expect("init_single_context must succeed against a healthy mock");

        // Each endpoint fetched exactly once during initialization.
        assert_eq!(
            mock.discovery_fetch_count(),
            1,
            "discovery endpoint must be fetched exactly once"
        );
        assert_eq!(
            mock.jwks_fetch_count(),
            1,
            "jwks endpoint must be fetched exactly once"
        );

        // Context preserves the input configuration verbatim.
        assert_eq!(ctx.tag, AudienceTag::Vault);
        assert_eq!(ctx.audience, "apokryphos-test-vault");
        assert_eq!(ctx.issuer_url.as_str(), mock.issuer_url().as_str());

        // JWKS cache holds one ES256 key indexed by both kid + thumbprint.
        let jwks = ctx.jwks.load_full();
        assert_eq!(jwks.len(), 1);
        let candidates = jwks.lookup_candidates(Some("test-key-1"));
        assert_eq!(candidates.len(), 1, "kid lookup must find the served key");
        assert_eq!(candidates[0].alg, crate::auth::jwks::JwsAlg::Es256);

        // The thumbprint index is consistent with the kid index.
        let thumbprints: Vec<_> = jwks.iter_thumbprints().collect();
        assert_eq!(thumbprints.len(), 1);
        assert!(jwks.lookup_by_thumbprint(&thumbprints[0]).is_some());

        // Discovery cache holds the mock's jwks_uri.
        let discovery = ctx.discovery.load_full();
        let expected_jwks_uri = mock.issuer_url().join("/jwks.json").unwrap();
        assert_eq!(discovery.jwks_uri.as_str(), expected_jwks_uri.as_str());
    }

    /// Negative path: when the JWKS endpoint serves a key set that contains
    /// only non-FR-010a algorithms (here: a single RS256 key), the parser
    /// returns `Empty` and `init_single_context` surfaces `EmptyJwks` —
    /// which `app.rs::run()` maps to a non-zero exit (FR-002).
    #[tokio::test]
    async fn init_single_context_rejects_jwks_with_no_fr_010a_keys() {
        // RS256 RSA key with synthetic values — the parser filters it out
        // before computing a thumbprint, so the values don't need to be
        // valid crypto.
        let unsupported_jwks = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "rs256-only",
                "n": "AQAB",
                "e": "AQAB"
            }]
        });
        let mock = MockOidcProvider::start(unsupported_jwks).await;

        let oidc_cfg = OidcAudienceConfig {
            issuer_url: mock.issuer_url(),
            audience: "apokryphos-test-vault".to_string(),
        };
        let http_client = reqwest::Client::new();
        let result = init_single_context(
            AudienceTag::Vault,
            &oidc_cfg,
            Arc::new(AuthConfig::default()),
            &http_client,
        )
        .await;

        // Avoid `{:?}` on the `Ok` arm: `OidcContext` does not derive `Debug`
        // because it would require Debug on `Weak<OidcContext>` (cyclic).
        // Match-discriminator pattern instead.
        match result {
            Err(ContextInitError::EmptyJwks {
                audience: AudienceTag::Vault,
            }) => {} // expected
            Err(other) => panic!("expected EmptyJwks(vault), got error: {other}"),
            Ok(_) => panic!("expected EmptyJwks(vault), got Ok"),
        }
    }
}

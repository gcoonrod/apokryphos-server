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
//! US2 scope adds: `init_contexts` (dual-init + cross-reach + startup
//! overlap check), `check_disjoint_jwks` (the FR-006 thumbprint-set
//! disjointness test), and `install_refreshed_jwks` (the runtime-refresh
//! variant that rejects an incoming JWKS overlap WITHOUT exiting the
//! process per FR-007).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::AtomicU64;

use arc_swap::ArcSwap;
use openidconnect::reqwest;
use tokio::sync::Notify;
use url::Url;

use crate::auth::discovery::{Discovery, DiscoveryFetchError, fetch_discovery};
use crate::auth::jwks::{Jwks, JwksFetchError, fetch_jwks};
use crate::config::{AuthConfig, OidcAudienceConfig, ServerConfig};

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

    /// HTTP client used for both scheduled and on-demand JWKS/discovery
    /// refreshes. `reqwest::Client` is internally `Arc`'d, so cloning is
    /// cheap — each context stores its own clone of the shared client
    /// configured in `app::run` (with redirect::Policy::none() and a
    /// bounded timeout).
    pub(crate) http_client: reqwest::Client,

    /// R6 single-flight signaling. `notify_waiters` is called by the
    /// task that successfully claims the on-demand-refresh slot (via
    /// the CAS on `last_on_demand_refresh`) once the JWKS fetch +
    /// install has completed (whether successfully or not). Waiters
    /// — concurrent requests that observed the rate-limit window —
    /// re-check the JWKS after waking.
    pub(crate) refresh_notify: Notify,

    /// R6 on-demand-refresh rate limit: seconds-since-Unix-epoch of when
    /// a refresh attempt was *claimed* (set via `compare_exchange` BEFORE
    /// the fetch begins). Pairs with `last_refresh_completed` (set AFTER
    /// the install) so loser-path callers in `on_demand_refresh` can
    /// distinguish "winner is still fetching" from "winner has already
    /// finished" — the latter case lets losers retry immediately without
    /// waiting on the fire-and-forget `refresh_notify`.
    #[allow(dead_code)]
    pub(crate) last_on_demand_refresh: AtomicU64,

    /// Seconds-since-Unix-epoch of the most recent refresh *completion*
    /// (success or failure — set unconditionally after the fetch
    /// resolves, before `notify_waiters` fires). Monotonic non-decreasing.
    /// Lets `on_demand_refresh` losers close the `notify_waiters` race:
    /// `notify_waiters` doesn't store a permit, so a loser whose
    /// `notified()` future is created after the winner has already
    /// fired the notify would otherwise wait the full timeout for
    /// nothing. The loser re-checks this field against its `prev`
    /// snapshot and short-circuits when a completion has been observed.
    #[allow(dead_code)]
    pub(crate) last_refresh_completed: AtomicU64,

    /// Cross-context reach (US2 / T028–T030). `Weak` breaks the
    /// `Arc<OidcContext> ⇌ Arc<OidcContext>` cycle that two strong
    /// references would create. Set by `init_contexts` AFTER both
    /// contexts are constructed but BEFORE any refresh task runs;
    /// `set()` is one-shot — calling it twice is a programmer error and
    /// panics, because `init_contexts` is the single wiring point.
    other: OnceLock<Weak<OidcContext>>,
}

/// Runtime overlap diagnostic returned by `check_disjoint_jwks` and
/// `install_refreshed_jwks`. The `Display` impl names ONLY the audience
/// tag of the side that brought in the duplicate key — never the key's
/// thumbprint or any JWK byte. Constitution Principle IV: an attacker
/// who can read logs MUST NOT learn which signing key is in use.
#[derive(Debug)]
pub struct OverlapError {
    /// The audience tag of the JWKS that contained a key already present
    /// in the *other* context's JWKS. For startup (T028), this is the
    /// `b`-side of `check_disjoint_jwks(vault, admin)` — i.e., admin.
    /// For runtime refresh (T030), this is `self_ctx.tag` — the context
    /// whose refresh attempt collided with the existing other-context
    /// JWKS.
    pub context_with_extra_key: AudienceTag,
}

impl std::fmt::Display for OverlapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "oidc contexts share signing keys; audience {} contains a key already present in the other context",
            self.context_with_extra_key
        )
    }
}

impl std::error::Error for OverlapError {}

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
        http_client: http_client.clone(),
        refresh_notify: Notify::new(),
        last_on_demand_refresh: AtomicU64::new(0),
        last_refresh_completed: AtomicU64::new(0),
        other: OnceLock::new(),
    }))
}

/// T029: thumbprint-set disjointness test. Returns `Ok(())` if `a` and
/// `b` share no JWK thumbprints; `Err(OverlapError { context_with_extra_key: b_tag })`
/// on first match. The caller passes `b_tag` so the error names the
/// audience whose key set is *not allowed* to contain the duplicate —
/// at startup (T028), that's admin (since admin is the second context
/// init'd); at runtime refresh (T030), it's `self_ctx.tag`.
///
/// `HashSet`'s native hasher is fine: the input is a SHA-256 thumbprint,
/// so the worst an attacker controlling JWKS contents could do is force
/// a 256-bit hash collision — well outside their reach. There is no
/// adversarial input that benefits from a randomized hasher here.
pub(crate) fn check_disjoint_jwks(
    a: &Jwks,
    b: &Jwks,
    b_tag: AudienceTag,
) -> Result<(), OverlapError> {
    let a_thumbs: HashSet<[u8; 32]> = a.iter_thumbprints().collect();
    for tp in b.iter_thumbprints() {
        if a_thumbs.contains(&tp) {
            return Err(OverlapError {
                context_with_extra_key: b_tag,
            });
        }
    }
    Ok(())
}

/// T028: dual-context startup constructor. Fetches discovery + JWKS for
/// both audiences sequentially, then runs the FR-006 disjointness check.
/// On overlap, returns `ContextInitError::JwksOverlap { context_with_extra_key: Admin }`
/// — admin is the b-side of the check, so a key shared by both contexts
/// is "an extra key in admin" from the disjointness check's perspective.
///
/// After the overlap check passes, both contexts' `other` `OnceLock`s
/// are populated with `Weak` references to the *other* context. This
/// MUST happen before any refresh task spawns (the runtime refresh path
/// in `install_refreshed_jwks` requires the cross-reach to be wired).
/// Both `set()` calls must succeed; this function is the single wiring
/// point, so a returned `Err` from `OnceLock::set` is a programmer
/// error and panics.
pub async fn init_contexts(
    cfg: &ServerConfig,
    http_client: &reqwest::Client,
) -> Result<(Arc<OidcContext>, Arc<OidcContext>), ContextInitError> {
    let auth_cfg = Arc::new(cfg.auth.clone());
    let vault_ctx = init_single_context(
        AudienceTag::Vault,
        &cfg.vault_oidc,
        Arc::clone(&auth_cfg),
        http_client,
    )
    .await?;
    let admin_ctx = init_single_context(
        AudienceTag::Admin,
        &cfg.admin_oidc,
        Arc::clone(&auth_cfg),
        http_client,
    )
    .await?;

    check_disjoint_jwks(
        &vault_ctx.jwks.load_full(),
        &admin_ctx.jwks.load_full(),
        AudienceTag::Admin,
    )
    .map_err(|e| ContextInitError::JwksOverlap {
        context_with_extra_key: e.context_with_extra_key,
    })?;

    vault_ctx
        .other
        .set(Arc::downgrade(&admin_ctx))
        .ok()
        .expect("context cross-reach already initialized (vault → admin)");
    admin_ctx
        .other
        .set(Arc::downgrade(&vault_ctx))
        .ok()
        .expect("context cross-reach already initialized (admin → vault)");

    Ok((vault_ctx, admin_ctx))
}

/// T030: runtime JWKS install with disjointness check. Called by both
/// the scheduled refresh task (T049) and the on-demand refresh path
/// (T031). Per FR-007, an overlap detected at runtime MUST NOT exit the
/// process — the new JWKS is rejected and the previous one stays in
/// place, with a `tracing::error!` diagnostic emitted at the documented
/// shape (audience tag only, no key material).
///
/// `Weak::upgrade` on `self_ctx.other` should never fail in normal
/// operation (both `Arc`s are held by `app::run`'s lifetime), but if it
/// does we refuse the install rather than skip the disjointness check.
/// Refusing-on-upgrade-failure means a transient impossible-state can't
/// silently disable the cross-context overlap guarantee.
pub(crate) fn install_refreshed_jwks(
    self_ctx: &OidcContext,
    new_jwks: Jwks,
) -> Result<(), OverlapError> {
    let Some(other_arc) = self_ctx.other.get().and_then(|weak| weak.upgrade()) else {
        tracing::error!(
            event = "context.refresh.cross_reach_failed",
            audience = self_ctx.tag.name(),
            "refused JWKS install: cross-context reach not initialized or other context dropped"
        );
        return Err(OverlapError {
            context_with_extra_key: self_ctx.tag,
        });
    };

    let other_jwks = other_arc.jwks.load_full();
    if let Err(e) = check_disjoint_jwks(&other_jwks, &new_jwks, self_ctx.tag) {
        tracing::error!(
            event = "context.refresh.overlap_rejected",
            audience = self_ctx.tag.name(),
            "refused JWKS install: new key set overlaps with other context"
        );
        return Err(e);
    }

    self_ctx.jwks.store(Arc::new(new_jwks));
    Ok(())
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
    use crate::auth::testing::{
        MockOidcProvider, deterministic_rng, es256_public_jwk, generate_es256_keypair,
    };
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

        let ctx = init_single_context(AudienceTag::Vault, &oidc_cfg, auth_cfg, &http_client)
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

    /// T029 unit test: `check_disjoint_jwks` returns Ok for two
    /// thumbprint-disjoint JWKS, and Err naming the b-side audience when
    /// a key thumbprint appears in both.
    #[tokio::test]
    async fn check_disjoint_jwks_detects_thumbprint_overlap() {
        use crate::auth::jwks::parse_jwks;
        use jsonwebtoken::jwk::JwkSet;

        let mut rng = deterministic_rng(7);
        let key_a: SigningKey = generate_es256_keypair(&mut rng);
        let key_b: SigningKey = generate_es256_keypair(&mut rng);
        let jwk_a = es256_public_jwk(key_a.verifying_key(), Some("a"));
        let jwk_b = es256_public_jwk(key_b.verifying_key(), Some("b"));

        let jwks_a: JwkSet = serde_json::from_value(json!({ "keys": [&jwk_a] })).unwrap();
        let jwks_b: JwkSet = serde_json::from_value(json!({ "keys": [&jwk_b] })).unwrap();
        let jwks_both: JwkSet =
            serde_json::from_value(json!({ "keys": [&jwk_a, &jwk_b] })).unwrap();

        let parsed_a = parse_jwks(jwks_a).unwrap();
        let parsed_b = parse_jwks(jwks_b).unwrap();
        let parsed_both = parse_jwks(jwks_both).unwrap();

        // Disjoint pair → Ok.
        assert!(check_disjoint_jwks(&parsed_a, &parsed_b, AudienceTag::Admin).is_ok());

        // Overlap → Err names the b-side audience the caller passed in.
        let err = check_disjoint_jwks(&parsed_a, &parsed_both, AudienceTag::Admin)
            .expect_err("overlap must be detected");
        assert_eq!(err.context_with_extra_key, AudienceTag::Admin);
        let display = err.to_string();
        assert!(display.contains("admin"));
        // No thumbprint hex / no base64 substring of the offending key in
        // the Display output. Test by asserting the JWK's `x` / `y`
        // coordinates don't appear in the diagnostic.
        if let serde_json::Value::String(x) = &jwk_a["x"] {
            assert!(
                !display.contains(x.as_str()),
                "Display must not leak JWK x coordinate"
            );
        }
    }

    /// T028 + T029 integration: two mock providers with deliberately
    /// overlapping JWKS → `init_contexts` returns `JwksOverlap` and the
    /// error message names the admin audience, never key material.
    #[tokio::test]
    async fn init_contexts_rejects_overlapping_jwks() {
        use crate::config::{ServerConfig, StorageBackend};

        let mut rng = deterministic_rng(13);
        let shared_key: SigningKey = generate_es256_keypair(&mut rng);
        let shared_jwk = es256_public_jwk(shared_key.verifying_key(), Some("shared"));
        let vault_only: SigningKey = generate_es256_keypair(&mut rng);
        let vault_jwk = es256_public_jwk(vault_only.verifying_key(), Some("vault-only"));

        let vault_jwks_doc = json!({ "keys": [&vault_jwk, &shared_jwk] });
        let admin_jwks_doc = json!({ "keys": [&shared_jwk] });
        let vault_mock = MockOidcProvider::start(vault_jwks_doc).await;
        let admin_mock = MockOidcProvider::start(admin_jwks_doc).await;

        let cfg = ServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            block_size_bytes: 1024 * 1024,
            storage_backend: StorageBackend::None,
            trusted_proxies: vec![],
            // Direct struct construction bypasses OidcAudienceConfig::new's
            // HTTPS check — mocks bind HTTP loopback. Production always
            // routes through the validating constructor.
            vault_oidc: OidcAudienceConfig {
                issuer_url: vault_mock.issuer_url(),
                audience: "vault-aud".to_string(),
            },
            admin_oidc: OidcAudienceConfig {
                issuer_url: admin_mock.issuer_url(),
                audience: "admin-aud".to_string(),
            },
            drain_timeout: std::time::Duration::from_secs(5),
            auth: AuthConfig::default(),
        };
        let http_client = reqwest::Client::new();
        let result = init_contexts(&cfg, &http_client).await;
        match result {
            Err(ContextInitError::JwksOverlap {
                context_with_extra_key: AudienceTag::Admin,
            }) => {} // expected
            Err(other) => panic!("expected JwksOverlap(admin), got error: {other}"),
            Ok(_) => panic!("expected JwksOverlap(admin), got Ok"),
        }
    }

    /// T028 happy path: disjoint JWKS → both contexts construct, the
    /// `Weak` cross-reach is wired in both directions, and each side can
    /// upgrade its `Weak` back to the other context's `Arc`.
    #[tokio::test]
    async fn init_contexts_wires_cross_reach_on_disjoint_jwks() {
        use crate::config::{ServerConfig, StorageBackend};

        let mut rng = deterministic_rng(29);
        let vault_key: SigningKey = generate_es256_keypair(&mut rng);
        let admin_key: SigningKey = generate_es256_keypair(&mut rng);
        let vault_jwk = es256_public_jwk(vault_key.verifying_key(), Some("vault-k"));
        let admin_jwk = es256_public_jwk(admin_key.verifying_key(), Some("admin-k"));

        let vault_mock = MockOidcProvider::start(json!({ "keys": [vault_jwk] })).await;
        let admin_mock = MockOidcProvider::start(json!({ "keys": [admin_jwk] })).await;

        let cfg = ServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            block_size_bytes: 1024 * 1024,
            storage_backend: StorageBackend::None,
            trusted_proxies: vec![],
            // Direct struct construction bypasses OidcAudienceConfig::new's
            // HTTPS check — mocks bind HTTP loopback. Production always
            // routes through the validating constructor.
            vault_oidc: OidcAudienceConfig {
                issuer_url: vault_mock.issuer_url(),
                audience: "vault-aud".to_string(),
            },
            admin_oidc: OidcAudienceConfig {
                issuer_url: admin_mock.issuer_url(),
                audience: "admin-aud".to_string(),
            },
            drain_timeout: std::time::Duration::from_secs(5),
            auth: AuthConfig::default(),
        };
        let http_client = reqwest::Client::new();
        let (vault_ctx, admin_ctx) = init_contexts(&cfg, &http_client)
            .await
            .expect("disjoint init_contexts must succeed");

        // Cross-reach is populated in both directions, and each Weak
        // upgrades to the other context.
        let vault_other = vault_ctx
            .other
            .get()
            .expect("vault.other set")
            .upgrade()
            .expect("admin Arc still live");
        assert_eq!(vault_other.tag, AudienceTag::Admin);
        let admin_other = admin_ctx
            .other
            .get()
            .expect("admin.other set")
            .upgrade()
            .expect("vault Arc still live");
        assert_eq!(admin_other.tag, AudienceTag::Vault);
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

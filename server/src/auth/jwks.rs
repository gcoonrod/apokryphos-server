//! JWKS fetching, parsing, and the FR-010a algorithm allowlist enforcement
//! at JWK-ingestion time (research R2, R5).
//!
//! Three concerns live here:
//!
//!   1. `JwsAlg` — the typed `{PS256, ES256}` enum that is the FR-010a
//!      allowlist's structural fence. Any algorithm outside this set
//!      cannot even be constructed.
//!   2. `Jwk` + `Jwks` — the parsed, deduplicated, thumbprint-indexed key
//!      set. JWKs whose `alg` is outside FR-010a are silently filtered out
//!      at parse time (the JWKS endpoint may serve keys for other clients;
//!      we only consume the FR-010a-compliant subset).
//!   3. `fetch_jwks` — the HTTP fetch path. Uses `reqwest` directly via
//!      `openidconnect`'s re-export; deserializes with `serde_json` into
//!      `jsonwebtoken::jwk::JwkSet` for ready interop with the verifier.
//!
//! Atomic-swap installation via `arc_swap::ArcSwap<Arc<Jwks>>` (R5, FR-005)
//! lives on `auth::context::OidcContext`, not here — this module produces
//! `Jwks` values that the caller then installs.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm};
use openidconnect::reqwest;
use url::Url;

use crate::auth::crypto::{self, JwkThumbprintInput};

/// FR-010a algorithm allowlist as a typed enum. No other variants exist by
/// design — any JWS whose `alg` is outside this set is rejected before
/// signature verification.
///
/// Clarify-Q1 settled this set as PS256 + ES256. Adding a variant requires
/// a spec amendment, not just a code change.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JwsAlg {
    Ps256,
    Es256,
}

impl JwsAlg {
    /// Map from `jsonwebtoken`'s `KeyAlgorithm` to our typed allowlist.
    /// Returns `None` for any algorithm outside FR-010a (`RS256`, `HS*`,
    /// `EdDSA`, `none`, etc.). Used at JWKS-ingestion time to filter the
    /// provider's key set.
    pub fn from_jwt_key_alg(alg: KeyAlgorithm) -> Option<Self> {
        match alg {
            KeyAlgorithm::PS256 => Some(JwsAlg::Ps256),
            KeyAlgorithm::ES256 => Some(JwsAlg::Es256),
            _ => None,
        }
    }

    /// Map to `jsonwebtoken::Algorithm` for the `Validation` configuration.
    pub fn to_jwt_algorithm(self) -> jsonwebtoken::Algorithm {
        match self {
            JwsAlg::Ps256 => jsonwebtoken::Algorithm::PS256,
            JwsAlg::Es256 => jsonwebtoken::Algorithm::ES256,
        }
    }
}

/// A parsed, FR-010a-conforming public key with its RFC 7638 thumbprint.
/// `jwk` retains the raw `jsonwebtoken::jwk::Jwk` so signature verification
/// can construct a `DecodingKey::from_jwk` without re-parsing.
#[derive(Debug, Clone)]
pub struct Jwk {
    pub kid: Option<String>,
    pub alg: JwsAlg,
    pub thumbprint: [u8; 32],
    /// The raw `jsonwebtoken` JWK. Held privately so callers that want the
    /// public-key material go through `jwk()` and don't accidentally
    /// re-export private fields.
    jwk: jsonwebtoken::jwk::Jwk,
}

impl Jwk {
    /// Access the underlying `jsonwebtoken::jwk::Jwk` for verifier
    /// construction (`DecodingKey::from_jwk(jwk.jwk())`).
    pub fn jwk(&self) -> &jsonwebtoken::jwk::Jwk {
        &self.jwk
    }
}

/// A parsed JWKS keyed by `kid` (preferred) and thumbprint (for DPoP `jkt`
/// matching and cross-context overlap detection).
#[derive(Debug, Clone)]
pub struct Jwks {
    by_kid: HashMap<String, Arc<Jwk>>,
    by_thumbprint: HashMap<[u8; 32], Arc<Jwk>>,
    /// Keys with no `kid` — consulted as a fallback during signature
    /// verification when the JWS header omits `kid`.
    keyless: Vec<Arc<Jwk>>,
}

impl Jwks {
    /// Construct an empty JWKS. Used in tests; production never observes one
    /// because `fetch_jwks` rejects empty key sets with `Empty`.
    pub fn empty() -> Self {
        Jwks {
            by_kid: HashMap::new(),
            by_thumbprint: HashMap::new(),
            keyless: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.by_kid.is_empty() && self.keyless.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_kid.len() + self.keyless.len()
    }

    /// Iterate over every cached thumbprint. Used by the cross-context
    /// overlap check at startup (FR-006) + after each refresh (FR-007).
    pub fn iter_thumbprints(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.by_thumbprint.keys().copied()
    }

    /// Candidate keys for signature verification. When `kid` is present,
    /// returns the matching key first; if absent or no match, returns the
    /// keyless set as a fallback (FR-011 verification tries each in order).
    pub fn lookup_candidates(&self, kid: Option<&str>) -> Vec<Arc<Jwk>> {
        if let Some(k) = kid {
            if let Some(found) = self.by_kid.get(k) {
                return vec![Arc::clone(found)];
            }
        }
        self.keyless.iter().cloned().collect()
    }

    /// Look up a key by its RFC 7638 thumbprint. Used for the FR-022
    /// `cnf.jkt` ↔ proof-key match.
    pub fn lookup_by_thumbprint(&self, tp: &[u8; 32]) -> Option<Arc<Jwk>> {
        self.by_thumbprint.get(tp).cloned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwksFetchError {
    #[error("HTTP fetch of JWKS failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWKS endpoint returned non-2xx status: {0}")]
    BadStatus(u16),
    #[error("JWKS JSON parse failed: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("JWKS contains no FR-010a-conformant keys (PS256 / ES256)")]
    Empty,
    #[error("EC key has unsupported curve (only P-256 is permitted per FR-010a)")]
    UnsupportedCurve,
    #[error("EC coordinate is not 32 bytes after base64url decode (got {len})")]
    InvalidEcCoordinate { len: usize },
    #[error("base64url decode of JWK field failed: {0}")]
    Base64Decode(String),
}

/// Fetch a JWKS from `jwks_uri` and parse into the FR-010a-filtered `Jwks`.
pub async fn fetch_jwks(
    http_client: &reqwest::Client,
    jwks_uri: &Url,
) -> Result<Jwks, JwksFetchError> {
    let response = http_client.get(jwks_uri.clone()).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(JwksFetchError::BadStatus(status.as_u16()));
    }
    let bytes = response.bytes().await?;
    let raw: JwkSet = serde_json::from_slice(&bytes)?;
    parse_jwks(raw)
}

/// T031: single-flight, rate-limited on-demand JWKS refresh (R6, FR-004).
///
/// Called from `token::validate_token` when signature verification has
/// failed against the currently-cached JWKS. The contract is:
///
///   - **Winner path** (one task per rate-limit window): atomically claim
///     the `last_on_demand_refresh` slot via `compare_exchange`. Fetch
///     the JWKS via `fetch_jwks` and install through
///     `auth::context::install_refreshed_jwks` (which runs the FR-007
///     runtime overlap check). When the fetch + install completes —
///     successfully or not — wake every waiter with `notify_waiters`.
///     Returns `true` only on a successful install, so the caller knows
///     a retry is meaningful.
///   - **Loser path** (all later callers within the same window): the
///     CAS fails. Await `refresh_notify` with a small timeout
///     (`on_demand_refresh_min_interval_secs / 2`). On wake-up, return
///     `true` so the caller re-checks the JWKS once. On timeout, return
///     `false`.
///   - **Stale-but-uncontended path**: the CAS succeeds (because the
///     stored timestamp is older than `now - interval`) — same as
///     winner path.
///
/// The returned `bool` is "**caller may retry once**", not "fetch
/// succeeded". A fetch failure that completes within the timeout still
/// produces `true` for waiters (we woke them; they should re-check
/// because the rate-limit window has reset). The retry will fail again
/// against the unchanged JWKS, which is the correct semantics: the
/// caller's signature error becomes the final answer.
pub(crate) async fn on_demand_refresh(ctx: &crate::auth::context::OidcContext) -> bool {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let interval_secs = ctx.auth_config.on_demand_refresh_min_interval_secs;
    let wait_timeout = Duration::from_secs(interval_secs.saturating_div(2).max(1));

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let prev = ctx.last_on_demand_refresh.load(Ordering::Acquire);
    let cutoff = prev.saturating_add(interval_secs);

    if now_secs < cutoff {
        // Inside the rate-limit window. Some other task either already
        // ran the refresh or is running it now; wait briefly for the
        // Notify and let the caller re-check the JWKS on wake.
        return tokio::time::timeout(wait_timeout, ctx.refresh_notify.notified())
            .await
            .is_ok();
    }

    // Try to claim the slot. If another task beat us to the CAS by
    // microseconds, fall back to the waiter path — the winner will
    // notify us when its fetch completes.
    if ctx
        .last_on_demand_refresh
        .compare_exchange(prev, now_secs, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return tokio::time::timeout(wait_timeout, ctx.refresh_notify.notified())
            .await
            .is_ok();
    }

    // Winner path. Fetch + install inline; wake waiters regardless.
    let jwks_uri = ctx.discovery.load().jwks_uri.clone();
    let install_result = match fetch_jwks(&ctx.http_client, &jwks_uri).await {
        Ok(new_jwks) => crate::auth::context::install_refreshed_jwks(ctx, new_jwks).is_ok(),
        Err(_) => {
            tracing::warn!(
                event = "jwks.on_demand_refresh_failed",
                audience = ctx.tag.name(),
                "on-demand JWKS refresh failed (network or parse error)"
            );
            false
        }
    };
    ctx.refresh_notify.notify_waiters();
    install_result
}

/// Parse a raw `JwkSet` into the FR-010a-filtered indexed `Jwks`. Public
/// for tests; the production fetch goes through `fetch_jwks`.
pub fn parse_jwks(raw: JwkSet) -> Result<Jwks, JwksFetchError> {
    let mut by_kid = HashMap::new();
    let mut by_thumbprint = HashMap::new();
    let mut keyless = Vec::new();

    for raw_jwk in raw.keys {
        // FR-010a: keep only PS256 / ES256. A JWK whose `alg` is anything
        // else is silently dropped — the JWKS may legitimately contain
        // keys for clients we don't speak to.
        let alg = match raw_jwk
            .common
            .key_algorithm
            .and_then(JwsAlg::from_jwt_key_alg)
        {
            Some(a) => a,
            None => continue,
        };

        let thumbprint = compute_thumbprint(&raw_jwk)?;
        let kid = raw_jwk.common.key_id.clone();
        let entry = Arc::new(Jwk {
            kid: kid.clone(),
            alg,
            thumbprint,
            jwk: raw_jwk,
        });
        by_thumbprint.insert(thumbprint, Arc::clone(&entry));
        match kid {
            Some(k) => {
                by_kid.insert(k, entry);
            }
            None => keyless.push(entry),
        }
    }

    if by_kid.is_empty() && keyless.is_empty() {
        return Err(JwksFetchError::Empty);
    }

    Ok(Jwks {
        by_kid,
        by_thumbprint,
        keyless,
    })
}

fn compute_thumbprint(jwk: &jsonwebtoken::jwk::Jwk) -> Result<[u8; 32], JwksFetchError> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => {
            if !matches!(ec.curve, EllipticCurve::P256) {
                return Err(JwksFetchError::UnsupportedCurve);
            }
            let x = engine
                .decode(&ec.x)
                .map_err(|e| JwksFetchError::Base64Decode(e.to_string()))?;
            let y = engine
                .decode(&ec.y)
                .map_err(|e| JwksFetchError::Base64Decode(e.to_string()))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(JwksFetchError::InvalidEcCoordinate {
                    len: x.len().max(y.len()),
                });
            }
            let mut x_arr = [0u8; 32];
            x_arr.copy_from_slice(&x);
            let mut y_arr = [0u8; 32];
            y_arr.copy_from_slice(&y);
            Ok(crypto::jwk_thumbprint(JwkThumbprintInput::EcP256 {
                x: &x_arr,
                y: &y_arr,
            }))
        }
        AlgorithmParameters::RSA(rsa) => {
            let n = engine
                .decode(&rsa.n)
                .map_err(|e| JwksFetchError::Base64Decode(e.to_string()))?;
            let e = engine
                .decode(&rsa.e)
                .map_err(|e| JwksFetchError::Base64Decode(e.to_string()))?;
            Ok(crypto::jwk_thumbprint(JwkThumbprintInput::Rsa {
                n: &n,
                e: &e,
            }))
        }
        // OctetKey / OctetKeyPair are not in FR-010a — `JwsAlg::from_jwt_key_alg`
        // would have returned `None` and the iterator would have skipped them
        // before reaching here. The match arm is exhaustive but unreachable.
        AlgorithmParameters::OctetKey(_) | AlgorithmParameters::OctetKeyPair(_) => {
            unreachable!("FR-010a filter should have rejected non-RSA/EC keys")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jws_alg_filters_out_disallowed_algorithms() {
        assert_eq!(
            JwsAlg::from_jwt_key_alg(KeyAlgorithm::PS256),
            Some(JwsAlg::Ps256)
        );
        assert_eq!(
            JwsAlg::from_jwt_key_alg(KeyAlgorithm::ES256),
            Some(JwsAlg::Es256)
        );
        // FR-010a rejections:
        assert_eq!(JwsAlg::from_jwt_key_alg(KeyAlgorithm::RS256), None);
        assert_eq!(JwsAlg::from_jwt_key_alg(KeyAlgorithm::HS256), None);
        assert_eq!(JwsAlg::from_jwt_key_alg(KeyAlgorithm::EdDSA), None);
    }

    #[test]
    fn parse_jwks_rejects_empty_filtered_set() {
        // A JWKS containing only RS256 keys is functionally empty for us.
        let json = br#"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"k1","n":"AQAB","e":"AQAB"}]}"#;
        let raw: JwkSet = serde_json::from_slice(json).unwrap();
        assert!(matches!(parse_jwks(raw), Err(JwksFetchError::Empty)));
    }

    #[test]
    fn parse_jwks_accepts_es256_with_kid() {
        // Synthetic P-256 key (32-byte x and y, all zero — valid encoding,
        // not a valid point, but adequate for parser exercise).
        let zeros_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        let json = format!(
            r#"{{"keys":[{{"kty":"EC","alg":"ES256","kid":"k1","crv":"P-256","x":"{zeros_b64}","y":"{zeros_b64}"}}]}}"#
        );
        let raw: JwkSet = serde_json::from_slice(json.as_bytes()).unwrap();
        let jwks = parse_jwks(raw).expect("parse should succeed");
        assert_eq!(jwks.len(), 1);
        let by_kid = jwks.lookup_candidates(Some("k1"));
        assert_eq!(by_kid.len(), 1);
        assert_eq!(by_kid[0].alg, JwsAlg::Es256);
    }
}

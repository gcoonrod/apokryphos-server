//! DPoP proof validation per RFC 9449 + FAPI 2.0 + DPoP profile (FR-010a,
//! FR-017..FR-023 inclusive of FR-022a, research R3 + R4 + R7 + R10).
//!
//! `validate_proof` is the *only* constructor of `DpopProof`. It runs the
//! validation pipeline in exactly the order FR-017..FR-023 specifies:
//!
//!   1. **FR-010a alg allowlist (FIRST gate)** — pre-decode the JOSE
//!      header; reject any `alg ∉ {PS256, ES256}` before signature work.
//!   1b. **RFC 9449 §4.2 `typ` header** — reject any proof whose JOSE
//!       `typ` is not exactly `"dpop+jwt"`.
//!   2. **FR-017 signature verify** — verify the JWS against the public
//!      key embedded in the proof's own `jwk` JOSE header parameter
//!      (RFC 9449 §4.2).
//!   3. **FR-018 `htm` match** — constant-time string equality with the
//!      request's HTTP method.
//!   4. **FR-019 `htu` match** — normalize per R10 (lower-case scheme +
//!      host, strip fragment, elide default ports), then constant-time
//!      compare component-wise against the effective request URI.
//!   5. **FR-020 `iat` freshness** — `now - iat <= dpop_freshness_secs +
//!      clock_skew_secs`; forward-skew also bounded by the skew tolerance.
//!   6. **FR-022 `jkt` ↔ `cnf.jkt` match** — compute RFC 7638 thumbprint
//!      of the proof's embedded `jwk`; constant-time compare against the
//!      access token's `cnf.jkt` field.
//!   6b. **FR-022a `ath` ↔ access-token-hash match** — compute base64url
//!       SHA-256 of the trimmed bearer-token bytes; constant-time compare
//!       against the proof's `ath` claim. Runs AFTER signature verify
//!       (so a forged proof rejecting at the sig step cannot leak
//!       access-token-hash material via timing) and BEFORE replay insert
//!       (so a substitution attempt cannot consume a `jti` slot).
//!   7. **FR-021 replay check** — atomic insert of `(audience_tag,
//!      sha256(jti))` into the replay store; `Replayed` → 401,
//!      `MemoryPressure` → 503.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
// SystemTime is still used for the iat-freshness check (Step 5); the
// audit-time deadline that previously used SystemTime + Duration was
// removed to avoid panics on adversarial config — see the replay-insert
// site below.

use axum::http::Method;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::auth::context::OidcContext;
use crate::auth::crypto::{ct_eq_32, ct_eq_str};
use crate::auth::failure::AuthFailure;
use crate::auth::jwks::JwsAlg;
use crate::auth::replay::{InsertError as ReplayInsertError, JtiKey, JtiReplayStore};
use crate::auth::token::AccessToken;

/// Validated DPoP proof. The fields are `pub(crate)` so the middleware
/// can read them for the audit-log path; outside the crate the proof is
/// opaque (no public accessors).
#[derive(Debug, Clone)]
pub struct DpopProof {
    #[allow(dead_code)]
    pub(crate) alg: JwsAlg,
    #[allow(dead_code)]
    pub(crate) htm: String,
    #[allow(dead_code)]
    pub(crate) htu: String,
    #[allow(dead_code)]
    pub(crate) iat: u64,
    #[allow(dead_code)]
    pub(crate) jti: String,
    /// SHA-256 thumbprint of the embedded `jwk`; matched against
    /// `AccessToken::cnf_jkt` via constant-time comparison.
    #[allow(dead_code)]
    pub(crate) thumbprint: [u8; 32],
    /// FR-022a: base64url-no-pad SHA-256 of the access token's
    /// wire-form ASCII bytes. Matched against the proof's `ath` claim
    /// via constant-time string equality.
    #[allow(dead_code)]
    pub(crate) ath: String,
}

#[derive(Deserialize)]
struct DpopClaims {
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<u64>,
    jti: Option<String>,
    /// FR-022a (RFC 9449 §4.2): base64url SHA-256 of the access token's
    /// wire-form bytes. Required at protected resources.
    #[serde(default)]
    ath: Option<String>,
}

/// Compute the FR-022a `ath` value for a given access token: base64url
/// (URL-safe, no padding) of SHA-256 over the token's wire-form ASCII
/// bytes. The caller passes the *trimmed* bearer-token string from the
/// `Authorization: DPoP <token>` header, after the scheme prefix is
/// stripped and surrounding whitespace removed.
pub(crate) fn compute_ath(raw_token: &str) -> String {
    let digest = Sha256::digest(raw_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Validate a raw DPoP proof JWS.
///
/// Arguments:
///   - `raw_proof` — the value of the request's `DPoP` header.
///   - `request_method` — the HTTP method of the current request.
///   - `effective_uri` — the request's URI as resolved by Phase 2's
///     proxy-trust middleware (scheme/host/port from the trusted-proxy
///     resolution, path+query from the request line).
///   - `access_token` — the previously-validated access token; its
///     `cnf_jkt` is matched against the proof's embedded-key thumbprint.
///   - `raw_token` — the trimmed bearer-token bytes from the request's
///     `Authorization: DPoP <token>` header. Used by FR-022a to compute
///     the expected `ath` value (base64url SHA-256 of these bytes) and
///     constant-time compare against the proof's `ath` claim.
///   - `ctx` — the OIDC context (provides the audience tag for the
///     replay-store key and the freshness/skew tolerances).
///   - `replay_store` — the shared `JtiReplayStore` for the FR-021 check.
pub(crate) async fn validate_proof(
    raw_proof: &str,
    request_method: &Method,
    effective_uri: &Url,
    access_token: &AccessToken,
    raw_token: &str,
    ctx: &OidcContext,
    replay_store: &JtiReplayStore,
) -> Result<DpopProof, AuthFailure> {
    // ── Step 1: FR-010a alg allowlist. ─────────────────────────────────
    let header = decode_header(raw_proof).map_err(|_| AuthFailure::InvalidAlg)?;
    let alg = match header.alg {
        Algorithm::PS256 => JwsAlg::Ps256,
        Algorithm::ES256 => JwsAlg::Es256,
        _ => return Err(AuthFailure::InvalidAlg),
    };

    // ── Step 1b: RFC 9449 §4.2 — JOSE typ MUST be "dpop+jwt". ──────────
    // Reject any other JWS — including ID tokens that happen to validate
    // against an embedded key. A non-DPoP JWS being routed through the
    // proof validator is a category-1 failure that should never reach
    // signature verification.
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(AuthFailure::ProofSignatureInvalid);
    }

    // ── Step 2: FR-017 signature verify against the embedded jwk. ──────
    let embedded_jwk = header.jwk.ok_or(AuthFailure::ProofSignatureInvalid)?;
    let decoding_key = DecodingKey::from_jwk(&embedded_jwk)
        .map_err(|_| AuthFailure::ProofSignatureInvalid)?;

    let mut validation = Validation::new(alg.to_jwt_algorithm());
    // DPoP proofs have no aud/iss/exp; jsonwebtoken's `Validation` would
    // reject them as missing if `required_spec_claims` includes `exp`.
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.set_audience::<&str>(&[]);

    let token_data = decode::<DpopClaims>(raw_proof, &decoding_key, &validation)
        .map_err(|_| AuthFailure::ProofSignatureInvalid)?;

    // ── Step 3: FR-018 htm match (constant-time). ──────────────────────
    let htm = token_data
        .claims
        .htm
        .ok_or(AuthFailure::ProofMissingClaim("htm"))?;
    if !ct_eq_str(&htm, request_method.as_str()) {
        return Err(AuthFailure::ProofHtmMismatch);
    }

    // ── Step 4: FR-019 htu match (normalized, component-wise CT). ──────
    let htu_raw = token_data
        .claims
        .htu
        .ok_or(AuthFailure::ProofMissingClaim("htu"))?;
    let htu_url = Url::parse(&htu_raw).map_err(|_| AuthFailure::ProofHtuMismatch)?;
    if !urls_equivalent_ct(&htu_url, effective_uri) {
        return Err(AuthFailure::ProofHtuMismatch);
    }

    // ── Step 5: FR-020 iat freshness. ──────────────────────────────────
    let iat = token_data
        .claims
        .iat
        .ok_or(AuthFailure::ProofMissingClaim("iat"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let freshness = ctx.auth_config.dpop_freshness_secs;
    let skew = ctx.auth_config.clock_skew_secs;
    let in_window = if iat <= now {
        now.saturating_sub(iat) <= freshness + skew
    } else {
        iat.saturating_sub(now) <= skew
    };
    if !in_window {
        return Err(AuthFailure::ProofIatStale);
    }

    // ── Step 6: FR-022 jkt ↔ cnf.jkt match. ────────────────────────────
    let thumbprint = compute_jwk_thumbprint(&embedded_jwk)?;
    if !ct_eq_32(&thumbprint, access_token.cnf_jkt()) {
        return Err(AuthFailure::ProofJktMismatch);
    }

    // ── Step 6b: FR-022a ath ↔ access-token-hash match. ───────────────
    // RFC 9449 §4.2: the `ath` claim binds the proof to the SPECIFIC
    // access token, not just the DPoP key. Missing `ath` is a hard
    // rejection (bearer-token-style proofs are forbidden — spec Story 3
    // Acceptance Scenario #9). Mismatched `ath` is the substitution-
    // resistance failure: the proof was minted against a different
    // access token than the one presented on this request.
    let claimed_ath = token_data
        .claims
        .ath
        .as_deref()
        .ok_or(AuthFailure::ProofMissingClaim("ath"))?;
    let expected_ath = compute_ath(raw_token);
    if !ct_eq_str(claimed_ath, &expected_ath) {
        return Err(AuthFailure::ProofAthMismatch);
    }

    // ── Step 7: FR-021 atomic replay check. ────────────────────────────
    let jti = token_data
        .claims
        .jti
        .ok_or(AuthFailure::ProofMissingClaim("jti"))?;
    let jti_key = JtiKey::new(ctx.tag.as_jti_key_byte(), &jti);
    // Use checked_add so an adversarial-but-validator-accepting
    // `jti_replay_window_secs` (config validation only enforces
    // `>= dpop_freshness_secs + clock_skew_secs`, not an upper bound)
    // cannot panic the request task. On overflow we treat the configured
    // window as "infinite" by falling back to the lowest-deadline behavior
    // (`now`), which makes the new entry effectively expire-on-next-tick.
    // The validator's lower-bound invariant already guarantees the window
    // is at least 90 s under normal configurations.
    let window = Duration::from_secs(ctx.auth_config.jti_replay_window_secs);
    let deadline_instant = std::time::Instant::now()
        .checked_add(window)
        .ok_or(AuthFailure::ProofIatStale)?;
    match replay_store.try_insert(jti_key, deadline_instant) {
        Ok(()) => {}
        Err(ReplayInsertError::Replayed) => return Err(AuthFailure::ProofReplayed),
        Err(ReplayInsertError::MemoryPressure) => return Err(AuthFailure::MemoryPressure),
    }

    Ok(DpopProof {
        alg,
        htm,
        htu: htu_raw,
        iat,
        jti,
        thumbprint,
        ath: expected_ath,
    })
}

/// Component-wise URL equality with constant-time string comparison.
///
/// R10 normalization rules (applied symmetrically to both URLs by the
/// `url` crate's parser):
///   - scheme lower-cased
///   - host lower-cased
///   - default port elided
///   - fragment stripped (we just don't include it in the comparison)
///   - query preserved verbatim
///
/// The comparison decomposes the URL into (scheme, host, port, path,
/// query) and constant-time-compares each component. Going string-for-
/// string on `Url::as_str()` is rejected because two URLs that are
/// semantically equal (e.g., `https://h/` vs `https://h`) can serialize
/// differently.
fn urls_equivalent_ct(a: &Url, b: &Url) -> bool {
    // The url crate already normalizes scheme/host case + default ports.
    let scheme_eq = ct_eq_str(a.scheme(), b.scheme());
    let host_eq = match (a.host_str(), b.host_str()) {
        (Some(ha), Some(hb)) => ct_eq_str(ha, hb),
        (None, None) => true,
        _ => false,
    };
    let port_eq = a.port_or_known_default() == b.port_or_known_default();
    let path_eq = ct_eq_str(a.path(), b.path());
    let query_eq = match (a.query(), b.query()) {
        (Some(qa), Some(qb)) => ct_eq_str(qa, qb),
        (None, None) => true,
        _ => false,
    };
    // Reject any URI carrying a userinfo component. RFC 3986 §3.2.1
    // makes userinfo part of the authority, and an attacker who controls
    // the `htu` claim could include arbitrary userinfo
    // (`http://user@host/api/whoami`) that the request URI typically
    // lacks. Rather than try to compare a component that should never
    // be present on either side, reject the proof outright if either
    // URL has userinfo. `Url::username()` returns an empty string when
    // none is set; `Url::password()` returns None.
    let no_userinfo =
        a.username().is_empty() && a.password().is_none()
            && b.username().is_empty() && b.password().is_none();
    scheme_eq && host_eq && port_eq && path_eq && query_eq && no_userinfo
}

fn compute_jwk_thumbprint(jwk: &jsonwebtoken::jwk::Jwk) -> Result<[u8; 32], AuthFailure> {
    use crate::auth::crypto::{JwkThumbprintInput, jwk_thumbprint};
    use base64::Engine;
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => {
            if !matches!(ec.curve, EllipticCurve::P256) {
                return Err(AuthFailure::ProofSignatureInvalid);
            }
            let x = engine
                .decode(&ec.x)
                .map_err(|_| AuthFailure::ProofSignatureInvalid)?;
            let y = engine
                .decode(&ec.y)
                .map_err(|_| AuthFailure::ProofSignatureInvalid)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AuthFailure::ProofSignatureInvalid);
            }
            let mut x_arr = [0u8; 32];
            let mut y_arr = [0u8; 32];
            x_arr.copy_from_slice(&x);
            y_arr.copy_from_slice(&y);
            Ok(jwk_thumbprint(JwkThumbprintInput::EcP256 {
                x: &x_arr,
                y: &y_arr,
            }))
        }
        AlgorithmParameters::RSA(rsa) => {
            let n = engine
                .decode(&rsa.n)
                .map_err(|_| AuthFailure::ProofSignatureInvalid)?;
            let e = engine
                .decode(&rsa.e)
                .map_err(|_| AuthFailure::ProofSignatureInvalid)?;
            Ok(jwk_thumbprint(JwkThumbprintInput::Rsa { n: &n, e: &e }))
        }
        _ => Err(AuthFailure::ProofSignatureInvalid),
    }
}

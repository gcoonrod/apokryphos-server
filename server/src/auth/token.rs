//! Access-token validation (FR-010a, FR-011..FR-016, research R3).
//!
//! `validate_token` is the *only* constructor of `AccessToken`. It runs the
//! validation pipeline in exactly the order FR-011..FR-016 specifies:
//!
//!   1. **FR-010a alg allowlist** — pre-decode the JOSE header via
//!      `jsonwebtoken::decode_header`; if `alg ∉ {PS256, ES256}`, reject
//!      with `InvalidAlg` BEFORE any signature work runs.
//!   2. **FR-011 signature verify** — try each candidate key from the
//!      context's cached JWKS (kid-matched first, then keyless fallbacks).
//!      A signature failure SHOULD trigger an on-demand refresh per
//!      FR-004 — that path is stubbed here and wired up in T031 (US2).
//!   3. **FR-012 issuer match** — constant-time `iss == ctx.issuer_url`.
//!   4. **FR-013 audience match** — constant-time `aud == ctx.audience`.
//!   5. **FR-014 exp/nbf checks** — already done by jsonwebtoken's
//!      `Validation` with our `clock_skew_secs` leeway. We re-check
//!      `exp > now - leeway` explicitly so the failure category is
//!      cleanly attributable to FR-014.
//!   6. **FR-015 required-claims check** — `sub`, `aud`, `iss`, `exp`,
//!      `iat`, and `cnf.jkt` MUST all be present. `cnf.jkt` is the
//!      bearer-only rejection: a token without it cannot be DPoP-bound.
//!
//! All string comparisons (`iss`, `aud`) go through `auth::crypto::ct_eq_str`
//! per FR-016. `cnf.jkt` is parsed from its base64url form into `[u8; 32]`
//! once at validation time so the per-request DPoP `jkt` comparison
//! (FR-022, in `auth::dpop`) can use `ct_eq_32` against the raw bytes.

use std::time::SystemTime;

use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::auth::context::OidcContext;
use crate::auth::crypto::ct_eq_str;
use crate::auth::failure::AuthFailure;
use crate::auth::jwks::JwsAlg;

/// Validated access token. The only public constructor is
/// `validate_token`. Fields are `pub(crate)` so handlers can read `sub` /
/// `cnf_jkt` after the middleware completes; outside the crate, the
/// `VaultSubject` / `AdminSubject` wrappers are the only exposed handles.
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub(crate) sub: String,
    pub(crate) aud: String,
    pub(crate) iss: String,
    pub(crate) exp: u64,
    pub(crate) iat: u64,
    pub(crate) nbf: Option<u64>,
    /// SHA-256 thumbprint of the bound DPoP key, parsed from the
    /// `cnf.jkt` claim's base64url representation. 32 raw bytes,
    /// constant-time-compared against the proof's computed thumbprint
    /// (FR-022).
    pub(crate) cnf_jkt: [u8; 32],
}

impl AccessToken {
    pub fn sub(&self) -> &str {
        &self.sub
    }
    pub fn cnf_jkt(&self) -> &[u8; 32] {
        &self.cnf_jkt
    }
}

/// JWS claims as deserialized from the token payload. All required fields
/// are `Option` so a missing-claim error surfaces as the specific
/// `TokenMissingClaim(name)` variant (cleaner than a serde parse error).
#[derive(Deserialize)]
struct TokenClaims {
    sub: Option<String>,
    /// `aud` may be a string or array of strings in the JWT spec; FAPI 2.0
    /// + the FR-013 single-audience rule means we treat any array form as
    /// invalid. The middleware compares this string verbatim against
    /// the context's configured audience via constant-time equality.
    #[serde(default)]
    aud: Option<AudienceField>,
    iss: Option<String>,
    exp: Option<u64>,
    iat: Option<u64>,
    nbf: Option<u64>,
    #[serde(default)]
    cnf: Option<CnfClaim>,
}

/// Single-string audience only. The serde-untagged variant lets us accept
/// the most common provider form (`"aud": "value"`) and reject the array
/// form structurally.
#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceField {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Deserialize)]
struct CnfClaim {
    jkt: Option<String>,
}

/// Validate a raw JWS access token against the supplied OIDC context.
/// Returns the constructed `AccessToken` on success; `AuthFailure` on any
/// negative case (the caller's middleware translates each variant to the
/// uniform 401 via `auth::failure::respond_401`).
pub(crate) async fn validate_token(
    raw_jws: &str,
    ctx: &OidcContext,
) -> Result<AccessToken, AuthFailure> {
    // ── Step 1: FR-010a alg allowlist (FIRST gate). ─────────────────────
    let header = decode_header(raw_jws).map_err(|_| AuthFailure::InvalidAlg)?;
    let alg = match header.alg {
        Algorithm::PS256 => JwsAlg::Ps256,
        Algorithm::ES256 => JwsAlg::Es256,
        _ => return Err(AuthFailure::InvalidAlg),
    };

    // ── Step 2: FR-011 signature verify against cached JWKS. ────────────
    // The on-demand JWKS refresh hook (FR-004) is the only validation
    // step that's stubbed in US1; T031 (US2) wires it through `ctx`'s
    // `last_on_demand_refresh` rate limit + a single re-verify retry.
    // Until then a signature failure surfaces directly as InvalidSignature.
    let jwks = ctx.jwks.load_full();
    let candidates = jwks.lookup_candidates(header.kid.as_deref());
    if candidates.is_empty() {
        return Err(AuthFailure::TokenSignatureInvalid);
    }

    let mut validation = Validation::new(alg.to_jwt_algorithm());
    // Disable jsonwebtoken's exp/nbf/aud validation entirely; we run our
    // own constant-time iss/aud comparison (Steps 4/5) and a manual
    // exp/nbf check (Step 5a) AFTER iss/aud per the documented ordering
    // at the top of this file. This fixes two PR-review-cycle findings:
    //   1. With validate_exp = true, jsonwebtoken rejected expired
    //      tokens during decode — BEFORE the constant-time iss/aud
    //      check ran. The wire-level outcome was the uniform 401, but
    //      the log category was "auth.token.expired" even for a token
    //      with a wrong audience presented after expiry. Disabling here
    //      and re-checking later makes the category match the validation
    //      order documented in this module.
    //   2. With multiple candidate keys, the per-candidate loop below
    //      could overwrite a terminal claim error (Expired / NotYetValid /
    //      InvalidIssuer / InvalidAudience) with a later candidate's
    //      InvalidSignature, producing the wrong log category. We now
    //      break the loop on the FIRST candidate that decodes
    //      successfully, then run claim checks once on its decoded
    //      payload — there's no terminal-error overwrite path because
    //      claim checks happen outside the retry loop.
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.leeway = ctx.auth_config.clock_skew_secs;
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.set_audience::<&str>(&[]);

    let mut last_err = None;
    let token_data = (|| -> Option<jsonwebtoken::TokenData<TokenClaims>> {
        for candidate in &candidates {
            let decoding_key = match DecodingKey::from_jwk(candidate.jwk()) {
                Ok(k) => k,
                Err(_) => continue,
            };
            match decode::<TokenClaims>(raw_jws, &decoding_key, &validation) {
                Ok(td) => return Some(td),
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        None
    })();

    let data = match token_data {
        Some(d) => d,
        None => {
            // Map jsonwebtoken's terminal error to our auth-failure taxonomy.
            return Err(map_jwt_error(last_err));
        }
    };

    // ── Step 3: FR-015 required-claims check. ──────────────────────────
    let sub = data
        .claims
        .sub
        .ok_or(AuthFailure::TokenMissingClaim("sub"))?;
    let iss = data
        .claims
        .iss
        .ok_or(AuthFailure::TokenMissingClaim("iss"))?;
    let iat = data
        .claims
        .iat
        .ok_or(AuthFailure::TokenMissingClaim("iat"))?;
    let exp = data
        .claims
        .exp
        .ok_or(AuthFailure::TokenMissingClaim("exp"))?;
    let aud_field = data
        .claims
        .aud
        .ok_or(AuthFailure::TokenMissingClaim("aud"))?;
    let aud = match aud_field {
        AudienceField::Single(s) => s,
        AudienceField::Multiple(_) => {
            // FR-013 single-audience rule — JWT arrays not accepted.
            return Err(AuthFailure::TokenAudienceMismatch);
        }
    };
    let cnf = data
        .claims
        .cnf
        .ok_or(AuthFailure::TokenMissingClaim("cnf"))?;
    let cnf_jkt_b64 = cnf.jkt.ok_or(AuthFailure::TokenMissingClaim("cnf.jkt"))?;

    // ── Step 4: FR-012 issuer match (constant-time). ───────────────────
    if !ct_eq_str(&iss, ctx.issuer_url.as_str().trim_end_matches('/')) {
        return Err(AuthFailure::TokenIssuerMismatch);
    }

    // ── Step 5: FR-013 audience match (constant-time). ─────────────────
    if !ct_eq_str(&aud, ctx.audience.as_str()) {
        return Err(AuthFailure::TokenAudienceMismatch);
    }

    // ── Step 5a: FR-014 exp/nbf check (after iss/aud per the
    // documented ordering — see the validation-pipeline comment at the
    // top of this file). Disabled in `Validation` above so it runs
    // here, after the constant-time iss/aud comparisons rather than
    // inside jsonwebtoken's decode (which would have run BEFORE the
    // ct_eq_str checks and produced TokenExpired log categories for
    // tokens that also had iss/aud problems).
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let skew = ctx.auth_config.clock_skew_secs;
    if exp.saturating_add(skew) <= now_secs {
        return Err(AuthFailure::TokenExpired);
    }
    if let Some(nbf) = data.claims.nbf {
        if nbf > now_secs.saturating_add(skew) {
            return Err(AuthFailure::TokenNotYetValid);
        }
    }

    // ── Parse cnf.jkt to raw 32 bytes for FR-022 (DPoP-side). ──────────
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jkt_bytes = engine
        .decode(&cnf_jkt_b64)
        .map_err(|_| AuthFailure::TokenMissingClaim("cnf.jkt"))?;
    if jkt_bytes.len() != 32 {
        return Err(AuthFailure::TokenMissingClaim("cnf.jkt"));
    }
    let mut cnf_jkt = [0u8; 32];
    cnf_jkt.copy_from_slice(&jkt_bytes);

    Ok(AccessToken {
        sub,
        aud,
        iss,
        exp,
        iat,
        nbf: data.claims.nbf,
        cnf_jkt,
    })
}

/// Map jsonwebtoken's `ErrorKind` taxonomy to our auth-failure variants.
/// Most error kinds collapse to `TokenSignatureInvalid` (the generic
/// "we couldn't verify" outcome); a few have category-specific arms.
fn map_jwt_error(err: Option<jsonwebtoken::errors::Error>) -> AuthFailure {
    use jsonwebtoken::errors::ErrorKind;
    let Some(e) = err else {
        return AuthFailure::TokenSignatureInvalid;
    };
    match e.kind() {
        ErrorKind::ExpiredSignature => AuthFailure::TokenExpired,
        ErrorKind::ImmatureSignature => AuthFailure::TokenNotYetValid,
        ErrorKind::InvalidIssuer => AuthFailure::TokenIssuerMismatch,
        ErrorKind::InvalidAudience => AuthFailure::TokenAudienceMismatch,
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::InvalidKeyFormat => AuthFailure::InvalidAlg,
        _ => AuthFailure::TokenSignatureInvalid,
    }
}

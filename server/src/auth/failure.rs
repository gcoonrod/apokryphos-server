//! Auth-failure response generation + the `AuthFailure` taxonomy used internally.
//!
//! `respond_401` is the *only* function in the codebase that produces a 401
//! response on the auth-failure path. Every variant of `AuthFailure` (except
//! `MemoryPressure`) translates to the same byte-shape (FR-029, Clarify-Q3,
//! SC-002, SC-003). `respond_503_memory_pressure` mirrors for the FR-021
//! memory-pressure exit path that arises only when the in-process replay
//! store is at its configured budget.
//!
//! The `AuthFailure` enum is `pub(in crate::auth)` — never exported, never
//! serialized into a response body, never written into a `WWW-Authenticate`
//! header. Its only consumer is the FR-033 log-event helper which writes
//! the failure category name (not the variant data) to a `tracing::debug!`
//! event.

use std::net::IpAddr;

use axum::body::Body;
use axum::http::{Response, StatusCode, header};

/// The single fixed `WWW-Authenticate` value emitted on every 401 response,
/// regardless of failure cause. Per RFC 9449 §7 and Clarify-Q3, the value
/// advertises the challenge scheme (DPoP) and the permitted algorithms
/// (PS256, ES256 — both public per FR-010a). No `error`, `error_description`,
/// `realm`, or `scope` parameter MAY appear.
const WWW_AUTHENTICATE_VALUE: &str = r#"DPoP algs="PS256 ES256""#;

/// Categories of authentication failure, used internally for the FR-033 log
/// event's `category` field. NEVER serialized into a response.
///
/// The list is exhaustive against the FR-011..FR-023 + FR-010a check matrix.
/// Adding a variant requires updating `category()` below.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // variants are referenced only by future US1/US3 wiring
pub(in crate::auth) enum AuthFailure {
    MissingToken,
    MissingProof,
    InvalidAlg,
    TokenSignatureInvalid,
    TokenIssuerMismatch,
    TokenAudienceMismatch,
    TokenExpired,
    TokenNotYetValid,
    TokenMissingClaim(&'static str),
    ProofSignatureInvalid,
    ProofHtmMismatch,
    ProofHtuMismatch,
    ProofIatStale,
    ProofJktMismatch,
    ProofReplayed,
    ProofMissingClaim(&'static str),
    JwksRefreshFailed,
    /// Replay store at `max_replay_entries`. Distinct exit path from the
    /// other variants: translates to `respond_503_memory_pressure` rather
    /// than `respond_401`.
    MemoryPressure,
}

impl AuthFailure {
    /// Short category name for the structured-log `category` field.
    pub(in crate::auth) fn category(&self) -> &'static str {
        match self {
            Self::MissingToken => "auth.token.missing",
            Self::MissingProof => "auth.dpop.missing",
            Self::InvalidAlg => "auth.alg.disallowed",
            Self::TokenSignatureInvalid => "auth.token.bad_signature",
            Self::TokenIssuerMismatch => "auth.token.iss_mismatch",
            Self::TokenAudienceMismatch => "auth.token.aud_mismatch",
            Self::TokenExpired => "auth.token.expired",
            Self::TokenNotYetValid => "auth.token.nbf_future",
            Self::TokenMissingClaim(_) => "auth.token.missing_claim",
            Self::ProofSignatureInvalid => "auth.dpop.bad_signature",
            Self::ProofHtmMismatch => "auth.dpop.htm_mismatch",
            Self::ProofHtuMismatch => "auth.dpop.htu_mismatch",
            Self::ProofIatStale => "auth.dpop.iat_stale",
            Self::ProofJktMismatch => "auth.dpop.jkt_mismatch",
            Self::ProofReplayed => "auth.dpop.replayed",
            Self::ProofMissingClaim(_) => "auth.dpop.missing_claim",
            Self::JwksRefreshFailed => "auth.jwks.refresh_failed",
            Self::MemoryPressure => "auth.replay.memory_pressure",
        }
    }
}

/// Build the uniform 401 response. Every auth-failure cause (except
/// `MemoryPressure`) translates to byte-identical bytes here.
///
/// Headers (FR-029):
///   - `WWW-Authenticate: DPoP algs="PS256 ES256"` (fixed value)
///   - `Content-Length: 0`
/// Body: empty.
/// Forbidden: `Content-Type`, `Retry-After`, any error-detail header.
pub fn respond_401() -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, WWW_AUTHENTICATE_VALUE)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("static 401 response builder is infallible")
}

/// Emit a structured `DEBUG`-level tracing event for an authentication
/// failure (FR-033). Carries the category name and the effective client
/// address (as resolved by Phase 2's proxy-trust middleware) — NEVER the
/// raw token, raw proof, or `jti` value (FR-031, FR-032). Specific
/// `AuthFailure` claim-name payloads (`TokenMissingClaim(name)` etc.) are
/// flattened into the category string by `category()`; the offending
/// claim name itself is `&'static str` so logging it carries no
/// secret-bearing payload.
///
/// The `MAY` modality from FR-033 means operators can choose to filter
/// these out by running at `--log-level WARN` or higher; the events
/// remain useful at the default `INFO` level (which suppresses DEBUG)
/// only for active troubleshooting.
pub(in crate::auth) fn log_failure(failure: &AuthFailure, effective_address: IpAddr) {
    tracing::debug!(
        category = failure.category(),
        client = %effective_address,
        "auth.failure"
    );
}

/// Build the 503 memory-pressure response. Used when the `JtiReplayStore`
/// is at its configured `max_replay_entries` budget and cannot insert a
/// new `jti` without evicting an in-window entry (which FR-021 forbids).
///
/// Headers: `Content-Length: 0`. No `Retry-After` (would allow time
/// correlation across requests). No `Content-Type`.
/// Body: empty.
pub fn respond_503_memory_pressure() -> Response<Body> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("static 503 response builder is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn respond_401_has_fixed_shape() {
        let response = respond_401();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap(),
            r#"DPoP algs="PS256 ES256""#
        );
        assert_eq!(
            response.headers().get(header::CONTENT_LENGTH).unwrap(),
            "0"
        );
        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn respond_401_is_byte_identical_across_calls() {
        let a = respond_401();
        let b = respond_401();
        assert_eq!(a.status(), b.status());
        assert_eq!(
            a.headers().get(header::WWW_AUTHENTICATE),
            b.headers().get(header::WWW_AUTHENTICATE)
        );
        assert_eq!(
            a.headers().get(header::CONTENT_LENGTH),
            b.headers().get(header::CONTENT_LENGTH)
        );
        let a_body = to_bytes(a.into_body(), usize::MAX).await.unwrap();
        let b_body = to_bytes(b.into_body(), usize::MAX).await.unwrap();
        assert_eq!(a_body, b_body);
    }

    #[tokio::test]
    async fn respond_503_memory_pressure_has_fixed_shape() {
        let response = respond_503_memory_pressure();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::CONTENT_LENGTH).unwrap(),
            "0"
        );
        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        assert!(response.headers().get("retry-after").is_none());
    }

    #[test]
    fn auth_failure_categories_distinct_per_variant() {
        // Spot-check that variants map to distinct category strings (the
        // log subsystem's filterability depends on this). Two variants with
        // the same category would defeat FR-033's filterable taxonomy.
        let categories = [
            AuthFailure::MissingToken,
            AuthFailure::MissingProof,
            AuthFailure::InvalidAlg,
            AuthFailure::TokenSignatureInvalid,
            AuthFailure::TokenIssuerMismatch,
            AuthFailure::TokenAudienceMismatch,
            AuthFailure::TokenExpired,
            AuthFailure::TokenNotYetValid,
            AuthFailure::ProofSignatureInvalid,
            AuthFailure::ProofHtmMismatch,
            AuthFailure::ProofHtuMismatch,
            AuthFailure::ProofIatStale,
            AuthFailure::ProofJktMismatch,
            AuthFailure::ProofReplayed,
            AuthFailure::JwksRefreshFailed,
            AuthFailure::MemoryPressure,
        ]
        .iter()
        .map(|f| f.category())
        .collect::<Vec<_>>();

        let mut sorted = categories.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(categories.len(), sorted.len(), "duplicate category strings: {categories:?}");
    }
}

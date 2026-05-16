//! Per-route-group authentication middleware (FR-008..FR-010, research R9).
//!
//! Phase 3 US1 lands only `VaultGuard`; `AdminGuard` arrives in US2 (T032).
//! Both will be **structurally distinct types** so mixing them at router
//! construction is a compile error — research R9's "no ambient
//! current-audience state" promise.
//!
//! Each guard's `Service::call`:
//!   1. Reads `Authorization: DPoP <token>` (FR-009 first leg).
//!   2. Reads `DPoP: <proof>` (FR-009 second leg).
//!   3. Calls `validate_token` → `validate_proof` in that order.
//!   4. On success, inserts the audience-correct subject extension into
//!      request extensions and forwards to the inner service.
//!   5. On any `AuthFailure` (other than `MemoryPressure`) returns the
//!      byte-identical 401 from `auth::failure::respond_401`. On
//!      `MemoryPressure` returns the 503 from `respond_503_memory_pressure`.
//!
//! The effective request URI (for FR-019 `htu` matching) is built from
//! Phase 2's `EffectiveAddress` (proxy-resolved scheme/host) + the request
//! line's path-and-query.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::response::Response;
use tower::{Layer, Service};

use crate::auth::context::OidcContext;
use crate::auth::dpop::validate_proof;
use crate::auth::failure::{AuthFailure, log_failure, respond_401, respond_503_memory_pressure};
use crate::auth::replay::JtiReplayStore;
use crate::auth::subject::{VaultSubject, VaultSubjectExtension};
use crate::auth::token::validate_token;
use crate::proxy_trust::{EffectiveAddress, EffectiveScheme};

/// Vault-audience guard. Produced by `vault_guard(ctx, replay_store)`;
/// `Layer::layer(...)` wraps the inner service so every authenticated
/// request runs through the token + DPoP pipeline before reaching a
/// handler.
#[derive(Clone)]
pub struct VaultGuard {
    ctx: Arc<OidcContext>,
    replay: Arc<JtiReplayStore>,
}

/// Build a `VaultGuard` bound to the given context + replay store.
pub fn vault_guard(ctx: Arc<OidcContext>, replay: Arc<JtiReplayStore>) -> VaultGuard {
    VaultGuard { ctx, replay }
}

impl<S> Layer<S> for VaultGuard {
    type Service = VaultGuardService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        VaultGuardService {
            inner,
            ctx: Arc::clone(&self.ctx),
            replay: Arc::clone(&self.replay),
        }
    }
}

#[derive(Clone)]
pub struct VaultGuardService<S> {
    inner: S,
    ctx: Arc<OidcContext>,
    replay: Arc<JtiReplayStore>,
}

impl<S> Service<Request> for VaultGuardService<S>
where
    S: Service<Request, Response = Response, Error = std::convert::Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let ctx = Arc::clone(&self.ctx);
        let replay = Arc::clone(&self.replay);
        // Canonical tower "replace-with-clone" pattern. `poll_ready` was
        // driven on `self.inner`; that readiness is consumed by `call` and
        // belongs to *that* instance. We move the ready instance into the
        // future via `mem::replace`, leaving a fresh clone in `self.inner`
        // for the next `poll_ready`/`call` cycle. Simply cloning before
        // calling would invoke a clone whose readiness state is unknown —
        // a Service-contract violation for any non-always-ready inner.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            // Capture the effective client address up front; we need it
            // both for the success path (request extensions remain intact)
            // and for the failure log emission.
            let client_addr = request
                .extensions()
                .get::<EffectiveAddress>()
                .map(|e| e.addr)
                .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

            match authenticate_vault(&mut request, &ctx, &replay).await {
                Ok(subject) => {
                    request.extensions_mut().insert(VaultSubjectExtension(subject));
                    inner.call(request).await
                }
                Err(failure) => {
                    // FR-033: emit a category-bearing DEBUG event before
                    // collapsing to the uniform 401/503 response. The
                    // event carries the failure category + effective
                    // client address — never the raw token, proof,
                    // or jti (FR-031, FR-032).
                    log_failure(&failure, client_addr);
                    match failure {
                        AuthFailure::MemoryPressure => Ok(respond_503_memory_pressure()),
                        _ => Ok(respond_401()),
                    }
                }
            }
        })
    }
}

/// Extract the `Authorization` and `DPoP` headers, run the token + DPoP
/// pipeline, and return a `VaultSubject` on success.
async fn authenticate_vault(
    request: &mut Request,
    ctx: &OidcContext,
    replay: &JtiReplayStore,
) -> Result<VaultSubject, AuthFailure> {
    // ── Extract Authorization: DPoP <token> ─────────────────────────────
    // RFC 9110 §11.1: HTTP authentication scheme tokens are case-insensitive.
    // Split on the first ASCII space; compare the scheme via
    // `eq_ignore_ascii_case`. Handles all 32 ASCII-case combinations of
    // "DPoP" (`DPoP`, `dpop`, `DPOP`, `Dpop`, `dPoP`, …) in one branch.
    let auth_value = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(AuthFailure::MissingToken)?
        .to_str()
        .map_err(|_| AuthFailure::MissingToken)?;
    let (scheme, rest) = auth_value
        .split_once(' ')
        .ok_or(AuthFailure::MissingToken)?;
    if !scheme.eq_ignore_ascii_case("DPoP") {
        return Err(AuthFailure::MissingToken);
    }
    let raw_token = rest.trim();
    if raw_token.is_empty() {
        return Err(AuthFailure::MissingToken);
    }

    // ── Extract DPoP: <proof> ───────────────────────────────────────────
    let raw_proof = request
        .headers()
        .get("dpop")
        .ok_or(AuthFailure::MissingProof)?
        .to_str()
        .map_err(|_| AuthFailure::MissingProof)?
        .trim();
    if raw_proof.is_empty() {
        return Err(AuthFailure::MissingProof);
    }

    // ── Build effective request URI from Phase 2's EffectiveAddress ─────
    let effective_uri = build_effective_uri(request)?;

    // ── Token validation (FR-010a → FR-016) ─────────────────────────────
    let access_token = validate_token(raw_token, ctx).await?;

    // ── DPoP validation (FR-010a → FR-023) ──────────────────────────────
    let _proof = validate_proof(
        raw_proof,
        request.method(),
        &effective_uri,
        &access_token,
        ctx,
        replay,
    )
    .await?;

    Ok(VaultSubject::new(access_token.sub().to_string()))
}

/// Construct the effective request URI from Phase 2's resolved
/// `EffectiveAddress` plus the request's path+query. The effective
/// scheme comes from the proxy-trust middleware; the request's `Host`
/// header is consulted as a fallback for the authority.
fn build_effective_uri(request: &Request) -> Result<url::Url, AuthFailure> {
    let scheme = request
        .extensions()
        .get::<EffectiveAddress>()
        .map(|e| match e.scheme {
            EffectiveScheme::Https => "https",
            EffectiveScheme::Http => "http",
        })
        .unwrap_or("http");

    let authority = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| request.uri().authority().map(|a| a.as_str()))
        .ok_or(AuthFailure::ProofHtuMismatch)?;

    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let raw = format!("{}://{}{}", scheme, authority, path_and_query);
    url::Url::parse(&raw).map_err(|_| AuthFailure::ProofHtuMismatch)
}

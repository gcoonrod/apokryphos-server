//! Proxy-trust middleware (FR-007..010, invariants P1..P7).
//!
//! `resolve::resolve_effective_address` is the pure decision function; this
//! module wraps it in an axum middleware that reads the peer `SocketAddr`
//! (from `ConnectInfo` extension) and the `X-Forwarded-*` headers, then
//! inserts the computed `EffectiveAddress` into request extensions for
//! downstream handlers and the 404 fallback.

mod resolve;

pub use resolve::{EffectiveAddress, EffectiveScheme, resolve_effective_address};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::app::AppState;

/// Per-request middleware. Never short-circuits — every request flows on with
/// an `EffectiveAddress` attached to its extensions.
pub async fn middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // ConnectInfo<SocketAddr> is inserted by `into_make_service_with_connect_info`
    // in production. In tests driven via `tower::ServiceExt::oneshot` it may be
    // absent; the test can `request.extensions_mut().insert(ConnectInfo(sa))`
    // explicitly if it cares about the peer address.
    let peer_addr: IpAddr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(sa)| sa.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let xff = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let xfp = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let effective = resolve_effective_address(
        peer_addr,
        EffectiveScheme::Http, // direct peer scheme is HTTP — TLS termination is upstream (FR-026)
        &state.config.trusted_proxies,
        xff.as_deref(),
        xfp.as_deref(),
    );

    request.extensions_mut().insert(effective);
    next.run(request).await
}

//! T022: SC-004 — request from inside the trusted CIDR honors X-Forwarded-*.
//!
//! Builds a small router with `proxy_trust::middleware` and a debug echo
//! handler that returns the resolved `EffectiveAddress` as JSON. Drives via
//! `tower::ServiceExt::oneshot` with an explicit `ConnectInfo`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use apokryphos_server::AppState;
use apokryphos_server::config::{OidcAudienceConfig, ServerConfig, StorageBackend};
use apokryphos_server::proxy_trust::{self, EffectiveAddress};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::routing::get;
use tower::ServiceExt;

async fn echo_effective(Extension(e): Extension<EffectiveAddress>) -> String {
    format!("{}|{:?}", e.addr, e.scheme)
}

fn build_test_router(trusted: Vec<ipnet::IpNet>) -> Router {
    let cfg = ServerConfig {
        bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        block_size_bytes: 1,
        storage_backend: StorageBackend::None,
        trusted_proxies: trusted,
        vault_oidc: OidcAudienceConfig::new("vault", "https://x.invalid".into(), "v".into())
            .unwrap(),
        admin_oidc: OidcAudienceConfig::new("admin", "https://y.invalid".into(), "a".into())
            .unwrap(),
        drain_timeout: std::time::Duration::from_secs(30),
        auth: apokryphos_server::config::AuthConfig::default(),
    };
    let state = AppState {
        config: Arc::new(cfg),
    };
    Router::new()
        .route("/echo", get(echo_effective))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            proxy_trust::middleware,
        ))
        .with_state(state)
}

#[tokio::test]
async fn in_range_peer_honors_xff_and_xfp() {
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let router = build_test_router(trusted);

    let peer: SocketAddr = "10.0.0.5:54321".parse().unwrap();
    let req = Request::builder()
        .uri("/echo")
        .header("x-forwarded-for", "1.2.3.4")
        .header("x-forwarded-proto", "https")
        .extension(ConnectInfo(peer))
        .body(Body::empty())
        .unwrap();

    let res = router.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert_eq!(text, "1.2.3.4|Https");
}

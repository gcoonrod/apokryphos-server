//! Phase 3 / Phase 7 conformance harness — public helper API.
//!
//! This module re-exports the production-shape test helpers from
//! `apokryphos_server::auth::testing` plus a thin `TestServer` convenience
//! wrapper that owns the assembled router + the two `MockOidcProvider`s
//! for vault and admin audiences. The wrapper exposes mint helpers for
//! tokens and DPoP proofs against either audience so the smoke tests (and
//! Phase 7's full conformance matrix) can drive end-to-end scenarios
//! through the public API only — without reaching into `pub(crate)` or
//! `pub(in crate::auth)` internals. That isolation is deliberate: it locks
//! the surface area the conformance harness depends on, so Phase 3's
//! internal refactors don't ripple into Phase 7's test code.
//!
//! ## Helper API summary
//!
//! - `TestServer::start()` — boots two `MockOidcProvider`s with disjoint
//!   ES256 keypairs, initialises dual `OidcContext`s, and assembles the
//!   `/api/whoami` + `/admin/whoami` router. Returns the live server bound
//!   to a tower oneshot service. Drop the `TestServer` to abort the mocks.
//! - `TestServer::mint_vault_token(sub)` — vault-audience access token.
//! - `TestServer::mint_admin_token(sub)` — admin-audience access token.
//! - `TestServer::mint_dpop_proof(audience, token, htm, htu, jti)` —
//!   DPoP proof bound to `token` via `ath`.
//! - `TestServer::mint_dpop_proof_with_iat(...)` — same but allows
//!   overriding `iat` (for stale-iat negative cases).
//! - `TestServer::oneshot(request)` — drives one request through the
//!   assembled router and returns the `Response`.

#![allow(dead_code)] // smoke.rs only exercises a subset; Phase 7 covers the rest

use std::sync::Arc;

use apokryphos_server::AppState;
use apokryphos_server::auth::JtiReplayStore;
use apokryphos_server::auth::context::init_contexts;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::config::{
    AuthConfig, OidcAudienceConfig, ServerConfig, StorageBackend,
};
use apokryphos_server::routes::build_router;
use axum::body::Body;
use axum::http::{Request, Response};
use openidconnect::reqwest;
use std::net::SocketAddr;
use std::time::Duration;
use tower::ServiceExt;

/// Re-export the audience selector so smoke tests don't reach into the
/// server crate's internal module paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Vault,
    Admin,
}

const VAULT_KID: &str = "conformance-vault-key";
const ADMIN_KID: &str = "conformance-admin-key";
const VAULT_AUD: &str = "apokryphos-conformance-vault";
const ADMIN_AUD: &str = "apokryphos-conformance-admin";

/// Live test server: owns the assembled router and the two
/// `MockOidcProvider`s. Drop the value to abort the mock tasks.
pub struct TestServer {
    router: axum::Router,
    vault_signing: p256::ecdsa::SigningKey,
    admin_signing: p256::ecdsa::SigningKey,
    vault_issuer: url::Url,
    admin_issuer: url::Url,
    // Mocks held so background tasks stay alive for the test's duration.
    _vault_mock: MockOidcProvider,
    _admin_mock: MockOidcProvider,
}

impl TestServer {
    /// Boot the test server. Generates fresh ES256 keypairs per call, so
    /// independent test invocations do not share key material.
    pub async fn start() -> Self {
        // Deterministic seed per call → reproducible failures; the seed
        // chosen here is distinct from the seeds used by `server/tests/*`
        // so any one test's fixture is independent of the others.
        let mut rng = deterministic_rng(0xC0FE);
        let vault_signing = generate_es256_keypair(&mut rng);
        let admin_signing = generate_es256_keypair(&mut rng);

        let vault_jwks = serde_json::json!({
            "keys": [es256_public_jwk(vault_signing.verifying_key(), Some(VAULT_KID))]
        });
        let admin_jwks = serde_json::json!({
            "keys": [es256_public_jwk(admin_signing.verifying_key(), Some(ADMIN_KID))]
        });
        let vault_mock = MockOidcProvider::start(vault_jwks).await;
        let admin_mock = MockOidcProvider::start(admin_jwks).await;
        let vault_issuer = vault_mock.issuer_url();
        let admin_issuer = admin_mock.issuer_url();

        let cfg = ServerConfig {
            bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            block_size_bytes: 1024 * 1024,
            storage_backend: StorageBackend::None,
            trusted_proxies: vec![],
            vault_oidc: OidcAudienceConfig {
                issuer_url: vault_issuer.clone(),
                audience: VAULT_AUD.to_string(),
            },
            admin_oidc: OidcAudienceConfig {
                issuer_url: admin_issuer.clone(),
                audience: ADMIN_AUD.to_string(),
            },
            drain_timeout: Duration::from_secs(5),
            auth: AuthConfig::default(),
        };
        let http_client = reqwest::Client::new();
        let (vault_ctx, admin_ctx) = init_contexts(&cfg, &http_client)
            .await
            .expect("init_contexts must succeed against disjoint conformance mocks");

        let auth_cfg = Arc::new(cfg.auth.clone());
        let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

        let state = AppState {
            config: Arc::new(cfg.clone()),
        };
        let router =
            build_router(state, Some(vault_ctx), Some(admin_ctx), Some(replay_store));

        TestServer {
            router,
            vault_signing,
            admin_signing,
            vault_issuer,
            admin_issuer,
            _vault_mock: vault_mock,
            _admin_mock: admin_mock,
        }
    }

    /// Mint a vault-audience access token for `sub`.
    pub fn mint_vault_token(&self, sub: &str) -> String {
        self.mint_token(Audience::Vault, sub)
    }

    /// Mint an admin-audience access token for `sub`.
    pub fn mint_admin_token(&self, sub: &str) -> String {
        self.mint_token(Audience::Admin, sub)
    }

    fn mint_token(&self, audience: Audience, sub: &str) -> String {
        let (signing, kid, aud, issuer) = match audience {
            Audience::Vault => (
                &self.vault_signing,
                VAULT_KID,
                VAULT_AUD,
                &self.vault_issuer,
            ),
            Audience::Admin => (
                &self.admin_signing,
                ADMIN_KID,
                ADMIN_AUD,
                &self.admin_issuer,
            ),
        };
        let now = now_unix_secs();
        let claims = MintTokenClaims {
            sub: sub.to_string(),
            aud: aud.to_string(),
            iss: issuer.as_str().trim_end_matches('/').to_string(),
            iat: now,
            exp: now + 3600,
            nbf: None,
            cnf_jkt: es256_thumbprint_b64url(signing.verifying_key()),
        };
        mint_es256_token(&claims, signing, Some(kid), false)
    }

    /// Mint a DPoP proof bound to `token` via FR-022a `ath`, at the
    /// current wall-clock `iat`.
    pub fn mint_dpop_proof(
        &self,
        audience: Audience,
        token: &str,
        htm: &str,
        htu: &str,
        jti: &str,
    ) -> String {
        self.mint_dpop_proof_with_iat(audience, token, htm, htu, jti, now_unix_secs())
    }

    /// Mint a DPoP proof with an explicit `iat`. Used by negative tests
    /// that need a stale or future iat.
    pub fn mint_dpop_proof_with_iat(
        &self,
        audience: Audience,
        token: &str,
        htm: &str,
        htu: &str,
        jti: &str,
        iat: u64,
    ) -> String {
        let signing = match audience {
            Audience::Vault => &self.vault_signing,
            Audience::Admin => &self.admin_signing,
        };
        mint_es256_dpop_proof(signing, htm, htu, iat, jti, Some(token))
    }

    /// Drive a request through the assembled router. Returns the response.
    pub async fn oneshot(&self, request: Request<Body>) -> Response<Body> {
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("oneshot must complete")
    }
}

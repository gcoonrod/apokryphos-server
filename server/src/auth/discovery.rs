//! OIDC discovery document fetching + parsing (FR-001, FR-003a).
//!
//! Phase 2 / Phase 3 minimal: we fetch `<issuer>/.well-known/openid-configuration`
//! and extract ONLY `jwks_uri`. Per FR-003a + FR-012, the discovery document's
//! advertised `issuer` is NOT trusted — the configured `issuer_url` is the
//! source of truth for issuer matching at token-validation time.
//!
//! ## Implementation note: HTTP client choice
//!
//! Research R2 suggested `openidconnect::core::CoreProviderMetadata::discover_async`
//! for discovery. In implementation we use `reqwest` directly (re-exported via
//! `openidconnect::reqwest`) because openidconnect's type tree
//! (`CoreProviderMetadata`, `CoreJsonWebKeySet`) is parallel to `jsonwebtoken`'s
//! (`jsonwebtoken::jwk::Jwk`, `JwkSet`) — using the openidconnect parser would
//! force a type-translation step before signature verification. Going through
//! `reqwest` + `serde_json` deserializes once into the jsonwebtoken-compatible
//! representation. Deviation from R2 documented here; the dep surface is
//! unchanged because `reqwest` is reachable via `openidconnect`'s re-export.

use openidconnect::reqwest;
use serde::Deserialize;
use url::Url;

/// Suffix to append to the issuer URL per OIDC Discovery 1.0 §4.
///
/// Note the absence of a leading `/`. `url::Url::join` follows RFC 3986
/// §5.2.2: an absolute-path reference (one that starts with `/`) replaces
/// the entire path of the base. For a path-based issuer like
/// `https://idp.example/tenant`, joining `/.well-known/openid-configuration`
/// would silently drop the `/tenant` segment and fetch from the wrong
/// tenant. We therefore construct the discovery URL via explicit string
/// concatenation (trim trailing slash + append the well-known suffix)
/// and then re-parse, which preserves the issuer's full path.
const DISCOVERY_SUFFIX: &str = "/.well-known/openid-configuration";

/// Parsed OIDC discovery document. Only `jwks_uri` is retained; every other
/// field is intentionally discarded (FR-003a + FR-012).
#[derive(Debug, Clone)]
pub struct Discovery {
    pub jwks_uri: Url,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryFetchError {
    #[error("failed to build discovery URL from issuer {issuer:?}: {source}")]
    UrlBuild {
        issuer: String,
        #[source]
        source: url::ParseError,
    },
    #[error("HTTP fetch of discovery document failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("discovery endpoint returned non-2xx status: {0}")]
    BadStatus(u16),
    #[error("discovery document JSON parse failed: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("discovery document advertised jwks_uri {value:?} is not a valid URL: {source}")]
    JwksUriParse {
        value: String,
        #[source]
        source: url::ParseError,
    },
    #[error("discovery document advertised jwks_uri must use scheme \"https\" (got {scheme:?})")]
    JwksUriScheme { scheme: String },
}

/// Fetch the OIDC discovery document at `<issuer>/.well-known/openid-configuration`.
/// Returns the parsed `jwks_uri`. Per FR-003a, the document's `issuer` field
/// is NOT trusted; only `jwks_uri` is consumed.
///
/// Production: rejects `jwks_uri` whose scheme is not `https` (FAPI 2.0
/// TLS-everywhere). Test builds (`cfg(any(test, feature = "test-utils"))`)
/// accept HTTP for the in-process `MockOidcProvider` use case.
pub async fn fetch_discovery(
    http_client: &reqwest::Client,
    issuer_url: &Url,
) -> Result<Discovery, DiscoveryFetchError> {
    // Build the discovery URL by string concatenation rather than
    // `Url::join`. See `DISCOVERY_SUFFIX`'s doc comment for the
    // path-preservation rationale.
    let raw = format!(
        "{}{}",
        issuer_url.as_str().trim_end_matches('/'),
        DISCOVERY_SUFFIX
    );
    let discovery_url = Url::parse(&raw).map_err(|source| DiscoveryFetchError::UrlBuild {
        issuer: issuer_url.to_string(),
        source,
    })?;

    let response = http_client.get(discovery_url).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(DiscoveryFetchError::BadStatus(status.as_u16()));
    }
    let bytes = response.bytes().await?;
    let doc: DiscoveryDocument = serde_json::from_slice(&bytes)?;

    let jwks_uri =
        Url::parse(&doc.jwks_uri).map_err(|source| DiscoveryFetchError::JwksUriParse {
            value: doc.jwks_uri.clone(),
            source,
        })?;

    // FAPI 2.0 mandates TLS-everywhere. The HTTPS check is relaxed only
    // when test-utils is enabled AND we're in a debug build — so a
    // release binary built with `--features test-utils` (e.g., `cargo
    // build --release --all-features`) still enforces HTTPS. The
    // in-process MockOidcProvider runs in cfg(test) + cfg(debug_assertions)
    // contexts, so the test path remains usable.
    #[cfg(not(all(any(test, feature = "test-utils"), debug_assertions)))]
    if jwks_uri.scheme() != "https" {
        return Err(DiscoveryFetchError::JwksUriScheme {
            scheme: jwks_uri.scheme().to_string(),
        });
    }

    Ok(Discovery { jwks_uri })
}

/// T050: scheduled discovery refresh task. Spawned per `OidcContext`
/// by `app::run` (T048). On each tick, re-fetches the discovery
/// document and atomically swaps it via `ctx.discovery.store(...)`.
/// No overlap check is needed — the discovery doc carries only the
/// `jwks_uri`, not key material. Per FR-003a, a fetch failure does
/// NOT evict the cached document; the previous one keeps serving.
///
/// Like `jwks::scheduled_refresh_task`, the first immediate tick from
/// `tokio::time::interval` is consumed before the loop — the startup
/// fetch already populated `ctx.discovery`.
pub async fn scheduled_refresh_task(
    ctx: std::sync::Arc<crate::auth::context::OidcContext>,
    mut shutdown: crate::shutdown::ShutdownRx,
) {
    // Defensive early-exit (same rationale as jwks::scheduled_refresh_task):
    // a receiver cloned after the watch has flipped would otherwise
    // never observe `changed()`.
    if *shutdown.borrow() {
        return;
    }

    let dur = std::time::Duration::from_secs(ctx.auth_config.discovery_refresh_secs);
    let mut tick = tokio::time::interval(dur);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                match fetch_discovery(&ctx.http_client, &ctx.issuer_url).await {
                    Ok(new_discovery) => {
                        ctx.discovery.store(std::sync::Arc::new(new_discovery));
                    }
                    Err(_) => {
                        tracing::warn!(
                            event = "discovery.scheduled_refresh_failed",
                            audience = ctx.tag.name(),
                            "scheduled discovery refresh failed; cached document retained"
                        );
                    }
                }
            }
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: replicate the URL-construction logic from `fetch_discovery`
    /// so we can unit-test path preservation without spinning up an HTTP
    /// client.
    fn build_discovery_url(issuer: &str) -> Url {
        let issuer_url = Url::parse(issuer).unwrap();
        let raw = format!(
            "{}{}",
            issuer_url.as_str().trim_end_matches('/'),
            DISCOVERY_SUFFIX
        );
        Url::parse(&raw).unwrap()
    }

    #[test]
    fn discovery_url_appends_to_root_issuer() {
        assert_eq!(
            build_discovery_url("https://idp.example.invalid").as_str(),
            "https://idp.example.invalid/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_appends_to_root_issuer_with_trailing_slash() {
        assert_eq!(
            build_discovery_url("https://idp.example.invalid/").as_str(),
            "https://idp.example.invalid/.well-known/openid-configuration"
        );
    }

    /// Regression test for the path-drop bug surfaced in PR #4 review:
    /// `Url::join("/.well-known/openid-configuration")` would silently
    /// replace `/tenant` with `/.well-known/...`. The string-concat
    /// construction preserves the path.
    #[test]
    fn discovery_url_preserves_path_based_issuer() {
        assert_eq!(
            build_discovery_url("https://idp.example.invalid/tenant").as_str(),
            "https://idp.example.invalid/tenant/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_preserves_path_based_issuer_with_trailing_slash() {
        assert_eq!(
            build_discovery_url("https://idp.example.invalid/tenant/").as_str(),
            "https://idp.example.invalid/tenant/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_document_parses_minimal_json() {
        let json = br#"{"issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks.json","unrelated":"ignored"}"#;
        let doc: DiscoveryDocument = serde_json::from_slice(json).unwrap();
        assert_eq!(doc.jwks_uri, "https://idp.example/jwks.json");
    }
}

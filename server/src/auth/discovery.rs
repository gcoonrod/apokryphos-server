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

const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

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
    let discovery_url =
        issuer_url
            .join(DISCOVERY_PATH)
            .map_err(|source| DiscoveryFetchError::UrlBuild {
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

    #[cfg(not(any(test, feature = "test-utils")))]
    if jwks_uri.scheme() != "https" {
        return Err(DiscoveryFetchError::JwksUriScheme {
            scheme: jwks_uri.scheme().to_string(),
        });
    }

    Ok(Discovery { jwks_uri })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_join_appends_discovery_path() {
        let issuer = Url::parse("https://idp.example.invalid").unwrap();
        let joined = issuer.join(DISCOVERY_PATH).unwrap();
        assert_eq!(
            joined.as_str(),
            "https://idp.example.invalid/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_document_parses_minimal_json() {
        let json = br#"{"issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks.json","unrelated":"ignored"}"#;
        let doc: DiscoveryDocument = serde_json::from_slice(json).unwrap();
        assert_eq!(doc.jwks_uri, "https://idp.example/jwks.json");
    }
}

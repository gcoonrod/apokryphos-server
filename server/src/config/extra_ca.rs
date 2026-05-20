//! Optional extra-CA-certificate loading from `APOK_EXTRA_CA_CERT_FILE`.
//!
//! Operator-supplied private-CA certificate, loaded once at startup and
//! handed to the OIDC HTTP client via
//! `reqwest::ClientBuilder::add_root_certificate`. Required when the OIDC
//! issuer is fronted by a TLS terminator using a private CA (the homelab
//! `deploy/` reference uses Caddy's `tls internal` local CA). When unset,
//! the default Mozilla roots (webpki-roots) are sufficient.
//!
//! Lives in `config/` because this module is the sole owner of env-var
//! and filesystem access (see `mod.rs` doc-comment and FR-012). PEM
//! parsing is intentionally NOT done here; `reqwest::Certificate` is a
//! TLS-stack type that has no business leaking into `config::`.

use std::path::PathBuf;

/// Errors raised while reading `APOK_EXTRA_CA_CERT_FILE`.
#[derive(Debug, thiserror::Error)]
pub enum ExtraCaError {
    #[error("failed to read APOK_EXTRA_CA_CERT_FILE={path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Load PEM bytes from `APOK_EXTRA_CA_CERT_FILE` if set. Returns
/// `Ok(None)` when the env var is unset or empty — the caller treats
/// that as "use default trust roots only".
pub fn load_optional_pem() -> Result<Option<(PathBuf, Vec<u8>)>, ExtraCaError> {
    let Some(value) = std::env::var_os("APOK_EXTRA_CA_CERT_FILE") else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(value);
    let bytes = std::fs::read(&path).map_err(|source| ExtraCaError::Read {
        path: path.clone(),
        source,
    })?;
    Ok(Some((path, bytes)))
}

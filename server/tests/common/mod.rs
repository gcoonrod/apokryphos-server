//! Shared test helpers (R5, R6).
//!
//! `CapturingBuffer` lets tests capture `tracing` output into an in-memory
//! buffer without disturbing the global subscriber. `with_captured_logs`
//! installs a scoped subscriber for the closure's lifetime.
//!
//! `minimal_valid_config` returns a `ServerConfig` with known-distinct
//! audiences and an empty trusted_proxies list, suitable for any test that
//! needs to build a router or driver run() without re-deriving validation
//! rules in every test.

#![allow(dead_code)] // not every test file uses every helper

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apokryphos_server::config::{OidcAudienceConfig, ServerConfig, StorageBackend};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
pub struct CapturingBuffer(pub Arc<Mutex<Vec<u8>>>);

impl CapturingBuffer {
    pub fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

pub struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturingBuffer {
    type Writer = CapturingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CapturingWriter(self.0.clone())
    }
}

/// Run `f` with a scoped subscriber that captures every record into a buffer.
/// Returns `(captured_text, f's_return)`. The global subscriber is untouched.
pub fn with_captured_logs<F, R>(f: F) -> (String, R)
where
    F: FnOnce() -> R,
{
    let buffer = CapturingBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    (buffer.contents(), result)
}

/// Minimal known-valid `ServerConfig` for tests that don't care about specific
/// field values. Uses recognizable issuer URLs and audiences so SC-006-style
/// tests can assert these strings are absent from `/health` responses.
pub fn minimal_valid_config() -> ServerConfig {
    ServerConfig {
        bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        block_size_bytes: 1024 * 1024,
        storage_backend: StorageBackend::None,
        trusted_proxies: Vec::new(),
        vault_oidc: OidcAudienceConfig::new(
            "vault",
            "https://test-issuer.invalid/vault-7a4f".to_string(),
            "apokryphos-test-vault-7a4f".to_string(),
        )
        .expect("test fixture: vault OIDC config"),
        admin_oidc: OidcAudienceConfig::new(
            "admin",
            "https://test-issuer.invalid/admin-c8d2".to_string(),
            "apokryphos-test-admin-c8d2".to_string(),
        )
        .expect("test fixture: admin OIDC config"),
        drain_timeout: Duration::from_secs(30),
    }
}

/// Trait-like builder extension for short drain timeouts in shutdown tests.
pub trait ConfigBuilderExt {
    fn with_drain_timeout(self, timeout: Duration) -> Self;
}

impl ConfigBuilderExt for ServerConfig {
    fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }
}

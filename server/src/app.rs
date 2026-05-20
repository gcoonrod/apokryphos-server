//! Bootstrap-time state (`AppState`), error union (`AppError`), and the
//! `run()` entry point that drives the server through its lifecycle.
//!
//! Lifecycle (R3, R8, plan §"Bootstrap order"):
//!   1. config::load()
//!   2. bind listener
//!   3. emit server.started
//!   4. axum::serve runs until the shutdown future resolves
//!   5. drain remaining in-flight requests, bounded by `drain_timeout`
//!   6. emit server.shutdown.completed (exactly once across every terminal path)
//!
//! `AppState` lives here (not in `routes::`) so both `routes::` and
//! `proxy_trust::` can depend on `app::AppState` without a cycle.
//!
//! ## Drain-timeout semantics (correction to research.md R8)
//!
//! R8's code sketch wrapped the entire `axum::serve(...).with_graceful_shutdown`
//! future in `tokio::time::timeout(drain_timeout, ...)`. That is a bug: the
//! timeout would fire after `drain_timeout` seconds of *total uptime*, not
//! after `drain_timeout` seconds of *drain time*. A server with a 30 s drain
//! configuration would unexpectedly exit 30 s after startup with no signal.
//!
//! The fix here: only start the drain timer AFTER the caller's `shutdown`
//! future resolves. Until then, `axum::serve` runs indefinitely.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::config::{self, ConfigError, ServerConfig};
use crate::logging::events::{
    emit_server_shutdown_completed, emit_server_started, emit_storage_startup_failed,
    emit_storage_startup_ready,
};
use crate::routes;
use crate::shutdown;
use crate::storage::{self, StorageInitError};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("failed to bind listener at {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },

    #[error("failed to install signal handlers: {0}")]
    SignalSetup(#[source] io::Error),

    #[error("serve error during request handling: {0}")]
    Serve(#[source] io::Error),

    /// Phase 3 auth subsystem startup failure: discovery or JWKS fetch
    /// failed, JWKS was empty, or the two contexts' JWKS overlapped at
    /// startup (FR-002, FR-006). `auth::context::ContextInitError` has
    /// landed in this PR (T018) and is what `run()` produces, but the
    /// variant payload is `String` here so the call site `format!`s the
    /// typed error's `Display`-impl message instead of moving the error
    /// itself. T028 (US2, dual-context `init_contexts`) will switch to
    /// `ContextInitError` directly so the structured fields (e.g.,
    /// `JwksOverlap.context_with_extra_key`) can be inspected by callers
    /// — the `String` form is an interim type-erasure that loses field
    /// access in exchange for not requiring `ContextInitError` to be
    /// reachable from `app.rs` until the dual-context constructor lands.
    #[error("auth subsystem initialization failed: {0}")]
    Auth(String),

    /// Phase 4 storage subsystem startup failure: the configured block root
    /// is missing, not a directory, or not writable. The corresponding
    /// `storage.startup.failed` event has already been emitted at the point
    /// where this variant is constructed (see `run`).
    #[error("storage subsystem initialization failed: {0}")]
    Storage(#[from] StorageInitError),
}

/// Production entry point. Returns `Err` for config-load / bind / serve
/// failures; the caller (`main`) translates to an `ExitCode`.
///
/// Phase 3 US2 bootstrap order:
///   1. `config::load()` — Phase 2.
///   2. `auth::init_contexts(&cfg, &http_client)` — fetch discovery +
///      JWKS for both audiences, run FR-006 startup disjointness check,
///      wire the Weak cross-reach. FR-002 / FR-006 startup failures
///      propagate as `AppError::Auth` (mapped to non-zero exit by main).
///   3. Construct `Arc<JtiReplayStore>` from the validated `AuthConfig`.
///   4. Bind listener (Phase 2).
///   5. `emit_server_started` (Phase 2).
///   6. `routes::build_router(state, Some(vault_ctx), Some(admin_ctx), Some(replay_store))`.
///   7. Serve with graceful drain (Phase 2).
///
/// US4 (T048-T051) will spawn the four scheduled refresh tasks
/// (JWKS×2 + discovery×2) and the replay-store cleanup task between
/// steps 2 and 4.
pub async fn run() -> Result<(), AppError> {
    let cfg = config::load()?;
    let bind_addr = cfg.bind_address;
    let drain_timeout = cfg.drain_timeout;

    // Phase 3 US1 vault-context init (FR-002, FR-006).
    //
    // The startup OIDC fetches (discovery + JWKS) MUST fail fast rather
    // than hang the binary. `reqwest::Client::new()` imposes no
    // request/read timeout — only an OS connect timeout — so a stalling
    // issuer would block `run()` before `bind` and `emit_server_started`.
    // We build the client with an explicit 30-second total request
    // timeout. A follow-on task can promote this to an `AuthConfig`
    // knob (e.g. `oidc_http_timeout_secs`) when configurability
    // matters; for now 30s is a defensive default that catches
    // pathological providers without breaking sane ones.
    let auth_cfg = Arc::new(cfg.auth.clone());
    // Build the OIDC HTTP client with two production defences:
    //   1. `timeout(30s)` — a stalling issuer cannot hang `run()` before
    //      bind + emit_server_started (PR #4 review-cycle Round 1).
    //   2. `redirect(Policy::none())` — reqwest's default policy is
    //      `Policy::limited(10)`, which silently follows 3xx redirects.
    //      An HTTPS discovery or `jwks_uri` could redirect to `http://`
    //      and bypass the scheme check that runs against the *original*
    //      URL. Disabling redirects entirely is the simplest defence:
    //      a legitimate OIDC provider should not be issuing redirects
    //      from these endpoints in the first place.
    let mut http_client_builder = openidconnect::reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(openidconnect::reqwest::redirect::Policy::none());

    // Operator-supplied extra root CA. Required when the OIDC issuer is
    // fronted by a TLS terminator using a private CA (e.g. the homelab
    // `deploy/` reference uses Caddy's `tls internal`). The default rustls
    // trust store baked into reqwest (via webpki-roots) is a static Mozilla
    // root bundle that ignores SSL_CERT_FILE and the system trust store,
    // so a private-CA chain has to be loaded explicitly here. Unset →
    // default Mozilla roots, suitable for any publicly-trusted issuer.
    if let Some(path) = std::env::var_os("APOK_EXTRA_CA_CERT_FILE") {
        let pem = std::fs::read(&path).map_err(|e| {
            AppError::Auth(format!(
                "failed to read APOK_EXTRA_CA_CERT_FILE={}: {e}",
                std::path::Path::new(&path).display()
            ))
        })?;
        let cert = openidconnect::reqwest::Certificate::from_pem(&pem).map_err(|e| {
            AppError::Auth(format!(
                "failed to parse APOK_EXTRA_CA_CERT_FILE={} as PEM: {e}",
                std::path::Path::new(&path).display()
            ))
        })?;
        http_client_builder = http_client_builder.add_root_certificate(cert);
        tracing::info!(
            path = %std::path::Path::new(&path).display(),
            "OIDC HTTP client trust: added extra root CA"
        );
    }

    let http_client = http_client_builder
        .build()
        .map_err(|e| AppError::Auth(format!("failed to build OIDC HTTP client: {e}")))?;
    let (vault_ctx, admin_ctx) = crate::auth::context::init_contexts(&cfg, &http_client)
        .await
        .map_err(|e| AppError::Auth(e.to_string()))?;

    // Phase 4 storage init (FR-011, plan.md §"Bootstrap order" step 5).
    // Failure here exits before bind with a structured `storage.startup.failed`
    // event. Success emits `storage.startup.ready` before the auth-task spawn
    // and the `server.started` event below. Returns Option: None means the
    // operator selected `storage_backend = "none"` (Phase 2/3 fixtures) and
    // block routes are not mounted.
    let storage_provider = match storage::init_from_config(&cfg).await {
        Ok(opt) => {
            if let crate::config::StorageBackend::LocalFs { root } = &cfg.storage_backend {
                emit_storage_startup_ready(&root.display().to_string());
            }
            opt
        }
        Err(e) => {
            emit_storage_startup_failed(&e.root_path().display().to_string(), e.step(), e.cause());
            return Err(AppError::Storage(e));
        }
    };

    let replay_store = Arc::new(crate::auth::JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let state = AppState {
        config: Arc::new(cfg),
    };

    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|source| AppError::Bind {
            addr: bind_addr,
            source,
        })?;
    let local_addr = listener.local_addr().map_err(|source| AppError::Bind {
        addr: bind_addr,
        source,
    })?;

    // Install signal handlers *before* announcing readiness, so a signal
    // arriving immediately after bind cannot fall through to the default
    // termination disposition while axum is still setting up its serve loop.
    let signals = shutdown::install_signals().map_err(AppError::SignalSetup)?;
    let (shutdown_fut, shutdown_rx) = shutdown::shutdown_coordinator(signals, drain_timeout);

    // T048: spawn the four scheduled refresh tasks + replay-store
    // cleanup before announcing readiness. Each clones the watch
    // receiver and breaks out of its loop when the watch flips to
    // `true` (the shutdown_fut above sends it). The task handles are
    // detached — we rely on the watch + the drain-timeout backstop
    // for graceful termination; aborting on serve-exit is unnecessary
    // because the watch already prompts a clean break, and a task
    // that misses the watch wakeup is still cancelled when the runtime
    // shuts down.
    let _vault_jwks_task = tokio::spawn(crate::auth::jwks::scheduled_refresh_task(
        Arc::clone(&vault_ctx),
        shutdown_rx.clone(),
    ));
    let _admin_jwks_task = tokio::spawn(crate::auth::jwks::scheduled_refresh_task(
        Arc::clone(&admin_ctx),
        shutdown_rx.clone(),
    ));
    let _vault_discovery_task = tokio::spawn(crate::auth::discovery::scheduled_refresh_task(
        Arc::clone(&vault_ctx),
        shutdown_rx.clone(),
    ));
    let _admin_discovery_task = tokio::spawn(crate::auth::discovery::scheduled_refresh_task(
        Arc::clone(&admin_ctx),
        shutdown_rx.clone(),
    ));
    let _replay_cleanup_task = tokio::spawn(crate::auth::replay::cleanup_task(
        Arc::clone(&replay_store),
        shutdown_rx,
    ));

    emit_server_started(local_addr);

    let router = routes::build_router(
        state,
        Some(Arc::clone(&vault_ctx)),
        Some(Arc::clone(&admin_ctx)),
        Some(Arc::clone(&replay_store)),
        storage_provider,
    );
    serve_with_shutdown(listener, router, shutdown_fut, drain_timeout).await
}

/// Drive `axum::serve` with a caller-supplied shutdown future and a wall-clock
/// drain timeout. Emits `server.shutdown.completed` exactly once across every
/// terminal path (clean drain, forced timeout, mid-serve error). Invariant A6.
///
/// The drain timer is armed **only after `shutdown` resolves**, not at the
/// start of serving — see the module docstring for the bug this prevents.
///
/// Public (gated on `test-utils`) so integration tests can drive shutdown
/// with a test channel rather than real OS signals.
#[cfg(any(test, feature = "test-utils"))]
pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    router: axum::Router,
    shutdown: F,
    drain_timeout: Duration,
) -> Result<(), AppError>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with_shutdown_inner(listener, router, shutdown, drain_timeout).await
}

#[cfg(not(any(test, feature = "test-utils")))]
async fn serve_with_shutdown<F>(
    listener: TcpListener,
    router: axum::Router,
    shutdown: F,
    drain_timeout: Duration,
) -> Result<(), AppError>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with_shutdown_inner(listener, router, shutdown, drain_timeout).await
}

async fn serve_with_shutdown_inner<F>(
    listener: TcpListener,
    router: axum::Router,
    shutdown: F,
    drain_timeout: Duration,
) -> Result<(), AppError>
where
    F: Future<Output = ()> + Send + 'static,
{
    // Wrap the caller's shutdown future so we get a notification the moment
    // it resolves. axum's `with_graceful_shutdown` consumes the future; we
    // also need to know when it fired so we can start the drain timer.
    let (drain_start_tx, drain_start_rx) = oneshot::channel::<()>();
    let shutdown_with_notify = async move {
        shutdown.await;
        // If receiver was dropped (we already exited), nothing to do.
        let _ = drain_start_tx.send(());
    };

    use std::future::IntoFuture;
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    let serve_fut = axum::serve(listener, make_service)
        .with_graceful_shutdown(shutdown_with_notify)
        .into_future();
    tokio::pin!(serve_fut);

    // Phase 1: serve indefinitely until either the shutdown signal fires
    // OR axum::serve itself terminates (which shouldn't happen without a
    // signal — listener-level errors fall into the Err branch).
    tokio::select! {
        result = &mut serve_fut => {
            // axum::serve completed before shutdown was triggered.
            return match result {
                Ok(()) => {
                    emit_server_shutdown_completed(true);
                    Ok(())
                }
                Err(e) => {
                    emit_server_shutdown_completed(false);
                    Err(AppError::Serve(e))
                }
            };
        }
        _ = drain_start_rx => {
            // Shutdown future resolved (emit_server_shutdown_initiated already
            // fired inside the listener helper). Fall through to phase 2.
        }
    }

    // Phase 2: drain in-flight requests, bounded by `drain_timeout`.
    match tokio::time::timeout(drain_timeout, &mut serve_fut).await {
        Ok(Ok(())) => {
            emit_server_shutdown_completed(true);
            Ok(())
        }
        Ok(Err(e)) => {
            emit_server_shutdown_completed(false);
            Err(AppError::Serve(e))
        }
        Err(_elapsed) => {
            // FR-017: forced close is still a clean process exit.
            emit_server_shutdown_completed(false);
            Ok(())
        }
    }
}

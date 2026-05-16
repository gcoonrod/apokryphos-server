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
use crate::logging::events::{emit_server_shutdown_completed, emit_server_started};
use crate::routes;
use crate::shutdown;

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

    #[error("serve error during request handling: {0}")]
    Serve(#[source] io::Error),
}

/// Production entry point. Returns `Err` for config-load / bind / serve
/// failures; the caller (`main`) translates to an `ExitCode`.
pub async fn run() -> Result<(), AppError> {
    let cfg = config::load()?;
    let bind_addr = cfg.bind_address;
    let drain_timeout = cfg.drain_timeout;
    let state = AppState {
        config: Arc::new(cfg),
    };

    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|source| AppError::Bind { addr: bind_addr, source })?;
    let local_addr = listener.local_addr().map_err(|source| AppError::Bind {
        addr: bind_addr,
        source,
    })?;

    emit_server_started(local_addr);

    let router = routes::build_router(state);
    serve_with_shutdown(
        listener,
        router,
        shutdown::signal_listener_for_signals(drain_timeout),
        drain_timeout,
    )
    .await
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

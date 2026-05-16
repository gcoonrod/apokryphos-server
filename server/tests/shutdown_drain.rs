//! T032-T034: SC-008, FR-017, FR-018 — graceful drain semantics.
//!
//! Drives `app::serve_with_shutdown` (test-utils gated) so the tests can
//! supply a short drain timeout without going through `config::load`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use apokryphos_server::serve_with_shutdown;
use apokryphos_server::AppState;
use axum::routing::get;
use axum::Router;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::common::minimal_valid_config;

async fn bind_ephemeral() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.expect("ephemeral bind")
}

#[allow(dead_code)]
fn empty_state() -> AppState {
    AppState {
        config: Arc::new(minimal_valid_config()),
    }
}

/// T032: SC-008 happy path — shutdown signal fires, no in-flight requests,
/// drain completes well inside the timeout window.
#[tokio::test]
async fn drain_completes_in_window() {
    let listener = bind_ephemeral().await;
    let (tx, rx) = oneshot::channel();
    let router: Router = Router::new().route("/", get(|| async { "ok" }));
    let shutdown_fut = async move {
        let _ = rx.await;
    };

    // Fire the shutdown trigger after a brief delay so serve has time to start.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = tx.send(());
    });

    let start = std::time::Instant::now();
    let result = serve_with_shutdown(listener, router, shutdown_fut, Duration::from_secs(2)).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "expected Ok, got {result:?}");
    assert!(
        elapsed < Duration::from_secs(1),
        "drain should not have hit the timeout, took {elapsed:?}"
    );
}

/// T033: FR-017 — drain timeout exceeded because a request handler runs
/// longer than the drain window. The server force-closes at the deadline
/// and the outer Result is still `Ok` (forced close is not an error per
/// FR-017).
///
/// Sequencing (no wall-clock grace periods; everything is event-driven):
///   1. Spawn `serve_with_shutdown` as a task.
///   2. Connect a client via retry-connect (handles the bind race without a
///      fixed sleep). Write a full `/slow` request.
///   3. The `/slow` handler notifies an `entered` channel *before* sleeping,
///      so the test knows the request is provably in-flight when shutdown
///      fires — no 150 ms guess about request dispatch latency.
///   4. Fire shutdown; start the elapsed timer here ("drain time", not
///      "uptime").
///   5. Await the server task. Assert elapsed ≥ drain_timeout (the slow
///      handler held drain open until the deadline) and ≤ 2 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_timeout_exceeded_returns_ok_with_drained_cleanly_false() {
    let listener = bind_ephemeral().await;
    let local_addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let drain_timeout = Duration::from_millis(200);

    // Handler-entry signal: the `/slow` handler fires this before sleeping,
    // so the test can wait for proof of in-flight status without guessing.
    let entered = Arc::new(tokio::sync::Notify::new());
    let entered_handler = Arc::clone(&entered);

    let router: Router = Router::new().route(
        "/slow",
        get(move || {
            let notify = Arc::clone(&entered_handler);
            async move {
                notify.notify_one();
                tokio::time::sleep(Duration::from_secs(10)).await;
                "done"
            }
        }),
    );
    let shutdown_fut = async move {
        let _ = shutdown_rx.await;
    };

    // (1) Start the server in a task.
    let server_handle =
        tokio::spawn(serve_with_shutdown(listener, router, shutdown_fut, drain_timeout));

    // (2) Connect with retry so we don't race the bind, then write the request.
    let client_handle = tokio::spawn(async move {
        let mut stream = loop {
            match TcpStream::connect(local_addr).await {
                Ok(s) => break s,
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        };
        let _ = stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        let _ = stream.flush().await;
        // Block reading until the server force-closes.
        let mut buf = [0u8; 64];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    });

    // (3) Wait until the handler has provably been entered.
    entered.notified().await;

    // (4) Fire shutdown — START the timer here.
    let shutdown_start = std::time::Instant::now();
    let _ = shutdown_tx.send(());

    // (5) Wait for the server.
    let result = server_handle.await.expect("server task panicked");
    let drain_elapsed = shutdown_start.elapsed();

    let _ = client_handle.await;

    assert!(
        result.is_ok(),
        "forced timeout must still return Ok (FR-017): {result:?}"
    );
    // The slow handler's sleep is 10 s; drain timeout is 200 ms. Real drain
    // time should be ~drain_timeout. Allow 50 ms slack for scheduling noise.
    assert!(
        drain_elapsed >= drain_timeout.saturating_sub(Duration::from_millis(50)),
        "drain returned before timeout elapsed (took {drain_elapsed:?})"
    );
    assert!(
        drain_elapsed < Duration::from_secs(2),
        "drain took far too long: {drain_elapsed:?}"
    );
}

/// T034: FR-018 — shutdown trigger that arrives before any request still
/// exits cleanly without entering an extended drain.
#[tokio::test]
async fn signal_before_traffic_exits_cleanly() {
    let listener = bind_ephemeral().await;
    let (tx, rx) = oneshot::channel();
    let router: Router = Router::new().route("/", get(|| async { "ok" }));
    let shutdown_fut = async move {
        let _ = rx.await;
    };
    tx.send(()).unwrap();

    let start = std::time::Instant::now();
    let result =
        serve_with_shutdown(listener, router, shutdown_fut, Duration::from_secs(5)).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok());
    assert!(
        elapsed < Duration::from_secs(1),
        "should exit immediately, took {elapsed:?}"
    );
}

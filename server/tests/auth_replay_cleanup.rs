//! T047 — replay-store cleanup correctness (research R7, validate-plan G3).
//!
//! Two complementary assertions:
//!
//!   1. **Cleanup actually removes**: insert N entries with staggered
//!      deadlines, advance time past the last deadline, call
//!      `maintenance_tick`. Afterwards `len() == 0` AND re-inserting any
//!      of the original jtis returns `Ok(())`. That second check is the
//!      load-bearing one — if `maintenance_tick` only dropped the
//!      entries from `expiry_queue` but left them in `entries`, a
//!      re-insert would return `Replayed` and the test would fail.
//!
//!   2. **Cleanup is not implicit**: without calling `maintenance_tick`,
//!      advancing time alone MUST NOT cause entries to silently
//!      disappear. The constitution's no-side-channel principle plus
//!      FR-021's no-eviction guarantee both rely on this.
//!
//! Uses `tokio::time::pause()` so the test is deterministic and runs
//! in milliseconds.

use std::sync::Arc;
use std::time::Duration;

use apokryphos_server::auth::{AudienceTag, JtiKey, JtiReplayStore, ReplayInsertError};
use apokryphos_server::config::AuthConfig;
use tokio::time::Instant;

const N: usize = 100;
const VAULT_TAG: u8 = 1; // mirrors AudienceTag::Vault::as_jti_key_byte()

fn jti_keys(prefix: &str) -> Vec<(String, JtiKey)> {
    (0..N)
        .map(|i| {
            let raw = format!("{prefix}-{i:03}");
            let key = JtiKey::new(AudienceTag::Vault.as_jti_key_byte(), &raw);
            (raw, key)
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn maintenance_tick_removes_expired_and_allows_reinsertion() {
    let mut auth = AuthConfig::default();
    auth.max_replay_entries = 1000; // headroom over N
    let store = JtiReplayStore::new(Arc::new(auth));

    let keys = jti_keys("cleanup-positive");

    // Insert N entries with deadlines staggered 1ms apart starting at
    // `now + 1ms`. Last deadline is `now + N*1ms = now + 100ms`.
    let base = Instant::now();
    for (i, (_, key)) in keys.iter().enumerate() {
        let deadline = base + Duration::from_millis((i as u64) + 1);
        store
            .try_insert(*key, deadline.into_std())
            .expect("insert must succeed below budget");
    }
    assert_eq!(store.len(), N);

    // Advance past the last deadline.
    tokio::time::advance(Duration::from_millis((N as u64) + 10)).await;
    store.maintenance_tick(Instant::now().into_std());
    let _ = VAULT_TAG; // (named constant kept for inline doc clarity)

    // Both checks: the lazy count AND a true round-trip insert.
    assert_eq!(store.len(), 0, "len() must drop to zero after cleanup");
    let post_cleanup_deadline = Instant::now() + Duration::from_secs(60);
    for (raw, key) in &keys {
        match store.try_insert(*key, post_cleanup_deadline.into_std()) {
            Ok(()) => {} // expected
            Err(e) => panic!(
                "after maintenance_tick, jti {raw} should re-insert cleanly; got {e}"
            ),
        }
    }
    assert_eq!(
        store.len(),
        N,
        "after re-insertion, the store should hold all N keys again"
    );
}

#[tokio::test(start_paused = true)]
async fn entries_are_not_silently_evicted_when_maintenance_is_not_called() {
    let mut auth = AuthConfig::default();
    auth.max_replay_entries = 1000;
    let store = JtiReplayStore::new(Arc::new(auth));

    let keys = jti_keys("cleanup-negative");

    let base = Instant::now();
    for (i, (_, key)) in keys.iter().enumerate() {
        let deadline = base + Duration::from_millis((i as u64) + 1);
        store
            .try_insert(*key, deadline.into_std())
            .expect("insert must succeed below budget");
    }

    // Advance time past every deadline — but DO NOT call maintenance_tick.
    // The entries should remain present; FR-021 forbids implicit eviction.
    tokio::time::advance(Duration::from_millis((N as u64) + 10)).await;

    assert_eq!(store.len(), N, "len() must NOT change without maintenance_tick");
    // Re-inserting any of the original jtis must still report Replayed,
    // proving the entries are physically present in `entries`.
    let any_future_deadline = Instant::now() + Duration::from_secs(60);
    for (raw, key) in &keys {
        match store.try_insert(*key, any_future_deadline.into_std()) {
            Err(ReplayInsertError::Replayed) => {} // expected
            Err(other) => panic!("expected Replayed for {raw}, got {other}"),
            Ok(()) => panic!(
                "{raw} was silently evicted without maintenance_tick — FR-021 violation"
            ),
        }
    }
}

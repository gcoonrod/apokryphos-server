//! In-process DPoP `jti` replay store (FR-021, research R7).
//!
//! Detects DPoP-proof replay within the configured replay window. Two
//! synchronized structures:
//!
//!   - `entries: Mutex<HashMap<JtiKey, Instant>>` — primary store. The key
//!     is `(audience_tag, sha256(jti))` so cross-audience replay is
//!     structurally impossible regardless of `jti` collisions.
//!   - `expiry_queue: Mutex<BinaryHeap<Reverse<(Instant, JtiKey)>>>` —
//!     min-heap by deadline for O(log n) cleanup.
//!
//! ## Statelessness deviation (constitution Principle III)
//!
//! The store is in-process only. Loss-on-restart shortens the effective
//! replay window by at most one restart's worth of recent proofs, all of
//! which are within design-margin freshness. Multi-instance operation is
//! NOT the supported topology in this phase; a follow-on phase will adopt
//! either a stateless DPoP variant or a shared replay store. See plan.md
//! Complexity Tracking row 9.
//!
//! ## Memory pressure (FR-021 absolute prohibition)
//!
//! `try_insert` always takes the `entries` lock first and checks for a
//! replay BEFORE checking memory pressure. This ordering is load-bearing:
//! a `jti` that has already been seen MUST be rejected with `Replayed`
//! regardless of whether the store is at capacity. Only NEW (previously-
//! unseen) keys are subject to the memory-pressure check; if they arrive
//! while `entries.len() >= config.max_replay_entries`, `try_insert` returns
//! `MemoryPressure` and the middleware translates to a 503 (no body) per
//! `auth::failure::respond_503_memory_pressure`. The 503 makes the
//! operator's monitoring see a degraded service rather than silently
//! granting an attacker a free replay window via eviction.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::config::AuthConfig;

/// Composite key for the replay store: `audience_tag` (1 byte) + SHA-256
/// hash of the raw `jti` (32 bytes). Audience tag goes first so that
/// cross-audience replay is structurally impossible regardless of `jti`
/// collisions across audiences.
///
/// `jti` is hashed (rather than stored raw) so the per-entry memory budget
/// is bounded at 33 bytes plus the `Instant` deadline regardless of how
/// long client `jti` values get. SHA-256 collisions across distinct `jti`s
/// are computationally infeasible, so FR-021's uniqueness guarantee holds.
///
/// Visibility: `pub` because `JtiReplayStore::try_insert` exposes it on
/// its signature. The opaque shape (no public field constructor, no
/// public method other than `new`) prevents external code from
/// fabricating arbitrary `JtiKey` values; only `JtiKey::new(audience_tag,
/// raw_jti)` is reachable.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Copy, Clone, Debug)]
pub struct JtiKey {
    audience: u8,
    jti_hash: [u8; 32],
}

impl JtiKey {
    /// Build a key from raw bytes. `audience_tag` is `0x01` for Vault and
    /// `0x02` for Admin (the canonical mapping is in `auth::context::AudienceTag`
    /// which lands in Phase 3 US1 — we accept the tag as a `u8` here so
    /// replay.rs has no Phase 3 module dependency).
    pub fn new(audience_tag: u8, raw_jti: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(raw_jti.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        JtiKey {
            audience: audience_tag,
            jti_hash: digest,
        }
    }
}

/// Cause of an `insert` rejection. Caller (`auth::middleware`) translates:
/// `Replayed` → `respond_401`, `MemoryPressure` → `respond_503_memory_pressure`.
#[derive(Debug, thiserror::Error)]
pub enum InsertError {
    #[error("jti already seen within the replay window")]
    Replayed,
    #[error("replay store at max_replay_entries; refusing to evict in-window entries")]
    MemoryPressure,
}

/// In-process replay store. One instance per process is shared across both
/// audience contexts (the `audience_tag` byte in the key keeps them
/// disjoint).
pub struct JtiReplayStore {
    entries: Mutex<HashMap<JtiKey, Instant>>,
    expiry_queue: Mutex<BinaryHeap<Reverse<(Instant, JtiKey)>>>,
    /// Snapshot of `entries.len()`, updated under the `entries` lock on
    /// every successful mutation. Read by the public `len()` accessor
    /// for tests + external observability (e.g. metrics, capacity-
    /// pressure alerting). NOT used as a lock-free pre-check inside
    /// `try_insert` — replay detection has precedence over memory
    /// pressure, so `try_insert` always acquires the entries lock and
    /// reads `entries.len()` under it.
    len: AtomicUsize,
    config: Arc<AuthConfig>,
}

impl JtiReplayStore {
    pub fn new(config: Arc<AuthConfig>) -> Self {
        // Reserve some headroom but cap initial allocation so an
        // operator who configures `max_replay_entries = 10_000_000` does
        // not allocate that much memory at startup.
        let initial_capacity = (config.max_replay_entries / 4).min(8192);
        JtiReplayStore {
            entries: Mutex::new(HashMap::with_capacity(initial_capacity)),
            expiry_queue: Mutex::new(BinaryHeap::with_capacity(initial_capacity)),
            len: AtomicUsize::new(0),
            config,
        }
    }

    /// Atomic check-and-insert. Returns:
    ///   - `Ok(())` if the key was inserted (the proof is now bound for the
    ///     configured replay window).
    ///   - `Err(Replayed)` if the key is already present. Returned even
    ///     when the store is at `max_replay_entries` — a replayed `jti`
    ///     is still a replay, and the FR-021 "no eviction" rule does not
    ///     mean replays go undetected.
    ///   - `Err(MemoryPressure)` if the key is NEW and the store is at
    ///     budget; the caller MUST emit the 503 response. No in-window
    ///     entry is evicted.
    pub fn try_insert(&self, key: JtiKey, deadline: Instant) -> Result<(), InsertError> {
        // Order matters: check for replay BEFORE memory pressure. A
        // replayed `jti` must always be detected and rejected with
        // `Replayed` (FR-021's primary guarantee); memory pressure only
        // affects the insert-a-new-key path. Taking the lock first costs
        // one acquire-release pair per request under load; this is
        // acceptable because the lock is held only briefly.
        let mut entries = self.entries.lock();
        if entries.contains_key(&key) {
            return Err(InsertError::Replayed);
        }

        if entries.len() >= self.config.max_replay_entries {
            return Err(InsertError::MemoryPressure);
        }

        entries.insert(key, deadline);
        self.len.store(entries.len(), Ordering::Release);
        drop(entries);

        // Push onto the expiry queue. Lock order is entries-first then
        // expiry_queue (the entries lock has been released above), which
        // is fixed across this module to prevent deadlock with
        // `maintenance_tick`.
        self.expiry_queue.lock().push(Reverse((deadline, key)));
        Ok(())
    }

    /// Remove all entries whose deadline is past `now`. Called periodically
    /// by the cleanup task (US4 / T051).
    pub fn maintenance_tick(&self, now: Instant) {
        let mut expired_keys = Vec::new();
        {
            let mut queue = self.expiry_queue.lock();
            while let Some(Reverse((deadline, _))) = queue.peek() {
                if *deadline > now {
                    break;
                }
                if let Some(Reverse((_, key))) = queue.pop() {
                    expired_keys.push(key);
                }
            }
        }
        if expired_keys.is_empty() {
            return;
        }

        let mut entries = self.entries.lock();
        for key in expired_keys {
            entries.remove(&key);
        }
        self.len.store(entries.len(), Ordering::Release);
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config(max_entries: usize) -> Arc<AuthConfig> {
        Arc::new(AuthConfig {
            clock_skew_secs: 60,
            dpop_freshness_secs: 30,
            jwks_refresh_secs: 3600,
            discovery_refresh_secs: 86_400,
            on_demand_refresh_min_interval_secs: 30,
            jti_replay_window_secs: 90,
            max_replay_entries: max_entries,
        })
    }

    #[test]
    fn insert_then_replay_rejects_second() {
        let store = JtiReplayStore::new(test_config(1024));
        let key = JtiKey::new(1, "abc123");
        let deadline = Instant::now() + Duration::from_secs(90);
        assert!(store.try_insert(key, deadline).is_ok());
        assert!(matches!(
            store.try_insert(key, deadline),
            Err(InsertError::Replayed)
        ));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn cross_audience_same_jti_not_replayed() {
        let store = JtiReplayStore::new(test_config(1024));
        let vault = JtiKey::new(1, "same-jti");
        let admin = JtiKey::new(2, "same-jti");
        let deadline = Instant::now() + Duration::from_secs(90);
        assert!(store.try_insert(vault, deadline).is_ok());
        assert!(
            store.try_insert(admin, deadline).is_ok(),
            "different audience tag → different key"
        );
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn memory_pressure_at_budget_does_not_evict() {
        let store = JtiReplayStore::new(test_config(2));
        let deadline = Instant::now() + Duration::from_secs(90);
        assert!(store.try_insert(JtiKey::new(1, "a"), deadline).is_ok());
        assert!(store.try_insert(JtiKey::new(1, "b"), deadline).is_ok());
        assert!(matches!(
            store.try_insert(JtiKey::new(1, "c"), deadline),
            Err(InsertError::MemoryPressure)
        ));
        // FR-021 absolute prohibition: no eviction under pressure.
        assert_eq!(store.len(), 2);
        assert!(
            matches!(
                store.try_insert(JtiKey::new(1, "a"), deadline),
                Err(InsertError::Replayed)
            ),
            "previously inserted key MUST still be present (no eviction under pressure)"
        );
    }

    #[test]
    fn maintenance_tick_removes_expired() {
        let store = JtiReplayStore::new(test_config(1024));
        let now = Instant::now();
        let past_deadline = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
        let future_deadline = now + Duration::from_secs(60);

        store
            .try_insert(JtiKey::new(1, "expired-1"), past_deadline)
            .unwrap();
        store
            .try_insert(JtiKey::new(1, "expired-2"), past_deadline)
            .unwrap();
        store
            .try_insert(JtiKey::new(1, "fresh-1"), future_deadline)
            .unwrap();
        assert_eq!(store.len(), 3);

        store.maintenance_tick(now);
        assert_eq!(store.len(), 1, "two expired entries should be removed");

        // The fresh entry is still present (replay rejected).
        assert!(matches!(
            store.try_insert(JtiKey::new(1, "fresh-1"), future_deadline),
            Err(InsertError::Replayed)
        ));
        // The expired entries are gone (insert succeeds).
        assert!(
            store
                .try_insert(JtiKey::new(1, "expired-1"), future_deadline)
                .is_ok()
        );
    }

    #[test]
    fn maintenance_tick_with_no_expired_is_noop() {
        let store = JtiReplayStore::new(test_config(1024));
        let now = Instant::now();
        store
            .try_insert(JtiKey::new(1, "fresh"), now + Duration::from_secs(60))
            .unwrap();
        store.maintenance_tick(now);
        assert_eq!(store.len(), 1);
    }
}

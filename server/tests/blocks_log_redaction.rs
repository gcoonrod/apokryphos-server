//! T033 — log redaction sweep (spec FR-025 / SC-010).
//!
//! Installs a thread-local `tracing` subscriber that captures every log
//! line, runs a full PUT → GET → DELETE through the storage layer with a
//! high-entropy 1 KiB payload, and asserts that no 16-byte window of the
//! payload appears verbatim in any captured log line.
//!
//! The 16-byte window keeps false positives statistically negligible
//! (probability of any 16-byte window appearing by chance ≈ 1 / 2^128).

use apokryphos_server::storage::{BlockId, LocalFsProvider, StorageProvider};
use bytes::Bytes;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

mod common;

use crate::common::with_captured_logs;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn random_canonical_id(rng: &mut ChaCha8Rng) -> BlockId {
    let mut s = String::with_capacity(43);
    for _ in 0..43 {
        let idx = rng.gen_range(0..ALPHABET.len());
        s.push(ALPHABET[idx] as char);
    }
    BlockId::parse(&s).unwrap()
}

#[test]
fn no_payload_byte_window_appears_in_captured_logs() {
    // Generate high-entropy payload before installing the subscriber so
    // the random number generator's own internal allocations don't show
    // up in the capture buffer.
    let mut rng = ChaCha8Rng::seed_from_u64(0xDEAD_BEEF_C0DE_FACEu64);
    let id = random_canonical_id(&mut rng);
    let mut payload_bytes = vec![0u8; 1024];
    rng.fill(payload_bytes.as_mut_slice());
    let payload = Bytes::from(payload_bytes.clone());

    let (captured, _result) = with_captured_logs(|| {
        // The Tokio runtime is created INSIDE the captured subscriber
        // scope so every event the storage layer emits flows through it.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let tmp = tempfile::tempdir().unwrap();
            let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());
            provider.put(&id, payload.clone()).await.unwrap();
            let fetched = provider.get(&id).await.unwrap();
            assert_eq!(fetched, payload);
            provider.delete(&id).await.unwrap();
        });
    });

    // Scan: any 16-byte contiguous window of the payload must NOT appear
    // verbatim in the captured log text.
    let captured_bytes = captured.as_bytes();
    for (start, window) in payload_bytes.windows(16).enumerate() {
        // Use a byte-substring search.
        if captured_bytes.windows(window.len()).any(|c| c == window) {
            panic!(
                "FR-025 violation: 16-byte payload window starting at offset {start} \
                 appears verbatim in captured log output. \
                 Window: {window:02x?}"
            );
        }
    }
}

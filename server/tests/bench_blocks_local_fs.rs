//! T036 — latency benchmark (spec SC-011 / research.md R14).
//!
//! `#[ignore]`'d by default — run with:
//!
//! ```text
//! cargo test --features test-utils --test bench_blocks_local_fs -- \
//!   --ignored --test-threads=1 --nocapture
//! ```
//!
//! Performs 1,000 PUT-then-GET pairs with random 43-char canonical IDs
//! and 1 MiB random payloads against a `LocalFsProvider` backed by a
//! `TempDir`. Records `Instant::elapsed` per call, sorts into p50 / p95
//! / p99, and emits a single JSON line on stdout for CI trend tracking.
//! Does NOT assert on numeric thresholds — numbers vary across runners.

use std::time::Instant;

use apokryphos_server::storage::{BlockId, LocalFsProvider, StorageProvider};
use bytes::Bytes;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn random_canonical_id(rng: &mut ChaCha8Rng) -> BlockId {
    let mut s = String::with_capacity(43);
    for _ in 0..43 {
        let idx = rng.gen_range(0..ALPHABET.len());
        s.push(ALPHABET[idx] as char);
    }
    BlockId::parse(&s).unwrap()
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    let idx = ((sorted.len() as f64) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[tokio::test]
#[ignore = "T036: SC-011 latency bench; run with --ignored on a quiesced workstation"]
async fn put_get_latency_p99_under_25ms_per_planning_target() {
    const N: usize = 1_000;
    const PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MiB

    let tmp = tempfile::tempdir().unwrap();
    let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());

    let mut rng = ChaCha8Rng::seed_from_u64(0xBEEF_BEEF_BEEF_BEEF);
    let mut put_ns: Vec<u128> = Vec::with_capacity(N);
    let mut get_ns: Vec<u128> = Vec::with_capacity(N);

    let mut payload_bytes = vec![0u8; PAYLOAD_SIZE];
    for trial in 0..N {
        rng.fill(payload_bytes.as_mut_slice());
        let id = random_canonical_id(&mut rng);
        let payload = Bytes::from(payload_bytes.clone());

        let t0 = Instant::now();
        provider.put(&id, payload).await.unwrap();
        put_ns.push(t0.elapsed().as_nanos());

        let t0 = Instant::now();
        let _ = provider.get(&id).await.unwrap();
        get_ns.push(t0.elapsed().as_nanos());

        if trial % 100 == 0 {
            eprintln!("bench trial {trial}/{N}");
        }
    }

    put_ns.sort_unstable();
    get_ns.sort_unstable();
    let put_p50 = percentile(&put_ns, 0.50);
    let put_p95 = percentile(&put_ns, 0.95);
    let put_p99 = percentile(&put_ns, 0.99);
    let get_p50 = percentile(&get_ns, 0.50);
    let get_p95 = percentile(&get_ns, 0.95);
    let get_p99 = percentile(&get_ns, 0.99);

    println!(
        "{{\"phase\":\"4\",\"bench\":\"blocks_local_fs\",\
        \"put\":{{\"p50\":{put_p50},\"p95\":{put_p95},\"p99\":{put_p99}}},\
        \"get\":{{\"p50\":{get_p50},\"p95\":{get_p95},\"p99\":{get_p99}}},\
        \"n\":{N},\"payload_bytes\":{PAYLOAD_SIZE}}}"
    );
}

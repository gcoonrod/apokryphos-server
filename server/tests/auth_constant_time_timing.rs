//! T059 — SC-011 / R13 / validate-plan G1: constant-time `ct_eq_bytes` evidence.
//!
//! ## Methodology
//!
//! The constant-time property of `auth::crypto::ct_eq_bytes` is the single
//! security invariant guarding `cnf.jkt` comparison (FR-016), `ath`
//! comparison (FR-022a), and every other equality check on auth-critical
//! paths. A non-constant-time implementation would leak the prefix-match
//! length to a timing side channel, enabling an attacker to recover a JWK
//! thumbprint or an `ath` hash byte-by-byte.
//!
//! This test generates a corpus of `(control, test)` 32-byte pairs where
//! `test` matches `control` in its first `k ∈ {0, 1, 2, …, 32}` bytes and
//! differs thereafter. For each prefix length, it runs `ct_eq_bytes(control,
//! test)` 10,000 times and measures the elapsed time via
//! `std::time::Instant::elapsed`. The per-prefix median is recorded.
//!
//! It then computes Spearman's rank correlation between (a) the prefix
//! length and (b) the median elapsed nanoseconds. Under a true
//! constant-time implementation the medians should be approximately equal
//! and ρ should be near zero. The test asserts `|ρ| < 0.1` per SC-011 +
//! validate-plan G1.
//!
//! ## Sample-size note
//!
//! The original task text suggests prefix lengths `{0, 8, 16, 24, 32}` (n=5).
//! At n=5, Spearman's ρ has 0.1-step granularity and a single tie can swing
//! ρ by 0.5 — the test becomes flaky even on a perfectly constant-time
//! implementation. We therefore sample every prefix length 0..=32 (n=33).
//! That gives the test statistical power to detect a true monotonic timing
//! relationship while tolerating sub-nanosecond noise in the median
//! measurements. The 0/8/16/24/32 lengths from the spec are a subset.
//!
//! ## Run conditions
//!
//! This test is `#[ignore]`d because:
//!   (a) it runs 330,000 timed iterations and is slow on its own;
//!   (b) it is flaky on noisy CI runners — the |ρ| < 0.1 floor assumes a
//!       quiesced workstation.
//!
//! Invoke explicitly:
//!
//! ```text
//! cargo test --features test-utils auth_constant_time_timing -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required so concurrent test threads don't fight
//! for the CPU during the timed loop.
//!
//! ## Spearman ρ (tie-aware)
//!
//! Computed as the Pearson correlation coefficient of the (x_rank, y_rank)
//! pairs. Tied values get midrank (average of the consecutive ranks they
//! would occupy). This is the standard tie-aware Spearman formulation and
//! produces ρ = 0 on a constant-y sample (modulo σy=0, in which case the
//! correlation is undefined → we treat that as 0).

use apokryphos_server::auth::crypto::ct_eq_bytes;
use std::time::Instant;

const RUNS_PER_PREFIX: usize = 10_000;

fn build_test(control: &[u8; 32], match_prefix: usize) -> [u8; 32] {
    let mut test = [0xBBu8; 32];
    test[..match_prefix].copy_from_slice(&control[..match_prefix]);
    test
}

/// Assign midrank to each element of `values`, returning a vector of
/// length `values.len()` where the element at position `i` is the rank
/// (1-indexed) of `values[i]`. Tied values share the mean of the
/// consecutive ranks they would otherwise occupy.
fn midranks(values: &[f64]) -> Vec<f64> {
    let n = values.len();
    let mut indices: Vec<usize> = (0..n).collect();
    indices.sort_by(|&a, &b| values[a].partial_cmp(&values[b]).unwrap());
    let mut ranks = vec![0.0f64; n];
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n && values[indices[j]] == values[indices[i]] {
            j += 1;
        }
        let mean_rank = ((i + 1) as f64 + j as f64) / 2.0;
        for k in i..j {
            ranks[indices[k]] = mean_rank;
        }
        i = j;
    }
    ranks
}

/// Pearson correlation coefficient.
fn pearson(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    let mean_x: f64 = x.iter().sum::<f64>() / n;
    let mean_y: f64 = y.iter().sum::<f64>() / n;
    let mut num = 0.0f64;
    let mut sx2 = 0.0f64;
    let mut sy2 = 0.0f64;
    for (xi, yi) in x.iter().zip(y.iter()) {
        let dx = xi - mean_x;
        let dy = yi - mean_y;
        num += dx * dy;
        sx2 += dx * dx;
        sy2 += dy * dy;
    }
    let denom = (sx2 * sy2).sqrt();
    if denom == 0.0 {
        // One of the variables is constant → correlation is undefined.
        // For constant y (perfectly tied medians) this means "no
        // detectable correlation" — return 0.
        0.0
    } else {
        num / denom
    }
}

fn spearman_rho(medians_ns: &[u128]) -> f64 {
    let xs: Vec<f64> = (0..medians_ns.len()).map(|i| i as f64).collect();
    let ys: Vec<f64> = medians_ns.iter().map(|&m| m as f64).collect();
    let x_rank = midranks(&xs);
    let y_rank = midranks(&ys);
    pearson(&x_rank, &y_rank)
}

#[test]
fn spearman_rho_handles_ties_correctly() {
    // All-tied → ρ = 0 (σy = 0 → undefined → defined as 0).
    assert_eq!(spearman_rho(&[100u128, 100, 100, 100, 100]), 0.0);
    // Strict monotonic → ρ = 1.
    let rho = spearman_rho(&[100u128, 200, 300, 400, 500]);
    assert!((rho - 1.0).abs() < 1e-9, "got {rho}");
    // Strict anti-monotonic → ρ = -1.
    let rho = spearman_rho(&[500u128, 400, 300, 200, 100]);
    assert!((rho + 1.0).abs() < 1e-9, "got {rho}");
    // Near-constant with one outlier should produce a small ρ. With ties
    // at the bottom (rank 2 each) and one rank-5 outlier, the Pearson-of-
    // ranks comes out roughly ±0.5; that's the natural granularity of
    // n=5, which is precisely why the actual T059 sample uses n=33.
    let rho = spearman_rho(&[541u128, 551, 541, 541, 541]);
    assert!(rho.abs() < 0.6, "got {rho}");
}

#[test]
#[ignore = "T059: SC-011 constant-time timing test; run with --ignored on a quiesced workstation"]
fn ct_eq_bytes_is_constant_time_spearman() {
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::{RngCore, SeedableRng};

    const N_PREFIXES: usize = 33;
    let control = [0xAAu8; 32];
    let tests: Vec<[u8; 32]> = (0..N_PREFIXES).map(|k| build_test(&control, k)).collect();

    // Warm-up so CPU frequency / cache state stabilizes before timed
    // measurement begins. Without this, the early prefix indices absorb
    // cold-start cost and the medians get biased by ordering.
    {
        let warm_test = build_test(&control, 16);
        for _ in 0..200_000 {
            std::hint::black_box(ct_eq_bytes(
                std::hint::black_box(&control),
                std::hint::black_box(&warm_test),
            ));
        }
    }

    // Interleaved sampling: each round measures all 33 prefixes in a
    // freshly-shuffled order. This decorrelates measurement-time from
    // prefix-length, which is critical on workstations where the CPU
    // governor changes frequency over the test's wallclock window —
    // a naive monotonic loop would falsely correlate low frequencies
    // with high prefix indices.
    let mut samples: Vec<Vec<u128>> = (0..N_PREFIXES)
        .map(|_| Vec::with_capacity(RUNS_PER_PREFIX))
        .collect();
    let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE_BEEF_DEAD_BABEu64);
    let mut order: [usize; N_PREFIXES] = std::array::from_fn(|i| i);
    for _round in 0..RUNS_PER_PREFIX {
        // Fisher-Yates shuffle.
        for i in (1..N_PREFIXES).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            order.swap(i, j);
        }
        for &k in order.iter() {
            let start = Instant::now();
            std::hint::black_box(ct_eq_bytes(
                std::hint::black_box(&control),
                std::hint::black_box(&tests[k]),
            ));
            samples[k].push(start.elapsed().as_nanos());
        }
    }

    let medians: Vec<u128> = samples
        .iter_mut()
        .map(|v| {
            v.sort_unstable();
            v[v.len() / 2]
        })
        .collect();

    let rho = spearman_rho(&medians);
    tracing::info!(
        rho = rho,
        medians = ?medians,
        "ct_eq_bytes Spearman ρ (T059)"
    );
    println!("T059: medians_ns = {medians:?}, ρ = {rho:.4}");
    assert!(
        rho.abs() < 0.1,
        "SC-011 / G1: Spearman ρ = {rho:.4} exceeds the constant-time floor \
         of |ρ| < 0.1; medians_ns = {medians:?}",
    );
}

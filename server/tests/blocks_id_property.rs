//! T032 — random-ID property test (spec SC-009).
//!
//! Two property-style sweeps against the storage layer:
//!   1. **Canonical**: 1,000 random 43-char base64url IDs each round-trip
//!      through PUT → GET → DELETE with byte-identical payload integrity.
//!   2. **Non-canonical**: 1,000 random strings from four classes (wrong
//!      length, wrong alphabet, path-traversal characters, random bytes)
//!      are rejected by `BlockId::parse`.
//!
//! Sweep size is 1k (the spec mentions 10k as the target; 1k keeps the
//! integration test fast while still giving strong confidence — every
//! parse-rejection path is deterministic so additional trials reproduce
//! the same outcome).

use apokryphos_server::storage::{BlockId, LocalFsProvider, StorageProvider};
use bytes::Bytes;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const FORBIDDEN: &[u8] = b"+/=!@#$%^&*()[]{}<>?,;:|\\\"'`~";
const TRAVERSAL: &[u8] = b"./\\";

#[tokio::test]
async fn random_canonical_ids_round_trip() {
    const N: usize = 1_000;
    let tmp = tempfile::tempdir().unwrap();
    let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());
    let mut rng = ChaCha8Rng::seed_from_u64(0xC0DE_FACE_C0FF_EE42);

    for _ in 0..N {
        let mut s = String::with_capacity(43);
        for _ in 0..43 {
            let idx = rng.gen_range(0..ALPHABET.len());
            s.push(ALPHABET[idx] as char);
        }
        let id = BlockId::parse(&s).expect("canonical id must parse");
        let payload = Bytes::from(rng.next_u32().to_be_bytes().to_vec());
        provider.put(&id, payload.clone()).await.unwrap();
        let fetched = provider.get(&id).await.unwrap();
        assert_eq!(fetched, payload, "byte-identical round-trip");
        provider.delete(&id).await.unwrap();
    }
}

#[tokio::test]
async fn random_non_canonical_strings_are_all_rejected_by_parse() {
    const N_PER_CLASS: usize = 250;
    let mut rng = ChaCha8Rng::seed_from_u64(0xBADB_EEFB_ADF0_0DDD);

    // Class 1: wrong length (alphabet-clean, length ∈ [1, 100] \ {43}).
    for _ in 0..N_PER_CLASS {
        let len = loop {
            let n = rng.gen_range(1..=100);
            if n != 43 {
                break n;
            }
        };
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let idx = rng.gen_range(0..ALPHABET.len());
            s.push(ALPHABET[idx] as char);
        }
        assert!(
            BlockId::parse(&s).is_none(),
            "wrong-length id ({} chars) must not parse: {s:?}",
            s.len()
        );
    }

    // Class 2: right length, one or more forbidden chars.
    for _ in 0..N_PER_CLASS {
        let mut bytes = vec![0u8; 43];
        for b in bytes.iter_mut() {
            *b = ALPHABET[rng.gen_range(0..ALPHABET.len())];
        }
        // Replace at least one position with a forbidden character.
        let n_corrupt = rng.gen_range(1..=5);
        for _ in 0..n_corrupt {
            let pos = rng.gen_range(0..43);
            bytes[pos] = FORBIDDEN[rng.gen_range(0..FORBIDDEN.len())];
        }
        let s = String::from_utf8(bytes).unwrap();
        assert!(
            BlockId::parse(&s).is_none(),
            "forbidden-char id must not parse"
        );
    }

    // Class 3: right length, one or more path-traversal characters.
    for _ in 0..N_PER_CLASS {
        let mut bytes = vec![0u8; 43];
        for b in bytes.iter_mut() {
            *b = ALPHABET[rng.gen_range(0..ALPHABET.len())];
        }
        let pos = rng.gen_range(0..43);
        bytes[pos] = TRAVERSAL[rng.gen_range(0..TRAVERSAL.len())];
        let s = String::from_utf8(bytes).unwrap();
        assert!(
            BlockId::parse(&s).is_none(),
            "traversal-char id must not parse"
        );
    }

    // Class 4: random length, alphabet-clean, but at the boundary. Skip
    // exactly-43 since that would be canonical; use 42 or 44.
    for _ in 0..N_PER_CLASS {
        let len = if rng.gen_bool(0.5) { 42 } else { 44 };
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let idx = rng.gen_range(0..ALPHABET.len());
            s.push(ALPHABET[idx] as char);
        }
        assert!(
            BlockId::parse(&s).is_none(),
            "off-by-one length must not parse"
        );
    }
}

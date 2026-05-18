//! T038 — provider invariants (spec FR-004 / FR-005 / FR-010 / SC-006).
//!
//! Three sub-tests against a fresh `LocalFsProvider` over a `TempDir`:
//!   1. **Idempotent delete state-snapshot** — DELETEs of 500 random
//!      absent IDs leave the block-root tree unchanged byte-for-byte.
//!   2. **`exists` consistency** — `exists(X)` reflects PUT/DELETE state.
//!   3. **File mode 0600 / Dir mode 0700** — a successful PUT lands a
//!      file with mode `0o600` inside shard dirs with mode `0o700`.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use apokryphos_server::storage::{BlockId, LocalFsProvider, StorageProvider};
use bytes::Bytes;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use walkdir::WalkDir;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn random_canonical_id(rng: &mut ChaCha8Rng) -> BlockId {
    let mut s = String::with_capacity(43);
    for _ in 0..43 {
        let idx = rng.gen_range(0..ALPHABET.len());
        s.push(ALPHABET[idx] as char);
    }
    BlockId::parse(&s).expect("random id must parse")
}

fn snapshot_tree(root: &PathBuf) -> BTreeSet<String> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .map(|e| {
            e.path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn delete_500_absent_ids_leaves_tree_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());

    let before = snapshot_tree(&tmp.path().to_path_buf());

    let mut rng = ChaCha8Rng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..500 {
        let id = random_canonical_id(&mut rng);
        provider
            .delete(&id)
            .await
            .expect("idempotent delete must succeed");
    }

    let after = snapshot_tree(&tmp.path().to_path_buf());
    assert_eq!(
        before, after,
        "FR-004 / SC-006: delete on absent IDs must not create any filesystem state"
    );
}

#[tokio::test]
async fn exists_reflects_put_and_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());
    let mut rng = ChaCha8Rng::seed_from_u64(0xFEED_FACE_AAAA_5555);
    let id = random_canonical_id(&mut rng);

    assert!(
        !provider.exists(&id).await.unwrap(),
        "exists must be false before any PUT"
    );
    provider
        .put(&id, Bytes::from_static(b"contents"))
        .await
        .unwrap();
    assert!(
        provider.exists(&id).await.unwrap(),
        "FR-005: exists must be true after PUT"
    );
    provider.delete(&id).await.unwrap();
    assert!(
        !provider.exists(&id).await.unwrap(),
        "FR-005: exists must be false after DELETE"
    );
}

#[tokio::test]
async fn put_creates_file_with_mode_0600_in_shard_dir_mode_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());

    let mut rng = ChaCha8Rng::seed_from_u64(0xC0DE_C0DE_DEAD_BEEF);
    let id = random_canonical_id(&mut rng);
    provider
        .put(&id, Bytes::from_static(b"mode test payload"))
        .await
        .unwrap();

    // The block file lives at <root>/<top>/<mid>/<id> (data-model.md
    // §LocalFsProvider). Walk the tree and inspect the leaf file mode.
    let mut found_block = false;
    let mut shard_dir_modes_correct = true;
    for entry in WalkDir::new(tmp.path()).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let meta = std::fs::metadata(path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        if meta.is_dir() {
            // Skip the root tempdir itself (created by tempfile).
            if path == tmp.path() {
                continue;
            }
            if mode != 0o700 {
                shard_dir_modes_correct = false;
                eprintln!(
                    "shard dir {} has mode {:o} (expected 0o700)",
                    path.display(),
                    mode
                );
            }
        } else if meta.is_file() {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name == id.as_str() {
                found_block = true;
                assert_eq!(
                    mode, 0o600,
                    "FR-010: block file mode must be 0600 (got {mode:o})"
                );
            }
        }
    }
    assert!(
        found_block,
        "PUT must produce a file named after the block id"
    );
    assert!(
        shard_dir_modes_correct,
        "FR-010: every created shard directory must have mode 0700"
    );
}

//! Local-filesystem `StorageProvider` implementation (spec FR-007..011,
//! research.md R2/R4/R6/R8).
//!
//! This module is the only place in the crate allowed to call
//! `std::fs::*`, `tokio::fs::*`, `std::os::unix::fs::*`, or `tempfile::*` —
//! enforced structurally by `tests/no_direct_fs.rs` (spec FR-012, SC-008).
//!
//! ## Atomic-write invariant (FR-008, FR-008a, R2)
//!
//! `put` writes payload bytes to a temp file *in the same leaf shard
//! directory* as the destination, fsyncs it, and atomically `persist`s
//! (renames) it onto the destination path. The rename is the only
//! externally visible state mutation. `tempfile::NamedTempFile` handles
//! `Drop`-time cleanup so an aborted `put` leaves no orphan temp files
//! in the steady state.
//!
//! ## Async + tempfile composition
//!
//! `tempfile`'s API is synchronous. To avoid blocking the tokio scheduler
//! on disk I/O, each storage operation that touches the filesystem runs
//! inside `tokio::task::spawn_blocking`. This is the idiomatic Rust async
//! pattern for the underlying-sync-API case; it costs one extra
//! thread-pool hop per call but preserves correct backpressure under load.
//!
//! ## Mode 0600 invariant (FR-010)
//!
//! Temp files are created with mode `0600` via
//! `tempfile::Builder::permissions`, so the post-rename file already has
//! the correct mode. Parent shard directories are created with mode `0700`
//! via `std::fs::DirBuilder::mode(0o700)`.
//!
//! ## Startup probe (FR-011, R6)
//!
//! `init(root)` validates the root exists, is a directory, and accepts a
//! probe-write through the *same code path* that production `put` uses
//! (temp + fsync + persist + unlink). The probe is the only positive
//! evidence of writability robust against overlay-filesystem permission
//! lies.

use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;

use super::block_id::BlockId;
use super::path::{block_path, shard_dir};
use super::provider::{BackendFailureCause, StorageError, StorageInitError, StorageProvider};

const PROBE_FILENAME: &str = ".startup_probe";

/// Local-filesystem block storage provider.
///
/// The single `root` field is the absolute, startup-validated block root
/// directory under which all blocks live in the two-level shard layout.
#[derive(Debug)]
pub struct LocalFsProvider {
    root: PathBuf,
}

impl LocalFsProvider {
    /// Construct + run the FR-011 startup probe. On success, returns a
    /// provider whose `root` has been validated for metadata, is_dir, and
    /// writability through the production code path.
    pub async fn init(root: PathBuf) -> Result<Self, StorageInitError> {
        let probe_root = root.clone();
        let outcome = tokio::task::spawn_blocking(move || run_init_probe(&probe_root))
            .await
            .expect("init probe spawn_blocking must not panic");
        outcome.map(|()| LocalFsProvider { root })
    }

    /// Construct without running the startup probe.
    ///
    /// Test-only — used by integration tests that inject a
    /// `tempfile::TempDir`-backed root they already created.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_unchecked(root: PathBuf) -> Self {
        LocalFsProvider { root }
    }

    /// Borrow the root path (test-only).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Synchronous startup probe: metadata → is_dir → temp+write+sync+rename+unlink.
fn run_init_probe(root: &Path) -> Result<(), StorageInitError> {
    let meta = std::fs::metadata(root).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            StorageInitError::RootMissing {
                path: root.to_path_buf(),
            }
        } else {
            StorageInitError::RootNotWritable {
                path: root.to_path_buf(),
                source,
            }
        }
    })?;
    if !meta.is_dir() {
        return Err(StorageInitError::RootNotDirectory {
            path: root.to_path_buf(),
        });
    }

    let mut temp = tempfile::Builder::new()
        .prefix(".probe.")
        .suffix(".tmp")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(root)
        .map_err(|source| StorageInitError::RootNotWritable {
            path: root.to_path_buf(),
            source,
        })?;
    temp.write_all(b"probe")
        .map_err(|source| StorageInitError::RootNotWritable {
            path: root.to_path_buf(),
            source,
        })?;
    temp.as_file_mut()
        .sync_all()
        .map_err(|source| StorageInitError::RootNotWritable {
            path: root.to_path_buf(),
            source,
        })?;
    let probe_dst = root.join(PROBE_FILENAME);
    temp.persist(&probe_dst)
        .map_err(|persist_err| StorageInitError::RootNotWritable {
            path: root.to_path_buf(),
            source: persist_err.error,
        })?;
    // Best-effort unlink. If this fails, the probe file lingers but
    // the writability assertion is already proven; do not fail startup.
    let _ = std::fs::remove_file(&probe_dst);
    Ok(())
}

/// Synchronous `put` body run on a blocking thread.
fn run_put(root: &Path, id: &BlockId, payload: &[u8]) -> Result<(), StorageError> {
    let shard = shard_dir(root, id);
    let dst = block_path(root, id);

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&shard)
        .map_err(|source| StorageError::Backend {
            cause: BackendFailureCause::classify(&source),
            source,
        })?;

    let mut temp = tempfile::Builder::new()
        .prefix(".put.")
        .suffix(".tmp")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(&shard)
        .map_err(|source| StorageError::Backend {
            cause: BackendFailureCause::classify(&source),
            source,
        })?;
    temp.write_all(payload)
        .map_err(|source| StorageError::Backend {
            cause: BackendFailureCause::classify(&source),
            source,
        })?;
    temp.as_file_mut()
        .sync_all()
        .map_err(|source| StorageError::Backend {
            cause: BackendFailureCause::classify(&source),
            source,
        })?;
    temp.persist(&dst)
        .map_err(|persist_err| StorageError::Backend {
            cause: BackendFailureCause::classify(&persist_err.error),
            source: persist_err.error,
        })?;
    Ok(())
}

#[async_trait]
impl StorageProvider for LocalFsProvider {
    async fn put(&self, id: &BlockId, payload: Bytes) -> Result<(), StorageError> {
        let root = self.root.clone();
        let id = id.clone();
        tokio::task::spawn_blocking(move || run_put(&root, &id, &payload))
            .await
            .expect("put spawn_blocking must not panic")
    }

    async fn get(&self, id: &BlockId) -> Result<Bytes, StorageError> {
        let path = block_path(&self.root, id);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Bytes::from(bytes)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Err(StorageError::NotFound),
            Err(source) => Err(StorageError::Backend {
                cause: BackendFailureCause::classify(&source),
                source,
            }),
        }
    }

    async fn delete(&self, id: &BlockId) -> Result<(), StorageError> {
        let path = block_path(&self.root, id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            // FR-004: NotFound is success.
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StorageError::Backend {
                cause: BackendFailureCause::classify(&source),
                source,
            }),
        }
    }

    async fn exists(&self, id: &BlockId) -> Result<bool, StorageError> {
        let path = block_path(&self.root, id);
        match tokio::fs::try_exists(&path).await {
            Ok(b) => Ok(b),
            Err(source) => Err(StorageError::Backend {
                cause: BackendFailureCause::classify(&source),
                source,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_id(byte: u8) -> BlockId {
        let s: String = std::iter::repeat_n(byte as char, 43).collect();
        BlockId::parse(&s).unwrap()
    }

    #[tokio::test]
    async fn put_get_delete_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());
        let id = fresh_id(b'A');
        let payload = Bytes::from_static(b"hello world payload");
        provider.put(&id, payload.clone()).await.unwrap();
        let fetched = provider.get(&id).await.unwrap();
        assert_eq!(fetched, payload);
        assert!(provider.exists(&id).await.unwrap());
        provider.delete(&id).await.unwrap();
        assert!(!provider.exists(&id).await.unwrap());
        assert!(matches!(
            provider.get(&id).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn delete_absent_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = LocalFsProvider::new_unchecked(tmp.path().to_path_buf());
        let id = fresh_id(b'B');
        provider.delete(&id).await.unwrap();
    }

    #[tokio::test]
    async fn init_rejects_missing_root() {
        let bogus = std::path::PathBuf::from("/this/path/does/not/exist/apokryphos");
        let err = LocalFsProvider::init(bogus).await.unwrap_err();
        assert!(matches!(err, StorageInitError::RootMissing { .. }));
    }

    #[tokio::test]
    async fn init_rejects_non_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("not_a_dir");
        std::fs::write(&file_path, b"plain file").unwrap();
        let err = LocalFsProvider::init(file_path).await.unwrap_err();
        assert!(matches!(err, StorageInitError::RootNotDirectory { .. }));
    }

    #[tokio::test]
    async fn init_accepts_writable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = LocalFsProvider::init(tmp.path().to_path_buf())
            .await
            .expect("writable tempdir must pass probe");
        let id = fresh_id(b'C');
        provider
            .put(&id, Bytes::from_static(b"after init"))
            .await
            .unwrap();
    }
}

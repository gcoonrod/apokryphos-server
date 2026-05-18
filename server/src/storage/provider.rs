//! `StorageProvider` trait + error types (spec FR-001..006, FR-027, FR-030).
//!
//! The trait is the only legal interface between route handlers and any
//! concrete storage backend. Phase 4 ships a single implementation
//! (`LocalFsProvider`); Phase 6 will add an S3-compatible variant under the
//! same trait without changing call sites.

use std::path::PathBuf;

use async_trait::async_trait;
use bytes::Bytes;

pub use super::block_id::BlockId;

/// The minimal storage surface (spec FR-001..006).
///
/// Concrete implementations MUST satisfy:
///
/// - `put` is atomic against partial writes (FR-003): a concurrent or
///   subsequent `get` of the same id observes either the previous complete
///   payload or the new complete payload, never an empty file, never a
///   partial write.
/// - `put` is idempotent for the same `(id, payload)` pair (FR-002).
/// - `delete` is idempotent: deleting a block that does not exist is a
///   success (FR-004).
/// - `exists` returns a boolean with a response shape consistent with
///   `get`/`delete` (FR-005).
/// - The trait surface MUST NOT expose file names, MIME types, sizes other
///   than the configured `block_size_bytes`, byte ranges, hierarchy,
///   modification timestamps, or any other client-side semantics (FR-006).
///
/// `payload` length is enforced by the route handler before this method is
/// called; the implementation MUST treat the bytes as opaque (Principle I).
#[async_trait]
pub trait StorageProvider: Send + Sync + 'static {
    /// Atomically store `payload` under `id`.
    async fn put(&self, id: &BlockId, payload: Bytes) -> Result<(), StorageError>;

    /// Return the stored bytes under `id`, or `StorageError::NotFound`.
    async fn get(&self, id: &BlockId) -> Result<Bytes, StorageError>;

    /// Remove the block under `id`. `NotFound` is NOT an error.
    async fn delete(&self, id: &BlockId) -> Result<(), StorageError>;

    /// Boolean existence check (FR-005).
    async fn exists(&self, id: &BlockId) -> Result<bool, StorageError>;
}

/// Failure modes surfaced from a `StorageProvider` operation.
///
/// `NotFound` maps to the byte-identical 404 (FR-016, FR-022).
/// `Backend` maps to the byte-identical 503 (FR-031). The route handler
/// MUST NOT distinguish `BackendFailureCause` variants in the response;
/// the cause is logged via the structured event only (data-model.md
/// §"Log-event schema").
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("block not found")]
    NotFound,

    #[error("backend failure: {cause:?}")]
    Backend {
        cause: BackendFailureCause,
        #[source]
        source: std::io::Error,
    },
}

/// Categorized backend-failure cause (data-model.md §"Block-storage core types").
/// The `as_str()` form is what the log emitter records; the underlying
/// `io::Error::to_string()` is forbidden in any log field by FR-025.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailureCause {
    DiskFull,
    PermissionDenied,
    IoError,
}

impl BackendFailureCause {
    /// Categorize a `std::io::Error` for log/event use without retaining its
    /// message string.
    pub fn classify(err: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        // `ErrorKind::StorageFull` stabilized in Rust 1.85; the project
        // pins `rust-version = "1.95"`, so the variant is always available.
        match err.kind() {
            ErrorKind::StorageFull => Self::DiskFull,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::IoError,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DiskFull => "disk_full",
            Self::PermissionDenied => "permission_denied",
            Self::IoError => "io_error",
        }
    }
}

/// Startup-probe failure modes (spec FR-011).
///
/// Surfaced by `LocalFsProvider::init` and re-emitted by
/// `storage::init_from_config`. `app::run` maps any variant to
/// `AppError::Storage` and exits non-zero before binding the listener.
#[derive(Debug, thiserror::Error)]
pub enum StorageInitError {
    #[error("block root '{path}' does not exist")]
    RootMissing { path: PathBuf },

    #[error("block root '{path}' is not a directory")]
    RootNotDirectory { path: PathBuf },

    #[error("block root '{path}' is not writable: probe write failed")]
    RootNotWritable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl StorageInitError {
    /// Tag for the structured `storage.startup.failed` event's `step` field.
    pub fn step(&self) -> &'static str {
        match self {
            Self::RootMissing { .. } => "metadata",
            Self::RootNotDirectory { .. } => "is_dir",
            Self::RootNotWritable { .. } => "probe_write",
        }
    }

    /// Categorized cause for the structured event.
    pub fn cause(&self) -> &'static str {
        match self {
            Self::RootMissing { .. } => "io_error",
            Self::RootNotDirectory { .. } => "io_error",
            Self::RootNotWritable { source, .. } => BackendFailureCause::classify(source).as_str(),
        }
    }

    /// The block-root path that triggered the failure.
    pub fn root_path(&self) -> &PathBuf {
        match self {
            Self::RootMissing { path }
            | Self::RootNotDirectory { path }
            | Self::RootNotWritable { path, .. } => path,
        }
    }
}

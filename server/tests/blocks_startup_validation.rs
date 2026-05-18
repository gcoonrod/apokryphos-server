//! T028 — US4 startup validation test (spec FR-011, SC-007).
//!
//! Drives `LocalFsProvider::init` against four `block_root` configurations:
//!   (a) path does not exist → `StorageInitError::RootMissing`
//!   (b) path exists but is a regular file → `StorageInitError::RootNotDirectory`
//!   (c) path exists, is a directory, but is not writable → `StorageInitError::RootNotWritable`
//!   (d) path exists, is a writable directory → success + probe cleanup

use std::os::unix::fs::PermissionsExt;

use apokryphos_server::storage::{LocalFsProvider, StorageInitError};

#[tokio::test]
async fn missing_root_yields_root_missing() {
    let bogus = std::path::PathBuf::from("/this/path/does/not/exist/apokryphos-4-T028");
    let err = LocalFsProvider::init(bogus.clone())
        .await
        .expect_err("missing path must fail");
    assert!(
        matches!(err, StorageInitError::RootMissing { ref path } if path == &bogus),
        "expected RootMissing, got {err:?}"
    );
    assert_eq!(err.step(), "metadata");
}

#[tokio::test]
async fn regular_file_root_yields_not_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("im_a_file_not_a_directory");
    std::fs::write(&file_path, b"this is a file").unwrap();
    let err = LocalFsProvider::init(file_path.clone())
        .await
        .expect_err("file path must fail is_dir check");
    assert!(
        matches!(err, StorageInitError::RootNotDirectory { ref path } if path == &file_path),
        "expected RootNotDirectory, got {err:?}"
    );
    assert_eq!(err.step(), "is_dir");
}

#[tokio::test]
async fn readonly_dir_yields_root_not_writable() {
    // Skip when running as root: root can write through any mode bits,
    // so the negative case is unreachable.
    // SAFETY: `libc::geteuid` is always safe to call.
    let is_root = unsafe { libc::geteuid() == 0 };
    if is_root {
        eprintln!("skipping read-only-dir test: running as root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let ro_dir = tmp.path().join("readonly");
    std::fs::create_dir(&ro_dir).unwrap();
    let mut perms = std::fs::metadata(&ro_dir).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&ro_dir, perms).unwrap();

    let err = LocalFsProvider::init(ro_dir.clone())
        .await
        .expect_err("read-only directory must fail probe-write");
    assert!(
        matches!(err, StorageInitError::RootNotWritable { ref path, .. } if path == &ro_dir),
        "expected RootNotWritable, got {err:?}"
    );
    assert_eq!(err.step(), "probe_write");

    // Restore writability so TempDir can clean up.
    let mut perms = std::fs::metadata(&ro_dir).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&ro_dir, perms).unwrap();
}

#[tokio::test]
async fn writable_dir_passes_probe() {
    let tmp = tempfile::tempdir().unwrap();
    let _provider = LocalFsProvider::init(tmp.path().to_path_buf())
        .await
        .expect("writable tempdir must pass probe");
    assert!(
        !tmp.path().join(".startup_probe").exists(),
        "probe file must be cleaned up after a successful probe"
    );
}

//! On-disk path layout for the local-filesystem `StorageProvider`
//! implementation (spec FR-008a, research.md R4).
//!
//! Two-level base64url-2-char prefix sharding: a block with ID `c[0..43]` is
//! stored at `<root>/<c[0..2]>/<c[2..4]>/<full-id>`. Both helpers below take
//! a *validated* [`BlockId`], so the `Path::join` only ever sees
//! alphabet-clean bytes — path traversal is structurally impossible
//! (the base64url alphabet excludes `/`, `.`, and `\`).

use std::path::{Path, PathBuf};

use super::block_id::BlockId;

/// `<root>/<id.shard_top()>/<id.shard_mid()>/` — the leaf shard directory
/// for `id`. `LocalFsProvider::put` uses this as the rename-atomicity
/// boundary (the temp file lives in this directory).
pub(crate) fn shard_dir(root: &Path, id: &BlockId) -> PathBuf {
    root.join(id.shard_top()).join(id.shard_mid())
}

/// `<root>/<id.shard_top()>/<id.shard_mid()>/<id.as_str()>` — the full
/// destination path for `id`'s contents.
pub(crate) fn block_path(root: &Path, id: &BlockId) -> PathBuf {
    shard_dir(root, id).join(id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> BlockId {
        BlockId::parse("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq").unwrap()
    }

    #[test]
    fn shard_dir_uses_two_2_char_levels() {
        let root = Path::new("/var/lib/apokryphos/blocks");
        let dir = shard_dir(root, &id());
        assert_eq!(dir.to_str().unwrap(), "/var/lib/apokryphos/blocks/AB/CD");
    }

    #[test]
    fn block_path_appends_full_id() {
        let root = Path::new("/var/lib/apokryphos/blocks");
        let path = block_path(root, &id());
        assert_eq!(
            path.to_str().unwrap(),
            "/var/lib/apokryphos/blocks/AB/CD/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
        );
    }
}

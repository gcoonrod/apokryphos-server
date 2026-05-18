//! `BlockId` — a 43-character base64url-no-padding canonical block identifier
//! (spec FR-013). Constructed only via `BlockId::parse`, which uses a
//! constant-time AND-over-bytes alphabet check (spec FR-014, FR-026 second
//! sentence). Existence of a `BlockId` value is the type-level proof that
//! its inner string is alphabet-clean and exactly `LEN` bytes long.

use std::fmt;

/// The canonical 43-character base64url-no-padding length (256 bits).
pub const LEN: usize = 43;

/// A validated block identifier.
///
/// Constructed only via [`BlockId::parse`]. The `Display` impl produces the
/// canonical 43-byte string. The inner string is intentionally private so the
/// invariant (FR-013 length + FR-014 alphabet) cannot be sidestepped.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BlockId(String);

impl BlockId {
    /// The constant FR-013 length.
    pub const LEN: usize = LEN;

    /// Validate and construct a `BlockId` from a candidate string.
    ///
    /// Returns `Some` iff `s` is exactly 43 bytes long AND every byte is in
    /// the base64url alphabet `A-Za-z0-9-_` (RFC 4648 §5, padding forbidden).
    /// Returns `None` otherwise. The check ANDs the validity of every byte
    /// without an early return, so the timing of this function does not
    /// depend on the position of the first invalid character (FR-026
    /// second sentence).
    ///
    /// Note: the spec's "trailing-bit interpretation" is deliberately loose
    /// (see spec §Assumptions). A 43-char base64url string encodes 258 bits;
    /// strict canonical 256-bit encodings would constrain the trailing 2
    /// bits, but `parse` accepts the full alphabet space.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != LEN {
            return None;
        }
        let mut valid: u8 = 1;
        for &b in s.as_bytes() {
            valid &= is_base64url_byte(b);
        }
        if valid == 1 {
            Some(BlockId(s.to_string()))
        } else {
            None
        }
    }

    /// The canonical 43-byte string (identical to what `parse` was given).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// First 2 characters — the top-level shard discriminator.
    /// Used by `storage::path::shard_dir` to build the on-disk path
    /// `<root>/<top>/<mid>/<id>` (spec FR-008a).
    pub fn shard_top(&self) -> &str {
        &self.0[..2]
    }

    /// Characters `[2..4]` — the mid-level shard discriminator.
    /// Used by `storage::path::shard_dir` (spec FR-008a).
    pub fn shard_mid(&self) -> &str {
        &self.0[2..4]
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-byte base64url validity (RFC 4648 §5). Returns `1` if the byte is in
/// `A-Z | a-z | 0-9 | - | _`, else `0`. Branchless to satisfy FR-026's "no
/// early-return short-circuit" review-block.
///
/// **Clippy exception**: `RangeInclusive::contains(&b)` uses short-circuit
/// `&&`, which would break the constant-time invariant. The bitwise `&`
/// form below evaluates both bounds for every byte, which is exactly what
/// FR-026 requires.
#[inline]
#[allow(clippy::manual_range_contains)]
fn is_base64url_byte(b: u8) -> u8 {
    let upper = ((b >= b'A') & (b <= b'Z')) as u8;
    let lower = ((b >= b'a') & (b <= b'z')) as u8;
    let digit = ((b >= b'0') & (b <= b'9')) as u8;
    let dash = (b == b'-') as u8;
    let underscore = (b == b'_') as u8;
    upper | lower | digit | dash | underscore
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_canonical_43_char_alphabet() {
        let id = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        assert_eq!(id.len(), LEN);
        let parsed = BlockId::parse(id).expect("must parse");
        assert_eq!(parsed.as_str(), id);
        assert_eq!(parsed.shard_top(), "AB");
        assert_eq!(parsed.shard_mid(), "CD");
    }

    #[test]
    fn parse_accepts_dash_and_underscore() {
        let id = "-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-";
        assert_eq!(id.len(), LEN);
        assert!(BlockId::parse(id).is_some());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(BlockId::parse("").is_none());
        assert!(BlockId::parse("a").is_none());
        assert!(BlockId::parse(&"a".repeat(42)).is_none());
        assert!(BlockId::parse(&"a".repeat(44)).is_none());
    }

    #[test]
    fn parse_rejects_disallowed_chars() {
        // `=` (base64 padding), `+`, `/` are NOT in base64url-no-padding.
        let bad = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop="; // 43 chars but last is `=`
        assert_eq!(bad.len(), LEN);
        assert!(BlockId::parse(bad).is_none());
        let bad = "AAA+BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // contains `+`
        assert_eq!(bad.len(), LEN);
        assert!(BlockId::parse(bad).is_none());
        let bad = "AAA/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // contains `/`
        assert_eq!(bad.len(), LEN);
        assert!(BlockId::parse(bad).is_none());
    }

    #[test]
    fn parse_rejects_path_traversal_chars() {
        let bad = "AAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // contains `.`
        assert_eq!(bad.len(), LEN);
        assert!(BlockId::parse(bad).is_none());
        let bad = "AAA/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // contains `/`
        assert!(BlockId::parse(bad).is_none());
        let bad = "AAA\\BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // contains `\`
        assert_eq!(bad.len(), LEN);
        assert!(BlockId::parse(bad).is_none());
    }

    #[test]
    fn display_round_trips() {
        let id = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        let parsed = BlockId::parse(id).unwrap();
        assert_eq!(format!("{parsed}"), id);
    }
}

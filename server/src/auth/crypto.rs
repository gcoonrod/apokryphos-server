//! Constant-time comparison primitives + RFC 7638 JWK thumbprint computation.
//!
//! Every byte/string equality comparison performed on auth-critical paths
//! (FR-016, FR-023) MUST route through `ct_eq_bytes` / `ct_eq_str` /
//! `ct_eq_32`. These wrappers delegate to `subtle::ConstantTimeEq` which is
//! constant-time-audited.
//!
//! Note on the one allowed early return: `ct_eq_bytes` short-circuits when
//! the two inputs have different lengths. FAPI 2.0 + DPoP does NOT require
//! length-blinding (the lengths of audience strings, htu paths, etc. are
//! either operator-configured or wire-public anyway). The "no early return"
//! property holds for the *value-dependent* comparison: once two equal-
//! length slices reach `subtle::ConstantTimeEq`, no byte-position-dependent
//! branch can fire.
//!
//! `jwk_thumbprint` computes the RFC 7638 §3.1 + §3.2 canonical-JSON SHA-256
//! digest of a JWK's public-key parameters. The canonical form is ASCII-only
//! (all field values are base64url-encoded strings), so there are no Unicode
//! normalization concerns. The order of fields in the canonical JSON is
//! lexicographic and is fixed by RFC 7638 — we hand-construct the string
//! rather than going through `serde_json` because the latter does not
//! guarantee field order without explicit struct ordering.

use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Constant-time byte-slice equality. Length leak is allowed (FAPI 2.0 does
/// not require length-blinding); the bytes themselves are compared in time
/// independent of their values.
#[inline]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time UTF-8 string equality (delegates to `ct_eq_bytes`).
#[inline]
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time fixed-length 32-byte equality. Length is constant so no
/// length-leak edge case exists.
#[inline]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// The minimal public-key shape needed for RFC 7638 thumbprint computation.
///
/// `Rsa` and `EcP256` mirror the FAPI 2.0 + DPoP allowlist's PS256 / ES256
/// algorithm pair (Clarify-Q1, FR-010a). No other variants exist by design.
/// `auth::jwks::Jwk` (Phase 3 US1) will produce one of these on demand for
/// thumbprint computation; Phase 2 keeps this enum local to `auth::crypto`.
pub enum JwkThumbprintInput<'a> {
    /// RSA public key: `n` (modulus) and `e` (public exponent). Both byte
    /// slices MUST be the unpadded big-endian representations that the JWK
    /// `n` / `e` fields decode to.
    Rsa { n: &'a [u8], e: &'a [u8] },
    /// EC P-256 public key: `x` and `y` coordinates, each 32 bytes.
    EcP256 { x: &'a [u8; 32], y: &'a [u8; 32] },
}

/// Compute the RFC 7638 thumbprint: SHA-256 over canonical JSON of the
/// JWK's public-key parameters. Returns the 32-byte raw digest.
///
/// Canonical JSON rules per RFC 7638 §3.1 + §3.2:
///   - Field order: lexicographic ASCII.
///   - No whitespace between tokens.
///   - All field values are base64url-encoded (URL-safe, no padding).
///   - No Unicode escapes (all bytes are ASCII).
pub fn jwk_thumbprint(input: JwkThumbprintInput<'_>) -> [u8; 32] {
    let json = canonical_json(&input);
    Sha256::digest(json.as_bytes()).into()
}

/// Base64url-encoded SHA-256 thumbprint (URL-safe alphabet, no padding).
/// Used for human-readable thumbprint comparison (e.g., the `cnf.jkt`
/// claim's wire form).
pub fn jwk_thumbprint_b64url(input: JwkThumbprintInput<'_>) -> String {
    let digest = jwk_thumbprint(input);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn canonical_json(input: &JwkThumbprintInput<'_>) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match input {
        JwkThumbprintInput::Rsa { n, e } => {
            // RFC 7638 §3.2: for an RSA key the required members in
            // lexicographic order are `e`, `kty`, `n`.
            let e_b64 = engine.encode(e);
            let n_b64 = engine.encode(n);
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e_b64, n_b64)
        }
        JwkThumbprintInput::EcP256 { x, y } => {
            // RFC 7638 §3.2: for an EC key the required members in
            // lexicographic order are `crv`, `kty`, `x`, `y`.
            let x_b64 = engine.encode(x.as_slice());
            let y_b64 = engine.encode(y.as_slice());
            format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                x_b64, y_b64
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_bytes_equal_inputs_return_true() {
        assert!(ct_eq_bytes(b"hello", b"hello"));
    }

    #[test]
    fn ct_eq_bytes_different_inputs_return_false() {
        assert!(!ct_eq_bytes(b"hello", b"world"));
    }

    #[test]
    fn ct_eq_bytes_different_lengths_return_false() {
        assert!(!ct_eq_bytes(b"hello", b"helloo"));
    }

    #[test]
    fn ct_eq_bytes_empty_both_sides() {
        assert!(ct_eq_bytes(b"", b""));
    }

    #[test]
    fn ct_eq_bytes_one_empty_one_not_returns_false() {
        assert!(!ct_eq_bytes(b"", b"x"));
        assert!(!ct_eq_bytes(b"x", b""));
    }

    #[test]
    fn ct_eq_str_equal() {
        assert!(ct_eq_str("audience-foo", "audience-foo"));
    }

    #[test]
    fn ct_eq_str_different() {
        assert!(!ct_eq_str("vault-aud", "admin-aud"));
    }

    #[test]
    fn ct_eq_32_equal_arrays() {
        let a = [0xaa; 32];
        let b = [0xaa; 32];
        assert!(ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_32_one_byte_differs() {
        let a = [0xaa; 32];
        let mut b = a;
        b[15] = 0xbb;
        assert!(!ct_eq_32(&a, &b));
    }

    /// RFC 7638 §3.1 worked example: SHA-256 thumbprint of the canonical
    /// JSON `{"e":"AQAB","kty":"RSA","n":"0vx7…"}` equals
    /// `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.
    #[test]
    fn jwk_thumbprint_rfc7638_rsa_worked_example() {
        let n_b64 = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let e_b64 = "AQAB";
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(n_b64)
            .unwrap();
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(e_b64)
            .unwrap();
        let tp = jwk_thumbprint_b64url(JwkThumbprintInput::Rsa { n: &n, e: &e });
        assert_eq!(tp, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn jwk_thumbprint_changes_when_modulus_changes() {
        let n1 = vec![0u8; 256];
        let mut n2 = n1.clone();
        n2[0] = 1;
        let e = vec![1, 0, 1];
        let t1 = jwk_thumbprint(JwkThumbprintInput::Rsa { n: &n1, e: &e });
        let t2 = jwk_thumbprint(JwkThumbprintInput::Rsa { n: &n2, e: &e });
        assert_ne!(t1, t2);
    }

    #[test]
    fn jwk_thumbprint_ec_changes_when_coordinate_changes() {
        let x = [0xaa; 32];
        let y1 = [0xbb; 32];
        let mut y2 = y1;
        y2[0] = 0xcc;
        let t1 = jwk_thumbprint(JwkThumbprintInput::EcP256 { x: &x, y: &y1 });
        let t2 = jwk_thumbprint(JwkThumbprintInput::EcP256 { x: &x, y: &y2 });
        assert_ne!(t1, t2);
    }
}

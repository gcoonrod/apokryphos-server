//! T038 — attempts the cross-subject conversion impl that would defeat
//! the type fence. Two privacy barriers block it:
//!
//!   1. The inner `Sub` newtype field is `pub(in crate::auth)` — the
//!      `VaultSubject(v.0)` destructure cannot reach the private field
//!      from outside the auth module.
//!   2. Even if (1) were public, `AdminSubject` cannot be constructed
//!      via its tuple-struct constructor outside `auth::*` because the
//!      tuple field's type (`Sub`) is private.
//!
//! Either error is sufficient; in practice the compiler reports both.

use apokryphos_server::auth::{AdminSubject, VaultSubject};

impl From<VaultSubject> for AdminSubject {
    fn from(v: VaultSubject) -> Self {
        // Attempt to destructure the private inner `Sub` and rewrap it.
        let VaultSubject(inner) = v;
        AdminSubject(inner)
    }
}

fn main() {}

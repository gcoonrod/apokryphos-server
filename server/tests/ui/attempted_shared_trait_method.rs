//! T039 — attempts a shared-input trait method that would funnel both
//! subject types into the same generic API. The construction fails for
//! two reasons:
//!
//!   1. The only `&str`-shaped accessor each subject exposes is
//!      `into_string(self) -> String`, which *consumes* the wrapper. A
//!      trait method `fn name(&self) -> &str` therefore can't be
//!      implemented without reaching the private inner `Sub`.
//!   2. Trying to access the inner `Sub` field (`self.0`) is a private
//!      field access from outside `auth::*`, which fails to compile.

use apokryphos_server::auth::{AdminSubject, VaultSubject};

trait AnySubject {
    fn name(&self) -> &str;
}

impl AnySubject for VaultSubject {
    fn name(&self) -> &str {
        // Private field access — `self.0` is `Sub`, which is
        // `pub(in crate::auth)`.
        self.0.as_ref()
    }
}

impl AnySubject for AdminSubject {
    fn name(&self) -> &str {
        self.0.as_ref()
    }
}

fn main() {}

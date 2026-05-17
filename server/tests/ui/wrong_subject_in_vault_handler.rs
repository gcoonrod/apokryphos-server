//! T036 — compile-fail fixture for SC-004.
//!
//! Models the natural mistake of a developer trying to use an
//! `AdminSubject` extractor inside a vault-mounted handler. Axum will
//! happily compile the handler signature itself (both subject types
//! implement `FromRequestParts`), but a real vault handler eventually
//! needs to do something useful with the subject — typically funneling
//! it into the audience-correct logic. Here the "something useful" is
//! constructing a `VaultSubject` from the admin subject's `sub` string,
//! which is the exact mistake the type fence is supposed to block.
//!
//! `VaultSubject::new` is `pub(in crate::auth)`, so this call site —
//! outside the `auth` module — fails to compile.

use apokryphos_server::auth::{AdminSubject, VaultSubject};

async fn vault_handler_misusing_admin_subject(admin: AdminSubject) -> String {
    // Attempted escape: re-wrap the admin sub as a vault sub. This is
    // exactly the funnel the type fence exists to prevent.
    let v = VaultSubject::new(admin.into_string());
    v.into_string()
}

fn main() {
    let _ = vault_handler_misusing_admin_subject;
}

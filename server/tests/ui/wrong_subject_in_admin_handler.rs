//! T037 — mirror of T036 for the admin side. Mounting a `VaultSubject`
//! extractor inside an admin handler and trying to re-wrap it as an
//! `AdminSubject` fails to compile because `AdminSubject::new` is
//! `pub(in crate::auth)`.

use apokryphos_server::auth::{AdminSubject, VaultSubject};

async fn admin_handler_misusing_vault_subject(vault: VaultSubject) -> String {
    let a = AdminSubject::new(vault.into_string());
    a.into_string()
}

fn main() {
    let _ = admin_handler_misusing_vault_subject;
}

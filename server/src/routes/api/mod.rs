//! Vault-audience routes (`/api/*`).
//!
//! Phase 3 US1: only `GET /api/whoami` (FR-027). Future phases add the
//! actual block-storage endpoints (`/api/blocks/{id}`) under the same guard.

mod whoami;

pub use whoami::vault_routes;

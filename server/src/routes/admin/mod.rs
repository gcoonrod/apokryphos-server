//! Admin-audience routes (`/admin/*`).
//!
//! Phase 3 US2: only `GET /admin/whoami` (FR-028). The admin route tree
//! is symmetric with the vault tree under `routes::api`: same guard
//! shape (`any(handler).layer(guard)` + in-handler method dispatch +
//! short-circuit on non-GET inside the guard) so non-GET methods return
//! a byte-shape-identical 404 (no Allow, no WWW-Authenticate).

mod whoami;

pub use whoami::admin_routes;

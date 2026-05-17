//! FAPI 2.0 + DPoP authentication core (constitution Principle IV).
//!
//! This module replaces the Phase 1 placeholder. It is wired into the crate
//! surface via `lib.rs`'s `pub mod auth;` (Phase 3 T003). See
//! `specs/003-fapi-dpop-auth-core/contracts/internal.md` §`auth/mod.rs`
//! for the public surface and the cross-module forbidden-interaction rules.
//!
//! ## Submodule status (Phase 3 US1 MVP — all live; US2 extends the dual-context surface)
//!
//! | Submodule    | Current state                                           | Owning tasks |
//! |--------------|---------------------------------------------------------|--------------|
//! | `crypto`     | ✅ `ct_eq_*` + RFC 7638 JWK thumbprint                  | T010         |
//! | `failure`    | ✅ `respond_401` + `respond_503` + `log_failure` + `AuthFailure` | T011 |
//! | `subject`    | ✅ `VaultSubject` + `AdminSubject` + private extensions | T012         |
//! | `replay`     | ✅ `JtiReplayStore` + `JtiKey`                          | T013         |
//! | `testing`    | ✅ keygen + RNG + `MockOidcProvider` + mint_* helpers   | T014         |
//! | `context`    | ✅ `OidcContext` + `AudienceTag` + `init_single_context`; US2 adds `init_contexts` + cross-reach (`Weak<OidcContext>`) | T018, T028 |
//! | `discovery`  | ✅ `fetch_discovery` + `Discovery` cache                | T016         |
//! | `dpop`       | ✅ `validate_proof` (FR-010a, FR-017..FR-023)           | T020         |
//! | `jwks`       | ✅ `fetch_jwks` + `Jwks` + `JwsAlg` allowlist           | T017         |
//! | `middleware` | ✅ `VaultGuard`; US2 adds `AdminGuard`                  | T021, T032   |
//! | `token`      | ✅ `validate_token` (FR-010a, FR-011..FR-016)           | T019         |

pub mod context;
pub mod crypto;
pub mod discovery;
mod dpop;
pub mod failure;
pub mod jwks;
pub mod middleware;
pub mod replay;
pub(crate) mod subject;
mod token;

// `auth::testing` is gated on the `test-utils` feature ONLY (not on
// `cfg(test)`). The module pulls in optional deps (p256, rsa, rand,
// rand_chacha) that are themselves activated only by the feature; if
// the gate also fired on plain `cfg(test)`, `cargo test` without
// `--features test-utils` would fail to compile because those crates
// aren't in the dependency graph. Phase 3 integration tests under
// `server/tests/` declare `required-features = ["test-utils"]`, and
// inline `mod tests` blocks that need `auth::testing` are themselves
// gated on the feature.
#[cfg(feature = "test-utils")]
pub mod testing;

// Phase 2 + Phase 3 (US1 first step) re-exports. Phase 3 US2 will broaden
// this as `VaultGuard`, `AdminGuard`, `init_contexts`, etc. land. See
// contracts/internal.md §`auth/mod.rs`.
pub use context::{
    AudienceTag, ContextInitError, OidcContext, init_contexts, init_single_context,
};
pub use discovery::{Discovery, DiscoveryFetchError};
pub use failure::{respond_401, respond_503_memory_pressure};
pub use jwks::{Jwk, Jwks, JwksFetchError, JwsAlg};
pub use replay::{InsertError as ReplayInsertError, JtiKey, JtiReplayStore};
pub use subject::{AdminSubject, VaultSubject};

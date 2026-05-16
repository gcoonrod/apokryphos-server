//! FAPI 2.0 + DPoP authentication core (constitution Principle IV).
//!
//! This module replaces the Phase 1 placeholder. It is wired into the crate
//! surface via `lib.rs`'s `pub mod auth;` (Phase 3 T003). See
//! `specs/003-fapi-dpop-auth-core/contracts/internal.md` §`auth/mod.rs`
//! for the public surface and the cross-module forbidden-interaction rules.
//!
//! ## Submodule status (Phase 2 = scaffold; Phase 3 = full implementation)
//!
//! | Submodule    | Phase 2 status                         | Filled in by |
//! |--------------|----------------------------------------|--------------|
//! | `crypto`     | ✅ ct_eq_* + JWK thumbprint            | T010         |
//! | `failure`    | ✅ respond_401 + respond_503 + AuthFailure | T011     |
//! | `subject`    | ✅ VaultSubject + AdminSubject + ext keys | T012      |
//! | `replay`     | ✅ JtiReplayStore                      | T013         |
//! | `testing`    | ✅ key generation + RNG (rest deferred to Phase 3) | T014 |
//! | `context`    | stub (empty file)                      | T018, T028   |
//! | `discovery`  | stub                                   | T016         |
//! | `dpop`       | stub                                   | T020         |
//! | `jwks`       | stub                                   | T017         |
//! | `middleware` | stub                                   | T021, T032   |
//! | `token`      | stub                                   | T019         |

mod context;
pub mod crypto;
mod discovery;
mod dpop;
pub mod failure;
mod jwks;
mod middleware;
pub mod replay;
mod subject;
mod token;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

// Phase 2 re-exports (the only types currently usable from outside `auth::`).
// Phase 3 will broaden this as `OidcContext`, `VaultGuard`, `AdminGuard`,
// `init_contexts`, etc. land. See contracts/internal.md §`auth/mod.rs`.
pub use failure::{respond_401, respond_503_memory_pressure};
pub use replay::{InsertError as ReplayInsertError, JtiKey, JtiReplayStore};
pub use subject::{AdminSubject, VaultSubject};

//! Phase 3 / Phase 7 conformance harness — entrypoint.
//!
//! This crate-root test target lives outside `server/tests/` (see
//! `specs/003-fapi-dpop-auth-core/research.md` decision R14): the conformance
//! harness is intended to grow into the FAPI 2.0 + DPoP profile compliance
//! matrix in Phase 7, at which point it will be lifted into its own crate
//! when the workspace is reconfigured. Keeping it at the repo root from
//! Phase 3 onward means Phase 7's lift-out is a pure manifest change —
//! no source-file moves, no cross-crate path renames.
//!
//! Phase 3 ships the **scaffolding only**: the smoke tests below exercise
//! the user-stories 1-3 end-to-end through the public test-helper API
//! (no `pub(crate)` / `pub(in crate::auth)` reach-through). The full
//! FAPI 2.0 negative-case matrix is the deliverable of Phase 7 (see the
//! constitution's roadmap; Principle IV / V).

mod helpers;
mod smoke;

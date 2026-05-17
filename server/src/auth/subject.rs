//! Distinct subject types for the two audiences (FR-024, FR-025, FR-026).
//!
//! `VaultSubject` and `AdminSubject` carry the authenticated `sub` value of
//! a vault-audience or admin-audience request respectively. They are
//! deliberately separate Rust types:
//!
//!   - The inner `Sub(Box<str>)` newtype is `pub(in crate::auth)` so it can
//!     only be constructed from inside `auth::*`. A developer who writes
//!     `AdminSubject::new(vault_sub.into_string())` outside `auth::` gets a
//!     privacy error — `Sub` is not exposed.
//!
//!   - No `From<VaultSubject> for AdminSubject` (or reverse) impl exists.
//!     The four `tests/ui/*.rs` compile-fail fixtures (US2 / SC-004 /
//!     T036–T040) verify that any attempt to define one fails to compile.
//!
//!   - No shared trait exposes a `&str` accessor or a generic consumer
//!     that could funnel both subject types into a single function. The
//!     only accessor is `into_string(self) -> String` (consumes self).
//!
//! Each subject's `FromRequestParts` impl reads only from a typed
//! request-extension key — `VaultSubjectExtension` / `AdminSubjectExtension` —
//! which is also `pub(in crate::auth)` and constructible only by the
//! matching guard. A handler mounted under the wrong guard cannot extract
//! the wrong subject because the extension key it's looking for was
//! never inserted by that guard.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::auth::failure::respond_401;

/// Private newtype backing both subject types. The privacy boundary is the
/// load-bearing part of FR-024/FR-026: code outside `auth::*` cannot
/// construct a `Sub`, therefore cannot construct a `VaultSubject` or
/// `AdminSubject` either.
#[derive(Clone, Debug)]
pub(in crate::auth) struct Sub(Box<str>);

impl Sub {
    // `new` is consumed by `VaultSubject::new` / `AdminSubject::new` below,
    // both of which are themselves consumed by the Phase 3 vault/admin
    // guards (T021/T032). Phase 2 ships the type fence; Phase 3 wires it
    // up. The `#[allow(dead_code)]` here is the cleanest way to keep
    // Phase 2 warning-free without falsely advertising the API as live.
    #[allow(dead_code)]
    pub(in crate::auth) fn new(s: impl Into<Box<str>>) -> Self {
        Sub(s.into())
    }

    fn into_string(self) -> String {
        String::from(self.0)
    }
}

/// Authenticated subject for a vault-audience request. Constructible only
/// by `auth::middleware::VaultGuard` (Phase 3 US1 / T021). Not convertible
/// to or from `AdminSubject` (FR-024, FR-025, FR-026).
#[derive(Clone, Debug)]
pub struct VaultSubject(Sub);

impl VaultSubject {
    /// Construct from the validated `sub` claim. Only callable from within
    /// `auth::*` (`Sub` is `pub(in crate::auth)`). Consumed by the Phase 3
    /// vault guard (T021); Phase 2 ships the type fence ahead of the guard.
    #[allow(dead_code)]
    pub(in crate::auth) fn new(sub: impl Into<Box<str>>) -> Self {
        VaultSubject(Sub::new(sub))
    }

    /// Consume the wrapper and return the inner `sub` as a `String`. This
    /// is the ONLY public accessor — there is intentionally no `as_str`,
    /// `AsRef<str>`, `Deref<Target = str>`, or `Borrow<str>` impl. Returning
    /// a borrowed `&str` would let callers funnel both `VaultSubject` and
    /// `AdminSubject` into a single `fn frob(s: &str)`, which would defeat
    /// the type-level distinction this module exists to enforce.
    pub fn into_string(self) -> String {
        self.0.into_string()
    }
}

/// Authenticated subject for an admin-audience request. Mirror of
/// `VaultSubject` in every respect except the audience binding.
#[derive(Clone, Debug)]
pub struct AdminSubject(Sub);

impl AdminSubject {
    /// Mirror of `VaultSubject::new`. Consumed by the Phase 3 admin guard (T032).
    #[allow(dead_code)]
    pub(in crate::auth) fn new(sub: impl Into<Box<str>>) -> Self {
        AdminSubject(Sub::new(sub))
    }

    pub fn into_string(self) -> String {
        self.0.into_string()
    }
}

/// Request-extension carrier for `VaultSubject`. Visibility is
/// `pub(crate)` so the routes layer can read the extension after the
/// guard inserts it (specifically: the `any(handler)`-style dispatcher
/// in `routes/api/whoami.rs` needs to read this on GET requests). The
/// inner field stays `pub VaultSubject` rather than exposing `Sub`
/// directly — and `VaultSubject`'s own constructor is still
/// `pub(in crate::auth)`, so external code STILL cannot construct an
/// extension. The widened visibility is a one-way valve: read-only
/// access for the dispatcher.
#[derive(Clone, Debug)]
pub(crate) struct VaultSubjectExtension(pub VaultSubject);

/// Mirror for `AdminSubject`.
#[derive(Clone, Debug)]
pub(crate) struct AdminSubjectExtension(pub AdminSubject);

impl<S> FromRequestParts<S> for VaultSubject
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<VaultSubjectExtension>()
            .map(|ext| ext.0.clone())
            .ok_or_else(|| respond_401().into_response())
    }
}

impl<S> FromRequestParts<S> for AdminSubject
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AdminSubjectExtension>()
            .map(|ext| ext.0.clone())
            .ok_or_else(|| respond_401().into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_subject_round_trips_through_into_string() {
        let v = VaultSubject::new("user-42");
        assert_eq!(v.into_string(), "user-42");
    }

    #[test]
    fn admin_subject_round_trips_through_into_string() {
        let a = AdminSubject::new("admin-root");
        assert_eq!(a.into_string(), "admin-root");
    }

    #[tokio::test]
    async fn vault_subject_extracts_from_request_extension() {
        use axum::http::Request;

        let mut req: Request<()> = Request::builder().body(()).unwrap();
        let inserted = VaultSubject::new("u-1");
        req.extensions_mut()
            .insert(VaultSubjectExtension(inserted));
        let (mut parts, _body) = req.into_parts();
        let extracted = VaultSubject::from_request_parts(&mut parts, &())
            .await
            .expect("extension present");
        assert_eq!(extracted.into_string(), "u-1");
    }

    #[tokio::test]
    async fn vault_subject_rejection_when_extension_missing() {
        use axum::http::{Request, StatusCode};

        let req: Request<()> = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let result = VaultSubject::from_request_parts(&mut parts, &()).await;
        let rejection = result.expect_err("no extension should reject");
        assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_extraction_fails_when_only_vault_extension_present() {
        use axum::http::Request;

        // Insert a VaultSubjectExtension; attempt to extract AdminSubject.
        // The AdminSubjectExtension key is not present, so extraction
        // yields 401. The type system would normally prevent this at
        // compile time (a route mounted under VaultGuard has its handler
        // typed to accept VaultSubject only); here we exercise the runtime
        // fallback path for completeness.
        let mut req: Request<()> = Request::builder().body(()).unwrap();
        req.extensions_mut()
            .insert(VaultSubjectExtension(VaultSubject::new("u-1")));
        let (mut parts, _) = req.into_parts();
        let result = AdminSubject::from_request_parts(&mut parts, &()).await;
        assert!(
            result.is_err(),
            "admin extraction must fail when only vault extension is present"
        );
    }
}

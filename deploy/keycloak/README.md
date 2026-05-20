# Keycloak realm imports

These JSON files are imported by Keycloak at first boot via the
`--import-realm` CLI flag (set in `deploy/compose.yaml`). The import is
idempotent — re-imports are no-ops if the realm already exists, so
`docker compose restart keycloak` is cheap.

## Files

| File | Realm | Purpose |
|---|---|---|
| `vault-realm.json` | `vault` | Issues tokens with `aud=apokryphos-vault` for the future vault SPA → `/api/blocks/{id}` flow. |
| `apok-admin-realm.json` | `apok-admin` | Issues tokens with `aud=apokryphos-admin` for the future admin SPA → `/admin/*` flow. |

`vault` and `apok-admin` are cryptographically isolated by realm — each
gets its own key set, satisfying apokryphos-server's FR-006 disjoint
JWKS startup invariant for free (verified empirically by JWKS `kid`-set
diff against a live Keycloak 26.6 instance during the design phase of
this deployment reference).

## What the realms configure

Every realm import sets the following invariants. Operators changing
them via the admin UI should be aware these are load-bearing.

1. **Signing keys** — explicit `rsa-generated` (alg=PS256) and
   `ecdsa-generated` (curve=P-256, alg=ES256) key providers. Without
   these, Keycloak only generates RS256 keys, and the FAPI 2.0 client
   policy's `secure-signature-algorithm` executor would refuse to issue
   tokens because no PS256/ES256 key exists. Discovery would advertise
   PS256/ES256 as *supported* but the JWKS would not actually contain
   matching keys → token-issuance failures. This is the #1 gotcha when
   hand-rolling realm imports.

2. **`defaultSignatureAlgorithm = "PS256"`** — realm-wide default. Per-
   client overrides (`access.token.signed.response.alg`) are layered
   on top.

3. **Client policy** — a single policy named
   `apokryphos-{vault,admin}-fapi-2-dpop` binds the built-in
   `fapi-2-dpop-security-profile` to every client in the realm that
   sets the `dpop.bound.access.tokens=true` attribute. The profile is
   a Keycloak 26.6+ built-in; its executors enforce:
   - `dpop-bind-enforcer` — DPoP-bound access tokens (RFC 9449)
   - `secure-signature-algorithm` — PS/ES/EdDSA only; no HS*, no RS256
   - `pkce-enforcer` — PKCE S256 mandatory
   - `reject-implicit-grant` — code flow only
   - `secure-par-content` — Pushed Authorization Requests
   - `confidential-client` / `secure-client-authenticator` — strong client auth
   - `consent-required`, `full-scope-disabled` — least-privilege defaults

4. **Audience mapper** — each realm has an `apokryphos-{vault,admin}-
   audience` client scope, set as a default scope, that injects the
   correct `aud` claim into access tokens. apokryphos-server's
   `vault_oidc.audience` / `admin_oidc.audience` config values MUST
   match these audience strings exactly.

5. **Brute-force protection** — `bruteForceProtected: true`, with
   tighter thresholds on the admin realm (3 failures vs 5, 30-minute
   max wait vs 15) because admin compromise has higher blast radius.

6. **No self-registration** — `registrationAllowed: false`. The
   operator creates users via the admin UI. The vault realm allows
   `resetPasswordAllowed: true`; the admin realm does not (operator
   must reset via the master admin).

## What the realm imports DO NOT do

These need to happen manually after first boot via the Keycloak admin UI:

- **Create users.** Visit `https://auth.apokryphos.local/admin` → vault
  realm → Users → Add user. Enroll TOTP / WebAuthn from the user UI
  after the first login.
- **Set realm hostname / email server.** The defaults work for
  homelab, but production deployments should set realm display HTML,
  brand colors, and an SMTP server for password reset emails.
- **Customize redirect URIs.** Both stub clients ship with
  `http://localhost:{5173,5174}/*` for local dev plus
  `https://api.apokryphos.local/*` placeholders. Replace these with
  your real SPA origins before going past localhost development.

## Updating a running realm

The `--import-realm` flag is **import-only**. To update an existing
realm with changed JSON, you have three options:

1. **Quick + destructive** (smoke-test environments only): delete the
   realm in the admin UI, then `docker compose restart keycloak` to
   re-import.
2. **Targeted edits** via the admin UI (preferred for one-off changes).
3. **kcadm.sh** for scripted batch changes — exec into the Keycloak
   container and use the official admin CLI.

For production, treat these JSON files as documentation of the
desired state, but make all changes via the admin UI or kcadm.sh so
operator audit logs reflect the change.

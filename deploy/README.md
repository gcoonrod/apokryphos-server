# apokryphos-server homelab reference deployment

A turnkey `docker compose` stack that brings up apokryphos-server behind
a Caddy reverse proxy with a Keycloak 26.6 OIDC provider, configured for
FAPI 2.0 + DPoP. This is a **reference deployment** intended as a
starting point — not a hardened production configuration.

## What you get

```
                    ┌─── auth.apokryphos.local ──→ Keycloak (vault + apok-admin realms)
host :443 ─→ Caddy ─┤
                    └─── api.apokryphos.local  ──→ apokryphos-server
```

Five containers on one Docker network: Caddy (TLS terminator), Keycloak
26.6 (OIDC IdP with DPoP enabled), Postgres 17 (Keycloak's store),
apokryphos-server, and a one-shot helper that publishes Caddy's local
CA root cert for the server to trust.

The two Keycloak realms (`vault`, `apok-admin`) are pre-imported with:
PS256 + ES256 signing keys, the built-in `fapi-2-dpop-security-profile`
client policy, an audience mapper for `aud=apokryphos-{vault,admin}`,
brute-force protection, and one stub SPA client per realm. See
[`keycloak/README.md`](./keycloak/README.md) for the full breakdown.

## Prerequisites

- Docker Engine 26+ and the Compose v2 plugin (`docker compose version`)
- ~2 GB free RAM (Keycloak alone wants ~1 GB)
- The ability to edit your `/etc/hosts` (or your local DNS)

## First boot

### 1. Bootstrap secrets

```bash
cd deploy
cp .env.example .env
$EDITOR .env
```

Generate a real Postgres password:

```bash
openssl rand -base64 32
```

Pick a non-default `KC_BOOTSTRAP_ADMIN_PASSWORD`. You'll rotate it on
first login.

### 2. Resolve the homelab hostnames

The compose stack uses two FQDNs:
- `auth.apokryphos.local` — Keycloak
- `api.apokryphos.local` — apokryphos-server

Add them to your `/etc/hosts`:

```
127.0.0.1   auth.apokryphos.local api.apokryphos.local
```

(Or configure your local DNS — dnsmasq, Pi-hole, etc. — to map these
to the host running compose.)

### 3. Materialize the live config

```bash
cp apokryphos.toml.example apokryphos.toml
```

The `.example` is a template that gets baked into the repo; the live
`apokryphos.toml` is what compose mounts into the container, and is
gitignored.

### 4. Bring up the stack

```bash
docker compose up -d
```

This builds the apokryphos-server image (~3-5 minutes on first run,
faster afterwards via Docker layer cache) and starts all five services.

Watch the boot sequence:

```bash
docker compose logs -f
```

You're looking for:
- `caddy` — `serving initial configuration` then `certificate obtained successfully` for both hosts
- `keycloak` — `Imported realm vault` and `Imported realm apok-admin`, then `Listening on: http://0.0.0.0:8080`
- `caddy-cert-publisher` — `published Caddy local CA root` then exits 0
- `apokryphos-server` — `OIDC contexts initialized` (FR-002 + FR-006 passed) then `bind: 0.0.0.0:8443` then `ready`

If apokryphos-server logs a startup error mentioning "issuer URL" or
"discovery" or "JWKS", see [Troubleshooting](#troubleshooting) below.

### 5. Trust the Caddy local CA in your browser

Caddy generates a self-signed CA root on first boot. To avoid a
browser warning on every visit, import it as a trusted root:

```bash
# Extract Caddy's local CA root
docker compose exec -u root caddy cat /data/caddy/pki/authorities/local/root.crt > caddy-local-ca.crt
```

Then in your browser:
- **Firefox**: Settings → Privacy & Security → View Certificates →
  Authorities → Import → select `caddy-local-ca.crt` → check "Trust this
  CA to identify websites".
- **Chrome/Edge**: System keychain (macOS Keychain Access /
  Windows MMC certmgr.msc / Linux `update-ca-certificates` after copying
  to `/usr/local/share/ca-certificates/`).

For production, replace the `tls internal` directive in
[`caddy/Caddyfile`](./caddy/Caddyfile) with a real CA (Let's Encrypt
or Tailscale-issued certs); the file has commented stubs showing how.

### 6. Create your first vault user

Visit `https://auth.apokryphos.local/admin` and sign in with the
bootstrap admin credentials from `.env`.

1. **Switch to the `vault` realm** (top-left realm dropdown).
2. Users → Add user → fill in username + email → Save.
3. Credentials tab → Set password → uncheck "Temporary" → Save.
4. Authentication → Required actions → ensure "Configure OTP" is
   enabled.
5. Have the user sign in for the first time at
   `https://auth.apokryphos.local/realms/vault/account` and enroll
   TOTP/WebAuthn.

### 7. Verify apokryphos-server end-to-end

The fastest sanity check: hit the server's authenticated probe.

```bash
# Without a token — expect a byte-identical 401
curl -i --cacert caddy-local-ca.crt https://api.apokryphos.local/api/whoami

# Expected: HTTP/2 401, body is exactly the 401 wire-image apokryphos-
# server emits (see specs/003-fapi-dpop-auth-core/contracts/).
```

A real PUT/GET/DELETE round-trip requires obtaining a DPoP-bound access
token, which is a multi-step flow (PKCE + PAR + DPoP proof generation).
That's the job of the future vault SPA; for now the conformance test
suite in `server/tests/conformance/` exercises that flow programmatically.

### 8. Rotate the bootstrap admin

Once you've confirmed everything works:

1. In the Keycloak master realm, create a new admin user with a strong
   password.
2. Delete the bootstrap admin user (the one named in `KC_BOOTSTRAP_ADMIN_USERNAME`).
3. Optionally clear `KC_BOOTSTRAP_ADMIN_PASSWORD` from `.env` — it's
   only read at first boot.

## Daily operations

### Restart a single service

```bash
docker compose restart apokryphos-server
```

### Rebuild after changing server code

```bash
docker compose build apokryphos-server && docker compose up -d apokryphos-server
```

### Tail logs

```bash
docker compose logs -f apokryphos-server
docker compose logs -f keycloak
```

### Back up state

Two volumes hold persistent state:
- `apokryphos_postgres_data` — Keycloak's realm + user database
- `apokryphos_apokryphos_blocks` — cypher-block storage

Stop the stack and use `docker run --rm -v <volume>:/data -v $(pwd):/backup
alpine tar -czf /backup/<volume>.tar.gz -C /data .`.

### Tear down (keeping data)

```bash
docker compose down
```

### Tear down (destroying data)

```bash
docker compose down -v
```

## Troubleshooting

### apokryphos-server exits at startup with "issuer URL"

The issuer URL in `apokryphos.toml` must match what Keycloak puts in
the `iss` claim of tokens. That's controlled by Keycloak's
`KC_HOSTNAME` env var (set in `compose.yaml` to
`https://auth.apokryphos.local`) and the realm name. If you changed
either, both sides must agree.

Quick check:

```bash
curl --cacert caddy-local-ca.crt https://auth.apokryphos.local/realms/vault/.well-known/openid-configuration | python3 -m json.tool | grep issuer
```

That value MUST equal the `issuer_url` in `apokryphos.toml`.

### apokryphos-server logs "JWKS overlap" at startup

FR-006 says the vault realm's signing keys must be cryptographically
disjoint from the admin realm's. This is satisfied automatically by
Keycloak's realms-per-audience model unless you've manually copied keys
between realms. To fix: delete one realm and re-import it (or rotate
its signing key via the admin UI → Realm Settings → Keys → Providers).

### apokryphos-server logs "JWKS fetch failed" / TLS error

The Caddy local CA root cert wasn't published. Check:

```bash
docker compose logs caddy-cert-publisher
docker compose exec apokryphos-server ls -la /etc/ssl/caddy/
```

You should see `caddy-local-ca.crt` mode 0644. If empty, the
caddy-cert-publisher service didn't run successfully — restart it:

```bash
docker compose up caddy-cert-publisher
docker compose restart apokryphos-server
```

### Keycloak hangs at startup

Keycloak 26.x is JVM-heavy and slow to start (~30–90s on a cold boot).
If it hangs longer, check:

```bash
docker compose logs keycloak | tail -50
```

Common causes: Postgres not healthy yet (compose dependency should
prevent this), out of memory (Keycloak wants ~1 GB heap), or the
realm-import JSON is malformed.

### "site not found" for Caddy routes

If the browser shows a Caddy 404 page, the FQDN didn't make it to
Caddy with a matching `Host:` header. Verify your `/etc/hosts` is
correct and the host's `:443` is mapped to the container.

## What's intentionally not included

- **HTTPS for `api.apokryphos.local` to apokryphos-server**: Caddy
  proxies plain HTTP to `apokryphos-server:8443` because the
  intra-network traffic is on a Docker bridge. If you want
  defense-in-depth in-network TLS, add a self-signed cert to
  apokryphos-server and update Caddy's reverse_proxy line accordingly.
- **Rate limiting / WAF**: Caddy can do this but the homelab default
  doesn't. Use the [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit)
  module if you expose this past your LAN.
- **Backup automation**: see the manual `docker run … tar -czf …`
  recipe above. Wrap it in cron or a systemd timer to suit.
- **Multi-host / HA Keycloak**: out of scope. Keycloak supports
  cluster mode with the same Postgres backing store if you outgrow
  a single node.
- **A real SMTP server**: Keycloak's password-reset flow needs one.
  Set `[realm] smtp_server.host = …` via the admin UI when you have
  one (e.g. a self-hosted maddy/postfix or a transactional provider).

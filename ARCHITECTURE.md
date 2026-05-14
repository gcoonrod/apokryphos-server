# Architecture

apokryphos-server is a 3-tier system: a reverse proxy at the edge, a stateless Rust API tier in the middle, and one or more decoupled single-page application (SPA) clients that the user interacts with. This document describes the **target** architecture; not every component exists in Phase 1, and a "Not in Phase 1" subsection at the end enumerates what is still to come.

## Topology

```
                ┌───────────────────┐         ┌───────────────────┐
   ┌───────┐    │                   │         │                   │    ┌──────────┐
   │ User  │──► │   Reverse Proxy   │ ──HTTP─►│    Rust API tier  │──► │ Storage  │
   │  +    │    │  (Nginx/Caddy)    │         │  (apokryphos-     │    │ (local   │
   │ SPA   │    │  TLS termination  │ ◄──HTTP─│   server binary)  │ ◄──│  FS / S3)│
   └───────┘    │  Static SPA assets│         │  Stateless        │    └──────────┘
       ▲        │  X-Forwarded-*    │         │  Single binary    │
       │        └───────────────────┘         └───────────────────┘
       │                  ▲
       │                  │
       └── static asset ──┘
           (vault-spa, admin-spa)
```

All traffic from the user is terminated at the reverse proxy. The proxy serves static SPA assets directly and forwards API requests to the Rust API tier. The Rust API tier is stateless and persists everything it needs through a `StorageProvider` abstraction, which is implemented over a local filesystem or S3-compatible object store.

## Tier descriptions

### 1. Reverse proxy

The reverse proxy is the user-facing component. It terminates TLS (the Rust API tier does not implement TLS itself), serves the two SPA bundles as static assets, and forwards `/api/...` requests to the Rust API tier. The proxy is also where FAPI 2.0–mandated TLS configuration lives.

Because the Rust API tier honors `X-Forwarded-For` and `X-Forwarded-Proto`, the proxy is responsible for setting those headers correctly and only for trusted upstream connections. Proxy trust configuration is part of the deployment artifacts. The binding rules: the default configuration MUST refuse forwarded headers from unknown sources, the upstream IP allowlist (or equivalent trust-boundary control) MUST be explicit and documented, and the server MUST NOT mandate native mTLS — TLS termination at the edge proxy is the supported deployment model.

### 2. Rust API tier (`server/`)

The Rust API tier is a single statically linked binary. It is stateless: any instance can serve any request, with no sticky sessions and no in-process caches that affect correctness. Horizontal scaling is just running more replicas.

The tier exposes a deliberately small and structure-free public surface: `/api/blocks/{id}` for opaque cypher-block storage, `/manifest` for the client-encrypted manifest blob, and the FAPI 2.0 + DPoP authentication endpoints. No endpoint reflects filenames, MIME types, or client-side hierarchy — the server is **blind**: it cannot interpret client data structure.

All cryptographic operations the server performs (DPoP signature validation, MAC comparisons, etc.) use constant-time primitives. All security-relevant lookups use constant-time comparisons. The server **never** parses or validates manifest contents.

The crate's source tree reserves locations for the three architectural concerns that will be filled in across Phase 2+:

- `server/src/auth/` — FAPI 2.0 + DPoP authentication (constitution Principle IV). Vault and admin authentication are cryptographically and logically isolated.
- `server/src/storage/` — the `StorageProvider` trait abstraction and at least two implementations (local filesystem, S3-compatible) (constitution Principle III).
- `server/src/routes/` — HTTP route definitions, generic and structure-free (constitution Principle II).

### 3. Decoupled SPAs (`clients/`)

Two separate SPAs interact with the API tier, kept cryptographically and logically isolated:

- **`vault-spa/`** — the end-user vault client. Owns all encryption, padding, key derivation (PBKDF2 / HKDF), and integrity construction. Downloads the encrypted manifest, decrypts it locally, and maps logical files to cypher-block IDs entirely in-browser. The server learns nothing about file names or folder structure from this SPA.
- **`admin-spa/`** — the operator's management UI. Uses a different audience, different token-signing keys, and a different session context than the vault SPA so that compromise of one surface cannot escalate to the other.

Both SPAs ship as static asset bundles served by the reverse proxy. They have no server-rendered components.

## Data flows

- **Cypher-block write**: `vault-spa` → reverse proxy → `PUT /api/blocks/{id}` → Rust API tier → `StorageProvider.put(id, payload)`. Payload size must match the deployment-configured fixed block size; non-conforming payloads are rejected.
- **Manifest update**: `vault-spa` decrypts the current manifest locally, mutates the in-memory representation, re-encrypts, and sends `PUT /manifest` with an `If-Match` ETag. The server compares the ETag, persists if it matches, and rejects with `412 Precondition Failed` otherwise. The server does not parse the manifest contents.
- **Authentication**: client requests an OIDC + FAPI 2.0 authorization code with PKCE, obtains DPoP-bound tokens, and presents them on every authenticated request. The server validates the DPoP proof using constant-time primitives.

## Not in Phase 1

The following components are part of the target architecture but **not** implemented in Phase 1 of this repository:

- **Reverse-proxy configuration** — `deploy/` contains only a placeholder marker. No `nginx.conf`, no `docker-compose.yaml`, no container images.
- **The Rust API tier's actual endpoints** — `server/src/routes/` is an empty placeholder module. No routes, no handlers.
- **The `StorageProvider` trait and its implementations** — `server/src/storage/` is an empty placeholder. No filesystem or S3 backend exists yet.
- **FAPI 2.0 + DPoP authentication flows** — `server/src/auth/` is an empty placeholder. `openidconnect` is declared in `Cargo.toml` but not yet wired up.
- **Static SPA bundles** — both `clients/vault-spa/` and `clients/admin-spa/` are empty placeholder directories. No framework choice has been made.
- **TLS termination, FAPI 2.0 conformance suite, ETag concurrency, block-size enforcement** — all gated by Phase 2+.

Each of these components has a dedicated future phase in the project plan and is fenced from Phase 1 by `spec.md` FR-016 and FR-017.

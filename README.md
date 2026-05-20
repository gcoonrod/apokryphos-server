# apokryphos-server

A zero-trust, "blind" block-storage server for end-to-end encrypted client vaults.

## What this is

apokryphos-server is the API tier of a self-hostable, zero-trust file vault. The server is deliberately **blind**: it never receives, processes, persists, or transmits unencrypted user data, plaintext file names, or any material sufficient to decrypt user content. All cryptographic operations happen in the client; the server is a high-availability bucket for opaque, fixed-size cypher-blocks. There is no password recovery, no key escrow, no administrative decryption path — if a client loses its key, the only administrative action available is a destructive quota-resetting purge of the affected vault.

This repository is in **Phase 1: scaffolding**. The Rust binary compiles and runs but ships no functional application logic, route handlers, authentication flows, persistence operations, or cryptographic execution. Phase 2+ will add those, gated by five non-negotiable design principles: zero-trust / blind server, side-channel resistance, stateless single-binary architecture, FAPI 2.0 + DPoP authentication, and a client-authoritative manifest contract.

## Repository layout

- **`server/`** — the Rust API crate plus its production `Dockerfile`. A single binary is produced for deployment (glibc-linked against `debian:bookworm-slim`; switch to a `*-musl` Rust target if you need a fully static build).
- **`clients/vault-spa/`** — placeholder for the reference end-user vault SPA.
- **`clients/admin-spa/`** — placeholder for the administrative management SPA.
- **`deploy/`** — homelab reference deployment: `docker compose` stack with Caddy, Keycloak 26.6 (FAPI 2.0 + DPoP), Postgres, and apokryphos-server. See `deploy/README.md` for the first-boot walkthrough.

## Build the server

From the repository root:

```bash
cd server
cargo build
```

To run the (deliberately minimal) Phase 1 binary, which initializes structured tracing and emits a single startup event before exiting:

```bash
cargo run
```

You should see a single `tracing` line with the message `apokryphos-server scaffold initialized` and an exit code of `0`.

### Versions verified at scaffold time

| Component | Version | Source of truth |
|-----------|---------|------------------|
| Rust toolchain (rustc) | 1.95.0 (stable) | `rustc --version` at scaffold time |
| MSRV (declared) | 1.95 | `server/Cargo.toml` `rust-version` field |
| tokio | 1.52 | `server/Cargo.toml` |
| axum | 0.8 | `server/Cargo.toml` |
| serde | 1.0 | `server/Cargo.toml` |
| tracing | 0.1 | `server/Cargo.toml` |
| tracing-subscriber | 0.3 | `server/Cargo.toml` |
| openidconnect | 4.0 | `server/Cargo.toml` |
| rusqlite | 0.39 | `server/Cargo.toml` |

These versions were last validated on **2026-05-14**. Contributors using newer minor versions are welcome but should re-run `cargo build` from a clean checkout to confirm.

## Further reading

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — the planned 3-tier topology (reverse proxy → Rust API → decoupled SPAs).
- **[SECURITY.md](./SECURITY.md)** — how to privately report a vulnerability via GitHub Private Security Advisories.
- **[LICENSE](./LICENSE)** — full license text. The project is licensed under **Apache-2.0**.

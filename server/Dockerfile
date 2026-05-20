# Multi-stage build for apokryphos-server.
#
# Stage 1 (`builder`): pinned Rust toolchain matching server/Cargo.toml's
# `rust-version = "1.95"`. We deliberately do NOT use `--features test-utils`
# here — that gate is for the test/dev surface, and the production binary
# must exclude `rsa`/`p256`/`rand` (Phase 3 test-utils-gated optional deps
# pattern; see server/Cargo.toml `[features]` block).
#
# Stage 2 (runtime): minimal `debian:bookworm-slim` so the operator has
# `bash` + `ca-certificates` for ad-hoc inspection. We don't use `scratch`
# or `distroless` here because:
#   - `rusqlite` is built with the `bundled` feature, so we link statically
#     against SQLite; no system libsqlite3 needed.
#   - `ca-certificates` is required for TLS verification when openidconnect
#     reaches out to the discovery + JWKS endpoints over HTTPS.
#   - Operators in homelab contexts benefit from being able to `docker exec`
#     in and curl their own discovery endpoints during initial setup.
#
# Build context: repo root (the `deploy/compose.yaml` file points
# `build.context: ..` so the Cargo.lock at server/ is reachable).

ARG RUST_VERSION=1.95
ARG DEBIAN_VERSION=bookworm-slim

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /build

# Copy the crate manifest + lockfile FIRST so Docker can cache the
# crate-registry download (NOT compiled deps — `cargo fetch` only
# populates ~/.cargo/registry with crate tarballs; dependency
# compilation happens in the `cargo build` step below alongside
# application code, so any source change re-triggers it). The cached
# fetch layer just saves the network round-trip on rebuilds. Operators
# who want true incremental dep caching can switch to `cargo-chef` or
# a stub-compile pattern; for a homelab reference Dockerfile, the
# fetch-only caching is good enough.
COPY server/Cargo.toml server/Cargo.lock ./
# Bring in the test files BEFORE `cargo fetch`. Cargo parses the full
# manifest and validates every `[[test]] path = "..."` exists, even
# under `cargo fetch` (which only downloads to the registry — no build).
# The workspace-level conformance test at server/Cargo.toml's
# `path = "../tests/conformance/main.rs"` requires `tests/conformance/`
# at the build root too, so we copy both trees.
COPY server/tests ./tests
COPY tests /tests
# Stub `src/main.rs` so the manifest parse + fetch succeeds without the
# real source. The real `src/` is copied in the next layer.
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    cargo fetch --locked

# Now bring in the real source. The registry-download layer above
# stays cached as long as Cargo.{toml,lock} and `tests/` are unchanged.
COPY server/src ./src

# Production build — NO test-utils feature. The release profile inherits
# the default opt-level (3) + LTO settings from Cargo.toml.
RUN cargo build --release --locked

# ----------------------------------------------------------------------------

FROM debian:${DEBIAN_VERSION} AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Non-root runtime user. The numeric UID/GID are stable so volume mounts
# from the host can be pre-chowned by the operator.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --system --gid ${APP_GID} apokryphos && \
    useradd  --system --uid ${APP_UID} --gid ${APP_GID} \
             --home /var/lib/apokryphos --no-create-home apokryphos

# Storage root for the LocalFs backend. Mount-point for a host volume in
# production; the directory must exist + be writable by the apokryphos user.
RUN mkdir -p /var/lib/apokryphos/blocks && \
    chown -R apokryphos:apokryphos /var/lib/apokryphos

COPY --from=builder /build/target/release/apokryphos-server /usr/local/bin/apokryphos-server

USER apokryphos
WORKDIR /var/lib/apokryphos

# The server reads config from APOK_CONFIG_PATH and/or APOK_* env vars.
# `deploy/compose.yaml` mounts a host TOML file and points APOK_CONFIG_PATH
# at the in-container path.
ENV RUST_LOG=info
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/apokryphos-server"]

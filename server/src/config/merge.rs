//! Env-overrides-file precedence (R14, invariant C5). Per-key, not per-table.

use super::env::{PartialAuth, PartialConfig, PartialOidc, PartialStorage, PartialStorageLocalFs};

pub fn env_overrides_file(env: PartialConfig, file: PartialConfig) -> PartialConfig {
    PartialConfig {
        bind_address: env.bind_address.or(file.bind_address),
        block_size_bytes: env.block_size_bytes.or(file.block_size_bytes),
        storage_backend: env.storage_backend.or(file.storage_backend),
        storage: merge_storage(env.storage, file.storage),
        trusted_proxies: env.trusted_proxies.or(file.trusted_proxies),
        drain_timeout_secs: env.drain_timeout_secs.or(file.drain_timeout_secs),
        vault_oidc: merge_oidc(env.vault_oidc, file.vault_oidc),
        admin_oidc: merge_oidc(env.admin_oidc, file.admin_oidc),
        auth: merge_auth(env.auth, file.auth),
    }
}

fn merge_storage(
    env: Option<PartialStorage>,
    file: Option<PartialStorage>,
) -> Option<PartialStorage> {
    match (env, file) {
        (Some(e), Some(f)) => Some(PartialStorage {
            local_fs: merge_local_fs(e.local_fs, f.local_fs),
        }),
        (Some(e), None) => Some(e),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    }
}

fn merge_local_fs(
    env: Option<PartialStorageLocalFs>,
    file: Option<PartialStorageLocalFs>,
) -> Option<PartialStorageLocalFs> {
    match (env, file) {
        (Some(e), Some(f)) => Some(PartialStorageLocalFs {
            root: e.root.or(f.root),
        }),
        (Some(e), None) => Some(e),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    }
}

fn merge_oidc(env: Option<PartialOidc>, file: Option<PartialOidc>) -> Option<PartialOidc> {
    match (env, file) {
        (Some(e), Some(f)) => Some(PartialOidc {
            issuer_url: e.issuer_url.or(f.issuer_url),
            audience: e.audience.or(f.audience),
        }),
        (Some(e), None) => Some(e),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    }
}

fn merge_auth(env: Option<PartialAuth>, file: Option<PartialAuth>) -> Option<PartialAuth> {
    match (env, file) {
        (Some(e), Some(f)) => Some(PartialAuth {
            clock_skew_secs: e.clock_skew_secs.or(f.clock_skew_secs),
            dpop_freshness_secs: e.dpop_freshness_secs.or(f.dpop_freshness_secs),
            jwks_refresh_secs: e.jwks_refresh_secs.or(f.jwks_refresh_secs),
            discovery_refresh_secs: e.discovery_refresh_secs.or(f.discovery_refresh_secs),
            on_demand_refresh_min_interval_secs: e
                .on_demand_refresh_min_interval_secs
                .or(f.on_demand_refresh_min_interval_secs),
            jti_replay_window_secs: e.jti_replay_window_secs.or(f.jti_replay_window_secs),
            max_replay_entries: e.max_replay_entries.or(f.max_replay_entries),
        }),
        (Some(e), None) => Some(e),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    }
}

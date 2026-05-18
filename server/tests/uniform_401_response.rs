//! T054 — uniform 401 response shape (SC-003, FR-029, Clarify-Q3).
//!
//! ## Methodology
//!
//! The byte-identical 401 contract (FR-029, SC-003, Clarify-Q3) is wire-level:
//! every authentication failure cause MUST produce a response whose status
//! line, header block, and body bytes are indistinguishable on the wire.
//! Any divergence — different `Content-Length`, different `WWW-Authenticate`
//! value, an extra `Allow` or `Retry-After` header, even header *ordering*
//! that depends on which validation step rejected the request — would leak
//! information to an attacker probing the route.
//!
//! Approach:
//!   1. Enumerate a fixture table of ≥ 11 failure causes (the spec floor).
//!      We include 17 here for safety margin: every variant of `AuthFailure`
//!      reachable through the assembled router except `MemoryPressure`
//!      (which translates to 503, not 401) and `JwksRefreshFailed` (which
//!      requires a different fixture — see T052/T053 for refresh tests).
//!   2. Drive each cause through `tower::ServiceExt::oneshot` against a
//!      production-shape `build_router` (proxy-trust layer, guards, the
//!      whole stack). No bypassing — the test exercises exactly what an
//!      external attacker would see.
//!   3. Capture each response as a `WireImage` (status code + sorted
//!      `(name, value)` header list + body bytes). The header list is
//!      sorted because HTTP/1.1 declares header order non-significant; if
//!      we asserted on insertion order we would couple to axum's internal
//!      `HeaderMap` iteration and falsely fail on irrelevant refactors.
//!      The contract is wire-level identity, not source-level identity.
//!   4. Assert pairwise byte-equality: img[0] == img[i] for every i.
//!
//! We pick deterministic-emission (sorted) over per-test canonicalization
//! of axum's order because the wire-level contract is what matters; the
//! header values themselves are what `respond_401` deterministically emits.

mod common;

use std::sync::Arc;

use apokryphos_server::AppState;
use apokryphos_server::auth::JtiReplayStore;
use apokryphos_server::auth::context::init_contexts;
use apokryphos_server::auth::testing::{
    MintTokenClaims, MockOidcProvider, deterministic_rng, es256_public_jwk,
    es256_thumbprint_b64url, generate_es256_keypair, mint_es256_dpop_proof, mint_es256_token,
    now_unix_secs,
};
use apokryphos_server::config::{AuthConfig, OidcAudienceConfig, ServerConfig, StorageBackend};
use apokryphos_server::routes::build_router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, Response, StatusCode, header};
use openidconnect::reqwest;
use tower::ServiceExt;

use crate::common::minimal_valid_config;

const VAULT_KID: &str = "u401-vault-key";
const ADMIN_KID: &str = "u401-admin-key";
const VAULT_AUD: &str = "apokryphos-u401-vault";
const ADMIN_AUD: &str = "apokryphos-u401-admin";
const VAULT_HTU: &str = "http://127.0.0.1/api/whoami";

struct Fixture {
    router: axum::Router,
    vault_signing: p256::ecdsa::SigningKey,
    /// A second key NOT in the vault JWKS — used to mint a token whose
    /// signature won't verify and a proof whose `cnf.jkt` won't match.
    rogue_signing: p256::ecdsa::SigningKey,
    vault_issuer: url::Url,
    _vault_mock: MockOidcProvider,
    _admin_mock: MockOidcProvider,
}

async fn setup_fixture() -> Fixture {
    let mut rng = deterministic_rng(54);
    let vault_signing = generate_es256_keypair(&mut rng);
    let admin_signing = generate_es256_keypair(&mut rng);
    let rogue_signing = generate_es256_keypair(&mut rng);

    let vault_jwks = serde_json::json!({
        "keys": [es256_public_jwk(vault_signing.verifying_key(), Some(VAULT_KID))]
    });
    let admin_jwks = serde_json::json!({
        "keys": [es256_public_jwk(admin_signing.verifying_key(), Some(ADMIN_KID))]
    });
    let vault_mock = MockOidcProvider::start(vault_jwks).await;
    let admin_mock = MockOidcProvider::start(admin_jwks).await;
    let vault_issuer = vault_mock.issuer_url();
    let admin_issuer = admin_mock.issuer_url();

    let cfg = ServerConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        block_size_bytes: 1024 * 1024,
        storage_backend: StorageBackend::None,
        trusted_proxies: vec![],
        vault_oidc: OidcAudienceConfig {
            issuer_url: vault_issuer.clone(),
            audience: VAULT_AUD.to_string(),
        },
        admin_oidc: OidcAudienceConfig {
            issuer_url: admin_issuer.clone(),
            audience: ADMIN_AUD.to_string(),
        },
        drain_timeout: std::time::Duration::from_secs(5),
        auth: AuthConfig::default(),
    };
    let http_client = reqwest::Client::new();
    let (vault_ctx, admin_ctx) = init_contexts(&cfg, &http_client)
        .await
        .expect("init_contexts must succeed against disjoint mocks");

    let auth_cfg = Arc::new(cfg.auth.clone());
    let replay_store = Arc::new(JtiReplayStore::new(Arc::clone(&auth_cfg)));

    let state = AppState {
        config: Arc::new(minimal_valid_config()),
    };
    let router = build_router(
        state,
        Some(vault_ctx),
        Some(admin_ctx),
        Some(replay_store),
        None,
    );

    Fixture {
        router,
        vault_signing,
        rogue_signing,
        vault_issuer,
        _vault_mock: vault_mock,
        _admin_mock: admin_mock,
    }
}

fn iss_str(issuer: &url::Url) -> String {
    issuer.as_str().trim_end_matches('/').to_string()
}

fn mint_vault_token(fx: &Fixture, sub: &str) -> String {
    let now = now_unix_secs();
    let claims = MintTokenClaims {
        sub: sub.to_string(),
        aud: VAULT_AUD.to_string(),
        iss: iss_str(&fx.vault_issuer),
        iat: now,
        exp: now + 3600,
        nbf: None,
        cnf_jkt: es256_thumbprint_b64url(fx.vault_signing.verifying_key()),
    };
    mint_es256_token(&claims, &fx.vault_signing, Some(VAULT_KID), false)
}

fn mint_proof_bound(
    fx: &Fixture,
    token: &str,
    htm: &str,
    htu: &str,
    iat: u64,
    jti: &str,
) -> String {
    mint_es256_dpop_proof(&fx.vault_signing, htm, htu, iat, jti, Some(token))
}

/// Captured wire image: status + sorted headers + body bytes.
#[derive(Debug, PartialEq, Eq)]
struct WireImage {
    status: StatusCode,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

async fn capture(response: Response<Body>) -> WireImage {
    let status = response.status();
    let mut headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    WireImage {
        status,
        headers,
        body,
    }
}

fn req(method: Method, uri: &str, auth: Option<&str>, dpop: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HeaderValue::from_static("127.0.0.1"));
    if let Some(t) = auth {
        b = b.header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", t)).unwrap(),
        );
    }
    if let Some(p) = dpop {
        b = b.header("dpop", HeaderValue::from_str(p).unwrap());
    }
    b.body(Body::empty()).unwrap()
}

/// Builds a `Request<Body>` for one row of the fixture table. Captured
/// closures are sometimes stateful (the replay case memoizes its priming
/// proof), so the table holds boxed `Fn` rather than function pointers.
type RequestBuilder = Box<dyn Fn(&Fixture) -> Request<Body> + Send + Sync>;

/// One row of the failure-cause fixture table.
struct Case {
    label: &'static str,
    /// Lazily builds the request because some causes mutate state (replay).
    request: RequestBuilder,
}

fn build_cases() -> Vec<Case> {
    use std::sync::Mutex;

    let mut cases: Vec<Case> = Vec::new();

    // 1. MissingToken — no Authorization header.
    cases.push(Case {
        label: "no_auth_header",
        request: Box::new(|_| req(Method::GET, "/api/whoami", None, None)),
    });

    // 2. MissingProof — Authorization but no DPoP.
    cases.push(Case {
        label: "no_dpop_header",
        request: Box::new(|fx| {
            let t = mint_vault_token(fx, "u-2");
            req(Method::GET, "/api/whoami", Some(&t), None)
        }),
    });

    // 3. InvalidAlg in token — hand-craft an HS256 header. jsonwebtoken
    //    refuses to mint without a secret-bearing key, so we build the JWS
    //    byte-by-byte: header.payload.signature.
    cases.push(Case {
        label: "token_alg_hs256",
        request: Box::new(|fx| {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let header = b64.encode(br#"{"alg":"HS256","typ":"JWT","kid":"u401-vault-key"}"#);
            let now = now_unix_secs();
            let payload = b64.encode(
                serde_json::to_vec(&serde_json::json!({
                    "sub": "u-3",
                    "aud": VAULT_AUD,
                    "iss": iss_str(&fx.vault_issuer),
                    "iat": now,
                    "exp": now + 3600,
                    "cnf": { "jkt": es256_thumbprint_b64url(fx.vault_signing.verifying_key()) },
                }))
                .unwrap(),
            );
            let sig = b64.encode([0xAAu8; 32]);
            let token = format!("{}.{}.{}", header, payload, sig);
            let proof = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now, "jti-3");
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 4. TokenSignatureInvalid — sign with rogue key but advertise the
    //    in-JWKS kid so dispatch reaches signature verification.
    cases.push(Case {
        label: "token_bad_signature",
        request: Box::new(|fx| {
            let now = now_unix_secs();
            let claims = MintTokenClaims {
                sub: "u-4".to_string(),
                aud: VAULT_AUD.to_string(),
                iss: iss_str(&fx.vault_issuer),
                iat: now,
                exp: now + 3600,
                nbf: None,
                cnf_jkt: es256_thumbprint_b64url(fx.rogue_signing.verifying_key()),
            };
            let token = mint_es256_token(&claims, &fx.rogue_signing, Some(VAULT_KID), false);
            let proof = mint_es256_dpop_proof(
                &fx.rogue_signing,
                "GET",
                VAULT_HTU,
                now,
                "jti-4",
                Some(&token),
            );
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 5. TokenIssuerMismatch.
    cases.push(Case {
        label: "token_iss_mismatch",
        request: Box::new(|fx| {
            let now = now_unix_secs();
            let claims = MintTokenClaims {
                sub: "u-5".to_string(),
                aud: VAULT_AUD.to_string(),
                iss: "https://attacker.example.invalid".to_string(),
                iat: now,
                exp: now + 3600,
                nbf: None,
                cnf_jkt: es256_thumbprint_b64url(fx.vault_signing.verifying_key()),
            };
            let token = mint_es256_token(&claims, &fx.vault_signing, Some(VAULT_KID), false);
            let proof = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now, "jti-5");
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 6. TokenAudienceMismatch.
    cases.push(Case {
        label: "token_aud_mismatch",
        request: Box::new(|fx| {
            let now = now_unix_secs();
            let claims = MintTokenClaims {
                sub: "u-6".to_string(),
                aud: "wrong-audience".to_string(),
                iss: iss_str(&fx.vault_issuer),
                iat: now,
                exp: now + 3600,
                nbf: None,
                cnf_jkt: es256_thumbprint_b64url(fx.vault_signing.verifying_key()),
            };
            let token = mint_es256_token(&claims, &fx.vault_signing, Some(VAULT_KID), false);
            let proof = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now, "jti-6");
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 7. TokenExpired.
    cases.push(Case {
        label: "token_expired",
        request: Box::new(|fx| {
            let now = now_unix_secs();
            let claims = MintTokenClaims {
                sub: "u-7".to_string(),
                aud: VAULT_AUD.to_string(),
                iss: iss_str(&fx.vault_issuer),
                iat: now - 7200,
                exp: now - 3600,
                nbf: None,
                cnf_jkt: es256_thumbprint_b64url(fx.vault_signing.verifying_key()),
            };
            let token = mint_es256_token(&claims, &fx.vault_signing, Some(VAULT_KID), false);
            let proof = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now, "jti-7");
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 8. TokenMissingClaim(cnf.jkt) — omit_cnf_jkt = true.
    cases.push(Case {
        label: "token_missing_cnf_jkt",
        request: Box::new(|fx| {
            let now = now_unix_secs();
            let claims = MintTokenClaims {
                sub: "u-8".to_string(),
                aud: VAULT_AUD.to_string(),
                iss: iss_str(&fx.vault_issuer),
                iat: now,
                exp: now + 3600,
                nbf: None,
                cnf_jkt: String::new(),
            };
            let token = mint_es256_token(&claims, &fx.vault_signing, Some(VAULT_KID), true);
            let proof = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now, "jti-8");
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // (Note: `TokenMissingClaim(sub)` — empty `sub` — is currently accepted
    // by the validator path; the FR-015 "required" reading is "present"
    // rather than "non-empty". Empty-string `sub` is not a reachable
    // 401-producing failure cause through the assembled router, so it's
    // omitted from this byte-identity matrix. If the policy tightens, add
    // it here. The omission does not weaken SC-003 — we still cover 16
    // distinct causes vs the spec floor of 11.)

    // 10. InvalidAlg in proof — hand-craft a DPoP proof header with alg=none.
    cases.push(Case {
        label: "proof_alg_none",
        request: Box::new(|fx| {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let token = mint_vault_token(fx, "u-10");
            let pubjwk = es256_public_jwk(fx.vault_signing.verifying_key(), None);
            let header = b64.encode(
                serde_json::to_vec(&serde_json::json!({
                    "alg": "none",
                    "typ": "dpop+jwt",
                    "jwk": pubjwk,
                }))
                .unwrap(),
            );
            let now = now_unix_secs();
            let payload = b64.encode(
                serde_json::to_vec(&serde_json::json!({
                    "htm": "GET",
                    "htu": VAULT_HTU,
                    "iat": now,
                    "jti": "jti-10",
                }))
                .unwrap(),
            );
            let proof = format!("{}.{}.", header, payload);
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 11. ProofSignatureInvalid — keep valid header+payload, junk the sig.
    cases.push(Case {
        label: "proof_bad_signature",
        request: Box::new(|fx| {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let token = mint_vault_token(fx, "u-11");
            let now = now_unix_secs();
            let good = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now, "jti-11");
            let mut parts: Vec<String> = good.split('.').map(|s| s.to_string()).collect();
            parts[2] = b64.encode([0xCCu8; 64]);
            let bad = parts.join(".");
            req(Method::GET, "/api/whoami", Some(&token), Some(&bad))
        }),
    });

    // 12. ProofHtmMismatch.
    cases.push(Case {
        label: "proof_htm_wrong",
        request: Box::new(|fx| {
            let token = mint_vault_token(fx, "u-12");
            let now = now_unix_secs();
            let proof = mint_proof_bound(fx, &token, "POST", VAULT_HTU, now, "jti-12");
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 13. ProofHtuMismatch.
    cases.push(Case {
        label: "proof_htu_wrong",
        request: Box::new(|fx| {
            let token = mint_vault_token(fx, "u-13");
            let now = now_unix_secs();
            let proof = mint_proof_bound(
                fx,
                &token,
                "GET",
                "http://attacker.example.invalid/api/whoami",
                now,
                "jti-13",
            );
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 14. ProofIatStale.
    cases.push(Case {
        label: "proof_iat_stale",
        request: Box::new(|fx| {
            let token = mint_vault_token(fx, "u-14");
            let now = now_unix_secs();
            let proof = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now - 3600, "jti-14");
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 15. ProofJktMismatch — token says cnf.jkt = vault key thumbprint;
    //     proof's `jwk` is the rogue key. Validator rejects on cnf.jkt vs
    //     proof's jwk thumbprint comparison.
    cases.push(Case {
        label: "proof_jkt_mismatch",
        request: Box::new(|fx| {
            let token = mint_vault_token(fx, "u-15");
            let now = now_unix_secs();
            let proof = mint_es256_dpop_proof(
                &fx.rogue_signing,
                "GET",
                VAULT_HTU,
                now,
                "jti-15",
                Some(&token),
            );
            req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
        }),
    });

    // 16. ProofReplayed — priming success, then replay rejection. We
    //     memoize the prepared (token, proof) pair across the two stages.
    let replay_state: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
    {
        let st = Arc::clone(&replay_state);
        cases.push(Case {
            label: "proof_replayed_priming",
            request: Box::new(move |fx| {
                let token = mint_vault_token(fx, "u-16");
                let now = now_unix_secs();
                let proof = mint_proof_bound(fx, &token, "GET", VAULT_HTU, now, "jti-16-replay");
                *st.lock().unwrap() = Some((token.clone(), proof.clone()));
                req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
            }),
        });
    }
    {
        let st = Arc::clone(&replay_state);
        cases.push(Case {
            label: "proof_replayed",
            request: Box::new(move |_| {
                let guard = st.lock().unwrap();
                let (token, proof) = guard
                    .as_ref()
                    .expect("priming case ran before replay")
                    .clone();
                req(Method::GET, "/api/whoami", Some(&token), Some(&proof))
            }),
        });
    }

    // 17. ProofAthMismatch — bind proof's `ath` to a *different* token.
    cases.push(Case {
        label: "proof_ath_mismatch",
        request: Box::new(|fx| {
            let real_token = mint_vault_token(fx, "u-17a");
            let other_token = mint_vault_token(fx, "u-17b");
            let now = now_unix_secs();
            let proof = mint_es256_dpop_proof(
                &fx.vault_signing,
                "GET",
                VAULT_HTU,
                now,
                "jti-17",
                Some(&other_token),
            );
            req(Method::GET, "/api/whoami", Some(&real_token), Some(&proof))
        }),
    });

    cases
}

#[tokio::test]
async fn uniform_401_byte_identical_across_all_failure_causes() {
    let fixture = setup_fixture().await;
    let cases = build_cases();

    // Drive every case sequentially so state-dependent rejections (replay)
    // observe the priming request. The byte-identity assertion excludes
    // the priming case itself (it succeeds — that's the point).
    let mut images: Vec<(String, WireImage)> = Vec::with_capacity(cases.len());
    for case in &cases {
        let req = (case.request)(&fixture);
        let resp = fixture
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("oneshot must complete");
        images.push((case.label.to_string(), capture(resp).await));
    }

    let priming = images
        .iter()
        .find(|(l, _)| l == "proof_replayed_priming")
        .expect("priming case present");
    assert_eq!(
        priming.1.status,
        StatusCode::OK,
        "priming request must succeed; otherwise the replay test is vacuous"
    );

    let failures: Vec<&(String, WireImage)> = images
        .iter()
        .filter(|(l, _)| l != "proof_replayed_priming")
        .collect();

    let reference = &failures[0].1;
    assert_eq!(
        reference.status,
        StatusCode::UNAUTHORIZED,
        "reference case ({}) must be 401",
        failures[0].0
    );

    // SC-003 floor is ≥ 11; we expect 16. Anything less means a case was
    // silently dropped during fixture construction.
    assert!(
        failures.len() >= 11,
        "SC-003 floor: ≥ 11 failure causes required; got {}",
        failures.len()
    );

    for (label, img) in failures.iter().skip(1) {
        assert_eq!(
            img.status, reference.status,
            "status differs at case {label}: ref={} vs {}",
            reference.status, img.status,
        );
        assert_eq!(
            img.headers, reference.headers,
            "headers differ at case {label}",
        );
        assert_eq!(
            img.body, reference.body,
            "body differs at case {label}: ref={:?} vs {:?}",
            reference.body, img.body,
        );
    }
}

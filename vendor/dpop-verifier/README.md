
# Dpop Verifier

A tiny DPoP proof verifier for Rust:
- ES256/P-256
- EdDSA/Ed25519 (with feature "eddsa")
- Manual claim checks (htm/htu/iat/ath)
- Pluggable replay store (DB/Redis/etc.)
- DPoP-Nonce support
- Optional client binding for per-client replay protection
- Optional Actix helper to canonicalize request URL

Made this small crate for my own needs. If you feel it's lacking or is missing something and/or does not actually follow the spec etc. feel free to open an issue.

## Install

Crates.io
```toml
[dependencies]
dpop-verifier = { version = "4.1.0", features = ["actix-web", "eddsa"] }
```

Git
```toml
[dependencies]
dpop-verifier = { git = "https://github.com/ukonhattu/dpop-verifier"} # Recommend setting tag/commit
```

## Quick start (framework-agnostic)

```rust
use dpop_verifier::{DpopVerifier, ReplayStore, ReplayContext, DpopError};

struct MyStore;

#[async_trait::async_trait]
impl ReplayStore for MyStore { // Use your own store like DB or Redis
    async fn insert_once(
        &mut self,
        _jti_hash: [u8; 32],
        _ctx: ReplayContext<'_>,
    ) -> Result<bool, DpopError> {
        // Return true if first time seeing this jti_hash within your TTL, else false.
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Read the DPoP header value from the inbound HTTP request
    let dpop = "..."; // compact JWS from `DPoP:` header

    // 2) Provide the *externally visible* request target (scheme/host[:port]/path) and method
    let expected_htu = "https://example.com/api/token";
    let expected_htm = "POST";

    // 3) If verifying at a Resource Server with an access token, pass it here (binds `ath`)
let access_token = None::<&str>;
// Optional: bind proofs to an OAuth client identifier to prevent cross-client replays
let client_id = None::<String>;

// 4) Create a verifier with your desired options (builder pattern)
let mut verifier = DpopVerifier::new()
        .with_max_age_seconds(300)       // 300s max age
        .with_future_skew_seconds(5);    // 5s future skew tolerance

if let Some(client_id) = client_id {
    verifier = verifier.with_client_binding(client_id);
}

    // 5) Verify proof and record its `jti` (via your `ReplayStore`)
    let mut store = MyStore;
    let verified = verifier
        .verify(&mut store, dpop, expected_htu, expected_htm, access_token)
        .await?;

    println!("DPoP key thumbprint (jkt): {}", verified.jkt);
    Ok(())
}
```

## Stateless nonce (recommended): `NonceMode::Hmac`
No DB needed. The verifier will issue a fresh nonce for you (in the error) and verify it on the next request. Bind the nonce to htu/htm/and the DPoP key (jkt).

```rust
use std::sync::Arc;
use dpop_verifier::{DpopVerifier, NonceMode, DpopError};
#[cfg(feature="actix-web")]
use dpop_verifier::actix_helpers::{dpop_header_str, expected_htu_from_actix};

fn client_id_for_request(_req: &actix_web::HttpRequest) -> Option<String> {
    // Look up the client identifier associated with this request (OAuth client_id, etc.)
    None
}

struct App {
    dpop_secret: Arc<[u8]>, // keep in app state; rotate periodically
}

// Resource Server (Actix example)
async fn protected(req: actix_web::HttpRequest, app: actix_web::web::Data<App>)
    -> actix_web::HttpResponse
{
    let dpop = match dpop_header_str(&req) {
        Ok(s) => s,
        Err(_) => return actix_web::HttpResponse::Unauthorized().finish(),
    };
    let expected_htu = expected_htu_from_actix(&req, false);
    let expected_htm = req.method().as_str();

    // Create verifier with HMAC nonce mode
    // If you also have an access token, pass it as Some(token) to bind `ath`.
    let mut verifier = DpopVerifier::new()
        .with_max_age_seconds(300)
        .with_future_skew_seconds(5)
        .with_nonce_mode(NonceMode::Hmac {
            secret: app.dpop_secret.clone(),
            max_age_seconds: 300,
            bind_htu_htm: true,
            bind_jkt: true,
            bind_client: true,
        });

    if let Some(client_id) = client_id_for_request(&req) {
        verifier = verifier.with_client_binding(client_id);
    }

    match verifier.verify(&mut (), dpop, &expected_htu, expected_htm, None).await {
        Ok(verified) => {
            // OK: verified.jkt is the key thumbprint bound to this request
            actix_web::HttpResponse::Ok().finish()
        }
        Err(DpopError::UseDpopNonce { nonce }) => {
            // Tell the client to retry with this nonce
            actix_web::HttpResponse::Unauthorized()
                .insert_header(("DPoP-Nonce", nonce))
                .insert_header(("WWW-Authenticate", r#"DPoP error="use_dpop_nonce", algs="ES256""#))
                .insert_header(("Access-Control-Expose-Headers", "WWW-Authenticate, DPoP-Nonce"))
                .finish()
        }
        Err(_) => actix_web::HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", r#"DPoP error="invalid_dpop_proof""#))
            .finish(),
    }
}

```

## Stateful nonce (string equality): `NonceMode::RequireEqual`
If you already issue/store a nonce per client/session, require exact equality. (No context binding here; use HMAC mode if you want binding to htu/htm/jkt.)

```rust
use dpop_verifier::{DpopVerifier, NonceMode, DpopError};

// Pseudo: fetch the previously issued nonce for this client/session
fn load_expected_nonce(user_id: &str) -> Option<String> { /* ... */ None }
fn issue_and_store_nonce(user_id: &str) -> String { /* random string, store */ "n123".into() }

async fn protected(req: actix_web::HttpRequest, user_id: String) -> actix_web::HttpResponse {
    let dpop = /* read DPoP header */ match req.headers().get("DPoP").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return actix_web::HttpResponse::Unauthorized().finish(),
    };
    let expected_htu = format!("https://example.com{}", req.uri().path());
    let expected_htm = req.method().as_str();

    let expected = match load_expected_nonce(&user_id) {
        Some(n) => n,
        None => {
            let fresh = issue_and_store_nonce(&user_id);
            return actix_web::HttpResponse::Unauthorized()
                .insert_header(("DPoP-Nonce", fresh))
                .insert_header(("WWW-Authenticate", r#"DPoP error="use_dpop_nonce", algs="ES256""#))
                .finish();
        }
    };

    let verifier = DpopVerifier::new()
        .with_max_age_seconds(300)
        .with_future_skew_seconds(5)
        .with_nonce_mode(NonceMode::RequireEqual {
            expected_nonce: expected.clone()
        });

    match verifier.verify(&mut (), dpop, &expected_htu, expected_htm, None).await {
        Ok(_) => actix_web::HttpResponse::Ok().finish(),
        Err(DpopError::UseDpopNonce { .. }) | Err(DpopError::MissingNonce) => {
            // Mismatch or missing -> issue a fresh one for the next try
            let fresh = issue_and_store_nonce(&user_id);
            actix_web::HttpResponse::Unauthorized()
                .insert_header(("DPoP-Nonce", fresh))
                .insert_header(("WWW-Authenticate", r#"DPoP error="use_dpop_nonce", algs="ES256""#))
                .finish()
        }
        Err(_) => actix_web::HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", r#"DPoP error="invalid_dpop_proof""#))
            .finish(),
    }
}

```

## Some notes on nonce
Notes

- In HMAC mode, you usually don’t pre-issue a nonce—the verifier will return UseDpopNonce { nonce } when needed, and you just forward that value.
- Set `bind_client: true` and call `.with_client_binding(..)` if you want the nonce to be scoped to a particular OAuth client.

Always expose `WWW-Authenticate` / `DPoP-Nonce` to browsers:

```http
Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce
```
- To bind ath on a Resource Server, call verify_proof(..., Some(access_token), ...).

- For non-Actix stacks, compute:

    * `expected_htu` = externally visible scheme://host[:port]/path (no query/fragment),

    * `expected_htm` = request method string ("GET", "POST", ...).

## Actix helpers

Enable ["actix-web"] feature

```rust
use dpop_verifier::DpopVerifier;
use dpop_verifier::actix_helpers::{dpop_header_str, expected_htu_from_actix};

async fn handler(req: actix_web::HttpRequest) -> actix_web::Result<()> {
    let dpop = dpop_header_str(&req).map_err(|_| actix_web::error::ErrorUnauthorized("DPoP"))?;
    let expected_htu = expected_htu_from_actix(&req, /* trust_proxies */ false); //(see proxy trust note)
    let expected_htm = req.method().as_str();

    // ... get your ReplayStore
    // let mut store = ...

    let mut verifier = DpopVerifier::new()
        .with_max_age_seconds(300)
        .with_future_skew_seconds(5);

    // Optionally bind the proof to your own client identifier (if available)
    // if let Some(client_id) = client_id_for_request(&req) {
    //     verifier = verifier.with_client_binding(client_id);
    // }

    verifier.verify(&mut store, dpop, &expected_htu, expected_htm, None)
        .await
        .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?;

    Ok(())
}
```

> Proxy trust note: Only use X-Forwarded-* (true option) when you explicitly trust your proxy/load-balancer. Otherwise prefer connection info (false option).

## API Surface

### New API (recommended)
```rust
pub struct DpopVerifier {
    // Create with builder pattern
}

impl DpopVerifier {
    pub fn new() -> Self;
    pub fn with_max_age_seconds(self, max_age_seconds: i64) -> Self;
    pub fn with_future_skew_seconds(self, future_skew_seconds: i64) -> Self;
    pub fn with_nonce_mode(self, nonce_mode: NonceMode) -> Self;
    pub fn with_client_binding(self, client_id: impl Into<String>) -> Self;
    pub fn without_client_binding(self) -> Self;

    pub async fn verify<S: ReplayStore + ?Sized>(
        &self,
        store: &mut S,
        dpop_compact_jws: &str,
        expected_htu: &str,
        expected_htm: &str,
        access_token: Option<&str>,
    ) -> Result<VerifiedDpop, DpopError>;
}

pub struct VerifiedDpop {
    pub jkt: String, // JWK SHA-256 thumbprint (base64url, no pad)
    pub jti: String,
    pub iat: i64,
}

pub struct ClientBinding {
    pub client_id: String,
}
```

### Legacy API (deprecated)
The old `verify_proof` function is still available for backward compatibility but is deprecated:
```rust
#[deprecated]
pub async fn verify_proof<S: ReplayStore + ?Sized>(
    store: &mut S,
    dpop_compact_jws: &str,
    expected_htu: &str,
    expected_htm: &str,
    access_token: Option<&str>,
    opts: VerifyOptions,
) -> Result<VerifiedDpop, DpopError>;
```



### Replay store
Provide a store that return `true` only the first time it sees jti withint TTL window:
```rust
#[async_trait::async_trait]
pub trait ReplayStore {
    async fn insert_once(
        &mut self,
        jti_hash: [u8; 32],         // SHA-256 of jti
        ctx: ReplayContext<'_>,     // { jkt, htm, htu, client_id, iat }
    ) -> Result<bool, DpopError>;
}
```

### Actix helpers
```rust
pub fn dpop_header_str(req: &actix_web::HttpRequest) -> Result<&str, DpopError>;
pub fn expected_htu_from_actix(req: &actix_web::HttpRequest, trust_proxies: bool) -> String;
```

## Issues

- Issues & PRs welcome, please notify me if you find any security vulnerability
- Feel like the crate is missing something, butchers the spec, is not working as it should? -> Make an issue and I will investigate

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

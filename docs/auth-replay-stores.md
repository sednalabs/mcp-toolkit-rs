# Auth Replay Stores

`mcp-toolkit-auth` can enforce one-time bearer-token use by checking the JWT
`jti` claim. This is an explicit opt-in behavior controlled by
`AuthConfig::jti_enforce_bearer`; ordinary bearer tokens remain reusable by
default because many MCP transports reuse the same bearer token across a
session.

## Default Behavior

`Authenticator::new()` keeps the existing default:

- if `jti_ttl_s > 0` and `jti_cache_size > 0`, the authenticator creates an
  in-memory replay store;
- if `jti_enforce_bearer` is false, the store is not consulted for bearer-only
  requests;
- if `jti_enforce_bearer` is true, bearer-only requests must include a non-empty
  `jti`, and a repeated unexpired `jti` returns `AuthError::ReplayDetected`.

The default in-memory store protects only the process that owns it. Two
different OS processes with separate stores do not share replay state.

## Shared Store Seam

Services that need shared replay protection can construct their authenticator
with `Authenticator::new_with_jti_replay_store(config, store)`.

The `store` is a `SharedJtiReplayStore`, which is an `Arc<dyn JtiReplayStore>`.
Implementations must perform the check-and-record operation atomically in their
backend. A split check followed by a later insert can admit replay races.
`AuthConfig::jti_ttl_s` must stay positive so replay checking is enabled;
`jti_cache_size` only sizes the default in-memory store and is ignored for a
caller-supplied backend. Supplying a custom replay store with a disabled TTL is
treated as a configuration error.

```rust
use std::time::Duration;

use mcp_toolkit_auth::{AuthConfig, Authenticator, InMemoryJtiReplayStore};

let mut config = AuthConfig::default();
config.jti_enforce_bearer = true;

let store = InMemoryJtiReplayStore::shared(Duration::from_secs(300), 5000);
let auth_a = Authenticator::new_with_jti_replay_store(config.clone(), store.clone())?;
let auth_b = Authenticator::new_with_jti_replay_store(config, store)?;
# Ok::<(), mcp_toolkit_auth::AuthError>(())
```

The shared in-memory store is useful when multiple authenticators live in one
process. Multi-process deployments should provide a service-owned implementation
of `JtiReplayStore` backed by a shared system such as SQLite, Redis, or another
atomic compare-and-set store.

## Protection Matrix

| Store shape | Protects repeated JTI in one authenticator | Protects across authenticators in one process | Protects across OS processes |
| --- | --- | --- | --- |
| Default `Authenticator::new()` store | yes | no | no |
| Shared `InMemoryJtiReplayStore` handle | yes | yes | no |
| Service-owned shared backend | yes | yes | yes, if every process uses the same backend |

## Deployment Notes

- Keep bearer JTI enforcement disabled unless the client and transport contract
  support one-time bearer tokens.
- Use short TTLs matched to token lifetime and accepted clock skew.
- Treat replay-store failures as auth failures. The toolkit maps backend errors
  to a 500-class auth error rather than silently accepting replay risk.
- Do not log raw tokens or raw JTIs. Use hashed identifiers in service logs when
  replay troubleshooting is needed.

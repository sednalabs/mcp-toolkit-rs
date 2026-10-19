# Current MCP Baseline

Baseline date: 2026-10-19

The workspace pins `rmcp` and `rmcp-macros` to `3.5.1`, the latest published
stable SDK release checked on this date. Its upstream source is
[`rmcp-v3.5.1`](https://github.com/modelcontextprotocol/rust-sdk/releases/tag/rmcp-v3.5.1),
commit `79437f291b2c44053d00dcd5db969fd0cca7c887`. The protocol baseline remains
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning);
an SDK patch release does not change the protocol date.

The workspace patches `rmcp` and `rmcp-macros` to maintained SDK revision
`1d2e6ffdaccc7711552154dd2c9d7af4913a8f1e` for the existing `Origin`/schema-cache and
current-protocol disconnect corrections. Both corrections are retained on top
of the complete `3.5.1` release; neither has an equivalent in that release.
The toolkit workspace can therefore validate and consume that exact source
revision. Cargo patch tables are root-workspace-local: a consumer of toolkit
crates does not inherit this override. Consumers that need the correction must
add their own root-level override until a compatible RMCP release is available.
This is a source-build contract, not a hosted-validation, landing, or
crates.io-release promise.

The `3.5.1` changes preserve discovery as a lifecycle-neutral bootstrap probe,
return handler-generated invalid-parameter errors in-band, and supply missing
cache hints for current-protocol peers. The maintained stdio templates test
`server/discover` followed by current metadata-bearing requests and, separately,
by legacy `initialize`/`notifications/initialized` requests. The current path
asserts `resultType`, `ttlMs`, and `cacheScope`; the legacy path asserts that
the current result discriminator is not added to legacy tool results.

## Gap matrix

| Boundary | Current evidence | Deliberate gap or next proof | Downstream consumer benefit |
| --- | --- | --- | --- |
| Protocol era selection | Toolkit exercises legacy `2025-11-25` and explicitly selects modern `2026-07-28`; SDK `LATEST` selects the newest stateless era, while `LATEST_WITH_INITIALIZE` selects the newest handshake era. | Hosted HTTP/stdio contract runs must bind the exact candidate head and lockfile. | `google-search-console-mcp` and other template consumers avoid silently negotiating the legacy era. |
| HTTP lifecycle and headers | SDK owns lifecycle, header, `Origin`, and discovery behavior; toolkit remains deployment assembly. | Re-run toolkit current/legacy HTTP probes. Downstream discovery configurations require their own adoption tests. | `cloudflare-mcp` gets a stable header/auth deployment boundary without a second protocol parser. |
| Session replay | Legacy `2025-11-25` sessions may use `SessionManager::event_store` for GET plus `Last-Event-ID` replay and persisted streams when the hook is wired. The current `2026-07-28` protocol removes the GET stream endpoint and resumable replay; Toolkit current GET/DELETE requests return 405. Toolkit recording managers do not forward the SDK event-store hook. | A consumer claiming legacy replay must wire and test the SDK hook, including ordering, dedupe, snapshots, and authorization. | Consumers can distinguish recording/observability from durable replay instead of relying on an unsafe blanket claim. |
| Domain behavior | Toolkit contract and pattern manifests cover transport, schemas, and selected auth/release evidence. | Each downstream repository must retest its own domain contracts against the candidate revision. | `postgres-mcp` retains ownership of SQL policy and database behavior while consuming the shared transport baseline. |
| Dependency follow-up | `rustls 0.23.45` is included; PostgreSQL floor is raised. | OpenTelemetry, `jsonschema 0.57`, and general dependency refreshes remain separately gated; no blind `reqwest`/`jsonwebtoken` refresh. | Downstreams receive a bounded SDK migration rather than unrelated policy or dependency churn. |

No row above asserts that hosted checks have passed. Toolkit acceptance requires
hosted evidence bound to its repository, exact head SHA, workflow/run identity,
and lockfile. Downstream adoption is separate and additionally binds the
consumer revision; toolkit validation alone does not prove it.

## Public current-protocol route hints

`mcp_toolkit_server::http::declares_current_protocol` and
`payload_declares_current_protocol` expose the server's existing HTTP-header
and JSON-body route declarations for downstream composition. They use RMCP's
protocol-version representation and ordering, which can classify opaque or
unsupported version strings as current. They do not validate version syntax,
protocol support, the protocol exchange, or stateless lifecycle behavior. They
grant no authentication, session, or actor authority. Delegate protocol
validation and request semantics to RMCP.

The SDK's `initialize` handling remains on its legacy handshake path even when
one of these hints recognizes a current-era declaration. Downstream callers
must retain their session and actor checks for `initialize`; a current-era hint
must not be used to bypass those checks or any normal authorization decision.

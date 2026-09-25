# Current MCP Baseline

Baseline date: 2026-09-25

The migration candidate pins `rmcp` and `rmcp-macros` to `3.4.1`. The release
is represented by commit `9427a929959e665e0d12e9395f674026baf4bd48`, is
non-yanked on the registry, and has MSRV 1.88. This is a documentation
baseline, not hosted validation, landing, or a crates.io release promise.

## Gap matrix

| Boundary | Current evidence | Deliberate gap or next proof | Downstream consumer benefit |
| --- | --- | --- | --- |
| Protocol era selection | Toolkit exercises legacy `2025-11-25` and explicitly selects modern `2026-07-28`; SDK `LATEST` remains legacy. | Hosted HTTP/stdio contract runs must bind the exact candidate head and lockfile. | `google-search-console-mcp` and other template consumers avoid silently negotiating the legacy era. |
| HTTP lifecycle and headers | SDK owns lifecycle, header, `Origin`, and discovery behavior; toolkit remains deployment assembly. | Re-run toolkit current/legacy HTTP probes. Downstream discovery configurations require their own adoption tests. | `cloudflare-mcp` gets a stable header/auth deployment boundary without a second protocol parser. |
| Session replay | SDK optionally supports `SessionManager::event_store` for GET plus `Last-Event-ID` replay and persisted streams. Toolkit recording managers do not forward it. | A consumer claiming replay must wire and test the SDK hook, including ordering, dedupe, snapshots, and authorization. | Consumers can distinguish recording/observability from durable replay instead of relying on an unsafe blanket claim. |
| Domain behavior | Toolkit contract and pattern manifests cover transport, schemas, and selected auth/release evidence. | Each downstream repository must retest its own domain contracts against the candidate revision. | `postgres-mcp` retains ownership of SQL policy and database behavior while consuming the shared transport baseline. |
| Dependency follow-up | `rustls 0.23.45` is included; PostgreSQL floor is raised. | OpenTelemetry, `jsonschema 0.57`, and general dependency refreshes remain separately gated; no blind `reqwest`/`jsonwebtoken` refresh. | Downstreams receive a bounded SDK migration rather than unrelated policy or dependency churn. |

No row above asserts that hosted checks have passed. Toolkit acceptance requires
hosted evidence bound to its repository, exact head SHA, workflow/run identity,
and lockfile. Downstream adoption is separate and additionally binds the
consumer revision; toolkit validation alone does not prove it.

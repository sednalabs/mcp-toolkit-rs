# MCP 2026-07-28 conformance evidence ledger (updated 6 November 2026)

Reference: [stable 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog).
Latest official Rust SDK release observed: **rmcp 3.8.0 (26 October 2026)**.
The currently pinned toolkit source is **rmcp 3.8.0 with a project-maintained
transport fork**, qualified in [PR #330](https://github.com/sednalabs/mcp-toolkit-rs/pull/330).
See [the current baseline](current-mcp-baseline.md) for the exact source revision
and retained hardening. This is not the unmodified official SDK.

This is a **scope and qualification ledger**, not a declaration of full
specification certification or acceptance by any particular client.

| Spec capability | Current toolkit evidence | Residual proof or migration |
| --- | --- | --- |
| Stateless 2026 requests without initialize/session | `http_current_protocol` true-router tests; `current_protocol_contract` | Recheck each consumer over its deployed OAuth boundary |
| `server/discover` and version selection | Existing discovery response assertion; real HTTP proof landed in PR #323 | Consumer negative unsupported-version tests |
| SEP-2243 method/name/parameter headers | `http_current_protocol` positive, mismatch and duplicate rejection | Validate real hosted client and latest SDK |
| Cacheable results, private/public TTL and resultType | `current_cacheable_result_contract` and real HTTP `tools/list` test (landed PR #329) | Apply contract to authenticated `resources/read`, `resources/list`, and prompts where exposed |
| `subscriptions/listen` versus legacy methods | SDK API forwarding and existing Ops/IRC consumers; resource invalidation (landed PR #326) | Live acknowledgement, subscriptionId, cancellation and gap-inventory tests |
| InputRequired MRTR, requestState | RMCP handles protocol; toolkit has no universal service proof | Add proof only for consumers which support MRTR; do not invent capability |
| Tasks / other extensions | Optional SDK extensions, not automatically advertised by toolkit | Do not claim compliance for unimplemented capabilities |
| OAuth PRM, issuer, PKCE and scopes | AuthSurface and Apps contract tests; metadata and challenge helpers (landed PRs #327 and #328) | Exercise real issuer, token audience, scope increment and Client ID Metadata |
| Result JSON Schema 2020-12 | Generic dialect validator and schema-snapshot helper | Validate consumer-specific refs/composition limits and actual tools |
| RMCP SDK currency | Pinned 3.8.0 fork with transport hardening; landed PR #330 | Requalify dependent apps; remove the patch only after equivalent upstream fixes and tests are proven |
| Client compatibility | Hosted toolkit tests plus consumer CI | Run real ChatGPT, Codex and a current SDK client, including unsupported features |

The test helper is intentionally transport-facing but test-only: it validates a
provided real JSON HTTP response and its privacy hints, without creating
sessions, authenticating callers or rewriting results.

Do not mistake a green unit test for complete server conformance. The final
qualification requires implementation-specific feature claims, the official
conformance suite, supported client versions and live OAuth integration.

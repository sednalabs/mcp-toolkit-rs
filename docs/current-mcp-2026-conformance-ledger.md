# MCP 2026-07-28 conformance evidence ledger (1 November 2026)

Reference: [stable 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog).
Latest official Rust SDK release observed: **rmcp 3.8.0 (26 October 2026)**.
The currently pinned toolkit source is **rmcp 3.5.1 with a project-maintained
transport fork**, which is not equivalent to using the latest official SDK.

This is a **scope and qualification ledger**, not a declaration of full
specification certification or acceptance by any particular client.

| Spec capability | Current toolkit evidence | Residual proof or migration |
| --- | --- | --- |
| Stateless 2026 requests without initialize/session | `http_current_protocol` true-router tests; `current_protocol_contract` | Recheck against official rmcp 3.8.0 and over deployed OAuth boundary |
| `server/discover` and version selection | Existing discovery response assertion; separate HTTP proof in PR #323 | Land and verify PR #323; negative unsupported-version tests |
| SEP-2243 method/name/parameter headers | `http_current_protocol` positive, mismatch and duplicate rejection | Validate real hosted client and latest SDK |
| Cacheable results, private/public TTL and resultType | `current_cacheable_result_contract` and real HTTP `tools/list` test (this PR) | Apply contract to authenticated `resources/read`, `resources/list`, and prompts where exposed |
| `subscriptions/listen` versus legacy methods | SDK API forwarding and existing Ops/IRC consumers; resource invalidation PR #326 | Live acknowledgement, subscriptionId, cancellation and gap-inventory tests |
| InputRequired MRTR, requestState | RMCP handles protocol; toolkit has no universal service proof | Add proof only for consumers which support MRTR; do not invent capability |
| Tasks / other extensions | Optional SDK extensions, not automatically advertised by toolkit | Do not claim compliance for unimplemented capabilities |
| OAuth PRM, issuer, PKCE and scopes | AuthSurface and Apps contract tests; metadata PR #327 and challenge PR #328 | Exercise real issuer, token audience, scope increment and Client ID Metadata |
| Result JSON Schema 2020-12 | Generic dialect validator and schema-snapshot helper | Validate consumer-specific refs/composition limits and actual tools |
| RMCP SDK currency | Pinned 3.5.1 fork with local transport fixes | Qualify latest official 3.8.0; compare fork carry, lockfiles and dependent apps, then remove patch only if proven |
| Client compatibility | Hosted toolkit tests plus consumer CI | Run real ChatGPT, Codex and a current SDK client, including unsupported features |

The test helper is intentionally transport-facing but test-only: it validates a
provided real JSON HTTP response and its privacy hints, without creating
sessions, authenticating callers or rewriting results.

Do not mistake a green unit test for complete server conformance. The final
qualification requires implementation-specific feature claims, the official
conformance suite, supported client versions and live OAuth integration.

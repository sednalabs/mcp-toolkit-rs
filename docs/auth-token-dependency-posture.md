# Auth/Token Dependency Posture

This document defines the dependency posture for authentication and token
mechanics in `mcp-toolkit-rs`.

## Goal

Keep token facts trustworthy before they enter toolkit policy mapping or a
formal policy-kernel decision. The toolkit should use maintained public crates
for token mechanics and keep local code limited to small, reviewed glue around
canonical inputs, error mapping, and policy context construction.

## Boundary

In scope:

- bearer-token header extraction;
- JWT/JWS/JWK/JWKS validation;
- OAuth/OIDC metadata validation and discovery;
- OAuth token introspection;
- replay/JTI checks;
- scope, role, issuer, audience, subject, and client-id extraction;
- DPoP sender constraints;
- future mTLS sender constraints and token-exchange clients.

Out of scope:

- pure policy-kernel decisions after canonicalization;
- raw TLS implementation;
- authorization-server internals;
- service-specific business authorization rules.

## Selection Rules

Auth/token mechanics must follow these rules:

1. Prefer reputable, maintained public crates for cryptography, JWT/JWS/JWK,
   OAuth/OIDC, DPoP, mTLS, introspection, token exchange, and URL/HTTP parsing.
2. Keep local code to shape checks, typed configuration, canonicalization,
   bounded caching, provider glue, error mapping, and policy-input projection.
3. Do not add low-level crypto, JOSE, JWT, OAuth, or proof-of-possession code
   directly unless the dependency-governance PR note explains why a higher-level
   crate cannot fit.
4. Do not parse JWT compact serialization by splitting token segments or
   base64url-decoding claims in local code. Use a reviewed JOSE/JWT crate.
5. Do not infer authorization from unverified claims. Claims must come from a
   verified JWT/JWKS provider, an active introspection response, or another
   explicitly trusted canonical auth fact source.
6. Enable a sender-constraint or token-exchange mechanic only after it has an
   explicit design note, dependency-governance evidence, and conformance tests.
   DPoP meets that gate only through the atomic entrypoint documented below;
   mTLS remains absent. Outbound DPoP token exchange meets this gate through
   the crate-backed boundary documented below.

## Current Auth/Token Mechanics Inventory

| Mechanic | Current owner | Classification | Required posture |
| --- | --- | --- | --- |
| `Authorization: Bearer` header extraction | `crates/mcp-toolkit-auth/src/bearer.rs` | Approved local glue | Header-shape parser only; never validates claims or logs raw token values. |
| JWT/JWS validation | `crates/mcp-toolkit-auth/src/providers/jwks.rs` and `delegation.rs` | Crate-backed | Use `jsonwebtoken` for decode, signature verification, algorithm restriction, and validation setup. |
| JWK/JWKS handling | `crates/mcp-toolkit-auth/src/providers/jwks.rs` | Crate-backed with bounded local cache | Use `jsonwebtoken::jwk` for key material; local code may fetch, size-limit, cache, and refresh keys. |
| OAuth/OIDC metadata discovery | `crates/mcp-toolkit-auth/src/config.rs` and `surface.rs` | Crate-backed HTTP plus local validation | Use `reqwest`, `serde`, and `url`-validated toolkit helpers; local code validates issuer/endpoint shape and loopback-only insecure HTTP. |
| OAuth token introspection | `crates/mcp-toolkit-auth/src/providers/introspection.rs` | Crate-backed HTTP plus local validation | Use `reqwest`/`serde`; local code may size-limit, cache by token hash, enforce active tokens, and validate issuer/audience for introspection mode. |
| Token fingerprints | `crates/mcp-toolkit-auth/src/util.rs` | Approved local glue | Use one-way hashes for diagnostics/cache keys; do not expose raw tokens. |
| Claim extraction | `crates/mcp-toolkit-auth/src/claims.rs` | Approved canonicalization glue | Extract scopes, roles, issuer, audience, subject, and client identity only after provider verification. |
| Replay/JTI checks | `crates/mcp-toolkit-auth/src/replay.rs` | Approved local policy/storage glue | Store replay markers through the `JtiReplayStore` abstraction; fail closed on backend errors. |
| Auth error mapping | `crates/mcp-toolkit-auth/src/error.rs`, `claims.rs`, and `surface.rs` | Approved local contract glue | Map provider failures to stable low-leakage error codes and challenges. |
| DPoP sender constraints | `crates/mcp-toolkit-auth/src/dpop.rs` and `authenticator.rs` | Crate-backed atomic verification | `dpop-verifier` validates the full proof and toolkit immediately matches its JKT against `cnf.jkt`; see `docs/design/dpop-atomic-authentication-boundary.md`. Normal Bearer entrypoints reject every `cnf` claim. |
| Outbound DPoP P-256 key generation | `crates/mcp-toolkit-auth/src/outbound_dpop.rs` | Narrow `p256` production boundary | Generate P-256 key material only; use `jsonwebtoken` for JWK extraction, thumbprints, compact JWS encoding, and ES256 signing. Do not expand this boundary into proof verification or bespoke JOSE parsing. |
| Test-only P-256 proof fixtures | `crates/mcp-toolkit-auth/src/internal_tests.rs` and integration tests | `p256` test use | Real signed DPoP fixtures only; production verification remains exclusively in `dpop-verifier`. |
| RFC 8693 token exchange client | `crates/mcp-toolkit-auth/src/outbound_dpop.rs` | Crate-backed HTTP, JOSE, URL, and typed local glue | Use the no-redirect client, mandatory audit metadata, isolated bounded nonce stores, one nonce retry, and fail-closed `token_type=DPoP` response validation documented in `docs/design/outbound-dpop-token-exchange.md`. |

## No-Go Patterns

The following patterns are not acceptable in production auth/token code:

- direct JWT claim reads from unverified token strings;
- manual JWT segment splitting, base64url decoding, or JSON claim parsing;
- direct RSA/ECDSA/EdDSA verification implemented in toolkit code;
- ad hoc OAuth/OIDC discovery parsing that bypasses typed metadata validation;
- DPoP proof verification implemented as local string or signature plumbing;
- token-exchange logic that silently broadens audience, scopes, subject, or TTL;
- logging raw tokens, raw JTIs, authorization headers, or introspection secrets;
- accepting inactive, unknown, or introspection-failed tokens as anonymous or
  partially authenticated identities.

## Guardrails For New Auth Mechanics

Any new auth/token mechanic must include:

- a dependency-governance note from `docs/dependency-governance.md`;
- a classification in this document or a linked follow-up;
- tests at the natural boundary: provider validation, metadata contract,
  policy-input projection, or replay behavior;
- hosted validation evidence before merge;
- a tracked follow-up for any unacceptable bespoke token logic that remains
  after the change.

For future DPoP extensions, mTLS, private-key JWT, or new JOSE formats, prefer a
crate whose API validates the whole proof/token object. Do not compose signature
primitives, compact token parsing, and claim checks by hand. Outbound proof
construction uses `jsonwebtoken`; inbound proof verification remains exclusively
owned by `dpop-verifier`.

## Enforcement

`scripts/auth_dependency_posture_check.py` is part of
`scripts/dependency_governance_check.sh`. It enforces the current repository
posture by checking that:

- this document keeps the required inventory and guardrail sections;
- high-risk JWT validation calls remain in the approved provider files;
- local auth code does not parse JWT compact serialization manually;
- low-level auth crypto crates are not added directly to `mcp-toolkit-auth`
  without updating the guardrail.

The script is intentionally narrow. It does not replace code review, dependency
governance notes, or hosted Rust validation; it prevents the easiest regressions
from becoming the default path.

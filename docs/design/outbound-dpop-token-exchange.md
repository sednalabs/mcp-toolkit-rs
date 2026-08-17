# Outbound DPoP Token Exchange Boundary

## Decision

`mcp-toolkit-auth::outbound_dpop` owns reusable RFC 9449 proof construction and
RFC 8693 token-exchange transport. Service repositories must keep business
authorization, audience and scope selection, service-version negotiation, and
actor/project policy outside this boundary.

The module uses existing maintained dependencies:

- `p256` generates a P-256 private key and emits PKCS#8 key material;
- `jsonwebtoken` extracts the public JWK, computes its RFC 7638 thumbprint, and
  performs compact ES256 JWS encoding;
- `reqwest`, `http`, and `serde` own HTTP, URL, header, form, and JSON mechanics;
- `sha2` computes the RFC 9449 access-token hash.

No compact JWT parsing, signature implementation, or proof verification is
implemented locally. Inbound verification remains exclusively in
`dpop-verifier` through the atomic resource-server authentication entrypoint.

## Security contract

The client:

1. requires HTTPS except for explicit loopback-only test/emulator configuration;
2. disables redirects and ambient proxy discovery at the token endpoint;
3. canonicalizes proof targets without user information, query, or fragment;
4. marks authorization and proof headers sensitive;
5. keys token-endpoint nonces by canonical endpoint and keeps them separate from
   method/resource nonces;
6. bounds nonce length, token and resource nonce cardinality, response size, and
   retry count;
7. retries a token request once only for an OAuth `use_dpop_nonce` response with
   a single valid `DPoP-Nonce` header;
8. requires non-empty audit subject, actor-client, and exchange-id metadata before
   a token-exchange request can be constructed;
9. accepts RFC 8707 resource indicators only as absolute, fragment-free URIs;
10. requires a successful bound exchange to return `token_type=DPoP` and the
    exact requested `issued_token_type`;
11. rejects broadened returned scopes and refresh tokens outside this bounded
    exchange profile;
12. permits only an explicit standard OAuth error-code allowlist into formatted
    diagnostics; and
13. never includes tokens, proofs, nonces, private keys, response bodies, or raw
    authorization-server descriptions in formatted diagnostics.

Resource clients obtain a transaction object whose nonce-challenge method
accepts only one `401` plus one valid `DPoP-Nonce`. The transaction constructs a
fresh proof for the retry; callers still own the request body, dispatch, response
interpretation, and service-specific availability policy.

## Caller contract

Before exchange, a service must:

- authorize the subject, audience, resource, scopes, and requested token type;
- bind `TokenExchangeAuditMetadata` to its policy decision and durable audit path;
- configure the authorization server and client credentials from a trusted source;
- retain any service capability matrix or old-generation behavior downstream; and
- validate any domain-specific token claims after the authorization server issues
  the result.

The toolkit deliberately does not implement denial-triggered Bearer fallback,
audience discovery, service generation detection, subject/actor authorization,
or product receipt schemas.

## Dependency governance

This change moves existing `p256 0.13.2` from test-only to a narrow production
key-generation boundary; it adds no new crate and does not use `p256` for compact
JWS encoding or verification.

- purpose: generate ephemeral P-256 key material for outbound RFC 9449 proofs;
- alternatives: `jsonwebtoken` can sign and extract a JWK but does not generate
  fresh EC private keys; direct backend APIs would couple the toolkit to a crypto
  provider and enlarge the boundary;
- maintenance and reputation: `p256` is the RustCrypto P-256 implementation and
  was already used by the toolkit's signed-proof fixtures;
- security and license proof: the hosted dependency-governance workflow remains
  authoritative for RustSec, source, and license checks;
- startup impact: one key generation and JOSE key initialization per client;
- rollback: remove `outbound_dpop`, return `p256` to dev-dependencies, and restore
  the posture allowlist entry to test-only use.

## Acceptance tests

Hosted tests must prove signature and JWK binding, `ath`, canonical targets,
two-endpoint nonce isolation under concurrency, one-retry behavior, DPoP and
issued-token-type enforcement, resource-indicator validation, response bounds,
redirect and ambient-proxy denial, Basic client-auth shape, cancellation,
mandatory audit metadata, and secret-safe diagnostics.

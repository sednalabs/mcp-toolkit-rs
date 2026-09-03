# Outbound DPoP Token Exchange Boundary

## Decision

`mcp-toolkit-auth::outbound_dpop` owns reusable RFC 9449 proof construction and
RFC 8693 token-exchange transport. Service repositories must keep business
authorization, audience and scope selection, service-version negotiation, and
actor/project policy outside this boundary. The toolkit signs and validates
bounded proof structure and transport policy; it does not authorize provider
access or decide whether an exchange should execute.

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

1. requires an explicit exact-endpoint trust policy for the credential-bearing
   token endpoint and an explicit exact target policy for every resource
   authorization; both use HTTPS except for an explicit numeric-loopback-only
   test/emulator policy. Resource policies compare the canonical target (the
   scheme, authority, and path; query and fragment components are not signed);
2. disables redirects and ambient proxy discovery at the token endpoint;
3. canonicalizes proof targets without user information, query, or fragment;
4. marks authorization and proof headers sensitive;
5. keys token-endpoint nonces by canonical endpoint and keeps them separate from
   method/resource nonces;
6. bounds nonce length, token and resource nonce cardinality, response size, and
   retry count;
7. retries a token request once only for an OAuth `use_dpop_nonce` response with
   a single RFC 9449 `b64token` `DPoP-Nonce` header;
8. accepts only the typed `BearerSubjectToken` contract for the RFC 8693
   subject; sender-constrained subject tokens are unsupported rather than
   inferred from a generic secret;
9. requires non-empty audit subject, actor-client, and exchange-id metadata before
   a token-exchange request can be constructed;
10. accepts RFC 8707 resource indicators only as absolute, fragment-free URIs,
   rejects user information, and redacts query components from diagnostics;
11. represents only access-token-for-access-token RFC 8693 requests and requires
    a successful exchange to be HTTP `200` with one `application/json` media
    type, `token_type=DPoP`, and the exact access-token `issued_token_type`;
12. parses returned scope with RFC 6749's literal-space grammar, treats omission
    as the requested scope, and rejects malformed or broadened scopes and refresh
    tokens outside this bounded exchange profile;
13. permits only an explicit standard OAuth error-code allowlist into formatted
    diagnostics; and
14. never includes tokens, proofs, nonces, private keys, response bodies, or raw
    authorization-server descriptions in formatted diagnostics.

`exchange` returns an explicitly unverified `DpopAccessToken`. A response
`token_type=DPoP` is not proof of server `cnf.jkt` binding, audience, or TTL.
Before resource authorization, the caller must pass provider-backed
`DpopProviderValidationMetadata` to `validate_provider_binding`; only the
resulting `DpopBoundAccessToken` can create a resource transaction. The
metadata carries the token fingerprint, proof-key thumbprint, provider,
audience, and expiry, and the toolkit checks local consistency and freshness
without pretending to perform provider introspection.

Resource clients obtain a transaction object whose nonce-challenge method
accepts only one `401` plus one valid `DPoP-Nonce`. The transaction constructs a
fresh proof for the retry; callers still own the request body, dispatch, response
interpretation, provider authorization, audience/scope policy, and service-specific
availability policy.

## Caller contract

Before exchange, a service must:

- authorize the bearer subject, audience, resource, and scopes for the fixed
  access-token-for-access-token profile;
- bind `TokenExchangeAuditMetadata` to its policy decision and durable audit path;
- configure the authorization server and client credentials from a trusted source,
  explicitly review the exact token-endpoint policy, and pass an exact target
  policy for each resource target to `resource_request`;
- obtain provider-backed binding metadata and call `validate_provider_binding`
  before treating the response as sender-constrained;
- retain any service capability matrix or old-generation behavior downstream; and
- validate any domain-specific token claims after the authorization server issues
  the result.

The toolkit deliberately does not implement denial-triggered Bearer fallback,
audience discovery, service generation detection, subject/actor authorization,
provider introspection, `cnf.jkt` verification, TTL/audience authorization, or
product receipt schemas.

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
fixed issued-token-type enforcement, exact HTTP-success and JSON-media-type
handling, resource-indicator validation and diagnostic redaction, strict HTTPS
with a numeric-loopback-only development exception, response bounds, redirect
and ambient-proxy denial, Basic client-auth shape, cancellation, mandatory audit
metadata, and secret-safe diagnostics.

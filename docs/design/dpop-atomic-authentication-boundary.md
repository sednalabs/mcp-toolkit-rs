# Atomic DPoP Authentication Boundary

## Decision

`mcp-toolkit-auth` accepts sender-constrained access tokens only through
`Authenticator::authenticate_sender_constrained_dpop`. That operation invokes
`dpop-verifier` 4.4.0 itself with the raw compact proof, the exact access
token, canonical HTTP target and method, a configured `DpopVerifier`, and the
resource server's `ReplayStore`. It then compares the verified JKT with
`cnf.jkt` before returning an authenticator-bound `VerifiedAuthContext`.

The operation accepts only `DpopToken` and `DpopProof` values produced by the
strict header parsers. Raw strings and ordinary Bearer credentials cannot be
passed to the supported sender-constrained entrypoint. Both credential wrappers
redact their `Debug` representation.

Ordinary `authenticate_headers` and `authenticate_token` remain strictly
Bearer-only. They reject every token that carries a `cnf` claim, and successful
calls return the same authenticator-bound context type as the sender-constrained
entrypoint.

## Rationale

There is no public receipt, Boolean, context, thumbprint, or `VerifiedDpop`
shortcut. The toolkit validates the DPoP compact JWS, signature, target,
method, access-token hash, freshness, configured nonce policy, confirmation
thumbprint, and replay insertion before returning an authentication context.
Missing, malformed, or mismatched `cnf.jkt` claims fail with the normal
low-leakage invalid-token response.

The toolkit validates the access token first and wraps the caller's replay store
with the expected `cnf.jkt`. `dpop-verifier` computes the proof JKT only after
signature verification; the wrapper forwards replay insertion only when that
verified JKT matches the token. Proofs signed by attacker-controlled keys
therefore cannot consume or evict replay entries for the protected token.
Resource servers must still use a bounded, shared, atomic replay store for
matching proofs.

`SenderConstrainedAuthError` keeps the original `DpopError` as a typed source.
A trusted transport adapter can therefore issue a nonce response or distinguish
a replay-store failure, while ordinary external responses remain generic and do
not disclose verifier internals.

## Integration contract

1. Parse exactly one RFC 9449 `Authorization: DPoP <token>` header with
   `parse_strict_dpop_authorization`, and parse exactly one compact proof from
   the request's `DPoP` header with `parse_strict_dpop_proof`. Pass those typed
   values directly to the atomic authenticator. Do not route a
   sender-constrained token through the ordinary `Bearer` authorization scheme.
2. Derive `expected_htu` and `expected_htm` from the canonical request after
   trusted-proxy processing.
3. Configure `DpopVerifier` for the service's freshness and nonce policy and
   provide one shared, atomic `ReplayStore` across workers.
4. Call `authenticate_sender_constrained_dpop` exactly once. Map its typed
   `DpopError` only in trusted transport code; return generic failures to the
   client unless the protocol expressly requires a nonce challenge. Retain the
   returned `VerifiedAuthContext` wherever downstream code requires provenance;
   request-extension retrieval must name the expected authenticator.

## Trust boundary

The toolkit removes the accidental in-process bypass that accepted a
caller-selected verification result. It cannot defend against malicious code in
the same process that deliberately supplies a permissive verifier, false
canonical request values, or a non-shared replay store. The resource server owns
those inputs and must keep that ingress and replay implementation trusted.

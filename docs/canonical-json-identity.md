# Canonical JSON and intent identity

The production API lives in the `mcp-toolkit-core::canonical_json` module.
It replaces the need for consumers to copy test-only encoding or construct
ad hoc SHA-256 request digests.

## Exact-byte profile

The toolkit canonical form recursively sorts JSON object keys by Rust string
ordering, preserves array order, and serializes JSON scalars using serde_json
as compact UTF-8 without a trailing newline. This deliberately matches the
existing toolkit JSON contract and receipt snapshot profile. It is **not**
RFC 8785 (JCS): number formatting and supplementary-plane key ordering can
differ. Do not mix canonicalization profiles in a single approval protocol.

The same JSON value, regardless of object insertion order, has the same
canonical bytes and SHA-256 digest. SHA-256 is calculated over those bytes,
not over source text, a pretty-printed representation, or a preview.

For an empty object, the bytes are `{}` and the SHA-256 hex digest is
`44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`.

## Consumer contract

Start with a validated `serde_json::Value` containing a complete versioned
intent envelope. Include the operation/tool identity, effect target,
complete arguments, and any authority-relevant context, such as the
principal or resource revision. Construct `CanonicalJsonIdentity::new(&value)`
and retain its `bytes()` and `sha256()` together; `sha256_id()` supplies
an algorithm-qualified `sha256:<lowercase hex>` identifier.

This primitive **does not** authorize a mutation, manage approval lifecycles,
validate a tool's intent shape, persist evidence, or reconcile uncertain
effects. Those remain consumer and higher-level toolkit responsibilities.
Do not treat matching hashes alone as a grant of execution authority.
Do not log raw intent bytes or publicly expose digests of low-entropy secrets.
Callers must impose appropriate input-size limits and reject ambiguous
duplicate JSON keys before parsing if their protocol requires it.

Test-only receipt budget assertions remain in `mcp-toolkit-testing`, and
their canonical encoding now delegates to this production implementation.

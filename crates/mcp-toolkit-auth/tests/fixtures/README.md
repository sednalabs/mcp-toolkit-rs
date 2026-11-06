# Strict bearer header vectors

`strict-bearer-v1.json` is a language-neutral corpus for the existing
`parse_strict_bearer_authorization` profile, not a universal OAuth parser.
The adjacent integration test runs every vector against the public Rust API.

Each case has a unique `id`, an ordered `headers` list, and exactly one of
`token` (extraction succeeds) or `error` (Rust error variant name).
Header values use byte arrays so non-visible bytes can be represented without
Unicode normalization. Preserve repeated headers with append/multimap semantics;
do not flatten them into a dictionary or select the first value.
Header names are case-insensitive. The corpus intentionally specifies the
existing error precedence, including trailing whitespace for an empty token.
All values are synthetic.

## Provenance and limits

The ecosystem harvest identified array-first extraction and case-normalization
overwrite in [mcp-toolkit-ts validator.ts](https://github.com/sednalabs/mcp-toolkit-ts/blob/afadac90e63a98474fd727f6e5223d3493dfe6d2/src/server/auth/validator.ts).
Those behaviors are counterexamples, not behavior to port. The repeated-header
vectors cover identical, differently cased, and empty-first/last variants that
the original Rust unit tests did not separately exercise.

This corpus preserves the Rust strict policy: one header, case-insensitive
Bearer scheme, one ASCII space, visible text, no surrounding whitespace or
controls, and a non-empty opaque token. Extraction does not verify JWT syntax,
signatures, issuer, audience, subject, expiry, sender constraints or authority.
Do not treat a passing vector as authentication, or normalize a request to make
it pass. Compatibility/non-strict mode is outside this profile. CR/LF and NUL
bytes rejected by the HTTP header constructor are outside these parser vectors.

Run with:

```sh
cargo test -p mcp-toolkit-auth --test bearer_header_fixtures
```

Other runtimes can consume this corpus to report policy differences. No
TypeScript or Python conformance pass is claimed here. The Rust test also checks
that direct and nested parser diagnostics do not contain the synthetic canary.

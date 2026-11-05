# Compact tool results

`mcp_toolkit_server::response::compact_result` is an opt-in adapter available with
`stdio`, `http`, `auth`, or `operational-resources`. It keeps a caller-authored text
projection beside the original structured content without serializing the full
payload into both fields. RMCP continues to own the wire model.

## Incremental adoption

Existing analytics and administration servers can retain their local success and
error envelope builders, including tabular, scratchpad, timing, and domain error
metadata. Replace only their final result conversion:

```rust
use mcp_toolkit_server::response::{compact_result, ResponseLimits, ToolOutcome};

// Select this variant from the same domain outcome that builds the envelope.
let outcome = ToolOutcome::Error(safe_error_envelope);
let result = compact_result(
    outcome,
    "The request failed. Check the configured resource and try again.",
    None,
    ResponseLimits::default(),
)?;
```

A domain `ok: false` field alone does not make an MCP error. Select `Error` from
the actual domain failure branch; it sets `isError: true`. `Success` sets false.
The adapter deliberately does not inspect or enforce an `ok` field, and does not
invent one universal response envelope. Do not map a failed probe through the
success branch. Keep protocol-level errors separate from tool execution errors.

The default budgets are 12 KiB of UTF-8 text, 48 KiB of serialized structured
content, and 64 KiB of serialized complete result. Applications may choose their
own limits. Whole-result measurement includes JSON escaping and protocol `_meta`,
but not the enclosing JSON-RPC message or transport headers. Serialization stops
at the limit without allocating a second JSON buffer. These limits do not bound
previously allocated input memory or recursive input construction.

Over-budget output is rejected, not silently truncated. Handle rejection with an
application-owned, allowlisted fallback or a smaller result/pagination flow. Do
not echo the original payload in the fallback. Choose text that is actionable
for content-only clients, and do not mutate the returned result without checking
the final transport budget again.

Structured payload fields named `meta` or `_meta` remain untouched; optional
protocol metadata is written only to the result's top-level `_meta`. There is no
merge or collision policy that overwrites domain fields. Explicit JSON null is
preserved as present structured content.

## Safety boundary

All three inputs (payload, summary, and protocol metadata) must already be safe
for the caller. Prefer allowlisted error codes and messages over raw provider or
command errors. Existing observability redaction is heuristic defense in depth,
not a guarantee of client-output safety. This adapter does not sanitize data or
claim to replace bounded recursive redaction.

The regression tests serialize the public result and assert `isError`, content
projection, null/empty/large payload preservation, UTF-8 and escaped JSON byte
boundaries, metadata separation, and non-echoing rejection diagnostics. Consumer
adoption should add the same wire-level assertions around its local envelope;
checking only the inner `ok` field misses MCP error-signaling regressions.

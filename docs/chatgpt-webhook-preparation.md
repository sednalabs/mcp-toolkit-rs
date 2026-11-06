# ChatGPT webhook preparation

Enable `mcp-toolkit-http`'s optional `chatgpt-events` feature for I/O-free
preparation of the documented ChatGPT webhook contract. The independent core
`webhook::validate_chatgpt_signing_secret` helper checks only the signing-secret
format accepted by this integration. Subscription request parsing, identity and
lifetime policy are outside this module.

## Delivery

1. Authorize the event and validate its data schema in the application.
2. Build an `EventEnvelope` with event ID, name, `time::OffsetDateTime`, a JSON
   object, and optional string cursor. `PreparedWebhook::event` serializes it
   once with a capped writer into owned immutable bytes, at most 256 KiB total.
3. Construct `WebhookSigner` from the current secret and optionally one previous
   secret. The ChatGPT key profile requires a `whsec_` prefix and 24–64 decoded
   bytes in canonical standard base64, bounded to 88 encoded bytes. These are
   integration-specific limits, not universal Standard Webhooks requirements.
   The service, not this helper, decides whether the previous key is eligible.
4. `PreparedWebhook::sign` takes the subscription ID and explicit current Unix
   seconds. It returns the exact borrowed body and Content-Type, webhook-id,
   webhook-timestamp, webhook-signature and X-MCP-Subscription-Id headers.
   Both rotation signatures cover identical bytes and are separated by one space.
5. Reuse the same prepared event ID/body for a retry and supply fresh signing
   time. Dispatch, retry timing and cancellation are application decisions.

Event timestamps use RFC3339 with a timezone. Event bodies contain
`eventId`, `name`, `timestamp`, `data`, and string-or-null `cursor`, with no
application `type` field. IDs accept 1–256 ASCII letters, digits, dash,
underscore, period or colon. Names are nonblank and at most 256 UTF-8 bytes;
cursors are at most 4096 bytes. Accessors expose sensitive material deliberately;
Debug and error output do not. Signatures are marked sensitive in HeaderMap.

## Callback verification

Supply a fresh cryptographically random 32-byte nonce, a unique message ID,
explicit issuance time, and a later finite deadline to `PendingChallenge::new`.
`sign` prepares the signed JSON `{"type":"verification","challenge":"..."}`.
The challenge is the unpadded base64url nonce. No entropy or time is read here.

After the authorized HTTP client receives a response, `verify` consumes the
pending value even on failure. It requires 2xx status, explicit current time
within `[issued_at, deadline)`, and a JSON object containing only the echoed
`challenge` string. The entire response, including whitespace, is limited to
1024 bytes. Duplicate/unknown fields, positional arrays, trailing JSON values,
wrong types/lengths and mismatches fail closed. Fixed-length comparison uses
`subtle`. This is not Standard Webhooks' separate header-MAC verification flow.

The caller must cap actual network reads, bind each response to the precise
callback/principal/generation, consume durable single-use state, and authorize
activation. The non-Clone pending value protects only one in-memory ownership
flow. It cannot prevent a caller from recreating a challenge with reused entropy.

## Application boundary

These helpers never connect, resolve DNS, read a clock, store secrets or state,
activate subscriptions, acknowledge source events, dispatch or retry. The
application owns HTTPS/public-address egress validation, connection-time DNS
binding, redirect rejection, bounded network I/O, current access checks,
callback/principal binding, secure entropy, key custody, rotation eligibility,
durable generations and checkpoints. A signature or successful echo alone
confers no application authority.

## Validation

The standard hosted baseline includes exact-head `--locked` HTTP feature-enabled
tests/doctests, focused core validator tests and doctests, and an HTTP
feature-disabled build. Workspace coverage and all-feature Clippy cover the new
module as well. Tests include the official Standard Webhooks vector,
UTF-8/escaping byte identity, body limit and limit-plus-one, rotations, redaction,
malformed echoes, deadline boundaries,
consuming ownership and deterministic JSON parser mutation fuzzing. Core tests
cover key-profile boundaries, malformed encodings, safe errors and deterministic
format fuzzing. Existing CodeQL and dependency-governance gates remain in force.
Code Quality ingestion remains opt-in and is not enabled by this feature.

References: [ChatGPT MCP Events](https://developers.openai.com/plugins/build/mcp-events)
and [Standard Webhooks Rust](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/rust).

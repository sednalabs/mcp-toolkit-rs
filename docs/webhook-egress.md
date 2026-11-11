# Guarded webhook HTTPS egress

Enable `mcp-toolkit-http`'s optional `webhook-egress` feature to send a single
`SignedWebhook` produced by the existing [preparation helpers](chatgpt-webhook-preparation.md).
It includes `chatgpt-events` but does not change the default feature surface.

```rust,no_run
use mcp_toolkit_http::webhook_egress::{WebhookEgress, WebhookEgressLimits};
// After application authorization and fresh signing:
// let response = WebhookEgress::new(WebhookEgressLimits::default())?
//     .send(authorized_callback, &signed).await?;
// pending.verify(response.status(), response.body(), current_unix_seconds)?;
```

`WebhookEgress` retains only validated limits. Every `send` creates a fresh
HTTP/1 client and copies the already prepared immutable bytes once into its
request body. It does not reserialize, resign, add authorization, retry, pool
connections, activate subscriptions or start a worker. Status and bounded body
accessors are explicit; errors and Debug output omit callbacks, addresses,
signatures, request data and response data. No underlying error source is exposed.
`WebhookEgressError::status()` preserves a received HTTP status even when the body
is encoded, oversized, truncated or times out. Applications must consult it when
applying status-based retry rules, such as terminal 410/413 responses. A failure
before complete, valid HTTP headers has no trustworthy status and returns None.

## Address and transport contract

- Accept only lowercase `https://`, a canonical ASCII DNS hostname containing a
  dot, canonical dotted-decimal IPv4, or bracketed canonical IPv6. Reject userinfo
  (including empty userinfo), fragments, whitespace/control characters,
  backslashes, escaped hosts, IPv4 shorthand/octal/hex, Unicode hostnames,
  trailing dots, empty labels and noncanonical or zero ports. Punycode DNS labels
  are accepted. Paths and queries retain URL-parser encoding semantics.
- Resolve each attempt anew through the OS resolver. Inspect at most 32 answers
  and reject the entire answer set if any address is non-public, or if it is
  empty or excessive. Never pick the public subset from mixed answers.
- Reject private, loopback, link-local, unspecified, documentation, multicast,
  reserved and shared-address IPv4 blocks, plus Azure's globally numbered
  platform virtual IP. Conservatively permit only IPv6 global-unicast 2000::/3,
  excluding protocol assignments, documentation and 6to4. Mapped/compatible IPv4,
  NAT64, Teredo, local, multicast and other special IPv6 ranges are denied.
  This is a conservative profile, not a promise to support every special-purpose
  globally reachable address. Keep its registry exclusions current.
- A sealed address set supplies the client's only resolver. It returns only the
  validated addresses for the original hostname and fails for any other name.
  It never calls DNS again. Literal IP URLs are checked before reqwest's literal
  fast path. The URL host remains unchanged for Host and certificate validation.
  DNS names also retain their SNI; literal IP identities omit SNI as required. Connection attempts can use only the validated socket addresses.
- Use an explicit rustls ring provider and the maintained `webpki-roots` bundle.
  Do not use the platform verifier, native trust overrides, custom roots, client
  certificates, TLS key logging or OS revocation lookups. This avoids certificate
  verification causing additional OS network traffic. TLS 1.2/1.3 verification
  remains enabled. Private enterprise trust is intentionally unsupported.
- Disable environment/system proxies, redirects, protocol retries and all four
  automatic decompression options explicitly, including under feature unification.
  Reject all 3xx responses and any Content-Encoding header, even `identity`.
  Send Accept-Encoding: identity. A prepared signed request supplies only its five
  immutable headers; Host, framing and Connection are transport-owned.

A public destination can still proxy or disclose information it receives. This
transport does not authenticate the subscriber, prove the callback owner's
identity or constrain the host operating system's routing/NAT. Deployments still
need appropriate network isolation and application authorization.

## Resource and cancellation bounds

Defaults: DNS 3 seconds, connect/TLS 5 seconds, read-idle 3 seconds, total 15
seconds, response body 1024 bytes. Durations must be positive, at most 60 seconds,
and no longer than the total. The response cap must be 1..=65536 bytes. The outer
attempt deadline includes DNS admission, resolution, client setup, connection,
request transmission and actual body reads. Tokio deadlines are cooperative,
not real-time preemption of synchronous cryptographic/OS work.

Requests inherit the preparation helper's 256 KiB body limit and bounded headers.
Response Content-Length is checked early, but never trusted as the only bound:
every actual chunk is checked before appending. Chunked/unknown-length bodies
are capped too. HTTP/1 response headers are limited to 32; Hyper additionally
bounds its parser/read buffer (approximately 400 KiB in the locked version).
The transport does not expose unbounded response headers. A declared shorter
Content-Length defines HTTP message framing; extra peer bytes are not returned
and cannot contaminate another request because connections are never reused.

OS DNS is synchronous and cannot be forcibly cancelled. A process-wide semaphore
admits at most eight blocking resolver jobs, including jobs whose caller timed
out or cancelled. A job retains its slot until OS resolution returns; queued
callers remain subject to DNS and total deadlines. The resolver job contains no
client, callback body or send continuation, so it cannot send after cancellation.
Hung OS resolution can exhaust these slots and delay runtime shutdown. It must
be addressed by deployment resolver health or process isolation, not an insecure
address override. Callers must also bound their own concurrent send attempts.

Dropping a send future abandons request/response handling and closes its
unpooled transport. It cannot retract queued, in-flight or received bytes; bytes
may still arrive after cancellation. A network error, timeout or cancellation is
an ambiguous delivery outcome. The application owns current authorization,
expiry, generation binding, idempotency, secret custody and decisions about a new freshly signed retry. A successful
transport receipt never acknowledges source work or proves live integration
acceptance.

## Qualification and limits of the evidence

The required baseline runs feature-enabled unit/TLS tests and doctests at the
exact PR head, preserves the independently enabled preparation tests, and checks
the feature-disabled crate. All-feature workspace Clippy, coverage, MSRV,
dependency governance and security checks remain required. Tests need OpenSSL
on PATH to generate ephemeral local test certificates; the standard Ubuntu CI
runner provides it. The isolated proxy-environment subprocess test is Linux-only,
using /proc/self/exe rather than an environment-controlled executable path.
There are no committed test keys or external callback calls.
A separate exact-head lane enables reqwest gzip/brotli/deflate/zstd/native-tls
features together and reruns the transport tests with --locked. That isolated
runner exports the exact Git source to a separate fixture workspace and verifies
HTTP source hashes. It enables the extra features in that fixture manifest only,
resolves the additional test dependencies, and checks every resolved package
against the fixture lock. It uploads both manifests, metadata, a feature tree,
the graph check, fixture lock, source hashes and SHA. It does not change the committed production lock or replace the locked
feature/default lane. This proves the runtime disables decoders and selects its
explicit rustls configuration despite Cargo feature unification.

Controlled TLS tests use an ephemeral loopback listener, private test-only
construction of the sealed address set, and a test-only trust root. They exercise
the same actual reqwest connector, pinning resolver, rustls certificate checking,
SNI, Host and byte transport. The public API has no private-address or TLS bypass.
Separate public-entrypoint/address tests prove loopback rejection; loopback TLS
success is not evidence that the complete public API permits loopback.

Coverage includes mixed answers and simulated rebinding, a resolver with no
fallback, wrong-host/untrusted certificate failures before HTTP, exact signed
body/header identity, redirect and proxy sinks, response header/body bounds,
chunking, truncation, compression rejection, idle/total deadlines, cancellation,
DNS admission limits and a signed challenge round trip. The rebinding case is a
controlled resolver-state test, not a live authoritative-DNS rebinding experiment.
Public Internet reachability, real receiver acceptance, provider-specific routing
and deployment DNS/TLS behavior still require consumer qualification.

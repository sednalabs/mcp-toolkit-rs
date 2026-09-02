# Auth Control-Plane Policy Runtime

`mcp-toolkit-policy-runtime` provides a reusable auth/control-plane policy
surface for HTTP MCP servers that already use the toolkit auth surface.

The helper is intentionally narrow:

- `AuthControlPlaneHttpMapper` projects sanitized data from an
  authenticator-bound context and `AuthSurfaceContext` into an
  `auth-control-plane/v1` envelope.
- `AuthControlPlanePolicyAuthority` evaluates that envelope with the embedded
  policy kernel and emits `PolicyAuthorityDecision` provenance.
- `PolicyProvenanceRequirement` validates that emitted decisions carry the
  expected `decision_source`, `runtime_mode`, and `policy_contract_version`
  before a server treats them as release evidence.
- `PolicyAuthorityLayer` consumes the current auth surface's request witness,
  attaches allow decisions to request extensions, and attaches deny decisions
  to response extensions.

The mapper copies actor, subject, scopes, roles, issuer, audience, client,
method, path, tool, action, resource, project, session, token-mode, delegation,
exchange, proof, risk, and health/status observation metadata. It deliberately
does not copy raw bearer tokens.

The auth surface strips pre-existing auth extensions and issues a fresh,
single-use request witness. That witness is valid only while the request is
executing inside the auth surface and is bound to the exact method, URI, and
authorization header. The policy layer rejects missing, stale, replayed,
rebound, independently issued, or incorrectly ordered witnesses before calling
the configured authority or inner service.

The default authority also fails closed when authentication is absent,
session/project binding is inconsistent, token-exchange metadata is missing its
audit binding, sender-constrained posture is incomplete, or the embedded policy
kernel denies the route/scope/claims decision. Health and status routes are
protected by default; services can explicitly opt into `PublicReadOnly`
exposure for read-only health/status routes. Those routes still receive a
current auth-surface witness, but carry no authenticated principal.

Typical assembly:

```rust
use mcp_toolkit_policy_runtime::{
    AuthControlPlaneHttpMapper, AuthControlPlanePolicyAuthority, PolicyAuthorityLayer,
};

let authority = AuthControlPlanePolicyAuthority::builder()
    .expected_issuer("https://issuer.example")
    .expected_audience("mcp://example")
    .allow_azp("example-client")
    .default_scopes("mcp:read", "mcp:write")
    .build()
    .shared();

let layer = PolicyAuthorityLayer::new(
    authority,
    AuthControlPlaneHttpMapper::default(),
    authenticator.clone(),
);
```

`authenticator` must be the same shared instance configured on the enclosing
auth surface. The policy gate enforces that topology at runtime: placing the
policy layer outside the auth surface produces a fail-closed
`auth_surface_request_unverified` denial instead of evaluating reusable request
extensions. Explicitly public read-only routes remain supported when they are
declared on the enclosing auth surface and allowed by the policy authority.

Server-specific business rules, token exchange execution, downstream client
calls, and product-specific allowlists stay in service crates. The toolkit owns
the shared request projection, fail-closed deny translation, and provenance
plumbing.

Use `docs/policy-kernel-provenance-acceptance.md` before claiming
policy-kernel adoption for a server. It names the runtime metadata, hosted
manifest, artifact identity, and deny-before-mutation evidence that consumers
must preserve; the consuming repository owns that evidence.

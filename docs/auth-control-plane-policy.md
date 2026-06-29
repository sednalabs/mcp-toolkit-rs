# Auth Control-Plane Policy Runtime

`mcp-toolkit-policy-runtime` provides a reusable auth/control-plane policy
surface for HTTP MCP servers that already use the toolkit auth surface.

The helper is intentionally narrow:

- `AuthControlPlaneHttpMapper` projects sanitized `AuthContext` and
  `AuthSurfaceContext` into an `auth-control-plane/v1` envelope.
- `AuthControlPlanePolicyAuthority` evaluates that envelope with the embedded
  policy kernel and emits `PolicyAuthorityDecision` provenance.
- `PolicyAuthorityLayer` attaches allow decisions to request extensions and deny
  decisions to response extensions.

The mapper copies actor, subject, scopes, roles, issuer, audience, client,
method, path, tool, action, resource, project, session, token-mode, delegation,
exchange, proof, risk, and health/status observation metadata. It deliberately
does not copy raw bearer tokens.

The default authority fails closed when authenticated context is absent,
session/project binding is inconsistent, token-exchange metadata is missing its
audit binding, sender-constrained posture is incomplete, or the embedded policy
kernel denies the route/scope/claims decision. Health and status routes are
protected by default; services can opt into `PublicReadOnly` exposure for
read-only health/status routes that the policy layer wraps.

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

let layer = PolicyAuthorityLayer::new(authority, AuthControlPlaneHttpMapper::default());
```

Server-specific business rules, token exchange execution, downstream client
calls, and product-specific allowlists stay in service crates. The toolkit owns
the shared request projection, fail-closed deny translation, and provenance
plumbing.

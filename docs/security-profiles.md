# MCP Auth Security Profiles (Inventory + Selection)

This document inventories common auth/token patterns and defines **security
profiles** to standardize new MCP deployments.
The goal is to make the right choice fast, repeatable, and auditable.

## Rationale

MCP services often have different trust boundaries: admin gateways, data access
boundaries, read-only tools, and local development harnesses. This catalog makes the intended
security level explicit so new services do not drift or over/under-harden.

## Profile Summary

| Profile | Intended use | Minimum controls | Typical implementation |
| --- | --- | --- | --- |
| **L0: Dev/Local** | local dev/test only | Delegation tokens, short TTLs | HS256 delegation; minimal checks |
| **L1: Read-only** | low-risk read-only services | JWKS/OIDC validation, required scopes | JWKS validation + strict resource URL |
| **L2: Strong** | sensitive read/limited write | JWKS + optional introspection, azp allowlist, opt-in JTI replay | JWKS + introspection cache + optional replay guard |
| **L3: Boundary/Gateway** | admin/data boundary | Dual validation + token exchange | Introspection + RFC 8693 exchange + policy boundary |

> **Rule of thumb:** prefer the highest level that matches the data sensitivity
> and trust boundary without introducing unnecessary moving parts.

## Profile Definitions

### L0: Dev/Local
- **Use when:** local developer environments, test harnesses, or bootstrapping.
- **Controls:**
  - Delegation token validation (HS256).
  - Short-lived tokens; replay guard optional.
- **Avoid:** production use.
- **Tooling fit:** `mcp-toolkit-auth` `AuthMode::Delegation`.

### L1: Read-only (Production basic)
- **Use when:** read-only tools that expose non-critical data and have no
  downstream policy boundary.
- **Controls:**
  - JWKS/OIDC validation (issuer + audience).
  - Required scopes for tool families.
  - Strict OAuth resource URL checks when possible.
- **Tooling fit:** `AuthMode::Jwks` + `strict_oauth = true`.

### L2: Strong (Production strong)
- **Use when:** sensitive read-only or constrained write operations (metadata
  change, config updates) and IP-sensitive content.
- **Controls:**
  - JWKS validation + **optional introspection** (revocation-aware).
  - Bearer-token JTI replay enforcement is opt-in; bearer tokens remain
    reusable by design unless explicitly configured for one-time use.
  - Streamable HTTP clients normally reuse one bearer token across initialize,
    initialized notification, and follow-up requests.
  - Client allowlists (`azp` / client_id) and strict token type where supported.
- **Tooling fit:** `AuthMode::Jwks` + introspection cache + optional replay guard + allowlists.

### L3: Boundary/Gateway
- **Use when:** crossing a **data boundary** (DB, admin APIs) or when the
  MCP itself must not carry admin credentials.
- **Controls:**
  - **Inbound token validation** (introspection/JWKS).
  - **Token exchange** (RFC 8693) to downscope for downstream calls.
  - Independent policy enforcement at the boundary service.
  - Bearer-token JTI replay enforcement only when the service explicitly opts
    into one-time bearer-token semantics.
  - Sender-constrained replay protection requires dedicated DPoP/mTLS handling;
    the profile presets do not imply it.
- **Tooling fit:** MCP validates; gateway performs exchange + policy enforcement.

## Common Service Shapes

### Read-only service with sensitive data

**Recommendation: L2 (Strong).**

Rationale:
- The service is read-only, but the data may still be sensitive or high-value.
- If there is no downstream boundary, the MCP server is the strongest gate.
- JWKS + optional introspection gives revocation awareness without the full
  gateway complexity.
- Add client allowlists (`azp`/client_id), strict OAuth resource checks, and
  explicit replay protections only when the transport/token contract supports
  them.

Minimum L2 controls:
- JWKS validation with strict issuer/audience.
- Required scope, such as `service:read`.
- Optional introspection cache (short TTL) for revocation.
- Allowlist of client IDs/`azp` for production.
- Host binding + allowed hosts (DNS rebinding protection).

### MCP server with a privileged downstream boundary

**Recommendation: L2 for the MCP server and L3 for the boundary service.**

Minimum controls:

- Resource-server validation at the MCP boundary.
- Independent validation at the downstream boundary.
- RFC 8693 token exchange where downscoping is required.
- Explicit scope, role, and audience checks before privileged operations.
- No long-lived downstream credentials in the MCP server.

## Implementation Guidance (Toolkit Alignment)

Use `mcp-toolkit-auth` for consistent primitives:
- `AuthMode::Jwks` or `AuthMode::Introspection` (production).
- Required scopes enforced centrally.
- Optional JTI replay guard for services that explicitly require one-time
  bearer-token semantics.
- Shared JTI replay stores via `JtiReplayStore` when a multi-worker deployment
  needs bearer replay state outside one authenticator process.
- Strict OAuth resource URL checks for protected resource metadata.

Auth/token mechanics must also follow
`docs/auth-token-dependency-posture.md`: JWT/JWK/OAuth/DPoP/introspection/token
exchange plumbing should be crate-backed, while local code stays limited to
reviewed glue, canonicalization, and policy-input projection.

### Profile presets (Rust)

`mcp-toolkit-auth` exposes `AuthSecurityProfile` with `L1ReadOnly`, `L2Strong`, and
`L3Boundary` presets. These helpers set conservative defaults for introspection
caching and strict OAuth settings, but **do not** populate issuer, audience,
JWKS URL, required scopes, or one-time bearer-token replay enforcement. Services
must still set those fields per environment.

```rust
use mcp_toolkit_auth::{AuthConfig, AuthSecurityProfile};

let mut auth = AuthConfig::with_profile(AuthSecurityProfile::L2Strong);
auth.issuer = Some("https://issuer.example".to_string());
auth.audience = Some("service-aud".to_string());
auth.jwks_url = Some("https://issuer.example/certs".to_string());
auth.required_scopes = vec!["service:read".to_string()];
```

Auth profiles are separate from tool-surface profiles. Generated servers should
use `ToolCatalog::with_standard_profiles(["read"])` so the live MCP surface
starts in `read_only` mode while an explicit `operator` profile can expose
reviewed mutation tools. If a provider write scope is missing, report that as
provider auth/permission state; if the tool is hidden by `read_only`, report the
tool-profile denial such as `TOOL_DENIED_READ_ONLY_PROFILE`.

Where the toolkit does not yet cover a feature (e.g., DPoP/mTLS sender
constraints), document the divergence and prefer alignment work in the toolkit
before service-specific implementations.

## Selection Checklist for New Services

1. Is there a downstream boundary (DB/admin API)? If yes → L3.
2. Is data sensitive (IP, customer data)? If yes → L2 or higher.
3. Is the service read-only and low sensitivity? L1 may be sufficient.
4. Is this dev/test only? L0 acceptable.

## References

- `../crates/mcp-toolkit-auth/src/lib.rs`
- `../crates/mcp-toolkit-auth/src/config.rs`

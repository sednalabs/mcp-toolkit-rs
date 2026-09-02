# Policy Kernel Provenance Acceptance

This note defines the toolkit-side acceptance contract for MCP servers that
consume policy-kernel evidence. It keeps runtime metadata, hosted artifacts,
and release wording aligned without claiming whole-service formal proof.

## Acceptance Envelope

Every server adoption claim must preserve these decision fields from
`PolicyAuthorityDecision`:

- `decision_source`: which toolkit authority produced the decision;
- `runtime_mode`: `rust`, `spark_prefer`, or `spark_required`;
- `policy_contract_version`: the kernel contract version evaluated by the
  decision, when the authority has a versioned contract;
- `required_scopes`: the scopes the authority required for allow decisions,
  when available.

Services can enforce the metadata shape with
`PolicyProvenanceRequirement` before installing an authority or before
accepting a policy decision as release evidence:

```rust
use mcp_toolkit_policy_runtime::{
    PolicyAuthority, PolicyProvenanceRequirement, PolicyRuntimeMode,
};

let decision = authority.evaluate(&request);
decision.validate_provenance(
    &PolicyProvenanceRequirement::new()
        .decision_source_prefix("mcp_toolkit_policy_runtime.sql_restricted")
        .allow_runtime_mode(PolicyRuntimeMode::Rust)
        .policy_contract_version("sql-restricted/v1"),
)?;
```

For `auth-control-plane/v1`, the expected toolkit authority source is
`mcp_toolkit_policy_runtime.auth_control_plane`.

## Evidence Required Before Adoption Claims

An MCP server can claim toolkit policy-kernel adoption only when it has all of
the following:

- a `PolicyAuthorityDecision` whose provenance satisfies the server's
  `PolicyProvenanceRequirement`;
- a hosted toolkit consumption manifest from
  `.github/workflows/policy-kernel-consumption.yml` or an equivalent trusted
  proof lane;
- the policy-kernel commit, contract version, and downloaded artifact SHA-256
  identities from that manifest when artifacts are supplied;
- a reference to the relevant policy-kernel claim ledger row;
- local evidence that denied or uncertain policy results stop handler
  invocation and mutation before side effects occur.

For auth/control-plane consumers, the relevant policy-kernel references are:

- `spec/release-assurance-claim-ledger.md`;
- `spec/auth-control-plane-invariant-frontier.md`;
- `spec/consumer-mutation-denial-contract.md`.

## Server Integration Rules

Install auth/control-plane mappers after authentication and canonicalization.
Raw bearer tokens, raw OAuth responses, raw HTTP parsing, and product-specific
business rules stay outside the toolkit authority.

When a mapper cannot determine subject, actor, project, session, delegation, or
sender-constrained posture with confidence, the service must deny before
calling downstream handlers or mutating shared state.

For delegated or act-as surfaces, preserve the selected project, effective
project, subject, actor, session, and delegation evidence source in service
logs or response extensions where the service exposes policy provenance.

For `spark_required`, missing SPARK runtime availability must remain
fail-closed. For `spark_prefer`, fallback to Rust must preserve the configured
runtime mode and decision source so operators can tell that SPARK was preferred
but not used for that decision.

## Hosted Consumption Manifest

The hosted consumption workflow records:

- toolkit SHA;
- configured policy-kernel ref and SHA;
- runtime modes exercised;
- decision metadata coverage;
- SQL conformance report summary;
- optional downloaded artifact paths and SHA-256 values.

Public policy-kernel targets can be consumed by the public workflow without an
extra secret. Private or inaccessible targets require a trusted proof lane
outside this public workflow.

The consuming repository owns its manifest, policy-kernel ref, downloaded
artifacts, claim-ledger reference, and deny-before-mutation evidence. This
document defines the toolkit-side acceptance contract; it does not create or
maintain those consumer-local files.

## Non-Claims

This acceptance contract does not prove:

- OAuth, JWT, DPoP, Keycloak, TLS, HTTP, URI, JSON, or raw token parsing;
- distributed replay-cache freshness;
- middleware ordering in a consuming service;
- session persistence, transaction rollback, audit durability, or queue
  behavior;
- production rollout safety without server-local evidence.

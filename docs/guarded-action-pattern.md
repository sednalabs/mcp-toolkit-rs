# Guarded Action Pattern

This pattern is for services that need useful administrative inspection or
preview tools without accidentally turning the server into an always-on write
surface.

## Core Primitives

`mcp-toolkit-core::guarded_action` provides the reusable substrate:

- `GuardedActionPosture` describes whether an action is read-only,
  no-mutation proof, preview, guarded apply, mutating, destructive, or
  send-adjacent.
- `GuardedActionRuntimeMode` enforces fail-closed service modes:
  `read_only`, `preview_only`, and `enabled`.
- `GuardedActionPlanSeed` builds deterministic plan ids from public-safe action,
  scope, and target identifiers.
- `GuardedActionPreview<TPreview, TEvidence>` and
  `GuardedActionApply<TApplied, TEvidence>` provide typed response envelopes for
  preview/apply flows.
- `GuardedActionNoMutationProof<TProof, TEvidence>` provides a typed response
  envelope for proof-only tools that approach a hazardous boundary while
  keeping `mutation_performed=false` and `production_action_authorized=false`.

These helpers do not replace service-owned authorization, allowlists, or fresh
readback. They standardize the shape so different MCP servers stop reinventing
the same policy hints.

## Attaching Risk Posture To Tool Inventory

Use `ToolCapability::with_risk_posture(...)` so discovery, audits, and deferred
tool-search consumers can distinguish simple reads from guarded writes:

```rust
use mcp_toolkit_core::guarded_action::GuardedActionPosture;
use mcp_toolkit_core::tool_inventory::ToolCapability;

let preview = ToolCapability::new("queue_control_preview")
    .with_group("admin")
    .with_risk_posture(GuardedActionPosture::preview());

let apply = ToolCapability::new("queue_control_apply")
    .with_group("admin")
    .with_risk_posture(GuardedActionPosture::guarded_apply());

let proof = ToolCapability::new("send_wizard_readback")
    .with_group("admin")
    .with_risk_posture(GuardedActionPosture::no_mutation_proof());
```

The `ToolSearchResponse` JSON now carries `risk_posture` for each matching tool
when that metadata is present.

## Read-Only HTTP Or Admin Guards

For a service-level runtime mode:

1. classify the action with `GuardedActionPosture`;
2. load the current `GuardedActionRuntimeMode` from service config;
3. call `runtime_mode.assert_allowed(action_name, posture)` before any unsafe
   backend route, admin page, or apply submission is touched.

This keeps the default behavior boring:

- `read_only` allows reads only;
- `read_only` also allows no-mutation proof tools because they are
  non-mutating, but those tools must expose their proof boundary explicitly;
- `preview_only` allows reads plus preview planning;
- `enabled` allows guarded apply and other reviewed write surfaces.

## No-Mutation Proof Tools

Use `GuardedActionPosture::no_mutation_proof()` before adding service-local
"safe preview" or "readback" helpers that touch a hazardous workflow boundary.
Examples include rendering a final confirmation form, resolving a send wizard
recipient count, or probing a publish path without submitting the final action.

The service still owns:

- an explicit route/action allowlist;
- before/after invariant readback;
- proof evidence that explains exactly where the tool stopped;
- tests that prove the final mutation, send, publish, trigger, or schedule step
  was not invoked.

The generic helper `no_mutation_proof_policy_decision(...)` in
`mcp-toolkit-policy-core` can be used to fail closed if a response admits that
proof was not performed, evidence is empty, a mutation occurred, or a
production action was authorized.

## Plan Binding Guidance

Build plan ids only from non-secret identifiers. Good inputs are:

- reviewed action family, such as `queue-control`;
- explicit scope, such as `tenant-42`;
- target or form state identifier that is already safe to expose, or a service-
  owned redacted fingerprint.

Do not pass raw secrets, access tokens, or hidden form values into
`GuardedActionPlanSeed`.

## Preview/Apply Response Shape

Preview should return:

- deterministic `plan_id`;
- posture and runtime mode;
- bounded preview payload;
- compact evidence that lets an operator confirm the scope;
- optional expiry timestamp when the preview should not live forever.

Apply should return:

- the exact `plan_id` it honored;
- posture and runtime mode;
- bounded applied result;
- redacted readback evidence that proves the state after the mutation.

## References

- `docs/easy-server-ergonomics.md`
- `docs/legacy-system-adapter-pattern.md`
- `crates/mcp-toolkit-core/src/guarded_action.rs`

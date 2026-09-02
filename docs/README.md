# Documentation map

This map points to the repository's public guides and decision records. Start
with one audience section, then follow the linked deep guide that answers the
question at hand.

## Evaluators and consumers

- [Golden path](golden-path.md) — end-to-end server shape, crate boundaries, contracts, hosted checks, and release handoff.
- [Toolkit boundary](toolkit-boundary.md) — what belongs here versus in a consuming service.
- [Ecosystem map](ecosystem-map.md) — toolkit, reference architecture, and service layers.
- [Reference-server atlas](reference-server-atlas.md) — living public implementations to study.
- [Pattern manifests](pattern-manifests.md) and [pattern recipes](pattern-recipes.md) — machine-readable shapes and adoption guidance.
- [Downstream conformance](downstream-conformance.md) — checking a consuming server against a reference pattern.

## Server authors

- [Starter templates](starter-templates.md), [new-server CLI reference](new-server-cli-reference.md), and [new-server delivery lane](new-server-delivery-lane.md) — choose, generate, and prove a server scaffold.
- [Easy server ergonomics](easy-server-ergonomics.md) and [provider auth/client configuration](provider-auth-and-client-config.md) — first-run setup and diagnostics.
- [Tool inventory migration](tool-inventory-migration.md), [tool schema snapshots](tool-schema-snapshots.md), and [contract testing](contract-testing.md) — stable tool contracts.
- [Deferred loading and tool search](deferred-loading-and-tool-search.md) — large catalogues and discovery.
- [Server composition layer](server-composition-layer.md), [SEP-2243 HTTP headers](sep-2243-http-headers.md), and [scratchpad](scratchpad.md) — reusable runtime composition, the current Streamable HTTP header contract, and bounded analytical state.
- [Legacy-system adapter pattern](legacy-system-adapter-pattern.md) — safe integration of partial or legacy APIs.

## Security and policy adopters

- [Auth surface](auth-surface.md), [auth error contracts](auth-error-contracts.md), [auth replay stores](auth-replay-stores.md), and [token dependency posture](auth-token-dependency-posture.md).
- [Auth control-plane policy](auth-control-plane-policy.md), [security profiles](security-profiles.md), [guarded action pattern](guarded-action-pattern.md), and [upstream OAuth](upstream-oauth.md).
- [Policy kernel provenance acceptance](policy-kernel-provenance-acceptance.md), [SQL policy-kernel conformance](sql-policy-kernel-conformance.md), and [policy dependency governance](dependency-governance.md).
- [Capability projections](capability-projections.md), [provider auth](provider-auth-and-client-config.md), and [MCP/rmcp alignment review](mcp-rmcp-alignment-review.md).

## Maintainers and release owners

- [Contributing guide](../CONTRIBUTING.md), [public landing policy](public-landing-policy.md), [cargo package release](cargo-package-release.md), and [dependency governance](dependency-governance.md).
- [CodeQL query-pack reuse](codeql-query-pack-reuse.md) and [observability rollout](observability-rollout.md).
- [Observability evolution](observability-evolution.md), [new-server delivery lane](new-server-delivery-lane.md), and the decision records below.

## Decision records and reference notes

The `decision-0001` through `decision-0006` files, [scratchpad notes](scratchpad.md), [capability projections](capability-projections.md), [instant server generation](instant-server-generation.md), [provider auth](provider-auth-and-client-config.md), and [public landing policy](public-landing-policy.md) preserve design context. They are evidence and decision records, not a promise that every proposal is implemented.

Other focused references include [architecture](ARCHITECTURE.md), [tool guide](TOOL_GUIDE.md), [dependency governance](dependency-governance.md), [contract testing](contract-testing.md), [pattern manifests](pattern-manifests.md), [observability evolution](observability-evolution.md), [observability rollout](observability-rollout.md), [new-server CLI](new-server-cli-reference.md), [MCP/rmcp alignment](mcp-rmcp-alignment-review.md), [provider auth](provider-auth-and-client-config.md), [capability projections](capability-projections.md), and [toolkit boundary](toolkit-boundary.md).

### Consumer-local evidence

Paths such as `spec/`, `.github/workflows/`, generated snapshots, and release
receipts in a consuming repository remain owned and maintained by that
consumer. Toolkit documentation describes the contract; it does not make
consumer-local evidence part of this repository.

# Pattern Manifests

Pattern manifests are small JSON files that describe which reusable MCP server
shapes a reference server or template demonstrates. They sit between the
human-readable atlas and future generator or documentation tooling.

Use manifests when a pattern is real enough to reuse but not yet ready to
become a toolkit API. The manifest records the evidence without copying
provider clients, deployment policy, or product vocabulary into this toolkit.
The `mcp-toolkit patterns` CLI command uses manifest evidence generated from
`docs/pattern-manifests/*.json`, so new server authors can inspect an archetype
without opening every reference repository first. Add a registry entry when a
new manifest introduces a new archetype.

## Files

- `docs/pattern-manifest.schema.json` is the schema for manifest version 1.
- `docs/pattern-manifests/*.json` are example manifests for reference servers.
- `docs/reference-server-atlas.md` remains the human map and extraction guide.
- `docs/pattern-recipes.md` turns the same patterns into implementation steps.
- `docs/downstream-conformance.md` explains the advisory conformance report
  generated from the same manifests.

Each manifest should be public, boring, and reviewable. It must not contain
secrets, hostnames, account ids, private paths, or environment-specific setup.

## Required Shape

Every manifest has these top-level fields:

| Field | Purpose |
| --- | --- |
| `schema_version` | Manifest format version. Use `1` until the schema changes. |
| `server` | Name, public repository, language, and whether the row is a reference server, template, adoption slice, or adjacent reference. |
| `patterns` | Archetypes from `docs/reference-server-atlas.md`. |
| `toolkit_crates` | Toolkit crates that already own reusable substrate for this row. Empty is allowed for adjacent references. |
| `transports` | Served or demonstrated MCP transport shapes. |
| `auth_modes` | Authentication and authorization modes the row demonstrates. |
| `tool_surface` | Discovery, mutation, and schema-snapshot posture. |
| `scratchpad` | Whether large-result scratchpad behavior is supported and by which engine. |
| `profiles` | Named operator profiles and tool groups. Omit `default` when it is false. |
| `conformance` | Current proof posture for schema, transport, auth, domain, hosted validation, and release evidence. |
| `references` | Public docs, source landmarks, tests, templates, or workflows used as evidence. |

Prefer `planned` or `reference-only` over overstating the current toolkit
surface. A manifest is useful only if it tells later generator work what is
already reusable and what is still service-owned.

The CLI reports these states with:

```sh
mcp-toolkit conformance
mcp-toolkit conformance --pattern google-provider-read-only
mcp-toolkit conformance --strict
```

## Review Rules

When adding or updating a manifest:

1. Link it from the atlas row or the recipe that consumes it.
2. Keep provider-specific semantics in `references` and `notes`, not in generic
   field names.
3. Update `docs/pattern-recipes.md` if the manifest proves or changes a recipe.
4. Update `crates/mcp-toolkit-testing/tests/new_server_delivery_lane_docs.rs`
   when a required field, archetype, or directory name changes.
5. Record the manifest path in the PR or work item evidence block.
6. Run `mcp-toolkit conformance --strict` when the manifest changes; hard
   contradictions must be fixed before the row is used as generator evidence.

## Ownership Rules

Manifest fields should point to toolkit owners conservatively:

- `mcp-toolkit-core` owns inventory, schema, catalog, deferred-loading, and
  query-evidence substrate.
- `mcp-toolkit-server` owns stdio startup, Streamable HTTP assembly, route
  bundles, host guards, and server composition.
- `mcp-toolkit-auth` and `mcp-toolkit-http` own MCP auth metadata, bearer
  challenges, token validation surfaces, replay stores, and device-auth
  metadata.
- `mcp-toolkit-testing` owns schema snapshots, stdio contract tests, auth
  metadata tests, bearer challenges, host rejection, and future manifest
  conformance helpers.
- Policy crates own SQL classification, capability guards, and runtime policy
  adapters.
- `mcp-toolkit-scratchpad` owns generic DuckDB session lifecycle, bounded query,
  table inventory, retention, and local evidence-export substrate. Services
  still own provider-specific ingest and domain output contracts.

If no crate clearly owns a field yet, leave the manifest as evidence and create
a work item before adding a dependency or new API.

## Minimal Example

```json
{
  "schema_version": 1,
  "server": {
    "name": "example-mcp",
    "repository": "https://github.com/example/example-mcp",
    "language": "rust",
    "role": "reference_server"
  },
  "patterns": ["minimal-stdio-intent"],
  "toolkit_crates": ["mcp-toolkit-core", "mcp-toolkit-testing"],
  "transports": ["stdio"],
  "auth_modes": ["none"],
  "tool_surface": {
    "discovery": ["tool-inventory", "schema_snapshot"],
    "mutation_policy": "none",
    "schema_snapshot": "present"
  },
  "scratchpad": {
    "supported": false,
    "engine": "none",
    "profile": "none",
    "notes": "No large-result workflow."
  },
  "profiles": [
    {
      "name": "default",
      "default": true,
      "tool_groups": ["read"]
    }
  ],
  "conformance": {
    "schema_snapshot": "present",
    "transport_contract": "present",
    "auth_surface_contract": "not-applicable",
    "domain_contracts": "present",
    "hosted_validation": "present",
    "release_evidence": "planned"
  },
  "references": [
    {
      "label": "README",
      "kind": "doc",
      "path": "README.md"
    }
  ]
}
```

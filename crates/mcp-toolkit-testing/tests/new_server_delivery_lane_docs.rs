const LANE_DOC: &str = include_str!("../../../docs/new-server-delivery-lane.md");
const REFERENCE_ATLAS_DOC: &str = include_str!("../../../docs/reference-server-atlas.md");
const PATTERN_MANIFESTS_DOC: &str = include_str!("../../../docs/pattern-manifests.md");
const PATTERN_RECIPES_DOC: &str = include_str!("../../../docs/pattern-recipes.md");
const PATTERN_MANIFEST_SCHEMA: &str = include_str!("../../../docs/pattern-manifest.schema.json");
const PATTERN_MANIFEST_FILES: [(&str, &str); 6] = [
    (
        "cloudflare-mcp.json",
        include_str!("../../../docs/pattern-manifests/cloudflare-mcp.json"),
    ),
    (
        "ga4-mcp.json",
        include_str!("../../../docs/pattern-manifests/ga4-mcp.json"),
    ),
    (
        "google-admin-mcp.json",
        include_str!("../../../docs/pattern-manifests/google-admin-mcp.json"),
    ),
    (
        "google-search-console-mcp.json",
        include_str!("../../../docs/pattern-manifests/google-search-console-mcp.json"),
    ),
    (
        "keycloak-admin-mcp.json",
        include_str!("../../../docs/pattern-manifests/keycloak-admin-mcp.json"),
    ),
    (
        "postgres-mcp.json",
        include_str!("../../../docs/pattern-manifests/postgres-mcp.json"),
    ),
];

const REQUIRED_GATES: [&str; 7] = [
    "## Gate 1: Start From The Appropriate mcp-toolkit-rs Template",
    "## Gate 2: Define 3-7 First-Class Intent Tools",
    "## Gate 3: Add mcp-toolkit-testing Contract Coverage",
    "## Gate 4: Add Domain Output Contract Tests For Every Intent Tool",
    "## Gate 5: Validate On GitHub Actions",
    "## Gate 6: Require Reviewer Sidecar Signoff Before Merge",
    "## Gate 7: Install Or Promote Only From A Proven Artifact Or Tagged Commit",
];

const REQUIRED_EVIDENCE_LINES: [&str; 9] = [
    "Server shape:",
    "Toolkit template:",
    "Intent tools:",
    "Toolkit contract tests:",
    "Domain output contract tests:",
    "GitHub Actions run:",
    "Reviewer signoff:",
    "Promotion source:",
    "Rollback:",
];

#[test]
fn new_server_delivery_lane_keeps_required_gates_in_order() {
    let mut previous = 0;

    for gate in REQUIRED_GATES {
        let index = LANE_DOC
            .find(gate)
            .unwrap_or_else(|| panic!("missing required delivery lane gate: {gate}"));
        assert!(
            index >= previous,
            "delivery lane gate is out of order: {gate}"
        );
        previous = index;
    }
}

#[test]
fn new_server_delivery_lane_records_reviewable_evidence_block() {
    for line in REQUIRED_EVIDENCE_LINES {
        assert!(
            LANE_DOC.contains(line),
            "delivery lane evidence block is missing `{line}`"
        );
    }
}

#[test]
fn new_server_delivery_lane_mentions_primary_toolkit_surfaces() {
    for surface in [
        "mcp-toolkit --bin mcp-toolkit -- new",
        "mcp-toolkit --bin mcp-toolkit -- patterns",
        "mcp-toolkit patterns <id>",
        "mcp-toolkit templates",
        "--pattern minimal-stdio-intent",
        "templates/curated-stdio-intent-server",
        "templates/single-crate-public-stdio-server",
        "templates/hosted-http-auth-server",
        "mcp_toolkit_testing::stdio_contract::assert_stdio_tools_list",
        "mcp-toolkit-server::http::LocalMcpHttpServerBuilder",
        "Protected Resource Metadata",
        "GitHub Actions",
        "reviewer sidecar",
        "SHA256 digest",
    ] {
        assert!(
            LANE_DOC.contains(surface),
            "delivery lane does not mention `{surface}`"
        );
    }
}

#[test]
fn reference_server_atlas_covers_living_server_patterns() {
    for needle in [
        "sednalabs/google-admin-mcp",
        "sednalabs/ga4-mcp",
        "sednalabs/google-search-console-mcp",
        "sednalabs/cloudflare-mcp",
        "sednalabs/postgres-mcp",
        "sednalabs/keycloak-admin-mcp",
        "`minimal-stdio-intent`",
        "`google-provider-read-only`",
        "`analytics-scratchpad`",
        "`hosted-http-auth`",
        "`operator-mutation`",
        "`database-policy`",
        "`public-release-ready`",
    ] {
        assert!(
            REFERENCE_ATLAS_DOC.contains(needle),
            "reference server atlas is missing `{needle}`"
        );
    }
}

#[test]
fn delivery_lane_requires_reference_atlas_evidence() {
    for needle in [
        "docs/reference-server-atlas.md",
        "the reference atlas row used, or why no row fits",
        "docs/pattern-manifests/*.json",
        "docs/pattern-recipes.md",
        "the pattern manifest and recipe used, or why no manifest fits yet",
    ] {
        assert!(
            LANE_DOC.contains(needle),
            "delivery lane is missing atlas evidence requirement `{needle}`"
        );
    }
}

#[test]
fn pattern_manifest_docs_pin_the_generator_facing_contract() {
    for needle in [
        "docs/pattern-manifest.schema.json",
        "docs/pattern-manifests/*.json",
        "mcp-toolkit patterns",
        "manifest evidence generated from",
        "Add a registry entry",
        "Omit `default` when it is false",
        "schema_version",
        "toolkit_crates",
        "auth_modes",
        "tool_surface",
        "scratchpad",
        "conformance",
        "mcp-toolkit-core",
        "mcp-toolkit-testing",
    ] {
        assert!(
            PATTERN_MANIFESTS_DOC.contains(needle),
            "pattern manifest docs are missing `{needle}`"
        );
    }

    for needle in [
        "\"schema_version\"",
        "\"server\"",
        "\"patterns\"",
        "\"toolkit_crates\"",
        "\"transports\"",
        "\"auth_modes\"",
        "\"tool_surface\"",
        "\"scratchpad\"",
        "\"profiles\"",
        "\"conformance\"",
        "\"references\"",
        "\"minimal-stdio-intent\"",
        "\"google-provider-read-only\"",
        "\"analytics-scratchpad\"",
        "\"hosted-http-auth\"",
        "\"operator-mutation\"",
        "\"database-policy\"",
        "\"public-release-ready\"",
    ] {
        assert!(
            PATTERN_MANIFEST_SCHEMA.contains(needle),
            "pattern manifest schema is missing `{needle}`"
        );
    }
}

#[test]
fn pattern_recipes_cover_all_atlas_archetypes() {
    for needle in [
        "## `minimal-stdio-intent`",
        "## `google-provider-read-only`",
        "## `analytics-scratchpad`",
        "## `hosted-http-auth`",
        "## `operator-mutation`",
        "## `database-policy`",
        "## `public-release-ready`",
        "Toolkit owner:",
        "Reference manifests:",
        "Required proof:",
    ] {
        assert!(
            PATTERN_RECIPES_DOC.contains(needle),
            "pattern recipes are missing `{needle}`"
        );
    }
}

#[test]
fn pattern_manifest_examples_are_present_for_reference_rows() {
    let manifest_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/pattern-manifests");

    let entries = std::fs::read_dir(&manifest_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_dir.display()));
    let mut discovered = std::collections::BTreeSet::new();

    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!("failed to read entry in {}: {err}", manifest_dir.display())
        });
        let file_name = entry.file_name();
        let file_name = file_name
            .to_str()
            .unwrap_or("<non-utf8 manifest filename>")
            .to_owned();
        if !file_name.ends_with(".json") {
            continue;
        }
        discovered.insert(file_name);
    }

    for (file_name, manifest) in PATTERN_MANIFEST_FILES {
        assert!(
            discovered.remove(file_name),
            "expected pattern manifest file is missing: {file_name}"
        );
        let value: serde_json::Value = serde_json::from_str(manifest)
            .unwrap_or_else(|err| panic!("invalid JSON in {file_name}: {err}"));

        for field in [
            "schema_version",
            "server",
            "patterns",
            "toolkit_crates",
            "transports",
            "auth_modes",
            "tool_surface",
            "scratchpad",
            "profiles",
            "conformance",
            "references",
        ] {
            assert!(
                value.get(field).is_some(),
                "{file_name} is missing required field `{field}`"
            );
        }
    }

    assert!(
        discovered.is_empty(),
        "unexpected pattern manifest files without include_str! coverage: {discovered:?}"
    );
}

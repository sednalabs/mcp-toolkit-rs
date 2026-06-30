const LANE_DOC: &str = include_str!("../../../docs/new-server-delivery-lane.md");
const REFERENCE_ATLAS_DOC: &str = include_str!("../../../docs/reference-server-atlas.md");

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
        "templates/curated-stdio-intent-server",
        "templates/single-crate-public-stdio-server",
        "templates/hosted-http-auth-server",
        "mcp_toolkit_testing::stdio_contract::assert_stdio_tools_list",
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
    ] {
        assert!(
            LANE_DOC.contains(needle),
            "delivery lane is missing atlas evidence requirement `{needle}`"
        );
    }
}

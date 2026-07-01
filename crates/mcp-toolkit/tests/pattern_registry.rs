use std::process::Command;

use mcp_toolkit::patterns::{
    conformance_findings, manifests_for_pattern, pattern_manifests, patterns,
    recommended_template_for_pattern, PatternConformanceSeverity,
};

#[test]
fn pattern_registry_has_manifest_evidence_and_templates() {
    for pattern in patterns() {
        assert!(
            manifests_for_pattern(pattern.id).next().is_some(),
            "missing manifest evidence for {}",
            pattern.id
        );
        assert!(
            recommended_template_for_pattern(pattern.id).is_some(),
            "missing recommended template for {}",
            pattern.id
        );
    }
}

#[test]
fn cli_lists_patterns_and_pattern_details() {
    let list_output = run_toolkit(["patterns"]);
    assert!(list_output.contains("minimal-stdio-intent"));
    assert!(list_output.contains("google-provider-read-only"));
    assert!(list_output.contains("hosted-http-auth"));

    let detail_output = run_toolkit(["patterns", "google-provider-read-only"]);
    assert!(detail_output.contains("Archetype: google-provider-read-only"));
    assert!(detail_output.contains("Recommended template: curated-stdio-intent"));
    assert!(detail_output.contains("google-admin-mcp"));
    assert!(detail_output.contains("google-search-console-mcp"));
    assert!(detail_output.contains("conformance: schema=present"));
    assert!(detail_output.contains("docs/pattern-recipes.md#google-provider-read-only"));

    let help_output = run_toolkit(["patterns", "--help"]);
    assert!(help_output.contains("Patterns include manifest evidence"));
    assert!(!help_output.contains("Patterns are generated from"));
}

#[test]
fn pattern_manifests_have_no_hard_conformance_findings() {
    let hard_findings: Vec<_> = pattern_manifests()
        .iter()
        .flat_map(conformance_findings)
        .filter(|finding| finding.severity == PatternConformanceSeverity::Hard)
        .collect();

    assert!(
        hard_findings.is_empty(),
        "hard conformance findings: {hard_findings:#?}"
    );
}

#[test]
fn cli_reports_downstream_conformance() {
    let output = run_toolkit(["conformance"]);
    assert!(output.contains("Downstream MCP conformance posture"));
    assert!(output.contains("google-search-console-mcp"));
    assert!(output.contains("schema=present transport=present auth=present"));
    assert!(output.contains("release evidence is planned"));

    let pattern_output = run_toolkit(["conformance", "--pattern", "analytics-scratchpad"]);
    assert!(pattern_output.contains("ga4-mcp"));
    assert!(pattern_output.contains("google-search-console-mcp"));
    assert!(!pattern_output.contains("postgres-mcp"));

    let server_output = run_toolkit(["conformance", "--server", "postgres-mcp"]);
    assert!(server_output.contains("postgres-mcp"));
    assert!(server_output.contains("release=present"));

    let strict_output = run_toolkit(["conformance", "--strict"]);
    assert!(strict_output.contains("hard=0"));
}

fn run_toolkit<const N: usize>(args: [&str; N]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run mcp-toolkit: {error}"));

    assert!(
        output.status.success(),
        "mcp-toolkit exited with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("mcp-toolkit stdout was not UTF-8: {error}"))
}

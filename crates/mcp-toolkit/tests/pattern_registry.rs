use std::process::Command;

use mcp_toolkit::patterns::{manifests_for_pattern, patterns, recommended_template_for_pattern};

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
    assert!(detail_output.contains("docs/pattern-recipes.md#google-provider-read-only"));
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

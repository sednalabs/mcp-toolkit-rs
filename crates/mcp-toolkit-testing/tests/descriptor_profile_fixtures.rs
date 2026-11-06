//! Replays portable descriptor fixtures against the existing toolkit profile.

use mcp_toolkit_testing::openai_apps_contract::OpenAiAppsConformanceProfile;
use serde_json::Value;
use std::collections::BTreeSet;

#[test]
fn descriptor_profile_fixture_expectations() {
    let corpus: Value =
        serde_json::from_str(include_str!("../fixtures/descriptor-profiles-v1.json"))
            .expect("valid fixture JSON");
    assert_eq!(corpus["format_version"], 1);
    let cases = corpus["cases"].as_array().expect("fixture cases");
    assert!(!cases.is_empty());
    let mut ids = BTreeSet::new();
    let profile = OpenAiAppsConformanceProfile::new("https://example.test/mcp", &[])
        .with_tool_only_connector_metadata()
        .with_required_output_schema();
    for case in cases {
        let id = case["id"].as_str().expect("case ID");
        assert!(ids.insert(id), "duplicate fixture ID: {id}");
        let expected = case["expected"]["toolkit_tool_only_required_output"]
            .as_bool()
            .expect("toolkit expectation");
        let actual = std::panic::catch_unwind(|| {
            profile.assert_tool_descriptor(&case["descriptor"]);
        })
        .is_ok();
        assert_eq!(actual, expected, "fixture {id}");
        // Probe expectations are source-pinned, not executed by this crate.
        for kind in ["errors", "warnings"] {
            let codes = case["expected"]["probe_chatgpt_tool"][kind]
                .as_array()
                .expect("probe finding codes");
            assert!(codes.iter().all(|code| code.as_str().is_some()));
        }
    }
}

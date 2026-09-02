use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const PLANNER: &str = include_str!("../../../tests/validation_lab/planner.json");
const CATALOG: &str = include_str!("../../../tests/validation_lab/catalog.json");
const ARTIFACT_ORIGIN: &str =
    include_str!("../../../tests/validation_lab/artifact_origin_negative.json");
const WORKFLOW: &str =
    include_str!("../../../tests/validation_lab/workflow_contract.json");
const AGGREGATOR_CASES: [(&str, &str); 4] = [
    (
        "no-op",
        include_str!("../../../tests/validation_lab/aggregator_noop.json"),
    ),
    (
        "unknown",
        include_str!("../../../tests/validation_lab/aggregator_unknown.json"),
    ),
    (
        "blocker",
        include_str!("../../../tests/validation_lab/aggregator_blocker.json"),
    ),
    (
        "ranking",
        include_str!("../../../tests/validation_lab/aggregator_ranking.json"),
    ),
];

fn json(raw: &str) -> Value {
    serde_json::from_str(raw).expect("validation-lab fixture must be valid JSON")
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing fixture field `{key}`"))
}

fn string_field(value: &Value, key: &str) -> &str {
    field(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("fixture field `{key}` must be a string"))
}

fn exact_sha(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[test]
fn planner_pins_profiles_lanes_and_exact_candidate_identity() {
    let planner = json(PLANNER);
    assert_eq!(string_field(&planner, "schema"), "toolkit_frontier_plan");
    assert_eq!(field(&planner, "version"), 1);

    let candidate = field(&planner, "candidate");
    assert_eq!(string_field(candidate, "repository"), "sednalabs/mcp-toolkit-rs");
    assert_eq!(string_field(candidate, "ref"), "refs/heads/main");
    assert!(exact_sha(string_field(candidate, "sha"), 40));
    assert!(exact_sha(string_field(candidate, "tree"), 40));
    let targets = field(&planner, "target_set")
        .as_array()
        .expect("target set array");
    let targets: Vec<_> = targets
        .iter()
        .map(|target| target.as_str().expect("target string"))
        .collect();
    assert_eq!(
        targets,
        [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ]
    );
    let target_set: BTreeSet<_> = targets.iter().copied().collect();

    let profiles = field(&planner, "profiles")
        .as_array()
        .expect("profiles array");
    let profile_ids: BTreeSet<_> = profiles
        .iter()
        .map(|profile| string_field(profile, "id"))
        .collect();
    assert_eq!(profile_ids, BTreeSet::from(["checkpoint", "frontier", "targeted"]));

    let lanes = field(&planner, "lanes").as_array().expect("lanes array");
    let mut lane_ids = BTreeSet::new();
    for lane in lanes {
        assert!(
            lane_ids.insert(string_field(lane, "lane_id")),
            "lane IDs must be unique"
        );
        let identity = field(lane, "identity");
        for key in ["repository", "ref", "sha", "tree"] {
            assert_eq!(
                field(identity, key),
                field(candidate, key),
                "lane identity drifted for {key}"
            );
        }
        let artifact = field(lane, "artifact");
        assert!(target_set.contains(string_field(lane, "target")));
        assert!(!string_field(artifact, "name").is_empty());
        assert!(!string_field(artifact, "run_id").is_empty());
        assert!(
            field(artifact, "run_attempt")
                .as_u64()
                .is_some_and(|attempt| attempt > 0)
        );
        if string_field(lane, "lane_id") == "frontier-five-target" {
            let artifact_targets: BTreeSet<_> = field(artifact, "targets")
                .as_array()
                .expect("frontier target list")
                .iter()
                .map(|target| target.as_str().expect("target string"))
                .collect();
            assert_eq!(artifact_targets, target_set);
        }
    }

    let summaries = field(&planner, "summary_families")
        .as_array()
        .expect("summary families array");
    let mut sentinels = BTreeSet::new();
    for summary in summaries {
        assert!(
            sentinels.insert(string_field(summary, "sentinel")),
            "sentinels must be unique"
        );
        assert!(
            field(summary, "depth")
                .as_u64()
                .is_some_and(|depth| depth > 0)
        );
    }
}

#[test]
fn catalog_keeps_package_and_rmcp_entries_unmaterialized() {
    let catalog = json(CATALOG);
    let entries = field(&catalog, "entries")
        .as_array()
        .expect("catalog entries array");
    assert_eq!(entries.len(), 2);
    for entry in entries {
        assert_eq!(string_field(entry, "status"), "catalog-only");
        assert_eq!(string_field(entry, "implementation"), "unmaterialized");
        assert_eq!(string_field(entry, "acceptance"), "not-claimed");
    }
}

#[test]
fn aggregator_fails_closed_for_noop_unknown_and_blocker_cases() {
    for (case_name, raw) in AGGREGATOR_CASES {
        let fixture = json(raw);
        assert_eq!(string_field(&fixture, "case"), case_name);
        let expected = field(&fixture, "expected");
        if case_name != "ranking" {
            assert_eq!(string_field(expected, "decision"), "fail");
            assert_eq!(
                field(&fixture, "lanes")
                    .as_array()
                    .expect("lanes array")
                    .len(),
                1
            );
        }
    }
}

#[test]
fn aggregator_ranks_independently_actionable_failures_before_optional_evidence() {
    let fixture = json(AGGREGATOR_CASES[3].1);
    let expected = field(&fixture, "expected");
    let ranked = field(expected, "ranked_failures")
        .as_array()
        .expect("ranked failures");
    let ranked: Vec<_> = ranked
        .iter()
        .map(|id| id.as_str().expect("lane ID string"))
        .collect();
    assert_eq!(
        ranked,
        ["lane-blocker", "lane-unknown", "lane-noop"]
    );
    assert!(!ranked.contains(&"lane-optional"));
}

#[test]
fn artifact_identity_rejects_same_name_from_a_different_run_attempt() {
    let fixture = json(ARTIFACT_ORIGIN);
    let candidate = field(&fixture, "candidate");
    let artifacts = field(&fixture, "artifacts")
        .as_array()
        .expect("artifacts array");
    let mut identities = BTreeMap::new();
    for artifact in artifacts {
        for key in ["repository", "ref", "tree"] {
            assert_eq!(field(artifact, key), field(candidate, key));
        }
        assert_eq!(field(artifact, "head_sha"), field(candidate, "sha"));
        let identity = (
            string_field(artifact, "name"),
            string_field(artifact, "run_id"),
            field(artifact, "run_attempt")
                .as_u64()
                .expect("positive run attempt"),
        );
        assert!(
            identities.insert(identity, artifact).is_none(),
            "duplicate artifact identities must be rejected"
        );
        assert!(exact_sha(string_field(artifact, "head_sha"), 40));
    }
    assert_eq!(artifacts[0].get("name"), artifacts[1].get("name"));
    assert_eq!(artifacts[0].get("run_id"), artifacts[1].get("run_id"));
    assert_ne!(artifacts[0].get("run_attempt"), artifacts[1].get("run_attempt"));
    assert_eq!(
        artifacts[0].get("name").and_then(Value::as_str),
        Some("frontier-lane")
    );
    assert_eq!(
        artifacts[0].get("run_id").and_then(Value::as_str),
        Some("2001")
    );
    assert!(!field(&fixture, "expected")
        .get("accepted")
        .and_then(Value::as_bool)
        .unwrap());
}

#[test]
fn generated_workflow_contract_requires_canonical_coupling_and_fail_slow_uploads() {
    let workflow = json(WORKFLOW);
    let contract = field(&workflow, "workflow");
    assert_eq!(field(contract, "generated"), true);
    assert_eq!(string_field(contract, "artifact_upload"), "always");
    assert_eq!(string_field(contract, "fanout"), "capped-fail-slow");
    assert_eq!(string_field(contract, "aggregation"), "target-bound");

    let coupling = field(&workflow, "coupling");
    assert_eq!(string_field(coupling, "proof"), "canonical-generator");
    let fields = field(coupling, "shared_fields")
        .as_array()
        .expect("coupled fields");
    for required in [
        "repository",
        "ref",
        "sha",
        "tree",
        "profile",
        "lane_id",
        "target",
        "run_id",
        "run_attempt",
    ] {
        assert!(fields.iter().any(|field| field.as_str() == Some(required)));
    }
}

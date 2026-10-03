#![cfg(feature = "operational-resources")]

use mcp_toolkit_server::operational_resources::{
    OperationalResourceError, OperationalResourceUris, OperationalState, OperationalStatus,
};
use rmcp::model::{ProtocolVersion, ResourceContents};
use serde_json::{json, Value};

fn resources() -> OperationalResourceUris {
    OperationalResourceUris::new(
        "build-helper://ops/status",
        "build-helper://ops/attestation",
    )
    .expect("valid distinct custom resource URIs")
}

#[test]
fn uri_validation_requires_distinct_custom_schemes() {
    assert_eq!(
        OperationalResourceUris::new("https://example/status", "example://attestation"),
        Err(OperationalResourceError::InvalidUri)
    );
    assert_eq!(
        OperationalResourceUris::new("example://same", "example://same"),
        Err(OperationalResourceError::DuplicateUris)
    );
    assert_eq!(
        OperationalResourceUris::new("example://status?token", "example://attestation"),
        Err(OperationalResourceError::InvalidUri)
    );
}

#[test]
fn status_output_is_closed_and_timestamped_by_the_helper() {
    let resources = resources();
    let status = OperationalStatus {
        state: OperationalState::Degraded,
        component: "mcp-server".to_owned(),
        server_version: "1.2.3".to_owned(),
    };
    let result = resources
        .read_status(
            "build-helper://ops/status",
            &status,
            &ProtocolVersion::V_2026_07_28,
        )
        .expect("valid status projection");
    let text = match &result.contents[0] {
        ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("status resource is JSON text"),
    };
    let value: Value = serde_json::from_str(text).expect("valid JSON status");
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["component"], "mcp-server");
    assert_eq!(value["server_version"], "1.2.3");
    assert!(value["timestamp"].as_u64().is_some());
    assert_eq!(result.ttl_ms, Some(0));
    assert_eq!(result.cache_scope, Some(rmcp::model::CacheScope::Private));
}

#[test]
fn resource_results_follow_current_and_legacy_protocol_fields() {
    let resources = resources();
    let status = OperationalStatus {
        state: OperationalState::Ready,
        component: "mcp-server".to_owned(),
        server_version: "1.2.3".to_owned(),
    };
    let current = resources.list_result(&ProtocolVersion::V_2026_07_28);
    assert_eq!(current.resources.len(), 2);
    assert_eq!(current.ttl_ms, Some(0));
    assert_eq!(current.cache_scope, Some(rmcp::model::CacheScope::Private));
    assert_eq!(current.result_type, Some(rmcp::model::ResultType::COMPLETE));

    let legacy = resources.list_result(&ProtocolVersion::V_2025_11_25);
    assert_eq!(legacy.ttl_ms, None);
    assert_eq!(legacy.cache_scope, None);
    assert_eq!(legacy.result_type, None);

    let legacy_read = resources
        .read_status(
            "build-helper://ops/status",
            &status,
            &ProtocolVersion::V_2025_11_25,
        )
        .expect("legacy status projection");
    assert_eq!(legacy_read.ttl_ms, None);
    assert_eq!(legacy_read.cache_scope, None);
    assert_eq!(legacy_read.result_type, None);
}

#[test]
fn uri_mismatch_and_unbounded_status_values_fail_closed() {
    let resources = resources();
    let status = OperationalStatus {
        state: OperationalState::Ready,
        component: "server/path".to_owned(),
        server_version: "1.2.3".to_owned(),
    };
    assert!(matches!(
        resources.read_status(
            "build-helper://ops/attestation",
            &status,
            &ProtocolVersion::V_2026_07_28,
        ),
        Err(OperationalResourceError::UnknownResource)
    ));
    assert!(matches!(
        resources.read_status(
            "build-helper://ops/status",
            &status,
            &ProtocolVersion::V_2026_07_28,
        ),
        Err(OperationalResourceError::InvalidInput)
    ));
}

#[test]
fn attestation_projection_rejects_non_v2_and_drops_private_fields() {
    let resources = resources();
    let mut raw = json!({
        "status": "degraded",
        "schema_version": 2,
        "component": "mcp-server",
        "timestamp": "caller timestamp",
        "request_id": "private-request-id",
        "attestation": {
            "identity": {
                "server_version": "1.2.3",
                "contract_version": "private-contract",
                "build_identity": "revision-secret",
                "source_fingerprint": "fingerprint-secret"
            },
            "source": {"vcs": "git", "revision": "revision-secret", "reference": "private-branch", "dirty": true},
            "build_metadata": {"profile": "release", "target": "private-target", "rustc_version": "private-rustc", "source_date_epoch": null},
            "runtime": {"pid": 123, "executable_path": "/private/path", "binary_size_bytes": 7, "binary_modified_unix_ms": 8}
        },
        "unavailable": [{"field":"attestation.runtime.pid", "code":"provenance.unavailable.process_id", "reason":"private detail"}, {"field":"custom.field", "code":"custom.code", "reason":"echo me not"}],
        "extensions": {"private": {"value":"must not be returned"}}
    });
    let envelope: mcp_toolkit_provenance::AttestationEnvelope =
        serde_json::from_value(raw.clone()).expect("valid typed envelope");
    let result = resources
        .read_attestation(
            "build-helper://ops/attestation",
            &envelope,
            &ProtocolVersion::V_2026_07_28,
        )
        .expect("valid v2 envelope");
    let text = match &result.contents[0] {
        ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("attestation resource is JSON text"),
    };
    assert!(!text.contains("revision-secret"));
    assert!(!text.contains("fingerprint-secret"));
    assert!(!text.contains("private-branch"));
    assert!(!text.contains("private-request-id"));
    assert!(!text.contains("private detail"));
    assert!(!text.contains("must not be returned"));
    let value: Value = serde_json::from_str(text).expect("valid JSON attestation");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(
        value["unavailable"],
        json!([{"field":"process_id", "code":"process"}])
    );

    raw["schema_version"] = json!(1);
    let invalid: mcp_toolkit_provenance::AttestationEnvelope =
        serde_json::from_value(raw.clone()).expect("schema version is a public u32 field");
    assert!(matches!(
        resources.read_attestation(
            "build-helper://ops/attestation",
            &invalid,
            &ProtocolVersion::V_2026_07_28,
        ),
        Err(OperationalResourceError::InvalidInput)
    ));

    raw["schema_version"] = json!(u32::MAX);
    let invalid: mcp_toolkit_provenance::AttestationEnvelope =
        serde_json::from_value(raw).expect("maximum schema version is representable");
    assert!(matches!(
        resources.read_attestation(
            "build-helper://ops/attestation",
            &invalid,
            &ProtocolVersion::V_2026_07_28,
        ),
        Err(OperationalResourceError::InvalidInput)
    ));
}

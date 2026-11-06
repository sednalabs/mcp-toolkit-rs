//! Verify optional upstream capabilities through the toolkit re-export.
//!
//! Capability serialization is not application implementation or client acceptance.

use mcp_toolkit_core::rmcp::model::{JsonObject, ServerCapabilities};
use serde_json::json;

#[test]
fn optional_extensions_are_not_advertised_by_default() {
    let capabilities = ServerCapabilities::builder().enable_tools().build();
    assert!(capabilities.events.is_none());
    assert!(!capabilities.supports_skills());
    assert_eq!(
        serde_json::to_value(capabilities).unwrap(),
        json!({ "tools": {} })
    );
}

#[test]
fn skills_and_events_compose_without_enabling_subscriptions() {
    let mut capabilities = ServerCapabilities::builder()
        .enable_tools()
        .enable_resources()
        .enable_skills()
        .build();
    assert!(capabilities.events.is_none());
    assert!(capabilities.supports_skills());
    capabilities.events = Some(JsonObject::new());
    let wire = serde_json::to_value(&capabilities).unwrap();
    assert_eq!(wire["events"], json!({}));
    assert!(wire["resources"].get("subscribe").is_none());
    assert!(wire.get("experimental").is_none());
    let decoded: ServerCapabilities = serde_json::from_value(wire).unwrap();
    assert!(decoded.supports_skills());
    assert_eq!(decoded, capabilities);
}

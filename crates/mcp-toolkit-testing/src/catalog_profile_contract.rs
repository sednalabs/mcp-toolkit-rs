//! # Catalog Profile Contract Assertions
//!
//! Test helpers for validating native MCP catalog profile artifacts emitted by
//! `mcp-toolkit-core::tool_inventory`.
//!
//! ## Rationale
//! Large MCP servers should expose coherent native tool profiles without adding
//! workaround discovery tools to the production surface. A profile contract lets
//! probes and service tests compare the advertised catalog against required
//! tools and groups before a host sees the server.
//!
//! ## Security Boundaries
//! * Checks descriptor/catalog metadata only; it does not authorize tool calls.
//! * Treats payloads as public test artifacts and reports only tool/profile
//!   names already present in those artifacts.

use mcp_toolkit_core::tool_inventory::ToolCatalogContract;
use serde_json::Value;
use std::collections::HashSet;

/// Asserts that a native catalog profile contract is satisfied.
///
/// # Panics
/// Panics when required tools or groups are missing, or when the serialized
/// contract does not satisfy [`assert_tool_catalog_profile_contract_value`].
pub fn assert_tool_catalog_profile_contract(contract: &ToolCatalogContract) {
    assert!(
        contract.is_satisfied(),
        "catalog profile {:?} has missing required tools {:?} or groups {:?}",
        contract.profile_key,
        contract.missing_required_tools,
        contract.missing_required_groups
    );
    assert_tool_catalog_profile_contract_value(&contract.to_value());
}

/// Asserts the stable JSON shape for a native catalog profile contract.
///
/// # Panics
/// Panics when required fields are missing, tool counts drift from the tool
/// list, tool names are duplicated, or the contract reports unsatisfied
/// requirements.
pub fn assert_tool_catalog_profile_contract_value(payload: &Value) {
    assert_eq!(
        payload.get("schema").and_then(Value::as_str),
        Some("mcp_tool_catalog_profile_contract"),
        "catalog profile contract must advertise its schema"
    );
    assert_eq!(
        payload.get("version").and_then(Value::as_u64),
        Some(1),
        "catalog profile contract must advertise version 1"
    );
    let profile = required_object(payload, "profile");
    required_non_empty_string_from(profile, "key");
    required_non_empty_string_from(profile, "title");
    required_non_empty_string_from(profile, "description");
    let operation = required_non_empty_string(payload, "operation");
    assert!(
        matches!(operation, "list" | "call"),
        "catalog profile contract operation must be list or call, got {operation:?}"
    );

    let tool_names = required_string_array(payload, "tool_names");
    let tool_count = payload
        .get("tool_count")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("catalog profile contract must include numeric tool_count"));
    assert_eq!(
        tool_count as usize,
        tool_names.len(),
        "catalog profile contract tool_count must match tool_names length"
    );
    let unique_tools = tool_names.iter().collect::<HashSet<_>>();
    assert_eq!(
        unique_tools.len(),
        tool_names.len(),
        "catalog profile contract tool_names must not contain duplicates"
    );

    let requirements = required_object(payload, "requirements");
    assert_eq!(
        requirements.get("satisfied").and_then(Value::as_bool),
        Some(true),
        "catalog profile requirements must be satisfied"
    );
    assert!(
        required_string_array_from(requirements, "missing_required_tools").is_empty(),
        "catalog profile contract must not report missing required tools"
    );
    assert!(
        required_string_array_from(requirements, "missing_required_groups").is_empty(),
        "catalog profile contract must not report missing required groups"
    );

    required_object(payload, "policy");
}

/// Asserts that a contract contains all required tool names.
///
/// # Panics
/// Panics when the contract shape is invalid or any required tool is absent.
pub fn assert_tool_catalog_profile_contains_tools(payload: &Value, required_tools: &[&str]) {
    assert_tool_catalog_profile_contract_value(payload);
    let tool_names = required_string_array(payload, "tool_names");
    let missing = required_tools
        .iter()
        .copied()
        .filter(|required| !tool_names.iter().any(|name| name == required))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "catalog profile contract is missing required tools {missing:?}; got {tool_names:?}"
    );
}

fn required_object<'a>(payload: &'a Value, field: &str) -> &'a serde_json::Map<String, Value> {
    payload
        .get(field)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("catalog profile contract must include object field {field:?}"))
}

fn required_non_empty_string<'a>(payload: &'a Value, field: &str) -> &'a str {
    required_non_empty_string_from(
        payload
            .as_object()
            .unwrap_or_else(|| panic!("catalog profile contract payload must be an object")),
        field,
    )
}

fn required_non_empty_string_from<'a>(
    payload: &'a serde_json::Map<String, Value>,
    field: &str,
) -> &'a str {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty() && value.trim() == *value)
        .unwrap_or_else(|| {
            panic!("catalog profile contract must include non-empty trimmed string field {field:?}")
        })
}

fn required_string_array(payload: &Value, field: &str) -> Vec<String> {
    required_string_array_from(
        payload
            .as_object()
            .unwrap_or_else(|| panic!("catalog profile contract payload must be an object")),
        field,
    )
}

fn required_string_array_from(
    payload: &serde_json::Map<String, Value>,
    field: &str,
) -> Vec<String> {
    payload
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("catalog profile contract must include array field {field:?}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty() && value.trim() == *value)
                .unwrap_or_else(|| {
                    panic!(
                        "catalog profile contract field {field:?} must contain only non-empty trimmed strings"
                    )
                })
                .to_string()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        assert_tool_catalog_profile_contains_tools, assert_tool_catalog_profile_contract,
        assert_tool_catalog_profile_contract_value,
    };
    use mcp_toolkit_core::tool_inventory::{
        ToolCapability, ToolCatalogProfile, ToolInventory, ToolInventoryPolicy, ToolOperation,
    };
    use serde_json::json;

    #[test]
    fn accepts_satisfied_catalog_contract_value() {
        let payload = json!({
            "schema": "mcp_tool_catalog_profile_contract",
            "version": 1,
            "profile": {
                "key": "core",
                "title": "Core",
                "description": "Core read tools",
                "instructions": null,
            },
            "operation": "list",
            "tool_count": 2,
            "tool_names": ["items.read", "items.search"],
            "groups": ["items"],
            "requirements": {
                "required_tools": ["items.read"],
                "missing_required_tools": [],
                "required_groups": ["items"],
                "missing_required_groups": [],
                "satisfied": true,
            },
            "policy": {
                "allowed_groups": ["items"],
                "read_only_only": true,
                "include_unregistered": false,
                "enabled_feature_flags": [],
            },
        });

        assert_tool_catalog_profile_contract_value(&payload);
        assert_tool_catalog_profile_contains_tools(&payload, &["items.read"]);
    }

    #[test]
    fn accepts_core_contract_struct() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("items.read")
            .with_group("items")
            .with_read_only(true)])
        .expect("inventory");
        let profile = ToolCatalogProfile::new("core", "Core", "Core read tools")
            .expect("profile")
            .with_policy(ToolInventoryPolicy::strict_read_only().with_allowed_groups(["items"]))
            .with_required_tools(["items.read"])
            .expect("required tools")
            .with_required_groups(["items"])
            .expect("required groups");

        let contract = inventory.catalog_contract(&profile, ToolOperation::List);

        assert_tool_catalog_profile_contract(&contract);
    }
}

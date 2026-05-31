//! # Tool Schema Snapshots
//!
//! Deterministic serialization helpers for MCP tool surfaces.
//!
//! ## Ownership
//! This module owns the shared JSON envelope and canonical ordering used when
//! MCP servers print or snapshot their registered tool definitions.
//!
//! ## Non-ownership
//! This module does not register tools, invoke tools, or assert against files.
//! Test assertion policy remains in `mcp-toolkit-testing`.
//!
//! ## Policy & Guarantees
//! * **Stable Output**: Sorts tools by name and canonicalizes object keys.
//! * **Small Surface**: Accepts any serde-serializable tool definition without
//!   requiring callers to expose a concrete tool type.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying the exact tool set they intend to expose.
//! * Writing or comparing the rendered JSON when persistence is needed.

use serde::Serialize;
use serde_json::{Map, Value};

/// Schema identifier for deterministic MCP tool schema snapshots.
pub const TOOL_SCHEMA_SNAPSHOT_SCHEMA: &str = "mcp_tool_schema_snapshot";
/// Current schema version for deterministic MCP tool schema snapshots.
pub const TOOL_SCHEMA_SNAPSHOT_VERSION: u64 = 1;

/// Extracts deterministic tool names from a list of serialized tool definitions.
///
/// # Errors
/// Returns a serialization error if any tool definition cannot be converted to
/// JSON.
pub fn tool_names<T>(tools: &[T]) -> Result<Vec<String>, serde_json::Error>
where
    T: Serialize,
{
    let mut names = Vec::with_capacity(tools.len());
    for tool in tools {
        let value = serde_json::to_value(tool)?;
        if let Some(name) = value
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(Value::as_str)
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Generates a deterministic JSON snapshot from a list of tool definitions.
///
/// # Errors
/// Returns a serialization error if any tool definition cannot be converted to
/// JSON.
pub fn tool_schema_snapshot_value<T>(tools: &[T]) -> Result<Value, serde_json::Error>
where
    T: Serialize,
{
    let mut serialized = Vec::with_capacity(tools.len());
    for tool in tools {
        serialized.push(serde_json::to_value(tool)?);
    }
    serialized.sort_by_key(tool_sort_key);
    Ok(canonicalize_json(Value::Object(Map::from_iter([
        (
            "schema".to_string(),
            Value::String(TOOL_SCHEMA_SNAPSHOT_SCHEMA.to_string()),
        ),
        (
            "version".to_string(),
            Value::Number(TOOL_SCHEMA_SNAPSHOT_VERSION.into()),
        ),
        ("tools".to_string(), Value::Array(serialized)),
    ]))))
}

fn tool_sort_key(value: &Value) -> String {
    value
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut ordered = Map::new();
            for (key, value) in entries {
                ordered.insert(key, canonicalize_json(value));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{tool_names, tool_schema_snapshot_value};
    use serde_json::json;

    #[test]
    fn snapshot_value_is_sorted_by_tool_name() {
        let tools = vec![
            json!({"description":"second","name":"zeta","inputSchema":{"type":"object"}}),
            json!({"name":"alpha","description":"first","inputSchema":{"type":"object"}}),
        ];
        let snapshot = tool_schema_snapshot_value(&tools).expect("serialize snapshot");
        let names: Vec<&str> = snapshot["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn snapshot_value_canonicalizes_nested_object_keys() {
        let tools = vec![json!({
            "name": "alpha",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "z": {"type": "string", "description": "last"},
                    "a": {"description": "first", "type": "string"}
                }
            }
        })];
        let snapshot = tool_schema_snapshot_value(&tools).expect("serialize snapshot");
        assert_eq!(
            snapshot["tools"][0]["inputSchema"]["properties"],
            json!({
                "a": {"description": "first", "type": "string"},
                "z": {"description": "last", "type": "string"}
            })
        );
    }

    #[test]
    fn tool_names_are_sorted_and_skip_missing_names() {
        let tools = vec![
            json!({"name":"zeta"}),
            json!({"description":"missing name"}),
            json!({"name":"alpha"}),
        ];
        let names = tool_names(&tools).expect("extract names");
        assert_eq!(names, vec!["alpha", "zeta"]);
    }
}

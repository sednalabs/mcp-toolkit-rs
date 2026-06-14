//! # MCP Toolkit Testing
//!
//! Reusable test doubles, mocks, and integration test harnesses for MCP servers.
//!
//! ## Ownership
//! This module owns the shared test fixtures, snapshot assertion utilities, and
//! environment-driven test helpers.
//!
//! ## Non-ownership
//! This module does not provide core application logic; it is strictly intended
//! for test-suite consumption.
//!
//! ## Policy & Guarantees
//! * **Snapshot Parity**: Provides deterministic JSON snapshot generation and
//!   validation to ensure API-schema consistency.
//! * **Dev Isolation**: Fixtures are intended for integration testing in non-production
//!   build environments.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Integrating these helpers into `#[cfg(test)]` modules only.
//! * Managing the lifecycle of local snapshot files on disk.
//!
//! ## References
//! * `docs/design/testing-strategy.md`

use serde::Serialize;
use serde_json::{Map, Value};
use std::path::Path;

pub mod auth_surface_contract;
pub mod openai_apps_contract;
pub mod stdio_contract;
pub use mcp_toolkit_core::tool_schema::tool_schema_snapshot_value;

/// Environment variable for opting into tool schema snapshot updates.
pub const UPDATE_TOOL_SNAPSHOTS_ENV: &str = "MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS";
/// Environment variable for opting into JSON contract snapshot updates.
pub const UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV: &str = "MCP_TOOLKIT_UPDATE_JSON_CONTRACT_SNAPSHOTS";

/// Configuration for snapshot assertion behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotAssertionOptions {
    /// If true, rewrites the snapshot file with the current canonical value.
    pub update: bool,
}

impl SnapshotAssertionOptions {
    /// Resolves snapshot behavior from process environment.
    pub fn from_env() -> Self {
        Self::from_env_var(UPDATE_TOOL_SNAPSHOTS_ENV)
    }

    /// Resolves snapshot behavior from a specific process environment variable.
    pub fn from_env_var(env_var: &str) -> Self {
        Self {
            update: snapshot_update_enabled(env_var),
        }
    }
}

impl Default for SnapshotAssertionOptions {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Asserts that tool schema output matches a committed snapshot file.
///
/// # Panics
/// Panics if serialization fails, I/O fails, or drift is detected in non-update mode.
pub fn assert_tool_schema_snapshot<T>(snapshot_path: impl AsRef<Path>, tools: &[T])
where
    T: Serialize,
{
    let snapshot_path = snapshot_path.as_ref();
    let options = SnapshotAssertionOptions::from_env();
    assert_tool_schema_snapshot_with_options(snapshot_path, tools, options);
}

/// Generates a deterministic JSON contract snapshot from an arbitrary value.
pub fn json_contract_snapshot_value<T>(
    schema: &str,
    version: u64,
    payload: &T,
) -> Result<Value, serde_json::Error>
where
    T: Serialize,
{
    let payload = canonicalize_json(serde_json::to_value(payload)?);
    Ok(canonicalize_json(Value::Object(Map::from_iter([
        ("schema".to_string(), Value::String(schema.to_string())),
        ("version".to_string(), Value::Number(version.into())),
        ("payload".to_string(), payload),
    ]))))
}

/// Asserts that a JSON contract payload matches a committed snapshot file.
///
/// # Panics
/// Panics if serialization fails, I/O fails, or drift is detected in non-update mode.
pub fn assert_json_contract_snapshot<T>(
    snapshot_path: impl AsRef<Path>,
    schema: &str,
    version: u64,
    payload: &T,
) where
    T: Serialize,
{
    let snapshot_path = snapshot_path.as_ref();
    let options = SnapshotAssertionOptions::from_env_var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV);
    assert_json_contract_snapshot_with_options(snapshot_path, schema, version, payload, options);
}

fn assert_tool_schema_snapshot_with_options<T>(
    snapshot_path: &Path,
    tools: &[T],
    options: SnapshotAssertionOptions,
) where
    T: Serialize,
{
    let actual = tool_schema_snapshot_value(tools)
        .unwrap_or_else(|err| panic!("failed to serialize tool schema: {err}"));
    assert_canonical_snapshot(
        snapshot_path,
        &actual,
        options,
        UPDATE_TOOL_SNAPSHOTS_ENV,
        "tool schema snapshot",
    );
}

/// Asserts a JSON contract snapshot with explicit behavior.
///
/// # Panics
/// Panics if serialization fails, I/O fails, or drift is detected in non-update mode.
pub fn assert_json_contract_snapshot_with_options<T>(
    snapshot_path: &Path,
    schema: &str,
    version: u64,
    payload: &T,
    options: SnapshotAssertionOptions,
) where
    T: Serialize,
{
    let actual = json_contract_snapshot_value(schema, version, payload)
        .unwrap_or_else(|err| panic!("failed to serialize JSON contract: {err}"));
    assert_canonical_snapshot(
        snapshot_path,
        &actual,
        options,
        UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV,
        "JSON contract snapshot",
    );
}

fn assert_canonical_snapshot(
    snapshot_path: &Path,
    actual: &Value,
    options: SnapshotAssertionOptions,
    update_env: &str,
    snapshot_label: &str,
) {
    if options.update {
        write_snapshot(snapshot_path, actual).unwrap_or_else(|err| {
            panic!(
                "failed to write updated {snapshot_label} at {}: {err}",
                snapshot_path.display()
            )
        });
        return;
    }

    let expected_raw = std::fs::read_to_string(snapshot_path).unwrap_or_else(|err| {
        panic!(
            "missing {snapshot_label} at {} ({err}). Re-run with {update_env}=1 to create.",
            snapshot_path.display()
        )
    });
    let expected = serde_json::from_str::<Value>(&expected_raw).unwrap_or_else(|err| {
        panic!(
            "invalid JSON in {snapshot_label} {}: {err}",
            snapshot_path.display()
        )
    });
    let expected = canonicalize_json(expected);

    if expected != *actual {
        let expected_pretty = serde_json::to_string_pretty(&expected)
            .unwrap_or_else(|err| panic!("failed to format snapshot: {err}"));
        let actual_pretty = serde_json::to_string_pretty(actual)
            .unwrap_or_else(|err| panic!("failed to format actual: {err}"));
        panic!(
            "{snapshot_label} drift at {}.\n\
             Re-run with {update_env}=1 to update.\n\n\
             Expected:\n{}\n\n\
             Actual:\n{}",
            snapshot_path.display(),
            expected_pretty,
            actual_pretty
        );
    }
}

fn write_snapshot(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    std::fs::write(path, format!("{rendered}\n"))
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

fn snapshot_update_enabled(env_var: &str) -> bool {
    std::env::var(env_var)
        .ok()
        .map(|raw| parse_bool(&raw))
        .unwrap_or(false)
}

fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        assert_json_contract_snapshot, assert_json_contract_snapshot_with_options,
        assert_tool_schema_snapshot_with_options, json_contract_snapshot_value,
        tool_schema_snapshot_value, SnapshotAssertionOptions, UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV,
    };
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

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
    fn update_mode_writes_snapshot_file() {
        let tools = vec![json!({"name":"alpha","description":"desc"})];
        let path = unique_test_path("update_mode_writes_snapshot_file");
        assert_tool_schema_snapshot_with_options(
            &path,
            &tools,
            SnapshotAssertionOptions { update: true },
        );
        let written = std::fs::read_to_string(&path).expect("snapshot written");
        assert!(written.contains("\"name\": \"alpha\""));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strict_mode_panics_on_drift() {
        let path = unique_test_path("strict_mode_panics_on_drift");
        std::fs::write(
            &path,
            "{\n  \"schema\": \"mcp_tool_schema_snapshot\",\n  \"version\": 1,\n  \"tools\": []\n}\n",
        )
        .expect("seed snapshot");
        let tools = vec![json!({"name":"alpha","description":"desc"})];
        let result = std::panic::catch_unwind(|| {
            assert_tool_schema_snapshot_with_options(
                &path,
                &tools,
                SnapshotAssertionOptions { update: false },
            );
        });
        assert!(result.is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn json_contract_snapshot_value_canonicalizes_payload_keys() {
        let snapshot = json_contract_snapshot_value(
            "mcp_resource_snapshot",
            1,
            &json!({
                "z": {"b": 2, "a": 1},
                "a": ["x", {"d": 4, "c": 3}]
            }),
        )
        .expect("serialize snapshot");
        assert_eq!(snapshot["schema"], "mcp_resource_snapshot");
        assert_eq!(snapshot["version"], 1);
        assert_eq!(
            snapshot["payload"],
            json!({
                "a": ["x", {"c": 3, "d": 4}],
                "z": {"a": 1, "b": 2}
            })
        );
    }

    #[test]
    fn json_update_mode_writes_snapshot_file() {
        let path = unique_test_path("json_update_mode_writes_snapshot_file");
        assert_json_contract_snapshot_with_options(
            &path,
            "mcp_resource_snapshot",
            1,
            &json!({"kind": "about", "value": {"name": "alpha"}}),
            SnapshotAssertionOptions { update: true },
        );
        let written = std::fs::read_to_string(&path).expect("snapshot written");
        assert!(written.contains("\"schema\": \"mcp_resource_snapshot\""));
        assert!(written.contains("\"kind\": \"about\""));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn json_strict_mode_panics_on_drift() {
        let path = unique_test_path("json_strict_mode_panics_on_drift");
        std::fs::write(
            &path,
            "{\n  \"schema\": \"mcp_resource_snapshot\",\n  \"version\": 1,\n  \"payload\": {\"kind\": \"about\"}\n}\n",
        )
        .expect("seed snapshot");
        let result = std::panic::catch_unwind(|| {
            assert_json_contract_snapshot_with_options(
                &path,
                "mcp_resource_snapshot",
                1,
                &json!({"kind": "help"}),
                SnapshotAssertionOptions { update: false },
            );
        });
        assert!(result.is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn json_public_wrapper_accepts_matching_snapshot() {
        let _guard = env_lock().lock().expect("env lock");
        let path = unique_test_path("json_public_wrapper_accepts_matching_snapshot");
        std::fs::write(
            &path,
            "{\n  \"schema\": \"mcp_resource_snapshot\",\n  \"version\": 1,\n  \"payload\": {\"kind\": \"about\", \"value\": {\"a\": 1, \"b\": 2}}\n}\n",
        )
        .expect("seed snapshot");
        let previous = std::env::var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV).ok();
        remove_test_env_var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV);
        assert_json_contract_snapshot(
            &path,
            "mcp_resource_snapshot",
            1,
            &json!({"kind": "about", "value": {"b": 2, "a": 1}}),
        );
        restore_env_var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV, previous);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn json_missing_snapshot_message_mentions_update_env() {
        let _guard = env_lock().lock().expect("env lock");
        let path = unique_test_path("json_missing_snapshot_message_mentions_update_env");
        let _ = std::fs::remove_file(&path);
        let previous = std::env::var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV).ok();
        remove_test_env_var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV);
        let result = std::panic::catch_unwind(|| {
            assert_json_contract_snapshot(
                &path,
                "mcp_resource_snapshot",
                1,
                &json!({"kind": "about"}),
            );
        });
        restore_env_var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV, previous);
        let panic =
            panic_message(result.expect_err("strict mode should panic on missing snapshot"));
        assert!(panic.contains(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV));
    }

    #[test]
    fn json_public_wrapper_update_mode_writes_snapshot_file() {
        let _guard = env_lock().lock().expect("env lock");
        let path = unique_test_path("json_public_wrapper_update_mode_writes_snapshot_file");
        let _ = std::fs::remove_file(&path);
        let previous = std::env::var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV).ok();
        set_test_env_var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV, "1");
        assert_json_contract_snapshot(
            &path,
            "mcp_resource_snapshot",
            1,
            &json!({"kind": "about", "value": {"name": "alpha"}}),
        );
        restore_env_var(UPDATE_JSON_CONTRACT_SNAPSHOTS_ENV, previous);
        let written = std::fs::read_to_string(&path).expect("snapshot written");
        assert!(written.contains("\"schema\": \"mcp_resource_snapshot\""));
        assert!(written.contains("\"kind\": \"about\""));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn json_strict_mode_panics_on_invalid_json_snapshot() {
        let path = unique_test_path("json_strict_mode_panics_on_invalid_json_snapshot");
        std::fs::write(&path, "{ this is not json }\n").expect("seed invalid snapshot");
        let result = std::panic::catch_unwind(|| {
            assert_json_contract_snapshot_with_options(
                &path,
                "mcp_resource_snapshot",
                1,
                &json!({"kind": "about"}),
                SnapshotAssertionOptions { update: false },
            );
        });
        let panic = panic_message(result.expect_err("strict mode should reject invalid JSON"));
        assert!(panic.contains("invalid JSON in JSON contract snapshot"));
        let _ = std::fs::remove_file(path);
    }

    fn unique_test_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("mcp_toolkit_testing_{name}_{nonce}.json"))
    }

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = payload.downcast_ref::<String>() {
            return message.clone();
        }
        if let Some(message) = payload.downcast_ref::<&'static str>() {
            return (*message).to_string();
        }
        "<non-string panic payload>".to_string()
    }

    fn restore_env_var(key: &str, value: Option<String>) {
        if let Some(value) = value {
            set_test_env_var(key, value);
        } else {
            remove_test_env_var(key);
        }
    }

    fn set_test_env_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
        // SAFETY: callers hold `env_lock()` while mutating and reading the
        // snapshot update environment variable in these tests.
        unsafe { std::env::set_var(key, value) };
    }

    fn remove_test_env_var(key: &str) {
        // SAFETY: callers hold `env_lock()` while mutating and reading the
        // snapshot update environment variable in these tests.
        unsafe { std::env::remove_var(key) };
    }
}

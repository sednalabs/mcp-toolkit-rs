use mcp_toolkit_testing::stdio_contract::{
    assert_stdio_tool_response_excludes_substrings, assert_stdio_tools_list,
};
use serde_json::json;
use std::process::Command;

#[test]
fn stdio_initializes_and_lists_tools() {
    assert_stdio_tools_list(
        env!("CARGO_BIN_EXE_curated-stdio-intent-server"),
        &["brief_target", "detail_by_tracking_id"],
    );
}

#[test]
fn stdio_tool_call_does_not_echo_secret_material() {
    assert_stdio_tool_response_excludes_substrings(
        env!("CARGO_BIN_EXE_curated-stdio-intent-server"),
        "brief_target",
        json!({"target": "probe"}),
        &[
            "development-only-secret",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "BEGIN PRIVATE KEY",
        ],
    );
}

#[test]
fn cli_print_tools_lists_active_profile_tools() {
    let output = Command::new(env!("CARGO_BIN_EXE_curated-stdio-intent-server"))
        .arg("--print-tools")
        .env_remove("EXAMPLE_MCP_TOOL_PROFILE")
        .output()
        .expect("run --print-tools");

    assert!(
        output.status.success(),
        "--print-tools failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "brief_target\ndetail_by_tracking_id\n"
    );
}

#[test]
fn cli_print_tool_schema_uses_snapshot_envelope() {
    let output = Command::new(env!("CARGO_BIN_EXE_curated-stdio-intent-server"))
        .arg("--print-tool-schema")
        .env_remove("EXAMPLE_MCP_TOOL_PROFILE")
        .output()
        .expect("run --print-tool-schema");

    assert!(
        output.status.success(),
        "--print-tool-schema failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("schema snapshot json");
    assert_eq!(snapshot["schema"], "mcp_tool_schema_snapshot");
    assert_eq!(snapshot["version"], 1);
    assert_eq!(snapshot["tools"][0]["name"], "brief_target");
    assert_eq!(snapshot["tools"][1]["name"], "detail_by_tracking_id");
}

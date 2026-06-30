use mcp_toolkit_testing::stdio_contract::{
    assert_stdio_tool_response_excludes_substrings, assert_stdio_tools_list,
};
use serde_json::json;

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

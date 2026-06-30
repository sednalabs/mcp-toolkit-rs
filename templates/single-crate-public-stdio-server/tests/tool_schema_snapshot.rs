use mcp_toolkit_core::tool_inventory::READ_ONLY_PROFILE_KEY;
use mcp_toolkit_testing::assert_tool_schema_snapshot;
use single_crate_public_stdio_server::{IntentServer, IntentServerConfig};
use std::path::PathBuf;

#[test]
fn tool_schema_snapshot_contract_is_stable() {
    let server = IntentServer::new(IntentServerConfig::default()).expect("server");
    let snapshot_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/tool_schema_snapshot.v1.json");
    let tools = server
        .tool_schema_snapshot_for_profile(READ_ONLY_PROFILE_KEY)
        .expect("read-only profile");
    assert_tool_schema_snapshot(snapshot_path, &tools);
}

use curated_stdio_intent_server::{IntentServer, IntentServerConfig};
use mcp_toolkit_testing::assert_tool_schema_snapshot;
use std::path::PathBuf;

#[test]
fn tool_schema_snapshot_contract_is_stable() {
    let server = IntentServer::new(IntentServerConfig::default()).expect("server");
    let snapshot_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/tool_schema_snapshot.v1.json");
    assert_tool_schema_snapshot(snapshot_path, &server.tool_schema_snapshot());
}

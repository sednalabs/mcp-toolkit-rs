use mcp_toolkit_testing::stdio_contract::assert_stdio_tools_list;

#[test]
fn stdio_initializes_and_lists_tools() {
    assert_stdio_tools_list(
        env!("CARGO_BIN_EXE_curated-stdio-intent-server"),
        &["brief_target", "detail_by_tracking_id"],
    );
}

use curated_stdio_intent_server::{IntentServer, IntentServerConfig};
use mcp_toolkit_core::tool_inventory::{
    ToolCatalogProfile, ToolOperation, OPERATOR_PROFILE_KEY, READ_ONLY_PROFILE_KEY,
};
use mcp_toolkit_testing::catalog_profile_contract::{
    assert_tool_catalog_profile_contains_tools, assert_tool_catalog_profile_contract,
};

#[test]
fn read_only_profile_contract_contains_generated_tools() {
    assert_profile_contract_contains_tools(
        READ_ONLY_PROFILE_KEY,
        &["brief_target", "detail_by_tracking_id"],
    );
}

#[test]
fn operator_profile_contract_is_available_for_future_operator_tools() {
    assert_profile_contract_contains_tools(
        OPERATOR_PROFILE_KEY,
        &["brief_target", "detail_by_tracking_id"],
    );
}

fn assert_profile_contract_contains_tools(profile_key: &str, expected_tools: &[&str]) {
    let server = IntentServer::new(IntentServerConfig::default()).expect("server");
    let profile = server
        .catalog()
        .require_profile(profile_key)
        .expect("profile");
    let contract = profile_contract(&server, profile);

    assert_tool_catalog_profile_contract(&contract);
    assert_tool_catalog_profile_contains_tools(&contract.to_value(), expected_tools);
}

fn profile_contract(
    server: &IntentServer,
    profile: &ToolCatalogProfile,
) -> mcp_toolkit_core::tool_inventory::ToolCatalogContract {
    server
        .inventory()
        .catalog_contract(profile, ToolOperation::List)
}

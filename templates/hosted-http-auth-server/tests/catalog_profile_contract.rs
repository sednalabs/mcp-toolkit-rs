use hosted_http_auth_server::HostedHttpServer;
use mcp_toolkit_core::tool_inventory::{
    ToolCatalogProfile, ToolOperation, OPERATOR_PROFILE_KEY, READ_ONLY_PROFILE_KEY,
};
use mcp_toolkit_testing::catalog_profile_contract::{
    assert_tool_catalog_profile_contains_tools, assert_tool_catalog_profile_contract,
};

#[test]
fn read_only_profile_contract_contains_generated_tools() {
    assert_profile_contract_contains_tools(READ_ONLY_PROFILE_KEY, &["read_status"]);
}

#[test]
fn operator_profile_contract_is_available_for_future_operator_tools() {
    assert_profile_contract_contains_tools(OPERATOR_PROFILE_KEY, &["read_status"]);
}

fn assert_profile_contract_contains_tools(profile_key: &str, expected_tools: &[&str]) {
    let server = HostedHttpServer::new().expect("server");
    let profile = server
        .catalog()
        .require_profile(profile_key)
        .expect("profile");
    let contract = profile_contract(&server, profile);

    assert_tool_catalog_profile_contract(&contract);
    assert_tool_catalog_profile_contains_tools(&contract.to_value(), expected_tools);
}

fn profile_contract(
    server: &HostedHttpServer,
    profile: &ToolCatalogProfile,
) -> mcp_toolkit_core::tool_inventory::ToolCatalogContract {
    server
        .inventory()
        .catalog_contract(profile, ToolOperation::List)
}

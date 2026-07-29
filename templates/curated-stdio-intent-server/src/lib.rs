use mcp_toolkit::rmcp::{
    self,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResult, ContentBlock, ListToolsResult, ServerCapabilities,
        ServerInfo, Tool,
    },
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router, RoleServer, ServerHandler,
};
use mcp_toolkit::server::tools::list_tools_result;
use mcp_toolkit_core::guarded_action::GuardedActionPosture;
use mcp_toolkit_core::tool_inventory::{
    ToolCatalog, ToolCatalogEntry, ToolCatalogProfile, ToolDiscoveryMetadata, ToolInventory,
    ToolInventoryDecision, ToolInventoryError, ToolOperation, READ_ONLY_PROFILE_KEY,
};

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct BriefRequest {
    pub target: String,
}

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct DetailRequest {
    pub tracking_id: String,
}

#[derive(Debug, Clone)]
pub struct IntentServerConfig {
    pub service_name: String,
    pub tool_profile: String,
}

impl IntentServerConfig {
    pub fn from_env() -> Self {
        Self {
            service_name: std::env::var("EXAMPLE_MCP_SERVICE_NAME")
                .unwrap_or_else(|_| "curated-stdio-intent-server".to_string()),
            tool_profile: std::env::var("EXAMPLE_MCP_TOOL_PROFILE")
                .unwrap_or_else(|_| READ_ONLY_PROFILE_KEY.to_string()),
        }
    }
}

impl Default for IntentServerConfig {
    fn default() -> Self {
        Self {
            service_name: "curated-stdio-intent-server".to_string(),
            tool_profile: READ_ONLY_PROFILE_KEY.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntentServer {
    config: IntentServerConfig,
    tool_router: ToolRouter<Self>,
    catalog: ToolCatalog,
    inventory: ToolInventory,
}

impl IntentServer {
    pub fn new(config: IntentServerConfig) -> Result<Self, ToolInventoryError> {
        let catalog = ToolCatalog::from_entries([
            ToolCatalogEntry::new("brief_target")
                .with_group("read")
                .with_read_only(true)
                .with_risk_posture(GuardedActionPosture::read_only())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Summarize the current state for a named target.",
                    ["brief", "intent", "summary"],
                ))
                .with_handler("IntentServer::brief_target")?,
            ToolCatalogEntry::new("detail_by_tracking_id")
                .with_group("read")
                .with_read_only(true)
                .with_risk_posture(GuardedActionPosture::read_only())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Fetch a focused detail view by tracking id.",
                    ["detail", "tracking", "intent"],
                ))
                .with_handler("IntentServer::detail_by_tracking_id")?,
        ])?
        .with_standard_profiles(["read"])?;
        let inventory = catalog.inventory();
        Ok(Self {
            config,
            tool_router: Self::tool_router(),
            catalog,
            inventory,
        })
    }

    pub fn tool_schema_snapshot(&self) -> Vec<Tool> {
        self.tool_router.list_all()
    }

    pub fn tool_schema_snapshot_for_profile(
        &self,
        profile_key: &str,
    ) -> Result<Vec<Tool>, ToolInventoryError> {
        let profile = self.catalog.require_profile(profile_key)?;
        Ok(self.inventory.filter_tools_for_profile(
            self.tool_router.list_all(),
            ToolOperation::List,
            profile,
            |tool| tool.name.as_ref(),
        ))
    }

    pub fn catalog(&self) -> &ToolCatalog {
        &self.catalog
    }

    pub fn inventory(&self) -> &ToolInventory {
        &self.inventory
    }

    fn active_profile(&self) -> Result<&ToolCatalogProfile, ToolInventoryError> {
        self.catalog.require_profile(&self.config.tool_profile)
    }

    fn active_profile_decision(
        &self,
        tool_name: &str,
        operation: ToolOperation,
    ) -> Result<ToolInventoryDecision, ToolInventoryError> {
        Ok(self
            .inventory
            .decision_for_profile(tool_name, operation, self.active_profile()?))
    }
}

impl Default for IntentServer {
    fn default() -> Self {
        Self::new(IntentServerConfig::default()).expect("default inventory is valid")
    }
}

#[tool_router]
impl IntentServer {
    #[tool(description = "Summarize the current state for a named target.")]
    fn brief_target(&self, Parameters(request): Parameters<BriefRequest>) -> String {
        format!(
            "{} brief for {}: no backend configured in the starter template",
            self.config.service_name, request.target
        )
    }

    #[tool(description = "Fetch a focused detail view by tracking id.")]
    fn detail_by_tracking_id(&self, Parameters(request): Parameters<DetailRequest>) -> String {
        format!(
            "{} detail for {}: connect your domain backend here",
            self.config.service_name, request.tracking_id
        )
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for IntentServer {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let decision = self
            .active_profile_decision(request.name.as_ref(), ToolOperation::Call)
            .map_err(profile_error)?;
        if !decision.allowed() {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                decision.caller_message(),
            )]));
        }

        let context = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(context).await
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Curated stdio intent server starter template.")
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        let decision = self
            .active_profile_decision(name, ToolOperation::List)
            .ok()?;
        decision
            .allowed()
            .then(|| self.tool_router.get(name).cloned())
            .flatten()
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let tools = self
            .tool_schema_snapshot_for_profile(&self.config.tool_profile)
            .map_err(profile_error)?;
        list_tools_result(tools, request.as_ref())
    }
}

fn profile_error(error: ToolInventoryError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(error.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::{IntentServer, IntentServerConfig};
    use mcp_toolkit_core::tool_inventory::{OPERATOR_PROFILE_KEY, READ_ONLY_PROFILE_KEY};

    #[test]
    fn inventory_matches_exported_tool_names() {
        let server = IntentServer::new(IntentServerConfig::default()).expect("server");
        let tools = server.tool_schema_snapshot();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["brief_target", "detail_by_tracking_id"]);

        let active_tools = server
            .tool_schema_snapshot_for_profile(READ_ONLY_PROFILE_KEY)
            .expect("read-only profile");
        let active_names = active_tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(active_names, vec!["brief_target", "detail_by_tracking_id"]);
        assert!(server.catalog().operator_profile().is_some());
        assert!(server
            .tool_schema_snapshot_for_profile(OPERATOR_PROFILE_KEY)
            .is_ok());
        assert_eq!(
            server.catalog().to_value()["tools"][0]["name"],
            "brief_target"
        );
    }
}

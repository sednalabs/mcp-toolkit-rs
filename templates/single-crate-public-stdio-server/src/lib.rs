use mcp_toolkit::rmcp::{
    self,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo, Tool},
    schemars, tool, tool_handler, tool_router, ServerHandler,
};
use mcp_toolkit_core::guarded_action::GuardedActionPosture;
use mcp_toolkit_core::tool_inventory::{
    ToolCatalog, ToolCatalogEntry, ToolDiscoveryMetadata, ToolInventory, ToolInventoryError,
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
}

impl IntentServerConfig {
    pub fn from_env() -> Self {
        Self {
            service_name: std::env::var("EXAMPLE_MCP_SERVICE_NAME")
                .unwrap_or_else(|_| "single-crate-public-stdio-server".to_string()),
        }
    }
}

impl Default for IntentServerConfig {
    fn default() -> Self {
        Self {
            service_name: "single-crate-public-stdio-server".to_string(),
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
        ])?;
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

    pub fn catalog(&self) -> &ToolCatalog {
        &self.catalog
    }

    pub fn inventory(&self) -> &ToolInventory {
        &self.inventory
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
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Standalone public stdio MCP server starter template.")
    }
}

#[cfg(test)]
mod tests {
    use super::{IntentServer, IntentServerConfig};
    use mcp_toolkit_core::tool_inventory::{ToolInventoryPolicy, ToolOperation};

    #[test]
    fn inventory_matches_exported_tool_names() {
        let server = IntentServer::new(IntentServerConfig::default()).expect("server");
        let tools = server.tool_schema_snapshot();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["brief_target", "detail_by_tracking_id"]);

        let policy = ToolInventoryPolicy::default();
        assert!(server
            .inventory()
            .is_allowed("brief_target", ToolOperation::List, &policy));
        assert!(server.inventory().is_allowed(
            "detail_by_tracking_id",
            ToolOperation::Call,
            &policy
        ));
        assert_eq!(
            server.catalog().to_value()["tools"][0]["name"],
            "brief_target"
        );
    }
}

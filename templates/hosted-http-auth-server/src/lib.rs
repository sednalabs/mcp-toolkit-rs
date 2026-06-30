use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use mcp_toolkit::rmcp::{
    self,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo, Tool},
    schemars, tool, tool_handler, tool_router, ServerHandler,
};
use mcp_toolkit::server::{
    auth::{AuthSurfaceBuilder, IssuerEntry},
    http::{HttpBindSafety, LocalMcpHttpServerBuilder},
};
use mcp_toolkit_auth::surface::AuthorizationServerMetadataSource;
use mcp_toolkit_auth::{AuthConfig, AuthMode, Authenticator, AuthorizationServerMetadata};
use mcp_toolkit_core::guarded_action::GuardedActionPosture;
use mcp_toolkit_core::tool_inventory::{
    ToolCatalog, ToolCatalogEntry, ToolDiscoveryMetadata, ToolInventory, ToolInventoryError,
};

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct StatusRequest {
    pub component: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostedHttpConfig {
    pub bind_addr: SocketAddr,
    pub public_base_url: String,
    pub issuer: String,
    pub delegation_secret: String,
    pub allowed_hosts: Vec<String>,
    pub allow_non_loopback: bool,
}

impl HostedHttpConfig {
    pub fn local_dev() -> Self {
        Self {
            bind_addr: "127.0.0.1:9411".parse().expect("loopback bind addr"),
            public_base_url: "http://127.0.0.1:9411".to_string(),
            issuer: "http://issuer.example".to_string(),
            delegation_secret: "development-only-secret".to_string(),
            allowed_hosts: vec!["127.0.0.1".to_string(), "localhost".to_string()],
            allow_non_loopback: false,
        }
    }

    pub fn from_env() -> Result<Self, std::net::AddrParseError> {
        let default = Self::local_dev();
        let bind_addr = std::env::var("EXAMPLE_MCP_BIND_ADDR")
            .unwrap_or_else(|_| default.bind_addr.to_string())
            .parse()?;
        let public_base_url =
            std::env::var("EXAMPLE_MCP_PUBLIC_BASE_URL").unwrap_or(default.public_base_url);
        let issuer = std::env::var("EXAMPLE_MCP_ISSUER").unwrap_or(default.issuer);
        let delegation_secret =
            std::env::var("EXAMPLE_MCP_DELEGATION_SECRET").unwrap_or(default.delegation_secret);
        let allowed_hosts = std::env::var("EXAMPLE_MCP_ALLOWED_HOSTS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|host| !host.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|hosts| !hosts.is_empty())
            .unwrap_or(default.allowed_hosts);
        let allow_non_loopback = parse_bool_env("EXAMPLE_MCP_ALLOW_NON_LOOPBACK");
        Ok(Self {
            bind_addr,
            public_base_url,
            issuer,
            delegation_secret,
            allowed_hosts,
            allow_non_loopback,
        })
    }

    pub fn bind_safety(&self) -> HttpBindSafety {
        HttpBindSafety::new(self.allow_non_loopback, true)
    }

    pub fn resource_url(&self) -> String {
        format!("{}/mcp", self.public_base_url.trim_end_matches('/'))
    }
}

fn parse_bool_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct HostedHttpServer {
    tool_router: ToolRouter<Self>,
    catalog: ToolCatalog,
    inventory: ToolInventory,
}

impl HostedHttpServer {
    pub fn new() -> Result<Self, ToolInventoryError> {
        let catalog = ToolCatalog::from_entries([ToolCatalogEntry::new("read_status")
            .with_group("read")
            .with_read_only(true)
            .with_risk_posture(GuardedActionPosture::read_only())
            .with_discovery(ToolDiscoveryMetadata::new(
                "Read a status summary for one component.",
                ["status", "health", "read"],
            ))
            .with_handler("HostedHttpServer::read_status")?])?;
        let inventory = catalog.inventory()?;
        Ok(Self {
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

impl Default for HostedHttpServer {
    fn default() -> Self {
        Self::new().expect("default inventory is valid")
    }
}

#[tool_router]
impl HostedHttpServer {
    #[tool(description = "Read a status summary for one component.")]
    fn read_status(&self, Parameters(request): Parameters<StatusRequest>) -> String {
        let component = request.component.as_deref().unwrap_or("service");
        format!("{component}: starter template is running")
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for HostedHttpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Hosted HTTP/auth MCP server starter template.")
    }
}

pub fn build_router(
    config: HostedHttpConfig,
) -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let auth_layer =
        AuthSurfaceBuilder::single_issuer(config.public_base_url.clone(), issuer_entry(&config)?)
            .public_path("/health")
            .detect_insecure_http()
            .build()?;

    Ok(LocalMcpHttpServerBuilder::new()
        .allowed_hosts(config.allowed_hosts.clone())
        .stateless_fallback(true)
        .auth_layer(auth_layer)
        .build(|| Ok(HostedHttpServer::default())))
}

fn issuer_entry(
    config: &HostedHttpConfig,
) -> Result<IssuerEntry, Box<dyn std::error::Error + Send + Sync>> {
    let auth_config = AuthConfig {
        mode: AuthMode::Delegation,
        delegation_secret: Some(config.delegation_secret.clone()),
        delegation_issuer: config.issuer.clone(),
        delegation_audience: config.resource_url(),
        required_scopes: vec!["example.read".to_string()],
        ..AuthConfig::default()
    };
    let authenticator = Arc::new(Authenticator::new(auth_config)?);
    let metadata = AuthorizationServerMetadata {
        issuer: config.issuer.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", config.issuer),
        token_endpoint: format!("{}/oauth/token", config.issuer),
        registration_endpoint: None,
        jwks_uri: None,
        introspection_endpoint: None,
        device_authorization_endpoint: Some(format!("{}/oauth/device", config.issuer)),
        grant_types_supported: Some(vec![
            "authorization_code".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ]),
        client_id_metadata_document_supported: None,
        token_endpoint_auth_methods_supported: None,
        code_challenge_methods_supported: None,
    };

    Ok(IssuerEntry::from_metadata_source(
        "/mcp",
        AuthorizationServerMetadataSource::Explicit(metadata),
        "example",
        vec!["example.read".to_string()],
        HashSet::new(),
        authenticator,
        Some(config.resource_url()),
    )?)
}

#[cfg(test)]
mod tests {
    use super::{HostedHttpConfig, HostedHttpServer};
    use mcp_toolkit::server::http::{HttpBindSafety, HttpBindSafetyError};
    use mcp_toolkit_core::tool_inventory::{ToolInventoryPolicy, ToolOperation};

    #[test]
    fn inventory_exposes_only_read_status() {
        let server = HostedHttpServer::new().expect("server");
        let tools = server.tool_schema_snapshot();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["read_status"]);

        assert!(server.inventory().is_allowed(
            "read_status",
            ToolOperation::List,
            &ToolInventoryPolicy::default()
        ));
        assert_eq!(
            server.catalog().to_value()["tools"][0]["handler"],
            "HostedHttpServer::read_status"
        );
    }

    #[test]
    fn non_loopback_without_auth_is_rejected_by_policy() {
        let addr = "0.0.0.0:9411".parse().expect("addr");
        let result = HttpBindSafety::new(true, false).validate(addr);
        assert_eq!(
            result,
            Err(HttpBindSafetyError::AuthRequiredForNonLoopback { addr })
        );
    }

    #[test]
    fn local_dev_bind_policy_is_loopback_safe() {
        let config = HostedHttpConfig::local_dev();
        assert!(config.bind_safety().validate(config.bind_addr).is_ok());
    }
}

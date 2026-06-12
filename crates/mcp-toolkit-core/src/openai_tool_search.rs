//! # OpenAI Tool Search Helpers
//!
//! Small JSON builders for OpenAI Responses API tool-search integration with
//! MCP servers.
//!
//! ## Ownership
//! This module owns provider-specific configuration shapes that are useful to
//! many MCP servers and do not depend on a service domain model.
//!
//! ## Non-ownership
//! This module does not execute OpenAI requests, perform tool discovery, or
//! decide which service tools are safe to auto-approve.
//!
//! ## Policy & Guarantees
//! * **Generic MCP Shape**: Produces provider configuration without product
//!   names or service-specific tool policy.
//! * **Safe Defaults**: Leaves remote MCP approval behavior unset unless a
//!   caller explicitly supplies a reviewed read-only override.
//! * **Stable Metadata**: Provides consistent explanatory fields for hosted and
//!   client-executed tool search.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying accurate MCP server labels, descriptions, and URLs.
//! * Verifying any approval override only contains tools that are safe for the
//!   caller's trust boundary.
//! * Keeping generated configuration aligned with the OpenAI API version used
//!   by the client application.

use serde_json::{json, Map, Value};

/// Minimum OpenAI model family member that supports tool search.
pub const OPENAI_TOOL_SEARCH_MINIMUM_MODEL: &str = "gpt-5.4";

/// Recommended current OpenAI model for large MCP tool surfaces.
pub const OPENAI_TOOL_SEARCH_RECOMMENDED_MODEL: &str = "gpt-5.5";

/// Responses API tool type for OpenAI tool search.
pub const OPENAI_TOOL_SEARCH_TYPE: &str = "tool_search";

/// Responses API tool type for an MCP server.
pub const OPENAI_MCP_TOOL_TYPE: &str = "mcp";

/// OpenAI Responses API MCP server tool definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiMcpServerTool {
    pub server_label: String,
    pub server_description: String,
    pub server_url: String,
    pub defer_loading: bool,
}

impl OpenAiMcpServerTool {
    /// Create a deferred MCP server tool definition.
    pub fn new(
        server_label: impl Into<String>,
        server_description: impl Into<String>,
        server_url: impl Into<String>,
    ) -> Self {
        Self {
            server_label: server_label.into(),
            server_description: server_description.into(),
            server_url: server_url.into(),
            defer_loading: true,
        }
    }

    /// Control whether OpenAI should defer loading the MCP server's tools.
    pub fn with_defer_loading(mut self, defer_loading: bool) -> Self {
        self.defer_loading = defer_loading;
        self
    }

    /// Serialize this MCP server definition as a Responses API tool entry.
    pub fn to_value(&self) -> Value {
        json!({
            "type": OPENAI_MCP_TOOL_TYPE,
            "server_label": self.server_label,
            "server_description": self.server_description,
            "server_url": self.server_url,
            "defer_loading": self.defer_loading,
        })
    }
}

/// Optional read-only approval filter for trusted MCP workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiReadOnlyApprovalOverride {
    pub tool_names: Vec<String>,
}

impl OpenAiReadOnlyApprovalOverride {
    /// Create an approval override with normalized read-only tool names.
    ///
    /// Returns `None` when the reviewed tool list is empty after trimming and
    /// deduplication so callers do not accidentally emit an ambiguous approval
    /// filter.
    ///
    /// ```
    /// use mcp_toolkit_core::openai_tool_search::OpenAiReadOnlyApprovalOverride;
    ///
    /// let override_config = OpenAiReadOnlyApprovalOverride::new([
    ///     "read_b", "read_a", "read_a",
    /// ]);
    ///
    /// assert_eq!(
    ///     override_config.map(|config| config.tool_names),
    ///     Some(vec!["read_a".to_string(), "read_b".to_string()])
    /// );
    /// ```
    pub fn new<I, S>(tool_names: I) -> Option<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut tool_names = tool_names
            .into_iter()
            .filter_map(|tool_name| {
                let trimmed = tool_name.as_ref().trim();
                (!trimmed.is_empty()).then_some(trimmed.to_string())
            })
            .collect::<Vec<_>>();
        tool_names.sort();
        tool_names.dedup();

        (!tool_names.is_empty()).then_some(Self { tool_names })
    }

    /// Serialize this override as an OpenAI `require_approval` value.
    ///
    /// The filter is intentionally scoped to reviewed tool names. Callers should
    /// only pass names whose read-only behavior they have verified for their
    /// trust boundary.
    pub fn to_require_approval_value(&self) -> Value {
        json!({
            "never": {
                "tool_names": self.tool_names,
            }
        })
    }

    /// Serialize this override as documentation-friendly example payload.
    pub fn to_documentation_value(&self) -> Value {
        json!({
            "require_approval": self.to_require_approval_value(),
        })
    }
}

/// OpenAI Responses API tool-search configuration for one MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiMcpToolSearchConfig {
    pub model: String,
    pub minimum_model_for_tool_search: String,
    pub mcp_tool: OpenAiMcpServerTool,
    pub optional_trusted_read_only_approval_override: Option<OpenAiReadOnlyApprovalOverride>,
    pub notes: Vec<String>,
}

impl OpenAiMcpToolSearchConfig {
    /// Create a GPT-5.5-oriented hosted tool-search config for an MCP server.
    pub fn new(mcp_tool: OpenAiMcpServerTool) -> Self {
        Self {
            model: OPENAI_TOOL_SEARCH_RECOMMENDED_MODEL.to_string(),
            minimum_model_for_tool_search: OPENAI_TOOL_SEARCH_MINIMUM_MODEL.to_string(),
            mcp_tool,
            optional_trusted_read_only_approval_override: None,
            notes: Vec::new(),
        }
    }

    /// Override the recommended model string.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Override the minimum model string reported for tool-search support.
    pub fn with_minimum_model_for_tool_search(mut self, model: impl Into<String>) -> Self {
        self.minimum_model_for_tool_search = model.into();
        self
    }

    /// Add an optional read-only approval override for trusted workflows.
    ///
    /// `to_request_value()` applies this override inside the MCP tool
    /// definition. `to_documentation_value()` keeps the base request approval
    /// behavior unset and surfaces the override separately as an optional
    /// example.
    pub fn with_optional_trusted_read_only_approval_override(
        mut self,
        override_config: OpenAiReadOnlyApprovalOverride,
    ) -> Self {
        self.optional_trusted_read_only_approval_override = Some(override_config);
        self
    }

    /// Append explanatory notes to the generated config payload.
    pub fn with_notes<I, S>(mut self, notes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.notes.extend(notes.into_iter().map(Into::into));
        self
    }

    fn request_value_with_approval_mode(&self, include_approval_override: bool) -> Value {
        let mut payload = Map::new();
        payload.insert("model".to_string(), json!(self.model));
        let mut mcp_tool = self.mcp_tool.to_value();
        if let (Some(approval_override), Value::Object(mcp_tool_fields)) = (
            include_approval_override
                .then_some(self.optional_trusted_read_only_approval_override.as_ref())
                .flatten(),
            &mut mcp_tool,
        ) {
            mcp_tool_fields.insert(
                "require_approval".to_string(),
                approval_override.to_require_approval_value(),
            );
        }
        payload.insert(
            "tools".to_string(),
            json!([
                mcp_tool,
                {
                    "type": OPENAI_TOOL_SEARCH_TYPE,
                }
            ]),
        );
        Value::Object(payload)
    }

    /// Serialize this config as a Responses API request fragment.
    ///
    /// The returned value only contains fields that belong in the request body:
    /// `model` and the `tools` array, with any approval override embedded into
    /// the MCP tool definition.
    ///
    /// ```
    /// use mcp_toolkit_core::openai_tool_search::{
    ///     OpenAiMcpServerTool, OpenAiMcpToolSearchConfig,
    /// };
    ///
    /// let request = OpenAiMcpToolSearchConfig::new(OpenAiMcpServerTool::new(
    ///     "example",
    ///     "Example operational MCP tools.",
    ///     "https://example.com/mcp",
    /// ))
    /// .to_request_value();
    ///
    /// assert_eq!(request["model"], "gpt-5.5");
    /// assert_eq!(request["tools"][0]["type"], "mcp");
    /// assert_eq!(request["tools"][0]["defer_loading"], true);
    /// assert_eq!(request["tools"][1]["type"], "tool_search");
    /// ```
    pub fn to_request_value(&self) -> Value {
        self.request_value_with_approval_mode(true)
    }

    /// Serialize this config as a documentation or resource payload.
    ///
    /// This richer shape keeps the base request approval behavior unset, adds
    /// model-support notes, and exposes any reviewed approval override as a
    /// separate optional example instead of enabling it by default.
    pub fn to_documentation_value(&self) -> Value {
        let mut payload = match self.request_value_with_approval_mode(false) {
            Value::Object(fields) => fields,
            _ => Map::new(),
        };
        payload.insert(
            "minimum_model_for_tool_search".to_string(),
            json!(self.minimum_model_for_tool_search),
        );
        if let Some(approval_override) = &self.optional_trusted_read_only_approval_override {
            payload.insert(
                "optional_trusted_read_only_approval_override".to_string(),
                approval_override.to_documentation_value(),
            );
        }
        if !self.notes.is_empty() {
            payload.insert("notes".to_string(), json!(self.notes));
        }
        Value::Object(payload)
    }
}

/// Standard explanatory metadata for OpenAI deferred-loading responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiDeferredLoadingMetadata {
    pub hosted_tool_search: String,
    pub client_executed_tool_search: String,
    pub minimum_model: String,
    pub recommended_model: String,
    pub local_search_scope: String,
}

impl Default for OpenAiDeferredLoadingMetadata {
    fn default() -> Self {
        Self {
            hosted_tool_search: "Use OpenAI hosted tool_search by adding {\"type\":\"tool_search\"} to the Responses tools array and setting defer_loading=true on this MCP server definition.".to_string(),
            client_executed_tool_search: "Use client-executed tool search when tool discovery depends on application, project, tenant, or other runtime state that is not practical to declare up front.".to_string(),
            minimum_model: OPENAI_TOOL_SEARCH_MINIMUM_MODEL.to_string(),
            recommended_model: OPENAI_TOOL_SEARCH_RECOMMENDED_MODEL.to_string(),
            local_search_scope: "Local search results are helpers for non-hosted clients and manual allowed_tools narrowing; hosted OpenAI tool_search does not automatically call local search tools.".to_string(),
        }
    }
}

impl OpenAiDeferredLoadingMetadata {
    /// Serialize explanatory metadata for a local tool-search response.
    pub fn to_value(&self, metadata_label: Option<&str>) -> Value {
        json!({
            "hosted_tool_search": self.hosted_tool_search,
            "client_executed_tool_search": self.client_executed_tool_search,
            "minimum_model": self.minimum_model,
            "recommended_model": self.recommended_model,
            "local_search_scope": self.local_search_scope,
            "find_tools_scope": self.local_search_scope,
            "mcp_tool": { "defer_loading": true },
            "tool_search": { "type": OPENAI_TOOL_SEARCH_TYPE },
            "metadata_label": metadata_label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OpenAiMcpServerTool, OpenAiMcpToolSearchConfig, OpenAiReadOnlyApprovalOverride,
        OPENAI_TOOL_SEARCH_MINIMUM_MODEL, OPENAI_TOOL_SEARCH_RECOMMENDED_MODEL,
        OPENAI_TOOL_SEARCH_TYPE,
    };
    use serde_json::json;

    #[test]
    fn mcp_tool_search_request_uses_deferred_mcp_and_tool_search() {
        let request = OpenAiMcpToolSearchConfig::new(OpenAiMcpServerTool::new(
            "example",
            "Example operational MCP tools.",
            "https://example.com/mcp",
        ))
        .to_request_value();

        assert_eq!(
            request["model"],
            json!(OPENAI_TOOL_SEARCH_RECOMMENDED_MODEL)
        );
        assert_eq!(request["tools"][0]["type"], json!("mcp"));
        assert_eq!(request["tools"][0]["server_label"], json!("example"));
        assert_eq!(request["tools"][0]["defer_loading"], json!(true));
        assert_eq!(request["tools"][1]["type"], json!(OPENAI_TOOL_SEARCH_TYPE));
        assert!(request["tools"][0]["require_approval"].is_null());
    }

    #[test]
    fn documentation_value_keeps_default_approval_and_surfaces_optional_override() {
        let config = OpenAiMcpToolSearchConfig::new(OpenAiMcpServerTool::new(
            "example",
            "Example operational MCP tools.",
            "https://example.com/mcp",
        ))
        .with_optional_trusted_read_only_approval_override(
            OpenAiReadOnlyApprovalOverride::new(["read_b", "read_a", "read_a", " "])
                .expect("reviewed read-only tool list"),
        )
        .with_notes(["Keep mutating tools approval-gated."]);

        let value = config.to_documentation_value();

        assert_eq!(
            value["minimum_model_for_tool_search"],
            json!(OPENAI_TOOL_SEARCH_MINIMUM_MODEL)
        );
        assert!(value["tools"][0]["require_approval"].is_null());
        assert_eq!(
            value["optional_trusted_read_only_approval_override"]["require_approval"]["never"]
                ["tool_names"],
            json!(["read_a", "read_b"])
        );
        assert_eq!(
            value["notes"],
            json!(["Keep mutating tools approval-gated."])
        );
    }

    #[test]
    fn request_value_can_enable_reviewed_read_only_override() {
        let request = OpenAiMcpToolSearchConfig::new(OpenAiMcpServerTool::new(
            "example",
            "Example operational MCP tools.",
            "https://example.com/mcp",
        ))
        .with_optional_trusted_read_only_approval_override(
            OpenAiReadOnlyApprovalOverride::new(["read_a"]).expect("reviewed read-only tool list"),
        )
        .to_request_value();

        assert_eq!(
            request["tools"][0]["require_approval"]["never"]["tool_names"],
            json!(["read_a"])
        );
        assert!(request["minimum_model_for_tool_search"].is_null());
        assert!(request["notes"].is_null());
    }

    #[test]
    fn read_only_override_rejects_empty_reviewed_tool_lists() {
        assert!(OpenAiReadOnlyApprovalOverride::new(["", "   "]).is_none());
    }
}

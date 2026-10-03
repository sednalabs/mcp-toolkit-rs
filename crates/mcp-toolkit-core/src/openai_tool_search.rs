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

use std::borrow::Cow;

use serde_json::{json, Map, Value};

/// Historical minimum OpenAI model family member that supported tool search.
///
/// This value is retained for compatibility metadata and must not be treated
/// as a current capability threshold.
#[deprecated(note = "model support changes over time; describe capabilities instead")]
pub const OPENAI_TOOL_SEARCH_MINIMUM_MODEL: &str = "gpt-5.4";

/// Historical OpenAI model recommendation retained for compatibility metadata.
#[deprecated(note = "model recommendations change over time; select a model in the application")]
pub const OPENAI_TOOL_SEARCH_RECOMMENDED_MODEL: &str = "gpt-5.5";

/// Responses API tool type for OpenAI tool search.
pub const OPENAI_TOOL_SEARCH_TYPE: &str = "tool_search";

/// Responses API tool type for an MCP server.
pub const OPENAI_MCP_TOOL_TYPE: &str = "mcp";

/// Provider-neutral capability metadata for deferred loading and tool search.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenAiToolSearchCapabilities {
    /// Optional application-maintained compatibility details for model-specific clients.
    pub model_compatibility: Option<OpenAiToolSearchModelCompatibility>,
}

/// Explicit, application-maintained model compatibility metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiToolSearchModelCompatibility {
    pub minimum_model: String,
    pub recommended_model: Option<String>,
}

impl OpenAiToolSearchCapabilities {
    /// Add model compatibility metadata selected and maintained by the caller.
    pub fn with_model_compatibility(
        mut self,
        minimum_model: impl Into<String>,
        recommended_model: Option<impl Into<String>>,
    ) -> Self {
        self.model_compatibility = Some(OpenAiToolSearchModelCompatibility {
            minimum_model: minimum_model.into(),
            recommended_model: recommended_model.map(Into::into),
        });
        self
    }

    /// Serialize capability metadata without imposing a model policy.
    pub fn to_value(&self) -> Value {
        let mut value = json!({
            "hosted_tool_search": HOSTED_TOOL_SEARCH_METADATA,
            "client_executed_tool_search": CLIENT_EXECUTED_TOOL_SEARCH_METADATA,
            "local_search_scope": LOCAL_SEARCH_SCOPE_METADATA,
            "find_tools_scope": LOCAL_SEARCH_SCOPE_METADATA,
            "mcp_tool": { "defer_loading": true },
            "tool_search": { "type": OPENAI_TOOL_SEARCH_TYPE },
        });
        if let (Some(compatibility), Value::Object(fields)) =
            (&self.model_compatibility, &mut value)
        {
            if !compatibility.minimum_model.is_empty() {
                fields.insert(
                    "minimum_model".to_string(),
                    json!(compatibility.minimum_model),
                );
            }
            if let Some(recommended_model) = &compatibility.recommended_model {
                if !recommended_model.is_empty() {
                    fields.insert("recommended_model".to_string(), json!(recommended_model));
                }
            }
        }
        value
    }
}

const HOSTED_TOOL_SEARCH_METADATA: &str = "Use OpenAI hosted tool_search by adding {\"type\":\"tool_search\"} to the Responses tools array and setting defer_loading=true on this MCP server definition.";
const CLIENT_EXECUTED_TOOL_SEARCH_METADATA: &str = "Use client-executed tool search when tool discovery depends on application, project, tenant, or other runtime state that is not practical to declare up front.";
const LOCAL_SEARCH_SCOPE_METADATA: &str = "Local search results are helpers for non-hosted clients and manual allowed_tools narrowing; hosted OpenAI tool_search does not automatically call local search tools.";

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
    /// Create the historical model-pinned config for an MCP server.
    #[deprecated(note = "use OpenAiMcpToolSearchRequest with an application-selected model")]
    pub fn new(mcp_tool: OpenAiMcpServerTool) -> Self {
        Self {
            model: "gpt-5.5".to_string(),
            minimum_model_for_tool_search: "gpt-5.4".to_string(),
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
    ///     OpenAiMcpServerTool, OpenAiMcpToolSearchRequest,
    /// };
    ///
    /// let request = OpenAiMcpToolSearchRequest::new("application-selected-model", OpenAiMcpServerTool::new(
    ///     "example",
    ///     "Example operational MCP tools.",
    ///     "https://example.com/mcp",
    /// ))
    /// .to_request_value();
    ///
    /// assert_eq!(request["model"], "application-selected-model");
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
    /// historical model metadata, and exposes any reviewed approval override as
    /// a separate optional example instead of enabling it by default.
    #[deprecated(
        note = "use capability metadata; this payload only labels historical model values"
    )]
    pub fn to_documentation_value(&self) -> Value {
        let mut payload = match self.request_value_with_approval_mode(false) {
            Value::Object(fields) => fields,
            _ => Map::new(),
        };
        payload.insert(
            "minimum_model_for_tool_search".to_string(),
            json!(self.minimum_model_for_tool_search),
        );
        payload.insert(
            "model_compatibility_status".to_string(),
            json!("historical"),
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

/// Responses API tool-search request using a model selected by the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiMcpToolSearchRequest {
    pub model: String,
    pub mcp_tool: OpenAiMcpServerTool,
    pub optional_trusted_read_only_approval_override: Option<OpenAiReadOnlyApprovalOverride>,
}

impl OpenAiMcpToolSearchRequest {
    /// Create a request using the application's selected model.
    pub fn new(model: impl Into<String>, mcp_tool: OpenAiMcpServerTool) -> Self {
        Self {
            model: model.into(),
            mcp_tool,
            optional_trusted_read_only_approval_override: None,
        }
    }

    /// Add an optional reviewed read-only approval override.
    pub fn with_optional_trusted_read_only_approval_override(
        mut self,
        override_config: OpenAiReadOnlyApprovalOverride,
    ) -> Self {
        self.optional_trusted_read_only_approval_override = Some(override_config);
        self
    }

    /// Serialize this config as a Responses API request fragment.
    pub fn to_request_value(&self) -> Value {
        let mut mcp_tool = self.mcp_tool.to_value();
        if let (Some(approval_override), Value::Object(fields)) = (
            &self.optional_trusted_read_only_approval_override,
            &mut mcp_tool,
        ) {
            fields.insert(
                "require_approval".to_string(),
                approval_override.to_require_approval_value(),
            );
        }
        json!({
            "model": self.model,
            "tools": [mcp_tool, { "type": OPENAI_TOOL_SEARCH_TYPE }],
        })
    }
}

/// Standard explanatory metadata for OpenAI deferred-loading responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiDeferredLoadingMetadata {
    pub hosted_tool_search: Cow<'static, str>,
    pub client_executed_tool_search: Cow<'static, str>,
    pub minimum_model: Cow<'static, str>,
    pub recommended_model: Cow<'static, str>,
    pub local_search_scope: Cow<'static, str>,
}

impl Default for OpenAiDeferredLoadingMetadata {
    fn default() -> Self {
        Self {
            hosted_tool_search: Cow::Borrowed(HOSTED_TOOL_SEARCH_METADATA),
            client_executed_tool_search: Cow::Borrowed(CLIENT_EXECUTED_TOOL_SEARCH_METADATA),
            minimum_model: Cow::Borrowed(""),
            recommended_model: Cow::Borrowed(""),
            local_search_scope: Cow::Borrowed(LOCAL_SEARCH_SCOPE_METADATA),
        }
    }
}

impl OpenAiDeferredLoadingMetadata {
    /// Add caller-maintained model-specific compatibility metadata.
    pub fn with_model_compatibility(
        mut self,
        minimum_model: impl Into<String>,
        recommended_model: Option<impl Into<String>>,
    ) -> Self {
        self.minimum_model = Cow::Owned(minimum_model.into());
        self.recommended_model = recommended_model
            .map(|model| Cow::Owned(model.into()))
            .unwrap_or_else(|| Cow::Borrowed(""));
        self
    }

    /// Serialize explanatory metadata for a local tool-search response.
    pub fn to_value(&self, metadata_label: Option<&str>) -> Value {
        let mut value = json!({
            "hosted_tool_search": self.hosted_tool_search.as_ref(),
            "client_executed_tool_search": self.client_executed_tool_search.as_ref(),
            "local_search_scope": self.local_search_scope.as_ref(),
            "find_tools_scope": self.local_search_scope.as_ref(),
            "mcp_tool": { "defer_loading": true },
            "tool_search": { "type": OPENAI_TOOL_SEARCH_TYPE },
            "metadata_label": metadata_label,
        });
        if !self.minimum_model.is_empty() {
            value["minimum_model"] = json!(self.minimum_model.as_ref());
        }
        if !self.recommended_model.is_empty() {
            value["recommended_model"] = json!(self.recommended_model.as_ref());
        }
        value
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]

    use super::{
        OpenAiMcpServerTool, OpenAiMcpToolSearchConfig, OpenAiMcpToolSearchRequest,
        OpenAiReadOnlyApprovalOverride, OpenAiToolSearchCapabilities, OPENAI_TOOL_SEARCH_TYPE,
    };
    use serde_json::json;

    #[test]
    fn mcp_tool_search_request_uses_caller_selected_model() {
        let request = OpenAiMcpToolSearchRequest::new(
            "app-selected-model",
            OpenAiMcpServerTool::new(
                "example",
                "Example operational MCP tools.",
                "https://example.com/mcp",
            ),
        )
        .with_optional_trusted_read_only_approval_override(
            OpenAiReadOnlyApprovalOverride::new(["read_a"]).expect("reviewed read-only tool list"),
        )
        .to_request_value();

        assert_eq!(request["model"], json!("app-selected-model"));
        assert_eq!(request["tools"][0]["type"], json!("mcp"));
        assert_eq!(request["tools"][0]["server_label"], json!("example"));
        assert_eq!(request["tools"][0]["defer_loading"], json!(true));
        assert_eq!(request["tools"][1]["type"], json!(OPENAI_TOOL_SEARCH_TYPE));
        assert_eq!(
            request["tools"][0]["require_approval"]["never"]["tool_names"],
            json!(["read_a"])
        );
        assert!(request["tools"][1]["require_approval"].is_null());
    }

    #[test]
    fn neutral_capabilities_omit_models_and_allow_explicit_compatibility() {
        let neutral = OpenAiToolSearchCapabilities::default().to_value();
        assert!(neutral.get("minimum_model").is_none());
        assert!(neutral.get("recommended_model").is_none());

        let compatible = OpenAiToolSearchCapabilities::default()
            .with_model_compatibility("app-minimum", Some("app-recommended"))
            .to_value();
        assert_eq!(compatible["minimum_model"], json!("app-minimum"));
        assert_eq!(compatible["recommended_model"], json!("app-recommended"));

        let blank_compatibility = OpenAiToolSearchCapabilities::default()
            .with_model_compatibility("", Some(""))
            .to_value();
        assert!(blank_compatibility.get("minimum_model").is_none());
        assert!(blank_compatibility.get("recommended_model").is_none());
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

        assert_eq!(value["minimum_model_for_tool_search"], json!("gpt-5.4"));
        assert_eq!(value["model_compatibility_status"], json!("historical"));
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

    #[test]
    fn deferred_loading_metadata_is_neutral_by_default_and_compatibility_is_opt_in() {
        let neutral = super::OpenAiDeferredLoadingMetadata::default().to_value(None);
        assert!(neutral.get("minimum_model").is_none());
        assert!(neutral.get("recommended_model").is_none());

        let compatible = super::OpenAiDeferredLoadingMetadata::default()
            .with_model_compatibility("app-minimum", Some("app-recommended"))
            .to_value(None);
        assert_eq!(compatible["minimum_model"], json!("app-minimum"));
        assert_eq!(compatible["recommended_model"], json!("app-recommended"));
    }
}

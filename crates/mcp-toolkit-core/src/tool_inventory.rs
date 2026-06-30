//! # Tool Inventory Composition
//!
//! Inventory and capability composition for MCP tools.
//!
//! ## Ownership
//! This module owns the definition and filtering logic for `ToolCapability` and
//! `ToolInventory` registries, providing a mechanism to enforce tool exposure policies.
//!
//! ## Non-ownership
//! This module does not perform authentication, authorization, or transport-level
//! enforcement. It purely provides a capability-matching layer.
//!
//! ## Policy & Guarantees
//! * **Capability Composition**: Enables filtering of tool surfaces by group,
//!   read-only status, or feature flag.
//! * **Operation Awareness**: Supports fine-grained enforcement of `list` vs `call`
//!   permissions for registered tools.
//! * **Input Normalization**: Strips whitespace and validates non-empty identifiers
//!   to ensure robust inventory keys.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying trustable capability registrations.
//! * Ensuring that the `ToolInventoryPolicy` enforced reflects their actual
//!   authorization/permission requirements.
//!
//! ## References
//! * MCP Tool Discovery: https://modelcontextprotocol.io/docs/concepts/tools

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};

use serde_json::{json, Map, Value};

use crate::guarded_action::GuardedActionPosture;
use crate::openai_tool_search::OpenAiDeferredLoadingMetadata;

/// Standard profile key for generated read-only tool surfaces.
pub const READ_ONLY_PROFILE_KEY: &str = "read_only";

/// Standard profile key for explicit operator tool surfaces.
pub const OPERATOR_PROFILE_KEY: &str = "operator";

/// Standard feature flag for tools that should only appear in operator profiles.
pub const OPERATOR_TOOLS_FEATURE_FLAG: &str = "operator_tools";

/// MCP tool operation used for method-aware exposure checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolOperation {
    /// `tools/list` visibility.
    List,
    /// `tools/call` dispatch.
    Call,
}

/// Exposure mode for a registered tool capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolExposure {
    /// Tool is visible and callable.
    #[default]
    All,
    /// Tool is visible in `tools/list` only.
    ListOnly,
    /// Tool is callable only (rare, usually for internal migration paths).
    CallOnly,
    /// Tool is disabled for both list and call.
    Disabled,
}

impl ToolExposure {
    fn allows(self, operation: ToolOperation) -> bool {
        matches!(
            (self, operation),
            (ToolExposure::All, _)
                | (ToolExposure::ListOnly, ToolOperation::List)
                | (ToolExposure::CallOnly, ToolOperation::Call)
        )
    }
}

/// Registered capability metadata for a single tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCapability {
    name: String,
    group: Option<String>,
    read_only: bool,
    feature_flag: Option<String>,
    exposure: ToolExposure,
    discovery: Option<ToolDiscoveryMetadata>,
    risk_posture: Option<GuardedActionPosture>,
}

impl ToolCapability {
    /// Create a capability registration with default exposure.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: None,
            read_only: false,
            feature_flag: None,
            exposure: ToolExposure::All,
            discovery: None,
            risk_posture: None,
        }
    }

    /// Attach a logical group label.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Mark whether the tool is read-only.
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Attach an optional feature flag gate.
    pub fn with_feature_flag(mut self, feature_flag: impl Into<String>) -> Self {
        self.feature_flag = Some(feature_flag.into());
        self
    }

    /// Gate this capability behind the standard operator profile feature flag.
    pub fn with_operator_profile_gate(self) -> Self {
        self.with_feature_flag(OPERATOR_TOOLS_FEATURE_FLAG)
    }

    /// Configure operation-aware exposure.
    pub fn with_exposure(mut self, exposure: ToolExposure) -> Self {
        self.exposure = exposure;
        self
    }

    /// Attach metadata used by deferred-loading/tool-search clients.
    pub fn with_discovery(mut self, discovery: ToolDiscoveryMetadata) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// Attach risk posture metadata for guarded preview/apply or admin tools.
    pub fn with_risk_posture(mut self, risk_posture: GuardedActionPosture) -> Self {
        self.read_only = risk_posture.is_read_only();
        self.risk_posture = Some(risk_posture);
        self
    }

    /// Return the tool name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Return the group label, if present.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Return true when the capability is read-only.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Return the feature flag gate, if present.
    pub fn feature_flag(&self) -> Option<&str> {
        self.feature_flag.as_deref()
    }

    /// Return the operation exposure mode.
    pub fn exposure(&self) -> ToolExposure {
        self.exposure
    }

    /// Return optional discovery metadata for tool-search/deferred-loading clients.
    pub fn discovery(&self) -> Option<&ToolDiscoveryMetadata> {
        self.discovery.as_ref()
    }

    /// Return optional guarded-action posture metadata.
    pub fn risk_posture(&self) -> Option<&GuardedActionPosture> {
        self.risk_posture.as_ref()
    }
}

/// Searchable metadata for deferred-loading/tool-search integrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDiscoveryMetadata {
    description: String,
    keywords: Vec<String>,
}

impl ToolDiscoveryMetadata {
    /// Create discovery metadata with normalized keywords.
    pub fn new<I, S>(description: impl Into<String>, keywords: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut keywords = keywords
            .into_iter()
            .filter_map(|keyword| {
                let keyword = keyword.as_ref().trim().to_ascii_lowercase();
                (!keyword.is_empty()).then_some(keyword)
            })
            .collect::<Vec<_>>();
        keywords.sort();
        keywords.dedup();

        Self {
            description: description.into(),
            keywords,
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    /// Normalized keyword list.
    pub fn keywords(&self) -> &[String] {
        self.keywords.as_slice()
    }
}

/// Filter options for searching inventory metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolSearchFilter {
    pub query: Option<String>,
    pub group: Option<String>,
    pub read_only: Option<bool>,
    pub limit: Option<usize>,
}

/// Search result for one registered tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSearchResult {
    pub name: String,
    pub group: Option<String>,
    pub read_only: bool,
    pub description: Option<String>,
    pub keywords: Vec<String>,
    pub risk_posture: Option<GuardedActionPosture>,
}

/// Standard JSON envelope for tool-search/deferred-loading responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSearchResponse {
    pub operation: String,
    pub query: Option<String>,
    pub group: Option<String>,
    pub read_only: Option<bool>,
    pub results: Vec<ToolSearchResult>,
    pub schemas: Option<Value>,
    pub metadata_label: Option<String>,
}

impl ToolSearchResponse {
    /// Create a standard `find_tools` response from inventory search results.
    pub fn find_tools(
        query: Option<String>,
        group: Option<String>,
        read_only: Option<bool>,
        results: Vec<ToolSearchResult>,
    ) -> Self {
        Self {
            operation: "find_tools".to_string(),
            query,
            group,
            read_only,
            results,
            schemas: None,
            metadata_label: None,
        }
    }

    /// Attach optional MCP tool schemas keyed by tool name.
    pub fn with_schemas(mut self, schemas: Option<Value>) -> Self {
        self.schemas = schemas;
        self
    }

    /// Attach a compatibility label for clients/tests without changing semantics.
    pub fn with_metadata_label(mut self, label: impl Into<String>) -> Self {
        self.metadata_label = Some(label.into());
        self
    }

    /// Tool names suitable for OpenAI `allowed_tools` style narrowing.
    pub fn openai_allowed_tools(&self) -> Vec<String> {
        let mut tools = self
            .results
            .iter()
            .map(|result| result.name.clone())
            .collect::<Vec<_>>();
        tools.sort();
        tools.dedup();
        tools
    }

    /// Serialize to the common JSON shape used by deferred-loading/tool-search clients.
    pub fn to_value(&self) -> Value {
        let result_values = self
            .results
            .iter()
            .map(tool_search_result_value)
            .collect::<Vec<_>>();
        json!({
            "operation": self.operation,
            "query": self.query,
            "group": self.group,
            "read_only": self.read_only,
            "results": result_values,
            "openai_allowed_tools": self.openai_allowed_tools(),
            "schemas": self.schemas.clone(),
            "openai_deferred_loading": OpenAiDeferredLoadingMetadata::default()
                .to_value(self.metadata_label.as_deref()),
        })
    }

    /// Wrap this response in an OpenAI-oriented builder with extra result support.
    pub fn into_openai_response(self) -> OpenAiToolSearchResponse {
        OpenAiToolSearchResponse::from_response(self)
    }
}

/// Additive OpenAI response builder for local tool-search helpers.
///
/// # Examples
/// ```
/// use mcp_toolkit_core::tool_inventory::{ToolSearchResponse, ToolSearchResult};
/// use serde_json::json;
///
/// let response = ToolSearchResponse::find_tools(
///     Some("metrics".to_string()),
///     None,
///     None,
///     vec![ToolSearchResult {
///         name: "metrics.read".to_string(),
///         group: Some("metrics".to_string()),
///         read_only: true,
///         description: Some("Read metrics".to_string()),
///         keywords: vec!["metrics".to_string()],
///         risk_posture: None,
///     }],
/// )
/// .into_openai_response()
/// .with_companion_allowed_tools(["api_prepare_call"]);
///
/// let value = response.to_value();
/// assert_eq!(
///     value["openai_allowed_tools"],
///     json!(["api_prepare_call", "metrics.read"])
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiToolSearchResponse {
    pub response: ToolSearchResponse,
    pub companion_allowed_tools: Vec<String>,
    pub extra_results: Vec<Value>,
    pub openai_metadata: OpenAiDeferredLoadingMetadata,
}

impl OpenAiToolSearchResponse {
    /// Create an OpenAI-oriented response builder from a base search response.
    pub fn from_response(response: ToolSearchResponse) -> Self {
        Self {
            response,
            companion_allowed_tools: Vec::new(),
            extra_results: Vec::new(),
            openai_metadata: OpenAiDeferredLoadingMetadata::default(),
        }
    }

    /// Add extra tool names that should be allowed with the search results.
    pub fn with_companion_allowed_tools<I, S>(mut self, tool_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.companion_allowed_tools
            .extend(tool_names.into_iter().filter_map(|tool_name| {
                let trimmed = tool_name.as_ref().trim();
                (!trimmed.is_empty()).then_some(trimmed.to_string())
            }));
        self
    }

    /// Attach non-inventory search results without changing allowed tool names.
    pub fn with_extra_results<I>(mut self, results: I) -> Self
    where
        I: IntoIterator<Item = Value>,
    {
        self.extra_results.extend(results);
        self
    }

    /// Attach provider metadata for OpenAI deferred-loading clients.
    pub fn with_openai_metadata(mut self, metadata: OpenAiDeferredLoadingMetadata) -> Self {
        self.openai_metadata = metadata;
        self
    }

    /// Tool names suitable for OpenAI `allowed_tools` style narrowing.
    pub fn openai_allowed_tools(&self) -> Vec<String> {
        let mut tools = self.response.openai_allowed_tools();
        tools.extend(self.companion_allowed_tools.iter().cloned());
        tools.sort();
        tools.dedup();
        tools
    }

    /// Serialize to the common JSON shape used by OpenAI tool-search clients.
    pub fn to_value(&self) -> Value {
        let mut result_values = self
            .response
            .results
            .iter()
            .map(tool_search_result_value)
            .collect::<Vec<_>>();
        result_values.extend(self.extra_results.iter().cloned());
        json!({
            "operation": self.response.operation,
            "query": self.response.query,
            "group": self.response.group,
            "read_only": self.response.read_only,
            "results": result_values,
            "openai_allowed_tools": self.openai_allowed_tools(),
            "schemas": self.response.schemas.clone(),
            "openai_deferred_loading": self.openai_metadata
                .to_value(self.response.metadata_label.as_deref()),
        })
    }
}

fn tool_search_result_value(result: &ToolSearchResult) -> Value {
    json!({
        "type": "tool",
        "name": result.name,
        "group": result.group,
        "read_only": result.read_only,
        "description": result.description,
        "keywords": result.keywords,
        "risk_posture": result.risk_posture,
    })
}

/// Filtering policy for inventory-based capability composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInventoryPolicy {
    /// Optional allowlist of tool groups. `None` means all groups are allowed.
    pub allowed_groups: Option<HashSet<String>>,
    /// When true, only read-only tools are allowed.
    pub read_only_only: bool,
    /// Enabled feature flags for gated tools.
    pub enabled_feature_flags: HashSet<String>,
    /// Whether unknown/unregistered tool names should be allowed.
    pub include_unregistered: bool,
}

impl Default for ToolInventoryPolicy {
    fn default() -> Self {
        Self {
            allowed_groups: None,
            read_only_only: false,
            enabled_feature_flags: HashSet::new(),
            include_unregistered: true,
        }
    }
}

impl ToolInventoryPolicy {
    /// Create a strict policy that denies unknown/unregistered tools.
    pub fn strict() -> Self {
        Self {
            include_unregistered: false,
            ..Self::default()
        }
    }

    /// Create the standard explicit operator policy for generated servers.
    pub fn strict_operator() -> Self {
        Self::strict().with_feature_flags([OPERATOR_TOOLS_FEATURE_FLAG])
    }

    /// Create a strict policy for default read-only server profiles.
    ///
    /// This is the common safe baseline for MCP servers that expose read tools
    /// by default and enable mutations only through an explicit operator
    /// profile or similar higher-level switch.
    pub fn strict_read_only() -> Self {
        Self::strict().with_read_only_only(true)
    }

    /// Enable read-only-only filtering.
    pub fn with_read_only_only(mut self, read_only_only: bool) -> Self {
        self.read_only_only = read_only_only;
        self
    }

    /// Set group allowlist. Empty/blank inputs clear the allowlist.
    pub fn with_allowed_groups<I, S>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let normalized: HashSet<String> = groups
            .into_iter()
            .filter_map(|raw| {
                let trimmed = raw.as_ref().trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect();
        self.allowed_groups = if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        };
        self
    }

    /// Set enabled feature flags.
    pub fn with_feature_flags<I, S>(mut self, flags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.enabled_feature_flags = flags
            .into_iter()
            .filter_map(|raw| {
                let trimmed = raw.as_ref().trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect();
        self
    }

    /// Control fallback behavior for unregistered tools.
    pub fn with_include_unregistered(mut self, include_unregistered: bool) -> Self {
        self.include_unregistered = include_unregistered;
        self
    }

    fn allows_capability(&self, capability: &ToolCapability, operation: ToolOperation) -> bool {
        self.denial_reason(capability, operation).is_none()
    }

    fn denial_reason(
        &self,
        capability: &ToolCapability,
        operation: ToolOperation,
    ) -> Option<ToolInventoryDenialReason> {
        if !capability.exposure.allows(operation) {
            return Some(ToolInventoryDenialReason::ExposureDisabled);
        }
        if self.read_only_only && !capability.read_only {
            return Some(ToolInventoryDenialReason::ReadOnlyProfile);
        }
        if let Some(groups) = &self.allowed_groups {
            let Some(group) = capability.group.as_deref() else {
                return Some(ToolInventoryDenialReason::GroupNotAllowed);
            };
            if !groups.contains(group) {
                return Some(ToolInventoryDenialReason::GroupNotAllowed);
            }
        }
        if let Some(feature_flag) = capability.feature_flag.as_deref() {
            if !self.enabled_feature_flags.contains(feature_flag) {
                return Some(ToolInventoryDenialReason::FeatureFlagDisabled);
            }
        }
        None
    }
}

/// Stable reason why a tool was denied by an inventory/profile policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolInventoryDenialReason {
    /// The requested tool name was blank after trimming.
    BlankToolName,
    /// The tool is not registered and the policy denies unknown tools.
    UnregisteredTool,
    /// The tool is hidden for the requested MCP operation.
    ExposureDisabled,
    /// The active profile only permits read-only tools.
    ReadOnlyProfile,
    /// The active profile does not include the tool's group.
    GroupNotAllowed,
    /// The tool requires a feature flag that is not active.
    FeatureFlagDisabled,
}

impl ToolInventoryDenialReason {
    /// Stable machine-readable denial code.
    pub fn code(self) -> &'static str {
        match self {
            Self::BlankToolName => "TOOL_DENIED_BLANK_NAME",
            Self::UnregisteredTool => "TOOL_DENIED_UNREGISTERED",
            Self::ExposureDisabled => "TOOL_DENIED_EXPOSURE_DISABLED",
            Self::ReadOnlyProfile => "TOOL_DENIED_READ_ONLY_PROFILE",
            Self::GroupNotAllowed => "TOOL_DENIED_GROUP_NOT_ALLOWED",
            Self::FeatureFlagDisabled => "TOOL_DENIED_FEATURE_FLAG_DISABLED",
        }
    }

    /// Human-readable reason suitable for operator diagnostics.
    pub fn message(self) -> &'static str {
        match self {
            Self::BlankToolName => "tool name is empty",
            Self::UnregisteredTool => "tool is not registered in the catalog",
            Self::ExposureDisabled => "tool is not exposed for this MCP operation",
            Self::ReadOnlyProfile => "active profile allows read-only tools only",
            Self::GroupNotAllowed => "active profile does not include this tool group",
            Self::FeatureFlagDisabled => "active profile has not enabled this tool feature flag",
        }
    }
}

/// Policy decision for one tool under one operation/profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInventoryDecision {
    pub tool_name: String,
    pub operation: ToolOperation,
    pub profile_key: Option<String>,
    pub allowed: bool,
    pub denial_reason: Option<ToolInventoryDenialReason>,
}

impl ToolInventoryDecision {
    fn permit(tool_name: String, operation: ToolOperation, profile_key: Option<String>) -> Self {
        Self {
            tool_name,
            operation,
            profile_key,
            allowed: true,
            denial_reason: None,
        }
    }

    fn denied(
        tool_name: String,
        operation: ToolOperation,
        profile_key: Option<String>,
        denial_reason: ToolInventoryDenialReason,
    ) -> Self {
        Self {
            tool_name,
            operation,
            profile_key,
            allowed: false,
            denial_reason: Some(denial_reason),
        }
    }

    /// Return true when the profile/policy allows the operation.
    pub fn allowed(&self) -> bool {
        self.allowed
    }

    /// Short caller-visible message for profile-gated tool denials.
    pub fn caller_message(&self) -> String {
        match self.denial_reason {
            Some(reason) => format!(
                "{}: {} for `{}`",
                reason.code(),
                reason.message(),
                self.tool_name
            ),
            None => format!("tool `{}` is allowed", self.tool_name),
        }
    }

    /// Serialize this decision into a stable diagnostic artifact.
    pub fn to_value(&self) -> Value {
        json!({
            "schema": "mcp_tool_inventory_decision",
            "version": 1,
            "tool_name": self.tool_name,
            "operation": operation_label(self.operation),
            "profile_key": self.profile_key,
            "allowed": self.allowed,
            "denial": self.denial_reason.map(|reason| json!({
                "code": reason.code(),
                "message": reason.message(),
            })),
        })
    }
}

/// Named native catalog profile for a coherent MCP tool surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCatalogProfile {
    key: String,
    title: String,
    description: String,
    instructions: Option<String>,
    policy: ToolInventoryPolicy,
    required_tools: Vec<String>,
    required_groups: Vec<String>,
}

impl ToolCatalogProfile {
    /// Create a profile with normalized public identity fields.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when any identity field is blank.
    pub fn new(
        key: impl AsRef<str>,
        title: impl AsRef<str>,
        description: impl AsRef<str>,
    ) -> Result<Self, ToolInventoryError> {
        Ok(Self {
            key: normalize_non_empty("catalog profile key", key.as_ref())?,
            title: normalize_non_empty("catalog profile title", title.as_ref())?,
            description: normalize_non_empty("catalog profile description", description.as_ref())?,
            instructions: None,
            policy: ToolInventoryPolicy::strict(),
            required_tools: Vec::new(),
            required_groups: Vec::new(),
        })
    }

    /// Create the standard generated read-only profile.
    pub fn read_only_default() -> Self {
        Self {
            key: READ_ONLY_PROFILE_KEY.to_string(),
            title: "Read-only".to_string(),
            description: "Default profile that exposes read-only tools only.".to_string(),
            instructions: Some(
                "Enable an explicit operator profile before exposing mutation tools.".to_string(),
            ),
            policy: ToolInventoryPolicy::strict_read_only(),
            required_tools: Vec::new(),
            required_groups: Vec::new(),
        }
    }

    /// Create the standard explicit operator profile.
    pub fn operator_default() -> Self {
        Self {
            key: OPERATOR_PROFILE_KEY.to_string(),
            title: "Operator".to_string(),
            description: "Opt-in profile for reviewed operator and mutation tools.".to_string(),
            instructions: Some(
                "Use only for trusted operators with matching provider permissions.".to_string(),
            ),
            policy: ToolInventoryPolicy::strict_operator(),
            required_tools: Vec::new(),
            required_groups: Vec::new(),
        }
    }

    /// Attach short host-facing instructions for this profile.
    #[must_use]
    pub fn with_instructions(mut self, instructions: impl AsRef<str>) -> Self {
        let instructions = instructions.as_ref().trim();
        self.instructions = (!instructions.is_empty()).then(|| instructions.to_string());
        self
    }

    /// Replace the inventory policy used to shape this profile.
    #[must_use]
    pub fn with_policy(mut self, policy: ToolInventoryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Set tools that must be present after profile filtering.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when any tool name is blank.
    pub fn with_required_tools<I, S>(mut self, tools: I) -> Result<Self, ToolInventoryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.required_tools = normalize_non_empty_list("required tool", tools)?;
        Ok(self)
    }

    /// Set tool groups that must have at least one visible tool.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when any group name is blank.
    pub fn with_required_groups<I, S>(mut self, groups: I) -> Result<Self, ToolInventoryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.required_groups = normalize_non_empty_list("required group", groups)?;
        Ok(self)
    }

    /// Stable profile key.
    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// Human-readable profile title.
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    /// Human-readable profile description.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    /// Optional host-facing profile instructions.
    pub fn instructions(&self) -> Option<&str> {
        self.instructions.as_deref()
    }

    /// Inventory policy that shapes this profile.
    pub fn policy(&self) -> &ToolInventoryPolicy {
        &self.policy
    }

    /// Tools that must remain visible in this profile.
    pub fn required_tools(&self) -> &[String] {
        self.required_tools.as_slice()
    }

    /// Groups that must have at least one visible tool in this profile.
    pub fn required_groups(&self) -> &[String] {
        self.required_groups.as_slice()
    }
}

/// Probe-readable contract emitted for one native catalog profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCatalogContract {
    pub profile_key: String,
    pub title: String,
    pub description: String,
    pub instructions: Option<String>,
    pub operation: ToolOperation,
    pub tool_names: Vec<String>,
    pub groups: Vec<String>,
    pub required_tools: Vec<String>,
    pub missing_required_tools: Vec<String>,
    pub required_groups: Vec<String>,
    pub missing_required_groups: Vec<String>,
    pub allowed_groups: Option<Vec<String>>,
    pub read_only_only: bool,
    pub include_unregistered: bool,
    pub enabled_feature_flags: Vec<String>,
}

impl ToolCatalogContract {
    /// Return true when required tools and groups are present.
    pub fn is_satisfied(&self) -> bool {
        self.missing_required_tools.is_empty() && self.missing_required_groups.is_empty()
    }

    /// Serialize this profile contract into a stable JSON artifact.
    pub fn to_value(&self) -> Value {
        json!({
            "schema": "mcp_tool_catalog_profile_contract",
            "version": 1,
            "profile": {
                "key": self.profile_key,
                "title": self.title,
                "description": self.description,
                "instructions": self.instructions,
            },
            "operation": operation_label(self.operation),
            "tool_count": self.tool_names.len(),
            "tool_names": self.tool_names,
            "groups": self.groups,
            "requirements": {
                "required_tools": self.required_tools,
                "missing_required_tools": self.missing_required_tools,
                "required_groups": self.required_groups,
                "missing_required_groups": self.missing_required_groups,
                "satisfied": self.is_satisfied(),
            },
            "policy": {
                "allowed_groups": self.allowed_groups,
                "read_only_only": self.read_only_only,
                "include_unregistered": self.include_unregistered,
                "enabled_feature_flags": self.enabled_feature_flags,
            },
        })
    }
}

/// Example request/response pair attached to a typed catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCatalogExample {
    title: String,
    request: Value,
    response: Option<Value>,
}

impl ToolCatalogExample {
    /// Create an example with a human-readable title and request payload.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when `title` is blank.
    pub fn new(title: impl AsRef<str>, request: Value) -> Result<Self, ToolInventoryError> {
        Ok(Self {
            title: normalize_non_empty("tool example title", title.as_ref())?,
            request,
            response: None,
        })
    }

    /// Attach the expected response payload for this example.
    #[must_use]
    pub fn with_response(mut self, response: Value) -> Self {
        self.response = Some(response);
        self
    }

    /// Human-readable example title.
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    /// Example request payload.
    pub fn request(&self) -> &Value {
        &self.request
    }

    /// Optional example response payload.
    pub fn response(&self) -> Option<&Value> {
        self.response.as_ref()
    }
}

/// Typed declaration for one MCP tool catalog entry.
///
/// The entry keeps one source of truth for inventory metadata, schemas, examples,
/// tags, and the server-local handler symbol while leaving actual dispatch to
/// the owning server framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCatalogEntry {
    capability: ToolCapability,
    input_schema: Option<Value>,
    output_schema: Option<Value>,
    examples: Vec<ToolCatalogExample>,
    handler: Option<String>,
    tags: Vec<String>,
}

impl ToolCatalogEntry {
    /// Create a catalog entry for a tool name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            capability: ToolCapability::new(name),
            input_schema: None,
            output_schema: None,
            examples: Vec::new(),
            handler: None,
            tags: Vec::new(),
        }
    }

    /// Attach a logical group label.
    #[must_use]
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.capability = self.capability.with_group(group);
        self
    }

    /// Mark whether the tool is read-only.
    #[must_use]
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.capability = self.capability.with_read_only(read_only);
        self
    }

    /// Attach an optional feature flag gate.
    #[must_use]
    pub fn with_feature_flag(mut self, feature_flag: impl Into<String>) -> Self {
        self.capability = self.capability.with_feature_flag(feature_flag);
        self
    }

    /// Gate this entry behind the standard operator profile feature flag.
    #[must_use]
    pub fn with_operator_profile_gate(self) -> Self {
        Self {
            capability: self.capability.with_operator_profile_gate(),
            ..self
        }
    }

    /// Configure operation-aware exposure.
    #[must_use]
    pub fn with_exposure(mut self, exposure: ToolExposure) -> Self {
        self.capability = self.capability.with_exposure(exposure);
        self
    }

    /// Attach metadata used by deferred-loading/tool-search clients.
    #[must_use]
    pub fn with_discovery(mut self, discovery: ToolDiscoveryMetadata) -> Self {
        self.capability = self.capability.with_discovery(discovery);
        self
    }

    /// Attach risk posture metadata for guarded preview/apply or admin tools.
    #[must_use]
    pub fn with_risk_posture(mut self, risk_posture: GuardedActionPosture) -> Self {
        self.capability = self.capability.with_risk_posture(risk_posture);
        self
    }

    /// Attach the JSON input schema emitted for this tool.
    #[must_use]
    pub fn with_input_schema(mut self, schema: Value) -> Self {
        self.input_schema = Some(schema);
        self
    }

    /// Attach the JSON output schema emitted for this tool.
    #[must_use]
    pub fn with_output_schema(mut self, schema: Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Attach a server-local handler symbol for docs and generated tests.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when `handler` is blank.
    pub fn with_handler(mut self, handler: impl AsRef<str>) -> Result<Self, ToolInventoryError> {
        self.handler = Some(normalize_non_empty("tool handler", handler.as_ref())?);
        Ok(self)
    }

    /// Attach tags used by generated docs and recipe matching.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when any tag is blank.
    pub fn with_tags<I, S>(mut self, tags: I) -> Result<Self, ToolInventoryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.tags = normalize_non_empty_list("tool tag", tags)?;
        Ok(self)
    }

    /// Attach a request/response example for docs and generated tests.
    #[must_use]
    pub fn with_example(mut self, example: ToolCatalogExample) -> Self {
        self.examples.push(example);
        self
    }

    /// Return the inventory capability owned by this entry.
    pub fn capability(&self) -> &ToolCapability {
        &self.capability
    }

    /// Stable tool name.
    pub fn name(&self) -> &str {
        self.capability.name()
    }

    /// Optional JSON input schema.
    pub fn input_schema(&self) -> Option<&Value> {
        self.input_schema.as_ref()
    }

    /// Optional JSON output schema.
    pub fn output_schema(&self) -> Option<&Value> {
        self.output_schema.as_ref()
    }

    /// Catalog examples in declaration order.
    pub fn examples(&self) -> &[ToolCatalogExample] {
        self.examples.as_slice()
    }

    /// Optional server-local handler symbol.
    pub fn handler(&self) -> Option<&str> {
        self.handler.as_deref()
    }

    /// Normalized tags used by generated docs and recipe matching.
    pub fn tags(&self) -> &[String] {
        self.tags.as_slice()
    }
}

/// Typed catalog declaration that drives inventory, schemas, search, and profiles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolCatalog {
    entries: Vec<ToolCatalogEntry>,
    profiles: Vec<ToolCatalogProfile>,
}

impl ToolCatalog {
    /// Create an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a catalog from entry declarations.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when an entry is invalid or duplicated.
    pub fn from_entries<I>(entries: I) -> Result<Self, ToolInventoryError>
    where
        I: IntoIterator<Item = ToolCatalogEntry>,
    {
        let mut catalog = Self::new();
        for entry in entries {
            catalog.register(entry)?;
        }
        Ok(catalog)
    }

    /// Register a single catalog entry.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when the entry is invalid or duplicated.
    pub fn register(&mut self, entry: ToolCatalogEntry) -> Result<(), ToolInventoryError> {
        let ToolCatalogEntry {
            capability,
            input_schema,
            output_schema,
            examples,
            handler,
            tags,
        } = entry;

        let name = normalize_non_empty("tool name", capability.name())?;
        if self.entries.iter().any(|entry| entry.name() == name) {
            return Err(ToolInventoryError::duplicate_name(name));
        }

        let group = match capability.group {
            Some(raw_group) => Some(normalize_non_empty("tool group", raw_group.as_str())?),
            None => None,
        };
        let feature_flag = match capability.feature_flag {
            Some(raw_flag) => Some(normalize_non_empty("feature flag", raw_flag.as_str())?),
            None => None,
        };
        let handler = match handler {
            Some(raw_handler) => Some(normalize_non_empty("tool handler", raw_handler.as_str())?),
            None => None,
        };
        let tags = normalize_non_empty_list("tool tag", tags)?;

        self.entries.push(ToolCatalogEntry {
            capability: ToolCapability {
                name,
                group,
                read_only: capability.read_only,
                feature_flag,
                exposure: capability.exposure,
                discovery: capability.discovery,
                risk_posture: capability.risk_posture,
            },
            input_schema,
            output_schema,
            examples,
            handler,
            tags,
        });
        self.entries
            .sort_by(|left, right| left.capability.name.cmp(&right.capability.name));
        Ok(())
    }

    /// Return a copy of this catalog with another entry registered.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when the entry is invalid or duplicated.
    pub fn with_entry(mut self, entry: ToolCatalogEntry) -> Result<Self, ToolInventoryError> {
        self.register(entry)?;
        Ok(self)
    }

    /// Register a named profile for this catalog.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when a profile with the same key exists.
    pub fn register_profile(
        &mut self,
        profile: ToolCatalogProfile,
    ) -> Result<(), ToolInventoryError> {
        if self
            .profiles
            .iter()
            .any(|existing| existing.key == profile.key)
        {
            return Err(ToolInventoryError::duplicate_profile(profile.key));
        }
        self.profiles.push(profile);
        self.profiles
            .sort_by(|left, right| left.key.cmp(&right.key));
        Ok(())
    }

    /// Return a copy of this catalog with another profile registered.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when a profile with the same key exists.
    pub fn with_profile(mut self, profile: ToolCatalogProfile) -> Result<Self, ToolInventoryError> {
        self.register_profile(profile)?;
        Ok(self)
    }

    /// Register the standard read-only and operator profiles for generated servers.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when group names are blank or the standard
    /// profiles are already registered.
    pub fn register_standard_profiles<I, S>(
        &mut self,
        read_only_groups: I,
    ) -> Result<(), ToolInventoryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let read_only_groups =
            normalize_non_empty_list("read-only profile group", read_only_groups)?;
        let mut read_only_profile = ToolCatalogProfile::read_only_default();
        if !read_only_groups.is_empty() {
            read_only_profile = read_only_profile
                .with_policy(
                    ToolInventoryPolicy::strict_read_only()
                        .with_allowed_groups(read_only_groups.clone()),
                )
                .with_required_groups(read_only_groups)?;
        }

        self.register_profile(read_only_profile)?;
        self.register_profile(ToolCatalogProfile::operator_default())?;
        Ok(())
    }

    /// Return a copy of this catalog with standard generated profiles registered.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when group names are blank or the standard
    /// profiles are already registered.
    pub fn with_standard_profiles<I, S>(
        mut self,
        read_only_groups: I,
    ) -> Result<Self, ToolInventoryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.register_standard_profiles(read_only_groups)?;
        Ok(self)
    }

    /// Return all entries in stable name order.
    pub fn entries(&self) -> &[ToolCatalogEntry] {
        self.entries.as_slice()
    }

    /// Return all profiles in stable key order.
    pub fn profiles(&self) -> &[ToolCatalogProfile] {
        self.profiles.as_slice()
    }

    /// Return a named catalog profile.
    pub fn profile(&self, key: &str) -> Option<&ToolCatalogProfile> {
        let key = key.trim();
        self.profiles.iter().find(|profile| profile.key() == key)
    }

    /// Return a named catalog profile or a stable error.
    ///
    /// # Errors
    /// Returns [`ToolInventoryError`] when the profile is not registered or the
    /// requested key is blank.
    pub fn require_profile(&self, key: &str) -> Result<&ToolCatalogProfile, ToolInventoryError> {
        let key = normalize_non_empty("catalog profile key", key)?;
        self.profile(&key)
            .ok_or_else(|| ToolInventoryError::unknown_profile(key))
    }

    /// Return the standard generated read-only profile, when registered.
    pub fn read_only_profile(&self) -> Option<&ToolCatalogProfile> {
        self.profile(READ_ONLY_PROFILE_KEY)
    }

    /// Return the standard explicit operator profile, when registered.
    pub fn operator_profile(&self) -> Option<&ToolCatalogProfile> {
        self.profile(OPERATOR_PROFILE_KEY)
    }

    /// Return the catalog entry for a tool name.
    pub fn entry(&self, tool_name: &str) -> Option<&ToolCatalogEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name() == tool_name.trim())
    }

    /// Build the inventory represented by this catalog.
    pub fn inventory(&self) -> ToolInventory {
        let entries = self
            .entries
            .iter()
            .map(|entry| (entry.name().to_string(), entry.capability.clone()))
            .collect();
        ToolInventory { entries }
    }

    /// Build a schema object keyed by tool name.
    pub fn schemas_by_tool(&self) -> Value {
        let mut schemas = Map::new();
        for entry in &self.entries {
            let mut schema = Map::new();
            if let Some(input_schema) = &entry.input_schema {
                schema.insert("input".to_string(), input_schema.clone());
            }
            if let Some(output_schema) = &entry.output_schema {
                schema.insert("output".to_string(), output_schema.clone());
            }
            if !schema.is_empty() {
                schemas.insert(entry.name().to_string(), Value::Object(schema));
            }
        }
        Value::Object(schemas)
    }

    /// Search catalog inventory and return the standard tool-search envelope.
    pub fn search_response(
        &self,
        filter: &ToolSearchFilter,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
    ) -> ToolSearchResponse {
        let results = self.inventory().search(filter, operation, policy);
        ToolSearchResponse::find_tools(
            filter.query.clone(),
            filter.group.clone(),
            filter.read_only,
            results,
        )
        .with_schemas(Some(self.schemas_by_tool()))
    }

    /// Search catalog inventory through a named catalog profile.
    pub fn search_response_for_profile(
        &self,
        filter: &ToolSearchFilter,
        operation: ToolOperation,
        profile: &ToolCatalogProfile,
    ) -> ToolSearchResponse {
        self.search_response(filter, operation, profile.policy())
    }

    /// Build profile contracts for every registered profile.
    pub fn profile_contracts(&self, operation: ToolOperation) -> Vec<ToolCatalogContract> {
        let inventory = self.inventory();
        self.profiles
            .iter()
            .map(|profile| inventory.catalog_contract(profile, operation))
            .collect()
    }

    /// Serialize the catalog into a stable public artifact.
    pub fn to_value(&self) -> Value {
        json!({
            "schema": "mcp_tool_catalog",
            "version": 1,
            "tools": self.entries.iter().map(catalog_entry_value).collect::<Vec<_>>(),
            "profiles": self.profiles.iter().map(profile_value).collect::<Vec<_>>(),
            "schemas": self.schemas_by_tool(),
        })
    }
}

/// Inventory of registered tool capabilities.
#[derive(Debug, Clone, Default)]
pub struct ToolInventory {
    entries: HashMap<String, ToolCapability>,
}

impl ToolInventory {
    /// Create an empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an inventory from capability registrations.
    pub fn from_capabilities<I>(capabilities: I) -> Result<Self, ToolInventoryError>
    where
        I: IntoIterator<Item = ToolCapability>,
    {
        let mut inventory = Self::new();
        for capability in capabilities {
            inventory.register(capability)?;
        }
        Ok(inventory)
    }

    /// Register a single capability.
    pub fn register(&mut self, capability: ToolCapability) -> Result<(), ToolInventoryError> {
        let name = normalize_non_empty("tool name", capability.name())?;
        if self.entries.contains_key(&name) {
            return Err(ToolInventoryError::duplicate_name(name));
        }

        let group = match capability.group {
            Some(raw_group) => Some(normalize_non_empty("tool group", raw_group.as_str())?),
            None => None,
        };
        let feature_flag = match capability.feature_flag {
            Some(raw_flag) => Some(normalize_non_empty("feature flag", raw_flag.as_str())?),
            None => None,
        };

        self.entries.insert(
            name.clone(),
            ToolCapability {
                name,
                group,
                read_only: capability.read_only,
                feature_flag,
                exposure: capability.exposure,
                discovery: capability.discovery,
                risk_posture: capability.risk_posture,
            },
        );
        Ok(())
    }

    /// Return the registered capability for a tool name.
    pub fn capability(&self, tool_name: &str) -> Option<&ToolCapability> {
        self.entries.get(tool_name.trim())
    }

    /// Return all registered capabilities in stable name order.
    pub fn capabilities(&self) -> Vec<&ToolCapability> {
        let mut entries = self.entries.values().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        entries
    }

    /// Check whether a tool is allowed for an operation under a policy.
    pub fn is_allowed(
        &self,
        tool_name: &str,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
    ) -> bool {
        self.decision(tool_name, operation, policy).allowed()
    }

    /// Explain whether a tool is allowed for an operation under a policy.
    pub fn decision(
        &self,
        tool_name: &str,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
    ) -> ToolInventoryDecision {
        self.decision_inner(tool_name, operation, policy, None)
    }

    /// Explain whether a tool is allowed for an operation through a named profile.
    pub fn decision_for_profile(
        &self,
        tool_name: &str,
        operation: ToolOperation,
        profile: &ToolCatalogProfile,
    ) -> ToolInventoryDecision {
        self.decision_inner(
            tool_name,
            operation,
            profile.policy(),
            Some(profile.key().to_string()),
        )
    }

    fn decision_inner(
        &self,
        tool_name: &str,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
        profile_key: Option<String>,
    ) -> ToolInventoryDecision {
        let trimmed = tool_name.trim().to_string();
        if trimmed.is_empty() {
            return ToolInventoryDecision::denied(
                trimmed,
                operation,
                profile_key,
                ToolInventoryDenialReason::BlankToolName,
            );
        }
        match self.entries.get(&trimmed) {
            Some(capability) => match policy.denial_reason(capability, operation) {
                Some(reason) => {
                    ToolInventoryDecision::denied(trimmed, operation, profile_key, reason)
                }
                None => ToolInventoryDecision::permit(trimmed, operation, profile_key),
            },
            None if policy.include_unregistered => {
                ToolInventoryDecision::permit(trimmed, operation, profile_key)
            }
            None => ToolInventoryDecision::denied(
                trimmed,
                operation,
                profile_key,
                ToolInventoryDenialReason::UnregisteredTool,
            ),
        }
    }

    /// Filter a tool list by inventory policy using a name accessor.
    pub fn filter_tools<T, F>(
        &self,
        tools: Vec<T>,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
        tool_name: F,
    ) -> Vec<T>
    where
        F: Fn(&T) -> &str,
    {
        tools
            .into_iter()
            .filter(|tool| self.is_allowed(tool_name(tool), operation, policy))
            .collect()
    }

    /// Filter a tool list through a named catalog profile.
    pub fn filter_tools_for_profile<T, F>(
        &self,
        tools: Vec<T>,
        operation: ToolOperation,
        profile: &ToolCatalogProfile,
        tool_name: F,
    ) -> Vec<T>
    where
        F: Fn(&T) -> &str,
    {
        self.filter_tools(tools, operation, profile.policy(), tool_name)
    }

    /// Build a probe-readable contract for a named catalog profile.
    pub fn catalog_contract(
        &self,
        profile: &ToolCatalogProfile,
        operation: ToolOperation,
    ) -> ToolCatalogContract {
        let visible = self
            .capabilities()
            .into_iter()
            .filter(|capability| profile.policy.allows_capability(capability, operation))
            .collect::<Vec<_>>();

        let mut tool_names = visible
            .iter()
            .map(|capability| capability.name.clone())
            .collect::<Vec<_>>();
        tool_names.sort();

        let mut groups = visible
            .iter()
            .filter_map(|capability| capability.group.clone())
            .collect::<Vec<_>>();
        groups.sort();
        groups.dedup();

        let missing_required_tools = profile
            .required_tools
            .iter()
            .filter(|tool| tool_names.binary_search(tool).is_err())
            .cloned()
            .collect::<Vec<_>>();
        let missing_required_groups = profile
            .required_groups
            .iter()
            .filter(|group| groups.binary_search(group).is_err())
            .cloned()
            .collect::<Vec<_>>();

        ToolCatalogContract {
            profile_key: profile.key.clone(),
            title: profile.title.clone(),
            description: profile.description.clone(),
            instructions: profile.instructions.clone(),
            operation,
            tool_names,
            groups,
            required_tools: profile.required_tools.clone(),
            missing_required_tools,
            required_groups: profile.required_groups.clone(),
            missing_required_groups,
            allowed_groups: sorted_optional_set(&profile.policy.allowed_groups),
            read_only_only: profile.policy.read_only_only,
            include_unregistered: profile.policy.include_unregistered,
            enabled_feature_flags: sorted_set(&profile.policy.enabled_feature_flags),
        }
    }

    /// Search registered tool metadata under a policy.
    pub fn search(
        &self,
        filter: &ToolSearchFilter,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
    ) -> Vec<ToolSearchResult> {
        let query_terms = filter
            .query
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .filter(|term| !term.is_empty())
            .collect::<Vec<_>>();
        let group = filter
            .group
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        let mut results = self
            .capabilities()
            .into_iter()
            .filter(|capability| policy.allows_capability(capability, operation))
            .filter(|capability| {
                group.is_none_or(|group| capability.group.as_deref() == Some(group))
            })
            .filter(|capability| {
                filter
                    .read_only
                    .is_none_or(|read_only| capability.read_only == read_only)
            })
            .filter(|capability| capability.matches_query(&query_terms))
            .map(|capability| ToolSearchResult {
                name: capability.name.clone(),
                group: capability.group.clone(),
                read_only: capability.read_only,
                description: capability
                    .discovery
                    .as_ref()
                    .map(|discovery| discovery.description.clone()),
                keywords: capability
                    .discovery
                    .as_ref()
                    .map(|discovery| discovery.keywords.clone())
                    .unwrap_or_default(),
                risk_posture: capability.risk_posture,
            })
            .collect::<Vec<_>>();

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        results
    }
}

impl ToolCapability {
    fn matches_query(&self, terms: &[String]) -> bool {
        if terms.is_empty() {
            return true;
        }
        let mut haystack = String::new();
        haystack.push_str(&self.name.to_ascii_lowercase());
        if let Some(group) = &self.group {
            haystack.push(' ');
            haystack.push_str(&group.to_ascii_lowercase());
        }
        if let Some(discovery) = &self.discovery {
            haystack.push(' ');
            haystack.push_str(&discovery.description.to_ascii_lowercase());
            for keyword in &discovery.keywords {
                haystack.push(' ');
                haystack.push_str(keyword);
            }
        }
        terms.iter().all(|term| haystack.contains(term))
    }
}

/// Stable error type for inventory registration failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInventoryError {
    pub code: String,
    pub message: String,
}

impl ToolInventoryError {
    fn duplicate_name(name: String) -> Self {
        Self {
            code: "TOOL_INVENTORY_DUPLICATE_NAME".to_string(),
            message: format!("tool inventory contains duplicate registration for '{name}'"),
        }
    }

    fn duplicate_profile(key: String) -> Self {
        Self {
            code: "TOOL_CATALOG_DUPLICATE_PROFILE".to_string(),
            message: format!("tool catalog contains duplicate profile '{key}'"),
        }
    }

    fn unknown_profile(key: String) -> Self {
        Self {
            code: "TOOL_CATALOG_UNKNOWN_PROFILE".to_string(),
            message: format!("tool catalog does not contain profile '{key}'"),
        }
    }

    fn invalid_value(field: &str, value: &str) -> Self {
        Self {
            code: "TOOL_INVENTORY_INVALID_VALUE".to_string(),
            message: format!("{field} must not be empty; got '{value}'"),
        }
    }
}

impl Display for ToolInventoryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ToolInventoryError {}

fn normalize_non_empty(field: &str, value: &str) -> Result<String, ToolInventoryError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ToolInventoryError::invalid_value(field, value));
    }
    Ok(trimmed.to_string())
}

fn normalize_non_empty_list<I, S>(field: &str, values: I) -> Result<Vec<String>, ToolInventoryError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = Vec::new();
    for value in values {
        normalized.push(normalize_non_empty(field, value.as_ref())?);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn sorted_set(values: &HashSet<String>) -> Vec<String> {
    let mut values = values.iter().cloned().collect::<Vec<_>>();
    values.sort();
    values
}

fn sorted_optional_set(values: &Option<HashSet<String>>) -> Option<Vec<String>> {
    values.as_ref().map(sorted_set)
}

fn operation_label(operation: ToolOperation) -> &'static str {
    match operation {
        ToolOperation::List => "list",
        ToolOperation::Call => "call",
    }
}

fn exposure_label(exposure: ToolExposure) -> &'static str {
    match exposure {
        ToolExposure::All => "all",
        ToolExposure::ListOnly => "list_only",
        ToolExposure::CallOnly => "call_only",
        ToolExposure::Disabled => "disabled",
    }
}

fn catalog_entry_value(entry: &ToolCatalogEntry) -> Value {
    json!({
        "name": entry.name(),
        "group": entry.capability.group(),
        "read_only": entry.capability.read_only(),
        "feature_flag": entry.capability.feature_flag(),
        "exposure": exposure_label(entry.capability.exposure()),
        "discovery": entry.capability.discovery().map(discovery_value),
        "risk_posture": entry.capability.risk_posture(),
        "handler": entry.handler(),
        "tags": entry.tags(),
        "input_schema": entry.input_schema(),
        "output_schema": entry.output_schema(),
        "examples": entry.examples().iter().map(example_value).collect::<Vec<_>>(),
    })
}

fn discovery_value(discovery: &ToolDiscoveryMetadata) -> Value {
    json!({
        "description": discovery.description(),
        "keywords": discovery.keywords(),
    })
}

fn example_value(example: &ToolCatalogExample) -> Value {
    json!({
        "title": example.title(),
        "request": example.request(),
        "response": example.response(),
    })
}

fn profile_value(profile: &ToolCatalogProfile) -> Value {
    json!({
        "key": profile.key(),
        "title": profile.title(),
        "description": profile.description(),
        "instructions": profile.instructions(),
        "required_tools": profile.required_tools(),
        "required_groups": profile.required_groups(),
        "policy": {
            "allowed_groups": sorted_optional_set(&profile.policy.allowed_groups),
            "read_only_only": profile.policy.read_only_only,
            "include_unregistered": profile.policy.include_unregistered,
            "enabled_feature_flags": sorted_set(&profile.policy.enabled_feature_flags),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ToolCapability, ToolCatalog, ToolCatalogEntry, ToolCatalogExample, ToolCatalogProfile,
        ToolExposure, ToolInventory, ToolInventoryDenialReason, ToolInventoryPolicy, ToolOperation,
        OPERATOR_PROFILE_KEY, READ_ONLY_PROFILE_KEY,
    };
    use super::{ToolDiscoveryMetadata, ToolSearchFilter, ToolSearchResponse};
    use crate::guarded_action::{GuardedActionOperationClass, GuardedActionPosture};
    use serde_json::json;

    #[test]
    fn strict_policy_blocks_unregistered_tools() {
        let inventory = ToolInventory::new();
        let policy = ToolInventoryPolicy::strict();
        assert!(!inventory.is_allowed("unknown.tool", ToolOperation::List, &policy));
    }

    #[test]
    fn permissive_policy_allows_unregistered_tools() {
        let inventory = ToolInventory::new();
        let policy = ToolInventoryPolicy::default();
        assert!(inventory.is_allowed("unknown.tool", ToolOperation::Call, &policy));
    }

    #[test]
    fn registration_rejects_duplicate_names() {
        let result = ToolInventory::from_capabilities([
            ToolCapability::new("alpha.tool"),
            ToolCapability::new("alpha.tool"),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn read_only_filter_hides_writable_tools() {
        let result = ToolInventory::from_capabilities([
            ToolCapability::new("read.tool")
                .with_group("search")
                .with_read_only(true),
            ToolCapability::new("write.tool")
                .with_group("search")
                .with_read_only(false),
        ]);
        assert!(result.is_ok());
        let inventory = result.unwrap_or_default();
        let policy = ToolInventoryPolicy::strict_read_only();
        assert!(inventory.is_allowed("read.tool", ToolOperation::List, &policy));
        assert!(!inventory.is_allowed("write.tool", ToolOperation::List, &policy));
        assert!(!inventory.is_allowed("unknown.tool", ToolOperation::List, &policy));
    }

    #[test]
    fn search_matches_discovery_metadata_and_policy() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("cache.purge")
                .with_group("cache")
                .with_read_only(false)
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Purge cache entries",
                    ["invalidate", "clear"],
                )),
            ToolCapability::new("cache.list")
                .with_group("cache")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new("List cache settings", ["read"])),
            ToolCapability::new("dns.list")
                .with_group("dns")
                .with_read_only(true),
        ])
        .expect("inventory");

        let results = inventory.search(
            &ToolSearchFilter {
                query: Some("invalidate".to_string()),
                group: Some("cache".to_string()),
                read_only: Some(false),
                limit: Some(10),
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "cache.purge");
        assert_eq!(results[0].keywords, vec!["clear", "invalidate"]);
    }

    #[test]
    fn group_and_feature_flag_filters_are_applied() {
        let result = ToolInventory::from_capabilities([
            ToolCapability::new("ops.list")
                .with_group("ops")
                .with_read_only(true),
            ToolCapability::new("codebase.search")
                .with_group("codebase")
                .with_read_only(true)
                .with_feature_flag("feature.codebase"),
        ]);
        assert!(result.is_ok());
        let inventory = result.unwrap_or_default();
        let policy = ToolInventoryPolicy::strict()
            .with_allowed_groups(["codebase"])
            .with_feature_flags(["feature.codebase"]);
        assert!(inventory.is_allowed("codebase.search", ToolOperation::List, &policy));
        assert!(!inventory.is_allowed("ops.list", ToolOperation::List, &policy));
    }

    #[test]
    fn method_aware_exposure_can_hide_calls() {
        let result = ToolInventory::from_capabilities([ToolCapability::new("list.only")
            .with_group("debug")
            .with_exposure(ToolExposure::ListOnly)]);
        assert!(result.is_ok());
        let inventory = result.unwrap_or_default();
        let policy = ToolInventoryPolicy::strict();
        assert!(inventory.is_allowed("list.only", ToolOperation::List, &policy));
        assert!(!inventory.is_allowed("list.only", ToolOperation::Call, &policy));
    }

    #[test]
    fn search_response_builds_openai_tool_search_payload() {
        let response = ToolSearchResponse::find_tools(
            Some("cache".to_string()),
            Some("cache".to_string()),
            Some(true),
            vec![super::ToolSearchResult {
                name: "cache.list".to_string(),
                group: Some("cache".to_string()),
                read_only: true,
                description: Some("List cache settings".to_string()),
                keywords: vec!["cache".to_string(), "read".to_string()],
                risk_posture: None,
            }],
        )
        .with_schemas(Some(json!({"cache.list": {"name": "cache.list"}})))
        .with_metadata_label("unit-test");

        let value = response.to_value();
        assert_eq!(value["operation"], json!("find_tools"));
        assert_eq!(value["openai_allowed_tools"], json!(["cache.list"]));
        assert_eq!(
            value["openai_deferred_loading"]["tool_search"]["type"],
            json!("tool_search")
        );
        assert_eq!(
            value["openai_deferred_loading"]["recommended_model"],
            json!("gpt-5.5")
        );
        assert_eq!(value["schemas"]["cache.list"]["name"], json!("cache.list"));
    }

    #[test]
    fn search_response_includes_companion_tools_and_extra_results() {
        let response = ToolSearchResponse::find_tools(
            Some("queue metrics".to_string()),
            None,
            None,
            vec![super::ToolSearchResult {
                name: "queues.get".to_string(),
                group: Some("queues".to_string()),
                read_only: true,
                description: Some("Get queue details".to_string()),
                keywords: vec!["queue".to_string()],
                risk_posture: None,
            }],
        )
        .into_openai_response()
        .with_companion_allowed_tools([
            "api_read",
            "api_prepare_call",
            "api_find_operations",
            "api_prepare_call",
        ])
        .with_extra_results([json!({
            "type": "api_operation",
            "name": "api_read",
            "read_only": true,
        })]);

        let value = response.to_value();

        assert_eq!(
            value["openai_allowed_tools"],
            json!([
                "api_find_operations",
                "api_prepare_call",
                "api_read",
                "queues.get"
            ])
        );
        assert_eq!(value["results"][1]["type"], json!("api_operation"));
        assert_eq!(
            value["openai_deferred_loading"]["find_tools_scope"],
            value["openai_deferred_loading"]["local_search_scope"]
        );
    }

    #[test]
    fn catalog_profile_filters_tools_and_emits_satisfied_contract() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("items.search")
                .with_group("items")
                .with_read_only(true),
            ToolCapability::new("items.update")
                .with_group("items")
                .with_read_only(false),
            ToolCapability::new("graph.neighbors")
                .with_group("graph")
                .with_read_only(true),
            ToolCapability::new("admin.rotate_key")
                .with_group("admin")
                .with_read_only(false),
        ])
        .expect("inventory");
        let profile = ToolCatalogProfile::new(
            "read-core",
            "Read Core",
            "Read-only item and graph tools for default discovery.",
        )
        .expect("profile")
        .with_instructions("Use mutations only in an explicit write profile.")
        .with_policy(
            ToolInventoryPolicy::strict_read_only().with_allowed_groups(["items", "graph"]),
        )
        .with_required_tools(["items.search", "graph.neighbors"])
        .expect("required tools")
        .with_required_groups(["items", "graph"])
        .expect("required groups");

        let filtered = inventory.filter_tools_for_profile(
            vec![
                "admin.rotate_key",
                "graph.neighbors",
                "items.search",
                "items.update",
            ],
            ToolOperation::List,
            &profile,
            |tool| tool,
        );
        assert_eq!(filtered, vec!["graph.neighbors", "items.search"]);

        let contract = inventory.catalog_contract(&profile, ToolOperation::List);
        assert!(contract.is_satisfied());
        assert_eq!(
            contract.to_value(),
            json!({
                "schema": "mcp_tool_catalog_profile_contract",
                "version": 1,
                "profile": {
                    "key": "read-core",
                    "title": "Read Core",
                    "description": "Read-only item and graph tools for default discovery.",
                    "instructions": "Use mutations only in an explicit write profile.",
                },
                "operation": "list",
                "tool_count": 2,
                "tool_names": ["graph.neighbors", "items.search"],
                "groups": ["graph", "items"],
                "requirements": {
                    "required_tools": ["graph.neighbors", "items.search"],
                    "missing_required_tools": [],
                    "required_groups": ["graph", "items"],
                    "missing_required_groups": [],
                    "satisfied": true,
                },
                "policy": {
                    "allowed_groups": ["graph", "items"],
                    "read_only_only": true,
                    "include_unregistered": false,
                    "enabled_feature_flags": [],
                },
            })
        );
    }

    #[test]
    fn catalog_profile_contract_reports_missing_requirements() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("items.search")
            .with_group("items")
            .with_read_only(true)])
        .expect("inventory");
        let profile = ToolCatalogProfile::new(
            "graph",
            "Graph",
            "Graph navigation profile with required relationship tools.",
        )
        .expect("profile")
        .with_policy(ToolInventoryPolicy::strict_read_only().with_allowed_groups(["graph"]))
        .with_required_tools(["graph.neighbors"])
        .expect("required tools")
        .with_required_groups(["graph"])
        .expect("required groups");

        let contract = inventory.catalog_contract(&profile, ToolOperation::List);

        assert!(!contract.is_satisfied());
        assert_eq!(contract.tool_names, Vec::<String>::new());
        assert_eq!(contract.missing_required_tools, vec!["graph.neighbors"]);
        assert_eq!(contract.missing_required_groups, vec!["graph"]);
        assert_eq!(
            contract.to_value()["requirements"]["satisfied"],
            json!(false)
        );
    }

    #[test]
    fn typed_catalog_drives_inventory_search_schemas_and_profiles() {
        let read_entry = ToolCatalogEntry::new("items.search")
            .with_group("items")
            .with_risk_posture(GuardedActionPosture::read_only())
            .with_discovery(ToolDiscoveryMetadata::new(
                "Search item records.",
                ["items", "search", "read"],
            ))
            .with_input_schema(json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                }
            }))
            .with_output_schema(json!({
                "type": "object",
                "properties": {
                    "items": {"type": "array"}
                }
            }))
            .with_handler("ItemsServer::search")
            .expect("handler")
            .with_tags(["default", "generated"])
            .expect("tags")
            .with_example(
                ToolCatalogExample::new("search by owner", json!({"query": "owner:team"}))
                    .expect("example")
                    .with_response(json!({"items": []})),
            );
        let write_entry = ToolCatalogEntry::new("items.update")
            .with_group("items")
            .with_risk_posture(GuardedActionPosture::guarded_apply())
            .with_discovery(ToolDiscoveryMetadata::new(
                "Update an item record.",
                ["items", "update", "write"],
            ));
        let profile = ToolCatalogProfile::new(
            "read-default",
            "Read Default",
            "Default read-only generated profile.",
        )
        .expect("profile")
        .with_policy(ToolInventoryPolicy::strict_read_only().with_allowed_groups(["items"]))
        .with_required_tools(["items.search"])
        .expect("required tools");
        let catalog = ToolCatalog::from_entries([write_entry, read_entry])
            .expect("catalog")
            .with_profile(profile)
            .expect("profile registration");

        let inventory = catalog.inventory();
        assert!(inventory.is_allowed(
            "items.search",
            ToolOperation::Call,
            &ToolInventoryPolicy::strict_read_only()
        ));
        assert!(!inventory.is_allowed(
            "items.update",
            ToolOperation::Call,
            &ToolInventoryPolicy::strict_read_only()
        ));

        let response = catalog
            .search_response_for_profile(
                &ToolSearchFilter {
                    query: Some("search".to_string()),
                    group: Some("items".to_string()),
                    read_only: Some(true),
                    limit: None,
                },
                ToolOperation::List,
                &catalog.profiles()[0],
            )
            .to_value();
        assert_eq!(response["openai_allowed_tools"], json!(["items.search"]));
        assert_eq!(
            response["schemas"]["items.search"]["input"]["properties"]["query"]["type"],
            json!("string")
        );

        let contracts = catalog.profile_contracts(ToolOperation::List);
        assert_eq!(contracts.len(), 1);
        assert!(contracts[0].is_satisfied());
        assert_eq!(contracts[0].tool_names, vec!["items.search"]);

        let snapshot = catalog.to_value();
        assert_eq!(snapshot["schema"], json!("mcp_tool_catalog"));
        assert_eq!(snapshot["tools"][0]["name"], json!("items.search"));
        assert_eq!(
            snapshot["tools"][0]["examples"][0]["response"]["items"],
            json!([])
        );
        assert_eq!(snapshot["tools"][1]["name"], json!("items.update"));
        assert_eq!(snapshot["profiles"][0]["key"], json!("read-default"));
    }

    #[test]
    fn standard_profiles_hide_operator_tools_by_default() {
        let catalog = ToolCatalog::from_entries([
            ToolCatalogEntry::new("items.search")
                .with_group("read")
                .with_risk_posture(GuardedActionPosture::read_only()),
            ToolCatalogEntry::new("items.update")
                .with_group("operator")
                .with_operator_profile_gate()
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
        ])
        .expect("catalog")
        .with_standard_profiles(["read"])
        .expect("standard profiles");
        let inventory = catalog.inventory();
        let read_only_profile = catalog
            .read_only_profile()
            .expect("standard read-only profile");
        let operator_profile = catalog
            .operator_profile()
            .expect("standard operator profile");

        assert_eq!(read_only_profile.key(), READ_ONLY_PROFILE_KEY);
        assert_eq!(operator_profile.key(), OPERATOR_PROFILE_KEY);

        let read_tools = inventory.filter_tools_for_profile(
            vec!["items.search", "items.update"],
            ToolOperation::List,
            read_only_profile,
            |tool| tool,
        );
        assert_eq!(read_tools, vec!["items.search"]);

        let denied =
            inventory.decision_for_profile("items.update", ToolOperation::Call, read_only_profile);
        assert!(!denied.allowed());
        assert_eq!(
            denied.denial_reason,
            Some(ToolInventoryDenialReason::ReadOnlyProfile)
        );
        assert_eq!(
            denied.to_value()["denial"]["code"],
            json!("TOOL_DENIED_READ_ONLY_PROFILE")
        );

        assert!(inventory
            .decision_for_profile("items.update", ToolOperation::Call, operator_profile)
            .allowed());
        assert!(inventory
            .decision_for_profile("items.search", ToolOperation::List, operator_profile)
            .allowed());
    }

    #[test]
    fn strict_operator_policy_requires_the_operator_feature_flag() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("items.update")
            .with_group("operator")
            .with_operator_profile_gate()
            .with_risk_posture(GuardedActionPosture::guarded_apply())])
        .expect("inventory");

        let denied = inventory.decision(
            "items.update",
            ToolOperation::Call,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            denied.denial_reason,
            Some(ToolInventoryDenialReason::FeatureFlagDisabled)
        );

        let allowed = inventory.decision(
            "items.update",
            ToolOperation::Call,
            &ToolInventoryPolicy::strict_operator(),
        );
        assert!(allowed.allowed());
    }

    #[test]
    fn typed_catalog_rejects_duplicate_tools_profiles_and_blank_metadata() {
        let duplicate = ToolCatalog::from_entries([
            ToolCatalogEntry::new("items.search"),
            ToolCatalogEntry::new(" items.search "),
        ]);
        assert_eq!(
            duplicate.expect_err("duplicate tool").code,
            "TOOL_INVENTORY_DUPLICATE_NAME"
        );

        let blank_tag = ToolCatalogEntry::new("items.search").with_tags(["default", " "]);
        assert_eq!(
            blank_tag.expect_err("blank tag").code,
            "TOOL_INVENTORY_INVALID_VALUE"
        );

        let profile =
            ToolCatalogProfile::new("read-default", "Read", "Read tools").expect("profile");
        let profile_duplicate = ToolCatalog::new()
            .with_profile(profile.clone())
            .expect("first profile")
            .with_profile(profile);
        assert_eq!(
            profile_duplicate.expect_err("duplicate profile").code,
            "TOOL_CATALOG_DUPLICATE_PROFILE"
        );
    }

    #[test]
    fn risk_posture_metadata_flows_into_search_results() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("queue_control_preview")
                .with_group("admin")
                .with_risk_posture(GuardedActionPosture::preview()),
            ToolCapability::new("queue_control_apply")
                .with_group("admin")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
        ])
        .expect("inventory");

        let results = inventory.search(
            &ToolSearchFilter {
                query: Some("queue".to_string()),
                group: Some("admin".to_string()),
                read_only: None,
                limit: None,
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        let value = ToolSearchResponse::find_tools(None, None, None, results).to_value();
        assert_eq!(
            value["results"][0]["risk_posture"]["operation_class"],
            json!(GuardedActionOperationClass::GuardedApply.as_str())
        );
        assert_eq!(
            value["results"][0]["risk_posture"]["post_apply_readback_required"],
            json!(true)
        );
        assert_eq!(
            value["results"][1]["risk_posture"]["operation_class"],
            json!(GuardedActionOperationClass::Preview.as_str())
        );
    }

    #[test]
    fn risk_posture_aligns_the_read_only_flag_with_posture_semantics() {
        let mutating = ToolCapability::new("queue_control_apply")
            .with_read_only(true)
            .with_risk_posture(GuardedActionPosture::mutating());
        assert!(!mutating.read_only());

        let preview = ToolCapability::new("queue_control_preview")
            .with_read_only(true)
            .with_risk_posture(GuardedActionPosture::preview());
        assert!(!preview.read_only());

        let read_only = ToolCapability::new("queue_control_read")
            .with_read_only(false)
            .with_risk_posture(GuardedActionPosture::read_only());
        assert!(read_only.read_only());

        let proof = ToolCapability::new("send_wizard_readback")
            .with_read_only(false)
            .with_risk_posture(GuardedActionPosture::no_mutation_proof());
        assert!(proof.read_only());
    }
}

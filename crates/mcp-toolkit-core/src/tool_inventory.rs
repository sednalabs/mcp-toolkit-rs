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

use serde_json::{json, Value};

use crate::openai_tool_search::OpenAiDeferredLoadingMetadata;

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
        if !capability.exposure.allows(operation) {
            return false;
        }
        if self.read_only_only && !capability.read_only {
            return false;
        }
        if let Some(groups) = &self.allowed_groups {
            let Some(group) = capability.group.as_deref() else {
                return false;
            };
            if !groups.contains(group) {
                return false;
            }
        }
        if let Some(feature_flag) = capability.feature_flag.as_deref() {
            return self.enabled_feature_flags.contains(feature_flag);
        }
        true
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
        let trimmed = tool_name.trim();
        if trimmed.is_empty() {
            return false;
        }
        match self.entries.get(trimmed) {
            Some(capability) => policy.allows_capability(capability, operation),
            None => policy.include_unregistered,
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

#[cfg(test)]
mod tests {
    use super::{
        ToolCapability, ToolCatalogProfile, ToolExposure, ToolInventory, ToolInventoryPolicy,
        ToolOperation,
    };
    use super::{ToolDiscoveryMetadata, ToolSearchFilter, ToolSearchResponse};
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
}

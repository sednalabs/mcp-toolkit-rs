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
//! * MCP tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools

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

const RANKED_SEARCH_DEFAULT_LIMIT: usize = 20;
const RANKED_SEARCH_MAX_LIMIT: usize = 100;
const RANKED_SEARCH_MAX_QUERY_CHARS: usize = 1_024;
const RANKED_SEARCH_MAX_QUERY_TERMS: usize = 32;
const RANKED_SEARCH_MAX_EXCLUDED_TERMS: usize = 16;
const RANKED_SEARCH_MAX_IGNORED_TERMS: usize = 16;
const RANKED_SEARCH_MAX_GROUP_CHARS: usize = 128;
const RANKED_SEARCH_MAX_DESCRIPTION_CHARS: usize = 512;
const RANKED_SEARCH_MAX_KEYWORDS: usize = 32;
const RANKED_SEARCH_MAX_KEYWORD_CHARS: usize = 128;
const RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY: usize = 32;
const RANKED_SEARCH_MAX_ACTION_LEXEMES_TOTAL: usize = 256;
const RANKED_SEARCH_MAX_ACTION_LEXEME_CHARS: usize = 64;
const RANKED_SEARCH_COMPACT_MAX_BYTES: usize = 32 * 1_024;
const COMPACT_SEARCH_MAX_RESULTS: usize = 100;
const COMPACT_SEARCH_MAX_OPERATION_CHARS: usize = 64;
const COMPACT_SEARCH_MAX_TOOL_NAME_CHARS: usize = 256;
const COMPACT_SEARCH_MAX_SUMMARY_REASONS: usize = 16;
const COMPACT_SEARCH_MAX_SUMMARY_REASON_CHARS: usize = 64;
const COMPACT_OPENAI_MAX_COMPANION_TOOLS: usize = 100;
const COMPACT_OPENAI_MAX_EXTRA_RESULTS: usize = 32;
const COMPACT_OPENAI_MAX_EXTRA_RESULT_NODES: usize = 256;
const COMPACT_OPENAI_MAX_EXTRA_RESULT_TEXT_CHARS: usize = 4_096;

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
    action_lexemes: HashSet<String>,
    action_lexemes_truncated: bool,
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
            action_lexemes: HashSet::new(),
            action_lexemes_truncated: false,
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

    /// Add provider-specific canonical action roots used only for negative-intent matching.
    ///
    /// Exact matching remains available without this metadata. Register roots here when a
    /// provider uses action verbs outside the toolkit's conservative built-in vocabulary and
    /// expects inflected exclusions such as `without purging` to match `purge`.
    pub fn with_action_lexemes<I, S>(mut self, lexemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for (index, lexeme) in lexemes
            .into_iter()
            .take(RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY + 1)
            .enumerate()
        {
            if index == RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY {
                self.action_lexemes_truncated = true;
                break;
            }
            let (lexeme, truncated) =
                truncate_search_text(lexeme.as_ref(), RANKED_SEARCH_MAX_ACTION_LEXEME_CHARS);
            let lexeme = lexeme.trim().to_ascii_lowercase();
            if truncated
                || lexeme.is_empty()
                || !lexeme
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
            {
                self.action_lexemes_truncated = true;
                continue;
            }
            if self.action_lexemes.len() == RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY
                && !self.action_lexemes.contains(&lexeme)
            {
                self.action_lexemes_truncated = true;
                continue;
            }
            self.action_lexemes.insert(lexeme);
        }
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

/// Completeness metadata for one ranked inventory search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSearchMatchSummary {
    pub total_matches: usize,
    pub returned_count: usize,
    pub result_limit: usize,
    pub truncated: bool,
    pub truncation_reasons: Vec<String>,
    pub normalized_query_terms: Vec<String>,
    pub excluded_query_terms: Vec<String>,
    pub ignored_query_terms: Vec<String>,
}

impl ToolSearchMatchSummary {
    /// Serialize the match summary into its stable JSON shape.
    pub fn to_value(&self) -> Value {
        json!({
            "total_matches": self.total_matches,
            "returned_count": self.returned_count,
            "result_limit": self.result_limit,
            "truncated": self.truncated,
            "truncation_reasons": self.truncation_reasons,
            "normalized_query_terms": self.normalized_query_terms,
            "excluded_query_terms": self.excluded_query_terms,
            "ignored_query_terms": self.ignored_query_terms,
        })
    }
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

    /// Serialize a bounded selection response without schemas or hosted-client metadata.
    ///
    /// The response stays within 32 KiB and includes `compact_summary` when
    /// source fields or results must be reduced.
    pub fn to_compact_value(&self) -> Value {
        let mut projection = self.compact_projection();
        let mut diagnostics_compacted = false;
        loop {
            let value = with_compact_summary(
                projection.response.compact_value_from_bounded_fields(),
                &projection,
            );
            if serde_json::to_vec(&value)
                .is_ok_and(|bytes| bytes.len() <= RANKED_SEARCH_COMPACT_MAX_BYTES)
            {
                return value;
            }
            projection.truncated = true;
            push_unique_reason(&mut projection.truncation_reasons, "compact_response_bytes");
            if !diagnostics_compacted {
                projection.response.query = None;
                projection.response.group = None;
                diagnostics_compacted = true;
                continue;
            }
            if projection.response.results.pop().is_none() {
                return with_compact_summary(
                    projection.response.compact_value_from_bounded_fields(),
                    &projection,
                );
            }
        }
    }

    fn compact_projection(&self) -> CompactToolSearchProjection {
        let mut truncated = false;
        let (operation, operation_truncated) =
            truncate_search_text(&self.operation, COMPACT_SEARCH_MAX_OPERATION_CHARS);
        truncated |= operation_truncated;
        let query = bounded_optional_search_text(
            self.query.as_deref(),
            RANKED_SEARCH_MAX_QUERY_CHARS,
            &mut truncated,
        );
        let group = bounded_optional_search_text(
            self.group.as_deref(),
            RANKED_SEARCH_MAX_GROUP_CHARS,
            &mut truncated,
        );
        let mut result_metadata_truncated = false;
        let mut results = Vec::new();
        for result in self.results.iter().take(COMPACT_SEARCH_MAX_RESULTS) {
            match compact_search_result(result) {
                Some((result, result_truncated)) => {
                    result_metadata_truncated |= result_truncated;
                    results.push(result);
                }
                None => {
                    result_metadata_truncated = true;
                    break;
                }
            }
        }
        let result_limit_truncated = self.results.len() > COMPACT_SEARCH_MAX_RESULTS;
        let mut truncation_reasons = Vec::new();
        if truncated {
            push_unique_reason(&mut truncation_reasons, "input_metadata");
        }
        if result_metadata_truncated {
            push_unique_reason(&mut truncation_reasons, "result_metadata");
        }
        if result_limit_truncated {
            push_unique_reason(&mut truncation_reasons, "result_limit");
        }
        CompactToolSearchProjection {
            response: ToolSearchResponse {
                operation,
                query,
                group,
                read_only: self.read_only,
                results,
                schemas: None,
                metadata_label: None,
            },
            source_count: self.results.len(),
            truncated: truncated || result_metadata_truncated || result_limit_truncated,
            truncation_reasons,
        }
    }

    fn compact_value_from_bounded_fields(&self) -> Value {
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
        })
    }

    /// Wrap this response in an OpenAI-oriented builder with extra result support.
    pub fn into_openai_response(self) -> OpenAiToolSearchResponse {
        OpenAiToolSearchResponse::from_response(self)
    }
}

/// Ranked tool-search response with explicit completeness metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedToolSearchResponse {
    pub response: ToolSearchResponse,
    pub match_summary: ToolSearchMatchSummary,
}

impl RankedToolSearchResponse {
    /// Attach optional MCP tool schemas keyed by tool name.
    pub fn with_schemas(mut self, schemas: Option<Value>) -> Self {
        self.response = self.response.with_schemas(schemas);
        self
    }

    /// Attach a compatibility label for hosted-client metadata.
    pub fn with_metadata_label(mut self, label: impl Into<String>) -> Self {
        self.response = self.response.with_metadata_label(label);
        self
    }

    /// Serialize the ranked response with schemas and hosted-client metadata.
    pub fn to_value(&self) -> Value {
        with_match_summary(self.response.to_value(), &self.match_summary)
    }

    /// Serialize the ranked response within 32 KiB without schemas or hosted-client metadata.
    pub fn to_compact_value(&self) -> Value {
        let projection = self.response.compact_projection();
        let mut response = projection.response;
        let (mut summary, summary_truncated) = compact_match_summary(&self.match_summary);
        if projection.truncated || summary_truncated {
            summary.truncated = true;
            push_unique_reason(&mut summary.truncation_reasons, "compact_response_bytes");
        }
        summary.returned_count = response.results.len();
        let mut diagnostics_compacted = false;
        loop {
            let value = with_match_summary(response.compact_value_from_bounded_fields(), &summary);
            if serde_json::to_vec(&value)
                .is_ok_and(|bytes| bytes.len() <= RANKED_SEARCH_COMPACT_MAX_BYTES)
            {
                return value;
            }
            summary.truncated = true;
            push_unique_reason(&mut summary.truncation_reasons, "compact_response_bytes");
            if !diagnostics_compacted {
                response.query = None;
                response.group = None;
                summary.normalized_query_terms.clear();
                summary.excluded_query_terms.clear();
                summary.ignored_query_terms.clear();
                diagnostics_compacted = true;
                continue;
            }
            if response.results.pop().is_none() {
                summary.returned_count = 0;
                summary.truncation_reasons = vec!["compact_response_bytes".to_string()];
                return with_match_summary(response.compact_value_from_bounded_fields(), &summary);
            }
            summary.returned_count = response.results.len();
        }
    }

    /// Wrap this ranked response while preserving completeness metadata.
    pub fn into_openai_response(self) -> RankedOpenAiToolSearchResponse {
        RankedOpenAiToolSearchResponse {
            response: self.response.into_openai_response(),
            match_summary: self.match_summary,
        }
    }
}

fn with_match_summary(mut value: Value, summary: &ToolSearchMatchSummary) -> Value {
    if let Value::Object(object) = &mut value {
        object.insert("match_summary".to_string(), summary.to_value());
    }
    value
}

struct CompactToolSearchProjection {
    response: ToolSearchResponse,
    source_count: usize,
    truncated: bool,
    truncation_reasons: Vec<String>,
}

fn with_compact_summary(mut value: Value, projection: &CompactToolSearchProjection) -> Value {
    if let Value::Object(object) = &mut value {
        object.insert(
            "compact_summary".to_string(),
            json!({
                "source_count": projection.source_count,
                "returned_count": projection.response.results.len(),
                "truncated": projection.truncated,
                "truncation_reasons": projection.truncation_reasons,
            }),
        );
    }
    value
}

fn compact_search_result(result: &ToolSearchResult) -> Option<(ToolSearchResult, bool)> {
    let (name, name_truncated) =
        truncate_search_text(&result.name, COMPACT_SEARCH_MAX_TOOL_NAME_CHARS);
    if name.is_empty() || name_truncated {
        return None;
    }
    let mut truncated = false;
    let group = bounded_optional_search_text(
        result.group.as_deref(),
        RANKED_SEARCH_MAX_GROUP_CHARS,
        &mut truncated,
    );
    let description = result.description.as_deref().and_then(|description| {
        let (description, description_truncated) = truncate_search_text_at_token_boundary(
            description,
            RANKED_SEARCH_MAX_DESCRIPTION_CHARS,
        );
        truncated |= description_truncated;
        (!description.is_empty()).then_some(description)
    });
    truncated |= result.keywords.len() > RANKED_SEARCH_MAX_KEYWORDS;
    let mut keywords = Vec::new();
    for keyword in result.keywords.iter().take(RANKED_SEARCH_MAX_KEYWORDS) {
        let (keyword, keyword_truncated) =
            truncate_search_text_at_token_boundary(keyword, RANKED_SEARCH_MAX_KEYWORD_CHARS);
        truncated |= keyword_truncated;
        if !keyword.is_empty() && !keywords.contains(&keyword) {
            keywords.push(keyword);
        }
    }
    Some((
        ToolSearchResult {
            name,
            group,
            read_only: result.read_only,
            description,
            keywords,
            risk_posture: result.risk_posture,
        },
        truncated,
    ))
}

fn bounded_optional_search_text(
    value: Option<&str>,
    max_chars: usize,
    truncated: &mut bool,
) -> Option<String> {
    value.map(|value| {
        let (bounded, value_truncated) = truncate_search_text(value, max_chars);
        *truncated |= value_truncated;
        bounded
    })
}

fn compact_match_summary(summary: &ToolSearchMatchSummary) -> (ToolSearchMatchSummary, bool) {
    let (mut truncation_reasons, reasons_truncated) = bounded_search_string_list(
        &summary.truncation_reasons,
        COMPACT_SEARCH_MAX_SUMMARY_REASONS,
        COMPACT_SEARCH_MAX_SUMMARY_REASON_CHARS,
    );
    let (normalized_query_terms, normalized_truncated) = bounded_search_string_list(
        &summary.normalized_query_terms,
        RANKED_SEARCH_MAX_QUERY_TERMS,
        RANKED_SEARCH_MAX_KEYWORD_CHARS,
    );
    let (excluded_query_terms, excluded_truncated) = bounded_search_string_list(
        &summary.excluded_query_terms,
        RANKED_SEARCH_MAX_EXCLUDED_TERMS,
        RANKED_SEARCH_MAX_KEYWORD_CHARS,
    );
    let (ignored_query_terms, ignored_truncated) = bounded_search_string_list(
        &summary.ignored_query_terms,
        RANKED_SEARCH_MAX_IGNORED_TERMS,
        RANKED_SEARCH_MAX_KEYWORD_CHARS,
    );
    let compacted =
        reasons_truncated || normalized_truncated || excluded_truncated || ignored_truncated;
    if compacted {
        push_unique_reason(&mut truncation_reasons, "compact_response_bytes");
    }
    (
        ToolSearchMatchSummary {
            total_matches: summary.total_matches,
            returned_count: summary.returned_count,
            result_limit: summary.result_limit,
            truncated: summary.truncated || compacted,
            truncation_reasons,
            normalized_query_terms,
            excluded_query_terms,
            ignored_query_terms,
        },
        compacted,
    )
}

fn bounded_search_string_list(
    values: &[String],
    max_items: usize,
    max_chars: usize,
) -> (Vec<String>, bool) {
    let mut truncated = values.len() > max_items;
    let mut bounded = Vec::new();
    for value in values.iter().take(max_items) {
        let (value, value_truncated) = truncate_search_text(value, max_chars);
        truncated |= value_truncated;
        if !bounded.contains(&value) {
            bounded.push(value);
        }
    }
    (bounded, truncated)
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

    /// Serialize a bounded OpenAI selection response without schemas or hosted-client metadata.
    ///
    /// Inventory and extra results retain source-prefix order when the 32 KiB response budget
    /// requires truncation; companion names retain the full response's deterministic sort order.
    pub fn to_compact_value(&self) -> Value {
        let mut projection = self.compact_projection();
        let mut diagnostics_compacted = false;
        loop {
            let value = projection.to_value();
            if serde_json::to_vec(&value)
                .is_ok_and(|bytes| bytes.len() <= RANKED_SEARCH_COMPACT_MAX_BYTES)
            {
                return value;
            }
            projection.truncated = true;
            push_unique_reason(&mut projection.truncation_reasons, "compact_response_bytes");
            if !diagnostics_compacted {
                projection.response.query = None;
                projection.response.group = None;
                diagnostics_compacted = true;
                continue;
            }
            if !projection.shrink_auxiliary_payload() && !projection.shrink_inventory_result() {
                return projection.to_value();
            }
        }
    }

    fn compact_projection(&self) -> CompactOpenAiSearchProjection {
        let base = self.response.compact_projection();
        let companion_source_count = self.companion_allowed_tools.len();
        let mut companion_metadata_truncated = false;
        let mut companion_allowed_tools = Vec::new();
        for tool_name in self
            .companion_allowed_tools
            .iter()
            .take(COMPACT_OPENAI_MAX_COMPANION_TOOLS)
        {
            let (tool_name, truncated) =
                truncate_search_text(tool_name, COMPACT_SEARCH_MAX_TOOL_NAME_CHARS);
            let tool_name = tool_name.trim().to_string();
            companion_metadata_truncated |= truncated || tool_name.is_empty();
            if !tool_name.is_empty() && !truncated && !companion_allowed_tools.contains(&tool_name)
            {
                companion_allowed_tools.push(tool_name);
            }
        }
        companion_allowed_tools.sort();
        let companion_limit_truncated = companion_source_count > COMPACT_OPENAI_MAX_COMPANION_TOOLS;

        let extra_source_count = self.extra_results.len();
        let mut extra_metadata_truncated = false;
        let mut extra_results = Vec::new();
        for result in self
            .extra_results
            .iter()
            .take(COMPACT_OPENAI_MAX_EXTRA_RESULTS)
        {
            if compact_extra_result_fits(result) {
                extra_results.push(result.clone());
            } else {
                extra_metadata_truncated = true;
                break;
            }
        }
        let extra_limit_truncated = extra_source_count > COMPACT_OPENAI_MAX_EXTRA_RESULTS;

        let mut truncation_reasons = base.truncation_reasons;
        if companion_metadata_truncated {
            push_unique_reason(&mut truncation_reasons, "companion_tool_metadata");
        }
        if companion_limit_truncated {
            push_unique_reason(&mut truncation_reasons, "companion_tool_limit");
        }
        if extra_metadata_truncated {
            push_unique_reason(&mut truncation_reasons, "extra_result_metadata");
        }
        if extra_limit_truncated {
            push_unique_reason(&mut truncation_reasons, "extra_result_limit");
        }

        CompactOpenAiSearchProjection {
            response: base.response,
            source_count: base.source_count,
            companion_source_count,
            companion_allowed_tools,
            extra_source_count,
            extra_results,
            truncated: base.truncated
                || companion_metadata_truncated
                || companion_limit_truncated
                || extra_metadata_truncated
                || extra_limit_truncated,
            truncation_reasons,
        }
    }
}

/// OpenAI-oriented ranked response that preserves match completeness metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedOpenAiToolSearchResponse {
    pub response: OpenAiToolSearchResponse,
    pub match_summary: ToolSearchMatchSummary,
}

impl RankedOpenAiToolSearchResponse {
    /// Add extra tool names that should be allowed with the ranked results.
    pub fn with_companion_allowed_tools<I, S>(mut self, tool_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.response = self.response.with_companion_allowed_tools(tool_names);
        self
    }

    /// Attach non-inventory search results without changing ranked match counts.
    pub fn with_extra_results<I>(mut self, results: I) -> Self
    where
        I: IntoIterator<Item = Value>,
    {
        self.response = self.response.with_extra_results(results);
        self
    }

    /// Attach provider metadata for OpenAI deferred-loading clients.
    pub fn with_openai_metadata(mut self, metadata: OpenAiDeferredLoadingMetadata) -> Self {
        self.response = self.response.with_openai_metadata(metadata);
        self
    }

    /// Tool names suitable for OpenAI `allowed_tools` style narrowing.
    pub fn openai_allowed_tools(&self) -> Vec<String> {
        self.response.openai_allowed_tools()
    }

    /// Serialize the OpenAI response without losing ranked match completeness.
    pub fn to_value(&self) -> Value {
        with_match_summary(self.response.to_value(), &self.match_summary)
    }

    /// Serialize the ranked OpenAI response within 32 KiB while preserving completeness.
    pub fn to_compact_value(&self) -> Value {
        let mut projection = self.response.compact_projection();
        let (mut summary, summary_truncated) = compact_match_summary(&self.match_summary);
        if projection.truncated || summary_truncated {
            summary.truncated = true;
            push_unique_reason(&mut summary.truncation_reasons, "compact_response_bytes");
        }
        let mut diagnostics_compacted = false;
        loop {
            summary.returned_count = projection.response.results.len();
            let value = with_match_summary(projection.to_value(), &summary);
            if serde_json::to_vec(&value)
                .is_ok_and(|bytes| bytes.len() <= RANKED_SEARCH_COMPACT_MAX_BYTES)
            {
                return value;
            }
            projection.truncated = true;
            push_unique_reason(&mut projection.truncation_reasons, "compact_response_bytes");
            summary.truncated = true;
            push_unique_reason(&mut summary.truncation_reasons, "compact_response_bytes");
            if !diagnostics_compacted {
                projection.response.query = None;
                projection.response.group = None;
                summary.normalized_query_terms.clear();
                summary.excluded_query_terms.clear();
                summary.ignored_query_terms.clear();
                diagnostics_compacted = true;
                continue;
            }
            if !projection.shrink_auxiliary_payload() && !projection.shrink_inventory_result() {
                summary.returned_count = 0;
                return with_match_summary(projection.to_value(), &summary);
            }
        }
    }
}

struct CompactOpenAiSearchProjection {
    response: ToolSearchResponse,
    source_count: usize,
    companion_source_count: usize,
    companion_allowed_tools: Vec<String>,
    extra_source_count: usize,
    extra_results: Vec<Value>,
    truncated: bool,
    truncation_reasons: Vec<String>,
}

impl CompactOpenAiSearchProjection {
    fn openai_allowed_tools(&self) -> Vec<String> {
        let mut tools = self.response.openai_allowed_tools();
        tools.extend(self.companion_allowed_tools.iter().cloned());
        tools.sort();
        tools.dedup();
        tools
    }

    fn to_value(&self) -> Value {
        let mut results = self
            .response
            .results
            .iter()
            .map(tool_search_result_value)
            .collect::<Vec<_>>();
        results.extend(self.extra_results.iter().cloned());
        json!({
            "operation": self.response.operation,
            "query": self.response.query,
            "group": self.response.group,
            "read_only": self.response.read_only,
            "results": results,
            "openai_allowed_tools": self.openai_allowed_tools(),
            "compact_summary": {
                "source_count": self.source_count,
                "returned_count": self.response.results.len(),
                "companion_source_count": self.companion_source_count,
                "companion_returned_count": self.companion_allowed_tools.len(),
                "extra_source_count": self.extra_source_count,
                "extra_returned_count": self.extra_results.len(),
                "truncated": self.truncated,
                "truncation_reasons": self.truncation_reasons,
            },
        })
    }

    fn shrink_auxiliary_payload(&mut self) -> bool {
        if self.extra_results.pop().is_some() {
            return true;
        }
        self.companion_allowed_tools.pop().is_some()
    }

    fn shrink_inventory_result(&mut self) -> bool {
        self.response.results.pop().is_some()
    }
}

fn compact_extra_result_fits(value: &Value) -> bool {
    fn visit(value: &Value, nodes: &mut usize, text_chars: &mut usize) -> bool {
        *nodes += 1;
        if *nodes > COMPACT_OPENAI_MAX_EXTRA_RESULT_NODES {
            return false;
        }
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => true,
            Value::String(value) => {
                *text_chars += value
                    .chars()
                    .take(COMPACT_OPENAI_MAX_EXTRA_RESULT_TEXT_CHARS + 1)
                    .count();
                *text_chars <= COMPACT_OPENAI_MAX_EXTRA_RESULT_TEXT_CHARS
            }
            Value::Array(values) => values.iter().all(|value| visit(value, nodes, text_chars)),
            Value::Object(values) => values.iter().all(|(key, value)| {
                *text_chars += key
                    .chars()
                    .take(COMPACT_OPENAI_MAX_EXTRA_RESULT_TEXT_CHARS + 1)
                    .count();
                *text_chars <= COMPACT_OPENAI_MAX_EXTRA_RESULT_TEXT_CHARS
                    && visit(value, nodes, text_chars)
            }),
        }
    }

    let mut nodes = 0;
    let mut text_chars = 0;
    visit(value, &mut nodes, &mut text_chars)
}

fn push_unique_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|candidate| candidate == reason) {
        reasons.push(reason.to_string());
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

impl ToolInventoryPolicy {
    /// Create a strict policy that denies unknown/unregistered tools.
    pub fn strict() -> Self {
        Self {
            include_unregistered: false,
            ..Self::default()
        }
    }

    /// Create a permissive policy that allows unknown/unregistered tools.
    ///
    /// Use this only while migrating legacy servers whose tool registrations
    /// are not complete yet. Generated and public-facing servers should keep
    /// the default fail-closed behavior.
    pub fn permissive() -> Self {
        Self {
            include_unregistered: true,
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

    /// Add provider-specific canonical action roots used for negative-intent matching.
    #[must_use]
    pub fn with_action_lexemes<I, S>(mut self, lexemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.capability = self.capability.with_action_lexemes(lexemes);
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
                action_lexemes: capability.action_lexemes,
                action_lexemes_truncated: capability.action_lexemes_truncated,
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
        self.schemas_for_entries(self.entries.iter())
    }

    fn schemas_by_tool_names<'a>(&self, tool_names: impl IntoIterator<Item = &'a str>) -> Value {
        let wanted = tool_names
            .into_iter()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect::<HashSet<_>>();
        if wanted.is_empty() {
            return Value::Object(Map::new());
        }
        self.schemas_for_entries(
            self.entries
                .iter()
                .filter(|entry| wanted.contains(entry.name())),
        )
    }

    fn schemas_for_entries<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a ToolCatalogEntry>,
    ) -> Value {
        let mut schemas = Map::new();
        for entry in entries {
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
        let schemas = self.schemas_by_tool_names(results.iter().map(|result| result.name.as_str()));
        ToolSearchResponse::find_tools(
            filter.query.clone(),
            filter.group.clone(),
            filter.read_only,
            results,
        )
        .with_schemas(Some(schemas))
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

    /// Search catalog inventory with relevance ranking and completeness metadata.
    pub fn ranked_search_response(
        &self,
        filter: &ToolSearchFilter,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
    ) -> RankedToolSearchResponse {
        let response = self.inventory().search_ranked(filter, operation, policy);
        let schemas = self.schemas_by_tool_names(
            response
                .response
                .results
                .iter()
                .map(|result| result.name.as_str()),
        );
        response.with_schemas(Some(schemas))
    }

    /// Search catalog inventory with relevance ranking through a named profile.
    pub fn ranked_search_response_for_profile(
        &self,
        filter: &ToolSearchFilter,
        operation: ToolOperation,
        profile: &ToolCatalogProfile,
    ) -> RankedToolSearchResponse {
        self.ranked_search_response(filter, operation, profile.policy())
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
                action_lexemes: capability.action_lexemes,
                action_lexemes_truncated: capability.action_lexemes_truncated,
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

    /// Search registered tool metadata using natural-language relevance ranking.
    ///
    /// Unlike [`Self::search`], ranked search uses any meaningful query-term
    /// match, down-weights terms common across the visible catalog, and uses
    /// guarded-action posture as a deterministic tie-break so preview/read
    /// surfaces appear before apply surfaces with equal relevance. Common
    /// negative-intent forms exclude matching tools before an allowed-tool set
    /// is produced; ambiguous or truncated negation fails closed.
    ///
    /// # Examples
    /// ```
    /// use mcp_toolkit_core::tool_inventory::{
    ///     ToolCapability, ToolDiscoveryMetadata, ToolInventory, ToolInventoryPolicy,
    ///     ToolOperation, ToolSearchFilter,
    /// };
    ///
    /// let inventory = ToolInventory::from_capabilities([
    ///     ToolCapability::new("campaign.preview")
    ///         .with_read_only(true)
    ///         .with_discovery(ToolDiscoveryMetadata::new(
    ///             "Preview a campaign plan",
    ///             ["campaign", "plan", "preview"],
    ///         )),
    ///     ToolCapability::new("campaign.apply")
    ///         .with_discovery(ToolDiscoveryMetadata::new(
    ///             "Apply a reviewed campaign plan",
    ///             ["campaign", "apply"],
    ///         )),
    /// ])?;
    /// let response = inventory.search_ranked(
    ///     &ToolSearchFilter {
    ///         query: Some("help me plan a campaign".to_string()),
    ///         limit: Some(1),
    ///         ..ToolSearchFilter::default()
    ///     },
    ///     ToolOperation::List,
    ///     &ToolInventoryPolicy::strict(),
    /// );
    ///
    /// assert_eq!(response.response.results[0].name, "campaign.preview");
    /// assert_eq!(response.match_summary.total_matches, 2);
    /// assert!(response.match_summary.truncated);
    /// # Ok::<(), mcp_toolkit_core::tool_inventory::ToolInventoryError>(())
    /// ```
    pub fn search_ranked(
        &self,
        filter: &ToolSearchFilter,
        operation: ToolOperation,
        policy: &ToolInventoryPolicy,
    ) -> RankedToolSearchResponse {
        let (bounded_query, query_input_truncated) = filter
            .query
            .as_deref()
            .map(|query| truncate_search_text(query, RANKED_SEARCH_MAX_QUERY_CHARS))
            .map_or((None, false), |(query, truncated)| (Some(query), truncated));
        let browse_query = !query_input_truncated
            && bounded_query
                .as_deref()
                .is_none_or(|query| query.trim().is_empty());
        let requested_limit = filter.limit.unwrap_or(RANKED_SEARCH_DEFAULT_LIMIT);
        let result_limit = requested_limit.min(RANKED_SEARCH_MAX_LIMIT);
        let mut truncation_reasons = Vec::new();
        if query_input_truncated {
            push_unique_reason(&mut truncation_reasons, "query_input");
        }
        if requested_limit > RANKED_SEARCH_MAX_LIMIT {
            push_unique_reason(&mut truncation_reasons, "result_limit_clamped");
        }
        let (bounded_group, group_input_truncated) = filter
            .group
            .as_deref()
            .map(|group| truncate_search_text(group, RANKED_SEARCH_MAX_GROUP_CHARS))
            .map_or((None, false), |(group, truncated)| {
                let group = group.trim().to_string();
                ((!group.is_empty()).then_some(group), truncated)
            });
        if group_input_truncated {
            push_unique_reason(&mut truncation_reasons, "group_input");
        }
        let group = bounded_group.as_deref();

        let mut visible = self
            .capabilities()
            .into_iter()
            .filter(|capability| policy.allows_capability(capability, operation))
            .filter(|capability| {
                !group_input_truncated
                    && group.is_none_or(|group| capability.group.as_deref() == Some(group))
            })
            .filter(|capability| {
                filter
                    .read_only
                    .is_none_or(|read_only| capability.read_only == read_only)
            })
            .map(RankedCapabilityDocument::new)
            .collect::<Vec<_>>();
        let mut action_lexemes = default_search_action_lexemes();
        let mut action_lexemes_truncated = false;
        'documents: for document in &visible {
            for lexeme in &document.capability.action_lexemes {
                if action_lexemes.len() == RANKED_SEARCH_MAX_ACTION_LEXEMES_TOTAL
                    && !action_lexemes.contains(lexeme)
                {
                    action_lexemes_truncated = true;
                    break 'documents;
                }
                action_lexemes.insert(lexeme.clone());
            }
        }
        for document in &mut visible {
            document.build_exclusion_terms(&action_lexemes);
        }
        let normalized_query = normalize_ranked_query(
            bounded_query.as_deref().unwrap_or_default(),
            &action_lexemes,
        );
        let query_concepts = &normalized_query.positive_concepts;
        let excluded_query_concepts = &normalized_query.excluded_concepts;
        if normalized_query.positive_terms_truncated {
            push_unique_reason(&mut truncation_reasons, "normalized_query_terms");
        }
        if normalized_query.excluded_terms_truncated {
            push_unique_reason(&mut truncation_reasons, "excluded_query_terms");
        }
        if normalized_query.ignored_terms_truncated {
            push_unique_reason(&mut truncation_reasons, "ignored_query_terms");
        }
        if normalized_query.dangling_negation {
            push_unique_reason(&mut truncation_reasons, "query_intent_ambiguous");
        }
        let visible_metadata_truncated =
            action_lexemes_truncated || visible.iter().any(|document| document.metadata_truncated);
        if visible_metadata_truncated {
            push_unique_reason(&mut truncation_reasons, "result_metadata");
        }
        let visible = visible
            .into_iter()
            .filter(|document| document.name_selectable)
            .collect::<Vec<_>>();

        let document_frequencies = query_concepts
            .iter()
            .map(|concept| {
                visible
                    .iter()
                    .filter(|document| document.query_concept_score(concept) > 0)
                    .count()
            })
            .collect::<Vec<_>>();
        let document_count = visible.len();
        let fail_closed_query = query_input_truncated
            || normalized_query.excluded_terms_truncated
            || normalized_query.dangling_negation
            || (visible_metadata_truncated && !excluded_query_concepts.is_empty());

        let mut ranked = visible
            .into_iter()
            .filter_map(|document| {
                if fail_closed_query {
                    return None;
                }
                if browse_query {
                    return Some((
                        0_u64,
                        0_usize,
                        capability_safety_rank(document.capability),
                        document,
                    ));
                }
                if query_concepts.is_empty()
                    || excluded_query_concepts
                        .iter()
                        .any(|concept| document.matches_excluded_concept(concept))
                {
                    return None;
                }

                let mut score = 0_u64;
                let mut matched_terms = 0_usize;
                for (concept, document_frequency) in
                    query_concepts.iter().zip(document_frequencies.iter())
                {
                    let field_score = document.query_concept_score(concept);
                    if field_score == 0 {
                        continue;
                    }
                    matched_terms += 1;
                    let rarity_multiplier = (document_count + 1) / (document_frequency + 1);
                    score += (field_score * rarity_multiplier.max(1)) as u64;
                }

                (score > 0).then_some((
                    score,
                    matched_terms,
                    capability_safety_rank(document.capability),
                    document,
                ))
            })
            .collect::<Vec<_>>();

        if browse_query {
            ranked.sort_by(|left, right| {
                left.2
                    .cmp(&right.2)
                    .then_with(|| left.3.capability.name.cmp(&right.3.capability.name))
            });
        } else {
            ranked.sort_by(|left, right| {
                right
                    .0
                    .cmp(&left.0)
                    .then_with(|| right.1.cmp(&left.1))
                    .then_with(|| left.2.cmp(&right.2))
                    .then_with(|| left.3.capability.name.cmp(&right.3.capability.name))
            });
        }

        let total_matches = ranked.len();
        ranked.truncate(result_limit);
        if ranked.len() < total_matches {
            push_unique_reason(&mut truncation_reasons, "result_limit");
        }
        let mut result_metadata_truncated = false;
        let results = ranked
            .into_iter()
            .map(|(_, _, _, document)| {
                let (result, truncated) = document.capability.to_ranked_search_result();
                result_metadata_truncated |= truncated;
                result
            })
            .collect::<Vec<_>>();
        if result_metadata_truncated {
            push_unique_reason(&mut truncation_reasons, "result_metadata");
        }
        let returned_count = results.len();

        RankedToolSearchResponse {
            response: ToolSearchResponse::find_tools(
                bounded_query,
                bounded_group,
                filter.read_only,
                results,
            ),
            match_summary: ToolSearchMatchSummary {
                total_matches,
                returned_count,
                result_limit,
                truncated: !truncation_reasons.is_empty(),
                truncation_reasons,
                normalized_query_terms: normalized_query
                    .positive_concepts
                    .into_iter()
                    .map(|concept| concept.source)
                    .collect(),
                excluded_query_terms: normalized_query
                    .excluded_concepts
                    .into_iter()
                    .map(|concept| concept.source)
                    .collect(),
                ignored_query_terms: normalized_query.ignored_terms,
            },
        }
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

    fn to_ranked_search_result(&self) -> (ToolSearchResult, bool) {
        let mut metadata_truncated = self.action_lexemes_truncated;
        let group = self.group.as_deref().map(|group| {
            let (group, truncated) = truncate_search_text(group, RANKED_SEARCH_MAX_GROUP_CHARS);
            metadata_truncated |= truncated;
            group
        });
        let description = self.discovery.as_ref().and_then(|discovery| {
            let (description, truncated) = truncate_search_text_at_token_boundary(
                &discovery.description,
                RANKED_SEARCH_MAX_DESCRIPTION_CHARS,
            );
            metadata_truncated |= truncated;
            (!description.is_empty()).then_some(description)
        });
        let mut keywords = Vec::new();
        if let Some(discovery) = &self.discovery {
            metadata_truncated |= discovery.keywords.len() > RANKED_SEARCH_MAX_KEYWORDS;
            for keyword in discovery.keywords.iter().take(RANKED_SEARCH_MAX_KEYWORDS) {
                let (keyword, truncated) = truncate_search_text_at_token_boundary(
                    keyword,
                    RANKED_SEARCH_MAX_KEYWORD_CHARS,
                );
                metadata_truncated |= truncated;
                if !keyword.is_empty() && !keywords.contains(&keyword) {
                    keywords.push(keyword);
                }
            }
        }
        (
            ToolSearchResult {
                name: self.name.clone(),
                group,
                read_only: self.read_only,
                description,
                keywords,
                risk_posture: self.risk_posture,
            },
            metadata_truncated,
        )
    }
}

struct RankedCapabilityDocument<'a> {
    capability: &'a ToolCapability,
    name_terms: Vec<String>,
    group_terms: Vec<String>,
    description_terms: Vec<String>,
    keyword_terms: Vec<String>,
    exclusion_terms: HashSet<String>,
    metadata_truncated: bool,
    name_selectable: bool,
}

impl<'a> RankedCapabilityDocument<'a> {
    fn new(capability: &'a ToolCapability) -> Self {
        let (name, name_truncated) = truncate_search_text_at_token_boundary(
            &capability.name,
            COMPACT_SEARCH_MAX_TOOL_NAME_CHARS,
        );
        let (group, group_truncated) = capability.group.as_deref().map_or_else(
            || (String::new(), false),
            |group| truncate_search_text_at_token_boundary(group, RANKED_SEARCH_MAX_GROUP_CHARS),
        );
        let mut metadata_truncated =
            capability.action_lexemes_truncated || name_truncated || group_truncated;
        let mut description_terms = Vec::new();
        let mut keyword_terms = Vec::new();
        if let Some(discovery) = &capability.discovery {
            let (description, description_truncated) = truncate_search_text_at_token_boundary(
                &discovery.description,
                RANKED_SEARCH_MAX_DESCRIPTION_CHARS,
            );
            metadata_truncated |= description_truncated;
            description_terms = tokenize_search_text(&description);
            metadata_truncated |= discovery.keywords.len() > RANKED_SEARCH_MAX_KEYWORDS;
            for keyword in discovery.keywords.iter().take(RANKED_SEARCH_MAX_KEYWORDS) {
                let (keyword, keyword_truncated) = truncate_search_text_at_token_boundary(
                    keyword,
                    RANKED_SEARCH_MAX_KEYWORD_CHARS,
                );
                metadata_truncated |= keyword_truncated;
                for term in tokenize_search_text(&keyword) {
                    if !keyword_terms.contains(&term) {
                        keyword_terms.push(term);
                    }
                }
            }
        }
        let name_terms = tokenize_search_text(&name);
        let group_terms = tokenize_search_text(&group);
        Self {
            capability,
            name_terms,
            group_terms,
            description_terms,
            keyword_terms,
            exclusion_terms: HashSet::new(),
            metadata_truncated,
            name_selectable: !name_truncated && !name.is_empty(),
        }
    }

    fn build_exclusion_terms(&mut self, action_lexemes: &HashSet<String>) {
        for term in self
            .name_terms
            .iter()
            .chain(self.group_terms.iter())
            .chain(self.description_terms.iter())
            .chain(self.keyword_terms.iter())
        {
            let mut variants = search_token_variants(term);
            add_negative_action_variants(term, &mut variants, action_lexemes);
            for variant in variants {
                self.exclusion_terms.insert(variant);
            }
        }
    }

    fn query_term_score(&self, term: &str) -> usize {
        token_field_score(term, self.name_terms.iter(), 64)
            .max(token_field_score(term, self.group_terms.iter(), 24))
            .max(token_field_score(term, self.keyword_terms.iter(), 36))
            .max(token_field_score(term, self.description_terms.iter(), 12))
    }

    fn query_concept_score(&self, concept: &RankedQueryConcept) -> usize {
        concept
            .variants
            .iter()
            .map(|variant| self.query_term_score(variant))
            .max()
            .unwrap_or(0)
    }

    fn matches_excluded_concept(&self, concept: &RankedQueryConcept) -> bool {
        concept
            .variants
            .iter()
            .any(|variant| self.exclusion_terms.contains(variant))
    }
}

fn capability_safety_rank(capability: &ToolCapability) -> usize {
    capability.risk_posture.map_or_else(
        || if capability.read_only { 0 } else { 5 },
        |posture| match posture.operation_class {
            crate::guarded_action::GuardedActionOperationClass::Read => 0,
            crate::guarded_action::GuardedActionOperationClass::SensitiveRead => 1,
            crate::guarded_action::GuardedActionOperationClass::NoMutationProof => 2,
            crate::guarded_action::GuardedActionOperationClass::Preview => 3,
            crate::guarded_action::GuardedActionOperationClass::GuardedApply => 4,
            crate::guarded_action::GuardedActionOperationClass::Mutating => 5,
            crate::guarded_action::GuardedActionOperationClass::SendAdjacent => 6,
            crate::guarded_action::GuardedActionOperationClass::Destructive => 7,
        },
    )
}

struct NormalizedRankedQuery {
    positive_concepts: Vec<RankedQueryConcept>,
    excluded_concepts: Vec<RankedQueryConcept>,
    ignored_terms: Vec<String>,
    positive_terms_truncated: bool,
    excluded_terms_truncated: bool,
    ignored_terms_truncated: bool,
    dangling_negation: bool,
}

struct RankedQueryConcept {
    source: String,
    variants: Vec<String>,
}

fn normalize_ranked_query(query: &str, action_lexemes: &HashSet<String>) -> NormalizedRankedQuery {
    let mut positive_concepts = Vec::new();
    let mut excluded_concepts = Vec::new();
    let mut ignored_terms = Vec::new();
    let mut positive_terms_truncated = false;
    let mut excluded_terms_truncated = false;
    let mut ignored_terms_truncated = false;
    let mut negative_scope = false;
    let mut negative_scope_has_exclusion = false;
    let mut words = query
        .split(|character: char| !character.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .peekable();
    while let Some(mut raw) = words.next() {
        if is_search_negation_contraction_stem(&raw) && words.peek().is_some_and(|word| word == "t")
        {
            let _ = words.next();
            raw = "not".to_string();
        } else if is_search_negation_contraction(&raw) {
            raw = "not".to_string();
        }
        if raw.is_empty() {
            continue;
        }
        if is_search_negation_marker(&raw) {
            ignored_terms_truncated |=
                push_bounded_unique(&mut ignored_terms, raw, RANKED_SEARCH_MAX_IGNORED_TERMS);
            negative_scope = true;
            negative_scope_has_exclusion = false;
            continue;
        }
        if negative_scope && is_search_negation_continuation(&raw) {
            ignored_terms_truncated |=
                push_bounded_unique(&mut ignored_terms, raw, RANKED_SEARCH_MAX_IGNORED_TERMS);
            continue;
        }
        if negative_scope && is_search_negation_filler(&raw) {
            ignored_terms_truncated |=
                push_bounded_unique(&mut ignored_terms, raw, RANKED_SEARCH_MAX_IGNORED_TERMS);
            continue;
        }
        if is_search_stop_word(&raw) {
            ignored_terms_truncated |=
                push_bounded_unique(&mut ignored_terms, raw, RANKED_SEARCH_MAX_IGNORED_TERMS);
            continue;
        }
        let mut variants = search_token_variants(&raw);
        if variants.is_empty() {
            continue;
        }
        if negative_scope {
            add_negative_action_variants(&raw, &mut variants, action_lexemes);
            excluded_terms_truncated |= push_query_concept(
                &mut excluded_concepts,
                raw,
                variants,
                RANKED_SEARCH_MAX_EXCLUDED_TERMS,
            );
            negative_scope_has_exclusion = true;
        } else {
            positive_terms_truncated |= push_query_concept(
                &mut positive_concepts,
                raw,
                variants,
                RANKED_SEARCH_MAX_QUERY_TERMS,
            );
        }
    }
    NormalizedRankedQuery {
        positive_concepts,
        excluded_concepts,
        ignored_terms,
        positive_terms_truncated,
        excluded_terms_truncated,
        ignored_terms_truncated,
        dangling_negation: negative_scope && !negative_scope_has_exclusion,
    }
}

fn push_query_concept(
    concepts: &mut Vec<RankedQueryConcept>,
    source: String,
    variants: Vec<String>,
    max_concepts: usize,
) -> bool {
    if let Some(existing) = concepts.iter_mut().find(|existing| {
        existing
            .variants
            .iter()
            .any(|variant| variants.contains(variant))
    }) {
        for variant in variants {
            if !existing.variants.contains(&variant) {
                existing.variants.push(variant);
            }
        }
        return false;
    }
    if concepts.len() >= max_concepts {
        return true;
    }
    concepts.push(RankedQueryConcept { source, variants });
    false
}

fn tokenize_search_text(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .flat_map(search_token_variants)
        .collect()
}

fn search_token_variants(raw: &str) -> Vec<String> {
    let token = raw.trim().to_ascii_lowercase();
    if token.is_empty() {
        return Vec::new();
    }
    let mut variants = vec![token.clone()];
    for singular in singular_search_tokens(&token) {
        if singular != token && !variants.contains(&singular) {
            variants.push(singular);
        }
    }
    variants
}

fn singular_search_tokens(token: &str) -> Vec<String> {
    let explicit: &[&str] = match token {
        "ads" => &["ad"],
        "aliases" => &["alias"],
        "analyses" => &["analysis"],
        "apis" => &["api"],
        "axes" => &["axis", "axe"],
        "buses" => &["bus"],
        "campaigns" => &["campaign"],
        "canvases" => &["canvas"],
        "capabilities" => &["capability"],
        "categories" => &["category"],
        "cookies" => &["cookie"],
        "creatives" => &["creative"],
        "dependencies" => &["dependency"],
        "entries" => &["entry"],
        "groups" => &["group"],
        "ids" => &["id"],
        "indices" => &["index"],
        "items" => &["item"],
        "jobs" => &["job"],
        "keys" => &["key"],
        "logs" => &["log"],
        "matrices" => &["matrix"],
        "movies" => &["movie"],
        "networks" => &["network"],
        "orders" => &["order"],
        "pages" => &["page"],
        "placements" => &["placement"],
        "policies" => &["policy"],
        "processes" => &["process"],
        "queries" => &["query"],
        "reports" => &["report"],
        "repositories" => &["repository"],
        "results" => &["result"],
        "schemas" => &["schema"],
        "searches" => &["search"],
        "sessions" => &["session"],
        "sizes" => &["size"],
        "statuses" => &["status"],
        "strategies" => &["strategy"],
        "tables" => &["table"],
        "tools" => &["tool"],
        "uis" => &["ui"],
        "units" => &["unit"],
        "urls" => &["url"],
        _ => &[],
    };
    explicit
        .iter()
        .map(|singular| (*singular).to_string())
        .collect()
}

fn add_negative_action_variants(
    source: &str,
    variants: &mut Vec<String>,
    action_lexemes: &HashSet<String>,
) {
    let mut candidates = Vec::new();
    if let Some(base) = source.strip_suffix("ies").filter(|base| base.len() >= 2) {
        candidates.push(format!("{base}y"));
    } else {
        if let Some(base) = source
            .strip_suffix('s')
            .filter(|base| base.len() >= 3 && !base.ends_with('s'))
        {
            candidates.push(base.to_string());
        }
        if let Some(base) = source.strip_suffix("es").filter(|base| base.len() >= 3) {
            candidates.push(base.to_string());
        }
    }
    if let Some(base) = source.strip_suffix("ing").filter(|base| base.len() >= 3) {
        candidates.push(base.to_string());
        candidates.push(format!("{base}e"));
        if base.ends_with("ck") {
            candidates.push(base[..base.len() - 1].to_string());
        }
        if let Some(shortened) = strip_doubled_final_character(base) {
            candidates.push(shortened);
        }
    }
    if let Some(base) = source.strip_suffix("ied").filter(|base| base.len() >= 2) {
        candidates.push(format!("{base}y"));
    } else if let Some(base) = source.strip_suffix("ed").filter(|base| base.len() >= 3) {
        candidates.push(base.to_string());
        candidates.push(format!("{base}e"));
        if base.ends_with("ck") {
            candidates.push(base[..base.len() - 1].to_string());
        }
        if let Some(shortened) = strip_doubled_final_character(base) {
            candidates.push(shortened);
        }
    }
    for candidate in candidates {
        if action_lexemes.contains(&candidate) && !variants.contains(&candidate) {
            variants.push(candidate);
        }
    }
}

fn default_search_action_lexemes() -> HashSet<String> {
    [
        "add",
        "apply",
        "archive",
        "call",
        "close",
        "create",
        "deactivate",
        "delete",
        "destroy",
        "dispatch",
        "drop",
        "execute",
        "fetch",
        "find",
        "get",
        "ingest",
        "inspect",
        "invoke",
        "launch",
        "list",
        "mutate",
        "open",
        "plan",
        "preview",
        "publish",
        "purge",
        "push",
        "query",
        "read",
        "refresh",
        "remove",
        "rename",
        "retarget",
        "rotate",
        "run",
        "search",
        "select",
        "send",
        "start",
        "stop",
        "traffic",
        "unpublish",
        "update",
        "write",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn strip_doubled_final_character(value: &str) -> Option<String> {
    let mut characters = value.chars().rev();
    let last = characters.next()?;
    (characters.next() == Some(last)).then(|| {
        let mut shortened = value.to_string();
        shortened.pop();
        shortened
    })
}

fn push_bounded_unique(terms: &mut Vec<String>, term: String, max_terms: usize) -> bool {
    if terms.contains(&term) {
        return false;
    }
    if terms.len() >= max_terms {
        return true;
    }
    terms.push(term);
    false
}

fn is_search_negation_marker(term: &str) -> bool {
    matches!(
        term,
        "avoid" | "except" | "exclude" | "excluding" | "never" | "no" | "not" | "without"
    )
}

fn is_search_negation_continuation(term: &str) -> bool {
    matches!(term, "and" | "nor" | "or")
}

fn is_search_negation_contraction(term: &str) -> bool {
    matches!(
        term,
        "arent"
            | "cannot"
            | "cant"
            | "couldnt"
            | "didnt"
            | "doesnt"
            | "dont"
            | "hadnt"
            | "hasnt"
            | "havent"
            | "aint"
            | "isnt"
            | "mustnt"
            | "neednt"
            | "shouldnt"
            | "shant"
            | "wasnt"
            | "werent"
            | "wont"
            | "wouldnt"
    )
}

fn is_search_negation_contraction_stem(term: &str) -> bool {
    matches!(
        term,
        "aren"
            | "can"
            | "couldn"
            | "didn"
            | "doesn"
            | "don"
            | "hadn"
            | "hasn"
            | "haven"
            | "ain"
            | "isn"
            | "mustn"
            | "needn"
            | "shouldn"
            | "shan"
            | "wasn"
            | "weren"
            | "won"
            | "wouldn"
    )
}

fn is_search_negation_filler(term: &str) -> bool {
    matches!(
        term,
        "call"
            | "accidentally"
            | "actually"
            | "any"
            | "calling"
            | "choose"
            | "choosing"
            | "invoke"
            | "invoking"
            | "ever"
            | "select"
            | "selecting"
            | "tool"
            | "tools"
            | "use"
            | "using"
    )
}

fn is_search_stop_word(term: &str) -> bool {
    matches!(
        term,
        "a" | "an"
            | "and"
            | "are"
            | "be"
            | "by"
            | "can"
            | "could"
            | "do"
            | "does"
            | "for"
            | "from"
            | "have"
            | "how"
            | "i"
            | "in"
            | "is"
            | "it"
            | "me"
            | "my"
            | "of"
            | "on"
            | "only"
            | "or"
            | "please"
            | "should"
            | "show"
            | "that"
            | "the"
            | "this"
            | "to"
            | "want"
            | "we"
            | "would"
            | "with"
            | "you"
            | "your"
    )
}

fn token_field_score<'a>(
    query_term: &str,
    mut field_terms: impl Iterator<Item = &'a String>,
    exact_score: usize,
) -> usize {
    if field_terms.any(|field_term| query_term == field_term) {
        exact_score
    } else {
        0
    }
}

fn truncate_search_text(value: &str, max_chars: usize) -> (String, bool) {
    let mut characters = value.chars();
    let bounded = characters.by_ref().take(max_chars).collect::<String>();
    (bounded, characters.next().is_some())
}

fn truncate_search_text_at_token_boundary(value: &str, max_chars: usize) -> (String, bool) {
    let mut characters = value.chars();
    let mut bounded = characters.by_ref().take(max_chars).collect::<String>();
    let next = characters.next();
    let truncated = next.is_some();
    if truncated
        && next.is_some_and(|character| character.is_ascii_alphanumeric())
        && bounded
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_alphanumeric())
    {
        while bounded
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        {
            bounded.pop();
        }
    }
    (bounded, truncated)
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
        RankedToolSearchResponse, ToolCapability, ToolCatalog, ToolCatalogEntry,
        ToolCatalogExample, ToolCatalogProfile, ToolExposure, ToolInventory,
        ToolInventoryDenialReason, ToolInventoryPolicy, ToolOperation, ToolSearchMatchSummary,
        COMPACT_SEARCH_MAX_TOOL_NAME_CHARS, OPERATOR_PROFILE_KEY, RANKED_SEARCH_COMPACT_MAX_BYTES,
        RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY, RANKED_SEARCH_MAX_ACTION_LEXEMES_TOTAL,
        RANKED_SEARCH_MAX_ACTION_LEXEME_CHARS, RANKED_SEARCH_MAX_DESCRIPTION_CHARS,
        RANKED_SEARCH_MAX_EXCLUDED_TERMS, RANKED_SEARCH_MAX_GROUP_CHARS,
        RANKED_SEARCH_MAX_IGNORED_TERMS, RANKED_SEARCH_MAX_KEYWORDS,
        RANKED_SEARCH_MAX_KEYWORD_CHARS, RANKED_SEARCH_MAX_QUERY_CHARS,
        RANKED_SEARCH_MAX_QUERY_TERMS, READ_ONLY_PROFILE_KEY,
    };
    use super::{ToolDiscoveryMetadata, ToolSearchFilter, ToolSearchResponse, ToolSearchResult};
    use crate::guarded_action::{GuardedActionOperationClass, GuardedActionPosture};
    use serde_json::json;

    #[test]
    fn strict_policy_blocks_unregistered_tools() {
        let inventory = ToolInventory::new();
        let policy = ToolInventoryPolicy::strict();
        assert!(!inventory.is_allowed("unknown.tool", ToolOperation::List, &policy));
    }

    #[test]
    fn default_policy_blocks_unregistered_tools() {
        let inventory = ToolInventory::new();
        let policy = ToolInventoryPolicy::default();
        assert!(!inventory.is_allowed("unknown.tool", ToolOperation::Call, &policy));
    }

    #[test]
    fn permissive_policy_allows_unregistered_tools() {
        let inventory = ToolInventory::new();
        let policy = ToolInventoryPolicy::permissive();
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
    fn ranked_search_handles_natural_language_and_plural_terms() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("campaign.plan")
                .with_group("trafficking")
                .with_risk_posture(GuardedActionPosture::preview())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Preview line items and creatives before trafficking.",
                    ["campaign", "creative", "line item", "plan"],
                )),
            ToolCapability::new("report.read")
                .with_group("reporting")
                .with_risk_posture(GuardedActionPosture::read_only())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Read campaign delivery reports.",
                    ["campaign", "report"],
                )),
        ])
        .expect("inventory");

        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some(
                    "please help me plan campaigns with line items and creatives".to_string(),
                ),
                limit: Some(1),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert_eq!(ranked.response.results[0].name, "campaign.plan");
        assert_eq!(ranked.match_summary.total_matches, 2);
        assert!(ranked.match_summary.truncated);
        assert!(ranked
            .match_summary
            .normalized_query_terms
            .contains(&"creatives".to_string()));
        assert!(ranked
            .match_summary
            .ignored_query_terms
            .contains(&"please".to_string()));
    }

    #[test]
    fn ranked_search_preserves_strict_search_behavior() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("cache.purge")
            .with_read_only(true)
            .with_discovery(ToolDiscoveryMetadata::new(
                "Purge cache entries",
                ["invalidate"],
            ))])
        .expect("inventory");
        let filter = ToolSearchFilter {
            query: Some("invalidate unavailable".to_string()),
            ..ToolSearchFilter::default()
        };

        assert!(inventory
            .search(&filter, ToolOperation::List, &ToolInventoryPolicy::strict())
            .is_empty());
        assert_eq!(
            inventory
                .search_ranked(&filter, ToolOperation::List, &ToolInventoryPolicy::strict())
                .response
                .results[0]
                .name,
            "cache.purge"
        );
    }

    #[test]
    fn ranked_search_downweights_catalog_wide_terms() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("common.exact")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new("Common operation.", ["common"])),
            ToolCapability::new("special.read")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Common operation with a rare capability.",
                    ["rare"],
                )),
            ToolCapability::new("other.read")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new("Common operation.", ["common"])),
            ToolCapability::new("another.read")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new("Common operation.", ["common"])),
        ])
        .expect("inventory");

        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("common rare".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert_eq!(ranked.response.results[0].name, "special.read");
    }

    #[test]
    fn ranked_search_uses_safety_only_as_a_tie_break() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("campaign.apply")
                .with_risk_posture(GuardedActionPosture::guarded_apply())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Run campaign workflow.",
                    ["campaign", "workflow"],
                )),
            ToolCapability::new("campaign.preview")
                .with_risk_posture(GuardedActionPosture::preview())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Run campaign workflow.",
                    ["campaign", "workflow"],
                )),
        ])
        .expect("inventory");

        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("campaign workflow".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert_eq!(ranked.response.results[0].name, "campaign.preview");
        assert_eq!(ranked.response.results[1].name, "campaign.apply");

        let plural = ToolInventory::from_capabilities([
            ToolCapability::new("ads.delete")
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("ad.preview").with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("plural inventory")
        .search_ranked(
            &ToolSearchFilter {
                query: Some("ads".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(plural.response.results[0].name, "ad.preview");
        assert_eq!(plural.response.results[1].name, "ads.delete");
    }

    #[test]
    fn ranked_search_excludes_explicitly_negated_actions() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("campaign.apply")
                .with_risk_posture(GuardedActionPosture::guarded_apply())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Apply a campaign change.",
                    ["apply", "campaign"],
                )),
            ToolCapability::new("campaign.delete")
                .with_risk_posture(GuardedActionPosture::destructive())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Delete a campaign.",
                    ["campaign", "delete"],
                )),
            ToolCapability::new("campaign.preview")
                .with_risk_posture(GuardedActionPosture::preview())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Preview a campaign change.",
                    ["campaign", "preview"],
                )),
        ])
        .expect("inventory");

        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("preview campaign without using apply and delete".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert_eq!(
            ranked
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["campaign.preview"]
        );
        assert_eq!(
            ranked.match_summary.excluded_query_terms,
            vec!["apply", "delete"]
        );
        assert_eq!(
            ranked.to_compact_value()["openai_allowed_tools"],
            json!(["campaign.preview"])
        );

        let ambiguous = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("campaign not".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(ambiguous.response.results.is_empty());
        assert!(ambiguous
            .match_summary
            .truncation_reasons
            .contains(&"query_intent_ambiguous".to_string()));

        let exclusions = (0..(RANKED_SEARCH_MAX_EXCLUDED_TERMS + 1))
            .map(|index| format!("blocked{index}"))
            .collect::<Vec<_>>()
            .join(" or ");
        let capped = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some(format!("campaign without {exclusions}")),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(capped.response.results.is_empty());
        assert!(capped
            .match_summary
            .truncation_reasons
            .contains(&"excluded_query_terms".to_string()));

        for (query, excluded_term) in [
            ("campaign don't delete", "delete"),
            ("campaign dont delete", "delete"),
            ("campaign can't delete", "delete"),
            ("campaign cannot delete", "delete"),
            ("campaign ain't deleting", "deleting"),
            ("campaign shan't delete", "delete"),
            ("campaign without deleting", "deleting"),
            ("campaign don't accidentally delete", "delete"),
            ("campaign don't use any delete tools", "delete"),
        ] {
            let contracted = inventory.search_ranked(
                &ToolSearchFilter {
                    query: Some(query.to_string()),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
            assert_eq!(
                contracted
                    .response
                    .results
                    .iter()
                    .map(|result| result.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["campaign.preview", "campaign.apply"],
                "query: {query}"
            );
            assert_eq!(
                contracted.match_summary.excluded_query_terms,
                vec![excluded_term.to_string()],
                "query: {query}"
            );
        }

        let coordinated = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("preview campaign without delete, apply, or send".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            coordinated
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["campaign.preview"]
        );
        assert_eq!(
            coordinated.match_summary.excluded_query_terms,
            vec!["delete", "apply", "send"]
        );

        let plural_actions = ToolInventory::from_capabilities([
            ToolCapability::new("campaign.apply")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("campaign.delete")
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("campaign.write")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("campaign.preview")
                .with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("plural-action inventory")
        .search_ranked(
            &ToolSearchFilter {
                query: Some("preview campaign without deletes, applies, or writes".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            plural_actions
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["campaign.preview"]
        );
        assert_eq!(
            plural_actions.match_summary.excluded_query_terms,
            vec!["deletes", "applies", "writes"]
        );

        let es_actions = ToolInventory::from_capabilities([
            ToolCapability::new("campaign.publish")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("campaign.push")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("campaign.dispatch")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("campaign.refresh")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("campaign.preview")
                .with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("es-action inventory")
        .search_ranked(
            &ToolSearchFilter {
                query: Some(
                    "preview campaign without publishes, pushes, dispatches, or refreshes"
                        .to_string(),
                ),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            es_actions
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["campaign.preview"]
        );
        assert_eq!(
            es_actions.match_summary.excluded_query_terms,
            vec!["publishes", "pushes", "dispatches", "refreshes"]
        );

        for query in [
            "preview campaign without trafficking",
            "preview campaign without trafficked",
        ] {
            let traffic = ToolInventory::from_capabilities([
                ToolCapability::new("campaign.traffic")
                    .with_risk_posture(GuardedActionPosture::guarded_apply()),
                ToolCapability::new("campaign.preview")
                    .with_risk_posture(GuardedActionPosture::preview()),
            ])
            .expect("traffic inventory")
            .search_ranked(
                &ToolSearchFilter {
                    query: Some(query.to_string()),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
            assert_eq!(
                traffic
                    .response
                    .results
                    .iter()
                    .map(|result| result.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["campaign.preview"],
                "query: {query}"
            );
            assert_eq!(
                traffic.to_compact_value()["openai_allowed_tools"],
                json!(["campaign.preview"]),
                "query: {query}"
            );
        }

        let symmetric = ToolInventory::from_capabilities([
            ToolCapability::new("campaign.trafficking")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("campaign.delivery")
                .with_risk_posture(GuardedActionPosture::guarded_apply())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Trafficked campaign mutation.",
                    ["campaign"],
                )),
            ToolCapability::new("campaign.run")
                .with_risk_posture(GuardedActionPosture::guarded_apply())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Run a campaign mutation.",
                    ["campaign", "trafficking"],
                )),
            ToolCapability::new("campaign.preview")
                .with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("symmetric exclusion inventory")
        .search_ranked(
            &ToolSearchFilter {
                query: Some("preview campaign without traffic".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            symmetric
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["campaign.preview"]
        );
        assert_eq!(
            symmetric.to_compact_value()["openai_allowed_tools"],
            json!(["campaign.preview"])
        );

        let collision_inventory = ToolInventory::from_capabilities([
            ToolCapability::new("session.adding")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("session.canva")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("session.preview")
                .with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("negative collision inventory");
        let non_actions = collision_inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("preview session without canvas or ads".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            non_actions
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["session.preview", "session.adding", "session.canva"]
        );
        assert_eq!(
            non_actions.to_compact_value()["openai_allowed_tools"],
            json!(["session.adding", "session.canva", "session.preview"])
        );

        let recognized_action = collision_inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("preview session without add".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            recognized_action
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["session.preview", "session.canva"]
        );

        let extended_actions = ToolInventory::from_capabilities([
            ToolCapability::new("cache.purge")
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("cache.rotate")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("cache.destroy")
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("cache.unpublish")
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("cache.evict")
                .with_action_lexemes(["evict"])
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("cache.preview").with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("extended action inventory")
        .search_ranked(
            &ToolSearchFilter {
                query: Some(
                    "preview cache without purging rotating destroying unpublishing or evicting"
                        .to_string(),
                ),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            extended_actions
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["cache.preview"]
        );
        assert_eq!(
            extended_actions.to_compact_value()["openai_allowed_tools"],
            json!(["cache.preview"])
        );

        let catalog_actions = ToolCatalog::from_entries([
            ToolCatalogEntry::new("cache.evict")
                .with_action_lexemes(["evict"])
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCatalogEntry::new("cache.preview")
                .with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("catalog action inventory")
        .ranked_search_response(
            &ToolSearchFilter {
                query: Some("preview cache without evicting".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            catalog_actions.to_compact_value()["openai_allowed_tools"],
            json!(["cache.preview"])
        );

        let bounded_roots = ToolCapability::new("cache.preview").with_action_lexemes(
            (0..=RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY)
                .map(|index| format!("action{index}")),
        );
        assert_eq!(
            bounded_roots.action_lexemes.len(),
            RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY
        );
        assert!(bounded_roots.action_lexemes_truncated);

        let overlong_root = ToolCapability::new("cache.preview")
            .with_action_lexemes(["x".repeat(RANKED_SEARCH_MAX_ACTION_LEXEME_CHARS + 1)]);
        assert!(overlong_root.action_lexemes.is_empty());
        assert!(overlong_root.action_lexemes_truncated);

        let truncated_catalog = ToolCatalog::from_entries([ToolCatalogEntry::new("cache.preview")
            .with_action_lexemes(
                (0..=RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY)
                    .map(|index| format!("action{index}")),
            )
            .with_risk_posture(GuardedActionPosture::preview())])
        .expect("truncated catalog action inventory")
        .ranked_search_response(
            &ToolSearchFilter {
                query: Some("cache without evicting".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(truncated_catalog.response.results.is_empty());
        assert!(truncated_catalog
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));

        let capability_count = (RANKED_SEARCH_MAX_ACTION_LEXEMES_TOTAL
            / RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY)
            + 2;
        let aggregate_overflow =
            ToolInventory::from_capabilities((0..capability_count).map(|capability_index| {
                ToolCapability::new(format!("cache.{capability_index}"))
                    .with_action_lexemes(
                        (0..RANKED_SEARCH_MAX_ACTION_LEXEMES_PER_CAPABILITY)
                            .map(|lexeme_index| format!("action{capability_index}x{lexeme_index}")),
                    )
                    .with_risk_posture(GuardedActionPosture::preview())
            }))
            .expect("aggregate action inventory")
            .search_ranked(
                &ToolSearchFilter {
                    query: Some("cache without evicting".to_string()),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
        assert!(aggregate_overflow.response.results.is_empty());
        assert!(aggregate_overflow
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));
    }

    #[test]
    fn ranked_search_reports_limits_and_orders_browse_results_by_safety() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("alpha.apply")
                .with_risk_posture(GuardedActionPosture::guarded_apply()),
            ToolCapability::new("zeta.read").with_risk_posture(GuardedActionPosture::read_only()),
            ToolCapability::new("beta.preview").with_risk_posture(GuardedActionPosture::preview()),
        ])
        .expect("inventory");

        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                limit: Some(2),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert_eq!(ranked.match_summary.total_matches, 3);
        assert_eq!(ranked.match_summary.returned_count, 2);
        assert!(ranked.match_summary.truncated);
        assert_eq!(
            ranked
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["zeta.read", "beta.preview"]
        );
        assert_eq!(ranked.match_summary.result_limit, 2);
        assert_eq!(
            ranked.match_summary.truncation_reasons,
            vec!["result_limit"]
        );
    }

    #[test]
    fn ranked_search_fails_closed_when_a_supplied_query_has_no_searchable_terms() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("alpha.destroy")
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("zeta.read").with_risk_posture(GuardedActionPosture::read_only()),
        ])
        .expect("inventory");

        for query in ["please show me", "请删除", "---"] {
            let ranked = inventory.search_ranked(
                &ToolSearchFilter {
                    query: Some(query.to_string()),
                    limit: Some(1),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
            assert!(ranked.response.results.is_empty(), "query: {query}");
            assert_eq!(ranked.match_summary.total_matches, 0, "query: {query}");
        }

        let truncated_blank = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some(" ".repeat(RANKED_SEARCH_MAX_QUERY_CHARS + 1)),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(truncated_blank.response.results.is_empty());
        assert_eq!(truncated_blank.match_summary.total_matches, 0);
        assert!(truncated_blank
            .match_summary
            .truncation_reasons
            .contains(&"query_input".to_string()));

        let truncated_blank_group = inventory.search_ranked(
            &ToolSearchFilter {
                group: Some(format!(
                    "{}inventory",
                    " ".repeat(RANKED_SEARCH_MAX_GROUP_CHARS + 1)
                )),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(truncated_blank_group.response.results.is_empty());
        assert!(truncated_blank_group
            .match_summary
            .truncation_reasons
            .contains(&"group_input".to_string()));
    }

    #[test]
    fn ranked_search_does_not_invert_actions_or_match_lexical_collisions() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("article.unpublish")
                .with_risk_posture(GuardedActionPosture::destructive())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Remove an article.",
                    ["unpublish"],
                )),
            ToolCapability::new("article.publish")
                .with_risk_posture(GuardedActionPosture::preview())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Prepare article publication.",
                    ["publish"],
                )),
            ToolCapability::new("planet.destroy")
                .with_risk_posture(GuardedActionPosture::destructive()),
            ToolCapability::new("campaign.preview")
                .with_risk_posture(GuardedActionPosture::preview())
                .with_discovery(ToolDiscoveryMetadata::new("Preview campaign.", ["plan"])),
        ])
        .expect("inventory");

        let publish = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("publish".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(publish.match_summary.total_matches, 1);
        assert_eq!(publish.response.results[0].name, "article.publish");

        let plan = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("plan".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(plan.match_summary.total_matches, 1);
        assert_eq!(plan.response.results[0].name, "campaign.preview");
    }

    #[test]
    fn ranked_search_normalizes_common_short_and_irregular_plurals() {
        for (plural, singular) in [
            ("ads", "ad"),
            ("APIs", "api"),
            ("IDs", "id"),
            ("keys", "key"),
            ("jobs", "job"),
            ("logs", "log"),
            ("indices", "index"),
            ("matrices", "matrix"),
            ("queries", "query"),
            ("policies", "policy"),
            ("movies", "movie"),
            ("cookies", "cookie"),
            ("aliases", "alias"),
            ("repositories", "repository"),
            ("processes", "process"),
            ("searches", "search"),
            ("canvases", "canvas"),
            ("sizes", "size"),
            ("buses", "bus"),
            ("schemas", "schema"),
        ] {
            let variants = super::search_token_variants(plural);
            assert!(
                variants.contains(&plural.to_ascii_lowercase()),
                "original plural: {plural}"
            );
            assert!(variants.contains(&singular.to_string()), "plural: {plural}");
        }
        for protected in [
            "status", "analysis", "news", "series", "access", "canvas", "lens", "dns", "tls",
            "ops", "sms",
        ] {
            assert_eq!(
                super::search_token_variants(protected),
                vec![protected.to_string()],
                "protected singular: {protected}"
            );
        }
        let axes = super::search_token_variants("axes");
        assert!(axes.contains(&"axes".to_string()));
        assert!(axes.contains(&"axis".to_string()));
        assert!(axes.contains(&"axe".to_string()));
    }

    #[test]
    fn ranked_search_matches_regular_plurals_without_acronym_collisions() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("repository.read").with_read_only(true),
            ToolCapability::new("process.inspect").with_read_only(true),
            ToolCapability::new("search.run").with_read_only(true),
            ToolCapability::new("cookie.read").with_read_only(true),
            ToolCapability::new("alias.read").with_read_only(true),
            ToolCapability::new("canva.read").with_read_only(true),
            ToolCapability::new("canvas.read").with_read_only(true),
            ToolCapability::new("size.read").with_read_only(true),
            ToolCapability::new("bus.read").with_read_only(true),
            ToolCapability::new("schema.read").with_read_only(true),
            ToolCapability::new("op.read").with_read_only(true),
            ToolCapability::new("ops.read").with_read_only(true),
        ])
        .expect("inventory");

        for (query, expected) in [
            ("repositories", "repository.read"),
            ("processes", "process.inspect"),
            ("searches", "search.run"),
            ("cookies", "cookie.read"),
            ("aliases", "alias.read"),
            ("canvas", "canvas.read"),
            ("canvases", "canvas.read"),
            ("sizes", "size.read"),
            ("buses", "bus.read"),
            ("schemas", "schema.read"),
            ("ops", "ops.read"),
        ] {
            let ranked = inventory.search_ranked(
                &ToolSearchFilter {
                    query: Some(query.to_string()),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
            assert_eq!(ranked.match_summary.total_matches, 1, "query: {query}");
            assert_eq!(ranked.response.results[0].name, expected, "query: {query}");
        }

        let exclusion = ToolInventory::from_capabilities([
            ToolCapability::new("session.cookie")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Read a session cookie.",
                    ["cookie", "session"],
                )),
            ToolCapability::new("session.preview")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Preview a session.",
                    ["preview", "session"],
                )),
        ])
        .expect("exclusion inventory")
        .search_ranked(
            &ToolSearchFilter {
                query: Some("session without cookies".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(
            exclusion
                .response
                .results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["session.preview"]
        );
    }

    #[test]
    fn ranked_search_applies_default_and_hard_limits_with_explicit_reasons() {
        let inventory = ToolInventory::from_capabilities((0..105).map(|index| {
            ToolCapability::new(format!("tool.{index:03}"))
                .with_risk_posture(GuardedActionPosture::read_only())
        }))
        .expect("inventory");

        let default_page = inventory.search_ranked(
            &ToolSearchFilter::default(),
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(default_page.match_summary.total_matches, 105);
        assert_eq!(default_page.match_summary.returned_count, 20);
        assert_eq!(default_page.match_summary.result_limit, 20);
        assert_eq!(
            default_page.match_summary.truncation_reasons,
            vec!["result_limit"]
        );

        let clamped = inventory.search_ranked(
            &ToolSearchFilter {
                limit: Some(500),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(clamped.match_summary.returned_count, 100);
        assert_eq!(clamped.match_summary.result_limit, 100);
        assert_eq!(
            clamped.match_summary.truncation_reasons,
            vec!["result_limit_clamped", "result_limit"]
        );
    }

    #[test]
    fn ranked_search_bounds_query_and_result_metadata() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("bounded.tool")
            .with_read_only(true)
            .with_discovery(ToolDiscoveryMetadata::new(
                "d ".repeat((RANKED_SEARCH_MAX_DESCRIPTION_CHARS + 50) / 2 + 1),
                (0..(RANKED_SEARCH_MAX_KEYWORDS + 5)).map(|index| {
                    format!(
                        "{index:03}-{}",
                        "k".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS + 50)
                    )
                }),
            ))])
        .expect("inventory");
        let query = format!(
            "bounded {}",
            (0..50)
                .map(|index| format!("term{index}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some(query),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert_eq!(ranked.response.results.len(), 1);
        assert_eq!(
            ranked.response.results[0]
                .description
                .as_deref()
                .map(|value| value.chars().count()),
            Some(RANKED_SEARCH_MAX_DESCRIPTION_CHARS)
        );
        assert_eq!(
            ranked.response.results[0].keywords.len(),
            RANKED_SEARCH_MAX_KEYWORDS
        );
        for reason in ["normalized_query_terms", "result_metadata"] {
            assert!(
                ranked
                    .match_summary
                    .truncation_reasons
                    .contains(&reason.to_string()),
                "missing reason: {reason}"
            );
        }

        let overlong = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some(format!("bounded {}", "x".repeat(2_000))),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(overlong.response.results.is_empty());
        assert!(overlong
            .match_summary
            .truncation_reasons
            .contains(&"query_input".to_string()));

        let ignored = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some(
                    "bounded a an and are be by can could do does for from have how i in is it me my of on please should show that the this to want we would with you your"
                        .to_string(),
                ),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(ignored
            .match_summary
            .truncation_reasons
            .contains(&"ignored_query_terms".to_string()));
    }

    #[test]
    fn ranked_search_reports_metadata_bounds_that_can_hide_a_match() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("bounded.tool")
            .with_read_only(true)
            .with_discovery(ToolDiscoveryMetadata::new(
                format!("{} needle", "d".repeat(RANKED_SEARCH_MAX_DESCRIPTION_CHARS)),
                std::iter::empty::<&str>(),
            ))])
        .expect("inventory");
        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("needle".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert!(ranked.response.results.is_empty());
        assert_eq!(ranked.match_summary.total_matches, 0);
        assert!(ranked.match_summary.truncated);
        assert!(ranked
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));

        let hidden_exclusion =
            ToolInventory::from_capabilities([ToolCapability::new("campaign.hidden")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    format!(
                        "campaign {} delete",
                        "d".repeat(RANKED_SEARCH_MAX_DESCRIPTION_CHARS)
                    ),
                    ["campaign"],
                ))])
            .expect("hidden-exclusion inventory")
            .search_ranked(
                &ToolSearchFilter {
                    query: Some("campaign without delete".to_string()),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
        assert!(hidden_exclusion.response.results.is_empty());
        assert!(hidden_exclusion
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));

        let keyword_count =
            ToolInventory::from_capabilities([ToolCapability::new("bounded.keyword.count")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Bounded keyword count.",
                    (0..RANKED_SEARCH_MAX_KEYWORDS)
                        .map(|index| format!("a{index:03}"))
                        .chain(std::iter::once("zzzzneedle".to_string())),
                ))])
            .expect("keyword-count inventory")
            .search_ranked(
                &ToolSearchFilter {
                    query: Some("zzzzneedle".to_string()),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
        assert!(keyword_count.response.results.is_empty());
        assert!(keyword_count
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));

        let long_keyword = format!("{}needle", "x".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS));
        let keyword_length =
            ToolInventory::from_capabilities([ToolCapability::new("bounded.keyword.length")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Bounded keyword length.",
                    [long_keyword.clone()],
                ))])
            .expect("keyword-length inventory")
            .search_ranked(
                &ToolSearchFilter {
                    query: Some(long_keyword),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            );
        assert!(keyword_length.response.results.is_empty());
        assert!(keyword_length
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));

        let split_description = format!(
            "{} applydanger",
            "x".repeat(RANKED_SEARCH_MAX_DESCRIPTION_CHARS - 6)
        );
        let split_keyword = format!(
            "{} applydanger",
            "x".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS - 6)
        );
        let partial_inventory = ToolInventory::from_capabilities([
            ToolCapability::new("bounded.description.partial")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    split_description,
                    std::iter::empty::<&str>(),
                )),
            ToolCapability::new("bounded.keyword.partial")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new(
                    "Bounded keyword.",
                    [split_keyword],
                )),
        ])
        .expect("partial-token inventory");
        let partial_tokens = partial_inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("apply".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert!(partial_tokens.response.results.is_empty());
        assert!(partial_tokens
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));

        let partial_projection = partial_inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("bounded".to_string()),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(partial_projection.response.results.len(), 2);
        for result in &partial_projection.response.results {
            assert!(result
                .description
                .as_deref()
                .is_none_or(|description| !description.is_empty()));
            assert!(result.keywords.iter().all(|keyword| !keyword.is_empty()));
        }

        let identifier_bounds = ToolInventory::from_capabilities([
            ToolCapability::new("x".repeat(COMPACT_SEARCH_MAX_TOOL_NAME_CHARS + 1))
                .with_read_only(true),
            ToolCapability::new("inventory.read")
                .with_group("g".repeat(RANKED_SEARCH_MAX_GROUP_CHARS + 1))
                .with_read_only(true),
        ])
        .expect("identifier-bound inventory")
        .search_ranked(
            &ToolSearchFilter::default(),
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        assert_eq!(identifier_bounds.response.results.len(), 1);
        assert_eq!(identifier_bounds.response.results[0].name, "inventory.read");
        assert_eq!(
            identifier_bounds.response.results[0]
                .group
                .as_deref()
                .map(str::len),
            Some(RANKED_SEARCH_MAX_GROUP_CHARS)
        );
        assert!(identifier_bounds
            .match_summary
            .truncation_reasons
            .contains(&"result_metadata".to_string()));
    }

    #[test]
    fn ranked_search_bounds_an_overlong_group_and_fails_closed() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("inventory.read")
            .with_group("inventory")
            .with_read_only(true)])
        .expect("inventory");
        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                group: Some("g".repeat(RANKED_SEARCH_COMPACT_MAX_BYTES * 2)),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        assert!(ranked.response.results.is_empty());
        assert_eq!(
            ranked.response.group.as_deref().map(str::len),
            Some(RANKED_SEARCH_MAX_GROUP_CHARS)
        );
        assert!(ranked
            .match_summary
            .truncation_reasons
            .contains(&"group_input".to_string()));
        assert!(
            serde_json::to_vec(&ranked.to_compact_value())
                .expect("compact response serializes")
                .len()
                <= RANKED_SEARCH_COMPACT_MAX_BYTES
        );
    }

    #[test]
    fn ranked_compact_serialization_enforces_its_byte_budget() {
        let keywords = (0..RANKED_SEARCH_MAX_KEYWORDS)
            .map(|index| format!("{index:03}-{}", "k".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS)))
            .collect::<Vec<_>>();
        let inventory = ToolInventory::from_capabilities((0..100).map(|index| {
            ToolCapability::new(format!("tool.{index:03}"))
                .with_risk_posture(GuardedActionPosture::read_only())
                .with_discovery(ToolDiscoveryMetadata::new(
                    "d".repeat(RANKED_SEARCH_MAX_DESCRIPTION_CHARS),
                    keywords.clone(),
                ))
        }))
        .expect("inventory");
        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                limit: Some(100),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );

        let compact = ranked.to_compact_value();
        let bytes = serde_json::to_vec(&compact).expect("compact response serializes");
        assert!(bytes.len() <= RANKED_SEARCH_COMPACT_MAX_BYTES);
        let returned_count = compact["match_summary"]["returned_count"]
            .as_u64()
            .expect("returned count") as usize;
        assert!(returned_count > 0 && returned_count < 100);
        assert_eq!(
            compact["results"]
                .as_array()
                .expect("results")
                .iter()
                .map(|result| result["name"].as_str().expect("result name").to_string())
                .collect::<Vec<_>>(),
            (0..returned_count)
                .map(|index| format!("tool.{index:03}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(compact["match_summary"]["truncated"], true);
        assert!(compact["match_summary"]["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.contains(&json!("compact_response_bytes"))));
    }

    #[test]
    fn ranked_compact_serialization_bounds_caller_constructed_metadata() {
        let oversized = "x".repeat(RANKED_SEARCH_COMPACT_MAX_BYTES * 2);
        let ranked = RankedToolSearchResponse {
            response: ToolSearchResponse::find_tools(
                Some(oversized.clone()),
                Some(oversized.clone()),
                Some(true),
                Vec::new(),
            ),
            match_summary: ToolSearchMatchSummary {
                total_matches: 42,
                returned_count: 0,
                result_limit: 17,
                truncated: true,
                truncation_reasons: vec![oversized.clone()],
                normalized_query_terms: vec![oversized.clone()],
                excluded_query_terms: vec![oversized.clone()],
                ignored_query_terms: vec![oversized],
            },
        };

        let compact = ranked.to_compact_value();
        let bytes = serde_json::to_vec(&compact).expect("compact response serializes");
        assert!(bytes.len() <= RANKED_SEARCH_COMPACT_MAX_BYTES);
        assert_eq!(
            compact["query"].as_str().map(str::len),
            Some(RANKED_SEARCH_MAX_QUERY_CHARS)
        );
        assert_eq!(
            compact["group"].as_str().map(str::len),
            Some(RANKED_SEARCH_MAX_GROUP_CHARS)
        );
        assert_eq!(compact["match_summary"]["total_matches"], 42);
        assert_eq!(compact["match_summary"]["returned_count"], 0);
        assert_eq!(compact["match_summary"]["result_limit"], 17);
        assert!(compact["match_summary"]["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.contains(&json!("compact_response_bytes"))));
        assert_eq!(
            compact["match_summary"]["normalized_query_terms"][0]
                .as_str()
                .map(str::len),
            Some(RANKED_SEARCH_MAX_KEYWORD_CHARS)
        );

        let distinct_unicode_terms = |count: usize| {
            (0..count)
                .map(|index| {
                    let unique = char::from_u32(0x1F600 + index as u32).expect("valid emoji");
                    format!(
                        "{unique}{}",
                        "😀".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS - 1)
                    )
                })
                .collect::<Vec<_>>()
        };
        let retained_result = ToolSearchResult {
            name: "safe.read".to_string(),
            group: None,
            read_only: true,
            description: Some("Read safely".to_string()),
            keywords: vec!["safe".to_string()],
            risk_posture: Some(GuardedActionPosture::read_only()),
        };
        let mut custom_response =
            ToolSearchResponse::find_tools(None, None, Some(true), vec![retained_result.clone()]);
        custom_response.operation = "custom_ranked_discovery".to_string();
        let custom = RankedToolSearchResponse {
            response: custom_response,
            match_summary: ToolSearchMatchSummary {
                total_matches: 1,
                returned_count: 1,
                result_limit: 20,
                truncated: false,
                truncation_reasons: Vec::new(),
                normalized_query_terms: distinct_unicode_terms(RANKED_SEARCH_MAX_QUERY_TERMS),
                excluded_query_terms: distinct_unicode_terms(RANKED_SEARCH_MAX_EXCLUDED_TERMS),
                ignored_query_terms: distinct_unicode_terms(RANKED_SEARCH_MAX_IGNORED_TERMS),
            },
        };
        let (bounded_summary, _) = super::compact_match_summary(&custom.match_summary);
        let pre_fallback = super::with_match_summary(
            custom.response.compact_value_from_bounded_fields(),
            &bounded_summary,
        );
        assert!(
            serde_json::to_vec(&pre_fallback)
                .expect("pre-fallback ranked response serializes")
                .len()
                > RANKED_SEARCH_COMPACT_MAX_BYTES
        );
        let custom_compact = custom.to_compact_value();
        assert_eq!(custom_compact["operation"], "custom_ranked_discovery");
        assert_eq!(custom_compact["results"][0]["name"], "safe.read");
        assert_eq!(custom_compact["openai_allowed_tools"], json!(["safe.read"]));
        assert_eq!(custom_compact["match_summary"]["returned_count"], 1);
        assert_eq!(
            custom_compact["match_summary"]["normalized_query_terms"],
            json!([])
        );
        assert!(
            serde_json::to_vec(&custom_compact)
                .expect("custom compact ranked response serializes")
                .len()
                <= RANKED_SEARCH_COMPACT_MAX_BYTES
        );
    }

    #[test]
    fn ranked_search_serializers_make_completeness_and_payload_cost_explicit() {
        let inventory = ToolInventory::from_capabilities([ToolCapability::new("ads.read")
            .with_read_only(true)
            .with_discovery(ToolDiscoveryMetadata::new(
                "Read advertising inventory",
                ["ad", "inventory"],
            ))])
        .expect("inventory");
        let ranked = inventory
            .search_ranked(
                &ToolSearchFilter {
                    query: Some("show me ads".to_string()),
                    ..ToolSearchFilter::default()
                },
                ToolOperation::List,
                &ToolInventoryPolicy::strict(),
            )
            .with_schemas(Some(json!({"ads.read": {"input": {"type": "object"}}})))
            .with_metadata_label("unit-test");

        let full = ranked.to_value();
        assert_eq!(full["match_summary"]["total_matches"], json!(1));
        assert_eq!(full["match_summary"]["returned_count"], json!(1));
        assert_eq!(full["match_summary"]["result_limit"], json!(20));
        assert_eq!(full["match_summary"]["truncated"], json!(false));
        assert_eq!(full["match_summary"]["truncation_reasons"], json!([]));
        assert_eq!(
            full["match_summary"]["normalized_query_terms"],
            json!(["ads"])
        );
        assert_eq!(full["match_summary"]["excluded_query_terms"], json!([]));
        assert_eq!(
            full["match_summary"]["ignored_query_terms"],
            json!(["show", "me"])
        );
        assert!(full.get("schemas").is_some());
        assert!(full.get("openai_deferred_loading").is_some());

        let compact = ranked.to_compact_value();
        assert_eq!(
            compact,
            json!({
                "operation":"find_tools",
                "query":"show me ads",
                "group":null,
                "read_only":null,
                "results":[{
                    "type":"tool",
                    "name":"ads.read",
                    "group":null,
                    "read_only":true,
                    "description":"Read advertising inventory",
                    "keywords":["ad", "inventory"],
                    "risk_posture":null
                }],
                "openai_allowed_tools":["ads.read"],
                "match_summary":{
                    "total_matches":1,
                    "returned_count":1,
                    "result_limit":20,
                    "truncated":false,
                    "truncation_reasons":[],
                    "normalized_query_terms":["ads"],
                    "excluded_query_terms":[],
                    "ignored_query_terms":["show", "me"]
                }
            })
        );

        let openai = ranked
            .into_openai_response()
            .with_companion_allowed_tools(["api_read"])
            .with_extra_results([json!({
                "type":"api_operation",
                "name":"api_read",
                "read_only":true
            })])
            .to_value();
        assert_eq!(openai["match_summary"], full["match_summary"]);
        assert_eq!(
            openai["openai_allowed_tools"],
            json!(["ads.read", "api_read"])
        );
        assert_eq!(openai["results"][1]["name"], "api_read");
    }

    #[test]
    fn ranked_search_honors_policy_group_and_read_only_filters() {
        let inventory = ToolInventory::from_capabilities([
            ToolCapability::new("inventory.read")
                .with_group("inventory")
                .with_read_only(true)
                .with_discovery(ToolDiscoveryMetadata::new("Read inventory", ["inventory"])),
            ToolCapability::new("inventory.write")
                .with_group("inventory")
                .with_discovery(ToolDiscoveryMetadata::new("Write inventory", ["inventory"])),
            ToolCapability::new("admin.inventory")
                .with_group("admin")
                .with_read_only(true)
                .with_feature_flag("admin")
                .with_discovery(ToolDiscoveryMetadata::new("Read inventory", ["inventory"])),
        ])
        .expect("inventory");

        let ranked = inventory.search_ranked(
            &ToolSearchFilter {
                query: Some("inventory".to_string()),
                group: Some("inventory".to_string()),
                read_only: Some(true),
                limit: None,
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict_read_only().with_allowed_groups(["inventory"]),
        );

        assert_eq!(ranked.match_summary.total_matches, 1);
        assert_eq!(ranked.response.results[0].name, "inventory.read");
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

        let compact = response.to_compact_value();
        assert!(compact.get("schemas").is_none());
        assert!(compact.get("openai_deferred_loading").is_none());
        assert_eq!(compact["openai_allowed_tools"], json!(["cache.list"]));
    }

    #[test]
    fn compact_search_response_bounds_inputs_before_selection_serialization() {
        let oversized = "x".repeat(RANKED_SEARCH_COMPACT_MAX_BYTES * 2);
        let response = ToolSearchResponse::find_tools(
            Some(oversized.clone()),
            Some(oversized.clone()),
            Some(true),
            vec![
                super::ToolSearchResult {
                    name: "cache.list".to_string(),
                    group: Some("cache".to_string()),
                    read_only: true,
                    description: Some("List cache settings".to_string()),
                    keywords: vec!["cache".to_string()],
                    risk_posture: None,
                },
                super::ToolSearchResult {
                    name: oversized.clone(),
                    group: Some(oversized.clone()),
                    read_only: false,
                    description: Some(oversized.clone()),
                    keywords: vec![oversized.clone(); RANKED_SEARCH_MAX_KEYWORDS + 1],
                    risk_posture: Some(GuardedActionPosture::destructive()),
                },
                super::ToolSearchResult {
                    name: "cache.after-rejected".to_string(),
                    group: Some("cache".to_string()),
                    read_only: true,
                    description: Some("Must not cross a rejected prefix entry".to_string()),
                    keywords: vec!["cache".to_string()],
                    risk_posture: None,
                },
            ],
        )
        .with_schemas(Some(json!({"oversized": oversized})));

        let compact = response.to_compact_value();
        assert!(
            serde_json::to_vec(&compact)
                .expect("compact response serializes")
                .len()
                <= RANKED_SEARCH_COMPACT_MAX_BYTES
        );
        assert!(compact.get("schemas").is_none());
        assert_eq!(compact["openai_allowed_tools"], json!(["cache.list"]));
        assert_eq!(compact["compact_summary"]["source_count"], 3);
        assert_eq!(compact["compact_summary"]["returned_count"], 1);
        assert_eq!(compact["compact_summary"]["truncated"], true);
        assert!(compact["compact_summary"]["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| {
                reasons.contains(&json!("input_metadata"))
                    && reasons.contains(&json!("result_metadata"))
            }));
    }

    #[test]
    fn compact_search_response_retains_the_source_prefix_across_all_caps() {
        let keywords = (0..RANKED_SEARCH_MAX_KEYWORDS)
            .map(|index| format!("{index:03}-{}", "k".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS)))
            .collect::<Vec<_>>();
        let response = ToolSearchResponse::find_tools(
            Some("inventory".to_string()),
            None,
            Some(true),
            (0..101)
                .map(|index| super::ToolSearchResult {
                    name: format!("tool.{index:03}"),
                    group: Some("inventory".to_string()),
                    read_only: true,
                    description: Some("d".repeat(RANKED_SEARCH_MAX_DESCRIPTION_CHARS)),
                    keywords: keywords.clone(),
                    risk_posture: Some(GuardedActionPosture::read_only()),
                })
                .collect(),
        );

        let compact = response.to_compact_value();
        let returned_count = compact["compact_summary"]["returned_count"]
            .as_u64()
            .expect("returned count") as usize;
        assert!(returned_count > 0 && returned_count < 100);
        assert_eq!(compact["compact_summary"]["source_count"], 101);
        assert_eq!(compact["compact_summary"]["truncated"], true);
        assert!(compact["compact_summary"]["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| {
                reasons.contains(&json!("result_limit"))
                    && reasons.contains(&json!("compact_response_bytes"))
            }));
        assert_eq!(
            compact["results"]
                .as_array()
                .expect("results")
                .iter()
                .map(|result| result["name"].as_str().expect("result name").to_string())
                .collect::<Vec<_>>(),
            (0..returned_count)
                .map(|index| format!("tool.{index:03}"))
                .collect::<Vec<_>>()
        );
        assert!(
            serde_json::to_vec(&compact)
                .expect("compact response serializes")
                .len()
                <= RANKED_SEARCH_COMPACT_MAX_BYTES
        );
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
    fn compact_openai_responses_bound_all_extensions_and_retain_prefixes() {
        let oversized = "x".repeat(super::COMPACT_OPENAI_MAX_EXTRA_RESULT_TEXT_CHARS + 1);
        let plain = ToolSearchResponse::find_tools(
            Some("inventory".to_string()),
            None,
            Some(true),
            vec![super::ToolSearchResult {
                name: "inventory.read".to_string(),
                group: Some("inventory".to_string()),
                read_only: true,
                description: Some("Read inventory".to_string()),
                keywords: vec!["inventory".to_string()],
                risk_posture: Some(GuardedActionPosture::read_only()),
            }],
        )
        .with_schemas(Some(json!({"inventory.read":{"type":"object"}})))
        .into_openai_response()
        .with_extra_results([
            json!({"type":"api_operation","name":"extra.before"}),
            json!({"name":"oversized","payload":oversized}),
            json!({"type":"api_operation","name":"extra.after"}),
        ]);
        let plain_compact = plain.to_compact_value();
        assert!(plain_compact.get("schemas").is_none());
        assert!(plain_compact.get("openai_deferred_loading").is_none());
        assert_eq!(plain_compact["compact_summary"]["extra_source_count"], 3);
        assert_eq!(plain_compact["compact_summary"]["extra_returned_count"], 1);
        assert_eq!(plain_compact["results"][1]["name"], "extra.before");
        assert!(plain_compact["compact_summary"]["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.contains(&json!("extra_result_metadata"))));

        let companion_compact = ToolSearchResponse::find_tools(None, None, None, Vec::new())
            .into_openai_response()
            .with_companion_allowed_tools([
                format!(
                    "campaign.{}apply",
                    "x".repeat(COMPACT_SEARCH_MAX_TOOL_NAME_CHARS + 1)
                ),
                "inventory.read".to_string(),
            ])
            .to_compact_value();
        assert_eq!(
            companion_compact["openai_allowed_tools"],
            json!(["inventory.read"])
        );
        assert_eq!(
            companion_compact["compact_summary"]["companion_source_count"],
            2
        );
        assert_eq!(
            companion_compact["compact_summary"]["companion_returned_count"],
            1
        );
        assert!(companion_compact["compact_summary"]["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.contains(&json!("companion_tool_metadata"))));

        let keywords = (0..RANKED_SEARCH_MAX_KEYWORDS)
            .map(|index| format!("{index:03}-{}", "k".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS)))
            .collect::<Vec<_>>();
        let response = ToolSearchResponse::find_tools(
            Some("inventory".to_string()),
            None,
            Some(true),
            (0..2)
                .map(|index| super::ToolSearchResult {
                    name: format!("tool.{index:03}"),
                    group: Some("inventory".to_string()),
                    read_only: true,
                    description: Some("d".repeat(RANKED_SEARCH_MAX_DESCRIPTION_CHARS)),
                    keywords: keywords.clone(),
                    risk_posture: Some(GuardedActionPosture::read_only()),
                })
                .collect(),
        );
        let ranked = RankedToolSearchResponse {
            response,
            match_summary: ToolSearchMatchSummary {
                total_matches: 2,
                returned_count: 2,
                result_limit: 2,
                truncated: false,
                truncation_reasons: Vec::new(),
                normalized_query_terms: vec!["inventory".to_string()],
                excluded_query_terms: Vec::new(),
                ignored_query_terms: Vec::new(),
            },
        }
        .into_openai_response()
        .with_companion_allowed_tools(
            (0..(super::COMPACT_OPENAI_MAX_COMPANION_TOOLS + 1))
                .map(|index| format!("companion.{index:03}")),
        )
        .with_extra_results(
            (0..(super::COMPACT_OPENAI_MAX_EXTRA_RESULTS + 1)).map(|index| {
                json!({
                    "type":"api_operation",
                    "name":format!("extra.{index:03}"),
                    "description":"e".repeat(1_024)
                })
            }),
        );

        let compact = ranked.to_compact_value();
        assert!(
            serde_json::to_vec(&compact)
                .expect("compact OpenAI response serializes")
                .len()
                <= RANKED_SEARCH_COMPACT_MAX_BYTES
        );
        assert!(compact.get("schemas").is_none());
        assert!(compact.get("openai_deferred_loading").is_none());
        let inventory_returned = compact["compact_summary"]["returned_count"]
            .as_u64()
            .expect("inventory returned count") as usize;
        let extra_returned = compact["compact_summary"]["extra_returned_count"]
            .as_u64()
            .expect("extra returned count") as usize;
        assert!(inventory_returned > 0);
        assert!(extra_returned > 0);
        let results = compact["results"].as_array().expect("results");
        assert_eq!(
            results[..inventory_returned]
                .iter()
                .map(|result| result["name"].as_str().expect("inventory name").to_string())
                .collect::<Vec<_>>(),
            (0..inventory_returned)
                .map(|index| format!("tool.{index:03}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            results[inventory_returned..]
                .iter()
                .map(|result| result["name"].as_str().expect("extra name").to_string())
                .collect::<Vec<_>>(),
            (0..extra_returned)
                .map(|index| format!("extra.{index:03}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            compact["match_summary"]["returned_count"],
            json!(inventory_returned)
        );
        assert!(compact["compact_summary"]["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| {
                reasons.contains(&json!("companion_tool_limit"))
                    && reasons.contains(&json!("extra_result_limit"))
                    && reasons.contains(&json!("compact_response_bytes"))
            }));

        let unicode_terms = |count: usize| {
            (0..count)
                .map(|index| {
                    let unique = char::from_u32(0x1F600 + index as u32).expect("valid emoji");
                    format!(
                        "{unique}{}",
                        "😀".repeat(RANKED_SEARCH_MAX_KEYWORD_CHARS - 1)
                    )
                })
                .collect::<Vec<_>>()
        };
        let unicode_ranked = RankedToolSearchResponse {
            response: ToolSearchResponse::find_tools(
                None,
                None,
                Some(true),
                vec![ToolSearchResult {
                    name: "safe.read".to_string(),
                    group: None,
                    read_only: true,
                    description: Some("Read safely".to_string()),
                    keywords: vec!["safe".to_string()],
                    risk_posture: Some(GuardedActionPosture::read_only()),
                }],
            ),
            match_summary: ToolSearchMatchSummary {
                total_matches: 1,
                returned_count: 1,
                result_limit: 20,
                truncated: false,
                truncation_reasons: Vec::new(),
                normalized_query_terms: unicode_terms(RANKED_SEARCH_MAX_QUERY_TERMS),
                excluded_query_terms: unicode_terms(RANKED_SEARCH_MAX_EXCLUDED_TERMS),
                ignored_query_terms: unicode_terms(RANKED_SEARCH_MAX_IGNORED_TERMS),
            },
        };
        let (bounded_unicode_summary, _) =
            super::compact_match_summary(&unicode_ranked.match_summary);
        let unicode_openai = unicode_ranked.into_openai_response();
        let pre_fallback = super::with_match_summary(
            unicode_openai.response.compact_projection().to_value(),
            &bounded_unicode_summary,
        );
        assert!(
            serde_json::to_vec(&pre_fallback)
                .expect("pre-fallback Unicode response serializes")
                .len()
                > RANKED_SEARCH_COMPACT_MAX_BYTES
        );
        let unicode_summary = unicode_openai.to_compact_value();
        assert!(
            serde_json::to_vec(&unicode_summary)
                .expect("Unicode compact response serializes")
                .len()
                <= RANKED_SEARCH_COMPACT_MAX_BYTES
        );
        assert_eq!(unicode_summary["results"][0]["name"], "safe.read");
        assert_eq!(
            unicode_summary["openai_allowed_tools"],
            json!(["safe.read"])
        );
        assert_eq!(unicode_summary["match_summary"]["returned_count"], 1);
        assert_eq!(
            unicode_summary["match_summary"]["normalized_query_terms"],
            json!([])
        );
        assert_eq!(
            unicode_summary["match_summary"]["excluded_query_terms"],
            json!([])
        );
        assert_eq!(
            unicode_summary["match_summary"]["ignored_query_terms"],
            json!([])
        );
        assert_eq!(
            unicode_summary["match_summary"]["truncation_reasons"],
            json!(["compact_response_bytes"])
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
            ))
            .with_input_schema(json!({
                "type": "object",
                "properties": {
                    "id": {"type": "string"}
                },
                "required": ["id"]
            }));
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
        let response_schemas = response["schemas"].as_object().expect("schemas object");
        assert!(!response_schemas.contains_key("items.update"));

        let empty_response = catalog
            .search_response_for_profile(
                &ToolSearchFilter {
                    query: Some("missing".to_string()),
                    group: Some("items".to_string()),
                    read_only: Some(true),
                    limit: None,
                },
                ToolOperation::List,
                &catalog.profiles()[0],
            )
            .to_value();
        assert_eq!(empty_response["openai_allowed_tools"], json!([]));
        assert_eq!(empty_response["schemas"], json!({}));

        let ranked = catalog.ranked_search_response(
            &ToolSearchFilter {
                query: Some("items".to_string()),
                limit: Some(1),
                ..ToolSearchFilter::default()
            },
            ToolOperation::List,
            &ToolInventoryPolicy::strict(),
        );
        let ranked_full = ranked.to_value();
        assert_eq!(ranked_full["match_summary"]["total_matches"], 2);
        assert_eq!(ranked_full["match_summary"]["returned_count"], 1);
        assert_eq!(ranked_full["match_summary"]["truncated"], true);
        assert_eq!(ranked_full["openai_allowed_tools"], json!(["items.search"]));
        assert!(ranked_full["schemas"].get("items.search").is_some());
        assert!(ranked_full["schemas"].get("items.update").is_none());
        let ranked_compact = ranked.to_compact_value();
        assert!(ranked_compact.get("schemas").is_none());
        assert_eq!(
            ranked_compact["match_summary"],
            ranked_full["match_summary"]
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
        assert_eq!(
            snapshot["schemas"]["items.update"]["input"]["properties"]["id"]["type"],
            json!("string")
        );
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

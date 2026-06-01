//! # Gemini MCP Service
//!
//! Reusable MCP tool router and server handler for Gemini CLI-backed tools.
//!
//! ## Rationale
//! Provide one canonical implementation of Gemini tool contracts while letting
//! transport wrappers remain thin in server repos.
//!
//! ## Security Boundaries
//! * Defers process execution to policy-aware executor.
//! * Returns structured errors without exposing environment values.
//!
//! ## References
//! * `mcp-workspace/servers/gemini-cli-mcp-rs`

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_router, ErrorData, RoleServer, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::config::{AskGeminiPolicy, GeminiExecutionConfig, GeminiExecutionRawConfig};
use crate::executor::{
    execute_gemini_with_cancel, GeminiExecutionError, GeminiOutputFormat, GeminiPromptTransport,
    GeminiRequest,
};

fn codebase_scout_prompt(target: &str, question: &str) -> String {
    format!(
        "You are a codebase scout.\n\n\
Target path: {target}\n\
Question: {question}\n\n\
Execution strategy:\n\
1. If tool `delegate_to_agent` is available, call it exactly once with:\n\
   {{\"agent_name\":\"codebase_investigator\",\"objective\":\"Investigate target {target}. Question: {question}\"}}\n\
2. If `delegate_to_agent` is unavailable but tool `codebase_investigator` exists, call:\n\
   {{\"objective\":\"Investigate target {target}. Question: {question}\"}}\n\
3. If neither delegation path exists, run a direct investigation yourself.\n\
4. Convert final findings into the exact JSON schema below.\n\n\
Hard rules:\n\
- Use only evidence from files under the target path.\n\
- Do not invent files, symbols, behavior, or outcomes.\n\
- If you cannot access target files, set status to NO_ACCESS and explain why.\n\
- Prefer concrete references: path, symbol/function, and one-sentence relevance.\n\
- Keep output concise and technical.\n\
    - Do not emit planning chatter, scratchpads, XML, or markdown.\n\
    - Output must be a single JSON object only.\n\
    - Do not repeat the input question or target path in the response payload.\n\n\
Return JSON only with this schema:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"top_hits\": [\n\
    {{\"path\": \"string\", \"symbol\": \"string|null\", \"reason\": \"string\"}}\n\
  ],\n\
  \"findings\": [\"string\"],\n\
  \"risks\": [\"string\"],\n\
  \"next_steps\": [\"string\"],\n\
  \"search_terms\": [\"string\"]\n\
}}"
    )
}

fn codebase_scout_fallback_prompt(target: &str, question: &str) -> String {
    format!(
        "Codebase scout fallback.\n\
Target path: {target}\n\
Question: {question}\n\n\
If delegation is available, call `delegate_to_agent` with:\n\
{{\"agent_name\":\"codebase_investigator\",\"objective\":\"Investigate target {target}. Question: {question}\"}}\n\
Output must be exactly one JSON object.\n\
Return JSON only:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"top_hits\": [{{\"path\": \"string\", \"symbol\": \"string|null\", \"reason\": \"string\"}}],\n\
  \"findings\": [\"string\"],\n\
  \"next_steps\": [\"string\"]\n\
}}"
    )
}

fn codebase_investigator_prompt(target: &str, objective: &str) -> String {
    format!(
        "You are running a deep code investigation.\n\n\
Target path: {target}\n\
Objective: {objective}\n\n\
Execution strategy:\n\
1. If tool `delegate_to_agent` is available, call it exactly once with:\n\
   {{\"agent_name\":\"codebase_investigator\",\"objective\":\"{objective} (target: {target})\"}}\n\
2. If `delegate_to_agent` is unavailable but tool `codebase_investigator` exists, call:\n\
   {{\"objective\":\"{objective} (target: {target})\"}}\n\
3. If neither delegation path exists, perform a direct deep investigation yourself.\n\
4. Include architecture impact and concrete change locations.\n\n\
Hard rules:\n\
- Use only evidence from files under the target path.\n\
- Do not invent files, symbols, behavior, or outcomes.\n\
- If target files are inaccessible, set status to NO_ACCESS.\n\
- Keep output concise, technical, and implementation-oriented.\n\
    - Do not emit scratchpads, XML, markdown, or explanatory preamble.\n\
    - Output must be a single JSON object only.\n\
    - Do not repeat the objective or target path in the response payload.\n\n\
Return JSON only with this schema:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"summary\": \"string\",\n\
  \"relevant_locations\": [\n\
    {{\"path\": \"string\", \"reason\": \"string\", \"key_symbols\": [\"string\"]}}\n\
  ],\n\
  \"impact_map\": [\"string\"],\n\
  \"action_plan\": [\"string\"],\n\
  \"evidence_gaps\": [\"string\"]\n\
}}"
    )
}

fn codebase_investigator_fallback_prompt(target: &str, objective: &str) -> String {
    format!(
        "Codebase investigator fallback.\n\
Target path: {target}\n\
Objective: {objective}\n\n\
If available, call `delegate_to_agent` with:\n\
{{\"agent_name\":\"codebase_investigator\",\"objective\":\"{objective} (target: {target})\"}}\n\
Output must be exactly one JSON object.\n\
Return JSON only:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"summary\": \"string\",\n\
  \"relevant_locations\": [{{\"path\": \"string\", \"reason\": \"string\", \"key_symbols\": [\"string\"]}}],\n\
  \"action_plan\": [\"string\"]\n\
}}"
    )
}

/// Summary: reusable MCP server implementation that exposes Gemini tools.
///
/// # Errors
/// * Tool-level errors are surfaced as structured responses.
///
/// # Security
/// * Uses execution policy from [`GeminiExecutionConfig`] for every call.
///
/// # Panics
/// * Does not panic.
#[derive(Clone)]
pub struct GeminiMcp {
    config: Arc<GeminiExecutionConfig>,
    tool_router: ToolRouter<GeminiMcp>,
}

#[derive(Debug, Serialize)]
struct ValidationIssue {
    field: String,
    code: String,
    expected_type: String,
    received_type: String,
    corrective_hint: String,
}

#[derive(Debug, Clone)]
struct ResolvedModel {
    requested: Option<String>,
    used: Option<String>,
    default_model_applied: bool,
    fallback_mode: &'static str,
    fallback_reason: Option<String>,
}

#[derive(Debug)]
enum ErrorCategory {
    InputValidation,
    ModelNotAllowed,
    ModelNotFound,
    AuthSessionInvalid,
    FileAccess,
    QuotaOrRateLimit,
    NetworkOrTransport,
}

impl ErrorCategory {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InputValidation => "input_validation",
            Self::ModelNotAllowed => "model_not_allowed",
            Self::ModelNotFound => "model_not_found",
            Self::AuthSessionInvalid => "auth_session_invalid",
            Self::FileAccess => "file_access",
            Self::QuotaOrRateLimit => "quota_or_rate_limit",
            Self::NetworkOrTransport => "network_or_transport",
        }
    }
}

fn validate_required_text_field(
    field: &str,
    value: &str,
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        errors.push(ValidationIssue {
            field: field.to_string(),
            code: "invalid_value".to_string(),
            expected_type: "non-empty string".to_string(),
            received_type: "string".to_string(),
            corrective_hint: format!("Set {field} to a non-empty string."),
        });
        None
    } else {
        Some(value.to_string())
    }
}

fn validate_target_within_include_directories(
    target: &str,
    include_directories: &[String],
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let target = validate_required_text_field("target", target, errors)?;
    if include_directories.is_empty() {
        return Some(target);
    }

    let canonical_target = match std::fs::canonicalize(&target) {
        Ok(path) => path,
        Err(err) => {
            errors.push(ValidationIssue {
                field: "target".to_string(),
                code: "invalid_value".to_string(),
                expected_type: "existing path inside configured include directories".to_string(),
                received_type: "string".to_string(),
                corrective_hint: format!("Set target to an existing path. Details: {err}"),
            });
            return None;
        }
    };

    let mut roots = Vec::<PathBuf>::new();
    let mut root_labels = Vec::<String>::new();
    for raw_root in include_directories {
        let root = raw_root.trim();
        if root.is_empty() {
            continue;
        }
        match std::fs::canonicalize(root) {
            Ok(path) if path.is_dir() => {
                root_labels.push(path.display().to_string());
                roots.push(path);
            }
            Ok(path) => {
                errors.push(ValidationIssue {
                    field: "target".to_string(),
                    code: "server_config_invalid".to_string(),
                    expected_type: "directory path".to_string(),
                    received_type: "file path".to_string(),
                    corrective_hint: format!(
                        "Configured include directory '{root}' resolves to '{}' which is not a directory.",
                        path.display()
                    ),
                });
                return None;
            }
            Err(err) => {
                errors.push(ValidationIssue {
                    field: "target".to_string(),
                    code: "server_config_invalid".to_string(),
                    expected_type: "existing include directory".to_string(),
                    received_type: "missing/unreadable path".to_string(),
                    corrective_hint: format!(
                        "Configured include directory '{root}' is invalid: {err}"
                    ),
                });
                return None;
            }
        }
    }

    if !roots.iter().any(|root| canonical_target.starts_with(root)) {
        errors.push(ValidationIssue {
            field: "target".to_string(),
            code: "out_of_scope".to_string(),
            expected_type: "path under configured include directories".to_string(),
            received_type: "string".to_string(),
            corrective_hint: format!("Set target under one of: {}.", root_labels.join(", ")),
        });
        return None;
    }

    Some(target)
}

fn normalize_optional_model_field(
    field: &str,
    value: Option<String>,
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let raw = value?;
    let value = raw.trim();
    if value.is_empty() {
        errors.push(ValidationIssue {
            field: field.to_string(),
            code: "invalid_value".to_string(),
            expected_type: "non-empty string".to_string(),
            received_type: "string".to_string(),
            corrective_hint: format!("Set {field} to a non-empty string or omit it."),
        });
        None
    } else {
        Some(value.to_string())
    }
}

fn normalize_model_list(models: &[String]) -> Vec<String> {
    models
        .iter()
        .map(|model| model.trim().to_string())
        .filter(|model| !model.is_empty())
        .collect()
}

fn find_allowlisted_model(allowlist: &[String], requested: &str) -> Option<String> {
    allowlist
        .iter()
        .find(|candidate| candidate.eq_ignore_ascii_case(requested))
        .cloned()
}

fn resolve_model(
    config: &GeminiExecutionConfig,
    requested: Option<String>,
) -> Result<ResolvedModel, ErrorCategory> {
    let normalized_requested = requested
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let allowlist = normalize_model_list(&config.model_allowlist);
    let allowlist_is_empty = allowlist.is_empty();

    let default_model = config.default_model.as_ref().and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    });

    if allowlist_is_empty {
        return if let Some(model) = normalized_requested {
            Ok(ResolvedModel {
                requested: Some(model.clone()),
                used: Some(model),
                default_model_applied: false,
                fallback_mode: "requested",
                fallback_reason: None,
            })
        } else if let Some(default_model) = default_model {
            Ok(ResolvedModel {
                requested: None,
                used: Some(default_model),
                default_model_applied: true,
                fallback_mode: "configured_default",
                fallback_reason: None,
            })
        } else {
            Ok(ResolvedModel {
                requested: None,
                used: None,
                default_model_applied: false,
                fallback_mode: "none",
                fallback_reason: None,
            })
        };
    }

    if let Some(requested) = normalized_requested.clone() {
        if let Some(allowlisted_model) = find_allowlisted_model(&allowlist, &requested) {
            return Ok(ResolvedModel {
                requested: Some(requested.clone()),
                used: Some(allowlisted_model),
                default_model_applied: false,
                fallback_mode: "requested",
                fallback_reason: None,
            });
        }
        return Err(ErrorCategory::ModelNotAllowed);
    }

    if let Some(default_model) = default_model {
        if let Some(allowlisted_model) = find_allowlisted_model(&allowlist, &default_model) {
            return Ok(ResolvedModel {
                requested: None,
                used: Some(allowlisted_model),
                default_model_applied: true,
                fallback_mode: "configured_default",
                fallback_reason: None,
            });
        }
        let Some(fallback_model) = allowlist.first().cloned() else {
            return Err(ErrorCategory::ModelNotFound);
        };
        return Ok(ResolvedModel {
            requested: None,
            used: Some(fallback_model.clone()),
            default_model_applied: false,
            fallback_mode: "allowlist_default",
            fallback_reason: Some(format!(
                "Configured default model was not allowlisted; using '{fallback_model}'."
            )),
        });
    }

    let Some(fallback_model) = allowlist.first().cloned() else {
        return Err(ErrorCategory::ModelNotFound);
    };
    Ok(ResolvedModel {
        requested: None,
        used: Some(fallback_model.clone()),
        default_model_applied: false,
        fallback_mode: "allowlist_default",
        fallback_reason: Some("No model was provided; using first allowlist model.".to_string()),
    })
}

fn response_with_metadata(
    base: Value,
    validation_errors: &[ValidationIssue],
    model: &ResolvedModel,
) -> CallToolResult {
    let Value::Object(mut object) = base else {
        return CallToolResult::structured(base);
    };

    object.insert("validation_errors".to_string(), json!(validation_errors));
    object.insert("model_requested".to_string(), json!(model.requested));
    object.insert("model_used".to_string(), json!(model.used));
    object.insert(
        "default_model_applied".to_string(),
        json!(model.default_model_applied),
    );
    object.insert("fallback_mode".to_string(), json!(model.fallback_mode));
    object.insert("fallback_reason".to_string(), json!(model.fallback_reason));
    CallToolResult::structured(Value::Object(object))
}

fn parse_json_response(raw: &str) -> Option<Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else if let Ok(value) = serde_json::from_str(trimmed) {
        Some(value)
    } else {
        parse_embedded_json(trimmed)
    }
}

fn sanitize_codebase_tool_output(mut value: Value) -> Value {
    const BANNED_KEYS: [&str; 3] = ["question", "objective", "target"];

    match &mut value {
        Value::Object(object) => {
            object.retain(|key, _| {
                !BANNED_KEYS
                    .iter()
                    .any(|banned| key.eq_ignore_ascii_case(banned))
            });
            for value in object.values_mut() {
                *value = sanitize_codebase_tool_output(value.clone());
            }
        }
        Value::Array(values) => {
            for value in values.iter_mut() {
                *value = sanitize_codebase_tool_output(value.clone());
            }
        }
        _ => {}
    }

    value
}

fn parse_embedded_json(raw: &str) -> Option<Value> {
    let bytes = raw.as_bytes();
    for i in 0..bytes.len() {
        let (open, close) = match bytes[i] {
            b'{' => (b'{', b'}'),
            b'[' => (b'[', b']'),
            _ => continue,
        };

        let mut depth = 0i64;
        let mut in_string = false;
        let mut escaped = false;
        for j in i..bytes.len() {
            let byte = bytes[j];
            if escaped {
                escaped = false;
                continue;
            }

            if in_string {
                if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }

            if byte == b'"' {
                in_string = true;
                continue;
            }

            if byte == open {
                depth += 1;
            } else if byte == close {
                depth -= 1;
                if depth == 0 {
                    let candidate = &raw[i..=j];
                    if let Ok(value) = serde_json::from_str(candidate) {
                        return Some(value);
                    }
                    break;
                }
            }
        }
    }

    None
}

fn allowed_models_hint(allowlist: &[String]) -> String {
    if allowlist.is_empty() {
        return "<no allowlist configured>".to_string();
    }
    allowlist.join(", ")
}

fn model_not_allowed_issue(allowlist: &[String]) -> ValidationIssue {
    ValidationIssue {
        field: "model".to_string(),
        code: "model_not_allowed".to_string(),
        expected_type: "allowlisted model id".to_string(),
        received_type: "string".to_string(),
        corrective_hint: format!("Set model to one of: {}.", allowed_models_hint(allowlist)),
    }
}

fn classify_execution_error(err: &GeminiExecutionError) -> ErrorCategory {
    match err {
        GeminiExecutionError::MissingApiKey => ErrorCategory::AuthSessionInvalid,
        GeminiExecutionError::FailedExit { stderr, .. } => classify_stderr_error(stderr),
        GeminiExecutionError::InvalidIncludeDirectory { .. } => ErrorCategory::FileAccess,
        GeminiExecutionError::SpawnFailed(_)
        | GeminiExecutionError::Cancelled
        | GeminiExecutionError::TimedOut { .. } => ErrorCategory::NetworkOrTransport,
    }
}

fn classify_stderr_error(stderr: &str) -> ErrorCategory {
    let lower = stderr.to_lowercase();

    if lower.contains("model") && (lower.contains("not found") || lower.contains("unknown model")) {
        ErrorCategory::ModelNotFound
    } else if [
        "quota",
        "rate limit",
        "too many requests",
        "429",
        "resource_exhausted",
        "model_capacity_exhausted",
        "retryablequotaerror",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        ErrorCategory::QuotaOrRateLimit
    } else if [
        "path",
        "directory",
        "permission",
        "denied",
        "not found",
        "does not exist",
        "workspace",
        "access",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        ErrorCategory::FileAccess
    } else if ["401", "403", "auth", "token", "session", "unauth"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        ErrorCategory::AuthSessionInvalid
    } else {
        ErrorCategory::NetworkOrTransport
    }
}
impl GeminiMcp {
    /// Summary: construct a Gemini MCP server from execution config.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Keeps policy immutable through `Arc`.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn new(config: GeminiExecutionConfig) -> Self {
        Self {
            config: Arc::new(config),
            tool_router: Self::tool_router_gemini(),
        }
    }

    /// Summary: construct a Gemini MCP server from raw env-near config.
    ///
    /// # Errors
    /// * Returns `Err` if raw policy conversion fails.
    ///
    /// # Security
    /// * Normalizes execution policy before tool exposure.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn from_raw_config(raw: GeminiExecutionRawConfig) -> Result<Self, String> {
        Ok(Self::new(raw.into_execution_config()?))
    }

    /// Summary: list registered tool names.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Exposes only public tool names.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn tool_names(&self) -> Vec<String> {
        self.tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AskGeminiArgs {
    prompt: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    sandbox: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CodebaseScoutArgs {
    target: String,
    question: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    sandbox: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CodebaseInvestigatorArgs {
    target: String,
    objective: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    sandbox: bool,
}

#[tool_router(router = tool_router_gemini, vis = "pub")]
impl GeminiMcp {
    #[tool(
        name = "ask-gemini",
        description = "Ask Gemini CLI with optional model and sandbox flags."
    )]
    async fn ask_gemini(
        &self,
        ct: CancellationToken,
        Parameters(args): Parameters<AskGeminiArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut validation_errors = Vec::new();
        let prompt = validate_required_text_field("prompt", &args.prompt, &mut validation_errors);
        let mut request_include_directories = Vec::new();
        if matches!(self.config.ask_gemini_policy, AskGeminiPolicy::ScopedOnly) {
            if self.config.ask_gemini_allowed_roots.is_empty() {
                validation_errors.push(ValidationIssue {
                    field: "target".to_string(),
                    code: "server_config_invalid".to_string(),
                    expected_type: "non-empty GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS".to_string(),
                    received_type: "empty".to_string(),
                    corrective_hint:
                        "Configure GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS before using scoped ask-gemini mode."
                            .to_string(),
                });
                return Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::InputValidation.as_str(),
                        "error": "request payload failed validation",
                    }),
                    &validation_errors,
                    &ResolvedModel {
                        requested: None,
                        used: None,
                        default_model_applied: false,
                        fallback_mode: "none",
                        fallback_reason: None,
                    },
                ));
            }

            let Some(target_raw) = args.target.as_deref() else {
                validation_errors.push(ValidationIssue {
                    field: "target".to_string(),
                    code: "invalid_value".to_string(),
                    expected_type: "non-empty directory path under configured ask roots"
                        .to_string(),
                    received_type: "null".to_string(),
                    corrective_hint: "Set target to a directory under configured ask roots."
                        .to_string(),
                });
                return Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::InputValidation.as_str(),
                        "error": "request payload failed validation",
                    }),
                    &validation_errors,
                    &ResolvedModel {
                        requested: None,
                        used: None,
                        default_model_applied: false,
                        fallback_mode: "none",
                        fallback_reason: None,
                    },
                ));
            };

            let scoped_target = validate_target_within_include_directories(
                target_raw,
                &self.config.ask_gemini_allowed_roots,
                &mut validation_errors,
            );
            if let Some(target) = scoped_target {
                match std::fs::canonicalize(&target) {
                    Ok(path) if path.is_dir() => {
                        request_include_directories.push(path.display().to_string())
                    }
                    Ok(_) => validation_errors.push(ValidationIssue {
                        field: "target".to_string(),
                        code: "invalid_value".to_string(),
                        expected_type: "directory path".to_string(),
                        received_type: "file path".to_string(),
                        corrective_hint: "Set target to a directory path.".to_string(),
                    }),
                    Err(err) => validation_errors.push(ValidationIssue {
                        field: "target".to_string(),
                        code: "invalid_value".to_string(),
                        expected_type: "existing directory path".to_string(),
                        received_type: "string".to_string(),
                        corrective_hint: format!(
                            "Set target to an existing directory. Details: {err}"
                        ),
                    }),
                }
            }
        }
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };

        if let Some(_prompt) = prompt.as_ref() {
            match resolve_model(&self.config, requested_model.clone()) {
                Ok(resolution) => model = resolution,
                Err(ErrorCategory::ModelNotAllowed) => {
                    validation_errors.push(model_not_allowed_issue(&self.config.model_allowlist));
                    return Ok(response_with_metadata(
                        json!({
                            "ok": false,
                            "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                            "error": "requested model is not allowed by policy",
                        }),
                        &validation_errors,
                        &model,
                    ));
                }
                Err(category) => {
                    return Ok(response_with_metadata(
                        json!({
                            "ok": false,
                            "error_category": category.as_str(),
                            "error": "model resolution failed",
                        }),
                        &validation_errors,
                        &model,
                    ));
                }
            }
        }

        if !validation_errors.is_empty() {
            return Ok(response_with_metadata(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
            ));
        }

        let request = GeminiRequest {
            prompt: prompt.expect("validated prompt must be present"),
            model: model.used.clone(),
            sandbox: args.sandbox,
            include_directories: request_include_directories,
            ..Default::default()
        };

        match execute_gemini_with_cancel(&self.config, &request, ct).await {
            Ok(output) => Ok(response_with_metadata(
                json!({
                    "ok": true,
                    "response": output.stdout,
                    "stderr": output.stderr,
                }),
                &validation_errors,
                &model,
            )),
            Err(error) => {
                let category = classify_execution_error(&error);
                Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": error.to_string(),
                    }),
                    &validation_errors,
                    &model,
                ))
            }
        }
    }

    #[tool(
        name = "codebase-scout",
        description = "Run a high-context Gemini codebase analysis against a target path with a focused question."
    )]
    async fn codebase_scout(
        &self,
        ct: CancellationToken,
        Parameters(args): Parameters<CodebaseScoutArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut validation_errors = Vec::new();
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let question =
            validate_required_text_field("question", &args.question, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };

        if !validation_errors.is_empty() {
            return Ok(response_with_metadata(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => model = resolution,
            Err(ErrorCategory::ModelNotAllowed) => {
                validation_errors.push(model_not_allowed_issue(&self.config.model_allowlist));
                return Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &validation_errors,
                    &model,
                ));
            }
            Err(category) => {
                return Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                ));
            }
        }

        let target = target.expect("validated target must be present");
        let question = question.expect("validated question must be present");
        let prompt = codebase_scout_prompt(&target, &question);

        let request = GeminiRequest {
            prompt,
            model: model.used.clone(),
            sandbox: args.sandbox,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            ..Default::default()
        };
        match execute_gemini_with_cancel(&self.config, &request, ct.clone()).await {
            Ok(output) => match parse_json_response(&output.stdout) {
                Some(value) => Ok(CallToolResult::structured(sanitize_codebase_tool_output(
                    value,
                ))),
                None => {
                    let mut retry_model = model.clone();
                    retry_model.fallback_mode = "fallback_prompt";
                    retry_model.fallback_reason = Some(
                        "primary output was empty or invalid JSON; using fallback schema-constrained prompt."
                            .to_string(),
                    );
                    let fallback_request = GeminiRequest {
                        prompt: codebase_scout_fallback_prompt(&target, &question),
                        model: retry_model.used.clone(),
                        sandbox: args.sandbox,
                        output_format: GeminiOutputFormat::Json,
                        prompt_transport: GeminiPromptTransport::Stdin,
                        ..Default::default()
                    };
                    match execute_gemini_with_cancel(&self.config, &fallback_request, ct).await {
                        Ok(second_output) => match parse_json_response(&second_output.stdout) {
                            Some(value) => Ok(CallToolResult::structured(
                                sanitize_codebase_tool_output(value),
                            )),
                            None => Ok(response_with_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": ErrorCategory::NetworkOrTransport.as_str(),
                                    "error": "gemini returned an empty or invalid response for codebase-scout after retry",
                                    "first_stderr": output.stderr,
                                    "second_stderr": second_output.stderr,
                                }),
                                &validation_errors,
                                &retry_model,
                            )),
                        },
                        Err(err) => {
                            let category = classify_execution_error(&err);
                            Ok(response_with_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": category.as_str(),
                                    "error": err.to_string(),
                                    "retry_used": true,
                                }),
                                &validation_errors,
                                &retry_model,
                            ))
                        }
                    }
                }
            },
            Err(err) => {
                let category = classify_execution_error(&err);
                Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    &validation_errors,
                    &model,
                ))
            }
        }
    }

    #[tool(
        name = "codebase-investigator",
        description = "Run a deep architecture/root-cause investigation. Prefers Gemini's codebase_investigator subagent when available."
    )]
    async fn codebase_investigator(
        &self,
        ct: CancellationToken,
        Parameters(args): Parameters<CodebaseInvestigatorArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut validation_errors = Vec::new();
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let objective =
            validate_required_text_field("objective", &args.objective, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };

        if !validation_errors.is_empty() {
            return Ok(response_with_metadata(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => model = resolution,
            Err(ErrorCategory::ModelNotAllowed) => {
                validation_errors.push(model_not_allowed_issue(&self.config.model_allowlist));
                return Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &validation_errors,
                    &model,
                ));
            }
            Err(category) => {
                return Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                ));
            }
        }

        let target = target.expect("validated target must be present");
        let objective = objective.expect("validated objective must be present");
        let prompt = codebase_investigator_prompt(&target, &objective);
        let request = GeminiRequest {
            prompt,
            model: model.used.clone(),
            sandbox: args.sandbox,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            ..Default::default()
        };
        match execute_gemini_with_cancel(&self.config, &request, ct.clone()).await {
            Ok(output) => match parse_json_response(&output.stdout) {
                Some(value) => Ok(CallToolResult::structured(sanitize_codebase_tool_output(
                    value,
                ))),
                None => {
                    let mut retry_model = model.clone();
                    retry_model.fallback_mode = "fallback_prompt";
                    retry_model.fallback_reason = Some(
                        "primary output was empty or invalid JSON; using fallback schema-constrained prompt."
                            .to_string(),
                    );
                    let fallback_request = GeminiRequest {
                        prompt: codebase_investigator_fallback_prompt(&target, &objective),
                        model: retry_model.used.clone(),
                        sandbox: args.sandbox,
                        output_format: GeminiOutputFormat::Json,
                        prompt_transport: GeminiPromptTransport::Stdin,
                        ..Default::default()
                    };
                    match execute_gemini_with_cancel(&self.config, &fallback_request, ct).await {
                        Ok(second_output) => match parse_json_response(&second_output.stdout) {
                            Some(value) => Ok(CallToolResult::structured(
                                sanitize_codebase_tool_output(value),
                            )),
                            None => Ok(response_with_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": ErrorCategory::NetworkOrTransport.as_str(),
                                    "error": "gemini returned an empty or invalid response for codebase-investigator after retry",
                                    "first_stderr": output.stderr,
                                    "second_stderr": second_output.stderr,
                                }),
                                &validation_errors,
                                &retry_model,
                            )),
                        },
                        Err(err) => {
                            let category = classify_execution_error(&err);
                            Ok(response_with_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": category.as_str(),
                                    "error": err.to_string(),
                                    "retry_used": true,
                                }),
                                &validation_errors,
                                &retry_model,
                            ))
                        }
                    }
                }
            },
            Err(err) => {
                let category = classify_execution_error(&err);
                Ok(response_with_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    &validation_errors,
                    &model,
                ))
            }
        }
    }
}

impl ServerHandler for GeminiMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "Gemini CLI MCP tools for high-context analysis, codebase scouting, and deep investigations.",
            )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        let tools = self.tool_router.list_all();
        std::future::ready(Ok(ListToolsResult {
            meta: None,
            tools,
            next_cursor: None,
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let tool_context = ToolCallContext::new(self, request, context);
        async move { self.tool_router.call(tool_context).await }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        allowed_models_hint, classify_stderr_error, codebase_investigator_fallback_prompt,
        codebase_investigator_prompt, codebase_scout_fallback_prompt, codebase_scout_prompt,
        model_not_allowed_issue, normalize_model_list, normalize_optional_model_field,
        parse_json_response, resolve_model, sanitize_codebase_tool_output,
        validate_required_text_field, validate_target_within_include_directories, ErrorCategory,
        GeminiExecutionConfig,
    };
    use serde_json::json;

    #[test]
    fn codebase_scout_prompt_has_required_guardrails_and_schema() {
        let prompt = codebase_scout_prompt("/tmp/repo", "where are extractors?");
        assert!(prompt.contains("Hard rules:"));
        assert!(prompt.contains("Do not invent files"));
        assert!(prompt.contains("delegate_to_agent"));
        assert!(prompt.contains("codebase_investigator"));
        assert!(prompt.contains("single JSON object"));
        assert!(prompt.contains("\"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\""));
        assert!(prompt.contains("\"top_hits\""));
        assert!(!prompt.contains("@/tmp/repo"));
        assert!(prompt
            .contains("Do not repeat the input question or target path in the response payload."));
    }

    #[test]
    fn fallback_prompt_is_json_only_and_has_status() {
        let prompt = codebase_scout_fallback_prompt("/tmp/repo", "question");
        assert!(prompt.contains("Return JSON only"));
        assert!(prompt.contains("delegate_to_agent"));
        assert!(prompt.contains("\"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\""));
        assert!(prompt.contains("\"top_hits\""));
    }

    #[test]
    fn investigator_prompt_mentions_subagent_and_contract() {
        let prompt = codebase_investigator_prompt("/tmp/repo", "find root cause");
        assert!(prompt.contains("codebase_investigator"));
        assert!(prompt.contains("delegate_to_agent"));
        assert!(prompt.contains("\"relevant_locations\""));
        assert!(prompt.contains("\"impact_map\""));
        assert!(prompt.contains("single JSON object"));
        assert!(
            prompt.contains("Do not repeat the objective or target path in the response payload.")
        );
    }

    #[test]
    fn parse_json_response_handles_empty_and_non_json_inputs() {
        assert!(parse_json_response("{ \"ok\": true }").is_some());
        assert!(parse_json_response("  ").is_none());
        assert!(parse_json_response("status: ok").is_none());
    }

    #[test]
    fn sanitize_codebase_tool_output_removes_redundant_input_fields() {
        let input = json!({
            "status": "OK",
            "question": "How is this done?",
            "target": "/tmp/repo",
            "top_hits": [
                {"path": "src/lib.rs", "question": "nested question"}
            ],
            "details": {
                "objective": "hidden",
                "summary": "works"
            }
        });
        let sanitized = sanitize_codebase_tool_output(input);
        let Some(object) = sanitized.as_object() else {
            panic!("expected object");
        };
        assert!(!object.contains_key("question"));
        assert!(!object.contains_key("target"));
        assert_eq!(object["status"], "OK");
        assert_eq!(object["top_hits"][0]["path"], "src/lib.rs");
        let nested_top_hit = object["top_hits"][0]
            .as_object()
            .expect("top hit should be object");
        assert!(!nested_top_hit.contains_key("question"));
        let details = object["details"]
            .as_object()
            .expect("details should be object");
        assert!(!details.contains_key("objective"));
        assert_eq!(details["summary"], "works");
    }

    #[test]
    fn investigator_fallback_prompt_is_json_only() {
        let prompt = codebase_investigator_fallback_prompt("/tmp/repo", "find root cause");
        assert!(prompt.contains("Return JSON only"));
        assert!(prompt.contains("delegate_to_agent"));
        assert!(prompt.contains("\"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\""));
        assert!(prompt.contains("\"relevant_locations\""));
    }

    #[test]
    fn resolve_model_uses_default_when_requested_and_allowlisted_is_omitted() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-flash-preview".to_string()),
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };

        let resolved = resolve_model(&config, None).expect("expected default resolution");

        assert_eq!(resolved.requested, None);
        assert_eq!(resolved.used, Some("gemini-3-flash-preview".to_string()));
        assert!(resolved.default_model_applied);
        assert_eq!(resolved.fallback_mode, "configured_default");
    }

    #[test]
    fn resolve_model_rejects_non_allowlisted_request() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-flash-preview".to_string()),
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };
        let error = resolve_model(&config, Some("gemini-1.5-pro".to_string()))
            .expect_err("unsupported model should fail");
        assert!(matches!(error, ErrorCategory::ModelNotAllowed));
    }

    #[test]
    fn resolve_model_falls_back_to_first_allowlisted_model_if_default_missing() {
        let config = GeminiExecutionConfig {
            default_model: None,
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };

        let resolved = resolve_model(&config, None).expect("expected fallback to allowlist model");
        assert_eq!(resolved.used, Some("gemini-3-flash-preview".to_string()));
        assert!(!resolved.default_model_applied);
        assert_eq!(resolved.fallback_mode, "allowlist_default");
        assert!(resolved
            .fallback_reason
            .as_ref()
            .map(|reason| reason.contains("first allowlist model"))
            .unwrap_or(false));
    }

    #[test]
    fn resolve_model_falls_back_to_first_allowlisted_model_if_default_not_allowlisted() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-1.5-pro".to_string()),
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };
        let resolved = resolve_model(&config, None).expect("expected fallback resolution");
        assert_eq!(resolved.used, Some("gemini-3-flash-preview".to_string()));
        assert!(!resolved.default_model_applied);
        assert_eq!(resolved.fallback_mode, "allowlist_default");
        assert!(resolved
            .fallback_reason
            .as_ref()
            .map(|reason| reason.contains("not allowlisted"))
            .unwrap_or(false));
    }

    #[test]
    fn resolve_model_treats_model_case_insensitively_against_allowlist() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-flash-preview".to_string()),
            model_allowlist: vec![
                "Gemini-3-FLASH-Preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };
        let resolved = resolve_model(&config, Some("gemini-3-flash-preview".to_string()))
            .expect("expected allowlisted match");
        assert_eq!(resolved.used, Some("Gemini-3-FLASH-Preview".to_string()));
    }

    #[test]
    fn model_not_allowed_issue_is_actionable() {
        let issue = model_not_allowed_issue(&[
            "gemini-3-flash-preview".to_string(),
            "gemini-3-pro-preview".to_string(),
        ]);

        assert_eq!(issue.code, "model_not_allowed");
        assert_eq!(issue.field, "model");
        assert!(issue.corrective_hint.contains("gemini-3-flash-preview"));
        assert!(issue.corrective_hint.contains("gemini-3-pro-preview"));
    }

    #[test]
    fn normalize_and_validate_model_and_prompt_fields() {
        let mut issues = Vec::new();
        assert_eq!(
            validate_required_text_field("prompt", "  ", &mut issues),
            None
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "prompt");
        assert_eq!(issues[0].code, "invalid_value");
        assert_eq!(issues[0].expected_type, "non-empty string");
        assert_eq!(issues[0].received_type, "string");

        issues.clear();
        assert_eq!(
            normalize_optional_model_field(
                "model",
                Some("  gemini-3-flash-preview  ".to_string()),
                &mut issues
            ),
            Some("gemini-3-flash-preview".to_string())
        );
        assert!(issues.is_empty());

        assert_eq!(allowed_models_hint(&[]), "<no allowlist configured>");
        assert_eq!(
            normalize_model_list(&["a".to_string(), "  ".to_string(), "b".to_string()]),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn config_has_model_allowlist_joined_output() {
        assert_eq!(
            allowed_models_hint(&[
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ]),
            "gemini-3-flash-preview, gemini-3-pro-preview"
        );
    }

    #[test]
    fn target_validation_requires_path_within_include_directories() {
        let temp_root =
            std::env::temp_dir().join(format!("gemini-target-scope-{}", std::process::id()));
        let allowed_root = temp_root.join("allowed");
        let nested = allowed_root.join("nested");
        let outside_root = temp_root.join("outside");
        std::fs::create_dir_all(&nested).expect("create nested path");
        std::fs::create_dir_all(&outside_root).expect("create outside path");

        let mut errors = Vec::new();
        let allowed = validate_target_within_include_directories(
            &nested.display().to_string(),
            &[allowed_root.display().to_string()],
            &mut errors,
        );
        assert!(allowed.is_some(), "expected nested path to be accepted");
        assert!(errors.is_empty(), "unexpected errors for allowed target");

        errors.clear();
        let blocked = validate_target_within_include_directories(
            &outside_root.display().to_string(),
            &[allowed_root.display().to_string()],
            &mut errors,
        );
        assert!(blocked.is_none(), "expected outside path to be rejected");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "out_of_scope");

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn classify_stderr_prioritizes_quota_over_auth_terms() {
        let stderr = "Attempt failed with status 429; session token unchanged; RESOURCE_EXHAUSTED";
        let category = classify_stderr_error(stderr);
        assert!(matches!(category, ErrorCategory::QuotaOrRateLimit));
    }

    #[test]
    fn from_raw_config_uses_normalized_policy_path() {
        let raw = crate::config::GeminiExecutionRawConfig {
            gemini_api_key: Some("test-api-key".to_string()),
            ..crate::config::GeminiExecutionRawConfig::default()
        };
        let server = super::GeminiMcp::from_raw_config(raw).expect("raw config conversion");
        let names = server.tool_names();
        assert!(names.iter().any(|name| name == "ask-gemini"));
    }
}

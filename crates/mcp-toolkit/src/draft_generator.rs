//! # MCP Toolkit Draft Generator
//!
//! Proposes reviewable MCP tool-catalog drafts from existing API descriptions.
//!
//! ## Rationale
//! The fastest path from an upstream API to an MCP server should still produce
//! a human-reviewed draft rather than a generic endpoint proxy. This module
//! turns local OpenAPI, JSON Schema, and structured endpoint notes into a
//! conservative report that maintainers can copy into typed catalog entries.
//!
//! ## Security Boundaries
//! * Reads only one caller-provided local text file.
//! * Does not execute generated code, fetch remote references, or call upstream
//!   APIs.
//! * Marks write and destructive operations as disabled-by-default operator
//!   drafts.
//! * Leaves unresolved `$ref`, auth, pagination, rate-limit, and provider
//!   semantics as explicit review tasks.
//!
//! ## References
//! * `docs/instant-server-generation.md`
//! * `docs/new-server-delivery-lane.md`

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options"];

/// Configures one draft-tool proposal run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftGeneratorOptions {
    /// Local OpenAPI, JSON Schema, or structured documentation path.
    pub source: PathBuf,
}

/// Identifies the source format inferred by the draft generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftSourceKind {
    /// OpenAPI document with a top-level `paths` map.
    OpenApi,
    /// Standalone JSON Schema or schema-like JSON object.
    JsonSchema,
    /// Plain-text or markdown endpoint notes.
    StructuredDocs,
}

impl DraftSourceKind {
    /// Returns the stable string used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenApi => "openapi",
            Self::JsonSchema => "json_schema",
            Self::StructuredDocs => "structured_docs",
        }
    }
}

/// Conservative risk classification for a proposed tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftRisk {
    /// Read-only, safe-by-default inspection operation.
    Read,
    /// Mutating operation that needs an operator profile decision.
    Write,
    /// Destructive operation that needs separate human approval.
    Destructive,
    /// Operation could not be classified confidently.
    ManualReview,
}

impl DraftRisk {
    /// Returns the stable string used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Destructive => "destructive",
            Self::ManualReview => "manual_review",
        }
    }

    fn profile(self) -> &'static str {
        match self {
            Self::Read => "read_only",
            Self::Write | Self::Destructive | Self::ManualReview => "operator",
        }
    }

    fn enabled_by_default(self) -> bool {
        self == Self::Read
    }
}

/// One proposed MCP tool draft.
#[derive(Debug, Clone, PartialEq)]
pub struct DraftTool {
    /// Proposed MCP tool name.
    pub name: String,
    /// Human-readable summary.
    pub title: String,
    /// Source reference such as `GET /sites`.
    pub source_ref: String,
    /// Conservative risk classification.
    pub risk: DraftRisk,
    /// Generated profile gate.
    pub profile: String,
    /// Whether the generated server should expose this by default.
    pub enabled_by_default: bool,
    /// Proposed JSON input schema.
    pub input_schema: Value,
    /// Proposed JSON output schema, when the source provides one.
    pub output_schema: Option<Value>,
    /// Review tasks that must be resolved before exposing the tool.
    pub todos: Vec<String>,
}

/// Reviewable draft-tool report.
#[derive(Debug, Clone, PartialEq)]
pub struct DraftToolReport {
    /// Source path read by the generator.
    pub source: PathBuf,
    /// Inferred source kind.
    pub source_kind: DraftSourceKind,
    /// Proposed tools.
    pub tools: Vec<DraftTool>,
    /// Report-level warnings.
    pub warnings: Vec<String>,
}

impl DraftToolReport {
    /// Renders a concise operator-facing report.
    pub fn render_text(&self) -> String {
        let mut output = String::new();

        output.push_str("mcp-toolkit draft-tools\n");
        output.push_str(&format!("Source: {}\n", self.source.display()));
        output.push_str(&format!("Source kind: {}\n", self.source_kind.as_str()));
        output.push_str(&format!("Proposed tools: {}\n", self.tools.len()));
        output.push('\n');

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {warning}\n"));
            }
            output.push('\n');
        }

        output.push_str("Tools:\n");
        if self.tools.is_empty() {
            output.push_str("  none\n");
        } else {
            for tool in &self.tools {
                output.push_str(&format!(
                    "  [{}] {} ({}) - {}\n",
                    tool.risk.as_str(),
                    tool.name,
                    tool.profile,
                    tool.title
                ));
                output.push_str(&format!("    source: {}\n", tool.source_ref));
                output.push_str(&format!(
                    "    exposed by default: {}\n",
                    if tool.enabled_by_default { "yes" } else { "no" }
                ));
                if !tool.todos.is_empty() {
                    output.push_str("    review:\n");
                    for todo in &tool.todos {
                        output.push_str(&format!("      - {todo}\n"));
                    }
                }
            }
        }

        output.push('\n');
        output.push_str("Next:\n");
        output.push_str(concat!(
            "  review tool names, risk classes, auth scopes, pagination, ",
            "and rate limits\n"
        ));
        output.push_str("  copy approved drafts into `ToolCatalogEntry` declarations\n");
        output.push_str(concat!(
            "  add fake-adapter fixtures, schema snapshots, ",
            "and profile contract tests\n"
        ));

        output
    }

    /// Renders the report as stable pretty JSON.
    ///
    /// # Errors
    /// Returns `serde_json::Error` if the report cannot be serialized.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.to_json_value())
    }

    /// Converts the report to a JSON value suitable for writing to disk.
    pub fn to_json_value(&self) -> Value {
        let mut counts = BTreeMap::new();
        for tool in &self.tools {
            *counts.entry(tool.risk.as_str()).or_insert(0usize) += 1;
        }

        json!({
            "schema": "mcp_toolkit_draft_tools_report",
            "schema_version": 1,
            "source": self.source.display().to_string(),
            "source_kind": self.source_kind.as_str(),
            "summary": {
                "tool_count": self.tools.len(),
                "risk_counts": counts,
                "manual_review_required": self.tools.iter().any(|tool| !tool.enabled_by_default),
            },
            "warnings": self.warnings.clone(),
            "tools": self.tools.iter().map(DraftTool::to_json_value).collect::<Vec<_>>(),
            "next_steps": [
                "review tool names, risk classes, auth scopes, pagination, and rate limits",
                "copy approved drafts into ToolCatalogEntry declarations",
                "add fake-adapter fixtures, schema snapshots, and profile contract tests"
            ],
        })
    }
}

impl DraftTool {
    fn to_json_value(&self) -> Value {
        json!({
            "name": self.name.clone(),
            "title": self.title.clone(),
            "source_ref": self.source_ref.clone(),
            "risk": self.risk.as_str(),
            "profile": self.profile.clone(),
            "enabled_by_default": self.enabled_by_default,
            "input_schema": self.input_schema.clone(),
            "output_schema": self.output_schema.clone(),
            "todos": self.todos.clone(),
        })
    }
}

/// Errors returned by draft-tool proposal generation.
#[derive(Debug)]
pub enum DraftGeneratorError {
    /// Source file could not be read.
    Io {
        /// Source path involved in the failed operation.
        path: PathBuf,
        /// Source I/O error.
        source: std::io::Error,
    },
    /// Source looked like JSON but could not be parsed.
    Json {
        /// Source path involved in the failed operation.
        path: PathBuf,
        /// Source JSON error.
        source: serde_json::Error,
    },
}

impl fmt::Display for DraftGeneratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "failed to read `{}`: {source}", path.display())
            }
            Self::Json { path, source } => {
                write!(
                    formatter,
                    "failed to parse JSON `{}`: {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for DraftGeneratorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
        }
    }
}

/// Builds a reviewable tool-catalog draft from a local source file.
///
/// # Errors
/// Returns `DraftGeneratorError` when the source file cannot be read or when a
/// JSON-looking source cannot be parsed.
///
/// # Security
/// This function performs static local parsing only. It does not execute code,
/// fetch remote `$ref` targets, or expose mutating operations by default.
pub fn inspect_draft_source(
    options: &DraftGeneratorOptions,
) -> Result<DraftToolReport, DraftGeneratorError> {
    // codeql[rust/path-injection] Operator-selected local file after CLI validation.
    let contents =
        fs::read_to_string(&options.source).map_err(|source| DraftGeneratorError::Io {
            path: options.source.clone(),
            source,
        })?;

    let trimmed = contents.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let value =
            serde_json::from_str(&contents).map_err(|source| DraftGeneratorError::Json {
                path: options.source.clone(),
                source,
            })?;
        Ok(draft_from_json(options.source.clone(), value))
    } else {
        Ok(draft_from_structured_docs(
            options.source.clone(),
            &contents,
        ))
    }
}

fn draft_from_json(source: PathBuf, value: Value) -> DraftToolReport {
    if value.get("openapi").is_some()
        || value.get("swagger").is_some()
        || value.get("paths").is_some()
    {
        draft_from_openapi(source, &value)
    } else {
        draft_from_json_schema(source, value)
    }
}

fn draft_from_openapi(source: PathBuf, value: &Value) -> DraftToolReport {
    let mut tools = Vec::new();
    let mut warnings = Vec::new();
    let mut used_names = BTreeSet::new();
    let paths = match value.get("paths").and_then(Value::as_object) {
        Some(paths) => paths,
        None => {
            warnings.push("OpenAPI document has no object-valued `paths` map".to_string());
            return DraftToolReport {
                source,
                source_kind: DraftSourceKind::OpenApi,
                tools,
                warnings,
            };
        }
    };

    for (path, path_item) in paths {
        let Some(path_item_object) = path_item.as_object() else {
            warnings.push(format!(
                "skipped `{path}` because the path item is not an object"
            ));
            continue;
        };
        for method in HTTP_METHODS {
            let Some(operation) = path_item_object.get(*method) else {
                continue;
            };
            let Some(operation_object) = operation.as_object() else {
                warnings.push(format!(
                    "skipped `{method_upper} {path}` because the operation is not an object",
                    method_upper = method.to_ascii_uppercase()
                ));
                continue;
            };
            let risk = classify_operation(method, operation_object);
            let name = unique_name(
                proposed_tool_name(method, path, operation_object),
                &mut used_names,
            );
            let title = operation_object
                .get("summary")
                .and_then(Value::as_str)
                .or_else(|| operation_object.get("description").and_then(Value::as_str))
                .map(first_sentence)
                .unwrap_or_else(|| format!("{} {}", method.to_ascii_uppercase(), path));
            let input_schema = operation_input_schema(path, path_item_object, operation_object);
            let output_schema = response_schema(operation_object);
            let mut todos = standard_todos();
            append_openapi_todos(&mut todos, risk, operation_object);

            tools.push(DraftTool {
                name,
                title,
                source_ref: format!("{} {}", method.to_ascii_uppercase(), path),
                risk,
                profile: risk.profile().to_string(),
                enabled_by_default: risk.enabled_by_default(),
                input_schema,
                output_schema,
                todos,
            });
        }
    }

    if tools.is_empty() {
        warnings.push("no OpenAPI operations were found under `paths`".to_string());
    }

    DraftToolReport {
        source,
        source_kind: DraftSourceKind::OpenApi,
        tools,
        warnings,
    }
}

fn draft_from_json_schema(source: PathBuf, value: Value) -> DraftToolReport {
    let mut warnings = Vec::new();
    if !value.is_object() {
        warnings
            .push("JSON source is not an object; no schema-backed tool was proposed".to_string());
        return DraftToolReport {
            source,
            source_kind: DraftSourceKind::JsonSchema,
            tools: Vec::new(),
            warnings,
        };
    }

    let title = value
        .get("title")
        .and_then(Value::as_str)
        .map(first_sentence)
        .unwrap_or_else(|| "Validate schema-backed payload".to_string());
    let name = value
        .get("title")
        .and_then(Value::as_str)
        .map(normalize_identifier)
        .filter(|name| !name.is_empty())
        .map(|name| format!("{name}.validate"))
        .unwrap_or_else(|| "schema.validate".to_string());
    let todos = vec![
        "Decide which provider operation this schema belongs to".to_string(),
        "Rename the tool around user intent before exposing it".to_string(),
        "Add fixture-backed handler tests for accepted and rejected payloads".to_string(),
    ];

    DraftToolReport {
        source,
        source_kind: DraftSourceKind::JsonSchema,
        tools: vec![DraftTool {
            name,
            title,
            source_ref: "JSON Schema".to_string(),
            risk: DraftRisk::ManualReview,
            profile: DraftRisk::ManualReview.profile().to_string(),
            enabled_by_default: false,
            input_schema: value,
            output_schema: None,
            todos,
        }],
        warnings,
    }
}

fn draft_from_structured_docs(source: PathBuf, contents: &str) -> DraftToolReport {
    let mut tools = Vec::new();
    let mut warnings = Vec::new();
    let mut used_names = BTreeSet::new();

    for (line_index, line) in contents.lines().enumerate() {
        let normalized = normalize_doc_line(line);
        let mut parts = normalized.split_whitespace();
        let Some(method) = parts.next() else {
            continue;
        };
        let method_lower = method.to_ascii_lowercase();
        if !HTTP_METHODS.contains(&method_lower.as_str()) {
            continue;
        }
        let Some(path) = parts.next() else {
            warnings.push(format!(
                "line {} names `{method}` without an endpoint path",
                line_index + 1
            ));
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let risk = classify_method(&method_lower);
        let name = unique_name(
            proposed_path_tool_name(&method_lower, path),
            &mut used_names,
        );
        let title = parts.collect::<Vec<_>>().join(" ");
        let title = if title.is_empty() {
            format!("{} {}", method.to_ascii_uppercase(), path)
        } else {
            first_sentence(&title)
        };

        tools.push(DraftTool {
            name,
            title,
            source_ref: format!(
                "{} {} (line {})",
                method.to_ascii_uppercase(),
                path,
                line_index + 1
            ),
            risk,
            profile: risk.profile().to_string(),
            enabled_by_default: risk.enabled_by_default(),
            input_schema: path_parameter_schema(path),
            output_schema: None,
            todos: standard_todos(),
        });
    }

    if tools.is_empty() {
        warnings.push(
            "no endpoint-like lines were found; use lines such as `GET /items List items`"
                .to_string(),
        );
    }

    DraftToolReport {
        source,
        source_kind: DraftSourceKind::StructuredDocs,
        tools,
        warnings,
    }
}

fn operation_input_schema(
    path: &str,
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    for parameter in path_item
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
    {
        add_parameter_schema(parameter, &mut properties, &mut required);
    }

    for name in path_parameter_names(path) {
        if !properties.contains_key(&name) {
            properties.insert(name.clone(), json!({"type": "string"}));
            required.push(name);
        }
    }

    if let Some(body_schema) = request_body_schema(operation) {
        properties.insert("body".to_string(), body_schema);
        if operation
            .get("requestBody")
            .and_then(|body| body.get("required"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            required.push("body".to_string());
        }
    }

    object_schema(properties, required)
}

fn add_parameter_schema(
    parameter: &Value,
    properties: &mut Map<String, Value>,
    required: &mut Vec<String>,
) {
    let Some(name) = parameter.get("name").and_then(Value::as_str) else {
        return;
    };
    let name = normalize_identifier(name);
    if name.is_empty() {
        return;
    }
    let schema = parameter
        .get("schema")
        .cloned()
        .unwrap_or_else(|| json!({"type": "string"}));
    properties.insert(name.clone(), schema);

    let required_by_schema = parameter
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let required_by_location = parameter
        .get("in")
        .and_then(Value::as_str)
        .map(|location| location == "path")
        .unwrap_or(false);
    if required_by_schema || required_by_location {
        required.push(name);
    }
}

fn path_parameter_schema(path: &str) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for name in path_parameter_names(path) {
        properties.insert(name.clone(), json!({"type": "string"}));
        required.push(name);
    }
    object_schema(properties, required)
}

fn object_schema(properties: Map<String, Value>, mut required: Vec<String>) -> Value {
    required.sort();
    required.dedup();

    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert("additionalProperties".to_string(), Value::Bool(false));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert(
            "required".to_string(),
            Value::Array(required.into_iter().map(Value::String).collect()),
        );
    }
    Value::Object(schema)
}

fn request_body_schema(operation: &Map<String, Value>) -> Option<Value> {
    let body = operation.get("requestBody")?;
    let content = body.get("content").and_then(Value::as_object)?;
    content
        .get("application/json")
        .and_then(|media| media.get("schema"))
        .cloned()
        .or_else(|| {
            content
                .values()
                .find_map(|media| media.get("schema"))
                .cloned()
        })
}

fn response_schema(operation: &Map<String, Value>) -> Option<Value> {
    let responses = operation.get("responses").and_then(Value::as_object)?;
    responses
        .iter()
        .filter(|(status, _)| status.starts_with('2'))
        .find_map(|(_, response)| {
            response
                .get("content")
                .and_then(Value::as_object)
                .and_then(|content| {
                    content
                        .get("application/json")
                        .and_then(|media| media.get("schema"))
                        .cloned()
                        .or_else(|| {
                            content
                                .values()
                                .find_map(|media| media.get("schema"))
                                .cloned()
                        })
                })
        })
}

fn append_openapi_todos(todos: &mut Vec<String>, risk: DraftRisk, operation: &Map<String, Value>) {
    if risk != DraftRisk::Read {
        todos.push(
            "Keep this disabled until an operator profile and provider scope are reviewed"
                .to_string(),
        );
    }
    if operation.get("security").is_none() {
        todos.push(
            "Confirm provider auth scopes; source operation did not declare security".to_string(),
        );
    }
    if object_contains_ref(operation) {
        todos.push("Resolve local `$ref` schemas before generating typed Rust models".to_string());
    }
}

fn standard_todos() -> Vec<String> {
    vec![
        "Confirm the proposed tool name describes user intent, not just an endpoint".to_string(),
        "Add upstream timeout, pagination, rate-limit, and error-mapping decisions".to_string(),
        "Add schema snapshot, profile contract, and fake-adapter output tests".to_string(),
    ]
}

fn classify_operation(method: &str, operation: &Map<String, Value>) -> DraftRisk {
    let method_risk = classify_method(method);
    if method_risk == DraftRisk::Read {
        return DraftRisk::Read;
    }

    let operation_id = operation
        .get("operationId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let text = operation
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| operation.get("description").and_then(Value::as_str))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let combined = format!("{operation_id} {text}");

    if combined.contains("delete") || combined.contains("remove") || combined.contains("purge") {
        DraftRisk::Destructive
    } else if combined.contains("create")
        || combined.contains("update")
        || combined.contains("submit")
        || combined.contains("publish")
        || combined.contains("write")
    {
        DraftRisk::Write
    } else {
        method_risk
    }
}

fn classify_method(method: &str) -> DraftRisk {
    match method {
        "get" | "head" | "options" => DraftRisk::Read,
        "delete" => DraftRisk::Destructive,
        "post" | "put" | "patch" => DraftRisk::Write,
        _ => DraftRisk::ManualReview,
    }
}

fn proposed_tool_name(method: &str, path: &str, operation: &Map<String, Value>) -> String {
    operation
        .get("operationId")
        .and_then(Value::as_str)
        .map(normalize_identifier)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| proposed_path_tool_name(method, path))
}

fn proposed_path_tool_name(method: &str, path: &str) -> String {
    let action = match classify_method(method) {
        DraftRisk::Read if path_parameter_names(path).is_empty() => "list",
        DraftRisk::Read => "get",
        DraftRisk::Write => match method {
            "post" => "create",
            "put" | "patch" => "update",
            _ => "write",
        },
        DraftRisk::Destructive => "delete",
        DraftRisk::ManualReview => "review",
    };
    let resource = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .rfind(|segment| !is_path_parameter(segment))
        .map(normalize_identifier)
        .filter(|segment| !segment.is_empty())
        .unwrap_or_else(|| "endpoint".to_string());
    format!("{resource}.{action}")
}

fn unique_name(name: String, used_names: &mut BTreeSet<String>) -> String {
    if used_names.insert(name.clone()) {
        return name;
    }

    let mut suffix = 2usize;
    loop {
        let candidate = format!("{name}_{suffix}");
        if used_names.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

fn normalize_identifier(input: &str) -> String {
    let mut output = String::new();
    let mut previous_was_separator = true;
    let mut previous_was_lower_or_digit = false;

    for character in input.chars() {
        if character.is_ascii_uppercase() {
            if previous_was_lower_or_digit && !previous_was_separator {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
            previous_was_separator = false;
            previous_was_lower_or_digit = true;
        } else if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
            previous_was_separator = false;
            previous_was_lower_or_digit = true;
        } else if !previous_was_separator {
            output.push('_');
            previous_was_separator = true;
            previous_was_lower_or_digit = false;
        }
    }

    output.trim_matches('_').to_string()
}

fn normalize_doc_line(line: &str) -> String {
    line.trim()
        .trim_start_matches('#')
        .trim_start_matches('-')
        .trim_start_matches('*')
        .trim()
        .to_string()
}

fn path_parameter_names(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| is_path_parameter(segment))
        .map(|segment| {
            segment
                .trim_start_matches('{')
                .trim_end_matches('}')
                .trim_start_matches(':')
                .trim()
        })
        .filter(|segment| !segment.is_empty())
        .map(normalize_identifier)
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn is_path_parameter(segment: &str) -> bool {
    segment.starts_with('{') && segment.ends_with('}') || segment.starts_with(':')
}

fn first_sentence(text: &str) -> String {
    text.split('.')
        .next()
        .map(str::trim)
        .filter(|sentence| !sentence.is_empty())
        .unwrap_or(text.trim())
        .to_string()
}

fn contains_ref(value: &Value) -> bool {
    match value {
        Value::Object(object) => object_contains_ref(object),
        Value::Array(values) => values.iter().any(contains_ref),
        _ => false,
    }
}

fn object_contains_ref(object: &Map<String, Value>) -> bool {
    object
        .iter()
        .any(|(key, value)| key == "$ref" || contains_ref(value))
}

#[cfg(test)]
mod tests {
    use super::{inspect_draft_source, DraftGeneratorOptions, DraftRisk, DraftSourceKind};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn openapi_draft_classifies_read_write_and_destructive_operations() {
        let root = temp_root("openapi-draft");
        let source = root.join("openapi.json");
        fs::write(
            &source,
            json!({
                "openapi": "3.1.0",
                "paths": {
                    "/sites/{siteUrl}/sitemaps": {
                        "get": {
                            "operationId": "listSitemaps",
                            "summary": "List submitted sitemaps.",
                            "parameters": [
                                {
                                    "name": "siteUrl",
                                    "in": "path",
                                    "required": true,
                                    "schema": {"type": "string"}
                                },
                                {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                            ],
                            "security": [{"oauth": ["webmasters.readonly"]}],
                            "responses": {
                                "200": {
                                    "content": {
                                        "application/json": {
                                            "schema": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        },
                        "post": {
                            "operationId": "submitSitemap",
                            "summary": "Submit a sitemap.",
                            "requestBody": {
                                "required": true,
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/SitemapSubmit"}
                                    }
                                }
                            },
                            "responses": {"204": {"description": "submitted"}}
                        },
                        "delete": {
                            "summary": "Delete a sitemap.",
                            "responses": {"204": {"description": "deleted"}}
                        }
                    }
                }
            })
            .to_string(),
        )
        .expect("write openapi source");

        let report =
            inspect_draft_source(&DraftGeneratorOptions { source }).expect("draft openapi source");

        assert_eq!(report.source_kind, DraftSourceKind::OpenApi);
        assert_eq!(report.tools.len(), 3);
        assert_eq!(report.tools[0].name, "list_sitemaps");
        assert_eq!(report.tools[0].risk, DraftRisk::Read);
        assert!(report.tools[0].enabled_by_default);
        assert_eq!(
            report.tools[0].input_schema["properties"]["site_url"]["type"],
            json!("string")
        );
        assert_eq!(report.tools[1].name, "submit_sitemap");
        assert_eq!(report.tools[1].risk, DraftRisk::Write);
        assert!(!report.tools[1].enabled_by_default);
        assert!(report.tools[1]
            .todos
            .iter()
            .any(|todo| todo.contains("Resolve local `$ref`")));
        assert_eq!(report.tools[2].risk, DraftRisk::Destructive);

        cleanup(root);
    }

    #[test]
    fn structured_docs_draft_parses_endpoint_lines() {
        let root = temp_root("docs-draft");
        let source = root.join("endpoints.md");
        fs::write(
            &source,
            "# API\n- GET /reports/{reportId} Fetch a report\n- POST /reports Create a report\n",
        )
        .expect("write docs source");

        let report =
            inspect_draft_source(&DraftGeneratorOptions { source }).expect("draft docs source");

        assert_eq!(report.source_kind, DraftSourceKind::StructuredDocs);
        assert_eq!(report.tools.len(), 2);
        assert_eq!(report.tools[0].name, "reports.get");
        assert_eq!(report.tools[0].risk, DraftRisk::Read);
        assert_eq!(
            report.tools[0].input_schema["required"],
            json!(["report_id"])
        );
        assert_eq!(report.tools[1].risk, DraftRisk::Write);

        cleanup(root);
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = PathBuf::from(format!(
            "target/mcp-toolkit-draft-generator-tests/{prefix}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp root");
        path
    }

    fn cleanup(path: PathBuf) {
        fs::remove_dir_all(path).expect("remove temp root");
    }
}

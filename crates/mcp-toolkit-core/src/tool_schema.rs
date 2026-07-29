//! # Tool Schema Snapshots
//!
//! Deterministic serialization helpers for MCP tool surfaces.
//!
//! ## Ownership
//! This module owns the shared JSON envelope and canonical ordering used when
//! MCP servers print or snapshot their registered tool definitions.
//!
//! ## Non-ownership
//! This module does not register tools, invoke tools, or assert against files.
//! Test assertion policy remains in `mcp-toolkit-testing`.
//!
//! ## Policy & Guarantees
//! * **Stable Output**: Sorts tools by name and canonicalizes object keys.
//! * **Small Surface**: Accepts any serde-serializable tool definition without
//!   requiring callers to expose a concrete tool type.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying the exact tool set they intend to expose.
//! * Writing or comparing the rendered JSON when persistence is needed.

use std::fmt::{Display, Formatter};

use serde::Serialize;
use serde_json::{Map, Value};

/// Schema identifier for deterministic MCP tool schema snapshots.
pub const TOOL_SCHEMA_SNAPSHOT_SCHEMA: &str = "mcp_tool_schema_snapshot";
/// Current schema version for deterministic MCP tool schema snapshots.
pub const TOOL_SCHEMA_SNAPSHOT_VERSION: u64 = 1;

/// Default maximum number of JSON values inspected while validating one schema.
pub const DEFAULT_SCHEMA_DIALECT_MAX_NODES: usize = 1_024;
/// Default maximum compact-JSON byte size accepted for one schema document.
pub const DEFAULT_SCHEMA_DIALECT_MAX_INPUT_BYTES: usize = 1024 * 1024;
/// Default maximum active local-reference depth while validating one schema.
pub const DEFAULT_SCHEMA_DIALECT_MAX_REFERENCE_DEPTH: usize = 32;
/// Default maximum UTF-8 byte length accepted for one local reference.
pub const DEFAULT_SCHEMA_DIALECT_MAX_REFERENCE_BYTES: usize = 4 * 1024;
/// Maximum source bytes retained in a reference error's diagnostic preview.
pub const SCHEMA_DIALECT_REFERENCE_ERROR_PREVIEW_BYTES: usize = 128;

/// Validation policy for a consumer-specific JSON Schema dialect.
///
/// The validator is deliberately opt-in: it does not change the toolkit's
/// capability constructors or the JSON Schema vocabulary accepted by other
/// consumers. A caller selects the root-level constraints its target accepts
/// and validates a schema immediately before registration or projection.
///
/// ```
/// use mcp_toolkit_core::tool_schema::{
///     validate_schema_dialect, SchemaDialectPolicy,
/// };
/// use serde_json::json;
///
/// let policy = SchemaDialectPolicy::new()
///     .with_forbidden_root_keywords(["oneOf", "enum"]);
///
/// validate_schema_dialect(&json!({"type": "object"}), &policy)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDialectPolicy {
    require_object_root: bool,
    forbidden_root_keywords: Vec<String>,
    max_reference_depth: usize,
    max_nodes: usize,
    max_input_bytes: usize,
    max_reference_bytes: usize,
}

impl SchemaDialectPolicy {
    /// Creates a policy that requires an object root and uses bounded traversal.
    pub fn new() -> Self {
        Self {
            require_object_root: true,
            forbidden_root_keywords: Vec::new(),
            max_reference_depth: DEFAULT_SCHEMA_DIALECT_MAX_REFERENCE_DEPTH,
            max_nodes: DEFAULT_SCHEMA_DIALECT_MAX_NODES,
            max_input_bytes: DEFAULT_SCHEMA_DIALECT_MAX_INPUT_BYTES,
            max_reference_bytes: DEFAULT_SCHEMA_DIALECT_MAX_REFERENCE_BYTES,
        }
    }

    /// Replaces the keywords prohibited at the schema root.
    pub fn with_forbidden_root_keywords<I, S>(mut self, keywords: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.forbidden_root_keywords = keywords
            .into_iter()
            .map(|keyword| keyword.as_ref().trim().to_string())
            .filter(|keyword| !keyword.is_empty())
            .collect();
        self
    }

    /// Sets whether the resolved schema root must include `object` in its
    /// `type` declaration.
    ///
    /// Disabling this semantic requirement still requires the submitted schema
    /// document itself to be a JSON object. Scalar JSON values are never schema
    /// documents accepted by this validator. A root `$ref` may resolve to a
    /// boolean schema only when this requirement is disabled. A JSON Schema
    /// `type` declaration may be either one valid type name or a non-empty array
    /// of unique valid type names.
    pub fn with_object_root_requirement(mut self, require_object_root: bool) -> Self {
        self.require_object_root = require_object_root;
        self
    }

    /// Sets the maximum active `#/$defs` reference depth.
    pub fn with_max_reference_depth(mut self, max_reference_depth: usize) -> Self {
        self.max_reference_depth = max_reference_depth;
        self
    }

    /// Sets the maximum raw-document and reference-graph node budget.
    pub fn with_max_nodes(mut self, max_nodes: usize) -> Self {
        self.max_nodes = max_nodes;
        self
    }

    /// Sets the maximum compact-JSON byte size of the submitted document.
    ///
    /// The validator computes this budget without serializing or cloning the
    /// document and enforces it before root reference resolution.
    pub fn with_max_input_bytes(mut self, max_input_bytes: usize) -> Self {
        self.max_input_bytes = max_input_bytes;
        self
    }

    /// Sets the maximum UTF-8 byte length of each `$ref` string.
    ///
    /// This limit is checked before percent decoding or JSON Pointer
    /// construction.
    pub fn with_max_reference_bytes(mut self, max_reference_bytes: usize) -> Self {
        self.max_reference_bytes = max_reference_bytes;
        self
    }
}

impl Default for SchemaDialectPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors returned by [`validate_schema_dialect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaDialectError {
    /// The submitted document was not a JSON object or failed object-root policy.
    RootMustBeObject,
    /// A configured root keyword was present.
    ForbiddenRootKeyword { keyword: String },
    /// A `$ref` was missing, malformed, or outside the permitted local `$defs` tree.
    ///
    /// The reference field is a bounded diagnostic preview, never the complete
    /// value of a non-string reference.
    UnsupportedReference { reference: String },
    /// A local JSON Pointer used an escape other than `~0` or `~1`.
    InvalidJsonPointerEscape { reference: String },
    /// A schema-position reference keyword is outside this dialect's supported subset.
    UnsupportedReferenceKeyword { keyword: &'static str },
    /// A schema-position keyword would establish an embedded resource that this
    /// bounded root-document resolver cannot represent safely.
    UnsupportedSchemaKeyword { keyword: &'static str },
    /// A local `$defs` reference did not resolve in the submitted schema.
    UnresolvedReference { reference: String },
    /// A local `$defs` reference would revisit an active reference chain.
    RecursiveReference { reference: String },
    /// Local-reference resolution exceeded the configured active-depth budget.
    ReferenceDepthExceeded { max_reference_depth: usize },
    /// Traversal exceeded the configured JSON-value budget.
    NodeBudgetExceeded { max_nodes: usize },
    /// The submitted document exceeded the configured compact-JSON byte budget.
    InputBudgetExceeded { max_input_bytes: usize },
    /// A `$ref` exceeded the configured UTF-8 byte budget.
    ReferenceBudgetExceeded { max_reference_bytes: usize },
    /// A schema-bearing keyword contained a value with an invalid JSON shape.
    InvalidSchemaShape {
        /// The schema keyword whose value had the invalid shape.
        keyword: String,
        /// The JSON shape required at this position.
        expected: &'static str,
        /// The JSON shape that was supplied.
        actual: &'static str,
    },
}

impl Display for SchemaDialectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootMustBeObject => formatter.write_str(
                "schema dialect requires a JSON-object document and, when enabled, a resolved `type: \"object\"` root",
            ),
            Self::ForbiddenRootKeyword { keyword } => {
                write!(
                    formatter,
                    "schema root contains forbidden keyword `{keyword}`"
                )
            }
            Self::UnsupportedReference { reference } => write!(
                formatter,
                "schema reference `{reference}` is not a supported local `#/$defs` reference"
            ),
            Self::InvalidJsonPointerEscape { reference } => write!(
                formatter,
                "schema reference `{reference}` contains an invalid JSON Pointer escape"
            ),
            Self::UnsupportedReferenceKeyword { keyword } => {
                write!(formatter, "schema reference keyword `{keyword}` is not supported")
            }
            Self::UnsupportedSchemaKeyword { keyword } => {
                write!(formatter, "schema keyword `{keyword}` is not supported")
            }
            Self::UnresolvedReference { reference } => {
                write!(formatter, "schema reference `{reference}` does not resolve")
            }
            Self::RecursiveReference { reference } => {
                write!(formatter, "schema reference `{reference}` is recursive")
            }
            Self::ReferenceDepthExceeded {
                max_reference_depth,
            } => write!(
                formatter,
                "schema reference depth exceeds configured maximum of {max_reference_depth}"
            ),
            Self::NodeBudgetExceeded { max_nodes } => {
                write!(
                    formatter,
                    "schema exceeds configured node budget of {max_nodes}"
                )
            }
            Self::InputBudgetExceeded { max_input_bytes } => write!(
                formatter,
                "schema exceeds configured input budget of {max_input_bytes} bytes"
            ),
            Self::ReferenceBudgetExceeded {
                max_reference_bytes,
            } => write!(
                formatter,
                "schema reference exceeds configured budget of {max_reference_bytes} bytes"
            ),
            Self::InvalidSchemaShape {
                keyword,
                expected,
                actual,
            } => write!(
                formatter,
                "schema keyword `{keyword}` requires {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for SchemaDialectError {}

/// Validates a JSON Schema against a bounded, caller-selected dialect.
///
/// Only local references rooted at `#/$defs/` are accepted. Their URI-fragment
/// suffix is percent-decoded before JSON Pointer resolution. Resolution never
/// performs I/O, and unresolved or recursive references fail closed. The
/// validator first preflights the complete compact-JSON input byte size and raw
/// node count before resolving a root `$ref`. It then checks configured
/// forbidden keys on every submitted or referenced root-chain schema and
/// validates every raw document node. Reference-chain validation is separate,
/// so following a `$ref` cannot inflate whole-document accounting. Every
/// reference is length-checked before percent decoding or JSON Pointer
/// construction. Schema-bearing map and composition containers must have their
/// required object or array shape, and each contained schema must be an object
/// or permitted boolean schema. Legacy tuple arrays are supported for `items`, while
/// `additionalItems` accepts only one object or boolean schema. `$dynamicRef`,
/// `$recursiveRef`, and `$id` are not supported in schema positions. In
/// particular, `$id` is rejected so a nested schema cannot establish an
/// embedded resource while this validator resolves local references against
/// the submitted root document.
///
/// A root `$ref` may have sibling keywords under modern JSON Schema semantics.
/// When object-root enforcement is enabled, both an explicit root `type`
/// sibling and the terminal referenced root must independently declare
/// `type: "object"`; a contradictory sibling fails closed.
///
/// # Errors
/// Returns an error if the root violates the policy, a reference is not a
/// bounded local `$defs` reference, a local reference cannot be resolved, a
/// reference cycle is found, an unsupported reference keyword or JSON Pointer
/// escape is used, a schema-bearing value has an invalid shape, or an input,
/// reference, node, or reference-depth budget is exceeded.
///
/// # Security
/// The function never follows remote references. It fail-closes on oversized
/// documents before root resolution, bounds reference parsing separately, and
/// retains only a fixed-size preview of attacker-controlled references in
/// public errors.
pub fn validate_schema_dialect(
    schema: &Value,
    policy: &SchemaDialectPolicy,
) -> Result<(), SchemaDialectError> {
    preflight_schema_input(schema, policy)?;
    if !schema.is_object() {
        return Err(SchemaDialectError::RootMustBeObject);
    }
    let mut state = SchemaTraversalState::default();
    resolve_root(schema, schema, policy, &mut state)?;

    traverse_schema(schema, schema, policy, &mut state)
}

#[derive(Default)]
struct SchemaTraversalState {
    nodes: usize,
    reference_graph_nodes: usize,
    active_references: Vec<String>,
}

#[derive(Default)]
struct SchemaInputBudget {
    nodes: usize,
    bytes: usize,
}

fn preflight_schema_input(
    schema: &Value,
    policy: &SchemaDialectPolicy,
) -> Result<(), SchemaDialectError> {
    preflight_json_value(schema, policy, &mut SchemaInputBudget::default())
}

fn preflight_json_value(
    value: &Value,
    policy: &SchemaDialectPolicy,
    budget: &mut SchemaInputBudget,
) -> Result<(), SchemaDialectError> {
    budget.nodes = budget
        .nodes
        .checked_add(1)
        .ok_or(SchemaDialectError::NodeBudgetExceeded {
            max_nodes: policy.max_nodes,
        })?;
    if budget.nodes > policy.max_nodes {
        return Err(SchemaDialectError::NodeBudgetExceeded {
            max_nodes: policy.max_nodes,
        });
    }

    match value {
        Value::Null => charge_input_bytes(4, policy, budget),
        Value::Bool(true) => charge_input_bytes(4, policy, budget),
        Value::Bool(false) => charge_input_bytes(5, policy, budget),
        Value::Number(number) => charge_input_bytes(number.to_string().len(), policy, budget),
        Value::String(string) => charge_json_string_bytes(string, policy, budget),
        Value::Array(values) => {
            charge_input_bytes(2, policy, budget)?;
            charge_input_bytes(values.len().saturating_sub(1), policy, budget)?;
            for value in values {
                preflight_json_value(value, policy, budget)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            charge_input_bytes(2, policy, budget)?;
            charge_input_bytes(object.len().saturating_sub(1), policy, budget)?;
            charge_input_bytes(object.len(), policy, budget)?;
            for (key, value) in object {
                charge_json_string_bytes(key, policy, budget)?;
                preflight_json_value(value, policy, budget)?;
            }
            Ok(())
        }
    }
}

fn charge_json_string_bytes(
    value: &str,
    policy: &SchemaDialectPolicy,
    budget: &mut SchemaInputBudget,
) -> Result<(), SchemaDialectError> {
    // Each counter is bounded by `value.len()`. Only the weighted aggregation
    // can overflow, and that arithmetic remains checked and fail-closed.
    let mut two_byte_escape_count = 0usize;
    let mut six_byte_escape_count = 0usize;
    for byte in value.bytes() {
        match byte {
            b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => {
                two_byte_escape_count += 1;
            }
            0x00..=0x1f => {
                six_byte_escape_count += 1;
            }
            _ => {}
        }
    }
    let escaped_extra_bytes = six_byte_escape_count
        .checked_mul(5)
        .and_then(|six_byte_extra| two_byte_escape_count.checked_add(six_byte_extra))
        .ok_or_else(|| input_budget_exceeded(policy))?;
    let serialized_bytes = value
        .len()
        .checked_add(2)
        .and_then(|quoted_bytes| quoted_bytes.checked_add(escaped_extra_bytes))
        .ok_or_else(|| input_budget_exceeded(policy))?;
    charge_input_bytes(serialized_bytes, policy, budget)
}

fn charge_input_bytes(
    bytes: usize,
    policy: &SchemaDialectPolicy,
    budget: &mut SchemaInputBudget,
) -> Result<(), SchemaDialectError> {
    budget.bytes = budget
        .bytes
        .checked_add(bytes)
        .ok_or_else(|| input_budget_exceeded(policy))?;
    if budget.bytes > policy.max_input_bytes {
        return Err(input_budget_exceeded(policy));
    }
    Ok(())
}

fn input_budget_exceeded(policy: &SchemaDialectPolicy) -> SchemaDialectError {
    SchemaDialectError::InputBudgetExceeded {
        max_input_bytes: policy.max_input_bytes,
    }
}

fn check_root_keywords(
    schema: &Value,
    policy: &SchemaDialectPolicy,
) -> Result<(), SchemaDialectError> {
    let object = schema
        .as_object()
        .ok_or(SchemaDialectError::RootMustBeObject)?;
    for keyword in &policy.forbidden_root_keywords {
        if object.contains_key(keyword) {
            return Err(SchemaDialectError::ForbiddenRootKeyword {
                keyword: keyword.clone(),
            });
        }
    }
    Ok(())
}

fn resolve_root<'a>(
    schema: &'a Value,
    document: &'a Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<&'a Value, SchemaDialectError> {
    validate_root_chain_schema(schema, policy)?;
    let Some(object) = schema.as_object() else {
        return Ok(schema);
    };
    let Some(reference) = object.get("$ref") else {
        return Ok(schema);
    };
    let reference = reference
        .as_str()
        .ok_or_else(|| SchemaDialectError::UnsupportedReference {
            reference: reference_value_preview(reference),
        })?;
    resolve_reference(reference, document, policy, state, |resolved, state| {
        resolve_root(resolved, document, policy, state)
    })
}

fn validate_root_chain_schema(
    schema: &Value,
    policy: &SchemaDialectPolicy,
) -> Result<(), SchemaDialectError> {
    let Some(object) = schema.as_object() else {
        return if schema.is_boolean() && !policy.require_object_root {
            Ok(())
        } else {
            Err(SchemaDialectError::RootMustBeObject)
        };
    };
    check_root_keywords(schema, policy)?;
    reject_unsupported_schema_keywords(object)?;
    let has_object_type = root_type_includes_object(object.get("type"))?;
    let type_present = object.contains_key("type");
    let has_reference = object.contains_key("$ref");
    if policy.require_object_root
        && ((!has_reference && !has_object_type)
            || (has_reference && type_present && !has_object_type))
    {
        return Err(SchemaDialectError::RootMustBeObject);
    }
    Ok(())
}

fn root_type_includes_object(type_value: Option<&Value>) -> Result<bool, SchemaDialectError> {
    const VALID_TYPES: [&str; 7] = [
        "null", "boolean", "object", "array", "number", "integer", "string",
    ];

    match type_value {
        None => Ok(false),
        Some(Value::String(type_name)) => {
            if !VALID_TYPES.contains(&type_name.as_str()) {
                return Err(SchemaDialectError::RootMustBeObject);
            }
            Ok(type_name == "object")
        }
        Some(Value::Array(type_names)) => {
            if type_names.is_empty() || type_names.len() > VALID_TYPES.len() {
                return Err(SchemaDialectError::RootMustBeObject);
            }
            let mut seen_types = 0_u8;
            let mut includes_object = false;
            for type_name in type_names {
                let Some(type_name) = type_name.as_str() else {
                    return Err(SchemaDialectError::RootMustBeObject);
                };
                let Some(type_index) = VALID_TYPES
                    .iter()
                    .position(|valid_type| type_name == *valid_type)
                else {
                    return Err(SchemaDialectError::RootMustBeObject);
                };
                let type_bit = 1_u8 << type_index;
                if seen_types & type_bit != 0 {
                    return Err(SchemaDialectError::RootMustBeObject);
                }
                seen_types |= type_bit;
                includes_object |= type_name == "object";
            }
            Ok(includes_object)
        }
        Some(_) => Err(SchemaDialectError::RootMustBeObject),
    }
}

fn traverse_schema(
    schema: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    traverse_schema_at(schema, document, policy, state, "<schema>")
}

fn traverse_schema_at(
    schema: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    context: &str,
) -> Result<(), SchemaDialectError> {
    count_node(policy, state)?;
    match schema {
        Value::Object(object) => {
            reject_unsupported_schema_keywords(object)?;
            if let Some(reference) = object.get("$ref") {
                validate_reference_graph(reference, document, policy, state)?;
            }
            for (schema_keyword, value) in object {
                match schema_keyword.as_str() {
                    "$defs" | "properties" | "patternProperties" | "dependentSchemas" => {
                        traverse_schema_map(value, document, policy, state, schema_keyword)?;
                    }
                    "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                        traverse_schema_array(value, document, policy, state, schema_keyword)?;
                    }
                    "items" => {
                        traverse_schema_or_array(value, document, policy, state, schema_keyword)?;
                    }
                    "additionalItems" => {
                        traverse_schema_at(value, document, policy, state, schema_keyword)?;
                    }
                    "additionalProperties"
                    | "contains"
                    | "propertyNames"
                    | "not"
                    | "if"
                    | "then"
                    | "else"
                    | "unevaluatedProperties"
                    | "unevaluatedItems"
                    | "contentSchema" => {
                        traverse_schema_at(value, document, policy, state, schema_keyword)?;
                    }
                    "dependencies" => {
                        traverse_dependencies(value, document, policy, state)?;
                    }
                    _ => traverse_data(value, policy, state)?,
                }
            }
        }
        Value::Array(_) => {
            return Err(invalid_schema_shape(
                context,
                "an object or boolean",
                schema,
            ));
        }
        Value::Bool(_) => {}
        Value::Null | Value::Number(_) | Value::String(_) => {
            return Err(invalid_schema_shape(
                context,
                "an object or boolean",
                schema,
            ));
        }
    }
    Ok(())
}

fn invalid_schema_shape(
    keyword: &str,
    expected: &'static str,
    value: &Value,
) -> SchemaDialectError {
    SchemaDialectError::InvalidSchemaShape {
        keyword: keyword.to_string(),
        expected,
        actual: json_shape(value),
    }
}

fn json_shape(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "an object",
        Value::Array(_) => "an array",
        Value::Bool(_) => "a boolean",
        Value::Null => "null",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
    }
}

fn reject_unsupported_reference_keywords(
    schema: &Map<String, Value>,
) -> Result<(), SchemaDialectError> {
    for keyword in ["$dynamicRef", "$recursiveRef"] {
        if schema.contains_key(keyword) {
            return Err(SchemaDialectError::UnsupportedReferenceKeyword { keyword });
        }
    }
    Ok(())
}

fn reject_unsupported_schema_keywords(
    schema: &Map<String, Value>,
) -> Result<(), SchemaDialectError> {
    if schema.contains_key("$id") {
        return Err(SchemaDialectError::UnsupportedSchemaKeyword { keyword: "$id" });
    }
    reject_unsupported_reference_keywords(schema)
}

fn traverse_schema_map(
    schemas: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    keyword: &str,
) -> Result<(), SchemaDialectError> {
    let schemas = schemas
        .as_object()
        .ok_or_else(|| invalid_schema_shape(keyword, "an object", schemas))?;
    count_node(policy, state)?;
    for schema in schemas.values() {
        traverse_schema_at(schema, document, policy, state, keyword)?;
    }
    Ok(())
}

fn traverse_schema_array(
    schemas: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    keyword: &str,
) -> Result<(), SchemaDialectError> {
    let schemas = schemas
        .as_array()
        .ok_or_else(|| invalid_schema_shape(keyword, "an array", schemas))?;
    count_node(policy, state)?;
    for schema in schemas {
        traverse_schema_at(schema, document, policy, state, keyword)?;
    }
    Ok(())
}

fn traverse_schema_or_array(
    schema: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    keyword: &str,
) -> Result<(), SchemaDialectError> {
    if schema.is_array() {
        traverse_schema_array(schema, document, policy, state, keyword)
    } else {
        traverse_schema_at(schema, document, policy, state, keyword)
    }
}

fn traverse_dependencies(
    dependencies: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    let Some(dependencies) = dependencies.as_object() else {
        return Err(invalid_schema_shape(
            "dependencies",
            "an object",
            dependencies,
        ));
    };
    count_node(policy, state)?;
    for dependency in dependencies.values() {
        if dependency.is_object() || dependency.is_boolean() {
            traverse_schema_at(dependency, document, policy, state, "dependencies")?;
        } else if !dependency.is_array() {
            return Err(invalid_schema_shape(
                "dependencies",
                "a schema object, boolean, or array",
                dependency,
            ));
        } else {
            traverse_data(dependency, policy, state)?;
        }
    }
    Ok(())
}

fn traverse_data(
    value: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    count_node(policy, state)?;
    match value {
        Value::Object(object) => {
            for value in object.values() {
                traverse_data(value, policy, state)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                traverse_data(value, policy, state)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_reference_graph(
    reference: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    let reference = reference
        .as_str()
        .ok_or_else(|| SchemaDialectError::UnsupportedReference {
            reference: reference_value_preview(reference),
        })?;
    resolve_reference(reference, document, policy, state, |resolved, state| {
        traverse_reference_graph_schema(resolved, document, policy, state)
    })
}

fn traverse_reference_graph_schema(
    schema: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    traverse_reference_graph_schema_at(schema, document, policy, state, "<schema>")
}

fn traverse_reference_graph_schema_at(
    schema: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    context: &str,
) -> Result<(), SchemaDialectError> {
    count_reference_graph_node(policy, state)?;
    let Some(object) = schema.as_object() else {
        if schema.is_boolean() {
            return Ok(());
        }
        return Err(invalid_schema_shape(
            context,
            "an object or boolean",
            schema,
        ));
    };
    reject_unsupported_schema_keywords(object)?;
    if let Some(reference) = object.get("$ref") {
        validate_reference_graph(reference, document, policy, state)?;
    }
    for (schema_keyword, value) in object {
        match schema_keyword.as_str() {
            "$defs" | "properties" | "patternProperties" | "dependentSchemas" => {
                traverse_reference_graph_map(value, document, policy, state, schema_keyword)?;
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                traverse_reference_graph_array(value, document, policy, state, schema_keyword)?;
            }
            "items" => {
                traverse_reference_graph_schema_or_array(
                    value,
                    document,
                    policy,
                    state,
                    schema_keyword,
                )?;
            }
            "additionalItems" => {
                traverse_reference_graph_schema_at(value, document, policy, state, schema_keyword)?;
            }
            "additionalProperties"
            | "contains"
            | "propertyNames"
            | "not"
            | "if"
            | "then"
            | "else"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "contentSchema" => {
                traverse_reference_graph_schema_at(value, document, policy, state, schema_keyword)?;
            }
            "dependencies" => {
                traverse_reference_graph_dependencies(value, document, policy, state)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn traverse_reference_graph_map(
    schemas: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    keyword: &str,
) -> Result<(), SchemaDialectError> {
    let schemas = schemas
        .as_object()
        .ok_or_else(|| invalid_schema_shape(keyword, "an object", schemas))?;
    for schema in schemas.values() {
        traverse_reference_graph_schema_at(schema, document, policy, state, keyword)?;
    }
    Ok(())
}

fn traverse_reference_graph_array(
    schemas: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    keyword: &str,
) -> Result<(), SchemaDialectError> {
    let schemas = schemas
        .as_array()
        .ok_or_else(|| invalid_schema_shape(keyword, "an array", schemas))?;
    for schema in schemas {
        traverse_reference_graph_schema_at(schema, document, policy, state, keyword)?;
    }
    Ok(())
}

fn traverse_reference_graph_schema_or_array(
    schema: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    keyword: &str,
) -> Result<(), SchemaDialectError> {
    if schema.is_array() {
        traverse_reference_graph_array(schema, document, policy, state, keyword)
    } else {
        traverse_reference_graph_schema_at(schema, document, policy, state, keyword)
    }
}

fn traverse_reference_graph_dependencies(
    dependencies: &Value,
    document: &Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    let Some(dependencies) = dependencies.as_object() else {
        return Err(invalid_schema_shape(
            "dependencies",
            "an object",
            dependencies,
        ));
    };
    for dependency in dependencies.values() {
        if dependency.is_object() || dependency.is_boolean() {
            traverse_reference_graph_schema_at(
                dependency,
                document,
                policy,
                state,
                "dependencies",
            )?;
        } else if !dependency.is_array() {
            return Err(invalid_schema_shape(
                "dependencies",
                "a schema object, boolean, or array",
                dependency,
            ));
        }
    }
    Ok(())
}

fn count_node(
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    state.nodes = state.nodes.saturating_add(1);
    if state.nodes > policy.max_nodes {
        return Err(SchemaDialectError::NodeBudgetExceeded {
            max_nodes: policy.max_nodes,
        });
    }
    Ok(())
}

fn count_reference_graph_node(
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
) -> Result<(), SchemaDialectError> {
    state.reference_graph_nodes = state.reference_graph_nodes.saturating_add(1);
    if state.reference_graph_nodes > policy.max_nodes {
        return Err(SchemaDialectError::NodeBudgetExceeded {
            max_nodes: policy.max_nodes,
        });
    }
    Ok(())
}

fn resolve_reference<'a, T, F>(
    reference: &str,
    document: &'a Value,
    policy: &SchemaDialectPolicy,
    state: &mut SchemaTraversalState,
    visit: F,
) -> Result<T, SchemaDialectError>
where
    F: FnOnce(&'a Value, &mut SchemaTraversalState) -> Result<T, SchemaDialectError>,
{
    let pointer = local_reference_pointer(reference, policy)?;
    if state.active_references.len() >= policy.max_reference_depth {
        return Err(SchemaDialectError::ReferenceDepthExceeded {
            max_reference_depth: policy.max_reference_depth,
        });
    }
    if state
        .active_references
        .iter()
        .any(|active_reference| active_reference == &pointer)
    {
        return Err(SchemaDialectError::RecursiveReference {
            reference: reference_error_preview(reference),
        });
    }
    let resolved =
        document
            .pointer(&pointer)
            .ok_or_else(|| SchemaDialectError::UnresolvedReference {
                reference: reference_error_preview(reference),
            })?;
    state.active_references.push(pointer);
    let result = visit(resolved, state);
    state.active_references.pop();
    result
}

fn local_reference_pointer(
    reference: &str,
    policy: &SchemaDialectPolicy,
) -> Result<String, SchemaDialectError> {
    if reference.len() > policy.max_reference_bytes {
        return Err(SchemaDialectError::ReferenceBudgetExceeded {
            max_reference_bytes: policy.max_reference_bytes,
        });
    }
    let encoded_path = reference.strip_prefix("#/$defs/").ok_or_else(|| {
        SchemaDialectError::UnsupportedReference {
            reference: reference_error_preview(reference),
        }
    })?;
    let decoded_path = decode_uri_fragment(encoded_path).ok_or_else(|| {
        SchemaDialectError::UnsupportedReference {
            reference: reference_error_preview(reference),
        }
    })?;
    if !has_valid_json_pointer_escapes(&decoded_path) {
        return Err(SchemaDialectError::InvalidJsonPointerEscape {
            reference: reference_error_preview(reference),
        });
    }
    Ok(format!("/$defs/{decoded_path}"))
}

fn reference_value_preview(reference: &Value) -> String {
    match reference {
        Value::String(reference) => reference_error_preview(reference),
        Value::Null => "<null>".to_string(),
        Value::Bool(_) => "<boolean>".to_string(),
        Value::Number(_) => "<number>".to_string(),
        Value::Array(_) => "<array>".to_string(),
        Value::Object(_) => "<object>".to_string(),
    }
}

fn reference_error_preview(reference: &str) -> String {
    if reference.len() <= SCHEMA_DIALECT_REFERENCE_ERROR_PREVIEW_BYTES {
        return reference.to_string();
    }
    let mut preview_end = SCHEMA_DIALECT_REFERENCE_ERROR_PREVIEW_BYTES;
    while !reference.is_char_boundary(preview_end) {
        preview_end -= 1;
    }
    let mut preview = String::with_capacity(preview_end + 3);
    preview.push_str(&reference[..preview_end]);
    preview.push_str("...");
    preview
}

fn has_valid_json_pointer_escapes(pointer: &str) -> bool {
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'~' {
            index += 1;
            continue;
        }
        let Some(escape) = bytes.get(index + 1) else {
            return false;
        };
        if !matches!(*escape, b'0' | b'1') {
            return false;
        }
        index += 2;
    }
    true
}

fn decode_uri_fragment(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = *bytes.get(index + 1)?;
        let low = *bytes.get(index + 2)?;
        decoded.push((hex_value(high)? << 4) | hex_value(low)?);
        index += 3;
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Extracts deterministic tool names from a list of serialized tool definitions.
///
/// # Errors
/// Returns a serialization error if any tool definition cannot be converted to
/// JSON.
pub fn tool_names<T>(tools: &[T]) -> Result<Vec<String>, serde_json::Error>
where
    T: Serialize,
{
    let mut names = Vec::with_capacity(tools.len());
    for tool in tools {
        let value = serde_json::to_value(tool)?;
        if let Some(name) = value
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(Value::as_str)
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Generates a deterministic JSON snapshot from a list of tool definitions.
///
/// # Errors
/// Returns a serialization error if any tool definition cannot be converted to
/// JSON.
pub fn tool_schema_snapshot_value<T>(tools: &[T]) -> Result<Value, serde_json::Error>
where
    T: Serialize,
{
    let mut serialized = Vec::with_capacity(tools.len());
    for tool in tools {
        serialized.push(serde_json::to_value(tool)?);
    }
    serialized.sort_by_key(tool_sort_key);
    Ok(canonicalize_json(Value::Object(Map::from_iter([
        (
            "schema".to_string(),
            Value::String(TOOL_SCHEMA_SNAPSHOT_SCHEMA.to_string()),
        ),
        (
            "version".to_string(),
            Value::Number(TOOL_SCHEMA_SNAPSHOT_VERSION.into()),
        ),
        ("tools".to_string(), Value::Array(serialized)),
    ]))))
}

fn tool_sort_key(value: &Value) -> String {
    value
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut ordered = Map::new();
            for (key, value) in entries {
                ordered.insert(key, canonicalize_json(value));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        charge_json_string_bytes, tool_names, tool_schema_snapshot_value, validate_schema_dialect,
        SchemaDialectError, SchemaDialectPolicy, SchemaInputBudget,
        SCHEMA_DIALECT_REFERENCE_ERROR_PREVIEW_BYTES,
    };
    use serde_json::{json, Map, Value};

    #[test]
    fn dialect_validation_accepts_an_object_root_resolved_from_local_defs() {
        let schema = json!({
            "$ref": "#/$defs/request",
            "$defs": {
                "request": {
                    "type": "object",
                    "properties": {
                        "filter": {"$ref": "#/$defs/filter"}
                    }
                },
                "filter": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}}
                }
            }
        });
        let policy = SchemaDialectPolicy::new()
            .with_forbidden_root_keywords(["oneOf", "anyOf", "allOf", "enum", "const", "not"]);

        assert_eq!(validate_schema_dialect(&schema, &policy), Ok(()));
    }

    #[test]
    fn dialect_validation_checks_configured_keywords_before_and_after_root_resolution() {
        let policy = SchemaDialectPolicy::new().with_forbidden_root_keywords(["enum"]);
        let direct_schema = json!({"type": "object", "enum": []});
        let referenced_schema = json!({
            "$ref": "#/$defs/request",
            "$defs": {"request": {"type": "object", "enum": []}}
        });

        assert_eq!(
            validate_schema_dialect(&direct_schema, &policy),
            Err(SchemaDialectError::ForbiddenRootKeyword {
                keyword: "enum".to_string(),
            })
        );
        assert_eq!(
            validate_schema_dialect(&referenced_schema, &policy),
            Err(SchemaDialectError::ForbiddenRootKeyword {
                keyword: "enum".to_string(),
            })
        );
    }

    #[test]
    fn dialect_validation_rejects_non_object_and_unsupported_roots() {
        let policy = SchemaDialectPolicy::new();

        assert_eq!(
            validate_schema_dialect(&json!(true), &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&json!({"type": "string"}), &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
    }

    #[test]
    fn dialect_validation_preflights_giant_root_values_before_semantic_errors() {
        let max_input_bytes = 256;
        let policy = SchemaDialectPolicy::new()
            .with_max_input_bytes(max_input_bytes)
            .with_max_nodes(4_096);
        let giant_string_root = Value::String("x".repeat(4_096));
        let giant_array_root = Value::Array(vec![Value::Null; 256]);
        let giant_non_string_root_reference = json!({
            "$ref": {"payload": "x".repeat(4_096)}
        });
        let expected = Err(SchemaDialectError::InputBudgetExceeded { max_input_bytes });

        assert_eq!(
            validate_schema_dialect(&giant_string_root, &policy),
            expected.clone()
        );
        assert_eq!(
            validate_schema_dialect(&giant_array_root, &policy),
            expected.clone()
        );
        assert_eq!(
            validate_schema_dialect(&giant_non_string_root_reference, &policy),
            expected
        );
    }

    #[test]
    fn dialect_validation_enforces_exact_input_and_reference_byte_boundaries() {
        let smallest_object_schema = json!({"type": "object"});
        assert_eq!(
            validate_schema_dialect(
                &smallest_object_schema,
                &SchemaDialectPolicy::new().with_max_input_bytes(17),
            ),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(
                &smallest_object_schema,
                &SchemaDialectPolicy::new().with_max_input_bytes(16),
            ),
            Err(SchemaDialectError::InputBudgetExceeded {
                max_input_bytes: 16,
            })
        );

        let escaped_string_schema = json!({
            "type": "object",
            "const": "\"\\\u{0000}\n"
        });
        assert_eq!(
            validate_schema_dialect(
                &escaped_string_schema,
                &SchemaDialectPolicy::new().with_max_input_bytes(40),
            ),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(
                &escaped_string_schema,
                &SchemaDialectPolicy::new().with_max_input_bytes(39),
            ),
            Err(SchemaDialectError::InputBudgetExceeded {
                max_input_bytes: 39,
            })
        );

        let reference = "#/$defs/root";
        let referenced_schema = json!({
            "$ref": reference,
            "$defs": {"root": {"type": "object"}}
        });
        assert_eq!(
            validate_schema_dialect(
                &referenced_schema,
                &SchemaDialectPolicy::new().with_max_reference_bytes(reference.len()),
            ),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(
                &referenced_schema,
                &SchemaDialectPolicy::new().with_max_reference_bytes(reference.len() - 1),
            ),
            Err(SchemaDialectError::ReferenceBudgetExceeded {
                max_reference_bytes: reference.len() - 1,
            })
        );
    }

    #[test]
    fn dialect_string_byte_charge_fails_closed_at_usize_boundary() {
        let policy = SchemaDialectPolicy::new().with_max_input_bytes(usize::MAX);
        let mut exact_budget = SchemaInputBudget {
            nodes: 0,
            bytes: usize::MAX - 2,
        };
        assert_eq!(
            charge_json_string_bytes("", &policy, &mut exact_budget),
            Ok(())
        );
        assert_eq!(exact_budget.bytes, usize::MAX);

        let mut crossing_budget = SchemaInputBudget {
            nodes: 0,
            bytes: usize::MAX - 1,
        };
        assert_eq!(
            charge_json_string_bytes("", &policy, &mut crossing_budget),
            Err(SchemaDialectError::InputBudgetExceeded {
                max_input_bytes: usize::MAX,
            })
        );
        assert_eq!(crossing_budget.bytes, usize::MAX - 1);
    }

    #[test]
    fn dialect_validation_bounds_reference_errors_without_serializing_attacker_values() {
        let non_string_reference = json!({
            "$ref": {"payload": ["attacker", "controlled"]}
        });
        assert_eq!(
            validate_schema_dialect(&non_string_reference, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::UnsupportedReference {
                reference: "<object>".to_string(),
            })
        );

        let long_reference = format!("https://example.invalid/{}", "x".repeat(1_024));
        let long_reference_schema = json!({
            "type": "object",
            "properties": {"entry": {"$ref": long_reference.clone()}}
        });
        let expected_preview = format!(
            "{}...",
            &long_reference[..SCHEMA_DIALECT_REFERENCE_ERROR_PREVIEW_BYTES]
        );
        assert_eq!(
            validate_schema_dialect(
                &long_reference_schema,
                &SchemaDialectPolicy::new()
                    .with_max_input_bytes(4_096)
                    .with_max_reference_bytes(2_048),
            ),
            Err(SchemaDialectError::UnsupportedReference {
                reference: expected_preview,
            })
        );
    }

    #[test]
    fn dialect_validation_rejects_many_large_references_as_one_bounded_input() {
        let mut properties = Map::new();
        for index in 0..32 {
            properties.insert(
                format!("property_{index}"),
                json!({"$ref": format!("#/$defs/{index}_{}", "x".repeat(128))}),
            );
        }
        let schema = json!({
            "type": "object",
            "properties": properties
        });

        assert_eq!(
            validate_schema_dialect(
                &schema,
                &SchemaDialectPolicy::new()
                    .with_max_nodes(1_024)
                    .with_max_input_bytes(1_024)
                    .with_max_reference_bytes(256),
            ),
            Err(SchemaDialectError::InputBudgetExceeded {
                max_input_bytes: 1_024,
            })
        );
    }

    #[test]
    fn dialect_validation_handles_type_arrays_for_direct_and_referenced_roots() {
        let policy = SchemaDialectPolicy::new();
        let relaxed = policy.clone().with_object_root_requirement(false);
        let direct_object_union = json!({"type": ["object", "null"]});
        let maximal_valid_union = json!({
            "type": ["null", "boolean", "object", "array", "number", "integer", "string"]
        });
        let referenced_object_union = json!({
            "$ref": "#/$defs/root",
            "$defs": {"root": {"type": ["object", "null"]}}
        });
        let direct_string_union = json!({"type": ["string", "null"]});
        let referenced_string_union = json!({
            "$ref": "#/$defs/root",
            "$defs": {"root": {"type": ["string", "null"]}}
        });
        let malformed_direct = [
            json!({"type": []}),
            json!({"type": ["object", 1]}),
            json!({"type": ["object", "object"]}),
            json!({"type": "unknown"}),
        ];
        let oversized_type_array = json!({"type": vec!["object"; 4_096]});
        let malformed_referenced = json!({
            "$ref": "#/$defs/root",
            "$defs": {"root": {"type": ["object", null]}}
        });

        assert_eq!(
            validate_schema_dialect(&direct_object_union, &policy),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&maximal_valid_union, &policy),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&referenced_object_union, &policy),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&direct_string_union, &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&referenced_string_union, &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&direct_string_union, &relaxed),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&referenced_string_union, &relaxed),
            Ok(())
        );
        for malformed in malformed_direct {
            assert_eq!(
                validate_schema_dialect(&malformed, &policy),
                Err(SchemaDialectError::RootMustBeObject)
            );
            assert_eq!(
                validate_schema_dialect(&malformed, &relaxed),
                Err(SchemaDialectError::RootMustBeObject)
            );
        }
        assert_eq!(
            validate_schema_dialect(&oversized_type_array, &policy),
            Err(SchemaDialectError::NodeBudgetExceeded { max_nodes: 1_024 })
        );
        assert_eq!(
            validate_schema_dialect(&oversized_type_array, &relaxed),
            Err(SchemaDialectError::NodeBudgetExceeded { max_nodes: 1_024 })
        );
        assert_eq!(
            validate_schema_dialect(&malformed_referenced, &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&malformed_referenced, &relaxed),
            Err(SchemaDialectError::RootMustBeObject)
        );
    }

    #[test]
    fn dialect_validation_does_not_treat_legacy_definitions_as_schema_containers() {
        let schema = json!({
            "type": "object",
            "definitions": {
                "legacy": {"$ref": "https://example.invalid/remote"}
            }
        });

        assert_eq!(
            validate_schema_dialect(&schema, &SchemaDialectPolicy::new()),
            Ok(())
        );
    }

    #[test]
    fn dialect_validation_rejects_remote_and_unresolved_references() {
        let policy = SchemaDialectPolicy::new();
        let remote = json!({"$ref": "https://example.invalid/schema.json"});
        let missing = json!({"$ref": "#/$defs/missing"});

        assert_eq!(
            validate_schema_dialect(&remote, &policy),
            Err(SchemaDialectError::UnsupportedReference {
                reference: "https://example.invalid/schema.json".to_string(),
            })
        );
        assert_eq!(
            validate_schema_dialect(&missing, &policy),
            Err(SchemaDialectError::UnresolvedReference {
                reference: "#/$defs/missing".to_string(),
            })
        );
    }

    #[test]
    fn dialect_validation_decodes_uri_fragments_before_json_pointer_resolution() {
        let encoded_space = json!({
            "$ref": "#/$defs/with%20space",
            "$defs": {"with space": {"type": "object"}}
        });
        let encoded_utf8 = json!({
            "type": "object",
            "properties": {"mark": {"$ref": "#/$defs/%E2%9C%93"}},
            "$defs": {"✓": {"type": "object"}}
        });
        let json_pointer_escaped_name = json!({
            "$ref": "#/$defs/a~1b~0c",
            "$defs": {"a/b~c": {"type": "object"}}
        });
        let malformed_escape = json!({"$ref": "#/$defs/bad%2"});

        assert_eq!(
            validate_schema_dialect(&encoded_space, &SchemaDialectPolicy::new()),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&encoded_utf8, &SchemaDialectPolicy::new()),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&json_pointer_escaped_name, &SchemaDialectPolicy::new()),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&malformed_escape, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::UnsupportedReference {
                reference: "#/$defs/bad%2".to_string(),
            })
        );
    }

    #[test]
    fn dialect_validation_rejects_invalid_json_pointer_escapes_even_when_keys_exist() {
        let invalid_numeric_escape = json!({
            "$ref": "#/$defs/a~2b",
            "$defs": {"a~2b": {"type": "object"}}
        });
        let invalid_letter_escape = json!({
            "$ref": "#/$defs/a~xb",
            "$defs": {"a~xb": {"type": "object"}}
        });
        let trailing_escape = json!({
            "$ref": "#/$defs/a~",
            "$defs": {"a~": {"type": "object"}}
        });

        assert_eq!(
            validate_schema_dialect(&invalid_numeric_escape, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::InvalidJsonPointerEscape {
                reference: "#/$defs/a~2b".to_string(),
            })
        );
        assert_eq!(
            validate_schema_dialect(&invalid_letter_escape, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::InvalidJsonPointerEscape {
                reference: "#/$defs/a~xb".to_string(),
            })
        );
        assert_eq!(
            validate_schema_dialect(&trailing_escape, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::InvalidJsonPointerEscape {
                reference: "#/$defs/a~".to_string(),
            })
        );
    }

    #[test]
    fn dialect_validation_rejects_unsupported_reference_keywords_in_schema_positions() {
        let dynamic_reference = json!({
            "type": "object",
            "properties": {
                "child": {"$dynamicRef": "https://example.invalid/dynamic"}
            }
        });
        let recursive_reference = json!({
            "type": "object",
            "$defs": {
                "unused": {"$recursiveRef": "https://example.invalid/recursive"}
            }
        });

        assert_eq!(
            validate_schema_dialect(&dynamic_reference, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::UnsupportedReferenceKeyword {
                keyword: "$dynamicRef",
            })
        );
        assert_eq!(
            validate_schema_dialect(&recursive_reference, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::UnsupportedReferenceKeyword {
                keyword: "$recursiveRef",
            })
        );
    }

    #[test]
    fn dialect_validation_rejects_malformed_schema_containers_before_reference_values() {
        let policy = SchemaDialectPolicy::new();
        let malformed_containers = [
            (
                json!({
                    "type": "object",
                    "$defs": [
                        {"$ref": "https://example.invalid/remote"},
                        {"$dynamicRef": "#/$defs/dynamic"},
                        {"$recursiveRef": "#/$defs/recursive"}
                    ]
                }),
                SchemaDialectError::InvalidSchemaShape {
                    keyword: "$defs".to_string(),
                    expected: "an object",
                    actual: "an array",
                },
            ),
            (
                json!({
                    "type": "object",
                    "properties": [
                        {"$ref": "https://example.invalid/remote"},
                        {"$dynamicRef": "#/$defs/dynamic"},
                        {"$recursiveRef": "#/$defs/recursive"}
                    ]
                }),
                SchemaDialectError::InvalidSchemaShape {
                    keyword: "properties".to_string(),
                    expected: "an object",
                    actual: "an array",
                },
            ),
            (
                json!({
                    "type": "object",
                    "allOf": {
                        "remote": {"$ref": "https://example.invalid/remote"},
                        "dynamic": {"$dynamicRef": "#/$defs/dynamic"},
                        "recursive": {"$recursiveRef": "#/$defs/recursive"}
                    }
                }),
                SchemaDialectError::InvalidSchemaShape {
                    keyword: "allOf".to_string(),
                    expected: "an array",
                    actual: "an object",
                },
            ),
        ];

        for (schema, expected) in malformed_containers {
            assert_eq!(validate_schema_dialect(&schema, &policy), Err(expected));
        }
    }

    #[test]
    fn dialect_validation_rejects_malformed_containers_in_reference_graph() {
        let schema = json!({
            "$ref": "#/$defs/root",
            "$defs": {
                "root": {
                    "type": "object",
                    "properties": [
                        {"$ref": "https://example.invalid/remote"},
                        {"$dynamicRef": "#/$defs/dynamic"},
                        {"$recursiveRef": "#/$defs/recursive"}
                    ]
                }
            }
        });

        assert_eq!(
            validate_schema_dialect(&schema, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::InvalidSchemaShape {
                keyword: "properties".to_string(),
                expected: "an object",
                actual: "an array",
            })
        );
    }

    #[test]
    fn dialect_validation_rejects_invalid_scalar_schema_values_but_accepts_booleans() {
        let malformed = [
            (
                json!({
                    "type": "object",
                    "properties": {"child": "invalid"}
                }),
                SchemaDialectError::InvalidSchemaShape {
                    keyword: "properties".to_string(),
                    expected: "an object or boolean",
                    actual: "a string",
                },
            ),
            (
                json!({"type": "object", "allOf": [null]}),
                SchemaDialectError::InvalidSchemaShape {
                    keyword: "allOf".to_string(),
                    expected: "an object or boolean",
                    actual: "null",
                },
            ),
        ];

        for (schema, expected) in malformed {
            assert_eq!(
                validate_schema_dialect(&schema, &SchemaDialectPolicy::new()),
                Err(expected)
            );
        }

        let boolean_schemas = json!({
            "type": "object",
            "$defs": {"allow": true},
            "properties": {"allow": false},
            "allOf": [true],
            "items": false,
            "additionalProperties": true
        });
        assert_eq!(
            validate_schema_dialect(&boolean_schemas, &SchemaDialectPolicy::new()),
            Ok(())
        );
    }

    #[test]
    fn dialect_validation_treats_reference_shaped_literal_data_as_data() {
        let schema = json!({
            "type": "object",
            "default": {"$ref": "https://example.invalid/default"},
            "examples": [{"$dynamicRef": "https://example.invalid/example"}],
            "const": {"$recursiveRef": "https://example.invalid/const"},
            "enum": [{"$ref": "https://example.invalid/enum"}]
        });

        assert_eq!(
            validate_schema_dialect(&schema, &SchemaDialectPolicy::new()),
            Ok(())
        );
    }

    #[test]
    fn dialect_validation_keeps_schema_document_and_root_reference_rules_explicit() {
        let relaxed = SchemaDialectPolicy::new().with_object_root_requirement(false);
        let referenced_string = json!({
            "$ref": "#/$defs/string",
            "$defs": {"string": {"type": "string"}}
        });
        let referenced_boolean = json!({
            "$ref": "#/$defs/accept",
            "$defs": {"accept": true}
        });
        let contradictory_root_sibling = json!({
            "$ref": "#/$defs/object",
            "type": "string",
            "$defs": {"object": {"type": "object"}}
        });
        let compatible_root_sibling = json!({
            "$ref": "#/$defs/object",
            "type": "object",
            "$defs": {"object": {"type": "object"}}
        });

        assert_eq!(
            validate_schema_dialect(&json!({"type": "string"}), &relaxed),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&referenced_string, &relaxed),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&referenced_boolean, &relaxed),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&json!(true), &relaxed),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&contradictory_root_sibling, &SchemaDialectPolicy::new(),),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&compatible_root_sibling, &SchemaDialectPolicy::new()),
            Ok(())
        );
    }

    #[test]
    fn dialect_validation_checks_every_root_reference_chain_schema() {
        let policy = SchemaDialectPolicy::new().with_forbidden_root_keywords(["not"]);
        let valid_chain = json!({
            "$ref": "#/$defs/first",
            "$defs": {
                "first": {"$ref": "#/$defs/second"},
                "second": {"type": "object"}
            }
        });
        let malformed_intermediate_type = json!({
            "$ref": "#/$defs/first",
            "$defs": {
                "first": {"$ref": "#/$defs/second", "type": ["object", true]},
                "second": {"type": "object"}
            }
        });
        let contradictory_intermediate_type = json!({
            "$ref": "#/$defs/first",
            "$defs": {
                "first": {"$ref": "#/$defs/second", "type": "string"},
                "second": {"type": "object"}
            }
        });
        let malformed_terminal_type = json!({
            "$ref": "#/$defs/first",
            "$defs": {
                "first": {"$ref": "#/$defs/second"},
                "second": {"type": true}
            }
        });
        let forbidden_intermediate_keyword = json!({
            "$ref": "#/$defs/first",
            "$defs": {
                "first": {"$ref": "#/$defs/second", "not": {"type": "string"}},
                "second": {"type": "object"}
            }
        });

        assert_eq!(validate_schema_dialect(&valid_chain, &policy), Ok(()));
        assert_eq!(
            validate_schema_dialect(&malformed_intermediate_type, &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&contradictory_intermediate_type, &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&malformed_terminal_type, &policy),
            Err(SchemaDialectError::RootMustBeObject)
        );
        assert_eq!(
            validate_schema_dialect(&forbidden_intermediate_keyword, &policy),
            Err(SchemaDialectError::ForbiddenRootKeyword {
                keyword: "not".to_string(),
            })
        );
    }

    #[test]
    fn dialect_validation_validates_unreferenced_definitions_and_counts_raw_nodes_once() {
        let referenced_definition = json!({
            "type": "object",
            "properties": {"request": {"$ref": "#/$defs/request"}},
            "$defs": {"request": {"type": "object"}}
        });
        let unreferenced_remote_reference = json!({
            "type": "object",
            "$defs": {
                "unused": {"$ref": "https://example.invalid/schema.json"}
            }
        });

        assert_eq!(
            validate_schema_dialect(
                &referenced_definition,
                &SchemaDialectPolicy::new().with_max_nodes(8),
            ),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(
                &referenced_definition,
                &SchemaDialectPolicy::new().with_max_nodes(7),
            ),
            Err(SchemaDialectError::NodeBudgetExceeded { max_nodes: 7 })
        );
        assert_eq!(
            validate_schema_dialect(&unreferenced_remote_reference, &SchemaDialectPolicy::new(),),
            Err(SchemaDialectError::UnsupportedReference {
                reference: "https://example.invalid/schema.json".to_string(),
            })
        );
    }

    #[test]
    fn dialect_validation_rejects_recursive_references_and_exhausted_budgets() {
        let recursive = json!({
            "$ref": "#/$defs/request",
            "$defs": {"request": {"$ref": "#/$defs/request"}}
        });
        let nested = json!({
            "$ref": "#/$defs/first",
            "$defs": {
                "first": {"$ref": "#/$defs/second"},
                "second": {"type": "object"}
            }
        });
        let small = json!({"type": "object"});

        assert_eq!(
            validate_schema_dialect(&recursive, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::RecursiveReference {
                reference: "#/$defs/request".to_string(),
            })
        );
        assert_eq!(
            validate_schema_dialect(
                &nested,
                &SchemaDialectPolicy::new().with_max_reference_depth(1),
            ),
            Err(SchemaDialectError::ReferenceDepthExceeded {
                max_reference_depth: 1,
            })
        );
        assert_eq!(
            validate_schema_dialect(&small, &SchemaDialectPolicy::new().with_max_nodes(1)),
            Err(SchemaDialectError::NodeBudgetExceeded { max_nodes: 1 })
        );
    }

    #[test]
    fn dialect_validation_rejects_cycles_through_nested_schema_positions() {
        let properties_cycle = json!({
            "type": "object",
            "properties": {"entry": {"$ref": "#/$defs/first"}},
            "$defs": {
                "first": {
                    "type": "object",
                    "properties": {"next": {"$ref": "#/$defs/second"}}
                },
                "second": {
                    "type": "object",
                    "properties": {"next": {"$ref": "#/$defs/first"}}
                }
            }
        });
        let items_and_composition_cycle = json!({
            "type": "object",
            "properties": {"entry": {"$ref": "#/$defs/first"}},
            "$defs": {
                "first": {"items": {"$ref": "#/$defs/second"}},
                "second": {"allOf": [{"$ref": "#/$defs/first"}]}
            }
        });
        let acyclic_nested_reference = json!({
            "type": "object",
            "properties": {"entry": {"$ref": "#/$defs/first"}},
            "$defs": {
                "first": {"items": {"$ref": "#/$defs/second"}},
                "second": {"type": "object"}
            }
        });

        assert_eq!(
            validate_schema_dialect(&properties_cycle, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::RecursiveReference {
                reference: "#/$defs/second".to_string(),
            })
        );
        assert_eq!(
            validate_schema_dialect(&items_and_composition_cycle, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::RecursiveReference {
                reference: "#/$defs/second".to_string(),
            })
        );
        assert_eq!(
            validate_schema_dialect(&acyclic_nested_reference, &SchemaDialectPolicy::new()),
            Ok(())
        );
    }

    #[test]
    fn dialect_validation_rejects_embedded_resource_local_unresolved_reference() {
        let schema = json!({
            "type": "object",
            "properties": {"entry": {"$ref": "#/$defs/embedded"}},
            "$defs": {
                "embedded": {
                    "$id": "https://example.invalid/embedded.json",
                    "$ref": "#/$defs/missing",
                    "$defs": {"local": {"type": "string"}}
                },
                "missing": {"type": "object"}
            }
        });

        assert_eq!(
            validate_schema_dialect(&schema, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::UnsupportedSchemaKeyword { keyword: "$id" })
        );
    }

    #[test]
    fn dialect_validation_rejects_embedded_resource_cycle() {
        let schema = json!({
            "type": "object",
            "properties": {"entry": {"$ref": "#/$defs/embedded"}},
            "$defs": {
                "embedded": {
                    "$id": "https://example.invalid/embedded.json",
                    "$ref": "#/$defs/first",
                    "$defs": {
                        "first": {"$ref": "#/$defs/second"},
                        "second": {"$ref": "#/$defs/first"}
                    }
                },
                "first": {"type": "object"},
                "second": {"type": "object"}
            }
        });

        assert_eq!(
            validate_schema_dialect(&schema, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::UnsupportedSchemaKeyword { keyword: "$id" })
        );
    }

    #[test]
    fn dialect_validation_limits_additional_items_to_one_schema() {
        let object_schema = json!({
            "type": "object",
            "items": [{"type": "string"}],
            "additionalItems": {"type": "number"}
        });
        let boolean_schema = json!({
            "type": "object",
            "items": [{"type": "string"}],
            "additionalItems": false
        });
        let array_schema = json!({
            "type": "object",
            "items": [{"type": "string"}],
            "additionalItems": [{"type": "number"}]
        });

        assert_eq!(
            validate_schema_dialect(&object_schema, &SchemaDialectPolicy::new()),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&boolean_schema, &SchemaDialectPolicy::new()),
            Ok(())
        );
        assert_eq!(
            validate_schema_dialect(&array_schema, &SchemaDialectPolicy::new()),
            Err(SchemaDialectError::InvalidSchemaShape {
                keyword: "additionalItems".to_string(),
                expected: "an object or boolean",
                actual: "an array",
            })
        );
    }

    #[test]
    fn snapshot_value_is_sorted_by_tool_name() {
        let tools = vec![
            json!({"description":"second","name":"zeta","inputSchema":{"type":"object"}}),
            json!({"name":"alpha","description":"first","inputSchema":{"type":"object"}}),
        ];
        let snapshot = tool_schema_snapshot_value(&tools).expect("serialize snapshot");
        let names: Vec<&str> = snapshot["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn snapshot_value_canonicalizes_nested_object_keys() {
        let tools = vec![json!({
            "name": "alpha",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "z": {"type": "string", "description": "last"},
                    "a": {"description": "first", "type": "string"}
                }
            }
        })];
        let snapshot = tool_schema_snapshot_value(&tools).expect("serialize snapshot");
        assert_eq!(
            snapshot["tools"][0]["inputSchema"]["properties"],
            json!({
                "a": {"description": "first", "type": "string"},
                "z": {"description": "last", "type": "string"}
            })
        );
    }

    #[test]
    fn tool_names_are_sorted_and_skip_missing_names() {
        let tools = vec![
            json!({"name":"zeta"}),
            json!({"description":"missing name"}),
            json!({"name":"alpha"}),
        ];
        let names = tool_names(&tools).expect("extract names");
        assert_eq!(names, vec!["alpha", "zeta"]);
    }
}

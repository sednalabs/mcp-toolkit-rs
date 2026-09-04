//! # Capability Projections
//!
//! Generic capability descriptors for projecting one operation into MCP and
//! OpenAPI-facing contracts.
//!
//! ## Ownership
//! This module owns protocol-adjacent metadata that is useful across MCP
//! servers: names, model-facing text, JSON schemas, OAuth scope requirements,
//! safety hints, audit identity, and projection helpers.
//!
//! ## Non-ownership
//! This module does not register handlers, enforce authorization, serve HTTP
//! routes, or define a service domain model. Consuming services own execution,
//! policy enforcement, and deployment-specific configuration.
//!
//! ## Policy & Guarantees
//! * **Single Contract Source**: One capability can emit MCP and OpenAPI metadata.
//! * **Small Surface**: Schemas are carried as JSON objects to avoid forcing one
//!   schema-generation dependency on all callers.
//! * **Projection Parity**: Required scopes, schemas, safety hints, and audit
//!   identity are preserved in generated metadata.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying schemas that match their real handler contracts.
//! * Enforcing required scopes at runtime.
//! * Choosing route paths, HTTP methods, handlers, and deployment settings.
//!
//! ## References
//! * `docs/capability-projections.md`
//! * Model Context Protocol tool metadata
//! * OpenAPI operation objects

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use rmcp::model::{JsonObject, MetaObject, Tool, ToolAnnotations};
use serde_json::{json, Map, Value};

use crate::mcp_apps::{
    mcp_apps_tool_descriptor_with_security_schemes, with_mcp_apps_oauth_security_scheme,
    McpAppsSecurityScheme,
};

/// Errors returned while building or projecting capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// A required text field was empty or whitespace-only.
    EmptyField { field: &'static str },
    /// A JSON schema value was not an object.
    SchemaMustBeObject { field: &'static str },
    /// A registry already contains the same capability id.
    DuplicateCapability { id: String },
}

impl Display for CapabilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilityError::EmptyField { field } => {
                write!(formatter, "capability field `{field}` must not be empty")
            }
            CapabilityError::SchemaMustBeObject { field } => {
                write!(
                    formatter,
                    "capability schema `{field}` must be a JSON object"
                )
            }
            CapabilityError::DuplicateCapability { id } => {
                write!(formatter, "duplicate capability id `{id}`")
            }
        }
    }
}

impl std::error::Error for CapabilityError {}

/// Stable identifier for one capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// Creates a normalized capability identifier.
    ///
    /// # Errors
    /// Returns `CapabilityError::EmptyField` when the id is empty after trimming.
    pub fn new(id: impl Into<String>) -> Result<Self, CapabilityError> {
        let id = normalize_required("id", id.into())?;
        Ok(Self(id))
    }

    /// Returns the canonical capability id.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns a stable OpenAPI operation id derived from this capability id.
    pub fn to_operation_id(&self) -> String {
        operation_id_from_capability_id(self.as_str())
    }
}

impl Display for CapabilityId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// OAuth scopes required to invoke a capability.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopePolicy {
    scopes: Vec<String>,
}

impl ScopePolicy {
    /// Builds a normalized scope policy.
    pub fn new<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized = Vec::new();
        for scope in scopes {
            let scope = scope.as_ref().trim();
            if scope.is_empty() || normalized.iter().any(|candidate| candidate == scope) {
                continue;
            }
            normalized.push(scope.to_string());
        }
        Self { scopes: normalized }
    }

    /// Returns the required scopes in caller order.
    pub fn scopes(&self) -> &[String] {
        self.scopes.as_slice()
    }

    /// Returns true when this capability does not require OAuth scopes.
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    fn to_openapi_scope_map(&self) -> Map<String, Value> {
        self.scopes
            .iter()
            .map(|scope| (scope.clone(), Value::String(String::new())))
            .collect()
    }
}

/// Safety hints for projecting capability behavior to client metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySafety {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

impl CapabilitySafety {
    /// Creates safety hints for a read-only capability.
    pub const fn read_only() -> Self {
        Self {
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
        }
    }

    /// Creates safety hints for an idempotent write capability.
    pub const fn idempotent_write() -> Self {
        Self {
            read_only: false,
            destructive: false,
            idempotent: true,
            open_world: false,
        }
    }

    /// Creates safety hints for a non-destructive mutating capability.
    pub const fn mutating() -> Self {
        Self {
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
        }
    }

    /// Creates safety hints for a destructive capability.
    pub const fn destructive() -> Self {
        Self {
            read_only: false,
            destructive: true,
            idempotent: false,
            open_world: false,
        }
    }

    /// Converts safety hints into MCP tool annotations.
    pub fn to_mcp_annotations(self, title: impl Into<String>) -> ToolAnnotations {
        ToolAnnotations::with_title(title)
            .read_only(self.read_only)
            .destructive(self.destructive)
            .idempotent(self.idempotent)
            .open_world(self.open_world)
    }
}

impl Default for CapabilitySafety {
    fn default() -> Self {
        Self::mutating()
    }
}

/// Stable audit metadata for one capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPolicy {
    event: String,
}

impl AuditPolicy {
    /// Creates audit metadata with a stable event name.
    ///
    /// # Errors
    /// Returns `CapabilityError::EmptyField` when the event name is empty after
    /// trimming.
    pub fn new(event: impl Into<String>) -> Result<Self, CapabilityError> {
        Ok(Self {
            event: normalize_required("audit.event", event.into())?,
        })
    }

    /// Returns the stable audit event name.
    pub fn event(&self) -> &str {
        self.event.as_str()
    }
}

/// Documentation or contract-test example for a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityExample {
    pub name: String,
    pub input: Value,
    pub output: Option<Value>,
}

/// OpenAPI OAuth 2 authorization-code security scheme metadata.
///
/// ```
/// use mcp_toolkit_core::capability::{
///     OpenApiOAuth2AuthorizationCodeSecurityScheme, ScopePolicy,
/// };
/// use serde_json::json;
///
/// let scheme = OpenApiOAuth2AuthorizationCodeSecurityScheme::new(
///     "https://issuer.example/authorize",
///     "https://issuer.example/token",
///     ScopePolicy::new(["items:read"]),
/// )?;
///
/// assert_eq!(scheme.to_value()["type"], json!("oauth2"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiOAuth2AuthorizationCodeSecurityScheme {
    authorization_url: String,
    token_url: String,
    scopes: ScopePolicy,
}

impl OpenApiOAuth2AuthorizationCodeSecurityScheme {
    /// Creates reusable OpenAPI OAuth 2 authorization-code security metadata.
    ///
    /// # Errors
    /// Returns an error when either URL field is empty after trimming.
    pub fn new(
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
        scopes: ScopePolicy,
    ) -> Result<Self, CapabilityError> {
        Ok(Self {
            authorization_url: normalize_required(
                "openapi.oauth.authorization_url",
                authorization_url.into(),
            )?,
            token_url: normalize_required("openapi.oauth.token_url", token_url.into())?,
            scopes,
        })
    }

    /// Serializes this scheme as an OpenAPI security scheme object.
    pub fn to_value(&self) -> Value {
        json!({
            "type": "oauth2",
            "flows": {
                "authorizationCode": {
                    "authorizationUrl": self.authorization_url,
                    "tokenUrl": self.token_url,
                    "scopes": self.scopes.to_openapi_scope_map(),
                },
            },
        })
    }
}

impl CapabilityExample {
    /// Creates a capability example.
    ///
    /// # Errors
    /// Returns `CapabilityError::EmptyField` when the example name is empty
    /// after trimming.
    pub fn new(name: impl Into<String>, input: Value) -> Result<Self, CapabilityError> {
        Ok(Self {
            name: normalize_required("example.name", name.into())?,
            input,
            output: None,
        })
    }

    /// Attaches expected output to the example.
    pub fn with_output(mut self, output: Value) -> Self {
        self.output = Some(output);
        self
    }
}

/// Canonical metadata for one server capability.
///
/// ```
/// use mcp_toolkit_core::capability::{Capability, CapabilitySafety};
/// use serde_json::json;
///
/// let capability = Capability::new(
///     "items.search",
///     "Search items",
///     "Search items visible to the caller.",
///     json!({
///         "type": "object",
///         "properties": {"query": {"type": "string"}},
///         "required": ["query"]
///     }),
/// )?
/// .with_required_scopes(["items:read"])
/// .with_safety(CapabilitySafety::read_only());
///
/// let tool = capability.to_mcp_tool();
/// let operation = capability.to_openapi_operation("OAuth2")?;
///
/// assert_eq!(tool.name, "items.search");
/// assert_eq!(operation["operationId"], json!("itemsSearch"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    id: CapabilityId,
    title: String,
    description: String,
    input_schema: JsonObject,
    output_schema: Option<JsonObject>,
    scopes: ScopePolicy,
    safety: CapabilitySafety,
    audit: AuditPolicy,
    examples: Vec<CapabilityExample>,
}

impl Capability {
    /// Creates a capability with required identity, text, and input schema.
    ///
    /// # Errors
    /// Returns an error when required text is empty or the input schema is not a
    /// JSON object.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Result<Self, CapabilityError> {
        let id = CapabilityId::new(id)?;
        Ok(Self {
            title: normalize_required("title", title.into())?,
            description: normalize_required("description", description.into())?,
            input_schema: schema_object("input_schema", input_schema)?,
            audit: AuditPolicy::new(id.as_str())?,
            id,
            output_schema: None,
            scopes: ScopePolicy::default(),
            safety: CapabilitySafety::default(),
            examples: Vec::new(),
        })
    }

    /// Returns the canonical capability id.
    pub fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Returns the model-facing title.
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    /// Returns the model-facing description.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    /// Returns required OAuth scopes.
    pub fn scopes(&self) -> &ScopePolicy {
        &self.scopes
    }

    /// Returns safety hints.
    pub fn safety(&self) -> CapabilitySafety {
        self.safety
    }

    /// Returns audit metadata.
    pub fn audit(&self) -> &AuditPolicy {
        &self.audit
    }

    /// Returns examples associated with this capability.
    pub fn examples(&self) -> &[CapabilityExample] {
        self.examples.as_slice()
    }

    /// Attaches an output schema.
    ///
    /// # Errors
    /// Returns an error when the schema is not a JSON object.
    pub fn with_output_schema(mut self, output_schema: Value) -> Result<Self, CapabilityError> {
        self.output_schema = Some(schema_object("output_schema", output_schema)?);
        Ok(self)
    }

    /// Attaches required OAuth scopes.
    pub fn with_required_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.scopes = ScopePolicy::new(scopes);
        self
    }

    /// Attaches safety hints.
    pub fn with_safety(mut self, safety: CapabilitySafety) -> Self {
        self.safety = safety;
        self
    }

    /// Attaches audit metadata.
    pub fn with_audit(mut self, audit: AuditPolicy) -> Self {
        self.audit = audit;
        self
    }

    /// Adds a documentation or contract-test example.
    pub fn with_example(mut self, example: CapabilityExample) -> Self {
        self.examples.push(example);
        self
    }

    /// Converts this capability into an MCP tool descriptor.
    pub fn to_mcp_tool(&self) -> Tool {
        let mut tool = Tool::new(
            self.id.as_str().to_string(),
            self.description.clone(),
            Arc::new(self.input_schema.clone()),
        )
        .with_title(self.title.clone())
        .with_annotations(self.safety.to_mcp_annotations(self.title.clone()));

        if let Some(output_schema) = &self.output_schema {
            tool = tool.with_raw_output_schema(Arc::new(output_schema.clone()));
        }
        if !self.scopes.is_empty() {
            tool = tool.with_meta(with_mcp_apps_oauth_security_scheme(
                Some(capability_meta(self)),
                self.scopes.scopes().iter().map(String::as_str),
            ));
        } else {
            tool = tool.with_meta(capability_meta(self));
        }
        tool
    }

    /// Converts this capability into an Apps-compatible tool descriptor.
    ///
    /// The descriptor mirrors `securitySchemes` at both the standard
    /// descriptor field and `_meta["securitySchemes"]`, using this
    /// capability's required scope policy as the source of truth.
    ///
    /// # Errors
    /// Returns `serde_json::Error` if the underlying `rmcp` tool cannot be
    /// serialized.
    pub fn to_mcp_apps_tool_descriptor(&self) -> Result<Value, serde_json::Error> {
        let tool = self.to_mcp_tool();
        let security_schemes = if self.scopes.is_empty() {
            vec![McpAppsSecurityScheme::noauth()]
        } else {
            vec![McpAppsSecurityScheme::oauth2(
                self.scopes.scopes().iter().map(String::as_str),
            )]
        };
        mcp_apps_tool_descriptor_with_security_schemes(&tool, security_schemes)
    }

    /// Converts this capability into an OpenAPI operation object.
    ///
    /// # Errors
    /// Returns an error when this capability requires OAuth scopes and the
    /// security scheme name is empty.
    pub fn to_openapi_operation(
        &self,
        security_scheme_name: &str,
    ) -> Result<Value, CapabilityError> {
        let security_scheme_name = security_scheme_name.trim();
        if !self.scopes.is_empty() && security_scheme_name.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "openapi.security_scheme_name",
            });
        }
        let response_content = self
            .output_schema
            .as_ref()
            .map(|schema| json!({"schema": Value::Object(schema.clone())}))
            .unwrap_or_else(|| json!({}));
        let mut operation = Map::from_iter([
            (
                "operationId".to_string(),
                Value::String(self.id.to_operation_id()),
            ),
            ("summary".to_string(), Value::String(self.title.clone())),
            (
                "description".to_string(),
                Value::String(self.description.clone()),
            ),
            (
                "requestBody".to_string(),
                json!({
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": Value::Object(self.input_schema.clone()),
                        },
                    },
                }),
            ),
            (
                "responses".to_string(),
                json!({
                    "200": {
                        "description": "Capability result",
                        "content": {
                            "application/json": response_content,
                        },
                    },
                }),
            ),
            (
                "x-mcp-tool-name".to_string(),
                Value::String(self.id.as_str().to_string()),
            ),
            (
                "x-capability-audit-event".to_string(),
                Value::String(self.audit.event().to_string()),
            ),
            ("x-capability-safety".to_string(), self.safety.to_value()),
        ]);
        operation.insert(
            "security".to_string(),
            if self.scopes.is_empty() {
                // An explicit empty requirement overrides any document-level
                // security inheritance and keeps this projection aligned with
                // the Apps `noauth` descriptor.
                Value::Array(Vec::new())
            } else {
                Value::Array(vec![Value::Object(Map::from_iter([(
                    security_scheme_name.to_string(),
                    Value::Array(
                        self.scopes
                            .scopes()
                            .iter()
                            .map(|scope| Value::String(scope.clone()))
                            .collect(),
                    ),
                )]))])
            },
        );
        Ok(Value::Object(operation))
    }
}

impl CapabilitySafety {
    fn to_value(self) -> Value {
        json!({
            "read_only": self.read_only,
            "destructive": self.destructive,
            "idempotent": self.idempotent,
            "open_world": self.open_world,
        })
    }
}

/// Registry of canonical capabilities.
#[derive(Debug, Clone, Default)]
pub struct CapabilityRegistry {
    capabilities: Vec<Capability>,
    ids: HashSet<CapabilityId>,
}

impl CapabilityRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one capability to the registry.
    ///
    /// # Errors
    /// Returns `CapabilityError::DuplicateCapability` when the id is already
    /// registered.
    pub fn register(&mut self, capability: Capability) -> Result<(), CapabilityError> {
        if !self.ids.insert(capability.id.clone()) {
            return Err(CapabilityError::DuplicateCapability {
                id: capability.id.as_str().to_string(),
            });
        }
        self.capabilities.push(capability);
        Ok(())
    }

    /// Returns all registered capabilities in registration order.
    pub fn capabilities(&self) -> &[Capability] {
        self.capabilities.as_slice()
    }

    /// Returns the capability with a matching id.
    pub fn get(&self, id: &str) -> Option<&Capability> {
        self.capabilities
            .iter()
            .find(|capability| capability.id.as_str() == id)
    }

    /// Converts all registered capabilities into MCP tool descriptors.
    pub fn to_mcp_tools(&self) -> Vec<Tool> {
        self.capabilities
            .iter()
            .map(Capability::to_mcp_tool)
            .collect()
    }

    /// Converts all registered capabilities into OpenAPI operation objects.
    ///
    /// # Errors
    /// Returns an error when any scoped capability cannot be projected with the
    /// provided security scheme name.
    pub fn to_openapi_operations(
        &self,
        security_scheme_name: &str,
    ) -> Result<Vec<Value>, CapabilityError> {
        self.capabilities
            .iter()
            .map(|capability| capability.to_openapi_operation(security_scheme_name))
            .collect()
    }
}

fn capability_meta(capability: &Capability) -> MetaObject {
    let mut meta = MetaObject::new();
    meta.0.insert(
        "capability".to_string(),
        json!({
            "id": capability.id.as_str(),
            "audit_event": capability.audit.event(),
        }),
    );
    meta
}

fn normalize_required(field: &'static str, value: String) -> Result<String, CapabilityError> {
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        Err(CapabilityError::EmptyField { field })
    } else {
        Ok(normalized)
    }
}

fn schema_object(field: &'static str, value: Value) -> Result<JsonObject, CapabilityError> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(CapabilityError::SchemaMustBeObject { field }),
    }
}

fn operation_id_from_capability_id(id: &str) -> String {
    let mut output = String::new();
    let mut capitalize_next = false;
    for character in id.chars() {
        if character.is_ascii_alphanumeric() {
            if output.is_empty() {
                output.push(character.to_ascii_lowercase());
                capitalize_next = false;
            } else if capitalize_next {
                output.push(character.to_ascii_uppercase());
                capitalize_next = false;
            } else {
                output.push(character);
            }
        } else {
            capitalize_next = true;
        }
    }
    if output.is_empty() {
        "capability".to_string()
    } else {
        output
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        AuditPolicy, Capability, CapabilityError, CapabilityExample, CapabilityId,
        CapabilityRegistry, CapabilitySafety, OpenApiOAuth2AuthorizationCodeSecurityScheme,
        ScopePolicy,
    };

    fn search_capability() -> Capability {
        Capability::new(
            "work_items.search",
            "Search work items",
            "Search work items visible to the caller.",
            json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            }),
        )
        .expect("valid capability")
        .with_output_schema(json!({
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "object"}}
            }
        }))
        .expect("valid output schema")
        .with_required_scopes(["ops:read", "ops:read", " "])
        .with_safety(CapabilitySafety::read_only())
        .with_audit(AuditPolicy::new("work_items.search").expect("audit policy"))
        .with_example(
            CapabilityExample::new("basic search", json!({"query": "open"}))
                .expect("example")
                .with_output(json!({"items": []})),
        )
    }

    fn public_capability() -> Capability {
        Capability::new(
            "status.ping",
            "Ping status",
            "Return public service status.",
            json!({"type": "object"}),
        )
        .expect("valid capability")
        .with_safety(CapabilitySafety::read_only())
    }

    #[test]
    fn scope_policy_preserves_order_and_deduplicates() {
        let policy = ScopePolicy::new(["ops:write", "ops:read", "ops:write", ""]);

        assert_eq!(
            policy.scopes(),
            &["ops:write".to_string(), "ops:read".to_string()]
        );
    }

    #[test]
    fn operation_id_is_stable_for_dotted_capability_ids() {
        let id = CapabilityId::new("work_items.search").expect("valid id");

        assert_eq!(id.to_operation_id(), "workItemsSearch");
    }

    #[test]
    fn operation_id_ignores_leading_separators() {
        let id = CapabilityId::new(".work_items.search").expect("valid id");

        assert_eq!(id.to_operation_id(), "workItemsSearch");
    }

    #[test]
    fn mcp_projection_preserves_schema_scopes_safety_and_audit_metadata() {
        let tool = search_capability().to_mcp_tool();
        let value = serde_json::to_value(&tool).expect("serialize tool");

        assert_eq!(value["name"], "work_items.search");
        assert_eq!(value["title"], "Search work items");
        assert_eq!(value["inputSchema"]["required"], json!(["query"]));
        assert_eq!(
            value["outputSchema"]["properties"]["items"]["type"],
            "array"
        );
        assert_eq!(value["annotations"]["readOnlyHint"], true);
        assert_eq!(value["annotations"]["destructiveHint"], false);
        assert_eq!(
            value["_meta"]["capability"]["audit_event"],
            "work_items.search"
        );
        assert_eq!(
            value["_meta"]["securitySchemes"],
            json!([{"type": "oauth2", "scopes": ["ops:read"]}])
        );
    }

    #[test]
    fn apps_projection_mirrors_security_schemes_from_scope_policy() {
        let value = search_capability()
            .to_mcp_apps_tool_descriptor()
            .expect("apps tool descriptor");

        assert_eq!(value["name"], "work_items.search");
        assert_eq!(
            value["securitySchemes"],
            json!([{"type": "oauth2", "scopes": ["ops:read"]}])
        );
        assert_eq!(value["_meta"]["securitySchemes"], value["securitySchemes"]);
        assert_eq!(
            value["_meta"]["capability"]["audit_event"],
            "work_items.search"
        );
    }

    #[test]
    fn canonical_schemas_are_preserved_across_native_apps_and_openapi_projections() {
        let input_schema = json!({
            "type": "object",
            "properties": {
                "request": {"$ref": "#/$defs/request"}
            },
            "required": ["request"],
            "$defs": {
                "request": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1}
                    },
                    "required": ["query"]
                }
            }
        });
        let output_schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/item"}
                }
            },
            "required": ["items"],
            "$defs": {
                "item": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"]
                }
            }
        });
        let capability = Capability::new(
            "items.search",
            "Search items",
            "Search items visible to the caller.",
            input_schema.clone(),
        )
        .expect("valid capability")
        .with_output_schema(output_schema.clone())
        .expect("valid output schema");
        let native = serde_json::to_value(capability.to_mcp_tool()).expect("native descriptor");
        let apps = capability
            .to_mcp_apps_tool_descriptor()
            .expect("apps descriptor");
        let openapi = capability
            .to_openapi_operation("OAuth2")
            .expect("OpenAPI operation");

        assert_eq!(
            json!({
                "native": {
                    "input": native["inputSchema"].clone(),
                    "output": native["outputSchema"].clone(),
                },
                "apps": {
                    "input": apps["inputSchema"].clone(),
                    "output": apps["outputSchema"].clone(),
                },
                "openapi": {
                    "input": openapi["requestBody"]["content"]["application/json"]["schema"]
                        .clone(),
                    "output": openapi["responses"]["200"]["content"]["application/json"]
                        ["schema"]
                        .clone(),
                },
            }),
            json!({
                "native": {"input": input_schema, "output": output_schema},
                "apps": {"input": input_schema, "output": output_schema},
                "openapi": {"input": input_schema, "output": output_schema},
            })
        );
    }

    #[test]
    fn projection_preserves_absent_output_schema_and_explicit_noauth() {
        let capability = public_capability();
        let native = serde_json::to_value(capability.to_mcp_tool()).expect("native descriptor");
        let apps = capability
            .to_mcp_apps_tool_descriptor()
            .expect("apps descriptor");
        let openapi = capability
            .to_openapi_operation("OAuth2")
            .expect("OpenAPI operation");

        assert!(native.get("outputSchema").is_none());
        assert!(apps.get("outputSchema").is_none());
        assert!(openapi["responses"]["200"]["content"]["application/json"]
            .get("schema")
            .is_none());
        assert_eq!(openapi["security"], json!([]));
    }

    #[test]
    fn normalized_projection_equality_covers_all_contract_metadata() {
        let capability = search_capability();
        let native = serde_json::to_value(capability.to_mcp_tool()).expect("native descriptor");
        let apps = capability
            .to_mcp_apps_tool_descriptor()
            .expect("apps descriptor");
        let openapi = capability
            .to_openapi_operation("OAuth2")
            .expect("OpenAPI operation");

        let normalized = json!({
            "native": {
                "name": native["name"],
                "title": native["title"],
                "description": native["description"],
                "inputSchema": native["inputSchema"],
                "outputSchema": native["outputSchema"],
                "annotations": native["annotations"],
                "_meta": native["_meta"],
            },
            "apps": {
                "name": apps["name"],
                "title": apps["title"],
                "description": apps["description"],
                "inputSchema": apps["inputSchema"],
                "outputSchema": apps["outputSchema"],
                "annotations": apps["annotations"],
                "securitySchemes": apps["securitySchemes"],
                "_meta": apps["_meta"],
            },
            "openapi": {
                "operationId": openapi["operationId"],
                "summary": openapi["summary"],
                "description": openapi["description"],
                "requestBody": openapi["requestBody"],
                "responses": openapi["responses"],
                "security": openapi["security"],
                "x-mcp-tool-name": openapi["x-mcp-tool-name"],
                "x-capability-audit-event": openapi["x-capability-audit-event"],
                "x-capability-safety": openapi["x-capability-safety"],
            },
        });

        assert_eq!(
            normalized,
            json!({
                "native": {
                    "name": "work_items.search",
                    "title": "Search work items",
                    "description": "Search work items visible to the caller.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]
                    },
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "items": {"type": "array", "items": {"type": "object"}}
                        }
                    },
                    "annotations": {
                        "title": "Search work items",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    },
                    "_meta": {
                        "capability": {
                            "id": "work_items.search",
                            "audit_event": "work_items.search"
                        },
                        "securitySchemes": [{"type": "oauth2", "scopes": ["ops:read"]}]
                    }
                },
                "apps": {
                    "name": "work_items.search",
                    "title": "Search work items",
                    "description": "Search work items visible to the caller.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]
                    },
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "items": {"type": "array", "items": {"type": "object"}}
                        }
                    },
                    "annotations": {
                        "title": "Search work items",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    },
                    "securitySchemes": [{"type": "oauth2", "scopes": ["ops:read"]}],
                    "_meta": {
                        "capability": {
                            "id": "work_items.search",
                            "audit_event": "work_items.search"
                        },
                        "securitySchemes": [{"type": "oauth2", "scopes": ["ops:read"]}]
                    }
                },
                "openapi": {
                    "operationId": "workItemsSearch",
                    "summary": "Search work items",
                    "description": "Search work items visible to the caller.",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"query": {"type": "string"}},
                                    "required": ["query"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Capability result",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "items": {"type": "array", "items": {"type": "object"}}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "security": [{"OAuth2": ["ops:read"]}],
                    "x-mcp-tool-name": "work_items.search",
                    "x-capability-audit-event": "work_items.search",
                    "x-capability-safety": {
                        "read_only": true,
                        "destructive": false,
                        "idempotent": true,
                        "open_world": false
                    }
                }
            })
        );
    }

    #[test]
    fn apps_projection_marks_unscoped_capabilities_noauth() {
        let capability = public_capability();

        let value = capability
            .to_mcp_apps_tool_descriptor()
            .expect("apps tool descriptor");

        assert_eq!(value["securitySchemes"], json!([{"type": "noauth"}]));
        assert_eq!(value["_meta"]["securitySchemes"], value["securitySchemes"]);
        assert_eq!(
            capability
                .to_openapi_operation("OAuth2")
                .expect("OpenAPI operation")["security"],
            json!([])
        );
    }

    #[test]
    fn openapi_projection_preserves_schema_scopes_safety_and_audit_metadata() {
        let operation = search_capability()
            .to_openapi_operation("OAuth2")
            .expect("valid OpenAPI operation");

        assert_eq!(operation["operationId"], "workItemsSearch");
        assert_eq!(operation["summary"], "Search work items");
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["required"],
            json!(["query"])
        );
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
                ["items"]["type"],
            "array"
        );
        assert_eq!(operation["security"], json!([{"OAuth2": ["ops:read"]}]));
        assert_eq!(operation["x-mcp-tool-name"], "work_items.search");
        assert_eq!(operation["x-capability-audit-event"], "work_items.search");
        assert_eq!(operation["x-capability-safety"]["read_only"], true);
    }

    #[test]
    fn openapi_projection_rejects_empty_security_scheme_for_scoped_capability() {
        let error = search_capability()
            .to_openapi_operation(" ")
            .expect_err("empty security scheme should fail");

        assert_eq!(
            error,
            CapabilityError::EmptyField {
                field: "openapi.security_scheme_name"
            }
        );
    }

    #[test]
    fn openapi_oauth_security_scheme_projects_authorization_code_flow() {
        let scheme = OpenApiOAuth2AuthorizationCodeSecurityScheme::new(
            "https://issuer.example/authorize",
            "https://issuer.example/token",
            ScopePolicy::new(["ops:read", "ops:write"]),
        )
        .expect("valid OAuth scheme");

        assert_eq!(
            scheme.to_value(),
            json!({
                "type": "oauth2",
                "flows": {
                    "authorizationCode": {
                        "authorizationUrl": "https://issuer.example/authorize",
                        "tokenUrl": "https://issuer.example/token",
                        "scopes": {
                            "ops:read": "",
                            "ops:write": "",
                        },
                    },
                },
            })
        );
    }

    #[test]
    fn registry_projects_mcp_tools_and_openapi_operations() {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(search_capability())
            .expect("valid capability");
        registry
            .register(public_capability())
            .expect("valid public capability");

        let tools = registry.to_mcp_tools();
        let operations = registry
            .to_openapi_operations("OAuth2")
            .expect("valid OpenAPI operations");

        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            vec!["work_items.search", "status.ping"]
        );
        assert_eq!(
            operations
                .iter()
                .map(|operation| operation["operationId"].as_str().unwrap_or_default())
                .collect::<Vec<_>>(),
            vec!["workItemsSearch", "statusPing"]
        );
        assert_eq!(operations[0]["security"], json!([{"OAuth2": ["ops:read"]}]));
        assert_eq!(operations[1]["security"], json!([]));
    }

    #[test]
    fn registry_rejects_duplicate_capabilities() {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(search_capability())
            .expect("first registration");
        let duplicate = registry
            .register(search_capability())
            .expect_err("duplicate id should fail");

        assert_eq!(
            duplicate,
            CapabilityError::DuplicateCapability {
                id: "work_items.search".to_string()
            }
        );
    }

    #[test]
    fn capability_rejects_non_object_schemas() {
        let error = Capability::new("bad", "Bad", "Bad capability.", json!(true))
            .expect_err("schema should be rejected");

        assert_eq!(
            error,
            CapabilityError::SchemaMustBeObject {
                field: "input_schema"
            }
        );
    }
}

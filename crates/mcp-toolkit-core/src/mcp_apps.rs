//! # MCP Apps Helpers
//!
//! Small descriptor metadata builders for MCP servers exposed as apps.
//!
//! ## Ownership
//! This module owns provider-specific descriptor metadata shapes that are useful
//! to many MCP servers and do not depend on a service domain model.
//!
//! ## Non-ownership
//! This module does not decide which OAuth scopes are required for a tool,
//! register tools, or enforce authorization.
//!
//! ## Policy & Guarantees
//! * **Typed Boundary**: Accepts `rmcp` model values and emits Apps descriptor
//!   metadata so callers do not duplicate provider-specific JSON construction.
//! * **Scope Order Preservation**: Preserves caller scope order because some
//!   hosts display or request scopes in descriptor order.
//! * **Local Metadata Merge**: Replaces only the Apps `securitySchemes` entries
//!   and preserves unrelated descriptor or `_meta` keys.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying the full tool-specific OAuth scope list required by the host.
//! * Keeping host-facing descriptor metadata aligned with the app descriptor
//!   contract they target.

use rmcp::model::{MetaObject as Meta, Tool};
use serde::ser::Error as _;
use serde_json::{json, Map, Value};

/// MCP app `_meta` key for tool OAuth security schemes.
pub const MCP_APPS_SECURITY_SCHEMES_META_KEY: &str = "securitySchemes";

/// No-auth security scheme type used by MCP app tool descriptors.
pub const MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE: &str = "noauth";

/// OAuth 2 security scheme type used by MCP app tool descriptors.
pub const MCP_APPS_OAUTH2_SECURITY_SCHEME_TYPE: &str = "oauth2";

/// `_meta` key that marks a tool as requiring explicit approval before use.
pub const MCP_APPS_APPROVAL_REQUIRED_META_KEY: &str = "approval_required";

/// `_meta` key that describes a tool's output sensitivity class.
pub const MCP_APPS_SENSITIVITY_META_KEY: &str = "sensitivity";

/// `_meta` key that describes a tool operation class.
pub const MCP_APPS_OPERATION_CLASS_META_KEY: &str = "operation_class";

/// `_meta` key that describes the hazardous boundary a proof-only tool stops at.
pub const MCP_APPS_PROOF_BOUNDARY_META_KEY: &str = "proof_boundary";

/// `_meta` key that records whether mutation is prohibited by the tool contract.
pub const MCP_APPS_MUTATION_PROHIBITED_META_KEY: &str = "mutation_prohibited";

/// `_meta` key that records whether a production action is authorized.
pub const MCP_APPS_PRODUCTION_ACTION_AUTHORIZED_META_KEY: &str = "production_action_authorized";

/// `_meta` key used by Apps clients for widget bridge accessibility.
pub const MCP_APPS_WIDGET_ACCESSIBLE_META_KEY: &str = "openai/widgetAccessible";

/// Auth policy entry for an MCP app tool descriptor.
///
/// Apps clients read `securitySchemes` on the tool descriptor, and some hosts
/// also require the same array mirrored into `_meta["securitySchemes"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpAppsSecurityScheme {
    NoAuth,
    OAuth2(McpAppsOAuthSecurityScheme),
}

impl McpAppsSecurityScheme {
    /// Builds a `noauth` security scheme.
    ///
    /// # Errors
    /// This function does not return errors.
    pub const fn noauth() -> Self {
        Self::NoAuth
    }

    /// Builds an OAuth 2 security scheme with normalized scopes.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn oauth2<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::OAuth2(McpAppsOAuthSecurityScheme::new(scopes))
    }

    /// Serializes this security scheme as MCP app descriptor metadata.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn to_value(&self) -> Value {
        match self {
            Self::NoAuth => json!({
                "type": MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE,
            }),
            Self::OAuth2(scheme) => scheme.to_value(),
        }
    }
}

/// Builds an OAuth 2 security scheme for an MCP app tool descriptor.
///
/// Empty or whitespace-only scope entries are ignored. Duplicate scopes are
/// ignored after their first occurrence so caller order remains stable.
///
/// ```
/// use mcp_toolkit_core::mcp_apps::McpAppsOAuthSecurityScheme;
///
/// let scheme = McpAppsOAuthSecurityScheme::new([
///     "openid",
///     "profile",
///     "ops:read",
///     "ops:read",
/// ]);
///
/// assert_eq!(scheme.scopes, vec!["openid", "profile", "ops:read"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAppsOAuthSecurityScheme {
    pub scopes: Vec<String>,
}

impl McpAppsOAuthSecurityScheme {
    /// Builds a normalized OAuth 2 security scheme.
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

    /// Serializes this security scheme as MCP app descriptor metadata.
    pub fn to_value(&self) -> Value {
        json!({
            "type": MCP_APPS_OAUTH2_SECURITY_SCHEME_TYPE,
            "scopes": self.scopes,
        })
    }
}

/// Upserts the MCP app OAuth security scheme into an `rmcp` metadata object.
///
/// Existing metadata is preserved except for `securitySchemes`, which is
/// replaced with a single OAuth 2 security scheme using the provided scopes.
///
/// ```
/// use rmcp::model::MetaObject as Meta;
/// use serde_json::json;
/// use mcp_toolkit_core::mcp_apps::with_mcp_apps_oauth_security_scheme;
///
/// let mut existing = Meta::new();
/// existing.0.insert("ui".to_string(), json!({"visibility":["model"]}));
///
/// let meta = with_mcp_apps_oauth_security_scheme(
///     Some(existing),
///     ["openid", "profile", "ops:read"],
/// );
///
/// assert_eq!(meta.0["ui"], json!({"visibility":["model"]}));
/// assert_eq!(
///     meta.0["securitySchemes"],
///     json!([{"type":"oauth2","scopes":["openid","profile","ops:read"]}])
/// );
/// ```
pub fn with_mcp_apps_oauth_security_scheme<I, S>(existing: Option<Meta>, scopes: I) -> Meta
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    with_mcp_apps_security_schemes(existing, [McpAppsSecurityScheme::oauth2(scopes)])
}

/// Upserts MCP app security schemes into an `rmcp` metadata object.
///
/// Existing metadata is preserved except for `securitySchemes`, which is
/// replaced with the supplied scheme array.
///
/// ```
/// use rmcp::model::MetaObject as Meta;
/// use serde_json::json;
/// use mcp_toolkit_core::mcp_apps::{
///     with_mcp_apps_security_schemes, McpAppsSecurityScheme,
/// };
///
/// let meta = with_mcp_apps_security_schemes(
///     Some(Meta::new()),
///     [
///         McpAppsSecurityScheme::noauth(),
///         McpAppsSecurityScheme::oauth2(["items:read"]),
///     ],
/// );
///
/// assert_eq!(
///     meta.0["securitySchemes"],
///     json!([
///         {"type":"noauth"},
///         {"type":"oauth2","scopes":["items:read"]},
///     ])
/// );
/// ```
///
/// # Errors
/// This function does not return errors.
pub fn with_mcp_apps_security_schemes<I>(existing: Option<Meta>, schemes: I) -> Meta
where
    I: IntoIterator<Item = McpAppsSecurityScheme>,
{
    let mut meta = existing.unwrap_or_default();
    meta.0.insert(
        MCP_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
        security_schemes_value(schemes),
    );
    meta
}

/// Adds model-only sensitive-output metadata to an MCP Apps tool descriptor.
///
/// Existing metadata is preserved. The helper records a reusable contract for
/// tools that are non-mutating but may reveal unredacted secrets or admin
/// configuration values after an explicit approval gate.
pub fn with_mcp_apps_sensitive_output_metadata(
    existing: Option<Meta>,
    sensitivity: impl Into<String>,
) -> Meta {
    let mut meta = with_mcp_apps_security_schemes(existing, [McpAppsSecurityScheme::noauth()]);
    meta.0
        .insert(MCP_APPS_APPROVAL_REQUIRED_META_KEY.to_string(), json!(true));
    meta.0.insert(
        MCP_APPS_SENSITIVITY_META_KEY.to_string(),
        json!(sensitivity.into()),
    );
    meta.0.insert(
        MCP_APPS_WIDGET_ACCESSIBLE_META_KEY.to_string(),
        json!(false),
    );
    upsert_model_only_ui_visibility(&mut meta);
    meta
}

/// Adds model-only no-mutation proof metadata to an MCP Apps tool descriptor.
///
/// Existing metadata is preserved. The helper records a reusable contract for
/// tools that may approach a hazardous boundary for proof while prohibiting
/// the final mutation, send, publish, trigger, or schedule action.
pub fn with_mcp_apps_no_mutation_proof_metadata(
    existing: Option<Meta>,
    proof_boundary: impl Into<String>,
) -> Meta {
    let mut meta = with_mcp_apps_security_schemes(existing, [McpAppsSecurityScheme::noauth()]);
    meta.0.insert(
        MCP_APPS_OPERATION_CLASS_META_KEY.to_string(),
        json!("no_mutation_proof"),
    );
    meta.0.insert(
        MCP_APPS_APPROVAL_REQUIRED_META_KEY.to_string(),
        json!(false),
    );
    meta.0.insert(
        MCP_APPS_PROOF_BOUNDARY_META_KEY.to_string(),
        json!(proof_boundary.into()),
    );
    meta.0.insert(
        MCP_APPS_MUTATION_PROHIBITED_META_KEY.to_string(),
        json!(true),
    );
    meta.0.insert(
        MCP_APPS_PRODUCTION_ACTION_AUTHORIZED_META_KEY.to_string(),
        json!(false),
    );
    meta.0.insert(
        MCP_APPS_WIDGET_ACCESSIBLE_META_KEY.to_string(),
        json!(false),
    );
    upsert_model_only_ui_visibility(&mut meta);
    meta
}

/// Serializes an `rmcp` tool descriptor with Apps security schemes mirrored.
///
/// The returned JSON object includes both the descriptor-level
/// `securitySchemes` field and the compatibility mirror at
/// `_meta["securitySchemes"]`.
///
/// # Errors
/// Returns `serde_json::Error` if the `rmcp` tool cannot be serialized.
pub fn mcp_apps_tool_descriptor_with_security_schemes<I>(
    tool: &Tool,
    schemes: I,
) -> Result<Value, serde_json::Error>
where
    I: IntoIterator<Item = McpAppsSecurityScheme>,
{
    let mut descriptor = match serde_json::to_value(tool)? {
        Value::Object(object) => object,
        _ => {
            return Err(serde_json::Error::custom(
                "expected Tool to serialize to a JSON object",
            ));
        }
    };
    let security_schemes = security_schemes_value(schemes);

    descriptor.insert(
        MCP_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
        security_schemes.clone(),
    );
    let meta = descriptor
        .entry("_meta".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    match meta {
        Value::Object(object) => {
            object.insert(
                MCP_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
                security_schemes,
            );
        }
        _ => {
            let mut object = Map::new();
            object.insert(
                MCP_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
                security_schemes,
            );
            *meta = Value::Object(object);
        }
    }

    Ok(Value::Object(descriptor))
}

/// Ensures an Apps tool descriptor has both primary and `_meta` security schemes.
///
/// Some MCP SDK model types can carry only `_meta["securitySchemes"]`, while
/// Apps clients read the primary descriptor-level `securitySchemes` field. This
/// helper promotes either location to both locations without changing unrelated
/// descriptor fields.
///
/// Returns `true` when the descriptor was changed.
pub fn normalize_mcp_apps_security_schemes_in_tool_descriptor(descriptor: &mut Value) -> bool {
    let Value::Object(object) = descriptor else {
        return false;
    };
    let primary_security_schemes = object.get(MCP_APPS_SECURITY_SCHEMES_META_KEY).cloned();
    let meta_security_schemes = object
        .get("_meta")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get(MCP_APPS_SECURITY_SCHEMES_META_KEY))
        .cloned();
    let Some(security_schemes) = primary_security_schemes.or(meta_security_schemes) else {
        return false;
    };

    let mut changed = false;
    if object.get(MCP_APPS_SECURITY_SCHEMES_META_KEY) != Some(&security_schemes) {
        object.insert(
            MCP_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
            security_schemes.clone(),
        );
        changed = true;
    }

    let meta = object
        .entry("_meta".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !meta.is_object() {
        *meta = Value::Object(Map::new());
        changed = true;
    }
    if let Value::Object(meta_object) = meta {
        if meta_object.get(MCP_APPS_SECURITY_SCHEMES_META_KEY) != Some(&security_schemes) {
            meta_object.insert(
                MCP_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
                security_schemes,
            );
            changed = true;
        }
    }

    changed
}

/// Normalizes Apps security schemes in an MCP `tools/list` JSON-RPC payload.
///
/// This accepts a single JSON-RPC response, a JSON-RPC batch, or a direct
/// object containing a `tools` array. It returns the number of tool descriptors
/// changed.
pub fn normalize_mcp_apps_security_schemes_in_tools_list_payload(payload: &mut Value) -> usize {
    match payload {
        Value::Array(items) => items
            .iter_mut()
            .map(normalize_mcp_apps_security_schemes_in_tools_list_message)
            .sum(),
        _ => normalize_mcp_apps_security_schemes_in_tools_list_message(payload),
    }
}

fn normalize_mcp_apps_security_schemes_in_tools_list_message(message: &mut Value) -> usize {
    if let Some(tools) = message.pointer_mut("/result/tools") {
        return normalize_mcp_apps_security_schemes_in_tools_array(tools);
    }
    if let Some(tools) = message.get_mut("tools") {
        return normalize_mcp_apps_security_schemes_in_tools_array(tools);
    }
    0
}

fn normalize_mcp_apps_security_schemes_in_tools_array(tools: &mut Value) -> usize {
    let Value::Array(tools) = tools else {
        return 0;
    };
    tools.iter_mut().fold(0, |count, tool| {
        if normalize_mcp_apps_security_schemes_in_tool_descriptor(tool) {
            count + 1
        } else {
            count
        }
    })
}

fn security_schemes_value<I>(schemes: I) -> Value
where
    I: IntoIterator<Item = McpAppsSecurityScheme>,
{
    Value::Array(
        schemes
            .into_iter()
            .map(|scheme| scheme.to_value())
            .collect(),
    )
}

fn upsert_model_only_ui_visibility(meta: &mut Meta) {
    let mut ui = meta
        .0
        .remove("ui")
        .and_then(|value| match value {
            Value::Object(object) => Some(object),
            _ => None,
        })
        .unwrap_or_default();
    ui.insert("visibility".to_string(), json!(["model"]));
    meta.0.insert("ui".to_string(), Value::Object(ui));
}

#[cfg(test)]
mod tests {
    use super::{
        mcp_apps_tool_descriptor_with_security_schemes,
        normalize_mcp_apps_security_schemes_in_tool_descriptor,
        normalize_mcp_apps_security_schemes_in_tools_list_payload,
        with_mcp_apps_no_mutation_proof_metadata, with_mcp_apps_oauth_security_scheme,
        with_mcp_apps_security_schemes, with_mcp_apps_sensitive_output_metadata,
        McpAppsOAuthSecurityScheme, McpAppsSecurityScheme, MCP_APPS_APPROVAL_REQUIRED_META_KEY,
        MCP_APPS_MUTATION_PROHIBITED_META_KEY, MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE,
        MCP_APPS_OAUTH2_SECURITY_SCHEME_TYPE, MCP_APPS_OPERATION_CLASS_META_KEY,
        MCP_APPS_PRODUCTION_ACTION_AUTHORIZED_META_KEY, MCP_APPS_PROOF_BOUNDARY_META_KEY,
        MCP_APPS_SECURITY_SCHEMES_META_KEY, MCP_APPS_SENSITIVITY_META_KEY,
        MCP_APPS_WIDGET_ACCESSIBLE_META_KEY,
    };
    use rmcp::model::{JsonObject, MetaObject as Meta, Tool};
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn oauth_security_scheme_preserves_scope_order_and_deduplicates() {
        let scheme =
            McpAppsOAuthSecurityScheme::new(["openid", "profile", "", "ops:read", "ops:read"]);

        assert_eq!(
            scheme.scopes,
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "ops:read".to_string(),
            ]
        );
        assert_eq!(
            scheme.to_value(),
            json!({
                "type": MCP_APPS_OAUTH2_SECURITY_SCHEME_TYPE,
                "scopes": ["openid", "profile", "ops:read"],
            })
        );
    }

    #[test]
    fn generic_security_scheme_supports_noauth_and_oauth2() {
        let noauth = McpAppsSecurityScheme::noauth();
        let oauth2 = McpAppsSecurityScheme::oauth2(["items:read"]);

        assert_eq!(
            noauth.to_value(),
            json!({"type": MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE})
        );
        assert_eq!(
            oauth2.to_value(),
            json!({"type": MCP_APPS_OAUTH2_SECURITY_SCHEME_TYPE, "scopes": ["items:read"]})
        );
    }

    #[test]
    fn sensitive_output_metadata_marks_model_only_approval_required_tools() {
        let mut existing = Meta::new();
        existing
            .0
            .insert("owner".to_string(), json!("service-owned"));
        existing
            .0
            .insert("ui".to_string(), json!({"resourceUri": "ui://admin.html"}));

        let meta =
            with_mcp_apps_sensitive_output_metadata(Some(existing), "unredacted_admin_form_values");

        assert_eq!(meta.0["owner"], json!("service-owned"));
        assert_eq!(meta.0[MCP_APPS_APPROVAL_REQUIRED_META_KEY], json!(true));
        assert_eq!(
            meta.0[MCP_APPS_SENSITIVITY_META_KEY],
            json!("unredacted_admin_form_values")
        );
        assert_eq!(meta.0[MCP_APPS_WIDGET_ACCESSIBLE_META_KEY], json!(false));
        assert_eq!(
            meta.0["ui"],
            json!({"resourceUri": "ui://admin.html", "visibility": ["model"]})
        );
        assert_eq!(
            meta.0[MCP_APPS_SECURITY_SCHEMES_META_KEY],
            json!([{"type": MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE}])
        );
    }

    #[test]
    fn no_mutation_proof_metadata_marks_model_only_non_mutating_boundary() {
        let mut existing = Meta::new();
        existing
            .0
            .insert("owner".to_string(), json!("service-owned"));
        existing
            .0
            .insert("ui".to_string(), json!({"resourceUri": "ui://proof.html"}));

        let meta = with_mcp_apps_no_mutation_proof_metadata(
            Some(existing),
            "render final form without submitting",
        );

        assert_eq!(meta.0["owner"], json!("service-owned"));
        assert_eq!(
            meta.0[MCP_APPS_OPERATION_CLASS_META_KEY],
            json!("no_mutation_proof")
        );
        assert_eq!(meta.0[MCP_APPS_APPROVAL_REQUIRED_META_KEY], json!(false));
        assert_eq!(
            meta.0[MCP_APPS_PROOF_BOUNDARY_META_KEY],
            json!("render final form without submitting")
        );
        assert_eq!(meta.0[MCP_APPS_MUTATION_PROHIBITED_META_KEY], json!(true));
        assert_eq!(
            meta.0[MCP_APPS_PRODUCTION_ACTION_AUTHORIZED_META_KEY],
            json!(false)
        );
        assert_eq!(meta.0[MCP_APPS_WIDGET_ACCESSIBLE_META_KEY], json!(false));
        assert_eq!(
            meta.0["ui"],
            json!({"resourceUri": "ui://proof.html", "visibility": ["model"]})
        );
        assert_eq!(
            meta.0[MCP_APPS_SECURITY_SCHEMES_META_KEY],
            json!([{"type": MCP_APPS_NOAUTH_SECURITY_SCHEME_TYPE}])
        );
    }

    #[test]
    fn oauth_security_scheme_meta_preserves_unrelated_metadata() {
        let mut existing = Meta::new();
        existing
            .0
            .insert("ui".to_string(), json!({"visibility": ["model"]}));
        existing.0.insert(
            MCP_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
            json!([{"type":"noauth"}]),
        );

        let meta =
            with_mcp_apps_oauth_security_scheme(Some(existing), ["openid", "profile", "ops:read"]);

        assert_eq!(meta.0["ui"], json!({"visibility": ["model"]}));
        assert_eq!(
            meta.0[MCP_APPS_SECURITY_SCHEMES_META_KEY],
            json!([{
                "type": "oauth2",
                "scopes": ["openid", "profile", "ops:read"],
            }])
        );
    }

    #[test]
    fn generic_security_scheme_meta_replaces_only_security_schemes() {
        let mut existing = Meta::new();
        existing
            .0
            .insert("ui".to_string(), json!({"visibility": ["model"]}));

        let meta = with_mcp_apps_security_schemes(
            Some(existing),
            [
                McpAppsSecurityScheme::noauth(),
                McpAppsSecurityScheme::oauth2(["items:read"]),
            ],
        );

        assert_eq!(meta.0["ui"], json!({"visibility": ["model"]}));
        assert_eq!(
            meta.0[MCP_APPS_SECURITY_SCHEMES_META_KEY],
            json!([
                {"type": "noauth"},
                {"type": "oauth2", "scopes": ["items:read"]},
            ])
        );
    }

    #[test]
    fn apps_tool_descriptor_mirrors_security_schemes() {
        let mut meta = Meta::new();
        meta.0
            .insert("ui".to_string(), json!({"resourceUri": "ui://search.html"}));
        let tool = Tool::new(
            "items.search",
            "Search items",
            Arc::new(JsonObject::default()),
        )
        .with_meta(meta);

        let descriptor = mcp_apps_tool_descriptor_with_security_schemes(
            &tool,
            [McpAppsSecurityScheme::oauth2(["items:read"])],
        )
        .expect("tool descriptor");

        assert_eq!(descriptor["name"], "items.search");
        assert_eq!(
            descriptor["securitySchemes"],
            json!([{"type": "oauth2", "scopes": ["items:read"]}])
        );
        assert_eq!(
            descriptor["_meta"]["securitySchemes"],
            descriptor["securitySchemes"]
        );
        assert_eq!(
            descriptor["_meta"]["ui"],
            json!({"resourceUri": "ui://search.html"})
        );
    }

    #[test]
    fn normalizes_tool_descriptor_from_meta_security_schemes() {
        let mut descriptor = json!({
            "name": "items.search",
            "_meta": {
                "securitySchemes": [
                    {"type": "oauth2", "scopes": ["openid", "profile", "items:read"]}
                ],
                "ui": {"visibility": ["model"]}
            }
        });

        assert!(normalize_mcp_apps_security_schemes_in_tool_descriptor(
            &mut descriptor
        ));

        assert_eq!(
            descriptor["securitySchemes"],
            json!([{"type": "oauth2", "scopes": ["openid", "profile", "items:read"]}])
        );
        assert_eq!(
            descriptor["_meta"]["securitySchemes"],
            descriptor["securitySchemes"]
        );
        assert_eq!(descriptor["_meta"]["ui"], json!({"visibility": ["model"]}));
    }

    #[test]
    fn normalizes_tool_descriptor_from_primary_security_schemes() {
        let mut descriptor = json!({
            "name": "items.search",
            "securitySchemes": [
                {"type": "oauth2", "scopes": ["items:read"]}
            ]
        });

        assert!(normalize_mcp_apps_security_schemes_in_tool_descriptor(
            &mut descriptor
        ));

        assert_eq!(
            descriptor["_meta"]["securitySchemes"],
            descriptor["securitySchemes"]
        );
    }

    #[test]
    fn normalizes_json_rpc_tools_list_response_security_schemes() {
        let mut payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "items.search",
                        "_meta": {
                            "securitySchemes": [
                                {"type": "oauth2", "scopes": ["items:read"]}
                            ]
                        }
                    },
                    {
                        "name": "items.public"
                    }
                ]
            }
        });

        assert_eq!(
            normalize_mcp_apps_security_schemes_in_tools_list_payload(&mut payload),
            1
        );

        assert_eq!(
            payload["result"]["tools"][0]["securitySchemes"],
            json!([{"type": "oauth2", "scopes": ["items:read"]}])
        );
        assert!(payload["result"]["tools"][1]["securitySchemes"].is_null());
    }

    #[test]
    fn normalizes_batch_tools_list_responses() {
        let mut payload = json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "items.search",
                            "_meta": {
                                "securitySchemes": [
                                    {"type": "oauth2", "scopes": ["items:read"]}
                                ]
                            }
                        }
                    ]
                }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "tools": [
                        {
                            "name": "items.lookup",
                            "securitySchemes": [
                                {"type": "oauth2", "scopes": ["items:lookup"]}
                            ]
                        }
                    ]
                }
            }
        ]);

        assert_eq!(
            normalize_mcp_apps_security_schemes_in_tools_list_payload(&mut payload),
            2
        );

        assert_eq!(
            payload[0]["result"]["tools"][0]["securitySchemes"],
            payload[0]["result"]["tools"][0]["_meta"]["securitySchemes"]
        );
        assert_eq!(
            payload[1]["result"]["tools"][0]["securitySchemes"],
            payload[1]["result"]["tools"][0]["_meta"]["securitySchemes"]
        );
    }

    #[test]
    fn leaves_non_tools_list_payload_unchanged() {
        let mut payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "capabilities": {}
            }
        });
        let original = payload.clone();

        assert_eq!(
            normalize_mcp_apps_security_schemes_in_tools_list_payload(&mut payload),
            0
        );
        assert_eq!(payload, original);
    }
}

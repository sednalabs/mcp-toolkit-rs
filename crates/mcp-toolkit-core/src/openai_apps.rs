//! # OpenAI Apps Helpers
//!
//! Small metadata builders for MCP servers exposed through the OpenAI Apps SDK.
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
//! * **Typed Boundary**: Accepts and returns `rmcp::model::Meta` so callers do
//!   not duplicate provider-specific JSON construction.
//! * **Scope Order Preservation**: Preserves caller scope order because some
//!   hosts display or request scopes in descriptor order.
//! * **Local Metadata Merge**: Replaces only the Apps `securitySchemes` entry and
//!   preserves unrelated `_meta` keys.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying the full tool-specific OAuth scope list required by the host.
//! * Keeping host-facing descriptor metadata aligned with the Apps SDK version
//!   they target.

use rmcp::model::Meta;
use serde_json::{json, Value};

/// Apps SDK `_meta` key for tool OAuth security schemes.
pub const OPENAI_APPS_SECURITY_SCHEMES_META_KEY: &str = "securitySchemes";

/// OAuth 2 security scheme type used by OpenAI Apps tool descriptors.
pub const OPENAI_APPS_OAUTH2_SECURITY_SCHEME_TYPE: &str = "oauth2";

/// Builds an OAuth 2 security scheme for an OpenAI Apps tool descriptor.
///
/// Empty or whitespace-only scope entries are ignored. Duplicate scopes are
/// ignored after their first occurrence so caller order remains stable.
///
/// ```
/// use mcp_toolkit_core::openai_apps::OpenAiAppsOAuthSecurityScheme;
///
/// let scheme = OpenAiAppsOAuthSecurityScheme::new([
///     "openid",
///     "profile",
///     "ops:read",
///     "ops:read",
/// ]);
///
/// assert_eq!(scheme.scopes, vec!["openid", "profile", "ops:read"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiAppsOAuthSecurityScheme {
    pub scopes: Vec<String>,
}

impl OpenAiAppsOAuthSecurityScheme {
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

    /// Serializes this security scheme as Apps SDK descriptor metadata.
    pub fn to_value(&self) -> Value {
        json!({
            "type": OPENAI_APPS_OAUTH2_SECURITY_SCHEME_TYPE,
            "scopes": self.scopes,
        })
    }
}

/// Upserts the Apps SDK OAuth security scheme into an `rmcp` metadata object.
///
/// Existing metadata is preserved except for `securitySchemes`, which is
/// replaced with a single OAuth 2 security scheme using the provided scopes.
///
/// ```
/// use rmcp::model::Meta;
/// use serde_json::json;
/// use mcp_toolkit_core::openai_apps::with_openai_apps_oauth_security_scheme;
///
/// let mut existing = Meta::new();
/// existing.0.insert("ui".to_string(), json!({"visibility":["model"]}));
///
/// let meta = with_openai_apps_oauth_security_scheme(
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
pub fn with_openai_apps_oauth_security_scheme<I, S>(existing: Option<Meta>, scopes: I) -> Meta
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut meta = existing.unwrap_or_default();
    let security_scheme = OpenAiAppsOAuthSecurityScheme::new(scopes);
    meta.0.insert(
        OPENAI_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
        Value::Array(vec![security_scheme.to_value()]),
    );
    meta
}

#[cfg(test)]
mod tests {
    use super::{
        with_openai_apps_oauth_security_scheme, OpenAiAppsOAuthSecurityScheme,
        OPENAI_APPS_OAUTH2_SECURITY_SCHEME_TYPE, OPENAI_APPS_SECURITY_SCHEMES_META_KEY,
    };
    use rmcp::model::Meta;
    use serde_json::json;

    #[test]
    fn oauth_security_scheme_preserves_scope_order_and_deduplicates() {
        let scheme =
            OpenAiAppsOAuthSecurityScheme::new(["openid", "profile", "", "ops:read", "ops:read"]);

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
                "type": OPENAI_APPS_OAUTH2_SECURITY_SCHEME_TYPE,
                "scopes": ["openid", "profile", "ops:read"],
            })
        );
    }

    #[test]
    fn oauth_security_scheme_meta_preserves_unrelated_metadata() {
        let mut existing = Meta::new();
        existing
            .0
            .insert("ui".to_string(), json!({"visibility": ["model"]}));
        existing.0.insert(
            OPENAI_APPS_SECURITY_SCHEMES_META_KEY.to_string(),
            json!([{"type":"noauth"}]),
        );

        let meta = with_openai_apps_oauth_security_scheme(
            Some(existing),
            ["openid", "profile", "ops:read"],
        );

        assert_eq!(meta.0["ui"], json!({"visibility": ["model"]}));
        assert_eq!(
            meta.0[OPENAI_APPS_SECURITY_SCHEMES_META_KEY],
            json!([{
                "type": "oauth2",
                "scopes": ["openid", "profile", "ops:read"],
            }])
        );
    }
}

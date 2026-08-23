//! # OIDC Discovery Capability Validation
//!
//! Provider-neutral requirements for validating already-fetched OIDC discovery
//! metadata before a caller enables an OAuth flow.
//!
//! ## Security Boundaries
//! * Validation performs no network I/O and never handles credentials or tokens.
//! * Issuer identity, endpoint URL shape, optional same-origin policy, and
//!   advertised capabilities are checked before metadata is trusted.

use std::collections::HashSet;

use mcp_toolkit_http::oauth::{validate_absolute_url, UrlValidationError};
use reqwest::Url;
use thiserror::Error;

use crate::OidcDiscovery;

/// Identifies an endpoint advertised by OIDC discovery metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OidcDiscoveryEndpoint {
    Authorization,
    Token,
    Registration,
    Jwks,
    Introspection,
    DeviceAuthorization,
}

impl OidcDiscoveryEndpoint {
    fn field_name(self) -> &'static str {
        match self {
            Self::Authorization => "authorization_endpoint",
            Self::Token => "token_endpoint",
            Self::Registration => "registration_endpoint",
            Self::Jwks => "jwks_uri",
            Self::Introspection => "introspection_endpoint",
            Self::DeviceAuthorization => "device_authorization_endpoint",
        }
    }

    fn value(self, metadata: &OidcDiscovery) -> Option<&str> {
        match self {
            Self::Authorization => metadata.authorization_endpoint.as_deref(),
            Self::Token => metadata.token_endpoint.as_deref(),
            Self::Registration => metadata.registration_endpoint.as_deref(),
            Self::Jwks => Some(metadata.jwks_uri.as_str()),
            Self::Introspection => metadata.introspection_endpoint.as_deref(),
            Self::DeviceAuthorization => metadata.device_authorization_endpoint.as_deref(),
        }
    }
}

/// Describes the capabilities a caller requires from OIDC discovery metadata.
///
/// # Examples
/// ```
/// use mcp_toolkit_auth::{OidcDiscoveryEndpoint, OidcDiscoveryRequirements};
///
/// let requirements = OidcDiscoveryRequirements::new("https://issuer.example")
///     .with_required_endpoints([
///         OidcDiscoveryEndpoint::Authorization,
///         OidcDiscoveryEndpoint::Token,
///     ])
///     .with_required_grant_types(["authorization_code"])
///     .with_required_response_types(["code"])
///     .with_required_code_challenge_methods(["S256"]);
/// let _ = requirements;
/// ```
///
/// Exact policies are opt-in and compare each capability list as a set:
/// ```
/// use mcp_toolkit_auth::OidcDiscoveryRequirements;
///
/// let requirements = OidcDiscoveryRequirements::new("https://issuer.example")
///     .with_exact_grant_types(["authorization_code"]);
/// let _ = requirements;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcDiscoveryRequirements {
    expected_issuer: String,
    required_endpoints: Vec<OidcDiscoveryEndpoint>,
    required_grant_types: Vec<String>,
    required_response_types: Vec<String>,
    required_code_challenge_methods: Vec<String>,
    exact_grant_types: Option<Vec<String>>,
    exact_response_types: Option<Vec<String>>,
    exact_code_challenge_methods: Option<Vec<String>>,
    require_endpoint_origin_match: bool,
    allow_insecure_http: bool,
}

impl OidcDiscoveryRequirements {
    /// Creates requirements bound to one expected issuer identifier.
    pub fn new(expected_issuer: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            required_endpoints: Vec::new(),
            required_grant_types: Vec::new(),
            required_response_types: Vec::new(),
            required_code_challenge_methods: Vec::new(),
            exact_grant_types: None,
            exact_response_types: None,
            exact_code_challenge_methods: None,
            require_endpoint_origin_match: false,
            allow_insecure_http: false,
        }
    }

    /// Requires the listed discovery endpoints to be present and valid.
    pub fn with_required_endpoints<I>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = OidcDiscoveryEndpoint>,
    {
        self.required_endpoints = endpoints.into_iter().collect();
        self
    }

    /// Requires every listed OAuth grant type.
    pub fn with_required_grant_types<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_grant_types = values.into_iter().map(Into::into).collect();
        self
    }

    /// Requires every listed OAuth response type.
    pub fn with_required_response_types<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_response_types = values.into_iter().map(Into::into).collect();
        self
    }

    /// Requires every listed PKCE code challenge method.
    pub fn with_required_code_challenge_methods<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_code_challenge_methods = values.into_iter().map(Into::into).collect();
        self
    }

    /// Requires the advertised grant-type list to contain exactly these values.
    ///
    /// The list is compared as a set, so its order does not matter. An empty
    /// list explicitly requires an advertised, empty list; an omitted metadata
    /// field does not satisfy this policy. Values are validated when
    /// [`Self::validate`] is called.
    pub fn with_exact_grant_types<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exact_grant_types = Some(values.into_iter().map(Into::into).collect());
        self
    }

    /// Requires the advertised response-type list to contain exactly these
    /// values, compared as an order-independent set. Each response type may
    /// contain a space-delimited set of response names; names within one value
    /// are also compared without regard to order.
    ///
    /// An empty list explicitly requires an advertised, empty list; an omitted
    /// metadata field does not satisfy this policy. Values are validated when
    /// [`Self::validate`] is called.
    pub fn with_exact_response_types<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exact_response_types = Some(values.into_iter().map(Into::into).collect());
        self
    }

    /// Requires the advertised PKCE method list to contain exactly these
    /// values, compared as an order-independent set.
    ///
    /// An empty list explicitly requires an advertised, empty list; an omitted
    /// metadata field does not satisfy this policy. Values are validated when
    /// [`Self::validate`] is called.
    pub fn with_exact_code_challenge_methods<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exact_code_challenge_methods = Some(values.into_iter().map(Into::into).collect());
        self
    }

    /// Requires each advertised endpoint to share the issuer's origin.
    ///
    /// This policy is opt-in because OAuth deployments may deliberately use
    /// endpoints on origins other than the issuer origin.
    pub fn with_endpoint_origin_match(mut self, required: bool) -> Self {
        self.require_endpoint_origin_match = required;
        self
    }

    /// Allows HTTP metadata URLs when a caller explicitly accepts that policy.
    pub fn with_insecure_http(mut self, allowed: bool) -> Self {
        self.allow_insecure_http = allowed;
        self
    }

    /// Validates discovery metadata against these requirements.
    ///
    /// # Errors
    /// Returns [`OidcDiscoveryValidationError`] when metadata is malformed or
    /// does not satisfy the caller's issuer, endpoint, or capability policy.
    ///
    /// # Security
    /// Validate metadata before using its endpoints or enabling an OAuth flow.
    pub fn validate(&self, metadata: &OidcDiscovery) -> Result<(), OidcDiscoveryValidationError> {
        validate_requirement_values("required_endpoints", &self.required_endpoints)?;
        validate_capability_requirements(
            "grant_types_supported",
            &self.required_grant_types,
            self.exact_grant_types.as_deref(),
        )?;
        validate_capability_requirements(
            "response_types_supported",
            &self.required_response_types,
            self.exact_response_types.as_deref(),
        )?;
        validate_capability_requirements(
            "code_challenge_methods_supported",
            &self.required_code_challenge_methods,
            self.exact_code_challenge_methods.as_deref(),
        )?;

        validate_url(
            "expected_issuer",
            &self.expected_issuer,
            self.allow_insecure_http,
        )?;
        let discovered_issuer_value = metadata
            .issuer
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(OidcDiscoveryValidationError::MissingIssuer)?;
        let discovered_issuer =
            validate_url("issuer", discovered_issuer_value, self.allow_insecure_http)?;
        if discovered_issuer_value != self.expected_issuer {
            return Err(OidcDiscoveryValidationError::IssuerMismatch);
        }

        for endpoint in &self.required_endpoints {
            let value = endpoint
                .value(metadata)
                .filter(|value| !value.is_empty())
                .ok_or(OidcDiscoveryValidationError::MissingEndpoint(*endpoint))?;
            let endpoint_url =
                validate_url(endpoint.field_name(), value, self.allow_insecure_http)?;
            if self.require_endpoint_origin_match && !same_origin(&discovered_issuer, &endpoint_url)
            {
                return Err(OidcDiscoveryValidationError::EndpointOriginMismatch(
                    *endpoint,
                ));
            }
        }

        validate_capabilities(
            "grant_types_supported",
            metadata.grant_types_supported.as_deref(),
            &self.required_grant_types,
            self.exact_grant_types.as_deref(),
        )?;
        validate_capabilities(
            "response_types_supported",
            metadata.response_types_supported.as_deref(),
            &self.required_response_types,
            self.exact_response_types.as_deref(),
        )?;
        validate_capabilities(
            "code_challenge_methods_supported",
            metadata.code_challenge_methods_supported.as_deref(),
            &self.required_code_challenge_methods,
            self.exact_code_challenge_methods.as_deref(),
        )?;
        Ok(())
    }
}

/// Reports why OIDC discovery metadata failed a capability contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OidcDiscoveryValidationError {
    #[error("OIDC discovery metadata is missing issuer")]
    MissingIssuer,
    #[error("OIDC discovery issuer does not match the expected issuer")]
    IssuerMismatch,
    #[error("OIDC discovery URL for {field} is invalid: {reason}")]
    InvalidUrl {
        field: &'static str,
        reason: UrlValidationError,
    },
    #[error("OIDC discovery URL for {0} is not canonical")]
    NonCanonicalUrl(&'static str),
    #[error("OIDC discovery metadata is missing required endpoint {0:?}")]
    MissingEndpoint(OidcDiscoveryEndpoint),
    #[error("OIDC discovery endpoint {0:?} does not match the issuer origin")]
    EndpointOriginMismatch(OidcDiscoveryEndpoint),
    #[error("OIDC discovery requirements for {0} contain an invalid value")]
    InvalidRequirements(&'static str),
    #[error("OIDC discovery metadata field {field} has an invalid value at index {index}")]
    InvalidCapabilityValue { field: &'static str, index: usize },
    #[error("OIDC discovery metadata field {field} has a duplicate value at index {index}")]
    DuplicateCapabilityValue { field: &'static str, index: usize },
    #[error("OIDC discovery metadata is missing required field {0}")]
    MissingCapabilityField(&'static str),
    #[error("OIDC discovery metadata field {field} is missing required value {value}")]
    MissingRequiredCapability { field: &'static str, value: String },
    #[error(
        "OIDC discovery requirement for {field} excludes required value {value} from its exact set"
    )]
    RequiredCapabilityExcludedByExactPolicy { field: &'static str, value: String },
    #[error("OIDC discovery metadata field {field} contains unexpected value {value}")]
    UnexpectedCapability { field: &'static str, value: String },
}

fn validate_url(
    field: &'static str,
    value: &str,
    allow_insecure_http: bool,
) -> Result<Url, OidcDiscoveryValidationError> {
    if value.trim() != value {
        return Err(OidcDiscoveryValidationError::NonCanonicalUrl(field));
    }
    validate_absolute_url(value, allow_insecure_http)
        .map_err(|reason| OidcDiscoveryValidationError::InvalidUrl { field, reason })?;
    let url = Url::parse(value).map_err(|_| OidcDiscoveryValidationError::InvalidUrl {
        field,
        reason: UrlValidationError::Invalid,
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (matches!(field, "expected_issuer" | "issuer") && url.query().is_some())
    {
        return Err(OidcDiscoveryValidationError::NonCanonicalUrl(field));
    }
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.origin() == right.origin()
}

fn validate_requirement_values(
    field: &'static str,
    values: &[OidcDiscoveryEndpoint],
) -> Result<(), OidcDiscoveryValidationError> {
    let mut seen = HashSet::new();
    if values.iter().any(|value| !seen.insert(*value)) {
        return Err(OidcDiscoveryValidationError::InvalidRequirements(field));
    }
    Ok(())
}

fn validate_capability_requirements(
    field: &'static str,
    required: &[String],
    exact: Option<&[String]>,
) -> Result<(), OidcDiscoveryValidationError> {
    let mut seen = HashSet::new();
    for value in required {
        let Some(canonical) = canonical_capability(field, value) else {
            return Err(OidcDiscoveryValidationError::InvalidRequirements(field));
        };
        if !seen.insert(canonical) {
            return Err(OidcDiscoveryValidationError::InvalidRequirements(field));
        }
    }
    let Some(exact) = exact else {
        return Ok(());
    };
    let mut exact_seen = HashSet::new();
    for value in exact {
        let Some(canonical) = canonical_capability(field, value) else {
            return Err(OidcDiscoveryValidationError::InvalidRequirements(field));
        };
        if !exact_seen.insert(canonical) {
            return Err(OidcDiscoveryValidationError::InvalidRequirements(field));
        }
    }
    if let Some(value) = required.iter().find(|value| {
        canonical_capability(field, value).is_some_and(|canonical| !exact_seen.contains(&canonical))
    }) {
        return Err(
            OidcDiscoveryValidationError::RequiredCapabilityExcludedByExactPolicy {
                field,
                value: value.clone(),
            },
        );
    }
    Ok(())
}

fn validate_capabilities(
    field: &'static str,
    advertised: Option<&[String]>,
    required: &[String],
    exact: Option<&[String]>,
) -> Result<(), OidcDiscoveryValidationError> {
    let Some(advertised) = advertised else {
        return if required.is_empty() && exact.is_none() {
            Ok(())
        } else {
            Err(OidcDiscoveryValidationError::MissingCapabilityField(field))
        };
    };
    let mut seen = HashSet::new();
    for (index, value) in advertised.iter().enumerate() {
        let Some(canonical) = canonical_capability(field, value) else {
            return Err(OidcDiscoveryValidationError::InvalidCapabilityValue { field, index });
        };
        if !seen.insert(canonical) {
            return Err(OidcDiscoveryValidationError::DuplicateCapabilityValue { field, index });
        }
    }
    for required_value in required {
        let Some(canonical) = canonical_capability(field, required_value) else {
            return Err(OidcDiscoveryValidationError::InvalidRequirements(field));
        };
        if !seen.contains(&canonical) {
            return Err(OidcDiscoveryValidationError::MissingRequiredCapability {
                field,
                value: required_value.clone(),
            });
        }
    }
    if let Some(exact) = exact {
        let mut exact_seen = HashSet::new();
        for value in exact {
            let Some(canonical) = canonical_capability(field, value) else {
                return Err(OidcDiscoveryValidationError::InvalidRequirements(field));
            };
            exact_seen.insert(canonical);
        }
        if let Some(value) = advertised.iter().find(|value| {
            canonical_capability(field, value)
                .is_some_and(|canonical| !exact_seen.contains(&canonical))
        }) {
            return Err(OidcDiscoveryValidationError::UnexpectedCapability {
                field,
                value: value.clone(),
            });
        }
        if let Some(value) = exact.iter().find(|value| {
            canonical_capability(field, value).is_some_and(|canonical| !seen.contains(&canonical))
        }) {
            return Err(OidcDiscoveryValidationError::MissingRequiredCapability {
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn canonical_capability(field: &'static str, value: &str) -> Option<String> {
    if field == "response_types_supported" {
        return canonical_response_type(value);
    }
    valid_capability(value).then(|| value.to_string())
}

fn canonical_response_type(value: &str) -> Option<String> {
    let mut tokens = value.split(' ').collect::<Vec<_>>();
    if tokens.is_empty() || tokens.iter().any(|token| !valid_response_name(token)) {
        return None;
    }
    tokens.sort_unstable();
    if tokens.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    Some(tokens.join(" "))
}

fn valid_response_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'
            )
        })
}

fn valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

#[cfg(test)]
mod tests {
    use super::{OidcDiscoveryEndpoint, OidcDiscoveryRequirements, OidcDiscoveryValidationError};
    use crate::OidcDiscovery;
    use mcp_toolkit_http::oauth::UrlValidationError;

    type ExactCapabilitySetter =
        fn(OidcDiscoveryRequirements, Vec<&'static str>) -> OidcDiscoveryRequirements;

    fn metadata() -> OidcDiscovery {
        OidcDiscovery {
            issuer: Some("https://issuer.example/tenant".to_string()),
            authorization_endpoint: Some("https://issuer.example/authorize".to_string()),
            token_endpoint: Some("https://issuer.example/token".to_string()),
            registration_endpoint: None,
            jwks_uri: "https://issuer.example/jwks".to_string(),
            introspection_endpoint: None,
            device_authorization_endpoint: Some("https://issuer.example/device".to_string()),
            grant_types_supported: Some(vec![
                "authorization_code".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ]),
            response_types_supported: Some(vec!["code".to_string()]),
            client_id_metadata_document_supported: None,
            token_endpoint_auth_methods_supported: None,
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        }
    }

    fn requirements() -> OidcDiscoveryRequirements {
        OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_endpoints([
                OidcDiscoveryEndpoint::Authorization,
                OidcDiscoveryEndpoint::Token,
                OidcDiscoveryEndpoint::Jwks,
                OidcDiscoveryEndpoint::DeviceAuthorization,
            ])
            .with_required_grant_types([
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:device_code",
            ])
            .with_required_response_types(["code"])
            .with_required_code_challenge_methods(["S256"])
            .with_endpoint_origin_match(true)
    }

    #[test]
    fn validates_complete_capability_contract() {
        assert_eq!(requirements().validate(&metadata()), Ok(()));
    }

    #[test]
    fn rejects_issuer_mismatch() {
        let mut metadata = metadata();
        metadata.issuer = Some("https://other.example/tenant".to_string());
        assert_eq!(
            requirements().validate(&metadata),
            Err(OidcDiscoveryValidationError::IssuerMismatch)
        );
    }

    #[test]
    fn rejects_non_exact_issuer_identity() {
        let mut metadata = metadata();
        metadata.issuer = Some("https://issuer.example/tenant/".to_string());
        assert_eq!(
            requirements().validate(&metadata),
            Err(OidcDiscoveryValidationError::IssuerMismatch)
        );
    }

    #[test]
    fn rejects_missing_required_endpoint() {
        let mut metadata = metadata();
        metadata.device_authorization_endpoint = None;
        assert_eq!(
            requirements().validate(&metadata),
            Err(OidcDiscoveryValidationError::MissingEndpoint(
                OidcDiscoveryEndpoint::DeviceAuthorization
            ))
        );
    }

    #[test]
    fn rejects_malformed_endpoint() {
        let mut metadata = metadata();
        metadata.token_endpoint = Some("not-a-url".to_string());
        assert_eq!(
            requirements().validate(&metadata),
            Err(OidcDiscoveryValidationError::InvalidUrl {
                field: "token_endpoint",
                reason: UrlValidationError::Invalid,
            })
        );
    }

    #[test]
    fn rejects_cross_origin_endpoint_when_policy_requires_issuer_origin() {
        let mut metadata = metadata();
        metadata.token_endpoint = Some("https://tokens.example/token".to_string());
        assert_eq!(
            requirements().validate(&metadata),
            Err(OidcDiscoveryValidationError::EndpointOriginMismatch(
                OidcDiscoveryEndpoint::Token
            ))
        );

        assert_eq!(
            requirements()
                .with_endpoint_origin_match(false)
                .validate(&metadata),
            Ok(())
        );
    }

    #[test]
    fn rejects_missing_required_capabilities() {
        let mut missing_grant = metadata();
        missing_grant.grant_types_supported = Some(vec!["authorization_code".to_string()]);
        assert_eq!(
            requirements().validate(&missing_grant),
            Err(OidcDiscoveryValidationError::MissingRequiredCapability {
                field: "grant_types_supported",
                value: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            })
        );

        let mut missing_response = metadata();
        missing_response.response_types_supported = None;
        assert_eq!(
            requirements().validate(&missing_response),
            Err(OidcDiscoveryValidationError::MissingCapabilityField(
                "response_types_supported"
            ))
        );

        let mut missing_pkce = metadata();
        missing_pkce.code_challenge_methods_supported = Some(vec!["plain".to_string()]);
        assert_eq!(
            requirements().validate(&missing_pkce),
            Err(OidcDiscoveryValidationError::MissingRequiredCapability {
                field: "code_challenge_methods_supported",
                value: "S256".to_string(),
            })
        );
    }

    #[test]
    fn rejects_duplicate_or_noncanonical_capability_values() {
        let mut duplicate = metadata();
        duplicate.grant_types_supported = Some(vec![
            "authorization_code".to_string(),
            "authorization_code".to_string(),
        ]);
        assert_eq!(
            requirements().validate(&duplicate),
            Err(OidcDiscoveryValidationError::DuplicateCapabilityValue {
                field: "grant_types_supported",
                index: 1,
            })
        );

        let mut malformed = metadata();
        malformed.response_types_supported = Some(vec![" code".to_string()]);
        assert_eq!(
            requirements().validate(&malformed),
            Err(OidcDiscoveryValidationError::InvalidCapabilityValue {
                field: "response_types_supported",
                index: 0,
            })
        );
    }

    #[test]
    fn response_type_composites_compare_without_inner_order() {
        let mut advertised = metadata();
        advertised.response_types_supported = Some(vec!["id_token token".to_string()]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_response_types(["token id_token"]);

        assert_eq!(requirements.validate(&advertised), Ok(()));
    }

    #[test]
    fn exact_response_type_policy_compares_canonical_composites() {
        let mut advertised = metadata();
        advertised.response_types_supported = Some(vec!["id_token token".to_string()]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_response_types(["token id_token"]);

        assert_eq!(requirements.validate(&advertised), Ok(()));
    }

    #[test]
    fn response_type_policy_rejects_duplicate_canonical_composites() {
        let mut advertised = metadata();
        advertised.response_types_supported = Some(vec![
            "id_token token".to_string(),
            "token id_token".to_string(),
        ]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_response_types(["id_token token"]);

        assert_eq!(
            requirements.validate(&advertised),
            Err(OidcDiscoveryValidationError::DuplicateCapabilityValue {
                field: "response_types_supported",
                index: 1,
            })
        );
    }

    #[test]
    fn response_type_policy_rejects_duplicate_canonical_requirements() {
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_response_types(["id_token token", "token id_token"]);

        assert_eq!(
            requirements.validate(&metadata()),
            Err(OidcDiscoveryValidationError::InvalidRequirements(
                "response_types_supported"
            ))
        );
    }

    #[test]
    fn response_type_policy_rejects_malformed_composite_spacing_and_tokens() {
        for malformed in [
            "",
            " id_token token",
            "id_token token ",
            "id_token  token",
            "id_token\ttoken",
            "id_token\u{00a0}token",
            "id_token token token",
        ] {
            let mut advertised = metadata();
            advertised.response_types_supported = Some(vec![malformed.to_string()]);
            let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
                .with_required_response_types(["id_token token"]);

            assert_eq!(
                requirements.validate(&advertised),
                Err(OidcDiscoveryValidationError::InvalidCapabilityValue {
                    field: "response_types_supported",
                    index: 0,
                }),
                "malformed response type: {malformed:?}"
            );
        }
    }

    #[test]
    fn response_type_requirements_reject_rfc6749_invalid_response_names() {
        for punctuation in ["+", "%", "!", "/", "-", "."] {
            let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
                .with_exact_response_types([format!("custom{punctuation}2")]);

            assert_eq!(
                requirements.validate(&metadata()),
                Err(OidcDiscoveryValidationError::InvalidRequirements(
                    "response_types_supported"
                )),
                "invalid response name punctuation: {punctuation:?}"
            );
        }
    }

    #[test]
    fn advertised_response_types_reject_rfc6749_invalid_response_names_at_index() {
        for punctuation in ["+", "%", "!", "/", "-", "."] {
            let mut advertised = metadata();
            advertised.response_types_supported =
                Some(vec!["code".to_string(), format!("custom{punctuation}2")]);
            let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
                .with_required_response_types(["code"]);

            assert_eq!(
                requirements.validate(&advertised),
                Err(OidcDiscoveryValidationError::InvalidCapabilityValue {
                    field: "response_types_supported",
                    index: 1,
                }),
                "invalid response name punctuation: {punctuation:?}"
            );
        }
    }

    #[test]
    fn valid_custom_response_names_and_reordered_composites_are_accepted() {
        let mut advertised = metadata();
        advertised.response_types_supported = Some(vec!["token custom_2".to_string()]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_response_types(["custom_2 token"]);

        assert_eq!(requirements.validate(&advertised), Ok(()));
    }

    #[test]
    fn grant_type_urn_punctuation_remains_accepted() {
        let mut advertised = metadata();
        advertised.grant_types_supported = Some(vec![
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_grant_types(["urn:ietf:params:oauth:grant-type:device_code"]);

        assert_eq!(requirements.validate(&advertised), Ok(()));
    }

    #[test]
    fn grant_and_pkce_capabilities_retain_scalar_whitespace_rejection() {
        let mut grant = metadata();
        grant.grant_types_supported = Some(vec!["authorization_code device_code".to_string()]);
        assert_eq!(
            requirements().validate(&grant),
            Err(OidcDiscoveryValidationError::InvalidCapabilityValue {
                field: "grant_types_supported",
                index: 0,
            })
        );

        let mut pkce = metadata();
        pkce.code_challenge_methods_supported = Some(vec!["S256 plain".to_string()]);
        assert_eq!(
            requirements().validate(&pkce),
            Err(OidcDiscoveryValidationError::InvalidCapabilityValue {
                field: "code_challenge_methods_supported",
                index: 0,
            })
        );
    }

    #[test]
    fn exact_capability_policy_accepts_the_same_sets_in_a_different_order() {
        let mut reordered = metadata();
        reordered.grant_types_supported = Some(vec![
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "authorization_code".to_string(),
        ]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_grant_types([
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:device_code",
            ])
            .with_exact_response_types(["code"])
            .with_exact_code_challenge_methods(["S256"]);

        assert_eq!(requirements.validate(&reordered), Ok(()));
    }

    #[test]
    fn exact_capability_policy_rejects_surplus_values() {
        let mut extra = metadata();
        extra.response_types_supported = Some(vec!["code".to_string(), "token".to_string()]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_response_types(["code"]);

        assert_eq!(
            requirements.validate(&extra),
            Err(OidcDiscoveryValidationError::UnexpectedCapability {
                field: "response_types_supported",
                value: "token".to_string(),
            })
        );
    }

    #[test]
    fn exact_capability_policy_rejects_missing_values() {
        let mut missing = metadata();
        missing.grant_types_supported = Some(vec!["authorization_code".to_string()]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_grant_types([
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:device_code",
            ]);

        assert_eq!(
            requirements.validate(&missing),
            Err(OidcDiscoveryValidationError::MissingRequiredCapability {
                field: "grant_types_supported",
                value: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            })
        );
    }

    #[test]
    fn exact_capability_policy_distinguishes_empty_from_absent() {
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_response_types([] as [&str; 0]);

        let mut empty = metadata();
        empty.response_types_supported = Some(Vec::new());
        assert_eq!(requirements.validate(&empty), Ok(()));

        let mut absent = metadata();
        absent.response_types_supported = None;
        assert_eq!(
            requirements.validate(&absent),
            Err(OidcDiscoveryValidationError::MissingCapabilityField(
                "response_types_supported"
            ))
        );
    }

    #[test]
    fn exact_capability_policy_rejects_empty_list_with_advertised_value() {
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_code_challenge_methods([] as [&str; 0]);

        assert_eq!(
            requirements.validate(&metadata()),
            Err(OidcDiscoveryValidationError::UnexpectedCapability {
                field: "code_challenge_methods_supported",
                value: "S256".to_string(),
            })
        );
    }

    #[test]
    fn exact_policy_reports_required_values_excluded_by_exact_set() {
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_grant_types(["authorization_code"])
            .with_exact_grant_types(["urn:ietf:params:oauth:grant-type:device_code"]);

        assert_eq!(
            requirements.validate(&metadata()),
            Err(
                OidcDiscoveryValidationError::RequiredCapabilityExcludedByExactPolicy {
                    field: "grant_types_supported",
                    value: "authorization_code".to_string(),
                }
            )
        );
    }

    #[test]
    fn exact_policy_rejects_duplicate_requirements_for_every_capability_field() {
        fn with_exact_grant_types(
            requirements: OidcDiscoveryRequirements,
            values: Vec<&'static str>,
        ) -> OidcDiscoveryRequirements {
            requirements.with_exact_grant_types(values)
        }

        fn with_exact_response_types(
            requirements: OidcDiscoveryRequirements,
            values: Vec<&'static str>,
        ) -> OidcDiscoveryRequirements {
            requirements.with_exact_response_types(values)
        }

        fn with_exact_code_challenge_methods(
            requirements: OidcDiscoveryRequirements,
            values: Vec<&'static str>,
        ) -> OidcDiscoveryRequirements {
            requirements.with_exact_code_challenge_methods(values)
        }

        let cases: [(&str, ExactCapabilitySetter); 3] = [
            ("grant_types_supported", with_exact_grant_types),
            ("response_types_supported", with_exact_response_types),
            (
                "code_challenge_methods_supported",
                with_exact_code_challenge_methods,
            ),
        ];

        for (field, setter) in cases {
            assert_eq!(
                setter(
                    OidcDiscoveryRequirements::new("https://issuer.example/tenant"),
                    vec!["authorization_code", "authorization_code"],
                )
                .validate(&metadata()),
                Err(OidcDiscoveryValidationError::InvalidRequirements(field))
            );
        }
    }

    #[test]
    fn exact_policy_rejects_malformed_requirements_for_every_capability_field() {
        fn with_exact_grant_types(
            requirements: OidcDiscoveryRequirements,
            values: Vec<&'static str>,
        ) -> OidcDiscoveryRequirements {
            requirements.with_exact_grant_types(values)
        }

        fn with_exact_response_types(
            requirements: OidcDiscoveryRequirements,
            values: Vec<&'static str>,
        ) -> OidcDiscoveryRequirements {
            requirements.with_exact_response_types(values)
        }

        fn with_exact_code_challenge_methods(
            requirements: OidcDiscoveryRequirements,
            values: Vec<&'static str>,
        ) -> OidcDiscoveryRequirements {
            requirements.with_exact_code_challenge_methods(values)
        }

        let cases: [(&str, ExactCapabilitySetter); 3] = [
            ("grant_types_supported", with_exact_grant_types),
            ("response_types_supported", with_exact_response_types),
            (
                "code_challenge_methods_supported",
                with_exact_code_challenge_methods,
            ),
        ];

        for (field, setter) in cases {
            assert_eq!(
                setter(
                    OidcDiscoveryRequirements::new("https://issuer.example/tenant"),
                    vec!["authorization_code", " invalid"],
                )
                .validate(&metadata()),
                Err(OidcDiscoveryValidationError::InvalidRequirements(field))
            );
        }
    }

    #[test]
    fn required_subset_policy_accepts_surplus_capabilities_without_exact_policy() {
        let mut metadata = metadata();
        metadata.response_types_supported = Some(vec!["code".to_string(), "token".to_string()]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_response_types(["code"]);

        assert_eq!(requirements.validate(&metadata), Ok(()));
    }

    #[test]
    fn exact_capability_policy_keeps_duplicate_rejection() {
        let mut duplicate = metadata();
        duplicate.grant_types_supported = Some(vec![
            "authorization_code".to_string(),
            "authorization_code".to_string(),
        ]);
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_exact_grant_types(["authorization_code"]);

        assert_eq!(
            requirements.validate(&duplicate),
            Err(OidcDiscoveryValidationError::DuplicateCapabilityValue {
                field: "grant_types_supported",
                index: 1,
            })
        );
    }

    #[test]
    fn invalid_exact_requirement_is_rejected_before_metadata_validation() {
        let requirements = OidcDiscoveryRequirements::new("https://issuer.example/tenant")
            .with_required_grant_types(["authorization_code"])
            .with_exact_grant_types(["urn:ietf:params:oauth:grant-type:device_code"]);

        assert_eq!(
            requirements.validate(&metadata()),
            Err(
                OidcDiscoveryValidationError::RequiredCapabilityExcludedByExactPolicy {
                    field: "grant_types_supported",
                    value: "authorization_code".to_string(),
                }
            )
        );
    }

    #[test]
    fn deserializes_response_types_for_capability_validation() {
        let parsed: OidcDiscovery = serde_json::from_value(serde_json::json!({
            "issuer": "https://issuer.example/tenant",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/jwks",
            "grant_types_supported": ["authorization_code"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"]
        }))
        .expect("discovery metadata");

        assert_eq!(
            parsed.response_types_supported,
            Some(vec!["code".to_string()])
        );
    }
}

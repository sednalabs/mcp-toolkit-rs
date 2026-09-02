//! # Protected Resource Metadata Validation
//!
//! Typed, caller-configurable validation for externally fetched RFC 9728
//! metadata.
//!
//! ## Security Boundaries
//! * Validation performs no network I/O and never handles bearer tokens.
//! * Resource identity is exact, authorization-server URLs are canonical, and
//!   list equality or subset policy remains explicit caller configuration.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use url::Url;

use super::{validate_absolute_url, ResourceMetadata, UrlValidationError};

/// Selects a list-valued RFC 9728 metadata field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceMetadataListField {
    AuthorizationServers,
    ScopesSupported,
    BearerMethodsSupported,
}

impl ResourceMetadataListField {
    fn name(self) -> &'static str {
        match self {
            Self::AuthorizationServers => "authorization_servers",
            Self::ScopesSupported => "scopes_supported",
            Self::BearerMethodsSupported => "bearer_methods_supported",
        }
    }
}

/// Describes caller policy for one list-valued metadata field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataListRequirements {
    require_non_empty: bool,
    required_values: Vec<String>,
    exact_values: Option<Vec<String>>,
}

impl MetadataListRequirements {
    /// Creates an unconstrained list policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires the metadata list to contain at least one entry.
    pub fn with_non_empty(mut self, required: bool) -> Self {
        self.require_non_empty = required;
        self
    }

    /// Requires the metadata list to contain every supplied value.
    pub fn with_required_values<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_values = values.into_iter().map(Into::into).collect();
        self
    }

    /// Requires exact ordered equality with the supplied list.
    pub fn with_exact_values<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exact_values = Some(values.into_iter().map(Into::into).collect());
        self
    }
}

/// Describes the RFC 9728 metadata contract expected by a caller.
///
/// # Examples
/// ```
/// use mcp_toolkit_http::oauth::{
///     MetadataListRequirements, ResourceMetadataRequirements,
/// };
///
/// let requirements = ResourceMetadataRequirements::new("https://api.example/mcp")
///     .with_authorization_servers(
///         MetadataListRequirements::new()
///             .with_exact_values(["https://issuer.example"]),
///     )
///     .with_scopes_supported(
///         MetadataListRequirements::new().with_required_values(["records.read"]),
///     )
///     .with_bearer_methods_supported(
///         MetadataListRequirements::new().with_required_values(["header"]),
///     );
/// let _ = requirements;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMetadataRequirements {
    expected_resource: String,
    authorization_servers: MetadataListRequirements,
    scopes_supported: MetadataListRequirements,
    bearer_methods_supported: MetadataListRequirements,
    allow_insecure_http: bool,
}

impl ResourceMetadataRequirements {
    /// Creates requirements bound to one exact resource identifier.
    pub fn new(expected_resource: impl Into<String>) -> Self {
        Self {
            expected_resource: expected_resource.into(),
            authorization_servers: MetadataListRequirements::new(),
            scopes_supported: MetadataListRequirements::new(),
            bearer_methods_supported: MetadataListRequirements::new(),
            allow_insecure_http: false,
        }
    }

    /// Configures authorization-server list policy.
    pub fn with_authorization_servers(mut self, policy: MetadataListRequirements) -> Self {
        self.authorization_servers = policy;
        self
    }

    /// Configures supported-scope list policy.
    pub fn with_scopes_supported(mut self, policy: MetadataListRequirements) -> Self {
        self.scopes_supported = policy;
        self
    }

    /// Configures bearer-method list policy.
    pub fn with_bearer_methods_supported(mut self, policy: MetadataListRequirements) -> Self {
        self.bearer_methods_supported = policy;
        self
    }

    /// Allows HTTP metadata identifiers when a caller explicitly accepts it.
    pub fn with_insecure_http(mut self, allowed: bool) -> Self {
        self.allow_insecure_http = allowed;
        self
    }

    /// Validates externally fetched RFC 9728 metadata.
    ///
    /// # Errors
    /// Returns [`ResourceMetadataValidationError`] when resource identity, URL
    /// shape, or configured list policy is not satisfied.
    ///
    /// # Security
    /// Apply validation before trusting authorization-server locations or using
    /// the metadata to select scopes or bearer presentation methods.
    pub fn validate(
        &self,
        metadata: &ResourceMetadata,
    ) -> Result<(), ResourceMetadataValidationError> {
        validate_resource_identifier(
            "expected_resource",
            &self.expected_resource,
            self.allow_insecure_http,
        )?;
        validate_resource_identifier("resource", &metadata.resource, self.allow_insecure_http)?;
        if metadata.resource != self.expected_resource {
            return Err(ResourceMetadataValidationError::ResourceMismatch);
        }

        validate_list(
            ResourceMetadataListField::AuthorizationServers,
            &metadata.authorization_servers,
            &self.authorization_servers,
            self.allow_insecure_http,
        )?;
        validate_list(
            ResourceMetadataListField::ScopesSupported,
            &metadata.scopes_supported,
            &self.scopes_supported,
            self.allow_insecure_http,
        )?;
        validate_list(
            ResourceMetadataListField::BearerMethodsSupported,
            &metadata.bearer_methods_supported,
            &self.bearer_methods_supported,
            self.allow_insecure_http,
        )?;
        Ok(())
    }
}

/// Reports why protected resource metadata failed a caller contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceMetadataValidationError {
    InvalidUrl {
        field: &'static str,
        index: Option<usize>,
        reason: UrlValidationError,
    },
    NonCanonicalUrl {
        field: &'static str,
        index: Option<usize>,
    },
    ResourceMismatch,
    InvalidRequirements(ResourceMetadataListField),
    RequiredListEmpty(ResourceMetadataListField),
    InvalidListValue {
        field: ResourceMetadataListField,
        index: usize,
    },
    DuplicateListValue {
        field: ResourceMetadataListField,
        index: usize,
    },
    MissingRequiredValue {
        field: ResourceMetadataListField,
        value: String,
    },
    ListMismatch(ResourceMetadataListField),
}

impl fmt::Display for ResourceMetadataValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl {
                field,
                index,
                reason,
            } => match index {
                Some(index) => write!(formatter, "invalid {field} URL at index {index}: {reason}"),
                None => write!(formatter, "invalid {field} URL: {reason}"),
            },
            Self::NonCanonicalUrl { field, index } => match index {
                Some(index) => write!(formatter, "non-canonical {field} URL at index {index}"),
                None => write!(formatter, "non-canonical {field} URL"),
            },
            Self::ResourceMismatch => formatter.write_str("resource metadata identifier mismatch"),
            Self::InvalidRequirements(field) => {
                write!(formatter, "invalid requirements for {}", field.name())
            }
            Self::RequiredListEmpty(field) => {
                write!(
                    formatter,
                    "required metadata list {} is empty",
                    field.name()
                )
            }
            Self::InvalidListValue { field, index } => write!(
                formatter,
                "invalid metadata value for {} at index {index}",
                field.name()
            ),
            Self::DuplicateListValue { field, index } => write!(
                formatter,
                "duplicate metadata value for {} at index {index}",
                field.name()
            ),
            Self::MissingRequiredValue { field, value } => write!(
                formatter,
                "metadata field {} is missing required value {value}",
                field.name()
            ),
            Self::ListMismatch(field) => {
                write!(formatter, "metadata field {} does not match", field.name())
            }
        }
    }
}

impl Error for ResourceMetadataValidationError {}

fn validate_resource_identifier(
    field: &'static str,
    value: &str,
    allow_insecure_http: bool,
) -> Result<(), ResourceMetadataValidationError> {
    if value.trim() != value {
        return Err(ResourceMetadataValidationError::NonCanonicalUrl { field, index: None });
    }
    validate_absolute_url(value, allow_insecure_http).map_err(|reason| {
        ResourceMetadataValidationError::InvalidUrl {
            field,
            index: None,
            reason,
        }
    })?;
    let url = Url::parse(value).map_err(|_| ResourceMetadataValidationError::InvalidUrl {
        field,
        index: None,
        reason: UrlValidationError::Invalid,
    })?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ResourceMetadataValidationError::NonCanonicalUrl { field, index: None });
    }
    Ok(())
}

fn validate_list(
    field: ResourceMetadataListField,
    actual: &[String],
    requirements: &MetadataListRequirements,
    allow_insecure_http: bool,
) -> Result<(), ResourceMetadataValidationError> {
    validate_policy(field, requirements, allow_insecure_http)?;
    if requirements.require_non_empty && actual.is_empty() {
        return Err(ResourceMetadataValidationError::RequiredListEmpty(field));
    }

    let mut seen = HashSet::new();
    for (index, value) in actual.iter().enumerate() {
        validate_list_value(field, value, index, allow_insecure_http)?;
        if !seen.insert(value.as_str()) {
            return Err(ResourceMetadataValidationError::DuplicateListValue { field, index });
        }
    }
    for value in &requirements.required_values {
        if !seen.contains(value.as_str()) {
            return Err(ResourceMetadataValidationError::MissingRequiredValue {
                field,
                value: value.clone(),
            });
        }
    }
    if requirements
        .exact_values
        .as_ref()
        .is_some_and(|expected| expected != actual)
    {
        return Err(ResourceMetadataValidationError::ListMismatch(field));
    }
    Ok(())
}

fn validate_policy(
    field: ResourceMetadataListField,
    requirements: &MetadataListRequirements,
    allow_insecure_http: bool,
) -> Result<(), ResourceMetadataValidationError> {
    let mut required_seen = HashSet::new();
    for (index, value) in requirements.required_values.iter().enumerate() {
        if validate_list_value(field, value, index, allow_insecure_http).is_err()
            || !required_seen.insert(value.as_str())
        {
            return Err(ResourceMetadataValidationError::InvalidRequirements(field));
        }
    }
    if let Some(exact) = &requirements.exact_values {
        let mut exact_seen = HashSet::new();
        for (index, value) in exact.iter().enumerate() {
            if validate_list_value(field, value, index, allow_insecure_http).is_err()
                || !exact_seen.insert(value.as_str())
            {
                return Err(ResourceMetadataValidationError::InvalidRequirements(field));
            }
        }
    }
    Ok(())
}

fn validate_list_value(
    field: ResourceMetadataListField,
    value: &str,
    index: usize,
    allow_insecure_http: bool,
) -> Result<(), ResourceMetadataValidationError> {
    if field == ResourceMetadataListField::AuthorizationServers {
        if value.trim() != value {
            return Err(ResourceMetadataValidationError::NonCanonicalUrl {
                field: field.name(),
                index: Some(index),
            });
        }
        validate_absolute_url(value, allow_insecure_http).map_err(|reason| {
            ResourceMetadataValidationError::InvalidUrl {
                field: field.name(),
                index: Some(index),
                reason,
            }
        })?;
        let url = Url::parse(value).map_err(|_| ResourceMetadataValidationError::InvalidUrl {
            field: field.name(),
            index: Some(index),
            reason: UrlValidationError::Invalid,
        })?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ResourceMetadataValidationError::NonCanonicalUrl {
                field: field.name(),
                index: Some(index),
            });
        }
        return Ok(());
    }

    if valid_metadata_token(value) {
        Ok(())
    } else {
        Err(ResourceMetadataValidationError::InvalidListValue { field, index })
    }
}

fn valid_metadata_token(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

#[cfg(test)]
mod tests {
    use super::{
        MetadataListRequirements, ResourceMetadataListField, ResourceMetadataRequirements,
        ResourceMetadataValidationError,
    };
    use crate::oauth::{ResourceMetadata, UrlValidationError};

    fn metadata() -> ResourceMetadata {
        ResourceMetadata {
            resource: "https://api.example/mcp".to_string(),
            authorization_servers: vec![
                "https://login.example/tenant".to_string(),
                "https://backup.example".to_string(),
            ],
            scopes_supported: vec!["read:data".to_string(), "write:data".to_string()],
            bearer_methods_supported: vec!["header".to_string()],
        }
    }

    fn requirements() -> ResourceMetadataRequirements {
        ResourceMetadataRequirements::new("https://api.example/mcp")
            .with_authorization_servers(
                MetadataListRequirements::new()
                    .with_exact_values(["https://login.example/tenant", "https://backup.example"]),
            )
            .with_scopes_supported(
                MetadataListRequirements::new()
                    .with_non_empty(true)
                    .with_required_values(["read:data"]),
            )
            .with_bearer_methods_supported(
                MetadataListRequirements::new().with_exact_values(["header"]),
            )
    }

    #[test]
    fn validates_externally_deserialized_metadata() {
        let parsed: ResourceMetadata = serde_json::from_value(serde_json::json!({
            "resource": "https://api.example/mcp",
            "authorization_servers": [
                "https://login.example/tenant",
                "https://backup.example"
            ],
            "scopes_supported": ["read:data", "write:data"],
            "bearer_methods_supported": ["header"]
        }))
        .expect("resource metadata");

        assert_eq!(requirements().validate(&parsed), Ok(()));
    }

    #[test]
    fn rejects_exact_resource_mismatch() {
        let mut metadata = metadata();
        metadata.resource = "https://api.example/other".to_string();
        assert_eq!(
            requirements().validate(&metadata),
            Err(ResourceMetadataValidationError::ResourceMismatch)
        );
    }

    #[test]
    fn rejects_malformed_authorization_server() {
        let mut metadata = metadata();
        metadata.authorization_servers[0] = "not-a-url".to_string();
        assert_eq!(
            requirements()
                .with_authorization_servers(MetadataListRequirements::new())
                .validate(&metadata),
            Err(ResourceMetadataValidationError::InvalidUrl {
                field: "authorization_servers",
                index: Some(0),
                reason: UrlValidationError::Invalid,
            })
        );
    }

    #[test]
    fn rejects_noncanonical_authorization_server() {
        let mut metadata = metadata();
        metadata.authorization_servers[0] =
            "https://login.example/tenant?redirect=elsewhere".to_string();
        assert_eq!(
            requirements()
                .with_authorization_servers(MetadataListRequirements::new())
                .validate(&metadata),
            Err(ResourceMetadataValidationError::NonCanonicalUrl {
                field: "authorization_servers",
                index: Some(0),
            })
        );
    }

    #[test]
    fn permits_cross_origin_authorization_servers_selected_by_caller_policy() {
        assert_eq!(requirements().validate(&metadata()), Ok(()));
    }

    #[test]
    fn rejects_duplicate_authorization_server() {
        let mut metadata = metadata();
        metadata.authorization_servers[1] = metadata.authorization_servers[0].clone();
        assert_eq!(
            requirements()
                .with_authorization_servers(MetadataListRequirements::new())
                .validate(&metadata),
            Err(ResourceMetadataValidationError::DuplicateListValue {
                field: ResourceMetadataListField::AuthorizationServers,
                index: 1,
            })
        );
    }

    #[test]
    fn rejects_scope_shape_and_policy_mismatch() {
        let mut malformed = metadata();
        malformed.scopes_supported[0] = "read data".to_string();
        assert_eq!(
            requirements().validate(&malformed),
            Err(ResourceMetadataValidationError::InvalidListValue {
                field: ResourceMetadataListField::ScopesSupported,
                index: 0,
            })
        );

        let mut missing = metadata();
        missing.scopes_supported = vec!["write:data".to_string()];
        assert_eq!(
            requirements()
                .with_scopes_supported(
                    MetadataListRequirements::new().with_required_values(["read:data"]),
                )
                .validate(&missing),
            Err(ResourceMetadataValidationError::MissingRequiredValue {
                field: ResourceMetadataListField::ScopesSupported,
                value: "read:data".to_string(),
            })
        );

        let mut extra = metadata();
        extra.scopes_supported.push("admin:data".to_string());
        assert_eq!(
            requirements()
                .with_scopes_supported(
                    MetadataListRequirements::new().with_exact_values(["read:data", "write:data"]),
                )
                .validate(&extra),
            Err(ResourceMetadataValidationError::ListMismatch(
                ResourceMetadataListField::ScopesSupported
            ))
        );
    }

    #[test]
    fn rejects_missing_or_malformed_bearer_methods() {
        let mut missing = metadata();
        missing.bearer_methods_supported.clear();
        assert_eq!(
            requirements()
                .with_bearer_methods_supported(
                    MetadataListRequirements::new().with_non_empty(true),
                )
                .validate(&missing),
            Err(ResourceMetadataValidationError::RequiredListEmpty(
                ResourceMetadataListField::BearerMethodsSupported
            ))
        );

        let mut malformed = metadata();
        malformed.bearer_methods_supported = vec!["header method".to_string()];
        assert_eq!(
            requirements()
                .with_bearer_methods_supported(MetadataListRequirements::new())
                .validate(&malformed),
            Err(ResourceMetadataValidationError::InvalidListValue {
                field: ResourceMetadataListField::BearerMethodsSupported,
                index: 0,
            })
        );
    }

    #[test]
    fn rejects_invalid_caller_list_policy() {
        let invalid =
            MetadataListRequirements::new().with_required_values(["read:data", "read:data"]);
        assert_eq!(
            requirements()
                .with_scopes_supported(invalid)
                .validate(&metadata()),
            Err(ResourceMetadataValidationError::InvalidRequirements(
                ResourceMetadataListField::ScopesSupported
            ))
        );
    }
}

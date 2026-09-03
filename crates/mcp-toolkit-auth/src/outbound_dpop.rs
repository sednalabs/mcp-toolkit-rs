//! # Outbound DPoP Token Exchange
//!
//! Reusable RFC 9449 proof construction and RFC 8693 token-exchange transport
//! for service clients that need sender-constrained access tokens.
//!
//! ## Ownership
//! This module owns P-256 proof keys, canonical DPoP targets, nonce isolation,
//! bounded token-endpoint retries, typed exchange forms, and low-leakage
//! response validation. It accepts only an explicitly trusted token endpoint
//! policy and only a typed bearer subject token.
//!
//! ## Non-ownership
//! Callers remain responsible for deciding whether exchange is authorized,
//! selecting audiences and scopes, validating actor/project policy, and
//! projecting audit facts into their policy kernel.
//!
//! ## Security Boundaries
//! * `jsonwebtoken` owns compact JWS encoding and ES256 signing.
//! * `p256` is used only to generate a P-256 key encoded for `jsonwebtoken`.
//! * Redirects are disabled and non-loopback token endpoints require HTTPS.
//! * A token endpoint must be bound to an explicit exact-endpoint trust policy;
//!   an arbitrary URL cannot be used as a credential destination.
//! * Credentials, proofs, nonces, and private keys are redacted from `Debug`
//!   and error output.
//! * Token-endpoint and method/resource nonces use distinct bounded stores.
//!
//! ## References
//! * RFC 7638: JSON Web Key Thumbprint.
//! * RFC 8693: OAuth 2.0 Token Exchange.
//! * RFC 9449: OAuth 2.0 Demonstrating Proof of Possession.
//! * **DESIGN**: `docs/design/outbound-dpop-token-exchange.md`.
//!
//! ## Example
//! ```rust,no_run
//! use mcp_toolkit_auth::outbound_dpop::{
//!     BearerSubjectToken, DpopEndpointPolicy, DpopSigner,
//!     DpopTokenExchangeClient, DpopTokenExchangeConfig,
//!     Rfc8693TokenExchangeRequest, TokenExchangeAuditMetadata,
//! };
//! use mcp_toolkit_auth::upstream_oauth::SecretString;
//! use reqwest::Url;
//!
//! # fn configure() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = DpopSigner::generate()?;
//! let endpoint = Url::parse("https://issuer.example/oauth/token")?;
//! let config = DpopTokenExchangeConfig::new(
//!     endpoint.clone(),
//!     DpopEndpointPolicy::exact_https(endpoint)?,
//!     "service-client",
//!     Some(SecretString::new("client-secret")),
//! )?;
//! let client = DpopTokenExchangeClient::new(config, signer)?;
//! let audit = TokenExchangeAuditMetadata::new("exchange-id", "subject", "service-client")?;
//! let subject = BearerSubjectToken::new(SecretString::new("subject-token"))?;
//! let request = Rfc8693TokenExchangeRequest::new(subject, audit)?
//!     .with_audience("https://resource.example")?
//!     .with_scopes(vec!["resource:read".to_string()])?;
//! # let _ = (client, request);
//! # Ok(())
//! # }
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use jsonwebtoken::jwk::{Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePrivateKey;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::upstream_oauth::{OAuthClientAuthMethod, SecretString};

/// RFC 8693 token-exchange grant type.
pub const RFC8693_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 access-token type identifier.
pub const RFC8693_ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_FIELD_BYTES: usize = 2048;
const MAX_REQUEST_ITEMS: usize = 64;
const MAX_NONCE_BYTES: usize = 1024;
const DEFAULT_TOKEN_ENDPOINT_NONCE_CAPACITY: usize = 64;
const DEFAULT_RESOURCE_NONCE_CAPACITY: usize = 256;

/// Explicit trust policy for one credential-bearing transport target.
///
/// The policy is deliberately exact rather than a wildcard hostname rule:
/// callers must review and bind the complete canonical URL before constructing
/// a client or authorizing a resource request. `exact_loopback_http` is
/// reserved for local emulators and test fixtures.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopEndpointPolicy {
    endpoint: Url,
    allow_insecure_loopback: bool,
}

impl fmt::Debug for DpopEndpointPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopEndpointPolicy")
            .field("endpoint", &self.endpoint)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .finish()
    }
}

impl DpopEndpointPolicy {
    /// Trusts one HTTPS transport target URL exactly.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidUrl`] for URL credentials, query,
    /// fragments, or an endpoint that is not HTTPS.
    pub fn exact_https(endpoint: Url) -> Result<Self, OutboundDpopError> {
        validate_endpoint_shape(&endpoint)?;
        validate_http_url(&endpoint, false)?;
        Ok(Self {
            endpoint,
            allow_insecure_loopback: false,
        })
    }

    /// Trusts one numeric-loopback HTTP endpoint for a local emulator/test.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidUrl`] or
    /// [`OutboundDpopError::InsecureEndpoint`] when the URL is not a numeric
    /// loopback HTTP endpoint.
    pub fn exact_loopback_http(endpoint: Url) -> Result<Self, OutboundDpopError> {
        validate_endpoint_shape(&endpoint)?;
        validate_http_url(&endpoint, true)?;
        Ok(Self {
            endpoint,
            allow_insecure_loopback: true,
        })
    }

    fn matches(&self, endpoint: &Url) -> bool {
        self.endpoint == *endpoint
    }

    fn matches_resource(&self, target: &Url) -> Result<bool, OutboundDpopError> {
        if target.username().is_empty()
            && target.password().is_none()
            && target.fragment().is_none()
        {
            let canonical_target =
                canonical_dpop_target_with_policy(target, self.allow_insecure_loopback)?;
            let canonical_endpoint =
                canonical_dpop_target_with_policy(&self.endpoint, self.allow_insecure_loopback)?;
            Ok(canonical_target == canonical_endpoint)
        } else {
            Err(OutboundDpopError::InvalidUrl)
        }
    }
}

/// Failures from outbound DPoP proof and token-exchange operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OutboundDpopError {
    /// A required configuration or request field is blank or inconsistent.
    #[error("outbound DPoP field {0} is invalid")]
    InvalidField(&'static str),
    /// A URL is malformed or cannot be represented as an HTTP target.
    #[error("outbound DPoP URL is invalid")]
    InvalidUrl,
    /// A non-loopback endpoint does not use HTTPS.
    #[error("outbound DPoP endpoint must use https unless it is loopback")]
    InsecureEndpoint,
    /// The credential-bearing endpoint was not covered by the explicit trust policy.
    #[error("outbound DPoP endpoint is not covered by its explicit trust policy")]
    UntrustedEndpoint,
    /// The P-256 signing key could not be encoded for the JOSE library.
    #[error("unable to initialize outbound DPoP signing key")]
    KeyInitialization,
    /// The JOSE library rejected proof construction.
    #[error("unable to construct outbound DPoP proof")]
    ProofConstruction,
    /// The local HTTP client could not be constructed.
    #[error("unable to initialize outbound DPoP HTTP client")]
    HttpClientInitialization,
    /// The token-endpoint HTTP operation failed.
    #[error("outbound DPoP token endpoint request failed ({0})")]
    Http(HttpFailureKind),
    /// A credential could not be represented safely as an HTTP header.
    #[error("outbound DPoP credential header is invalid")]
    InvalidCredentialHeader,
    /// A nonce header was duplicated, malformed, or too large.
    #[error("outbound DPoP nonce header is invalid")]
    InvalidNonceHeader,
    /// Shared nonce state could not be accessed.
    #[error("outbound DPoP nonce state is unavailable")]
    NonceStateUnavailable,
    /// The bounded resource-nonce store is full.
    #[error("outbound DPoP resource nonce capacity is exhausted")]
    ResourceNonceCapacityExceeded,
    /// The bounded token-endpoint nonce store is full.
    #[error("outbound DPoP token endpoint nonce capacity is exhausted")]
    TokenEndpointNonceCapacityExceeded,
    /// A second nonce challenge attempted to exceed the one-retry contract.
    #[error("outbound DPoP nonce retry limit reached")]
    NonceRetryLimitReached,
    /// The token response exceeded its fixed byte budget.
    #[error("outbound DPoP token response exceeded {max_bytes} bytes")]
    ResponseTooLarge { max_bytes: usize },
    /// The token endpoint rejected the request with a low-leakage OAuth code.
    #[error("outbound DPoP token endpoint returned {status} ({code})")]
    TokenEndpointRejected {
        status: StatusCode,
        code: SafeOAuthErrorCode,
    },
    /// A successful response was not a valid RFC 8693 response.
    #[error("outbound DPoP token response is malformed")]
    MalformedTokenResponse,
    /// A successful response did not use the required JSON media type.
    #[error("outbound DPoP token response did not use application/json")]
    UnexpectedResponseContentType,
    /// A successful response omitted its access token.
    #[error("outbound DPoP token response omitted the access token")]
    MissingAccessToken,
    /// A DPoP-bound exchange returned a missing or different token type.
    #[error("outbound DPoP token response did not return token_type DPoP")]
    UnexpectedTokenType,
    /// The response's issued-token type conflicts with the requested type.
    #[error("outbound DPoP token response returned an unexpected issued_token_type")]
    UnexpectedIssuedTokenType,
    /// The response returned scopes outside the caller's requested set.
    #[error("outbound DPoP token response broadened the requested scopes")]
    BroadenedScopes,
    /// The response unexpectedly returned a refresh token.
    #[error("outbound DPoP token response unexpectedly included a refresh token")]
    UnexpectedRefreshToken,
    /// A bound access token was used with a different proof signer.
    #[error("outbound DPoP access token does not match this proof signer")]
    SignerMismatch,
    /// A response token has not been validated by the provider for DPoP use.
    #[error("outbound DPoP token requires provider-backed binding validation")]
    ProviderBindingValidationRequired,
    /// Provider validation metadata does not match the returned token or signer.
    #[error("outbound DPoP provider binding metadata does not match the token")]
    ProviderBindingMismatch,
    /// Provider validation metadata is expired or otherwise unusable.
    #[error("outbound DPoP provider binding metadata is expired or invalid")]
    ProviderBindingExpired,
}

/// Low-leakage categories for token-endpoint transport failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailureKind {
    Timeout,
    Connect,
    Request,
    ResponseBody,
    Other,
}

impl fmt::Display for HttpFailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Request => "request",
            Self::ResponseBody => "response_body",
            Self::Other => "other",
        })
    }
}

/// Sanitized OAuth error code safe for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeOAuthErrorCode(String);

impl SafeOAuthErrorCode {
    fn from_untrusted(value: Option<&str>) -> Self {
        let value = value.filter(|candidate| {
            matches!(
                *candidate,
                "invalid_request"
                    | "invalid_client"
                    | "invalid_grant"
                    | "unauthorized_client"
                    | "unsupported_grant_type"
                    | "invalid_scope"
                    | "invalid_target"
                    | "use_dpop_nonce"
                    | "temporarily_unavailable"
                    | "server_error"
            )
        });
        Self(value.unwrap_or("token_endpoint_error").to_string())
    }

    /// Returns the bounded OAuth error code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeOAuthErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Public P-256 JWK and its RFC 7638 thumbprint.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopPublicJwk {
    jwk: Jwk,
    thumbprint: String,
}

impl fmt::Debug for DpopPublicJwk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopPublicJwk")
            .field("jwk", &self.jwk)
            .field("thumbprint", &self.thumbprint)
            .finish()
    }
}

impl DpopPublicJwk {
    /// Returns the public JWK for proof headers or confirmation metadata.
    pub fn as_jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// Returns the RFC 7638 SHA-256 JWK thumbprint.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
}

/// P-256 signer used for outbound DPoP proofs.
#[derive(Clone)]
pub struct DpopSigner {
    encoding_key: EncodingKey,
    public_jwk: DpopPublicJwk,
}

impl fmt::Debug for DpopSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopSigner")
            .field("private_key", &"<redacted>")
            .field("public_jwk", &self.public_jwk)
            .finish()
    }
}

impl DpopSigner {
    /// Generates a fresh P-256 proof key.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::KeyInitialization`] if PKCS#8 or public-JWK
    /// construction fails.
    ///
    /// # Security
    /// Keep this signer scoped to the intended client identity. Its private key
    /// is redacted from formatted output but remains resident in process memory.
    pub fn generate() -> Result<Self, OutboundDpopError> {
        let signing_key = SigningKey::random(&mut OsRng);
        let document = signing_key
            .to_pkcs8_der()
            .map_err(|_| OutboundDpopError::KeyInitialization)?;
        let encoding_key = EncodingKey::from_ec_der(document.as_bytes());
        let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256)
            .map_err(|_| OutboundDpopError::KeyInitialization)?;
        let thumbprint = jwk.thumbprint(ThumbprintHash::SHA256);
        Ok(Self {
            encoding_key,
            public_jwk: DpopPublicJwk { jwk, thumbprint },
        })
    }

    /// Returns the public key and confirmation thumbprint for this signer.
    pub fn public_jwk(&self) -> &DpopPublicJwk {
        &self.public_jwk
    }

    /// Constructs a proof for an OAuth token endpoint.
    ///
    /// # Errors
    /// Returns URL, time, or JOSE construction failures.
    ///
    /// # Security
    /// The proof is authentication material and redacts itself from `Debug`.
    pub fn token_endpoint_proof(
        &self,
        endpoint: &Url,
        nonce: Option<&str>,
    ) -> Result<OutboundDpopProof, OutboundDpopError> {
        self.proof(Method::POST, endpoint, None, nonce, false)
    }

    /// Constructs a proof bound to a resource method, target, and access token.
    ///
    /// # Errors
    /// Returns URL, time, or JOSE construction failures.
    ///
    /// # Security
    /// Computes `ath` from the access token without exposing the token. The
    /// returned proof is credential material and must not be logged.
    pub fn resource_proof(
        &self,
        method: Method,
        target: &Url,
        access_token: &SecretString,
        nonce: Option<&str>,
    ) -> Result<OutboundDpopProof, OutboundDpopError> {
        self.proof(method, target, Some(access_token), nonce, false)
    }

    fn proof(
        &self,
        method: Method,
        target: &Url,
        access_token: Option<&SecretString>,
        nonce: Option<&str>,
        allow_insecure_loopback: bool,
    ) -> Result<OutboundDpopProof, OutboundDpopError> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OutboundDpopError::ProofConstruction)?
            .as_secs();
        if nonce.is_some_and(|value| !valid_nonce(value)) {
            return Err(OutboundDpopError::InvalidNonceHeader);
        }
        let htu = canonical_dpop_target_with_policy(target, allow_insecure_loopback)?;
        let ath = access_token.map(|token| {
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                Sha256::digest(token.expose_secret().as_bytes()),
            )
        });
        let claims = DpopProofClaims {
            htu: &htu,
            htm: method.as_str(),
            jti: Uuid::new_v4().to_string(),
            iat,
            ath: ath.as_deref(),
            nonce,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(self.public_jwk.jwk.clone());
        let compact = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|_| OutboundDpopError::ProofConstruction)?;
        Ok(OutboundDpopProof(SecretString::new(compact)))
    }

    fn token_endpoint_proof_with_policy(
        &self,
        endpoint: &Url,
        nonce: Option<&str>,
        allow_insecure_loopback: bool,
    ) -> Result<OutboundDpopProof, OutboundDpopError> {
        self.proof(Method::POST, endpoint, None, nonce, allow_insecure_loopback)
    }

    fn resource_proof_with_policy(
        &self,
        method: Method,
        target: &Url,
        access_token: &SecretString,
        nonce: Option<&str>,
        allow_insecure_loopback: bool,
    ) -> Result<OutboundDpopProof, OutboundDpopError> {
        self.proof(
            method,
            target,
            Some(access_token),
            nonce,
            allow_insecure_loopback,
        )
    }
}

#[derive(Serialize)]
struct DpopProofClaims<'a> {
    htu: &'a str,
    htm: &'a str,
    jti: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

/// Compact outbound DPoP proof with redacted diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboundDpopProof(SecretString);

impl fmt::Debug for OutboundDpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OutboundDpopProof(<redacted>)")
    }
}

impl OutboundDpopProof {
    /// Returns the compact proof for the `DPoP` request header.
    ///
    /// # Security
    /// The returned value is request authentication material. Expose it only at
    /// the HTTP boundary and never log it.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Canonicalizes an HTTP target for an RFC 9449 `htu` claim.
///
/// # Errors
/// Returns [`OutboundDpopError::InvalidUrl`] for non-HTTP(S) URLs.
///
/// # Security
/// Removes user information, query, and fragment components before the target
/// is signed. The public default requires HTTPS.
pub fn canonical_dpop_target(target: &Url) -> Result<String, OutboundDpopError> {
    canonical_dpop_target_with_policy(target, false)
}

fn canonical_dpop_target_with_policy(
    target: &Url,
    allow_insecure_loopback: bool,
) -> Result<String, OutboundDpopError> {
    validate_http_url(target, allow_insecure_loopback)?;
    let mut canonical = target.clone();
    canonical
        .set_username("")
        .map_err(|_| OutboundDpopError::InvalidUrl)?;
    canonical
        .set_password(None)
        .map_err(|_| OutboundDpopError::InvalidUrl)?;
    canonical.set_query(None);
    canonical.set_fragment(None);
    Ok(canonical.to_string())
}

fn redacted_resource_for_debug(value: &str) -> String {
    let Ok(mut resource) = Url::parse(value) else {
        return "<invalid-resource>".to_string();
    };
    if resource.set_username("").is_err() || resource.set_password(None).is_err() {
        return "<invalid-resource>".to_string();
    }
    let query_was_present = resource.query().is_some();
    resource.set_query(None);
    if query_was_present {
        format!("{resource}?<redacted>")
    } else {
        resource.to_string()
    }
}

/// Mandatory audit identity accompanying one token exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenExchangeAuditMetadata {
    exchange_id: String,
    audit_subject: String,
    audit_actor_client: String,
}

impl fmt::Debug for TokenExchangeAuditMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenExchangeAuditMetadata")
            .field("exchange_id_present", &true)
            .field("audit_subject_present", &true)
            .field("audit_actor_client_present", &true)
            .finish()
    }
}

impl TokenExchangeAuditMetadata {
    /// Builds mandatory exchange audit metadata.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] when any value is blank.
    ///
    /// # Security
    /// These values are not sent to the authorization server. Callers must bind
    /// them to their policy decision and audit record before invoking exchange.
    pub fn new(
        exchange_id: impl Into<String>,
        audit_subject: impl Into<String>,
        audit_actor_client: impl Into<String>,
    ) -> Result<Self, OutboundDpopError> {
        let exchange_id = required_field(exchange_id, "exchange_id")?;
        let audit_subject = required_field(audit_subject, "audit_subject")?;
        let audit_actor_client = required_field(audit_actor_client, "audit_actor_client")?;
        Ok(Self {
            exchange_id,
            audit_subject,
            audit_actor_client,
        })
    }

    /// Returns the caller-owned exchange correlation id.
    pub fn exchange_id(&self) -> &str {
        &self.exchange_id
    }

    /// Returns the policy-bound audit subject.
    pub fn audit_subject(&self) -> &str {
        &self.audit_subject
    }

    /// Returns the policy-bound actor client.
    pub fn audit_actor_client(&self) -> &str {
        &self.audit_actor_client
    }
}

/// A bearer access token accepted as an RFC 8693 subject.
///
/// This explicit type prevents an arbitrary secret (including a
/// sender-constrained token) from being silently labelled as a bearer subject.
/// Provider-specific sender-constrained subject tokens are intentionally not
/// supported by this bounded client.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerSubjectToken(SecretString);

impl fmt::Debug for BearerSubjectToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerSubjectToken(<redacted>)")
    }
}

impl BearerSubjectToken {
    /// Wraps one non-empty bearer token for an RFC 8693 exchange.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] for blank, oversized, or
    /// control-character-bearing values.
    pub fn new(subject_token: SecretString) -> Result<Self, OutboundDpopError> {
        if !valid_credential(subject_token.expose_secret()) {
            return Err(OutboundDpopError::InvalidField("subject_token"));
        }
        Ok(Self(subject_token))
    }

    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Typed RFC 8693 token-exchange request.
#[derive(Clone)]
pub struct Rfc8693TokenExchangeRequest {
    subject_token: BearerSubjectToken,
    resources: Vec<String>,
    audiences: Vec<String>,
    scopes: Vec<String>,
    audit: TokenExchangeAuditMetadata,
}

impl fmt::Debug for Rfc8693TokenExchangeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rfc8693TokenExchangeRequest")
            .field("subject_token", &"<redacted>")
            .field("subject_token_type", &RFC8693_ACCESS_TOKEN_TYPE)
            .field("requested_token_type", &RFC8693_ACCESS_TOKEN_TYPE)
            .field(
                "resources",
                &self
                    .resources
                    .iter()
                    .map(|value| redacted_resource_for_debug(value))
                    .collect::<Vec<_>>(),
            )
            .field("audiences", &self.audiences)
            .field("scopes", &self.scopes)
            .field("audit", &self.audit)
            .finish()
    }
}

impl Rfc8693TokenExchangeRequest {
    /// Builds a bearer-subject access-token-for-access-token exchange request.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] for a blank subject token.
    ///
    /// # Security
    /// Mandatory audit metadata makes an unaudited exchange request
    /// unrepresentable. The subject token is redacted from formatted output.
    /// Sender-constrained subject tokens are not accepted by this API.
    pub fn new(
        subject_token: BearerSubjectToken,
        audit: TokenExchangeAuditMetadata,
    ) -> Result<Self, OutboundDpopError> {
        Ok(Self {
            subject_token,
            resources: Vec::new(),
            audiences: Vec::new(),
            scopes: Vec::new(),
            audit,
        })
    }

    /// Adds one caller-authorized RFC 8707 resource indicator.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] when the value is not an
    /// absolute, fragment-free URI.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Result<Self, OutboundDpopError> {
        if self.resources.len() >= MAX_REQUEST_ITEMS {
            return Err(OutboundDpopError::InvalidField("resource"));
        }
        let resource = required_field(resource, "resource")?;
        let parsed =
            Url::parse(&resource).map_err(|_| OutboundDpopError::InvalidField("resource"))?;
        if parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(OutboundDpopError::InvalidField("resource"));
        }
        self.resources.push(resource);
        Ok(self)
    }

    /// Adds one caller-authorized target audience.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] when the value is blank.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Result<Self, OutboundDpopError> {
        if self.audiences.len() >= MAX_REQUEST_ITEMS {
            return Err(OutboundDpopError::InvalidField("audience"));
        }
        self.audiences.push(required_field(audience, "audience")?);
        Ok(self)
    }

    /// Sets the caller-authorized scope set.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] for blank or duplicated scopes.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Result<Self, OutboundDpopError> {
        if scopes.len() > MAX_REQUEST_ITEMS {
            return Err(OutboundDpopError::InvalidField("scopes"));
        }
        let mut unique = HashSet::new();
        for scope in &scopes {
            if !valid_scope_token(scope) || !unique.insert(scope.as_str()) {
                return Err(OutboundDpopError::InvalidField("scopes"));
            }
        }
        self.scopes = scopes;
        Ok(self)
    }

    /// Returns the mandatory audit metadata for policy/audit projection.
    pub fn audit(&self) -> &TokenExchangeAuditMetadata {
        &self.audit
    }

    fn form(&self) -> Vec<(&'static str, String)> {
        let mut form = vec![
            ("grant_type", RFC8693_GRANT_TYPE.to_string()),
            (
                "subject_token",
                self.subject_token.expose_secret().to_string(),
            ),
            ("subject_token_type", RFC8693_ACCESS_TOKEN_TYPE.to_string()),
            (
                "requested_token_type",
                RFC8693_ACCESS_TOKEN_TYPE.to_string(),
            ),
        ];
        form.extend(
            self.resources
                .iter()
                .cloned()
                .map(|value| ("resource", value)),
        );
        form.extend(
            self.audiences
                .iter()
                .cloned()
                .map(|value| ("audience", value)),
        );
        if !self.scopes.is_empty() {
            form.push(("scope", self.scopes.join(" ")));
        }
        form
    }
}

/// Configuration for a DPoP-bound RFC 8693 token-exchange client.
#[derive(Clone)]
pub struct DpopTokenExchangeConfig {
    token_endpoint: Url,
    client_id: String,
    client_secret: Option<SecretString>,
    client_auth_method: OAuthClientAuthMethod,
    timeout: Duration,
    allow_insecure_loopback: bool,
}

impl fmt::Debug for DpopTokenExchangeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopTokenExchangeConfig")
            .field("token_endpoint", &self.token_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret_present", &self.client_secret.is_some())
            .field("client_auth_method", &self.client_auth_method)
            .field("timeout", &self.timeout)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .finish()
    }
}

impl DpopTokenExchangeConfig {
    /// Builds a production token-exchange configuration.
    ///
    /// # Errors
    /// Returns field, URL, or HTTPS enforcement failures.
    ///
    /// # Security
    /// The exact endpoint must be covered by the caller's explicit trust policy.
    /// This prevents an arbitrary HTTPS URL from becoming a credential sink.
    pub fn new(
        token_endpoint: Url,
        endpoint_policy: DpopEndpointPolicy,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
    ) -> Result<Self, OutboundDpopError> {
        Self::build(token_endpoint, endpoint_policy, client_id, client_secret)
    }

    fn build(
        token_endpoint: Url,
        endpoint_policy: DpopEndpointPolicy,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
    ) -> Result<Self, OutboundDpopError> {
        validate_endpoint_shape(&token_endpoint)?;
        validate_http_url(&token_endpoint, endpoint_policy.allow_insecure_loopback)?;
        if !endpoint_policy.matches(&token_endpoint) {
            return Err(OutboundDpopError::UntrustedEndpoint);
        }
        let client_id = required_field(client_id, "client_id")?;
        if client_secret
            .as_ref()
            .is_some_and(|value| !valid_credential(value.expose_secret()))
        {
            return Err(OutboundDpopError::InvalidField("client_secret"));
        }
        Ok(Self {
            token_endpoint,
            client_id,
            client_secret,
            client_auth_method: OAuthClientAuthMethod::RequestBody,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            allow_insecure_loopback: endpoint_policy.allow_insecure_loopback,
        })
    }

    /// Selects request-body or HTTP Basic client authentication.
    pub fn with_client_auth_method(mut self, method: OAuthClientAuthMethod) -> Self {
        self.client_auth_method = method;
        self
    }

    /// Sets the complete token-endpoint request timeout.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] for a zero timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, OutboundDpopError> {
        if timeout.is_zero() {
            return Err(OutboundDpopError::InvalidField("timeout"));
        }
        self.timeout = timeout;
        Ok(self)
    }
}

/// Shared, bounded nonce state with isolated token and resource namespaces.
#[derive(Clone)]
pub struct DpopNonceState {
    inner: Arc<Mutex<NonceStateInner>>,
    token_endpoint_capacity: usize,
    resource_capacity: usize,
}

#[derive(Default)]
struct NonceStateInner {
    token_endpoints: HashMap<String, String>,
    resources: HashMap<ResourceNonceKey, String>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ResourceNonceKey {
    method: Method,
    target: String,
}

impl Default for DpopNonceState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NonceStateInner::default())),
            token_endpoint_capacity: DEFAULT_TOKEN_ENDPOINT_NONCE_CAPACITY,
            resource_capacity: DEFAULT_RESOURCE_NONCE_CAPACITY,
        }
    }
}

impl fmt::Debug for DpopNonceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (token_endpoint_nonce_count, resource_nonce_count) = self
            .inner
            .lock()
            .map(|state| (state.token_endpoints.len(), state.resources.len()))
            .unwrap_or((0, 0));
        formatter
            .debug_struct("DpopNonceState")
            .field("token_endpoint_nonce_count", &token_endpoint_nonce_count)
            .field("resource_nonce_count", &resource_nonce_count)
            .field("token_endpoint_capacity", &self.token_endpoint_capacity)
            .field("resource_capacity", &self.resource_capacity)
            .finish()
    }
}

impl DpopNonceState {
    /// Builds nonce state with a bounded number of method/resource entries.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] for zero capacity.
    pub fn with_resource_capacity(capacity: usize) -> Result<Self, OutboundDpopError> {
        if capacity == 0 {
            return Err(OutboundDpopError::InvalidField("resource_nonce_capacity"));
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(NonceStateInner::default())),
            token_endpoint_capacity: DEFAULT_TOKEN_ENDPOINT_NONCE_CAPACITY,
            resource_capacity: capacity,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, NonceStateInner>, OutboundDpopError> {
        self.inner
            .lock()
            .map_err(|_| OutboundDpopError::NonceStateUnavailable)
    }

    fn token_endpoint_nonce(&self, endpoint: &str) -> Result<Option<String>, OutboundDpopError> {
        Ok(self.lock()?.token_endpoints.get(endpoint).cloned())
    }

    fn set_token_endpoint_nonce(
        &self,
        endpoint: String,
        nonce: String,
    ) -> Result<(), OutboundDpopError> {
        let mut state = self.lock()?;
        if !state.token_endpoints.contains_key(&endpoint)
            && state.token_endpoints.len() >= self.token_endpoint_capacity
        {
            return Err(OutboundDpopError::TokenEndpointNonceCapacityExceeded);
        }
        state.token_endpoints.insert(endpoint, nonce);
        Ok(())
    }

    fn resource_nonce(&self, key: &ResourceNonceKey) -> Result<Option<String>, OutboundDpopError> {
        Ok(self.lock()?.resources.get(key).cloned())
    }

    fn set_resource_nonce(
        &self,
        key: ResourceNonceKey,
        nonce: String,
    ) -> Result<(), OutboundDpopError> {
        let mut state = self.lock()?;
        if !state.resources.contains_key(&key) && state.resources.len() >= self.resource_capacity {
            return Err(OutboundDpopError::ResourceNonceCapacityExceeded);
        }
        state.resources.insert(key, nonce);
        Ok(())
    }
}

/// Reusable DPoP-bound RFC 8693 client.
#[derive(Clone)]
pub struct DpopTokenExchangeClient {
    config: DpopTokenExchangeConfig,
    token_endpoint_key: String,
    signer: DpopSigner,
    nonces: DpopNonceState,
    http: Client,
}

impl fmt::Debug for DpopTokenExchangeClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopTokenExchangeClient")
            .field("config", &self.config)
            .field("token_endpoint_key", &self.token_endpoint_key)
            .field("signer", &self.signer)
            .field("nonces", &self.nonces)
            .finish_non_exhaustive()
    }
}

impl DpopTokenExchangeClient {
    /// Builds a no-redirect token-exchange client with isolated nonce state.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::HttpClientInitialization`] when the HTTP
    /// client cannot be constructed.
    ///
    /// # Security
    /// The client never follows token-endpoint redirects.
    pub fn new(
        config: DpopTokenExchangeConfig,
        signer: DpopSigner,
    ) -> Result<Self, OutboundDpopError> {
        Self::with_nonce_state(config, signer, DpopNonceState::default())
    }

    /// Builds a client with caller-supplied bounded nonce state.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::HttpClientInitialization`] when the HTTP
    /// client cannot be constructed.
    ///
    /// # Security
    /// Share nonce state only between requests using the same signer and trust
    /// boundary. Redirects and ambient proxy discovery remain disabled.
    pub fn with_nonce_state(
        config: DpopTokenExchangeConfig,
        signer: DpopSigner,
        nonces: DpopNonceState,
    ) -> Result<Self, OutboundDpopError> {
        let token_endpoint_key = canonical_dpop_target_with_policy(
            &config.token_endpoint,
            config.allow_insecure_loopback,
        )?;
        let http = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .build()
            .map_err(|_| OutboundDpopError::HttpClientInitialization)?;
        Ok(Self {
            config,
            token_endpoint_key,
            signer,
            nonces,
            http,
        })
    }

    /// Returns this client's public proof key and confirmation thumbprint.
    pub fn public_jwk(&self) -> &DpopPublicJwk {
        self.signer.public_jwk()
    }

    /// Executes one RFC 8693 exchange with at most one eligible nonce retry.
    ///
    /// # Errors
    /// Returns transport, nonce, endpoint, response-shape, scope, or token-type
    /// failures. A repeated nonce challenge returns
    /// [`OutboundDpopError::NonceRetryLimitReached`].
    ///
    /// # Security
    /// The caller must authorize and audit the requested audience, resources,
    /// and scopes before invoking this method. The response must explicitly use
    /// token type `DPoP`; Bearer and missing token types fail closed. The result
    /// is [`DpopAccessToken`], which remains unverified until the caller supplies
    /// provider-backed binding metadata to [`Self::validate_provider_binding`].
    pub async fn exchange(
        &self,
        request: &Rfc8693TokenExchangeRequest,
    ) -> Result<DpopAccessToken, OutboundDpopError> {
        let mut nonce_override: Option<String> = None;
        for attempt in 0..=1 {
            let nonce = match nonce_override.as_ref() {
                Some(value) => Some(value.clone()),
                None => self.nonces.token_endpoint_nonce(&self.token_endpoint_key)?,
            };
            let proof = self.signer.token_endpoint_proof_with_policy(
                &self.config.token_endpoint,
                nonce.as_deref(),
                self.config.allow_insecure_loopback,
            )?;
            let response = self.send_exchange(request, &proof).await?;
            let status = response.status();
            let headers = response.headers().clone();
            let nonce_header = strict_nonce_header(&headers)?;
            if let Some(nonce) = nonce_header.as_ref() {
                self.nonces
                    .set_token_endpoint_nonce(self.token_endpoint_key.clone(), nonce.clone())?;
            }
            if status == StatusCode::OK && !has_strict_json_content_type(&headers) {
                return Err(OutboundDpopError::UnexpectedResponseContentType);
            }
            let body = read_bounded_body(response, MAX_TOKEN_RESPONSE_BYTES).await?;
            if status == StatusCode::OK {
                return self.validate_success(request, &body);
            }

            let oauth_error = parse_oauth_error(&body);
            let eligible_nonce_challenge =
                matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED)
                    && oauth_error.as_deref() == Some("use_dpop_nonce")
                    && nonce_header.is_some();
            if eligible_nonce_challenge {
                if attempt == 1 {
                    return Err(OutboundDpopError::NonceRetryLimitReached);
                }
                nonce_override = nonce_header;
                continue;
            }
            return Err(OutboundDpopError::TokenEndpointRejected {
                status,
                code: SafeOAuthErrorCode::from_untrusted(oauth_error.as_deref()),
            });
        }
        Err(OutboundDpopError::NonceRetryLimitReached)
    }

    async fn send_exchange(
        &self,
        request: &Rfc8693TokenExchangeRequest,
        proof: &OutboundDpopProof,
    ) -> Result<reqwest::Response, OutboundDpopError> {
        let mut proof_header = HeaderValue::from_str(proof.expose_secret())
            .map_err(|_| OutboundDpopError::InvalidCredentialHeader)?;
        proof_header.set_sensitive(true);
        let mut form = request.form();
        let mut builder = self
            .http
            .post(self.config.token_endpoint.clone())
            .header("DPoP", proof_header);
        match self.config.client_auth_method {
            OAuthClientAuthMethod::RequestBody => {
                form.push(("client_id", self.config.client_id.clone()));
                if let Some(secret) = self.config.client_secret.as_ref() {
                    form.push(("client_secret", secret.expose_secret().to_string()));
                }
            }
            OAuthClientAuthMethod::Basic => {
                builder = builder.basic_auth(
                    &self.config.client_id,
                    self.config
                        .client_secret
                        .as_ref()
                        .map(SecretString::expose_secret),
                );
            }
        }
        builder
            .form(&form)
            .send()
            .await
            .map_err(|error| OutboundDpopError::Http(classify_http_error(&error)))
    }

    fn validate_success(
        &self,
        request: &Rfc8693TokenExchangeRequest,
        body: &[u8],
    ) -> Result<DpopAccessToken, OutboundDpopError> {
        let raw: RawTokenExchangeResponse =
            serde_json::from_slice(body).map_err(|_| OutboundDpopError::MalformedTokenResponse)?;
        if raw.refresh_token.is_some() {
            return Err(OutboundDpopError::UnexpectedRefreshToken);
        }
        let access_token = raw
            .access_token
            .filter(|value| !value.trim().is_empty())
            .ok_or(OutboundDpopError::MissingAccessToken)?;
        if !raw
            .token_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("dpop"))
        {
            return Err(OutboundDpopError::UnexpectedTokenType);
        }
        let issued_token_type = raw
            .issued_token_type
            .ok_or(OutboundDpopError::UnexpectedIssuedTokenType)?;
        if issued_token_type != RFC8693_ACCESS_TOKEN_TYPE {
            return Err(OutboundDpopError::UnexpectedIssuedTokenType);
        }
        let scope = match raw.scope {
            Some(scope) => {
                if !valid_scope_list(&scope) {
                    return Err(OutboundDpopError::MalformedTokenResponse);
                }
                let requested: HashSet<&str> = request.scopes.iter().map(String::as_str).collect();
                if scope.split(' ').any(|granted| !requested.contains(granted)) {
                    return Err(OutboundDpopError::BroadenedScopes);
                }
                Some(scope)
            }
            None if request.scopes.is_empty() => None,
            None => Some(request.scopes.join(" ")),
        };
        Ok(DpopAccessToken {
            access_token: SecretString::new(access_token),
            expires_in: raw.expires_in,
            scope,
        })
    }

    /// Validates provider-backed DPoP binding metadata for an exchange result.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::ProviderBindingMismatch`] when the
    /// token-hash or `cnf.jkt` does not match, or
    /// [`OutboundDpopError::ProviderBindingExpired`] when metadata has expired.
    ///
    /// # Security
    /// `token_type=DPoP` is not treated as proof of sender binding, audience, or
    /// TTL. The metadata must come from a trusted provider validation path;
    /// this method performs only local consistency and freshness checks.
    pub fn validate_provider_binding(
        &self,
        token: &DpopAccessToken,
        metadata: DpopProviderValidationMetadata,
    ) -> Result<DpopBoundAccessToken, OutboundDpopError> {
        if metadata.access_token_hash != token.access_token_hash()
            || metadata.cnf_jkt != self.signer.public_jwk.thumbprint
        {
            return Err(OutboundDpopError::ProviderBindingMismatch);
        }
        if metadata.expires_at <= SystemTime::now() {
            return Err(OutboundDpopError::ProviderBindingExpired);
        }
        Ok(DpopBoundAccessToken {
            access_token: token.access_token.clone(),
            expires_in: token.expires_in,
            scope: token.scope.clone(),
            proof_thumbprint: metadata.cnf_jkt,
            audience: metadata.audience,
            expires_at: metadata.expires_at,
            provider: metadata.provider,
        })
    }

    /// Starts one resource authorization attempt bound to this client's signer
    /// and an explicit exact target policy.
    ///
    /// # Errors
    /// Returns URL, trust-policy, or signer-binding failures.
    ///
    /// # Security
    /// The returned transaction permits at most one 401 nonce retry.
    pub fn resource_request<'a>(
        &'a self,
        token: &'a DpopBoundAccessToken,
        method: Method,
        target: Url,
        target_policy: &DpopEndpointPolicy,
    ) -> Result<DpopResourceRequest<'a>, OutboundDpopError> {
        if token.proof_thumbprint != self.signer.public_jwk.thumbprint {
            return Err(OutboundDpopError::SignerMismatch);
        }
        if !target_policy.matches_resource(&target)? {
            return Err(OutboundDpopError::UntrustedEndpoint);
        }
        let canonical_target =
            canonical_dpop_target_with_policy(&target, self.config.allow_insecure_loopback)?;
        let nonce_method = method.clone();
        Ok(DpopResourceRequest {
            client: self,
            token,
            method,
            target,
            nonce_key: ResourceNonceKey {
                method: nonce_method,
                target: canonical_target,
            },
            nonce_retry_used: false,
        })
    }
}

/// Access token returned by an RFC 8693 exchange, pending provider validation.
///
/// This type intentionally has no resource-request capability. A successful
/// response's `token_type=DPoP` does not prove `cnf.jkt`, audience, or TTL.
#[derive(Clone)]
pub struct DpopAccessToken {
    access_token: SecretString,
    expires_in: Option<u64>,
    scope: Option<String>,
}

impl fmt::Debug for DpopAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopAccessToken")
            .field("access_token", &"<redacted>")
            .field("issued_token_type", &RFC8693_ACCESS_TOKEN_TYPE)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

impl DpopAccessToken {
    /// Returns the secret access token for request authorization.
    ///
    /// # Security
    /// Expose the value only at the HTTP boundary and never log it.
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Returns the validated RFC 8693 issued-token type.
    pub fn issued_token_type(&self) -> &str {
        RFC8693_ACCESS_TOKEN_TYPE
    }

    /// Returns the token lifetime in seconds when supplied.
    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }

    /// Returns the granted scope string when supplied.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Returns the SHA-256 access-token hash for provider metadata binding.
    ///
    /// This is a non-secret fingerprint and is safe to compare with an
    /// introspection result, but it is not itself proof that the provider
    /// validated the token.
    pub fn access_token_hash(&self) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(self.access_token.expose_secret().as_bytes()),
        )
    }
}

/// Provider-backed validation metadata required before a token is treated as
/// sender-constrained.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopProviderValidationMetadata {
    provider: String,
    access_token_hash: String,
    cnf_jkt: String,
    audience: String,
    expires_at: SystemTime,
}

impl fmt::Debug for DpopProviderValidationMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopProviderValidationMetadata")
            .field("provider", &self.provider)
            .field("access_token_hash", &self.access_token_hash)
            .field("cnf_jkt", &self.cnf_jkt)
            .field("audience", &self.audience)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl DpopProviderValidationMetadata {
    /// Creates metadata produced by a provider validation/introspection path.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] for blank values and
    /// [`OutboundDpopError::ProviderBindingExpired`] for an expired lifetime.
    ///
    /// # Security
    /// This records an assertion supplied by a trusted provider integration; it
    /// does not perform provider I/O or JWT parsing.
    pub fn from_provider(
        provider: impl Into<String>,
        access_token_hash: impl Into<String>,
        cnf_jkt: impl Into<String>,
        audience: impl Into<String>,
        expires_at: SystemTime,
    ) -> Result<Self, OutboundDpopError> {
        let provider = required_field(provider, "provider")?;
        let access_token_hash = required_field(access_token_hash, "access_token_hash")?;
        let cnf_jkt = required_field(cnf_jkt, "cnf_jkt")?;
        let audience = required_field(audience, "audience")?;
        if expires_at <= SystemTime::now() {
            return Err(OutboundDpopError::ProviderBindingExpired);
        }
        Ok(Self {
            provider,
            access_token_hash,
            cnf_jkt,
            audience,
            expires_at,
        })
    }

    /// Returns the provider identity recorded with the validation assertion.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the provider-validated audience.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Returns the provider-validated expiry instant.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

/// DPoP-bound access token produced only after provider metadata validation.
#[derive(Clone)]
pub struct DpopBoundAccessToken {
    access_token: SecretString,
    expires_in: Option<u64>,
    scope: Option<String>,
    proof_thumbprint: String,
    audience: String,
    expires_at: SystemTime,
    provider: String,
}

impl fmt::Debug for DpopBoundAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopBoundAccessToken")
            .field("access_token", &"<redacted>")
            .field("issued_token_type", &RFC8693_ACCESS_TOKEN_TYPE)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("proof_thumbprint", &self.proof_thumbprint)
            .field("audience", &self.audience)
            .field("expires_at", &self.expires_at)
            .field("provider", &self.provider)
            .finish()
    }
}

impl DpopBoundAccessToken {
    /// Returns the secret access token for request authorization.
    ///
    /// # Security
    /// Expose the value only at the HTTP boundary and never log it.
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Returns the validated RFC 8693 issued-token type.
    pub fn issued_token_type(&self) -> &str {
        RFC8693_ACCESS_TOKEN_TYPE
    }

    /// Returns the token lifetime in seconds when supplied by the endpoint.
    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }

    /// Returns the granted scope string when supplied.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Returns the provider-validated proof-key thumbprint.
    pub fn proof_thumbprint(&self) -> &str {
        &self.proof_thumbprint
    }

    /// Returns the provider-validated audience.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Returns the provider-validated expiry instant.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Returns the provider identity that supplied the binding assertion.
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

/// One resource request transaction with a one-retry nonce budget.
pub struct DpopResourceRequest<'a> {
    client: &'a DpopTokenExchangeClient,
    token: &'a DpopBoundAccessToken,
    method: Method,
    target: Url,
    nonce_key: ResourceNonceKey,
    nonce_retry_used: bool,
}

impl fmt::Debug for DpopResourceRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopResourceRequest")
            .field("method", &self.method)
            .field("target", &self.nonce_key.target)
            .field("access_token", &"<redacted>")
            .field("nonce_retry_used", &self.nonce_retry_used)
            .finish()
    }
}

impl DpopResourceRequest<'_> {
    /// Constructs the current DPoP authorization headers for this transaction.
    ///
    /// # Errors
    /// Returns nonce-state, proof, or credential-header failures.
    ///
    /// # Security
    /// The returned headers contain credentials and redact formatted output.
    pub fn authorization(&self) -> Result<DpopAuthorization, OutboundDpopError> {
        let nonce = self.client.nonces.resource_nonce(&self.nonce_key)?;
        let proof = self.client.signer.resource_proof_with_policy(
            self.method.clone(),
            &self.target,
            &self.token.access_token,
            nonce.as_deref(),
            self.client.config.allow_insecure_loopback,
        )?;
        DpopAuthorization::new(
            &self.token.access_token,
            proof,
            &self.method,
            &self.target,
            self.client.config.allow_insecure_loopback,
        )
    }

    /// Records a successful-response nonce for the next request.
    ///
    /// # Errors
    /// Returns malformed-header, capacity, or nonce-state failures.
    pub fn observe_response_nonce(&self, headers: &HeaderMap) -> Result<bool, OutboundDpopError> {
        let Some(nonce) = strict_nonce_header(headers)? else {
            return Ok(false);
        };
        self.client
            .nonces
            .set_resource_nonce(self.nonce_key.clone(), nonce)?;
        Ok(true)
    }

    /// Accepts one eligible resource-server nonce challenge.
    ///
    /// # Errors
    /// Returns malformed-header, capacity, nonce-state, or retry-limit failures.
    ///
    /// # Security
    /// Only a `401 Unauthorized` response carrying one valid `DPoP-Nonce`
    /// header is eligible, and each transaction can accept it once.
    pub fn accept_nonce_challenge(
        &mut self,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Result<bool, OutboundDpopError> {
        if status != StatusCode::UNAUTHORIZED {
            return Ok(false);
        }
        let Some(nonce) = strict_nonce_header(headers)? else {
            return Ok(false);
        };
        if self.nonce_retry_used {
            return Err(OutboundDpopError::NonceRetryLimitReached);
        }
        self.client
            .nonces
            .set_resource_nonce(self.nonce_key.clone(), nonce)?;
        self.nonce_retry_used = true;
        Ok(true)
    }
}

/// Secret-bearing `Authorization` and `DPoP` request headers.
pub struct DpopAuthorization {
    authorization: HeaderValue,
    proof: HeaderValue,
    method: Method,
    canonical_target: String,
    allow_insecure_loopback: bool,
}

impl fmt::Debug for DpopAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopAuthorization(<redacted>)")
    }
}

impl DpopAuthorization {
    fn new(
        access_token: &SecretString,
        proof: OutboundDpopProof,
        method: &Method,
        target: &Url,
        allow_insecure_loopback: bool,
    ) -> Result<Self, OutboundDpopError> {
        let mut authorization =
            HeaderValue::from_str(&format!("DPoP {}", access_token.expose_secret()))
            .map_err(|_| OutboundDpopError::InvalidCredentialHeader)?;
        authorization.set_sensitive(true);
        let mut proof = HeaderValue::from_str(proof.expose_secret())
            .map_err(|_| OutboundDpopError::InvalidCredentialHeader)?;
        proof.set_sensitive(true);
        Ok(Self {
            authorization,
            proof,
            method: method.clone(),
            canonical_target: canonical_dpop_target_with_policy(target, allow_insecure_loopback)?,
            allow_insecure_loopback,
        })
    }

    /// Applies the DPoP authorization to a matching reqwest request builder.
    ///
    /// Building the request is part of this operation so the method and URL can
    /// be checked before credential-bearing headers are attached. The caller
    /// must use the returned request for the dispatch; applying these headers to
    /// a different target is rejected.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::UntrustedEndpoint`] when the builder's
    /// method or canonical target differs from the transaction that produced
    /// this authorization, or [`OutboundDpopError::Http`] when the builder
    /// cannot be materialized.
    ///
    /// # Security
    /// Both headers are marked sensitive. Do not add middleware that logs raw
    /// request headers before reqwest's sensitivity metadata is honored.
    pub fn apply(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Request, OutboundDpopError> {
        let mut request = builder
            .build()
            .map_err(|_| OutboundDpopError::Http(HttpFailureKind::Request))?;
        if !request.url().username().is_empty()
            || request.url().password().is_some()
            || request.url().fragment().is_some()
        {
            return Err(OutboundDpopError::UntrustedEndpoint);
        }
        let request_target = canonical_dpop_target_with_policy(
            request.url(),
            self.allow_insecure_loopback,
        )?;
        if request.method() != &self.method || request_target != self.canonical_target {
            return Err(OutboundDpopError::UntrustedEndpoint);
        }
        let headers = request.headers_mut();
        headers.insert(http::header::AUTHORIZATION, self.authorization.clone());
        headers.insert(http::header::HeaderName::from_static("dpop"), self.proof.clone());
        Ok(request)
    }
}

#[derive(Deserialize)]
struct RawTokenExchangeResponse {
    access_token: Option<String>,
    issued_token_type: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct RawOAuthError {
    error: Option<String>,
}

fn parse_oauth_error(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<RawOAuthError>(body)
        .ok()
        .and_then(|error| error.error)
}

async fn read_bounded_body(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, OutboundDpopError> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    loop {
        let next_chunk = stream.next().await;
        let Some(chunk) = next_chunk else {
            break;
        };
        let chunk = chunk.map_err(|error| {
            OutboundDpopError::Http(if error.is_timeout() {
                HttpFailureKind::Timeout
            } else {
                HttpFailureKind::ResponseBody
            })
        })?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(OutboundDpopError::ResponseTooLarge { max_bytes });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn classify_http_error(error: &reqwest::Error) -> HttpFailureKind {
    if error.is_timeout() {
        HttpFailureKind::Timeout
    } else if error.is_connect() {
        HttpFailureKind::Connect
    } else if error.is_request() {
        HttpFailureKind::Request
    } else if error.is_body() || error.is_decode() {
        HttpFailureKind::ResponseBody
    } else {
        HttpFailureKind::Other
    }
}

fn strict_nonce_header(headers: &HeaderMap) -> Result<Option<String>, OutboundDpopError> {
    let mut values = headers.get_all("dpop-nonce").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(OutboundDpopError::InvalidNonceHeader);
    }
    let value = value
        .to_str()
        .map_err(|_| OutboundDpopError::InvalidNonceHeader)?;
    if !valid_nonce(value) {
        return Err(OutboundDpopError::InvalidNonceHeader);
    }
    Ok(Some(value.to_string()))
}

fn has_strict_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(http::header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().ok().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

fn valid_nonce(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_NONCE_BYTES {
        return false;
    }
    let core_len = value
        .bytes()
        .position(|byte| byte == b'=')
        .unwrap_or(value.len());
    core_len > 0
        && value.as_bytes()[..core_len].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && value.as_bytes()[core_len..]
            .iter()
            .all(|byte| *byte == b'=')
}

fn required_field(
    value: impl Into<String>,
    field: &'static str,
) -> Result<String, OutboundDpopError> {
    let value = value.into();
    if value.trim().is_empty()
        || value.len() > MAX_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OutboundDpopError::InvalidField(field));
    }
    Ok(value)
}

fn valid_credential(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FIELD_BYTES
        && value.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        })
}

fn valid_scope_list(value: &str) -> bool {
    !value.is_empty() && value.split(' ').all(valid_scope_token)
}

fn validate_endpoint_shape(url: &Url) -> Result<(), OutboundDpopError> {
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OutboundDpopError::InvalidUrl);
    }
    Ok(())
}

fn validate_http_url(url: &Url, allow_loopback_http: bool) -> Result<(), OutboundDpopError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_loopback_http && is_loopback_url(url) => Ok(()),
        "http" => Err(OutboundDpopError::InsecureEndpoint),
        _ => Err(OutboundDpopError::InvalidUrl),
    }
}

fn is_loopback_url(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        let numeric_host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        numeric_host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
    })
}

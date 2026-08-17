//! # Outbound DPoP Token Exchange
//!
//! Reusable RFC 9449 proof construction and RFC 8693 token-exchange transport
//! for service clients that need sender-constrained access tokens.
//!
//! ## Ownership
//! This module owns P-256 proof keys, canonical DPoP targets, nonce isolation,
//! bounded token-endpoint retries, typed exchange forms, and low-leakage
//! response validation.
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
//!     DpopSigner, DpopTokenExchangeClient, DpopTokenExchangeConfig,
//!     Rfc8693TokenExchangeRequest, TokenExchangeAuditMetadata,
//! };
//! use mcp_toolkit_auth::upstream_oauth::SecretString;
//! use reqwest::Url;
//!
//! # fn configure() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = DpopSigner::generate()?;
//! let config = DpopTokenExchangeConfig::new(
//!     Url::parse("https://issuer.example/oauth/token")?,
//!     "service-client",
//!     Some(SecretString::new("client-secret")),
//! )?;
//! let client = DpopTokenExchangeClient::new(config, signer)?;
//! let audit = TokenExchangeAuditMetadata::new("exchange-id", "subject", "service-client")?;
//! let request = Rfc8693TokenExchangeRequest::new(SecretString::new("subject-token"), audit)?
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
const DEFAULT_RESOURCE_NONCE_CAPACITY: usize = 256;

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
    /// A successful response was not valid RFC 8693 JSON.
    #[error("outbound DPoP token response is malformed")]
    MalformedTokenResponse,
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
            !candidate.is_empty()
                && candidate.len() <= 64
                && candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
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
        self.proof(Method::POST, endpoint, None, nonce)
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
        self.proof(method, target, Some(access_token), nonce)
    }

    fn proof(
        &self,
        method: Method,
        target: &Url,
        access_token: Option<&SecretString>,
        nonce: Option<&str>,
    ) -> Result<OutboundDpopProof, OutboundDpopError> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OutboundDpopError::ProofConstruction)?
            .as_secs();
        self.proof_at(method, target, access_token, nonce, iat, Uuid::new_v4())
    }

    fn proof_at(
        &self,
        method: Method,
        target: &Url,
        access_token: Option<&SecretString>,
        nonce: Option<&str>,
        iat: u64,
        jti: Uuid,
    ) -> Result<OutboundDpopProof, OutboundDpopError> {
        if nonce.is_some_and(|value| !valid_nonce(value)) {
            return Err(OutboundDpopError::InvalidNonceHeader);
        }
        let htu = canonical_dpop_target(target)?;
        let ath = access_token.map(|token| {
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                Sha256::digest(token.expose_secret().as_bytes()),
            )
        });
        let claims = DpopProofClaims {
            htu: &htu,
            htm: method.as_str(),
            jti: jti.to_string(),
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
/// is signed. HTTP is accepted only for loopback hosts.
pub fn canonical_dpop_target(target: &Url) -> Result<String, OutboundDpopError> {
    validate_http_url(target, true)?;
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

/// Typed RFC 8693 token-exchange request.
#[derive(Clone)]
pub struct Rfc8693TokenExchangeRequest {
    subject_token: SecretString,
    subject_token_type: String,
    requested_token_type: String,
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
            .field("subject_token_type", &self.subject_token_type)
            .field("requested_token_type", &self.requested_token_type)
            .field("resources", &self.resources)
            .field("audiences", &self.audiences)
            .field("scopes", &self.scopes)
            .field("audit", &self.audit)
            .finish()
    }
}

impl Rfc8693TokenExchangeRequest {
    /// Builds an access-token-for-access-token exchange request.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] for a blank subject token.
    ///
    /// # Security
    /// Mandatory audit metadata makes an unaudited exchange request
    /// unrepresentable. The subject token is redacted from formatted output.
    pub fn new(
        subject_token: SecretString,
        audit: TokenExchangeAuditMetadata,
    ) -> Result<Self, OutboundDpopError> {
        if !valid_credential(subject_token.expose_secret()) {
            return Err(OutboundDpopError::InvalidField("subject_token"));
        }
        Ok(Self {
            subject_token,
            subject_token_type: RFC8693_ACCESS_TOKEN_TYPE.to_string(),
            requested_token_type: RFC8693_ACCESS_TOKEN_TYPE.to_string(),
            resources: Vec::new(),
            audiences: Vec::new(),
            scopes: Vec::new(),
            audit,
        })
    }

    /// Sets the subject-token type.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] when the type is blank.
    pub fn with_subject_token_type(
        mut self,
        token_type: impl Into<String>,
    ) -> Result<Self, OutboundDpopError> {
        self.subject_token_type = required_field(token_type, "subject_token_type")?;
        Ok(self)
    }

    /// Sets the requested token type.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] when the type is blank.
    pub fn with_requested_token_type(
        mut self,
        token_type: impl Into<String>,
    ) -> Result<Self, OutboundDpopError> {
        self.requested_token_type = required_field(token_type, "requested_token_type")?;
        Ok(self)
    }

    /// Adds one caller-authorized RFC 8707 resource indicator.
    ///
    /// # Errors
    /// Returns [`OutboundDpopError::InvalidField`] when the value is blank.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Result<Self, OutboundDpopError> {
        if self.resources.len() >= MAX_REQUEST_ITEMS {
            return Err(OutboundDpopError::InvalidField("resource"));
        }
        self.resources.push(required_field(resource, "resource")?);
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
            ("subject_token_type", self.subject_token_type.clone()),
            ("requested_token_type", self.requested_token_type.clone()),
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
    /// Rejects redirects, URL credentials, fragments, and non-HTTPS endpoints.
    pub fn new(
        token_endpoint: Url,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
    ) -> Result<Self, OutboundDpopError> {
        Self::build(token_endpoint, client_id, client_secret, false)
    }

    /// Builds a token-exchange configuration permitting loopback HTTP.
    ///
    /// # Errors
    /// Returns field or URL validation failures.
    ///
    /// # Security
    /// Intended only for local emulators and tests; non-loopback HTTP remains
    /// rejected.
    pub fn new_allow_insecure_loopback(
        token_endpoint: Url,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
    ) -> Result<Self, OutboundDpopError> {
        Self::build(token_endpoint, client_id, client_secret, true)
    }

    fn build(
        token_endpoint: Url,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
        allow_loopback_http: bool,
    ) -> Result<Self, OutboundDpopError> {
        validate_http_url(&token_endpoint, allow_loopback_http)?;
        if !token_endpoint.username().is_empty()
            || token_endpoint.password().is_some()
            || token_endpoint.query().is_some()
            || token_endpoint.fragment().is_some()
        {
            return Err(OutboundDpopError::InvalidUrl);
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
    resource_capacity: usize,
}

#[derive(Default)]
struct NonceStateInner {
    token_endpoint: Option<String>,
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
            resource_capacity: DEFAULT_RESOURCE_NONCE_CAPACITY,
        }
    }
}

impl fmt::Debug for DpopNonceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (token_nonce_present, resource_nonce_count) = self
            .inner
            .lock()
            .map(|state| (state.token_endpoint.is_some(), state.resources.len()))
            .unwrap_or((false, 0));
        formatter
            .debug_struct("DpopNonceState")
            .field("token_endpoint_nonce_present", &token_nonce_present)
            .field("resource_nonce_count", &resource_nonce_count)
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
            resource_capacity: capacity,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, NonceStateInner>, OutboundDpopError> {
        self.inner
            .lock()
            .map_err(|_| OutboundDpopError::NonceStateUnavailable)
    }

    fn token_endpoint_nonce(&self) -> Result<Option<String>, OutboundDpopError> {
        Ok(self.lock()?.token_endpoint.clone())
    }

    fn set_token_endpoint_nonce(&self, nonce: String) -> Result<(), OutboundDpopError> {
        self.lock()?.token_endpoint = Some(nonce);
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
    signer: DpopSigner,
    nonces: DpopNonceState,
    http: Client,
}

impl fmt::Debug for DpopTokenExchangeClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopTokenExchangeClient")
            .field("config", &self.config)
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
    /// boundary. Redirects remain disabled.
    pub fn with_nonce_state(
        config: DpopTokenExchangeConfig,
        signer: DpopSigner,
        nonces: DpopNonceState,
    ) -> Result<Self, OutboundDpopError> {
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .build()
            .map_err(|_| OutboundDpopError::HttpClientInitialization)?;
        Ok(Self {
            config,
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
    /// token type `DPoP`; Bearer and missing token types fail closed.
    pub async fn exchange(
        &self,
        request: &Rfc8693TokenExchangeRequest,
    ) -> Result<DpopBoundAccessToken, OutboundDpopError> {
        let mut nonce_override = None;
        for attempt in 0..=1 {
            let nonce = match nonce_override.as_ref() {
                Some(value) => Some(value.clone()),
                None => self.nonces.token_endpoint_nonce()?,
            };
            let proof = self
                .signer
                .token_endpoint_proof(&self.config.token_endpoint, nonce.as_deref())?;
            let response = self.send_exchange(request, &proof).await?;
            let status = response.status();
            let headers = response.headers().clone();
            let nonce_header = strict_nonce_header(&headers)?;
            if let Some(nonce) = nonce_header.as_ref() {
                self.nonces.set_token_endpoint_nonce(nonce.clone())?;
            }
            let body = read_bounded_body(response, MAX_TOKEN_RESPONSE_BYTES).await?;
            if status.is_success() {
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
    ) -> Result<DpopBoundAccessToken, OutboundDpopError> {
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
        if raw
            .issued_token_type
            .as_deref()
            .is_some_and(|value| value != request.requested_token_type)
        {
            return Err(OutboundDpopError::UnexpectedIssuedTokenType);
        }
        if let Some(scope) = raw.scope.as_deref() {
            let requested: HashSet<&str> = request.scopes.iter().map(String::as_str).collect();
            if scope
                .split_ascii_whitespace()
                .any(|granted| !requested.contains(granted))
            {
                return Err(OutboundDpopError::BroadenedScopes);
            }
        }
        Ok(DpopBoundAccessToken {
            access_token: SecretString::new(access_token),
            issued_token_type: raw.issued_token_type,
            expires_in: raw.expires_in,
            scope: raw.scope,
            proof_thumbprint: self.signer.public_jwk.thumbprint.clone(),
        })
    }

    /// Starts one resource authorization attempt bound to this client's signer.
    ///
    /// # Errors
    /// Returns URL or signer-binding failures.
    ///
    /// # Security
    /// The returned transaction permits at most one 401 nonce retry.
    pub fn resource_request<'a>(
        &'a self,
        token: &'a DpopBoundAccessToken,
        method: Method,
        target: Url,
    ) -> Result<DpopResourceRequest<'a>, OutboundDpopError> {
        if token.proof_thumbprint != self.signer.public_jwk.thumbprint {
            return Err(OutboundDpopError::SignerMismatch);
        }
        let canonical_target = canonical_dpop_target(&target)?;
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

/// DPoP-bound access token returned by a validated RFC 8693 exchange.
#[derive(Clone)]
pub struct DpopBoundAccessToken {
    access_token: SecretString,
    issued_token_type: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    proof_thumbprint: String,
}

impl fmt::Debug for DpopBoundAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopBoundAccessToken")
            .field("access_token", &"<redacted>")
            .field("issued_token_type", &self.issued_token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("proof_thumbprint", &self.proof_thumbprint)
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

    /// Returns the RFC 8693 issued-token type when supplied.
    pub fn issued_token_type(&self) -> Option<&str> {
        self.issued_token_type.as_deref()
    }

    /// Returns the token lifetime in seconds when supplied.
    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }

    /// Returns the granted scope string when supplied.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Returns the proof-key thumbprint bound to this token result.
    pub fn proof_thumbprint(&self) -> &str {
        &self.proof_thumbprint
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
        let proof = self.client.signer.resource_proof(
            self.method.clone(),
            &self.target,
            &self.token.access_token,
            nonce.as_deref(),
        )?;
        DpopAuthorization::new(&self.token.access_token, proof)
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
        })
    }

    /// Applies the DPoP authorization to a reqwest request builder.
    ///
    /// # Security
    /// Both headers are marked sensitive. Do not add middleware that logs raw
    /// request headers before reqwest's sensitivity metadata is honored.
    pub fn apply(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder
            .header(http::header::AUTHORIZATION, self.authorization.clone())
            .header("DPoP", self.proof.clone())
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
    while let Some(chunk) = stream.next().await {
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

fn valid_nonce(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NONCE_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
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
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .map(|address| address.is_loopback())
                .unwrap_or(false)
    })
}

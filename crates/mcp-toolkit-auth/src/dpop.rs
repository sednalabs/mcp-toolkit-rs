//! # Sender-Constrained DPoP Authentication
//!
//! Parses the RFC 9449 authorization and proof headers and preserves trusted
//! verifier failures for the resource server.
//!
//! ## Rationale
//! Provides one strict extraction contract so resource servers do not accept
//! ambiguous sender-constrained credentials before atomic proof verification.
//!
//! ## Security Boundaries
//! * Header parsing does not validate the token or proof.
//! * Returned token and proof strings are authentication material and must not
//!   be logged.
//! * Typed verifier failures are for trusted transport mapping; external error
//!   bodies must remain low-leakage.
//!
//! ## References
//! * RFC 9449: OAuth 2.0 Demonstrating Proof of Possession.

use std::fmt;

use dpop_verifier::DpopError;
use http::HeaderMap;
use thiserror::Error;

use crate::AuthError;

/// A DPoP-bound access token borrowed from an `Authorization` header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DpopToken<'a> {
    value: &'a str,
}

impl fmt::Debug for DpopToken<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopToken(<redacted>)")
    }
}

impl<'a> DpopToken<'a> {
    /// Returns the raw DPoP-bound access-token credential.
    ///
    /// # Security
    /// The returned value is a credential. Callers must not log, trace, or
    /// expose it in diagnostics.
    pub fn as_str(&self) -> &'a str {
        self.value
    }
}

/// A compact DPoP proof borrowed from the request's `DPoP` header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DpopProof<'a> {
    value: &'a str,
}

impl fmt::Debug for DpopProof<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopProof(<redacted>)")
    }
}

impl<'a> DpopProof<'a> {
    /// Returns the raw compact DPoP proof.
    ///
    /// # Security
    /// The returned value contains request authentication material. Callers
    /// must not log, trace, or expose it in diagnostics.
    pub fn as_str(&self) -> &'a str {
        self.value
    }
}

/// Strict DPoP authorization-header parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DpopParseError {
    /// The request does not contain an `Authorization` header.
    #[error("missing authorization header")]
    MissingAuthorization,
    /// The request contains more than one `Authorization` header.
    #[error("multiple authorization headers")]
    MultipleAuthorizationHeaders,
    /// The `Authorization` header contains bytes that are not valid visible text.
    #[error("authorization header is not valid visible text")]
    InvalidHeaderValue,
    /// The header contains leading or trailing whitespace.
    #[error("authorization header contains leading or trailing whitespace")]
    LeadingOrTrailingWhitespace,
    /// The header contains a control character.
    #[error("authorization header contains a control character")]
    ControlCharacter,
    /// The scheme and token are not separated by exactly one ASCII space.
    #[error("authorization header must use exactly one space separator")]
    InvalidSeparator,
    /// The authorization scheme is not `DPoP`.
    #[error("authorization scheme is not dpop")]
    UnsupportedScheme,
    /// The `DPoP` scheme is present but the token is empty.
    #[error("missing dpop-bound access token")]
    MissingToken,
}

/// Strict `DPoP` proof-header parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DpopProofParseError {
    /// The request does not contain a `DPoP` proof header.
    #[error("missing dpop proof header")]
    MissingProof,
    /// The request contains more than one `DPoP` proof header.
    #[error("multiple dpop proof headers")]
    MultipleProofHeaders,
    /// The `DPoP` proof header is not valid visible text.
    #[error("dpop proof header is not valid visible text")]
    InvalidHeaderValue,
    /// The `DPoP` proof is empty or contains whitespace/control characters.
    #[error("dpop proof header must contain one compact proof")]
    InvalidProofValue,
}

/// Parses exactly one strict `Authorization: DPoP <token>` header.
///
/// The strict parser accepts one `Authorization` header, a case-insensitive
/// `DPoP` scheme, exactly one ASCII space separator, no leading or trailing
/// whitespace, no control characters, and a non-empty token.
///
/// # Errors
/// Returns [`DpopParseError`] when the header is missing, duplicated, invalid
/// text, uses the wrong scheme, has extra whitespace/control characters, or
/// has no token.
///
/// # Security
/// This function only extracts the credential. Callers must pass the returned
/// token and the request's compact `DPoP` proof to
/// [`crate::Authenticator::authenticate_sender_constrained_dpop`] before
/// trusting any identity or authorization claims. Callers must not log the
/// returned token.
///
/// # Examples
/// ```rust
/// use http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
/// use mcp_toolkit_auth::parse_strict_dpop_authorization;
///
/// let mut headers = HeaderMap::new();
/// headers.insert(AUTHORIZATION, HeaderValue::from_static("DPoP token"));
///
/// let parsed = parse_strict_dpop_authorization(&headers)?;
/// assert_eq!(parsed.as_str(), "token");
/// # Ok::<(), mcp_toolkit_auth::DpopParseError>(())
/// ```
pub fn parse_strict_dpop_authorization(
    headers: &HeaderMap,
) -> Result<DpopToken<'_>, DpopParseError> {
    let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
    let value = values.next().ok_or(DpopParseError::MissingAuthorization)?;
    if values.next().is_some() {
        return Err(DpopParseError::MultipleAuthorizationHeaders);
    }

    let raw = value
        .to_str()
        .map_err(|_| DpopParseError::InvalidHeaderValue)?;
    parse_strict_dpop_value(raw)
}

fn parse_strict_dpop_value(raw: &str) -> Result<DpopToken<'_>, DpopParseError> {
    if raw.trim() != raw {
        return Err(DpopParseError::LeadingOrTrailingWhitespace);
    }
    if raw.chars().any(char::is_control) {
        return Err(DpopParseError::ControlCharacter);
    }
    if raw.matches(' ').count() != 1 {
        return Err(DpopParseError::InvalidSeparator);
    }

    let (scheme, token) = raw
        .split_once(' ')
        .ok_or(DpopParseError::InvalidSeparator)?;
    if !scheme.eq_ignore_ascii_case("dpop") {
        return Err(DpopParseError::UnsupportedScheme);
    }
    if token.is_empty() {
        return Err(DpopParseError::MissingToken);
    }

    Ok(DpopToken { value: token })
}

/// Parses exactly one non-empty compact proof from the request's `DPoP` header.
///
/// # Errors
/// Returns [`DpopProofParseError`] when the proof header is missing,
/// duplicated, invalid text, empty, or contains whitespace/control characters.
/// Compact-JWS syntax and cryptographic validity remain the verifier's
/// responsibility.
///
/// # Security
/// This function only enforces an unambiguous HTTP header shape. Callers must
/// pass the result to
/// [`crate::Authenticator::authenticate_sender_constrained_dpop`] and must not
/// log the proof.
///
/// # Examples
/// ```rust
/// use http::{HeaderMap, HeaderValue};
/// use mcp_toolkit_auth::parse_strict_dpop_proof;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("dpop", HeaderValue::from_static("header.payload.signature"));
///
/// let proof = parse_strict_dpop_proof(&headers)?;
/// assert_eq!(proof.as_str(), "header.payload.signature");
/// # Ok::<(), mcp_toolkit_auth::DpopProofParseError>(())
/// ```
pub fn parse_strict_dpop_proof(headers: &HeaderMap) -> Result<DpopProof<'_>, DpopProofParseError> {
    let mut values = headers.get_all("dpop").iter();
    let value = values.next().ok_or(DpopProofParseError::MissingProof)?;
    if values.next().is_some() {
        return Err(DpopProofParseError::MultipleProofHeaders);
    }

    let raw = value
        .to_str()
        .map_err(|_| DpopProofParseError::InvalidHeaderValue)?;
    parse_strict_dpop_proof_value(raw)
}

fn parse_strict_dpop_proof_value(raw: &str) -> Result<DpopProof<'_>, DpopProofParseError> {
    if raw.is_empty() || raw.chars().any(char::is_whitespace) {
        return Err(DpopProofParseError::InvalidProofValue);
    }

    Ok(DpopProof { value: raw })
}

/// A failure from atomic sender-constrained DPoP authentication.
///
/// The wrapped source remains available to trusted resource-server code. That
/// code may, for example, return a DPoP nonce challenge for
/// [`DpopError::UseDpopNonce`] or distinguish a replay-store fault from an
/// invalid proof. It must not expose the wrapped detail in an ordinary Bearer
/// response.
#[derive(Debug, Error)]
pub enum SenderConstrainedAuthError {
    /// DPoP proof verification failed after access-token preflight.
    ///
    /// This includes signature, request binding, access-token hash, freshness,
    /// nonce, replay, and replay-store failures. A proof-key mismatch is mapped
    /// to [`Self::Authentication`] by the confirmation-bound replay guard.
    #[error("sender-constrained authentication failed")]
    Dpop(#[source] DpopError),
    /// Access-token preflight or confirmation-key matching failed.
    ///
    /// Missing or malformed `cnf.jkt` fails before proof verification. A valid
    /// proof under a different key fails when the verifier reaches guarded
    /// replay admission, without touching the underlying replay store.
    #[error("sender-constrained authentication failed")]
    Authentication(#[source] AuthError),
}

impl SenderConstrainedAuthError {
    /// Returns the DPoP verifier failure for trusted transport mapping.
    pub fn dpop_error(&self) -> Option<&DpopError> {
        match self {
            Self::Dpop(error) => Some(error),
            Self::Authentication(_) => None,
        }
    }

    /// Returns the token-preflight or confirmation-key failure.
    pub fn auth_error(&self) -> Option<&AuthError> {
        match self {
            Self::Dpop(_) => None,
            Self::Authentication(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{header::AUTHORIZATION, HeaderMap, HeaderValue};

    use super::{
        parse_strict_dpop_authorization, parse_strict_dpop_proof, DpopParseError,
        DpopProofParseError,
    };

    fn parse_header(value: HeaderValue) -> Result<String, DpopParseError> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value);
        parse_strict_dpop_authorization(&headers).map(|token| token.as_str().to_owned())
    }

    #[test]
    fn accepts_single_dpop_header_case_insensitively() {
        for value in ["DPoP token", "dpop token"] {
            let parsed = parse_header(HeaderValue::from_static(value));
            assert_eq!(parsed.as_deref(), Ok("token"));
        }
    }

    #[test]
    fn credential_debug_output_is_redacted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("DPoP secret-access-token"),
        );
        headers.insert(
            "dpop",
            HeaderValue::from_static("secret.header.payload.signature"),
        );

        let token = parse_strict_dpop_authorization(&headers).expect("token");
        let proof = parse_strict_dpop_proof(&headers).expect("proof");
        let token_debug = format!("{token:?}");
        let proof_debug = format!("{proof:?}");

        assert_eq!(token_debug, "DpopToken(<redacted>)");
        assert_eq!(proof_debug, "DpopProof(<redacted>)");
        assert!(!token_debug.contains(token.as_str()));
        assert!(!proof_debug.contains(proof.as_str()));
    }

    #[test]
    fn rejects_missing_or_multiple_authorization_headers() {
        let empty_headers = HeaderMap::new();
        let missing = parse_strict_dpop_authorization(&empty_headers);
        assert_eq!(missing, Err(DpopParseError::MissingAuthorization));

        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("DPoP one"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("DPoP two"));
        let multiple = parse_strict_dpop_authorization(&headers);
        assert_eq!(multiple, Err(DpopParseError::MultipleAuthorizationHeaders));
    }

    #[test]
    fn rejects_bearer_basic_and_malformed_schemes() {
        assert_eq!(
            parse_header(HeaderValue::from_static("Bearer token")),
            Err(DpopParseError::UnsupportedScheme)
        );
        assert_eq!(
            parse_header(HeaderValue::from_static("Basic token")),
            Err(DpopParseError::UnsupportedScheme)
        );
        assert_eq!(
            parse_header(HeaderValue::from_static("DPoPtoken")),
            Err(DpopParseError::InvalidSeparator)
        );
    }

    #[test]
    fn rejects_invalid_text_whitespace_and_control_characters() {
        let invalid_value = match HeaderValue::from_bytes(b"DPoP \xff") {
            Ok(value) => value,
            Err(error) => panic!("expected http to accept obs-text header value: {error}"),
        };
        assert_eq!(
            parse_header(invalid_value),
            Err(DpopParseError::InvalidHeaderValue)
        );
        assert_eq!(
            parse_header(HeaderValue::from_static(" DPoP token")),
            Err(DpopParseError::LeadingOrTrailingWhitespace)
        );
        assert_eq!(
            parse_header(HeaderValue::from_static("DPoP token ")),
            Err(DpopParseError::LeadingOrTrailingWhitespace)
        );
        assert_eq!(
            super::parse_strict_dpop_value("DPoP\ttoken"),
            Err(DpopParseError::ControlCharacter)
        );
        assert_eq!(
            parse_header(HeaderValue::from_static("DPoP  token")),
            Err(DpopParseError::InvalidSeparator)
        );
    }

    #[test]
    fn parses_exactly_one_compact_dpop_proof_header() {
        let mut headers = HeaderMap::new();
        headers.insert("dpop", HeaderValue::from_static("header.payload.signature"));
        let proof = parse_strict_dpop_proof(&headers);
        assert_eq!(
            proof.map(|value| value.as_str().to_owned()),
            Ok("header.payload.signature".to_string())
        );
    }

    #[test]
    fn rejects_missing_duplicate_or_ambiguous_dpop_proof_headers() {
        assert_eq!(
            parse_strict_dpop_proof(&HeaderMap::new()),
            Err(DpopProofParseError::MissingProof)
        );

        let mut duplicated = HeaderMap::new();
        duplicated.append("dpop", HeaderValue::from_static("one"));
        duplicated.append("dpop", HeaderValue::from_static("two"));
        assert_eq!(
            parse_strict_dpop_proof(&duplicated),
            Err(DpopProofParseError::MultipleProofHeaders)
        );

        let invalid_value = match HeaderValue::from_bytes(b"\xff") {
            Ok(value) => value,
            Err(error) => panic!("expected http to accept obs-text header value: {error}"),
        };
        let mut invalid = HeaderMap::new();
        invalid.insert("dpop", invalid_value);
        assert_eq!(
            parse_strict_dpop_proof(&invalid),
            Err(DpopProofParseError::InvalidHeaderValue)
        );

        for value in ["", "one two", "one\ttwo"] {
            assert_eq!(
                super::parse_strict_dpop_proof_value(value),
                Err(DpopProofParseError::InvalidProofValue),
                "{value:?}"
            );
        }
    }
}

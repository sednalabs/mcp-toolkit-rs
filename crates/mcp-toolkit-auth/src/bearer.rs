//! Bearer-token parsing helpers.
//!
//! ## Rationale
//! Provides one strict parser for `Authorization: Bearer ...` headers so service
//! edges do not duplicate auth-token extraction rules.
//!
//! ## Security Boundaries
//! * Parses header shape only; it does not validate token signatures, claims, or
//!   authorization scope.
//! * Returned token strings are credentials and must not be logged.
//!
//! ## References
//! * RFC 6750: OAuth 2.0 Bearer Token Usage.

use http::HeaderMap;
use thiserror::Error;

/// A bearer token borrowed from an `Authorization` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BearerToken<'a> {
    value: &'a str,
}

impl<'a> BearerToken<'a> {
    /// Returns the raw bearer-token credential.
    ///
    /// # Security
    /// The returned value is a credential. Callers must not log, trace, or expose
    /// it in diagnostics.
    pub fn as_str(&self) -> &'a str {
        self.value
    }
}

/// Strict bearer-token parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BearerParseError {
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
    /// The authorization scheme is not `Bearer`.
    #[error("authorization scheme is not bearer")]
    UnsupportedScheme,
    /// The `Bearer` scheme is present but the token is empty.
    #[error("missing bearer token")]
    MissingToken,
}

/// Parses exactly one strict `Authorization: Bearer <token>` header.
///
/// The strict parser accepts one `Authorization` header, a case-insensitive
/// `Bearer` scheme, exactly one ASCII space separator, no leading or trailing
/// whitespace, no control characters, and a non-empty token.
///
/// # Errors
/// Returns [`BearerParseError`] when the header is missing, duplicated, invalid
/// text, uses the wrong scheme, has extra whitespace/control characters, or has
/// no token.
///
/// # Security
/// This function only extracts the credential. Callers must validate the token
/// before trusting any identity or authorization claims, and must not log the
/// returned token.
///
/// # Examples
/// ```rust
/// use http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
/// use mcp_toolkit_auth::parse_strict_bearer_authorization;
///
/// let mut headers = HeaderMap::new();
/// headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
///
/// let parsed = parse_strict_bearer_authorization(&headers)?;
/// assert_eq!(parsed.as_str(), "token");
/// # Ok::<(), mcp_toolkit_auth::BearerParseError>(())
/// ```
pub fn parse_strict_bearer_authorization(
    headers: &HeaderMap,
) -> Result<BearerToken<'_>, BearerParseError> {
    let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or(BearerParseError::MissingAuthorization)?;
    if values.next().is_some() {
        return Err(BearerParseError::MultipleAuthorizationHeaders);
    }

    let raw = value
        .to_str()
        .map_err(|_| BearerParseError::InvalidHeaderValue)?;
    parse_strict_bearer_value(raw)
}

fn parse_strict_bearer_value(raw: &str) -> Result<BearerToken<'_>, BearerParseError> {
    if raw.trim() != raw {
        return Err(BearerParseError::LeadingOrTrailingWhitespace);
    }
    if raw.chars().any(char::is_control) {
        return Err(BearerParseError::ControlCharacter);
    }
    if raw.matches(' ').count() != 1 {
        return Err(BearerParseError::InvalidSeparator);
    }

    let (scheme, token) = raw
        .split_once(' ')
        .ok_or(BearerParseError::InvalidSeparator)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(BearerParseError::UnsupportedScheme);
    }
    if token.is_empty() {
        return Err(BearerParseError::MissingToken);
    }

    Ok(BearerToken { value: token })
}

#[cfg(test)]
mod tests {
    use http::{header::AUTHORIZATION, HeaderMap, HeaderValue};

    use super::{parse_strict_bearer_authorization, BearerParseError};

    fn parse_header(value: HeaderValue) -> Result<String, BearerParseError> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value);
        parse_strict_bearer_authorization(&headers).map(|token| token.as_str().to_owned())
    }

    #[test]
    fn accepts_single_bearer_header() {
        let parsed = parse_header(HeaderValue::from_static("Bearer token"));
        assert_eq!(parsed.as_deref(), Ok("token"));
    }

    #[test]
    fn accepts_scheme_case_insensitively() {
        let parsed = parse_header(HeaderValue::from_static("bearer token"));
        assert_eq!(parsed.as_deref(), Ok("token"));
    }

    #[test]
    fn rejects_missing_authorization_header() {
        let headers = HeaderMap::new();
        let parsed = parse_strict_bearer_authorization(&headers);
        assert_eq!(parsed, Err(BearerParseError::MissingAuthorization));
    }

    #[test]
    fn rejects_multiple_authorization_headers() {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer one"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer two"));

        let parsed = parse_strict_bearer_authorization(&headers);
        assert_eq!(parsed, Err(BearerParseError::MultipleAuthorizationHeaders));
    }

    #[test]
    fn rejects_invalid_header_value() {
        let value = match HeaderValue::from_bytes(b"Bearer \xff") {
            Ok(value) => value,
            Err(err) => panic!("expected http to accept obs-text header value: {err}"),
        };
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value);

        let parsed = parse_strict_bearer_authorization(&headers);
        assert_eq!(parsed, Err(BearerParseError::InvalidHeaderValue));
    }

    #[test]
    fn rejects_leading_or_trailing_whitespace() {
        let leading = parse_header(HeaderValue::from_static(" Bearer token"));
        let trailing = parse_header(HeaderValue::from_static("Bearer token "));

        assert_eq!(leading, Err(BearerParseError::LeadingOrTrailingWhitespace));
        assert_eq!(trailing, Err(BearerParseError::LeadingOrTrailingWhitespace));
    }

    #[test]
    fn rejects_control_characters() {
        let parsed = super::parse_strict_bearer_value("Bearer\ttoken");
        assert_eq!(parsed, Err(BearerParseError::ControlCharacter));
    }

    #[test]
    fn rejects_extra_or_missing_space_separator() {
        let extra = parse_header(HeaderValue::from_static("Bearer  token"));
        let missing = parse_header(HeaderValue::from_static("Bearertoken"));

        assert_eq!(extra, Err(BearerParseError::InvalidSeparator));
        assert_eq!(missing, Err(BearerParseError::InvalidSeparator));
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let parsed = parse_header(HeaderValue::from_static("Basic token"));
        assert_eq!(parsed, Err(BearerParseError::UnsupportedScheme));
    }

    #[test]
    fn rejects_missing_token() {
        let parsed = parse_header(HeaderValue::from_static("Bearer "));
        assert_eq!(parsed, Err(BearerParseError::LeadingOrTrailingWhitespace));
    }
}

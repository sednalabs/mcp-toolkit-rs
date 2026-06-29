//! # Host Header Helpers
//!
//! Shared parsing and validation helpers for Host headers and base URL derivation.
//!
//! ## Ownership
//! This module owns the logic for parsing and allowlist-based validation of HTTP
//! Host headers.
//!
//! ## Non-ownership
//! This module does not manage the transport layer; it relies on the caller
//! to extract and provide HTTP headers.
//!
//! ## Policy & Guarantees
//! * **DNS Rebinding Defense**: Enforces strict allowlist validation for Host headers.
//! * **Header Trust**: Honors `x-forwarded-proto` only for scheme derivation.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Providing a defined set of allowed hostnames.
//! * Handling validation error responses appropriately for their API surface.
//!
//! ## References
//! * RFC 3986: URI syntax (host/port formatting).

use std::collections::HashSet;
use std::net::Ipv6Addr;

use http::header::HOST;
use http::{HeaderMap, StatusCode, Uri};

/// Parsed host header components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHost {
    /// The hostname (lowercased, without brackets).
    pub host: String,
    /// Optional numeric port.
    pub port: Option<String>,
    /// True when the host was an IPv6 literal.
    pub ipv6: bool,
}

/// Normalized HTTP authority for Host header allowlist matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAuthority {
    /// The hostname (lowercased, without IPv6 brackets).
    pub host: String,
    /// Optional numeric port.
    pub port: Option<u16>,
}

/// Host header validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostValidationError {
    MissingHost,
    InvalidHost,
    NotAllowed,
}

impl HostValidationError {
    /// Returns the HTTP status code for the validation failure.
    pub fn status_code(self) -> StatusCode {
        match self {
            HostValidationError::MissingHost | HostValidationError::InvalidHost => {
                StatusCode::BAD_REQUEST
            }
            HostValidationError::NotAllowed => StatusCode::FORBIDDEN,
        }
    }

    /// Returns a short response body for the validation failure.
    pub fn message(self) -> &'static str {
        match self {
            HostValidationError::MissingHost => "Missing Host header",
            HostValidationError::InvalidHost => "Invalid Host header",
            HostValidationError::NotAllowed => "Host not allowed",
        }
    }
}

/// Parses a Host header value into host/port components.
pub fn parse_host_header(header: &str) -> Option<ParsedHost> {
    let trimmed = header.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_lowercase();
        if host.parse::<Ipv6Addr>().is_err() {
            return None;
        }
        let remainder = &rest[end + 1..];
        let port = match remainder {
            "" => None,
            _ => {
                let port = remainder.strip_prefix(':')?;
                Some(normalize_port(port)?)
            }
        };
        if host.is_empty() {
            return None;
        }
        return Some(ParsedHost {
            host,
            port,
            ipv6: true,
        });
    }
    let (host, port) = match trimmed.split_once(':') {
        Some((host, port)) => (host, Some(normalize_port(port)?)),
        None => (trimmed, None),
    };
    if host.is_empty() {
        return None;
    }
    Some(ParsedHost {
        host: host.to_lowercase(),
        port,
        ipv6: false,
    })
}

/// Validates that a request Host header is present, well-formed, and allowlisted.
pub fn validate_host_header(
    headers: &HeaderMap,
    allowed_hosts: &HashSet<String>,
) -> Result<ParsedHost, HostValidationError> {
    let host_header = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or(HostValidationError::MissingHost)?;
    let parsed = parse_host_header(host_header).ok_or(HostValidationError::InvalidHost)?;
    if !allowed_hosts.contains(&parsed.host) {
        return Err(HostValidationError::NotAllowed);
    }
    Ok(parsed)
}

/// Validates a request Host header against hostname or `host:port` allowlist entries.
///
/// This mirrors rmcp Streamable HTTP host allowlist semantics:
/// * an empty allowlist permits all well-formed Host headers,
/// * a bare hostname permits any port for that host,
/// * a `host:port` entry permits only that exact port.
pub fn validate_host_authority_header(
    headers: &HeaderMap,
    allowed_hosts: &[String],
) -> Result<HostAuthority, HostValidationError> {
    validate_request_authority(None, headers, allowed_hosts)
}

/// Validates a request authority from `Host` or, when `Host` is absent, from the URI.
///
/// This preserves rmcp Streamable HTTP host validation behavior for HTTP/2 and
/// nested-router call paths where `Host` may be represented as `:authority`.
pub fn validate_request_authority(
    uri: Option<&Uri>,
    headers: &HeaderMap,
    allowed_hosts: &[String],
) -> Result<HostAuthority, HostValidationError> {
    let parsed = request_authority(uri, headers)?;
    if !host_authority_is_allowed(&parsed, allowed_hosts) {
        return Err(HostValidationError::NotAllowed);
    }
    Ok(parsed)
}

/// Derives the base URL from request headers with allowlist enforcement.
pub fn base_url(
    headers: &HeaderMap,
    allowed_hosts: &HashSet<String>,
    default_host: &str,
) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_host_header)
        .filter(|parsed| allowed_hosts.contains(&parsed.host))
        .map(format_host)
        .unwrap_or_else(|| default_host.to_string());
    format!("{scheme}://{host}")
}

fn normalize_port(port: &str) -> Option<String> {
    let trimmed = port.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn host_authority_is_allowed(host: &HostAuthority, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    allowed_hosts
        .iter()
        .filter_map(|allowed| parse_allowed_authority(allowed))
        .any(|allowed| {
            allowed.host == host.host
                && match allowed.port {
                    Some(port) => host.port == Some(port),
                    None => true,
                }
        })
}

fn parse_host_authority(header: &str) -> Option<HostAuthority> {
    let authority = http::uri::Authority::try_from(header.trim()).ok()?;
    Some(normalize_authority(authority.host(), authority.port_u16()))
}

fn request_authority(
    uri: Option<&Uri>,
    headers: &HeaderMap,
) -> Result<HostAuthority, HostValidationError> {
    if let Some(host_header) = headers.get(HOST) {
        let host_header = host_header
            .to_str()
            .map_err(|_| HostValidationError::InvalidHost)?;
        return parse_host_authority(host_header).ok_or(HostValidationError::InvalidHost);
    }
    uri.and_then(Uri::authority)
        .map(|authority| normalize_authority(authority.host(), authority.port_u16()))
        .ok_or(HostValidationError::MissingHost)
}

fn parse_allowed_authority(allowed: &str) -> Option<HostAuthority> {
    let allowed = allowed.trim();
    if allowed.is_empty() {
        return None;
    }
    if let Ok(authority) = http::uri::Authority::try_from(allowed) {
        return Some(normalize_authority(authority.host(), authority.port_u16()));
    }
    Some(normalize_authority(allowed, None))
}

fn normalize_authority(host: &str, port: Option<u16>) -> HostAuthority {
    HostAuthority {
        host: normalize_authority_host(host),
        port,
    }
}

fn normalize_authority_host(host: &str) -> String {
    host.trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

fn format_host(parsed: ParsedHost) -> String {
    let host = if parsed.ipv6 {
        format!("[{}]", parsed.host)
    } else {
        parsed.host
    };
    match parsed.port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        base_url, parse_host_header, validate_host_authority_header, validate_host_header,
        HostValidationError,
    };
    use std::collections::HashSet;

    use http::{header::HOST, HeaderMap};

    #[test]
    fn parses_ipv4_host_and_port() {
        let parsed = parse_host_header("example.com:8080").expect("parsed");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port.as_deref(), Some("8080"));
        assert!(!parsed.ipv6);
    }

    #[test]
    fn rejects_non_ipv6_extra_colon_segments() {
        assert!(parse_host_header("example.com:80:90").is_none());
    }

    #[test]
    fn parses_ipv6_literal() {
        let parsed = parse_host_header("[::1]:9412").expect("parsed");
        assert_eq!(parsed.host, "::1");
        assert_eq!(parsed.port.as_deref(), Some("9412"));
        assert!(parsed.ipv6);
    }

    #[test]
    fn rejects_bracketed_hostnames() {
        assert!(parse_host_header("[example.com]").is_none());
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "[localhost]".parse().expect("header"));
        let allowed: HashSet<String> = ["localhost".to_string()].into_iter().collect();
        let err = validate_host_header(&headers, &allowed).expect_err("error");
        assert_eq!(err, HostValidationError::InvalidHost);
    }

    #[test]
    fn validate_host_header_rejects_unknown() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com".parse().expect("header"));
        let allowed: HashSet<String> = ["localhost".to_string()].into_iter().collect();
        let err = validate_host_header(&headers, &allowed).expect_err("error");
        assert_eq!(err, HostValidationError::NotAllowed);
    }

    #[test]
    fn validate_host_authority_header_honors_port_qualified_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com:8080".parse().expect("header"));
        let allowed = ["example.com:8080".to_string()];
        let parsed = validate_host_authority_header(&headers, &allowed).expect("allowed host");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, Some(8080));
    }

    #[test]
    fn validate_host_authority_header_rejects_wrong_port() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com:8081".parse().expect("header"));
        let allowed = ["example.com:8080".to_string()];
        let err = validate_host_authority_header(&headers, &allowed).expect_err("error");
        assert_eq!(err, HostValidationError::NotAllowed);
    }

    #[test]
    fn validate_host_authority_header_allows_any_port_for_bare_host() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com:8081".parse().expect("header"));
        let allowed = ["example.com".to_string()];
        let parsed = validate_host_authority_header(&headers, &allowed).expect("allowed host");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, Some(8081));
    }

    #[test]
    fn validate_host_authority_header_allows_all_when_allowlist_empty() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com:8081".parse().expect("header"));
        let parsed = validate_host_authority_header(&headers, &[]).expect("allowed host");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, Some(8081));
    }

    #[test]
    fn validate_request_authority_falls_back_to_uri_authority_when_host_absent() {
        let headers = HeaderMap::new();
        let uri = "http://example.com:8080/mcp" // DevSkim: ignore DS137138 absolute URI fixture
            .parse()
            .expect("absolute URI");
        let allowed = ["example.com:8080".to_string()];
        let parsed =
            super::validate_request_authority(Some(&uri), &headers, &allowed).expect("authority");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, Some(8080));
    }

    #[test]
    fn validate_request_authority_prefers_invalid_host_over_uri_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com:80:90".parse().expect("header"));
        let uri = "http://example.com:8080/mcp" // DevSkim: ignore DS137138 absolute URI fixture
            .parse()
            .expect("absolute URI");
        let allowed = ["example.com:8080".to_string()];
        let err = super::validate_request_authority(Some(&uri), &headers, &allowed)
            .expect_err("invalid host wins");
        assert_eq!(err, HostValidationError::InvalidHost);
    }

    #[test]
    fn base_url_falls_back_to_default() {
        let headers = HeaderMap::new();
        let allowed: HashSet<String> = ["localhost".to_string()].into_iter().collect();
        let url = base_url(&headers, &allowed, "localhost:1234");
        assert_eq!(url, "http://localhost:1234");
    }

    #[test]
    fn base_url_falls_back_to_default_on_malformed_host() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com:80:90".parse().expect("header"));
        let allowed: HashSet<String> = ["example.com".to_string()].into_iter().collect();
        let url = base_url(&headers, &allowed, "localhost:1234");
        assert_eq!(url, "http://localhost:1234");
    }
}

//! # HTTP Header Forwarding Policy
//!
//! Primitives for sanitizing and filtering HTTP headers during proxy operations.
//!
//! ## Ownership
//! This module owns the header classification logic, identifying which headers are
//! hop-by-hop and which are safe to forward across proxy boundaries.
//!
//! ## Non-ownership
//! This module does not perform I/O or manipulate actual request/response objects;
//! it provides purely functional classification of header names.
//!
//! ## Policy & Guarantees
//! * **Proxy Hardening**: Mitigates header-smuggling and hop-by-hop injection by
//!   filtering standard transport-level headers.
//! * **Identity Protection**: Blocks standard authentication headers from being
//!   forwarded, reducing credential leakage risk.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Implementing the actual removal/filtering of headers based on these classifications.
//! * Ensuring that security-critical headers (e.g., Auth) are handled according to
//!   the specific service's trust model.
//!
//! ## References
//! * RFC 9110: HTTP Semantics (Hop-by-hop headers).

/// Returns true when the header is a hop-by-hop or proxy-specific transport header.
pub fn is_transport_hop_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Returns true when a request header is safe to forward upstream.
///
/// # Security
/// * Aids in mitigating injection by blocking transport-level headers (e.g., Host, Auth).
pub fn should_forward_request_header(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    if is_transport_hop_header(&normalized) {
        return false;
    }

    !matches!(
        normalized.as_str(),
        "authorization" | "host" | "content-length"
    )
}

/// Returns true when a response header is safe to forward downstream.
pub fn should_forward_response_header(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    if is_transport_hop_header(&normalized) {
        return false;
    }

    !matches!(normalized.as_str(), "content-length")
}

#[cfg(test)]
mod tests {
    use super::{
        is_transport_hop_header, should_forward_request_header, should_forward_response_header,
    };

    #[test]
    fn transport_hop_header_detection_is_strict() {
        assert!(is_transport_hop_header("connection"));
        assert!(is_transport_hop_header("Keep-Alive"));
        assert!(is_transport_hop_header("TE"));
        assert!(is_transport_hop_header("proxy-authorization"));
        assert!(!is_transport_hop_header("content-type"));
        assert!(!is_transport_hop_header("x-request-id"));
    }

    #[test]
    fn request_forwarding_denies_sensitive_and_hop_headers() {
        assert!(!should_forward_request_header("authorization"));
        assert!(!should_forward_request_header("host"));
        assert!(!should_forward_request_header("content-length"));
        assert!(!should_forward_request_header("connection"));
        assert!(!should_forward_request_header("proxy-connection"));
        assert!(!should_forward_request_header("upgrade"));
    }

    #[test]
    fn request_forwarding_allows_safe_application_headers() {
        assert!(should_forward_request_header("content-type"));
        assert!(should_forward_request_header("accept"));
        assert!(should_forward_request_header("x-request-id"));
        assert!(should_forward_request_header("x-actor-id"));
    }

    #[test]
    fn response_forwarding_denies_transport_headers() {
        assert!(!should_forward_response_header("transfer-encoding"));
        assert!(!should_forward_response_header("connection"));
        assert!(!should_forward_response_header("trailer"));
        assert!(!should_forward_response_header("content-length"));
    }

    #[test]
    fn response_forwarding_allows_safe_headers() {
        assert!(should_forward_response_header("content-type"));
        assert!(should_forward_response_header("cache-control"));
        assert!(should_forward_response_header("x-request-id"));
    }
}

//! # HTTP Path Policy
//!
//! Primitives for validating HTTP request paths against common injection and
//! path-traversal vectors.
//!
//! ## Ownership
//! This module owns the normalization, sanitization, and confusion-detection
//! logic for HTTP paths to ensure consistent path handling.
//!
//! ## Non-ownership
//! This module does not manage transport or I/O; it acts as a functional validation
//! layer for input strings presented as HTTP paths.
//!
//! ## Policy & Guarantees
//! * **Path Confusion Mitigation**: Detects and rejects path traversal, matrix
//!   parameters, and encoded delimiters that could bypass routing logic.
//! * **Structural Bounding**: Enforces length constraints to prevent resource exhaustion.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying raw request paths before they are interpreted or used as filesystem keys.
//! * Ensuring that the returned `Decision` is applied at the correct architectural gate.
//!
//! ## References
//! * [MCP Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

use crate::{string_within_boundary_limit, Decision, DecisionCode};

/// Returns true when the path contains matrix parameters (e.g., `;foo=bar`).
pub fn contains_matrix_params(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b';' {
            return true;
        }

        if index + 2 < bytes.len()
            && bytes[index] == b'%'
            && bytes[index + 1].eq_ignore_ascii_case(&b'3')
            && bytes[index + 2].eq_ignore_ascii_case(&b'b')
        {
            return true;
        }

        index += 1;
    }

    false
}

/// Returns true when the path contains percent-encoded delimiters.
pub fn contains_encoded_delimiter(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("%2f")
        || lower.contains("%3b")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%2e")
        || lower.contains("%5c")
}

/// Returns true when the path contains traversal or separator-confusion vectors.
///
/// # Security
/// * Aids in mitigating traversal attacks by inspecting both raw and partially-decoded paths.
pub fn contains_path_confusion(path: &str) -> bool {
    path.contains('\\')
        || contains_encoded_delimiter(path)
        || has_malformed_percent_encoding(path)
        || path
            .trim_matches('/')
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        || percent_decode_once(path)
            .map(|decoded| {
                decoded.contains('\\')
                    || decoded.contains(';')
                    || decoded.contains('?')
                    || decoded.contains('#')
                    || contains_encoded_delimiter(&decoded)
                    || decoded
                        .trim_matches('/')
                        .split('/')
                        .any(|segment| matches!(segment, "." | ".."))
            })
            .unwrap_or(true)
}

/// Returns true when the path has at least one non-empty segment.
pub fn has_path_segment(path: &str) -> bool {
    path.trim_matches('/')
        .split('/')
        .any(|segment| !segment.is_empty())
}

/// Validates a request path against standard hardening rules.
///
/// # Security
/// * Rejects paths containing matrix parameters, query components, or traversal sequences.
pub fn validate_http_path(path: &str) -> Decision {
    if !string_within_boundary_limit(path) {
        return Decision::deny(DecisionCode::InvalidInput, Some("boundary_limits"));
    }
    if contains_matrix_params(path) || path.contains('?') || path.contains('#') {
        return Decision::deny(DecisionCode::InvalidPath, None);
    }
    if contains_path_confusion(path) {
        return Decision::deny(DecisionCode::InvalidPath, None);
    }
    Decision::allow()
}

/// Alias for [`validate_http_path`].
pub fn evaluate_http_path(path: &str) -> Decision {
    validate_http_path(path)
}

fn has_malformed_percent_encoding(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || hex_value(bytes[i + 1]).is_none()
                || hex_value(bytes[i + 2]).is_none()
            {
                return true;
            }
            i += 3;
            continue;
        }
        i += 1;
    }
    false
}

fn percent_decode_once(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut i = 0usize;
    let mut decoded = String::with_capacity(path.len());

    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex_value(*bytes.get(i + 1)?)?;
            let lo = hex_value(*bytes.get(i + 2)?)?;
            decoded.push(char::from((hi << 4) | lo));
            i += 3;
            continue;
        }
        decoded.push(char::from(bytes[i]));
        i += 1;
    }

    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        contains_matrix_params, contains_path_confusion, evaluate_http_path, has_path_segment,
        validate_http_path,
    };

    #[test]
    fn detects_matrix_params() {
        assert!(contains_matrix_params("/admin/realms;foo/test"));
        assert!(contains_matrix_params("/admin/realms/test;v=1"));
        assert!(contains_matrix_params("/admin/realms%3bfoo/test"));
        assert!(contains_matrix_params("/admin/realms%3Bfoo/test"));
        assert!(!contains_matrix_params("/admin/realms/test"));
    }

    #[test]
    fn detects_path_confusion_vectors() {
        assert!(contains_path_confusion("/admin/realms/../users"));
        assert!(contains_path_confusion("/admin/realms/%2e%2e/users"));
        assert!(contains_path_confusion("/admin/realms/%2Fusers"));
        assert!(contains_path_confusion("/admin\\realms\\users"));
        assert!(!contains_path_confusion("/admin/realms/example/users"));
    }

    #[test]
    fn validation_denies_invalid_paths() {
        let decision = evaluate_http_path("/admin/realms/%2e%2e/users");
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_PATH"));
    }

    #[test]
    fn validation_allows_clean_paths() {
        let decision = validate_http_path("/admin/realms/example/users");
        assert!(decision.allow);
    }

    #[test]
    fn validation_allows_double_slash_path() {
        let decision = validate_http_path("/admin//realms/users");
        assert!(decision.allow);
    }

    #[test]
    fn validation_allows_empty_path_for_missing_realm_handling() {
        let decision = validate_http_path("");
        assert!(decision.allow);
    }

    #[test]
    fn validation_denies_paths_over_boundary_limit() {
        let oversized = format!("/{}", "a".repeat(crate::BOUNDARY_MAX_STRING_LENGTH));
        let decision = validate_http_path(&oversized);
        assert!(!decision.allow);
        assert_eq!(decision.code.as_deref(), Some("INVALID_INPUT"));
        assert_eq!(decision.reason.as_deref(), Some("boundary_limits"));
    }

    #[test]
    fn root_has_no_path_segment() {
        assert!(!has_path_segment("/"));
        assert!(!has_path_segment(""));
        assert!(has_path_segment("/mcp"));
    }
}

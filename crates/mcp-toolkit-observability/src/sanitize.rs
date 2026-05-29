//! # Input Sanitization
//!
//! Utilities for cleaning and normalizing potentially untrusted input strings.
//!
//! ## Ownership
//! This module owns the logic for stripping control characters, enforcing length limits,
//! and orchestrating heuristic redaction of telemetry data.
//!
//! ## Non-ownership
//! This module does not guarantee security against sophisticated injection or
//! data exfiltration. It relies on heuristic patterns and basic character filtering.
//!
//! ## Policy & Guarantees
//! * **Character Normalization**: Strips control characters to mitigate basic log forging.
//! * **Length Bounding**: Enforces length constraints to reduce the risk of log-flooding.
//! * **Heuristic Redaction**: Integrates with `redaction` to reduce the risk of secret leakage.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Ensuring that untrusted input is validated according to domain-specific requirements.
//! * Assessing whether heuristic sanitization is sufficient for their threat model.
//! * Ensuring consistent sanitization policies across telemetry emitters.
//!
//! ## References
//! * [Log Injection Mitigation] (Internal observability guidelines)

use serde_json::Value;

use crate::redaction::{
    redact_json_keys, redact_kv_pairs, redact_telemetry_text, truncate, DEFAULT_REDACT_KEYS,
    DEFAULT_REDACT_VALUE,
};

const DEFAULT_LOG_VALUE_MAX: usize = 128;

fn is_control_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{001F}') || c == '\u{007F}'
}

/// Removes control characters from a string to mitigate basic log manipulation.
pub fn strip_control_chars(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    value.chars().filter(|c| !is_control_char(*c)).collect()
}

/// Sanitize a string for use as an HTTP header name.
pub fn sanitize_header_name(name: &str) -> String {
    strip_control_chars(name).trim().to_string()
}

/// Sanitize a string for use as an HTTP header value, with an optional length limit.
pub fn sanitize_header_value(value: &str, max_len: Option<usize>) -> String {
    let cleaned = strip_control_chars(value).trim().to_string();
    match max_len {
        Some(limit) if limit > 0 => cleaned.chars().take(limit).collect(),
        _ => cleaned,
    }
}

/// Sanitize a string for inclusion in a log message.
pub fn sanitize_log_value(value: &str) -> String {
    sanitize_log_value_with_limit(value, DEFAULT_LOG_VALUE_MAX)
}

/// Sanitize a string for inclusion in a log message, with a hard length limit.
pub fn sanitize_log_value_with_limit(value: &str, max_len: usize) -> String {
    let cleaned = strip_control_chars(value).trim().to_string();
    if cleaned.len() <= max_len {
        cleaned
    } else {
        cleaned.chars().take(max_len).collect()
    }
}

/// Optionally sanitize an optional string for logging.
pub fn sanitize_log_value_opt(value: Option<&str>, max_len: usize) -> Option<String> {
    let text = strip_control_chars(value.unwrap_or("")).trim().to_string();
    if text.is_empty() {
        return None;
    }
    if text.len() <= max_len {
        return Some(text);
    }
    Some(text.chars().take(max_len).collect())
}

/// Sanitizes an error message by stripping control characters and applying heuristic redaction.
///
/// # Security
/// * Aids in mitigating accidental secret exposure through best-effort redaction.
pub fn sanitize_error_message(message: &str, max_len: usize) -> String {
    let scrubbed = strip_control_chars(message);
    let scrubbed = redact_telemetry_text(&scrubbed);
    truncate(&scrubbed, max_len)
}

/// Sanitizes an exchange error body (supports both JSON and KV pairs).
///
/// # Security
/// * Mitigates accidental secret exposure via best-effort heuristic redaction.
pub fn sanitize_exchange_error(raw: &str, max_bytes: usize) -> String {
    let cleaned = strip_control_chars(raw);
    let redacted = if let Ok(mut value) = serde_json::from_str::<Value>(&cleaned) {
        redact_json_keys(&mut value, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE);
        value.to_string()
    } else {
        redact_kv_pairs(&cleaned, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE)
    };
    let redacted = redact_telemetry_text(&redacted);
    truncate_bytes(&redacted, max_bytes)
}

/// Truncates a string to a maximum number of bytes, ensuring no partial UTF-8 characters.
pub fn truncate_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut out = String::new();
    for ch in value.chars() {
        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_chars() {
        let value = "a\u{0001}b";
        assert_eq!(strip_control_chars(value), "ab");
    }

    #[test]
    fn sanitizes_error_messages() {
        let value = "Authorization: Bearer abc";
        let sanitized = sanitize_error_message(value, 128);
        assert!(sanitized.contains("REDACTED"));
    }

    #[test]
    fn sanitizes_exchange_error_json() {
        let raw = r#"{"access_token":"abc","foo":"bar"}"#;
        let sanitized = sanitize_exchange_error(raw, 512);
        assert!(sanitized.contains(DEFAULT_REDACT_VALUE));
    }

    #[test]
    fn sanitizes_exchange_error_redacts_postgres_url() {
        let raw = r#"{"db":"postgresql://user:pass@localhost/app"}"#;
        let sanitized = sanitize_exchange_error(raw, 512);
        assert!(sanitized.contains("REDACTED"));
        assert!(!sanitized.contains("user:pass"));
    }
}

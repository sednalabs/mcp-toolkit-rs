//! # Log Redaction
//!
//! Heuristic helpers for masking sensitive data in telemetry streams.
//!
//! ## Ownership
//! This module owns the definitions of sensitive key patterns and the logic for
//! applying best-effort redaction to strings, JSON payloads, and KV pairs.
//!
//! ## Non-ownership
//! This module does not provide guaranteed secret detection. It does not inspect
//! data for complex or obfuscated secrets, nor does it guarantee the absence
//! of sensitive data in output.
//!
//! ## Policy & Guarantees
//! * **Masking**: Replaces substrings matching known secret patterns (e.g., Bearer tokens,
//!   GitHub PATs) with a redaction placeholder.
//! * **Risk Reduction**: Functions as a defense-in-depth layer to reduce the risk
//!   of accidental exposure.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Ensuring primary secret management occurs elsewhere (e.g., proper key vault usage).
//! * Assessing whether the heuristic patterns in this module sufficiently cover their risk profile.
//! * Ensuring that telemetry payloads are appropriately sanitized before passing to
//!   untrusted log aggregators.
//!
//! ## References
//! * [Sensitive Data Masking] Internal project observability guidelines.

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

pub const DEFAULT_REDACT_VALUE: &str = "<redacted>";
pub const DEFAULT_REDACT_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "subject_token",
    "client_secret",
    "authorization",
];

static RE_AUTH_BEARER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(authorization:[[:space:]]*bearer[[:space:]]+)[^[:space:]]+")
        .expect("auth bearer regex")
});
static RE_BEARER_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)bearer[[:space:]]+[A-Za-z0-9._~-]+").expect("bearer regex"));
static RE_GITHUB_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(github_pat\s*[=:]\s*)\S+").expect("github_pat regex"));
static RE_GH_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"gh[a-z]_[A-Za-z0-9_]{36,}").expect("gh token regex"));
static RE_GENERIC_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(password|token|secret|api_key)\s*[=:]\s*\S+").expect("generic secret regex")
});
static RE_OAUTH_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(client_secret|subject_token|access_token|refresh_token)\s*[=:]\s*\S+")
        .expect("oauth secret regex")
});
static RE_POSTGRES_URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)postgresql(\+\w+)?://[^\s]+").expect("postgres url regex"));

/// Applies best-effort redaction to telemetry text.
///
/// # Security
/// * Masks known secret patterns to mitigate accidental exposure.
/// * Callers should not rely on this for comprehensive secret scrubbing.
pub fn redact_telemetry_text(text: &str) -> String {
    let mut scrubbed = text.to_string();
    scrubbed = RE_AUTH_BEARER
        .replace_all(&scrubbed, "${1}REDACTED")
        .to_string();
    scrubbed = RE_BEARER_TOKEN
        .replace_all(&scrubbed, "Bearer REDACTED")
        .to_string();
    scrubbed = RE_GITHUB_PAT
        .replace_all(&scrubbed, "${1}REDACTED")
        .to_string();
    scrubbed = RE_GH_TOKEN.replace_all(&scrubbed, "REDACTED").to_string();
    scrubbed = RE_GENERIC_SECRET
        .replace_all(&scrubbed, "${1}=REDACTED")
        .to_string();
    scrubbed = RE_OAUTH_SECRET
        .replace_all(&scrubbed, "${1}=REDACTED")
        .to_string();
    scrubbed = RE_POSTGRES_URL
        .replace_all(&scrubbed, "postgresql://REDACTED")
        .to_string();
    scrubbed
}

/// Recursively redacts values for keys matching a sensitive set.
///
/// # Security
/// * Overwrites sensitive field values in JSON telemetry to mitigate exposure.
pub fn redact_json_keys(value: &mut Value, keys: &[&str], replacement: &str) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if should_redact_key(key, keys) {
                    *entry = Value::String(replacement.to_string());
                } else {
                    redact_json_keys(entry, keys, replacement);
                }
            }
        }
        Value::Array(items) => {
            for entry in items.iter_mut() {
                redact_json_keys(entry, keys, replacement);
            }
        }
        _ => {}
    }
}

/// Redacts values in ampersand-separated key-value pairs.
///
/// # Security
/// * Scrubs the value portion of known sensitive keys to mitigate credential leaks
///   through query strings or formatted parameters.
pub fn redact_kv_pairs(text: &str, keys: &[&str], replacement: &str) -> String {
    let mut output = String::new();
    let mut first = true;
    for part in text.split('&') {
        if !first {
            output.push('&');
        }
        first = false;
        if let Some((key, value)) = part.split_once('=') {
            if should_redact_key(key, keys) {
                output.push_str(key);
                output.push('=');
                output.push_str(replacement);
            } else {
                output.push_str(key);
                output.push('=');
                output.push_str(value);
            }
        } else {
            output.push_str(part);
        }
    }
    output
}

/// Truncate a string to a maximum length, appending an ellipsis if necessary.
pub fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    if limit <= 1 {
        return ".".repeat(limit);
    }
    if limit <= 3 {
        return ".".repeat(limit);
    }
    let mut cutoff = limit - 3;
    while cutoff > 0 && !text.is_char_boundary(cutoff) {
        cutoff -= 1;
    }
    let mut out = text[..cutoff].to_string();
    out.push_str("...");
    out
}

fn should_redact_key(key: &str, keys: &[&str]) -> bool {
    let key = key.to_ascii_lowercase();
    keys.iter().any(|candidate| *candidate == key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_bearer_tokens() {
        let text = "Authorization: Bearer abc.def";
        let scrubbed = redact_telemetry_text(text);
        assert!(scrubbed.contains("REDACTED"));
    }

    #[test]
    fn redacts_json_keys() {
        let mut payload = json!({
            "access_token": "abc",
            "nested": { "refresh_token": "def" },
            "ok": "yes",
        });
        redact_json_keys(&mut payload, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE);
        assert_eq!(payload["access_token"], DEFAULT_REDACT_VALUE);
        assert_eq!(payload["nested"]["refresh_token"], DEFAULT_REDACT_VALUE);
        assert_eq!(payload["ok"], "yes");
    }

    #[test]
    fn redacts_kv_pairs() {
        let text = "access_token=abc&foo=bar";
        let scrubbed = redact_kv_pairs(text, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE);
        assert_eq!(scrubbed, "access_token=<redacted>&foo=bar");
    }

    #[test]
    fn truncate_respects_utf8_boundaries() {
        assert_eq!(truncate("åß∂ƒ", 7), "åß...");
        assert_eq!(truncate("😀abcdef", 4), "...");
    }
}

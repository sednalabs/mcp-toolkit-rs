//! # Auth Utilities
//!
//! Internal utilities for telemetry, hashing, and debugging in authentication flows.
//!
//! ## Ownership
//! This module owns the hashing and redaction utilities used for authenticated event
//! debug logging and identity obfuscation within the auth crate.
//!
//! ## Non-ownership
//! This module does not manage business logic or authentication state; it is purely
//! a collection of support primitives.
//!
//! ## Policy & Guarantees
//! * **Identity Hashing**: Provides stable hashes for identifiers (e.g., token refs,
//!   subjects) to mitigate exposure of raw sensitive values.
//! * **Debug Redaction**: Orchestrates heuristic redaction for debug-level auth events.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Ensuring that debug events are only emitted if the appropriate environment flags are set.
//! * Treating utility-generated hashes as non-reversible identifiers.
//!
//! ## References
//! * `crate::redaction`
//! * `crate::sanitize`

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mcp_toolkit_observability::{
    redact_json_keys, sanitize_log_value_with_limit, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::debug;

const AUTH_DEBUG_ENV: &str = "MCP_TOOLKIT_AUTH_DEBUG";
const AUTH_DEBUG_MAX_BYTES: usize = 2048;

/// Generates a stable token reference hash to identify tokens in logs without exposure.
pub(crate) fn token_ref(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Generates a short hex hash for an identifier.
pub(crate) fn hash_identifier(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let hex = digest.iter().fold(String::with_capacity(64), |mut hex, byte| {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing a digest to String cannot fail");
        hex
    });
    hex.chars().take(12).collect()
}

fn auth_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        let raw = std::env::var(AUTH_DEBUG_ENV).unwrap_or_default();
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Emits an authenticated debug event, applying best-effort redaction.
pub(crate) fn auth_debug_event(event: &str, mut payload: Value) {
    if !auth_debug_enabled() || !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    redact_json_keys(&mut payload, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE);
    let message = sanitize_log_value_with_limit(&payload.to_string(), AUTH_DEBUG_MAX_BYTES);
    debug!(auth_debug = event, payload = message);
}

//! Authentication Provider Implementations
//!
//! Internal provider logic for OIDC/OAuth 2.0 authentication flows, including
//! JWKS caching, token introspection, and delegation handling.
//!
//! ## Rationale
//! Encapsulates provider-specific protocol interactions (OIDC, OAuth) to keep
//! the main auth surface clean.
//!
//! ## Security Boundaries
//! * Implements boundary-aware request/response handling (e.g. body size limiting).
//! * Centralizes logic for caching and validation of tokens and keys.
//!
//! ## References
//! * [RFC 7662] OAuth 2.0 Token Introspection.
//! * [OpenID Connect Core 1.0]

mod delegation;
mod introspection;
mod jwks;

use futures_util::StreamExt;

use crate::AuthError;

pub(crate) use introspection::IntrospectionCache;
pub(crate) use jwks::JwksCache;

/// Reads and buffers a response body while enforcing a size limit to prevent resource exhaustion.
///
/// # Errors
/// * Returns `AuthError::Generic` if reading the stream fails or if the response size
///   exceeds `max_bytes`.
///
/// # Security
/// * **DoS Protection**: Enforces a strict upper bound (`max_bytes`) on response sizes
///   to prevent memory exhaustion when processing untrusted provider responses.
async fn read_body_limited(
    response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, AuthError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();

    loop {
        let next_chunk = stream.next().await;
        let Some(chunk_result) = next_chunk else {
            break;
        };

        let chunk = chunk_result.map_err(|e| AuthError::Generic {
            message: format!("Failed to read {label} response: {e}"),
            status_code: 502,
            code: None,
            reason: None,
        })?;

        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(AuthError::Generic {
                message: format!("{label} response too large"),
                status_code: 502,
                code: None,
                reason: None,
            });
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

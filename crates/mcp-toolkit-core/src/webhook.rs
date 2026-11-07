//! # Webhook signing-secret profiles
//!
//! ## Rationale
//! Share bounded signing-secret format validation without depending on an HTTP
//! transport, request decoder, or subscription lifecycle.
//!
//! ## Security boundaries
//! Validation checks format only, not entropy, ownership, authorization or key
//! custody. Errors never retain input or decoder details. No I/O occurs here.
//! The ChatGPT profile is narrower than the general Standard Webhooks protocol.
//!
//! ## References
//! * [ChatGPT MCP Events](https://developers.openai.com/plugins/build/mcp-events)

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// Reports an invalid signing-secret format without retaining secret contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningSecretError;

impl fmt::Display for SigningSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid webhook signing secret")
    }
}

impl std::error::Error for SigningSecretError {}

/// Validates the signing-secret format accepted by the ChatGPT webhook profile.
///
/// # Errors
/// Rejects a missing `whsec_` prefix, malformed canonical standard base64, or a
/// decoded key outside 24..=64 bytes. The encoded suffix is capped at 88 bytes
/// before decoding. These bounds are not universal Standard Webhooks limits.
///
/// # Security
/// This checks format only, not entropy, ownership, authorization or custody.
/// Do not log the input. The temporary decoded key is not guaranteed zeroized.
///
/// ```
/// use mcp_toolkit_core::webhook::validate_chatgpt_signing_secret;
/// // This fixed value demonstrates format only; it is not a usable secret.
/// validate_chatgpt_signing_secret("whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
/// assert!(validate_chatgpt_signing_secret("whsec_").is_err());
/// # Ok::<(), mcp_toolkit_core::webhook::SigningSecretError>(())
/// ```
pub fn validate_chatgpt_signing_secret(secret: &str) -> Result<(), SigningSecretError> {
    let encoded = secret
        .strip_prefix("whsec_")
        .filter(|value| value.len() <= 88)
        .ok_or(SigningSecretError)?;
    let bytes = STANDARD.decode(encoded).map_err(|_| SigningSecretError)?;
    if !(24..=64).contains(&bytes.len()) {
        return Err(SigningSecretError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed bytes exercise encoding only; these values never reach a signer.
    fn encoded_key(bytes: usize) -> String {
        format!("whsec_{}", STANDARD.encode(vec![0_u8; bytes]))
    }

    #[test]
    fn accepts_each_decoded_length_in_the_chatgpt_profile() {
        for bytes in 24..=64 {
            assert_eq!(validate_chatgpt_signing_secret(&encoded_key(bytes)), Ok(()));
        }
    }

    #[test]
    fn rejects_decoded_lengths_outside_the_profile() {
        for bytes in [0, 1, 23, 65, 66] {
            assert_eq!(
                validate_chatgpt_signing_secret(&encoded_key(bytes)),
                Err(SigningSecretError)
            );
        }
    }

    #[test]
    fn rejects_wrong_prefix_and_noncanonical_base64() {
        let valid = encoded_key(25);
        let mut noncanonical = valid.clone();
        let position = noncanonical.len() - 3;
        noncanonical.replace_range(position..position + 1, "B");
        let url_safe = format!("whsec_{}", "_".repeat(32));
        for input in [
            valid[6..].to_owned(),
            valid.replacen("whsec_", "WHSEC_", 1),
            format!(" {valid}"),
            format!("{valid}\n"),
            format!("{valid}="),
            valid.trim_end_matches('=').to_owned(),
            noncanonical,
            url_safe,
            "whsec_é".to_owned(),
        ] {
            assert_eq!(
                validate_chatgpt_signing_secret(&input),
                Err(SigningSecretError)
            );
        }
    }

    #[test]
    fn bounds_encoded_input_before_decoding() {
        let maximum = encoded_key(64);
        assert_eq!(maximum.len(), 6 + 88);
        assert_eq!(validate_chatgpt_signing_secret(&maximum), Ok(()));
        for extra in [1, 1024 * 1024] {
            let input = format!("{maximum}{}", "A".repeat(extra));
            assert_eq!(
                validate_chatgpt_signing_secret(&input),
                Err(SigningSecretError)
            );
        }
    }

    #[test]
    fn errors_never_echo_input_or_decoder_details() {
        let error = validate_chatgpt_signing_secret("whsec_private-invalid-value").unwrap_err();
        assert_eq!(error.to_string(), "invalid webhook signing secret");
        assert_eq!(format!("{error:?}"), "SigningSecretError");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn deterministic_fuzz_of_secret_format_validation() {
        let mut seed = 0x517c_c1b7_u32;
        for length in 0..512 {
            let bytes: Vec<u8> = (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            let input = format!("whsec_{}", String::from_utf8_lossy(&bytes));
            let _ = validate_chatgpt_signing_secret(&input);
        }
        let valid = encoded_key(32);
        for position in 0..valid.len() {
            for replacement in ["!", " ", "\n", "é"] {
                let mut input = valid.clone();
                input.replace_range(position..position + 1, replacement);
                assert_eq!(
                    validate_chatgpt_signing_secret(&input),
                    Err(SigningSecretError)
                );
            }
        }
    }
}

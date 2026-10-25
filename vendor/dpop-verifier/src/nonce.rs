//! Stateless DPoP-Nonce issuance & verification using HMAC-SHA256.
//!
//! Nonce format (binary, then base64url(no-pad)):
//!   version(1) || ts_be(8) || rand(16) || mac(16)
//!
//! mac = HMAC-SHA256(secret, version || ts || rand || ctx_bytes)[..16]
//! ctx_bytes = concatenation of tagged optional fields:
//!   b"HTU\0" + htu + b"\0"  (if provided)
//!   b"HTM\0" + htm + b"\0"  (if provided)
//!   b"JKT\0" + jkt + b"\0"  (if provided)

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::DpopError;

/// Helper trait to convert various secret types into `SecretBox<[u8]>`.
/// This allows functions to accept both `SecretBox<[u8]>` and non-boxed types like `&[u8]` or `Vec<u8>`.
pub trait IntoSecretBox {
    fn into_secret_box(self) -> SecretBox<[u8]>;
}

impl IntoSecretBox for SecretBox<[u8]> {
    fn into_secret_box(self) -> SecretBox<[u8]> {
        self
    }
}

impl IntoSecretBox for &SecretBox<[u8]> {
    fn into_secret_box(self) -> SecretBox<[u8]> {
        self.clone()
    }
}

impl IntoSecretBox for &[u8] {
    fn into_secret_box(self) -> SecretBox<[u8]> {
        SecretBox::from(self.to_vec())
    }
}

impl<const N: usize> IntoSecretBox for &[u8; N] {
    fn into_secret_box(self) -> SecretBox<[u8]> {
        SecretBox::from(self.to_vec())
    }
}

impl IntoSecretBox for Vec<u8> {
    fn into_secret_box(self) -> SecretBox<[u8]> {
        SecretBox::from(self)
    }
}

impl IntoSecretBox for &Vec<u8> {
    fn into_secret_box(self) -> SecretBox<[u8]> {
        SecretBox::from(self.clone())
    }
}

type HmacSha256 = Hmac<Sha256>;

const NONCE_VERSION: u8 = 1;
const NONCE_RANDOM_LENGTH: usize = 16;
const NONCE_MAC_LENGTH: usize = 16; // truncated
const NONCE_TOTAL_LENGTH: usize = 1 + 8 + 16 + 16; // version + timestamp + random + mac
const NONCE_ENCODED_LENGTH: usize = (NONCE_TOTAL_LENGTH * 4).div_ceil(3);
const NONCE_FUTURE_SKEW_SECS: i64 = 5;

/// Optional binding context (only fields you want to bind).
pub struct NonceCtx<'a> {
    pub htu: Option<&'a str>,
    pub htm: Option<&'a str>,
    pub jkt: Option<&'a str>,
    pub client: Option<&'a str>,
}

fn ctx_bytes(ctx: &NonceCtx<'_>) -> Vec<u8> {
    let mut context_bytes = Vec::new();
    if let Some(htu) = ctx.htu {
        context_bytes.extend_from_slice(b"HTU\0");
        context_bytes.extend_from_slice(htu.as_bytes());
        context_bytes.push(0);
    }
    if let Some(htm) = ctx.htm {
        context_bytes.extend_from_slice(b"HTM\0");
        context_bytes.extend_from_slice(htm.as_bytes());
        context_bytes.push(0);
    }
    if let Some(jkt) = ctx.jkt {
        context_bytes.extend_from_slice(b"JKT\0");
        context_bytes.extend_from_slice(jkt.as_bytes());
        context_bytes.push(0);
    }
    if let Some(client_id) = ctx.client {
        context_bytes.extend_from_slice(b"CID\0");
        context_bytes.extend_from_slice(client_id.as_bytes());
        context_bytes.push(0);
    }
    context_bytes
}

/// Issue a fresh nonce bound to the given context.
///
/// Accepts either a `SecretBox<[u8]>` or any type that can be converted to bytes (e.g., `&[u8]`, `Vec<u8>`).
/// Non-boxed types will be automatically converted to `SecretBox` internally.
pub fn issue_nonce<S>(secret: S, now_unix: i64, ctx: &NonceCtx<'_>) -> Result<String, DpopError>
where
    S: IntoSecretBox,
{
    let secret_box = secret.into_secret_box();
    let version_bytes = [NONCE_VERSION];
    let timestamp_bytes = now_unix.to_be_bytes();

    let mut random_bytes = [0u8; NONCE_RANDOM_LENGTH];
    OsRng.fill_bytes(&mut random_bytes);

    // HMAC-SHA256 accepts keys of any length; this should never fail
    let mut hmac = HmacSha256::new_from_slice(secret_box.expose_secret())
        .map_err(|_| DpopError::InvalidHmacConfig)?;

    hmac.update(&version_bytes);
    hmac.update(&timestamp_bytes);
    hmac.update(&random_bytes);
    hmac.update(&ctx_bytes(ctx));
    let mac_tag = hmac.finalize().into_bytes();

    let mut nonce_bytes = Vec::with_capacity(NONCE_TOTAL_LENGTH);
    nonce_bytes.extend_from_slice(&version_bytes);
    nonce_bytes.extend_from_slice(&timestamp_bytes);
    nonce_bytes.extend_from_slice(&random_bytes);
    nonce_bytes.extend_from_slice(&mac_tag[..NONCE_MAC_LENGTH]);

    Ok(B64.encode(nonce_bytes))
}

/// Verify a nonce with age & skew limits, re-binding to the given context.
/// On success returns Ok(()); on failure returns a DpopError (NonceMismatch/NonceStale/FutureSkew).
///
/// Accepts either a `SecretBox<[u8]>` or any type that can be converted to bytes (e.g., `&[u8]`, `Vec<u8>`).
/// Non-boxed types will be automatically converted to `SecretBox` internally.
pub fn verify_nonce<S>(
    secret: S,
    nonce_b64: &str,
    now_unix: i64,
    max_age_secs: i64,
    ctx: &NonceCtx<'_>,
) -> Result<(), DpopError>
where
    S: IntoSecretBox,
{
    // Reject impossible fixed-format inputs before allocating decoded storage.
    if nonce_b64.len() != NONCE_ENCODED_LENGTH {
        return Err(DpopError::NonceMismatch);
    }
    let secret_box = secret.into_secret_box();
    let nonce_bytes = B64
        .decode(nonce_b64.as_bytes())
        .map_err(|_| DpopError::NonceMismatch)?;

    if nonce_bytes.len() != NONCE_TOTAL_LENGTH {
        return Err(DpopError::NonceMismatch);
    }

    let version = nonce_bytes[0];
    if version != NONCE_VERSION {
        return Err(DpopError::NonceMismatch);
    }

    // Safe extraction of timestamp bytes
    let timestamp_bytes: [u8; 8] = nonce_bytes
        .get(1..9)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DpopError::NonceMismatch)?;
    let timestamp = i64::from_be_bytes(timestamp_bytes);

    // Safe extraction of random and MAC bytes
    let random_bytes = nonce_bytes
        .get(9..9 + NONCE_RANDOM_LENGTH)
        .ok_or(DpopError::NonceMismatch)?;
    let mac_from_nonce = nonce_bytes
        .get(9 + NONCE_RANDOM_LENGTH..)
        .ok_or(DpopError::NonceMismatch)?;

    // Age & future skew checks
    if now_unix - timestamp > max_age_secs {
        return Err(DpopError::NonceStale);
    }
    if timestamp - now_unix > NONCE_FUTURE_SKEW_SECS {
        return Err(DpopError::FutureSkew);
    }

    // Recompute MAC
    // HMAC-SHA256 accepts keys of any length; this should never fail
    let mut hmac = HmacSha256::new_from_slice(secret_box.expose_secret())
        .map_err(|_| DpopError::InvalidHmacConfig)?;

    hmac.update(&[version]);
    hmac.update(&timestamp.to_be_bytes());
    hmac.update(random_bytes);
    hmac.update(&ctx_bytes(ctx));
    let computed_mac = hmac.finalize().into_bytes();

    if bool::from(mac_from_nonce.ct_eq(&computed_mac[..NONCE_MAC_LENGTH])) {
        Ok(())
    } else {
        Err(DpopError::NonceMismatch)
    }
}

/// Verify against multiple secrets (e.g., key rotation: current, previous).
///
/// Accepts a slice of secrets, where each secret can be either a `SecretBox<[u8]>` or any type
/// that can be converted to bytes (e.g., `&[u8]`, `Vec<u8>`).
pub fn verify_nonce_with_any<S>(
    secrets: &[S],
    nonce_b64: &str,
    now_unix: i64,
    max_age_secs: i64,
    ctx: &NonceCtx<'_>,
) -> Result<(), DpopError>
where
    S: IntoSecretBox + Clone,
{
    let mut last_error = DpopError::NonceMismatch;
    for secret in secrets {
        match verify_nonce(secret.clone(), nonce_b64, now_unix, max_age_secs, ctx) {
            Ok(()) => return Ok(()),
            Err(error @ DpopError::FutureSkew)
            | Err(error @ DpopError::NonceStale)
            | Err(error @ DpopError::NonceMismatch) => last_error = error,
            Err(error) => return Err(error),
        };
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn roundtrip_ok_with_binding() {
        let secret = SecretBox::from(b"supersecretkey".to_vec());
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let context = NonceCtx {
            htu: Some("https://ex.com/a"),
            htm: Some("POST"),
            jkt: Some("thumb"),
            client: None,
        };

        let nonce = issue_nonce(&secret, current_time, &context).expect("issue_nonce");
        assert_eq!(nonce.len(), NONCE_ENCODED_LENGTH);
        assert!(verify_nonce(&secret, &nonce, current_time, 300, &context).is_ok());
    }

    #[test]
    fn invalid_nonce_lengths_reject_before_secret_conversion() {
        struct UnusedSecret;
        impl IntoSecretBox for UnusedSecret {
            fn into_secret_box(self) -> SecretBox<[u8]> {
                panic!("invalid length must be rejected before secret conversion")
            }
        }
        let context = NonceCtx {
            htu: None,
            htm: None,
            jkt: None,
            client: None,
        };
        for length in [
            0,
            NONCE_ENCODED_LENGTH - 1,
            NONCE_ENCODED_LENGTH + 1,
            131_072,
        ] {
            assert!(matches!(
                verify_nonce(UnusedSecret, &"A".repeat(length), 0, 300, &context),
                Err(DpopError::NonceMismatch)
            ));
        }
        for character in ['*', '='] {
            let invalid = format!("{}{}", "A".repeat(NONCE_ENCODED_LENGTH - 1), character);
            assert!(matches!(
                verify_nonce(b"synthetic-secret", &invalid, 0, 300, &context),
                Err(DpopError::NonceMismatch)
            ));
        }
    }

    #[test]
    fn bad_ctx_fails() {
        let secret = SecretBox::from(b"k".to_vec());
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let original_context = NonceCtx {
            htu: Some("https://ex.com/a"),
            htm: Some("GET"),
            jkt: Some("t"),
            client: None,
        };
        let nonce = issue_nonce(&secret, current_time, &original_context).expect("issue_nonce");

        // Change HTU → should fail
        let different_context = NonceCtx {
            htu: Some("https://ex.com/b"),
            htm: Some("GET"),
            jkt: Some("t"),
            client: None,
        };
        assert!(matches!(
            verify_nonce(&secret, &nonce, current_time, 300, &different_context),
            Err(DpopError::NonceMismatch)
        ));
    }

    #[test]
    fn stale_and_future_skew() {
        let secret = SecretBox::from(b"k2".to_vec());
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let empty_context = NonceCtx {
            htu: None,
            htm: None,
            jkt: None,
            client: None,
        };

        let future_nonce =
            issue_nonce(&secret, current_time + 10, &empty_context).expect("issue_nonce");
        assert!(matches!(
            verify_nonce(&secret, &future_nonce, current_time, 300, &empty_context),
            Err(DpopError::FutureSkew)
        ));

        let stale_nonce =
            issue_nonce(&secret, current_time - 301, &empty_context).expect("issue_nonce");
        assert!(matches!(
            verify_nonce(&secret, &stale_nonce, current_time, 300, &empty_context),
            Err(DpopError::NonceStale)
        ));
    }

    #[test]
    fn rotation_any_secret() {
        let current_secret = SecretBox::from(b"current".to_vec());
        let previous_secret = SecretBox::from(b"previous".to_vec());
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let context = NonceCtx {
            htu: Some("u"),
            htm: Some("M"),
            jkt: None,
            client: None,
        };

        let nonce_from_previous =
            issue_nonce(&previous_secret, current_time, &context).expect("issue_nonce");
        assert!(verify_nonce_with_any(
            &[&current_secret, &previous_secret],
            &nonce_from_previous,
            current_time,
            300,
            &context
        )
        .is_ok());

        let nonce_from_current =
            issue_nonce(&current_secret, current_time, &context).expect("issue_nonce");
        assert!(verify_nonce_with_any(
            &[&current_secret, &previous_secret],
            &nonce_from_current,
            current_time,
            300,
            &context
        )
        .is_ok());
    }

    #[test]
    fn accepts_non_boxed_types() {
        // Test that functions accept &[u8] directly
        let secret_bytes = b"test-secret";
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let context = NonceCtx {
            htu: Some("https://ex.com/a"),
            htm: Some("GET"),
            jkt: Some("thumb"),
            client: None,
        };

        let nonce =
            issue_nonce(secret_bytes.as_slice(), current_time, &context).expect("issue_nonce");
        assert!(verify_nonce(secret_bytes.as_slice(), &nonce, current_time, 300, &context).is_ok());

        // Test with Vec<u8>
        let secret_vec = b"test-secret-vec".to_vec();
        let nonce2 = issue_nonce(&secret_vec, current_time, &context).expect("issue_nonce");
        assert!(verify_nonce(&secret_vec, &nonce2, current_time, 300, &context).is_ok());
    }
}

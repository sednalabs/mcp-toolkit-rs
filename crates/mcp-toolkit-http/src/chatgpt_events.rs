//! # ChatGPT webhook preparation
//!
//! ## Rationale
//! Prepare the documented event envelope, Standard Webhooks headers, and signed
//! JSON callback-verification challenge without performing I/O. Enable the
//! `chatgpt-events` feature to use these helpers.
//!
//! ## Security boundaries
//! No network, DNS, clock reads, persistence, dispatch or retries occur here.
//! The application owns authentication, callback/principal binding, HTTPS and
//! public-address egress checks (including DNS rebinding and redirects), current
//! access checks, protected key storage, rotation eligibility, durable single-use
//! verification and subscription activation. A successful echo is not authority
//! to deliver events. Bound response reads before passing their bytes here.
//!
//! Bodies are serialized once with a capped writer and borrowed unchanged by
//! each signed attempt. Debug and errors omit bodies, keys, challenges and
//! signatures. Explicit body/header access is sensitive; it must not be logged.
//! In-memory redaction does not promise zeroization or encrypted storage.
//!
//! ## References
//! * [ChatGPT MCP Events](https://developers.openai.com/plugins/build/mcp-events)
//! * [Standard Webhooks](https://www.standardwebhooks.com/)

use std::fmt;
use std::io::{self, Write};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode};
use mcp_toolkit_core::chatgpt_events::validate_signing_secret;
use serde::de::{value::MapAccessDeserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use standardwebhooks::Webhook;
use subtle::ConstantTimeEq;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub use mcp_toolkit_core::chatgpt_events::MAX_EVENT_BODY_BYTES;

/// Maximum byte length of an event/message or subscription header identifier.
pub const MAX_HEADER_ID_BYTES: usize = 256;
/// Required entropy input size; callers supply fresh cryptographically random bytes.
pub const CHALLENGE_NONCE_BYTES: usize = 32;
/// Maximum accepted callback-verification JSON response size, including whitespace.
pub const MAX_CHALLENGE_RESPONSE_BYTES: usize = 1024;

const ENCODED_CHALLENGE_BYTES: usize = 43;

/// Reports a safe category without including sensitive input or parser excerpts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookPreparationError {
    InvalidSigningSecret,
    InvalidIdentifier,
    InvalidEvent,
    InvalidTimestamp,
    BodyTooLarge,
    SerializationFailed,
    SigningFailed,
    InvalidChallengeLifetime,
    ChallengeExpired,
    UnsuccessfulResponse,
    InvalidChallengeResponse,
}

impl fmt::Display for WebhookPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSigningSecret => "invalid webhook signing secret",
            Self::InvalidIdentifier => "invalid webhook header identifier",
            Self::InvalidEvent => "invalid webhook event envelope",
            Self::InvalidTimestamp => "invalid webhook timestamp",
            Self::BodyTooLarge => "webhook body exceeds size limit",
            Self::SerializationFailed => "webhook serialization failed",
            Self::SigningFailed => "webhook signing failed",
            Self::InvalidChallengeLifetime => "invalid webhook challenge lifetime",
            Self::ChallengeExpired => "webhook challenge outside its validity interval",
            Self::UnsuccessfulResponse => "webhook verification response is not successful",
            Self::InvalidChallengeResponse => "invalid webhook verification response",
        })
    }
}

impl std::error::Error for WebhookPreparationError {}

/// Supplies a typed event envelope; `data` is always an object and `cursor` a string or null.
///
/// The timestamp is the source event time, independent of each delivery attempt's
/// signing timestamp. The wire body has no application `type` field.
pub struct EventEnvelope<'a> {
    pub event_id: &'a str,
    pub name: &'a str,
    pub timestamp: OffsetDateTime,
    pub data: &'a Map<String, Value>,
    pub cursor: Option<&'a str>,
}

impl fmt::Debug for EventEnvelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventEnvelope").finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireEvent<'a> {
    event_id: &'a str,
    name: &'a str,
    timestamp: String,
    data: &'a Map<String, Value>,
    cursor: Option<&'a str>,
}

/// Retains immutable, bounded JSON bytes for repeat signing without reserialization.
#[derive(Clone)]
pub struct PreparedWebhook {
    message_id: String,
    body: Box<[u8]>,
}

impl fmt::Debug for PreparedWebhook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedWebhook").finish_non_exhaustive()
    }
}

impl PreparedWebhook {
    /// Serializes an event exactly once into at most 256 KiB of UTF-8 JSON.
    ///
    /// # Errors
    /// Rejects invalid identifiers, blank/over-256-byte names, over-4096-byte
    /// cursors, non-RFC3339 timestamps, and bodies exceeding the byte budget.
    ///
    /// # Security
    /// This validates wire shape only. Authorize and schema-check data first.
    /// IDs must contain 1..=256 ASCII letters, digits, `-`, `_`, `.`, or `:`.
    /// Reuse this object for retries but sign each attempt with explicit fresh time.
    ///
    /// ```
    /// use mcp_toolkit_http::chatgpt_events::{EventEnvelope, PreparedWebhook, WebhookSigner};
    /// use serde_json::{Map, Value};
    /// use time::OffsetDateTime;
    /// let data = Map::<String, Value>::new();
    /// let body = PreparedWebhook::event(EventEnvelope {
    ///     event_id: "evt_1", name: "item.changed",
    ///     timestamp: OffsetDateTime::from_unix_timestamp(1_700_000_000)?,
    ///     data: &data, cursor: None,
    /// })?;
    /// // This public test key is not suitable for production.
    /// let signer = WebhookSigner::new("whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None)?;
    /// let attempt = body.sign(&signer, "sub_1", 1_700_000_001)?;
    /// assert_eq!(attempt.body(), body.body());
    /// assert_eq!(attempt.headers()["webhook-id"], "evt_1");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn event(event: EventEnvelope<'_>) -> Result<Self, WebhookPreparationError> {
        validate_identifier(event.event_id)?;
        if event.name.trim().is_empty()
            || event.name.len() > 256
            || event.cursor.is_some_and(|cursor| cursor.len() > 4096)
        {
            return Err(WebhookPreparationError::InvalidEvent);
        }
        let timestamp = event
            .timestamp
            .format(&Rfc3339)
            .map_err(|_| WebhookPreparationError::InvalidTimestamp)?;
        Self::serialize(
            event.event_id,
            &WireEvent {
                event_id: event.event_id,
                name: event.name,
                timestamp,
                data: event.data,
                cursor: event.cursor,
            },
        )
    }

    fn serialize(
        message_id: &str,
        value: &impl Serialize,
    ) -> Result<Self, WebhookPreparationError> {
        validate_identifier(message_id)?;
        let mut writer = BoundedBody::new();
        if serde_json::to_writer(&mut writer, value).is_err() {
            return Err(if writer.exceeded {
                WebhookPreparationError::BodyTooLarge
            } else {
                WebhookPreparationError::SerializationFailed
            });
        }
        Ok(Self {
            message_id: message_id.to_owned(),
            body: writer.bytes.into_boxed_slice(),
        })
    }

    /// Borrows the exact sensitive JSON bytes; do not log them.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Signs these same bytes and constructs the five required HTTP headers.
    ///
    /// # Errors
    /// Rejects invalid subscription IDs, negative/unrepresentable Unix seconds,
    /// or signing/header conversion failure.
    ///
    /// # Security
    /// Supply current Unix seconds for every attempt; this does not read a clock.
    /// Authorize dispatch, callback egress and both keys before calling. A signed
    /// result is preparation, not authorization, persistence or an automatic retry.
    pub fn sign<'a>(
        &'a self,
        signer: &WebhookSigner,
        subscription_id: &str,
        unix_timestamp: i64,
    ) -> Result<SignedWebhook<'a>, WebhookPreparationError> {
        validate_identifier(subscription_id)?;
        validate_timestamp(unix_timestamp)?;
        let signature = signer.sign(&self.message_id, unix_timestamp, &self.body)?;
        let mut headers = HeaderMap::with_capacity(5);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("webhook-id", header_value(&self.message_id)?);
        headers.insert(
            "webhook-timestamp",
            header_value(&unix_timestamp.to_string())?,
        );
        let mut signature = header_value(&signature)?;
        signature.set_sensitive(true);
        headers.insert("webhook-signature", signature);
        headers.insert("x-mcp-subscription-id", header_value(subscription_id)?);
        Ok(SignedWebhook {
            body: &self.body,
            headers,
        })
    }
}

/// Holds a validated current signing key and at most one previous key.
///
/// The application decides whether the previous key remains eligible. No key
/// generation, rotation policy, storage, logging or zeroization is supplied.
pub struct WebhookSigner {
    current: Webhook,
    previous: Option<Webhook>,
}

impl fmt::Debug for WebhookSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSigner").finish_non_exhaustive()
    }
}

impl WebhookSigner {
    /// Validates each key through the core `whsec_`/24..=64-byte contract.
    ///
    /// # Errors
    /// Rejects either invalid key without exposing its contents.
    ///
    /// # Security
    /// Caller supplies cryptographically random keys from protected storage.
    /// Format validation cannot establish key entropy, consent or eligibility.
    pub fn new(current: &str, previous: Option<&str>) -> Result<Self, WebhookPreparationError> {
        fn key(secret: &str) -> Result<Webhook, WebhookPreparationError> {
            validate_signing_secret(secret)
                .map_err(|_| WebhookPreparationError::InvalidSigningSecret)?;
            Webhook::new(secret).map_err(|_| WebhookPreparationError::InvalidSigningSecret)
        }
        Ok(Self {
            current: key(current)?,
            previous: previous.map(key).transpose()?,
        })
    }

    fn sign(
        &self,
        message_id: &str,
        unix_timestamp: i64,
        body: &[u8],
    ) -> Result<String, WebhookPreparationError> {
        let mut signature = self
            .current
            .sign(message_id, unix_timestamp, body)
            .map_err(|_| WebhookPreparationError::SigningFailed)?;
        if let Some(previous) = &self.previous {
            let older_signature = previous
                .sign(message_id, unix_timestamp, body)
                .map_err(|_| WebhookPreparationError::SigningFailed)?;
            signature.push(' ');
            signature.push_str(&older_signature);
        }
        Ok(signature)
    }
}

/// Borrows the exact prepared body alongside immutable signed headers.
pub struct SignedWebhook<'a> {
    body: &'a [u8],
    headers: HeaderMap,
}

impl fmt::Debug for SignedWebhook<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedWebhook").finish_non_exhaustive()
    }
}

impl SignedWebhook<'_> {
    /// Borrows sensitive body bytes for the caller's authorized HTTP client.
    pub fn body(&self) -> &[u8] {
        self.body
    }

    /// Borrows signed headers; the signature value is marked sensitive.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

/// Owns one JSON callback challenge and consumes itself on any verification attempt.
///
/// This type is deliberately not Clone or serializable. Its in-memory ownership
/// does not replace durable single-use state or callback/principal binding.
pub struct PendingChallenge {
    request: PreparedWebhook,
    expected: [u8; ENCODED_CHALLENGE_BYTES],
    issued_at: i64,
    deadline: i64,
}

impl fmt::Debug for PendingChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingChallenge").finish_non_exhaustive()
    }
}

impl PendingChallenge {
    /// Prepares signed-JSON challenge content from caller-supplied fresh entropy.
    ///
    /// # Errors
    /// Rejects invalid message IDs/timestamps, a deadline not later than issuance,
    /// or body serialization failure.
    ///
    /// # Security
    /// Supply a fresh cryptographic 32-byte nonce and unique message ID for every
    /// callback verification. The helper cannot detect reuse or weak randomness.
    /// Bind the pending challenge to the exact callback, principal and generation
    /// in durable application state. Neither time nor randomness is generated here.
    ///
    /// ```
    /// use mcp_toolkit_http::chatgpt_events::{PendingChallenge, WebhookSigner};
    /// use http::StatusCode;
    /// // Deterministic test values only; production needs fresh cryptographic entropy.
    /// let pending = PendingChallenge::new("verify_1", [7; 32], 100, 130)?;
    /// let signer = WebhookSigner::new("whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None)?;
    /// let request = pending.sign(&signer, "sub_1", 101)?;
    /// let json: serde_json::Value = serde_json::from_slice(request.body())?;
    /// let echo = serde_json::to_vec(&serde_json::json!({"challenge": json["challenge"]}))?;
    /// pending.verify(StatusCode::OK, &echo, 102)?;
    /// // Persist the bound single-use result before application-controlled activation.
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(
        message_id: &str,
        nonce: [u8; CHALLENGE_NONCE_BYTES],
        issued_at: i64,
        deadline: i64,
    ) -> Result<Self, WebhookPreparationError> {
        validate_timestamp(issued_at)?;
        validate_timestamp(deadline)?;
        if deadline <= issued_at {
            return Err(WebhookPreparationError::InvalidChallengeLifetime);
        }
        let challenge = URL_SAFE_NO_PAD.encode(nonce);
        let expected = challenge
            .as_bytes()
            .try_into()
            .map_err(|_| WebhookPreparationError::SerializationFailed)?;
        #[derive(Serialize)]
        struct Verification<'a> {
            #[serde(rename = "type")]
            kind: &'static str,
            challenge: &'a str,
        }
        Ok(Self {
            request: PreparedWebhook::serialize(
                message_id,
                &Verification {
                    kind: "verification",
                    challenge: &challenge,
                },
            )?,
            expected,
            issued_at,
            deadline,
        })
    }

    /// Signs the verification JSON during its explicit validity interval.
    ///
    /// # Errors
    /// Rejects times outside `[issued_at, deadline)` and any signing input error.
    ///
    /// # Security
    /// Bind and authorize the destination before sending; this performs no I/O.
    pub fn sign<'a>(
        &'a self,
        signer: &WebhookSigner,
        subscription_id: &str,
        unix_timestamp: i64,
    ) -> Result<SignedWebhook<'a>, WebhookPreparationError> {
        self.check_time(unix_timestamp)?;
        self.request.sign(signer, subscription_id, unix_timestamp)
    }

    /// Consumes this challenge and verifies a bounded 2xx JSON challenge echo.
    ///
    /// # Errors
    /// Rejects non-2xx status, time outside `[issued_at, deadline)`, oversized or
    /// malformed JSON, arrays, unknown/duplicate fields, trailing values, wrong
    /// types/lengths, and a challenge mismatch. Failure also consumes the value.
    ///
    /// # Security
    /// Compare only fixed-length bytes using `subtle`; parsing and length checks
    /// are not constant-time. Bind the actual HTTP response to this callback and
    /// principal. Independently consume durable state and authorize activation.
    /// This is the ChatGPT JSON echo protocol, not a header-MAC challenge protocol.
    ///
    /// ```compile_fail
    /// use mcp_toolkit_http::chatgpt_events::PendingChallenge;
    /// use http::StatusCode;
    /// let pending = PendingChallenge::new("verify_1", [7; 32], 100, 130).unwrap();
    /// let _ = pending.verify(StatusCode::OK, b"{}", 101);
    /// let _ = pending.verify(StatusCode::OK, b"{}", 101); // already consumed
    /// ```
    pub fn verify(
        self,
        status: StatusCode,
        response: &[u8],
        unix_timestamp: i64,
    ) -> Result<(), WebhookPreparationError> {
        self.check_time(unix_timestamp)?;
        if !status.is_success() {
            return Err(WebhookPreparationError::UnsuccessfulResponse);
        }
        if response.len() > MAX_CHALLENGE_RESPONSE_BYTES {
            return Err(WebhookPreparationError::InvalidChallengeResponse);
        }
        let echo = parse_echo(response)?;
        let received: &[u8; ENCODED_CHALLENGE_BYTES] = echo
            .challenge
            .as_bytes()
            .try_into()
            .map_err(|_| WebhookPreparationError::InvalidChallengeResponse)?;
        if bool::from(self.expected.ct_eq(received)) {
            Ok(())
        } else {
            Err(WebhookPreparationError::InvalidChallengeResponse)
        }
    }

    fn check_time(&self, unix_timestamp: i64) -> Result<(), WebhookPreparationError> {
        if unix_timestamp < self.issued_at || unix_timestamp >= self.deadline {
            Err(WebhookPreparationError::ChallengeExpired)
        } else {
            Ok(())
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeEcho {
    challenge: String,
}

fn parse_echo(response: &[u8]) -> Result<ChallengeEcho, WebhookPreparationError> {
    // Derived structs alone accept positional arrays. Force the map entrypoint
    // while retaining serde's duplicate/unknown-field rejection.
    struct EchoVisitor;
    impl<'de> Visitor<'de> for EchoVisitor {
        type Value = ChallengeEcho;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON challenge object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            ChallengeEcho::deserialize(MapAccessDeserializer::new(map))
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(response);
    let echo = serde::Deserializer::deserialize_map(&mut deserializer, EchoVisitor)
        .map_err(|_| WebhookPreparationError::InvalidChallengeResponse)?;
    deserializer
        .end()
        .map_err(|_| WebhookPreparationError::InvalidChallengeResponse)?;
    Ok(echo)
}

fn validate_identifier(value: &str) -> Result<(), WebhookPreparationError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_ID_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(WebhookPreparationError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_timestamp(value: i64) -> Result<(), WebhookPreparationError> {
    if value < 0 || OffsetDateTime::from_unix_timestamp(value).is_err() {
        return Err(WebhookPreparationError::InvalidTimestamp);
    }
    Ok(())
}

fn header_value(value: &str) -> Result<HeaderValue, WebhookPreparationError> {
    HeaderValue::from_str(value).map_err(|_| WebhookPreparationError::SigningFailed)
}

struct BoundedBody {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl BoundedBody {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_EVENT_BODY_BYTES),
            exceeded: false,
        }
    }
}

impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_EVENT_BODY_BYTES - self.bytes.len() {
            self.exceeded = true;
            return Err(io::Error::other("webhook body exceeds size limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;

    // Public Standard Webhooks interoperability fixture, not a production key.
    const SECRET: &str = "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";
    const NOW: i64 = 1_649_367_553;

    fn event(data: &Map<String, Value>) -> Result<PreparedWebhook, WebhookPreparationError> {
        PreparedWebhook::event(EventEnvelope {
            event_id: "evt_1",
            name: "item.changed",
            timestamp: OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
            data,
            cursor: None,
        })
    }

    fn pending() -> PendingChallenge {
        PendingChallenge::new("verify_1", [7; CHALLENGE_NONCE_BYTES], NOW, NOW + 30).unwrap()
    }

    fn echo() -> Vec<u8> {
        serde_json::to_vec(&json!({"challenge": URL_SAFE_NO_PAD.encode([7; 32])})).unwrap()
    }

    #[test]
    fn official_standard_webhooks_fixed_signature_vector() {
        let signer = WebhookSigner::new(SECRET, None).unwrap();
        assert_eq!(
            signer
                .sign(
                    "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk",
                    NOW,
                    br#"{"email":"test@example.com","username":"test_user"}"#,
                )
                .unwrap(),
            "v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw="
        );
    }

    #[test]
    fn exact_utf8_escaping_envelope_and_signed_bytes() {
        let data = json!({"text": "héllo\n\"\\"}).as_object().unwrap().clone();
        let body = event(&data).unwrap();
        let expected = concat!(
            "{\"eventId\":\"evt_1\",\"name\":\"item.changed\",",
            "\"timestamp\":\"2022-04-07T21:39:13Z\",",
            "\"data\":{\"text\":\"héllo\\n\\\"\\\\\"},\"cursor\":null}"
        );
        assert_eq!(body.body(), expected.as_bytes());
        let signer = WebhookSigner::new(SECRET, None).unwrap();
        let signed = body.sign(&signer, "sub_1", NOW).unwrap();
        assert!(std::ptr::eq(signed.body(), body.body()));
        assert_eq!(signed.headers().len(), 5);
        assert_eq!(signed.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(signed.headers()["webhook-id"], "evt_1");
        assert_eq!(signed.headers()["webhook-timestamp"], NOW.to_string());
        assert_eq!(signed.headers()["x-mcp-subscription-id"], "sub_1");
        assert!(signed.headers()["webhook-signature"].is_sensitive());
        assert_eq!(
            signed.headers()["webhook-signature"],
            Webhook::new(SECRET)
                .unwrap()
                .sign("evt_1", NOW, expected.as_bytes())
                .unwrap()
        );
        let decoded: Value = serde_json::from_slice(body.body()).unwrap();
        assert_eq!(decoded.as_object().unwrap().len(), 5);
        assert!(decoded.get("type").is_none());
        assert_eq!(decoded["data"], Value::Object(data));
    }

    #[test]
    fn retries_reuse_event_identity_and_body_but_sign_with_fresh_timestamp() {
        let body = event(&Map::new()).unwrap();
        let signer = WebhookSigner::new(SECRET, None).unwrap();
        let first = body.sign(&signer, "sub_1", NOW).unwrap();
        let retry = body.sign(&signer, "sub_1", NOW + 10).unwrap();
        assert!(std::ptr::eq(first.body(), retry.body()));
        assert_eq!(first.headers()["webhook-id"], retry.headers()["webhook-id"]);
        assert_ne!(
            first.headers()["webhook-signature"],
            retry.headers()["webhook-signature"]
        );
        assert_ne!(
            first.headers()["webhook-timestamp"],
            retry.headers()["webhook-timestamp"]
        );
        assert_eq!(
            retry.headers()["webhook-signature"],
            Webhook::new(SECRET)
                .unwrap()
                .sign("evt_1", NOW + 10, retry.body())
                .unwrap()
        );
    }

    #[test]
    fn rotation_signatures_each_verify_the_same_body() {
        // The published verifier reads a clock. Only this interoperability test
        // uses wall time; every toolkit preparation API takes explicit time.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let previous = format!("whsec_{}", STANDARD.encode([9; 32]));
        let signer = WebhookSigner::new(SECRET, Some(&previous)).unwrap();
        let body = event(&Map::new()).unwrap();
        let signed = body.sign(&signer, "sub_1", now).unwrap();
        let signatures: Vec<_> = signed.headers()["webhook-signature"]
            .to_str()
            .unwrap()
            .split(' ')
            .collect();
        assert_eq!(signatures.len(), 2);
        for (secret, signature) in [SECRET, previous.as_str()].into_iter().zip(signatures) {
            let mut headers = signed.headers().clone();
            headers.insert(
                "webhook-signature",
                HeaderValue::from_str(signature).unwrap(),
            );
            Webhook::new(secret)
                .unwrap()
                .verify(signed.body(), &headers)
                .unwrap();
        }
    }

    #[test]
    fn writer_enforces_exact_limit_before_appending() {
        let mut writer = BoundedBody::new();
        writer.write_all(&vec![b'x'; MAX_EVENT_BODY_BYTES]).unwrap();
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes.len(), MAX_EVENT_BODY_BYTES);
        assert!(writer.exceeded);
        let mut writer = BoundedBody::new();
        assert!(writer
            .write_all(&vec![0; MAX_EVENT_BODY_BYTES + 1])
            .is_err());
        assert!(writer.bytes.is_empty());
    }

    #[test]
    fn serialized_complete_body_limit_and_one_byte_over() {
        let mut data = json!({"text": ""}).as_object().unwrap().clone();
        let overhead = event(&data).unwrap().body().len();
        data.insert(
            "text".into(),
            json!("x".repeat(MAX_EVENT_BODY_BYTES - overhead)),
        );
        assert_eq!(event(&data).unwrap().body().len(), MAX_EVENT_BODY_BYTES);
        data["text"] = json!("x".repeat(MAX_EVENT_BODY_BYTES - overhead + 1));
        assert!(matches!(
            event(&data),
            Err(WebhookPreparationError::BodyTooLarge)
        ));
        data["text"] = json!("\n".repeat(MAX_EVENT_BODY_BYTES / 2));
        assert!(matches!(
            event(&data),
            Err(WebhookPreparationError::BodyTooLarge)
        ));
    }

    #[test]
    fn signer_reuses_strict_core_validation_for_both_keys() {
        for length in [24, 32, 64] {
            let secret = format!("whsec_{}", STANDARD.encode(vec![7; length]));
            assert!(WebhookSigner::new(&secret, Some(&secret)).is_ok());
        }
        for secret in [
            "".to_owned(),
            "whsec_".to_owned(),
            "AAAA".to_owned(),
            "whsec_!!!!".to_owned(),
            "whsec_private-marker".to_owned(),
            format!("whsec_{}", STANDARD.encode([7; 23])),
            format!("whsec_{}", STANDARD.encode([7; 65])),
        ] {
            for result in [
                WebhookSigner::new(&secret, None),
                WebhookSigner::new(SECRET, Some(&secret)),
            ] {
                let error = result.unwrap_err();
                assert_eq!(error, WebhookPreparationError::InvalidSigningSecret);
                assert!(!error.to_string().contains("private-marker"));
            }
        }
    }

    #[test]
    fn header_ids_reject_injection_whitespace_unicode_and_oversize() {
        let signer = WebhookSigner::new(SECRET, None).unwrap();
        let body = event(&Map::new()).unwrap();
        for id in [
            "",
            " ",
            "foo bar",
            "a\r\nwebhook-id:x",
            "é",
            "a\t",
            "a\0",
            "a,b",
        ] {
            assert_eq!(
                validate_identifier(id),
                Err(WebhookPreparationError::InvalidIdentifier)
            );
            assert!(matches!(
                body.sign(&signer, id, NOW),
                Err(WebhookPreparationError::InvalidIdentifier)
            ));
            assert!(matches!(
                PendingChallenge::new(id, [7; 32], NOW, NOW + 1),
                Err(WebhookPreparationError::InvalidIdentifier)
            ));
        }
        assert!(validate_identifier("AZaz09-_.:").is_ok());
        assert!(validate_identifier(&"x".repeat(MAX_HEADER_ID_BYTES)).is_ok());
        assert_eq!(
            validate_identifier(&"x".repeat(MAX_HEADER_ID_BYTES + 1)),
            Err(WebhookPreparationError::InvalidIdentifier)
        );
        for timestamp in [-1, i64::MIN, i64::MAX] {
            assert!(matches!(
                body.sign(&signer, "sub_1", timestamp),
                Err(WebhookPreparationError::InvalidTimestamp)
            ));
        }
    }

    #[test]
    fn typed_event_validates_name_cursor_timestamp_and_id() {
        let data = Map::new();
        let valid = || EventEnvelope {
            event_id: "evt_1",
            name: "item.changed",
            timestamp: OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
            data: &data,
            cursor: Some("opaque-cursor"),
        };
        let mut input = valid();
        input.event_id = "invalid id";
        assert!(matches!(
            PreparedWebhook::event(input),
            Err(WebhookPreparationError::InvalidIdentifier)
        ));
        for name in ["".to_owned(), " \n".to_owned(), "é".repeat(129)] {
            let mut input = valid();
            input.name = &name;
            assert!(matches!(
                PreparedWebhook::event(input),
                Err(WebhookPreparationError::InvalidEvent)
            ));
        }
        let cursor = "x".repeat(4097);
        let mut input = valid();
        input.cursor = Some(&cursor);
        assert!(matches!(
            PreparedWebhook::event(input),
            Err(WebhookPreparationError::InvalidEvent)
        ));
        let mut input = valid();
        input.timestamp = input
            .timestamp
            .to_offset(time::UtcOffset::from_hms(1, 2, 3).unwrap());
        assert!(matches!(
            PreparedWebhook::event(input),
            Err(WebhookPreparationError::InvalidTimestamp)
        ));
        let mut input = valid();
        input.timestamp = input
            .timestamp
            .to_offset(time::UtcOffset::from_hms(2, 0, 0).unwrap());
        let body = PreparedWebhook::event(input).unwrap();
        let json: Value = serde_json::from_slice(body.body()).unwrap();
        assert!(json["timestamp"].as_str().unwrap().ends_with("+02:00"));
        assert_eq!(json["cursor"], "opaque-cursor");
    }

    #[test]
    fn debug_redacts_every_sensitive_wrapper() {
        let signer = WebhookSigner::new(SECRET, None).unwrap();
        let body = event(
            json!({"private-marker":"private-body"})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        let signed = body.sign(&signer, "sub_1", NOW).unwrap();
        assert_eq!(format!("{signer:?}"), "WebhookSigner { .. }");
        assert_eq!(format!("{body:?}"), "PreparedWebhook { .. }");
        assert_eq!(format!("{signed:?}"), "SignedWebhook { .. }");
        assert_eq!(format!("{:?}", pending()), "PendingChallenge { .. }");
        assert!(!format!("{:?}", signed.headers())
            .contains(signed.headers()["webhook-signature"].to_str().unwrap()));
    }

    #[test]
    fn challenge_body_has_json_verification_contract_and_valid_signature() {
        let pending = pending();
        let signer = WebhookSigner::new(SECRET, None).unwrap();
        let signed = pending.sign(&signer, "sub_1", NOW + 1).unwrap();
        let decoded: Value = serde_json::from_slice(signed.body()).unwrap();
        assert_eq!(
            decoded,
            json!({"type": "verification", "challenge": URL_SAFE_NO_PAD.encode([7; 32])})
        );
        assert_eq!(signed.headers()["webhook-id"], "verify_1");
        assert_eq!(
            signed.headers()["webhook-signature"],
            Webhook::new(SECRET)
                .unwrap()
                .sign("verify_1", NOW + 1, signed.body())
                .unwrap()
        );
        pending.verify(StatusCode::OK, &echo(), NOW + 1).unwrap();
    }

    #[test]
    fn challenge_accepts_only_success_and_explicit_validity_interval() {
        for status in [200, 201, 204, 299] {
            assert!(pending()
                .verify(StatusCode::from_u16(status).unwrap(), &echo(), NOW)
                .is_ok());
        }
        for status in [100, 199, 300, 302, 400, 401, 500] {
            assert_eq!(
                pending().verify(StatusCode::from_u16(status).unwrap(), &echo(), NOW),
                Err(WebhookPreparationError::UnsuccessfulResponse)
            );
        }
        assert!(pending().verify(StatusCode::OK, &echo(), NOW + 29).is_ok());
        let signer = WebhookSigner::new(SECRET, None).unwrap();
        for time in [NOW - 1, NOW + 30, i64::MIN, i64::MAX] {
            assert_eq!(
                pending().verify(StatusCode::OK, &echo(), time),
                Err(WebhookPreparationError::ChallengeExpired)
            );
            assert!(matches!(
                pending().sign(&signer, "sub_1", time),
                Err(WebhookPreparationError::ChallengeExpired)
            ));
        }
        for deadline in [NOW - 1, NOW] {
            assert!(matches!(
                PendingChallenge::new("v_1", [7; 32], NOW, deadline),
                Err(WebhookPreparationError::InvalidChallengeLifetime)
            ));
        }
        for (issued, deadline) in [(-1, NOW), (NOW, i64::MAX)] {
            assert!(matches!(
                PendingChallenge::new("v_1", [7; 32], issued, deadline),
                Err(WebhookPreparationError::InvalidTimestamp)
            ));
        }
    }

    #[test]
    fn challenge_rejects_bad_shape_duplicate_trailing_and_wrong_values() {
        let challenge = URL_SAFE_NO_PAD.encode([7; 32]);
        for response in [
            "null".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            format!("[\"{challenge}\"]"),
            format!("\"{challenge}\""),
            "{\"challenge\":null}".to_owned(),
            "{\"challenge\":42}".to_owned(),
            "{\"challenge\":{}}".to_owned(),
            "{\"challenge\":[]}".to_owned(),
            "{\"challenge\":\"short\"}".to_owned(),
            format!("{{\"challenge\":\"{challenge}\",\"challenge\":\"{challenge}\"}}"),
            format!("{{\"challenge\":\"{challenge}\",\"extra\":true}}"),
            format!("{{\"challenge\":\"{challenge}\"}} {{}}"),
            format!("{{\"challenge\":\"{}\"}}", URL_SAFE_NO_PAD.encode([8; 32])),
            format!("{{\"challenge\":\"{challenge}x\"}}"),
        ] {
            assert_eq!(
                pending().verify(StatusCode::OK, response.as_bytes(), NOW),
                Err(WebhookPreparationError::InvalidChallengeResponse)
            );
        }
        assert_eq!(
            pending().verify(StatusCode::OK, &[0xff], NOW),
            Err(WebhookPreparationError::InvalidChallengeResponse)
        );
    }

    #[test]
    fn response_budget_accepts_exact_boundary_and_rejects_one_over() {
        let mut response = echo();
        response.resize(MAX_CHALLENGE_RESPONSE_BYTES, b' ');
        assert!(pending().verify(StatusCode::OK, &response, NOW).is_ok());
        response.push(b' ');
        assert_eq!(
            pending().verify(StatusCode::OK, &response, NOW),
            Err(WebhookPreparationError::InvalidChallengeResponse)
        );
    }

    #[test]
    fn deterministic_fuzz_of_challenge_parser_and_consuming_verifier() {
        let mut state = 13_u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as usize
        };
        let check = |bytes: &[u8]| {
            if pending().verify(StatusCode::OK, bytes, NOW).is_ok() {
                let value: Value = serde_json::from_slice(bytes).unwrap();
                assert_eq!(value, json!({"challenge": URL_SAFE_NO_PAD.encode([7; 32])}));
                assert!(bytes.len() <= MAX_CHALLENGE_RESPONSE_BYTES);
            }
        };
        for length in 0..512 {
            check(&(0..length).map(|_| next() as u8).collect::<Vec<_>>());
        }
        let seed = echo();
        check(&seed);
        for _ in 0..4096 {
            let mut bytes = seed.clone();
            for _ in 0..1 + next() % 8 {
                let index = next() % (bytes.len() + 1);
                match next() % 4 {
                    0 if index < bytes.len() => bytes[index] = next() as u8,
                    1 if index < bytes.len() => {
                        bytes.remove(index);
                    }
                    2 => bytes.insert(index, next() as u8),
                    _ => bytes.truncate(index),
                }
            }
            check(&bytes);
        }
    }
}

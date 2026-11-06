//! # ChatGPT webhook Events requests
//!
//! ## Rationale
//! Decode the documented ChatGPT webhook subset without coupling an MCP server
//! to a particular event source, database, recipient runtime, or HTTP client.
//! Reuse the toolkit canonical JSON profile for stable subscription identity.
//!
//! ## Security boundaries
//! These are wire-contract helpers, not an Events service. Parsing does not
//! authorize a subscription, validate callback network destinations, verify a
//! challenge, sign a request, persist state, or send anything. The application
//! must perform those checks and must recheck current access before each send.
//! Callback URLs, signing keys, selectors and cursors are omitted from Debug.
//! JSON arguments use serde_json semantics; validate the same parsed arguments
//! for authorization and event-schema checks. Duplicate keys discarded inside
//! argument objects cannot be recovered by canonicalization.
//!
//! ## References
//! * [ChatGPT MCP Events](https://developers.openai.com/plugins/build/mcp-events)
//! * [Draft Events design](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md)

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};

use crate::canonical_json::CanonicalJsonIdentity;

/// Local input budget, independent of the protocol's delivery-body limit.
pub const MAX_SUBSCRIPTION_REQUEST_BYTES: usize = 64 * 1024;

/// Complete webhook event bodies must not exceed this number of UTF-8 bytes.
pub const MAX_EVENT_BODY_BYTES: usize = 256 * 1024;

/// A safe error category that never includes request values or parser excerpts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventRequestError {
    RequestTooLarge,
    InvalidRequest,
    InvalidSigningSecret,
    InvalidPrincipal,
    InvalidLifetimePolicy,
}

impl fmt::Display for EventRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RequestTooLarge => "event subscription request exceeds size limit",
            Self::InvalidRequest => "invalid event subscription request",
            Self::InvalidSigningSecret => "invalid webhook signing secret",
            Self::InvalidPrincipal => "invalid authenticated subscription principal",
            Self::InvalidLifetimePolicy => "invalid subscription lifetime policy",
        })
    }
}

impl std::error::Error for EventRequestError {}

/// Distinguishes an omitted lifetime from an explicit request for no expiry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RequestedLifetime {
    #[default]
    ServerDefault,
    NoExpiry,
    Milliseconds(u64),
}

impl<'de> Deserialize<'de> for RequestedLifetime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<u64>::deserialize(deserializer).map(|value| match value {
            Some(milliseconds) => Self::Milliseconds(milliseconds),
            None => Self::NoExpiry,
        })
    }
}

impl RequestedLifetime {
    /// Grants a finite duration according to explicit server policy.
    ///
    /// A request for no expiry may receive the server's finite default. A
    /// suggestion is capped at the maximum and clamped up only to the minimum.
    /// This does not start a timer or persist an expiry.
    ///
    /// # Errors
    /// Rejects a zero minimum or a default outside the inclusive policy range.
    ///
    /// ```
    /// use mcp_toolkit_core::chatgpt_events::RequestedLifetime;
    /// assert_eq!(RequestedLifetime::Milliseconds(10).grant_finite_ms(900, 100, 3600)?, 100);
    /// assert_eq!(RequestedLifetime::NoExpiry.grant_finite_ms(900, 100, 3600)?, 900);
    /// # Ok::<(), mcp_toolkit_core::chatgpt_events::EventRequestError>(())
    /// ```
    pub fn grant_finite_ms(
        self,
        default_ms: u64,
        minimum_ms: u64,
        maximum_ms: u64,
    ) -> Result<u64, EventRequestError> {
        if minimum_ms == 0 || default_ms < minimum_ms || default_ms > maximum_ms {
            return Err(EventRequestError::InvalidLifetimePolicy);
        }
        Ok(match self {
            Self::Milliseconds(milliseconds) => milliseconds.clamp(minimum_ms, maximum_ms),
            Self::ServerDefault | Self::NoExpiry => default_ms,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubscribe {
    name: String,
    arguments: Map<String, Value>,
    delivery: RawDelivery,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default, rename = "maxAgeMs")]
    max_age_ms: Option<u64>,
    #[serde(default, rename = "ttlMs")]
    lifetime: RequestedLifetime,
    #[serde(default, rename = "_meta")]
    _metadata: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelivery {
    mode: String,
    url: String,
    secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnsubscribe {
    name: String,
    arguments: Map<String, Value>,
    delivery: RawStopDelivery,
    #[serde(default, rename = "_meta")]
    _metadata: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStopDelivery {
    mode: String,
    url: String,
}

/// A bounded, webhook-only subscribe request with a well-formed signing key.
///
/// No Serialize implementation is supplied: persist secrets only through the
/// application's approved protected-storage boundary, never generic metadata.
/// The raw and decoded key remain sensitive in memory; this type does not
/// promise zeroization or encrypted storage.
#[derive(Clone)]
pub struct WebhookSubscribeRequest {
    key: SubscriptionKey,
    signing_secret: String,
    cursor: Option<String>,
    max_age_ms: Option<u64>,
    lifetime: RequestedLifetime,
}

impl fmt::Debug for WebhookSubscribeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSubscribeRequest")
            .finish_non_exhaustive()
    }
}

impl WebhookSubscribeRequest {
    /// Parses JSON-RPC params, not the surrounding JSON-RPC envelope.
    ///
    /// # Errors
    /// Rejects oversize input, malformed/extra fields, non-webhook delivery,
    /// invalid signing keys and blank or over-budget identity fields.
    ///
    /// # Security
    /// The callback is an untrusted string. Before challenge and every send,
    /// require HTTPS, validate and bind DNS to the connection, block non-public
    /// addresses and redirects, and enforce bounded I/O. Also authorize the
    /// principal and arguments against current state and validate the event's
    /// input schema. Successful parsing alone permits no outbound connection.
    ///
    /// ```
    /// use mcp_toolkit_core::chatgpt_events::{RequestedLifetime, WebhookSubscribeRequest};
    /// let params = br#"{
    ///   "name":"item.changed", "arguments":{"item":"one"},
    ///   "delivery":{"mode":"webhook","url":"https://receiver.example/callback",
    ///     "secret":"whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
    /// }"#;
    /// let request = WebhookSubscribeRequest::parse(params)?;
    /// assert_eq!(request.lifetime(), RequestedLifetime::ServerDefault);
    /// // A syntactically valid test key does not prove secure entropy or consent.
    /// # Ok::<(), mcp_toolkit_core::chatgpt_events::EventRequestError>(())
    /// ```
    pub fn parse(params: &[u8]) -> Result<Self, EventRequestError> {
        check_budget(params)?;
        let raw: RawSubscribe =
            serde_json::from_slice(params).map_err(|_| EventRequestError::InvalidRequest)?;
        if raw.delivery.mode != "webhook" {
            return Err(EventRequestError::InvalidRequest);
        }
        let key = SubscriptionKey::new(raw.name, raw.arguments, raw.delivery.url)?;
        validate_signing_secret(&raw.delivery.secret)?;
        if raw
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > 4096)
        {
            return Err(EventRequestError::InvalidRequest);
        }
        Ok(Self {
            key,
            signing_secret: raw.delivery.secret,
            cursor: raw.cursor,
            max_age_ms: raw.max_age_ms,
            lifetime: raw.lifetime,
        })
    }

    /// Borrows the stable selector used by subscribe, refresh and unsubscribe.
    pub fn key(&self) -> &SubscriptionKey {
        &self.key
    }

    /// Borrows the client-supplied Standard Webhooks secret for protected use.
    ///
    /// # Security
    /// Never log or return this value. It does not authorize a callback or event.
    pub fn signing_secret(&self) -> &str {
        &self.signing_secret
    }

    /// Borrows the client-owned replay request; it is not a server checkpoint.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Returns the requested replay-age bound, if supplied.
    pub fn max_age_ms(&self) -> Option<u64> {
        self.max_age_ms
    }

    /// Returns the requested lifetime without conflating missing and null.
    pub fn lifetime(&self) -> RequestedLifetime {
        self.lifetime
    }
}

/// The identity-bearing fields shared by subscribe and unsubscribe.
///
/// The callback and argument strings retain their parsed values. No URL or
/// Unicode normalization is performed, and object key order is ignored only
/// when computing the canonical identity. This is not an authorization token.
#[derive(Clone)]
pub struct SubscriptionKey {
    name: String,
    arguments: Map<String, Value>,
    callback_url: String,
}

impl fmt::Debug for SubscriptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionKey").finish_non_exhaustive()
    }
}

impl SubscriptionKey {
    fn new(
        name: String,
        arguments: Map<String, Value>,
        callback_url: String,
    ) -> Result<Self, EventRequestError> {
        if !bounded_nonblank(&name, 256) || !bounded_nonblank(&callback_url, 4096) {
            return Err(EventRequestError::InvalidRequest);
        }
        Ok(Self {
            name,
            arguments,
            callback_url,
        })
    }

    /// Parses the identity from webhook-only unsubscribe params.
    ///
    /// # Errors
    /// Rejects oversized or malformed input, unsupported delivery modes and
    /// fields not in the unsubscribe contract, including a signing secret.
    ///
    /// # Security
    /// Reauthenticate and authorize against the owner before cancelling. Do not
    /// contact this callback to unsubscribe or reveal whether a foreign key exists.
    pub fn parse_unsubscribe(params: &[u8]) -> Result<Self, EventRequestError> {
        check_budget(params)?;
        let raw: RawUnsubscribe =
            serde_json::from_slice(params).map_err(|_| EventRequestError::InvalidRequest)?;
        if raw.delivery.mode != "webhook" {
            return Err(EventRequestError::InvalidRequest);
        }
        Self::new(raw.name, raw.arguments, raw.delivery.url)
    }

    /// Borrows the event name for authorized discovery/schema lookup.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrows the same arguments that must be validated and authorized.
    pub fn arguments(&self) -> &Map<String, Value> {
        &self.arguments
    }

    /// Borrows the untrusted callback URL; this is not an egress approval.
    pub fn callback_url(&self) -> &str {
        &self.callback_url
    }

    /// Derives a stable opaque routing ID from the full authenticated tuple.
    ///
    /// Refresh-only values (secret, cursor, TTL and replay-age bound) are absent
    /// from this tuple. Reuses the toolkit compact canonical JSON profile, not
    /// RFC 8785. Keep this identity profile stable when retaining subscriptions.
    ///
    /// # Errors
    /// Rejects a blank or over-budget principal or JSON encoding failure.
    ///
    /// # Security
    /// Supply a verified, issuer/tenant-qualified principal from authentication,
    /// never a caller label. Bind any domain/project scope into validated event
    /// arguments or an unambiguous authenticated principal namespace. The hash
    /// is routing identity only; it does not prove rights, hide low-entropy
    /// selectors, grant a lease, or acknowledge source events.
    pub fn subscription_id(
        &self,
        authenticated_principal: &str,
    ) -> Result<String, EventRequestError> {
        if !bounded_nonblank(authenticated_principal, 1024) {
            return Err(EventRequestError::InvalidPrincipal);
        }
        let identity = CanonicalJsonIdentity::new(&json!({
            "profile": "mcp-toolkit.chatgpt-webhook-subscription.v1",
            "principal": authenticated_principal,
            "url": self.callback_url,
            "name": self.name,
            "arguments": self.arguments,
        }))
        .map_err(|_| EventRequestError::InvalidRequest)?;
        Ok(format!("sub_{}", identity.sha256_hex()))
    }
}

fn check_budget(params: &[u8]) -> Result<(), EventRequestError> {
    if params.len() > MAX_SUBSCRIPTION_REQUEST_BYTES {
        Err(EventRequestError::RequestTooLarge)
    } else {
        Ok(())
    }
}

fn bounded_nonblank(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum
}

fn validate_signing_secret(secret: &str) -> Result<(), EventRequestError> {
    let encoded = secret
        .strip_prefix("whsec_")
        .filter(|value| value.len() <= 88)
        .ok_or(EventRequestError::InvalidSigningSecret)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| EventRequestError::InvalidSigningSecret)?;
    if !(24..=64).contains(&bytes.len()) {
        return Err(EventRequestError::InvalidSigningSecret);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({
            "name": "item.changed",
            "arguments": {"item": "private-item", "nested": {"z": 2, "a": 1}},
            "delivery": {
                "mode": "webhook", "url": "https://receiver.example/private-callback",
                "secret": format!("whsec_{}", STANDARD.encode([7_u8; 32])),
            },
            "cursor": null,
        })
    }

    fn parse(value: &Value) -> Result<WebhookSubscribeRequest, EventRequestError> {
        WebhookSubscribeRequest::parse(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn documented_subscribe_and_unsubscribe_have_the_same_identity() {
        let value = request();
        let subscribe = parse(&value).unwrap();
        let stop = json!({
            "name": value["name"], "arguments": value["arguments"],
            "delivery": {"mode":"webhook", "url":value["delivery"]["url"]}
        });
        let unsubscribe =
            SubscriptionKey::parse_unsubscribe(&serde_json::to_vec(&stop).unwrap()).unwrap();
        assert_eq!(
            subscribe.key().subscription_id("issuer:principal").unwrap(),
            unsubscribe.subscription_id("issuer:principal").unwrap()
        );
        assert_eq!(subscribe.key().name(), "item.changed");
        assert_eq!(
            subscribe.key().arguments(),
            value["arguments"].as_object().unwrap()
        );
        assert_eq!(
            subscribe.key().callback_url(),
            value["delivery"]["url"].as_str().unwrap()
        );
        assert_eq!(
            subscribe.signing_secret(),
            value["delivery"]["secret"].as_str().unwrap()
        );
        assert_eq!(subscribe.cursor(), None);
        assert_eq!(subscribe.max_age_ms(), None);
    }

    #[test]
    fn lifetime_distinguishes_missing_null_and_integer() {
        let mut value = request();
        assert_eq!(
            parse(&value).unwrap().lifetime(),
            RequestedLifetime::ServerDefault
        );
        value["ttlMs"] = Value::Null;
        assert_eq!(
            parse(&value).unwrap().lifetime(),
            RequestedLifetime::NoExpiry
        );
        value["ttlMs"] = json!(0);
        assert_eq!(
            parse(&value).unwrap().lifetime(),
            RequestedLifetime::Milliseconds(0)
        );
        for invalid in [json!(-1), json!(1.5), json!("300"), json!(true)] {
            value["ttlMs"] = invalid;
            assert!(matches!(
                parse(&value),
                Err(EventRequestError::InvalidRequest)
            ));
        }
    }

    #[test]
    fn finite_policy_clamps_without_granting_infinite_lifetime() {
        for (request, expected) in [
            (RequestedLifetime::ServerDefault, 900),
            (RequestedLifetime::NoExpiry, 900),
            (RequestedLifetime::Milliseconds(0), 100),
            (RequestedLifetime::Milliseconds(400), 400),
            (RequestedLifetime::Milliseconds(u64::MAX), 3600),
        ] {
            assert_eq!(request.grant_finite_ms(900, 100, 3600), Ok(expected));
        }
        for (default, min, max) in [(0, 0, 10), (10, 20, 30), (40, 20, 30), (5, 10, 1)] {
            assert_eq!(
                RequestedLifetime::NoExpiry.grant_finite_ms(default, min, max),
                Err(EventRequestError::InvalidLifetimePolicy)
            );
        }
    }

    #[test]
    fn refresh_mutable_values_do_not_change_the_identity() {
        let original = parse(&request())
            .unwrap()
            .key()
            .subscription_id("issuer:principal")
            .unwrap();
        let mut refreshed = request();
        refreshed["delivery"]["secret"] = json!(format!("whsec_{}", STANDARD.encode([9_u8; 64])));
        refreshed["ttlMs"] = json!(300_000);
        refreshed["cursor"] = json!("private-cursor");
        refreshed["maxAgeMs"] = json!(900_000);
        refreshed["_meta"] = json!({"request": "not-identity"});
        let refreshed = parse(&refreshed).unwrap();
        assert_eq!(
            original,
            refreshed.key().subscription_id("issuer:principal").unwrap()
        );
        assert_eq!(refreshed.cursor(), Some("private-cursor"));
        assert_eq!(refreshed.max_age_ms(), Some(900_000));
    }

    #[test]
    fn every_identity_dimension_changes_the_id() {
        let value = request();
        let original = parse(&value)
            .unwrap()
            .key()
            .subscription_id("issuer:principal")
            .unwrap();
        assert_ne!(
            original,
            parse(&value)
                .unwrap()
                .key()
                .subscription_id("other:principal")
                .unwrap()
        );
        for (field, replacement) in [
            ("name", json!("item.created")),
            ("arguments", json!({"item":"other"})),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            assert_ne!(
                original,
                parse(&changed)
                    .unwrap()
                    .key()
                    .subscription_id("issuer:principal")
                    .unwrap()
            );
        }
        let mut changed = value;
        changed["delivery"]["url"] = json!("https://receiver.example/other");
        assert_ne!(
            original,
            parse(&changed)
                .unwrap()
                .key()
                .subscription_id("issuer:principal")
                .unwrap()
        );
    }

    #[test]
    fn recursive_argument_order_is_canonical() {
        let mut left = request();
        let mut right = request();
        left["arguments"] = serde_json::from_str(r#"{"z":{"b":2,"a":1},"a":[1,2]}"#).unwrap();
        right["arguments"] = serde_json::from_str(r#"{"a":[1,2],"z":{"a":1,"b":2}}"#).unwrap();
        assert_eq!(
            parse(&left).unwrap().key().subscription_id("p").unwrap(),
            parse(&right).unwrap().key().subscription_id("p").unwrap()
        );
        right["arguments"]["a"] = json!([2, 1]);
        assert_ne!(
            parse(&left).unwrap().key().subscription_id("p").unwrap(),
            parse(&right).unwrap().key().subscription_id("p").unwrap()
        );
    }

    #[test]
    fn rejects_unsupported_and_malformed_contracts_without_echoing_values() {
        for value in [
            json!(null),
            json!([]),
            json!({}),
            json!({"name":"x","arguments":[],"delivery":{"mode":"webhook","url":"x","secret":"x"}}),
        ] {
            assert!(parse(&value).is_err());
        }
        for mode in ["poll", "push", "stream", "", "WEBHOOK"] {
            let mut value = request();
            value["delivery"]["mode"] = json!(mode);
            assert!(matches!(
                parse(&value),
                Err(EventRequestError::InvalidRequest)
            ));
        }
        let mut value = request();
        value["delivery"]["mode"] = json!({"webhook": null});
        assert!(matches!(
            parse(&value),
            Err(EventRequestError::InvalidRequest)
        ));
        value = request();
        value["actor"] = json!("untrusted");
        assert!(matches!(
            parse(&value),
            Err(EventRequestError::InvalidRequest)
        ));
        value.as_object_mut().unwrap().remove("actor");
        value["delivery"]["extra"] = json!("private-marker");
        let error = parse(&value).unwrap_err();
        assert_eq!(error.to_string(), "invalid event subscription request");
    }

    #[test]
    fn signing_secret_format_and_decoded_size_are_checked() {
        for length in [24, 32, 64] {
            assert_eq!(
                validate_signing_secret(&format!("whsec_{}", STANDARD.encode(vec![0; length]))),
                Ok(())
            );
        }
        for secret in [
            "",
            "whsec_bad",
            "whsec_!!!!",
            "other_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                validate_signing_secret(secret),
                Err(EventRequestError::InvalidSigningSecret)
            );
        }
        for length in [0, 23, 65, 1000] {
            assert_eq!(
                validate_signing_secret(&format!("whsec_{}", STANDARD.encode(vec![0; length]))),
                Err(EventRequestError::InvalidSigningSecret)
            );
        }
    }

    #[test]
    fn input_bounds_are_utf8_bytes_and_errors_remain_safe() {
        assert!(matches!(
            WebhookSubscribeRequest::parse(&vec![b' '; MAX_SUBSCRIPTION_REQUEST_BYTES + 1]),
            Err(EventRequestError::RequestTooLarge)
        ));
        let mut value = request();
        value["name"] = json!("é".repeat(129));
        assert!(matches!(
            parse(&value),
            Err(EventRequestError::InvalidRequest)
        ));
        value["name"] = json!(" \n");
        assert!(parse(&value).is_err());
        value = request();
        value["cursor"] = json!("x".repeat(4097));
        assert!(parse(&value).is_err());
        let key = parse(&request()).unwrap().key().clone();
        for principal in ["".to_owned(), "  ".to_owned(), "x".repeat(1025)] {
            assert_eq!(
                key.subscription_id(&principal),
                Err(EventRequestError::InvalidPrincipal)
            );
        }
    }

    #[test]
    fn debug_hides_callback_key_arguments_and_cursor() {
        let mut value = request();
        value["cursor"] = json!("private-cursor");
        let parsed = parse(&value).unwrap();
        assert_eq!(format!("{parsed:?}"), "WebhookSubscribeRequest { .. }");
        assert_eq!(format!("{:?}", parsed.key()), "SubscriptionKey { .. }");
        let stop = SubscriptionKey::parse_unsubscribe(&serde_json::to_vec(&value).unwrap());
        assert!(matches!(stop, Err(EventRequestError::InvalidRequest)));
    }

    #[test]
    fn identity_profile_has_a_fixed_storage_compatibility_vector() {
        let key = parse(&request()).unwrap().key().clone();
        let expected = concat!(
            "sub_",
            "280466babb5cc578",
            "ac24d45b4a030f90",
            "743ffcfc1f2e296e",
            "78e6f369524e3a57"
        );
        assert_eq!(key.subscription_id("issuer:principal").unwrap(), expected);
    }

    #[test]
    fn unsubscribe_rejects_object_mode_and_unknown_fields() {
        let valid = json!({
            "name": "item.changed", "arguments": {"item": "one"},
            "delivery": {"mode": "webhook", "url": "https://receiver.example/callback"}
        });
        for mode in [json!({"webhook": null}), json!(null), json!(["webhook"])] {
            let mut value = valid.clone();
            value["delivery"]["mode"] = mode;
            assert!(matches!(
                SubscriptionKey::parse_unsubscribe(&serde_json::to_vec(&value).unwrap()),
                Err(EventRequestError::InvalidRequest)
            ));
        }
        let mut value = valid;
        value["id"] = json!("caller-selected-id");
        assert!(SubscriptionKey::parse_unsubscribe(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn exact_callback_cursor_and_total_request_boundaries() {
        let mut value = request();
        value["delivery"]["url"] = json!("x".repeat(4096));
        value["cursor"] = json!("x".repeat(4096));
        assert!(parse(&value).is_ok());
        value["delivery"]["url"] = json!("x".repeat(4097));
        assert!(parse(&value).is_err());
        let mut bytes = serde_json::to_vec(&request()).unwrap();
        bytes.resize(MAX_SUBSCRIPTION_REQUEST_BYTES, b' ');
        assert!(WebhookSubscribeRequest::parse(&bytes).is_ok());
        bytes.push(b' ');
        assert!(matches!(
            WebhookSubscribeRequest::parse(&bytes),
            Err(EventRequestError::RequestTooLarge)
        ));
    }

    #[test]
    fn duplicate_envelope_fields_and_excessive_nesting_are_rejected() {
        let value = serde_json::to_string(&request()).unwrap();
        let duplicate = value.replacen('{', "{\"name\":\"another-event\",", 1);
        assert!(matches!(
            WebhookSubscribeRequest::parse(duplicate.as_bytes()),
            Err(EventRequestError::InvalidRequest)
        ));
        let nested = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        let nested = value.replace(
            "\"arguments\":{",
            &format!("\"arguments\":{{\"deep\":{nested},"),
        );
        assert!(matches!(
            WebhookSubscribeRequest::parse(nested.as_bytes()),
            Err(EventRequestError::InvalidRequest)
        ));
    }

    #[test]
    fn deterministic_mutation_fuzz_keeps_both_parsers_bounded() {
        fn check(bytes: &[u8]) {
            if let Ok(parsed) = WebhookSubscribeRequest::parse(bytes) {
                assert_eq!(format!("{parsed:?}"), "WebhookSubscribeRequest { .. }");
                assert_eq!(
                    parsed.key().subscription_id("issuer:principal"),
                    parsed.clone().key().subscription_id("issuer:principal")
                );
            }
            if let Ok(parsed) = SubscriptionKey::parse_unsubscribe(bytes) {
                assert_eq!(format!("{parsed:?}"), "SubscriptionKey { .. }");
                assert_eq!(
                    parsed.subscription_id("issuer:principal"),
                    parsed.clone().subscription_id("issuer:principal")
                );
            }
        }

        let mut state = 7_u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as usize
        };
        for length in 0..512 {
            let bytes: Vec<u8> = (0..length).map(|_| next() as u8).collect();
            check(&bytes);
        }
        let mut stop = request();
        stop["delivery"].as_object_mut().unwrap().remove("secret");
        let seeds = [
            serde_json::to_vec(&request()).unwrap(),
            serde_json::to_vec(&stop).unwrap(),
        ];
        for seed in seeds {
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
}

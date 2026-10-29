//! # Canonical JSON Identity
//!
//! ## Rationale
//! Provide stable production JSON bytes and an SHA-256 identity for exact
//! request and effect-intent payloads, independent of object insertion order.
//!
//! ## Security Boundaries
//! * This is the toolkit's compact serde_json profile, not RFC 8785 (JCS).
//! * Object keys are sorted recursively by Rust string order; array order and
//!   JSON scalar representations are preserved.
//! * A digest identifies bytes, not permission to perform an effect. Callers
//!   must bind the operation, target, relevant context, and complete arguments
//!   into their own versioned intent envelope before hashing.
//! * Inputs are JSON values. This API cannot detect duplicate keys discarded
//!   by an upstream JSON parser or authenticate the origin of the values.
//! * Avoid exposing digests of low-entropy secrets as they can enable guessing.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

/// Encodes a JSON value as compact, recursively key-ordered UTF-8 bytes.
///
/// Object keys use Rust string ordering at every depth. Array positions and
/// scalar JSON representations remain unchanged. No whitespace or trailing
/// newline is emitted. This encoding deliberately does not claim RFC 8785
/// compatibility, particularly for number formatting and non-BMP key order.
///
/// # Errors
/// Returns a serialization error if serde_json cannot encode the value.
///
/// # Security
/// Hash only a complete, context-bound JSON intent; a bare argument digest
/// does not establish an authorization or bind a request to its effect target.
/// Validate raw JSON for ambiguous duplicate keys before constructing a Value
/// if the application requires that property.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&order_object_keys(value))
}

fn order_object_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
            let mut ordered = Map::new();
            for (key, nested) in sorted {
                ordered.insert(key.clone(), order_object_keys(nested));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.iter().map(order_object_keys).collect()),
        other => other.clone(),
    }
}

/// Owns the exact canonical JSON bytes and their SHA-256 digest together.
///
/// Construct this from a complete, versioned JSON envelope describing the
/// intended operation. Hashing arguments alone is insufficient for approval
/// binding: equal arguments can have different tools, targets, or authority.
///
/// The Debug implementation intentionally omits payload bytes and their digest.
///
/// ```
/// use mcp_toolkit_core::canonical_json::CanonicalJsonIdentity;
/// use serde_json::json;
///
/// let intent = json!({
///     "schema": "example-intent.v1",
///     "tool": "example.update",
///     "arguments": { "z": 2, "a": 1 }
/// });
/// let identity = CanonicalJsonIdentity::new(&intent)?;
/// assert!(identity.sha256_id().starts_with("sha256:"));
/// assert_eq!(identity.bytes(), b"{\"arguments\":{\"a\":1,\"z\":2},\"schema\":\"example-intent.v1\",\"tool\":\"example.update\"}");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct CanonicalJsonIdentity {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl fmt::Debug for CanonicalJsonIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalJsonIdentity")
            .field("byte_count", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl CanonicalJsonIdentity {
    /// Binds a JSON value's canonical bytes to its SHA-256 digest.
    ///
    /// # Errors
    /// Returns a serialization error if the value cannot be encoded.
    ///
    /// # Security
    /// This is a fingerprint, not an approval or authorization. The caller
    /// must build and validate the complete intent envelope before invoking it.
    pub fn new(value: &Value) -> Result<Self, serde_json::Error> {
        let bytes = canonical_json_bytes(value)?;
        let sha256 = Sha256::digest(&bytes).into();
        Ok(Self { bytes, sha256 })
    }

    /// Borrows the exact bytes used to calculate the digest.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 digest as a 32-byte array.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Renders the digest as 64 lowercase hexadecimal digits.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Renders the algorithm-qualified identity (sha256: followed by hex).
    #[must_use]
    pub fn sha256_id(&self) -> String {
        format!("sha256:{}", self.sha256_hex())
    }

    /// Consumes the identity and returns the exact hashed bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_json_bytes, CanonicalJsonIdentity};
    use serde_json::{json, Value};

    #[test]
    fn canonical_bytes_are_independent_of_recursive_object_order() {
        let left: Value = serde_json::from_str(r#"{"z":{"b":2,"a":1},"a":[{"d":4,"c":3},"é🦀"]}"#)
            .expect("left is valid JSON");
        let right: Value = serde_json::from_str(r#"{"a":[{"c":3,"d":4},"é🦀"],"z":{"a":1,"b":2}}"#)
            .expect("right is valid JSON");
        let expected = r#"{"a":[{"c":3,"d":4},"é🦀"],"z":{"a":1,"b":2}}"#.as_bytes();

        assert_eq!(canonical_json_bytes(&left).expect("left bytes"), expected);
        assert_eq!(canonical_json_bytes(&right).expect("right bytes"), expected);
        assert_eq!(
            CanonicalJsonIdentity::new(&left).expect("left identity"),
            CanonicalJsonIdentity::new(&right).expect("right identity")
        );
    }

    #[test]
    fn sha256_is_over_exact_bytes_with_a_fixed_known_vector() {
        let identity = CanonicalJsonIdentity::new(&json!({})).expect("identity");
        assert_eq!(identity.bytes(), b"{}");
        const EMPTY_OBJECT_SHA256: &str = concat!(
            "44136fa355b3678a",
            "1146ad16f7e8649e",
            "94fb4fc21fe77e83",
            "10c060f61caaff8a",
        );
        assert_eq!(identity.sha256_hex(), EMPTY_OBJECT_SHA256);
        assert_eq!(identity.sha256_id(), format!("sha256:{EMPTY_OBJECT_SHA256}"));
        assert_eq!(identity.sha256().len(), 32);
        assert_eq!(identity.clone().into_bytes(), identity.bytes());
    }

    #[test]
    fn array_order_arguments_and_operation_context_change_identity() {
        let base = json!({
            "schema": "intent.v1",
            "tool": "example.update",
            "target": "resource-a",
            "arguments": {"items": [1, 2]}
        });
        let identity = CanonicalJsonIdentity::new(&base).expect("base");
        let variants = [
            json!({"schema":"intent.v1","tool":"example.update","target":"resource-a","arguments":{"items":[2,1]}}),
            json!({"schema":"intent.v1","tool":"example.update","target":"resource-a","arguments":{"items":[1,3]}}),
            json!({"schema":"intent.v1","tool":"example.delete","target":"resource-a","arguments":{"items":[1,2]}}),
            json!({"schema":"intent.v1","tool":"example.update","target":"resource-b","arguments":{"items":[1,2]}}),
            json!({"schema":"intent.v2","tool":"example.update","target":"resource-a","arguments":{"items":[1,2]}}),
        ];
        for variant in variants {
            let other = CanonicalJsonIdentity::new(&variant).expect("variant");
            assert_ne!(identity, other);
        }
    }

    #[test]
    fn preserves_json_scalar_representation_and_exact_utf8_size() {
        let value = json!({"text": "é🦀", "control": "\u{0000}\n", "array": [true, null, -1]});
        let bytes = canonical_json_bytes(&value).expect("canonical bytes");
        assert_eq!(
            bytes,
            r#"{"array":[true,null,-1],"control":"\u0000\n","text":"é🦀"}"#.as_bytes()
        );
        assert!(
            bytes.len()
                > String::from_utf8(bytes.clone())
                    .expect("utf8")
                    .chars()
                    .count()
        );
    }

    #[test]
    fn debug_does_not_expose_payload_or_its_digest() {
        let identity =
            CanonicalJsonIdentity::new(&json!({"example": "private-test-marker"})).expect("identity");
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("byte_count"));
        assert!(!rendered.contains("private-test-marker"));
        assert!(!rendered.contains(&identity.sha256_hex()));
    }
}

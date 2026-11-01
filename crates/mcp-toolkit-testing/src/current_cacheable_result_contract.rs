//! # MCP 2026-07-28 cacheable-result HTTP conformance
//!
//! A bounded *test-only* assertion for real routed HTTP results. It checks
//! modern result metadata and correlation, not the SDK's internal structures.
//! It does not authenticate callers or assert that a model consumed data.

use http::header::CONTENT_TYPE;
use http::{HeaderMap, StatusCode};
use serde_json::Value;

/// Expected cache policy for one current-protocol JSON-RPC result.
#[derive(Debug, Clone)]
pub struct CurrentCacheableResultContract {
    expected_request_id: Value,
    resource_private: bool,
    max_ttl_ms: u64,
}

impl CurrentCacheableResultContract {
    /// Construct the contract. Defaults to private, zero-TTL results.
    pub fn new(request_id: Value) -> Self {
        Self {
            expected_request_id: request_id,
            resource_private: true,
            max_ttl_ms: 0,
        }
    }

    /// Allow a positive cache lifetime up to the stated limit.
    pub fn with_max_ttl_ms(mut self, max_ttl_ms: u64) -> Self {
        self.max_ttl_ms = max_ttl_ms;
        self
    }

    /// Permit a public cache scope for a genuinely public resource.
    ///
    /// Sensitive tool results, private resource lists and authenticated
    /// projections should retain the default private policy.
    pub fn allow_public_cache(mut self) -> Self {
        self.resource_private = false;
        self
    }

    /// Validate an actual JSON HTTP result (tools/list, resources/list,
    /// resources/read, prompts/list or resources/templates/list).
    ///
    /// # Panics
    /// Fails on bad HTTP status/content-type, legacy session IDs, JSON-RPC
    /// errors, missing result metadata, invalid/too-long TTL or wrong scope.
    ///
    /// # Security
    /// This checks *observed* result metadata only. Authentication and cache
    /// partitioning remain the server's responsibility. Avoid printing the
    /// response body because it may include private tool/resource data.
    pub fn assert_http_json_response(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        bytes: &[u8],
    ) -> Value {
        assert_eq!(status, StatusCode::OK, "current MCP HTTP status");
        assert!(
            !headers.contains_key("mcp-session-id"),
            "current MCP response must not mint a legacy session"
        );
        assert!(
            headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|v| v.split(';').next())
                .is_some_and(|kind| kind.trim() == "application/json"),
            "current MCP JSON content type"
        );
        let value: Value = serde_json::from_slice(bytes).expect("valid JSON-RPC response");
        assert_eq!(value["jsonrpc"], "2.0", "JSON-RPC envelope");
        assert_eq!(
            value.get("id"),
            Some(&self.expected_request_id),
            "JSON-RPC response ID"
        );
        assert!(value.get("error").is_none(), "result must not be an error");
        let result = value
            .get("result")
            .and_then(Value::as_object)
            .expect("result must be an object");
        assert_eq!(
            result.get("resultType").and_then(Value::as_str),
            Some("complete"),
            "current result requires complete discriminator"
        );
        let ttl = result
            .get("ttlMs")
            .and_then(Value::as_u64)
            .expect("cacheable result must expose nonnegative integer ttlMs");
        assert!(
            ttl <= self.max_ttl_ms,
            "cacheable result TTL exceeds caller-defined maximum"
        );
        let scope = result
            .get("cacheScope")
            .and_then(Value::as_str)
            .expect("cacheable result must expose cacheScope");
        assert!(
            matches!(scope, "public" | "private"),
            "cacheScope must be public or private"
        );
        if self.resource_private {
            assert_eq!(scope, "private", "private response must not be publicly cacheable");
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::CurrentCacheableResultContract;
    use http::header::{HeaderValue, CONTENT_TYPE};
    use http::{HeaderMap, StatusCode};
    use serde_json::{json, Value};

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    fn valid() -> Value {
        json!({
            "jsonrpc": "2.0", "id": 7,
            "result": {
                "resultType": "complete", "tools": [], "ttlMs": 0,
                "cacheScope": "private"
            }
        })
    }

    fn verify(payload: &Value) {
        CurrentCacheableResultContract::new(json!(7)).assert_http_json_response(
            StatusCode::OK,
            &headers(),
            payload.to_string().as_bytes(),
        );
    }

    #[test]
    fn accepts_private_current_results() {
        verify(&valid());
    }

    #[test]
    fn requires_complete_result_and_cache_hints() {
        for key in ["resultType", "ttlMs", "cacheScope"] {
            let mut broken = valid();
            broken["result"].as_object_mut().unwrap().remove(key);
            assert!(std::panic::catch_unwind(|| verify(&broken)).is_err());
        }
        let mut broken = valid();
        broken["result"]["ttlMs"] = json!(-1);
        assert!(std::panic::catch_unwind(|| verify(&broken)).is_err());
        let mut broken = valid();
        broken["result"]["ttlMs"] = json!(1.5);
        assert!(std::panic::catch_unwind(|| verify(&broken)).is_err());
    }

    #[test]
    fn private_policy_rejects_public_cache_and_stale_ttl() {
        let mut payload = valid();
        payload["result"]["cacheScope"] = json!("public");
        assert!(std::panic::catch_unwind(|| verify(&payload)).is_err());
        payload["result"]["cacheScope"] = json!("private");
        payload["result"]["ttlMs"] = json!(1);
        assert!(std::panic::catch_unwind(|| verify(&payload)).is_err());
        CurrentCacheableResultContract::new(json!(7))
            .with_max_ttl_ms(1)
            .assert_http_json_response(
                StatusCode::OK,
                &headers(),
                payload.to_string().as_bytes(),
            );
    }

    #[test]
    fn rejects_legacy_session_and_wrong_id() {
        let mut headers = headers();
        headers.insert("mcp-session-id", HeaderValue::from_static("legacy"));
        let payload = valid().to_string();
        assert!(std::panic::catch_unwind(|| {
            CurrentCacheableResultContract::new(json!(7)).assert_http_json_response(
                StatusCode::OK,
                &headers,
                payload.as_bytes(),
            );
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            CurrentCacheableResultContract::new(json!(8)).assert_http_json_response(
                StatusCode::OK,
                &headers(),
                payload.as_bytes(),
            );
        })
        .is_err());
    }

    #[test]
    fn explicit_public_cache_requires_policy_opt_in() {
        let mut payload = valid();
        payload["result"]["cacheScope"] = json!("public");
        CurrentCacheableResultContract::new(json!(7))
            .allow_public_cache()
            .assert_http_json_response(
                StatusCode::OK,
                &headers(),
                payload.to_string().as_bytes(),
            );
    }
}

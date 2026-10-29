//! # Current MCP Discovery HTTP Contract
//!
//! Reusable response assertions for the MCP 2026-07-28 discovery era.
//!
//! ## Rationale
//! An SDK handler test alone does not prove that a server's real HTTP router
//! advertises modern protocol versions without opening a legacy session.
//! This helper checks the public JSON-RPC and HTTP boundary without adopting
//! a service's application state, credentials or transport implementation.
//!
//! ## Security Boundaries
//! * Test-only assertions do not authenticate requests or authorize tools.
//! * MCP serverInfo is self-reported and never a trust or identity credential.
//! * The response body is not included in parser failures, avoiding accidental
//!   exposure of sensitive service responses in routine CI diagnostics.
//!
//! ## References
//! * https://modelcontextprotocol.io/specification/2026-07-28/server/discover

use http::header::CONTENT_TYPE;
use http::{HeaderMap, StatusCode};
use serde_json::Value;

const SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";

/// Required properties of one successful current-protocol `server/discover` response.
#[derive(Debug, Clone)]
pub struct CurrentDiscoveryContract {
    expected_protocol_version: String,
    expected_request_id: Value,
    required_capabilities: Vec<String>,
    require_server_identity: bool,
}

impl CurrentDiscoveryContract {
    /// Selects an advertised protocol version and the exact request ID.
    pub fn new(protocol_version: impl Into<String>, request_id: Value) -> Self {
        let expected_protocol_version = protocol_version.into();
        assert!(
            !expected_protocol_version.trim().is_empty(),
            "expected protocol version cannot be empty"
        );
        Self {
            expected_protocol_version,
            expected_request_id: request_id,
            required_capabilities: Vec::new(),
            require_server_identity: false,
        }
    }

    /// Requires one named capability to be advertised as a JSON object.
    pub fn require_capability(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        assert!(!name.is_empty(), "required capability name cannot be empty");
        self.required_capabilities.push(name);
        self
    }

    /// Requires a nonempty self-reported server name and version in result metadata.
    ///
    /// This is a display/debugging assertion, not identity verification or an
    /// authorization check.
    pub fn require_server_identity(mut self) -> Self {
        self.require_server_identity = true;
        self
    }

    /// Asserts one HTTP discovery response and returns its full JSON-RPC envelope.
    ///
    /// Accepts `application/json` or one-result `text/event-stream` without
    /// accepting extra application events or ignoring JSON-RPC errors.
    ///
    /// # Panics
    /// Panics on any transport, JSON-RPC, version, capability, or metadata
    /// mismatch, without logging the raw response body.
    ///
    /// # Security
    /// These are test-only checks. An authenticated request must already have
    /// passed through the service's own HTTP and security boundaries.
    pub fn assert_http_response(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Value {
        assert_eq!(status, StatusCode::OK, "modern discovery HTTP status");
        assert!(
            !headers.contains_key("mcp-session-id"),
            "modern discovery must not return a legacy MCP session"
        );
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .expect("modern discovery response must declare a Content-Type");
        let envelope = match content_type {
            "application/json" => serde_json::from_slice::<Value>(body)
                .expect("modern discovery must contain valid JSON"),
            "text/event-stream" => parse_single_sse_result(body),
            _ => panic!("modern discovery must use JSON or SSE content type"),
        };

        assert_eq!(envelope["jsonrpc"], "2.0", "JSON-RPC version");
        assert_eq!(
            envelope.get("id"),
            Some(&self.expected_request_id),
            "JSON-RPC request/response ID correlation"
        );
        assert!(
            envelope.get("error").is_none(),
            "modern discovery must not be a JSON-RPC error"
        );
        let result = envelope
            .get("result")
            .and_then(Value::as_object)
            .expect("modern discovery result must be an object");
        assert_eq!(
            result.get("resultType").and_then(Value::as_str),
            Some("complete"),
            "discovery must return a complete result"
        );
        assert!(
            result
                .get("supportedVersions")
                .and_then(Value::as_array)
                .is_some_and(|versions| versions.iter().any(|version| {
                    version.as_str() == Some(self.expected_protocol_version.as_str())
                })),
            "discovery does not advertise the required protocol version"
        );
        let capabilities = result
            .get("capabilities")
            .and_then(Value::as_object)
            .expect("discovery capabilities must be an object");
        for name in &self.required_capabilities {
            assert!(
                capabilities.get(name).is_some_and(Value::is_object),
                "discovery is missing an object-valued required capability: {name}"
            );
        }
        assert!(
            result
                .get("ttlMs")
                .is_some_and(|value| value.as_u64().is_some()),
            "discovery must contain nonnegative integer ttlMs"
        );
        assert!(
            result
                .get("cacheScope")
                .and_then(Value::as_str)
                .is_some_and(|scope| matches!(scope, "private" | "public")),
            "discovery must include private or public cacheScope"
        );
        if self.require_server_identity {
            let info = result
                .get("_meta")
                .and_then(|meta| meta.get(SERVER_INFO_KEY))
                .and_then(Value::as_object)
                .expect("discovery result metadata must contain serverInfo");
            for field in ["name", "version"] {
                assert!(
                    info.get(field)
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "serverInfo must contain nonempty {field}"
                );
            }
        }

        envelope
    }
}

fn parse_single_sse_result(body: &[u8]) -> Value {
    let text = std::str::from_utf8(body).expect("SSE discovery body must be valid UTF-8");
    let mut messages = Vec::new();
    let mut data_lines = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.trim_start());
        } else if line.is_empty() {
            if !data_lines.is_empty() {
                messages.push(data_lines.join("\n"));
                data_lines.clear();
            }
        } else {
            assert!(
                line.starts_with(':')
                    || line.starts_with("event:")
                    || line.starts_with("id:")
                    || line.starts_with("retry:"),
                "unexpected line in SSE discovery response"
            );
        }
    }
    if !data_lines.is_empty() {
        messages.push(data_lines.join("\n"));
    }
    assert_eq!(
        messages.len(),
        1,
        "modern discovery SSE must contain exactly one data event"
    );
    serde_json::from_str(&messages[0]).expect("SSE discovery event must contain valid JSON")
}

#[cfg(test)]
mod tests {
    use super::CurrentDiscoveryContract;
    use http::header::{HeaderValue, CONTENT_TYPE};
    use http::{HeaderMap, StatusCode};
    use serde_json::{json, Value};

    fn example_discovery() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "resultType": "complete",
                "supportedVersions": ["2025-11-25", "2026-07-28"],
                "capabilities": {"tools": {}, "resources": {}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "example-server",
                        "version": "1.0"
                    }
                },
                "ttlMs": 0,
                "cacheScope": "private"
            }
        })
    }

    fn contract() -> CurrentDiscoveryContract {
        CurrentDiscoveryContract::new("2026-07-28", json!(7))
            .require_capability("tools")
            .require_server_identity()
    }

    fn content_type(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn accepts_complete_json_http_discovery() {
        let payload = example_discovery();
        let serialized = serde_json::to_vec(&payload).expect("serialize fixture");
        let headers = content_type("application/json; charset=utf-8");
        assert_eq!(
            contract().assert_http_response(StatusCode::OK, &headers, &serialized),
            payload
        );
    }

    #[test]
    fn accepts_single_sse_result_with_crlf_and_comment() {
        let payload = example_discovery();
        let body = format!(": keepalive\r\nevent: message\r\ndata: {payload}\r\n\r\n");
        let headers = content_type("text/event-stream");
        assert_eq!(
            contract().assert_http_response(StatusCode::OK, &headers, body.as_bytes()),
            payload
        );
    }

    #[test]
    fn rejects_missing_version_extra_event_and_legacy_session() {
        let mut missing = example_discovery();
        missing["result"]["supportedVersions"] = json!(["2025-11-25"]);
        let response = serde_json::to_vec(&missing).expect("serialize fixture");
        let headers = content_type("application/json");
        assert!(
            std::panic::catch_unwind(|| {
                contract().assert_http_response(StatusCode::OK, &headers, &response)
            })
            .is_err(),
            "the advertised version is required"
        );

        let valid = example_discovery().to_string();
        let extra_event = format!("data: {valid}\n\ndata: {valid}\n\n");
        let headers = content_type("text/event-stream");
        assert!(
            std::panic::catch_unwind(|| {
                contract().assert_http_response(StatusCode::OK, &headers, extra_event.as_bytes())
            })
            .is_err(),
            "unrelated SSE messages must not be silently accepted"
        );

        let mut headers = content_type("application/json");
        headers.insert("mcp-session-id", HeaderValue::from_static("legacy-session"));
        assert!(
            std::panic::catch_unwind(|| {
                contract().assert_http_response(StatusCode::OK, &headers, valid.as_bytes())
            })
            .is_err(),
            "modern HTTP must not return a legacy session identifier"
        );
    }

    #[test]
    fn rejects_wrong_request_id_missing_capability_and_identity() {
        let headers = content_type("application/json");
        let mut payload = example_discovery();
        payload["id"] = json!(8);
        assert!(std::panic::catch_unwind(|| {
            contract().assert_http_response(
                StatusCode::OK,
                &headers,
                payload.to_string().as_bytes(),
            )
        })
        .is_err());

        let mut payload = example_discovery();
        payload["result"]["capabilities"] = json!({});
        assert!(std::panic::catch_unwind(|| {
            contract().assert_http_response(
                StatusCode::OK,
                &headers,
                payload.to_string().as_bytes(),
            )
        })
        .is_err());

        let mut payload = example_discovery();
        payload["result"]
            .as_object_mut()
            .expect("object")
            .remove("_meta");
        assert!(std::panic::catch_unwind(|| {
            contract().assert_http_response(
                StatusCode::OK,
                &headers,
                payload.to_string().as_bytes(),
            )
        })
        .is_err());
    }
}

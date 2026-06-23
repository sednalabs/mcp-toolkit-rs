//! # OpenAI Retrievable MCP Helpers
//!
//! JSON builders for the OpenAI MCP `search`/`fetch` contract used by
//! company-knowledge, retrievable connector, and deep-research surfaces.
//!
//! ## Ownership
//! This module owns the provider-specific schema and response shapes that are
//! useful to many MCP servers. It does not choose a backing corpus or decide
//! authorization policy.
//!
//! ## Non-ownership
//! This module does not execute searches, dereference document ids, construct
//! product-specific URLs, or decide whether data may be exposed to a caller.
//!
//! ## Policy & Guarantees
//! * **Exact Tool Names**: The OpenAI-compatible tools are named `search` and
//!   `fetch`.
//! * **Small Schemas**: Input schemas carry only the required OpenAI fields.
//! * **Citable Results**: Output builders preserve canonical URL fields so hosts
//!   can attach citation metadata.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Enforcing caller authorization before returning data.
//! * Supplying stable ids that `fetch` can dereference.
//! * Supplying canonical HTTP(S) URLs when citation metadata is expected.

use serde_json::{json, Map, Value};

/// OpenAI retrievable MCP search tool name.
pub const OPENAI_RETRIEVABLE_SEARCH_TOOL_NAME: &str = "search";

/// OpenAI retrievable MCP fetch tool name.
pub const OPENAI_RETRIEVABLE_FETCH_TOOL_NAME: &str = "fetch";

/// Build the OpenAI-compatible `search` tool input schema.
#[must_use]
pub fn openai_retrievable_search_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": {
                "type": "string"
            }
        },
        "required": ["query"],
        "additionalProperties": false
    })
}

/// Build the OpenAI-compatible `fetch` tool input schema.
#[must_use]
pub fn openai_retrievable_fetch_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": {
                "type": "string"
            }
        },
        "required": ["id"],
        "additionalProperties": false
    })
}

/// Build the recommended OpenAI-compatible `search` output schema.
#[must_use]
pub fn openai_retrievable_search_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "title": { "type": "string" },
                        "url": { "type": "string" }
                    },
                    "required": ["id", "title", "url"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["results"],
        "additionalProperties": false
    })
}

/// Build the recommended OpenAI-compatible `fetch` output schema.
#[must_use]
pub fn openai_retrievable_fetch_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "title": { "type": "string" },
            "text": { "type": "string" },
            "url": { "type": "string" },
            "metadata": {
                "type": "object",
                "additionalProperties": true
            }
        },
        "required": ["id", "title", "text", "url"],
        "additionalProperties": false
    })
}

/// Build one OpenAI-compatible `search` result object.
///
/// Empty ids, titles, and URLs are preserved so conformance tests can catch
/// invalid callers rather than silently rewriting provider data.
#[must_use]
pub fn openai_retrievable_search_result(
    id: impl Into<String>,
    title: impl Into<String>,
    url: impl Into<String>,
) -> Value {
    json!({
        "id": id.into(),
        "title": title.into(),
        "url": url.into(),
    })
}

/// Build an OpenAI-compatible `search` response payload.
#[must_use]
pub fn openai_retrievable_search_response<I>(results: I) -> Value
where
    I: IntoIterator<Item = Value>,
{
    json!({
        "results": results.into_iter().collect::<Vec<_>>(),
    })
}

/// Build an OpenAI-compatible `fetch` response payload.
#[must_use]
pub fn openai_retrievable_fetch_response(
    id: impl Into<String>,
    title: impl Into<String>,
    text: impl Into<String>,
    url: impl Into<String>,
    metadata: Option<Map<String, Value>>,
) -> Value {
    let mut payload = Map::from_iter([
        ("id".to_string(), Value::String(id.into())),
        ("title".to_string(), Value::String(title.into())),
        ("text".to_string(), Value::String(text.into())),
        ("url".to_string(), Value::String(url.into())),
    ]);
    if let Some(metadata) = metadata {
        payload.insert("metadata".to_string(), Value::Object(metadata));
    }
    Value::Object(payload)
}

/// Return true when a value is a non-empty string suitable for citation URLs.
#[must_use]
pub fn has_non_empty_string_url(value: &Value) -> bool {
    value
        .get("url")
        .and_then(Value::as_str)
        .is_some_and(|url| !url.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        has_non_empty_string_url, openai_retrievable_fetch_input_schema,
        openai_retrievable_fetch_output_schema, openai_retrievable_fetch_response,
        openai_retrievable_search_input_schema, openai_retrievable_search_output_schema,
        openai_retrievable_search_response, openai_retrievable_search_result,
        OPENAI_RETRIEVABLE_FETCH_TOOL_NAME, OPENAI_RETRIEVABLE_SEARCH_TOOL_NAME,
    };
    use serde_json::{json, Map};

    #[test]
    fn retrievable_constants_use_literal_openai_tool_names() {
        assert_eq!(OPENAI_RETRIEVABLE_SEARCH_TOOL_NAME, "search");
        assert_eq!(OPENAI_RETRIEVABLE_FETCH_TOOL_NAME, "fetch");
    }

    #[test]
    fn retrievable_input_schemas_are_minimal_and_exact() {
        assert_eq!(
            openai_retrievable_search_input_schema(),
            json!({
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": false
            })
        );
        assert_eq!(
            openai_retrievable_fetch_input_schema(),
            json!({
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
                "additionalProperties": false
            })
        );
    }

    #[test]
    fn retrievable_output_schemas_match_recommended_shapes() {
        assert_eq!(
            openai_retrievable_search_output_schema()["required"],
            json!(["results"])
        );
        assert_eq!(
            openai_retrievable_fetch_output_schema()["required"],
            json!(["id", "title", "text", "url"])
        );
    }

    #[test]
    fn retrievable_response_builders_preserve_citation_urls() {
        let result =
            openai_retrievable_search_result("doc-1", "Quarterly plan", "https://example.test/doc");
        assert!(has_non_empty_string_url(&result));

        assert_eq!(
            openai_retrievable_search_response([result]),
            json!({
                "results": [{
                    "id": "doc-1",
                    "title": "Quarterly plan",
                    "url": "https://example.test/doc"
                }]
            })
        );

        let mut metadata = Map::new();
        metadata.insert("source".to_string(), json!("knowledge"));
        assert_eq!(
            openai_retrievable_fetch_response(
                "doc-1",
                "Quarterly plan",
                "Full text",
                "https://example.test/doc",
                Some(metadata),
            ),
            json!({
                "id": "doc-1",
                "title": "Quarterly plan",
                "text": "Full text",
                "url": "https://example.test/doc",
                "metadata": {"source": "knowledge"}
            })
        );
    }
}

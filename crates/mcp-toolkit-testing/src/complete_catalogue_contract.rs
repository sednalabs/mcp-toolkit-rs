//! Complete MCP catalogue conformance evidence.
//!
//! This module validates the boundary between protocol pagination and a host's
//! authoritative catalogue. It deliberately models request and response
//! cursors for every observed page so a test cannot substitute a first-page
//! sample for proof that the full cursor chain was drained.

use serde_json::Value;
use std::collections::HashSet;

/// One observed `tools/list` request and response page.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolListPageEvidence {
    pub request_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub tools: Vec<Value>,
}

impl ToolListPageEvidence {
    /// Builds one page of tool-list conformance evidence.
    #[must_use]
    pub fn new(
        request_cursor: Option<String>,
        tools: Vec<Value>,
        next_cursor: Option<String>,
    ) -> Self {
        Self {
            request_cursor,
            next_cursor,
            tools,
        }
    }
}

/// Proves that observed `tools/list` pages form one complete catalogue walk.
///
/// The assertion checks the full cursor chain, accepts an empty string as an
/// opaque non-null cursor, rejects cursor cycles and duplicate tool names, pins
/// the exact catalogue size, and requires named sentinels. Put at least one
/// sentinel beyond page one so the test fails when a host publishes only its
/// initial page.
///
/// ```
/// use mcp_toolkit_testing::complete_catalogue_contract::{
///     ToolListPageEvidence, assert_complete_tool_catalogue,
/// };
/// use serde_json::json;
///
/// let pages = [
///     ToolListPageEvidence::new(
///         None,
///         vec![json!({"name": "items.search"})],
///         Some("page-2".to_string()),
///     ),
///     ToolListPageEvidence::new(
///         Some("page-2".to_string()),
///         vec![json!({"name": "items.repair"})],
///         None,
///     ),
/// ];
///
/// assert_complete_tool_catalogue(&pages, 2, &["items.repair"]);
/// ```
///
/// # Panics
/// Panics when no pages were observed, the request/response cursor chain is
/// incomplete or cyclic, a descriptor has no non-empty string `name`, tool
/// names repeat, the exact tool count differs, or a required sentinel is
/// absent.
pub fn assert_complete_tool_catalogue(
    pages: &[ToolListPageEvidence],
    expected_tool_count: usize,
    required_tool_names: &[&str],
) {
    assert!(
        !pages.is_empty(),
        "complete tools/list evidence must include at least one page"
    );
    assert_eq!(
        pages[0].request_cursor, None,
        "the first tools/list request must not carry a cursor"
    );

    let mut observed_continuation_cursors = HashSet::new();
    let mut tool_names = HashSet::new();
    let mut ordered_tool_names = Vec::new();

    for (index, page) in pages.iter().enumerate() {
        if index > 0 {
            assert_eq!(
                page.request_cursor,
                pages[index - 1].next_cursor,
                "tools/list page {} did not request the exact opaque nextCursor from page {}",
                index + 1,
                index
            );
            assert!(
                page.request_cursor.is_some(),
                "tools/list evidence continued after a terminal page"
            );
        }

        if let Some(next_cursor) = &page.next_cursor {
            assert!(
                observed_continuation_cursors.insert(next_cursor.clone()),
                "tools/list evidence repeated or cycled cursor {next_cursor:?}"
            );
        } else {
            assert_eq!(
                index + 1,
                pages.len(),
                "tools/list evidence contains pages after a terminal response"
            );
        }

        for descriptor in &page.tools {
            let name = descriptor
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| {
                    panic!(
                        "tools/list page {} contains a descriptor without a non-empty string name",
                        index + 1
                    )
                });
            assert!(
                tool_names.insert(name.to_string()),
                "complete tools/list catalogue contains duplicate tool name {name:?}"
            );
            ordered_tool_names.push(name);
        }
    }

    assert!(
        pages.last().is_some_and(|page| page.next_cursor.is_none()),
        "final tools/list evidence page must omit nextCursor"
    );
    assert_eq!(
        ordered_tool_names.len(),
        expected_tool_count,
        "complete tools/list catalogue count differs; observed names: {ordered_tool_names:?}"
    );

    let missing = required_tool_names
        .iter()
        .copied()
        .filter(|required| !tool_names.contains(*required))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "complete tools/list catalogue is missing required sentinels {missing:?}; observed names: {ordered_tool_names:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::{assert_complete_tool_catalogue, ToolListPageEvidence};
    use serde_json::json;
    use std::panic::catch_unwind;

    #[test]
    fn accepts_complete_walk_with_empty_cursor_and_later_page_sentinel() {
        let pages = [
            ToolListPageEvidence::new(None, vec![json!({"name": "first"})], Some(String::new())),
            ToolListPageEvidence::new(Some(String::new()), vec![json!({"name": "sentinel"})], None),
        ];

        assert_complete_tool_catalogue(&pages, 2, &["sentinel"]);
    }

    #[test]
    fn rejects_first_page_only_evidence() {
        let pages = [ToolListPageEvidence::new(
            None,
            vec![json!({"name": "first"})],
            Some("page-2".to_string()),
        )];

        assert!(catch_unwind(|| assert_complete_tool_catalogue(&pages, 2, &["sentinel"])).is_err());
    }

    #[test]
    fn rejects_cursor_cycles_and_duplicate_tool_names() {
        let cursor_cycle = [
            ToolListPageEvidence::new(None, vec![json!({"name": "first"})], Some("a".to_string())),
            ToolListPageEvidence::new(
                Some("a".to_string()),
                vec![json!({"name": "second"})],
                Some("a".to_string()),
            ),
        ];
        let duplicate_names = [
            ToolListPageEvidence::new(
                None,
                vec![json!({"name": "same"})],
                Some("next".to_string()),
            ),
            ToolListPageEvidence::new(
                Some("next".to_string()),
                vec![json!({"name": "same"})],
                None,
            ),
        ];

        assert!(
            catch_unwind(|| assert_complete_tool_catalogue(&cursor_cycle, 2, &["second"])).is_err()
        );
        assert!(
            catch_unwind(|| assert_complete_tool_catalogue(&duplicate_names, 2, &["same"]))
                .is_err()
        );
    }

    #[test]
    fn rejects_broken_cursor_chain_and_missing_sentinel() {
        let broken_chain = [
            ToolListPageEvidence::new(
                None,
                vec![json!({"name": "first"})],
                Some("expected".to_string()),
            ),
            ToolListPageEvidence::new(
                Some("other".to_string()),
                vec![json!({"name": "second"})],
                None,
            ),
        ];
        let missing_sentinel = [ToolListPageEvidence::new(
            None,
            vec![json!({"name": "first"})],
            None,
        )];

        assert!(
            catch_unwind(|| assert_complete_tool_catalogue(&broken_chain, 2, &["second"])).is_err()
        );
        assert!(catch_unwind(|| assert_complete_tool_catalogue(
            &missing_sentinel,
            1,
            &["sentinel"]
        ))
        .is_err());
    }
}

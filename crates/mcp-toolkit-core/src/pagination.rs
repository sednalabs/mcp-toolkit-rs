//! # MCP List Pagination
//!
//! Shared cursor pagination helpers for MCP list operations.
//!
//! ## Ownership
//! This module owns transport-neutral helpers for MCP operations that support
//! `PaginatedRequestParams`, such as `tools/list`, `resources/list`,
//! `resources/templates/list`, and `prompts/list`.
//!
//! ## Non-ownership
//! This module does not choose a product's page size, sort order, visibility
//! policy, or stable inventory source. Callers must provide a deterministic item
//! sequence for a cursor to remain meaningful.
//!
//! ## Policy & Guarantees
//! * **Opaque cursors**: Cursor strings intentionally expose no contract beyond
//!   being round-trippable through this helper.
//! * **Fail loud**: Invalid cursors are reported as typed errors so servers can
//!   return MCP `Invalid params` instead of silently restarting pagination.
//!
//! ## References
//! * [MCP pagination](https://modelcontextprotocol.io/specification/draft/server/utilities/pagination)

use rmcp::model::PaginatedRequestParams;
use std::error::Error;
use std::fmt;

const CURSOR_PREFIX: &str = "mcp-toolkit-offset-v1:";

/// Page returned from a deterministic MCP list operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub start: usize,
    pub end: usize,
    pub total: usize,
}

impl<T> ListPage<T> {
    /// Returns `true` when the page did not include every remaining item.
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// Error returned when an MCP pagination request cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaginationError {
    EmptyPageSize,
    InvalidCursor(String),
    CursorOutOfRange { offset: usize, total: usize },
}

impl fmt::Display for PaginationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPageSize => formatter.write_str("page size must be greater than zero"),
            Self::InvalidCursor(cursor) => write!(formatter, "invalid pagination cursor: {cursor}"),
            Self::CursorOutOfRange { offset, total } => {
                write!(
                    formatter,
                    "pagination cursor offset {offset} is beyond item count {total}"
                )
            }
        }
    }
}

impl Error for PaginationError {}

/// Paginates a stable item slice using an MCP request cursor.
///
/// # Errors
/// Returns [`PaginationError::EmptyPageSize`] when `page_size` is zero,
/// [`PaginationError::InvalidCursor`] when the request cursor was not produced
/// by this helper, or [`PaginationError::CursorOutOfRange`] when the cursor
/// points beyond the supplied item sequence.
pub fn paginate_list<T: Clone>(
    items: &[T],
    request: Option<&PaginatedRequestParams>,
    page_size: usize,
) -> Result<ListPage<T>, PaginationError> {
    if page_size == 0 {
        return Err(PaginationError::EmptyPageSize);
    }

    let start = request
        .and_then(|params| params.cursor.as_deref())
        .map(parse_cursor)
        .transpose()?
        .unwrap_or(0);
    if start > items.len() {
        return Err(PaginationError::CursorOutOfRange {
            offset: start,
            total: items.len(),
        });
    }

    let end = start.saturating_add(page_size).min(items.len());
    let next_cursor = if end < items.len() {
        Some(format!("{CURSOR_PREFIX}{end}"))
    } else {
        None
    };

    Ok(ListPage {
        items: items[start..end].to_vec(),
        next_cursor,
        start,
        end,
        total: items.len(),
    })
}

fn parse_cursor(cursor: &str) -> Result<usize, PaginationError> {
    let Some(offset) = cursor.strip_prefix(CURSOR_PREFIX) else {
        return Err(PaginationError::InvalidCursor(cursor.to_string()));
    };
    offset
        .parse::<usize>()
        .map_err(|_| PaginationError::InvalidCursor(cursor.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{paginate_list, PaginationError};
    use rmcp::model::PaginatedRequestParams;

    #[test]
    fn first_page_returns_next_cursor_when_more_items_exist() {
        let items = ["a", "b", "c"];

        let page = paginate_list(&items, None, 2).expect("page should paginate");

        assert_eq!(page.items, vec!["a", "b"]);
        assert_eq!(
            page.next_cursor.as_deref(),
            Some("mcp-toolkit-offset-v1:2")
        );
        assert_eq!(page.start, 0);
        assert_eq!(page.end, 2);
        assert_eq!(page.total, 3);
        assert!(page.has_more());
    }

    #[test]
    fn cursor_page_resumes_at_encoded_offset() {
        let items = ["a", "b", "c"];
        let request = PaginatedRequestParams::default()
            .with_cursor(Some("mcp-toolkit-offset-v1:2".to_string()));

        let page = paginate_list(&items, Some(&request), 2).expect("page should paginate");

        assert_eq!(page.items, vec!["c"]);
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.start, 2);
        assert_eq!(page.end, 3);
        assert_eq!(page.total, 3);
        assert!(!page.has_more());
    }

    #[test]
    fn invalid_cursor_is_rejected() {
        let items = ["a", "b", "c"];
        let request = PaginatedRequestParams::default().with_cursor(Some("2".to_string()));

        let err = paginate_list(&items, Some(&request), 2).expect_err("cursor should fail");

        assert_eq!(err, PaginationError::InvalidCursor("2".to_string()));
    }

    #[test]
    fn out_of_range_cursor_is_rejected() {
        let items = ["a", "b", "c"];
        let request = PaginatedRequestParams::default()
            .with_cursor(Some("mcp-toolkit-offset-v1:4".to_string()));

        let err = paginate_list(&items, Some(&request), 2).expect_err("cursor should fail");

        assert_eq!(
            err,
            PaginationError::CursorOutOfRange {
                offset: 4,
                total: 3
            }
        );
    }

    #[test]
    fn empty_page_size_is_rejected() {
        let items = ["a", "b", "c"];

        let err = paginate_list(&items, None, 0).expect_err("page size should fail");

        assert_eq!(err, PaginationError::EmptyPageSize);
    }
}

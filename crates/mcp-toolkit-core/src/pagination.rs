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
//! * **Complete catalogue publication**: Client-side collection returns items
//!   only after the cursor chain terminates successfully. A bounded or cyclic
//!   walk fails without returning a partial catalogue.
//!
//! ## References
//! * [MCP pagination](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination)

use rmcp::model::PaginatedRequestParams;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::future::Future;

const CURSOR_PREFIX: &str = "mcp-toolkit-offset-v1:";

/// Default maximum number of pages accepted by [`collect_paginated_list`].
pub const DEFAULT_LIST_DRAIN_MAX_PAGES: usize = 64;

/// Default maximum number of items accepted by [`collect_paginated_list`].
pub const DEFAULT_LIST_DRAIN_MAX_ITEMS: usize = 10_000;

/// One page returned by a remote MCP list operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedListPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

impl<T> FetchedListPage<T> {
    /// Builds a fetched page from its items and opaque continuation cursor.
    #[must_use]
    pub fn new(items: Vec<T>, next_cursor: Option<String>) -> Self {
        Self { items, next_cursor }
    }
}

/// Safety limits for a complete remote-list collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListDrainLimits {
    pub max_pages: usize,
    pub max_items: usize,
}

impl ListDrainLimits {
    /// Builds explicit page and item limits.
    #[must_use]
    pub const fn new(max_pages: usize, max_items: usize) -> Self {
        Self {
            max_pages,
            max_items,
        }
    }
}

impl Default for ListDrainLimits {
    fn default() -> Self {
        Self::new(DEFAULT_LIST_DRAIN_MAX_PAGES, DEFAULT_LIST_DRAIN_MAX_ITEMS)
    }
}

/// Error returned while collecting a complete remote MCP list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListDrainError<E> {
    EmptyPageLimit,
    EmptyItemLimit,
    Fetch(E),
    RepeatedCursor(String),
    PageLimitExceeded {
        max_pages: usize,
    },
    ItemLimitExceeded {
        max_items: usize,
        observed_items: usize,
    },
}

impl<E: fmt::Display> fmt::Display for ListDrainError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPageLimit => formatter.write_str("list page limit must be greater than zero"),
            Self::EmptyItemLimit => formatter.write_str("list item limit must be greater than zero"),
            Self::Fetch(error) => write!(formatter, "list page fetch failed: {error}"),
            Self::RepeatedCursor(cursor) => {
                write!(formatter, "list pagination repeated cursor {cursor:?}")
            }
            Self::PageLimitExceeded { max_pages } => {
                write!(formatter, "list pagination exceeded {max_pages} pages")
            }
            Self::ItemLimitExceeded {
                max_items,
                observed_items,
            } => write!(
                formatter,
                "list pagination returned {observed_items} items, exceeding the limit of {max_items}"
            ),
        }
    }
}

impl<E: Error + 'static> Error for ListDrainError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Fetch(error) => Some(error),
            Self::EmptyPageLimit
            | Self::EmptyItemLimit
            | Self::RepeatedCursor(_)
            | Self::PageLimitExceeded { .. }
            | Self::ItemLimitExceeded { .. } => None,
        }
    }
}

/// Collects every page of a remote MCP list before returning any items.
///
/// The first fetch receives `None`. Every non-null `nextCursor` is passed back
/// unchanged as `Some(cursor)`, including the empty string. The collector
/// rejects repeated cursors and hard-limit breaches, so callers can publish the
/// returned vector atomically without accidentally treating a partial page walk
/// as the authoritative catalogue.
///
/// Serialized-byte and wall-clock limits remain transport-host concerns because
/// this helper neither serializes items nor owns I/O timeouts.
///
/// ```
/// # async fn example() -> Result<(), mcp_toolkit_core::pagination::ListDrainError<&'static str>> {
/// use mcp_toolkit_core::pagination::{
///     FetchedListPage, ListDrainLimits, collect_paginated_list,
/// };
///
/// let mut pages = vec![
///     FetchedListPage::new(vec!["alpha"], Some("next".to_string())),
///     FetchedListPage::new(vec!["omega"], None),
/// ]
/// .into_iter();
/// let catalogue = collect_paginated_list(ListDrainLimits::default(), move |_cursor| {
///     std::future::ready(pages.next().ok_or("missing fixture page"))
/// })
/// .await?;
///
/// assert_eq!(catalogue, vec!["alpha", "omega"]);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns [`ListDrainError::Fetch`] when the page callback fails,
/// [`ListDrainError::RepeatedCursor`] when a server repeats or cycles a cursor,
/// or a typed limit error when the configured page or item budget is invalid or
/// exceeded.
pub async fn collect_paginated_list<T, E, Fetch, FetchFuture>(
    limits: ListDrainLimits,
    mut fetch_page: Fetch,
) -> Result<Vec<T>, ListDrainError<E>>
where
    Fetch: FnMut(Option<String>) -> FetchFuture,
    FetchFuture: Future<Output = Result<FetchedListPage<T>, E>>,
{
    if limits.max_pages == 0 {
        return Err(ListDrainError::EmptyPageLimit);
    }
    if limits.max_items == 0 {
        return Err(ListDrainError::EmptyItemLimit);
    }

    let mut items = Vec::new();
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();

    for _ in 0..limits.max_pages {
        let page = fetch_page(cursor).await.map_err(ListDrainError::Fetch)?;
        let observed_items = items.len().saturating_add(page.items.len());
        if observed_items > limits.max_items {
            return Err(ListDrainError::ItemLimitExceeded {
                max_items: limits.max_items,
                observed_items,
            });
        }
        items.extend(page.items);

        let Some(next_cursor) = page.next_cursor else {
            return Ok(items);
        };
        if !seen_cursors.insert(next_cursor.clone()) {
            return Err(ListDrainError::RepeatedCursor(next_cursor));
        }
        cursor = Some(next_cursor);
    }

    Err(ListDrainError::PageLimitExceeded {
        max_pages: limits.max_pages,
    })
}

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
    use super::{
        collect_paginated_list, paginate_list, FetchedListPage, ListDrainError, ListDrainLimits,
        PaginationError,
    };
    use rmcp::model::PaginatedRequestParams;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        let output = future.as_mut().poll(&mut context);
        match output {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("fixture future unexpectedly returned pending"),
        }
    }

    #[test]
    fn first_page_returns_next_cursor_when_more_items_exist() {
        let items = ["a", "b", "c"];

        let page = paginate_list(&items, None, 2).expect("page should paginate");

        assert_eq!(page.items, vec!["a", "b"]);
        assert_eq!(page.next_cursor.as_deref(), Some("mcp-toolkit-offset-v1:2"));
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

    #[test]
    fn client_drain_collects_every_page_and_round_trips_empty_cursor() {
        let requests = Rc::new(RefCell::new(Vec::new()));
        let recorded_requests = Rc::clone(&requests);
        let mut pages = VecDeque::from([
            FetchedListPage::new(vec!["first"], Some(String::new())),
            FetchedListPage::new(vec!["sentinel"], Some("final".to_string())),
            FetchedListPage::new(vec!["last"], None),
        ]);

        let result = poll_ready(collect_paginated_list(
            ListDrainLimits::new(4, 10),
            move |cursor| {
                recorded_requests.borrow_mut().push(cursor);
                std::future::ready(
                    pages
                        .pop_front()
                        .ok_or_else(|| "missing fixture page".to_string()),
                )
            },
        ));

        assert_eq!(result, Ok(vec!["first", "sentinel", "last"]));
        assert_eq!(
            requests.borrow().as_slice(),
            &[None, Some(String::new()), Some("final".to_string())]
        );
    }

    #[test]
    fn client_drain_rejects_cursor_cycle_without_partial_success() {
        let mut pages = VecDeque::from([
            FetchedListPage::new(vec!["first"], Some("a".to_string())),
            FetchedListPage::new(vec!["second"], Some("b".to_string())),
            FetchedListPage::new(vec!["third"], Some("a".to_string())),
        ]);

        let result = poll_ready(collect_paginated_list(
            ListDrainLimits::new(4, 10),
            move |_cursor| {
                std::future::ready(
                    pages
                        .pop_front()
                        .ok_or_else(|| "missing fixture page".to_string()),
                )
            },
        ));

        assert_eq!(result, Err(ListDrainError::RepeatedCursor("a".to_string())));
    }

    #[test]
    fn client_drain_rejects_page_and_item_limit_breaches() {
        let page_limited = poll_ready(collect_paginated_list(
            ListDrainLimits::new(1, 10),
            |_cursor| {
                std::future::ready(Ok::<_, String>(FetchedListPage::new(
                    vec!["first"],
                    Some("more".to_string()),
                )))
            },
        ));
        let item_limited = poll_ready(collect_paginated_list(
            ListDrainLimits::new(2, 1),
            |_cursor| {
                std::future::ready(Ok::<_, String>(FetchedListPage::new(
                    vec!["first", "sentinel"],
                    None,
                )))
            },
        ));

        assert_eq!(
            page_limited,
            Err(ListDrainError::PageLimitExceeded { max_pages: 1 })
        );
        assert_eq!(
            item_limited,
            Err(ListDrainError::ItemLimitExceeded {
                max_items: 1,
                observed_items: 2,
            })
        );
    }

    #[test]
    fn client_drain_rejects_zero_limits_before_fetching() {
        let page_limit = poll_ready(collect_paginated_list(
            ListDrainLimits::new(0, 1),
            |_cursor| {
                std::future::ready(Ok::<_, String>(FetchedListPage::<String>::new(
                    Vec::new(),
                    None,
                )))
            },
        ));
        let item_limit = poll_ready(collect_paginated_list(
            ListDrainLimits::new(1, 0),
            |_cursor| {
                std::future::ready(Ok::<_, String>(FetchedListPage::<String>::new(
                    Vec::new(),
                    None,
                )))
            },
        ));

        assert_eq!(page_limit, Err(ListDrainError::EmptyPageLimit));
        assert_eq!(item_limit, Err(ListDrainError::EmptyItemLimit));
    }
}

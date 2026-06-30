//! # Tool Result Helpers
//!
//! Small adapters for MCP server tool-list behavior.
//!
//! ## Rationale
//! Servers that customize `ServerHandler::list_tools` usually do so to apply
//! service-owned visibility policy before returning `rmcp`'s tool schemas. This
//! module keeps the protocol mechanics for `tools/list` pagination in one place
//! so generated servers do not drift from the MCP list contract.
//!
//! ## Security Boundaries
//! * Callers own authorization and visibility filtering before passing tools in.
//! * Cursor validation is transport-neutral and maps invalid cursors to
//!   JSON-RPC `Invalid params`.
//!
//! ## References
//! * **MCP tools**: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
//! * **MCP pagination**: <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination>

use mcp_toolkit_core::pagination::{paginate_list, PaginationError};
use rmcp::model::{ListToolsResult, PaginatedRequestParams, Tool};

/// Default page size for generated `tools/list` implementations.
pub const DEFAULT_TOOLS_LIST_PAGE_SIZE: usize = 100;

/// Builds a `tools/list` result using the toolkit's default page size.
///
/// # Errors
/// Returns `ErrorData::invalid_params` when the request cursor is invalid for
/// the supplied tool sequence.
pub fn list_tools_result(
    tools: Vec<Tool>,
    request: Option<&PaginatedRequestParams>,
) -> Result<ListToolsResult, rmcp::ErrorData> {
    list_tools_result_with_page_size(tools, request, DEFAULT_TOOLS_LIST_PAGE_SIZE)
}

/// Builds a `tools/list` result using an explicit page size.
///
/// # Errors
/// Returns `ErrorData::invalid_params` when the request cursor is invalid for
/// the supplied tool sequence or when `page_size` is zero.
pub fn list_tools_result_with_page_size(
    tools: Vec<Tool>,
    request: Option<&PaginatedRequestParams>,
    page_size: usize,
) -> Result<ListToolsResult, rmcp::ErrorData> {
    let page = paginate_list(&tools, request, page_size).map_err(pagination_error)?;
    Ok(ListToolsResult {
        tools: page.items,
        meta: None,
        next_cursor: page.next_cursor,
    })
}

fn pagination_error(error: PaginationError) -> rmcp::ErrorData {
    rmcp::ErrorData::invalid_params(error.to_string(), None)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::model::{PaginatedRequestParams, Tool};

    use super::{
        list_tools_result, list_tools_result_with_page_size, DEFAULT_TOOLS_LIST_PAGE_SIZE,
    };

    #[test]
    fn default_result_paginates_large_surfaces() {
        let tools = (0..=DEFAULT_TOOLS_LIST_PAGE_SIZE)
            .map(|index| tool(&format!("tool_{index}")))
            .collect::<Vec<_>>();

        let result = list_tools_result(tools, None).expect("page");

        assert_eq!(result.tools.len(), DEFAULT_TOOLS_LIST_PAGE_SIZE);
        assert_eq!(
            result.next_cursor,
            Some(format!(
                "mcp-toolkit-offset-v1:{DEFAULT_TOOLS_LIST_PAGE_SIZE}"
            ))
        );
    }

    #[test]
    fn paginates_tool_results_and_returns_next_cursor() {
        let tools = vec![tool("alpha"), tool("beta"), tool("gamma")];

        let result = list_tools_result_with_page_size(tools, None, 2).expect("page");

        let names = result
            .tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["alpha", "beta"]);
        assert_eq!(
            result.next_cursor.as_deref(),
            Some("mcp-toolkit-offset-v1:2")
        );
    }

    #[test]
    fn rejects_invalid_tool_list_cursor() {
        let tools = vec![tool("alpha")];
        let request = PaginatedRequestParams::default().with_cursor(Some("1".to_string()));

        let error =
            list_tools_result_with_page_size(tools, Some(&request), 2).expect_err("cursor error");

        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_string(),
            format!("{name} description"),
            Arc::new(Default::default()),
        )
    }
}

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

use mcp_toolkit_core::{
    pagination::{paginate_list, PaginationError},
    tool_schema::{tool_names, tool_schema_snapshot_value},
};
use rmcp::model::{ListToolsResult, PaginatedRequestParams, Tool};

/// Default page size for generated `tools/list` implementations.
pub const DEFAULT_TOOLS_LIST_PAGE_SIZE: usize = 100;

/// Local tool-surface command supported by generated MCP server binaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolSurfaceCommand {
    /// Start the normal MCP transport.
    Serve,
    /// Print active tool names and exit.
    PrintTools,
    /// Print the canonical active tool schema snapshot and exit.
    PrintToolSchema,
    /// Run the generated-server doctor against the current working directory.
    Doctor,
    /// Print a copyable MCP client configuration snippet for the current project.
    PrintClientConfig,
    /// Print help text and exit.
    Help,
}

/// Parses local tool-surface command-line arguments from the current process.
///
/// # Errors
/// Returns an operator-facing error string when an unknown argument is provided
/// or when a supported command receives extra arguments.
pub fn tool_surface_command_from_env() -> Result<ToolSurfaceCommand, String> {
    tool_surface_command_from_args(std::env::args().skip(1))
}

/// Parses local tool-surface command-line arguments.
///
/// # Errors
/// Returns an operator-facing error string when an unknown argument is provided
/// or when a supported command receives extra arguments.
pub fn tool_surface_command_from_args<I, S>(args: I) -> Result<ToolSurfaceCommand, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    let Some(arg) = args.next() else {
        return Ok(ToolSurfaceCommand::Serve);
    };
    let arg = arg.as_ref();
    let command = match arg {
        "--print-tools" => ToolSurfaceCommand::PrintTools,
        "--print-tool-schema" => ToolSurfaceCommand::PrintToolSchema,
        "--doctor" => ToolSurfaceCommand::Doctor,
        "--print-client-config" => ToolSurfaceCommand::PrintClientConfig,
        "--help" | "-h" => ToolSurfaceCommand::Help,
        other => return Err(format!("unknown argument: {other}")),
    };

    if args.next().is_some() {
        return Err(format!("{arg} does not accept extra arguments"));
    }

    Ok(command)
}

/// Renders help text for generated MCP server binaries.
pub fn render_tool_surface_help(binary_name: &str) -> String {
    format!(
        "\
{binary_name}

USAGE:
    {binary_name} [--print-tools|--print-tool-schema|--doctor|--print-client-config]

OPTIONS:
    --print-tools          Print the active profile's tool names, then exit
    --print-tool-schema    Print the active profile's canonical tool schema snapshot, then exit
    --doctor               Run static generated-server checks for the current directory
    --print-client-config  Print a Codex-style MCP client config for the current directory
    -h, --help             Print this help text
"
    )
}

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

/// Renders a deterministic newline-separated list of MCP tool names.
///
/// # Errors
/// Returns a serialization error if any tool definition cannot be converted to
/// JSON for name extraction.
pub fn render_tool_names(tools: &[Tool]) -> Result<String, serde_json::Error> {
    let names = tool_names(tools)?;
    if names.is_empty() {
        return Ok(String::new());
    }
    Ok(format!("{}\n", names.join("\n")))
}

/// Renders a deterministic pretty JSON snapshot of MCP tool schemas.
///
/// The output uses the same `mcp_tool_schema_snapshot` envelope as
/// `mcp-toolkit-testing::assert_tool_schema_snapshot`, so operators can compare
/// a generated server's CLI output with committed contract snapshots.
///
/// # Errors
/// Returns a serialization error if any tool definition cannot be converted to
/// JSON.
pub fn render_tool_schema_snapshot(tools: &[Tool]) -> Result<String, serde_json::Error> {
    let snapshot = tool_schema_snapshot_value(tools)?;
    let mut rendered = serde_json::to_string_pretty(&snapshot)?;
    rendered.push('\n');
    Ok(rendered)
}

/// Renders a local tool-surface command that needs the active tool list.
///
/// # Errors
/// Returns a serialization error if any tool definition cannot be converted to
/// JSON for the requested output format.
pub fn render_tool_surface_command(
    command: ToolSurfaceCommand,
    tools: &[Tool],
) -> Result<Option<String>, serde_json::Error> {
    match command {
        ToolSurfaceCommand::Serve
        | ToolSurfaceCommand::Doctor
        | ToolSurfaceCommand::PrintClientConfig
        | ToolSurfaceCommand::Help => Ok(None),
        ToolSurfaceCommand::PrintTools => render_tool_names(tools).map(Some),
        ToolSurfaceCommand::PrintToolSchema => render_tool_schema_snapshot(tools).map(Some),
    }
}

fn pagination_error(error: PaginationError) -> rmcp::ErrorData {
    rmcp::ErrorData::invalid_params(error.to_string(), None)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::model::{PaginatedRequestParams, Tool};

    use super::{
        list_tools_result, list_tools_result_with_page_size, render_tool_names,
        render_tool_schema_snapshot, render_tool_surface_command, render_tool_surface_help,
        tool_surface_command_from_args, ToolSurfaceCommand, DEFAULT_TOOLS_LIST_PAGE_SIZE,
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

    #[test]
    fn renders_sorted_tool_names_for_cli_inspection() {
        let output = render_tool_names(&[tool("zeta"), tool("alpha")]).expect("render names");

        assert_eq!(output, "alpha\nzeta\n");
    }

    #[test]
    fn renders_schema_snapshot_for_cli_inspection() {
        let output = render_tool_schema_snapshot(&[tool("alpha")]).expect("render snapshot");
        let snapshot: serde_json::Value = serde_json::from_str(&output).expect("snapshot json");

        assert_eq!(snapshot["schema"], "mcp_tool_schema_snapshot");
        assert_eq!(snapshot["version"], 1);
        assert_eq!(snapshot["tools"][0]["name"], "alpha");
    }

    #[test]
    fn parses_tool_surface_commands() {
        assert_eq!(
            tool_surface_command_from_args(Vec::<String>::new()),
            Ok(ToolSurfaceCommand::Serve)
        );
        assert_eq!(
            tool_surface_command_from_args(["--print-tools"]),
            Ok(ToolSurfaceCommand::PrintTools)
        );
        assert_eq!(
            tool_surface_command_from_args(["--print-tool-schema"]),
            Ok(ToolSurfaceCommand::PrintToolSchema)
        );
        assert_eq!(
            tool_surface_command_from_args(["--doctor"]),
            Ok(ToolSurfaceCommand::Doctor)
        );
        assert_eq!(
            tool_surface_command_from_args(["--print-client-config"]),
            Ok(ToolSurfaceCommand::PrintClientConfig)
        );
        assert_eq!(
            tool_surface_command_from_args(["--help"]),
            Ok(ToolSurfaceCommand::Help)
        );
        assert!(tool_surface_command_from_args(["--print-tools", "extra"]).is_err());
        assert_eq!(
            tool_surface_command_from_args(["--bogus", "extra"]),
            Err("unknown argument: --bogus".to_string())
        );
    }

    #[test]
    fn renders_tool_surface_command_outputs() {
        let tools = vec![tool("alpha")];
        let names = render_tool_surface_command(ToolSurfaceCommand::PrintTools, &tools)
            .expect("render names")
            .expect("output");

        assert_eq!(names, "alpha\n");
        assert!(
            render_tool_surface_command(ToolSurfaceCommand::Serve, &tools)
                .expect("render serve")
                .is_none()
        );
    }

    #[test]
    fn renders_tool_surface_help_text() {
        let help = render_tool_surface_help("example-mcp");

        assert!(help.contains(
            "example-mcp [--print-tools|--print-tool-schema|--doctor|--print-client-config]"
        ));
        assert!(help.contains("--doctor"));
        assert!(help.contains("--print-client-config"));
        assert!(help.contains("--print-tool-schema"));
    }

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_string(),
            format!("{name} description"),
            Arc::new(Default::default()),
        )
    }
}

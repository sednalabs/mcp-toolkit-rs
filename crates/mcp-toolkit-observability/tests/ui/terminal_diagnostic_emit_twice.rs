use std::time::Duration;

use mcp_toolkit_observability::{
    DiagnosticToolName, RequestCorrelationId, ToolCallTerminalDiagnostic,
};

fn main() {
    let diagnostic = ToolCallTerminalDiagnostic::success(
        RequestCorrelationId::new("request-1").unwrap(),
        DiagnosticToolName::new("example.search").unwrap(),
        Duration::from_millis(5),
    );

    diagnostic.emit();
    diagnostic.emit();
}

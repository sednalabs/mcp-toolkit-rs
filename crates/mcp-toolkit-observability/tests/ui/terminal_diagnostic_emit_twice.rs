use std::time::Duration;

use mcp_toolkit_observability::{
    DiagnosticToolName, RequestCorrelationId, ToolCallTerminalDiagnostic,
};

fn main() {
    let diagnostic = ToolCallTerminalDiagnostic::success(
        RequestCorrelationId::parse("018f3f8e-7b9a-7d12-8c34-1234567890ab").unwrap(),
        DiagnosticToolName::new("example.search").unwrap(),
        Duration::from_millis(5),
    );

    diagnostic.emit();
    diagnostic.emit();
}

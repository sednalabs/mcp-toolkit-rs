//! # RMCP Model Helpers
//!
//! Constructor helpers for common RMCP/MCP model structures.
//!
//! ## When to use
//! Use these wrappers at the boundary where you construct protocol-facing
//! `rmcp` models and want the toolkit to apply a consistent protocol version or
//! handshake metadata. They are most useful in server startup, client bootstrap,
//! and transport adapters.
//!
//! Prefer the underlying `rmcp` builders directly when you already have a local
//! construction pattern and do not need the extra consistency layer.
//!
//! ## Ownership
//! This module owns the builder wrappers for `rmcp` models, providing a consistent
//! interface for initializing client and server information structures.
//!
//! ## Non-ownership
//! This module does not manage the model definitions themselves; it purely acts
//! as a wrapper layer for common `rmcp` model construction patterns.
//!
//! ## Policy & Guarantees
//! * **Consistent Initialization**: Ensures that critical model fields like `protocol_version`
//!   are consistently applied during construction.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying correct `ProtocolVersion` and implementation details.
//! * Providing valid configuration for model structures being built.

use rmcp::model::{
    ClientCapabilities, ClientInfo, Implementation, PaginatedRequestParams, ProtocolVersion,
    ReadResourceResult, ResourceContents, ServerCapabilities, ServerInfo,
};

/// Build client info with an explicit protocol version.
///
/// Use this when you want `ClientInfo` creation to stay consistent across
/// transport adapters or handshake helpers.
pub fn client_info(
    protocol_version: ProtocolVersion,
    capabilities: ClientCapabilities,
    client_info: Implementation,
) -> ClientInfo {
    ClientInfo::new(capabilities, client_info).with_protocol_version(protocol_version)
}

/// Build server info with an explicit protocol version and optional instructions.
///
/// Use this for server bootstrap metadata that should always carry the chosen
/// protocol version and optional startup instructions.
pub fn server_info(
    protocol_version: ProtocolVersion,
    capabilities: ServerCapabilities,
    server_info: Implementation,
    instructions: Option<String>,
) -> ServerInfo {
    let info = ServerInfo::new(capabilities)
        .with_protocol_version(protocol_version)
        .with_server_info(server_info);
    match instructions {
        Some(instructions) => info.with_instructions(instructions),
        None => info,
    }
}

/// Build paginated request params with an optional cursor.
///
/// Use this when forwarding cursor-based list or read requests through MCP
/// wrappers.
pub fn paginated_request_params(cursor: Option<String>) -> PaginatedRequestParams {
    PaginatedRequestParams::default().with_cursor(cursor)
}

/// Build a read-resource result from resource contents.
///
/// Use this to wrap resource payloads into the standard MCP response shape.
pub fn read_resource_result(contents: Vec<ResourceContents>) -> ReadResourceResult {
    ReadResourceResult::new(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_info_preserves_protocol_version() {
        let info = client_info(
            ProtocolVersion::V_2024_11_05,
            ClientCapabilities::default(),
            Implementation::new("probe", "0.1.0"),
        );
        assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);
        assert_eq!(info.client_info.name, "probe");
    }

    #[test]
    fn server_info_preserves_instructions() {
        let info = server_info(
            ProtocolVersion::V_2024_11_05,
            ServerCapabilities::default(),
            Implementation::new("server", "0.1.0"),
            Some("hello".to_string()),
        );
        assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);
        assert_eq!(info.instructions.as_deref(), Some("hello"));
    }

    #[test]
    fn paginated_request_params_sets_cursor() {
        let params = paginated_request_params(Some("next".to_string()));
        assert_eq!(params.cursor.as_deref(), Some("next"));
    }

    #[test]
    fn read_resource_result_wraps_contents() {
        let contents = vec![ResourceContents::text("memo://test", "ok")];
        let result = read_resource_result(contents.clone());
        assert_eq!(result.contents, contents);
    }
}

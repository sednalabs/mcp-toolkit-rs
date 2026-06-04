# Contract Testing Helpers

The `mcp-toolkit-testing` crate contains reusable assertions for the failure
modes that have historically been easy to miss in MCP servers: exported tool
drift, stdio callability, OAuth metadata shape, bearer challenges, and pre-auth
host rejection.

## Tool Schema Snapshots

Use `assert_tool_schema_snapshot` after the server has assembled its exported
tool list. Strict mode is the default; set
`MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1` only when intentionally rebaselining a
reviewed contract change.

Use `assert_json_contract_snapshot` for other JSON surfaces that need canonical
object ordering and strict/update behavior.

## Stdio Callability

Use `stdio_contract::assert_stdio_tools_list` in binary integration tests:

```rust
use mcp_toolkit_testing::stdio_contract::assert_stdio_tools_list;

#[test]
fn stdio_initializes_and_lists_tools() {
    assert_stdio_tools_list(
        env!("CARGO_BIN_EXE_my_server"),
        &["brief_target", "detail_by_tracking_id"],
    );
}
```

This helper spawns the real binary, performs the MCP `initialize` handshake,
sends `notifications/initialized`, calls `tools/list`, and compares the
exported tool names. It is intended to catch runtime wiring mistakes that a
direct `ToolRouter` unit test cannot see.

## Auth Surface Contracts

Use `auth_surface_contract::AuthSurfaceContract` for Protected Resource
Metadata and missing-token bearer challenges:

```rust
use mcp_toolkit_testing::auth_surface_contract::AuthSurfaceContract;

let contract = AuthSurfaceContract::new(
    "https://example.test/mcp",
    &["https://issuer.example"],
    &["example.read"],
    "example",
);

contract.assert_resource_metadata(&resource_metadata_json);
contract.assert_missing_token_response(response.status(), response.headers());
```

Use `AuthorizationServerMetadataContract` to pin authorization-server metadata,
including device authorization endpoints and grant type lists:

```rust
use mcp_toolkit_testing::auth_surface_contract::AuthorizationServerMetadataContract;

AuthorizationServerMetadataContract::new(
    "https://issuer.example",
    "https://issuer.example/oauth/authorize",
    "https://issuer.example/oauth/token",
)
.with_device_authorization_endpoint("https://issuer.example/oauth/device")
.with_grant_types_supported(&[
    "authorization_code",
    "urn:ietf:params:oauth:grant-type:device_code",
])
.assert_metadata(&authorization_server_metadata_json);
```

Use `assert_forbidden_without_bearer_challenge` for pre-auth guard failures.
For example, a bad-host `/mcp` request should be rejected by the host guard
before the auth layer emits a bearer challenge:

```rust
use mcp_toolkit_testing::auth_surface_contract::assert_forbidden_without_bearer_challenge;

assert_forbidden_without_bearer_challenge(response.status(), response.headers());
```

## Adoption Expectation

New toolkit-built servers should include at least:

- one strict tool-schema snapshot;
- one stdio or HTTP runtime smoke test, matching the served transport;
- auth metadata and bearer-challenge contract tests for hosted HTTP servers;
- pre-auth host rejection tests for hosted HTTP servers with host allowlists;
- GitHub-hosted CI that runs the strict contract tests without update-mode
  environment variables.

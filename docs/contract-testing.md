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

For runtime HTTP conformance tests, implement
`auth_surface_contract::AuthSurfaceProbeClient` over the server's existing test
client. The toolkit owns only the common assertions; each server still owns how
it starts an in-process router, spawned binary, or hosted test deployment.

```rust
use mcp_toolkit_testing::auth_surface_contract::{
    AuthSurfaceContract, AuthSurfaceProbeClient, AuthSurfaceProbeResponse,
    AuthSurfaceProbeResult,
};

struct ProbeClient {
    base_url: String,
}

impl AuthSurfaceProbeClient for ProbeClient {
    fn get_json(&mut self, path: &str) -> AuthSurfaceProbeResult<serde_json::Value> {
        let response = reqwest::blocking::get(format!("{}{}", self.base_url.trim_end_matches('/'), path))?;
        Ok(response.json()?)
    }

    fn get_unauthenticated(&mut self, path: &str) -> AuthSurfaceProbeResult<AuthSurfaceProbeResponse> {
        let response = reqwest::blocking::get(format!("{}{}", self.base_url.trim_end_matches('/'), path))?;
        let status = response.status();
        let headers = response.headers().clone();
        Ok(AuthSurfaceProbeResponse::new(status, headers))
    }
}

let contract = AuthSurfaceContract::new(
    "https://example.test/mcp",
    &["https://issuer.example"],
    &["example.read"],
    "example",
);

contract.assert_http_probe(&mut ProbeClient { base_url }, "/mcp");
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

`AuthorizationServerMetadataContract::assert_http_probe` can be used with the
same probe client when the server publishes inline authorization-server
metadata. Use `assert_http_probe_at` when the server intentionally exposes a
specific RFC 8414 alternate well-known path.

Use `assert_forbidden_without_bearer_challenge` for pre-auth guard failures.
For example, a bad-host `/mcp` request should be rejected by the host guard
before the auth layer emits a bearer challenge:

```rust
use mcp_toolkit_testing::auth_surface_contract::assert_forbidden_without_bearer_challenge;

assert_forbidden_without_bearer_challenge(response.status(), response.headers());
```

## OpenAI Apps Contracts

Use `openai_apps_contract::OpenAiAppsConformanceProfile` when a hosted HTTP
server is exposed as an OpenAI Apps connector. This profile is stricter than the
generic auth-surface contract: it checks protected-resource metadata,
authorization-code + PKCE metadata, declared client registration mode, Apps tool
descriptor `securitySchemes` parity, and runtime `mcp/www_authenticate`
challenges.

```rust
use mcp_toolkit_testing::openai_apps_contract::{
    OpenAiAppsClientRegistrationMode, OpenAiAppsConformanceProfile,
};

let authorization_servers = ["https://issuer.example"];
let required_scopes = ["example.read"];
let profile = OpenAiAppsConformanceProfile::new(
    "https://example.test/mcp",
    &authorization_servers,
)
.with_required_scopes(&required_scopes)
.with_client_registration(OpenAiAppsClientRegistrationMode::ClientIdMetadataDocument);

profile.assert_resource_metadata(&resource_metadata_json);
profile.assert_authorization_server_metadata(&authorization_server_metadata_json);
profile.assert_tool_descriptor(&apps_tool_descriptor_json);
profile.assert_tool_result_authenticate_meta(&tool_result_meta_json);
```

For large tool catalogs, validate the first paginated `tools/list` page as a
deliberate host discovery surface. This catches regressions where critical
tools exist on later pages but a client chooses tools from the initial page or a
deferred tool index is populated incompletely.

```rust
profile.assert_tool_list_page(
    &first_page_tool_descriptors,
    OpenAiAppsToolListPageBudget::new(40, 180_000, 32_000),
);
profile.assert_tool_list_first_page_contains_tools(
    &first_page_tool_descriptors,
    &["items.search", "items.read"],
);
profile.assert_tool_list_page_discovery_priorities(
    &first_page_tool_descriptors,
    "example/discovery",
);
```

## Adoption Expectation

New toolkit-built servers should include at least:

- one strict tool-schema snapshot;
- one stdio or HTTP runtime smoke test, matching the served transport;
- auth metadata and bearer-challenge contract tests for hosted HTTP servers;
- OpenAI Apps conformance tests for hosted HTTP servers intended for ChatGPT;
- pre-auth host rejection tests for hosted HTTP servers with host allowlists;
- GitHub-hosted CI that runs the strict contract tests without update-mode
  environment variables.

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

Use `stdio_contract::assert_stdio_tool_response_excludes_substrings` when the
same process-boundary test should also prove a starter or readback tool does
not serialize common secret material:

```rust
use mcp_toolkit_testing::stdio_contract::{
    assert_stdio_tool_response_excludes_substrings, assert_stdio_tools_list,
};
use serde_json::json;

assert_stdio_tools_list(env!("CARGO_BIN_EXE_my_server"), &["brief_target"]);
assert_stdio_tool_response_excludes_substrings(
    env!("CARGO_BIN_EXE_my_server"),
    "brief_target",
    json!({"target": "probe"}),
    &["BEGIN PRIVATE KEY", "GOOGLE_APPLICATION_CREDENTIALS"],
);
```

## Catalog Profile Contracts

Use `catalog_profile_contract` helpers when a server ships multiple catalog
profiles, especially the standard `read_only` and `operator` surfaces emitted
by the maintained templates:

```rust
use mcp_toolkit_core::tool_inventory::{ToolOperation, READ_ONLY_PROFILE_KEY};
use mcp_toolkit_testing::catalog_profile_contract::{
    assert_tool_catalog_profile_contains_tools, assert_tool_catalog_profile_contract,
};

let profile = server.catalog().require_profile(READ_ONLY_PROFILE_KEY)?;
let contract = server.inventory().catalog_contract(profile, ToolOperation::List);
assert_tool_catalog_profile_contract(&contract);
assert_tool_catalog_profile_contains_tools(&contract.to_value(), &["brief_target"]);
```

These tests protect both sides of profile-gated discovery: the default profile
must keep first-run clients narrow, while the operator profile remains visible
to reviewers and explicit deployments.

## Response Safety Contracts

Use `response_safety_contract` helpers for proof-only and sensitive-adjacent
tools where the serialized response contract matters more than an internal Rust
struct. These assertions are useful for no-mutation proof tools built with
`GuardedActionPosture::no_mutation_proof()`.

```rust
use mcp_toolkit_testing::response_safety_contract::{
    assert_no_mutation_proof_flags,
    assert_payload_excludes_substrings,
};

let report = build_send_wizard_readback_fixture();

assert_no_mutation_proof_flags(&report);
assert_payload_excludes_substrings(
    &report,
    &["person@example.invalid", "smtp-password"],
);
```

For service-specific flag names, use `assert_json_bool_field_false(&report,
"production_send_authorized")` alongside the standard proof assertions.

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

For large tool catalogues, the mandatory host-facing proof is a complete cursor
drain with an exact count and a required sentinel deliberately placed beyond
page one. Recording each request cursor prevents a first-page sample from being
mistaken for the catalogue contract.

```rust
use mcp_toolkit_testing::complete_catalogue_contract::{
    ToolListPageEvidence, assert_complete_tool_catalogue,
};

assert_complete_tool_catalogue(
    &observed_tool_list_pages,
    94,
    &["items.repair"],
);
```

Per-page budgets and first-page ordering may still be useful compatibility
hints for hosts with constrained previews. They are adjunct checks only: a
first-page assertion does not prove that a host collected, indexed, or can call
later-page tools.

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
- catalog-profile tests when the server exposes read-only, scratchpad,
  operator, or other filtered discovery surfaces;
- response-safety assertions for proof-only tools, sensitive reads, and
  redacted administrative readbacks;
- auth metadata and bearer-challenge contract tests for hosted HTTP servers;
- OpenAI Apps conformance tests for hosted HTTP servers intended for ChatGPT;
- pre-auth host rejection tests for hosted HTTP servers with host allowlists;
- GitHub-hosted CI that runs the strict contract tests without update-mode
  environment variables.

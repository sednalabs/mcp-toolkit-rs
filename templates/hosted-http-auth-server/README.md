# Hosted HTTP/Auth Server Starter

This template is the smallest maintained path for a hosted Streamable HTTP MCP
server with OAuth Protected Resource Metadata and bearer-auth enforcement.

It demonstrates:

- `mcp-toolkit-server::http::LocalMcpHttpServerBuilder` for HTTP runtime and
  route-bundle composition;
- explicit bind safety for non-loopback listeners;
- host allowlists for DNS rebinding defense;
- `AuthSurfaceBuilder` with public health checks and `/mcp` bearer challenges;
- standard `read_only` and `operator` catalog profiles, with
  `EXAMPLE_MCP_TOOL_PROFILE=read_only` as the default live MCP surface;
- device-code capable OAuth metadata for headless MCP client login;
- generated catalog-profile contract tests for `read_only` and `operator`;
- route-level auth-surface contract tests;
- tool schema snapshots for exported MCP tools;
- `--print-tools` and `--print-tool-schema` for local tool-surface inspection
  without binding the HTTP listener;
- `spec/mcp_probe_http_auth_smoke.v1.json` for a token-backed scripted
  `mcp-probe` smoke scenario against a running local server.

## Use

From this repository:

```bash
cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml
```

Run locally:

```bash
EXAMPLE_MCP_BIND_ADDR=127.0.0.1:9411 \
EXAMPLE_MCP_PUBLIC_BASE_URL=http://127.0.0.1:9411 \
EXAMPLE_MCP_ISSUER=http://issuer.example \
EXAMPLE_MCP_DELEGATION_SECRET=development-only-secret \
cargo run --manifest-path templates/hosted-http-auth-server/Cargo.toml
```

When copying the template into a new repository, replace the path dependencies
in `Cargo.toml` with Git dependencies, configure a real HTTPS
`EXAMPLE_MCP_PUBLIC_BASE_URL`, and use a production token validator instead of
the delegation-mode development skeleton.

Inspect the active profile's tool surface without starting a client or binding
HTTP:

```bash
cargo run --manifest-path templates/hosted-http-auth-server/Cargo.toml -- --print-tools
cargo run --manifest-path templates/hosted-http-auth-server/Cargo.toml -- --print-tool-schema
```

## Contract And Probe Checks

The generated tests cover profile contracts, route-level auth metadata,
schema drift, and bind safety:

```bash
cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml \
  --all-targets --all-features
```

The scripted probe scenario is intentionally bearer-token backed because `/mcp`
requires auth. Start the local server, place a valid test access token at the
configured `access_token_path`, then run:

```bash
MCP_PROBE_ALLOWED_HOSTS=127.0.0.1,localhost \
node /path/to/mcp-probe/dist/index.js run \
  --script spec/mcp_probe_http_auth_smoke.v1.json
```

## Headless MCP Device Auth

The template publishes OAuth metadata that can include a device authorization
endpoint. MCP clients can use that metadata to authenticate from SSH sessions,
remote shells, CI jobs, and other headless environments where a localhost
browser callback is inconvenient.

For [Codex Sedna](https://github.com/sednalabs/codex), configure the server in
`config.toml`, start the hosted MCP server, then run:

```bash
codex mcp login <server-name> --device-auth
```

Codex prints the verification URL and user code supplied by the authorization
server, then stores the resulting MCP credentials for that configured server.

## Safety Defaults

- The default bind address is loopback.
- Non-loopback binding is denied unless explicitly enabled.
- Auth is always required for `/mcp`.
- `/health` is public and should not include service-specific secrets.
- Host headers are allowlisted by default.
- Browser `Origin` headers are allowlisted by default. Use
  `EXAMPLE_MCP_ALLOWED_ORIGINS` with comma-separated full origins such as
  `https://app.example.com`.
- `EXAMPLE_MCP_TOOL_PROFILE` defaults to `read_only`; mutation tools should use
  the `operator` profile and `ToolCatalogEntry::with_operator_profile_gate()`.

## Snapshot Workflow

Strict mode:

```bash
cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml \
  tool_schema_snapshot_contract_is_stable
```

Intentional rebaseline:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 \
cargo test --manifest-path templates/hosted-http-auth-server/Cargo.toml \
  tool_schema_snapshot_contract_is_stable
```

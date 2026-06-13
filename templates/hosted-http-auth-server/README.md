# Hosted HTTP/Auth Server Starter

This template is the smallest maintained path for a hosted Streamable HTTP MCP
server with OAuth Protected Resource Metadata and bearer-auth enforcement.

It demonstrates:

- `mcp-toolkit-server` HTTP runtime and route-bundle composition;
- explicit bind safety for non-loopback listeners;
- host allowlists for DNS rebinding defense;
- `AuthSurfaceBuilder` with public health checks and `/mcp` bearer challenges;
- device-code capable OAuth metadata for headless MCP client login;
- route-level auth-surface contract tests;
- tool schema snapshots for exported MCP tools.

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

## Headless MCP Device Auth

The template publishes OAuth metadata that can include a device authorization
endpoint. MCP clients can use that metadata to authenticate from SSH sessions,
remote shells, CI jobs, and other headless environments where a localhost
browser callback is inconvenient.

For Codex Sedna, configure the server in `config.toml`, start the hosted MCP
server, then run:

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

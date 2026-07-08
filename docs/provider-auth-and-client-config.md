# Provider Auth, Profiles, And Client Configuration

This guide is the operator-facing companion to `docs/upstream-oauth.md`,
`docs/easy-server-ergonomics.md`, and `docs/security-profiles.md`. Use it when a
toolkit-built server calls a provider API such as Google Analytics, Google
Search Console, Cloudflare, or another upstream service.

Keep three boundaries separate:

- **MCP Auth** controls which client may call the MCP server.
- **Provider auth** controls which upstream API the MCP server may call.
- **Tool profiles** control which MCP tools are visible and runnable, such as
  `read_only`, `scratchpad`, or `operator`.

A server can pass one boundary and still fail another. For example, an MCP
client can be correctly linked while the upstream provider token lacks a scope,
or provider credentials can be valid while a mutation tool stays hidden by the
default `read_only` profile.

## Generated Server Defaults

Generated servers should default to the lowest-friction safe path:

- serve the `read_only` tool profile by default;
- keep mutation tools behind an explicit `operator` profile;
- use read-only provider scopes until a maintainer intentionally adds write
  tools;
- expose a credential-free status tool before requiring provider data access;
- return next-step diagnostics instead of opening a browser from data tools;
- keep hosted validation in GitHub Actions with strict contract tests.

Use `ToolCatalog::with_standard_profiles(["read"])` for the default
`read_only` and `operator` profile pair. Use
`ToolCatalogEntry::with_operator_profile_gate()` for mutation tools so they do
not appear in default discovery.

## Standard Setup Surface

Provider-backed servers should expose a small setup surface. Names can be
service-specific, but the behavior should stay consistent:

| Tool or command | Purpose |
| --- | --- |
| `auth_status` or `connection_status` | Report credential sources, selected scopes, cache presence, quota project, profile, and last verification result. |
| `auth_login` or `auth_browser_login` | Run an explicit user login flow when browser OAuth is the easiest trial path. |
| `auth_reauth` | Repeat login with forced consent when a refresh token is stale, rotated, or missing a new scope. |
| `auth_logout` | Remove local cached credentials and explain provider-side revocation separately. |
| `auth_probe` | Call a low-cost read-only endpoint to prove upstream access. |
| `print_client_config`, `mcp-toolkit client-config`, or docs equivalent | Show the MCP client command, URL, profile env vars, and restart notes without including secrets. |

Data tools should only use configured credentials. If credentials are missing,
return a redacted status-shaped error that points to the setup tool or CLI
command.

## Safe `auth_status` Shape

`auth_status` should be useful enough for remote debugging without returning
secret material. Prefer booleans, redacted paths, selected scopes, and concrete
next steps:

```json
{
  "ready": false,
  "profile": "read_only",
  "credential_sources": [
    {
      "kind": "application_default_credentials",
      "present": true,
      "path": "~/.config/gcloud/application_default_credentials.json"
    },
    {
      "kind": "service_account_file",
      "present": false,
      "env": "GOOGLE_APPLICATION_CREDENTIALS"
    }
  ],
  "scopes": [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/webmasters.readonly"
  ],
  "quota_project": {
    "configured": false
  },
  "last_verification": {
    "ok": false,
    "kind": "quota_project_missing",
    "message": "Set an ADC quota project and ensure the provider API is enabled."
  },
  "next_steps": [
    "gcloud auth application-default set-quota-project YOUR_PROJECT",
    "rerun auth_status with verification enabled"
  ]
}
```

Never include access tokens, refresh tokens, bearer headers, private keys,
client secrets, raw credential JSON, service-account private-key material, or
full provider responses in status output.

Use `mcp_toolkit_auth::provider_auth::ProviderAuthStatus` for this shape when a
server is implemented in Rust. Populate credential sources with
`ProviderCredentialSourceStatus`, quota state with `ProviderQuotaProjectStatus`,
and probe results with `ProviderAuthVerification`. Those types are deliberately
secret-safe status containers; credential loading and provider probing still
belong in the server or provider SDK.

## Credential Source Order

Use provider-standard credentials when they exist. A typical precedence order is:

1. Server-specific explicit credential configuration for sealed deployments.
2. Provider-standard environment variables or credential files.
3. Local CLI or application-default user credentials for trials.
4. Metadata-service credentials in cloud runtimes.

For providers with both personal OAuth and service accounts, support both when
the dependencies already make that cheap. Personal OAuth is usually the easiest
human trial path. Service accounts are usually the unattended deployment path,
but they still need provider-side resource permissions.

## Google Provider Defaults

For Google-backed MCP servers, keep the first-run path explicit and boring:

1. Enable the required API on a Google Cloud project.
2. Choose a quota project that the operator may use for billing/quota.
3. Authenticate with Application Default Credentials for the read-only trial.
4. Set the ADC quota project.
5. Run `auth_status` or `auth_probe` before starting data tools.

Example for a read-only Search Console-style server:

```bash
gcloud auth application-default login \
  --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/webmasters.readonly
gcloud auth application-default set-quota-project YOUR_PROJECT
```

Some Google APIs reject local ADC requests without
`https://www.googleapis.com/auth/cloud-platform` even when the provider-specific
read scope is also present. If verification fails with a quota-project or
disabled-API error, set the quota project, enable the upstream API on that
project, and make sure the authenticated principal may use the project for
quota.

When several Google MCP servers share one OS user, prefer a server-specific
ADC file instead of the conventional global gcloud ADC file. Run `gcloud auth
application-default login` with a service-specific `CLOUDSDK_CONFIG` directory,
then have the server read that directory's
`application_default_credentials.json` through
`mcp_toolkit_auth::upstream_oauth::google_authorized_user_adc_from_file`.
This keeps one server's scope update from replacing another server's refresh
token grant.

When the server owns browser OAuth directly, use
`mcp_toolkit_auth::upstream_oauth` instead of hand-rolled token exchange. Prefer
a Desktop OAuth client for dynamic loopback ports. For SSH or remote hosts,
print the authorization URL and use a loopback port forward, ask the operator
to paste the final loopback callback URL into
`PendingLoopbackAuthorization::finish_with_callback_url`, or use a two-step MCP
login tool that starts the listener and completes after the callback. When a
Google server wants ADC-compatible runtime behavior after direct browser OAuth,
store the token response with `save_google_authorized_user_adc` and then load it
through `google_authorized_user_adc_from_file`.

For Google ADC paths, use `mcp_toolkit_auth::provider_auth` helpers to keep
scopes and diagnostics consistent:

- `GoogleProviderAuthConfig::adc_login_scopes()` and
  `google_adc_login_command()` include
  `https://www.googleapis.com/auth/cloud-platform` with provider read scopes;
- `GoogleProviderAuthConfig::adc_setup_plan()` returns a secret-safe,
  serializable command plan for browser login, headless login, client-id-file
  fallback, ADC quota project, and one-or-more API enablement hints;
- `ProviderAuthCommand` carries both argv and a copyable shell rendering so
  MCP auth tools can avoid hand-rolled command strings;
- `classify_google_provider_auth_error()` maps common Google failures into
  stable kinds such as `missing_quota_project`, `api_disabled`,
  `missing_scope`, `permission_denied`, `oauth_app_blocked`, and
  `reauth_required`;
- `google_quota_project_next_steps()` returns the canonical ADC quota-project
  remediation sequence.

For unattended Google deployments, prefer a service-account file or workload
identity path. Configure the service-account credential with the provider's
standard environment variable or a service-specific variable, grant that
principal access to the provider resource, and keep user OAuth caches out of the
deployment artifact.

## Scopes And Tool Profiles

Read and write authorization should line up across provider scopes and MCP tool
profiles:

- `read_only` profile: read scopes only, no mutation tools in discovery.
- `scratchpad` profile: analytical or large-result helpers, still non-mutating
  unless the service explicitly documents otherwise.
- `operator` profile: mutation-ready tools and any provider write scopes.

If a mutation tool is hidden by the default profile, return the catalog/profile
denial such as `TOOL_DENIED_READ_ONLY_PROFILE`. If the tool is visible but the
provider rejects the call, report provider auth or permission state instead.
That distinction keeps "login again", "enable operator profile", and "grant
upstream access" from collapsing into one vague failure.

## MCP Client Configuration

Client configuration formats vary, but the generated server should document the
same fields every time:

- server name;
- transport (`stdio` command or hosted HTTP URL);
- environment variables that select the tool profile;
- auth/login command, if provider login is external to the MCP client;
- restart guidance after changing credentials, profile, binary path, or hosted
  URL.

For maintained Rust starter templates, use the toolkit front door after
generation:

```bash
mcp-toolkit client-config ./my-mcp-server
```

From inside a maintained generated starter, `cargo run -- --print-client-config`
prints the same kind of client snippet without requiring the operator to find
the toolkit binary first.

Use `--transport stdio` or `--transport http` if the scaffold is incomplete and
the transport cannot be inferred yet. Use `--command`, `--url`, `--name`, and
`--profile` when rendering deployment-specific snippets.

For a stdio server, the client configuration usually points at the built binary
and pins the safe profile:

```toml
[mcp_servers.my_mcp_server]
command = "/opt/my-mcp-server/bin/my-mcp-server"
args = []

[mcp_servers.my_mcp_server.env]
MY_MCP_SERVER_TOOL_PROFILE = "read_only"
```

For a hosted HTTP/auth server, the client configuration usually points at the
public MCP URL. MCP Auth, device authorization, or dynamic client registration
then controls the client-to-server login:

```toml
[mcp_servers.my_mcp_server]
url = "https://my-mcp-server.example.com/mcp"
```

For local hosted trials, use loopback URLs only in local config. Public
Protected Resource Metadata should describe the externally reachable MCP URL
before a remote client links.

## Troubleshooting Matrix

| Symptom | Boundary | Likely fix |
| --- | --- | --- |
| `auth_status` reports no credential material | Provider auth | Run the provider login command or configure the service-account credential source. |
| Provider says scope is missing | Provider auth | Re-run login with the documented read or operator scopes; use `auth_reauth` when cached consent is stale. |
| Google reports missing quota project | Provider auth | Run `gcloud auth application-default set-quota-project YOUR_PROJECT`; ensure the API is enabled and the principal may use the project for quota. |
| Google reports API disabled | Provider auth | Enable the required API on the quota project, then re-run `auth_probe`. |
| Tool is not listed in `tools/list` | Tool profile | Check the selected profile and restart the MCP client after changing profile env vars. |
| Tool is listed but returns `TOOL_DENIED_READ_ONLY_PROFILE` | Tool profile | Switch to an explicit operator profile only after reviewing the write surface. |
| Hosted `/mcp` returns a bearer challenge | MCP Auth | Link or refresh the MCP client login for the hosted server. |
| Stdio client still uses old settings | Client process | Restart the MCP client so it launches a new server process with the new env and binary. |

## Documentation Checklist

Before closing a provider-auth docs slice, ensure the server README or generated
docs include:

- the default profile and how to opt into any operator profile;
- the read-only scopes and any separate operator scopes;
- the exact login, reauth, logout, status, and probe command names;
- the credential source precedence;
- service-account or unattended deployment notes;
- quota-project or billing-project requirements where applicable;
- client configuration examples for the served transport;
- restart guidance for long-lived MCP clients;
- redaction guarantees for status and error output.

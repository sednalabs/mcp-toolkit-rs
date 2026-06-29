# Upstream OAuth

`mcp_toolkit_auth::upstream_oauth` is for MCP servers that need to call an
upstream API with user or operator consent. It is separate from MCP Auth:

- MCP Auth proves that a client may call the MCP server.
- Upstream OAuth proves that the MCP server may call a provider API.

The `upstream` name is intentional: it marks server-to-provider API
authorization, not inbound MCP authorization. Treat the module path as alpha API
until the first non-alpha `0.1.0` release.

A hosted MCP server can use both. Keep the tool names, configuration, and docs
clear so operators know which side of the boundary they are changing.

## Recommended Server Shape

For provider APIs such as Google Search Console or Google Analytics, expose a
small setup surface:

- `auth_status`: reports configured credential sources, selected scopes, cache
  presence, and optional token-acquisition proof without returning tokens;
- `auth_browser_login`: starts or runs an explicit browser login flow;
- `auth_reauth`: repeats browser login with provider-specific forced consent
  when the refresh token is invalid or stale;
- `auth_logout`: removes the local cache and explains provider-side revocation
  separately;
- `auth_probe`: calls a low-cost read-only endpoint to prove upstream access.

Data tools should never open a browser. They should either use a configured
credential source or return a next-step error that points to the setup tool.

## Google Browser OAuth Defaults

For Google upstream APIs, the toolkit provides:

- `google_oauth_client_from_file` / `google_oauth_client_from_slice` for
  downloaded OAuth client JSON;
- `LoopbackOAuthOptions::google_login()` for normal browser login with offline
  access;
- `LoopbackOAuthOptions::google_reauth()` for fresh consent when replacing a
  refresh token;
- `start_loopback_authorization` for PKCE S256 authorization-code flow using a
  local loopback callback;
- `RefreshTokenFileStore` for refresh-token cache files with Unix owner-only
  permissions and cross-platform symlink/non-file guards, including symlinked
  ancestor directories;
- `RefreshTokenProvider` for cached access-token refreshes, including
  provider-issued replacement refresh tokens.

The helper uses `oauth2` for authorization URL construction, PKCE, code
exchange, refresh-token exchange, and response parsing. Token endpoint HTTP is
toolkit-owned and disables redirects, so downstream servers do not need to pass
or correctly configure a lower-level HTTP client. Provider-neutral configs can
select request-body or HTTP Basic client authentication with
`OAuthClientAuthMethod`.

The Google parser accepts `installed` and `web` client-secret JSON objects, but
the easiest local trial path should use a Desktop client where possible.
Desktop clients are the normal choice for dynamic loopback ports. Web clients
work when the generated loopback redirect URI exactly matches one of the client
file's registered redirect URIs. For Google loopback web-client trials, a
registered URI without a port can also match a runtime port when the scheme,
path, and query are the same and the hosts are common loopback aliases such as
`localhost`, `127.0.0.1`, or `[::1]`. With the default callback path, register
`http://localhost/oauth/callback` or `http://127.0.0.1/oauth/callback` for that
shape. Otherwise the helper fails before sending the user into consent.

## SSH And Headless Operation

The loopback helper returns the authorization URL and redirect URI before it
waits for completion. Servers can use that in two low-friction ways:

- a CLI command can print the URL, listen on the loopback port, and wait;
- a two-step MCP tool can return a URL/session first, then complete on a follow
  up tool call while the server keeps the pending listener.

For SSH or remote hosts, bind the callback to loopback on the remote host and
use an SSH local port forward from the browser-capable machine. Prefer a fresh
port for retry after state mismatch, stale tabs, or callback refusal.

## Token Handling Rules

Do not log, return, serialize into tool output, or include in errors:

- access tokens;
- refresh tokens;
- client secrets;
- private keys;
- bearer headers;
- raw credential JSON.

Use status booleans and redacted metadata instead: client id present, cache
path, refresh-token present, scopes, expiry metadata, and last verification
result. On Unix, file-backed refresh-token caches must be owner-only. On other
platforms, prefer the user's profile-protected config directory or a
platform-native secret store when stronger local-at-rest guarantees are needed.
The file store hardens directories it creates for the cache, but it does not
chmod existing parent directories; use an app-specific cache path rather than a
shared directory when possible. Symlinked cache files or ancestor directories
are rejected so a cache path cannot silently escape the intended config tree.
When `RefreshTokenProvider::take_replacement_refresh_token()` returns metadata,
persist the replacement token, scopes, token type, and expiry promptly so
providers that rotate refresh tokens do not strand the next refresh or leave
status output stale.

## Generator Guidance

Future OpenAPI or documentation-to-MCP generators should treat upstream OAuth as
a reusable provider seam:

1. Read OAuth security schemes and scope metadata from the source document.
2. Generate setup/status/probe tools from the toolkit pattern.
3. Generate provider config and token-provider plumbing, not provider-specific
   ad hoc token exchange code.
4. Leave exact scopes, read/write profile gates, and first useful probe endpoint
   in the generated review report for maintainer confirmation.

Generated servers should default to read-only scopes when available, avoid raw
HTTP pass-through tools, and require review before exposing mutating operations.

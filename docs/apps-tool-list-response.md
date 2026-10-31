# ChatGPT Apps tools/list HTTP security metadata

Hosted MCP Apps clients may require OAuth `securitySchemes` at both
the tool descriptor's top level and `_meta.securitySchemes`. Toolkit
already provides a pure JSON normalizer in `mcp-toolkit-core::mcp_apps`.

For hosted Rust/Axum servers using RMCP's Tool model, enable the optional
`mcp-toolkit-server` `http` feature and attach its
`apps_http::mirror_apps_tool_security_schemes` middleware **only** to the
protected MCP route. The middleware reads successful, uncompressed
`application/json` responses (maximum 256 KiB), copies tool security
metadata using the core normalizer, and leaves SSE subscription streams,
denied requests, and other methods unchanged. When the bytes change it
removes stale Content-Length and ETag headers.

The caller must still enforce authentication/authorisation, scope checks,
per-tool discovery policy, and the host's actual OAuth linking protocol.
The middleware is opt-in to avoid changing non-Apps services, and it
does **not** advertise or invent an OAuth permission: it only mirrors
the server-authored declaration already available on the Tool value.

This addresses a real last-mile descriptor mismatch in
[IRC MCP PR #1](https://github.com/sednalabs/irc-mcp/pull/1).
A future RMCP Tool model supporting first-class top-level security schemes
may replace this compatibility adapter.

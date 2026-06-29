# Auth Error Contracts

This document defines the stable error contract used by `mcp-toolkit-auth`
when an MCP HTTP server rejects a request during authentication or
authorization.

The contract has two audiences:

- OAuth clients receive a low-leakage RFC 6750 wire error in
  `WWW-Authenticate`.
- Servers, tests, observers, and policy integrations receive a stable internal
  decision code through `AuthError::contract()` and
  `AuthError::decision_code()`.

The two values are intentionally separate. RFC 6750 allows only a small public
error vocabulary, while operators need more precise internal decision labels.

## Wire Contract

Auth failures continue to use the same HTTP status and bearer challenge shape:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp", error="invalid_token"
```

The bearer `error` parameter is limited to RFC 6750 values:

| Failure class | HTTP status | Bearer error |
| --- | ---: | --- |
| Missing bearer token | 401 | `invalid_request` |
| Invalid bearer token | 401 | `invalid_token` |
| Expired token | 401 | `invalid_token` |
| Malformed token or request | 400 or 401 | `invalid_request` or `invalid_token` |
| Wrong issuer or audience | 401 | `invalid_token` |
| Insufficient scope | 403 | `insufficient_scope` |
| Forbidden by policy | 403 | `insufficient_scope` |
| Internal auth configuration failure | 500 | none |

`error_description` is present only for low-leakage cases such as a missing
token, an expired token, a replayed token, or missing scopes. Token parsing and
validation failures do not expose claim-level detail in the public challenge.

The response body remains a short public message for compatibility with
existing clients that display or log body text. Clients should prefer the
bearer challenge for machine-readable OAuth handling.

## Internal Decision Codes

`AuthError::contract()` returns an `AuthErrorContract` with a non-null
`decision_code`. This code is the stable value for logs, auth failure
observers, tests, and service policy hooks.

| Failure class | Decision code |
| --- | --- |
| Missing bearer token | `MISSING_BEARER_TOKEN` |
| Invalid bearer token | `INVALID_BEARER_TOKEN` |
| Expired token | `TOKEN_EXPIRED` |
| Token replay detected | `TOKEN_REPLAY_DETECTED` |
| Malformed token or required claim missing | `MALFORMED_BEARER_TOKEN` |
| Wrong issuer or audience | `TOKEN_ISSUER_OR_AUDIENCE_MISMATCH` |
| Insufficient scope | `INSUFFICIENT_SCOPE` |
| Client not allowed for this service | `AUTH_CLIENT_NOT_ALLOWED` |
| Forbidden by policy | `AUTH_POLICY_DENIED` |
| Auth configuration failure | `AUTH_CONFIG_ERROR` |
| Unexpected internal auth failure | `AUTH_INTERNAL_ERROR` |
| Other auth failure | `AUTH_FAILURE` |

Service-specific generic errors may set an explicit stable code with
`AuthError::with_code()`. Explicit codes take precedence over fallback mapping
from status or reason.

## Mapping Guidance

Use the specific `AuthError` variants whenever possible:

- `MissingToken` for absent bearer credentials.
- `InvalidToken` for opaque invalid credentials.
- `TokenExpired` for expired JWTs or provider responses.
- `ReplayDetected` when replay protection rejects a token.
- `MissingScopes` when a valid token lacks required scopes.
- `ConfigError` when server-side auth configuration is invalid.

For generic provider errors, attach a stable reason with
`AuthError::with_reason()`. The toolkit maps common reasons into canonical
decision codes:

| Generic reason | Decision code | Bearer error |
| --- | --- | --- |
| `invalid_issuer`, `invalid_audience`, `issuer_mismatch` | `TOKEN_ISSUER_OR_AUDIENCE_MISMATCH` | `invalid_token` |
| `invalid_token`, `invalid_signature`, `invalid_algorithm`, `invalid_key` | `INVALID_BEARER_TOKEN` | `invalid_token` |
| `missing_kid`, `kid_not_found`, `invalid_key_use`, `immature_signature` | `INVALID_BEARER_TOKEN` | `invalid_token` |
| `invalid_subject`, `missing_claim` | `MALFORMED_BEARER_TOKEN` | `invalid_token` |
| `insufficient_scope`, `missing_scopes` | `INSUFFICIENT_SCOPE` | `insufficient_scope` |
| `client_not_allowed` | `AUTH_CLIENT_NOT_ALLOWED` | `insufficient_scope` |
| `policy_denied`, `forbidden` | `AUTH_POLICY_DENIED` | `insufficient_scope` |

Unknown generic errors fall back by status:

| HTTP status | Decision code | Bearer error |
| ---: | --- | --- |
| 400 | `MALFORMED_BEARER_TOKEN` | `invalid_request` |
| 401 | `INVALID_BEARER_TOKEN` | `invalid_token` |
| 403 | `AUTH_POLICY_DENIED` | `insufficient_scope` |
| 500-599 | `AUTH_INTERNAL_ERROR` | none |
| Other | `AUTH_FAILURE` | none |

## Compatibility Notes

This contract preserves the public RFC 6750 bearer error vocabulary. The new
decision code is for internal and operator-facing surfaces, so clients that
already rely on `WWW-Authenticate` continue to see standard OAuth error values.

Auth failure observers now receive the internal decision code rather than the
RFC 6750 bearer error. This avoids ambiguous `invalid_token` buckets and keeps
the observer contract free of null placeholders.

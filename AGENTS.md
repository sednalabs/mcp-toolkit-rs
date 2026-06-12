# Rust MCP Toolkit Guidelines

This document defines the engineering and documentation standards for `mcp-toolkit-rs`.
Our goal is reliable, low-noise engineering guidance. We leverage Rust's strong
type system for safety and use documentation to explain *why*, not just *what*.

## 1. The "Lean" Documentation Standard

We adhere to a pragmatic lean docstring standard. We avoid repetitive "reference bloat" by anchoring context at the module level.

### Module-Level Documentation (`//!`)
Every `lib.rs` and major `mod.rs` MUST start with a context block. This is the **only** place where general Design Docs, ADRs, or broad Spec links should live.

```rust
//! # MCP Toolkit Core
//!
//! primitives and traits for the Model Context Protocol.
//!
//! ## Rationale
//! Provides a type-safe foundation for building MCP servers and clients without
//! adhering to a specific transport implementation.
//!
//! ## Security Boundaries
//! * Pure data types only; no network I/O.
//! * Parsing logic must be fuzz-tested.
//!
//! ## References
//! * **SPEC**: [Model Context Protocol v1.0](https://...)
//! * **DESIGN**: `docs/design/rust-toolkit-architecture.md`
```

### Item-Level Documentation (`///`)
Public functions and structs focus on **usage**, **safety**, and **correctness**.
*   **Do not** repeat generic references on every function.
*   **Do** include specific spec clauses if the implementation is non-obvious (e.g., "Implements exponential backoff per MCP Spec §4.2").

**Required Sections:**
1.  **Summary**: One active-verb sentence.
2.  **# Errors**: Explicitly state conditions for `Err` variants.
3.  **# Security**: Mandatory if the function handles auth, input validation, or unsafe blocks.
4.  **# Panics**: If the function can panic (avoid this in library code).

**Example:**

```rust
/// Validates a client capability handshake.
///
/// Ensures the client supports the required protocol version and features.
///
/// # Errors
/// Returns `HandshakeError::VersionMismatch` if the client protocol < 1.0.
///
/// # Security
/// * Constant-time comparison used for session tokens.
/// * Rejects payloads > 1MB to prevent DoS.
pub fn validate_handshake(req: &HandshakeReq) -> Result<(), HandshakeError> { ... }
```

## 2. Rust Idioms & Quality

*   **Clippy**: No warnings allowed (`cargo clippy --all-targets --all-features`).
*   **Unwrap**: `unwrap()` and `expect()` are forbidden in library code. Propagate errors.
*   **Async**: Use `async-trait` only when necessary. Prefer pure functional logic where possible.
*   **Testing**:
    *   Unit tests in the same file (`mod tests`).
    *   Integration tests in `tests/` directory.
    *   Doc tests are required for public APIs.

## 3. Crate Structure

*   `mcp-toolkit-core`: Types, traits, minimal deps.
*   `mcp-toolkit-http`: SSE/Post transports.
*   `mcp-toolkit-auth`: Authz/Authn logic.
*   (Keep dependencies shallow. Do not depend on `mcp-toolkit-http` from `core`.)

## Engineering Style

Prefer solutions that are:

1. Small and direct.
2. Incremental and reversible.
3. Easy to understand for new contributors.
4. Backed by clear tooling and tests.
5. Consistent with existing architecture and repository conventions.

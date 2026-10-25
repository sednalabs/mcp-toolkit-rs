# The next small service

Start with the maintained lean template, not a copy of provider-specific glue.
From the toolkit checkout (Rust 1.99.0):

```sh
cargo run --locked -p mcp-toolkit --bin mcp-toolkit -- new \
  --name archive-mcp --template curated-stdio-intent \
  --output archive-mcp --toolkit-root .
cd archive-mcp
cargo fmt --all
cargo test
cargo run -- --print-client-config
```

The CLI resolves `--toolkit-root .` before writing dependencies. The generated
`rust-toolchain.toml` selects Rust 1.99.0 even outside the toolkit checkout;
rustup may download it on first use. Keep the generated `Cargo.lock` after the
first resolution, then use `cargo test --locked`. No credentials or live backend
are needed for the starter tests. For a published toolkit dependency, generate with `--toolkit-git URL` instead
of a local root, then pin each generated toolkit Git dependency to the same
reviewed commit using Cargo's `rev` field. Do not invent an unpublished revision.

## Add only the provider-specific parts

- Keep typed RMCP routes aligned with the starter's `ToolCatalog` / `ToolInventory`
  metadata and profile checks.
- Keep setup/status useful when no provider is configured; a read-only hint does
  not authorize access or constrain handler implementation.
- Keep account binding, command allowlists, credentials and response filtering
  in your service. Reuse the existing stdio contract helpers for offline protocol
  and redaction tests.
- For managed child lifecycles, inspect `mcp_toolkit::process::supervisor` before
  inventing another subprocess manager. Services still own pipe bounds, safe
  command construction and provider output interpretation.

## Binary-local client configuration, without handwritten JSON

The generated stdio binary's `--print-client-config` uses its actual executable
path. Copying just the binary and running it from another directory still works;
`--doctor` deliberately remains a source-project check. The client snippet uses
an explicit public `read_only` default, never the shell's profile value.

For a fixed read-only archive service, do not invent
an unsupported profile variable. Reuse the same renderer with an empty explicit
environment slice:

```rust,no_run
use mcp_toolkit::client_config::{
    render_executable_client_config, ClientConfigFormat,
};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
print!("{}", render_executable_client_config(
    "archive", &std::env::current_exe()?,
    ClientConfigFormat::McpServersJson, &[],
)?);
# Ok(())
# }
```

`CodexToml` emits `[mcp_servers."name"]`; `McpServersJson` emits `mcpServers`.
Both escape paths/names, reject invalid or duplicate environment keys, reject
non-Unicode executable paths rather than changing them, and leave `args` empty.
Explicit environment values are not redacted: pass public defaults only, never
credentials. Use the existing project-oriented `render_client_config` when you
actually want to inspect a source tree or generate hosted HTTP configuration.

The shared tool-surface parser accepts OS arguments safely and never repeats
unknown values in errors. Services with additional CLI operations may keep
custom dispatch, but should use `args_os` and the same no-echo rule.

## Proof for the next generated service

`python3 scripts/check_generated_servers.py` creates renamed copies of all
three starters outside this repository. It verifies the emitted toolchain pin
without forcing `RUSTUP_TOOLCHAIN`, then formats renamed sources and checks formatting, tests, locked builds
and warning-free Clippy. The stdio tests copy the binary away from its source
and verify its client configuration. It does not authenticate or contact live
providers, and it does not substitute for hosted CI before publication.

# Container hardening for Rust MCP servers

This is an optional **consumer-owned deployment recipe**, not a toolkit
runtime API, generated image, new security profile, or mandatory release gate.
It applies to both stdio and hosted MCP processes when teams choose Docker.
Follow the relevant toolkit [transport and auth contracts](golden-path.md)
regardless of packaging.

## Minimal reusable principles

- Use a multi-stage build. Build Rust and any native dependencies in a builder;
  copy **only** the release executables and necessary runtime libraries/CA
  certificates into the final image. Confirm the dynamic library closure of
  each binary instead of assuming a static executable.
- Treat the Docker build context as a credential boundary. Prefer an explicit
  allowlist in `.dockerignore` for manifests, the lockfile, source and public
  generated inputs. Review any recursively included directories for nested
  credentials, secrets or build-time downloaded artifacts. Never copy `.git`,
  `.env`, Google ADC, cloud credential directories, or private worktrees.
- Use `cargo build --locked --release` against the service's committed
  `Cargo.lock`. For a release intended to be reproducible, pin base-image
  digests and retain the exact source/dependency/image identity. A mutable
  distro or Rust tag alone is not such proof.
- Run as a non-root numeric UID/GID; give it only the home/cache paths it
  actually needs. Keep bind-mounted credentials read-only and accessible to
  that UID, not world-readable. Pass credentials at **runtime** via a secret
  mount or approved secret delivery mechanism, never through `COPY`, a build
  argument, or Docker image layers.
- Keep stdio protocol output clean: diagnostics go to stderr, MCP JSON-RPC to
  stdout. An HTTP binary may share the image but must remain subject to
  its separate bind, origin, authentication and session contracts. A container
  does not supply MCP authorization.
- Prefer a read-only root filesystem, dropped capabilities,
  `no-new-privileges` and a bounded temporary filesystem in deployment
  where the service supports them. Declare any required writable state
  explicitly; DuckDB/scratchpad-heavy servers may need a carefully scoped
  writable data or temp mount.

## Acceptance: prove the image that will be used

In a focused GitHub-hosted job on the **exact proposed head**, exercise:

1. `docker build` using the actual Dockerfile and committed lockfile.
2. `docker run --entrypoint ...` to verify effective UID/GID is non-root,
   expected binaries exist, and startup does not require a privileged port.
3. A credential-free `--print-tools`, `--doctor` or equivalent if the
   consumer supports one. Assert that output parses and contains the expected
   served-surface entries. A CLI-only check is *not* a substitute for the
   toolkit's stdio/HTTP MCP protocol contract tests.
4. Where feasible, a second smoke with `--read-only --cap-drop=ALL`,
   `--security-opt=no-new-privileges` and a small `--tmpfs /tmp`.

Capture the hosted run URL, exact head SHA, actual smoke result and remaining
runtime assumptions in the consumer's PR. A Dockerfile review, an unexecuted
workflow, or `docker build` on a different revision is not build acceptance.
Avoid injecting real provider tokens into untrusted PR CI.

Do **not** extract Docker/build configuration into the toolkit as a new
framework merely because two servers use containers. Service dependencies,
native library closure, deployment network, secret mounts, writable volumes
and base images remain the service's responsibility.

## Example / provenance

The bounded GA4 consumer example is
[sednalabs/ga4-mcp PR #43](https://github.com/sednalabs/ga4-mcp/pull/43)
(Ops `w2089`). It demonstrates a multi-stage image, non-root runtime,
allowlisted context and focused smoke. **Its exact-head container job was not
yet observed at the time of this documentation candidate.** Treat the example
as a reviewable implementation, not a validated golden image, until its hosted
run and review are recorded. The separate GA4 Compose deployment profile
belongs to Ops `w2090`.

This recipe does not change the active toolkit release/migration train and
must not be merged as part of that train without the release owner's
coordination.

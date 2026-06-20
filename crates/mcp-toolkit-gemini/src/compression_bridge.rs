//! # Gemini Compression Bridge
//!
//! Executes resumed-session compression through Gemini CLI's internal core APIs
//! without routing through the non-interactive slash-command surface.
//!
//! ## Rationale
//! Current headless `/compress` handling in upstream Gemini CLI can fall
//! through to the model. This bridge preserves Gemini's own compression logic
//! while avoiding that broken surface.
//!
//! ## Security Boundaries
//! * Executes a repo-owned Node helper without invoking a shell.
//! * Resolves Gemini CLI module imports from the configured Gemini binary path.
//! * Returns structured bridge diagnostics only; callers decide how to surface
//!   them to tool consumers.
//!
//! ## References
//! * MCP servers that support resumed-session compression.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::config::GeminiExecutionConfig;
use crate::executor::{GeminiExecutionError, normalize_working_directory, resolve_gemini_binary};

/// Summary: structured result returned by the Node compression bridge.
///
/// # Errors
/// * Produced only after the helper returns parseable JSON.
///
/// # Security
/// * Contains bridge diagnostics only; no environment values are included.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct SessionCompressionBridgeResult {
    pub ok: bool,
    pub compression_status: Option<String>,
    pub original_token_count: Option<u64>,
    pub new_token_count: Option<u64>,
    pub session_id: Option<String>,
    pub conversation_file: Option<String>,
    pub error_category: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompressionBridgeModulePaths {
    config_module: PathBuf,
    session_utils_module: PathBuf,
    core_index_module: PathBuf,
}

/// Summary: execute the dedicated Node helper for resumed-session compression.
///
/// # Errors
/// * Returns [`GeminiExecutionError`] for bridge launch, timeout, module
///   resolution, JSON parsing, or helper exit failures.
///
/// # Security
/// * Uses resolved absolute module paths derived from the configured Gemini
///   binary, avoiding ambient global-package lookup.
///
/// # Panics
/// * Does not panic.
pub(crate) async fn execute_session_compression_bridge(
    config: &GeminiExecutionConfig,
    resume_selector: &str,
    working_directory: Option<&str>,
    prompt_id: &str,
    cancellation: CancellationToken,
) -> Result<SessionCompressionBridgeResult, GeminiExecutionError> {
    let script_path = config
        .resume_compression_bridge_script_path
        .as_deref()
        .ok_or_else(|| {
            GeminiExecutionError::SpawnFailed(
                "resume compression bridge script path is not configured".to_string(),
            )
        })?;
    let helper_script = PathBuf::from(script_path);
    if !helper_script.is_file() {
        return Err(GeminiExecutionError::SpawnFailed(format!(
            "resume compression bridge script was not found at {}",
            helper_script.display()
        )));
    }

    let helper_modules = resolve_bridge_modules(config)?;
    let node_bin = resolve_gemini_binary(&config.gemini_node_bin);
    let helper_cwd = normalized_helper_cwd(working_directory)?
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let mut command = Command::new(node_bin);
    command.arg(&helper_script);
    command.arg("--config-module");
    command.arg(&helper_modules.config_module);
    command.arg("--session-utils-module");
    command.arg(&helper_modules.session_utils_module);
    command.arg("--core-index-module");
    command.arg(&helper_modules.core_index_module);
    command.arg("--resume-selector");
    command.arg(resume_selector);
    command.arg("--prompt-id");
    command.arg(prompt_id);
    command.arg("--cwd");
    command.arg(&helper_cwd);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        GeminiExecutionError::SpawnFailed("compression bridge stdout was not captured".to_string())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        GeminiExecutionError::SpawnFailed("compression bridge stderr was not captured".to_string())
    })?;

    let stdout_task = tokio::spawn(async move {
        let mut reader = stdout;
        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .await
            .map(|_| String::from_utf8_lossy(&buffer).into_owned())
    });
    let stderr_task = tokio::spawn(async move {
        let mut reader = stderr;
        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .await
            .map(|_| String::from_utf8_lossy(&buffer).into_owned())
    });

    let status = wait_for_bridge_exit(&mut child, config.timeout, cancellation).await?;
    let stdout = stdout_task
        .await
        .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?
        .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;
    let stderr = stderr_task
        .await
        .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?
        .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;

    if !status.success() {
        return Err(GeminiExecutionError::FailedExit {
            code: status.code(),
            stderr: stderr.trim().to_string(),
        });
    }

    parse_bridge_result(&stdout, &stderr)
}

fn normalized_helper_cwd(
    working_directory: Option<&str>,
) -> Result<Option<PathBuf>, GeminiExecutionError> {
    let Some(working_directory) = working_directory else {
        return Ok(None);
    };
    Ok(Some(PathBuf::from(normalize_working_directory(
        working_directory,
    )?)))
}

async fn wait_for_bridge_exit(
    child: &mut Child,
    timeout_budget: std::time::Duration,
    cancellation: CancellationToken,
) -> Result<std::process::ExitStatus, GeminiExecutionError> {
    if timeout_budget.is_zero() {
        tokio::select! {
            _ = cancellation.cancelled() => {
                terminate_bridge_child(child).await;
                Err(GeminiExecutionError::SpawnFailed(
                    "compression bridge cancelled".to_string(),
                ))
            }
            status = child.wait() => {
                status.map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))
            }
        }
    } else {
        tokio::select! {
            _ = cancellation.cancelled() => {
                terminate_bridge_child(child).await;
                Err(GeminiExecutionError::SpawnFailed(
                    "compression bridge cancelled".to_string(),
                ))
            }
            status = timeout(timeout_budget, child.wait()) => match status {
                Ok(status) => status.map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string())),
                Err(_) => {
                    terminate_bridge_child(child).await;
                    Err(GeminiExecutionError::SpawnFailed(format!(
                        "compression bridge timed out after {}s",
                        timeout_budget.as_secs()
                    )))
                }
            }
        }
    }
}

async fn terminate_bridge_child(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn resolve_bridge_modules(
    config: &GeminiExecutionConfig,
) -> Result<CompressionBridgeModulePaths, GeminiExecutionError> {
    let gemini_bin = PathBuf::from(resolve_gemini_binary(&config.gemini_bin));
    let canonical = std::fs::canonicalize(&gemini_bin).map_err(|err| {
        GeminiExecutionError::SpawnFailed(format!(
            "failed to resolve configured gemini binary {}: {err}",
            gemini_bin.display()
        ))
    })?;
    let Some(paths) = derive_bridge_module_paths(&canonical) else {
        return Err(GeminiExecutionError::SpawnFailed(format!(
            "could not derive Gemini CLI module paths from {}",
            canonical.display()
        )));
    };
    let required_paths = [
        &paths.config_module,
        &paths.session_utils_module,
        &paths.core_index_module,
    ];
    for required in required_paths {
        if !required.is_file() {
            return Err(GeminiExecutionError::SpawnFailed(format!(
                "required Gemini CLI bridge module was not found at {}",
                required.display()
            )));
        }
    }
    Ok(paths)
}

fn derive_bridge_module_paths(canonical_gemini_bin: &Path) -> Option<CompressionBridgeModulePaths> {
    for ancestor in canonical_gemini_bin.ancestors() {
        let package_root = ancestor.to_path_buf();
        if package_root.file_name() != Some(OsStr::new("gemini-cli")) {
            continue;
        }
        let config_module = package_root.join("dist/src/config/config.js");
        let session_utils_module = package_root.join("dist/src/utils/sessionUtils.js");
        let core_index_module =
            package_root.join("node_modules/@google/gemini-cli-core/dist/src/index.js");
        return Some(CompressionBridgeModulePaths {
            config_module,
            session_utils_module,
            core_index_module,
        });
    }
    None
}

fn parse_bridge_result(
    stdout: &str,
    stderr: &str,
) -> Result<SessionCompressionBridgeResult, GeminiExecutionError> {
    let trimmed = stdout.trim();
    match serde_json::from_str::<SessionCompressionBridgeResult>(trimmed) {
        Ok(result) => Ok(result),
        Err(primary_error) => {
            if let Some(last_line) = trimmed.lines().rev().find_map(|line| {
                let line = line.trim();
                if line.is_empty() { None } else { Some(line) }
            }) {
                if last_line != trimmed {
                    if let Ok(result) =
                        serde_json::from_str::<SessionCompressionBridgeResult>(last_line)
                    {
                        return Ok(result);
                    }
                }
            }

            let stderr = stderr.trim();
            let mut message = format!("compression bridge returned invalid json: {primary_error}");
            if !trimmed.is_empty() {
                if let Some(last_line) = trimmed.lines().rev().find_map(|line| {
                    let line = line.trim();
                    if line.is_empty() { None } else { Some(line) }
                }) {
                    message.push_str(" | stdout(last non-empty line): ");
                    message.push_str(last_line);
                }
            }
            if !stderr.is_empty() {
                message.push_str(" | stderr: ");
                message.push_str(stderr);
            }
            Err(GeminiExecutionError::SpawnFailed(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionCompressionBridgeResult, derive_bridge_module_paths, parse_bridge_result};
    use std::path::Path;

    #[test]
    fn derive_bridge_module_paths_from_global_npm_install() {
        let paths = derive_bridge_module_paths(Path::new(
            "/home/test/.nvm/versions/node/v22.17.1/lib/node_modules/@google/gemini-cli/dist/index.js",
        ))
        .expect("expected module paths");
        assert_eq!(
            paths.config_module,
            Path::new(
                "/home/test/.nvm/versions/node/v22.17.1/lib/node_modules/@google/gemini-cli/dist/src/config/config.js"
            )
        );
        assert_eq!(
            paths.session_utils_module,
            Path::new(
                "/home/test/.nvm/versions/node/v22.17.1/lib/node_modules/@google/gemini-cli/dist/src/utils/sessionUtils.js"
            )
        );
        assert_eq!(
            paths.core_index_module,
            Path::new(
                "/home/test/.nvm/versions/node/v22.17.1/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/index.js"
            )
        );
    }

    #[test]
    fn parse_bridge_result_accepts_last_json_line_after_debug_output() {
        let stdout = concat!(
            "Ignore file not found: /tmp/.geminiignore, continue without it.\n",
            "Hook registry initialized with 0 hook entries\n",
            "{\"ok\":false,\"compression_status\":null,\"original_token_count\":null,",
            "\"new_token_count\":null,\"session_id\":null,\"conversation_file\":null,",
            "\"error_category\":\"auth_session_invalid\",",
            "\"error\":\"BaseLlmClient not initialized\"}\n"
        );

        let parsed = parse_bridge_result(stdout, "").expect("expected parsed bridge result");
        assert_eq!(
            parsed,
            SessionCompressionBridgeResult {
                ok: false,
                compression_status: None,
                original_token_count: None,
                new_token_count: None,
                session_id: None,
                conversation_file: None,
                error_category: Some("auth_session_invalid".to_string()),
                error: Some("BaseLlmClient not initialized".to_string()),
            }
        );
    }
}

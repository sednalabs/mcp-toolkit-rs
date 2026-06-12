//! # Gemini CLI Executor
//!
//! Async execution wrapper for `gemini` prompt execution with policy-aware flags.
//!
//! ## Rationale
//! Keep process execution behavior consistent across servers and avoid ad-hoc
//! shell wrappers.
//!
//! ## Security Boundaries
//! * Executes Gemini without shell interpolation.
//! * Applies MCP allowlist flags from config.
//! * Requires API-key authentication and clears inherited environment state before spawn.
//!
//! ## References
//! * `mcp-workspace/toolkits/mcp-toolkit-rs/crates/mcp-toolkit-gemini`

use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::time::Instant;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::config::GeminiExecutionConfig;

/// Output formatting mode for Gemini CLI stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GeminiOutputFormat {
    #[default]
    Text,
    Json,
    StreamJson,
}

impl GeminiOutputFormat {
    fn as_cli_value(self) -> Option<&'static str> {
        match self {
            Self::Text => None,
            Self::Json => Some("json"),
            Self::StreamJson => Some("stream-json"),
        }
    }
}

/// Control how the prompt is delivered to Gemini CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GeminiPromptTransport {
    /// Pass the prompt as a command-line positional argument (short prompts only).
    #[default]
    ArgPrompt,
    /// Pipe the prompt through stdin (preferred for large prompts).
    Stdin,
}

/// Options for a single Gemini request.
#[derive(Debug, Clone, Default)]
pub struct GeminiRequest {
    pub prompt: String,
    pub model: Option<String>,
    pub sandbox: bool,
    pub output_format: GeminiOutputFormat,
    pub prompt_transport: GeminiPromptTransport,
    pub include_directories: Vec<String>,
}

/// Successful Gemini CLI process result.
#[derive(Debug, Clone)]
pub struct GeminiResponse {
    pub stdout: String,
    pub stderr: String,
}

/// Error variants for Gemini process execution.
#[derive(Debug)]
pub enum GeminiExecutionError {
    MissingApiKey,
    SpawnFailed(String),
    Cancelled,
    TimedOut { seconds: u64 },
    FailedExit { code: Option<i32>, stderr: String },
    InvalidIncludeDirectory { path: String, reason: String },
}

impl fmt::Display for GeminiExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingApiKey => write!(
                f,
                "GEMINI_API_KEY is required; account-based Gemini CLI auth is not supported"
            ),
            Self::SpawnFailed(message) => write!(f, "failed to spawn gemini: {message}"),
            Self::Cancelled => write!(f, "gemini command cancelled"),
            Self::TimedOut { seconds } => {
                write!(f, "gemini command timed out after {seconds}s")
            }
            Self::FailedExit { code, stderr } => {
                write!(f, "gemini exited with code {code:?}: {stderr}")
            }
            Self::InvalidIncludeDirectory { path, reason } => {
                write!(f, "invalid Gemini include-directory '{path}': {reason}")
            }
        }
    }
}

impl std::error::Error for GeminiExecutionError {}

/// Summary: execute a Gemini CLI request under toolkit policy.
///
/// # Errors
/// * Returns [`GeminiExecutionError::SpawnFailed`] when process launch fails.
/// * Returns [`GeminiExecutionError::TimedOut`] on timeout.
/// * Returns [`GeminiExecutionError::FailedExit`] on non-zero exit status.
///
/// # Security
/// * Runs command directly without a shell.
/// * Applies MCP allowlist policy from config on every invocation.
///
/// # Panics
/// * Does not panic.
pub async fn execute_gemini(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
) -> Result<GeminiResponse, GeminiExecutionError> {
    execute_gemini_with_cancel(config, request, CancellationToken::new()).await
}

fn is_no_input_stdin_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("no input provided via stdin")
}

fn is_retryable_429_error(error: &GeminiExecutionError) -> bool {
    let GeminiExecutionError::FailedExit { stderr, .. } = error else {
        return false;
    };
    let lower = stderr.to_lowercase();
    [
        " 429",
        "status 429",
        "\"code\": 429",
        "too many requests",
        "rate limit",
        "resource_exhausted",
        "model_capacity_exhausted",
        "retryablequotaerror",
        "quota",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

async fn execute_with_prompt_fallback(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
    cancellation_token: CancellationToken,
) -> Result<GeminiResponse, GeminiExecutionError> {
    match execute_gemini_once(config, request, cancellation_token.clone()).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let needs_fallback = request.prompt_transport == GeminiPromptTransport::ArgPrompt
                && matches!(
                    &error,
                    GeminiExecutionError::FailedExit { stderr, .. }
                        if is_no_input_stdin_error(stderr)
                );

            if !needs_fallback {
                return Err(error);
            }

            let mut stdin_request = request.clone();
            stdin_request.prompt_transport = GeminiPromptTransport::Stdin;
            execute_gemini_once(config, &stdin_request, cancellation_token).await
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeminiCommandSpec {
    bin: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    stdin_payload: Option<String>,
}

fn build_gemini_command_spec(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
) -> Result<GeminiCommandSpec, GeminiExecutionError> {
    let mut args = Vec::new();
    let mut env = Vec::new();
    let api_key = config.api_key.trim();
    if api_key.is_empty() {
        return Err(GeminiExecutionError::MissingApiKey);
    }

    env.push(("GEMINI_API_KEY".to_string(), api_key.to_string()));
    if let Some(path) = std::env::var_os("PATH") {
        env.push(("PATH".to_string(), path.to_string_lossy().to_string()));
    }

    for arg in config.allowed_mcp_servers.as_cli_args() {
        args.push(arg);
    }

    let mut include_directories = config.include_directories.clone();
    include_directories.extend(request.include_directories.iter().cloned());
    for dir in normalize_include_directories(&include_directories)? {
        args.push("--include-directories".to_string());
        args.push(dir);
    }

    if let Some(format) = request.output_format.as_cli_value() {
        args.push("--output-format".to_string());
        args.push(format.to_string());
    }

    if let Some(model) = request.model.as_ref().or(config.default_model.as_ref()) {
        args.push("-m".to_string());
        args.push(model.clone());
    }

    if request.sandbox {
        args.push("-s".to_string());
    }

    let stdin_payload = match request.prompt_transport {
        GeminiPromptTransport::ArgPrompt => {
            // Prefer positional prompts over --prompt (-p), which is deprecated upstream.
            // Use `--` to ensure prompts starting with '-' are treated as positional input.
            args.push("--".to_string());
            args.push(request.prompt.clone());
            None
        }
        GeminiPromptTransport::Stdin => {
            // No prompt args; Gemini CLI will read from stdin in non-interactive mode.
            Some(request.prompt.clone())
        }
    };

    Ok(GeminiCommandSpec {
        bin: resolve_gemini_binary(&config.gemini_bin),
        args,
        env,
        stdin_payload,
    })
}

async fn execute_gemini_once(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
    cancellation_token: CancellationToken,
) -> Result<GeminiResponse, GeminiExecutionError> {
    let spec = build_gemini_command_spec(config, request)?;
    let mut command = Command::new(&spec.bin);
    command.env_clear();
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    if spec.stdin_payload.is_some() {
        command.stdin(std::process::Stdio::piped());
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    for arg in &spec.args {
        command.arg(arg);
    }

    let mut child = command
        .spawn()
        .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;

    if let Some(payload) = spec.stdin_payload {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(GeminiExecutionError::SpawnFailed(
                "gemini stdin was not captured".to_string(),
            ));
        };
        tokio::spawn(async move {
            let _ = stdin.write_all(payload.as_bytes()).await;
            let _ = stdin.shutdown().await;
        });
    }

    let mut stdout = child.stdout.take().ok_or_else(|| {
        GeminiExecutionError::SpawnFailed("gemini stdout was not captured".to_string())
    })?;
    let mut stderr = child.stderr.take().ok_or_else(|| {
        GeminiExecutionError::SpawnFailed("gemini stderr was not captured".to_string())
    })?;

    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf).await;
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });

    enum WaitOutcome {
        Completed(std::process::ExitStatus),
        Cancelled,
        TimedOut,
    }

    let outcome = tokio::select! {
        status = child.wait() => status
            .map(WaitOutcome::Completed)
            .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?,
        _ = cancellation_token.cancelled() => WaitOutcome::Cancelled,
        _ = tokio::time::sleep(config.timeout), if !config.timeout.is_zero() => WaitOutcome::TimedOut,
    };

    match outcome {
        WaitOutcome::Cancelled => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            Err(GeminiExecutionError::Cancelled)
        }
        WaitOutcome::TimedOut => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            Err(GeminiExecutionError::TimedOut {
                seconds: config.timeout.as_secs(),
            })
        }
        WaitOutcome::Completed(status) => {
            let stdout = stdout_task
                .await
                .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;
            let stderr = stderr_task
                .await
                .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;
            let stdout = String::from_utf8_lossy(&stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&stderr).trim().to_string();

            if !status.success() {
                Err(GeminiExecutionError::FailedExit {
                    code: status.code(),
                    stderr,
                })
            } else {
                Ok(GeminiResponse { stdout, stderr })
            }
        }
    }
}

fn normalize_include_directories(
    include_directories: &[String],
) -> Result<Vec<String>, GeminiExecutionError> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for raw_dir in include_directories {
        let dir = raw_dir.trim();
        if dir.is_empty() {
            continue;
        }

        let dir = Path::new(dir);
        let metadata = std::fs::metadata(dir).map_err(|error| {
            GeminiExecutionError::InvalidIncludeDirectory {
                path: dir.to_string_lossy().to_string(),
                reason: format!("metadata lookup failed: {error}"),
            }
        })?;
        if !metadata.is_dir() {
            return Err(GeminiExecutionError::InvalidIncludeDirectory {
                path: dir.to_string_lossy().to_string(),
                reason: "path exists but is not a directory".to_string(),
            });
        }

        let readable = std::fs::read_dir(dir).is_ok();
        if !readable {
            return Err(GeminiExecutionError::InvalidIncludeDirectory {
                path: dir.to_string_lossy().to_string(),
                reason: "directory is not readable".to_string(),
            });
        }

        let canonical = std::fs::canonicalize(dir).map_err(|error| {
            GeminiExecutionError::InvalidIncludeDirectory {
                path: dir.to_string_lossy().to_string(),
                reason: format!("canonicalization failed: {error}"),
            }
        })?;
        let canonical = canonical.to_string_lossy().to_string();
        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }

    Ok(normalized)
}

fn resolve_gemini_binary(raw: &str) -> String {
    let path = Path::new(raw);
    if path.is_absolute() || path.components().count() > 1 {
        return raw.to_string();
    }

    if let Some(resolved) = resolve_from_path(raw) {
        return resolved;
    }

    raw.to_string()
}

fn resolve_from_path(binary: &str) -> Option<String> {
    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(binary);
            if is_executable(&candidate) {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let metadata = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return false,
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        (mode & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Summary: execute a Gemini CLI request under toolkit policy with cancellation support.
///
/// # Errors
/// * Returns [`GeminiExecutionError::SpawnFailed`] when process launch fails.
/// * Returns [`GeminiExecutionError::Cancelled`] when the cancellation token fires.
/// * Returns [`GeminiExecutionError::TimedOut`] when `config.timeout` elapses (unless it is zero).
/// * Returns [`GeminiExecutionError::FailedExit`] on non-zero exit status.
///
/// # Security
/// * Runs command directly without a shell.
/// * Applies MCP allowlist policy from config on every invocation.
///
/// # Panics
/// * Does not panic.
pub async fn execute_gemini_with_cancel(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
    cancellation_token: CancellationToken,
) -> Result<GeminiResponse, GeminiExecutionError> {
    let started_at = Instant::now();
    let mut retries_attempted = 0u64;
    let retry_interval = if config.retry_429_interval.is_zero() {
        std::time::Duration::from_secs(1)
    } else {
        config.retry_429_interval
    };

    loop {
        match execute_with_prompt_fallback(config, request, cancellation_token.clone()).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                let within_retry_budget = config.retry_429_window.is_zero()
                    || started_at.elapsed() < config.retry_429_window;
                let retry_enabled = config.retry_429_enabled;
                let retries_remaining = retries_attempted < config.retry_429_max_retries
                    && config.retry_429_max_retries > 0;
                if !retry_enabled
                    || !within_retry_budget
                    || !retries_remaining
                    || !is_retryable_429_error(&error)
                {
                    return Err(error);
                }

                retries_attempted += 1;
                let next_delay = if config.retry_429_window.is_zero() {
                    retry_interval
                } else {
                    let remaining = config.retry_429_window.saturating_sub(started_at.elapsed());
                    if remaining.is_zero() {
                        return Err(error);
                    }
                    if retry_interval > remaining {
                        remaining
                    } else {
                        retry_interval
                    }
                };
                tokio::select! {
                    _ = cancellation_token.cancelled() => return Err(GeminiExecutionError::Cancelled),
                    _ = tokio::time::sleep(next_delay) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_gemini_command_spec, GeminiOutputFormat, GeminiPromptTransport, GeminiRequest,
    };
    use crate::config::{AllowedMcpServers, GeminiExecutionConfig};
    use std::path::PathBuf;

    fn make_temp_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp-toolkit-gemini-command-spec-{}-{}",
            std::process::id(),
            suffix
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn command_spec_matrix_ask_gemini_arg_prompt() {
        let include_dir = make_temp_dir("ask");
        let config = GeminiExecutionConfig {
            api_key: "test-api-key".to_string(),
            default_model: None,
            allowed_mcp_servers: AllowedMcpServers::Names(vec!["ops".to_string()]),
            include_directories: vec![include_dir.display().to_string()],
            ..GeminiExecutionConfig::default()
        };
        let request = GeminiRequest {
            prompt: "summarize this".to_string(),
            model: Some("gemini-3-pro".to_string()),
            sandbox: false,
            output_format: GeminiOutputFormat::Text,
            prompt_transport: GeminiPromptTransport::ArgPrompt,
            ..GeminiRequest::default()
        };

        let spec = build_gemini_command_spec(&config, &request).expect("build command spec");
        assert!(spec
            .args
            .windows(2)
            .any(|window| window[0] == "--allowed-mcp-server-names" && window[1] == "ops"));
        assert!(spec
            .args
            .windows(2)
            .any(|window| window[0] == "-m" && window[1] == "gemini-3-pro"));
        assert!(spec.args.iter().any(|arg| arg == "--"));
        assert!(spec.args.iter().any(|arg| arg == "summarize this"));
        assert!(spec
            .env
            .iter()
            .any(|(key, value)| key == "GEMINI_API_KEY" && value == "test-api-key"));
        assert!(spec.env.iter().any(|(key, _)| key == "PATH"));
        assert!(!spec.env.iter().any(|(key, _)| key == "HOME"));
        assert!(!spec.env.iter().any(|(key, _)| key == "GEMINI_SANDBOX"));
        assert!(spec.stdin_payload.is_none());
        let _ = std::fs::remove_dir_all(include_dir);
    }

    #[test]
    fn command_spec_matrix_codebase_scout_stdin_json() {
        let include_dir = make_temp_dir("scout");
        let request_dir = make_temp_dir("scout-request");
        let config = GeminiExecutionConfig {
            api_key: "test-api-key".to_string(),
            allowed_mcp_servers: AllowedMcpServers::None,
            include_directories: vec![include_dir.display().to_string()],
            ..GeminiExecutionConfig::default()
        };
        let request = GeminiRequest {
            prompt: "{\"status\":\"ok\"}".to_string(),
            model: None,
            sandbox: false,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![request_dir.display().to_string()],
        };

        let spec = build_gemini_command_spec(&config, &request).expect("build command spec");
        assert!(spec
            .args
            .windows(2)
            .any(|window| window[0] == "--allowed-mcp-server-names" && window[1] == "__none__"));
        assert!(spec
            .args
            .windows(2)
            .any(|window| window[0] == "--output-format" && window[1] == "json"));
        assert!(
            spec.args
                .iter()
                .filter(|arg| arg.as_str() == "--include-directories")
                .count()
                >= 2
        );
        assert_eq!(spec.stdin_payload.as_deref(), Some("{\"status\":\"ok\"}"));
        assert!(!spec.args.iter().any(|arg| arg == "--"));
        let _ = std::fs::remove_dir_all(include_dir);
        let _ = std::fs::remove_dir_all(request_dir);
    }

    #[test]
    fn command_spec_matrix_codebase_investigator_uses_default_model_with_sandbox() {
        let config = GeminiExecutionConfig {
            api_key: "test-api-key".to_string(),
            default_model: Some("gemini-3-flash-preview".to_string()),
            allowed_mcp_servers: AllowedMcpServers::All,
            ..GeminiExecutionConfig::default()
        };
        let request = GeminiRequest {
            prompt: "investigate".to_string(),
            model: None,
            sandbox: true,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            ..GeminiRequest::default()
        };

        let spec = build_gemini_command_spec(&config, &request).expect("build command spec");
        assert!(spec
            .args
            .windows(2)
            .any(|window| { window[0] == "-m" && window[1] == "gemini-3-flash-preview" }));
        assert!(spec.args.iter().any(|arg| arg == "-s"));
        assert!(!spec.env.iter().any(|(key, _)| key == "GEMINI_SANDBOX"));
        assert_eq!(spec.stdin_payload.as_deref(), Some("investigate"));
        assert!(!spec
            .args
            .iter()
            .any(|arg| arg == "--allowed-mcp-server-names"));
    }

    #[test]
    fn command_spec_requires_api_key() {
        let config = GeminiExecutionConfig::default();
        let request = GeminiRequest {
            prompt: "hello".to_string(),
            ..GeminiRequest::default()
        };

        let err = build_gemini_command_spec(&config, &request)
            .expect_err("missing API key should fail before command construction");
        assert!(matches!(err, super::GeminiExecutionError::MissingApiKey));
    }
}

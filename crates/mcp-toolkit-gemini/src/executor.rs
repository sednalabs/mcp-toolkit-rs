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
//!
//! ## References
//! * Gemini CLI-backed MCP service implementations.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::config::{AllowedMcpServers, GeminiExecutionConfig};
use crate::observe::GeminiOutputStream;

/// Summary: output formatting mode for Gemini CLI stdout.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * `Json` and `StreamJson` help callers parse output without scraping tool logs.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiOutputFormat {
    Text,
    Json,
    StreamJson,
}

impl Default for GeminiOutputFormat {
    fn default() -> Self {
        Self::Text
    }
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

/// Summary: control how the prompt is delivered to Gemini CLI.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * `Stdin` avoids OS argv length limits for large prompts.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiPromptTransport {
    /// Pass the prompt as a command-line positional argument (short prompts only).
    ArgPrompt,
    /// Pipe the prompt through stdin (preferred for large prompts).
    Stdin,
}

impl Default for GeminiPromptTransport {
    fn default() -> Self {
        Self::ArgPrompt
    }
}

/// Summary: tool-time options for one Gemini call.
///
/// # Errors
/// * Validation is handled by callers and executor.
///
/// # Security
/// * Keeps tool-level overrides explicit.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Default)]
pub struct GeminiRequest {
    pub prompt: String,
    pub model: Option<String>,
    pub resume: Option<String>,
    pub sandbox: bool,
    pub allowed_mcp_servers: Option<AllowedMcpServers>,
    pub output_format: GeminiOutputFormat,
    pub prompt_transport: GeminiPromptTransport,
    pub include_directories: Vec<String>,
    pub working_directory: Option<String>,
}

/// Summary: successful Gemini CLI process result.
///
/// # Errors
/// * Produced only when execution succeeds.
///
/// # Security
/// * Contains model output; caller is responsible for downstream redaction.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone)]
pub struct GeminiResponse {
    pub stdout: String,
    pub stderr: String,
    pub retry_count: u32,
}

pub const GEMINI_SESSION_PROBE_SOURCE_JSON: &str = "noninteractive_json_probe";

/// Summary: terminal result for the bounded Gemini session probe.
///
/// # Errors
/// * Produced only when the probe succeeds.
///
/// # Security
/// * Contains model output only from the bounded JSON probe path.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone)]
pub struct GeminiSessionProbeResult {
    pub response: GeminiResponse,
    pub gemini_invocations: u32,
    pub model: Option<String>,
}

/// Summary: terminal error for the bounded Gemini session probe.
///
/// # Errors
/// * Wraps the underlying Gemini CLI failure plus probe invocation count.
///
/// # Security
/// * Preserves only execution metadata needed for auditability.
///
/// # Panics
/// * Does not panic.
#[derive(Debug)]
pub struct GeminiSessionProbeError {
    pub error: GeminiExecutionError,
    pub gemini_invocations: u32,
}

/// Summary: observable execution phases for Gemini subprocess lifecycle.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Contains process-state metadata only (no payload content).
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiExecutionPhase {
    ToolCallStarted,
    Spawned,
    WaitingForOutput,
    ToolCallFinished,
    Completed,
}

/// Summary: heartbeat snapshot emitted while a Gemini subprocess is running.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Exposes counters and timing only.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeminiHeartbeatSnapshot {
    pub attempt: u32,
    pub pid: Option<u32>,
    pub elapsed_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub last_output_age_ms: Option<u64>,
    pub stalled: bool,
}

/// Summary: error variants for Gemini process execution.
///
/// # Errors
/// * Returned by [`execute_gemini`] when process start/run/exit fails.
///
/// # Security
/// * Messages avoid embedding secrets by construction.
///
/// # Panics
/// * Does not panic.
#[derive(Debug)]
pub enum GeminiExecutionError {
    SpawnFailed(String),
    Cancelled,
    TimedOut { seconds: u64 },
    FailedExit { code: Option<i32>, stderr: String },
    UnsupportedCommand { command: String, details: String },
    InvalidIncludeDirectory { path: String, reason: String },
    InvalidWorkingDirectory { path: String, reason: String },
}

/// Summary: callback contract for streaming Gemini stdout/stderr chunks.
///
/// # Errors
/// * Implementers should handle internal errors without returning.
///
/// # Security
/// * Chunk text may contain sensitive prompt/response data.
///
/// # Panics
/// * Implementations should avoid panics.
pub trait GeminiOutputObserver: Send + Sync {
    fn on_chunk(&self, stream: GeminiOutputStream, chunk_text: &str);

    fn on_retry_scheduled(&self, _next_attempt: u32, _reason: &str, _delay: Duration) {}

    fn on_phase(&self, _attempt: u32, _phase: GeminiExecutionPhase, _pid: Option<u32>) {}

    fn on_heartbeat(&self, _snapshot: GeminiHeartbeatSnapshot) {}
}

impl fmt::Display for GeminiExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpawnFailed(message) => write!(f, "failed to spawn gemini: {message}"),
            Self::Cancelled => write!(f, "gemini command cancelled"),
            Self::TimedOut { seconds } => {
                write!(f, "gemini command timed out after {seconds}s")
            }
            Self::FailedExit { code, stderr } => {
                write!(f, "gemini exited with code {code:?}: {stderr}")
            }
            Self::UnsupportedCommand { command, details } => {
                write!(f, "gemini command '{command}' is unavailable: {details}")
            }
            Self::InvalidIncludeDirectory { path, reason } => {
                write!(f, "invalid Gemini include-directory '{path}': {reason}")
            }
            Self::InvalidWorkingDirectory { path, reason } => {
                write!(f, "invalid Gemini working-directory '{path}': {reason}")
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

const RETRY_REASON_429: &str = "transient_rate_limit_429";
const RETRY_REASON_429_MODEL_CAPACITY: &str = "transient_model_capacity_429";
const RETRY_REASON_SANDBOX_FALLBACK: &str = "sandbox_runtime_unavailable_fallback_to_host";

fn is_missing_sandbox_runtime_error(error: &GeminiExecutionError) -> bool {
    let GeminiExecutionError::FailedExit { stderr, .. } = error else {
        return false;
    };
    let lower = stderr.to_lowercase();
    let mentions_sandbox_runtime = [
        "gemini-cli/sandbox",
        "gemini sandbox",
        "sandbox:0.",
        "sandbox image",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if !mentions_sandbox_runtime {
        return false;
    }
    [
        "not found",
        "no such image",
        "manifest unknown",
        "failed to resolve reference",
        "name unknown",
        "pull access denied",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_terminal_quota_exhaustion_message(lower: &str) -> bool {
    [
        "terminalquotaerror",
        "you have exhausted your capacity on this model",
        "quota will reset after",
        "your quota will reset after",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn retryable_429_reason(error: &GeminiExecutionError) -> Option<&'static str> {
    let GeminiExecutionError::FailedExit { stderr, .. } = error else {
        return None;
    };
    let lower = stderr.to_lowercase();
    let has_429_signal = [
        " 429",
        "status 429",
        "\"code\": 429",
        "too many requests",
        "rate limit",
        "resource_exhausted",
        "model_capacity_exhausted",
        "no capacity available for model",
        "retryablequotaerror",
    ]
    .iter()
    .any(|needle| lower.contains(needle));

    if !has_429_signal || is_terminal_quota_exhaustion_message(&lower) {
        return None;
    }

    if [
        "model_capacity_exhausted",
        "no capacity available for model",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        Some(RETRY_REASON_429_MODEL_CAPACITY)
    } else {
        Some(RETRY_REASON_429)
    }
}

static RETRY_DELAY_JITTER_STATE: AtomicU64 = AtomicU64::new(0);

fn next_retry_jitter_u64() -> u64 {
    let mut current = RETRY_DELAY_JITTER_STATE.load(Ordering::Relaxed);
    if current == 0 {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                duration
                    .as_nanos()
                    .wrapping_add(u128::from(std::process::id()))
                    .min(u128::from(u64::MAX)) as u64
            })
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        let normalized_seed = if seed == 0 { 1 } else { seed };
        RETRY_DELAY_JITTER_STATE.store(normalized_seed, Ordering::Relaxed);
        current = normalized_seed;
    }

    loop {
        let mut next = current;
        // xorshift64*: low-overhead non-cryptographic jitter source.
        next ^= next << 13;
        next ^= next >> 7;
        next ^= next << 17;
        if next == 0 {
            next = 1;
        }

        match RETRY_DELAY_JITTER_STATE.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

fn fixed_retry_delay(interval: Duration) -> Duration {
    if interval.is_zero() {
        Duration::from_secs(1)
    } else {
        interval
    }
}

fn sample_random_retry_delay(min: Duration, max: Duration) -> Duration {
    if max <= min {
        return min;
    }

    let min_ms = min.as_millis().min(u128::from(u64::MAX)) as u64;
    let max_ms = max.as_millis().min(u128::from(u64::MAX)) as u64;
    if max_ms <= min_ms {
        return Duration::from_millis(min_ms);
    }

    let span = max_ms.saturating_sub(min_ms);
    let jitter = next_retry_jitter_u64() % span.saturating_add(1);
    Duration::from_millis(min_ms.saturating_add(jitter))
}

fn configured_retry_delay(config: &GeminiExecutionConfig) -> Duration {
    match config.retry_429_random_interval_range {
        Some((min, max)) => sample_random_retry_delay(min, max),
        None => fixed_retry_delay(config.retry_429_interval),
    }
}

const MIN_RETRY_WINDOW_REMAINING: Duration = Duration::from_millis(500);

const NO_OUTPUT_MARKER: u64 = u64::MAX;

#[derive(Debug)]
struct StreamTelemetry {
    stdout_bytes: AtomicU64,
    stderr_bytes: AtomicU64,
    last_output_elapsed_ms: AtomicU64,
}

impl Default for StreamTelemetry {
    fn default() -> Self {
        Self {
            stdout_bytes: AtomicU64::new(0),
            stderr_bytes: AtomicU64::new(0),
            last_output_elapsed_ms: AtomicU64::new(NO_OUTPUT_MARKER),
        }
    }
}

async fn stop_heartbeat_task(
    stop_tx: Option<watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<()>>,
) {
    if let Some(stop_tx) = stop_tx {
        let _ = stop_tx.send(true);
    }
    if let Some(task) = task {
        let _ = task.await;
    }
}

fn build_heartbeat_snapshot(
    attempt: u32,
    pid: Option<u32>,
    process_started_at: Instant,
    telemetry: &StreamTelemetry,
    stall_threshold_ms: u64,
) -> GeminiHeartbeatSnapshot {
    let elapsed_ms = process_started_at
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    let stdout_bytes = telemetry.stdout_bytes.load(Ordering::Relaxed);
    let stderr_bytes = telemetry.stderr_bytes.load(Ordering::Relaxed);
    let raw_last_output = telemetry.last_output_elapsed_ms.load(Ordering::Relaxed);
    let last_output_age_ms = if raw_last_output == NO_OUTPUT_MARKER {
        Some(elapsed_ms)
    } else {
        Some(elapsed_ms.saturating_sub(raw_last_output))
    };
    let stalled = if stall_threshold_ms == 0 {
        false
    } else {
        last_output_age_ms
            .map(|age| age >= stall_threshold_ms)
            .unwrap_or(false)
    };

    GeminiHeartbeatSnapshot {
        attempt,
        pid,
        elapsed_ms,
        stdout_bytes,
        stderr_bytes,
        last_output_age_ms,
        stalled,
    }
}

fn emit_final_heartbeat(
    output_observer: Option<&Arc<dyn GeminiOutputObserver>>,
    inspect_heartbeat_enabled: bool,
    attempt: u32,
    pid: Option<u32>,
    process_started_at: Instant,
    telemetry: &StreamTelemetry,
    stall_threshold_ms: u64,
) {
    if !inspect_heartbeat_enabled {
        return;
    }
    if let Some(observer) = output_observer {
        observer.on_heartbeat(build_heartbeat_snapshot(
            attempt,
            pid,
            process_started_at,
            telemetry,
            stall_threshold_ms,
        ));
    }
}

async fn execute_with_prompt_fallback(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
    cancellation_token: CancellationToken,
    output_observer: Option<Arc<dyn GeminiOutputObserver>>,
    attempt: u32,
) -> Result<GeminiResponse, GeminiExecutionError> {
    let primary_result = match execute_gemini_once(
        config,
        request,
        cancellation_token.clone(),
        output_observer.clone(),
        attempt,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(error) => {
            let needs_fallback = request.prompt_transport == GeminiPromptTransport::ArgPrompt
                && matches!(
                    &error,
                    GeminiExecutionError::FailedExit { stderr, .. }
                        if is_no_input_stdin_error(stderr)
                );

            if !needs_fallback {
                Err(error)
            } else {
                let mut stdin_request = request.clone();
                stdin_request.prompt_transport = GeminiPromptTransport::Stdin;
                execute_gemini_once(
                    config,
                    &stdin_request,
                    cancellation_token.clone(),
                    output_observer.clone(),
                    attempt,
                )
                .await
            }
        }
    };

    if primary_result.is_ok() || !request.sandbox || !config.sandbox_fallback_enabled {
        return primary_result;
    }

    let primary_error = match primary_result {
        Ok(response) => return Ok(response),
        Err(error) => error,
    };
    if !is_missing_sandbox_runtime_error(&primary_error) {
        return Err(primary_error);
    }

    if let Some(observer) = output_observer.as_ref() {
        observer.on_retry_scheduled(
            attempt.saturating_add(1),
            RETRY_REASON_SANDBOX_FALLBACK,
            Duration::ZERO,
        );
    }

    let mut host_request = request.clone();
    host_request.sandbox = false;
    match execute_gemini_once(
        config,
        &host_request,
        cancellation_token.clone(),
        output_observer.clone(),
        attempt,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(error) => {
            let needs_stdin_fallback = host_request.prompt_transport
                == GeminiPromptTransport::ArgPrompt
                && matches!(
                    &error,
                    GeminiExecutionError::FailedExit { stderr, .. }
                        if is_no_input_stdin_error(stderr)
                );
            if !needs_stdin_fallback {
                return Err(error);
            }
            let mut stdin_request = host_request;
            stdin_request.prompt_transport = GeminiPromptTransport::Stdin;
            execute_gemini_once(
                config,
                &stdin_request,
                cancellation_token,
                output_observer,
                attempt,
            )
            .await
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeminiCommandSpec {
    bin: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    stdin_payload: Option<String>,
    working_directory: Option<String>,
}

fn build_gemini_command_spec(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
) -> Result<GeminiCommandSpec, GeminiExecutionError> {
    let mut args = Vec::new();
    let mut env = Vec::new();

    let effective_allowed_mcp_servers = request
        .allowed_mcp_servers
        .as_ref()
        .unwrap_or(&config.allowed_mcp_servers);
    for arg in effective_allowed_mcp_servers.as_cli_args() {
        args.push(arg);
    }

    let include_directories = effective_include_directories(config, request);
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

    if let Some(resume_selector) = request.resume.as_ref() {
        args.push("--resume".to_string());
        args.push(resume_selector.clone());
    }

    if request.sandbox {
        args.push("-s".to_string());
    } else {
        // Prevent host-level defaults (e.g. GEMINI_SANDBOX=true in service env)
        // from forcing sandbox mode when the tool request did not ask for it.
        env.push(("GEMINI_SANDBOX".to_string(), "false".to_string()));
    }

    if let Some(home_dir) = config.home_dir.as_deref() {
        env.push(("HOME".to_string(), home_dir.to_string()));
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
            // Gemini CLI 0.32.x only stays headless when `-p/--prompt` is present.
            // Use an empty prompt sentinel so large requests can still flow over stdin.
            args.push("-p".to_string());
            args.push(String::new());
            Some(request.prompt.clone())
        }
    };

    let working_directory = match request.working_directory.as_deref() {
        Some(raw_dir) => Some(normalize_working_directory(raw_dir)?),
        None => None,
    };

    Ok(GeminiCommandSpec {
        bin: resolve_gemini_binary(&config.gemini_bin),
        args,
        env,
        stdin_payload,
        working_directory,
    })
}

fn effective_include_directories(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
) -> Vec<String> {
    if request.working_directory.is_some() && !request.include_directories.is_empty() {
        return request.include_directories.clone();
    }

    let mut include_directories = config.include_directories.clone();
    include_directories.extend(request.include_directories.iter().cloned());
    include_directories
}

async fn execute_gemini_once(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
    cancellation_token: CancellationToken,
    output_observer: Option<Arc<dyn GeminiOutputObserver>>,
    attempt: u32,
) -> Result<GeminiResponse, GeminiExecutionError> {
    let spec = build_gemini_command_spec(config, request)?;
    let mut command = Command::new(&spec.bin);
    if let Some(working_directory) = spec.working_directory.as_deref() {
        command.current_dir(working_directory);
    }
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
    let child_pid = child.id();
    if let Some(observer) = output_observer.as_ref() {
        observer.on_phase(attempt, GeminiExecutionPhase::Spawned, child_pid);
    }

    let process_started_at = Instant::now();
    let telemetry = Arc::new(StreamTelemetry::default());
    let stall_threshold_ms = config
        .inspect_stall_threshold
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    let mut heartbeat_stop_tx: Option<watch::Sender<bool>> = None;
    let mut heartbeat_task = None;
    if config.inspect_heartbeat_enabled {
        if let Some(observer) = output_observer.as_ref() {
            let observer = observer.clone();
            let telemetry = telemetry.clone();
            let (stop_tx, mut stop_rx) = watch::channel(false);
            let heartbeat_interval = if config.inspect_heartbeat_interval.is_zero() {
                Duration::from_secs(1)
            } else {
                config.inspect_heartbeat_interval
            };
            let stall_threshold_ms = stall_threshold_ms;
            heartbeat_task = Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(heartbeat_interval) => {
                            observer.on_heartbeat(build_heartbeat_snapshot(
                                attempt,
                                child_pid,
                                process_started_at,
                                &telemetry,
                                stall_threshold_ms,
                            ));
                        }
                        changed = stop_rx.changed() => {
                            if changed.is_err() || *stop_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }));
            heartbeat_stop_tx = Some(stop_tx);
        }
    }

    if let Some(payload) = spec.stdin_payload {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            stop_heartbeat_task(heartbeat_stop_tx, heartbeat_task).await;
            return Err(GeminiExecutionError::SpawnFailed(
                "gemini stdin was not captured".to_string(),
            ));
        };
        tokio::spawn(async move {
            let _ = stdin.write_all(payload.as_bytes()).await;
            let _ = stdin.shutdown().await;
        });
    }

    let stdout = child.stdout.take().ok_or_else(|| {
        GeminiExecutionError::SpawnFailed("gemini stdout was not captured".to_string())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        GeminiExecutionError::SpawnFailed("gemini stderr was not captured".to_string())
    })?;
    if let Some(observer) = output_observer.as_ref() {
        observer.on_phase(attempt, GeminiExecutionPhase::WaitingForOutput, child_pid);
    }

    let stdout_observer = output_observer.clone();
    let stdout_telemetry = telemetry.clone();
    let stdout_task = tokio::spawn(async move {
        read_stream_with_observer(
            stdout,
            GeminiOutputStream::Stdout,
            stdout_observer,
            Some(stdout_telemetry),
            process_started_at,
        )
        .await
    });
    let stderr_observer = output_observer.clone();
    let stderr_telemetry = telemetry.clone();
    let stderr_task = tokio::spawn(async move {
        read_stream_with_observer(
            stderr,
            GeminiOutputStream::Stderr,
            stderr_observer,
            Some(stderr_telemetry),
            process_started_at,
        )
        .await
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
            stop_heartbeat_task(heartbeat_stop_tx, heartbeat_task).await;
            emit_final_heartbeat(
                output_observer.as_ref(),
                config.inspect_heartbeat_enabled,
                attempt,
                child_pid,
                process_started_at,
                &telemetry,
                stall_threshold_ms,
            );
            Err(GeminiExecutionError::Cancelled)
        }
        WaitOutcome::TimedOut => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            stop_heartbeat_task(heartbeat_stop_tx, heartbeat_task).await;
            emit_final_heartbeat(
                output_observer.as_ref(),
                config.inspect_heartbeat_enabled,
                attempt,
                child_pid,
                process_started_at,
                &telemetry,
                stall_threshold_ms,
            );
            Err(GeminiExecutionError::TimedOut {
                seconds: config.timeout.as_secs(),
            })
        }
        WaitOutcome::Completed(status) => {
            stop_heartbeat_task(heartbeat_stop_tx, heartbeat_task).await;
            let stdout = stdout_task
                .await
                .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;
            let stderr = stderr_task
                .await
                .map_err(|err| GeminiExecutionError::SpawnFailed(err.to_string()))?;
            emit_final_heartbeat(
                output_observer.as_ref(),
                config.inspect_heartbeat_enabled,
                attempt,
                child_pid,
                process_started_at,
                &telemetry,
                stall_threshold_ms,
            );
            let stdout = String::from_utf8_lossy(&stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&stderr).trim().to_string();

            if !status.success() {
                Err(GeminiExecutionError::FailedExit {
                    code: status.code(),
                    stderr,
                })
            } else {
                Ok(GeminiResponse {
                    stdout,
                    stderr,
                    retry_count: 0,
                })
            }
        }
    }
}

async fn read_stream_with_observer<R>(
    mut reader: R,
    stream: GeminiOutputStream,
    observer: Option<Arc<dyn GeminiOutputObserver>>,
    telemetry: Option<Arc<StreamTelemetry>>,
    process_started_at: Instant,
) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut buffer = vec![0u8; 2048];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(read) => read,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        output.extend_from_slice(chunk);
        if let Some(telemetry) = telemetry.as_ref() {
            let chunk_len = read.min(usize::MAX) as u64;
            match stream {
                GeminiOutputStream::Stdout => {
                    telemetry
                        .stdout_bytes
                        .fetch_add(chunk_len, Ordering::Relaxed);
                }
                GeminiOutputStream::Stderr => {
                    telemetry
                        .stderr_bytes
                        .fetch_add(chunk_len, Ordering::Relaxed);
                }
            }
            let elapsed_ms = process_started_at
                .elapsed()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            telemetry
                .last_output_elapsed_ms
                .store(elapsed_ms, Ordering::Relaxed);
        }
        if let Some(observer) = observer.as_ref() {
            let text = String::from_utf8_lossy(chunk);
            observer.on_chunk(stream, &text);
        }
    }
    output
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

pub(crate) fn normalize_working_directory(raw_dir: &str) -> Result<String, GeminiExecutionError> {
    let dir = raw_dir.trim();
    if dir.is_empty() {
        return Err(GeminiExecutionError::InvalidWorkingDirectory {
            path: raw_dir.to_string(),
            reason: "path was empty".to_string(),
        });
    }

    let dir = Path::new(dir);
    let metadata =
        std::fs::metadata(dir).map_err(|error| GeminiExecutionError::InvalidWorkingDirectory {
            path: dir.to_string_lossy().to_string(),
            reason: format!("metadata lookup failed: {error}"),
        })?;
    if !metadata.is_dir() {
        return Err(GeminiExecutionError::InvalidWorkingDirectory {
            path: dir.to_string_lossy().to_string(),
            reason: "path exists but is not a directory".to_string(),
        });
    }

    let readable = std::fs::read_dir(dir).is_ok();
    if !readable {
        return Err(GeminiExecutionError::InvalidWorkingDirectory {
            path: dir.to_string_lossy().to_string(),
            reason: "directory is not readable".to_string(),
        });
    }

    let canonical = std::fs::canonicalize(dir).map_err(|error| {
        GeminiExecutionError::InvalidWorkingDirectory {
            path: dir.to_string_lossy().to_string(),
            reason: format!("canonicalization failed: {error}"),
        }
    })?;
    Ok(canonical.to_string_lossy().to_string())
}

pub(crate) fn resolve_gemini_binary(raw: &str) -> String {
    let path = Path::new(raw);
    if path.is_absolute() || path.components().count() > 1 {
        return raw.to_string();
    }

    if let Some(resolved) = resolve_from_path(raw) {
        return resolved;
    }
    if let Some(resolved) = resolve_from_user_home(raw) {
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

fn resolve_from_user_home(binary: &str) -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let home = PathBuf::from(home);

    let local_candidate = home.join(".local").join("bin").join(binary);
    if is_executable(&local_candidate) {
        return Some(local_candidate.to_string_lossy().into_owned());
    }

    let nvm_dir = std::env::var("NVM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".nvm").join("versions").join("node"));
    if let Some(resolved) = resolve_nvm_version(binary, &nvm_dir) {
        return Some(resolved);
    }

    let current_dir = nvm_dir.join("current").join("bin").join(binary);
    if is_executable(&current_dir) {
        return Some(current_dir.to_string_lossy().into_owned());
    }

    None
}

fn resolve_nvm_version(binary: &str, nvm_dir: &Path) -> Option<String> {
    let base = if nvm_dir.ends_with("node") {
        nvm_dir.to_path_buf()
    } else if nvm_dir
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .map_or(false, |file_name| file_name.starts_with('v'))
    {
        nvm_dir.parent().unwrap_or(nvm_dir).to_path_buf()
    } else {
        nvm_dir.join("node")
    };
    let mut versions = Vec::new();
    let mut current = std::fs::read_dir(&base).ok()?;
    while let Some(Ok(entry)) = current.next() {
        let file_name = entry.file_name();
        let version = file_name.to_string_lossy();
        if version.starts_with('v') {
            versions.push(file_name);
        }
    }
    versions.sort();
    versions.reverse();

    for version in versions {
        let candidate = base.join(version).join("bin").join(binary);
        if is_executable(&candidate) {
            return Some(candidate.to_string_lossy().into_owned());
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
    execute_gemini_with_cancel_observed(config, request, cancellation_token, None).await
}

/// Summary: execute a Gemini CLI request with optional stream observer support.
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
pub async fn execute_gemini_with_cancel_observed(
    config: &GeminiExecutionConfig,
    request: &GeminiRequest,
    cancellation_token: CancellationToken,
    output_observer: Option<Arc<dyn GeminiOutputObserver>>,
) -> Result<GeminiResponse, GeminiExecutionError> {
    let started_at = Instant::now();
    let mut retries_attempted = 0u64;

    loop {
        let attempt = retries_attempted.saturating_add(1).min(u64::from(u32::MAX)) as u32;
        match execute_with_prompt_fallback(
            config,
            request,
            cancellation_token.clone(),
            output_observer.clone(),
            attempt,
        )
        .await
        {
            Ok(mut response) => {
                response.retry_count = retries_attempted.min(u64::from(u32::MAX)) as u32;
                return Ok(response);
            }
            Err(error) => {
                let retry_reason = retryable_429_reason(&error);
                let within_retry_budget = config.retry_429_window.is_zero()
                    || started_at.elapsed() < config.retry_429_window;
                let retry_enabled = config.retry_429_enabled;
                let retries_remaining = retries_attempted < config.retry_429_max_retries
                    && config.retry_429_max_retries > 0;
                if !retry_enabled
                    || !within_retry_budget
                    || !retries_remaining
                    || retry_reason.is_none()
                {
                    return Err(error);
                }
                let Some(retry_reason) = retry_reason else {
                    return Err(error);
                };

                retries_attempted += 1;
                let retry_delay = configured_retry_delay(config);
                let next_delay = if config.retry_429_window.is_zero() {
                    retry_delay
                } else {
                    let remaining = config.retry_429_window.saturating_sub(started_at.elapsed());
                    if remaining <= MIN_RETRY_WINDOW_REMAINING {
                        return Err(error);
                    }
                    retry_delay.min(remaining)
                };
                if let Some(observer) = output_observer.as_ref() {
                    observer.on_retry_scheduled(
                        (retries_attempted + 1).min(u64::from(u32::MAX)) as u32,
                        retry_reason,
                        next_delay,
                    );
                }
                tokio::select! {
                    _ = cancellation_token.cancelled() => return Err(GeminiExecutionError::Cancelled),
                    _ = tokio::time::sleep(next_delay) => {}
                }
            }
        }
    }
}

const SESSION_STATS_PROBE_PROMPT: &str = "Return exactly OK.";
const SESSION_STATS_PREFERRED_MODELS: &[&str] = &[
    "gemini-2.5-flash-lite",
    "gemini-3-flash-preview",
    "gemini-2.5-flash",
];

pub(crate) fn select_session_probe_model(config: &GeminiExecutionConfig) -> Option<String> {
    if !config.model_allowlist.is_empty() {
        for candidate in SESSION_STATS_PREFERRED_MODELS {
            if let Some(model) = config
                .model_allowlist
                .iter()
                .find(|model| model.eq_ignore_ascii_case(candidate))
            {
                return Some(model.clone());
            }
        }

        if let Some(default_model) = config.default_model.as_ref() {
            if let Some(model) = config
                .model_allowlist
                .iter()
                .find(|model| model.eq_ignore_ascii_case(default_model))
            {
                return Some(model.clone());
            }
        }

        return config.model_allowlist.first().cloned();
    }

    config.default_model.clone()
}

fn gemini_session_probe_request(
    output_format: GeminiOutputFormat,
    model: Option<String>,
) -> GeminiRequest {
    GeminiRequest {
        prompt: SESSION_STATS_PROBE_PROMPT.to_string(),
        model,
        allowed_mcp_servers: Some(AllowedMcpServers::None),
        output_format,
        prompt_transport: GeminiPromptTransport::Stdin,
        ..GeminiRequest::default()
    }
}

/// Summary: run a lightweight non-interactive Gemini probe for session telemetry.
///
/// # Errors
/// * Returns [`GeminiExecutionError::SpawnFailed`] when process launch fails.
/// * Returns [`GeminiExecutionError::Cancelled`] when the cancellation token fires.
/// * Returns [`GeminiExecutionError::TimedOut`] when `config.stats_timeout` elapses (unless it is zero).
/// * Returns [`GeminiExecutionError::FailedExit`] on non-zero exit status.
///
/// # Security
/// * Runs command directly without shell interpolation.
/// * Uses JSON output, stdin prompt transport, and disables downstream MCP fan-out.
///
/// # Panics
/// * Does not panic.
fn gemini_session_probe_config(
    config: &GeminiExecutionConfig,
    timeout: Duration,
) -> GeminiExecutionConfig {
    let mut probe_config = config.clone();
    probe_config.timeout = timeout;
    probe_config.include_directories.clear();
    probe_config.retry_429_enabled = false;
    probe_config.retry_429_max_retries = 0;
    probe_config.retry_429_window = Duration::ZERO;
    probe_config.retry_429_random_interval_range = None;
    probe_config
}

fn gemini_invocations_from_response(response: &GeminiResponse) -> u32 {
    response.retry_count.saturating_add(1)
}

pub async fn execute_gemini_stats_session(
    config: &GeminiExecutionConfig,
    cancellation_token: CancellationToken,
) -> Result<GeminiSessionProbeResult, GeminiSessionProbeError> {
    let probe_model = select_session_probe_model(config);
    let json_config = gemini_session_probe_config(config, config.stats_timeout);
    let json_request = gemini_session_probe_request(GeminiOutputFormat::Json, probe_model.clone());

    execute_gemini_with_cancel_observed(&json_config, &json_request, cancellation_token, None)
        .await
        .map(|response| GeminiSessionProbeResult {
            gemini_invocations: gemini_invocations_from_response(&response),
            model: probe_model,
            response,
        })
        .map_err(|error| GeminiSessionProbeError {
            error,
            gemini_invocations: 1,
        })
}

#[cfg(test)]
mod tests {
    use super::{
        GEMINI_SESSION_PROBE_SOURCE_JSON, GeminiExecutionError, GeminiOutputFormat,
        GeminiPromptTransport, GeminiRequest, SESSION_STATS_PROBE_PROMPT,
        build_gemini_command_spec, gemini_session_probe_config, gemini_session_probe_request,
        is_missing_sandbox_runtime_error, retryable_429_reason, select_session_probe_model,
    };
    use crate::config::{AllowedMcpServers, GeminiExecutionConfig};
    use std::path::PathBuf;
    use std::time::Duration;

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
        let include_canonical = std::fs::canonicalize(&include_dir)
            .expect("canonical include dir")
            .to_string_lossy()
            .to_string();
        let config = GeminiExecutionConfig {
            default_model: None,
            allowed_mcp_servers: AllowedMcpServers::Names(vec!["ops".to_string()]),
            include_directories: vec![include_dir.display().to_string()],
            ..GeminiExecutionConfig::default()
        };
        let request = GeminiRequest {
            prompt: "summarize this".to_string(),
            model: Some("gemini-3-pro".to_string()),
            resume: Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            sandbox: false,
            output_format: GeminiOutputFormat::Text,
            prompt_transport: GeminiPromptTransport::ArgPrompt,
            ..GeminiRequest::default()
        };

        let spec = build_gemini_command_spec(&config, &request).expect("build command spec");
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "--allowed-mcp-server-names" && window[1] == "ops")
        );
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "-m" && window[1] == "gemini-3-pro")
        );
        assert!(spec.args.windows(2).any(|window| {
            window[0] == "--resume" && window[1] == "81acb59f-3c1f-4d14-91a4-98c8359e4e1b"
        }));
        assert!(spec.args.iter().any(|arg| arg == "--"));
        assert!(spec.args.iter().any(|arg| arg == "summarize this"));
        let include_pairs: Vec<(&String, &String)> = spec
            .args
            .windows(2)
            .filter_map(|window| {
                (window[0] == "--include-directories").then_some((&window[0], &window[1]))
            })
            .collect();
        assert_eq!(include_pairs.len(), 1);
        assert_eq!(include_pairs[0].1.as_str(), include_canonical);
        assert!(
            spec.env
                .iter()
                .any(|(key, value)| key == "GEMINI_SANDBOX" && value == "false")
        );
        assert!(spec.stdin_payload.is_none());
        assert!(spec.working_directory.is_none());
        let _ = std::fs::remove_dir_all(include_dir);
    }

    #[test]
    fn command_spec_matrix_codebase_scout_stdin_json() {
        let include_dir = make_temp_dir("scout");
        let include_canonical = std::fs::canonicalize(&include_dir)
            .expect("canonical config include dir")
            .to_string_lossy()
            .to_string();
        let request_dir = make_temp_dir("scout-request");
        let request_canonical = std::fs::canonicalize(&request_dir)
            .expect("canonical request include dir")
            .to_string_lossy()
            .to_string();
        let config = GeminiExecutionConfig {
            allowed_mcp_servers: AllowedMcpServers::None,
            include_directories: vec![include_dir.display().to_string()],
            ..GeminiExecutionConfig::default()
        };
        let request = GeminiRequest {
            prompt: "{\"status\":\"ok\"}".to_string(),
            model: None,
            resume: None,
            sandbox: false,
            allowed_mcp_servers: None,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![request_dir.display().to_string()],
            working_directory: Some(request_dir.display().to_string()),
        };

        let spec = build_gemini_command_spec(&config, &request).expect("build command spec");
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "--allowed-mcp-server-names" && window[1] == "__none__")
        );
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "--output-format" && window[1] == "json")
        );
        let include_paths: Vec<&str> = spec
            .args
            .windows(2)
            .filter_map(|window| {
                (window[0] == "--include-directories").then_some(window[1].as_str())
            })
            .collect();
        assert_eq!(include_paths.len(), 1);
        assert_eq!(include_paths[0], request_canonical);
        assert!(!include_paths.contains(&include_canonical.as_str()));
        assert_eq!(
            spec.working_directory.as_deref(),
            Some(request_dir.to_string_lossy().as_ref())
        );
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "-p" && window[1].is_empty())
        );
        assert_eq!(spec.stdin_payload.as_deref(), Some("{\"status\":\"ok\"}"));
        assert!(!spec.args.iter().any(|arg| arg == "--"));
        let _ = std::fs::remove_dir_all(include_dir);
        let _ = std::fs::remove_dir_all(request_dir);
    }

    #[test]
    fn command_spec_matrix_codebase_investigator_uses_default_model_with_sandbox() {
        let config = GeminiExecutionConfig {
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
        assert!(
            spec.args
                .windows(2)
                .any(|window| { window[0] == "-m" && window[1] == "gemini-3-flash-preview" })
        );
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "-p" && window[1].is_empty())
        );
        assert!(spec.args.iter().any(|arg| arg == "-s"));
        assert!(!spec.env.iter().any(|(key, _)| key == "GEMINI_SANDBOX"));
        assert_eq!(spec.stdin_payload.as_deref(), Some("investigate"));
        assert!(spec.working_directory.is_none());
        assert!(
            !spec
                .args
                .iter()
                .any(|arg| arg == "--allowed-mcp-server-names")
        );
    }

    #[test]
    fn request_allowlist_override_replaces_config_allowlist() {
        let config = GeminiExecutionConfig {
            allowed_mcp_servers: AllowedMcpServers::None,
            ..GeminiExecutionConfig::default()
        };
        let request = GeminiRequest {
            prompt: "probe".to_string(),
            model: None,
            sandbox: false,
            allowed_mcp_servers: Some(AllowedMcpServers::Names(vec![
                "postgres".to_string(),
                "ops".to_string(),
            ])),
            output_format: GeminiOutputFormat::Text,
            prompt_transport: GeminiPromptTransport::ArgPrompt,
            ..GeminiRequest::default()
        };

        let spec = build_gemini_command_spec(&config, &request).expect("build command spec");
        assert!(spec.args.windows(2).any(|window| {
            window[0] == "--allowed-mcp-server-names" && window[1] == "postgres"
        }));
        assert!(
            spec.args
                .windows(2)
                .any(|window| { window[0] == "--allowed-mcp-server-names" && window[1] == "ops" })
        );
        assert!(!spec.args.iter().any(|arg| arg == "__none__"));
    }

    #[test]
    fn request_allowlist_override_can_disable_mcp_when_config_allows() {
        let config = GeminiExecutionConfig {
            allowed_mcp_servers: AllowedMcpServers::All,
            ..GeminiExecutionConfig::default()
        };
        let request = GeminiRequest {
            prompt: "probe".to_string(),
            model: None,
            sandbox: false,
            allowed_mcp_servers: Some(AllowedMcpServers::None),
            output_format: GeminiOutputFormat::Text,
            prompt_transport: GeminiPromptTransport::ArgPrompt,
            ..GeminiRequest::default()
        };

        let spec = build_gemini_command_spec(&config, &request).expect("build command spec");
        assert!(spec.args.windows(2).any(|window| {
            window[0] == "--allowed-mcp-server-names" && window[1] == "__none__"
        }));
    }

    #[test]
    fn retry_reason_rejects_terminal_quota_exhaustion() {
        let error = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: "TerminalQuotaError: You have exhausted your capacity on this model. Your quota will reset after 8h45m15s.".to_string(),
        };
        assert_eq!(retryable_429_reason(&error), None);
    }

    #[test]
    fn retry_reason_allows_model_capacity_exhaustion() {
        let error = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"reason":"MODEL_CAPACITY_EXHAUSTED"}],"message":"No capacity available for model gemini-3-flash-preview on the server"}}"#.to_string(),
        };
        assert_eq!(
            retryable_429_reason(&error),
            Some("transient_model_capacity_429")
        );
    }

    #[test]
    fn sandbox_runtime_detector_matches_missing_image_failure() {
        let error = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: "failed to start sandbox runtime: us-docker.pkg.dev/gemini-code-dev/gemini-cli/sandbox:0.31.0 not found".to_string(),
        };
        assert!(is_missing_sandbox_runtime_error(&error));
    }

    #[test]
    fn sandbox_runtime_detector_ignores_non_sandbox_errors() {
        let error = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: "request failed: model not found".to_string(),
        };
        assert!(!is_missing_sandbox_runtime_error(&error));
    }

    #[test]
    fn retry_reason_allows_generic_transient_429() {
        let error = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: "Attempt failed with status 429 (rate limit exceeded).".to_string(),
        };
        assert_eq!(
            retryable_429_reason(&error),
            Some("transient_rate_limit_429")
        );
    }

    #[test]
    fn session_probe_source_label_is_stable() {
        assert_eq!(
            GEMINI_SESSION_PROBE_SOURCE_JSON,
            "noninteractive_json_probe"
        );
    }

    #[test]
    fn session_probe_model_prefers_allowlisted_flash_lite_over_default_pro() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-pro-preview".to_string()),
            model_allowlist: vec![
                "gemini-3-pro-preview".to_string(),
                "gemini-2.5-flash-lite".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };

        assert_eq!(
            select_session_probe_model(&config).as_deref(),
            Some("gemini-2.5-flash-lite")
        );
    }

    #[test]
    fn session_probe_request_uses_json_stdin_and_disables_nested_mcp() {
        let include_dir = make_temp_dir("session-probe");
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-pro".to_string()),
            allowed_mcp_servers: AllowedMcpServers::All,
            include_directories: vec![include_dir.display().to_string()],
            ..GeminiExecutionConfig::default()
        };

        let probe_config = gemini_session_probe_config(&config, Duration::from_secs(120));
        let spec = build_gemini_command_spec(
            &probe_config,
            &gemini_session_probe_request(GeminiOutputFormat::Json, None),
        )
        .expect("build command spec");

        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "--allowed-mcp-server-names" && window[1] == "__none__")
        );
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "--output-format" && window[1] == "json")
        );
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "-m" && window[1] == "gemini-3-pro")
        );
        assert!(
            spec.args
                .windows(2)
                .any(|window| window[0] == "-p" && window[1].is_empty())
        );
        let include_paths: Vec<&str> = spec
            .args
            .windows(2)
            .filter_map(|window| {
                (window[0] == "--include-directories").then_some(window[1].as_str())
            })
            .collect();
        assert!(include_paths.is_empty());
        assert_eq!(
            spec.stdin_payload.as_deref(),
            Some(SESSION_STATS_PROBE_PROMPT)
        );
        assert!(spec.working_directory.is_none());
        assert!(!spec.args.iter().any(|arg| arg == "--"));

        let _ = std::fs::remove_dir_all(include_dir);
    }
}

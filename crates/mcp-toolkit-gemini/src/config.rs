//! # Gemini Toolkit Configuration
//!
//! Shared configuration primitives for Gemini CLI-backed MCP tools.
//!
//! ## Rationale
//! Keep Gemini execution policy explicit and reusable across MCP servers
//! without duplicating flag parsing or defaults.
//!
//! ## Security Boundaries
//! * Default policy denies downstream Gemini MCP servers (`__none__`).
//! * Callers must still control API keys via environment variables.
//!
//! ## References
//! * MCP servers that share Gemini CLI execution policy.

use std::time::Duration;

/// Summary: default allowlisted models when no explicit env override is provided.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Keeps model selection constrained by default.
///
/// # Panics
/// * Does not panic.
pub const DEFAULT_GEMINI_MODEL_ALLOWLIST: &str =
    "gemini-3-flash-preview,gemini-3-pro-preview,gemini-2.5-flash-lite";

/// Summary: select which downstream Gemini MCP servers are allowed.
///
/// # Errors
/// * Parsing errors are surfaced by [`AllowedMcpServers::parse_csv`].
///
/// # Security
/// * `None` prevents accidental tool fan-out into unrelated MCP servers.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AllowedMcpServers {
    #[default]
    None,
    All,
    Names(Vec<String>),
}

impl AllowedMcpServers {
    /// Summary: parse CSV/keyword policy for `--allowed-mcp-server-names`.
    ///
    /// Accepted values:
    /// * empty / `__none__` / `none` => [`AllowedMcpServers::None`]
    /// * `__all__` / `all` => [`AllowedMcpServers::All`]
    /// * `ops,spark_mcp` => [`AllowedMcpServers::Names`]
    ///
    /// # Errors
    /// * Returns `Err` when names are present but all tokens are blank.
    ///
    /// # Security
    /// * Trims whitespace and drops empty tokens to avoid accidental broad policy.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn parse_csv(raw: &str) -> Result<Self, String> {
        let value = raw.trim();
        if value.is_empty()
            || value.eq_ignore_ascii_case("__none__")
            || value.eq_ignore_ascii_case("none")
        {
            return Ok(Self::None);
        }
        if value.eq_ignore_ascii_case("__all__") || value.eq_ignore_ascii_case("all") {
            return Ok(Self::All);
        }
        let names = value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if names.is_empty() {
            return Err("allowed MCP server list was empty after trimming".to_string());
        }
        Ok(Self::Names(names))
    }

    /// Summary: return CLI args for Gemini's MCP allowlist flags.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * `None` emits explicit `__none__` to keep policy deterministic.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn as_cli_args(&self) -> Vec<String> {
        match self {
            Self::None => vec![
                "--allowed-mcp-server-names".to_string(),
                "__none__".to_string(),
            ],
            Self::All => Vec::new(),
            Self::Names(names) => names
                .iter()
                .flat_map(|name| ["--allowed-mcp-server-names".to_string(), name.clone()])
                .collect(),
        }
    }
}

/// Summary: controls whether `ask-gemini` accepts freeform prompts.
///
/// # Errors
/// * Parsing errors are surfaced by server config loaders.
///
/// # Security
/// * `ScopedOnly` rejects prompt-only usage and requires a validated target path.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AskGeminiPolicy {
    #[default]
    Freeform,
    ScopedOnly,
}

/// Summary: controls default pre-run compression for resumed Gemini calls.
///
/// # Errors
/// * Parsing errors are surfaced by server config loaders.
///
/// # Security
/// * Keeps resumed-session growth policy explicit and centrally enforced.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResumeCompressionDefault {
    #[default]
    Auto,
    Off,
}

/// Summary: env-near runtime policy fields prior to normalization.
///
/// # Errors
/// * Validation and normalization occur when converting into
///   [`GeminiExecutionConfig`].
///
/// # Security
/// * Stores execution policy only; does not contain credential material.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiExecutionRawConfig {
    pub gemini_bin: String,
    pub gemini_node_bin: String,
    pub gemini_default_model: Option<String>,
    pub gemini_model_allowlist: Vec<String>,
    pub gemini_home_dir: Option<String>,
    pub gemini_allowed_server_names: String,
    pub gemini_include_directories: Vec<String>,
    pub gemini_retry_429_enabled: bool,
    pub gemini_retry_429_window_seconds: u64,
    pub gemini_retry_429_max_retries: u64,
    pub gemini_retry_429_interval_seconds: u64,
    pub gemini_retry_429_random_interval_enabled: bool,
    pub gemini_retry_429_random_interval_min_millis: u64,
    pub gemini_retry_429_random_interval_max_millis: u64,
    pub gemini_inspect_heartbeat_enabled: bool,
    pub gemini_inspect_heartbeat_interval_millis: u64,
    pub gemini_inspect_stall_threshold_millis: u64,
    pub gemini_ask_gemini_mode: String,
    pub gemini_ask_gemini_allowed_roots: Vec<String>,
    pub gemini_enable_resume: bool,
    pub gemini_resume_compression_default: String,
    pub gemini_resume_context_warn_percent: u64,
    pub gemini_usage_ledger_path: Option<String>,
    pub gemini_response_debug_path: Option<String>,
    pub gemini_session_probe_snapshot_path: Option<String>,
    pub gemini_resume_compression_bridge_script_path: Option<String>,
    pub gemini_sandbox_fallback_enabled: bool,
    pub gemini_timeout_seconds: u64,
    pub gemini_stats_timeout_seconds: u64,
    pub gemini_session_probe_stale_window_seconds: u64,
    pub gemini_async_max_tracked_invocations: usize,
    pub gemini_async_retention_seconds: u64,
}

impl Default for GeminiExecutionRawConfig {
    fn default() -> Self {
        Self {
            gemini_bin: "gemini".to_string(),
            gemini_node_bin: "node".to_string(),
            gemini_default_model: None,
            gemini_model_allowlist: DEFAULT_GEMINI_MODEL_ALLOWLIST
                .split(',')
                .map(str::to_string)
                .collect(),
            gemini_home_dir: None,
            gemini_allowed_server_names: "__none__".to_string(),
            gemini_include_directories: Vec::new(),
            gemini_retry_429_enabled: false,
            gemini_retry_429_window_seconds: 900,
            gemini_retry_429_max_retries: 2,
            gemini_retry_429_interval_seconds: 10,
            gemini_retry_429_random_interval_enabled: false,
            gemini_retry_429_random_interval_min_millis: 1_000,
            gemini_retry_429_random_interval_max_millis: 120_000,
            gemini_inspect_heartbeat_enabled: false,
            gemini_inspect_heartbeat_interval_millis: 15_000,
            gemini_inspect_stall_threshold_millis: 60_000,
            gemini_ask_gemini_mode: "freeform".to_string(),
            gemini_ask_gemini_allowed_roots: Vec::new(),
            gemini_enable_resume: true,
            gemini_resume_compression_default: "auto".to_string(),
            gemini_resume_context_warn_percent: 70,
            gemini_usage_ledger_path: None,
            gemini_response_debug_path: None,
            gemini_session_probe_snapshot_path: None,
            gemini_resume_compression_bridge_script_path: None,
            gemini_sandbox_fallback_enabled: true,
            gemini_timeout_seconds: 3600,
            gemini_stats_timeout_seconds: 120,
            gemini_session_probe_stale_window_seconds: 900,
            gemini_async_max_tracked_invocations: 128,
            gemini_async_retention_seconds: 21_600,
        }
    }
}

impl GeminiExecutionRawConfig {
    /// Summary: load raw execution policy fields from process environment.
    ///
    /// # Errors
    /// * Returns `Err` for invalid boolean or integer environment values.
    ///
    /// # Security
    /// * Reads only explicit Gemini MCP policy keys.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn from_process_env() -> Result<Self, String> {
        Self::from_env_lookup(|key| std::env::var(key).ok())
    }

    /// Summary: load raw execution policy fields from a map-like environment.
    ///
    /// # Errors
    /// * Returns `Err` for invalid boolean or integer values.
    ///
    /// # Security
    /// * Allows deterministic, test-friendly parsing without touching global env.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn from_env_map(env: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        Self::from_env_lookup(|key| env.get(key).cloned())
    }

    fn from_env_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        Ok(Self {
            gemini_bin: env_setting(&lookup, "GEMINI_CLI_BIN", "gemini"),
            gemini_node_bin: env_setting(&lookup, "GEMINI_NODE_BIN", "node"),
            gemini_default_model: env_optional_string(&lookup, "GEMINI_MCP_DEFAULT_MODEL"),
            gemini_model_allowlist: env_csv(
                &lookup,
                "GEMINI_MCP_ALLOWED_MODELS",
                DEFAULT_GEMINI_MODEL_ALLOWLIST,
            ),
            gemini_home_dir: env_optional_string(&lookup, "GEMINI_MCP_HOME_DIR"),
            gemini_allowed_server_names: env_setting(
                &lookup,
                "GEMINI_MCP_ALLOWED_SERVER_NAMES",
                "__none__",
            ),
            gemini_include_directories: env_csv(&lookup, "GEMINI_MCP_INCLUDE_DIRECTORIES", ""),
            gemini_retry_429_enabled: env_flag(&lookup, "GEMINI_MCP_RETRY_429_ENABLED", false)?,
            gemini_retry_429_window_seconds: env_u64(
                &lookup,
                "GEMINI_MCP_RETRY_429_WINDOW_SECONDS",
                900,
            )?,
            gemini_retry_429_max_retries: env_u64(&lookup, "GEMINI_MCP_RETRY_429_MAX_RETRIES", 2)?,
            gemini_retry_429_interval_seconds: env_u64(
                &lookup,
                "GEMINI_MCP_RETRY_429_INTERVAL_SECONDS",
                10,
            )?,
            gemini_retry_429_random_interval_enabled: env_flag(
                &lookup,
                "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_ENABLED",
                false,
            )?,
            gemini_retry_429_random_interval_min_millis: env_duration_seconds_as_millis(
                &lookup,
                "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MIN_SECONDS",
                1.0,
            )?,
            gemini_retry_429_random_interval_max_millis: env_duration_seconds_as_millis(
                &lookup,
                "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MAX_SECONDS",
                120.0,
            )?,
            gemini_inspect_heartbeat_enabled: env_flag(
                &lookup,
                "GEMINI_MCP_INSPECT_HEARTBEAT_ENABLED",
                false,
            )?,
            gemini_inspect_heartbeat_interval_millis: env_duration_seconds_as_millis(
                &lookup,
                "GEMINI_MCP_INSPECT_HEARTBEAT_INTERVAL_SECONDS",
                15.0,
            )?,
            gemini_inspect_stall_threshold_millis: env_duration_seconds_as_millis(
                &lookup,
                "GEMINI_MCP_INSPECT_STALL_SECONDS",
                60.0,
            )?,
            gemini_ask_gemini_mode: env_setting(&lookup, "GEMINI_MCP_ASK_GEMINI_MODE", "freeform"),
            gemini_ask_gemini_allowed_roots: env_csv(
                &lookup,
                "GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS",
                "",
            ),
            gemini_enable_resume: env_flag(&lookup, "GEMINI_MCP_ENABLE_RESUME", true)?,
            gemini_resume_compression_default: env_setting(
                &lookup,
                "GEMINI_MCP_RESUME_COMPRESSION_DEFAULT",
                "auto",
            ),
            gemini_resume_context_warn_percent: env_u64(
                &lookup,
                "GEMINI_MCP_RESUME_CONTEXT_WARN_PERCENT",
                70,
            )?,
            gemini_usage_ledger_path: env_optional_string(&lookup, "GEMINI_MCP_USAGE_LEDGER_PATH"),
            gemini_response_debug_path: env_optional_string(
                &lookup,
                "GEMINI_MCP_RESPONSE_DEBUG_PATH",
            ),
            gemini_session_probe_snapshot_path: env_optional_string(
                &lookup,
                "GEMINI_MCP_SESSION_PROBE_SNAPSHOT_PATH",
            ),
            gemini_resume_compression_bridge_script_path: env_optional_string(
                &lookup,
                "GEMINI_MCP_RESUME_COMPRESSION_BRIDGE_SCRIPT_PATH",
            ),
            gemini_sandbox_fallback_enabled: env_flag(
                &lookup,
                "GEMINI_MCP_SANDBOX_FALLBACK_ENABLED",
                true,
            )?,
            gemini_timeout_seconds: env_u64(&lookup, "GEMINI_MCP_TIMEOUT_SECONDS", 3600)?,
            gemini_stats_timeout_seconds: env_u64(
                &lookup,
                "GEMINI_MCP_STATS_TIMEOUT_SECONDS",
                120,
            )?,
            gemini_session_probe_stale_window_seconds: env_u64(
                &lookup,
                "GEMINI_MCP_SESSION_PROBE_STALE_WINDOW_SECONDS",
                900,
            )?,
            gemini_async_max_tracked_invocations: env_usize(
                &lookup,
                "GEMINI_MCP_ASYNC_MAX_TRACKED_INVOCATIONS",
                128,
            )?,
            gemini_async_retention_seconds: env_u64(
                &lookup,
                "GEMINI_MCP_ASYNC_RETENTION_SECONDS",
                21_600,
            )?,
        })
    }

    /// Summary: convert raw env-near fields into normalized execution policy.
    ///
    /// # Errors
    /// * Returns `Err` for invalid allowlist/ask-mode values.
    ///
    /// # Security
    /// * Normalizes policy to deny-by-default downstream MCP unless explicitly
    ///   broadened.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn to_execution_config(&self) -> Result<GeminiExecutionConfig, String> {
        let allowed_mcp_servers =
            AllowedMcpServers::parse_csv(&self.gemini_allowed_server_names)
                .map_err(|err| format!("invalid GEMINI_MCP_ALLOWED_SERVER_NAMES: {err}"))?;
        let ask_gemini_policy = parse_ask_gemini_policy(&self.gemini_ask_gemini_mode)?;
        let resume_compression_default =
            parse_resume_compression_default(&self.gemini_resume_compression_default)?;
        if self.gemini_resume_context_warn_percent > 100 {
            return Err(
                "GEMINI_MCP_RESUME_CONTEXT_WARN_PERCENT must be between 0 and 100.".to_string(),
            );
        }

        let retry_429_random_interval_range = if self.gemini_retry_429_random_interval_enabled {
            if self.gemini_retry_429_random_interval_max_millis
                < self.gemini_retry_429_random_interval_min_millis
            {
                return Err(
                    "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MAX_SECONDS must be >= GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MIN_SECONDS."
                        .to_string(),
                );
            }
            Some((
                Duration::from_millis(self.gemini_retry_429_random_interval_min_millis),
                Duration::from_millis(self.gemini_retry_429_random_interval_max_millis),
            ))
        } else {
            None
        };

        Ok(GeminiExecutionConfig {
            gemini_bin: self.gemini_bin.clone(),
            gemini_node_bin: self.gemini_node_bin.clone(),
            default_model: self.gemini_default_model.clone(),
            model_allowlist: self.gemini_model_allowlist.clone(),
            allowed_mcp_servers,
            home_dir: self.gemini_home_dir.clone(),
            timeout: Duration::from_secs(self.gemini_timeout_seconds),
            include_directories: self.gemini_include_directories.clone(),
            retry_429_enabled: self.gemini_retry_429_enabled,
            retry_429_window: Duration::from_secs(self.gemini_retry_429_window_seconds),
            retry_429_max_retries: self.gemini_retry_429_max_retries,
            retry_429_interval: Duration::from_secs(self.gemini_retry_429_interval_seconds),
            retry_429_random_interval_range,
            inspect_heartbeat_enabled: self.gemini_inspect_heartbeat_enabled,
            inspect_heartbeat_interval: Duration::from_millis(
                self.gemini_inspect_heartbeat_interval_millis,
            ),
            inspect_stall_threshold: Duration::from_millis(
                self.gemini_inspect_stall_threshold_millis,
            ),
            ask_gemini_policy,
            ask_gemini_allowed_roots: self.gemini_ask_gemini_allowed_roots.clone(),
            enable_resume: self.gemini_enable_resume,
            resume_compression_default,
            resume_context_warn_percent: self.gemini_resume_context_warn_percent,
            usage_ledger_path: self.gemini_usage_ledger_path.clone(),
            response_debug_path: self.gemini_response_debug_path.clone(),
            session_probe_snapshot_path: self.gemini_session_probe_snapshot_path.clone(),
            resume_compression_bridge_script_path: self
                .gemini_resume_compression_bridge_script_path
                .clone(),
            sandbox_fallback_enabled: self.gemini_sandbox_fallback_enabled,
            stats_timeout: Duration::from_secs(self.gemini_stats_timeout_seconds),
            session_probe_stale_window: Duration::from_secs(
                self.gemini_session_probe_stale_window_seconds,
            ),
            async_max_tracked_invocations: self.gemini_async_max_tracked_invocations,
            async_retention: Duration::from_secs(self.gemini_async_retention_seconds),
        })
    }

    /// Summary: consume raw config and return normalized execution config.
    ///
    /// # Errors
    /// * Returns the same parse/validation errors as
    ///   [`GeminiExecutionRawConfig::to_execution_config`].
    ///
    /// # Security
    /// * Preserves deny-by-default downstream MCP policy semantics.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn into_execution_config(self) -> Result<GeminiExecutionConfig, String> {
        self.to_execution_config()
    }
}

/// Summary: load normalized execution policy directly from process env.
///
/// # Errors
/// * Returns `Err` for invalid env values or policy conversions.
///
/// # Security
/// * Centralizes execution-policy parsing in the toolkit crate.
///
/// # Panics
/// * Does not panic.
pub fn load_execution_config_from_process_env() -> Result<GeminiExecutionConfig, String> {
    GeminiExecutionRawConfig::from_process_env()?.into_execution_config()
}

/// Summary: load normalized execution policy from a test/local env map.
///
/// # Errors
/// * Returns `Err` for invalid env values or policy conversions.
///
/// # Security
/// * Supports deterministic parser testing without process-global mutation.
///
/// # Panics
/// * Does not panic.
pub fn load_execution_config_from_env_map(
    env: &std::collections::HashMap<String, String>,
) -> Result<GeminiExecutionConfig, String> {
    GeminiExecutionRawConfig::from_env_map(env)?.into_execution_config()
}

fn env_setting<F>(lookup: &F, key: &str, default: &str) -> String
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key).unwrap_or_else(|| default.to_string())
}

fn env_optional_string<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

fn env_csv<F>(lookup: &F, key: &str, default: &str) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = lookup(key).unwrap_or_else(|| default.to_string());
    raw.split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn env_flag<F>(lookup: &F, key: &str, default: bool) -> Result<bool, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) => match raw.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            "" => Ok(default),
            _ => Err(format!("Invalid boolean for {key}: {raw}")),
        },
        None => Ok(default),
    }
}

fn env_u64<F>(lookup: &F, key: &str, default: u64) -> Result<u64, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<u64>()
            .map_err(|err| format!("Invalid {key}: {err}")),
        _ => Ok(default),
    }
}

fn env_usize<F>(lookup: &F, key: &str, default: usize) -> Result<usize, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("Invalid {key}: {err}")),
        _ => Ok(default),
    }
}

fn env_duration_seconds_as_millis<F>(
    lookup: &F,
    key: &str,
    default_seconds: f64,
) -> Result<u64, String>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = match lookup(key) {
        Some(raw) if !raw.trim().is_empty() => raw.trim().to_string(),
        _ => return Ok((default_seconds * 1000.0).round().max(0.0) as u64),
    };
    let seconds = raw
        .parse::<f64>()
        .map_err(|err| format!("Invalid {key}: {err}"))?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(format!(
            "Invalid {key}: value must be a finite non-negative number of seconds"
        ));
    }
    let millis = (seconds * 1000.0).round();
    if millis > u64::MAX as f64 {
        return Err(format!("Invalid {key}: value is too large"));
    }
    Ok(millis as u64)
}

fn parse_ask_gemini_policy(value: &str) -> Result<AskGeminiPolicy, String> {
    match value.trim().to_lowercase().as_str() {
        "" | "freeform" => Ok(AskGeminiPolicy::Freeform),
        "scoped" | "scoped_only" | "scoped-only" | "target_required" | "target-required" => {
            Ok(AskGeminiPolicy::ScopedOnly)
        }
        _ => Err(format!(
            "Unsupported GEMINI_MCP_ASK_GEMINI_MODE={value:?}; use 'freeform' or 'scoped'."
        )),
    }
}

fn parse_resume_compression_default(value: &str) -> Result<ResumeCompressionDefault, String> {
    match value.trim().to_lowercase().as_str() {
        "" | "auto" => Ok(ResumeCompressionDefault::Auto),
        "off" | "disabled" | "false" => Ok(ResumeCompressionDefault::Off),
        _ => Err(format!(
            "Unsupported GEMINI_MCP_RESUME_COMPRESSION_DEFAULT={value:?}; use 'auto' or 'off'."
        )),
    }
}

/// Summary: runtime execution settings for Gemini CLI-backed tooling.
///
/// # Errors
/// * Validation is handled by callers when converting from env/CLI.
///
/// # Security
/// * Holds execution policy only; does not store secrets directly.
///
/// # Panics
/// * Does not panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiExecutionConfig {
    pub gemini_bin: String,
    pub gemini_node_bin: String,
    pub default_model: Option<String>,
    pub model_allowlist: Vec<String>,
    pub allowed_mcp_servers: AllowedMcpServers,
    pub home_dir: Option<String>,
    /// Maximum wall-clock time for a single Gemini CLI invocation.
    ///
    /// Set to `Duration::ZERO` to disable server-side timeouts and rely on
    /// MCP request cancellation instead.
    pub timeout: Duration,
    /// Maximum wall-clock time for the lightweight `gemini-session-stats` probe.
    ///
    /// Keep this short so unsupported or wedged local CLI states fail fast
    /// without consuming the main tool-call timeout budget.
    pub stats_timeout: Duration,
    /// Additional workspace roots that Gemini may read during tool execution.
    ///
    /// This maps to repeated `--include-directories` CLI flags.
    pub include_directories: Vec<String>,
    /// Enable fixed-interval retries for Gemini 429/resource-exhausted failures.
    ///
    /// This retry is implemented in the MCP wrapper and is intended for transient
    /// model-capacity exhaustion.
    pub retry_429_enabled: bool,
    /// Maximum wall-clock budget for MCP-level 429 retries.
    ///
    /// Set to `Duration::ZERO` to disable the time budget; retry behavior is then
    /// controlled by `retry_429_max_retries`.
    pub retry_429_window: Duration,
    /// Maximum number of additional 429 retries allowed after the initial attempt.
    ///
    /// Example: `2` means one initial call plus up to two retries.
    pub retry_429_max_retries: u64,
    /// Fixed delay between MCP-level 429 retry attempts.
    ///
    /// Set to `Duration::ZERO` to use a 1-second minimum interval.
    /// Ignored when `retry_429_random_interval_range` is configured.
    pub retry_429_interval: Duration,
    /// Optional random delay range between MCP-level 429 retries.
    ///
    /// When set, each retry sleep is sampled uniformly between
    /// `(min, max)` with millisecond precision.
    pub retry_429_random_interval_range: Option<(Duration, Duration)>,
    /// Enable periodic execution heartbeats for live inspection.
    ///
    /// This is best-effort observability only and does not alter tool behavior.
    pub inspect_heartbeat_enabled: bool,
    /// Interval between heartbeat snapshots when heartbeat is enabled.
    pub inspect_heartbeat_interval: Duration,
    /// Threshold used to classify an in-flight invocation as stalled.
    pub inspect_stall_threshold: Duration,
    /// Policy for freeform vs path-scoped `ask-gemini`.
    pub ask_gemini_policy: AskGeminiPolicy,
    /// Allowed roots for `ask-gemini` when `ask_gemini_policy=ScopedOnly`.
    pub ask_gemini_allowed_roots: Vec<String>,
    /// Enable opt-in Gemini conversation resume for all tools.
    ///
    /// When disabled, tool calls that provide a `resume` selector fail fast with
    /// a structured validation error.
    pub enable_resume: bool,
    /// Default pre-run compression policy for resumed Gemini calls.
    pub resume_compression_default: ResumeCompressionDefault,
    /// Warning threshold for resumed calls that still finish with a hot context window.
    pub resume_context_warn_percent: u64,
    /// Optional newline-delimited JSON ledger path for per-tool Gemini token usage records.
    pub usage_ledger_path: Option<String>,
    /// Optional newline-delimited JSON path for raw Gemini response envelopes.
    ///
    /// This is useful for local diagnostics when Gemini wrappers include large
    /// metadata payloads (`session_id`, `stats`) that should not be relayed
    /// back into model context.
    pub response_debug_path: Option<String>,
    /// Optional JSON path for the latest successful `gemini-session-stats` snapshot.
    ///
    /// When unset, the toolkit derives a sibling file next to the usage ledger
    /// or response-debug artifact when either path is configured.
    pub session_probe_snapshot_path: Option<String>,
    /// Optional absolute path to the Node helper used for resumed-session compression.
    pub resume_compression_bridge_script_path: Option<String>,
    /// Enable automatic fallback to non-sandbox execution when sandbox runtime
    /// artifacts are unavailable (for example, missing sandbox container image).
    pub sandbox_fallback_enabled: bool,
    /// Maximum freshness window for serving cached `gemini-session-stats` data
    /// when the live probe fails transiently.
    pub session_probe_stale_window: Duration,
    /// Maximum number of async Gemini invocations retained in-process.
    pub async_max_tracked_invocations: usize,
    /// Retention window for completed async invocation results.
    pub async_retention: Duration,
}

impl Default for GeminiExecutionConfig {
    fn default() -> Self {
        Self {
            gemini_bin: "gemini".to_string(),
            gemini_node_bin: "node".to_string(),
            default_model: None,
            model_allowlist: Vec::new(),
            allowed_mcp_servers: AllowedMcpServers::None,
            home_dir: None,
            timeout: Duration::from_secs(3600),
            stats_timeout: Duration::from_secs(120),
            include_directories: Vec::new(),
            retry_429_enabled: false,
            retry_429_window: Duration::ZERO,
            retry_429_max_retries: 2,
            retry_429_interval: Duration::from_secs(5),
            retry_429_random_interval_range: None,
            inspect_heartbeat_enabled: false,
            inspect_heartbeat_interval: Duration::from_secs(15),
            inspect_stall_threshold: Duration::from_secs(60),
            ask_gemini_policy: AskGeminiPolicy::Freeform,
            ask_gemini_allowed_roots: Vec::new(),
            enable_resume: true,
            resume_compression_default: ResumeCompressionDefault::Auto,
            resume_context_warn_percent: 70,
            usage_ledger_path: None,
            response_debug_path: None,
            session_probe_snapshot_path: None,
            resume_compression_bridge_script_path: None,
            sandbox_fallback_enabled: true,
            session_probe_stale_window: Duration::from_secs(900),
            async_max_tracked_invocations: 128,
            async_retention: Duration::from_secs(21_600),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AllowedMcpServers, AskGeminiPolicy, DEFAULT_GEMINI_MODEL_ALLOWLIST,
        GeminiExecutionRawConfig, ResumeCompressionDefault, load_execution_config_from_env_map,
    };
    use std::collections::HashMap;
    use std::time::Duration;

    #[test]
    fn parse_none_aliases() {
        assert_eq!(
            AllowedMcpServers::parse_csv("__none__").expect("parse"),
            AllowedMcpServers::None
        );
        assert_eq!(
            AllowedMcpServers::parse_csv(" ").expect("parse"),
            AllowedMcpServers::None
        );
    }

    #[test]
    fn parse_all_aliases() {
        assert_eq!(
            AllowedMcpServers::parse_csv("__all__").expect("parse"),
            AllowedMcpServers::All
        );
        assert_eq!(
            AllowedMcpServers::parse_csv("all").expect("parse"),
            AllowedMcpServers::All
        );
    }

    #[test]
    fn parse_named_servers() {
        assert_eq!(
            AllowedMcpServers::parse_csv("ops, spark_mcp").expect("parse named servers"),
            AllowedMcpServers::Names(vec!["ops".to_string(), "spark_mcp".to_string()])
        );
    }

    #[test]
    fn raw_defaults_match_current_runtime_contract() {
        let raw = GeminiExecutionRawConfig::default();
        assert_eq!(raw.gemini_bin, "gemini");
        assert_eq!(raw.gemini_node_bin, "node");
        assert_eq!(raw.gemini_allowed_server_names, "__none__");
        assert_eq!(raw.gemini_timeout_seconds, 3600);
        assert_eq!(raw.gemini_stats_timeout_seconds, 120);
        assert_eq!(raw.gemini_retry_429_window_seconds, 900);
        assert!(!raw.gemini_retry_429_random_interval_enabled);
        assert_eq!(raw.gemini_retry_429_random_interval_min_millis, 1_000);
        assert_eq!(raw.gemini_retry_429_random_interval_max_millis, 120_000);
        assert!(!raw.gemini_inspect_heartbeat_enabled);
        assert_eq!(raw.gemini_inspect_heartbeat_interval_millis, 15_000);
        assert_eq!(raw.gemini_inspect_stall_threshold_millis, 60_000);
        assert!(raw.gemini_enable_resume);
        assert_eq!(raw.gemini_resume_compression_default, "auto");
        assert_eq!(raw.gemini_resume_context_warn_percent, 70);
        assert!(raw.gemini_sandbox_fallback_enabled);
        assert_eq!(raw.gemini_session_probe_stale_window_seconds, 900);
        assert!(raw.gemini_resume_compression_bridge_script_path.is_none());
        assert_eq!(raw.gemini_async_max_tracked_invocations, 128);
        assert_eq!(raw.gemini_async_retention_seconds, 21_600);
        assert_eq!(
            raw.gemini_model_allowlist,
            DEFAULT_GEMINI_MODEL_ALLOWLIST
                .split(',')
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert!(
            raw.gemini_model_allowlist
                .iter()
                .any(|model| model == "gemini-2.5-flash-lite")
        );
    }

    #[test]
    fn raw_loader_parses_env_map_overrides() {
        let mut env = HashMap::new();
        env.insert("GEMINI_CLI_BIN".to_string(), "/usr/bin/gemini".to_string());
        env.insert("GEMINI_NODE_BIN".to_string(), "/usr/bin/node".to_string());
        env.insert(
            "GEMINI_MCP_DEFAULT_MODEL".to_string(),
            "gemini-3-pro".to_string(),
        );
        env.insert(
            "GEMINI_MCP_ALLOWED_MODELS".to_string(),
            "m1, m2 , ,m3".to_string(),
        );
        env.insert(
            "GEMINI_MCP_INCLUDE_DIRECTORIES".to_string(),
            "/a,/b, /c".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RETRY_429_ENABLED".to_string(),
            "true".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RETRY_429_WINDOW_SECONDS".to_string(),
            "12".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RETRY_429_MAX_RETRIES".to_string(),
            "4".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RETRY_429_INTERVAL_SECONDS".to_string(),
            "3".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_ENABLED".to_string(),
            "true".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MIN_SECONDS".to_string(),
            "1.25".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MAX_SECONDS".to_string(),
            "2.5".to_string(),
        );
        env.insert(
            "GEMINI_MCP_INSPECT_HEARTBEAT_ENABLED".to_string(),
            "true".to_string(),
        );
        env.insert(
            "GEMINI_MCP_INSPECT_HEARTBEAT_INTERVAL_SECONDS".to_string(),
            "2.5".to_string(),
        );
        env.insert(
            "GEMINI_MCP_INSPECT_STALL_SECONDS".to_string(),
            "7.25".to_string(),
        );
        env.insert(
            "GEMINI_MCP_ASK_GEMINI_MODE".to_string(),
            "scoped-only".to_string(),
        );
        env.insert(
            "GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS".to_string(),
            "/r1,/r2".to_string(),
        );
        env.insert("GEMINI_MCP_ENABLE_RESUME".to_string(), "false".to_string());
        env.insert(
            "GEMINI_MCP_RESUME_COMPRESSION_DEFAULT".to_string(),
            "off".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RESUME_CONTEXT_WARN_PERCENT".to_string(),
            "85".to_string(),
        );
        env.insert(
            "GEMINI_MCP_USAGE_LEDGER_PATH".to_string(),
            "/tmp/gemini-usage.jsonl".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RESPONSE_DEBUG_PATH".to_string(),
            "/tmp/gemini-response-debug.jsonl".to_string(),
        );
        env.insert(
            "GEMINI_MCP_SESSION_PROBE_SNAPSHOT_PATH".to_string(),
            "/tmp/gemini-session-probe.json".to_string(),
        );
        env.insert(
            "GEMINI_MCP_RESUME_COMPRESSION_BRIDGE_SCRIPT_PATH".to_string(),
            "/tmp/gemini-compress.mjs".to_string(),
        );
        env.insert(
            "GEMINI_MCP_SANDBOX_FALLBACK_ENABLED".to_string(),
            "false".to_string(),
        );
        env.insert("GEMINI_MCP_TIMEOUT_SECONDS".to_string(), "99".to_string());
        env.insert(
            "GEMINI_MCP_STATS_TIMEOUT_SECONDS".to_string(),
            "11".to_string(),
        );
        env.insert(
            "GEMINI_MCP_SESSION_PROBE_STALE_WINDOW_SECONDS".to_string(),
            "120".to_string(),
        );
        env.insert(
            "GEMINI_MCP_ASYNC_MAX_TRACKED_INVOCATIONS".to_string(),
            "19".to_string(),
        );
        env.insert(
            "GEMINI_MCP_ASYNC_RETENTION_SECONDS".to_string(),
            "2400".to_string(),
        );

        let raw = GeminiExecutionRawConfig::from_env_map(&env).expect("parse env map");
        assert_eq!(raw.gemini_bin, "/usr/bin/gemini");
        assert_eq!(raw.gemini_node_bin, "/usr/bin/node");
        assert_eq!(raw.gemini_default_model.as_deref(), Some("gemini-3-pro"));
        assert_eq!(raw.gemini_model_allowlist, vec!["m1", "m2", "m3"]);
        assert_eq!(raw.gemini_include_directories, vec!["/a", "/b", "/c"]);
        assert!(raw.gemini_retry_429_enabled);
        assert_eq!(raw.gemini_retry_429_window_seconds, 12);
        assert_eq!(raw.gemini_retry_429_max_retries, 4);
        assert_eq!(raw.gemini_retry_429_interval_seconds, 3);
        assert!(raw.gemini_retry_429_random_interval_enabled);
        assert_eq!(raw.gemini_retry_429_random_interval_min_millis, 1_250);
        assert_eq!(raw.gemini_retry_429_random_interval_max_millis, 2_500);
        assert!(raw.gemini_inspect_heartbeat_enabled);
        assert_eq!(raw.gemini_inspect_heartbeat_interval_millis, 2_500);
        assert_eq!(raw.gemini_inspect_stall_threshold_millis, 7_250);
        assert_eq!(raw.gemini_ask_gemini_mode, "scoped-only");
        assert_eq!(raw.gemini_ask_gemini_allowed_roots, vec!["/r1", "/r2"]);
        assert!(!raw.gemini_enable_resume);
        assert_eq!(raw.gemini_resume_compression_default, "off");
        assert_eq!(raw.gemini_resume_context_warn_percent, 85);
        assert_eq!(
            raw.gemini_usage_ledger_path.as_deref(),
            Some("/tmp/gemini-usage.jsonl")
        );
        assert_eq!(
            raw.gemini_response_debug_path.as_deref(),
            Some("/tmp/gemini-response-debug.jsonl")
        );
        assert_eq!(
            raw.gemini_session_probe_snapshot_path.as_deref(),
            Some("/tmp/gemini-session-probe.json")
        );
        assert_eq!(
            raw.gemini_resume_compression_bridge_script_path.as_deref(),
            Some("/tmp/gemini-compress.mjs")
        );
        assert!(!raw.gemini_sandbox_fallback_enabled);
        assert_eq!(raw.gemini_timeout_seconds, 99);
        assert_eq!(raw.gemini_stats_timeout_seconds, 11);
        assert_eq!(raw.gemini_session_probe_stale_window_seconds, 120);
        assert_eq!(raw.gemini_async_max_tracked_invocations, 19);
        assert_eq!(raw.gemini_async_retention_seconds, 2400);
    }

    #[test]
    fn raw_loader_rejects_invalid_boolean() {
        let mut env = HashMap::new();
        env.insert(
            "GEMINI_MCP_RETRY_429_ENABLED".to_string(),
            "definitely".to_string(),
        );
        let err =
            GeminiExecutionRawConfig::from_env_map(&env).expect_err("invalid boolean should fail");
        assert!(err.contains("Invalid boolean for GEMINI_MCP_RETRY_429_ENABLED"));
    }

    #[test]
    fn raw_loader_rejects_invalid_u64() {
        let mut env = HashMap::new();
        env.insert(
            "GEMINI_MCP_TIMEOUT_SECONDS".to_string(),
            "invalid".to_string(),
        );
        let err =
            GeminiExecutionRawConfig::from_env_map(&env).expect_err("invalid u64 should fail");
        assert!(err.contains("Invalid GEMINI_MCP_TIMEOUT_SECONDS"));
    }

    #[test]
    fn raw_loader_rejects_invalid_retry_random_interval_seconds() {
        let mut env = HashMap::new();
        env.insert(
            "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MIN_SECONDS".to_string(),
            "abc".to_string(),
        );
        let err = GeminiExecutionRawConfig::from_env_map(&env)
            .expect_err("invalid random interval seconds should fail");
        assert!(err.contains("Invalid GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MIN_SECONDS"));
    }

    #[test]
    fn raw_to_normalized_execution_config_converts_policy_fields() {
        let raw = GeminiExecutionRawConfig {
            gemini_bin: "/bin/gemini".to_string(),
            gemini_node_bin: "/usr/bin/node".to_string(),
            gemini_default_model: Some("gemini-3-pro".to_string()),
            gemini_model_allowlist: vec!["gemini-3-pro".to_string(), "gemini-3-flash".to_string()],
            gemini_home_dir: Some("/tmp/home".to_string()),
            gemini_allowed_server_names: "ops,codebase_search_mcp".to_string(),
            gemini_include_directories: vec!["/repo".to_string()],
            gemini_retry_429_enabled: true,
            gemini_retry_429_window_seconds: 120,
            gemini_retry_429_max_retries: 5,
            gemini_retry_429_interval_seconds: 3,
            gemini_retry_429_random_interval_enabled: true,
            gemini_retry_429_random_interval_min_millis: 1_000,
            gemini_retry_429_random_interval_max_millis: 2_000,
            gemini_inspect_heartbeat_enabled: true,
            gemini_inspect_heartbeat_interval_millis: 3_000,
            gemini_inspect_stall_threshold_millis: 8_000,
            gemini_ask_gemini_mode: "target_required".to_string(),
            gemini_ask_gemini_allowed_roots: vec!["/repo".to_string(), "/repo2".to_string()],
            gemini_enable_resume: false,
            gemini_resume_compression_default: "off".to_string(),
            gemini_resume_context_warn_percent: 85,
            gemini_usage_ledger_path: Some("/tmp/gemini-usage.jsonl".to_string()),
            gemini_response_debug_path: Some("/tmp/gemini-response-debug.jsonl".to_string()),
            gemini_session_probe_snapshot_path: Some("/tmp/gemini-session-probe.json".to_string()),
            gemini_resume_compression_bridge_script_path: Some(
                "/tmp/gemini-compress.mjs".to_string(),
            ),
            gemini_sandbox_fallback_enabled: false,
            gemini_timeout_seconds: 77,
            gemini_stats_timeout_seconds: 9,
            gemini_session_probe_stale_window_seconds: 321,
            gemini_async_max_tracked_invocations: 55,
            gemini_async_retention_seconds: 7_200,
        };

        let normalized = raw
            .to_execution_config()
            .expect("convert raw to normalized config");
        assert_eq!(normalized.gemini_bin, "/bin/gemini");
        assert_eq!(normalized.gemini_node_bin, "/usr/bin/node");
        assert_eq!(normalized.default_model.as_deref(), Some("gemini-3-pro"));
        assert_eq!(
            normalized.model_allowlist,
            vec!["gemini-3-pro".to_string(), "gemini-3-flash".to_string()]
        );
        assert_eq!(
            normalized.allowed_mcp_servers,
            AllowedMcpServers::Names(vec!["ops".to_string(), "codebase_search_mcp".to_string()])
        );
        assert_eq!(normalized.async_max_tracked_invocations, 55);
        assert_eq!(normalized.async_retention, Duration::from_secs(7_200));
        assert_eq!(normalized.home_dir.as_deref(), Some("/tmp/home"));
        assert_eq!(normalized.include_directories, vec!["/repo".to_string()]);
        assert!(normalized.retry_429_enabled);
        assert_eq!(normalized.retry_429_window, Duration::from_secs(120));
        assert_eq!(normalized.retry_429_max_retries, 5);
        assert_eq!(normalized.retry_429_interval, Duration::from_secs(3));
        assert_eq!(
            normalized.retry_429_random_interval_range,
            Some((Duration::from_secs(1), Duration::from_secs(2)))
        );
        assert!(normalized.inspect_heartbeat_enabled);
        assert_eq!(
            normalized.inspect_heartbeat_interval,
            Duration::from_secs(3)
        );
        assert_eq!(normalized.inspect_stall_threshold, Duration::from_secs(8));
        assert_eq!(normalized.ask_gemini_policy, AskGeminiPolicy::ScopedOnly);
        assert_eq!(
            normalized.ask_gemini_allowed_roots,
            vec!["/repo".to_string(), "/repo2".to_string()]
        );
        assert!(!normalized.enable_resume);
        assert_eq!(
            normalized.resume_compression_default,
            ResumeCompressionDefault::Off
        );
        assert_eq!(normalized.resume_context_warn_percent, 85);
        assert_eq!(
            normalized.usage_ledger_path.as_deref(),
            Some("/tmp/gemini-usage.jsonl")
        );
        assert_eq!(
            normalized.response_debug_path.as_deref(),
            Some("/tmp/gemini-response-debug.jsonl")
        );
        assert_eq!(
            normalized.session_probe_snapshot_path.as_deref(),
            Some("/tmp/gemini-session-probe.json")
        );
        assert_eq!(
            normalized.resume_compression_bridge_script_path.as_deref(),
            Some("/tmp/gemini-compress.mjs")
        );
        assert!(!normalized.sandbox_fallback_enabled);
        assert_eq!(normalized.timeout, Duration::from_secs(77));
        assert_eq!(normalized.stats_timeout, Duration::from_secs(9));
        assert_eq!(
            normalized.session_probe_stale_window,
            Duration::from_secs(321)
        );
    }

    #[test]
    fn raw_to_normalized_rejects_invalid_allowlist_policy() {
        let raw = GeminiExecutionRawConfig {
            gemini_allowed_server_names: ",  ,".to_string(),
            ..GeminiExecutionRawConfig::default()
        };
        let err = raw
            .to_execution_config()
            .expect_err("invalid allowlist policy should fail");
        assert!(err.contains("invalid GEMINI_MCP_ALLOWED_SERVER_NAMES"));
    }

    #[test]
    fn raw_to_normalized_rejects_invalid_ask_policy() {
        let raw = GeminiExecutionRawConfig {
            gemini_ask_gemini_mode: "unknown".to_string(),
            ..GeminiExecutionRawConfig::default()
        };
        let err = raw
            .to_execution_config()
            .expect_err("invalid ask policy should fail");
        assert!(err.contains("Unsupported GEMINI_MCP_ASK_GEMINI_MODE"));
    }

    #[test]
    fn raw_to_normalized_rejects_invalid_resume_compression_default() {
        let raw = GeminiExecutionRawConfig {
            gemini_resume_compression_default: "sometimes".to_string(),
            ..GeminiExecutionRawConfig::default()
        };
        let err = raw
            .to_execution_config()
            .expect_err("invalid resume compression default should fail");
        assert!(err.contains("Unsupported GEMINI_MCP_RESUME_COMPRESSION_DEFAULT"));
    }

    #[test]
    fn raw_to_normalized_rejects_warn_percent_above_hundred() {
        let raw = GeminiExecutionRawConfig {
            gemini_resume_context_warn_percent: 101,
            ..GeminiExecutionRawConfig::default()
        };
        let err = raw
            .to_execution_config()
            .expect_err("warn percent above hundred should fail");
        assert!(err.contains("GEMINI_MCP_RESUME_CONTEXT_WARN_PERCENT"));
    }

    #[test]
    fn raw_to_normalized_rejects_retry_random_interval_when_max_lt_min() {
        let raw = GeminiExecutionRawConfig {
            gemini_retry_429_random_interval_enabled: true,
            gemini_retry_429_random_interval_min_millis: 5_000,
            gemini_retry_429_random_interval_max_millis: 2_000,
            ..GeminiExecutionRawConfig::default()
        };
        let err = raw
            .to_execution_config()
            .expect_err("max below min should fail");
        assert!(err.contains(
            "GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MAX_SECONDS must be >= GEMINI_MCP_RETRY_429_RANDOM_INTERVAL_MIN_SECONDS"
        ));
    }

    #[test]
    fn load_execution_config_from_env_map_is_additive_and_deterministic() {
        let mut env = HashMap::new();
        env.insert(
            "GEMINI_MCP_ALLOWED_SERVER_NAMES".to_string(),
            "__none__".to_string(),
        );
        env.insert(
            "GEMINI_MCP_ASK_GEMINI_MODE".to_string(),
            "freeform".to_string(),
        );
        env.insert("GEMINI_MCP_TIMEOUT_SECONDS".to_string(), "3".to_string());

        let config = load_execution_config_from_env_map(&env).expect("load normalized config");
        assert_eq!(config.allowed_mcp_servers, AllowedMcpServers::None);
        assert_eq!(config.ask_gemini_policy, AskGeminiPolicy::Freeform);
        assert_eq!(config.timeout, Duration::from_secs(3));
    }
}

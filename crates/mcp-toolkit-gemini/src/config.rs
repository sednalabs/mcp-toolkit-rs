//! # Gemini Toolkit Configuration
//!
//! Shared configuration primitives for Gemini CLI-backed MCP tools.
//!
//! ## Ownership
//! This module owns the parsing, normalization, and validation logic for Gemini
//! execution policies, including allowlists and retry budget settings.
//!
//! ## Non-ownership
//! This module does not manage direct model invocation; it focuses solely on
//! defining and validating the execution environment.
//!
//! ## Policy & Guarantees
//! * **Deterministic Parsing**: Provides structured conversion of environment variables
//!   into type-safe execution configurations.
//! * **Policy Defaults**: Enforces deny-by-default behavior for downstream MCP server
//!   access to mitigate risks associated with unintended tool fan-out.
//! * **API-key-only Auth**: Requires `GEMINI_API_KEY`; account-based Gemini CLI
//!   authentication and inherited home-directory credentials are unsupported.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Supplying process environment variables or hash maps compliant with the expected schema.
//! * Translating configuration errors into appropriate service-startup failures.
//!
//! ## References
//! * `mcp-workspace/servers/gemini-cli-mcp-rs`

use std::time::Duration;

/// Default allowlisted models when no explicit override is provided.
pub const DEFAULT_GEMINI_MODEL_ALLOWLIST: &str = "gemini-3-flash-preview,gemini-3-pro-preview";

/// Policy defining which downstream MCP servers are reachable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AllowedMcpServers {
    #[default]
    None,
    All,
    Names(Vec<String>),
}

impl AllowedMcpServers {
    /// Parses a CSV or keyword string into an allowlist policy.
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

    /// Generates CLI arguments representing the allowlist.
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

/// Controls whether `ask-gemini` accepts freeform prompts or restricted scoped targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AskGeminiPolicy {
    #[default]
    Freeform,
    ScopedOnly,
}

/// Raw execution policy fields prior to normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiExecutionRawConfig {
    pub gemini_api_key: Option<String>,
    pub gemini_bin: String,
    pub gemini_default_model: Option<String>,
    pub gemini_model_allowlist: Vec<String>,
    pub gemini_allowed_server_names: String,
    pub gemini_include_directories: Vec<String>,
    pub gemini_retry_429_enabled: bool,
    pub gemini_retry_429_window_seconds: u64,
    pub gemini_retry_429_max_retries: u64,
    pub gemini_retry_429_interval_seconds: u64,
    pub gemini_ask_gemini_mode: String,
    pub gemini_ask_gemini_allowed_roots: Vec<String>,
    pub gemini_timeout_seconds: u64,
}

impl Default for GeminiExecutionRawConfig {
    fn default() -> Self {
        Self {
            gemini_api_key: None,
            gemini_bin: "gemini".to_string(),
            gemini_default_model: None,
            gemini_model_allowlist: DEFAULT_GEMINI_MODEL_ALLOWLIST
                .split(',')
                .map(str::to_string)
                .collect(),
            gemini_allowed_server_names: "__none__".to_string(),
            gemini_include_directories: Vec::new(),
            gemini_retry_429_enabled: false,
            gemini_retry_429_window_seconds: 900,
            gemini_retry_429_max_retries: 2,
            gemini_retry_429_interval_seconds: 10,
            gemini_ask_gemini_mode: "freeform".to_string(),
            gemini_ask_gemini_allowed_roots: Vec::new(),
            gemini_timeout_seconds: 3600,
        }
    }
}

impl GeminiExecutionRawConfig {
    /// Loads raw execution policy fields from process environment.
    pub fn from_process_env() -> Result<Self, String> {
        Self::from_env_lookup(|key| std::env::var(key).ok())
    }

    /// Loads raw execution policy fields from a map-like environment.
    pub fn from_env_map(env: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        Self::from_env_lookup(|key| env.get(key).cloned())
    }

    fn from_env_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        Ok(Self {
            gemini_api_key: env_optional_string(&lookup, "GEMINI_API_KEY"),
            gemini_bin: env_setting(&lookup, "GEMINI_CLI_BIN", "gemini"),
            gemini_default_model: env_optional_string(&lookup, "GEMINI_MCP_DEFAULT_MODEL"),
            gemini_model_allowlist: env_csv(
                &lookup,
                "GEMINI_MCP_ALLOWED_MODELS",
                DEFAULT_GEMINI_MODEL_ALLOWLIST,
            ),
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
            gemini_ask_gemini_mode: env_setting(&lookup, "GEMINI_MCP_ASK_GEMINI_MODE", "freeform"),
            gemini_ask_gemini_allowed_roots: env_csv(
                &lookup,
                "GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS",
                "",
            ),
            gemini_timeout_seconds: env_u64(&lookup, "GEMINI_MCP_TIMEOUT_SECONDS", 3600)?,
        })
    }

    /// Converts raw fields into a normalized execution configuration.
    pub fn to_execution_config(&self) -> Result<GeminiExecutionConfig, String> {
        let api_key = self.gemini_api_key.as_deref().ok_or_else(|| {
            "GEMINI_API_KEY is required; account-based Gemini CLI auth is not supported".to_string()
        })?;
        let allowed_mcp_servers =
            AllowedMcpServers::parse_csv(&self.gemini_allowed_server_names)
                .map_err(|err| format!("invalid GEMINI_MCP_ALLOWED_SERVER_NAMES: {err}"))?;
        let ask_gemini_policy = parse_ask_gemini_policy(&self.gemini_ask_gemini_mode)?;

        Ok(GeminiExecutionConfig {
            api_key: api_key.to_string(),
            gemini_bin: self.gemini_bin.clone(),
            default_model: self.gemini_default_model.clone(),
            model_allowlist: self.gemini_model_allowlist.clone(),
            allowed_mcp_servers,
            timeout: Duration::from_secs(self.gemini_timeout_seconds),
            include_directories: self.gemini_include_directories.clone(),
            retry_429_enabled: self.gemini_retry_429_enabled,
            retry_429_window: Duration::from_secs(self.gemini_retry_429_window_seconds),
            retry_429_max_retries: self.gemini_retry_429_max_retries,
            retry_429_interval: Duration::from_secs(self.gemini_retry_429_interval_seconds),
            ask_gemini_policy,
            ask_gemini_allowed_roots: self.gemini_ask_gemini_allowed_roots.clone(),
        })
    }

    /// Consumes raw config and returns a normalized execution configuration.
    pub fn into_execution_config(self) -> Result<GeminiExecutionConfig, String> {
        self.to_execution_config()
    }
}

/// Loads normalized execution policy directly from process environment.
pub fn load_execution_config_from_process_env() -> Result<GeminiExecutionConfig, String> {
    GeminiExecutionRawConfig::from_process_env()?.into_execution_config()
}

/// Loads normalized execution policy from a provided map.
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

/// Runtime execution settings for Gemini CLI-backed tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiExecutionConfig {
    /// API key passed to the Gemini CLI as `GEMINI_API_KEY`.
    ///
    /// Account-based Gemini CLI auth is intentionally unsupported.
    pub api_key: String,
    pub gemini_bin: String,
    pub default_model: Option<String>,
    pub model_allowlist: Vec<String>,
    pub allowed_mcp_servers: AllowedMcpServers,
    /// Maximum wall-clock time for a single Gemini CLI invocation.
    pub timeout: Duration,
    /// Additional workspace roots Gemini may read during execution.
    pub include_directories: Vec<String>,
    /// Enable fixed-interval retries for transient 429/exhaustion failures.
    pub retry_429_enabled: bool,
    /// Time budget for retry attempts.
    pub retry_429_window: Duration,
    /// Maximum retry attempts permitted.
    pub retry_429_max_retries: u64,
    /// Delay between retry attempts.
    pub retry_429_interval: Duration,
    /// Policy for freeform vs path-scoped `ask-gemini`.
    pub ask_gemini_policy: AskGeminiPolicy,
    /// Allowed roots for `ask-gemini` when `ask_gemini_policy=ScopedOnly`.
    pub ask_gemini_allowed_roots: Vec<String>,
}

impl Default for GeminiExecutionConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            gemini_bin: "gemini".to_string(),
            default_model: None,
            model_allowlist: Vec::new(),
            allowed_mcp_servers: AllowedMcpServers::None,
            timeout: Duration::from_secs(3600),
            include_directories: Vec::new(),
            retry_429_enabled: false,
            retry_429_window: Duration::ZERO,
            retry_429_max_retries: 2,
            retry_429_interval: Duration::from_secs(5),
            ask_gemini_policy: AskGeminiPolicy::Freeform,
            ask_gemini_allowed_roots: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        load_execution_config_from_env_map, AllowedMcpServers, AskGeminiPolicy,
        GeminiExecutionRawConfig, DEFAULT_GEMINI_MODEL_ALLOWLIST,
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
        assert_eq!(raw.gemini_api_key, None);
        assert_eq!(raw.gemini_bin, "gemini");
        assert_eq!(raw.gemini_allowed_server_names, "__none__");
        assert_eq!(raw.gemini_timeout_seconds, 3600);
        assert_eq!(raw.gemini_retry_429_window_seconds, 900);
        assert_eq!(
            raw.gemini_model_allowlist,
            DEFAULT_GEMINI_MODEL_ALLOWLIST
                .split(',')
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn raw_loader_parses_env_map_overrides() {
        let mut env = HashMap::new();
        env.insert("GEMINI_API_KEY".to_string(), "test-api-key".to_string());
        env.insert("GEMINI_CLI_BIN".to_string(), "/usr/bin/gemini".to_string());
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
            "GEMINI_MCP_ASK_GEMINI_MODE".to_string(),
            "scoped-only".to_string(),
        );
        env.insert(
            "GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS".to_string(),
            "/r1,/r2".to_string(),
        );
        env.insert("GEMINI_MCP_TIMEOUT_SECONDS".to_string(), "99".to_string());

        let raw = GeminiExecutionRawConfig::from_env_map(&env).expect("parse env map");
        assert_eq!(raw.gemini_api_key.as_deref(), Some("test-api-key"));
        assert_eq!(raw.gemini_bin, "/usr/bin/gemini");
        assert_eq!(raw.gemini_default_model.as_deref(), Some("gemini-3-pro"));
        assert_eq!(raw.gemini_model_allowlist, vec!["m1", "m2", "m3"]);
        assert_eq!(raw.gemini_include_directories, vec!["/a", "/b", "/c"]);
        assert!(raw.gemini_retry_429_enabled);
        assert_eq!(raw.gemini_retry_429_window_seconds, 12);
        assert_eq!(raw.gemini_retry_429_max_retries, 4);
        assert_eq!(raw.gemini_retry_429_interval_seconds, 3);
        assert_eq!(raw.gemini_ask_gemini_mode, "scoped-only");
        assert_eq!(raw.gemini_ask_gemini_allowed_roots, vec!["/r1", "/r2"]);
        assert_eq!(raw.gemini_timeout_seconds, 99);
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
    fn raw_to_normalized_execution_config_converts_policy_fields() {
        let raw = GeminiExecutionRawConfig {
            gemini_api_key: Some("test-api-key".to_string()),
            gemini_bin: "/bin/gemini".to_string(),
            gemini_default_model: Some("gemini-3-pro".to_string()),
            gemini_model_allowlist: vec!["gemini-3-pro".to_string(), "gemini-3-flash".to_string()],
            gemini_allowed_server_names: "ops,codebase_search_mcp".to_string(),
            gemini_include_directories: vec!["/repo".to_string()],
            gemini_retry_429_enabled: true,
            gemini_retry_429_window_seconds: 120,
            gemini_retry_429_max_retries: 5,
            gemini_retry_429_interval_seconds: 3,
            gemini_ask_gemini_mode: "target_required".to_string(),
            gemini_ask_gemini_allowed_roots: vec!["/repo".to_string(), "/repo2".to_string()],
            gemini_timeout_seconds: 77,
        };

        let normalized = raw
            .to_execution_config()
            .expect("convert raw to normalized config");
        assert_eq!(normalized.api_key, "test-api-key");
        assert_eq!(normalized.gemini_bin, "/bin/gemini");
        assert_eq!(normalized.default_model.as_deref(), Some("gemini-3-pro"));
        assert_eq!(
            normalized.model_allowlist,
            vec!["gemini-3-pro".to_string(), "gemini-3-flash".to_string()]
        );
        assert_eq!(
            normalized.allowed_mcp_servers,
            AllowedMcpServers::Names(vec!["ops".to_string(), "codebase_search_mcp".to_string()])
        );
        assert_eq!(normalized.include_directories, vec!["/repo".to_string()]);
        assert!(normalized.retry_429_enabled);
        assert_eq!(normalized.retry_429_window, Duration::from_secs(120));
        assert_eq!(normalized.retry_429_max_retries, 5);
        assert_eq!(normalized.retry_429_interval, Duration::from_secs(3));
        assert_eq!(normalized.ask_gemini_policy, AskGeminiPolicy::ScopedOnly);
        assert_eq!(
            normalized.ask_gemini_allowed_roots,
            vec!["/repo".to_string(), "/repo2".to_string()]
        );
        assert_eq!(normalized.timeout, Duration::from_secs(77));
    }

    #[test]
    fn raw_to_normalized_rejects_invalid_allowlist_policy() {
        let raw = GeminiExecutionRawConfig {
            gemini_api_key: Some("test-api-key".to_string()),
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
            gemini_api_key: Some("test-api-key".to_string()),
            gemini_ask_gemini_mode: "unknown".to_string(),
            ..GeminiExecutionRawConfig::default()
        };
        let err = raw
            .to_execution_config()
            .expect_err("invalid ask policy should fail");
        assert!(err.contains("Unsupported GEMINI_MCP_ASK_GEMINI_MODE"));
    }

    #[test]
    fn raw_to_normalized_requires_api_key() {
        let raw = GeminiExecutionRawConfig::default();
        let err = raw
            .to_execution_config()
            .expect_err("missing API key should fail");
        assert!(err.contains("GEMINI_API_KEY is required"));
        assert!(err.contains("account-based Gemini CLI auth is not supported"));
    }

    #[test]
    fn load_execution_config_from_env_map_is_additive_and_deterministic() {
        let mut env = HashMap::new();
        env.insert("GEMINI_API_KEY".to_string(), "test-api-key".to_string());
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
        assert_eq!(config.api_key, "test-api-key");
        assert_eq!(config.allowed_mcp_servers, AllowedMcpServers::None);
        assert_eq!(config.ask_gemini_policy, AskGeminiPolicy::Freeform);
        assert_eq!(config.timeout, Duration::from_secs(3));
    }
}

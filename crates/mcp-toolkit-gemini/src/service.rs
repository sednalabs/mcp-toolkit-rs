//! # Gemini MCP Service
//!
//! Reusable MCP tool router and server handler for Gemini CLI-backed tools.
//!
//! ## Rationale
//! Provide one canonical implementation of Gemini tool contracts while letting
//! transport wrappers remain thin in server repos.
//!
//! ## Security Boundaries
//! * Defers process execution to policy-aware executor.
//! * Returns structured errors without exposing environment values.
//!
//! ## References
//! * Transport wrappers that embed the reusable Gemini MCP service.

use std::collections::HashSet;
use std::fs::{OpenOptions, create_dir_all};
use std::future::Future;
use std::io::Write;
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::request::Parts;
use mcp_toolkit_auth::auth_context_from_parts;
use mcp_toolkit_core::rmcp_models;
use mcp_toolkit_core::tool_schema::tool_schema_snapshot_value;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::transport::common::http_header::HEADER_SESSION_ID;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::async_registry::{
    GeminiAsyncInvocationRegistry, GeminiAsyncInvocationSnapshot, GeminiAsyncInvocationState,
};
use crate::compression_bridge::{
    SessionCompressionBridgeResult, execute_session_compression_bridge,
};
use crate::config::{
    AllowedMcpServers, AskGeminiPolicy, GeminiExecutionConfig, GeminiExecutionRawConfig,
    ResumeCompressionDefault,
};
use crate::executor::{
    GEMINI_SESSION_PROBE_SOURCE_JSON, GeminiExecutionError, GeminiExecutionPhase,
    GeminiHeartbeatSnapshot, GeminiOutputFormat, GeminiOutputObserver, GeminiPromptTransport,
    GeminiRequest, GeminiResponse, GeminiSessionProbeError, execute_gemini_stats_session,
    execute_gemini_with_cancel_observed, retryable_429_reason, select_session_probe_model,
};
use crate::observe::{
    GeminiInvocationEvent, GeminiInvocationEventKind, GeminiInvocationMetadata,
    GeminiInvocationObserver, GeminiInvocationPhase, GeminiOutputStream, GeminiUsageSnapshot,
    NoopGeminiInvocationObserver,
};
use crate::resume::{
    ConversationResumeProvider, GeminiCliResumeProvider, ResumeExecutionPlan, ResumeStrategy,
};

fn codebase_scout_prompt(target: &str, question: &str) -> String {
    format!(
        "You are a codebase scout.\n\n\
Target path: {target}\n\
Question: {question}\n\n\
Execution strategy:\n\
1. If tool `delegate_to_agent` is available, call it at most once with:\n\
   {{\"agent_name\":\"codebase_investigator\",\"objective\":\"Investigate target {target}. Question: {question}\"}}\n\
2. Otherwise, investigate directly using only tools explicitly available in the runtime.\n\
3. Prefer direct file/search/read tools over exploratory tool loops.\n\
4. Convert final findings into the exact JSON schema below.\n\n\
Hard rules:\n\
- Use only evidence from files under the target path.\n\
- Do not invent files, symbols, behavior, or outcomes.\n\
- If you cannot access target files, set status to NO_ACCESS and explain why.\n\
- Do not guess tool names or call tools that are not explicitly available.\n\
- Prefer concrete references: path, symbol/function, and one-sentence relevance.\n\
- Keep output concise and technical.\n\
    - Do not emit planning chatter, scratchpads, XML, or markdown.\n\
    - Output must be a single JSON object only.\n\
    - Do not repeat the input question or target path in the response payload.\n\n\
Return JSON only with this schema:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"top_hits\": [\n\
    {{\"path\": \"string\", \"symbol\": \"string|null\", \"reason\": \"string\"}}\n\
  ],\n\
  \"findings\": [\"string\"],\n\
  \"risks\": [\"string\"],\n\
  \"next_steps\": [\"string\"],\n\
  \"search_terms\": [\"string\"]\n\
}}"
    )
}

fn codebase_scout_fallback_prompt(target: &str, question: &str) -> String {
    format!(
        "Codebase scout fallback.\n\
Target path: {target}\n\
Question: {question}\n\n\
Investigate directly using only tools explicitly available in the runtime.\n\
Do not delegate and do not guess tool names.\n\
Output must be exactly one JSON object.\n\
Return JSON only:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"top_hits\": [{{\"path\": \"string\", \"symbol\": \"string|null\", \"reason\": \"string\"}}],\n\
  \"findings\": [\"string\"],\n\
  \"next_steps\": [\"string\"]\n\
}}"
    )
}

fn codebase_investigator_prompt(target: &str, objective: &str) -> String {
    format!(
        "You are running a deep code investigation.\n\n\
Target path: {target}\n\
Objective: {objective}\n\n\
Execution strategy:\n\
1. Investigate directly using only tools explicitly available in the runtime.\n\
2. Prefer direct file/search/read tools over delegation loops.\n\
3. Include architecture impact and concrete change locations.\n\n\
Hard rules:\n\
- Use only evidence from files under the target path.\n\
- Do not invent files, symbols, behavior, or outcomes.\n\
- If target files are inaccessible, set status to NO_ACCESS.\n\
- Do not guess tool names or call tools that are not explicitly available.\n\
- Keep output concise, technical, and implementation-oriented.\n\
    - Do not emit scratchpads, XML, markdown, or explanatory preamble.\n\
    - Output must be a single JSON object only.\n\
    - Do not repeat the objective or target path in the response payload.\n\n\
Return JSON only with this schema:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"summary\": \"string\",\n\
  \"relevant_locations\": [\n\
    {{\"path\": \"string\", \"reason\": \"string\", \"key_symbols\": [\"string\"]}}\n\
  ],\n\
  \"impact_map\": [\"string\"],\n\
  \"action_plan\": [\"string\"],\n\
  \"evidence_gaps\": [\"string\"]\n\
}}"
    )
}

fn codebase_investigator_fallback_prompt(target: &str, objective: &str) -> String {
    format!(
        "Codebase investigator fallback.\n\
Target path: {target}\n\
Objective: {objective}\n\n\
Investigate directly using only tools explicitly available in the runtime.\n\
Do not delegate and do not guess tool names.\n\
Output must be exactly one JSON object.\n\
Return JSON only:\n\
{{\n\
  \"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\",\n\
  \"summary\": \"string\",\n\
  \"relevant_locations\": [{{\"path\": \"string\", \"reason\": \"string\", \"key_symbols\": [\"string\"]}}],\n\
  \"action_plan\": [\"string\"]\n\
}}"
    )
}

fn apply_ask_explain_mode_prompt(prompt: String, explain: bool) -> String {
    if !explain {
        return prompt;
    }
    format!(
        "{prompt}\n\n---\n\
Transparency mode is enabled for this response.\n\
After your main answer, add a concise section titled `Reasoning Summary` with:\n\
- key evidence considered\n\
- assumptions or uncertainties\n\
- why the recommendation follows from that evidence\n\
Do not expose hidden chain-of-thought or exhaustive internal reasoning."
    )
}

const MOBILE_PROVIDER_EVIDENCE_QUERY_PACK_ID: &str = "mobile_provider_evidence_v1";
const DEFAULT_MOBILE_EVIDENCE_PROVIDERS: [&str; 4] = ["Dodo", "Optus", "Moose", "ALDI"];

fn sql_string_literal(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "''"))
}

fn sql_text_array_literal(values: &[String]) -> String {
    let entries = values
        .iter()
        .map(|value| sql_string_literal(value))
        .collect::<Vec<_>>();
    format!("ARRAY[{}]", entries.join(", "))
}

fn mobile_provider_like_patterns(providers: &[String]) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut seen = HashSet::new();
    for provider in providers {
        let trimmed = provider.trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidates = [
            format!("%{}%", trimmed),
            format!("%{} mobile%", trimmed),
            format!("%{} nbn%", trimmed),
        ];
        for candidate in candidates {
            let key = candidate.to_ascii_lowercase();
            if seen.insert(key) {
                patterns.push(candidate);
            }
        }
    }
    patterns
}

fn mobile_provider_evidence_prompt(providers: &[String]) -> String {
    let patterns = mobile_provider_like_patterns(providers);
    let provider_pattern_array = sql_text_array_literal(&patterns);
    let providers_json = serde_json::to_string(providers).unwrap_or_else(|_| "[]".to_string());
    format!(
        "You are a compact evidence bundler for mobile extraction investigations.\n\n\
Query pack id: {pack_id}\n\
Use Postgres MCP tool `execute_sql` only.\n\
Run the bounded queries below exactly and do not run exploratory or unbounded queries.\n\
Provider patterns (for ILIKE ANY): {provider_pattern_array}\n\n\
Q1 max_dates:\n\
SELECT 'provider_week_ci' AS table_name, MAX(week)::text AS max_date FROM public.provider_week_ci\n\
UNION ALL\n\
SELECT 'provider_month_ci' AS table_name, MAX(month)::text AS max_date FROM public.provider_month_ci\n\
UNION ALL\n\
SELECT 'offer_history' AS table_name, MAX(snapshot_date)::text AS max_date FROM public.offer_history\n\
UNION ALL\n\
SELECT 'offer_snapshots' AS table_name, MAX(snapshot_date)::text AS max_date FROM public.offer_snapshots;\n\n\
Q2 offer_history_current_counts:\n\
SELECT provider, COUNT(*) AS row_count\n\
FROM public.offer_history\n\
WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM public.offer_history)\n\
  AND provider ILIKE ANY ({provider_pattern_array})\n\
GROUP BY provider\n\
ORDER BY row_count DESC\n\
LIMIT 50;\n\n\
Q3 offer_snapshots_current_counts:\n\
SELECT provider, COUNT(*) AS row_count\n\
FROM public.offer_snapshots\n\
WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM public.offer_snapshots)\n\
  AND provider ILIKE ANY ({provider_pattern_array})\n\
GROUP BY provider\n\
ORDER BY row_count DESC\n\
LIMIT 50;\n\n\
Q4 offer_history_last_seen:\n\
SELECT provider, MAX(snapshot_date)::text AS last_seen, COUNT(*) AS total_rows\n\
FROM public.offer_history\n\
WHERE provider ILIKE ANY ({provider_pattern_array})\n\
GROUP BY provider\n\
ORDER BY last_seen DESC, total_rows DESC\n\
LIMIT 50;\n\n\
Q5 provider_week_ci_current_counts:\n\
SELECT provider, COUNT(*) AS row_count\n\
FROM public.provider_week_ci\n\
WHERE week = (SELECT MAX(week) FROM public.provider_week_ci)\n\
  AND provider ILIKE ANY ({provider_pattern_array})\n\
GROUP BY provider\n\
ORDER BY row_count DESC\n\
LIMIT 50;\n\n\
Q6 provider_month_ci_current_counts:\n\
SELECT provider, COUNT(*) AS row_count\n\
FROM public.provider_month_ci\n\
WHERE month = (SELECT MAX(month) FROM public.provider_month_ci)\n\
  AND provider ILIKE ANY ({provider_pattern_array})\n\
GROUP BY provider\n\
ORDER BY row_count DESC\n\
LIMIT 50;\n\n\
Rules:\n\
- Do not run `SELECT *`.\n\
- Keep all queries bounded and aggregate-oriented.\n\
- If any query fails, keep going and report the failure in `gaps` with query id + error.\n\
- Output exactly one JSON object; no markdown and no prose.\n\n\
Return JSON only:\n\
{{\n\
  \"status\": \"OK|INSUFFICIENT_CONTEXT|NO_ACCESS\",\n\
  \"query_pack\": \"{pack_id}\",\n\
  \"providers\": {providers_json},\n\
  \"table_max_dates\": [{{\"table\": \"string\", \"max_date\": \"string|null\"}}],\n\
  \"evidence\": {{\n\
    \"offer_history_current_counts\": [{{\"provider\": \"string\", \"row_count\": 0}}],\n\
    \"offer_snapshots_current_counts\": [{{\"provider\": \"string\", \"row_count\": 0}}],\n\
    \"offer_history_last_seen\": [{{\"provider\": \"string\", \"last_seen\": \"string|null\", \"total_rows\": 0}}],\n\
    \"provider_week_ci_current_counts\": [{{\"provider\": \"string\", \"row_count\": 0}}],\n\
    \"provider_month_ci_current_counts\": [{{\"provider\": \"string\", \"row_count\": 0}}]\n\
  }},\n\
  \"sql_citations\": [{{\"id\": \"Q1|Q2|Q3|Q4|Q5|Q6\", \"sql\": \"string\", \"why\": \"string\"}}],\n\
  \"actionable_outcome\": [\"string\"],\n\
  \"gaps\": [\"string\"]\n\
}}",
        pack_id = MOBILE_PROVIDER_EVIDENCE_QUERY_PACK_ID,
    )
}

static INVOCATION_COUNTER: AtomicU64 = AtomicU64::new(1);
static SESSION_PROBE_SNAPSHOT_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);
const SESSION_PROBE_CACHED_429_RESET_LIMIT: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct FanoutGeminiInvocationObserver {
    observers: Vec<Arc<dyn GeminiInvocationObserver>>,
}

impl GeminiInvocationObserver for FanoutGeminiInvocationObserver {
    fn on_event(&self, event: GeminiInvocationEvent) {
        for observer in &self.observers {
            observer.on_event(event.clone());
        }
    }
}

#[derive(Debug, Clone)]
struct ToolInvocationContext {
    metadata: GeminiInvocationMetadata,
}

impl ToolInvocationContext {
    fn new(
        tool_name: &str,
        model_requested: Option<String>,
        model_used: Option<String>,
        resume_selector: Option<String>,
        resume_strategy: Option<String>,
        resume_requested: bool,
        sandbox: bool,
        parts: &Parts,
    ) -> Self {
        let actor = auth_context_from_parts(parts)
            .map(|auth| auth.actor)
            .unwrap_or_else(|| "local".to_string());
        let session_id = parts
            .headers
            .get(HEADER_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let request_id = parts
            .headers
            .get("x-mcp-jsonrpc-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        let sequence = INVOCATION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let invocation_id = format!("gmi-{}-{}", current_unix_timestamp_ms(), sequence);
        Self {
            metadata: GeminiInvocationMetadata {
                invocation_id,
                tool_name: tool_name.to_string(),
                actor,
                session_id,
                request_id,
                model_requested,
                model_used,
                resume_requested,
                resume_selector,
                resume_strategy,
                effective_scope_roots: Vec::new(),
                nested_mcp_policy: "__none__".to_string(),
                sandbox,
            },
        }
    }

    fn set_request_policy(
        &mut self,
        effective_scope_roots: &[String],
        nested_mcp_policy: Option<&AllowedMcpServers>,
    ) {
        self.metadata.effective_scope_roots =
            normalized_scope_roots_for_metadata(effective_scope_roots);
        self.metadata.nested_mcp_policy = nested_mcp_policy_label(nested_mcp_policy);
    }
}

struct ChunkObserver {
    observer: Arc<dyn GeminiInvocationObserver>,
    invocation: ToolInvocationContext,
    attempt: u32,
    retry_count: Arc<AtomicU64>,
}

impl GeminiOutputObserver for ChunkObserver {
    fn on_chunk(&self, stream: GeminiOutputStream, chunk_text: &str) {
        self.observer.on_event(GeminiInvocationEvent::new(
            self.invocation.metadata.clone(),
            GeminiInvocationEventKind::Chunk {
                attempt: self.attempt,
                stream,
                text: chunk_text.to_string(),
            },
        ));
    }

    fn on_retry_scheduled(&self, next_attempt: u32, reason: &str, delay: std::time::Duration) {
        self.retry_count.fetch_add(1, Ordering::Relaxed);
        self.observer.on_event(GeminiInvocationEvent::new(
            self.invocation.metadata.clone(),
            GeminiInvocationEventKind::RetryScheduled {
                next_attempt,
                reason: reason.to_string(),
                delay_ms: delay.as_millis().min(u128::from(u64::MAX)) as u64,
            },
        ));
    }

    fn on_phase(&self, attempt: u32, phase: GeminiExecutionPhase, pid: Option<u32>) {
        let phase = match phase {
            GeminiExecutionPhase::ToolCallStarted => GeminiInvocationPhase::ToolCallStarted,
            GeminiExecutionPhase::Spawned => GeminiInvocationPhase::Spawned,
            GeminiExecutionPhase::WaitingForOutput => GeminiInvocationPhase::WaitingForOutput,
            GeminiExecutionPhase::ToolCallFinished => GeminiInvocationPhase::ToolCallFinished,
            GeminiExecutionPhase::Completed => GeminiInvocationPhase::Completed,
        };
        self.observer.on_event(GeminiInvocationEvent::new(
            self.invocation.metadata.clone(),
            GeminiInvocationEventKind::Phase {
                attempt,
                phase,
                pid,
            },
        ));
    }

    fn on_heartbeat(&self, snapshot: GeminiHeartbeatSnapshot) {
        self.observer.on_event(GeminiInvocationEvent::new(
            self.invocation.metadata.clone(),
            GeminiInvocationEventKind::Heartbeat {
                attempt: snapshot.attempt,
                pid: snapshot.pid,
                elapsed_ms: snapshot.elapsed_ms,
                stdout_bytes: snapshot.stdout_bytes,
                stderr_bytes: snapshot.stderr_bytes,
                last_output_age_ms: snapshot.last_output_age_ms,
                stalled: snapshot.stalled,
            },
        ));
    }
}

/// Summary: reusable MCP server implementation that exposes Gemini tools.
///
/// # Errors
/// * Tool-level errors are surfaced as structured responses.
///
/// # Security
/// * Uses execution policy from [`GeminiExecutionConfig`] for every call.
///
/// # Panics
/// * Does not panic.
#[derive(Clone)]
pub struct GeminiMcp {
    config: Arc<GeminiExecutionConfig>,
    resume_provider: Arc<dyn ConversationResumeProvider>,
    invocation_observer: Arc<dyn GeminiInvocationObserver>,
    async_registry: Arc<GeminiAsyncInvocationRegistry>,
    usage_ledger: Arc<TokenUsageLedger>,
    response_debug_artifact: Arc<ResponseEnvelopeDebugArtifact>,
    session_probe_snapshot: Arc<SessionProbeSnapshotArtifact>,
    tool_router: ToolRouter<GeminiMcp>,
}

#[derive(Debug, Serialize)]
struct ValidationIssue {
    field: String,
    code: String,
    expected_type: String,
    received_type: String,
    corrective_hint: String,
}

#[derive(Debug, Clone)]
struct ResolvedModel {
    requested: Option<String>,
    used: Option<String>,
    default_model_applied: bool,
    fallback_mode: &'static str,
    fallback_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCategory {
    InputValidation,
    ResumeUnavailable,
    ModelNotAllowed,
    ModelNotFound,
    AuthSessionInvalid,
    FileAccess,
    QuotaOrRateLimit,
    ToolRegistryMismatch,
    ToolRuntime,
    ExecutionTimeout,
    NetworkOrTransport,
    ResponseContract,
}

impl ErrorCategory {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InputValidation => "input_validation",
            Self::ResumeUnavailable => "resume_unavailable",
            Self::ModelNotAllowed => "model_not_allowed",
            Self::ModelNotFound => "model_not_found",
            Self::AuthSessionInvalid => "auth_session_invalid",
            Self::FileAccess => "file_access",
            Self::QuotaOrRateLimit => "quota_or_rate_limit",
            Self::ToolRegistryMismatch => "tool_registry_mismatch",
            Self::ToolRuntime => "tool_runtime",
            Self::ExecutionTimeout => "execution_timeout",
            Self::NetworkOrTransport => "network_or_transport",
            Self::ResponseContract => "response_contract",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "input_validation" => Some(Self::InputValidation),
            "resume_unavailable" => Some(Self::ResumeUnavailable),
            "model_not_allowed" => Some(Self::ModelNotAllowed),
            "model_not_found" => Some(Self::ModelNotFound),
            "auth_session_invalid" => Some(Self::AuthSessionInvalid),
            "file_access" => Some(Self::FileAccess),
            "quota_or_rate_limit" => Some(Self::QuotaOrRateLimit),
            "tool_registry_mismatch" => Some(Self::ToolRegistryMismatch),
            "tool_runtime" => Some(Self::ToolRuntime),
            "execution_timeout" => Some(Self::ExecutionTimeout),
            "network_or_transport" => Some(Self::NetworkOrTransport),
            "response_contract" => Some(Self::ResponseContract),
            _ => None,
        }
    }

    fn retryability(self) -> &'static str {
        match self {
            Self::QuotaOrRateLimit | Self::ExecutionTimeout | Self::NetworkOrTransport => {
                "after_backoff"
            }
            Self::InputValidation
            | Self::ResumeUnavailable
            | Self::ModelNotAllowed
            | Self::ModelNotFound
            | Self::AuthSessionInvalid
            | Self::FileAccess
            | Self::ToolRegistryMismatch
            | Self::ToolRuntime
            | Self::ResponseContract => "after_fix",
        }
    }

    fn salvageability(self) -> &'static str {
        match self {
            Self::ResumeUnavailable | Self::ExecutionTimeout | Self::NetworkOrTransport => {
                "fresh_session"
            }
            Self::QuotaOrRateLimit => "model_downgrade",
            Self::ResponseContract => "schema_retry",
            Self::InputValidation
            | Self::ModelNotAllowed
            | Self::ModelNotFound
            | Self::AuthSessionInvalid
            | Self::FileAccess
            | Self::ToolRegistryMismatch
            | Self::ToolRuntime => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeOutcome {
    Applied,
    MissingFallback,
    Invalid,
    MissingFallbackFailed,
}

impl ResumeOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::MissingFallback => "missing_fallback",
            Self::Invalid => "invalid",
            Self::MissingFallbackFailed => "missing_fallback_failed",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::Applied => 1,
            Self::MissingFallback => 2,
            Self::Invalid => 3,
            Self::MissingFallbackFailed => 4,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ResumeLedgerState {
    requested: bool,
    selector: Option<String>,
    strategy: Option<String>,
    applied: bool,
    outcome: Option<ResumeOutcome>,
}

impl ResumeLedgerState {
    fn from_request(resume_selector: Option<String>, strategy: ResumeStrategy) -> Self {
        let requested = resume_selector.is_some();
        Self {
            requested,
            selector: resume_selector,
            strategy: requested.then(|| strategy.as_str().to_string()),
            applied: false,
            outcome: None,
        }
    }

    fn from_plan(plan: &ResumeExecutionPlan) -> Self {
        Self {
            requested: plan.requested,
            selector: plan.selector.clone(),
            strategy: plan.requested.then(|| plan.strategy.as_str().to_string()),
            applied: false,
            outcome: None,
        }
    }

    fn mark_applied(&mut self) {
        self.applied = true;
        self.set_outcome(ResumeOutcome::Applied);
    }

    fn mark_missing_fallback(&mut self) {
        self.set_outcome(ResumeOutcome::MissingFallback);
    }

    fn mark_invalid(&mut self) {
        self.set_outcome(ResumeOutcome::Invalid);
    }

    fn mark_missing_fallback_failed(&mut self) {
        self.set_outcome(ResumeOutcome::MissingFallbackFailed);
    }

    fn set_outcome(&mut self, outcome: ResumeOutcome) {
        let replace = self
            .outcome
            .map(|current| outcome.priority() >= current.priority())
            .unwrap_or(true);
        if replace {
            self.outcome = Some(outcome);
        }
    }

    fn outcome_label(&self) -> Option<String> {
        self.outcome.map(|outcome| outcome.as_str().to_string())
    }

    fn is_resume_unavailable(&self) -> bool {
        matches!(self.outcome, Some(ResumeOutcome::Invalid))
    }
}

#[derive(Debug, Clone, Default, Serialize)]
struct TokenUsageSummary {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
}

impl TokenUsageSummary {
    fn add_assign(&mut self, other: &Self) {
        self.input_tokens = sum_optional_tokens(self.input_tokens, other.input_tokens);
        self.output_tokens = sum_optional_tokens(self.output_tokens, other.output_tokens);
        self.total_tokens = sum_optional_tokens(self.total_tokens, other.total_tokens);
        self.reasoning_tokens = sum_optional_tokens(self.reasoning_tokens, other.reasoning_tokens);
        self.cache_read_tokens =
            sum_optional_tokens(self.cache_read_tokens, other.cache_read_tokens);
        self.cache_write_tokens =
            sum_optional_tokens(self.cache_write_tokens, other.cache_write_tokens);
    }

    fn normalize_totals(&mut self) {
        if self.total_tokens.is_none() {
            if let (Some(input), Some(output)) = (self.input_tokens, self.output_tokens) {
                self.total_tokens = Some(input.saturating_add(output));
            }
        }
    }

    fn score(&self) -> usize {
        let mut score = 0usize;
        if self.total_tokens.is_some() {
            score += 8;
        }
        if self.input_tokens.is_some() {
            score += 4;
        }
        if self.output_tokens.is_some() {
            score += 4;
        }
        if self.reasoning_tokens.is_some() {
            score += 2;
        }
        if self.cache_read_tokens.is_some() {
            score += 1;
        }
        if self.cache_write_tokens.is_some() {
            score += 1;
        }
        score
    }
}

fn sum_optional_tokens(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(lhs), Some(rhs)) => Some(lhs.saturating_add(rhs)),
        (Some(lhs), None) => Some(lhs),
        (None, Some(rhs)) => Some(rhs),
        (None, None) => None,
    }
}

#[derive(Debug, Clone)]
struct TokenUsageExtraction {
    usage: TokenUsageSummary,
    source: String,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ContextWindowSnapshot {
    percent_used: Option<f64>,
    percent_remaining: Option<f64>,
    source: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct AskGeminiGuardrailMetrics {
    drift_detected: u32,
    drift_repaired: u32,
    drift_failed: u32,
    invalid_table_refs: u32,
    citation_missing: u32,
}

impl AskGeminiGuardrailMetrics {
    fn record_drift(&mut self, drift: &AskGeminiContractDrift) {
        self.drift_detected = self.drift_detected.saturating_add(1);
        self.invalid_table_refs = self
            .invalid_table_refs
            .saturating_add(drift.invalid_table_refs);
        self.citation_missing = self.citation_missing.saturating_add(drift.citation_missing);
    }
}

#[derive(Debug, Clone, Default)]
struct ToolCallUsageAccumulator {
    gemini_invocations: u32,
    usage: TokenUsageSummary,
    sources: Vec<String>,
    context_window: Option<ContextWindowSnapshot>,
    guardrail_metrics: AskGeminiGuardrailMetrics,
}

impl ToolCallUsageAccumulator {
    fn record_output(&mut self, stdout: &str, stderr: &str, gemini_invocations: u64) {
        self.gemini_invocations = self
            .gemini_invocations
            .saturating_add(saturating_u64_to_u32(gemini_invocations));
        if let Some(extracted) = extract_token_usage(stdout, stderr) {
            self.usage.add_assign(&extracted.usage);
            self.sources.push(extracted.source);
        }
        if let Some(extracted) = extract_context_window_snapshot(stdout, stderr) {
            self.context_window = Some(extracted);
        }
    }

    fn record_error(&mut self, error: &GeminiExecutionError, gemini_invocations: u64) {
        self.gemini_invocations = self
            .gemini_invocations
            .saturating_add(saturating_u64_to_u32(gemini_invocations));
        if let GeminiExecutionError::FailedExit { stderr, .. } = error {
            if let Some(extracted) = extract_token_usage("", stderr) {
                self.usage.add_assign(&extracted.usage);
                self.sources.push(extracted.source);
            }
            if let Some(extracted) = extract_context_window_snapshot("", stderr) {
                self.context_window = Some(extracted);
            }
        }
    }

    fn usage_source(&self) -> Option<String> {
        if self.sources.is_empty() {
            return None;
        }
        let mut unique = Vec::<String>::new();
        for source in &self.sources {
            if !unique.iter().any(|existing| existing == source) {
                unique.push(source.clone());
            }
        }
        Some(unique.join(","))
    }

    fn context_window(&self) -> Option<&ContextWindowSnapshot> {
        self.context_window.as_ref()
    }
}

fn saturating_u64_to_u32(value: u64) -> u32 {
    value.min(u64::from(u32::MAX)) as u32
}

fn retry_count_from_invocations(gemini_invocations: u32) -> u32 {
    gemini_invocations.saturating_sub(1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionCompressionMode {
    Auto,
    Forced,
    Disabled,
}

impl SessionCompressionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Forced => "forced",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionCompressionDecisionSource {
    ServerDefault,
    ToolOverride,
}

impl SessionCompressionDecisionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ServerDefault => "server_default",
            Self::ToolOverride => "tool_override",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ContextGuardrailResult {
    mode: String,
    warned: bool,
    threshold_percent: u64,
    percent_used: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct ToolUsageLedgerRecord {
    version: u8,
    timestamp_ms: u64,
    tool_name: String,
    invocation_id: String,
    resolved_session_id: Option<String>,
    ok: bool,
    error_category: Option<String>,
    failure_class: Option<String>,
    retryability: Option<String>,
    salvageability: Option<String>,
    result_source: String,
    degraded: bool,
    stale_age_ms: Option<u64>,
    live_error_category: Option<String>,
    duration_ms: u64,
    gemini_invocations: u32,
    retry_count: u32,
    model_requested: Option<String>,
    model_used: Option<String>,
    resume_requested: bool,
    resume_selector: Option<String>,
    resume_strategy: Option<String>,
    resume_applied: bool,
    resume_outcome: Option<String>,
    default_model_applied: bool,
    fallback_mode: String,
    fallback_reason: Option<String>,
    effective_scope_roots: Vec<String>,
    nested_mcp_policy: String,
    usage_source: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    context_window_percent_used: Option<f64>,
    context_window_percent_remaining: Option<f64>,
    context_window_source: Option<String>,
    session_compression_mode: Option<String>,
    session_compression_attempted: bool,
    session_compression_ok: Option<bool>,
    session_compression_skipped_reason: Option<String>,
    context_guardrail_warned: bool,
    context_guardrail_threshold_percent: Option<u64>,
    drift_detected: u32,
    drift_repaired: u32,
    drift_failed: u32,
    invalid_table_refs: u32,
    citation_missing: u32,
}

#[derive(Debug, Clone)]
struct InvocationResultMetadata {
    result_source: String,
    degraded: bool,
    stale_age_ms: Option<u64>,
    live_error_category: Option<String>,
}

impl Default for InvocationResultMetadata {
    fn default() -> Self {
        Self {
            result_source: "live".to_string(),
            degraded: false,
            stale_age_ms: None,
            live_error_category: None,
        }
    }
}

impl InvocationResultMetadata {
    fn session_probe_source(source: &str, degraded: bool) -> Self {
        Self {
            result_source: source.to_string(),
            degraded,
            ..Self::default()
        }
    }

    fn cached_recent_probe(stale_age_ms: u64, live_error_category: &str) -> Self {
        Self {
            result_source: "cached_recent_probe".to_string(),
            degraded: true,
            stale_age_ms: Some(stale_age_ms),
            live_error_category: Some(live_error_category.to_string()),
        }
    }
}

#[derive(Debug)]
struct TokenUsageLedger {
    path: Option<PathBuf>,
}

impl TokenUsageLedger {
    fn new(config: &GeminiExecutionConfig) -> Self {
        let path = config
            .usage_ledger_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Self { path }
    }

    fn record(&self, record: &ToolUsageLedgerRecord) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = create_dir_all(parent);
        }
        let Ok(line) = serde_json::to_string(record) else {
            return;
        };
        let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
            return;
        };
        let _ = file.write_all(line.as_bytes());
        let _ = file.write_all(b"\n");
        let _ = file.flush();
    }
}

fn reliability_metadata_from_error_label(
    error_label: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(error_label) = error_label else {
        return (None, None, None);
    };
    let Some(category) = ErrorCategory::from_str(error_label) else {
        return (Some(error_label.to_string()), None, None);
    };
    (
        Some(category.as_str().to_string()),
        Some(category.retryability().to_string()),
        Some(category.salvageability().to_string()),
    )
}

#[derive(Debug, Clone, Serialize)]
struct ResponseEnvelopeDebugRecord {
    version: u8,
    timestamp_ms: u64,
    invocation_id: Option<String>,
    tool_name: String,
    model_used: Option<String>,
    resume_requested: bool,
    resume_selector: Option<String>,
    resume_strategy: Option<String>,
    resume_outcome: Option<String>,
    response_envelope: Value,
}

#[derive(Debug)]
struct ResponseEnvelopeDebugArtifact {
    path: Option<PathBuf>,
}

impl ResponseEnvelopeDebugArtifact {
    fn new(config: &GeminiExecutionConfig) -> Self {
        let path = config
            .response_debug_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Self { path }
    }

    fn record(&self, record: &ResponseEnvelopeDebugRecord) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = create_dir_all(parent);
        }
        let Ok(line) = serde_json::to_string(record) else {
            return;
        };
        let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
            return;
        };
        let _ = file.write_all(line.as_bytes());
        let _ = file.write_all(b"\n");
        let _ = file.flush();
    }
}

#[derive(Debug)]
struct SessionProbeSnapshotArtifact {
    path: Option<PathBuf>,
}

impl SessionProbeSnapshotArtifact {
    fn new(config: &GeminiExecutionConfig) -> Self {
        let path = config
            .session_probe_snapshot_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| derived_session_probe_snapshot_path(config));
        Self { path }
    }

    fn record_success(
        &self,
        snapshot: &GeminiSessionProbeSnapshot,
        probe_execution: &GeminiSessionProbeExecutionSummary,
        source: &str,
        degraded: bool,
    ) -> Option<String> {
        if degraded {
            return None;
        }
        let Some(path) = self.path.as_ref() else {
            return None;
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = create_dir_all(parent) {
                return Some(session_probe_cache_io_warning(
                    path,
                    "create parent directory",
                    &error,
                ));
            }
        }
        let record = CachedSessionProbeSnapshot {
            version: 1,
            captured_at_ms: current_unix_timestamp_ms(),
            source: source.to_string(),
            session: snapshot.clone(),
            probe_execution: probe_execution.clone(),
        };
        let payload = match serde_json::to_vec_pretty(&record) {
            Ok(payload) => payload,
            Err(error) => {
                return Some(session_probe_cache_io_warning(
                    path,
                    "serialize snapshot",
                    &error,
                ));
            }
        };
        write_private_session_probe_snapshot(path, &payload)
            .err()
            .map(|error| session_probe_cache_io_warning(path, "persist snapshot", &error))
    }

    fn load_recent(
        &self,
        freshness_window: Duration,
    ) -> Result<Option<CachedSessionProbeHit>, String> {
        if freshness_window.is_zero() {
            return Ok(None);
        }
        let Some(path) = self.path.as_ref() else {
            return Ok(None);
        };
        let payload = match std::fs::read_to_string(path) {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(session_probe_cache_io_warning(
                    path,
                    "read snapshot",
                    &error,
                ));
            }
        };
        let snapshot: CachedSessionProbeSnapshot = serde_json::from_str(&payload)
            .map_err(|error| session_probe_cache_io_warning(path, "parse snapshot", &error))?;
        Ok(cached_session_probe_hit(
            snapshot,
            freshness_window,
            current_unix_timestamp_ms(),
        ))
    }
}

fn derived_session_probe_snapshot_path(config: &GeminiExecutionConfig) -> Option<PathBuf> {
    [
        config.usage_ledger_path.as_deref(),
        config.response_debug_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .find_map(|value| {
        let path = PathBuf::from(value);
        path.parent()
            .map(|parent| parent.join("session-probe.latest.json"))
    })
}

fn current_unix_timestamp_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(_) => 0,
    }
}

fn cached_session_probe_hit(
    snapshot: CachedSessionProbeSnapshot,
    freshness_window: Duration,
    now_ms: u64,
) -> Option<CachedSessionProbeHit> {
    let stale_age_ms = now_ms.saturating_sub(snapshot.captured_at_ms);
    let freshness_window_ms = freshness_window.as_millis().min(u128::from(u64::MAX)) as u64;
    if stale_age_ms > freshness_window_ms {
        return None;
    }
    Some(CachedSessionProbeHit {
        snapshot,
        stale_age_ms,
    })
}

fn refresh_cached_session_probe_hit(
    snapshot: &CachedSessionProbeSnapshot,
    freshness_window: Duration,
) -> Option<CachedSessionProbeHit> {
    cached_session_probe_hit(
        snapshot.clone(),
        freshness_window,
        current_unix_timestamp_ms(),
    )
}

fn next_session_probe_snapshot_tmp_path(path: &Path) -> PathBuf {
    let sequence = SESSION_PROBE_SNAPSHOT_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("session-probe.latest.json");
    let temp_name = format!(
        ".{name}.tmp-{}-{}-{sequence}",
        std::process::id(),
        current_unix_timestamp_ms()
    );
    match path.parent() {
        Some(parent) => parent.join(temp_name),
        None => PathBuf::from(temp_name),
    }
}

fn session_probe_cache_io_warning(
    path: &Path,
    action: &str,
    error: &dyn std::fmt::Display,
) -> String {
    format!(
        "Session probe cache could not {action} at {}: {error}",
        path.display()
    )
}

fn write_private_session_probe_snapshot(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    let tmp_path = next_session_probe_snapshot_tmp_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let write_result = (|| {
        let mut file = options.open(&tmp_path)?;
        file.write_all(payload)?;
        file.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
}

fn parse_reset_after_duration(stderr: &str) -> Option<Duration> {
    let lower = stderr.to_lowercase();
    let marker_index = [
        "quota will reset after",
        "your quota will reset after",
        "reset after",
    ]
    .iter()
    .find_map(|marker| lower.find(marker).map(|index| (index, marker.len())))?;
    let tail = &lower[marker_index.0 + marker_index.1..];
    let mut total_seconds = 0u64;
    let mut digits = String::new();
    let mut saw_component = false;

    for ch in tail.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        if ch.is_ascii_whitespace() {
            continue;
        }
        let Ok(value) = digits.parse::<u64>() else {
            break;
        };
        let unit_seconds = match ch {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => break,
        };
        saw_component = true;
        total_seconds = total_seconds.saturating_add(value.saturating_mul(unit_seconds));
        digits.clear();
    }

    saw_component.then(|| Duration::from_secs(total_seconds))
}

fn is_cache_eligible_session_probe_failure(
    error: &GeminiExecutionError,
    category: ErrorCategory,
) -> bool {
    if matches!(category, ErrorCategory::ExecutionTimeout) {
        return true;
    }
    if !matches!(category, ErrorCategory::QuotaOrRateLimit) {
        return false;
    }

    if let GeminiExecutionError::FailedExit { stderr, .. } = error {
        if parse_reset_after_duration(stderr)
            .map(|duration| duration <= SESSION_PROBE_CACHED_429_RESET_LIMIT)
            .unwrap_or(false)
        {
            return true;
        }
    }

    matches!(
        retryable_429_reason(error),
        Some("transient_model_capacity_429")
    )
}

fn session_probe_warning(source: &str) -> String {
    format!(
        "Gemini CLI no longer exposes supported `stats session` output in this path; returned lightweight {source} telemetry instead."
    )
}

fn cached_session_probe_warning(stale_age_ms: u64, live_error_category: &str) -> String {
    format!(
        "Live Gemini CLI session probe failed transiently with {live_error_category}; returned the last successful cached probe snapshot from {stale_age_ms}ms ago."
    )
}

fn validate_required_text_field(
    field: &str,
    value: &str,
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        errors.push(ValidationIssue {
            field: field.to_string(),
            code: "invalid_value".to_string(),
            expected_type: "non-empty string".to_string(),
            received_type: "string".to_string(),
            corrective_hint: format!("Set {field} to a non-empty string."),
        });
        None
    } else {
        Some(value.to_string())
    }
}

fn validate_target_within_include_directories(
    target: &str,
    include_directories: &[String],
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let target = validate_required_text_field("target", target, errors)?;
    let canonical_target = match std::fs::canonicalize(&target) {
        Ok(path) => path,
        Err(err) => {
            errors.push(ValidationIssue {
                field: "target".to_string(),
                code: "invalid_value".to_string(),
                expected_type: "existing path inside configured include directories".to_string(),
                received_type: "string".to_string(),
                corrective_hint: format!("Set target to an existing path. Details: {err}"),
            });
            return None;
        }
    };
    if !canonical_target.is_dir() {
        errors.push(ValidationIssue {
            field: "target".to_string(),
            code: "invalid_value".to_string(),
            expected_type: "existing directory path inside configured include directories"
                .to_string(),
            received_type: "file path".to_string(),
            corrective_hint: "Set target to an existing directory path.".to_string(),
        });
        return None;
    }

    let mut roots = Vec::<PathBuf>::new();
    let mut root_labels = Vec::<String>::new();
    for raw_root in include_directories {
        let root = raw_root.trim();
        if root.is_empty() {
            continue;
        }
        match std::fs::canonicalize(root) {
            Ok(path) if path.is_dir() => {
                root_labels.push(path.display().to_string());
                roots.push(path);
            }
            Ok(path) => {
                errors.push(ValidationIssue {
                    field: "target".to_string(),
                    code: "server_config_invalid".to_string(),
                    expected_type: "directory path".to_string(),
                    received_type: "file path".to_string(),
                    corrective_hint: format!(
                        "Configured include directory '{root}' resolves to '{}' which is not a directory.",
                        path.display()
                    ),
                });
                return None;
            }
            Err(err) => {
                errors.push(ValidationIssue {
                    field: "target".to_string(),
                    code: "server_config_invalid".to_string(),
                    expected_type: "existing include directory".to_string(),
                    received_type: "missing/unreadable path".to_string(),
                    corrective_hint: format!(
                        "Configured include directory '{root}' is invalid: {err}"
                    ),
                });
                return None;
            }
        }
    }

    if !roots.iter().any(|root| canonical_target.starts_with(root)) {
        errors.push(ValidationIssue {
            field: "target".to_string(),
            code: "out_of_scope".to_string(),
            expected_type: "path under configured include directories".to_string(),
            received_type: "string".to_string(),
            corrective_hint: format!("Set target under one of: {}.", root_labels.join(", ")),
        });
        return None;
    }

    Some(canonical_target.display().to_string())
}

fn resolve_scoped_ask_gemini_target(
    target: Option<&str>,
    inferred_cwd: Result<PathBuf, std::io::Error>,
    allowed_roots: &[String],
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let target_candidate = match target {
        Some(target) => target.to_string(),
        None => match inferred_cwd {
            Ok(path) => path.display().to_string(),
            Err(err) => {
                errors.push(ValidationIssue {
                    field: "target".to_string(),
                    code: "cwd_unavailable".to_string(),
                    expected_type:
                        "explicit target or current working directory under configured ask roots"
                            .to_string(),
                    received_type: "null".to_string(),
                    corrective_hint: format!(
                        "Pass target explicitly or start the server from a directory under configured ask roots. Details: {err}"
                    ),
                });
                return None;
            }
        },
    };

    validate_target_within_include_directories(&target_candidate, allowed_roots, errors)
}

fn normalize_optional_model_field(
    field: &str,
    value: Option<String>,
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let Some(raw) = value else {
        return None;
    };
    let value = raw.trim();
    if value.is_empty() {
        errors.push(ValidationIssue {
            field: field.to_string(),
            code: "invalid_value".to_string(),
            expected_type: "non-empty string".to_string(),
            received_type: "string".to_string(),
            corrective_hint: format!("Set {field} to a non-empty string or omit it."),
        });
        None
    } else {
        Some(value.to_string())
    }
}

fn normalize_optional_resume_selector(
    value: Option<String>,
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let Some(raw) = value else {
        return None;
    };
    let value = raw.trim();
    if value.is_empty() {
        errors.push(ValidationIssue {
            field: "resume".to_string(),
            code: "invalid_value".to_string(),
            expected_type: "non-empty string".to_string(),
            received_type: "string".to_string(),
            corrective_hint:
                "Set resume to an explicit Gemini session selector, or omit it for stateless execution."
                .to_string(),
        });
        None
    } else if value.eq_ignore_ascii_case("latest") {
        errors.push(ValidationIssue {
            field: "resume".to_string(),
            code: "invalid_value".to_string(),
            expected_type: "explicit Gemini session selector".to_string(),
            received_type: "string".to_string(),
            corrective_hint:
                "Set resume to a specific Gemini session id/selector instead of 'latest', or omit it for stateless execution."
                    .to_string(),
        });
        None
    } else if let Some(normalized) = normalize_resume_selector_for_cli(value) {
        Some(normalized)
    } else {
        Some(value.to_string())
    }
}

fn normalize_resume_selector_for_cli(raw: &str) -> Option<String> {
    let normalized = raw.trim().trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if normalized.is_empty() {
        None
    } else if let Some(suffix) = normalized.strip_prefix("session-") {
        if looks_like_uuid_session_id(suffix) {
            Some(suffix.to_string())
        } else {
            Some(normalized.to_string())
        }
    } else {
        Some(normalized.to_string())
    }
}

fn looks_like_session_number_selector(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit())
}

fn normalize_allowed_mcp_servers_override(
    value: Option<String>,
    errors: &mut Vec<ValidationIssue>,
) -> Option<AllowedMcpServers> {
    let Some(raw) = value else {
        return None;
    };
    let value = raw.trim();
    if value.is_empty() {
        errors.push(ValidationIssue {
            field: "allowed_mcp_server_names".to_string(),
            code: "invalid_value".to_string(),
            expected_type: "__none__, __all__, or comma-separated server names".to_string(),
            received_type: "string".to_string(),
            corrective_hint:
                "Set allowed_mcp_server_names to '__none__', '__all__', or names like 'postgres,ops'."
                    .to_string(),
        });
        return None;
    }

    match AllowedMcpServers::parse_csv(value) {
        Ok(parsed) => Some(parsed),
        Err(err) => {
            errors.push(ValidationIssue {
                field: "allowed_mcp_server_names".to_string(),
                code: "invalid_value".to_string(),
                expected_type: "__none__, __all__, or comma-separated server names".to_string(),
                received_type: "string".to_string(),
                corrective_hint: format!(
                    "Fix allowed_mcp_server_names. Use '__none__', '__all__', or names like 'postgres,ops'. Details: {err}"
                ),
            });
            None
        }
    }
}

fn default_to_no_nested_mcp_servers(value: Option<AllowedMcpServers>) -> Option<AllowedMcpServers> {
    value.or(Some(AllowedMcpServers::None))
}

fn normalized_scope_roots_for_metadata(scope_roots: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for scope_root in scope_roots {
        let trimmed = scope_root.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !normalized.iter().any(|existing| existing == trimmed) {
            normalized.push(trimmed.to_string());
        }
    }
    normalized
}

fn nested_mcp_policy_label(policy: Option<&AllowedMcpServers>) -> String {
    match policy {
        Some(AllowedMcpServers::None) | None => "__none__".to_string(),
        Some(AllowedMcpServers::All) => "__all__".to_string(),
        Some(AllowedMcpServers::Names(names)) => names.join(","),
    }
}

fn normalize_mobile_provider_field(
    value: Vec<String>,
    errors: &mut Vec<ValidationIssue>,
) -> Vec<String> {
    let mut providers = Vec::new();
    let mut seen = HashSet::new();
    let source = if value.is_empty() {
        DEFAULT_MOBILE_EVIDENCE_PROVIDERS
            .iter()
            .map(|provider| provider.to_string())
            .collect::<Vec<_>>()
    } else {
        value
    };

    for raw in source {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > 64 {
            errors.push(ValidationIssue {
                field: "providers".to_string(),
                code: "invalid_value".to_string(),
                expected_type: "provider names with at most 64 characters".to_string(),
                received_type: "string".to_string(),
                corrective_hint: format!(
                    "Shorten provider '{}'; provider names must be <= 64 characters.",
                    trimmed
                ),
            });
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            providers.push(trimmed.to_string());
        }
    }

    if providers.is_empty() {
        errors.push(ValidationIssue {
            field: "providers".to_string(),
            code: "invalid_value".to_string(),
            expected_type: "non-empty provider list".to_string(),
            received_type: "empty".to_string(),
            corrective_hint:
                "Set providers to at least one provider name, or omit it to use defaults."
                    .to_string(),
        });
    }

    providers
}

fn normalize_model_list(models: &[String]) -> Vec<String> {
    models
        .iter()
        .map(|model| model.trim().to_string())
        .filter(|model| !model.is_empty())
        .collect()
}

fn canonical_model_alias_key(model: &str) -> Option<String> {
    let mut normalized = model.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    if let Some(stripped) = normalized.strip_suffix("-preview") {
        normalized = stripped.to_string();
    } else if let Some(stripped) = normalized.strip_suffix("-latest") {
        normalized = stripped.to_string();
    }

    if let Some(stripped) = normalized.strip_suffix("-lite") {
        if stripped.ends_with("-flash") || stripped.ends_with("-pro") {
            normalized = stripped.to_string();
        }
    }

    Some(normalized)
}

fn find_allowlisted_model(allowlist: &[String], requested: &str) -> Option<String> {
    allowlist
        .iter()
        .find(|candidate| candidate.eq_ignore_ascii_case(requested))
        .cloned()
}

fn find_allowlisted_model_by_alias(allowlist: &[String], requested: &str) -> Option<String> {
    let requested_key = canonical_model_alias_key(requested)?;
    let mut matches = allowlist
        .iter()
        .filter_map(|candidate| {
            canonical_model_alias_key(candidate)
                .filter(|candidate_key| candidate_key == &requested_key)
                .map(|_| candidate.clone())
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

fn suggested_allowlisted_models(allowlist: &[String], requested: &str) -> Vec<String> {
    let Some(requested_key) = canonical_model_alias_key(requested) else {
        return Vec::new();
    };
    let mut suggestions = Vec::new();
    for candidate in allowlist {
        let Some(candidate_key) = canonical_model_alias_key(candidate) else {
            continue;
        };
        if candidate_key != requested_key {
            continue;
        }
        if suggestions
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(candidate))
        {
            continue;
        }
        suggestions.push(candidate.clone());
        if suggestions.len() >= 3 {
            break;
        }
    }
    suggestions
}

fn next_allowlisted_downgrade_model(allowlist: &[String], current_model: &str) -> Option<String> {
    let current = current_model.trim();
    if current.is_empty() {
        return allowlist.first().cloned();
    }

    if let Some(current_index) = allowlist
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(current))
    {
        return allowlist
            .iter()
            .skip(current_index.saturating_add(1))
            .find(|candidate| !candidate.eq_ignore_ascii_case(current))
            .cloned();
    }

    allowlist
        .iter()
        .find(|candidate| !candidate.eq_ignore_ascii_case(current))
        .cloned()
}

fn resolve_model(
    config: &GeminiExecutionConfig,
    requested: Option<String>,
) -> Result<ResolvedModel, ErrorCategory> {
    let normalized_requested = requested
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let allowlist = normalize_model_list(&config.model_allowlist);
    let allowlist_is_empty = allowlist.is_empty();

    let default_model = config.default_model.as_ref().and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    });

    if allowlist_is_empty {
        return if let Some(model) = normalized_requested {
            Ok(ResolvedModel {
                requested: Some(model.clone()),
                used: Some(model),
                default_model_applied: false,
                fallback_mode: "requested",
                fallback_reason: None,
            })
        } else if let Some(default_model) = default_model {
            Ok(ResolvedModel {
                requested: None,
                used: Some(default_model),
                default_model_applied: true,
                fallback_mode: "configured_default",
                fallback_reason: None,
            })
        } else {
            Ok(ResolvedModel {
                requested: None,
                used: None,
                default_model_applied: false,
                fallback_mode: "none",
                fallback_reason: None,
            })
        };
    }

    if let Some(requested) = normalized_requested.clone() {
        if let Some(allowlisted_model) = find_allowlisted_model(&allowlist, &requested) {
            return Ok(ResolvedModel {
                requested: Some(requested.clone()),
                used: Some(allowlisted_model),
                default_model_applied: false,
                fallback_mode: "requested",
                fallback_reason: None,
            });
        }
        if let Some(alias_model) = find_allowlisted_model_by_alias(&allowlist, &requested) {
            return Ok(ResolvedModel {
                requested: Some(requested.clone()),
                used: Some(alias_model.clone()),
                default_model_applied: false,
                fallback_mode: "requested_alias",
                fallback_reason: Some(format!(
                    "Requested model '{requested}' mapped to allowlisted alias '{alias_model}'."
                )),
            });
        }
        return Err(ErrorCategory::ModelNotAllowed);
    }

    if let Some(default_model) = default_model {
        if let Some(allowlisted_model) = find_allowlisted_model(&allowlist, &default_model) {
            return Ok(ResolvedModel {
                requested: None,
                used: Some(allowlisted_model),
                default_model_applied: true,
                fallback_mode: "configured_default",
                fallback_reason: None,
            });
        }
        let Some(fallback_model) = allowlist.first().cloned() else {
            return Err(ErrorCategory::ModelNotFound);
        };
        return Ok(ResolvedModel {
            requested: None,
            used: Some(fallback_model.clone()),
            default_model_applied: false,
            fallback_mode: "allowlist_default",
            fallback_reason: Some(format!(
                "Configured default model was not allowlisted; using '{fallback_model}'."
            )),
        });
    }

    let Some(fallback_model) = allowlist.first().cloned() else {
        return Err(ErrorCategory::ModelNotFound);
    };
    Ok(ResolvedModel {
        requested: None,
        used: Some(fallback_model.clone()),
        default_model_applied: false,
        fallback_mode: "allowlist_default",
        fallback_reason: Some("No model was provided; using first allowlist model.".to_string()),
    })
}

fn response_with_metadata(
    base: Value,
    validation_errors: &[ValidationIssue],
    model: &ResolvedModel,
) -> CallToolResult {
    let Value::Object(mut object) = base else {
        return CallToolResult::structured(base);
    };

    object.insert("validation_errors".to_string(), json!(validation_errors));
    object.insert("model_requested".to_string(), json!(model.requested));
    object.insert("model_used".to_string(), json!(model.used));
    object.insert(
        "default_model_applied".to_string(),
        json!(model.default_model_applied),
    );
    object.insert("fallback_mode".to_string(), json!(model.fallback_mode));
    object.insert("fallback_reason".to_string(), json!(model.fallback_reason));
    CallToolResult::structured(Value::Object(object))
}

fn context_window_metadata_json(snapshot: &ContextWindowSnapshot) -> Value {
    json!({
        "percent_used": snapshot.percent_used,
        "percent_remaining": snapshot.percent_remaining,
        "source": snapshot.source,
    })
}

fn attach_context_window_metadata(base: Value, snapshot: Option<&ContextWindowSnapshot>) -> Value {
    let Some(snapshot) = snapshot else {
        return base;
    };
    match base {
        Value::Object(mut object) => {
            object.insert(
                "context_window".to_string(),
                context_window_metadata_json(snapshot),
            );
            Value::Object(object)
        }
        non_object => non_object,
    }
}

fn attach_session_compression_metadata(
    base: Value,
    compression: Option<&SessionCompressionResult>,
) -> Value {
    let Some(compression) = compression else {
        return base;
    };
    match base {
        Value::Object(mut object) => {
            object.insert("session_compression".to_string(), json!(compression));
            Value::Object(object)
        }
        non_object => non_object,
    }
}

fn attach_context_guardrail_metadata(
    base: Value,
    guardrail: Option<&ContextGuardrailResult>,
) -> Value {
    let Some(guardrail) = guardrail else {
        return base;
    };
    match base {
        Value::Object(mut object) => {
            object.insert("context_guardrail".to_string(), json!(guardrail));
            Value::Object(object)
        }
        non_object => non_object,
    }
}

fn attach_runtime_metadata(
    base: Value,
    context_window: Option<&ContextWindowSnapshot>,
    compression: Option<&SessionCompressionResult>,
    guardrail: Option<&ContextGuardrailResult>,
) -> Value {
    attach_context_guardrail_metadata(
        attach_session_compression_metadata(
            attach_context_window_metadata(base, context_window),
            compression,
        ),
        guardrail,
    )
}

fn resume_context_mode_label(resume: &ResumeLedgerState) -> &'static str {
    if resume.applied {
        return "resumed";
    }

    if !resume.requested {
        return "fresh";
    }

    match resume.outcome {
        Some(ResumeOutcome::MissingFallback) => "fresh_fallback",
        Some(ResumeOutcome::Invalid) => "resume_unavailable",
        Some(ResumeOutcome::MissingFallbackFailed) => "resume_fallback_failed",
        Some(ResumeOutcome::Applied) => "resumed",
        None => "resume_requested",
    }
}

fn resume_metadata_json(resume: &ResumeLedgerState) -> Value {
    json!({
        "requested": resume.requested,
        "selector": resume.selector.clone(),
        "strategy": resume.strategy.clone(),
        "applied": resume.applied,
        "outcome": resume.outcome_label(),
        "context_mode": resume_context_mode_label(resume),
    })
}

fn resume_diagnostic_json(resume: &ResumeLedgerState) -> Option<Value> {
    let outcome = resume.outcome?;
    let selector = resume.selector.clone();
    let strategy = resume.strategy.clone();
    let context_mode = resume_context_mode_label(resume);
    match outcome {
        ResumeOutcome::Applied => None,
        ResumeOutcome::MissingFallback => Some(json!({
            "severity": "warning",
            "code": "resume_unavailable_fresh_fallback",
            "message": "Requested resume selector was unavailable; the tool continued in a fresh session.",
            "corrective_hint": "Use `resume_strategy=require` to fail fast, or capture `resolved_session_id` from this response before the next follow-up call.",
            "requested_selector": selector,
            "strategy": strategy,
            "context_mode": context_mode,
        })),
        ResumeOutcome::Invalid => Some(json!({
            "severity": "error",
            "code": "resume_unavailable",
            "message": "Requested resume selector was unavailable and the call did not fall back to a fresh session.",
            "corrective_hint": "Retry without `resume`, provide a valid session selector, or use `resume_strategy=fresh_if_missing` if a fresh run is acceptable.",
            "requested_selector": selector,
            "strategy": strategy,
            "context_mode": context_mode,
        })),
        ResumeOutcome::MissingFallbackFailed => Some(json!({
            "severity": "error",
            "code": "resume_fallback_failed",
            "message": "Requested resume selector was unavailable and the follow-up fresh-session fallback also failed.",
            "corrective_hint": "Inspect the execution error and retry without `resume` only after confirming the selector is stale.",
            "requested_selector": selector,
            "strategy": strategy,
            "context_mode": context_mode,
        })),
    }
}

fn attach_resume_metadata(base: Value, resume: &ResumeLedgerState) -> Value {
    match base {
        Value::Object(mut object) => {
            object.insert("resume".to_string(), resume_metadata_json(resume));
            if let Some(diagnostic) = resume_diagnostic_json(resume) {
                object.insert("resume_diagnostic".to_string(), diagnostic);
            }
            Value::Object(object)
        }
        non_object => non_object,
    }
}

fn attach_resolved_session_id(base: Value, resolved_session_id: Option<&str>) -> Value {
    match base {
        Value::Object(mut object) => {
            object.insert(
                "resolved_session_id".to_string(),
                json!(resolved_session_id),
            );
            Value::Object(object)
        }
        non_object => non_object,
    }
}

fn attach_ask_explain_requested(base: Value, explain_requested: bool) -> Value {
    match base {
        Value::Object(mut object) => {
            object.insert(
                "explain_mode_requested".to_string(),
                json!(explain_requested),
            );
            Value::Object(object)
        }
        non_object => non_object,
    }
}

fn ask_gemini_payload(
    base: Value,
    explain_requested: bool,
    resolved_session_id: Option<&str>,
) -> Value {
    attach_ask_explain_requested(
        attach_resolved_session_id(base, resolved_session_id),
        explain_requested,
    )
}

fn normalize_session_id_candidate(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn looks_like_uuid_session_id(value: &str) -> bool {
    if value.eq_ignore_ascii_case("latest") {
        return false;
    }
    if value.len() < 32 || value.len() > 64 {
        return false;
    }
    let mut hyphen_count = 0usize;
    for ch in value.chars() {
        if ch == '-' {
            hyphen_count += 1;
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    hyphen_count >= 4
}

fn extract_session_id_from_json_object(object: &serde_json::Map<String, Value>) -> Option<String> {
    for key in ["session_id", "sessionId"] {
        if let Some(session_id) = object
            .get(key)
            .and_then(Value::as_str)
            .and_then(normalize_session_id_candidate)
        {
            return Some(session_id);
        }
    }

    object
        .get("session")
        .and_then(Value::as_object)
        .and_then(|session| {
            for key in ["id", "session_id", "sessionId"] {
                if let Some(session_id) = session
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(normalize_session_id_candidate)
                {
                    return Some(session_id);
                }
            }
            None
        })
}

fn find_session_id_in_json_value(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) => extract_session_id_from_json_object(object),
        Value::Array(values) => values.iter().find_map(|entry| match entry {
            Value::Object(object) => extract_session_id_from_json_object(object),
            _ => None,
        }),
        _ => None,
    }
}

fn extract_session_id_from_json_text(raw: &str) -> Option<String> {
    parse_json_response(raw).and_then(|value| find_session_id_in_json_value(&value))
}

fn extract_session_id_from_text(raw: &str) -> Option<String> {
    for raw_line in raw.lines() {
        let line = cleaned_stats_session_line(raw_line);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = text_after_case_insensitive_marker(&line, "session id:") {
            if let Some(candidate) = normalize_session_id_candidate(rest) {
                return Some(candidate);
            }
        }
    }
    None
}

fn fallback_session_id_from_resume_plan(
    resume_plan: &ResumeExecutionPlan,
    resume_state: &ResumeLedgerState,
) -> Option<String> {
    if !resume_state.applied {
        return None;
    }
    let selector = resume_plan.selector.as_deref()?.trim();
    let selector = normalize_resume_selector_for_cli(selector)?;
    if looks_like_uuid_session_id(&selector) || looks_like_session_number_selector(&selector) {
        Some(selector)
    } else {
        None
    }
}

fn resolve_session_id_from_gemini_output(
    output: &GeminiResponse,
    resume_plan: &ResumeExecutionPlan,
    resume_state: &ResumeLedgerState,
) -> Option<String> {
    extract_session_id_from_json_text(&output.stdout)
        .or_else(|| extract_session_id_from_json_text(&output.stderr))
        .or_else(|| extract_session_id_from_text(&output.stdout))
        .or_else(|| extract_session_id_from_text(&output.stderr))
        .or_else(|| fallback_session_id_from_resume_plan(resume_plan, resume_state))
}

fn resolve_session_id_from_gemini_error(
    error: &GeminiExecutionError,
    resume_plan: &ResumeExecutionPlan,
    resume_state: &ResumeLedgerState,
) -> Option<String> {
    if let GeminiExecutionError::FailedExit { stderr, .. } = error {
        extract_session_id_from_json_text(stderr)
            .or_else(|| extract_session_id_from_text(stderr))
            .or_else(|| fallback_session_id_from_resume_plan(resume_plan, resume_state))
    } else {
        fallback_session_id_from_resume_plan(resume_plan, resume_state)
    }
}

fn response_with_metadata_and_resume(
    base: Value,
    validation_errors: &[ValidationIssue],
    model: &ResolvedModel,
    resume: &ResumeLedgerState,
) -> CallToolResult {
    response_with_metadata(
        attach_resume_metadata(base, resume),
        validation_errors,
        model,
    )
}

fn async_success(payload: Value, elapsed_ms_value: u64) -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": true,
        "data": payload,
        "meta": {"elapsed_ms": elapsed_ms_value},
    }))
}

fn async_error(code: &str, reason: &str, message: &str, elapsed_ms_value: u64) -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": false,
        "error": {
            "error": message,
            "code": code,
            "reason": reason,
        },
        "meta": {"elapsed_ms": elapsed_ms_value},
    }))
}

fn async_suggested_wait_ms(state: GeminiAsyncInvocationState) -> Option<u64> {
    match state {
        GeminiAsyncInvocationState::Pending => Some(250),
        GeminiAsyncInvocationState::Running => Some(1_000),
        GeminiAsyncInvocationState::Succeeded
        | GeminiAsyncInvocationState::Failed
        | GeminiAsyncInvocationState::Canceled => None,
    }
}

fn async_snapshot_payload(snapshot: &GeminiAsyncInvocationSnapshot, include_result: bool) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("invocation_id".to_string(), json!(snapshot.invocation_id));
    payload.insert("tool_name".to_string(), json!(snapshot.tool_name));
    payload.insert("actor".to_string(), json!(snapshot.actor));
    payload.insert("session_id".to_string(), json!(snapshot.session_id));
    payload.insert("request_id".to_string(), json!(snapshot.request_id));
    payload.insert(
        "model_requested".to_string(),
        json!(snapshot.model_requested),
    );
    payload.insert("model_used".to_string(), json!(snapshot.model_used));
    payload.insert(
        "resume_selector".to_string(),
        json!(snapshot.resume_selector),
    );
    payload.insert(
        "resume_strategy".to_string(),
        json!(snapshot.resume_strategy),
    );
    payload.insert(
        "effective_scope_roots".to_string(),
        json!(snapshot.effective_scope_roots),
    );
    payload.insert(
        "nested_mcp_policy".to_string(),
        json!(snapshot.nested_mcp_policy),
    );
    payload.insert("state".to_string(), json!(snapshot.state.as_str()));
    payload.insert("terminal".to_string(), json!(snapshot.terminal()));
    payload.insert(
        "cancel_requested".to_string(),
        json!(snapshot.cancel_requested),
    );
    payload.insert(
        "created_at_unix_ms".to_string(),
        json!(snapshot.created_at_unix_ms),
    );
    payload.insert(
        "started_at_unix_ms".to_string(),
        json!(snapshot.started_at_unix_ms),
    );
    payload.insert(
        "last_event_unix_ms".to_string(),
        json!(snapshot.last_event_unix_ms),
    );
    payload.insert(
        "finished_at_unix_ms".to_string(),
        json!(snapshot.finished_at_unix_ms),
    );
    payload.insert("latest_attempt".to_string(), json!(snapshot.latest_attempt));
    payload.insert("retry_count".to_string(), json!(snapshot.retry_count));
    payload.insert("last_phase".to_string(), json!(snapshot.last_phase));
    payload.insert("pid".to_string(), json!(snapshot.pid));
    payload.insert("stdout_bytes".to_string(), json!(snapshot.stdout_bytes));
    payload.insert("stderr_bytes".to_string(), json!(snapshot.stderr_bytes));
    payload.insert(
        "last_output_age_ms".to_string(),
        json!(snapshot.last_output_age_ms),
    );
    payload.insert("stalled".to_string(), json!(snapshot.stalled));
    payload.insert(
        "suggested_wait_ms".to_string(),
        json!(async_suggested_wait_ms(snapshot.state)),
    );
    payload.insert(
        "result_available".to_string(),
        json!(snapshot.terminal() && snapshot.result.is_some()),
    );
    if include_result
        && snapshot.terminal()
        && let Some(result) = snapshot.result.clone()
    {
        payload.insert("result".to_string(), result);
    }
    Value::Object(payload)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeminiAsyncStatusWaitMode {
    Immediate,
    Deadline { wait_ms: u64 },
    UntilTerminal,
}

fn parse_async_status_wait_mode(
    wait_ms: Option<u64>,
    wait_until_terminal: bool,
) -> Result<GeminiAsyncStatusWaitMode, &'static str> {
    if wait_until_terminal {
        if wait_ms.is_some() {
            return Err("wait_ms cannot be combined with wait_until_terminal=true");
        }
        return Ok(GeminiAsyncStatusWaitMode::UntilTerminal);
    }
    let Some(wait_ms) = wait_ms else {
        return Ok(GeminiAsyncStatusWaitMode::Immediate);
    };
    if wait_ms == 0 || wait_ms > 3_600_000 {
        return Err("wait_ms must be between 1 and 3600000");
    }
    Ok(GeminiAsyncStatusWaitMode::Deadline { wait_ms })
}

fn parse_json_response(raw: &str) -> Option<Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else if let Ok(value) = serde_json::from_str(trimmed) {
        Some(value)
    } else {
        parse_embedded_json(trimmed)
    }
}

fn strip_ansi_escape_sequences(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            output.push(ch);
            continue;
        }

        // Consume CSI/OSC-style escape sequences.
        if let Some(next) = chars.next() {
            match next {
                '[' => {
                    while let Some(seq) = chars.next() {
                        if ('@'..='~').contains(&seq) {
                            break;
                        }
                    }
                }
                ']' => {
                    while let Some(seq) = chars.next() {
                        if seq == '\u{7}' {
                            break;
                        }
                        if seq == '\u{1b}' {
                            if matches!(chars.peek(), Some('\\')) {
                                let _ = chars.next();
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    output
}

fn cleaned_stats_session_line(raw_line: &str) -> String {
    let without_ansi = strip_ansi_escape_sequences(raw_line);
    let trimmed = without_ansi.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let stripped = trimmed
        .trim_matches(|ch| matches!(ch, '│' | '┃' | '|'))
        .trim();
    if stripped.is_empty() {
        return String::new();
    }

    let has_payload = stripped
        .chars()
        .any(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '%' | '.'));
    if !has_payload {
        return String::new();
    }

    stripped.to_string()
}

#[cfg(test)]
fn parse_u64_digits(raw: &str) -> Option<u64> {
    let digits: String = raw.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u64>().ok()
    }
}

#[cfg(test)]
fn parse_stats_session_duration_seconds(reset_window: &str) -> Option<u64> {
    let mut total_seconds = 0u64;
    let mut saw_unit = false;
    for token in reset_window.split_whitespace() {
        let token = token.trim_end_matches(',');
        if token.len() < 2 {
            continue;
        }
        let (number, unit) = token.split_at(token.len() - 1);
        let Ok(value) = number.parse::<u64>() else {
            continue;
        };
        let unit_seconds = match unit {
            "d" | "D" => Some(value.saturating_mul(86_400)),
            "h" | "H" => Some(value.saturating_mul(3_600)),
            "m" | "M" => Some(value.saturating_mul(60)),
            "s" | "S" => Some(value),
            _ => None,
        };
        if let Some(seconds) = unit_seconds {
            saw_unit = true;
            total_seconds = total_seconds.saturating_add(seconds);
        }
    }
    saw_unit.then_some(total_seconds)
}

fn text_after_case_insensitive_marker<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let line_lower = line.to_ascii_lowercase();
    let marker_lower = marker.to_ascii_lowercase();
    let index = line_lower.find(&marker_lower)?;
    line.get(index + marker.len()..)
}

#[cfg(test)]
fn parse_quota_window_line(line: &str) -> Option<GeminiQuotaWindow> {
    let mut columns = line.split_whitespace();
    let model = columns.next()?;
    if !model.starts_with("gemini-") {
        return None;
    }

    let requests_raw = columns.next().map(str::to_string);
    let requests = requests_raw.as_deref().and_then(parse_u64_digits);
    let usage_remaining_percent = line.split_whitespace().find_map(|token| {
        let value = token.strip_suffix('%')?;
        value.parse::<f64>().ok()
    });

    let reset_in = text_after_case_insensitive_marker(line, "resets in")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let reset_in_seconds = reset_in
        .as_deref()
        .and_then(parse_stats_session_duration_seconds);
    let reset_at_unix_ms = reset_in_seconds
        .map(|seconds| current_unix_timestamp_ms().saturating_add(seconds.saturating_mul(1_000)));

    Some(GeminiQuotaWindow {
        model: model.to_string(),
        requests,
        requests_raw,
        usage_remaining_percent,
        reset_in,
        reset_in_seconds,
        reset_at_unix_ms,
    })
}

#[cfg(test)]
fn parse_session_stats_snapshot(raw_stdout: &str) -> GeminiSessionStatsSnapshot {
    let mut snapshot = GeminiSessionStatsSnapshot::default();

    for raw_line in raw_stdout.lines() {
        let line = cleaned_stats_session_line(raw_line);
        if line.is_empty() {
            continue;
        }

        if let Some((label, value)) = line.split_once(':') {
            let label = label.trim().to_ascii_lowercase();
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match label.as_str() {
                "session id" => snapshot.session_id = Some(value.to_string()),
                "auth method" => snapshot.auth_method = Some(value.to_string()),
                "tier" => snapshot.tier = Some(value.to_string()),
                _ => {}
            }
            continue;
        }

        if let Some(quota_window) = parse_quota_window_line(&line) {
            snapshot.quotas.push(quota_window);
        }
    }

    snapshot
}

fn parse_session_probe_stats_object(
    object: &serde_json::Map<String, Value>,
) -> GeminiSessionProbeStats {
    let cached_tokens = sum_optional_tokens(
        object_u64_any_case(
            object,
            &[
                "cached_tokens",
                "cachedTokens",
                "cached",
                "cachedContentTokenCount",
                "cache_read",
                "cacheReadTokenCount",
            ],
        ),
        object_u64_any_case(
            object,
            &[
                "cache_write",
                "cacheWriteTokenCount",
                "cached_output_tokens",
            ],
        ),
    );
    let tool_calls = object_u64_any_case(
        object,
        &["tool_calls", "toolCalls", "total_calls", "totalCalls"],
    )
    .or_else(|| {
        object_value_ignore_ascii_case(object, "tools")
            .and_then(Value::as_object)
            .and_then(|tools| {
                object_u64_any_case(
                    tools,
                    &[
                        "total",
                        "count",
                        "total_calls",
                        "totalCalls",
                        "tool_calls",
                        "toolCalls",
                    ],
                )
            })
    });

    GeminiSessionProbeStats {
        input_tokens: object_u64_any_case(
            object,
            &[
                "input_tokens",
                "inputTokenCount",
                "prompt_tokens",
                "promptTokenCount",
                "input",
                "prompt",
            ],
        ),
        output_tokens: object_u64_any_case(
            object,
            &[
                "output_tokens",
                "outputTokenCount",
                "completion_tokens",
                "completionTokenCount",
                "candidatesTokenCount",
                "output",
                "completion",
            ],
        ),
        total_tokens: object_u64_any_case(object, &["total_tokens", "totalTokenCount", "total"]),
        cached_tokens,
        direct_input_tokens: object_u64_any_case(
            object,
            &[
                "direct_input_tokens",
                "directInputTokens",
                "direct_input",
                "directInput",
            ],
        )
        .or_else(|| object_u64_any_case(object, &["input", "prompt"])),
        duration_ms: object_u64_any_case(
            object,
            &["duration_ms", "durationMs", "elapsed_ms", "elapsedMs"],
        ),
        tool_calls,
    }
}

fn parse_session_probe_snapshot(raw_stdout: &str, raw_stderr: &str) -> GeminiSessionProbeSnapshot {
    let mut snapshot = GeminiSessionProbeSnapshot {
        session_id: extract_session_id_from_json_text(raw_stdout)
            .or_else(|| extract_session_id_from_json_text(raw_stderr))
            .or_else(|| extract_session_id_from_text(raw_stdout))
            .or_else(|| extract_session_id_from_text(raw_stderr)),
        ..GeminiSessionProbeSnapshot::default()
    };

    let parsed_json = parse_json_response(raw_stdout).or_else(|| parse_json_response(raw_stderr));
    let Some(parsed_json) = parsed_json else {
        return snapshot;
    };

    if let Some(root_object) = parsed_json.as_object() {
        snapshot.auth_method = object_string_any_case(root_object, &["auth_method", "authMethod"]);
        snapshot.tier = object_string_any_case(root_object, &["tier"]);
    }

    if let Some(extracted) = extract_usage_from_json(&parsed_json) {
        let usage = extracted.usage;
        snapshot.probe_stats.input_tokens = usage.input_tokens;
        snapshot.probe_stats.output_tokens = usage.output_tokens;
        snapshot.probe_stats.total_tokens = usage.total_tokens;
        snapshot.probe_stats.cached_tokens =
            sum_optional_tokens(usage.cache_read_tokens, usage.cache_write_tokens)
                .or(usage.cache_read_tokens)
                .or(usage.cache_write_tokens);
    }

    let parsed_stats = parsed_json
        .as_object()
        .and_then(|root| object_value_ignore_ascii_case(root, "stats").and_then(Value::as_object))
        .or_else(|| parsed_json.as_object())
        .map(parse_session_probe_stats_object)
        .unwrap_or_default();

    snapshot.probe_stats.input_tokens = snapshot
        .probe_stats
        .input_tokens
        .or(parsed_stats.input_tokens);
    snapshot.probe_stats.output_tokens = snapshot
        .probe_stats
        .output_tokens
        .or(parsed_stats.output_tokens);
    snapshot.probe_stats.total_tokens = snapshot
        .probe_stats
        .total_tokens
        .or(parsed_stats.total_tokens);
    snapshot.probe_stats.cached_tokens = snapshot
        .probe_stats
        .cached_tokens
        .or(parsed_stats.cached_tokens);
    snapshot.probe_stats.direct_input_tokens = parsed_stats.direct_input_tokens;
    snapshot.probe_stats.duration_ms = parsed_stats.duration_ms;
    snapshot.probe_stats.tool_calls = parsed_stats.tool_calls;

    snapshot
}

fn strip_codebase_envelope_metadata(value: Value) -> Value {
    let Value::Object(mut object) = value else {
        return value;
    };
    object.remove("session_id");
    object.remove("stats");
    Value::Object(object)
}

#[derive(Debug, Clone)]
struct AskGeminiOutputPayload {
    response_text: String,
    response_json: Option<Value>,
    response_envelope: Option<Value>,
}

fn value_has_meaningful_ask_gemini_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(raw) => !raw.trim().is_empty(),
        Value::Array(values) => values.iter().any(value_has_meaningful_ask_gemini_content),
        Value::Object(map) => map.iter().any(|(key, nested)| {
            if key == "session_id" || key == "stats" {
                return false;
            }
            if key == "response" && matches!(nested, Value::String(raw) if raw.trim().is_empty()) {
                return false;
            }
            value_has_meaningful_ask_gemini_content(nested)
        }),
        _ => true,
    }
}

fn ask_gemini_response_text_fallback(
    response_json: Option<&Value>,
    response_envelope: Option<&Value>,
    raw_stdout: &str,
) -> Option<String> {
    if let Some(value) =
        response_json.filter(|value| value_has_meaningful_ask_gemini_content(value))
    {
        return Some(value.to_string());
    }

    if let Some(envelope) = response_envelope {
        let stripped = strip_codebase_envelope_metadata(envelope.clone());
        if value_has_meaningful_ask_gemini_content(&stripped) {
            return Some(stripped.to_string());
        }
    }

    let trimmed = raw_stdout.trim();
    if !trimmed.is_empty() && parse_json_response(trimmed).is_none() {
        return Some(trimmed.to_string());
    }

    None
}

fn normalize_ask_gemini_output(raw_stdout: &str) -> AskGeminiOutputPayload {
    let Some(parsed) = parse_json_response(raw_stdout) else {
        return AskGeminiOutputPayload {
            response_text: raw_stdout.to_string(),
            response_json: None,
            response_envelope: None,
        };
    };

    let mut response_text = raw_stdout.to_string();
    let mut response_json = None;
    let response_envelope =
        matches!(&parsed, Value::Object(_) | Value::Array(_)).then_some(parsed.clone());

    if let Value::Object(object) = &parsed {
        if let Some(response_value) = object.get("response") {
            match response_value {
                Value::String(raw_response) => {
                    response_text = raw_response.clone();
                    response_json =
                        parse_json_response(raw_response).map(strip_codebase_envelope_metadata);
                }
                Value::Object(_) | Value::Array(_) => {
                    response_json = Some(strip_codebase_envelope_metadata(response_value.clone()));
                    response_text = response_value.to_string();
                }
                _ => {}
            }
        }
    }

    if response_json.is_none() && matches!(&parsed, Value::Object(_) | Value::Array(_)) {
        response_json = Some(strip_codebase_envelope_metadata(parsed.clone()));
    }

    AskGeminiOutputPayload {
        response_text,
        response_json,
        response_envelope,
    }
}

fn normalize_codebase_tool_response(value: Value) -> Option<(Value, Option<Value>)> {
    if let Value::Object(object) = &value {
        if let Some(response_value) = object.get("response") {
            let normalized = match response_value {
                Value::String(raw) => parse_json_response(raw),
                Value::Object(_) | Value::Array(_) => Some(response_value.clone()),
                _ => None,
            }?;
            return Some((sanitize_codebase_tool_output(normalized), Some(value)));
        }
    }

    Some((
        sanitize_codebase_tool_output(strip_codebase_envelope_metadata(value)),
        None,
    ))
}

fn sanitize_codebase_tool_output(mut value: Value) -> Value {
    const BANNED_KEYS: [&str; 3] = ["question", "objective", "target"];

    match &mut value {
        Value::Object(object) => {
            object.retain(|key, _| {
                !BANNED_KEYS
                    .iter()
                    .any(|banned| key.eq_ignore_ascii_case(banned))
            });
            for value in object.values_mut() {
                *value = sanitize_codebase_tool_output(value.clone());
            }
        }
        Value::Array(values) => {
            for value in values.iter_mut() {
                *value = sanitize_codebase_tool_output(value.clone());
            }
        }
        _ => {}
    }

    value
}

fn parse_embedded_json(raw: &str) -> Option<Value> {
    let bytes = raw.as_bytes();
    for i in 0..bytes.len() {
        let (open, close) = match bytes[i] {
            b'{' => (b'{', b'}'),
            b'[' => (b'[', b']'),
            _ => continue,
        };

        let mut depth = 0i64;
        let mut in_string = false;
        let mut escaped = false;
        for j in i..bytes.len() {
            let byte = bytes[j];
            if escaped {
                escaped = false;
                continue;
            }

            if in_string {
                if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }

            if byte == b'"' {
                in_string = true;
                continue;
            }

            if byte == open {
                depth += 1;
            } else if byte == close {
                depth -= 1;
                if depth == 0 {
                    let candidate = &raw[i..=j];
                    if let Ok(value) = serde_json::from_str(candidate) {
                        return Some(value);
                    }
                    break;
                }
            }
        }
    }

    None
}

const SQL_GUARDRAIL_REQUIRED_SECTIONS: [&str; 4] = [
    "verified_findings",
    "inferred_hypotheses",
    "sql_citations",
    "unknowns",
];
const SQL_GUARDRAIL_MAX_REPAIR_ATTEMPTS: u8 = 3;
const SQL_GUARDRAIL_REPAIR_PROMPT_MAX_CHARS: usize = 1_600;

#[derive(Debug, Clone, Deserialize, JsonSchema, Default)]
struct AskGeminiSqlGuardrailsArgs {
    #[serde(default)]
    #[schemars(
        description = "Allowlisted fully-qualified SQL tables that citations may reference (case-insensitive)."
    )]
    allowed_tables: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "Allowlisted table prefixes (for example ops. or analytics.) that citations may reference."
    )]
    allowed_table_prefixes: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "Denied fully-qualified SQL tables that must not appear in citations."
    )]
    denied_tables: Vec<String>,
    #[serde(default = "default_sql_guardrail_repair_attempts")]
    #[schemars(
        description = "Maximum contract-repair retries after drift detection (0-3). Default: 1."
    )]
    repair_attempts: u8,
}

fn default_sql_guardrail_repair_attempts() -> u8 {
    1
}

#[derive(Debug, Clone)]
struct AskGeminiSqlGuardrails {
    allowed_tables: Vec<String>,
    allowed_table_prefixes: Vec<String>,
    denied_tables: Vec<String>,
    repair_attempts: u8,
}

impl AskGeminiSqlGuardrails {
    fn from_args(
        raw: AskGeminiSqlGuardrailsArgs,
        errors: &mut Vec<ValidationIssue>,
    ) -> Option<Self> {
        let allowed_tables = normalize_guardrail_identifier_entries(
            "sql_guardrails.allowed_tables",
            raw.allowed_tables,
            errors,
        );
        let allowed_table_prefixes = normalize_guardrail_prefix_entries(
            "sql_guardrails.allowed_table_prefixes",
            raw.allowed_table_prefixes,
            errors,
        );
        let denied_tables = normalize_guardrail_identifier_entries(
            "sql_guardrails.denied_tables",
            raw.denied_tables,
            errors,
        );

        if allowed_tables.is_empty() && allowed_table_prefixes.is_empty() {
            errors.push(ValidationIssue {
                field: "sql_guardrails".to_string(),
                code: "invalid_value".to_string(),
                expected_type: "at least one allowlisted table or table prefix".to_string(),
                received_type: "empty policy".to_string(),
                corrective_hint: "Set sql_guardrails.allowed_tables and/or sql_guardrails.allowed_table_prefixes when enabling strict SQL guardrails.".to_string(),
            });
        }

        if raw.repair_attempts > SQL_GUARDRAIL_MAX_REPAIR_ATTEMPTS {
            errors.push(ValidationIssue {
                field: "sql_guardrails.repair_attempts".to_string(),
                code: "invalid_value".to_string(),
                expected_type: format!(
                    "integer in range 0..={SQL_GUARDRAIL_MAX_REPAIR_ATTEMPTS}"
                ),
                received_type: raw.repair_attempts.to_string(),
                corrective_hint: format!(
                    "Set sql_guardrails.repair_attempts to a value between 0 and {SQL_GUARDRAIL_MAX_REPAIR_ATTEMPTS}."
                ),
            });
        }

        if errors
            .iter()
            .any(|issue| issue.field.starts_with("sql_guardrails"))
        {
            return None;
        }

        Some(Self {
            allowed_tables,
            allowed_table_prefixes,
            denied_tables,
            repair_attempts: raw.repair_attempts,
        })
    }

    fn policy_summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.allowed_tables.is_empty() {
            parts.push(format!(
                "allowed tables: {}",
                self.allowed_tables.join(", ")
            ));
        }
        if !self.allowed_table_prefixes.is_empty() {
            parts.push(format!(
                "allowed prefixes: {}",
                self.allowed_table_prefixes.join(", ")
            ));
        }
        if !self.denied_tables.is_empty() {
            parts.push(format!("denied tables: {}", self.denied_tables.join(", ")));
        }
        if parts.is_empty() {
            "no table policy configured".to_string()
        } else {
            parts.join("; ")
        }
    }

    fn table_allowed(&self, table_ref: &str) -> bool {
        self.allowed_tables
            .iter()
            .any(|allowed| allowed == table_ref)
            || self
                .allowed_table_prefixes
                .iter()
                .any(|prefix| table_ref.starts_with(prefix))
    }
}

#[derive(Debug, Clone)]
struct AskGeminiContractDrift {
    reason_code: &'static str,
    issues: Vec<String>,
    invalid_table_refs: u32,
    citation_missing: u32,
}

impl AskGeminiContractDrift {
    fn summary(&self) -> String {
        self.issues
            .first()
            .cloned()
            .unwrap_or_else(|| "SQL response contract drift detected".to_string())
    }
}

fn normalize_guardrail_identifier_entries(
    field: &str,
    values: Vec<String>,
    errors: &mut Vec<ValidationIssue>,
) -> Vec<String> {
    let mut normalized = Vec::<String>::new();
    for raw in values {
        let Some(value) = normalize_sql_identifier(&raw) else {
            errors.push(ValidationIssue {
                field: field.to_string(),
                code: "invalid_value".to_string(),
                expected_type: "SQL identifier (for example schema.table)".to_string(),
                received_type: "string".to_string(),
                corrective_hint: format!(
                    "Replace '{raw}' with a valid SQL identifier for {field}."
                ),
            });
            continue;
        };
        if !normalized.iter().any(|existing| existing == &value) {
            normalized.push(value);
        }
    }
    normalized
}

fn normalize_guardrail_prefix_entries(
    field: &str,
    values: Vec<String>,
    errors: &mut Vec<ValidationIssue>,
) -> Vec<String> {
    let mut normalized = Vec::<String>::new();
    for raw in values {
        let value = raw.trim();
        if value.is_empty() {
            errors.push(ValidationIssue {
                field: field.to_string(),
                code: "invalid_value".to_string(),
                expected_type: "non-empty SQL table prefix".to_string(),
                received_type: "string".to_string(),
                corrective_hint: format!(
                    "Replace '{raw}' with a valid SQL table prefix for {field}."
                ),
            });
            continue;
        }

        let mut prefix = value
            .trim_matches(|ch| matches!(ch, '`' | '"' | '\''))
            .to_ascii_lowercase();
        if !prefix.ends_with('.') {
            prefix.push('.');
        }
        if !prefix
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '.'))
            || prefix == "."
            || prefix.contains("..")
        {
            errors.push(ValidationIssue {
                field: field.to_string(),
                code: "invalid_value".to_string(),
                expected_type: "SQL table prefix (for example schema.)".to_string(),
                received_type: "string".to_string(),
                corrective_hint: format!(
                    "Replace '{raw}' with a valid SQL table prefix for {field}."
                ),
            });
            continue;
        }

        if !normalized.iter().any(|existing| existing == &prefix) {
            normalized.push(prefix);
        }
    }
    normalized
}

fn normalize_sql_identifier(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_end_matches(|ch| matches!(ch, ',' | ';'))
        .trim_matches(|ch| matches!(ch, '`' | '"' | '\''));
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.eq_ignore_ascii_case("select") {
        return None;
    }

    let mut normalized_parts = Vec::new();
    for part in trimmed.split('.') {
        let cleaned = part
            .trim()
            .trim_matches(|ch| matches!(ch, '`' | '"' | '\''))
            .trim();
        if cleaned.is_empty() {
            return None;
        }
        if !cleaned
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
        {
            return None;
        }
        normalized_parts.push(cleaned.to_ascii_lowercase());
    }

    if normalized_parts.is_empty() {
        None
    } else {
        Some(normalized_parts.join("."))
    }
}

fn parse_ask_gemini_response_payload(raw_stdout: &str) -> Option<Value> {
    let parsed = parse_json_response(raw_stdout)?;
    if let Value::Object(object) = &parsed {
        if let Some(response_value) = object.get("response") {
            return match response_value {
                Value::String(raw) => parse_json_response(raw),
                Value::Object(_) | Value::Array(_) => Some(response_value.clone()),
                _ => None,
            };
        }
    }
    Some(parsed)
}

fn extract_sql_table_references(sql: &str) -> Vec<String> {
    let mut tokens = Vec::<String>::new();
    let mut current = String::new();
    for ch in sql.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '.' | '"' | '`') {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    let mut refs = Vec::<String>::new();
    for index in 0..tokens.len() {
        let lower = tokens[index].to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "from" | "join" | "update" | "into" | "table"
        ) {
            continue;
        }

        let mut cursor = index + 1;
        while cursor < tokens.len() {
            let candidate = tokens[cursor].to_ascii_lowercase();
            if matches!(
                candidate.as_str(),
                "left" | "right" | "inner" | "outer" | "cross" | "full" | "lateral" | "only" | "as"
            ) {
                cursor += 1;
                continue;
            }
            if candidate == "select" {
                break;
            }
            if let Some(normalized) = normalize_sql_identifier(&tokens[cursor]) {
                if !refs.iter().any(|existing| existing == &normalized) {
                    refs.push(normalized);
                }
            }
            break;
        }
    }

    refs
}

fn validate_sql_guardrail_output(
    raw_stdout: &str,
    guardrails: &AskGeminiSqlGuardrails,
) -> Result<Value, AskGeminiContractDrift> {
    let Some(payload) = parse_ask_gemini_response_payload(raw_stdout) else {
        return Err(AskGeminiContractDrift {
            reason_code: "invalid_json",
            issues: vec!["Gemini response did not contain parseable JSON.".to_string()],
            invalid_table_refs: 0,
            citation_missing: 1,
        });
    };
    let Some(object) = payload.as_object() else {
        return Err(AskGeminiContractDrift {
            reason_code: "invalid_contract",
            issues: vec!["Gemini response JSON must be an object.".to_string()],
            invalid_table_refs: 0,
            citation_missing: 1,
        });
    };

    let mut issues = Vec::<String>::new();
    let mut invalid_table_refs = 0u32;
    let mut citation_missing = 0u32;

    for section in SQL_GUARDRAIL_REQUIRED_SECTIONS {
        match object_value_ignore_ascii_case(object, section) {
            Some(Value::Array(_)) => {}
            Some(_) => issues.push(format!(
                "Field '{section}' must be an array in strict SQL contract output."
            )),
            None => issues.push(format!(
                "Missing required field '{section}' in strict SQL contract output."
            )),
        }
    }

    match object_value_ignore_ascii_case(object, "sql_citations") {
        Some(Value::Array(citations)) => {
            if citations.is_empty() {
                citation_missing = citation_missing.saturating_add(1);
                issues.push(
                    "Field 'sql_citations' must include at least one SQL citation.".to_string(),
                );
            }
            for (index, citation) in citations.iter().enumerate() {
                let Some(citation_object) = citation.as_object() else {
                    citation_missing = citation_missing.saturating_add(1);
                    issues.push(format!(
                        "sql_citations[{index}] must be an object with a non-empty 'sql' field."
                    ));
                    continue;
                };
                let sql = object_value_ignore_ascii_case(citation_object, "sql")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let Some(sql) = sql else {
                    citation_missing = citation_missing.saturating_add(1);
                    issues.push(format!(
                        "sql_citations[{index}] is missing required non-empty field 'sql'."
                    ));
                    continue;
                };

                let table_refs = extract_sql_table_references(sql);
                if table_refs.is_empty() {
                    citation_missing = citation_missing.saturating_add(1);
                    issues.push(format!(
                        "sql_citations[{index}] did not reference a detectable SQL table."
                    ));
                    continue;
                }

                for table_ref in table_refs {
                    if guardrails
                        .denied_tables
                        .iter()
                        .any(|denied| denied == &table_ref)
                    {
                        invalid_table_refs = invalid_table_refs.saturating_add(1);
                        issues.push(format!(
                            "sql_citations[{index}] references denied table '{table_ref}'."
                        ));
                        continue;
                    }

                    if !guardrails.table_allowed(&table_ref) {
                        invalid_table_refs = invalid_table_refs.saturating_add(1);
                        issues.push(format!(
                            "sql_citations[{index}] references out-of-policy table '{table_ref}'."
                        ));
                    }
                }
            }
        }
        Some(_) => {
            citation_missing = citation_missing.saturating_add(1);
            issues.push("Field 'sql_citations' must be an array.".to_string());
        }
        None => {
            citation_missing = citation_missing.saturating_add(1);
            issues.push("Missing required field 'sql_citations'.".to_string());
        }
    }

    if issues.is_empty() {
        Ok(payload)
    } else {
        Err(AskGeminiContractDrift {
            reason_code: "invalid_contract",
            issues,
            invalid_table_refs,
            citation_missing,
        })
    }
}

fn truncate_for_guardrail_prompt(input: &str, max_chars: usize) -> String {
    let trimmed = input.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let mut truncated = String::with_capacity(max_chars.saturating_add(3));
    for (idx, ch) in trimmed.chars().enumerate() {
        if idx >= max_chars {
            break;
        }
        truncated.push(ch);
    }
    truncated.push_str("...");
    truncated
}

fn build_sql_guardrail_prompt(prompt: &str, guardrails: &AskGeminiSqlGuardrails) -> String {
    format!(
        "{prompt}\n\n\
Strict SQL response contract (enforced server-side):\n\
- Return exactly one JSON object.\n\
- Include keys: verified_findings, inferred_hypotheses, sql_citations, unknowns.\n\
- Every sql_citations entry must include a non-empty 'sql' field.\n\
- Citations may only reference policy-approved tables.\n\
- If evidence is weak, put it under unknowns instead of verified_findings.\n\
- Do not emit markdown, code fences, or explanatory prose.\n\
Table policy: {}.",
        guardrails.policy_summary()
    )
}

fn build_sql_guardrail_repair_prompt(
    original_prompt: &str,
    drift: &AskGeminiContractDrift,
    guardrails: &AskGeminiSqlGuardrails,
) -> String {
    let objective =
        truncate_for_guardrail_prompt(original_prompt, SQL_GUARDRAIL_REPAIR_PROMPT_MAX_CHARS);
    let mut issue_lines = String::new();
    for issue in drift.issues.iter().take(8) {
        issue_lines.push_str("- ");
        issue_lines.push_str(issue);
        issue_lines.push('\n');
    }

    format!(
        "Repair the previous SQL response so it satisfies strict contract checks.\n\
Original objective (truncated):\n{objective}\n\n\
Validation errors from previous response:\n{issue_lines}\n\
Return one JSON object only with keys verified_findings, inferred_hypotheses, sql_citations, unknowns.\n\
Each sql_citations item must include a non-empty sql string.\n\
Never reference tables outside this policy: {}.\n\
When uncertain, place details in unknowns.",
        guardrails.policy_summary()
    )
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            number
                .as_i64()
                .and_then(|value| (value >= 0).then_some(value as u64))
        }),
        Value::String(raw) => raw.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn object_value_ignore_ascii_case<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a Value> {
    object.get(key).or_else(|| {
        object
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    })
}

fn object_u64_any_case(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object_value_ignore_ascii_case(object, key).and_then(value_as_u64))
}

fn object_string_any_case(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        object_value_ignore_ascii_case(object, key).and_then(|value| match value {
            Value::String(raw) => {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then_some(trimmed.to_string())
            }
            _ => None,
        })
    })
}

fn extract_usage_from_object(object: &serde_json::Map<String, Value>) -> Option<TokenUsageSummary> {
    let mut usage = TokenUsageSummary {
        input_tokens: object_u64_any_case(
            object,
            &[
                "promptTokenCount",
                "prompt_token_count",
                "inputTokenCount",
                "input_token_count",
                "inputTokens",
                "input_tokens",
                "requestTokenCount",
            ],
        ),
        output_tokens: object_u64_any_case(
            object,
            &[
                "candidatesTokenCount",
                "completionTokenCount",
                "completion_token_count",
                "outputTokenCount",
                "output_token_count",
                "outputTokens",
                "output_tokens",
                "responseTokenCount",
            ],
        ),
        total_tokens: object_u64_any_case(
            object,
            &[
                "totalTokenCount",
                "total_token_count",
                "totalTokens",
                "total_tokens",
            ],
        ),
        reasoning_tokens: object_u64_any_case(
            object,
            &[
                "thoughtsTokenCount",
                "reasoningTokenCount",
                "reasoning_token_count",
                "thought_tokens",
                "reasoningTokens",
                "reasoning_tokens",
            ],
        ),
        cache_read_tokens: object_u64_any_case(
            object,
            &[
                "cachedContentTokenCount",
                "cacheReadTokenCount",
                "cache_read_token_count",
                "cached_input_tokens",
            ],
        ),
        cache_write_tokens: object_u64_any_case(
            object,
            &[
                "cacheWriteTokenCount",
                "cache_write_token_count",
                "cached_output_tokens",
            ],
        ),
    };

    usage.normalize_totals();
    (usage.score() > 0).then_some(usage)
}

fn extract_usage_from_stats_tokens_object(
    object: &serde_json::Map<String, Value>,
) -> Option<TokenUsageSummary> {
    let mut usage = TokenUsageSummary {
        input_tokens: object_u64_any_case(
            object,
            &[
                "prompt",
                "prompt_tokens",
                "promptTokenCount",
                "input",
                "input_tokens",
                "inputTokenCount",
            ],
        ),
        output_tokens: object_u64_any_case(
            object,
            &[
                "candidates",
                "candidatesTokenCount",
                "output",
                "output_tokens",
                "outputTokenCount",
            ],
        ),
        total_tokens: object_u64_any_case(object, &["total", "total_tokens", "totalTokenCount"]),
        reasoning_tokens: object_u64_any_case(
            object,
            &[
                "thoughts",
                "thought_tokens",
                "thoughtsTokenCount",
                "reasoning",
                "reasoning_tokens",
                "reasoningTokenCount",
            ],
        ),
        cache_read_tokens: object_u64_any_case(
            object,
            &[
                "cached",
                "cached_tokens",
                "cachedContentTokenCount",
                "cache_read",
                "cacheReadTokenCount",
            ],
        ),
        cache_write_tokens: object_u64_any_case(object, &["cache_write", "cacheWriteTokenCount"]),
    };

    usage.normalize_totals();
    (usage.score() > 0).then_some(usage)
}

fn extract_usage_from_stats_models(value: &Value) -> Option<TokenUsageExtraction> {
    let root = value.as_object()?;
    let stats = object_value_ignore_ascii_case(root, "stats")?.as_object()?;
    let models = object_value_ignore_ascii_case(stats, "models")?.as_object()?;

    let mut usage = TokenUsageSummary::default();
    let mut saw_role_tokens = false;
    let mut saw_model_tokens = false;

    for model in models.values() {
        let Some(model_object) = model.as_object() else {
            continue;
        };

        let mut model_had_role_tokens = false;
        if let Some(roles) =
            object_value_ignore_ascii_case(model_object, "roles").and_then(Value::as_object)
        {
            for role in roles.values() {
                let Some(role_object) = role.as_object() else {
                    continue;
                };
                let Some(tokens) = object_value_ignore_ascii_case(role_object, "tokens")
                    .and_then(Value::as_object)
                else {
                    continue;
                };
                if let Some(extracted) = extract_usage_from_stats_tokens_object(tokens) {
                    usage.add_assign(&extracted);
                    saw_role_tokens = true;
                    model_had_role_tokens = true;
                }
            }
        }

        if model_had_role_tokens {
            continue;
        }

        let Some(tokens) =
            object_value_ignore_ascii_case(model_object, "tokens").and_then(Value::as_object)
        else {
            continue;
        };
        if let Some(extracted) = extract_usage_from_stats_tokens_object(tokens) {
            usage.add_assign(&extracted);
            saw_model_tokens = true;
        }
    }

    let source = if saw_role_tokens {
        Some("json:$.stats.models.*.roles.*.tokens".to_string())
    } else if saw_model_tokens {
        Some("json:$.stats.models.*.tokens".to_string())
    } else if let Some(tokens) =
        object_value_ignore_ascii_case(stats, "tokens").and_then(Value::as_object)
    {
        if let Some(extracted) = extract_usage_from_stats_tokens_object(tokens) {
            usage.add_assign(&extracted);
            Some("json:$.stats.tokens".to_string())
        } else {
            None
        }
    } else {
        None
    }?;

    usage.normalize_totals();
    (usage.score() > 0).then_some(TokenUsageExtraction { usage, source })
}

fn extract_usage_from_json(value: &Value) -> Option<TokenUsageExtraction> {
    if let Some(extracted) = extract_usage_from_stats_models(value) {
        return Some(extracted);
    }

    fn walk(value: &Value, path: &str, best: &mut Option<(TokenUsageSummary, String, usize)>) {
        match value {
            Value::Object(object) => {
                if let Some(usage) = extract_usage_from_object(object) {
                    let score = usage.score();
                    let replace = best
                        .as_ref()
                        .map_or(true, |(_, _, current)| score > *current);
                    if replace {
                        *best = Some((usage, path.to_string(), score));
                    }
                }
                for (key, nested) in object {
                    let nested_path = format!("{path}.{key}");
                    walk(nested, &nested_path, best);
                }
            }
            Value::Array(values) => {
                for (index, nested) in values.iter().enumerate() {
                    let nested_path = format!("{path}[{index}]");
                    walk(nested, &nested_path, best);
                }
            }
            _ => {}
        }
    }

    let mut best: Option<(TokenUsageSummary, String, usize)> = None;
    walk(value, "$", &mut best);
    best.map(|(usage, path, _)| TokenUsageExtraction {
        usage,
        source: format!("json:{path}"),
    })
}

fn parse_first_number_after_label(text: &str, label: &str) -> Option<u64> {
    let mut search_start = 0usize;
    while let Some(found) = text[search_start..].find(label) {
        let value_start = search_start + found + label.len();
        let tail = &text[value_start..];
        let mut digits = String::new();
        let mut seen_digit = false;
        for ch in tail.chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
                seen_digit = true;
            } else if seen_digit {
                break;
            }
        }
        if !digits.is_empty() {
            return digits.parse::<u64>().ok();
        }
        search_start = value_start;
    }
    None
}

fn parse_first_number_after_any_label(text: &str, labels: &[&str]) -> Option<u64> {
    labels
        .iter()
        .find_map(|label| parse_first_number_after_label(text, label))
}

fn extract_usage_from_text(raw: &str) -> Option<TokenUsageExtraction> {
    let text = raw.to_lowercase();
    let mut usage = TokenUsageSummary {
        input_tokens: parse_first_number_after_any_label(
            &text,
            &[
                "input tokens",
                "prompt tokens",
                "prompt token count",
                "input_token_count",
            ],
        ),
        output_tokens: parse_first_number_after_any_label(
            &text,
            &[
                "output tokens",
                "completion tokens",
                "candidate tokens",
                "completion token count",
                "output_token_count",
            ],
        ),
        total_tokens: parse_first_number_after_any_label(
            &text,
            &["total tokens", "total token count", "total_token_count"],
        ),
        reasoning_tokens: parse_first_number_after_any_label(
            &text,
            &[
                "reasoning tokens",
                "thought tokens",
                "thought token count",
                "reasoning token count",
            ],
        ),
        cache_read_tokens: parse_first_number_after_any_label(
            &text,
            &["cache read tokens", "cached input tokens"],
        ),
        cache_write_tokens: parse_first_number_after_any_label(
            &text,
            &["cache write tokens", "cached output tokens"],
        ),
    };
    usage.normalize_totals();
    (usage.score() > 0).then_some(TokenUsageExtraction {
        usage,
        source: "text".to_string(),
    })
}

fn extract_token_usage(stdout: &str, stderr: &str) -> Option<TokenUsageExtraction> {
    if let Some(value) = parse_json_response(stdout) {
        if let Some(extracted) = extract_usage_from_json(&value) {
            return Some(TokenUsageExtraction {
                source: format!("stdout:{}", extracted.source),
                ..extracted
            });
        }
    }
    if let Some(value) = parse_json_response(stderr) {
        if let Some(extracted) = extract_usage_from_json(&value) {
            return Some(TokenUsageExtraction {
                source: format!("stderr:{}", extracted.source),
                ..extracted
            });
        }
    }
    if let Some(extracted) = extract_usage_from_text(stderr) {
        return Some(TokenUsageExtraction {
            source: format!("stderr:{}", extracted.source),
            ..extracted
        });
    }
    if let Some(extracted) = extract_usage_from_text(stdout) {
        return Some(TokenUsageExtraction {
            source: format!("stdout:{}", extracted.source),
            ..extracted
        });
    }
    None
}

fn normalize_percentage(value: f64) -> Option<f64> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let normalized = if value <= 1.0 { value * 100.0 } else { value };
    if normalized > 100.0 {
        return None;
    }
    Some((normalized * 1000.0).round() / 1000.0)
}

fn parse_first_percentage_token(raw: &str) -> Option<f64> {
    let mut token = String::new();
    let mut started = false;
    let mut seen_dot = false;

    for ch in raw.chars() {
        if ch.is_ascii_digit() {
            token.push(ch);
            started = true;
            continue;
        }
        if ch == '.' && started && !seen_dot {
            token.push(ch);
            seen_dot = true;
            continue;
        }
        if started {
            break;
        }
    }

    if token.is_empty() {
        return None;
    }
    token.parse::<f64>().ok().and_then(normalize_percentage)
}

fn parse_percentage_from_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64().and_then(normalize_percentage),
        Value::String(text) => parse_first_percentage_token(text),
        _ => None,
    }
}

fn key_indicates_remaining(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    ["remaining", "remain", "left", "available"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn key_indicates_used(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    ["used", "usage", "consumed", "full"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn finalize_context_window_snapshot(snapshot: &mut ContextWindowSnapshot) -> bool {
    if snapshot.percent_used.is_none() {
        if let Some(remaining) = snapshot.percent_remaining {
            snapshot.percent_used = normalize_percentage((100.0 - remaining).clamp(0.0, 100.0));
        }
    }
    if snapshot.percent_remaining.is_none() {
        if let Some(used) = snapshot.percent_used {
            snapshot.percent_remaining = normalize_percentage((100.0 - used).clamp(0.0, 100.0));
        }
    }
    snapshot.percent_used.is_some() || snapshot.percent_remaining.is_some()
}

fn extract_context_window_from_json(value: &Value) -> Option<ContextWindowSnapshot> {
    fn walk(value: &Value, path: &str, snapshot: &mut ContextWindowSnapshot) {
        match value {
            Value::Object(object) => {
                for (key, nested) in object {
                    let nested_path = format!("{path}.{key}");
                    let lower_path = nested_path.to_ascii_lowercase();
                    let lower_key = key.to_ascii_lowercase();
                    if lower_path.contains("context") {
                        if let Some(percent) = parse_percentage_from_value(nested) {
                            if key_indicates_remaining(&lower_key)
                                && snapshot.percent_remaining.is_none()
                            {
                                snapshot.percent_remaining = Some(percent);
                                snapshot.source = Some(format!("json:{nested_path}:remaining"));
                            } else if (key_indicates_used(&lower_key)
                                || lower_key.contains("percent")
                                || lower_key.contains("pct")
                                || lower_key.contains("ratio"))
                                && snapshot.percent_used.is_none()
                            {
                                snapshot.percent_used = Some(percent);
                                snapshot.source = Some(format!("json:{nested_path}:used"));
                            }
                        }
                    }
                    walk(nested, &nested_path, snapshot);
                }
            }
            Value::Array(items) => {
                for (index, nested) in items.iter().enumerate() {
                    let nested_path = format!("{path}[{index}]");
                    walk(nested, &nested_path, snapshot);
                }
            }
            _ => {}
        }
    }

    let mut snapshot = ContextWindowSnapshot::default();
    walk(value, "$", &mut snapshot);
    if !finalize_context_window_snapshot(&mut snapshot) {
        return None;
    }
    Some(snapshot)
}

fn extract_context_window_from_text(raw: &str) -> Option<ContextWindowSnapshot> {
    let mut snapshot = ContextWindowSnapshot::default();
    for line in raw.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("context") {
            continue;
        }
        let Some(percent) = parse_first_percentage_token(&lower) else {
            continue;
        };
        if key_indicates_remaining(&lower) {
            if snapshot.percent_remaining.is_none() {
                snapshot.percent_remaining = Some(percent);
                snapshot.source = Some("text:context_remaining".to_string());
            }
            continue;
        }
        if key_indicates_used(&lower) || lower.contains("window") {
            if snapshot.percent_used.is_none() {
                snapshot.percent_used = Some(percent);
                snapshot.source = Some("text:context_used".to_string());
            }
        }
    }
    if !finalize_context_window_snapshot(&mut snapshot) {
        return None;
    }
    Some(snapshot)
}

fn prefix_context_source(snapshot: ContextWindowSnapshot, prefix: &str) -> ContextWindowSnapshot {
    let mut enriched = snapshot;
    enriched.source = Some(match enriched.source {
        Some(source) => format!("{prefix}:{source}"),
        None => prefix.to_string(),
    });
    enriched
}

fn extract_context_window_snapshot(stdout: &str, stderr: &str) -> Option<ContextWindowSnapshot> {
    if let Some(value) = parse_json_response(stdout) {
        if let Some(snapshot) = extract_context_window_from_json(&value) {
            return Some(prefix_context_source(snapshot, "stdout"));
        }
    }
    if let Some(value) = parse_json_response(stderr) {
        if let Some(snapshot) = extract_context_window_from_json(&value) {
            return Some(prefix_context_source(snapshot, "stderr"));
        }
    }
    if let Some(snapshot) = extract_context_window_from_text(stderr) {
        return Some(prefix_context_source(snapshot, "stderr"));
    }
    if let Some(snapshot) = extract_context_window_from_text(stdout) {
        return Some(prefix_context_source(snapshot, "stdout"));
    }
    None
}

fn allowed_models_hint(allowlist: &[String]) -> String {
    if allowlist.is_empty() {
        return "<no allowlist configured>".to_string();
    }
    allowlist.join(", ")
}

fn model_not_allowed_issue(allowlist: &[String], requested: Option<&str>) -> ValidationIssue {
    let mut corrective_hint = format!("Set model to one of: {}.", allowed_models_hint(allowlist));
    if let Some(requested) = requested {
        let suggestions = suggested_allowlisted_models(allowlist, requested);
        if !suggestions.is_empty() {
            corrective_hint.push_str(&format!(
                " Closest allowlisted alias match: {}.",
                suggestions.join(", ")
            ));
        }
    }
    ValidationIssue {
        field: "model".to_string(),
        code: "model_not_allowed".to_string(),
        expected_type: "allowlisted model id".to_string(),
        received_type: "string".to_string(),
        corrective_hint,
    }
}

fn classify_execution_error(err: &GeminiExecutionError) -> ErrorCategory {
    match err {
        GeminiExecutionError::FailedExit { stderr, .. } => classify_stderr_error(stderr),
        GeminiExecutionError::UnsupportedCommand { .. } => ErrorCategory::InputValidation,
        GeminiExecutionError::InvalidIncludeDirectory { .. }
        | GeminiExecutionError::InvalidWorkingDirectory { .. } => ErrorCategory::FileAccess,
        GeminiExecutionError::TimedOut { .. } => ErrorCategory::ExecutionTimeout,
        GeminiExecutionError::SpawnFailed(_) | GeminiExecutionError::Cancelled => {
            ErrorCategory::NetworkOrTransport
        }
    }
}

fn classify_stderr_error(stderr: &str) -> ErrorCategory {
    let lower = stderr.to_lowercase();

    if [
        "quota",
        "rate limit",
        "too many requests",
        "429",
        "resource_exhausted",
        "model_capacity_exhausted",
        "retryablequotaerror",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        ErrorCategory::QuotaOrRateLimit
    } else if [
        "tool \"",
        "tool not found",
        "did you mean one of",
        "unknown tool",
        "unrecognized tool",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        ErrorCategory::ToolRegistryMismatch
    } else if [
        "subagent failed",
        "maximum call stack size exceeded",
        "rangeerror",
        "operation was aborted",
        "loop detected",
        "agent execution blocked",
        "agent execution stopped",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        ErrorCategory::ToolRuntime
    } else if lower.contains("model")
        && (lower.contains("not found") || lower.contains("unknown model"))
    {
        ErrorCategory::ModelNotFound
    } else if [
        "path",
        "directory",
        "permission",
        "denied",
        "not found",
        "does not exist",
        "workspace",
        "access",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        ErrorCategory::FileAccess
    } else if ["401", "403", "auth", "token", "session", "unauth"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        ErrorCategory::AuthSessionInvalid
    } else {
        ErrorCategory::NetworkOrTransport
    }
}

fn blocking_codebase_fallback_category(stderr: &str) -> Option<ErrorCategory> {
    if stderr.trim().is_empty() {
        return None;
    }
    let category = classify_stderr_error(stderr);
    match category {
        ErrorCategory::QuotaOrRateLimit
        | ErrorCategory::ToolRegistryMismatch
        | ErrorCategory::ToolRuntime
        | ErrorCategory::ModelNotFound
        | ErrorCategory::AuthSessionInvalid
        | ErrorCategory::FileAccess
        | ErrorCategory::ExecutionTimeout => Some(category),
        ErrorCategory::InputValidation
        | ErrorCategory::ResumeUnavailable
        | ErrorCategory::ModelNotAllowed
        | ErrorCategory::NetworkOrTransport
        | ErrorCategory::ResponseContract => None,
    }
}

#[derive(Debug)]
enum AskGeminiExecutionFailure {
    Execution(GeminiExecutionError),
    Contract(AskGeminiContractDrift),
}

#[derive(Debug)]
struct AskGeminiExecutionOutcome {
    output: GeminiResponse,
    response_json: Option<Value>,
    guardrail_repair_used: bool,
}

impl GeminiMcp {
    /// Summary: construct a Gemini MCP server from execution config.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Keeps policy immutable through `Arc`.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn new(config: GeminiExecutionConfig) -> Self {
        Self::new_with_observer(config, Arc::new(NoopGeminiInvocationObserver))
    }

    /// Summary: construct a Gemini MCP server with a custom invocation observer.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Observer callbacks run inline; observers must avoid leaking sensitive data.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn new_with_observer(
        config: GeminiExecutionConfig,
        invocation_observer: Arc<dyn GeminiInvocationObserver>,
    ) -> Self {
        let async_registry = Arc::new(GeminiAsyncInvocationRegistry::new(&config));
        let invocation_observer: Arc<dyn GeminiInvocationObserver> =
            Arc::new(FanoutGeminiInvocationObserver {
                observers: vec![invocation_observer, async_registry.observer()],
            });
        let usage_ledger = Arc::new(TokenUsageLedger::new(&config));
        let response_debug_artifact = Arc::new(ResponseEnvelopeDebugArtifact::new(&config));
        let session_probe_snapshot = Arc::new(SessionProbeSnapshotArtifact::new(&config));
        let resume_provider: Arc<dyn ConversationResumeProvider> =
            Arc::new(GeminiCliResumeProvider);
        Self {
            config: Arc::new(config),
            resume_provider,
            invocation_observer,
            async_registry,
            usage_ledger,
            response_debug_artifact,
            session_probe_snapshot,
            tool_router: Self::tool_router_gemini(),
        }
    }

    /// Summary: construct a Gemini MCP server from raw env-near config.
    ///
    /// # Errors
    /// * Returns `Err` if raw policy conversion fails.
    ///
    /// # Security
    /// * Normalizes execution policy before tool exposure.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn from_raw_config(raw: GeminiExecutionRawConfig) -> Result<Self, String> {
        Ok(Self::new(raw.into_execution_config()?))
    }

    /// Summary: list registered tool names.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Exposes only public tool names.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn tool_names(&self) -> Vec<String> {
        self.tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
    }

    /// Summary: serialize the registered tool surface as a deterministic snapshot.
    ///
    /// # Errors
    /// * Returns JSON serialization errors if a tool definition cannot be encoded.
    ///
    /// # Security
    /// * Serializes tool metadata only; does not invoke tools or inspect credentials.
    ///
    /// # Panics
    /// * Does not panic.
    pub fn tool_schema_snapshot(&self) -> Result<Value, serde_json::Error> {
        tool_schema_snapshot_value(&self.tool_router.list_all())
    }

    async fn execute_with_usage(
        &self,
        request: &GeminiRequest,
        ct: CancellationToken,
        usage: &mut ToolCallUsageAccumulator,
        invocation: &ToolInvocationContext,
        attempt: u32,
    ) -> Result<GeminiResponse, GeminiExecutionError> {
        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::AttemptStarted { attempt },
            ));
        let retry_count = Arc::new(AtomicU64::new(0));
        let chunk_observer: Arc<dyn GeminiOutputObserver> = Arc::new(ChunkObserver {
            observer: self.invocation_observer.clone(),
            invocation: invocation.clone(),
            attempt,
            retry_count: retry_count.clone(),
        });
        let result =
            execute_gemini_with_cancel_observed(&self.config, request, ct, Some(chunk_observer))
                .await;
        let gemini_invocations = retry_count.load(Ordering::Relaxed).saturating_add(1);
        match &result {
            Ok(output) => usage.record_output(&output.stdout, &output.stderr, gemini_invocations),
            Err(error) => usage.record_error(error, gemini_invocations),
        }
        result
    }

    fn resolve_session_compression_policy(
        &self,
        override_enabled: Option<bool>,
    ) -> (SessionCompressionMode, SessionCompressionDecisionSource) {
        match override_enabled {
            Some(true) => (
                SessionCompressionMode::Forced,
                SessionCompressionDecisionSource::ToolOverride,
            ),
            Some(false) => (
                SessionCompressionMode::Disabled,
                SessionCompressionDecisionSource::ToolOverride,
            ),
            None => (
                match self.config.resume_compression_default {
                    ResumeCompressionDefault::Auto => SessionCompressionMode::Auto,
                    ResumeCompressionDefault::Off => SessionCompressionMode::Disabled,
                },
                SessionCompressionDecisionSource::ServerDefault,
            ),
        }
    }

    async fn maybe_compress_session(
        &self,
        enabled: Option<bool>,
        request: &GeminiRequest,
        ct: CancellationToken,
        resume_plan: &ResumeExecutionPlan,
    ) -> Option<SessionCompressionResult> {
        let (mode, decision_source) = self.resolve_session_compression_policy(enabled);
        let requested = !matches!(mode, SessionCompressionMode::Disabled);

        if matches!(mode, SessionCompressionMode::Disabled) {
            return Some(SessionCompressionResult {
                mode: mode.as_str().to_string(),
                decision_source: decision_source.as_str().to_string(),
                requested,
                attempted: false,
                ok: false,
                skipped_reason: Some("disabled".to_string()),
                error_category: None,
                error: None,
                retry_count: None,
                compression_status: None,
                original_token_count: None,
                new_token_count: None,
                session_id: None,
                conversation_file: None,
            });
        }

        if !resume_plan.requested || resume_plan.selector.is_none() {
            return Some(SessionCompressionResult {
                mode: mode.as_str().to_string(),
                decision_source: decision_source.as_str().to_string(),
                requested,
                attempted: false,
                ok: false,
                skipped_reason: Some("resume_required".to_string()),
                error_category: None,
                error: None,
                retry_count: None,
                compression_status: None,
                original_token_count: None,
                new_token_count: None,
                session_id: None,
                conversation_file: None,
            });
        }

        let resume_selector = resume_plan
            .selector
            .as_deref()
            .expect("resume selector must be present when compression is attempted");
        let prompt_id = format!("mcp-compress:{resume_selector}");

        match execute_session_compression_bridge(
            &self.config,
            resume_selector,
            request.working_directory.as_deref(),
            &prompt_id,
            ct,
        )
        .await
        {
            Ok(result) => Some(session_compression_result_from_bridge(
                mode,
                decision_source,
                requested,
                result,
            )),
            Err(error) => {
                let (skipped_reason, error_category, error_text) =
                    if self.resume_provider.is_unavailable_error(&error)
                        && resume_plan.strategy.allows_fresh_fallback()
                    {
                        (
                            Some("resume_unavailable_fresh_fallback".to_string()),
                            Some(ErrorCategory::ResumeUnavailable.as_str().to_string()),
                            None,
                        )
                    } else {
                        let category = classify_execution_error(&error);
                        (
                            None,
                            Some(category.as_str().to_string()),
                            Some(error.to_string()),
                        )
                    };
                Some(SessionCompressionResult {
                    mode: mode.as_str().to_string(),
                    decision_source: decision_source.as_str().to_string(),
                    requested,
                    attempted: true,
                    ok: false,
                    skipped_reason,
                    error_category,
                    error: error_text,
                    retry_count: None,
                    compression_status: None,
                    original_token_count: None,
                    new_token_count: None,
                    session_id: None,
                    conversation_file: None,
                })
            }
        }
    }

    fn evaluate_context_guardrail(
        &self,
        resume: &ResumeLedgerState,
        usage: &ToolCallUsageAccumulator,
    ) -> Option<ContextGuardrailResult> {
        if !resume.applied {
            return None;
        }

        let percent_used = usage
            .context_window()
            .and_then(|snapshot| snapshot.percent_used);
        let threshold_percent = self.config.resume_context_warn_percent;
        Some(ContextGuardrailResult {
            mode: "warn".to_string(),
            warned: percent_used.is_some_and(|value| value >= threshold_percent as f64),
            threshold_percent,
            percent_used,
        })
    }

    fn resolve_resume_plan(
        &self,
        resume_selector: Option<String>,
        strategy: ResumeStrategy,
        validation_errors: &mut Vec<ValidationIssue>,
    ) -> Option<ResumeExecutionPlan> {
        match self
            .resume_provider
            .resolve(&self.config, resume_selector, strategy)
        {
            Ok(plan) => Some(plan),
            Err(err) => {
                validation_errors.push(ValidationIssue {
                    field: "resume".to_string(),
                    code: err.code.to_string(),
                    expected_type: "explicit Gemini session selector".to_string(),
                    received_type: "string".to_string(),
                    corrective_hint: format!("{} {}", err.message, err.corrective_hint),
                });
                None
            }
        }
    }

    fn classify_execution_error_with_resume(
        &self,
        err: &GeminiExecutionError,
        resume: &ResumeLedgerState,
    ) -> ErrorCategory {
        if resume.is_resume_unavailable() {
            ErrorCategory::ResumeUnavailable
        } else {
            classify_execution_error(err)
        }
    }

    async fn execute_with_resume_strategy(
        &self,
        request: &GeminiRequest,
        ct: CancellationToken,
        usage: &mut ToolCallUsageAccumulator,
        resume_plan: &ResumeExecutionPlan,
        resume_state: &mut ResumeLedgerState,
        invocation: &ToolInvocationContext,
    ) -> Result<GeminiResponse, GeminiExecutionError> {
        let mut resumed_request = request.clone();
        if resume_plan.selector.is_some() {
            resumed_request.resume = resume_plan.selector.clone();
        }

        match self
            .execute_with_usage(&resumed_request, ct.clone(), usage, invocation, 1)
            .await
        {
            Ok(output) => {
                if resume_plan.requested || resumed_request.resume.is_some() {
                    if !resume_state.requested {
                        resume_state.requested = true;
                        resume_state.selector = resumed_request.resume.clone();
                        if resume_state.strategy.is_none() {
                            resume_state.strategy = Some(resume_plan.strategy.as_str().to_string());
                        }
                    }
                    resume_state.mark_applied();
                }
                Ok(output)
            }
            Err(err) => {
                if !resume_plan.requested || !self.resume_provider.is_unavailable_error(&err) {
                    return Err(err);
                }

                if !resume_plan.strategy.allows_fresh_fallback() {
                    resume_state.mark_invalid();
                    return Err(err);
                }

                self.invocation_observer
                    .on_event(GeminiInvocationEvent::new(
                        invocation.metadata.clone(),
                        GeminiInvocationEventKind::RetryScheduled {
                            next_attempt: 2,
                            reason: "resume_unavailable_fallback_to_fresh".to_string(),
                            delay_ms: 0,
                        },
                    ));

                let mut fresh_request = request.clone();
                fresh_request.resume = None;
                match self
                    .execute_with_usage(&fresh_request, ct, usage, invocation, 2)
                    .await
                {
                    Ok(output) => {
                        resume_state.mark_missing_fallback();
                        Ok(output)
                    }
                    Err(fallback_err) => {
                        resume_state.mark_missing_fallback_failed();
                        Err(fallback_err)
                    }
                }
            }
        }
    }

    async fn execute_with_resume_and_quota_downgrade(
        &self,
        request: &GeminiRequest,
        ct: CancellationToken,
        usage: &mut ToolCallUsageAccumulator,
        resume_plan: &ResumeExecutionPlan,
        resume_state: &mut ResumeLedgerState,
        invocation: &mut ToolInvocationContext,
        model: &mut ResolvedModel,
    ) -> Result<GeminiResponse, GeminiExecutionError> {
        match self
            .execute_with_resume_strategy(
                request,
                ct.clone(),
                usage,
                resume_plan,
                resume_state,
                invocation,
            )
            .await
        {
            Ok(output) => Ok(output),
            Err(error) => {
                let category = self.classify_execution_error_with_resume(&error, resume_state);
                if !matches!(category, ErrorCategory::QuotaOrRateLimit) {
                    return Err(error);
                }

                let Some(active_model) = model.used.clone() else {
                    return Err(error);
                };
                let allowlist = normalize_model_list(&self.config.model_allowlist);
                let Some(fallback_model) =
                    next_allowlisted_downgrade_model(&allowlist, &active_model)
                else {
                    return Err(error);
                };
                if fallback_model.eq_ignore_ascii_case(&active_model) {
                    return Err(error);
                }

                let next_attempt = usage.gemini_invocations.saturating_add(1).max(1);
                self.invocation_observer
                    .on_event(GeminiInvocationEvent::new(
                        invocation.metadata.clone(),
                        GeminiInvocationEventKind::RetryScheduled {
                            next_attempt,
                            reason: format!(
                                "quota_model_fallback:{}->{}",
                                active_model, fallback_model
                            ),
                            delay_ms: 0,
                        },
                    ));

                let mut fallback_request = request.clone();
                fallback_request.model = Some(fallback_model.clone());
                let mut fallback_resume_plan = resume_plan.clone();
                let mut fallback_resume_state = resume_state.clone();
                if !fallback_resume_plan.requested {
                    if let Some(resolved_session_id) =
                        resolve_session_id_from_gemini_error(&error, resume_plan, resume_state)
                    {
                        fallback_resume_plan.requested = true;
                        fallback_resume_plan.selector = Some(resolved_session_id.clone());
                        fallback_resume_state.requested = true;
                        fallback_resume_state.selector = Some(resolved_session_id.clone());
                        fallback_resume_state.strategy =
                            Some(fallback_resume_plan.strategy.as_str().to_string());
                        invocation.metadata.resume_requested = true;
                        invocation.metadata.resume_selector = Some(resolved_session_id);
                        invocation.metadata.resume_strategy =
                            Some(fallback_resume_plan.strategy.as_str().to_string());
                    }
                }

                match self
                    .execute_with_resume_strategy(
                        &fallback_request,
                        ct,
                        usage,
                        &fallback_resume_plan,
                        &mut fallback_resume_state,
                        invocation,
                    )
                    .await
                {
                    Ok(output) => {
                        *resume_state = fallback_resume_state;
                        model.used = Some(fallback_model.clone());
                        model.default_model_applied = false;
                        model.fallback_mode = "quota_model_fallback";
                        model.fallback_reason = Some(format!(
                            "Downgraded from '{active_model}' to '{fallback_model}' after quota/rate-limit failure."
                        ));
                        invocation.metadata.resume_requested = resume_state.requested;
                        invocation.metadata.resume_selector = resume_state.selector.clone();
                        invocation.metadata.resume_strategy = resume_state.strategy.clone();
                        invocation.metadata.model_used = model.used.clone();
                        Ok(output)
                    }
                    Err(fallback_error) => {
                        *resume_state = fallback_resume_state;
                        invocation.metadata.resume_requested = resume_state.requested;
                        invocation.metadata.resume_selector = resume_state.selector.clone();
                        invocation.metadata.resume_strategy = resume_state.strategy.clone();
                        Err(fallback_error)
                    }
                }
            }
        }
    }

    async fn execute_ask_gemini(
        &self,
        request: &GeminiRequest,
        ct: CancellationToken,
        usage: &mut ToolCallUsageAccumulator,
        resume_plan: &ResumeExecutionPlan,
        resume_state: &mut ResumeLedgerState,
        invocation: &mut ToolInvocationContext,
        model: &mut ResolvedModel,
        sql_guardrails: Option<&AskGeminiSqlGuardrails>,
    ) -> Result<AskGeminiExecutionOutcome, AskGeminiExecutionFailure> {
        let output = self
            .execute_with_resume_and_quota_downgrade(
                request,
                ct.clone(),
                usage,
                resume_plan,
                resume_state,
                invocation,
                model,
            )
            .await
            .map_err(AskGeminiExecutionFailure::Execution)?;

        let Some(guardrails) = sql_guardrails else {
            return Ok(AskGeminiExecutionOutcome {
                output,
                response_json: None,
                guardrail_repair_used: false,
            });
        };

        let mut latest_drift = match validate_sql_guardrail_output(&output.stdout, guardrails) {
            Ok(payload) => {
                return Ok(AskGeminiExecutionOutcome {
                    output,
                    response_json: Some(payload),
                    guardrail_repair_used: false,
                });
            }
            Err(drift) => {
                usage.guardrail_metrics.record_drift(&drift);
                if guardrails.repair_attempts == 0 {
                    usage.guardrail_metrics.drift_failed =
                        usage.guardrail_metrics.drift_failed.saturating_add(1);
                    return Err(AskGeminiExecutionFailure::Contract(drift));
                }
                drift
            }
        };

        for repair_index in 0..guardrails.repair_attempts {
            let next_attempt = usage.gemini_invocations.saturating_add(1).max(1);
            self.invocation_observer
                .on_event(GeminiInvocationEvent::new(
                    invocation.metadata.clone(),
                    GeminiInvocationEventKind::RetryScheduled {
                        next_attempt,
                        reason: format!("response_contract_repair:{}", latest_drift.reason_code),
                        delay_ms: 0,
                    },
                ));

            let mut repair_request = request.clone();
            repair_request.resume = None;
            repair_request.prompt =
                build_sql_guardrail_repair_prompt(&request.prompt, &latest_drift, guardrails);

            let repair_output = self
                .execute_with_usage(&repair_request, ct.clone(), usage, invocation, next_attempt)
                .await
                .map_err(AskGeminiExecutionFailure::Execution)?;

            match validate_sql_guardrail_output(&repair_output.stdout, guardrails) {
                Ok(payload) => {
                    usage.guardrail_metrics.drift_repaired =
                        usage.guardrail_metrics.drift_repaired.saturating_add(1);
                    return Ok(AskGeminiExecutionOutcome {
                        output: repair_output,
                        response_json: Some(payload),
                        guardrail_repair_used: true,
                    });
                }
                Err(drift) => {
                    usage.guardrail_metrics.record_drift(&drift);
                    latest_drift = drift;
                    if repair_index + 1 == guardrails.repair_attempts {
                        usage.guardrail_metrics.drift_failed =
                            usage.guardrail_metrics.drift_failed.saturating_add(1);
                    }
                }
            }
        }

        Err(AskGeminiExecutionFailure::Contract(latest_drift))
    }

    fn record_tool_usage(
        &self,
        tool_name: &str,
        started_at: Instant,
        model: &ResolvedModel,
        resume: &ResumeLedgerState,
        ok: bool,
        error_category: Option<&str>,
        usage: &ToolCallUsageAccumulator,
        invocation: &ToolInvocationContext,
        result: Option<&InvocationResultMetadata>,
        resolved_session_id: Option<&str>,
        session_compression: Option<&SessionCompressionResult>,
        context_guardrail: Option<&ContextGuardrailResult>,
    ) {
        let mut usage_summary = usage.usage.clone();
        usage_summary.normalize_totals();
        let duration_ms = started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let (failure_class, retryability, salvageability) =
            reliability_metadata_from_error_label(error_category);
        let result = result.cloned().unwrap_or_default();
        let record = ToolUsageLedgerRecord {
            version: 3,
            timestamp_ms: current_unix_timestamp_ms(),
            tool_name: tool_name.to_string(),
            invocation_id: invocation.metadata.invocation_id.clone(),
            resolved_session_id: resolved_session_id.map(str::to_string),
            ok,
            error_category: error_category.map(str::to_string),
            failure_class,
            retryability,
            salvageability,
            result_source: result.result_source,
            degraded: result.degraded,
            stale_age_ms: result.stale_age_ms,
            live_error_category: result.live_error_category,
            duration_ms,
            gemini_invocations: usage.gemini_invocations,
            retry_count: retry_count_from_invocations(usage.gemini_invocations),
            model_requested: model.requested.clone(),
            model_used: model.used.clone(),
            resume_requested: resume.requested,
            resume_selector: resume.selector.clone(),
            resume_strategy: resume.strategy.clone(),
            resume_applied: resume.applied,
            resume_outcome: resume.outcome_label(),
            default_model_applied: model.default_model_applied,
            fallback_mode: model.fallback_mode.to_string(),
            fallback_reason: model.fallback_reason.clone(),
            effective_scope_roots: invocation.metadata.effective_scope_roots.clone(),
            nested_mcp_policy: invocation.metadata.nested_mcp_policy.clone(),
            usage_source: usage
                .usage_source()
                .or_else(|| Some("unavailable".to_string())),
            input_tokens: usage_summary.input_tokens,
            output_tokens: usage_summary.output_tokens,
            total_tokens: usage_summary.total_tokens,
            reasoning_tokens: usage_summary.reasoning_tokens,
            cache_read_tokens: usage_summary.cache_read_tokens,
            cache_write_tokens: usage_summary.cache_write_tokens,
            context_window_percent_used: usage.context_window().and_then(|v| v.percent_used),
            context_window_percent_remaining: usage
                .context_window()
                .and_then(|v| v.percent_remaining),
            context_window_source: usage.context_window().and_then(|v| v.source.clone()),
            session_compression_mode: session_compression.map(|value| value.mode.clone()),
            session_compression_attempted: session_compression
                .map(|value| value.attempted)
                .unwrap_or(false),
            session_compression_ok: session_compression
                .filter(|value| value.attempted)
                .map(|value| value.ok),
            session_compression_skipped_reason: session_compression
                .and_then(|value| value.skipped_reason.clone()),
            context_guardrail_warned: context_guardrail.map(|value| value.warned).unwrap_or(false),
            context_guardrail_threshold_percent: context_guardrail
                .map(|value| value.threshold_percent),
            drift_detected: usage.guardrail_metrics.drift_detected,
            drift_repaired: usage.guardrail_metrics.drift_repaired,
            drift_failed: usage.guardrail_metrics.drift_failed,
            invalid_table_refs: usage.guardrail_metrics.invalid_table_refs,
            citation_missing: usage.guardrail_metrics.citation_missing,
        };
        self.usage_ledger.record(&record);
    }

    fn record_response_envelope_debug(
        &self,
        invocation_id: Option<&str>,
        tool_name: &str,
        model: &ResolvedModel,
        resume: &ResumeLedgerState,
        response_envelope: Value,
    ) {
        let record = ResponseEnvelopeDebugRecord {
            version: 1,
            timestamp_ms: current_unix_timestamp_ms(),
            invocation_id: invocation_id.map(str::to_string),
            tool_name: tool_name.to_string(),
            model_used: model.used.clone(),
            resume_requested: resume.requested,
            resume_selector: resume.selector.clone(),
            resume_strategy: resume.strategy.clone(),
            resume_outcome: resume.outcome_label(),
            response_envelope,
        };
        self.response_debug_artifact.record(&record);
    }

    fn emit_started(&self, invocation: &ToolInvocationContext) {
        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::Started,
            ));
        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::Phase {
                    attempt: 1,
                    phase: GeminiInvocationPhase::ToolCallStarted,
                    pid: None,
                },
            ));
    }

    fn emit_validation_failed(&self, invocation: &ToolInvocationContext, error_category: &str) {
        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::ValidationFailed {
                    error_category: error_category.to_string(),
                },
            ));
    }

    fn emit_finished(
        &self,
        invocation: &ToolInvocationContext,
        started_at: Instant,
        model: &ResolvedModel,
        resume: &ResumeLedgerState,
        ok: bool,
        error_category: Option<&str>,
        usage: &ToolCallUsageAccumulator,
        result: Option<&InvocationResultMetadata>,
        session_compression: Option<&SessionCompressionResult>,
        context_guardrail: Option<&ContextGuardrailResult>,
    ) {
        let mut usage_summary = usage.usage.clone();
        usage_summary.normalize_totals();
        let duration_ms = started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let terminal_attempt = usage.gemini_invocations.max(1);
        let (failure_class, retryability, salvageability) =
            reliability_metadata_from_error_label(error_category);
        let result = result.cloned().unwrap_or_default();
        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::Phase {
                    attempt: terminal_attempt,
                    phase: GeminiInvocationPhase::ToolCallFinished,
                    pid: None,
                },
            ));
        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::Phase {
                    attempt: terminal_attempt,
                    phase: GeminiInvocationPhase::Completed,
                    pid: None,
                },
            ));
        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::Finished {
                    ok,
                    error_category: error_category.map(str::to_string),
                    failure_class,
                    retryability,
                    salvageability,
                    result_source: result.result_source,
                    degraded: result.degraded,
                    stale_age_ms: result.stale_age_ms,
                    live_error_category: result.live_error_category,
                    duration_ms,
                    gemini_invocations: usage.gemini_invocations,
                    retry_count: retry_count_from_invocations(usage.gemini_invocations),
                    usage: GeminiUsageSnapshot {
                        input_tokens: usage_summary.input_tokens,
                        output_tokens: usage_summary.output_tokens,
                        total_tokens: usage_summary.total_tokens,
                        reasoning_tokens: usage_summary.reasoning_tokens,
                        cache_read_tokens: usage_summary.cache_read_tokens,
                        cache_write_tokens: usage_summary.cache_write_tokens,
                    },
                    usage_source: usage
                        .usage_source()
                        .or_else(|| Some("unavailable".to_string())),
                    context_window_percent_used: usage
                        .context_window()
                        .and_then(|snapshot| snapshot.percent_used),
                    context_window_percent_remaining: usage
                        .context_window()
                        .and_then(|snapshot| snapshot.percent_remaining),
                    context_window_source: usage
                        .context_window()
                        .and_then(|snapshot| snapshot.source.clone()),
                    session_compression_mode: session_compression.map(|value| value.mode.clone()),
                    session_compression_attempted: session_compression
                        .map(|value| value.attempted)
                        .unwrap_or(false),
                    session_compression_ok: session_compression
                        .filter(|value| value.attempted)
                        .map(|value| value.ok),
                    session_compression_skipped_reason: session_compression
                        .and_then(|value| value.skipped_reason.clone()),
                    context_guardrail_warned: context_guardrail
                        .map(|value| value.warned)
                        .unwrap_or(false),
                    context_guardrail_threshold_percent: context_guardrail
                        .map(|value| value.threshold_percent),
                    resume_applied: resume.applied,
                    resume_outcome: resume.outcome_label(),
                    fallback_mode: model.fallback_mode.to_string(),
                    fallback_reason: model.fallback_reason.clone(),
                },
            ));
    }

    fn prepare_ask_gemini(
        &self,
        args: AskGeminiArgs,
        parts: &Parts,
    ) -> Result<PreparedAskGemini, CallToolResult> {
        let started_at = Instant::now();
        let resume_selector_hint = args
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut invocation = ToolInvocationContext::new(
            "ask-gemini",
            args.model.clone(),
            None,
            resume_selector_hint.clone(),
            resume_selector_hint
                .as_ref()
                .map(|_| args.resume_strategy.as_str().to_string()),
            resume_selector_hint.is_some(),
            args.sandbox,
            parts,
        );

        let mut validation_errors = Vec::new();
        let resume_early =
            ResumeLedgerState::from_request(resume_selector_hint.clone(), args.resume_strategy);
        let mut prompt =
            validate_required_text_field("prompt", &args.prompt, &mut validation_errors);
        let sql_guardrails = args
            .sql_guardrails
            .and_then(|raw| AskGeminiSqlGuardrails::from_args(raw, &mut validation_errors));
        let mut request_include_directories = Vec::new();
        let mut request_working_directory = None;
        if matches!(self.config.ask_gemini_policy, AskGeminiPolicy::ScopedOnly) {
            if self.config.ask_gemini_allowed_roots.is_empty() {
                return Err(response_with_metadata_and_resume(
                    ask_gemini_payload(
                        json!({
                            "ok": false,
                            "error_category": ErrorCategory::InputValidation.as_str(),
                            "error": "request payload failed validation",
                        }),
                        args.explain,
                        None,
                    ),
                    &[ValidationIssue {
                        field: "target".to_string(),
                        code: "server_config_invalid".to_string(),
                        expected_type: "non-empty GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS".to_string(),
                        received_type: "empty".to_string(),
                        corrective_hint:
                            "Configure GEMINI_MCP_ASK_GEMINI_ALLOWED_ROOTS before using scoped ask-gemini mode."
                                .to_string(),
                    }],
                    &ResolvedModel {
                        requested: None,
                        used: None,
                        default_model_applied: false,
                        fallback_mode: "none",
                        fallback_reason: None,
                    },
                    &resume_early,
                ));
            }

            if let Some(target) = resolve_scoped_ask_gemini_target(
                args.target.as_deref(),
                std::env::current_dir(),
                &self.config.ask_gemini_allowed_roots,
                &mut validation_errors,
            ) {
                request_include_directories.push(target.clone());
                request_working_directory = Some(target);
            }
        }
        if let Some(prompt_value) = prompt.take() {
            prompt = Some(match sql_guardrails.as_ref() {
                Some(guardrails) => build_sql_guardrail_prompt(&prompt_value, guardrails),
                None => prompt_value,
            });
        }
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);
        let resume_selector =
            normalize_optional_resume_selector(args.resume, &mut validation_errors);
        let allowed_mcp_servers =
            default_to_no_nested_mcp_servers(normalize_allowed_mcp_servers_override(
                args.allowed_mcp_server_names,
                &mut validation_errors,
            ));
        let resume_plan = self.resolve_resume_plan(
            resume_selector,
            args.resume_strategy,
            &mut validation_errors,
        );

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = requested_model.clone();

        if let Some(_prompt) = prompt.as_ref() {
            match resolve_model(&self.config, requested_model.clone()) {
                Ok(resolution) => {
                    model = resolution;
                    invocation.metadata.model_used = model.used.clone();
                }
                Err(ErrorCategory::ModelNotAllowed) => {
                    validation_errors.push(model_not_allowed_issue(
                        &self.config.model_allowlist,
                        requested_model.as_deref(),
                    ));
                    return Err(response_with_metadata_and_resume(
                        ask_gemini_payload(
                            json!({
                                "ok": false,
                                "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                                "error": "requested model is not allowed by policy",
                            }),
                            args.explain,
                            None,
                        ),
                        &validation_errors,
                        &model,
                        &resume_early,
                    ));
                }
                Err(category) => {
                    return Err(response_with_metadata_and_resume(
                        ask_gemini_payload(
                            json!({
                                "ok": false,
                                "error_category": category.as_str(),
                                "error": "model resolution failed",
                            }),
                            args.explain,
                            None,
                        ),
                        &validation_errors,
                        &model,
                        &resume_early,
                    ));
                }
            }
        }

        if !validation_errors.is_empty() {
            return Err(response_with_metadata_and_resume(
                ask_gemini_payload(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::InputValidation.as_str(),
                        "error": "request payload failed validation",
                    }),
                    args.explain,
                    None,
                ),
                &validation_errors,
                &model,
                &resume_early,
            ));
        }

        let resume_plan = resume_plan.expect("resume plan should be available after validation");
        let resume = ResumeLedgerState::from_plan(&resume_plan);
        invocation.metadata.resume_requested = resume.requested;
        invocation.metadata.resume_selector = resume.selector.clone();
        invocation.metadata.resume_strategy = resume.strategy.clone();
        let prompt = apply_ask_explain_mode_prompt(
            prompt.expect("validated prompt must be present"),
            args.explain,
        );
        let request = GeminiRequest {
            prompt,
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers,
            output_format: args.response_mode.output_format(),
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: request_include_directories,
            working_directory: request_working_directory,
            ..Default::default()
        };
        invocation.set_request_policy(
            &request.include_directories,
            request.allowed_mcp_servers.as_ref(),
        );
        Ok(PreparedAskGemini {
            started_at,
            invocation,
            validation_errors,
            model,
            resume_plan,
            resume,
            request,
            sql_guardrails,
            explain: args.explain,
            response_mode: args.response_mode,
            compress_session: args.compress_session,
        })
    }

    async fn run_prepared_ask_gemini(
        &self,
        mut prepared: PreparedAskGemini,
        ct: CancellationToken,
    ) -> CallToolResult {
        self.emit_started(&prepared.invocation);
        let session_compression = self
            .maybe_compress_session(
                prepared.compress_session,
                &prepared.request,
                ct.clone(),
                &prepared.resume_plan,
            )
            .await;

        let mut usage = ToolCallUsageAccumulator::default();
        match self
            .execute_ask_gemini(
                &prepared.request,
                ct,
                &mut usage,
                &prepared.resume_plan,
                &mut prepared.resume,
                &mut prepared.invocation,
                &mut prepared.model,
                prepared.sql_guardrails.as_ref(),
            )
            .await
        {
            Ok(outcome) => {
                let resolved_session_id = resolve_session_id_from_gemini_output(
                    &outcome.output,
                    &prepared.resume_plan,
                    &prepared.resume,
                );
                let context_guardrail = self.evaluate_context_guardrail(&prepared.resume, &usage);
                let normalized_output = normalize_ask_gemini_output(&outcome.output.stdout);
                let mut response_json = outcome.response_json;
                if !matches!(prepared.response_mode, AskGeminiResponseMode::Full)
                    && response_json.is_none()
                {
                    response_json = normalized_output.response_json.clone();
                }
                if let Some(envelope) = normalized_output.response_envelope.clone() {
                    self.record_response_envelope_debug(
                        Some(prepared.invocation.metadata.invocation_id.as_str()),
                        "ask-gemini",
                        &prepared.model,
                        &prepared.resume,
                        envelope.clone(),
                    );
                }
                let response_text = if matches!(prepared.response_mode, AskGeminiResponseMode::Full)
                {
                    outcome.output.stdout.clone()
                } else {
                    normalized_output.response_text
                };
                let response_text = if response_text.trim().is_empty() {
                    ask_gemini_response_text_fallback(
                        response_json.as_ref(),
                        normalized_output.response_envelope.as_ref(),
                        &outcome.output.stdout,
                    )
                    .unwrap_or(response_text)
                } else {
                    response_text
                };
                if response_text.trim().is_empty() {
                    self.record_tool_usage(
                        "ask-gemini",
                        prepared.started_at,
                        &prepared.model,
                        &prepared.resume,
                        false,
                        Some(ErrorCategory::ResponseContract.as_str()),
                        &usage,
                        &prepared.invocation,
                        None,
                        resolved_session_id.as_deref(),
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    self.emit_finished(
                        &prepared.invocation,
                        prepared.started_at,
                        &prepared.model,
                        &prepared.resume,
                        false,
                        Some(ErrorCategory::ResponseContract.as_str()),
                        &usage,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    let payload = attach_runtime_metadata(
                        ask_gemini_payload(
                            json!({
                                "ok": false,
                                "error_category": ErrorCategory::ResponseContract.as_str(),
                                "error": "gemini returned an empty response for ask-gemini",
                                "response_json": response_json,
                                "stdout": outcome.output.stdout,
                                "stderr": outcome.output.stderr,
                            }),
                            prepared.explain,
                            resolved_session_id.as_deref(),
                        ),
                        usage.context_window(),
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    return response_with_metadata_and_resume(
                        payload,
                        &prepared.validation_errors,
                        &prepared.model,
                        &prepared.resume,
                    );
                }
                self.record_tool_usage(
                    "ask-gemini",
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    true,
                    None,
                    &usage,
                    &prepared.invocation,
                    None,
                    resolved_session_id.as_deref(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &prepared.invocation,
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    true,
                    None,
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let mut response = serde_json::Map::new();
                response.insert("ok".to_string(), json!(true));
                response.insert("response".to_string(), json!(response_text));
                if prepared.response_mode.include_stderr() {
                    response.insert("stderr".to_string(), json!(outcome.output.stderr));
                }
                if let Some(response_json) = response_json {
                    response.insert("response_json".to_string(), response_json);
                }
                if let Some(Value::Object(envelope)) = normalized_output.response_envelope {
                    for (key, value) in envelope {
                        if key == "response" || response.contains_key(&key) {
                            continue;
                        }
                        response.insert(key, value);
                    }
                }
                if prepared.sql_guardrails.is_some() {
                    response.insert(
                        "sql_guardrails".to_string(),
                        json!({
                            "enabled": true,
                            "repair_used": outcome.guardrail_repair_used,
                            "metrics": usage.guardrail_metrics.clone(),
                        }),
                    );
                }
                let payload = attach_runtime_metadata(
                    ask_gemini_payload(
                        Value::Object(response),
                        prepared.explain,
                        resolved_session_id.as_deref(),
                    ),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                response_with_metadata_and_resume(
                    payload,
                    &prepared.validation_errors,
                    &prepared.model,
                    &prepared.resume,
                )
            }
            Err(AskGeminiExecutionFailure::Execution(error)) => {
                let category = self.classify_execution_error_with_resume(&error, &prepared.resume);
                let resolved_session_id = resolve_session_id_from_gemini_error(
                    &error,
                    &prepared.resume_plan,
                    &prepared.resume,
                );
                let context_guardrail = self.evaluate_context_guardrail(&prepared.resume, &usage);
                self.record_tool_usage(
                    "ask-gemini",
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &prepared.invocation,
                    None,
                    resolved_session_id.as_deref(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &prepared.invocation,
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    ask_gemini_payload(
                        json!({
                            "ok": false,
                            "error_category": category.as_str(),
                            "error": error.to_string(),
                        }),
                        prepared.explain,
                        resolved_session_id.as_deref(),
                    ),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                response_with_metadata_and_resume(
                    payload,
                    &prepared.validation_errors,
                    &prepared.model,
                    &prepared.resume,
                )
            }
            Err(AskGeminiExecutionFailure::Contract(drift)) => {
                let context_guardrail = self.evaluate_context_guardrail(&prepared.resume, &usage);
                self.record_tool_usage(
                    "ask-gemini",
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(ErrorCategory::ResponseContract.as_str()),
                    &usage,
                    &prepared.invocation,
                    None,
                    prepared.resume.selector.as_deref(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &prepared.invocation,
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(ErrorCategory::ResponseContract.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    ask_gemini_payload(
                        json!({
                            "ok": false,
                            "error_category": ErrorCategory::ResponseContract.as_str(),
                            "error": drift.summary(),
                            "contract_drift": {
                                "reason_code": drift.reason_code,
                                "issues": drift.issues,
                                "invalid_table_refs": drift.invalid_table_refs,
                                "citation_missing": drift.citation_missing,
                            }
                        }),
                        prepared.explain,
                        prepared.resume.selector.as_deref(),
                    ),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                response_with_metadata_and_resume(
                    payload,
                    &prepared.validation_errors,
                    &prepared.model,
                    &prepared.resume,
                )
            }
        }
    }

    fn prepare_codebase_scout(
        &self,
        args: CodebaseScoutArgs,
        parts: &Parts,
    ) -> Result<PreparedCodebaseScout, CallToolResult> {
        let started_at = Instant::now();
        let resume_selector_hint = args
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut invocation = ToolInvocationContext::new(
            "codebase-scout",
            args.model.clone(),
            None,
            resume_selector_hint.clone(),
            resume_selector_hint
                .as_ref()
                .map(|_| args.resume_strategy.as_str().to_string()),
            resume_selector_hint.is_some(),
            args.sandbox,
            parts,
        );

        let mut validation_errors = Vec::new();
        let resume_early =
            ResumeLedgerState::from_request(resume_selector_hint.clone(), args.resume_strategy);
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let question =
            validate_required_text_field("question", &args.question, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);
        let resume_selector =
            normalize_optional_resume_selector(args.resume, &mut validation_errors);
        let allowed_mcp_servers =
            default_to_no_nested_mcp_servers(normalize_allowed_mcp_servers_override(
                args.allowed_mcp_server_names,
                &mut validation_errors,
            ));
        let resume_plan = self.resolve_resume_plan(
            resume_selector,
            args.resume_strategy,
            &mut validation_errors,
        );

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = requested_model.clone();

        if !validation_errors.is_empty() {
            return Err(response_with_metadata_and_resume(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
                &resume_early,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => {
                model = resolution;
                invocation.metadata.model_used = model.used.clone();
            }
            Err(ErrorCategory::ModelNotAllowed) => {
                let mut errors = validation_errors;
                errors.push(model_not_allowed_issue(
                    &self.config.model_allowlist,
                    requested_model.as_deref(),
                ));
                return Err(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &errors,
                    &model,
                    &resume_early,
                ));
            }
            Err(category) => {
                return Err(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
        }

        let resume_plan = resume_plan.expect("resume plan should be available after validation");
        let resume = ResumeLedgerState::from_plan(&resume_plan);
        invocation.metadata.resume_requested = resume.requested;
        invocation.metadata.resume_selector = resume.selector.clone();
        invocation.metadata.resume_strategy = resume.strategy.clone();
        let target = target.expect("validated target must be present");
        let question = question.expect("validated question must be present");
        let request = GeminiRequest {
            prompt: codebase_scout_prompt(&target, &question),
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers: allowed_mcp_servers.clone(),
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target.clone()),
            ..Default::default()
        };
        invocation.set_request_policy(
            &request.include_directories,
            request.allowed_mcp_servers.as_ref(),
        );
        let fallback_request = GeminiRequest {
            prompt: codebase_scout_fallback_prompt(&target, &question),
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target),
            ..Default::default()
        };
        Ok(PreparedCodebaseScout {
            started_at,
            invocation,
            validation_errors,
            model,
            resume_plan,
            resume,
            request,
            fallback_request,
            compress_session: args.compress_session,
        })
    }

    async fn run_prepared_codebase_scout(
        &self,
        mut prepared: PreparedCodebaseScout,
        ct: CancellationToken,
    ) -> CallToolResult {
        self.emit_started(&prepared.invocation);
        let session_compression = self
            .maybe_compress_session(
                prepared.compress_session,
                &prepared.request,
                ct.clone(),
                &prepared.resume_plan,
            )
            .await;
        let mut usage = ToolCallUsageAccumulator::default();
        match self
            .execute_with_resume_and_quota_downgrade(
                &prepared.request,
                ct.clone(),
                &mut usage,
                &prepared.resume_plan,
                &mut prepared.resume,
                &mut prepared.invocation,
                &mut prepared.model,
            )
            .await
        {
            Ok(output) => match self.parse_codebase_tool_output(
                "codebase-scout",
                &prepared.model,
                &prepared.resume,
                &output.stdout,
            ) {
                Some(value) => {
                    let context_guardrail =
                        self.evaluate_context_guardrail(&prepared.resume, &usage);
                    self.record_tool_usage(
                        "codebase-scout",
                        prepared.started_at,
                        &prepared.model,
                        &prepared.resume,
                        true,
                        None,
                        &usage,
                        &prepared.invocation,
                        None,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    let payload = attach_runtime_metadata(
                        value,
                        usage.context_window(),
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    self.emit_finished(
                        &prepared.invocation,
                        prepared.started_at,
                        &prepared.model,
                        &prepared.resume,
                        true,
                        None,
                        &usage,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    response_with_metadata_and_resume(
                        payload,
                        &prepared.validation_errors,
                        &prepared.model,
                        &prepared.resume,
                    )
                }
                None => {
                    if let Some(category) = blocking_codebase_fallback_category(&output.stderr) {
                        let context_guardrail =
                            self.evaluate_context_guardrail(&prepared.resume, &usage);
                        self.record_tool_usage(
                            "codebase-scout",
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            &prepared.invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &prepared.invocation,
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        let payload = attach_runtime_metadata(
                            json!({
                                "ok": false,
                                "error_category": category.as_str(),
                                "error": "gemini returned invalid structured output and stderr indicates a non-contract execution failure",
                                "stderr": output.stderr,
                            }),
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        return response_with_metadata_and_resume(
                            payload,
                            &prepared.validation_errors,
                            &prepared.model,
                            &prepared.resume,
                        );
                    }
                    let mut retry_model = prepared.model.clone();
                    retry_model.fallback_mode = "fallback_prompt";
                    retry_model.fallback_reason = Some(
                        "primary output was empty or invalid JSON; using fallback schema-constrained prompt."
                            .to_string(),
                    );
                    match self
                        .execute_with_resume_and_quota_downgrade(
                            &prepared.fallback_request,
                            ct,
                            &mut usage,
                            &prepared.resume_plan,
                            &mut prepared.resume,
                            &mut prepared.invocation,
                            &mut retry_model,
                        )
                        .await
                    {
                        Ok(second_output) => match self.parse_codebase_tool_output(
                            "codebase-scout",
                            &retry_model,
                            &prepared.resume,
                            &second_output.stdout,
                        ) {
                            Some(value) => {
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&prepared.resume, &usage);
                                self.record_tool_usage(
                                    "codebase-scout",
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    true,
                                    None,
                                    &usage,
                                    &prepared.invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    value,
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &prepared.invocation,
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    true,
                                    None,
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                response_with_metadata_and_resume(
                                    payload,
                                    &prepared.validation_errors,
                                    &retry_model,
                                    &prepared.resume,
                                )
                            }
                            None => {
                                let category =
                                    blocking_codebase_fallback_category(&second_output.stderr)
                                        .unwrap_or(ErrorCategory::ResponseContract);
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&prepared.resume, &usage);
                                self.record_tool_usage(
                                    "codebase-scout",
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    &prepared.invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &prepared.invocation,
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    json!({
                                        "ok": false,
                                        "error_category": category.as_str(),
                                        "error": "gemini returned an empty or invalid response for codebase-scout after retry",
                                        "first_stderr": output.stderr,
                                        "second_stderr": second_output.stderr,
                                    }),
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                response_with_metadata_and_resume(
                                    payload,
                                    &prepared.validation_errors,
                                    &retry_model,
                                    &prepared.resume,
                                )
                            }
                        },
                        Err(err) => {
                            let category =
                                self.classify_execution_error_with_resume(&err, &prepared.resume);
                            let context_guardrail =
                                self.evaluate_context_guardrail(&prepared.resume, &usage);
                            self.record_tool_usage(
                                "codebase-scout",
                                prepared.started_at,
                                &retry_model,
                                &prepared.resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                &prepared.invocation,
                                None,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            self.emit_finished(
                                &prepared.invocation,
                                prepared.started_at,
                                &retry_model,
                                &prepared.resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            let payload = attach_runtime_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": category.as_str(),
                                    "error": err.to_string(),
                                    "retry_used": true,
                                }),
                                usage.context_window(),
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            response_with_metadata_and_resume(
                                payload,
                                &prepared.validation_errors,
                                &retry_model,
                                &prepared.resume,
                            )
                        }
                    }
                }
            },
            Err(err) => {
                let category = self.classify_execution_error_with_resume(&err, &prepared.resume);
                let context_guardrail = self.evaluate_context_guardrail(&prepared.resume, &usage);
                self.record_tool_usage(
                    "codebase-scout",
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &prepared.invocation,
                    None,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &prepared.invocation,
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                response_with_metadata_and_resume(
                    payload,
                    &prepared.validation_errors,
                    &prepared.model,
                    &prepared.resume,
                )
            }
        }
    }

    fn prepare_codebase_investigator(
        &self,
        args: CodebaseInvestigatorArgs,
        parts: &Parts,
    ) -> Result<PreparedCodebaseInvestigator, CallToolResult> {
        let started_at = Instant::now();
        let resume_selector_hint = args
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut invocation = ToolInvocationContext::new(
            "codebase-investigator",
            args.model.clone(),
            None,
            resume_selector_hint.clone(),
            resume_selector_hint
                .as_ref()
                .map(|_| args.resume_strategy.as_str().to_string()),
            resume_selector_hint.is_some(),
            args.sandbox,
            parts,
        );

        let mut validation_errors = Vec::new();
        let resume_early =
            ResumeLedgerState::from_request(resume_selector_hint.clone(), args.resume_strategy);
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let objective =
            validate_required_text_field("objective", &args.objective, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);
        let resume_selector =
            normalize_optional_resume_selector(args.resume, &mut validation_errors);
        let allowed_mcp_servers =
            default_to_no_nested_mcp_servers(normalize_allowed_mcp_servers_override(
                args.allowed_mcp_server_names,
                &mut validation_errors,
            ));
        let resume_plan = self.resolve_resume_plan(
            resume_selector,
            args.resume_strategy,
            &mut validation_errors,
        );

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = requested_model.clone();

        if !validation_errors.is_empty() {
            return Err(response_with_metadata_and_resume(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
                &resume_early,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => {
                model = resolution;
                invocation.metadata.model_used = model.used.clone();
            }
            Err(ErrorCategory::ModelNotAllowed) => {
                let mut errors = validation_errors;
                errors.push(model_not_allowed_issue(
                    &self.config.model_allowlist,
                    requested_model.as_deref(),
                ));
                return Err(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &errors,
                    &model,
                    &resume_early,
                ));
            }
            Err(category) => {
                return Err(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
        }

        let resume_plan = resume_plan.expect("resume plan should be available after validation");
        let resume = ResumeLedgerState::from_plan(&resume_plan);
        invocation.metadata.resume_requested = resume.requested;
        invocation.metadata.resume_selector = resume.selector.clone();
        invocation.metadata.resume_strategy = resume.strategy.clone();
        let target = target.expect("validated target must be present");
        let objective = objective.expect("validated objective must be present");
        let request = GeminiRequest {
            prompt: codebase_investigator_prompt(&target, &objective),
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers: allowed_mcp_servers.clone(),
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target.clone()),
            ..Default::default()
        };
        invocation.set_request_policy(
            &request.include_directories,
            request.allowed_mcp_servers.as_ref(),
        );
        let fallback_request = GeminiRequest {
            prompt: codebase_investigator_fallback_prompt(&target, &objective),
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target),
            ..Default::default()
        };
        Ok(PreparedCodebaseInvestigator {
            started_at,
            invocation,
            validation_errors,
            model,
            resume_plan,
            resume,
            request,
            fallback_request,
            compress_session: args.compress_session,
        })
    }

    async fn run_prepared_codebase_investigator(
        &self,
        mut prepared: PreparedCodebaseInvestigator,
        ct: CancellationToken,
    ) -> CallToolResult {
        self.emit_started(&prepared.invocation);
        let session_compression = self
            .maybe_compress_session(
                prepared.compress_session,
                &prepared.request,
                ct.clone(),
                &prepared.resume_plan,
            )
            .await;
        let mut usage = ToolCallUsageAccumulator::default();
        match self
            .execute_with_resume_and_quota_downgrade(
                &prepared.request,
                ct.clone(),
                &mut usage,
                &prepared.resume_plan,
                &mut prepared.resume,
                &mut prepared.invocation,
                &mut prepared.model,
            )
            .await
        {
            Ok(output) => match self.parse_codebase_tool_output(
                "codebase-investigator",
                &prepared.model,
                &prepared.resume,
                &output.stdout,
            ) {
                Some(value) => {
                    let context_guardrail =
                        self.evaluate_context_guardrail(&prepared.resume, &usage);
                    self.record_tool_usage(
                        "codebase-investigator",
                        prepared.started_at,
                        &prepared.model,
                        &prepared.resume,
                        true,
                        None,
                        &usage,
                        &prepared.invocation,
                        None,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    let payload = attach_runtime_metadata(
                        value,
                        usage.context_window(),
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    self.emit_finished(
                        &prepared.invocation,
                        prepared.started_at,
                        &prepared.model,
                        &prepared.resume,
                        true,
                        None,
                        &usage,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    response_with_metadata_and_resume(
                        payload,
                        &prepared.validation_errors,
                        &prepared.model,
                        &prepared.resume,
                    )
                }
                None => {
                    if let Some(category) = blocking_codebase_fallback_category(&output.stderr) {
                        let context_guardrail =
                            self.evaluate_context_guardrail(&prepared.resume, &usage);
                        self.record_tool_usage(
                            "codebase-investigator",
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            &prepared.invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &prepared.invocation,
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        let payload = attach_runtime_metadata(
                            json!({
                                "ok": false,
                                "error_category": category.as_str(),
                                "error": "gemini returned invalid structured output and stderr indicates a non-contract execution failure",
                                "stderr": output.stderr,
                            }),
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        return response_with_metadata_and_resume(
                            payload,
                            &prepared.validation_errors,
                            &prepared.model,
                            &prepared.resume,
                        );
                    }
                    let mut retry_model = prepared.model.clone();
                    retry_model.fallback_mode = "fallback_prompt";
                    retry_model.fallback_reason = Some(
                        "primary output was empty or invalid JSON; using fallback schema-constrained prompt."
                            .to_string(),
                    );
                    match self
                        .execute_with_resume_and_quota_downgrade(
                            &prepared.fallback_request,
                            ct,
                            &mut usage,
                            &prepared.resume_plan,
                            &mut prepared.resume,
                            &mut prepared.invocation,
                            &mut retry_model,
                        )
                        .await
                    {
                        Ok(second_output) => match self.parse_codebase_tool_output(
                            "codebase-investigator",
                            &retry_model,
                            &prepared.resume,
                            &second_output.stdout,
                        ) {
                            Some(value) => {
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&prepared.resume, &usage);
                                self.record_tool_usage(
                                    "codebase-investigator",
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    true,
                                    None,
                                    &usage,
                                    &prepared.invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    value,
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &prepared.invocation,
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    true,
                                    None,
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                response_with_metadata_and_resume(
                                    payload,
                                    &prepared.validation_errors,
                                    &retry_model,
                                    &prepared.resume,
                                )
                            }
                            None => {
                                let category =
                                    blocking_codebase_fallback_category(&second_output.stderr)
                                        .unwrap_or(ErrorCategory::ResponseContract);
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&prepared.resume, &usage);
                                self.record_tool_usage(
                                    "codebase-investigator",
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    &prepared.invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &prepared.invocation,
                                    prepared.started_at,
                                    &retry_model,
                                    &prepared.resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    json!({
                                        "ok": false,
                                        "error_category": category.as_str(),
                                        "error": "gemini returned an empty or invalid response for codebase-investigator after retry",
                                        "first_stderr": output.stderr,
                                        "second_stderr": second_output.stderr,
                                    }),
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                response_with_metadata_and_resume(
                                    payload,
                                    &prepared.validation_errors,
                                    &retry_model,
                                    &prepared.resume,
                                )
                            }
                        },
                        Err(err) => {
                            let category =
                                self.classify_execution_error_with_resume(&err, &prepared.resume);
                            let context_guardrail =
                                self.evaluate_context_guardrail(&prepared.resume, &usage);
                            self.record_tool_usage(
                                "codebase-investigator",
                                prepared.started_at,
                                &retry_model,
                                &prepared.resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                &prepared.invocation,
                                None,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            self.emit_finished(
                                &prepared.invocation,
                                prepared.started_at,
                                &retry_model,
                                &prepared.resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            let payload = attach_runtime_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": category.as_str(),
                                    "error": err.to_string(),
                                    "retry_used": true,
                                }),
                                usage.context_window(),
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            response_with_metadata_and_resume(
                                payload,
                                &prepared.validation_errors,
                                &retry_model,
                                &prepared.resume,
                            )
                        }
                    }
                }
            },
            Err(err) => {
                let category = self.classify_execution_error_with_resume(&err, &prepared.resume);
                let context_guardrail = self.evaluate_context_guardrail(&prepared.resume, &usage);
                self.record_tool_usage(
                    "codebase-investigator",
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &prepared.invocation,
                    None,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &prepared.invocation,
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                response_with_metadata_and_resume(
                    payload,
                    &prepared.validation_errors,
                    &prepared.model,
                    &prepared.resume,
                )
            }
        }
    }

    fn prepare_mobile_provider_evidence_pack(
        &self,
        args: MobileProviderEvidenceArgs,
        parts: &Parts,
    ) -> Result<PreparedMobileProviderEvidence, CallToolResult> {
        let started_at = Instant::now();
        let resume_selector_hint = args
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut invocation = ToolInvocationContext::new(
            "mobile-provider-evidence-pack",
            args.model.clone(),
            None,
            resume_selector_hint.clone(),
            resume_selector_hint
                .as_ref()
                .map(|_| args.resume_strategy.as_str().to_string()),
            resume_selector_hint.is_some(),
            args.sandbox,
            parts,
        );

        let mut validation_errors = Vec::new();
        let resume_early =
            ResumeLedgerState::from_request(resume_selector_hint.clone(), args.resume_strategy);
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let providers = normalize_mobile_provider_field(args.providers, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);
        let resume_selector =
            normalize_optional_resume_selector(args.resume, &mut validation_errors);
        let allowed_mcp_servers =
            default_to_no_nested_mcp_servers(normalize_allowed_mcp_servers_override(
                args.allowed_mcp_server_names,
                &mut validation_errors,
            ));
        let resume_plan = self.resolve_resume_plan(
            resume_selector,
            args.resume_strategy,
            &mut validation_errors,
        );

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = requested_model.clone();

        if !validation_errors.is_empty() {
            return Err(response_with_metadata_and_resume(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
                &resume_early,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => {
                model = resolution;
                invocation.metadata.model_used = model.used.clone();
            }
            Err(ErrorCategory::ModelNotAllowed) => {
                let mut errors = validation_errors;
                errors.push(model_not_allowed_issue(
                    &self.config.model_allowlist,
                    requested_model.as_deref(),
                ));
                return Err(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &errors,
                    &model,
                    &resume_early,
                ));
            }
            Err(category) => {
                return Err(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
        }

        let resume_plan = resume_plan.expect("resume plan should be available after validation");
        let resume = ResumeLedgerState::from_plan(&resume_plan);
        invocation.metadata.resume_requested = resume.requested;
        invocation.metadata.resume_selector = resume.selector.clone();
        invocation.metadata.resume_strategy = resume.strategy.clone();
        let target = target.expect("validated target must be present");
        let request = GeminiRequest {
            prompt: mobile_provider_evidence_prompt(&providers),
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target),
            ..Default::default()
        };
        invocation.set_request_policy(
            &request.include_directories,
            request.allowed_mcp_servers.as_ref(),
        );
        Ok(PreparedMobileProviderEvidence {
            started_at,
            invocation,
            validation_errors,
            model,
            resume_plan,
            resume,
            request,
            providers,
            compress_session: args.compress_session,
        })
    }

    async fn run_prepared_mobile_provider_evidence_pack(
        &self,
        mut prepared: PreparedMobileProviderEvidence,
        ct: CancellationToken,
    ) -> CallToolResult {
        self.emit_started(&prepared.invocation);
        let session_compression = self
            .maybe_compress_session(
                prepared.compress_session,
                &prepared.request,
                ct.clone(),
                &prepared.resume_plan,
            )
            .await;
        let mut usage = ToolCallUsageAccumulator::default();
        match self
            .execute_with_resume_and_quota_downgrade(
                &prepared.request,
                ct,
                &mut usage,
                &prepared.resume_plan,
                &mut prepared.resume,
                &mut prepared.invocation,
                &mut prepared.model,
            )
            .await
        {
            Ok(output) => {
                let parsed = parse_json_response(&output.stdout).and_then(|value| {
                    let (normalized, maybe_envelope) = normalize_codebase_tool_response(value)?;
                    if let Some(envelope) = maybe_envelope {
                        self.record_response_envelope_debug(
                            None,
                            "mobile-provider-evidence-pack",
                            &prepared.model,
                            &prepared.resume,
                            envelope,
                        );
                    }
                    Some(normalized)
                });

                match parsed {
                    Some(mut value) => {
                        let context_guardrail =
                            self.evaluate_context_guardrail(&prepared.resume, &usage);
                        if let Value::Object(object) = &mut value {
                            object.insert(
                                "query_pack".to_string(),
                                json!(MOBILE_PROVIDER_EVIDENCE_QUERY_PACK_ID),
                            );
                            object
                                .insert("providers".to_string(), json!(prepared.providers.clone()));
                            if !output.stderr.is_empty() {
                                object.insert("stderr".to_string(), json!(output.stderr));
                            }
                        }
                        let payload = attach_runtime_metadata(
                            value,
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.record_tool_usage(
                            "mobile-provider-evidence-pack",
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            true,
                            None,
                            &usage,
                            &prepared.invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &prepared.invocation,
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            true,
                            None,
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        response_with_metadata_and_resume(
                            payload,
                            &prepared.validation_errors,
                            &prepared.model,
                            &prepared.resume,
                        )
                    }
                    None => {
                        let stdout_preview = output.stdout.chars().take(600).collect::<String>();
                        let context_guardrail =
                            self.evaluate_context_guardrail(&prepared.resume, &usage);
                        self.record_tool_usage(
                            "mobile-provider-evidence-pack",
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            false,
                            Some(ErrorCategory::NetworkOrTransport.as_str()),
                            &usage,
                            &prepared.invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &prepared.invocation,
                            prepared.started_at,
                            &prepared.model,
                            &prepared.resume,
                            false,
                            Some(ErrorCategory::NetworkOrTransport.as_str()),
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        let payload = attach_runtime_metadata(
                            json!({
                                "ok": false,
                                "error_category": ErrorCategory::NetworkOrTransport.as_str(),
                                "error": "gemini returned an empty or invalid JSON response for mobile-provider-evidence-pack",
                                "stdout_preview": stdout_preview,
                                "stderr": output.stderr,
                            }),
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        response_with_metadata_and_resume(
                            payload,
                            &prepared.validation_errors,
                            &prepared.model,
                            &prepared.resume,
                        )
                    }
                }
            }
            Err(err) => {
                let category = self.classify_execution_error_with_resume(&err, &prepared.resume);
                let context_guardrail = self.evaluate_context_guardrail(&prepared.resume, &usage);
                self.record_tool_usage(
                    "mobile-provider-evidence-pack",
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &prepared.invocation,
                    None,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &prepared.invocation,
                    prepared.started_at,
                    &prepared.model,
                    &prepared.resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                response_with_metadata_and_resume(
                    payload,
                    &prepared.validation_errors,
                    &prepared.model,
                    &prepared.resume,
                )
            }
        }
    }

    fn parse_codebase_tool_output(
        &self,
        tool_name: &str,
        model: &ResolvedModel,
        resume: &ResumeLedgerState,
        raw_stdout: &str,
    ) -> Option<Value> {
        let parsed = parse_json_response(raw_stdout)?;
        let (normalized, maybe_envelope) = normalize_codebase_tool_response(parsed)?;
        if let Some(envelope) = maybe_envelope {
            self.record_response_envelope_debug(None, tool_name, model, resume, envelope);
        }
        Some(attach_resume_metadata(normalized, resume))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum AskGeminiResponseMode {
    #[serde(alias = "raw")]
    Full,
    FinalOnly,
    StructuredJson,
}

impl Default for AskGeminiResponseMode {
    fn default() -> Self {
        Self::Full
    }
}

impl AskGeminiResponseMode {
    fn output_format(self) -> GeminiOutputFormat {
        match self {
            Self::Full => GeminiOutputFormat::Text,
            Self::FinalOnly | Self::StructuredJson => GeminiOutputFormat::Json,
        }
    }

    fn include_stderr(self) -> bool {
        matches!(self, Self::Full)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AskGeminiArgs {
    prompt: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional explicit conversation selector for iterative follow-up work. Pass a specific Gemini session id/selector when prior context materially helps."
    )]
    resume: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Resume handling policy: inherit (default) fails if resume is unavailable, fresh_if_missing falls back to stateless execution, require strictly enforces resume availability."
    )]
    resume_strategy: ResumeStrategy,
    #[serde(default)]
    #[schemars(
        description = "Optional override for pre-run session compression on resumed calls. Omit to follow server policy, set true to force compression, or false to disable it for this call."
    )]
    compress_session: Option<bool>,
    #[serde(default)]
    #[schemars(
        description = "When true, ask Gemini to include a concise, explicit `Reasoning Summary` section in the visible response (without hidden chain-of-thought)."
    )]
    explain: bool,
    #[serde(default)]
    #[schemars(
        description = "Controls response shaping: `full` returns raw stdout/stderr (default), `final_only` returns just the final answer text, and `structured_json` requests JSON output and surfaces parsed response payloads."
    )]
    response_mode: AskGeminiResponseMode,
    #[serde(default = "default_sandbox_false")]
    sandbox: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional per-call MCP server allowlist override for the nested Gemini run. Use '__none__' to disable MCP tools, '__all__' to allow all, or a comma-separated server list like 'postgres,ops'. When omitted, ask-gemini defaults to '__none__' to avoid MCP tool churn."
    )]
    allowed_mcp_server_names: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional strict SQL response guardrails. When set, ask-gemini enforces JSON sections, table policy, and bounded corrective retries."
    )]
    sql_guardrails: Option<AskGeminiSqlGuardrailsArgs>,
}

const fn default_sandbox_false() -> bool {
    false
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CodebaseScoutArgs {
    target: String,
    question: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional explicit conversation selector to preserve prior investigative context across repeated scout calls. Pass a specific Gemini session id/selector, or omit for deterministic one-shot runs."
    )]
    resume: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Resume handling policy: inherit (default) fails if resume is unavailable, fresh_if_missing falls back to stateless execution, require strictly enforces resume availability."
    )]
    resume_strategy: ResumeStrategy,
    #[serde(default)]
    #[schemars(
        description = "Optional override for pre-run session compression on resumed calls. Omit to follow server policy, set true to force compression, or false to disable it for this call."
    )]
    compress_session: Option<bool>,
    #[serde(default)]
    sandbox: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional per-call MCP server allowlist override for the nested Gemini run. Use '__none__' to disable MCP tools, '__all__' to allow all, or a comma-separated server list like 'postgres,ops'. When omitted, codebase-scout defaults to '__none__'."
    )]
    allowed_mcp_server_names: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CodebaseInvestigatorArgs {
    target: String,
    objective: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional explicit conversation selector to continue a prior deep-investigation thread. Pass a specific Gemini session id/selector when follow-up analysis depends on earlier context."
    )]
    resume: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Resume handling policy: inherit (default) fails if resume is unavailable, fresh_if_missing falls back to stateless execution, require strictly enforces resume availability."
    )]
    resume_strategy: ResumeStrategy,
    #[serde(default)]
    #[schemars(
        description = "Optional override for pre-run session compression on resumed calls. Omit to follow server policy, set true to force compression, or false to disable it for this call."
    )]
    compress_session: Option<bool>,
    #[serde(default)]
    sandbox: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional per-call MCP server allowlist override for the nested Gemini run. Use '__none__' to disable MCP tools, '__all__' to allow all, or a comma-separated server list like 'postgres,ops'. When omitted, codebase-investigator defaults to '__none__'."
    )]
    allowed_mcp_server_names: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MobileProviderEvidenceArgs {
    target: String,
    #[serde(default)]
    #[schemars(
        description = "Optional provider list. Defaults to Dodo, Optus, Moose, and ALDI when omitted."
    )]
    providers: Vec<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional explicit conversation selector for iterative evidence refreshes. Pass a specific Gemini session id/selector, or omit for deterministic one-shot runs."
    )]
    resume: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Resume handling policy: inherit (default) fails if resume is unavailable, fresh_if_missing falls back to stateless execution, require strictly enforces resume availability."
    )]
    resume_strategy: ResumeStrategy,
    #[serde(default)]
    #[schemars(
        description = "Optional override for pre-run session compression on resumed calls. Omit to follow server policy, set true to force compression, or false to disable it for this call."
    )]
    compress_session: Option<bool>,
    #[serde(default)]
    sandbox: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional per-call MCP server allowlist override for the nested Gemini run. Use '__none__' to disable MCP tools, '__all__' to allow all, or a comma-separated server list like 'postgres,ops'."
    )]
    allowed_mcp_server_names: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GeminiInvocationStatusArgs {
    invocation_id: String,
    #[serde(default)]
    wait_ms: Option<u64>,
    #[serde(default)]
    wait_until_terminal: bool,
    #[serde(default)]
    include_result: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GeminiInvocationCancelArgs {
    invocation_id: String,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct GeminiSessionStatsArgs {}

struct PreparedAskGemini {
    started_at: Instant,
    invocation: ToolInvocationContext,
    validation_errors: Vec<ValidationIssue>,
    model: ResolvedModel,
    resume_plan: ResumeExecutionPlan,
    resume: ResumeLedgerState,
    request: GeminiRequest,
    sql_guardrails: Option<AskGeminiSqlGuardrails>,
    explain: bool,
    response_mode: AskGeminiResponseMode,
    compress_session: Option<bool>,
}

struct PreparedCodebaseScout {
    started_at: Instant,
    invocation: ToolInvocationContext,
    validation_errors: Vec<ValidationIssue>,
    model: ResolvedModel,
    resume_plan: ResumeExecutionPlan,
    resume: ResumeLedgerState,
    request: GeminiRequest,
    fallback_request: GeminiRequest,
    compress_session: Option<bool>,
}

struct PreparedCodebaseInvestigator {
    started_at: Instant,
    invocation: ToolInvocationContext,
    validation_errors: Vec<ValidationIssue>,
    model: ResolvedModel,
    resume_plan: ResumeExecutionPlan,
    resume: ResumeLedgerState,
    request: GeminiRequest,
    fallback_request: GeminiRequest,
    compress_session: Option<bool>,
}

struct PreparedMobileProviderEvidence {
    started_at: Instant,
    invocation: ToolInvocationContext,
    validation_errors: Vec<ValidationIssue>,
    model: ResolvedModel,
    resume_plan: ResumeExecutionPlan,
    resume: ResumeLedgerState,
    request: GeminiRequest,
    providers: Vec<String>,
    compress_session: Option<bool>,
}

#[cfg(test)]
#[derive(Debug, Clone, Serialize)]
struct GeminiQuotaWindow {
    model: String,
    requests: Option<u64>,
    requests_raw: Option<String>,
    usage_remaining_percent: Option<f64>,
    reset_in: Option<String>,
    reset_in_seconds: Option<u64>,
    reset_at_unix_ms: Option<u64>,
}

#[cfg(test)]
#[derive(Debug, Clone, Serialize, Default)]
struct GeminiSessionStatsSnapshot {
    session_id: Option<String>,
    auth_method: Option<String>,
    tier: Option<String>,
    quotas: Vec<GeminiQuotaWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GeminiSessionProbeStats {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    cached_tokens: Option<u64>,
    direct_input_tokens: Option<u64>,
    duration_ms: Option<u64>,
    tool_calls: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GeminiSessionProbeSnapshot {
    session_id: Option<String>,
    auth_method: Option<String>,
    tier: Option<String>,
    probe_stats: GeminiSessionProbeStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GeminiSessionProbeExecutionSummary {
    gemini_invocations: u32,
    model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSessionProbeSnapshot {
    version: u8,
    captured_at_ms: u64,
    source: String,
    session: GeminiSessionProbeSnapshot,
    probe_execution: GeminiSessionProbeExecutionSummary,
}

#[derive(Debug, Clone)]
struct CachedSessionProbeHit {
    snapshot: CachedSessionProbeSnapshot,
    stale_age_ms: u64,
}

fn session_compression_result_from_bridge(
    mode: SessionCompressionMode,
    decision_source: SessionCompressionDecisionSource,
    requested: bool,
    result: SessionCompressionBridgeResult,
) -> SessionCompressionResult {
    let compression_status = result.compression_status.clone();
    let ok = match compression_status.as_deref() {
        Some(status) => compression_status_is_success(status),
        None => false,
    };
    let error_category = if result.ok {
        compression_status
            .as_deref()
            .filter(|status| !compression_status_is_success(status))
            .map(|_| ErrorCategory::ToolRuntime.as_str().to_string())
    } else {
        normalize_session_compression_bridge_error_category(result.error_category.as_deref())
    };
    let error = if result.ok {
        compression_status
            .as_deref()
            .filter(|status| !compression_status_is_success(status))
            .map(|status| format!("Gemini compression finished with status {status}"))
            .or_else(|| {
                if compression_status.is_none() {
                    Some("compression bridge returned no compression status".to_string())
                } else {
                    None
                }
            })
    } else {
        result.error.clone().or_else(|| {
            Some("compression bridge reported failure without an error message".to_string())
        })
    };
    SessionCompressionResult {
        mode: mode.as_str().to_string(),
        decision_source: decision_source.as_str().to_string(),
        requested,
        attempted: true,
        ok,
        skipped_reason: None,
        error_category,
        error,
        retry_count: None,
        compression_status,
        original_token_count: result.original_token_count,
        new_token_count: result.new_token_count,
        session_id: result.session_id,
        conversation_file: result.conversation_file,
    }
}

fn compression_status_is_success(status: &str) -> bool {
    matches!(status, "COMPRESSED" | "NOOP" | "CONTENT_TRUNCATED")
}

fn normalize_session_compression_bridge_error_category(raw: Option<&str>) -> Option<String> {
    match raw.and_then(ErrorCategory::from_str) {
        Some(category) => Some(category.as_str().to_string()),
        None => Some(ErrorCategory::ToolRuntime.as_str().to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
struct SessionCompressionResult {
    mode: String,
    decision_source: String,
    requested: bool,
    attempted: bool,
    ok: bool,
    skipped_reason: Option<String>,
    error_category: Option<String>,
    error: Option<String>,
    retry_count: Option<u32>,
    compression_status: Option<String>,
    original_token_count: Option<u64>,
    new_token_count: Option<u64>,
    session_id: Option<String>,
    conversation_file: Option<String>,
}

#[tool_router(router = tool_router_gemini, vis = "pub")]
impl GeminiMcp {
    #[tool(
        name = "ask-gemini",
        description = "Ask Gemini CLI with optional model, sandbox, and opt-in conversation resume. Use resume for iterative follow-up work where prior context matters."
    )]
    async fn ask_gemini(
        &self,
        ct: CancellationToken,
        Parameters(args): Parameters<AskGeminiArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        match self.prepare_ask_gemini(args, &parts) {
            Ok(prepared) => Ok(self.run_prepared_ask_gemini(prepared, ct).await),
            Err(result) => Ok(result),
        }
    }

    #[tool(
        name = "ask-gemini-start",
        description = "Start an asynchronous Gemini prompt and return an invocation_id for later polling."
    )]
    async fn ask_gemini_start(
        &self,
        Parameters(args): Parameters<AskGeminiArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let prepared = match self.prepare_ask_gemini(args, &parts) {
            Ok(prepared) => prepared,
            Err(result) => return Ok(result),
        };
        let handle = match self.async_registry.register(&prepared.invocation.metadata) {
            Ok(handle) => handle,
            Err(err) => {
                return Ok(async_error(
                    err.code(),
                    err.reason(),
                    err.message(),
                    started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                ));
            }
        };
        let service = self.clone();
        let handle_for_task = handle.clone();
        let job_ct = handle.cancellation_token();
        tokio::spawn(async move {
            let result = service.run_prepared_ask_gemini(prepared, job_ct).await;
            let payload = result.structured_content.unwrap_or_else(|| {
                json!({
                    "ok": false,
                    "error_category": "tool_runtime",
                    "error": "ask-gemini async runner did not produce structured content",
                })
            });
            let snapshot = handle_for_task.snapshot();
            let state = if snapshot.cancel_requested {
                GeminiAsyncInvocationState::Canceled
            } else if payload.get("ok").and_then(Value::as_bool) == Some(true) {
                GeminiAsyncInvocationState::Succeeded
            } else {
                GeminiAsyncInvocationState::Failed
            };
            handle_for_task.complete(state, payload, service.async_registry.retention());
        });
        Ok(async_success(
            async_snapshot_payload(&handle.snapshot(), false),
            started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        ))
    }

    #[tool(
        name = "mobile-provider-evidence-pack",
        description = "Run a bounded Postgres MCP query pack for mobile providers and return a compact evidence bundle with SQL citations."
    )]
    async fn mobile_provider_evidence_pack(
        &self,
        ct: CancellationToken,
        Parameters(args): Parameters<MobileProviderEvidenceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let resume_selector_hint = args
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut invocation = ToolInvocationContext::new(
            "mobile-provider-evidence-pack",
            args.model.clone(),
            None,
            resume_selector_hint.clone(),
            resume_selector_hint
                .as_ref()
                .map(|_| args.resume_strategy.as_str().to_string()),
            resume_selector_hint.is_some(),
            args.sandbox,
            &parts,
        );
        self.emit_started(&invocation);

        let mut validation_errors = Vec::new();
        let usage_early = ToolCallUsageAccumulator::default();
        let resume_early =
            ResumeLedgerState::from_request(resume_selector_hint.clone(), args.resume_strategy);
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let providers = normalize_mobile_provider_field(args.providers, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);
        let resume_selector =
            normalize_optional_resume_selector(args.resume, &mut validation_errors);
        let allowed_mcp_servers =
            default_to_no_nested_mcp_servers(normalize_allowed_mcp_servers_override(
                args.allowed_mcp_server_names,
                &mut validation_errors,
            ));
        let resume_plan = self.resolve_resume_plan(
            resume_selector,
            args.resume_strategy,
            &mut validation_errors,
        );

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = requested_model.clone();

        if !validation_errors.is_empty() {
            self.emit_validation_failed(&invocation, ErrorCategory::InputValidation.as_str());
            self.emit_finished(
                &invocation,
                started_at,
                &model,
                &resume_early,
                false,
                Some(ErrorCategory::InputValidation.as_str()),
                &usage_early,
                None,
                None,
                None,
            );
            return Ok(response_with_metadata_and_resume(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
                &resume_early,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => {
                model = resolution;
                invocation.metadata.model_used = model.used.clone();
            }
            Err(ErrorCategory::ModelNotAllowed) => {
                validation_errors.push(model_not_allowed_issue(
                    &self.config.model_allowlist,
                    requested_model.as_deref(),
                ));
                self.emit_validation_failed(&invocation, ErrorCategory::ModelNotAllowed.as_str());
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume_early,
                    false,
                    Some(ErrorCategory::ModelNotAllowed.as_str()),
                    &usage_early,
                    None,
                    None,
                    None,
                );
                return Ok(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
            Err(category) => {
                self.emit_validation_failed(&invocation, category.as_str());
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume_early,
                    false,
                    Some(category.as_str()),
                    &usage_early,
                    None,
                    None,
                    None,
                );
                return Ok(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
        }

        let resume_plan = resume_plan.expect("resume plan should be available after validation");
        let mut resume = ResumeLedgerState::from_plan(&resume_plan);
        invocation.metadata.resume_requested = resume.requested;
        invocation.metadata.resume_selector = resume.selector.clone();
        invocation.metadata.resume_strategy = resume.strategy.clone();
        let target = target.expect("validated target must be present");
        let prompt = mobile_provider_evidence_prompt(&providers);
        let request = GeminiRequest {
            prompt,
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers,
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target),
            ..Default::default()
        };
        invocation.set_request_policy(
            &request.include_directories,
            request.allowed_mcp_servers.as_ref(),
        );
        let session_compression = self
            .maybe_compress_session(args.compress_session, &request, ct.clone(), &resume_plan)
            .await;
        let mut usage = ToolCallUsageAccumulator::default();
        match self
            .execute_with_resume_and_quota_downgrade(
                &request,
                ct,
                &mut usage,
                &resume_plan,
                &mut resume,
                &mut invocation,
                &mut model,
            )
            .await
        {
            Ok(output) => {
                let parsed = parse_json_response(&output.stdout).and_then(|value| {
                    let (normalized, maybe_envelope) = normalize_codebase_tool_response(value)?;
                    if let Some(envelope) = maybe_envelope {
                        self.record_response_envelope_debug(
                            None,
                            "mobile-provider-evidence-pack",
                            &model,
                            &resume,
                            envelope,
                        );
                    }
                    Some(normalized)
                });

                match parsed {
                    Some(mut value) => {
                        let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                        if let Value::Object(object) = &mut value {
                            object.insert(
                                "query_pack".to_string(),
                                json!(MOBILE_PROVIDER_EVIDENCE_QUERY_PACK_ID),
                            );
                            object.insert("providers".to_string(), json!(providers));
                            if !output.stderr.is_empty() {
                                object.insert("stderr".to_string(), json!(output.stderr));
                            }
                        }
                        let payload = attach_runtime_metadata(
                            value,
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.record_tool_usage(
                            "mobile-provider-evidence-pack",
                            started_at,
                            &model,
                            &resume,
                            true,
                            None,
                            &usage,
                            &invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &invocation,
                            started_at,
                            &model,
                            &resume,
                            true,
                            None,
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        Ok(response_with_metadata_and_resume(
                            payload,
                            &validation_errors,
                            &model,
                            &resume,
                        ))
                    }
                    None => {
                        let stdout_preview = output.stdout.chars().take(600).collect::<String>();
                        let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                        self.record_tool_usage(
                            "mobile-provider-evidence-pack",
                            started_at,
                            &model,
                            &resume,
                            false,
                            Some(ErrorCategory::NetworkOrTransport.as_str()),
                            &usage,
                            &invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &invocation,
                            started_at,
                            &model,
                            &resume,
                            false,
                            Some(ErrorCategory::NetworkOrTransport.as_str()),
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        let payload = attach_runtime_metadata(
                            json!({
                                "ok": false,
                                "error_category": ErrorCategory::NetworkOrTransport.as_str(),
                                "error": "gemini returned an empty or invalid JSON response for mobile-provider-evidence-pack",
                                "stdout_preview": stdout_preview,
                                "stderr": output.stderr,
                            }),
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        Ok(response_with_metadata_and_resume(
                            payload,
                            &validation_errors,
                            &model,
                            &resume,
                        ))
                    }
                }
            }
            Err(err) => {
                let category = self.classify_execution_error_with_resume(&err, &resume);
                let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                self.record_tool_usage(
                    "mobile-provider-evidence-pack",
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &invocation,
                    None,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                Ok(response_with_metadata_and_resume(
                    payload,
                    &validation_errors,
                    &model,
                    &resume,
                ))
            }
        }
    }

    #[tool(
        name = "mobile-provider-evidence-pack-start",
        description = "Start an asynchronous mobile provider evidence pack run and return an invocation_id."
    )]
    async fn mobile_provider_evidence_pack_start(
        &self,
        Parameters(args): Parameters<MobileProviderEvidenceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let prepared = match self.prepare_mobile_provider_evidence_pack(args, &parts) {
            Ok(prepared) => prepared,
            Err(result) => return Ok(result),
        };
        let handle = match self.async_registry.register(&prepared.invocation.metadata) {
            Ok(handle) => handle,
            Err(err) => {
                return Ok(async_error(
                    err.code(),
                    err.reason(),
                    err.message(),
                    started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                ));
            }
        };
        let service = self.clone();
        let handle_for_task = handle.clone();
        let job_ct = handle.cancellation_token();
        tokio::spawn(async move {
            let result = service
                .run_prepared_mobile_provider_evidence_pack(prepared, job_ct)
                .await;
            let payload = result.structured_content.unwrap_or_else(|| {
                json!({
                    "ok": false,
                    "error_category": "tool_runtime",
                    "error": "mobile-provider-evidence-pack async runner did not produce structured content",
                })
            });
            let snapshot = handle_for_task.snapshot();
            let state = if snapshot.cancel_requested {
                GeminiAsyncInvocationState::Canceled
            } else if payload.get("ok").and_then(Value::as_bool) == Some(true) {
                GeminiAsyncInvocationState::Succeeded
            } else {
                GeminiAsyncInvocationState::Failed
            };
            handle_for_task.complete(state, payload, service.async_registry.retention());
        });
        Ok(async_success(
            async_snapshot_payload(&handle.snapshot(), false),
            started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        ))
    }

    #[tool(
        name = "gemini-session-stats",
        description = "Probe Gemini CLI session identity and lightweight usage telemetry without relying on deprecated `stats session` output."
    )]
    async fn gemini_session_stats(
        &self,
        ct: CancellationToken,
        Parameters(_args): Parameters<GeminiSessionStatsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let mut invocation = ToolInvocationContext::new(
            "gemini-session-stats",
            None,
            None,
            None,
            None,
            false,
            false,
            &parts,
        );
        let nested_mcp_policy = AllowedMcpServers::None;
        invocation.set_request_policy(&[], Some(&nested_mcp_policy));

        let probe_model = select_session_probe_model(&self.config);
        let mut model = ResolvedModel {
            requested: probe_model.clone(),
            used: probe_model,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = model.requested.clone();
        invocation.metadata.model_used = model.used.clone();
        self.emit_started(&invocation);
        let resume = ResumeLedgerState::default();
        let mut usage = ToolCallUsageAccumulator::default();
        let mut cache_warning = None;
        let recent_snapshot = match self
            .session_probe_snapshot
            .load_recent(self.config.session_probe_stale_window)
        {
            Ok(snapshot) => snapshot,
            Err(warning) => {
                cache_warning = Some(warning);
                None
            }
        };

        self.invocation_observer
            .on_event(GeminiInvocationEvent::new(
                invocation.metadata.clone(),
                GeminiInvocationEventKind::AttemptStarted { attempt: 1 },
            ));

        match execute_gemini_stats_session(&self.config, ct).await {
            Ok(output) => {
                model.used = output.model.clone().or_else(|| model.used.clone());
                invocation.metadata.model_used = model.used.clone();
                let gemini_invocations = u64::from(output.gemini_invocations);
                usage.record_output(
                    &output.response.stdout,
                    &output.response.stderr,
                    gemini_invocations,
                );
                let snapshot =
                    parse_session_probe_snapshot(&output.response.stdout, &output.response.stderr);
                let probe_execution = GeminiSessionProbeExecutionSummary {
                    gemini_invocations: output.gemini_invocations,
                    model: output.model.clone(),
                };
                let result = InvocationResultMetadata::session_probe_source(
                    GEMINI_SESSION_PROBE_SOURCE_JSON,
                    false,
                );

                let write_cache_warning = self.session_probe_snapshot.record_success(
                    &snapshot,
                    &probe_execution,
                    GEMINI_SESSION_PROBE_SOURCE_JSON,
                    false,
                );
                self.record_tool_usage(
                    "gemini-session-stats",
                    started_at,
                    &model,
                    &resume,
                    true,
                    None,
                    &usage,
                    &invocation,
                    Some(&result),
                    snapshot.session_id.as_deref(),
                    None,
                    None,
                );
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume,
                    true,
                    None,
                    &usage,
                    Some(&result),
                    None,
                    None,
                );

                let mut response = serde_json::Map::new();
                response.insert("ok".to_string(), json!(true));
                response.insert(
                    "source".to_string(),
                    json!(GEMINI_SESSION_PROBE_SOURCE_JSON),
                );
                response.insert("degraded".to_string(), json!(false));
                response.insert(
                    "session".to_string(),
                    json!({
                        "session_id": snapshot.session_id,
                        "auth_method": snapshot.auth_method,
                        "tier": snapshot.tier,
                    }),
                );
                response.insert("probe_stats".to_string(), json!(snapshot.probe_stats));
                response.insert("probe_execution".to_string(), json!(probe_execution));
                response.insert(
                    "live_probe_attempt".to_string(),
                    json!({
                        "ok": true,
                        "gemini_invocations": usage.gemini_invocations,
                    }),
                );
                response.insert("quotas".to_string(), json!([]));
                response.insert(
                    "warning".to_string(),
                    json!(session_probe_warning(GEMINI_SESSION_PROBE_SOURCE_JSON)),
                );
                if let Some(cache_warning) = write_cache_warning.or(cache_warning) {
                    response.insert("cache_warning".to_string(), json!(cache_warning));
                }
                if !output.response.stderr.is_empty() {
                    response.insert("stderr".to_string(), json!(output.response.stderr));
                }

                Ok(CallToolResult::structured(Value::Object(response)))
            }
            Err(GeminiSessionProbeError {
                error,
                gemini_invocations,
            }) => {
                usage.record_error(&error, u64::from(gemini_invocations));
                let category = self.classify_execution_error_with_resume(&error, &resume);
                if is_cache_eligible_session_probe_failure(&error, category) {
                    if let Some(cached) = recent_snapshot.as_ref().and_then(|cached| {
                        refresh_cached_session_probe_hit(
                            &cached.snapshot,
                            self.config.session_probe_stale_window,
                        )
                    }) {
                        let result = InvocationResultMetadata::cached_recent_probe(
                            cached.stale_age_ms,
                            category.as_str(),
                        );
                        self.record_tool_usage(
                            "gemini-session-stats",
                            started_at,
                            &model,
                            &resume,
                            true,
                            Some(category.as_str()),
                            &usage,
                            &invocation,
                            Some(&result),
                            cached.snapshot.session.session_id.as_deref(),
                            None,
                            None,
                        );
                        self.emit_finished(
                            &invocation,
                            started_at,
                            &model,
                            &resume,
                            true,
                            Some(category.as_str()),
                            &usage,
                            Some(&result),
                            None,
                            None,
                        );

                        let freshness_window_ms =
                            self.config
                                .session_probe_stale_window
                                .as_millis()
                                .min(u128::from(u64::MAX)) as u64;
                        let mut response = serde_json::Map::new();
                        response.insert("ok".to_string(), json!(true));
                        response.insert("source".to_string(), json!("cached_recent_probe"));
                        response.insert("degraded".to_string(), json!(true));
                        response.insert(
                            "session".to_string(),
                            json!({
                                "session_id": cached.snapshot.session.session_id,
                                "auth_method": cached.snapshot.session.auth_method,
                                "tier": cached.snapshot.session.tier,
                            }),
                        );
                        response.insert(
                            "probe_stats".to_string(),
                            json!(cached.snapshot.session.probe_stats),
                        );
                        response.insert(
                            "probe_execution".to_string(),
                            json!(cached.snapshot.probe_execution),
                        );
                        response.insert(
                            "live_probe_attempt".to_string(),
                            json!({
                                "ok": false,
                                "gemini_invocations": usage.gemini_invocations,
                                "error_category": category.as_str(),
                                "error": error.to_string(),
                            }),
                        );
                        response.insert("quotas".to_string(), json!([]));
                        response.insert("stale_age_ms".to_string(), json!(cached.stale_age_ms));
                        response.insert(
                            "freshness_window_ms".to_string(),
                            json!(freshness_window_ms),
                        );
                        response.insert(
                            "snapshot_captured_at_ms".to_string(),
                            json!(cached.snapshot.captured_at_ms),
                        );
                        response.insert(
                            "cached_probe_source".to_string(),
                            json!(cached.snapshot.source),
                        );
                        response.insert(
                            "live_probe_error_category".to_string(),
                            json!(category.as_str()),
                        );
                        response.insert("live_probe_error".to_string(), json!(error.to_string()));
                        response.insert(
                            "warning".to_string(),
                            json!(cached_session_probe_warning(
                                cached.stale_age_ms,
                                category.as_str(),
                            )),
                        );
                        if let Some(cache_warning) = cache_warning {
                            response.insert("cache_warning".to_string(), json!(cache_warning));
                        }

                        return Ok(CallToolResult::structured(Value::Object(response)));
                    }
                }

                self.record_tool_usage(
                    "gemini-session-stats",
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &invocation,
                    None,
                    None,
                    None,
                    None,
                );
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    None,
                    None,
                );
                let mut response = serde_json::Map::new();
                response.insert("ok".to_string(), json!(false));
                response.insert("error_category".to_string(), json!(category.as_str()));
                response.insert("error".to_string(), json!(error.to_string()));
                response.insert(
                    "live_probe_attempt".to_string(),
                    json!({
                        "ok": false,
                        "gemini_invocations": usage.gemini_invocations,
                        "error_category": category.as_str(),
                    }),
                );
                if let Some(cache_warning) = cache_warning {
                    response.insert("cache_warning".to_string(), json!(cache_warning));
                }
                Ok(CallToolResult::structured(Value::Object(response)))
            }
        }
    }

    #[tool(
        name = "gemini-invocation-status",
        description = "Read Gemini async invocation status and optionally wait for updates or include the terminal result."
    )]
    async fn gemini_invocation_status(
        &self,
        Parameters(args): Parameters<GeminiInvocationStatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let wait_mode = match parse_async_status_wait_mode(args.wait_ms, args.wait_until_terminal) {
            Ok(wait_mode) => wait_mode,
            Err(message) => {
                return Ok(async_error(
                    "GEMINI_ASYNC_INVALID_WAIT",
                    "gemini_async_invalid_wait",
                    message,
                    started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                ));
            }
        };
        let Some(handle) = self.async_registry.get(args.invocation_id.trim()) else {
            return Ok(async_error(
                "GEMINI_ASYNC_INVOCATION_NOT_FOUND",
                "gemini_async_invocation_not_found",
                "async Gemini invocation not found",
                started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            ));
        };

        match wait_mode {
            GeminiAsyncStatusWaitMode::Immediate => {}
            GeminiAsyncStatusWaitMode::Deadline { wait_ms } => {
                let revision = handle.revision();
                let _ = handle
                    .wait_for_update_since(revision, Some(Duration::from_millis(wait_ms)))
                    .await;
            }
            GeminiAsyncStatusWaitMode::UntilTerminal => loop {
                let snapshot = handle.snapshot();
                if snapshot.terminal() {
                    break;
                }
                let revision = handle.revision();
                let _ = handle.wait_for_update_since(revision, None).await;
            },
        }

        let snapshot = handle.snapshot();
        Ok(async_success(
            async_snapshot_payload(&snapshot, args.include_result),
            started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        ))
    }

    #[tool(
        name = "gemini-invocation-cancel",
        description = "Request cancellation of a running async Gemini invocation."
    )]
    async fn gemini_invocation_cancel(
        &self,
        Parameters(args): Parameters<GeminiInvocationCancelArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let Some(handle) = self.async_registry.get(args.invocation_id.trim()) else {
            return Ok(async_error(
                "GEMINI_ASYNC_INVOCATION_NOT_FOUND",
                "gemini_async_invocation_not_found",
                "async Gemini invocation not found",
                started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            ));
        };
        let snapshot = if handle.snapshot().terminal() {
            handle.snapshot()
        } else {
            handle.request_cancel()
        };
        Ok(async_success(
            async_snapshot_payload(&snapshot, false),
            started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        ))
    }

    #[tool(
        name = "codebase-scout",
        description = "Run a high-context Gemini codebase analysis against a target path with a focused question. Resume is optional for iterative threads; omit it for deterministic one-shot scouting."
    )]
    async fn codebase_scout(
        &self,
        ct: CancellationToken,
        Parameters(args): Parameters<CodebaseScoutArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let resume_selector_hint = args
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut invocation = ToolInvocationContext::new(
            "codebase-scout",
            args.model.clone(),
            None,
            resume_selector_hint.clone(),
            resume_selector_hint
                .as_ref()
                .map(|_| args.resume_strategy.as_str().to_string()),
            resume_selector_hint.is_some(),
            args.sandbox,
            &parts,
        );
        self.emit_started(&invocation);

        let mut validation_errors = Vec::new();
        let usage_early = ToolCallUsageAccumulator::default();
        let resume_early =
            ResumeLedgerState::from_request(resume_selector_hint.clone(), args.resume_strategy);
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let question =
            validate_required_text_field("question", &args.question, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);
        let resume_selector =
            normalize_optional_resume_selector(args.resume, &mut validation_errors);
        let allowed_mcp_servers =
            default_to_no_nested_mcp_servers(normalize_allowed_mcp_servers_override(
                args.allowed_mcp_server_names,
                &mut validation_errors,
            ));
        let resume_plan = self.resolve_resume_plan(
            resume_selector,
            args.resume_strategy,
            &mut validation_errors,
        );

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = requested_model.clone();

        if !validation_errors.is_empty() {
            self.emit_validation_failed(&invocation, ErrorCategory::InputValidation.as_str());
            self.emit_finished(
                &invocation,
                started_at,
                &model,
                &resume_early,
                false,
                Some(ErrorCategory::InputValidation.as_str()),
                &usage_early,
                None,
                None,
                None,
            );
            return Ok(response_with_metadata_and_resume(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
                &resume_early,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => {
                model = resolution;
                invocation.metadata.model_used = model.used.clone();
            }
            Err(ErrorCategory::ModelNotAllowed) => {
                validation_errors.push(model_not_allowed_issue(
                    &self.config.model_allowlist,
                    requested_model.as_deref(),
                ));
                self.emit_validation_failed(&invocation, ErrorCategory::ModelNotAllowed.as_str());
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume_early,
                    false,
                    Some(ErrorCategory::ModelNotAllowed.as_str()),
                    &usage_early,
                    None,
                    None,
                    None,
                );
                return Ok(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
            Err(category) => {
                self.emit_validation_failed(&invocation, category.as_str());
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume_early,
                    false,
                    Some(category.as_str()),
                    &usage_early,
                    None,
                    None,
                    None,
                );
                return Ok(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
        }

        let resume_plan = resume_plan.expect("resume plan should be available after validation");
        let mut resume = ResumeLedgerState::from_plan(&resume_plan);
        invocation.metadata.resume_requested = resume.requested;
        invocation.metadata.resume_selector = resume.selector.clone();
        invocation.metadata.resume_strategy = resume.strategy.clone();
        let target = target.expect("validated target must be present");
        let question = question.expect("validated question must be present");
        let prompt = codebase_scout_prompt(&target, &question);

        let request = GeminiRequest {
            prompt,
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers: allowed_mcp_servers.clone(),
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target.clone()),
            ..Default::default()
        };
        invocation.set_request_policy(
            &request.include_directories,
            request.allowed_mcp_servers.as_ref(),
        );
        let session_compression = self
            .maybe_compress_session(args.compress_session, &request, ct.clone(), &resume_plan)
            .await;
        let mut usage = ToolCallUsageAccumulator::default();
        match self
            .execute_with_resume_and_quota_downgrade(
                &request,
                ct.clone(),
                &mut usage,
                &resume_plan,
                &mut resume,
                &mut invocation,
                &mut model,
            )
            .await
        {
            Ok(output) => match self.parse_codebase_tool_output(
                "codebase-scout",
                &model,
                &resume,
                &output.stdout,
            ) {
                Some(value) => {
                    let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                    self.record_tool_usage(
                        "codebase-scout",
                        started_at,
                        &model,
                        &resume,
                        true,
                        None,
                        &usage,
                        &invocation,
                        None,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    let payload = attach_runtime_metadata(
                        value,
                        usage.context_window(),
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    self.emit_finished(
                        &invocation,
                        started_at,
                        &model,
                        &resume,
                        true,
                        None,
                        &usage,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    Ok(CallToolResult::structured(payload))
                }
                None => {
                    if let Some(category) = blocking_codebase_fallback_category(&output.stderr) {
                        let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                        self.record_tool_usage(
                            "codebase-scout",
                            started_at,
                            &model,
                            &resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            &invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &invocation,
                            started_at,
                            &model,
                            &resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        let payload = attach_runtime_metadata(
                            json!({
                                "ok": false,
                                "error_category": category.as_str(),
                                "error": "gemini returned invalid structured output and stderr indicates a non-contract execution failure",
                                "stderr": output.stderr,
                            }),
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        return Ok(response_with_metadata_and_resume(
                            payload,
                            &validation_errors,
                            &model,
                            &resume,
                        ));
                    }
                    let mut retry_model = model.clone();
                    retry_model.fallback_mode = "fallback_prompt";
                    retry_model.fallback_reason = Some(
                        "primary output was empty or invalid JSON; using fallback schema-constrained prompt."
                            .to_string(),
                    );
                    let fallback_request = GeminiRequest {
                        prompt: codebase_scout_fallback_prompt(&target, &question),
                        model: retry_model.used.clone(),
                        sandbox: args.sandbox,
                        allowed_mcp_servers: allowed_mcp_servers.clone(),
                        output_format: GeminiOutputFormat::Json,
                        prompt_transport: GeminiPromptTransport::Stdin,
                        include_directories: vec![target.clone()],
                        working_directory: Some(target.clone()),
                        ..Default::default()
                    };
                    match self
                        .execute_with_resume_and_quota_downgrade(
                            &fallback_request,
                            ct,
                            &mut usage,
                            &resume_plan,
                            &mut resume,
                            &mut invocation,
                            &mut retry_model,
                        )
                        .await
                    {
                        Ok(second_output) => match self.parse_codebase_tool_output(
                            "codebase-scout",
                            &retry_model,
                            &resume,
                            &second_output.stdout,
                        ) {
                            Some(value) => {
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&resume, &usage);
                                self.record_tool_usage(
                                    "codebase-scout",
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    true,
                                    None,
                                    &usage,
                                    &invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    value,
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &invocation,
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    true,
                                    None,
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                Ok(CallToolResult::structured(payload))
                            }
                            None => {
                                let category =
                                    blocking_codebase_fallback_category(&second_output.stderr)
                                        .unwrap_or(ErrorCategory::ResponseContract);
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&resume, &usage);
                                self.record_tool_usage(
                                    "codebase-scout",
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    &invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &invocation,
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    json!({
                                        "ok": false,
                                        "error_category": category.as_str(),
                                        "error": "gemini returned an empty or invalid response for codebase-scout after retry",
                                        "first_stderr": output.stderr,
                                        "second_stderr": second_output.stderr,
                                    }),
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                Ok(response_with_metadata_and_resume(
                                    payload,
                                    &validation_errors,
                                    &retry_model,
                                    &resume,
                                ))
                            }
                        },
                        Err(err) => {
                            let category = self.classify_execution_error_with_resume(&err, &resume);
                            let context_guardrail =
                                self.evaluate_context_guardrail(&resume, &usage);
                            self.record_tool_usage(
                                "codebase-scout",
                                started_at,
                                &retry_model,
                                &resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                &invocation,
                                None,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            self.emit_finished(
                                &invocation,
                                started_at,
                                &retry_model,
                                &resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            let payload = attach_runtime_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": category.as_str(),
                                    "error": err.to_string(),
                                    "retry_used": true,
                                }),
                                usage.context_window(),
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            Ok(response_with_metadata_and_resume(
                                payload,
                                &validation_errors,
                                &retry_model,
                                &resume,
                            ))
                        }
                    }
                }
            },
            Err(err) => {
                let category = self.classify_execution_error_with_resume(&err, &resume);
                let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                self.record_tool_usage(
                    "codebase-scout",
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &invocation,
                    None,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                Ok(response_with_metadata_and_resume(
                    payload,
                    &validation_errors,
                    &model,
                    &resume,
                ))
            }
        }
    }

    #[tool(
        name = "codebase-scout-start",
        description = "Start an asynchronous codebase scout run and return an invocation_id."
    )]
    async fn codebase_scout_start(
        &self,
        Parameters(args): Parameters<CodebaseScoutArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let prepared = match self.prepare_codebase_scout(args, &parts) {
            Ok(prepared) => prepared,
            Err(result) => return Ok(result),
        };
        let handle = match self.async_registry.register(&prepared.invocation.metadata) {
            Ok(handle) => handle,
            Err(err) => {
                return Ok(async_error(
                    err.code(),
                    err.reason(),
                    err.message(),
                    started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                ));
            }
        };
        let service = self.clone();
        let handle_for_task = handle.clone();
        let job_ct = handle.cancellation_token();
        tokio::spawn(async move {
            let result = service.run_prepared_codebase_scout(prepared, job_ct).await;
            let payload = result.structured_content.unwrap_or_else(|| {
                json!({
                    "ok": false,
                    "error_category": "tool_runtime",
                    "error": "codebase-scout async runner did not produce structured content",
                })
            });
            let snapshot = handle_for_task.snapshot();
            let state = if snapshot.cancel_requested {
                GeminiAsyncInvocationState::Canceled
            } else if payload.get("ok").and_then(Value::as_bool) == Some(true) {
                GeminiAsyncInvocationState::Succeeded
            } else {
                GeminiAsyncInvocationState::Failed
            };
            handle_for_task.complete(state, payload, service.async_registry.retention());
        });
        Ok(async_success(
            async_snapshot_payload(&handle.snapshot(), false),
            started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        ))
    }

    #[tool(
        name = "codebase-investigator",
        description = "Run a deep architecture/root-cause investigation. Prefers Gemini's codebase_investigator subagent when available. Supports opt-in resume for iterative investigations."
    )]
    async fn codebase_investigator(
        &self,
        ct: CancellationToken,
        Parameters(args): Parameters<CodebaseInvestigatorArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let resume_selector_hint = args
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut invocation = ToolInvocationContext::new(
            "codebase-investigator",
            args.model.clone(),
            None,
            resume_selector_hint.clone(),
            resume_selector_hint
                .as_ref()
                .map(|_| args.resume_strategy.as_str().to_string()),
            resume_selector_hint.is_some(),
            args.sandbox,
            &parts,
        );
        self.emit_started(&invocation);

        let mut validation_errors = Vec::new();
        let usage_early = ToolCallUsageAccumulator::default();
        let resume_early =
            ResumeLedgerState::from_request(resume_selector_hint.clone(), args.resume_strategy);
        let target = validate_target_within_include_directories(
            &args.target,
            &self.config.include_directories,
            &mut validation_errors,
        );
        let objective =
            validate_required_text_field("objective", &args.objective, &mut validation_errors);
        let requested_model =
            normalize_optional_model_field("model", args.model, &mut validation_errors);
        let resume_selector =
            normalize_optional_resume_selector(args.resume, &mut validation_errors);
        let allowed_mcp_servers =
            default_to_no_nested_mcp_servers(normalize_allowed_mcp_servers_override(
                args.allowed_mcp_server_names,
                &mut validation_errors,
            ));
        let resume_plan = self.resolve_resume_plan(
            resume_selector,
            args.resume_strategy,
            &mut validation_errors,
        );

        let mut model = ResolvedModel {
            requested: requested_model.clone(),
            used: None,
            default_model_applied: false,
            fallback_mode: "none",
            fallback_reason: None,
        };
        invocation.metadata.model_requested = requested_model.clone();

        if !validation_errors.is_empty() {
            self.emit_validation_failed(&invocation, ErrorCategory::InputValidation.as_str());
            self.emit_finished(
                &invocation,
                started_at,
                &model,
                &resume_early,
                false,
                Some(ErrorCategory::InputValidation.as_str()),
                &usage_early,
                None,
                None,
                None,
            );
            return Ok(response_with_metadata_and_resume(
                json!({
                    "ok": false,
                    "error_category": ErrorCategory::InputValidation.as_str(),
                    "error": "request payload failed validation",
                }),
                &validation_errors,
                &model,
                &resume_early,
            ));
        }

        match resolve_model(&self.config, requested_model.clone()) {
            Ok(resolution) => {
                model = resolution;
                invocation.metadata.model_used = model.used.clone();
            }
            Err(ErrorCategory::ModelNotAllowed) => {
                validation_errors.push(model_not_allowed_issue(
                    &self.config.model_allowlist,
                    requested_model.as_deref(),
                ));
                self.emit_validation_failed(&invocation, ErrorCategory::ModelNotAllowed.as_str());
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume_early,
                    false,
                    Some(ErrorCategory::ModelNotAllowed.as_str()),
                    &usage_early,
                    None,
                    None,
                    None,
                );
                return Ok(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": ErrorCategory::ModelNotAllowed.as_str(),
                        "error": "requested model is not allowed by policy",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
            Err(category) => {
                self.emit_validation_failed(&invocation, category.as_str());
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume_early,
                    false,
                    Some(category.as_str()),
                    &usage_early,
                    None,
                    None,
                    None,
                );
                return Ok(response_with_metadata_and_resume(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": "model resolution failed",
                    }),
                    &validation_errors,
                    &model,
                    &resume_early,
                ));
            }
        }

        let resume_plan = resume_plan.expect("resume plan should be available after validation");
        let mut resume = ResumeLedgerState::from_plan(&resume_plan);
        invocation.metadata.resume_requested = resume.requested;
        invocation.metadata.resume_selector = resume.selector.clone();
        invocation.metadata.resume_strategy = resume.strategy.clone();
        let target = target.expect("validated target must be present");
        let objective = objective.expect("validated objective must be present");
        let prompt = codebase_investigator_prompt(&target, &objective);
        let request = GeminiRequest {
            prompt,
            model: model.used.clone(),
            sandbox: args.sandbox,
            allowed_mcp_servers: allowed_mcp_servers.clone(),
            output_format: GeminiOutputFormat::Json,
            prompt_transport: GeminiPromptTransport::Stdin,
            include_directories: vec![target.clone()],
            working_directory: Some(target.clone()),
            ..Default::default()
        };
        invocation.set_request_policy(
            &request.include_directories,
            request.allowed_mcp_servers.as_ref(),
        );
        let session_compression = self
            .maybe_compress_session(args.compress_session, &request, ct.clone(), &resume_plan)
            .await;
        let mut usage = ToolCallUsageAccumulator::default();
        match self
            .execute_with_resume_and_quota_downgrade(
                &request,
                ct.clone(),
                &mut usage,
                &resume_plan,
                &mut resume,
                &mut invocation,
                &mut model,
            )
            .await
        {
            Ok(output) => match self.parse_codebase_tool_output(
                "codebase-investigator",
                &model,
                &resume,
                &output.stdout,
            ) {
                Some(value) => {
                    let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                    self.record_tool_usage(
                        "codebase-investigator",
                        started_at,
                        &model,
                        &resume,
                        true,
                        None,
                        &usage,
                        &invocation,
                        None,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    let payload = attach_runtime_metadata(
                        value,
                        usage.context_window(),
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    self.emit_finished(
                        &invocation,
                        started_at,
                        &model,
                        &resume,
                        true,
                        None,
                        &usage,
                        None,
                        session_compression.as_ref(),
                        context_guardrail.as_ref(),
                    );
                    Ok(CallToolResult::structured(payload))
                }
                None => {
                    if let Some(category) = blocking_codebase_fallback_category(&output.stderr) {
                        let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                        self.record_tool_usage(
                            "codebase-investigator",
                            started_at,
                            &model,
                            &resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            &invocation,
                            None,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        self.emit_finished(
                            &invocation,
                            started_at,
                            &model,
                            &resume,
                            false,
                            Some(category.as_str()),
                            &usage,
                            None,
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        let payload = attach_runtime_metadata(
                            json!({
                                "ok": false,
                                "error_category": category.as_str(),
                                "error": "gemini returned invalid structured output and stderr indicates a non-contract execution failure",
                                "stderr": output.stderr,
                            }),
                            usage.context_window(),
                            session_compression.as_ref(),
                            context_guardrail.as_ref(),
                        );
                        return Ok(response_with_metadata_and_resume(
                            payload,
                            &validation_errors,
                            &model,
                            &resume,
                        ));
                    }
                    let mut retry_model = model.clone();
                    retry_model.fallback_mode = "fallback_prompt";
                    retry_model.fallback_reason = Some(
                        "primary output was empty or invalid JSON; using fallback schema-constrained prompt."
                            .to_string(),
                    );
                    let fallback_request = GeminiRequest {
                        prompt: codebase_investigator_fallback_prompt(&target, &objective),
                        model: retry_model.used.clone(),
                        sandbox: args.sandbox,
                        allowed_mcp_servers: allowed_mcp_servers.clone(),
                        output_format: GeminiOutputFormat::Json,
                        prompt_transport: GeminiPromptTransport::Stdin,
                        include_directories: vec![target.clone()],
                        working_directory: Some(target.clone()),
                        ..Default::default()
                    };
                    match self
                        .execute_with_resume_and_quota_downgrade(
                            &fallback_request,
                            ct,
                            &mut usage,
                            &resume_plan,
                            &mut resume,
                            &mut invocation,
                            &mut retry_model,
                        )
                        .await
                    {
                        Ok(second_output) => match self.parse_codebase_tool_output(
                            "codebase-investigator",
                            &retry_model,
                            &resume,
                            &second_output.stdout,
                        ) {
                            Some(value) => {
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&resume, &usage);
                                self.record_tool_usage(
                                    "codebase-investigator",
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    true,
                                    None,
                                    &usage,
                                    &invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    value,
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &invocation,
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    true,
                                    None,
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                Ok(CallToolResult::structured(payload))
                            }
                            None => {
                                let category =
                                    blocking_codebase_fallback_category(&second_output.stderr)
                                        .unwrap_or(ErrorCategory::ResponseContract);
                                let context_guardrail =
                                    self.evaluate_context_guardrail(&resume, &usage);
                                self.record_tool_usage(
                                    "codebase-investigator",
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    &invocation,
                                    None,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                self.emit_finished(
                                    &invocation,
                                    started_at,
                                    &retry_model,
                                    &resume,
                                    false,
                                    Some(category.as_str()),
                                    &usage,
                                    None,
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                let payload = attach_runtime_metadata(
                                    json!({
                                        "ok": false,
                                        "error_category": category.as_str(),
                                        "error": "gemini returned an empty or invalid response for codebase-investigator after retry",
                                        "first_stderr": output.stderr,
                                        "second_stderr": second_output.stderr,
                                    }),
                                    usage.context_window(),
                                    session_compression.as_ref(),
                                    context_guardrail.as_ref(),
                                );
                                Ok(response_with_metadata_and_resume(
                                    payload,
                                    &validation_errors,
                                    &retry_model,
                                    &resume,
                                ))
                            }
                        },
                        Err(err) => {
                            let category = self.classify_execution_error_with_resume(&err, &resume);
                            let context_guardrail =
                                self.evaluate_context_guardrail(&resume, &usage);
                            self.record_tool_usage(
                                "codebase-investigator",
                                started_at,
                                &retry_model,
                                &resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                &invocation,
                                None,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            self.emit_finished(
                                &invocation,
                                started_at,
                                &retry_model,
                                &resume,
                                false,
                                Some(category.as_str()),
                                &usage,
                                None,
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            let payload = attach_runtime_metadata(
                                json!({
                                    "ok": false,
                                    "error_category": category.as_str(),
                                    "error": err.to_string(),
                                    "retry_used": true,
                                }),
                                usage.context_window(),
                                session_compression.as_ref(),
                                context_guardrail.as_ref(),
                            );
                            Ok(response_with_metadata_and_resume(
                                payload,
                                &validation_errors,
                                &retry_model,
                                &resume,
                            ))
                        }
                    }
                }
            },
            Err(err) => {
                let category = self.classify_execution_error_with_resume(&err, &resume);
                let context_guardrail = self.evaluate_context_guardrail(&resume, &usage);
                self.record_tool_usage(
                    "codebase-investigator",
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    &invocation,
                    None,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                self.emit_finished(
                    &invocation,
                    started_at,
                    &model,
                    &resume,
                    false,
                    Some(category.as_str()),
                    &usage,
                    None,
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                let payload = attach_runtime_metadata(
                    json!({
                        "ok": false,
                        "error_category": category.as_str(),
                        "error": err.to_string(),
                    }),
                    usage.context_window(),
                    session_compression.as_ref(),
                    context_guardrail.as_ref(),
                );
                Ok(response_with_metadata_and_resume(
                    payload,
                    &validation_errors,
                    &model,
                    &resume,
                ))
            }
        }
    }

    #[tool(
        name = "codebase-investigator-start",
        description = "Start an asynchronous codebase investigator run and return an invocation_id."
    )]
    async fn codebase_investigator_start(
        &self,
        Parameters(args): Parameters<CodebaseInvestigatorArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let started_at = Instant::now();
        let prepared = match self.prepare_codebase_investigator(args, &parts) {
            Ok(prepared) => prepared,
            Err(result) => return Ok(result),
        };
        let handle = match self.async_registry.register(&prepared.invocation.metadata) {
            Ok(handle) => handle,
            Err(err) => {
                return Ok(async_error(
                    err.code(),
                    err.reason(),
                    err.message(),
                    started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                ));
            }
        };
        let service = self.clone();
        let handle_for_task = handle.clone();
        let job_ct = handle.cancellation_token();
        tokio::spawn(async move {
            let result = service
                .run_prepared_codebase_investigator(prepared, job_ct)
                .await;
            let payload = result.structured_content.unwrap_or_else(|| {
                json!({
                    "ok": false,
                    "error_category": "tool_runtime",
                    "error": "codebase-investigator async runner did not produce structured content",
                })
            });
            let snapshot = handle_for_task.snapshot();
            let state = if snapshot.cancel_requested {
                GeminiAsyncInvocationState::Canceled
            } else if payload.get("ok").and_then(Value::as_bool) == Some(true) {
                GeminiAsyncInvocationState::Succeeded
            } else {
                GeminiAsyncInvocationState::Failed
            };
            handle_for_task.complete(state, payload, service.async_registry.retention());
        });
        Ok(async_success(
            async_snapshot_payload(&handle.snapshot(), false),
            started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        ))
    }
}

impl ServerHandler for GeminiMcp {
    fn get_info(&self) -> ServerInfo {
        rmcp_models::server_info(
            ProtocolVersion::V_2024_11_05,
            ServerCapabilities::builder().enable_tools().build(),
            Implementation::from_build_env(),
            Some(
                "Gemini CLI MCP tools for high-context analysis, codebase scouting, and deep investigations.".to_string(),
            ),
        )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        let tools = self.tool_router.list_all();
        std::future::ready(Ok(ListToolsResult {
            meta: None,
            tools,
            next_cursor: None,
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let tool_context = ToolCallContext::new(self, request, context);
        async move { self.tool_router.call(tool_context).await }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AskGeminiArgs, AskGeminiGuardrailMetrics, AskGeminiResponseMode, AskGeminiSqlGuardrails,
        AskGeminiSqlGuardrailsArgs, ErrorCategory, GeminiExecutionConfig,
        GeminiSessionProbeExecutionSummary, GeminiSessionProbeSnapshot, GeminiSessionStatsArgs,
        MOBILE_PROVIDER_EVIDENCE_QUERY_PACK_ID, ResolvedModel, ResponseEnvelopeDebugArtifact,
        ResponseEnvelopeDebugRecord, ResumeLedgerState, ResumeStrategy, SessionCompressionResult,
        SessionProbeSnapshotArtifact, TokenUsageLedger, ToolCallUsageAccumulator,
        ToolUsageLedgerRecord, ValidationIssue, allowed_models_hint, apply_ask_explain_mode_prompt,
        ask_gemini_payload, ask_gemini_response_text_fallback, attach_context_window_metadata,
        attach_resolved_session_id, attach_resume_metadata, attach_session_compression_metadata,
        blocking_codebase_fallback_category, build_sql_guardrail_prompt,
        build_sql_guardrail_repair_prompt, cached_session_probe_warning, classify_stderr_error,
        codebase_investigator_fallback_prompt, codebase_investigator_prompt,
        codebase_scout_fallback_prompt, codebase_scout_prompt, current_unix_timestamp_ms,
        default_to_no_nested_mcp_servers, extract_context_window_snapshot,
        extract_sql_table_references, extract_token_usage, is_cache_eligible_session_probe_failure,
        mobile_provider_evidence_prompt, model_not_allowed_issue, next_allowlisted_downgrade_model,
        normalize_allowed_mcp_servers_override, normalize_ask_gemini_output,
        normalize_codebase_tool_response, normalize_mobile_provider_field, normalize_model_list,
        normalize_optional_model_field, normalize_optional_resume_selector,
        normalize_sql_identifier, parse_json_response, parse_session_probe_snapshot,
        parse_session_stats_snapshot, parse_stats_session_duration_seconds,
        reliability_metadata_from_error_label, resolve_model, resolve_scoped_ask_gemini_target,
        resolve_session_id_from_gemini_error, resolve_session_id_from_gemini_output,
        resume_context_mode_label, sanitize_codebase_tool_output,
        session_compression_result_from_bridge, validate_required_text_field,
        validate_sql_guardrail_output, validate_target_within_include_directories,
    };
    use crate::config::AllowedMcpServers;
    use crate::executor::{GeminiExecutionError, GeminiOutputFormat, GeminiResponse};
    use crate::resume::ResumeExecutionPlan;
    use rmcp::handler::server::tool::Extension;
    use rmcp::handler::server::wrapper::Parameters;
    use serde_json::json;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn codebase_scout_prompt_has_required_guardrails_and_schema() {
        let prompt = codebase_scout_prompt("/tmp/repo", "where are extractors?");
        assert!(prompt.contains("Hard rules:"));
        assert!(prompt.contains("Do not invent files"));
        assert!(prompt.contains("delegate_to_agent"));
        assert!(prompt.contains("codebase_investigator"));
        assert!(
            prompt.contains(
                "Do not guess tool names or call tools that are not explicitly available."
            )
        );
        assert!(prompt.contains("single JSON object"));
        assert!(prompt.contains("\"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\""));
        assert!(prompt.contains("\"top_hits\""));
        assert!(!prompt.contains("@/tmp/repo"));
        assert!(!prompt.contains(
            "If `delegate_to_agent` is unavailable but tool `codebase_investigator` exists"
        ));
        assert!(
            prompt.contains(
                "Do not repeat the input question or target path in the response payload."
            )
        );
    }

    #[test]
    fn fallback_prompt_is_json_only_and_has_status() {
        let prompt = codebase_scout_fallback_prompt("/tmp/repo", "question");
        assert!(prompt.contains("Return JSON only"));
        assert!(!prompt.contains("delegate_to_agent"));
        assert!(prompt.contains(
            "Investigate directly using only tools explicitly available in the runtime."
        ));
        assert!(prompt.contains("Do not delegate and do not guess tool names."));
        assert!(prompt.contains("\"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\""));
        assert!(prompt.contains("\"top_hits\""));
    }

    #[test]
    fn investigator_prompt_mentions_subagent_and_contract() {
        let prompt = codebase_investigator_prompt("/tmp/repo", "find root cause");
        assert!(!prompt.contains("delegate_to_agent"));
        assert!(!prompt.contains("codebase_investigator"));
        assert!(prompt.contains(
            "Investigate directly using only tools explicitly available in the runtime."
        ));
        assert!(
            prompt.contains(
                "Do not guess tool names or call tools that are not explicitly available."
            )
        );
        assert!(prompt.contains("\"relevant_locations\""));
        assert!(prompt.contains("\"impact_map\""));
        assert!(prompt.contains("single JSON object"));
        assert!(
            prompt.contains("Do not repeat the objective or target path in the response payload.")
        );
    }

    #[test]
    fn mobile_provider_evidence_prompt_is_bounded_and_structured() {
        let prompt = mobile_provider_evidence_prompt(&[
            "Dodo".to_string(),
            "Optus".to_string(),
            "Moose".to_string(),
            "ALDI".to_string(),
        ]);
        assert!(prompt.contains("execute_sql"));
        assert!(prompt.contains(MOBILE_PROVIDER_EVIDENCE_QUERY_PACK_ID));
        assert!(prompt.contains("Q1 max_dates"));
        assert!(prompt.contains("Q6 provider_month_ci_current_counts"));
        assert!(prompt.contains("LIMIT 50"));
        assert!(prompt.contains("\"sql_citations\""));
        assert!(prompt.contains("\"actionable_outcome\""));
    }

    #[test]
    fn normalize_mobile_provider_field_defaults_and_deduplicates() {
        let mut errors = Vec::new();
        let defaults = normalize_mobile_provider_field(Vec::new(), &mut errors);
        assert!(errors.is_empty());
        assert_eq!(
            defaults,
            vec![
                "Dodo".to_string(),
                "Optus".to_string(),
                "Moose".to_string(),
                "ALDI".to_string(),
            ]
        );

        let custom = normalize_mobile_provider_field(
            vec![
                " dodo ".to_string(),
                "Dodo".to_string(),
                "Moose".to_string(),
                " ".to_string(),
                "ALDI".to_string(),
            ],
            &mut errors,
        );
        assert!(errors.is_empty());
        assert_eq!(
            custom,
            vec!["dodo".to_string(), "Moose".to_string(), "ALDI".to_string(),]
        );
    }

    #[test]
    fn ask_gemini_args_default_sandbox_is_false() {
        let parsed: AskGeminiArgs =
            serde_json::from_value(json!({"prompt": "ping"})).expect("parse ask args");
        assert!(!parsed.sandbox);
        assert!(!parsed.explain);
        assert!(matches!(parsed.response_mode, AskGeminiResponseMode::Full));
    }

    #[test]
    fn ask_gemini_response_mode_maps_to_expected_output_format() {
        assert_eq!(
            AskGeminiResponseMode::Full.output_format(),
            GeminiOutputFormat::Text
        );
        assert_eq!(
            AskGeminiResponseMode::FinalOnly.output_format(),
            GeminiOutputFormat::Json
        );
        assert_eq!(
            AskGeminiResponseMode::StructuredJson.output_format(),
            GeminiOutputFormat::Json
        );
    }

    #[test]
    fn normalize_ask_gemini_output_prefers_response_field_and_parses_embedded_json() {
        let payload = normalize_ask_gemini_output(
            r#"{"response":"{\"status\":\"ok\",\"summary\":\"clean\"}","session_id":"abc","stats":{"totalCalls":2}}"#,
        );
        assert_eq!(
            payload.response_text,
            r#"{"status":"ok","summary":"clean"}"#
        );
        let Some(response_json) = payload.response_json else {
            panic!("expected parsed response json");
        };
        assert_eq!(response_json["status"], "ok");
        assert_eq!(response_json["summary"], "clean");
        assert!(response_json["session_id"].is_null());
        let Some(response_envelope) = payload.response_envelope else {
            panic!("expected parsed response envelope");
        };
        assert_eq!(response_envelope["session_id"], "abc");
        assert_eq!(response_envelope["stats"]["totalCalls"], 2);
    }

    #[test]
    fn ask_gemini_response_text_fallback_uses_structured_payload_when_response_is_blank() {
        let payload = normalize_ask_gemini_output(
            r#"{"response":"","status":"ok","summary":"clean","session_id":"abc"}"#,
        );
        let fallback = ask_gemini_response_text_fallback(
            payload.response_json.as_ref(),
            payload.response_envelope.as_ref(),
            "",
        );
        let Some(fallback) = fallback else {
            panic!("expected fallback text");
        };
        assert_eq!(
            fallback,
            r#"{"response":"","status":"ok","summary":"clean"}"#
        );
    }

    #[test]
    fn ask_gemini_response_text_fallback_rejects_empty_envelope_only() {
        let payload = normalize_ask_gemini_output(
            r#"{"response":"","session_id":"abc","stats":{"totalCalls":2}}"#,
        );
        let fallback = ask_gemini_response_text_fallback(
            payload.response_json.as_ref(),
            payload.response_envelope.as_ref(),
            "",
        );
        assert!(fallback.is_none());
    }

    #[test]
    fn apply_ask_explain_mode_prompt_appends_transparency_guidance() {
        let prompt = apply_ask_explain_mode_prompt("Solve this task".to_string(), true);
        assert!(prompt.contains("Solve this task"));
        assert!(prompt.contains("Reasoning Summary"));
        assert!(prompt.contains("Do not expose hidden chain-of-thought"));
    }

    #[test]
    fn ask_gemini_payload_always_carries_explain_and_session_metadata() {
        let payload = ask_gemini_payload(json!({"ok": true}), true, Some("session-xyz"));
        assert_eq!(payload["resolved_session_id"], "session-xyz");
        assert_eq!(payload["explain_mode_requested"], true);
    }

    #[test]
    fn attach_resolved_session_id_sets_null_when_unavailable() {
        let payload = attach_resolved_session_id(json!({"ok": true}), None);
        assert_eq!(payload["resolved_session_id"], serde_json::Value::Null);
    }

    #[test]
    fn resolve_session_id_from_output_prefers_structured_json() {
        let resume_plan = ResumeExecutionPlan {
            requested: false,
            selector: None,
            strategy: ResumeStrategy::Inherit,
        };
        let resume_state = ResumeLedgerState::from_plan(&resume_plan);
        let output = GeminiResponse {
            stdout: r#"{"ok":true,"response":"done","session_id":"session-json-123"}"#.to_string(),
            stderr: String::new(),
            retry_count: 0,
        };

        let resolved = resolve_session_id_from_gemini_output(&output, &resume_plan, &resume_state);
        assert_eq!(resolved.as_deref(), Some("session-json-123"));
    }

    #[test]
    fn resolve_session_id_from_output_supports_session_object_id() {
        let resume_plan = ResumeExecutionPlan {
            requested: false,
            selector: None,
            strategy: ResumeStrategy::Inherit,
        };
        let resume_state = ResumeLedgerState::from_plan(&resume_plan);
        let output = GeminiResponse {
            stdout: r#"{"ok":true,"session":{"id":"session-object-789"}}"#.to_string(),
            stderr: String::new(),
            retry_count: 0,
        };

        let resolved = resolve_session_id_from_gemini_output(&output, &resume_plan, &resume_state);
        assert_eq!(resolved.as_deref(), Some("session-object-789"));
    }

    #[test]
    fn resolve_session_id_from_output_ignores_unrelated_nested_session_id() {
        let resume_plan = ResumeExecutionPlan {
            requested: false,
            selector: None,
            strategy: ResumeStrategy::Inherit,
        };
        let resume_state = ResumeLedgerState::from_plan(&resume_plan);
        let output = GeminiResponse {
            stdout: r#"{"ok":true,"response":{"details":{"session_id":"nested-session-should-not-match"}}}"#
                .to_string(),
            stderr: String::new(),
            retry_count: 0,
        };

        let resolved = resolve_session_id_from_gemini_output(&output, &resume_plan, &resume_state);
        assert_eq!(resolved, None);
    }

    #[test]
    fn resolve_session_id_from_output_supports_plain_text_stats_line() {
        let resume_plan = ResumeExecutionPlan {
            requested: false,
            selector: None,
            strategy: ResumeStrategy::Inherit,
        };
        let resume_state = ResumeLedgerState::from_plan(&resume_plan);
        let output = GeminiResponse {
            stdout: "Session ID: text-session-456\nTier: test".to_string(),
            stderr: String::new(),
            retry_count: 0,
        };

        let resolved = resolve_session_id_from_gemini_output(&output, &resume_plan, &resume_state);
        assert_eq!(resolved.as_deref(), Some("text-session-456"));
    }

    #[test]
    fn resolve_session_id_falls_back_to_applied_resume_uuid() {
        let resume_plan = ResumeExecutionPlan {
            requested: true,
            selector: Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            strategy: ResumeStrategy::Inherit,
        };
        let mut resume_state = ResumeLedgerState::from_plan(&resume_plan);
        resume_state.mark_applied();
        let output = GeminiResponse {
            stdout: String::new(),
            stderr: String::new(),
            retry_count: 0,
        };

        let resolved = resolve_session_id_from_gemini_output(&output, &resume_plan, &resume_state);
        assert_eq!(
            resolved.as_deref(),
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b")
        );
    }

    #[test]
    fn resolve_session_id_falls_back_to_applied_session_selector_with_prefix() {
        let resume_plan = ResumeExecutionPlan {
            requested: true,
            selector: Some("session-81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            strategy: ResumeStrategy::Inherit,
        };
        let mut resume_state = ResumeLedgerState::from_plan(&resume_plan);
        resume_state.mark_applied();
        let output = GeminiResponse {
            stdout: String::new(),
            stderr: String::new(),
            retry_count: 0,
        };

        let resolved = resolve_session_id_from_gemini_output(&output, &resume_plan, &resume_state);
        assert_eq!(
            resolved.as_deref(),
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b")
        );
    }

    #[test]
    fn resolve_session_id_from_error_parses_failed_exit_stderr_json() {
        let resume_plan = ResumeExecutionPlan {
            requested: true,
            selector: Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            strategy: ResumeStrategy::Inherit,
        };
        let mut resume_state = ResumeLedgerState::from_plan(&resume_plan);
        resume_state.mark_applied();
        let error = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: r#"{"error":"upstream unavailable","session_id":"session-from-error"}"#
                .to_string(),
        };

        let resolved = resolve_session_id_from_gemini_error(&error, &resume_plan, &resume_state);
        assert_eq!(resolved.as_deref(), Some("session-from-error"));
    }

    #[test]
    fn normalize_sql_identifier_rejects_invalid_tokens() {
        assert_eq!(
            normalize_sql_identifier("\"ops\".\"events\""),
            Some("ops.events".to_string())
        );
        assert_eq!(
            normalize_sql_identifier(" analytics.report_runs "),
            Some("analytics.report_runs".to_string())
        );
        assert!(normalize_sql_identifier("ops.events;drop table x").is_none());
        assert!(normalize_sql_identifier("   ").is_none());
    }

    #[test]
    fn extract_sql_table_references_handles_from_join_and_update() {
        let refs = extract_sql_table_references(
            "select * from ops.run_events e join analytics.rollups r on r.id=e.id; update ops.run_events set x=1",
        );
        assert_eq!(
            refs,
            vec![
                "ops.run_events".to_string(),
                "analytics.rollups".to_string(),
            ]
        );
    }

    #[test]
    fn sql_guardrails_from_args_requires_allowlist() {
        let mut issues = Vec::<ValidationIssue>::new();
        let guardrails = AskGeminiSqlGuardrails::from_args(
            AskGeminiSqlGuardrailsArgs {
                allowed_tables: Vec::new(),
                allowed_table_prefixes: Vec::new(),
                denied_tables: Vec::new(),
                repair_attempts: 1,
            },
            &mut issues,
        );
        assert!(guardrails.is_none());
        assert!(issues.iter().any(|issue| issue.field == "sql_guardrails"));
    }

    #[test]
    fn validate_sql_guardrail_output_accepts_valid_contract() {
        let mut issues = Vec::<ValidationIssue>::new();
        let guardrails = AskGeminiSqlGuardrails::from_args(
            AskGeminiSqlGuardrailsArgs {
                allowed_tables: vec!["ops.run_events".to_string()],
                allowed_table_prefixes: vec!["analytics.".to_string()],
                denied_tables: vec!["ops.secrets".to_string()],
                repair_attempts: 1,
            },
            &mut issues,
        )
        .expect("guardrail policy should parse");
        assert!(issues.is_empty());

        let raw_output = r#"{
            "response": {
                "verified_findings": ["stable"],
                "inferred_hypotheses": [],
                "sql_citations": [
                    {"purpose":"count","sql":"select count(*) from ops.run_events"},
                    {"purpose":"trend","sql":"select * from analytics.rollups"}
                ],
                "unknowns": []
            }
        }"#;
        let parsed = validate_sql_guardrail_output(raw_output, &guardrails)
            .expect("valid SQL response should satisfy strict contract");
        assert_eq!(parsed["verified_findings"][0], "stable");
    }

    #[test]
    fn validate_sql_guardrail_output_rejects_out_of_scope_tables() {
        let mut issues = Vec::<ValidationIssue>::new();
        let guardrails = AskGeminiSqlGuardrails::from_args(
            AskGeminiSqlGuardrailsArgs {
                allowed_tables: vec!["ops.run_events".to_string()],
                allowed_table_prefixes: Vec::new(),
                denied_tables: Vec::new(),
                repair_attempts: 1,
            },
            &mut issues,
        )
        .expect("guardrail policy should parse");
        assert!(issues.is_empty());

        let raw_output = r#"{
            "verified_findings": [],
            "inferred_hypotheses": [],
            "sql_citations": [
                {"purpose":"oops","sql":"select * from ops.other_table"}
            ],
            "unknowns": []
        }"#;
        let drift = validate_sql_guardrail_output(raw_output, &guardrails)
            .expect_err("out-of-policy SQL table should fail contract validation");
        assert_eq!(drift.reason_code, "invalid_contract");
        assert!(drift.invalid_table_refs >= 1);
    }

    #[test]
    fn sql_guardrail_prompts_include_contract_and_policy() {
        let mut issues = Vec::<ValidationIssue>::new();
        let guardrails = AskGeminiSqlGuardrails::from_args(
            AskGeminiSqlGuardrailsArgs {
                allowed_tables: vec!["ops.run_events".to_string()],
                allowed_table_prefixes: vec!["analytics.".to_string()],
                denied_tables: vec!["ops.secrets".to_string()],
                repair_attempts: 1,
            },
            &mut issues,
        )
        .expect("guardrail policy should parse");
        assert!(issues.is_empty());

        let prompt = build_sql_guardrail_prompt("Investigate retries", &guardrails);
        assert!(prompt.contains("Strict SQL response contract"));
        assert!(prompt.contains("verified_findings"));
        assert!(prompt.contains("ops.run_events"));

        let drift =
            validate_sql_guardrail_output("{}", &guardrails).expect_err("empty object should fail");
        let repair_prompt =
            build_sql_guardrail_repair_prompt("Investigate retries", &drift, &guardrails);
        assert!(repair_prompt.contains("Validation errors"));
        assert!(repair_prompt.contains("ops.run_events"));
    }

    #[test]
    fn guardrail_metrics_record_drift_counts() {
        let mut metrics = AskGeminiGuardrailMetrics::default();
        let drift = super::AskGeminiContractDrift {
            reason_code: "invalid_contract",
            issues: vec!["missing sql_citations".to_string()],
            invalid_table_refs: 2,
            citation_missing: 1,
        };
        metrics.record_drift(&drift);
        assert_eq!(metrics.drift_detected, 1);
        assert_eq!(metrics.invalid_table_refs, 2);
        assert_eq!(metrics.citation_missing, 1);
    }

    #[test]
    fn parse_json_response_handles_empty_and_non_json_inputs() {
        assert!(parse_json_response("{ \"ok\": true }").is_some());
        assert!(parse_json_response("  ").is_none());
        assert!(parse_json_response("status: ok").is_none());
    }

    #[test]
    fn parse_stats_session_duration_supports_human_units() {
        assert_eq!(parse_stats_session_duration_seconds("8h 15m"), Some(29_700));
        assert_eq!(
            parse_stats_session_duration_seconds("1d 2h 30m 10s"),
            Some(95_410)
        );
        assert_eq!(parse_stats_session_duration_seconds("reset soon"), None);
    }

    #[test]
    fn parse_session_stats_snapshot_extracts_quota_rows() {
        let raw = r#"
╭──────────────────────────────────────────╮
│ Session Stats                            │
│ Session ID:                 81acb59f-3c1f-4d14-91a4-98c8359e4e1b
│ Auth Method:                Logged in with Google (grant@example.com)
│ Tier:                       Gemini Code Assist for individuals
│ Model                       Reqs             Usage remaining
│ gemini-2.5-flash              -         14.3% resets in 8h 15m
│ gemini-2.5-pro                12        50.0% resets in 8h 10m
╰──────────────────────────────────────────╯
"#;

        let snapshot = parse_session_stats_snapshot(raw);
        assert_eq!(
            snapshot.session_id.as_deref(),
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b")
        );
        assert!(
            snapshot
                .auth_method
                .as_deref()
                .map(|value| value.contains("Logged in with Google"))
                .unwrap_or(false)
        );
        assert_eq!(
            snapshot.tier.as_deref(),
            Some("Gemini Code Assist for individuals")
        );
        assert_eq!(snapshot.quotas.len(), 2);
        assert_eq!(snapshot.quotas[0].model, "gemini-2.5-flash");
        assert_eq!(snapshot.quotas[0].requests_raw.as_deref(), Some("-"));
        assert_eq!(snapshot.quotas[0].requests, None);
        assert_eq!(snapshot.quotas[0].usage_remaining_percent, Some(14.3));
        assert_eq!(snapshot.quotas[0].reset_in.as_deref(), Some("8h 15m"));
        assert_eq!(snapshot.quotas[0].reset_in_seconds, Some(29_700));
        assert!(snapshot.quotas[0].reset_at_unix_ms.is_some());

        assert_eq!(snapshot.quotas[1].model, "gemini-2.5-pro");
        assert_eq!(snapshot.quotas[1].requests, Some(12));
        assert_eq!(snapshot.quotas[1].usage_remaining_percent, Some(50.0));
        assert_eq!(snapshot.quotas[1].reset_in.as_deref(), Some("8h 10m"));
    }

    #[test]
    fn parse_session_probe_snapshot_extracts_session_id_and_stats() {
        let raw = r#"{
  "session_id": "session-probe-1",
  "response": "OK",
  "stats": {
    "total_tokens": 9,
    "input_tokens": 6,
    "output_tokens": 3,
    "cached": 2,
    "input": 4,
    "duration_ms": 1234,
    "tool_calls": 0
  }
}"#;

        let snapshot = parse_session_probe_snapshot(raw, "");
        assert_eq!(snapshot.session_id.as_deref(), Some("session-probe-1"));
        assert_eq!(snapshot.probe_stats.total_tokens, Some(9));
        assert_eq!(snapshot.probe_stats.input_tokens, Some(6));
        assert_eq!(snapshot.probe_stats.output_tokens, Some(3));
        assert_eq!(snapshot.probe_stats.cached_tokens, Some(2));
        assert_eq!(snapshot.probe_stats.direct_input_tokens, Some(4));
        assert_eq!(snapshot.probe_stats.duration_ms, Some(1234));
        assert_eq!(snapshot.probe_stats.tool_calls, Some(0));
    }

    #[test]
    fn extract_token_usage_reads_usage_metadata_json() {
        let stdout = r#"{
            "status": "OK",
            "usageMetadata": {
                "promptTokenCount": 17,
                "candidatesTokenCount": 9,
                "totalTokenCount": 26
            }
        }"#;
        let extracted = extract_token_usage(stdout, "").expect("expected usage extraction");
        assert_eq!(extracted.usage.input_tokens, Some(17));
        assert_eq!(extracted.usage.output_tokens, Some(9));
        assert_eq!(extracted.usage.total_tokens, Some(26));
        assert!(extracted.source.starts_with("stdout:json:"));
    }

    #[test]
    fn extract_token_usage_reads_stats_role_tokens() {
        let stdout = r#"{
            "response": "{\"status\":\"OK\"}",
            "session_id": "session-123",
            "stats": {
                "models": {
                    "gemini-3-pro-preview": {
                        "roles": {
                            "main": {
                                "tokens": {
                                    "cached": 7072,
                                    "candidates": 691,
                                    "input": 13101,
                                    "prompt": 20173,
                                    "thoughts": 2239,
                                    "tool": 0,
                                    "total": 23103
                                }
                            }
                        }
                    },
                    "gemini-3-flash-preview": {
                        "roles": {
                            "subagent": {
                                "tokens": {
                                    "cached": 150024,
                                    "candidates": 1509,
                                    "input": 88310,
                                    "prompt": 238334,
                                    "thoughts": 5853,
                                    "tool": 0,
                                    "total": 245696
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let extracted = extract_token_usage(stdout, "").expect("expected usage extraction");
        assert_eq!(extracted.usage.input_tokens, Some(258507));
        assert_eq!(extracted.usage.output_tokens, Some(2200));
        assert_eq!(extracted.usage.total_tokens, Some(268799));
        assert_eq!(extracted.usage.reasoning_tokens, Some(8092));
        assert_eq!(extracted.usage.cache_read_tokens, Some(157096));
        assert_eq!(
            extracted.source,
            "stdout:json:$.stats.models.*.roles.*.tokens"
        );
    }

    #[test]
    fn extract_token_usage_reads_stats_model_tokens_without_roles() {
        let stdout = r#"{
            "status": "OK",
            "stats": {
                "models": {
                    "gemini-3-pro-preview": {
                        "tokens": {
                            "prompt": 120,
                            "candidates": 7,
                            "total": 127
                        }
                    }
                }
            }
        }"#;
        let extracted = extract_token_usage(stdout, "").expect("expected usage extraction");
        assert_eq!(extracted.usage.input_tokens, Some(120));
        assert_eq!(extracted.usage.output_tokens, Some(7));
        assert_eq!(extracted.usage.total_tokens, Some(127));
        assert_eq!(extracted.source, "stdout:json:$.stats.models.*.tokens");
    }

    #[test]
    fn extract_token_usage_falls_back_to_text_summary() {
        let stderr = "request complete: input tokens 12 output tokens 5 total tokens 17";
        let extracted = extract_token_usage("", stderr).expect("expected text usage extraction");
        assert_eq!(extracted.usage.input_tokens, Some(12));
        assert_eq!(extracted.usage.output_tokens, Some(5));
        assert_eq!(extracted.usage.total_tokens, Some(17));
        assert_eq!(extracted.source, "stderr:text");
    }

    #[test]
    fn extract_context_window_snapshot_reads_json_remaining_percent() {
        let stdout = r#"{
            "session": {
                "contextWindow": {
                    "remainingPercent": 14.3
                }
            }
        }"#;

        let snapshot =
            extract_context_window_snapshot(stdout, "").expect("expected context snapshot");
        assert_eq!(snapshot.percent_remaining, Some(14.3));
        assert_eq!(snapshot.percent_used, Some(85.7));
        assert!(
            snapshot
                .source
                .as_deref()
                .map(|source| source.starts_with("stdout:json:"))
                .unwrap_or(false)
        );
    }

    #[test]
    fn extract_context_window_snapshot_reads_text_used_percent() {
        let stderr = "footer: context window used 73.2% for this session";
        let snapshot =
            extract_context_window_snapshot("", stderr).expect("expected context snapshot");
        assert_eq!(snapshot.percent_used, Some(73.2));
        assert_eq!(snapshot.percent_remaining, Some(26.8));
        assert_eq!(snapshot.source.as_deref(), Some("stderr:text:context_used"));
    }

    #[test]
    fn attach_session_compression_metadata_includes_requested_result() {
        let compression = SessionCompressionResult {
            mode: "auto".to_string(),
            decision_source: "server_default".to_string(),
            requested: true,
            attempted: true,
            ok: true,
            skipped_reason: None,
            error_category: None,
            error: None,
            retry_count: Some(2),
            compression_status: Some("COMPRESSED".to_string()),
            original_token_count: Some(1200),
            new_token_count: Some(640),
            session_id: Some("session-compressed".to_string()),
            conversation_file: Some("/tmp/session.json".to_string()),
        };

        let payload = attach_session_compression_metadata(json!({"ok": true}), Some(&compression));
        assert_eq!(payload["session_compression"]["requested"], true);
        assert_eq!(payload["session_compression"]["retry_count"], 2);
        assert_eq!(
            payload["session_compression"]["compression_status"],
            "COMPRESSED"
        );
        assert_eq!(payload["session_compression"]["original_token_count"], 1200);
        assert_eq!(payload["session_compression"]["new_token_count"], 640);
        assert_eq!(
            payload["session_compression"]["session_id"],
            "session-compressed"
        );
        assert_eq!(
            payload["session_compression"]["conversation_file"],
            "/tmp/session.json"
        );

        let payload = attach_context_window_metadata(
            payload,
            Some(&super::ContextWindowSnapshot {
                percent_used: Some(88.0),
                percent_remaining: Some(12.0),
                source: Some("stdout:text:context_used".to_string()),
            }),
        );
        assert_eq!(payload["context_window"]["percent_used"], 88.0);
        assert_eq!(payload["context_window"]["percent_remaining"], 12.0);
    }

    #[test]
    fn session_compression_result_from_bridge_preserves_success_metadata() {
        let result = session_compression_result_from_bridge(
            super::SessionCompressionMode::Auto,
            super::SessionCompressionDecisionSource::ServerDefault,
            true,
            super::SessionCompressionBridgeResult {
                ok: true,
                compression_status: Some("CONTENT_TRUNCATED".to_string()),
                original_token_count: Some(2100),
                new_token_count: Some(1600),
                session_id: Some("session-bridge".to_string()),
                conversation_file: Some("/tmp/bridge.json".to_string()),
                error_category: None,
                error: None,
            },
        );

        assert!(result.ok);
        assert_eq!(result.error_category, None);
        assert_eq!(
            result.compression_status.as_deref(),
            Some("CONTENT_TRUNCATED")
        );
        assert_eq!(result.original_token_count, Some(2100));
        assert_eq!(result.new_token_count, Some(1600));
        assert_eq!(result.session_id.as_deref(), Some("session-bridge"));
    }

    #[test]
    fn session_compression_result_from_bridge_marks_failure_status() {
        let result = session_compression_result_from_bridge(
            super::SessionCompressionMode::Auto,
            super::SessionCompressionDecisionSource::ToolOverride,
            true,
            super::SessionCompressionBridgeResult {
                ok: true,
                compression_status: Some("COMPRESSION_FAILED_INFLATED_TOKEN_COUNT".to_string()),
                original_token_count: Some(4000),
                new_token_count: Some(4300),
                session_id: None,
                conversation_file: None,
                error_category: None,
                error: None,
            },
        );

        assert!(!result.ok);
        assert_eq!(
            result.error_category.as_deref(),
            Some(super::ErrorCategory::ToolRuntime.as_str())
        );
        assert_eq!(
            result.error.as_deref(),
            Some("Gemini compression finished with status COMPRESSION_FAILED_INFLATED_TOKEN_COUNT")
        );
    }

    #[test]
    fn resolve_session_compression_policy_honors_server_default_and_override() {
        let mcp = super::GeminiMcp::new(GeminiExecutionConfig::default());
        assert_eq!(
            mcp.resolve_session_compression_policy(None),
            (
                super::SessionCompressionMode::Auto,
                super::SessionCompressionDecisionSource::ServerDefault
            )
        );
        assert_eq!(
            mcp.resolve_session_compression_policy(Some(false)),
            (
                super::SessionCompressionMode::Disabled,
                super::SessionCompressionDecisionSource::ToolOverride
            )
        );

        let mcp = super::GeminiMcp::new(GeminiExecutionConfig {
            resume_compression_default: crate::config::ResumeCompressionDefault::Off,
            ..GeminiExecutionConfig::default()
        });
        assert_eq!(
            mcp.resolve_session_compression_policy(None),
            (
                super::SessionCompressionMode::Disabled,
                super::SessionCompressionDecisionSource::ServerDefault
            )
        );
    }

    #[test]
    fn evaluate_context_guardrail_warns_only_for_resumed_hot_sessions() {
        let mcp = super::GeminiMcp::new(GeminiExecutionConfig {
            resume_context_warn_percent: 70,
            ..GeminiExecutionConfig::default()
        });
        let mut usage = ToolCallUsageAccumulator::default();
        usage.context_window = Some(super::ContextWindowSnapshot {
            percent_used: Some(82.0),
            percent_remaining: Some(18.0),
            source: Some("stdout:text:context_used".to_string()),
        });

        let fresh_resume = ResumeLedgerState::from_request(None, ResumeStrategy::Inherit);
        assert!(
            mcp.evaluate_context_guardrail(&fresh_resume, &usage)
                .is_none()
        );

        let mut resumed = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::Inherit,
        );
        resumed.mark_applied();
        let guardrail = mcp
            .evaluate_context_guardrail(&resumed, &usage)
            .expect("resumed call should evaluate guardrail");
        assert_eq!(guardrail.mode, "warn");
        assert!(guardrail.warned);
        assert_eq!(guardrail.threshold_percent, 70);
        assert_eq!(guardrail.percent_used, Some(82.0));
    }

    #[test]
    fn sanitize_codebase_tool_output_removes_redundant_input_fields() {
        let input = json!({
            "status": "OK",
            "question": "How is this done?",
            "target": "/tmp/repo",
            "top_hits": [
                {"path": "src/lib.rs", "question": "nested question"}
            ],
            "details": {
                "objective": "hidden",
                "summary": "works"
            }
        });
        let sanitized = sanitize_codebase_tool_output(input);
        let Some(object) = sanitized.as_object() else {
            panic!("expected object");
        };
        assert!(!object.contains_key("question"));
        assert!(!object.contains_key("target"));
        assert_eq!(object["status"], "OK");
        assert_eq!(object["top_hits"][0]["path"], "src/lib.rs");
        let nested_top_hit = object["top_hits"][0]
            .as_object()
            .expect("top hit should be object");
        assert!(!nested_top_hit.contains_key("question"));
        let details = object["details"]
            .as_object()
            .expect("details should be object");
        assert!(!details.contains_key("objective"));
        assert_eq!(details["summary"], "works");
    }

    #[test]
    fn normalize_codebase_tool_response_unwraps_response_envelope() {
        let envelope = json!({
            "response": "```json\n{\"status\":\"OK\",\"summary\":\"looks good\",\"objective\":\"drop this\"}\n```",
            "session_id": "abc-123",
            "stats": {"tokens": 42}
        });
        let (normalized, debug_envelope) =
            normalize_codebase_tool_response(envelope.clone()).expect("normalize envelope");

        assert_eq!(normalized["status"], "OK");
        assert_eq!(normalized["summary"], "looks good");
        let Some(normalized_object) = normalized.as_object() else {
            panic!("normalized output should be object");
        };
        assert!(!normalized_object.contains_key("objective"));
        assert_eq!(debug_envelope, Some(envelope));
    }

    #[test]
    fn normalize_codebase_tool_response_drops_session_metadata_for_plain_json() {
        let parsed = json!({
            "status": "OK",
            "summary": "stable",
            "session_id": "should-not-propagate",
            "stats": {"totalCalls": 99},
            "target": "/tmp/repo"
        });
        let (normalized, debug_envelope) =
            normalize_codebase_tool_response(parsed).expect("normalize plain json");

        assert_eq!(normalized["status"], "OK");
        let Some(normalized_object) = normalized.as_object() else {
            panic!("normalized output should be object");
        };
        assert!(!normalized_object.contains_key("session_id"));
        assert!(!normalized_object.contains_key("stats"));
        assert!(!normalized_object.contains_key("target"));
        assert!(debug_envelope.is_none());
    }

    #[test]
    fn normalize_codebase_tool_response_rejects_invalid_response_envelope_payload() {
        let parsed = json!({
            "response": "not-json",
            "session_id": "abc",
            "stats": {"totalCalls": 1}
        });
        assert!(normalize_codebase_tool_response(parsed).is_none());
    }

    #[test]
    fn resume_context_mode_reports_fresh_resumed_and_fallback_states() {
        let fresh = ResumeLedgerState::from_request(None, ResumeStrategy::Inherit);
        assert_eq!(resume_context_mode_label(&fresh), "fresh");

        let mut resumed = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::Inherit,
        );
        assert_eq!(resume_context_mode_label(&resumed), "resume_requested");
        resumed.mark_applied();
        assert_eq!(resume_context_mode_label(&resumed), "resumed");

        let mut fallback = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::FreshIfMissing,
        );
        fallback.mark_missing_fallback();
        assert_eq!(resume_context_mode_label(&fallback), "fresh_fallback");

        let mut unavailable = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::Inherit,
        );
        unavailable.mark_invalid();
        assert_eq!(
            resume_context_mode_label(&unavailable),
            "resume_unavailable"
        );

        let mut fallback_failed = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::FreshIfMissing,
        );
        fallback_failed.mark_missing_fallback_failed();
        assert_eq!(
            resume_context_mode_label(&fallback_failed),
            "resume_fallback_failed"
        );
    }

    #[test]
    fn attach_resume_metadata_adds_resume_object_to_structured_payloads() {
        let mut resume = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::FreshIfMissing,
        );
        resume.mark_missing_fallback();

        let enriched = attach_resume_metadata(json!({"ok": true}), &resume);
        assert_eq!(enriched["ok"], true);
        assert_eq!(enriched["resume"]["requested"], true);
        assert_eq!(
            enriched["resume"]["selector"],
            "81acb59f-3c1f-4d14-91a4-98c8359e4e1b"
        );
        assert_eq!(enriched["resume"]["strategy"], "fresh_if_missing");
        assert_eq!(enriched["resume"]["applied"], false);
        assert_eq!(enriched["resume"]["outcome"], "missing_fallback");
        assert_eq!(enriched["resume"]["context_mode"], "fresh_fallback");
        assert_eq!(
            enriched["resume_diagnostic"]["code"],
            "resume_unavailable_fresh_fallback"
        );
        assert_eq!(enriched["resume_diagnostic"]["severity"], "warning");
    }

    #[test]
    fn attach_resume_metadata_adds_error_diagnostic_for_invalid_resume() {
        let mut resume = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::Inherit,
        );
        resume.mark_invalid();

        let enriched = attach_resume_metadata(json!({"ok": false}), &resume);
        assert_eq!(enriched["resume"]["outcome"], "invalid");
        assert_eq!(enriched["resume"]["context_mode"], "resume_unavailable");
        assert_eq!(enriched["resume_diagnostic"]["code"], "resume_unavailable");
        assert_eq!(enriched["resume_diagnostic"]["severity"], "error");
    }

    #[test]
    fn parse_codebase_tool_output_includes_resume_metadata() {
        let mcp = super::GeminiMcp::new(GeminiExecutionConfig::default());
        let model = ResolvedModel {
            requested: None,
            used: Some("gemini-3-flash-preview".to_string()),
            default_model_applied: false,
            fallback_mode: "requested",
            fallback_reason: None,
        };
        let mut resume = ResumeLedgerState::from_request(
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            ResumeStrategy::Inherit,
        );
        resume.mark_applied();

        let parsed = mcp
            .parse_codebase_tool_output(
                "codebase-scout",
                &model,
                &resume,
                r#"{"status":"OK","summary":"ready"}"#,
            )
            .expect("expected parsed json output");

        assert_eq!(parsed["status"], "OK");
        assert_eq!(parsed["summary"], "ready");
        assert_eq!(parsed["resume"]["context_mode"], "resumed");
        assert_eq!(
            parsed["resume"]["selector"],
            "81acb59f-3c1f-4d14-91a4-98c8359e4e1b"
        );
    }

    #[test]
    fn investigator_fallback_prompt_is_json_only() {
        let prompt = codebase_investigator_fallback_prompt("/tmp/repo", "find root cause");
        assert!(prompt.contains("Return JSON only"));
        assert!(!prompt.contains("delegate_to_agent"));
        assert!(prompt.contains(
            "Investigate directly using only tools explicitly available in the runtime."
        ));
        assert!(prompt.contains("Do not delegate and do not guess tool names."));
        assert!(prompt.contains("\"status\": \"OK|NO_ACCESS|INSUFFICIENT_CONTEXT\""));
        assert!(prompt.contains("\"relevant_locations\""));
    }

    #[test]
    fn usage_ledger_writes_jsonl_record_when_path_is_configured() {
        let path = std::env::temp_dir().join(format!(
            "gemini-usage-ledger-test-{}-{}.jsonl",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        let ledger = TokenUsageLedger {
            path: Some(path.clone()),
        };
        let record = ToolUsageLedgerRecord {
            version: 3,
            timestamp_ms: current_unix_timestamp_ms(),
            tool_name: "ask-gemini".to_string(),
            invocation_id: "gmi-test-1".to_string(),
            resolved_session_id: Some("session-usage-test".to_string()),
            ok: true,
            error_category: None,
            failure_class: None,
            retryability: None,
            salvageability: None,
            result_source: "live".to_string(),
            degraded: false,
            stale_age_ms: None,
            live_error_category: None,
            duration_ms: 42,
            gemini_invocations: 1,
            retry_count: 0,
            model_requested: Some("gemini-3-pro-preview".to_string()),
            model_used: Some("gemini-3-pro-preview".to_string()),
            resume_requested: true,
            resume_selector: Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            resume_strategy: Some("fresh_if_missing".to_string()),
            resume_applied: false,
            resume_outcome: Some("missing_fallback".to_string()),
            default_model_applied: false,
            fallback_mode: "requested".to_string(),
            fallback_reason: None,
            effective_scope_roots: vec!["/tmp/repo".to_string()],
            nested_mcp_policy: "__none__".to_string(),
            usage_source: Some("stdout:json:$.usageMetadata".to_string()),
            input_tokens: Some(10),
            output_tokens: Some(4),
            total_tokens: Some(14),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
            context_window_percent_used: Some(22.5),
            context_window_percent_remaining: Some(77.5),
            context_window_source: Some("stdout:text:context_used".to_string()),
            session_compression_mode: Some("auto".to_string()),
            session_compression_attempted: true,
            session_compression_ok: Some(true),
            session_compression_skipped_reason: None,
            context_guardrail_warned: false,
            context_guardrail_threshold_percent: Some(70),
            drift_detected: 1,
            drift_repaired: 1,
            drift_failed: 0,
            invalid_table_refs: 2,
            citation_missing: 1,
        };
        ledger.record(&record);

        let raw = std::fs::read_to_string(&path).expect("usage ledger should be readable");
        let mut lines = raw.lines();
        let first = lines
            .next()
            .expect("usage ledger should contain one record");
        let parsed: serde_json::Value =
            serde_json::from_str(first).expect("usage ledger row should be valid json");
        assert_eq!(parsed["tool_name"], "ask-gemini");
        assert_eq!(parsed["invocation_id"], "gmi-test-1");
        assert_eq!(parsed["resolved_session_id"], "session-usage-test");
        assert_eq!(parsed["total_tokens"], 14);
        assert_eq!(parsed["retry_count"], 0);
        assert_eq!(parsed["nested_mcp_policy"], "__none__");
        assert_eq!(parsed["effective_scope_roots"][0], "/tmp/repo");
        assert_eq!(parsed["resume_strategy"], "fresh_if_missing");
        assert_eq!(parsed["resume_outcome"], "missing_fallback");
        assert_eq!(parsed["result_source"], "live");
        assert_eq!(parsed["degraded"], false);
        assert_eq!(parsed["context_window_percent_used"], 22.5);
        assert_eq!(parsed["context_window_percent_remaining"], 77.5);
        assert_eq!(parsed["session_compression_mode"], "auto");
        assert_eq!(parsed["session_compression_attempted"], true);
        assert_eq!(parsed["session_compression_ok"], true);
        assert_eq!(parsed["context_guardrail_warned"], false);
        assert_eq!(parsed["context_guardrail_threshold_percent"], 70);
        assert_eq!(parsed["drift_detected"], 1);
        assert_eq!(parsed["invalid_table_refs"], 2);
        assert!(lines.next().is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn response_debug_artifact_writes_jsonl_record_when_path_is_configured() {
        let path = std::env::temp_dir().join(format!(
            "gemini-response-debug-test-{}-{}.jsonl",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        let artifact = ResponseEnvelopeDebugArtifact {
            path: Some(path.clone()),
        };
        let record = ResponseEnvelopeDebugRecord {
            version: 1,
            timestamp_ms: current_unix_timestamp_ms(),
            invocation_id: Some("gmi-123".to_string()),
            tool_name: "codebase-investigator".to_string(),
            model_used: Some("gemini-3-pro-preview".to_string()),
            resume_requested: true,
            resume_selector: Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string()),
            resume_strategy: Some("inherit".to_string()),
            resume_outcome: Some("applied".to_string()),
            response_envelope: json!({
                "response": "{\"status\":\"OK\"}",
                "session_id": "debug-session",
                "stats": {"totalCalls": 1}
            }),
        };
        artifact.record(&record);

        let raw =
            std::fs::read_to_string(&path).expect("response debug artifact should be readable");
        let mut lines = raw.lines();
        let first = lines
            .next()
            .expect("response debug artifact should contain one record");
        let parsed: serde_json::Value =
            serde_json::from_str(first).expect("response debug row should be valid json");
        assert_eq!(parsed["tool_name"], "codebase-investigator");
        assert_eq!(parsed["invocation_id"], "gmi-123");
        assert_eq!(
            parsed["resume_selector"],
            "81acb59f-3c1f-4d14-91a4-98c8359e4e1b"
        );
        assert_eq!(parsed["response_envelope"]["session_id"], "debug-session");
        assert!(lines.next().is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn session_probe_snapshot_artifact_uses_usage_ledger_sibling_by_default() {
        let config = GeminiExecutionConfig {
            usage_ledger_path: Some("/tmp/gemini-cli-mcp/token-usage.jsonl".to_string()),
            ..GeminiExecutionConfig::default()
        };
        let artifact = SessionProbeSnapshotArtifact::new(&config);
        assert_eq!(
            artifact.path,
            Some(std::path::PathBuf::from(
                "/tmp/gemini-cli-mcp/session-probe.latest.json"
            ))
        );
    }

    #[test]
    fn session_probe_snapshot_artifact_reads_recent_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "gemini-session-probe-snapshot-test-{}-{}.json",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        let artifact = SessionProbeSnapshotArtifact {
            path: Some(path.clone()),
        };
        let snapshot = GeminiSessionProbeSnapshot {
            session_id: Some("session-probe-1".to_string()),
            auth_method: Some("oauth-user".to_string()),
            tier: Some("pro".to_string()),
            probe_stats: Default::default(),
        };
        let probe_execution = GeminiSessionProbeExecutionSummary {
            gemini_invocations: 1,
            model: Some("gemini-2.5-flash-lite".to_string()),
        };
        assert!(
            artifact
                .record_success(
                    &snapshot,
                    &probe_execution,
                    "noninteractive_json_probe",
                    false,
                )
                .is_none()
        );

        let hit = artifact
            .load_recent(Duration::from_secs(60))
            .expect("snapshot read should succeed")
            .expect("recent snapshot should load");
        assert_eq!(
            hit.snapshot.session.session_id.as_deref(),
            Some("session-probe-1")
        );
        assert_eq!(
            hit.snapshot.probe_execution.model.as_deref(),
            Some("gemini-2.5-flash-lite")
        );
        assert!(hit.stale_age_ms <= 60_000);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn gemini_session_stats_returns_cached_snapshot_for_transient_timeout() {
        let temp_dir = std::env::temp_dir().join(format!(
            "gemini-session-probe-fallback-test-{}-{}",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let script_path = temp_dir.join("fake-gemini-timeout.sh");
        std::fs::write(
            &script_path,
            "#!/usr/bin/env bash
sleep 5
",
        )
        .expect("write fake gemini script");
        let mut permissions = std::fs::metadata(&script_path)
            .expect("script metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod fake gemini script");

        let ledger_path = temp_dir.join("usage.jsonl");
        let snapshot_path = temp_dir.join("session-probe.latest.json");
        let mcp = super::GeminiMcp::new(GeminiExecutionConfig {
            gemini_bin: script_path.to_string_lossy().into_owned(),
            usage_ledger_path: Some(ledger_path.to_string_lossy().into_owned()),
            session_probe_snapshot_path: Some(snapshot_path.to_string_lossy().into_owned()),
            stats_timeout: Duration::from_secs(1),
            session_probe_stale_window: Duration::from_secs(60),
            ..GeminiExecutionConfig::default()
        });

        let cached_snapshot = GeminiSessionProbeSnapshot {
            session_id: Some("cached-session".to_string()),
            auth_method: Some("oauth-user".to_string()),
            tier: Some("pro".to_string()),
            probe_stats: super::GeminiSessionProbeStats {
                total_tokens: Some(12),
                input_tokens: Some(10),
                output_tokens: Some(2),
                ..Default::default()
            },
        };
        let probe_execution = GeminiSessionProbeExecutionSummary {
            gemini_invocations: 1,
            model: Some("gemini-2.5-flash-lite".to_string()),
        };
        assert!(
            mcp.session_probe_snapshot
                .record_success(
                    &cached_snapshot,
                    &probe_execution,
                    "noninteractive_json_probe",
                    false,
                )
                .is_none()
        );

        let (parts, _) = http::Request::builder()
            .body(())
            .expect("request")
            .into_parts();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                mcp.gemini_session_stats(
                    CancellationToken::new(),
                    Parameters(GeminiSessionStatsArgs {}),
                    Extension(parts),
                )
                .await
            })
            .expect("tool result");
        let payload = result.structured_content.expect("structured payload");

        assert_eq!(payload["ok"], true);
        assert_eq!(payload["source"], "cached_recent_probe");
        assert_eq!(payload["degraded"], true);
        assert_eq!(payload["live_probe_error_category"], "execution_timeout");
        assert_eq!(payload["session"]["session_id"], "cached-session");
        assert_eq!(payload["cached_probe_source"], "noninteractive_json_probe");
        assert!(payload["stale_age_ms"].as_u64().is_some());
        assert_eq!(payload["freshness_window_ms"], 60_000);
        assert_eq!(payload["live_probe_attempt"]["ok"], false);
        assert_eq!(payload["live_probe_attempt"]["gemini_invocations"], 1);

        let raw = std::fs::read_to_string(&ledger_path).expect("usage ledger should exist");
        let parsed: serde_json::Value = serde_json::from_str(
            raw.lines()
                .last()
                .expect("usage ledger should contain a record"),
        )
        .expect("usage ledger row should be json");
        assert_eq!(parsed["tool_name"], "gemini-session-stats");
        assert_eq!(parsed["result_source"], "cached_recent_probe");
        assert_eq!(parsed["degraded"], true);
        assert_eq!(parsed["error_category"], "execution_timeout");
        assert_eq!(parsed["live_error_category"], "execution_timeout");
        assert_eq!(parsed["gemini_invocations"], 1);
        assert_eq!(parsed["resolved_session_id"], "cached-session");
        assert!(
            parsed["effective_scope_roots"]
                .as_array()
                .expect("effective scope roots should be an array")
                .is_empty()
        );

        let _ = std::fs::remove_file(script_path);
        let _ = std::fs::remove_file(ledger_path);
        let _ = std::fs::remove_file(snapshot_path);
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn session_probe_snapshot_artifact_persists_private_permissions() {
        let path = std::env::temp_dir().join(format!(
            "gemini-session-probe-permissions-test-{}-{}.json",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        let artifact = SessionProbeSnapshotArtifact {
            path: Some(path.clone()),
        };
        let snapshot = GeminiSessionProbeSnapshot {
            session_id: Some("session-probe-private".to_string()),
            auth_method: Some("oauth-user".to_string()),
            tier: Some("pro".to_string()),
            probe_stats: Default::default(),
        };
        let probe_execution = GeminiSessionProbeExecutionSummary {
            gemini_invocations: 1,
            model: Some("gemini-2.5-flash-lite".to_string()),
        };

        assert!(
            artifact
                .record_success(
                    &snapshot,
                    &probe_execution,
                    "noninteractive_json_probe",
                    false,
                )
                .is_none()
        );

        let mode = std::fs::metadata(&path)
            .expect("snapshot metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cache_eligible_session_probe_failures_are_narrow() {
        let timeout = GeminiExecutionError::TimedOut { seconds: 30 };
        assert!(is_cache_eligible_session_probe_failure(
            &timeout,
            ErrorCategory::ExecutionTimeout,
        ));

        let short_reset_429 = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr:
                "You have exhausted your capacity on this model. Your quota will reset after 2s."
                    .to_string(),
        };
        assert!(is_cache_eligible_session_probe_failure(
            &short_reset_429,
            ErrorCategory::QuotaOrRateLimit,
        ));

        let generic_429 = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: "Attempt failed with status 429 (rate limit exceeded).".to_string(),
        };
        assert!(!is_cache_eligible_session_probe_failure(
            &generic_429,
            ErrorCategory::QuotaOrRateLimit,
        ));

        let capacity_429 = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"reason":"MODEL_CAPACITY_EXHAUSTED"}],"message":"No capacity available for model gemini-3-flash-preview on the server"}}"#.to_string(),
        };
        assert!(is_cache_eligible_session_probe_failure(
            &capacity_429,
            ErrorCategory::QuotaOrRateLimit,
        ));

        let terminal_quota = GeminiExecutionError::FailedExit {
            code: Some(1),
            stderr: "TerminalQuotaError: You have exhausted your capacity on this model. Your quota will reset after 8h45m15s.".to_string(),
        };
        assert!(!is_cache_eligible_session_probe_failure(
            &terminal_quota,
            ErrorCategory::QuotaOrRateLimit,
        ));

        let cancelled = GeminiExecutionError::Cancelled;
        assert!(!is_cache_eligible_session_probe_failure(
            &cancelled,
            ErrorCategory::NetworkOrTransport,
        ));
    }

    #[cfg(unix)]
    #[test]
    fn gemini_session_stats_does_not_return_snapshot_that_became_stale() {
        let temp_dir = std::env::temp_dir().join(format!(
            "gemini-session-probe-stale-during-timeout-test-{}-{}",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let script_path = temp_dir.join("fake-gemini-timeout.sh");
        std::fs::write(
            &script_path,
            "#!/usr/bin/env bash
sleep 5
",
        )
        .expect("write fake gemini script");
        let mut permissions = std::fs::metadata(&script_path)
            .expect("script metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod fake gemini script");

        let snapshot_path = temp_dir.join("session-probe.latest.json");
        let mcp = super::GeminiMcp::new(GeminiExecutionConfig {
            gemini_bin: script_path.to_string_lossy().into_owned(),
            session_probe_snapshot_path: Some(snapshot_path.to_string_lossy().into_owned()),
            stats_timeout: Duration::from_secs(2),
            session_probe_stale_window: Duration::from_secs(1),
            ..GeminiExecutionConfig::default()
        });

        let cached_snapshot = GeminiSessionProbeSnapshot {
            session_id: Some("cached-session".to_string()),
            auth_method: Some("oauth-user".to_string()),
            tier: Some("pro".to_string()),
            probe_stats: Default::default(),
        };
        let probe_execution = GeminiSessionProbeExecutionSummary {
            gemini_invocations: 1,
            model: Some("gemini-2.5-flash-lite".to_string()),
        };
        assert!(
            mcp.session_probe_snapshot
                .record_success(
                    &cached_snapshot,
                    &probe_execution,
                    "noninteractive_json_probe",
                    false,
                )
                .is_none()
        );

        let (parts, _) = http::Request::builder()
            .body(())
            .expect("request")
            .into_parts();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                mcp.gemini_session_stats(
                    CancellationToken::new(),
                    Parameters(GeminiSessionStatsArgs {}),
                    Extension(parts),
                )
                .await
            })
            .expect("tool result");
        let payload = result.structured_content.expect("structured payload");

        assert_eq!(payload["ok"], false);
        assert_eq!(payload["error_category"], "execution_timeout");
        assert!(payload["source"].is_null());

        let _ = std::fs::remove_file(script_path);
        let _ = std::fs::remove_file(snapshot_path);
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn session_probe_snapshot_artifact_reports_parse_failures() {
        let path = std::env::temp_dir().join(format!(
            "gemini-session-probe-invalid-test-{}-{}.json",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        std::fs::write(&path, b"not-json").expect("write invalid snapshot");
        let artifact = SessionProbeSnapshotArtifact {
            path: Some(path.clone()),
        };

        let warning = artifact
            .load_recent(Duration::from_secs(60))
            .expect_err("invalid snapshot should return warning");
        assert!(warning.contains("parse snapshot"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn session_probe_snapshot_artifact_rejects_stale_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "gemini-session-probe-stale-test-{}-{}.json",
            std::process::id(),
            current_unix_timestamp_ms()
        ));
        let payload = json!({
            "version": 1,
            "captured_at_ms": current_unix_timestamp_ms().saturating_sub(120_000),
            "source": "noninteractive_json_probe",
            "session": {
                "session_id": "session-probe-2",
                "auth_method": "oauth-user",
                "tier": "pro",
                "probe_stats": {}
            },
            "probe_execution": {
                "gemini_invocations": 1,
                "model": "gemini-2.5-flash-lite"
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&payload).expect("json"))
            .expect("stale snapshot write");
        let artifact = SessionProbeSnapshotArtifact {
            path: Some(path.clone()),
        };

        assert!(
            artifact
                .load_recent(Duration::from_secs(15))
                .expect("stale snapshot read should succeed")
                .is_none()
        );
        assert_eq!(
            cached_session_probe_warning(12_345, "execution_timeout"),
            "Live Gemini CLI session probe failed transiently with execution_timeout; returned the last successful cached probe snapshot from 12345ms ago."
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolve_model_uses_default_when_requested_and_allowlisted_is_omitted() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-flash-preview".to_string()),
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };

        let resolved = resolve_model(&config, None).expect("expected default resolution");

        assert_eq!(resolved.requested, None);
        assert_eq!(resolved.used, Some("gemini-3-flash-preview".to_string()));
        assert!(resolved.default_model_applied);
        assert_eq!(resolved.fallback_mode, "configured_default");
    }

    #[test]
    fn resolve_model_rejects_non_allowlisted_request() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-flash-preview".to_string()),
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };
        let error = resolve_model(&config, Some("gemini-1.5-pro".to_string()))
            .expect_err("unsupported model should fail");
        assert!(matches!(error, ErrorCategory::ModelNotAllowed));
    }

    #[test]
    fn resolve_model_falls_back_to_first_allowlisted_model_if_default_missing() {
        let config = GeminiExecutionConfig {
            default_model: None,
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };

        let resolved = resolve_model(&config, None).expect("expected fallback to allowlist model");
        assert_eq!(resolved.used, Some("gemini-3-flash-preview".to_string()));
        assert_eq!(resolved.default_model_applied, false);
        assert_eq!(resolved.fallback_mode, "allowlist_default");
        assert!(
            resolved
                .fallback_reason
                .as_ref()
                .map(|reason| reason.contains("first allowlist model"))
                .unwrap_or(false)
        );
    }

    #[test]
    fn resolve_model_falls_back_to_first_allowlisted_model_if_default_not_allowlisted() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-1.5-pro".to_string()),
            model_allowlist: vec![
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };
        let resolved = resolve_model(&config, None).expect("expected fallback resolution");
        assert_eq!(resolved.used, Some("gemini-3-flash-preview".to_string()));
        assert!(!resolved.default_model_applied);
        assert_eq!(resolved.fallback_mode, "allowlist_default");
        assert!(
            resolved
                .fallback_reason
                .as_ref()
                .map(|reason| reason.contains("not allowlisted"))
                .unwrap_or(false)
        );
    }

    #[test]
    fn resolve_model_treats_model_case_insensitively_against_allowlist() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-flash-preview".to_string()),
            model_allowlist: vec![
                "Gemini-3-FLASH-Preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };
        let resolved = resolve_model(&config, Some("gemini-3-flash-preview".to_string()))
            .expect("expected allowlisted match");
        assert_eq!(resolved.used, Some("Gemini-3-FLASH-Preview".to_string()));
    }

    #[test]
    fn resolve_model_maps_preview_alias_to_allowlisted_variant() {
        let config = GeminiExecutionConfig {
            default_model: Some("gemini-3-flash-preview".to_string()),
            model_allowlist: vec![
                "gemini-2.5-flash-lite".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            ..GeminiExecutionConfig::default()
        };
        let resolved = resolve_model(&config, Some("gemini-2.5-flash-preview".to_string()))
            .expect("expected alias resolution");
        assert_eq!(resolved.used, Some("gemini-2.5-flash-lite".to_string()));
        assert_eq!(resolved.fallback_mode, "requested_alias");
        assert!(
            resolved
                .fallback_reason
                .as_deref()
                .map(|reason| reason.contains("mapped to allowlisted alias"))
                .unwrap_or(false)
        );
    }

    #[test]
    fn next_allowlisted_downgrade_model_picks_next_allowlisted_entry() {
        let allowlist = vec![
            "gemini-3-pro-preview".to_string(),
            "gemini-3-flash-preview".to_string(),
            "gemini-2.5-flash-lite".to_string(),
        ];
        let fallback = next_allowlisted_downgrade_model(&allowlist, "gemini-3-pro-preview");
        assert_eq!(fallback.as_deref(), Some("gemini-3-flash-preview"));
    }

    #[test]
    fn next_allowlisted_downgrade_model_returns_none_at_end_of_allowlist() {
        let allowlist = vec![
            "gemini-3-pro-preview".to_string(),
            "gemini-3-flash-preview".to_string(),
        ];
        let fallback = next_allowlisted_downgrade_model(&allowlist, "gemini-3-flash-preview");
        assert_eq!(fallback, None);
    }

    #[test]
    fn model_not_allowed_issue_is_actionable() {
        let issue = model_not_allowed_issue(
            &[
                "gemini-2.5-flash-lite".to_string(),
                "gemini-3-pro-preview".to_string(),
            ],
            Some("gemini-2.5-flash-preview"),
        );

        assert_eq!(issue.code, "model_not_allowed");
        assert_eq!(issue.field, "model");
        assert!(issue.corrective_hint.contains("gemini-2.5-flash-lite"));
        assert!(issue.corrective_hint.contains("gemini-3-pro-preview"));
        assert!(
            issue
                .corrective_hint
                .contains("Closest allowlisted alias match")
        );
    }

    #[test]
    fn normalize_and_validate_model_and_prompt_fields() {
        let mut issues = Vec::new();
        assert_eq!(
            validate_required_text_field("prompt", "  ", &mut issues),
            None
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "prompt");
        assert_eq!(issues[0].code, "invalid_value");
        assert_eq!(issues[0].expected_type, "non-empty string");
        assert_eq!(issues[0].received_type, "string");

        issues.clear();
        assert_eq!(
            normalize_optional_model_field(
                "model",
                Some("  gemini-3-flash-preview  ".to_string()),
                &mut issues
            ),
            Some("gemini-3-flash-preview".to_string())
        );
        assert!(issues.is_empty());

        assert_eq!(
            normalize_optional_resume_selector(
                Some(" 81acb59f-3c1f-4d14-91a4-98c8359e4e1b ".to_string()),
                &mut issues
            ),
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string())
        );
        assert!(issues.is_empty());

        assert_eq!(
            normalize_optional_resume_selector(
                Some("session-81acb59f-3c1f-4d14-91a4-98c8359e4e1b ".to_string()),
                &mut issues
            ),
            Some("81acb59f-3c1f-4d14-91a4-98c8359e4e1b".to_string())
        );
        assert!(issues.is_empty());

        assert_eq!(
            normalize_optional_resume_selector(Some(" latest ".to_string()), &mut issues),
            None
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "resume");
        assert_eq!(issues[0].expected_type, "explicit Gemini session selector");
        issues.clear();

        assert_eq!(
            normalize_optional_resume_selector(Some("   ".to_string()), &mut issues),
            None
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "resume");
        issues.clear();

        assert_eq!(
            normalize_allowed_mcp_servers_override(Some("postgres, ops".to_string()), &mut issues),
            Some(AllowedMcpServers::Names(vec![
                "postgres".to_string(),
                "ops".to_string()
            ]))
        );
        assert!(issues.is_empty());

        assert_eq!(
            normalize_allowed_mcp_servers_override(Some("__none__".to_string()), &mut issues),
            Some(AllowedMcpServers::None)
        );
        assert!(issues.is_empty());

        assert_eq!(
            normalize_allowed_mcp_servers_override(Some(" , ".to_string()), &mut issues),
            None
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "allowed_mcp_server_names");
        issues.clear();

        assert_eq!(
            default_to_no_nested_mcp_servers(None),
            Some(AllowedMcpServers::None)
        );
        assert_eq!(
            default_to_no_nested_mcp_servers(Some(AllowedMcpServers::Names(vec![
                "postgres".to_string()
            ]))),
            Some(AllowedMcpServers::Names(vec!["postgres".to_string()]))
        );

        assert_eq!(allowed_models_hint(&[]), "<no allowlist configured>");
        assert_eq!(
            normalize_model_list(&["a".to_string(), "  ".to_string(), "b".to_string()]),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn config_has_model_allowlist_joined_output() {
        assert_eq!(
            allowed_models_hint(&[
                "gemini-3-flash-preview".to_string(),
                "gemini-3-pro-preview".to_string(),
            ]),
            "gemini-3-flash-preview, gemini-3-pro-preview"
        );
    }

    #[test]
    fn target_validation_requires_path_within_include_directories() {
        let temp_root =
            std::env::temp_dir().join(format!("gemini-target-scope-{}", std::process::id()));
        let allowed_root = temp_root.join("allowed");
        let nested = allowed_root.join("nested");
        let nested_alias = allowed_root.join("nested/../nested");
        let outside_root = temp_root.join("outside");
        std::fs::create_dir_all(&nested).expect("create nested path");
        std::fs::create_dir_all(&outside_root).expect("create outside path");

        let mut errors = Vec::new();
        let allowed = validate_target_within_include_directories(
            &nested_alias.display().to_string(),
            &[allowed_root.display().to_string()],
            &mut errors,
        );
        assert!(allowed.is_some(), "expected nested path to be accepted");
        assert!(errors.is_empty(), "unexpected errors for allowed target");
        assert_eq!(allowed.as_deref(), Some(nested.to_string_lossy().as_ref()));

        errors.clear();
        let blocked = validate_target_within_include_directories(
            &outside_root.display().to_string(),
            &[allowed_root.display().to_string()],
            &mut errors,
        );
        assert!(blocked.is_none(), "expected outside path to be rejected");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "out_of_scope");

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn scoped_ask_gemini_target_defaults_to_inferred_cwd_when_missing() {
        let temp_root =
            std::env::temp_dir().join(format!("gemini-ask-scope-target-{}", std::process::id()));
        let allowed_root = temp_root.join("allowed");
        let cwd = allowed_root.join("repo");
        std::fs::create_dir_all(&cwd).expect("create inferred cwd");

        let mut errors = Vec::new();
        let resolved = resolve_scoped_ask_gemini_target(
            None,
            Ok(cwd.clone()),
            &[allowed_root.display().to_string()],
            &mut errors,
        );

        assert!(errors.is_empty(), "unexpected validation errors");
        assert_eq!(resolved.as_deref(), Some(cwd.to_string_lossy().as_ref()));

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn scoped_ask_gemini_target_reports_cwd_unavailable_when_missing() {
        let mut errors = Vec::new();
        let resolved = resolve_scoped_ask_gemini_target(
            None,
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cwd unavailable",
            )),
            &["/tmp".to_string()],
            &mut errors,
        );

        assert!(resolved.is_none(), "expected resolution failure");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "cwd_unavailable");
    }

    #[test]
    fn classify_stderr_prioritizes_quota_over_auth_terms() {
        let stderr = "Attempt failed with status 429; session token unchanged; RESOURCE_EXHAUSTED";
        let category = classify_stderr_error(stderr);
        assert!(matches!(category, ErrorCategory::QuotaOrRateLimit));
    }

    #[test]
    fn classify_stderr_prioritizes_quota_over_model_not_found_terms() {
        let stderr = "Model not found for this tenant. Attempt failed with status 429 and RESOURCE_EXHAUSTED.";
        let category = classify_stderr_error(stderr);
        assert!(matches!(category, ErrorCategory::QuotaOrRateLimit));
    }

    #[test]
    fn classify_stderr_detects_tool_registry_mismatch() {
        let stderr =
            "Error executing tool run_shell_command: Tool \"run_shell_command\" not found.";
        let category = classify_stderr_error(stderr);
        assert!(matches!(category, ErrorCategory::ToolRegistryMismatch));
        assert_eq!(category.retryability(), "after_fix");
        assert_eq!(category.salvageability(), "none");
    }

    #[test]
    fn classify_stderr_detects_tool_runtime_abort() {
        let stderr = "Error executing tool codebase_investigator: Subagent Failed: codebase_investigator\nError: The operation was aborted.\n";
        let category = classify_stderr_error(stderr);
        assert!(matches!(category, ErrorCategory::ToolRuntime));
    }

    #[test]
    fn blocking_codebase_fallback_category_skips_schema_retry_for_runtime_failures() {
        let stderr = "RangeError: Maximum call stack size exceeded";
        let category = blocking_codebase_fallback_category(stderr);
        assert!(matches!(category, Some(ErrorCategory::ToolRuntime)));
    }

    #[test]
    fn blocking_codebase_fallback_category_allows_schema_retry_when_stderr_is_empty() {
        assert_eq!(blocking_codebase_fallback_category(""), None);
        assert_eq!(blocking_codebase_fallback_category("   "), None);
    }

    #[test]
    fn reliability_metadata_from_error_label_maps_retry_and_salvage() {
        let (failure_class, retryability, salvageability) =
            reliability_metadata_from_error_label(Some("quota_or_rate_limit"));
        assert_eq!(failure_class.as_deref(), Some("quota_or_rate_limit"));
        assert_eq!(retryability.as_deref(), Some("after_backoff"));
        assert_eq!(salvageability.as_deref(), Some("model_downgrade"));

        let (_, retryability, salvageability) =
            reliability_metadata_from_error_label(Some("response_contract"));
        assert_eq!(retryability.as_deref(), Some("after_fix"));
        assert_eq!(salvageability.as_deref(), Some("schema_retry"));
    }

    #[test]
    fn from_raw_config_uses_normalized_policy_path() {
        let raw = crate::config::GeminiExecutionRawConfig::default();
        let server = super::GeminiMcp::from_raw_config(raw).expect("raw config conversion");
        let names = server.tool_names();
        assert!(names.iter().any(|name| name == "ask-gemini"));
        assert!(names.iter().any(|name| name == "gemini-session-stats"));
        assert!(
            names
                .iter()
                .any(|name| name == "mobile-provider-evidence-pack")
        );
    }
}

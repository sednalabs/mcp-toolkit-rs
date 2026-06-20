use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mcp_toolkit_gemini::executor::{
    GeminiExecutionPhase, GeminiHeartbeatSnapshot, GeminiOutputObserver, GeminiPromptTransport,
    execute_gemini_with_cancel_observed,
};
use mcp_toolkit_gemini::observe::GeminiOutputStream;
use mcp_toolkit_gemini::{
    AllowedMcpServers, AskGeminiPolicy, GeminiExecutionConfig, GeminiRequest, execute_gemini,
};
use tokio_util::sync::CancellationToken;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(1);

fn make_test_dir() -> PathBuf {
    let dir = PathBuf::from("target")
        .join("mcp-toolkit-gemini-tests")
        .join(format!(
            "{}-{}",
            std::process::id(),
            TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&dir).expect("create test temp directory");
    dir
}

#[cfg(unix)]
fn make_fake_gemini_script(_prefix: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = make_test_dir();

    let script_path = dir.join("fake-gemini.sh");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@"
"#;
    fs::write(&script_path, script).expect("write fake gemini script");

    let mut perms = fs::metadata(&script_path)
        .expect("stat fake gemini script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("chmod fake gemini script");

    script_path
}

fn cleanup_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(parent);
    }
}

#[derive(Default)]
struct CountingObserver {
    chunk_events: AtomicU64,
    retry_events: AtomicU64,
    phase_events: AtomicU64,
    heartbeat_events: AtomicU64,
}

impl GeminiOutputObserver for CountingObserver {
    fn on_chunk(&self, _stream: GeminiOutputStream, _chunk_text: &str) {
        self.chunk_events.fetch_add(1, Ordering::Relaxed);
    }

    fn on_retry_scheduled(&self, _next_attempt: u32, _reason: &str, _delay: Duration) {
        self.retry_events.fetch_add(1, Ordering::Relaxed);
    }

    fn on_phase(&self, _attempt: u32, _phase: GeminiExecutionPhase, _pid: Option<u32>) {
        self.phase_events.fetch_add(1, Ordering::Relaxed);
    }

    fn on_heartbeat(&self, _snapshot: GeminiHeartbeatSnapshot) {
        self.heartbeat_events.fetch_add(1, Ordering::Relaxed);
    }
}

struct SaturatingHeartbeatObserver {
    sender: mpsc::SyncSender<GeminiHeartbeatSnapshot>,
    dropped_heartbeats: AtomicU64,
}

impl GeminiOutputObserver for SaturatingHeartbeatObserver {
    fn on_chunk(&self, _stream: GeminiOutputStream, _chunk_text: &str) {}

    fn on_heartbeat(&self, snapshot: GeminiHeartbeatSnapshot) {
        if self.sender.try_send(snapshot).is_err() {
            self.dropped_heartbeats.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct LastHeartbeatObserver {
    heartbeat_events: AtomicU64,
    last_snapshot: Mutex<Option<GeminiHeartbeatSnapshot>>,
}

impl GeminiOutputObserver for LastHeartbeatObserver {
    fn on_chunk(&self, _stream: GeminiOutputStream, _chunk_text: &str) {}

    fn on_heartbeat(&self, snapshot: GeminiHeartbeatSnapshot) {
        self.heartbeat_events.fetch_add(1, Ordering::Relaxed);
        let mut guard = self
            .last_snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = Some(snapshot);
    }
}

#[cfg(unix)]
fn make_fake_gemini_script_with_stdin_fallback(_prefix: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = make_test_dir();

    let script_path = dir.join("fake-gemini.sh");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

for arg in "$@"; do
    if [[ "$arg" == "--" ]]; then
        echo "No input provided via stdin. Input can be provided by piping data into gemini or using the --prompt option." >&2
        exit 42
    fi
done

payload=$(cat)
if [[ -z "$payload" ]]; then
    echo "No input provided via stdin. Input can be provided by piping data into gemini or using the --prompt option." >&2
    exit 42
fi

printf '{\"ok\": true}\n'
"#;
    fs::write(&script_path, script).expect("write fake gemini fallback script");

    let mut perms = fs::metadata(&script_path)
        .expect("stat fake gemini fallback script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("chmod fake gemini fallback script");

    script_path
}

#[cfg(unix)]
fn make_fake_gemini_script_printing_sandbox_env(_prefix: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = make_test_dir();

    let script_path = dir.join("fake-gemini.sh");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

printf 'sandbox=%s\n' "${GEMINI_SANDBOX-<unset>}"
printf '%s\n' "$@"
"#;
    fs::write(&script_path, script).expect("write fake gemini env script");

    let mut perms = fs::metadata(&script_path)
        .expect("stat fake gemini env script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("chmod fake gemini env script");

    script_path
}

#[cfg(unix)]
fn make_fake_gemini_script_missing_sandbox_runtime(_prefix: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = make_test_dir();

    let script_path = dir.join("fake-gemini.sh");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

for arg in "$@"; do
    if [[ "$arg" == "-s" ]]; then
        echo "failed to start sandbox runtime: us-docker.pkg.dev/gemini-code-dev/gemini-cli/sandbox:0.31.0 not found" >&2
        exit 1
    fi
done

printf 'sandbox=%s\n' "${GEMINI_SANDBOX-<unset>}"
printf '%s\n' "$@"
"#;
    fs::write(&script_path, script).expect("write fake gemini missing sandbox script");

    let mut perms = fs::metadata(&script_path)
        .expect("stat fake gemini missing sandbox script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("chmod fake gemini missing sandbox script");

    script_path
}

#[cfg(unix)]
fn make_fake_gemini_script_printing_pwd(_prefix: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = make_test_dir();

    let script_path = dir.join("fake-gemini.sh");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

printf 'cwd=%s\n' "$(pwd)"
"#;
    fs::write(&script_path, script).expect("write fake gemini pwd script");

    let mut perms = fs::metadata(&script_path)
        .expect("stat fake gemini pwd script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("chmod fake gemini pwd script");

    script_path
}

#[cfg(unix)]
fn make_fake_gemini_script_retrying_429(_prefix: &str, failures_before_success: usize) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = make_test_dir();

    let script_path = dir.join("fake-gemini.sh");
    let counter_path = dir.join("retry-count.txt");
    let script = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

counter_file="{counter_file}"
count=0
if [[ -f "$counter_file" ]]; then
  count=$(cat "$counter_file")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$counter_file"

if (( count <= {failures_before_success} )); then
  echo "Attempt $count failed with status 429 (RESOURCE_EXHAUSTED / MODEL_CAPACITY_EXHAUSTED)" >&2
  exit 1
fi

printf 'ok-after-429-retry\n'
"#,
        counter_file = counter_path.display(),
        failures_before_success = failures_before_success
    );
    fs::write(&script_path, script).expect("write fake gemini retry script");

    let mut perms = fs::metadata(&script_path)
        .expect("stat fake gemini retry script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("chmod fake gemini retry script");

    script_path
}

#[cfg(unix)]
fn make_fake_gemini_script_with_delay(_prefix: &str, delay_ms: u64) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = make_test_dir();

    let script_path = dir.join("fake-gemini.sh");
    let delay_seconds = (delay_ms as f64) / 1000.0;
    let script = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
sleep {delay_seconds}
printf 'ok-after-delay\n'
"#,
        delay_seconds = delay_seconds
    );
    fs::write(&script_path, script).expect("write fake gemini delay script");

    let mut perms = fs::metadata(&script_path)
        .expect("stat fake gemini delay script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("chmod fake gemini delay script");

    script_path
}

#[tokio::test]
#[cfg(unix)]
async fn default_policy_passes_explicit_none_allowlist() {
    let script_path = make_fake_gemini_script("none");
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini");
    cleanup_parent(&script_path);

    let args = output.stdout.lines().collect::<Vec<_>>();
    assert!(
        args.windows(2)
            .any(|w| { w[0] == "--allowed-mcp-server-names" && w[1] == "__none__" })
    );
    assert!(args.contains(&"--"));
    assert!(args.contains(&"hello"));
}

#[tokio::test]
#[cfg(unix)]
async fn named_allowlist_is_forwarded_and_none_not_used() {
    let script_path = make_fake_gemini_script("named");
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::Names(vec![
            "ops".to_string(),
            "codebase_search_mcp".to_string(),
        ]),
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini");
    cleanup_parent(&script_path);

    let args = output.stdout.lines().collect::<Vec<_>>();
    assert!(
        args.windows(2)
            .any(|w| { w[0] == "--allowed-mcp-server-names" && w[1] == "ops" })
    );
    assert!(
        args.windows(2)
            .any(|w| { w[0] == "--allowed-mcp-server-names" && w[1] == "codebase_search_mcp" })
    );
    assert!(!args.contains(&"__none__"));
}

#[tokio::test]
#[cfg(unix)]
async fn codebase_tool_falls_back_to_stdin_when_arg_prompt_is_rejected_by_gemini() {
    let script_path = make_fake_gemini_script_with_stdin_fallback("stdin-fallback");
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello world".to_string(),
        model: None,
        sandbox: false,
        prompt_transport: GeminiPromptTransport::ArgPrompt,
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini via stdin fallback");
    cleanup_parent(&script_path);

    let parsed: serde_json::Value =
        serde_json::from_str(&output.stdout).expect("fake gemini output should be valid JSON");
    assert_eq!(parsed["ok"], true);
}

#[tokio::test]
#[cfg(unix)]
async fn sandbox_false_forces_child_gemini_sandbox_off() {
    let script_path = make_fake_gemini_script_printing_sandbox_env("sandbox-off");
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini with sandbox disabled");
    cleanup_parent(&script_path);

    let lines = output.stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.first().copied(), Some("sandbox=false"));
    assert!(!lines.contains(&"-s"));
}

#[tokio::test]
#[cfg(unix)]
async fn sandbox_true_passes_sandbox_flag() {
    let script_path = make_fake_gemini_script_printing_sandbox_env("sandbox-on");
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: true,
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini with sandbox enabled");
    cleanup_parent(&script_path);

    let lines = output.stdout.lines().collect::<Vec<_>>();
    assert!(lines.contains(&"-s"));
}

#[tokio::test]
#[cfg(unix)]
async fn sandbox_missing_runtime_falls_back_to_host_when_enabled() {
    let script_path = make_fake_gemini_script_missing_sandbox_runtime("sandbox-fallback-enabled");
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: true,
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini with sandbox fallback");
    cleanup_parent(&script_path);

    let lines = output.stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.first().copied(), Some("sandbox=false"));
    assert!(!lines.contains(&"-s"));
}

#[tokio::test]
#[cfg(unix)]
async fn sandbox_missing_runtime_returns_error_when_fallback_disabled() {
    let script_path = make_fake_gemini_script_missing_sandbox_runtime("sandbox-fallback-disabled");
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: false,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: true,
        ..Default::default()
    };

    let error = execute_gemini(&config, &request)
        .await
        .expect_err("sandbox runtime failure should bubble when fallback is disabled");
    cleanup_parent(&script_path);
    assert!(
        error
            .to_string()
            .contains("gemini-cli/sandbox:0.31.0 not found"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn working_directory_is_applied_to_gemini_subprocess() {
    let script_path = make_fake_gemini_script_printing_pwd("working-dir");
    let script_parent = script_path
        .parent()
        .expect("script should have parent directory");
    let working_dir = script_parent.join("target-dir");
    fs::create_dir_all(&working_dir).expect("create target-dir");
    let working_dir_alias = working_dir.join(".");

    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
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
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        working_directory: Some(working_dir_alias.display().to_string()),
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini with working directory");
    cleanup_parent(&script_path);

    let lines = output.stdout.lines().collect::<Vec<_>>();
    let expected = format!("cwd={}", working_dir.display());
    assert_eq!(lines.first().copied(), Some(expected.as_str()));
}

#[tokio::test]
#[cfg(unix)]
async fn retries_429_until_success_within_retry_window() {
    let script_path = make_fake_gemini_script_retrying_429("retry-429-success", 2);
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
        include_directories: Vec::new(),
        retry_429_enabled: true,
        retry_429_window: Duration::from_secs(15),
        retry_429_max_retries: 2,
        retry_429_interval: Duration::from_millis(20),
        retry_429_random_interval_range: None,
        inspect_heartbeat_enabled: false,
        inspect_heartbeat_interval: Duration::from_secs(15),
        inspect_stall_threshold: Duration::from_secs(60),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        enable_resume: true,
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };

    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini with retry");
    cleanup_parent(&script_path);
    assert_eq!(output.stdout.trim(), "ok-after-429-retry");
    assert_eq!(output.retry_count, 2);
}

#[tokio::test]
#[cfg(unix)]
async fn stops_retrying_429_after_retry_window_expires() {
    let script_path = make_fake_gemini_script_retrying_429("retry-429-expire", 1000);
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
        include_directories: Vec::new(),
        retry_429_enabled: true,
        retry_429_window: Duration::from_millis(120),
        retry_429_max_retries: 100,
        retry_429_interval: Duration::from_millis(40),
        retry_429_random_interval_range: None,
        inspect_heartbeat_enabled: false,
        inspect_heartbeat_interval: Duration::from_secs(15),
        inspect_stall_threshold: Duration::from_secs(60),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        enable_resume: true,
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };

    let err = execute_gemini(&config, &request)
        .await
        .expect_err("retry window should eventually return the 429 error");
    cleanup_parent(&script_path);

    match err {
        mcp_toolkit_gemini::GeminiExecutionError::FailedExit { stderr, .. } => {
            let lower = stderr.to_lowercase();
            assert!(lower.contains("429"));
        }
        other => panic!("expected FailedExit, got {other:?}"),
    }
}

#[tokio::test]
#[cfg(unix)]
async fn random_retry_interval_overrides_fixed_interval_for_429_retries() {
    let script_path = make_fake_gemini_script_retrying_429("retry429-random", 1);
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
        include_directories: Vec::new(),
        retry_429_enabled: true,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 3,
        retry_429_interval: Duration::from_secs(2),
        retry_429_random_interval_range: Some((
            Duration::from_millis(25),
            Duration::from_millis(25),
        )),
        inspect_heartbeat_enabled: false,
        inspect_heartbeat_interval: Duration::from_secs(15),
        inspect_stall_threshold: Duration::from_secs(60),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        enable_resume: true,
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };

    let started = Instant::now();
    let output = execute_gemini(&config, &request)
        .await
        .expect("execute fake gemini with random retry interval");
    let elapsed = started.elapsed();
    cleanup_parent(&script_path);

    assert_eq!(output.stdout.trim(), "ok-after-429-retry");
    assert_eq!(output.retry_count, 1);
    assert!(
        elapsed < Duration::from_millis(1500),
        "expected randomized retry delay to avoid fixed 2s sleep, elapsed={elapsed:?}"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn heartbeat_toggle_preserves_output_and_retry_behavior() {
    let script_path_without = make_fake_gemini_script_retrying_429("heartbeat-parity-retry-off", 2);
    let script_path_with = make_fake_gemini_script_retrying_429("heartbeat-parity-retry-on", 2);
    let base_config = GeminiExecutionConfig {
        gemini_bin: script_path_without.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
        include_directories: Vec::new(),
        retry_429_enabled: true,
        retry_429_window: Duration::from_secs(15),
        retry_429_max_retries: 4,
        retry_429_interval: Duration::from_millis(15),
        retry_429_random_interval_range: None,
        inspect_heartbeat_enabled: false,
        inspect_heartbeat_interval: Duration::from_millis(20),
        inspect_stall_threshold: Duration::from_secs(60),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        enable_resume: true,
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };

    let observer_without = Arc::new(CountingObserver::default());
    let output_without = execute_gemini_with_cancel_observed(
        &base_config,
        &request,
        CancellationToken::new(),
        Some(observer_without.clone()),
    )
    .await
    .expect("execute with heartbeat disabled");

    let mut heartbeat_config = base_config.clone();
    heartbeat_config.gemini_bin = script_path_with.to_string_lossy().to_string();
    heartbeat_config.inspect_heartbeat_enabled = true;
    let observer_with = Arc::new(CountingObserver::default());
    let output_with = execute_gemini_with_cancel_observed(
        &heartbeat_config,
        &request,
        CancellationToken::new(),
        Some(observer_with.clone()),
    )
    .await
    .expect("execute with heartbeat enabled");

    cleanup_parent(&script_path_without);
    cleanup_parent(&script_path_with);
    assert_eq!(output_without.stdout, output_with.stdout);
    assert_eq!(output_without.stderr, output_with.stderr);
    assert_eq!(output_without.retry_count, output_with.retry_count);
    assert_eq!(output_with.retry_count, 2);
    assert_eq!(observer_without.heartbeat_events.load(Ordering::Relaxed), 0);
}

#[tokio::test]
#[cfg(unix)]
async fn heartbeat_observer_backpressure_does_not_block_execution() {
    let script_path = make_fake_gemini_script_with_delay("heartbeat-backpressure", 220);
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
        include_directories: Vec::new(),
        retry_429_enabled: false,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 0,
        retry_429_interval: Duration::from_secs(5),
        retry_429_random_interval_range: None,
        inspect_heartbeat_enabled: true,
        inspect_heartbeat_interval: Duration::from_millis(10),
        inspect_stall_threshold: Duration::from_secs(60),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        enable_resume: true,
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };
    let (sender, _receiver) = mpsc::sync_channel(1);
    let observer = Arc::new(SaturatingHeartbeatObserver {
        sender,
        dropped_heartbeats: AtomicU64::new(0),
    });

    let started = Instant::now();
    let output = execute_gemini_with_cancel_observed(
        &config,
        &request,
        CancellationToken::new(),
        Some(observer.clone()),
    )
    .await
    .expect("execute should finish despite heartbeat sink backpressure");
    let elapsed = started.elapsed();
    cleanup_parent(&script_path);

    assert_eq!(output.stdout.trim(), "ok-after-delay");
    assert!(
        elapsed < Duration::from_millis(2000),
        "heartbeat backpressure must not block execution, elapsed={elapsed:?}"
    );
    assert!(
        observer.dropped_heartbeats.load(Ordering::Relaxed) > 0,
        "expected bounded heartbeat sink to drop some snapshots"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn final_heartbeat_reflects_terminal_stream_bytes() {
    let script_path = make_fake_gemini_script_with_delay("heartbeat-final-snapshot", 25);
    let config = GeminiExecutionConfig {
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        home_dir: None,
        include_directories: Vec::new(),
        retry_429_enabled: false,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 0,
        retry_429_interval: Duration::from_secs(5),
        retry_429_random_interval_range: None,
        inspect_heartbeat_enabled: true,
        inspect_heartbeat_interval: Duration::from_secs(60),
        inspect_stall_threshold: Duration::from_secs(60),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        enable_resume: true,
        resume_compression_default: mcp_toolkit_gemini::config::ResumeCompressionDefault::Auto,
        resume_context_warn_percent: 70,
        usage_ledger_path: None,
        response_debug_path: None,
        session_probe_snapshot_path: None,
        sandbox_fallback_enabled: true,
        timeout: Duration::from_secs(5),
        stats_timeout: Duration::from_secs(5),
        session_probe_stale_window: Duration::from_secs(900),
        ..GeminiExecutionConfig::default()
    };
    let request = GeminiRequest {
        prompt: "hello".to_string(),
        model: None,
        sandbox: false,
        ..Default::default()
    };
    let observer = Arc::new(LastHeartbeatObserver::default());

    let output = execute_gemini_with_cancel_observed(
        &config,
        &request,
        CancellationToken::new(),
        Some(observer.clone()),
    )
    .await
    .expect("execute with heartbeat enabled");
    cleanup_parent(&script_path);

    assert_eq!(output.stdout.trim(), "ok-after-delay");
    assert!(
        observer.heartbeat_events.load(Ordering::Relaxed) >= 1,
        "expected at least one heartbeat event"
    );
    let snapshot = observer
        .last_snapshot
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .expect("expected final heartbeat snapshot");
    assert!(
        snapshot.stdout_bytes >= b"ok-after-delay\n".len() as u64,
        "expected terminal heartbeat stdout_bytes to include full output, got {}",
        snapshot.stdout_bytes
    );
}

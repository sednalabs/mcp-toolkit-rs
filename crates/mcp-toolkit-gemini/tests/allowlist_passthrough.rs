use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mcp_toolkit_gemini::executor::GeminiPromptTransport;
use mcp_toolkit_gemini::{
    execute_gemini, AllowedMcpServers, AskGeminiPolicy, GeminiExecutionConfig, GeminiRequest,
};

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

enum FakeGeminiMode {
    EchoArgs,
    StdinFallback,
    SandboxEnv,
    Retry429 { failures_before_success: usize },
}

impl FakeGeminiMode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::EchoArgs => "echo_args",
            Self::StdinFallback => "stdin_fallback",
            Self::SandboxEnv => "sandbox_env",
            Self::Retry429 { .. } => "retry_429",
        }
    }
}

#[cfg(unix)]
fn unique_test_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let ordinal = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "mcp-toolkit-gemini-tests-{}-{}-{}-{}",
        std::process::id(),
        prefix,
        nonce,
        ordinal
    ))
}

#[cfg(unix)]
fn make_fake_gemini_script(prefix: &str, mode: FakeGeminiMode) -> PathBuf {
    use std::os::unix::fs::symlink;

    let dir = unique_test_dir(prefix);
    fs::create_dir_all(&dir).expect("create test temp directory");
    fs::write(dir.join("mode"), mode.as_str()).expect("write fake gemini mode");
    if let FakeGeminiMode::Retry429 {
        failures_before_success,
    } = mode
    {
        fs::write(
            dir.join("failures-before-success"),
            failures_before_success.to_string(),
        )
        .expect("write fake gemini retry failure count");
    }

    let driver_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-gemini-driver.sh");
    let script_path = dir.join("fake-gemini.sh");
    symlink(&driver_path, &script_path).expect("link fake gemini driver");
    script_path
}

#[cfg(unix)]
fn make_fake_gemini_echo_script(prefix: &str) -> PathBuf {
    make_fake_gemini_script(prefix, FakeGeminiMode::EchoArgs)
}

fn cleanup_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(parent);
    }
}

#[cfg(unix)]
fn make_fake_gemini_script_with_stdin_fallback(prefix: &str) -> PathBuf {
    make_fake_gemini_script(prefix, FakeGeminiMode::StdinFallback)
}

#[cfg(unix)]
fn make_fake_gemini_script_printing_sandbox_env(prefix: &str) -> PathBuf {
    make_fake_gemini_script(prefix, FakeGeminiMode::SandboxEnv)
}

#[cfg(unix)]
fn make_fake_gemini_script_retrying_429(prefix: &str, failures_before_success: usize) -> PathBuf {
    make_fake_gemini_script(
        prefix,
        FakeGeminiMode::Retry429 {
            failures_before_success,
        },
    )
}

#[tokio::test]
#[cfg(unix)]
async fn default_policy_passes_explicit_none_allowlist() {
    let script_path = make_fake_gemini_echo_script("none");
    let config = GeminiExecutionConfig {
        api_key: "test-api-key".to_string(),
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        include_directories: Vec::new(),
        retry_429_enabled: false,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 2,
        retry_429_interval: Duration::from_secs(5),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        timeout: Duration::from_secs(5),
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
    assert!(args
        .windows(2)
        .any(|w| { w[0] == "--allowed-mcp-server-names" && w[1] == "__none__" }));
    assert!(args.contains(&"--"));
    assert!(args.contains(&"hello"));
}

#[tokio::test]
#[cfg(unix)]
async fn named_allowlist_is_forwarded_and_none_not_used() {
    let script_path = make_fake_gemini_echo_script("named");
    let config = GeminiExecutionConfig {
        api_key: "test-api-key".to_string(),
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::Names(vec![
            "ops".to_string(),
            "codebase_search_mcp".to_string(),
        ]),
        include_directories: Vec::new(),
        retry_429_enabled: false,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 2,
        retry_429_interval: Duration::from_secs(5),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        timeout: Duration::from_secs(5),
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
    assert!(args
        .windows(2)
        .any(|w| { w[0] == "--allowed-mcp-server-names" && w[1] == "ops" }));
    assert!(args
        .windows(2)
        .any(|w| { w[0] == "--allowed-mcp-server-names" && w[1] == "codebase_search_mcp" }));
    assert!(!args.contains(&"__none__"));
}

#[tokio::test]
#[cfg(unix)]
async fn codebase_tool_falls_back_to_stdin_when_arg_prompt_is_rejected_by_gemini() {
    let script_path = make_fake_gemini_script_with_stdin_fallback("stdin-fallback");
    let config = GeminiExecutionConfig {
        api_key: "test-api-key".to_string(),
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        include_directories: Vec::new(),
        retry_429_enabled: false,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 2,
        retry_429_interval: Duration::from_secs(5),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        timeout: Duration::from_secs(5),
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
        api_key: "test-api-key".to_string(),
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        include_directories: Vec::new(),
        retry_429_enabled: false,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 2,
        retry_429_interval: Duration::from_secs(5),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        timeout: Duration::from_secs(5),
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
        api_key: "test-api-key".to_string(),
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        include_directories: Vec::new(),
        retry_429_enabled: false,
        retry_429_window: Duration::ZERO,
        retry_429_max_retries: 2,
        retry_429_interval: Duration::from_secs(5),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        timeout: Duration::from_secs(5),
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
async fn retries_429_until_success_within_retry_window() {
    let script_path = make_fake_gemini_script_retrying_429("retry-429-success", 2);
    let config = GeminiExecutionConfig {
        api_key: "test-api-key".to_string(),
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        include_directories: Vec::new(),
        retry_429_enabled: true,
        retry_429_window: Duration::from_secs(15),
        retry_429_max_retries: 2,
        retry_429_interval: Duration::from_millis(20),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        timeout: Duration::from_secs(5),
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
}

#[tokio::test]
#[cfg(unix)]
async fn stops_retrying_429_after_retry_window_expires() {
    let script_path = make_fake_gemini_script_retrying_429("retry-429-expire", 1000);
    let config = GeminiExecutionConfig {
        api_key: "test-api-key".to_string(),
        gemini_bin: script_path.to_string_lossy().to_string(),
        default_model: None,
        model_allowlist: Vec::new(),
        allowed_mcp_servers: AllowedMcpServers::None,
        include_directories: Vec::new(),
        retry_429_enabled: true,
        retry_429_window: Duration::from_millis(120),
        retry_429_max_retries: 100,
        retry_429_interval: Duration::from_millis(40),
        ask_gemini_policy: AskGeminiPolicy::Freeform,
        ask_gemini_allowed_roots: Vec::new(),
        timeout: Duration::from_secs(5),
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

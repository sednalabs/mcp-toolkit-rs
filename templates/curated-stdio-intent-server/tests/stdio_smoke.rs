use mcp_toolkit_testing::stdio_contract::{
    assert_stdio_tool_response_excludes_substrings, assert_stdio_tools_list, StdioMcpProcess,
};
use serde_json::json;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn stdio_initializes_and_lists_tools() {
    assert_stdio_tools_list(
        env!("CARGO_BIN_EXE_curated-stdio-intent-server"),
        &["brief_target", "detail_by_tracking_id"],
    );
}

#[test]
fn stdio_tool_call_does_not_echo_secret_material() {
    assert_stdio_tool_response_excludes_substrings(
        env!("CARGO_BIN_EXE_curated-stdio-intent-server"),
        "brief_target",
        json!({"target": "probe"}),
        &[
            "development-only-secret",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "BEGIN PRIVATE KEY",
        ],
    );
}

#[test]
fn cli_print_tools_lists_active_profile_tools() {
    let output = Command::new(env!("CARGO_BIN_EXE_curated-stdio-intent-server"))
        .arg("--print-tools")
        .env_remove("EXAMPLE_MCP_TOOL_PROFILE")
        .output()
        .expect("run --print-tools");

    assert!(
        output.status.success(),
        "--print-tools failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "brief_target\ndetail_by_tracking_id\n"
    );
}

#[test]
fn cli_print_tool_schema_uses_snapshot_envelope() {
    let output = Command::new(env!("CARGO_BIN_EXE_curated-stdio-intent-server"))
        .arg("--print-tool-schema")
        .env_remove("EXAMPLE_MCP_TOOL_PROFILE")
        .output()
        .expect("run --print-tool-schema");

    assert!(
        output.status.success(),
        "--print-tool-schema failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("schema snapshot json");
    assert_eq!(snapshot["schema"], "mcp_tool_schema_snapshot");
    assert_eq!(snapshot["version"], 1);
    assert_eq!(snapshot["tools"][0]["name"], "brief_target");
    assert_eq!(snapshot["tools"][1]["name"], "detail_by_tracking_id");
}

#[test]
fn cli_doctor_reports_generated_project_ready() {
    let output = Command::new(env!("CARGO_BIN_EXE_curated-stdio-intent-server"))
        .arg("--doctor")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run --doctor");

    assert!(
        output.status.success(),
        "--doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("mcp-toolkit doctor"));
    assert!(stdout.contains("Shape: stdio"));
    assert!(stdout.contains("Ready: yes"));
}

#[test]
fn cli_print_client_config_renders_stdio_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_curated-stdio-intent-server"))
        .arg("--print-client-config")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run --print-client-config");

    assert!(
        output.status.success(),
        "--print-client-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("[mcp_servers.\"curated-stdio-intent-server\"]"));
    assert!(stdout.contains("command = \""));
    assert!(stdout.contains("EXAMPLE_MCP_TOOL_PROFILE = \"read_only\""));
}

#[test]
fn stdio_discovery_preserves_current_and_legacy_tool_lifecycles() {
    for legacy in [false, true] {
        let mut process = StdioMcpProcess::start(env!("CARGO_BIN_EXE_curated-stdio-intent-server"));
        let meta = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {
                "name": "toolkit-sdk-upgrade-contract",
                "version": "0.0.0"
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        process.send(json!({
            "jsonrpc": "2.0", "id": 10, "method": "server/discover",
            "params": {"_meta": meta.clone()}
        }));
        let discovery = process.response(10);
        assert!(discovery.get("error").is_none(), "{discovery}");
        assert!(discovery["result"]["supportedVersions"]
            .as_array()
            .expect("supported versions")
            .contains(&json!("2026-07-28")));

        if legacy {
            process.send(json!({
                "jsonrpc": "2.0", "id": 11, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "legacy-contract", "version": "0.0.0"}
                }
            }));
            let initialized = process.response(11);
            assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
            process.send(json!({
                "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
            }));
        }

        let mut list_params = json!({});
        if !legacy {
            list_params["_meta"] = meta.clone();
        }
        process.send(json!({
            "jsonrpc": "2.0", "id": 12, "method": "tools/list", "params": list_params
        }));
        let listed = process.response(12);
        assert!(listed.get("error").is_none(), "{listed}");
        let names: Vec<_> = listed["result"]["tools"]
            .as_array()
            .expect("listed tools")
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect();
        assert_eq!(names, ["brief_target", "detail_by_tracking_id"]);
        if !legacy {
            assert_eq!(listed["result"]["resultType"], "complete");
            assert_eq!(listed["result"]["ttlMs"], 0);
            assert_eq!(listed["result"]["cacheScope"], "private");
        }

        let mut call_params = json!({"name": "brief_target", "arguments": {"target": "probe"}});
        if !legacy {
            call_params["_meta"] = meta;
        }
        process.send(json!({
            "jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": call_params
        }));
        let called = process.response(13);
        assert!(called.get("error").is_none(), "{called}");
        assert_eq!(called["result"]["isError"], false);
        assert!(!called["result"]["content"]
            .as_array()
            .expect("tool content")
            .is_empty());
        if legacy {
            assert!(called["result"].get("resultType").is_none());
        } else {
            assert_eq!(called["result"]["resultType"], "complete");
        }
    }
}

#[test]
fn copied_binary_prints_its_own_client_config_outside_source_tree() {
    const PROFILE_ENV: &str = "EXAMPLE_MCP_TOOL_PROFILE";
    let mut builder = tempfile::Builder::new();
    builder.prefix("copied-client-config-");
    #[cfg(unix)]
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    let directory = builder.tempdir().expect("owned test directory");
    let root = directory.path();
    #[cfg(unix)]
    assert_eq!(
        root.metadata()
            .expect("test directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700,
    );
    let copied = root.join(format!("copied server{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(env!("CARGO_BIN_EXE_curated-stdio-intent-server"), &copied).expect("copy binary");
    let output = Command::new(&copied)
        .arg("--print-client-config")
        .current_dir(root)
        .env(PROFILE_ENV, "private-environment-canary")
        .output()
        .expect("copied binary config");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("config UTF-8");
    let escaped_path = copied
        .to_str()
        .expect("test path UTF-8")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    assert!(
        stdout.contains(&format!("command = \"{escaped_path}\"")),
        "{stdout}"
    );
    assert!(stdout.contains("TOOL_PROFILE = \"read_only\""));
    assert!(!stdout.contains("private-environment-canary"));
    assert!(!root.join("Cargo.toml").exists());
    directory.close().expect("remove test copy");
}

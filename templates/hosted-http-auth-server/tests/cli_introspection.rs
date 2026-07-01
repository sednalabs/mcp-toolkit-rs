use std::process::Command;

#[test]
fn cli_print_tools_lists_active_profile_tools_without_binding_http() {
    let output = Command::new(env!("CARGO_BIN_EXE_hosted-http-auth-server"))
        .arg("--print-tools")
        .env_remove("EXAMPLE_MCP_TOOL_PROFILE")
        .env("EXAMPLE_MCP_BIND_ADDR", "not-a-socket-address")
        .output()
        .expect("run --print-tools");

    assert!(
        output.status.success(),
        "--print-tools failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "read_status\n"
    );
}

#[test]
fn cli_print_tool_schema_uses_snapshot_envelope_without_binding_http() {
    let output = Command::new(env!("CARGO_BIN_EXE_hosted-http-auth-server"))
        .arg("--print-tool-schema")
        .env_remove("EXAMPLE_MCP_TOOL_PROFILE")
        .env("EXAMPLE_MCP_BIND_ADDR", "not-a-socket-address")
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
    assert_eq!(snapshot["tools"][0]["name"], "read_status");
}

#[test]
fn cli_doctor_reports_generated_project_ready_without_binding_http() {
    let output = Command::new(env!("CARGO_BIN_EXE_hosted-http-auth-server"))
        .arg("--doctor")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("EXAMPLE_MCP_BIND_ADDR", "not-a-socket-address")
        .output()
        .expect("run --doctor");

    assert!(
        output.status.success(),
        "--doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("mcp-toolkit doctor"));
    assert!(stdout.contains("Shape: hosted-http-auth"));
    assert!(stdout.contains("Ready: yes"));
}

#[test]
fn cli_print_client_config_renders_hosted_http_config_without_binding_http() {
    let output = Command::new(env!("CARGO_BIN_EXE_hosted-http-auth-server"))
        .arg("--print-client-config")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("EXAMPLE_MCP_BIND_ADDR", "not-a-socket-address")
        .output()
        .expect("run --print-client-config");

    assert!(
        output.status.success(),
        "--print-client-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("[mcp_servers.\"hosted-http-auth-server\"]"));
    assert!(stdout.contains("url = \"http://127.0.0.1:9411/mcp\""));
    assert!(!stdout.contains("command ="));
}

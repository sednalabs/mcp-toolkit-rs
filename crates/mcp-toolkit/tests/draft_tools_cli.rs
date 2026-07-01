use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

#[test]
fn draft_tools_cli_outputs_json_report_for_openapi() {
    let root = temp_root("draft-tools-cli");
    let source = root.join("openapi.json");
    fs::write(
        &source,
        json!({
            "openapi": "3.1.0",
            "paths": {
                "/sites": {
                    "get": {
                        "operationId": "listSites",
                        "summary": "List sites.",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {"type": "object"}
                                    }
                                }
                            }
                        }
                    }
                },
                "/sites/{siteUrl}/sitemaps": {
                    "post": {
                        "operationId": "submitSitemap",
                        "summary": "Submit a sitemap.",
                        "parameters": [
                            {
                                "name": "siteUrl",
                                "in": "path",
                                "required": true,
                                "schema": {"type": "string"}
                            }
                        ],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "responses": {"204": {"description": "submitted"}}
                    }
                }
            }
        })
        .to_string(),
    )
    .expect("write OpenAPI source");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .args([
            "draft-tools",
            source.to_str().expect("source path"),
            "--json",
        ])
        .output()
        .expect("run mcp-toolkit draft-tools");

    assert!(
        output.status.success(),
        "draft-tools failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("parse draft report JSON");
    assert_eq!(report["schema"], json!("mcp_toolkit_draft_tools_report"));
    assert_eq!(report["source_kind"], json!("openapi"));
    assert_eq!(report["summary"]["tool_count"], json!(2));

    let tools = report["tools"].as_array().expect("tools array");
    assert_eq!(tools[0]["name"], json!("list_sites"));
    assert_eq!(tools[0]["risk"], json!("read"));
    assert_eq!(tools[0]["enabled_by_default"], json!(true));
    assert_eq!(tools[1]["name"], json!("submit_sitemap"));
    assert_eq!(tools[1]["risk"], json!("write"));
    assert_eq!(tools[1]["profile"], json!("operator"));
    assert_eq!(tools[1]["enabled_by_default"], json!(false));
    assert_eq!(
        tools[1]["input_schema"]["properties"]["site_url"]["type"],
        json!("string")
    );

    cleanup(root);
}

fn temp_root(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path = PathBuf::from(format!(
        "target/mcp-toolkit-draft-tools-tests/{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn cleanup(path: PathBuf) {
    let _ = fs::remove_dir_all(path);
}

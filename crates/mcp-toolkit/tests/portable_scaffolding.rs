//! Public scaffolds should be reproducible and usable from an existing Git clone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // DevSkim: ignore DS173237 because this repeated-character revision is a test fixture, not a credential.

struct Project(PathBuf);

impl Project {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "mcp-portable-scaffold-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&root).expect("create isolated project");
        Self(root)
    }

    fn cli(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
            .current_dir(&self.0)
            .args(arguments)
            .output()
            .expect("run toolkit CLI")
    }

    fn generate(&self, additional: &[&str]) -> Output {
        let mut args = vec![
            "new",
            "warehouse-mcp",
            "--template",
            "public-stdio",
            "--output",
            ".",
        ];
        args.extend_from_slice(additional);
        self.cli(&args)
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn successful(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("UTF-8 CLI output")
}

fn manifest(root: &Path) -> toml_edit::DocumentMut {
    fs::read_to_string(root.join("Cargo.toml"))
        .expect("generated manifest")
        .parse()
        .expect("valid TOML")
}

#[test]
fn current_clone_preserves_license_and_git_while_pinning_every_toolkit_dependency() {
    let project = Project::new();
    fs::create_dir(project.0.join(".git")).unwrap();
    fs::write(project.0.join(".git/marker"), "keep git metadata\n").unwrap();
    fs::write(
        project.0.join("LICENSE"),
        "Existing Apache license and attribution\n",
    )
    .unwrap();

    successful(project.generate(&["--keep-license", "--toolkit-rev", REVISION]));
    assert_eq!(
        fs::read_to_string(project.0.join("LICENSE")).unwrap(),
        "Existing Apache license and attribution\n"
    );
    assert_eq!(
        fs::read_to_string(project.0.join(".git/marker")).unwrap(),
        "keep git metadata\n"
    );

    let manifest = manifest(&project.0);
    for section in ["dependencies", "dev-dependencies"] {
        for (name, dependency) in manifest[section].as_table().unwrap() {
            if name.starts_with("mcp-toolkit") {
                assert_eq!(
                    dependency["git"].as_str(),
                    Some("https://github.com/sednalabs/mcp-toolkit-rs")
                );
                assert_eq!(dependency["rev"].as_str(), Some(REVISION));
                assert!(dependency.get("path").is_none());
            }
        }
    }
    let root_manifest = manifest_at_toolkit_root();
    for package in ["rmcp", "rmcp-macros"] {
        for key in ["git", "rev"] {
            assert_eq!(
                manifest["patch"]["crates-io"][package][key].as_str(),
                root_manifest["patch"]["crates-io"][package][key].as_str()
            );
        }
    }
}

fn manifest_at_toolkit_root() -> toml_edit::DocumentMut {
    manifest(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

#[test]
fn keep_license_does_not_relax_other_collisions_or_partially_generate() {
    let project = Project::new();
    fs::write(project.0.join("LICENSE"), "existing license\n").unwrap();
    fs::write(project.0.join("README.md"), "existing documentation\n").unwrap();
    let output = project.generate(&["--keep-license"]);
    assert!(!output.status.success());
    assert!(!project.0.join("Cargo.toml").exists());
    assert!(!project.0.join(".github").exists());
    assert_eq!(
        fs::read_to_string(project.0.join("README.md")).unwrap(),
        "existing documentation\n"
    );
}

#[test]
fn an_existing_license_still_requires_explicit_preservation() {
    let project = Project::new();
    fs::write(project.0.join("LICENSE"), "existing license\n").unwrap();
    let output = project.generate(&[]);
    assert!(!output.status.success());
    assert!(!project.0.join("Cargo.toml").exists());
    assert_eq!(
        fs::read_to_string(project.0.join("LICENSE")).unwrap(),
        "existing license\n"
    );
}

#[test]
fn keep_license_writes_missing_license_and_wins_over_force() {
    let project = Project::new();
    successful(project.generate(&["--keep-license"]));
    assert!(project.0.join("LICENSE").is_file());
    fs::write(project.0.join("LICENSE"), "retained license\n").unwrap();
    successful(project.generate(&["--keep-license", "--force"]));
    assert_eq!(
        fs::read_to_string(project.0.join("LICENSE")).unwrap(),
        "retained license\n"
    );
}

#[cfg(unix)]
#[test]
fn keep_license_rejects_a_symlink_before_writing_anything() {
    let project = Project::new();
    let external = Project::new();
    fs::write(external.0.join("LICENSE"), "external license\n").unwrap();
    std::os::unix::fs::symlink(external.0.join("LICENSE"), project.0.join("LICENSE")).unwrap();
    let output = project.generate(&["--keep-license", "--force"]);
    assert!(!output.status.success());
    assert!(!project.0.join("Cargo.toml").exists());
    assert_eq!(
        fs::read_to_string(external.0.join("LICENSE")).unwrap(),
        "external license\n"
    );
}

#[test]
fn mutable_or_malformed_revisions_are_rejected_before_creating_output() {
    for revision in [
        "main",
        "v1.0.0",
        "1234567",
        "",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    ] {
        let project = Project::new();
        let output = project.generate(&["--toolkit-rev", revision]);
        assert!(!output.status.success(), "accepted {revision:?}");
        assert!(fs::read_dir(&project.0).unwrap().next().is_none());
    }
}

#[test]
fn custom_git_url_is_pinned_and_used_by_dependency_governance() {
    let project = Project::new();
    let url = "https://github.com/example/mcp-toolkit-rs";
    successful(project.generate(&["--toolkit-git", url, "--toolkit-rev", REVISION]));
    let manifest = manifest(&project.0);
    assert_eq!(
        manifest["dependencies"]["mcp-toolkit"]["git"].as_str(),
        Some(url)
    );
    assert_eq!(
        manifest["dependencies"]["mcp-toolkit"]["rev"].as_str(),
        Some(REVISION)
    );
    let governance = fs::read_to_string(project.0.join("deny.toml"))
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let allowed = governance["sources"]["allow-git"].as_array().unwrap();
    assert!(allowed.iter().any(|value| value.as_str() == Some(url)));
    assert!(!allowed
        .iter()
        .any(|value| value.as_str() == Some("https://github.com/sednalabs/mcp-toolkit-rs")));
}

#[test]
fn revision_cannot_claim_to_pin_a_local_path_dependency() {
    let project = Project::new();
    let output = project.generate(&["--toolkit-root", ".", "--toolkit-rev", REVISION]);
    assert!(!output.status.success());
    assert!(!project.0.join("Cargo.toml").exists());
}

#[test]
fn kiro_stdio_config_is_valid_json_with_no_implicit_auto_approvals() {
    let project = Project::new();
    successful(project.generate(&[]));
    let command = "C:\\MCP Tools\\warehouse \"quoted\".exe";
    let output = successful(project.cli(&[
        "client-config",
        ".",
        "--format",
        "kiro",
        "--command",
        command,
    ]));
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "mcpServers": {"warehouse-mcp": {
                "command": command,
                "args": [],
                "env": {"WAREHOUSE_MCP_TOOL_PROFILE": "read_only"},
                "disabled": false,
                "autoApprove": [],
                "disabledTools": [],
            }}
        })
    );
}

#[test]
fn hosted_kiro_config_omits_process_fields_and_preserves_escaped_url() {
    let project = Project::new();
    successful(project.generate(&[]));
    let url = "https://example.test/mcp?label=\"quoted\"";
    let output = successful(project.cli(&[
        "client-config",
        ".",
        "--transport",
        "http",
        "--format",
        "kiro",
        "--url",
        url,
    ]));
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        value["mcpServers"]["warehouse-mcp"],
        serde_json::json!({
            "url": url, "disabled": false, "autoApprove": [], "disabledTools": [],
        })
    );
}

#[test]
fn generic_json_config_does_not_include_kiro_only_fields() {
    let project = Project::new();
    successful(project.generate(&[]));
    let output =
        successful(project.cli(&["client-config", ".", "--format", "json", "--installed"]));
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        value["mcpServers"]["warehouse-mcp"],
        serde_json::json!({
            "command": "warehouse-mcp", "args": [], "env": {"WAREHOUSE_MCP_TOOL_PROFILE": "read_only"},
        })
    );
}

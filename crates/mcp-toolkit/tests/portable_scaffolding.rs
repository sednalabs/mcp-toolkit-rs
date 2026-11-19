//! Public scaffolds should be reproducible and usable from an existing Git clone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // DevSkim: ignore DS173237 because this repeated-character revision is a test fixture, not a credential.

struct Project(tempfile::TempDir);

impl Project {
    fn new() -> Self {
        Self(
            tempfile::Builder::new()
                .prefix("mcp-portable-scaffold-")
                .tempdir()
                .expect("create owned isolated project"),
        )
    }

    fn cli(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
            .current_dir(self.0.path())
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
    fs::create_dir(project.0.path().join(".git")).unwrap();
    fs::write(project.0.path().join(".git/marker"), "keep git metadata\n").unwrap();
    fs::write(
        project.0.path().join("LICENSE"),
        "Existing Apache license and attribution\n",
    )
    .unwrap();

    successful(project.generate(&["--keep-license", "--toolkit-rev", REVISION]));
    assert_eq!(
        fs::read_to_string(project.0.path().join("LICENSE")).unwrap(),
        "Existing Apache license and attribution\n"
    );
    assert_eq!(
        fs::read_to_string(project.0.path().join(".git/marker")).unwrap(),
        "keep git metadata\n"
    );

    let manifest = manifest(project.0.path());
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
fn every_git_dependency_uses_its_actual_package_version_for_wildcard_policy() {
    let toolkit_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for template in [
        "single-crate-public-stdio",
        "curated-stdio-intent",
        "hosted-http-auth",
    ] {
        for pinned in [false, true] {
            let project = Project::new();
            let mut options = vec![
                "--template",
                template,
                "--toolkit-git",
                "https://github.com/sednalabs/mcp-toolkit-rs",
            ];
            if pinned {
                options.extend(["--toolkit-rev", REVISION]);
            }
            successful(project.generate(&options));
            let generated = manifest(project.0.path());
            let mut found = 0;
            for section in ["dependencies", "dev-dependencies"] {
                let Some(dependencies) = generated.get(section).and_then(toml_edit::Item::as_table)
                else {
                    continue;
                };
                for (name, dependency) in dependencies {
                    if !name.starts_with("mcp-toolkit") {
                        continue;
                    }
                    let source = manifest(&toolkit_root.join("crates").join(name));
                    let version = source["package"]["version"].as_str().unwrap();
                    assert_eq!(
                        dependency["version"].as_str(),
                        Some(format!("={version}").as_str()),
                        "{template}: {name} must satisfy the generated no-wildcard policy"
                    );
                    assert!(dependency.get("path").is_none());
                    found += 1;
                }
            }
            assert!(found > 0);
            if template == "single-crate-public-stdio" {
                let deny: toml_edit::DocumentMut =
                    fs::read_to_string(project.0.path().join("deny.toml"))
                        .unwrap()
                        .parse()
                        .unwrap();
                assert_eq!(deny["bans"]["wildcards"].as_str(), Some("deny"));
                assert!(deny["advisories"]["ignore"].as_array().unwrap().is_empty());
                assert!(!project
                    .0
                    .path()
                    .join(".cargo/advisory-exceptions.toml")
                    .exists());
            }
        }
    }
}

#[test]
fn fresh_public_repositories_require_coverage_without_external_service_setup() {
    let project = Project::new();
    successful(project.generate(&["--toolkit-rev", REVISION]));
    let workflow: serde_json::Value = noyalib_serde_yaml::from_str(
        &fs::read_to_string(project.0.path().join(".github/workflows/code-coverage.yml")).unwrap(),
    )
    .unwrap();
    let steps = workflow["jobs"]["rust-coverage"]["steps"]
        .as_array()
        .unwrap();
    let step = |name| steps.iter().find(|step| step["name"] == name).unwrap();
    let generation = step("Generate coverage");
    assert!(generation.get("if").is_none());
    assert!(generation.get("continue-on-error").is_none());
    assert!(generation["run"]
        .as_str()
        .unwrap()
        .contains("cargo llvm-cov"));
    let artifact = step("Upload Cobertura report");
    assert!(artifact.get("if").is_none());
    assert!(artifact.get("continue-on-error").is_none());
    assert_eq!(artifact["with"]["if-no-files-found"], "error");
    let service = step("Upload coverage to GitHub Code Quality");
    assert_eq!(
        service["if"],
        "${{ vars.ENABLE_GITHUB_CODE_QUALITY == 'true' }}"
    );
    assert!(service.get("continue-on-error").is_none());
}

#[test]
fn keep_license_does_not_relax_other_collisions_or_partially_generate() {
    let project = Project::new();
    fs::write(project.0.path().join("LICENSE"), "existing license\n").unwrap();
    fs::write(
        project.0.path().join("README.md"),
        "existing documentation\n",
    )
    .unwrap();
    let output = project.generate(&["--keep-license"]);
    assert!(!output.status.success());
    assert!(!project.0.path().join("Cargo.toml").exists());
    assert!(!project.0.path().join(".github").exists());
    assert_eq!(
        fs::read_to_string(project.0.path().join("README.md")).unwrap(),
        "existing documentation\n"
    );
}

#[test]
fn an_existing_license_still_requires_explicit_preservation() {
    let project = Project::new();
    fs::write(project.0.path().join("LICENSE"), "existing license\n").unwrap();
    let output = project.generate(&[]);
    assert!(!output.status.success());
    assert!(!project.0.path().join("Cargo.toml").exists());
    assert_eq!(
        fs::read_to_string(project.0.path().join("LICENSE")).unwrap(),
        "existing license\n"
    );
}

#[test]
fn keep_license_writes_missing_license_and_wins_over_force() {
    let project = Project::new();
    successful(project.generate(&["--keep-license"]));
    assert!(project.0.path().join("LICENSE").is_file());
    fs::write(project.0.path().join("LICENSE"), "retained license\n").unwrap();
    successful(project.generate(&["--keep-license", "--force"]));
    assert_eq!(
        fs::read_to_string(project.0.path().join("LICENSE")).unwrap(),
        "retained license\n"
    );
}

#[cfg(unix)]
#[test]
fn keep_license_rejects_a_symlink_before_writing_anything() {
    let project = Project::new();
    let external = Project::new();
    fs::write(external.0.path().join("LICENSE"), "external license\n").unwrap();
    std::os::unix::fs::symlink(
        external.0.path().join("LICENSE"),
        project.0.path().join("LICENSE"),
    )
    .unwrap();
    let output = project.generate(&["--keep-license", "--force"]);
    assert!(!output.status.success());
    assert!(!project.0.path().join("Cargo.toml").exists());
    assert_eq!(
        fs::read_to_string(external.0.path().join("LICENSE")).unwrap(),
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
        assert!(fs::read_dir(project.0.path()).unwrap().next().is_none());
    }
}

#[test]
fn custom_git_url_is_pinned_and_used_by_dependency_governance() {
    let project = Project::new();
    let url = "https://github.com/example/mcp-toolkit-rs";
    successful(project.generate(&["--toolkit-git", url, "--toolkit-rev", REVISION]));
    let manifest = manifest(project.0.path());
    assert_eq!(
        manifest["dependencies"]["mcp-toolkit"]["git"].as_str(),
        Some(url)
    );
    assert_eq!(
        manifest["dependencies"]["mcp-toolkit"]["rev"].as_str(),
        Some(REVISION)
    );
    let governance = fs::read_to_string(project.0.path().join("deny.toml"))
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
    assert!(!project.0.path().join("Cargo.toml").exists());
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

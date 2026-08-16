//! # MCP Toolkit Release Preflight
//!
//! Static public-readiness checks for generated Rust MCP server repositories.
//!
//! ## Rationale
//! `doctor` answers "is this scaffold complete?" while release preflight
//! answers "does this generated repository carry the public proof surface a
//! maintainer should expect before publishing or installing it?"
//!
//! ## Security Boundaries
//! * Reads only metadata and small text files under the caller-provided project.
//! * Does not execute generated code, shell scripts, or provider clients.
//! * Uses high-confidence secret markers only; organization-specific policies
//!   remain outside this public toolkit.
//!
//! ## References
//! * `docs/new-server-delivery-lane.md`
//! * `docs/new-server-cli-reference.md`
//! * `docs/public-landing-policy.md`

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::doctor::{inspect_project, DoctorShape};
use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};
use toml_edit::{DocumentMut, Item, TableLike};

const REQUIRED_PUBLIC_FILES: &[(&str, &str)] = &[
    ("README", "README.md"),
    ("License file", "LICENSE"),
    ("Cargo manifest", "Cargo.toml"),
    ("Cargo lockfile", "Cargo.lock"),
    (
        "Rust baseline workflow",
        ".github/workflows/rust-baseline.yml",
    ),
    ("CodeQL workflow", ".github/workflows/codeql.yml"),
    (
        "Dependency governance workflow",
        ".github/workflows/dependency-governance.yml",
    ),
    (
        "Code coverage workflow",
        ".github/workflows/code-coverage.yml",
    ),
    (
        "Workflow-security query tests",
        ".github/workflows/codeql-query-tests.yml",
    ),
    ("Tool schema snapshot", "spec/tool_schema_snapshot.v1.json"),
    (
        "Catalog profile contract test",
        "tests/catalog_profile_contract.rs",
    ),
    ("Tool schema snapshot test", "tests/tool_schema_snapshot.rs"),
    (
        "Dependency governance script",
        "scripts/dependency_governance_check.sh",
    ),
    (
        "Dependency governance docs",
        "docs/dependency-governance.md",
    ),
    (
        "Native Linux release workflow",
        ".github/workflows/native-release-artifacts.yml",
    ),
    (
        "Native release artifact verifier",
        "scripts/native_release_artifact.py",
    ),
    ("Dependency audit config", "deny.toml"),
];

const STDIO_PROBE_SCENARIO: &str = "spec/mcp_probe_stdio_smoke.v1.json";
const HTTP_AUTH_PROBE_SCENARIO: &str = "spec/mcp_probe_http_auth_smoke.v1.json";

const TEXT_FILE_EXTENSIONS: &[&str] =
    &["toml", "md", "rs", "json", "yml", "yaml", "sh", "py", "txt"];

const TEXT_FILE_NAMES: &[&str] = &[
    "LICENSE",
    ".gitignore",
    "Dockerfile",
    "Makefile",
    "Jenkinsfile",
];

const SECRET_MARKERS: &[(&str, &str)] = &[
    ("private key block", "-----BEGIN "),
    ("GitHub token", "ghp_"),
    ("Slack token", "xoxb-"),
    ("Google OAuth access token", "ya29."),
    ("OpenAI project secret key", "sk-proj-"),
    ("JSON refresh token", "\"refresh_token\""),
    ("JSON access token", "\"access_token\""),
    ("JSON client secret", "\"client_secret\""),
    ("JSON private key", "\"private_key\""),
];

/// Records one release-preflight check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePreflightCheck {
    /// Human-readable check label.
    pub label: &'static str,
    /// Relative path, path group, or static policy inspected for the check.
    pub target: String,
    /// Whether this check blocks public-ready status.
    pub required: bool,
    /// Whether the check passed.
    pub passed: bool,
    /// Short operator-facing detail.
    pub detail: String,
}

/// Summarizes release-preflight readiness for a generated server repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePreflightReport {
    /// Project root inspected by preflight.
    pub root: PathBuf,
    /// Inferred generated-server shape.
    pub shape: DoctorShape,
    /// Public-readiness checks performed.
    pub checks: Vec<ReleasePreflightCheck>,
}

impl ReleasePreflightReport {
    /// Returns true when all required checks pass.
    pub fn ready(&self) -> bool {
        self.checks
            .iter()
            .all(|check| !check.required || check.passed)
    }

    /// Renders the report for terminal output.
    pub fn render(&self) -> String {
        let mut output = String::new();

        output.push_str("mcp-toolkit release-preflight\n");
        output.push_str(&format!("Project: {}\n", self.root.display()));
        output.push_str(&format!("Shape: {}\n", self.shape.as_str()));
        output.push_str(&format!(
            "Public ready: {}\n",
            if self.ready() { "yes" } else { "no" }
        ));
        output.push('\n');
        output.push_str("Checks:\n");

        for check in &self.checks {
            let status = if check.passed {
                "ok"
            } else if check.required {
                "missing"
            } else {
                "warn"
            };
            output.push_str(&format!(
                "  [{status}] {} ({}) - {}\n",
                check.label, check.target, check.detail
            ));
        }

        output.push('\n');
        output.push_str("Next:\n");
        output.push_str(&format!("  cd {}\n", self.root.display()));
        output.push_str("  cargo fmt --all --check\n");
        output.push_str("  cargo test --all-targets --all-features\n");
        output.push_str("  ./scripts/dependency_governance_check.sh\n");
        output.push_str("  record the GitHub Actions run URL before publishing or installing\n");

        output
    }
}

/// Inspects a generated Rust MCP server repository for public readiness.
///
/// This check is intentionally static and credential-free. It is suitable for
/// use before a build, before a PR, or in generated-project CI.
pub fn inspect_release_preflight(root: impl AsRef<Path>) -> ReleasePreflightReport {
    let root = root.as_ref().to_path_buf();
    let doctor = inspect_project(&root);
    let mut checks = Vec::new();

    checks.push(ReleasePreflightCheck {
        label: "Generated scaffold doctor",
        target: "mcp-toolkit doctor".to_string(),
        required: true,
        passed: doctor.ready(),
        detail: if doctor.ready() {
            "starter source, schema, transport proof, and workflow are present".to_string()
        } else {
            "run `mcp-toolkit doctor` and restore missing scaffold files".to_string()
        },
    });

    for (label, path) in REQUIRED_PUBLIC_FILES {
        checks.push(file_check(&root, label, path));
    }

    checks.push(probe_scenario_check(&root, doctor.shape));
    checks.push(manifest_metadata_check(&root));
    checks.push(portable_toolkit_dependencies_check(&root));
    checks.push(cargo_local_path_overrides_check(&root));
    checks.push(readme_guidance_check(&root));
    checks.push(native_release_contract_check(&root));
    checks.push(secret_marker_check(&root));

    ReleasePreflightReport {
        root,
        shape: doctor.shape,
        checks,
    }
}

fn file_check(root: &Path, label: &'static str, path: &'static str) -> ReleasePreflightCheck {
    let present = exists(root, path);
    ReleasePreflightCheck {
        label,
        target: path.to_string(),
        required: true,
        passed: present,
        detail: if present {
            "present".to_string()
        } else {
            "required for a public-ready generated MCP repository".to_string()
        },
    }
}

fn probe_scenario_check(root: &Path, shape: DoctorShape) -> ReleasePreflightCheck {
    let (target, detail) = match shape {
        DoctorShape::HostedHttpAuth => (
            HTTP_AUTH_PROBE_SCENARIO,
            "required hosted HTTP auth MCP probe scenario",
        ),
        DoctorShape::PublicStdio | DoctorShape::Stdio => {
            (STDIO_PROBE_SCENARIO, "required stdio MCP probe scenario")
        }
        DoctorShape::Unknown => (
            "spec/mcp_probe_*.v1.json",
            "doctor could not infer the generated transport; restore stdio or hosted HTTP proof",
        ),
    };
    let passed = shape != DoctorShape::Unknown && exists(root, target);
    ReleasePreflightCheck {
        label: "MCP probe scenario",
        target: target.to_string(),
        required: true,
        passed,
        detail: if passed {
            "present".to_string()
        } else {
            detail.to_string()
        },
    }
}

fn manifest_metadata_check(root: &Path) -> ReleasePreflightCheck {
    let path = root.join("Cargo.toml");
    let contents = fs::read_to_string(&path);
    let (passed, detail) = match contents {
        Ok(contents) => {
            let has_license = contains_manifest_key(&contents, "license");
            let has_description = contains_manifest_key(&contents, "description");
            match (has_license, has_description) {
                (true, true) => (
                    true,
                    "Cargo manifest declares license and description".to_string(),
                ),
                (false, true) => (false, "Cargo manifest is missing `license`".to_string()),
                (true, false) => (false, "Cargo manifest is missing `description`".to_string()),
                (false, false) => (
                    false,
                    "Cargo manifest is missing `license` and `description`".to_string(),
                ),
            }
        }
        Err(error) => (false, format!("failed to read Cargo.toml: {error}")),
    };

    ReleasePreflightCheck {
        label: "Cargo package metadata",
        target: "Cargo.toml".to_string(),
        required: true,
        passed,
        detail,
    }
}

fn portable_toolkit_dependencies_check(root: &Path) -> ReleasePreflightCheck {
    let path = root.join("Cargo.toml");
    let contents = fs::read_to_string(&path);
    let (passed, detail) = match contents {
        Ok(contents) => match local_toolkit_path_dependencies(&contents) {
            Ok(local_deps) => {
                if local_deps.is_empty() {
                    (
                        true,
                        "toolkit dependencies are portable or absent".to_string(),
                    )
                } else {
                    (
                        false,
                        format!(
                            "replace local toolkit path dependencies with `--toolkit-git`: {}",
                            local_deps.join(", ")
                        ),
                    )
                }
            }
            Err(error) => (false, format!("failed to parse Cargo.toml: {error}")),
        },
        Err(error) => (false, format!("failed to read Cargo.toml: {error}")),
    };

    ReleasePreflightCheck {
        label: "Portable toolkit dependencies",
        target: "Cargo.toml".to_string(),
        required: true,
        passed,
        detail,
    }
}

fn cargo_local_path_overrides_check(root: &Path) -> ReleasePreflightCheck {
    let config_paths = [".cargo/config.toml", ".cargo/config"];
    let mut overrides = Vec::new();
    for relative in config_paths {
        if !exists(root, relative) {
            continue;
        }
        let path = root.join(relative);
        match fs::read_to_string(&path) {
            Ok(contents) => match cargo_config_path_overrides(&contents) {
                Ok(mut findings) => overrides.append(&mut findings),
                Err(error) => {
                    return ReleasePreflightCheck {
                        label: "Cargo local path overrides",
                        target: relative.to_string(),
                        required: true,
                        passed: false,
                        detail: format!("failed to parse {relative}: {error}"),
                    };
                }
            },
            Err(error) => {
                return ReleasePreflightCheck {
                    label: "Cargo local path overrides",
                    target: relative.to_string(),
                    required: true,
                    passed: false,
                    detail: format!("failed to read {relative}: {error}"),
                };
            }
        }
    }
    overrides.sort();
    overrides.dedup();
    ReleasePreflightCheck {
        label: "Cargo local path overrides",
        target: ".cargo/config.toml".to_string(),
        required: true,
        passed: overrides.is_empty(),
        detail: if overrides.is_empty() {
            "no committed Cargo path overrides found".to_string()
        } else {
            format!(
                "remove committed Cargo path overrides: {}",
                overrides.join(", ")
            )
        },
    }
}

fn readme_guidance_check(root: &Path) -> ReleasePreflightCheck {
    let path = root.join("README.md");
    let contents = fs::read_to_string(&path);
    let (passed, detail) = match contents {
        Ok(contents) => {
            let required = [
                "cargo run -- --doctor",
                "cargo run -- --print-tools",
                "cargo run -- --print-tool-schema",
                "cargo run -- --print-client-config",
                "cargo test --all-targets --all-features",
            ];
            let missing: Vec<_> = required
                .iter()
                .copied()
                .filter(|needle| !contents.contains(needle))
                .collect();
            if missing.is_empty() {
                (
                    true,
                    "README includes first-run and validation commands".to_string(),
                )
            } else {
                (false, format!("README is missing {}", missing.join(", ")))
            }
        }
        Err(error) => (false, format!("failed to read README.md: {error}")),
    };

    ReleasePreflightCheck {
        label: "README first-run guidance",
        target: "README.md".to_string(),
        required: true,
        passed,
        detail,
    }
}

fn yaml_get<'a>(mapping: &'a YamlMapping, key: &str) -> Option<&'a YamlValue> {
    mapping.get(YamlValue::String(key.to_string()))
}

fn yaml_mapping<'a>(value: &'a YamlValue, context: &str) -> Result<&'a YamlMapping, String> {
    value
        .as_mapping()
        .ok_or_else(|| format!("{} must be a mapping", context))
}

fn yaml_string(value: &YamlValue, context: &str) -> Result<String, String> {
    value
        .as_str()
        .map(str::trim)
        .map(str::to_string)
        .ok_or_else(|| format!("{} must be a string", context))
}

fn permission_map_matches(value: Option<&YamlValue>, expected: &[(&str, &str)]) -> bool {
    let Some(mapping) = value.and_then(YamlValue::as_mapping) else {
        return false;
    };
    if mapping.len() != expected.len() {
        return false;
    }
    expected.iter().all(|(key, expected_value)| {
        yaml_get(mapping, key).and_then(YamlValue::as_str) == Some(*expected_value)
    })
}

fn job_steps<'a>(job: &'a YamlMapping, context: &str) -> Result<&'a Vec<YamlValue>, String> {
    yaml_get(job, "steps")
        .and_then(YamlValue::as_sequence)
        .ok_or_else(|| format!("{}.steps must be a sequence", context))
}

fn step_mappings<'a>(job: &'a YamlMapping, context: &str) -> Result<Vec<&'a YamlMapping>, String> {
    job_steps(job, context)?
        .iter()
        .enumerate()
        .map(|(index, step)| yaml_mapping(step, &format!("{context}.steps[{index}]")))
        .collect()
}

fn job_run_text(job: &YamlMapping, context: &str) -> Result<String, String> {
    let mut commands = Vec::new();
    for step in step_mappings(job, context)? {
        if let Some(run) = yaml_get(step, "run") {
            let run = yaml_string(run, &format!("{context} run"))?;
            let mut continued = String::new();
            for line in run.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let continues = line.ends_with('\\');
                let line = line.trim_end_matches('\\').trim_end();
                if !continued.is_empty() {
                    continued.push(' ');
                }
                continued.push_str(line);
                if !continues {
                    commands.push(std::mem::take(&mut continued));
                }
            }
            if !continued.is_empty() {
                commands.push(continued);
            }
        }
    }
    Ok(commands.join("\n"))
}

fn has_active_command(run_text: &str, prefix: &str) -> bool {
    run_text.lines().any(|line| line.starts_with(prefix))
}

fn job_uses(job: &YamlMapping, context: &str) -> Result<Vec<String>, String> {
    step_mappings(job, context)?
        .into_iter()
        .filter_map(|step| yaml_get(step, "uses"))
        .map(|value| yaml_string(value, &format!("{context} uses")))
        .collect()
}

fn job_needs(job: &YamlMapping, context: &str) -> Result<Vec<String>, String> {
    let Some(value) = yaml_get(job, "needs") else {
        return Ok(Vec::new());
    };
    if let Some(value) = value.as_str() {
        return Ok(vec![value.to_string()]);
    }
    value
        .as_sequence()
        .ok_or_else(|| format!("{context}.needs must be a string or sequence"))?
        .iter()
        .map(|value| yaml_string(value, &format!("{context}.needs")))
        .collect()
}

fn exact_strings(value: Option<&YamlValue>, expected: &[&str]) -> bool {
    let Some(values) = value.and_then(YamlValue::as_sequence) else {
        return false;
    };
    let actual = values
        .iter()
        .filter_map(YamlValue::as_str)
        .collect::<Vec<_>>();
    actual == expected
}

#[derive(Clone, Copy)]
enum ExpectedStepValue {
    String(&'static str),
    Bool(bool),
    Integer(i64),
}

#[derive(Clone, Copy)]
enum PrivilegedStepBody {
    Run {
        script: &'static str,
    },
    Action {
        uses: &'static str,
        inputs: &'static [(&'static str, ExpectedStepValue)],
    },
}

#[derive(Clone, Copy)]
struct PrivilegedStepContract {
    name: &'static str,
    body: PrivilegedStepBody,
}

const CHECKOUT_ACTION: &str = "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10";
const DOWNLOAD_ACTION: &str = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";
const ATTEST_ACTION: &str =
    "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8";
const UPLOAD_ACTION: &str = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";

const TRUSTED_SOURCE_PROOF_RUN: &str = r#"set -euo pipefail
git fetch --force --no-tags origin +refs/heads/main:refs/remotes/origin/main
source_main_proven=$(python3 scripts/native_release_artifact.py prove-source \
  --repository . \
  --candidate "$GITHUB_SHA" \
  --source-event "$GITHUB_EVENT_NAME" \
  --source-ref "$GITHUB_REF")
test "$source_main_proven" = true
echo "SOURCE_MAIN_PROVEN=$source_main_proven" >> "$GITHUB_ENV"
"#;

const GENERATED_REVERIFY_RUN: &str = r#"set -euo pipefail
test "$GITHUB_EVENT_NAME" = push
case "$GITHUB_REF" in
  refs/heads/main|refs/tags/v[0-9]*) ;;
  *) echo "attestation requires a main push or version tag" >&2; exit 1 ;;
esac
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
source_tree=$(git rev-parse HEAD^{tree})
x86_archive="downloaded/$BINARY_NAME-x86_64-unknown-linux-gnu-$GITHUB_SHA.tar.gz"
arm_archive="downloaded/$BINARY_NAME-aarch64-unknown-linux-gnu-$GITHUB_SHA.tar.gz"
python3 scripts/native_release_artifact.py compare \
  --archive "$x86_archive" \
  --target x86_64-unknown-linux-gnu \
  --archive "$arm_archive" \
  --target aarch64-unknown-linux-gnu \
  --binary-name "$BINARY_NAME" \
  --candidate "$GITHUB_SHA" \
  --source-repository "$GITHUB_REPOSITORY" \
  --source-event "$GITHUB_EVENT_NAME" \
  --source-ref "$GITHUB_REF" \
  --source-tree "$source_tree" \
  --source-main-proven "$SOURCE_MAIN_PROVEN" \
  --manifest Cargo.toml \
  --lockfile Cargo.lock \
  --output trusted-verification.json
cmp trusted-verification.json downloaded/native-release-verification.json
test "$(find downloaded -maxdepth 1 -type f | wc -l)" -eq 5
python3 scripts/native_release_artifact.py authorize \
  --verification trusted-verification.json \
  --binary-name "$BINARY_NAME" \
  --candidate "$GITHUB_SHA" \
  --source-repository "$GITHUB_REPOSITORY" \
  --source-event "$GITHUB_EVENT_NAME" \
  --source-ref "$GITHUB_REF" \
  --source-tree "$source_tree" \
  --workflow-run-id "$GITHUB_RUN_ID" \
  --workflow-run-attempt "$GITHUB_RUN_ATTEMPT" \
  --output release-authorization.json
"#;

const ROOT_REVERIFY_RUN: &str = r#"set -euo pipefail
test "$GITHUB_EVENT_NAME" = push
case "$GITHUB_REF" in
  refs/heads/main|refs/tags/v[0-9]*) ;;
  *) echo "attestation requires a main push or version tag" >&2; exit 1 ;;
esac
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
source_tree=$(git rev-parse HEAD^{tree})
x86_archive="downloaded/$BINARY_NAME-x86_64-unknown-linux-gnu-$GITHUB_SHA.tar.gz"
arm_archive="downloaded/$BINARY_NAME-aarch64-unknown-linux-gnu-$GITHUB_SHA.tar.gz"
python3 scripts/native_release_artifact.py compare \
  --archive "$x86_archive" \
  --target x86_64-unknown-linux-gnu \
  --archive "$arm_archive" \
  --target aarch64-unknown-linux-gnu \
  --binary-name "$BINARY_NAME" \
  --candidate "$GITHUB_SHA" \
  --source-repository "$GITHUB_REPOSITORY" \
  --source-event "$GITHUB_EVENT_NAME" \
  --source-ref "$GITHUB_REF" \
  --source-tree "$source_tree" \
  --source-main-proven "$SOURCE_MAIN_PROVEN" \
  --manifest "$MANIFEST_PATH" \
  --lockfile templates/single-crate-public-stdio-server/Cargo.lock \
  --output trusted-template-verification.json
cmp trusted-template-verification.json downloaded/native-template-verification.json
test "$(find downloaded -maxdepth 1 -type f | wc -l)" -eq 5
python3 scripts/native_release_artifact.py authorize \
  --verification trusted-template-verification.json \
  --binary-name "$BINARY_NAME" \
  --candidate "$GITHUB_SHA" \
  --source-repository "$GITHUB_REPOSITORY" \
  --source-event "$GITHUB_EVENT_NAME" \
  --source-ref "$GITHUB_REF" \
  --source-tree "$source_tree" \
  --workflow-run-id "$GITHUB_RUN_ID" \
  --workflow-run-attempt "$GITHUB_RUN_ATTEMPT" \
  --output release-authorization.json
"#;

const CHECKOUT_INPUTS: &[(&str, ExpectedStepValue)] = &[
    ("fetch-depth", ExpectedStepValue::Integer(0)),
    ("persist-credentials", ExpectedStepValue::Bool(false)),
    ("ref", ExpectedStepValue::String("${{ github.sha }}")),
];
const GENERATED_DOWNLOAD_INPUTS: &[(&str, ExpectedStepValue)] = &[
    (
        "pattern",
        ExpectedStepValue::String("native-linux-*-${{ github.sha }}"),
    ),
    ("path", ExpectedStepValue::String("downloaded")),
    ("merge-multiple", ExpectedStepValue::Bool(true)),
];
const GENERATED_ATTEST_INPUTS: &[(&str, ExpectedStepValue)] = &[(
    "subject-path",
    ExpectedStepValue::String(
        "downloaded/*.tar.gz\ndownloaded/*.tar.gz.sha256\ndownloaded/native-release-verification.json\nrelease-authorization.json",
    ),
)];
const GENERATED_UPLOAD_INPUTS: &[(&str, ExpectedStepValue)] = &[
    (
        "name",
        ExpectedStepValue::String("native-linux-authorization-${{ github.sha }}"),
    ),
    (
        "path",
        ExpectedStepValue::String("release-authorization.json"),
    ),
    ("if-no-files-found", ExpectedStepValue::String("error")),
    ("retention-days", ExpectedStepValue::Integer(14)),
];
const ROOT_LOCKFILE_DOWNLOAD_INPUTS: &[(&str, ExpectedStepValue)] = &[
    (
        "name",
        ExpectedStepValue::String("native-stdio-template-source-inputs-${{ github.sha }}"),
    ),
    (
        "path",
        ExpectedStepValue::String("templates/single-crate-public-stdio-server"),
    ),
];
const ROOT_ARTIFACT_DOWNLOAD_INPUTS: &[(&str, ExpectedStepValue)] = &[
    (
        "pattern",
        ExpectedStepValue::String("native-stdio-template-*-unknown-linux-gnu-${{ github.sha }}"),
    ),
    ("path", ExpectedStepValue::String("downloaded")),
    ("merge-multiple", ExpectedStepValue::Bool(true)),
];
const ROOT_REPORT_DOWNLOAD_INPUTS: &[(&str, ExpectedStepValue)] = &[
    (
        "name",
        ExpectedStepValue::String("native-stdio-template-verification-${{ github.sha }}"),
    ),
    ("path", ExpectedStepValue::String("downloaded")),
];
const ROOT_ATTEST_INPUTS: &[(&str, ExpectedStepValue)] = &[(
    "subject-path",
    ExpectedStepValue::String(
        "downloaded/*.tar.gz\ndownloaded/*.tar.gz.sha256\ndownloaded/native-template-verification.json\nrelease-authorization.json",
    ),
)];
const ROOT_UPLOAD_INPUTS: &[(&str, ExpectedStepValue)] = &[
    (
        "name",
        ExpectedStepValue::String("native-stdio-template-authorization-${{ github.sha }}"),
    ),
    (
        "path",
        ExpectedStepValue::String("release-authorization.json"),
    ),
    ("if-no-files-found", ExpectedStepValue::String("error")),
    ("retention-days", ExpectedStepValue::Integer(14)),
];

const GENERATED_PRIVILEGED_STEPS: &[PrivilegedStepContract] = &[
    PrivilegedStepContract {
        name: "Checkout exact trusted candidate",
        body: PrivilegedStepBody::Action {
            uses: CHECKOUT_ACTION,
            inputs: CHECKOUT_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Prove protected-main ancestry for trusted source",
        body: PrivilegedStepBody::Run {
            script: TRUSTED_SOURCE_PROOF_RUN,
        },
    },
    PrivilegedStepContract {
        name: "Download verified artifact set",
        body: PrivilegedStepBody::Action {
            uses: DOWNLOAD_ACTION,
            inputs: GENERATED_DOWNLOAD_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Reverify trusted consumer artifact set",
        body: PrivilegedStepBody::Run {
            script: GENERATED_REVERIFY_RUN,
        },
    },
    PrivilegedStepContract {
        name: "Attest verified native archives, checksums, and report",
        body: PrivilegedStepBody::Action {
            uses: ATTEST_ACTION,
            inputs: GENERATED_ATTEST_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Upload attested release authorization receipt",
        body: PrivilegedStepBody::Action {
            uses: UPLOAD_ACTION,
            inputs: GENERATED_UPLOAD_INPUTS,
        },
    },
];

const ROOT_PRIVILEGED_STEPS: &[PrivilegedStepContract] = &[
    PrivilegedStepContract {
        name: "Checkout exact trusted candidate",
        body: PrivilegedStepBody::Action {
            uses: CHECKOUT_ACTION,
            inputs: CHECKOUT_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Prove protected-main ancestry for trusted source",
        body: PrivilegedStepBody::Run {
            script: TRUSTED_SOURCE_PROOF_RUN,
        },
    },
    PrivilegedStepContract {
        name: "Download immutable template lockfile",
        body: PrivilegedStepBody::Action {
            uses: DOWNLOAD_ACTION,
            inputs: ROOT_LOCKFILE_DOWNLOAD_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Download verified template artifact set",
        body: PrivilegedStepBody::Action {
            uses: DOWNLOAD_ACTION,
            inputs: ROOT_ARTIFACT_DOWNLOAD_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Download verified template report",
        body: PrivilegedStepBody::Action {
            uses: DOWNLOAD_ACTION,
            inputs: ROOT_REPORT_DOWNLOAD_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Reverify trusted consumer artifact set",
        body: PrivilegedStepBody::Run {
            script: ROOT_REVERIFY_RUN,
        },
    },
    PrivilegedStepContract {
        name: "Attest verified template archives, checksums, and report",
        body: PrivilegedStepBody::Action {
            uses: ATTEST_ACTION,
            inputs: ROOT_ATTEST_INPUTS,
        },
    },
    PrivilegedStepContract {
        name: "Upload attested template authorization receipt",
        body: PrivilegedStepBody::Action {
            uses: UPLOAD_ACTION,
            inputs: ROOT_UPLOAD_INPUTS,
        },
    },
];

fn mapping_has_exact_keys(mapping: &YamlMapping, expected: &[&str]) -> bool {
    mapping.len() == expected.len() && expected.iter().all(|key| yaml_get(mapping, key).is_some())
}

fn expected_step_value_matches(actual: Option<&YamlValue>, expected: ExpectedStepValue) -> bool {
    match expected {
        ExpectedStepValue::String(expected) => actual
            .and_then(YamlValue::as_str)
            .is_some_and(|actual| actual.trim() == expected),
        ExpectedStepValue::Bool(expected) => actual.and_then(YamlValue::as_bool) == Some(expected),
        ExpectedStepValue::Integer(expected) => {
            actual.and_then(YamlValue::as_i64) == Some(expected)
        }
    }
}

/// Validates the complete native architecture routing boundary as one closed
/// contract. Any additional strategy option, matrix dimension, include row,
/// or row field can change where unprivileged release code executes, so the
/// workflow must match the canonical hosted runner/target product exactly.
fn validate_exact_native_architecture_strategy(
    job: &YamlMapping,
    context: &str,
) -> Vec<String> {
    let valid = yaml_get(job, "runs-on").and_then(YamlValue::as_str)
        == Some("${{ matrix.runner }}")
        && yaml_get(job, "strategy")
            .and_then(YamlValue::as_mapping)
            .is_some_and(|strategy| {
                mapping_has_exact_keys(strategy, &["fail-fast", "matrix"])
                    && yaml_get(strategy, "fail-fast").and_then(YamlValue::as_bool) == Some(false)
                    && yaml_get(strategy, "matrix")
                        .and_then(YamlValue::as_mapping)
                        .is_some_and(|matrix| {
                            mapping_has_exact_keys(matrix, &["include"])
                                && yaml_get(matrix, "include")
                                    .and_then(YamlValue::as_sequence)
                                    .is_some_and(|include| {
                                        let expected = [
                                            ("ubuntu-24.04", "x86_64-unknown-linux-gnu"),
                                            ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"),
                                        ];
                                        include.len() == expected.len()
                                            && include.iter().zip(expected).all(
                                                |(row, (expected_runner, expected_target))| {
                                                    row.as_mapping().is_some_and(|row| {
                                                        mapping_has_exact_keys(
                                                            row,
                                                            &["runner", "target"],
                                                        ) && yaml_get(row, "runner")
                                                            .and_then(YamlValue::as_str)
                                                            == Some(expected_runner)
                                                            && yaml_get(row, "target")
                                                                .and_then(YamlValue::as_str)
                                                                == Some(expected_target)
                                                    })
                                                },
                                            )
                                    })
                        })
            });

    if valid {
        Vec::new()
    } else {
        vec![format!(
            "{context} must use only runs-on: ${{{{ matrix.runner }}}}, fail-fast: false, and the exact ordered x86_64 and arm64 matrix.include hosted runner/target rows with no extra keys or dimensions"
        )]
    }
}

/// Validates only the privileged job's ordered step boundary. Workflow-specific
/// trigger, job, dependency, permission, and runner semantics remain in their
/// owning validators. Both generated and toolkit-root workflows use this one
/// fail-closed step/key/action/input/run-body contract. YAML scalar parsing
/// supplies standard YAML line-break normalization; this validator performs no
/// trimming, continuation folding, or other command-body normalization.
fn validate_privileged_steps(
    job: &YamlMapping,
    context: &str,
    expected: &[PrivilegedStepContract],
) -> Result<Vec<String>, String> {
    let steps = step_mappings(job, context)?;
    let mut violations = Vec::new();
    let actual_names = steps
        .iter()
        .map(|step| yaml_get(step, "name").and_then(YamlValue::as_str))
        .collect::<Vec<_>>();
    let expected_names = expected
        .iter()
        .map(|step| Some(step.name))
        .collect::<Vec<_>>();
    if steps.len() != expected.len() || actual_names != expected_names {
        violations.push(format!(
            "{context} privileged step sequence must match the exact ordered contract"
        ));
    }

    for (index, (step, expected_step)) in steps.iter().zip(expected.iter()).enumerate() {
        let step_context = format!("{context}.steps[{index}] {}", expected_step.name);
        match expected_step.body {
            PrivilegedStepBody::Run { script } => {
                if !mapping_has_exact_keys(step, &["name", "run", "shell"])
                    || yaml_get(step, "shell").and_then(YamlValue::as_str) != Some("bash")
                    || yaml_get(step, "run").and_then(YamlValue::as_str).is_none()
                {
                    violations.push(format!(
                        "{step_context} must contain only exact name, shell, and run keys"
                    ));
                }
                if yaml_get(step, "run").and_then(YamlValue::as_str) != Some(script) {
                    violations.push(format!(
                        "{step_context} run body must match the exact canonical command body"
                    ));
                }
            }
            PrivilegedStepBody::Action { uses, inputs } => {
                if !mapping_has_exact_keys(step, &["name", "uses", "with"])
                    || yaml_get(step, "uses").and_then(YamlValue::as_str) != Some(uses)
                {
                    violations.push(format!(
                        "{step_context} action is not pinned to the exact contract or contains unexpected keys"
                    ));
                }
                let Some(with) = yaml_get(step, "with").and_then(YamlValue::as_mapping) else {
                    violations.push(format!("{step_context}.with must be an exact mapping"));
                    continue;
                };
                let inputs_match = mapping_has_exact_keys(
                    with,
                    &inputs.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
                ) && inputs
                    .iter()
                    .all(|(key, value)| expected_step_value_matches(yaml_get(with, key), *value));
                if !inputs_match {
                    if inputs.iter().any(|(key, _)| *key == "subject-path") {
                        violations.push(format!(
                            "{step_context} subject-path must match the exact complete ordered subject set"
                        ));
                    } else {
                        violations.push(format!(
                            "{step_context}.with must match the exact permitted key/value contract"
                        ));
                    }
                }
            }
        }
    }

    Ok(violations)
}

fn validate_native_release_workflow(workflow: &str) -> Result<Vec<String>, String> {
    let document: YamlValue = serde_yaml_ng::from_str(workflow)
        .map_err(|error| format!("invalid workflow YAML: {error}"))?;
    let root = yaml_mapping(&document, "workflow")?;
    let triggers = yaml_get(root, "on")
        .ok_or_else(|| "workflow.on is required".to_string())
        .and_then(|value| yaml_mapping(value, "workflow.on"))?;
    let mut violations = Vec::new();
    if triggers.len() != 1 || yaml_get(triggers, "push").is_none() {
        violations.push("workflow must be triggered only by trusted push events".to_string());
    } else if let Some(push) = yaml_get(triggers, "push") {
        let push = yaml_mapping(push, "workflow.on.push")?;
        let mut push_keys = push
            .keys()
            .filter_map(YamlValue::as_str)
            .collect::<Vec<_>>();
        push_keys.sort_unstable();
        if push.len() != 2
            || push_keys != ["branches", "tags"]
            || !exact_strings(yaml_get(push, "branches"), &["main"])
            || !exact_strings(yaml_get(push, "tags"), &["v[0-9]*"])
        {
            violations.push(
                "push trigger must contain only exact main and version-tag filters".to_string(),
            );
        }
    }
    if !permission_map_matches(yaml_get(root, "permissions"), &[("contents", "read")]) {
        violations.push("workflow permissions must be contents: read".to_string());
    }

    let jobs = yaml_get(root, "jobs")
        .ok_or_else(|| "workflow.jobs is required".to_string())
        .and_then(|value| yaml_mapping(value, "workflow.jobs"))?;
    let mut job_names = jobs
        .keys()
        .filter_map(YamlValue::as_str)
        .collect::<Vec<_>>();
    job_names.sort_unstable();
    if jobs.len() != 3
        || job_names
            != [
                "attest-native-linux",
                "build-native-linux",
                "verify-native-linux",
            ]
    {
        violations.push(
            "workflow jobs must contain only build, verification, and attestation jobs".to_string(),
        );
    }
    let build = yaml_get(jobs, "build-native-linux")
        .ok_or_else(|| "build-native-linux job is required".to_string())
        .and_then(|value| yaml_mapping(value, "build-native-linux"))?;
    let verify = yaml_get(jobs, "verify-native-linux")
        .ok_or_else(|| "verify-native-linux job is required".to_string())
        .and_then(|value| yaml_mapping(value, "verify-native-linux"))?;
    let attest = yaml_get(jobs, "attest-native-linux")
        .ok_or_else(|| "attest-native-linux job is required".to_string())
        .and_then(|value| yaml_mapping(value, "attest-native-linux"))?;

    if !mapping_has_exact_keys(
        attest,
        &[
            "env",
            "if",
            "name",
            "needs",
            "permissions",
            "runs-on",
            "steps",
            "timeout-minutes",
        ],
    ) {
        violations.push(
            "attestation job must contain the complete exact privileged job contract".to_string(),
        );
    }

    if yaml_get(build, "permissions").is_some() || yaml_get(verify, "permissions").is_some() {
        violations
            .push("build and verification jobs must inherit read-only permissions".to_string());
    }
    if yaml_get(verify, "runs-on").and_then(YamlValue::as_str) != Some("ubuntu-24.04")
        || yaml_get(attest, "runs-on").and_then(YamlValue::as_str) != Some("ubuntu-24.04")
    {
        violations.push(
            "required jobs must use the exact matrix or literal GitHub-hosted runner labels"
                .to_string(),
        );
    }
    if !permission_map_matches(
        yaml_get(attest, "permissions"),
        &[
            ("attestations", "write"),
            ("contents", "read"),
            ("id-token", "write"),
        ],
    ) {
        violations
            .push("attestation job must use exact job-scoped provenance permissions".to_string());
    }
    let attest_if = yaml_get(attest, "if")
        .and_then(YamlValue::as_str)
        .map(str::trim);
    if attest_if
        != Some(
            "github.event_name == 'push' && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v'))",
        )
    {
        violations.push("attestation job must be gated to main or version-tag push events".to_string());
    }
    let verify_needs = job_needs(verify, "verify-native-linux")?;
    if verify_needs != ["build-native-linux"] {
        violations.push("verification must depend on native builds".to_string());
    }
    let attest_needs = job_needs(attest, "attest-native-linux")?;
    if attest_needs != ["build-native-linux", "verify-native-linux"] {
        violations
            .push("attestation must depend on successful build and verification jobs".to_string());
    }

    violations.extend(validate_exact_native_architecture_strategy(
        build,
        "native build architecture strategy",
    ));

    let build_run = job_run_text(build, "build-native-linux")?;
    if !has_active_command(&build_run, "git fetch --force --no-tags origin")
        || !has_active_command(
            &build_run,
            "source_main_proven=$(python3 scripts/native_release_artifact.py prove-source",
        )
        || !build_run.contains("--source-main-proven")
    {
        violations.push(
            "build job must prove protected-main ancestry from complete fetched history"
                .to_string(),
        );
    }
    for required in ["cargo build --release --locked", "cargo cyclonedx"] {
        if !has_active_command(&build_run, required) {
            violations.push(format!("build job is missing active command {required}"));
        }
    }
    let package_command = build_run.lines().find(|line| {
        line.starts_with("archive=$(python3 scripts/native_release_artifact.py package")
    });
    let verify_command = build_run
        .lines()
        .find(|line| line.starts_with("python3 scripts/native_release_artifact.py verify"));
    for (label, command) in [("package", package_command), ("verify", verify_command)] {
        let Some(command) = command else {
            violations.push(format!("build job is missing active {label} command"));
            continue;
        };
        for argument in [
            "--source-repository",
            "--source-event",
            "--source-ref",
            "--source-tree",
            "--source-main-proven",
            "--manifest",
            "--lockfile",
        ] {
            if !command.contains(argument) {
                violations.push(format!("active {label} command is missing {argument}"));
            }
        }
    }
    let verify_run = job_run_text(verify, "verify-native-linux")?;
    if !has_active_command(&verify_run, "git fetch --force --no-tags origin")
        || !has_active_command(
            &verify_run,
            "source_main_proven=$(python3 scripts/native_release_artifact.py prove-source",
        )
        || !verify_run.contains("--source-main-proven")
    {
        violations
            .push("verification job must independently prove protected-main ancestry".to_string());
    }
    let compare_command = verify_run
        .lines()
        .find(|line| line.starts_with("python3 scripts/native_release_artifact.py compare"));
    if match compare_command {
        Some(command) => {
            !command.contains("--source-tree")
                || !command.contains("--source-main-proven")
                || !command.contains("--lockfile")
        }
        None => true,
    } {
        violations.push("verification job must compare source-bound native artifacts".to_string());
    }
    let attest_run = job_run_text(attest, "attest-native-linux")?;
    if !has_active_command(
        &attest_run,
        "python3 scripts/native_release_artifact.py compare",
    ) || !has_active_command(&attest_run, "cmp trusted-verification.json")
        || !has_active_command(
            &attest_run,
            "python3 scripts/native_release_artifact.py authorize",
        )
        || !attest_run
            .lines()
            .any(|line| line.contains("--output release-authorization.json"))
        || !has_active_command(&attest_run, "git fetch --force --no-tags origin")
        || !has_active_command(
            &attest_run,
            "source_main_proven=$(python3 scripts/native_release_artifact.py prove-source",
        )
        || !attest_run.contains("--source-main-proven")
    {
        violations.push(
            "attestation job must independently reverify the consumer artifact set".to_string(),
        );
    }
    let authorize_command = attest_run
        .lines()
        .find(|line| line.starts_with("python3 scripts/native_release_artifact.py authorize"));
    if match authorize_command {
        Some(command) => [
            "--binary-name",
            "--candidate",
            "--source-repository",
            "--source-event",
            "--source-ref",
            "--source-tree",
        ]
        .iter()
        .any(|argument| !command.contains(argument)),
        None => true,
    } {
        violations.push("authorization receipt must bind every exact source identity".to_string());
    }

    violations.extend(validate_privileged_steps(
        attest,
        "attest-native-linux",
        GENERATED_PRIVILEGED_STEPS,
    )?);

    let mut all_uses = Vec::new();
    for (name, value) in jobs {
        let Some(name) = name.as_str() else {
            violations.push("workflow job identifiers must be strings".to_string());
            continue;
        };
        let job = yaml_mapping(value, &format!("workflow.jobs.{name}"))?;
        if name == "attest-native-linux" {
            continue;
        }
        for value in job_uses(job, name)? {
            if !value.starts_with("./") {
                let pinned = value.rsplit_once('@').is_some_and(|(_, reference)| {
                    reference.len() == 40
                        && reference
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                });
                if !pinned {
                    violations.push(format!(
                        "external action is not pinned to a lowercase SHA: {value}"
                    ));
                }
            }
            all_uses.push((name, value));
        }
    }
    if all_uses
        .iter()
        .any(|(_, value)| value.starts_with("actions/attest-build-provenance@"))
    {
        violations
            .push("only the trusted attestation job may invoke provenance attestation".to_string());
    }
    for (name, job) in [
        ("build-native-linux", build),
        ("verify-native-linux", verify),
    ] {
        let mut checkout_count = 0;
        for step in step_mappings(job, name)? {
            let Some(uses) = yaml_get(step, "uses").and_then(YamlValue::as_str) else {
                continue;
            };
            if !uses.trim().starts_with("actions/checkout@") {
                continue;
            }
            checkout_count += 1;
            let Some(with) = yaml_get(step, "with").and_then(YamlValue::as_mapping) else {
                violations.push(format!(
                    "{name} checkout must define exact candidate settings"
                ));
                continue;
            };
            if yaml_get(with, "persist-credentials").and_then(YamlValue::as_bool) != Some(false)
                || yaml_get(with, "ref").and_then(YamlValue::as_str) != Some("${{ github.sha }}")
                || yaml_get(with, "fetch-depth").and_then(YamlValue::as_i64) != Some(0)
            {
                violations.push(format!(
                    "{name} checkout must disable credentials, pin github.sha, and fetch complete history"
                ));
            }
        }
        if checkout_count != 1 {
            violations.push(format!(
                "{name} must contain exactly one pinned checkout step"
            ));
        }
    }

    Ok(violations)
}

fn validate_native_template_attestation_workflow(workflow: &str) -> Result<Vec<String>, String> {
    let document: YamlValue = serde_yaml_ng::from_str(workflow)
        .map_err(|error| format!("invalid template attestation workflow YAML: {error}"))?;
    let root = yaml_mapping(&document, "template attestation workflow")?;
    let triggers = yaml_get(root, "on")
        .ok_or_else(|| "template attestation workflow.on is required".to_string())
        .and_then(|value| yaml_mapping(value, "template attestation workflow.on"))?;
    let mut violations = Vec::new();
    if triggers.len() != 1 || yaml_get(triggers, "push").is_none() {
        violations.push(
            "template attestation workflow must be triggered only by trusted push events"
                .to_string(),
        );
    } else if let Some(push) = yaml_get(triggers, "push") {
        let push = yaml_mapping(push, "template attestation workflow.on.push")?;
        let mut push_keys = push
            .keys()
            .filter_map(YamlValue::as_str)
            .collect::<Vec<_>>();
        push_keys.sort_unstable();
        if push.len() != 2
            || push_keys != ["branches", "tags"]
            || !exact_strings(yaml_get(push, "branches"), &["main"])
            || !exact_strings(yaml_get(push, "tags"), &["v[0-9]*"])
        {
            violations.push(
                "template attestation push trigger must contain only exact main and version-tag filters"
                    .to_string(),
            );
        }
    }
    if !permission_map_matches(yaml_get(root, "permissions"), &[("contents", "read")]) {
        violations
            .push("template attestation workflow permissions must be contents: read".to_string());
    }

    let jobs = yaml_get(root, "jobs")
        .ok_or_else(|| "template attestation workflow.jobs is required".to_string())
        .and_then(|value| yaml_mapping(value, "template attestation workflow.jobs"))?;
    let mut job_names = jobs
        .keys()
        .filter_map(YamlValue::as_str)
        .collect::<Vec<_>>();
    job_names.sort_unstable();
    if jobs.len() != 2 || job_names != ["attest-native-template", "prove-native-template"] {
        violations.push(
            "template attestation workflow jobs must contain only proof and attestation jobs"
                .to_string(),
        );
    }
    let prove = yaml_get(jobs, "prove-native-template")
        .ok_or_else(|| "prove-native-template job is required".to_string())
        .and_then(|value| yaml_mapping(value, "prove-native-template"))?;
    let attest = yaml_get(jobs, "attest-native-template")
        .ok_or_else(|| "attest-native-template job is required".to_string())
        .and_then(|value| yaml_mapping(value, "attest-native-template"))?;

    let mut prove_keys = prove
        .keys()
        .filter_map(YamlValue::as_str)
        .collect::<Vec<_>>();
    prove_keys.sort_unstable();
    let mut attest_keys = attest
        .keys()
        .filter_map(YamlValue::as_str)
        .collect::<Vec<_>>();
    attest_keys.sort_unstable();
    if prove.len() != 2 || prove_keys != ["permissions", "uses"] {
        violations.push(
            "template proof job must contain only its local reusable call and read permission"
                .to_string(),
        );
    }
    if attest.len() != 8
        || attest_keys
            != [
                "env",
                "if",
                "name",
                "needs",
                "permissions",
                "runs-on",
                "steps",
                "timeout-minutes",
            ]
    {
        violations.push(
            "template attestation job must contain the complete exact privileged job contract"
                .to_string(),
        );
    }

    if !permission_map_matches(yaml_get(prove, "permissions"), &[("contents", "read")])
        || yaml_get(prove, "uses").and_then(YamlValue::as_str)
            != Some("./.github/workflows/native-stdio-release-template-proof.yml")
        || yaml_get(prove, "runs-on").is_some()
        || yaml_get(prove, "steps").is_some()
    {
        violations.push(
            "template proof job must call only the local read-only reusable proof workflow"
                .to_string(),
        );
    }
    if job_needs(attest, "attest-native-template")? != ["prove-native-template"] {
        violations
            .push("template attestation must depend on successful template proof".to_string());
    }
    if yaml_get(attest, "runs-on").and_then(YamlValue::as_str) != Some("ubuntu-24.04") {
        violations.push(
            "template attestation job must use the exact GitHub-hosted runner label".to_string(),
        );
    }
    if !permission_map_matches(
        yaml_get(attest, "permissions"),
        &[
            ("attestations", "write"),
            ("contents", "read"),
            ("id-token", "write"),
        ],
    ) {
        violations.push(
            "template attestation job must isolate exact job-scoped OIDC and attestation permissions"
                .to_string(),
        );
    }
    if yaml_get(attest, "if")
        .and_then(YamlValue::as_str)
        .map(str::trim)
        != Some(
            "github.event_name == 'push' && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v'))",
        )
    {
        violations.push(
            "template attestation job must be gated to main or version-tag push events".to_string(),
        );
    }

    violations.extend(validate_privileged_steps(
        attest,
        "attest-native-template",
        ROOT_PRIVILEGED_STEPS,
    )?);

    let attest_run = job_run_text(attest, "attest-native-template")?;
    for required in [
        "git fetch --force --no-tags origin +refs/heads/main:refs/remotes/origin/main",
        "source_main_proven=$(python3 scripts/native_release_artifact.py prove-source",
        "python3 scripts/native_release_artifact.py compare",
        "cmp trusted-template-verification.json downloaded/native-template-verification.json",
        "python3 scripts/native_release_artifact.py authorize",
    ] {
        if !has_active_command(&attest_run, required) {
            violations.push(format!(
                "template attestation authorization path is missing active command {required}"
            ));
        }
    }
    if !attest_run.contains("--source-main-proven") {
        violations.push(
            "template attestation authorization path must bind protected-main ancestry".to_string(),
        );
    }
    let authorize_command = attest_run
        .lines()
        .find(|line| line.starts_with("python3 scripts/native_release_artifact.py authorize"));
    if match authorize_command {
        Some(command) => [
            "--binary-name",
            "--candidate",
            "--source-repository",
            "--source-event",
            "--source-ref",
            "--source-tree",
            "--workflow-run-id",
            "--workflow-run-attempt",
            "--output release-authorization.json",
        ]
        .iter()
        .any(|argument| !command.contains(argument)),
        None => true,
    } {
        violations.push(
            "template authorization receipt must bind exact source and workflow-run identity"
                .to_string(),
        );
    }

    Ok(violations)
}

fn native_release_contract_check(root: &Path) -> ReleasePreflightCheck {
    let workflow_path = root.join(".github/workflows/native-release-artifacts.yml");
    let helper_path = root.join("scripts/native_release_artifact.py");
    let workflow = fs::read_to_string(&workflow_path);
    let helper = fs::read_to_string(&helper_path);
    let (passed, detail) = match (workflow, helper) {
        (Ok(workflow), Ok(helper)) => match validate_native_release_workflow(&workflow) {
            Ok(mut violations) => {
                let required_helper = [
                    "BUILD-CANDIDATE",
                    "MANIFEST.sha256",
                    "CycloneDX",
                    "tool-inventory.json",
                    "tool-schema.json",
                    "verify_elf",
                    "inspect_glibc",
                    "validate_sbom_graph",
                    "prove_source_on_main",
                    "release_source_eligible",
                    "authorization_receipt",
                    "mcp-toolkit.release.source.main_proven",
                    "mcp-toolkit.release.source.tree",
                    "mcp-toolkit.release.lockfile.sha256",
                ];
                violations.extend(
                    required_helper
                        .iter()
                        .filter(|needle| !helper.contains(**needle))
                        .map(|needle| format!("release verifier is missing {needle}")),
                );
                let template_attestation_path =
                    root.join(".github/workflows/native-stdio-release-template-attest.yml");
                if template_attestation_path.exists() {
                    match fs::read_to_string(&template_attestation_path) {
                        Ok(template_attestation) => {
                            match validate_native_template_attestation_workflow(
                                &template_attestation,
                            ) {
                                Ok(template_violations) => violations.extend(template_violations),
                                Err(error) => violations.push(error),
                            }
                        }
                        Err(error) => violations.push(format!(
                            "failed to read native template attestation workflow: {error}"
                        )),
                    }
                }
                if violations.is_empty() {
                    (
                        true,
                        "trusted main/tag attestation follows read-only builds, consumer reverification, source/input-bound SBOMs, and GNU runtime checks"
                            .to_string(),
                    )
                } else {
                    (false, violations.join("; "))
                }
            }
            Err(error) => (false, error),
        },
        (Err(error), _) => (
            false,
            format!("failed to read native release workflow: {error}"),
        ),
        (_, Err(error)) => (
            false,
            format!("failed to read native release verifier: {error}"),
        ),
    };

    ReleasePreflightCheck {
        label: "Native Linux release contract",
        target:
            ".github/workflows/native-release-artifacts.yml + optional native template attestation workflow + scripts/native_release_artifact.py"
                .to_string(),
        required: true,
        passed,
        detail,
    }
}

fn secret_marker_check(root: &Path) -> ReleasePreflightCheck {
    let findings = high_confidence_secret_findings(root);
    let passed = findings.is_empty();
    ReleasePreflightCheck {
        label: "High-confidence secret marker scan",
        target: "generated text files".to_string(),
        required: true,
        passed,
        detail: if passed {
            "no high-confidence secret markers found".to_string()
        } else {
            format!("found {}", findings.join(", "))
        },
    }
}

fn local_toolkit_path_dependencies(contents: &str) -> Result<Vec<String>, toml_edit::TomlError> {
    let manifest = contents.parse::<DocumentMut>()?;
    let mut deps = Vec::new();
    collect_dependency_tables(manifest.as_table(), &mut deps);
    if let Some(workspace) = manifest
        .as_item()
        .get("workspace")
        .and_then(Item::as_table_like)
    {
        collect_dependency_tables(workspace, &mut deps);
    }
    if let Some(target) = manifest
        .as_item()
        .get("target")
        .and_then(Item::as_table_like)
    {
        collect_target_dependency_tables(target, &mut deps);
    }
    collect_cargo_override_tables(manifest.as_table(), &mut deps);
    deps.sort();
    deps.dedup();
    Ok(deps)
}

fn cargo_config_path_overrides(contents: &str) -> Result<Vec<String>, toml_edit::TomlError> {
    let config = contents.parse::<DocumentMut>()?;
    let mut overrides = Vec::new();
    if let Some(paths) = config.as_item().get("paths") {
        let has_entries = paths
            .as_array()
            .map(|array| !array.is_empty())
            .unwrap_or(true);
        if has_entries {
            overrides.push("paths".to_string());
        }
    }
    Ok(overrides)
}

fn collect_cargo_override_tables(root: &dyn TableLike, deps: &mut Vec<String>) {
    if let Some(patch) = root.get("patch").and_then(Item::as_table_like) {
        for (_source, item) in patch.iter() {
            if let Some(source_overrides) = item.as_table_like() {
                collect_local_toolkit_dependencies(source_overrides, deps);
            }
        }
    }
    if let Some(replace) = root.get("replace").and_then(Item::as_table_like) {
        collect_local_toolkit_dependencies(replace, deps);
    }
}

fn collect_target_dependency_tables(table: &dyn TableLike, deps: &mut Vec<String>) {
    for (_name, item) in table.iter() {
        if let Some(child) = item.as_table_like() {
            collect_dependency_tables(child, deps);
            collect_target_dependency_tables(child, deps);
        }
        if let Some(array) = item.as_array_of_tables() {
            for child in array.iter() {
                collect_dependency_tables(child, deps);
                collect_target_dependency_tables(child, deps);
            }
        }
    }
}

fn collect_dependency_tables(table: &dyn TableLike, deps: &mut Vec<String>) {
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dependencies) = table.get(table_name).and_then(Item::as_table_like) {
            collect_local_toolkit_dependencies(dependencies, deps);
        }
    }
}

fn collect_local_toolkit_dependencies(table: &dyn TableLike, deps: &mut Vec<String>) {
    for (name, item) in table.iter() {
        let Some(toolkit_dependency) = toolkit_dependency_label(name, item) else {
            continue;
        };
        let Some(metadata) = item.as_table_like() else {
            continue;
        };
        if metadata.contains_key("path") {
            deps.push(toolkit_dependency);
        }
    }
}

fn toolkit_dependency_label(name: &str, item: &Item) -> Option<String> {
    if is_toolkit_dependency_name(name) {
        return Some(name.to_string());
    }
    let package = item
        .as_table_like()
        .and_then(|metadata| metadata.get("package"))
        .and_then(Item::as_str)?;
    if is_toolkit_dependency_name(package) {
        Some(format!("{name} (package = {package})"))
    } else {
        None
    }
}

fn is_toolkit_dependency_name(name: &str) -> bool {
    name == "mcp-toolkit" || name.starts_with("mcp-toolkit-") || name.starts_with("mcp-toolkit:")
}

fn contains_manifest_key(contents: &str, key: &str) -> bool {
    let mut in_package = false;
    for line in contents.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let table_name = trimmed[1..trimmed.len() - 1].trim();
            in_package = table_name == "package";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some((candidate, value)) = trimmed.split_once('=') {
            if manifest_key_has_value(candidate.trim(), value.trim(), key) {
                return true;
            }
        }
    }
    false
}

fn manifest_key_has_value(candidate: &str, value: &str, key: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    if candidate == key {
        return true;
    }

    matches!(candidate.strip_prefix(key), Some(".workspace")) && value == "true"
}

fn high_confidence_secret_findings(root: &Path) -> Vec<String> {
    let mut findings = Vec::new();
    let root = match fs::canonicalize(root) {
        Ok(root) => root,
        Err(_) => return findings,
    };
    scan_dir(&root, &root, &mut findings);
    findings
}

fn scan_dir(root: &Path, dir: &Path, findings: &mut Vec<String>) {
    let dir = match canonical_child(root, dir) {
        Some(dir) => dir,
        None => return,
    };
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry_result in entries {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            if let Some(path) = canonical_child(root, &path) {
                scan_dir(root, &path, findings);
            }
        } else if file_type.is_file() && should_scan_text_file(&path) {
            scan_file(root, &path, findings);
        }
    }
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == ".git" || name == "target" || name == "node_modules")
        .unwrap_or(false)
}

fn should_scan_text_file(path: &Path) -> bool {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| TEXT_FILE_NAMES.contains(&name) || name.starts_with(".env"))
        .unwrap_or(false)
    {
        return true;
    }

    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| TEXT_FILE_EXTENSIONS.contains(&extension))
        .unwrap_or(false)
}

fn canonical_child(root: &Path, path: &Path) -> Option<PathBuf> {
    let path = fs::canonicalize(path).ok()?;
    if path.starts_with(root) {
        Some(path)
    } else {
        None
    }
}

fn scan_file(root: &Path, path: &Path, findings: &mut Vec<String>) {
    let path = match canonical_child(root, path) {
        Some(path) => path,
        None => return,
    };
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(_) => return,
    };
    for (label, marker) in SECRET_MARKERS {
        if contents.contains(marker) {
            let relative = path.strip_prefix(root).unwrap_or(path.as_path());
            findings.push(format!("{} in {}", label, relative.display()));
        }
    }
}

fn exists(root: &Path, relative: &str) -> bool {
    let mut current = root.to_path_buf();
    let mut components = Path::new(relative).components().peekable();

    while let Some(component) = components.next() {
        match component {
            Component::Normal(segment) => current.push(segment),
            _ => return false,
        }

        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            return false;
        }

        if components.peek().is_some() {
            if !file_type.is_dir() {
                return false;
            }
        } else {
            return file_type.is_file();
        }
    }

    false
}

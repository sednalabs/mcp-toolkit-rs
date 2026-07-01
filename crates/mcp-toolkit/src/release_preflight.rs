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

const REQUIRED_PUBLIC_FILES: &[(&str, &str)] = &[
    ("README", "README.md"),
    ("License file", "LICENSE"),
    ("Cargo manifest", "Cargo.toml"),
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
    ("MCP probe scenario", "spec/mcp_probe_stdio_smoke.v1.json"),
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
    ("Dependency audit config", "deny.toml"),
];

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

    checks.push(manifest_metadata_check(&root));
    checks.push(readme_guidance_check(&root));
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

//! # MCP Toolkit Generated Server Doctor
//!
//! Inspects generated Rust MCP server projects for the starter files and proof
//! artifacts that the maintained templates are expected to carry.
//!
//! ## Rationale
//! New server authors should be able to ask the toolkit whether a scaffold is
//! complete before wiring it into an MCP client. This module keeps that check
//! deterministic and filesystem-only so it can run before dependencies build.
//!
//! ## Security Boundaries
//! * Reads only file metadata below the caller-provided project directory.
//! * Does not execute generated code or shell commands.
//! * Reports relative paths and suggested commands only.
//!
//! ## References
//! * `docs/starter-templates.md`
//! * `docs/easy-server-ergonomics.md`

use std::fs;
use std::path::{Component, Path, PathBuf};

const REQUIRED_FILES: &[(&str, &str)] = &[
    ("Cargo manifest", "Cargo.toml"),
    ("Library entrypoint", "src/lib.rs"),
    ("Binary entrypoint", "src/main.rs"),
    ("Tool schema snapshot", "spec/tool_schema_snapshot.v1.json"),
    ("Tool schema snapshot test", "tests/tool_schema_snapshot.rs"),
    (
        "Catalog profile contract test",
        "tests/catalog_profile_contract.rs",
    ),
    (
        "Hosted validation workflow",
        ".github/workflows/rust-baseline.yml",
    ),
];

const STDIO_CONTRACT_TEST: &str = "tests/stdio_smoke.rs";
const HTTP_AUTH_CONTRACT_TEST: &str = "tests/http_auth_contract.rs";
const STDIO_PROBE_SCENARIO: &str = "spec/mcp_probe_stdio_smoke.v1.json";
const HTTP_AUTH_PROBE_SCENARIO: &str = "spec/mcp_probe_http_auth_smoke.v1.json";
const TRANSPORT_PROOF_PATH: &str = "tests/stdio_smoke.rs + spec/mcp_probe_stdio_smoke.v1.json or tests/http_auth_contract.rs + spec/mcp_probe_http_auth_smoke.v1.json";
const PUBLIC_GOVERNANCE_SCRIPT: &str = "scripts/dependency_governance_check.sh";

/// Classifies the generated server shape that the doctor can infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorShape {
    /// A hosted Streamable HTTP server with auth contracts.
    HostedHttpAuth,
    /// A standalone public stdio server with additional governance files.
    PublicStdio,
    /// A stdio server with the standard process-local contract.
    Stdio,
    /// The project is missing enough starter files that the shape is unknown.
    Unknown,
}

impl DoctorShape {
    /// Returns the stable label shown in CLI output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostedHttpAuth => "hosted-http-auth",
            Self::PublicStdio => "public-stdio",
            Self::Stdio => "stdio",
            Self::Unknown => "unknown",
        }
    }
}

/// Records one generated-server doctor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    /// Human-readable check label.
    pub label: &'static str,
    /// Relative path or path group inspected for the check.
    pub path: String,
    /// Whether a missing file should make the report fail.
    pub required: bool,
    /// Whether the required file or file group is present.
    pub present: bool,
}

/// Summarizes the generated-server doctor result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// Project root inspected by the doctor.
    pub root: PathBuf,
    /// Inferred generated-server shape.
    pub shape: DoctorShape,
    /// File and contract checks performed.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Returns true when every required generated-server check passed.
    pub fn ready(&self) -> bool {
        self.checks
            .iter()
            .all(|check| !check.required || check.present)
    }

    /// Renders the report for terminal output.
    pub fn render(&self) -> String {
        let mut output = String::new();

        output.push_str("mcp-toolkit doctor\n");
        output.push_str(&format!("Project: {}\n", self.root.display()));
        output.push_str(&format!("Shape: {}\n", self.shape.as_str()));
        output.push_str(&format!(
            "Ready: {}\n",
            if self.ready() { "yes" } else { "no" }
        ));
        output.push('\n');
        output.push_str("Checks:\n");

        for check in &self.checks {
            let status = if check.present { "ok" } else { "missing" };
            output.push_str(&format!("  [{status}] {} ({})\n", check.label, check.path));
        }

        output.push('\n');
        output.push_str("Next:\n");
        output.push_str(&format!("  cd {}\n", self.root.display()));
        output.push_str("  cargo fmt --all --check\n");
        output.push_str("  cargo test --all-targets --all-features\n");
        output.push_str("  cargo run -- --print-tools\n");
        output.push_str("  cargo run -- --print-tool-schema\n");

        if self.shape == DoctorShape::HostedHttpAuth {
            output.push_str("  cargo run -- --help\n");
        }

        output
    }
}

/// Inspects a generated Rust MCP server directory.
///
/// The check is intentionally static: it verifies the files that make the
/// scaffold reviewable before any build, test, or provider login step runs.
pub fn inspect_project(root: impl AsRef<Path>) -> DoctorReport {
    let root = root.as_ref().to_path_buf();
    let shape = infer_shape(&root);
    let mut checks = Vec::with_capacity(REQUIRED_FILES.len() + 2);

    for (label, path) in REQUIRED_FILES {
        checks.push(file_check(&root, label, path));
    }

    checks.push(DoctorCheck {
        label: "Transport contract and probe",
        path: TRANSPORT_PROOF_PATH.to_string(),
        required: true,
        present: has_stdio_proof(&root) || has_http_auth_proof(&root),
    });

    DoctorReport {
        root,
        shape,
        checks,
    }
}

fn infer_shape(root: &Path) -> DoctorShape {
    if has_http_auth_proof(root) {
        DoctorShape::HostedHttpAuth
    } else if has_stdio_proof(root) && exists(root, PUBLIC_GOVERNANCE_SCRIPT) {
        DoctorShape::PublicStdio
    } else if has_stdio_proof(root) {
        DoctorShape::Stdio
    } else {
        DoctorShape::Unknown
    }
}

fn has_stdio_proof(root: &Path) -> bool {
    exists(root, STDIO_CONTRACT_TEST) && exists(root, STDIO_PROBE_SCENARIO)
}

fn has_http_auth_proof(root: &Path) -> bool {
    exists(root, HTTP_AUTH_CONTRACT_TEST) && exists(root, HTTP_AUTH_PROBE_SCENARIO)
}

fn file_check(root: &Path, label: &'static str, path: &'static str) -> DoctorCheck {
    DoctorCheck {
        label,
        path: path.to_string(),
        required: true,
        present: exists(root, path),
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

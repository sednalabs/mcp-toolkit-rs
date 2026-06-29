use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn template_root() -> PathBuf {
    repo_root().join("templates/single-crate-public-stdio-server")
}

fn assert_relative_path_exists(root: &Path, relative: &str) {
    assert!(
        root.join(relative).exists(),
        "expected template path to exist: {relative}"
    );
}

#[test]
fn standalone_public_template_includes_required_repo_files() {
    let root = template_root();
    for relative in [
        "Cargo.toml",
        "README.md",
        "LICENSE",
        ".gitignore",
        "deny.toml",
        "docs/dependency-governance.md",
        "scripts/dependency_governance_check.sh",
        "scripts/rebaseline_tool_schema_snapshot.sh",
        ".github/workflows/rust-baseline.yml",
        ".github/workflows/code-coverage.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/codeql-query-tests.yml",
        ".github/workflows/dependency-governance.yml",
        ".github/codeql/codeql-rust.yml",
        ".github/codeql/actions-workflow-security/qlpack.yml",
        ".github/codeql/actions-workflow-security/suites/actions-workflow-security.qls",
        "spec/tool_schema_snapshot.v1.json",
        "tests/stdio_smoke.rs",
    ] {
        assert_relative_path_exists(&root, relative);
    }
}

#[test]
fn standalone_public_template_workflows_reference_local_paths_only() {
    let root = template_root();

    let dependency_governance =
        std::fs::read_to_string(root.join(".github/workflows/dependency-governance.yml"))
            .expect("dependency-governance workflow");
    for referenced in [
        "scripts/dependency_governance_check.sh",
        "scripts/rmcp_macro_runtime_pin_check.py",
        "docs/dependency-governance.md",
        "deny.toml",
    ] {
        assert!(
            dependency_governance.contains(referenced),
            "dependency-governance workflow is missing reference `{referenced}`"
        );
        assert_relative_path_exists(&root, referenced);
    }

    let codeql = std::fs::read_to_string(root.join(".github/workflows/codeql.yml"))
        .expect("codeql workflow");
    for referenced in [
        "Cargo.toml",
        ".github/codeql/codeql-rust.yml",
        ".github/codeql/actions-workflow-security",
    ] {
        assert!(
            codeql.contains(referenced),
            "codeql workflow is missing reference `{referenced}`"
        );
        assert_relative_path_exists(&root, referenced);
    }

    let query_tests =
        std::fs::read_to_string(root.join(".github/workflows/codeql-query-tests.yml"))
            .expect("codeql-query-tests workflow");
    assert!(query_tests.contains(".github/codeql/actions-workflow-security"));
    assert_relative_path_exists(
        &root,
        ".github/codeql/actions-workflow-security/suites/actions-workflow-security.qls",
    );
}

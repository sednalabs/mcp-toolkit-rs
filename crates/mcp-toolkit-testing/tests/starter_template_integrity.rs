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

fn named_template_root(name: &str) -> PathBuf {
    repo_root().join("templates").join(name)
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

#[test]
fn starter_templates_source_rmcp_through_mcp_toolkit() {
    for template in [
        "single-crate-public-stdio-server",
        "curated-stdio-intent-server",
        "hosted-http-auth-server",
    ] {
        let root = named_template_root(template);
        let cargo_toml =
            std::fs::read_to_string(root.join("Cargo.toml")).expect("template Cargo.toml");
        assert!(
            !manifest_declares_dependency(&cargo_toml, "rmcp"),
            "{template} should not declare a direct rmcp dependency"
        );
        assert!(
            !manifest_declares_dependency(&cargo_toml, "rmcp-macros"),
            "{template} should not declare a direct rmcp-macros dependency"
        );

        let lib_rs = std::fs::read_to_string(root.join("src/lib.rs")).expect("template lib.rs");
        assert!(
            lib_rs.contains("mcp_toolkit::rmcp"),
            "{template} should import the server authoring surface through mcp_toolkit::rmcp"
        );
    }
}

fn manifest_declares_dependency(manifest: &str, dependency_name: &str) -> bool {
    let mut in_dependency_section = false;

    for line in manifest.lines() {
        let trimmed = line.split('#').next().unwrap_or_default().trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = &trimmed[1..trimmed.len() - 1];
            in_dependency_section = matches!(
                section,
                "dependencies" | "dev-dependencies" | "build-dependencies"
            );
            continue;
        }

        if !in_dependency_section {
            continue;
        }

        if let Some((declared_name, _)) = trimmed.split_once('=')
            && declared_name.trim() == dependency_name
        {
            return true;
        }
    }

    false
}

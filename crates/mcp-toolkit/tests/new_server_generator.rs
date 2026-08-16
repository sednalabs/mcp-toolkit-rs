use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_toolkit::new_server::{
    default_toolkit_root, generate_new_server, templates, NewServerOptions, ToolkitDependencySource,
};
use mcp_toolkit::release_preflight::inspect_release_preflight;

#[test]
fn generator_creates_curated_stdio_project() {
    let root = temp_root("curated");
    let output = root.join("example-mcp");

    let summary = generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate curated template");

    assert!(
        summary.created_files >= 11,
        "expected generated curated template to create at least 11 files, got {}",
        summary.created_files
    );
    assert!(output.join("Cargo.toml").exists());
    assert!(output.join(".github/workflows/rust-baseline.yml").exists());
    assert!(output.join("tests/catalog_profile_contract.rs").exists());
    assert!(output.join("spec/mcp_probe_stdio_smoke.v1.json").exists());

    let manifest = read(&output.join("Cargo.toml"));
    assert!(manifest.contains("name = \"example-mcp\""));
    assert!(manifest.contains("git = \"https://github.com/sednalabs/mcp-toolkit-rs\""));
    assert!(!manifest.contains("../../crates/mcp-toolkit"));

    let smoke = read(&output.join("tests/stdio_smoke.rs"));
    assert!(smoke.contains("CARGO_BIN_EXE_example-mcp"));

    let profile_contract = read(&output.join("tests/catalog_profile_contract.rs"));
    assert!(profile_contract.contains("use example_mcp::{IntentServer, IntentServerConfig};"));
    assert!(!profile_contract.contains("curated_stdio_intent_server"));

    let probe_scenario = read(&output.join("spec/mcp_probe_stdio_smoke.v1.json"));
    assert!(probe_scenario.contains("example-mcp brief for probe"));
    assert!(!probe_scenario.contains("curated-stdio-intent-server"));

    let main = read(&output.join("src/main.rs"));
    assert!(main.contains("use example_mcp::"));
    assert!(!main.contains("curated_stdio_intent_server"));

    let readme = read(&output.join("README.md"));
    assert!(readme.contains("--manifest-path Cargo.toml"));
    assert!(!readme.contains("templates/example-mcp/Cargo.toml"));
    assert!(!readme.contains("templates/curated-stdio-intent-server/Cargo.toml"));

    cleanup(root);
}

#[test]
fn generator_emits_contract_and_probe_artifacts_for_every_template() {
    let root = temp_root("all-template-contracts");
    let canonical_runner_policy =
        read(&default_toolkit_root().join("scripts/workflow_runner_policy_check.py"));

    for template in templates() {
        let package_name = format!("{}-generated", template.id);
        let output = root.join(&package_name);

        generate_new_server(&NewServerOptions {
            template: template.id.to_string(),
            package_name: package_name.clone(),
            output_dir: output.clone(),
            toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
            overwrite: false,
        })
        .unwrap_or_else(|error| panic!("generate template {}: {error}", template.id));

        assert!(
            output.join("tests/catalog_profile_contract.rs").exists(),
            "{} should include catalog profile contract tests",
            template.id
        );
        assert!(
            output.join("tests/tool_schema_snapshot.rs").exists(),
            "{} should include tool schema snapshot tests",
            template.id
        );
        assert_eq!(
            read(&output.join("scripts/workflow_runner_policy_check.py")),
            canonical_runner_policy,
            "{} should emit the canonical workflow runner policy helper",
            template.id
        );

        if template.id == "hosted-http-auth" {
            assert!(
                output.join("tests/http_auth_contract.rs").exists(),
                "{} should include HTTP auth contract tests",
                template.id
            );
            assert!(
                output
                    .join("spec/mcp_probe_http_auth_smoke.v1.json")
                    .exists(),
                "{} should include an HTTP auth probe scenario",
                template.id
            );
        } else {
            assert!(
                output.join("tests/stdio_smoke.rs").exists(),
                "{} should include stdio smoke tests",
                template.id
            );
            assert!(
                output.join("spec/mcp_probe_stdio_smoke.v1.json").exists(),
                "{} should include a stdio probe scenario",
                template.id
            );
        }

        if template.id == "single-crate-public-stdio" {
            assert!(
                output
                    .join(".github/workflows/native-release-artifacts.yml")
                    .exists(),
                "{} should include the native release artifact workflow",
                template.id
            );
            assert!(
                output.join("scripts/native_release_artifact.py").exists(),
                "{} should include the native release verifier",
                template.id
            );
            let workflow = read(&output.join(".github/workflows/native-release-artifacts.yml"));
            assert!(workflow.contains("BINARY_NAME: single-crate-public-stdio-generated"));
            assert!(!workflow.contains("single-crate-public-stdio-server"));
        }
    }

    cleanup(root);
}

#[test]
fn doctor_accepts_generated_templates() {
    let root = temp_root("doctor-generated");

    for template in templates() {
        let package_name = format!("{}-generated", template.id);
        let output = root.join(&package_name);

        generate_new_server(&NewServerOptions {
            template: template.id.to_string(),
            package_name,
            output_dir: output.clone(),
            toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
            overwrite: false,
        })
        .unwrap_or_else(|error| panic!("generate template {}: {error}", template.id));

        let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
            .arg("doctor")
            .arg(&output)
            .output()
            .unwrap_or_else(|error| panic!("run doctor for {}: {error}", template.id));

        assert!(
            doctor.status.success(),
            "doctor failed for template {} with {}\nstdout:\n{}\nstderr:\n{}",
            template.id,
            doctor.status,
            String::from_utf8_lossy(&doctor.stdout),
            String::from_utf8_lossy(&doctor.stderr)
        );

        let stdout = String::from_utf8_lossy(&doctor.stdout);
        assert!(stdout.contains("Ready: yes"));
        assert!(stdout.contains("Tool schema snapshot"));
        assert!(stdout.contains("cargo run -- --doctor"));
        assert!(stdout.contains("cargo run -- --print-tools"));
        assert!(stdout.contains("cargo run -- --print-tool-schema"));
        assert!(stdout.contains("cargo run -- --print-client-config"));
        assert!(stdout.contains("mcp-toolkit client-config"));
    }

    cleanup(root);
}

#[test]
fn release_preflight_accepts_public_stdio_generated_project() {
    let root = temp_root("release-preflight-public");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");
    add_lockfile(&output);

    let report = inspect_release_preflight(&output);
    assert!(report.ready(), "public template should be release-ready");

    let preflight = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("release-preflight")
        .arg(&output)
        .output()
        .expect("run release-preflight for public template");

    assert!(
        preflight.status.success(),
        "release-preflight failed for public template with {}\nstdout:\n{}\nstderr:\n{}",
        preflight.status,
        String::from_utf8_lossy(&preflight.stdout),
        String::from_utf8_lossy(&preflight.stderr)
    );

    let stdout = String::from_utf8_lossy(&preflight.stdout);
    assert!(stdout.contains("Public ready: yes"));
    assert!(stdout.contains("CodeQL workflow"));
    assert!(stdout.contains("Dependency governance workflow"));
    assert!(stdout.contains("Native Linux release workflow"));
    assert!(stdout.contains("Native Linux release contract"));
    assert!(stdout.contains("Portable toolkit dependencies"));
    assert!(stdout.contains("High-confidence secret marker scan"));

    cleanup(root);
}

#[test]
fn release_preflight_rejects_incomplete_native_release_semantics() {
    let root = temp_root("release-preflight-native-contract");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path)
        .replace("cargo build --release --locked", "cargo build --release")
        .replace(
            "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
            "actions/attest-build-provenance@main",
        );
    fs::write(&workflow_path, workflow).expect("weaken native release workflow fixture");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(contract.detail.contains("cargo build --release --locked"));
    assert!(!report.ready());

    cleanup(root);
}

#[test]
fn release_preflight_rejects_unpinned_native_release_actions() {
    let root = temp_root("release-preflight-native-action-pin");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path).replace(
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "actions/attest-build-provenance@main",
    );
    fs::write(&workflow_path, workflow).expect("weaken native action pin fixture");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(contract.detail.contains("not pinned"));
    assert!(!report.ready());

    cleanup(root);
}

#[test]
fn release_preflight_rejects_folded_unpinned_native_release_actions() {
    let root = temp_root("release-preflight-native-folded-action-pin");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path).replace(
        "uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "uses: >-\n          actions/attest-build-provenance@main",
    );
    fs::write(&workflow_path, workflow).expect("fold unpinned action fixture");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(
        contract.detail.contains("not pinned"),
        "{}",
        contract.detail
    );

    cleanup(root);
}

#[test]
fn release_preflight_rejects_inert_release_semantics() {
    let root = temp_root("release-preflight-native-inert-semantics");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path).replace(
        "run: cargo build --release --locked --target \"$TARGET\" --bin \"$BINARY_NAME\"",
        "run: |\n          # cargo build --release --locked\n          echo 'cargo build --release --locked'",
    );
    fs::write(&workflow_path, workflow).expect("replace active build with inert comment");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(
        contract.detail.contains("cargo build --release --locked"),
        "{}",
        contract.detail
    );

    cleanup(root);
}

#[test]
fn release_preflight_rejects_untrusted_release_authority() {
    let root = temp_root("release-preflight-native-untrusted-authority");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path)
        .replace("  push:\n", "  pull_request:\n  push:\n")
        .replace(
            "  build-native-linux:\n",
            "  build-native-linux:\n    permissions:\n      id-token: write\n      contents: read\n",
        );
    fs::write(&workflow_path, workflow).expect("grant untrusted release authority");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(contract.detail.contains("trusted push events"));
    assert!(contract.detail.contains("read-only permissions"));

    cleanup(root);
}

#[test]
fn release_preflight_rejects_extra_privileged_release_job() {
    let root = temp_root("release-preflight-native-extra-job");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path).replace(
        "jobs:\n",
        "jobs:\n  unreviewed-privileged-job:\n    runs-on: ubuntu-24.04\n    permissions:\n      id-token: write\n      contents: read\n    steps:\n      - run: echo unexpected\n\n",
    );
    fs::write(&workflow_path, workflow).expect("add extra privileged release job");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(
        contract.detail.contains("must contain only"),
        "{}",
        contract.detail
    );

    cleanup(root);
}

#[test]
fn release_preflight_rejects_unexpected_release_runner() {
    let root = temp_root("release-preflight-native-runner");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path).replace(
        "  verify-native-linux:\n    name: Verify cross-architecture release contract\n    needs: build-native-linux\n    runs-on: ubuntu-24.04",
        "  verify-native-linux:\n    name: Verify cross-architecture release contract\n    needs: build-native-linux\n    runs-on: self-hosted",
    );
    fs::write(&workflow_path, workflow).expect("change verifier runner");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(
        contract.detail.contains("runner labels"),
        "{}",
        contract.detail
    );

    cleanup(root);
}

#[test]
fn release_preflight_rejects_every_native_architecture_matrix_shape_drift() {
    let root = temp_root("release-preflight-native-matrix-shape");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let canonical = read(&workflow_path);
    let include_rows = concat!(
        "        include:\n",
        "          - runner: ubuntu-24.04\n",
        "            target: x86_64-unknown-linux-gnu\n",
        "          - runner: ubuntu-24.04-arm\n",
        "            target: aarch64-unknown-linux-gnu\n",
    );
    let cases = vec![
        (
            "runs-on expression drift",
            replace_once(
                &canonical,
                "    runs-on: ${{ matrix.runner }}\n",
                "    runs-on: ${{ matrix.os }}\n",
                "runs-on expression drift",
            ),
        ),
        (
            "self-hosted extra runner dimension",
            replace_once(
                &canonical,
                include_rows,
                &format!(
                    "{include_rows}        runner: [ubuntu-24.04, self-hosted]\n"
                ),
                "self-hosted extra runner dimension",
            ),
        ),
        (
            "extra target dimension",
            replace_once(
                &canonical,
                include_rows,
                &format!(
                    "{include_rows}        target: [x86_64-unknown-linux-gnu]\n"
                ),
                "extra target dimension",
            ),
        ),
        (
            "extra os dimension",
            replace_once(
                &canonical,
                include_rows,
                &format!("{include_rows}        os: [linux]\n"),
                "extra os dimension",
            ),
        ),
        (
            "matrix exclude",
            replace_once(
                &canonical,
                include_rows,
                &format!("{include_rows}        exclude: []\n"),
                "matrix exclude",
            ),
        ),
        (
            "unknown matrix key",
            replace_once(
                &canonical,
                include_rows,
                &format!("{include_rows}        unexpected: true\n"),
                "unknown matrix key",
            ),
        ),
        (
            "strategy max-parallel",
            replace_once(
                &canonical,
                "      fail-fast: false\n",
                "      fail-fast: false\n      max-parallel: 1\n",
                "strategy max-parallel",
            ),
        ),
        (
            "strategy unknown key",
            replace_once(
                &canonical,
                "      fail-fast: false\n",
                "      fail-fast: false\n      unexpected: true\n",
                "strategy unknown key",
            ),
        ),
        (
            "fail-fast drift",
            replace_once(
                &canonical,
                "      fail-fast: false\n",
                "      fail-fast: true\n",
                "fail-fast drift",
            ),
        ),
        (
            "missing matrix row",
            replace_once(
                &canonical,
                "          - runner: ubuntu-24.04-arm\n            target: aarch64-unknown-linux-gnu\n",
                "",
                "missing matrix row",
            ),
        ),
        (
            "extra matrix row",
            replace_once(
                &canonical,
                include_rows,
                &format!(
                    "{include_rows}          - runner: ubuntu-24.04\n            target: x86_64-unknown-linux-gnu\n"
                ),
                "extra matrix row",
            ),
        ),
        (
            "duplicate matrix row",
            replace_once(
                &canonical,
                include_rows,
                concat!(
                    "        include:\n",
                    "          - runner: ubuntu-24.04\n",
                    "            target: x86_64-unknown-linux-gnu\n",
                    "          - runner: ubuntu-24.04\n",
                    "            target: x86_64-unknown-linux-gnu\n",
                ),
                "duplicate matrix row",
            ),
        ),
        (
            "reordered matrix rows",
            replace_once(
                &canonical,
                include_rows,
                concat!(
                    "        include:\n",
                    "          - runner: ubuntu-24.04-arm\n",
                    "            target: aarch64-unknown-linux-gnu\n",
                    "          - runner: ubuntu-24.04\n",
                    "            target: x86_64-unknown-linux-gnu\n",
                ),
                "reordered matrix rows",
            ),
        ),
        (
            "matrix row extra key",
            replace_once(
                &canonical,
                "          - runner: ubuntu-24.04\n            target: x86_64-unknown-linux-gnu\n",
                "          - runner: ubuntu-24.04\n            target: x86_64-unknown-linux-gnu\n            unexpected: true\n",
                "matrix row extra key",
            ),
        ),
        (
            "matrix row missing key",
            replace_once(
                &canonical,
                "          - runner: ubuntu-24.04\n            target: x86_64-unknown-linux-gnu\n",
                "          - runner: ubuntu-24.04\n",
                "matrix row missing key",
            ),
        ),
        (
            "matrix row target drift",
            replace_once(
                &canonical,
                "            target: x86_64-unknown-linux-gnu\n",
                "            target: x86_64-unknown-linux-musl\n",
                "matrix row target drift",
            ),
        ),
    ];

    for (label, mutated) in cases {
        assert_native_release_contract_rejects(
            &output,
            &workflow_path,
            &canonical,
            label,
            mutated,
            "exact ordered x86_64 and arm64 matrix.include",
        );
    }

    cleanup(root);
}

#[test]
fn release_preflight_rejects_incomplete_tag_ancestry_proof() {
    let root = temp_root("release-preflight-native-tag-ancestry");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path)
        .replace("fetch-depth: 0", "fetch-depth: 1")
        .replace(
            "git fetch --force --no-tags origin +refs/heads/main:refs/remotes/origin/main",
            "echo skipped-main-fetch",
        );
    fs::write(&workflow_path, workflow).expect("weaken tag ancestry proof");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(
        contract.detail.contains("protected-main ancestry")
            || contract.detail.contains("complete history"),
        "{}",
        contract.detail
    );

    cleanup(root);
}

#[test]
fn release_preflight_rejects_attestation_before_consumer_verification() {
    let root = temp_root("release-preflight-native-attestation-order");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path).replace(
        "      - verify-native-linux\n",
        "      - build-native-linux\n",
    );
    fs::write(&workflow_path, workflow).expect("remove verification dependency");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed);
    assert!(
        contract
            .detail
            .contains("successful build and verification"),
        "{}",
        contract.detail
    );

    cleanup(root);
}

#[test]
fn release_preflight_rejects_generated_privileged_step_and_subject_drift() {
    let root = temp_root("release-preflight-generated-privileged-steps");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let canonical = read(&workflow_path);
    let attest_step = "      - name: Attest verified native archives, checksums, and report\n";
    let upload_step = "      - name: Upload attested release authorization receipt\n";
    let attest_uses =
        "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8\n";
    let reverify_run =
        "      - name: Reverify trusted consumer artifact set\n        shell: bash\n";
    let privileged_job = "  attest-native-linux:\n";

    let cases = vec![
        (
            "extra privileged run",
            replace_once(
                &canonical,
                attest_step,
                &format!(
                    "      - name: Unexpected privileged run\n        shell: bash\n        run: echo unexpected\n\n{attest_step}"
                ),
                "extra privileged run",
            ),
            "privileged step sequence",
        ),
        (
            "reordered privileged steps",
            swap_once(
                &canonical,
                attest_step,
                upload_step,
                "reordered privileged steps",
            ),
            "privileged step sequence",
        ),
        (
            "duplicated privileged step",
            replace_once(
                &canonical,
                attest_step,
                &format!(
                    "      - name: Reverify trusted consumer artifact set\n        shell: bash\n        run: echo duplicate\n\n{attest_step}"
                ),
                "duplicated privileged step",
            ),
            "privileged step sequence",
        ),
        (
            "unexpected action run key",
            replace_once(
                &canonical,
                attest_uses,
                &format!("{attest_uses}        run: echo unexpected\n"),
                "unexpected action run key",
            ),
            "unexpected keys",
        ),
        (
            "unexpected action shell key",
            replace_once(
                &canonical,
                attest_uses,
                &format!("{attest_uses}        shell: bash\n"),
                "unexpected action shell key",
            ),
            "unexpected keys",
        ),
        (
            "privileged action pin drift",
            replace_once(
                &canonical,
                attest_uses,
                "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd9\n",
                "privileged action pin drift",
            ),
            "not pinned to the exact contract",
        ),
        (
            "unexpected action input key",
            replace_once(
                &canonical,
                "          subject-path: |\n",
                "          unexpected: true\n          subject-path: |\n",
                "unexpected action input key",
            ),
            "subject-path",
        ),
        (
            "unexpected run env key",
            replace_once(
                &canonical,
                reverify_run,
                &format!("{reverify_run}        env:\n          UNEXPECTED: true\n"),
                "unexpected run env key",
            ),
            "only exact name, shell, and run keys",
        ),
        (
            "unexpected run with key",
            replace_once(
                &canonical,
                reverify_run,
                &format!("{reverify_run}        with:\n          unexpected: true\n"),
                "unexpected run with key",
            ),
            "only exact name, shell, and run keys",
        ),
        (
            "prepended privileged shell command",
            replace_once_after(
                &canonical,
                privileged_job,
                "        run: |\n          set -euo pipefail\n          git fetch --force --no-tags origin",
                "        run: |\n          echo prepended\n          set -euo pipefail\n          git fetch --force --no-tags origin",
                "prepended privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "appended privileged shell command",
            replace_once_after(
                &canonical,
                privileged_job,
                "            --output release-authorization.json\n\n      - name: Attest verified native archives",
                "            --output release-authorization.json\n          echo appended\n\n      - name: Attest verified native archives",
                "appended privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "injected privileged shell command",
            replace_once_after(
                &canonical,
                privileged_job,
                "          source_tree=$(git rev-parse HEAD^{tree})\n          x86_archive=",
                "          source_tree=$(git rev-parse HEAD^{tree})\n          echo injected\n          x86_archive=",
                "injected privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "replaced privileged shell command",
            replace_once_after(
                &canonical,
                privileged_job,
                "          cmp trusted-verification.json downloaded/native-release-verification.json\n",
                "          cp trusted-verification.json downloaded/native-release-verification.json\n",
                "replaced privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "mutated privileged required argument",
            replace_once_after(
                &canonical,
                privileged_job,
                "            --workflow-run-attempt \"$GITHUB_RUN_ATTEMPT\" \\\n",
                "            --workflow-run-attempt \"$GITHUB_RUN_NUMBER\" \\\n",
                "mutated privileged required argument",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "reordered privileged shell commands",
            replace_once_after(
                &canonical,
                privileged_job,
                "          cmp trusted-verification.json downloaded/native-release-verification.json\n          test \"$(find downloaded -maxdepth 1 -type f | wc -l)\" -eq 5\n",
                "          test \"$(find downloaded -maxdepth 1 -type f | wc -l)\" -eq 5\n          cmp trusted-verification.json downloaded/native-release-verification.json\n",
                "reordered privileged shell commands",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "privileged continuation whitespace trick",
            replace_once_after(
                &canonical,
                privileged_job,
                "            --candidate \"$GITHUB_SHA\" \\\n",
                "            --candidate \"$GITHUB_SHA\"\\\n",
                "privileged continuation whitespace trick",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "missing attestation subject",
            replace_once(
                &canonical,
                "            downloaded/*.tar.gz.sha256\n",
                "",
                "missing attestation subject",
            ),
            "subject-path",
        ),
        (
            "substituted attestation subject",
            replace_once(
                &canonical,
                "            downloaded/native-release-verification.json\n",
                "            downloaded/substituted-verification.json\n",
                "substituted attestation subject",
            ),
            "subject-path",
        ),
        (
            "extra attestation subject",
            replace_once(
                &canonical,
                "            release-authorization.json\n",
                "            release-authorization.json\n            downloaded/unexpected.json\n",
                "extra attestation subject",
            ),
            "subject-path",
        ),
        (
            "duplicated attestation subject",
            replace_once(
                &canonical,
                "            downloaded/*.tar.gz.sha256\n",
                "            downloaded/*.tar.gz.sha256\n            downloaded/*.tar.gz.sha256\n",
                "duplicated attestation subject",
            ),
            "subject-path",
        ),
        (
            "reordered attestation subjects",
            replace_once(
                &canonical,
                "            downloaded/*.tar.gz\n            downloaded/*.tar.gz.sha256\n",
                "            downloaded/*.tar.gz.sha256\n            downloaded/*.tar.gz\n",
                "reordered attestation subjects",
            ),
            "subject-path",
        ),
    ];

    for (label, mutated, expected_detail) in cases {
        assert_native_release_contract_rejects(
            &output,
            &workflow_path,
            &canonical,
            label,
            mutated,
            expected_detail,
        );
    }

    cleanup(root);
}

#[test]
fn release_preflight_rejects_weakened_native_template_attestation_wrapper() {
    let root = temp_root("release-preflight-native-template-attestation");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let wrapper_path = output.join(".github/workflows/native-stdio-release-template-attest.yml");
    let canonical_wrapper = read(
        &default_toolkit_root().join(".github/workflows/native-stdio-release-template-attest.yml"),
    );
    fs::write(&wrapper_path, &canonical_wrapper).expect("install canonical wrapper fixture");

    let canonical_report = inspect_release_preflight(&output);
    let canonical_contract = canonical_report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(canonical_contract.passed, "{}", canonical_contract.detail);

    let weakened_cases = [
        (
            "trigger",
            "on:\n  push:\n",
            "on:\n  workflow_dispatch:\n  push:\n",
            "triggered only by trusted push events",
        ),
        (
            "job graph",
            "jobs:\n",
            "jobs:\n  unexpected-job:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo unexpected\n\n",
            "must contain only proof and attestation jobs",
        ),
        (
            "dependency",
            "    needs: prove-native-template\n",
            "    needs: []\n",
            "depend on successful template proof",
        ),
        (
            "OIDC isolation",
            "      id-token: write\n",
            "      id-token: read\n",
            "isolate exact job-scoped OIDC",
        ),
        (
            "runner",
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: self-hosted\n",
            "exact GitHub-hosted runner label",
        ),
        (
            "action pin",
            "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
            "actions/attest-build-provenance@main",
            "not pinned",
        ),
        (
            "checkout custody",
            "          persist-credentials: false\n",
            "          persist-credentials: true\n",
            "exact permitted key/value contract",
        ),
        (
            "authorization path",
            "          python3 scripts/native_release_artifact.py authorize \\\n",
            "          echo skipped-authorization \\\n",
            "authorization path is missing active command",
        ),
    ];

    for (label, original, replacement, expected_detail) in weakened_cases {
        assert!(
            canonical_wrapper.contains(original),
            "canonical fixture is missing mutation anchor for {label}"
        );
        fs::write(
            &wrapper_path,
            canonical_wrapper.replacen(original, replacement, 1),
        )
        .unwrap_or_else(|error| panic!("write weakened {label} fixture: {error}"));
        let report = inspect_release_preflight(&output);
        let contract = report
            .checks
            .iter()
            .find(|check| check.label == "Native Linux release contract")
            .expect("native release contract check");
        assert!(!contract.passed, "{label} weakening should fail preflight");
        assert!(
            contract.detail.contains(expected_detail),
            "{label} weakening produced unexpected detail: {}",
            contract.detail
        );
    }

    let attest_step = "      - name: Attest verified template archives, checksums, and report\n";
    let upload_step = "      - name: Upload attested template authorization receipt\n";
    let attest_uses =
        "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8\n";
    let reverify_run =
        "      - name: Reverify trusted consumer artifact set\n        shell: bash\n";
    let privileged_job = "  attest-native-template:\n";
    let structural_cases = vec![
        (
            "root extra privileged run",
            replace_once(
                &canonical_wrapper,
                attest_step,
                &format!(
                    "      - name: Unexpected privileged run\n        shell: bash\n        run: echo unexpected\n\n{attest_step}"
                ),
                "root extra privileged run",
            ),
            "privileged step sequence",
        ),
        (
            "root reordered privileged steps",
            swap_once(
                &canonical_wrapper,
                attest_step,
                upload_step,
                "root reordered privileged steps",
            ),
            "privileged step sequence",
        ),
        (
            "root duplicated privileged step",
            replace_once(
                &canonical_wrapper,
                attest_step,
                &format!(
                    "      - name: Reverify trusted consumer artifact set\n        shell: bash\n        run: echo duplicate\n\n{attest_step}"
                ),
                "root duplicated privileged step",
            ),
            "privileged step sequence",
        ),
        (
            "root unexpected action run key",
            replace_once(
                &canonical_wrapper,
                attest_uses,
                &format!("{attest_uses}        run: echo unexpected\n"),
                "root unexpected action run key",
            ),
            "unexpected keys",
        ),
        (
            "root unexpected action shell key",
            replace_once(
                &canonical_wrapper,
                attest_uses,
                &format!("{attest_uses}        shell: bash\n"),
                "root unexpected action shell key",
            ),
            "unexpected keys",
        ),
        (
            "root privileged action pin drift",
            replace_once(
                &canonical_wrapper,
                attest_uses,
                "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd9\n",
                "root privileged action pin drift",
            ),
            "not pinned to the exact contract",
        ),
        (
            "root unexpected action input key",
            replace_once(
                &canonical_wrapper,
                "          subject-path: |\n",
                "          unexpected: true\n          subject-path: |\n",
                "root unexpected action input key",
            ),
            "subject-path",
        ),
        (
            "root unexpected run env key",
            replace_once(
                &canonical_wrapper,
                reverify_run,
                &format!("{reverify_run}        env:\n          UNEXPECTED: true\n"),
                "root unexpected run env key",
            ),
            "only exact name, shell, and run keys",
        ),
        (
            "root unexpected run with key",
            replace_once(
                &canonical_wrapper,
                reverify_run,
                &format!("{reverify_run}        with:\n          unexpected: true\n"),
                "root unexpected run with key",
            ),
            "only exact name, shell, and run keys",
        ),
        (
            "root prepended privileged shell command",
            replace_once_after(
                &canonical_wrapper,
                privileged_job,
                "        run: |\n          set -euo pipefail\n          git fetch --force --no-tags origin",
                "        run: |\n          echo prepended\n          set -euo pipefail\n          git fetch --force --no-tags origin",
                "root prepended privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "root appended privileged shell command",
            replace_once_after(
                &canonical_wrapper,
                privileged_job,
                "            --output release-authorization.json\n\n      - name: Attest verified template archives",
                "            --output release-authorization.json\n          echo appended\n\n      - name: Attest verified template archives",
                "root appended privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "root injected privileged shell command",
            replace_once_after(
                &canonical_wrapper,
                privileged_job,
                "          source_tree=$(git rev-parse HEAD^{tree})\n          x86_archive=",
                "          source_tree=$(git rev-parse HEAD^{tree})\n          echo injected\n          x86_archive=",
                "root injected privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "root replaced privileged shell command",
            replace_once_after(
                &canonical_wrapper,
                privileged_job,
                "          cmp trusted-template-verification.json downloaded/native-template-verification.json\n",
                "          cp trusted-template-verification.json downloaded/native-template-verification.json\n",
                "root replaced privileged shell command",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "root mutated privileged required argument",
            replace_once_after(
                &canonical_wrapper,
                privileged_job,
                "            --workflow-run-attempt \"$GITHUB_RUN_ATTEMPT\" \\\n",
                "            --workflow-run-attempt \"$GITHUB_RUN_NUMBER\" \\\n",
                "root mutated privileged required argument",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "root reordered privileged shell commands",
            replace_once_after(
                &canonical_wrapper,
                privileged_job,
                "          cmp trusted-template-verification.json downloaded/native-template-verification.json\n          test \"$(find downloaded -maxdepth 1 -type f | wc -l)\" -eq 5\n",
                "          test \"$(find downloaded -maxdepth 1 -type f | wc -l)\" -eq 5\n          cmp trusted-template-verification.json downloaded/native-template-verification.json\n",
                "root reordered privileged shell commands",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "root privileged continuation whitespace trick",
            replace_once_after(
                &canonical_wrapper,
                privileged_job,
                "            --candidate \"$GITHUB_SHA\" \\\n",
                "            --candidate \"$GITHUB_SHA\"\\\n",
                "root privileged continuation whitespace trick",
            ),
            "run body must match the exact canonical command body",
        ),
        (
            "root missing attestation subject",
            replace_once(
                &canonical_wrapper,
                "            downloaded/*.tar.gz.sha256\n",
                "",
                "root missing attestation subject",
            ),
            "subject-path",
        ),
        (
            "root substituted attestation subject",
            replace_once(
                &canonical_wrapper,
                "            downloaded/native-template-verification.json\n",
                "            downloaded/substituted-verification.json\n",
                "root substituted attestation subject",
            ),
            "subject-path",
        ),
        (
            "root extra attestation subject",
            replace_once(
                &canonical_wrapper,
                "            release-authorization.json\n",
                "            release-authorization.json\n            downloaded/unexpected.json\n",
                "root extra attestation subject",
            ),
            "subject-path",
        ),
        (
            "root duplicated attestation subject",
            replace_once(
                &canonical_wrapper,
                "            downloaded/*.tar.gz.sha256\n",
                "            downloaded/*.tar.gz.sha256\n            downloaded/*.tar.gz.sha256\n",
                "root duplicated attestation subject",
            ),
            "subject-path",
        ),
        (
            "root reordered attestation subjects",
            replace_once(
                &canonical_wrapper,
                "            downloaded/*.tar.gz\n            downloaded/*.tar.gz.sha256\n",
                "            downloaded/*.tar.gz.sha256\n            downloaded/*.tar.gz\n",
                "root reordered attestation subjects",
            ),
            "subject-path",
        ),
    ];

    for (label, mutated, expected_detail) in structural_cases {
        assert_native_release_contract_rejects(
            &output,
            &wrapper_path,
            &canonical_wrapper,
            label,
            mutated,
            expected_detail,
        );
    }

    cleanup(root);
}

#[test]
fn release_preflight_accepts_local_native_release_actions() {
    let root = temp_root("release-preflight-native-local-action");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");
    add_lockfile(&output);

    let workflow_path = output.join(".github/workflows/native-release-artifacts.yml");
    let workflow = read(&workflow_path).replacen(
        "    steps:\n",
        "    steps:\n      - uses: ./.github/actions/release-setup\n",
        1,
    );
    fs::write(&workflow_path, workflow).expect("add local action fixture");

    let report = inspect_release_preflight(&output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(contract.passed, "{}", contract.detail);
    assert!(report.ready());

    cleanup(root);
}

#[test]
fn release_preflight_rejects_public_project_with_local_toolkit_paths() {
    let root = temp_root("release-preflight-local-paths");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let report = inspect_release_preflight(&output);
    assert!(
        !report.ready(),
        "local toolkit path dependencies should not be public-ready"
    );

    let preflight = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("release-preflight")
        .arg(&output)
        .output()
        .expect("run release-preflight for local-path public template");

    assert!(!preflight.status.success());
    let stdout = String::from_utf8_lossy(&preflight.stdout);
    assert!(stdout.contains("Public ready: no"));
    assert!(stdout.contains("[missing] Portable toolkit dependencies (Cargo.toml)"));
    assert!(stdout.contains("replace local toolkit path dependencies with `--toolkit-git`"));

    cleanup(root);
}

#[test]
fn release_preflight_rejects_multiline_and_renamed_local_toolkit_paths() {
    let root = temp_root("release-preflight-local-path-forms");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let manifest_path = output.join("Cargo.toml");
    let manifest = read(&manifest_path)
        .replace(
            "mcp-toolkit = { git = \"https://github.com/sednalabs/mcp-toolkit-rs\", features = [\"server-stdio\"] }",
            "mcp-toolkit = {\n  path = \"../mcp-toolkit\",\n  features = [\"server-stdio\"],\n}",
        )
        .replace(
            "mcp-toolkit-core = { git = \"https://github.com/sednalabs/mcp-toolkit-rs\" }",
            "toolkit_core = { package = \"mcp-toolkit-core\", path = \"../mcp-toolkit-core\" }",
        );
    fs::write(&manifest_path, manifest).expect("write local toolkit dependency forms");

    let report = inspect_release_preflight(&output);
    assert!(
        !report.ready(),
        "multiline or renamed local toolkit dependencies should not be public-ready"
    );
    let dependency_check = report
        .checks
        .iter()
        .find(|check| check.label == "Portable toolkit dependencies")
        .expect("portable dependency check");
    assert!(dependency_check.detail.contains("mcp-toolkit"));
    assert!(dependency_check.detail.contains("toolkit_core"));

    cleanup(root);
}

#[test]
fn release_preflight_rejects_cargo_local_toolkit_overrides() {
    let root = temp_root("release-preflight-cargo-overrides");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let manifest_path = output.join("Cargo.toml");
    let mut manifest = read(&manifest_path);
    manifest.push_str(
        r#"
[patch.crates-io]
mcp-toolkit-testing = { path = "../mcp-toolkit-testing" }

[replace]
"mcp-toolkit-core:0.1.0" = { path = "../mcp-toolkit-core" }
"#,
    );
    fs::write(&manifest_path, manifest).expect("write local Cargo overrides");

    let report = inspect_release_preflight(&output);
    assert!(
        !report.ready(),
        "local Cargo toolkit overrides should not be public-ready"
    );
    let dependency_check = report
        .checks
        .iter()
        .find(|check| check.label == "Portable toolkit dependencies")
        .expect("portable dependency check");
    assert!(dependency_check.detail.contains("mcp-toolkit-testing"));
    assert!(dependency_check.detail.contains("mcp-toolkit-core"));

    cleanup(root);
}

#[test]
fn release_preflight_rejects_committed_cargo_path_overrides() {
    let root = temp_root("release-preflight-cargo-config");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let cargo_config = output.join(".cargo/config.toml");
    fs::create_dir_all(cargo_config.parent().expect("cargo config parent"))
        .expect("create .cargo directory");
    fs::write(
        &cargo_config,
        "paths = [\"../mcp-toolkit-rs/crates/mcp-toolkit-core\"]\n",
    )
    .expect("write Cargo path override");

    let report = inspect_release_preflight(&output);
    assert!(
        !report.ready(),
        "committed Cargo path overrides should not be public-ready"
    );
    let override_check = report
        .checks
        .iter()
        .find(|check| check.label == "Cargo local path overrides")
        .expect("Cargo local path override check");
    assert!(override_check.detail.contains("paths"));

    cleanup(root);
}

#[test]
fn release_preflight_uses_hosted_http_probe_for_hosted_projects() {
    let root = temp_root("release-preflight-hosted");
    let output = root.join("hosted-mcp");

    generate_new_server(&NewServerOptions {
        template: "hosted-http-auth".to_string(),
        package_name: "hosted-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate hosted HTTP template");
    add_public_release_files(&output);
    add_manifest_description(&output);

    let report = inspect_release_preflight(&output);
    assert!(
        report.ready(),
        "hosted public project should satisfy release preflight with HTTP probe: {:#?}",
        report.checks
    );
    let probe_check = report
        .checks
        .iter()
        .find(|check| check.label == "MCP probe scenario")
        .expect("probe check");
    assert_eq!(probe_check.target, "spec/mcp_probe_http_auth_smoke.v1.json");

    fs::remove_file(output.join("spec/mcp_probe_http_auth_smoke.v1.json"))
        .expect("remove hosted HTTP probe");
    fs::write(output.join("spec/mcp_probe_stdio_smoke.v1.json"), "{}\n")
        .expect("write irrelevant stdio probe");

    let report = inspect_release_preflight(&output);
    assert!(
        !report.ready(),
        "hosted public project should require the HTTP auth probe"
    );
    assert_eq!(report.shape.as_str(), "unknown");

    cleanup(root);
}

#[test]
fn release_preflight_accepts_workspace_inherited_package_metadata() {
    let root = temp_root("release-preflight-workspace-metadata");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let manifest_path = output.join("Cargo.toml");
    let description_line = concat!(
        "description = \"Standalone public Rust MCP server starter with hosted CI, ",
        "governance, and dual-native Linux release artifacts.\""
    );
    let manifest = read(&manifest_path)
        .replace("license = \"Apache-2.0\"", "license.workspace = true")
        .replace(description_line, "description.workspace = true");
    fs::write(&manifest_path, manifest).expect("write workspace-inherited package metadata");
    add_lockfile(&output);

    let report = inspect_release_preflight(&output);
    assert!(
        report.ready(),
        "workspace-inherited metadata should satisfy release preflight: {:#?}",
        report.checks
    );

    cleanup(root);
}

#[test]
fn release_preflight_rejects_non_public_starter_until_public_files_exist() {
    let root = temp_root("release-preflight-curated");
    let output = root.join("example-mcp");

    generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate curated template");

    let preflight = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("release-preflight")
        .arg(&output)
        .output()
        .expect("run release-preflight for curated template");

    assert!(!preflight.status.success());

    let stdout = String::from_utf8_lossy(&preflight.stdout);
    assert!(stdout.contains("Public ready: no"));
    assert!(stdout.contains("[missing] License file (LICENSE)"));
    assert!(stdout.contains("[missing] CodeQL workflow (.github/workflows/codeql.yml)"));
    assert!(stdout.contains("[ok] Generated scaffold doctor"));

    let stderr = String::from_utf8_lossy(&preflight.stderr);
    assert!(stderr.contains("release-preflight found missing public-readiness requirements"));

    cleanup(root);
}

#[test]
fn release_preflight_rejects_high_confidence_secret_markers() {
    let root = temp_root("release-preflight-secret");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::Git(
            "https://github.com/sednalabs/mcp-toolkit-rs".to_string(),
        ),
        overwrite: false,
    })
    .expect("generate public stdio template");
    fs::write(
        output.join("docs/accidental-secret.md"),
        "do not publish: \"client_secret\": \"redacted-example\"\n",
    )
    .expect("write accidental secret marker");
    fs::write(
        output.join(".env.local"),
        "OPENAI_API_KEY=sk-proj-redacted\n",
    )
    .expect("write accidental env secret marker");
    fs::write(
        output.join("Dockerfile"),
        "ENV GOOGLE_TOKEN=ya29.redacted\n",
    )
    .expect("write accidental Dockerfile secret marker");
    fs::create_dir_all(output.join("node_modules/package"))
        .expect("create skipped node_modules tree");
    fs::write(
        output.join("node_modules/package/.env"),
        "IGNORED_CLIENT_SECRET=\"client_secret\"\n",
    )
    .expect("write skipped node_modules secret marker");

    let preflight = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("release-preflight")
        .arg(&output)
        .output()
        .expect("run release-preflight with secret marker");

    assert!(!preflight.status.success());

    let stdout = String::from_utf8_lossy(&preflight.stdout);
    assert!(stdout.contains("Public ready: no"));
    assert!(stdout.contains("[missing] High-confidence secret marker scan"));
    assert!(stdout.contains("JSON client secret in docs/accidental-secret.md"));
    assert!(stdout.contains("OpenAI project secret key in .env.local"));
    assert!(stdout.contains("Google OAuth access token in Dockerfile"));
    assert!(!stdout.contains("node_modules"));

    cleanup(root);
}

#[test]
fn generator_emits_project_local_doctor_and_client_config_commands_for_every_template() {
    let root = temp_root("all-template-local-commands");

    for template in templates() {
        let package_name = format!("{}-generated", template.id);
        let output = root.join(&package_name);

        generate_new_server(&NewServerOptions {
            template: template.id.to_string(),
            package_name,
            output_dir: output.clone(),
            toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
            overwrite: false,
        })
        .unwrap_or_else(|error| panic!("generate template {}: {error}", template.id));

        let main = read(&output.join("src/main.rs"));
        assert!(
            main.contains("ToolSurfaceCommand::Doctor"),
            "{} should expose a project-local doctor command",
            template.id
        );
        assert!(
            main.contains("ToolSurfaceCommand::PrintClientConfig"),
            "{} should expose a project-local client-config command",
            template.id
        );
        assert!(
            main.contains("inspect_project"),
            "{} should use the toolkit doctor helper",
            template.id
        );
        assert!(
            main.contains("render_client_config"),
            "{} should use the toolkit client-config helper",
            template.id
        );

        let readme = read(&output.join("README.md"));
        assert!(
            readme.contains("cargo run -- --doctor"),
            "{} should document the project-local doctor command",
            template.id
        );
        assert!(
            readme.contains("cargo run -- --print-client-config"),
            "{} should document the project-local client-config command",
            template.id
        );
    }

    cleanup(root);
}

#[test]
fn client_config_renders_stdio_generated_project() {
    let root = temp_root("client-config-stdio");
    let output = root.join("example-mcp");

    generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate curated template");

    let config_root = output.join("..").join("example-mcp");
    let config = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("client-config")
        .arg(&config_root)
        .output()
        .expect("run client-config for stdio generated project");

    assert!(
        config.status.success(),
        "client-config failed with {}\nstdout:\n{}\nstderr:\n{}",
        config.status,
        String::from_utf8_lossy(&config.stdout),
        String::from_utf8_lossy(&config.stderr)
    );

    let stdout = String::from_utf8_lossy(&config.stdout);
    let expected_command = output
        .canonicalize()
        .expect("canonical generated output")
        .join("target")
        .join("release")
        .join("example-mcp");
    assert!(stdout.contains("[mcp_servers.\"example-mcp\"]"));
    assert!(stdout.contains(&format!("command = \"{}\"", toml_path(&expected_command))));
    assert!(stdout.contains("args = []"));
    assert!(stdout.contains("[mcp_servers.\"example-mcp\".env]"));
    assert!(stdout.contains("EXAMPLE_MCP_TOOL_PROFILE = \"read_only\""));

    cleanup(root);
}

#[test]
fn client_config_renders_hosted_http_generated_project() {
    let root = temp_root("client-config-http");
    let output = root.join("example-http-mcp");

    generate_new_server(&NewServerOptions {
        template: "hosted-http-auth".to_string(),
        package_name: "example-http-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate hosted template");

    let config = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("client-config")
        .arg(&output)
        .output()
        .expect("run client-config for hosted generated project");

    assert!(
        config.status.success(),
        "client-config failed with {}\nstdout:\n{}\nstderr:\n{}",
        config.status,
        String::from_utf8_lossy(&config.stdout),
        String::from_utf8_lossy(&config.stderr)
    );

    let stdout = String::from_utf8_lossy(&config.stdout);
    assert!(stdout.contains("[mcp_servers.\"example-http-mcp\"]"));
    assert!(stdout.contains("url = \"http://127.0.0.1:9411/mcp\""));
    assert!(!stdout.contains("command ="));

    cleanup(root);
}

#[test]
fn client_config_supports_overrides() {
    let root = temp_root("client-config-overrides");
    let output = root.join("example-mcp");

    generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate curated template");

    let config = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("client-config")
        .arg(&output)
        .args([
            "--name",
            "workspace-example",
            "--transport",
            "stdio",
            "--command",
            "/opt/example/bin/example-mcp",
            "--profile",
            "operator",
        ])
        .output()
        .expect("run client-config with overrides");

    assert!(config.status.success());

    let stdout = String::from_utf8_lossy(&config.stdout);
    assert!(stdout.contains("[mcp_servers.\"workspace-example\"]"));
    assert!(stdout.contains("command = \"/opt/example/bin/example-mcp\""));
    assert!(stdout.contains("EXAMPLE_MCP_TOOL_PROFILE = \"operator\""));

    cleanup(root);
}

#[test]
fn client_config_reports_unknown_transport_without_override() {
    let root = temp_root("client-config-unknown");
    let empty = root.join("empty");
    fs::create_dir_all(&empty).expect("create empty directory");
    fs::write(
        empty.join("Cargo.toml"),
        "[ package ] # generated metadata\nname = 'empty' # comment\n",
    )
    .expect("write minimal manifest");

    let config = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("client-config")
        .arg(&empty)
        .output()
        .expect("run client-config for incomplete generated project");

    assert!(!config.status.success());

    let stderr = String::from_utf8_lossy(&config.stderr);
    assert!(stderr.contains("could not infer generated-server transport"));

    cleanup(root);
}

#[test]
fn doctor_reports_missing_generated_artifacts() {
    let root = temp_root("doctor-missing");
    let empty = root.join("empty");
    fs::create_dir_all(&empty).expect("create empty directory");

    let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("doctor")
        .arg(&empty)
        .output()
        .expect("run doctor for empty directory");

    assert!(!doctor.status.success());

    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(stdout.contains("Ready: no"));
    assert!(stdout.contains("[missing] Cargo manifest (Cargo.toml)"));
    assert!(stdout.contains("Shape: unknown"));

    let stderr = String::from_utf8_lossy(&doctor.stderr);
    assert!(stderr.contains("doctor found missing required generated-server files"));

    cleanup(root);
}

#[test]
fn doctor_rejects_missing_target_path() {
    let root = temp_root("doctor-missing-target");
    let missing = root.join("missing");

    let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("doctor")
        .arg(&missing)
        .output()
        .expect("run doctor for missing target");

    assert!(!doctor.status.success());
    assert!(doctor.stdout.is_empty());

    let stderr = String::from_utf8_lossy(&doctor.stderr);
    assert!(stderr.contains("doctor path"));
    assert!(stderr.contains("does not exist"));

    cleanup(root);
}

#[test]
fn doctor_rejects_file_target_path() {
    let root = temp_root("doctor-file-target");
    let target_file = root.join("Cargo.toml");
    fs::write(&target_file, "[package]\nname = \"not-a-directory\"\n").expect("write target file");

    let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("doctor")
        .arg(&target_file)
        .output()
        .expect("run doctor for file target");

    assert!(!doctor.status.success());
    assert!(doctor.stdout.is_empty());

    let stderr = String::from_utf8_lossy(&doctor.stderr);
    assert!(stderr.contains("doctor path"));
    assert!(stderr.contains("is not a directory"));

    cleanup(root);
}

#[test]
fn doctor_rejects_mismatched_transport_artifacts() {
    let root = temp_root("doctor-mismatch");
    let output = root.join("example-mcp");

    generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate curated template");

    fs::remove_file(output.join("spec/mcp_probe_stdio_smoke.v1.json"))
        .expect("remove stdio probe scenario");
    fs::write(
        output.join("spec/mcp_probe_http_auth_smoke.v1.json"),
        "{}\n",
    )
    .expect("write mismatched HTTP probe scenario");

    let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("doctor")
        .arg(&output)
        .output()
        .expect("run doctor for mismatched transport artifacts");

    assert!(!doctor.status.success());

    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(stdout.contains("Ready: no"));
    assert!(stdout.contains("[missing] Transport contract and probe"));
    assert!(stdout.contains("Shape: unknown"));

    cleanup(root);
}

#[cfg(unix)]
#[test]
fn doctor_rejects_symlinked_required_files() {
    use std::os::unix::fs::symlink;

    let root = temp_root("doctor-symlink");
    let output = root.join("example-mcp");

    generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate curated template");

    let external_manifest = root.join("external-Cargo.toml");
    fs::write(&external_manifest, "[package]\nname = \"external\"\n")
        .expect("write external manifest");
    fs::remove_file(output.join("Cargo.toml")).expect("remove generated manifest");
    symlink(&external_manifest, output.join("Cargo.toml")).expect("symlink generated manifest");

    let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("doctor")
        .arg(&output)
        .output()
        .expect("run doctor for symlinked required file");

    assert!(!doctor.status.success());

    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(stdout.contains("Ready: no"));
    assert!(stdout.contains("[missing] Cargo manifest (Cargo.toml)"));

    cleanup(root);
}

#[cfg(unix)]
#[test]
fn doctor_rejects_symlinked_required_directories() {
    use std::os::unix::fs::symlink;

    let root = temp_root("doctor-symlink-dir");
    let output = root.join("example-mcp");

    generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate curated template");

    let external_tests = root.join("external-tests");
    fs::create_dir_all(&external_tests).expect("create external tests directory");
    fs::write(external_tests.join("tool_schema_snapshot.rs"), "\n")
        .expect("write external snapshot test");
    fs::write(external_tests.join("catalog_profile_contract.rs"), "\n")
        .expect("write external profile contract test");
    fs::write(external_tests.join("stdio_smoke.rs"), "\n").expect("write external stdio test");
    fs::remove_dir_all(output.join("tests")).expect("remove generated tests directory");
    symlink(&external_tests, output.join("tests")).expect("symlink generated tests directory");

    let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .arg("doctor")
        .arg(&output)
        .output()
        .expect("run doctor for symlinked required directory");

    assert!(!doctor.status.success());

    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(stdout.contains("Ready: no"));
    assert!(stdout.contains("[missing] Tool schema snapshot test"));
    assert!(stdout.contains("[missing] Transport contract and probe"));

    cleanup(root);
}

#[test]
fn generator_is_idempotent_for_unchanged_files() {
    let root = temp_root("idempotent");
    let output = root.join("example-mcp");
    let options = NewServerOptions {
        template: "stdio".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output,
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    };

    let first = generate_new_server(&options).expect("first generation");
    let second = generate_new_server(&options).expect("second generation");

    assert_eq!(first.created_files, second.unchanged_files);
    assert_eq!(second.created_files, 0);
    assert_eq!(second.overwritten_files, 0);

    cleanup(root);
}

#[test]
fn generator_refuses_changed_files_without_force() {
    let root = temp_root("overwrite");
    let output = root.join("example-mcp");
    let options = NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    };

    generate_new_server(&options).expect("initial generation");
    fs::write(output.join("README.md"), "local edit\n").expect("write local edit");

    let error = generate_new_server(&options)
        .expect_err("changed file should require explicit overwrite")
        .to_string();
    assert!(error.contains("refusing to overwrite changed file"));

    cleanup(root);
}

#[cfg(unix)]
#[test]
fn generator_preserves_executable_template_scripts() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root("permissions");
    let output = root.join("public-mcp");

    generate_new_server(&NewServerOptions {
        template: "single-crate-public-stdio".to_string(),
        package_name: "public-mcp".to_string(),
        output_dir: output.clone(),
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect("generate public stdio template");

    let mode = fs::metadata(output.join("scripts/rebaseline_tool_schema_snapshot.sh"))
        .expect("script metadata")
        .permissions()
        .mode();
    assert_ne!(mode & 0o111, 0, "generated script should be executable");

    cleanup(root);
}

#[cfg(unix)]
#[test]
fn generator_refuses_symlink_output_directory() {
    use std::os::unix::fs::symlink;

    let root = temp_root("symlink-output");
    let external = root.join("external");
    let output = root.join("example-mcp");
    fs::create_dir_all(&external).expect("create external target");
    symlink(&external, &output).expect("create output symlink");

    let error = generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output,
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: false,
    })
    .expect_err("symlinked output directories should be rejected")
    .to_string();

    assert!(error.contains("refusing output directory through symlink"));
    assert!(!external.join("Cargo.toml").exists());

    cleanup(root);
}

#[cfg(unix)]
#[test]
fn generator_refuses_symlink_destination_files() {
    use std::os::unix::fs::symlink;

    let root = temp_root("symlink-file");
    let output = root.join("example-mcp");
    let external = root.join("external-readme.md");
    fs::create_dir_all(&output).expect("create output dir");
    fs::write(&external, "external\n").expect("write external file");
    symlink(&external, output.join("README.md")).expect("create file symlink");

    let error = generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output,
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: true,
    })
    .expect_err("symlinked generated files should be rejected")
    .to_string();

    assert!(error.contains("refusing to write generated file through symlink"));
    assert_eq!(read(&external), "external\n");

    cleanup(root);
}

#[cfg(unix)]
#[test]
fn generator_refuses_symlink_destination_directories() {
    use std::os::unix::fs::symlink;

    let root = temp_root("symlink-child-dir");
    let output = root.join("example-mcp");
    let external = root.join("external-src");
    fs::create_dir_all(&external).expect("create external target");
    fs::create_dir_all(&output).expect("create output dir");
    symlink(&external, output.join("src")).expect("create src symlink");

    let error = generate_new_server(&NewServerOptions {
        template: "curated-stdio-intent".to_string(),
        package_name: "example-mcp".to_string(),
        output_dir: output,
        toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
        overwrite: true,
    })
    .expect_err("symlinked generated directories should be rejected")
    .to_string();

    assert!(error.contains("refusing generated output path through symlink"));
    assert!(!external.join("main.rs").exists());

    cleanup(root);
}

#[cfg(unix)]
#[test]
fn cli_resolves_relative_toolkit_root_from_invocation_cwd() {
    use std::os::unix::fs::symlink;

    let root = temp_root("cli-toolkit-root");
    let work = root.join("work");
    let toolkit_link = root.join("toolkit-root");
    fs::create_dir_all(&work).expect("create invocation cwd");
    symlink(default_toolkit_root(), &toolkit_link).expect("create toolkit root symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-toolkit"))
        .current_dir(&work)
        .args([
            "new",
            "--name",
            "example-mcp",
            "--toolkit-root",
            "../toolkit-root",
        ])
        .output()
        .expect("run mcp-toolkit new");

    assert!(
        output.status.success(),
        "mcp-toolkit new failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest = read(&work.join("example-mcp/Cargo.toml"));
    let expected = default_toolkit_root().join("crates/mcp-toolkit");
    assert!(manifest.contains(&format!("path = \"{}\"", toml_path(&expected))));
    assert!(!manifest.contains("../toolkit-root"));

    cleanup(root);
}

fn temp_root(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path = PathBuf::from(format!(
        "target/mcp-toolkit-new-server-tests/{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn missing_fixture_anchor(kind: &str, label: &str) -> ! {
    std::panic::panic_any(["fixture is missing ", kind, " anchor for ", label].concat())
}

fn replace_once(contents: &str, original: &str, replacement: &str, label: &str) -> String {
    if !contents.contains(original) {
        missing_fixture_anchor("mutation", label);
    }
    contents.replacen(original, replacement, 1)
}

fn replace_once_after(
    contents: &str,
    section: &str,
    original: &str,
    replacement: &str,
    label: &str,
) -> String {
    let section_start = contents
        .find(section)
        .unwrap_or_else(|| missing_fixture_anchor("section", label));
    let search_start = section_start + section.len();
    let relative_start = contents[search_start..]
        .find(original)
        .unwrap_or_else(|| missing_fixture_anchor("mutation", label));
    let replacement_start = search_start + relative_start;
    let replacement_end = replacement_start + original.len();
    let mut mutated = contents.to_string();
    mutated.replace_range(replacement_start..replacement_end, replacement);
    mutated
}

fn swap_once(contents: &str, first: &str, second: &str, label: &str) -> String {
    let marker = "__MCP_TOOLKIT_PRIVILEGED_STEP_SWAP_MARKER__";
    assert!(!contents.contains(marker));
    let swapped = replace_once(contents, first, marker, label);
    let swapped = replace_once(&swapped, second, first, label);
    replace_once(&swapped, marker, second, label)
}

fn assert_native_release_contract_rejects(
    output: &Path,
    workflow_path: &Path,
    canonical: &str,
    label: &str,
    mutated: String,
    expected_detail: &str,
) {
    assert_ne!(
        canonical, mutated,
        "{label} mutation must change the fixture"
    );
    fs::write(workflow_path, mutated)
        .unwrap_or_else(|error| panic!("write weakened {label} fixture: {error}"));
    let report = inspect_release_preflight(output);
    let contract = report
        .checks
        .iter()
        .find(|check| check.label == "Native Linux release contract")
        .expect("native release contract check");
    assert!(!contract.passed, "{label} weakening should fail preflight");
    assert!(
        contract.detail.contains(expected_detail),
        "{label} weakening produced unexpected detail: {}",
        contract.detail
    );
}

fn cleanup(path: PathBuf) {
    let _ = fs::remove_dir_all(path);
}

fn add_public_release_files(output: &Path) {
    let public_template = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("templates/single-crate-public-stdio-server");
    for relative in [
        "LICENSE",
        "deny.toml",
        ".github/workflows/codeql.yml",
        ".github/workflows/code-coverage.yml",
        ".github/workflows/dependency-governance.yml",
        ".github/workflows/codeql-query-tests.yml",
        ".github/workflows/native-release-artifacts.yml",
        "scripts/dependency_governance_check.sh",
        "scripts/native_release_artifact.py",
        "docs/dependency-governance.md",
    ] {
        let target = output.join(relative);
        fs::create_dir_all(target.parent().expect("target parent")).expect("create parent");
        fs::copy(public_template.join(relative), target).expect("copy public release file");
    }
    add_lockfile(output);
}

fn add_lockfile(output: &Path) {
    fs::write(
        output.join("Cargo.lock"),
        "# generated for release preflight\nversion = 4\n",
    )
    .expect("write Cargo.lock fixture");
}

fn add_manifest_description(output: &Path) {
    let manifest_path = output.join("Cargo.toml");
    let manifest = read(&manifest_path);
    fs::write(
        &manifest_path,
        manifest.replace(
            "publish = false\n",
            "publish = false\ndescription = \"Hosted HTTP Rust MCP server starter with auth metadata and hosted validation.\"\n",
        ),
    )
    .expect("write manifest description");
}

fn toml_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

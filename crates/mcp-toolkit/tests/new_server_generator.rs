use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_toolkit::new_server::{
    default_toolkit_root, generate_new_server, NewServerOptions, ToolkitDependencySource,
};

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

    assert_eq!(summary.created_files, 9);
    assert!(output.join("Cargo.toml").exists());
    assert!(output.join(".github/workflows/rust-baseline.yml").exists());

    let manifest = read(&output.join("Cargo.toml"));
    assert!(manifest.contains("name = \"example-mcp\""));
    assert!(manifest.contains("git = \"https://github.com/sednalabs/mcp-toolkit-rs\""));
    assert!(!manifest.contains("../../crates/mcp-toolkit"));

    let smoke = read(&output.join("tests/stdio_smoke.rs"));
    assert!(smoke.contains("CARGO_BIN_EXE_example-mcp"));

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

fn cleanup(path: PathBuf) {
    let _ = fs::remove_dir_all(path);
}

fn toml_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

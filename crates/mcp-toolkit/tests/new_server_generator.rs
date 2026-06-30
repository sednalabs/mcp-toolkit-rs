use std::fs;
use std::path::{Path, PathBuf};
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

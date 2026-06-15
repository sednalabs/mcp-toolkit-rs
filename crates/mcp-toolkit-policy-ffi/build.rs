use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const FALLBACK_PK_ABI_MAJOR: u32 = 1;
const FALLBACK_PK_ABI_MINOR: u32 = 0;

const KERNEL_ROOT_ENV: &str = "PK_POLICY_KERNEL_ROOT";

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-env-changed={KERNEL_ROOT_ENV}");
    let kernel_root_env = env::var_os(KERNEL_ROOT_ENV);
    let kernel_root = kernel_root_env
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            root.join("..")
                .join("..")
                .join("..")
                .join("..")
                .join("mcp-policy-kernel")
        });
    let header = kernel_root
        .join("spark")
        .join("include")
        .join("pk_policy_kernel.h");

    println!("cargo:rerun-if-changed={}", header.display());

    let default_artifacts_missing = kernel_root_env.is_none() && !header.exists();

    let (major, minor) = if default_artifacts_missing {
        println!(
            "cargo:warning=kernel artifacts not found at {}; using built-in fallback ABI constants",
            kernel_root.display()
        );
        (FALLBACK_PK_ABI_MAJOR, FALLBACK_PK_ABI_MINOR)
    } else {
        let contents = read_kernel_file(&header, "pk_policy_kernel.h");
        let major = extract_define(&contents, "PK_ABI_MAJOR")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("missing/invalid PK_ABI_MAJOR in {}", header.display()));
        let minor = extract_define(&contents, "PK_ABI_MINOR")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("missing/invalid PK_ABI_MINOR in {}", header.display()));
        (major, minor)
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("pk_abi.rs");
    fs::write(
        &out_path,
        format!(
            "pub const PK_ABI_MAJOR: u32 = {major};\npub const PK_ABI_MINOR: u32 = {minor};\n",
        ),
    )
    .expect("write pk_abi.rs");
}

fn extract_define(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with("#define") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == key {
                return Some(parts[2].to_string());
            }
        }
    }
    None
}

fn read_kernel_file(path: &Path, desc: &str) -> String {
    match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) => panic!("failed to read {} at {}: {}", desc, path.display(), err),
    }
}

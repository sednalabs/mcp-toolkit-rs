use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const FALLBACK_BOUNDARY_MAX_STRING_LENGTH: usize = 2048;
const FALLBACK_BOUNDARY_MAX_LIST_LENGTH: usize = 128;
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
                .join("policy-kernel")
        });
    let header = kernel_root
        .join("spark")
        .join("include")
        .join("pk_policy_kernel.h");
    let policy_types = kernel_root
        .join("spark")
        .join("src")
        .join("policy_types.ads");

    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", policy_types.display());

    let default_artifacts_missing =
        kernel_root_env.is_none() && !header.exists() && !policy_types.exists();

    let (max_string_len, max_list_len, major, minor) = if default_artifacts_missing {
        println!(
            "cargo:warning=kernel artifacts not found at {}; using built-in fallback constants",
            kernel_root.display()
        );
        (
            FALLBACK_BOUNDARY_MAX_STRING_LENGTH,
            FALLBACK_BOUNDARY_MAX_LIST_LENGTH,
            FALLBACK_PK_ABI_MAJOR,
            FALLBACK_PK_ABI_MINOR,
        )
    } else {
        let header_contents = read_kernel_file(&header, "pk_policy_kernel.h");
        let policy_types_contents = read_kernel_file(&policy_types, "policy_types.ads");

        let max_string_len =
            extract_ada_positive_constant(&policy_types_contents, "Max_String_Length")
                .unwrap_or_else(|| {
                    panic!(
                        "missing/invalid Max_String_Length in {}",
                        policy_types.display()
                    )
                });
        let max_list_len = extract_ada_positive_constant(&policy_types_contents, "Max_List_Length")
            .unwrap_or_else(|| {
                panic!(
                    "missing/invalid Max_List_Length in {}",
                    policy_types.display()
                )
            });
        let major = extract_define(&header_contents, "PK_ABI_MAJOR")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("missing/invalid PK_ABI_MAJOR in {}", header.display()));
        let minor = extract_define(&header_contents, "PK_ABI_MINOR")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("missing/invalid PK_ABI_MINOR in {}", header.display()));

        (max_string_len, max_list_len, major, minor)
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    fs::write(
        out_dir.join("pk_boundary.rs"),
        format!(
            "pub const BOUNDARY_MAX_STRING_LENGTH: usize = {max_string_len};\n\
             pub const BOUNDARY_MAX_LIST_LENGTH: usize = {max_list_len};\n\
             pub const PK_ABI_MAJOR: u32 = {major};\n\
             pub const PK_ABI_MINOR: u32 = {minor};\n"
        ),
    )
    .expect("write pk_boundary.rs");
}

fn extract_define(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if !line.starts_with("#define") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == key {
            return Some(parts[2].to_string());
        }
    }
    None
}

fn extract_ada_positive_constant(contents: &str, key: &str) -> Option<usize> {
    for line in contents.lines() {
        let line = line.split("--").next().unwrap_or("").trim();
        if !line.starts_with(key) {
            continue;
        }
        let (_, value_part) = line.split_once(": constant Positive :=")?;
        let value = value_part.trim().trim_end_matches(';');
        if value.chars().all(|ch| ch.is_ascii_digit()) {
            return value.parse().ok();
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

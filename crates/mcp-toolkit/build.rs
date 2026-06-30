use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("../..");
    let templates_root = repo_root.join("templates");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_file = out_dir.join("new_server_templates.rs");

    println!("cargo:rerun-if-changed={}", templates_root.display());

    let generated = generate_templates_module(&templates_root).expect("generate template module");
    fs::write(out_file, generated).expect("write generated template module");
}

fn generate_templates_module(templates_root: &Path) -> io::Result<String> {
    let mut templates = Vec::new();

    for entry in sorted_entries(templates_root)? {
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let template_root = entry.path();
        let template_name = entry.file_name().to_string_lossy().into_owned();
        let mut assets = Vec::new();
        collect_assets(&template_root, &template_root, &mut assets)?;
        assets.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        templates.push(TemplateAssets {
            source_dir: template_name,
            assets,
        });
    }

    templates.sort_by(|left, right| left.source_dir.cmp(&right.source_dir));

    let mut module = String::from(
        "pub(crate) struct EmbeddedTemplateAsset {\n    pub(crate) relative_path: &'static str,\n    pub(crate) contents: &'static [u8],\n    pub(crate) executable: bool,\n}\n\npub(crate) struct EmbeddedTemplate {\n    pub(crate) source_dir: &'static str,\n    pub(crate) assets: &'static [EmbeddedTemplateAsset],\n}\n\npub(crate) static EMBEDDED_TEMPLATES: &[EmbeddedTemplate] = &[\n",
    );

    for template in templates {
        module.push_str("    EmbeddedTemplate {\n");
        module.push_str(&format!(
            "        source_dir: {:?},\n        assets: &[\n",
            template.source_dir
        ));

        for asset in template.assets {
            module.push_str("            EmbeddedTemplateAsset {\n");
            module.push_str(&format!(
                "                relative_path: {:?},\n",
                asset.relative_path
            ));
            module.push_str(&format!(
                "                contents: include_bytes!({:?}),\n",
                asset.absolute_path.display().to_string()
            ));
            module.push_str(&format!(
                "                executable: {},\n",
                asset.executable
            ));
            module.push_str("            },\n");
        }

        module.push_str("        ],\n    },\n");
    }

    module.push_str("];\n");
    Ok(module)
}

fn collect_assets(root: &Path, current: &Path, assets: &mut Vec<TemplateAsset>) -> io::Result<()> {
    for entry in sorted_entries(current)? {
        let file_type = entry.file_type()?;
        let path = entry.path();

        if file_type.is_dir() {
            if is_ignored_dir(&path) {
                continue;
            }
            collect_assets(root, &path, assets)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let relative_path = path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        println!("cargo:rerun-if-changed={}", path.display());
        assets.push(TemplateAsset {
            relative_path,
            absolute_path: path.clone(),
            executable: is_executable(&path)?,
        });
    }

    Ok(())
}

fn is_ignored_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | "target")
    )
}

fn sorted_entries(path: &Path) -> io::Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    Ok(fs::metadata(path)?.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> io::Result<bool> {
    Ok(false)
}

struct TemplateAssets {
    source_dir: String,
    assets: Vec<TemplateAsset>,
}

struct TemplateAsset {
    relative_path: String,
    absolute_path: PathBuf,
    executable: bool,
}

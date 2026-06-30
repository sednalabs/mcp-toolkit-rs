use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("../..");
    let templates_root = repo_root.join("templates");
    let manifests_root = repo_root.join("docs/pattern-manifests");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let templates_out_file = out_dir.join("new_server_templates.rs");
    let pattern_registry_out_file = out_dir.join("pattern_registry.rs");

    println!("cargo:rerun-if-changed={}", templates_root.display());
    println!("cargo:rerun-if-changed={}", manifests_root.display());

    let generated = generate_templates_module(&templates_root).expect("generate template module");
    fs::write(templates_out_file, generated).expect("write generated template module");

    let generated =
        generate_pattern_registry_module(&manifests_root).expect("generate pattern registry");
    fs::write(pattern_registry_out_file, generated).expect("write generated pattern registry");
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

fn generate_pattern_registry_module(manifests_root: &Path) -> Result<String, Box<dyn Error>> {
    let mut manifests = Vec::new();

    for entry in sorted_entries(manifests_root)? {
        if !entry.file_type()?.is_file() {
            continue;
        }

        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }

        println!("cargo:rerun-if-changed={}", path.display());
        let contents = fs::read_to_string(&path)?;
        let value: Value = serde_json::from_str(&contents)?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        manifests.push(read_pattern_manifest(file_name, &value)?);
    }

    manifests.sort_by(|left, right| left.path.cmp(&right.path));

    let mut module =
        String::from("pub(crate) static PATTERN_MANIFESTS: &[PatternManifestSpec] = &[\n");

    for manifest in manifests {
        module.push_str("    PatternManifestSpec {\n");
        module.push_str(&format!("        path: {:?},\n", manifest.path));
        module.push_str("        server: PatternServerSpec {\n");
        module.push_str(&format!("            name: {:?},\n", manifest.server.name));
        module.push_str(&format!(
            "            repository: {:?},\n",
            manifest.server.repository
        ));
        module.push_str(&format!("            role: {:?},\n", manifest.server.role));
        module.push_str(&format!(
            "            notes: {:?},\n",
            manifest.server.notes
        ));
        module.push_str("        },\n");
        module.push_str(&format!(
            "        patterns: &{},\n",
            string_array_literal(&manifest.patterns)
        ));
        module.push_str(&format!(
            "        toolkit_crates: &{},\n",
            string_array_literal(&manifest.toolkit_crates)
        ));
        module.push_str(&format!(
            "        transports: &{},\n",
            string_array_literal(&manifest.transports)
        ));
        module.push_str(&format!(
            "        auth_modes: &{},\n",
            string_array_literal(&manifest.auth_modes)
        ));
        module.push_str(&format!(
            "        discovery: &{},\n",
            string_array_literal(&manifest.discovery)
        ));
        module.push_str(&format!(
            "        mutation_policy: {:?},\n",
            manifest.mutation_policy
        ));
        module.push_str(&format!(
            "        schema_snapshot: {:?},\n",
            manifest.schema_snapshot
        ));
        module.push_str("        scratchpad: PatternScratchpadSpec {\n");
        module.push_str(&format!(
            "            supported: {},\n",
            manifest.scratchpad.supported
        ));
        module.push_str(&format!(
            "            engine: {:?},\n",
            manifest.scratchpad.engine
        ));
        module.push_str(&format!(
            "            profile: {:?},\n",
            manifest.scratchpad.profile
        ));
        module.push_str(&format!(
            "            notes: {:?},\n",
            manifest.scratchpad.notes
        ));
        module.push_str("        },\n");
        module.push_str(&format!(
            "        default_profiles: &{},\n",
            string_array_literal(&manifest.default_profiles)
        ));
        module.push_str(&format!(
            "        profiles: &{},\n",
            string_array_literal(&manifest.profiles)
        ));
        module.push_str(&format!(
            "        conformance_notes: {:?},\n",
            manifest.conformance_notes
        ));
        module.push_str("        references: &[\n");
        for reference in manifest.references {
            module.push_str("            PatternReferenceSpec {\n");
            module.push_str(&format!("                label: {:?},\n", reference.label));
            module.push_str(&format!("                kind: {:?},\n", reference.kind));
            module.push_str(&format!("                path: {:?},\n", reference.path));
            module.push_str("            },\n");
        }
        module.push_str("        ],\n");
        module.push_str("    },\n");
    }

    module.push_str("];\n");
    Ok(module)
}

fn read_pattern_manifest(path: String, value: &Value) -> Result<PatternManifest, Box<dyn Error>> {
    let server = object_field(value, "server")?;
    let tool_surface = object_field(value, "tool_surface")?;
    let scratchpad = object_field(value, "scratchpad")?;
    let conformance = object_field(value, "conformance")?;

    let mut default_profiles = Vec::new();
    let mut profiles = Vec::new();
    for profile in array_field(value, "profiles")? {
        let profile = profile
            .as_object()
            .ok_or_else(|| manifest_error("profile entries must be objects"))?;
        let name = string_field_object(profile, "name")?.to_string();
        if optional_bool_field_object(profile, "default", false)? {
            default_profiles.push(name.clone());
        }
        profiles.push(name);
    }

    let mut references = Vec::new();
    for reference in array_field(value, "references")? {
        let reference = reference
            .as_object()
            .ok_or_else(|| manifest_error("reference entries must be objects"))?;
        references.push(PatternReference {
            label: string_field_object(reference, "label")?.to_string(),
            kind: string_field_object(reference, "kind")?.to_string(),
            path: string_field_object(reference, "path")?.to_string(),
        });
    }

    Ok(PatternManifest {
        path: format!("docs/pattern-manifests/{path}"),
        server: PatternServer {
            name: string_field(server, "name")?.to_string(),
            repository: string_field(server, "repository")?.to_string(),
            role: string_field(server, "role")?.to_string(),
            notes: optional_string_field(server, "notes")
                .unwrap_or("")
                .to_string(),
        },
        patterns: string_array(value, "patterns")?,
        toolkit_crates: string_array(value, "toolkit_crates")?,
        transports: string_array(value, "transports")?,
        auth_modes: string_array(value, "auth_modes")?,
        discovery: string_array(tool_surface, "discovery")?,
        mutation_policy: string_field(tool_surface, "mutation_policy")?.to_string(),
        schema_snapshot: string_field(tool_surface, "schema_snapshot")?.to_string(),
        scratchpad: PatternScratchpad {
            supported: bool_field(scratchpad, "supported")?,
            engine: string_field(scratchpad, "engine")?.to_string(),
            profile: string_field(scratchpad, "profile")?.to_string(),
            notes: string_field(scratchpad, "notes")?.to_string(),
        },
        default_profiles,
        profiles,
        conformance_notes: optional_string_field(conformance, "notes")
            .unwrap_or("")
            .to_string(),
        references,
    })
}

fn object_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| manifest_error(format!("missing object field `{field}`")))
}

fn array_field<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| manifest_error(format!("missing array field `{field}`")))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| manifest_error(format!("missing string field `{field}`")))
}

fn optional_string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_field(value: &Value, field: &str) -> Result<bool, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| manifest_error(format!("missing bool field `{field}`")))
}

fn string_field_object<'a>(
    value: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| manifest_error(format!("missing string field `{field}`")))
}

fn optional_bool_field_object(
    value: &serde_json::Map<String, Value>,
    field: &str,
    default: bool,
) -> Result<bool, Box<dyn Error>> {
    match value.get(field) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| manifest_error(format!("field `{field}` must be a bool"))),
        None => Ok(default),
    }
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>, Box<dyn Error>> {
    array_field(value, field)?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                manifest_error(format!("array field `{field}` must contain strings"))
            })
        })
        .collect()
}

fn manifest_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

fn string_array_literal(values: &[String]) -> String {
    let mut literal = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            literal.push_str(", ");
        }
        literal.push_str(&format!("{value:?}"));
    }
    literal.push(']');
    literal
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

struct PatternManifest {
    path: String,
    server: PatternServer,
    patterns: Vec<String>,
    toolkit_crates: Vec<String>,
    transports: Vec<String>,
    auth_modes: Vec<String>,
    discovery: Vec<String>,
    mutation_policy: String,
    schema_snapshot: String,
    scratchpad: PatternScratchpad,
    default_profiles: Vec<String>,
    profiles: Vec<String>,
    conformance_notes: String,
    references: Vec<PatternReference>,
}

struct PatternServer {
    name: String,
    repository: String,
    role: String,
    notes: String,
}

struct PatternScratchpad {
    supported: bool,
    engine: String,
    profile: String,
    notes: String,
}

struct PatternReference {
    label: String,
    kind: String,
    path: String,
}

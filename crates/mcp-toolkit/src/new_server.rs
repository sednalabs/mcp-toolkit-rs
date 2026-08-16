//! # MCP Toolkit New Server Generator
//!
//! Generates new Rust MCP server skeletons from the maintained repository
//! templates.
//!
//! ## Rationale
//! Makes the correct new-server path faster than copying a template by hand,
//! while keeping the existing templates as the single source of scaffold truth.
//!
//! ## Security Boundaries
//! * Embeds only files from the repository's `templates/` directory.
//! * Refuses to overwrite changed files unless the caller explicitly allows it.
//! * Validates generated relative paths before writing under a relative output
//!   directory rooted at the caller's current working directory.
//!
//! ## References
//! * `docs/new-server-delivery-lane.md`
//! * `docs/starter-templates.md`

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

mod embedded_templates {
    include!(concat!(env!("OUT_DIR"), "/new_server_templates.rs"));
}

const DEFAULT_TEMPLATE: &str = "curated-stdio-intent";
const DEFAULT_TOOLKIT_GIT: &str = "https://github.com/sednalabs/mcp-toolkit-rs";

/// Declares one maintained new-server template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateSpec {
    /// Stable CLI identifier for the template.
    pub id: &'static str,
    /// Source template directory embedded from `templates/`.
    pub source_dir: &'static str,
    /// Package name used inside the source template before rewriting.
    pub source_package: &'static str,
    /// Human-readable template summary.
    pub description: &'static str,
    aliases: &'static [&'static str],
}

/// Selects how generated Cargo manifests should depend on `mcp-toolkit-rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolkitDependencySource {
    /// Rewrite toolkit path dependencies to an absolute or caller-provided local
    /// repository root.
    LocalPath(PathBuf),
    /// Rewrite toolkit dependencies to a Git repository URL.
    Git(String),
}

/// Configures a new-server generation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewServerOptions {
    /// Template id or alias.
    pub template: String,
    /// Cargo package and binary name for the generated server.
    pub package_name: String,
    /// Target directory for generated files.
    pub output_dir: PathBuf,
    /// Toolkit dependency source written into generated Cargo manifests.
    pub toolkit_dependency: ToolkitDependencySource,
    /// Overwrite generated files that already differ.
    pub overwrite: bool,
}

/// Summarizes a successful new-server generation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewServerSummary {
    /// Template selected for generation.
    pub template: TemplateSpec,
    /// Cargo package and binary name written into the generated project.
    pub package_name: String,
    /// Target directory for generated files.
    pub output_dir: PathBuf,
    /// Count of newly written files.
    pub created_files: usize,
    /// Count of existing files that already matched generated content.
    pub unchanged_files: usize,
    /// Count of changed files overwritten because `overwrite` was enabled.
    pub overwritten_files: usize,
}

/// Errors returned by the new-server generator.
#[derive(Debug)]
pub enum NewServerError {
    /// The requested template id or alias does not match a maintained template.
    UnknownTemplate(String),
    /// The requested package name is not a safe Cargo package name.
    InvalidPackageName(String),
    /// An embedded source template was not found in the generated asset set.
    MissingEmbeddedTemplate(&'static str),
    /// An embedded template path is absolute, empty, or attempts to escape the
    /// output directory.
    UnsafeTemplatePath(String),
    /// The requested output directory is absolute, empty, or attempts to escape
    /// the current working directory.
    InvalidOutputDirectory(PathBuf),
    /// An existing output directory component is a symbolic link.
    OutputDirectoryContainsSymlink(PathBuf),
    /// An existing generated output path component is a symbolic link.
    OutputPathContainsSymlink(PathBuf),
    /// A generated destination file is a symbolic link.
    RefusingSymlinkDestination(PathBuf),
    /// A generated file would overwrite changed content without permission.
    RefusingOverwrite(PathBuf),
    /// Underlying filesystem I/O failed.
    Io {
        /// Filesystem path involved in the failed operation.
        path: PathBuf,
        /// Source I/O error.
        source: io::Error,
    },
}

impl fmt::Display for NewServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTemplate(template) => write!(
                formatter,
                "unknown template `{template}`; run `mcp-toolkit templates` to list supported templates"
            ),
            Self::InvalidPackageName(package_name) => write!(
                formatter,
                "invalid package name `{package_name}`; use ASCII letters, numbers, `_`, or `-`"
            ),
            Self::MissingEmbeddedTemplate(source_dir) => write!(
                formatter,
                "embedded template assets are missing source directory `{source_dir}`"
            ),
            Self::UnsafeTemplatePath(path) => {
                write!(formatter, "refusing unsafe embedded template path `{path}`")
            }
            Self::InvalidOutputDirectory(path) => write!(
                formatter,
                "invalid output directory `{}`; use a relative path under the current directory",
                path.display()
            ),
            Self::OutputDirectoryContainsSymlink(path) => write!(
                formatter,
                "refusing output directory through symlink `{}`",
                path.display()
            ),
            Self::OutputPathContainsSymlink(path) => write!(
                formatter,
                "refusing generated output path through symlink `{}`",
                path.display()
            ),
            Self::RefusingSymlinkDestination(path) => write!(
                formatter,
                "refusing to write generated file through symlink `{}`",
                path.display()
            ),
            Self::RefusingOverwrite(path) => write!(
                formatter,
                "refusing to overwrite changed file `{}`; rerun with --force to replace generated files",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(formatter, "filesystem operation failed for `{}`: {source}", path.display())
            }
        }
    }
}

impl Error for NewServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Returns the maintained new-server templates.
pub fn templates() -> &'static [TemplateSpec] {
    const TEMPLATES: &[TemplateSpec] = &[
        TemplateSpec {
            id: "curated-stdio-intent",
            source_dir: "curated-stdio-intent-server",
            source_package: "curated-stdio-intent-server",
            description: "Small process-local stdio server with a curated intent tool surface.",
            aliases: &["curated-stdio-intent-server", "stdio", "stdio-intent"],
        },
        TemplateSpec {
            id: "single-crate-public-stdio",
            source_dir: "single-crate-public-stdio-server",
            source_package: "single-crate-public-stdio-server",
            description: "Standalone public stdio repository with CI, governance, and dual-native Linux release artifacts.",
            aliases: &[
                "single-crate-public-stdio-server",
                "public-stdio",
                "public",
            ],
        },
        TemplateSpec {
            id: "hosted-http-auth",
            source_dir: "hosted-http-auth-server",
            source_package: "hosted-http-auth-server",
            description: "Hosted Streamable HTTP server with OAuth metadata, bearer challenges, and host guards.",
            aliases: &["hosted-http-auth-server", "http-auth", "hosted-http"],
        },
    ];

    TEMPLATES
}

/// Returns the default template id used by `mcp-toolkit new`.
pub fn default_template_id() -> &'static str {
    DEFAULT_TEMPLATE
}

/// Returns the default public Git URL used when callers request Git
/// dependencies.
pub fn default_toolkit_git_url() -> &'static str {
    DEFAULT_TOOLKIT_GIT
}

/// Returns the default local toolkit root compiled into the generator.
pub fn default_toolkit_root() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    match fs::canonicalize(&root) {
        Ok(canonical) => canonical,
        Err(_) => root,
    }
}

/// Finds a maintained template by id, source directory, or alias.
pub fn find_template(name: &str) -> Option<TemplateSpec> {
    templates()
        .iter()
        .copied()
        .find(|template| template.id == name || template.aliases.contains(&name))
}

/// Generates a new Rust MCP server from a maintained template.
///
/// # Errors
/// Returns `NewServerError` if the template or package name is invalid, if an
/// output path is unsafe, if a file would be overwritten without permission, or
/// if filesystem writes fail.
///
/// # Security
/// The generator validates every embedded relative path and only writes below
/// a relative output directory rooted at the caller's current working directory.
pub fn generate_new_server(options: &NewServerOptions) -> Result<NewServerSummary, NewServerError> {
    validate_package_name(&options.package_name)?;
    let template = find_template(&options.template)
        .ok_or_else(|| NewServerError::UnknownTemplate(options.template.clone()))?;
    let embedded = embedded_templates::EMBEDDED_TEMPLATES
        .iter()
        .find(|assets| assets.source_dir == template.source_dir)
        .ok_or(NewServerError::MissingEmbeddedTemplate(template.source_dir))?;

    let output_dir = OutputDirectory::new(&options.output_dir)?;
    let prepared_assets = prepare_assets(embedded, template, options, &output_dir)?;

    if !options.overwrite {
        for asset in &prepared_assets {
            if asset.destination.exists() && read_generated(&asset.destination)? != asset.content {
                return Err(NewServerError::RefusingOverwrite(
                    asset.destination.path.clone(),
                ));
            }
        }
    }

    let mut created_files = 0;
    let mut unchanged_files = 0;
    let mut overwritten_files = 0;

    create_output_dir(&output_dir)?;

    for asset in prepared_assets {
        if asset.destination.exists() {
            let existing = read_generated(&asset.destination)?;
            if existing == asset.content {
                set_executable_if_needed(&asset.destination, asset.executable)?;
                unchanged_files += 1;
                continue;
            }

            write_generated(&asset.destination, &asset.content)?;
            overwritten_files += 1;
        } else {
            create_parent_dir(&asset.destination)?;
            write_generated(&asset.destination, &asset.content)?;
            created_files += 1;
        }

        set_executable_if_needed(&asset.destination, asset.executable)?;
    }

    Ok(NewServerSummary {
        template,
        package_name: options.package_name.clone(),
        output_dir: options.output_dir.clone(),
        created_files,
        unchanged_files,
        overwritten_files,
    })
}

fn prepare_assets(
    embedded: &embedded_templates::EmbeddedTemplate,
    template: TemplateSpec,
    options: &NewServerOptions,
    output_dir: &OutputDirectory,
) -> Result<Vec<PreparedAsset>, NewServerError> {
    let mut prepared = Vec::with_capacity(embedded.assets.len());

    for asset in embedded.assets {
        let relative = safe_template_relative_path(asset.relative_path)?;
        let destination = output_dir.destination(&relative)?;
        let content = render_asset(asset.contents, template, options);
        prepared.push(PreparedAsset {
            destination,
            content,
            executable: asset.executable,
        });
    }

    Ok(prepared)
}

fn validate_package_name(package_name: &str) -> Result<(), NewServerError> {
    let valid = !package_name.is_empty()
        && package_name != "."
        && package_name != ".."
        && !package_name.starts_with('-')
        && !package_name.ends_with('-')
        && package_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');

    if valid {
        Ok(())
    } else {
        Err(NewServerError::InvalidPackageName(package_name.to_string()))
    }
}

fn safe_template_relative_path(relative_path: &str) -> Result<PathBuf, NewServerError> {
    let path = Path::new(relative_path);
    safe_relative_components(path)
        .map_err(|_| NewServerError::UnsafeTemplatePath(relative_path.to_string()))
}

fn safe_output_relative_path(path: &Path) -> Result<PathBuf, NewServerError> {
    safe_relative_components(path)
        .map_err(|_| NewServerError::InvalidOutputDirectory(path.to_path_buf()))
}

fn existing_symlink_component(
    root: &Path,
    relative: &Path,
) -> Result<Option<PathBuf>, NewServerError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Ok(Some(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(NewServerError::Io {
                    path: current,
                    source,
                });
            }
        }
    }

    Ok(None)
}

fn safe_relative_components(path: &Path) -> Result<PathBuf, ()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(());
    }

    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => safe.push(part),
            Component::CurDir => {}
            _ => return Err(()),
        }
    }

    if safe.as_os_str().is_empty() {
        return Err(());
    }

    Ok(safe)
}

fn ensure_destination_inside_output(
    output_dir: &Path,
    destination: PathBuf,
    relative_path: &Path,
) -> Result<GeneratedPath, NewServerError> {
    if destination.starts_with(output_dir) {
        Ok(GeneratedPath { path: destination })
    } else {
        Err(NewServerError::UnsafeTemplatePath(
            relative_path.display().to_string(),
        ))
    }
}

struct OutputDirectory {
    path: PathBuf,
}

impl OutputDirectory {
    fn new(path: &Path) -> Result<Self, NewServerError> {
        let relative = safe_output_relative_path(path)?;
        let cwd = std::env::current_dir().map_err(|source| NewServerError::Io {
            path: PathBuf::from("."),
            source,
        })?;
        if let Some(symlink) = existing_symlink_component(&cwd, &relative)? {
            return Err(NewServerError::OutputDirectoryContainsSymlink(symlink));
        }
        Ok(Self {
            path: cwd.join(relative),
        })
    }

    fn destination(&self, relative_path: &Path) -> Result<GeneratedPath, NewServerError> {
        let path = ensure_destination_inside_output(
            &self.path,
            self.path.join(relative_path),
            relative_path,
        )?;
        if let Some(symlink) = existing_symlink_component(&self.path, relative_path)? {
            if symlink == path.path {
                return Err(NewServerError::RefusingSymlinkDestination(symlink));
            }
            return Err(NewServerError::OutputPathContainsSymlink(symlink));
        }
        Ok(path)
    }
}

struct GeneratedPath {
    path: PathBuf,
}

impl GeneratedPath {
    fn exists(&self) -> bool {
        self.path.exists()
    }
}

struct PreparedAsset {
    destination: GeneratedPath,
    content: Vec<u8>,
    executable: bool,
}

fn render_asset(contents: &[u8], template: TemplateSpec, options: &NewServerOptions) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let source_crate = cargo_crate_identifier(template.source_package);
    let target_crate = cargo_crate_identifier(&options.package_name);

    let rendered = rewrite_toolkit_dependencies(
        &text
            .replace(
                &format!("templates/{}/Cargo.toml", template.source_dir),
                "Cargo.toml",
            )
            .replace(&format!("templates/{}", template.source_dir), ".")
            .replace(&source_crate, &target_crate)
            .replace(template.source_package, &options.package_name),
        &options.toolkit_dependency,
    );

    rendered.into_bytes()
}

fn cargo_crate_identifier(package_name: &str) -> String {
    package_name.replace('-', "_")
}

fn rewrite_toolkit_dependencies(
    text: &str,
    toolkit_dependency: &ToolkitDependencySource,
) -> String {
    let mut rewritten = text.to_string();

    for package in toolkit_path_dependencies(text) {
        rewritten = rewritten.replace(
            &format!("{package} = {{ path = \"../../crates/{package}\""),
            &format!(
                "{package} = {{ {}",
                dependency_prefix(&package, toolkit_dependency)
            ),
        );
    }

    rewritten
}

fn toolkit_path_dependencies(text: &str) -> Vec<String> {
    let mut packages = Vec::new();
    let dependency_prefix = " = { path = \"../../crates/";

    for line in text.lines() {
        let line = line.trim_start();
        let Some((package, path_suffix)) = line.split_once(dependency_prefix) else {
            continue;
        };
        let Some(path_package) = path_suffix.split('"').next() else {
            continue;
        };
        if package.starts_with("mcp-toolkit") && package == path_package {
            packages.push(package.to_string());
        }
    }

    packages.sort();
    packages.dedup();
    packages
}

fn dependency_prefix(package: &str, toolkit_dependency: &ToolkitDependencySource) -> String {
    match toolkit_dependency {
        ToolkitDependencySource::LocalPath(root) => format!(
            "path = \"{}\"",
            toml_path(&root.join("crates").join(package))
        ),
        ToolkitDependencySource::Git(url) => {
            format!(
                "git = \"{}\"",
                url.replace('\\', "\\\\").replace('"', "\\\"")
            )
        }
    }
}

fn toml_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn create_output_dir(output_dir: &OutputDirectory) -> Result<(), NewServerError> {
    fs::create_dir_all(&output_dir.path).map_err(|source| NewServerError::Io {
        path: output_dir.path.clone(),
        source,
    })
}

fn create_parent_dir(path: &GeneratedPath) -> Result<(), NewServerError> {
    if let Some(parent) = path.path.parent() {
        fs::create_dir_all(parent).map_err(|source| NewServerError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    Ok(())
}

fn read_generated(path: &GeneratedPath) -> Result<Vec<u8>, NewServerError> {
    fs::read(&path.path).map_err(|source| NewServerError::Io {
        path: path.path.clone(),
        source,
    })
}

fn write_generated(path: &GeneratedPath, content: &[u8]) -> Result<(), NewServerError> {
    fs::write(&path.path, content).map_err(|source| NewServerError::Io {
        path: path.path.clone(),
        source,
    })
}

#[cfg(unix)]
fn set_executable_if_needed(path: &GeneratedPath, executable: bool) -> Result<(), NewServerError> {
    use std::os::unix::fs::PermissionsExt;

    if !executable {
        return Ok(());
    }

    let metadata = fs::metadata(&path.path).map_err(|source| NewServerError::Io {
        path: path.path.clone(),
        source,
    })?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    fs::set_permissions(&path.path, permissions).map_err(|source| NewServerError::Io {
        path: path.path.clone(),
        source,
    })
}

#[cfg(not(unix))]
fn set_executable_if_needed(
    _path: &GeneratedPath,
    _executable: bool,
) -> Result<(), NewServerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_aliases_resolve() {
        assert_eq!(
            find_template("stdio").map(|template| template.id),
            Some("curated-stdio-intent")
        );
        assert_eq!(
            find_template("hosted-http-auth-server").map(|template| template.id),
            Some("hosted-http-auth")
        );
    }

    #[test]
    fn package_name_validation_rejects_path_like_names() {
        for name in ["", ".", "..", "../server", "/tmp/server", "-server"] {
            assert!(validate_package_name(name).is_err(), "{name} should fail");
        }
    }

    #[test]
    fn output_dir_validation_rejects_escape_paths() {
        for path in [Path::new(""), Path::new(".."), Path::new("../server")] {
            assert!(
                safe_output_relative_path(path).is_err(),
                "{} should fail",
                path.display()
            );
        }
    }

    #[test]
    fn dependency_rewrite_supports_git_sources() {
        let manifest = concat!(
            r#"mcp-toolkit = { path = "../../crates/mcp-toolkit", features = ["server-stdio"] }"#,
            "\n",
            r#"mcp-toolkit-server = { path = "../../crates/mcp-toolkit-server" }"#,
            "\n",
            r#"mcp-toolkit-http = { path = "../../crates/mcp-toolkit-http", features = ["auth"] }"#,
        );
        let rewritten = render_asset(
            manifest.as_bytes(),
            templates()[0],
            &NewServerOptions {
                template: "curated-stdio-intent".to_string(),
                package_name: "example-mcp".to_string(),
                output_dir: PathBuf::from("example-mcp"),
                toolkit_dependency: ToolkitDependencySource::Git(
                    "https://example.com/toolkit.git".to_string(),
                ),
                overwrite: false,
            },
        );
        assert_eq!(
            String::from_utf8(rewritten).expect("utf8"),
            concat!(
                r#"mcp-toolkit = { git = "https://example.com/toolkit.git", features = ["server-stdio"] }"#,
                "\n",
                r#"mcp-toolkit-server = { git = "https://example.com/toolkit.git" }"#,
                "\n",
                r#"mcp-toolkit-http = { git = "https://example.com/toolkit.git", features = ["auth"] }"#,
            )
        );
    }

    #[test]
    fn dependency_rewrite_discovers_only_matching_toolkit_path_dependencies() {
        let manifest = concat!(
            r#"mcp-toolkit-server = { path = "../../crates/mcp-toolkit-server" }"#,
            "\n",
            r#"mcp-toolkit-http = { path = "../../crates/mcp-toolkit-core" }"#,
            "\n",
            r#"other-toolkit = { path = "../../crates/other-toolkit" }"#,
        );
        assert_eq!(
            toolkit_path_dependencies(manifest),
            vec!["mcp-toolkit-server".to_string()]
        );
    }

    #[test]
    fn render_asset_keeps_binary_content_unchanged() {
        let binary = [0, 159, 146, 150];
        assert_eq!(
            render_asset(
                &binary,
                templates()[0],
                &NewServerOptions {
                    template: "curated-stdio-intent".to_string(),
                    package_name: "example-mcp".to_string(),
                    output_dir: PathBuf::from("example-mcp"),
                    toolkit_dependency: ToolkitDependencySource::LocalPath(default_toolkit_root()),
                    overwrite: false,
                },
            ),
            binary
        );
    }
}

//! # MCP Toolkit Client Configuration Renderer
//!
//! Renders copyable MCP client configuration snippets for generated Rust MCP
//! server projects and standalone installed stdio binaries.
//!
//! ## Rationale
//! Generated servers should not leave operators to hand-translate a package
//! name, binary path, profile environment variable, or hosted MCP URL into each
//! client's configuration shape. This module keeps the first client-config
//! helper deterministic and filesystem-only.
//!
//! ## Security Boundaries
//! * Project rendering reads only the generated project's `Cargo.toml` package name.
//! * Executable rendering reads no files or process environment values.
//! * Does not execute generated code or inspect credential material.
//! * Never discovers credentials; caller-supplied values are rendered verbatim
//!   after escaping and validation. Pass only non-secret configuration values.
//!
//! ## References
//! * `docs/provider-auth-and-client-config.md`
//! * `docs/easy-server-ergonomics.md`

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::doctor::{inspect_project, DoctorShape};
use mcp_toolkit_core::tool_inventory::READ_ONLY_PROFILE_KEY;

const DEFAULT_PROFILE_ENV: &str = "EXAMPLE_MCP_TOOL_PROFILE";
const DEFAULT_HOSTED_HTTP_MCP_URL: &str = "http://127.0.0.1:9411/mcp";

/// Selects the rendered MCP transport configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigTransport {
    /// Render a stdio process configuration.
    Stdio,
    /// Render a hosted Streamable HTTP configuration.
    HostedHttp,
}

impl ClientConfigTransport {
    /// Parses a CLI transport label.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "stdio" => Some(Self::Stdio),
            "http" | "hosted-http" | "hosted_http" => Some(Self::HostedHttp),
            _ => None,
        }
    }
}

/// Selects a common stdio MCP client configuration format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigFormat {
    /// Codex-style `[mcp_servers."name"]` tables.
    CodexToml,
    /// A JSON object with an `mcpServers` map.
    McpServersJson,
}

/// Reports invalid explicit configuration without echoing caller data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecutableClientConfigError {
    /// The executable path cannot be represented in JSON or TOML without loss.
    NonUnicodeExecutable,
    /// A required field is empty or contains a control character.
    InvalidField,
    /// Environment keys must be unique, nonempty ASCII letters, digits or `_`.
    InvalidEnvironment,
}

impl fmt::Display for ExecutableClientConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonUnicodeExecutable => "client configuration requires a Unicode executable path",
            Self::InvalidField => "client configuration fields must be nonempty and contain no control characters",
            Self::InvalidEnvironment => "client configuration environment keys must be unique ASCII letters, digits or underscores",
        })
    }
}

impl Error for ExecutableClientConfigError {}

/// Renders configuration for one stdio executable, without needing its source tree.
///
/// Pass `std::env::current_exe()?` from a binary-local `--print-client-config`
/// command. An empty `environment` slice omits the environment block entirely;
/// no tool profile is inferred. Arguments are empty because this helper targets
/// the toolkit's no-arguments stdio launch contract.
///
/// ```
/// use std::path::Path;
/// use mcp_toolkit::client_config::{render_executable_client_config, ClientConfigFormat};
/// let config = render_executable_client_config(
///     "archive", Path::new("/opt/archive-mcp"),
///     ClientConfigFormat::McpServersJson, &[],
/// )?;
/// assert!(config.contains("mcpServers"));
/// assert!(!config.contains("env"));
/// # Ok::<(), mcp_toolkit::client_config::ExecutableClientConfigError>(())
/// ```
///
/// # Errors
/// Rejects empty names/paths, control characters, non-Unicode executable paths,
/// and invalid or duplicate environment keys before rendering either format.
/// Empty environment values are allowed. Errors do not echo input values.
///
/// # Security
/// Reads no environment values, files or credentials, and never executes the
/// command. Explicit environment values are NOT redacted: pass only public
/// defaults such as a read-only profile, never tokens or account secrets.
/// Use an absolute executable path to avoid client-dependent PATH resolution.
pub fn render_executable_client_config(
    server_name: &str,
    executable: &Path,
    format: ClientConfigFormat,
    environment: &[(&str, &str)],
) -> Result<String, ExecutableClientConfigError> {
    let command = executable
        .to_str()
        .ok_or(ExecutableClientConfigError::NonUnicodeExecutable)?;
    for value in [server_name, command] {
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(ExecutableClientConfigError::InvalidField);
        }
    }
    let mut env = std::collections::BTreeMap::new();
    for &(key, value) in environment {
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || env.insert(key, value).is_some()
        {
            return Err(ExecutableClientConfigError::InvalidEnvironment);
        }
        if value.chars().any(char::is_control) {
            return Err(ExecutableClientConfigError::InvalidField);
        }
    }
    match format {
        ClientConfigFormat::CodexToml => {
            let name = toml_string(server_name);
            let mut output = format!(
                "[mcp_servers.{name}]\ncommand = {}\nargs = []\n",
                toml_string(command),
            );
            if !env.is_empty() {
                output.push_str(&format!("\n[mcp_servers.{name}.env]\n"));
                for (key, value) in env {
                    output.push_str(&format!("{key} = {}\n", toml_string(value)));
                }
            }
            Ok(output)
        }
        ClientConfigFormat::McpServersJson => {
            let mut server = serde_json::json!({"command": command, "args": []});
            if !env.is_empty() {
                server["env"] = serde_json::json!(env);
            }
            // Value serialization is infallible; use its pretty Display formatter
            // rather than exposing a generic serialization error with input data.
            let config = serde_json::json!({"mcpServers": {server_name: server}});
            Ok(format!("{config:#}\n"))
        }
    }
}

/// Configures client configuration rendering for a generated server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfigOptions {
    /// Generated server project root.
    pub root: PathBuf,
    /// Optional MCP client server name. Defaults to the Cargo package name.
    pub server_name: Option<String>,
    /// Optional transport override. Defaults to the doctor-inferred shape.
    pub transport: Option<ClientConfigTransport>,
    /// Optional stdio command path. Defaults to `<root>/target/release/<package>`.
    pub command: Option<String>,
    /// Use the installed command name resolved from `PATH`.
    pub installed: bool,
    /// Optional hosted MCP URL. Defaults to the hosted starter local URL.
    pub url: Option<String>,
    /// Tool profile value for stdio process environment configuration.
    pub profile: String,
    /// Optional stdio environment variable name.
    pub env_key: Option<String>,
    /// Optional stdio environment variable value.
    pub env_value: Option<String>,
}

/// Errors returned while rendering client configuration.
#[derive(Debug)]
pub enum ClientConfigError {
    /// The generated project root is missing or not a directory.
    InvalidRoot(PathBuf),
    /// The generated project manifest could not be read.
    Io {
        /// Path involved in the failed filesystem operation.
        path: PathBuf,
        /// Source I/O error.
        source: io::Error,
    },
    /// `Cargo.toml` does not contain a supported `[package] name = "..."`
    /// declaration.
    MissingPackageName(PathBuf),
    /// The transport could not be inferred from generated proof files.
    UnknownTransport,
    /// An environment key is not a valid TOML bare key.
    InvalidEnvKey(String),
    /// An environment value contains a control character unsupported by TOML strings.
    InvalidEnvValue,
    /// A caller-supplied rendered field contains a TOML control character.
    InvalidControlCharacter(&'static str),
}

impl fmt::Display for ClientConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot(path) => write!(
                formatter,
                "client-config path `{}` is not a generated-server directory",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(formatter, "failed to read `{}`: {source}", path.display())
            }
            Self::MissingPackageName(path) => write!(
                formatter,
                "failed to find package name in `{}`",
                path.display()
            ),
            Self::UnknownTransport => write!(
                formatter,
                "could not infer generated-server transport; pass --transport stdio or --transport http"
            ),
            Self::InvalidEnvKey(key) => write!(formatter, "invalid client-config environment key `{key}`"),
            Self::InvalidEnvValue => write!(formatter, "client-config environment value contains a control character"),
            Self::InvalidControlCharacter(field) => write!(formatter, "client-config {field} contains a control character"),
        }
    }
}

impl Error for ClientConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Renders a Codex-style TOML MCP client configuration snippet.
///
/// # Errors
/// Returns `ClientConfigError` when the project root is invalid, the Cargo
/// package name cannot be read, or the transport cannot be inferred.
pub fn render_client_config(options: &ClientConfigOptions) -> Result<String, ClientConfigError> {
    if !options.root.is_dir() {
        return Err(ClientConfigError::InvalidRoot(options.root.clone()));
    }

    let canonical_root = options
        .root
        .canonicalize()
        .map_err(|source| ClientConfigError::Io {
            path: options.root.clone(),
            source,
        })?;
    let package_name = package_name_from_manifest(&canonical_root)?;
    let server_name = options
        .server_name
        .clone()
        .unwrap_or_else(|| package_name.clone());
    validate_text("server name", &server_name)?;
    if let Some(command) = options.command.as_deref() {
        validate_text("command", command)?;
    }
    if let Some(url) = options.url.as_deref() {
        validate_text("url", url)?;
    }
    validate_text("profile", &options.profile)?;
    let transport = match options.transport {
        Some(transport) => transport,
        None => infer_transport(&canonical_root)?,
    };

    let env_key = options.env_key.as_deref().unwrap_or_else(|| {
        // Derive the generated contract key while preserving the historical
        // EXAMPLE_MCP key for the example package.
        if package_name == "example-mcp" {
            DEFAULT_PROFILE_ENV
        } else {
            ""
        }
    });
    let derived_key;
    let env_key = if env_key.is_empty() {
        derived_key = profile_env_key(&package_name);
        derived_key.as_str()
    } else {
        env_key
    };
    validate_env_key(env_key)?;
    if let Some(value) = options
        .env_value
        .as_deref()
        .or(Some(options.profile.as_str()))
    {
        if value.chars().any(|c| c.is_control()) {
            return Err(ClientConfigError::InvalidEnvValue);
        }
    }

    Ok(match transport {
        ClientConfigTransport::Stdio => render_stdio_config(
            options,
            &package_name,
            &server_name,
            &canonical_root,
            env_key,
        ),
        ClientConfigTransport::HostedHttp => render_hosted_http_config(options, &server_name),
    })
}

fn infer_transport(root: &Path) -> Result<ClientConfigTransport, ClientConfigError> {
    match inspect_project(root).shape {
        DoctorShape::HostedHttpAuth => Ok(ClientConfigTransport::HostedHttp),
        DoctorShape::PublicStdio | DoctorShape::Stdio => Ok(ClientConfigTransport::Stdio),
        DoctorShape::Unknown => Err(ClientConfigError::UnknownTransport),
    }
}

fn render_stdio_config(
    options: &ClientConfigOptions,
    package_name: &str,
    server_name: &str,
    canonical_root: &Path,
    env_key: &str,
) -> String {
    let command = options.command.clone().unwrap_or_else(|| {
        if options.installed {
            return package_name.to_string();
        }
        canonical_root
            .join("target")
            .join("release")
            .join(package_name)
            .display()
            .to_string()
    });

    format!(
        "[mcp_servers.{}]\ncommand = \"{}\"\nargs = []\n\n[mcp_servers.{}.env]\n{} = \"{}\"\n",
        toml_string(server_name),
        toml_string_value(&command),
        toml_string(server_name),
        env_key,
        toml_string_value(options.env_value.as_deref().unwrap_or(&options.profile)),
    )
}

fn profile_env_key(package_name: &str) -> String {
    let mut key = package_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    key.push_str("_TOOL_PROFILE");
    key
}

fn validate_env_key(key: &str) -> Result<(), ClientConfigError> {
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ClientConfigError::InvalidEnvKey(key.to_string()));
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ClientConfigError> {
    if value.chars().any(|c| c.is_control()) {
        return Err(ClientConfigError::InvalidControlCharacter(field));
    }
    Ok(())
}

fn render_hosted_http_config(options: &ClientConfigOptions, server_name: &str) -> String {
    let url = options
        .url
        .clone()
        .unwrap_or_else(|| DEFAULT_HOSTED_HTTP_MCP_URL.to_string());

    format!(
        "[mcp_servers.{}]\nurl = \"{}\"\n",
        toml_string(server_name),
        toml_string_value(&url),
    )
}

fn package_name_from_manifest(root: &Path) -> Result<String, ClientConfigError> {
    let manifest = root.join("Cargo.toml");
    let contents = fs::read_to_string(&manifest).map_err(|source| ClientConfigError::Io {
        path: manifest.clone(),
        source,
    })?;

    let mut in_package = false;
    for line in contents.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let table_name = trimmed[1..trimmed.len() - 1].trim();
            in_package = table_name == "package";
            continue;
        }

        if !in_package {
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() == "name" {
            if let Some(value) = quoted_value(value.trim()) {
                return Ok(value.to_string());
            }
        }
    }

    Err(ClientConfigError::MissingPackageName(manifest))
}

fn quoted_value(value: &str) -> Option<&str> {
    if let Some(stripped) = value.strip_prefix('"') {
        stripped.split('"').next()
    } else if let Some(stripped) = value.strip_prefix('\'') {
        stripped.split('\'').next()
    } else {
        None
    }
}

fn toml_string(value: &str) -> String {
    format!("\"{}\"", toml_string_value(value))
}

fn toml_string_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

impl Default for ClientConfigOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            server_name: None,
            transport: None,
            command: None,
            installed: false,
            url: None,
            profile: READ_ONLY_PROFILE_KEY.to_string(),
            env_key: None,
            env_value: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn executable_configs_round_trip_without_source_tree_or_invented_environment() {
        let name = "archive \\\"資料";
        let command = Path::new("C:\\MCP tools\\archive \\\"資料.exe");
        for format in [
            ClientConfigFormat::CodexToml,
            ClientConfigFormat::McpServersJson,
        ] {
            let rendered = render_executable_client_config(name, command, format, &[]).unwrap();
            match format {
                ClientConfigFormat::CodexToml => {
                    let parsed = rendered.parse::<toml_edit::DocumentMut>().unwrap();
                    let server = &parsed["mcp_servers"][name];
                    assert_eq!(server["command"].as_str(), command.to_str());
                    assert!(server["args"].as_array().unwrap().is_empty());
                    assert!(server.get("env").is_none());
                }
                ClientConfigFormat::McpServersJson => {
                    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
                    let server = &parsed["mcpServers"][name];
                    assert_eq!(server["command"].as_str(), command.to_str());
                    assert_eq!(server["args"], serde_json::json!([]));
                    assert!(server.get("env").is_none());
                }
            }
        }
    }

    #[test]
    fn executable_config_only_renders_explicit_environment_in_stable_order() {
        let environment = [("Z_LAST", ""), ("ARCHIVE_PROFILE", "read_only")];
        let toml = render_executable_client_config(
            "archive",
            Path::new("archive"),
            ClientConfigFormat::CodexToml,
            &environment,
        )
        .unwrap();
        let parsed = toml.parse::<toml_edit::DocumentMut>().unwrap();
        let env = &parsed["mcp_servers"]["archive"]["env"];
        assert_eq!(env["ARCHIVE_PROFILE"].as_str(), Some("read_only"));
        assert_eq!(env["Z_LAST"].as_str(), Some(""));
        assert!(toml.find("ARCHIVE_PROFILE").unwrap() < toml.find("Z_LAST").unwrap());
        let json = render_executable_client_config(
            "archive",
            Path::new("archive"),
            ClientConfigFormat::McpServersJson,
            &environment,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["mcpServers"]["archive"]["env"],
            serde_json::json!({
                "ARCHIVE_PROFILE": "read_only", "Z_LAST": "",
            })
        );
    }

    #[test]
    fn executable_config_rejects_ambiguous_or_unsafe_inputs_without_echoing_them() {
        for format in [
            ClientConfigFormat::CodexToml,
            ClientConfigFormat::McpServersJson,
        ] {
            for (name, path, env) in [
                ("", "archive", vec![]),
                ("archive", "", vec![]),
                ("secret-canary\n", "archive", vec![]),
                ("archive", "secret-canary\0", vec![]),
                ("archive", "archive", vec![("secret-canary", "value")]),
                ("archive", "archive", vec![("PROFILE", "secret-canary\n")]),
                (
                    "archive",
                    "archive",
                    vec![("PROFILE", "one"), ("PROFILE", "two")],
                ),
            ] {
                let error = render_executable_client_config(name, Path::new(path), format, &env)
                    .unwrap_err();
                assert!(!error.to_string().contains("secret-canary"));
                assert!(!format!("{error:?}").contains("secret-canary"));
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn executable_config_rejects_non_unicode_paths_without_lossy_replacement() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/private-\xff"));
        assert_eq!(
            render_executable_client_config(
                "archive",
                path,
                ClientConfigFormat::McpServersJson,
                &[],
            )
            .unwrap_err(),
            ExecutableClientConfigError::NonUnicodeExecutable
        );
    }

    fn project_legacy() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = PathBuf::from(format!(
            "/tmp/mcp-toolkit-client-config-legacy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = 'demo-server'\nversion = '0.1.0'\n",
        )
        .unwrap();
        root
    }

    fn project_overrides() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = PathBuf::from(format!(
            "/tmp/mcp-toolkit-client-config-overrides-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = 'demo-server'\nversion = '0.1.0'\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn defaults_preserve_legacy_profile_and_local_binary() {
        let root = project_legacy();
        let output = render_client_config(&ClientConfigOptions {
            root: root.clone(),
            transport: Some(ClientConfigTransport::Stdio),
            ..Default::default()
        })
        .unwrap();
        assert!(output.contains("target/release/demo-server"));
        assert!(output.contains("DEMO_SERVER_TOOL_PROFILE = \"read_only\""));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn installed_and_environment_overrides_are_rendered() {
        let root = project_overrides();
        let output = render_client_config(&ClientConfigOptions {
            root: root.clone(),
            transport: Some(ClientConfigTransport::Stdio),
            installed: true,
            env_key: Some("DEMO_PROFILE".into()),
            env_value: Some("operator".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(output.contains("command = \"demo-server\""));
        assert!(output.contains("DEMO_PROFILE = \"operator\""));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn control_characters_are_rejected_from_rendered_fields() {
        let root = project_overrides();
        let error = render_client_config(&ClientConfigOptions {
            root,
            transport: Some(ClientConfigTransport::Stdio),
            env_value: Some("operator\ninjected = true".into()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(error, ClientConfigError::InvalidEnvValue));
    }
}

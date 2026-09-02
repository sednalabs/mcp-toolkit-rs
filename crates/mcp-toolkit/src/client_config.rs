//! # MCP Toolkit Client Configuration Renderer
//!
//! Renders copyable MCP client configuration snippets for generated Rust MCP
//! server projects.
//!
//! ## Rationale
//! Generated servers should not leave operators to hand-translate a package
//! name, binary path, profile environment variable, or hosted MCP URL into each
//! client's configuration shape. This module keeps the first client-config
//! helper deterministic and filesystem-only.
//!
//! ## Security Boundaries
//! * Reads only the generated project's `Cargo.toml` package name.
//! * Does not execute generated code or inspect credential material.
//! * Emits no secrets; profile and URL values come from caller-supplied options
//!   or starter-template defaults.
//!
//! ## References
//! * `docs/provider-auth-and-client-config.md`
//! * `docs/easy-server-ergonomics.md`

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
    if let Some(value) = options.env_value.as_deref().or(Some(options.profile.as_str())) {
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

    fn project(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("mcp-toolkit-client-config-{name}"));
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
        let root = project("legacy");
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
        let root = project("overrides");
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
}

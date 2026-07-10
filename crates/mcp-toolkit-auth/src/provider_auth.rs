//! # Provider Auth Diagnostics
//!
//! Status and troubleshooting primitives for MCP servers that call upstream
//! provider APIs on behalf of an operator.
//!
//! ## Ownership
//! This module owns provider-auth status shapes and low-leakage remediation
//! text. It keeps upstream API credential diagnostics separate from inbound MCP
//! client authentication.
//!
//! ## Non-ownership
//! This module does not load provider credentials, exchange OAuth tokens, call
//! provider APIs, or decide service-specific resource permissions.
//!
//! ## Policy & Guarantees
//! * Status values are serializable without including credential material.
//! * Google ADC helpers include `cloud-platform` with provider-specific scopes.
//! * Error classification returns stable machine-readable kinds plus next steps.
//!
//! ## Caller Responsibility
//! Callers are responsible for probing the upstream provider, redacting raw
//! provider responses before exposing them, and enforcing tool-level profiles.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Google scope required by local ADC for several Google APIs.
pub const GOOGLE_CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Stable category for a provider-auth credential source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialSourceKind {
    /// Provider-standard Application Default Credentials.
    ApplicationDefaultCredentials,
    /// Service-account credentials loaded from a file path.
    ServiceAccountFile,
    /// Service-account credentials loaded from an environment payload.
    ServiceAccountJson,
    /// OAuth client credentials supplied for a browser or refresh-token flow.
    OAuthClient,
    /// Refresh-token cache managed by the server or toolkit.
    RefreshTokenCache,
    /// Cloud runtime metadata-service credentials.
    MetadataService,
    /// Provider-specific or server-specific source.
    Other,
}

/// Secret-safe status for one credential source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCredentialSourceStatus {
    /// Credential source kind.
    pub kind: ProviderCredentialSourceKind,
    /// True when credential material or a cache marker was detected.
    pub present: bool,
    /// Optional redacted path or path hint.
    #[serde(rename = "path", skip_serializing_if = "Option::is_none")]
    pub path_hint: Option<String>,
    /// Optional environment variable name that controls this source.
    #[serde(rename = "env", skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Optional public note. Do not include secret-bearing values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ProviderCredentialSourceStatus {
    /// Builds a credential-source status with no optional hints.
    ///
    /// # Security
    /// `kind` and `present` are safe to expose. Add only redacted path or
    /// environment-variable names through the builder helpers.
    pub fn new(kind: ProviderCredentialSourceKind, present: bool) -> Self {
        Self {
            kind,
            present,
            path_hint: None,
            env_var: None,
            note: None,
        }
    }

    /// Adds a redacted or user-home-relative path hint.
    ///
    /// # Security
    /// Callers must not pass raw private paths when status output may be shown
    /// outside the operator's trusted environment.
    pub fn with_path_hint(mut self, path_hint: impl Into<String>) -> Self {
        self.path_hint = Some(path_hint.into());
        self
    }

    /// Adds the environment variable that configures this source.
    pub fn with_env_var(mut self, env_var: impl Into<String>) -> Self {
        self.env_var = Some(env_var.into());
        self
    }

    /// Adds a public operator-facing note.
    ///
    /// # Security
    /// Keep notes free of tokens, credential JSON, bearer headers, private keys,
    /// authorization codes, email addresses, and raw provider responses.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Provider-auth quota-project status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderQuotaProjectStatus {
    /// True when the upstream provider quota/billing project is configured.
    pub configured: bool,
    /// Optional redacted project hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_hint: Option<String>,
    /// Optional source label such as an environment variable or ADC metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional redacted error message explaining why the status is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProviderQuotaProjectStatus {
    /// Reports an absent quota project.
    pub fn missing() -> Self {
        Self {
            configured: false,
            project_hint: None,
            source: None,
            error: None,
        }
    }

    /// Reports a configured quota project using a redacted or public-safe hint.
    pub fn configured(project_hint: impl Into<String>) -> Self {
        Self {
            configured: true,
            project_hint: Some(project_hint.into()),
            source: None,
            error: None,
        }
    }

    /// Adds a public source label.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Adds a redacted error message.
    ///
    /// # Security
    /// Callers must redact paths, tokens, credential JSON, and provider
    /// responses before passing `error` when output may leave the operator's
    /// trusted environment.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

/// Stable provider-auth verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAuthVerification {
    /// True when a verification probe succeeded.
    pub ok: bool,
    /// Stable machine-readable result kind.
    pub kind: String,
    /// Public operator-facing summary.
    pub message: String,
}

impl ProviderAuthVerification {
    /// Builds a successful verification result.
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            kind: "ok".to_string(),
            message: message.into(),
        }
    }

    /// Builds a failed verification result.
    pub fn failed(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            kind: kind.into(),
            message: message.into(),
        }
    }
}

/// Stable secret-safe check result for provider-auth status tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderAuthCheckStatus {
    /// True when the server attempted the check.
    pub checked: bool,
    /// Probe outcome when a check was attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    /// Public reason when a check was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Redacted public error when a check failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional public remediation hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Product-specific safe metadata for the check.
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

impl ProviderAuthCheckStatus {
    /// Builds a skipped check result.
    pub fn skipped() -> Self {
        Self {
            checked: false,
            ok: None,
            reason: None,
            error: None,
            hint: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Builds a successful checked result.
    pub fn ok() -> Self {
        Self {
            checked: true,
            ok: Some(true),
            reason: None,
            error: None,
            hint: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Builds a failed checked result.
    ///
    /// # Security
    /// `error` must already be redacted. Do not pass bearer tokens, refresh
    /// tokens, private keys, credential JSON, authorization codes, or raw
    /// provider responses.
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            checked: true,
            ok: Some(false),
            reason: None,
            error: Some(error.into()),
            hint: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Adds a public skipped-check reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Adds a public remediation hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Adds one product-specific metadata field.
    ///
    /// # Security
    /// Metadata must be secret-safe. Do not include tokens, private keys,
    /// client secrets, credential JSON, authorization codes, or raw provider
    /// responses.
    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Secret-safe provider-auth status shape for MCP tools or CLIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAuthStatus {
    /// Whether the server should attempt provider-backed data tools.
    pub ready: bool,
    /// Optional selected tool profile, such as `read_only` or `operator`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Credential sources considered by the server.
    pub credential_sources: Vec<ProviderCredentialSourceStatus>,
    /// Required provider scopes for the selected profile.
    pub scopes: Vec<String>,
    /// Provider quota/billing project status, when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_project: Option<ProviderQuotaProjectStatus>,
    /// Last verification probe result, when a probe was run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verification: Option<ProviderAuthVerification>,
    /// Ordered operator next steps.
    pub next_steps: Vec<String>,
}

impl ProviderAuthStatus {
    /// Builds a provider-auth status from required scopes.
    ///
    /// # Security
    /// The status is intended for operator-facing diagnostics. Callers must only
    /// add credential-source hints and verification messages that are safe to
    /// show without leaking credential material.
    pub fn new(ready: bool, scopes: Vec<String>) -> Self {
        Self {
            ready,
            profile: None,
            credential_sources: Vec::new(),
            scopes,
            quota_project: None,
            last_verification: None,
            next_steps: Vec::new(),
        }
    }

    /// Adds the selected tool profile.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Adds credential-source statuses.
    pub fn with_credential_sources(
        mut self,
        credential_sources: Vec<ProviderCredentialSourceStatus>,
    ) -> Self {
        self.credential_sources = credential_sources;
        self
    }

    /// Adds quota-project status.
    pub fn with_quota_project(mut self, quota_project: ProviderQuotaProjectStatus) -> Self {
        self.quota_project = Some(quota_project);
        self
    }

    /// Adds the latest verification result.
    pub fn with_last_verification(mut self, verification: ProviderAuthVerification) -> Self {
        self.last_verification = Some(verification);
        self
    }

    /// Adds ordered operator next steps.
    pub fn with_next_steps(mut self, next_steps: Vec<String>) -> Self {
        self.next_steps = next_steps;
        self
    }
}

/// Secret-safe provider-auth command rendered for operator setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAuthCommand {
    /// Argument vector suitable for process execution.
    pub argv: Vec<String>,
    /// Copyable shell representation for docs, CLIs, and MCP diagnostics.
    pub shell: String,
}

impl ProviderAuthCommand {
    /// Builds a command from an argument vector and renders a shell-safe display
    /// string.
    ///
    /// # Security
    /// Only pass public setup arguments. Do not include tokens, authorization
    /// codes, client secrets, private keys, or credential JSON payloads.
    pub fn new(argv: Vec<String>) -> Self {
        let shell = format_provider_auth_command(&argv);
        Self { argv, shell }
    }
}

/// Google ADC setup plan for operator-facing auth tools and documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleProviderAuthSetupPlan {
    /// Human-readable API name, such as `Search Console API`.
    pub api_name: String,
    /// ADC login scopes, including `cloud-platform`.
    pub scopes: Vec<String>,
    /// Browser-capable ADC login command.
    pub login: ProviderAuthCommand,
    /// Headless-friendly ADC login command.
    pub headless_login: ProviderAuthCommand,
    /// ADC login command with a client-id file fallback.
    pub login_with_client_id_file: ProviderAuthCommand,
    /// Headless-friendly ADC login command with a client-id file fallback.
    pub headless_login_with_client_id_file: ProviderAuthCommand,
    /// ADC quota-project command.
    pub quota_project: ProviderAuthCommand,
    /// API enablement command, when the Google service name is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_enable: Option<ProviderAuthCommand>,
    /// Ordered safe next-step summaries.
    pub next_steps: Vec<String>,
    /// Safe notes for common Google auth footguns.
    pub notes: Vec<String>,
}

/// Canonical Google ADC login helper response for MCP auth tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleProviderAuthLoginCommand {
    /// Primary login argv for the requested mode.
    pub command: Vec<String>,
    /// Primary login shell command for copy/paste use.
    pub shell_command: String,
    /// Headless login argv.
    pub headless_command: Vec<String>,
    /// Headless login shell command for copy/paste use.
    pub headless_shell_command: String,
    /// Browser-capable login argv with the client-id-file placeholder.
    pub client_id_file_command: Vec<String>,
    /// Browser-capable login shell command with the client-id-file placeholder.
    pub client_id_file_shell_command: String,
    /// Headless login argv with the client-id-file placeholder.
    pub client_id_file_headless_command: Vec<String>,
    /// Headless login shell command with the client-id-file placeholder.
    pub client_id_file_headless_shell_command: String,
    /// ADC quota-project shell command using the configured placeholder.
    pub quota_project_command: String,
    /// ADC quota-project argv using the configured placeholder.
    pub quota_project_command_argv: Vec<String>,
    /// Optional API enablement shell command.
    pub api_enable_command: Option<String>,
    /// Optional API enablement argv.
    pub api_enable_command_argv: Option<Vec<String>>,
    /// Follow-up shell commands customized for this request.
    pub follow_up_commands: Vec<String>,
    /// ADC login scopes.
    pub adc_scopes: Vec<String>,
    /// Optional Cloud SDK config directory used for server-specific ADC.
    pub cloudsdk_config: Option<String>,
    /// Optional ADC credential file path.
    pub credential_file: Option<String>,
    /// True when the conventional shared ADC file is intentionally targeted.
    pub shared_adc: bool,
    /// Requested provider scope string.
    pub scope: String,
    /// True when the request intentionally targets the operator/write scope.
    pub operator_scope_requested: bool,
    /// Optional quota project supplied with this request.
    pub quota_project: Option<String>,
    /// Ordered safe next-step summaries.
    pub next_steps: Vec<String>,
    /// Safe notes for common Google auth footguns.
    pub notes: Vec<String>,
    /// Restart or verification instruction after login.
    pub after_login: String,
}

/// Inputs for building a Google ADC login helper response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleProviderAuthLoginOptions {
    /// Requested provider scope string.
    pub scope: String,
    /// Whether the primary command should be headless.
    pub headless: bool,
    /// Optional request-specific OAuth client-id file.
    pub client_id_file: Option<String>,
    /// Optional quota project supplied with this request.
    pub quota_project: Option<String>,
    /// Optional Cloud SDK config directory used for server-specific ADC.
    pub cloudsdk_config: Option<String>,
    /// Optional ADC credential file path.
    pub credential_file: Option<String>,
    /// True when the conventional shared ADC file is intentionally targeted.
    pub shared_adc: bool,
    /// True when the request intentionally targets the operator/write scope.
    pub operator_scope_requested: bool,
    /// Safe notes for common Google auth footguns.
    pub notes: Vec<String>,
    /// Restart or verification instruction after login.
    pub after_login: String,
}

impl GoogleProviderAuthLoginOptions {
    /// Builds login-helper options for a scope.
    ///
    /// # Security
    /// Fields are serialized in operator-facing auth output. Do not include
    /// tokens, client secrets, credential JSON, or private keys.
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            headless: false,
            client_id_file: None,
            quota_project: None,
            cloudsdk_config: None,
            credential_file: None,
            shared_adc: false,
            operator_scope_requested: false,
            notes: Vec::new(),
            after_login: "Restart stdio MCP clients that keep long-lived server processes, then call auth_status with verification enabled.".to_string(),
        }
    }

    /// Sets whether the primary command should be headless.
    pub fn with_headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    /// Adds an OAuth client-id file path for the primary command.
    pub fn with_client_id_file(mut self, client_id_file: impl Into<String>) -> Self {
        self.client_id_file = Some(client_id_file.into());
        self
    }

    /// Adds a quota project to follow-up commands.
    pub fn with_quota_project(mut self, quota_project: impl Into<String>) -> Self {
        self.quota_project = Some(quota_project.into());
        self
    }

    /// Adds a Cloud SDK config directory for server-specific ADC.
    pub fn with_cloudsdk_config(mut self, cloudsdk_config: impl Into<String>) -> Self {
        self.cloudsdk_config = Some(cloudsdk_config.into());
        self
    }

    /// Adds the target ADC credential file path.
    pub fn with_credential_file(mut self, credential_file: impl Into<String>) -> Self {
        self.credential_file = Some(credential_file.into());
        self
    }

    /// Marks whether shared ADC is intentionally targeted.
    pub fn with_shared_adc(mut self, shared_adc: bool) -> Self {
        self.shared_adc = shared_adc;
        self
    }

    /// Marks whether an operator/write scope is requested.
    pub fn with_operator_scope_requested(mut self, operator_scope_requested: bool) -> Self {
        self.operator_scope_requested = operator_scope_requested;
        self
    }

    /// Adds safe operator-facing notes.
    pub fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }

    /// Adds the post-login instruction.
    pub fn with_after_login(mut self, after_login: impl Into<String>) -> Self {
        self.after_login = after_login.into();
        self
    }
}

/// Google provider-auth configuration used to build diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleProviderAuthConfig {
    /// Human-readable API name, such as `Search Console API`.
    pub api_name: String,
    /// Required provider scopes, excluding `cloud-platform`.
    pub provider_scopes: Vec<String>,
    /// Google Cloud API service names, such as `searchconsole.googleapis.com`.
    pub api_service_names: Vec<String>,
    /// Placeholder or redacted quota project label used in next steps.
    pub quota_project_placeholder: String,
}

impl GoogleProviderAuthConfig {
    /// Builds a Google provider-auth configuration.
    ///
    /// # Security
    /// This config carries public labels and scope strings only. Do not use a
    /// sensitive project id as `quota_project_placeholder` in public responses.
    pub fn new(api_name: impl Into<String>, provider_scopes: Vec<String>) -> Self {
        Self {
            api_name: api_name.into(),
            provider_scopes,
            api_service_names: Vec::new(),
            quota_project_placeholder: "YOUR_PROJECT".to_string(),
        }
    }

    /// Adds the Google API service name used by `gcloud services enable`.
    pub fn with_api_service_name(mut self, api_service_name: impl Into<String>) -> Self {
        extend_unique_api_services(&mut self.api_service_names, [api_service_name.into()]);
        self
    }

    /// Adds one or more Google API service names used by `gcloud services enable`.
    pub fn with_api_service_names<I, S>(mut self, api_service_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        extend_unique_api_services(&mut self.api_service_names, api_service_names);
        self
    }

    /// Sets the quota-project placeholder used in next-step commands.
    pub fn with_quota_project_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.quota_project_placeholder = placeholder.into();
        self
    }

    /// Returns ADC login scopes with `cloud-platform` prepended and duplicates removed.
    pub fn adc_login_scopes(&self) -> Vec<String> {
        google_adc_login_scopes(self.provider_scopes.iter().map(String::as_str))
    }

    /// Returns the `gcloud auth application-default login` command argv.
    pub fn adc_login_command(&self, headless: bool) -> Vec<String> {
        google_adc_login_command(self.provider_scopes.iter().map(String::as_str), headless)
    }

    /// Returns the ADC login command with a Google OAuth client-id file.
    pub fn adc_login_command_with_client_id_file(
        &self,
        headless: bool,
        client_id_file: &str,
    ) -> Vec<String> {
        google_adc_login_command_with_client_id_file(
            self.provider_scopes.iter().map(String::as_str),
            headless,
            client_id_file,
        )
    }

    /// Returns the ADC quota-project command argv.
    pub fn adc_quota_project_command(&self) -> Vec<String> {
        google_adc_quota_project_command(&self.quota_project_placeholder)
    }

    /// Returns the API enablement command argv, when this config knows the API
    /// service name.
    pub fn api_enable_command(&self) -> Option<Vec<String>> {
        self.api_service_names
            .iter()
            .any(|service| !service.trim().is_empty())
            .then(|| {
                google_api_enable_command_multi(
                    self.api_service_names.iter().map(String::as_str),
                    &self.quota_project_placeholder,
                )
            })
    }

    /// Builds a serializable Google ADC setup plan for CLI/MCP auth tools.
    pub fn adc_setup_plan(&self) -> GoogleProviderAuthSetupPlan {
        let client_id_file_placeholder = "/path/to/client_id.json";
        let login = ProviderAuthCommand::new(self.adc_login_command(false));
        let headless_login = ProviderAuthCommand::new(self.adc_login_command(true));
        let login_with_client_id_file = ProviderAuthCommand::new(
            self.adc_login_command_with_client_id_file(false, client_id_file_placeholder),
        );
        let headless_login_with_client_id_file = ProviderAuthCommand::new(
            self.adc_login_command_with_client_id_file(true, client_id_file_placeholder),
        );
        let quota_project = ProviderAuthCommand::new(self.adc_quota_project_command());
        let api_enable = self.api_enable_command().map(ProviderAuthCommand::new);
        let mut next_steps = vec![
            "run the browser login command, or the headless command on SSH hosts".to_string(),
            "set an ADC quota project if Google reports that local ADC requires one".to_string(),
        ];
        if api_enable.is_some() {
            next_steps.push("enable the required Google API on the quota project".to_string());
        }
        next_steps.push("rerun auth_status or auth_probe after changing credentials".to_string());

        GoogleProviderAuthSetupPlan {
            api_name: self.api_name.clone(),
            scopes: self.adc_login_scopes(),
            login,
            headless_login,
            login_with_client_id_file,
            headless_login_with_client_id_file,
            quota_project,
            api_enable,
            next_steps,
            notes: vec![
                "Use the client-id-file command if Google rejects the provider scope during ADC login.".to_string(),
                "For unattended deployments, prefer service-account or workload identity credentials over local user ADC.".to_string(),
            ],
        }
    }

    /// Builds the canonical Google ADC login helper response.
    pub fn adc_login_command_contract(
        &self,
        options: &GoogleProviderAuthLoginOptions,
    ) -> GoogleProviderAuthLoginCommand {
        let client_id_file_placeholder = "/path/to/client_id.json";
        let command = match options.client_id_file.as_deref() {
            Some(client_id_file) => {
                self.adc_login_command_with_client_id_file(options.headless, client_id_file)
            }
            None => self.adc_login_command(options.headless),
        };
        let headless_command = match options.client_id_file.as_deref() {
            Some(client_id_file) => {
                self.adc_login_command_with_client_id_file(true, client_id_file)
            }
            None => self.adc_login_command(true),
        };
        let client_id_file_command =
            self.adc_login_command_with_client_id_file(false, client_id_file_placeholder);
        let client_id_file_headless_command =
            self.adc_login_command_with_client_id_file(true, client_id_file_placeholder);
        let quota_project_command_argv = self.adc_quota_project_command();
        let api_enable_command_argv = self.api_enable_command();
        let cloudsdk_config = options.cloudsdk_config.as_deref();
        let follow_up_commands = options
            .quota_project
            .as_deref()
            .map(|project| {
                vec![format_google_cloudsdk_command(
                    &google_adc_quota_project_command(project),
                    cloudsdk_config,
                )]
            })
            .unwrap_or_default();

        GoogleProviderAuthLoginCommand {
            command: command.clone(),
            shell_command: format_google_cloudsdk_command(&command, cloudsdk_config),
            headless_command: headless_command.clone(),
            headless_shell_command: format_google_cloudsdk_command(
                &headless_command,
                cloudsdk_config,
            ),
            client_id_file_command: client_id_file_command.clone(),
            client_id_file_shell_command: format_google_cloudsdk_command(
                &client_id_file_command,
                cloudsdk_config,
            ),
            client_id_file_headless_command: client_id_file_headless_command.clone(),
            client_id_file_headless_shell_command: format_google_cloudsdk_command(
                &client_id_file_headless_command,
                cloudsdk_config,
            ),
            quota_project_command: format_google_cloudsdk_command(
                &quota_project_command_argv,
                cloudsdk_config,
            ),
            quota_project_command_argv,
            api_enable_command: api_enable_command_argv
                .as_ref()
                .map(|command| format_provider_auth_command(command)),
            api_enable_command_argv,
            follow_up_commands,
            adc_scopes: self.adc_login_scopes(),
            cloudsdk_config: options.cloudsdk_config.clone(),
            credential_file: options.credential_file.clone(),
            shared_adc: options.shared_adc,
            scope: options.scope.clone(),
            operator_scope_requested: options.operator_scope_requested,
            quota_project: options.quota_project.clone(),
            next_steps: self.adc_setup_plan().next_steps,
            notes: options.notes.clone(),
            after_login: options.after_login.clone(),
        }
    }
}

/// Stable Google provider-auth failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleProviderAuthFailureKind {
    /// No credential source was detected.
    MissingCredentials,
    /// The credential lacks one or more required OAuth scopes.
    MissingScope,
    /// Google ADC has no quota project.
    MissingQuotaProject,
    /// The required Google API is not enabled on the quota project.
    ApiDisabled,
    /// The authenticated principal lacks provider-side permission.
    PermissionDenied,
    /// Google rejected the OAuth app or consent flow.
    OAuthAppBlocked,
    /// The local OAuth grant is stale, revoked, or invalid.
    ReauthRequired,
    /// The provider response did not match a known category.
    Unknown,
}

impl GoogleProviderAuthFailureKind {
    /// Returns a stable lowercase string for status output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredentials => "missing_credentials",
            Self::MissingScope => "missing_scope",
            Self::MissingQuotaProject => "missing_quota_project",
            Self::ApiDisabled => "api_disabled",
            Self::PermissionDenied => "permission_denied",
            Self::OAuthAppBlocked => "oauth_app_blocked",
            Self::ReauthRequired => "reauth_required",
            Self::Unknown => "unknown",
        }
    }
}

/// Google provider-auth diagnostic with stable kind and operator next steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleProviderAuthDiagnostic {
    /// Stable failure category.
    pub kind: GoogleProviderAuthFailureKind,
    /// Public operator-facing summary.
    pub message: String,
    /// Ordered remediation steps.
    pub next_steps: Vec<String>,
}

impl GoogleProviderAuthDiagnostic {
    /// Converts this diagnostic into a provider-auth verification value.
    pub fn verification(&self) -> ProviderAuthVerification {
        ProviderAuthVerification::failed(self.kind.as_str(), self.message.clone())
    }
}

/// Returns Google ADC login scopes with `cloud-platform` included once.
pub fn google_adc_login_scopes<'a>(
    provider_scopes: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let mut scopes = vec![GOOGLE_CLOUD_PLATFORM_SCOPE.to_string()];
    extend_unique_scopes(&mut scopes, provider_scopes);
    scopes
}

/// Returns the `gcloud auth application-default login` command argv.
pub fn google_adc_login_command<'a>(
    provider_scopes: impl IntoIterator<Item = &'a str>,
    headless: bool,
) -> Vec<String> {
    let scopes = google_adc_login_scopes(provider_scopes).join(",");
    let mut command = vec![
        "gcloud".to_string(),
        "auth".to_string(),
        "application-default".to_string(),
        "login".to_string(),
        format!("--scopes={scopes}"),
    ];
    if headless {
        command.push("--no-launch-browser".to_string());
    }
    command
}

/// Returns the `gcloud auth application-default login` command argv with a
/// client-id file fallback.
pub fn google_adc_login_command_with_client_id_file<'a>(
    provider_scopes: impl IntoIterator<Item = &'a str>,
    headless: bool,
    client_id_file: &str,
) -> Vec<String> {
    let mut command = google_adc_login_command(provider_scopes, false);
    if headless {
        command.push("--no-browser".to_string());
    }
    command.push("--client-id-file".to_string());
    command.push(client_id_file_or_default(client_id_file).to_string());
    command
}

/// Returns the `gcloud auth application-default set-quota-project` command argv.
pub fn google_adc_quota_project_command(project_placeholder: &str) -> Vec<String> {
    vec![
        "gcloud".to_string(),
        "auth".to_string(),
        "application-default".to_string(),
        "set-quota-project".to_string(),
        placeholder_or_default(project_placeholder).to_string(),
    ]
}

/// Returns the `gcloud services enable` command argv for a Google API.
pub fn google_api_enable_command(api_service_name: &str, project_placeholder: &str) -> Vec<String> {
    google_api_enable_command_multi([api_service_name], project_placeholder)
}

/// Returns the `gcloud services enable` command argv for one or more Google APIs.
pub fn google_api_enable_command_multi<'a>(
    api_service_names: impl IntoIterator<Item = &'a str>,
    project_placeholder: &str,
) -> Vec<String> {
    let mut command = vec![
        "gcloud".to_string(),
        "services".to_string(),
        "enable".to_string(),
    ];
    let mut services = Vec::new();
    extend_unique_api_services(&mut services, api_service_names);
    command.extend(services);
    command.extend([
        "--project".to_string(),
        placeholder_or_default(project_placeholder).to_string(),
    ]);
    command
}

fn extend_unique_api_services<I, S>(services: &mut Vec<String>, api_service_names: I)
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    for api_service_name in api_service_names {
        let api_service_name = api_service_name.into();
        let trimmed = api_service_name.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !services.iter().any(|existing| existing == trimmed) {
            services.push(trimmed.to_string());
        }
    }
}

/// Builds standard next steps for a missing Google ADC quota project.
pub fn google_quota_project_next_steps(project_placeholder: &str) -> Vec<String> {
    vec![
        format_command(google_adc_quota_project_command(project_placeholder)),
        "ensure the required Google API is enabled on that project".to_string(),
        "rerun auth_status or auth_probe after updating the quota project".to_string(),
    ]
}

/// Classifies a Google API auth error into a stable provider-auth diagnostic.
///
/// # Security
/// `response_body` may contain provider details. The returned diagnostic uses
/// only generic public messages and commands; callers should not echo the raw
/// response body in MCP tool output.
pub fn classify_google_provider_auth_error(
    status_code: u16,
    response_body: &str,
    config: &GoogleProviderAuthConfig,
) -> GoogleProviderAuthDiagnostic {
    let signals = GoogleErrorSignals::from_body(response_body);
    let text = signals.normalized_text();
    let kind = classify_google_failure_kind(status_code, &signals, &text);
    let next_steps = google_next_steps(kind, config);
    let message = google_failure_message(kind, config);
    GoogleProviderAuthDiagnostic {
        kind,
        message,
        next_steps,
    }
}

fn extend_unique_scopes<'a>(
    scopes: &mut Vec<String>,
    provider_scopes: impl IntoIterator<Item = &'a str>,
) {
    for scope in provider_scopes {
        let trimmed = scope.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !scopes.iter().any(|existing| existing == trimmed) {
            scopes.push(trimmed.to_string());
        }
    }
}

fn placeholder_or_default(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "YOUR_PROJECT"
    } else {
        trimmed
    }
}

fn client_id_file_or_default(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "/path/to/client_id.json"
    } else {
        trimmed
    }
}

#[derive(Debug, Default)]
struct GoogleErrorSignals {
    messages: Vec<String>,
    reasons: Vec<String>,
    statuses: Vec<String>,
}

impl GoogleErrorSignals {
    fn from_body(body: &str) -> Self {
        let mut signals = Self::default();
        signals.messages.push(body.to_string());
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
            collect_google_error_signals(&value, &mut signals);
        }
        signals
    }

    fn normalized_text(&self) -> String {
        let mut text = String::new();
        for value in self
            .messages
            .iter()
            .chain(self.reasons.iter())
            .chain(self.statuses.iter())
        {
            text.push_str(value);
            text.push('\n');
        }
        text.to_ascii_lowercase()
    }

    fn has_reason(&self, reason: &str) -> bool {
        self.reasons
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(reason))
    }

    fn has_status(&self, status: &str) -> bool {
        self.statuses
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(status))
    }
}

fn collect_google_error_signals(value: &serde_json::Value, signals: &mut GoogleErrorSignals) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                match (key.as_str(), value) {
                    ("message", serde_json::Value::String(message)) => {
                        signals.messages.push(message.clone());
                    }
                    ("reason", serde_json::Value::String(reason)) => {
                        signals.reasons.push(reason.clone());
                    }
                    ("status", serde_json::Value::String(status)) => {
                        signals.statuses.push(status.clone());
                    }
                    _ => collect_google_error_signals(value, signals),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_google_error_signals(item, signals);
            }
        }
        _ => {}
    }
}

fn classify_google_failure_kind(
    status_code: u16,
    signals: &GoogleErrorSignals,
    text: &str,
) -> GoogleProviderAuthFailureKind {
    if contains_all(text, &["quota project", "not set"])
        || contains_all(text, &["requires a quota project"])
    {
        return GoogleProviderAuthFailureKind::MissingQuotaProject;
    }
    if text.contains("insufficient authentication scopes")
        || text.contains("insufficient_scope")
        || text.contains("invalid_scope")
        || signals.has_reason("ACCESS_TOKEN_SCOPE_INSUFFICIENT")
        || signals.has_status("PERMISSION_DENIED") && text.contains("scope")
    {
        return GoogleProviderAuthFailureKind::MissingScope;
    }
    if signals.has_reason("SERVICE_DISABLED")
        || signals.has_reason("accessNotConfigured")
        || text.contains("api has not been used")
        || contains_all(text, &["api", "disabled"])
    {
        return GoogleProviderAuthFailureKind::ApiDisabled;
    }
    if text.contains("app is blocked")
        || text.contains("access blocked")
        || text.contains("blocked this access")
    {
        return GoogleProviderAuthFailureKind::OAuthAppBlocked;
    }
    if text.contains("invalid_grant")
        || text.contains("token has been expired or revoked")
        || text.contains("reauth")
    {
        return GoogleProviderAuthFailureKind::ReauthRequired;
    }
    if status_code == 401 || text.contains("could not load the default credentials") {
        return GoogleProviderAuthFailureKind::MissingCredentials;
    }
    if status_code == 403 || signals.has_status("PERMISSION_DENIED") {
        return GoogleProviderAuthFailureKind::PermissionDenied;
    }
    GoogleProviderAuthFailureKind::Unknown
}

fn contains_all(text: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| text.contains(needle))
}

fn google_failure_message(
    kind: GoogleProviderAuthFailureKind,
    config: &GoogleProviderAuthConfig,
) -> String {
    match kind {
        GoogleProviderAuthFailureKind::MissingCredentials => {
            format!(
                "No Google credentials were detected for {}.",
                config.api_name
            )
        }
        GoogleProviderAuthFailureKind::MissingScope => {
            format!(
                "Google credentials are missing a required {} scope.",
                config.api_name
            )
        }
        GoogleProviderAuthFailureKind::MissingQuotaProject => {
            "Google ADC is missing a quota project.".to_string()
        }
        GoogleProviderAuthFailureKind::ApiDisabled => {
            format!(
                "The required Google API is not enabled for {}.",
                config.api_name
            )
        }
        GoogleProviderAuthFailureKind::PermissionDenied => {
            format!(
                "The authenticated Google principal cannot access the requested {} resource.",
                config.api_name
            )
        }
        GoogleProviderAuthFailureKind::OAuthAppBlocked => {
            "Google blocked the OAuth app or consent flow.".to_string()
        }
        GoogleProviderAuthFailureKind::ReauthRequired => {
            "The cached Google OAuth grant needs to be refreshed.".to_string()
        }
        GoogleProviderAuthFailureKind::Unknown => {
            format!("Google provider auth failed for {}.", config.api_name)
        }
    }
}

fn google_next_steps(
    kind: GoogleProviderAuthFailureKind,
    config: &GoogleProviderAuthConfig,
) -> Vec<String> {
    match kind {
        GoogleProviderAuthFailureKind::MissingCredentials => vec![
            format_command(config.adc_login_command(true)),
            format_command(config.adc_quota_project_command()),
            "rerun auth_status or auth_probe".to_string(),
        ],
        GoogleProviderAuthFailureKind::MissingScope => vec![
            format_command(config.adc_login_command(true)),
            "use auth_reauth if a cached OAuth grant is missing the new scope".to_string(),
            "restart the MCP client after credentials change".to_string(),
        ],
        GoogleProviderAuthFailureKind::MissingQuotaProject => {
            google_quota_project_next_steps(&config.quota_project_placeholder)
        }
        GoogleProviderAuthFailureKind::ApiDisabled => {
            let mut steps = Vec::new();
            if let Some(command) = config.api_enable_command() {
                steps.push(format_command(command));
            } else {
                steps.push("enable the required Google API on the quota project".to_string());
            }
            steps.push("rerun auth_status or auth_probe".to_string());
            steps
        }
        GoogleProviderAuthFailureKind::PermissionDenied => vec![
            "grant the authenticated Google principal access to the provider resource".to_string(),
            "confirm the selected tool profile matches the requested operation".to_string(),
            "rerun auth_probe with a low-cost read-only request".to_string(),
        ],
        GoogleProviderAuthFailureKind::OAuthAppBlocked => vec![
            "use a Google OAuth client that is allowed for this account or organization".to_string(),
            "for local trials, prefer Application Default Credentials when supported".to_string(),
            "rerun auth_login or auth_reauth after changing the OAuth client".to_string(),
        ],
        GoogleProviderAuthFailureKind::ReauthRequired => vec![
            "run auth_reauth to force fresh Google consent".to_string(),
            "clear stale local provider-auth caches if reauth still fails".to_string(),
            "rerun auth_status or auth_probe".to_string(),
        ],
        GoogleProviderAuthFailureKind::Unknown => vec![
            "rerun auth_status with verification enabled".to_string(),
            "check Google credentials, quota project, API enablement, scopes, and provider resource permissions".to_string(),
        ],
    }
}

fn format_command(parts: Vec<String>) -> String {
    format_provider_auth_command(&parts)
}

/// Formats a provider-auth command argv as a copyable shell string.
pub fn format_provider_auth_command(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| shell_quote_provider_auth_arg(part))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Formats a provider-auth command argv with an optional `CLOUDSDK_CONFIG`.
pub fn format_google_cloudsdk_command(parts: &[String], cloudsdk_config: Option<&str>) -> String {
    let Some(dir) = cloudsdk_config
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return format_provider_auth_command(parts);
    };
    let dir_shell = format_provider_auth_command(&[dir.to_string()]);
    let command = format_provider_auth_command(parts);
    if command.is_empty() {
        #[cfg(windows)]
        {
            format!("$env:CLOUDSDK_CONFIG={dir_shell}")
        }
        #[cfg(not(windows))]
        {
            format!("CLOUDSDK_CONFIG={dir_shell}")
        }
    } else {
        #[cfg(windows)]
        {
            format!("$env:CLOUDSDK_CONFIG={dir_shell}; {command}")
        }
        #[cfg(not(windows))]
        {
            format!("CLOUDSDK_CONFIG={dir_shell} {command}")
        }
    }
}

fn shell_quote_provider_auth_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.bytes().all(is_shell_safe_provider_auth_byte) {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn is_shell_safe_provider_auth_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'_'
            | b'-'
            | b'.'
            | b'/'
            | b':'
            | b','
            | b'='
            | b'@'
            | b'+'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_adc_login_scopes_include_cloud_platform_once() {
        let scopes = google_adc_login_scopes([
            GOOGLE_CLOUD_PLATFORM_SCOPE,
            "https://www.googleapis.com/auth/webmasters.readonly",
            " https://www.googleapis.com/auth/webmasters.readonly ",
            "",
        ]);

        assert_eq!(
            scopes,
            vec![
                GOOGLE_CLOUD_PLATFORM_SCOPE.to_string(),
                "https://www.googleapis.com/auth/webmasters.readonly".to_string()
            ]
        );
    }

    #[test]
    fn google_adc_login_command_supports_headless_mode() {
        let config = GoogleProviderAuthConfig::new(
            "Search Console API",
            vec!["https://www.googleapis.com/auth/webmasters.readonly".to_string()],
        );

        let command = config.adc_login_command(true);

        assert_eq!(
            command,
            vec![
                "gcloud".to_string(),
                "auth".to_string(),
                "application-default".to_string(),
                "login".to_string(),
                "--scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/webmasters.readonly".to_string(),
                "--no-launch-browser".to_string(),
            ]
        );
    }

    #[test]
    fn provider_auth_command_shell_quotes_paths_with_spaces() {
        let command = ProviderAuthCommand::new(vec![
            "ga4-mcp".to_string(),
            "auth".to_string(),
            "login".to_string(),
            "--client-id-file".to_string(),
            "/tmp/client id.json".to_string(),
        ]);

        assert_eq!(
            command.shell,
            "ga4-mcp auth login --client-id-file '/tmp/client id.json'"
        );
        assert_eq!(command.argv[4], "/tmp/client id.json");
    }

    #[test]
    fn google_adc_login_command_supports_client_id_file() {
        let config = GoogleProviderAuthConfig::new(
            "Analytics Admin API",
            vec!["https://www.googleapis.com/auth/analytics.readonly".to_string()],
        );

        let command =
            config.adc_login_command_with_client_id_file(true, "/tmp/google oauth client.json");
        let rendered = format_provider_auth_command(&command);

        assert_eq!(
            command,
            vec![
                "gcloud".to_string(),
                "auth".to_string(),
                "application-default".to_string(),
                "login".to_string(),
                "--scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/analytics.readonly".to_string(),
                "--no-browser".to_string(),
                "--client-id-file".to_string(),
                "/tmp/google oauth client.json".to_string(),
            ]
        );
        assert_eq!(
            rendered,
            "gcloud auth application-default login --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/analytics.readonly --no-browser --client-id-file '/tmp/google oauth client.json'"
        );
    }

    #[test]
    fn google_adc_setup_plan_collects_common_operator_commands() {
        let config = GoogleProviderAuthConfig::new(
            "Search Console API",
            vec!["https://www.googleapis.com/auth/webmasters.readonly".to_string()],
        )
        .with_api_service_name("searchconsole.googleapis.com");

        let plan = config.adc_setup_plan();

        assert_eq!(plan.api_name, "Search Console API");
        assert_eq!(
            plan.scopes,
            vec![
                GOOGLE_CLOUD_PLATFORM_SCOPE.to_string(),
                "https://www.googleapis.com/auth/webmasters.readonly".to_string()
            ]
        );
        assert_eq!(plan.login.argv, config.adc_login_command(false));
        assert!(plan.headless_login.shell.contains("--no-launch-browser"));
        assert!(!plan
            .login_with_client_id_file
            .shell
            .contains("--no-launch-browser"));
        assert!(plan
            .login_with_client_id_file
            .shell
            .contains("--client-id-file /path/to/client_id.json"));
        assert!(plan
            .headless_login_with_client_id_file
            .shell
            .contains("--no-browser --client-id-file /path/to/client_id.json"));
        assert_eq!(
            plan.quota_project.shell,
            "gcloud auth application-default set-quota-project YOUR_PROJECT"
        );
        assert_eq!(
            plan.api_enable.expect("api enable command").shell,
            "gcloud services enable searchconsole.googleapis.com --project YOUR_PROJECT"
        );
        assert!(plan
            .next_steps
            .iter()
            .any(|step| step.contains("auth_status or auth_probe")));
        assert!(plan
            .notes
            .iter()
            .any(|note| note.contains("client-id-file")));
    }

    #[test]
    fn google_adc_setup_plan_supports_multiple_api_enable_services() {
        let config = GoogleProviderAuthConfig::new(
            "Google Analytics API",
            vec!["https://www.googleapis.com/auth/analytics.readonly".to_string()],
        )
        .with_api_service_names([
            "analyticsadmin.googleapis.com",
            "analyticsdata.googleapis.com",
        ]);

        let plan = config.adc_setup_plan();

        assert_eq!(
            plan.api_enable.expect("api enable command").shell,
            "gcloud services enable analyticsadmin.googleapis.com analyticsdata.googleapis.com --project YOUR_PROJECT"
        );
    }

    #[test]
    fn google_adc_login_contract_has_stable_helper_shape() {
        let config = GoogleProviderAuthConfig::new(
            "Search Console API",
            vec!["https://www.googleapis.com/auth/webmasters.readonly".to_string()],
        )
        .with_api_service_name("searchconsole.googleapis.com");
        let contract = config.adc_login_command_contract(
            &GoogleProviderAuthLoginOptions::new(
                "https://www.googleapis.com/auth/webmasters.readonly",
            )
            .with_headless(true)
            .with_client_id_file("/tmp/client id.json")
            .with_quota_project("project-id")
            .with_cloudsdk_config("/tmp/gsc adc")
            .with_credential_file("/tmp/gsc adc/application_default_credentials.json")
            .with_operator_scope_requested(false)
            .with_notes(vec!["No token or client secret is returned.".to_string()])
            .with_after_login("Restart the MCP client, then run auth_status.".to_string()),
        );

        let value = serde_json::to_value(&contract).expect("serialize auth login contract");
        let object = value.as_object().expect("object");
        let mut keys = object.keys().cloned().collect::<Vec<_>>();
        keys.sort();

        assert_eq!(
            keys,
            vec![
                "adc_scopes",
                "after_login",
                "api_enable_command",
                "api_enable_command_argv",
                "client_id_file_command",
                "client_id_file_headless_command",
                "client_id_file_headless_shell_command",
                "client_id_file_shell_command",
                "cloudsdk_config",
                "command",
                "credential_file",
                "follow_up_commands",
                "headless_command",
                "headless_shell_command",
                "next_steps",
                "notes",
                "operator_scope_requested",
                "quota_project",
                "quota_project_command",
                "quota_project_command_argv",
                "scope",
                "shared_adc",
                "shell_command",
            ]
        );
        assert_eq!(
            object
                .get("command")
                .and_then(|value| value.as_array())
                .map(Vec::len),
            Some(8)
        );
        assert!(object
            .get("shell_command")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("CLOUDSDK_CONFIG='/tmp/gsc adc' gcloud auth")));
        assert!(object
            .get("quota_project_command")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.contains("set-quota-project YOUR_PROJECT")));
        assert!(object
            .get("follow_up_commands")
            .and_then(|value| value.as_array())
            .is_some_and(|commands| commands.iter().any(|value| value
                .as_str()
                .is_some_and(|command| command.contains("set-quota-project project-id")))));
    }

    #[test]
    fn google_adc_setup_plan_omits_blank_api_enable_command() {
        let config =
            GoogleProviderAuthConfig::new("Example API", Vec::new()).with_api_service_name("  ");

        let plan = config.adc_setup_plan();

        assert!(plan.api_enable.is_none());
        assert!(plan
            .next_steps
            .iter()
            .all(|step| !step.contains("enable the required Google API")));
    }

    #[test]
    fn google_adc_setup_plan_omits_direct_blank_api_services() {
        let config = GoogleProviderAuthConfig {
            api_name: "Example API".to_string(),
            provider_scopes: Vec::new(),
            api_service_names: vec![" ".to_string(), "\t".to_string()],
            quota_project_placeholder: "YOUR_PROJECT".to_string(),
        };

        let plan = config.adc_setup_plan();

        assert!(plan.api_enable.is_none());
        assert!(plan
            .next_steps
            .iter()
            .all(|step| !step.contains("enable the required Google API")));
    }

    #[test]
    fn google_error_classifier_prioritizes_missing_quota_project() {
        let body = r#"{
            "error": {
                "code": 403,
                "message": "Your application is authenticating by using local Application Default Credentials. The searchconsole.googleapis.com API requires a quota project, which is not set by default.",
                "status": "PERMISSION_DENIED",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": "SERVICE_DISABLED",
                        "domain": "googleapis.com"
                    }
                ]
            }
        }"#;
        let config = GoogleProviderAuthConfig::new(
            "Search Console API",
            vec!["https://www.googleapis.com/auth/webmasters.readonly".to_string()],
        )
        .with_api_service_name("searchconsole.googleapis.com");

        let diagnostic = classify_google_provider_auth_error(403, body, &config);

        assert_eq!(
            diagnostic.kind,
            GoogleProviderAuthFailureKind::MissingQuotaProject
        );
        assert!(diagnostic.next_steps.contains(
            &"gcloud auth application-default set-quota-project YOUR_PROJECT".to_string()
        ));
    }

    #[test]
    fn google_error_classifier_detects_api_disabled() {
        let body = r#"{
            "error": {
                "code": 403,
                "message": "Google Search Console API has not been used in project 123 before or it is disabled.",
                "status": "PERMISSION_DENIED",
                "errors": [{"reason": "accessNotConfigured"}]
            }
        }"#;
        let config = GoogleProviderAuthConfig::new("Search Console API", Vec::new())
            .with_api_service_name("searchconsole.googleapis.com");

        let diagnostic = classify_google_provider_auth_error(403, body, &config);

        assert_eq!(diagnostic.kind, GoogleProviderAuthFailureKind::ApiDisabled);
        assert_eq!(
            diagnostic.next_steps[0],
            "gcloud services enable searchconsole.googleapis.com --project YOUR_PROJECT"
        );
    }

    #[test]
    fn google_error_classifier_detects_missing_scope() {
        let body = r#"{
            "error": {
                "code": 403,
                "message": "Request had insufficient authentication scopes.",
                "status": "PERMISSION_DENIED"
            }
        }"#;
        let config = GoogleProviderAuthConfig::new(
            "Analytics Admin API",
            vec!["https://www.googleapis.com/auth/analytics.readonly".to_string()],
        );

        let diagnostic = classify_google_provider_auth_error(403, body, &config);

        assert_eq!(diagnostic.kind, GoogleProviderAuthFailureKind::MissingScope);
        assert!(diagnostic.next_steps[0].contains("cloud-platform"));
        assert!(diagnostic.next_steps[0].contains("analytics.readonly"));
    }

    #[test]
    fn provider_auth_status_serializes_without_secret_material() {
        let status = ProviderAuthStatus::new(false, vec![GOOGLE_CLOUD_PLATFORM_SCOPE.to_string()])
            .with_profile("read_only")
            .with_credential_sources(vec![
                ProviderCredentialSourceStatus::new(
                    ProviderCredentialSourceKind::ApplicationDefaultCredentials,
                    true,
                )
                .with_path_hint("~/.config/gcloud/application_default_credentials.json"),
                ProviderCredentialSourceStatus::new(
                    ProviderCredentialSourceKind::ServiceAccountFile,
                    false,
                )
                .with_env_var("GOOGLE_APPLICATION_CREDENTIALS"),
            ])
            .with_quota_project(ProviderQuotaProjectStatus::missing())
            .with_last_verification(ProviderAuthVerification::failed(
                "missing_quota_project",
                "Google ADC is missing a quota project.",
            ))
            .with_next_steps(google_quota_project_next_steps("YOUR_PROJECT"));

        let json = serde_json::to_string(&status).expect("serialize status");

        assert!(json.contains("application_default_credentials"));
        assert!(json.contains(r#""path":"~/.config/gcloud/application_default_credentials.json""#));
        assert!(json.contains(r#""env":"GOOGLE_APPLICATION_CREDENTIALS""#));
        assert!(!json.contains("path_hint"));
        assert!(!json.contains("env_var"));
        assert!(json.contains("missing_quota_project"));
        assert!(json.contains("set-quota-project"));
        assert!(!json.contains("ya29."));
        assert!(!json.contains("refresh_token"));
        assert!(!json.contains("private_key"));
    }

    #[test]
    fn provider_auth_check_status_allows_safe_product_metadata() {
        let check = ProviderAuthCheckStatus::ok()
            .with_metadata("sample_resource_count", serde_json::json!(1))
            .with_hint("safe hint");
        let skipped = ProviderAuthCheckStatus::skipped().with_reason("not requested");
        let failed = ProviderAuthCheckStatus::failed("redacted provider error");

        assert_eq!(
            serde_json::to_value(check).expect("serialize check"),
            serde_json::json!({
                "checked": true,
                "ok": true,
                "hint": "safe hint",
                "sample_resource_count": 1
            })
        );
        assert_eq!(
            serde_json::to_value(skipped).expect("serialize skipped"),
            serde_json::json!({
                "checked": false,
                "reason": "not requested"
            })
        );
        assert_eq!(
            serde_json::to_value(failed).expect("serialize failed"),
            serde_json::json!({
                "checked": true,
                "ok": false,
                "error": "redacted provider error"
            })
        );
    }
}

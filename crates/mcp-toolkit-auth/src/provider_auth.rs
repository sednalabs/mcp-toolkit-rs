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

use serde::{Deserialize, Serialize};

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
}

impl ProviderQuotaProjectStatus {
    /// Reports an absent quota project.
    pub fn missing() -> Self {
        Self {
            configured: false,
            project_hint: None,
        }
    }

    /// Reports a configured quota project using a redacted or public-safe hint.
    pub fn configured(project_hint: impl Into<String>) -> Self {
        Self {
            configured: true,
            project_hint: Some(project_hint.into()),
        }
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

/// Google provider-auth configuration used to build diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleProviderAuthConfig {
    /// Human-readable API name, such as `Search Console API`.
    pub api_name: String,
    /// Required provider scopes, excluding `cloud-platform`.
    pub provider_scopes: Vec<String>,
    /// Google Cloud API service name, such as `searchconsole.googleapis.com`.
    pub api_service_name: Option<String>,
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
            api_service_name: None,
            quota_project_placeholder: "YOUR_PROJECT".to_string(),
        }
    }

    /// Adds the Google API service name used by `gcloud services enable`.
    pub fn with_api_service_name(mut self, api_service_name: impl Into<String>) -> Self {
        self.api_service_name = Some(api_service_name.into());
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

/// Builds standard next steps for a missing Google ADC quota project.
pub fn google_quota_project_next_steps(project_placeholder: &str) -> Vec<String> {
    let project = placeholder_or_default(project_placeholder);
    vec![
        format!("gcloud auth application-default set-quota-project {project}"),
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
            format!(
                "gcloud auth application-default set-quota-project {}",
                placeholder_or_default(&config.quota_project_placeholder)
            ),
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
            if let Some(service) = config.api_service_name.as_deref() {
                steps.push(format!(
                    "gcloud services enable {service} --project {}",
                    placeholder_or_default(&config.quota_project_placeholder)
                ));
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
    parts.join(" ")
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
}

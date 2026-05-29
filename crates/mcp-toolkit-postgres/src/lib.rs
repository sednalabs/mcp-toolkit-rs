//! # MCP Toolkit PostgreSQL Helpers
//!
//! Shared PostgreSQL connection helpers for Rust MCP services.
//!
//! ## Rationale
//! Centralize DSN normalization and TLS mode handling so servers can enforce
//! a consistent, explicit transport policy.
//!
//! ## Security Boundaries
//! * `sslmode=require` maps to encrypted transport without certificate
//!   verification for compatibility.
//! * `sslmode=prefer` is represented explicitly so callers can reject
//!   downgrade-prone mode.
//! * `sslmode=verify-ca|verify-full` uses verified TLS (native roots plus
//!   optional `sslrootcert`).
//! * Invalid or ambiguous `sslmode` values fail closed.
//! * `connect()` uses strict policy and rejects insecure modes unless callers
//!   explicitly opt in with `connect_with_policy(...)`.
//!
//! ## References
//! * PostgreSQL Connection Strings: https://www.postgresql.org/docs/current/libpq-connect.html
//! * `tokio-postgres` documentation: https://docs.rs/tokio-postgres
//!
//! ## Notes
//! * This crate does not execute SQL.
//! * The caller owns SQL safety and authorization checks.

use std::fmt;
use std::iter::Peekable;
use std::str::CharIndices;
use std::sync::{Arc, Once};

use form_urlencoded::parse as parse_form_urlencoded;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio_postgres::tls::TlsStream;
use tokio_postgres::{Client, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

/// TLS policy derived from DSN `sslmode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgTlsMode {
    Disable,
    InsecureRequire,
    InsecurePrefer,
    Verified,
}

impl PgTlsMode {
    /// Returns true when TLS does not verify server certificates.
    pub const fn is_insecure(self) -> bool {
        matches!(self, Self::InsecureRequire | Self::InsecurePrefer)
    }

    /// Returns true when DSN requested downgrade-prone `sslmode=prefer`.
    pub const fn is_prefer(self) -> bool {
        matches!(self, Self::InsecurePrefer)
    }
}

/// Policy for insecure PostgreSQL TLS modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PgInsecureTlsPolicy {
    /// Reject both `sslmode=require` and `sslmode=prefer`.
    #[default]
    DisallowAll,
    /// Allow `sslmode=require`, reject `sslmode=prefer`.
    AllowRequireOnly,
    /// Allow both insecure compatibility modes.
    AllowRequireAndPrefer,
}

impl PgInsecureTlsPolicy {
    const fn allows(self, mode: PgTlsMode) -> bool {
        match (self, mode) {
            (_, PgTlsMode::Disable | PgTlsMode::Verified) => true,
            (Self::DisallowAll, PgTlsMode::InsecureRequire | PgTlsMode::InsecurePrefer) => false,
            (Self::AllowRequireOnly, PgTlsMode::InsecureRequire) => true,
            (Self::AllowRequireOnly, PgTlsMode::InsecurePrefer) => false,
            (
                Self::AllowRequireAndPrefer,
                PgTlsMode::InsecureRequire | PgTlsMode::InsecurePrefer,
            ) => true,
        }
    }
}

/// Parsed PostgreSQL connection policy from a DSN string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgConnectionConfig {
    dsn: String,
    connect_dsn: String,
    tls_mode: PgTlsMode,
    ssl_root_cert: Option<String>,
}

impl PgConnectionConfig {
    /// Build config from a raw DSN.
    ///
    /// # Errors
    /// Returns `PostgresTransportError` when DSN syntax is invalid,
    /// `sslmode` is invalid/ambiguous, or critical TLS fields are ambiguous.
    ///
    /// # Security
    /// * Rejects ambiguous `sslmode` input to avoid parser-precedence bypasses.
    /// * Supports URI and key-value DSNs with the same policy behavior.
    pub fn from_dsn(raw_dsn: &str) -> Result<Self, PostgresTransportError> {
        let dsn = normalize_dsn(raw_dsn);
        let parsed = parse_dsn_transport(&dsn)?;

        Ok(Self {
            dsn,
            connect_dsn: parsed.connect_dsn,
            tls_mode: parsed.tls_mode,
            ssl_root_cert: parsed.ssl_root_cert,
        })
    }

    /// Returns the normalized DSN.
    pub fn normalized_dsn(&self) -> &str {
        &self.dsn
    }

    /// Returns the TLS mode selected from DSN parameters.
    pub const fn tls_mode(&self) -> PgTlsMode {
        self.tls_mode
    }

    /// Validate TLS mode against an insecure-mode policy.
    ///
    /// # Errors
    /// Returns `PostgresTransportError` when the selected TLS mode violates
    /// the supplied policy.
    ///
    /// # Security
    /// * Enforces the configured insecure TLS policy.
    /// * Used to ensure that connections created by this toolkit conform to
    ///   the host application's security requirements.
    pub fn validate_tls_policy(
        &self,
        policy: PgInsecureTlsPolicy,
    ) -> Result<(), PostgresTransportError> {
        if policy.allows(self.tls_mode) {
            return Ok(());
        }
        Err(PostgresTransportError::tls_policy_disallowed(self.tls_mode))
    }

    /// Open a new PostgreSQL client with strict TLS policy.
    ///
    /// # Errors
    /// Returns `PostgresTransportError` when TLS mode violates strict policy,
    /// TLS configuration is invalid, or connection setup fails.
    ///
    /// # Security
    /// * Defaults to `PgInsecureTlsPolicy::DisallowAll` to enforce the strictest
    ///   possible connection security.
    /// * All connections are subject to explicit TLS validation.
    pub async fn connect(&self) -> Result<(Client, ConnectionDriver), PostgresTransportError> {
        self.connect_with_policy(PgInsecureTlsPolicy::DisallowAll)
            .await
    }

    /// Open a new PostgreSQL client using explicit insecure-mode policy.
    ///
    /// # Errors
    /// Returns `PostgresTransportError` when TLS mode violates policy,
    /// TLS configuration is invalid, or connection setup fails.
    ///
    /// # Security
    /// * Allows callers to explicitly opt-in to insecure transport if required.
    /// * Validates the connection configuration against the provided `policy`
    ///   before initiating transport.
    pub async fn connect_with_policy(
        &self,
        policy: PgInsecureTlsPolicy,
    ) -> Result<(Client, ConnectionDriver), PostgresTransportError> {
        self.validate_tls_policy(policy)?;
        self.connect_transport().await
    }

    /// Open a new PostgreSQL client with already-validated TLS mode.
    ///
    /// # Errors
    /// Returns `PostgresTransportError` for TLS configuration errors or
    /// connect failures.
    async fn connect_transport(
        &self,
    ) -> Result<(Client, ConnectionDriver), PostgresTransportError> {
        match self.tls_mode {
            PgTlsMode::Disable => {
                let (client, connection) = tokio_postgres::connect(&self.connect_dsn, NoTls)
                    .await
                    .map_err(PostgresTransportError::connect_failed)?;
                Ok((client, spawn_connection_driver(connection)))
            }
            PgTlsMode::InsecureRequire | PgTlsMode::InsecurePrefer => {
                ensure_rustls_provider_installed();
                let tls = build_insecure_tls_connector();
                let (client, connection) = tokio_postgres::connect(&self.connect_dsn, tls)
                    .await
                    .map_err(PostgresTransportError::connect_failed)?;
                Ok((client, spawn_connection_driver(connection)))
            }
            PgTlsMode::Verified => {
                ensure_rustls_provider_installed();
                let tls = build_verified_tls_connector(self.ssl_root_cert.as_deref())?;
                let (client, connection) = tokio_postgres::connect(&self.connect_dsn, tls)
                    .await
                    .map_err(PostgresTransportError::connect_failed)?;
                Ok((client, spawn_connection_driver(connection)))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDsn {
    connect_dsn: String,
    tls_mode: PgTlsMode,
    ssl_root_cert: Option<String>,
}

/// Join handle for a spawned PostgreSQL connection driver task.
#[derive(Debug)]
pub struct ConnectionDriver {
    join: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
}

/// Structured error from a PostgreSQL connection driver task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDriverError {
    message: String,
    sqlstate: Option<String>,
}

impl ConnectionDriver {
    /// Wait for the driver task to finish.
    ///
    /// # Errors
    /// Returns `ConnectionDriverError` when the underlying connection driver
    /// reports a transport/protocol error or the task fails to join.
    ///
    /// # Security
    /// * Ensures that connection failures are surfaced to the application
    ///   for proper handling, preventing silent connection drops.
    pub async fn wait(self) -> Result<(), ConnectionDriverError> {
        match self.join.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                let sqlstate = err
                    .as_db_error()
                    .map(|db_err| db_err.code().code().to_string());
                Err(ConnectionDriverError {
                    message: err.to_string(),
                    sqlstate,
                })
            }
            Err(join_err) => Err(ConnectionDriverError {
                message: format!("connection driver task join failure: {join_err}"),
                sqlstate: None,
            }),
        }
    }
}

impl ConnectionDriverError {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }
}

/// Structured error for DSN/TLS/connect handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTransportError {
    code: &'static str,
    reason: &'static str,
    message: String,
    sqlstate: Option<String>,
}

impl PostgresTransportError {
    fn invalid_sslmode(value: &str) -> Self {
        Self {
            code: "PG_SSLMODE_INVALID",
            reason: "sslmode_invalid",
            message: format!(
                "invalid sslmode {:?} (expected disable|prefer|require|verify-ca|verify-full)",
                value
            ),
            sqlstate: None,
        }
    }

    fn ambiguous_sslmode() -> Self {
        Self {
            code: "PG_SSLMODE_INVALID",
            reason: "sslmode_ambiguous",
            message: "multiple sslmode parameters are not allowed".to_string(),
            sqlstate: None,
        }
    }

    fn invalid_dsn(message: impl Into<String>) -> Self {
        Self {
            code: "PG_DSN_INVALID",
            reason: "dsn_invalid",
            message: message.into(),
            sqlstate: None,
        }
    }

    fn ambiguous_dsn_parameter(parameter: &str) -> Self {
        Self {
            code: "PG_DSN_INVALID",
            reason: "dsn_param_ambiguous",
            message: format!("multiple {parameter} parameters are not allowed"),
            sqlstate: None,
        }
    }

    fn tls_policy_disallowed(mode: PgTlsMode) -> Self {
        let sslmode = match mode {
            PgTlsMode::InsecureRequire => "require",
            PgTlsMode::InsecurePrefer => "prefer",
            PgTlsMode::Disable => "disable",
            PgTlsMode::Verified => "verify",
        };
        Self {
            code: "PG_TLS_POLICY_VIOLATION",
            reason: "tls_policy_disallowed",
            message: format!("sslmode={sslmode} is disallowed by TLS policy"),
            sqlstate: None,
        }
    }

    fn connect_failed(err: tokio_postgres::Error) -> Self {
        let sqlstate = err
            .as_db_error()
            .map(|db_err| db_err.code().code().to_string());
        Self {
            code: "PG_CONNECT_FAILED",
            reason: "connect_failed",
            message: err.to_string(),
            sqlstate,
        }
    }

    fn tls_config_error(message: impl Into<String>) -> Self {
        Self {
            code: "PG_TLS_CONFIG_ERROR",
            reason: "tls_config_error",
            message: message.into(),
            sqlstate: None,
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }
}

impl fmt::Display for PostgresTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PostgresTransportError {}

/// Normalize Python/libpq DSN prefixes to `postgresql://`.
pub fn normalize_dsn(dsn: &str) -> String {
    if let Some(rest) = dsn.strip_prefix("postgresql+psycopg2://") {
        return format!("postgresql://{rest}");
    }
    if let Some(rest) = dsn.strip_prefix("postgresql+psycopg_async://") {
        return format!("postgresql://{rest}");
    }
    if let Some(rest) = dsn.strip_prefix("postgresql+psycopg://") {
        return format!("postgresql://{rest}");
    }
    if let Some(rest) = dsn.strip_prefix("postgres://") {
        return format!("postgresql://{rest}");
    }
    dsn.to_string()
}

/// Read a query parameter from a DSN URI string.
pub fn query_param(dsn: &str, key: &str) -> Option<String> {
    let query = dsn.split_once('?')?.1;
    for (name, value) in parse_form_urlencoded(query.as_bytes()) {
        if name == key {
            return Some(value.into_owned());
        }
    }
    None
}

/// Map DSN `sslmode` to a concrete TLS mode.
///
/// # Errors
/// Returns `PostgresTransportError` for unsupported/ambiguous values or
/// invalid DSN syntax.
///
/// # Security
/// Rejects ambiguous `sslmode` declarations to avoid precedence confusion.
pub fn tls_mode_for_dsn(dsn: &str) -> Result<PgTlsMode, PostgresTransportError> {
    let normalized = normalize_dsn(dsn);
    Ok(parse_dsn_transport(&normalized)?.tls_mode)
}

fn parse_dsn_transport(dsn: &str) -> Result<ParsedDsn, PostgresTransportError> {
    if dsn.trim().is_empty() {
        return Err(PostgresTransportError::invalid_dsn(
            "connection string must not be empty",
        ));
    }

    if is_uri_dsn(dsn) {
        parse_uri_dsn(dsn)
    } else {
        parse_keyword_dsn(dsn)
    }
}

fn is_uri_dsn(dsn: &str) -> bool {
    dsn.starts_with("postgresql://") || dsn.starts_with("postgres://")
}

fn parse_uri_dsn(dsn: &str) -> Result<ParsedDsn, PostgresTransportError> {
    let params = dsn
        .split_once('?')
        .map(|(_, query)| {
            parse_form_urlencoded(query.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let sslmode = unique_param_value_from_pairs(&params, "sslmode")?;
    let tls_mode = match sslmode {
        Some(value) => tls_mode_from_sslmode(&value)?,
        None => PgTlsMode::Disable,
    };

    let ssl_root_cert = unique_param_value_from_pairs(&params, "sslrootcert")?
        .and_then(|value| (!value.trim().is_empty()).then_some(value));

    let connect_dsn = if matches!(tls_mode, PgTlsMode::Verified) {
        rewrite_uri_sslmode_to_require(dsn, &params)?
    } else {
        dsn.to_string()
    };

    Ok(ParsedDsn {
        connect_dsn,
        tls_mode,
        ssl_root_cert,
    })
}

fn rewrite_uri_sslmode_to_require(
    dsn: &str,
    params: &[(String, String)],
) -> Result<String, PostgresTransportError> {
    let (base, _) = dsn.split_once('?').ok_or_else(|| {
        PostgresTransportError::invalid_dsn(
            "verified sslmode requires query parameter form in URI DSN",
        )
    })?;

    let mut serializer = form_urlencoded::Serializer::new(String::new());
    let mut replaced_sslmode = false;

    for (name, value) in params {
        if name.eq_ignore_ascii_case("sslmode") {
            serializer.append_pair(name, "require");
            replaced_sslmode = true;
        } else {
            serializer.append_pair(name, value);
        }
    }

    if !replaced_sslmode {
        return Err(PostgresTransportError::invalid_dsn(
            "verified sslmode is missing from URI query",
        ));
    }

    Ok(format!("{base}?{}", serializer.finish()))
}

fn unique_param_value_from_pairs(
    params: &[(String, String)],
    key: &str,
) -> Result<Option<String>, PostgresTransportError> {
    let values = params
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    unique_param_value(key, values)
}

fn parse_keyword_dsn(dsn: &str) -> Result<ParsedDsn, PostgresTransportError> {
    let mut params = KeywordConninfoParser::new(dsn).parse()?;

    let sslmode = unique_param_value_from_conninfo(&params, "sslmode")?;
    let tls_mode = match sslmode {
        Some(value) => tls_mode_from_sslmode(&value)?,
        None => PgTlsMode::Disable,
    };

    let ssl_root_cert = unique_param_value_from_conninfo(&params, "sslrootcert")?
        .and_then(|value| (!value.trim().is_empty()).then_some(value));

    let connect_dsn = if matches!(tls_mode, PgTlsMode::Verified) {
        for param in &mut params {
            if param.key.eq_ignore_ascii_case("sslmode") {
                param.value = "require".to_string();
            }
        }
        serialize_keyword_conninfo(&params)
    } else {
        dsn.to_string()
    };

    Ok(ParsedDsn {
        connect_dsn,
        tls_mode,
        ssl_root_cert,
    })
}

fn unique_param_value_from_conninfo(
    params: &[ConninfoParam],
    key: &str,
) -> Result<Option<String>, PostgresTransportError> {
    let values = params
        .iter()
        .filter(|param| param.key.eq_ignore_ascii_case(key))
        .map(|param| param.value.clone())
        .collect::<Vec<_>>();
    unique_param_value(key, values)
}

fn unique_param_value(
    key: &str,
    values: Vec<String>,
) -> Result<Option<String>, PostgresTransportError> {
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() > 1 {
        if key.eq_ignore_ascii_case("sslmode") {
            return Err(PostgresTransportError::ambiguous_sslmode());
        }
        return Err(PostgresTransportError::ambiguous_dsn_parameter(key));
    }
    Ok(values.into_iter().next())
}

fn tls_mode_from_sslmode(value: &str) -> Result<PgTlsMode, PostgresTransportError> {
    let sslmode = value.to_ascii_lowercase();
    match sslmode.as_str() {
        "disable" => Ok(PgTlsMode::Disable),
        "require" => Ok(PgTlsMode::InsecureRequire),
        "prefer" => Ok(PgTlsMode::InsecurePrefer),
        "verify-ca" | "verify-full" => Ok(PgTlsMode::Verified),
        _ => Err(PostgresTransportError::invalid_sslmode(value)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConninfoParam {
    key: String,
    value: String,
}

struct KeywordConninfoParser<'a> {
    source: &'a str,
    it: Peekable<CharIndices<'a>>,
}

impl<'a> KeywordConninfoParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            it: source.char_indices().peekable(),
        }
    }

    fn parse(mut self) -> Result<Vec<ConninfoParam>, PostgresTransportError> {
        let mut params = Vec::new();
        while let Some(param) = self.parameter()? {
            params.push(param);
        }
        Ok(params)
    }

    fn skip_ws(&mut self) {
        while matches!(self.it.peek(), Some((_, c)) if c.is_whitespace()) {
            self.it.next();
        }
    }

    fn keyword(&mut self) -> Option<&'a str> {
        let start = self.it.peek()?.0;
        while let Some(&(idx, c)) = self.it.peek() {
            if c.is_whitespace() || c == '=' {
                return Some(&self.source[start..idx]);
            }
            self.it.next();
        }
        Some(&self.source[start..])
    }

    fn eat(&mut self, expected: char) -> Result<(), PostgresTransportError> {
        match self.it.next() {
            Some((_, got)) if got == expected => Ok(()),
            _ => Err(PostgresTransportError::invalid_dsn(format!(
                "expected '{expected}' in connection string"
            ))),
        }
    }

    fn value(&mut self) -> Result<String, PostgresTransportError> {
        match self.it.peek() {
            Some((_, '\'')) => {
                self.it.next();
                let value = self.quoted_value()?;
                self.eat('\'')?;
                Ok(value)
            }
            Some(_) => self.simple_value(),
            None => Err(PostgresTransportError::invalid_dsn(
                "unexpected EOF while parsing connection parameter value",
            )),
        }
    }

    fn simple_value(&mut self) -> Result<String, PostgresTransportError> {
        let mut value = String::new();

        while let Some(&(_, c)) = self.it.peek() {
            if c.is_whitespace() {
                break;
            }

            self.it.next();
            if c == '\\' {
                let escaped = self.it.next().ok_or_else(|| {
                    PostgresTransportError::invalid_dsn(
                        "dangling escape in connection parameter value",
                    )
                })?;
                value.push(escaped.1);
            } else {
                value.push(c);
            }
        }

        if value.is_empty() {
            return Err(PostgresTransportError::invalid_dsn(
                "unexpected EOF while parsing connection parameter value",
            ));
        }

        Ok(value)
    }

    fn quoted_value(&mut self) -> Result<String, PostgresTransportError> {
        let mut value = String::new();

        while let Some(&(_, c)) = self.it.peek() {
            if c == '\'' {
                return Ok(value);
            }

            self.it.next();
            if c == '\\' {
                let escaped = self.it.next().ok_or_else(|| {
                    PostgresTransportError::invalid_dsn(
                        "dangling escape in quoted connection parameter value",
                    )
                })?;
                value.push(escaped.1);
            } else {
                value.push(c);
            }
        }

        Err(PostgresTransportError::invalid_dsn(
            "unterminated quoted connection parameter value",
        ))
    }

    fn parameter(&mut self) -> Result<Option<ConninfoParam>, PostgresTransportError> {
        self.skip_ws();

        let key = match self.keyword() {
            Some(key) => key,
            None => return Ok(None),
        };

        if key.is_empty() {
            return Err(PostgresTransportError::invalid_dsn(
                "empty connection parameter name",
            ));
        }

        self.skip_ws();
        self.eat('=')?;
        self.skip_ws();
        let value = self.value()?;

        Ok(Some(ConninfoParam {
            key: key.to_string(),
            value,
        }))
    }
}

fn serialize_keyword_conninfo(params: &[ConninfoParam]) -> String {
    params
        .iter()
        .map(|param| format!("{}={}", param.key, quote_conninfo_value(&param.value)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_conninfo_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\\' || ch == '\'' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

fn ensure_rustls_provider_installed() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_insecure_tls_connector() -> MakeRustlsConnect {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    MakeRustlsConnect::new(config)
}

fn build_verified_tls_connector(
    ssl_root_cert: Option<&str>,
) -> Result<MakeRustlsConnect, PostgresTransportError> {
    let mut roots = rustls::RootCertStore::empty();

    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        return Err(PostgresTransportError::tls_config_error(format!(
            "failed loading native cert roots: {:?}",
            native.errors
        )));
    }
    for cert in native.certs {
        roots.add(cert).map_err(|err| {
            PostgresTransportError::tls_config_error(format!(
                "failed adding native cert root: {err}"
            ))
        })?;
    }

    if let Some(path) = ssl_root_cert {
        if !path.trim().is_empty() {
            let certs = CertificateDer::pem_file_iter(path).map_err(|err| {
                PostgresTransportError::tls_config_error(format!(
                    "failed reading sslrootcert {:?}: {err}",
                    path
                ))
            })?;
            for cert in certs {
                let cert = cert.map_err(|err| {
                    PostgresTransportError::tls_config_error(format!(
                        "failed parsing sslrootcert {:?}: {err}",
                        path
                    ))
                })?;
                roots.add(cert).map_err(|err| {
                    PostgresTransportError::tls_config_error(format!(
                        "failed adding sslrootcert {:?}: {err}",
                        path
                    ))
                })?;
            }
        }
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn spawn_connection_driver<S, T>(connection: tokio_postgres::Connection<S, T>) -> ConnectionDriver
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    T: TlsStream + Unpin + Send + 'static,
{
    let join = tokio::spawn(connection);
    ConnectionDriver { join }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_dsn, query_param, tls_mode_for_dsn, PgConnectionConfig, PgInsecureTlsPolicy,
        PgTlsMode,
    };

    #[test]
    fn normalize_dsn_converts_psycopg_and_postgres_prefixes() {
        assert_eq!(
            normalize_dsn("postgresql+psycopg://user:pass@localhost:5432/db"),
            "postgresql://user:pass@localhost:5432/db"
        );
        assert_eq!(
            normalize_dsn("postgres://user:pass@localhost:5432/db"),
            "postgresql://user:pass@localhost:5432/db"
        );
    }

    #[test]
    fn query_param_extracts_value() {
        let dsn = "postgresql://user:pass@localhost:5432/db?sslmode=verify-full&connect_timeout=5";
        assert_eq!(query_param(dsn, "sslmode"), Some("verify-full".to_string()));
        assert_eq!(query_param(dsn, "connect_timeout"), Some("5".to_string()));
        assert_eq!(query_param(dsn, "missing"), None);
    }

    #[test]
    fn query_param_decodes_percent_encoding() {
        let dsn =
            "postgresql://user:pass@localhost:5432/db?sslrootcert=%2Fetc%2Fssl%2Fcerts%2Fca.pem";
        assert_eq!(
            query_param(dsn, "sslrootcert"),
            Some("/etc/ssl/certs/ca.pem".to_string())
        );
    }

    #[test]
    fn tls_mode_defaults_to_disable_when_absent() {
        let mode = tls_mode_for_dsn("postgresql://user:pass@localhost:5432/db")
            .expect("absent sslmode should default to disable");
        assert_eq!(mode, PgTlsMode::Disable);
    }

    #[test]
    fn tls_mode_parses_supported_values() {
        assert_eq!(
            tls_mode_for_dsn("postgresql://u:p@h:5432/d?sslmode=disable")
                .expect("disable should parse"),
            PgTlsMode::Disable
        );
        assert_eq!(
            tls_mode_for_dsn("postgresql://u:p@h:5432/d?sslmode=require")
                .expect("require should parse"),
            PgTlsMode::InsecureRequire
        );
        assert_eq!(
            tls_mode_for_dsn("postgresql://u:p@h:5432/d?sslmode=prefer")
                .expect("prefer should parse"),
            PgTlsMode::InsecurePrefer
        );
        assert_eq!(
            tls_mode_for_dsn("postgresql://u:p@h:5432/d?sslmode=verify-full")
                .expect("verify-full should parse"),
            PgTlsMode::Verified
        );
    }

    #[test]
    fn tls_mode_parses_keyword_dsn_values() {
        assert_eq!(
            tls_mode_for_dsn("host=localhost user=postgres dbname=app sslmode=require")
                .expect("require should parse"),
            PgTlsMode::InsecureRequire
        );
        assert_eq!(
            tls_mode_for_dsn("host=localhost user=postgres dbname=app sslmode=verify-ca")
                .expect("verify-ca should parse"),
            PgTlsMode::Verified
        );
    }

    #[test]
    fn tls_mode_rejects_duplicate_sslmode_in_uri() {
        let err = tls_mode_for_dsn("postgresql://u:p@h:5432/d?sslmode=require&sslmode=disable")
            .expect_err("duplicate sslmode should fail");
        assert_eq!(err.code(), "PG_SSLMODE_INVALID");
        assert_eq!(err.reason(), "sslmode_ambiguous");
    }

    #[test]
    fn tls_mode_rejects_duplicate_sslmode_in_keyword_dsn() {
        let err = tls_mode_for_dsn(
            "host=localhost user=postgres dbname=app sslmode=require sslmode=disable",
        )
        .expect_err("duplicate sslmode should fail");
        assert_eq!(err.code(), "PG_SSLMODE_INVALID");
        assert_eq!(err.reason(), "sslmode_ambiguous");
    }

    #[test]
    fn tls_mode_rejects_invalid_values() {
        let err = tls_mode_for_dsn("postgresql://u:p@h:5432/d?sslmode=bogus")
            .expect_err("invalid sslmode should fail");
        assert_eq!(err.code(), "PG_SSLMODE_INVALID");
    }

    #[test]
    fn config_normalizes_and_parses_mode() {
        let config =
            PgConnectionConfig::from_dsn("postgresql+psycopg://u:p@h:5432/d?sslmode=verify-ca")
                .expect("config should parse");
        assert_eq!(
            config.normalized_dsn(),
            "postgresql://u:p@h:5432/d?sslmode=verify-ca"
        );
        assert_eq!(
            config.connect_dsn,
            "postgresql://u:p@h:5432/d?sslmode=require"
        );
        assert_eq!(config.tls_mode(), PgTlsMode::Verified);
    }

    #[test]
    fn config_rewrites_verified_sslmode_for_keyword_dsn() {
        let config = PgConnectionConfig::from_dsn(
            "host=localhost user=postgres dbname=app sslmode=verify-full sslrootcert='/etc/ssl/certs/ca.pem'",
        )
        .expect("keyword dsn should parse");

        assert_eq!(config.tls_mode(), PgTlsMode::Verified);
        assert!(config.connect_dsn.contains("sslmode='require'"));
        assert_eq!(
            config.ssl_root_cert.as_deref(),
            Some("/etc/ssl/certs/ca.pem")
        );
    }

    #[test]
    fn config_rejects_ambiguous_sslrootcert() {
        let err = PgConnectionConfig::from_dsn(
            "postgresql://u:p@h:5432/d?sslmode=verify-full&sslrootcert=/tmp/a.pem&sslrootcert=/tmp/b.pem",
        )
        .expect_err("ambiguous sslrootcert should fail");
        assert_eq!(err.code(), "PG_DSN_INVALID");
        assert_eq!(err.reason(), "dsn_param_ambiguous");
    }

    #[test]
    fn connect_policy_rejects_insecure_modes_by_default() {
        let require = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=require")
            .expect("parse require");
        let prefer = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=prefer")
            .expect("parse prefer");

        let require_err = require
            .validate_tls_policy(PgInsecureTlsPolicy::DisallowAll)
            .expect_err("require should be rejected by strict default");
        assert_eq!(require_err.code(), "PG_TLS_POLICY_VIOLATION");
        assert_eq!(require_err.reason(), "tls_policy_disallowed");
        assert_eq!(require_err.sqlstate(), None);

        let prefer_err = prefer
            .validate_tls_policy(PgInsecureTlsPolicy::DisallowAll)
            .expect_err("prefer should be rejected by strict default");
        assert_eq!(prefer_err.code(), "PG_TLS_POLICY_VIOLATION");
        assert_eq!(prefer_err.reason(), "tls_policy_disallowed");
    }

    #[test]
    fn connect_policy_allow_require_only_rejects_prefer() {
        let require = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=require")
            .expect("parse require");
        let prefer = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=prefer")
            .expect("parse prefer");

        require
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireOnly)
            .expect("require should be allowed");
        prefer
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireOnly)
            .expect_err("prefer should remain blocked");
    }
}

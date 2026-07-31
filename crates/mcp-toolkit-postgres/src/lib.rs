//! # MCP Toolkit PostgreSQL Helpers
//!
//! Shared PostgreSQL connection helpers for Rust MCP services.
//!
//! ## Rationale
//! Centralize DSN normalization, TLS mode handling, and target identity
//! verification so servers can enforce explicit connection policy.
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
//! * Target verification uses PostgreSQL's cluster `system_identifier` rather
//!   than treating a database name or network address as sufficient identity.
//!
//! ## References
//! * PostgreSQL Connection Strings: https://www.postgresql.org/docs/current/libpq-connect.html
//! * `tokio-postgres` documentation: https://docs.rs/tokio-postgres
//!
//! ## Notes
//! * This crate executes only its fixed, read-only server identity query.
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
    /// Reject plaintext plus `sslmode=require` and `sslmode=prefer`.
    #[default]
    DisallowAll,
    /// Allow `sslmode=require`, reject plaintext and `sslmode=prefer`.
    AllowRequireOnly,
    /// Allow plaintext plus both insecure compatibility modes.
    AllowRequireAndPrefer,
}

impl PgInsecureTlsPolicy {
    const fn allows(self, mode: PgTlsMode) -> bool {
        match (self, mode) {
            (_, PgTlsMode::Verified) => true,
            (
                Self::DisallowAll,
                PgTlsMode::Disable | PgTlsMode::InsecureRequire | PgTlsMode::InsecurePrefer,
            ) => false,
            (Self::AllowRequireOnly, PgTlsMode::Disable) => false,
            (Self::AllowRequireOnly, PgTlsMode::InsecureRequire) => true,
            (Self::AllowRequireOnly, PgTlsMode::InsecurePrefer) => false,
            (
                Self::AllowRequireAndPrefer,
                PgTlsMode::Disable | PgTlsMode::InsecureRequire | PgTlsMode::InsecurePrefer,
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

/// Expected identity for one PostgreSQL deployment profile.
///
/// The environment and deployment labels are operator-controlled identifiers.
/// The cluster system identifier and database name are compared with values
/// read from the connected PostgreSQL server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgIdentityExpectation {
    environment: String,
    deployment: String,
    cluster_system_identifier: String,
    database: String,
}

impl PgIdentityExpectation {
    /// Creates a fail-closed PostgreSQL identity expectation.
    ///
    /// # Errors
    /// Returns [`PostgresIdentityError`] when a value is blank, contains
    /// control characters or surrounding whitespace, exceeds its bound, or
    /// when `cluster_system_identifier` is not an unsigned decimal integer.
    ///
    /// # Security
    /// Environment and deployment labels do not attest a server by themselves.
    /// Verification also requires the server-provided cluster system identifier
    /// and current database to match exactly.
    pub fn new(
        environment: impl Into<String>,
        deployment: impl Into<String>,
        cluster_system_identifier: impl Into<String>,
        database: impl Into<String>,
    ) -> Result<Self, PostgresIdentityError> {
        Ok(Self {
            environment: validate_identity_value("environment", environment.into(), 128)?,
            deployment: validate_identity_value("deployment", deployment.into(), 128)?,
            cluster_system_identifier: validate_numeric_identity_value(
                "cluster_system_identifier",
                cluster_system_identifier.into(),
                20,
            )?,
            database: validate_identity_value("database", database.into(), 63)?,
        })
    }

    /// Returns the operator-controlled environment label.
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// Returns the stable deployment profile label.
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    /// Returns the expected PostgreSQL cluster system identifier.
    pub fn cluster_system_identifier(&self) -> &str {
        &self.cluster_system_identifier
    }

    /// Returns the expected database name.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Verifies an observed server identity and binds it to this profile.
    ///
    /// # Errors
    /// Returns [`PostgresIdentityError`] when the cluster system identifier or
    /// database name differs from the expected profile.
    ///
    /// # Security
    /// Comparison is exact and fail-closed. A matching database name on a
    /// different PostgreSQL cluster is rejected.
    ///
    /// # Examples
    /// ```
    /// use mcp_toolkit_postgres::{PgIdentityExpectation, PgServerIdentity};
    ///
    /// let expected = PgIdentityExpectation::new(
    ///     "production",
    ///     "primary",
    ///     "7521467493250607290",
    ///     "application",
    /// )?;
    /// let observed = PgServerIdentity::from_values(
    ///     "7521467493250607290",
    ///     "application",
    ///     "170004",
    /// )?;
    /// let verified = expected.verify(&observed)?;
    /// assert_eq!(verified.environment(), "production");
    /// # Ok::<(), mcp_toolkit_postgres::PostgresIdentityError>(())
    /// ```
    pub fn verify(
        &self,
        observed: &PgServerIdentity,
    ) -> Result<PgVerifiedIdentity, PostgresIdentityError> {
        if observed.cluster_system_identifier != self.cluster_system_identifier {
            return Err(PostgresIdentityError::mismatch(
                "cluster_system_identifier",
                &self.cluster_system_identifier,
                &observed.cluster_system_identifier,
            ));
        }
        if observed.database != self.database {
            return Err(PostgresIdentityError::mismatch(
                "database",
                &self.database,
                &observed.database,
            ));
        }

        Ok(PgVerifiedIdentity {
            environment: self.environment.clone(),
            deployment: self.deployment.clone(),
            server: observed.clone(),
        })
    }
}

/// Identity observed from a connected PostgreSQL server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgServerIdentity {
    cluster_system_identifier: String,
    database: String,
    server_version_num: String,
}

impl PgServerIdentity {
    /// Creates an observed server identity from values read through another
    /// PostgreSQL client or pool implementation.
    ///
    /// # Errors
    /// Returns [`PostgresIdentityError`] when a value is invalid or when a
    /// numeric identity field is not an unsigned decimal integer.
    ///
    /// # Security
    /// This constructor validates representation only. The caller owns the
    /// provenance of supplied values; prefer [`read_postgres_identity`] when
    /// using a `tokio-postgres` client.
    pub fn from_values(
        cluster_system_identifier: impl Into<String>,
        database: impl Into<String>,
        server_version_num: impl Into<String>,
    ) -> Result<Self, PostgresIdentityError> {
        Ok(Self {
            cluster_system_identifier: validate_numeric_identity_value(
                "cluster_system_identifier",
                cluster_system_identifier.into(),
                20,
            )?,
            database: validate_identity_value("database", database.into(), 63)?,
            server_version_num: validate_numeric_identity_value(
                "server_version_num",
                server_version_num.into(),
                12,
            )?,
        })
    }

    /// Returns the server-provided PostgreSQL cluster system identifier.
    pub fn cluster_system_identifier(&self) -> &str {
        &self.cluster_system_identifier
    }

    /// Returns the current database name.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Returns PostgreSQL's numeric server version string.
    pub fn server_version_num(&self) -> &str {
        &self.server_version_num
    }
}

/// Server identity verified against an operator-controlled deployment profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgVerifiedIdentity {
    environment: String,
    deployment: String,
    server: PgServerIdentity,
}

impl PgVerifiedIdentity {
    /// Returns the verified environment label.
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// Returns the verified deployment profile label.
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    /// Returns the observed server identity that matched the profile.
    pub const fn server(&self) -> &PgServerIdentity {
        &self.server
    }
}

/// Reads the stable, non-secret identity of a connected PostgreSQL server.
///
/// # Errors
/// Returns [`PostgresIdentityError`] when PostgreSQL rejects the fixed identity
/// query, returns no row, or returns an invalid identity value.
///
/// # Required Privileges
/// The connected role must be permitted to execute
/// `pg_catalog.pg_control_system()`. PostgreSQL grants this to superusers and
/// roles with `pg_monitor` privileges by default; operators can instead grant
/// `EXECUTE` on the function explicitly.
///
/// # Security
/// Uses a fixed read-only query and does not expose a DSN, credentials, client
/// address, or server network address. The cluster system identifier is read
/// from `pg_control_system()` so database-name equality alone cannot establish
/// target identity.
pub async fn read_postgres_identity(
    client: &Client,
) -> Result<PgServerIdentity, PostgresIdentityError> {
    const IDENTITY_QUERY: &str = "SELECT control.system_identifier::text AS cluster_system_identifier, pg_catalog.current_database()::text AS database, pg_catalog.current_setting('server_version_num') AS server_version_num FROM pg_catalog.pg_control_system() AS control";

    let row = client
        .query_opt(IDENTITY_QUERY, &[])
        .await
        .map_err(PostgresIdentityError::query_failed)?
        .ok_or_else(PostgresIdentityError::missing_identity_row)?;
    let cluster_system_identifier = row
        .try_get::<_, String>("cluster_system_identifier")
        .map_err(PostgresIdentityError::query_failed)?;
    let database = row
        .try_get::<_, String>("database")
        .map_err(PostgresIdentityError::query_failed)?;
    let server_version_num = row
        .try_get::<_, String>("server_version_num")
        .map_err(PostgresIdentityError::query_failed)?;

    PgServerIdentity::from_values(cluster_system_identifier, database, server_version_num)
}

/// Reads and verifies a connected PostgreSQL server identity.
///
/// # Errors
/// Returns [`PostgresIdentityError`] when the identity query fails or the
/// observed cluster/database does not match `expected`.
///
/// # Security
/// Fails closed on missing, invalid, or mismatched identity evidence.
pub async fn verify_postgres_identity(
    client: &Client,
    expected: &PgIdentityExpectation,
) -> Result<PgVerifiedIdentity, PostgresIdentityError> {
    let observed = read_postgres_identity(client).await?;
    expected.verify(&observed)
}

/// Structured error for PostgreSQL target identity handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresIdentityError {
    code: &'static str,
    reason: &'static str,
    message: String,
    field: Option<&'static str>,
    expected: Option<String>,
    observed: Option<String>,
    sqlstate: Option<String>,
}

impl PostgresIdentityError {
    fn invalid_value(field: &'static str, requirement: &'static str) -> Self {
        Self {
            code: "PG_IDENTITY_INVALID",
            reason: "identity_value_invalid",
            message: format!("invalid PostgreSQL identity field {field}: {requirement}"),
            field: Some(field),
            expected: None,
            observed: None,
            sqlstate: None,
        }
    }

    fn mismatch(field: &'static str, expected: &str, observed: &str) -> Self {
        Self {
            code: "PG_IDENTITY_MISMATCH",
            reason: "identity_mismatch",
            message: format!("PostgreSQL identity mismatch for {field}"),
            field: Some(field),
            expected: Some(expected.to_string()),
            observed: Some(observed.to_string()),
            sqlstate: None,
        }
    }

    fn query_failed(err: tokio_postgres::Error) -> Self {
        let sqlstate = err
            .as_db_error()
            .map(|db_err| db_err.code().code().to_string());
        Self {
            code: "PG_IDENTITY_QUERY_FAILED",
            reason: "identity_query_failed",
            message: err.to_string(),
            field: None,
            expected: None,
            observed: None,
            sqlstate,
        }
    }

    fn missing_identity_row() -> Self {
        Self {
            code: "PG_IDENTITY_QUERY_FAILED",
            reason: "identity_row_missing",
            message: "PostgreSQL identity query returned no row".to_string(),
            field: None,
            expected: None,
            observed: None,
            sqlstate: None,
        }
    }

    /// Returns the stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the stable machine-readable reason.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Returns the human-readable error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the identity field associated with validation or mismatch.
    pub const fn field(&self) -> Option<&'static str> {
        self.field
    }

    /// Returns the expected field value for a mismatch.
    pub fn expected(&self) -> Option<&str> {
        self.expected.as_deref()
    }

    /// Returns the observed field value for a mismatch.
    pub fn observed(&self) -> Option<&str> {
        self.observed.as_deref()
    }

    /// Returns the PostgreSQL SQLSTATE for an identity-query failure.
    pub fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }
}

impl fmt::Display for PostgresIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PostgresIdentityError {}

fn validate_identity_value(
    field: &'static str,
    value: String,
    max_len: usize,
) -> Result<String, PostgresIdentityError> {
    if value.is_empty() {
        return Err(PostgresIdentityError::invalid_value(
            field,
            "must not be blank",
        ));
    }
    if value.trim() != value {
        return Err(PostgresIdentityError::invalid_value(
            field,
            "must not contain surrounding whitespace",
        ));
    }
    if value.len() > max_len {
        return Err(PostgresIdentityError::invalid_value(
            field,
            "exceeds the maximum length",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(PostgresIdentityError::invalid_value(
            field,
            "must not contain control characters",
        ));
    }
    Ok(value)
}

fn validate_numeric_identity_value(
    field: &'static str,
    value: String,
    max_len: usize,
) -> Result<String, PostgresIdentityError> {
    let value = validate_identity_value(field, value, max_len)?;
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PostgresIdentityError::invalid_value(
            field,
            "must be an unsigned decimal integer",
        ));
    }
    Ok(value)
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
        normalize_dsn, query_param, tls_mode_for_dsn, PgConnectionConfig, PgIdentityExpectation,
        PgInsecureTlsPolicy, PgServerIdentity, PgTlsMode,
    };

    #[test]
    fn identity_verification_binds_environment_to_observed_cluster() {
        let expected = PgIdentityExpectation::new(
            "production",
            "primary",
            "7521467493250607290",
            "application",
        )
        .expect("valid expectation");
        let observed =
            PgServerIdentity::from_values("7521467493250607290", "application", "170004")
                .expect("valid observation");

        let verified = expected.verify(&observed).expect("identity should match");

        assert_eq!(verified.environment(), "production");
        assert_eq!(verified.deployment(), "primary");
        assert_eq!(verified.server(), &observed);
    }

    #[test]
    fn identity_verification_rejects_same_database_on_different_cluster() {
        let expected = PgIdentityExpectation::new(
            "production",
            "primary",
            "7521467493250607290",
            "application",
        )
        .expect("valid expectation");
        let observed =
            PgServerIdentity::from_values("7521467493250607291", "application", "170004")
                .expect("valid observation");

        let err = expected
            .verify(&observed)
            .expect_err("same database name must not hide cluster mismatch");

        assert_eq!(err.code(), "PG_IDENTITY_MISMATCH");
        assert_eq!(err.reason(), "identity_mismatch");
        assert_eq!(err.field(), Some("cluster_system_identifier"));
        assert_eq!(err.expected(), Some("7521467493250607290"));
        assert_eq!(err.observed(), Some("7521467493250607291"));
        assert_eq!(err.sqlstate(), None);
    }

    #[test]
    fn identity_verification_rejects_database_mismatch() {
        let expected = PgIdentityExpectation::new(
            "production",
            "primary",
            "7521467493250607290",
            "application",
        )
        .expect("valid expectation");
        let observed =
            PgServerIdentity::from_values("7521467493250607290", "application_shadow", "170004")
                .expect("valid observation");

        let err = expected
            .verify(&observed)
            .expect_err("database mismatch must fail closed");

        assert_eq!(err.code(), "PG_IDENTITY_MISMATCH");
        assert_eq!(err.reason(), "identity_mismatch");
        assert_eq!(err.field(), Some("database"));
        assert_eq!(err.expected(), Some("application"));
        assert_eq!(err.observed(), Some("application_shadow"));
    }

    #[test]
    fn identity_values_reject_missing_ambiguous_or_log_unsafe_input() {
        let blank_environment =
            PgIdentityExpectation::new("", "primary", "7521467493250607290", "application")
                .expect_err("environment must be explicit");
        let non_numeric_cluster =
            PgIdentityExpectation::new("production", "primary", "cluster-a", "application")
                .expect_err("cluster identifier must be canonical");
        let unsafe_deployment = PgIdentityExpectation::new(
            "production",
            "primary\nforged",
            "7521467493250607290",
            "application",
        )
        .expect_err("control characters must be rejected");

        assert_eq!(blank_environment.code(), "PG_IDENTITY_INVALID");
        assert_eq!(blank_environment.field(), Some("environment"));
        assert_eq!(non_numeric_cluster.code(), "PG_IDENTITY_INVALID");
        assert_eq!(
            non_numeric_cluster.field(),
            Some("cluster_system_identifier")
        );
        assert_eq!(unsafe_deployment.code(), "PG_IDENTITY_INVALID");
        assert_eq!(unsafe_deployment.field(), Some("deployment"));
    }

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
        let disable = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=disable")
            .expect("parse disable");
        let absent =
            PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d").expect("parse absent");
        let require = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=require")
            .expect("parse require");
        let prefer = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=prefer")
            .expect("parse prefer");

        let disable_err = disable
            .validate_tls_policy(PgInsecureTlsPolicy::DisallowAll)
            .expect_err("disable should be rejected by strict default");
        assert_eq!(disable_err.code(), "PG_TLS_POLICY_VIOLATION");
        assert_eq!(disable_err.reason(), "tls_policy_disallowed");

        let absent_err = absent
            .validate_tls_policy(PgInsecureTlsPolicy::DisallowAll)
            .expect_err("implicit disable should be rejected by strict default");
        assert_eq!(absent_err.code(), "PG_TLS_POLICY_VIOLATION");

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
        let disable = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=disable")
            .expect("parse disable");
        let require = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=require")
            .expect("parse require");
        let prefer = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=prefer")
            .expect("parse prefer");

        disable
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireOnly)
            .expect_err("disable should remain blocked");
        require
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireOnly)
            .expect("require should be allowed");
        prefer
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireOnly)
            .expect_err("prefer should remain blocked");
    }

    #[test]
    fn connect_policy_can_explicitly_allow_compatibility_modes() {
        let disable = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=disable")
            .expect("parse disable");
        let require = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=require")
            .expect("parse require");
        let prefer = PgConnectionConfig::from_dsn("postgresql://u:p@h:5432/d?sslmode=prefer")
            .expect("parse prefer");

        disable
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireAndPrefer)
            .expect("disable should be explicitly allowed by compatibility policy");
        require
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireAndPrefer)
            .expect("require should be explicitly allowed by compatibility policy");
        prefer
            .validate_tls_policy(PgInsecureTlsPolicy::AllowRequireAndPrefer)
            .expect("prefer should be explicitly allowed by compatibility policy");
    }
}

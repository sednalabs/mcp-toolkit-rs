//! # Terminal Tool-Call Diagnostics
//!
//! Provides a closed, typed event contract for terminal MCP tool-call
//! diagnostics. The contract deliberately has no arbitrary payload, arguments,
//! body, claim-set, or error-message field.
//!
//! ## Security Boundaries
//! * Dynamic textual identifiers are validated while borrowed, then copied into
//!   a purpose-specific length-bounded type.
//! * Principal and session correlation accept only fixed-size keyed digest
//!   output produced by the caller's identity boundary, never raw identifiers.
//! * Failure records accept validated static identifiers, never dynamic error
//!   data or raw error values.
//! * Emission consumes the record, providing at-most-once emission for that
//!   record instance. Downstream lifecycle integration remains responsible for
//!   constructing exactly one record for each real tool call.
//! * Value-bearing public types use redacted `Debug` implementations.

use std::error::Error;
use std::fmt;
use std::time::Duration;

use tracing::{event, Level};

const MAX_REQUEST_ID_LEN: usize = 128;
const MAX_TOOL_NAME_LEN: usize = 128;
const MAX_ERROR_IDENTIFIER_LEN: usize = 64;
const DIGEST_BYTES: usize = 32;
const PRINCIPAL_DIGEST_PREFIX: &str = "principal-keyed256:";
const SESSION_DIGEST_PREFIX: &str = "session-keyed256:";
const CATALOGUE_FINGERPRINT_PREFIX: &str = "sha256:";
const REDACTED_DEBUG_VALUE: &str = "<redacted>";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Identifies a field in a rejected terminal diagnostic value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticField {
    RequestId,
    ToolName,
    ErrorCode,
    ErrorClass,
}

impl DiagnosticField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestId => "request_id",
            Self::ToolName => "tool_name",
            Self::ErrorCode => "error_code",
            Self::ErrorClass => "error_class",
        }
    }
}

/// Classifies why a terminal diagnostic value was rejected.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticValueErrorKind {
    Empty,
    TooLong { max_bytes: usize },
    InvalidCharacter,
}

/// Reports a rejected bounded diagnostic identifier without echoing its value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DiagnosticValueError {
    field: DiagnosticField,
    kind: DiagnosticValueErrorKind,
}

impl DiagnosticValueError {
    /// Returns the field whose value failed validation.
    pub const fn field(&self) -> DiagnosticField {
        self.field
    }

    /// Returns the non-sensitive validation failure category.
    pub const fn kind(&self) -> DiagnosticValueErrorKind {
        self.kind
    }
}

impl fmt::Display for DiagnosticValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            DiagnosticValueErrorKind::Empty => {
                write!(formatter, "{} must not be empty", self.field.as_str())
            }
            DiagnosticValueErrorKind::TooLong { max_bytes } => write!(
                formatter,
                "{} exceeds the {max_bytes}-byte limit",
                self.field.as_str()
            ),
            DiagnosticValueErrorKind::InvalidCharacter => write!(
                formatter,
                "{} contains a character outside the diagnostic identifier alphabet",
                self.field.as_str()
            ),
        }
    }
}

impl Error for DiagnosticValueError {}

#[derive(Eq, PartialEq)]
struct BoundedIdentifier(String);

impl BoundedIdentifier {
    fn parse(
        field: DiagnosticField,
        value: impl AsRef<str>,
        max_bytes: usize,
    ) -> Result<Self, DiagnosticValueError> {
        let value = value.as_ref();
        validate_identifier(field, value, max_bytes)?;
        Ok(Self(value.to_owned()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED_DEBUG_VALUE)
    }
}

#[derive(Eq, PartialEq)]
struct StaticIdentifier(&'static str);

impl StaticIdentifier {
    fn parse(
        field: DiagnosticField,
        value: &'static str,
        max_bytes: usize,
    ) -> Result<Self, DiagnosticValueError> {
        validate_identifier(field, value, max_bytes)?;
        Ok(Self(value))
    }

    fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Debug for StaticIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED_DEBUG_VALUE)
    }
}

fn validate_identifier(
    field: DiagnosticField,
    value: &str,
    max_bytes: usize,
) -> Result<(), DiagnosticValueError> {
    if value.is_empty() {
        return Err(DiagnosticValueError {
            field,
            kind: DiagnosticValueErrorKind::Empty,
        });
    }
    if value.len() > max_bytes {
        return Err(DiagnosticValueError {
            field,
            kind: DiagnosticValueErrorKind::TooLong { max_bytes },
        });
    }
    if !value.bytes().all(is_diagnostic_identifier_byte) {
        return Err(DiagnosticValueError {
            field,
            kind: DiagnosticValueErrorKind::InvalidCharacter,
        });
    }
    Ok(())
}

const fn is_diagnostic_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
}

fn encode_digest(prefix: &str, digest: [u8; DIGEST_BYTES]) -> String {
    let mut encoded = String::with_capacity(prefix.len() + (DIGEST_BYTES * 2));
    encoded.push_str(prefix);
    for byte in digest {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn redacted_wrapper_debug(
    type_name: &'static str,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    formatter
        .debug_tuple(type_name)
        .field(&REDACTED_DEBUG_VALUE)
        .finish()
}

macro_rules! bounded_owned_identifier {
    (
        $(#[$meta:meta])*
        $name:ident,
        $field:path,
        $max:ident
    ) => {
        $(#[$meta])*
        #[derive(Eq, PartialEq)]
        pub struct $name(BoundedIdentifier);

        impl $name {
            /// Creates an identifier after enforcing its closed alphabet and byte bound.
            ///
            /// # Errors
            /// Returns [`DiagnosticValueError`] when the value is empty, too long, or
            /// contains characters outside `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `:`, `/`.
            ///
            /// # Security
            /// Validation occurs against the borrowed input before this type allocates
            /// owned storage. Lexical validity does not make a value safe to disclose;
            /// callers must still use the intended identifier source.
            pub fn new(value: impl AsRef<str>) -> Result<Self, DiagnosticValueError> {
                BoundedIdentifier::parse($field, value, $max).map(Self)
            }

            /// Returns the validated identifier.
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                redacted_wrapper_debug(stringify!($name), formatter)
            }
        }
    };
}

macro_rules! bounded_static_identifier {
    (
        $(#[$meta:meta])*
        $name:ident,
        $field:path
    ) => {
        $(#[$meta])*
        #[derive(Eq, PartialEq)]
        pub struct $name(StaticIdentifier);

        impl $name {
            /// Creates an error identifier from program-static vocabulary.
            ///
            /// # Errors
            /// Returns [`DiagnosticValueError`] when the value is empty, too long, or
            /// contains characters outside `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `:`, `/`.
            ///
            /// # Security
            /// The static lifetime prevents dynamic error text and tenant data from
            /// entering this field. It does not prove governance: callers must select
            /// values from a documented or allowlisted error vocabulary.
            pub fn from_static(value: &'static str) -> Result<Self, DiagnosticValueError> {
                StaticIdentifier::parse($field, value, MAX_ERROR_IDENTIFIER_LEN).map(Self)
            }

            /// Returns the validated static identifier.
            pub fn as_str(&self) -> &'static str {
                self.0.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                redacted_wrapper_debug(stringify!($name), formatter)
            }
        }
    };
}

bounded_owned_identifier!(
    /// Correlates the terminal diagnostic with the originating request.
    RequestCorrelationId,
    DiagnosticField::RequestId,
    MAX_REQUEST_ID_LEN
);

bounded_owned_identifier!(
    /// Identifies the invoked MCP tool using its registered catalogue name.
    DiagnosticToolName,
    DiagnosticField::ToolName,
    MAX_TOOL_NAME_LEN
);

bounded_static_identifier!(
    /// Identifies a documented static error code without carrying error text.
    StaticErrorCode,
    DiagnosticField::ErrorCode
);

bounded_static_identifier!(
    /// Identifies a documented static error class without carrying error text.
    StaticErrorClass,
    DiagnosticField::ErrorClass
);

/// Carries an opaque principal correlation derived at the identity boundary.
#[derive(Eq, PartialEq)]
pub struct PrincipalCorrelationDigest(String);

impl PrincipalCorrelationDigest {
    /// Encodes a keyed, principal-domain-separated 256-bit digest.
    ///
    /// # Security
    /// The toolkit deliberately does not accept a raw principal identifier.
    /// Derive this digest with a secret-keyed construction and a principal-specific
    /// domain separator before crossing the observability boundary. An unkeyed hash
    /// of an email address or other enumerable identifier is not sufficient.
    pub fn from_keyed_digest(digest: [u8; DIGEST_BYTES]) -> Self {
        Self(encode_digest(PRINCIPAL_DIGEST_PREFIX, digest))
    }

    /// Returns the opaque rendered correlation digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrincipalCorrelationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted_wrapper_debug("PrincipalCorrelationDigest", formatter)
    }
}

/// Carries an opaque session correlation derived at the session boundary.
#[derive(Eq, PartialEq)]
pub struct SessionCorrelationDigest(String);

impl SessionCorrelationDigest {
    /// Encodes a keyed, session-domain-separated 256-bit digest.
    ///
    /// # Security
    /// The toolkit deliberately does not accept a raw session identifier. Derive
    /// this digest with a secret-keyed construction and a session-specific domain
    /// separator before crossing the observability boundary.
    pub fn from_keyed_digest(digest: [u8; DIGEST_BYTES]) -> Self {
        Self(encode_digest(SESSION_DIGEST_PREFIX, digest))
    }

    /// Returns the opaque rendered correlation digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionCorrelationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted_wrapper_debug("SessionCorrelationDigest", formatter)
    }
}

/// Carries the SHA-256 fingerprint of the schema or catalogue revision.
#[derive(Eq, PartialEq)]
pub struct CatalogueFingerprint(String);

impl CatalogueFingerprint {
    /// Encodes a 256-bit SHA-256 schema or catalogue fingerprint.
    pub fn from_sha256(digest: [u8; DIGEST_BYTES]) -> Self {
        Self(encode_digest(CATALOGUE_FINGERPRINT_PREFIX, digest))
    }

    /// Returns the rendered fingerprint.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CatalogueFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted_wrapper_debug("CatalogueFingerprint", formatter)
    }
}

/// Describes the terminal result without accepting raw error data.
#[derive(Eq, PartialEq)]
pub enum ToolCallTerminalOutcome {
    Success,
    Failure {
        code: StaticErrorCode,
        class: StaticErrorClass,
    },
}

impl fmt::Debug for ToolCallTerminalOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => formatter.write_str("Success"),
            Self::Failure { code, class } => formatter
                .debug_struct("Failure")
                .field("code", code)
                .field("class", class)
                .finish(),
        }
    }
}

/// Carries one fixed-schema terminal diagnostic record.
///
/// The record is intentionally not `Clone` or `Copy`, and [`Self::emit`]
/// consumes it. Required hosted compile-fail coverage proves that one record
/// cannot be emitted twice. The caller remains responsible for creating one
/// record per real tool-call lifecycle.
#[must_use = "terminal diagnostics must be emitted or deliberately discarded"]
#[derive(Eq, PartialEq)]
pub struct ToolCallTerminalDiagnostic {
    request_id: RequestCorrelationId,
    session_correlation: Option<SessionCorrelationDigest>,
    principal_correlation: Option<PrincipalCorrelationDigest>,
    tool_name: DiagnosticToolName,
    duration: Duration,
    outcome: ToolCallTerminalOutcome,
    catalogue_fingerprint: Option<CatalogueFingerprint>,
}

impl ToolCallTerminalDiagnostic {
    /// Creates a successful terminal diagnostic record.
    pub fn success(
        request_id: RequestCorrelationId,
        tool_name: DiagnosticToolName,
        duration: Duration,
    ) -> Self {
        Self {
            request_id,
            session_correlation: None,
            principal_correlation: None,
            tool_name,
            duration,
            outcome: ToolCallTerminalOutcome::Success,
            catalogue_fingerprint: None,
        }
    }

    /// Creates a failed terminal diagnostic from static error identifiers.
    ///
    /// # Security
    /// This constructor intentionally accepts no error object or message. Map
    /// failures to a documented static code and class before constructing the record.
    pub fn failure(
        request_id: RequestCorrelationId,
        tool_name: DiagnosticToolName,
        duration: Duration,
        code: StaticErrorCode,
        class: StaticErrorClass,
    ) -> Self {
        Self {
            request_id,
            session_correlation: None,
            principal_correlation: None,
            tool_name,
            duration,
            outcome: ToolCallTerminalOutcome::Failure { code, class },
            catalogue_fingerprint: None,
        }
    }

    /// Adds an opaque session correlation digest.
    pub fn with_session_correlation(mut self, digest: SessionCorrelationDigest) -> Self {
        self.session_correlation = Some(digest);
        self
    }

    /// Adds an opaque principal correlation digest.
    pub fn with_principal_correlation(mut self, digest: PrincipalCorrelationDigest) -> Self {
        self.principal_correlation = Some(digest);
        self
    }

    /// Adds the schema or catalogue SHA-256 fingerprint used for this call.
    pub fn with_catalogue_fingerprint(mut self, fingerprint: CatalogueFingerprint) -> Self {
        self.catalogue_fingerprint = Some(fingerprint);
        self
    }

    /// Emits one fixed-schema tracing event and consumes this record.
    ///
    /// This is an at-most-once guarantee for this record instance, not an
    /// exactly-once guarantee for an external tool-call lifecycle.
    ///
    /// # Security
    /// The event contains only the purpose-specific fields represented by this
    /// type. It has no raw error, argument, body, token, or arbitrary-field path.
    pub fn emit(self) {
        emit_tool_call_terminal(self);
    }

    fn snapshot(&self) -> ToolCallTerminalSnapshot<'_> {
        let (outcome, error_code, error_class) = match &self.outcome {
            ToolCallTerminalOutcome::Success => ("success", "", ""),
            ToolCallTerminalOutcome::Failure { code, class } => {
                ("failure", code.as_str(), class.as_str())
            }
        };

        ToolCallTerminalSnapshot {
            request_id: self.request_id.as_str(),
            session_correlation: self
                .session_correlation
                .as_ref()
                .map(SessionCorrelationDigest::as_str)
                .unwrap_or(""),
            principal_correlation: self
                .principal_correlation
                .as_ref()
                .map(PrincipalCorrelationDigest::as_str)
                .unwrap_or(""),
            tool_name: self.tool_name.as_str(),
            duration_ms: duration_millis(self.duration),
            outcome,
            error_code,
            error_class,
            catalogue_fingerprint: self
                .catalogue_fingerprint
                .as_ref()
                .map(CatalogueFingerprint::as_str)
                .unwrap_or(""),
        }
    }
}

impl fmt::Debug for ToolCallTerminalDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCallTerminalDiagnostic")
            .field("request_id", &REDACTED_DEBUG_VALUE)
            .field(
                "session_correlation",
                &self
                    .session_correlation
                    .as_ref()
                    .map(|_| REDACTED_DEBUG_VALUE),
            )
            .field(
                "principal_correlation",
                &self
                    .principal_correlation
                    .as_ref()
                    .map(|_| REDACTED_DEBUG_VALUE),
            )
            .field("tool_name", &REDACTED_DEBUG_VALUE)
            .field("duration", &self.duration)
            .field("outcome", &self.outcome)
            .field(
                "catalogue_fingerprint",
                &self
                    .catalogue_fingerprint
                    .as_ref()
                    .map(|_| REDACTED_DEBUG_VALUE),
            )
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ToolCallTerminalSnapshot<'a> {
    request_id: &'a str,
    session_correlation: &'a str,
    principal_correlation: &'a str,
    tool_name: &'a str,
    duration_ms: u64,
    outcome: &'static str,
    error_code: &'a str,
    error_class: &'a str,
    catalogue_fingerprint: &'a str,
}

/// Emits one fixed-schema terminal tracing event and consumes its record.
///
/// The same record cannot be emitted twice. Downstream lifecycle integration is
/// responsible for constructing one record for each real tool call.
///
/// # Security
/// The API accepts no raw error, arguments, body, token, claim set, or arbitrary
/// field collection. Use static error vocabulary and opaque correlation digests.
pub fn emit_tool_call_terminal(diagnostic: ToolCallTerminalDiagnostic) {
    let fields = diagnostic.snapshot();
    event!(
        target: "mcp_toolkit_observability",
        Level::INFO,
        event = "mcp.tool_call.terminal",
        request_id = fields.request_id,
        session_correlation = fields.session_correlation,
        principal_correlation = fields.principal_correlation,
        tool_name = fields.tool_name,
        duration_ms = fields.duration_ms,
        outcome = fields.outcome,
        error_code = fields.error_code,
        error_class = fields.error_class,
        catalogue_fingerprint = fields.catalogue_fingerprint,
    );
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    const PRINCIPAL_DIGEST: [u8; DIGEST_BYTES] = [0x11; DIGEST_BYTES];
    const SESSION_DIGEST: [u8; DIGEST_BYTES] = [0x22; DIGEST_BYTES];
    const CATALOGUE_DIGEST: [u8; DIGEST_BYTES] = [0x33; DIGEST_BYTES];

    fn request_id() -> RequestCorrelationId {
        RequestCorrelationId::new("request-123").expect("fixture request id is valid")
    }

    fn tool_name() -> DiagnosticToolName {
        DiagnosticToolName::new("example.read").expect("fixture tool name is valid")
    }

    fn error_code() -> StaticErrorCode {
        StaticErrorCode::from_static("request.invalid_shape").expect("valid static error code")
    }

    fn error_class() -> StaticErrorClass {
        StaticErrorClass::from_static("invalid_request").expect("valid static error class")
    }

    #[test]
    fn successful_snapshot_is_a_complete_stable_object() {
        let diagnostic = ToolCallTerminalDiagnostic::success(
            request_id(),
            tool_name(),
            Duration::from_millis(27),
        )
        .with_session_correlation(SessionCorrelationDigest::from_keyed_digest(SESSION_DIGEST))
        .with_principal_correlation(PrincipalCorrelationDigest::from_keyed_digest(
            PRINCIPAL_DIGEST,
        ))
        .with_catalogue_fingerprint(CatalogueFingerprint::from_sha256(CATALOGUE_DIGEST));
        let expected_session = format!("{SESSION_DIGEST_PREFIX}{}", "22".repeat(DIGEST_BYTES));
        let expected_principal = format!("{PRINCIPAL_DIGEST_PREFIX}{}", "11".repeat(DIGEST_BYTES));
        let expected_catalogue = format!(
            "{CATALOGUE_FINGERPRINT_PREFIX}{}",
            "33".repeat(DIGEST_BYTES)
        );

        assert_eq!(
            diagnostic.snapshot(),
            ToolCallTerminalSnapshot {
                request_id: "request-123",
                session_correlation: &expected_session,
                principal_correlation: &expected_principal,
                tool_name: "example.read",
                duration_ms: 27,
                outcome: "success",
                error_code: "",
                error_class: "",
                catalogue_fingerprint: &expected_catalogue,
            }
        );
    }

    #[test]
    fn failure_snapshot_uses_static_identifiers_and_has_no_error_text_field() {
        let diagnostic = ToolCallTerminalDiagnostic::failure(
            request_id(),
            tool_name(),
            Duration::from_millis(31),
            error_code(),
            error_class(),
        );

        assert_eq!(
            diagnostic.snapshot(),
            ToolCallTerminalSnapshot {
                request_id: "request-123",
                session_correlation: "",
                principal_correlation: "",
                tool_name: "example.read",
                duration_ms: 31,
                outcome: "failure",
                error_code: "request.invalid_shape",
                error_class: "invalid_request",
                catalogue_fingerprint: "",
            }
        );
    }

    #[test]
    fn borrowed_input_is_validated_before_owned_storage_is_created() {
        struct BorrowOnly<'a>(&'a str);

        impl AsRef<str> for BorrowOnly<'_> {
            fn as_ref(&self) -> &str {
                self.0
            }
        }

        let oversized = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        let error = RequestCorrelationId::new(BorrowOnly(&oversized))
            .expect_err("oversized borrowed input must be rejected");
        assert_eq!(
            error.kind(),
            DiagnosticValueErrorKind::TooLong {
                max_bytes: MAX_REQUEST_ID_LEN,
            }
        );
    }

    #[test]
    fn value_errors_never_echo_the_rejected_value() {
        let rejected = "Bearer secret value";
        let error = RequestCorrelationId::new(rejected).expect_err("spaces must be rejected");

        assert_eq!(error.field(), DiagnosticField::RequestId);
        assert_eq!(error.kind(), DiagnosticValueErrorKind::InvalidCharacter);
        assert!(!error.to_string().contains(rejected));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn static_error_identifiers_reject_invalid_vocabulary() {
        assert_eq!(
            StaticErrorCode::from_static("")
                .expect_err("empty values must be rejected")
                .kind(),
            DiagnosticValueErrorKind::Empty
        );
        assert_eq!(
            StaticErrorClass::from_static("invalid request")
                .expect_err("spaces must be rejected")
                .kind(),
            DiagnosticValueErrorKind::InvalidCharacter
        );
    }

    #[test]
    fn debug_output_redacts_every_value_bearing_public_type() {
        let diagnostic = ToolCallTerminalDiagnostic::failure(
            request_id(),
            tool_name(),
            Duration::from_millis(31),
            error_code(),
            error_class(),
        )
        .with_session_correlation(SessionCorrelationDigest::from_keyed_digest(SESSION_DIGEST))
        .with_principal_correlation(PrincipalCorrelationDigest::from_keyed_digest(
            PRINCIPAL_DIGEST,
        ))
        .with_catalogue_fingerprint(CatalogueFingerprint::from_sha256(CATALOGUE_DIGEST));

        let output = format!("{diagnostic:?}");
        for forbidden in [
            "request-123",
            "example.read",
            "request.invalid_shape",
            "invalid_request",
            "11111111",
            "22222222",
            "33333333",
        ] {
            assert!(!output.contains(forbidden), "debug leaked {forbidden}");
        }
        assert!(output.contains(REDACTED_DEBUG_VALUE));
    }

    #[test]
    fn emit_produces_one_terminal_event_for_one_record() {
        let sink = SharedSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_level(false)
            .compact()
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            ToolCallTerminalDiagnostic::failure(
                request_id(),
                tool_name(),
                Duration::from_millis(42),
                StaticErrorCode::from_static("db.unavailable").expect("valid static error code"),
                StaticErrorClass::from_static("dependency_failure")
                    .expect("valid static error class"),
            )
            .emit();
        });

        let output = sink.contents();
        assert_eq!(
            output,
            concat!(
                "event=\"mcp.tool_call.terminal\" ",
                "request_id=\"request-123\" ",
                "session_correlation=\"\" ",
                "principal_correlation=\"\" ",
                "tool_name=\"example.read\" ",
                "duration_ms=42 ",
                "outcome=\"failure\" ",
                "error_code=\"db.unavailable\" ",
                "error_class=\"dependency_failure\" ",
                "catalogue_fingerprint=\"\"\n",
            )
        );
    }

    #[derive(Clone, Default)]
    struct SharedSink {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedSink {
        fn contents(&self) -> String {
            let bytes = self.buffer.lock().expect("sink lock poisoned").clone();
            String::from_utf8(bytes).expect("sink should contain valid utf8")
        }
    }

    impl<'a> MakeWriter<'a> for SharedSink {
        type Writer = SharedSinkWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedSinkWriter {
                buffer: self.buffer.clone(),
            }
        }
    }

    struct SharedSinkWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedSinkWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .expect("sink lock poisoned")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

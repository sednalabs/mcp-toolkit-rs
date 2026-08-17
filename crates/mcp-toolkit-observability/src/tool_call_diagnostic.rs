//! # Terminal Tool-Call Diagnostics
//!
//! Provides a closed, typed event contract for one terminal diagnostic per MCP
//! tool call. The contract deliberately has no arbitrary payload, arguments,
//! body, claim-set, or error-message field.
//!
//! ## Security Boundaries
//! * Every textual value is represented by a purpose-specific, length-bounded
//!   type with a restricted ASCII alphabet.
//! * Failure records accept stable error identifiers, never raw error values.
//! * Emission consumes the record, preventing the same record from being
//!   emitted twice.
//! * Callers must supply opaque, already-approved identifiers. In particular,
//!   principal identifiers must not contain names, email addresses, or claims.

use std::error::Error;
use std::fmt;
use std::time::Duration;

use tracing::{event, Level};

const MAX_REQUEST_ID_LEN: usize = 128;
const MAX_SESSION_ID_LEN: usize = 128;
const MAX_PRINCIPAL_ID_LEN: usize = 96;
const MAX_TOOL_NAME_LEN: usize = 128;
const MAX_ERROR_IDENTIFIER_LEN: usize = 64;
const MAX_CATALOGUE_FINGERPRINT_LEN: usize = 128;

/// Identifies a field in a rejected terminal diagnostic value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticField {
    RequestId,
    SessionId,
    PrincipalId,
    ToolName,
    ErrorCode,
    ErrorClass,
    CatalogueFingerprint,
}

impl DiagnosticField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestId => "request_id",
            Self::SessionId => "session_id",
            Self::PrincipalId => "principal_id",
            Self::ToolName => "tool_name",
            Self::ErrorCode => "error_code",
            Self::ErrorClass => "error_class",
            Self::CatalogueFingerprint => "catalogue_fingerprint",
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

#[derive(Debug, Eq, PartialEq)]
struct BoundedIdentifier(String);

impl BoundedIdentifier {
    fn parse(
        field: DiagnosticField,
        value: impl Into<String>,
        max_bytes: usize,
    ) -> Result<Self, DiagnosticValueError> {
        let value = value.into();
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
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

const fn is_diagnostic_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
}

macro_rules! bounded_identifier {
    (
        $(#[$meta:meta])*
        $name:ident,
        $field:path,
        $max:ident
    ) => {
        $(#[$meta])*
        #[derive(Debug, Eq, PartialEq)]
        pub struct $name(BoundedIdentifier);

        impl $name {
            /// Creates an identifier after enforcing its closed alphabet and byte bound.
            ///
            /// # Errors
            /// Returns [`DiagnosticValueError`] when the value is empty, too long, or
            /// contains characters outside `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `:`, `/`.
            ///
            /// # Security
            /// The constructor does not decide whether the identifier is appropriate to
            /// disclose. Supply only an opaque identifier already approved for telemetry.
            pub fn new(value: impl Into<String>) -> Result<Self, DiagnosticValueError> {
                BoundedIdentifier::parse($field, value, $max).map(Self)
            }

            /// Returns the validated identifier.
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

bounded_identifier!(
    /// Correlates the terminal diagnostic with the originating request.
    RequestCorrelationId,
    DiagnosticField::RequestId,
    MAX_REQUEST_ID_LEN
);

bounded_identifier!(
    /// Identifies a session only when its identifier is safe to emit.
    SafeSessionId,
    DiagnosticField::SessionId,
    MAX_SESSION_ID_LEN
);

bounded_identifier!(
    /// Identifies a principal using an opaque, pre-approved telemetry identifier.
    SafePrincipalId,
    DiagnosticField::PrincipalId,
    MAX_PRINCIPAL_ID_LEN
);

bounded_identifier!(
    /// Identifies the invoked MCP tool.
    DiagnosticToolName,
    DiagnosticField::ToolName,
    MAX_TOOL_NAME_LEN
);

bounded_identifier!(
    /// Identifies a stable, documented error code without carrying error text.
    StableErrorCode,
    DiagnosticField::ErrorCode,
    MAX_ERROR_IDENTIFIER_LEN
);

bounded_identifier!(
    /// Identifies a stable error class without carrying error text.
    StableErrorClass,
    DiagnosticField::ErrorClass,
    MAX_ERROR_IDENTIFIER_LEN
);

bounded_identifier!(
    /// Identifies the schema or catalogue revision used for the call.
    CatalogueFingerprint,
    DiagnosticField::CatalogueFingerprint,
    MAX_CATALOGUE_FINGERPRINT_LEN
);

/// Describes the terminal result without accepting raw error data.
#[derive(Debug, Eq, PartialEq)]
pub enum ToolCallTerminalOutcome {
    Success,
    Failure {
        code: StableErrorCode,
        class: StableErrorClass,
    },
}

/// Carries the fixed-schema terminal diagnostic for one MCP tool call.
///
/// The record is intentionally not `Clone` or `Copy`, and [`Self::emit`]
/// consumes it. The following therefore does not compile:
///
/// ```compile_fail
/// use std::time::Duration;
/// use mcp_toolkit_observability::{
///     DiagnosticToolName, RequestCorrelationId, ToolCallTerminalDiagnostic,
/// };
///
/// let diagnostic = ToolCallTerminalDiagnostic::success(
///     RequestCorrelationId::new("request-1").unwrap(),
///     DiagnosticToolName::new("example.search").unwrap(),
///     Duration::from_millis(5),
/// );
/// diagnostic.emit();
/// diagnostic.emit();
/// ```
#[must_use = "terminal diagnostics must be emitted or deliberately discarded"]
#[derive(Debug, Eq, PartialEq)]
pub struct ToolCallTerminalDiagnostic {
    request_id: RequestCorrelationId,
    session_id: Option<SafeSessionId>,
    principal_id: Option<SafePrincipalId>,
    tool_name: DiagnosticToolName,
    duration: Duration,
    outcome: ToolCallTerminalOutcome,
    catalogue_fingerprint: Option<CatalogueFingerprint>,
}

impl ToolCallTerminalDiagnostic {
    /// Creates a successful terminal diagnostic.
    pub fn success(
        request_id: RequestCorrelationId,
        tool_name: DiagnosticToolName,
        duration: Duration,
    ) -> Self {
        Self {
            request_id,
            session_id: None,
            principal_id: None,
            tool_name,
            duration,
            outcome: ToolCallTerminalOutcome::Success,
            catalogue_fingerprint: None,
        }
    }

    /// Creates a failed terminal diagnostic from stable error identifiers.
    ///
    /// # Security
    /// This constructor intentionally accepts no error object or message. Map
    /// failures to documented, bounded identifiers before constructing the record.
    pub fn failure(
        request_id: RequestCorrelationId,
        tool_name: DiagnosticToolName,
        duration: Duration,
        code: StableErrorCode,
        class: StableErrorClass,
    ) -> Self {
        Self {
            request_id,
            session_id: None,
            principal_id: None,
            tool_name,
            duration,
            outcome: ToolCallTerminalOutcome::Failure { code, class },
            catalogue_fingerprint: None,
        }
    }

    /// Adds a session identifier that is already safe for telemetry.
    pub fn with_session_id(mut self, session_id: SafeSessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Adds an opaque principal identifier that is already safe for telemetry.
    ///
    /// # Security
    /// Do not use a display name, email address, raw claim, or subject token.
    pub fn with_principal_id(mut self, principal_id: SafePrincipalId) -> Self {
        self.principal_id = Some(principal_id);
        self
    }

    /// Adds the schema or catalogue fingerprint used for this call.
    pub fn with_catalogue_fingerprint(mut self, fingerprint: CatalogueFingerprint) -> Self {
        self.catalogue_fingerprint = Some(fingerprint);
        self
    }

    /// Emits exactly one fixed-schema terminal tracing event and consumes the record.
    ///
    /// # Security
    /// The event contains only the purpose-specific bounded fields represented by
    /// this type. It has no raw error, argument, body, token, or arbitrary-field path.
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
            session_id: self
                .session_id
                .as_ref()
                .map(SafeSessionId::as_str)
                .unwrap_or(""),
            principal_id: self
                .principal_id
                .as_ref()
                .map(SafePrincipalId::as_str)
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

#[derive(Debug, Eq, PartialEq)]
struct ToolCallTerminalSnapshot<'a> {
    request_id: &'a str,
    session_id: &'a str,
    principal_id: &'a str,
    tool_name: &'a str,
    duration_ms: u64,
    outcome: &'static str,
    error_code: &'a str,
    error_class: &'a str,
    catalogue_fingerprint: &'a str,
}

/// Emits one fixed-schema terminal tracing event and consumes its diagnostic.
///
/// # Security
/// The API accepts no raw error, arguments, body, token, claim set, or arbitrary
/// field collection. Use stable error identifiers and opaque telemetry identifiers.
pub fn emit_tool_call_terminal(diagnostic: ToolCallTerminalDiagnostic) {
    let fields = diagnostic.snapshot();
    event!(
        target: "mcp_toolkit_observability",
        Level::INFO,
        event = "mcp.tool_call.terminal",
        request_id = fields.request_id,
        session_id = fields.session_id,
        principal_id = fields.principal_id,
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

    fn request_id() -> RequestCorrelationId {
        RequestCorrelationId::new("request-123").expect("fixture request id is valid")
    }

    fn tool_name() -> DiagnosticToolName {
        DiagnosticToolName::new("work_item.read").expect("fixture tool name is valid")
    }

    #[test]
    fn successful_snapshot_is_a_complete_stable_object() {
        let diagnostic = ToolCallTerminalDiagnostic::success(
            request_id(),
            tool_name(),
            Duration::from_millis(27),
        )
        .with_session_id(SafeSessionId::new("session-9").expect("valid session id"))
        .with_principal_id(SafePrincipalId::new("service-principal-1").expect("valid principal id"))
        .with_catalogue_fingerprint(
            CatalogueFingerprint::new("sha256:0123456789abcdef")
                .expect("valid catalogue fingerprint"),
        );

        assert_eq!(
            diagnostic.snapshot(),
            ToolCallTerminalSnapshot {
                request_id: "request-123",
                session_id: "session-9",
                principal_id: "service-principal-1",
                tool_name: "work_item.read",
                duration_ms: 27,
                outcome: "success",
                error_code: "",
                error_class: "",
                catalogue_fingerprint: "sha256:0123456789abcdef",
            }
        );
    }

    #[test]
    fn failure_snapshot_uses_identifiers_and_has_no_error_text_field() {
        let diagnostic = ToolCallTerminalDiagnostic::failure(
            request_id(),
            tool_name(),
            Duration::from_millis(31),
            StableErrorCode::new("request.invalid_shape").expect("valid error code"),
            StableErrorClass::new("invalid_request").expect("valid error class"),
        );

        assert_eq!(
            diagnostic.snapshot(),
            ToolCallTerminalSnapshot {
                request_id: "request-123",
                session_id: "",
                principal_id: "",
                tool_name: "work_item.read",
                duration_ms: 31,
                outcome: "failure",
                error_code: "request.invalid_shape",
                error_class: "invalid_request",
                catalogue_fingerprint: "",
            }
        );
    }

    #[test]
    fn value_errors_never_echo_the_rejected_value() {
        let rejected = "Bearer secret value";
        let error = SafePrincipalId::new(rejected).expect_err("spaces must be rejected");

        assert_eq!(error.field(), DiagnosticField::PrincipalId);
        assert_eq!(error.kind(), DiagnosticValueErrorKind::InvalidCharacter);
        assert!(!error.to_string().contains(rejected));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn identifiers_reject_empty_oversized_and_non_ascii_values() {
        assert_eq!(
            RequestCorrelationId::new("")
                .expect_err("empty values must be rejected")
                .kind(),
            DiagnosticValueErrorKind::Empty
        );
        assert_eq!(
            StableErrorCode::new("x".repeat(MAX_ERROR_IDENTIFIER_LEN + 1))
                .expect_err("oversized values must be rejected")
                .kind(),
            DiagnosticValueErrorKind::TooLong {
                max_bytes: MAX_ERROR_IDENTIFIER_LEN,
            }
        );
        assert_eq!(
            SafeSessionId::new("session-☃")
                .expect_err("non-ascii values must be rejected")
                .kind(),
            DiagnosticValueErrorKind::InvalidCharacter
        );
    }

    #[test]
    fn emit_produces_one_terminal_event_with_the_fixed_schema() {
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
                StableErrorCode::new("db.unavailable").expect("valid error code"),
                StableErrorClass::new("dependency_failure").expect("valid error class"),
            )
            .emit();
        });

        let output = sink.contents();
        assert_eq!(output.matches("mcp.tool_call.terminal").count(), 1);
        for expected in [
            "request_id=request-123",
            "session_id=\"\"",
            "principal_id=\"\"",
            "tool_name=work_item.read",
            "duration_ms=42",
            "outcome=\"failure\"",
            "error_code=db.unavailable",
            "error_class=dependency_failure",
            "catalogue_fingerprint=\"\"",
        ] {
            assert!(output.contains(expected), "missing {expected} in {output}");
        }
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

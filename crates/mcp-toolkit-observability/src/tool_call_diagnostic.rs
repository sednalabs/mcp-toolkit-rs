//! # Terminal Tool-Call Diagnostics
//!
//! Provides a closed, typed event contract for terminal MCP tool-call
//! diagnostics. The contract deliberately has no arbitrary payload, arguments,
//! body, claim-set, identity-correlation, or error-message field.
//!
//! ## Security Boundaries
//! * Request correlation is accepted only as a canonical lowercase UUID.
//! * Tool names are validated while borrowed, then copied into a
//!   purpose-specific length-bounded type.
//! * Failure records accept only toolkit-owned error-code and error-class enums.
//! * Catalogue fingerprints accept only fixed-width SHA-256 output.
//! * Emission consumes the record, providing at-most-once emission for that
//!   record instance. Downstream lifecycle integration remains responsible for
//!   constructing exactly one record for each real tool call.
//! * Value-bearing public types use redacted `Debug` implementations.

use std::error::Error;
use std::fmt;
use std::time::Duration;

use tracing::{event, Level};

const CANONICAL_UUID_LEN: usize = 36;
const MAX_TOOL_NAME_LEN: usize = 128;
const DIGEST_BYTES: usize = 32;
const CATALOGUE_FINGERPRINT_PREFIX: &str = "sha256:";
const REDACTED_DEBUG_VALUE: &str = "<redacted>";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Identifies a field in a rejected terminal diagnostic value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticField {
    RequestId,
    ToolName,
}

impl DiagnosticField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestId => "request_id",
            Self::ToolName => "tool_name",
        }
    }
}

/// Classifies why a terminal diagnostic value was rejected.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticValueErrorKind {
    Empty,
    TooLong { max_bytes: usize },
    InvalidCharacter,
    InvalidCanonicalUuid,
}

/// Reports a rejected diagnostic value without echoing its contents.
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
            DiagnosticValueErrorKind::InvalidCanonicalUuid => write!(
                formatter,
                "{} must be a canonical lowercase UUID",
                self.field.as_str()
            ),
        }
    }
}

impl Error for DiagnosticValueError {}

fn redacted_wrapper_debug(
    type_name: &'static str,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    formatter
        .debug_tuple(type_name)
        .field(&REDACTED_DEBUG_VALUE)
        .finish()
}

/// Correlates the terminal diagnostic with its originating request.
///
/// The value is restricted to the canonical lowercase textual UUID form so it
/// is opaque, fixed-width, and non-semantic at this shared contract boundary.
#[derive(Eq, PartialEq)]
pub struct RequestCorrelationId(String);

impl RequestCorrelationId {
    /// Parses a canonical lowercase UUID after validating the borrowed input.
    ///
    /// # Errors
    /// Returns [`DiagnosticValueError`] unless `value` is exactly 36 ASCII
    /// bytes with lowercase hexadecimal groups in `8-4-4-4-12` form.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, DiagnosticValueError> {
        let value = value.as_ref();
        if !is_canonical_lowercase_uuid(value) {
            return Err(DiagnosticValueError {
                field: DiagnosticField::RequestId,
                kind: DiagnosticValueErrorKind::InvalidCanonicalUuid,
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical UUID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RequestCorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted_wrapper_debug("RequestCorrelationId", formatter)
    }
}

fn is_canonical_lowercase_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != CANONICAL_UUID_LEN {
        return false;
    }

    bytes.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f')
        }
    })
}

/// Identifies the invoked MCP tool using its registered catalogue name.
#[derive(Eq, PartialEq)]
pub struct DiagnosticToolName(String);

impl DiagnosticToolName {
    /// Creates a tool name after enforcing its closed alphabet and byte bound.
    ///
    /// # Errors
    /// Returns [`DiagnosticValueError`] when the value is empty, longer than
    /// 128 bytes, or contains characters outside `A-Z`, `a-z`, `0-9`, `-`,
    /// `_`, `.`, `:`, `/`.
    ///
    /// # Security
    /// Validation occurs against borrowed input before owned storage is
    /// allocated. Callers must still supply the registered catalogue name, not
    /// untrusted request data.
    pub fn new(value: impl AsRef<str>) -> Result<Self, DiagnosticValueError> {
        let value = value.as_ref();
        validate_tool_name(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated tool name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DiagnosticToolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted_wrapper_debug("DiagnosticToolName", formatter)
    }
}

fn validate_tool_name(value: &str) -> Result<(), DiagnosticValueError> {
    let field = DiagnosticField::ToolName;
    if value.is_empty() {
        return Err(DiagnosticValueError {
            field,
            kind: DiagnosticValueErrorKind::Empty,
        });
    }
    if value.len() > MAX_TOOL_NAME_LEN {
        return Err(DiagnosticValueError {
            field,
            kind: DiagnosticValueErrorKind::TooLong {
                max_bytes: MAX_TOOL_NAME_LEN,
            },
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

/// Toolkit-owned terminal error codes.
///
/// Public enum variants are the only construction path, so runtime strings and
/// leaked allocations cannot become diagnostic error codes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ToolCallErrorCode {
    InvalidArguments,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    Cancelled,
    Timeout,
    DependencyUnavailable,
    Internal,
}

impl ToolCallErrorCode {
    /// Returns the stable emitted representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::Internal => "internal",
        }
    }

    /// Returns the single error class assigned to this code.
    pub const fn class(self) -> ToolCallErrorClass {
        match self {
            Self::InvalidArguments => ToolCallErrorClass::InvalidRequest,
            Self::Unauthenticated => ToolCallErrorClass::Authentication,
            Self::PermissionDenied => ToolCallErrorClass::Authorization,
            Self::NotFound => ToolCallErrorClass::NotFound,
            Self::Conflict => ToolCallErrorClass::Conflict,
            Self::RateLimited => ToolCallErrorClass::ResourceExhausted,
            Self::Cancelled => ToolCallErrorClass::Cancellation,
            Self::Timeout => ToolCallErrorClass::DeadlineExceeded,
            Self::DependencyUnavailable => ToolCallErrorClass::Dependency,
            Self::Internal => ToolCallErrorClass::Internal,
        }
    }
}

/// Toolkit-owned terminal error classes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ToolCallErrorClass {
    InvalidRequest,
    Authentication,
    Authorization,
    NotFound,
    Conflict,
    ResourceExhausted,
    Cancellation,
    DeadlineExceeded,
    Dependency,
    Internal,
}

impl ToolCallErrorClass {
    /// Returns the stable emitted representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Cancellation => "cancellation",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Dependency => "dependency",
            Self::Internal => "internal",
        }
    }
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

/// Carries the SHA-256 fingerprint of the schema or catalogue revision.
#[derive(Eq, PartialEq)]
pub struct CatalogueFingerprint(String);

impl CatalogueFingerprint {
    /// Encodes a fixed-width 256-bit SHA-256 schema or catalogue fingerprint.
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
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ToolCallTerminalOutcome {
    Success,
    Failure { code: ToolCallErrorCode },
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
            tool_name,
            duration,
            outcome: ToolCallTerminalOutcome::Success,
            catalogue_fingerprint: None,
        }
    }

    /// Creates a failed terminal diagnostic from closed error enums.
    ///
    /// # Security
    /// This constructor intentionally accepts no error object, message, or
    /// string identifier. Services map failures onto toolkit-owned variants
    /// before constructing the record.
    pub fn failure(
        request_id: RequestCorrelationId,
        tool_name: DiagnosticToolName,
        duration: Duration,
        code: ToolCallErrorCode,
    ) -> Self {
        Self {
            request_id,
            tool_name,
            duration,
            outcome: ToolCallTerminalOutcome::Failure { code },
            catalogue_fingerprint: None,
        }
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
    /// type. It has no raw error, argument, body, token, identity, or
    /// arbitrary-field path.
    pub fn emit(self) {
        emit_tool_call_terminal(self);
    }

    fn snapshot(&self) -> ToolCallTerminalSnapshot<'_> {
        let (outcome, error_code, error_class) = match self.outcome {
            ToolCallTerminalOutcome::Success => ("success", "", ""),
            ToolCallTerminalOutcome::Failure { code } => {
                ("failure", code.as_str(), code.class().as_str())
            }
        };

        ToolCallTerminalSnapshot {
            request_id: self.request_id.as_str(),
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
    tool_name: &'a str,
    duration_ms: u64,
    outcome: &'static str,
    error_code: &'static str,
    error_class: &'static str,
    catalogue_fingerprint: &'a str,
}

/// Emits one fixed-schema terminal tracing event and consumes its record.
///
/// The same record cannot be emitted twice. Downstream lifecycle integration is
/// responsible for constructing one record for each real tool call.
///
/// # Security
/// The API accepts no raw error, arguments, body, token, identity, claim set, or
/// arbitrary field collection. Error values come only from closed enums.
pub fn emit_tool_call_terminal(diagnostic: ToolCallTerminalDiagnostic) {
    let fields = diagnostic.snapshot();
    event!(
        target: "mcp_toolkit_observability",
        Level::INFO,
        event = "mcp.tool_call.terminal",
        request_id = fields.request_id,
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

    const REQUEST_ID: &str = "018f3f8e-7b9a-7d12-8c34-1234567890ab";
    const CATALOGUE_DIGEST: [u8; DIGEST_BYTES] = [0x33; DIGEST_BYTES];

    fn request_id() -> RequestCorrelationId {
        RequestCorrelationId::parse(REQUEST_ID).expect("fixture request id is valid")
    }

    fn tool_name() -> DiagnosticToolName {
        DiagnosticToolName::new("example.read").expect("fixture tool name is valid")
    }

    #[test]
    fn successful_snapshot_is_a_complete_stable_object() {
        let diagnostic = ToolCallTerminalDiagnostic::success(
            request_id(),
            tool_name(),
            Duration::from_millis(27),
        )
        .with_catalogue_fingerprint(CatalogueFingerprint::from_sha256(CATALOGUE_DIGEST));
        let expected_catalogue = format!(
            "{CATALOGUE_FINGERPRINT_PREFIX}{}",
            "33".repeat(DIGEST_BYTES)
        );

        assert_eq!(
            diagnostic.snapshot(),
            ToolCallTerminalSnapshot {
                request_id: REQUEST_ID,
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
    fn failure_snapshot_uses_closed_enums_and_has_no_error_text_field() {
        let diagnostic = ToolCallTerminalDiagnostic::failure(
            request_id(),
            tool_name(),
            Duration::from_millis(31),
            ToolCallErrorCode::InvalidArguments,
        );

        assert_eq!(
            diagnostic.snapshot(),
            ToolCallTerminalSnapshot {
                request_id: REQUEST_ID,
                tool_name: "example.read",
                duration_ms: 31,
                outcome: "failure",
                error_code: "invalid_arguments",
                error_class: "invalid_request",
                catalogue_fingerprint: "",
            }
        );
    }

    #[test]
    fn request_id_accepts_only_canonical_lowercase_uuid_text() {
        for rejected in [
            "request-123",
            "018F3F8E-7B9A-7D12-8C34-1234567890AB",
            "018f3f8e-7b9a-7d12-8c34-1234567890ag",
            "018f3f8e-7b9a-7d12-8c34-1234567890ab0",
        ] {
            let error = RequestCorrelationId::parse(rejected)
                .expect_err("non-canonical request id must be rejected");
            assert_eq!(error.field(), DiagnosticField::RequestId);
            assert_eq!(error.kind(), DiagnosticValueErrorKind::InvalidCanonicalUuid);
            assert!(!error.to_string().contains(rejected));
        }

        let unhyphenated = "0".repeat(32);
        let error = RequestCorrelationId::parse(&unhyphenated)
            .expect_err("unhyphenated request id must be rejected");
        assert_eq!(error.kind(), DiagnosticValueErrorKind::InvalidCanonicalUuid);
        assert!(!error.to_string().contains(&unhyphenated));
    }

    #[test]
    fn borrowed_input_is_validated_before_owned_storage_is_created() {
        struct BorrowOnly<'a>(&'a str);

        impl AsRef<str> for BorrowOnly<'_> {
            fn as_ref(&self) -> &str {
                self.0
            }
        }

        let oversized = "x".repeat(MAX_TOOL_NAME_LEN + 1);
        let error = DiagnosticToolName::new(BorrowOnly(&oversized))
            .expect_err("oversized borrowed input must be rejected");
        assert_eq!(
            error.kind(),
            DiagnosticValueErrorKind::TooLong {
                max_bytes: MAX_TOOL_NAME_LEN,
            }
        );

        let error = RequestCorrelationId::parse(BorrowOnly("not-a-uuid"))
            .expect_err("invalid borrowed UUID must be rejected");
        assert_eq!(error.kind(), DiagnosticValueErrorKind::InvalidCanonicalUuid);
    }

    #[test]
    fn value_errors_never_echo_the_rejected_value() {
        let rejected = "Bearer secret value";
        let error = DiagnosticToolName::new(rejected).expect_err("spaces must be rejected");

        assert_eq!(error.field(), DiagnosticField::ToolName);
        assert_eq!(error.kind(), DiagnosticValueErrorKind::InvalidCharacter);
        assert!(!error.to_string().contains(rejected));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn error_code_and_derived_class_are_exhaustively_stable() {
        assert_eq!(
            [
                (
                    ToolCallErrorCode::InvalidArguments.as_str(),
                    ToolCallErrorCode::InvalidArguments.class().as_str(),
                ),
                (
                    ToolCallErrorCode::Unauthenticated.as_str(),
                    ToolCallErrorCode::Unauthenticated.class().as_str(),
                ),
                (
                    ToolCallErrorCode::PermissionDenied.as_str(),
                    ToolCallErrorCode::PermissionDenied.class().as_str(),
                ),
                (
                    ToolCallErrorCode::NotFound.as_str(),
                    ToolCallErrorCode::NotFound.class().as_str(),
                ),
                (
                    ToolCallErrorCode::Conflict.as_str(),
                    ToolCallErrorCode::Conflict.class().as_str(),
                ),
                (
                    ToolCallErrorCode::RateLimited.as_str(),
                    ToolCallErrorCode::RateLimited.class().as_str(),
                ),
                (
                    ToolCallErrorCode::Cancelled.as_str(),
                    ToolCallErrorCode::Cancelled.class().as_str(),
                ),
                (
                    ToolCallErrorCode::Timeout.as_str(),
                    ToolCallErrorCode::Timeout.class().as_str(),
                ),
                (
                    ToolCallErrorCode::DependencyUnavailable.as_str(),
                    ToolCallErrorCode::DependencyUnavailable.class().as_str(),
                ),
                (
                    ToolCallErrorCode::Internal.as_str(),
                    ToolCallErrorCode::Internal.class().as_str(),
                ),
            ],
            [
                ("invalid_arguments", "invalid_request"),
                ("unauthenticated", "authentication"),
                ("permission_denied", "authorization"),
                ("not_found", "not_found"),
                ("conflict", "conflict"),
                ("rate_limited", "resource_exhausted"),
                ("cancelled", "cancellation"),
                ("timeout", "deadline_exceeded"),
                ("dependency_unavailable", "dependency"),
                ("internal", "internal"),
            ]
        );
    }

    #[test]
    fn catalogue_fingerprint_has_fixed_width() {
        let fingerprint = CatalogueFingerprint::from_sha256(CATALOGUE_DIGEST);

        assert_eq!(
            fingerprint.as_str().len(),
            CATALOGUE_FINGERPRINT_PREFIX.len() + (DIGEST_BYTES * 2)
        );
        assert!(fingerprint
            .as_str()
            .starts_with(CATALOGUE_FINGERPRINT_PREFIX));
    }

    #[test]
    fn debug_output_redacts_every_value_bearing_public_type() {
        let diagnostic = ToolCallTerminalDiagnostic::failure(
            request_id(),
            tool_name(),
            Duration::from_millis(31),
            ToolCallErrorCode::DependencyUnavailable,
        )
        .with_catalogue_fingerprint(CatalogueFingerprint::from_sha256(CATALOGUE_DIGEST));

        let output = format!("{diagnostic:?}");
        for forbidden in [REQUEST_ID, "example.read", "33333333"] {
            assert!(!output.contains(forbidden), "debug leaked {forbidden}");
        }
        assert!(output.contains(REDACTED_DEBUG_VALUE));
    }

    #[test]
    fn emit_produces_one_complete_terminal_event_for_one_record() {
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
                ToolCallErrorCode::DependencyUnavailable,
            )
            .emit();
        });

        let output = sink.contents();
        assert_eq!(
            output,
            concat!(
                "event=\"mcp.tool_call.terminal\" ",
                "request_id=\"018f3f8e-7b9a-7d12-8c34-1234567890ab\" ",
                "tool_name=\"example.read\" ",
                "duration_ms=42 ",
                "outcome=\"failure\" ",
                "error_code=\"dependency_unavailable\" ",
                "error_class=\"dependency\" ",
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

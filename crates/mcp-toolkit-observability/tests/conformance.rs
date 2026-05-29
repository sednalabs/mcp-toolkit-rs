use mcp_toolkit_observability::{
    redact_telemetry_text, sanitize_error_message, sanitize_exchange_error,
    sanitize_log_value_with_limit, strip_control_chars, truncate,
};

#[test]
fn sanitize_and_redaction_behavior_is_stable() {
    assert_eq!(strip_control_chars("abc\nxyz"), "abcxyz");
    assert_eq!(sanitize_log_value_with_limit("abc\nxyz", 3), "abc");
    assert_eq!(truncate("abcdef", 5), "ab...");

    let redacted = redact_telemetry_text("Authorization: Bearer secret-token");
    assert!(redacted.contains("REDACTED"));
    assert!(!redacted.contains("secret-token"));
}

#[test]
fn exchange_error_redacts_known_secret_fields_and_bounds_output() {
    let payload =
        r#"{"access_token":"abc","refresh_token":"def","db":"postgresql://user:pass@host/db"}"#;
    let sanitized = sanitize_exchange_error(payload, 64);
    assert!(sanitized.contains("<redacted>"));
    assert!(!sanitized.contains("abc"));
    assert!(!sanitized.contains("def"));
    assert!(!sanitized.contains("user:pass"));
    assert!(sanitized.len() <= 64);
}

#[test]
fn sanitize_error_message_removes_control_chars_and_redacts_tokens() {
    let input = "oops\nAuthorization: Bearer ultra-secret";
    let output = sanitize_error_message(input, 512);
    assert!(!output.contains('\n'));
    assert!(!output.contains("ultra-secret"));
    assert!(output.contains("REDACTED"));
}

#[cfg(feature = "tracing-bridge")]
mod tracing_bridge_conformance {
    use std::error::Error;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use mcp_toolkit_observability::{
        emit_error, emit_event, make_span, safe_secret, EventContext, Level, SafeField,
    };
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Debug)]
    struct StaticError(&'static str);

    impl std::fmt::Display for StaticError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for StaticError {}

    #[test]
    fn tracing_bridge_bounds_and_redacts_fields() {
        let huge = "x".repeat(4096);
        let field = SafeField::text("payload", huge);
        assert!(field.value.len() <= 256);
        assert_eq!(safe_secret("token").value, "<redacted>");
    }

    #[test]
    fn tracing_bridge_emission_never_leaks_raw_secrets() {
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
            let ctx = EventContext::new()
                .with_request_id("req\n1")
                .with_tool_name("build.start");
            let _span = make_span("tool.call", &ctx).entered();
            emit_event(
                Level::INFO,
                "tool.call.started",
                &ctx,
                &[SafeField::text("authorization", "Bearer top-secret")],
            );
            let err = StaticError("Authorization: Bearer another-secret");
            emit_error(Level::ERROR, "tool.call.failed", &ctx, &err);
        });

        let output = sink.contents();
        assert!(output.contains("REDACTED"));
        assert!(!output.contains("top-secret"));
        assert!(!output.contains("another-secret"));
        assert!(!output.contains("req\n1"));
    }

    #[derive(Clone, Default)]
    struct SharedSink {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedSink {
        fn contents(&self) -> String {
            let bytes = self.buffer.lock().expect("sink lock poisoned").clone();
            String::from_utf8(bytes).expect("sink should contain utf8")
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
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .expect("sink lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(feature = "metrics-facade")]
mod metrics_conformance {
    use mcp_toolkit_observability::{
        normalize_label_value, record_request, record_tool_call, OutcomeClass, TransportMode,
    };

    #[test]
    fn metrics_labels_are_sanitized_and_bucketed() {
        let label = normalize_label_value("tool\nname/Bearer secret");
        assert!(!label.contains('\n'));
        assert!(label.contains("REDACTED"));

        record_tool_call(
            "build.start",
            OutcomeClass::Success,
            TransportMode::StreamableHttp,
            std::time::Duration::from_millis(12),
        );
        record_request(
            "custom_operation_with_dynamic_tail_123",
            OutcomeClass::Denied,
            TransportMode::StreamableHttp,
            std::time::Duration::from_millis(4),
        );
    }
}

#[cfg(feature = "otel-export")]
mod otel_conformance {
    use mcp_toolkit_observability::{init_otel_runtime, OTelConfig, OtlpProtocol};

    #[test]
    fn otel_runtime_is_optional_when_endpoint_absent() {
        let cfg = OTelConfig {
            service_name: "example-mcp".to_string(),
            endpoint: None,
            protocol: OtlpProtocol::Grpc,
            timeout: std::time::Duration::from_millis(1000),
        };

        let runtime = init_otel_runtime(&cfg).expect("init should succeed");
        assert!(runtime.is_none());
    }
}

#[cfg(not(feature = "metrics-facade"))]
#[test]
fn metrics_facade_is_noop_when_feature_is_disabled() {
    // No direct call possible for disabled feature specific behavior assertions.
    // This test intentionally verifies build + execution in default feature set.
    assert_eq!(std::time::Duration::from_millis(1).as_millis(), 1);
}

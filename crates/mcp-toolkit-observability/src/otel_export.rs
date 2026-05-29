//! # OpenTelemetry Export Bridge
//!
//! Optional OTel integration helpers for MCP tracing.
//!
//! ## Ownership
//! This module owns the initialization, configuration, and runtime management of
//! the OpenTelemetry tracing provider.
//!
//! ## Non-ownership
//! This module does not manage low-level telemetry ingestion; it acts as a bridge
//! to external OTLP exporters.
//!
//! ## Policy & Guarantees
//! * **Feature-Gated**: Tracing remains inert and side-effect free unless enabled via
//!   feature flags and environment configuration.
//! * **Execution Integrity**: Traces are only emitted when an explicit endpoint is provided.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Configuring OTel environment variables (e.g., `OTEL_EXPORTER_OTLP_ENDPOINT`).
//! * Calling `init_otel_from_env` at system startup.
//!
//! ## References
//! * `docs/design/observability.md`

use std::error::Error;
use std::fmt;
use std::time::Duration;

use crate::sanitize::sanitize_log_value_with_limit;

const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const SERVICE_NAME_MAX_LEN: usize = 64;
const ENDPOINT_MAX_LEN: usize = 256;

/// OTLP protocol selection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OtlpProtocol {
    Grpc,
    HttpProtobuf,
}

impl OtlpProtocol {
    fn from_env(raw: Option<String>) -> Self {
        match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
            "http/protobuf" | "http" => Self::HttpProtobuf,
            _ => Self::Grpc,
        }
    }
}

/// OTel configuration loaded from environment.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OTelConfig {
    pub service_name: String,
    pub endpoint: Option<String>,
    pub protocol: OtlpProtocol,
    pub timeout: Duration,
}

/// Loads OTel configuration from environment.
pub fn load_otel_config_from_env(default_service_name: &str) -> OTelConfig {
    let service_name = sanitize_or_default(
        std::env::var("MCP_OTEL_SERVICE_NAME").ok(),
        default_service_name,
        SERVICE_NAME_MAX_LEN,
    );

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .map(|raw| sanitize_log_value_with_limit(raw.trim(), ENDPOINT_MAX_LEN))
        .filter(|value| !value.is_empty());

    let protocol = OtlpProtocol::from_env(std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").ok());

    let timeout = std::env::var("OTEL_EXPORTER_OTLP_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_TIMEOUT_MS));

    OTelConfig {
        service_name,
        endpoint,
        protocol,
        timeout,
    }
}

fn sanitize_or_default(raw: Option<String>, default: &str, max_len: usize) -> String {
    let candidate = raw
        .as_deref()
        .map(|value| sanitize_log_value_with_limit(value.trim(), max_len))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sanitize_log_value_with_limit(default, max_len));
    if candidate.is_empty() {
        "mcp-service".to_string()
    } else {
        candidate
    }
}

/// OTel initialization error.
#[derive(Debug, Clone)]
pub struct OTelInitError {
    message: String,
}

#[cfg(feature = "otel-export")]
impl OTelInitError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OTelInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for OTelInitError {}

#[cfg(feature = "otel-export")]
use opentelemetry::global;
#[cfg(feature = "otel-export")]
use opentelemetry::trace::TracerProvider as _;
#[cfg(feature = "otel-export")]
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
#[cfg(feature = "otel-export")]
use opentelemetry_sdk::trace::{SdkTracerProvider, Tracer};
#[cfg(feature = "otel-export")]
use opentelemetry_sdk::Resource;
#[cfg(feature = "otel-export")]
use tracing::Subscriber;
#[cfg(feature = "otel-export")]
use tracing_subscriber::registry::LookupSpan;

#[cfg(feature = "otel-export")]
pub use tracing_opentelemetry::OpenTelemetryLayer;

/// Runtime handle for an initialized OTel tracer provider.
#[cfg(feature = "otel-export")]
#[derive(Debug, Clone)]
pub struct OTelRuntime {
    provider: SdkTracerProvider,
    tracer: Tracer,
}

#[cfg(feature = "otel-export")]
impl OTelRuntime {
    /// Returns a clone of the configured tracer.
    pub fn tracer(&self) -> Tracer {
        self.tracer.clone()
    }

    /// Shuts down the provider and flushes exporters.
    pub fn shutdown(self) -> Result<(), OTelInitError> {
        self.provider
            .shutdown()
            .map_err(|err| OTelInitError::new(err.to_string()))
    }
}

#[cfg(not(feature = "otel-export"))]
#[derive(Debug, Clone)]
pub struct OTelRuntime;

/// Initializes optional OTel export based on environment.
pub fn init_otel_from_env(
    default_service_name: &str,
) -> Result<Option<OTelRuntime>, OTelInitError> {
    let config = load_otel_config_from_env(default_service_name);
    init_otel_runtime(&config)
}

/// Initializes optional OTel export from explicit configuration.
#[cfg(feature = "otel-export")]
pub fn init_otel_runtime(config: &OTelConfig) -> Result<Option<OTelRuntime>, OTelInitError> {
    let Some(endpoint) = config.endpoint.clone() else {
        return Ok(None);
    };

    if config.protocol == OtlpProtocol::HttpProtobuf {
        return Err(OTelInitError::new(
            "http/protobuf OTLP export is not enabled in this build; use grpc protocol",
        ));
    }

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(config.timeout)
        .build()
        .map_err(|err| OTelInitError::new(err.to_string()))?;

    let resource = Resource::builder_empty()
        .with_service_name(config.service_name.clone())
        .build();

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer(config.service_name.clone());
    global::set_tracer_provider(provider.clone());

    Ok(Some(OTelRuntime { provider, tracer }))
}

#[cfg(not(feature = "otel-export"))]
pub fn init_otel_runtime(_config: &OTelConfig) -> Result<Option<OTelRuntime>, OTelInitError> {
    Ok(None)
}

/// Builds a tracing layer from an initialized OTel runtime.
#[cfg(feature = "otel-export")]
pub fn otel_tracing_layer<S>(runtime: &OTelRuntime) -> OpenTelemetryLayer<S, Tracer>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    tracing_opentelemetry::layer().with_tracer(runtime.tracer())
}

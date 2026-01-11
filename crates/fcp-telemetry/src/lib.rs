//! FCP Telemetry - Unified Metrics, Logging, and Tracing for FCP Connectors
//!
//! This crate provides comprehensive observability infrastructure for FCP connectors:
//!
//! - **Structured Logging**: JSON-formatted logs with automatic field injection
//! - **Metrics Collection**: Counters, gauges, histograms with Prometheus export
//! - **Distributed Tracing**: Span creation with W3C Trace Context propagation
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_telemetry::{TelemetryConfig, init_telemetry};
//!
//! // Initialize with defaults
//! init_telemetry(TelemetryConfig::default()).await?;
//!
//! // Use tracing macros as normal
//! tracing::info!(connector_id = "my-connector", "Starting up");
//!
//! // Record metrics
//! fcp_telemetry::metrics::increment_counter("requests_total", &[("connector", "my-connector")]);
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod context;
mod logging;
pub mod metrics;
mod tracing_layer;
mod export;

pub use context::*;
pub use logging::*;
pub use tracing_layer::*;
pub use export::*;

use std::sync::OnceLock;

/// Global telemetry state.
static TELEMETRY: OnceLock<TelemetryState> = OnceLock::new();

/// Internal telemetry state.
struct TelemetryState {
    #[allow(dead_code)]
    config: TelemetryConfig,
}

/// Configuration for telemetry initialization.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service/connector name for identifying logs and metrics.
    pub service_name: String,

    /// Log level filter (e.g., "info", "debug", "trace").
    pub log_level: String,

    /// Enable JSON log output.
    pub json_logs: bool,

    /// Enable Prometheus metrics endpoint.
    pub prometheus_enabled: bool,

    /// Prometheus metrics endpoint port.
    pub prometheus_port: u16,

    /// Enable OTLP trace export.
    pub otlp_enabled: bool,

    /// OTLP endpoint URL.
    pub otlp_endpoint: Option<String>,

    /// Sample rate for tracing (0.0 to 1.0).
    pub trace_sample_rate: f64,

    /// Fields to redact from logs (sensitive data).
    pub redact_fields: Vec<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "fcp-connector".to_string(),
            log_level: "info".to_string(),
            json_logs: true,
            prometheus_enabled: false,
            prometheus_port: 9090,
            otlp_enabled: false,
            otlp_endpoint: None,
            trace_sample_rate: 1.0,
            redact_fields: vec![
                "password".to_string(),
                "api_key".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "authorization".to_string(),
            ],
        }
    }
}

impl TelemetryConfig {
    /// Create a new configuration with the given service name.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            ..Default::default()
        }
    }

    /// Set the log level.
    #[must_use]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Enable or disable JSON logs.
    #[must_use]
    pub const fn with_json_logs(mut self, enabled: bool) -> Self {
        self.json_logs = enabled;
        self
    }

    /// Enable Prometheus metrics on the given port.
    #[must_use]
    pub const fn with_prometheus(mut self, port: u16) -> Self {
        self.prometheus_enabled = true;
        self.prometheus_port = port;
        self
    }

    /// Enable OTLP trace export to the given endpoint.
    #[must_use]
    pub fn with_otlp(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_enabled = true;
        self.otlp_endpoint = Some(endpoint.into());
        self
    }

    /// Set the trace sampling rate (0.0 to 1.0).
    #[must_use]
    pub const fn with_sample_rate(mut self, rate: f64) -> Self {
        self.trace_sample_rate = rate;
        self
    }

    /// Add fields to redact from logs.
    #[must_use]
    pub fn with_redact_fields(mut self, fields: Vec<String>) -> Self {
        self.redact_fields.extend(fields);
        self
    }
}

/// Initialize the telemetry system.
///
/// This should be called once at application startup. Subsequent calls are no-ops.
///
/// # Errors
///
/// Returns an error if telemetry initialization fails.
pub async fn init_telemetry(config: TelemetryConfig) -> Result<(), TelemetryError> {
    // Initialize logging
    init_logging(&config)?;

    // Initialize metrics if Prometheus enabled
    if config.prometheus_enabled {
        init_prometheus_exporter(config.prometheus_port)?;
    }

    // Initialize OTLP tracing if enabled
    if config.otlp_enabled {
        if let Some(ref endpoint) = config.otlp_endpoint {
            init_otlp_tracer(&config.service_name, endpoint).await?;
        }
    }

    // Store config
    let _ = TELEMETRY.set(TelemetryState { config });

    Ok(())
}

/// Initialize telemetry synchronously (for simple use cases without OTLP).
///
/// # Errors
///
/// Returns an error if initialization fails.
pub fn init_telemetry_sync(config: TelemetryConfig) -> Result<(), TelemetryError> {
    // Initialize logging
    init_logging(&config)?;

    // Initialize metrics if Prometheus enabled
    if config.prometheus_enabled {
        init_prometheus_exporter(config.prometheus_port)?;
    }

    // Store config
    let _ = TELEMETRY.set(TelemetryState { config });

    Ok(())
}

/// Telemetry error type.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// Failed to initialize logging.
    #[error("Failed to initialize logging: {0}")]
    LoggingInit(String),

    /// Failed to initialize metrics.
    #[error("Failed to initialize metrics: {0}")]
    MetricsInit(String),

    /// Failed to initialize tracing.
    #[error("Failed to initialize tracing: {0}")]
    TracingInit(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Shutdown telemetry gracefully.
///
/// This flushes any pending metrics and traces.
pub async fn shutdown_telemetry() {
    // Shutdown OpenTelemetry if initialized
    opentelemetry::global::shutdown_tracer_provider();
}

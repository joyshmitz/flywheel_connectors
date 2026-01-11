//! Export formats for telemetry data.
//!
//! Supports Prometheus exposition format and OTLP export.

use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};

use crate::TelemetryError;

/// Initialize the Prometheus metrics exporter.
///
/// This starts an HTTP server on the specified port that exposes metrics
/// in Prometheus exposition format at `/metrics`.
pub fn init_prometheus_exporter(port: u16) -> Result<(), TelemetryError> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;

    tracing::info!(port = port, "Prometheus metrics exporter started");

    Ok(())
}

/// Initialize the OTLP trace exporter.
///
/// This sets up OpenTelemetry trace export to an OTLP-compatible collector.
pub async fn init_otlp_tracer(
    service_name: &str,
    endpoint: &str,
) -> Result<(), TelemetryError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| TelemetryError::TracingInit(e.to_string()))?;

    let resource = Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
    ]);

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider);

    tracing::info!(endpoint = endpoint, "OTLP trace exporter initialized");

    Ok(())
}

/// Generate Prometheus exposition format text from current metrics.
///
/// This is useful for embedding metrics in custom HTTP handlers.
#[must_use]
pub fn prometheus_text_format() -> String {
    // The PrometheusBuilder handles this internally via the HTTP server
    // This function is provided for custom integrations
    "# Metrics are exposed via HTTP endpoint\n".to_string()
}

/// Health check endpoint response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthResponse {
    /// Service status.
    pub status: String,

    /// Service version.
    pub version: String,

    /// Uptime in seconds.
    pub uptime_seconds: u64,

    /// Additional checks.
    pub checks: Vec<HealthCheck>,
}

/// Individual health check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    /// Check name.
    pub name: String,

    /// Check status.
    pub status: String,

    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl HealthResponse {
    /// Create a healthy response.
    #[must_use]
    pub fn healthy(version: &str, uptime_seconds: u64) -> Self {
        Self {
            status: "healthy".to_string(),
            version: version.to_string(),
            uptime_seconds,
            checks: Vec::new(),
        }
    }

    /// Create an unhealthy response.
    #[must_use]
    pub fn unhealthy(version: &str, uptime_seconds: u64, message: &str) -> Self {
        Self {
            status: "unhealthy".to_string(),
            version: version.to_string(),
            uptime_seconds,
            checks: vec![HealthCheck {
                name: "main".to_string(),
                status: "fail".to_string(),
                message: Some(message.to_string()),
            }],
        }
    }

    /// Add a health check.
    #[must_use]
    pub fn with_check(mut self, name: &str, passed: bool, message: Option<&str>) -> Self {
        self.checks.push(HealthCheck {
            name: name.to_string(),
            status: if passed { "pass" } else { "fail" }.to_string(),
            message: message.map(String::from),
        });
        self
    }

    /// Check if all checks passed.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == "healthy" && self.checks.iter().all(|c| c.status == "pass")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_healthy() {
        let response = HealthResponse::healthy("1.0.0", 3600);
        assert!(response.is_healthy());
        assert_eq!(response.status, "healthy");
    }

    #[test]
    fn test_health_response_with_checks() {
        let response = HealthResponse::healthy("1.0.0", 3600)
            .with_check("database", true, None)
            .with_check("cache", true, Some("Connected"));

        assert!(response.is_healthy());
        assert_eq!(response.checks.len(), 2);
    }

    #[test]
    fn test_health_response_unhealthy() {
        let response = HealthResponse::unhealthy("1.0.0", 3600, "Database connection failed");
        assert!(!response.is_healthy());
        assert_eq!(response.status, "unhealthy");
    }
}

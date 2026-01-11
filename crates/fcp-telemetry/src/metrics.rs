//! Metrics collection for FCP connectors.
//!
//! Provides counters, gauges, histograms, and timers with label support.

use std::sync::OnceLock;
use std::time::Instant;

use metrics::{
    counter, gauge, histogram,
    describe_counter, describe_gauge, describe_histogram,
    Counter, Gauge, Histogram,
};

/// Global metrics registry state.
static METRICS_INITIALIZED: OnceLock<bool> = OnceLock::new();

/// Initialize the metrics system with standard FCP metrics descriptions.
pub fn init_metrics() {
    if METRICS_INITIALIZED.set(true).is_err() {
        return; // Already initialized
    }

    // Request metrics
    describe_counter!(
        "fcp_requests_total",
        "Total number of FCP requests processed"
    );
    describe_counter!(
        "fcp_requests_errors_total",
        "Total number of FCP request errors"
    );
    describe_histogram!(
        "fcp_request_duration_seconds",
        "FCP request duration in seconds"
    );

    // Connection metrics
    describe_gauge!(
        "fcp_connections_active",
        "Number of active connections"
    );
    describe_gauge!(
        "fcp_connections_total",
        "Total number of connections (including closed)"
    );

    // Health metrics
    describe_gauge!(
        "fcp_health_status",
        "Connector health status (1=ready, 0.5=degraded, 0=error)"
    );
    describe_gauge!(
        "fcp_uptime_seconds",
        "Connector uptime in seconds"
    );

    // Queue metrics
    describe_gauge!(
        "fcp_queue_depth",
        "Current queue depth"
    );
    describe_counter!(
        "fcp_queue_processed_total",
        "Total items processed from queue"
    );

    // Rate limit metrics
    describe_gauge!(
        "fcp_rate_limit_remaining",
        "Remaining rate limit quota"
    );
    describe_counter!(
        "fcp_rate_limit_exceeded_total",
        "Total number of rate limit exceeded events"
    );

    // Event metrics
    describe_counter!(
        "fcp_events_emitted_total",
        "Total events emitted"
    );
    describe_counter!(
        "fcp_events_dropped_total",
        "Total events dropped"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Counter Operations
// ─────────────────────────────────────────────────────────────────────────────

/// Increment a counter by 1.
pub fn increment_counter(name: &'static str, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    counter!(name, &labels).increment(1);
}

/// Increment a counter by a specific amount.
pub fn increment_counter_by(name: &'static str, value: u64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    counter!(name, &labels).increment(value);
}

/// Get a counter handle for repeated operations.
#[must_use]
pub fn get_counter(name: &'static str, labels: &[(&'static str, &str)]) -> Counter {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    counter!(name, &labels)
}

// ─────────────────────────────────────────────────────────────────────────────
// Gauge Operations
// ─────────────────────────────────────────────────────────────────────────────

/// Set a gauge value.
pub fn set_gauge(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    gauge!(name, &labels).set(value);
}

/// Increment a gauge.
pub fn increment_gauge(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    gauge!(name, &labels).increment(value);
}

/// Decrement a gauge.
pub fn decrement_gauge(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    gauge!(name, &labels).decrement(value);
}

/// Get a gauge handle for repeated operations.
#[must_use]
pub fn get_gauge(name: &'static str, labels: &[(&'static str, &str)]) -> Gauge {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    gauge!(name, &labels)
}

// ─────────────────────────────────────────────────────────────────────────────
// Histogram Operations
// ─────────────────────────────────────────────────────────────────────────────

/// Record a histogram value.
pub fn record_histogram(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    histogram!(name, &labels).record(value);
}

/// Get a histogram handle for repeated operations.
#[must_use]
pub fn get_histogram(name: &'static str, labels: &[(&'static str, &str)]) -> Histogram {
    let labels: Vec<(&'static str, String)> = labels
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    histogram!(name, &labels)
}

// ─────────────────────────────────────────────────────────────────────────────
// Timer Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A timer for measuring operation duration.
pub struct Timer {
    start: Instant,
    name: &'static str,
    labels: Vec<(&'static str, String)>,
}

impl Timer {
    /// Start a new timer.
    #[must_use]
    pub fn start(name: &'static str, labels: &[(&'static str, &str)]) -> Self {
        Self {
            start: Instant::now(),
            name,
            labels: labels.iter().map(|(k, v)| (*k, v.to_string())).collect(),
        }
    }

    /// Get elapsed time in seconds.
    #[must_use]
    pub fn elapsed_seconds(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Get elapsed time in milliseconds.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Stop the timer and record to histogram.
    pub fn stop(self) {
        histogram!(self.name, &self.labels).record(self.start.elapsed().as_secs_f64());
    }

    /// Stop and record, returning elapsed seconds.
    pub fn stop_and_return(self) -> f64 {
        let elapsed = self.elapsed_seconds();
        self.stop();
        elapsed
    }
}

/// RAII guard for timing a scope.
pub struct TimerGuard {
    timer: Option<Timer>,
}

impl TimerGuard {
    /// Create a new timer guard.
    #[must_use]
    pub fn new(name: &'static str, labels: &[(&'static str, &str)]) -> Self {
        Self {
            timer: Some(Timer::start(name, labels)),
        }
    }

    /// Get elapsed time so far.
    #[must_use]
    pub fn elapsed_seconds(&self) -> f64 {
        self.timer.as_ref().map_or(0.0, Timer::elapsed_seconds)
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.stop();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-defined FCP Metrics Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Record a successful request.
pub fn record_request_success(connector: &str, operation: &str, duration_seconds: f64) {
    increment_counter("fcp_requests_total", &[
        ("connector", connector),
        ("operation", operation),
        ("status", "success"),
    ]);
    record_histogram("fcp_request_duration_seconds", duration_seconds, &[
        ("connector", connector),
        ("operation", operation),
    ]);
}

/// Record a failed request.
pub fn record_request_error(connector: &str, operation: &str, error_type: &str, duration_seconds: f64) {
    increment_counter("fcp_requests_total", &[
        ("connector", connector),
        ("operation", operation),
        ("status", "error"),
    ]);
    increment_counter("fcp_requests_errors_total", &[
        ("connector", connector),
        ("operation", operation),
        ("error_type", error_type),
    ]);
    record_histogram("fcp_request_duration_seconds", duration_seconds, &[
        ("connector", connector),
        ("operation", operation),
    ]);
}

/// Update health status metric.
pub fn update_health_status(connector: &str, status: HealthStatusMetric) {
    let value = match status {
        HealthStatusMetric::Ready => 1.0,
        HealthStatusMetric::Degraded => 0.5,
        HealthStatusMetric::Error => 0.0,
    };
    set_gauge("fcp_health_status", value, &[("connector", connector)]);
}

/// Health status for metrics.
#[derive(Debug, Clone, Copy)]
pub enum HealthStatusMetric {
    /// Connector is ready.
    Ready,
    /// Connector is degraded.
    Degraded,
    /// Connector is in error state.
    Error,
}

/// Update rate limit metrics.
pub fn update_rate_limit(connector: &str, remaining: u32, exceeded: bool) {
    set_gauge("fcp_rate_limit_remaining", f64::from(remaining), &[("connector", connector)]);
    if exceeded {
        increment_counter("fcp_rate_limit_exceeded_total", &[("connector", connector)]);
    }
}

/// Record event emission.
pub fn record_event_emitted(connector: &str, event_type: &str) {
    increment_counter("fcp_events_emitted_total", &[
        ("connector", connector),
        ("event_type", event_type),
    ]);
}

/// Record dropped event.
pub fn record_event_dropped(connector: &str, event_type: &str, reason: &str) {
    increment_counter("fcp_events_dropped_total", &[
        ("connector", connector),
        ("event_type", event_type),
        ("reason", reason),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer() {
        let timer = Timer::start("test_metric", &[("test", "true")]);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();
        assert!(elapsed >= 10);
    }

    #[test]
    fn test_timer_guard() {
        let guard = TimerGuard::new("test_metric", &[("test", "true")]);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = guard.elapsed_seconds();
        assert!(elapsed >= 0.01);
    }
}

//! Test harness for FCP connectors.
//!
//! The [`ConnectorTestHarness`] wraps a connector and provides:
//! - Automatic logging and request/response recording
//! - Convenience methods for common test flows
//! - Built-in assertions for connector state

use std::time::Instant;

use fcp_core::{FcpConnector, FcpResult, HealthSnapshot};
use tracing::{debug, info};

/// Recorded operation for test inspection.
#[derive(Debug, Clone)]
pub struct RecordedOperation {
    /// Operation name
    pub operation: String,
    /// Input parameters (as JSON)
    pub input: Option<serde_json::Value>,
    /// Result (success value or error message)
    pub result: Result<serde_json::Value, String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Test harness that wraps an FCP connector with testing utilities.
///
/// Provides:
/// - Request/response recording for assertions
/// - Timing measurements
/// - Convenience methods for common test flows
/// - State tracking
pub struct ConnectorTestHarness<C> {
    connector: C,
    operations: Vec<RecordedOperation>,
    configured: bool,
    handshaken: bool,
}

impl<C: FcpConnector> ConnectorTestHarness<C> {
    /// Create a new test harness wrapping the given connector.
    pub const fn new(connector: C) -> Self {
        Self {
            connector,
            operations: Vec::new(),
            configured: false,
            handshaken: false,
        }
    }

    /// Get a reference to the inner connector.
    pub const fn connector(&self) -> &C {
        &self.connector
    }

    /// Get a mutable reference to the inner connector.
    pub const fn connector_mut(&mut self) -> &mut C {
        &mut self.connector
    }

    /// Get all recorded operations.
    #[must_use]
    pub fn operations(&self) -> &[RecordedOperation] {
        &self.operations
    }

    /// Get the last recorded operation.
    #[must_use]
    pub fn last_operation(&self) -> Option<&RecordedOperation> {
        self.operations.last()
    }

    /// Clear recorded operations.
    pub fn clear_operations(&mut self) {
        self.operations.clear();
    }

    /// Check if the harness has been configured.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.configured
    }

    /// Check if the harness has completed handshake.
    #[must_use]
    pub const fn is_handshaken(&self) -> bool {
        self.handshaken
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    /// Configure the connector with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration fails.
    pub async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let start = Instant::now();
        info!("Configuring connector with: {:?}", config);

        let result = self.connector.configure(config.clone()).await;

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        self.operations.push(RecordedOperation {
            operation: "configure".to_string(),
            input: Some(config),
            result: result
                .as_ref()
                .map(|()| serde_json::json!({}))
                .map_err(ToString::to_string),
            duration_ms,
            timestamp: chrono::Utc::now(),
        });

        if result.is_ok() {
            self.configured = true;
        }

        result
    }

    /// Configure with an empty configuration object.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration fails.
    pub async fn configure_default(&mut self) -> FcpResult<()> {
        self.configure(serde_json::json!({})).await
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Health
    // ─────────────────────────────────────────────────────────────────────────────

    /// Get the connector's health status.
    pub async fn health(&mut self) -> HealthSnapshot {
        let start = Instant::now();
        debug!("Getting health status");

        let result = self.connector.health().await;

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        self.operations.push(RecordedOperation {
            operation: "health".to_string(),
            input: None,
            result: Ok(serde_json::to_value(&result).unwrap_or_default()),
            duration_ms,
            timestamp: chrono::Utc::now(),
        });

        result
    }

    /// Get the connector's introspection data.
    pub fn introspect(&mut self) -> fcp_core::Introspection {
        let start = Instant::now();
        debug!("Getting introspection");

        let result = self.connector.introspect();

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        self.operations.push(RecordedOperation {
            operation: "introspect".to_string(),
            input: None,
            result: Ok(serde_json::to_value(&result).unwrap_or_default()),
            duration_ms,
            timestamp: chrono::Utc::now(),
        });

        result
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Assertions
    // ─────────────────────────────────────────────────────────────────────────────

    /// Assert that the last operation succeeded.
    ///
    /// # Panics
    ///
    /// Panics if the last operation failed or no operations recorded.
    pub fn assert_last_success(&self) {
        let op = self.last_operation().expect("No operations recorded");
        assert!(op.result.is_ok(), "Last operation failed: {:?}", op.result);
    }

    /// Assert that the last operation failed.
    ///
    /// # Panics
    ///
    /// Panics if the last operation succeeded or no operations recorded.
    pub fn assert_last_failure(&self) {
        let op = self.last_operation().expect("No operations recorded");
        assert!(
            op.result.is_err(),
            "Expected failure but got: {:?}",
            op.result
        );
    }

    /// Assert the connector is ready.
    ///
    /// # Panics
    ///
    /// Panics if the connector is not ready.
    pub async fn assert_ready(&mut self) {
        let health = self.health().await;
        assert!(
            health.is_ready(),
            "Connector not ready: {:?}",
            health.status
        );
    }

    /// Assert the connector is healthy (ready or degraded).
    ///
    /// # Panics
    ///
    /// Panics if the connector is not healthy.
    pub async fn assert_healthy(&mut self) {
        let health = self.health().await;
        assert!(
            health.is_healthy(),
            "Connector not healthy: {:?}",
            health.status
        );
    }

    /// Assert total operation count.
    ///
    /// # Panics
    ///
    /// Panics if count doesn't match.
    pub fn assert_operation_count(&self, expected: usize) {
        assert_eq!(
            self.operations.len(),
            expected,
            "Expected {} operations but got {}",
            expected,
            self.operations.len()
        );
    }

    /// Assert all operations completed under the given duration.
    ///
    /// # Panics
    ///
    /// Panics if any operation exceeded the duration.
    pub fn assert_all_under_duration(&self, max_ms: u64) {
        for op in &self.operations {
            assert!(
                op.duration_ms <= max_ms,
                "Operation '{}' took {}ms, exceeding limit of {}ms",
                op.operation,
                op.duration_ms,
                max_ms
            );
        }
    }

    /// Get statistics about recorded operations.
    #[must_use]
    pub fn stats(&self) -> HarnessStats {
        let total = self.operations.len();
        let successes = self
            .operations
            .iter()
            .filter(|op| op.result.is_ok())
            .count();
        let failures = total - successes;
        let total_duration_ms: u64 = self.operations.iter().map(|op| op.duration_ms).sum();
        let avg_duration_ms = if total > 0 {
            total_duration_ms / total as u64
        } else {
            0
        };
        let max_duration_ms = self
            .operations
            .iter()
            .map(|op| op.duration_ms)
            .max()
            .unwrap_or(0);

        HarnessStats {
            total_operations: total,
            successes,
            failures,
            total_duration_ms,
            avg_duration_ms,
            max_duration_ms,
        }
    }
}

/// Statistics about harness operations.
#[derive(Debug, Clone)]
pub struct HarnessStats {
    /// Total operations executed
    pub total_operations: usize,
    /// Successful operations
    pub successes: usize,
    /// Failed operations
    pub failures: usize,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
    /// Average duration in milliseconds
    pub avg_duration_ms: u64,
    /// Maximum duration in milliseconds
    pub max_duration_ms: u64,
}

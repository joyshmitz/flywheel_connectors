//! Connector trait and base types.
//!
//! Based on FCP Specification Section 4 (System Architecture).

use std::pin::Pin;

use async_trait::async_trait;
use futures_util::Stream;

use crate::{
    CapabilityToken, ConnectorId, EventEnvelope, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, Introspection, InvokeRequest, InvokeResponse, ShutdownRequest,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};

/// Type alias for event streams.
pub type EventStream = Pin<Box<dyn Stream<Item = FcpResult<EventEnvelope>> + Send>>;

/// Core connector trait - all FCP connectors must implement this.
#[async_trait]
pub trait FcpConnector: Send + Sync {
    /// Get the connector's unique identifier.
    fn id(&self) -> &ConnectorId;

    /// Configure the connector with the given settings.
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()>;

    /// Perform the FCP handshake.
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse>;

    /// Get the current health status.
    async fn health(&self) -> HealthSnapshot;

    /// Get connector metrics.
    fn metrics(&self) -> ConnectorMetrics;

    /// Gracefully shutdown the connector.
    async fn shutdown(&mut self, req: ShutdownRequest) -> FcpResult<()>;

    /// Get introspection data describing capabilities.
    fn introspect(&self) -> Introspection;

    /// Invoke an operation.
    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;

    /// Subscribe to event topics.
    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse>;

    /// Unsubscribe from event topics.
    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()>;
}

/// Connector metrics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct ConnectorMetrics {
    /// Total requests received
    pub requests_total: u64,
    /// Successful requests
    pub requests_success: u64,
    /// Failed requests
    pub requests_error: u64,
    /// Active connections/sessions
    pub connections_active: u64,
    /// Events emitted
    pub events_emitted: u64,
    /// Current request latency (p50) in milliseconds
    pub latency_p50_ms: u64,
    /// Current request latency (p99) in milliseconds
    pub latency_p99_ms: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Archetype Traits
// ─────────────────────────────────────────────────────────────────────────────

/// Request-response archetype (e.g., REST API, GraphQL).
#[async_trait]
pub trait RequestResponse: FcpConnector {
    /// Send a request and wait for a response.
    async fn request(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;
}

/// Streaming archetype (e.g., WebSocket, SSE).
#[async_trait]
pub trait Streaming: FcpConnector {
    /// Subscribe to a stream.
    async fn stream_subscribe(&self, topic: &str) -> FcpResult<EventStream>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

/// Bidirectional archetype (e.g., WebSocket chat).
#[async_trait]
pub trait Bidirectional: Streaming {
    /// Send a message to the stream.
    async fn send(&self, message: serde_json::Value) -> FcpResult<()>;
}

/// Polling archetype (e.g., IMAP, RSS).
#[async_trait]
pub trait Polling: FcpConnector {
    /// Start polling a target.
    async fn start_polling(
        &self,
        target: &str,
        interval: Option<std::time::Duration>,
        token: &CapabilityToken,
    ) -> FcpResult<()>;

    /// Stop polling a target.
    async fn stop_polling(&self, target: &str, token: &CapabilityToken) -> FcpResult<()>;

    /// Trigger immediate poll.
    async fn poll_now(&self, target: &str, token: &CapabilityToken) -> FcpResult<usize>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

/// Webhook archetype (e.g., GitHub, Stripe).
#[async_trait]
pub trait Webhook: FcpConnector {
    /// Register a webhook handler.
    async fn register_handler(&self, source: &str, token: &CapabilityToken) -> FcpResult<()>;

    /// Get the webhook URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector cannot produce a webhook URL for `source`.
    fn webhook_url(&self, source: &str) -> FcpResult<String>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

// ─────────────────────────────────────────────────────────────────────────────
// Base Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Base connector state that can be reused by implementations.
#[derive(Debug)]
pub struct BaseConnector {
    /// Connector ID
    pub id: ConnectorId,
    /// Whether configured
    pub configured: bool,
    /// Whether handshake completed
    pub handshaken: bool,
    /// Metrics
    pub metrics: ConnectorMetrics,
}

impl BaseConnector {
    /// Create a new base connector.
    #[must_use]
    pub fn new(id: impl Into<ConnectorId>) -> Self {
        Self {
            id: id.into(),
            configured: false,
            handshaken: false,
            metrics: ConnectorMetrics::default(),
        }
    }

    /// Check if the connector is ready.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `FcpError::NotConfigured` if `configure` has not completed.
    /// - `FcpError::NotHandshaken` if `handshake` has not completed.
    pub const fn check_ready(&self) -> FcpResult<()> {
        if !self.configured {
            return Err(crate::FcpError::NotConfigured);
        }
        if !self.handshaken {
            return Err(crate::FcpError::NotHandshaken);
        }
        Ok(())
    }

    /// Increment request count.
    pub const fn record_request(&mut self, success: bool) {
        self.metrics.requests_total += 1;
        if success {
            self.metrics.requests_success += 1;
        } else {
            self.metrics.requests_error += 1;
        }
    }

    /// Increment event count.
    pub const fn record_event(&mut self) {
        self.metrics.events_emitted += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // ConnectorMetrics tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_default() {
        let metrics = ConnectorMetrics::default();

        assert_eq!(metrics.requests_total, 0);
        assert_eq!(metrics.requests_success, 0);
        assert_eq!(metrics.requests_error, 0);
        assert_eq!(metrics.connections_active, 0);
        assert_eq!(metrics.events_emitted, 0);
        assert_eq!(metrics.latency_p50_ms, 0);
        assert_eq!(metrics.latency_p99_ms, 0);
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
    }

    #[test]
    fn connector_metrics_clone() {
        let metrics = ConnectorMetrics {
            requests_total: 100,
            requests_success: 95,
            ..Default::default()
        };

        // Clone and verify both copies have correct values
        let cloned = metrics.clone();
        assert_eq!(metrics.requests_total, 100);
        assert_eq!(cloned.requests_total, 100);
        assert_eq!(cloned.requests_success, 95);
    }

    #[test]
    fn connector_metrics_debug() {
        let metrics = ConnectorMetrics::default();
        let debug = format!("{metrics:?}");

        assert!(debug.contains("ConnectorMetrics"));
        assert!(debug.contains("requests_total"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // BaseConnector tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_new() {
        let id = ConnectorId::from_static("my:connector:v1");
        let base = BaseConnector::new(id);

        assert_eq!(base.id.as_str(), "my:connector:v1");
        assert!(!base.configured);
        assert!(!base.handshaken);
        assert_eq!(base.metrics.requests_total, 0);
    }

    #[test]
    fn base_connector_new_with_connector_id() {
        let id = ConnectorId::new("test", "streaming", "v1").unwrap();
        let base = BaseConnector::new(id);

        assert_eq!(base.id.as_str(), "test:streaming:v1");
    }

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("test:base:v1")
    }

    #[test]
    fn base_connector_check_ready_not_configured() {
        let base = BaseConnector::new(test_connector_id());

        let result = base.check_ready();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::FcpError::NotConfigured
        ));
    }

    #[test]
    fn base_connector_check_ready_not_handshaken() {
        let mut base = BaseConnector::new(test_connector_id());
        base.configured = true;

        let result = base.check_ready();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::FcpError::NotHandshaken
        ));
    }

    #[test]
    fn base_connector_check_ready_success() {
        let mut base = BaseConnector::new(test_connector_id());
        base.configured = true;
        base.handshaken = true;

        let result = base.check_ready();

        assert!(result.is_ok());
    }

    #[test]
    fn base_connector_record_request_success() {
        let mut base = BaseConnector::new(test_connector_id());

        base.record_request(true);

        assert_eq!(base.metrics.requests_total, 1);
        assert_eq!(base.metrics.requests_success, 1);
        assert_eq!(base.metrics.requests_error, 0);
    }

    #[test]
    fn base_connector_record_request_failure() {
        let mut base = BaseConnector::new(test_connector_id());

        base.record_request(false);

        assert_eq!(base.metrics.requests_total, 1);
        assert_eq!(base.metrics.requests_success, 0);
        assert_eq!(base.metrics.requests_error, 1);
    }

    #[test]
    fn base_connector_record_request_multiple() {
        let mut base = BaseConnector::new(test_connector_id());

        base.record_request(true);
        base.record_request(true);
        base.record_request(false);
        base.record_request(true);
        base.record_request(false);

        assert_eq!(base.metrics.requests_total, 5);
        assert_eq!(base.metrics.requests_success, 3);
        assert_eq!(base.metrics.requests_error, 2);
    }

    #[test]
    fn base_connector_record_event() {
        let mut base = BaseConnector::new(test_connector_id());

        base.record_event();
        base.record_event();
        base.record_event();

        assert_eq!(base.metrics.events_emitted, 3);
    }

    #[test]
    fn base_connector_debug() {
        let base = BaseConnector::new(ConnectorId::from_static("debug:test:v1"));
        let debug = format!("{base:?}");

        assert!(debug.contains("BaseConnector"));
        assert!(debug.contains("debug:test:v1"));
        assert!(debug.contains("configured"));
        assert!(debug.contains("handshaken"));
    }

    #[test]
    fn base_connector_lifecycle() {
        // Test typical connector lifecycle
        let mut base = BaseConnector::new(ConnectorId::from_static("lifecycle:connector:v1"));

        // Initially not ready
        assert!(base.check_ready().is_err());

        // After configuration
        base.configured = true;
        assert!(base.check_ready().is_err());

        // After handshake
        base.handshaken = true;
        assert!(base.check_ready().is_ok());

        // Record some activity
        base.record_request(true);
        base.record_request(true);
        base.record_request(false);
        base.record_event();
        base.record_event();

        assert_eq!(base.metrics.requests_total, 3);
        assert_eq!(base.metrics.requests_success, 2);
        assert_eq!(base.metrics.requests_error, 1);
        assert_eq!(base.metrics.events_emitted, 2);
    }
}

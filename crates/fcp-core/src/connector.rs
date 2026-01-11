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
    pub fn check_ready(&self) -> FcpResult<()> {
        if !self.configured {
            return Err(crate::FcpError::NotConfigured);
        }
        if !self.handshaken {
            return Err(crate::FcpError::NotHandshaken);
        }
        Ok(())
    }

    /// Increment request count.
    pub fn record_request(&mut self, success: bool) {
        self.metrics.requests_total += 1;
        if success {
            self.metrics.requests_success += 1;
        } else {
            self.metrics.requests_error += 1;
        }
    }

    /// Increment event count.
    pub fn record_event(&mut self) {
        self.metrics.events_emitted += 1;
    }
}

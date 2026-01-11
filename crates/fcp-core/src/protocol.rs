//! Protocol types for FCP - wire format messages.
//!
//! Based on FCP Specification Section 9 (Wire Protocol).

use serde::{Deserialize, Serialize};

use crate::{
    CapabilityGrant, CapabilityId, CapabilityToken, CorrelationId, IdempotencyClass,
    InstanceId, OperationId, Provenance, SafetyTier, SessionId, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Handshake Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Handshake request from hub to connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Protocol version
    pub version: String,

    /// Zone the connector will run in
    pub zone: ZoneId,

    /// Host's Ed25519 public key for signing capability tokens
    pub host_public_key: [u8; 32],

    /// Nonce for replay protection
    pub nonce: [u8; 16],

    /// Capabilities the hub is requesting
    #[serde(default)]
    pub capabilities_requested: Vec<CapabilityGrant>,

    /// Requested instance ID (hub may assign)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_instance_id: Option<InstanceId>,
}

/// Handshake response from connector to hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Status: "accepted" or error
    pub status: String,

    /// Capabilities actually granted
    pub capabilities_granted: Vec<CapabilityGrant>,

    /// Session ID for this connection
    pub session_id: SessionId,

    /// Hash of the connector's manifest
    pub manifest_hash: String,

    /// Echo back the nonce
    pub nonce: [u8; 16],

    /// Event capabilities (streaming, replay, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_caps: Option<EventCaps>,

    /// Auth capabilities (OAuth, API key, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_caps: Option<AuthCaps>,

    /// Hash of the operation catalog for caching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_catalog_hash: Option<String>,
}

/// Event capabilities advertised by a connector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventCaps {
    /// Whether streaming is supported
    #[serde(default)]
    pub streaming: bool,

    /// Whether event replay is supported
    #[serde(default)]
    pub replay: bool,

    /// Minimum events to buffer
    #[serde(default)]
    pub min_buffer_events: u32,

    /// Whether events require acknowledgment
    #[serde(default)]
    pub requires_ack: bool,
}

/// Authentication capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCaps {
    /// Supported auth methods
    pub methods: Vec<String>,

    /// OAuth configuration if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
}

/// OAuth configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub authorize_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Invoke Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Request to invoke an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeRequest {
    /// Message type ("request")
    pub r#type: String,

    /// Unique request ID
    pub id: uuid::Uuid,

    /// Operation to invoke
    pub operation: OperationId,

    /// Input parameters
    pub input: serde_json::Value,

    /// Capability token authorizing this request
    pub capability_token: CapabilityToken,

    /// Correlation ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,

    /// Provenance for taint tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,

    /// Idempotency key for retries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Response from an operation invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResponse {
    /// Message type ("response")
    pub r#type: String,

    /// Request ID this is responding to
    pub id: uuid::Uuid,

    /// Result data
    pub result: serde_json::Value,

    /// Resource URIs created/modified
    #[serde(default)]
    pub resource_uris: Vec<String>,

    /// Cursor for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscribe Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Request to subscribe to event topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// Topics to subscribe to
    pub topics: Vec<String>,

    /// Optional capability token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,

    /// Resume from cursor (for replay)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Response to subscription request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResponse {
    /// Topics confirmed
    pub confirmed_topics: Vec<String>,

    /// Current cursors for each topic
    #[serde(default)]
    pub cursors: std::collections::HashMap<String, String>,

    /// Whether replay is available
    pub replay_supported: bool,

    /// Buffer size info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<BufferInfo>,
}

/// Buffer information for streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferInfo {
    pub size: u32,
    pub max_size: u32,
}

/// Request to unsubscribe from topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// Topics to unsubscribe from
    pub topics: Vec<String>,

    /// Optional capability token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Shutdown Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Request to shutdown the connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownRequest {
    /// Reason for shutdown
    pub reason: String,

    /// Grace period in milliseconds
    #[serde(default = "default_grace_period")]
    pub grace_period_ms: u64,
}

fn default_grace_period() -> u64 {
    5000
}

// ─────────────────────────────────────────────────────────────────────────────
// Introspection
// ─────────────────────────────────────────────────────────────────────────────

/// Introspection data describing connector capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Introspection {
    /// Available operations
    pub operations: Vec<OperationInfo>,

    /// Available event topics
    #[serde(default)]
    pub events: Vec<EventInfo>,

    /// Resource types this connector manages
    #[serde(default)]
    pub resource_types: Vec<ResourceTypeInfo>,

    /// Auth capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_caps: Option<AuthCaps>,

    /// Event capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_caps: Option<EventCaps>,
}

/// Information about an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationInfo {
    /// Operation ID
    pub id: OperationId,

    /// Human-readable summary
    pub summary: String,

    /// JSON Schema for input
    pub input_schema: serde_json::Value,

    /// JSON Schema for output
    pub output_schema: serde_json::Value,

    /// Required capability
    pub capability: CapabilityId,

    /// Risk level description
    pub risk_level: String,

    /// Safety tier
    pub safety_tier: SafetyTier,

    /// Idempotency class
    pub idempotency: IdempotencyClass,

    /// AI agent hints
    pub ai_hints: AgentHint,
}

/// Hints for AI agents on how to use an operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentHint {
    /// When to use this operation
    pub when_to_use: String,

    /// Common mistakes to avoid
    #[serde(default)]
    pub common_mistakes: Vec<String>,

    /// Example invocations
    #[serde(default)]
    pub examples: Vec<String>,

    /// Related operations
    #[serde(default)]
    pub related: Vec<CapabilityId>,
}

/// Information about an event topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    /// Topic name
    pub topic: String,

    /// JSON Schema for event data
    pub schema: serde_json::Value,

    /// Whether acknowledgment is required
    pub requires_ack: bool,
}

/// Information about a resource type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTypeInfo {
    /// Resource type name
    pub name: String,

    /// URI pattern
    pub uri_pattern: String,

    /// JSON Schema for resource
    pub schema: serde_json::Value,
}

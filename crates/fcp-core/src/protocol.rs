//! Protocol types for FCP - wire format messages.
//!
//! Based on FCP Specification Section 9 (Wire Protocol).
//!
//! This module implements the canonical wire format as defined in the
//! FCP Specification V1. All types are designed to be serializable to
//! both JSON (for debugging) and CBOR (for production).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    CapabilityGrant, CapabilityId, CapabilityToken, CorrelationId, IdempotencyClass,
    InstanceId, OperationId, Provenance, RiskLevel, SafetyTier, SessionId, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Request ID (Wire Format)
// ─────────────────────────────────────────────────────────────────────────────

/// Request identifier for correlation.
///
/// On the wire, this is a string like "req_123" or a UUID string.
/// The format is not prescribed; the Hub and connector just need to echo it back.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub String);

impl RequestId {
    /// Create a new request ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a new random request ID using UUID.
    #[must_use]
    pub fn random() -> Self {
        Self(format!("req_{}", uuid::Uuid::new_v4()))
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<S: Into<String>> From<S> for RequestId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handshake Messages (Section 9.10)
// ─────────────────────────────────────────────────────────────────────────────

/// Host information sent during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// Host name (e.g., "flywheel-hub")
    pub name: String,

    /// Host version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Build identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
}

/// Transport capabilities for negotiation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportCaps {
    /// Supported compression algorithms (e.g., ["zstd", "lz4"])
    #[serde(default)]
    pub compression: Vec<String>,

    /// Maximum frame size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_frame_size: Option<u32>,
}

/// Handshake request from hub to connector.
///
/// Per FCP Specification Section 9.10:
/// - `protocol_version`: Version string for compatibility
/// - `zone`: Zone this connector instance will be bound to
/// - `zone_dir`: Filesystem path for persistent storage (required for stateful connectors)
/// - `host_public_key`: Ed25519 public key for capability token verification
/// - `nonce`: 32-byte random nonce for replay protection
/// - `capabilities_requested`: Capabilities the hub wants to grant
/// - `host`: Optional host metadata
/// - `transport_caps`: Optional transport negotiation
/// - `requested_instance_id`: Optional preferred instance ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Protocol version (e.g., "1.0.0")
    pub protocol_version: String,

    /// Zone the connector will run in
    pub zone: ZoneId,

    /// Filesystem path for zone-scoped persistent storage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_dir: Option<String>,

    /// Host's Ed25519 public key for signing capability tokens
    pub host_public_key: [u8; 32],

    /// Nonce for replay protection (32 bytes per spec)
    pub nonce: [u8; 32],

    /// Capabilities the hub is requesting to grant
    #[serde(default)]
    pub capabilities_requested: Vec<CapabilityId>,

    /// Host metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,

    /// Transport capabilities for negotiation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_caps: Option<TransportCaps>,

    /// Requested instance ID (hub may assign)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_instance_id: Option<InstanceId>,
}

/// Handshake response from connector to hub.
///
/// Per FCP Specification Section 9.10:
/// - `status`: "accepted" or error string
/// - `capabilities_granted`: Actual capabilities the connector will honor
/// - `session_id`: Unique session identifier for this connection
/// - `manifest_hash`: SHA256 hash of the connector manifest for integrity
/// - `nonce`: Echo back the 32-byte nonce to prove liveness
/// - `event_caps`: Event streaming capabilities (if supported)
/// - `auth_caps`: Authentication methods (if applicable)
/// - `op_catalog_hash`: Hash of operations list for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Status: "accepted" or error
    pub status: String,

    /// Capabilities actually granted
    pub capabilities_granted: Vec<CapabilityGrant>,

    /// Session ID for this connection
    pub session_id: SessionId,

    /// Hash of the connector's manifest (e.g., "sha256:abc123...")
    pub manifest_hash: String,

    /// Echo back the nonce (32 bytes per spec)
    pub nonce: [u8; 32],

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

/// Invoke context for locale and pagination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvokeContext {
    /// Locale for internationalization (e.g., "en-US")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Pagination parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<serde_json::Value>,
}

/// Request to invoke an operation.
///
/// Per FCP Specification Section 9.7:
/// - `type`: Always "invoke"
/// - `id`: Unique request ID for correlation
/// - `operation`: Operation to invoke (e.g., "gmail.search")
/// - `input`: JSON input parameters
/// - `capability_token`: FCT authorizing this request
/// - `context`: Optional locale and pagination
/// - `idempotency_key`: Optional key for retry deduplication
/// - `deadline_ms`: Optional timeout deadline
/// - `correlation_id`: Optional tracing correlation
/// - `provenance`: Optional provenance for taint tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeRequest {
    /// Message type (always "invoke")
    pub r#type: String,

    /// Unique request ID for correlation
    pub id: RequestId,

    /// Operation to invoke
    pub operation: OperationId,

    /// Input parameters
    pub input: serde_json::Value,

    /// Capability token authorizing this request
    pub capability_token: CapabilityToken,

    /// Request context (locale, pagination)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<InvokeContext>,

    /// Idempotency key for retries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,

    /// Deadline in milliseconds from now
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,

    /// Correlation ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,

    /// Provenance for taint tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

/// Response from an operation invocation.
///
/// Per FCP Specification Section 9.7:
/// - `type`: Always "response"
/// - `id`: Request ID this is responding to
/// - `result`: JSON result data
/// - `resource_uris`: Canonical URIs for resources created/modified
/// - `next_cursor`: Pagination cursor for next page
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResponse {
    /// Message type (always "response")
    pub r#type: String,

    /// Request ID this is responding to
    pub id: RequestId,

    /// Result data
    pub result: serde_json::Value,

    /// Resource URIs created/modified (e.g., "fcp://fcp.gmail/message/17c9a...")
    #[serde(default)]
    pub resource_uris: Vec<String>,

    /// Cursor for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscribe Messages (Section 9.9)
// ─────────────────────────────────────────────────────────────────────────────

/// Request to subscribe to event topics.
///
/// Per FCP Specification Section 9.9:
/// - `type`: Always "subscribe"
/// - `id`: Unique request ID
/// - `topics`: List of topic patterns to subscribe to
/// - `since`: Cursor position for replay (if supported)
/// - `max_events_per_sec`: Backpressure limit
/// - `batch_ms`: Batching window in milliseconds
/// - `window_size`: Flow control window size
/// - `capability_token`: Optional auth token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// Message type (always "subscribe")
    pub r#type: String,

    /// Unique request ID
    pub id: RequestId,

    /// Topics to subscribe to
    pub topics: Vec<String>,

    /// Resume from cursor (for replay)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Maximum events per second (backpressure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_events_per_sec: Option<u32>,

    /// Batching window in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_ms: Option<u32>,

    /// Flow control window size
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_size: Option<u32>,

    /// Optional capability token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
}

/// Replay buffer information.
///
/// Per FCP Specification Section 9.9.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBufferInfo {
    /// Minimum events retained in buffer
    pub min_events: u32,

    /// Overflow policy (e.g., "stream.reset")
    pub overflow: String,
}

/// Response to subscription request.
///
/// Per FCP Specification Section 9.9.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResponse {
    /// Message type (always "response")
    pub r#type: String,

    /// Request ID this is responding to
    pub id: RequestId,

    /// Result containing subscription details
    pub result: SubscribeResult,
}

/// Subscription result details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResult {
    /// Topics confirmed
    pub confirmed_topics: Vec<String>,

    /// Current cursors for each topic
    #[serde(default)]
    pub cursors: HashMap<String, String>,

    /// Whether replay is available
    pub replay_supported: bool,

    /// Buffer info (min_events, overflow policy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<ReplayBufferInfo>,
}

/// Request to unsubscribe from topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// Message type (always "unsubscribe")
    pub r#type: String,

    /// Unique request ID
    pub id: RequestId,

    /// Topics to unsubscribe from
    pub topics: Vec<String>,

    /// Optional capability token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Shutdown Messages (Section 9.12)
// ─────────────────────────────────────────────────────────────────────────────

/// Request to shutdown the connector.
///
/// Per FCP Specification Section 9.12:
/// - `deadline_ms`: Maximum time to complete shutdown
/// - `drain`: Whether to flush pending events before terminating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownRequest {
    /// Message type (always "shutdown")
    pub r#type: String,

    /// Maximum time to complete shutdown in milliseconds
    #[serde(default = "default_deadline")]
    pub deadline_ms: u64,

    /// Whether to flush pending events before terminating
    #[serde(default)]
    pub drain: bool,

    /// Optional reason for shutdown (for logging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn default_deadline() -> u64 {
    10000 // 10 seconds default
}

/// Shutdown acknowledgment from connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownAck {
    /// Message type (always "shutdown_ack")
    pub r#type: String,

    /// Status of shutdown
    pub status: String,

    /// Number of events flushed (if drain was true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_flushed: Option<u64>,

    /// Number of in-flight requests completed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests_completed: Option<u64>,
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
///
/// Per FCP Specification Section 8.2 and 9.6:
/// - Operations MUST declare capability, risk_level, safety_tier, and idempotency
/// - `risk_level` is for UX/prioritization; `safety_tier` is normative enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationInfo {
    /// Operation ID (e.g., "gmail.search")
    pub id: OperationId,

    /// Human-readable summary
    pub summary: String,

    /// Detailed description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema for input
    pub input_schema: serde_json::Value,

    /// JSON Schema for output
    pub output_schema: serde_json::Value,

    /// Required capability
    pub capability: CapabilityId,

    /// Risk level (for UX/prioritization)
    pub risk_level: RiskLevel,

    /// Safety tier (normative enforcement)
    pub safety_tier: SafetyTier,

    /// Idempotency class
    pub idempotency: IdempotencyClass,

    /// AI agent hints
    pub ai_hints: AgentHint,

    /// Rate limit configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<crate::RateLimit>,

    /// Approval mode required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<ApprovalMode>,
}

/// Approval mode for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// No approval needed
    None,
    /// Policy-based approval
    Policy,
    /// Interactive human approval
    Interactive,
    /// Elevation token required
    ElevationToken,
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

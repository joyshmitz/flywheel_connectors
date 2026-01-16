//! Protocol types for FCP - wire format messages.
//!
//! Based on FCP Specification Section 9 (Wire Protocol).
//!
//! This module implements the canonical wire format as defined in the
//! FCP Specification V2. All types are designed to be serializable to
//! both JSON (for debugging) and CBOR (for production).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    ApprovalToken, CapabilityGrant, CapabilityId, CapabilityToken, CorrelationId, IdempotencyClass,
    InstanceId, OperationId, Provenance, RiskLevel, SafetyTier, SessionId, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Request ID (Wire Format)
// ─────────────────────────────────────────────────────────────────────────────

/// Request identifier for correlation.
///
/// On the wire, this is a string like "`req_123`" or a UUID string.
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
    /// Supported compression algorithms (e.g., `zstd`, `lz4`)
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
/// - `approval_tokens`: Approval tokens for elevation/declassification/execution
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

    /// Approval tokens authorizing this request.
    ///
    /// These tokens can authorize:
    /// - Elevation: Allow integrity to flow upward
    /// - Declassification: Allow confidentiality to flow downward
    /// - Execution: Scope-limited approval for specific operations
    ///
    /// Per FCP Specification Section 7.4, approval tokens are first-class
    /// mesh objects that must be validated against the request context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_tokens: Vec<ApprovalToken>,
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

    /// Resource URIs created/modified (e.g., `<fcp://fcp.gmail/message/17c9a...>`)
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

    /// Buffer info (`min_events`, overflow policy)
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

const fn default_deadline() -> u64 {
    10000 // 10 seconds default
}

/// Shutdown acknowledgment from connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownAck {
    /// Message type (always "`shutdown_ack`")
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
/// - Operations MUST declare capability, `risk_level`, `safety_tier`, and `idempotency`
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityToken;

    // ─────────────────────────────────────────────────────────────────────────
    // RequestId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn request_id_new() {
        let id = RequestId::new("req_123");
        assert_eq!(id.to_string(), "req_123");
    }

    #[test]
    fn request_id_random() {
        let id = RequestId::random();
        assert!(id.to_string().starts_with("req_"));
    }

    #[test]
    fn request_id_from_string() {
        let id: RequestId = "my-request".into();
        assert_eq!(id.0, "my-request");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handshake Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn handshake_request_serialization_roundtrip() {
        let req = HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: Some("/var/fcp/zones/work".into()),
            host_public_key: [0x42_u8; 32],
            nonce: [0xaa_u8; 32],
            capabilities_requested: vec!["cap.read".parse().unwrap()],
            host: Some(HostInfo {
                name: "flywheel-hub".into(),
                version: Some("2.0.0".into()),
                build: Some("abc123".into()),
            }),
            transport_caps: Some(TransportCaps {
                compression: vec!["zstd".into()],
                max_frame_size: Some(65536),
            }),
            requested_instance_id: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: HandshakeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.protocol_version, "1.0.0");
        assert_eq!(deserialized.zone.as_str(), "z:work");
        assert_eq!(deserialized.host_public_key, [0x42_u8; 32]);
        assert_eq!(deserialized.nonce, [0xaa_u8; 32]);
        assert_eq!(deserialized.capabilities_requested.len(), 1);
        assert!(deserialized.host.is_some());
        assert!(deserialized.transport_caps.is_some());
    }

    #[test]
    fn handshake_request_minimal() {
        let req = HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::public(),
            zone_dir: None,
            host_public_key: [0_u8; 32],
            nonce: [0_u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("zone_dir"));
        // Note: check for exact field name with colon to avoid matching host_public_key
        assert!(!json.contains("\"host\":"));
        assert!(!json.contains("transport_caps"));
    }

    #[test]
    fn handshake_response_serialization_roundtrip() {
        let resp = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: vec![crate::CapabilityGrant {
                capability: "cap.read".parse().unwrap(),
                operation: None,
            }],
            session_id: SessionId::new(),
            manifest_hash: "sha256:abc123".into(),
            nonce: [0xbb_u8; 32],
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 1000,
                requires_ack: true,
            }),
            auth_caps: Some(AuthCaps {
                methods: vec!["oauth2".into()],
                oauth: Some(OAuthConfig {
                    authorize_url: "https://example.com/auth".into(),
                    token_url: "https://example.com/token".into(),
                    scopes: vec!["read".into(), "write".into()],
                }),
            }),
            op_catalog_hash: Some("sha256:def456".into()),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: HandshakeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, "accepted");
        assert_eq!(deserialized.capabilities_granted.len(), 1);
        assert!(deserialized.event_caps.is_some());
        assert!(deserialized.auth_caps.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Invoke Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invoke_request_serialization_roundtrip() {
        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_001"),
            operation: "gmail.search".parse().unwrap(),
            input: serde_json::json!({"query": "from:alice"}),
            capability_token: CapabilityToken::test_token(),
            context: Some(InvokeContext {
                locale: Some("en-US".into()),
                pagination: Some(serde_json::json!({"page": 1, "size": 10})),
            }),
            idempotency_key: Some("idem_123".into()),
            deadline_ms: Some(30000),
            correlation_id: Some(CorrelationId::new()),
            provenance: Some(crate::Provenance::new(ZoneId::work())),
            approval_tokens: Vec::new(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: InvokeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "invoke");
        assert_eq!(deserialized.id.0, "req_001");
        assert_eq!(deserialized.operation.as_str(), "gmail.search");
        assert!(deserialized.context.is_some());
        assert_eq!(deserialized.idempotency_key, Some("idem_123".into()));
        assert_eq!(deserialized.deadline_ms, Some(30000));
    }

    #[test]
    fn invoke_response_serialization_roundtrip() {
        let resp = InvokeResponse {
            r#type: "response".into(),
            id: RequestId::new("req_001"),
            result: serde_json::json!({"messages": []}),
            resource_uris: vec!["fcp://fcp.gmail/message/123".into()],
            next_cursor: Some("cursor_abc".into()),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: InvokeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "response");
        assert_eq!(deserialized.id.0, "req_001");
        assert_eq!(deserialized.resource_uris.len(), 1);
        assert_eq!(deserialized.next_cursor, Some("cursor_abc".into()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Subscribe Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn subscribe_request_serialization_roundtrip() {
        let req = SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("sub_001"),
            topics: vec!["messages.*".into(), "events.new".into()],
            since: Some("cursor_start".into()),
            max_events_per_sec: Some(100),
            batch_ms: Some(500),
            window_size: Some(10),
            capability_token: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: SubscribeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "subscribe");
        assert_eq!(deserialized.topics.len(), 2);
        assert_eq!(deserialized.since, Some("cursor_start".into()));
        assert_eq!(deserialized.max_events_per_sec, Some(100));
    }

    #[test]
    fn subscribe_response_serialization_roundtrip() {
        let resp = SubscribeResponse {
            r#type: "response".into(),
            id: RequestId::new("sub_001"),
            result: SubscribeResult {
                confirmed_topics: vec!["messages.*".into()],
                cursors: std::iter::once(("messages.*".into(), "cursor_123".into())).collect(),
                replay_supported: true,
                buffer: Some(ReplayBufferInfo {
                    min_events: 1000,
                    overflow: "stream.reset".into(),
                }),
            },
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: SubscribeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.result.confirmed_topics.len(), 1);
        assert!(deserialized.result.replay_supported);
        assert!(deserialized.result.buffer.is_some());
    }

    #[test]
    fn unsubscribe_request_serialization() {
        let req = UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("unsub_001"),
            topics: vec!["messages.*".into()],
            capability_token: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: UnsubscribeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "unsubscribe");
        assert_eq!(deserialized.topics.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Shutdown Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn shutdown_request_defaults() {
        let json = r#"{"type":"shutdown"}"#;
        let req: ShutdownRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.r#type, "shutdown");
        assert_eq!(req.deadline_ms, 10000); // Default
        assert!(!req.drain);
    }

    #[test]
    fn shutdown_request_with_values() {
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 30000,
            drain: true,
            reason: Some("Maintenance".into()),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ShutdownRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.deadline_ms, 30000);
        assert!(deserialized.drain);
        assert_eq!(deserialized.reason, Some("Maintenance".into()));
    }

    #[test]
    fn shutdown_ack_serialization() {
        let ack = ShutdownAck {
            r#type: "shutdown_ack".into(),
            status: "completed".into(),
            events_flushed: Some(100),
            requests_completed: Some(5),
        };

        let json = serde_json::to_string(&ack).unwrap();
        let deserialized: ShutdownAck = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, "completed");
        assert_eq!(deserialized.events_flushed, Some(100));
        assert_eq!(deserialized.requests_completed, Some(5));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Introspection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_info_serialization_roundtrip() {
        let op = OperationInfo {
            id: "gmail.search".parse().unwrap(),
            summary: "Search emails".into(),
            description: Some("Searches Gmail using query syntax".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "array"}),
            capability: "cap.gmail.read".parse().unwrap(),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When user wants to find emails".into(),
                common_mistakes: vec!["Forgetting date range".into()],
                examples: vec!["gmail.search({query: 'from:alice'})".into()],
                related: vec!["cap.gmail.write".parse().unwrap()],
            },
            rate_limit: Some(crate::RateLimit {
                max: 100,
                per_ms: 60000,
                burst: Some(10),
                scope: Some("per_zone".into()),
            }),
            requires_approval: Some(ApprovalMode::Policy),
        };

        let json = serde_json::to_string(&op).unwrap();
        let deserialized: OperationInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id.as_str(), "gmail.search");
        assert_eq!(deserialized.summary, "Search emails");
        assert!(matches!(deserialized.risk_level, RiskLevel::Low));
        assert!(matches!(deserialized.safety_tier, SafetyTier::Safe));
        assert!(matches!(deserialized.idempotency, IdempotencyClass::Strict));
    }

    #[test]
    fn risk_level_serialization() {
        let levels = [
            (RiskLevel::Low, "low"),
            (RiskLevel::Medium, "medium"),
            (RiskLevel::High, "high"),
            (RiskLevel::Critical, "critical"),
        ];

        for (level, expected) in levels {
            let json = serde_json::to_string(&level).unwrap();
            assert!(json.contains(expected));
            let deserialized: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, level);
        }
    }

    #[test]
    fn safety_tier_serialization() {
        let tiers = [
            (SafetyTier::Safe, "safe"),
            (SafetyTier::Risky, "risky"),
            (SafetyTier::Dangerous, "dangerous"),
            (SafetyTier::Forbidden, "forbidden"),
        ];

        for (tier, expected) in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            assert!(json.contains(expected));
            let deserialized: SafetyTier = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, tier);
        }
    }

    #[test]
    fn idempotency_class_serialization() {
        let classes = [
            (IdempotencyClass::None, "none"),
            (IdempotencyClass::BestEffort, "best_effort"),
            (IdempotencyClass::Strict, "strict"),
        ];

        for (class, expected) in classes {
            let json = serde_json::to_string(&class).unwrap();
            assert!(json.contains(expected));
            let deserialized: IdempotencyClass = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, class);
        }
    }

    #[test]
    fn approval_mode_serialization() {
        let modes = [
            (ApprovalMode::None, "none"),
            (ApprovalMode::Policy, "policy"),
            (ApprovalMode::Interactive, "interactive"),
            (ApprovalMode::ElevationToken, "elevation_token"),
        ];

        for (mode, expected) in modes {
            let json = serde_json::to_string(&mode).unwrap();
            assert!(json.contains(expected));
            let deserialized: ApprovalMode = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, mode);
        }
    }

    #[test]
    fn introspection_serialization() {
        let intro = Introspection {
            operations: vec![],
            events: vec![EventInfo {
                topic: "messages.new".into(),
                schema: serde_json::json!({"type": "object"}),
                requires_ack: true,
            }],
            resource_types: vec![ResourceTypeInfo {
                name: "Message".into(),
                uri_pattern: "fcp://fcp.gmail/message/{id}".into(),
                schema: serde_json::json!({"type": "object"}),
            }],
            auth_caps: None,
            event_caps: Some(EventCaps::default()),
        };

        let json = serde_json::to_string(&intro).unwrap();
        let deserialized: Introspection = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.events.len(), 1);
        assert_eq!(deserialized.resource_types.len(), 1);
        assert!(deserialized.event_caps.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Transport / Host Info Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_info_serialization() {
        let info = HostInfo {
            name: "test-hub".into(),
            version: Some("1.0.0".into()),
            build: Some("git-abc123".into()),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: HostInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "test-hub");
        assert_eq!(deserialized.version, Some("1.0.0".into()));
        assert_eq!(deserialized.build, Some("git-abc123".into()));
    }

    #[test]
    fn transport_caps_default() {
        let caps = TransportCaps::default();
        assert!(caps.compression.is_empty());
        assert!(caps.max_frame_size.is_none());
    }

    #[test]
    fn event_caps_default() {
        let caps = EventCaps::default();
        assert!(!caps.streaming);
        assert!(!caps.replay);
        assert_eq!(caps.min_buffer_events, 0);
        assert!(!caps.requires_ack);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SessionId and CorrelationId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn session_id_unique() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn session_id_display() {
        let id = SessionId::new();
        let display = id.to_string();
        assert!(!display.is_empty());
    }

    #[test]
    fn correlation_id_unique() {
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::new();
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn correlation_id_display() {
        let id = CorrelationId::new();
        let display = id.to_string();
        assert!(!display.is_empty());
    }
}

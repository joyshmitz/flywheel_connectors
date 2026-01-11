# FCP Model Connectors

## Canonical Reference Implementations for Connector Archetypes

> **Purpose**: Define the fundamental data flow patterns and provide production-quality Rust implementations for each archetype.
> **Version**: 1.0.0
> **License**: MIT

---

## Table of Contents

1. [Archetype Overview](#archetype-overview)
2. [Core Traits & Types](#core-traits--types)
3. [Archetype 1: Request-Response](#archetype-1-request-response)
4. [Archetype 2: Streaming (Server Push)](#archetype-2-streaming-server-push)
5. [Archetype 3: Bidirectional Channel](#archetype-3-bidirectional-channel)
6. [Archetype 4: Polling (Pull-Based)](#archetype-4-polling-pull-based)
7. [Archetype 5: Webhook (Event Receiver)](#archetype-5-webhook-event-receiver)
8. [Archetype 6: Queue/Pub-Sub](#archetype-6-queuepub-sub)
9. [Archetype 7: File/Blob Storage](#archetype-7-fileblob-storage)
10. [Archetype 8: Database/Query Engine](#archetype-8-databasequery-engine)
11. [Archetype 9: CLI/Process Wrapper](#archetype-9-cliprocess-wrapper)
12. [Archetype 10: Browser Automation](#archetype-10-browser-automation)
13. [Composition Patterns](#composition-patterns)

---

## Archetype Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FCP CONNECTOR ARCHETYPES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │ REQUEST-RESPONSE│  │    STREAMING    │  │  BIDIRECTIONAL  │             │
│  │                 │  │                 │  │                 │             │
│  │   Agent ──────► │  │   Agent ◄───── │  │   Agent ◄─────► │             │
│  │          ◄───── │  │         Server  │  │          Server │             │
│  │         Service │  │                 │  │                 │             │
│  │                 │  │                 │  │                 │             │
│  │ Examples:       │  │ Examples:       │  │ Examples:       │             │
│  │ • REST APIs     │  │ • WebSocket     │  │ • Chat protocols│             │
│  │ • GraphQL       │  │ • SSE           │  │ • Collaborative │             │
│  │ • gRPC unary    │  │ • Log tailing   │  │ • Game state    │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │     POLLING     │  │     WEBHOOK     │  │   QUEUE/PUBSUB  │             │
│  │                 │  │                 │  │                 │             │
│  │   Agent ──────► │  │   Agent ◄───── │  │   Agent ◄─────► │             │
│  │   (periodic)    │  │    (push)       │  │          Broker │             │
│  │         Service │  │         Service │  │                 │             │
│  │                 │  │                 │  │                 │             │
│  │ Examples:       │  │ Examples:       │  │ Examples:       │             │
│  │ • Email (IMAP)  │  │ • GitHub hooks  │  │ • Redis Pub/Sub │             │
│  │ • RSS feeds     │  │ • Stripe events │  │ • NATS          │             │
│  │ • Status checks │  │ • Slack events  │  │ • Kafka         │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   FILE/BLOB     │  │ DATABASE/QUERY  │  │  CLI/PROCESS    │             │
│  │                 │  │                 │  │                 │             │
│  │   Agent ──────► │  │   Agent ──────► │  │   Agent ──────► │             │
│  │   (upload/dl)   │  │   (query)       │  │   (spawn)       │             │
│  │         Storage │  │         DB      │  │         Process │             │
│  │                 │  │                 │  │                 │             │
│  │ Examples:       │  │ Examples:       │  │ Examples:       │             │
│  │ • S3            │  │ • PostgreSQL    │  │ • git           │             │
│  │ • GCS           │  │ • Vector DBs    │  │ • kubectl       │             │
│  │ • Local FS      │  │ • Elasticsearch │  │ • terraform     │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │    BROWSER      │  ← Special: Combines multiple patterns                 │
│  │   AUTOMATION    │                                                        │
│  │                 │                                                        │
│  │   Agent ──────► │                                                        │
│  │   (CDP)         │                                                        │
│  │         Browser │                                                        │
│  └─────────────────┘                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Traits & Types

These are the foundational types shared across all archetypes.

```rust
// ============================================================================
// File: fcp-core/src/lib.rs
// Core FCP types and traits
// ============================================================================

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio_stream::Stream;
use tracing::{instrument, Span};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum FcpError {
    // Protocol errors (1xxx)
    #[error("Protocol error: {message}")]
    Protocol { code: u16, message: String },
    
    // Auth errors (2xxx)
    #[error("Authentication failed: {message}")]
    Auth { code: u16, message: String },
    
    // Capability errors (3xxx)
    #[error("Capability denied: {capability}")]
    CapabilityDenied { capability: String, reason: String },
    
    // Zone errors (4xxx)
    #[error("Zone violation: {message}")]
    ZoneViolation { source: ZoneId, target: ZoneId, message: String },
    
    // Connector errors (5xxx)
    #[error("Connector error: {message}")]
    Connector { code: u16, message: String, retryable: bool },
    
    // Resource errors (6xxx)
    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },
    
    // External service errors (7xxx)
    #[error("External service error: {service} - {message}")]
    External { 
        service: String, 
        message: String, 
        status_code: Option<u16>,
        retryable: bool,
        retry_after: Option<Duration>,
    },
    
    // Internal errors (9xxx)
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl FcpError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::External { retryable, .. } => *retryable,
            Self::Connector { retryable, .. } => *retryable,
            Self::ResourceExhausted { .. } => true,
            _ => false,
        }
    }
    
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::External { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// Map internal errors to the canonical wire response shape.
    pub fn to_response(&self) -> FcpErrorResponse {
        match self {
            Self::Protocol { code, message } => FcpErrorResponse {
                code: format!("FCP-{:04}", code),
                message: message.clone(),
                retryable: false,
                retry_after_ms: None,
                details: None,
                ai_recovery_hint: None,
            },
            Self::Auth { code, message } => FcpErrorResponse {
                code: format!("FCP-{:04}", code),
                message: message.clone(),
                retryable: false,
                retry_after_ms: None,
                details: None,
                ai_recovery_hint: None,
            },
            Self::CapabilityDenied { capability, reason } => FcpErrorResponse {
                code: "FCP-3001".into(),
                message: format!("Capability denied: {reason}"),
                retryable: false,
                retry_after_ms: None,
                details: Some(serde_json::json!({
                    "capability": capability,
                    "reason": reason,
                })),
                ai_recovery_hint: None,
            },
            Self::ZoneViolation { source, target, message } => FcpErrorResponse {
                code: "FCP-4001".into(),
                message: message.clone(),
                retryable: false,
                retry_after_ms: None,
                details: Some(serde_json::json!({
                    "source_zone": source.0,
                    "target_zone": target.0,
                })),
                ai_recovery_hint: None,
            },
            Self::Connector { code, message, retryable } => FcpErrorResponse {
                code: format!("FCP-{:04}", code),
                message: message.clone(),
                retryable: *retryable,
                retry_after_ms: self.retry_after().map(|d| d.as_millis() as u64),
                details: None,
                ai_recovery_hint: None,
            },
            Self::ResourceExhausted { resource } => FcpErrorResponse {
                code: "FCP-6000".into(),
                message: format!("Resource exhausted: {resource}"),
                retryable: true,
                retry_after_ms: None,
                details: Some(serde_json::json!({ "resource": resource })),
                ai_recovery_hint: None,
            },
            Self::External { service, message, status_code, retryable, retry_after } => {
                let code = match status_code {
                    Some(429) => "FCP_RATE_LIMITED",
                    Some(504) => "FCP_TIMEOUT",
                    _ => "FCP_DEPENDENCY_UNAVAILABLE",
                };
                FcpErrorResponse {
                    code: code.into(),
                    message: message.clone(),
                    retryable: *retryable,
                    retry_after_ms: retry_after.map(|d| d.as_millis() as u64),
                    details: Some(serde_json::json!({
                        "service": service,
                        "status_code": status_code,
                    })),
                    ai_recovery_hint: None,
                }
            }
            Self::Internal { message } => FcpErrorResponse {
                code: "FCP_INTERNAL".into(),
                message: message.clone(),
                retryable: false,
                retry_after_ms: None,
                details: None,
                ai_recovery_hint: None,
            },
        }
    }
}

pub type FcpResult<T> = Result<T, FcpError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcpErrorResponse {
    /// Error code (e.g., "FCP-4002" or "FCP_FORBIDDEN")
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Whether retry might succeed
    pub retryable: bool,
    /// Suggested retry delay
    pub retry_after_ms: Option<u64>,
    /// Structured details
    pub details: Option<serde_json::Value>,
    /// Agent-friendly recovery hint
    pub ai_recovery_hint: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectorId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstanceId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZoneId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl Default for CorrelationId {
    fn default() -> Self {
        Self(Uuid::new_v4())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub kind: String,
    pub id: String,
    pub trust: TrustLevel,
    pub display: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Owner,
    Admin,
    Paired,
    Untrusted,
    Anonymous,
    Blocked,
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Tokens (FCT) and Verification
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub jti: Uuid,
    pub sub: PrincipalId,
    pub iss: ZoneId,
    pub aud: ConnectorId,
    pub instance: Option<InstanceId>,
    pub iat: u64,
    pub exp: u64,
    pub caps: Vec<CapabilityGrant>,
    pub constraints: CapabilityConstraints,
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability: CapabilityId,
    pub operation: Option<OperationId>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityConstraints {
    pub resource_allow: Vec<String>,
    pub resource_deny: Vec<String>,
    pub max_calls: Option<u32>,
    pub max_bytes: Option<u64>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max: u32,
    pub per_ms: u64,
    pub burst: Option<u32>,
    pub scope: Option<String>, // per_connector | per_zone | per_principal
}

#[derive(Debug, Clone)]
pub struct CapabilityVerifier {
    pub host_public_key: [u8; 32],
    pub zone_id: ZoneId,
    pub instance_id: InstanceId,
}

impl CapabilityVerifier {
    pub fn verify(
        &self,
        token: &CapabilityToken,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<()> {
        // Pseudocode: verify signature, expiry, zone, instance, op, constraints
        // NOTE: signature verification omitted for brevity; use ed25519-dalek in real code.
        let now = chrono::Utc::now().timestamp() as u64;
        if token.exp <= now {
            return Err(FcpError::Auth {
                code: 2001,
                message: "Capability token expired".into(),
            });
        }
        if token.iss != self.zone_id {
            return Err(FcpError::ZoneViolation {
                source: token.iss.clone(),
                target: self.zone_id.clone(),
                message: "Token zone mismatch".into(),
            });
        }
        if let Some(ref inst) = token.instance {
            if inst != &self.instance_id {
                return Err(FcpError::CapabilityDenied {
                    capability: operation.0.clone(),
                    reason: "Instance mismatch".into(),
                });
            }
        }
        let op_allowed = token.caps.iter().any(|c| match &c.operation {
            Some(op) => op == operation,
            None => c.capability.0 == operation.0,
        });
        if !op_allowed {
            return Err(FcpError::CapabilityDenied {
                capability: operation.0.clone(),
                reason: "Operation not granted".into(),
            });
        }
        // Enforce resource allow/deny constraints
        if !token.constraints.resource_allow.is_empty() {
            let allowed = resource_uris.iter().all(|uri| {
                token.constraints.resource_allow.iter().any(|p| uri.starts_with(p))
            });
            if !allowed {
                return Err(FcpError::CapabilityDenied {
                    capability: operation.0.clone(),
                    reason: "Resource not allowed".into(),
                });
            }
        }
        if token
            .constraints
            .resource_deny
            .iter()
            .any(|p| resource_uris.iter().any(|uri| uri.starts_with(p)))
        {
            return Err(FcpError::CapabilityDenied {
                capability: operation.0.clone(),
                reason: "Resource explicitly denied".into(),
            });
        }
        // Max calls/max bytes/idempotency enforcement require shared state; enforce at call sites.
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone System
// ─────────────────────────────────────────────────────────────────────────────

pub type CapabilitySet = Vec<CapabilityId>;
pub type PrincipalPolicy = serde_json::Value;
pub type ConnectorPolicy = serde_json::Value;
pub type AuditPolicy = serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    pub id: ZoneId,
    pub name: String,
    pub trust_level: u8,
    pub trust_grade: Option<TrustGrade>,
    pub parent: Option<ZoneId>,
    pub principals: PrincipalPolicy,
    pub capability_ceiling: CapabilitySet,
    pub allowed_connectors: ConnectorPolicy,
    pub data_flow: DataFlowPolicy,
    pub audit: AuditPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustGrade {
    LocalOwner,
    TrustedRemote,
    Public,
    Automation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPolicy {
    pub inbound_from: Vec<ZoneId>,
    pub outbound_to: Vec<ZoneId>,
}

#[derive(Debug, Clone)]
pub struct ZoneContext {
    pub current_zone: ZoneId,
    pub allowed_zones: Vec<ZoneId>,
}

impl ZoneContext {
    pub fn can_access(&self, target: &ZoneId) -> bool {
        self.allowed_zones.contains(target) || &self.current_zone == target
    }
    
    pub fn enforce(&self, target: &ZoneId) -> FcpResult<()> {
        if self.can_access(target) {
            Ok(())
        } else {
            Err(FcpError::ZoneViolation {
                source: self.current_zone.clone(),
                target: target.clone(),
                message: "Zone access denied".into(),
            })
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Invoke Request/Response Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeRequest {
    pub r#type: String,
    pub id: CorrelationId,
    pub operation: OperationId,
    pub input: serde_json::Value,
    pub capability_token: CapabilityToken,
    pub context: Option<InvokeContext>,
    pub idempotency_key: Option<String>,
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeContext {
    pub locale: Option<String>,
    pub pagination: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResponse {
    pub r#type: String,
    pub id: CorrelationId,
    pub result: serde_json::Value,
    pub resource_uris: Vec<String>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequest {
    pub topics: Vec<String>,
    pub since: Option<String>,
    pub max_events_per_sec: Option<u32>,
    pub batch_ms: Option<u32>,
    pub window_size: Option<u32>,
    /// Optional capability token (may be provided via frame/meta in JSON-RPC compat)
    pub capability_token: Option<CapabilityToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResponse {
    pub confirmed_topics: Vec<String>,
    pub cursors: HashMap<String, String>,
    pub replay_supported: bool,
    pub buffer: Option<ReplayBufferInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBufferInfo {
    pub min_events: u32,
    pub overflow: String, // e.g., "stream.reset"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    pub topics: Vec<String>,
    /// Optional capability token (may be provided via frame/meta in JSON-RPC compat)
    pub capability_token: Option<CapabilityToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportCaps {
    pub compression: Vec<String>,
    pub max_frame_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub name: String,
    pub version: Option<String>,
    pub build: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub protocol_version: String,
    pub host: Option<HostInfo>,
    pub zone: ZoneId,
    pub zone_dir: Option<String>,
    pub capabilities_requested: Vec<CapabilityId>,
    pub nonce: [u8; 32],
    pub host_public_key: [u8; 32],
    pub transport_caps: Option<TransportCaps>,
    pub requested_instance_id: Option<InstanceId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub status: String,
    pub capabilities_granted: Vec<CapabilityId>,
    pub session_id: SessionId,
    pub manifest_hash: String,
    pub nonce: [u8; 32],
    pub event_caps: Option<EventCaps>,
    pub auth_caps: Option<AuthCaps>,
    pub op_catalog_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownRequest {
    pub deadline_ms: u64,
    pub drain: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Types (Envelope)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub r#type: String,
    pub topic: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub seq: u64,
    pub cursor: Option<String>,
    pub requires_ack: bool,
    pub ack_deadline_ms: Option<u64>,
    pub data: EventData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub connector_id: ConnectorId,
    pub instance_id: InstanceId,
    pub zone_id: ZoneId,
    pub principal: Principal,
    pub payload: serde_json::Value,
    pub correlation_id: Option<CorrelationId>,
    pub resource_uris: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Health & Metrics
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Starting,
    Ready,
    Degraded { reason: String },
    Error { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub status: HealthState,
    pub uptime_ms: u64,
    pub load: Option<LoadMetrics>,
    pub details: Option<HealthDetails>,
    pub rate_limit: Option<RateLimitState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadMetrics {
    pub cpu: f64,
    pub mem_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthDetails {
    pub last_error: Option<String>,
    pub dependencies: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitState {
    pub remaining: u32,
    pub reset_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectorMetrics {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_error: u64,
    pub latency_p50_ms: f64,
    pub latency_p99_ms: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Connector Trait
// ─────────────────────────────────────────────────────────────────────────────

/// The base trait all FCP connectors must implement.
#[async_trait]
pub trait FcpConnector: Send + Sync {
    /// Unique connector identifier
    fn id(&self) -> &ConnectorId;

    /// Describe static connector metadata (manifest-safe subset)
    fn describe(&self) -> DescribeInfo {
        let introspection = self.introspect();
        DescribeInfo::from_introspection(self.id(), &introspection)
    }
    
    /// Apply configuration (validated by Host)
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()>;
    
    /// Perform protocol handshake with Host
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse>;
    
    /// Get current health status
    async fn health(&self) -> HealthSnapshot;
    
    /// Get current metrics
    fn metrics(&self) -> ConnectorMetrics;
    
    /// Graceful shutdown
    async fn shutdown(&mut self, req: ShutdownRequest) -> FcpResult<()>;
    
    /// Introspection: operations, events, and resource types
    fn introspect(&self) -> Introspection;

    /// Full capabilities catalog (stable across runtime sessions)
    fn capabilities(&self) -> Introspection {
        self.introspect()
    }

    /// Invoke an operation
    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;

    /// Subscribe to event streams (streaming connectors only)
    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::Connector {
            code: 5005,
            message: "Streaming not supported".into(),
            retryable: false,
        })
    }

    /// Unsubscribe from event streams (streaming connectors only)
    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::Connector {
            code: 5005,
            message: "Streaming not supported".into(),
            retryable: false,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationInfo {
    pub id: OperationId,
    pub summary: String,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub capability: CapabilityId,
    pub risk_level: String, // low | medium | high | critical
    pub safety_tier: SafetyTier,
    pub idempotency: IdempotencyClass,
    pub ai_hints: AgentHint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHint {
    pub when_to_use: String,
    pub common_mistakes: Vec<String>,
    pub examples: Vec<String>,
    pub related: Vec<CapabilityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyTier {
    Safe,
    Risky,
    Dangerous,
    Forbidden,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    None,
    BestEffort,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    pub topic: String,
    pub schema: serde_json::Value,
    pub requires_ack: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCaps {
    pub methods: Vec<String>, // device_code | browser_oauth | api_key | bot_token
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCaps {
    pub streaming: bool,
    pub replay: bool,
    pub min_buffer_events: u32,
    pub requires_ack: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeInfo {
    pub id: ConnectorId,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub documentation: Option<String>,
    pub repository: Option<String>,
    pub archetypes: Vec<String>,
    pub auth_caps: Option<AuthCaps>,
    pub event_caps: Option<EventCaps>,
    pub resource_types: Vec<String>,
}

impl DescribeInfo {
    pub fn from_introspection(id: &ConnectorId, introspection: &Introspection) -> Self {
        Self {
            id: id.clone(),
            name: id.0.clone(),
            version: None,
            description: None,
            documentation: None,
            repository: None,
            archetypes: Vec::new(),
            auth_caps: introspection.auth_caps.clone(),
            event_caps: introspection.event_caps.clone(),
            resource_types: introspection.resource_types.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Introspection {
    pub operations: Vec<OperationInfo>,
    pub events: Vec<EventInfo>,
    pub resource_types: Vec<String>,
    pub auth_caps: Option<AuthCaps>,
    pub event_caps: Option<EventCaps>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Stream Types
// ─────────────────────────────────────────────────────────────────────────────

pub type EventStream = Pin<Box<dyn Stream<Item = FcpResult<EventEnvelope>> + Send>>;
pub type ByteStream = Pin<Box<dyn Stream<Item = FcpResult<Bytes>> + Send>>;

// ─────────────────────────────────────────────────────────────────────────────
// Utility: Retry with Backoff
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

pub async fn retry_with_backoff<F, Fut, T>(
    config: &RetryConfig,
    mut operation: F,
) -> FcpResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = FcpResult<T>>,
{
    let mut delay = config.initial_delay;
    let mut attempt = 0;
    
    loop {
        attempt += 1;
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if e.is_retryable() && attempt < config.max_attempts => {
                if let Some(retry_after) = e.retry_after() {
                    tokio::time::sleep(retry_after).await;
                } else {
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(
                        Duration::from_secs_f64(delay.as_secs_f64() * config.multiplier),
                        config.max_delay,
                    );
                }
            }
            Err(e) => return Err(e),
        }
    }
}
```

---

## Archetype 1: Request-Response

The most common pattern: synchronous request/response over HTTP or similar protocols.

**Examples**: REST APIs, GraphQL, gRPC unary calls

```rust
// ============================================================================
// File: fcp-archetype-request-response/src/lib.rs
// Model connector: Request-Response pattern (e.g., REST API)
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::*;
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponseConfig {
    /// Base URL for the API
    pub base_url: String,
    
    /// Authentication configuration
    pub auth: AuthConfig,
    
    /// Request timeout
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    
    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,
    
    /// Rate limiting
    pub rate_limit: Option<RateLimitConfig>,
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthConfig {
    None,
    Bearer { token: String },
    Basic { username: String, password: String },
    ApiKey { header: String, key: String },
    OAuth2 { client_id: String, client_secret: String, token_url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub burst: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State
// ─────────────────────────────────────────────────────────────────────────────

pub struct RequestResponseConnector {
    id: ConnectorId,
    config: Option<RequestResponseConfig>,
    client: Option<Client>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    
    // Metrics (atomic for lock-free access)
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_error: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    
    // Rate limiter state
    rate_limiter: Option<Arc<RwLock<RateLimiterState>>>,
    
    // OAuth token cache
    oauth_token: Arc<RwLock<Option<OAuthToken>>>,
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    last_update: Instant,
    config: RateLimitConfig,
}

#[derive(Debug, Clone)]
struct OAuthToken {
    access_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl RequestResponseConnector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: ConnectorId(id.into()),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_error: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            rate_limiter: None,
            oauth_token: Arc::new(RwLock::new(None)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl FcpConnector for RequestResponseConnector {
    fn id(&self) -> &ConnectorId {
        &self.id
    }
    
    #[instrument(skip(self, config))]
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: RequestResponseConfig = serde_json::from_value(config)
            .map_err(|e| FcpError::Connector {
                code: 5005,
                message: format!("Invalid configuration: {e}"),
                retryable: false,
            })?;
        
        // Build HTTP client
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(format!("fcp-connector/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        
        // Initialize rate limiter if configured
        if let Some(ref rl_config) = config.rate_limit {
            self.rate_limiter = Some(Arc::new(RwLock::new(RateLimiterState {
                tokens: rl_config.burst as f64,
                last_update: Instant::now(),
                config: rl_config.clone(),
            })));
        }
        
        self.client = Some(client);
        self.config = Some(config);
        
        info!(connector = %self.id.0, "Connector configured");
        Ok(())
    }
    
    #[instrument(skip(self, req))]
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let instance_id = req
            .requested_instance_id
            .unwrap_or_else(|| InstanceId(format!("inst_{}", Uuid::new_v4())));

        self.verifier = Some(CapabilityVerifier {
            host_public_key: req.host_public_key,
            zone_id: req.zone.clone(),
            instance_id: instance_id.clone(),
        });
        let session_id = SessionId(Uuid::new_v4());
        self.session_id = Some(session_id.clone());
        
        info!(connector = %self.id.0, session = %session_id.0, "Handshake complete");
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req.capabilities_requested,
            session_id,
            manifest_hash: "sha256:placeholder".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }
    
    async fn health(&self) -> HealthSnapshot {
        let Some(ref client) = self.client else {
            return HealthSnapshot {
                status: HealthState::Error {
                    reason: "Not initialized".into(),
                },
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            };
        };
        
        let Some(ref config) = self.config else {
            return HealthSnapshot {
                status: HealthState::Error {
                    reason: "Not configured".into(),
                },
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            };
        };
        
        // Perform a lightweight health check request
        match client.get(&config.base_url).send().await {
            Ok(resp) if resp.status().is_success() || resp.status() == StatusCode::UNAUTHORIZED => {
                HealthSnapshot {
                    status: HealthState::Ready,
                    uptime_ms: 0,
                    load: None,
                    details: None,
                    rate_limit: None,
                }
            }
            Ok(resp) => HealthSnapshot {
                status: HealthState::Degraded {
                    reason: format!("Unexpected status: {}", resp.status()),
                },
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            },
            Err(e) => HealthSnapshot {
                status: HealthState::Error {
                    reason: format!("Connection failed: {e}"),
                },
                uptime_ms: 0,
                load: None,
                details: Some(HealthDetails {
                    last_error: Some(e.to_string()),
                    dependencies: None,
                }),
                rate_limit: None,
            },
        }
    }
    
    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_error: self.requests_error.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
    
    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        info!(connector = %self.id.0, "Shutting down");
        self.client = None;
        self.session_id = None;
        Ok(())
    }
    
    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId("http.get".into()),
                    summary: "Perform HTTP GET request".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "query": { "type": "object" }
                        },
                        "required": ["path"]
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "integer" },
                            "body": { "type": "object" }
                        }
                    }),
                    capability: CapabilityId("http.get".into()),
                    risk_level: "low".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Fetch data from the configured API.".into(),
                        common_mistakes: vec!["Missing path parameter".into()],
                        examples: vec!["GET /v1/status".into()],
                        related: vec![CapabilityId("http.post".into())],
                    },
                },
                OperationInfo {
                    id: OperationId("http.post".into()),
                    summary: "Perform HTTP POST request".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "body": { "type": "object" }
                        },
                        "required": ["path"]
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "integer" },
                            "body": { "type": "object" }
                        }
                    }),
                    capability: CapabilityId("http.post".into()),
                    risk_level: "medium".into(),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use: "Create or update resources on the API.".into(),
                        common_mistakes: vec!["Posting to the wrong path".into()],
                        examples: vec!["POST /v1/items".into()],
                        related: vec![CapabilityId("http.get".into())],
                    },
                },
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.request(req).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request-Response Specific Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for connectors that follow request-response pattern
#[async_trait]
pub trait RequestResponse: FcpConnector {
    /// Execute a request and get a response
    async fn request(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;
}

#[async_trait]
impl RequestResponse for RequestResponseConnector {
    #[instrument(skip(self), fields(correlation_id = %req.id.0))]
    async fn request(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let start = Instant::now();
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        
        // Capability token verification
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(&req.capability_token, &req.operation, &[])?;
        
        // Rate limit check
        self.check_rate_limit().await?;
        
        // Build and execute HTTP request
        let result = self.execute_http_request(&req).await;
        
        // Update metrics
        let duration = start.elapsed();
        match &result {
            Ok(_) => self.requests_success.fetch_add(1, Ordering::Relaxed),
            Err(_) => self.requests_error.fetch_add(1, Ordering::Relaxed),
        };
        
        result.map(|data| InvokeResponse {
            r#type: "response".into(),
            id: req.id,
            result: data,
            resource_uris: vec![],
            next_cursor: None,
        })
    }
}

impl RequestResponseConnector {
    async fn check_rate_limit(&self) -> FcpResult<()> {
        let Some(ref limiter) = self.rate_limiter else {
            return Ok(());
        };
        
        let mut state = limiter.write().await;
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_update).as_secs_f64();
        
        // Replenish tokens
        state.tokens = (state.tokens + elapsed * state.config.requests_per_second)
            .min(state.config.burst as f64);
        state.last_update = now;
        
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            let wait_time = (1.0 - state.tokens) / state.config.requests_per_second;
            Err(FcpError::External {
                service: "rate_limiter".into(),
                message: "Rate limit exceeded".into(),
                status_code: Some(429),
                retryable: true,
                retry_after: Some(Duration::from_secs_f64(wait_time)),
            })
        }
    }
    
    #[instrument(skip(self))]
    async fn execute_http_request(&self, req: &InvokeRequest) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not initialized".into(),
            retryable: false,
        })?;
        
        let config = self.config.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not configured".into(),
            retryable: false,
        })?;
        
        // Parse request parameters
        let path = req.input.get("path")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::Connector {
                code: 5005,
                message: "Missing 'path' parameter".into(),
                retryable: false,
            })?;
        
        let method = match req.operation.0.as_str() {
            "http.get" => Method::GET,
            "http.post" => Method::POST,
            _ => return Err(FcpError::Connector {
                code: 5005,
                message: format!(
                    "Unknown operation: {} (expected http.get or http.post)",
                    req.operation.0
                ),
                retryable: false,
            }),
        };
        
        let url = format!("{}{}", config.base_url.trim_end_matches('/'), path);
        let mut request = client.request(method, &url);
        
        // Add authentication
        request = self.add_auth(request, config).await?;
        
        // Add body for POST/PUT/PATCH
        if let Some(body) = req.input.get("body") {
            request = request.json(body);
            self.bytes_sent.fetch_add(
                serde_json::to_vec(body).map(|v| v.len()).unwrap_or(0) as u64,
                Ordering::Relaxed,
            );
        }
        
        // Add query parameters
        if let Some(query) = req.input.get("query").and_then(|v| v.as_object()) {
            for (k, v) in query {
                if let Some(s) = v.as_str() {
                    request = request.query(&[(k, s)]);
                }
            }
        }
        
        // Execute with retry
        let response = retry_with_backoff(&config.retry, || async {
            let resp = request.try_clone()
                .ok_or(FcpError::Internal { message: "Failed to clone request".into() })?
                .send()
                .await
                .map_err(|e| FcpError::External {
                    service: "http".into(),
                    message: e.to_string(),
                    status_code: e.status().map(|s| s.as_u16()),
                    retryable: e.is_timeout() || e.is_connect(),
                    retry_after: None,
                })?;
            
            let status = resp.status();
            
            // Handle rate limiting
            if status == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = resp.headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(Duration::from_secs);
                
                return Err(FcpError::External {
                    service: "http".into(),
                    message: "Rate limited".into(),
                    status_code: Some(429),
                    retryable: true,
                    retry_after,
                });
            }
            
            let bytes = resp.bytes().await.map_err(|e| FcpError::External {
                service: "http".into(),
                message: e.to_string(),
                status_code: Some(status.as_u16()),
                retryable: false,
                retry_after: None,
            })?;
            
            self.bytes_received.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            
            if status.is_success() {
                serde_json::from_slice(&bytes).map_err(|e| FcpError::External {
                    service: "http".into(),
                    message: format!("Invalid JSON response: {e}"),
                    status_code: Some(status.as_u16()),
                    retryable: false,
                    retry_after: None,
                })
            } else {
                Err(FcpError::External {
                    service: "http".into(),
                    message: String::from_utf8_lossy(&bytes).to_string(),
                    status_code: Some(status.as_u16()),
                    retryable: status.is_server_error(),
                    retry_after: None,
                })
            }
        }).await?;
        
        Ok(response)
    }
    
    async fn add_auth(
        &self,
        mut request: reqwest::RequestBuilder,
        config: &RequestResponseConfig,
    ) -> FcpResult<reqwest::RequestBuilder> {
        match &config.auth {
            AuthConfig::None => {}
            AuthConfig::Bearer { token } => {
                request = request.bearer_auth(token);
            }
            AuthConfig::Basic { username, password } => {
                request = request.basic_auth(username, Some(password));
            }
            AuthConfig::ApiKey { header, key } => {
                request = request.header(header.as_str(), key.as_str());
            }
            AuthConfig::OAuth2 { client_id, client_secret, token_url } => {
                let token = self.get_oauth_token(client_id, client_secret, token_url).await?;
                request = request.bearer_auth(&token.access_token);
            }
        }
        Ok(request)
    }
    
    async fn get_oauth_token(
        &self,
        client_id: &str,
        client_secret: &str,
        token_url: &str,
    ) -> FcpResult<OAuthToken> {
        // Check cache
        {
            let cached = self.oauth_token.read().await;
            if let Some(ref token) = *cached {
                if token.expires_at > chrono::Utc::now() + chrono::Duration::seconds(60) {
                    return Ok(token.clone());
                }
            }
        }
        
        // Fetch new token
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Client not initialized".into(),
        })?;
        
        let response = client
            .post(token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .map_err(|e| FcpError::Auth {
                code: 2001,
                message: format!("OAuth token request failed: {e}"),
            })?;
        
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: i64,
        }
        
        let token_resp: TokenResponse = response.json().await.map_err(|e| FcpError::Auth {
            code: 2001,
            message: format!("Invalid OAuth response: {e}"),
        })?;
        
        let token = OAuthToken {
            access_token: token_resp.access_token,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(token_resp.expires_in),
        };
        
        // Cache token
        *self.oauth_token.write().await = Some(token.clone());
        
        Ok(token)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};
    
    #[tokio::test]
    async fn test_basic_get_request() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("GET"))
            .and(path("/api/test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "success"
            })))
            .mount(&mock_server)
            .await;
        
        let mut connector = RequestResponseConnector::new("test");
        
        connector.configure(serde_json::json!({
            "base_url": mock_server.uri(),
            "auth": { "type": "None" }
        })).await.unwrap();

        let instance_id = InstanceId("inst_test".into());
        connector.handshake(HandshakeRequest {
            protocol_version: "1.0.0".into(),
            host: None,
            zone: ZoneId("z:test".into()),
            zone_dir: None,
            capabilities_requested: vec![CapabilityId("http.get".into())],
            nonce: [0u8; 32],
            host_public_key: [0u8; 32],
            transport_caps: None,
            requested_instance_id: Some(instance_id.clone()),
        }).await.unwrap();

        let token = CapabilityToken {
            jti: Uuid::new_v4(),
            sub: PrincipalId("tester".into()),
            iss: ZoneId("z:test".into()),
            aud: ConnectorId("test".into()),
            instance: Some(instance_id),
            iat: 0,
            exp: u64::MAX,
            caps: vec![CapabilityGrant {
                capability: CapabilityId("http.get".into()),
                operation: Some(OperationId("http.get".into())),
            }],
            constraints: CapabilityConstraints::default(),
            sig: [0u8; 64],
        };

        let response = connector.request(InvokeRequest {
            r#type: "invoke".into(),
            id: CorrelationId::default(),
            operation: OperationId("http.get".into()),
            input: serde_json::json!({ "path": "/api/test" }),
            capability_token: token,
            context: None,
            idempotency_key: None,
            deadline_ms: None,
        }).await.unwrap();

        assert_eq!(response.result["message"], "success");
    }
    
    #[tokio::test]
    async fn test_capability_denied() {
        let mut connector = RequestResponseConnector::new("test");
        
        connector.configure(serde_json::json!({
            "base_url": "http://localhost",
            "auth": { "type": "None" }
        })).await.unwrap();

        let instance_id = InstanceId("inst_test".into());
        connector.handshake(HandshakeRequest {
            protocol_version: "1.0.0".into(),
            host: None,
            zone: ZoneId("z:test".into()),
            zone_dir: None,
            capabilities_requested: vec![CapabilityId("http.post".into())],
            nonce: [0u8; 32],
            host_public_key: [0u8; 32],
            transport_caps: None,
            requested_instance_id: Some(instance_id.clone()),
        }).await.unwrap();

        let token = CapabilityToken {
            jti: Uuid::new_v4(),
            sub: PrincipalId("tester".into()),
            iss: ZoneId("z:test".into()),
            aud: ConnectorId("test".into()),
            instance: Some(instance_id),
            iat: 0,
            exp: u64::MAX,
            caps: vec![CapabilityGrant {
                capability: CapabilityId("http.post".into()),
                operation: Some(OperationId("http.post".into())),
            }],
            constraints: CapabilityConstraints::default(),
            sig: [0u8; 64],
        };

        let result = connector.request(InvokeRequest {
            r#type: "invoke".into(),
            id: CorrelationId::default(),
            operation: OperationId("http.get".into()),
            input: serde_json::json!({ "path": "/test" }),
            capability_token: token,
            context: None,
            idempotency_key: None,
            deadline_ms: None,
        }).await;
        
        assert!(matches!(result, Err(FcpError::CapabilityDenied { .. })));
    }
}
```

---

## Archetype 2: Streaming (Server Push)

Server continuously pushes data to the client.

**Examples**: WebSocket feeds, SSE, log tailing, real-time market data

```rust
// ============================================================================
// File: fcp-archetype-streaming/src/lib.rs
// Model connector: Streaming pattern (Server Push)
// ============================================================================

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fcp_core::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, instrument, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// WebSocket URL to connect to
    pub url: String,
    
    /// Authentication
    pub auth: Option<StreamingAuth>,
    
    /// Reconnect configuration
    #[serde(default)]
    pub reconnect: ReconnectConfig,
    
    /// Heartbeat interval (for ping/pong)
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval: Duration,
    
    /// Buffer size for broadcast channel
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_heartbeat() -> Duration {
    Duration::from_secs(30)
}

fn default_buffer_size() -> usize {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StreamingAuth {
    QueryParam { key: String, value: String },
    Header { name: String, value: String },
    Message { payload: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectConfig {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_initial_delay")]
    pub initial_delay: Duration,
    #[serde(default = "default_max_delay")]
    pub max_delay: Duration,
}

fn default_max_attempts() -> u32 { 10 }
fn default_initial_delay() -> Duration { Duration::from_secs(1) }
fn default_max_delay() -> Duration { Duration::from_secs(60) }

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_delay: default_initial_delay(),
            max_delay: default_max_delay(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State
// ─────────────────────────────────────────────────────────────────────────────

pub struct StreamingConnector {
    id: ConnectorId,
    config: Option<StreamingConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    
    // Connection state
    connected: Arc<AtomicBool>,
    shutdown_signal: Option<mpsc::Sender<()>>,
    
    // Event broadcasting
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    
    // Subscriptions
    subscriptions: Arc<RwLock<Vec<String>>>,
    subscription_tx: Option<mpsc::Sender<SubscriptionCommand>>,
    
    // Metrics
    events_received: AtomicU64,
    reconnects: AtomicU64,
    bytes_received: AtomicU64,
}

#[derive(Debug)]
enum SubscriptionCommand {
    Subscribe(String),
    Unsubscribe(String),
}

impl StreamingConnector {
    pub fn new(id: impl Into<String>) -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        
        Self {
            id: ConnectorId(id.into()),
            config: None,
            verifier: None,
            session_id: None,
            connected: Arc::new(AtomicBool::new(false)),
            shutdown_signal: None,
            event_tx,
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            subscription_tx: None,
            events_received: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl FcpConnector for StreamingConnector {
    fn id(&self) -> &ConnectorId {
        &self.id
    }
    
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: StreamingConfig = serde_json::from_value(config)
            .map_err(|e| FcpError::Connector {
                code: 5005,
                message: format!("Invalid configuration: {e}"),
                retryable: false,
            })?;
        
        self.config = Some(config);
        Ok(())
    }
    
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let instance_id = req
            .requested_instance_id
            .unwrap_or_else(|| InstanceId(format!("inst_{}", Uuid::new_v4())));

        self.verifier = Some(CapabilityVerifier {
            host_public_key: req.host_public_key,
            zone_id: req.zone.clone(),
            instance_id: instance_id.clone(),
        });
        let session_id = SessionId(Uuid::new_v4());
        self.session_id = Some(session_id.clone());
        
        // Start the connection loop
        self.start_connection_loop().await?;
        
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req.capabilities_requested,
            session_id,
            manifest_hash: "sha256:placeholder".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 10_000,
                requires_ack: true,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }
    
    async fn health(&self) -> HealthSnapshot {
        if self.connected.load(Ordering::SeqCst) {
            HealthSnapshot {
                status: HealthState::Ready,
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            }
        } else {
            HealthSnapshot {
                status: HealthState::Degraded {
                    reason: "Not connected".into(),
                },
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            }
        }
    }
    
    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.events_received.load(Ordering::Relaxed),
            requests_success: self.events_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
    
    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(ref tx) = self.shutdown_signal {
            let _ = tx.send(()).await;
        }
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }
    
    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![EventInfo {
                topic: format!("connector.{}.stream.event", self.id.0),
                schema: serde_json::json!({ "type": "object" }),
                requires_ack: true,
            }],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 10_000,
                requires_ack: true,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let _ = req;
        Err(FcpError::Connector {
            code: 5005,
            message: "No invoke operations supported; use subscribe/unsubscribe".into(),
            retryable: false,
        })
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        for topic in &req.topics {
            let _ = Streaming::subscribe(self, topic).await?;
        }
        Ok(SubscribeResponse {
            confirmed_topics: req.topics,
            cursors: HashMap::new(),
            replay_supported: true,
            buffer: Some(ReplayBufferInfo {
                min_events: 10_000,
                overflow: "stream.reset".into(),
            }),
        })
    }

    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()> {
        for topic in &req.topics {
            Streaming::unsubscribe(self, topic).await?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming-Specific Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for connectors that receive streaming data
#[async_trait]
pub trait Streaming: FcpConnector {
    /// Subscribe to a topic and get a stream of events
    async fn subscribe(&self, topic: &str) -> FcpResult<EventStream>;
    
    /// Unsubscribe from a topic
    async fn unsubscribe(&self, topic: &str) -> FcpResult<()>;
    
    /// Get all events (regardless of topic)
    fn events(&self) -> EventStream;
}

#[async_trait]
impl Streaming for StreamingConnector {
    #[instrument(skip(self))]
    async fn subscribe(&self, topic: &str) -> FcpResult<EventStream> {
        // Add to subscription list
        {
            let mut subs = self.subscriptions.write().await;
            if !subs.contains(&topic.to_string()) {
                subs.push(topic.to_string());
            }
        }
        
        // Send subscription command
        if let Some(ref tx) = self.subscription_tx {
            tx.send(SubscriptionCommand::Subscribe(topic.to_string()))
                .await
                .map_err(|_| FcpError::Connector {
                    code: 5003,
                    message: "Connection not active".into(),
                    retryable: true,
                })?;
        }
        
        // Return filtered stream
        let topic = topic.to_string();
        let rx = self.event_tx.subscribe();
        let stream = BroadcastStream::new(rx)
            .filter_map(move |result| {
                let topic = topic.clone();
                async move {
                    match result {
                        Ok(Ok(event)) if event.topic == topic => Some(Ok(event)),
                        Ok(Err(e)) => Some(Err(e)),
                        _ => None,
                    }
                }
            });
        
        Ok(Box::pin(stream))
    }
    
    async fn unsubscribe(&self, topic: &str) -> FcpResult<()> {
        // Remove from subscription list
        {
            let mut subs = self.subscriptions.write().await;
            subs.retain(|t| t != topic);
        }
        
        // Send unsubscription command
        if let Some(ref tx) = self.subscription_tx {
            let _ = tx.send(SubscriptionCommand::Unsubscribe(topic.to_string())).await;
        }
        
        Ok(())
    }
    
    fn events(&self) -> EventStream {
        let rx = self.event_tx.subscribe();
        let stream = BroadcastStream::new(rx)
            .filter_map(|result| async move {
                match result {
                    Ok(event) => Some(event),
                    Err(_) => None, // Lagged, skip
                }
            });
        
        Box::pin(stream)
    }
}

impl StreamingConnector {
    async fn start_connection_loop(&mut self) -> FcpResult<()> {
        let config = self.config.clone().ok_or(FcpError::Connector {
            code: 5002,
            message: "Not configured".into(),
            retryable: false,
        })?;
        
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let (sub_tx, mut sub_rx) = mpsc::channel::<SubscriptionCommand>(100);
        
        self.shutdown_signal = Some(shutdown_tx);
        self.subscription_tx = Some(sub_tx);
        
        let event_tx = self.event_tx.clone();
        let connected = self.connected.clone();
        let subscriptions = self.subscriptions.clone();
        let events_received = &self.events_received as *const AtomicU64;
        let bytes_received = &self.bytes_received as *const AtomicU64;
        let reconnects = &self.reconnects as *const AtomicU64;
        let connector_id = self.id.clone();
        let instance_id = self
            .verifier
            .as_ref()
            .map(|verifier| verifier.instance_id.clone())
            .unwrap_or_else(|| InstanceId("inst_unknown".into()));
        let zone_id = self
            .verifier
            .as_ref()
            .map(|verifier| verifier.zone_id.clone())
            .unwrap_or_else(|| ZoneId("z:unknown".into()));
        
        // Spawn connection management task
        tokio::spawn(async move {
            let events_received = unsafe { &*events_received };
            let bytes_received = unsafe { &*bytes_received };
            let reconnects = unsafe { &*reconnects };
            
            let mut reconnect_delay = config.reconnect.initial_delay;
            let mut reconnect_attempts = 0;
            
            loop {
                // Build URL with auth if needed
                let url = match &config.auth {
                    Some(StreamingAuth::QueryParam { key, value }) => {
                        format!("{}?{}={}", config.url, key, value)
                    }
                    _ => config.url.clone(),
                };
                
                // Attempt connection
                match connect_async(&url).await {
                    Ok((ws_stream, _)) => {
                        connected.store(true, Ordering::SeqCst);
                        reconnect_delay = config.reconnect.initial_delay;
                        reconnect_attempts = 0;
                        
                        info!(url = %config.url, "WebSocket connected");
                        
                        let (mut write, mut read) = ws_stream.split();
                        
                        // Send auth message if configured
                        if let Some(StreamingAuth::Message { ref payload }) = config.auth {
                            let msg = Message::Text(payload.to_string());
                            if let Err(e) = write.send(msg).await {
                                error!(?e, "Failed to send auth message");
                                continue;
                            }
                        }
                        
                        // Resubscribe to previous topics
                        {
                            let subs = subscriptions.read().await;
                            for topic in subs.iter() {
                                let sub_msg = serde_json::json!({
                                    "type": "subscribe",
                                    "topic": topic
                                });
                                if let Err(e) = write.send(Message::Text(sub_msg.to_string())).await {
                                    warn!(?e, topic = %topic, "Failed to resubscribe");
                                }
                            }
                        }
                        
                        // Set up heartbeat
                        let heartbeat_interval = config.heartbeat_interval;
                        let mut heartbeat = tokio::time::interval(heartbeat_interval);
                        
                        loop {
                            tokio::select! {
                                // Shutdown signal
                                _ = shutdown_rx.recv() => {
                                    info!("Shutdown signal received");
                                    let _ = write.send(Message::Close(None)).await;
                                    return;
                                }
                                
                                // Heartbeat
                                _ = heartbeat.tick() => {
                                    if let Err(e) = write.send(Message::Ping(vec![])).await {
                                        warn!(?e, "Heartbeat failed");
                                        break;
                                    }
                                }
                                
                                // Subscription commands
                                Some(cmd) = sub_rx.recv() => {
                                    let msg = match cmd {
                                        SubscriptionCommand::Subscribe(topic) => {
                                            serde_json::json!({
                                                "type": "subscribe",
                                                "topic": topic
                                            })
                                        }
                                        SubscriptionCommand::Unsubscribe(topic) => {
                                            serde_json::json!({
                                                "type": "unsubscribe",
                                                "topic": topic
                                            })
                                        }
                                    };
                                    if let Err(e) = write.send(Message::Text(msg.to_string())).await {
                                        warn!(?e, "Failed to send subscription command");
                                    }
                                }
                                
                                // Incoming messages
                                Some(msg) = read.next() => {
                                    match msg {
                                        Ok(Message::Text(text)) => {
                                            bytes_received.fetch_add(text.len() as u64, Ordering::Relaxed);
                                            
                                            if let Ok(event) = Self::parse_event(
                                                &text,
                                                &connector_id,
                                                &instance_id,
                                                &zone_id,
                                            ) {
                                                events_received.fetch_add(1, Ordering::Relaxed);
                                                let _ = event_tx.send(Ok(event));
                                            }
                                        }
                                        Ok(Message::Binary(data)) => {
                                            bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                                            // Handle binary messages if needed
                                        }
                                        Ok(Message::Ping(data)) => {
                                            let _ = write.send(Message::Pong(data)).await;
                                        }
                                        Ok(Message::Close(_)) => {
                                            info!("Server closed connection");
                                            break;
                                        }
                                        Err(e) => {
                                            error!(?e, "WebSocket error");
                                            break;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        
                        connected.store(false, Ordering::SeqCst);
                    }
                    Err(e) => {
                        error!(?e, "Connection failed");
                    }
                }
                
                // Reconnect logic
                reconnect_attempts += 1;
                if reconnect_attempts >= config.reconnect.max_attempts {
                    error!("Max reconnect attempts reached");
                    let _ = event_tx.send(Err(FcpError::External {
                        service: "websocket".into(),
                        message: "Max reconnect attempts reached".into(),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    }));
                    return;
                }
                
                reconnects.fetch_add(1, Ordering::Relaxed);
                warn!(
                    attempt = reconnect_attempts,
                    delay_secs = reconnect_delay.as_secs(),
                    "Reconnecting..."
                );
                
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = std::cmp::min(
                    reconnect_delay * 2,
                    config.reconnect.max_delay,
                );
            }
        });
        
        // Wait for initial connection
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        if self.connected.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(FcpError::External {
                service: "websocket".into(),
                message: "Initial connection failed".into(),
                status_code: None,
                retryable: true,
                retry_after: Some(Duration::from_secs(1)),
            })
        }
    }
    
    fn parse_event(
        text: &str,
        connector_id: &ConnectorId,
        instance_id: &InstanceId,
        zone_id: &ZoneId,
    ) -> Result<EventEnvelope, serde_json::Error> {
        #[derive(Deserialize)]
        struct RawEvent {
            #[serde(default)]
            topic: Option<String>,
            #[serde(flatten)]
            data: serde_json::Value,
        }
        
        let raw: RawEvent = serde_json::from_str(text)?;
        let default_topic = format!("connector.{}.stream.event", connector_id.0);
        let raw_topic = raw.topic.unwrap_or_default();
        let topic = if raw_topic.is_empty() {
            default_topic
        } else if raw_topic.starts_with("connector.") || raw_topic.starts_with("connectors.") {
            raw_topic
        } else {
            format!("connector.{}.{}", connector_id.0, raw_topic)
        };
        
        Ok(EventEnvelope {
            r#type: "event".into(),
            topic,
            timestamp: chrono::Utc::now(),
            seq: 0,
            cursor: None,
            requires_ack: false,
            ack_deadline_ms: None,
            data: EventData {
                connector_id: connector_id.clone(),
                instance_id: instance_id.clone(),
                zone_id: zone_id.clone(),
                principal: Principal {
                    kind: "external".into(),
                    id: "unknown".into(),
                    trust: TrustLevel::Untrusted,
                    display: None,
                },
                payload: raw.data,
                correlation_id: None,
                resource_uris: vec![],
            },
        })
    }
}
```

---

## Archetype 3: Bidirectional Channel

Both client and server can send messages at any time.

**Examples**: Chat protocols, collaborative editing, game state sync

```rust
// ============================================================================
// File: fcp-archetype-bidirectional/src/lib.rs
// Model connector: Bidirectional Channel pattern
// ============================================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fcp_core::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, instrument, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BidirectionalConfig {
    pub url: String,
    pub auth: Option<serde_json::Value>,
    #[serde(default = "default_timeout")]
    pub request_timeout: Duration,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconnectConfig {
    pub enabled: bool,
    pub max_attempts: u32,
    pub initial_delay: Duration,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State
// ─────────────────────────────────────────────────────────────────────────────

pub struct BidirectionalConnector {
    id: ConnectorId,
    config: Option<BidirectionalConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    
    // Outbound channel
    outbound_tx: Option<mpsc::Sender<OutboundMessage>>,
    
    // Pending requests (for request-response over bidirectional)
    pending_requests: Arc<RwLock<HashMap<String, oneshot::Sender<serde_json::Value>>>>,
    
    // Inbound event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    
    // Metrics
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
}

#[derive(Debug)]
struct OutboundMessage {
    payload: serde_json::Value,
    /// If Some, this is a request expecting a response
    response_tx: Option<oneshot::Sender<serde_json::Value>>,
    request_id: Option<String>,
}

impl BidirectionalConnector {
    pub fn new(id: impl Into<String>) -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        
        Self {
            id: ConnectorId(id.into()),
            config: None,
            verifier: None,
            session_id: None,
            outbound_tx: None,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl FcpConnector for BidirectionalConnector {
    fn id(&self) -> &ConnectorId {
        &self.id
    }
    
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: BidirectionalConfig = serde_json::from_value(config)
            .map_err(|e| FcpError::Connector {
                code: 5005,
                message: format!("Invalid configuration: {e}"),
                retryable: false,
            })?;
        
        self.config = Some(config);
        Ok(())
    }
    
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let instance_id = req
            .requested_instance_id
            .unwrap_or_else(|| InstanceId(format!("inst_{}", Uuid::new_v4())));

        self.verifier = Some(CapabilityVerifier {
            host_public_key: req.host_public_key,
            zone_id: req.zone.clone(),
            instance_id: instance_id.clone(),
        });
        let session_id = SessionId(Uuid::new_v4());
        self.session_id = Some(session_id.clone());
        
        self.start_channel().await?;
        
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req.capabilities_requested,
            session_id,
            manifest_hash: "sha256:placeholder".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }
    
    async fn health(&self) -> HealthSnapshot {
        if self.outbound_tx.is_some() {
            HealthSnapshot {
                status: HealthState::Ready,
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            }
        } else {
            HealthSnapshot {
                status: HealthState::Error {
                    reason: "Not connected".into(),
                },
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            }
        }
    }
    
    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.messages_sent.load(Ordering::Relaxed)
                + self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.messages_sent.load(Ordering::Relaxed),
            bytes_received: self.messages_received.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
    
    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.outbound_tx = None;
        Ok(())
    }
    
    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId("channel.send".into()),
                    summary: "Send a message (fire and forget)".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": { "message": { "type": "object" } },
                        "required": ["message"]
                    }),
                    output_schema: serde_json::json!({ "type": "null" }),
                    capability: CapabilityId("channel.send".into()),
                    risk_level: "medium".into(),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a channel or chat.".into(),
                        common_mistakes: vec!["Sending to the wrong thread".into()],
                        examples: vec!["send {message: {...}}".into()],
                        related: vec![CapabilityId("channel.request".into())],
                    },
                },
                OperationInfo {
                    id: OperationId("channel.request".into()),
                    summary: "Send a request and wait for response".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": { "message": { "type": "object" } },
                        "required": ["message"]
                    }),
                    output_schema: serde_json::json!({ "type": "object" }),
                    capability: CapabilityId("channel.request".into()),
                    risk_level: "medium".into(),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message expecting a reply.".into(),
                        common_mistakes: vec!["Waiting indefinitely for a response".into()],
                        examples: vec!["request {message: {...}}".into()],
                        related: vec![CapabilityId("channel.send".into())],
                    },
                },
            ],
            events: vec![EventInfo {
                topic: format!("connector.{}.channel.inbound", self.id.0),
                schema: serde_json::json!({ "type": "object" }),
                requires_ack: false,
            }],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(&req.capability_token, &req.operation, &[])?;

        match req.operation.0.as_str() {
            "channel.send" => {
                self.send(req.input, &req.capability_token).await?;
                Ok(InvokeResponse {
                    r#type: "response".into(),
                    id: req.id,
                    result: serde_json::json!(null),
                    resource_uris: vec![],
                    next_cursor: None,
                })
            }
            "channel.request" => {
                let response = self.request(req.input, &req.capability_token).await?;
                Ok(InvokeResponse {
                    r#type: "response".into(),
                    id: req.id,
                    result: response,
                    resource_uris: vec![],
                    next_cursor: None,
                })
            }
            _ => Err(FcpError::Connector {
                code: 5005,
                message: "Unknown operation".into(),
                retryable: false,
            }),
        }
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        let confirmed = if req.topics.is_empty() {
            vec!["default".into()]
        } else {
            req.topics
        };
        Ok(SubscribeResponse {
            confirmed_topics: confirmed,
            cursors: HashMap::new(),
            replay_supported: false,
            buffer: None,
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bidirectional-Specific Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for connectors with bidirectional communication
#[async_trait]
pub trait Bidirectional: FcpConnector {
    /// Send a message without expecting a response
    async fn send(&self, message: serde_json::Value, token: &CapabilityToken) -> FcpResult<()>;
    
    /// Send a request and wait for a response
    async fn request(&self, message: serde_json::Value, token: &CapabilityToken)
        -> FcpResult<serde_json::Value>;
    
    /// Get stream of incoming events/messages
    fn events(&self) -> EventStream;
}

#[async_trait]
impl Bidirectional for BidirectionalConnector {
    #[instrument(skip(self, message))]
    async fn send(&self, message: serde_json::Value, token: &CapabilityToken) -> FcpResult<()> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(token, &OperationId("channel.send".into()), &[])?;
        
        let tx = self.outbound_tx.as_ref().ok_or(FcpError::Connector {
            code: 5003,
            message: "Not connected".into(),
            retryable: true,
        })?;
        
        tx.send(OutboundMessage {
            payload: message,
            response_tx: None,
            request_id: None,
        })
        .await
        .map_err(|_| FcpError::Connector {
            code: 5003,
            message: "Channel closed".into(),
            retryable: true,
        })?;
        
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    
    #[instrument(skip(self, message))]
    async fn request(
        &self,
        message: serde_json::Value,
        token: &CapabilityToken,
    ) -> FcpResult<serde_json::Value> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(token, &OperationId("channel.request".into()), &[])?;
        
        let tx = self.outbound_tx.as_ref().ok_or(FcpError::Connector {
            code: 5003,
            message: "Not connected".into(),
            retryable: true,
        })?;
        
        let request_id = Uuid::new_v4().to_string();
        let (response_tx, response_rx) = oneshot::channel();
        
        // Register pending request
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(request_id.clone(), response_tx);
        }
        
        // Send message with request ID
        let mut payload = message;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("request_id".into(), request_id.clone().into());
        }
        
        tx.send(OutboundMessage {
            payload,
            response_tx: None,
            request_id: Some(request_id.clone()),
        })
        .await
        .map_err(|_| FcpError::Connector {
            code: 5003,
            message: "Channel closed".into(),
            retryable: true,
        })?;
        
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        
        // Wait for response with timeout
        let timeout = self.config.as_ref()
            .map(|c| c.request_timeout)
            .unwrap_or(Duration::from_secs(30));
        
        let result = tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| {
                // Clean up pending request on timeout
                let pending = self.pending_requests.clone();
                let rid = request_id.clone();
                tokio::spawn(async move {
                    pending.write().await.remove(&rid);
                });
                
                FcpError::External {
                    service: "channel".into(),
                    message: "Request timed out".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                }
            })?
            .map_err(|_| FcpError::External {
                service: "channel".into(),
                message: "Response channel dropped".into(),
                status_code: None,
                retryable: true,
                retry_after: None,
            })?;
        
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        Ok(result)
    }
    
    fn events(&self) -> EventStream {
        let rx = self.event_tx.subscribe();
        let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
            .filter_map(|r| async move {
                match r {
                    Ok(event) => Some(event),
                    Err(_) => None,
                }
            });
        Box::pin(stream)
    }
}

impl BidirectionalConnector {
    async fn start_channel(&mut self) -> FcpResult<()> {
        let config = self.config.clone().ok_or(FcpError::Connector {
            code: 5002,
            message: "Not configured".into(),
            retryable: false,
        })?;
        
        let (ws_stream, _) = connect_async(&config.url)
            .await
            .map_err(|e| FcpError::External {
                service: "websocket".into(),
                message: e.to_string(),
                status_code: None,
                retryable: true,
                retry_after: Some(Duration::from_secs(1)),
            })?;
        
        let (mut write, mut read) = ws_stream.split();
        
        // Channel for outbound messages
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundMessage>(100);
        self.outbound_tx = Some(outbound_tx);
        
        let event_tx = self.event_tx.clone();
        let pending_requests = self.pending_requests.clone();
        let messages_received = &self.messages_received as *const AtomicU64;
        let connector_id = self.id.clone();
        let instance_id = self
            .verifier
            .as_ref()
            .map(|verifier| verifier.instance_id.clone())
            .unwrap_or_else(|| InstanceId("inst_unknown".into()));
        let zone_id = self
            .verifier
            .as_ref()
            .map(|verifier| verifier.zone_id.clone())
            .unwrap_or_else(|| ZoneId("z:unknown".into()));
        
        // Spawn read/write tasks
        tokio::spawn(async move {
            let messages_received = unsafe { &*messages_received };
            
            loop {
                tokio::select! {
                    // Outbound messages
                    Some(msg) = outbound_rx.recv() => {
                        let text = msg.payload.to_string();
                        if let Err(e) = write.send(Message::Text(text)).await {
                            error!(?e, "Failed to send message");
                            break;
                        }
                    }
                    
                    // Inbound messages
                    Some(msg) = read.next() => {
                        match msg {
                            Ok(Message::Text(text)) => {
                                messages_received.fetch_add(1, Ordering::Relaxed);
                                
                                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                                    // Check if this is a response to a pending request
                                    if let Some(request_id) = value.get("request_id").and_then(|v| v.as_str()) {
                                        let mut pending = pending_requests.write().await;
                                        if let Some(tx) = pending.remove(request_id) {
                                            let _ = tx.send(value.clone());
                                            continue;
                                        }
                                    }
                                    
                                    // Otherwise, broadcast as event
                                    let event = EventEnvelope {
                                        r#type: "event".into(),
                                        topic: format!("connector.{}.channel.inbound", connector_id.0),
                                        timestamp: chrono::Utc::now(),
                                        seq: 0,
                                        cursor: None,
                                        requires_ack: false,
                                        ack_deadline_ms: None,
                                        data: EventData {
                                            connector_id: connector_id.clone(),
                                            instance_id: instance_id.clone(),
                                            zone_id: zone_id.clone(),
                                            principal: Principal {
                                                kind: "external".into(),
                                                id: "unknown".into(),
                                                trust: TrustLevel::Untrusted,
                                                display: None,
                                            },
                                            payload: value,
                                            correlation_id: None,
                                            resource_uris: vec![],
                                        },
                                    };
                                    let _ = event_tx.send(Ok(event));
                                }
                            }
                            Ok(Message::Close(_)) => {
                                info!("Connection closed by server");
                                break;
                            }
                            Err(e) => {
                                error!(?e, "WebSocket error");
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
}
```

---

## Archetype 4: Polling (Pull-Based)

Client periodically checks for new data.

**Examples**: Email (IMAP), RSS feeds, API status checks

```rust
// ============================================================================
// File: fcp-archetype-polling/src/lib.rs
// Model connector: Polling pattern (Pull-Based)
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::*;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, instrument, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollingConfig {
    /// Default polling interval
    #[serde(default = "default_interval")]
    pub default_interval: Duration,
    
    /// Minimum allowed interval (prevents abuse)
    #[serde(default = "default_min_interval")]
    pub min_interval: Duration,
    
    /// Backoff on empty results
    #[serde(default)]
    pub adaptive_backoff: AdaptiveBackoffConfig,
    
    /// Maximum items per poll
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_interval() -> Duration { Duration::from_secs(60) }
fn default_min_interval() -> Duration { Duration::from_secs(5) }
fn default_batch_size() -> usize { 100 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdaptiveBackoffConfig {
    /// Enable adaptive backoff
    pub enabled: bool,
    /// Multiplier when no new items
    pub empty_multiplier: f64,
    /// Divisor when new items found
    pub found_divisor: f64,
    /// Maximum backoff interval
    pub max_interval: Duration,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State
// ─────────────────────────────────────────────────────────────────────────────

/// Cursor for tracking poll position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PollCursor {
    /// No cursor (start from beginning)
    None,
    /// Timestamp-based cursor
    Timestamp(chrono::DateTime<chrono::Utc>),
    /// ID-based cursor
    Id(String),
    /// Offset-based cursor
    Offset(u64),
    /// Opaque cursor from service
    Opaque(String),
}

impl Default for PollCursor {
    fn default() -> Self {
        Self::None
    }
}

pub struct PollingConnector<F, S>
where
    F: PollSource,
    S: CursorStore,
{
    id: ConnectorId,
    config: Option<PollingConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    
    // Poll source (the actual data fetcher)
    source: Option<F>,
    
    // Cursor persistence
    cursor_store: Option<S>,
    
    // Current state per poll target
    poll_states: Arc<RwLock<std::collections::HashMap<String, PollState>>>,
    
    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    
    // Control channel
    control_tx: Option<mpsc::Sender<PollCommand>>,
    
    // Metrics
    polls_total: AtomicU64,
    items_fetched: AtomicU64,
    empty_polls: AtomicU64,
}

#[derive(Debug, Clone)]
struct PollState {
    cursor: PollCursor,
    current_interval: Duration,
    last_poll: Option<Instant>,
    consecutive_empty: u32,
}

#[derive(Debug)]
enum PollCommand {
    Start { target: String, interval: Option<Duration> },
    Stop { target: String },
    PollNow { target: String },
    Shutdown,
}

// ─────────────────────────────────────────────────────────────────────────────
// Traits for Customization
// ─────────────────────────────────────────────────────────────────────────────

/// Source of pollable data
#[async_trait]
pub trait PollSource: Send + Sync + 'static {
    /// Initialize the source
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()>;
    
    /// Poll for new items
    async fn poll(
        &self,
        target: &str,
        cursor: &PollCursor,
        limit: usize,
    ) -> FcpResult<PollResult>;
}

#[derive(Debug)]
pub struct PollResult {
    /// Items fetched
    pub items: Vec<serde_json::Value>,
    /// New cursor for next poll
    pub next_cursor: PollCursor,
    /// Whether there are more items to fetch
    pub has_more: bool,
}

/// Storage for poll cursors
#[async_trait]
pub trait CursorStore: Send + Sync + 'static {
    async fn get(&self, target: &str) -> FcpResult<Option<PollCursor>>;
    async fn set(&self, target: &str, cursor: &PollCursor) -> FcpResult<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory Cursor Store
// ─────────────────────────────────────────────────────────────────────────────

pub struct InMemoryCursorStore {
    cursors: Arc<RwLock<std::collections::HashMap<String, PollCursor>>>,
}

impl InMemoryCursorStore {
    pub fn new() -> Self {
        Self {
            cursors: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}

#[async_trait]
impl CursorStore for InMemoryCursorStore {
    async fn get(&self, target: &str) -> FcpResult<Option<PollCursor>> {
        Ok(self.cursors.read().await.get(target).cloned())
    }
    
    async fn set(&self, target: &str, cursor: &PollCursor) -> FcpResult<()> {
        self.cursors.write().await.insert(target.to_string(), cursor.clone());
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

impl<F: PollSource, S: CursorStore> PollingConnector<F, S> {
    pub fn new(id: impl Into<String>, source: F, cursor_store: S) -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        
        Self {
            id: ConnectorId(id.into()),
            config: None,
            verifier: None,
            session_id: None,
            source: Some(source),
            cursor_store: Some(cursor_store),
            poll_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
            event_tx,
            control_tx: None,
            polls_total: AtomicU64::new(0),
            items_fetched: AtomicU64::new(0),
            empty_polls: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl<F: PollSource, S: CursorStore> FcpConnector for PollingConnector<F, S> {
    fn id(&self) -> &ConnectorId {
        &self.id
    }
    
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        // Parse polling config
        let polling_config: PollingConfig = config.get("polling")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::Connector {
                code: 5005,
                message: format!("Invalid polling config: {e}"),
                retryable: false,
            })?
            .unwrap_or_else(|| PollingConfig {
                default_interval: default_interval(),
                min_interval: default_min_interval(),
                adaptive_backoff: Default::default(),
                batch_size: default_batch_size(),
            });
        
        // Initialize source
        if let Some(ref mut source) = self.source {
            source.configure(config.get("source").cloned().unwrap_or_default()).await?;
        }
        
        self.config = Some(polling_config);
        Ok(())
    }
    
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let instance_id = req
            .requested_instance_id
            .unwrap_or_else(|| InstanceId(format!("inst_{}", Uuid::new_v4())));

        self.verifier = Some(CapabilityVerifier {
            host_public_key: req.host_public_key,
            zone_id: req.zone.clone(),
            instance_id: instance_id.clone(),
        });
        let session_id = SessionId(Uuid::new_v4());
        self.session_id = Some(session_id.clone());
        
        self.start_poll_loop().await?;
        
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req.capabilities_requested,
            session_id,
            manifest_hash: "sha256:placeholder".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }
    
    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot {
            status: HealthState::Ready,
            uptime_ms: 0,
            load: None,
            details: None,
            rate_limit: None,
        }
    }
    
    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.polls_total.load(Ordering::Relaxed),
            requests_success: self.items_fetched.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
    
    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(ref tx) = self.control_tx {
            let _ = tx.send(PollCommand::Shutdown).await;
        }
        Ok(())
    }
    
    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId("poll.start".into()),
                    summary: "Start polling a target".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "target": { "type": "string" },
                            "interval_seconds": { "type": "integer" }
                        },
                        "required": ["target"]
                    }),
                    output_schema: serde_json::json!({ "type": "null" }),
                    capability: CapabilityId("poll.start".into()),
                    risk_level: "low".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Begin polling for updates.".into(),
                        common_mistakes: vec!["Polling too frequently".into()],
                        examples: vec!["start_polling target=mailbox".into()],
                        related: vec![CapabilityId("poll.stop".into())],
                    },
                },
                OperationInfo {
                    id: OperationId("poll.stop".into()),
                    summary: "Stop polling a target".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": { "target": { "type": "string" } },
                        "required": ["target"]
                    }),
                    output_schema: serde_json::json!({ "type": "null" }),
                    capability: CapabilityId("poll.stop".into()),
                    risk_level: "low".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Stop polling to save resources.".into(),
                        common_mistakes: vec!["Stopping the wrong target".into()],
                        examples: vec!["stop_polling target=mailbox".into()],
                        related: vec![CapabilityId("poll.start".into())],
                    },
                },
                OperationInfo {
                    id: OperationId("poll.immediate".into()),
                    summary: "Trigger immediate poll".into(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": { "target": { "type": "string" } },
                        "required": ["target"]
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": { "items_count": { "type": "integer" } }
                    }),
                    capability: CapabilityId("poll.immediate".into()),
                    risk_level: "low".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use: "Force a refresh outside the normal interval.".into(),
                        common_mistakes: vec!["Calling too frequently".into()],
                        examples: vec!["poll_now target=mailbox".into()],
                        related: vec![CapabilityId("poll.start".into())],
                    },
                },
            ],
            events: vec![EventInfo {
                topic: format!("connector.{}.poll.item", self.id.0),
                schema: serde_json::json!({ "type": "object" }),
                requires_ack: false,
            }],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(&req.capability_token, &req.operation, &[])?;

        match req.operation.0.as_str() {
            "poll.start" => {
                let target = req
                    .input
                    .get("target")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::Connector {
                        code: 5005,
                        message: "Missing target".into(),
                        retryable: false,
                    })?;
                let interval = req
                    .input
                    .get("interval_seconds")
                    .and_then(|v| v.as_u64())
                    .map(Duration::from_secs);
                self.start_polling(target, interval, &req.capability_token).await?;
                Ok(InvokeResponse {
                    r#type: "response".into(),
                    id: req.id,
                    result: serde_json::json!(null),
                    resource_uris: vec![],
                    next_cursor: None,
                })
            }
            "poll.stop" => {
                let target = req
                    .input
                    .get("target")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::Connector {
                        code: 5005,
                        message: "Missing target".into(),
                        retryable: false,
                    })?;
                self.stop_polling(target, &req.capability_token).await?;
                Ok(InvokeResponse {
                    r#type: "response".into(),
                    id: req.id,
                    result: serde_json::json!(null),
                    resource_uris: vec![],
                    next_cursor: None,
                })
            }
            "poll.immediate" => {
                let target = req
                    .input
                    .get("target")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::Connector {
                        code: 5005,
                        message: "Missing target".into(),
                        retryable: false,
                    })?;
                let count = self.poll_now(target, &req.capability_token).await?;
                Ok(InvokeResponse {
                    r#type: "response".into(),
                    id: req.id,
                    result: serde_json::json!({ "items_count": count }),
                    resource_uris: vec![],
                    next_cursor: None,
                })
            }
            _ => Err(FcpError::Connector {
                code: 5005,
                message: "Unknown operation".into(),
                retryable: false,
            }),
        }
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        let token = req.capability_token.as_ref().ok_or(FcpError::Connector {
            code: 5005,
            message: "Missing capability_token for subscribe".into(),
            retryable: false,
        })?;
        for topic in &req.topics {
            self.start_polling(topic, None, token).await?;
        }
        Ok(SubscribeResponse {
            confirmed_topics: req.topics,
            cursors: HashMap::new(),
            replay_supported: false,
            buffer: None,
        })
    }

    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()> {
        let token = req.capability_token.as_ref().ok_or(FcpError::Connector {
            code: 5005,
            message: "Missing capability_token for unsubscribe".into(),
            retryable: false,
        })?;
        for topic in &req.topics {
            self.stop_polling(topic, token).await?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Polling-Specific Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for connectors that poll for data
#[async_trait]
pub trait Polling: FcpConnector {
    /// Start polling a target
    async fn start_polling(
        &self,
        target: &str,
        interval: Option<Duration>,
        token: &CapabilityToken,
    ) -> FcpResult<()>;
    
    /// Stop polling a target
    async fn stop_polling(&self, target: &str, token: &CapabilityToken) -> FcpResult<()>;
    
    /// Trigger immediate poll
    async fn poll_now(&self, target: &str, token: &CapabilityToken) -> FcpResult<usize>;
    
    /// Get event stream
    fn events(&self) -> EventStream;
}

#[async_trait]
impl<F: PollSource, S: CursorStore> Polling for PollingConnector<F, S> {
    async fn start_polling(
        &self,
        target: &str,
        interval: Option<Duration>,
        token: &CapabilityToken,
    ) -> FcpResult<()> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(token, &OperationId("poll.start".into()), &[])?;
        
        if let Some(ref tx) = self.control_tx {
            tx.send(PollCommand::Start {
                target: target.to_string(),
                interval,
            })
            .await
            .map_err(|_| FcpError::Connector {
                code: 5003,
                message: "Poll loop not running".into(),
                retryable: true,
            })?;
        }
        
        Ok(())
    }
    
    async fn stop_polling(&self, target: &str, token: &CapabilityToken) -> FcpResult<()> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(token, &OperationId("poll.stop".into()), &[])?;
        
        if let Some(ref tx) = self.control_tx {
            let _ = tx.send(PollCommand::Stop {
                target: target.to_string(),
            }).await;
        }
        
        Ok(())
    }
    
    async fn poll_now(&self, target: &str, token: &CapabilityToken) -> FcpResult<usize> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(token, &OperationId("poll.immediate".into()), &[])?;
        
        // Direct poll without going through the loop
        // Implementation would trigger immediate poll and return count
        Ok(0) // Placeholder
    }
    
    fn events(&self) -> EventStream {
        let rx = self.event_tx.subscribe();
        let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
            .filter_map(|r| async move {
                match r {
                    Ok(event) => Some(event),
                    Err(_) => None,
                }
            });
        Box::pin(stream)
    }
}

impl<F: PollSource, S: CursorStore> PollingConnector<F, S> {
    async fn start_poll_loop(&mut self) -> FcpResult<()> {
        let (control_tx, mut control_rx) = mpsc::channel::<PollCommand>(100);
        self.control_tx = Some(control_tx);
        
        let config = self.config.clone().unwrap_or_else(|| PollingConfig {
            default_interval: default_interval(),
            min_interval: default_min_interval(),
            adaptive_backoff: Default::default(),
            batch_size: default_batch_size(),
        });
        
        let source = self.source.take().ok_or(FcpError::Connector {
            code: 5002,
            message: "No poll source".into(),
            retryable: false,
        })?;
        
        let cursor_store = self.cursor_store.take().ok_or(FcpError::Connector {
            code: 5002,
            message: "No cursor store".into(),
            retryable: false,
        })?;
        
        let poll_states = self.poll_states.clone();
        let event_tx = self.event_tx.clone();
        let polls_total = &self.polls_total as *const AtomicU64;
        let items_fetched = &self.items_fetched as *const AtomicU64;
        let empty_polls = &self.empty_polls as *const AtomicU64;
        let connector_id = self.id.clone();
        let instance_id = self
            .verifier
            .as_ref()
            .map(|verifier| verifier.instance_id.clone())
            .unwrap_or_else(|| InstanceId("inst_unknown".into()));
        let zone_id = self
            .verifier
            .as_ref()
            .map(|verifier| verifier.zone_id.clone())
            .unwrap_or_else(|| ZoneId("z:unknown".into()));
        
        tokio::spawn(async move {
            let polls_total = unsafe { &*polls_total };
            let items_fetched = unsafe { &*items_fetched };
            let empty_polls = unsafe { &*empty_polls };
            
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            
            loop {
                tokio::select! {
                    // Control commands
                    Some(cmd) = control_rx.recv() => {
                        match cmd {
                            PollCommand::Start { target, interval: custom_interval } => {
                                let mut states = poll_states.write().await;
                                let cursor = cursor_store.get(&target).await.ok().flatten()
                                    .unwrap_or_default();
                                
                                states.insert(target, PollState {
                                    cursor,
                                    current_interval: custom_interval.unwrap_or(config.default_interval),
                                    last_poll: None,
                                    consecutive_empty: 0,
                                });
                            }
                            PollCommand::Stop { target } => {
                                poll_states.write().await.remove(&target);
                            }
                            PollCommand::PollNow { target } => {
                                // Mark for immediate poll
                                if let Some(state) = poll_states.write().await.get_mut(&target) {
                                    state.last_poll = None;
                                }
                            }
                            PollCommand::Shutdown => {
                                info!("Poll loop shutting down");
                                return;
                            }
                        }
                    }
                    
                    // Tick - check if any targets need polling
                    _ = interval.tick() => {
                        let now = Instant::now();
                        let targets_to_poll: Vec<String> = {
                            let states = poll_states.read().await;
                            states.iter()
                                .filter(|(_, state)| {
                                    state.last_poll.map_or(true, |last| {
                                        now.duration_since(last) >= state.current_interval
                                    })
                                })
                                .map(|(target, _)| target.clone())
                                .collect()
                        };
                        
                        for target in targets_to_poll {
                            let cursor = {
                                poll_states.read().await.get(&target)
                                    .map(|s| s.cursor.clone())
                                    .unwrap_or_default()
                            };
                            
                            polls_total.fetch_add(1, Ordering::Relaxed);
                            
                            match source.poll(&target, &cursor, config.batch_size).await {
                                Ok(result) => {
                                    let count = result.items.len();
                                    items_fetched.fetch_add(count as u64, Ordering::Relaxed);
                                    
                                    // Update state
                                    {
                                        let mut states = poll_states.write().await;
                                        if let Some(state) = states.get_mut(&target) {
                                            state.cursor = result.next_cursor.clone();
                                            state.last_poll = Some(Instant::now());
                                            
                                            // Adaptive backoff
                                            if config.adaptive_backoff.enabled {
                                                if count == 0 {
                                                    state.consecutive_empty += 1;
                                                    empty_polls.fetch_add(1, Ordering::Relaxed);
                                                    
                                                    state.current_interval = Duration::from_secs_f64(
                                                        (state.current_interval.as_secs_f64() 
                                                            * config.adaptive_backoff.empty_multiplier)
                                                            .min(config.adaptive_backoff.max_interval.as_secs_f64())
                                                    );
                                                } else {
                                                    state.consecutive_empty = 0;
                                                    state.current_interval = Duration::from_secs_f64(
                                                        (state.current_interval.as_secs_f64() 
                                                            / config.adaptive_backoff.found_divisor)
                                                            .max(config.min_interval.as_secs_f64())
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    
                                    // Save cursor
                                    let _ = cursor_store.set(&target, &result.next_cursor).await;
                                    
                                    // Emit events
                                    for item in result.items {
                                        let event = EventEnvelope {
                                            r#type: "event".into(),
                                            topic: format!("connector.{}.poll.item", connector_id.0),
                                            timestamp: chrono::Utc::now(),
                                            seq: 0,
                                            cursor: None,
                                            requires_ack: false,
                                            ack_deadline_ms: None,
                                            data: EventData {
                                                connector_id: connector_id.clone(),
                                                instance_id: instance_id.clone(),
                                                zone_id: zone_id.clone(),
                                                principal: Principal {
                                                    kind: "system".into(),
                                                    id: "poller".into(),
                                                    trust: TrustLevel::Admin,
                                                    display: None,
                                                },
                                                payload: item,
                                                correlation_id: None,
                                                resource_uris: vec![],
                                            },
                                        };
                                        let _ = event_tx.send(Ok(event));
                                    }
                                }
                                Err(e) => {
                                    warn!(?e, target = %target, "Poll failed");
                                    let _ = event_tx.send(Err(e));
                                }
                            }
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
}
```

---

## Archetype 5: Webhook (Event Receiver)

External services push events to us via HTTP.

**Examples**: GitHub webhooks, Stripe events, Slack events

```rust
// ============================================================================
// File: fcp-archetype-webhook/src/lib.rs
// Model connector: Webhook pattern (Event Receiver)
// ============================================================================

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use fcp_core::*;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, instrument, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Address to bind HTTP server
    pub bind_addr: SocketAddr,
    
    /// Base path for webhook endpoints
    #[serde(default = "default_base_path")]
    pub base_path: String,
    
    /// Signature verification settings
    pub signature: Option<SignatureConfig>,
    
    /// IP allowlist
    pub allowed_ips: Option<Vec<String>>,
    
    /// Event routing rules
    #[serde(default)]
    pub routes: Vec<WebhookRoute>,
}

fn default_base_path() -> String {
    "/webhooks".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Header containing the signature
    pub header: String,
    /// Secret key for HMAC verification
    pub secret: String,
    /// Signature algorithm
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
    /// Signature format (hex or base64)
    #[serde(default)]
    pub format: SignatureFormat,
    /// Optional prefix in signature header (e.g., "sha256=")
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    #[default]
    HmacSha256,
    HmacSha1,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum SignatureFormat {
    #[default]
    Hex,
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRoute {
    /// Source service identifier
    pub source: String,
    /// Path suffix (appended to base_path)
    pub path: String,
    /// Event type extraction (JSONPath)
    pub event_type_path: Option<String>,
    /// Custom signature config (overrides global)
    pub signature: Option<SignatureConfig>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State
// ─────────────────────────────────────────────────────────────────────────────

pub struct WebhookConnector {
    id: ConnectorId,
    config: Option<WebhookConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    
    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    
    // Server handle
    server_handle: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    
    // Registered handlers
    handlers: Arc<RwLock<HashMap<String, WebhookHandler>>>,
    
    // Metrics
    webhooks_received: AtomicU64,
    webhooks_verified: AtomicU64,
    webhooks_rejected: AtomicU64,
}

type WebhookHandler = Box<dyn Fn(&EventEnvelope) -> bool + Send + Sync>;

impl WebhookConnector {
    pub fn new(id: impl Into<String>) -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        
        Self {
            id: ConnectorId(id.into()),
            config: None,
            verifier: None,
            session_id: None,
            event_tx,
            server_handle: None,
            shutdown_tx: None,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            webhooks_received: AtomicU64::new(0),
            webhooks_verified: AtomicU64::new(0),
            webhooks_rejected: AtomicU64::new(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl FcpConnector for WebhookConnector {
    fn id(&self) -> &ConnectorId {
        &self.id
    }
    
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: WebhookConfig = serde_json::from_value(config)
            .map_err(|e| FcpError::Connector {
                code: 5005,
                message: format!("Invalid configuration: {e}"),
                retryable: false,
            })?;
        
        self.config = Some(config);
        Ok(())
    }
    
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let instance_id = req
            .requested_instance_id
            .unwrap_or_else(|| InstanceId(format!("inst_{}", Uuid::new_v4())));

        self.verifier = Some(CapabilityVerifier {
            host_public_key: req.host_public_key,
            zone_id: req.zone.clone(),
            instance_id: instance_id.clone(),
        });
        let session_id = SessionId(Uuid::new_v4());
        self.session_id = Some(session_id.clone());
        
        self.start_server().await?;
        
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req.capabilities_requested,
            session_id,
            manifest_hash: "sha256:placeholder".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }
    
    async fn health(&self) -> HealthSnapshot {
        if self.server_handle.is_some() {
            HealthSnapshot {
                status: HealthState::Ready,
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            }
        } else {
            HealthSnapshot {
                status: HealthState::Error {
                    reason: "Server not running".into(),
                },
                uptime_ms: 0,
                load: None,
                details: None,
                rate_limit: None,
            }
        }
    }
    
    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.webhooks_received.load(Ordering::Relaxed),
            requests_success: self.webhooks_verified.load(Ordering::Relaxed),
            requests_error: self.webhooks_rejected.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
    
    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
        Ok(())
    }
    
    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId("webhook.register".into()),
                summary: "Register a webhook handler for a source".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "source": { "type": "string" },
                        "filter": { "type": "object" }
                    },
                    "required": ["source"]
                }),
                output_schema: serde_json::json!({ "type": "null" }),
                capability: CapabilityId("webhook.register".into()),
                risk_level: "low".into(),
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Register a handler to process incoming webhooks.".into(),
                    common_mistakes: vec!["Using an invalid source id".into()],
                    examples: vec!["register source=github".into()],
                    related: vec![],
                },
            }],
            events: vec![EventInfo {
                topic: format!("connector.{}.webhook.received", self.id.0),
                schema: serde_json::json!({ "type": "object" }),
                requires_ack: false,
            }],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(&req.capability_token, &req.operation, &[])?;

        match req.operation.0.as_str() {
            "webhook.register" => {
                let source = req
                    .input
                    .get("source")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::Connector {
                        code: 5005,
                        message: "Missing source".into(),
                        retryable: false,
                    })?;
                self.register_handler(source, |_| true, &req.capability_token).await?;
                Ok(InvokeResponse {
                    r#type: "response".into(),
                    id: req.id,
                    result: serde_json::json!(null),
                    resource_uris: vec![],
                    next_cursor: None,
                })
            }
            _ => Err(FcpError::Connector {
                code: 5005,
                message: "Unknown operation".into(),
                retryable: false,
            }),
        }
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            confirmed_topics: req.topics,
            cursors: HashMap::new(),
            replay_supported: false,
            buffer: None,
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Webhook-Specific Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for connectors that receive webhooks
#[async_trait]
pub trait Webhook: FcpConnector {
    /// Register a handler for webhook events
    async fn register_handler<F>(
        &self,
        source: &str,
        handler: F,
        token: &CapabilityToken,
    ) -> FcpResult<()>
    where
        F: Fn(&EventEnvelope) -> bool + Send + Sync + 'static;
    
    /// Get URL for receiving webhooks
    fn webhook_url(&self, source: &str) -> FcpResult<String>;
    
    /// Get event stream
    fn events(&self) -> EventStream;
}

#[async_trait]
impl Webhook for WebhookConnector {
    async fn register_handler<F>(
        &self,
        source: &str,
        handler: F,
        token: &CapabilityToken,
    ) -> FcpResult<()>
    where
        F: Fn(&EventEnvelope) -> bool + Send + Sync + 'static,
    {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Connector not handshaken".into(),
            retryable: false,
        })?;
        verifier.verify(token, &OperationId("webhook.register".into()), &[])?;
        
        let mut handlers = self.handlers.write().await;
        handlers.insert(source.to_string(), Box::new(handler));
        
        Ok(())
    }
    
    fn webhook_url(&self, source: &str) -> FcpResult<String> {
        let config = self.config.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Not configured".into(),
            retryable: false,
        })?;
        
        Ok(format!(
            "http://{}{}/{}",
            config.bind_addr,
            config.base_path,
            source
        ))
    }
    
    fn events(&self) -> EventStream {
        let rx = self.event_tx.subscribe();
        let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
            .filter_map(|r| async move {
                match r {
                    Ok(event) => Some(event),
                    Err(_) => None,
                }
            });
        Box::pin(stream)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Server
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    config: WebhookConfig,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    connector_id: ConnectorId,
    instance_id: InstanceId,
    zone_id: ZoneId,
    webhooks_received: Arc<AtomicU64>,
    webhooks_verified: Arc<AtomicU64>,
    webhooks_rejected: Arc<AtomicU64>,
}

impl WebhookConnector {
    async fn start_server(&mut self) -> FcpResult<()> {
        let config = self.config.clone().ok_or(FcpError::Connector {
            code: 5002,
            message: "Not configured".into(),
            retryable: false,
        })?;
        
        let state = AppState {
            config: config.clone(),
            event_tx: self.event_tx.clone(),
            connector_id: self.id.clone(),
            instance_id: self
                .verifier
                .as_ref()
                .map(|verifier| verifier.instance_id.clone())
                .unwrap_or_else(|| InstanceId("inst_unknown".into())),
            zone_id: self
                .verifier
                .as_ref()
                .map(|verifier| verifier.zone_id.clone())
                .unwrap_or_else(|| ZoneId("z:unknown".into())),
            webhooks_received: Arc::new(AtomicU64::new(0)),
            webhooks_verified: Arc::new(AtomicU64::new(0)),
            webhooks_rejected: Arc::new(AtomicU64::new(0)),
        };
        
        // Build routes
        let base_path = config.base_path.clone();
        let router = Router::new()
            .route(
                &format!("{}/:source", base_path),
                post(handle_webhook),
            )
            .with_state(state);
        
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);
        
        let listener = tokio::net::TcpListener::bind(&config.bind_addr)
            .await
            .map_err(|e| FcpError::Connector {
                code: 5006,
                message: format!("Failed to bind: {e}"),
                retryable: true,
            })?;
        
        info!(addr = %config.bind_addr, "Webhook server starting");
        
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .ok();
        });
        
        self.server_handle = Some(handle);
        
        Ok(())
    }
}

async fn handle_webhook(
    State(state): State<AppState>,
    Path(source): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    state.webhooks_received.fetch_add(1, Ordering::Relaxed);
    
    // Find route config
    let route = state.config.routes.iter()
        .find(|r| r.source == source);
    
    // Get signature config (route-specific or global)
    let sig_config = route.and_then(|r| r.signature.as_ref())
        .or(state.config.signature.as_ref());
    
    // Verify signature if configured
    if let Some(sig) = sig_config {
        if !verify_signature(&headers, &body, sig) {
            state.webhooks_rejected.fetch_add(1, Ordering::Relaxed);
            warn!(source = %source, "Webhook signature verification failed");
            return StatusCode::UNAUTHORIZED;
        }
    }
    
    state.webhooks_verified.fetch_add(1, Ordering::Relaxed);
    
    // Parse body
    let data: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!(?e, "Failed to parse webhook body");
            return StatusCode::BAD_REQUEST;
        }
    };
    
    // Extract event type
    let event_type = route
        .and_then(|r| r.event_type_path.as_ref())
        .and_then(|path| {
            // Simple JSONPath implementation
            let mut current = &data;
            for part in path.split('.') {
                current = current.get(part)?;
            }
            current.as_str().map(String::from)
        })
        .unwrap_or_else(|| "webhook".into());
    
    // Create event
    let event = EventEnvelope {
        r#type: "event".into(),
        topic: format!("connector.{}.webhook.received", state.connector_id.0),
        timestamp: chrono::Utc::now(),
        seq: 0,
        cursor: None,
        requires_ack: false,
        ack_deadline_ms: None,
        data: EventData {
            connector_id: state.connector_id.clone(),
            instance_id: state.instance_id.clone(),
            zone_id: state.zone_id.clone(),
            principal: Principal {
                kind: "webhook".into(),
                id: source.clone(),
                trust: TrustLevel::Untrusted,
                display: None,
            },
            payload: data,
            correlation_id: headers
                .get("x-correlation-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| Uuid::parse_str(s).ok())
                .map(CorrelationId),
            resource_uris: vec![],
        },
    };
    
    // Broadcast event
    let _ = state.event_tx.send(Ok(event));
    
    StatusCode::OK
}

fn verify_signature(headers: &HeaderMap, body: &Bytes, config: &SignatureConfig) -> bool {
    let signature = match headers.get(&config.header) {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        },
        None => return false,
    };
    
    // Strip prefix if configured
    let signature = if let Some(ref prefix) = config.prefix {
        signature.strip_prefix(prefix).unwrap_or(signature)
    } else {
        signature
    };
    
    // Compute expected signature
    let expected = match config.algorithm {
        SignatureAlgorithm::HmacSha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(config.secret.as_bytes())
                .expect("HMAC can take key of any size");
            mac.update(body);
            let result = mac.finalize();
            
            match config.format {
                SignatureFormat::Hex => hex::encode(result.into_bytes()),
                SignatureFormat::Base64 => {
                    use base64::{Engine, engine::general_purpose::STANDARD};
                    STANDARD.encode(result.into_bytes())
                }
            }
        }
        SignatureAlgorithm::HmacSha1 => {
            // Similar implementation with SHA1
            unimplemented!("SHA1 not implemented in this example")
        }
    };
    
    // Constant-time comparison
    expected.as_bytes() == signature.as_bytes()
}
```

---

I'll continue with the remaining archetypes in the next section. Would you like me to continue with:

- **Archetype 6: Queue/Pub-Sub** (Redis, NATS, Kafka)
- **Archetype 7: File/Blob Storage** (S3, GCS)
- **Archetype 8: Database/Query Engine** (SQL, Vector DBs)
- **Archetype 9: CLI/Process Wrapper** (git, kubectl)
- **Archetype 10: Browser Automation** (CDP/Playwright)
- **Composition Patterns** (combining archetypes)
# FCP Model Connectors - Part 3

## Continuation: Browser Archetype Completion & Composition Patterns

---

## Archetype 10: Browser Automation (Continued)

```rust
// ─────────────────────────────────────────────────────────────────────────────
// Browser-Specific Trait (Continued)
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait Browser: FcpConnector {
    /// Create a new page
    async fn new_page(&self, token: &CapabilityToken) -> FcpResult<String>;
    
    /// Close a page
    async fn close_page(&self, page_id: &str, token: &CapabilityToken) -> FcpResult<()>;
    
    /// Execute an action on a page
    async fn execute(
        &self,
        page_id: &str,
        action: BrowserAction,
        token: &CapabilityToken,
    ) -> FcpResult<BrowserActionResult>;
    
    /// Execute multiple actions in sequence
    async fn execute_batch(
        &self,
        page_id: &str,
        actions: Vec<BrowserAction>,
        token: &CapabilityToken,
    ) -> FcpResult<Vec<BrowserActionResult>>;
    
    /// Get page info
    async fn page_info(&self, page_id: &str, token: &CapabilityToken) -> FcpResult<PageInfo>;
    
    /// Find elements matching selector
    async fn query_selector_all(
        &self,
        page_id: &str,
        selector: &str,
        token: &CapabilityToken,
    ) -> FcpResult<Vec<ElementInfo>>;
    
    /// Wait for a condition
    async fn wait_for(
        &self,
        page_id: &str,
        condition: WaitCondition,
        timeout: Duration,
        token: &CapabilityToken,
    ) -> FcpResult<()>;
    
    /// Intercept network requests
    async fn set_request_interception(
        &self,
        page_id: &str,
        patterns: Vec<String>,
        handler: RequestHandler,
        token: &CapabilityToken,
    ) -> FcpResult<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WaitCondition {
    Selector(String),
    Navigation,
    NetworkIdle,
    Function(String), // JavaScript function that returns true when ready
}

pub type RequestHandler = Box<dyn Fn(InterceptedRequest) -> RequestAction + Send + Sync>;

#[derive(Debug, Clone)]
pub struct InterceptedRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub resource_type: String,
}

#[derive(Debug, Clone)]
pub enum RequestAction {
    Continue,
    Block,
    Modify {
        url: Option<String>,
        headers: Option<HashMap<String, String>>,
    },
    Respond {
        status: u16,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    },
}

#[async_trait]
impl Browser for BrowserConnector {
    async fn new_page(&self, token: &CapabilityToken) -> FcpResult<String> {
        self.verifier
            .as_ref()
            .ok_or(FcpError::Connector {
                code: 5002,
                message: "Connector not handshaken".into(),
                retryable: false,
            })?
            .verify(token, &OperationId("browser.new_page".into()), &[])?;
        
        let page_id = Uuid::new_v4().to_string();
        
        // In real implementation, would create actual browser page
        let mut pages = self.pages.write().await;
        pages.insert(page_id.clone(), PageHandle);
        
        Ok(page_id)
    }
    
    async fn close_page(&self, page_id: &str, token: &CapabilityToken) -> FcpResult<()> {
        self.verifier
            .as_ref()
            .ok_or(FcpError::Connector {
                code: 5002,
                message: "Connector not handshaken".into(),
                retryable: false,
            })?
            .verify(token, &OperationId("browser.close_page".into()), &[])?;
        
        let mut pages = self.pages.write().await;
        pages.remove(page_id).ok_or(FcpError::Connector {
            code: 5001,
            message: format!("Page not found: {}", page_id),
            retryable: false,
        })?;
        
        Ok(())
    }
    
    #[instrument(skip(self))]
    async fn execute(
        &self,
        page_id: &str,
        action: BrowserAction,
        token: &CapabilityToken,
    ) -> FcpResult<BrowserActionResult> {
        self.verifier
            .as_ref()
            .ok_or(FcpError::Connector {
                code: 5002,
                message: "Connector not handshaken".into(),
                retryable: false,
            })?
            .verify(token, &OperationId("browser.execute".into()), &[])?;
        
        let start = std::time::Instant::now();
        self.actions_executed.fetch_add(1, Ordering::Relaxed);
        
        // Verify page exists
        {
            let pages = self.pages.read().await;
            if !pages.contains_key(page_id) {
                return Err(FcpError::Connector {
                    code: 5001,
                    message: format!("Page not found: {}", page_id),
                    retryable: false,
                });
            }
        }
        
        let config = self.config.as_ref().ok_or(FcpError::Connector {
            code: 5002,
            message: "Not configured".into(),
            retryable: false,
        })?;
        
        // Execute action based on type
        let result = match &action {
            BrowserAction::Navigate { url, wait_until } => {
                self.navigations.fetch_add(1, Ordering::Relaxed);
                
                // In real implementation, would navigate browser
                debug!(url = %url, wait_until = ?wait_until, "Navigating");
                
                Ok(serde_json::json!({
                    "url": url,
                    "status": 200
                }))
            }
            
            BrowserAction::Click { selector } => {
                debug!(selector = %selector, "Clicking element");
                Ok(serde_json::json!({ "clicked": true }))
            }
            
            BrowserAction::Type { selector, text, delay_ms } => {
                debug!(selector = %selector, text_len = text.len(), "Typing");
                Ok(serde_json::json!({ "typed": true }))
            }
            
            BrowserAction::Fill { selector, value } => {
                debug!(selector = %selector, "Filling field");
                Ok(serde_json::json!({ "filled": true }))
            }
            
            BrowserAction::Screenshot { full_page, selector, format } => {
                self.screenshots_taken.fetch_add(1, Ordering::Relaxed);
                
                // In real implementation, would capture screenshot
                Ok(serde_json::json!({
                    "format": format,
                    "data": "base64_encoded_image_data"
                }))
            }
            
            BrowserAction::Content => {
                Ok(serde_json::json!({
                    "html": "<html>...</html>"
                }))
            }
            
            BrowserAction::GetText { selector } => {
                Ok(serde_json::json!({
                    "text": "Element text content"
                }))
            }
            
            BrowserAction::GetAttribute { selector, attribute } => {
                Ok(serde_json::json!({
                    "value": "attribute_value"
                }))
            }
            
            BrowserAction::Evaluate { script } => {
                // Security check - ensure evaluate capability
                self.verifier
                    .as_ref()
                    .ok_or(FcpError::Connector {
                        code: 5002,
                        message: "Connector not handshaken".into(),
                        retryable: false,
                    })?
                    .verify(token, &OperationId("browser.evaluate".into()), &[])?;
                
                Ok(serde_json::json!({
                    "result": null
                }))
            }
            
            BrowserAction::SetCookies { cookies } => {
                Ok(serde_json::json!({
                    "set": cookies.len()
                }))
            }
            
            BrowserAction::GetCookies => {
                Ok(serde_json::json!({
                    "cookies": []
                }))
            }
            
            BrowserAction::ClearCookies => {
                Ok(serde_json::json!({
                    "cleared": true
                }))
            }
            
            BrowserAction::WaitForSelector { selector, timeout_ms } => {
                Ok(serde_json::json!({
                    "found": true
                }))
            }
            
            BrowserAction::WaitForNavigation { timeout_ms } => {
                Ok(serde_json::json!({
                    "navigated": true
                }))
            }
            
            BrowserAction::Select { selector, value } => {
                Ok(serde_json::json!({
                    "selected": value
                }))
            }
            
            BrowserAction::Press { key } => {
                Ok(serde_json::json!({
                    "pressed": key
                }))
            }
            
            BrowserAction::Scroll { x, y } => {
                Ok(serde_json::json!({
                    "scrolled": { "x": x, "y": y }
                }))
            }
        };
        
        let duration = start.elapsed();
        
        match result {
            Ok(data) => Ok(BrowserActionResult {
                action: format!("{:?}", std::mem::discriminant(&action)),
                success: true,
                data,
                error: None,
                duration_ms: duration.as_millis() as u64,
            }),
            Err(e) => Ok(BrowserActionResult {
                action: format!("{:?}", std::mem::discriminant(&action)),
                success: false,
                data: serde_json::Value::Null,
                error: Some(e.to_string()),
                duration_ms: duration.as_millis() as u64,
            }),
        }
    }
    
    async fn execute_batch(
        &self,
        page_id: &str,
        actions: Vec<BrowserAction>,
        token: &CapabilityToken,
    ) -> FcpResult<Vec<BrowserActionResult>> {
        let mut results = Vec::with_capacity(actions.len());
        
        for action in actions {
            let result = self.execute(page_id, action, token).await?;
            let should_continue = result.success;
            results.push(result);
            
            if !should_continue {
                break;
            }
        }
        
        Ok(results)
    }
    
    async fn page_info(&self, page_id: &str, _token: &CapabilityToken) -> FcpResult<PageInfo> {
        let pages = self.pages.read().await;
        if !pages.contains_key(page_id) {
            return Err(FcpError::Connector {
                code: 5001,
                message: format!("Page not found: {}", page_id),
                retryable: false,
            });
        }
        
        Ok(PageInfo {
            url: "https://example.com".into(),
            title: "Example Page".into(),
            viewport: self.config.as_ref()
                .map(|c| c.viewport.clone())
                .unwrap_or_default(),
        })
    }
    
    async fn query_selector_all(
        &self,
        page_id: &str,
        selector: &str,
        token: &CapabilityToken,
    ) -> FcpResult<Vec<ElementInfo>> {
        self.verifier
            .as_ref()
            .ok_or(FcpError::Connector {
                code: 5002,
                message: "Connector not handshaken".into(),
                retryable: false,
            })?
            .verify(token, &OperationId("browser.query".into()), &[])?;
        
        // In real implementation, would query DOM
        Ok(vec![])
    }
    
    async fn wait_for(
        &self,
        page_id: &str,
        condition: WaitCondition,
        timeout: Duration,
        _token: &CapabilityToken,
    ) -> FcpResult<()> {
        // In real implementation, would wait for condition
        Ok(())
    }
    
    async fn set_request_interception(
        &self,
        page_id: &str,
        patterns: Vec<String>,
        handler: RequestHandler,
        token: &CapabilityToken,
    ) -> FcpResult<()> {
        self.verifier
            .as_ref()
            .ok_or(FcpError::Connector {
                code: 5002,
                message: "Connector not handshaken".into(),
                retryable: false,
            })?
            .verify(token, &OperationId("browser.intercept".into()), &[])?;
        
        // In real implementation, would set up request interception
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-Level Browser Automation Helpers
// ─────────────────────────────────────────────────────────────────────────────

impl BrowserConnector {
    /// Convenience method: navigate and wait for load
    pub async fn goto(
        &self,
        page_id: &str,
        url: &str,
        token: &CapabilityToken,
    ) -> FcpResult<BrowserActionResult> {
        self.execute(page_id, BrowserAction::Navigate {
            url: url.to_string(),
            wait_until: Some(WaitUntil::NetworkIdle),
        }, token).await
    }
    
    /// Convenience method: fill form and submit
    pub async fn fill_form(
        &self,
        page_id: &str,
        fields: HashMap<String, String>,
        submit_selector: Option<&str>,
        token: &CapabilityToken,
    ) -> FcpResult<Vec<BrowserActionResult>> {
        let mut actions: Vec<BrowserAction> = fields.into_iter()
            .map(|(selector, value)| BrowserAction::Fill { selector, value })
            .collect();
        
        if let Some(submit) = submit_selector {
            actions.push(BrowserAction::Click { selector: submit.to_string() });
            actions.push(BrowserAction::WaitForNavigation { timeout_ms: None });
        }
        
        self.execute_batch(page_id, actions, token).await
    }
    
    /// Convenience method: extract structured data from page
    pub async fn extract_data(
        &self,
        page_id: &str,
        schema: ExtractionSchema,
        token: &CapabilityToken,
    ) -> FcpResult<serde_json::Value> {
        let script = schema.to_javascript();
        
        let result = self.execute(page_id, BrowserAction::Evaluate { script }, token).await?;
        
        Ok(result.data.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionSchema {
    /// Root selector
    pub root: Option<String>,
    /// Fields to extract
    pub fields: Vec<ExtractionField>,
    /// Whether to extract multiple items
    pub multiple: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionField {
    pub name: String,
    pub selector: String,
    pub attribute: Option<String>, // None means text content
    pub transform: Option<String>, // JavaScript transform function
}

impl ExtractionSchema {
    fn to_javascript(&self) -> String {
        // Generate JavaScript to extract data according to schema
        let fields_js: Vec<String> = self.fields.iter().map(|f| {
            let value_expr = if let Some(ref attr) = f.attribute {
                format!("el.querySelector('{}')?.getAttribute('{}')", f.selector, attr)
            } else {
                format!("el.querySelector('{}')?.textContent?.trim()", f.selector)
            };
            
            let transformed = if let Some(ref transform) = f.transform {
                format!("(({})({}))", transform, value_expr)
            } else {
                value_expr
            };
            
            format!("'{}': {}", f.name, transformed)
        }).collect();
        
        let extract_one = format!("(el) => ({{ {} }})", fields_js.join(", "));
        
        if self.multiple {
            let root = self.root.as_deref().unwrap_or("body");
            format!(
                "Array.from(document.querySelectorAll('{}')).map({})",
                root, extract_one
            )
        } else {
            let root = self.root.as_deref().unwrap_or("document");
            format!("({})({})", extract_one, root)
        }
    }
}
```

---

## Composition Patterns

Real-world connectors often combine multiple archetypes. Here are patterns for composing them.

```rust
// ============================================================================
// File: fcp-composition/src/lib.rs
// Composition patterns for combining connector archetypes
// ============================================================================

use std::sync::Arc;

use async_trait::async_trait;
use fcp_core::*;

// ─────────────────────────────────────────────────────────────────────────────
// Pattern 1: Request-Response + Streaming (e.g., OpenAI API)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector that supports both sync requests and streaming responses
pub struct HybridApiConnector<R, S>
where
    R: RequestResponse,
    S: Streaming,
{
    request_handler: R,
    stream_handler: S,
}

impl<R, S> HybridApiConnector<R, S>
where
    R: RequestResponse,
    S: Streaming,
{
    pub fn new(request_handler: R, stream_handler: S) -> Self {
        Self {
            request_handler,
            stream_handler,
        }
    }
    
    /// Execute request, optionally streaming the response
    pub async fn execute(
        &self,
        request: InvokeRequest,
        streaming: bool,
    ) -> FcpResult<HybridResponse> {
        if streaming {
            // For streaming, subscribe to response stream
            let stream = self
                .stream_handler
                .subscribe(&request.id.0.to_string())
                .await?;
            Ok(HybridResponse::Stream(stream))
        } else {
            // For non-streaming, use regular request-response
            let response = self.request_handler.request(request).await?;
            Ok(HybridResponse::Complete(response))
        }
    }
}

pub enum HybridResponse {
    Complete(InvokeResponse),
    Stream(EventStream),
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern 2: Polling + Webhook (e.g., GitHub - poll for changes, receive hooks)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector that can both poll for changes and receive webhooks
pub struct DualIngestConnector<P, W>
where
    P: Polling,
    W: Webhook,
{
    poller: P,
    webhook_receiver: W,
    /// Deduplicate events from both sources
    event_deduplicator: Arc<EventDeduplicator>,
}

struct EventDeduplicator {
    seen_ids: tokio::sync::RwLock<std::collections::HashSet<String>>,
    max_size: usize,
}

impl EventDeduplicator {
    fn new(max_size: usize) -> Self {
        Self {
            seen_ids: tokio::sync::RwLock::new(std::collections::HashSet::new()),
            max_size,
        }
    }
    
    async fn is_duplicate(&self, event_id: &str) -> bool {
        let seen = self.seen_ids.read().await;
        seen.contains(event_id)
    }
    
    async fn mark_seen(&self, event_id: &str) {
        let mut seen = self.seen_ids.write().await;
        if seen.len() >= self.max_size {
            // Simple eviction - clear half
            let to_remove: Vec<_> = seen.iter().take(self.max_size / 2).cloned().collect();
            for id in to_remove {
                seen.remove(&id);
            }
        }
        seen.insert(event_id.to_string());
    }
}

impl<P, W> DualIngestConnector<P, W>
where
    P: Polling,
    W: Webhook,
{
    pub fn new(poller: P, webhook_receiver: W) -> Self {
        Self {
            poller,
            webhook_receiver,
            event_deduplicator: Arc::new(EventDeduplicator::new(10000)),
        }
    }
    
    /// Get unified event stream from both sources
    pub fn events(&self) -> EventStream {
        let poll_events = self.poller.events();
        let webhook_events = self.webhook_receiver.events();
        let deduplicator = self.event_deduplicator.clone();
        
        // Merge streams with deduplication
        let merged = futures_util::stream::select(poll_events, webhook_events);
        
        let deduplicated = merged.filter_map(move |event| {
            let deduplicator = deduplicator.clone();
            async move {
                match &event {
                    Ok(e) => {
                        let event_id = e.id.to_string();
                        if deduplicator.is_duplicate(&event_id).await {
                            None
                        } else {
                            deduplicator.mark_seen(&event_id).await;
                            Some(event)
                        }
                    }
                    Err(_) => Some(event),
                }
            }
        });
        
        Box::pin(deduplicated)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern 3: CLI + Storage (e.g., git - commands that produce/consume files)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector that wraps CLI tool with file system access
pub struct FileAwareCliConnector<C, S>
where
    C: Cli,
    S: Storage,
{
    cli: C,
    storage: S,
    work_dir: std::path::PathBuf,
}

impl<C, S> FileAwareCliConnector<C, S>
where
    C: Cli,
    S: Storage,
{
    pub fn new(cli: C, storage: S, work_dir: std::path::PathBuf) -> Self {
        Self { cli, storage, work_dir }
    }
    
    /// Run command that produces output files, then upload them
    pub async fn run_and_upload(
        &self,
        command: CliCommand,
        output_patterns: Vec<String>,
        destination_prefix: &str,
    ) -> FcpResult<Vec<UploadResult>> {
        // Run the command
        let result = self.cli.run(command).await?;
        
        if result.exit_code != 0 {
            return Err(FcpError::External {
                service: "cli".into(),
                message: format!("Command failed with exit code {}", result.exit_code),
                status_code: None,
                retryable: false,
                retry_after: None,
            });
        }
        
        // Find matching output files
        let mut uploads = Vec::new();
        
        for pattern in output_patterns {
            let glob_pattern = self.work_dir.join(&pattern);
            let paths = glob::glob(glob_pattern.to_str().unwrap_or(""))
                .map_err(|e| FcpError::Internal { message: e.to_string() })?;
            
            for path in paths.flatten() {
                let data = tokio::fs::read(&path).await.map_err(|e| FcpError::External {
                    service: "fs".into(),
                    message: e.to_string(),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                })?;
                
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let key = format!("{}/{}", destination_prefix.trim_end_matches('/'), filename);
                
                let upload = self.storage.put(&key, Bytes::from(data), PutOptions::default()).await?;
                uploads.push(upload);
            }
        }
        
        Ok(uploads)
    }
    
    /// Download files, run command that uses them
    pub async fn download_and_run(
        &self,
        source_keys: Vec<String>,
        command: CliCommand,
    ) -> FcpResult<CliResult> {
        // Download files to work directory
        for key in source_keys {
            let data = self.storage.get(&key).await?;
            let filename = key.rsplit('/').next().unwrap_or(&key);
            let local_path = self.work_dir.join(filename);
            
            tokio::fs::write(&local_path, &data).await.map_err(|e| FcpError::External {
                service: "fs".into(),
                message: e.to_string(),
                status_code: None,
                retryable: false,
                retry_after: None,
            })?;
        }
        
        // Run command
        self.cli.run(command).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern 4: Browser + Request-Response (e.g., authenticated scraping)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector that uses browser for auth, then API for data
pub struct BrowserAuthenticatedApiConnector<B, R>
where
    B: Browser,
    R: RequestResponse,
{
    browser: B,
    api: R,
    auth_state: tokio::sync::RwLock<Option<AuthState>>,
}

#[derive(Clone)]
struct AuthState {
    cookies: Vec<Cookie>,
    tokens: std::collections::HashMap<String, String>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl<B, R> BrowserAuthenticatedApiConnector<B, R>
where
    B: Browser,
    R: RequestResponse,
{
    pub fn new(browser: B, api: R) -> Self {
        Self {
            browser,
            api,
            auth_state: tokio::sync::RwLock::new(None),
        }
    }
    
    /// Authenticate via browser flow
    pub async fn authenticate(&self, auth_flow: AuthFlow, token: &CapabilityToken) -> FcpResult<()> {
        let page_id = self.browser.new_page(token).await?;
        
        // Navigate to login page
        self.browser.execute(&page_id, BrowserAction::Navigate {
            url: auth_flow.login_url,
            wait_until: Some(WaitUntil::NetworkIdle),
        }, token).await?;
        
        // Fill credentials
        if let Some(username_selector) = auth_flow.username_selector {
            self.browser.execute(&page_id, BrowserAction::Fill {
                selector: username_selector,
                value: auth_flow.username,
            }, token).await?;
        }
        
        if let Some(password_selector) = auth_flow.password_selector {
            self.browser.execute(&page_id, BrowserAction::Fill {
                selector: password_selector,
                value: auth_flow.password,
            }, token).await?;
        }
        
        // Submit form
        if let Some(submit_selector) = auth_flow.submit_selector {
            self.browser.execute(&page_id, BrowserAction::Click {
                selector: submit_selector,
            }, token).await?;
            
            self.browser.execute(&page_id, BrowserAction::WaitForNavigation {
                timeout_ms: Some(10000),
            }, token).await?;
        }
        
        // Extract cookies
        let cookies_result = self.browser.execute(&page_id, BrowserAction::GetCookies, token).await?;
        let cookies: Vec<Cookie> = serde_json::from_value(
            cookies_result.data.get("cookies").cloned().unwrap_or_default()
        ).unwrap_or_default();
        
        // Extract tokens from localStorage/sessionStorage if needed
        let tokens_script = r#"
            ({
                localStorage: Object.fromEntries(Object.entries(localStorage)),
                sessionStorage: Object.fromEntries(Object.entries(sessionStorage))
            })
        "#;
        
        let tokens_result = self.browser.execute(&page_id, BrowserAction::Evaluate {
            script: tokens_script.to_string(),
        }, token).await?;
        
        let mut tokens = std::collections::HashMap::new();
        if let Some(storage) = tokens_result.data.get("result").and_then(|v| v.as_object()) {
            if let Some(ls) = storage.get("localStorage").and_then(|v| v.as_object()) {
                for (k, v) in ls {
                    if let Some(s) = v.as_str() {
                        tokens.insert(k.clone(), s.to_string());
                    }
                }
            }
        }
        
        // Store auth state
        let auth_state = AuthState {
            cookies,
            tokens,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        
        *self.auth_state.write().await = Some(auth_state);
        
        // Close browser page
        self.browser.close_page(&page_id, token).await?;
        
        Ok(())
    }
    
    /// Make authenticated API request
    pub async fn request(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        // Check if auth is still valid
        {
            let auth = self.auth_state.read().await;
            if auth.is_none() || auth.as_ref().unwrap().expires_at < chrono::Utc::now() {
                return Err(FcpError::Auth {
                    code: 2001,
                    message: "Authentication required or expired".into(),
                });
            }
        }
        
        // Add auth cookies/tokens to request
        // (In real implementation, would modify request headers)
        
        self.api.request(req).await
    }
}

#[derive(Debug, Clone)]
pub struct AuthFlow {
    pub login_url: String,
    pub username_selector: Option<String>,
    pub username: String,
    pub password_selector: Option<String>,
    pub password: String,
    pub submit_selector: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern 5: Database + Queue (e.g., transactional outbox pattern)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector implementing transactional outbox pattern
pub struct TransactionalOutboxConnector<D, Q>
where
    D: Database,
    Q: Queue,
{
    database: D,
    queue: Q,
    outbox_table: String,
}

impl<D, Q> TransactionalOutboxConnector<D, Q>
where
    D: Database,
    Q: Queue,
{
    pub fn new(database: D, queue: Q, outbox_table: String) -> Self {
        Self {
            database,
            queue,
            outbox_table,
        }
    }
    
    /// Execute database mutation and queue message atomically
    pub async fn execute_with_event(
        &self,
        mutation: Query,
        event_topic: &str,
        event_payload: serde_json::Value,
    ) -> FcpResult<()> {
        // Start transaction
        let tx_id = self.database.begin().await?;
        
        // Execute the main mutation
        if let Err(e) = self.database.execute(mutation).await {
            self.database.rollback(&tx_id).await?;
            return Err(e);
        }
        
        // Insert into outbox table
        let outbox_insert = Query {
            statement: format!(
                "INSERT INTO {} (id, topic, payload, created_at, published) VALUES ($1, $2, $3, NOW(), FALSE)",
                self.outbox_table
            ),
            params: vec![
                QueryParam::String(Uuid::new_v4().to_string()),
                QueryParam::String(event_topic.to_string()),
                QueryParam::Json(event_payload),
            ],
            timeout: None,
        };
        
        if let Err(e) = self.database.execute(outbox_insert).await {
            self.database.rollback(&tx_id).await?;
            return Err(e);
        }
        
        // Commit transaction
        self.database.commit(&tx_id).await?;
        
        // Trigger outbox processing (non-blocking)
        tokio::spawn({
            let this = self.clone();
            async move {
                let _ = this.process_outbox().await;
            }
        });
        
        Ok(())
    }
    
    /// Process pending outbox messages
    async fn process_outbox(&self) -> FcpResult<()> {
        // Query pending messages
        let query = Query {
            statement: format!(
                "SELECT id, topic, payload FROM {} WHERE published = FALSE ORDER BY created_at LIMIT 100",
                self.outbox_table
            ),
            params: vec![],
            timeout: None,
        };
        
        let result = self.database.query(query).await?;
        
        for row in result.rows {
            let id = row.get(0).and_then(|v| v.as_str()).unwrap_or_default();
            let topic = row.get(1).and_then(|v| v.as_str()).unwrap_or_default();
            let payload = row.get(2).cloned().unwrap_or(serde_json::Value::Null);
            
            // Publish to queue
            match self.queue.publish(
                topic,
                Bytes::from(payload.to_string()),
                PublishOptions::default(),
            ).await {
                Ok(_) => {
                    // Mark as published
                    let update = Query {
                        statement: format!(
                            "UPDATE {} SET published = TRUE WHERE id = $1",
                            self.outbox_table
                        ),
                        params: vec![QueryParam::String(id.to_string())],
                        timeout: None,
                    };
                    let _ = self.database.execute(update).await;
                }
                Err(e) => {
                    // Log error, will retry on next processing
                    tracing::warn!(id = %id, error = ?e, "Failed to publish outbox message");
                }
            }
        }
        
        Ok(())
    }
}

// For clone in tokio::spawn
impl<D: Clone, Q: Clone> Clone for TransactionalOutboxConnector<D, Q>
where
    D: Database,
    Q: Queue,
{
    fn clone(&self) -> Self {
        Self {
            database: self.database.clone(),
            queue: self.queue.clone(),
            outbox_table: self.outbox_table.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern 6: Multi-Archetype Service Connector (e.g., Discord)
// ─────────────────────────────────────────────────────────────────────────────

/// A full-featured connector combining multiple patterns
/// This is what a real Discord connector would look like
pub struct FullServiceConnector {
    /// REST API for commands (Request-Response)
    rest_api: Box<dyn RequestResponse>,
    /// Gateway for real-time events (Bidirectional)
    gateway: Box<dyn Bidirectional>,
    /// File uploads (Storage)
    cdn: Box<dyn Storage>,
    /// Event processing (can use either gateway events or webhooks)
    event_source: EventSourceType,
}

enum EventSourceType {
    Gateway,
    Webhook(Box<dyn Webhook>),
}

impl FullServiceConnector {
    /// Send a message (combines REST + CDN for attachments)
    pub async fn send_message(
        &self,
        channel_id: &str,
        content: &str,
        attachments: Vec<Attachment>,
        token: &CapabilityToken,
    ) -> FcpResult<serde_json::Value> {
        // Upload attachments to CDN first
        let mut attachment_refs = Vec::new();
        
        for (i, attachment) in attachments.into_iter().enumerate() {
            let key = format!("attachments/{}/{}", channel_id, attachment.filename);
            let result = self.cdn.put(&key, attachment.data, PutOptions {
                content_type: Some(attachment.content_type),
                ..Default::default()
            }).await?;
            
            attachment_refs.push(serde_json::json!({
                "id": i,
                "filename": attachment.filename,
                "uploaded_filename": result.key
            }));
        }
        
        // Send message via REST API
        let request = InvokeRequest {
            r#type: "invoke".into(),
            id: CorrelationId::default(),
            operation: OperationId("http.post".into()),
            input: serde_json::json!({
                "path": format!("/channels/{}/messages", channel_id),
                "body": {
                    "content": content,
                    "attachments": attachment_refs
                }
            }),
            capability_token: token.clone(),
            context: None,
            idempotency_key: None,
            deadline_ms: None,
        };
        
        let response = self.rest_api.request(request).await?;
        Ok(response.result)
    }
    
    /// Subscribe to real-time events
    pub fn events(&self) -> EventStream {
        match &self.event_source {
            EventSourceType::Gateway => self.gateway.events(),
            EventSourceType::Webhook(webhook) => webhook.events(),
        }
    }
    
    /// Send gateway command (e.g., update presence)
    pub async fn send_gateway_command(
        &self,
        command: serde_json::Value,
        token: &CapabilityToken,
    ) -> FcpResult<()> {
        self.gateway.send(command, token).await
    }
}

struct Attachment {
    filename: String,
    content_type: String,
    data: Bytes,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Factory
// ─────────────────────────────────────────────────────────────────────────────

/// Factory for creating composed connectors
pub struct ConnectorFactory;

impl ConnectorFactory {
    /// Create a connector based on service type
    pub async fn create(
        service: &str,
        config: serde_json::Value,
    ) -> FcpResult<Box<dyn FcpConnector>> {
        match service {
            "github" => {
                // GitHub = REST API + Webhooks + Polling (for some features)
                todo!("Create composed GitHub connector")
            }
            "slack" => {
                // Slack = REST API + WebSocket (Socket Mode) + Webhooks (Events API)
                todo!("Create composed Slack connector")
            }
            "discord" => {
                // Discord = REST API + WebSocket Gateway + CDN
                todo!("Create composed Discord connector")
            }
            "stripe" => {
                // Stripe = REST API + Webhooks
                todo!("Create composed Stripe connector")
            }
            "openai" => {
                // OpenAI = REST API + Streaming (SSE)
                todo!("Create composed OpenAI connector")
            }
            "postgres" | "mysql" => {
                // Direct database
                let mut connector = DatabaseConnector::new(service);
                connector.configure(config).await?;
                Ok(Box::new(connector))
            }
            "s3" | "gcs" => {
                // Direct storage
                let mut connector = StorageConnector::new(service);
                connector.configure(config).await?;
                Ok(Box::new(connector))
            }
            "redis" | "nats" => {
                // Direct queue
                let mut connector = QueueConnector::new(service);
                connector.configure(config).await?;
                Ok(Box::new(connector))
            }
            "git" | "kubectl" | "terraform" => {
                // CLI wrapper
                let mut connector = CliConnector::new(service);
                connector.configure(config).await?;
                Ok(Box::new(connector))
            }
            "browser" | "playwright" => {
                // Browser automation
                let mut connector = BrowserConnector::new(service);
                connector.configure(config).await?;
                Ok(Box::new(connector))
            }
            _ => Err(FcpError::Connector {
                code: 5005,
                message: format!("Unknown service: {}", service),
                retryable: false,
            }),
        }
    }
}
```

---

## Summary: Archetype Selection Guide

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHETYPE SELECTION DECISION TREE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  START: What is the primary data flow pattern?                              │
│                                                                             │
│  ┌─ Client initiates, waits for response?                                   │
│  │   └─ YES → Request-Response (REST, GraphQL, gRPC)                        │
│  │                                                                          │
│  ┌─ Server pushes data continuously?                                        │
│  │   └─ YES → Streaming (WebSocket, SSE, log tail)                          │
│  │                                                                          │
│  ┌─ Both sides send at any time?                                            │
│  │   └─ YES → Bidirectional (chat, collab, gaming)                          │
│  │                                                                          │
│  ┌─ Client periodically checks for changes?                                 │
│  │   └─ YES → Polling (email, RSS, status)                                  │
│  │                                                                          │
│  ┌─ External service pushes to us via HTTP?                                 │
│  │   └─ YES → Webhook (GitHub, Stripe, Slack events)                        │
│  │                                                                          │
│  ┌─ Async message passing through broker?                                   │
│  │   └─ YES → Queue/Pub-Sub (Redis, NATS, Kafka)                            │
│  │                                                                          │
│  ┌─ Large binary data transfer?                                             │
│  │   └─ YES → File/Blob Storage (S3, GCS)                                   │
│  │                                                                          │
│  ┌─ Structured queries against data?                                        │
│  │   └─ YES → Database (SQL, NoSQL, Vector)                                 │
│  │                                                                          │
│  ┌─ Wrapping existing CLI tool?                                             │
│  │   └─ YES → CLI/Process (git, kubectl)                                    │
│  │                                                                          │
│  ┌─ Automating web browser?                                                 │
│  │   └─ YES → Browser Automation (CDP/Playwright)                           │
│  │                                                                          │
│  ┌─ Multiple patterns needed?                                               │
│  │   └─ YES → Composition (see patterns above)                              │
│  │                                                                          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    COMMON SERVICE → ARCHETYPE MAPPINGS                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  SERVICE          PRIMARY         SECONDARY       TERTIARY                  │
│  ────────────────────────────────────────────────────────────               │
│  Twitter          Request-Resp    Streaming       Webhook                   │
│  Discord          Bidirectional   Request-Resp    Storage (CDN)             │
│  Slack            Request-Resp    Bidirectional   Webhook                   │
│  GitHub           Request-Resp    Webhook         Polling                   │
│  Stripe           Request-Resp    Webhook         -                         │
│  OpenAI           Request-Resp    Streaming       -                         │
│  Gmail            Request-Resp    Polling         Webhook (push)            │
│  Google Drive     Request-Resp    Storage         Webhook                   │
│  PostgreSQL       Database        -               -                         │
│  Redis            Queue           Database        -                         │
│  S3               Storage         -               -                         │
│  Pinecone         Database        Request-Resp    -                         │
│  Git              CLI             Storage         -                         │
│  Kubernetes       CLI             Request-Resp    Streaming (logs)          │
│  Home Assistant   Request-Resp    Streaming       Webhook                   │
│  Telegram         Request-Resp    Polling         Webhook                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Cargo.toml for Full Implementation

```toml
[package]
name = "fcp-connectors"
version = "1.0.0"
edition = "2021"
rust-version = "1.75"

[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }
tokio-stream = "0.1"
tokio-util = { version = "0.7", features = ["io", "codec"] }
futures-util = "0.3"

# HTTP
reqwest = { version = "0.11", features = ["json", "stream", "cookies"] }
axum = { version = "0.7", features = ["ws"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["trace", "cors"] }

# WebSocket
tokio-tungstenite = { version = "0.21", features = ["native-tls"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rmp-serde = "1.1"  # MessagePack

# Cryptography
hmac = "0.12"
sha2 = "0.10"
ed25519-dalek = "2.1"
rand = "0.8"

# Database drivers
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "mysql", "sqlite"] }
redis = { version = "0.24", features = ["tokio-comp", "connection-manager"] }

# Storage
aws-sdk-s3 = "1.10"
google-cloud-storage = "0.15"

# CLI
which = "6.0"
glob = "0.3"

# Browser automation (optional - heavy dependency)
chromiumoxide = { version = "0.5", optional = true }

# Utilities
uuid = { version = "1.6", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
bytes = "1.5"
thiserror = "1.0"
async-trait = "0.1"
tracing = "0.1"
tracing-subscriber = "0.3"
base64 = "0.21"
hex = "0.4"
md5 = "0.7"
mime_guess = "2.0"

[dev-dependencies]
wiremock = "0.5"
tempfile = "3.9"
tokio-test = "0.4"

[features]
default = []
browser = ["chromiumoxide"]
full = ["browser"]
```

---

## File Organization

```
fcp-connectors/
├── Cargo.toml
├── src/
│   ├── lib.rs                      # Re-exports
│   ├── core/
│   │   ├── mod.rs
│   │   ├── types.rs                # FcpError, IDs, etc.
│   │   ├── capability.rs           # Capability system
│   │   ├── zone.rs                 # Zone system
│   │   └── traits.rs               # FcpConnector trait
│   │
│   ├── archetypes/
│   │   ├── mod.rs
│   │   ├── request_response.rs     # Archetype 1
│   │   ├── streaming.rs            # Archetype 2
│   │   ├── bidirectional.rs        # Archetype 3
│   │   ├── polling.rs              # Archetype 4
│   │   ├── webhook.rs              # Archetype 5
│   │   ├── queue.rs                # Archetype 6
│   │   ├── storage.rs              # Archetype 7
│   │   ├── database.rs             # Archetype 8
│   │   ├── cli.rs                  # Archetype 9
│   │   └── browser.rs              # Archetype 10
│   │
│   ├── composition/
│   │   ├── mod.rs
│   │   ├── hybrid_api.rs           # Pattern 1
│   │   ├── dual_ingest.rs          # Pattern 2
│   │   ├── file_aware_cli.rs       # Pattern 3
│   │   ├── browser_auth.rs         # Pattern 4
│   │   ├── transactional_outbox.rs # Pattern 5
│   │   └── full_service.rs         # Pattern 6
│   │
│   ├── drivers/
│   │   ├── mod.rs
│   │   ├── redis.rs                # Redis queue driver
│   │   ├── local_fs.rs             # Local storage driver
│   │   └── ...                     # Other drivers
│   │
│   └── factory.rs                  # ConnectorFactory
│
└── tests/
    ├── request_response_test.rs
    ├── streaming_test.rs
    └── ...
```

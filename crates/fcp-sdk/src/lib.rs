//! FCP2 Connector SDK
//!
//! This crate provides the SDK for authoring FCP2-compliant connectors.
//! It re-exports key types from `fcp-core` and provides convenience utilities
//! to make implementing connectors easy and correct.
//!
//! # Quick Start
//!
//! ```ignore
//! use fcp_sdk::prelude::*;
//!
//! #[derive(Debug)]
//! struct MyConnector {
//!     base: BaseConnector,
//! }
//!
//! #[async_trait]
//! impl FcpConnector for MyConnector {
//!     fn id(&self) -> &ConnectorId {
//!         &self.base.id
//!     }
//!
//!     async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
//!         // Configure your connector
//!         self.base.set_configured(true);
//!         Ok(())
//!     }
//!
//!     // ... implement other methods
//! }
//! ```
//!
//! # Architecture
//!
//! The SDK is structured around:
//!
//! - **[`FcpConnector`]**: The core trait all connectors must implement
//! - **[`BaseConnector`]**: A base implementation with common functionality
//! - **[`FcpError`]**: Structured error types with recovery hints
//! - **Archetype traits**: [`Streaming`], [`Bidirectional`], [`Polling`], [`Webhook`]
//!
//! # Error Handling
//!
//! All errors use the FCP error taxonomy:
//!
//! | Code Range | Category |
//! |------------|----------|
//! | FCP-1xxx | Protocol errors |
//! | FCP-2xxx | Auth/Identity errors |
//! | FCP-3xxx | Capability errors |
//! | FCP-4xxx | Zone/Topology errors |
//! | FCP-5xxx | Connector errors |
//! | FCP-6xxx | Resource errors |
//! | FCP-7xxx | External service errors |
//! | FCP-9xxx | Internal errors |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ─────────────────────────────────────────────────────────────────────────────
// Re-exports from fcp-core
// ─────────────────────────────────────────────────────────────────────────────

/// Core connector trait and base implementation.
pub use fcp_core::{
    BaseConnector,
    Bidirectional,
    // Capability tokens
    CapabilityGrant,
    CapabilityToken,

    // Identifiers
    ConnectorId,
    ConnectorMetrics,
    CorrelationId,
    // Cost and availability
    CostEstimate,
    CurrencyCost,
    // Error types
    ErrorCategory,
    // Events
    EventAck,
    EventCaps,
    EventData,
    EventEnvelope,
    EventNack,
    EventStream,
    FcpConnector,
    FcpError,
    FcpErrorResponse,
    FcpResult,

    // Protocol messages
    HandshakeRequest,
    HandshakeResponse,
    // Health and metrics
    HealthSnapshot,
    HealthState,
    InstanceId,
    Introspection,
    InvokeContext,
    InvokeRequest,
    InvokeResponse,
    InvokeStatus,
    LivenessResponse,
    ObjectId,
    OperationId,
    Polling,
    Principal,
    // Provenance
    Provenance,
    ProvenanceStep,
    RateLimitStatus,
    ReadinessResponse,
    ReplayBufferInfo,
    RequestId,
    RequestResponse,
    ResourceAvailability,
    SessionId,
    ShutdownAck,
    ShutdownRequest,
    SimulateRequest,
    SimulateResponse,
    Streaming,
    SubscribeRequest,
    SubscribeResponse,
    SubscribeResult,
    TaintFlag,
    TaintLevel,
    // Observability
    TraceContext,
    TrustLevel,
    UnsubscribeRequest,
    Webhook,
    ZoneId,

    // Core connector infrastructure
    async_trait,
};

/// Re-exports from fcp-manifest for connector configuration.
pub use fcp_manifest::{
    ConnectorArchetype, ConnectorCrdtType, ConnectorRuntimeFormat, ConnectorStateModel,
};

// ─────────────────────────────────────────────────────────────────────────────
// SDK-specific modules
// ─────────────────────────────────────────────────────────────────────────────

pub mod prelude;

// ─────────────────────────────────────────────────────────────────────────────
// Re-export commonly used external crates
// ─────────────────────────────────────────────────────────────────────────────

pub use serde;
pub use serde_json;
pub use thiserror;
pub use tracing;

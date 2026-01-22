//! SDK Prelude - Import everything you need for connector development.
//!
//! # Usage
//!
//! ```ignore
//! use fcp_sdk::prelude::*;
//! ```
//!
//! This imports all commonly used types for implementing FCP connectors.

// Core traits
pub use crate::{
    BaseConnector, Bidirectional, FcpConnector, Polling, RequestResponse, Streaming, Webhook,
    async_trait,
};

// Error types
pub use crate::{FcpError, FcpResult};

// Protocol messages
pub use crate::{
    HandshakeRequest, HandshakeResponse, Introspection, InvokeContext, InvokeRequest,
    InvokeResponse, InvokeStatus, ShutdownAck, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};

// Cost and availability
pub use crate::{CostEstimate, CurrencyCost, ResourceAvailability};

// Events
pub use crate::{EventAck, EventCaps, EventData, EventEnvelope, EventNack, EventStream};

// Health
pub use crate::{ConnectorMetrics, HealthSnapshot, HealthState};

// Identifiers
pub use crate::{ConnectorId, InstanceId, ObjectId, RequestId, ZoneId};

// Capability tokens
pub use crate::CapabilityToken;

// Provenance
pub use crate::{Provenance, TaintFlag, TaintLevel, TrustLevel};

// Principal
pub use crate::Principal;

// Archetypes and state models
pub use crate::{
    ConnectorArchetype, ConnectorCrdtType, ConnectorRuntimeFormat, ConnectorStateModel,
};

// Streaming helpers
pub use crate::streaming::{
    AckResult, BufferLimits, EventStreamManager, NackResult, ReplayError, SubscribeOutcome,
};

// External crates commonly needed
pub use serde::{Deserialize, Serialize};
pub use serde_json::json;
pub use tracing::{debug, error, info, instrument, trace, warn};

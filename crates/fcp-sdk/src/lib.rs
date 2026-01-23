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
    RateLimitConfig,
    RateLimitDeclarations,
    RateLimitEnforcement,
    RateLimitPool,
    RateLimitScope,
    RateLimitStatus,
    RateLimitUnit,
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
pub mod streaming;

// ─────────────────────────────────────────────────────────────────────────────
// Schema validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// JSON Schema validation errors produced by the SDK.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SchemaValidationError {
    /// The provided schema is invalid and could not be compiled.
    #[error("invalid JSON Schema: {message}")]
    InvalidSchema {
        /// Human-readable error message.
        message: String,
    },

    /// The value failed schema validation.
    #[error("schema validation failed: {message}")]
    ValidationFailed {
        /// Human-readable summary message.
        message: String,
        /// Individual validation errors (formatted strings).
        errors: Vec<String>,
    },
}

/// Compiled JSON Schema validator for repeated use.
#[derive(Debug, Clone)]
pub struct SchemaValidator {
    validator: std::sync::Arc<jsonschema::Validator>,
}

impl SchemaValidator {
    /// Compile a JSON Schema into a reusable validator.
    ///
    /// # Errors
    /// Returns [`SchemaValidationError::InvalidSchema`] if the schema is invalid.
    pub fn compile(schema: &serde_json::Value) -> Result<Self, SchemaValidationError> {
        let validator = jsonschema::Validator::new(schema).map_err(|e| {
            SchemaValidationError::InvalidSchema {
                message: e.to_string(),
            }
        })?;
        Ok(Self {
            validator: std::sync::Arc::new(validator),
        })
    }

    /// Validate a JSON value against the compiled schema.
    ///
    /// # Errors
    /// Returns [`SchemaValidationError::ValidationFailed`] if validation fails.
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), SchemaValidationError> {
        match self.validator.validate(value) {
            Ok(()) => Ok(()),
            Err(errors) => {
                let details: Vec<String> = errors.map(|e| e.to_string()).collect();
                let message = details.join("; ");
                Err(SchemaValidationError::ValidationFailed {
                    message,
                    errors: details,
                })
            }
        }
    }
}

/// Compile and validate a JSON value against a JSON Schema in one step.
///
/// # Errors
/// Returns [`SchemaValidationError`] if the schema is invalid or validation fails.
pub fn validate_json_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), SchemaValidationError> {
    SchemaValidator::compile(schema)?.validate(value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-export commonly used external crates
// ─────────────────────────────────────────────────────────────────────────────

pub use serde;
pub use serde_json;
pub use thiserror;
pub use tracing;

#[cfg(test)]
mod tests {
    use super::{SchemaValidator, validate_json_schema};
    use serde_json::json;

    #[test]
    fn validate_schema_success_and_failure() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });

        let ok_value = json!({ "name": "fcp" });
        let bad_value = json!({});

        assert!(validate_json_schema(&schema, &ok_value).is_ok());
        assert!(validate_json_schema(&schema, &bad_value).is_err());

        let validator = SchemaValidator::compile(&schema).expect("schema compiles");
        assert!(validator.validate(&ok_value).is_ok());
        assert!(validator.validate(&bad_value).is_err());
    }
}

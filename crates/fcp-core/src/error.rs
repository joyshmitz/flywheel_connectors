//! FCP Error types and error response structures.
//!
//! Error codes follow the FCP specification:
//! - FCP-1xxx: Protocol errors
//! - FCP-2xxx: Auth/Identity errors
//! - FCP-3xxx: Capability errors
//! - FCP-4xxx: Zone/Topology/Provenance errors
//! - FCP-5xxx: Connector lifecycle/health errors
//! - FCP-6xxx: Resource errors
//! - FCP-7xxx: External service errors
//! - FCP-9xxx: Internal errors

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// FCP error type covering all error categories.
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "category")]
pub enum FcpError {
    // ─────────────────────────────────────────────────────────────────────────
    // Protocol errors (FCP-1xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Invalid request: {message}")]
    InvalidRequest {
        code: u16,
        message: String,
    },

    #[error("Malformed frame: {message}")]
    MalformedFrame {
        code: u16,
        message: String,
    },

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        expected: String,
        actual: String,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Auth errors (FCP-2xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Unauthorized: {message}")]
    Unauthorized {
        code: u16,
        message: String,
    },

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid signature")]
    InvalidSignature,

    // ─────────────────────────────────────────────────────────────────────────
    // Capability errors (FCP-3xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Capability denied: {capability}")]
    CapabilityDenied {
        capability: String,
        reason: String,
    },

    #[error("Rate limited: retry after {retry_after_ms}ms")]
    RateLimited {
        retry_after_ms: u64,
    },

    #[error("Operation not granted: {operation}")]
    OperationNotGranted {
        operation: String,
    },

    #[error("Resource not allowed: {resource}")]
    ResourceNotAllowed {
        resource: String,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Zone errors (FCP-4xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Zone violation: {message}")]
    ZoneViolation {
        source_zone: String,
        target_zone: String,
        message: String,
    },

    #[error("Taint violation: origin {origin_zone} cannot invoke {capability} in {target_zone}")]
    TaintViolation {
        origin_zone: String,
        target_zone: String,
        capability: String,
    },

    #[error("Elevation required for {capability}")]
    ElevationRequired {
        capability: String,
        ttl_seconds: Option<u32>,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Connector errors (FCP-5xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Connector unavailable: {message}")]
    ConnectorUnavailable {
        code: u16,
        message: String,
    },

    #[error("Connector not configured")]
    NotConfigured,

    #[error("Connector not handshaken")]
    NotHandshaken,

    #[error("Health check failed: {reason}")]
    HealthCheckFailed {
        reason: String,
    },

    #[error("Streaming not supported")]
    StreamingNotSupported,

    // ─────────────────────────────────────────────────────────────────────────
    // Resource errors (FCP-6xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Resource not found: {resource}")]
    ResourceNotFound {
        resource: String,
    },

    #[error("Resource exhausted: {resource}")]
    ResourceExhausted {
        resource: String,
    },

    #[error("Conflict: {message}")]
    Conflict {
        message: String,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // External service errors (FCP-7xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("External service error: {service} - {message}")]
    External {
        service: String,
        message: String,
        status_code: Option<u16>,
        retryable: bool,
        #[serde(with = "optional_duration_millis")]
        retry_after: Option<Duration>,
    },

    #[error("Upstream timeout: {service}")]
    UpstreamTimeout {
        service: String,
    },

    #[error("Dependency unavailable: {service}")]
    DependencyUnavailable {
        service: String,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // Internal errors (FCP-9xxx)
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Internal error: {message}")]
    Internal {
        message: String,
    },
}

mod optional_duration_millis {
    use std::time::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => serializer.serialize_some(&d.as_millis()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis: Option<u64> = Option::deserialize(deserializer)?;
        Ok(millis.map(Duration::from_millis))
    }
}

impl FcpError {
    /// Returns true if the error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::External { retryable, .. } => *retryable,
            Self::RateLimited { .. } => true,
            Self::ResourceExhausted { .. } => true,
            Self::UpstreamTimeout { .. } => true,
            Self::DependencyUnavailable { .. } => true,
            Self::ConnectorUnavailable { .. } => true,
            _ => false,
        }
    }

    /// Returns the suggested retry delay, if any.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::External { retry_after, .. } => *retry_after,
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to wire response format.
    #[must_use]
    pub fn to_response(&self) -> FcpErrorResponse {
        let (code, ai_hint) = match self {
            Self::InvalidRequest { code, .. } => (format!("FCP-{code:04}"), None),
            Self::MalformedFrame { code, .. } => (format!("FCP-{code:04}"), None),
            Self::ChecksumMismatch => ("FCP-1004".into(), None),
            Self::VersionMismatch { .. } => ("FCP-1005".into(), None),

            Self::Unauthorized { code, .. } => (format!("FCP-{code:04}"), None),
            Self::TokenExpired => ("FCP-2002".into(), Some("Request a new capability token.".into())),
            Self::InvalidSignature => ("FCP-2003".into(), None),

            Self::CapabilityDenied { .. } => ("FCP-3001".into(), None),
            Self::RateLimited { .. } => (
                "FCP-3002".into(),
                Some("Wait for the rate limit to reset before retrying.".into()),
            ),
            Self::OperationNotGranted { .. } => ("FCP-3003".into(), None),
            Self::ResourceNotAllowed { .. } => ("FCP-3004".into(), None),

            Self::ZoneViolation { .. } => ("FCP-4001".into(), None),
            Self::TaintViolation { .. } => (
                "FCP-4002".into(),
                Some("Request elevation or move the workflow to a trusted zone.".into()),
            ),
            Self::ElevationRequired { .. } => (
                "FCP-4003".into(),
                Some("Request owner approval for this action.".into()),
            ),

            Self::ConnectorUnavailable { code, .. } => (format!("FCP-{code:04}"), None),
            Self::NotConfigured => ("FCP-5002".into(), None),
            Self::NotHandshaken => ("FCP-5003".into(), None),
            Self::HealthCheckFailed { .. } => ("FCP-5004".into(), None),
            Self::StreamingNotSupported => ("FCP-5005".into(), None),

            Self::ResourceNotFound { .. } => ("FCP-6001".into(), None),
            Self::ResourceExhausted { .. } => ("FCP-6002".into(), None),
            Self::Conflict { .. } => ("FCP-6003".into(), None),

            Self::External { status_code, .. } => {
                let code = match status_code {
                    Some(429) => "FCP-7001",  // Rate limited
                    Some(504) => "FCP-7002",  // Timeout
                    _ => "FCP-7003",          // Dependency unavailable
                };
                (code.into(), None)
            }
            Self::UpstreamTimeout { .. } => ("FCP-7002".into(), None),
            Self::DependencyUnavailable { .. } => ("FCP-7003".into(), None),

            Self::Internal { .. } => ("FCP-9001".into(), None),
        };

        FcpErrorResponse {
            code,
            message: self.to_string(),
            retryable: self.is_retryable(),
            retry_after_ms: self.retry_after().map(|d| d.as_millis() as u64),
            details: self.details(),
            ai_recovery_hint: ai_hint,
        }
    }

    /// Extract structured details for the error.
    #[must_use]
    pub fn details(&self) -> Option<serde_json::Value> {
        match self {
            Self::CapabilityDenied { capability, reason } => Some(serde_json::json!({
                "capability": capability,
                "reason": reason,
            })),
            Self::ZoneViolation { source_zone, target_zone, .. } => Some(serde_json::json!({
                "source_zone": source_zone,
                "target_zone": target_zone,
            })),
            Self::TaintViolation { origin_zone, target_zone, capability } => Some(serde_json::json!({
                "origin_zone": origin_zone,
                "target_zone": target_zone,
                "capability": capability,
            })),
            Self::ElevationRequired { capability, ttl_seconds } => Some(serde_json::json!({
                "capability": capability,
                "ttl_seconds": ttl_seconds,
            })),
            Self::External { service, status_code, .. } => Some(serde_json::json!({
                "service": service,
                "status_code": status_code,
            })),
            _ => None,
        }
    }
}

/// Result type alias for FCP operations.
pub type FcpResult<T> = Result<T, FcpError>;

/// Wire format for error responses (matches FCP specification Section 16.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcpErrorResponse {
    /// Error code (e.g., "FCP-4002" or "FCP_FORBIDDEN")
    pub code: String,

    /// Human-readable message
    pub message: String,

    /// Whether retry might succeed
    pub retryable: bool,

    /// Suggested retry delay in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,

    /// Structured details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// Agent-friendly recovery hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_recovery_hint: Option<String>,
}

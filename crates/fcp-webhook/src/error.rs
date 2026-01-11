//! Webhook error types.

use std::time::Duration;

/// Webhook errors.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// Invalid signature.
    #[error("Invalid webhook signature")]
    InvalidSignature,

    /// Missing signature header.
    #[error("Missing signature header: {0}")]
    MissingSignature(String),

    /// Timestamp validation failed.
    #[error("Timestamp validation failed: {reason}")]
    TimestampValidation {
        /// Failure reason.
        reason: String,
        /// Actual timestamp.
        timestamp: Option<i64>,
        /// Current time.
        current_time: i64,
        /// Allowed tolerance.
        tolerance: Duration,
    },

    /// Replay detected (duplicate event).
    #[error("Replay detected: event {event_id} already processed")]
    ReplayDetected {
        /// Duplicate event ID.
        event_id: String,
    },

    /// Payload too large.
    #[error("Payload too large: {size} bytes exceeds limit of {limit}")]
    PayloadTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        limit: usize,
    },

    /// Invalid payload format.
    #[error("Invalid payload: {0}")]
    InvalidPayload(String),

    /// Unsupported event type.
    #[error("Unsupported event type: {0}")]
    UnsupportedEventType(String),

    /// Provider not configured.
    #[error("Provider not configured: {0}")]
    ProviderNotConfigured(String),

    /// IP not allowed.
    #[error("IP address not in allowlist: {0}")]
    IpNotAllowed(String),

    /// Delivery failed.
    #[error("Webhook delivery failed: {0}")]
    DeliveryFailed(String),

    /// JSON parsing error.
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Hex decoding error.
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
}

/// Result type for webhook operations.
pub type WebhookResult<T> = Result<T, WebhookError>;

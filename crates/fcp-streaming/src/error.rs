//! Streaming error types.

use std::time::Duration;

/// Streaming errors.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection closed unexpectedly.
    #[error("Connection closed: {reason}")]
    ConnectionClosed {
        /// Close reason.
        reason: String,
        /// Close code (for WebSocket).
        code: Option<u16>,
    },

    /// HTTP error.
    #[error("HTTP error: {status} - {message}")]
    HttpError {
        /// HTTP status code.
        status: u16,
        /// Error message.
        message: String,
    },

    /// Parse error.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Timeout.
    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    /// Reconnection limit exceeded.
    #[error("Reconnection limit exceeded after {attempts} attempts")]
    ReconnectLimitExceeded {
        /// Number of reconnection attempts.
        attempts: u32,
    },

    /// Buffer overflow.
    #[error("Buffer overflow: {size} bytes exceeds limit of {limit}")]
    BufferOverflow {
        /// Current size.
        size: usize,
        /// Maximum allowed size.
        limit: usize,
    },

    /// Invalid state.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// WebSocket error.
    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    /// SSE error.
    #[error("SSE error: {0}")]
    SseError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// HTTP client error.
    #[error("HTTP client error: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

/// Result type for streaming operations.
pub type StreamResult<T> = Result<T, StreamError>;

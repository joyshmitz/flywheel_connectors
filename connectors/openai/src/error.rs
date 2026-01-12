//! OpenAI error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result type for OpenAI operations.
pub type OpenAIResult<T> = Result<T, OpenAIError>;

/// OpenAI-specific errors.
#[derive(Debug, Error)]
pub enum OpenAIError {
    /// HTTP/network error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON parsing error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid API key
    #[error("Invalid API key")]
    InvalidApiKey,

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited {
        /// Suggested retry delay in milliseconds
        retry_after_ms: u64,
    },

    /// Server overloaded
    #[error("Server overloaded, retry after {retry_after_ms}ms")]
    Overloaded {
        /// Suggested retry delay in milliseconds
        retry_after_ms: u64,
    },

    /// Context length exceeded
    #[error("Context length exceeded: {message}")]
    ContextLengthExceeded {
        /// Error message
        message: String,
    },

    /// Content filter triggered
    #[error("Content filtered: {message}")]
    ContentFiltered {
        /// Error message
        message: String,
    },

    /// API error
    #[error("API error ({error_type}): {message}")]
    Api {
        /// Error type
        error_type: String,
        /// Error message
        message: String,
        /// HTTP status code
        status_code: Option<u16>,
    },

    /// Client not configured
    #[error("Client not configured")]
    NotConfigured,
}

impl OpenAIError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited { .. } | Self::Overloaded { .. })
    }

    /// Get retry-after duration if available.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } | Self::Overloaded { retry_after_ms } => {
                Some(Duration::from_millis(*retry_after_ms))
            }
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidApiKey => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid OpenAI API key".into(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
            },
            Self::ContextLengthExceeded { message } => FcpError::InvalidRequest {
                code: 2002,
                message: message.clone(),
            },
            Self::ContentFiltered { message } => FcpError::InvalidRequest {
                code: 2003,
                message: message.clone(),
            },
            Self::NotConfigured => FcpError::NotConfigured,
            Self::Api {
                message,
                status_code,
                ..
            } => FcpError::External {
                service: "openai".into(),
                message: message.clone(),
                status_code: *status_code,
                retryable: false,
                retry_after: None,
            },
            Self::Http(e) => FcpError::External {
                service: "openai".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: e.is_timeout() || e.is_connect(),
                retry_after: None,
            },
            Self::Json(e) => FcpError::MalformedFrame {
                code: 2004,
                message: format!("JSON parsing error: {e}"),
            },
            Self::Overloaded { retry_after_ms } => FcpError::External {
                service: "openai".into(),
                message: "Server is overloaded".into(),
                status_code: Some(503),
                retryable: true,
                retry_after: Some(Duration::from_millis(*retry_after_ms)),
            },
        }
    }
}

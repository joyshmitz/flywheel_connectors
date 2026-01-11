//! Anthropic-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Anthropic-specific errors.
#[derive(Error, Debug)]
pub enum AnthropicError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Anthropic API returned an error
    #[error("Anthropic API error ({error_type}): {message}")]
    Api {
        error_type: String,
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Overloaded (529)
    #[error("API overloaded, retry after {retry_after_ms}ms")]
    Overloaded { retry_after_ms: u64 },

    /// Invalid API key
    #[error("Invalid API key")]
    InvalidApiKey,

    /// Context length exceeded
    #[error("Context length exceeded: {message}")]
    ContextLengthExceeded { message: String },

    /// Budget exceeded
    #[error("Budget exceeded: spent ${spent:.4}, limit ${limit:.4}")]
    BudgetExceeded { spent: f64, limit: f64 },

    /// Not configured
    #[error("Connector not configured")]
    NotConfigured,

    /// Stream error
    #[error("Stream error: {0}")]
    Stream(String),
}

impl AnthropicError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Overloaded { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, Some(500..=599) | Some(429))
            }
            Self::Stream(_) => true,
            _ => false,
        }
    }

    /// Get the suggested retry delay.
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
            Self::Http(e) => FcpError::External {
                service: "anthropic".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                error_type,
                message,
                status_code,
            } => {
                if *status_code == Some(401) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid Anthropic API key".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                    }
                } else {
                    FcpError::External {
                        service: "anthropic".into(),
                        message: format!("{error_type}: {message}"),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
            },
            Self::Overloaded { retry_after_ms } => FcpError::External {
                service: "anthropic".into(),
                message: "API overloaded".into(),
                status_code: Some(529),
                retryable: true,
                retry_after: Some(Duration::from_millis(*retry_after_ms)),
            },
            Self::InvalidApiKey => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid Anthropic API key".into(),
            },
            Self::ContextLengthExceeded { message } => FcpError::InvalidRequest {
                code: 1004,
                message: message.clone(),
            },
            Self::BudgetExceeded { spent, limit } => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Budget exceeded: spent ${spent:.4}, limit ${limit:.4}"),
            },
            Self::NotConfigured => FcpError::NotConfigured,
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Stream(msg) => FcpError::External {
                service: "anthropic".into(),
                message: msg.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

/// Result type for Anthropic operations.
pub type AnthropicResult<T> = Result<T, AnthropicError>;

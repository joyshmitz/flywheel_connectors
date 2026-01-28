//! Error types for the GraphQL client.

use std::time::Duration;

use fcp_core::FcpError;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// HTTP error information captured from reqwest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpErrorInfo {
    /// Error message.
    pub message: String,
    /// HTTP status code (if available).
    pub status_code: Option<u16>,
    /// Whether the error was a timeout.
    pub is_timeout: bool,
    /// Whether the error was a connection failure.
    pub is_connect: bool,
    /// Whether the error was a request error.
    pub is_request: bool,
}

impl From<reqwest::Error> for HttpErrorInfo {
    fn from(err: reqwest::Error) -> Self {
        Self {
            message: err.to_string(),
            status_code: err.status().map(|status| status.as_u16()),
            is_timeout: err.is_timeout(),
            is_connect: err.is_connect(),
            is_request: err.is_request(),
        }
    }
}

/// GraphQL error location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlErrorLocation {
    /// Line number in the query (1-based).
    pub line: u32,
    /// Column number in the query (1-based).
    pub column: u32,
}

/// GraphQL path segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GraphqlPathSegment {
    /// Field name.
    Key(String),
    /// Array index.
    Index(i64),
}

/// GraphQL error (per GraphQL spec).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphqlError {
    /// Human-readable error message.
    pub message: String,
    /// Location(s) within the query.
    #[serde(default)]
    pub locations: Vec<GraphqlErrorLocation>,
    /// Path within the response where the error occurred.
    #[serde(default)]
    pub path: Vec<GraphqlPathSegment>,
    /// Extensions metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Error type for GraphQL client operations.
#[derive(Debug, Clone, Error)]
pub enum GraphqlClientError {
    /// HTTP/network error.
    #[error("HTTP error: {0:?}")]
    Http(HttpErrorInfo),

    /// HTTP response status error.
    #[error("HTTP status {status} with body: {body}")]
    HttpStatus {
        /// HTTP status code.
        status: StatusCode,
        /// Response body (truncated if needed).
        body: String,
        /// Retry-After duration when supplied.
        retry_after: Option<Duration>,
    },

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(String),

    /// GraphQL-level errors returned by the server.
    #[error("GraphQL errors: {errors:?}")]
    GraphqlErrors {
        /// GraphQL error list.
        errors: Vec<GraphqlError>,
    },

    /// GraphQL protocol violation.
    #[error("GraphQL protocol error: {message}")]
    Protocol {
        /// Details.
        message: String,
    },

    /// Schema validation error.
    #[error("Schema validation failed: {message}")]
    SchemaValidation {
        /// Summary message.
        message: String,
        /// Individual validation errors.
        errors: Vec<String>,
    },

    /// Retry policy exhausted.
    #[error("Retry policy exhausted after {attempts} attempts")]
    RetriesExhausted {
        /// Attempt count.
        attempts: usize,
    },
}

impl From<reqwest::Error> for GraphqlClientError {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(HttpErrorInfo::from(err))
    }
}

impl From<serde_json::Error> for GraphqlClientError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

impl GraphqlClientError {
    /// Returns `true` if the error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(info) => info.is_timeout || info.is_connect || info.is_request,
            Self::HttpStatus { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            _ => false,
        }
    }

    /// Convert the error to an FCP error for a named service.
    #[must_use]
    pub fn to_fcp_error(&self, service: &str) -> FcpError {
        match self {
            Self::Http(info) => FcpError::External {
                service: service.into(),
                message: info.message.clone(),
                status_code: info.status_code,
                retryable: info.is_timeout || info.is_connect,
                retry_after: None,
            },
            Self::HttpStatus {
                status,
                body,
                retry_after,
            } => {
                if *status == StatusCode::TOO_MANY_REQUESTS {
                    if let Some(duration) = retry_after {
                        return FcpError::RateLimited {
                            retry_after_ms: duration.as_millis() as u64,
                            violation: None,
                        };
                    }
                    return FcpError::RateLimited {
                        retry_after_ms: 1000,
                        violation: None,
                    };
                }
                if *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN {
                    return FcpError::Unauthorized {
                        code: 2001,
                        message: format!("{service} unauthorized: {body}"),
                    };
                }
                FcpError::External {
                    service: service.into(),
                    message: body.clone(),
                    status_code: Some(status.as_u16()),
                    retryable: status.is_server_error(),
                    retry_after: *retry_after,
                }
            }
            Self::Json(message) => FcpError::MalformedFrame {
                code: 2004,
                message: format!("JSON parsing error: {message}"),
            },
            Self::GraphqlErrors { errors } => {
                let message = errors
                    .get(0)
                    .map(|err| err.message.clone())
                    .unwrap_or_else(|| "GraphQL error".to_string());
                FcpError::External {
                    service: service.into(),
                    message,
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                }
            }
            Self::Protocol { message } => FcpError::InvalidRequest {
                code: 1002,
                message: message.clone(),
            },
            Self::SchemaValidation { message, .. } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::RetriesExhausted { attempts } => FcpError::External {
                service: service.into(),
                message: format!("Retry policy exhausted after {attempts} attempts"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        }
    }
}

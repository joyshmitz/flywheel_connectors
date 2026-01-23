//! Error types for fcp-host.

use thiserror::Error;

/// Errors that can occur in fcp-host operations.
#[derive(Debug, Error)]
pub enum HostError {
    /// Connector not found in registry.
    #[error("connector not found: {0}")]
    ConnectorNotFound(String),

    /// Invalid filter parameter.
    #[error("invalid filter: {0}")]
    InvalidFilter(String),

    /// Registry error.
    #[error("registry error: {0}")]
    RegistryError(String),

    /// Preflight check failed.
    #[error("preflight failed: {0}")]
    PreflightFailed(String),

    /// Cache error.
    #[error("cache error: {0}")]
    CacheError(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for host operations.
pub type HostResult<T> = Result<T, HostError>;

//! Error types for Tailscale integration.

use thiserror::Error;

/// Result type for Tailscale operations.
pub type TailscaleResult<T> = Result<T, TailscaleError>;

/// Errors that can occur during Tailscale operations.
#[derive(Debug, Error)]
pub enum TailscaleError {
    /// Invalid tag format (must be `tag:fcp-<suffix>`).
    #[error("invalid FCP tag format: {0}")]
    InvalidTag(String),

    /// Invalid zone ID format (must be `z:<name>`).
    #[error("invalid zone ID format: {0}")]
    InvalidZoneId(String),

    /// Tag does not have the FCP prefix.
    #[error("tag '{0}' does not have FCP prefix 'tag:fcp-'")]
    NotFcpTag(String),

    /// `LocalAPI` request failed.
    #[error("`LocalAPI` request failed: {0}")]
    LocalApiRequest(String),

    /// `LocalAPI` returned an error response.
    #[error("`LocalAPI` error: {0}")]
    LocalApiError(String),

    /// Failed to parse `LocalAPI` response.
    #[error("failed to parse `LocalAPI` response: {0}")]
    ParseError(String),

    /// Node is not connected to tailnet.
    #[error("node is not connected to tailnet")]
    NotConnected,

    /// Peer not found.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Invalid attestation signature.
    #[error("invalid attestation signature")]
    InvalidAttestation,

    /// Attestation has expired.
    #[error("attestation has expired")]
    AttestationExpired,

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] fcp_crypto::CryptoError),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

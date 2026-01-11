//! OAuth error types.

use std::time::Duration;

/// OAuth errors.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Invalid client configuration.
    #[error("Invalid OAuth configuration: {0}")]
    InvalidConfig(String),

    /// State mismatch (potential CSRF attack).
    #[error("OAuth state mismatch: expected {expected}, got {actual}")]
    StateMismatch {
        /// Expected state value.
        expected: String,
        /// Received state value.
        actual: String,
    },

    /// Authorization error from provider.
    #[error("Authorization error: {error} - {description}")]
    AuthorizationError {
        /// Error code from provider.
        error: String,
        /// Human-readable description.
        description: String,
        /// Error URI for more information.
        error_uri: Option<String>,
    },

    /// Token exchange failed.
    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// Token refresh failed.
    #[error("Token refresh failed: {0}")]
    RefreshFailed(String),

    /// Token expired.
    #[error("Token expired {0:?} ago")]
    TokenExpired(Duration),

    /// No refresh token available.
    #[error("No refresh token available")]
    NoRefreshToken,

    /// Invalid token response.
    #[error("Invalid token response: {0}")]
    InvalidTokenResponse(String),

    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// JSON parsing failed.
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    /// URL parsing failed.
    #[error("URL parsing failed: {0}")]
    UrlError(#[from] url::ParseError),

    /// OAuth 1.0a signature error.
    #[error("OAuth 1.0a signature error: {0}")]
    SignatureError(String),

    /// Provider not supported.
    #[error("Provider not supported: {0}")]
    UnsupportedProvider(String),

    /// Token not found.
    #[error("Token not found for key: {0}")]
    TokenNotFound(String),

    /// PKCE error.
    #[error("PKCE error: {0}")]
    PkceError(String),
}

/// Result type for OAuth operations.
pub type OAuthResult<T> = Result<T, OAuthError>;

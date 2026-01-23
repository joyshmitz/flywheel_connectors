//! Bootstrap error types.

use thiserror::Error;

/// Result type for bootstrap operations.
pub type BootstrapResult<T> = Result<T, BootstrapError>;

/// Errors that can occur during bootstrap operations.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Time synchronization error.
    #[error("time skew detected: drift={drift:?}, suggestion: {suggestion}")]
    TimeSkew {
        /// Amount of clock drift detected.
        drift: std::time::Duration,
        /// Suggestion for the user.
        suggestion: &'static str,
    },

    /// Genesis already exists at this location.
    #[error("genesis already exists: fingerprint={fingerprint}")]
    AlreadyExists {
        /// Fingerprint of the existing genesis.
        fingerprint: String,
    },

    /// Partial state detected from a crashed initialization.
    #[error("partial bootstrap state detected at phase: {phase}")]
    PartialState {
        /// Phase where the crash occurred.
        phase: String,
    },

    /// Recovery phrase is invalid.
    #[error("invalid recovery phrase: {0}")]
    InvalidRecoveryPhrase(String),

    /// Fingerprint mismatch during recovery.
    #[error("genesis fingerprint mismatch: expected={expected}, actual={actual}")]
    FingerprintMismatch {
        /// Expected fingerprint.
        expected: String,
        /// Actual fingerprint computed.
        actual: String,
    },

    /// Ceremony error.
    #[error("ceremony error: {0}")]
    Ceremony(String),

    /// Ceremony timeout.
    #[error("ceremony timed out at phase: {phase}")]
    CeremonyTimeout {
        /// Phase where the timeout occurred.
        phase: String,
    },

    /// Hardware token error.
    #[error("hardware token error: {0}")]
    HardwareToken(String),

    /// No hardware tokens found.
    #[error("no hardware tokens detected")]
    NoHardwareTokens,

    /// Cryptographic error.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<ciborium::ser::Error<std::io::Error>> for BootstrapError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<ciborium::de::Error<std::io::Error>> for BootstrapError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        Self::Serialization(e.to_string())
    }
}

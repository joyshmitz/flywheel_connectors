//! Error types for FCP2 cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },

    /// Invalid signature.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid key ID format.
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),

    /// AEAD encryption failed.
    #[error("AEAD encryption failed")]
    AeadEncryptFailed,

    /// AEAD decryption failed (authentication failed or invalid ciphertext).
    #[error("AEAD decryption failed: authentication or decryption error")]
    AeadDecryptFailed,

    /// HPKE operation failed.
    #[error("HPKE operation failed: {0}")]
    HpkeFailed(String),

    /// COSE operation failed.
    #[error("COSE operation failed: {0}")]
    CoseFailed(String),

    /// Invalid nonce length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes.
        expected: usize,
        /// Actual nonce length provided.
        actual: usize,
    },

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key.
    #[error("invalid secret key")]
    InvalidSecretKey,

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Token validation error.
    #[error("token validation error: {0}")]
    TokenValidationError(String),

    /// Token expired.
    #[error("token expired")]
    TokenExpired,

    /// Token not yet valid.
    #[error("token not yet valid")]
    TokenNotYetValid,

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Result type alias for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

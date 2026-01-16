//! Error types for FCP2 stores.

use fcp_core::ObjectId;
use thiserror::Error;

/// Errors for object store operations.
#[derive(Debug, Error)]
pub enum ObjectStoreError {
    #[error("object not found: {0}")]
    NotFound(ObjectId),

    #[error("object already exists: {0}")]
    AlreadyExists(ObjectId),

    #[error("storage quota exceeded: {used} / {max} bytes")]
    QuotaExceeded { used: u64, max: u64 },

    #[error("invalid object: {reason}")]
    InvalidObject { reason: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(String),
}

/// Errors for symbol store operations.
#[derive(Debug, Error)]
pub enum SymbolStoreError {
    #[error("symbol not found: object={object_id}, esi={esi}")]
    NotFound { object_id: ObjectId, esi: u32 },

    #[error("object not found: {0}")]
    ObjectNotFound(ObjectId),

    #[error("storage quota exceeded: {used} / {max} bytes")]
    QuotaExceeded { used: u64, max: u64 },

    #[error("invalid symbol: {reason}")]
    InvalidSymbol { reason: String },

    #[error("I/O error: {0}")]
    Io(String),
}

/// Errors for quarantine operations.
#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("quarantine quota exceeded for zone: {used} / {max} bytes")]
    QuotaExceeded { used: u64, max: u64 },

    #[error("object not in quarantine: {0}")]
    NotFound(ObjectId),

    #[error("promotion denied: {reason}")]
    PromotionDenied { reason: String },

    #[error("schema validation failed: {reason}")]
    SchemaValidationFailed { reason: String },
}

/// Errors for repair operations.
#[derive(Debug, Error)]
pub enum RepairError {
    #[error("repair rate limit exceeded")]
    RateLimitExceeded,

    #[error("insufficient coverage data")]
    InsufficientCoverage,

    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),

    #[error("symbol store error: {0}")]
    SymbolStore(#[from] SymbolStoreError),

    #[error("decode error: {0}")]
    Decode(String),
}

/// Errors for garbage collection.
#[derive(Debug, Error)]
pub enum GcError {
    #[error("GC in progress")]
    InProgress,

    #[error("invalid root: {0}")]
    InvalidRoot(ObjectId),

    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),

    #[error("symbol store error: {0}")]
    SymbolStore(#[from] SymbolStoreError),
}

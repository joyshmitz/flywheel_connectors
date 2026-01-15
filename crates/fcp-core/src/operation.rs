//! Exactly-once semantics for FCP2 operations.
//!
//! This module implements `OperationIntent` and `OperationReceipt` as defined in
//! `FCP_Specification_V2.md` §15. Together with idempotency keys, these objects
//! provide exactly-once semantics for external side effects.
//!
//! # Core Concepts
//!
//! ## Exactly-Once Semantics
//!
//! For Strict idempotency and for Risky/Dangerous operations:
//! 1. `MeshNode` MUST store `OperationIntent` (Required retention) BEFORE executing side effects
//! 2. `OperationIntent` MUST reference the execution lease via `ObjectHeader.refs` (for Risky/Dangerous)
//! 3. `OperationReceipt` MUST reference the `OperationIntent` via `ObjectHeader.refs`
//! 4. On crash recovery, check for intents without corresponding receipts
//!
//! ## Idempotency Enforcement
//!
//! - On retry with same `idempotency_key`, mesh returns prior receipt without re-executing
//! - Receipts are stored in symbol store (`RetentionClass::Lease` or Pinned for critical)
//! - Makes "best-effort vs strict idempotency" enforceable, not advisory
//!
//! ## Lease Binding
//!
//! For Risky/Dangerous operations, `OperationIntent.lease_seq` SHOULD bind to the
//! execution lease fencing token. This prevents zombie lease holders from executing
//! operations after losing the lease.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{IdempotencyClass, NodeSignature, ObjectHeader, ObjectId, TailscaleNodeId, ZoneId};

// ─────────────────────────────────────────────────────────────────────────────
// OperationIntent (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Operation intent - pre-commit for exactly-once semantics (NORMATIVE for Strict + Risky/Dangerous).
///
/// Closes the crash window between "side effect happened" and "receipt stored".
/// Written BEFORE executing an external side effect.
///
/// # Execution Rule (NORMATIVE)
///
/// 1. `MeshNode` MUST store `OperationIntent` BEFORE invoking the connector operation
/// 2. `OperationIntent` MUST reference the `ExecutionLease` via `header.refs` (for Risky/Dangerous)
/// 3. `OperationReceipt` MUST reference this intent via `header.refs`
/// 4. On crash recovery, intents without receipts indicate incomplete operations
///
/// # Fencing Token Binding
///
/// For Risky/Dangerous operations, `lease_seq` binds this intent to a specific
/// lease. Connectors can reject stale lease holders by comparing `lease_seq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationIntent {
    /// Standard object header with schema, zone, provenance.
    ///
    /// For Risky/Dangerous operations, `header.refs` MUST include the
    /// `ObjectId` of the execution lease.
    pub header: ObjectHeader,

    /// `ObjectId` of the original invoke request.
    pub request_object_id: ObjectId,

    /// Unique identifier from the capability token (jti claim).
    ///
    /// Links this intent to the specific capability token authorizing execution.
    pub capability_token_jti: Uuid,

    /// Idempotency key for exactly-once semantics (NORMATIVE for Strict).
    ///
    /// If present, retries with the same key MUST return the prior receipt
    /// without re-executing the operation.
    pub idempotency_key: Option<String>,

    /// When this intent was created (Unix timestamp seconds).
    pub planned_at: u64,

    /// Node that planned/will execute this operation.
    pub planned_by: TailscaleNodeId,

    /// Lease fencing token observed for this intent (NORMATIVE for Risky/Dangerous).
    ///
    /// Connectors/state writers can reject stale lease holders by comparing `lease_seq`.
    /// Must match the `lease_seq` of the active execution lease.
    pub lease_seq: Option<u64>,

    /// Optional upstream idempotency handle (e.g., Stripe idempotency key).
    ///
    /// When the external service provides its own idempotency mechanism,
    /// this field stores the handle used for that service.
    pub upstream_idempotency: Option<String>,

    /// Signature by the planning node's signing key.
    pub signature: NodeSignature,
}

impl OperationIntent {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Check if this intent requires strict idempotency enforcement.
    #[must_use]
    pub const fn requires_strict_idempotency(&self) -> bool {
        self.idempotency_key.is_some()
    }

    /// Check if this intent is bound to a lease.
    #[must_use]
    pub const fn is_lease_bound(&self) -> bool {
        self.lease_seq.is_some()
    }

    /// Compute the bytes that were signed.
    ///
    /// The signable content is the canonical representation of the intent
    /// excluding the signature field itself.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        // For signable bytes, we create a deterministic representation
        // of all fields except the signature itself.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FCP2-INTENT-V1");
        bytes.extend_from_slice(&self.header.created_at.to_le_bytes());
        bytes.extend_from_slice(self.request_object_id.as_bytes());
        bytes.extend_from_slice(self.capability_token_jti.as_bytes());
        if let Some(ref key) = self.idempotency_key {
            bytes.extend_from_slice(&[1]); // present marker
            bytes.extend_from_slice(key.as_bytes());
        } else {
            bytes.extend_from_slice(&[0]); // absent marker
        }
        bytes.extend_from_slice(&self.planned_at.to_le_bytes());
        bytes.extend_from_slice(self.planned_by.as_str().as_bytes());
        if let Some(seq) = self.lease_seq {
            bytes.extend_from_slice(&[1]);
            bytes.extend_from_slice(&seq.to_le_bytes());
        } else {
            bytes.extend_from_slice(&[0]);
        }
        if let Some(ref upstream) = self.upstream_idempotency {
            bytes.extend_from_slice(&[1]);
            bytes.extend_from_slice(upstream.as_bytes());
        } else {
            bytes.extend_from_slice(&[0]);
        }
        bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OperationReceipt (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Operation receipt object (NORMATIVE).
///
/// Records the successful completion of an operation, including what was
/// produced. For Strict idempotency, returning a prior receipt on retry
/// is REQUIRED.
///
/// # Idempotency Semantics
///
/// Operations with `SafetyTier::Dangerous` MUST be `IdempotencyClass::Strict`.
/// Operations with `SafetyTier::Risky` SHOULD be Strict unless there is a clear reason.
///
/// # Object References
///
/// `header.refs` MUST include the `ObjectId` of the corresponding `OperationIntent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationReceipt {
    /// Standard object header with schema, zone, provenance.
    ///
    /// `header.refs` MUST include the intent's `ObjectId`.
    pub header: ObjectHeader,

    /// `ObjectId` of the original invoke request.
    pub request_object_id: ObjectId,

    /// Idempotency key (echoed from intent if provided).
    ///
    /// Used for O(1) lookup on retry.
    pub idempotency_key: Option<String>,

    /// `ObjectId`s of outcome objects produced by the operation.
    ///
    /// These may be `InvokeResponse` objects, `ResourceObjects`, etc.
    pub outcome_object_ids: Vec<ObjectId>,

    /// `ResourceObject` IDs created or modified (NORMATIVE).
    ///
    /// Enables auditing of what resources were affected.
    pub resource_object_ids: Vec<ObjectId>,

    /// When execution completed (Unix timestamp seconds).
    pub executed_at: u64,

    /// Node that executed the operation.
    pub executed_by: TailscaleNodeId,

    /// Signature by executing node's signing key.
    pub signature: NodeSignature,
}

impl OperationReceipt {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Check if this receipt is for an idempotent operation.
    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        self.idempotency_key.is_some()
    }

    /// Get the total number of objects produced.
    #[must_use]
    pub fn total_objects_produced(&self) -> usize {
        self.outcome_object_ids.len() + self.resource_object_ids.len()
    }

    /// Compute the bytes that were signed.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Vec lengths capped by protocol limits
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FCP2-RECEIPT-V1");
        bytes.extend_from_slice(&self.header.created_at.to_le_bytes());
        bytes.extend_from_slice(self.request_object_id.as_bytes());
        if let Some(ref key) = self.idempotency_key {
            bytes.extend_from_slice(&[1]);
            bytes.extend_from_slice(key.as_bytes());
        } else {
            bytes.extend_from_slice(&[0]);
        }
        // Include outcome object IDs (count capped at u32::MAX for protocol encoding)
        let outcome_count = u32::try_from(self.outcome_object_ids.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&outcome_count.to_le_bytes());
        for oid in &self.outcome_object_ids {
            bytes.extend_from_slice(oid.as_bytes());
        }
        // Include resource object IDs (count capped at u32::MAX for protocol encoding)
        let resource_count = u32::try_from(self.resource_object_ids.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&resource_count.to_le_bytes());
        for oid in &self.resource_object_ids {
            bytes.extend_from_slice(oid.as_bytes());
        }
        bytes.extend_from_slice(&self.executed_at.to_le_bytes());
        bytes.extend_from_slice(self.executed_by.as_str().as_bytes());
        bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Intent Status (for crash recovery)
// ─────────────────────────────────────────────────────────────────────────────

/// Status of an operation intent.
///
/// Used during crash recovery to determine the state of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    /// Intent recorded, operation not yet started.
    Pending,
    /// Operation in progress (side effect may or may not have occurred).
    InProgress,
    /// Operation completed successfully (receipt exists).
    Completed,
    /// Operation failed (error receipt exists).
    Failed,
    /// Intent orphaned (no receipt, exceeded timeout).
    Orphaned,
}

impl std::fmt::Display for IntentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Orphaned => write!(f, "orphaned"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Idempotency Key Index Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Index entry for idempotency key lookups.
///
/// Enables O(1) lookup of receipts by idempotency key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyEntry {
    /// The idempotency key.
    pub key: String,

    /// Zone context for the operation.
    pub zone_id: ZoneId,

    /// `ObjectId` of the intent.
    pub intent_id: ObjectId,

    /// `ObjectId` of the receipt (if completed).
    pub receipt_id: Option<ObjectId>,

    /// Current status.
    pub status: IntentStatus,

    /// When the entry was created.
    pub created_at: u64,

    /// When the entry expires (for garbage collection).
    ///
    /// After expiry, the key may be reused (though the receipt remains
    /// valid for auditing).
    pub expires_at: u64,
}

impl IdempotencyEntry {
    /// Check if this entry has expired.
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Check if the operation is complete (success or failure).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.status, IntentStatus::Completed | IntentStatus::Failed)
    }

    /// Check if a retry should return the existing receipt.
    ///
    /// Returns true if:
    /// - Operation completed and receipt exists
    /// - Entry has not expired
    #[must_use]
    pub const fn should_return_cached(&self, now: u64) -> bool {
        !self.is_expired(now) && self.is_terminal() && self.receipt_id.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when intent/receipt validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationValidationError {
    /// Intent is missing for the given idempotency key.
    IntentNotFound { idempotency_key: String },

    /// Receipt already exists for this idempotency key.
    AlreadyCompleted { idempotency_key: String },

    /// Intent/receipt zone mismatch.
    ZoneMismatch { expected: ZoneId, got: ZoneId },

    /// Receipt does not reference the expected intent.
    IntentReferenceMissing { receipt_id: ObjectId },

    /// Lease sequence mismatch (stale lease holder).
    LeaseSeqMismatch { expected: u64, got: u64 },

    /// Intent has been orphaned.
    IntentOrphaned {
        intent_id: ObjectId,
        planned_at: u64,
    },

    /// Signature verification failed.
    SignatureInvalid { reason: String },

    /// Request object ID mismatch.
    RequestMismatch {
        expected: ObjectId,
        got: ObjectId,
    },
}

impl std::fmt::Display for OperationValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntentNotFound { idempotency_key } => {
                write!(f, "intent not found for idempotency key: {idempotency_key}")
            }
            Self::AlreadyCompleted { idempotency_key } => {
                write!(
                    f,
                    "operation already completed for idempotency key: {idempotency_key}"
                )
            }
            Self::ZoneMismatch { expected, got } => {
                write!(f, "zone mismatch: expected {expected}, got {got}")
            }
            Self::IntentReferenceMissing { receipt_id } => {
                write!(f, "receipt {receipt_id} does not reference an intent")
            }
            Self::LeaseSeqMismatch { expected, got } => {
                write!(f, "lease seq mismatch: expected {expected}, got {got}")
            }
            Self::IntentOrphaned {
                intent_id,
                planned_at,
            } => {
                write!(f, "intent {intent_id} orphaned (planned at {planned_at})")
            }
            Self::SignatureInvalid { reason } => {
                write!(f, "signature invalid: {reason}")
            }
            Self::RequestMismatch { expected, got } => {
                write!(f, "request mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for OperationValidationError {}

/// Validate that a receipt properly references its intent.
///
/// # Arguments
///
/// * `receipt` - The receipt to validate
/// * `intent` - The expected intent
///
/// # Errors
///
/// Returns an error if:
/// - Receipt's `request_object_id` doesn't match intent's
/// - Receipt's zone doesn't match intent's
/// - Receipt's `idempotency_key` doesn't match intent's
pub fn validate_receipt_intent_binding(
    receipt: &OperationReceipt,
    intent: &OperationIntent,
) -> Result<(), OperationValidationError> {
    // Check request object ID matches
    if receipt.request_object_id != intent.request_object_id {
        return Err(OperationValidationError::RequestMismatch {
            expected: intent.request_object_id,
            got: receipt.request_object_id,
        });
    }

    // Check zone matches
    if receipt.zone_id() != intent.zone_id() {
        return Err(OperationValidationError::ZoneMismatch {
            expected: intent.zone_id().clone(),
            got: receipt.zone_id().clone(),
        });
    }

    // Check idempotency key matches
    if receipt.idempotency_key != intent.idempotency_key {
        // This is a logic error - keys must match exactly
        return Err(OperationValidationError::IntentNotFound {
            idempotency_key: receipt
                .idempotency_key
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        });
    }

    Ok(())
}

/// Check if an intent should be considered orphaned.
///
/// An intent is orphaned if:
/// - No corresponding receipt exists
/// - More than `orphan_threshold_secs` have passed since `planned_at`
///
/// # Arguments
///
/// * `intent` - The intent to check
/// * `has_receipt` - Whether a receipt exists for this intent
/// * `now` - Current timestamp
/// * `orphan_threshold_secs` - Threshold for orphan detection
#[must_use]
pub const fn is_intent_orphaned(
    intent: &OperationIntent,
    has_receipt: bool,
    now: u64,
    orphan_threshold_secs: u64,
) -> bool {
    !has_receipt && now.saturating_sub(intent.planned_at) > orphan_threshold_secs
}

/// Determine idempotency class requirements based on safety tier.
///
/// Per spec:
/// - Dangerous operations MUST be Strict
/// - Risky operations SHOULD be Strict
/// - Safe operations MAY be any class
#[must_use]
pub const fn required_idempotency_for_safety_tier(is_dangerous: bool, is_risky: bool) -> IdempotencyClass {
    // Both Dangerous and Risky require Strict idempotency per spec
    if is_dangerous || is_risky {
        IdempotencyClass::Strict
    } else {
        IdempotencyClass::None // Safe ops don't require idempotency
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_object_id(name: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(name.as_bytes())
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(
            crate::NodeId::new("test-node"),
            [0u8; 64],
            1000,
        )
    }

    fn create_test_header() -> ObjectHeader {
        let zone = test_zone();
        ObjectHeader {
            schema: SchemaId::new("fcp.operation", "intent", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            created_at: 1000,
            provenance: Provenance::new(zone),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn create_test_intent() -> OperationIntent {
        OperationIntent {
            header: create_test_header(),
            request_object_id: test_object_id("request-1"),
            capability_token_jti: Uuid::nil(),
            idempotency_key: Some("idem-key-123".to_string()),
            planned_at: 1000,
            planned_by: test_node("executor-node"),
            lease_seq: Some(42),
            upstream_idempotency: None,
            signature: test_signature(),
        }
    }

    fn create_test_receipt() -> OperationReceipt {
        let mut header = create_test_header();
        header.schema = SchemaId::new("fcp.operation", "receipt", Version::new(1, 0, 0));

        OperationReceipt {
            header,
            request_object_id: test_object_id("request-1"),
            idempotency_key: Some("idem-key-123".to_string()),
            outcome_object_ids: vec![test_object_id("outcome-1")],
            resource_object_ids: vec![],
            executed_at: 1100,
            executed_by: test_node("executor-node"),
            signature: test_signature(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OperationIntent Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_intent_zone_id() {
        let intent = create_test_intent();
        assert_eq!(intent.zone_id(), &test_zone());
    }

    #[test]
    fn test_intent_requires_strict_idempotency() {
        let mut intent = create_test_intent();
        assert!(intent.requires_strict_idempotency());

        intent.idempotency_key = None;
        assert!(!intent.requires_strict_idempotency());
    }

    #[test]
    fn test_intent_is_lease_bound() {
        let mut intent = create_test_intent();
        assert!(intent.is_lease_bound());

        intent.lease_seq = None;
        assert!(!intent.is_lease_bound());
    }

    #[test]
    fn test_intent_signable_bytes_deterministic() {
        let intent = create_test_intent();
        let bytes1 = intent.signable_bytes();
        let bytes2 = intent.signable_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_intent_signable_bytes_differ_with_different_keys() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();

        intent1.idempotency_key = Some("key-1".to_string());
        intent2.idempotency_key = Some("key-2".to_string());

        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn test_intent_serde() {
        let intent = create_test_intent();
        let json = serde_json::to_string(&intent).unwrap();
        let deserialized: OperationIntent = serde_json::from_str(&json).unwrap();

        assert_eq!(intent.request_object_id, deserialized.request_object_id);
        assert_eq!(intent.idempotency_key, deserialized.idempotency_key);
        assert_eq!(intent.planned_at, deserialized.planned_at);
        assert_eq!(intent.lease_seq, deserialized.lease_seq);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OperationReceipt Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_receipt_zone_id() {
        let receipt = create_test_receipt();
        assert_eq!(receipt.zone_id(), &test_zone());
    }

    #[test]
    fn test_receipt_is_idempotent() {
        let mut receipt = create_test_receipt();
        assert!(receipt.is_idempotent());

        receipt.idempotency_key = None;
        assert!(!receipt.is_idempotent());
    }

    #[test]
    fn test_receipt_total_objects() {
        let mut receipt = create_test_receipt();
        assert_eq!(receipt.total_objects_produced(), 1);

        receipt.resource_object_ids = vec![test_object_id("resource-1"), test_object_id("resource-2")];
        assert_eq!(receipt.total_objects_produced(), 3);
    }

    #[test]
    fn test_receipt_signable_bytes_deterministic() {
        let receipt = create_test_receipt();
        let bytes1 = receipt.signable_bytes();
        let bytes2 = receipt.signable_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_receipt_serde() {
        let receipt = create_test_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: OperationReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.request_object_id, deserialized.request_object_id);
        assert_eq!(receipt.idempotency_key, deserialized.idempotency_key);
        assert_eq!(receipt.executed_at, deserialized.executed_at);
        assert_eq!(receipt.outcome_object_ids.len(), deserialized.outcome_object_ids.len());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IntentStatus Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_intent_status_display() {
        assert_eq!(IntentStatus::Pending.to_string(), "pending");
        assert_eq!(IntentStatus::InProgress.to_string(), "in_progress");
        assert_eq!(IntentStatus::Completed.to_string(), "completed");
        assert_eq!(IntentStatus::Failed.to_string(), "failed");
        assert_eq!(IntentStatus::Orphaned.to_string(), "orphaned");
    }

    #[test]
    fn test_intent_status_serde() {
        let statuses = [
            IntentStatus::Pending,
            IntentStatus::InProgress,
            IntentStatus::Completed,
            IntentStatus::Failed,
            IntentStatus::Orphaned,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: IntentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IdempotencyEntry Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_idempotency_entry_is_expired() {
        let entry = IdempotencyEntry {
            key: "test-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 2000,
        };

        assert!(!entry.is_expired(1500));
        assert!(entry.is_expired(2000));
        assert!(entry.is_expired(2500));
    }

    #[test]
    fn test_idempotency_entry_is_terminal() {
        let mut entry = IdempotencyEntry {
            key: "test-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 2000,
        };

        assert!(!entry.is_terminal());

        entry.status = IntentStatus::InProgress;
        assert!(!entry.is_terminal());

        entry.status = IntentStatus::Completed;
        assert!(entry.is_terminal());

        entry.status = IntentStatus::Failed;
        assert!(entry.is_terminal());
    }

    #[test]
    fn test_idempotency_entry_should_return_cached() {
        let mut entry = IdempotencyEntry {
            key: "test-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: Some(test_object_id("receipt")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Should return cached (completed + receipt + not expired)
        assert!(entry.should_return_cached(1500));

        // Should not return cached (expired)
        assert!(!entry.should_return_cached(2500));

        // Should not return cached (not terminal)
        entry.status = IntentStatus::InProgress;
        assert!(!entry.should_return_cached(1500));

        // Should not return cached (no receipt)
        entry.status = IntentStatus::Completed;
        entry.receipt_id = None;
        assert!(!entry.should_return_cached(1500));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_receipt_intent_binding_success() {
        let intent = create_test_intent();
        let receipt = create_test_receipt();

        let result = validate_receipt_intent_binding(&receipt, &intent);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_receipt_intent_binding_request_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.request_object_id = test_object_id("different-request");

        let result = validate_receipt_intent_binding(&receipt, &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::RequestMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_receipt_intent_binding_zone_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.header.zone_id = ZoneId::owner();

        let result = validate_receipt_intent_binding(&receipt, &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::ZoneMismatch { .. })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Orphan Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_intent_orphaned() {
        let intent = create_test_intent();

        // Not orphaned (has receipt)
        assert!(!is_intent_orphaned(&intent, true, 5000, 3600));

        // Not orphaned (within threshold)
        assert!(!is_intent_orphaned(&intent, false, 1500, 3600));

        // Orphaned (no receipt + past threshold)
        assert!(is_intent_orphaned(&intent, false, 5000, 3600));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Idempotency Class Requirements Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_required_idempotency_for_safety_tier() {
        // Dangerous MUST be Strict
        assert_eq!(
            required_idempotency_for_safety_tier(true, false),
            IdempotencyClass::Strict
        );

        // Risky SHOULD be Strict
        assert_eq!(
            required_idempotency_for_safety_tier(false, true),
            IdempotencyClass::Strict
        );

        // Safe operations don't require idempotency
        assert_eq!(
            required_idempotency_for_safety_tier(false, false),
            IdempotencyClass::None
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Retry Returns Same Receipt Test
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_retry_returns_same_receipt_scenario() {
        // Simulate a retry scenario
        let idempotency_key = "stripe-payment-xyz".to_string();

        // First: Create entry when intent is recorded
        let entry = IdempotencyEntry {
            key: idempotency_key.clone(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("receipt-1")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 1000 + 86400, // 24 hours
        };

        // Second request with same key at different time
        let retry_time = 1500;

        // Entry should indicate cached return
        assert!(entry.should_return_cached(retry_time));

        // The receipt_id from the entry is what should be returned
        assert_eq!(entry.receipt_id, Some(test_object_id("receipt-1")));
    }
}

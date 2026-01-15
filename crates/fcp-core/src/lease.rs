//! Distributed lease primitives for FCP2.
//!
//! This module implements leases as defined in `FCP_Specification_V2.md` §16.
//! Leases provide a unified distributed coordination primitive used for:
//!
//! - Operation execution (prevent duplicate side effects)
//! - ConnectorState writes (singleton_writer fencing)
//! - Computation migration (safe handoffs)
//!
//! # Core Concepts
//!
//! ## Fencing Tokens
//!
//! The `lease_seq` field is critical for safety:
//! - Monotonically increases per (zone_id, subject_object_id)
//! - Higher lease_seq wins deterministically, regardless of wall-clock expiry
//! - Prevents "zombie lease" problems where an old lease holder believes it still owns
//!
//! ## Coordinator Selection
//!
//! Coordinators are selected using HRW/Rendezvous hashing for deterministic,
//! consistent selection without a central coordinator. This ensures:
//! - No single point of failure
//! - Consistent selection across nodes
//! - Automatic failover when coordinator becomes unavailable
//!
//! ## Quorum Rules
//!
//! Different risk tiers require different quorum signatures:
//! - Safe ops: Single coordinator signature may be sufficient
//! - Risky ops: Require f+1 signatures
//! - Dangerous ops: Require n-f signatures

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{ObjectHeader, ObjectId, SignatureSet, TailscaleNodeId, ZoneId};

// ─────────────────────────────────────────────────────────────────────────────
// Lease Purpose (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Lease purpose discriminant (NORMATIVE).
///
/// Defines what a lease authorizes. Each purpose has specific semantics:
///
/// - `OperationExecution`: Prevents duplicate execution of operations with side effects.
///   Used by the exactly-once semantics system (see §15 OperationIntent/Receipt).
///
/// - `ConnectorStateWrite`: Serializes writes to SingleWriter connector state.
///   Only the lease holder may write to the associated state object.
///
/// - `ComputationMigration`: Coordinates computation migration between nodes.
///   Ensures safe handoffs during device changes or load balancing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePurpose {
    /// Prevents duplicate execution of operations with side effects.
    OperationExecution,
    /// Serializes writes to SingleWriter connector state.
    ConnectorStateWrite,
    /// Coordinates computation migration between nodes.
    ComputationMigration,
}

impl std::fmt::Display for LeasePurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationExecution => write!(f, "operation_execution"),
            Self::ConnectorStateWrite => write!(f, "connector_state_write"),
            Self::ComputationMigration => write!(f, "computation_migration"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Generic lease primitive (NORMATIVE).
///
/// A short-lived, renewable lock that says:
/// "node X owns subject S for purpose P until time T."
///
/// # Fencing Token Semantics
///
/// The `lease_seq` is critical for safety:
/// - Monotonically increases per (zone_id, subject_object_id)
/// - Higher `lease_seq` wins deterministically, regardless of wall-clock expiry
/// - Prevents "zombie lease" problems
///
/// # Coordinator Selection
///
/// The coordinator is selected via HRW/Rendezvous hashing over
/// `(zone_id, subject_object_id)`. This ensures deterministic, consistent
/// selection without a central coordinator.
///
/// # Quorum Requirements
///
/// - Safe ops: Single coordinator signature may be sufficient
/// - Risky ops: Require f+1 signatures
/// - Dangerous ops: Require n-f signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Standard object header with schema, zone, provenance.
    pub header: ObjectHeader,

    /// The subject being leased (request, state object, computation).
    pub subject_object_id: ObjectId,

    /// What this lease authorizes.
    pub purpose: LeasePurpose,

    /// Fencing token (NORMATIVE): monotonically increases per (zone_id, subject_object_id).
    ///
    /// The highest `lease_seq` wins deterministically, regardless of wall-clock `exp`.
    /// This is the critical safety property that prevents zombie leases.
    pub lease_seq: u64,

    /// Which node currently owns execution/write.
    pub owner_node: TailscaleNodeId,

    /// Lease issued at (Unix timestamp seconds).
    pub iat: u64,

    /// Lease expires at (Unix timestamp seconds).
    ///
    /// Short-lived by design; holder must renew before expiry.
    pub exp: u64,

    /// Deterministic coordinator for this lease (NORMATIVE).
    ///
    /// Selected via HRW/Rendezvous hashing over `(zone_id, subject_object_id)`.
    pub coordinator: TailscaleNodeId,

    /// Quorum signatures (NORMATIVE for Risky/Dangerous).
    ///
    /// The required number of signatures depends on the risk tier of the
    /// associated operation.
    pub quorum_signatures: SignatureSet,
}

impl Lease {
    /// Check if this lease is expired based on the given current timestamp.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.exp
    }

    /// Check if this lease is active (not expired) at the given timestamp.
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        !self.is_expired(now)
    }

    /// Get the zone ID from the header.
    #[must_use]
    pub fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Compare two leases for the same subject to determine which wins.
    ///
    /// # Conflict Resolution Rules (NORMATIVE)
    ///
    /// The lease with the higher `lease_seq` wins, regardless of expiry times.
    /// This ensures deterministic conflict resolution across all nodes.
    ///
    /// Returns:
    /// - `Ordering::Greater` if `self` wins
    /// - `Ordering::Less` if `other` wins
    /// - `Ordering::Equal` if they are the same (same seq)
    #[must_use]
    pub fn compare_priority(&self, other: &Self) -> Ordering {
        // Higher lease_seq wins
        self.lease_seq.cmp(&other.lease_seq)
    }

    /// Check if this lease supersedes another lease for the same subject.
    #[must_use]
    pub fn supersedes(&self, other: &Self) -> bool {
        self.compare_priority(other) == Ordering::Greater
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Request
// ─────────────────────────────────────────────────────────────────────────────

/// Request to acquire or renew a lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRequest {
    /// The subject to lease.
    pub subject_object_id: ObjectId,

    /// What the lease is for.
    pub purpose: LeasePurpose,

    /// Zone context.
    pub zone_id: ZoneId,

    /// Requesting node.
    pub requester: TailscaleNodeId,

    /// Requested duration in seconds.
    pub requested_duration_secs: u64,

    /// If renewing, the current lease_seq being held.
    /// If None, this is a new lease request.
    pub current_lease_seq: Option<u64>,
}

/// Response to a lease request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LeaseResponse {
    /// Lease granted.
    Granted(Lease),

    /// Lease denied - another holder has it.
    Denied {
        /// Current lease holder.
        current_holder: TailscaleNodeId,
        /// When the current lease expires.
        expires_at: u64,
        /// Current lease_seq (for information).
        current_seq: u64,
    },

    /// Lease conflict detected (for dangerous operations).
    Conflict {
        /// The conflicting leases.
        conflicting_leases: Vec<LeaseConflictInfo>,
        /// Whether manual resolution is required.
        requires_manual_resolution: bool,
    },
}

/// Information about a conflicting lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseConflictInfo {
    /// Holder of the conflicting lease.
    pub holder: TailscaleNodeId,
    /// Lease sequence number.
    pub lease_seq: u64,
    /// Expiry time.
    pub exp: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// HRW Coordinator Selection (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute HRW (Highest Random Weight) hash for coordinator selection.
///
/// This provides deterministic, consistent coordinator selection without
/// a central coordinator.
fn hrw_hash(zone_id: &ZoneId, subject_id: &ObjectId, node_id: &TailscaleNodeId) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP2-HRW-V1");
    hasher.update(zone_id.as_bytes());
    hasher.update(subject_id.as_bytes());
    hasher.update(node_id.as_str().as_bytes());

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    // Take the first 8 bytes as a u64 for comparison
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Select the coordinator for a lease using HRW/Rendezvous hashing.
///
/// # Arguments
///
/// * `zone_id` - The zone context
/// * `subject_id` - The object being leased
/// * `nodes` - Available nodes in the zone
///
/// # Returns
///
/// The node with the highest HRW hash, or `None` if no nodes are available.
///
/// # Determinism
///
/// This function is fully deterministic - given the same inputs, all nodes
/// will select the same coordinator. This is essential for distributed
/// coordination without explicit communication.
#[must_use]
pub fn select_coordinator(
    zone_id: &ZoneId,
    subject_id: &ObjectId,
    nodes: &[TailscaleNodeId],
) -> Option<TailscaleNodeId> {
    nodes
        .iter()
        .max_by_key(|n| hrw_hash(zone_id, subject_id, n))
        .cloned()
}

/// Get all nodes ranked by HRW score for a subject.
///
/// This is useful for determining failover order when the primary
/// coordinator is unavailable.
#[must_use]
pub fn rank_nodes_by_hrw(
    zone_id: &ZoneId,
    subject_id: &ObjectId,
    nodes: &[TailscaleNodeId],
) -> Vec<TailscaleNodeId> {
    let mut scored: Vec<_> = nodes
        .iter()
        .map(|n| (hrw_hash(zone_id, subject_id, n), n.clone()))
        .collect();
    // Sort descending by score
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored.into_iter().map(|(_, n)| n).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when lease validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseValidationError {
    /// Lease has expired.
    Expired { expired_at: u64, now: u64 },

    /// Lease is for wrong subject.
    SubjectMismatch {
        expected: ObjectId,
        got: ObjectId,
    },

    /// Lease is for wrong zone.
    ZoneMismatch { expected: ZoneId, got: ZoneId },

    /// Lease is for wrong purpose.
    PurposeMismatch {
        expected: LeasePurpose,
        got: LeasePurpose,
    },

    /// Lease has been superseded by a newer lease.
    Superseded {
        held_seq: u64,
        current_seq: u64,
    },

    /// Coordinator mismatch (wrong coordinator signed).
    CoordinatorMismatch {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },

    /// Insufficient quorum signatures.
    InsufficientQuorum { required: usize, got: usize },
}

impl std::fmt::Display for LeaseValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired { expired_at, now } => {
                write!(f, "lease expired at {expired_at}, current time is {now}")
            }
            Self::SubjectMismatch { expected, got } => {
                write!(f, "subject mismatch: expected {expected}, got {got}")
            }
            Self::ZoneMismatch { expected, got } => {
                write!(f, "zone mismatch: expected {expected}, got {got}")
            }
            Self::PurposeMismatch { expected, got } => {
                write!(f, "purpose mismatch: expected {expected}, got {got}")
            }
            Self::Superseded {
                held_seq,
                current_seq,
            } => {
                write!(
                    f,
                    "lease superseded: held seq {held_seq}, current seq {current_seq}"
                )
            }
            Self::CoordinatorMismatch { expected, got } => {
                write!(f, "coordinator mismatch: expected {}, got {}", expected.as_str(), got.as_str())
            }
            Self::InsufficientQuorum { required, got } => {
                write!(
                    f,
                    "insufficient quorum: required {required} signatures, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for LeaseValidationError {}

/// Validate a lease for use.
///
/// # Arguments
///
/// * `lease` - The lease to validate
/// * `expected_subject` - Expected subject object ID
/// * `expected_zone` - Expected zone ID
/// * `expected_purpose` - Expected purpose
/// * `current_known_seq` - The highest lease_seq known for this subject
/// * `now` - Current timestamp
/// * `required_signatures` - Minimum required quorum signatures
///
/// # Errors
///
/// Returns an error if validation fails.
pub fn validate_lease(
    lease: &Lease,
    expected_subject: &ObjectId,
    expected_zone: &ZoneId,
    expected_purpose: LeasePurpose,
    current_known_seq: u64,
    now: u64,
    required_signatures: usize,
) -> Result<(), LeaseValidationError> {
    // Check expiry
    if lease.is_expired(now) {
        return Err(LeaseValidationError::Expired {
            expired_at: lease.exp,
            now,
        });
    }

    // Check subject
    if &lease.subject_object_id != expected_subject {
        return Err(LeaseValidationError::SubjectMismatch {
            expected: *expected_subject,
            got: lease.subject_object_id,
        });
    }

    // Check zone
    if lease.zone_id() != expected_zone {
        return Err(LeaseValidationError::ZoneMismatch {
            expected: expected_zone.clone(),
            got: lease.zone_id().clone(),
        });
    }

    // Check purpose
    if lease.purpose != expected_purpose {
        return Err(LeaseValidationError::PurposeMismatch {
            expected: expected_purpose,
            got: lease.purpose,
        });
    }

    // Check if superseded (NORMATIVE: higher seq wins)
    if lease.lease_seq < current_known_seq {
        return Err(LeaseValidationError::Superseded {
            held_seq: lease.lease_seq,
            current_seq: current_known_seq,
        });
    }

    // Check quorum
    let sig_count = lease.quorum_signatures.len();
    if sig_count < required_signatures {
        return Err(LeaseValidationError::InsufficientQuorum {
            required: required_signatures,
            got: sig_count,
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_object_id(name: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(name.as_bytes())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HRW Coordinator Selection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hrw_deterministic() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        // Same inputs should always produce same output
        let coord1 = select_coordinator(&zone, &subject, &nodes);
        let coord2 = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(coord1, coord2);

        // Should not be None with non-empty nodes
        assert!(coord1.is_some());
    }

    #[test]
    fn test_hrw_empty_nodes() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes: Vec<TailscaleNodeId> = vec![];

        assert!(select_coordinator(&zone, &subject, &nodes).is_none());
    }

    #[test]
    fn test_hrw_single_node() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![test_node("only-node")];

        let coord = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(coord, Some(test_node("only-node")));
    }

    #[test]
    fn test_hrw_different_subjects_different_coordinators() {
        let zone = test_zone();
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
            test_node("node-d"),
            test_node("node-e"),
        ];

        // Different subjects may (probabilistically) get different coordinators
        let subjects: Vec<_> = (0..20).map(|i| test_object_id(&format!("subject-{i}"))).collect();

        let coords: Vec<_> = subjects
            .iter()
            .map(|s| select_coordinator(&zone, s, &nodes))
            .collect();

        // Not all coordinators should be the same (with high probability)
        let first = &coords[0];
        let all_same = coords.iter().all(|c| c == first);

        // This is probabilistic but should pass with overwhelming probability
        assert!(
            !all_same,
            "HRW should distribute load across nodes"
        );
    }

    #[test]
    fn test_rank_nodes_ordering() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);

        // Ranked should have same length as input
        assert_eq!(ranked.len(), nodes.len());

        // First ranked node should be the coordinator
        let coord = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(Some(&ranked[0]), coord.as_ref());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Priority Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_priority_higher_seq_wins() {
        let header = create_test_header();
        let subject = test_object_id("subject");

        let lease1 = Lease {
            header: header.clone(),
            subject_object_id: subject.clone(),
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 10,
            owner_node: test_node("node-a"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        let lease2 = Lease {
            header: header.clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 20,
            owner_node: test_node("node-b"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        // Higher seq wins
        assert!(lease2.supersedes(&lease1));
        assert!(!lease1.supersedes(&lease2));
        assert_eq!(lease1.compare_priority(&lease2), Ordering::Less);
        assert_eq!(lease2.compare_priority(&lease1), Ordering::Greater);
    }

    #[test]
    fn test_lease_priority_equal_seq() {
        let header = create_test_header();
        let subject = test_object_id("subject");

        let lease1 = Lease {
            header: header.clone(),
            subject_object_id: subject.clone(),
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 10,
            owner_node: test_node("node-a"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        let lease2 = Lease {
            header,
            subject_object_id: subject,
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 10,
            owner_node: test_node("node-b"),
            iat: 1000,
            exp: 3000, // Different expiry, but same seq
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        // Same seq = equal priority (neither supersedes)
        assert!(!lease1.supersedes(&lease2));
        assert!(!lease2.supersedes(&lease1));
        assert_eq!(lease1.compare_priority(&lease2), Ordering::Equal);
    }

    #[test]
    fn test_lease_expiry() {
        let header = create_test_header();
        let subject = test_object_id("subject");

        let lease = Lease {
            header,
            subject_object_id: subject,
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 1,
            owner_node: test_node("node-a"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        // Before expiry
        assert!(!lease.is_expired(1500));
        assert!(lease.is_active(1500));

        // At expiry
        assert!(lease.is_expired(2000));
        assert!(!lease.is_active(2000));

        // After expiry
        assert!(lease.is_expired(2500));
        assert!(!lease.is_active(2500));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_lease_success() {
        let header = create_test_header();
        let subject = test_object_id("subject");
        let zone = test_zone();

        let lease = Lease {
            header,
            subject_object_id: subject.clone(),
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 5,
            owner_node: test_node("node-a"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5, // current_known_seq
            1500, // now (before expiry)
            0, // no signatures required
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_lease_expired() {
        let header = create_test_header();
        let subject = test_object_id("subject");
        let zone = test_zone();

        let lease = Lease {
            header,
            subject_object_id: subject.clone(),
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 5,
            owner_node: test_node("node-a"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            2500, // now > exp
            0,
        );

        assert!(matches!(result, Err(LeaseValidationError::Expired { .. })));
    }

    #[test]
    fn test_validate_lease_superseded() {
        let header = create_test_header();
        let subject = test_object_id("subject");
        let zone = test_zone();

        let lease = Lease {
            header,
            subject_object_id: subject.clone(),
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 5,
            owner_node: test_node("node-a"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // current_known_seq > lease.lease_seq
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::Superseded { .. })
        ));
    }

    #[test]
    fn test_validate_lease_purpose_mismatch() {
        let header = create_test_header();
        let subject = test_object_id("subject");
        let zone = test_zone();

        let lease = Lease {
            header,
            subject_object_id: subject.clone(),
            purpose: LeasePurpose::OperationExecution,
            lease_seq: 5,
            owner_node: test_node("node-a"),
            iat: 1000,
            exp: 2000,
            coordinator: test_node("coord"),
            quorum_signatures: SignatureSet::default(),
        };

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::ConnectorStateWrite, // Wrong purpose
            5,
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::PurposeMismatch { .. })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeasePurpose Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_purpose_display() {
        assert_eq!(
            LeasePurpose::OperationExecution.to_string(),
            "operation_execution"
        );
        assert_eq!(
            LeasePurpose::ConnectorStateWrite.to_string(),
            "connector_state_write"
        );
        assert_eq!(
            LeasePurpose::ComputationMigration.to_string(),
            "computation_migration"
        );
    }

    #[test]
    fn test_lease_purpose_serde() {
        let purposes = [
            LeasePurpose::OperationExecution,
            LeasePurpose::ConnectorStateWrite,
            LeasePurpose::ComputationMigration,
        ];

        for purpose in purposes {
            let json = serde_json::to_string(&purpose).unwrap();
            let deserialized: LeasePurpose = serde_json::from_str(&json).unwrap();
            assert_eq!(purpose, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Functions
    // ─────────────────────────────────────────────────────────────────────────

    fn create_test_header() -> ObjectHeader {
        use fcp_cbor::SchemaId;
        use semver::Version;
        use crate::Provenance;

        let zone = test_zone();
        ObjectHeader {
            schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            created_at: 1000,
            provenance: Provenance::new(zone),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }
}

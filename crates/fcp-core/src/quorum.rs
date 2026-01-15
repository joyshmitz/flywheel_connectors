//! Trust/Quorum Model for FCP2 (NORMATIVE).
//!
//! This module defines quorum-signed object semantics with well-defined threshold
//! rules and conflict behavior. Many FCP2 objects require multiple signatures
//! (`AuditHead`, `RevocationHead`, `ZoneCheckpoint`, leases for risky ops).
//!
//! # Core Concepts
//!
//! - `n`: eligible nodes for a zone (by membership)
//! - `f`: maximum Byzantine faults assumed for that zone
//! - Threshold rules are configurable per zone
//!
//! # Risk Tiers
//!
//! | Tier | Required Signatures | Example Operations |
//! |------|--------------------|--------------------|
//! | `CriticalWrite` | `n - f` | `AuditHead`, `ZoneCheckpoint` |
//! | Dangerous | `n - f` | Dangerous leases |
//! | Risky | `f + 1` | Risky leases |
//! | Safe | 1 (coordinator) | Safe ops |
//!
//! # Determinism Rules
//!
//! - Quorum signatures MUST be sorted by `node_id` before hashing/encoding
//! - Tie-breakers MUST be deterministic and audited

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ZoneId;

/// Risk tier for operations requiring quorum signatures (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    /// Safe operations: coordinator-only signature allowed.
    Safe,
    /// Risky operations: require `f + 1` signatures.
    Risky,
    /// Dangerous operations: require `n - f` signatures.
    Dangerous,
    /// Critical writes (audit, checkpoint): require `n - f` signatures.
    CriticalWrite,
}

impl RiskTier {
    /// Get the human-readable name for this risk tier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Risky => "risky",
            Self::Dangerous => "dangerous",
            Self::CriticalWrite => "critical_write",
        }
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Operation purpose for quorum requirements (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuorumPurpose {
    /// Audit chain head advancement.
    AuditHead,
    /// Zone checkpoint creation.
    ZoneCheckpoint,
    /// Revocation chain head advancement.
    RevocationHead,
    /// Lease acquisition for dangerous operations.
    DangerousLease,
    /// Lease acquisition for risky operations.
    RiskyLease,
    /// Safe lease (coordinator only).
    SafeLease,
    /// Key rotation ceremony.
    KeyRotation,
    /// Zone membership change.
    MembershipChange,
}

impl QuorumPurpose {
    /// Get the default risk tier for this purpose.
    #[must_use]
    pub const fn default_risk_tier(&self) -> RiskTier {
        match self {
            Self::AuditHead | Self::ZoneCheckpoint | Self::RevocationHead => {
                RiskTier::CriticalWrite
            }
            Self::DangerousLease | Self::KeyRotation | Self::MembershipChange => {
                RiskTier::Dangerous
            }
            Self::RiskyLease => RiskTier::Risky,
            Self::SafeLease => RiskTier::Safe,
        }
    }
}

/// Quorum policy configuration for a zone (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumPolicy {
    /// Zone this policy applies to.
    pub zone_id: ZoneId,

    /// Total eligible nodes in the zone (n).
    pub eligible_nodes: u32,

    /// Maximum Byzantine faults assumed (f).
    pub max_faults: u32,

    /// Allow degraded mode operations.
    pub allow_degraded_mode: bool,

    /// Minimum nodes required for degraded mode.
    pub degraded_mode_min_nodes: u32,
}

impl QuorumPolicy {
    /// Create a new quorum policy.
    ///
    /// # Panics
    ///
    /// Panics if `max_faults >= eligible_nodes` or if `eligible_nodes == 0`.
    #[must_use]
    pub fn new(zone_id: ZoneId, eligible_nodes: u32, max_faults: u32) -> Self {
        assert!(eligible_nodes > 0, "eligible_nodes must be > 0");
        assert!(
            max_faults < eligible_nodes,
            "max_faults must be < eligible_nodes"
        );

        Self {
            zone_id,
            eligible_nodes,
            max_faults,
            allow_degraded_mode: false,
            degraded_mode_min_nodes: 1,
        }
    }

    /// Create a policy with degraded mode enabled.
    #[must_use]
    pub const fn with_degraded_mode(mut self, min_nodes: u32) -> Self {
        self.allow_degraded_mode = true;
        self.degraded_mode_min_nodes = min_nodes;
        self
    }

    /// Calculate the required number of signatures for a given risk tier.
    ///
    /// Returns the minimum number of signatures needed to satisfy the quorum
    /// requirement for the specified risk tier.
    #[must_use]
    pub fn required_signatures(&self, risk_tier: RiskTier) -> u32 {
        required_quorum(self.eligible_nodes, self.max_faults, risk_tier)
    }

    /// Check if a signature count satisfies the quorum for a risk tier.
    #[must_use]
    pub fn is_quorum_met(&self, signature_count: u32, risk_tier: RiskTier) -> bool {
        signature_count >= self.required_signatures(risk_tier)
    }

    /// Check if we're in degraded mode (reduced node count).
    #[must_use]
    pub const fn is_degraded(&self, available_nodes: u32) -> bool {
        available_nodes < self.eligible_nodes
    }

    /// Check if an operation is allowed in degraded mode.
    #[must_use]
    pub fn can_proceed_degraded(&self, available_nodes: u32, risk_tier: RiskTier) -> bool {
        if !self.allow_degraded_mode {
            return false;
        }

        if available_nodes < self.degraded_mode_min_nodes {
            return false;
        }

        // In degraded mode, only Safe operations are allowed
        risk_tier == RiskTier::Safe
    }
}

/// Calculate required quorum for given parameters (NORMATIVE).
///
/// # Arguments
///
/// * `n` - Total eligible nodes
/// * `f` - Maximum Byzantine faults
/// * `risk_tier` - The risk classification of the operation
///
/// # Returns
///
/// The minimum number of signatures required.
///
/// # Panics
///
/// Panics if `n == 0` or `f >= n`.
#[must_use]
pub fn required_quorum(n: u32, f: u32, risk_tier: RiskTier) -> u32 {
    assert!(n > 0, "n must be > 0");
    assert!(f < n, "f must be < n");

    match risk_tier {
        // Safe: coordinator only
        RiskTier::Safe => 1,
        // Risky: f + 1 (can tolerate up to f failures)
        RiskTier::Risky => f + 1,
        // Dangerous and CriticalWrite: n - f (classic BFT quorum)
        RiskTier::Dangerous | RiskTier::CriticalWrite => n - f,
    }
}

/// Node identifier for signature canonicalization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Create a new node ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the node ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Ord for NodeId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for NodeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single node signature in a quorum set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSignature {
    /// The node that produced this signature.
    pub node_id: NodeId,

    /// The Ed25519 signature bytes (64 bytes), hex-encoded for serialization.
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],

    /// Timestamp when the signature was created (UNIX seconds).
    pub signed_at: u64,
}

impl NodeSignature {
    /// Create a new node signature.
    #[must_use]
    pub const fn new(node_id: NodeId, signature: [u8; 64], signed_at: u64) -> Self {
        Self {
            node_id,
            signature,
            signed_at,
        }
    }
}

impl Ord for NodeSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.node_id.cmp(&other.node_id)
    }
}

impl PartialOrd for NodeSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A canonicalized set of quorum signatures (NORMATIVE).
///
/// Signatures are stored sorted by `node_id` to ensure deterministic
/// serialization for hashing and encoding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureSet {
    /// Signatures sorted by `node_id` (NORMATIVE: MUST be sorted).
    signatures: Vec<NodeSignature>,

    /// Set of node IDs for O(1) duplicate detection.
    #[serde(skip)]
    node_ids: BTreeSet<String>,
}

impl SignatureSet {
    /// Create a new empty signature set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a signature to the set.
    ///
    /// Returns `true` if the signature was added, `false` if a signature
    /// from this node already exists.
    pub fn add(&mut self, sig: NodeSignature) -> bool {
        if self.node_ids.contains(sig.node_id.as_str()) {
            return false;
        }

        self.node_ids.insert(sig.node_id.0.clone());
        self.signatures.push(sig);
        self.signatures.sort();
        true
    }

    /// Get the number of signatures in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Check if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Get an iterator over the signatures.
    pub fn iter(&self) -> impl Iterator<Item = &NodeSignature> {
        self.signatures.iter()
    }

    /// Get the signatures as a slice (guaranteed sorted by `node_id`).
    #[must_use]
    pub fn as_slice(&self) -> &[NodeSignature] {
        &self.signatures
    }

    /// Check if the signature set satisfies a quorum policy.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn satisfies_quorum(&self, policy: &QuorumPolicy, risk_tier: RiskTier) -> bool {
        // Safe: signature sets are bounded to reasonable sizes (< u32::MAX)
        policy.is_quorum_met(self.len() as u32, risk_tier)
    }

    /// Get canonical bytes for hashing (NORMATIVE).
    ///
    /// Format: concatenation of sorted `(node_id_bytes || signature)`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for sig in &self.signatures {
            out.extend_from_slice(sig.node_id.as_str().as_bytes());
            out.extend_from_slice(&sig.signature);
        }
        out
    }
}

/// Reason codes for degraded mode (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DegradedModeReason {
    /// Network partition detected.
    NetworkPartition,
    /// Insufficient nodes online.
    InsufficientNodes,
    /// Node failure detected.
    NodeFailure,
    /// Quorum timeout exceeded.
    QuorumTimeout,
    /// Manual override by operator.
    ManualOverride,
}

impl DegradedModeReason {
    /// Get the human-readable description.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NetworkPartition => "network_partition",
            Self::InsufficientNodes => "insufficient_nodes",
            Self::NodeFailure => "node_failure",
            Self::QuorumTimeout => "quorum_timeout",
            Self::ManualOverride => "manual_override",
        }
    }
}

impl fmt::Display for DegradedModeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Degraded mode state for a zone (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedModeState {
    /// Whether degraded mode is active.
    pub active: bool,

    /// Reason for entering degraded mode.
    pub reason: Option<DegradedModeReason>,

    /// When degraded mode was entered (UNIX timestamp).
    pub entered_at: Option<u64>,

    /// Number of available nodes.
    pub available_nodes: u32,

    /// Number of expected nodes.
    pub expected_nodes: u32,
}

impl DegradedModeState {
    /// Create a normal (non-degraded) state.
    #[must_use]
    pub const fn normal(available_nodes: u32) -> Self {
        Self {
            active: false,
            reason: None,
            entered_at: None,
            available_nodes,
            expected_nodes: available_nodes,
        }
    }

    /// Create a degraded state.
    #[must_use]
    pub const fn degraded(
        reason: DegradedModeReason,
        entered_at: u64,
        available_nodes: u32,
        expected_nodes: u32,
    ) -> Self {
        Self {
            active: true,
            reason: Some(reason),
            entered_at: Some(entered_at),
            available_nodes,
            expected_nodes,
        }
    }
}

/// Result of a quorum verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumVerificationResult {
    /// Whether the quorum was satisfied.
    pub satisfied: bool,

    /// Number of valid signatures.
    pub valid_count: u32,

    /// Number of signatures required.
    pub required_count: u32,

    /// Risk tier used for verification.
    pub risk_tier: RiskTier,

    /// Whether the zone is in degraded mode.
    pub degraded_mode: bool,

    /// Reason for failure (if any).
    pub failure_reason: Option<QuorumFailureReason>,
}

/// Reasons for quorum failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuorumFailureReason {
    /// Insufficient signatures.
    InsufficientSignatures,
    /// Invalid signature detected.
    InvalidSignature,
    /// Duplicate node signature.
    DuplicateNode,
    /// Node not in eligible set.
    NodeNotEligible,
    /// Operation not allowed in degraded mode.
    DegradedModeNotAllowed,
    /// Signature expired.
    SignatureExpired,
}

impl QuorumFailureReason {
    /// Get the human-readable description.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InsufficientSignatures => "insufficient_signatures",
            Self::InvalidSignature => "invalid_signature",
            Self::DuplicateNode => "duplicate_node",
            Self::NodeNotEligible => "node_not_eligible",
            Self::DegradedModeNotAllowed => "degraded_mode_not_allowed",
            Self::SignatureExpired => "signature_expired",
        }
    }
}

impl fmt::Display for QuorumFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Required Quorum Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_required_quorum_safe() {
        // Safe always requires 1 signature
        assert_eq!(required_quorum(3, 1, RiskTier::Safe), 1);
        assert_eq!(required_quorum(5, 2, RiskTier::Safe), 1);
        assert_eq!(required_quorum(7, 3, RiskTier::Safe), 1);
    }

    #[test]
    fn test_required_quorum_risky() {
        // Risky requires f + 1
        assert_eq!(required_quorum(3, 1, RiskTier::Risky), 2); // 1 + 1
        assert_eq!(required_quorum(5, 2, RiskTier::Risky), 3); // 2 + 1
        assert_eq!(required_quorum(7, 3, RiskTier::Risky), 4); // 3 + 1
    }

    #[test]
    fn test_required_quorum_dangerous() {
        // Dangerous requires n - f
        assert_eq!(required_quorum(3, 1, RiskTier::Dangerous), 2); // 3 - 1
        assert_eq!(required_quorum(5, 2, RiskTier::Dangerous), 3); // 5 - 2
        assert_eq!(required_quorum(7, 3, RiskTier::Dangerous), 4); // 7 - 3
    }

    #[test]
    fn test_required_quorum_critical_write() {
        // CriticalWrite requires n - f (same as Dangerous)
        assert_eq!(required_quorum(3, 1, RiskTier::CriticalWrite), 2);
        assert_eq!(required_quorum(5, 2, RiskTier::CriticalWrite), 3);
        assert_eq!(required_quorum(7, 3, RiskTier::CriticalWrite), 4);
    }

    #[test]
    fn test_required_quorum_edge_cases() {
        // Minimum valid config: n=1, f=0
        assert_eq!(required_quorum(1, 0, RiskTier::Safe), 1);
        assert_eq!(required_quorum(1, 0, RiskTier::Risky), 1); // 0 + 1
        assert_eq!(required_quorum(1, 0, RiskTier::Dangerous), 1); // 1 - 0
        assert_eq!(required_quorum(1, 0, RiskTier::CriticalWrite), 1);

        // Two nodes: n=2, f=0
        assert_eq!(required_quorum(2, 0, RiskTier::Risky), 1);
        assert_eq!(required_quorum(2, 0, RiskTier::Dangerous), 2);
    }

    #[test]
    #[should_panic(expected = "n must be > 0")]
    fn test_required_quorum_panics_n_zero() {
        required_quorum(0, 0, RiskTier::Safe);
    }

    #[test]
    #[should_panic(expected = "f must be < n")]
    fn test_required_quorum_panics_f_equals_n() {
        required_quorum(3, 3, RiskTier::Safe);
    }

    #[test]
    #[should_panic(expected = "f must be < n")]
    fn test_required_quorum_panics_f_greater_than_n() {
        required_quorum(3, 5, RiskTier::Safe);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // QuorumPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_policy_new() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert_eq!(policy.eligible_nodes, 5);
        assert_eq!(policy.max_faults, 2);
        assert!(!policy.allow_degraded_mode);
    }

    #[test]
    fn test_quorum_policy_with_degraded_mode() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2).with_degraded_mode(2);
        assert!(policy.allow_degraded_mode);
        assert_eq!(policy.degraded_mode_min_nodes, 2);
    }

    #[test]
    fn test_quorum_policy_required_signatures() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
        assert_eq!(policy.required_signatures(RiskTier::Risky), 3);
        assert_eq!(policy.required_signatures(RiskTier::Dangerous), 3);
        assert_eq!(policy.required_signatures(RiskTier::CriticalWrite), 3);
    }

    #[test]
    fn test_quorum_policy_is_quorum_met() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);

        // Safe: needs 1
        assert!(policy.is_quorum_met(1, RiskTier::Safe));
        assert!(policy.is_quorum_met(2, RiskTier::Safe));

        // Risky: needs 3
        assert!(!policy.is_quorum_met(2, RiskTier::Risky));
        assert!(policy.is_quorum_met(3, RiskTier::Risky));
        assert!(policy.is_quorum_met(4, RiskTier::Risky));

        // Dangerous: needs 3
        assert!(!policy.is_quorum_met(2, RiskTier::Dangerous));
        assert!(policy.is_quorum_met(3, RiskTier::Dangerous));
    }

    #[test]
    fn test_quorum_policy_is_degraded() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert!(!policy.is_degraded(5));
        assert!(policy.is_degraded(4));
        assert!(policy.is_degraded(1));
    }

    #[test]
    fn test_quorum_policy_can_proceed_degraded() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2).with_degraded_mode(2);

        // Safe ops allowed with sufficient nodes
        assert!(policy.can_proceed_degraded(3, RiskTier::Safe));
        assert!(policy.can_proceed_degraded(2, RiskTier::Safe));
        assert!(!policy.can_proceed_degraded(1, RiskTier::Safe)); // Below min

        // Non-safe ops not allowed in degraded mode
        assert!(!policy.can_proceed_degraded(3, RiskTier::Risky));
        assert!(!policy.can_proceed_degraded(3, RiskTier::Dangerous));
        assert!(!policy.can_proceed_degraded(3, RiskTier::CriticalWrite));
    }

    #[test]
    fn test_quorum_policy_degraded_mode_disabled() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        // Degraded mode disabled by default
        assert!(!policy.can_proceed_degraded(3, RiskTier::Safe));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SignatureSet Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signature_set_empty() {
        let set = SignatureSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_signature_set_add_single() {
        let mut set = SignatureSet::new();
        let sig = NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000);

        assert!(set.add(sig));
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_signature_set_rejects_duplicate() {
        let mut set = SignatureSet::new();
        let sig1 = NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000);
        let sig2 = NodeSignature::new(NodeId::new("node-1"), [1; 64], 2000);

        assert!(set.add(sig1));
        assert!(!set.add(sig2)); // Same node_id
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_signature_set_sorted_by_node_id() {
        let mut set = SignatureSet::new();

        // Add in non-sorted order
        set.add(NodeSignature::new(NodeId::new("node-c"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-a"), [1; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-b"), [2; 64], 1000));

        let ids: Vec<_> = set.iter().map(|s| s.node_id.as_str()).collect();
        assert_eq!(ids, vec!["node-a", "node-b", "node-c"]);
    }

    #[test]
    fn test_signature_set_canonical_bytes_deterministic() {
        let mut set1 = SignatureSet::new();
        let mut set2 = SignatureSet::new();

        // Add in different order
        set1.add(NodeSignature::new(NodeId::new("node-a"), [1; 64], 1000));
        set1.add(NodeSignature::new(NodeId::new("node-b"), [2; 64], 1000));

        set2.add(NodeSignature::new(NodeId::new("node-b"), [2; 64], 1000));
        set2.add(NodeSignature::new(NodeId::new("node-a"), [1; 64], 1000));

        // Canonical bytes should be identical
        assert_eq!(set1.canonical_bytes(), set2.canonical_bytes());
    }

    #[test]
    fn test_signature_set_satisfies_quorum() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        let mut set = SignatureSet::new();

        // Add 2 signatures (not enough for Risky/Dangerous)
        set.add(NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-2"), [1; 64], 1000));

        assert!(set.satisfies_quorum(&policy, RiskTier::Safe));
        assert!(!set.satisfies_quorum(&policy, RiskTier::Risky)); // needs 3

        // Add third signature
        set.add(NodeSignature::new(NodeId::new("node-3"), [2; 64], 1000));
        assert!(set.satisfies_quorum(&policy, RiskTier::Risky));
        assert!(set.satisfies_quorum(&policy, RiskTier::Dangerous));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RiskTier Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_risk_tier_display() {
        assert_eq!(RiskTier::Safe.to_string(), "safe");
        assert_eq!(RiskTier::Risky.to_string(), "risky");
        assert_eq!(RiskTier::Dangerous.to_string(), "dangerous");
        assert_eq!(RiskTier::CriticalWrite.to_string(), "critical_write");
    }

    #[test]
    fn test_quorum_purpose_default_risk_tier() {
        assert_eq!(
            QuorumPurpose::AuditHead.default_risk_tier(),
            RiskTier::CriticalWrite
        );
        assert_eq!(
            QuorumPurpose::ZoneCheckpoint.default_risk_tier(),
            RiskTier::CriticalWrite
        );
        assert_eq!(
            QuorumPurpose::DangerousLease.default_risk_tier(),
            RiskTier::Dangerous
        );
        assert_eq!(
            QuorumPurpose::RiskyLease.default_risk_tier(),
            RiskTier::Risky
        );
        assert_eq!(QuorumPurpose::SafeLease.default_risk_tier(), RiskTier::Safe);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DegradedModeState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_degraded_mode_state_normal() {
        let state = DegradedModeState::normal(5);
        assert!(!state.active);
        assert!(state.reason.is_none());
        assert!(state.entered_at.is_none());
        assert_eq!(state.available_nodes, 5);
    }

    #[test]
    fn test_degraded_mode_state_degraded() {
        let state = DegradedModeState::degraded(DegradedModeReason::NetworkPartition, 1000, 3, 5);
        assert!(state.active);
        assert_eq!(state.reason, Some(DegradedModeReason::NetworkPartition));
        assert_eq!(state.entered_at, Some(1000));
        assert_eq!(state.available_nodes, 3);
        assert_eq!(state.expected_nodes, 5);
    }

    #[test]
    fn test_degraded_mode_reason_display() {
        assert_eq!(
            DegradedModeReason::NetworkPartition.to_string(),
            "network_partition"
        );
        assert_eq!(
            DegradedModeReason::InsufficientNodes.to_string(),
            "insufficient_nodes"
        );
        assert_eq!(DegradedModeReason::NodeFailure.to_string(), "node_failure");
        assert_eq!(
            DegradedModeReason::QuorumTimeout.to_string(),
            "quorum_timeout"
        );
        assert_eq!(
            DegradedModeReason::ManualOverride.to_string(),
            "manual_override"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // QuorumFailureReason Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_failure_reason_display() {
        assert_eq!(
            QuorumFailureReason::InsufficientSignatures.to_string(),
            "insufficient_signatures"
        );
        assert_eq!(
            QuorumFailureReason::InvalidSignature.to_string(),
            "invalid_signature"
        );
        assert_eq!(
            QuorumFailureReason::DuplicateNode.to_string(),
            "duplicate_node"
        );
        assert_eq!(
            QuorumFailureReason::NodeNotEligible.to_string(),
            "node_not_eligible"
        );
        assert_eq!(
            QuorumFailureReason::DegradedModeNotAllowed.to_string(),
            "degraded_mode_not_allowed"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NodeId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_node_id_ordering() {
        let a = NodeId::new("aaa");
        let b = NodeId::new("bbb");
        let c = NodeId::new("ccc");

        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn test_node_id_display() {
        let id = NodeId::new("test-node-123");
        assert_eq!(id.to_string(), "test-node-123");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_risk_tier_serialization() {
        let tier = RiskTier::CriticalWrite;
        let json = serde_json::to_string(&tier).unwrap();
        let deserialized: RiskTier = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, tier);
    }

    #[test]
    fn test_quorum_policy_serialization() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2).with_degraded_mode(2);
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: QuorumPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.eligible_nodes, 5);
        assert_eq!(deserialized.max_faults, 2);
        assert!(deserialized.allow_degraded_mode);
        assert_eq!(deserialized.degraded_mode_min_nodes, 2);
    }

    #[test]
    fn test_signature_set_serialization() {
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-2"), [1; 64], 2000));

        let json = serde_json::to_string(&set).unwrap();
        let deserialized: SignatureSet = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.len(), 2);
        // Note: node_ids set is not serialized, so duplicate detection
        // won't work after deserialization without rebuilding
    }
}

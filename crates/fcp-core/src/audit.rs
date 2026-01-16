//! Audit, Explainability, and Tracing types for FCP2 (NORMATIVE).
//!
//! This module implements the audit and explainability system from `FCP_Specification_V2.md` §14.4.
//! Audit events provide an append-only, hash-linked chain for compliance and forensics.
//!
//! # Core Concepts
//!
//! - `AuditEvent`: Hash-linked, append-only chain node with monotonic sequence
//! - `AuditHead`: Quorum-signed checkpoint of audit chain head for O(1) freshness
//! - `ZoneCheckpoint`: Zone state snapshot for fast sync and garbage collection
//! - `DecisionReceipt`: Explainable allow/deny decision with evidence references
//! - `TraceContext`: W3C-compatible distributed tracing context
//!
//! # Hash-Linking
//!
//! Each `AuditEvent` contains:
//! - `prev`: `ObjectId` of the previous event (None for genesis)
//! - `seq`: Monotonically increasing sequence number
//!
//! This enables:
//! - Tamper detection (any modification breaks the chain)
//! - O(1) freshness comparison via sequence numbers
//! - Efficient sync by comparing head sequences
//!
//! # Decision Receipts
//!
//! Every policy decision MUST produce a `DecisionReceipt` that includes:
//! - The decision (Allow/Deny)
//! - Reason code for categorization
//! - Evidence `ObjectId`s that influenced the decision
//! - Optional human-readable explanation
//!
//! This ensures all access control decisions are auditable and explainable.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capability::{ConnectorId, OperationId, PrincipalId};
use crate::revocation::EpochId;
use crate::{ObjectHeader, ObjectId, QuorumPolicy, RiskTier, SignatureSet, ZoneId};

// ─────────────────────────────────────────────────────────────────────────────
// TraceContext (W3C Compatible)
// ─────────────────────────────────────────────────────────────────────────────

/// W3C Trace Context for distributed tracing (NORMATIVE).
///
/// Implements the W3C Trace Context specification for correlation across
/// services and mesh nodes. This enables integration with standard observability
/// tooling (Jaeger, Zipkin, OpenTelemetry).
///
/// # Format
///
/// The trace context follows W3C format:
/// - `trace_id`: 16-byte unique identifier for the entire trace
/// - `span_id`: 8-byte unique identifier for this span
/// - `flags`: Trace flags (bit 0 = sampled)
///
/// # Usage
///
/// ```ignore
/// let ctx = TraceContext::new();
/// let child = ctx.new_child_span();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceContext {
    /// 128-bit trace identifier (unique across the distributed trace).
    #[serde(with = "hex::serde")]
    pub trace_id: [u8; 16],

    /// 64-bit span identifier (unique within this trace).
    #[serde(with = "hex::serde")]
    pub span_id: [u8; 8],

    /// Trace flags (bit 0 = sampled).
    pub flags: u8,
}

impl TraceContext {
    /// Create a new trace context with random IDs.
    #[must_use]
    pub fn new() -> Self {
        let uuid_bytes = Uuid::new_v4().into_bytes();
        Self {
            trace_id: uuid_bytes,
            span_id: uuid_bytes[0..8].try_into().expect("slice is 8 bytes"),
            flags: 0x01, // Sampled by default
        }
    }

    /// Create a new child span within the same trace.
    #[must_use]
    pub fn new_child_span(&self) -> Self {
        let span_bytes = Uuid::new_v4().into_bytes();
        Self {
            trace_id: self.trace_id,
            span_id: span_bytes[0..8].try_into().expect("slice is 8 bytes"),
            flags: self.flags,
        }
    }

    /// Check if this trace is sampled.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Set the sampled flag.
    pub fn set_sampled(&mut self, sampled: bool) {
        if sampled {
            self.flags |= 0x01;
        } else {
            self.flags &= !0x01;
        }
    }

    /// Format as W3C traceparent header value.
    ///
    /// Format: `{version}-{trace_id}-{span_id}-{flags}`
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            hex::encode(self.trace_id),
            hex::encode(self.span_id),
            self.flags
        )
    }

    /// Parse from W3C traceparent header value.
    ///
    /// # Errors
    ///
    /// Returns `None` if the format is invalid.
    #[must_use]
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        // Version must be "00"
        if parts[0] != "00" {
            return None;
        }

        let trace_id: [u8; 16] = hex::decode(parts[1]).ok()?.try_into().ok()?;
        let span_id: [u8; 8] = hex::decode(parts[2]).ok()?.try_into().ok()?;
        let flags = u8::from_str_radix(parts[3], 16).ok()?;

        Some(Self {
            trace_id,
            span_id,
            flags,
        })
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_traceparent())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEventType
// ─────────────────────────────────────────────────────────────────────────────

/// Type of audit event (NORMATIVE).
///
/// Categorizes audit events for filtering and analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Capability token was minted.
    CapabilityMinted,

    /// Capability token was used (invocation).
    CapabilityUsed,

    /// Capability token was revoked.
    CapabilityRevoked,

    /// Policy decision was made.
    PolicyDecision,

    /// Zone crossing occurred.
    ZoneCrossing,

    /// Data transformation applied.
    DataTransform,

    /// Elevation was granted.
    ElevationGranted,

    /// Declassification was granted.
    DeclassificationGranted,

    /// Sanitizer processed input.
    SanitizerApplied,

    /// Session was established.
    SessionEstablished,

    /// Session was terminated.
    SessionTerminated,

    /// Connector invocation completed.
    ConnectorInvocation,

    /// Object was created.
    ObjectCreated,

    /// Object was accessed.
    ObjectAccessed,

    /// Error or failure occurred.
    Error,

    /// Custom event type (for extensibility).
    Custom(String),
}

impl AuditEventType {
    /// Get the canonical string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::CapabilityMinted => "capability_minted",
            Self::CapabilityUsed => "capability_used",
            Self::CapabilityRevoked => "capability_revoked",
            Self::PolicyDecision => "policy_decision",
            Self::ZoneCrossing => "zone_crossing",
            Self::DataTransform => "data_transform",
            Self::ElevationGranted => "elevation_granted",
            Self::DeclassificationGranted => "declassification_granted",
            Self::SanitizerApplied => "sanitizer_applied",
            Self::SessionEstablished => "session_established",
            Self::SessionTerminated => "session_terminated",
            Self::ConnectorInvocation => "connector_invocation",
            Self::ObjectCreated => "object_created",
            Self::ObjectAccessed => "object_accessed",
            Self::Error => "error",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Check if this event type is security-sensitive.
    #[must_use]
    pub const fn is_security_sensitive(&self) -> bool {
        matches!(
            self,
            Self::CapabilityMinted
                | Self::CapabilityRevoked
                | Self::PolicyDecision
                | Self::ZoneCrossing
                | Self::ElevationGranted
                | Self::DeclassificationGranted
                | Self::Error
        )
    }
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEvent
// ─────────────────────────────────────────────────────────────────────────────

/// Audit event chain node (NORMATIVE).
///
/// Links audit events into a hash-chain with monotonic sequence numbers.
/// This is the core primitive for the FCP audit log.
///
/// # Chain Integrity
///
/// Each event contains:
/// - `prev`: Hash of the previous event (None for genesis)
/// - `seq`: Monotonically increasing sequence number
///
/// Verifiers MUST check that:
/// 1. `seq` is exactly `prev.seq + 1` (or 0 for genesis)
/// 2. `prev` matches the actual hash of the previous event
///
/// # Correlation
///
/// Events are correlated using:
/// - `correlation_id`: Groups related events within a request flow
/// - `trace_context`: W3C trace context for distributed tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Object header with zone, schema, and provenance.
    pub header: ObjectHeader,

    /// Correlation ID for grouping related events.
    #[serde(with = "hex::serde")]
    pub correlation_id: [u8; 16],

    /// W3C trace context for distributed tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,

    /// Type of audit event.
    pub event_type: AuditEventType,

    /// Actor who triggered the event.
    pub actor: PrincipalId,

    /// Zone where the event occurred.
    pub zone_id: ZoneId,

    /// Connector involved (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,

    /// Operation invoked (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationId>,

    /// Capability token JTI used (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token_jti: Option<Uuid>,

    /// Request object that triggered this event (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_id: Option<ObjectId>,

    /// Result object produced by this event (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_object_id: Option<ObjectId>,

    /// Previous event in the chain (None for genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,

    /// Monotonic sequence number for O(1) freshness comparison.
    pub seq: u64,

    /// When the event occurred (UNIX timestamp seconds).
    pub occurred_at: u64,

    /// Event-specific metadata (JSON-serializable).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,

    /// Signature over the event (Ed25519, from the issuing node).
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

impl AuditEvent {
    /// Check if this event follows another event in the chain.
    ///
    /// # Arguments
    ///
    /// * `other` - The event that should precede this one
    /// * `other_id` - The `ObjectId` of `other`
    ///
    /// # Returns
    ///
    /// `true` if this event's `prev` points to `other_id` and this event's
    /// sequence number is exactly one greater than `other`'s.
    #[must_use]
    pub fn follows(&self, other: &Self, other_id: &ObjectId) -> bool {
        other
            .seq
            .checked_add(1)
            .is_some_and(|next_seq| self.seq == next_seq)
            && self.prev.as_ref() == Some(other_id)
    }

    /// Check if this is a genesis event (first in chain).
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.prev.is_none() && self.seq == 0
    }

    /// Get the zone this event belongs to.
    #[must_use]
    pub const fn zone(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Check if this event has an associated capability token.
    #[must_use]
    pub const fn has_capability(&self) -> bool {
        self.capability_token_jti.is_some()
    }

    /// Check if this event is correlated with another.
    #[must_use]
    pub fn is_correlated_with(&self, other: &Self) -> bool {
        self.correlation_id == other.correlation_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditHead
// ─────────────────────────────────────────────────────────────────────────────

/// Audit head checkpoint (NORMATIVE).
///
/// A quorum-signed checkpoint that represents the current state of the
/// audit chain for a zone. Nodes can compare `head_seq` values for
/// O(1) freshness determination.
///
/// # Quorum Requirements
///
/// The `quorum_signatures` field MUST satisfy the zone's quorum policy
/// for the audit chain to be considered valid. This prevents a single
/// compromised node from tampering with audit history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHead {
    /// Object header with zone, schema, and provenance.
    pub header: ObjectHeader,

    /// Zone this head applies to.
    pub zone_id: ZoneId,

    /// `ObjectId` of the head event.
    pub head_event: ObjectId,

    /// Sequence number of the head event (for O(1) freshness).
    pub head_seq: u64,

    /// Coverage ratio (0.0-1.0) of nodes that have synced to this head.
    pub coverage: f64,

    /// Epoch identifier for this checkpoint.
    pub epoch_id: EpochId,

    /// Quorum signatures from zone nodes (NORMATIVE).
    pub quorum_signatures: SignatureSet,
}

impl AuditHead {
    /// Check if this head is fresher than another.
    #[must_use]
    pub const fn is_fresher_than(&self, other: &Self) -> bool {
        self.head_seq > other.head_seq
    }

    /// Check if this head satisfies the quorum policy.
    #[must_use]
    pub fn satisfies_quorum(&self, policy: &QuorumPolicy) -> bool {
        self.quorum_signatures
            .satisfies_quorum(policy, RiskTier::CriticalWrite)
    }

    /// Get the age of this head relative to a timestamp.
    #[must_use]
    pub const fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.header.created_at)
    }

    /// Check if coverage is sufficient (>50% of nodes).
    #[must_use]
    pub fn has_sufficient_coverage(&self) -> bool {
        self.coverage > 0.5
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneCheckpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Zone checkpoint for fast sync and garbage collection (NORMATIVE).
///
/// A `ZoneCheckpoint` captures the complete state of a zone at a point in time.
/// This enables:
///
/// - **Fast sync**: New nodes can bootstrap from a checkpoint instead of
///   replaying the entire history
/// - **Garbage collection**: Objects referenced only by events before the
///   checkpoint can be safely pruned
/// - **Disaster recovery**: Checkpoints serve as recovery points
///
/// # Quorum Requirements
///
/// Checkpoints MUST be signed by a quorum of zone nodes to be valid.
/// This prevents a single node from creating a false checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneCheckpoint {
    /// Object header with zone, schema, and provenance.
    pub header: ObjectHeader,

    /// Zone this checkpoint applies to.
    pub zone_id: ZoneId,

    /// Revocation chain head at checkpoint time.
    pub rev_head: ObjectId,

    /// Revocation chain sequence at checkpoint time.
    pub rev_seq: u64,

    /// Audit chain head at checkpoint time.
    pub audit_head: ObjectId,

    /// Audit chain sequence at checkpoint time.
    pub audit_seq: u64,

    /// Zone definition object at checkpoint time.
    pub zone_definition_head: ObjectId,

    /// Zone policy object at checkpoint time.
    pub zone_policy_head: ObjectId,

    /// Active zone key manifest at checkpoint time.
    pub active_zone_key_manifest: ObjectId,

    /// Checkpoint sequence number.
    pub checkpoint_seq: u64,

    /// Epoch this checkpoint belongs to.
    pub as_of_epoch: EpochId,

    /// Quorum signatures from zone nodes (NORMATIVE).
    pub quorum_signatures: SignatureSet,
}

impl ZoneCheckpoint {
    /// Check if this checkpoint is fresher than another.
    #[must_use]
    pub const fn is_fresher_than(&self, other: &Self) -> bool {
        self.checkpoint_seq > other.checkpoint_seq
    }

    /// Check if this checkpoint satisfies the quorum policy.
    #[must_use]
    pub fn satisfies_quorum(&self, policy: &QuorumPolicy) -> bool {
        self.quorum_signatures
            .satisfies_quorum(policy, RiskTier::CriticalWrite)
    }

    /// Check if a revocation sequence is covered by this checkpoint.
    #[must_use]
    pub const fn covers_revocation(&self, rev_seq: u64) -> bool {
        rev_seq <= self.rev_seq
    }

    /// Check if an audit sequence is covered by this checkpoint.
    #[must_use]
    pub const fn covers_audit(&self, audit_seq: u64) -> bool {
        audit_seq <= self.audit_seq
    }

    /// Get the age of this checkpoint relative to a timestamp.
    #[must_use]
    pub const fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.header.created_at)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision and DecisionReceipt
// ─────────────────────────────────────────────────────────────────────────────

/// Access control decision (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Access is allowed.
    Allow,

    /// Access is denied.
    Deny,
}

impl Decision {
    /// Check if this is an allow decision.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Check if this is a deny decision.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// Decision receipt for explainable access control (NORMATIVE).
///
/// Every policy decision MUST produce a `DecisionReceipt` that captures:
/// - The decision outcome (allow/deny)
/// - A machine-readable reason code
/// - References to evidence that influenced the decision
/// - An optional human-readable explanation
///
/// This ensures all access control decisions are:
/// - **Auditable**: The decision is recorded with full context
/// - **Explainable**: Users can understand why access was granted/denied
/// - **Reproducible**: Given the same evidence, the same decision would be made
///
/// # Evidence Chain
///
/// The `evidence` field contains `ObjectId`s of objects that influenced
/// the decision. This typically includes:
/// - The capability token used
/// - The request object
/// - Relevant policy objects
/// - Provenance records
///
/// Verifiers can follow this chain to understand the decision rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Object header with zone, schema, and provenance.
    pub header: ObjectHeader,

    /// The request object that triggered this decision.
    pub request_object_id: ObjectId,

    /// The decision outcome.
    pub decision: Decision,

    /// Machine-readable reason code for categorization.
    pub reason_code: String,

    /// Evidence `ObjectId`s that influenced the decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ObjectId>,

    /// Human-readable explanation (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// When the decision was made (UNIX timestamp seconds).
    pub decided_at: u64,

    /// Policy version that was applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,

    /// Signature over the receipt (Ed25519).
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

impl DecisionReceipt {
    /// Check if the decision was allow.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.decision.is_allow()
    }

    /// Check if the decision was deny.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        self.decision.is_deny()
    }

    /// Check if this receipt has the given evidence.
    #[must_use]
    pub fn has_evidence(&self, object_id: &ObjectId) -> bool {
        self.evidence.contains(object_id)
    }

    /// Get the number of evidence items.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Common Reason Codes
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known decision reason codes (NORMATIVE).
///
/// These codes provide machine-readable categorization of decision outcomes.
/// Implementations MAY define additional codes with the `custom:` prefix.
pub mod reason_codes {
    /// Access granted - valid capability token.
    pub const CAPABILITY_VALID: &str = "capability_valid";

    /// Access denied - capability token expired.
    pub const CAPABILITY_EXPIRED: &str = "capability_expired";

    /// Access denied - capability token revoked.
    pub const CAPABILITY_REVOKED: &str = "capability_revoked";

    /// Access denied - capability token not yet valid.
    pub const CAPABILITY_NOT_YET_VALID: &str = "capability_not_yet_valid";

    /// Access denied - capability scope insufficient.
    pub const CAPABILITY_SCOPE_INSUFFICIENT: &str = "capability_scope_insufficient";

    /// Access denied - signature verification failed.
    pub const SIGNATURE_INVALID: &str = "signature_invalid";

    /// Access denied - policy explicitly denies this operation.
    pub const POLICY_DENIED: &str = "policy_denied";

    /// Access denied - rate limit exceeded.
    pub const RATE_LIMIT_EXCEEDED: &str = "rate_limit_exceeded";

    /// Access denied - insufficient integrity level.
    pub const INTEGRITY_INSUFFICIENT: &str = "integrity_insufficient";

    /// Access denied - tainted input for dangerous operation.
    pub const TAINTED_INPUT: &str = "tainted_input";

    /// Access denied - zone crossing not approved.
    pub const ZONE_CROSSING_UNAPPROVED: &str = "zone_crossing_unapproved";

    /// Access denied - quorum not satisfied.
    pub const QUORUM_NOT_SATISFIED: &str = "quorum_not_satisfied";

    /// Access granted - elevation token valid.
    pub const ELEVATION_VALID: &str = "elevation_valid";

    /// Access granted - declassification token valid.
    pub const DECLASSIFICATION_VALID: &str = "declassification_valid";

    /// Access denied - approval token invalid.
    pub const APPROVAL_TOKEN_INVALID: &str = "approval_token_invalid";

    /// Access denied - unknown/unspecified reason.
    pub const UNKNOWN: &str = "unknown";
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

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TraceContext Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trace_context_new() {
        let ctx = TraceContext::new();
        assert!(ctx.is_sampled());
        assert_ne!(ctx.trace_id, [0u8; 16]);
        assert_ne!(ctx.span_id, [0u8; 8]);
    }

    #[test]
    fn trace_context_child_span() {
        let parent = TraceContext::new();
        let child = parent.new_child_span();

        // Same trace, different span
        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(parent.flags, child.flags);
    }

    #[test]
    fn trace_context_sampled_flag() {
        let mut ctx = TraceContext::new();
        assert!(ctx.is_sampled());

        ctx.set_sampled(false);
        assert!(!ctx.is_sampled());

        ctx.set_sampled(true);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn trace_context_traceparent_roundtrip() {
        let ctx = TraceContext::new();
        let header = ctx.to_traceparent();

        let parsed = TraceContext::from_traceparent(&header).expect("parse failed");
        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.span_id, parsed.span_id);
        assert_eq!(ctx.flags, parsed.flags);
    }

    #[test]
    fn trace_context_traceparent_format() {
        let ctx = TraceContext {
            trace_id: [0x01; 16],
            span_id: [0x02; 8],
            flags: 0x01,
        };

        let header = ctx.to_traceparent();
        assert!(header.starts_with("00-"));
        assert!(header.ends_with("-01"));
        assert!(header.contains("01010101010101010101010101010101"));
        assert!(header.contains("0202020202020202"));
    }

    #[test]
    fn trace_context_invalid_traceparent() {
        assert!(TraceContext::from_traceparent("").is_none());
        assert!(TraceContext::from_traceparent("invalid").is_none());
        assert!(TraceContext::from_traceparent("01-trace-span-00").is_none()); // Wrong version
        assert!(TraceContext::from_traceparent("00-short-span-00").is_none()); // Short trace_id
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditEventType Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_type_display() {
        assert_eq!(AuditEventType::CapabilityMinted.to_string(), "capability_minted");
        assert_eq!(AuditEventType::PolicyDecision.to_string(), "policy_decision");
        assert_eq!(
            AuditEventType::Custom("my_event".into()).to_string(),
            "my_event"
        );
    }

    #[test]
    fn audit_event_type_security_sensitive() {
        assert!(AuditEventType::CapabilityMinted.is_security_sensitive());
        assert!(AuditEventType::PolicyDecision.is_security_sensitive());
        assert!(AuditEventType::ZoneCrossing.is_security_sensitive());
        assert!(!AuditEventType::ObjectCreated.is_security_sensitive());
        assert!(!AuditEventType::ConnectorInvocation.is_security_sensitive());
    }

    #[test]
    fn audit_event_type_serialization() {
        let event_type = AuditEventType::CapabilityUsed;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("capability_used"));

        let deserialized: AuditEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event_type);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditEvent Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_audit_event(seq: u64, prev: Option<ObjectId>) -> AuditEvent {
        AuditEvent {
            header: test_header(),
            correlation_id: [0x42; 16],
            trace_context: Some(TraceContext::new()),
            event_type: AuditEventType::CapabilityUsed,
            actor: PrincipalId::new("user_alice").expect("valid principal"),
            zone_id: ZoneId::work(),
            connector_id: Some(ConnectorId::from_static("fcp_telegram:connector:1.0.0")),
            operation: Some(OperationId::from_static("send_message")),
            capability_token_jti: Some(Uuid::new_v4()),
            request_object_id: Some(ObjectId::from_bytes([1u8; 32])),
            result_object_id: Some(ObjectId::from_bytes([2u8; 32])),
            prev,
            seq,
            occurred_at: 1_700_000_000,
            metadata: serde_json::json!({"key": "value"}),
            signature: [0u8; 64],
        }
    }

    #[test]
    fn audit_event_genesis() {
        let event = test_audit_event(0, None);
        assert!(event.is_genesis());
    }

    #[test]
    fn audit_event_not_genesis() {
        let prev_id = ObjectId::from_bytes([10u8; 32]);
        let event = test_audit_event(1, Some(prev_id));
        assert!(!event.is_genesis());
    }

    #[test]
    fn audit_event_follows() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event1 = test_audit_event(1, None);
        let event2 = test_audit_event(2, Some(event1_id));

        assert!(event2.follows(&event1, &event1_id));
        assert!(!event1.follows(&event2, &ObjectId::from_bytes([20u8; 32])));
    }

    #[test]
    fn audit_event_follows_overflow_protection() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event1 = test_audit_event(u64::MAX, None);
        let event2 = test_audit_event(0, Some(event1_id));

        // Should return false because u64::MAX + 1 overflows
        assert!(!event2.follows(&event1, &event1_id));
    }

    #[test]
    fn audit_event_correlation() {
        let event1 = test_audit_event(0, None);
        let mut event2 = test_audit_event(1, Some(ObjectId::from_bytes([1u8; 32])));
        event2.correlation_id = event1.correlation_id;

        assert!(event1.is_correlated_with(&event2));

        event2.correlation_id = [0xFF; 16];
        assert!(!event1.is_correlated_with(&event2));
    }

    #[test]
    fn audit_event_has_capability() {
        let event = test_audit_event(0, None);
        assert!(event.has_capability());

        let mut event_no_cap = test_audit_event(0, None);
        event_no_cap.capability_token_jti = None;
        assert!(!event_no_cap.has_capability());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuditHead Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_audit_head(seq: u64, coverage: f64) -> AuditHead {
        AuditHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([1u8; 32]),
            head_seq: seq,
            coverage,
            epoch_id: EpochId::new("epoch-1"),
            quorum_signatures: SignatureSet::new(),
        }
    }

    #[test]
    fn audit_head_is_fresher_than() {
        let head1 = test_audit_head(10, 0.8);
        let head2 = test_audit_head(20, 0.6);

        assert!(head2.is_fresher_than(&head1));
        assert!(!head1.is_fresher_than(&head2));
        assert!(!head1.is_fresher_than(&head1));
    }

    #[test]
    fn audit_head_coverage() {
        let high_coverage = test_audit_head(10, 0.8);
        let low_coverage = test_audit_head(10, 0.3);

        assert!(high_coverage.has_sufficient_coverage());
        assert!(!low_coverage.has_sufficient_coverage());
    }

    #[test]
    fn audit_head_age() {
        let mut head = test_audit_head(10, 0.8);
        head.header.created_at = 1_700_000_000;

        assert_eq!(head.age_secs(1_700_000_100), 100);
        assert_eq!(head.age_secs(1_699_999_900), 0); // Saturating sub
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneCheckpoint Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_zone_checkpoint(checkpoint_seq: u64, rev_seq: u64, audit_seq: u64) -> ZoneCheckpoint {
        ZoneCheckpoint {
            header: test_header(),
            zone_id: ZoneId::work(),
            rev_head: ObjectId::from_bytes([1u8; 32]),
            rev_seq,
            audit_head: ObjectId::from_bytes([2u8; 32]),
            audit_seq,
            zone_definition_head: ObjectId::from_bytes([3u8; 32]),
            zone_policy_head: ObjectId::from_bytes([4u8; 32]),
            active_zone_key_manifest: ObjectId::from_bytes([5u8; 32]),
            checkpoint_seq,
            as_of_epoch: EpochId::new("epoch-1"),
            quorum_signatures: SignatureSet::new(),
        }
    }

    #[test]
    fn zone_checkpoint_is_fresher_than() {
        let cp1 = test_zone_checkpoint(10, 100, 200);
        let cp2 = test_zone_checkpoint(20, 150, 250);

        assert!(cp2.is_fresher_than(&cp1));
        assert!(!cp1.is_fresher_than(&cp2));
    }

    #[test]
    fn zone_checkpoint_covers_revocation() {
        let cp = test_zone_checkpoint(10, 100, 200);

        assert!(cp.covers_revocation(50));
        assert!(cp.covers_revocation(100));
        assert!(!cp.covers_revocation(101));
    }

    #[test]
    fn zone_checkpoint_covers_audit() {
        let cp = test_zone_checkpoint(10, 100, 200);

        assert!(cp.covers_audit(150));
        assert!(cp.covers_audit(200));
        assert!(!cp.covers_audit(201));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Decision and DecisionReceipt Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decision_display() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }

    #[test]
    fn decision_is_allow_deny() {
        assert!(Decision::Allow.is_allow());
        assert!(!Decision::Allow.is_deny());
        assert!(!Decision::Deny.is_allow());
        assert!(Decision::Deny.is_deny());
    }

    fn test_decision_receipt(decision: Decision) -> DecisionReceipt {
        DecisionReceipt {
            header: test_header(),
            request_object_id: ObjectId::from_bytes([1u8; 32]),
            decision,
            reason_code: reason_codes::CAPABILITY_VALID.into(),
            evidence: vec![
                ObjectId::from_bytes([2u8; 32]),
                ObjectId::from_bytes([3u8; 32]),
            ],
            explanation: Some("Access granted per policy".into()),
            decided_at: 1_700_000_000,
            policy_version: Some("v1.2.3".into()),
            signature: [0u8; 64],
        }
    }

    #[test]
    fn decision_receipt_is_allowed_denied() {
        let allow_receipt = test_decision_receipt(Decision::Allow);
        assert!(allow_receipt.is_allowed());
        assert!(!allow_receipt.is_denied());

        let deny_receipt = test_decision_receipt(Decision::Deny);
        assert!(!deny_receipt.is_allowed());
        assert!(deny_receipt.is_denied());
    }

    #[test]
    fn decision_receipt_has_evidence() {
        let receipt = test_decision_receipt(Decision::Allow);
        assert!(receipt.has_evidence(&ObjectId::from_bytes([2u8; 32])));
        assert!(!receipt.has_evidence(&ObjectId::from_bytes([99u8; 32])));
    }

    #[test]
    fn decision_receipt_evidence_count() {
        let receipt = test_decision_receipt(Decision::Allow);
        assert_eq!(receipt.evidence_count(), 2);
    }

    #[test]
    fn decision_receipt_serialization() {
        let receipt = test_decision_receipt(Decision::Allow);
        let json = serde_json::to_string(&receipt).expect("serialization failed");

        assert!(json.contains("\"decision\":\"allow\""));
        assert!(json.contains("capability_valid"));

        let deserialized: DecisionReceipt =
            serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(deserialized.decision, Decision::Allow);
        assert_eq!(deserialized.reason_code, reason_codes::CAPABILITY_VALID);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Reason Codes Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn reason_codes_are_valid_strings() {
        // Ensure reason codes are lowercase snake_case
        assert_eq!(reason_codes::CAPABILITY_VALID, "capability_valid");
        assert_eq!(reason_codes::CAPABILITY_EXPIRED, "capability_expired");
        assert_eq!(reason_codes::POLICY_DENIED, "policy_denied");
        assert_eq!(reason_codes::RATE_LIMIT_EXCEEDED, "rate_limit_exceeded");
    }
}

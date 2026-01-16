//! Audit + explainability types for FCP2 (NORMATIVE).
//!
//! This module implements audit chain primitives and explainability receipts as
//! described in `FCP_Specification_V2.md` §23.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ConnectorId, CorrelationId, EpochId, NodeSignature, ObjectHeader, ObjectId, OperationId,
    PrincipalId, SignatureSet, ZoneId,
};

/// Required audit event types (NORMATIVE).
pub const EVENT_SECRET_ACCESS: &str = "secret.access";
pub const EVENT_CAPABILITY_INVOKE: &str = "capability.invoke";
pub const EVENT_ELEVATION_GRANTED: &str = "elevation.granted";
pub const EVENT_DECLASSIFICATION_GRANTED: &str = "declassification.granted";
pub const EVENT_ZONE_TRANSITION: &str = "zone.transition";
pub const EVENT_REVOCATION_ISSUED: &str = "revocation.issued";
pub const EVENT_SECURITY_VIOLATION: &str = "security.violation";
pub const EVENT_AUDIT_FORK_DETECTED: &str = "audit.fork_detected";

/// Distributed trace context (NORMATIVE when present).
///
/// W3C Trace Context compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// 16-byte trace ID (unique per logical request).
    pub trace_id: [u8; 16],
    /// 8-byte span ID (unique per span).
    pub span_id: [u8; 8],
    /// Trace flags/sampling (W3C trace-flags).
    pub flags: u8,
}

/// Audit event (NORMATIVE).
///
/// Append-only, hash-linked audit chain per zone. Each event links to its
/// predecessor via `prev` and carries a monotonic `seq` for O(1) freshness
/// comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Standard object header with schema, zone, provenance.
    pub header: ObjectHeader,
    /// Correlation ID for request tracing (16 bytes).
    pub correlation_id: CorrelationId,
    /// Optional full trace context (NORMATIVE when present in InvokeRequest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
    /// Event type (e.g., "secret.access", "capability.invoke").
    pub event_type: String,
    /// Actor who triggered the event.
    pub actor: PrincipalId,
    /// Zone where event occurred.
    pub zone_id: ZoneId,
    /// Connector ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,
    /// Operation ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationId>,
    /// Capability token JTI (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token_jti: Option<Uuid>,
    /// Request object ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_id: Option<ObjectId>,
    /// Result object ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_object_id: Option<ObjectId>,
    /// Previous event in chain (hash link) - enables tamper detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,
    /// Monotonic chain sequence number (NORMATIVE).
    pub seq: u64,
    /// When event occurred (Unix timestamp seconds).
    pub occurred_at: u64,
    /// Signature by the executing node.
    pub signature: NodeSignature,
}

impl AuditEvent {
    /// Get the zone ID this event belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Check if this event follows another event in the chain.
    ///
    /// # Arguments
    ///
    /// * `other` - The event that should precede this one
    /// * `other_id` - The `ObjectId` of `other` (computed from its content/header)
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
}

/// Audit head checkpoint (NORMATIVE).
///
/// Quorum-signed checkpoint of the audit chain head. Enables fast sync
/// without full chain traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHead {
    /// Object header.
    pub header: ObjectHeader,
    /// Zone this head covers.
    pub zone_id: ZoneId,
    /// Head event ObjectId (tip of the chain).
    pub head_event: ObjectId,
    /// Sequence number of `head_event` (NORMATIVE).
    pub head_seq: u64,
    /// Fraction of expected nodes contributing (0.0-1.0).
    pub coverage: f64,
    /// Epoch this head was checkpointed.
    pub epoch_id: EpochId,
    /// Quorum signatures from nodes (Byzantine-resilient).
    pub quorum_signatures: SignatureSet,
}

impl AuditHead {
    /// Get the zone ID this head belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }
}

/// Zone checkpoint for fast sync (NORMATIVE).
///
/// Quorum-signed checkpoint of zone state for efficient synchronization.
/// Acts as the single GC root (so reachability GC is well-defined).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneCheckpoint {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    // Enforceable heads (NORMATIVE).
    pub rev_head: ObjectId,
    pub rev_seq: u64,
    pub audit_head: ObjectId,
    pub audit_seq: u64,
    // Policy/config heads (NORMATIVE).
    pub zone_definition_head: ObjectId,
    pub zone_policy_head: ObjectId,
    pub active_zone_key_manifest: ObjectId,
    /// Monotonic checkpoint sequence (NORMATIVE; per-zone).
    pub checkpoint_seq: u64,
    pub as_of_epoch: EpochId,
    /// Quorum-signed (Byzantine-resilient under n/f model).
    pub quorum_signatures: SignatureSet,
}

impl ZoneCheckpoint {
    /// Get the zone ID this checkpoint belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }
}

/// Decision receipt for explainable allow/deny (NORMATIVE).
///
/// Content-addressed "why allowed/denied" record with stable reason_code and
/// evidence object IDs. This is what powers `fcp explain`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub header: ObjectHeader,
    /// The request that was evaluated.
    pub request_object_id: ObjectId,
    /// The decision (Allow or Deny).
    pub decision: Decision,
    /// Stable reason code for programmatic handling.
    pub reason_code: String,
    /// Evidence object IDs that support this decision.
    pub evidence: Vec<ObjectId>,
    /// Optional human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Signature by the evaluating node.
    pub signature: NodeSignature,
}

impl DecisionReceipt {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Returns true if this receipt is an allow decision.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }

    /// Returns true if this receipt is a deny decision.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self.decision, Decision::Deny)
    }
}

/// Decision outcome (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, Provenance};
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_header(kind: &str) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", kind, Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("node-1"), [0u8; 64], 1_700_000_000)
    }

    fn test_actor() -> PrincipalId {
        PrincipalId::new("user:alice").expect("principal id")
    }

    #[test]
    fn audit_event_follows_prev_and_seq() {
        let prev_id = ObjectId::test_id("audit-event-1");
        let event1 = AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([1u8; 16])),
            trace_context: None,
            event_type: EVENT_CAPABILITY_INVOKE.to_string(),
            actor: test_actor(),
            zone_id: ZoneId::work(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev: None,
            seq: 1,
            occurred_at: 1_700_000_001,
            signature: test_signature(),
        };

        let event2 = AuditEvent {
            header: test_header("AuditEvent"),
            correlation_id: CorrelationId(Uuid::from_bytes([2u8; 16])),
            trace_context: None,
            event_type: EVENT_CAPABILITY_INVOKE.to_string(),
            actor: test_actor(),
            zone_id: ZoneId::work(),
            connector_id: None,
            operation: None,
            capability_token_jti: None,
            request_object_id: None,
            result_object_id: None,
            prev: Some(prev_id),
            seq: 2,
            occurred_at: 1_700_000_002,
            signature: test_signature(),
        };

        assert!(event2.follows(&event1, &prev_id));
    }

    #[test]
    fn decision_serializes_as_lowercase() {
        let allow_json = serde_json::to_string(&Decision::Allow).unwrap();
        let deny_json = serde_json::to_string(&Decision::Deny).unwrap();
        assert_eq!(allow_json, "\"allow\"");
        assert_eq!(deny_json, "\"deny\"");
    }
}

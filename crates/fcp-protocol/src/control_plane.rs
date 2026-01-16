//! Control-plane object model and retention classification.
//!
//! Implements the normative control-plane object model from `FCP_Specification_V2.md` §9.4.
//! Control-plane objects wrap protocol messages with canonical serialization and retention
//! classification for auditability.

use fcp_cbor::SchemaId;
use fcp_core::{ObjectHeader, ObjectId, ObjectIdKey};
use serde::{Deserialize, Serialize};

/// Retention requirement for control-plane objects (NORMATIVE).
///
/// Some control-plane messages MUST be stored for auditability; others MAY be ephemeral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlPlaneRetention {
    /// MUST be stored for auditability and replay.
    ///
    /// Examples: invoke/response, receipts, approvals, secret access, revocations, audit events.
    Required,
    /// MAY be dropped after processing.
    ///
    /// Examples: health, handshake, `decode_status`, `symbol_ack`, introspect, configure, simulate.
    Ephemeral,
}

/// Control-plane object with canonical representation (NORMATIVE).
///
/// All control-plane message types MUST have a canonical CBOR object representation.
/// The `ControlPlaneObject` wraps the header and body for transmission over FCPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneObject {
    /// Object header with schema, zone, provenance, etc.
    pub header: ObjectHeader,
    /// Canonical payload bytes: `schema_hash` (32 bytes) || `canonical_cbor(body)`.
    pub body: Vec<u8>,
}

impl ControlPlaneObject {
    /// Create a new control-plane object from a header and body.
    ///
    /// The body should be pre-serialized as: `schema_hash || canonical_cbor(payload)`.
    #[must_use]
    pub const fn new(header: ObjectHeader, body: Vec<u8>) -> Self {
        Self { header, body }
    }

    /// Derive the object ID for this control-plane object.
    ///
    /// # Errors
    /// Returns an error if canonical bytes cannot be constructed.
    pub fn derive_id(&self, key: &ObjectIdKey) -> Result<ObjectId, fcp_cbor::SerializationError> {
        fcp_core::StoredObject::derive_id(&self.header, &self.body, key)
    }

    /// Get the schema for this object.
    #[must_use]
    pub const fn schema(&self) -> &SchemaId {
        &self.header.schema
    }

    /// Determine the retention requirement for this object based on its schema.
    #[must_use]
    pub fn retention(&self) -> ControlPlaneRetention {
        retention_for_schema(&self.header.schema)
    }
}

/// Well-known schema patterns for retention classification.
mod schema_patterns {
    /// Required retention schemas (must be stored for auditability).
    /// Note: Not used in code (default is Required), kept for documentation.
    #[allow(dead_code)]
    pub const REQUIRED_PREFIXES: &[&str] = &[
        "fcp.invoke",     // InvokeRequest/Response
        "fcp.receipt",    // Receipts
        "fcp.approval",   // Approvals
        "fcp.secret",     // Secret access
        "fcp.revoke",     // Revocations
        "fcp.audit",      // Audit events/heads
        "fcp.grant",      // Capability grants
        "fcp.membership", // Membership changes
    ];

    /// Ephemeral schemas (may be dropped after processing).
    pub const EPHEMERAL_PREFIXES: &[&str] = &[
        "fcp.health",     // Health checks
        "fcp.handshake",  // Handshake objects
        "fcp.status",     // Decode status, symbol ack
        "fcp.introspect", // Introspection
        "fcp.configure",  // Configuration
        "fcp.simulate",   // Simulation
        "fcp.ping",       // Ping/pong
        "fcp.heartbeat",  // Heartbeat
    ];
}

/// Determine retention requirement for a schema (NORMATIVE).
///
/// Default is `Required` for unknown schemas (fail-safe toward auditability).
#[must_use]
pub fn retention_for_schema(schema: &SchemaId) -> ControlPlaneRetention {
    let ns = schema.namespace.as_str();

    // Check explicit required prefixes first.
    for prefix in schema_patterns::REQUIRED_PREFIXES {
        if ns.starts_with(prefix) {
            return ControlPlaneRetention::Required;
        }
    }

    // Check ephemeral patterns next (explicit opt-out of storage).
    for prefix in schema_patterns::EPHEMERAL_PREFIXES {
        if ns.starts_with(prefix) {
            return ControlPlaneRetention::Ephemeral;
        }
    }

    // Default to Required for auditability
    ControlPlaneRetention::Required
}

/// Check if a schema requires storage (convenience helper).
#[must_use]
pub fn requires_storage(schema: &SchemaId) -> bool {
    retention_for_schema(schema) == ControlPlaneRetention::Required
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{Provenance, ZoneId};
    use semver::Version;

    fn test_schema(namespace: &str, name: &str) -> SchemaId {
        SchemaId::new(namespace, name, Version::new(1, 0, 0))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ControlPlaneRetention Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retention_invoke_is_required() {
        let schema = test_schema("fcp.invoke", "Request");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_receipt_is_required() {
        let schema = test_schema("fcp.receipt", "ExecutionReceipt");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_approval_is_required() {
        let schema = test_schema("fcp.approval", "CapabilityApproval");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_audit_is_required() {
        let schema = test_schema("fcp.audit", "AuditHead");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_health_is_ephemeral() {
        let schema = test_schema("fcp.health", "Ping");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_handshake_is_ephemeral() {
        let schema = test_schema("fcp.handshake", "Hello");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_status_is_ephemeral() {
        let schema = test_schema("fcp.status", "DecodeStatus");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_introspect_is_ephemeral() {
        let schema = test_schema("fcp.introspect", "Query");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_simulate_is_ephemeral() {
        let schema = test_schema("fcp.simulate", "CostEstimate");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_unknown_defaults_to_required() {
        // Unknown schemas should default to Required for fail-safe auditability
        let schema = test_schema("fcp.custom", "UnknownType");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // requires_storage Helper Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn requires_storage_true_for_required() {
        let schema = test_schema("fcp.invoke", "Request");
        assert!(requires_storage(&schema));
    }

    #[test]
    fn requires_storage_false_for_ephemeral() {
        let schema = test_schema("fcp.health", "Ping");
        assert!(!requires_storage(&schema));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ControlPlaneObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn control_plane_object_creation() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Request"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = vec![0x00; 64]; // Dummy body

        let obj = ControlPlaneObject::new(header, body.clone());

        assert_eq!(obj.body, body);
        assert_eq!(obj.schema().namespace, "fcp.invoke");
        assert_eq!(obj.retention(), ControlPlaneRetention::Required);
    }

    #[test]
    fn control_plane_object_derive_id() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Request"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"test body content".to_vec();
        let key = ObjectIdKey::from_bytes([0_u8; 32]);

        let obj = ControlPlaneObject::new(header, body);
        let id = obj.derive_id(&key).expect("derive_id should succeed");

        // Verify determinism
        let id2 = obj.derive_id(&key).expect("derive_id should succeed");
        assert_eq!(id, id2);
    }

    #[test]
    fn control_plane_object_retention_ephemeral() {
        let header = ObjectHeader {
            schema: test_schema("fcp.health", "Heartbeat"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = vec![];

        let obj = ControlPlaneObject::new(header, body);
        assert_eq!(obj.retention(), ControlPlaneRetention::Ephemeral);
    }

    #[test]
    fn control_plane_object_serialization_roundtrip() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Request"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"serialization test".to_vec();

        let obj = ControlPlaneObject::new(header, body.clone());
        let json = serde_json::to_string(&obj).expect("serialize should succeed");
        let deserialized: ControlPlaneObject =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.body, body);
        assert_eq!(deserialized.schema().namespace, "fcp.invoke");
    }
}

//! Connector state management for mesh-persisted state objects (NORMATIVE).
//!
//! Based on FCP Specification V2 §10 and docs §2.2.
//!
//! # Overview
//!
//! Implements the connector state model so polling/cursors/dedup are safe under
//! failover and migration. Authoritative state lives in mesh objects; local
//! `$CONNECTOR_STATE` is a cache only.
//!
//! # State Models
//!
//! - **Stateless**: No mesh-persisted state required
//! - **`SingletonWriter`**: Exactly one writer enforced via Lease
//! - **Crdt**: Multi-writer state using CRDT deltas + periodic snapshots
//!
//! # Key Invariants
//!
//! - State writes for `SingletonWriter` MUST be fenced by a Lease with
//!   `LeasePurpose::ConnectorStateWrite`
//! - Fork detection MUST pause connector execution and require resolution
//! - Snapshots enable compaction of older state objects

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{ConnectorId, InstanceId, ObjectHeader, ObjectId, TailscaleNodeId, ZoneId};

// ─────────────────────────────────────────────────────────────────────────────
// Signature Type
// ─────────────────────────────────────────────────────────────────────────────

/// Ed25519 signature (64 bytes) (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "hex::serde")] pub [u8; 64]);

impl Signature {
    /// Create a signature from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Create a zero signature (for testing).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 64])
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature")
            .field(&format!("{}...", &hex::encode(&self.0[..8])))
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}...", &hex::encode(&self.0[..8]))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::zero()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Types (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// CRDT type discriminant (NORMATIVE).
///
/// Defines the merge semantics for multi-writer connector state.
/// The actual CRDT implementations are in the `crate::crdt` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrdtType {
    /// Last-write-wins map (key-value with timestamps).
    ///
    /// Merge: Take entry with latest timestamp per key.
    /// Implementation: `crate::LwwMap`
    LwwMap,

    /// Observed-remove set (add/remove operations).
    ///
    /// Merge: Via observed-remove set algebra.
    /// Implementation: `crate::OrSet`
    OrSet,

    /// Grow-only counter (only increments).
    ///
    /// Merge: Take max per actor.
    /// Implementation: `crate::GCounter`
    GCounter,

    /// Positive-negative counter (increments and decrements).
    ///
    /// Merge: Merge positive and negative counters separately.
    /// Implementation: `crate::PnCounter`
    PnCounter,
}

impl CrdtType {
    /// Get the human-readable name for this CRDT type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LwwMap => "lww_map",
            Self::OrSet => "or_set",
            Self::GCounter => "g_counter",
            Self::PnCounter => "pn_counter",
        }
    }
}

impl fmt::Display for CrdtType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Model (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector state model discriminant (NORMATIVE).
///
/// Defines how connector state is persisted and synchronized in the mesh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectorStateModel {
    /// No mesh-persisted state required.
    ///
    /// The connector maintains no durable state across restarts.
    #[default]
    Stateless,

    /// Exactly one writer enforced via Lease (`ConnectorStateWrite` purpose).
    ///
    /// - State writes MUST be fenced by a Lease
    /// - Higher `lease_seq` wins deterministically
    /// - Fork detection triggers safety incident
    SingletonWriter,

    /// Multi-writer state using CRDT deltas + periodic snapshots.
    ///
    /// - Multiple nodes can write concurrently
    /// - Deltas are merged according to `crdt_type` semantics
    /// - Snapshots compact the delta chain
    Crdt {
        /// The CRDT type determining merge semantics.
        crdt_type: CrdtType,
    },
}

impl ConnectorStateModel {
    /// Check if this model is stateless.
    #[must_use]
    pub const fn is_stateless(&self) -> bool {
        matches!(self, Self::Stateless)
    }

    /// Check if this model requires singleton writer semantics.
    #[must_use]
    pub const fn is_singleton_writer(&self) -> bool {
        matches!(self, Self::SingletonWriter)
    }

    /// Check if this model uses CRDT semantics.
    #[must_use]
    pub const fn is_crdt(&self) -> bool {
        matches!(self, Self::Crdt { .. })
    }

    /// Get the CRDT type if this is a CRDT model.
    #[must_use]
    pub const fn crdt_type(&self) -> Option<CrdtType> {
        match self {
            Self::Crdt { crdt_type } => Some(*crdt_type),
            _ => None,
        }
    }
}

impl fmt::Display for ConnectorStateModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stateless => write!(f, "stateless"),
            Self::SingletonWriter => write!(f, "singleton_writer"),
            Self::Crdt { crdt_type } => write!(f, "crdt({crdt_type})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Root (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Root object for connector state (NORMATIVE).
///
/// This object defines the state model and points to the current head of the
/// state chain. It is the entry point for state resolution during failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateRoot {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier (for multi-instance connectors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// State model governing this connector's state.
    pub model: ConnectorStateModel,

    /// Latest `ConnectorStateObject` (or `None` if no state yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<ObjectId>,

    /// Schema version for safe upgrades (NORMATIVE).
    #[serde(default = "default_schema_version")]
    pub state_schema_version: u32,
}

const fn default_schema_version() -> u32 {
    1
}

impl ConnectorStateRoot {
    /// Create a new state root for a stateless connector.
    #[must_use]
    pub const fn stateless(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::Stateless,
            head: None,
            state_schema_version: 1,
        }
    }

    /// Create a new state root for a singleton-writer connector.
    #[must_use]
    pub const fn singleton_writer(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::SingletonWriter,
            head: None,
            state_schema_version: 1,
        }
    }

    /// Create a new state root for a CRDT connector.
    #[must_use]
    pub const fn crdt(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
        crdt_type: CrdtType,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::Crdt { crdt_type },
            head: None,
            state_schema_version: 1,
        }
    }

    /// Set the instance ID.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Set the head object ID.
    #[must_use]
    pub const fn with_head(mut self, head: ObjectId) -> Self {
        self.head = Some(head);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Object (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// State object in the state chain (NORMATIVE).
///
/// For `SingletonWriter` connectors, each state object represents an atomic
/// state transition. The chain is linked via `prev` references.
///
/// # Singleton Writer Fencing
///
/// For `SingletonWriter` model:
/// - `lease_seq` MUST be included (fencing token)
/// - `lease_object_id` MUST reference the authorizing Lease
/// - Verifiers MUST reject updates with stale `lease_seq`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateObject {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// Previous state object in the chain (`None` for genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,

    /// Monotonic sequence number.
    ///
    /// MUST increase for each state object. Used for ordering and fork detection.
    pub seq: u64,

    /// Canonical state blob (CBOR-encoded).
    ///
    /// The structure depends on the connector's state schema.
    pub state_cbor: Vec<u8>,

    /// Timestamp when this state was created (UNIX seconds).
    pub updated_at: u64,

    /// Fencing token (NORMATIVE for `SingletonWriter`).
    ///
    /// The `lease_seq` from the authorizing Lease. Verifiers MUST reject
    /// updates with stale fencing tokens.
    pub lease_seq: u64,

    /// The Lease object granting write authority (NORMATIVE for `SingletonWriter`).
    ///
    /// This MUST be included in `header.refs` for reference tracking.
    pub lease_object_id: ObjectId,

    /// Ed25519 signature over the canonical state object.
    pub signature: Signature,
}

impl ConnectorStateObject {
    /// Check if this is a genesis state object.
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.prev.is_none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Delta (NORMATIVE for CRDT models)
// ─────────────────────────────────────────────────────────────────────────────

/// Delta object for CRDT state models (NORMATIVE).
///
/// For `Crdt` connectors, deltas represent incremental changes that can be
/// merged according to CRDT semantics. Periodic snapshots compact the delta chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateDelta {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// CRDT type for this delta.
    pub crdt_type: CrdtType,

    /// Delta payload (CBOR-encoded).
    ///
    /// The structure depends on `crdt_type`:
    /// - `LwwMap`: `[(key, value, timestamp, actor)]`
    /// - `OrSet`: `[(element, add/remove, unique_tag)]`
    /// - `GCounter`: `[(actor_id, count)]`
    /// - `PnCounter`: `[(actor_id, pos_count, neg_count)]`
    pub delta_cbor: Vec<u8>,

    /// Timestamp when this delta was applied (UNIX seconds).
    pub applied_at: u64,

    /// Node that produced this delta.
    pub applied_by: TailscaleNodeId,

    /// Ed25519 signature over the canonical delta.
    pub signature: Signature,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Snapshot (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot for state compaction (NORMATIVE).
///
/// Snapshots capture the full state at a point in time, enabling:
/// - Efficient state recovery without replaying entire chain
/// - Garbage collection of older state objects/deltas
/// - Bounded storage consumption
///
/// # Compaction Rules
///
/// - `MeshNode` SHOULD create a snapshot every N updates or M bytes
/// - After snapshot is replicated, older objects MAY be GC'd
/// - Audit/policy pins may preserve older objects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateSnapshot {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// Latest state object included in this snapshot.
    pub covers_head: ObjectId,

    /// Sequence number of the covered head.
    pub covers_seq: u64,

    /// Full canonical state at `covers_head` (CBOR-encoded).
    pub state_cbor: Vec<u8>,

    /// Timestamp when this snapshot was created (UNIX seconds).
    pub snapshotted_at: u64,

    /// Ed25519 signature over the canonical snapshot.
    pub signature: Signature,
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection (NORMATIVE for SingletonWriter)
// ─────────────────────────────────────────────────────────────────────────────

/// Fork event indicating competing writes (NORMATIVE).
///
/// A fork occurs when two different `ConnectorStateObject` share the same `prev`
/// (competing sequence numbers). This indicates a lease violation or bug.
///
/// # Recovery Protocol
///
/// 1. Pause connector execution immediately
/// 2. Log the fork event for audit
/// 3. Require manual resolution OR automated "choose-by-lease" recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkEvent {
    /// The common predecessor.
    pub common_prev: ObjectId,

    /// First competing state object.
    pub branch_a: ObjectId,

    /// Second competing state object.
    pub branch_b: ObjectId,

    /// Sequence number at which the fork occurred.
    pub fork_seq: u64,

    /// Timestamp when the fork was detected (UNIX seconds).
    pub detected_at: u64,

    /// Zone in which the fork occurred.
    pub zone_id: ZoneId,

    /// Connector that experienced the fork.
    pub connector_id: ConnectorId,
}

/// Fork resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkResolution {
    /// Choose the branch with the higher `lease_seq`.
    ChooseByLease,

    /// Require manual intervention.
    ManualResolution,

    /// Merge both branches (only valid for CRDT state).
    CrdtMerge,
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton Writer Fencing Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when fencing validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencingError {
    /// The lease has expired.
    LeaseExpired { expired_at: u64, now: u64 },

    /// The `lease_seq` is stale (superseded by a newer lease).
    StaleLeaseSeq { held_seq: u64, current_seq: u64 },

    /// The lease is for the wrong subject.
    SubjectMismatch { expected: ObjectId, got: ObjectId },

    /// The lease purpose is not `ConnectorStateWrite`.
    WrongPurpose,

    /// The state object references a non-existent lease.
    LeaseNotFound { lease_id: ObjectId },
}

impl fmt::Display for FencingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseExpired { expired_at, now } => {
                write!(f, "lease expired at {expired_at}, current time is {now}")
            }
            Self::StaleLeaseSeq {
                held_seq,
                current_seq,
            } => {
                write!(
                    f,
                    "stale lease_seq: held {held_seq}, current is {current_seq}"
                )
            }
            Self::SubjectMismatch { expected, got } => {
                write!(f, "lease subject mismatch: expected {expected}, got {got}")
            }
            Self::WrongPurpose => {
                write!(f, "lease purpose is not ConnectorStateWrite")
            }
            Self::LeaseNotFound { lease_id } => {
                write!(f, "lease not found: {lease_id}")
            }
        }
    }
}

impl std::error::Error for FencingError {}

/// Validate that a state object has valid fencing for singleton-writer semantics.
///
/// # Arguments
///
/// * `state_obj` - The state object to validate
/// * `expected_subject` - The expected lease subject (usually the state root ID)
/// * `current_known_seq` - The highest known `lease_seq` for this subject
/// * `now` - Current timestamp for expiry checking
/// * `lease_exp` - Expiration time of the referenced lease
///
/// # Errors
///
/// Returns an error if fencing validation fails.
pub fn validate_singleton_writer_fencing(
    state_obj: &ConnectorStateObject,
    expected_subject: &ObjectId,
    current_known_seq: u64,
    now: u64,
    lease_exp: u64,
) -> Result<(), FencingError> {
    // Check lease expiry
    if now >= lease_exp {
        return Err(FencingError::LeaseExpired {
            expired_at: lease_exp,
            now,
        });
    }

    // Check fencing token is not stale
    if state_obj.lease_seq < current_known_seq {
        return Err(FencingError::StaleLeaseSeq {
            held_seq: state_obj.lease_seq,
            current_seq: current_known_seq,
        });
    }

    // Verify lease is in header refs
    if !state_obj.header.refs.contains(&state_obj.lease_object_id) {
        return Err(FencingError::LeaseNotFound {
            lease_id: state_obj.lease_object_id,
        });
    }

    // Note: Subject and purpose validation require the actual Lease object,
    // which should be done by the caller with access to the object store.
    let _ = expected_subject; // Used by caller for full validation

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for snapshot creation (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Create snapshot every N updates.
    #[serde(default = "default_snapshot_every_updates")]
    pub snapshot_every_updates: u32,

    /// Create snapshot every N bytes of state.
    #[serde(default = "default_snapshot_every_bytes")]
    pub snapshot_every_bytes: u64,
}

const fn default_snapshot_every_updates() -> u32 {
    5000
}

const fn default_snapshot_every_bytes() -> u64 {
    1_048_576 // 1 MiB
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            snapshot_every_updates: default_snapshot_every_updates(),
            snapshot_every_bytes: default_snapshot_every_bytes(),
        }
    }
}

impl SnapshotConfig {
    /// Check if a snapshot should be created.
    #[must_use]
    pub const fn should_snapshot(&self, updates_since_last: u32, bytes_since_last: u64) -> bool {
        updates_since_last >= self.snapshot_every_updates
            || bytes_since_last >= self.snapshot_every_bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // CrdtType Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crdt_type_display() {
        assert_eq!(CrdtType::LwwMap.to_string(), "lww_map");
        assert_eq!(CrdtType::OrSet.to_string(), "or_set");
        assert_eq!(CrdtType::GCounter.to_string(), "g_counter");
        assert_eq!(CrdtType::PnCounter.to_string(), "pn_counter");
    }

    #[test]
    fn crdt_type_serde_roundtrip() {
        for crdt_type in [
            CrdtType::LwwMap,
            CrdtType::OrSet,
            CrdtType::GCounter,
            CrdtType::PnCounter,
        ] {
            let json = serde_json::to_string(&crdt_type).unwrap();
            let deserialized: CrdtType = serde_json::from_str(&json).unwrap();
            assert_eq!(crdt_type, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateModel Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_model_stateless() {
        let model = ConnectorStateModel::Stateless;
        assert!(model.is_stateless());
        assert!(!model.is_singleton_writer());
        assert!(!model.is_crdt());
        assert!(model.crdt_type().is_none());
        assert_eq!(model.to_string(), "stateless");
    }

    #[test]
    fn connector_state_model_singleton_writer() {
        let model = ConnectorStateModel::SingletonWriter;
        assert!(!model.is_stateless());
        assert!(model.is_singleton_writer());
        assert!(!model.is_crdt());
        assert!(model.crdt_type().is_none());
        assert_eq!(model.to_string(), "singleton_writer");
    }

    #[test]
    fn connector_state_model_crdt() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        };
        assert!(!model.is_stateless());
        assert!(!model.is_singleton_writer());
        assert!(model.is_crdt());
        assert_eq!(model.crdt_type(), Some(CrdtType::LwwMap));
        assert_eq!(model.to_string(), "crdt(lww_map)");
    }

    #[test]
    fn connector_state_model_default_is_stateless() {
        let model = ConnectorStateModel::default();
        assert!(model.is_stateless());
    }

    #[test]
    fn connector_state_model_serde_roundtrip() {
        let models = [
            ConnectorStateModel::Stateless,
            ConnectorStateModel::SingletonWriter,
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::OrSet,
            },
        ];

        for model in models {
            let json = serde_json::to_string(&model).unwrap();
            let deserialized: ConnectorStateModel = serde_json::from_str(&json).unwrap();
            assert_eq!(model, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SnapshotConfig Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_config_default() {
        let config = SnapshotConfig::default();
        assert_eq!(config.snapshot_every_updates, 5000);
        assert_eq!(config.snapshot_every_bytes, 1_048_576);
    }

    #[test]
    fn snapshot_config_should_snapshot() {
        let config = SnapshotConfig {
            snapshot_every_updates: 100,
            snapshot_every_bytes: 1000,
        };

        assert!(!config.should_snapshot(50, 500));
        assert!(config.should_snapshot(100, 500)); // Updates threshold
        assert!(config.should_snapshot(50, 1000)); // Bytes threshold
        assert!(config.should_snapshot(100, 1000)); // Both thresholds
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signature Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_zero() {
        let sig = Signature::zero();
        assert_eq!(sig.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn signature_from_bytes() {
        let bytes = [42u8; 64];
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn signature_display() {
        let sig = Signature::from_bytes([0xab; 64]);
        let display = sig.to_string();
        assert!(display.contains("abababab"));
        assert!(display.ends_with("..."));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FencingError Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fencing_error_display() {
        let err = FencingError::LeaseExpired {
            expired_at: 1000,
            now: 2000,
        };
        assert!(err.to_string().contains("expired"));

        let err = FencingError::StaleLeaseSeq {
            held_seq: 5,
            current_seq: 10,
        };
        assert!(err.to_string().contains("stale"));

        let err = FencingError::WrongPurpose;
        assert!(err.to_string().contains("ConnectorStateWrite"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkResolution Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_resolution_serde() {
        let resolutions = [
            ForkResolution::ChooseByLease,
            ForkResolution::ManualResolution,
            ForkResolution::CrdtMerge,
        ];

        for resolution in resolutions {
            let json = serde_json::to_string(&resolution).unwrap();
            let deserialized: ForkResolution = serde_json::from_str(&json).unwrap();
            assert_eq!(resolution, deserialized);
        }
    }
}

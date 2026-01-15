//! Golden vector tests for Trust/Quorum Model.
//!
//! This module provides:
//! - CBOR golden vector generation and verification
//! - Structured test logging per FCP2 requirements
//!
//! Golden vectors are stored in `tests/vectors/quorum/`:
//! - `quorum_3_of_3.cbor` - 3-node unanimous quorum
//! - `quorum_3_of_5.cbor` - 3-of-5 quorum configuration
//! - `degraded_state.cbor` - Degraded mode state snapshot

use std::fs;
use std::path::PathBuf;

use fcp_core::{
    DegradedModeReason, DegradedModeState, NodeId, NodeSignature, QuorumPolicy, RiskTier,
    SignatureSet, ZoneId,
};

/// Test logging structure per FCP2 requirements.
#[derive(Debug, serde::Serialize)]
struct TestLogEntry {
    timestamp: String,
    test_name: String,
    phase: String,
    correlation_id: String,
    n: u32,
    f: u32,
    quorum_size: u32,
    signatures_collected: u32,
    result: String,
}

impl TestLogEntry {
    fn new(test_name: &str, n: u32, f: u32, quorum_size: u32, signatures_collected: u32) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: test_name.to_string(),
            phase: "execute".to_string(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
            n,
            f,
            quorum_size,
            signatures_collected,
            result: "pending".to_string(),
        }
    }

    fn pass(mut self) -> Self {
        self.result = "pass".to_string();
        self
    }

    #[allow(dead_code)]
    fn fail(mut self) -> Self {
        self.result = "fail".to_string();
        self
    }

    fn log(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap());
    }
}

/// Get the path to the golden vectors directory.
fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("quorum")
}

/// Create a signature set with the specified number of nodes.
fn create_signature_set(node_count: usize) -> SignatureSet {
    let mut set = SignatureSet::new();
    for i in 0..node_count {
        set.add(NodeSignature::new(
            NodeId::new(format!("node-{i:02}")),
            [i as u8; 64],
            1704067200 + i as u64, // 2024-01-01 00:00:00 + offset
        ));
    }
    set
}

/// Golden vector: 3-of-3 unanimous quorum.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct Quorum3Of3Vector {
    /// Policy configuration
    zone_id: String,
    eligible_nodes: u32,
    max_faults: u32,
    /// Quorum requirements per tier
    safe_required: u32,
    risky_required: u32,
    dangerous_required: u32,
    critical_required: u32,
    /// Signature set
    signatures: Vec<SignatureEntry>,
    /// Verification result
    satisfies_critical: bool,
}

/// Golden vector: 3-of-5 quorum.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct Quorum3Of5Vector {
    /// Policy configuration
    zone_id: String,
    eligible_nodes: u32,
    max_faults: u32,
    /// Quorum requirements per tier
    safe_required: u32,
    risky_required: u32,
    dangerous_required: u32,
    critical_required: u32,
    /// Signature set (3 signatures)
    signatures: Vec<SignatureEntry>,
    /// Verification results
    satisfies_safe: bool,
    satisfies_risky: bool,
    satisfies_dangerous: bool,
    satisfies_critical: bool,
}

/// Golden vector: degraded mode state.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct DegradedStateVector {
    /// Whether degraded mode is active
    active: bool,
    /// Reason for degraded mode
    reason: String,
    /// When degraded mode was entered (Unix timestamp)
    entered_at: u64,
    /// Available vs expected nodes
    available_nodes: u32,
    expected_nodes: u32,
    /// Policy configuration
    eligible_nodes: u32,
    max_faults: u32,
    degraded_mode_min_nodes: u32,
    /// Whether Safe operations can proceed
    can_proceed_safe: bool,
    /// Whether Risky operations can proceed
    can_proceed_risky: bool,
}

/// Signature entry for serialization.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct SignatureEntry {
    node_id: String,
    #[serde(with = "hex::serde")]
    signature: [u8; 64],
    signed_at: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Generation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_generate_quorum_3_of_3_golden_vector() {
    let mut log = TestLogEntry::new("test_generate_quorum_3_of_3_golden_vector", 3, 0, 3, 3);

    // Create 3-node unanimous policy (f=0)
    let policy = QuorumPolicy::new(ZoneId::work(), 3, 0);
    let sig_set = create_signature_set(3);

    // Build vector
    let vector = Quorum3Of3Vector {
        zone_id: "z:work".to_string(),
        eligible_nodes: 3,
        max_faults: 0,
        safe_required: policy.required_signatures(RiskTier::Safe),
        risky_required: policy.required_signatures(RiskTier::Risky),
        dangerous_required: policy.required_signatures(RiskTier::Dangerous),
        critical_required: policy.required_signatures(RiskTier::CriticalWrite),
        signatures: sig_set
            .iter()
            .map(|s| SignatureEntry {
                node_id: s.node_id.as_str().to_string(),
                signature: s.signature,
                signed_at: s.signed_at,
            })
            .collect(),
        satisfies_critical: sig_set.satisfies_quorum(&policy, RiskTier::CriticalWrite),
    };

    // Verify expectations
    assert_eq!(vector.safe_required, 1);
    assert_eq!(vector.risky_required, 1); // f + 1 = 0 + 1
    assert_eq!(vector.dangerous_required, 3); // n - f = 3 - 0
    assert_eq!(vector.critical_required, 3);
    assert!(vector.satisfies_critical);

    // Serialize to CBOR
    let cbor_bytes = {
        let mut buf = Vec::new();
        ciborium::into_writer(&vector, &mut buf).expect("CBOR serialization failed");
        buf
    };

    // Write to file
    let path = vectors_dir().join("quorum_3_of_3.cbor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &cbor_bytes).expect("Failed to write golden vector");

    // Verify round-trip
    let loaded: Quorum3Of3Vector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");
    assert_eq!(loaded, vector);

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_quorum_3_of_5_golden_vector() {
    let mut log = TestLogEntry::new("test_generate_quorum_3_of_5_golden_vector", 5, 2, 3, 3);

    // Create 5-node policy with f=2 (tolerates 2 Byzantine faults)
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
    let sig_set = create_signature_set(3); // Only 3 signatures

    // Build vector
    let vector = Quorum3Of5Vector {
        zone_id: "z:work".to_string(),
        eligible_nodes: 5,
        max_faults: 2,
        safe_required: policy.required_signatures(RiskTier::Safe),
        risky_required: policy.required_signatures(RiskTier::Risky),
        dangerous_required: policy.required_signatures(RiskTier::Dangerous),
        critical_required: policy.required_signatures(RiskTier::CriticalWrite),
        signatures: sig_set
            .iter()
            .map(|s| SignatureEntry {
                node_id: s.node_id.as_str().to_string(),
                signature: s.signature,
                signed_at: s.signed_at,
            })
            .collect(),
        satisfies_safe: sig_set.satisfies_quorum(&policy, RiskTier::Safe),
        satisfies_risky: sig_set.satisfies_quorum(&policy, RiskTier::Risky),
        satisfies_dangerous: sig_set.satisfies_quorum(&policy, RiskTier::Dangerous),
        satisfies_critical: sig_set.satisfies_quorum(&policy, RiskTier::CriticalWrite),
    };

    // Verify expectations
    assert_eq!(vector.safe_required, 1);
    assert_eq!(vector.risky_required, 3); // f + 1 = 2 + 1
    assert_eq!(vector.dangerous_required, 3); // n - f = 5 - 2
    assert_eq!(vector.critical_required, 3);

    // With 3 signatures:
    assert!(vector.satisfies_safe); // 3 >= 1
    assert!(vector.satisfies_risky); // 3 >= 3
    assert!(vector.satisfies_dangerous); // 3 >= 3
    assert!(vector.satisfies_critical); // 3 >= 3

    // Serialize to CBOR
    let cbor_bytes = {
        let mut buf = Vec::new();
        ciborium::into_writer(&vector, &mut buf).expect("CBOR serialization failed");
        buf
    };

    // Write to file
    let path = vectors_dir().join("quorum_3_of_5.cbor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &cbor_bytes).expect("Failed to write golden vector");

    // Verify round-trip
    let loaded: Quorum3Of5Vector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");
    assert_eq!(loaded, vector);

    log = log.pass();
    log.log();
}

#[test]
fn test_generate_degraded_state_golden_vector() {
    let mut log = TestLogEntry::new("test_generate_degraded_state_golden_vector", 5, 1, 4, 3);

    // Create policy with degraded mode enabled
    let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(3);

    // Create degraded state
    let state = DegradedModeState::degraded(
        DegradedModeReason::NodeFailure,
        1704067200, // 2024-01-01 00:00:00 UTC
        3,          // 3 nodes available
        5,          // 5 expected
    );

    // Build vector
    let vector = DegradedStateVector {
        active: state.active,
        reason: state
            .reason
            .map_or("none".to_string(), |r| r.as_str().to_string()),
        entered_at: state.entered_at.unwrap_or(0),
        available_nodes: state.available_nodes,
        expected_nodes: state.expected_nodes,
        eligible_nodes: policy.eligible_nodes,
        max_faults: policy.max_faults,
        degraded_mode_min_nodes: policy.degraded_mode_min_nodes,
        can_proceed_safe: policy.can_proceed_degraded(3, RiskTier::Safe),
        can_proceed_risky: policy.can_proceed_degraded(3, RiskTier::Risky),
    };

    // Verify expectations
    assert!(vector.active);
    assert_eq!(vector.reason, "node_failure");
    assert_eq!(vector.available_nodes, 3);
    assert_eq!(vector.expected_nodes, 5);
    assert!(vector.can_proceed_safe); // Safe ops allowed in degraded mode
    assert!(!vector.can_proceed_risky); // Risky ops NOT allowed in degraded mode

    // Serialize to CBOR
    let cbor_bytes = {
        let mut buf = Vec::new();
        ciborium::into_writer(&vector, &mut buf).expect("CBOR serialization failed");
        buf
    };

    // Write to file
    let path = vectors_dir().join("degraded_state.cbor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &cbor_bytes).expect("Failed to write golden vector");

    // Verify round-trip
    let loaded: DegradedStateVector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");
    assert_eq!(loaded, vector);

    log = log.pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Verification Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_verify_quorum_3_of_3_golden_vector() {
    let path = vectors_dir().join("quorum_3_of_3.cbor");

    // Skip if file doesn't exist (will be created by generation test)
    if !path.exists() {
        eprintln!("Skipping verification: {path:?} not found (run generation test first)");
        return;
    }

    let cbor_bytes = fs::read(&path).expect("Failed to read golden vector");
    let vector: Quorum3Of3Vector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");

    // Verify structure
    assert_eq!(vector.eligible_nodes, 3);
    assert_eq!(vector.max_faults, 0);
    assert_eq!(vector.safe_required, 1);
    assert_eq!(vector.critical_required, 3);
    assert_eq!(vector.signatures.len(), 3);
    assert!(vector.satisfies_critical);

    // Verify signatures are properly ordered
    let node_ids: Vec<_> = vector.signatures.iter().map(|s| &s.node_id).collect();
    let mut sorted = node_ids.clone();
    sorted.sort();
    assert_eq!(node_ids, sorted, "Signatures must be sorted by node_id");
}

#[test]
fn test_verify_quorum_3_of_5_golden_vector() {
    let path = vectors_dir().join("quorum_3_of_5.cbor");

    if !path.exists() {
        eprintln!("Skipping verification: {path:?} not found");
        return;
    }

    let cbor_bytes = fs::read(&path).expect("Failed to read golden vector");
    let vector: Quorum3Of5Vector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");

    // Verify structure
    assert_eq!(vector.eligible_nodes, 5);
    assert_eq!(vector.max_faults, 2);
    assert_eq!(vector.signatures.len(), 3);

    // 3 signatures should satisfy all tiers for n=5, f=2
    assert!(vector.satisfies_safe);
    assert!(vector.satisfies_risky);
    assert!(vector.satisfies_dangerous);
    assert!(vector.satisfies_critical);
}

#[test]
fn test_verify_degraded_state_golden_vector() {
    let path = vectors_dir().join("degraded_state.cbor");

    if !path.exists() {
        eprintln!("Skipping verification: {path:?} not found");
        return;
    }

    let cbor_bytes = fs::read(&path).expect("Failed to read golden vector");
    let vector: DegradedStateVector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");

    // Verify structure
    assert!(vector.active);
    assert_eq!(vector.reason, "node_failure");
    assert_eq!(vector.available_nodes, 3);
    assert_eq!(vector.expected_nodes, 5);
    assert!(vector.can_proceed_safe);
    assert!(!vector.can_proceed_risky);
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging Format Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_logging_format_compliance() {
    // Verify that test log entries match the required format
    let log = TestLogEntry::new("test_quorum_threshold", 5, 1, 4, 4).pass();

    let json = serde_json::to_string(&log).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify required fields
    assert!(parsed.get("timestamp").is_some());
    assert_eq!(parsed.get("test_name").unwrap(), "test_quorum_threshold");
    assert_eq!(parsed.get("phase").unwrap(), "execute");
    assert!(parsed.get("correlation_id").is_some());
    assert_eq!(parsed.get("n").unwrap(), 5);
    assert_eq!(parsed.get("f").unwrap(), 1);
    assert_eq!(parsed.get("quorum_size").unwrap(), 4);
    assert_eq!(parsed.get("signatures_collected").unwrap(), 4);
    assert_eq!(parsed.get("result").unwrap(), "pass");
}

#[test]
fn test_logging_rfc3339_timestamp() {
    let log = TestLogEntry::new("test_timestamp", 1, 0, 1, 1);

    // Verify timestamp is valid RFC3339
    let parsed = chrono::DateTime::parse_from_rfc3339(&log.timestamp);
    assert!(parsed.is_ok(), "Timestamp should be valid RFC3339");
}

#[test]
fn test_logging_uuid_correlation_id() {
    let log = TestLogEntry::new("test_correlation", 1, 0, 1, 1);

    // Verify correlation_id is valid UUID
    let parsed = uuid::Uuid::parse_str(&log.correlation_id);
    assert!(parsed.is_ok(), "Correlation ID should be valid UUID");
}

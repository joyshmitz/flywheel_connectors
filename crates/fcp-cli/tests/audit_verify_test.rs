//! Integration tests for `fcp audit verify` command (bd-1im5).
//!
//! Tests audit chain verification with structured JSONL logging per
//! `docs/STANDARD_Testing_Logging.md`.
//!
//! # Test Coverage
//!
//! - Valid chain passes verification
//! - Missing link (seq gap) fails with expected code
//! - Fork detection triggers failure
//! - Zone mismatch detection
//! - Genesis validation
//!
//! # Logging
//!
//! All tests emit structured JSONL with `test_name`, `module`, `phase`,
//! `correlation_id`, and `result`.

use assert_cmd::Command;
use predicates::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use tempfile::TempDir;

/// Structured log entry per `STANDARD_Testing_Logging.md`.
#[derive(Debug, Serialize)]
struct TestLogEntry {
    timestamp: String,
    level: String,
    test_name: String,
    module: String,
    phase: String,
    correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

impl TestLogEntry {
    fn new(test_name: &str, correlation_id: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: "info".into(),
            test_name: test_name.into(),
            module: "fcp-cli::audit".into(),
            phase: "setup".into(),
            correlation_id: correlation_id.into(),
            message: None,
            result: None,
            chain_seq: None,
            error_code: None,
        }
    }

    fn phase(mut self, phase: &str) -> Self {
        self.phase = phase.into();
        self
    }

    fn message(mut self, msg: &str) -> Self {
        self.message = Some(msg.into());
        self
    }

    fn result(mut self, result: &str) -> Self {
        self.result = Some(result.into());
        self
    }

    const fn chain_seq(mut self, seq: u64) -> Self {
        self.chain_seq = Some(seq);
        self
    }

    fn error_code(mut self, code: &str) -> Self {
        self.error_code = Some(code.into());
        self
    }

    fn emit(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap_or_default());
    }
}

/// Get the `fcp` command for testing.
fn fcp_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
    cmd.env("RUST_LOG", "error");
    cmd
}

/// Generate a correlation ID for test tracing.
fn correlation_id() -> String {
    format!("test-{}", std::process::id())
}

/// Audit event record for test data.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEventRecord {
    object_id: String,
    event: AuditEventData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEventData {
    header: HeaderData,
    correlation_id: String,
    event_type: String,
    actor: String,
    zone_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev: Option<String>,
    seq: u64,
    occurred_at: u64,
    signature: SignatureData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderData {
    schema: SchemaData,
    zone_id: String,
    created_at: u64,
    provenance: ProvenanceData,
    refs: Vec<String>,
    foreign_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemaData {
    namespace: String,
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvenanceData {
    origin_zone: String,
    current_zone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureData {
    node_id: String,
    signature: String,
    signed_at: u64,
}

/// Generate a deterministic hex object ID from a sequence number.
fn hex_object_id(seq: u64) -> String {
    // Create a 32-byte (64 hex char) deterministic ID
    format!("{seq:064x}")
}

fn create_test_event(seq: u64, prev: Option<&str>) -> AuditEventRecord {
    AuditEventRecord {
        object_id: hex_object_id(seq),
        event: AuditEventData {
            header: HeaderData {
                schema: SchemaData {
                    namespace: "fcp.core".into(),
                    name: "AuditEvent".into(),
                    version: "1.0.0".into(),
                },
                zone_id: "z:work".into(),
                created_at: 1_700_000_000 + seq,
                provenance: ProvenanceData {
                    origin_zone: "z:work".into(),
                    current_zone: "z:work".into(),
                },
                refs: vec![],
                foreign_refs: vec![],
            },
            correlation_id: format!("{seq:032x}"),
            event_type: "capability.invoke".into(),
            actor: "user:alice".into(),
            zone_id: "z:work".into(),
            prev: prev.map(String::from),
            seq,
            occurred_at: 1_700_000_000 + seq,
            signature: SignatureData {
                node_id: "node-1".into(),
                signature: "0".repeat(128),
                signed_at: 1_700_000_000 + seq,
            },
        },
    }
}

fn write_events_jsonl(events: &[AuditEventRecord], path: &std::path::Path) {
    let content: String = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, content).expect("write events");
}

mod audit_verify {
    use super::*;

    #[test]
    fn valid_chain_passes_verification() {
        let corr_id = correlation_id();
        let log = TestLogEntry::new("valid_chain_passes_verification", &corr_id);
        log.phase("setup").message("Creating valid chain").emit();

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Create valid chain: genesis (seq 0) → seq 1 → seq 2
        let events = vec![
            create_test_event(0, None),
            create_test_event(1, Some(&hex_object_id(0))),
            create_test_event(2, Some(&hex_object_id(1))),
        ];
        write_events_jsonl(&events, &events_path);

        TestLogEntry::new("valid_chain_passes_verification", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify")
            .chain_seq(2)
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"ok\""));

        TestLogEntry::new("valid_chain_passes_verification", &corr_id)
            .phase("verify")
            .result("pass")
            .message("Valid chain verified successfully")
            .emit();
    }

    #[test]
    fn missing_link_fails_with_seq_gap() {
        let corr_id = correlation_id();
        let log = TestLogEntry::new("missing_link_fails_with_seq_gap", &corr_id);
        log.phase("setup")
            .message("Creating chain with seq gap")
            .emit();

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Create chain with gap: seq 0, seq 2 (missing seq 1)
        let events = vec![
            create_test_event(0, None),
            create_test_event(2, Some(&hex_object_id(0))), // Gap: should be seq 1
        ];
        write_events_jsonl(&events, &events_path);

        TestLogEntry::new("missing_link_fails_with_seq_gap", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify on gapped chain")
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success() // Command succeeds but reports failure status
            .stdout(predicate::str::contains("\"status\": \"fail\""))
            .stdout(predicate::str::contains("audit.seq_gap"));

        TestLogEntry::new("missing_link_fails_with_seq_gap", &corr_id)
            .phase("verify")
            .result("pass")
            .error_code("audit.seq_gap")
            .message("Seq gap correctly detected")
            .emit();
    }

    #[test]
    fn fork_detection_triggers_failure() {
        let corr_id = correlation_id();
        let log = TestLogEntry::new("fork_detection_triggers_failure", &corr_id);
        log.phase("setup").message("Creating forked chain").emit();

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Create fork: two events with same seq but different object_ids
        let event1 = create_test_event(1, Some(&hex_object_id(0)));
        let mut event2 = create_test_event(1, Some(&hex_object_id(0)));
        // Use a different hex ID for the fork
        event2.object_id = format!("{:064x}", 999u64); // Different ID, same seq

        let audit_events = vec![create_test_event(0, None), event1, event2];
        write_events_jsonl(&audit_events, &events_path);

        TestLogEntry::new("fork_detection_triggers_failure", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify on forked chain")
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"fail\""))
            .stdout(predicate::str::contains("audit.fork_detected"));

        TestLogEntry::new("fork_detection_triggers_failure", &corr_id)
            .phase("verify")
            .result("pass")
            .error_code("audit.fork_detected")
            .message("Fork correctly detected")
            .emit();
    }

    #[test]
    fn genesis_without_seq_zero_fails() {
        let corr_id = correlation_id();
        TestLogEntry::new("genesis_without_seq_zero_fails", &corr_id)
            .phase("setup")
            .message("Creating chain starting at seq 1")
            .emit();

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Chain starting at seq 1 (no genesis)
        let events = vec![
            create_test_event(1, None), // Should fail: not seq 0
        ];
        write_events_jsonl(&events, &events_path);

        TestLogEntry::new("genesis_without_seq_zero_fails", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify")
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"fail\""))
            .stdout(predicate::str::contains("audit.genesis_invalid"));

        TestLogEntry::new("genesis_without_seq_zero_fails", &corr_id)
            .phase("verify")
            .result("pass")
            .error_code("audit.genesis_invalid")
            .message("Genesis validation correctly failed")
            .emit();
    }

    #[test]
    fn prev_mismatch_fails_verification() {
        let corr_id = correlation_id();
        TestLogEntry::new("prev_mismatch_fails_verification", &corr_id)
            .phase("setup")
            .message("Creating chain with wrong prev pointer")
            .emit();

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Event 1 points to wrong prev
        let events = vec![
            create_test_event(0, None),
            create_test_event(1, Some(&format!("{:064x}", 999u64))), // Wrong prev
        ];
        write_events_jsonl(&events, &events_path);

        TestLogEntry::new("prev_mismatch_fails_verification", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify")
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"fail\""))
            .stdout(predicate::str::contains("audit.prev_mismatch"));

        TestLogEntry::new("prev_mismatch_fails_verification", &corr_id)
            .phase("verify")
            .result("pass")
            .error_code("audit.prev_mismatch")
            .message("Prev mismatch correctly detected")
            .emit();
    }

    #[test]
    fn empty_chain_returns_warn() {
        let corr_id = correlation_id();
        TestLogEntry::new("empty_chain_returns_warn", &corr_id)
            .phase("setup")
            .message("Creating empty events file")
            .emit();

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");
        fs::write(&events_path, "").expect("write empty file");

        TestLogEntry::new("empty_chain_returns_warn", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify on empty chain")
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"warn\""))
            .stdout(predicate::str::contains("audit.chain.empty"));

        TestLogEntry::new("empty_chain_returns_warn", &corr_id)
            .phase("verify")
            .result("pass")
            .error_code("audit.chain.empty")
            .message("Empty chain warning correctly issued")
            .emit();
    }

    #[test]
    fn zone_filter_validates_events() {
        let corr_id = correlation_id();
        TestLogEntry::new("zone_filter_validates_events", &corr_id)
            .phase("setup")
            .message("Creating chain with mismatched zone")
            .emit();

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Events are in z:work, but we filter for z:private
        let events = vec![create_test_event(0, None)];
        write_events_jsonl(&events, &events_path);

        TestLogEntry::new("zone_filter_validates_events", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify with zone filter")
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--zone", "z:private"])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"warn\""))
            .stdout(predicate::str::contains("audit.zone_mismatch"));

        TestLogEntry::new("zone_filter_validates_events", &corr_id)
            .phase("verify")
            .result("pass")
            .error_code("audit.zone_mismatch")
            .message("Zone mismatch correctly detected")
            .emit();
    }

    #[test]
    fn verify_requires_events_flag() {
        let corr_id = correlation_id();
        TestLogEntry::new("verify_requires_events_flag", &corr_id)
            .phase("execute")
            .message("Running fcp audit verify without --events")
            .emit();

        fcp_cmd()
            .args(["audit", "verify"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--events"));

        TestLogEntry::new("verify_requires_events_flag", &corr_id)
            .phase("verify")
            .result("pass")
            .message("Missing --events correctly reported")
            .emit();
    }
}

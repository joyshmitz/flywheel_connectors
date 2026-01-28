//! E2E tests for `fcp audit verify` and `fcp audit timeline` (bd-161t).
//!
//! Uses a harness to generate audit chains and validates CLI output with
//! structured JSONL logging per `docs/STANDARD_Testing_Logging.md`.
//!
//! # Test Scenarios
//!
//! - Generate valid audit chain, verify passes, timeline renders correctly
//! - Generate chain with issues, verify detects problems
//! - Timeline filtering by zone and limit
//!
//! # Logging
//!
//! All tests emit structured JSONL with `test_name`, `module`, `phase`,
//! `correlation_id`, and `result` to `/tmp/test_artifacts/`.

use assert_cmd::Command;
use chrono::Utc;
use predicates::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

/// Structured log entry per `STANDARD_Testing_Logging.md`.
#[derive(Debug, Serialize, Deserialize)]
struct E2eLogEntry {
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
    chain_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issues_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

impl E2eLogEntry {
    fn new(test_name: &str, correlation_id: &str) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            level: "info".into(),
            test_name: test_name.into(),
            module: "fcp-cli::audit::e2e".into(),
            phase: "setup".into(),
            correlation_id: correlation_id.into(),
            message: None,
            result: None,
            chain_len: None,
            issues_found: None,
            error_code: None,
            duration_ms: None,
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

    const fn chain_len(mut self, len: usize) -> Self {
        self.chain_len = Some(len);
        self
    }

    const fn issues_found(mut self, count: usize) -> Self {
        self.issues_found = Some(count);
        self
    }

    fn error_code(mut self, code: &str) -> Self {
        self.error_code = Some(code.into());
        self
    }

    const fn duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }
}

/// Log collector for E2E tests.
struct E2eLogCollector {
    entries: Vec<E2eLogEntry>,
    log_file: Option<File>,
}

impl E2eLogCollector {
    fn new(log_path: Option<&PathBuf>) -> Self {
        let log_file = log_path.and_then(|p| {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).ok();
            }
            File::create(p).ok()
        });
        Self {
            entries: Vec::new(),
            log_file,
        }
    }

    fn push(&mut self, entry: E2eLogEntry) {
        if let Some(ref mut f) = self.log_file {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = writeln!(f, "{json}");
            }
        }
        // Also emit to stderr for test visibility
        if let Ok(json) = serde_json::to_string(&entry) {
            eprintln!("{json}");
        }
        self.entries.push(entry);
    }

    fn to_jsonl(&self) -> String {
        self.entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Audit event record for test data generation.
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

// Note: TraceContext requires [u8; 16] trace_id and [u8; 8] span_id byte arrays.
// For simplicity, E2E tests omit trace_context. Unit tests in audit_verify_test.rs
// demonstrate the core verification logic without trace context.

/// Test harness for generating audit chains.
struct AuditChainHarness {
    zone_id: String,
    events: Vec<AuditEventRecord>,
    base_timestamp: u64,
}

impl AuditChainHarness {
    fn new(zone_id: &str) -> Self {
        Self {
            zone_id: zone_id.into(),
            events: Vec::new(),
            base_timestamp: 1_700_000_000,
        }
    }

    /// Generate a deterministic hex object ID from a sequence number.
    fn object_id(seq: u64) -> String {
        format!("{seq:064x}")
    }

    /// Add an event to the chain.
    fn add_event(&mut self, event_type: &str, actor: &str) -> &mut Self {
        let seq = self.events.len() as u64;
        let prev = if seq == 0 {
            None
        } else {
            Some(Self::object_id(seq - 1))
        };

        let event = AuditEventRecord {
            object_id: Self::object_id(seq),
            event: AuditEventData {
                header: HeaderData {
                    schema: SchemaData {
                        namespace: "fcp.core".into(),
                        name: "AuditEvent".into(),
                        version: "1.0.0".into(),
                    },
                    zone_id: self.zone_id.clone(),
                    created_at: self.base_timestamp + seq,
                    provenance: ProvenanceData {
                        origin_zone: self.zone_id.clone(),
                        current_zone: self.zone_id.clone(),
                    },
                    refs: vec![],
                    foreign_refs: vec![],
                },
                correlation_id: format!("{seq:032x}"),
                event_type: event_type.into(),
                actor: actor.into(),
                zone_id: self.zone_id.clone(),
                prev,
                seq,
                occurred_at: self.base_timestamp + seq,
                signature: SignatureData {
                    node_id: "node-1".into(),
                    signature: "0".repeat(128),
                    signed_at: self.base_timestamp + seq,
                },
            },
        };
        self.events.push(event);
        self
    }

    /// Add a genesis event (seq 0).
    fn genesis(&mut self, actor: &str) -> &mut Self {
        self.add_event("zone.created", actor)
    }

    /// Add a capability invoke event.
    fn capability_invoke(&mut self, actor: &str) -> &mut Self {
        self.add_event("capability.invoke", actor)
    }

    /// Add a secret access event.
    fn secret_access(&mut self, actor: &str) -> &mut Self {
        self.add_event("secret.access", actor)
    }

    /// Add a security violation event.
    fn security_violation(&mut self, actor: &str) -> &mut Self {
        self.add_event("security.violation", actor)
    }

    /// Write events to a JSONL file.
    fn write_to(&self, path: &std::path::Path) {
        let content: String = self
            .events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(path, content).expect("write events");
    }

    /// Get the number of events.
    fn len(&self) -> usize {
        self.events.len()
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
    format!(
        "e2e-{}-{}",
        std::process::id(),
        Utc::now().timestamp_millis()
    )
}

/// Get the log output directory.
fn log_output_dir() -> PathBuf {
    PathBuf::from("/tmp/test_artifacts")
}

mod e2e_audit {
    use super::*;

    #[test]
    fn e2e_valid_chain_verify_and_timeline() {
        let corr_id = correlation_id();
        let log_path = log_output_dir().join("e2e_valid_chain.jsonl");
        let mut logs = E2eLogCollector::new(Some(&log_path));
        let start = std::time::Instant::now();

        logs.push(
            E2eLogEntry::new("e2e_valid_chain_verify_and_timeline", &corr_id)
                .phase("setup")
                .message("Creating valid audit chain with harness"),
        );

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Generate a realistic audit chain
        let mut harness = AuditChainHarness::new("z:work");
        harness
            .genesis("system:bootstrap")
            .capability_invoke("user:alice")
            .secret_access("user:alice")
            .capability_invoke("user:bob")
            .security_violation("user:mallory");

        harness.write_to(&events_path);

        logs.push(
            E2eLogEntry::new("e2e_valid_chain_verify_and_timeline", &corr_id)
                .phase("execute")
                .message("Running fcp audit verify")
                .chain_len(harness.len()),
        );

        // Test verify command
        let verify_output = fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let verify_stdout = String::from_utf8_lossy(&verify_output);
        assert!(
            verify_stdout.contains("\"status\": \"ok\""),
            "Expected status ok, got: {verify_stdout}"
        );

        logs.push(
            E2eLogEntry::new("e2e_valid_chain_verify_and_timeline", &corr_id)
                .phase("verify")
                .message("Verify command succeeded")
                .result("pass"),
        );

        // Test timeline command
        logs.push(
            E2eLogEntry::new("e2e_valid_chain_verify_and_timeline", &corr_id)
                .phase("execute")
                .message("Running fcp audit timeline"),
        );

        let timeline_output = fcp_cmd()
            .args(["audit", "timeline"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let timeline_stdout = String::from_utf8_lossy(&timeline_output);
        // Timeline should have all 5 events
        assert!(
            timeline_stdout.contains("zone.created"),
            "Timeline should include genesis event"
        );
        assert!(
            timeline_stdout.contains("capability.invoke"),
            "Timeline should include capability invoke"
        );
        assert!(
            timeline_stdout.contains("security.violation"),
            "Timeline should include security violation"
        );

        #[allow(clippy::cast_possible_truncation)] // Test durations fit in u64
        let elapsed = start.elapsed().as_millis() as u64;
        logs.push(
            E2eLogEntry::new("e2e_valid_chain_verify_and_timeline", &corr_id)
                .phase("verify")
                .result("pass")
                .message("E2E valid chain scenario completed successfully")
                .chain_len(harness.len())
                .issues_found(0)
                .duration_ms(elapsed),
        );
    }

    #[test]
    fn e2e_broken_chain_detection() {
        let corr_id = correlation_id();
        let log_path = log_output_dir().join("e2e_broken_chain.jsonl");
        let mut logs = E2eLogCollector::new(Some(&log_path));
        let start = std::time::Instant::now();

        logs.push(
            E2eLogEntry::new("e2e_broken_chain_detection", &corr_id)
                .phase("setup")
                .message("Creating chain with sequence gap"),
        );

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Create chain with a gap: seq 0, seq 2 (missing seq 1)
        let mut harness = AuditChainHarness::new("z:work");
        harness.genesis("system:bootstrap");

        // Manually add a broken event with wrong seq
        let broken_event = AuditEventRecord {
            object_id: AuditChainHarness::object_id(2),
            event: AuditEventData {
                header: HeaderData {
                    schema: SchemaData {
                        namespace: "fcp.core".into(),
                        name: "AuditEvent".into(),
                        version: "1.0.0".into(),
                    },
                    zone_id: "z:work".into(),
                    created_at: 1_700_000_002,
                    provenance: ProvenanceData {
                        origin_zone: "z:work".into(),
                        current_zone: "z:work".into(),
                    },
                    refs: vec![],
                    foreign_refs: vec![],
                },
                correlation_id: format!("{:032x}", 2u64),
                event_type: "capability.invoke".into(),
                actor: "user:alice".into(),
                zone_id: "z:work".into(),
                prev: Some(AuditChainHarness::object_id(0)),
                seq: 2, // Gap: should be seq 1
                occurred_at: 1_700_000_002,
                signature: SignatureData {
                    node_id: "node-1".into(),
                    signature: "0".repeat(128),
                    signed_at: 1_700_000_002,
                },
            },
        };
        harness.events.push(broken_event);
        harness.write_to(&events_path);

        logs.push(
            E2eLogEntry::new("e2e_broken_chain_detection", &corr_id)
                .phase("execute")
                .message("Running fcp audit verify on broken chain"),
        );

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"fail\""))
            .stdout(predicate::str::contains("audit.seq_gap"));

        #[allow(clippy::cast_possible_truncation)] // Test durations fit in u64
        let elapsed = start.elapsed().as_millis() as u64;
        logs.push(
            E2eLogEntry::new("e2e_broken_chain_detection", &corr_id)
                .phase("verify")
                .result("pass")
                .error_code("audit.seq_gap")
                .message("Sequence gap correctly detected")
                .issues_found(1)
                .duration_ms(elapsed),
        );
    }

    #[test]
    fn e2e_timeline_with_limit() {
        let corr_id = correlation_id();
        let log_path = log_output_dir().join("e2e_timeline_limit.jsonl");
        let mut logs = E2eLogCollector::new(Some(&log_path));

        logs.push(
            E2eLogEntry::new("e2e_timeline_with_limit", &corr_id)
                .phase("setup")
                .message("Creating chain with 10 events"),
        );

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Generate a chain with 10 events
        let mut harness = AuditChainHarness::new("z:work");
        harness.genesis("system:bootstrap");
        for i in 0..9 {
            harness.capability_invoke(&format!("user:user{i}"));
        }
        harness.write_to(&events_path);

        logs.push(
            E2eLogEntry::new("e2e_timeline_with_limit", &corr_id)
                .phase("execute")
                .message("Running fcp audit timeline with limit=3")
                .chain_len(harness.len()),
        );

        // Request only 3 events
        let output = fcp_cmd()
            .args(["audit", "timeline"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--limit", "3"])
            .args(["--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        // Count the number of JSON objects (lines)
        let json_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
        assert_eq!(
            json_lines.len(),
            3,
            "Expected 3 events, got {}",
            json_lines.len()
        );

        logs.push(
            E2eLogEntry::new("e2e_timeline_with_limit", &corr_id)
                .phase("verify")
                .result("pass")
                .message("Timeline limit correctly applied"),
        );
    }

    #[test]
    fn e2e_timeline_zone_filter() {
        let corr_id = correlation_id();
        let log_path = log_output_dir().join("e2e_timeline_zone.jsonl");
        let mut logs = E2eLogCollector::new(Some(&log_path));

        logs.push(
            E2eLogEntry::new("e2e_timeline_zone_filter", &corr_id)
                .phase("setup")
                .message("Creating chain in z:work zone"),
        );

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        let mut harness = AuditChainHarness::new("z:work");
        harness
            .genesis("system:bootstrap")
            .capability_invoke("user:alice");
        harness.write_to(&events_path);

        logs.push(
            E2eLogEntry::new("e2e_timeline_zone_filter", &corr_id)
                .phase("execute")
                .message("Running fcp audit timeline with zone filter for z:private"),
        );

        // Filter for a different zone - should return empty
        let output = fcp_cmd()
            .args(["audit", "timeline"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--zone", "z:private"])
            .args(["--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        // No events should match z:private
        let json_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
        assert!(
            json_lines.is_empty(),
            "Expected 0 events for z:private filter, got {}",
            json_lines.len()
        );

        logs.push(
            E2eLogEntry::new("e2e_timeline_zone_filter", &corr_id)
                .phase("verify")
                .result("pass")
                .message("Zone filter correctly excludes non-matching events"),
        );
    }

    #[test]
    fn e2e_verify_with_fork_detection() {
        let corr_id = correlation_id();
        let log_path = log_output_dir().join("e2e_fork_detection.jsonl");
        let mut logs = E2eLogCollector::new(Some(&log_path));
        let start = std::time::Instant::now();

        logs.push(
            E2eLogEntry::new("e2e_verify_with_fork_detection", &corr_id)
                .phase("setup")
                .message("Creating forked chain (two events at same seq)"),
        );

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        let mut harness = AuditChainHarness::new("z:work");
        harness.genesis("system:bootstrap");
        harness.capability_invoke("user:alice");

        // Create a forked event with same seq but different object_id
        let fork_event = AuditEventRecord {
            object_id: format!("{:064x}", 999u64), // Different ID
            event: AuditEventData {
                header: HeaderData {
                    schema: SchemaData {
                        namespace: "fcp.core".into(),
                        name: "AuditEvent".into(),
                        version: "1.0.0".into(),
                    },
                    zone_id: "z:work".into(),
                    created_at: 1_700_000_001,
                    provenance: ProvenanceData {
                        origin_zone: "z:work".into(),
                        current_zone: "z:work".into(),
                    },
                    refs: vec![],
                    foreign_refs: vec![],
                },
                correlation_id: format!("{:032x}", 998u64),
                event_type: "capability.invoke".into(),
                actor: "user:mallory".into(),
                zone_id: "z:work".into(),
                prev: Some(AuditChainHarness::object_id(0)),
                seq: 1, // Same seq as existing event 1
                occurred_at: 1_700_000_001,
                signature: SignatureData {
                    node_id: "node-2".into(), // Different node
                    signature: "1".repeat(128),
                    signed_at: 1_700_000_001,
                },
            },
        };
        harness.events.push(fork_event);
        harness.write_to(&events_path);

        logs.push(
            E2eLogEntry::new("e2e_verify_with_fork_detection", &corr_id)
                .phase("execute")
                .message("Running fcp audit verify on forked chain"),
        );

        fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"status\": \"fail\""))
            .stdout(predicate::str::contains("audit.fork_detected"));

        #[allow(clippy::cast_possible_truncation)] // Test durations fit in u64
        let elapsed = start.elapsed().as_millis() as u64;
        logs.push(
            E2eLogEntry::new("e2e_verify_with_fork_detection", &corr_id)
                .phase("verify")
                .result("pass")
                .error_code("audit.fork_detected")
                .message("Fork correctly detected in E2E scenario")
                .issues_found(1)
                .duration_ms(elapsed),
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn e2e_full_audit_workflow() {
        let corr_id = correlation_id();
        let log_path = log_output_dir().join("e2e_full_workflow.jsonl");
        let mut logs = E2eLogCollector::new(Some(&log_path));
        let start = std::time::Instant::now();

        logs.push(
            E2eLogEntry::new("e2e_full_audit_workflow", &corr_id)
                .phase("setup")
                .message("Starting full audit workflow: generate -> verify -> timeline"),
        );

        let tmp = TempDir::new().unwrap();
        let events_path = tmp.path().join("events.jsonl");

        // Step 1: Generate realistic audit chain
        let mut harness = AuditChainHarness::new("z:work");
        harness
            .genesis("system:bootstrap")
            .capability_invoke("user:alice")
            .secret_access("user:alice")
            .capability_invoke("user:bob")
            .capability_invoke("user:bob")
            .secret_access("user:bob")
            .security_violation("user:mallory");

        harness.write_to(&events_path);

        logs.push(
            E2eLogEntry::new("e2e_full_audit_workflow", &corr_id)
                .phase("execute")
                .message("Step 1: Chain generated")
                .chain_len(harness.len()),
        );

        // Step 2: Verify chain integrity
        let verify_output = fcp_cmd()
            .args(["audit", "verify"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--zone", "z:work"])
            .args(["--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let verify_stdout = String::from_utf8_lossy(&verify_output);
        assert!(
            verify_stdout.contains("\"status\": \"ok\""),
            "Verify should pass"
        );
        assert!(
            verify_stdout.contains("\"chain_len\": 7"),
            "Chain should have 7 events"
        );

        logs.push(
            E2eLogEntry::new("e2e_full_audit_workflow", &corr_id)
                .phase("execute")
                .message("Step 2: Verification passed"),
        );

        // Step 3: Render timeline
        let timeline_output = fcp_cmd()
            .args(["audit", "timeline"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--zone", "z:work"])
            .args(["--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let timeline_stdout = String::from_utf8_lossy(&timeline_output);

        // Verify timeline includes all event types
        assert!(timeline_stdout.contains("zone.created"));
        assert!(timeline_stdout.contains("capability.invoke"));
        assert!(timeline_stdout.contains("secret.access"));
        assert!(timeline_stdout.contains("security.violation"));

        // Note: trace context omitted in E2E tests (requires byte array format)

        logs.push(
            E2eLogEntry::new("e2e_full_audit_workflow", &corr_id)
                .phase("execute")
                .message("Step 3: Timeline rendered"),
        );

        // Step 4: Verify timeline with limit
        let limited_output = fcp_cmd()
            .args(["audit", "timeline"])
            .args(["--events", events_path.to_str().unwrap()])
            .args(["--limit", "3"])
            .args(["--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let limited_stdout = String::from_utf8_lossy(&limited_output);
        let limited_line_count = limited_stdout
            .lines()
            .filter(|l| l.starts_with('{'))
            .count();
        assert_eq!(
            limited_line_count, 3,
            "Limited timeline should have 3 events"
        );

        #[allow(clippy::cast_possible_truncation)] // Test durations fit in u64
        let elapsed = start.elapsed().as_millis() as u64;
        logs.push(
            E2eLogEntry::new("e2e_full_audit_workflow", &corr_id)
                .phase("verify")
                .result("pass")
                .message("Full audit workflow completed successfully")
                .chain_len(harness.len())
                .issues_found(0)
                .duration_ms(elapsed),
        );

        // Persist final log summary
        let jsonl = logs.to_jsonl();
        assert!(!jsonl.is_empty(), "JSONL log output should not be empty");
    }
}

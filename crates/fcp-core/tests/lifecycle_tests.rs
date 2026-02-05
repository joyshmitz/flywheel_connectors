//! Lifecycle state machine unit tests with structured JSONL logging.
//!
//! These tests validate the connector lifecycle state machine per `docs/STANDARD_Testing_Logging.md`.
//! All tests emit structured JSONL logs and validate against the E2E schema.
//!
//! Coverage:
//! - Valid transition sequence (Pending → Installing → Canary → Production)
//! - Failed health → rollback (health below threshold triggers auto-rollback)
//! - Repeated failures → disabled state (circuit breaker behavior)

#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

use std::time::Instant;

use chrono::Utc;
use fcp_core::{
    CanaryPolicy, ConnectorId, HealthMetrics, LifecycleError, LifecycleRecord, LifecycleState,
    TransitionReason,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Context
// ─────────────────────────────────────────────────────────────────────────────

/// Test context for structured logging with connector lifecycle context.
struct TestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    connector_id: ConnectorId,
    version: semver::Version,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl TestContext {
    fn new(test_name: &str, connector_id: ConnectorId, version: semver::Version) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-core::lifecycle".to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            connector_id,
            version,
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn log_phase(&self, phase: &str, details: Option<serde_json::Value>) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let mut entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "connector_id": self.connector_id.to_string(),
            "version": self.version.to_string(),
            "result": "pass",
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });

        if let Some(d) = details {
            entry["details"] = d;
        }

        self.capture.push_value(&entry).expect("log entry");
    }

    fn log_transition(&self, from: LifecycleState, to: LifecycleState, reason: &str) {
        self.log_phase(
            "transition",
            Some(json!({
                "from": from.as_str(),
                "to": to.as_str(),
                "reason": reason
            })),
        );
    }

    fn log_health_update(&self, health: &HealthMetrics) {
        self.log_phase(
            "health_update",
            Some(json!({
                "samples": health.samples,
                "successes": health.successes,
                "failures": health.failures,
                "success_rate": health.success_rate
            })),
        );
    }

    fn assert_eq<T: std::fmt::Debug + PartialEq>(&mut self, actual: &T, expected: &T, msg: &str) {
        if actual == expected {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}: expected {expected:?}, got {actual:?}");
        }
    }

    fn assert_true(&mut self, condition: bool, msg: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}");
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn finalize(&self, result: &str) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": "verify",
            "correlation_id": self.correlation_id,
            "connector_id": self.connector_id.to_string(),
            "version": self.version.to_string(),
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });
        self.capture.push_value(&entry).expect("final log entry");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_connector_id() -> ConnectorId {
    ConnectorId::from_static("test:lifecycle:v1")
}

const fn test_version() -> semver::Version {
    semver::Version::new(1, 0, 0)
}

/// Create a lifecycle record transitioned to canary state.
fn create_canary_record(policy: CanaryPolicy) -> LifecycleRecord {
    let mut record =
        LifecycleRecord::new(test_connector_id(), test_version()).with_canary_policy(policy);

    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("pending -> installing");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("installing -> canary");

    record
}

// ─────────────────────────────────────────────────────────────────────────────
// Valid Transition Sequence Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test the happy path: Pending → Installing → Canary → Production.
#[test]
fn test_valid_transition_sequence_to_production() {
    let mut ctx = TestContext::new(
        "valid_transition_sequence_to_production",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "happy_path_to_production"})),
    );

    // Create a new lifecycle record
    let mut record = LifecycleRecord::new(test_connector_id(), test_version()).with_canary_policy(
        CanaryPolicy::new()
            .with_promotion_threshold(90)
            .with_min_samples(5)
            .with_min_canary_duration(0),
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Pending,
        "Initial state should be Pending",
    );
    ctx.log_phase("assert", Some(json!({"state": "Pending"})));

    // Transition: Pending → Installing
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("pending -> installing");
    ctx.log_transition(
        LifecycleState::Pending,
        LifecycleState::Installing,
        "InstallComplete",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Installing,
        "Should be Installing after transition",
    );

    // Transition: Installing → Canary
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("installing -> canary");
    ctx.log_transition(
        LifecycleState::Installing,
        LifecycleState::Canary,
        "InstallComplete",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should be Canary after transition",
    );

    // Add health samples
    for _ in 0..5 {
        record.update_health(true, Some(100));
    }
    ctx.log_health_update(&record.health);

    // Check auto-promotion eligibility
    ctx.assert_true(
        record.should_auto_promote(),
        "Should be eligible for auto-promotion",
    );

    // Transition: Canary → Production
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 100 },
        )
        .expect("canary -> production");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::Production,
        "AutoPromotion",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Production,
        "Should be Production after promotion",
    );

    ctx.assert_eq(
        &record.transitions.len(),
        &3,
        "Should have 3 transitions recorded",
    );

    ctx.finalize("pass");
}

/// Test manual promotion from canary to production.
#[test]
fn test_manual_promotion() {
    let mut ctx = TestContext::new("manual_promotion", test_connector_id(), test_version());

    ctx.log_phase("setup", Some(json!({"scenario": "manual_promotion"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Manual promotion (even without meeting thresholds)
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect("canary -> production");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::Production,
        "ManualPromotion",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Production,
        "Should be Production after manual promotion",
    );

    // Verify transition reason is recorded
    let last_transition = record.transitions.last().expect("should have transitions");
    ctx.assert_eq(
        &last_transition.reason,
        &TransitionReason::ManualPromotion,
        "Transition reason should be ManualPromotion",
    );

    ctx.finalize("pass");
}

/// Test invalid transition is rejected.
#[test]
fn test_invalid_transition_rejected() {
    let mut ctx = TestContext::new(
        "invalid_transition_rejected",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "invalid_transition"})));

    let mut record = LifecycleRecord::new(test_connector_id(), test_version());

    // Try to skip Installing and go directly to Production
    let result = record.transition(
        LifecycleState::Production,
        TransitionReason::ManualPromotion,
    );

    ctx.assert_true(
        result.is_err(),
        "Should reject Pending -> Production transition",
    );

    if let Err(LifecycleError::InvalidTransition { from, to }) = result {
        ctx.assert_eq(
            &from,
            &LifecycleState::Pending,
            "From state should be Pending",
        );
        ctx.assert_eq(
            &to,
            &LifecycleState::Production,
            "To state should be Production",
        );
        ctx.log_phase(
            "assert",
            Some(json!({
                "error": "InvalidTransition",
                "from": from.as_str(),
                "to": to.as_str()
            })),
        );
    }

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Failed Health → Rollback Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test automatic rollback when health drops below threshold.
#[test]
fn test_auto_rollback_on_health_failure() {
    let mut ctx = TestContext::new(
        "auto_rollback_on_health_failure",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "health_failure_rollback"})),
    );

    // Create canary with specific thresholds
    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_rollback_threshold(80)
            .with_min_samples(10),
    );

    ctx.log_phase(
        "config",
        Some(json!({
            "rollback_threshold": 80,
            "min_samples": 10
        })),
    );

    // Add failing health samples (70% success rate)
    for _ in 0..7 {
        record.update_health(true, Some(100));
    }
    for _ in 0..3 {
        record.update_health(false, Some(500));
    }

    ctx.log_health_update(&record.health);

    // Verify auto-rollback should trigger
    ctx.assert_true(
        record.should_auto_rollback(),
        "Should trigger auto-rollback with 70% success rate",
    );

    ctx.assert_eq(
        &record.health.success_rate,
        &70u8,
        "Success rate should be 70%",
    );

    // Execute rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 70,
                failure_reason: "Success rate below threshold".to_string(),
            },
        )
        .expect("canary -> rolled_back");

    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::RolledBack,
        "Should be RolledBack after health failure",
    );

    ctx.finalize("pass");
}

/// Test manual rollback from production.
#[test]
fn test_manual_rollback_from_production() {
    let mut ctx = TestContext::new(
        "manual_rollback_from_production",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "manual_rollback"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // First promote to production
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect("canary -> production");

    // Then rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback {
                reason: Some("Emergency rollback due to customer reports".to_string()),
            },
        )
        .expect("production -> rolled_back");

    ctx.log_transition(
        LifecycleState::Production,
        LifecycleState::RolledBack,
        "ManualRollback",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::RolledBack,
        "Should be RolledBack after manual rollback",
    );

    ctx.finalize("pass");
}

/// Test recovery from rollback (retry with new canary).
#[test]
fn test_recovery_from_rollback() {
    let mut ctx = TestContext::new(
        "recovery_from_rollback",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "recovery_retry"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 75,
                failure_reason: "Test failure".to_string(),
            },
        )
        .expect("canary -> rolled_back");

    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback",
    );

    // Retry: RolledBack → Canary
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "1.0.0".to_string(),
                to_version: "1.0.1".to_string(),
            },
        )
        .expect("rolled_back -> canary");

    ctx.log_transition(
        LifecycleState::RolledBack,
        LifecycleState::Canary,
        "NewVersion",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should be back in Canary for retry",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Repeated Failures → Disabled State Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test disabling a connector after repeated failures.
#[test]
fn test_disable_after_repeated_failures() {
    let mut ctx = TestContext::new(
        "disable_after_repeated_failures",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "repeated_failures_disable"})),
    );

    let mut record = create_canary_record(CanaryPolicy::new());

    // Simulate repeated rollbacks
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 60,
                failure_reason: "First failure".to_string(),
            },
        )
        .expect("first rollback");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback#1",
    );

    // Retry
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("retry canary");

    // Second rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 55,
                failure_reason: "Second failure".to_string(),
            },
        )
        .expect("second rollback");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback#2",
    );

    // After repeated failures, disable the connector
    record
        .transition(
            LifecycleState::Disabled,
            TransitionReason::Disabled {
                reason: "Repeated failures - circuit breaker triggered".to_string(),
            },
        )
        .expect("rolled_back -> disabled");
    ctx.log_transition(
        LifecycleState::RolledBack,
        LifecycleState::Disabled,
        "Disabled",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Disabled,
        "Should be Disabled after repeated failures",
    );

    ctx.assert_true(
        !record.state.is_active(),
        "Disabled state should not be active",
    );

    ctx.finalize("pass");
}

/// Test re-enabling a disabled connector.
#[test]
fn test_reenable_disabled_connector() {
    let mut ctx = TestContext::new(
        "reenable_disabled_connector",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "reenable"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Disable
    record
        .transition(
            LifecycleState::Disabled,
            TransitionReason::Disabled {
                reason: "Manual disable for maintenance".to_string(),
            },
        )
        .expect("canary -> disabled");

    // Re-enable by transitioning back to canary
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "1.0.0".to_string(),
                to_version: "1.0.2".to_string(),
            },
        )
        .expect("disabled -> canary");
    ctx.log_transition(
        LifecycleState::Disabled,
        LifecycleState::Canary,
        "NewVersion",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should be Canary after re-enable",
    );

    ctx.assert_true(record.state.is_active(), "Canary state should be active");

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Metrics Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test health metrics accumulation and success rate calculation.
#[test]
fn test_health_metrics_calculation() {
    let mut ctx = TestContext::new(
        "health_metrics_calculation",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "health_calculation"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Add mixed health samples
    for i in 0..100 {
        let success = i < 95; // 95% success rate
        let latency = if success { 50 + (i % 50) } else { 1000 };
        record.update_health(success, Some(latency));
    }

    ctx.log_health_update(&record.health);

    ctx.assert_eq(&record.health.samples, &100, "Should have 100 samples");
    ctx.assert_eq(&record.health.successes, &95, "Should have 95 successes");
    ctx.assert_eq(&record.health.failures, &5, "Should have 5 failures");
    ctx.assert_eq(
        &record.health.success_rate,
        &95u8,
        "Success rate should be 95%",
    );
    ctx.assert_eq(
        &record.health.max_latency_ms,
        &1000,
        "Max latency should be 1000ms",
    );

    ctx.finalize("pass");
}

/// Test health reset when entering canary.
#[test]
fn test_health_reset() {
    let mut ctx = TestContext::new("health_reset", test_connector_id(), test_version());

    ctx.log_phase("setup", Some(json!({"scenario": "health_reset"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Add some health data
    for _ in 0..50 {
        record.update_health(true, Some(100));
    }

    ctx.assert_eq(&record.health.samples, &50, "Should have 50 samples");

    // Reset health
    record.reset_health();
    ctx.log_phase("action", Some(json!({"action": "reset_health"})));

    ctx.assert_eq(&record.health.samples, &0, "Samples should be reset to 0");
    ctx.assert_eq(
        &record.health.successes,
        &0,
        "Successes should be reset to 0",
    );
    ctx.assert_eq(&record.health.failures, &0, "Failures should be reset to 0");

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Canary Policy Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test canary policy validation.
#[test]
fn test_canary_policy_validation() {
    let mut ctx = TestContext::new(
        "canary_policy_validation",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "policy_validation"})));

    // Valid policy
    let valid_policy = CanaryPolicy::new()
        .with_promotion_threshold(95)
        .with_rollback_threshold(80);

    ctx.assert_true(
        valid_policy.validate().is_ok(),
        "Valid policy should pass validation",
    );

    // Invalid policy (promotion <= rollback)
    let invalid_policy = CanaryPolicy::new()
        .with_promotion_threshold(80)
        .with_rollback_threshold(90);

    ctx.assert_true(
        invalid_policy.validate().is_err(),
        "Invalid policy should fail validation",
    );

    // Invalid traffic percentage
    let invalid_traffic = CanaryPolicy::new().with_canary_traffic_percent(150);

    ctx.assert_true(
        invalid_traffic.validate().is_err(),
        "Policy with traffic > 100% should fail",
    );

    ctx.finalize("pass");
}

/// Test auto-promotion threshold behavior.
#[test]
fn test_auto_promotion_threshold() {
    let mut ctx = TestContext::new(
        "auto_promotion_threshold",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "promotion_threshold"})));

    // Create canary with strict thresholds
    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_promotion_threshold(95)
            .with_min_samples(100)
            .with_min_canary_duration(0),
    );

    // Add 94 successes (below threshold)
    for _ in 0..94 {
        record.update_health(true, Some(100));
    }
    for _ in 0..6 {
        record.update_health(false, Some(100));
    }

    ctx.log_health_update(&record.health);
    ctx.assert_eq(
        &record.health.success_rate,
        &94u8,
        "Success rate should be 94%",
    );
    ctx.assert_true(
        !record.should_auto_promote(),
        "Should NOT auto-promote at 94%",
    );

    // Add more successes to reach 95%+
    record.reset_health();
    for _ in 0..96 {
        record.update_health(true, Some(100));
    }
    for _ in 0..4 {
        record.update_health(false, Some(100));
    }

    ctx.log_health_update(&record.health);
    ctx.assert_eq(
        &record.health.success_rate,
        &96u8,
        "Success rate should be 96%",
    );
    ctx.assert_true(record.should_auto_promote(), "Should auto-promote at 96%");

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Transition Audit Trail Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test that all transitions are recorded in the audit trail.
#[test]
fn test_transition_audit_trail() {
    let mut ctx = TestContext::new(
        "transition_audit_trail",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "audit_trail"})));

    let mut record = LifecycleRecord::new(test_connector_id(), test_version());

    // Perform several transitions
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("t1");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("t2");
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 98 },
        )
        .expect("t3");
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback {
                reason: Some("Testing".to_string()),
            },
        )
        .expect("t4");

    // Verify audit trail
    ctx.assert_eq(
        &record.transitions.len(),
        &4,
        "Should have 4 transitions in audit trail",
    );

    // Check first transition
    let t1 = &record.transitions[0];
    ctx.assert_eq(&t1.from, &LifecycleState::Pending, "T1 from Pending");
    ctx.assert_eq(&t1.to, &LifecycleState::Installing, "T1 to Installing");

    // Check last transition
    let t4 = &record.transitions[3];
    ctx.assert_eq(&t4.from, &LifecycleState::Production, "T4 from Production");
    ctx.assert_eq(&t4.to, &LifecycleState::RolledBack, "T4 to RolledBack");

    // Log the full audit trail
    ctx.log_phase(
        "audit_trail",
        Some(json!({
            "transitions": record.transitions.iter().map(|t| {
                json!({
                    "from": t.from.as_str(),
                    "to": t.to.as_str(),
                    "timestamp": t.timestamp.to_rfc3339()
                })
            }).collect::<Vec<_>>()
        })),
    );

    ctx.finalize("pass");
}

/// Test transition timestamps are monotonically increasing.
#[test]
fn test_transition_timestamps() {
    let mut ctx = TestContext::new("transition_timestamps", test_connector_id(), test_version());

    ctx.log_phase("setup", Some(json!({"scenario": "timestamp_ordering"})));

    let mut record = LifecycleRecord::new(test_connector_id(), test_version());

    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("t1");

    // Small delay to ensure different timestamps
    std::thread::sleep(std::time::Duration::from_millis(10));

    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("t2");

    ctx.assert_true(
        record.transitions[1].timestamp >= record.transitions[0].timestamp,
        "Timestamps should be monotonically non-decreasing",
    );

    ctx.finalize("pass");
}

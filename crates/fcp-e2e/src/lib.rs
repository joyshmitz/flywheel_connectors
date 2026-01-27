//! E2E connector verification framework (FCP2).
//!
//! This crate provides a lightweight harness for running connector-level
//! end-to-end checks against the FCP2 contract. It is intentionally minimal
//! and deterministic, with structured JSON logging.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod logging;

use std::time::Instant;

use fcp_core::{
    CorrelationId, FcpConnector, FcpError, HandshakeRequest, HealthSnapshot, Introspection,
    InvokeRequest,
};
use serde::{Deserialize, Serialize};

pub use logging::{AssertionsSummary, E2eLogEntry, E2eLogger};

/// Errors returned by the E2E harness.
#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    /// Connector returned an error.
    #[error("connector error: {0}")]
    Connector(String),
}

/// Result of a connector suite run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eReport {
    /// Test name.
    pub test_name: String,
    /// Whether the run passed.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Collected structured logs.
    pub logs: Vec<E2eLogEntry>,
}

/// Scenario configuration for a connector suite run.
#[derive(Debug, Clone)]
pub struct ConnectorSuite {
    /// Name for the scenario (used in logs).
    pub test_name: String,
    /// Configuration payload.
    pub config: serde_json::Value,
    /// Handshake request to send.
    pub handshake: HandshakeRequest,
    /// Optional invoke request to test operation handling.
    pub invoke: Option<InvokeRequest>,
    /// Expect the invoke call to fail (default deny paths).
    pub expect_invoke_error: bool,
}

impl ConnectorSuite {
    /// Create a minimal suite with an empty config.
    #[must_use]
    pub fn minimal(test_name: impl Into<String>, handshake: HandshakeRequest) -> Self {
        Self {
            test_name: test_name.into(),
            config: serde_json::json!({}),
            handshake,
            invoke: None,
            expect_invoke_error: false,
        }
    }
}

/// Runner for connector E2E suites.
pub struct E2eRunner {
    module: String,
    logger: E2eLogger,
}

impl E2eRunner {
    /// Create a new runner.
    #[must_use]
    pub fn new(module: impl Into<String>) -> Self {
        Self {
            module: module.into(),
            logger: E2eLogger::new(),
        }
    }

    /// Execute a connector suite and return a report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if the connector returns an error in a required phase.
    pub async fn run_connector_suite<C: FcpConnector>(
        mut self,
        connector: &mut C,
        suite: ConnectorSuite,
    ) -> Result<E2eReport, E2eError> {
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();
        let mut passed = true;
        let mut assertions_passed: u32 = 0;
        let mut assertions_failed: u32 = 0;

        let config_result = timed_async(|| connector.configure(suite.config.clone()))
            .await
            .map_value(|_| serde_json::json!({}));
        passed &= log_result(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            "setup",
            &correlation_id,
            "configure",
            config_result,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let handshake_result = timed_async(|| connector.handshake(suite.handshake.clone()))
            .await
            .map_value(|_| serde_json::json!({ "status": "accepted" }));
        passed &= log_result(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            "setup",
            &correlation_id,
            "handshake",
            handshake_result,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let health = timed_sync(|| connector.health()).await;
        passed &= log_health(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            &correlation_id,
            health,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let introspect = timed_sync(|| connector.introspect()).await;
        passed &= log_introspection(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            &correlation_id,
            introspect,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        if let Some(invoke) = suite.invoke.clone() {
            let invoke_result = timed_async(|| connector.invoke(invoke.clone()))
                .await
                .map_value(|_| serde_json::json!({ "status": "ok" }));
            let ok = log_result(
                &mut self.logger,
                &suite.test_name,
                &self.module,
                "execute",
                &correlation_id,
                "invoke",
                invoke_result,
                &mut assertions_passed,
                &mut assertions_failed,
            );

            if suite.expect_invoke_error {
                if ok {
                    passed = false;
                }
            } else {
                passed &= ok;
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let summary = AssertionsSummary::new(assertions_passed, assertions_failed);
        let summary_entry = E2eLogEntry::new(
            "info",
            suite.test_name.clone(),
            self.module.clone(),
            "teardown",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            summary,
            serde_json::json!({}),
        );
        self.logger.push(summary_entry);

        Ok(E2eReport {
            test_name: suite.test_name,
            passed,
            duration_ms,
            logs: self.logger.entries().to_vec(),
        })
    }
}

async fn timed_async<T, F, Fut>(f: F) -> TimedResult<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, FcpError>>,
{
    let start = Instant::now();
    let result = f().await;
    TimedResult {
        result: result.map_err(|e| e.to_string()),
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

async fn timed_sync<T, F>(f: F) -> TimedValue<T>
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = f();
    TimedValue {
        value,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

struct TimedResult<T> {
    result: Result<T, String>,
    duration_ms: u64,
}

impl<T> TimedResult<T> {
    fn map_value<U>(self, f: impl FnOnce(T) -> U) -> TimedResult<U> {
        TimedResult {
            result: self.result.map(f),
            duration_ms: self.duration_ms,
        }
    }
}

struct TimedValue<T> {
    value: T,
    duration_ms: u64,
}

fn log_result(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    phase: &str,
    correlation_id: &str,
    operation: &str,
    result: TimedResult<serde_json::Value>,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = result.result.is_ok();
    if success {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if success { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        phase.to_string(),
        correlation_id.to_string(),
        if success { "pass" } else { "fail" },
        result.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation": operation,
            "error": result.result.clone().err(),
        }),
    );
    logger.push(entry);

    success
}

fn log_health(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    health: TimedValue<HealthSnapshot>,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = health.value.is_healthy();
    if success {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if success { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        "verify".to_string(),
        correlation_id.to_string(),
        if success { "pass" } else { "fail" },
        health.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "health": serde_json::to_value(&health.value).unwrap_or_default(),
        }),
    );
    logger.push(entry);

    success
}

fn log_introspection(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    introspection: TimedValue<Introspection>,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = !introspection.value.operations.is_empty();
    if success {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if success { "info" } else { "warn" },
        test_name.to_string(),
        module.to_string(),
        "verify".to_string(),
        correlation_id.to_string(),
        if success { "pass" } else { "fail" },
        introspection.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation_count": introspection.value.operations.len(),
        }),
    );
    logger.push(entry);

    success
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{
        AgentHint, BaseConnector, CapabilityId, ConnectorId, EventCaps, HandshakeResponse,
        HealthSnapshot, InstanceId, InvokeResponse, InvokeStatus, OperationId, OperationInfo,
        RiskLevel, SafetyTier, SessionId, ZoneId,
    };

    #[derive(Debug)]
    struct DummyConnector {
        base: BaseConnector,
    }

    impl DummyConnector {
        fn new() -> Self {
            Self {
                base: BaseConnector::new(ConnectorId::from_static(
                    "fcp.dummy:request_response:0.1.0",
                )),
            }
        }
    }

    #[fcp_core::async_trait]
    impl FcpConnector for DummyConnector {
        fn id(&self) -> &fcp_core::ConnectorId {
            &self.base.id
        }

        async fn configure(&mut self, _config: serde_json::Value) -> fcp_core::FcpResult<()> {
            self.base.set_configured(true);
            Ok(())
        }

        async fn handshake(&mut self, _req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
            self.base.set_handshaken(true);
            Ok(HandshakeResponse {
                status: "accepted".to_string(),
                capabilities_granted: vec![],
                session_id: SessionId::new(),
                manifest_hash: "sha256:dummy".to_string(),
                nonce: [1u8; 32],
                event_caps: Some(EventCaps {
                    streaming: false,
                    replay: false,
                    min_buffer_events: 0,
                    requires_ack: false,
                }),
                auth_caps: None,
                op_catalog_hash: None,
            })
        }

        async fn health(&self) -> HealthSnapshot {
            HealthSnapshot::ready()
        }

        fn metrics(&self) -> fcp_core::ConnectorMetrics {
            self.base.metrics()
        }

        async fn shutdown(&mut self, _req: fcp_core::ShutdownRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }

        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![OperationInfo {
                    id: OperationId::from("dummy.echo"),
                    summary: "Echo".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: serde_json::json!({"type": "object"}),
                    capability: CapabilityId::from("dummy.echo"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: fcp_core::IdempotencyClass::Idempotent,
                    ai_hints: AgentHint {
                        when_to_use: "echo".to_string(),
                        common_mistakes: vec![],
                        availability_notes: None,
                    },
                    rate_limit: None,
                    requires_approval: None,
                }],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
            if req.operation.as_str() == "dummy.echo" {
                Ok(InvokeResponse {
                    id: req.id,
                    status: InvokeStatus::Ok,
                    output: serde_json::json!({"ok": true}),
                    error: None,
                })
            } else {
                Err(FcpError::Unauthorized {
                    code: 2101,
                    message: "Missing capability".to_string(),
                })
            }
        }

        async fn subscribe(&self, _req: fcp_core::SubscribeRequest) -> fcp_core::FcpResult<fcp_core::SubscribeResponse> {
            Err(FcpError::Unsupported {
                code: 5001,
                message: "Streaming not supported".to_string(),
            })
        }

        async fn unsubscribe(&self, _req: fcp_core::UnsubscribeRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }
    }

    fn test_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [1u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    #[tokio::test]
    async fn runs_minimal_suite() {
        let mut connector = DummyConnector::new();
        let suite = ConnectorSuite::minimal("dummy_suite", test_handshake());
        let report = E2eRunner::new("fcp-e2e")
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(report.passed, "suite should pass");
        assert!(!report.logs.is_empty(), "logs should be emitted");
    }

    #[tokio::test]
    async fn logs_denied_invoke() {
        let mut connector = DummyConnector::new();
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-1"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite {
            test_name: "deny_invoke".to_string(),
            config: serde_json::json!({}),
            handshake: test_handshake(),
            invoke: Some(invoke),
            expect_invoke_error: true,
        };

        let report = E2eRunner::new("fcp-e2e")
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(report.passed, "deny suite should pass when error expected");
        let json_lines = report
            .logs
            .iter()
            .filter_map(|entry| serde_json::to_string(entry).ok())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(json_lines.contains("deny_invoke"));
    }
}

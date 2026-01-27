//! E2E connector verification framework (FCP2).
//!
//! This crate provides a lightweight harness for running connector-level
//! end-to-end checks against the FCP2 contract. It is intentionally minimal
//! and deterministic, with structured JSON logging.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod logging;

use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use fcp_conformance::run_all_interop_tests;
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

impl E2eReport {
    /// Serialize logs to JSON lines.
    #[must_use]
    pub fn to_json_lines(&self) -> String {
        self.logs
            .iter()
            .filter_map(|entry| serde_json::to_string(entry).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Write logs to a JSONL file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        for entry in &self.logs {
            let line = serde_json::to_string(entry)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
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

    /// Run the protocol interop suite and emit a report.
    #[must_use]
    pub fn run_interop_suite(&mut self, test_name: impl Into<String>) -> E2eReport {
        let test_name = test_name.into();
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();

        let summary = run_all_interop_tests();
        let passed = summary.all_passed();
        let duration_ms = start.elapsed().as_millis() as u64;

        let failures: Vec<serde_json::Value> = summary
            .failures
            .iter()
            .map(|failure| {
                serde_json::json!({
                    "name": failure.name,
                    "category": failure.category,
                    "message": failure.message,
                })
            })
            .collect();

        let entry = E2eLogEntry::new(
            if passed { "info" } else { "error" },
            test_name.clone(),
            self.module.clone(),
            "verify",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            AssertionsSummary::new(summary.passed as u32, summary.failed as u32),
            serde_json::json!({
                "interop": {
                    "total": summary.total,
                    "passed": summary.passed,
                    "failed": summary.failed,
                    "failures": failures,
                }
            }),
        );
        self.logger.push(entry);

        E2eReport {
            test_name,
            passed,
            duration_ms,
            logs: self.logger.drain(),
        }
    }

    /// Execute a connector suite and return a report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if the connector returns an error in a required phase.
    pub async fn run_connector_suite<C: FcpConnector>(
        &mut self,
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
            false,
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
            false,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let health = timed_async_value(|| connector.health()).await;
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
                suite.expect_invoke_error,
                &mut assertions_passed,
                &mut assertions_failed,
            );

            passed &= ok;
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
            logs: self.logger.drain(),
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
        result,
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

async fn timed_async_value<T, F, Fut>(f: F) -> TimedValue<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let value = f().await;
    TimedValue {
        value,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

struct TimedResult<T> {
    result: Result<T, FcpError>,
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
    expect_error: bool,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = result.result.is_ok();
    let passed = if expect_error { !success } else { success };
    if passed {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let (decision, reason_code, reason_message, error_details, retryable, retry_after_ms) =
        if let Err(err) = &result.result {
            let response = err.to_response();
            (
                Some("deny".to_string()),
                Some(response.code),
                Some(response.message),
                response.details,
                Some(response.retryable),
                response.retry_after_ms,
            )
        } else {
            (None, None, None, None, None, None)
        };

    let entry = E2eLogEntry::new(
        if passed { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        phase.to_string(),
        correlation_id.to_string(),
        if passed { "pass" } else { "fail" },
        result.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation": operation,
            "decision": decision,
            "reason_code": reason_code,
            "reason_message": reason_message,
            "error_details": error_details,
            "retryable": retryable,
            "retry_after_ms": retry_after_ms,
            "expected_error": expect_error,
        }),
    );
    logger.push(entry);

    passed
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
        AgentHint, BaseConnector, CapabilityId, CapabilityToken, ConnectorId, EventCaps,
        HandshakeResponse, HealthSnapshot, InstanceId, InvokeResponse, OperationId, OperationInfo,
        RiskLevel, SafetyTier, SessionId, ZoneId,
    };
    use fcp_testkit::MockApiServer;

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

        async fn handshake(
            &mut self,
            _req: HandshakeRequest,
        ) -> fcp_core::FcpResult<HandshakeResponse> {
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
                    id: OperationId::from_static("dummy.echo"),
                    summary: "Echo".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: serde_json::json!({"type": "object"}),
                    capability: CapabilityId::from_static("dummy.echo"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: fcp_core::IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "echo".to_string(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
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
                Ok(InvokeResponse::ok(
                    req.id,
                    serde_json::json!({ "ok": true }),
                ))
            } else {
                Err(FcpError::Unauthorized {
                    code: 2101,
                    message: "Missing capability".to_string(),
                })
            }
        }

        async fn subscribe(
            &self,
            _req: fcp_core::SubscribeRequest,
        ) -> fcp_core::FcpResult<fcp_core::SubscribeResponse> {
            Err(FcpError::StreamingNotSupported)
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
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
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
            operation: OperationId::from_static("dummy.denied"),
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

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(report.passed, "deny suite should pass when error expected");
        let json_lines = report.to_json_lines();
        assert!(json_lines.contains("deny_invoke"));
    }

    #[tokio::test]
    async fn mock_server_smoke() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/health", serde_json::json!({ "ok": true }))
            .await;

        let url = format!("{}/health", mock.base_url());
        let body: serde_json::Value = reqwest::get(url)
            .await
            .expect("request ok")
            .json()
            .await
            .expect("json body");

        assert_eq!(body, serde_json::json!({ "ok": true }));
        mock.assert_request_count(1).await;
    }
}

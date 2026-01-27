//! Mechanical connector compliance checks (static + dynamic).
//!
//! Static checks validate connector manifests. Dynamic checks execute standard
//! methods against an in-process connector implementation.

use fcp_core::{
    FcpConnector, FcpError, HandshakeRequest, HealthState, InvokeRequest, InvokeStatus,
    SimulateRequest,
};
use fcp_manifest::ConnectorManifest;
use serde::{Deserialize, Serialize};

/// Compliance check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skipped,
}

/// Result for a single compliance check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Check identifier (stable string for CI parsing).
    pub check: String,
    /// Outcome of the check.
    pub status: CheckStatus,
    /// Human-readable detail.
    pub message: String,
}

impl ComplianceFinding {
    fn pass(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Pass,
            message: message.into(),
        }
    }

    fn fail(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Fail,
            message: message.into(),
        }
    }

    fn skipped(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Skipped,
            message: message.into(),
        }
    }
}

/// Static compliance results (manifest validation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticCompliance {
    /// Whether all static checks passed.
    pub passed: bool,
    /// Individual findings.
    pub findings: Vec<ComplianceFinding>,
}

impl StaticCompliance {
    /// Run static checks against a manifest TOML payload.
    #[must_use]
    pub fn run_manifest(manifest_toml: &str) -> Self {
        let mut findings = Vec::new();
        let parse_result = ConnectorManifest::parse_str(manifest_toml);
        let passed = match parse_result {
            Ok(_) => {
                findings.push(ComplianceFinding::pass(
                    "manifest.parse_validate",
                    "manifest parsed and validated",
                ));
                true
            }
            Err(err) => {
                findings.push(ComplianceFinding::fail(
                    "manifest.parse_validate",
                    err.to_string(),
                ));
                false
            }
        };

        Self { passed, findings }
    }
}

/// Input configuration for dynamic compliance checks.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct DynamicSuite {
    /// Configuration payload.
    pub config: serde_json::Value,
    /// Handshake request to send.
    pub handshake: HandshakeRequest,
    /// Optional invoke request to exercise default deny or success paths.
    pub invoke: Option<InvokeRequest>,
    /// Whether invoke is expected to error.
    pub expect_invoke_error: bool,
    /// Optional simulate request for preflight checks.
    pub simulate: Option<SimulateRequest>,
    /// Expected `would_succeed` flag from simulate (if provided).
    pub expect_simulate_would_succeed: Option<bool>,
    /// Require simulate denial details when `would_succeed` is false.
    pub require_simulate_denial_details: bool,
    /// Require capability-denied style error on invoke denial.
    pub require_capability_denial: bool,
    /// Require a decision receipt ID on invoke denial.
    pub require_decision_receipt: bool,
}

impl DynamicSuite {
    /// Minimal suite with empty config and no invoke request.
    #[must_use]
    pub fn minimal(handshake: HandshakeRequest) -> Self {
        Self {
            config: serde_json::json!({}),
            handshake,
            invoke: None,
            expect_invoke_error: false,
            simulate: None,
            expect_simulate_would_succeed: None,
            require_simulate_denial_details: false,
            require_capability_denial: false,
            require_decision_receipt: false,
        }
    }
}

/// Dynamic compliance results (standard method checks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicCompliance {
    /// Whether all dynamic checks passed.
    pub passed: bool,
    /// Individual findings.
    pub findings: Vec<ComplianceFinding>,
}

impl DynamicCompliance {
    /// Create a skipped dynamic report.
    #[must_use]
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            passed: true,
            findings: vec![ComplianceFinding::skipped("dynamic.skip", reason)],
        }
    }
}

/// Aggregate compliance report (static + dynamic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Static checks (manifest).
    pub static_checks: StaticCompliance,
    /// Dynamic checks (standard methods).
    pub dynamic_checks: DynamicCompliance,
}

impl ComplianceReport {
    /// Whether the compliance report is passing.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.static_checks.passed && self.dynamic_checks.passed
    }
}

/// Run dynamic compliance checks against an in-process connector.
#[allow(clippy::too_many_lines)]
pub async fn run_dynamic_checks<C: FcpConnector>(
    connector: &mut C,
    suite: DynamicSuite,
) -> DynamicCompliance {
    let mut findings = Vec::new();
    let mut passed = true;

    let configure_result = connector.configure(suite.config.clone()).await;
    let configured = match configure_result {
        Ok(()) => {
            findings.push(ComplianceFinding::pass("configure", "configure ok"));
            true
        }
        Err(err) => {
            passed = false;
            findings.push(ComplianceFinding::fail("configure", err.to_string()));
            false
        }
    };

    let handshake_result = connector.handshake(suite.handshake.clone()).await;
    let handshaken = match handshake_result {
        Ok(response) => {
            if response.status == "accepted" {
                findings.push(ComplianceFinding::pass("handshake", "handshake accepted"));
                true
            } else {
                passed = false;
                findings.push(ComplianceFinding::fail(
                    "handshake",
                    format!("handshake status {}", response.status),
                ));
                false
            }
        }
        Err(err) => {
            passed = false;
            findings.push(ComplianceFinding::fail("handshake", err.to_string()));
            false
        }
    };

    let introspection = connector.introspect();
    findings.push(ComplianceFinding::pass(
        "introspect",
        format!(
            "operations={}, events={}, resource_types={}",
            introspection.operations.len(),
            introspection.events.len(),
            introspection.resource_types.len()
        ),
    ));

    let health = connector.health().await;
    match health.status {
        HealthState::Error { reason } => {
            passed = false;
            findings.push(ComplianceFinding::fail("health", reason));
        }
        _ => {
            findings.push(ComplianceFinding::pass(
                "health",
                format!("status={:?}", health.status),
            ));
        }
    }

    if let Some(simulate) = suite.simulate {
        if configured && handshaken {
            let simulate_result = connector.simulate(simulate).await;
            match simulate_result {
                Ok(response) => {
                    if let Some(expected) = suite.expect_simulate_would_succeed {
                        if response.would_succeed == expected {
                            findings.push(ComplianceFinding::pass(
                                "simulate",
                                format!("would_succeed={}", response.would_succeed),
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "simulate",
                                format!(
                                    "expected would_succeed={} but got {}",
                                    expected, response.would_succeed
                                ),
                            ));
                        }
                    } else {
                        findings.push(ComplianceFinding::pass(
                            "simulate",
                            format!("would_succeed={}", response.would_succeed),
                        ));
                    }

                    if !response.would_succeed && suite.require_simulate_denial_details {
                        let has_details = response
                            .denial_code
                            .as_ref()
                            .is_some_and(|code| !code.is_empty())
                            || response
                                .failure_reason
                                .as_ref()
                                .is_some_and(|reason| !reason.is_empty())
                            || !response.missing_capabilities.is_empty();
                        if has_details {
                            findings.push(ComplianceFinding::pass(
                                "simulate.denial_details",
                                "denial details present",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "simulate.denial_details",
                                "missing denial code/reason/capabilities",
                            ));
                        }
                    }
                }
                Err(err) => {
                    passed = false;
                    findings.push(ComplianceFinding::fail("simulate", err.to_string()));
                }
            }
        } else {
            findings.push(ComplianceFinding::skipped(
                "simulate",
                "skipped due to configure/handshake failure",
            ));
        }
    }

    if let Some(invoke) = suite.invoke {
        if configured && handshaken {
            let invoke_result = connector.invoke(invoke).await;
            match (suite.expect_invoke_error, invoke_result) {
                (true, Ok(response)) => {
                    if response.status == InvokeStatus::Error {
                        findings.push(ComplianceFinding::pass("invoke", "expected error observed"));
                    } else {
                        passed = false;
                        findings.push(ComplianceFinding::fail(
                            "invoke",
                            "expected error but got success",
                        ));
                    }

                    if suite.require_decision_receipt {
                        if response.decision_receipt_id.is_some() {
                            findings.push(ComplianceFinding::pass(
                                "invoke.decision_receipt",
                                "decision receipt present",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "invoke.decision_receipt",
                                "missing decision receipt",
                            ));
                        }
                    }

                    if suite.require_capability_denial {
                        let is_capability_denial =
                            response.error.as_ref().is_some_and(is_capability_denial);
                        if is_capability_denial {
                            findings.push(ComplianceFinding::pass(
                                "invoke.capability_denial",
                                "capability denial reported",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "invoke.capability_denial",
                                "expected capability denial error",
                            ));
                        }
                    }
                }
                (true, Err(err)) => {
                    findings.push(ComplianceFinding::pass("invoke", "expected error observed"));
                    if suite.require_decision_receipt {
                        passed = false;
                        findings.push(ComplianceFinding::fail(
                            "invoke.decision_receipt",
                            "missing decision receipt (error returned)",
                        ));
                    }
                    if suite.require_capability_denial {
                        if is_capability_denial(&err) {
                            findings.push(ComplianceFinding::pass(
                                "invoke.capability_denial",
                                "capability denial reported",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "invoke.capability_denial",
                                "expected capability denial error",
                            ));
                        }
                    }
                }
                (false, Ok(response)) => {
                    if response.status == InvokeStatus::Ok {
                        findings.push(ComplianceFinding::pass("invoke", "invoke ok"));
                    } else {
                        passed = false;
                        findings.push(ComplianceFinding::fail("invoke", "unexpected invoke error"));
                    }
                }
                (false, Err(err)) => {
                    passed = false;
                    findings.push(ComplianceFinding::fail("invoke", err.to_string()));
                }
            }
        } else {
            findings.push(ComplianceFinding::skipped(
                "invoke",
                "skipped due to configure/handshake failure",
            ));
        }
    }

    DynamicCompliance { passed, findings }
}

const fn is_capability_denial(err: &FcpError) -> bool {
    matches!(
        err,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::{CheckStatus, StaticCompliance};
    use fcp_manifest::ConnectorManifest;

    fn with_computed_interface_hash(raw: &str) -> String {
        let unchecked =
            ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
        let computed = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        raw.replace(
            &unchecked.manifest.interface_hash.to_string(),
            &computed.to_string(),
        )
    }

    #[test]
    fn static_manifest_valid_passes() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let materialized = with_computed_interface_hash(raw);
        let report = StaticCompliance::run_manifest(&materialized);
        assert!(report.passed);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.status == CheckStatus::Pass),
            "expected all findings to pass"
        );
    }

    #[test]
    fn static_manifest_invalid_version_fails() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_invalid_version.toml");
        let materialized = with_computed_interface_hash(raw);
        let report = StaticCompliance::run_manifest(&materialized);
        assert!(!report.passed);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.status == CheckStatus::Fail),
            "expected at least one failure"
        );
    }
}

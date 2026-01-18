//! Policy objects and evaluation helpers for FCP2.
//!
//! This module defines zone policy objects and a minimal evaluation pipeline
//! that produces stable decision reason codes and decision receipts.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    ApprovalScope, ApprovalToken, CapabilityGrant, CapabilityId, ConfidentialityLevel, ConnectorId,
    Decision, DecisionReceipt, FlowCheckResult, IntegrityLevel, NodeSignature, ObjectHeader,
    ObjectId, OperationId, PrincipalId, ProvenanceRecord, ProvenanceViolation, RoleObject,
    SafetyTier, SanitizerReceipt, TaintFlag, TaintFlags, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Zone Transport Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Transport modes observed by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Direct LAN/peer-to-peer transport.
    Lan,
    /// DERP relay transport.
    Derp,
    /// Funnel ingress transport.
    Funnel,
}

/// Zone transport policy (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransportPolicy {
    pub allow_lan: bool,
    pub allow_derp: bool,
    pub allow_funnel: bool,
}

impl ZoneTransportPolicy {
    /// Check whether a transport mode is permitted.
    #[must_use]
    pub const fn allows(&self, mode: TransportMode) -> bool {
        match mode {
            TransportMode::Lan => self.allow_lan,
            TransportMode::Derp => self.allow_derp,
            TransportMode::Funnel => self.allow_funnel,
        }
    }
}

impl Default for ZoneTransportPolicy {
    fn default() -> Self {
        Self {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        }
    }
}

/// Decision receipt emission policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceiptPolicy {
    pub emit_on_allow: bool,
    pub emit_on_deny: bool,
}

impl Default for DecisionReceiptPolicy {
    fn default() -> Self {
        Self {
            emit_on_allow: false,
            emit_on_deny: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Objects
// ─────────────────────────────────────────────────────────────────────────────

/// `ZoneDefinitionObject` (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDefinitionObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub name: String,
    pub integrity_level: IntegrityLevel,
    pub confidentiality_level: ConfidentialityLevel,
    pub symbol_port: u16,
    pub control_port: u16,
    pub transport_policy: ZoneTransportPolicy,
    pub policy_object_id: ObjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,
    pub signature: NodeSignature,
}

/// `ZonePolicyObject` (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePolicyObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    #[serde(default)]
    pub principal_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub principal_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub connector_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub connector_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_ceiling: Vec<CapabilityId>,
    #[serde(default)]
    pub transport_policy: ZoneTransportPolicy,
    #[serde(default)]
    pub decision_receipts: DecisionReceiptPolicy,
}

/// A bounded glob-only policy pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPattern {
    pub pattern: String,
}

impl PolicyPattern {
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        pattern_matches(&self.pattern, value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource Objects
// ─────────────────────────────────────────────────────────────────────────────

/// Zone-bound handle to an external resource (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceObject {
    pub header: ObjectHeader,
    pub resource_uri: String,
    pub integrity_label: IntegrityLevel,
    pub confidentiality_label: ConfidentialityLevel,
    #[serde(default)]
    pub taint_flags: TaintFlags,
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Reason Codes
// ─────────────────────────────────────────────────────────────────────────────

/// Stable policy decision reason codes (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReasonCode {
    Allow,
    CapabilityInsufficient,
    CheckpointStaleFrontier,
    RevocationStaleFrontier,
    TaintPublicInputDangerous,
    TaintUnverifiedLinkRisky,
    TaintMaliciousInput,
    TaintRiskyRequiresElevation,
    TaintCrossZoneUnapproved,
    IntegrityInsufficient,
    ZonePolicyPrincipalDenied,
    ZonePolicyConnectorDenied,
    ZonePolicyCapabilityDenied,
    ZonePolicyPrincipalNotAllowed,
    ZonePolicyConnectorNotAllowed,
    ZonePolicyCapabilityNotAllowed,
    ApprovalMissingElevation,
    ApprovalMissingDeclassification,
    ApprovalMissingExecution,
    ApprovalExecutionScopeMismatch,
    ApprovalExpired,
    ApprovalZoneMismatch,
    ApprovalTokenInvalid,
    TransportDerpForbidden,
    TransportFunnelForbidden,
    TransportLanForbidden,
    SanitizerReceiptInvalid,
    SanitizerCoverageInsufficient,
}

impl DecisionReasonCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::CapabilityInsufficient => "capability.insufficient",
            Self::CheckpointStaleFrontier => "checkpoint.stale_frontier",
            Self::RevocationStaleFrontier => "revocation.stale_frontier",
            Self::TaintPublicInputDangerous => "taint.public_input_dangerous",
            Self::TaintUnverifiedLinkRisky => "taint.unverified_link_risky",
            Self::TaintMaliciousInput => "taint.malicious_input",
            Self::TaintRiskyRequiresElevation => "taint.risky_requires_elevation",
            Self::TaintCrossZoneUnapproved => "taint.cross_zone_unapproved",
            Self::IntegrityInsufficient => "integrity.insufficient",
            Self::ZonePolicyPrincipalDenied => "zone_policy.principal_denied",
            Self::ZonePolicyConnectorDenied => "zone_policy.connector_denied",
            Self::ZonePolicyCapabilityDenied => "zone_policy.capability_denied",
            Self::ZonePolicyPrincipalNotAllowed => "zone_policy.principal_not_allowed",
            Self::ZonePolicyConnectorNotAllowed => "zone_policy.connector_not_allowed",
            Self::ZonePolicyCapabilityNotAllowed => "zone_policy.capability_not_allowed",
            Self::ApprovalMissingElevation => "approval.missing_elevation",
            Self::ApprovalMissingDeclassification => "approval.missing_declassification",
            Self::ApprovalMissingExecution => "approval.missing_execution",
            Self::ApprovalExecutionScopeMismatch => "approval.execution_scope_mismatch",
            Self::ApprovalExpired => "approval.expired",
            Self::ApprovalZoneMismatch => "approval.zone_mismatch",
            Self::ApprovalTokenInvalid => "approval.token_invalid",
            Self::TransportDerpForbidden => "transport.derp_forbidden",
            Self::TransportFunnelForbidden => "transport.funnel_forbidden",
            Self::TransportLanForbidden => "transport.lan_forbidden",
            Self::SanitizerReceiptInvalid => "taint.sanitizer_invalid",
            Self::SanitizerCoverageInsufficient => "taint.sanitizer_coverage_insufficient",
        }
    }

    #[must_use]
    pub const fn from_provenance_violation(error: &ProvenanceViolation) -> Self {
        match error {
            ProvenanceViolation::PublicInputForDangerousOperation => {
                Self::TaintPublicInputDangerous
            }
            ProvenanceViolation::MaliciousInputDetected => Self::TaintMaliciousInput,
            ProvenanceViolation::TaintedInputForRiskyOperation { .. } => {
                Self::TaintRiskyRequiresElevation
            }
            ProvenanceViolation::InsufficientIntegrity { .. } => Self::IntegrityInsufficient,
            ProvenanceViolation::InvalidElevation { .. } => Self::ApprovalMissingElevation,
            ProvenanceViolation::InvalidDeclassification { .. } => {
                Self::ApprovalMissingDeclassification
            }
            ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation => {
                Self::TaintCrossZoneUnapproved
            }
            ProvenanceViolation::SanitizerCoverageInsufficient => {
                Self::SanitizerCoverageInsufficient
            }
            ProvenanceViolation::ApprovalTokenInvalid => Self::ApprovalTokenInvalid,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Models
// ─────────────────────────────────────────────────────────────────────────────

/// Policy decision result.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason_code: DecisionReasonCode,
    pub evidence: Vec<ObjectId>,
    pub explanation: Option<String>,
}

impl PolicyDecision {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub const fn allow(evidence: Vec<ObjectId>) -> Self {
        Self {
            decision: Decision::Allow,
            reason_code: DecisionReasonCode::Allow,
            evidence,
            explanation: None,
        }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub const fn deny(reason_code: DecisionReasonCode, evidence: Vec<ObjectId>) -> Self {
        Self {
            decision: Decision::Deny,
            reason_code,
            evidence,
            explanation: None,
        }
    }

    #[must_use]
    pub fn to_receipt(
        &self,
        header: ObjectHeader,
        request_object_id: ObjectId,
        signature: NodeSignature,
    ) -> DecisionReceipt {
        DecisionReceipt {
            header,
            request_object_id,
            decision: self.decision,
            reason_code: self.reason_code.as_str().to_string(),
            evidence: self.evidence.clone(),
            explanation: self.explanation.clone(),
            signature,
        }
    }
}

/// Invocation context for policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecisionInput<'a> {
    pub request_object_id: ObjectId,
    pub zone_id: ZoneId,
    pub principal: PrincipalId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub capability_id: CapabilityId,
    pub safety_tier: SafetyTier,
    pub provenance: ProvenanceRecord,
    pub approval_tokens: &'a [ApprovalToken],
    pub sanitizer_receipts: &'a [SanitizerReceipt],
    pub request_input: Option<&'a serde_json::Value>,
    pub request_input_hash: Option<[u8; 32]>,
    pub related_object_ids: &'a [ObjectId],
    pub transport: TransportMode,
    pub checkpoint_fresh: bool,
    pub revocation_fresh: bool,
    pub execution_approval_required: bool,
    pub now_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Policy evaluator for `ZonePolicyObject` instances.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub zone_policy: ZonePolicyObject,
}

impl PolicyEngine {
    /// Evaluate an invocation request against the zone policy.
    #[must_use]
    pub fn evaluate_invoke(&self, input: &PolicyDecisionInput<'_>) -> PolicyDecision {
        if !input.revocation_fresh {
            return PolicyDecision::deny(DecisionReasonCode::RevocationStaleFrontier, Vec::new());
        }
        if !input.checkpoint_fresh {
            return PolicyDecision::deny(DecisionReasonCode::CheckpointStaleFrontier, Vec::new());
        }

        if let Some(reason) = check_transport(&self.zone_policy.transport_policy, input.transport) {
            return PolicyDecision::deny(reason, Vec::new());
        }

        if let Some(reason) = check_pattern_lists(&self.zone_policy, input) {
            return PolicyDecision::deny(reason, Vec::new());
        }

        if !self.zone_policy.capability_ceiling.is_empty()
            && !self
                .zone_policy
                .capability_ceiling
                .contains(&input.capability_id)
        {
            return PolicyDecision::deny(DecisionReasonCode::CapabilityInsufficient, Vec::new());
        }

        let mut evidence = Vec::new();
        let mut provenance = input.provenance.clone();

        if let Some(reason) = apply_sanitizer_receipts(input, &mut provenance, &mut evidence) {
            return PolicyDecision::deny(reason, evidence);
        }

        if matches!(
            input.safety_tier,
            SafetyTier::Risky
                | SafetyTier::Dangerous
                | SafetyTier::Critical
                | SafetyTier::Forbidden
        ) && provenance.taint_flags.contains(TaintFlag::UnverifiedLink)
        {
            return PolicyDecision::deny(DecisionReasonCode::TaintUnverifiedLinkRisky, evidence);
        }

        if matches!(
            input.safety_tier,
            SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden
        ) && provenance.taint_flags.contains(TaintFlag::PublicInput)
        {
            return PolicyDecision::deny(DecisionReasonCode::TaintPublicInputDangerous, evidence);
        }

        if let Some(reason) = apply_flow_approvals(input, &mut provenance, &mut evidence) {
            return PolicyDecision::deny(reason, evidence);
        }

        if input.execution_approval_required {
            match find_execution_approval(input) {
                Ok(Some(token)) => evidence.push(approval_token_object_id(token)),
                Ok(None) => {
                    return PolicyDecision::deny(
                        DecisionReasonCode::ApprovalMissingExecution,
                        evidence,
                    );
                }
                Err(reason) => return PolicyDecision::deny(reason, evidence),
            }
        }

        if let Err(error) = provenance.can_drive_operation(input.safety_tier) {
            return PolicyDecision::deny(
                DecisionReasonCode::from_provenance_violation(&error),
                evidence,
            );
        }

        PolicyDecision::allow(evidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Role Graph (DAG enforcement)
// ─────────────────────────────────────────────────────────────────────────────

/// Role graph validation errors.
#[derive(Debug, thiserror::Error)]
pub enum RoleGraphError {
    #[error("unknown role id: {role_id}")]
    UnknownRole { role_id: ObjectId },

    #[error("role inheritance cycle detected: {cycle:?}")]
    RoleCycle { cycle: Vec<ObjectId> },
}

/// Role graph for resolving role inheritance.
#[derive(Debug, Clone)]
pub struct RoleGraph {
    roles: HashMap<ObjectId, RoleObject>,
}

impl RoleGraph {
    #[must_use]
    pub const fn new(roles: HashMap<ObjectId, RoleObject>) -> Self {
        Self { roles }
    }

    /// Validate that role inheritance is acyclic.
    ///
    /// # Errors
    /// Returns [`RoleGraphError::RoleCycle`] if a cycle is detected or
    /// [`RoleGraphError::UnknownRole`] if a referenced role is missing.
    pub fn validate_acyclic(&self) -> Result<(), RoleGraphError> {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();

        for role_id in self.roles.keys() {
            self.visit(role_id, &mut visiting, &mut visited, &mut Vec::new())?;
        }

        Ok(())
    }

    fn visit(
        &self,
        role_id: &ObjectId,
        visiting: &mut HashSet<ObjectId>,
        visited: &mut HashSet<ObjectId>,
        stack: &mut Vec<ObjectId>,
    ) -> Result<(), RoleGraphError> {
        if visited.contains(role_id) {
            return Ok(());
        }
        if visiting.contains(role_id) {
            stack.push(*role_id);
            return Err(RoleGraphError::RoleCycle {
                cycle: stack.clone(),
            });
        }

        let role = self
            .roles
            .get(role_id)
            .ok_or(RoleGraphError::UnknownRole { role_id: *role_id })?;

        visiting.insert(*role_id);
        stack.push(*role_id);

        for included in &role.includes {
            self.visit(included, visiting, visited, stack)?;
        }

        visiting.remove(role_id);
        visited.insert(*role_id);
        stack.pop();
        Ok(())
    }

    /// Resolve effective capability grants for a role set.
    ///
    /// # Errors
    /// Returns [`RoleGraphError::UnknownRole`] if any role id is missing.
    pub fn resolve_caps(
        &self,
        role_ids: &[ObjectId],
    ) -> Result<Vec<CapabilityGrant>, RoleGraphError> {
        let mut resolved = Vec::new();
        let mut seen = HashSet::new();

        for role_id in role_ids {
            self.collect_caps(role_id, &mut seen, &mut resolved)?;
        }

        Ok(resolved)
    }

    fn collect_caps(
        &self,
        role_id: &ObjectId,
        seen: &mut HashSet<ObjectId>,
        out: &mut Vec<CapabilityGrant>,
    ) -> Result<(), RoleGraphError> {
        if seen.contains(role_id) {
            return Ok(());
        }
        let role = self
            .roles
            .get(role_id)
            .ok_or(RoleGraphError::UnknownRole { role_id: *role_id })?;
        seen.insert(*role_id);
        out.extend(role.caps.iter().cloned());
        for included in &role.includes {
            self.collect_caps(included, seen, out)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn check_transport(
    policy: &ZoneTransportPolicy,
    mode: TransportMode,
) -> Option<DecisionReasonCode> {
    if policy.allows(mode) {
        None
    } else {
        Some(match mode {
            TransportMode::Lan => DecisionReasonCode::TransportLanForbidden,
            TransportMode::Derp => DecisionReasonCode::TransportDerpForbidden,
            TransportMode::Funnel => DecisionReasonCode::TransportFunnelForbidden,
        })
    }
}

fn check_pattern_lists(
    policy: &ZonePolicyObject,
    input: &PolicyDecisionInput<'_>,
) -> Option<DecisionReasonCode> {
    if matches_any(&policy.principal_deny, input.principal.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyPrincipalDenied);
    }
    if matches_any(&policy.connector_deny, input.connector_id.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyConnectorDenied);
    }
    if matches_any(&policy.capability_deny, input.capability_id.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyCapabilityDenied);
    }

    if !policy.principal_allow.is_empty()
        && !matches_any(&policy.principal_allow, input.principal.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyPrincipalNotAllowed);
    }
    if !policy.connector_allow.is_empty()
        && !matches_any(&policy.connector_allow, input.connector_id.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyConnectorNotAllowed);
    }
    if !policy.capability_allow.is_empty()
        && !matches_any(&policy.capability_allow, input.capability_id.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyCapabilityNotAllowed);
    }

    None
}

fn matches_any(patterns: &[PolicyPattern], value: &str) -> bool {
    patterns.iter().any(|pattern| pattern.matches(value))
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return true;
    }

    let mut index = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if idx == 0 && !pattern.starts_with('*') && !value.starts_with(part) {
            return false;
        }
        if idx == parts.len() - 1 && !pattern.ends_with('*') && !value.ends_with(part) {
            return false;
        }

        match value[index..].find(part) {
            Some(pos) => {
                index += pos + part.len();
            }
            None => return false,
        }
    }

    true
}

fn apply_flow_approvals(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Option<DecisionReasonCode> {
    match provenance.can_flow_to(&input.zone_id) {
        FlowCheckResult::Allowed => None,
        FlowCheckResult::RequiresElevation => apply_elevation(input, provenance, evidence).err(),
        FlowCheckResult::RequiresDeclassification => {
            apply_declassification(input, provenance, evidence).err()
        }
        FlowCheckResult::RequiresBoth => {
            if let Err(reason) = apply_elevation(input, provenance, evidence) {
                return Some(reason);
            }
            if let Err(reason) = apply_declassification(input, provenance, evidence) {
                return Some(reason);
            }
            None
        }
    }
}

fn apply_elevation(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Result<(), DecisionReasonCode> {
    let required = IntegrityLevel::from_zone(&input.zone_id);

    let token = input
        .approval_tokens
        .iter()
        .find(|token| token.is_valid(input.now_ms) && token.zone_id == input.zone_id)
        .and_then(|token| match &token.scope {
            ApprovalScope::Elevation(scope) => {
                if scope.operation_id == input.operation_id.as_str()
                    && scope.target_integrity >= required
                {
                    Some(token)
                } else {
                    None
                }
            }
            _ => None,
        })
        .ok_or(DecisionReasonCode::ApprovalMissingElevation)?;

    let token_id = approval_token_object_id(token);
    let target = match &token.scope {
        ApprovalScope::Elevation(scope) => scope.target_integrity,
        _ => required,
    };

    provenance
        .apply_elevation(target, token_id, input.now_ms)
        .map_err(|_| DecisionReasonCode::ApprovalMissingElevation)?;

    evidence.push(token_id);
    Ok(())
}

fn apply_declassification(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Result<(), DecisionReasonCode> {
    let target = ConfidentialityLevel::from_zone(&input.zone_id);

    let token = input
        .approval_tokens
        .iter()
        .find(|token| token.is_valid(input.now_ms) && token.zone_id == input.zone_id)
        .and_then(|token| match &token.scope {
            ApprovalScope::Declassification(scope) => {
                let objects_match = if input.related_object_ids.is_empty() {
                    scope.object_ids.contains(&input.request_object_id)
                } else {
                    input
                        .related_object_ids
                        .iter()
                        .all(|id| scope.object_ids.contains(id))
                };

                if scope.from_zone == provenance.current_zone
                    && scope.to_zone == input.zone_id
                    && scope.target_confidentiality <= provenance.confidentiality_label
                    && scope.target_confidentiality == target
                    && objects_match
                {
                    Some(token)
                } else {
                    None
                }
            }
            _ => None,
        })
        .ok_or(DecisionReasonCode::ApprovalMissingDeclassification)?;

    let token_id = approval_token_object_id(token);
    let new_level = match &token.scope {
        ApprovalScope::Declassification(scope) => scope.target_confidentiality,
        _ => target,
    };

    provenance
        .apply_declassification(new_level, token_id, input.now_ms)
        .map_err(|_| DecisionReasonCode::ApprovalMissingDeclassification)?;

    evidence.push(token_id);
    Ok(())
}

fn find_execution_approval<'a>(
    input: &PolicyDecisionInput<'a>,
) -> Result<Option<&'a ApprovalToken>, DecisionReasonCode> {
    let mut saw_execution_scope = false;
    let mut had_mismatch = false;

    for token in input.approval_tokens {
        if !token.is_valid(input.now_ms) || token.zone_id != input.zone_id {
            continue;
        }

        let ApprovalScope::Execution(scope) = &token.scope else {
            continue;
        };
        saw_execution_scope = true;

        if scope.connector_id != input.connector_id.as_str() {
            continue;
        }
        if !pattern_matches(&scope.method_pattern, input.operation_id.as_str()) {
            continue;
        }
        if let Some(request_id) = scope.request_object_id {
            if request_id != input.request_object_id {
                had_mismatch = true;
                continue;
            }
        }
        if let Some(expected_hash) = scope.input_hash {
            if input.request_input_hash != Some(expected_hash) {
                had_mismatch = true;
                continue;
            }
        }
        if !scope.input_constraints.is_empty()
            && !input_constraints_match(scope.input_constraints.as_slice(), input.request_input)
        {
            had_mismatch = true;
            continue;
        }

        return Ok(Some(token));
    }

    if saw_execution_scope && had_mismatch {
        Err(DecisionReasonCode::ApprovalExecutionScopeMismatch)
    } else {
        Ok(None)
    }
}

fn input_constraints_match(
    constraints: &[crate::InputConstraint],
    input: Option<&serde_json::Value>,
) -> bool {
    let Some(value) = input else {
        return false;
    };

    constraints
        .iter()
        .all(|constraint| value.pointer(&constraint.pointer) == Some(&constraint.expected))
}

fn apply_sanitizer_receipts(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Option<DecisionReasonCode> {
    for receipt in input.sanitizer_receipts {
        if !receipt.is_valid() {
            return Some(DecisionReasonCode::SanitizerReceiptInvalid);
        }

        if !receipt_covers_inputs(receipt, &provenance.input_sources) {
            return Some(DecisionReasonCode::SanitizerCoverageInsufficient);
        }

        let receipt_id = sanitizer_receipt_object_id(receipt);
        provenance.apply_taint_reduction(
            &receipt.cleared_flags,
            receipt_id,
            receipt.covered_inputs.clone(),
            receipt.timestamp_ms,
        );
        evidence.push(receipt_id);
    }

    None
}

fn receipt_covers_inputs(receipt: &SanitizerReceipt, inputs: &[ObjectId]) -> bool {
    if inputs.is_empty() {
        return true;
    }
    inputs.iter().all(|input| receipt.covers_input(input))
}

fn approval_token_object_id(token: &ApprovalToken) -> ObjectId {
    // SECURITY: Use content-addressed ID to prevent malleability.
    // We use the full canonical encoding of the token.
    // Note: We use from_unscoped_bytes here because we don't have the Zone ObjectIdKey available
    // in this context, but this still ensures the ID is bound to the token content.
    let bytes =
        fcp_cbor::to_canonical_cbor(token).unwrap_or_else(|_| token.token_id.as_bytes().to_vec());
    ObjectId::from_unscoped_bytes(&bytes)
}

fn sanitizer_receipt_object_id(receipt: &SanitizerReceipt) -> ObjectId {
    ObjectId::from_unscoped_bytes(receipt.receipt_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApprovalScope, ElevationScope, IntegrityLevel, ZoneId};

    #[test]
    fn test_approval_token_object_id_is_content_addressed() {
        // Demonstrates that ObjectId is derived from full content, ensuring malleability protection.

        let mut token = ApprovalToken {
            token_id: "test-token-123".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            issuer: "issuer".to_string(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op".to_string(),
                original_provenance_id: ObjectId::from_unscoped_bytes(b"prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        let id1 = approval_token_object_id(&token);

        // Mutate content but keep token_id
        if let ApprovalScope::Elevation(ref mut scope) = token.scope {
            scope.target_integrity = IntegrityLevel::Untrusted;
        }
        let id2 = approval_token_object_id(&token);

        // IDs MUST be different despite having same token_id
        assert_ne!(id1, id2);

        // And they must NOT match the simple hash of the ID string
        assert_ne!(id1, ObjectId::from_unscoped_bytes(b"test-token-123"));
    }
}

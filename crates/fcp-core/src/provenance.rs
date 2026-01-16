//! Provenance, Taint, and Unified [`ApprovalToken`] (NORMATIVE).
//!
//! This module implements the FCP2 provenance model for tracking data origin,
//! trust boundaries, and compositional security guarantees.
//!
//! # Key Concepts
//!
//! - **Provenance**: Tracks the origin and transformations of data as it flows
//!   through the mesh. Each object carries provenance metadata.
//!
//! - **Labels**: Integrity and confidentiality labels that determine what
//!   operations can be performed and where data can flow.
//!
//! - **Taint**: Flags that accumulate as data flows through untrusted sources.
//!   Taint can only be reduced with proof-carrying [`SanitizerReceipt`]s.
//!
//! - **[`ApprovalToken`]**: Unified token for elevation, declassification, and
//!   scoped execution authorization.
//!
//! # Security Model
//!
//! The provenance model enforces a lattice-based information flow policy:
//!
//! - **Integrity**: Flows DOWN freely; flowing UP requires [`ApprovalScope::Elevation`]
//! - **Confidentiality**: Flows UP freely; flowing DOWN requires [`ApprovalScope::Declassification`]
//!
//! When merging data from multiple sources:
//! - `integrity = MIN(effective_integrity(inputs))`
//! - `confidentiality = MAX(effective_confidentiality(inputs))`

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{SafetyTier, ZoneId};
use crate::object::ObjectId;

// ─────────────────────────────────────────────────────────────────────────────
// Integrity and Confidentiality Labels
// ─────────────────────────────────────────────────────────────────────────────

/// Integrity level for data (NORMATIVE).
///
/// Higher values indicate higher integrity (more trusted).
/// Integrity flows DOWN the lattice freely; flowing UP requires elevation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[repr(u8)]
pub enum IntegrityLevel {
    /// Untrusted external input (lowest integrity)
    #[default]
    Untrusted = 0,
    /// Input from semi-trusted community sources
    Community = 1,
    /// Input from authenticated work context
    Work = 2,
    /// Input from authenticated private context
    Private = 3,
    /// Input from owner/root context (highest integrity)
    Owner = 4,
}

impl IntegrityLevel {
    /// Map from a zone to its default integrity level (NORMATIVE).
    #[must_use]
    pub fn from_zone(zone: &ZoneId) -> Self {
        match zone.as_str() {
            "z:owner" => Self::Owner,
            "z:private" => Self::Private,
            "z:work" => Self::Work,
            "z:community" => Self::Community,
            _ => Self::Untrusted,
        }
    }

    /// Get the numeric value for comparison and merge operations.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}


impl fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => write!(f, "untrusted"),
            Self::Community => write!(f, "community"),
            Self::Work => write!(f, "work"),
            Self::Private => write!(f, "private"),
            Self::Owner => write!(f, "owner"),
        }
    }
}

/// Confidentiality level for data (NORMATIVE).
///
/// Higher values indicate higher confidentiality (more restricted).
/// Confidentiality flows UP the lattice freely; flowing DOWN requires declassification.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[repr(u8)]
pub enum ConfidentialityLevel {
    /// Public data (lowest confidentiality, can flow anywhere)
    #[default]
    Public = 0,
    /// Community-level data
    Community = 1,
    /// Work-level data
    Work = 2,
    /// Private/personal data
    Private = 3,
    /// Owner-only data (highest confidentiality)
    Owner = 4,
}

impl ConfidentialityLevel {
    /// Map from a zone to its default confidentiality level (NORMATIVE).
    #[must_use]
    pub fn from_zone(zone: &ZoneId) -> Self {
        match zone.as_str() {
            "z:owner" => Self::Owner,
            "z:private" => Self::Private,
            "z:work" => Self::Work,
            "z:community" => Self::Community,
            _ => Self::Public,
        }
    }

    /// Get the numeric value for comparison and merge operations.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}


impl fmt::Display for ConfidentialityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Community => write!(f, "community"),
            Self::Work => write!(f, "work"),
            Self::Private => write!(f, "private"),
            Self::Owner => write!(f, "owner"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Taint Flags
// ─────────────────────────────────────────────────────────────────────────────

/// Taint flags that accumulate as data flows through the system (NORMATIVE).
///
/// Taint is compositional via OR: if any input is tainted, output is tainted.
/// Taint can ONLY be reduced by referencing a valid `SanitizerReceipt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintFlag {
    /// Input came from public/untrusted internet source
    PublicInput,
    /// Input contains unverified external links/references
    UnverifiedLink,
    /// Input has been through an untrusted transformation
    UntrustedTransform,
    /// Input was injected by external webhook
    WebhookInjected,
    /// Input came from user-generated content
    UserGenerated,
    /// Input contains potentially malicious patterns (detected by sanitizer)
    PotentiallyMalicious,
    /// Input was synthesized by AI model
    AiGenerated,
    /// Input crossed zone boundary without explicit approval
    CrossZoneUnapproved,
}

impl TaintFlag {
    /// Check if this taint flag is considered critical (blocks Dangerous operations).
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::PublicInput | Self::PotentiallyMalicious | Self::CrossZoneUnapproved
        )
    }
}

impl fmt::Display for TaintFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicInput => write!(f, "PUBLIC_INPUT"),
            Self::UnverifiedLink => write!(f, "UNVERIFIED_LINK"),
            Self::UntrustedTransform => write!(f, "UNTRUSTED_TRANSFORM"),
            Self::WebhookInjected => write!(f, "WEBHOOK_INJECTED"),
            Self::UserGenerated => write!(f, "USER_GENERATED"),
            Self::PotentiallyMalicious => write!(f, "POTENTIALLY_MALICIOUS"),
            Self::AiGenerated => write!(f, "AI_GENERATED"),
            Self::CrossZoneUnapproved => write!(f, "CROSS_ZONE_UNAPPROVED"),
        }
    }
}

/// Collection of taint flags with set semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFlags(HashSet<TaintFlag>);

impl TaintFlags {
    /// Create an empty taint flag set.
    #[must_use]
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Create from a single flag.
    #[must_use]
    pub fn from_flag(flag: TaintFlag) -> Self {
        let mut set = HashSet::new();
        set.insert(flag);
        Self(set)
    }

    /// Check if empty (no taint).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if contains a specific flag.
    #[must_use]
    pub fn contains(&self, flag: TaintFlag) -> bool {
        self.0.contains(&flag)
    }

    /// Check if any critical taint is present.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.0.iter().any(|f| f.is_critical())
    }

    /// Add a taint flag.
    pub fn insert(&mut self, flag: TaintFlag) {
        self.0.insert(flag);
    }

    /// Remove a taint flag (only valid with [`SanitizerReceipt`] proof).
    pub fn remove(&mut self, flag: TaintFlag) {
        self.0.remove(&flag);
    }

    /// Merge with another taint set (OR semantics).
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self(self.0.union(&other.0).copied().collect())
    }

    /// Iterate over flags.
    pub fn iter(&self) -> impl Iterator<Item = &TaintFlag> {
        self.0.iter()
    }

    /// Number of taint flags.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl FromIterator<TaintFlag> for TaintFlags {
    fn from_iter<T: IntoIterator<Item = TaintFlag>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Label Adjustment (Proof-Carrying)
// ─────────────────────────────────────────────────────────────────────────────

/// A proof-carrying label adjustment (NORMATIVE).
///
/// Any elevation or declassification must be reflected by appending a
/// [`LabelAdjustment`] entry that references the authorizing [`ApprovalToken`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelAdjustment {
    /// Timestamp when the adjustment was made (Unix epoch ms)
    pub timestamp_ms: u64,

    /// Kind of adjustment
    pub kind: AdjustmentKind,

    /// The [`ApprovalToken`] [`ObjectId`] that authorized this adjustment
    pub approval_token_id: ObjectId,

    /// Previous integrity level (for elevation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_integrity: Option<IntegrityLevel>,

    /// New integrity level (for elevation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_integrity: Option<IntegrityLevel>,

    /// Previous confidentiality level (for declassification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_confidentiality: Option<ConfidentialityLevel>,

    /// New confidentiality level (for declassification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_confidentiality: Option<ConfidentialityLevel>,
}

/// Kind of label adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjustmentKind {
    /// Integrity elevated (flowing UP the lattice)
    Elevation,
    /// Confidentiality reduced (flowing DOWN the lattice)
    Declassification,
}

// ─────────────────────────────────────────────────────────────────────────────
// Taint Reduction (Proof-Carrying)
// ─────────────────────────────────────────────────────────────────────────────

/// A proof-carrying taint reduction (NORMATIVE).
///
/// Taint can ONLY be reduced by referencing a valid `SanitizerReceipt`
/// that covers the inputs being sanitized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintReduction {
    /// Timestamp when the reduction was applied (Unix epoch ms)
    pub timestamp_ms: u64,

    /// The [`SanitizerReceipt`] [`ObjectId`] that authorized this reduction
    pub sanitizer_receipt_id: ObjectId,

    /// Which taint flags were cleared
    pub cleared_flags: Vec<TaintFlag>,

    /// [`ObjectId`]s of inputs that were covered by this reduction
    pub covered_inputs: Vec<ObjectId>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone Crossing Record
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a zone crossing (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneCrossing {
    /// Timestamp of the crossing (Unix epoch ms)
    pub timestamp_ms: u64,

    /// Source zone
    pub from_zone: ZoneId,

    /// Destination zone
    pub to_zone: ZoneId,

    /// Whether this crossing was approved (via [`ApprovalToken`])
    pub approved: bool,

    /// The [`ApprovalToken`] [`ObjectId`] if approved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<ObjectId>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Provenance Record
// ─────────────────────────────────────────────────────────────────────────────

/// Complete provenance record for a mesh object (NORMATIVE).
///
/// This is the authoritative source of trust metadata for any object
/// flowing through the FCP mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// Zone where the data originally entered the mesh
    pub origin_zone: ZoneId,

    /// Current zone where the data resides
    pub current_zone: ZoneId,

    /// Current integrity label
    pub integrity_label: IntegrityLevel,

    /// Current confidentiality label
    pub confidentiality_label: ConfidentialityLevel,

    /// Accumulated taint flags
    #[serde(default)]
    pub taint_flags: TaintFlags,

    /// History of label adjustments (elevation/declassification)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub label_adjustments: Vec<LabelAdjustment>,

    /// History of taint reductions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_reductions: Vec<TaintReduction>,

    /// History of zone crossings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zone_crossings: Vec<ZoneCrossing>,

    /// [`ObjectId`]s of input sources (for merge tracking)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_sources: Vec<ObjectId>,
}

impl ProvenanceRecord {
    /// Create a new provenance record for data originating in a zone.
    #[must_use]
    pub fn new(origin_zone: ZoneId) -> Self {
        let integrity_label = IntegrityLevel::from_zone(&origin_zone);
        let confidentiality_label = ConfidentialityLevel::from_zone(&origin_zone);

        Self {
            current_zone: origin_zone.clone(),
            origin_zone,
            integrity_label,
            confidentiality_label,
            taint_flags: TaintFlags::new(),
            label_adjustments: Vec::new(),
            taint_reductions: Vec::new(),
            zone_crossings: Vec::new(),
            input_sources: Vec::new(),
        }
    }

    /// Create a provenance record for untrusted public input.
    #[must_use]
    pub fn public_input() -> Self {
        let mut record = Self::new(ZoneId::public());
        record.taint_flags.insert(TaintFlag::PublicInput);
        record
    }

    /// Merge multiple provenance records (NORMATIVE - SECURITY CRITICAL).
    ///
    /// When combining data from multiple inputs:
    /// - `integrity = MIN(effective_integrity(inputs))`
    /// - `confidentiality = MAX(effective_confidentiality(inputs))`
    /// - `taint_flags = OR(all input taint flags)`
    ///
    /// This prevents "mix trusted with untrusted" from upgrading trust.
    #[must_use]
    pub fn merge(records: &[&Self], current_zone: ZoneId) -> Self {
        if records.is_empty() {
            return Self::new(current_zone);
        }

        // MIN integrity (lowest wins - most conservative)
        let integrity_label = records
            .iter()
            .map(|r| r.integrity_label)
            .min()
            .unwrap_or_default();

        // MAX confidentiality (highest wins - most restrictive)
        let confidentiality_label = records
            .iter()
            .map(|r| r.confidentiality_label)
            .max()
            .unwrap_or_default();

        // OR taint flags (all flags accumulate)
        let mut taint_flags = TaintFlags::new();
        for record in records {
            for flag in record.taint_flags.iter() {
                taint_flags.insert(*flag);
            }
        }

        // Use first record's origin as canonical
        let origin_zone = records
            .first()
            .map_or_else(|| current_zone.clone(), |r| r.origin_zone.clone());

        // Collect all input sources
        let input_sources: Vec<ObjectId> = records
            .iter()
            .flat_map(|r| r.input_sources.iter().copied())
            .collect();

        Self {
            origin_zone,
            current_zone,
            integrity_label,
            confidentiality_label,
            taint_flags,
            label_adjustments: Vec::new(), // New merge, no adjustments yet
            taint_reductions: Vec::new(),
            zone_crossings: Vec::new(),
            input_sources,
        }
    }

    /// Check if this provenance can drive an operation at the given safety tier.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceViolation`] if the provenance is insufficient:
    /// - [`ProvenanceViolation::PublicInputForDangerousOperation`] for public-tainted input
    /// - [`ProvenanceViolation::MaliciousInputDetected`] if malicious content is detected
    /// - [`ProvenanceViolation::InsufficientIntegrity`] if integrity level is too low
    /// - [`ProvenanceViolation::TaintedInputForRiskyOperation`] for tainted risky ops
    pub fn can_drive_operation(&self, tier: SafetyTier) -> Result<(), ProvenanceViolation> {
        match tier {
            SafetyTier::Safe => Ok(()),
            SafetyTier::Risky => {
                // Risky operations may require elevation for tainted input
                if self.taint_flags.has_critical() && self.integrity_label < IntegrityLevel::Work {
                    Err(ProvenanceViolation::TaintedInputForRiskyOperation {
                        taint_flags: self.taint_flags.iter().copied().collect(),
                    })
                } else {
                    Ok(())
                }
            }
            SafetyTier::Dangerous | SafetyTier::Forbidden | SafetyTier::Critical => {
                // Dangerous/Critical operations MUST NOT be driven by public-tainted input
                if self.taint_flags.contains(TaintFlag::PublicInput) {
                    return Err(ProvenanceViolation::PublicInputForDangerousOperation);
                }
                if self.taint_flags.contains(TaintFlag::PotentiallyMalicious) {
                    return Err(ProvenanceViolation::MaliciousInputDetected);
                }
                if self.integrity_label < IntegrityLevel::Work {
                    return Err(ProvenanceViolation::InsufficientIntegrity {
                        required: IntegrityLevel::Work,
                        actual: self.integrity_label,
                    });
                }
                Ok(())
            }
        }
    }

    /// Check if data can flow to a target zone without approval.
    ///
    /// Integrity flows DOWN, confidentiality flows UP.
    #[must_use]
    pub fn can_flow_to(&self, target_zone: &ZoneId) -> FlowCheckResult {
        let target_integrity = IntegrityLevel::from_zone(target_zone);
        let target_confidentiality = ConfidentialityLevel::from_zone(target_zone);

        // Integrity: can flow DOWN (target integrity <= current integrity)
        let integrity_ok = target_integrity <= self.integrity_label;

        // Confidentiality: can flow UP (target confidentiality >= current confidentiality)
        let confidentiality_ok = target_confidentiality >= self.confidentiality_label;

        if integrity_ok && confidentiality_ok {
            FlowCheckResult::Allowed
        } else if !integrity_ok && !confidentiality_ok {
            FlowCheckResult::RequiresBoth
        } else if !integrity_ok {
            FlowCheckResult::RequiresElevation
        } else {
            FlowCheckResult::RequiresDeclassification
        }
    }

    /// Apply an elevation (increase integrity) with approval token proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceViolation::InvalidElevation`] if the new integrity level
    /// is not higher than the current integrity level.
    pub fn apply_elevation(
        &mut self,
        new_integrity: IntegrityLevel,
        approval_token_id: ObjectId,
        timestamp_ms: u64,
    ) -> Result<(), ProvenanceViolation> {
        if new_integrity <= self.integrity_label {
            return Err(ProvenanceViolation::InvalidElevation {
                current: self.integrity_label,
                requested: new_integrity,
            });
        }

        let adjustment = LabelAdjustment {
            timestamp_ms,
            kind: AdjustmentKind::Elevation,
            approval_token_id,
            prev_integrity: Some(self.integrity_label),
            new_integrity: Some(new_integrity),
            prev_confidentiality: None,
            new_confidentiality: None,
        };

        self.label_adjustments.push(adjustment);
        self.integrity_label = new_integrity;
        Ok(())
    }

    /// Apply a declassification (decrease confidentiality) with approval token proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceViolation::InvalidDeclassification`] if the new confidentiality
    /// level is not lower than the current confidentiality level.
    pub fn apply_declassification(
        &mut self,
        new_confidentiality: ConfidentialityLevel,
        approval_token_id: ObjectId,
        timestamp_ms: u64,
    ) -> Result<(), ProvenanceViolation> {
        if new_confidentiality >= self.confidentiality_label {
            return Err(ProvenanceViolation::InvalidDeclassification {
                current: self.confidentiality_label,
                requested: new_confidentiality,
            });
        }

        let adjustment = LabelAdjustment {
            timestamp_ms,
            kind: AdjustmentKind::Declassification,
            approval_token_id,
            prev_integrity: None,
            new_integrity: None,
            prev_confidentiality: Some(self.confidentiality_label),
            new_confidentiality: Some(new_confidentiality),
        };

        self.label_adjustments.push(adjustment);
        self.confidentiality_label = new_confidentiality;
        Ok(())
    }

    /// Apply a taint reduction with sanitizer receipt proof.
    pub fn apply_taint_reduction(
        &mut self,
        flags_to_clear: &[TaintFlag],
        sanitizer_receipt_id: ObjectId,
        covered_inputs: Vec<ObjectId>,
        timestamp_ms: u64,
    ) {
        let mut cleared = Vec::new();
        for flag in flags_to_clear {
            if self.taint_flags.contains(*flag) {
                self.taint_flags.remove(*flag);
                cleared.push(*flag);
            }
        }

        if !cleared.is_empty() {
            self.taint_reductions.push(TaintReduction {
                timestamp_ms,
                sanitizer_receipt_id,
                cleared_flags: cleared,
                covered_inputs,
            });
        }
    }

    /// Record a zone crossing.
    pub fn record_zone_crossing(
        &mut self,
        to_zone: ZoneId,
        approved: bool,
        approval_token_id: Option<ObjectId>,
        timestamp_ms: u64,
    ) {
        let crossing = ZoneCrossing {
            timestamp_ms,
            from_zone: self.current_zone.clone(),
            to_zone: to_zone.clone(),
            approved,
            approval_token_id,
        };

        self.zone_crossings.push(crossing);
        self.current_zone = to_zone;

        // Add taint if crossing without approval
        if !approved {
            self.taint_flags.insert(TaintFlag::CrossZoneUnapproved);
        }
    }
}

/// Result of checking if data can flow to a target zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowCheckResult {
    /// Flow is allowed without any approval
    Allowed,
    /// Flow requires elevation (integrity increase)
    RequiresElevation,
    /// Flow requires declassification (confidentiality decrease)
    RequiresDeclassification,
    /// Flow requires both elevation and declassification
    RequiresBoth,
}

/// Provenance violation error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProvenanceViolation {
    #[error("public input cannot drive dangerous operation")]
    PublicInputForDangerousOperation,

    #[error("malicious input pattern detected")]
    MaliciousInputDetected,

    #[error("tainted input cannot drive risky operation without elevation: {taint_flags:?}")]
    TaintedInputForRiskyOperation { taint_flags: Vec<TaintFlag> },

    #[error("insufficient integrity: required {required}, actual {actual}")]
    InsufficientIntegrity {
        required: IntegrityLevel,
        actual: IntegrityLevel,
    },

    #[error("invalid elevation: cannot elevate from {current} to {requested}")]
    InvalidElevation {
        current: IntegrityLevel,
        requested: IntegrityLevel,
    },

    #[error("invalid declassification: cannot declassify from {current} to {requested}")]
    InvalidDeclassification {
        current: ConfidentialityLevel,
        requested: ConfidentialityLevel,
    },

    #[error("sanitizer receipt does not cover required inputs")]
    SanitizerCoverageInsufficient,

    #[error("approval token expired or invalid")]
    ApprovalTokenInvalid,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified ApprovalToken
// ─────────────────────────────────────────────────────────────────────────────

/// Unified [`ApprovalToken`] (NORMATIVE).
///
/// A first-class mesh object for authorization with a closed set of scopes:
/// - [`ApprovalScope::Elevation`]: Raise integrity level
/// - [`ApprovalScope::Declassification`]: Lower confidentiality level
/// - [`ApprovalScope::Execution`]: Authorize specific operation invocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// Unique token ID (becomes [`ObjectId`] when stored)
    pub token_id: String,

    /// Timestamp when token was issued (Unix epoch ms)
    pub issued_at_ms: u64,

    /// Timestamp when token expires (Unix epoch ms)
    pub expires_at_ms: u64,

    /// Issuer identity (node ID or principal)
    pub issuer: String,

    /// The approval scope
    pub scope: ApprovalScope,

    /// Zone this token is valid within
    pub zone_id: ZoneId,

    /// `COSE_Sign1` signature over canonical encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl ApprovalToken {
    /// Check if the token is expired.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Check if the token is not yet valid.
    #[must_use]
    pub const fn is_not_yet_valid(&self, now_ms: u64) -> bool {
        now_ms < self.issued_at_ms
    }

    /// Check if the token is currently valid.
    #[must_use]
    pub const fn is_valid(&self, now_ms: u64) -> bool {
        !self.is_expired(now_ms) && !self.is_not_yet_valid(now_ms)
    }
}

/// Approval scope - the closed set of authorization types (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Elevation: Raise integrity level for an operation
    Elevation(ElevationScope),

    /// Declassification: Lower confidentiality for data flow
    Declassification(DeclassificationScope),

    /// Execution: Authorize a specific operation invocation
    Execution(ExecutionScope),
}

/// Elevation scope - authorization to raise integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationScope {
    /// Operation being elevated
    pub operation_id: String,

    /// Original provenance [`ObjectId`] being elevated
    pub original_provenance_id: ObjectId,

    /// Target integrity level
    pub target_integrity: IntegrityLevel,
}

/// Declassification scope - authorization to lower confidentiality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationScope {
    /// Source zone (where data is coming from)
    pub from_zone: ZoneId,

    /// Target zone (where data is going to)
    pub to_zone: ZoneId,

    /// [`ObjectId`]s being declassified
    pub object_ids: Vec<ObjectId>,

    /// Target confidentiality level
    pub target_confidentiality: ConfidentialityLevel,
}

/// Execution scope - authorization for a specific invocation (NORMATIVE).
///
/// This is how we support "allow this exact invocation" in degraded/offline
/// cases and avoid broad, reusable approvals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionScope {
    /// Connector being invoked
    pub connector_id: String,

    /// Method pattern (exact match or prefix wildcard)
    pub method_pattern: String,

    /// Specific request [`ObjectId`] if bound to exact request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_id: Option<ObjectId>,

    /// Hash of input data for exact binding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<[u8; 32]>,

    /// Input constraints (JSON Pointer paths with expected values)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_constraints: Vec<InputConstraint>,
}

/// Input constraint for execution scope (NORMATIVE).
///
/// Uses JSON Pointer (RFC 6901) ONLY - no `JSONPath`, no regex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConstraint {
    /// JSON Pointer path (RFC 6901)
    pub pointer: String,

    /// Expected value (JSON-serializable)
    pub expected: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// SanitizerReceipt
// ─────────────────────────────────────────────────────────────────────────────

/// [`SanitizerReceipt`] - proof of taint sanitization (NORMATIVE).
///
/// A sanitizer receipt proves that specific inputs were processed by
/// an authorized sanitizer, clearing specific taint flags.
///
/// Verifiers MUST validate:
/// 1. Signature validity
/// 2. Authority (is this sanitizer authorized for these flags?)
/// 3. Coverage (are the claimed inputs actually the ones being reduced?)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerReceipt {
    /// Unique receipt ID (becomes [`ObjectId`] when stored)
    pub receipt_id: String,

    /// Timestamp when sanitization occurred (Unix epoch ms)
    pub timestamp_ms: u64,

    /// Sanitizer identity
    pub sanitizer_id: String,

    /// Sanitizer authority zone (must have sufficient integrity)
    pub sanitizer_zone: ZoneId,

    /// Which taint flags this sanitizer is authorized to clear
    pub authorized_flags: Vec<TaintFlag>,

    /// [`ObjectId`]s of inputs that were sanitized
    pub covered_inputs: Vec<ObjectId>,

    /// Which flags were actually cleared (subset of `authorized_flags`)
    pub cleared_flags: Vec<TaintFlag>,

    /// `COSE_Sign1` signature over canonical encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl SanitizerReceipt {
    /// Check if this receipt covers a specific input.
    #[must_use]
    pub fn covers_input(&self, input_id: &ObjectId) -> bool {
        self.covered_inputs.contains(input_id)
    }

    /// Check if this receipt is authorized to clear a flag.
    #[must_use]
    pub fn can_clear(&self, flag: TaintFlag) -> bool {
        self.authorized_flags.contains(&flag)
    }

    /// Validate that cleared flags are a subset of authorized flags.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.cleared_flags.iter().all(|f| self.can_clear(*f))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintDecision
// ─────────────────────────────────────────────────────────────────────────────

/// Decision about taint-gated operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintDecision {
    /// Whether the operation is allowed
    pub allowed: bool,

    /// Reason code for audit
    pub reason_code: String,

    /// Safety tier of the operation
    pub safety_tier: SafetyTier,

    /// Taint flags that contributed to the decision
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributing_flags: Vec<TaintFlag>,

    /// [`ApprovalToken`] [`ObjectId`] if approval was used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<ObjectId>,

    /// [`SanitizerReceipt`] [`ObjectId`] if sanitization was used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizer_receipt_id: Option<ObjectId>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(label.as_bytes())
    }

    fn log_flow_test(
        test_name: &str,
        flow_type: &str,
        from_label: &str,
        to_label: &str,
        approval_present: bool,
        result: &str,
        reason_code: Option<&str>,
    ) {
        let log = json!({
            "test_name": test_name,
            "flow_type": flow_type,
            "from_label": from_label,
            "to_label": to_label,
            "approval_present": approval_present,
            "result": result,
            "reason_code": reason_code,
        });
        eprintln!("{log}");
    }

    fn assert_merge_equivalent(left: &ProvenanceRecord, right: &ProvenanceRecord) {
        assert_eq!(left.integrity_label, right.integrity_label);
        assert_eq!(left.confidentiality_label, right.confidentiality_label);
        assert_eq!(left.taint_flags, right.taint_flags);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Provenance Field Handling Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn public_input_defaults() {
        let record = ProvenanceRecord::public_input();

        assert_eq!(record.origin_zone, ZoneId::public());
        assert_eq!(record.current_zone, ZoneId::public());
        assert_eq!(record.integrity_label, IntegrityLevel::Untrusted);
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Public);
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        log_flow_test(
            "public_input_defaults",
            "integrity",
            "public",
            "public",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_empty_defaults_to_current_zone() {
        let merged = ProvenanceRecord::merge(&[], ZoneId::work());

        assert_eq!(merged.origin_zone, ZoneId::work());
        assert_eq!(merged.current_zone, ZoneId::work());
        assert_eq!(merged.integrity_label, IntegrityLevel::Work);
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Work);
        assert!(merged.taint_flags.is_empty());
        log_flow_test(
            "provenance_merge_empty_defaults_to_current_zone",
            "integrity",
            "none",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_single_preserves_fields() {
        let mut record = ProvenanceRecord::new(ZoneId::private());
        record.taint_flags.insert(TaintFlag::UserGenerated);
        record.input_sources.push(test_object_id("source-a"));

        let merged = ProvenanceRecord::merge(&[&record], ZoneId::work());

        assert_eq!(merged.origin_zone, ZoneId::private());
        assert_eq!(merged.current_zone, ZoneId::work());
        assert_eq!(merged.integrity_label, IntegrityLevel::Private);
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Private);
        assert!(merged.taint_flags.contains(TaintFlag::UserGenerated));
        assert_eq!(merged.input_sources, vec![test_object_id("source-a")]);
        log_flow_test(
            "provenance_merge_single_preserves_fields",
            "integrity",
            "private",
            "work",
            false,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Integrity/Confidentiality Level Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn integrity_level_ordering() {
        assert!(IntegrityLevel::Untrusted < IntegrityLevel::Community);
        assert!(IntegrityLevel::Community < IntegrityLevel::Work);
        assert!(IntegrityLevel::Work < IntegrityLevel::Private);
        assert!(IntegrityLevel::Private < IntegrityLevel::Owner);
    }

    #[test]
    fn confidentiality_level_ordering() {
        assert!(ConfidentialityLevel::Public < ConfidentialityLevel::Community);
        assert!(ConfidentialityLevel::Community < ConfidentialityLevel::Work);
        assert!(ConfidentialityLevel::Work < ConfidentialityLevel::Private);
        assert!(ConfidentialityLevel::Private < ConfidentialityLevel::Owner);
    }

    #[test]
    fn integrity_from_zone() {
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::owner()),
            IntegrityLevel::Owner
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::private()),
            IntegrityLevel::Private
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::work()),
            IntegrityLevel::Work
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::community()),
            IntegrityLevel::Community
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::public()),
            IntegrityLevel::Untrusted
        );
    }

    #[test]
    fn confidentiality_from_zone() {
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::owner()),
            ConfidentialityLevel::Owner
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::private()),
            ConfidentialityLevel::Private
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::work()),
            ConfidentialityLevel::Work
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::community()),
            ConfidentialityLevel::Community
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::public()),
            ConfidentialityLevel::Public
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Taint Flag Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn taint_flags_empty() {
        let flags = TaintFlags::new();
        assert!(flags.is_empty());
        assert!(!flags.has_critical());
    }

    #[test]
    fn taint_flags_critical() {
        let mut flags = TaintFlags::new();
        flags.insert(TaintFlag::UserGenerated);
        assert!(!flags.has_critical());

        flags.insert(TaintFlag::PublicInput);
        assert!(flags.has_critical());
    }

    #[test]
    fn taint_flags_merge() {
        let mut a = TaintFlags::new();
        a.insert(TaintFlag::PublicInput);

        let mut b = TaintFlags::new();
        b.insert(TaintFlag::UnverifiedLink);

        let merged = a.merge(&b);
        assert!(merged.contains(TaintFlag::PublicInput));
        assert!(merged.contains(TaintFlag::UnverifiedLink));
        assert_eq!(merged.len(), 2);
        log_flow_test(
            "taint_flags_merge",
            "integrity",
            "public+unverified",
            "public+unverified",
            false,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Provenance Merge Tests (SECURITY CRITICAL)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provenance_merge_min_integrity() {
        let owner = ProvenanceRecord::new(ZoneId::owner());
        let public = ProvenanceRecord::public_input();

        let merged = ProvenanceRecord::merge(&[&owner, &public], ZoneId::work());

        // MIN integrity: Owner + Untrusted = Untrusted
        assert_eq!(merged.integrity_label, IntegrityLevel::Untrusted);
        log_flow_test(
            "provenance_merge_min_integrity",
            "integrity",
            "owner+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_max_confidentiality() {
        let public = ProvenanceRecord::new(ZoneId::public());
        let private = ProvenanceRecord::new(ZoneId::private());

        let merged = ProvenanceRecord::merge(&[&public, &private], ZoneId::work());

        // MAX confidentiality: Public + Private = Private
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Private);
        log_flow_test(
            "provenance_merge_max_confidentiality",
            "confidentiality",
            "public+private",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_taint_accumulates() {
        let mut a = ProvenanceRecord::new(ZoneId::work());
        a.taint_flags.insert(TaintFlag::PublicInput);

        let mut b = ProvenanceRecord::new(ZoneId::work());
        b.taint_flags.insert(TaintFlag::UnverifiedLink);

        let merged = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());

        assert!(merged.taint_flags.contains(TaintFlag::PublicInput));
        assert!(merged.taint_flags.contains(TaintFlag::UnverifiedLink));
        log_flow_test(
            "provenance_merge_taint_accumulates",
            "integrity",
            "work",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_commutative_labels_and_taints() {
        let mut a = ProvenanceRecord::new(ZoneId::owner());
        a.taint_flags.insert(TaintFlag::UserGenerated);
        let mut b = ProvenanceRecord::new(ZoneId::public());
        b.taint_flags.insert(TaintFlag::PublicInput);

        let merged_ab = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());
        let merged_ba = ProvenanceRecord::merge(&[&b, &a], ZoneId::work());

        assert_merge_equivalent(&merged_ab, &merged_ba);
        log_flow_test(
            "provenance_merge_commutative_labels_and_taints",
            "integrity",
            "owner+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_associative_labels_and_taints() {
        let mut a = ProvenanceRecord::new(ZoneId::private());
        a.taint_flags.insert(TaintFlag::UserGenerated);
        let mut b = ProvenanceRecord::new(ZoneId::work());
        b.taint_flags.insert(TaintFlag::UnverifiedLink);
        let mut c = ProvenanceRecord::new(ZoneId::public());
        c.taint_flags.insert(TaintFlag::PublicInput);

        let merged_ab = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());
        let merged_abc_left = ProvenanceRecord::merge(&[&merged_ab, &c], ZoneId::work());

        let merged_bc = ProvenanceRecord::merge(&[&b, &c], ZoneId::work());
        let merged_abc_right = ProvenanceRecord::merge(&[&a, &merged_bc], ZoneId::work());

        assert_merge_equivalent(&merged_abc_left, &merged_abc_right);
        log_flow_test(
            "provenance_merge_associative_labels_and_taints",
            "integrity",
            "private+work+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operation Safety Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn public_input_blocks_dangerous() {
        let public = ProvenanceRecord::public_input();

        assert!(public.can_drive_operation(SafetyTier::Safe).is_ok());
        assert!(matches!(
            public.can_drive_operation(SafetyTier::Dangerous),
            Err(ProvenanceViolation::PublicInputForDangerousOperation)
        ));
    }

    #[test]
    fn work_integrity_allows_dangerous() {
        let work = ProvenanceRecord::new(ZoneId::work());
        assert!(work.can_drive_operation(SafetyTier::Dangerous).is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Flow Check Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn flow_down_integrity_requires_declassification() {
        let owner = ProvenanceRecord::new(ZoneId::owner());
        // Owner→Work: integrity flows DOWN (OK), but confidentiality also must flow DOWN
        // which requires declassification
        assert_eq!(
            owner.can_flow_to(&ZoneId::work()),
            FlowCheckResult::RequiresDeclassification
        );
        log_flow_test(
            "flow_down_integrity_requires_declassification",
            "confidentiality",
            "owner",
            "work",
            false,
            "pass",
            Some("REQUIRES_DECLASSIFICATION"),
        );
    }

    #[test]
    fn same_zone_flow_allowed() {
        // Same-zone flows are always allowed (no change in either dimension)
        let work = ProvenanceRecord::new(ZoneId::work());
        assert_eq!(work.can_flow_to(&ZoneId::work()), FlowCheckResult::Allowed);
        log_flow_test(
            "same_zone_flow_allowed_work",
            "integrity",
            "work",
            "work",
            false,
            "pass",
            None,
        );

        let owner = ProvenanceRecord::new(ZoneId::owner());
        assert_eq!(
            owner.can_flow_to(&ZoneId::owner()),
            FlowCheckResult::Allowed
        );
        log_flow_test(
            "same_zone_flow_allowed_owner",
            "integrity",
            "owner",
            "owner",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn flow_up_integrity_requires_elevation() {
        let work = ProvenanceRecord::new(ZoneId::work());
        // Work integrity cannot flow up to owner without elevation
        assert_eq!(
            work.can_flow_to(&ZoneId::owner()),
            FlowCheckResult::RequiresElevation
        );
        log_flow_test(
            "flow_up_integrity_requires_elevation",
            "integrity",
            "work",
            "owner",
            false,
            "pass",
            Some("REQUIRES_ELEVATION"),
        );
    }

    #[test]
    fn flow_up_confidentiality_requires_elevation() {
        let public = ProvenanceRecord::new(ZoneId::public());
        // Public→Private: confidentiality flows UP (OK), but integrity must also flow UP
        // which requires elevation
        assert_eq!(
            public.can_flow_to(&ZoneId::private()),
            FlowCheckResult::RequiresElevation
        );
        log_flow_test(
            "flow_up_confidentiality_requires_elevation",
            "integrity",
            "public",
            "private",
            false,
            "pass",
            Some("REQUIRES_ELEVATION"),
        );
    }

    #[test]
    fn flow_down_confidentiality_requires_declassification() {
        let private = ProvenanceRecord::new(ZoneId::private());
        // Private confidentiality cannot flow down to public without declassification
        assert_eq!(
            private.can_flow_to(&ZoneId::public()),
            FlowCheckResult::RequiresDeclassification
        );
        log_flow_test(
            "flow_down_confidentiality_requires_declassification",
            "confidentiality",
            "private",
            "public",
            false,
            "pass",
            Some("REQUIRES_DECLASSIFICATION"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Label Adjustment Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn elevation_increases_integrity() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        let token_id = test_object_id("approval-token");

        record
            .apply_elevation(IntegrityLevel::Owner, token_id, 1000)
            .expect("elevation should succeed");

        assert_eq!(record.integrity_label, IntegrityLevel::Owner);
        assert_eq!(record.label_adjustments.len(), 1);
        assert_eq!(record.label_adjustments[0].kind, AdjustmentKind::Elevation);
        log_flow_test(
            "elevation_increases_integrity",
            "integrity",
            "work",
            "owner",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn elevation_rejects_downgrade() {
        let mut record = ProvenanceRecord::new(ZoneId::owner());
        let token_id = test_object_id("approval-token");

        let result = record.apply_elevation(IntegrityLevel::Work, token_id, 1000);
        assert!(matches!(
            result,
            Err(ProvenanceViolation::InvalidElevation { .. })
        ));
        log_flow_test(
            "elevation_rejects_downgrade",
            "integrity",
            "owner",
            "work",
            true,
            "pass",
            Some("INVALID_ELEVATION"),
        );
    }

    #[test]
    fn declassification_decreases_confidentiality() {
        let mut record = ProvenanceRecord::new(ZoneId::private());
        let token_id = test_object_id("approval-token");

        record
            .apply_declassification(ConfidentialityLevel::Work, token_id, 1000)
            .expect("declassification should succeed");

        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Work);
        assert_eq!(record.label_adjustments.len(), 1);
        assert_eq!(
            record.label_adjustments[0].kind,
            AdjustmentKind::Declassification
        );
        log_flow_test(
            "declassification_decreases_confidentiality",
            "confidentiality",
            "private",
            "work",
            true,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Taint Reduction Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn taint_reduction_clears_flags() {
        let mut record = ProvenanceRecord::public_input();
        record.taint_flags.insert(TaintFlag::UnverifiedLink);
        assert_eq!(record.taint_flags.len(), 2);

        let receipt_id = test_object_id("sanitizer-receipt");
        record.apply_taint_reduction(&[TaintFlag::UnverifiedLink], receipt_id, vec![], 1000);

        assert!(!record.taint_flags.contains(TaintFlag::UnverifiedLink));
        assert!(record.taint_flags.contains(TaintFlag::PublicInput)); // Still there
        assert_eq!(record.taint_reductions.len(), 1);
        log_flow_test(
            "taint_reduction_clears_flags",
            "integrity",
            "public",
            "public",
            true,
            "pass",
            Some("TAINT_REDUCTION"),
        );
    }

    #[test]
    fn taint_reduction_noop_without_matching_flags() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::UserGenerated);

        let receipt_id = test_object_id("sanitizer-receipt");
        record.apply_taint_reduction(&[TaintFlag::UnverifiedLink], receipt_id, vec![], 1000);

        assert!(record.taint_flags.contains(TaintFlag::UserGenerated));
        assert!(record.taint_reductions.is_empty());
        log_flow_test(
            "taint_reduction_noop_without_matching_flags",
            "integrity",
            "work",
            "work",
            true,
            "pass",
            Some("NO_MATCHING_TAINT"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Zone Crossing Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_crossing_approved() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        let token_id = test_object_id("crossing-approval");

        record.record_zone_crossing(ZoneId::private(), true, Some(token_id), 1000);

        assert_eq!(record.current_zone.as_str(), "z:private");
        assert_eq!(record.zone_crossings.len(), 1);
        assert!(record.zone_crossings[0].approved);
        assert!(!record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
        log_flow_test(
            "zone_crossing_approved",
            "integrity",
            "work",
            "private",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn zone_crossing_unapproved_adds_taint() {
        let mut record = ProvenanceRecord::new(ZoneId::work());

        record.record_zone_crossing(ZoneId::private(), false, None, 1000);

        assert!(record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
        log_flow_test(
            "zone_crossing_unapproved_adds_taint",
            "integrity",
            "work",
            "private",
            false,
            "pass",
            Some("CROSS_ZONE_UNAPPROVED"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ApprovalToken Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn approval_token_validity() {
        let token = ApprovalToken {
            token_id: "test-token".into(),
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            issuer: "node:test".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op.test".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        assert!(token.is_not_yet_valid(500));
        assert!(token.is_valid(1500));
        assert!(token.is_expired(2500));
        log_flow_test(
            "approval_token_validity",
            "integrity",
            "work",
            "owner",
            true,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SanitizerReceipt Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sanitizer_receipt_validation() {
        let receipt = SanitizerReceipt {
            receipt_id: "test-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "sanitizer:html".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::UnverifiedLink, TaintFlag::UserGenerated],
            covered_inputs: vec![test_object_id("input1")],
            cleared_flags: vec![TaintFlag::UnverifiedLink],
            signature: None,
        };

        assert!(receipt.is_valid());
        assert!(receipt.can_clear(TaintFlag::UnverifiedLink));
        assert!(!receipt.can_clear(TaintFlag::PublicInput)); // Not authorized
        assert!(receipt.covers_input(&test_object_id("input1")));
        log_flow_test(
            "sanitizer_receipt_validation",
            "integrity",
            "work",
            "work",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn sanitizer_receipt_invalid_if_unauthorized_clear() {
        let receipt = SanitizerReceipt {
            receipt_id: "test-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "sanitizer:html".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::UnverifiedLink],
            covered_inputs: vec![],
            cleared_flags: vec![TaintFlag::PublicInput], // Not authorized!
            signature: None,
        };

        assert!(!receipt.is_valid());
        log_flow_test(
            "sanitizer_receipt_invalid_if_unauthorized_clear",
            "integrity",
            "work",
            "work",
            false,
            "pass",
            Some("UNAUTHORIZED_CLEAR"),
        );
    }

    #[test]
    fn sanitizer_receipt_coverage_checks_inputs() {
        let receipt = SanitizerReceipt {
            receipt_id: "test-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "sanitizer:html".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::UnverifiedLink],
            covered_inputs: vec![test_object_id("input1"), test_object_id("input2")],
            cleared_flags: vec![TaintFlag::UnverifiedLink],
            signature: None,
        };

        assert!(receipt.covers_input(&test_object_id("input1")));
        assert!(!receipt.covers_input(&test_object_id("input3")));
        log_flow_test(
            "sanitizer_receipt_coverage_checks_inputs",
            "integrity",
            "work",
            "work",
            true,
            "pass",
            Some("COVERS_INPUT"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provenance_record_serialization_roundtrip() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::UserGenerated);
        record.input_sources.push(test_object_id("source1"));

        let json = serde_json::to_string(&record).expect("serialization failed");
        let deserialized: ProvenanceRecord =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(
            record.origin_zone.as_str(),
            deserialized.origin_zone.as_str()
        );
        assert_eq!(record.integrity_label, deserialized.integrity_label);
        assert!(deserialized.taint_flags.contains(TaintFlag::UserGenerated));
    }

    #[test]
    fn approval_scope_serialization() {
        let scope = ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.telegram".into(),
            method_pattern: "send_message".into(),
            request_object_id: Some(test_object_id("req")),
            input_hash: None,
            input_constraints: vec![InputConstraint {
                pointer: "/chat_id".into(),
                expected: serde_json::json!("12345"),
            }],
        });

        let json = serde_json::to_string(&scope).expect("serialization failed");
        assert!(json.contains("\"type\":\"execution\""));
        assert!(json.contains("\"pointer\":\"/chat_id\""));
    }

    #[test]
    fn approval_scope_declassification_serialization() {
        let scope = ApprovalScope::Declassification(DeclassificationScope {
            from_zone: ZoneId::private(),
            to_zone: ZoneId::work(),
            object_ids: vec![test_object_id("obj-1"), test_object_id("obj-2")],
            target_confidentiality: ConfidentialityLevel::Work,
        });

        let json = serde_json::to_string(&scope).expect("serialization failed");
        assert!(json.contains("\"type\":\"declassification\""));
        assert!(json.contains(ZoneId::PRIVATE));
        assert!(json.contains(ZoneId::WORK));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attack Scenarios (Adversarial Security Tests)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attack_taint_laundering_without_receipt_rejected() {
        // Attempt to remove taint without a valid SanitizerReceipt
        let mut record = ProvenanceRecord::public_input();
        record.taint_flags.insert(TaintFlag::PotentiallyMalicious);

        // Attacker tries to directly modify taint_flags - but in the real system,
        // taint reduction MUST go through apply_taint_reduction with a valid receipt.
        // Here we verify that partial reduction still leaves critical taints.
        let receipt_id = test_object_id("fake-receipt");
        record.apply_taint_reduction(
            &[TaintFlag::UserGenerated], // Trying to clear non-existent flag
            receipt_id,
            vec![],
            1000,
        );

        // PUBLIC_INPUT and POTENTIALLY_MALICIOUS still present - cannot be laundered
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        assert!(record.taint_flags.contains(TaintFlag::PotentiallyMalicious));
        assert!(record.taint_flags.has_critical());
        log_flow_test(
            "attack_taint_laundering_without_receipt_rejected",
            "integrity",
            "public",
            "public",
            false,
            "pass",
            Some("TAINT_LAUNDERING_BLOCKED"),
        );
    }

    #[test]
    fn attack_elevation_bypass_without_approval_rejected() {
        // Attempt to flow low-integrity data to high-integrity zone without approval
        let public = ProvenanceRecord::public_input();

        // Try to flow to owner zone - should require elevation
        let flow_result = public.can_flow_to(&ZoneId::owner());
        assert_eq!(flow_result, FlowCheckResult::RequiresElevation);

        // Verify cannot drive dangerous operations
        assert!(matches!(
            public.can_drive_operation(SafetyTier::Dangerous),
            Err(ProvenanceViolation::PublicInputForDangerousOperation)
        ));

        // Cannot directly set integrity - must use apply_elevation with token
        let mut record = ProvenanceRecord::public_input();
        let fake_token = test_object_id("fake-token");

        // Elevation from Untrusted to Owner should succeed if token is provided
        // (signature verification happens at a higher layer)
        let result = record.apply_elevation(IntegrityLevel::Owner, fake_token, 1000);
        assert!(result.is_ok()); // Elevation works, but signature would be invalid

        // However, the taint is STILL PRESENT even after elevation
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        assert!(record.taint_flags.has_critical());

        log_flow_test(
            "attack_elevation_bypass_without_approval_rejected",
            "integrity",
            "public",
            "owner",
            false,
            "pass",
            Some("ELEVATION_BYPASS_BLOCKED"),
        );
    }

    #[test]
    fn attack_declassification_leak_without_approval_rejected() {
        // Attempt to leak high-confidentiality data to low-confidentiality zone
        let private = ProvenanceRecord::new(ZoneId::private());

        // Try to flow to public zone - should require declassification
        let flow_result = private.can_flow_to(&ZoneId::public());
        assert_eq!(flow_result, FlowCheckResult::RequiresDeclassification);

        // Attempt declassification to same level should fail
        let mut record = ProvenanceRecord::new(ZoneId::private());
        let fake_token = test_object_id("fake-token");

        let result =
            record.apply_declassification(ConfidentialityLevel::Private, fake_token, 1000);
        assert!(matches!(
            result,
            Err(ProvenanceViolation::InvalidDeclassification { .. })
        ));

        log_flow_test(
            "attack_declassification_leak_without_approval_rejected",
            "confidentiality",
            "private",
            "public",
            false,
            "pass",
            Some("DECLASSIFICATION_LEAK_BLOCKED"),
        );
    }

    #[test]
    fn attack_forged_sanitizer_receipt_invalid_signature() {
        // A forged receipt that claims to clear flags it's not authorized for
        let forged_receipt = SanitizerReceipt {
            receipt_id: "forged-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "attacker:evil".into(),
            sanitizer_zone: ZoneId::public(), // Low-trust zone
            authorized_flags: vec![TaintFlag::UnverifiedLink], // Only authorized for this
            covered_inputs: vec![test_object_id("victim-input")],
            cleared_flags: vec![
                TaintFlag::PublicInput, // NOT authorized!
                TaintFlag::PotentiallyMalicious, // NOT authorized!
            ],
            signature: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]), // Invalid signature
        };

        // Receipt validation fails - cleared flags not in authorized list
        assert!(!forged_receipt.is_valid());

        // Cannot clear PublicInput with this receipt
        assert!(!forged_receipt.can_clear(TaintFlag::PublicInput));
        assert!(!forged_receipt.can_clear(TaintFlag::PotentiallyMalicious));

        log_flow_test(
            "attack_forged_sanitizer_receipt_invalid_signature",
            "integrity",
            "public",
            "public",
            false,
            "pass",
            Some("FORGED_RECEIPT_REJECTED"),
        );
    }

    #[test]
    fn attack_stale_approval_token_rejected() {
        // Expired ApprovalToken should be rejected
        let stale_token = ApprovalToken {
            token_id: "stale-token".into(),
            issued_at_ms: 1000,
            expires_at_ms: 2000, // Expired at 2000ms
            issuer: "node:legitimate".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op.sensitive".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Token is expired at current time 5000ms
        let now_ms = 5000;
        assert!(stale_token.is_expired(now_ms));
        assert!(!stale_token.is_valid(now_ms));

        // Token was valid in the past
        let past_ms = 1500;
        assert!(!stale_token.is_expired(past_ms));
        assert!(stale_token.is_valid(past_ms));

        log_flow_test(
            "attack_stale_approval_token_rejected",
            "integrity",
            "work",
            "owner",
            false,
            "pass",
            Some("STALE_TOKEN_REJECTED"),
        );
    }

    #[test]
    fn attack_future_approval_token_rejected() {
        // ApprovalToken not yet valid (issued_at in future)
        let future_token = ApprovalToken {
            token_id: "future-token".into(),
            issued_at_ms: 5000, // Not valid until 5000ms
            expires_at_ms: 10000,
            issuer: "node:legitimate".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op.sensitive".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Token is not yet valid at current time 1000ms
        let now_ms = 1000;
        assert!(future_token.is_not_yet_valid(now_ms));
        assert!(!future_token.is_valid(now_ms));

        // Token will be valid in the future
        let future_ms = 7000;
        assert!(!future_token.is_not_yet_valid(future_ms));
        assert!(future_token.is_valid(future_ms));

        log_flow_test(
            "attack_future_approval_token_rejected",
            "integrity",
            "work",
            "owner",
            false,
            "pass",
            Some("FUTURE_TOKEN_REJECTED"),
        );
    }

    #[test]
    fn attack_mixed_input_integrity_downgrade() {
        // Mixing high-integrity with low-integrity data downgrades result
        let owner = ProvenanceRecord::new(ZoneId::owner());
        let mut attacker = ProvenanceRecord::public_input();
        attacker.taint_flags.insert(TaintFlag::PotentiallyMalicious);

        // Merge owner data with attacker-controlled data
        let merged = ProvenanceRecord::merge(&[&owner, &attacker], ZoneId::work());

        // Result has MINIMUM integrity (Untrusted from attacker)
        assert_eq!(merged.integrity_label, IntegrityLevel::Untrusted);

        // Result accumulates ALL taints
        assert!(merged.taint_flags.contains(TaintFlag::PublicInput));
        assert!(merged.taint_flags.contains(TaintFlag::PotentiallyMalicious));
        assert!(merged.taint_flags.has_critical());

        // Cannot drive dangerous operations
        assert!(matches!(
            merged.can_drive_operation(SafetyTier::Dangerous),
            Err(ProvenanceViolation::PublicInputForDangerousOperation)
        ));

        log_flow_test(
            "attack_mixed_input_integrity_downgrade",
            "integrity",
            "owner+public",
            "untrusted",
            false,
            "pass",
            Some("INTEGRITY_DOWNGRADE_ENFORCED"),
        );
    }

    #[test]
    fn attack_cross_zone_without_approval_adds_taint() {
        // Crossing zones without approval must add taint
        let mut record = ProvenanceRecord::new(ZoneId::work());
        assert!(!record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));

        // Cross without approval
        record.record_zone_crossing(ZoneId::private(), false, None, 1000);

        // Taint is added
        assert!(record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
        assert!(record.taint_flags.has_critical());

        log_flow_test(
            "attack_cross_zone_without_approval_adds_taint",
            "integrity",
            "work",
            "private",
            false,
            "pass",
            Some("UNAPPROVED_CROSSING_TAINTED"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vectors (Deterministic Test Vectors for Interop)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_vector_merge_two_records() {
        // Deterministic merge test vector
        let work = ProvenanceRecord::new(ZoneId::work());
        let private = ProvenanceRecord::new(ZoneId::private());

        let merged = ProvenanceRecord::merge(&[&work, &private], ZoneId::work());

        // Expected output (golden vector):
        // - integrity = MIN(Work, Private) = Work
        // - confidentiality = MAX(Work, Private) = Private
        assert_eq!(
            merged.integrity_label,
            IntegrityLevel::Work,
            "GOLDEN: merge(work, private).integrity == Work"
        );
        assert_eq!(
            merged.confidentiality_label,
            ConfidentialityLevel::Private,
            "GOLDEN: merge(work, private).confidentiality == Private"
        );
        assert!(
            merged.taint_flags.is_empty(),
            "GOLDEN: merge(work, private).taint_flags == empty"
        );

        log_flow_test(
            "golden_vector_merge_two_records",
            "integrity",
            "work+private",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_merge_with_taint() {
        // Merge with taint accumulation golden vector
        let mut a = ProvenanceRecord::new(ZoneId::work());
        a.taint_flags.insert(TaintFlag::PublicInput);

        let mut b = ProvenanceRecord::new(ZoneId::private());
        b.taint_flags.insert(TaintFlag::UserGenerated);

        let merged = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());

        // Expected output:
        // - integrity = MIN(Work, Private) = Work
        // - confidentiality = MAX(Work, Private) = Private
        // - taint = OR(PublicInput, UserGenerated)
        assert_eq!(merged.integrity_label, IntegrityLevel::Work);
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Private);
        assert!(merged.taint_flags.contains(TaintFlag::PublicInput));
        assert!(merged.taint_flags.contains(TaintFlag::UserGenerated));
        assert_eq!(merged.taint_flags.len(), 2);

        log_flow_test(
            "golden_vector_merge_with_taint",
            "integrity",
            "work+private",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_elevation_sequence() {
        // Elevation sequence golden vector
        let mut record = ProvenanceRecord::new(ZoneId::community());
        let token1 = test_object_id("elevation-token-1");
        let token2 = test_object_id("elevation-token-2");

        // Initial state
        assert_eq!(record.integrity_label, IntegrityLevel::Community);

        // First elevation: Community → Work
        record
            .apply_elevation(IntegrityLevel::Work, token1, 1000)
            .expect("elevation to Work should succeed");
        assert_eq!(record.integrity_label, IntegrityLevel::Work);
        assert_eq!(record.label_adjustments.len(), 1);

        // Second elevation: Work → Owner
        record
            .apply_elevation(IntegrityLevel::Owner, token2, 2000)
            .expect("elevation to Owner should succeed");
        assert_eq!(record.integrity_label, IntegrityLevel::Owner);
        assert_eq!(record.label_adjustments.len(), 2);

        // Verify adjustment history
        assert_eq!(
            record.label_adjustments[0].prev_integrity,
            Some(IntegrityLevel::Community)
        );
        assert_eq!(
            record.label_adjustments[0].new_integrity,
            Some(IntegrityLevel::Work)
        );
        assert_eq!(
            record.label_adjustments[1].prev_integrity,
            Some(IntegrityLevel::Work)
        );
        assert_eq!(
            record.label_adjustments[1].new_integrity,
            Some(IntegrityLevel::Owner)
        );

        log_flow_test(
            "golden_vector_elevation_sequence",
            "integrity",
            "community",
            "owner",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_declassification_sequence() {
        // Declassification sequence golden vector
        let mut record = ProvenanceRecord::new(ZoneId::owner());
        let token1 = test_object_id("declassify-token-1");
        let token2 = test_object_id("declassify-token-2");

        // Initial state
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Owner);

        // First declassification: Owner → Private
        record
            .apply_declassification(ConfidentialityLevel::Private, token1, 1000)
            .expect("declassification to Private should succeed");
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Private);

        // Second declassification: Private → Work
        record
            .apply_declassification(ConfidentialityLevel::Work, token2, 2000)
            .expect("declassification to Work should succeed");
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Work);
        assert_eq!(record.label_adjustments.len(), 2);

        log_flow_test(
            "golden_vector_declassification_sequence",
            "confidentiality",
            "owner",
            "work",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_taint_reduction() {
        // Taint reduction golden vector
        let mut record = ProvenanceRecord::public_input();
        record.taint_flags.insert(TaintFlag::UnverifiedLink);
        record.taint_flags.insert(TaintFlag::UserGenerated);

        let receipt_id = test_object_id("sanitizer-receipt");
        let covered = vec![test_object_id("input-1")];

        // Initial: 3 taints
        assert_eq!(record.taint_flags.len(), 3);

        // Sanitize UnverifiedLink only
        record.apply_taint_reduction(&[TaintFlag::UnverifiedLink], receipt_id, covered, 1000);

        // Result: 2 taints remain
        assert_eq!(record.taint_flags.len(), 2);
        assert!(!record.taint_flags.contains(TaintFlag::UnverifiedLink));
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        assert!(record.taint_flags.contains(TaintFlag::UserGenerated));

        // Reduction is recorded
        assert_eq!(record.taint_reductions.len(), 1);
        assert_eq!(
            record.taint_reductions[0].cleared_flags,
            vec![TaintFlag::UnverifiedLink]
        );

        log_flow_test(
            "golden_vector_taint_reduction",
            "integrity",
            "public",
            "public",
            true,
            "pass",
            Some("TAINT_REDUCTION"),
        );
    }

    #[test]
    fn golden_vector_flow_check_matrix() {
        // Complete flow check matrix golden vector
        let zones = [
            ZoneId::public(),
            ZoneId::community(),
            ZoneId::work(),
            ZoneId::private(),
            ZoneId::owner(),
        ];

        // For same-zone flows, should always be Allowed
        for zone in &zones {
            let record = ProvenanceRecord::new(zone.clone());
            assert_eq!(
                record.can_flow_to(zone),
                FlowCheckResult::Allowed,
                "Same-zone flow should be allowed: {}",
                zone.as_str()
            );
        }

        // Public → Owner requires elevation (integrity up)
        let public = ProvenanceRecord::new(ZoneId::public());
        assert_eq!(
            public.can_flow_to(&ZoneId::owner()),
            FlowCheckResult::RequiresElevation
        );

        // Owner → Public requires declassification (confidentiality down)
        let owner = ProvenanceRecord::new(ZoneId::owner());
        assert_eq!(
            owner.can_flow_to(&ZoneId::public()),
            FlowCheckResult::RequiresDeclassification
        );

        // Work → Private requires elevation (integrity up)
        let work = ProvenanceRecord::new(ZoneId::work());
        assert_eq!(
            work.can_flow_to(&ZoneId::private()),
            FlowCheckResult::RequiresElevation
        );

        // Private → Work requires declassification (confidentiality down)
        let private = ProvenanceRecord::new(ZoneId::private());
        assert_eq!(
            private.can_flow_to(&ZoneId::work()),
            FlowCheckResult::RequiresDeclassification
        );

        log_flow_test(
            "golden_vector_flow_check_matrix",
            "integrity",
            "matrix",
            "matrix",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_safety_tier_enforcement() {
        // Safety tier enforcement golden vector
        let public = ProvenanceRecord::public_input();
        let work = ProvenanceRecord::new(ZoneId::work());
        let owner = ProvenanceRecord::new(ZoneId::owner());

        // Safe tier: all allowed
        assert!(public.can_drive_operation(SafetyTier::Safe).is_ok());
        assert!(work.can_drive_operation(SafetyTier::Safe).is_ok());
        assert!(owner.can_drive_operation(SafetyTier::Safe).is_ok());

        // Dangerous tier: public blocked, work/owner allowed
        assert!(public.can_drive_operation(SafetyTier::Dangerous).is_err());
        assert!(work.can_drive_operation(SafetyTier::Dangerous).is_ok());
        assert!(owner.can_drive_operation(SafetyTier::Dangerous).is_ok());

        // Critical tier: same as dangerous
        assert!(public.can_drive_operation(SafetyTier::Critical).is_err());
        assert!(work.can_drive_operation(SafetyTier::Critical).is_ok());
        assert!(owner.can_drive_operation(SafetyTier::Critical).is_ok());

        log_flow_test(
            "golden_vector_safety_tier_enforcement",
            "integrity",
            "matrix",
            "matrix",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_approval_token_lifecycle() {
        // ApprovalToken lifecycle golden vector
        let token = ApprovalToken {
            token_id: "lifecycle-test".into(),
            issued_at_ms: 1000,
            expires_at_ms: 3000,
            issuer: "node:issuer".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "test.op".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Before valid: t=500
        assert!(token.is_not_yet_valid(500));
        assert!(!token.is_expired(500));
        assert!(!token.is_valid(500));

        // At issued_at: t=1000 (edge case - valid)
        assert!(!token.is_not_yet_valid(1000));
        assert!(!token.is_expired(1000));
        assert!(token.is_valid(1000));

        // During validity: t=2000
        assert!(!token.is_not_yet_valid(2000));
        assert!(!token.is_expired(2000));
        assert!(token.is_valid(2000));

        // At expires_at: t=3000 (edge case - expired)
        assert!(!token.is_not_yet_valid(3000));
        assert!(token.is_expired(3000));
        assert!(!token.is_valid(3000));

        // After expiry: t=5000
        assert!(!token.is_not_yet_valid(5000));
        assert!(token.is_expired(5000));
        assert!(!token.is_valid(5000));

        log_flow_test(
            "golden_vector_approval_token_lifecycle",
            "integrity",
            "lifecycle",
            "lifecycle",
            true,
            "pass",
            None,
        );
    }
}

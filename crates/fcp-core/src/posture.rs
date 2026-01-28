//! Device posture attestation for FCP2 policy enforcement.
//!
//! This module provides:
//! - [`PostureAttestation`] - Signed device posture claims from a trusted verifier
//! - [`PostureAttribute`] - Individual posture attributes (OS version, disk encryption, etc.)
//! - [`PostureRequirement`] - Policy-level requirements for device posture
//!
//! # Overview
//!
//! Device Posture Attestation proves that a device meets certain security requirements
//! before allowing it to participate in sensitive operations. This is distinct from
//! [`NodeKeyAttestation`](fcp-tailscale) which binds node identity to keys.
//!
//! # Example
//!
//! ```rust
//! use fcp_core::{PostureAttestation, PostureAttributeKey, PostureRequirements};
//!
//! // Create posture requirements for a zone
//! let requirements = PostureRequirements::builder()
//!     .require_disk_encryption(true)
//!     .require_os_min_version("14.0")
//!     .build();
//!
//! // Verify an attestation meets requirements
//! // (attestation would come from a trusted verifier)
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::NodeId;
use crate::object::ObjectId;

// ─────────────────────────────────────────────────────────────────────────────
// Posture Attributes
// ─────────────────────────────────────────────────────────────────────────────

/// Individual posture attribute types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureAttributeKey {
    /// Operating system type (e.g., "macos", "windows", "linux").
    OsType,
    /// Operating system version (e.g., "14.2.1").
    OsVersion,
    /// Whether disk encryption is enabled.
    DiskEncryption,
    /// Whether firewall is enabled.
    FirewallEnabled,
    /// Whether screen lock is enabled.
    ScreenLockEnabled,
    /// Screen lock timeout in seconds.
    ScreenLockTimeout,
    /// Whether antivirus is installed and active.
    AntivirusActive,
    /// Whether the device is managed (MDM enrolled).
    DeviceManaged,
    /// Whether secure boot is enabled.
    SecureBootEnabled,
    /// Whether the device has a TPM/Secure Enclave.
    TpmPresent,
    /// Custom attribute (for extensibility).
    Custom(String),
}

impl PostureAttributeKey {
    /// Get the string representation of this key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::OsType => "os_type",
            Self::OsVersion => "os_version",
            Self::DiskEncryption => "disk_encryption",
            Self::FirewallEnabled => "firewall_enabled",
            Self::ScreenLockEnabled => "screen_lock_enabled",
            Self::ScreenLockTimeout => "screen_lock_timeout",
            Self::AntivirusActive => "antivirus_active",
            Self::DeviceManaged => "device_managed",
            Self::SecureBootEnabled => "secure_boot_enabled",
            Self::TpmPresent => "tpm_present",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// A posture attribute value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PostureAttributeValue {
    /// Boolean value (e.g., `disk_encryption`: true).
    Bool(bool),
    /// String value (e.g., `os_version`: "14.2.1").
    String(String),
    /// Numeric value (e.g., `screen_lock_timeout`: 300).
    Number(i64),
}

impl PostureAttributeValue {
    /// Get as boolean if this is a bool value.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as string if this is a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get as number if this is a numeric value.
    #[must_use]
    pub const fn as_number(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture Attestation
// ─────────────────────────────────────────────────────────────────────────────

/// Signed device posture attestation from a trusted verifier.
///
/// This attestation proves that a device has been verified to meet certain
/// posture requirements at a point in time. The attestation is signed by
/// a trusted posture verifier (e.g., MDM, endpoint agent, or Tailscale).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureAttestation {
    /// Schema identifier for this attestation format.
    pub schema: String,

    /// Unique identifier for this attestation.
    pub attestation_id: String,

    /// Node ID of the device being attested.
    pub node_id: NodeId,

    /// Posture attributes collected from the device.
    pub attributes: HashMap<PostureAttributeKey, PostureAttributeValue>,

    /// When this attestation was issued.
    pub issued_at: DateTime<Utc>,

    /// When this attestation expires.
    pub expires_at: DateTime<Utc>,

    /// Identity of the verifier that issued this attestation.
    pub verifier_id: String,

    /// Signature over the attestation payload (base64-encoded).
    pub signature: String,

    /// Key ID of the verifier key that signed this attestation.
    pub verifier_kid: String,
}

impl PostureAttestation {
    /// Schema identifier for FCP posture attestations.
    pub const SCHEMA: &'static str = "fcp.posture.v1";

    /// Check if this attestation has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// Check if this attestation is valid (not expired and has correct schema).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.schema == Self::SCHEMA
    }

    /// Check if this attestation is for the specified node.
    #[must_use]
    pub fn is_for_node(&self, node_id: &NodeId) -> bool {
        self.node_id == *node_id
    }

    /// Get an attribute value.
    #[must_use]
    pub fn get_attribute(&self, key: &PostureAttributeKey) -> Option<&PostureAttributeValue> {
        self.attributes.get(key)
    }

    /// Check if disk encryption is enabled according to this attestation.
    #[must_use]
    pub fn disk_encryption_enabled(&self) -> Option<bool> {
        self.get_attribute(&PostureAttributeKey::DiskEncryption)
            .and_then(PostureAttributeValue::as_bool)
    }

    /// Get the OS version from this attestation.
    #[must_use]
    pub fn os_version(&self) -> Option<&str> {
        self.get_attribute(&PostureAttributeKey::OsVersion)
            .and_then(PostureAttributeValue::as_str)
    }

    /// Get the OS type from this attestation.
    #[must_use]
    pub fn os_type(&self) -> Option<&str> {
        self.get_attribute(&PostureAttributeKey::OsType)
            .and_then(PostureAttributeValue::as_str)
    }

    /// Get the remaining validity duration.
    #[must_use]
    pub fn remaining_validity(&self) -> chrono::Duration {
        self.expires_at - Utc::now()
    }

    /// Generate an object ID for this attestation (content-addressed).
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId::from_unscoped_bytes(self.attestation_id.as_bytes())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture Requirements
// ─────────────────────────────────────────────────────────────────────────────

/// A single posture requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PostureRequirement {
    /// Require a boolean attribute to be true.
    RequireTrue {
        /// The attribute that must be true.
        attribute: PostureAttributeKey,
    },
    /// Require a boolean attribute to be false.
    RequireFalse {
        /// The attribute that must be false.
        attribute: PostureAttributeKey,
    },
    /// Require a string attribute to match exactly.
    RequireEqual {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// The expected value.
        value: String,
    },
    /// Require a string attribute to be in a list of allowed values.
    RequireOneOf {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Allowed values.
        values: Vec<String>,
    },
    /// Require a version attribute to be at least a minimum version.
    RequireMinVersion {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Minimum version (semver or simple numeric comparison).
        min_version: String,
    },
    /// Require a numeric attribute to be at least a minimum value.
    RequireMinValue {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Minimum value.
        min_value: i64,
    },
    /// Require a numeric attribute to be at most a maximum value.
    RequireMaxValue {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Maximum value.
        max_value: i64,
    },
}

impl PostureRequirement {
    /// Check if an attestation satisfies this requirement.
    #[must_use]
    pub fn is_satisfied_by(&self, attestation: &PostureAttestation) -> bool {
        match self {
            Self::RequireTrue { attribute } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_bool)
                .unwrap_or(false),

            Self::RequireFalse { attribute } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_bool)
                .is_none_or(|v| !v),

            Self::RequireEqual { attribute, value } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_str)
                .is_some_and(|v| v == value),

            Self::RequireOneOf { attribute, values } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_str)
                .is_some_and(|v| values.iter().any(|allowed| allowed == v)),

            Self::RequireMinVersion {
                attribute,
                min_version,
            } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_str)
                .is_some_and(|v| version_gte(v, min_version)),

            Self::RequireMinValue {
                attribute,
                min_value,
            } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_number)
                .is_some_and(|v| v >= *min_value),

            Self::RequireMaxValue {
                attribute,
                max_value,
            } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_number)
                .is_some_and(|v| v <= *max_value),
        }
    }

    /// Get the attribute this requirement applies to.
    #[must_use]
    pub const fn attribute(&self) -> &PostureAttributeKey {
        match self {
            Self::RequireTrue { attribute }
            | Self::RequireFalse { attribute }
            | Self::RequireEqual { attribute, .. }
            | Self::RequireOneOf { attribute, .. }
            | Self::RequireMinVersion { attribute, .. }
            | Self::RequireMinValue { attribute, .. }
            | Self::RequireMaxValue { attribute, .. } => attribute,
        }
    }
}

/// Collection of posture requirements for a zone policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostureRequirements {
    /// List of requirements that must all be satisfied.
    pub requirements: Vec<PostureRequirement>,

    /// Maximum age of attestation in seconds (default: 24 hours).
    #[serde(default = "default_max_attestation_age")]
    pub max_attestation_age_secs: u64,

    /// Allowed verifier IDs (empty means any verifier is allowed).
    #[serde(default)]
    pub allowed_verifiers: Vec<String>,
}

const fn default_max_attestation_age() -> u64 {
    86400 // 24 hours
}

impl PostureRequirements {
    /// Create a new builder for posture requirements.
    #[must_use]
    pub fn builder() -> PostureRequirementsBuilder {
        PostureRequirementsBuilder::default()
    }

    /// Check if an attestation satisfies all requirements.
    #[must_use]
    pub fn is_satisfied_by(&self, attestation: &PostureAttestation) -> PostureCheckResult {
        // Check attestation is valid
        if attestation.is_expired() {
            return PostureCheckResult::AttestationExpired;
        }

        // Check attestation age
        let age_secs = (Utc::now() - attestation.issued_at).num_seconds();
        let max_age = i64::try_from(self.max_attestation_age_secs).unwrap_or(i64::MAX);
        if age_secs < 0 || age_secs > max_age {
            return PostureCheckResult::AttestationTooOld;
        }

        // Check verifier is allowed
        if !self.allowed_verifiers.is_empty()
            && !self.allowed_verifiers.contains(&attestation.verifier_id)
        {
            return PostureCheckResult::VerifierNotAllowed;
        }

        // Check all requirements
        for requirement in &self.requirements {
            if !requirement.is_satisfied_by(attestation) {
                return PostureCheckResult::RequirementNotMet {
                    attribute: requirement.attribute().clone(),
                };
            }
        }

        PostureCheckResult::Satisfied
    }

    /// Check if this requirements set is empty (no requirements).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }
}

/// Result of checking posture requirements against an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureCheckResult {
    /// All requirements are satisfied.
    Satisfied,
    /// Attestation has expired.
    AttestationExpired,
    /// Attestation is too old.
    AttestationTooOld,
    /// Verifier is not in the allowed list.
    VerifierNotAllowed,
    /// A specific requirement was not met.
    RequirementNotMet {
        /// The attribute that failed.
        attribute: PostureAttributeKey,
    },
}

impl PostureCheckResult {
    /// Check if the result indicates satisfaction.
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`PostureRequirements`].
#[derive(Debug, Default)]
pub struct PostureRequirementsBuilder {
    requirements: Vec<PostureRequirement>,
    max_attestation_age_secs: Option<u64>,
    allowed_verifiers: Vec<String>,
}

impl PostureRequirementsBuilder {
    /// Require disk encryption to be enabled.
    #[must_use]
    pub fn require_disk_encryption(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::DiskEncryption,
            });
        }
        self
    }

    /// Require firewall to be enabled.
    #[must_use]
    pub fn require_firewall(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::FirewallEnabled,
            });
        }
        self
    }

    /// Require screen lock to be enabled.
    #[must_use]
    pub fn require_screen_lock(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::ScreenLockEnabled,
            });
        }
        self
    }

    /// Require a minimum OS version.
    #[must_use]
    pub fn require_os_min_version(mut self, min_version: impl Into<String>) -> Self {
        self.requirements
            .push(PostureRequirement::RequireMinVersion {
                attribute: PostureAttributeKey::OsVersion,
                min_version: min_version.into(),
            });
        self
    }

    /// Require a specific OS type.
    #[must_use]
    pub fn require_os_type(mut self, os_type: impl Into<String>) -> Self {
        self.requirements.push(PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::OsType,
            value: os_type.into(),
        });
        self
    }

    /// Require the OS type to be one of the given types.
    #[must_use]
    pub fn require_os_type_one_of(mut self, os_types: Vec<String>) -> Self {
        self.requirements.push(PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: os_types,
        });
        self
    }

    /// Require device to be managed (MDM enrolled).
    #[must_use]
    pub fn require_device_managed(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::DeviceManaged,
            });
        }
        self
    }

    /// Require secure boot to be enabled.
    #[must_use]
    pub fn require_secure_boot(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::SecureBootEnabled,
            });
        }
        self
    }

    /// Require TPM/Secure Enclave to be present.
    #[must_use]
    pub fn require_tpm(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::TpmPresent,
            });
        }
        self
    }

    /// Add a custom requirement.
    #[must_use]
    pub fn require(mut self, requirement: PostureRequirement) -> Self {
        self.requirements.push(requirement);
        self
    }

    /// Set maximum attestation age in seconds.
    #[must_use]
    pub const fn max_attestation_age_secs(mut self, secs: u64) -> Self {
        self.max_attestation_age_secs = Some(secs);
        self
    }

    /// Add an allowed verifier.
    #[must_use]
    pub fn allow_verifier(mut self, verifier_id: impl Into<String>) -> Self {
        self.allowed_verifiers.push(verifier_id.into());
        self
    }

    /// Build the requirements.
    #[must_use]
    pub fn build(self) -> PostureRequirements {
        PostureRequirements {
            requirements: self.requirements,
            max_attestation_age_secs: self.max_attestation_age_secs.unwrap_or(86400),
            allowed_verifiers: self.allowed_verifiers,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Simple version comparison (>=).
///
/// Supports semver-style versions (e.g., "14.2.1" >= "14.0.0").
fn version_gte(actual: &str, required: &str) -> bool {
    let actual_parts: Vec<u64> = actual.split('.').filter_map(|s| s.parse().ok()).collect();
    let required_parts: Vec<u64> = required.split('.').filter_map(|s| s.parse().ok()).collect();

    for i in 0..required_parts.len().max(actual_parts.len()) {
        let a = actual_parts.get(i).copied().unwrap_or(0);
        let r = required_parts.get(i).copied().unwrap_or(0);
        if a > r {
            return true;
        }
        if a < r {
            return false;
        }
    }
    true // Equal versions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_attestation() -> PostureAttestation {
        let mut attributes = HashMap::new();
        attributes.insert(
            PostureAttributeKey::OsType,
            PostureAttributeValue::String("macos".to_string()),
        );
        attributes.insert(
            PostureAttributeKey::OsVersion,
            PostureAttributeValue::String("14.2.1".to_string()),
        );
        attributes.insert(
            PostureAttributeKey::DiskEncryption,
            PostureAttributeValue::Bool(true),
        );
        attributes.insert(
            PostureAttributeKey::FirewallEnabled,
            PostureAttributeValue::Bool(true),
        );
        attributes.insert(
            PostureAttributeKey::ScreenLockEnabled,
            PostureAttributeValue::Bool(true),
        );
        attributes.insert(
            PostureAttributeKey::ScreenLockTimeout,
            PostureAttributeValue::Number(300),
        );

        PostureAttestation {
            schema: PostureAttestation::SCHEMA.to_string(),
            attestation_id: "att-12345".to_string(),
            node_id: NodeId::new("node-test"),
            attributes,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            verifier_id: "verifier-1".to_string(),
            signature: "signature".to_string(),
            verifier_kid: "kid-1".to_string(),
        }
    }

    #[test]
    fn test_attestation_is_valid() {
        let attestation = create_test_attestation();
        assert!(attestation.is_valid());
        assert!(!attestation.is_expired());
    }

    #[test]
    fn test_attestation_expired() {
        let mut attestation = create_test_attestation();
        attestation.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(attestation.is_expired());
        assert!(!attestation.is_valid());
    }

    #[test]
    fn test_attestation_attribute_access() {
        let attestation = create_test_attestation();
        assert_eq!(attestation.os_type(), Some("macos"));
        assert_eq!(attestation.os_version(), Some("14.2.1"));
        assert_eq!(attestation.disk_encryption_enabled(), Some(true));
    }

    #[test]
    fn test_requirement_require_true() {
        let attestation = create_test_attestation();

        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::DiskEncryption,
        };
        assert!(req.is_satisfied_by(&attestation));

        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::AntivirusActive,
        };
        assert!(!req.is_satisfied_by(&attestation));
    }

    #[test]
    fn test_requirement_min_version() {
        let attestation = create_test_attestation();

        let req = PostureRequirement::RequireMinVersion {
            attribute: PostureAttributeKey::OsVersion,
            min_version: "14.0.0".to_string(),
        };
        assert!(req.is_satisfied_by(&attestation));

        let req = PostureRequirement::RequireMinVersion {
            attribute: PostureAttributeKey::OsVersion,
            min_version: "15.0.0".to_string(),
        };
        assert!(!req.is_satisfied_by(&attestation));
    }

    #[test]
    fn test_requirement_one_of() {
        let attestation = create_test_attestation();

        let req = PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec!["macos".to_string(), "windows".to_string()],
        };
        assert!(req.is_satisfied_by(&attestation));

        let req = PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec!["linux".to_string()],
        };
        assert!(!req.is_satisfied_by(&attestation));
    }

    #[test]
    fn test_requirements_builder() {
        let requirements = PostureRequirements::builder()
            .require_disk_encryption(true)
            .require_os_min_version("14.0")
            .require_os_type_one_of(vec!["macos".to_string(), "windows".to_string()])
            .max_attestation_age_secs(3600)
            .allow_verifier("verifier-1")
            .build();

        assert_eq!(requirements.requirements.len(), 3);
        assert_eq!(requirements.max_attestation_age_secs, 3600);
        assert_eq!(requirements.allowed_verifiers, vec!["verifier-1"]);

        let attestation = create_test_attestation();
        assert!(requirements.is_satisfied_by(&attestation).is_satisfied());
    }

    #[test]
    fn test_requirements_verifier_check() {
        let requirements = PostureRequirements::builder()
            .allow_verifier("trusted-verifier")
            .build();

        let attestation = create_test_attestation();
        assert_eq!(
            requirements.is_satisfied_by(&attestation),
            PostureCheckResult::VerifierNotAllowed
        );
    }

    #[test]
    fn test_version_comparison() {
        assert!(version_gte("14.2.1", "14.0.0"));
        assert!(version_gte("14.2.1", "14.2.1"));
        assert!(version_gte("15.0.0", "14.2.1"));
        assert!(!version_gte("14.0.0", "14.2.1"));
        assert!(!version_gte("13.0.0", "14.0.0"));
        assert!(version_gte("14", "14.0.0"));
        assert!(version_gte("14.2", "14.0"));
    }
}

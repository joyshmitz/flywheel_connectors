//! Install command types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for connector installation,
//! enabling automation and CI/CD integration.

use serde::{Deserialize, Serialize};

/// Installation result output record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallOutput {
    /// Connector ID that was installed.
    pub connector_id: String,

    /// Version that was installed.
    pub version: String,

    /// Target platform/arch.
    pub target: String,

    /// Zone where connector was installed.
    pub zone_id: String,

    /// Manifest hash (sha256:...).
    pub manifest_hash: String,

    /// Binary hash (sha256:...).
    pub binary_hash: String,

    /// Object ID of the manifest in the mesh store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_object_id: Option<String>,

    /// Object ID of the binary in the mesh store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_object_id: Option<String>,

    /// Verification details.
    pub verification: VerificationDetails,

    /// Installation timestamp (Unix seconds).
    pub installed_at: u64,

    /// ISO-8601 formatted timestamp for human readability.
    pub installed_at_iso: String,
}

/// Verification details for an installation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    /// Whether publisher signature was verified.
    pub publisher_signature_verified: bool,

    /// Whether registry signature was verified.
    pub registry_signature_verified: bool,

    /// Number of publisher signatures that passed threshold.
    pub publisher_signatures_valid: u8,

    /// Required publisher signature threshold.
    pub publisher_threshold: u8,

    /// Whether supply chain policy was satisfied.
    pub supply_chain_policy_satisfied: bool,

    /// Whether capability ceiling was respected.
    pub capability_ceiling_respected: bool,

    /// List of verified attestation types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_attestations: Vec<String>,

    /// SLSA level if verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slsa_level: Option<u8>,
}

impl Default for VerificationDetails {
    fn default() -> Self {
        Self {
            publisher_signature_verified: false,
            registry_signature_verified: false,
            publisher_signatures_valid: 0,
            publisher_threshold: 0,
            supply_chain_policy_satisfied: true,
            capability_ceiling_respected: true,
            verified_attestations: Vec::new(),
            slsa_level: None,
        }
    }
}

/// Install error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallError {
    /// Error code (FCP-XXXX).
    pub code: String,

    /// Human-readable error message.
    pub message: String,

    /// Recovery hints for operators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,

    /// Connector ID if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,

    /// Version if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for InstallError {}

#[allow(dead_code)] // Error constructors for future verification features
impl InstallError {
    /// Create a "connector not found" error.
    #[must_use]
    pub fn connector_not_found(connector_id: &str) -> Self {
        Self {
            code: "FCP-4010".to_string(),
            message: format!("Connector '{connector_id}' not found in registry"),
            hints: vec![
                "Verify the connector ID is correct".to_string(),
                "Check if the connector is published to the registry".to_string(),
                "Run 'fcp search <query>' to find available connectors".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "version not found" error.
    #[must_use]
    pub fn version_not_found(connector_id: &str, version: &str) -> Self {
        Self {
            code: "FCP-4011".to_string(),
            message: format!("Version '{version}' not found for connector '{connector_id}'"),
            hints: vec![
                "Verify the version string is correct".to_string(),
                "Run 'fcp info <connector>' to see available versions".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: Some(version.to_string()),
        }
    }

    /// Create a "signature verification failed" error.
    #[must_use]
    pub fn signature_verification_failed(connector_id: &str, reason: &str) -> Self {
        Self {
            code: "FCP-4012".to_string(),
            message: format!("Signature verification failed for '{connector_id}': {reason}"),
            hints: vec![
                "The connector may have been tampered with".to_string(),
                "Check if your trust policy keys are up to date".to_string(),
                "Contact the connector publisher if this persists".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "binary checksum mismatch" error.
    #[must_use]
    pub fn binary_checksum_mismatch(connector_id: &str, expected: &str, actual: &str) -> Self {
        Self {
            code: "FCP-4013".to_string(),
            message: format!(
                "Binary checksum mismatch for '{connector_id}': expected {expected}, got {actual}"
            ),
            hints: vec![
                "The binary may have been corrupted or tampered with".to_string(),
                "Try re-downloading the connector".to_string(),
                "Contact the connector publisher if this persists".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "capability ceiling violation" error.
    #[must_use]
    pub fn capability_ceiling_violation(connector_id: &str, capability: &str) -> Self {
        Self {
            code: "FCP-4014".to_string(),
            message: format!(
                "Connector '{connector_id}' requires capability '{capability}' which exceeds zone ceiling"
            ),
            hints: vec![
                "The connector requires capabilities not allowed in this zone".to_string(),
                "Check zone policy capability_ceiling settings".to_string(),
                "Contact zone administrator to expand capability ceiling".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "supply chain policy violation" error.
    #[must_use]
    pub fn supply_chain_policy_violation(connector_id: &str, reason: &str) -> Self {
        Self {
            code: "FCP-4015".to_string(),
            message: format!("Supply chain policy violation for '{connector_id}': {reason}"),
            hints: vec![
                "The connector does not meet supply chain requirements".to_string(),
                "Check if transparency log or attestations are required".to_string(),
                "Use --skip-supply-chain-check to bypass (not recommended)".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "target mismatch" error.
    #[must_use]
    pub fn target_mismatch(connector_id: &str, expected: &str, actual: &str) -> Self {
        Self {
            code: "FCP-4016".to_string(),
            message: format!(
                "Target mismatch for '{connector_id}': expected {expected}, got {actual}"
            ),
            hints: vec![
                format!("The connector binary is built for {actual}"),
                format!("Your system requires {expected}"),
                "Check if a compatible binary is available".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "zone not found" error.
    #[must_use]
    pub fn zone_not_found(zone_id: &str) -> Self {
        Self {
            code: "FCP-4001".to_string(),
            message: format!("Zone '{zone_id}' not found or not accessible"),
            hints: vec![
                "Verify the zone ID is correct".to_string(),
                "Check if you have access to this zone".to_string(),
                "Run 'fcp doctor --zone <zone>' to diagnose".to_string(),
            ],
            connector_id: None,
            version: None,
        }
    }

    /// Create a "mirror failed" error.
    #[must_use]
    pub fn mirror_failed(connector_id: &str, reason: &str) -> Self {
        Self {
            code: "FCP-5020".to_string(),
            message: format!("Failed to mirror connector '{connector_id}' to mesh store: {reason}"),
            hints: vec![
                "Check mesh node connectivity".to_string(),
                "Verify object store is writable".to_string(),
                "Run 'fcp doctor --zone <zone>' to check storage".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }
}

/// Installation progress event for streaming output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProgress {
    /// Current phase of installation.
    pub phase: InstallPhase,

    /// Human-readable message.
    pub message: String,

    /// Progress percentage (0-100) if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percent: Option<u8>,
}

/// Installation phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    /// Fetching manifest from registry.
    FetchingManifest,
    /// Verifying manifest signatures.
    VerifyingManifest,
    /// Fetching binary from registry.
    FetchingBinary,
    /// Verifying binary checksum.
    VerifyingBinary,
    /// Checking supply chain policy.
    CheckingSupplyChain,
    /// Mirroring to mesh store.
    Mirroring,
    /// Emitting audit event.
    EmittingAudit,
    /// Installation complete.
    Complete,
}

impl InstallPhase {
    /// Get human-readable label for this phase.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FetchingManifest => "Fetching manifest",
            Self::VerifyingManifest => "Verifying manifest",
            Self::FetchingBinary => "Fetching binary",
            Self::VerifyingBinary => "Verifying binary",
            Self::CheckingSupplyChain => "Checking supply chain",
            Self::Mirroring => "Mirroring to store",
            Self::EmittingAudit => "Emitting audit event",
            Self::Complete => "Complete",
        }
    }

    /// Get ANSI color code for this phase.
    #[must_use]
    pub const fn color(self) -> &'static str {
        match self {
            Self::Complete => "\x1b[32m", // Green
            _ => "\x1b[36m",              // Cyan
        }
    }

    /// Get symbol for this phase.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::FetchingManifest | Self::FetchingBinary => "↓",
            Self::VerifyingManifest | Self::VerifyingBinary => "✓",
            Self::CheckingSupplyChain => "⛓",
            Self::Mirroring => "→",
            Self::EmittingAudit => "📝",
            Self::Complete => "✔",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_output_json_snapshot() {
        let output = InstallOutput {
            connector_id: "fcp.telegram:base:v1".to_string(),
            version: "1.0.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            zone_id: "z:work".to_string(),
            manifest_hash: "sha256:abc123".to_string(),
            binary_hash: "sha256:def456".to_string(),
            manifest_object_id: Some("obj:manifest:123".to_string()),
            binary_object_id: Some("obj:binary:456".to_string()),
            verification: VerificationDetails {
                publisher_signature_verified: true,
                registry_signature_verified: true,
                publisher_signatures_valid: 2,
                publisher_threshold: 2,
                supply_chain_policy_satisfied: true,
                capability_ceiling_respected: true,
                verified_attestations: vec!["in-toto".to_string()],
                slsa_level: Some(3),
            },
            installed_at: 1_700_000_000,
            installed_at_iso: "2023-11-14T22:13:20Z".to_string(),
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("\"connector_id\": \"fcp.telegram:base:v1\""));
        assert!(json.contains("\"publisher_signature_verified\": true"));
        assert!(json.contains("\"slsa_level\": 3"));

        // Verify roundtrip
        let parsed: InstallOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "fcp.telegram:base:v1");
        assert_eq!(parsed.verification.slsa_level, Some(3));
    }

    #[test]
    fn install_error_connector_not_found() {
        let err = InstallError::connector_not_found("fcp.unknown:base:v1");
        assert_eq!(err.code, "FCP-4010");
        assert!(err.message.contains("fcp.unknown:base:v1"));
        assert!(!err.hints.is_empty());
    }

    #[test]
    fn install_error_signature_verification_failed() {
        let err = InstallError::signature_verification_failed(
            "fcp.telegram:base:v1",
            "invalid signature",
        );
        assert_eq!(err.code, "FCP-4012");
        assert!(err.message.contains("invalid signature"));
    }

    #[test]
    fn install_phase_labels() {
        assert_eq!(InstallPhase::FetchingManifest.label(), "Fetching manifest");
        assert_eq!(InstallPhase::Complete.label(), "Complete");
    }

    #[test]
    fn verification_details_default() {
        let details = VerificationDetails::default();
        assert!(!details.publisher_signature_verified);
        assert!(details.supply_chain_policy_satisfied);
        assert!(details.verified_attestations.is_empty());
    }
}

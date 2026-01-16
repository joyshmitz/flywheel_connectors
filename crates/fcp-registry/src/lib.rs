//! Registry verification and mirroring for FCP2 connectors.
//!
//! This crate validates connector manifests and binaries against supply-chain
//! policies and mirrors verified bundles into the object store.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chrono::Utc;
use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_core::{
    CapabilityId, ObjectHeader, ObjectId, ObjectIdKey, Provenance, RetentionClass, StorageMeta,
    StoredObject, ZoneId, ZonePolicyObject,
};
use fcp_crypto::ed25519::{Ed25519Signature, Ed25519VerifyingKey};
use fcp_manifest::{
    AttestationType, Base64Bytes, ConnectorManifest, ManifestError, SignatureEntry,
    SignaturesSection,
};
use fcp_store::{ObjectStore, ObjectStoreError};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MANIFEST_SIGNATURE_CONTEXT: &[u8] = b"fcp.registry.manifest.v1";

/// Registry verification failures.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("manifest parse failed: {0}")]
    ManifestParse(#[from] ManifestError),
    #[error("signature section missing from manifest")]
    MissingSignatures,
    #[error("no trusted key for kid `{kid}`")]
    UnknownKid { kid: String },
    #[error("signature verification failed for kid `{kid}`")]
    SignatureInvalid { kid: String },
    #[error("publisher signature threshold unmet (required {required}, valid {valid})")]
    PublisherThresholdUnmet { required: u8, valid: u8 },
    #[error("registry signature required but missing or invalid")]
    RegistrySignatureRequired,
    #[error("target mismatch (expected {expected}, got {found})")]
    TargetMismatch { expected: String, found: String },
    #[error("capability `{capability}` exceeds zone ceiling")]
    CapabilityCeilingViolation { capability: String },
    #[error("missing transparency log entry in manifest")]
    TransparencyLogMissing,
    #[error("transparency log evidence missing")]
    TransparencyEvidenceMissing,
    #[error("required attestation `{attestation}` not present")]
    RequiredAttestationMissing { attestation: String },
    #[error("attestation evidence missing")]
    AttestationEvidenceMissing,
    #[error("attestation does not meet minimum SLSA level {required}")]
    SlsaLevelInsufficient { required: u8 },
    #[error("attestation builder `{builder}` not in trusted builders list")]
    UntrustedBuilder { builder: String },
    #[error("manifest signing bytes serialization failed: {0}")]
    SigningBytes(#[from] SerializationError),
    #[error("signature bytes malformed")]
    SignatureBytes,
    #[error("object store failure: {0}")]
    ObjectStore(#[from] ObjectStoreError),
}

/// Connector bundle fetched from a registry.
#[derive(Debug, Clone)]
pub struct ConnectorBundle {
    pub manifest_toml: String,
    pub binary: Vec<u8>,
    pub target: ConnectorTarget,
}

/// Operating system + CPU architecture pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorTarget {
    pub os: String,
    pub arch: String,
}

impl ConnectorTarget {
    /// Build the target from the current process environment.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        }
    }

    #[must_use]
    pub fn as_string(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }
}

/// Trust roots used for registry verification.
#[derive(Debug, Clone, Default)]
pub struct RegistryTrustPolicy {
    pub publisher_keys: HashMap<String, Ed25519VerifyingKey>,
    pub registry_keys: HashMap<String, Ed25519VerifyingKey>,
    pub require_registry_signature: bool,
}

/// Evidence from external supply-chain verification.
#[derive(Debug, Clone, Default)]
pub struct SupplyChainEvidence {
    pub transparency_log_present: bool,
    pub attestations: Vec<AttestationEvidence>,
}

/// Attestation metadata verified by an external system.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub attestation_type: AttestationType,
    pub slsa_level: Option<u8>,
    pub builder_id: Option<String>,
}

/// Verified connector bundle metadata.
#[derive(Debug, Clone)]
pub struct VerifiedConnectorBundle {
    pub manifest: ConnectorManifest,
    pub manifest_hash: String,
    pub binary_hash: String,
    pub target: ConnectorTarget,
}

/// Minimal structured report for audit/logging sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryVerificationReport {
    pub connector_id: String,
    pub manifest_hash: String,
    pub binary_hash: String,
    pub target: ConnectorTarget,
    pub verified_at: u64,
    pub outcome: String,
}

impl VerifiedConnectorBundle {
    #[must_use]
    pub fn report(&self, outcome: &str) -> RegistryVerificationReport {
        let verified_at = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        RegistryVerificationReport {
            connector_id: self.manifest.connector.id.to_string(),
            manifest_hash: self.manifest_hash.clone(),
            binary_hash: self.binary_hash.clone(),
            target: self.target.clone(),
            verified_at,
            outcome: outcome.to_string(),
        }
    }
}

/// Mirroring outcome (object ids + hashes).
#[derive(Debug, Clone)]
pub struct MirrorResult {
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub manifest_hash: String,
    pub binary_hash: String,
}

/// Registry verifier and mirroring helper.
#[derive(Debug, Clone)]
pub struct RegistryVerifier {
    trust_policy: RegistryTrustPolicy,
}

impl RegistryVerifier {
    #[must_use]
    pub const fn new(trust_policy: RegistryTrustPolicy) -> Self {
        Self { trust_policy }
    }

    /// Verify a registry bundle against trust roots, policy, and target.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if verification fails.
    pub fn verify_bundle(
        &self,
        bundle: &ConnectorBundle,
        zone_policy: Option<&ZonePolicyObject>,
        supply_chain: Option<&SupplyChainEvidence>,
        expected_target: Option<&ConnectorTarget>,
    ) -> Result<VerifiedConnectorBundle, RegistryError> {
        let manifest = ConnectorManifest::parse_str(&bundle.manifest_toml)?;

        if let Some(expected) = expected_target {
            if &bundle.target != expected {
                return Err(RegistryError::TargetMismatch {
                    expected: expected.as_string(),
                    found: bundle.target.as_string(),
                });
            }
        }

        let binary_hash = hash_bytes(&bundle.binary);
        let manifest_hash = hash_bytes(bundle.manifest_toml.as_bytes());
        let signing_bytes = manifest_signing_bytes(&manifest)?;

        let sig_section = manifest
            .signatures
            .as_ref()
            .ok_or(RegistryError::MissingSignatures)?;

        let publisher_ok = verify_publishers(
            &self.trust_policy,
            sig_section,
            &signing_bytes,
            &binary_hash,
        )?;
        let registry_ok = verify_registry(
            &self.trust_policy,
            sig_section,
            &signing_bytes,
            &binary_hash,
        )?;

        if self.trust_policy.require_registry_signature && !registry_ok {
            return Err(RegistryError::RegistrySignatureRequired);
        }

        if !publisher_ok && !registry_ok {
            return Err(RegistryError::RegistrySignatureRequired);
        }

        enforce_capability_ceiling(zone_policy, &manifest)?;
        enforce_supply_chain_policy(&manifest, supply_chain)?;

        Ok(VerifiedConnectorBundle {
            manifest,
            manifest_hash,
            binary_hash,
            target: bundle.target.clone(),
        })
    }

    /// Mirror a verified bundle into the object store as pinned objects.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if object storage fails.
    pub async fn mirror_bundle(
        &self,
        verified: &VerifiedConnectorBundle,
        bundle: &ConnectorBundle,
        zone_id: ZoneId,
        object_id_key: &ObjectIdKey,
        store: &dyn ObjectStore,
    ) -> Result<MirrorResult, RegistryError> {
        let manifest_obj = ConnectorManifestObject {
            manifest_toml: bundle.manifest_toml.clone(),
            manifest_hash: verified.manifest_hash.clone(),
        };
        let binary_obj = ConnectorBinaryObject {
            target: verified.target.clone(),
            binary_hash: verified.binary_hash.clone(),
            binary: bundle.binary.clone(),
        };

        let manifest_schema =
            SchemaId::new("fcp.registry", "ConnectorManifest", Version::new(1, 0, 0));
        let binary_schema = SchemaId::new("fcp.registry", "ConnectorBinary", Version::new(1, 0, 0));

        let manifest_body = CanonicalSerializer::serialize(&manifest_obj, &manifest_schema)?;
        let binary_body = CanonicalSerializer::serialize(&binary_obj, &binary_schema)?;

        let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        let provenance = Provenance::new(zone_id.clone());

        let manifest_header = ObjectHeader {
            schema: manifest_schema,
            zone_id: zone_id.clone(),
            created_at: now,
            provenance: provenance.clone(),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let manifest_object_id =
            StoredObject::derive_id(&manifest_header, &manifest_body, object_id_key)?;
        let manifest_record = StoredObject {
            object_id: manifest_object_id,
            header: manifest_header,
            body: manifest_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        let binary_header = ObjectHeader {
            schema: binary_schema,
            zone_id,
            created_at: now,
            provenance,
            refs: vec![manifest_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let binary_object_id =
            StoredObject::derive_id(&binary_header, &binary_body, object_id_key)?;
        let binary_record = StoredObject {
            object_id: binary_object_id,
            header: binary_header,
            body: binary_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        store.put(manifest_record).await?;
        store.put(binary_record).await?;

        Ok(MirrorResult {
            manifest_object_id,
            binary_object_id,
            manifest_hash: verified.manifest_hash.clone(),
            binary_hash: verified.binary_hash.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectorManifestObject {
    manifest_toml: String,
    manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectorBinaryObject {
    target: ConnectorTarget,
    binary_hash: String,
    binary: Vec<u8>,
}

fn manifest_signing_bytes(manifest: &ConnectorManifest) -> Result<Vec<u8>, RegistryError> {
    let mut value = serde_json::to_value(manifest).map_err(|_| RegistryError::SignatureBytes)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signatures");
    }
    let schema = SchemaId::new("fcp.registry", "ManifestSigningView", Version::new(1, 0, 0));
    Ok(CanonicalSerializer::serialize(&value, &schema)?)
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

fn verify_publishers(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> Result<bool, RegistryError> {
    if sigs.publisher_signatures.is_empty() {
        return Ok(false);
    }

    let required = sigs.publisher_threshold.map_or(0, |t| t.k);
    let mut valid = 0u8;

    for entry in &sigs.publisher_signatures {
        if verify_signature_entry(trust, entry, signing_bytes, binary_hash, true)? {
            valid = valid.saturating_add(1);
        }
    }

    if required > 0 && valid < required {
        return Err(RegistryError::PublisherThresholdUnmet { required, valid });
    }

    Ok(valid > 0)
}

fn verify_registry(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> Result<bool, RegistryError> {
    let Some(entry) = sigs.registry_signature.as_ref() else {
        return Ok(false);
    };

    verify_signature_entry(trust, entry, signing_bytes, binary_hash, false)
}

fn verify_signature_entry(
    trust: &RegistryTrustPolicy,
    entry: &SignatureEntry,
    signing_bytes: &[u8],
    binary_hash: &str,
    publisher: bool,
) -> Result<bool, RegistryError> {
    let key = if publisher {
        trust.publisher_keys.get(&entry.kid)
    } else {
        trust.registry_keys.get(&entry.kid)
    }
    .ok_or_else(|| RegistryError::UnknownKid {
        kid: entry.kid.clone(),
    })?;

    let signature = signature_from_entry(&entry.sig)?;
    let message = signature_message(signing_bytes, binary_hash);

    key.verify_with_context(MANIFEST_SIGNATURE_CONTEXT, &message, &signature)
        .map_err(|_| RegistryError::SignatureInvalid {
            kid: entry.kid.clone(),
        })?;

    Ok(true)
}

fn signature_from_entry(sig: &Base64Bytes) -> Result<Ed25519Signature, RegistryError> {
    Ed25519Signature::try_from_slice(sig.as_bytes()).map_err(|_| RegistryError::SignatureBytes)
}

fn signature_message(signing_bytes: &[u8], binary_hash: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(signing_bytes.len() + binary_hash.len());
    message.extend_from_slice(signing_bytes);
    message.extend_from_slice(binary_hash.as_bytes());
    message
}

fn enforce_capability_ceiling(
    zone_policy: Option<&ZonePolicyObject>,
    manifest: &ConnectorManifest,
) -> Result<(), RegistryError> {
    let Some(policy) = zone_policy else {
        return Ok(());
    };

    if policy.capability_ceiling.is_empty() {
        return Ok(());
    }

    let mut caps: HashSet<CapabilityId> = HashSet::new();
    caps.extend(manifest.capabilities.required.iter().cloned());
    caps.extend(manifest.capabilities.optional.iter().cloned());
    for op in manifest.provides.operations.values() {
        caps.insert(op.capability.clone());
    }

    for cap in caps {
        if !policy.capability_ceiling.contains(&cap) {
            return Err(RegistryError::CapabilityCeilingViolation {
                capability: cap.as_str().to_string(),
            });
        }
    }

    Ok(())
}

fn enforce_supply_chain_policy(
    manifest: &ConnectorManifest,
    evidence: Option<&SupplyChainEvidence>,
) -> Result<(), RegistryError> {
    let Some(policy) = manifest.policy.as_ref() else {
        return Ok(());
    };

    if policy.require_transparency_log {
        let entry_present = manifest
            .signatures
            .as_ref()
            .and_then(|sig| sig.transparency_log_entry.as_ref())
            .is_some();
        if !entry_present {
            return Err(RegistryError::TransparencyLogMissing);
        }
        let evidence = evidence.ok_or(RegistryError::TransparencyEvidenceMissing)?;
        if !evidence.transparency_log_present {
            return Err(RegistryError::TransparencyEvidenceMissing);
        }
    }

    if !policy.require_attestation_types.is_empty() {
        let evidence = evidence.ok_or(RegistryError::AttestationEvidenceMissing)?;
        for required in &policy.require_attestation_types {
            if !evidence
                .attestations
                .iter()
                .any(|att| &att.attestation_type == required)
            {
                return Err(RegistryError::RequiredAttestationMissing {
                    attestation: attestation_label(*required).to_string(),
                });
            }
        }
    }

    if let Some(required_level) = policy.min_slsa_level {
        let evidence = evidence.ok_or(RegistryError::AttestationEvidenceMissing)?;
        let meets_level = evidence
            .attestations
            .iter()
            .any(|att| att.slsa_level.is_some_and(|level| level >= required_level));
        if !meets_level {
            return Err(RegistryError::SlsaLevelInsufficient {
                required: required_level,
            });
        }
    }

    if !policy.trusted_builders.is_empty() {
        let evidence = evidence.ok_or(RegistryError::AttestationEvidenceMissing)?;
        for attestation in &evidence.attestations {
            if let Some(builder) = attestation.builder_id.as_ref() {
                if !policy.trusted_builders.iter().any(|b| b == builder) {
                    return Err(RegistryError::UntrustedBuilder {
                        builder: builder.clone(),
                    });
                }
            }
        }
    }

    Ok(())
}

fn attestation_label(attestation: AttestationType) -> &'static str {
    match attestation {
        AttestationType::InToto => "in-toto",
        AttestationType::ReproducibleBuild => "reproducible-build",
        AttestationType::CodeReview => "code-review",
    }
}

#[async_trait]
pub trait RegistrySource: Send + Sync {
    async fn fetch_bundle(&self, connector_id: &str) -> Result<ConnectorBundle, RegistryError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::Utc;
    use fcp_core::{DecisionReceiptPolicy, ZoneTransportPolicy};
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::PolicySection;
    use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig};
    use serde_json::json;
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;
    use uuid::Uuid;

    const PLACEHOLDER_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

    #[derive(Default)]
    struct RegistryLogData {
        connector_id: Option<String>,
        version: Option<String>,
        manifest_hash: Option<String>,
        binary_hash: Option<String>,
        target: Option<String>,
        reason_code: Option<String>,
        details: Option<serde_json::Value>,
    }

    fn run_registry_test<F, Fut>(
        test_name: &str,
        phase: &str,
        operation: &str,
        assertions: u32,
        f: F,
    ) where
        F: FnOnce() -> Fut + panic::UnwindSafe,
        Fut: std::future::Future<Output = RegistryLogData>,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime");
            rt.block_on(f())
        }));
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let (passed, failed, outcome, data) = match &result {
            Ok(data) => (assertions, 0, "pass", Some(data)),
            Err(_) => (0, assertions, "fail", None),
        };

        let log = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": test_name,
            "module": "fcp-registry",
            "phase": phase,
            "operation": operation,
            "correlation_id": Uuid::new_v4().to_string(),
            "result": outcome,
            "duration_ms": duration_ms,
            "connector_id": data.and_then(|d| d.connector_id.clone()),
            "version": data.and_then(|d| d.version.clone()),
            "manifest_hash": data.and_then(|d| d.manifest_hash.clone()),
            "binary_hash": data.and_then(|d| d.binary_hash.clone()),
            "target": data.and_then(|d| d.target.clone()),
            "reason_code": data.and_then(|d| d.reason_code.clone()),
            "details": data.and_then(|d| d.details.clone()),
            "assertions": {
                "passed": passed,
                "failed": failed
            }
        });
        println!("{log}");

        if let Err(payload) = result {
            panic::resume_unwind(payload);
        }
    }

    fn minimal_manifest() -> ConnectorManifest {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
        ConnectorManifest::parse_str_unchecked(raw).expect("manifest parse")
    }

    fn base_manifest_toml() -> String {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
        let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("manifest");
        let hash = unchecked.compute_interface_hash().expect("interface hash");
        raw.replace(PLACEHOLDER_HASH, &hash.to_string())
    }

    fn unsigned_manifest_toml(extra_sections: &str) -> String {
        if extra_sections.trim().is_empty() {
            base_manifest_toml()
        } else {
            format!("{}\n{}", base_manifest_toml(), extra_sections)
        }
    }

    fn manifest_with_signature(sig: Base64Bytes) -> ConnectorManifest {
        let mut manifest = minimal_manifest();
        manifest.signatures = Some(SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "pub1".to_string(),
                sig,
            }],
            publisher_threshold: Some(fcp_manifest::SignatureThreshold { k: 1, n: 1 }),
            registry_signature: None,
            transparency_log_entry: None,
        });
        manifest
    }

    fn sign_manifest_toml(
        manifest_toml: &str,
        signing_key: &Ed25519SigningKey,
        binary_hash: &str,
    ) -> Base64Bytes {
        let manifest = ConnectorManifest::parse_str(manifest_toml).expect("manifest");
        let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
        let message = signature_message(&signing_bytes, binary_hash);
        let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
        Base64Bytes::try_from(format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        ))
        .expect("base64 sig")
    }

    fn publisher_signature_section(kid: &str, sig: &Base64Bytes) -> String {
        format!(
            r#"[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "{kid}"
sig = "{sig}"
"#,
            sig = String::from(sig.clone())
        )
    }

    fn registry_signature_section(kid: &str, sig: &Base64Bytes) -> String {
        format!(
            r#"[signatures.registry_signature]
kid = "{kid}"
sig = "{sig}"
"#,
            sig = String::from(sig.clone())
        )
    }

    fn with_signatures(unsigned: &str, signatures: &str) -> String {
        format!("{unsigned}\n{signatures}")
    }

    fn test_target() -> ConnectorTarget {
        ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        }
    }

    fn test_zone_policy(capability_ceiling: Vec<CapabilityId>) -> ZonePolicyObject {
        let zone = ZoneId::work();
        ZonePolicyObject {
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "ZonePolicyObject", Version::new(1, 0, 0)),
                zone_id: zone.clone(),
                created_at: 1_700_000_000,
                provenance: Provenance::new(zone.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            zone_id: zone,
            principal_allow: Vec::new(),
            principal_deny: Vec::new(),
            connector_allow: Vec::new(),
            connector_deny: Vec::new(),
            capability_allow: Vec::new(),
            capability_deny: Vec::new(),
            capability_ceiling,
            transport_policy: ZoneTransportPolicy::default(),
            decision_receipts: DecisionReceiptPolicy::default(),
        }
    }

    #[test]
    fn verify_publisher_signature_ok() {
        run_registry_test(
            "verify_publisher_signature_ok",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let manifest = minimal_manifest();
                let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                let binary_hash = "sha256:deadbeef";
                let message = signature_message(&signing_bytes, binary_hash);
                let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
                let sig = Base64Bytes::try_from(format!(
                    "base64:{}",
                    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
                ))
                .expect("base64 sig");

                let manifest = manifest_with_signature(sig);
                let sigs = manifest.signatures.as_ref().expect("signatures");

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let ok = verify_publishers(&trust, sigs, &signing_bytes, binary_hash)
                    .expect("verify publishers");
                assert!(ok);

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    version: Some(manifest.connector.version.to_string()),
                    reason_code: Some("publisher_signature_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_publisher_signature_rejects_unknown_kid() {
        run_registry_test(
            "verify_publisher_signature_rejects_unknown_kid",
            "verify",
            "signature",
            1,
            || async {
                let manifest = minimal_manifest();
                let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                let sig = Base64Bytes::try_from("base64:AA==".to_string()).expect("base64 sig");
                let manifest = manifest_with_signature(sig);
                let sigs = manifest.signatures.as_ref().expect("signatures");

                let trust = RegistryTrustPolicy::default();
                let err = verify_publishers(&trust, sigs, &signing_bytes, "sha256:dead")
                    .expect_err("unknown kid");
                assert!(matches!(err, RegistryError::UnknownKid { .. }));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("unknown_kid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_policy_requires_attestation_evidence() {
        run_registry_test(
            "supply_chain_policy_requires_attestation_evidence",
            "verify",
            "attestation",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![AttestationType::InToto],
                    min_slsa_level: None,
                    trusted_builders: Vec::new(),
                });

                let err =
                    enforce_supply_chain_policy(&manifest, None).expect_err("missing evidence");
                assert!(matches!(err, RegistryError::AttestationEvidenceMissing));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("attestation_evidence_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn capability_ceiling_violation_detected() {
        run_registry_test(
            "capability_ceiling_violation_detected",
            "verify",
            "policy",
            1,
            || async {
                let manifest = minimal_manifest();
                let policy = test_zone_policy(vec![CapabilityId::from_static("cap.other")]);

                let err =
                    enforce_capability_ceiling(Some(&policy), &manifest).expect_err("ceiling");
                assert!(matches!(
                    err,
                    RegistryError::CapabilityCeilingViolation { .. }
                ));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("capability_ceiling_violation".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_valid_publisher_signature() {
        run_registry_test(
            "verify_bundle_accepts_valid_publisher_signature",
            "verify",
            "signature",
            3,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                assert_eq!(verified.binary_hash, binary_hash);
                assert_eq!(verified.manifest_hash, hash_bytes(manifest_toml.as_bytes()));
                assert_eq!(verified.target, bundle.target);

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    version: Some(verified.manifest.connector.version.to_string()),
                    manifest_hash: Some(verified.manifest_hash),
                    binary_hash: Some(verified.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_signatures() {
        run_registry_test(
            "verify_bundle_rejects_missing_signatures",
            "verify",
            "signature",
            1,
            || async {
                let binary = b"registry-binary".to_vec();
                let bundle = ConnectorBundle {
                    manifest_toml: unsigned_manifest_toml(""),
                    binary,
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing signatures");
                assert!(matches!(err, RegistryError::MissingSignatures));

                RegistryLogData {
                    reason_code: Some("missing_signatures".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_malformed_manifest() {
        run_registry_test(
            "verify_bundle_rejects_malformed_manifest",
            "verify",
            "manifest",
            1,
            || async {
                let bundle = ConnectorBundle {
                    manifest_toml: "not-a-manifest".to_string(),
                    binary: vec![0u8],
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("malformed manifest");
                assert!(matches!(&err, RegistryError::ManifestParse(_)));

                RegistryLogData {
                    reason_code: Some("manifest_parse_failed".to_string()),
                    details: Some(json!({
                        "error": format!("{err}")
                    })),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_unknown_kid() {
        run_registry_test(
            "verify_bundle_rejects_unknown_kid",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("unknown kid");
                assert!(matches!(err, RegistryError::UnknownKid { .. }));

                RegistryLogData {
                    reason_code: Some("unknown_kid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_binary_hash_mismatch() {
        run_registry_test(
            "verify_bundle_rejects_binary_hash_mismatch",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let expected_binary = b"expected-binary".to_vec();
                let expected_hash = hash_bytes(&expected_binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &expected_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: b"tampered-binary".to_vec(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("binary mismatch");
                assert!(matches!(err, RegistryError::SignatureInvalid { .. }));

                RegistryLogData {
                    reason_code: Some("checksum_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_target_mismatch() {
        run_registry_test(
            "verify_bundle_rejects_target_mismatch",
            "verify",
            "target",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(
                        &bundle,
                        None,
                        None,
                        Some(&ConnectorTarget {
                            os: "darwin".to_string(),
                            arch: "amd64".to_string(),
                        }),
                    )
                    .expect_err("target mismatch");
                assert!(matches!(err, RegistryError::TargetMismatch { .. }));

                RegistryLogData {
                    reason_code: Some("target_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_capability_ceiling_violation() {
        run_registry_test(
            "verify_bundle_rejects_capability_ceiling_violation",
            "verify",
            "policy",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let zone_policy = test_zone_policy(vec![CapabilityId::from_static("network.dns")]);
                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, Some(&zone_policy), None, None)
                    .expect_err("capability ceiling");
                assert!(matches!(
                    err,
                    RegistryError::CapabilityCeilingViolation { .. }
                ));

                RegistryLogData {
                    reason_code: Some("capability_ceiling_violation".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_transparency_log_missing() {
        run_registry_test(
            "verify_bundle_rejects_transparency_log_missing",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing transparency entry");
                assert!(matches!(err, RegistryError::TransparencyLogMissing));

                RegistryLogData {
                    reason_code: Some("transparency_log_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_transparency_evidence_missing() {
        run_registry_test(
            "verify_bundle_rejects_transparency_evidence_missing",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let transparency_entry = format!(
                    r#"[signatures]
transparency_log_entry = "objectid:{}"
"#,
                    hex::encode([0u8; 32])
                );
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml = with_signatures(
                    &unsigned,
                    &format!(
                        "{signatures}\n{}",
                        publisher_signature_section("pub1", &sig),
                        signatures = transparency_entry.trim_end()
                    ),
                );

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing transparency evidence");
                assert!(matches!(err, RegistryError::TransparencyEvidenceMissing));

                RegistryLogData {
                    reason_code: Some("transparency_evidence_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_attestation_type() {
        run_registry_test(
            "verify_bundle_rejects_missing_attestation_type",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::CodeReview,
                        slsa_level: Some(2),
                        builder_id: Some("builder-a".to_string()),
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("missing attestation type");
                assert!(matches!(
                    err,
                    RegistryError::RequiredAttestationMissing { .. }
                ));

                RegistryLogData {
                    reason_code: Some("attestation_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_slsa_level_insufficient() {
        run_registry_test(
            "verify_bundle_rejects_slsa_level_insufficient",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
min_slsa_level = 3
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(2),
                        builder_id: Some("builder-a".to_string()),
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("insufficient slsa level");
                assert!(matches!(
                    err,
                    RegistryError::SlsaLevelInsufficient { required: 3 }
                ));

                RegistryLogData {
                    reason_code: Some("slsa_level_insufficient".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_untrusted_builder() {
        run_registry_test(
            "verify_bundle_rejects_untrusted_builder",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
trusted_builders = ["trusted-builder"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(3),
                        builder_id: Some("untrusted".to_string()),
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("untrusted builder");
                assert!(matches!(err, RegistryError::UntrustedBuilder { .. }));

                RegistryLogData {
                    reason_code: Some("untrusted_builder".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_registry_signature_required() {
        run_registry_test(
            "verify_bundle_rejects_registry_signature_required",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);
                trust.require_registry_signature = true;

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("registry signature required");
                assert!(matches!(err, RegistryError::RegistrySignatureRequired));

                RegistryLogData {
                    reason_code: Some("registry_signature_required".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_registry_signature_only() {
        run_registry_test(
            "verify_bundle_accepts_registry_signature_only",
            "verify",
            "signature",
            2,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &registry_signature_section("reg1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .registry_keys
                    .insert("reg1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("registry signature");
                assert_eq!(verified.binary_hash, binary_hash);
                assert_eq!(verified.manifest_hash, hash_bytes(manifest_toml.as_bytes()));

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    manifest_hash: Some(verified.manifest_hash),
                    binary_hash: Some(verified.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mirror_bundle_persists_objects() {
        run_registry_test(
            "mirror_bundle_persists_objects",
            "verify",
            "mirror",
            4,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let zone_id = ZoneId::work();
                let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

                let result = verifier
                    .mirror_bundle(&verified, &bundle, zone_id, &object_id_key, &store)
                    .await
                    .expect("mirror bundle");

                let manifest_object = store
                    .get(&result.manifest_object_id)
                    .await
                    .expect("manifest object");
                let binary_object = store
                    .get(&result.binary_object_id)
                    .await
                    .expect("binary object");

                assert_eq!(manifest_object.storage.retention, RetentionClass::Pinned);
                assert_eq!(binary_object.storage.retention, RetentionClass::Pinned);
                assert_eq!(binary_object.header.refs, vec![result.manifest_object_id]);
                assert_eq!(binary_object.header.zone_id, ZoneId::work());

                RegistryLogData {
                    manifest_hash: Some(result.manifest_hash),
                    binary_hash: Some(result.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }
}

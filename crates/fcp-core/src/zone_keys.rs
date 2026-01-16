//! Zone key distribution and rotation primitives.
//!
//! Implements `ZoneKeyManifest` objects and HPKE-wrapped zone keys.

use std::collections::HashMap;
use std::fmt;

use fcp_crypto::{
    CryptoError, Fcp2Aad, HpkeSealedBox, X25519PublicKey, X25519SecretKey, hpke_open, hpke_seal,
};
use serde::{Deserialize, Serialize};

use crate::{NodeSignature, ObjectHeader, ObjectIdKey, TailscaleNodeId, ZoneId};

/// Zone key length in bytes (ChaCha20-Poly1305 / XChaCha20-Poly1305).
pub const ZONE_KEY_LEN: usize = 32;

/// Zone key identifier (8 bytes as carried in FCPS frames).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ZoneKeyId(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 8]);

impl ZoneKeyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for ZoneKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneKeyId")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ZoneKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// `ObjectId` key identifier (8 bytes as carried in FCPS frames).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectIdKeyId(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 8]);

impl ObjectIdKeyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for ObjectIdKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectIdKeyId")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ObjectIdKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Symmetric zone encryption key (secret).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneKey([u8; ZONE_KEY_LEN]);

impl ZoneKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ZONE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ZONE_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for ZoneKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneKey")
            .field(&"[redacted; 32 bytes]")
            .finish()
    }
}

/// Supported zone key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKeyAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// Wrapped zone key entry (HPKE sealed box).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedZoneKey {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: HpkeSealedBox,
}

/// Wrapped `ObjectIdKey` entry (HPKE sealed box).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedObjectIdKey {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: HpkeSealedBox,
}

/// Rekey policy hints for zone membership changes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RekeyPolicy {
    #[serde(default)]
    pub epoch_ratchet: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_window_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retain_epochs: Option<u32>,
    #[serde(default)]
    pub rewrap_on_membership_change: bool,
    #[serde(default)]
    pub rotate_object_id_key_on_membership_change: bool,
}

/// Zone key manifest object (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneKeyManifest {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub zone_key_id: ZoneKeyId,
    pub object_id_key_id: ObjectIdKeyId,
    pub algorithm: ZoneKeyAlgorithm,
    pub valid_from: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_zone_key_id: Option<ZoneKeyId>,
    #[serde(default)]
    pub wrapped_keys: Vec<WrappedZoneKey>,
    #[serde(default)]
    pub wrapped_object_id_keys: Vec<WrappedObjectIdKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_policy: Option<RekeyPolicy>,
    pub signature: NodeSignature,
}

impl ZoneKeyManifest {
    /// Find the wrapped zone key for a recipient node.
    #[must_use]
    pub fn wrapped_key_for(&self, node_id: &TailscaleNodeId) -> Option<&WrappedZoneKey> {
        self.wrapped_keys
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }

    /// Find the wrapped `ObjectIdKey` for a recipient node.
    #[must_use]
    pub fn wrapped_object_id_key_for(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Option<&WrappedObjectIdKey> {
        self.wrapped_object_id_keys
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }
}

/// Zone key ring storing active/known keys by id.
#[derive(Debug, Clone)]
pub struct ZoneKeyRing {
    pub zone_id: ZoneId,
    zone_keys: HashMap<ZoneKeyId, ZoneKey>,
    object_id_keys: HashMap<ObjectIdKeyId, ObjectIdKey>,
    pub active_zone_key_id: Option<ZoneKeyId>,
    pub active_object_id_key_id: Option<ObjectIdKeyId>,
}

impl ZoneKeyRing {
    #[must_use]
    pub fn new(zone_id: ZoneId) -> Self {
        Self {
            zone_id,
            zone_keys: HashMap::new(),
            object_id_keys: HashMap::new(),
            active_zone_key_id: None,
            active_object_id_key_id: None,
        }
    }

    pub fn insert_zone_key(&mut self, key_id: ZoneKeyId, key: ZoneKey) {
        self.zone_keys.insert(key_id, key);
    }

    pub fn insert_object_id_key(&mut self, key_id: ObjectIdKeyId, key: ObjectIdKey) {
        self.object_id_keys.insert(key_id, key);
    }

    #[must_use]
    pub fn zone_key(&self, key_id: &ZoneKeyId) -> Option<&ZoneKey> {
        self.zone_keys.get(key_id)
    }

    #[must_use]
    pub fn object_id_key(&self, key_id: &ObjectIdKeyId) -> Option<&ObjectIdKey> {
        self.object_id_keys.get(key_id)
    }

    #[must_use]
    pub fn active_zone_key(&self) -> Option<&ZoneKey> {
        self.active_zone_key_id
            .as_ref()
            .and_then(|key_id| self.zone_keys.get(key_id))
    }

    #[must_use]
    pub fn active_object_id_key(&self) -> Option<&ObjectIdKey> {
        self.active_object_id_key_id
            .as_ref()
            .and_then(|key_id| self.object_id_keys.get(key_id))
    }

    #[must_use]
    pub fn set_active_zone_key(&mut self, key_id: ZoneKeyId) -> bool {
        if self.zone_keys.contains_key(&key_id) {
            self.active_zone_key_id = Some(key_id);
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn set_active_object_id_key(&mut self, key_id: ObjectIdKeyId) -> bool {
        if self.object_id_keys.contains_key(&key_id) {
            self.active_object_id_key_id = Some(key_id);
            true
        } else {
            false
        }
    }

    /// Apply a zone key manifest for the local node and update active keys.
    ///
    /// # Errors
    /// Returns `ZoneKeyError` if the manifest is for a different zone or
    /// required wrapped keys are missing/invalid.
    pub fn apply_manifest(
        &mut self,
        manifest: &ZoneKeyManifest,
        node_id: &TailscaleNodeId,
        node_secret: &X25519SecretKey,
    ) -> ZoneKeyResult<()> {
        if manifest.zone_id != self.zone_id {
            return Err(ZoneKeyError::ZoneIdMismatch {
                expected: self.zone_id.as_str().to_string(),
                found: manifest.zone_id.as_str().to_string(),
            });
        }

        let wrapped_zone = manifest.wrapped_key_for(node_id).ok_or_else(|| {
            ZoneKeyError::MissingWrappedZoneKey {
                node_id: node_id.as_str().to_string(),
            }
        })?;
        let zone_key = unwrap_zone_key(node_secret, &manifest.zone_id, wrapped_zone)?;
        self.insert_zone_key(manifest.zone_key_id, zone_key);
        self.active_zone_key_id = Some(manifest.zone_key_id);

        let wrapped_object_id = manifest.wrapped_object_id_key_for(node_id).ok_or_else(|| {
            ZoneKeyError::MissingWrappedObjectIdKey {
                node_id: node_id.as_str().to_string(),
            }
        })?;
        let object_id_key =
            unwrap_object_id_key(node_secret, &manifest.zone_id, wrapped_object_id)?;
        self.insert_object_id_key(manifest.object_id_key_id, object_id_key);
        self.active_object_id_key_id = Some(manifest.object_id_key_id);

        Ok(())
    }
}

/// Zone key distribution errors.
#[derive(Debug, thiserror::Error)]
pub enum ZoneKeyError {
    #[error("crypto failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid key length (expected {expected}, got {found})")]
    InvalidKeyLength { expected: usize, found: usize },
    #[error("zone id mismatch (expected {expected}, found {found})")]
    ZoneIdMismatch { expected: String, found: String },
    #[error("missing wrapped zone key for node `{node_id}`")]
    MissingWrappedZoneKey { node_id: String },
    #[error("missing wrapped ObjectIdKey for node `{node_id}`")]
    MissingWrappedObjectIdKey { node_id: String },
}

pub type ZoneKeyResult<T> = Result<T, ZoneKeyError>;

/// Wrap a zone key for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE sealing fails.
pub fn wrap_zone_key(
    recipient_pk: &X25519PublicKey,
    zone_id: &ZoneId,
    recipient_node_id: &TailscaleNodeId,
    issued_at: u64,
    zone_key: &ZoneKey,
) -> ZoneKeyResult<WrappedZoneKey> {
    let aad = Fcp2Aad::for_zone_key(
        zone_id.as_bytes(),
        recipient_node_id.as_str().as_bytes(),
        issued_at,
    );
    let sealed = hpke_seal(recipient_pk, zone_key.as_bytes(), &aad)?;
    Ok(WrappedZoneKey {
        recipient: recipient_node_id.clone(),
        issued_at,
        sealed,
    })
}

/// Unwrap a zone key for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE opening fails or key length is invalid.
pub fn unwrap_zone_key(
    recipient_sk: &X25519SecretKey,
    zone_id: &ZoneId,
    wrapped: &WrappedZoneKey,
) -> ZoneKeyResult<ZoneKey> {
    let aad = Fcp2Aad::for_zone_key(
        zone_id.as_bytes(),
        wrapped.recipient.as_str().as_bytes(),
        wrapped.issued_at,
    );
    let opened = hpke_open(recipient_sk, &wrapped.sealed, &aad)?;
    if opened.len() != ZONE_KEY_LEN {
        return Err(ZoneKeyError::InvalidKeyLength {
            expected: ZONE_KEY_LEN,
            found: opened.len(),
        });
    }
    let mut bytes = [0u8; ZONE_KEY_LEN];
    bytes.copy_from_slice(&opened);
    Ok(ZoneKey::from_bytes(bytes))
}

/// Wrap an `ObjectIdKey` for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE sealing fails.
pub fn wrap_object_id_key(
    recipient_pk: &X25519PublicKey,
    zone_id: &ZoneId,
    recipient_node_id: &TailscaleNodeId,
    issued_at: u64,
    object_id_key: &ObjectIdKey,
) -> ZoneKeyResult<WrappedObjectIdKey> {
    let aad = Fcp2Aad::for_objectid_key(
        zone_id.as_bytes(),
        recipient_node_id.as_str().as_bytes(),
        issued_at,
    );
    let sealed = hpke_seal(recipient_pk, object_id_key.as_bytes(), &aad)?;
    Ok(WrappedObjectIdKey {
        recipient: recipient_node_id.clone(),
        issued_at,
        sealed,
    })
}

/// Unwrap an `ObjectIdKey` for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE opening fails or key length is invalid.
pub fn unwrap_object_id_key(
    recipient_sk: &X25519SecretKey,
    zone_id: &ZoneId,
    wrapped: &WrappedObjectIdKey,
) -> ZoneKeyResult<ObjectIdKey> {
    let aad = Fcp2Aad::for_objectid_key(
        zone_id.as_bytes(),
        wrapped.recipient.as_str().as_bytes(),
        wrapped.issued_at,
    );
    let opened = hpke_open(recipient_sk, &wrapped.sealed, &aad)?;
    if opened.len() != ZONE_KEY_LEN {
        return Err(ZoneKeyError::InvalidKeyLength {
            expected: ZONE_KEY_LEN,
            found: opened.len(),
        });
    }
    let mut bytes = [0u8; ZONE_KEY_LEN];
    bytes.copy_from_slice(&opened);
    Ok(ObjectIdKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, NodeSignature, ObjectHeader, Provenance};
    use fcp_cbor::SchemaId;
    use fcp_crypto::x25519::X25519SecretKey;
    use rand::RngCore;
    use semver::Version;

    fn random_zone_key() -> ZoneKey {
        let mut bytes = [0u8; ZONE_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        ZoneKey::from_bytes(bytes)
    }

    fn random_object_id_key() -> ObjectIdKey {
        let mut bytes = [0u8; ZONE_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        ObjectIdKey::from_bytes(bytes)
    }

    fn test_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("owner-node"), [0u8; 64], 1_700_000_000)
    }

    #[test]
    fn zone_key_wrap_roundtrip() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-1");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let opened = unwrap_zone_key(&sk, &zone_id, &wrapped).unwrap();

        assert_eq!(opened, zone_key);
    }

    #[test]
    fn object_id_key_wrap_roundtrip() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-2");
        let issued_at = 1_700_000_123;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let opened = unwrap_object_id_key(&sk, &zone_id, &wrapped).unwrap();

        assert_eq!(opened, key);
    }

    #[test]
    fn unwrap_zone_key_fails_with_wrong_node_id() {
        let zone_id = ZoneId::community();
        let node_id = TailscaleNodeId::new("node-3");
        let issued_at = 1_700_000_456;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let mut wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        wrapped.recipient = TailscaleNodeId::new("node-4");

        let result = unwrap_zone_key(&sk, &zone_id, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn zone_key_ring_selects_by_id() {
        let zone_id = ZoneId::public();
        let mut ring = ZoneKeyRing::new(zone_id);

        let key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let key = ZoneKey::from_bytes([2u8; ZONE_KEY_LEN]);
        ring.insert_zone_key(key_id, key);

        assert!(ring.set_active_zone_key(key_id));
        assert_eq!(ring.active_zone_key(), Some(&key));
    }

    #[test]
    fn apply_manifest_unwraps_and_sets_active() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-apply");
        let issued_at = 1_700_000_777;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([9u8; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([7u8; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();

        assert_eq!(ring.active_zone_key_id, Some(manifest.zone_key_id));
        assert_eq!(
            ring.active_object_id_key_id,
            Some(manifest.object_id_key_id)
        );
        assert_eq!(ring.active_zone_key(), Some(&zone_key));
        assert_eq!(ring.active_object_id_key(), Some(&object_id_key));
    }

    #[test]
    fn apply_manifest_rejects_mismatched_zone() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-apply");
        let issued_at = 1_700_000_888;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([3u8; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([4u8; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(ZoneId::private());
        let err = ring
            .apply_manifest(&manifest, &node_id, &sk)
            .expect_err("zone mismatch");
        assert!(matches!(err, ZoneKeyError::ZoneIdMismatch { .. }));
    }

    /// Test key rotation: applying a new manifest rotates the active key while
    /// keeping the old key accessible by its ID (deterministic selection).
    #[test]
    fn rotation_deterministic_key_selection_by_zone_key_id() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-rotation");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === First manifest (epoch 1) ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let object_id_key_id_1 =
            ObjectIdKeyId::from_bytes([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();

        // Verify initial state
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));

        // === Second manifest (epoch 2) - rotation ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]);
        let object_id_key_id_2 =
            ObjectIdKeyId::from_bytes([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1), // Links to previous key
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: Some(RekeyPolicy {
                overlap_window_secs: Some(600),
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();

        // Verify rotation occurred
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_2));

        // CRITICAL: Both keys must be accessible by their IDs (deterministic selection)
        // This enables decryption of symbols encrypted under either epoch without trial decrypt.
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );

        // Verify we can switch active key back to epoch 1 (for decryption overlap window)
        assert!(ring.set_active_zone_key(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));
    }

    /// Test membership change: a removed node cannot decrypt newly wrapped keys
    /// because they are not included in the `wrapped_keys` list.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn membership_change_removed_node_cannot_decrypt() {
        let zone_id = ZoneId::work();

        // Three nodes initially in the zone
        let node_1_id = TailscaleNodeId::new("node-1");
        let node_2_id = TailscaleNodeId::new("node-2");
        let node_3_id = TailscaleNodeId::new("node-3"); // Will be removed

        let sk_1 = X25519SecretKey::generate();
        let pk_1 = sk_1.public_key();
        let sk_2 = X25519SecretKey::generate();
        let pk_2 = sk_2.public_key();
        let sk_3 = X25519SecretKey::generate();
        let pk_3 = sk_3.public_key();

        // === Initial manifest with all 3 nodes ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_3 =
            wrap_zone_key(&pk_3, &zone_id, &node_3_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_obj_1_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_3 =
            wrap_object_id_key(&pk_3, &zone_id, &node_3_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![
                wrapped_zone_1_for_1,
                wrapped_zone_1_for_2,
                wrapped_zone_1_for_3,
            ],
            wrapped_object_id_keys: vec![
                wrapped_obj_1_for_1,
                wrapped_obj_1_for_2,
                wrapped_obj_1_for_3,
            ],
            rekey_policy: None,
            signature: test_signature(),
        };

        // All 3 nodes can apply the initial manifest
        let mut ring_1 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_2 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_3 = ZoneKeyRing::new(zone_id.clone());

        ring_1
            .apply_manifest(&manifest_1, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_1, &node_2_id, &sk_2)
            .unwrap();
        ring_3
            .apply_manifest(&manifest_1, &node_3_id, &sk_3)
            .unwrap();

        // === Second manifest: node-3 is removed from membership ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x31; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x41; 8]);

        // Only wrap keys for nodes 1 and 2 (node 3 is excluded)
        let wrapped_zone_2_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_zone_2_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_obj_2_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &object_id_key_2).unwrap();
        let wrapped_obj_2_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![wrapped_zone_2_for_1, wrapped_zone_2_for_2],
            wrapped_object_id_keys: vec![wrapped_obj_2_for_1, wrapped_obj_2_for_2],
            rekey_policy: Some(RekeyPolicy {
                rewrap_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        // Nodes 1 and 2 can apply the new manifest
        ring_1
            .apply_manifest(&manifest_2, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_2, &node_2_id, &sk_2)
            .unwrap();

        // CRITICAL: Node 3 CANNOT apply the new manifest (no wrapped key for them)
        let err = ring_3
            .apply_manifest(&manifest_2, &node_3_id, &sk_3)
            .expect_err("removed node should fail");
        assert!(
            matches!(err, ZoneKeyError::MissingWrappedZoneKey { .. }),
            "expected MissingWrappedZoneKey error, got {err:?}"
        );

        // Verify nodes 1 and 2 have the new key
        assert_eq!(ring_1.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_2.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_1.active_zone_key(), Some(&zone_key_2));
        assert_eq!(ring_2.active_zone_key(), Some(&zone_key_2));

        // Node 3 still has only the old key
        assert_eq!(ring_3.active_zone_key_id, Some(zone_key_id_1));
        assert_eq!(ring_3.active_zone_key(), Some(&zone_key_1));
        assert!(ring_3.zone_key(&zone_key_id_2).is_none());
    }

    /// Test that `ObjectIdKey` rotation can happen independently or alongside `ZoneKey` rotation.
    #[test]
    fn rotation_with_object_id_key_change() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-objid-rotation");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === First manifest ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();

        // === Second manifest with BOTH ZoneKey AND ObjectIdKey rotation ===
        // (Used when rotate_object_id_key_on_membership_change policy is set)
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x41; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x51; 8]); // Also rotated!

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: Some(RekeyPolicy {
                rotate_object_id_key_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();

        // Verify both keys rotated
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring.active_object_id_key_id, Some(object_id_key_id_2));

        // Both old and new keys accessible (no trial decrypt needed)
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );
    }
}

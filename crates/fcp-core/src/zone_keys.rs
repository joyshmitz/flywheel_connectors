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
}

/// Zone key distribution errors.
#[derive(Debug, thiserror::Error)]
pub enum ZoneKeyError {
    #[error("crypto failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid key length (expected {expected}, got {found})")]
    InvalidKeyLength { expected: usize, found: usize },
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
    use fcp_crypto::x25519::X25519SecretKey;
    use rand::RngCore;

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
}

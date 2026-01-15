//! HPKE (Hybrid Public Key Encryption) for FCP2.
//!
//! Implements RFC 9180 sealed boxes for distributing zone keys and shares
//! to node encryption keys.
//!
//! ## Baseline Profile (MUST implement)
//! - KEM: DHKEM(X25519, HKDF-SHA256)
//! - KDF: HKDF-SHA256
//! - AEAD: ChaCha20-Poly1305
//!
//! ## AAD Binding (NORMATIVE)
//! When sealing keys/shares, AAD MUST include:
//! - `zone_id_hash` (or `zone_id`)
//! - `recipient_node_id`
//! - purpose string (e.g., "FCP2-ZONE-KEY")
//! - `issued_at`

use crate::error::{CryptoError, CryptoResult};
use crate::x25519::{X25519PublicKey, X25519SecretKey};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use serde::{Deserialize, Serialize};

/// HPKE encapsulated key size for X25519.
pub const HPKE_ENC_SIZE: usize = 32;

/// HPKE authentication tag size.
pub const HPKE_TAG_SIZE: usize = 16;

/// FCP2 purpose strings for AAD binding.
pub mod purpose {
    /// Purpose string for zone encryption keys.
    pub const ZONE_KEY: &[u8] = b"FCP2-ZONE-KEY";
    /// Purpose string for `ObjectId` derivation keys.
    pub const OBJECTID_KEY: &[u8] = b"FCP2-OBJECTID-KEY";
    /// Purpose string for owner secret shares.
    pub const OWNER_SHARE: &[u8] = b"FCP2-OWNER-SHARE";
    /// Purpose string for generic secret shares.
    pub const SECRET_SHARE: &[u8] = b"FCP2-SECRET-SHARE";
}

/// HPKE sealed box containing encapsulated key and ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpkeSealedBox {
    /// Encapsulated key (ephemeral public key).
    #[serde(with = "hex::serde")]
    pub enc: Vec<u8>,
    /// Ciphertext with authentication tag.
    #[serde(with = "hex::serde")]
    pub ciphertext: Vec<u8>,
}

impl HpkeSealedBox {
    /// Encode to bytes: enc || ciphertext.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.enc.len() + self.ciphertext.len());
        bytes.extend_from_slice(&self.enc);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < HPKE_ENC_SIZE + HPKE_TAG_SIZE {
            return Err(CryptoError::HpkeFailed("sealed box too short".into()));
        }
        Ok(Self {
            enc: bytes[..HPKE_ENC_SIZE].to_vec(),
            ciphertext: bytes[HPKE_ENC_SIZE..].to_vec(),
        })
    }
}

/// FCP2 AAD (Additional Authenticated Data) for HPKE sealing.
///
/// Binds the sealed data to its intended context per the spec.
#[derive(Clone, Debug)]
pub struct Fcp2Aad {
    /// Zone identifier (or hash).
    pub zone_id: Vec<u8>,
    /// Recipient node identifier.
    pub recipient_node_id: Vec<u8>,
    /// Purpose string (e.g., `purpose::ZONE_KEY`).
    pub purpose: Vec<u8>,
    /// Issuance timestamp (Unix seconds).
    pub issued_at: u64,
}

impl Fcp2Aad {
    /// Create new AAD for zone key distribution.
    #[must_use]
    pub fn for_zone_key(zone_id: &[u8], recipient_node_id: &[u8], issued_at: u64) -> Self {
        Self {
            zone_id: zone_id.to_vec(),
            recipient_node_id: recipient_node_id.to_vec(),
            purpose: purpose::ZONE_KEY.to_vec(),
            issued_at,
        }
    }

    /// Create new AAD for `ObjectId` key distribution.
    #[must_use]
    pub fn for_objectid_key(zone_id: &[u8], recipient_node_id: &[u8], issued_at: u64) -> Self {
        Self {
            zone_id: zone_id.to_vec(),
            recipient_node_id: recipient_node_id.to_vec(),
            purpose: purpose::OBJECTID_KEY.to_vec(),
            issued_at,
        }
    }

    /// Create new AAD for secret share distribution.
    #[must_use]
    pub fn for_secret_share(zone_id: &[u8], recipient_node_id: &[u8], issued_at: u64) -> Self {
        Self {
            zone_id: zone_id.to_vec(),
            recipient_node_id: recipient_node_id.to_vec(),
            purpose: purpose::SECRET_SHARE.to_vec(),
            issued_at,
        }
    }

    /// Encode AAD to bytes for HPKE.
    ///
    /// Format: `zone_id` || `recipient_node_id` || `purpose` || `issued_at` (8 bytes LE)
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            self.zone_id.len() + self.recipient_node_id.len() + self.purpose.len() + 8,
        );
        aad.extend_from_slice(&self.zone_id);
        aad.extend_from_slice(&self.recipient_node_id);
        aad.extend_from_slice(&self.purpose);
        aad.extend_from_slice(&self.issued_at.to_le_bytes());
        aad
    }
}

/// Seal (encrypt) data to a recipient's public key using HPKE.
///
/// # Arguments
///
/// * `recipient_pk` - Recipient's X25519 public key.
/// * `plaintext` - Data to encrypt.
/// * `aad` - Additional authenticated data (context binding).
///
/// # Errors
///
/// Returns an error if HPKE operations fail.
pub fn hpke_seal(
    recipient_pk: &X25519PublicKey,
    plaintext: &[u8],
    aad: &Fcp2Aad,
) -> CryptoResult<HpkeSealedBox> {
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&recipient_pk.to_bytes())
        .map_err(|e| CryptoError::HpkeFailed(format!("invalid recipient public key: {e}")))?;

    let mut rng = rand::rngs::OsRng;
    let (enc, mut sender_ctx) = hpke::setup_sender::<
        ChaCha20Poly1305Aead,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &pk, b"FCP2-HPKE", &mut rng)
    .map_err(|e| CryptoError::HpkeFailed(format!("setup_sender failed: {e}")))?;

    let aad_bytes = aad.encode();
    let ciphertext = sender_ctx
        .seal(plaintext, &aad_bytes)
        .map_err(|e| CryptoError::HpkeFailed(format!("seal failed: {e}")))?;

    Ok(HpkeSealedBox {
        enc: enc.to_bytes().to_vec(),
        ciphertext,
    })
}

/// Open (decrypt) an HPKE sealed box.
///
/// # Arguments
///
/// * `recipient_sk` - Recipient's X25519 secret key.
/// * `sealed_box` - The sealed box to decrypt.
/// * `aad` - Additional authenticated data (must match what was used for sealing).
///
/// # Errors
///
/// Returns an error if decryption fails (wrong key, tampered data, or wrong AAD).
pub fn hpke_open(
    recipient_sk: &X25519SecretKey,
    sealed_box: &HpkeSealedBox,
    aad: &Fcp2Aad,
) -> CryptoResult<Vec<u8>> {
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&recipient_sk.to_bytes())
        .map_err(|e| CryptoError::HpkeFailed(format!("invalid secret key: {e}")))?;

    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&sealed_box.enc)
        .map_err(|e| CryptoError::HpkeFailed(format!("invalid encapsulated key: {e}")))?;

    let mut receiver_ctx =
        hpke::setup_receiver::<ChaCha20Poly1305Aead, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk,
            &enc,
            b"FCP2-HPKE",
        )
        .map_err(|e| CryptoError::HpkeFailed(format!("setup_receiver failed: {e}")))?;

    let aad_bytes = aad.encode();
    receiver_ctx
        .open(&sealed_box.ciphertext, &aad_bytes)
        .map_err(|e| CryptoError::HpkeFailed(format!("open failed: {e}")))
}

// Type alias for the AEAD used internally
type ChaCha20Poly1305Aead = hpke::aead::ChaCha20Poly1305;

/// Convenience function: seal zone key material to a node.
///
/// # Errors
///
/// Returns an error if sealing fails.
pub fn seal_zone_key(
    recipient_pk: &X25519PublicKey,
    zone_key_material: &[u8],
    zone_id: &[u8],
    recipient_node_id: &[u8],
    issued_at: u64,
) -> CryptoResult<HpkeSealedBox> {
    let aad = Fcp2Aad::for_zone_key(zone_id, recipient_node_id, issued_at);
    hpke_seal(recipient_pk, zone_key_material, &aad)
}

/// Convenience function: open zone key material.
///
/// # Errors
///
/// Returns an error if opening fails.
pub fn open_zone_key(
    recipient_sk: &X25519SecretKey,
    sealed_box: &HpkeSealedBox,
    zone_id: &[u8],
    recipient_node_id: &[u8],
    issued_at: u64,
) -> CryptoResult<Vec<u8>> {
    let aad = Fcp2Aad::for_zone_key(zone_id, recipient_node_id, issued_at);
    hpke_open(recipient_sk, sealed_box, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_roundtrip() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let plaintext = b"secret zone key material";
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, plaintext, &aad).unwrap();
        let opened = hpke_open(&recipient_secret_key, &sealed, &aad).unwrap();

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn hpke_wrong_key_fails() {
        let sender_secret_key = X25519SecretKey::generate();
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        // Try to open with wrong key
        let result = hpke_open(&sender_secret_key, &sealed, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_wrong_aad_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let aad2 = Fcp2Aad::for_zone_key(b"z:private", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad1).unwrap();
        let result = hpke_open(&recipient_secret_key, &sealed, &aad2);

        assert!(result.is_err());
    }

    #[test]
    fn hpke_wrong_timestamp_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let aad2 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_891);

        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad1).unwrap();
        let result = hpke_open(&recipient_secret_key, &sealed, &aad2);

        assert!(result.is_err());
    }

    #[test]
    fn hpke_tampered_ciphertext_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let mut sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = sealed.ciphertext.first_mut() {
            *byte ^= 0xff;
        }

        let result = hpke_open(&recipient_secret_key, &sealed, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_sealed_box_bytes_roundtrip() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        let bytes = sealed.to_bytes();
        let parsed = HpkeSealedBox::from_bytes(&bytes).unwrap();

        assert_eq!(sealed.enc, parsed.enc);
        assert_eq!(sealed.ciphertext, parsed.ciphertext);
    }

    #[test]
    fn seal_zone_key_convenience() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let zone_key_material = [42u8; 32];
        let zone_id = b"z:work";
        let node_id = b"node-abc";
        let issued_at = 1_700_000_000;

        let sealed = seal_zone_key(
            &recipient_public_key,
            &zone_key_material,
            zone_id,
            node_id,
            issued_at,
        )
        .unwrap();

        let opened =
            open_zone_key(&recipient_secret_key, &sealed, zone_id, node_id, issued_at).unwrap();

        assert_eq!(opened, zone_key_material);
    }

    #[test]
    fn different_purposes_produce_different_aad() {
        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node", 1_234_567_890);
        let aad2 = Fcp2Aad::for_objectid_key(b"z:work", b"node", 1_234_567_890);
        let aad3 = Fcp2Aad::for_secret_share(b"z:work", b"node", 1_234_567_890);

        assert_ne!(aad1.encode(), aad2.encode());
        assert_ne!(aad1.encode(), aad3.encode());
        assert_ne!(aad2.encode(), aad3.encode());
    }

    #[test]
    fn hpke_empty_plaintext() {
        // HPKE should handle empty plaintext correctly
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let sealed = hpke_seal(&recipient_public_key, b"", &aad).unwrap();
        let opened = hpke_open(&recipient_secret_key, &sealed, &aad).unwrap();

        assert!(opened.is_empty());
    }

    #[test]
    fn hpke_large_plaintext() {
        // Test with a larger payload
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let large_plaintext = vec![0x42u8; 4096];
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, &large_plaintext, &aad).unwrap();
        let opened = hpke_open(&recipient_secret_key, &sealed, &aad).unwrap();

        assert_eq!(opened, large_plaintext);
    }

    #[test]
    fn hpke_sealed_box_from_bytes_too_short() {
        // Test that from_bytes rejects input that's too short
        let short_input = vec![0u8; HPKE_ENC_SIZE + HPKE_TAG_SIZE - 1];
        let result = HpkeSealedBox::from_bytes(&short_input);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_ciphertext_length() {
        // Verify ciphertext length is plaintext + tag
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let plaintext = b"test message";
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, plaintext, &aad).unwrap();

        // enc should be 32 bytes
        assert_eq!(sealed.enc.len(), HPKE_ENC_SIZE);
        // ciphertext should be plaintext.len() + 16 (tag)
        assert_eq!(sealed.ciphertext.len(), plaintext.len() + HPKE_TAG_SIZE);
    }

    #[test]
    fn hpke_wrong_recipient_node_id_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let aad2 = Fcp2Aad::for_zone_key(b"z:work", b"node-456", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad1).unwrap();
        let result = hpke_open(&recipient_secret_key, &sealed, &aad2);

        assert!(result.is_err());
    }

    #[test]
    fn hpke_tampered_enc_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let mut sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        // Tamper with the encapsulated key
        if let Some(byte) = sealed.enc.first_mut() {
            *byte ^= 0xff;
        }

        let result = hpke_open(&recipient_secret_key, &sealed, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn aad_encode_format() {
        // Verify the AAD encoding format
        let zone_id = b"z:work";
        let node_id = b"node-123";
        let issued_at: u64 = 1_234_567_890;

        let aad = Fcp2Aad::for_zone_key(zone_id, node_id, issued_at);
        let encoded = aad.encode();

        // Should be: zone_id || node_id || purpose || timestamp (8 bytes LE)
        let expected_len =
            zone_id.len() + node_id.len() + purpose::ZONE_KEY.len() + 8;
        assert_eq!(encoded.len(), expected_len);

        // Check that timestamp is at the end in little-endian
        let ts_bytes = &encoded[encoded.len() - 8..];
        let decoded_ts = u64::from_le_bytes(ts_bytes.try_into().unwrap());
        assert_eq!(decoded_ts, issued_at);
    }

    #[test]
    fn hpke_multiple_recipients() {
        // Test sealing to multiple recipients (different sealed boxes)
        let alice_secret = X25519SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bob_secret = X25519SecretKey::generate();
        let bob_public = bob_secret.public_key();

        let plaintext = b"shared secret";
        let aad_alice = Fcp2Aad::for_zone_key(b"z:work", b"node-alice", 1_234_567_890);
        let aad_bob = Fcp2Aad::for_zone_key(b"z:work", b"node-bob", 1_234_567_890);

        let sealed_for_alice = hpke_seal(&alice_public, plaintext, &aad_alice).unwrap();
        let sealed_for_bob = hpke_seal(&bob_public, plaintext, &aad_bob).unwrap();

        // Each recipient can open their own sealed box
        let opened_by_alice = hpke_open(&alice_secret, &sealed_for_alice, &aad_alice).unwrap();
        let opened_by_bob = hpke_open(&bob_secret, &sealed_for_bob, &aad_bob).unwrap();

        assert_eq!(opened_by_alice, plaintext);
        assert_eq!(opened_by_bob, plaintext);

        // Recipients cannot open each other's sealed boxes
        assert!(hpke_open(&alice_secret, &sealed_for_bob, &aad_bob).is_err());
        assert!(hpke_open(&bob_secret, &sealed_for_alice, &aad_alice).is_err());
    }

    #[test]
    fn fcp2_aad_purposes() {
        // Verify all purpose constants
        assert_eq!(purpose::ZONE_KEY, b"FCP2-ZONE-KEY");
        assert_eq!(purpose::OBJECTID_KEY, b"FCP2-OBJECTID-KEY");
        assert_eq!(purpose::OWNER_SHARE, b"FCP2-OWNER-SHARE");
        assert_eq!(purpose::SECRET_SHARE, b"FCP2-SECRET-SHARE");
    }
}

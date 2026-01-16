//! Universal transmission unit (NORMATIVE).
//!
//! Based on FCP Specification Section 4.1.

use fcp_core::{EpochId, ObjectId, ZoneId};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};

/// Full symbol envelope with encryption (NORMATIVE).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolEnvelope {
    /// Content address of complete object
    pub object_id: ObjectId,

    /// Encoding Symbol ID
    pub esi: u32,

    /// Source symbols needed (K)
    pub k: u16,

    /// Symbol payload (encrypted)
    pub data: Vec<u8>,

    /// Zone for key derivation
    pub zone_id: ZoneId,

    /// Zone key ID (for key rotation - enables deterministic decryption)
    pub zone_key_id: [u8; 8],

    /// Epoch for replay protection
    pub epoch_id: EpochId,

    /// Source node that produced this ciphertext (NORMATIVE)
    pub source_id: NodeId,

    /// Sender instance identifier (NORMATIVE)
    /// Random u64 chosen by the sender at startup for this (`zone_id`, `zone_key_id`) lifetime.
    pub sender_instance_id: u64,

    /// Monotonic frame sequence chosen by source (NORMATIVE)
    /// Monotonicity scope is (`zone_id`, `zone_key_id`, `source_id`, `sender_instance_id`).
    pub frame_seq: u64,

    /// AEAD authentication tag
    pub auth_tag: [u8; 16],
}

impl SymbolEnvelope {
    // TODO: Implement encrypt/decrypt when ZoneKey is available in fcp-core or fcp-crypto.
    // Spec requires ZoneKey::derive_sender_subkey and ZoneKey::encrypt_with_subkey.
}

/// Derive ChaCha20-Poly1305 nonce (12 bytes) deterministically (NORMATIVE).
///
/// nonce12 = `frame_seq_le` || `esi_le`
#[must_use]
#[allow(dead_code)]
pub fn derive_nonce12(frame_seq: u64, esi: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
    nonce
}

/// Derive XChaCha20-Poly1305 nonce (24 bytes) deterministically (NORMATIVE).
///
/// nonce24 = `sender_instance_id_le` || `frame_seq_le` || `esi_le` || `0u32`
#[must_use]
#[allow(dead_code)]
pub fn derive_nonce24(sender_instance_id: u64, frame_seq: u64, esi: u32) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0..8].copy_from_slice(&sender_instance_id.to_le_bytes());
    nonce[8..16].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[16..20].copy_from_slice(&esi.to_le_bytes());
    nonce[20..24].copy_from_slice(&0u32.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_nonce12_golden_vector() {
        // Spec Example or hypothetical values
        let frame_seq = 0x0102_0304_0506_0708;
        let esi = 0x0A0B_0C0D;

        let nonce = derive_nonce12(frame_seq, esi);

        let mut expected = [0u8; 12];
        expected[0..8].copy_from_slice(&frame_seq.to_le_bytes());
        expected[8..12].copy_from_slice(&esi.to_le_bytes());

        assert_eq!(nonce, expected);
    }

    #[test]
    fn test_derive_nonce24_golden_vector() {
        let sender_instance = 0x1122_3344_5566_7788;
        let frame_seq = 0x0102_0304_0506_0708;
        let esi = 0x0A0B_0C0D;

        let nonce = derive_nonce24(sender_instance, frame_seq, esi);

        let mut expected = [0u8; 24];
        expected[0..8].copy_from_slice(&sender_instance.to_le_bytes());
        expected[8..16].copy_from_slice(&frame_seq.to_le_bytes());
        expected[16..20].copy_from_slice(&esi.to_le_bytes());
        expected[20..24].copy_from_slice(&0u32.to_le_bytes());

        assert_eq!(nonce, expected);
    }
}

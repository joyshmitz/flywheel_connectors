//! Session handshake golden vectors.
//!
//! These vectors test the session handshake transcript and key derivation.

use serde::{Deserialize, Serialize};

/// Golden vector for session handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Initiator node ID.
    pub initiator_id: String,
    /// Responder node ID.
    pub responder_id: String,
    /// Initiator ephemeral secret key (hex) - for reproduction.
    pub initiator_ephemeral_sk: String,
    /// Initiator ephemeral public key (hex).
    pub initiator_ephemeral_pk: String,
    /// Responder ephemeral secret key (hex) - for reproduction.
    pub responder_ephemeral_sk: String,
    /// Responder ephemeral public key (hex).
    pub responder_ephemeral_pk: String,
    /// Hello nonce (hex).
    pub hello_nonce: String,
    /// Ack nonce (hex).
    pub ack_nonce: String,
    /// Expected shared secret (hex) - X25519 output.
    pub expected_shared_secret: String,
    /// Expected session ID (hex).
    #[serde(alias = "session_id")]
    pub session_id: String,
    /// Expected derived keys (hex).
    pub expected_keys: SessionDerivedKeys,
}

/// Derived session keys for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDerivedKeys {
    /// Control-plane encryption key (hex).
    pub k_ctx: String,
    /// Data-plane encryption key (hex).
    pub k_data: String,
    /// MAC key for initiator-to-responder (hex).
    pub k_mac_i2r: String,
    /// MAC key for responder-to-initiator (hex).
    pub k_mac_r2i: String,
}

impl SessionGoldenVector {
    /// Load all session golden vectors.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: Vec allocation
    pub fn load_all() -> Vec<Self> {
        // TODO: Load from embedded CBOR/JSON files
        vec![Self::vector_1_basic_handshake()]
    }

    /// Vector 1: Basic handshake
    #[must_use]
    pub fn vector_1_basic_handshake() -> Self {
        Self {
            description: "Basic handshake".into(),
            initiator_id: "node-initiator".into(),
            responder_id: "node-responder".into(),
            // Keys and nonces would be hardcoded here in a real vector
            initiator_ephemeral_sk: "00".repeat(32),
            initiator_ephemeral_pk: "00".repeat(32),
            responder_ephemeral_sk: "00".repeat(32),
            responder_ephemeral_pk: "00".repeat(32),
            hello_nonce: "00".repeat(16),
            ack_nonce: "00".repeat(16),
            expected_shared_secret: "93fea2a7c1aeb62cfd6452ff5badae8bdffcbd7196dc910c89944006d85dbb68".into(),
            session_id: "00".repeat(16),
            expected_keys: SessionDerivedKeys {
                k_ctx: "5f1c8e9e1f16618172a9fa8c5a83e373f29584590fe379898208aab446568b5e".into(),
                k_data: "00".repeat(32), // Unused in current implementation
                k_mac_i2r: "4e2ea40cb131c7d1e28bdca676195e69f3dd6fb0b88a4cceb5342f66bd4ca11c".into(),
                k_mac_r2i: "9ad57873567f373ff5793940b27f76117472c0084d97550c39ef07c9c2025003".into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vectors_parseable() {
        let vectors = SessionGoldenVector::load_all();
        assert!(!vectors.is_empty(), "vectors should be populated");
    }
}

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
            initiator_ephemeral_sk: "12".repeat(32),
            initiator_ephemeral_pk:
                "052a50773ac8d91773f2dc9662e12f0defe915e415b8a1c8e20a5a3d6ab2b843".into(),
            responder_ephemeral_sk: "34".repeat(32),
            responder_ephemeral_pk:
                "ffc951aa6f2fa03096d1d1b579735b2f6f84019fe2f617aa65ff3d68705f2527".into(),
            hello_nonce: "01".repeat(16),
            ack_nonce: "02".repeat(16),
            expected_shared_secret:
                "161e854907b902cf0ef64555458b3f0d86de9439c9eaf8595ea4834f8b4d0b0f".into(),
            session_id: "77".repeat(16),
            expected_keys: SessionDerivedKeys {
                k_ctx: "cf7f39884db5a0365e9529183e0664fbea8f585343b5a6c92de9e936aab6cc8f".into(),
                k_data: "00".repeat(32), // Unused in current implementation
                k_mac_i2r: "2114740f1b364fbaa79aead5054f827d66dd3a527415a9f198994c38314c2f4c"
                    .into(),
                k_mac_r2i: "ccf67f71dc2b558d95d173351cfbedadf20b88ca1dc8097dcd77eea42c0d4d8d"
                    .into(),
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

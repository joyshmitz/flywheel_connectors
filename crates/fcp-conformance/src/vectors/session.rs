//! Session handshake golden vectors.
//!
//! These vectors test the session handshake transcript and key derivation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
struct KeyScheduleVector {
    description: Option<String>,
    session_id: String,
    initiator_node_id: String,
    responder_node_id: String,
    initiator_ephemeral_sk: String,
    initiator_ephemeral_pk: String,
    responder_ephemeral_sk: String,
    responder_ephemeral_pk: String,
    hello_nonce: String,
    ack_nonce: String,
    shared_secret: String,
    k_mac_i2r: String,
    k_mac_r2i: String,
    k_ctx: String,
}

fn load_key_schedule_vector() -> KeyScheduleVector {
    let raw = include_str!("../../../../tests/vectors/sessions/key_schedule.json");
    serde_json::from_str(raw).expect("key_schedule.json must be valid JSON")
}

fn from_key_schedule(vector: KeyScheduleVector) -> SessionGoldenVector {
    SessionGoldenVector {
        description: vector
            .description
            .unwrap_or_else(|| "Session key schedule".to_string()),
        initiator_id: vector.initiator_node_id,
        responder_id: vector.responder_node_id,
        initiator_ephemeral_sk: vector.initiator_ephemeral_sk,
        initiator_ephemeral_pk: vector.initiator_ephemeral_pk,
        responder_ephemeral_sk: vector.responder_ephemeral_sk,
        responder_ephemeral_pk: vector.responder_ephemeral_pk,
        hello_nonce: vector.hello_nonce,
        ack_nonce: vector.ack_nonce,
        expected_shared_secret: vector.shared_secret,
        session_id: vector.session_id,
        expected_keys: SessionDerivedKeys {
            k_ctx: vector.k_ctx,
            k_data: "00".repeat(32),
            k_mac_i2r: vector.k_mac_i2r,
            k_mac_r2i: vector.k_mac_r2i,
        },
    }
}

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
        vec![from_key_schedule(load_key_schedule_vector())]
    }

    /// Vector 1: Basic handshake
    #[must_use]
    pub fn vector_1_basic_handshake() -> Self {
        from_key_schedule(load_key_schedule_vector())
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

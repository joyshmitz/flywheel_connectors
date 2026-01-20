//! FCPC (control-plane) golden vectors.
//!
//! These vectors test the FCPC frame encoding/decoding for control-plane messages.

use serde::{Deserialize, Serialize};

/// Golden vector for FCPC frame encoding/decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcpcGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Session ID bytes (16 bytes hex).
    pub session_id: String,
    /// Encryption key (32 bytes hex).
    pub key: String,
    /// Sequence number.
    pub seq: u64,
    /// Plaintext payload (hex).
    pub plaintext: String,
    /// Expected encoded frame (hex).
    pub expected_frame: String,
}

impl FcpcGoldenVector {
    /// Load all FCPC golden vectors.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: Vec allocation
    pub fn load_all() -> Vec<Self> {
        vec![Self {
            description: "FCPC seal vector (seq=1, i2r, default flags)".into(),
            session_id: "0102030405060708090a0b0c0d0e0f10".into(),
            key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .into(),
            seq: 1,
            plaintext: "48656c6c6f2c204643504321".into(),
            expected_frame: concat!(
                "4643504301000102030405060708090a0b0c0d0e0f10",
                "01000000000000000100",
                "0c000000",
                "d7329f33da068f5e6ae6ed7d",
                "d1e775d26470b07743efed714e38978d"
            )
            .into(),
        }]
    }

    /// Verify the golden vector against the implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the golden vector fails verification (e.g., decode
    /// errors, field mismatches, or invalid hex encoding).
    ///
    /// # Panics
    ///
    /// Panics if the hex-decoded bytes have unexpected length after validation.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_protocol::{FcpcFrame, FcpcFrameFlags, MeshSessionId, SessionDirection};

        let session_id_bytes =
            hex::decode(&self.session_id).map_err(|e| format!("invalid session_id hex: {e}"))?;
        let key_bytes = hex::decode(&self.key).map_err(|e| format!("invalid key hex: {e}"))?;
        let plaintext_bytes =
            hex::decode(&self.plaintext).map_err(|e| format!("invalid plaintext hex: {e}"))?;
        let expected_frame_bytes = hex::decode(&self.expected_frame)
            .map_err(|e| format!("invalid expected_frame hex: {e}"))?;

        if session_id_bytes.len() != 16 {
            return Err("session_id must be 16 bytes".into());
        }
        if key_bytes.len() != 32 {
            return Err("key must be 32 bytes".into());
        }

        let session_id = MeshSessionId(session_id_bytes.try_into().unwrap());
        let k_ctx = key_bytes.try_into().unwrap();

        // 1. Verify decoding
        let decoded =
            FcpcFrame::decode(&expected_frame_bytes).map_err(|e| format!("decode failed: {e}"))?;

        // 2. Verify header fields
        if decoded.header.session_id != session_id {
            return Err(format!(
                "session_id mismatch: got {:?}, want {:?}",
                decoded.header.session_id, session_id
            ));
        }
        if decoded.header.seq != self.seq {
            return Err(format!(
                "seq mismatch: got {}, want {}",
                decoded.header.seq, self.seq
            ));
        }

        // 3. Verify decryption
        // Note: Golden vectors usually assume InitiatorToResponder for simplicity unless specified
        let decrypted = decoded
            .open(SessionDirection::InitiatorToResponder, &k_ctx)
            .map_err(|e| format!("decrypt failed: {e}"))?;

        if decrypted != plaintext_bytes {
            return Err("decrypted plaintext mismatch".into());
        }

        // 4. Verify encoding (roundtrip)
        let sealed = FcpcFrame::seal(
            session_id,
            self.seq,
            SessionDirection::InitiatorToResponder,
            FcpcFrameFlags::default(),
            &plaintext_bytes,
            &k_ctx,
        )
        .map_err(|e| format!("seal failed: {e}"))?;

        let encoded = sealed.encode();
        // Encoded bytes might differ if AAD/Tags are non-deterministic, but for ChaCha20Poly1305 they should be deterministic given key/nonce
        // However, `seal` uses `from_counter_directional` which matches what we expect.
        if encoded != expected_frame_bytes {
            return Err("re-encoding mismatch".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vectors_parseable() {
        let vectors = FcpcGoldenVector::load_all();
        assert!(!vectors.is_empty(), "vectors should be populated");
    }
}

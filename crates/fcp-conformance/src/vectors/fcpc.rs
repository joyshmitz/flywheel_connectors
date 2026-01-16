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
        // TODO: Load from embedded CBOR/JSON files
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vectors_parseable() {
        let vectors = FcpcGoldenVector::load_all();
        // Currently empty, will be populated by conformance bead
        assert!(vectors.is_empty(), "vectors not yet populated");
    }
}

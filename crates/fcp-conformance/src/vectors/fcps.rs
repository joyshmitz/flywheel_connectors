//! FCPS (data-plane) golden vectors.
//!
//! These vectors test the FCPS frame encoding/decoding for symbol distribution.

use serde::{Deserialize, Serialize};

/// Golden vector for FCPS frame encoding/decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcpsGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Object ID (hex).
    pub object_id: String,
    /// Symbol index.
    pub symbol_index: u32,
    /// Symbol data (hex).
    pub symbol_data: String,
    /// Expected encoded frame (hex).
    pub expected_frame: String,
}

impl FcpsGoldenVector {
    /// Load all FCPS golden vectors.
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
        let vectors = FcpsGoldenVector::load_all();
        // Currently empty, will be populated by conformance bead
        assert!(vectors.is_empty(), "vectors not yet populated");
    }
}

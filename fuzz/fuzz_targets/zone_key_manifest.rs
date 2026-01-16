//! ZoneKeyManifest Fuzz Target (flywheel_connectors-1n78.6)
//!
//! Fuzzes ZoneKeyManifest parsing and HPKE unseal behavior including:
//! - CBOR deserialization with arbitrary input
//! - Wrapped key lookup by node ID
//! - HPKE unseal attempts with random keys
//!
//! Goal: Ensure no panics on arbitrary input; validate DoS resistance.

#![no_main]

use fcp_core::{TailscaleNodeId, ZoneKeyManifest};
use fcp_crypto::X25519SecretKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz CBOR deserialization of ZoneKeyManifest
    // This tests struct field parsing, nested types, and malformed CBOR handling
    if let Ok(manifest) = ciborium::from_reader::<ZoneKeyManifest, _>(data) {
        // If parsing succeeds, exercise the wrapped key lookup methods
        // These should never panic regardless of internal data

        // Test wrapped zone key lookup with various node IDs
        for node_id_str in ["node-1", "node-2", "", "x".repeat(256).as_str()] {
            let node_id = TailscaleNodeId::new(node_id_str);
            let _ = manifest.wrapped_key_for(&node_id);
            let _ = manifest.wrapped_object_id_key_for(&node_id);
        }

        // Test HPKE unseal behavior with a random key
        // The unseal should fail gracefully (wrong key), never panic
        let test_sk = X25519SecretKey::generate();

        for wrapped in &manifest.wrapped_keys {
            // Attempt to unseal with wrong key - should fail, not panic
            let _ = fcp_core::unwrap_zone_key(&test_sk, &manifest.zone_id, wrapped);
        }

        for wrapped in &manifest.wrapped_object_id_keys {
            // Attempt to unseal with wrong key - should fail, not panic
            let _ = fcp_core::unwrap_object_id_key(&test_sk, &manifest.zone_id, wrapped);
        }

        // Test field accessors
        let _ = manifest.zone_id.as_str();
        let _ = manifest.zone_key_id.as_bytes();
        let _ = manifest.object_id_key_id.as_bytes();
        let _ = format!("{:?}", manifest.algorithm);
        let _ = manifest.prev_zone_key_id;
        let _ = manifest.rekey_policy.as_ref();
    }

    // Also fuzz individual component types that appear in ZoneKeyManifest
    // These help find issues in nested structure parsing

    // Fuzz WrappedZoneKey parsing
    let _ = ciborium::from_reader::<fcp_core::WrappedZoneKey, _>(data);

    // Fuzz WrappedObjectIdKey parsing
    let _ = ciborium::from_reader::<fcp_core::WrappedObjectIdKey, _>(data);

    // Fuzz RekeyPolicy parsing
    let _ = ciborium::from_reader::<fcp_core::RekeyPolicy, _>(data);

    // Fuzz ZoneKeyId parsing
    let _ = ciborium::from_reader::<fcp_core::ZoneKeyId, _>(data);

    // Fuzz ObjectIdKeyId parsing
    let _ = ciborium::from_reader::<fcp_core::ObjectIdKeyId, _>(data);

    // Fuzz ZoneKeyAlgorithm parsing
    let _ = ciborium::from_reader::<fcp_core::ZoneKeyAlgorithm, _>(data);
});

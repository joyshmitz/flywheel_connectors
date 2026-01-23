//! Generate golden vectors for fcp-bootstrap tests.
//!
//! Run with: `cargo run -p fcp-bootstrap --example generate_golden_vectors`

use fcp_bootstrap::{GenesisState, RecoveryPhrase};
use std::fs;
use std::path::Path;

/// Well-known test mnemonic (DO NOT USE FOR REAL KEYS).
const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn main() {
    // Derive keypair from test mnemonic
    let phrase =
        RecoveryPhrase::from_mnemonic(TEST_MNEMONIC).expect("Test mnemonic should be valid");
    let keypair = phrase.derive_owner_keypair();

    // Create deterministic genesis
    let genesis = GenesisState::create_deterministic(&keypair.public());

    // Get fingerprint
    let fingerprint = genesis.fingerprint();
    println!("Genesis fingerprint: {fingerprint}");

    // Serialize to CBOR
    let cbor = genesis.to_cbor().expect("CBOR serialization should work");
    println!("Genesis CBOR length: {} bytes", cbor.len());

    // Write to test vectors directory
    let vectors_dir = Path::new("crates/fcp-bootstrap/tests/vectors");
    fs::create_dir_all(vectors_dir).expect("Failed to create vectors directory");

    let fingerprint_path = vectors_dir.join("expected_fingerprint.txt");
    fs::write(&fingerprint_path, format!("{fingerprint}\n")).expect("Failed to write fingerprint");
    println!("Wrote fingerprint to: {}", fingerprint_path.display());

    let cbor_path = vectors_dir.join("genesis.cbor");
    fs::write(&cbor_path, &cbor).expect("Failed to write CBOR");
    println!("Wrote CBOR to: {}", cbor_path.display());

    // Verify roundtrip
    let restored = GenesisState::from_cbor(&cbor).expect("CBOR deserialization should work");
    assert_eq!(
        genesis.fingerprint(),
        restored.fingerprint(),
        "Fingerprints should match after roundtrip"
    );
    println!("Roundtrip verification: OK");
}

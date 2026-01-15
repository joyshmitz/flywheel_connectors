//! Capability Token Fuzz Target (flywheel_connectors-nlz4)
//!
//! Fuzzes COSE_Sign1 token parsing and CWT claims extraction.
//! Goal: Ensure no panics or undefined behavior on arbitrary input.

#![no_main]

use fcp_crypto::cose::{CoseToken, CwtClaims};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz COSE_Sign1 parsing
    // This tests the CBOR parser and COSE structure validation
    let _ = CoseToken::from_cbor(data);

    // Fuzz CWT claims CBOR parsing
    // This tests the claims map parsing
    let _ = CwtClaims::from_cbor(data);
});

//! FCPS Frame Fuzz Target (flywheel_connectors-1n78.12)
//!
//! Fuzzes FCPS frame parsing including:
//! - Header decoding (magic, version, flags, lengths)
//! - Symbol record parsing
//! - Full frame decoding with MTU enforcement
//!
//! Goal: Ensure no panics on arbitrary input; validate DoS resistance.

#![no_main]

use fcp_protocol::{FcpsFrame, FcpsFrameHeader, FrameFlags, SymbolRecord};
use libfuzzer_sys::fuzz_target;

/// Maximum MTU for fuzz testing (64 KiB is generous).
const FUZZ_MTU: usize = 65536;

fuzz_target!(|data: &[u8]| {
    // Fuzz header decoding
    // This tests magic validation, version check, and field parsing
    let _ = FcpsFrameHeader::decode(data);

    // Fuzz full frame decoding with bounded MTU
    // This tests length validation and symbol record parsing
    let _ = FcpsFrame::decode(data, FUZZ_MTU);

    // Fuzz symbol record parsing with various symbol sizes
    // Tests for off-by-one errors and length miscalculations
    for symbol_size in [1u16, 64, 128, 256, 512, 1024, 2048] {
        let _ = SymbolRecord::decode(data, symbol_size);
    }

    // Fuzz frame flags parsing (should never panic, just truncate unknown bits)
    if data.len() >= 2 {
        let flags_bits = u16::from_le_bytes([data[0], data[1]]);
        let _ = FrameFlags::from_bits_truncate(flags_bits);
    }
});

//! FCPC Frame Fuzz Target (flywheel_connectors-1n78.13)
//!
//! Fuzzes FCPC control-plane frame parsing including:
//! - Header decoding (magic, version, session_id, seq, flags, length)
//! - Full frame decoding with payload limit enforcement
//! - Frame flags parsing
//!
//! Goal: Ensure no panics on arbitrary input; validate DoS resistance.

#![no_main]

use fcp_protocol::{FcpcFrame, FcpcFrameFlags, FcpcFrameHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz header decoding
    // Tests magic validation, version check, session_id parsing, seq/flags/len fields
    let _ = FcpcFrameHeader::decode(data);

    // Fuzz full frame decoding with default limit (4 MiB)
    let _ = FcpcFrame::decode(data);

    // Fuzz frame decoding with various payload limits
    for limit in [64, 256, 1024, 4096, 65536] {
        let _ = FcpcFrame::decode_with_limit(data, limit);
    }

    // Fuzz frame flags parsing (should never panic, just truncate unknown bits)
    if data.len() >= 2 {
        let flags_bits = u16::from_le_bytes([data[0], data[1]]);
        let _ = FcpcFrameFlags::from_bits_truncate(flags_bits);
    }

    // Test boundary conditions at minimum valid frame size
    // FCPC_HEADER_LEN (36) + FCPC_TAG_LEN (16) = 52 bytes minimum
    let _ = FcpcFrame::decode_with_limit(data, 0);
});

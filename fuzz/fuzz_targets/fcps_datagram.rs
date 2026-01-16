//! FCPS Datagram Fuzz Target (flywheel_connectors-1n78.12)
//!
//! Fuzzes FCPS datagram parsing (session layer):
//! - FcpsDatagram decode with various MTU limits
//! - Boundary conditions at various transport limits
//!
//! Goal: Ensure no panics on arbitrary input; validate length bounds checks.

#![no_main]

use fcp_protocol::{FcpsDatagram, FCPS_DATAGRAM_HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz datagram decoding with default reasonable limit (1500 bytes ~ MTU)
    let _ = FcpsDatagram::decode(data, 1500);

    // Fuzz with minimum reasonable transport limits
    let _ = FcpsDatagram::decode(data, 1024);

    // Fuzz with generous transport limits
    let _ = FcpsDatagram::decode(data, 65535);

    // Fuzz at exactly the header size boundary
    let _ = FcpsDatagram::decode(data, FCPS_DATAGRAM_HEADER_LEN as u16);
});

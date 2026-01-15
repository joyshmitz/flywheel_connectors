#![no_main]

use fcp_protocol::{decode_ack_cbor, decode_cookie_bytes, decode_hello_cbor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_hello_cbor(data);
    let _ = decode_ack_cbor(data);
    let _ = decode_cookie_bytes(data);
});

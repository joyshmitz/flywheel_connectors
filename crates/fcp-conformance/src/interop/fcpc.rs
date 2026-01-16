//! FCPC control-plane interop tests.
//!
//! Tests for FCPC frame parsing, ordering, bounded replay window,
//! and k_ctx AEAD integrity verification.

use crate::{InteropTestSummary, TestFailure};

/// FCPC interop test suite.
pub struct FcpcInteropTests;

impl FcpcInteropTests {
    /// Run all FCPC interop tests.
    pub fn run() -> InteropTestSummary {
        run_tests()
    }
}

/// Run all FCPC interop tests.
pub fn run_tests() -> InteropTestSummary {
    let mut summary = InteropTestSummary::default();

    // Test 1: Frame header parsing
    run_test(&mut summary, "header_parsing", test_header_parsing);

    // Test 2: AEAD encryption with k_ctx
    run_test(&mut summary, "aead_encryption", test_aead_encryption);

    // Test 3: Direction affects nonce
    run_test(&mut summary, "direction_nonce", test_direction_nonce);

    // Test 4: Bounded replay window
    run_test(&mut summary, "replay_window", test_replay_window);

    // Test 5: Sequence ordering
    run_test(&mut summary, "sequence_ordering", test_sequence_ordering);

    // Test 6: AAD binding
    run_test(&mut summary, "aad_binding", test_aad_binding);

    // Test 7: Flag encoding
    run_test(&mut summary, "flag_encoding", test_flag_encoding);

    summary
}

fn run_test<F>(summary: &mut InteropTestSummary, name: &str, test_fn: F)
where
    F: FnOnce() -> Result<(), String>,
{
    summary.total += 1;
    match test_fn() {
        Ok(()) => summary.passed += 1,
        Err(msg) => {
            summary.failed += 1;
            summary.failures.push(TestFailure {
                name: name.to_string(),
                category: "fcpc".to_string(),
                message: msg,
            });
        }
    }
}

/// Test: Frame header parsing from golden vectors.
fn test_header_parsing() -> Result<(), String> {
    use crate::vectors::fcpc::FcpcGoldenVector;

    // All golden vectors should parse correctly
    for (i, vector) in FcpcGoldenVector::load_all().iter().enumerate() {
        vector.verify().map_err(|e| {
            format!(
                "Vector {} ({}) header parsing failed: {}",
                i + 1,
                vector.description,
                e
            )
        })?;
    }

    Ok(())
}

/// Test: AEAD encryption with k_ctx key.
fn test_aead_encryption() -> Result<(), String> {
    use fcp_crypto::{AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher};

    // FCPC uses ChaCha20-Poly1305 with k_ctx as the key
    let k_ctx = AeadKey::from_bytes([0x11u8; 32]);
    let nonce = ChaCha20Nonce::from_bytes([0x00u8; 12]); // Simplified nonce for testing
    let plaintext = b"control plane message";
    let aad = b"session_id||seq||flags";

    let cipher = ChaCha20Poly1305Cipher::new(&k_ctx);

    // Encrypt
    let ciphertext = cipher
        .encrypt(&nonce, plaintext, aad)
        .map_err(|e| format!("encrypt failed: {e}"))?;

    // Ciphertext should include 16-byte tag
    if ciphertext.len() != plaintext.len() + 16 {
        return Err(format!(
            "ciphertext length {} != plaintext {} + 16",
            ciphertext.len(),
            plaintext.len()
        ));
    }

    // Decrypt should recover plaintext
    let decrypted = cipher
        .decrypt(&nonce, &ciphertext, aad)
        .map_err(|e| format!("decrypt failed: {e}"))?;

    if decrypted != plaintext {
        return Err("decrypted plaintext mismatch".to_string());
    }

    // Wrong key should fail
    let wrong_key = AeadKey::from_bytes([0x22u8; 32]);
    let wrong_cipher = ChaCha20Poly1305Cipher::new(&wrong_key);
    if wrong_cipher.decrypt(&nonce, &ciphertext, aad).is_ok() {
        return Err("decryption with wrong key should fail".to_string());
    }

    Ok(())
}

/// Test: Direction byte affects nonce construction.
fn test_direction_nonce() -> Result<(), String> {
    // FCPC nonce format: seq (8 bytes) + direction (1 byte) + padding (3 bytes)
    // Direction: 0 = initiator-to-responder, 1 = responder-to-initiator

    let seq: u64 = 42;

    let nonce_i2r = build_fcpc_nonce(seq, 0);
    let nonce_r2i = build_fcpc_nonce(seq, 1);

    // Same seq, different direction should produce different nonces
    if nonce_i2r == nonce_r2i {
        return Err("different directions should produce different nonces".to_string());
    }

    // Same seq, same direction should produce identical nonce
    let nonce_i2r_again = build_fcpc_nonce(seq, 0);
    if nonce_i2r != nonce_i2r_again {
        return Err("same inputs should produce identical nonce".to_string());
    }

    // Different seq should produce different nonce
    let nonce_diff_seq = build_fcpc_nonce(seq + 1, 0);
    if nonce_i2r == nonce_diff_seq {
        return Err("different seq should produce different nonce".to_string());
    }

    Ok(())
}

/// Build FCPC nonce from sequence number and direction.
fn build_fcpc_nonce(seq: u64, direction: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&seq.to_le_bytes());
    nonce[8] = direction;
    // Bytes 9-11 are padding (zeros)
    nonce
}

/// Test: Bounded replay window for control plane.
fn test_replay_window() -> Result<(), String> {
    // FCPC uses a bounded replay window to detect replayed frames
    // Window size: 64 sequence numbers (same as FCPS)

    let mut window = ControlPlaneReplayWindow::new(64);

    // Accept initial sequence
    if !window.accept(0) {
        return Err("initial seq 0 rejected".to_string());
    }

    // Reject replay
    if window.accept(0) {
        return Err("replay of seq 0 accepted".to_string());
    }

    // Accept higher sequences
    for seq in 1..10 {
        if !window.accept(seq) {
            return Err(format!("seq {seq} rejected"));
        }
    }

    // Out-of-order within window should work
    // Already accepted 0-9, skip 10, accept 11
    if !window.accept(11) {
        return Err("seq 11 rejected".to_string());
    }

    // Now 10 should still be acceptable (within window)
    if !window.accept(10) {
        return Err("seq 10 rejected (should be within window)".to_string());
    }

    // Replay of 10 should fail
    if window.accept(10) {
        return Err("replay of seq 10 accepted".to_string());
    }

    Ok(())
}

/// Replay window for control plane sequence numbers.
struct ControlPlaneReplayWindow {
    size: u64,
    highest_seen: u64,
    seen_bitmap: u64,
}

impl ControlPlaneReplayWindow {
    fn new(size: u64) -> Self {
        Self {
            size: size.min(64),
            highest_seen: 0,
            seen_bitmap: 0,
        }
    }

    fn accept(&mut self, seq: u64) -> bool {
        if seq > self.highest_seen {
            // New highest: slide window
            let diff = seq - self.highest_seen;
            if diff >= self.size {
                self.seen_bitmap = 1;
            } else {
                self.seen_bitmap <<= diff;
                self.seen_bitmap |= 1;
            }
            self.highest_seen = seq;
            true
        } else if self.highest_seen - seq >= self.size {
            // Too old
            false
        } else {
            // Within window
            let bit_index = self.highest_seen - seq;
            let mask = 1u64 << bit_index;
            if self.seen_bitmap & mask != 0 {
                false
            } else {
                self.seen_bitmap |= mask;
                true
            }
        }
    }
}

/// Test: Sequence ordering for control plane messages.
fn test_sequence_ordering() -> Result<(), String> {
    // Control plane messages should be processed in order
    // Out-of-order messages should be buffered or rejected based on policy

    let mut ordered_processor = OrderedProcessor::new();

    // Process in order: 0, 1, 2
    for seq in 0..3 {
        ordered_processor.process(seq);
    }

    if ordered_processor.next_expected != 3 {
        return Err(format!(
            "expected next_expected=3, got {}",
            ordered_processor.next_expected
        ));
    }

    // Process out of order: 5 before 3, 4
    ordered_processor.process(5);
    if ordered_processor.buffered.len() != 1 {
        return Err(format!(
            "expected 1 buffered, got {}",
            ordered_processor.buffered.len()
        ));
    }

    // Now process 3 and 4, should drain buffer
    ordered_processor.process(3);
    ordered_processor.process(4);

    // After processing 3, 4, 5 should all be done
    if ordered_processor.next_expected != 6 {
        return Err(format!(
            "expected next_expected=6 after drain, got {}",
            ordered_processor.next_expected
        ));
    }

    Ok(())
}

/// Simple ordered message processor for testing.
struct OrderedProcessor {
    next_expected: u64,
    buffered: Vec<u64>,
}

impl OrderedProcessor {
    fn new() -> Self {
        Self {
            next_expected: 0,
            buffered: Vec::new(),
        }
    }

    fn process(&mut self, seq: u64) {
        if seq == self.next_expected {
            self.next_expected += 1;
            // Drain any buffered sequences that are now ready
            self.drain_buffer();
        } else if seq > self.next_expected {
            // Buffer for later
            self.buffered.push(seq);
            self.buffered.sort_unstable();
        }
        // Ignore seq < next_expected (already processed)
    }

    fn drain_buffer(&mut self) {
        while let Some(&next) = self.buffered.first() {
            if next == self.next_expected {
                self.buffered.remove(0);
                self.next_expected += 1;
            } else {
                break;
            }
        }
    }
}

/// Test: AAD binding for FCPC frames.
fn test_aad_binding() -> Result<(), String> {
    // FCPC AAD: session_id (16) || seq (8 LE) || flags (2 LE)

    let session_id = [0xAAu8; 16];
    let seq: u64 = 100;
    let flags: u16 = 0x0001;

    let aad = build_fcpc_aad(&session_id, seq, flags);

    // AAD should be exactly 26 bytes
    if aad.len() != 26 {
        return Err(format!("AAD length {} != 26", aad.len()));
    }

    // Verify structure
    if &aad[0..16] != &session_id {
        return Err("AAD session_id mismatch".to_string());
    }
    if &aad[16..24] != &seq.to_le_bytes() {
        return Err("AAD seq mismatch".to_string());
    }
    if &aad[24..26] != &flags.to_le_bytes() {
        return Err("AAD flags mismatch".to_string());
    }

    // Different session_id should produce different AAD
    let session_id_2 = [0xBBu8; 16];
    let aad_2 = build_fcpc_aad(&session_id_2, seq, flags);
    if aad == aad_2 {
        return Err("different session_id should produce different AAD".to_string());
    }

    Ok(())
}

/// Build FCPC AAD from components.
fn build_fcpc_aad(session_id: &[u8; 16], seq: u64, flags: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(26);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&seq.to_le_bytes());
    aad.extend_from_slice(&flags.to_le_bytes());
    aad
}

/// Test: FCPC frame flag encoding.
fn test_flag_encoding() -> Result<(), String> {
    // FCPC flags are a u16 bitfield
    // Bit 0: ENCRYPTED
    // Bit 1: COMPRESSED

    let encrypted = 0x0001u16;
    let compressed = 0x0002u16;
    let both = 0x0003u16;

    // Test flag composition
    if encrypted | compressed != both {
        return Err("flag composition mismatch".to_string());
    }

    // Test flag extraction
    if both & encrypted != encrypted {
        return Err("ENCRYPTED flag not set in combined".to_string());
    }
    if both & compressed != compressed {
        return Err("COMPRESSED flag not set in combined".to_string());
    }

    // Encoding should be little-endian
    let encoded = both.to_le_bytes();
    if encoded != [0x03, 0x00] {
        return Err(format!(
            "flag encoding mismatch: expected [0x03, 0x00], got {:?}",
            encoded
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fcpc_interop_tests_pass() {
        let summary = run_tests();
        for failure in &summary.failures {
            eprintln!("FAIL: {} - {}", failure.name, failure.message);
        }
        assert!(
            summary.all_passed(),
            "FCPC interop tests failed: {}/{} passed",
            summary.passed,
            summary.total
        );
    }

    #[test]
    fn test_nonce_construction() {
        let nonce = build_fcpc_nonce(1, 0);
        // First 8 bytes should be seq=1 in LE
        assert_eq!(&nonce[..8], &1u64.to_le_bytes());
        // Byte 8 should be direction=0
        assert_eq!(nonce[8], 0);
    }

    #[test]
    fn test_replay_window_window_slide() {
        let mut window = ControlPlaneReplayWindow::new(64);

        // Accept 0
        assert!(window.accept(0));

        // Jump to 100, should slide window
        assert!(window.accept(100));

        // 0 should now be outside window
        assert!(!window.accept(0));

        // 50 should be outside window (100 - 50 = 50 >= 64? No, 50 < 64)
        // Actually 100 - 50 = 50 which is < 64, so it should be within window
        assert!(window.accept(50));
    }
}

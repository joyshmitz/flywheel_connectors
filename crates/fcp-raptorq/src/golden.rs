//! Golden vector tests for `RaptorQ` encoding/decoding.
//!
//! These tests verify deterministic behavior and provide reference test vectors.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use raptorq::{Decoder, EncodingPacket, PayloadId};

    use crate::{
        ChunkedObjectManifest, DecodeAdmissionController, EncodingDecision, RaptorQConfig,
        RaptorQDecoder, RaptorQEncoder,
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Configuration
    // ─────────────────────────────────────────────────────────────────────────

    /// Standard configuration for golden vector tests.
    fn golden_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 500,
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        }
    }

    /// Create a deterministic payload of given size.
    fn deterministic_payload(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: 1KB Object
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_1kb_symbol_count() {
        let config = golden_config();
        let payload = deterministic_payload(1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // 1024 bytes / 1024 byte symbols = 1 source symbol
        assert_eq!(encoder.source_symbols(), 1);
        // 5% of 1 = 0 repair symbols (rounds down)
        assert_eq!(encoder.repair_symbols(), 0);
        assert_eq!(encoder.total_symbols(), 1);
    }

    #[test]
    fn golden_1kb_roundtrip() {
        let config = golden_config();
        let payload = deterministic_payload(1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // Decode with all symbols
        let mut decoder = Decoder::new(oti);
        for (esi, data) in symbols {
            let packet = EncodingPacket::new(PayloadId::new(0, esi), data);
            if let Some(decoded) = decoder.decode(packet) {
                assert_eq!(decoded, payload);
                return;
            }
        }
        panic!("Failed to decode 1KB payload");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: 10KB Object
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_10kb_symbol_count() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // 10KB / 1024 byte symbols = 10 source symbols
        assert_eq!(encoder.source_symbols(), 10);
        // 5% of 10 = 0 repair symbols (rounds down)
        assert_eq!(encoder.repair_symbols(), 0);
    }

    #[test]
    fn golden_10kb_roundtrip() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = Decoder::new(oti);
        for (esi, data) in symbols {
            let packet = EncodingPacket::new(PayloadId::new(0, esi), data);
            if let Some(decoded) = decoder.decode(packet) {
                assert_eq!(decoded, payload);
                return;
            }
        }
        panic!("Failed to decode 10KB payload");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: 100KB Object
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_100kb_symbol_count() {
        let config = golden_config();
        let payload = deterministic_payload(100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

        // 100KB / 1024 byte symbols = 100 source symbols
        assert_eq!(encoder.source_symbols(), 100);
        // 5% of 100 = 5 repair symbols
        assert_eq!(encoder.repair_symbols(), 5);
        assert_eq!(encoder.total_symbols(), 105);
    }

    #[test]
    fn golden_100kb_roundtrip() {
        let config = golden_config();
        let payload = deterministic_payload(100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = Decoder::new(oti);
        for (esi, data) in symbols {
            let packet = EncodingPacket::new(PayloadId::new(0, esi), data);
            if let Some(decoded) = decoder.decode(packet) {
                assert_eq!(decoded, payload);
                return;
            }
        }
        panic!("Failed to decode 100KB payload");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests: Chunked Object (300KB)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_300kb_chunked_manifest() {
        let config = golden_config();
        let payload = deterministic_payload(300 * 1024);

        // Should use chunked encoding (> 256KB threshold)
        assert!(config.requires_chunking(300 * 1024));

        let decision = EncodingDecision::for_payload(&payload, &config).unwrap();
        assert!(decision.is_chunked());

        if let EncodingDecision::Chunked { manifest, chunks } = decision {
            // 300KB / 64KB chunks = 4.6875 -> 5 chunks
            assert_eq!(manifest.chunk_count(), 5);
            assert_eq!(chunks.len(), 5);
            assert_eq!(manifest.total_len, 300 * 1024);
            assert_eq!(manifest.chunk_size, 64 * 1024);

            // First 4 chunks should be 64KB
            assert_eq!(chunks[0].len(), 64 * 1024);
            assert_eq!(chunks[1].len(), 64 * 1024);
            assert_eq!(chunks[2].len(), 64 * 1024);
            assert_eq!(chunks[3].len(), 64 * 1024);

            // Last chunk is remainder: 300KB - 4*64KB = 44KB
            assert_eq!(chunks[4].len(), 300 * 1024 - 4 * 64 * 1024);

            // Reconstruct and verify
            let reconstructed = manifest.reconstruct(&chunks).unwrap();
            assert_eq!(reconstructed, payload);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Erasure Recovery Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn erasure_recovery_with_repair_symbols() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 2000, // 20% repair for better erasure recovery
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let payload = deterministic_payload(100 * 1024);
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        // K = 100, repair = 20% = 20, total = 120
        assert_eq!(encoder.source_symbols(), 100);
        assert_eq!(encoder.repair_symbols(), 20);

        // Simulate 10% erasure by skipping every 10th symbol
        let mut decoder = Decoder::new(oti);
        for (i, (esi, data)) in symbols.into_iter().enumerate() {
            if i % 10 == 0 {
                continue; // Skip every 10th symbol
            }
            let packet = EncodingPacket::new(PayloadId::new(0, esi), data);
            if let Some(decoded) = decoder.decode(packet) {
                assert_eq!(decoded, payload);
                return;
            }
        }
        panic!("Failed to recover from 10% erasure");
    }

    #[test]
    fn erasure_recovery_from_repair_only() {
        // Test decoding using only repair symbols (skipping all source symbols)
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 10000, // 100% repair (K repair symbols)
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let payload = deterministic_payload(10 * 1024);
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let k = encoder.source_symbols();

        // Use only repair symbols (ESI >= K)
        let mut decoder = Decoder::new(oti);
        for (esi, data) in symbols.into_iter() {
            if esi < k {
                continue; // Skip source symbols
            }
            let packet = EncodingPacket::new(PayloadId::new(0, esi), data);
            if let Some(decoded) = decoder.decode(packet) {
                assert_eq!(decoded, payload);
                return;
            }
        }
        panic!("Failed to decode from repair symbols only");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Symbol Determinism Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbols_are_deterministic() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        // Encode twice
        let encoder1 = RaptorQEncoder::new(&payload, &config).unwrap();
        let encoder2 = RaptorQEncoder::new(&payload, &config).unwrap();

        let symbols1 = encoder1.encode_all();
        let symbols2 = encoder2.encode_all();

        // Same payload produces same symbols
        assert_eq!(symbols1.len(), symbols2.len());
        for ((esi1, data1), (esi2, data2)) in symbols1.iter().zip(symbols2.iter()) {
            assert_eq!(esi1, esi2);
            assert_eq!(data1, data2);
        }
    }

    #[test]
    fn symbol_esi_uniqueness() {
        let config = golden_config();
        let payload = deterministic_payload(100 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();

        // All ESIs should be unique
        let mut seen_esis = std::collections::HashSet::new();
        for (esi, _) in &symbols {
            assert!(seen_esis.insert(*esi), "Duplicate ESI found: {esi}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DoS Mitigation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn dos_reject_oversized_payload() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024, // 1MB limit
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        // 2MB payload should be rejected
        let oversized = vec![0u8; 2 * 1024 * 1024];
        let result = RaptorQEncoder::new(&oversized, &config);
        assert!(result.is_err());
    }

    #[test]
    fn dos_concurrent_decode_limit() {
        let controller = DecodeAdmissionController::with_limits(
            2, // Only 2 concurrent
            64 * 1024 * 1024,
            Duration::from_secs(30),
            10000,
        );

        let permit1 = controller.try_acquire();
        let permit2 = controller.try_acquire();
        let permit3 = controller.try_acquire();

        assert!(permit1.is_some());
        assert!(permit2.is_some());
        assert!(permit3.is_none()); // Third should fail

        drop(permit1);
        let permit4 = controller.try_acquire();
        assert!(permit4.is_some()); // Now it should work
    }

    #[test]
    fn dos_decode_timeout() {
        let config = RaptorQConfig {
            symbol_size: 1024,
            repair_ratio_bps: 500,
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_millis(1), // Very short timeout
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        };

        let oti = raptorq::ObjectTransmissionInformation::new(1024, 1024, 1, 1, 8);
        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        // Should be timed out
        assert!(decoder.is_timed_out());
        let result = decoder.add_symbol(0, vec![0u8; 1024]);
        assert!(result.is_err());
    }

    #[test]
    fn dos_symbol_buffer_limit() {
        let controller = DecodeAdmissionController::with_limits(
            1,
            64 * 1024 * 1024,
            Duration::from_secs(30),
            3, // Only 3 symbols allowed
        );

        let mut permit = controller.try_acquire().unwrap();

        // First 3 should succeed
        assert!(permit.try_buffer_symbol(1024).is_ok());
        assert!(permit.try_buffer_symbol(1024).is_ok());
        assert!(permit.try_buffer_symbol(1024).is_ok());

        // Fourth should fail
        assert!(permit.try_buffer_symbol(1024).is_err());
    }

    #[test]
    fn dos_memory_limit() {
        let controller = DecodeAdmissionController::with_limits(
            1,
            2048, // Only 2KB memory
            Duration::from_secs(30),
            10000,
        );

        let mut permit = controller.try_acquire().unwrap();

        assert!(permit.try_buffer_symbol(1024).is_ok());
        assert!(permit.try_buffer_symbol(1024).is_ok());
        // Third 1KB should exceed 2KB limit
        assert!(permit.try_buffer_symbol(1024).is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Decode Status Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decode_status_tracking() {
        let config = golden_config();
        let oti = raptorq::ObjectTransmissionInformation::new(10 * 1024, 1024, 1, 1, 8);
        let decoder = RaptorQDecoder::new(oti, &config);

        // Initial state
        assert_eq!(decoder.received_count(), 0);
        assert_eq!(decoder.expected_k(), 10);
        assert!(!decoder.likely_complete());
    }

    #[test]
    fn decode_status_progress() {
        let config = golden_config();
        let payload = deterministic_payload(10 * 1024);

        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let symbols = encoder.encode_all();
        let oti = encoder.transmission_info();

        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Add symbols one by one
        for (i, (esi, data)) in symbols.into_iter().enumerate() {
            let _ = decoder.add_symbol(esi, data);
            assert_eq!(decoder.received_count(), (i + 1) as u32);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Chunk Manifest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn chunk_ids_are_deterministic() {
        let payload = deterministic_payload(300 * 1024);
        let config = golden_config();

        let (manifest1, chunks1) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);
        let (manifest2, chunks2) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        // Same payload produces same chunk IDs
        assert_eq!(manifest1.chunks, manifest2.chunks);
        assert_eq!(chunks1.len(), chunks2.len());

        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.content_id(), c2.content_id());
        }
    }

    #[test]
    fn chunk_ordering_deterministic() {
        let payload = deterministic_payload(300 * 1024);
        let config = golden_config();

        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        // Reconstruct to verify ordering
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);

        // Verify chunks are in correct order
        let mut offset = 0;
        for chunk in &chunks {
            let expected_data = &payload[offset..offset + chunk.len()];
            assert_eq!(chunk.bytes.as_slice(), expected_data);
            offset += chunk.len();
        }
    }

    #[test]
    fn chunk_hash_verification() {
        let payload = deterministic_payload(300 * 1024);
        let config = golden_config();

        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, config.chunk_size);

        // Valid payload passes verification
        assert!(manifest.verify_hash(&payload));

        // Modified payload fails verification
        let mut modified = payload.clone();
        modified[0] = 255;
        assert!(!manifest.verify_hash(&modified));

        // Corrupted chunk fails reconstruction
        let mut corrupted_chunks = chunks.clone();
        corrupted_chunks[0].bytes[0] = 255;
        assert!(manifest.reconstruct(&corrupted_chunks).is_err());
    }
}

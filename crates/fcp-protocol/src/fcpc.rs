//! FCPC (Flywheel Connector Protocol - Control) frame parsing and serialization.
//!
//! Implements the normative control-plane framing defined in `FCP_Specification_V2.md` §9.4.
//! Frames are authenticated (and by default encrypted) with the session `k_ctx`.

use bitflags::bitflags;
use fcp_crypto::aead::{AEAD_TAG_SIZE, chacha20_decrypt, chacha20_encrypt};
use fcp_crypto::{AeadKey, ChaCha20Nonce, CryptoError};
use thiserror::Error;

use crate::{MeshSessionId, ReplayWindow, SessionDirection, SessionReplayPolicy};

/// FCPC magic bytes: "FCPC".
pub const FCPC_MAGIC: [u8; 4] = [0x46, 0x43, 0x50, 0x43];

/// Current FCPC version.
pub const FCPC_VERSION: u16 = 1;

/// Fixed FCPC header length in bytes.
pub const FCPC_HEADER_LEN: usize = 36;

/// Fixed AEAD tag length in bytes.
pub const FCPC_TAG_LEN: usize = AEAD_TAG_SIZE;

/// Default maximum payload size for control-plane frames (4 MiB).
pub const DEFAULT_MAX_FCPC_PAYLOAD_LEN: usize = 4 * 1024 * 1024;

bitflags! {
    /// FCPC frame flags (NORMATIVE bits may be added as the spec evolves).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FcpcFrameFlags: u16 {
        /// Payload is encrypted (AEAD) with `k_ctx`.
        const ENCRYPTED = 0b0000_0000_0000_0001;
        /// Payload is compressed (reserved).
        const COMPRESSED = 0b0000_0000_0000_0010;
    }
}

impl Default for FcpcFrameFlags {
    fn default() -> Self {
        Self::ENCRYPTED
    }
}

/// FCPC frame parsing/verification errors.
#[derive(Debug, Error)]
pub enum FcpcError {
    #[error("frame too short (len {len}, min {min})")]
    TooShort { len: usize, min: usize },

    #[error("invalid magic bytes (expected FCPC, got {got:?})")]
    InvalidMagic { got: [u8; 4] },

    #[error("unsupported version {version}")]
    UnsupportedVersion { version: u16 },

    #[error("payload length mismatch (claimed {claimed}, actual {actual})")]
    LengthMismatch { claimed: usize, actual: usize },

    #[error("payload too large (len {len} > max {max})")]
    PayloadTooLarge { len: usize, max: usize },

    #[error("replay rejected for seq {seq}")]
    ReplayRejected { seq: u64 },

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Parsed FCPC frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FcpcFrameHeader {
    /// Protocol version.
    pub version: u16,
    /// Mesh session identifier.
    pub session_id: MeshSessionId,
    /// Monotonic sequence number (per direction).
    pub seq: u64,
    /// Frame flags.
    pub flags: FcpcFrameFlags,
    /// Ciphertext length (bytes, excluding tag).
    pub len: u32,
}

impl FcpcFrameHeader {
    /// Encode the header to bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; FCPC_HEADER_LEN] {
        let mut buf = [0u8; FCPC_HEADER_LEN];
        buf[0..4].copy_from_slice(&FCPC_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..22].copy_from_slice(self.session_id.as_bytes());
        buf[22..30].copy_from_slice(&self.seq.to_le_bytes());
        buf[30..32].copy_from_slice(&self.flags.bits().to_le_bytes());
        buf[32..36].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    /// Decode a header from bytes.
    ///
    /// # Errors
    /// Returns `FcpcError` if the header is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, FcpcError> {
        if bytes.len() < FCPC_HEADER_LEN {
            return Err(FcpcError::TooShort {
                len: bytes.len(),
                min: FCPC_HEADER_LEN,
            });
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != FCPC_MAGIC {
            return Err(FcpcError::InvalidMagic { got: magic });
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FCPC_VERSION {
            return Err(FcpcError::UnsupportedVersion { version });
        }

        let mut session_bytes = [0u8; 16];
        session_bytes.copy_from_slice(&bytes[6..22]);
        let session_id = MeshSessionId(session_bytes);

        let seq_bytes: [u8; 8] = bytes[22..30].try_into().map_err(|_| FcpcError::TooShort {
            len: bytes.len(),
            min: FCPC_HEADER_LEN,
        })?;
        let seq = u64::from_le_bytes(seq_bytes);
        let flags_bits = u16::from_le_bytes([bytes[30], bytes[31]]);
        let flags = FcpcFrameFlags::from_bits_truncate(flags_bits);
        let len_bytes: [u8; 4] = bytes[32..36].try_into().map_err(|_| FcpcError::TooShort {
            len: bytes.len(),
            min: FCPC_HEADER_LEN,
        })?;
        let len = u32::from_le_bytes(len_bytes);

        Ok(Self {
            version,
            session_id,
            seq,
            flags,
            len,
        })
    }
}

/// FCPC frame with authenticated payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcpcFrame {
    pub header: FcpcFrameHeader,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; FCPC_TAG_LEN],
}

impl FcpcFrame {
    /// Build an authenticated (and encrypted) FCPC frame.
    ///
    /// # Errors
    /// Returns `FcpcError` if encryption fails.
    pub fn seal(
        session_id: MeshSessionId,
        seq: u64,
        direction: SessionDirection,
        mut flags: FcpcFrameFlags,
        plaintext: &[u8],
        k_ctx: &[u8; 32],
    ) -> Result<Self, FcpcError> {
        flags.insert(FcpcFrameFlags::ENCRYPTED);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq,
            flags,
            len: 0,
        };
        let aad = build_fcpc_aad(&header);
        let nonce = ChaCha20Nonce::from_counter_directional(seq, direction.as_u8());
        let key = AeadKey::from_bytes(*k_ctx);
        let mut ciphertext = chacha20_encrypt(&key, &nonce, plaintext, &aad)?;
        let tag = split_tag(&mut ciphertext);

        let len = u32::try_from(ciphertext.len()).map_err(|_| FcpcError::PayloadTooLarge {
            len: ciphertext.len(),
            max: u32::MAX as usize,
        })?;
        let header = FcpcFrameHeader { len, ..header };

        Ok(Self {
            header,
            ciphertext,
            tag,
        })
    }

    /// Encode the frame into bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FCPC_HEADER_LEN + self.ciphertext.len() + FCPC_TAG_LEN);
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(&self.tag);
        buf
    }

    /// Decode a frame from bytes with a payload length limit.
    ///
    /// # Errors
    /// Returns `FcpcError` if the frame is malformed or exceeds limits.
    pub fn decode_with_limit(bytes: &[u8], max_payload_len: usize) -> Result<Self, FcpcError> {
        if bytes.len() < FCPC_HEADER_LEN + FCPC_TAG_LEN {
            return Err(FcpcError::TooShort {
                len: bytes.len(),
                min: FCPC_HEADER_LEN + FCPC_TAG_LEN,
            });
        }

        let header = FcpcFrameHeader::decode(bytes)?;
        let claimed = header.len as usize;
        if claimed > max_payload_len {
            return Err(FcpcError::PayloadTooLarge {
                len: claimed,
                max: max_payload_len,
            });
        }

        let expected_len = FCPC_HEADER_LEN + claimed + FCPC_TAG_LEN;
        if bytes.len() != expected_len {
            return Err(FcpcError::LengthMismatch {
                claimed,
                actual: bytes.len() - FCPC_HEADER_LEN - FCPC_TAG_LEN,
            });
        }

        let cipher_start = FCPC_HEADER_LEN;
        let cipher_end = cipher_start + claimed;
        let mut tag = [0u8; FCPC_TAG_LEN];
        tag.copy_from_slice(&bytes[cipher_end..cipher_end + FCPC_TAG_LEN]);

        Ok(Self {
            header,
            ciphertext: bytes[cipher_start..cipher_end].to_vec(),
            tag,
        })
    }

    /// Decode a frame using the default payload limit.
    ///
    /// # Errors
    /// Returns `FcpcError` if the frame is malformed or exceeds limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, FcpcError> {
        Self::decode_with_limit(bytes, DEFAULT_MAX_FCPC_PAYLOAD_LEN)
    }

    /// Decrypt the payload using `k_ctx` (AEAD).
    ///
    /// # Errors
    /// Returns `FcpcError` if decryption fails.
    pub fn open(&self, direction: SessionDirection, k_ctx: &[u8; 32]) -> Result<Vec<u8>, FcpcError> {
        let aad = build_fcpc_aad(&self.header);
        let nonce = ChaCha20Nonce::from_counter_directional(self.header.seq, direction.as_u8());
        let key = AeadKey::from_bytes(*k_ctx);
        let mut combined = Vec::with_capacity(self.ciphertext.len() + FCPC_TAG_LEN);
        combined.extend_from_slice(&self.ciphertext);
        combined.extend_from_slice(&self.tag);
        Ok(chacha20_decrypt(&key, &nonce, &combined, &aad)?)
    }

    /// Check replay window before accepting a frame.
    ///
    /// # Errors
    /// Returns `FcpcError::ReplayRejected` if the sequence is rejected.
    pub fn check_replay(&self, window: &mut ReplayWindow) -> Result<(), FcpcError> {
        if window.check_and_update(self.header.seq) {
            Ok(())
        } else {
            Err(FcpcError::ReplayRejected {
                seq: self.header.seq,
            })
        }
    }
}

fn build_fcpc_aad(header: &FcpcFrameHeader) -> [u8; 26] {
    let mut aad = [0u8; 26];
    aad[0..16].copy_from_slice(header.session_id.as_bytes());
    aad[16..24].copy_from_slice(&header.seq.to_le_bytes());
    aad[24..26].copy_from_slice(&header.flags.bits().to_le_bytes());
    aad
}

fn split_tag(ciphertext: &mut Vec<u8>) -> [u8; FCPC_TAG_LEN] {
    let tag_offset = ciphertext.len().saturating_sub(FCPC_TAG_LEN);
    let tag_bytes = ciphertext.split_off(tag_offset);
    let mut tag = [0u8; FCPC_TAG_LEN];
    tag.copy_from_slice(&tag_bytes);
    tag
}

/// Helper to build a replay window with normative defaults.
#[must_use]
pub fn default_replay_window() -> ReplayWindow {
    ReplayWindow::new(SessionReplayPolicy::default().max_reorder_window)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION_ID_BYTES: [u8; 16] = [0xAA; 16];
    const K_CTX: [u8; 32] = [0x11; 32];

    #[test]
    fn seal_round_trip() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let plaintext = b"fcpc payload bytes";
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            42,
            dir,
            FcpcFrameFlags::default(),
            plaintext,
            &K_CTX,
        )
        .expect("seal should succeed");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode should succeed");
        let opened = decoded.open(dir, &K_CTX).expect("open should succeed");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"x",
            &K_CTX,
        )
        .expect("seal should succeed");
        let mut bytes = frame.encode();
        bytes[0] = 0x00;
        let err = FcpcFrame::decode(&bytes).expect_err("bad magic should fail");
        assert!(matches!(err, FcpcError::InvalidMagic { .. }));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            2,
            dir,
            FcpcFrameFlags::default(),
            b"data",
            &K_CTX,
        )
        .expect("seal should succeed");
        let mut bytes = frame.encode();
        bytes.pop();
        let err = FcpcFrame::decode(&bytes).expect_err("length mismatch should fail");
        assert!(matches!(err, FcpcError::LengthMismatch { .. }));
    }

    #[test]
    fn replay_window_rejects_replay() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            7,
            dir,
            FcpcFrameFlags::default(),
            b"data",
            &K_CTX,
        )
        .expect("seal should succeed");
        let mut window = default_replay_window();
        frame.check_replay(&mut window).expect("first seen");
        let err = frame
            .check_replay(&mut window)
            .expect_err("replay rejected");
        assert!(matches!(err, FcpcError::ReplayRejected { .. }));
    }

    #[test]
    fn decode_rejects_payload_too_large() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            9,
            dir,
            FcpcFrameFlags::default(),
            b"data",
            &K_CTX,
        )
        .expect("seal should succeed");
        let bytes = frame.encode();
        let err = FcpcFrame::decode_with_limit(&bytes, 1).expect_err("payload too large");
        assert!(matches!(err, FcpcError::PayloadTooLarge { .. }));
    }
}

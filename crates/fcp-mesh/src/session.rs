//! FCP2 Session Layer: Authenticated handshake, key schedule, and anti-replay.
//!
//! This module implements the session layer that authenticates FCPS datagrams
//! and secures FCPC frames. The key idea: Ed25519 per-frame signatures are too
//! expensive; FCP2 uses a one-time authenticated handshake to derive session keys,
//! then MACs/encrypts frames with a monotonic sequence and a bounded replay window.
//!
//! # Security Model
//!
//! - Session establishment amortizes Ed25519 signature cost over many frames
//! - Poly1305 is reserved for AEAD contexts only; session MACs use HMAC-SHA256 or BLAKE3-keyed
//! - Stateless cookies prevent responder resource exhaustion from handshake floods

// Allow intentional design choices
#![allow(clippy::missing_panics_doc)] // Panics are unreachable in practice
#![allow(clippy::doc_markdown)] // Protocol-specific terms without backticks
#![allow(clippy::too_many_arguments)] // Session construction requires many params
#![allow(clippy::missing_fields_in_debug)] // Intentionally hide sensitive fields
#![allow(clippy::cast_possible_truncation)] // Protocol-constrained values fit in u8
#![allow(clippy::missing_const_for_fn)] // Not all fns can be const in stable Rust
#![allow(clippy::branches_sharing_code)] // Early returns make shared endings intentional

use fcp_crypto::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, X25519PublicKey};
use fcp_tailscale::NodeId;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Append a length-prefixed string to a buffer (NORMATIVE).
///
/// Format: `len (u16 LE) || bytes`
///
/// This prevents collision attacks where different (from, to) pairs
/// could produce identical transcript prefixes (e.g., "a"+"bc" vs "ab"+"c").
fn append_length_prefixed(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

/// Session crypto suite negotiation (NORMATIVE).
///
/// Defines the MAC algorithm used for session frame authentication.
/// Both suites use X25519 + HKDF-SHA256 for key derivation, but differ
/// in the MAC algorithm.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum SessionCryptoSuite {
    /// X25519 + HKDF-SHA256 + HMAC-SHA256 (tag truncated to 16 bytes)
    #[default]
    Suite1 = 0,
    /// X25519 + HKDF-SHA256 + BLAKE3-keyed (tag truncated to 16 bytes)
    Suite2 = 1,
}

impl SessionCryptoSuite {
    /// Parse from a byte value.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Suite1),
            1 => Some(Self::Suite2),
            _ => None,
        }
    }

    /// Convert to byte value.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Compute session MAC for a datagram (NORMATIVE).
    ///
    /// The MAC is computed over:
    /// `session_id || direction || seq (LE) || frame_bytes`
    ///
    /// Returns a 16-byte truncated MAC.
    #[must_use]
    pub fn compute_mac(
        &self,
        k_mac: &[u8; 32],
        session_id: &[u8; 16],
        direction: u8,
        seq: u64,
        frame_bytes: &[u8],
    ) -> [u8; 16] {
        let mut data = Vec::with_capacity(16 + 1 + 8 + frame_bytes.len());
        data.extend_from_slice(session_id);
        data.push(direction);
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(frame_bytes);

        let full_mac: [u8; 32] = match self {
            Self::Suite1 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(k_mac)
                    .expect("HMAC-SHA256 accepts any key length");
                mac.update(&data);
                mac.finalize().into_bytes().into()
            }
            Self::Suite2 => *blake3::keyed_hash(k_mac, &data).as_bytes(),
        };

        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&full_mac[..16]);
        truncated
    }

    /// Verify a session MAC.
    #[must_use]
    pub fn verify_mac(
        &self,
        k_mac: &[u8; 32],
        session_id: &[u8; 16],
        direction: u8,
        seq: u64,
        frame_bytes: &[u8],
        tag: &[u8; 16],
    ) -> bool {
        let expected = self.compute_mac(k_mac, session_id, direction, seq, frame_bytes);
        constant_time_eq::constant_time_eq(&expected, tag)
    }
}

/// Negotiated transport limits (NORMATIVE when used).
///
/// Used to keep FCPS frames MTU-safe and avoid IP fragmentation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TransportLimits {
    /// Maximum UDP payload bytes the sender will transmit for FCPS frames to this peer.
    /// Default if absent: 1200.
    pub max_datagram_bytes: u16,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_datagram_bytes: 1200,
        }
    }
}

/// Session handshake: initiator to responder (NORMATIVE).
///
/// The initiator sends a Hello message to begin session establishment.
/// The responder may reply with an Ack (accepting) or HelloRetry (requiring cookie).
#[derive(Clone, Debug)]
pub struct MeshSessionHello {
    /// Source node ID (initiator).
    pub from: NodeId,
    /// Destination node ID (responder).
    pub to: NodeId,
    /// Ephemeral X25519 public key for this session.
    pub eph_pubkey: X25519PublicKey,
    /// Random nonce for replay protection (NORMATIVE).
    /// Binds this handshake to a specific session attempt.
    pub nonce: [u8; 16],
    /// Optional stateless cookie (NORMATIVE when responder requires it).
    /// Prevents responder resource-exhaustion by deferring expensive work
    /// (signature verification, ECDH) until cookie is validated.
    pub cookie: Option<[u8; 32]>,
    /// Unix timestamp (seconds since epoch) of handshake creation.
    pub timestamp: u64,
    /// Supported crypto suites (ordered by preference).
    pub suites: Vec<SessionCryptoSuite>,
    /// Optional transport limits (NORMATIVE when present).
    pub transport_limits: Option<TransportLimits>,
    /// Node signature over transcript (NORMATIVE).
    pub signature: Ed25519Signature,
}

impl MeshSessionHello {
    /// Build transcript for signing/verification (NORMATIVE).
    ///
    /// transcript = "FCP2-HELLO-V1" || len(from) || from || len(to) || to ||
    ///              eph_pubkey || nonce || cookie || timestamp || suites || transport_limits
    ///
    /// Note: NodeId strings are length-prefixed (u16 LE) to prevent collision attacks.
    #[must_use]
    pub fn build_transcript(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(256);
        t.extend_from_slice(b"FCP2-HELLO-V1");
        append_length_prefixed(&mut t, self.from.as_str());
        append_length_prefixed(&mut t, self.to.as_str());
        t.extend_from_slice(&self.eph_pubkey.to_bytes());
        t.extend_from_slice(&self.nonce);
        if let Some(cookie) = &self.cookie {
            t.push(1);
            t.extend_from_slice(cookie);
        } else {
            t.push(0);
        }
        t.extend_from_slice(&self.timestamp.to_le_bytes());
        t.push(self.suites.len() as u8);
        for suite in &self.suites {
            t.push(suite.as_byte());
        }
        if let Some(limits) = &self.transport_limits {
            t.push(1);
            t.extend_from_slice(&limits.max_datagram_bytes.to_le_bytes());
        } else {
            t.push(0);
        }
        t
    }

    /// Sign the hello message.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) {
        let transcript = self.build_transcript();
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify signature against node's public key.
    #[must_use]
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> bool {
        let transcript = self.build_transcript();
        verifying_key.verify(&transcript, &self.signature).is_ok()
    }
}

/// Session handshake: responder to initiator (NORMATIVE).
///
/// The responder sends an Ack to accept the session and provide its
/// ephemeral public key and selected crypto suite.
#[derive(Clone, Debug)]
pub struct MeshSessionAck {
    /// Source node ID (responder).
    pub from: NodeId,
    /// Destination node ID (initiator).
    pub to: NodeId,
    /// Ephemeral X25519 public key for this session.
    pub eph_pubkey: X25519PublicKey,
    /// Random nonce for replay protection (NORMATIVE).
    /// Combined with hello_nonce, prevents session confusion attacks.
    pub nonce: [u8; 16],
    /// Session identifier (derived from handshake).
    pub session_id: [u8; 16],
    /// Selected crypto suite.
    pub suite: SessionCryptoSuite,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Node signature over full handshake transcript (NORMATIVE).
    pub signature: Ed25519Signature,
}

impl MeshSessionAck {
    /// Build transcript for signing/verification (NORMATIVE).
    ///
    /// transcript = "FCP2-ACK-V1" || len(from) || from || len(to) || to ||
    ///              eph_pubkey || nonce || session_id || suite || timestamp ||
    ///              hello.eph_pubkey || hello.nonce
    ///
    /// Note: NodeId strings are length-prefixed (u16 LE) to prevent collision attacks.
    #[must_use]
    pub fn build_transcript(&self, hello: &MeshSessionHello) -> Vec<u8> {
        let mut t = Vec::with_capacity(256);
        t.extend_from_slice(b"FCP2-ACK-V1");
        append_length_prefixed(&mut t, self.from.as_str());
        append_length_prefixed(&mut t, self.to.as_str());
        t.extend_from_slice(&self.eph_pubkey.to_bytes());
        t.extend_from_slice(&self.nonce);
        t.extend_from_slice(&self.session_id);
        t.push(self.suite.as_byte());
        t.extend_from_slice(&self.timestamp.to_le_bytes());
        // Bind to hello for anti-splicing
        t.extend_from_slice(&hello.eph_pubkey.to_bytes());
        t.extend_from_slice(&hello.nonce);
        t
    }

    /// Sign the ack message.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey, hello: &MeshSessionHello) {
        let transcript = self.build_transcript(hello);
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify signature against node's public key.
    #[must_use]
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey, hello: &MeshSessionHello) -> bool {
        let transcript = self.build_transcript(hello);
        verifying_key.verify(&transcript, &self.signature).is_ok()
    }
}

/// Stateless cookie challenge (NORMATIVE when used).
///
/// Responder can send this WITHOUT allocating session state or verifying
/// the hello signature. This prevents resource exhaustion from handshake
/// floods (similar to DTLS/QUIC HelloRetryRequest pattern).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshSessionHelloRetry {
    /// Source node ID (responder).
    pub from: NodeId,
    /// Destination node ID (initiator).
    pub to: NodeId,
    /// Stateless cookie computed by responder (NORMATIVE).
    pub cookie: [u8; 32],
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
}

impl MeshSessionHelloRetry {
    /// Compute cookie for a hello (NORMATIVE).
    ///
    /// cookie = HMAC(cookie_key, len(from) || from || len(to) || to ||
    ///               hello.eph_pubkey || hello.nonce || hello.timestamp)\[:32\]
    ///
    /// The cookie_key SHOULD be rotated periodically (e.g., every 60 seconds)
    /// with a grace window for in-flight handshakes.
    ///
    /// Note: NodeId strings are length-prefixed (u16 LE) to prevent collision attacks.
    #[must_use]
    pub fn compute_cookie(cookie_key: &[u8; 32], hello: &MeshSessionHello) -> [u8; 32] {
        // Build input with length-prefixed strings
        let mut input = Vec::with_capacity(128);
        append_length_prefixed(&mut input, hello.from.as_str());
        append_length_prefixed(&mut input, hello.to.as_str());
        input.extend_from_slice(&hello.eph_pubkey.to_bytes());
        input.extend_from_slice(&hello.nonce);
        input.extend_from_slice(&hello.timestamp.to_le_bytes());

        let mut mac =
            Hmac::<Sha256>::new_from_slice(cookie_key).expect("HMAC-SHA256 accepts any key length");
        mac.update(&input);

        let result = mac.finalize().into_bytes();
        let mut cookie = [0u8; 32];
        cookie.copy_from_slice(&result);
        cookie
    }

    /// Create a HelloRetry for a given hello.
    #[must_use]
    pub fn for_hello(
        cookie_key: &[u8; 32],
        hello: &MeshSessionHello,
        responder_id: NodeId,
        timestamp: u64,
    ) -> Self {
        Self {
            from: responder_id,
            to: hello.from.clone(),
            cookie: Self::compute_cookie(cookie_key, hello),
            timestamp,
        }
    }

    /// Verify a cookie in a hello matches what we would compute.
    #[must_use]
    pub fn verify_cookie(cookie_key: &[u8; 32], hello: &MeshSessionHello) -> bool {
        hello.cookie.as_ref().is_some_and(|provided| {
            let expected = Self::compute_cookie(cookie_key, hello);
            constant_time_eq::constant_time_eq(provided, &expected)
        })
    }
}

/// Session keys derived from handshake (NORMATIVE).
///
/// These keys are derived deterministically from the ECDH shared secret
/// and session parameters. The derivation binds keys to this specific
/// handshake, preventing session splicing attacks.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// MAC key for initiator to responder.
    pub k_mac_i2r: [u8; 32],
    /// MAC key for responder to initiator.
    pub k_mac_r2i: [u8; 32],
    /// Reserved for future control-plane AEAD (FCPC encryption).
    pub k_ctx: [u8; 32],
}

impl SessionKeys {
    /// Derive session keys from ECDH (NORMATIVE).
    ///
    /// ```text
    /// prk = HKDF-SHA256(
    ///     ikm = ECDH(eph_i, eph_r),
    ///     salt = session_id,
    ///     info = "FCP2-SESSION-V1" || len(initiator_id) || initiator_id ||
    ///            len(responder_id) || responder_id || hello_nonce || ack_nonce
    /// )
    ///
    /// keys = HKDF-Expand(prk, info="FCP2-SESSION-KEYS-V1", L=96) split as:
    /// - k_mac_i2r (32 bytes): MAC key for initiator to responder
    /// - k_mac_r2i (32 bytes): MAC key for responder to initiator
    /// - k_ctx     (32 bytes): reserved for FCPC AEAD
    /// ```
    ///
    /// Note: NodeId strings are length-prefixed (u16 LE) to prevent collision attacks.
    #[must_use]
    pub fn derive(
        ecdh_shared: &[u8; 32],
        session_id: &[u8; 16],
        initiator_id: &NodeId,
        responder_id: &NodeId,
        hello_nonce: &[u8; 16],
        ack_nonce: &[u8; 16],
    ) -> Self {
        // Build info string for expansion (with length-prefixed NodeIds)
        let mut info = Vec::with_capacity(128);
        info.extend_from_slice(b"FCP2-SESSION-V1");
        append_length_prefixed(&mut info, initiator_id.as_str());
        append_length_prefixed(&mut info, responder_id.as_str());
        info.extend_from_slice(hello_nonce);
        info.extend_from_slice(ack_nonce);

        // Extract PRK using session_id as salt and info in ikm
        // Note: The spec says "info" in the extraction step, but HKDF-Extract
        // doesn't use info. We incorporate info into the expand step.
        let hk = Hkdf::<Sha256>::new(Some(session_id), ecdh_shared);

        // Expand to 96 bytes with the info string
        let mut okm = [0u8; 96];
        hk.expand(&info, &mut okm)
            .expect("96 bytes is valid for HKDF-SHA256");

        // Split into keys
        let mut k_mac_i2r = [0u8; 32];
        let mut k_mac_r2i = [0u8; 32];
        let mut k_ctx = [0u8; 32];
        k_mac_i2r.copy_from_slice(&okm[0..32]);
        k_mac_r2i.copy_from_slice(&okm[32..64]);
        k_ctx.copy_from_slice(&okm[64..96]);

        Self {
            k_mac_i2r,
            k_mac_r2i,
            k_ctx,
        }
    }

    /// Get MAC key for a given direction.
    #[must_use]
    pub fn mac_key(&self, is_initiator: bool) -> &[u8; 32] {
        if is_initiator {
            &self.k_mac_i2r
        } else {
            &self.k_mac_r2i
        }
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

/// Replay protection policy (NORMATIVE defaults).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionReplayPolicy {
    /// Allow limited reordering; MUST be bounded.
    pub max_reorder_window: u64,
    /// Maximum number of frames into the future to accept (anti-DoS).
    /// Prevents window jumping attacks where a peer sends `seq=u64::MAX`.
    pub max_future_window: u64,
    /// Rekey periodically for operational hygiene and suite agility.
    pub rekey_after_frames: u64,
    /// Rekey after elapsed time to avoid pathological long-lived sessions.
    pub rekey_after_seconds: u64,
    /// Rekey after cumulative bytes to bound key exposure.
    pub rekey_after_bytes: u64,
}

impl Default for SessionReplayPolicy {
    fn default() -> Self {
        Self {
            max_reorder_window: 128,
            max_future_window: 1024,
            rekey_after_frames: 1_000_000_000,
            rekey_after_seconds: 86400,           // 24 hours
            rekey_after_bytes: 1_099_511_627_776, // 1 TiB
        }
    }
}

/// Time skew handling policy (NORMATIVE).
///
/// Clock drift is inevitable (mobile devices, VMs paused, etc.).
/// This policy defines tolerances for timestamp validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimePolicy {
    /// Maximum tolerated clock skew when validating iat/exp
    /// and handshake timestamps (default: 120 seconds).
    pub max_skew_secs: u64,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self { max_skew_secs: 120 }
    }
}

/// Replay window tracker for a session.
///
/// Uses a sliding bitmap to track received sequence numbers and detect
/// replays. The window allows for limited out-of-order delivery while
/// preventing replay attacks.
pub struct ReplayWindow {
    /// Highest sequence seen.
    highest_seq: u64,
    /// Bitmap of received sequences in window.
    /// Bit 0 = highest_seq, bit N = highest_seq - N.
    bitmap: u128,
    /// Window size (max reordering allowed).
    window_size: u64,
}

impl ReplayWindow {
    /// Create a new replay window with the given size.
    #[must_use]
    pub fn new(window_size: u64) -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
            window_size,
        }
    }

    /// Check if sequence is valid (not a replay) and update window.
    ///
    /// Returns `true` if the sequence is accepted, `false` if it's a replay
    /// or outside the acceptable window.
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false; // seq must start at 1
        }

        if seq > self.highest_seq {
            // New highest: shift window
            let shift = (seq - self.highest_seq).min(128);
            self.bitmap = self.bitmap.checked_shl(shift as u32).unwrap_or(0);
            self.bitmap |= 1; // Mark new highest as received
            self.highest_seq = seq;
            true
        } else {
            // Check if in window
            let diff = self.highest_seq - seq;
            if diff >= self.window_size || diff >= 128 {
                return false; // Too old
            }
            let bit = 1u128 << diff;
            if self.bitmap & bit != 0 {
                return false; // Replay
            }
            self.bitmap |= bit;
            true
        }
    }

    /// Get the highest sequence number seen.
    #[must_use]
    pub const fn highest_seq(&self) -> u64 {
        self.highest_seq
    }
}

impl std::fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("highest_seq", &self.highest_seq)
            .field("window_size", &self.window_size)
            .finish()
    }
}

/// Session state for a peer connection.
///
/// Represents an established session with a peer, including
/// cryptographic keys, anti-replay state, and rekey tracking.
pub struct MeshSession {
    /// Unique session identifier.
    pub session_id: [u8; 16],
    /// Peer node ID.
    pub peer_id: NodeId,
    /// Negotiated crypto suite.
    pub suite: SessionCryptoSuite,
    /// Session keys.
    pub keys: SessionKeys,
    /// Negotiated transport limits.
    pub transport_limits: TransportLimits,
    /// Whether we are the initiator.
    pub is_initiator: bool,

    // Anti-replay state
    /// Next sequence number to send.
    send_seq: u64,
    /// Replay window for received sequences.
    recv_window: ReplayWindow,

    // Rekey tracking
    /// Total frames sent on this session.
    frames_sent: u64,
    /// Total bytes sent on this session.
    bytes_sent: u64,
    /// Timestamp when session was established (seconds since epoch).
    established_at: u64,
    /// Replay policy for this session.
    replay_policy: SessionReplayPolicy,
}

impl MeshSession {
    /// Create a new session.
    #[must_use]
    pub fn new(
        session_id: [u8; 16],
        peer_id: NodeId,
        suite: SessionCryptoSuite,
        keys: SessionKeys,
        transport_limits: TransportLimits,
        is_initiator: bool,
        established_at: u64,
        replay_policy: SessionReplayPolicy,
    ) -> Self {
        Self {
            session_id,
            peer_id,
            suite,
            keys,
            transport_limits,
            is_initiator,
            send_seq: 0,
            recv_window: ReplayWindow::new(replay_policy.max_reorder_window),
            frames_sent: 0,
            bytes_sent: 0,
            established_at,
            replay_policy,
        }
    }

    /// Check if session needs rekeying.
    #[must_use]
    pub fn needs_rekey(&self, current_time: u64) -> bool {
        self.frames_sent >= self.replay_policy.rekey_after_frames
            || self.bytes_sent >= self.replay_policy.rekey_after_bytes
            || (current_time.saturating_sub(self.established_at))
                >= self.replay_policy.rekey_after_seconds
    }

    /// Get next send sequence and increment.
    pub fn next_send_seq(&mut self) -> u64 {
        self.send_seq += 1;
        self.send_seq
    }

    /// Check received sequence for replay and update window.
    pub fn check_recv_seq(&mut self, seq: u64) -> bool {
        self.recv_window.check_and_update(seq)
    }

    /// Get MAC key for sending.
    #[must_use]
    pub fn send_mac_key(&self) -> &[u8; 32] {
        self.keys.mac_key(self.is_initiator)
    }

    /// Get MAC key for receiving.
    #[must_use]
    pub fn recv_mac_key(&self) -> &[u8; 32] {
        self.keys.mac_key(!self.is_initiator)
    }

    /// Direction byte for MAC computation (sending).
    #[must_use]
    pub const fn send_direction(&self) -> u8 {
        if self.is_initiator { 0x00 } else { 0x01 }
    }

    /// Direction byte for MAC computation (receiving).
    #[must_use]
    pub const fn recv_direction(&self) -> u8 {
        if self.is_initiator { 0x01 } else { 0x00 }
    }

    /// Compute MAC for an outgoing frame and update counters.
    pub fn mac_outgoing(&mut self, frame_bytes: &[u8]) -> (u64, [u8; 16]) {
        let seq = self.next_send_seq();
        let mac = self.suite.compute_mac(
            self.send_mac_key(),
            &self.session_id,
            self.send_direction(),
            seq,
            frame_bytes,
        );
        self.frames_sent += 1;
        self.bytes_sent += frame_bytes.len() as u64;
        (seq, mac)
    }

    /// Verify MAC for an incoming frame and check replay.
    ///
    /// SECURITY NOTE: MAC is verified BEFORE updating the replay window.
    /// This prevents a DoS attack where an attacker burns sequence numbers
    /// by sending garbage frames that fail MAC verification.
    #[must_use]
    pub fn verify_incoming(&mut self, seq: u64, frame_bytes: &[u8], tag: &[u8; 16]) -> bool {
        // Quick bounds check (don't compute MAC for obviously invalid seqs)
        if seq == 0 {
            return false;
        }
        // Check if seq is in acceptable range before MAC computation
        let highest = self.recv_window.highest_seq();
        let future_limit = highest.saturating_add(self.replay_policy.max_future_window);

        // Anti-DoS: Prevent window jumping (seq >> highest)
        if seq > future_limit {
            return false;
        }

        if highest > 0 {
            let diff = highest.saturating_sub(seq);
            if diff >= self.replay_policy.max_reorder_window || diff >= 128 {
                return false; // Too old, reject without MAC check
            }
        }

        // CRITICAL: Verify MAC BEFORE updating replay window
        // This prevents DoS by sequence number exhaustion
        let mac_valid = self.suite.verify_mac(
            self.recv_mac_key(),
            &self.session_id,
            self.recv_direction(),
            seq,
            frame_bytes,
            tag,
        );

        if !mac_valid {
            return false;
        }

        // Only update replay window after MAC verification succeeds
        self.check_recv_seq(seq)
    }

    /// Get the session ID.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Get the peer ID.
    #[must_use]
    pub fn peer_id(&self) -> &NodeId {
        &self.peer_id
    }

    /// Get total frames sent.
    #[must_use]
    pub const fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Get total bytes sent.
    #[must_use]
    pub const fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }
}

impl std::fmt::Debug for MeshSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshSession")
            .field("session_id", &hex::encode(self.session_id))
            .field("peer_id", &self.peer_id)
            .field("suite", &self.suite)
            .field("is_initiator", &self.is_initiator)
            .field("send_seq", &self.send_seq)
            .field("frames_sent", &self.frames_sent)
            .field("bytes_sent", &self.bytes_sent)
            .finish()
    }
}

/// Generate a random session ID.
#[must_use]
pub fn generate_session_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut id);
    id
}

/// Generate a random nonce for handshake.
#[must_use]
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    nonce
}

/// Get current Unix timestamp in seconds.
#[must_use]
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_crypto::X25519SecretKey;

    fn make_test_hello() -> MeshSessionHello {
        let eph_sk = X25519SecretKey::generate();
        MeshSessionHello {
            from: NodeId::new("node-initiator"),
            to: NodeId::new("node-responder"),
            eph_pubkey: eph_sk.public_key(),
            nonce: [1u8; 16],
            cookie: None,
            timestamp: 1_700_000_000,
            suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
            transport_limits: Some(TransportLimits::default()),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        }
    }

    #[test]
    fn test_session_crypto_suite_roundtrip() {
        assert_eq!(
            SessionCryptoSuite::from_byte(SessionCryptoSuite::Suite1.as_byte()),
            Some(SessionCryptoSuite::Suite1)
        );
        assert_eq!(
            SessionCryptoSuite::from_byte(SessionCryptoSuite::Suite2.as_byte()),
            Some(SessionCryptoSuite::Suite2)
        );
        assert_eq!(SessionCryptoSuite::from_byte(42), None);
    }

    #[test]
    fn test_suite1_mac_computation() {
        let k_mac = [0x42u8; 32];
        let session_id = [0x01u8; 16];
        let direction = 0x00;
        let seq = 1u64;
        let frame = b"test frame data";

        let mac =
            SessionCryptoSuite::Suite1.compute_mac(&k_mac, &session_id, direction, seq, frame);

        // Verify MAC is deterministic
        let mac2 =
            SessionCryptoSuite::Suite1.compute_mac(&k_mac, &session_id, direction, seq, frame);
        assert_eq!(mac, mac2);

        // Verify MAC verification works
        assert!(SessionCryptoSuite::Suite1.verify_mac(
            &k_mac,
            &session_id,
            direction,
            seq,
            frame,
            &mac
        ));

        // Verify wrong MAC fails
        let mut wrong_mac = mac;
        wrong_mac[0] ^= 0xff;
        assert!(!SessionCryptoSuite::Suite1.verify_mac(
            &k_mac,
            &session_id,
            direction,
            seq,
            frame,
            &wrong_mac
        ));
    }

    #[test]
    fn test_suite2_mac_computation() {
        let k_mac = [0x42u8; 32];
        let session_id = [0x01u8; 16];
        let direction = 0x00;
        let seq = 1u64;
        let frame = b"test frame data";

        let mac =
            SessionCryptoSuite::Suite2.compute_mac(&k_mac, &session_id, direction, seq, frame);

        // Verify MAC is deterministic
        let mac2 =
            SessionCryptoSuite::Suite2.compute_mac(&k_mac, &session_id, direction, seq, frame);
        assert_eq!(mac, mac2);

        // Verify MAC verification works
        assert!(SessionCryptoSuite::Suite2.verify_mac(
            &k_mac,
            &session_id,
            direction,
            seq,
            frame,
            &mac
        ));
    }

    #[test]
    fn test_suites_produce_different_macs() {
        let k_mac = [0x42u8; 32];
        let session_id = [0x01u8; 16];
        let direction = 0x00;
        let seq = 1u64;
        let frame = b"test frame data";

        let mac1 =
            SessionCryptoSuite::Suite1.compute_mac(&k_mac, &session_id, direction, seq, frame);
        let mac2 =
            SessionCryptoSuite::Suite2.compute_mac(&k_mac, &session_id, direction, seq, frame);

        // Different suites should produce different MACs
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hello_transcript_deterministic() {
        let hello = make_test_hello();
        let t1 = hello.build_transcript();
        let t2 = hello.build_transcript();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_hello_transcript_includes_cookie() {
        let mut hello = make_test_hello();
        let t_without = hello.build_transcript();

        hello.cookie = Some([0xabu8; 32]);
        let t_with = hello.build_transcript();

        // Transcripts should differ
        assert_ne!(t_without, t_with);
        // With cookie should be longer
        assert!(t_with.len() > t_without.len());
    }

    #[test]
    fn test_hello_sign_verify() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut hello = make_test_hello();
        hello.sign(&signing_key);

        assert!(hello.verify(&verifying_key));

        // Tamper with hello
        hello.timestamp += 1;
        assert!(!hello.verify(&verifying_key));
    }

    #[test]
    fn test_ack_transcript_binds_to_hello() {
        let hello = make_test_hello();
        let eph_sk = X25519SecretKey::generate();

        let ack = MeshSessionAck {
            from: NodeId::new("node-responder"),
            to: NodeId::new("node-initiator"),
            eph_pubkey: eph_sk.public_key(),
            nonce: [2u8; 16],
            session_id: [3u8; 16],
            suite: SessionCryptoSuite::Suite1,
            timestamp: 1_700_000_001,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        let transcript = ack.build_transcript(&hello);

        // Transcript should include hello's eph_pubkey and nonce
        assert!(transcript.windows(16).any(|w| w == hello.nonce));
    }

    #[test]
    fn test_cookie_computation_deterministic() {
        let cookie_key = [0x42u8; 32];
        let hello = make_test_hello();

        let cookie1 = MeshSessionHelloRetry::compute_cookie(&cookie_key, &hello);
        let cookie2 = MeshSessionHelloRetry::compute_cookie(&cookie_key, &hello);

        assert_eq!(cookie1, cookie2);
    }

    #[test]
    fn test_cookie_verification() {
        let cookie_key = [0x42u8; 32];
        let mut hello = make_test_hello();

        // No cookie should fail
        assert!(!MeshSessionHelloRetry::verify_cookie(&cookie_key, &hello));

        // Correct cookie should pass
        let cookie = MeshSessionHelloRetry::compute_cookie(&cookie_key, &hello);
        hello.cookie = Some(cookie);
        assert!(MeshSessionHelloRetry::verify_cookie(&cookie_key, &hello));

        // Wrong cookie should fail
        let mut wrong_cookie = cookie;
        wrong_cookie[0] ^= 0xff;
        hello.cookie = Some(wrong_cookie);
        assert!(!MeshSessionHelloRetry::verify_cookie(&cookie_key, &hello));
    }

    #[test]
    fn test_session_keys_derivation() {
        let ecdh_shared = [0x42u8; 32];
        let session_id = [0x01u8; 16];
        let initiator_id = NodeId::new("initiator");
        let responder_id = NodeId::new("responder");
        let hello_nonce = [0x02u8; 16];
        let ack_nonce = [0x03u8; 16];

        let keys = SessionKeys::derive(
            &ecdh_shared,
            &session_id,
            &initiator_id,
            &responder_id,
            &hello_nonce,
            &ack_nonce,
        );

        // Keys should be deterministic
        let keys2 = SessionKeys::derive(
            &ecdh_shared,
            &session_id,
            &initiator_id,
            &responder_id,
            &hello_nonce,
            &ack_nonce,
        );

        assert_eq!(keys.k_mac_i2r, keys2.k_mac_i2r);
        assert_eq!(keys.k_mac_r2i, keys2.k_mac_r2i);
        assert_eq!(keys.k_ctx, keys2.k_ctx);

        // All three keys should be different
        assert_ne!(keys.k_mac_i2r, keys.k_mac_r2i);
        assert_ne!(keys.k_mac_i2r, keys.k_ctx);
        assert_ne!(keys.k_mac_r2i, keys.k_ctx);
    }

    #[test]
    fn test_session_keys_direction() {
        let keys = SessionKeys {
            k_mac_i2r: [0x01u8; 32],
            k_mac_r2i: [0x02u8; 32],
            k_ctx: [0x03u8; 32],
        };

        assert_eq!(keys.mac_key(true), &[0x01u8; 32]);
        assert_eq!(keys.mac_key(false), &[0x02u8; 32]);
    }

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new(128);

        // Seq 0 should be rejected
        assert!(!window.check_and_update(0));

        // First valid seq should be accepted
        assert!(window.check_and_update(1));
        assert_eq!(window.highest_seq(), 1);

        // Replay should be rejected
        assert!(!window.check_and_update(1));

        // Higher seq should be accepted
        assert!(window.check_and_update(5));
        assert_eq!(window.highest_seq(), 5);

        // Replay still rejected
        assert!(!window.check_and_update(1));
        assert!(!window.check_and_update(5));
    }

    #[test]
    fn test_replay_window_reordering() {
        let mut window = ReplayWindow::new(128);

        // Accept sequence 100
        assert!(window.check_and_update(100));

        // Accept out-of-order within window
        assert!(window.check_and_update(99));
        assert!(window.check_and_update(95));
        assert!(window.check_and_update(50)); // Still within 128-window

        // Reject replay
        assert!(!window.check_and_update(99));
        assert!(!window.check_and_update(50));
    }

    #[test]
    fn test_replay_window_old_rejected() {
        let mut window = ReplayWindow::new(128);

        // Accept sequence 200
        assert!(window.check_and_update(200));

        // Old sequence outside window should be rejected
        assert!(!window.check_and_update(50)); // 200 - 50 = 150 > 128
        assert!(!window.check_and_update(71)); // 200 - 71 = 129 > 128

        // Just inside window should work
        assert!(window.check_and_update(73)); // 200 - 73 = 127 < 128
    }

    #[test]
    fn test_replay_window_large_jump() {
        let mut window = ReplayWindow::new(128);

        assert!(window.check_and_update(1));
        assert!(window.check_and_update(1000));
        assert_eq!(window.highest_seq(), 1000);

        // Old seq 1 should be rejected (outside window)
        assert!(!window.check_and_update(1));

        // Recent seqs should work
        assert!(window.check_and_update(999));
        assert!(window.check_and_update(900)); // 1000 - 900 = 100 < 128
    }

    #[test]
    fn test_mesh_session_mac_flow() {
        let keys = SessionKeys {
            k_mac_i2r: [0x01u8; 32],
            k_mac_r2i: [0x02u8; 32],
            k_ctx: [0x03u8; 32],
        };

        let mut initiator = MeshSession::new(
            [0xAAu8; 16],
            NodeId::new("responder"),
            SessionCryptoSuite::Suite1,
            keys.clone(),
            TransportLimits::default(),
            true,
            1_700_000_000,
            SessionReplayPolicy::default(),
        );

        let mut responder = MeshSession::new(
            [0xAAu8; 16],
            NodeId::new("initiator"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            false,
            1_700_000_000,
            SessionReplayPolicy::default(),
        );

        let frame = b"hello from initiator";
        let (seq, mac) = initiator.mac_outgoing(frame);

        // Responder should verify successfully
        assert!(responder.verify_incoming(seq, frame, &mac));

        // Replay should fail
        assert!(!responder.verify_incoming(seq, frame, &mac));

        // Tampered frame should fail
        let (seq2, mac2) = initiator.mac_outgoing(b"original");
        assert!(!responder.verify_incoming(seq2, b"tampered", &mac2));
    }

    /// Regression test: verify that failed MAC verification does NOT burn sequence numbers.
    ///
    /// This tests the fix for a DoS vulnerability where an attacker could exhaust
    /// sequence numbers by sending garbage frames. The replay window should only
    /// be updated AFTER MAC verification succeeds.
    #[test]
    fn test_failed_mac_does_not_burn_sequence() {
        let keys = SessionKeys {
            k_mac_i2r: [0x01u8; 32],
            k_mac_r2i: [0x02u8; 32],
            k_ctx: [0x03u8; 32],
        };

        let mut initiator = MeshSession::new(
            [0xAAu8; 16],
            NodeId::new("responder"),
            SessionCryptoSuite::Suite1,
            keys.clone(),
            TransportLimits::default(),
            true,
            1_700_000_000,
            SessionReplayPolicy::default(),
        );

        let mut responder = MeshSession::new(
            [0xAAu8; 16],
            NodeId::new("initiator"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            false,
            1_700_000_000,
            SessionReplayPolicy::default(),
        );

        // Initiator sends a legitimate frame
        let frame = b"legitimate message";
        let (seq, mac) = initiator.mac_outgoing(frame);

        // Attacker sends garbage with the SAME sequence number but wrong MAC
        // This should fail verification but NOT burn the sequence number
        let garbage_mac = [0xFFu8; 16];
        assert!(!responder.verify_incoming(seq, b"attacker garbage", &garbage_mac));

        // The legitimate frame with the same sequence should STILL be accepted
        // because the failed MAC verification should not have updated the replay window
        assert!(
            responder.verify_incoming(seq, frame, &mac),
            "BUG: Failed MAC verification burned the sequence number! \
             This is a DoS vulnerability."
        );
    }

    #[test]
    fn test_mesh_session_rekey_triggers() {
        let keys = SessionKeys {
            k_mac_i2r: [0x01u8; 32],
            k_mac_r2i: [0x02u8; 32],
            k_ctx: [0x03u8; 32],
        };

        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            max_future_window: 1024,
            rekey_after_frames: 100,
            rekey_after_seconds: 3600,
            rekey_after_bytes: 10000,
        };

        let mut session = MeshSession::new(
            [0xAAu8; 16],
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            true,
            1_700_000_000,
            policy,
        );

        // Initially no rekey needed
        assert!(!session.needs_rekey(1_700_000_000));

        // Time-based rekey
        assert!(session.needs_rekey(1_700_000_000 + 3600));

        // Frame-based rekey
        for _ in 0..100 {
            session.mac_outgoing(b"x");
        }
        assert!(session.needs_rekey(1_700_000_000));
    }

    // =========================================================================
    // Golden vector tests
    // =========================================================================

    #[test]
    fn golden_vector_suite1_mac() {
        // Deterministic inputs for golden vector
        let k_mac = [0u8; 32]; // All zeros
        let session_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let direction = 0x00;
        let seq = 1u64;
        let frame = b"FCP2 golden vector test";

        let mac =
            SessionCryptoSuite::Suite1.compute_mac(&k_mac, &session_id, direction, seq, frame);

        // This is the expected output for HMAC-SHA256 truncated to 16 bytes
        assert_eq!(
            hex::encode(mac),
            "bb5200cb5649c3f7d7b50b6e51617840",
            "Suite1 (HMAC-SHA256) golden vector mismatch"
        );
    }

    #[test]
    fn golden_vector_suite2_mac() {
        // Deterministic inputs for golden vector
        let k_mac = [0u8; 32]; // All zeros
        let session_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let direction = 0x00;
        let seq = 1u64;
        let frame = b"FCP2 golden vector test";

        let mac =
            SessionCryptoSuite::Suite2.compute_mac(&k_mac, &session_id, direction, seq, frame);

        // This is the expected output for BLAKE3-keyed truncated to 16 bytes
        assert_eq!(
            hex::encode(mac),
            "38e594a7f8d2d9d369c12a210562f09c",
            "Suite2 (BLAKE3-keyed) golden vector mismatch"
        );
    }

    #[test]
    fn golden_vector_cookie_computation() {
        let cookie_key = [0x42u8; 32];
        let eph_sk = X25519SecretKey::from_bytes([0x01u8; 32]);

        let hello = MeshSessionHello {
            from: NodeId::new("nodeA"),
            to: NodeId::new("nodeB"),
            eph_pubkey: eph_sk.public_key(),
            nonce: [0x11u8; 16],
            cookie: None,
            timestamp: 1_700_000_000,
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        let cookie = MeshSessionHelloRetry::compute_cookie(&cookie_key, &hello);

        // Golden vector for cookie computation (with length-prefixed NodeIds)
        assert_eq!(
            hex::encode(cookie),
            "5527c7a1f0d071e04e8c01498bca3624733f73900b979eb5b46a990e9f9f5c04",
            "Cookie computation golden vector mismatch"
        );
    }

    #[test]
    fn golden_vector_session_keys() {
        let ecdh_shared = [0x55u8; 32];
        let session_id = [0xAAu8; 16];
        let initiator_id = NodeId::new("init");
        let responder_id = NodeId::new("resp");
        let hello_nonce = [0x11u8; 16];
        let ack_nonce = [0x22u8; 16];

        let keys = SessionKeys::derive(
            &ecdh_shared,
            &session_id,
            &initiator_id,
            &responder_id,
            &hello_nonce,
            &ack_nonce,
        );

        // Golden vectors for key derivation (with length-prefixed NodeIds)
        assert_eq!(
            hex::encode(keys.k_mac_i2r),
            "9faa9b6626586bd3daa2db1d266bf3a7e02c79a8adea4de7e20ee287ea3e8a96",
            "k_mac_i2r golden vector mismatch"
        );
        assert_eq!(
            hex::encode(keys.k_mac_r2i),
            "3ed082079350f70e8fb4c8c57324ff22677cb35dbe9afb7bdf491f730fbe8246",
            "k_mac_r2i golden vector mismatch"
        );
        assert_eq!(
            hex::encode(keys.k_ctx),
            "bc2e558e785c336fa3ea3c011aba852c4a222580a965ef740f98dec36438e44e",
            "k_ctx golden vector mismatch"
        );
    }

    #[test]
    fn golden_vector_hello_transcript() {
        let eph_sk = X25519SecretKey::from_bytes([0x01u8; 32]);

        let hello = MeshSessionHello {
            from: NodeId::new("nodeA"),
            to: NodeId::new("nodeB"),
            eph_pubkey: eph_sk.public_key(),
            nonce: [0x11u8; 16],
            cookie: None,
            timestamp: 1_700_000_000,
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: Some(TransportLimits {
                max_datagram_bytes: 1200,
            }),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        let transcript = hello.build_transcript();

        // Golden vector for hello transcript (with length-prefixed NodeIds)
        assert_eq!(
            hex::encode(&transcript),
            "464350322d48454c4c4f2d563105006e6f64654105006e6f646542\
a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209\
111111111111111111111111111111110000f1536500000000010001b004",
            "Hello transcript golden vector mismatch"
        );
    }

    #[test]
    fn golden_vector_ack_transcript() {
        let init_eph_sk = X25519SecretKey::from_bytes([0x01u8; 32]);
        let resp_eph_sk = X25519SecretKey::from_bytes([0x02u8; 32]);

        let hello = MeshSessionHello {
            from: NodeId::new("nodeA"),
            to: NodeId::new("nodeB"),
            eph_pubkey: init_eph_sk.public_key(),
            nonce: [0x11u8; 16],
            cookie: None,
            timestamp: 1_700_000_000,
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        let ack = MeshSessionAck {
            from: NodeId::new("nodeB"),
            to: NodeId::new("nodeA"),
            eph_pubkey: resp_eph_sk.public_key(),
            nonce: [0x22u8; 16],
            session_id: [0xAAu8; 16],
            suite: SessionCryptoSuite::Suite1,
            timestamp: 1_700_000_001,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        let transcript = ack.build_transcript(&hello);

        // Golden vector for ack transcript (with length-prefixed NodeIds, includes hello binding)
        assert_eq!(
            hex::encode(&transcript),
            "464350322d41434b2d563105006e6f64654205006e6f646541\
ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59\
22222222222222222222222222222222aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
0001f1536500000000a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209\
11111111111111111111111111111111",
            "Ack transcript golden vector mismatch"
        );
    }

    #[test]
    fn test_verify_incoming_rejects_future_window_exceeded() {
        let keys = SessionKeys {
            k_mac_i2r: [0x01u8; 32],
            k_mac_r2i: [0x02u8; 32],
            k_ctx: [0x03u8; 32],
        };

        let policy = SessionReplayPolicy {
            max_future_window: 100, // Small window for testing
            ..Default::default()
        };

        let mut responder = MeshSession::new(
            [0xAAu8; 16],
            NodeId::new("initiator"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            false,
            1_700_000_000,
            policy,
        );

        // Sequence 1 should be accepted (within window of 0+100)
        // We can't easily compute valid MAC without access to session keys logic here or exposing it
        // But we can check that it returns false. The tricky part is distinguishing "mac fail" from "window fail".
        // verify_incoming returns false for both.
        // However, if we use a seq > max_future_window, it should return false FAST,
        // without even checking MAC.

        // Let's create a valid MAC for a future packet to prove rejection is due to window
        let k_mac_i2r = [0x01u8; 32]; // initiator->responder key
        let session_id = [0xAAu8; 16];
        let direction = 0x00; // initiator->responder
        let frame = b"future attack";

        let seq_too_far = 200u64; // > 100
        let mac_valid_for_far_seq = SessionCryptoSuite::Suite1.compute_mac(
            &k_mac_i2r,
            &session_id,
            direction,
            seq_too_far,
            frame,
        );

        // Should return false due to window check
        assert!(!responder.verify_incoming(seq_too_far, frame, &mac_valid_for_far_seq));

        // Let's verify a valid seq *would* be accepted if window was respected
        let seq_valid = 50u64;
        let mac_valid = SessionCryptoSuite::Suite1.compute_mac(
            &k_mac_i2r,
            &session_id,
            direction,
            seq_valid,
            frame,
        );
        assert!(responder.verify_incoming(seq_valid, frame, &mac_valid));
    }
}

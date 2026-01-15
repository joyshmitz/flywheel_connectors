//! FCP2 crypto primitives and helpers.
//!
//! This crate provides the cryptographic building blocks used by zone key
//! distribution, capability tokens, sessions, receipts, and audit throughout
//! the FCP2 protocol.
//!
//! # Key Role Separation
//!
//! FCP uses distinct keys for:
//! - **Owner signing key** (Ed25519 public anchor; supports threshold signing)
//! - **Node signing key** (Ed25519)
//! - **Node encryption key** (X25519)
//! - **Node issuance key** (Ed25519) for token minting
//! - **Zone symmetric encryption keys** (ChaCha20-Poly1305 / XChaCha20-Poly1305)
//!
//! # Modules
//!
//! - [`ed25519`] - Ed25519 signing and verification
//! - [`x25519`] - X25519 ECDH key exchange
//! - [`hkdf`] - HKDF-SHA256 key derivation
//! - [`aead`] - ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD
//! - [`mac`] - BLAKE3 keyed MAC for session frames
//! - [`hpke_seal`] - HPKE (RFC 9180) for sealed boxes
//! - [`cose`] - COSE_Sign1/CWT helpers for capability tokens
//! - [`kid`] - Key identifier (KID) types
//! - [`canonicalize`] - Signature canonicalization helpers
//!
//! # Example: Signing and Verifying
//!
//! ```rust
//! use fcp_crypto::ed25519::Ed25519SigningKey;
//!
//! let sk = Ed25519SigningKey::generate();
//! let pk = sk.verifying_key();
//!
//! let message = b"important message";
//! let signature = sk.sign(message);
//!
//! assert!(pk.verify(message, &signature).is_ok());
//! ```
//!
//! # Example: HPKE Sealed Box
//!
//! ```rust
//! use fcp_crypto::x25519::X25519SecretKey;
//! use fcp_crypto::hpke_seal::{hpke_seal, hpke_open, Fcp2Aad};
//!
//! let recipient_sk = X25519SecretKey::generate();
//! let recipient_pk = recipient_sk.public_key();
//!
//! let plaintext = b"secret zone key";
//! let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1234567890);
//!
//! let sealed = hpke_seal(&recipient_pk, plaintext, &aad).unwrap();
//! let opened = hpke_open(&recipient_sk, &sealed, &aad).unwrap();
//!
//! assert_eq!(opened, plaintext);
//! ```
//!
//! # Example: Capability Token (COSE/CWT)
//!
//! ```rust
//! use fcp_crypto::ed25519::Ed25519SigningKey;
//! use fcp_crypto::cose::{CapabilityTokenBuilder, CoseToken};
//! use chrono::{Duration, Utc};
//!
//! let issuance_key = Ed25519SigningKey::generate();
//!
//! let token = CapabilityTokenBuilder::new()
//!     .capability_id("cap:discord.send")
//!     .zone_id("z:work")
//!     .principal("agent:claude")
//!     .operations(&["discord.send_message"])
//!     .issuer("node:primary")
//!     .validity(Utc::now(), Utc::now() + Duration::hours(24))
//!     .sign(&issuance_key)
//!     .unwrap();
//!
//! let claims = token.verify(&issuance_key.verifying_key()).unwrap();
//! assert_eq!(claims.get_capability_id(), Some("cap:discord.send"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod canonicalize;
pub mod cose;
pub mod ed25519;
pub mod error;
pub mod hkdf;
pub mod hpke_seal;
pub mod kid;
pub mod mac;
pub mod x25519;

// Re-export commonly used types at crate root
pub use aead::{
    chacha20_decrypt, chacha20_encrypt, xchacha20_decrypt, xchacha20_encrypt, AeadKey,
    ChaCha20Nonce, ChaCha20Poly1305Cipher, XChaCha20Nonce, XChaCha20Poly1305Cipher,
};
pub use canonicalize::{canonical_signing_bytes, schema_hash, Signable};
pub use cose::{CapabilityTokenBuilder, CoseToken, CwtClaims};
pub use ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
pub use error::{CryptoError, CryptoResult};
pub use hkdf::{hkdf_sha256, hkdf_sha256_array, DerivedKey, Fcp2KeyDerivation, HkdfSha256};
pub use hpke_seal::{hpke_open, hpke_seal, Fcp2Aad, HpkeSealedBox};
pub use kid::KeyId;
pub use mac::{blake3_mac, blake3_mac_full, blake3_mac_verify, Blake3Mac, MacKey};
pub use x25519::{X25519PublicKey, X25519SecretKey, X25519SharedSecret};

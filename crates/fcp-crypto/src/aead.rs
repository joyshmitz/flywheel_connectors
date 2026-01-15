//! AEAD encryption for FCP2 using ChaCha20-Poly1305.
//!
//! Provides authenticated encryption with associated data (AEAD) as used
//! by zone encryption, FCPS frames, and symbol envelopes.

use crate::error::{CryptoError, CryptoResult};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, XChaCha20Poly1305,
};
use zeroize::ZeroizeOnDrop;

/// ChaCha20-Poly1305 key size (256 bits).
pub const AEAD_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (96 bits / 12 bytes).
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 nonce size (192 bits / 24 bytes).
pub const XCHACHA20_NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size (128 bits / 16 bytes).
pub const AEAD_TAG_SIZE: usize = 16;

/// AEAD encryption key with zeroize semantics.
#[derive(Clone, ZeroizeOnDrop)]
pub struct AeadKey {
    bytes: [u8; AEAD_KEY_SIZE],
}

impl AeadKey {
    /// Create a new AEAD key from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; AEAD_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Generate a random AEAD key.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; AEAD_KEY_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self { bytes }
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `AEAD_KEY_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != AEAD_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: AEAD_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; AEAD_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; AEAD_KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey").finish_non_exhaustive()
    }
}

/// ChaCha20-Poly1305 nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaCha20Nonce([u8; CHACHA20_NONCE_SIZE]);

impl ChaCha20Nonce {
    /// Create from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHACHA20_NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Generate a random nonce.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; CHACHA20_NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    /// Create from a counter value.
    ///
    /// Useful for protocols with deterministic nonces.
    #[must_use]
    pub fn from_counter(counter: u64) -> Self {
        let mut bytes = [0u8; CHACHA20_NONCE_SIZE];
        bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        Self(bytes)
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `CHACHA20_NONCE_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != CHACHA20_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: CHACHA20_NONCE_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; CHACHA20_NONCE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHACHA20_NONCE_SIZE] {
        &self.0
    }
}

/// XChaCha20-Poly1305 nonce (extended nonce for random generation safety).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XChaCha20Nonce([u8; XCHACHA20_NONCE_SIZE]);

impl XChaCha20Nonce {
    /// Create from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; XCHACHA20_NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Generate a random nonce.
    ///
    /// XChaCha20 uses a 192-bit nonce which is safe for random generation
    /// (birthday collision resistance up to ~2^80 messages).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; XCHACHA20_NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `XCHACHA20_NONCE_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != XCHACHA20_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: XCHACHA20_NONCE_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; XCHACHA20_NONCE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; XCHACHA20_NONCE_SIZE] {
        &self.0
    }
}

/// ChaCha20-Poly1305 AEAD cipher.
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new cipher from a key.
    #[must_use]
    pub fn new(key: &AeadKey) -> Self {
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        Self { cipher }
    }

    /// Encrypt plaintext with associated data.
    ///
    /// Returns ciphertext with appended authentication tag.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (should not happen with valid inputs).
    pub fn encrypt(
        &self,
        nonce: &ChaCha20Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadEncryptFailed)
    }

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails (authentication failure or invalid ciphertext).
    pub fn decrypt(
        &self,
        nonce: &ChaCha20Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadDecryptFailed)
    }
}

/// XChaCha20-Poly1305 AEAD cipher (extended nonce variant).
///
/// Preferred when nonces are generated randomly, as the 192-bit nonce
/// provides sufficient collision resistance for ~2^80 messages.
pub struct XChaCha20Poly1305Cipher {
    cipher: XChaCha20Poly1305,
}

impl XChaCha20Poly1305Cipher {
    /// Create a new cipher from a key.
    #[must_use]
    pub fn new(key: &AeadKey) -> Self {
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        Self { cipher }
    }

    /// Encrypt plaintext with associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(
        &self,
        nonce: &XChaCha20Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadEncryptFailed)
    }

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn decrypt(
        &self,
        nonce: &XChaCha20Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadDecryptFailed)
    }

    /// Encrypt with a random nonce, returning (nonce || ciphertext).
    ///
    /// Convenience method for typical encryption workflows.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt_with_random_nonce(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let nonce = XChaCha20Nonce::generate();
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        let mut result = Vec::with_capacity(XCHACHA20_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce.as_bytes());
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext that has a prepended nonce.
    ///
    /// Expects input format: (nonce || ciphertext).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short or decryption fails.
    pub fn decrypt_with_prepended_nonce(
        &self,
        nonce_and_ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if nonce_and_ciphertext.len() < XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE {
            return Err(CryptoError::AeadDecryptFailed);
        }
        let nonce = XChaCha20Nonce::try_from_slice(&nonce_and_ciphertext[..XCHACHA20_NONCE_SIZE])?;
        let ciphertext = &nonce_and_ciphertext[XCHACHA20_NONCE_SIZE..];
        self.decrypt(&nonce, ciphertext, aad)
    }
}

/// Convenience function: encrypt with ChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn chacha20_encrypt(
    key: &AeadKey,
    nonce: &ChaCha20Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305Cipher::new(key);
    cipher.encrypt(nonce, plaintext, aad)
}

/// Convenience function: decrypt with ChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if decryption fails.
pub fn chacha20_decrypt(
    key: &AeadKey,
    nonce: &ChaCha20Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305Cipher::new(key);
    cipher.decrypt(nonce, ciphertext, aad)
}

/// Convenience function: encrypt with XChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn xchacha20_encrypt(
    key: &AeadKey,
    nonce: &XChaCha20Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305Cipher::new(key);
    cipher.encrypt(nonce, plaintext, aad)
}

/// Convenience function: decrypt with XChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if decryption fails.
pub fn xchacha20_decrypt(
    key: &AeadKey,
    nonce: &XChaCha20Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305Cipher::new(key);
    cipher.decrypt(nonce, ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_roundtrip() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::generate();
        let plaintext = b"hello world";
        let aad = b"additional data";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xchacha20_roundtrip() {
        let key = AeadKey::generate();
        let nonce = XChaCha20Nonce::generate();
        let plaintext = b"hello world";
        let aad = b"additional data";

        let ciphertext = xchacha20_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = xchacha20_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xchacha20_with_random_nonce_roundtrip() {
        let key = AeadKey::generate();
        let cipher = XChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"secret message";
        let aad = b"context";

        let encrypted = cipher.encrypt_with_random_nonce(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt_with_prepended_nonce(&encrypted, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = AeadKey::generate();
        let key2 = AeadKey::generate();
        let nonce = ChaCha20Nonce::generate();

        let ciphertext = chacha20_encrypt(&key1, &nonce, b"secret", b"aad").unwrap();
        let result = chacha20_decrypt(&key2, &nonce, &ciphertext, b"aad");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = AeadKey::generate();
        let nonce1 = ChaCha20Nonce::generate();
        let nonce2 = ChaCha20Nonce::generate();

        let ciphertext = chacha20_encrypt(&key, &nonce1, b"secret", b"aad").unwrap();
        let result = chacha20_decrypt(&key, &nonce2, &ciphertext, b"aad");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::generate();

        let ciphertext = chacha20_encrypt(&key, &nonce, b"secret", b"aad1").unwrap();
        let result = chacha20_decrypt(&key, &nonce, &ciphertext, b"aad2");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::generate();

        let mut ciphertext = chacha20_encrypt(&key, &nonce, b"secret", b"aad").unwrap();
        ciphertext[0] ^= 0xff; // Flip bits
        let result = chacha20_decrypt(&key, &nonce, &ciphertext, b"aad");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn empty_plaintext() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::generate();

        let ciphertext = chacha20_encrypt(&key, &nonce, b"", b"aad").unwrap();
        assert_eq!(ciphertext.len(), AEAD_TAG_SIZE); // Tag only

        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, b"aad").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn empty_aad() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::generate();
        let plaintext = b"secret";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, b"").unwrap();
        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nonce_from_counter() {
        let n1 = ChaCha20Nonce::from_counter(0);
        let n2 = ChaCha20Nonce::from_counter(1);
        let n3 = ChaCha20Nonce::from_counter(0);

        assert_ne!(n1, n2);
        assert_eq!(n1, n3);
    }

    #[test]
    fn ciphertext_length() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::generate();
        let plaintext = b"hello";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, b"").unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_SIZE);
    }

    #[test]
    fn golden_vector_chacha20poly1305() {
        // RFC 8439 test vector
        let key = AeadKey::from_bytes([
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ]);
        let nonce =
            ChaCha20Nonce::from_bytes([0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, &aad).unwrap();

        let expected = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        ).unwrap();

        assert_eq!(ciphertext, expected);

        // Verify decryption
        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

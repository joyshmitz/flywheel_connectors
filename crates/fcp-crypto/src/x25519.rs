//! X25519 Elliptic-curve Diffie-Hellman for FCP2.
//!
//! Provides key exchange primitives used in HPKE and direct key agreement.

use crate::error::{CryptoError, CryptoResult};
use crate::kid::KeyId;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 secret key size in bytes.
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// X25519 public key size in bytes.
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 shared secret size in bytes.
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// X25519 encryption secret key.
///
/// Used for receiving encrypted messages. The corresponding public key
/// can be shared with senders.
#[derive(ZeroizeOnDrop)]
pub struct X25519SecretKey {
    inner: StaticSecret,
    kid: KeyId,
    public: PublicKey,
}

impl X25519SecretKey {
    /// Generate a new random secret key.
    #[must_use]
    pub fn generate() -> Self {
        let inner = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
        let public = PublicKey::from(&inner);
        let kid = KeyId::derive_from_public_key(public.as_bytes());
        Self { inner, kid, public }
    }

    /// Create from raw secret key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_SECRET_KEY_SIZE]) -> Self {
        let inner = StaticSecret::from(bytes);
        let public = PublicKey::from(&inner);
        let kid = KeyId::derive_from_public_key(public.as_bytes());
        Self { inner, kid, public }
    }

    /// Export the secret key bytes.
    ///
    /// **Security Warning:** Handle with extreme care.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_SECRET_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// Get the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            inner: self.public,
            kid: self.kid.clone(),
        }
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.kid.clone()
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    ///
    /// Returns a shared secret that both parties can derive.
    #[must_use]
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> X25519SharedSecret {
        let shared = self.inner.diffie_hellman(&peer_public.inner);
        X25519SharedSecret {
            inner: *shared.as_bytes(),
        }
    }
}

impl Clone for X25519SecretKey {
    fn clone(&self) -> Self {
        Self::from_bytes(self.inner.to_bytes())
    }
}

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SecretKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// X25519 encryption public key.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct X25519PublicKey {
    #[serde(with = "public_key_serde")]
    inner: PublicKey,
    #[serde(skip)]
    kid: KeyId,
}

mod public_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(pk.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(serde::de::Error::custom(format!(
                "invalid X25519 public key length: expected {X25519_PUBLIC_KEY_SIZE}, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; X25519_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from(arr))
    }
}

impl X25519PublicKey {
    /// Create from raw public key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_KEY_SIZE]) -> Self {
        let inner = PublicKey::from(bytes);
        let kid = KeyId::derive_from_public_key(&bytes);
        Self { inner, kid }
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `X25519_PUBLIC_KEY_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut arr = [0u8; X25519_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(slice);
        Ok(Self::from_bytes(arr))
    }

    /// Export the public key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        *self.inner.as_bytes()
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.kid.clone()
    }

    /// Encode as lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl PartialEq for X25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_bytes() == other.inner.as_bytes()
    }
}

impl Eq for X25519PublicKey {}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519PublicKey")
            .field("kid", &self.kid)
            .field("bytes", &self.to_hex())
            .finish()
    }
}

/// X25519 shared secret from Diffie-Hellman.
///
/// This should be passed through a KDF (like HKDF) before use as a key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SharedSecret {
    inner: [u8; X25519_SHARED_SECRET_SIZE],
}

impl X25519SharedSecret {
    /// Get the raw shared secret bytes.
    ///
    /// **Security Warning:** Use HKDF to derive actual keys from this.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_SHARED_SECRET_SIZE] {
        &self.inner
    }
}

impl std::fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SharedSecret")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_exchange() {
        let alice_sk = X25519SecretKey::generate();
        let bob_sk = X25519SecretKey::generate();

        let alice_pk = alice_sk.public_key();
        let bob_pk = bob_sk.public_key();

        let alice_shared = alice_sk.diffie_hellman(&bob_pk);
        let bob_shared = bob_sk.diffie_hellman(&alice_pk);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn different_peers_different_secrets() {
        let alice_sk = X25519SecretKey::generate();
        let bob_sk = X25519SecretKey::generate();
        let charlie_sk = X25519SecretKey::generate();

        let bob_pk = bob_sk.public_key();
        let charlie_pk = charlie_sk.public_key();

        let alice_bob = alice_sk.diffie_hellman(&bob_pk);
        let alice_charlie = alice_sk.diffie_hellman(&charlie_pk);

        assert_ne!(alice_bob.as_bytes(), alice_charlie.as_bytes());
    }

    #[test]
    fn key_roundtrip() {
        let sk = X25519SecretKey::generate();
        let sk_bytes = sk.to_bytes();
        let sk2 = X25519SecretKey::from_bytes(sk_bytes);

        assert_eq!(sk.public_key(), sk2.public_key());
    }

    #[test]
    fn public_key_roundtrip() {
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk2 = X25519PublicKey::from_bytes(pk_bytes);

        assert_eq!(pk, pk2);
    }

    #[test]
    fn key_id_consistent() {
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        assert_eq!(sk.key_id(), pk.key_id());
    }

    #[test]
    fn deterministic_public_key() {
        let sk1 = X25519SecretKey::from_bytes([42u8; 32]);
        let sk2 = X25519SecretKey::from_bytes([42u8; 32]);
        assert_eq!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn golden_vector_x25519() {
        // Test vector: secret key = 32 bytes of 0x01
        let sk = X25519SecretKey::from_bytes([1u8; 32]);
        let pk = sk.public_key();

        // This is the X25519 public key for sk = [1; 32]
        // (clamped as per X25519 spec)
        assert_eq!(
            pk.to_hex(),
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
        );
    }
}

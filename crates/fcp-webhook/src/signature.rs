//! Webhook signature verification.
//!
//! Supports multiple signature algorithms used by different providers.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use crate::{WebhookError, WebhookResult};

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// HMAC-SHA256 (most common).
    HmacSha256,
    /// HMAC-SHA1 (legacy).
    HmacSha1,
    /// Ed25519 (Discord).
    Ed25519,
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacSha256 => write!(f, "HMAC-SHA256"),
            Self::HmacSha1 => write!(f, "HMAC-SHA1"),
            Self::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

/// Trait for signature verification.
pub trait SignatureVerifier: Send + Sync {
    /// Verify a signature against the payload.
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()>;

    /// Get the algorithm used.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// HMAC-SHA256 signature verifier.
#[derive(Clone)]
pub struct HmacSha256Verifier {
    secret: Vec<u8>,
}

impl HmacSha256Verifier {
    /// Create a new HMAC-SHA256 verifier.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
        }
    }

    /// Compute signature for a payload.
    #[must_use]
    pub fn compute(&self, payload: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(payload);
        hex::encode(mac.finalize().into_bytes())
    }
}

impl SignatureVerifier for HmacSha256Verifier {
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()> {
        // Handle different signature formats
        let sig_hex = signature
            .strip_prefix("sha256=")
            .or_else(|| signature.strip_prefix("v1="))
            .unwrap_or(signature);

        let expected = self.compute(payload);

        // Constant-time comparison
        if constant_time_eq(expected.as_bytes(), sig_hex.as_bytes()) {
            Ok(())
        } else {
            Err(WebhookError::InvalidSignature)
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::HmacSha256
    }
}

impl std::fmt::Debug for HmacSha256Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha256Verifier")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// HMAC-SHA1 signature verifier (legacy).
#[derive(Clone)]
pub struct HmacSha1Verifier {
    secret: Vec<u8>,
}

impl HmacSha1Verifier {
    /// Create a new HMAC-SHA1 verifier.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
        }
    }

    /// Compute signature for a payload.
    #[must_use]
    pub fn compute(&self, payload: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha1>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(payload);
        hex::encode(mac.finalize().into_bytes())
    }
}

impl SignatureVerifier for HmacSha1Verifier {
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()> {
        let sig_hex = signature.strip_prefix("sha1=").unwrap_or(signature);
        let expected = self.compute(payload);

        if constant_time_eq(expected.as_bytes(), sig_hex.as_bytes()) {
            Ok(())
        } else {
            Err(WebhookError::InvalidSignature)
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::HmacSha1
    }
}

impl std::fmt::Debug for HmacSha1Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha1Verifier")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Ed25519 signature verifier.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    public_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Verifier {
    /// Create from a hex-encoded public key.
    pub fn from_hex(public_key_hex: &str) -> WebhookResult<Self> {
        let key_bytes = hex::decode(public_key_hex)?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| WebhookError::InvalidSignature)?;

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_array)
            .map_err(|_| WebhookError::InvalidSignature)?;

        Ok(Self { public_key })
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> WebhookResult<Self> {
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|_| WebhookError::InvalidSignature)?;

        Ok(Self { public_key })
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()> {
        use ed25519_dalek::Verifier;

        let sig_bytes = hex::decode(signature)?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| WebhookError::InvalidSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        self.public_key
            .verify(payload, &signature)
            .map_err(|_| WebhookError::InvalidSignature)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_verify() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"test payload";
        let signature = verifier.compute(payload);

        assert!(verifier.verify(payload, &signature).is_ok());
        assert!(verifier.verify(payload, "invalid").is_err());
    }

    #[test]
    fn test_hmac_sha256_with_prefix() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"test payload";
        let signature = format!("sha256={}", verifier.compute(payload));

        assert!(verifier.verify(payload, &signature).is_ok());
    }

    #[test]
    fn test_hmac_sha1_verify() {
        let verifier = HmacSha1Verifier::new("secret");
        let payload = b"test payload";
        let signature = verifier.compute(payload);

        assert!(verifier.verify(payload, &signature).is_ok());
        assert!(verifier.verify(payload, "invalid").is_err());
    }

    #[test]
    fn test_hmac_sha1_with_prefix() {
        let verifier = HmacSha1Verifier::new("secret");
        let payload = b"test payload";
        let signature = format!("sha1={}", verifier.compute(payload));

        assert!(verifier.verify(payload, &signature).is_ok());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"helloworld"));
    }

    #[test]
    fn test_ed25519_verify() {
        use ed25519_dalek::{Signer, SigningKey};

        // Generate a key pair for testing
        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);

        let verifying_key = signing_key.verifying_key();
        let payload = b"test payload";
        let signature = signing_key.sign(payload);

        let verifier = Ed25519Verifier::from_bytes(&verifying_key.to_bytes()).unwrap();
        let sig_hex = hex::encode(signature.to_bytes());

        assert!(verifier.verify(payload, &sig_hex).is_ok());
    }
}

//! PKCE (Proof Key for Code Exchange) implementation.
//!
//! PKCE is an extension to OAuth 2.0 that prevents authorization code
//! interception attacks.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::OAuthError;

/// PKCE code challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PkceMethod {
    /// Plain text (not recommended).
    Plain,
    /// SHA-256 hash (recommended).
    #[default]
    S256,
}

impl std::fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::S256 => write!(f, "S256"),
        }
    }
}

/// PKCE verifier and challenge pair.
#[derive(Debug, Clone)]
pub struct Pkce {
    /// The code verifier (secret, sent during token exchange).
    verifier: String,
    /// The code challenge (sent during authorization).
    challenge: String,
    /// The challenge method used.
    method: PkceMethod,
}

impl Pkce {
    /// Generate a new PKCE pair using S256 method.
    #[must_use]
    pub fn new() -> Self {
        Self::with_method(PkceMethod::S256)
    }

    /// Generate a new PKCE pair with specified method.
    #[must_use]
    pub fn with_method(method: PkceMethod) -> Self {
        let verifier = Self::generate_verifier();
        let challenge = Self::compute_challenge(&verifier, method);

        Self {
            verifier,
            challenge,
            method,
        }
    }

    /// Create from an existing verifier.
    ///
    /// # Errors
    ///
    /// Returns error if verifier is invalid.
    pub fn from_verifier(verifier: &str, method: PkceMethod) -> Result<Self, OAuthError> {
        // Validate verifier length (43-128 characters per RFC 7636)
        if verifier.len() < 43 || verifier.len() > 128 {
            return Err(OAuthError::PkceError(format!(
                "Verifier must be 43-128 characters, got {}",
                verifier.len()
            )));
        }

        // Validate verifier characters (unreserved characters only)
        if !verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            return Err(OAuthError::PkceError(
                "Verifier contains invalid characters".to_string(),
            ));
        }

        let challenge = Self::compute_challenge(verifier, method);

        Ok(Self {
            verifier: verifier.to_string(),
            challenge,
            method,
        })
    }

    /// Get the code verifier.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Get the code challenge.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Get the challenge method.
    #[must_use]
    pub const fn method(&self) -> PkceMethod {
        self.method
    }

    /// Generate a cryptographically random verifier.
    fn generate_verifier() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Compute the challenge from a verifier.
    fn compute_challenge(verifier: &str, method: PkceMethod) -> String {
        match method {
            PkceMethod::Plain => verifier.to_string(),
            PkceMethod::S256 => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let hash = hasher.finalize();
                URL_SAFE_NO_PAD.encode(hash)
            }
        }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation() {
        let pkce = Pkce::new();

        // Verifier should be base64url encoded (43 chars for 32 bytes)
        assert_eq!(pkce.verifier().len(), 43);
        assert_eq!(pkce.method(), PkceMethod::S256);

        // Challenge should be different from verifier for S256
        assert_ne!(pkce.verifier(), pkce.challenge());
    }

    #[test]
    fn test_pkce_plain() {
        let pkce = Pkce::with_method(PkceMethod::Plain);

        // For plain method, challenge equals verifier
        assert_eq!(pkce.verifier(), pkce.challenge());
        assert_eq!(pkce.method(), PkceMethod::Plain);
    }

    #[test]
    fn test_pkce_from_verifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let pkce = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();

        assert_eq!(pkce.verifier(), verifier);
        // Known challenge for this verifier
        assert_eq!(pkce.challenge(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_pkce_invalid_verifier() {
        // Too short
        let result = Pkce::from_verifier("short", PkceMethod::S256);
        assert!(result.is_err());

        // Invalid characters
        let result = Pkce::from_verifier(&"a".repeat(50).replace('a', " "), PkceMethod::S256);
        assert!(result.is_err());
    }
}

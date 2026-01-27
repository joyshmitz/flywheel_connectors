//! Secret storage and access types for FCP2 (NORMATIVE).
//!
//! This module implements `SecretObject` and `SecretAccessToken` as described in
//! `FCP_Specification_V2.md` for secure credential handling.
//!
//! **Security guarantees:**
//! - Secret material MUST be zeroized immediately after use.
//! - Every successful access MUST emit an `AuditEvent` with `event_type = "secret.access"`.
//! - Secret bytes MUST NOT appear in logs or error messages.
//! - Threshold secrets (k-of-n) are supported via wrapped shares.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ObjectHeader, ObjectId, PrincipalId, ZoneId};

/// Canonical secret identifier (NORMATIVE).
///
/// A `SecretId` uniquely identifies a secret within a zone. It is used to
/// reference secrets without exposing their content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(Uuid);

impl SecretId {
    /// Create a new random `SecretId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `SecretId` from a UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Parse a `SecretId` from a string.
    ///
    /// # Errors
    /// Returns an error if the string is not a valid UUID.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    /// Create a test `SecretId` from bytes (for testing only).
    #[cfg(test)]
    #[must_use]
    pub const fn test_id(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretId")
            .field(&self.0.to_string())
            .finish()
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type of secret stored (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    /// API key or bearer token.
    ApiKey,
    /// OAuth access/refresh token.
    OAuthToken,
    /// Webhook signing secret.
    WebhookSecret,
    /// Database password.
    DatabasePassword,
    /// TLS client certificate and key.
    ClientCertificate,
    /// SSH private key.
    SshKey,
    /// Generic secret (opaque bytes).
    Generic,
    /// HMAC signing key.
    HmacKey,
    /// Encryption key material.
    EncryptionKey,
}

/// Secret storage format (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretFormat {
    /// Raw bytes, encrypted at rest.
    Raw,
    /// Threshold secret share (k-of-n).
    ThresholdShare {
        /// Share index (1-based).
        index: u8,
        /// Total shares required for reconstruction.
        threshold: u8,
        /// Total shares in the scheme.
        total: u8,
    },
    /// Wrapped key (encrypted with zone key).
    WrappedKey,
}

/// Mesh-stored secret object (NORMATIVE).
///
/// Secrets are stored/represented as mesh objects. The actual secret material
/// is encrypted; accessing it requires a valid `SecretAccessToken`.
///
/// **IMPORTANT**: The `encrypted_payload` field contains the encrypted secret.
/// The plaintext secret bytes MUST NEVER be logged, serialized to JSON for
/// debugging, or stored anywhere except ephemeral memory during use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretObject {
    /// Standard object header.
    pub header: ObjectHeader,

    /// Unique identifier for this secret.
    pub secret_id: SecretId,

    /// Type of secret (determines application semantics).
    pub secret_type: SecretType,

    /// Storage format (raw, threshold share, wrapped).
    pub format: SecretFormat,

    /// Human-readable label (MUST NOT contain secret material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Encrypted secret payload (zone-key encrypted).
    ///
    /// Format: `COSE_Encrypt0` with ChaCha20-Poly1305.
    /// AAD includes: `secret_id` || `zone_id` || `schema_hash`.
    #[serde(with = "crate::util::hex_or_bytes_vec")]
    pub encrypted_payload: Vec<u8>,

    /// Key derivation info for the encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_derivation_info: Option<KeyDerivationInfo>,

    /// When this secret expires (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Maximum times this secret can be accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_access_count: Option<u32>,

    /// Current access count (for rate limiting).
    #[serde(default)]
    pub access_count: u32,

    /// Object ID of the revocation entry if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<ObjectId>,
}

impl SecretObject {
    /// Check if this secret has expired.
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_unix >= exp)
    }

    /// Check if this secret has been revoked.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked_by.is_some()
    }

    /// Check if access count limit has been reached.
    #[must_use]
    pub fn is_access_exhausted(&self) -> bool {
        self.max_access_count
            .is_some_and(|max| self.access_count >= max)
    }

    /// Check if this secret is currently usable.
    #[must_use]
    pub fn is_usable(&self, now_unix: u64) -> bool {
        !self.is_expired(now_unix) && !self.is_revoked() && !self.is_access_exhausted()
    }

    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }
}

/// Key derivation information for secret encryption (NORMATIVE when present).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationInfo {
    /// Algorithm used (e.g., "HKDF-SHA256").
    pub algorithm: String,

    /// Salt (if applicable).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::util::hex_or_bytes_vec"
    )]
    pub salt: Vec<u8>,

    /// Info/context string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
}

/// Short-lived authorization to access a secret (NORMATIVE).
///
/// A `SecretAccessToken` grants temporary permission to decrypt and use a secret.
/// Every use of this token MUST emit an audit event.
///
/// **Security properties:**
/// - Short-lived (typically < 5 minutes).
/// - Single-use or bounded-use.
/// - Bound to a specific principal and purpose.
/// - Audited on creation and use.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretAccessToken {
    /// Unique token identifier (for audit correlation).
    #[zeroize(skip)]
    pub token_id: Uuid,

    /// Secret this token grants access to.
    #[zeroize(skip)]
    pub secret_id: SecretId,

    /// Zone where this token is valid.
    #[zeroize(skip)]
    pub zone_id: ZoneId,

    /// Principal who requested access.
    #[zeroize(skip)]
    pub requester: PrincipalId,

    /// Purpose/reason for access (for audit).
    #[zeroize(skip)]
    pub purpose: String,

    /// When this token was issued (Unix timestamp).
    #[zeroize(skip)]
    pub issued_at: u64,

    /// When this token expires (Unix timestamp).
    #[zeroize(skip)]
    pub expires_at: u64,

    /// Maximum number of times this token can be used.
    #[zeroize(skip)]
    pub max_uses: u32,

    /// Current use count.
    #[zeroize(skip)]
    pub use_count: u32,

    /// Cryptographic authorization (signed by zone authority).
    /// Format: `COSE_Sign1` over (`token_id` || `secret_id` || `zone_id` || requester || `expires_at`).
    authorization: Vec<u8>,
}

impl SecretAccessToken {
    /// Create a new `SecretAccessToken`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_id: SecretId,
        zone_id: ZoneId,
        requester: PrincipalId,
        purpose: String,
        issued_at: u64,
        expires_at: u64,
        max_uses: u32,
        authorization: Vec<u8>,
    ) -> Self {
        Self {
            token_id: Uuid::new_v4(),
            secret_id,
            zone_id,
            requester,
            purpose,
            issued_at,
            expires_at,
            max_uses,
            use_count: 0,
            authorization,
        }
    }

    /// Check if this token has expired.
    #[must_use]
    pub const fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }

    /// Check if this token has been exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.use_count >= self.max_uses
    }

    /// Check if this token is currently valid (not expired and not exhausted).
    #[must_use]
    pub const fn is_valid(&self, now_unix: u64) -> bool {
        !self.is_expired(now_unix) && !self.is_exhausted()
    }

    /// Record a use of this token.
    ///
    /// Returns `true` if the use was allowed, `false` if exhausted.
    pub const fn record_use(&mut self) -> bool {
        if self.is_exhausted() {
            return false;
        }
        self.use_count += 1;
        true
    }

    /// Get the authorization bytes (for verification).
    #[must_use]
    pub fn authorization(&self) -> &[u8] {
        &self.authorization
    }

    /// Remaining uses for this token.
    #[must_use]
    pub const fn remaining_uses(&self) -> u32 {
        self.max_uses.saturating_sub(self.use_count)
    }
}

impl fmt::Debug for SecretAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // MUST NOT expose authorization bytes in debug output
        f.debug_struct("SecretAccessToken")
            .field("token_id", &self.token_id)
            .field("secret_id", &self.secret_id)
            .field("zone_id", &self.zone_id)
            .field("requester", &self.requester)
            .field("purpose", &self.purpose)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .field("use_count", &self.use_count)
            .field("authorization", &"[redacted]")
            .finish()
    }
}

/// Decrypted secret material (NORMATIVE).
///
/// This type holds the actual secret bytes after decryption. It implements
/// `Zeroize` and `ZeroizeOnDrop` to ensure the secret is securely erased from
/// memory when dropped.
///
/// **CRITICAL**: This type MUST NOT implement `Serialize`, `Clone`, or any other
/// trait that would allow the secret to persist beyond its intended use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretMaterial {
    /// The decrypted secret bytes.
    bytes: Vec<u8>,
}

impl SecretMaterial {
    /// Create new secret material from bytes.
    ///
    /// The bytes are moved into this type and will be zeroized on drop.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Access the secret bytes.
    ///
    /// **WARNING**: Do not log, serialize, or persist these bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // MUST NOT expose secret bytes in debug output
        f.debug_struct("SecretMaterial")
            .field("len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", "SecretObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::new("user:alice").expect("valid principal")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_id_new_is_unique() {
        let id1 = SecretId::new();
        let id2 = SecretId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn secret_id_parse_roundtrip() {
        let id = SecretId::new();
        let s = id.to_string();
        let parsed = SecretId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn secret_id_display_is_uuid() {
        let uuid = Uuid::from_bytes([0xAB; 16]);
        let id = SecretId::from_uuid(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn secret_id_debug_redacts_nothing() {
        let id = SecretId::test_id([0x12; 16]);
        let debug = format!("{id:?}");
        assert!(debug.contains("SecretId"));
    }

    #[test]
    fn secret_id_serialization_roundtrip() {
        let id = SecretId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: SecretId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretType Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&SecretType::ApiKey).unwrap(),
            "\"api_key\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::OAuthToken).unwrap(),
            "\"o_auth_token\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::WebhookSecret).unwrap(),
            "\"webhook_secret\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::DatabasePassword).unwrap(),
            "\"database_password\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::ClientCertificate).unwrap(),
            "\"client_certificate\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_object_is_expired() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: Some("test-secret".into()),
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: Some(1_700_000_100),
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_expired(1_700_000_000));
        assert!(!secret.is_expired(1_700_000_099));
        assert!(secret.is_expired(1_700_000_100));
        assert!(secret.is_expired(1_700_000_200));
    }

    #[test]
    fn secret_object_no_expiry_never_expires() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: None,
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_expired(u64::MAX));
    }

    #[test]
    fn secret_object_is_revoked() {
        let mut secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: None,
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_revoked());

        secret.revoked_by = Some(ObjectId::from_bytes([0xFF; 32]));
        assert!(secret.is_revoked());
    }

    #[test]
    fn secret_object_access_exhausted() {
        let mut secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: None,
            max_access_count: Some(5),
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_access_exhausted());
        secret.access_count = 4;
        assert!(!secret.is_access_exhausted());
        secret.access_count = 5;
        assert!(secret.is_access_exhausted());
        secret.access_count = 6;
        assert!(secret.is_access_exhausted());
    }

    #[test]
    fn secret_object_is_usable() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: Some(1_700_000_100),
            max_access_count: Some(5),
            access_count: 3,
            revoked_by: None,
        };

        assert!(secret.is_usable(1_700_000_000));
    }

    #[test]
    fn secret_object_not_usable_when_expired() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: Some(1_700_000_100),
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_usable(1_700_000_200));
    }

    #[test]
    fn secret_object_serialization_roundtrip() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::DatabasePassword,
            format: SecretFormat::WrappedKey,
            label: Some("db-prod".into()),
            encrypted_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            key_derivation_info: Some(KeyDerivationInfo {
                algorithm: "HKDF-SHA256".into(),
                salt: vec![0x01, 0x02, 0x03],
                info: Some("db-password-v1".into()),
            }),
            expires_at: Some(1_800_000_000),
            max_access_count: Some(100),
            access_count: 5,
            revoked_by: None,
        };

        let json = serde_json::to_string(&secret).unwrap();
        let decoded: SecretObject = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.secret_id, secret.secret_id);
        assert_eq!(decoded.secret_type, SecretType::DatabasePassword);
        assert_eq!(decoded.label.as_deref(), Some("db-prod"));
        assert_eq!(decoded.encrypted_payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretFormat Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_format_threshold_share() {
        let format = SecretFormat::ThresholdShare {
            index: 1,
            threshold: 3,
            total: 5,
        };

        let json = serde_json::to_string(&format).unwrap();
        assert!(json.contains("threshold_share"));
        assert!(json.contains("\"index\":1"));
        assert!(json.contains("\"threshold\":3"));
        assert!(json.contains("\"total\":5"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretAccessToken Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_access_token_validity() {
        let token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "connector-egress".into(),
            1_700_000_000,
            1_700_000_300, // 5 minute validity
            3,
            vec![0u8; 64],
        );

        assert!(token.is_valid(1_700_000_000));
        assert!(token.is_valid(1_700_000_299));
        assert!(!token.is_valid(1_700_000_300)); // expired
        assert!(!token.is_valid(1_700_000_500)); // expired
    }

    #[test]
    fn secret_access_token_exhaustion() {
        let mut token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "test".into(),
            1_700_000_000,
            1_700_000_300,
            2,
            vec![0u8; 64],
        );

        assert!(!token.is_exhausted());
        assert_eq!(token.remaining_uses(), 2);

        assert!(token.record_use());
        assert!(!token.is_exhausted());
        assert_eq!(token.remaining_uses(), 1);

        assert!(token.record_use());
        assert!(token.is_exhausted());
        assert_eq!(token.remaining_uses(), 0);

        assert!(!token.record_use()); // Should fail - exhausted
    }

    #[test]
    fn secret_access_token_debug_redacts_authorization() {
        let token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "test".into(),
            1_700_000_000,
            1_700_000_300,
            1,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        let debug = format!("{token:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("beef"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretMaterial Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_material_access() {
        let material = SecretMaterial::new(vec![1, 2, 3, 4]);
        assert_eq!(material.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(material.len(), 4);
        assert!(!material.is_empty());
    }

    #[test]
    fn secret_material_empty() {
        let material = SecretMaterial::new(vec![]);
        assert!(material.is_empty());
        assert_eq!(material.len(), 0);
    }

    #[test]
    fn secret_material_debug_redacts() {
        let material = SecretMaterial::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{material:?}");
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("beef"));
    }

    #[test]
    fn secret_material_zeroize_on_drop() {
        // This test verifies the type has ZeroizeOnDrop derive
        // We can't easily verify the actual zeroization without unsafe code,
        // but we can verify the type compiles with the derive
        let material = SecretMaterial::new(vec![0xFF; 100]);
        assert_eq!(material.len(), 100);
        drop(material);
        // If we got here without panic, the drop succeeded
    }
}

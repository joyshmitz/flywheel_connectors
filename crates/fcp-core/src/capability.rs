//! Capability types and token verification.
//!
//! Capabilities are cryptographically-scoped permissions that grant specific
//! actions to principals within zones. Capability tokens (FCT) carry the
//! cryptographic proof of authorization.

use std::fmt;
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{FcpError, FcpResult};

/// Canonical identifier validation error (NORMATIVE).
///
/// Applies to the identifier set in `FCP_Specification_V2.md` §3.4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdValidationError {
    #[error("identifier must not be empty")]
    Empty,

    #[error("identifier too long ({len} bytes > {max} bytes)")]
    TooLong { len: usize, max: usize },

    #[error("identifier must be ASCII")]
    NonAscii,

    #[error("identifier contains uppercase ASCII")]
    UppercaseNotAllowed,

    #[error("identifier has invalid start character '{ch}'")]
    InvalidStartChar { ch: char },

    #[error("identifier has invalid character '{ch}' at byte {index}")]
    InvalidChar { ch: char, index: usize },
}

/// Validate identifier canonicity (NORMATIVE).
///
/// Rules:
/// - ASCII only (no Unicode)
/// - lowercase only (no mixed case)
/// - length ≤ 128 bytes
/// - regex: `^[a-z0-9][a-z0-9._:-]*$`
///
/// # Errors
/// Returns an `IdValidationError` if the identifier is not canonical.
pub fn validate_canonical_id(id: &str) -> Result<(), IdValidationError> {
    if id.is_empty() {
        return Err(IdValidationError::Empty);
    }

    if id.len() > 128 {
        return Err(IdValidationError::TooLong {
            len: id.len(),
            max: 128,
        });
    }

    if !id.is_ascii() {
        return Err(IdValidationError::NonAscii);
    }

    if id.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(IdValidationError::UppercaseNotAllowed);
    }

    let mut chars = id.char_indices();
    let Some((_, first)) = chars.next() else {
        return Err(IdValidationError::Empty);
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(IdValidationError::InvalidStartChar { ch: first });
    }

    for (index, ch) in chars {
        let ok =
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | ':' | '-');
        if !ok {
            return Err(IdValidationError::InvalidChar { ch, index });
        }
    }

    Ok(())
}

/// Capability identifier - unique name for a permission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityId(String);

impl CapabilityId {
    /// Create a new capability ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    /// Create a capability ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        Self::new(id).expect("static capability ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CapabilityId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value))
    }
}

impl From<CapabilityId> for String {
    fn from(value: CapabilityId) -> Self {
        value.0
    }
}

impl std::str::FromStr for CapabilityId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for CapabilityId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Connector identifier - unique name for a connector type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConnectorId(String);

impl ConnectorId {
    /// Create a new connector ID with full details.
    ///
    /// # Errors
    /// Returns an error if the constructed identifier is not canonical.
    pub fn new(
        name: impl Into<String>,
        archetype: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, IdValidationError> {
        Self::try_from(format!(
            "{}:{}:{}",
            name.into(),
            archetype.into(),
            version.into()
        ))
    }

    /// Create a connector ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        id.parse().expect("static connector ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConnectorId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value))
    }
}

impl From<ConnectorId> for String {
    fn from(value: ConnectorId) -> Self {
        value.0
    }
}

impl std::str::FromStr for ConnectorId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for ConnectorId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Instance identifier - unique ID for a running connector instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InstanceId(String);

impl InstanceId {
    /// Generate a new random instance ID.
    #[must_use]
    pub fn new() -> Self {
        Self(format!("inst_{}", Uuid::new_v4()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for InstanceId {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<String> for InstanceId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value))
    }
}

impl From<InstanceId> for String {
    fn from(value: InstanceId) -> Self {
        value.0
    }
}

impl std::str::FromStr for InstanceId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for InstanceId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Operation identifier - name for a connector function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    /// Create a new operation ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    /// Create an operation ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        Self::new(id).expect("static operation ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value))
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

impl std::str::FromStr for OperationId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for OperationId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Zone identifier - name of a trust boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ZoneId(String);

/// Fixed-size `ZoneId` hash (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneIdHash([u8; 32]);

impl ZoneIdHash {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ZoneIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneIdHash")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl AsRef<[u8]> for ZoneIdHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ZoneIdError {
    #[error("zone id must not be empty")]
    Empty,

    #[error("zone id too long ({len} bytes > {max} bytes)")]
    TooLong { len: usize, max: usize },

    #[error("zone id must be ASCII")]
    NonAscii,

    #[error("zone id must start with `z:`")]
    MissingPrefix,

    #[error("tailscale tag must start with `tag:fcp-`")]
    InvalidTailscaleTagPrefix,

    #[error("zone id has invalid character '{ch}' at byte {index}")]
    InvalidChar { ch: char, index: usize },
}

impl ZoneId {
    /// Owner zone - highest trust level.
    pub const OWNER: &str = "z:owner";
    /// Private zone - personal data.
    pub const PRIVATE: &str = "z:private";
    /// Work zone - project collaboration.
    pub const WORK: &str = "z:work";
    /// Community zone - public/semi-public content.
    pub const COMMUNITY: &str = "z:community";
    /// Public zone - internet-facing, untrusted.
    pub const PUBLIC: &str = "z:public";

    /// Create an owner zone.
    #[must_use]
    pub fn owner() -> Self {
        Self(Self::OWNER.into())
    }

    /// Create a private zone.
    #[must_use]
    pub fn private() -> Self {
        Self(Self::PRIVATE.into())
    }

    /// Create a work zone.
    #[must_use]
    pub fn work() -> Self {
        Self(Self::WORK.into())
    }

    /// Create a community zone.
    #[must_use]
    pub fn community() -> Self {
        Self(Self::COMMUNITY.into())
    }

    /// Create a public zone.
    #[must_use]
    pub fn public() -> Self {
        Self(Self::PUBLIC.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Raw bytes of canonical `ZoneId` string (NORMATIVE).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Fixed-size hash of `ZoneId` (NORMATIVE).
    #[must_use]
    pub fn hash(&self) -> ZoneIdHash {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-ZONE-ID-V1");
        h.update(self.as_bytes());
        ZoneIdHash(*h.finalize().as_bytes())
    }

    /// Map to Tailscale ACL tag.
    #[must_use]
    pub fn to_tailscale_tag(&self) -> String {
        format!(
            "tag:fcp-{}",
            self.as_str().strip_prefix("z:").unwrap_or(self.as_str())
        )
    }

    /// Create from Tailscale ACL tag.
    ///
    /// # Errors
    /// Returns an error if the tag prefix is invalid or the resulting zone id is non-canonical.
    pub fn from_tailscale_tag(tag: &str) -> Result<Self, ZoneIdError> {
        let Some(suffix) = tag.strip_prefix("tag:fcp-") else {
            return Err(ZoneIdError::InvalidTailscaleTagPrefix);
        };
        let zone = format!("z:{suffix}");
        zone.parse()
    }
}

impl ZoneId {
    fn validate(zone_id: &str) -> Result<(), ZoneIdError> {
        if zone_id.is_empty() {
            return Err(ZoneIdError::Empty);
        }

        if zone_id.len() > 64 {
            return Err(ZoneIdError::TooLong {
                len: zone_id.len(),
                max: 64,
            });
        }

        if !zone_id.is_ascii() {
            return Err(ZoneIdError::NonAscii);
        }

        if !zone_id.starts_with("z:") {
            return Err(ZoneIdError::MissingPrefix);
        }

        for (index, ch) in zone_id.char_indices() {
            let ok =
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, ':' | '_' | '-');
            if !ok {
                return Err(ZoneIdError::InvalidChar { ch, index });
            }
        }

        Ok(())
    }
}

impl TryFrom<String> for ZoneId {
    type Error = ZoneIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value))
    }
}

impl From<ZoneId> for String {
    fn from(value: ZoneId) -> Self {
        value.0
    }
}

impl std::str::FromStr for ZoneId {
    type Err = ZoneIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for ZoneId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Principal identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Create a new principal ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value))
    }
}

impl From<PrincipalId> for String {
    fn from(value: PrincipalId) -> Self {
        value.0
    }
}

impl std::str::FromStr for PrincipalId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for PrincipalId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Flywheel Capability Token (FCT) - cryptographically signed authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Token ID (unique per token)
    pub jti: Uuid,

    /// Subject (principal this token is issued to)
    pub sub: PrincipalId,

    /// Issuer (zone that issued this token)
    pub iss: ZoneId,

    /// Audience (connector this token is valid for)
    pub aud: ConnectorId,

    /// Optional instance binding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<InstanceId>,

    /// Issued at (Unix timestamp)
    pub iat: u64,

    /// Expires at (Unix timestamp)
    pub exp: u64,

    /// Granted capabilities
    pub caps: Vec<CapabilityGrant>,

    /// Additional constraints
    #[serde(default)]
    pub constraints: CapabilityConstraints,

    /// Ed25519 signature over the token payload
    #[serde(with = "signature_bytes")]
    pub sig: [u8; 64],
}

impl CapabilityToken {
    /// Create a test token with minimal fields for testing.
    ///
    /// This token has a dummy signature and should only be used in tests.
    ///
    /// # Panics
    /// Panics if any of the hard-coded test identifiers are not canonical.
    #[must_use]
    pub fn test_token() -> Self {
        Self {
            jti: Uuid::new_v4(),
            sub: "test-principal"
                .parse()
                .expect("test principal id must be canonical"),
            iss: ZoneId::work(),
            aud: "test-connector"
                .parse()
                .expect("test connector id must be canonical"),
            instance: None,
            iat: u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
            exp: u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0) + 3600,
            caps: vec![CapabilityGrant {
                capability: "cap.all"
                    .parse()
                    .expect("test capability id must be canonical"),
                operation: None,
            }],
            constraints: CapabilityConstraints::default(),
            sig: [0u8; 64], // Dummy signature for testing
        }
    }
}

mod signature_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid signature length"))
    }
}

/// A single capability grant within a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// The capability being granted
    pub capability: CapabilityId,

    /// Optional operation scope (if None, applies to all operations under this cap)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationId>,
}

/// Constraints on capability usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityConstraints {
    /// Resource URI patterns that are allowed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_allow: Vec<String>,

    /// Resource URI patterns that are denied
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_deny: Vec<String>,

    /// Maximum number of invocations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,

    /// Maximum bytes that can be transferred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,

    /// Idempotency key for deduplication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests in the period
    pub max: u32,

    /// Period in milliseconds
    pub per_ms: u64,

    /// Burst allowance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,

    /// Scope: `per_connector`, `per_zone`, or `per_principal`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Verifies capability tokens against the host's public key.
#[derive(Debug, Clone)]
pub struct CapabilityVerifier {
    /// Host's Ed25519 public key
    pub host_public_key: [u8; 32],

    /// Zone this connector is bound to
    pub zone_id: ZoneId,

    /// Instance ID for this connector
    pub instance_id: InstanceId,
}

impl CapabilityVerifier {
    /// Create a new capability verifier.
    #[must_use]
    pub const fn new(host_public_key: [u8; 32], zone_id: ZoneId, instance_id: InstanceId) -> Self {
        Self {
            host_public_key,
            zone_id,
            instance_id,
        }
    }

    /// Verify a capability token for a specific operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the token:
    /// - fails signature verification,
    /// - is expired,
    /// - is bound to a different zone or instance,
    /// - does not grant the requested operation,
    /// - violates resource constraints.
    pub fn verify(
        &self,
        token: &CapabilityToken,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<()> {
        // Verify signature
        self.verify_signature(token)?;

        // Check expiry
        // Use try_from to safely handle negative timestamps (before Unix epoch)
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        if token.exp <= now {
            return Err(FcpError::TokenExpired);
        }

        // Check zone binding
        if token.iss != self.zone_id {
            return Err(FcpError::ZoneViolation {
                source_zone: token.iss.0.clone(),
                target_zone: self.zone_id.0.clone(),
                message: "Token zone mismatch".into(),
            });
        }

        // Check instance binding (if specified)
        if let Some(ref inst) = token.instance {
            if inst != &self.instance_id {
                return Err(FcpError::CapabilityDenied {
                    capability: operation.0.clone(),
                    reason: "Instance mismatch".into(),
                });
            }
        }

        // Check operation is granted
        let op_allowed = token
            .caps
            .iter()
            .any(|c| c.operation.as_ref().is_none_or(|op| op == operation));
        if !op_allowed {
            return Err(FcpError::OperationNotGranted {
                operation: operation.0.clone(),
            });
        }

        // Enforce resource constraints
        Self::enforce_resource_constraints(&token.constraints, resource_uris)?;

        Ok(())
    }

    fn verify_signature(&self, token: &CapabilityToken) -> FcpResult<()> {
        // Reconstruct the payload that was signed
        let payload = serde_json::json!({
            "jti": token.jti,
            "sub": token.sub,
            "iss": token.iss,
            "aud": token.aud,
            "instance": token.instance,
            "iat": token.iat,
            "exp": token.exp,
            "caps": token.caps,
            "constraints": token.constraints,
        });
        let payload_bytes = serde_json::to_vec(&payload).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize token payload: {e}"),
        })?;

        // Verify Ed25519 signature
        let verifying_key =
            VerifyingKey::from_bytes(&self.host_public_key).map_err(|_| FcpError::Internal {
                message: "Invalid host public key".into(),
            })?;

        let signature = Signature::from_bytes(&token.sig);

        verifying_key
            .verify(&payload_bytes, &signature)
            .map_err(|_| FcpError::InvalidSignature)?;

        Ok(())
    }

    fn enforce_resource_constraints(
        constraints: &CapabilityConstraints,
        resource_uris: &[String],
    ) -> FcpResult<()> {
        // Check allow list (if non-empty, all resources must match)
        if !constraints.resource_allow.is_empty() {
            let all_allowed = resource_uris.iter().all(|uri| {
                constraints
                    .resource_allow
                    .iter()
                    .any(|pattern| uri.starts_with(pattern))
            });
            if !all_allowed {
                return Err(FcpError::ResourceNotAllowed {
                    resource: resource_uris.first().cloned().unwrap_or_default(),
                });
            }
        }

        // Check deny list
        for uri in resource_uris {
            if constraints
                .resource_deny
                .iter()
                .any(|pattern| uri.starts_with(pattern))
            {
                return Err(FcpError::ResourceNotAllowed {
                    resource: uri.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Risk level for operations and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Safety tier classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyTier {
    /// Safe by default, no approval needed
    Safe,
    /// Requires policy check
    Risky,
    /// Requires interactive approval
    Dangerous,
    /// Never allowed
    Forbidden,
}

/// Idempotency classification for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    /// No idempotency guarantees
    None,
    /// Best-effort deduplication
    BestEffort,
    /// Strict idempotency with key
    Strict,
}

/// Retry configuration for operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,

    /// Initial delay between retries
    #[serde(with = "duration_millis")]
    pub initial_delay: Duration,

    /// Maximum delay between retries
    #[serde(with = "duration_millis")]
    pub max_delay: Duration,

    /// Multiplier for exponential backoff
    pub multiplier: f64,
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

/// Retry with exponential backoff.
///
/// # Errors
///
/// Returns the final non-retryable error from `operation`, or the last retryable error once
/// `max_attempts` is exhausted.
pub async fn retry_with_backoff<F, Fut, T>(config: &RetryConfig, mut operation: F) -> FcpResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = FcpResult<T>>,
{
    let mut delay = config.initial_delay;
    let mut attempt = 0;

    loop {
        attempt += 1;
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if e.is_retryable() && attempt < config.max_attempts => {
                if let Some(retry_after) = e.retry_after() {
                    tokio::time::sleep(retry_after).await;
                } else {
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(
                        Duration::from_secs_f64(delay.as_secs_f64() * config.multiplier),
                        config.max_delay,
                    );
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Correlation identifier for request tracing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    /// Generate a new random correlation ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session identifier - unique ID for a handshake session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    /// Generate a new random session ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Principal - an identity making requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// Type of principal (e.g., "user", "agent", "service", "webhook")
    pub kind: String,

    /// Unique identifier for this principal
    pub id: String,

    /// Trust level of this principal
    pub trust: TrustLevel,

    /// Display name for humans
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// Trust level for principals.
///
/// Per FCP Specification Section 6.5 (Ingress Bindings):
/// These are the canonical trust levels for external principals.
/// Order is from lowest to highest trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Explicitly denied access
    Blocked,
    /// Unauthenticated user
    Anonymous,
    /// Authenticated but not approved
    Untrusted,
    /// Explicitly approved external user
    Paired,
    /// Elevated but not root
    Admin,
    /// Root trust (owner)
    Owner,
}

/// Taint level for provenance tracking.
///
/// Per FCP Specification Section 7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum TaintLevel {
    /// Trusted source only
    #[default]
    Untainted,
    /// Untrusted input present in chain
    Tainted,
    /// Direct untrusted instruction
    HighlyTainted,
}

/// A step in the provenance chain.
///
/// Per FCP Specification Section 7.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceStep {
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,

    /// Zone where this step occurred
    pub zone: ZoneId,

    /// Actor (agent/user/connector id)
    pub actor: String,

    /// Action performed (e.g., "discord.message", "tool.invoke")
    pub action: String,

    /// Resource URI or capability identifier
    pub resource: String,
}

/// Provenance metadata for tracking data origin.
///
/// Per FCP Specification Section 7.2:
/// - `origin_zone`: Where the triggering input originated
/// - `chain`: Monotonic chain of causal steps
/// - `taint`: Highest taint severity observed in the chain
/// - `elevated`: Whether explicit elevation has been granted
/// - `elevation_token`: Token proving elevation (if elevated)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// The zone where the request/data originated
    pub origin_zone: ZoneId,

    /// Monotonic chain of causal steps
    #[serde(default)]
    pub chain: Vec<ProvenanceStep>,

    /// Highest taint severity observed in the chain
    #[serde(default)]
    pub taint: TaintLevel,

    /// Whether this request has been elevated
    #[serde(default)]
    pub elevated: bool,

    /// Elevation token if elevated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevation_token: Option<String>,
}

impl Provenance {
    /// Create provenance from an origin zone.
    #[must_use]
    pub const fn new(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Create tainted provenance from an untrusted source.
    #[must_use]
    pub const fn tainted(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::Tainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Create highly tainted provenance from a direct untrusted instruction.
    #[must_use]
    pub const fn highly_tainted(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::HighlyTainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Add a step to the provenance chain.
    #[must_use]
    pub fn with_step(mut self, step: ProvenanceStep) -> Self {
        self.chain.push(step);
        self
    }

    /// Mark as elevated with a token.
    #[must_use]
    pub fn elevated_with(mut self, token: impl Into<String>) -> Self {
        self.elevated = true;
        self.elevation_token = Some(token.into());
        self
    }

    /// Check if this provenance is tainted.
    #[must_use]
    pub const fn is_tainted(&self) -> bool {
        !matches!(self.taint, TaintLevel::Untainted)
    }

    /// Check if this provenance can access a higher-trust zone.
    ///
    /// Per FCP spec, tainted provenance cannot access higher-trust zones
    /// without explicit elevation.
    #[must_use]
    pub const fn can_access_higher_trust(&self) -> bool {
        !self.is_tainted() || self.elevated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Canonical ID Validation Tests (FCP Spec §3.4.2)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canonical_id_valid_simple() {
        assert!(validate_canonical_id("hello").is_ok());
        assert!(validate_canonical_id("a").is_ok());
        assert!(validate_canonical_id("0").is_ok());
        assert!(validate_canonical_id("test123").is_ok());
    }

    #[test]
    fn canonical_id_valid_with_separators() {
        assert!(validate_canonical_id("hello.world").is_ok());
        assert!(validate_canonical_id("hello_world").is_ok());
        assert!(validate_canonical_id("hello-world").is_ok());
        assert!(validate_canonical_id("hello:world").is_ok());
        assert!(validate_canonical_id("a.b.c.d").is_ok());
        assert!(validate_canonical_id("fcp.gmail:message:send").is_ok());
    }

    #[test]
    fn canonical_id_valid_max_length() {
        let max_id = "a".repeat(128);
        assert!(validate_canonical_id(&max_id).is_ok());
    }

    #[test]
    fn canonical_id_reject_empty() {
        assert_eq!(validate_canonical_id(""), Err(IdValidationError::Empty));
    }

    #[test]
    fn canonical_id_reject_too_long() {
        let too_long = "a".repeat(129);
        assert_eq!(
            validate_canonical_id(&too_long),
            Err(IdValidationError::TooLong { len: 129, max: 128 })
        );
    }

    #[test]
    fn canonical_id_reject_uppercase() {
        assert_eq!(
            validate_canonical_id("Hello"),
            Err(IdValidationError::UppercaseNotAllowed)
        );
        assert_eq!(
            validate_canonical_id("helloWorld"),
            Err(IdValidationError::UppercaseNotAllowed)
        );
        assert_eq!(
            validate_canonical_id("HELLO"),
            Err(IdValidationError::UppercaseNotAllowed)
        );
    }

    #[test]
    fn canonical_id_reject_non_ascii() {
        assert_eq!(
            validate_canonical_id("héllo"),
            Err(IdValidationError::NonAscii)
        );
        assert_eq!(
            validate_canonical_id("hello世界"),
            Err(IdValidationError::NonAscii)
        );
        assert_eq!(
            validate_canonical_id("🚀rocket"),
            Err(IdValidationError::NonAscii)
        );
    }

    #[test]
    fn canonical_id_reject_invalid_start() {
        assert_eq!(
            validate_canonical_id(".hello"),
            Err(IdValidationError::InvalidStartChar { ch: '.' })
        );
        assert_eq!(
            validate_canonical_id("-hello"),
            Err(IdValidationError::InvalidStartChar { ch: '-' })
        );
        assert_eq!(
            validate_canonical_id("_hello"),
            Err(IdValidationError::InvalidStartChar { ch: '_' })
        );
        assert_eq!(
            validate_canonical_id(":hello"),
            Err(IdValidationError::InvalidStartChar { ch: ':' })
        );
    }

    #[test]
    fn canonical_id_reject_invalid_chars() {
        assert_eq!(
            validate_canonical_id("hello world"),
            Err(IdValidationError::InvalidChar { ch: ' ', index: 5 })
        );
        assert_eq!(
            validate_canonical_id("hello@world"),
            Err(IdValidationError::InvalidChar { ch: '@', index: 5 })
        );
        assert_eq!(
            validate_canonical_id("hello/world"),
            Err(IdValidationError::InvalidChar { ch: '/', index: 5 })
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_id_valid() {
        let cap = CapabilityId::new("cap.read").unwrap();
        assert_eq!(cap.as_str(), "cap.read");
    }

    #[test]
    fn capability_id_parse() {
        let cap: CapabilityId = "cap.write".parse().unwrap();
        assert_eq!(cap.as_str(), "cap.write");
    }

    #[test]
    fn capability_id_reject_invalid() {
        assert!(CapabilityId::new("Cap.Read").is_err());
        assert!(CapabilityId::new("").is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneId Tests (FCP Spec §3)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_id_standard_zones() {
        assert_eq!(ZoneId::owner().as_str(), "z:owner");
        assert_eq!(ZoneId::private().as_str(), "z:private");
        assert_eq!(ZoneId::work().as_str(), "z:work");
        assert_eq!(ZoneId::community().as_str(), "z:community");
        assert_eq!(ZoneId::public().as_str(), "z:public");
    }

    #[test]
    fn zone_id_parse_valid() {
        let zone: ZoneId = "z:owner".parse().unwrap();
        assert_eq!(zone.as_str(), "z:owner");

        let zone: ZoneId = "z:custom-zone".parse().unwrap();
        assert_eq!(zone.as_str(), "z:custom-zone");

        let zone: ZoneId = "z:zone_with_underscore".parse().unwrap();
        assert_eq!(zone.as_str(), "z:zone_with_underscore");
    }

    #[test]
    fn zone_id_reject_empty() {
        assert!(matches!("".parse::<ZoneId>(), Err(ZoneIdError::Empty)));
    }

    #[test]
    fn zone_id_reject_too_long() {
        let too_long = format!("z:{}", "a".repeat(63));
        assert!(matches!(
            too_long.parse::<ZoneId>(),
            Err(ZoneIdError::TooLong { .. })
        ));
    }

    #[test]
    fn zone_id_reject_missing_prefix() {
        assert!(matches!(
            "owner".parse::<ZoneId>(),
            Err(ZoneIdError::MissingPrefix)
        ));
        assert!(matches!(
            "zone:work".parse::<ZoneId>(),
            Err(ZoneIdError::MissingPrefix)
        ));
    }

    #[test]
    fn zone_id_reject_invalid_chars() {
        assert!(matches!(
            "z:Hello".parse::<ZoneId>(),
            Err(ZoneIdError::InvalidChar { ch: 'H', .. })
        ));
        assert!(matches!(
            "z:hello world".parse::<ZoneId>(),
            Err(ZoneIdError::InvalidChar { ch: ' ', .. })
        ));
    }

    #[test]
    fn zone_id_hash_determinism() {
        let zone1: ZoneId = "z:work".parse().unwrap();
        let zone2: ZoneId = "z:work".parse().unwrap();
        assert_eq!(zone1.hash().as_bytes(), zone2.hash().as_bytes());
    }

    #[test]
    fn zone_id_hash_differs_by_zone() {
        let work: ZoneId = "z:work".parse().unwrap();
        let owner: ZoneId = "z:owner".parse().unwrap();
        assert_ne!(work.hash().as_bytes(), owner.hash().as_bytes());
    }

    #[test]
    fn zone_id_hash_golden_vector() {
        let zone: ZoneId = "z:owner".parse().unwrap();
        // Golden vector: BLAKE3("FCP2-ZONE-ID-V1" || "z:owner")
        let hash_hex = hex::encode(zone.hash().as_bytes());
        assert_eq!(
            hash_hex,
            "94b8a413160f922920dcad0dd26528bb65ff045f6041ab2141700244d3e3b9c8"
        );
    }

    #[test]
    fn zone_id_tailscale_tag_mapping() {
        let zone = ZoneId::work();
        assert_eq!(zone.to_tailscale_tag(), "tag:fcp-work");

        let zone = ZoneId::owner();
        assert_eq!(zone.to_tailscale_tag(), "tag:fcp-owner");
    }

    #[test]
    fn zone_id_from_tailscale_tag() {
        let zone = ZoneId::from_tailscale_tag("tag:fcp-work").unwrap();
        assert_eq!(zone.as_str(), "z:work");

        let zone = ZoneId::from_tailscale_tag("tag:fcp-custom-zone").unwrap();
        assert_eq!(zone.as_str(), "z:custom-zone");
    }

    #[test]
    fn zone_id_from_tailscale_tag_invalid() {
        assert!(matches!(
            ZoneId::from_tailscale_tag("tag:work"),
            Err(ZoneIdError::InvalidTailscaleTagPrefix)
        ));
        assert!(matches!(
            ZoneId::from_tailscale_tag("fcp-work"),
            Err(ZoneIdError::InvalidTailscaleTagPrefix)
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Provenance Tests (FCP Spec §7.2)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provenance_untainted() {
        let p = Provenance::new(ZoneId::work());
        assert!(!p.is_tainted());
        assert!(p.can_access_higher_trust());
    }

    #[test]
    fn provenance_tainted() {
        let p = Provenance::tainted(ZoneId::public());
        assert!(p.is_tainted());
        assert!(!p.can_access_higher_trust());
    }

    #[test]
    fn provenance_elevated() {
        let p = Provenance::tainted(ZoneId::public()).elevated_with("token123");
        assert!(p.is_tainted());
        assert!(p.can_access_higher_trust()); // Elevated allows access
    }

    #[test]
    fn provenance_chain() {
        let step = ProvenanceStep {
            timestamp_ms: 1_234_567_890,
            zone: ZoneId::work(),
            actor: "agent:claude".into(),
            action: "tool.invoke".into(),
            resource: "fcp.gmail:send".into(),
        };
        let p = Provenance::new(ZoneId::work()).with_step(step);
        assert_eq!(p.chain.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TrustLevel Tests (FCP Spec §6.5)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Blocked < TrustLevel::Anonymous);
        assert!(TrustLevel::Anonymous < TrustLevel::Untrusted);
        assert!(TrustLevel::Untrusted < TrustLevel::Paired);
        assert!(TrustLevel::Paired < TrustLevel::Admin);
        assert!(TrustLevel::Admin < TrustLevel::Owner);
    }
}

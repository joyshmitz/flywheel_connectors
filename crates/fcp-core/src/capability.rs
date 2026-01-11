//! Capability types and token verification.
//!
//! Capabilities are cryptographically-scoped permissions that grant specific
//! actions to principals within zones. Capability tokens (FCT) carry the
//! cryptographic proof of authorization.

use std::time::Duration;
use std::fmt;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{FcpError, FcpResult};

/// Capability identifier - unique name for a permission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityId(pub String);

impl CapabilityId {
    /// Create a new capability ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl<S: Into<String>> From<S> for CapabilityId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Connector identifier - unique name for a connector type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectorId(pub String);

impl<S: Into<String>> From<S> for ConnectorId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Instance identifier - unique ID for a running connector instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstanceId(pub String);

impl InstanceId {
    /// Generate a new random instance ID.
    #[must_use]
    pub fn new() -> Self {
        Self(format!("inst_{}", Uuid::new_v4()))
    }
}

impl Default for InstanceId {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Into<String>> From<S> for InstanceId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Operation identifier - name for a connector function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationId(pub String);

impl<S: Into<String>> From<S> for OperationId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Zone identifier - name of a trust boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZoneId(pub String);

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
}

impl<S: Into<String>> From<S> for ZoneId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Principal identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub String);

impl<S: Into<String>> From<S> for PrincipalId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

mod signature_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64::engine::general_purpose::STANDARD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
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

    /// Scope: "per_connector", "per_zone", or "per_principal"
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
    pub fn verify(
        &self,
        token: &CapabilityToken,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<()> {
        // Verify signature
        self.verify_signature(token)?;

        // Check expiry
        let now = chrono::Utc::now().timestamp() as u64;
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
        let op_allowed = token.caps.iter().any(|c| match &c.operation {
            Some(op) => op == operation,
            None => true, // Wildcard grant
        });
        if !op_allowed {
            return Err(FcpError::OperationNotGranted {
                operation: operation.0.clone(),
            });
        }

        // Enforce resource constraints
        self.enforce_resource_constraints(&token.constraints, resource_uris)?;

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
        &self,
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
    use std::time::Duration;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

/// Trust level for principals and data sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Fully untrusted - external/unknown origin
    Untrusted,
    /// Community content - public but verified source
    Community,
    /// Work-level trust - project collaborators
    Work,
    /// Private trust - personal data
    Private,
    /// Owner-level trust - full system access
    Owner,
    /// Admin-level trust - internal system processes
    Admin,
}

/// Provenance metadata for tracking data origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// The zone where the request/data originated
    pub origin_zone: ZoneId,

    /// The principal that initiated the request
    pub origin_principal: String,

    /// Taint labels attached to this request
    #[serde(default)]
    pub taints: Vec<TaintLabel>,

    /// Whether this request has been elevated
    #[serde(default)]
    pub elevated: bool,

    /// Elevation token if elevated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevation_token: Option<String>,
}

impl Provenance {
    /// Create provenance from a zone and principal.
    #[must_use]
    pub fn new(origin_zone: ZoneId, origin_principal: impl Into<String>) -> Self {
        Self {
            origin_zone,
            origin_principal: origin_principal.into(),
            taints: Vec::new(),
            elevated: false,
            elevation_token: None,
        }
    }
}

/// Taint label indicating untrusted origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintLabel {
    /// Source of the taint (e.g., "discord", "webhook")
    pub source: String,

    /// When the taint was applied
    pub applied_at: chrono::DateTime<chrono::Utc>,

    /// Zones this taint blocks access to
    #[serde(default)]
    pub blocked_zones: Vec<ZoneId>,
}

impl TaintLabel {
    /// Create a new taint label from a source.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            applied_at: chrono::Utc::now(),
            blocked_zones: Vec::new(),
        }
    }
}

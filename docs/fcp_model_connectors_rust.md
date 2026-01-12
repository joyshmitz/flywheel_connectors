# FCP Model Connectors (Rust) - V2

## Canonical, Spec-Accurate Reference Patterns for FCP V2

> Purpose: Provide Rust-oriented, spec-accurate connector patterns that match FCP Specification V2.
> Version: 2.0.0
> Last Updated: 2026-01-12
> License: MIT
> Canonical Spec: FCP_Specification_V2.md

---

## Table of Contents

1. Scope and Alignment
2. Connector Model (V2)
3. Control-Plane Protocol (FCP2-SYM)
4. Canonical Types and Serialization
5. Zones, Provenance, Taint, Elevation, Declassification
6. Capability System and Tokens
7. Control-Plane Objects: Invoke, Events, Errors
8. Connector Manifest (TOML) and Embedding
9. Sandbox and Resource Limits
10. Connector Archetypes (V2) and Reference Patterns
11. Rust Connector Skeleton (SDK-aligned)
12. Streaming, Replay, and Acks
13. Idempotency, Rate Limits, and Receipts
14. Observability and Audit
15. Conformance Checklist (Connector)

---

## 1. Scope and Alignment

- This document is a Rust-focused view of the FCP V2 connector model.
- Canonical protocol mode is FCP2-SYM (FCPS frames + RaptorQ). FCP1 CBOR/JSON-RPC is compatibility only.
- All normative requirements use MUST/SHOULD/MAY in the RFC 2119 sense and are aligned to FCP Specification V2 (2026-01-12).

---

## 2. Connector Model (V2)

Connectors are sandboxed binaries that bridge external services to FCP.

```rust
/// Connector definition (NORMATIVE)
pub struct Connector {
    /// Unique identifier
    pub id: ConnectorId,

    /// Human-readable name
    pub name: String,

    /// Version
    pub version: Version,

    /// Runtime format
    pub format: ConnectorFormat,

    /// Connector archetypes
    pub archetypes: Vec<ConnectorArchetype>,

    /// Operations provided
    pub operations: Vec<Operation>,

    /// Events emitted
    pub events: Vec<EventType>,

    /// Required capabilities
    pub required_caps: Vec<CapabilityId>,

    /// Optional capabilities
    pub optional_caps: Vec<CapabilityId>,

    /// Forbidden capabilities
    pub forbidden_caps: Vec<CapabilityId>,
}

pub enum ConnectorArchetype {
    /// Sends and receives messages
    Bidirectional,
    /// Emits events (read-only)
    Streaming,
    /// Executes operations (write)
    Operational,
    /// Stores/retrieves data
    Storage,
    /// Provides knowledge/search
    Knowledge,
}

/// Connector runtime format (NORMATIVE)
pub enum ConnectorFormat {
    /// Native executable (ELF/Mach-O/PE)
    Native,
    /// WASI module (WASM) executed under a WASI runtime with hostcalls gated by capabilities
    /// Provides portable, capability-based sandbox consistent across OSes.
    Wasi,
}
```

---

## 3. Control-Plane Protocol (FCP2-SYM)

### 3.1 Protocol Modes

FCP V2 supports two protocol modes:

| Mode | Encoding | Use Case |
|------|----------|----------|
| FCP2-SYM (Canonical) | FCPS frames + RaptorQ | Production mesh-native |
| FCP1 (Compatibility) | CBOR/JSON-RPC frames | Legacy connectors |

### 3.2 Message Types (Wire Protocol)

| Type | Direction | Purpose |
|------|-----------|---------|
| `handshake` | Hub/Gateway -> Connector | Establish connection |
| `handshake_ack` | Connector -> Hub/Gateway | Confirm connection |
| `introspect` | Hub/Gateway -> Connector | Query operations |
| `configure` | Hub/Gateway -> Connector | Apply configuration |
| `invoke` | Hub/Gateway -> Connector | Execute operation |
| `response` | Connector -> Hub/Gateway | Operation result |
| `subscribe` | Hub/Gateway -> Connector | Subscribe to events |
| `event` | Connector -> Hub/Gateway | Async event |
| `health` | Hub/Gateway <-> Connector | Health check |
| `shutdown` | Hub/Gateway -> Connector | Graceful shutdown |
| `symbol_request` | Any -> Any | Request symbols (mesh) |
| `symbol_delivery` | Any -> Any | Deliver symbols (mesh) |
| `decode_status` | Any -> Any | Feedback: received/needed symbols |
| `symbol_ack` | Any -> Any | Stop condition for delivery |

### 3.3 Standard Methods (Connector Requirements)

Connectors MUST implement:

| Method | Purpose |
|--------|---------|
| `handshake` | Bind to zone, negotiate protocol |
| `describe` | Return manifest metadata |
| `introspect` | Return operations, events, resources |
| `capabilities` | Return full catalog |
| `configure` | Apply configuration |
| `invoke` | Execute operation |
| `health` | Report readiness |
| `shutdown` | Graceful termination |

Connectors that emit events MUST also support `subscribe` and `event` control-plane objects.

### 3.4 Control-Plane as Objects (NORMATIVE)

All control-plane messages are canonical CBOR objects with SchemaId and ObjectId.

```rust
/// Control plane object wrapper (NORMATIVE)
pub struct ControlPlaneObject {
    pub header: ObjectHeader,
    pub body: Vec<u8>, // canonical CBOR (schema-prefixed)
}
```

Transport options:

1. Local/IPC: canonical CBOR bytes over the connector transport.
2. Mesh: encoded to symbols and sent inside FCPS frames with `FrameFlags::CONTROL_PLANE`.

When `FrameFlags::CONTROL_PLANE` is set, receivers MUST verify checksum, decrypt symbols, reconstruct the object, verify schema, and store the object (subject to retention policy).

---

## 4. Canonical Types and Serialization

### 4.1 ObjectId and SchemaId

```rust
/// Content-addressed identifier (NORMATIVE)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]);

/// Secret per-zone object-id key (NORMATIVE)
pub struct ObjectIdKey(pub [u8; 32]);

impl ObjectId {
    /// Create ObjectId from content, zone, and schema (NORMATIVE for security objects)
    pub fn new(content: &[u8], zone: &ZoneId, schema: &SchemaId, key: &ObjectIdKey) -> Self {
        let mut h = blake3::Hasher::new_keyed(&key.0);
        h.update(b"FCP2-OBJECT-V2");
        h.update(zone.as_bytes());
        h.update(schema.hash().as_bytes());
        h.update(content);
        Self(*h.finalize().as_bytes())
    }

    /// Unscoped content hash (NON-NORMATIVE; MUST NOT be used for security objects)
    pub fn from_unscoped_bytes(content: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-CONTENT-V2");
        h.update(content);
        Self(*h.finalize().as_bytes())
    }
}
```

Security objects MUST use `ObjectId::new(content, zone, schema, key)`:

- CapabilityObject, CapabilityToken, PolicyObject, RevocationObject
- AuditEvent, AuditHead, SecretObject, ZoneKeyManifest
- DeviceEnrollment, NodeKeyAttestation
- Any object used as an authority anchor or enforcement input

### 4.2 Canonical Serialization

```rust
/// Canonical CBOR serialization (NORMATIVE)
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    pub fn serialize<T: Serialize>(value: &T, schema: &SchemaId) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(schema.hash().as_bytes());
        ciborium::ser::into_writer_canonical(value, &mut buf)
            .expect("Serialization cannot fail for valid types");
        buf
    }

    pub fn deserialize<T: DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        if data.len() < 32 {
            return Err(SerializationError::SchemaMismatch);
        }
        let got = &data[0..32];
        if got != expected_schema.hash().as_bytes() {
            return Err(SerializationError::SchemaMismatch);
        }
        ciborium::de::from_reader(&data[32..])
            .map_err(SerializationError::CborError)
    }
}
```

### 4.3 Object Header and Retention

```rust
/// Universal object header (NORMATIVE)
pub struct ObjectHeader {
    pub object_id: ObjectId,
    pub schema: SchemaId,
    pub zone_id: ZoneId,
    pub created_at: u64,
    pub provenance: Provenance,
    pub refs: Vec<ObjectId>,
    pub retention: RetentionClass,
    pub ttl_secs: Option<u64>,
}

pub enum RetentionClass {
    Pinned,
    Lease { expires_at: u64 },
    Ephemeral,
}
```

---

## 5. Zones, Provenance, Taint, Elevation, Declassification

### 5.1 Zone

```rust
/// Zone with cryptographic properties (NORMATIVE)
pub struct Zone {
    pub id: ZoneId,
    pub name: String,
    pub integrity_level: u8,
    pub confidentiality_level: u8,
    pub active_zone_key_id: [u8; 8],
    pub tailscale_tag: String,
    pub parent: Option<ZoneId>,
    pub policy: ZonePolicy,
}
```

### 5.2 Declassification Token

Used for confidentiality downgrades (e.g., z:private -> z:public).

```rust
pub struct DeclassificationToken {
    pub token_id: ObjectId,
    pub from_zone: ZoneId,
    pub to_zone: ZoneId,
    pub object_ids: Vec<ObjectId>,
    pub justification: String,
    pub approved_by: PrincipalId,
    pub approved_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}
```

### 5.3 Provenance and Taint

```rust
/// Provenance tracking (NORMATIVE)
#[derive(Clone)]
pub struct Provenance {
    pub origin_zone: ZoneId,
    pub current_zone: ZoneId,
    pub origin_integrity: u8,
    pub origin_confidentiality: u8,
    pub origin_principal: Option<PrincipalId>,
    pub taint: TaintFlags,
    pub zone_crossings: Vec<ZoneCrossing>,
    pub created_at: u64,
}

bitflags! {
    pub struct TaintFlags: u32 {
        const NONE            = 0;
        const PUBLIC_INPUT    = 1 << 0;
        const EXTERNAL_INPUT  = 1 << 1;
        const UNVERIFIED_LINK = 1 << 2;
        const USER_SUPPLIED   = 1 << 3;
        const PROMPT_SURFACE  = 1 << 4;
    }
}

#[derive(Clone)]
pub struct ZoneCrossing {
    pub from_zone: ZoneId,
    pub to_zone: ZoneId,
    pub crossed_at: u64,
    pub authorized_by: Option<ObjectId>,
}

impl Provenance {
    pub fn merge(inputs: &[Provenance]) -> Provenance { /* NORMATIVE */ }
    pub fn can_invoke(&self, operation: &Operation, target_zone: &Zone) -> TaintDecision { /* NORMATIVE */ }
}
```

### 5.4 Elevation Token

```rust
/// Elevation token for tainted operations (NORMATIVE)
pub struct ElevationToken {
    pub token_id: ObjectId,
    pub operation: OperationId,
    pub original_provenance: Provenance,
    pub approved_by: PrincipalId,
    pub approved_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}
```

Connector implications:

- The MeshNode/Gateway enforces taint, elevation, and declassification before invoking a connector.
- Connectors MUST preserve provenance on outputs and events and MUST NOT drop taint flags.
- If a connector merges inputs, it MUST merge provenance per the spec.

---

## 6. Capability System and Tokens

### 6.1 Capability Taxonomy (Non-exhaustive)

```
fcp.*            Protocol/meta
network.*        Network operations
network.tls.*    TLS identity constraints (SNI / SPKI pin)
storage.*        Persistence
ipc.*            IPC
system.*         System operations (restricted)
[service].*      Service-specific capabilities
```

### 6.2 Capability Definition

```rust
pub struct Capability {
    pub id: CapabilityId,
    pub name: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub safety_tier: SafetyTier,
    pub parent: Option<CapabilityId>,
    pub implies: Vec<CapabilityId>,
    pub conflicts_with: Vec<CapabilityId>,
    pub idempotency: IdempotencyClass,
    pub rate_limit: Option<RateLimit>,
    pub requires_approval: ApprovalMode,
    pub audit_level: AuditLevel,
    pub agent_hint: AgentHint,
}

pub enum RiskLevel { Low, Medium, High, Critical }

pub enum SafetyTier { Safe, Risky, Dangerous, Forbidden }

pub enum IdempotencyClass { None, BestEffort, Strict }

pub enum ApprovalMode { None, Policy, Interactive, ElevationToken }

pub struct AgentHint {
    pub when_to_use: String,
    pub common_mistakes: Vec<String>,
    pub examples: Vec<String>,
    pub related: Vec<CapabilityId>,
}
```

### 6.3 Capability Objects and Constraints

```rust
pub struct CapabilityObject {
    pub header: ObjectHeader,
    pub capability_id: CapabilityId,
    pub grantee: Grantee,
    pub constraints: CapabilityConstraints,
    pub placement: PlacementPolicy,
    pub valid_from: u64,
    pub valid_until: u64,
    pub signature: Signature,
}

pub enum Grantee {
    Principal(PrincipalId),
    Zone(ZoneId),
    Tag(String),
    Bearer,
}

pub struct CapabilityConstraints {
    pub resource_allow: Vec<String>,
    pub resource_deny: Vec<String>,
    pub max_calls: Option<u32>,
    pub max_bytes: Option<u64>,
    pub idempotency_scope: Option<String>,
    pub network: Option<NetworkConstraints>,
}

pub struct NetworkConstraints {
    pub host_allow: Vec<String>,
    pub port_allow: Vec<u16>,
    pub require_sni: bool,
    pub spki_pins: Vec<String>,
}
```

### 6.4 Placement Policy

```rust
pub struct PlacementPolicy {
    pub requires: Vec<DeviceRequirement>,
    pub prefers: Vec<DevicePreference>,
    pub excludes: Vec<DevicePattern>,
    pub zones: Vec<ZoneId>,
}
```

### 6.5 Capability Token (FCT)

```rust
pub struct CapabilityToken {
    pub jti: Uuid,
    pub sub: PrincipalId,
    pub iss_zone: ZoneId,
    pub iss_node: TailscaleNodeId,
    pub kid: [u8; 8],
    pub aud: ConnectorId,
    pub instance: Option<InstanceId>,
    pub iat: u64,
    pub exp: u64,
    pub caps: Vec<CapabilityGrant>,
    pub constraints: CapabilityConstraints,
    pub holder_node: TailscaleNodeId,
    pub rev_head: ObjectId,
    pub sig: [u8; 64],
}
```

Token verification MUST use the node issuance public key (not the node signing key), and the issuing node MUST have a valid `NodeKeyAttestation`.

---

## 7. Control-Plane Objects: Invoke, Events, Errors

### 7.1 Invoke Request/Response

```rust
pub struct InvokeRequest {
    pub id: String,
    pub operation: OperationId,
    pub input: Value,
    pub capability_token: CapabilityToken,
    pub provenance: Provenance,
    pub elevation_token: Option<ElevationToken>,
    pub declassification_token: Option<DeclassificationToken>,
    pub idempotency_key: Option<String>,
    pub holder_proof: Signature, // NORMATIVE
}

pub struct InvokeResponse {
    pub id: String,
    pub result: Value,
    pub resource_uris: Vec<String>,
    pub next_cursor: Option<String>,
    pub receipt: Option<ObjectId>,
}
```

The holder proof binds the request to the `holder_node` in the token and prevents replay by other nodes.

### 7.2 Operation Receipt

```rust
pub struct OperationReceipt {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub idempotency_key: Option<String>,
    pub outcome_object_ids: Vec<ObjectId>,
    pub resource_uris: Vec<String>,
    pub executed_at: u64,
    pub executed_by: TailscaleNodeId,
    pub signature: Signature,
}
```

Operations with `SafetyTier::Dangerous` MUST be `IdempotencyClass::Strict`.
Operations with `SafetyTier::Risky` SHOULD be `Strict` unless there is a clear reason.

### 7.3 Event Envelope

```rust
pub struct EventEnvelope {
    pub topic: String,
    pub timestamp: DateTime<Utc>,
    pub seq: u64,
    pub cursor: String,
    pub requires_ack: bool,
    pub data: Value,
}
```

### 7.4 Error Taxonomy

```rust
pub struct FcpError {
    pub code: String,              // e.g., "FCP-4002"
    pub message: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub details: Option<Value>,
    pub ai_recovery_hint: Option<String>,
}
```

Error ranges:

```
FCP-1000..1999  Protocol errors
FCP-2000..2999  Auth/Identity errors
FCP-3000..3999  Capability errors
FCP-4000..4999  Zone/Provenance errors
FCP-5000..5999  Lifecycle/health errors
FCP-6000..6999  Resource errors
FCP-7000..7999  External service errors
FCP-9000..9999  Internal errors
```

---

## 8. Connector Manifest (TOML) and Embedding

Manifest format is normative. Example:

```toml
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.0"

[connector]
id = "fcp.telegram"
name = "Telegram Connector"
version = "2026.1.0"
description = "Secure Telegram Bot API integration"
archetypes = ["bidirectional", "streaming"]
format = "native"  # "native" | "wasi"

[zones]
home = "z:community"
allowed_sources = ["z:owner", "z:private", "z:work", "z:community"]
allowed_targets = ["z:community"]
forbidden = ["z:public"]

[capabilities]
required = [
  "ipc.gateway",
  "network.dns",
  "network.outbound:api.telegram.org:443",
  "network.tls.sni",
  "network.tls.spki_pin",
  "storage.persistent:encrypted",
]
optional = ["media.download", "media.upload"]
forbidden = ["system.exec", "network.inbound"]

[provides.operations.telegram_send_message]
description = "Send a message to a Telegram chat"
capability = "telegram.send_message"
risk_level = "medium"
safety_tier = "risky"
requires_approval = "policy"
rate_limit = "60/min"
idempotency = "best_effort"
input_schema = { type = "object", required = ["chat_id", "text"] }
output_schema = { type = "object", required = ["message_id"] }
network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, spki_pins = ["base64:..."] }

[provides.operations.telegram_send_message.ai_hints]
when_to_use = "Use to post updates to approved chats."
common_mistakes = ["Sending secrets", "Responding to tainted inputs"]

[event_caps]
streaming = true
replay = true
min_buffer_events = 10000

[sandbox]
profile = "strict"            # "strict", "strict_plus", "moderate", or "permissive"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

[signatures]
publisher_signatures = [
  { kid = "pubkey1", sig = "base64:..." },
  { kid = "pubkey2", sig = "base64:..." },
]
publisher_threshold = "2-of-3"
registry_signature = { kid = "registry1", sig = "base64:..." }
transparency_log_entry = "objectid:..."
```

Manifest embedding (MUST be extractable without execution):

- ELF: `.fcp_manifest`
- Mach-O: `__FCP,__manifest`
- PE: `.fcpmanifest`

Connectors MUST implement `--manifest` to print the embedded manifest.

---

## 9. Sandbox and Resource Limits

```rust
pub struct SandboxConfig {
    pub profile: SandboxProfile,
    pub memory_mb: u32,
    pub cpu_percent: u8,
    pub wall_clock_timeout_ms: u64,
    pub fs_readonly_paths: Vec<PathBuf>,
    pub fs_writable_paths: Vec<PathBuf>,
    pub deny_exec: bool,
    pub deny_ptrace: bool,
}

pub enum SandboxProfile {
    Strict,
    StrictPlus, // microVM-backed where available
    Moderate,
    Permissive,
}
```

Enforcement:

- Resource limits are enforced by the OS sandbox.
- Filesystem access is limited to declared paths.
- Network access is limited to declared capabilities and constraints.
- Child process spawning and debugging/tracing can be denied.

---

## 10. Connector Archetypes (V2) and Reference Patterns

### 10.1 V2 Archetypes (Manifest `archetypes`)

- **Bidirectional**: Send/receive messages. Examples: chat protocols, collaborative apps.
- **Streaming**: Emit events (read-only). Examples: webhooks, SSE, log tailing.
- **Operational**: Execute operations (request/response). Examples: REST, GraphQL, gRPC-unary.
- **Storage**: Store/retrieve data. Examples: S3, GCS, local storage.
- **Knowledge**: Search/index/answer. Examples: note search, doc retrieval.

Only these values are valid in `connector.archetypes`.

### 10.2 Interaction Patterns (Non-archetype)

These patterns are helpful for design, but MUST map to V2 archetypes in the manifest:

- Request/Response -> Operational
- Polling -> Operational (often paired with Streaming events)
- Webhook -> Streaming (and/or Operational for ack/side effects)
- Queue/Pub-Sub -> Bidirectional or Streaming depending on the API

### 10.3 Reference Connector Patterns (Appendix C)

| Pattern | Description | Examples |
|---------|-------------|----------|
| Unified Messaging | Maps channels to zones | Telegram, Discord |
| Workspace | Local caching, write gating | Gmail, Calendar |
| Knowledge | Filesystem watch + search | Obsidian, Notion |
| DevOps | Typed CLI wrappers | gh, kubectl |

---

## 11. Rust Connector Skeleton (SDK-aligned)

### 11.1 Toolchain

- Rust edition: 2024 (nightly required)
- Cargo only
- `#![forbid(unsafe_code)]`

### 11.2 Crate Layout

```
connectors/myservice/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── connector.rs
    ├── ops/
    ├── events/
    └── error.rs
```

### 11.3 Minimal Skeleton

```rust
#![forbid(unsafe_code)]

use async_trait::async_trait;
use fcp_core::{
    Connector, ControlPlaneObject, FcpError, InvokeRequest, InvokeResponse,
    EventEnvelope, ObjectId, Provenance,
};

#[async_trait]
pub trait FcpConnector {
    fn metadata(&self) -> Connector;
    async fn handle_control_plane(&self, obj: ControlPlaneObject) -> Result<ControlPlaneObject, FcpError>;
}

pub struct MyConnector {
    // client handles, config, caches
}

#[async_trait]
impl FcpConnector for MyConnector {
    fn metadata(&self) -> Connector {
        // Return Connector metadata consistent with manifest
        unimplemented!()
    }

    async fn handle_control_plane(&self, obj: ControlPlaneObject) -> Result<ControlPlaneObject, FcpError> {
        // Dispatch by SchemaId from obj.header.schema
        // handshake | describe | introspect | capabilities | configure | invoke | subscribe | health | shutdown
        unimplemented!()
    }
}
```

Guidance:

- Dispatch on SchemaId, not JSON method strings.
- Validate all inputs against the declared schemas in the manifest.
- Enforce idempotency and rate limits within the connector for operations that require it.
- Preserve and propagate provenance on all outputs and events.

---

## 12. Streaming, Replay, and Acks

- Event streams use `EventEnvelope { topic, seq, cursor, requires_ack, data }`.
- `seq` MUST be monotonically increasing per topic.
- `cursor` MUST be opaque and stable for replay.
- If `requires_ack` is true, the consumer MUST ack via the control-plane schema defined in the SDK (connector should track delivery state).

Manifest flags:

```toml
[event_caps]
streaming = true
replay = true
min_buffer_events = 10000
```

---

## 13. Idempotency, Rate Limits, and Receipts

- `SafetyTier::Dangerous` -> `IdempotencyClass::Strict` (MUST).
- `SafetyTier::Risky` -> `IdempotencyClass::Strict` (SHOULD).
- Use `idempotency_key` to dedupe and return the prior `OperationReceipt`.
- Receipts are content-addressed objects stored via the symbol layer and referenced in `InvokeResponse.receipt`.

---

## 14. Observability and Audit

Connectors MUST:

- Emit structured logs (JSON) with `correlation_id`, `zone_id`, `connector_id`, `operation_id`.
- Redact secrets and PII.
- Emit audit events for secret access, high-risk operations, approvals/elevations, and zone transitions (via the Gateway/Mesh).

---

## 15. Conformance Checklist (Connector)

**Connector MUST:**

- Implement `--manifest` flag.
- Implement standard methods: `handshake`, `describe`, `introspect`, `capabilities`, `configure`, `invoke`, `health`, `shutdown`.
- Support event cursors and replay (when streaming).
- Declare capabilities in the manifest.
- Validate inputs.
- Never log secrets.
- Include AI hints for operations.

---

## Notes

- This document intentionally avoids FCP1-only constructs unless explicitly labeled as compatibility.
- For mesh, symbol, audit, and trust-anchor details, refer to `FCP_Specification_V2.md`.

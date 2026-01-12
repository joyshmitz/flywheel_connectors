# FCP Model Connectors (Rust) - V2

## Canonical, Spec-Accurate Reference for FCP V2 Connectors

> Purpose: Provide a Rust-focused connector guide aligned exactly to FCP Specification V2.
> Version: 2.0.0
> Status: Draft
> Last Updated: 2026-01-12
> License: MIT
> Canonical Spec: FCP_Specification_V2.md

---

## Table of Contents

1. Scope and Alignment
2. Connector Model and Lifecycle (V2)
   - 2.2 Connector State (NORMATIVE)
3. Control-Plane Protocol (FCP2-SYM)
   - 3.5 Session Authentication (NORMATIVE)
   - 3.6 Control Plane Retention Classes (NORMATIVE)
4. Canonical Types and Serialization
5. Zones, Approval Tokens, Provenance, and Taint
   - 5.2 Unified Approval Token
   - 5.3 Provenance and Taint (with taint_reductions)
6. Capability System
   - 6.3 Network Constraints (with CIDR deny, Egress Proxy)
7. Invoke, Receipts, and Event Envelopes
8. Streaming, Replay, and Acks
9. Error Taxonomy
10. Agent Integration (Introspection + MCP)
11. Connector Manifest (TOML) and Embedding
12. Sandbox Profiles and Enforcement
13. Automation Recipes and Provisioning Interface
14. Registry and Supply Chain
    - 14.3 Supply Chain Attestations
15. Lifecycle Management and Revocation
    - 15.3 Revocation (RevocationEvent, RevocationHead, RevocationRegistry)
16. Device-Aware Execution and Execution Leases
    - 16.1 Execution Leases (NORMATIVE)
    - 16.2 Device Profiles and Execution Planner
    - 16.3 Device Requirements and Preferences
17. Observability and Audit
    - 17.1 Metrics (NORMATIVE)
    - 17.2 Structured Logs
    - 17.3 Audit Chain (AuditEvent, AuditHead, ZoneFrontier)
18. Connector Archetypes (V2) and Patterns
19. Rust Connector Skeleton (SDK-aligned)
20. Conformance Checklist (Connector)

---

## 1. Scope and Alignment

- This document covers connector-facing requirements from FCP Specification V2.
- Canonical protocol mode is FCP2-SYM (FCPS frames + RaptorQ). FCP1 CBOR/JSON-RPC is compatibility only.
- All normative language uses MUST/SHOULD/MAY in the RFC 2119 sense.

---

## 2. Connector Model and Lifecycle (V2)

Connectors are sandboxed binaries that bridge external services to FCP:

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

Connector lifecycle:

```
DISCOVERED -> VERIFIED -> INSTALLED -> CONFIGURED -> ACTIVE
         -> rejected                      -> FAILED
                                          -> PAUSED
                                          -> STOPPED
```

### 2.2 Connector State (NORMATIVE)

Connectors with polling/cursors/dedup caches MUST externalize their canonical state into the mesh.
Local `$CONNECTOR_STATE` is a **cache only** — the authoritative state lives as mesh objects.

This enables:
- **Safe failover**: Another node can resume from the last committed state
- **Resumable polling**: Cursors survive node restarts and migrations
- **Deterministic migration semantics**: State is explicit, not implicit in process memory

```rust
/// Stable root for connector state (NORMATIVE)
pub struct ConnectorStateRoot {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    /// Latest ConnectorStateObject (or None if no state yet)
    pub head: Option<ObjectId>,
}

/// Append-only connector state update (NORMATIVE)
pub struct ConnectorStateObject {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    pub prev: Option<ObjectId>,
    /// Monotonic sequence for ordering
    pub seq: u64,
    /// Canonical connector-specific state blob
    pub state_cbor: Vec<u8>,
    pub updated_at: u64,
    /// Signature by executing node
    pub signature: Signature,
}
```

**Single-Writer Semantics (NORMATIVE):**

For any connector declaring `singleton_writer = true` in its manifest, the MeshNode MUST ensure
only one node writes `ConnectorStateObject` updates at a time. This is enforced using
`ExecutionLease` over `ConnectorStateRoot.object_id` or an equivalent lease primitive.

```toml
# In connector manifest
[connector]
singleton_writer = true  # Only one node can write state at a time
```

This prevents:
- Double-polling the same messages
- Duplicate event processing
- Cursor conflicts during migration

---

## 3. Control-Plane Protocol (FCP2-SYM)

### 3.1 Protocol Modes

| Mode | Encoding | Use Case |
|------|----------|----------|
| FCP2-SYM (Canonical) | FCPS frames + RaptorQ | Production mesh-native |
| FCP1 (Compatibility) | CBOR/JSON-RPC frames | Legacy connectors |

### 3.2 Message Types (Wire Protocol)

| Type | Direction | Purpose |
|------|-----------|---------|
| `handshake` | Hub -> Connector | Establish connection |
| `handshake_ack` | Connector -> Hub | Confirm connection |
| `introspect` | Hub -> Connector | Query operations |
| `configure` | Hub -> Connector | Apply configuration |
| `invoke` | Hub -> Connector | Execute operation |
| `response` | Connector -> Hub | Operation result |
| `subscribe` | Hub -> Connector | Subscribe to events |
| `event` | Connector -> Hub | Async event |
| `health` | Hub <-> Connector | Health check |
| `shutdown` | Hub -> Connector | Graceful shutdown |
| `symbol_request` | Any -> Any | Request symbols (mesh) |
| `symbol_delivery` | Any -> Any | Deliver symbols (mesh) |
| `decode_status` | Any -> Any | Feedback: received/needed symbols |
| `symbol_ack` | Any -> Any | Stop condition for delivery |

**FCPS Frame Format (90-byte header):**

```
Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")
Bytes 4-5:    Version (u16 LE)
Bytes 6-7:    Flags (u16 LE)
Bytes 8-11:   Symbol Count (u32 LE)
Bytes 12-15:  Total Payload Length (u32 LE)
Bytes 16-47:  Object ID (32 bytes)
Bytes 48-49:  Symbol Size (u16 LE, default 1024)
Bytes 50-57:  Zone Key ID (8 bytes, for rotation)
Bytes 58-73:  Zone ID hash (16 bytes, truncated SHA256)
Bytes 74-81:  Epoch ID (u64 LE)
Bytes 82-89:  Nonce Base (8 bytes, for per-symbol nonce derivation)
Bytes 90+:    Symbol payloads (concatenated)
Final 8:      Checksum (XXH3-64)
```

**Nonce Derivation (NORMATIVE):**

Per-symbol nonces are derived from frame_nonce_base and ESI, eliminating per-symbol RNG overhead
and saving 12 bytes/symbol bandwidth:

```rust
/// Derive per-symbol nonce from frame_nonce_base and ESI
/// nonce = frame_nonce_base[0..8] || esi_le[0..4]
fn derive_nonce(frame_nonce_base: &[u8; 8], esi: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(frame_nonce_base);
    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
    nonce
}
```

### 3.3 Standard Methods

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

Connectors that emit events are expected to support `subscribe` and `event` control-plane objects.

### 3.4 Control-Plane as Objects (NORMATIVE)

All control-plane messages (handshake/introspect/configure/invoke/response/subscribe/event/health/shutdown)
MUST be represented as canonical CBOR objects with SchemaId and ObjectId.

```rust
/// Control plane object wrapper (NORMATIVE)
pub struct ControlPlaneObject {
    pub header: ObjectHeader,
    pub body: Vec<u8>, // canonical CBOR (schema-prefixed)
}

/// Retention class for control plane messages (NORMATIVE)
pub enum ControlPlaneRetention {
    /// Must be stored (invoke, response, receipts, approvals, audit)
    Required,
    /// May be ephemeral (health, decode_status, symbol_ack)
    Ephemeral,
}
```

Transport options:

1. Local/IPC: canonical CBOR bytes over the connector transport.
2. Mesh: encoded to symbols and sent inside FCPS frames with `FrameFlags::CONTROL_PLANE`.

When `FrameFlags::CONTROL_PLANE` is set, receivers MUST:
1. Verify checksum
2. Decrypt symbols
3. Reconstruct the object payload (RAW chunking or RaptorQ)
4. Verify schema
5. Store the object if retention class is Required; otherwise MAY discard after processing

### 3.5 Session Authentication (NORMATIVE)

Ed25519 signatures per data-plane frame are too expensive when frames are near MTU (often ~1 symbol/frame).
FCP authenticates data-plane FCPS frames via a **session**:

1. A one-time handshake authenticated by attested node signing keys
2. Session-key derivation (X25519 ECDH + HKDF)
3. Per-frame MAC + sequence number for anti-replay

```rust
/// Session handshake: initiator → responder
pub struct MeshSessionHello {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    pub timestamp: u64,
    /// Node signature over transcript
    pub signature: Signature,
}

/// Session handshake: responder → initiator
pub struct MeshSessionAck {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    pub session_id: [u8; 16],
    pub timestamp: u64,
    /// Node signature over transcript
    pub signature: Signature,
}

/// Session key derivation (NORMATIVE)
/// session_key = HKDF-SHA256(
///     ikm = ECDH(initiator_eph, responder_eph),
///     salt = session_id,
///     info = "FCP2-SESSION-V1" || initiator_node_id || responder_node_id
/// )

/// Authenticated FCPS frame (NORMATIVE)
pub struct AuthenticatedFcpsFrame {
    pub frame: FcpsFrame,
    pub source_id: TailscaleNodeId,
    pub session_id: [u8; 16],
    /// Monotonic sequence for anti-replay
    pub seq: u64,
    /// Poly1305(session_key, session_id || seq || frame_bytes)
    pub mac: [u8; 16],
}
```

**Why session MACs instead of per-frame signatures:**
- Ed25519 signing is expensive at scale (especially mobile)
- AEAD already provides per-symbol cryptographic integrity
- Session establishment amortizes signature cost over many frames
- Preserves "cryptographic attribution independent of transport" goal

Signed frames MAY still be used for bootstrap/degraded mode, but high-throughput delivery MUST support session MACs.

### 3.6 Control Plane Retention Classes (NORMATIVE)

| Must Be Stored | May Be Ephemeral |
|----------------|------------------|
| invoke, response | health |
| receipts | handshake, handshake_ack |
| approvals (elevation, declassification) | decode_status |
| secret access | symbol_ack |
| revocations | introspect |
| audit events/heads | configure |

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

### 4.2 Canonical CBOR Serialization

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

### 4.3 Object Header and Placement

```rust
/// Universal object header (NORMATIVE)
///
/// ObjectId is derived from the canonical encoding of (header, body).
/// The header MUST NOT embed `object_id`.
pub struct ObjectHeader {
    pub schema: SchemaId,
    pub zone_id: ZoneId,
    pub created_at: u64,
    pub provenance: Provenance,
    pub refs: Vec<ObjectId>,
    pub ttl_secs: Option<u64>,
    /// Optional placement policy for symbol distribution (NORMATIVE when present)
    pub placement: Option<ObjectPlacementPolicy>,
}

/// Object placement policy (NORMATIVE when used)
pub struct ObjectPlacementPolicy {
    pub min_nodes: u8,
    pub max_node_fraction: f64,
    pub preferred_devices: Vec<String>,
    pub excluded_devices: Vec<String>,
    pub target_coverage: f64,
}
```

Retention is node-local storage metadata and is not part of the content-addressed header.
Mesh nodes periodically evaluate symbol coverage against `ObjectPlacementPolicy` and perform
background repair to maintain target coverage.

---

## 5. Zones, Approval Tokens, Provenance, and Taint

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

### 5.2 Unified Approval Token

The unified ApprovalToken replaces separate elevation and declassification tokens with a single type.
This simplifies: UI prompting, audit, verification code paths, and policy enforcement.

```rust
/// Unified approval token (NORMATIVE)
pub struct ApprovalToken {
    pub token_id: ObjectId,
    pub scope: ApprovalScope,
    /// Human-readable justification (UI + audit)
    pub justification: String,
    pub approved_by: PrincipalId,
    pub approved_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}

/// Approval scope (NORMATIVE)
pub enum ApprovalScope {
    /// Integrity elevation for a specific operation + provenance
    Elevation {
        operation: OperationId,
        original_provenance: Provenance,
    },
    /// Confidentiality downgrade for specific objects
    Declassification {
        from_zone: ZoneId,
        to_zone: ZoneId,
        object_ids: Vec<ObjectId>,
    },
}

impl ApprovalToken {
    /// Default TTL: 5 minutes
    pub const DEFAULT_TTL_SECS: u64 = 300;

    /// Verify token is valid
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), VerifyError> {
        // Check expiry
        if current_timestamp() > self.expires_at {
            return Err(VerifyError::Expired);
        }

        // Verify approver authority
        let approver_key = trust_anchors.get_principal_key(&self.approved_by)?;
        approver_key.verify(&self.signable_bytes(), &self.signature)?;

        // Verify approver has appropriate authority for the scope
        match &self.scope {
            ApprovalScope::Elevation { .. } => {
                if !trust_anchors.can_approve_elevation(&self.approved_by) {
                    return Err(VerifyError::InsufficientAuthority);
                }
            }
            ApprovalScope::Declassification { from_zone, to_zone, .. } => {
                if !trust_anchors.can_approve_declassification(&self.approved_by, from_zone, to_zone) {
                    return Err(VerifyError::InsufficientAuthority);
                }
            }
        }

        Ok(())
    }

    /// Create an elevation approval
    pub fn create_elevation(
        operation: OperationId,
        provenance: &Provenance,
        approver: &Identity,
        justification: &str,
        ttl: Option<u64>,
    ) -> Self;

    /// Create a declassification approval
    pub fn create_declassification(
        from_zone: ZoneId,
        to_zone: ZoneId,
        object_ids: Vec<ObjectId>,
        approver: &Identity,
        justification: &str,
        ttl: Option<u64>,
    ) -> Self;
}
```

### 5.3 Provenance and Taint

```rust
/// Provenance tracking (NORMATIVE)
#[derive(Clone)]
pub struct Provenance {
    pub origin_zone: ZoneId,
    /// Current zone (updated on every zone crossing)
    pub current_zone: ZoneId,
    pub origin_integrity: u8,
    pub origin_confidentiality: u8,
    pub origin_principal: Option<PrincipalId>,
    /// Taint flags (compositional: merged via OR across inputs)
    pub taint: TaintFlags,
    /// Taint reductions, each justified by a verifiable attestation (NORMATIVE)
    /// Allows specific taints to be cleared with proof (e.g., URL scan, malware check)
    pub taint_reductions: Vec<TaintReduction>,
    pub zone_crossings: Vec<ZoneCrossing>,
    pub created_at: u64,
}

/// Proof-carrying taint reduction (NORMATIVE)
///
/// Allows clearing specific taints when you can point to a verifiable attestation.
/// Examples:
/// - URL scanning cleared UNVERIFIED_LINK
/// - Malware scan cleared UNVERIFIED_LINK
/// - Strict schema validation cleared PROMPT_SURFACE for that field
#[derive(Clone)]
pub struct TaintReduction {
    /// Which taints are cleared
    pub clears: TaintFlags,
    /// Attestation/receipt ObjectId that justifies the reduction
    pub by_attestation: ObjectId,
    /// When the reduction was applied
    pub applied_at: u64,
}

bitflags! {
    /// Taint flags (NORMATIVE)
    pub struct TaintFlags: u32 {
        const NONE            = 0;
        const PUBLIC_INPUT    = 1 << 0;  // e.g. z:public messages, web
        const EXTERNAL_INPUT  = 1 << 1;  // e.g. paired external identities
        const UNVERIFIED_LINK = 1 << 2;  // URLs / attachments not scanned
        const USER_SUPPLIED   = 1 << 3;  // direct human input
        const PROMPT_SURFACE  = 1 << 4;  // content interpreted by an LLM
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
    /// Effective taint after applying reductions (NORMATIVE)
    ///
    /// Taint reductions allow specific taints to be cleared with proof.
    /// Without this, taint-only-accumulates leads to "approve everything" fatigue.
    pub fn effective_taint(&self) -> TaintFlags {
        let mut t = self.taint;
        for r in &self.taint_reductions {
            t.remove(r.clears);
        }
        t
    }
}
```

Taint decisions are enforced before invocation using `effective_taint()`:

- Public-tainted input cannot directly drive Dangerous operations.
- If `effective_taint() != NONE` and `operation.safety_tier >= Risky` and `target_zone.integrity_level > origin_integrity`,
  an ApprovalToken with `ApprovalScope::Elevation` is required.
- Otherwise, the operation is allowed.

Cross-zone movement updates `current_zone` and records zone crossings.

### 5.4 Connector Implications

- Objects stored in the mesh MUST include an `ObjectHeader`, which includes provenance.
- When a connector creates objects, it must supply provenance as part of the header and compute
  `ObjectId` from the canonical encoding of `(header, body)`.
- Elevation is handled by `ApprovalToken` with `ApprovalScope::Elevation` (see §5.2).
- Declassification is handled by `ApprovalToken` with `ApprovalScope::Declassification` (see §5.2).

---

## 6. Capability System

### 6.1 Capability Taxonomy (Non-exhaustive)

```
fcp.*                    Protocol/meta operations
├── fcp.connect          Establish connection
├── fcp.handshake        Complete handshake
└── fcp.introspect       Query capabilities

network.*                Network operations
├── network.egress       Outbound access via MeshNode egress proxy (DEFAULT in strict/moderate sandboxes)
├── network.raw_outbound:* Direct sockets (RARE; permissive sandbox only)
├── network.inbound:*    Listen for connections
└── network.dns          DNS resolution (explicit capability; policy surface)

network.tls.*            TLS identity constraints (NORMATIVE for sensitive connectors)
├── network.tls.sni       Enforce SNI hostname match
└── network.tls.spki_pin  Enforce SPKI pin(s) for target host(s)

storage.*                Data persistence
├── storage.persistent   Durable storage
├── storage.ephemeral    Temporary storage
└── storage.encrypted    Encrypted storage

ipc.*                    Inter-process communication
├── ipc.gateway          Gateway communication
└── ipc.agent            Agent communication

system.*                 System operations (restricted)
├── system.info          System information (readonly)
├── system.exec          Execute commands (dangerous)
└── system.env           Environment variables

[service].*              Service-specific capabilities
├── telegram.*           Telegram operations
├── discord.*            Discord operations
├── gmail.*              Gmail operations
├── calendar.*           Calendar operations
└── ...                  Other services
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

pub enum ApprovalMode {
    /// No approval needed
    None,
    /// Policy-based auto-approval
    Policy,
    /// Interactive human approval
    Interactive,
    /// Requires ApprovalToken (elevation or other scope)
    ApprovalRequired,
}

pub struct AgentHint {
    pub when_to_use: String,
    pub common_mistakes: Vec<String>,
    pub examples: Vec<String>,
    pub related: Vec<CapabilityId>,
}
```

### 6.3 Capability Object and Constraints

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

/// Network/TLS constraints (NORMATIVE for sensitive connectors)
///
/// Prevents DNS pivot, SSRF, and host confusion attacks.
pub struct NetworkConstraints {
    /// Allowed hostnames (exact or suffix match)
    pub host_allow: Vec<String>,
    /// Allowed ports
    pub port_allow: Vec<u16>,
    /// Optional explicit IP allow-list
    pub ip_allow: Vec<IpAddr>,
    /// CIDR blocks denied by policy
    /// NORMATIVE default includes: localhost (127.0.0.0/8, ::1), link-local (169.254.0.0/16),
    /// RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and tailnet ranges (100.64.0.0/10)
    pub cidr_deny: Vec<String>,
    /// Deny localhost unless explicitly allowed (NORMATIVE default: true)
    pub deny_localhost: bool,
    /// Deny private ranges unless explicitly allowed (NORMATIVE default: true)
    pub deny_private_ranges: bool,
    /// Deny tailnet address ranges unless explicitly allowed (NORMATIVE default: true)
    pub deny_tailnet_ranges: bool,
    /// Require SNI hostname match
    pub require_sni: bool,
    /// Optional SPKI pins (base64-encoded SHA256 of SubjectPublicKeyInfo)
    pub spki_pins: Vec<String>,
}
```

**Egress Proxy (NORMATIVE for strict/moderate sandboxes):**

In Strict and Moderate sandbox profiles, connectors MUST NOT be granted raw socket syscalls.
Network capabilities are implemented by a MeshNode-owned **egress proxy** enforcing NetworkConstraints:

- Connectors talk to the proxy over capability-gated IPC (`network.egress` capability)
- Proxy enforces `host_allow`, `port_allow`, `cidr_deny`, SNI, and SPKI pins
- No SSRF into localhost/tailnet/RFC1918 unless explicitly allowed
- DNS resolution goes through proxy with policy checks

Network/TLS constraints are NORMATIVE for sensitive connectors and include host/port
allow-lists, SNI enforcement, CIDR deny-lists, and optional SPKI pins.

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
/// Capability Token for operation invocation (NORMATIVE)
pub struct CapabilityToken {
    /// Unique token identifier
    pub jti: Uuid,
    /// Principal identifier
    pub sub: PrincipalId,
    /// Issuing zone
    pub iss_zone: ZoneId,
    /// Issuing node (signer) - the node that minted this token
    pub iss_node: TailscaleNodeId,
    /// Issuer key id (for rotation)
    pub kid: [u8; 8],
    /// Intended audience (connector)
    pub aud: ConnectorId,
    /// Optional connector instance binding
    pub instance: Option<InstanceId>,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Expires at (Unix timestamp)
    pub exp: u64,
    /// Granted capabilities
    pub caps: Vec<CapabilityGrant>,
    /// Constraints
    pub constraints: CapabilityConstraints,
    /// The only node allowed to present this token (sender-constrained)
    pub holder_node: TailscaleNodeId,
    /// Revocation head the issuer considered (NORMATIVE)
    /// Verifiers MUST have revocation state >= this head or fetch before acceptance.
    pub rev_head: ObjectId,
    /// Monotonic revocation sequence at rev_head (NORMATIVE)
    /// Enables O(1) freshness checks: verifier compares rev_seq, not chain traversal.
    pub rev_seq: u64,
    /// Ed25519 signature (by iss_node's issuance key)
    pub sig: [u8; 64],
}

pub struct CapabilityGrant {
    /// Granted capability
    pub capability: CapabilityId,
    /// Optional operation-level restriction
    pub operation: Option<OperationId>,
}

impl CapabilityToken {
    /// Default TTL: 5 minutes
    pub const DEFAULT_TTL_SECS: u64 = 300;

    /// Verify token validity (NORMATIVE)
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), TokenError> {
        // Check expiry
        if current_timestamp() > self.exp {
            return Err(TokenError::Expired);
        }

        // Verify signature using node issuance pubkey (NOT signing key, NOT zone key)
        // The issuing node must have a valid NodeKeyAttestation from owner
        let issuer_pubkey = trust_anchors.get_node_iss_pubkey(&self.iss_node, &self.kid)?;
        issuer_pubkey.verify(&self.signable_bytes(), &self.sig)?;

        // Enforce that issuing node is authorized to mint tokens for this zone
        trust_anchors.enforce_token_issuer_policy(&self.iss_zone, &self.iss_node)?;

        Ok(())
    }
}
```

Token verification MUST use the node issuance public key (not the node signing key). Issuance keys are
separately revocable. Verifiers compare `rev_seq` for O(1) freshness checks; full chain traversal is
only needed on seq mismatch. Verifiers MUST have revocation state >= `rev_head` (or fetch revocations)
before accepting a token.

---

## 7. Invoke, Receipts, and Event Envelopes

### 7.1 Invoke Request/Response

```rust
/// Invoke request (NORMATIVE)
pub struct InvokeRequest {
    pub id: String,
    pub operation: OperationId,
    pub input: Value,
    pub capability_token: CapabilityToken,
    pub provenance: Provenance,
    /// Unified approval tokens for elevation and/or declassification
    pub approval_tokens: Vec<ApprovalToken>,
    pub idempotency_key: Option<String>,

    /// Holder proof (NORMATIVE): binds presentation to holder_node in CapabilityToken
    /// Prevents token replay by anyone other than the designated holder.
    pub holder_proof: Signature,
}

impl InvokeRequest {
    /// Verify holder proof (NORMATIVE)
    pub fn verify_holder_proof(&self, trust_anchors: &TrustAnchors) -> Result<(), VerifyError> {
        let holder = &self.capability_token.holder_node;
        let holder_pubkey = trust_anchors.get_node_sig_pubkey(holder)?;
        holder_pubkey.verify(&self.holder_signable_bytes(), &self.holder_proof)
    }

    fn holder_signable_bytes(&self) -> Vec<u8> {
        // Include request id, operation, and token jti to bind holder proof to specific request
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.capability_token.jti.as_bytes());
        bytes
    }
}

/// Invoke response (NORMATIVE)
pub struct InvokeResponse {
    pub id: String,
    pub result: Value,
    pub resource_uris: Vec<String>,
    pub next_cursor: Option<String>,
    /// Receipt ObjectId (for operations with side effects)
    pub receipt: Option<ObjectId>,
}
```

The holder proof prevents token replay by anyone other than the designated holder. The signable bytes
bind the request to the specific `id`, `operation`, and token `jti`.

**Enforcement before execution:**
- If `effective_taint() != NONE` and operation requires elevation, the `approval_tokens` MUST contain
  an `ApprovalToken` with `ApprovalScope::Elevation`.
- If an operation writes outputs into a zone with lower confidentiality than the data label,
  `approval_tokens` MUST contain an `ApprovalToken` with `ApprovalScope::Declassification`.

### 7.2 Operation Receipt

```rust
/// Operation receipt object (NORMATIVE)
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

---

## 8. Streaming, Replay, and Acks

Event streaming requirements:

- Event envelopes include `topic`, `seq`, `cursor`, and `requires_ack` fields.
- If `requires_ack` is true, consumers are expected to ack; connectors can track delivery state.
- When `event_caps.replay = true`, connectors MUST support replay from a cursor.
- `event_caps.min_buffer_events` sets the minimum replay buffer size.

---

## 9. Error Taxonomy

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

## 10. Agent Integration (Introspection + MCP)

Agents MUST be able to query:

- Operations (schemas, risk levels)
- Approval requirements
- Rate limits
- Recovery hints

Map connector operations to MCP-compatible tools with:

- Schemas
- Risk annotations
- Examples
- Rate limits

---

## 11. Connector Manifest (TOML) and Embedding

### 11.1 Manifest Structure (NORMATIVE)

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

### 11.2 Manifest Embedding (NORMATIVE)

Manifests MUST be extractable without execution:

- ELF: `.fcp_manifest`
- Mach-O: `__FCP,__manifest`
- PE: `.fcpmanifest`

Connectors MUST implement `--manifest` to print the embedded manifest.

---

## 12. Sandbox Profiles and Enforcement

```rust
/// Sandbox configuration from manifest (NORMATIVE)
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
    /// Maximum restrictions (recommended for untrusted connectors)
    Strict,
    /// Maximum isolation (Linux): microVM-backed sandbox for high-risk connectors (NORMATIVE where available)
    StrictPlus,
    /// Balanced restrictions (default)
    Moderate,
    /// Minimal restrictions (only for highly trusted connectors)
    Permissive,
}
```

Enforcement:

- Resource limits (memory, CPU, time) are enforced by the OS sandbox.
- Filesystem access is limited to declared paths.
- Network access is limited to declared capabilities and constraints.
- Child process spawning and debugging/tracing can be denied.

---

## 13. Automation Recipes and Provisioning Interface

### 13.1 Recipe Model

Recipes are deterministic step lists for connector setup:

```toml
[recipe]
id = "telegram/setup"
version = "1"
description = "Set up Telegram bot integration"

[[steps]]
type = "prompt_user"
id = "bot_name"
message = "Choose a Telegram bot name"

[[steps]]
type = "open_url"
requires_approval = true
url = "https://t.me/BotFather"

[[steps]]
type = "prompt_secret"
id = "bot_token"
message = "Paste the Telegram bot token"

[[steps]]
type = "store_secret"
key = "telegram.bot_token"
value_from = "bot_token"
scope = "connector:fcp.telegram"
```

### 13.2 Provisioning Interface

| Operation | Purpose |
|-----------|---------|
| `fcp.provision.start` | Begin auth flow |
| `fcp.provision.poll` | Check status |
| `fcp.provision.complete` | Finalize credentials |
| `fcp.provision.abort` | Cancel and cleanup |

---

## 14. Registry and Supply Chain

### 14.1 Registry Sources (NORMATIVE)

Registries are sources, not dependencies. Implementations MUST support at least one of:

1. Remote registry (HTTP) - public registry like registry.flywheel.dev
2. Self-hosted registry (HTTP) - enterprise/private registry
3. Mesh mirror registry - connectors pinned as objects in z:owner or z:private

Connector binaries MUST be content-addressed objects and MAY be distributed via the symbol layer.

```rust
/// Registry source configuration (NORMATIVE)
pub enum RegistrySource {
    Remote { url: Url, trusted_keys: Vec<Ed25519PublicKey> },
    SelfHosted { url: Url, trusted_keys: Vec<Ed25519PublicKey> },
    MeshMirror { zone: ZoneId, index_object_id: ObjectId },
}
```

### 14.2 Transparency Log (Optional, NORMATIVE if enabled)

```rust
pub struct ConnectorTransparencyLogEntry {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub version: Version,
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    pub published_at: u64,
    pub signature: Signature,
}
```

### 14.3 Supply Chain Attestations (RECOMMENDED)

First-class provenance attestations make supply chain verification machine-checkable, not just "signature valid".

```rust
/// Supply chain attestation (NORMATIVE when present)
///
/// First-class, machine-checkable provenance statement.
/// Makes "built from repo X at commit Y under workflow Z" enforceable.
pub struct SupplyChainAttestation {
    pub header: ObjectHeader,
    pub attestation_type: AttestationType,
    /// The connector binary this attestation covers
    pub subject_binary: ObjectId,
    /// Raw attestation payload (e.g., in-toto statement JSON)
    pub payload: Vec<u8>,
    /// Signature by builder/attestor
    pub signature: Signature,
}

pub enum AttestationType {
    /// in-toto statement with SLSA provenance predicate
    InToto,
    /// Reproducible build attestation
    ReproducibleBuild,
    /// Code review attestation
    CodeReview,
    /// Custom attestation type
    Custom(String),
}

/// Owner policy for supply chain verification (NORMATIVE)
pub struct SupplyChainPolicy {
    /// Require transparency log entry
    pub require_transparency_log: bool,
    /// Required attestation types (all must be present)
    pub require_attestation_types: Vec<AttestationType>,
    /// Minimum SLSA level (0-4)
    pub min_slsa_level: u8,
    /// Trusted builder identities
    pub trusted_builders: Vec<String>,
    /// Trusted publisher key fingerprints
    pub trusted_publishers: Vec<[u8; 32]>,
}
```

Manifest declares attestations:

```toml
[supply_chain]
attestations = [
  { type = "in-toto", object_id = "objectid:..." },
  { type = "reproducible-build", object_id = "objectid:..." },
]

[policy]
require_transparency_log = true
require_attestation_types = ["in-toto"]
min_slsa_level = 2
trusted_builders = ["github-actions", "internal-ci"]
```

### 14.4 Verification Chain

Before execution, verify:

1. Manifest signature (registry or trusted publisher quorum)
2. Binary checksum matches manifest
3. Binary signature matches trusted key
4. Platform/arch match
5. Requested capabilities are within zone ceilings
6. Optional: release present in transparency log (if enabled)
7. **Supply chain attestations** (if policy requires): verify all required attestation types present,
   SLSA level >= min_slsa_level, builder identity in trusted_builders list

---

## 15. Lifecycle Management and Revocation

### 15.1 Activation Requirements

On activation:

1. Create sandbox
2. Inject secrets ephemerally
3. Negotiate handshake
4. Issue capability tokens
5. Start health checks

### 15.2 Updates and Rollback

- Staged updates
- Automatic rollback on crash loops
- Explicit pinning to known-good versions

### 15.3 Revocation (NORMATIVE)

Revocations are mesh objects and MUST be enforced before use.
Without revocation, "compromised device" recovery is mostly imaginary.

```rust
/// Revocation object (NORMATIVE)
pub struct RevocationObject {
    pub header: ObjectHeader,
    /// ObjectIds being revoked
    pub revoked: Vec<ObjectId>,
    /// Scope of revocation
    pub scope: RevocationScope,
    /// Human-readable reason
    pub reason: String,
    /// When revocation becomes effective
    pub effective_at: u64,
    /// Optional expiry (None = permanent)
    pub expires_at: Option<u64>,
    /// Owner signature (revocations MUST be owner-signed)
    pub signature: Signature,
}

/// Revocation event chain node (NORMATIVE)
///
/// Hash-linked chain for revocation freshness.
pub struct RevocationEvent {
    pub header: ObjectHeader,
    pub revocation_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    /// Monotonic chain sequence number (NORMATIVE)
    /// Enables O(1) freshness comparison: seq_a > seq_b ⟹ a is fresher than b.
    pub seq: u64,
    pub occurred_at: u64,
    pub signature: Signature,
}

/// Revocation head checkpoint (NORMATIVE)
///
/// Enables freshness semantics: tokens bound to a rev_head, verifiers MUST
/// have revocation state >= that head before accepting the token.
pub struct RevocationHead {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub head_event: ObjectId,
    /// Sequence number of head_event (NORMATIVE)
    /// Enables O(1) freshness comparison without chain traversal.
    pub head_seq: u64,
    pub epoch_id: EpochId,
    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
}

pub enum RevocationScope {
    /// Revoke capability objects/tokens
    Capability,
    /// Revoke issuer keys (node can no longer mint tokens)
    IssuerKey,
    /// Revoke node attestation (removes device from mesh)
    NodeAttestation,
    /// Revoke zone key (forces rotation)
    ZoneKey,
    /// Revoke connector binary (supply chain response)
    ConnectorBinary,
}

/// Revocation registry (NORMATIVE)
pub struct RevocationRegistry {
    revocations: HashMap<ObjectId, RevocationObject>,
    bloom_filter: BloomFilter, // Fast negative lookup
    /// Latest revocation head known for this zone
    pub head: Option<ObjectId>,
}

impl RevocationRegistry {
    /// Check if object is revoked (MUST be called before use)
    pub fn is_revoked(&self, object_id: &ObjectId) -> bool {
        if !self.bloom_filter.might_contain(object_id.as_bytes()) {
            return false; // Fast path: definitely not revoked
        }
        self.revocations.contains_key(object_id)
    }
}
```

**Enforcement points (NORMATIVE):**

1. Before accepting a capability token
2. Before executing an operation
3. Before accepting symbols for audit head updates
4. Before using zone keys
5. On connector startup

---

## 16. Device-Aware Execution and Execution Leases

### 16.1 Execution Leases (NORMATIVE)

Execution leases prevent duplicate side effects and stabilize migration:

```rust
/// Execution lease (NORMATIVE)
pub struct ExecutionLease {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub owner_node: TailscaleNodeId,
    pub iat: u64,
    pub exp: u64,
    pub signature: Signature,
}
```

Lease semantics:

- For Risky/Dangerous operations, execution MUST require a valid lease.
- The executing node MUST present the lease to run the connector operation.
- If the node dies, the lease expires and another node can acquire.

---

### 16.2 Device Profiles and Execution Planner

Device-aware execution uses profiles and placement policies to choose the best node:

```rust
/// Device profile (NORMATIVE)
pub struct DeviceProfile {
    pub node_id: TailscaleNodeId,
    pub hostname: String,
    pub device_class: DeviceClass,
    pub capabilities: DeviceCapabilities,
    pub current_state: DeviceState,
}

pub enum DeviceClass {
    Desktop { os: String },
    Laptop { os: String, battery: bool },
    Phone { os: String },
    Tablet { os: String },
    Server,
    Browser,
}

pub struct DeviceCapabilities {
    pub cpu_cores: u8,
    pub memory_mb: u32,
    pub gpu: Option<GpuInfo>,
    pub storage_mb: u64,
    pub network: NetworkCapability,
}

/// Execution planner (NORMATIVE)
pub struct ExecutionPlanner {
    pub devices: Vec<DeviceProfile>,
}
```

### 16.3 Device Requirements and Preferences

The placement policy uses requirements and preferences to guide device selection:

```rust
/// Device requirements (NORMATIVE)
pub enum DeviceRequirement {
    /// Must have GPU
    Gpu { min_vram_mb: u32 },
    /// Must have minimum memory
    Memory { min_mb: u32 },
    /// Must be on power (not battery)
    OnPower,
    /// Must have specific software
    Software { name: String, version: Option<String> },
    /// Must have network connectivity
    Network { min_bandwidth_mbps: Option<u32> },
    /// Must have specific Tailscale tag
    TailscaleTag(String),
    /// Required connector must be available (installed or fetchable)
    ConnectorAvailable { connector_id: ConnectorId, min_version: Option<Version> },
    /// Secret must be reconstructable under current policy
    SecretReconstructable { secret_id: SecretId, min_nodes: u8 },
    /// Must have sufficient quota headroom in the target zone store
    ZoneQuotaHeadroom { zone_id: ZoneId, min_free_mb: u32 },
}

/// Device preferences (NORMATIVE)
pub enum DevicePreference {
    /// Prefer devices with lower latency
    LowLatency { max_ms: u32, weight: f32 },
    /// Prefer devices with more resources
    HighResources { weight: f32 },
    /// Prefer specific device
    SpecificDevice { node_id: TailscaleNodeId, weight: f32 },
    /// Prefer devices where data is local
    DataLocality { object_ids: Vec<ObjectId>, weight: f32 },
}
```

The planner filters devices by `PlacementPolicy.requires` and scores them by `prefers`,
including latency, resources, data locality, secret reconstruction cost, and DERP penalties.

---

## 17. Observability and Audit

### 17.1 Metrics (NORMATIVE)

Required metrics:

- Request counts, latencies, error rates
- Resource usage
- Rate-limit denials
- Zone/taint denials

### 17.2 Structured Logs

Structured logs MUST:

- Be JSON
- Redact secrets
- Include `correlation_id`, `zone_id`, and `connector_id`

### 17.3 Audit Chain (NORMATIVE)

Audit is an append-only, hash-linked object chain per zone. This makes "tamper-evident by construction"
a testable, interoperable mechanism.

Audit events MUST be recorded for:

- Secret access
- High-risk capability use
- Approvals/elevations
- Zone transitions
- Security violations

```rust
/// Audit event (NORMATIVE)
pub struct AuditEvent {
    pub header: ObjectHeader,
    /// Correlation ID for request tracing
    pub correlation_id: [u8; 16],
    /// Event type (e.g., "secret.access", "capability.invoke", "elevation.granted")
    pub event_type: String,
    /// Actor who triggered the event
    pub actor: PrincipalId,
    /// Zone where event occurred
    pub zone_id: ZoneId,
    /// Connector ID (if applicable)
    pub connector_id: Option<ConnectorId>,
    /// Operation ID (if applicable)
    pub operation: Option<OperationId>,
    /// Capability token JTI (if applicable)
    pub capability_token_jti: Option<Uuid>,
    /// Request object ID (if applicable)
    pub request_object_id: Option<ObjectId>,
    /// Result object ID (if applicable)
    pub result_object_id: Option<ObjectId>,
    /// Previous event in chain (hash link)
    pub prev: Option<ObjectId>,
    /// Monotonic chain sequence number (NORMATIVE)
    pub seq: u64,
    /// When event occurred
    pub occurred_at: u64,
    /// Signature by executing node
    pub signature: Signature,
}

/// Audit head checkpoint (NORMATIVE)
pub struct AuditHead {
    pub header: ObjectHeader,
    /// Zone this head covers
    pub zone_id: ZoneId,
    /// Head event ObjectId
    pub head_event: ObjectId,
    /// Sequence number of head_event (NORMATIVE)
    pub head_seq: u64,
    /// Fraction of expected nodes contributing
    pub coverage: f64,
    /// Epoch this head was checkpointed
    pub epoch_id: EpochId,
    /// Quorum signatures from nodes
    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
}

/// Frontier checkpoint for fast sync (NORMATIVE)
///
/// Compact checkpoint of zone state for efficient synchronization.
/// Nodes can compare frontiers to quickly determine staleness.
pub struct ZoneFrontier {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub rev_head: ObjectId,
    pub rev_seq: u64,
    pub audit_head: ObjectId,
    pub audit_seq: u64,
    pub as_of_epoch: EpochId,
    /// Signature by executing node
    pub signature: Signature,
}
```

**Quorum Rule (default):** CriticalWrite requires n - f signatures (see V2 spec §18).
Nodes MUST refuse to advance AuditHead if quorum is not satisfied, unless in explicit degraded mode.

**Fork Detection (NORMATIVE):** Nodes discovering multiple heads for the same epoch MUST:
1. Log the fork event
2. Refuse to advance until reconciled
3. Alert owner for manual resolution

---

## 18. Connector Archetypes (V2) and Patterns

### 18.1 V2 Archetypes (Manifest `archetypes`)

- Bidirectional: send and receive messages
- Streaming: emit events (read-only)
- Operational: execute operations (request/response)
- Storage: store/retrieve data
- Knowledge: search/index/answer

Only these values are valid in `connector.archetypes`.

### 18.2 Interaction Pattern Mapping (Non-archetype)

These patterns map to V2 archetypes in the manifest:

- Request/Response -> Operational
- Polling -> Operational (often paired with Streaming events)
- Webhook -> Streaming (and/or Operational for acknowledgments)
- Queue/Pub-Sub -> Bidirectional or Streaming depending on API

### 18.3 Reference Connector Patterns (Appendix C)

| Pattern | Description | Examples |
|---------|-------------|----------|
| Unified Messaging | Maps channels to zones | Telegram, Discord |
| Workspace | Local caching, write gating | Gmail, Calendar |
| Knowledge | Filesystem watch + search | Obsidian, Notion |
| DevOps | Typed CLI wrappers | gh, kubectl |

---

## 19. Rust Connector Skeleton (SDK-aligned)

### 19.1 Toolchain Requirements

- Rust edition: 2024 (nightly required)
- Cargo only
- `#![forbid(unsafe_code)]`

### 19.2 Minimal Skeleton (Control-Plane Object Dispatch)

```rust
#![forbid(unsafe_code)]

use async_trait::async_trait;
use fcp_core::{
    Connector, ControlPlaneObject, FcpError,
};

#[async_trait]
pub trait FcpConnector {
    fn metadata(&self) -> Connector;
    async fn handle_control_plane(&self, obj: ControlPlaneObject) -> Result<ControlPlaneObject, FcpError>;
}

pub struct MyConnector {
    // clients, config, caches
}

#[async_trait]
impl FcpConnector for MyConnector {
    fn metadata(&self) -> Connector {
        // Return Connector metadata consistent with manifest
        unimplemented!()
    }

    async fn handle_control_plane(&self, obj: ControlPlaneObject) -> Result<ControlPlaneObject, FcpError> {
        // Dispatch by SchemaId from obj.header.schema:
        // handshake | describe | introspect | capabilities | configure | invoke | subscribe | health | shutdown
        unimplemented!()
    }
}
```

Implementation notes:

- Dispatch on SchemaId, not JSON method strings.
- Validate inputs against the manifest schemas.
- Enforce Strict idempotency when required; return prior receipts on duplicate idempotency_key.
- When producing mesh objects, include `ObjectHeader` with provenance.

---

## 20. Conformance Checklist (Connector)

Connector MUST:

**Protocol:**
- Implement `--manifest` flag.
- Implement standard methods: `handshake`, `describe`, `introspect`, `capabilities`, `configure`, `invoke`, `health`, `shutdown`.
- Support event cursors and replay when streaming.
- Support session authentication for high-throughput data plane.

**Capability & Security:**
- Declare required/optional/forbidden capabilities in the manifest.
- Use `network.egress` capability through MeshNode proxy (not raw sockets) in strict/moderate sandboxes.
- Validate inputs against manifest schemas.
- Never log secrets.

**State & Provenance:**
- Include `ObjectHeader` with provenance when producing mesh objects.
- Use `effective_taint()` for taint checks (respecting `taint_reductions`).
- Externalize state to `ConnectorStateObject` (authoritative state lives in mesh, not local cache).
- Use `singleton_writer = true` in manifest if connector requires single-writer semantics.

**Approval & Authorization:**
- Use unified `ApprovalToken` with `ApprovalScope::Elevation` or `ApprovalScope::Declassification`.
- Support `approval_tokens: Vec<ApprovalToken>` in `InvokeRequest`.
- Verify `rev_seq` for O(1) freshness checks on capability tokens.

**Supply Chain (RECOMMENDED):**
- Include supply chain attestations in manifest (`[supply_chain]` section).
- Support transparency log entries.
- Include AI hints for operations.

---

## Notes

- This document intentionally avoids FCP1-only constructs except where marked as compatibility.
- For mesh, symbol, audit, and trust-anchor details, refer to `FCP_Specification_V2.md`.
- All normative structures in this document are aligned with FCP Specification V2.

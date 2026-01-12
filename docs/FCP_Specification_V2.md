# Flywheel Connector Protocol (FCP) Specification V2

**Version:** 2.0.0
**Status:** Draft
**Last Updated:** 2026-01-12

---

## Abstract

The Flywheel Connector Protocol (FCP) is a mesh-native protocol for secure, distributed AI assistant operations across personal device meshes. FCP V2 fundamentally reimagines the protocol around three axioms: **Universal Fungibility** (RaptorQ symbols as the atomic unit), **Authenticated Mesh** (Tailscale as identity and transport), and **Explicit Authority** (cryptographic capability chains).

This specification defines:
- The complete wire protocol for symbol-native communication
- Connector architecture, manifests, and lifecycle management
- Zone-based security with cryptographic isolation
- Distributed state, computation migration, and offline access
- Registry, supply chain, and conformance requirements

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Foundational Axioms](#2-foundational-axioms)
3. [Foundational Primitives](#3-foundational-primitives)
4. [Symbol Layer](#4-symbol-layer)
5. [Zone Architecture](#5-zone-architecture)
6. [Provenance and Taint Tracking](#6-provenance-and-taint-tracking)
7. [Capability System](#7-capability-system)
8. [Mesh Architecture](#8-mesh-architecture)
9. [Wire Protocol](#9-wire-protocol)
10. [Connector Model](#10-connector-model)
11. [Connector Manifest](#11-connector-manifest)
12. [Automation Recipes](#12-automation-recipes)
13. [Registry and Supply Chain](#13-registry-and-supply-chain)
14. [Lifecycle Management](#14-lifecycle-management)
15. [Device-Aware Execution](#15-device-aware-execution)
16. [Computation Migration](#16-computation-migration)
17. [Security Model](#17-security-model)
18. [Trust Model and Byzantine Assumptions](#18-trust-model-and-byzantine-assumptions)
19. [Tailscale Integration](#19-tailscale-integration)
20. [RaptorQ Deep Integration](#20-raptorq-deep-integration)
21. [Offline Access](#21-offline-access)
22. [Agent Integration](#22-agent-integration)
23. [Observability and Audit](#23-observability-and-audit)
24. [Error Taxonomy](#24-error-taxonomy)
25. [Implementation Phases](#25-implementation-phases)
26. [Compatibility and Migration](#26-compatibility-and-migration)
27. [Conformance Requirements](#27-conformance-requirements)
- [Appendix A: FZPF v0.1 JSON Schema](#appendix-a-fzpf-v01-json-schema)
- [Appendix B: RaptorQ Configuration](#appendix-b-raptorq-configuration)
- [Appendix C: Reference Connector Patterns](#appendix-c-reference-connector-patterns)
- [Appendix D: SDK Crates](#appendix-d-sdk-crates)
- [Appendix E: Conformance Checklist](#appendix-e-conformance-checklist)
- [Appendix F: Golden Decision Test Vectors](#appendix-f-golden-decision-test-vectors)
- [Appendix G: Transport Priority](#appendix-g-transport-priority)

---

## 1. Introduction

### 1.1 Vision

Your personal AI runs on YOUR devices. Your data exists as symbols across YOUR mesh. Any subset of YOUR devices can reconstruct anything. Computation happens wherever optimal. Secrets are never complete anywhere. History is tamper-evident by construction.

This is not a cloud alternative. This is **digital sovereignty**.

### 1.2 Design Principles

1. **Mesh-Native**: Every device is the Hub. There is no central coordinator.
2. **Symbol-First**: All data flows as RaptorQ fountain-coded symbols.
3. **Zero-Trust Transport**: Tailscale provides authenticated, encrypted mesh networking.
4. **Cryptographic Authority**: All authority flows from owner keys through verifiable chains.
5. **Fail-Safe Defaults**: Default deny. Explicit grants. No ambient authority.
6. **Offline-Capable**: Reduced probability, not binary unavailability.
7. **Agent-Friendly**: Every operation is introspectable, typed, and has recovery hints.

### 1.3 Key Terminology

| Term | Definition |
|------|------------|
| **Symbol** | A RaptorQ-encoded fragment; any K' symbols reconstruct the original |
| **Object** | Content-addressed data identified by ObjectId |
| **Zone** | A cryptographic namespace with its own encryption key |
| **Epoch** | A logical time unit; no ordering within, ordering between |
| **MeshNode** | A device participating in the FCP mesh |
| **Capability** | An authorized operation with cryptographic proof |
| **Connector** | A sandboxed binary that bridges external services to FCP |
| **Hub** | Legacy term; in FCP V2, the mesh collectively IS the Hub |

### 1.4 Comparison: FCP V1 vs V2

| Aspect | FCP V1 (Hub-Spoke) | FCP V2 (Mesh-Native) |
|--------|--------------------|-----------------------|
| Architecture | Central Hub process | Mesh IS the Hub |
| Connectors | On specific machines | Capabilities anywhere |
| Sessions | Per-node | Mesh-wide contexts |
| Storage | Device-local | Symbol distribution |
| Sync | Between devices | Symbol flow |
| Offline | No access | Reduced probability |
| Identity | Per-service principals | Tailscale identity |
| Zones | Policy enforcement | Tailscale tags + crypto |
| Secrets | On devices | Threshold secrets (k-of-n) |
| Audit | Per-node logs | Distributed audit chain |
| Execution | Fixed location | Optimal device selection |
| Protocol | Connection-oriented | Symbol-oriented |

---

## 2. Foundational Axioms

### 2.1 Axiom 1: Universal Fungibility

**All data flows as RaptorQ symbols. Symbols are interchangeable.**

```rust
/// The universal transmission unit (NORMATIVE)
pub struct SymbolEnvelope {
    /// Content address of the complete object
    pub object_id: ObjectId,

    /// Encoding Symbol ID (ESI) - position in fountain code
    pub esi: u32,

    /// Total source symbols (K)
    pub k: u16,

    /// Symbol payload (fixed size, typically 1024 bytes)
    pub data: Vec<u8>,

    /// Zone for key selection
    pub zone_id: ZoneId,

    /// Epoch for temporal binding
    pub epoch_id: EpochId,

    /// Authentication tag (AEAD)
    pub auth_tag: [u8; 16],
}
```

**Key Properties:**
- Any K' symbols (K' ≈ K × 1.002) can reconstruct the original object
- No symbol is special—all are equally useful
- Receivers don't need to coordinate which symbols they receive
- Lost symbols don't require retransmission of specific data
- Multipath aggregation: symbols from any source contribute equally

### 2.2 Axiom 2: Authenticated Mesh

**Tailscale IS the transport AND the identity layer.**

Every FCP node:
- Has a stable Tailscale identity (unforgeable WireGuard keys)
- Can discover peers on the tailnet automatically
- Routes symbols through the optimal path (direct > relay)
- Maps zones to Tailscale ACL tags for defense-in-depth

```rust
/// Identity from Tailscale (NORMATIVE)
pub struct MeshIdentity {
    /// Tailscale node ID (stable across reconnects)
    pub node_id: TailscaleNodeId,

    /// Tailscale hostname
    pub hostname: String,

    /// Tailscale IPs (v4 and v6)
    pub ips: Vec<IpAddr>,

    /// ACL tags assigned to this node
    pub tags: Vec<String>,

    /// Device's owner key (for capability verification)
    pub owner_pubkey: Ed25519PublicKey,
}
```

### 2.3 Axiom 3: Explicit Authority

**No ambient authority. All capabilities flow from owner key through cryptographic chains.**

```rust
/// Authority chain (NORMATIVE)
pub enum AuthoritySource {
    /// Direct owner signature
    Owner(Signature),

    /// Delegated through capability chain
    Delegated {
        /// The capability granting this authority
        capability_id: ObjectId,
        /// Signature from capability holder
        signature: Signature,
        /// Chain back to owner (for verification)
        chain: Vec<ObjectId>,
    },
}

/// Every operation requires explicit authority
pub struct AuthorizedOperation {
    pub operation: OperationId,
    pub authority: AuthoritySource,
    pub constraints: OperationConstraints,
    pub expires_at: u64,
}
```

**The chain:**
```
Owner Key
    └── signs → Zone Keys
                    └── sign → Capability Objects
                                    └── authorize → Operations
```

---

## 3. Foundational Primitives

### 3.1 ObjectId

Content-addressed identifier binding content to zone and schema:

```rust
/// Content-addressed identifier (NORMATIVE)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Create ObjectId from content, zone, and schema
    pub fn new(content: &[u8], zone: &ZoneId, schema: &SchemaId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FCP2-OBJECT-V1");
        hasher.update(zone.as_bytes());
        hasher.update(schema.as_bytes());
        hasher.update(content);
        Self(hasher.finalize().into())
    }

    /// Quick creation from bytes only (for small objects)
    pub fn from_bytes(content: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FCP2-CONTENT-V1");
        hasher.update(content);
        Self(hasher.finalize().into())
    }
}
```

### 3.2 EpochId

Logical time unit for temporal binding:

```rust
/// Epoch identifier (NORMATIVE)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochId(u64);

impl EpochId {
    /// Create from Unix timestamp with configurable granularity
    pub fn from_timestamp(ts: u64, granularity_secs: u64) -> Self {
        Self(ts / granularity_secs)
    }

    /// Current epoch (default: 5-minute granularity)
    pub fn current() -> Self {
        Self::from_timestamp(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            300
        )
    }
}
```

**Ordering Semantics:**
- Events within the same epoch have NO defined order
- Events in different epochs are ordered by epoch
- This enables parallel processing and natural batching

### 3.3 SchemaId

Type identifier for objects:

```rust
/// Schema identifier (NORMATIVE)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SchemaId {
    /// Namespace (e.g., "fcp.core", "fcp.mesh")
    pub namespace: String,
    /// Type name (e.g., "CapabilityObject", "InvokeRequest")
    pub name: String,
    /// Version (semantic versioning)
    pub version: Version,
}

impl SchemaId {
    pub fn as_bytes(&self) -> Vec<u8> {
        format!("{}:{}@{}", self.namespace, self.name, self.version).into_bytes()
    }
}
```

### 3.4 ZoneId

Cryptographic namespace identifier:

```rust
/// Zone identifier (NORMATIVE)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ZoneId(String);

impl ZoneId {
    /// Standard zones (NORMATIVE)
    pub fn owner() -> Self { Self("z:owner".into()) }
    pub fn private() -> Self { Self("z:private".into()) }
    pub fn work() -> Self { Self("z:work".into()) }
    pub fn community() -> Self { Self("z:community".into()) }
    pub fn public() -> Self { Self("z:public".into()) }

    /// Map to Tailscale ACL tag
    pub fn to_tailscale_tag(&self) -> String {
        format!("tag:fcp-{}", self.0.strip_prefix("z:").unwrap_or(&self.0))
    }

    /// Create from Tailscale tag
    pub fn from_tailscale_tag(tag: &str) -> Option<Self> {
        tag.strip_prefix("tag:fcp-").map(|s| Self(format!("z:{}", s)))
    }
}
```

### 3.5 Canonical Serialization

Deterministic serialization for content addressing:

```rust
/// Canonical CBOR serialization (NORMATIVE)
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    /// Serialize to canonical CBOR (RFC 8949 deterministic encoding)
    pub fn serialize<T: Serialize>(value: &T, schema: &SchemaId) -> Vec<u8> {
        let mut buf = Vec::new();

        // Schema prefix for type binding
        buf.extend_from_slice(&(schema.as_bytes().len() as u16).to_le_bytes());
        buf.extend_from_slice(&schema.as_bytes());

        // Deterministic CBOR
        ciborium::ser::into_writer_canonical(value, &mut buf)
            .expect("Serialization cannot fail for valid types");

        buf
    }

    /// Deserialize with schema verification
    pub fn deserialize<T: DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        // Verify schema prefix
        let schema_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let schema_bytes = &data[2..2 + schema_len];

        if schema_bytes != expected_schema.as_bytes() {
            return Err(SerializationError::SchemaMismatch);
        }

        // Deserialize content
        ciborium::de::from_reader(&data[2 + schema_len..])
            .map_err(SerializationError::CborError)
    }
}
```

---

## 4. Symbol Layer

### 4.1 Symbol Envelope

The universal transmission unit with AEAD encryption:

```rust
/// Full symbol envelope with encryption (NORMATIVE)
pub struct SymbolEnvelope {
    /// Content address of complete object
    pub object_id: ObjectId,

    /// Encoding Symbol ID
    pub esi: u32,

    /// Source symbols needed (K)
    pub k: u16,

    /// Symbol payload (encrypted)
    pub data: Vec<u8>,

    /// Zone for key derivation
    pub zone_id: ZoneId,

    /// Epoch for replay protection
    pub epoch_id: EpochId,

    /// AEAD authentication tag
    pub auth_tag: [u8; 16],

    /// Nonce for encryption
    pub nonce: [u8; 12],
}

impl SymbolEnvelope {
    /// Encrypt symbol data with zone key
    pub fn encrypt(
        object_id: ObjectId,
        esi: u32,
        k: u16,
        plaintext: &[u8],
        zone_key: &ZoneKey,
        epoch: EpochId,
    ) -> Self {
        let nonce = generate_nonce();

        // Associated data binds symbol to context
        let aad = Self::build_aad(&object_id, esi, k, &zone_key.zone_id, epoch);

        let (ciphertext, auth_tag) = zone_key.encrypt(plaintext, &nonce, &aad);

        Self {
            object_id,
            esi,
            k,
            data: ciphertext,
            zone_id: zone_key.zone_id.clone(),
            epoch_id: epoch,
            auth_tag,
            nonce,
        }
    }

    /// Decrypt and verify symbol
    pub fn decrypt(&self, zone_key: &ZoneKey) -> Result<Vec<u8>, CryptoError> {
        let aad = Self::build_aad(
            &self.object_id,
            self.esi,
            self.k,
            &self.zone_id,
            self.epoch_id
        );

        zone_key.decrypt(&self.data, &self.nonce, &self.auth_tag, &aad)
    }

    fn build_aad(
        object_id: &ObjectId,
        esi: u32,
        k: u16,
        zone_id: &ZoneId,
        epoch: EpochId,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(object_id.as_bytes());
        aad.extend_from_slice(&esi.to_le_bytes());
        aad.extend_from_slice(&k.to_le_bytes());
        aad.extend_from_slice(zone_id.as_bytes());
        aad.extend_from_slice(&epoch.0.to_le_bytes());
        aad
    }
}
```

### 4.2 Signed Symbol Envelope

For source attribution and integrity:

```rust
/// Symbol with source signature (NORMATIVE)
pub struct SignedSymbolEnvelope {
    pub symbol: SymbolEnvelope,

    /// Source node identity
    pub source_id: TailscaleNodeId,

    /// Signature over symbol
    pub signature: Signature,

    /// Timestamp (for freshness)
    pub timestamp: u64,
}

impl SignedSymbolEnvelope {
    pub fn sign(symbol: SymbolEnvelope, identity: &MeshIdentity) -> Self {
        let timestamp = current_timestamp();
        let signature = identity.sign(&Self::signable_bytes(&symbol, timestamp));

        Self {
            symbol,
            source_id: identity.node_id.clone(),
            signature,
            timestamp,
        }
    }

    pub fn verify(&self, trusted_keys: &TrustAnchors) -> Result<(), VerifyError> {
        let pubkey = trusted_keys.get_node_key(&self.source_id)?;
        pubkey.verify(
            &Self::signable_bytes(&self.symbol, self.timestamp),
            &self.signature
        )
    }
}
```

### 4.3 FCPS Frame Format

Symbol-native frame format:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       FCPS FRAME FORMAT (Symbol-Native)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")                         │
│  Bytes 4-5:    Version (u16 LE)                                             │
│  Bytes 6-7:    Flags (u16 LE)                                               │
│  Bytes 8-11:   Symbol Count (u32 LE)                                        │
│  Bytes 12-15:  Total Payload Length (u32 LE)                                │
│  Bytes 16-47:  Object ID (32 bytes)                                         │
│  Bytes 48-63:  Zone ID hash (16 bytes, truncated SHA256)                    │
│  Bytes 64-71:  Epoch ID (u64 LE)                                            │
│  Bytes 72+:    Symbol payloads (concatenated)                               │
│  Final 8:      Checksum (XXH3-64)                                           │
│                                                                             │
│  Fixed header: 72 bytes                                                     │
│  Each symbol: 4 (ESI) + 2 (K) + N (data) + 16 (auth_tag) + 12 (nonce)      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.4 Frame Flags

```rust
bitflags! {
    pub struct FrameFlags: u16 {
        const REQUIRES_ACK      = 0b0000_0000_0001;  // Requires acknowledgment
        const COMPRESSED        = 0b0000_0000_0010;  // zstd compressed
        const ENCRYPTED         = 0b0000_0000_0100;  // Zone-encrypted symbols
        const RESPONSE          = 0b0000_0000_1000;  // Response to request
        const ERROR             = 0b0000_0001_0000;  // Error response
        const STREAMING         = 0b0000_0010_0000;  // Part of stream
        const STREAM_END        = 0b0000_0100_0000;  // Final frame in stream
        const HAS_CAP_TOKEN     = 0b0000_1000_0000;  // Contains capability token
        const ZONE_CROSSING     = 0b0001_0000_0000;  // Zone transition
        const PRIORITY          = 0b0010_0000_0000;  // High priority
        const RAPTORQ           = 0b0100_0000_0000;  // RaptorQ encoded (default)
        const CONTROL_PLANE     = 0b1000_0000_0000;  // Control plane object
    }
}
```

### 4.5 Multipath Symbol Delivery

Symbols flow through all available paths simultaneously:

```rust
/// Multipath delivery strategy (NORMATIVE)
pub struct MultipathDelivery {
    /// All available paths for symbol delivery
    paths: Vec<DeliveryPath>,

    /// Load balancing strategy
    strategy: LoadBalanceStrategy,
}

pub enum DeliveryPath {
    /// Direct Tailscale connection (lowest latency)
    TailscaleDirect { peer_ip: IpAddr },

    /// Tailscale via DERP relay
    TailscaleRelay { relay_id: u16 },

    /// Local network broadcast/multicast
    LocalNetwork { interface: String },

    /// Stored on peer (fetch on demand)
    PeerStorage { peer_id: TailscaleNodeId },
}

impl MultipathDelivery {
    /// Send symbols via all paths (receivers dedupe)
    pub async fn deliver(&self, symbols: Vec<SignedSymbolEnvelope>) -> DeliveryResult {
        let mut results = Vec::new();

        for (i, symbol) in symbols.iter().enumerate() {
            // Round-robin across paths
            let path = &self.paths[i % self.paths.len()];
            results.push(path.send(symbol.clone()).await);
        }

        DeliveryResult::from_results(results)
    }

    /// Receive from all paths (first K' symbols win)
    pub async fn receive(&self, object_id: ObjectId) -> Result<Vec<u8>, ReceiveError> {
        let mut decoder = RaptorQDecoder::new();

        // Listen on all paths concurrently
        let mut symbol_stream = self.listen_all_paths(object_id);

        while let Some(symbol) = symbol_stream.next().await {
            if let Some(data) = decoder.add_symbol(symbol)? {
                return Ok(data);
            }
        }

        Err(ReceiveError::InsufficientSymbols)
    }
}

---

## 5. Zone Architecture

### 5.1 Zone Hierarchy

Zones form a cryptographic trust hierarchy:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ZONE TRUST HIERARCHY                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   z:owner        [Trust: 100]  Direct owner control, most privileged        │
│       │                        Tailscale tag: tag:fcp-owner                 │
│       ▼                                                                     │
│   z:private      [Trust: 80]   Personal data, high sensitivity              │
│       │                        Tailscale tag: tag:fcp-private               │
│       ▼                                                                     │
│   z:work         [Trust: 60]   Professional context, medium sensitivity     │
│       │                        Tailscale tag: tag:fcp-work                  │
│       ▼                                                                     │
│   z:community    [Trust: 40]   Trusted external (paired users)              │
│       │                        Tailscale tag: tag:fcp-community             │
│       ▼                                                                     │
│   z:public       [Trust: 20]   Public/anonymous inputs                      │
│                                Tailscale tag: tag:fcp-public                │
│                                                                             │
│   INVARIANT: Data can flow DOWN (higher → lower trust) freely.              │
│              Data flowing UP requires explicit elevation + approval.        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Zone Definition

```rust
/// Zone with cryptographic properties (NORMATIVE)
pub struct Zone {
    /// Zone identifier
    pub id: ZoneId,

    /// Human-readable name
    pub name: String,

    /// Trust level (0-100)
    pub trust_level: u8,

    /// Zone encryption key (derived from owner key)
    pub zone_key: ZoneKey,

    /// Tailscale ACL tag
    pub tailscale_tag: String,

    /// Parent zone (for hierarchy)
    pub parent: Option<ZoneId>,

    /// Access policy
    pub policy: ZonePolicy,
}

/// Zone encryption key (NORMATIVE)
pub struct ZoneKey {
    pub zone_id: ZoneId,
    pub key_id: [u8; 8],
    pub symmetric_key: [u8; 32],  // ChaCha20-Poly1305
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl ZoneKey {
    /// Derive zone key from owner key and zone ID
    pub fn derive(owner_key: &Ed25519PrivateKey, zone_id: &ZoneId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FCP2-ZONE-KEY-V1");
        hasher.update(zone_id.as_bytes());
        hasher.update(owner_key.public_key().as_bytes());

        let key_material = hasher.finalize();

        Self {
            zone_id: zone_id.clone(),
            key_id: key_material[0..8].try_into().unwrap(),
            symmetric_key: key_material[8..40].try_into().unwrap(),
            created_at: current_timestamp(),
            expires_at: None,
        }
    }

    /// Encrypt data with this zone key
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let cipher = ChaCha20Poly1305::new(&self.symmetric_key.into());
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce.into(), aad, &mut ciphertext)
            .expect("Encryption cannot fail");
        (ciphertext, tag.into())
    }

    /// Decrypt data with this zone key
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(&self.symmetric_key.into());
        let mut plaintext = ciphertext.to_vec();
        cipher.decrypt_in_place_detached(nonce.into(), aad, &mut plaintext, tag.into())
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(plaintext)
    }
}
```

### 5.3 Zone Policy

```rust
/// Zone access policy (NORMATIVE)
pub struct ZonePolicy {
    /// Allowed principal patterns
    pub principals_allow: Vec<String>,

    /// Denied principal patterns (overrides allow)
    pub principals_deny: Vec<String>,

    /// Allowed connector patterns
    pub connectors_allow: Vec<String>,

    /// Denied connector patterns
    pub connectors_deny: Vec<String>,

    /// Allowed capability patterns
    pub cap_allow: Vec<String>,

    /// Denied capability patterns (overrides allow)
    pub cap_deny: Vec<String>,

    /// Default behavior when no rule matches
    pub default_deny: bool,
}

impl ZonePolicy {
    /// Evaluate access request
    pub fn evaluate(&self, request: &AccessRequest) -> PolicyDecision {
        // Step 1: Check principal
        if self.matches_any(&self.principals_deny, &request.principal) {
            return PolicyDecision::Deny("Principal denied by policy");
        }
        if !self.principals_allow.is_empty()
            && !self.matches_any(&self.principals_allow, &request.principal) {
            if self.default_deny {
                return PolicyDecision::Deny("Principal not in allow list");
            }
        }

        // Step 2: Check connector
        if self.matches_any(&self.connectors_deny, &request.connector) {
            return PolicyDecision::Deny("Connector denied by policy");
        }

        // Step 3: Check capability
        if self.matches_any(&self.cap_deny, &request.capability) {
            return PolicyDecision::Deny("Capability denied by policy");
        }
        if !self.cap_allow.is_empty()
            && !self.matches_any(&self.cap_allow, &request.capability) {
            if self.default_deny {
                return PolicyDecision::Deny("Capability not in allow list");
            }
        }

        PolicyDecision::Allow
    }
}
```

### 5.4 Zone-to-Tailscale ACL Mapping

```rust
/// Generate Tailscale ACL from zone policies (NORMATIVE)
pub struct AclGenerator {
    zones: Vec<Zone>,
}

impl AclGenerator {
    /// Generate Tailscale ACL JSON
    pub fn generate(&self) -> TailscaleAcl {
        let mut acl = TailscaleAcl::new();

        // Tag definitions
        for zone in &self.zones {
            acl.tag_owners.insert(
                zone.tailscale_tag.clone(),
                vec!["autogroup:admin".into()],
            );
        }

        // ACL rules: higher trust can access lower trust
        for zone in &self.zones {
            for target in &self.zones {
                if zone.trust_level >= target.trust_level {
                    acl.acls.push(AclRule {
                        action: "accept".into(),
                        src: vec![zone.tailscale_tag.clone()],
                        dst: vec![format!("{}:*", target.tailscale_tag)],
                    });
                }
            }
        }

        // Deny rules for explicit blocks
        for zone in &self.zones {
            for blocked in &zone.policy.connectors_deny {
                acl.acls.push(AclRule {
                    action: "deny".into(),
                    src: vec![zone.tailscale_tag.clone()],
                    dst: vec![blocked.clone()],
                });
            }
        }

        acl
    }
}
```

---

## 6. Provenance and Taint Tracking

### 6.1 Provenance Model

Every piece of data carries its origin:

```rust
/// Provenance tracking (NORMATIVE)
#[derive(Clone)]
pub struct Provenance {
    /// Origin zone
    pub origin_zone: ZoneId,

    /// Trust grade of origin
    pub origin_trust: TrustGrade,

    /// Principal who introduced the data
    pub origin_principal: Option<PrincipalId>,

    /// Taint level
    pub taint: TaintLevel,

    /// Crossed zones (audit trail)
    pub zone_crossings: Vec<ZoneCrossing>,

    /// Timestamp of creation
    pub created_at: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintLevel {
    /// No taint (owner-generated)
    Untainted = 0,

    /// Mild taint (trusted external)
    Tainted = 1,

    /// Heavy taint (public/anonymous)
    HighlyTainted = 2,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustGrade {
    /// Direct owner access
    Owner,
    /// Cryptographically paired device
    Paired,
    /// Trusted remote (known identity)
    TrustedRemote,
    /// Untrusted (anonymous/public)
    Untrusted,
}

#[derive(Clone)]
pub struct ZoneCrossing {
    pub from_zone: ZoneId,
    pub to_zone: ZoneId,
    pub crossed_at: u64,
    pub authorized_by: Option<ObjectId>,  // Elevation token if applicable
}
```

### 6.2 Taint Propagation Rules

```rust
impl Provenance {
    /// Compute taint when crossing zones
    pub fn cross_zone(&self, target: &Zone) -> Self {
        let mut new = self.clone();

        // Record crossing
        new.zone_crossings.push(ZoneCrossing {
            from_zone: self.origin_zone.clone(),
            to_zone: target.id.clone(),
            crossed_at: current_timestamp(),
            authorized_by: None,
        });

        // Taint increases when moving to higher-trust zone
        if target.trust_level > self.origin_trust.to_level() {
            new.taint = TaintLevel::max(new.taint, TaintLevel::Tainted);
        }

        new
    }

    /// Check if operation is allowed given taint
    pub fn can_invoke(&self, operation: &Operation, target_zone: &Zone) -> TaintDecision {
        // Rule 1: Untainted can do anything
        if self.taint == TaintLevel::Untainted {
            return TaintDecision::Allow;
        }

        // Rule 2: HighlyTainted cannot invoke dangerous operations
        if self.taint == TaintLevel::HighlyTainted
            && operation.safety_tier >= SafetyTier::Dangerous {
            return TaintDecision::Deny("Highly tainted origin cannot invoke dangerous operations");
        }

        // Rule 3: Tainted invoking risky in higher-trust zone needs elevation
        if self.taint >= TaintLevel::Tainted
            && operation.safety_tier >= SafetyTier::Risky
            && target_zone.trust_level > self.origin_trust.to_level() {
            return TaintDecision::RequireElevation;
        }

        TaintDecision::Allow
    }
}
```

### 6.3 Elevation Protocol

```rust
/// Elevation token for tainted operations (NORMATIVE)
pub struct ElevationToken {
    /// Token identifier
    pub token_id: ObjectId,

    /// What operation is elevated
    pub operation: OperationId,

    /// Original provenance
    pub original_provenance: Provenance,

    /// Who approved the elevation
    pub approved_by: PrincipalId,

    /// Approval timestamp
    pub approved_at: u64,

    /// Token expiry
    pub expires_at: u64,

    /// Signature from approver
    pub signature: Signature,
}

impl ElevationToken {
    /// Default TTL: 5 minutes
    pub const DEFAULT_TTL_SECS: u64 = 300;

    /// Create elevation token
    pub fn create(
        operation: OperationId,
        provenance: &Provenance,
        approver: &Identity,
        ttl: Option<u64>,
    ) -> Self {
        let now = current_timestamp();
        let expires_at = now + ttl.unwrap_or(Self::DEFAULT_TTL_SECS);

        let mut token = Self {
            token_id: ObjectId::default(),  // Will be set after signing
            operation,
            original_provenance: provenance.clone(),
            approved_by: approver.principal_id(),
            approved_at: now,
            expires_at,
            signature: Signature::default(),
        };

        // Sign and compute ID
        let signable = token.signable_bytes();
        token.signature = approver.sign(&signable);
        token.token_id = ObjectId::from_bytes(&signable);

        token
    }

    /// Verify token is valid
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), VerifyError> {
        // Check expiry
        if current_timestamp() > self.expires_at {
            return Err(VerifyError::Expired);
        }

        // Verify approver authority
        let approver_key = trust_anchors.get_principal_key(&self.approved_by)?;
        approver_key.verify(&self.signable_bytes(), &self.signature)?;

        // Verify approver has elevation authority
        if !trust_anchors.can_approve_elevation(&self.approved_by) {
            return Err(VerifyError::InsufficientAuthority);
        }

        Ok(())
    }
}
```

---

## 7. Capability System

### 7.1 Capability Taxonomy

FCP defines a hierarchical capability namespace:

```
fcp.*                    Protocol/meta operations
├── fcp.connect          Establish connection
├── fcp.handshake        Complete handshake
└── fcp.introspect       Query capabilities

network.*                Network operations
├── network.outbound:*   Outbound connections (host:port)
├── network.inbound:*    Listen for connections
└── network.dns          DNS resolution

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

### 7.2 Capability Definition

```rust
/// Capability definition (NORMATIVE)
pub struct Capability {
    /// Capability identifier (e.g., "telegram.send_message")
    pub id: CapabilityId,

    /// Human-readable name
    pub name: String,

    /// Detailed description
    pub description: String,

    /// Risk level (for UI/triage)
    pub risk_level: RiskLevel,

    /// Safety tier (for enforcement)
    pub safety_tier: SafetyTier,

    /// Parent capability (hierarchy)
    pub parent: Option<CapabilityId>,

    /// Implied capabilities (auto-granted)
    pub implies: Vec<CapabilityId>,

    /// Mutually exclusive capabilities
    pub conflicts_with: Vec<CapabilityId>,

    /// Idempotency expectation
    pub idempotency: IdempotencyClass,

    /// Rate limit
    pub rate_limit: Option<RateLimit>,

    /// Requires human approval
    pub requires_approval: ApprovalMode,

    /// Audit level when used
    pub audit_level: AuditLevel,

    /// Agent documentation
    pub agent_hint: AgentHint,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyTier {
    /// Read-only or non-sensitive
    Safe = 0,
    /// Private data exposure or public posting
    Risky = 1,
    /// Destructive or high-blast actions
    Dangerous = 2,
    /// Never allowed
    Forbidden = 3,
}

#[derive(Clone, Copy)]
pub enum IdempotencyClass {
    /// Duplicates may cause repeated side effects
    None,
    /// Connector attempts dedupe within a short window
    BestEffort,
    /// Connector MUST enforce dedupe using idempotency_key
    Strict,
}

#[derive(Clone, Copy)]
pub enum ApprovalMode {
    /// No approval needed
    None,
    /// Policy-based auto-approval
    Policy,
    /// Interactive human approval
    Interactive,
    /// Requires elevation token
    ElevationToken,
}

pub struct AgentHint {
    /// When should an agent use this capability?
    pub when_to_use: String,
    /// Common mistakes to avoid
    pub common_mistakes: Vec<String>,
    /// Example usage
    pub examples: Vec<String>,
    /// Related capabilities
    pub related: Vec<CapabilityId>,
}
```

### 7.3 Capability Object (Mesh-Native)

```rust
/// Capability as distributed object (NORMATIVE)
pub struct CapabilityObject {
    pub header: ObjectHeader,

    /// Capability being granted
    pub capability_id: CapabilityId,

    /// Who can use this capability
    pub grantee: Grantee,

    /// Constraints on use
    pub constraints: CapabilityConstraints,

    /// Placement policy (where can this execute?)
    pub placement: PlacementPolicy,

    /// Valid time range
    pub valid_from: u64,
    pub valid_until: u64,

    /// Signature from issuer
    pub signature: Signature,
}

pub enum Grantee {
    /// Specific principal
    Principal(PrincipalId),
    /// Any principal in zone
    Zone(ZoneId),
    /// Any principal with specific tag
    Tag(String),
    /// Bearer (whoever has the capability)
    Bearer,
}

pub struct CapabilityConstraints {
    /// Allowed resource URI prefixes
    pub resource_allow: Vec<String>,
    /// Denied resource URI prefixes
    pub resource_deny: Vec<String>,
    /// Maximum calls within validity period
    pub max_calls: Option<u32>,
    /// Maximum bytes (request + response)
    pub max_bytes: Option<u64>,
    /// Idempotency key scope
    pub idempotency_scope: Option<String>,
}
```

### 7.4 Placement Policy

```rust
/// Where can this capability execute? (NORMATIVE)
pub struct PlacementPolicy {
    /// Required device capabilities
    pub requires: Vec<DeviceRequirement>,

    /// Preferred device characteristics
    pub prefers: Vec<DevicePreference>,

    /// Devices that MUST NOT execute this
    pub excludes: Vec<DevicePattern>,

    /// Zone restrictions
    pub zones: Vec<ZoneId>,
}

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
}

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

### 7.5 Capability Token (FCT)

Short-lived token for operation invocation:

```rust
/// Capability Token for operation invocation (NORMATIVE)
pub struct CapabilityToken {
    /// Unique token identifier
    pub jti: Uuid,

    /// Principal identifier
    pub sub: PrincipalId,

    /// Issuing zone
    pub iss: ZoneId,

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

    /// Ed25519 signature
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

    /// Verify token validity
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), TokenError> {
        // Check expiry
        if current_timestamp() > self.exp {
            return Err(TokenError::Expired);
        }

        // Verify signature
        let issuer_key = trust_anchors.get_zone_key(&self.iss)?;
        issuer_key.verify(&self.signable_bytes(), &self.sig)?;

        Ok(())
    }
}
```

---

## 8. Mesh Architecture

### 8.1 MeshNode

Every device is a MeshNode—the distributed Hub:

```rust
/// Mesh node - every device IS the Hub (NORMATIVE)
pub struct MeshNode {
    /// This node's identity
    pub identity: MeshIdentity,

    /// Known peers on the tailnet
    pub peers: RwLock<HashMap<TailscaleNodeId, FcpPeer>>,

    /// Local symbol storage
    pub symbol_store: SymbolStore,

    /// Gossip layer for discovery
    pub gossip: MeshGossip,

    /// Capability registry
    pub capabilities: CapabilityRegistry,

    /// Zone keys (for encryption/decryption)
    pub zone_keys: HashMap<ZoneId, ZoneKey>,

    /// Trust anchors (owner key, known keys)
    pub trust_anchors: TrustAnchors,

    /// Tailscale client
    pub tailscale: TailscaleClient,
}

impl MeshNode {
    /// Handle incoming symbol frame
    pub async fn handle_symbols(&self, frame: FcpsFrame) -> Result<()> {
        // Verify frame integrity
        frame.verify_checksum()?;

        // Decrypt and store symbols
        let zone_key = self.zone_keys.get(&frame.zone_id)
            .ok_or(Error::UnknownZone)?;

        for symbol in frame.symbols {
            let envelope = symbol.decrypt(zone_key)?;
            self.symbol_store.store(envelope).await?;

            // Gossip symbol availability
            self.gossip.announce_symbol(&symbol.object_id, symbol.esi).await;
        }

        Ok(())
    }

    /// Invoke a capability
    pub async fn invoke(&self, request: InvokeRequest) -> Result<ResponseObject> {
        // 1. Verify capability token
        request.token.verify(&self.trust_anchors)?;

        // 2. Check provenance/taint
        let decision = request.provenance.can_invoke(
            &request.operation,
            self.get_zone(&request.token.iss)?,
        );
        match decision {
            TaintDecision::Deny(reason) => return Err(Error::TaintViolation(reason)),
            TaintDecision::RequireElevation => {
                if request.elevation_token.is_none() {
                    return Err(Error::ElevationRequired);
                }
                request.elevation_token.as_ref().unwrap().verify(&self.trust_anchors)?;
            }
            TaintDecision::Allow => {}
        }

        // 3. Find best device for execution
        let target = self.find_execution_target(&request).await?;

        // 4. Execute or delegate
        if target.node_id == self.identity.node_id {
            self.execute_locally(request).await
        } else {
            self.delegate_to_peer(&target, request).await
        }
    }
}
```

### 8.2 Gossip Layer

Efficient discovery without flooding:

```rust
/// Gossip layer for symbol and object discovery (NORMATIVE)
pub struct MeshGossip {
    /// Bloom filter of known object IDs
    pub object_filter: BloomFilter,

    /// Bloom filter of available symbols
    pub symbol_filter: BloomFilter,

    /// Vector clock for consistency
    pub vector_clock: VectorClock,

    /// Known peer states
    pub peer_states: HashMap<TailscaleNodeId, PeerGossipState>,
}

impl MeshGossip {
    /// Announce local symbol availability
    pub async fn announce_symbol(&mut self, object_id: &ObjectId, esi: u32) {
        self.object_filter.insert(object_id.as_bytes());
        self.symbol_filter.insert(&symbol_key(object_id, esi));
        self.vector_clock.increment_local();
    }

    /// Find peers that might have symbols for an object
    pub fn find_symbol_sources(&self, object_id: &ObjectId) -> Vec<TailscaleNodeId> {
        self.peer_states
            .iter()
            .filter(|(_, state)| state.object_filter.might_contain(object_id.as_bytes()))
            .map(|(id, _)| id.clone())
            .collect()
    }
}
```

### 8.3 DistributedState

State IS symbol distribution:

```rust
/// State is symbol distribution (NORMATIVE)
pub struct DistributedState {
    /// Object ID for this state
    pub object_id: ObjectId,

    /// Current symbol distribution
    pub distribution: SymbolDistribution,

    /// Minimum coverage for availability
    pub min_coverage: f64,
}

impl DistributedState {
    /// Current availability
    pub fn coverage(&self) -> f64 {
        let available: HashSet<u32> = self.distribution.node_symbols
            .values()
            .flatten()
            .cloned()
            .collect();
        available.len() as f64 / self.distribution.k as f64
    }

    /// Is state reconstructable?
    pub fn is_available(&self) -> bool {
        self.coverage() >= 1.0
    }
}
```

---

## 9. Wire Protocol

### 9.1 Protocol Modes

FCP V2 supports two protocol modes:

| Mode | Encoding | Use Case |
|------|----------|----------|
| **FCP2-SYM (Canonical)** | FCPS frames + RaptorQ | Production mesh-native |
| **FCP1 (Compatibility)** | CBOR/JSON-RPC frames | Legacy connectors |

### 9.2 Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `handshake` | Hub → Connector | Establish connection |
| `handshake_ack` | Connector → Hub | Confirm connection |
| `introspect` | Hub → Connector | Query operations |
| `configure` | Hub → Connector | Apply configuration |
| `invoke` | Hub → Connector | Execute operation |
| `response` | Connector → Hub | Operation result |
| `subscribe` | Hub → Connector | Subscribe to events |
| `event` | Connector → Hub | Async event |
| `health` | Hub ↔ Connector | Health check |
| `shutdown` | Hub → Connector | Graceful shutdown |
| `symbol_request` | Any → Any | Request symbols (mesh) |
| `symbol_delivery` | Any → Any | Deliver symbols (mesh) |

### 9.3 Invoke Request/Response

```rust
/// Invoke request (NORMATIVE)
pub struct InvokeRequest {
    pub id: String,
    pub operation: OperationId,
    pub input: Value,
    pub capability_token: CapabilityToken,
    pub provenance: Provenance,
    pub elevation_token: Option<ElevationToken>,
    pub idempotency_key: Option<String>,
}

/// Invoke response (NORMATIVE)
pub struct InvokeResponse {
    pub id: String,
    pub result: Value,
    pub resource_uris: Vec<String>,
    pub next_cursor: Option<String>,
}
```

### 9.4 Event Streaming

Events are batched into epochs for RaptorQ encoding:

```rust
/// Event envelope (NORMATIVE)
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

## 10. Connector Model

### 10.1 Connector Architecture

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
```

### 10.2 Connector Lifecycle

```
DISCOVERED → VERIFIED → INSTALLED → CONFIGURED → ACTIVE
         ↘ rejected                          ↘ FAILED
                                              ↘ PAUSED
                                              ↘ STOPPED
```

### 10.3 Standard Methods

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

---

## 11. Connector Manifest

### 11.1 Manifest Structure

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

[zones]
home = "z:community"
allowed_sources = ["z:owner", "z:private", "z:work", "z:community"]
allowed_targets = ["z:community"]
forbidden = ["z:public"]

[capabilities]
required = [
  "ipc.gateway",
  "network.outbound:api.telegram.org:443",
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

[provides.operations.telegram_send_message.ai_hints]
when_to_use = "Use to post updates to approved chats."
common_mistakes = ["Sending secrets", "Responding to tainted inputs"]

[event_caps]
streaming = true
replay = true
min_buffer_events = 10000

[signatures]
publisher_ed25519 = "base64:..."
registry_ed25519 = "base64:..."
```

### 11.2 Manifest Embedding

Manifests MUST be extractable without execution:
- ELF: `.fcp_manifest` section
- Mach-O: `__FCP,__manifest` segment
- PE: `.fcpmanifest` section

---

## 12. Automation Recipes

### 12.1 Recipe Model

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

### 12.2 Provisioning Interface

| Operation | Purpose |
|-----------|---------|
| `fcp.provision.start` | Begin auth flow |
| `fcp.provision.poll` | Check status |
| `fcp.provision.complete` | Finalize credentials |
| `fcp.provision.abort` | Cancel and cleanup |

---

## 13. Registry and Supply Chain

### 13.1 Registry Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    PRIMARY REGISTRY                        │
│                  registry.flywheel.dev                     │
│  ├── Git-backed manifest index                            │
│  ├── Binary storage (S3-compatible)                       │
│  ├── Signature verifier                                   │
│  ├── Reproducible build attestor                          │
│  └── CDN (global edge)                                    │
└───────────────────────────────────────────────────────────┘
```

### 13.2 Verification Chain

Before execution, verify:
1. Manifest signature (registry or trusted publisher)
2. Binary checksum matches manifest
3. Binary signature matches trusted key
4. Platform/arch match
5. Requested capabilities ⊆ zone ceilings

---

## 14. Lifecycle Management

### 14.1 Activation Requirements

On activation:
1. Create sandbox
2. Inject secrets ephemerally
3. Negotiate handshake
4. Issue capability tokens
5. Start health checks

### 14.2 Updates and Rollback

- Staged updates
- Automatic rollback on crash loops
- Explicit pinning to known-good versions

---

## 15. Device-Aware Execution

### 15.1 Device Profiles

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
```

### 15.2 Execution Planner

```rust
/// Execution planner (NORMATIVE)
pub struct ExecutionPlanner {
    pub devices: Vec<DeviceProfile>,
}

impl ExecutionPlanner {
    /// Find best device for capability
    pub fn plan(&self, capability: &MeshCapability) -> Option<TailscaleNodeId> {
        let mut candidates: Vec<_> = self.devices.iter()
            .filter(|d| self.satisfies_requirements(d, &capability.placement))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Score and sort by preference
        candidates.sort_by(|a, b| {
            let score_a = self.score_device(a, &capability.placement);
            let score_b = self.score_device(b, &capability.placement);
            score_b.partial_cmp(&score_a).unwrap()
        });

        Some(candidates[0].node_id.clone())
    }

    fn score_device(&self, device: &DeviceProfile, policy: &PlacementPolicy) -> f64 {
        let mut score = 0.0;
        for pref in &policy.prefers {
            match pref {
                DevicePreference::LowLatency { max_ms, weight } => {
                    if let Some(latency) = device.current_state.latency_ms {
                        if latency <= *max_ms {
                            score += weight;
                        }
                    }
                }
                DevicePreference::HighResources { weight } => {
                    score += weight * (device.capabilities.memory_mb as f64 / 16000.0);
                }
                _ => {}
            }
        }
        score
    }
}
```

---

## 16. Computation Migration

### 16.1 Migratable Computation

```rust
/// Computation that can move between devices (NORMATIVE)
pub struct MigratableComputation {
    pub computation_id: ObjectId,
    pub capability: MeshCapability,
    pub state: ComputationState,
    pub current_device: TailscaleNodeId,
}

pub enum ComputationState {
    Running { progress: f64 },
    Suspended { checkpoint: ObjectId },
    Completed { result: ObjectId },
    Failed { error: String },
}
```

### 16.2 Migration Protocol

```rust
impl MigratableComputation {
    pub async fn migrate(&mut self, target: TailscaleNodeId, mesh: &MeshNode) -> Result<()> {
        // 1. Checkpoint current state
        let checkpoint = self.checkpoint().await?;

        // 2. Distribute checkpoint as symbols
        mesh.distribute_object(checkpoint.clone()).await?;

        // 3. Notify target device
        mesh.send_migration_request(&target, self.computation_id, checkpoint.id).await?;

        // 4. Target reconstructs and resumes
        self.current_device = target;
        self.state = ComputationState::Running { progress: checkpoint.progress };

        Ok(())
    }
}
```

---

## 17. Security Model

### 17.1 Defense-in-Depth

```
Layer 1: Tailscale ACLs     → Network-level isolation
Layer 2: Zone Encryption    → Cryptographic isolation
Layer 3: Policy Objects     → Authority isolation
Layer 4: Capability Signing → Operation isolation
```

### 17.2 Source Diversity

Critical objects require symbols from multiple sources:

```rust
/// Source diversity policy (NORMATIVE)
pub struct DiversityPolicy {
    pub min_nodes: u8,
    pub min_zones: u8,
    pub max_node_fraction: f64,
}

impl DiversityPolicy {
    pub fn verify(&self, symbols: &[SignedSymbolEnvelope]) -> Result<()> {
        let nodes: HashSet<_> = symbols.iter().map(|s| &s.source_id).collect();
        if nodes.len() < self.min_nodes as usize {
            return Err(Error::InsufficientNodeDiversity);
        }
        Ok(())
    }
}
```

### 17.3 Threshold Secrets

Secrets distributed as k-of-n symbols:

```rust
/// Threshold secret (NORMATIVE)
pub struct ThresholdSecret {
    pub secret_id: SecretId,
    pub k: u8,  // Need k symbols
    pub n: u8,  // Distributed across n devices
    pub distribution: HashMap<TailscaleNodeId, SymbolId>,
}

impl ThresholdSecret {
    /// Use secret ephemerally
    pub async fn use_secret<F, R>(&self, f: F) -> Result<R>
    where F: FnOnce(&[u8]) -> R
    {
        let symbols = self.collect_k_symbols().await?;
        let secret = reconstruct_secure(&symbols)?;
        let result = f(&secret);
        secure_zero(secret);
        Ok(result)
    }
}
```

---

## 18. Trust Model and Byzantine Assumptions

### 18.1 Threat Model

**Trusted:**
- Tailscale identity (WireGuard keys unforgeable)
- Cryptographic primitives
- Owner's root key

**Assumed possible (defend against):**
- Compromised device
- Malicious peer
- Symbol injection
- Replay attacks
- Denial of service

### 18.2 Byzantine Fault Tolerance

```rust
/// Byzantine model (NORMATIVE)
pub struct ByzantineModel {
    pub n: u8,  // Total devices
    pub f: u8,  // Max compromised
}

impl ByzantineModel {
    /// Invariant: f < n/3 for safety
    pub fn is_safe(&self) -> bool {
        3 * self.f < self.n
    }
}

pub enum OperationClass {
    ReadOnly,       // Single device sufficient
    NormalWrite,    // Quorum: (n + f + 1) / 2
    CriticalWrite,  // Quorum: n - f
    Unanimous,      // All devices
}
```

---

## 19. Tailscale Integration

### 19.1 Tailscale Client

```rust
/// Tailscale local API client (NORMATIVE)
pub struct TailscaleClient {
    socket_path: PathBuf,
}

impl TailscaleClient {
    pub async fn status(&self) -> Result<TailscaleStatus> {
        self.get("/localapi/v0/status").await
    }

    pub async fn peers(&self) -> Result<Vec<TailscalePeer>> {
        let status = self.status().await?;
        Ok(status.peer.into_values().collect())
    }

    pub async fn whois(&self, ip: IpAddr) -> Result<NodeIdentity> {
        self.get(&format!("/localapi/v0/whois?addr={}", ip)).await
    }
}
```

### 19.2 Symbol Routing

```rust
/// Route symbols across Tailscale mesh (NORMATIVE)
pub struct TailscaleSymbolRouter {
    client: TailscaleClient,
    peers: RwLock<HashMap<String, FcpPeer>>,
}

impl TailscaleSymbolRouter {
    /// Distribute symbols with zone awareness
    pub async fn distribute(
        &self,
        object_id: ObjectId,
        symbols: Vec<EncodedSymbol>,
        zone: &ZoneId,
    ) -> Result<SymbolDistribution> {
        let peers = self.peers.read().await;
        let eligible: Vec<_> = peers.values()
            .filter(|p| self.can_store_for_zone(p, zone))
            .collect();

        // Round-robin distribution
        let mut distribution = SymbolDistribution::new(object_id);
        for (i, symbol) in symbols.into_iter().enumerate() {
            let target_idx = i % (eligible.len() + 1);
            if target_idx == 0 {
                self.local_store.store(symbol).await?;
            } else {
                self.send_to_peer(&eligible[target_idx - 1], symbol).await?;
            }
        }

        Ok(distribution)
    }
}
```

### 19.3 Funnel Gateway

```rust
/// Public ingress via Tailscale Funnel (NORMATIVE)
pub struct FunnelGateway {
    client: TailscaleClient,
    policy: FunnelPolicy,
}

pub struct FunnelPolicy {
    pub allowed_zones: Vec<ZoneId>,  // Typically z:public, z:community
    pub blocked_zones: Vec<ZoneId>,  // z:owner, z:private
    pub rate_limit_per_minute: u32,
}
```

---

## 20. RaptorQ Deep Integration

### 20.1 Epoch-Based Event Buffer

```rust
/// Epoch-based RaptorQ event buffer (NORMATIVE)
pub struct RaptorQEventBuffer {
    epoch_duration: Duration,
    current_epoch: RwLock<EpochWriter>,
    finalized_epochs: RwLock<HashMap<u64, EpochMetadata>>,
}

impl RaptorQEventBuffer {
    pub async fn finalize_epoch(&self) -> Result<()> {
        let epoch = self.current_epoch.write().await.take();
        let events_cbor = CanonicalSerializer::serialize(&epoch.events);
        let object_id = ObjectId::from_bytes(&events_cbor);

        // Encode to symbols and distribute
        let encoder = RaptorQEncoder::new(&events_cbor, SYMBOL_SIZE);
        let symbols: Vec<_> = encoder.get_encoded_packets(REPAIR_RATIO).collect();

        // Distribute symbols across peers
        self.distribute_symbols(epoch.id, symbols).await
    }
}
```

### 20.2 Connector Binary Distribution

Benefits of RaptorQ for updates:
- Parallel download from CDN + P2P + multicast
- No specific symbols required
- Resumable without bookmarks
- DoS resistant

---

## 21. Offline Access

### 21.1 Offline Capability

```rust
/// Offline capability (NORMATIVE)
pub struct OfflineCapability {
    pub accessible: HashMap<ObjectId, OfflineAccess>,
}

pub struct OfflineAccess {
    pub object_id: ObjectId,
    pub local_symbols: usize,
    pub k: usize,
}

impl OfflineAccess {
    pub fn can_access(&self) -> bool {
        self.local_symbols >= self.k
    }

    pub fn coverage(&self) -> f64 {
        self.local_symbols as f64 / self.k as f64
    }
}
```

### 21.2 Predictive Pre-staging

Based on user patterns, pre-stage symbols before needed.

---

## 22. Agent Integration

### 22.1 Introspection

Agents MUST be able to query:
- Operations (schemas, risk levels)
- Approval requirements
- Rate limits
- Recovery hints

### 22.2 MCP Integration

Map connector operations to MCP-compatible tools:
- Schemas
- Risk annotations
- Examples
- Rate limits

---

## 23. Observability and Audit

### 23.1 Metrics

Required metrics:
- Request counts, latencies, error rates
- Resource usage
- Rate-limit denials
- Zone/taint denials

### 23.2 Structured Logs

Logs MUST:
- Be structured (JSON)
- Redact secrets
- Include correlation_id, zone_id, connector_id

### 23.3 Audit Events

Record for:
- Secret access
- High-risk capability use
- Approvals/elevations
- Zone transitions
- Security violations

---

## 24. Error Taxonomy

### 24.1 Error Code Ranges

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

### 24.2 Error Response

```rust
pub struct FcpError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub details: Option<Value>,
    pub ai_recovery_hint: Option<String>,
}
```

---

## 25. Implementation Phases

### Phase 1: Core Mesh (MVP)

- MeshNode with Tailscale discovery
- Symbol request/delivery
- Basic zone isolation
- RaptorQ for objects > 1KB

### Phase 2: Events and Lifecycle

- Epoch-based event streaming
- RevocationObject
- Garbage collection
- Basic audit chain

### Phase 3: Full Security Model

- Full PolicyObject
- Quorum-signed audit heads
- Threshold secrets
- Source diversity enforcement
- Device loss response

---

## 26. Compatibility and Migration

### 26.1 FCP1 Compatibility

```rust
/// Hybrid translator (NORMATIVE)
pub struct HybridTranslator {
    pub peer_protocol: ProtocolVersion,
}

impl HybridTranslator {
    pub fn translate_outgoing(&self, msg: MeshObject) -> OutgoingFrame {
        match self.peer_protocol {
            ProtocolVersion::Fcp1 => self.to_json_rpc(msg),
            ProtocolVersion::Fcp2Sym => self.to_symbol_frame(msg),
        }
    }
}
```

### 26.2 Migration Path

```
Step 1: Add Tailscale to all nodes
Step 2: Deploy MeshNode alongside Hub
Step 3: Enable hybrid mode
Step 4: Migrate capabilities
Step 5: Enable zone encryption
Step 6: Disable FCP1 endpoints
```

---

## 27. Conformance Requirements

### 27.1 Mandatory Tests

1. Canonical serialization
2. ObjectId derivation
3. Symbol encoding/reconstruction
4. Signature verification
5. Revocation checking
6. Source diversity
7. Epoch ordering

### 27.2 Interop Tests

1. Handshake negotiation
2. Symbol exchange
3. Object reconstruction
4. Capability verification
5. Cross-zone bridging

---

## Appendix A: FZPF v0.1 JSON Schema

See FCP_Specification_V1.md Appendix I for the complete FZPF JSON Schema.

---

## Appendix B: RaptorQ Configuration

```rust
pub struct RaptorQConfig {
    pub symbol_size: u16,        // Default: 1024
    pub repair_ratio: f32,       // Default: 0.05
    pub max_object_size: u32,    // Default: 64MB
    pub decode_timeout: Duration, // Default: 30s
}
```

---

## Appendix C: Reference Connector Patterns

| Pattern | Description | Examples |
|---------|-------------|----------|
| Unified Messaging | Maps channels to zones | Telegram, Discord |
| Workspace | Local caching, write gating | Gmail, Calendar |
| Knowledge | Filesystem watch + search | Obsidian, Notion |
| DevOps | Typed CLI wrappers | gh, kubectl |

---

## Appendix D: SDK Crates

| Crate | Purpose |
|-------|---------|
| `fcp-core` | Core types, traits |
| `fcp-sdk` | Connector development |
| `fcp-mesh` | Mesh implementation |
| `fcp-raptorq` | RaptorQ integration |
| `fcp-tailscale` | Tailscale integration |
| `fcp-cli` | Command-line tools |

---

## Appendix E: Conformance Checklist

**Connector MUST:**
- [ ] Implement `--manifest` flag
- [ ] Implement standard methods
- [ ] Support event cursors + replay
- [ ] Declare capabilities
- [ ] Validate inputs
- [ ] Never log secrets
- [ ] Include AI hints

**MeshNode MUST:**
- [ ] Verify signatures before execution
- [ ] Enforce zones, capabilities, taint
- [ ] Provide audit events
- [ ] Support symbol routing
- [ ] Implement gossip layer

---

## Appendix F: Golden Decision Test Vectors

See FCP_Specification_V1.md Appendix J for test vectors.

---

## Appendix G: Transport Priority

```
Priority 1: Tailscale Direct (same LAN)     - <1ms, z:owner OK
Priority 2: Tailscale Mesh (NAT traversal)  - 10-100ms, z:owner OK
Priority 3: Tailscale DERP Relay            - 50-200ms, z:private and below
Priority 4: Tailscale Funnel (public)       - Variable, z:community/public only
```

---

## Summary

FCP V2 transforms the protocol from hub-spoke to mesh-native:

| Traditional FCP | Mesh-Native FCP |
|-----------------|-----------------|
| Hub process | Mesh IS the Hub |
| Connectors on machines | Capabilities anywhere |
| Sessions on nodes | Mesh-wide contexts |
| Storage on devices | Symbol distribution |
| Offline = no access | Offline = reduced probability |
| Secrets on devices | Threshold secrets (k-of-n) |

**The Vision:** Your personal AI runs on YOUR devices. Your data exists as symbols across YOUR mesh. This is **digital sovereignty**.


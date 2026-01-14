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

    /// Owner root public key (trust anchor)
    pub owner_pubkey: Ed25519PublicKey,

    /// Node signing public key (used for SignedFcpsFrame, gossip auth, receipts)
    pub node_sig_pubkey: Ed25519PublicKey,

    /// Node encryption public key (X25519) for wrapping zone keys + secret shares
    pub node_enc_pubkey: X25519PublicKey,

    /// Node issuance public key (Ed25519) used ONLY for minting capability tokens
    pub node_iss_pubkey: Ed25519PublicKey,

    /// Owner-signed attestation binding node_id ↔ node_sig_pubkey ↔ tags
    pub node_attestation: NodeKeyAttestation,
}

/// Owner-signed binding of node identity to a signing key (NORMATIVE)
pub struct NodeKeyAttestation {
    /// Tailscale node being attested
    pub node_id: TailscaleNodeId,
    /// Node's signing public key
    pub node_sig_pubkey: Ed25519PublicKey,
    /// Node's encryption public key (X25519) for sealed key distribution
    pub node_enc_pubkey: X25519PublicKey,
    /// Node's issuance public key for capability token minting
    pub node_iss_pubkey: Ed25519PublicKey,
    /// Authorized ACL tags for this node
    pub tags: Vec<String>,
    /// When attestation was issued
    pub issued_at: u64,
    /// Optional expiry (None = no expiry)
    pub expires_at: Option<u64>,
    /// Owner signature (may be produced via threshold signing; verifiable with owner_pubkey)
    pub signature: Signature,
}

#### 2.2.1 Threshold Owner Signing (RECOMMENDED)

Owner signatures are standard Ed25519 signatures verifiable with `owner_pubkey`. The mechanism used to *produce* the signature MAY be threshold.

Implementations SHOULD support a threshold signing mode (e.g., FROST for Ed25519) where k-of-n devices contribute partial signatures and no device ever holds the complete owner private key.

**Why this matters:**
- **Catastrophic compromise resistance:** 1 compromised device ≠ owner compromise.
- **Loss tolerance:** you can lose devices and still sign revocations/rotations.
- **Incident response coherence:** "remove device → rotate shares" becomes a first-class flow.

```rust
pub struct OwnerKeyPolicy {
    pub scheme: OwnerKeyScheme,
    pub threshold_k: u8,
    pub total_n: u8,
    pub participants: Vec<TailscaleNodeId>,
    pub max_skew_secs: u64,
}

pub enum OwnerKeyScheme {
    /// Full owner key on a single device (NOT RECOMMENDED)
    Single,
    /// k-of-n threshold signing (RECOMMENDED)
    Threshold,
}

/// Sealed owner key-share (NORMATIVE when OwnerKeyScheme::Threshold)
pub struct OwnerKeyShare {
    pub header: ObjectHeader,
    pub share_id: u8,
    pub node_id: TailscaleNodeId,
    /// Sealed to node_enc_pubkey
    pub sealed_share: Vec<u8>,
    pub issued_at: u64,
    /// Owner signature over the distribution statement
    pub signature: Signature,
}
```
```

**Key Role Separation (NORMATIVE):**

FCP requires five distinct key roles:
0. **Owner signing key** (Ed25519 public key): Root trust anchor. Implementations SHOULD avoid storing the owner *private* key in full on any single device by using threshold signing (§2.2.1).
1. **Node signing keys** (Ed25519): For frame attribution, gossip auth, operation receipts
2. **Node encryption keys** (X25519): For receiving sealed zone keys and secret shares
3. **Node issuance keys** (Ed25519): For minting capability tokens (separately revocable)
4. **Zone encryption keys** (ChaCha20-Poly1305): For AEAD encryption of symbols/objects

All three node key types MUST be attested by owner signature via `NodeKeyAttestation`.
Issuance keys are separately revocable so token minting can be disabled without affecting other node functions.

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

/// Secret per-zone object-id key (NORMATIVE)
///
/// This key is distributed to zone members via ZoneKeyManifest (NORMATIVE).
/// It remains stable across routine zone_key rotations.
/// Provides privacy against dictionary attacks on low-entropy objects.
pub struct ObjectIdKey(pub [u8; 32]);

impl ObjectId {
    /// Create ObjectId from content, zone, and schema (NORMATIVE for security objects)
    ///
    /// Uses keyed BLAKE3 for:
    /// - Performance (BLAKE3 is faster and parallel-friendly)
    /// - Privacy (keyed hash prevents dictionary attacks on low-entropy objects)
    pub fn new(content: &[u8], zone: &ZoneId, schema: &SchemaId, key: &ObjectIdKey) -> Self {
        let mut h = blake3::Hasher::new_keyed(&key.0);
        h.update(b"FCP2-OBJECT-V2");
        h.update(zone.as_bytes());
        h.update(schema.hash().as_bytes());
        h.update(content);
        Self(*h.finalize().as_bytes())
    }

    /// Unscoped content hash (NON-NORMATIVE; MUST NOT be used for security objects)
    ///
    /// WARNING: This creates a content hash without binding to zone + schema.
    /// This is a footgun for anything security-relevant.
    pub fn from_unscoped_bytes(content: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-CONTENT-V2");
        h.update(content);
        Self(*h.finalize().as_bytes())
    }
}

/// NORMATIVE SAFETY RULE:
/// The following object classes MUST use ObjectId::new(content, zone, schema):
/// - CapabilityObject, CapabilityToken, PolicyObject, RevocationObject
/// - AuditEvent, AuditHead, SecretObject, ZoneKeyManifest
/// - DeviceEnrollment, NodeKeyAttestation
/// - Any object used as an authority anchor or enforcement input
///
/// Using from_unscoped_bytes() for these objects is a SECURITY VIOLATION.
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

    /// Canonical type binding hash (NORMATIVE)
    /// Uses fixed-size hash to prevent DoS via maliciously large schema strings.
    pub fn hash(&self) -> SchemaHash {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-SCHEMA-V1");
        h.update(&self.as_bytes());
        SchemaHash(*h.finalize().as_bytes())
    }
}

/// 32-byte schema hash (NORMATIVE)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaHash([u8; 32]);

impl SchemaHash {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
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

        // Schema hash prefix for type binding (fixed-size, DoS-resistant)
        buf.extend_from_slice(schema.hash().as_bytes());

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
        // Verify schema hash prefix
        if data.len() < 32 {
            return Err(SerializationError::SchemaMismatch);
        }
        let got = &data[0..32];
        if got != expected_schema.hash().as_bytes() {
            return Err(SerializationError::SchemaMismatch);
        }

        // Deserialize content
        ciborium::de::from_reader(&data[32..])
            .map_err(SerializationError::CborError)
    }
}
```

### 3.6 ObjectHeader

All mesh-stored objects MUST begin with an ObjectHeader (NORMATIVE):

```rust
/// Universal object header (NORMATIVE)
///
/// NORMATIVE: ObjectId is derived from the canonical encoding of (header, body).
/// The header MUST NOT embed `object_id` to avoid self-referential hashing ambiguity.
pub struct ObjectHeader {
    /// Schema identifier
    pub schema: SchemaId,
    /// Zone this object belongs to
    pub zone_id: ZoneId,
    /// Creation timestamp
    pub created_at: u64,
    /// Origin provenance
    pub provenance: Provenance,
    /// Strong refs to other objects (object graph for GC + auditability)
    pub refs: Vec<ObjectId>,
    /// Optional TTL in seconds
    pub ttl_secs: Option<u64>,
    /// Optional placement policy for symbol distribution (NORMATIVE when present)
    /// Makes "offline = reduced probability" measurable and maintainable.
    pub placement: Option<ObjectPlacementPolicy>,
}

/// Object placement policy (NORMATIVE when used)
///
/// Defines how symbols for this object should be distributed across the mesh.
/// Enables quantifiable offline resilience SLOs.
pub struct ObjectPlacementPolicy {
    /// Minimum distinct nodes that should hold symbols for this object
    pub min_nodes: u8,
    /// Maximum fraction of total symbols any single node may hold (prevents concentration)
    pub max_node_fraction: f64,
    /// Preferred device selectors (e.g., "tag:fcp-private", "class:desktop")
    pub preferred_devices: Vec<String>,
    /// Hard exclusions (e.g., "tag:fcp-public", specific node IDs)
    pub excluded_devices: Vec<String>,
    /// Target coverage ratio (symbols held / symbols needed)
    /// 1.0 = exactly K symbols distributed; 1.5 = 50% redundancy
    pub target_coverage: f64,
}

/// Node-local storage metadata (NOT content-addressed)
///
/// Retention is storage policy and SHOULD NOT be committed to content addressing,
/// because different nodes can store the same object with different retention.
pub struct StorageMeta {
    pub retention: RetentionClass,
}

/// Stored object record (NORMATIVE)
pub struct StoredObject {
    pub object_id: ObjectId,
    pub header: ObjectHeader,
    /// Canonical CBOR body (schema-prefixed)
    pub body: Vec<u8>,
    /// Node-local storage policy
    pub storage: StorageMeta,
}

impl StoredObject {
    /// Canonical bytes used for ObjectId derivation (NORMATIVE)
    pub fn canonical_bytes(header: &ObjectHeader, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FCP2-OBJECT-V1");
        ciborium::ser::into_writer_canonical(header, &mut out).unwrap();
        out.extend_from_slice(body);
        out
    }

    pub fn derive_id(header: &ObjectHeader, body: &[u8], key: &ObjectIdKey) -> ObjectId {
        ObjectId::new(&Self::canonical_bytes(header, body), &header.zone_id, &header.schema, key)
    }
}

/// Retention class for garbage collection (NORMATIVE)
pub enum RetentionClass {
    /// Never evict unless explicitly unpinned
    Pinned,
    /// Keep until lease expires (renewable)
    Lease { expires_at: u64 },
    /// Best-effort cache; eviction allowed under pressure
    Ephemeral,
}
```

### 3.7 Garbage Collection and Pinning

Nodes MUST implement reachability-based GC per zone (NORMATIVE):

```rust
/// GC algorithm (NORMATIVE)
impl SymbolStore {
    pub fn garbage_collect(&mut self, zone_id: &ZoneId) -> GcResult {
        // 1. Compute root set
        // NORMATIVE: ZoneFrontier is the canonical zone root pointer.
        // Nodes MUST keep the latest ZoneFrontier pinned for each active zone.
        let mut roots = HashSet::new();
        if let Some(frontier) = self.get_latest_zone_frontier(zone_id) {
            roots.insert(frontier);
        }
        // Include any locally pinned objects (explicit pins are always GC roots).
        roots.extend(self.get_locally_pinned_roots(zone_id));

        // 2. Mark phase: traverse refs from roots
        let mut live = HashSet::new();
        let mut queue: VecDeque<_> = roots.into_iter().collect();
        while let Some(object_id) = queue.pop_front() {
            if live.insert(object_id) {
                if let Some(header) = self.get_header(&object_id) {
                    queue.extend(header.refs.iter().cloned());
                }
            }
        }

        // 3. Sweep phase: evict unreachable non-pinned objects
        let mut evicted = 0;
        for object_id in self.all_objects(zone_id) {
            if !live.contains(&object_id) {
                if let Some(meta) = self.get_storage_meta(&object_id) {
                    if !matches!(meta.retention, RetentionClass::Pinned) {
                        self.evict(&object_id);
                        evicted += 1;
                    }
                }
            }
        }

        GcResult { live: live.len(), evicted }
    }
}
```

**GC Invariants:**
- Never evict `Pinned` objects without explicit unpin request
- Respect `Lease` expiry times
- Enforce per-zone quotas
- Root set always includes: latest ZoneFrontier (pinned) + all explicitly pinned objects

### 3.8 ZoneFrontier as the Root Pointer (NORMATIVE)

ZoneFrontier is the compact, signed pointer to the current "heads" that define a zone's live object graph.
It is used for:
- **Fast sync:** Compare frontiers to determine staleness without traversal
- **GC root definition:** Frontier is the canonical root; everything reachable from it is live
- **Offline repair targets:** Frontier indicates which heads must remain reconstructable

```rust
/// Frontier checkpoint for fast sync (NORMATIVE)
///
/// Compact checkpoint of zone state for efficient synchronization.
/// Nodes can compare frontiers to quickly determine staleness.
pub struct ZoneFrontier {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    /// Latest revocation head
    pub rev_head: ObjectId,
    pub rev_seq: u64,
    /// Latest audit head
    pub audit_head: ObjectId,
    pub audit_seq: u64,
    /// Current epoch
    pub as_of_epoch: EpochId,
    /// Signature by executing node
    pub signature: Signature,
}
```

**Implementation Requirements (NORMATIVE):**
1. Store ZoneFrontier objects as normal mesh objects (content-addressed)
2. Pin the latest frontier per zone
3. Refuse to accept tokens/approvals referencing revocation state newer than the latest known frontier (must fetch first)

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

    /// Zone key ID (for key rotation - enables deterministic decryption)
    pub zone_key_id: [u8; 8],

    /// Epoch for replay protection
    pub epoch_id: EpochId,

    /// Source node that produced this ciphertext (NORMATIVE)
    /// Needed because symbol encryption uses a per-sender subkey (see below).
    pub source_id: TailscaleNodeId,

    /// Monotonic frame sequence chosen by source for this zone_key_id (NORMATIVE)
    pub frame_seq: u64,

    /// AEAD authentication tag
    pub auth_tag: [u8; 16],

    // NOTE: Nonce is NOT stored per-symbol.
    // NORMATIVE: nonce = frame_seq_le || esi_le
    // frame_seq is per-sender monotonic for a given (zone_id, zone_key_id).
}

/// Derive per-symbol nonce from frame_seq and ESI (NORMATIVE)
///
/// nonce = frame_seq_le[0..8] || esi_le[0..4]
/// Combined with per-sender subkeys, this eliminates nonce-collision risk across senders.
fn derive_nonce(frame_seq: u64, esi: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&frame_seq.to_le_bytes());
    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
    nonce
}

impl SymbolEnvelope {
    /// Encrypt symbol data with zone key (NORMATIVE)
    pub fn encrypt(
        object_id: ObjectId,
        esi: u32,
        k: u16,
        plaintext: &[u8],
        zone_key: &ZoneKey,
        epoch: EpochId,
        source_id: TailscaleNodeId,
        frame_seq: u64,
    ) -> Self {
        // NORMATIVE: derive nonce from frame_seq || esi_le
        let nonce = derive_nonce(frame_seq, esi);

        // Associated data binds symbol to context INCLUDING key_id for rotation safety
        let aad = Self::build_aad(&object_id, esi, k, &zone_key.zone_id, zone_key.key_id, epoch);

        // NORMATIVE: encrypt under a per-sender subkey derived from the zone key.
        // This prevents nonce collision across different senders.
        let sender_key = zone_key.derive_sender_subkey(&source_id);
        let (ciphertext, auth_tag) = zone_key.encrypt_with_subkey(&sender_key, plaintext, &nonce, &aad);

        Self {
            object_id,
            esi,
            k,
            data: ciphertext,
            zone_id: zone_key.zone_id.clone(),
            zone_key_id: zone_key.key_id,
            epoch_id: epoch,
            source_id,
            frame_seq,
            auth_tag,
        }
    }

    /// Decrypt and verify symbol (NORMATIVE)
    pub fn decrypt(&self, zone_key: &ZoneKey) -> Result<Vec<u8>, CryptoError> {
        // Verify key_id matches to catch rotation mismatches early
        if zone_key.key_id != self.zone_key_id {
            return Err(CryptoError::KeyIdMismatch {
                expected: self.zone_key_id,
                got: zone_key.key_id,
            });
        }

        // NORMATIVE: derive nonce from frame_seq || esi_le
        let nonce = derive_nonce(self.frame_seq, self.esi);

        let aad = Self::build_aad(
            &self.object_id,
            self.esi,
            self.k,
            &self.zone_id,
            self.zone_key_id,
            self.epoch_id
        );

        // NORMATIVE: decrypt using per-sender subkey
        let sender_key = zone_key.derive_sender_subkey(&self.source_id);
        zone_key.decrypt_with_subkey(&sender_key, &self.data, &nonce, &self.auth_tag, &aad)
    }

    fn build_aad(
        object_id: &ObjectId,
        esi: u32,
        k: u16,
        zone_id: &ZoneId,
        zone_key_id: [u8; 8],
        epoch: EpochId,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(72);
        aad.extend_from_slice(object_id.as_bytes());
        aad.extend_from_slice(&esi.to_le_bytes());
        aad.extend_from_slice(&k.to_le_bytes());
        aad.extend_from_slice(zone_id.as_bytes());
        aad.extend_from_slice(&zone_key_id);  // Binds AAD to specific key version
        aad.extend_from_slice(&epoch.0.to_le_bytes());
        aad
    }
}
```

### 4.2 Mesh Session Authentication (NORMATIVE)

Ed25519 signatures per data-plane frame are too expensive when frames are near MTU (often ~1 symbol/frame).
FCP therefore authenticates data-plane FCPS frames via a **session**:

1. A one-time handshake authenticated by attested node signing keys
2. Session-key derivation (X25519 ECDH + HKDF)
3. Per-frame MAC (safe under key reuse) + monotonic sequence number for anti-replay

**SECURITY NOTE (NORMATIVE):** Poly1305 is a one-time authenticator; using one Poly1305 key across
multiple frames is cryptographically insecure. FCP V2 therefore uses HMAC-SHA256 or BLAKE3-keyed
for session MACs and reserves Poly1305 for AEAD contexts only (where nonce uniqueness is enforced).

Signed frames MAY still be used for bootstrap/degraded mode, but high-throughput delivery MUST support session MACs.

**Why session MACs instead of per-frame signatures:**
- Ed25519 signing is expensive at scale (especially mobile)
- AEAD already provides per-symbol cryptographic integrity
- Session establishment amortizes signature cost over many frames
- Preserves "cryptographic attribution independent of transport" goal

```rust
/// Session crypto suite negotiation (NORMATIVE)
pub enum SessionCryptoSuite {
    /// X25519 + HKDF-SHA256 + HMAC-SHA256 (tag truncated to 16 bytes)
    Suite1,
    /// X25519 + HKDF-SHA256 + BLAKE3-keyed (tag truncated to 16 bytes)
    Suite2,
}

/// Session handshake: initiator → responder
pub struct MeshSessionHello {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    pub timestamp: u64,
    /// Supported crypto suites (ordered by preference)
    pub suites: Vec<SessionCryptoSuite>,
    /// Node signature over transcript
    pub signature: Signature,
}

/// Session handshake: responder → initiator
pub struct MeshSessionAck {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    pub session_id: [u8; 16],
    /// Selected crypto suite
    pub suite: SessionCryptoSuite,
    pub timestamp: u64,
    /// Node signature over transcript
    pub signature: Signature,
}

/// Session key derivation (NORMATIVE)
///
/// prk = HKDF-SHA256(
///     ikm = ECDH(initiator_eph, responder_eph),
///     salt = session_id,
///     info = "FCP2-SESSION-V1" || initiator_node_id || responder_node_id
/// )
///
/// keys = HKDF-Expand(prk, info="FCP2-SESSION-KEYS-V1", L=96) split as:
/// - k_mac_i2r (32 bytes): MAC key for initiator → responder
/// - k_mac_r2i (32 bytes): MAC key for responder → initiator
/// - k_ctx     (32 bytes): reserved for future header/control-plane AEAD

/// Authenticated FCPS frame (NORMATIVE)
pub struct AuthenticatedFcpsFrame {
    pub frame: FcpsFrame,
    pub source_id: TailscaleNodeId,
    pub session_id: [u8; 16],
    /// Monotonic sequence for anti-replay
    pub seq: u64,
    /// MAC over: session_id || direction || seq || frame_bytes
    /// - Suite1: HMAC-SHA256(k_mac_dir, ...) truncated to 16 bytes
    /// - Suite2: BLAKE3(keyed=k_mac_dir, ...) truncated to 16 bytes
    pub mac: [u8; 16],
}

/// Replay protection policy (NORMATIVE defaults)
pub struct SessionReplayPolicy {
    /// Allow limited reordering; MUST be bounded
    pub max_reorder_window: u64,   // default: 128
    /// Rekey periodically for operational hygiene and suite agility
    pub rekey_after_frames: u64,   // default: 1_000_000_000
}

/// Legacy signed frame (for bootstrap/degraded mode)
pub struct SignedFcpsFrame {
    pub frame: FcpsFrame,
    pub source_id: TailscaleNodeId,
    pub timestamp: u64,
    pub signature: Signature,
}

impl SignedFcpsFrame {
    pub fn sign(frame: FcpsFrame, identity: &MeshIdentity) -> Self {
        let timestamp = current_timestamp();
        let signature = identity.sign(&Self::signable_bytes(&frame, timestamp));
        Self { frame, source_id: identity.node_id.clone(), timestamp, signature }
    }

    pub fn verify(&self, trusted_keys: &TrustAnchors) -> Result<(), VerifyError> {
        let pubkey = trusted_keys.get_node_sig_pubkey(&self.source_id)?;
        pubkey.verify(&Self::signable_bytes(&self.frame, self.timestamp), &self.signature)
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
│  Bytes 48-49:  Symbol Size (u16 LE, default 1024)                           │
│  Bytes 50-57:  Zone Key ID (8 bytes, for rotation)                          │
│  Bytes 58-73:  Zone ID hash (16 bytes, truncated SHA256)                    │
│  Bytes 74-81:  Epoch ID (u64 LE)                                            │
│  Bytes 82-89:  Frame Seq (u64 LE, per-sender monotonic)                     │
│  Bytes 90+:    Symbol payloads (concatenated)                               │
│  Final 8:      Checksum (XXH3-64)                                           │
│                                                                             │
│  Fixed header: 90 bytes                                                     │
│  Each symbol: 4 (ESI) + 2 (K) + N (data) + 16 (auth_tag)                    │
│               (nonce derived from frame_seq_le || esi_le, NOT stored)       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Per-Sender Subkeys and Deterministic Nonces (NORMATIVE):**

Each sender MUST maintain a monotonic `frame_seq` per (zone_id, zone_key_id) and MUST NOT reuse it.
Combined with per-sender subkeys derived from the zone key, this eliminates nonce-collision risk:

```rust
impl ZoneKey {
    /// Derive per-sender subkey (NORMATIVE)
    ///
    /// sender_key = HKDF-SHA256(
    ///     ikm = zone_symmetric_key,
    ///     salt = zone_key_id,
    ///     info = "FCP2-SENDER-KEY-V1" || sender_node_id
    /// )
    pub fn derive_sender_subkey(&self, sender: &TailscaleNodeId) -> [u8; 32];
}
```

**Why per-sender subkeys + deterministic nonces:**
- 64-bit random nonces have birthday collision risk over long-running systems with many senders
- Per-sender subkeys eliminate cross-sender nonce collision (keys differ per sender)
- Deterministic `frame_seq` avoids RNG dependence and is testable
- No per-frame random generation overhead

**Key Rotation Benefits:**
- Including `zone_key_id` in frame header enables deterministic key selection
- No trial-decrypt needed during rotation periods
- Faster decrypt path, less DoS surface
- Cleaner auditability (log exactly which key was used)

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

/// Decode status feedback (NORMATIVE)
///
/// Enables flow control: receiver tells sender how many symbols received/needed.
pub struct DecodeStatus {
    pub header: ObjectHeader,
    pub object_id: ObjectId,
    pub zone_id: ZoneId,
    pub zone_key_id: [u8; 8],
    pub epoch_id: EpochId,
    /// Unique symbols received so far for this object
    pub received_unique: u32,
    /// Target required to decode (K')
    pub required: u32,
    /// Optional: compact bitmap/IBLT of missing ESIs (for targeted repair)
    pub missing_hint: Option<Vec<u8>>,
}

/// Symbol ack / stop condition (NORMATIVE)
///
/// Receiver tells sender to stop: object reconstructed.
pub struct SymbolAck {
    pub header: ObjectHeader,
    pub object_id: ObjectId,
    pub zone_id: ZoneId,
    pub zone_key_id: [u8; 8],
    pub epoch_id: EpochId,
    /// If present: reconstructed payload object id
    pub reconstructed_object_id: Option<ObjectId>,
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
    /// Send symbols with feedback-based pacing (NORMATIVE)
    ///
    /// NORMATIVE: sender SHOULD stop once it receives SymbolAck OR DecodeStatus indicates completion.
    /// NORMATIVE: sender MUST apply backpressure to avoid unbounded buffering.
    /// NORMATIVE: sender SHOULD use AIMD or BBR-style pacing based on DecodeStatus feedback.
    pub async fn deliver(&self, frame: SignedFcpsFrame) -> DeliveryResult {
        let mut results = Vec::new();

        // Round-robin symbols across paths
        for (i, symbol) in frame.frame.symbols.iter().enumerate() {
            let path = &self.paths[i % self.paths.len()];
            results.push(path.send(symbol.clone()).await);
        }

        // Listen for DecodeStatus/SymbolAck to stop early
        // Implementation should check for stop condition and halt delivery

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

Zones enforce **two independent security axes**:

1. **Integrity ("input trust")** — prevents low-integrity inputs from driving high-integrity effects
2. **Confidentiality ("data secrecy")** — prevents high-secrecy data from leaking into low-secrecy zones

Both axes are enforced mechanically (not by prompt, convention, or agent compliance).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ZONE INTEGRITY/CONFIDENTIALITY LATTICE                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   z:owner        [Integrity: 100 | Confidentiality: 100]  Direct owner      │
│       │                        Tailscale tag: tag:fcp-owner                 │
│       ▼                                                                     │
│   z:private      [Integrity: 80  | Confidentiality: 90]   Personal data     │
│       │                        Tailscale tag: tag:fcp-private               │
│       ▼                                                                     │
│   z:work         [Integrity: 60  | Confidentiality: 70]   Work context      │
│       │                        Tailscale tag: tag:fcp-work                  │
│       ▼                                                                     │
│   z:community    [Integrity: 40  | Confidentiality: 40]   Trusted external  │
│       │                        Tailscale tag: tag:fcp-community             │
│       ▼                                                                     │
│   z:public       [Integrity: 20  | Confidentiality: 10]   Public inputs     │
│                                Tailscale tag: tag:fcp-public                │
│                                                                             │
│   INVARIANTS:                                                               │
│     Integrity: data can flow DOWN (higher → lower integrity) freely.        │
│               data flowing UP requires explicit elevation + approval.       │
│     Confidentiality: data can flow UP (lower → higher confidentiality)      │
│                     freely. data flowing DOWN requires explicit             │
│                     declassification.                                       │
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

    /// Integrity level (0-100). Higher = more trusted inputs.
    pub integrity_level: u8,

    /// Confidentiality level (0-100). Higher = more secret data.
    pub confidentiality_level: u8,

    /// Active zone key id (selected from local ZoneKeyRing)
    pub active_zone_key_id: [u8; 8],

    /// Tailscale ACL tag
    pub tailscale_tag: String,

    /// Parent zone (for hierarchy)
    pub parent: Option<ZoneId>,

    /// Access policy
    pub policy: ZonePolicy,

    /// UDP/TCP port for symbol frames in this zone (NORMATIVE for port-gating)
    pub symbol_port: u16,

    /// UDP/TCP port for gossip/control-plane objects in this zone (NORMATIVE for port-gating)
    pub control_port: u16,
}

/// Unified approval token (NORMATIVE)
///
/// Consolidates ElevationToken and DeclassificationToken into a single type.
/// Simplifies: UI prompting, audit, verification code paths, policy.
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
}

/// Zone encryption key (NORMATIVE)
///
/// Zone keys are **randomly generated** symmetric keys, NOT derived from owner secret material.
/// HKDF is used for **subkey derivation** (per-sender subkeys, epoch subkeys), not for
/// deriving the zone key itself.
pub struct ZoneKey {
    pub zone_id: ZoneId,
    pub key_id: [u8; 8],
    /// Randomly generated 256-bit symmetric key for ChaCha20-Poly1305 AEAD
    pub symmetric_key: [u8; 32],
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl ZoneKey {
    /// Zone keys are provisioned via ZoneKeyManifest objects (NORMATIVE).
    /// Nodes MUST NOT require access to owner secret key material to encrypt/decrypt zone data.
    /// The owner key signs manifests (authorization), but does NOT act as an online KDF root.
    ///
    /// This enables:
    /// - True key rotation (new key_id without changing owner key)
    /// - Per-node key distribution (sealed to each node's X25519 key)
    /// - Operational key management without owner key exposure
    /// - Clean separation: owner key for attestation/revocation, zone keys for encryption

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

/// Zone key manifest (NORMATIVE)
///
/// Signed by the owner key. Distributes a specific zone_key_id's symmetric key
/// to eligible nodes by sealing it to each node_enc_pubkey.
pub struct ZoneKeyManifest {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub zone_key_id: [u8; 8],
    pub algorithm: ZoneKeyAlgorithm,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    /// Optional overlap with previous key_id for rotation windows
    pub prev_zone_key_id: Option<[u8; 8]>,

    /// ObjectIdKey material for this zone (NORMATIVE)
    /// Stable across routine zone_key rotations. Distributed via manifest.
    pub object_id_key_id: [u8; 8],
    pub wrapped_object_id_keys: Vec<WrappedObjectIdKey>,

    /// Optional ratchet policy for epoch keys (past secrecy)
    pub ratchet: Option<ZoneRatchetPolicy>,

    /// Sealed key material per node
    pub wrapped_keys: Vec<WrappedZoneKey>,
    pub signature: Signature,
}

pub enum ZoneKeyAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

pub struct WrappedZoneKey {
    pub node_id: TailscaleNodeId,
    /// Which node_enc_pubkey was used (supports node key rotation)
    pub node_enc_kid: [u8; 8],
    /// Sealed box containing the 32-byte zone symmetric key
    pub sealed_key: Vec<u8>,
}

/// Wrapped ObjectIdKey for distribution (NORMATIVE)
pub struct WrappedObjectIdKey {
    pub node_id: TailscaleNodeId,
    pub node_enc_kid: [u8; 8],
    /// Sealed box containing the 32-byte ObjectIdKey
    pub sealed_key: Vec<u8>,
}

/// Epoch ratchet policy for past secrecy (NORMATIVE when present)
///
/// If enabled, nodes MUST derive an epoch key, use it, then delete it after the
/// epoch window. Past epochs become undecryptable after deletion (past secrecy).
/// This is not full post-compromise security (for that you'd need MLS/TreeKEM),
/// but it's a significant improvement with modest complexity.
pub struct ZoneRatchetPolicy {
    /// If true, nodes MUST derive and delete epoch keys per policy
    pub enabled: bool,
    /// Number of seconds of overlap to tolerate clock skew and delayed frames
    pub overlap_secs: u64,
    /// Max epochs to retain for delayed/offline peers (bounded memory)
    pub retain_epochs: u32,
}

/// Local keyring for zone keys (NORMATIVE)
pub struct ZoneKeyRing {
    pub zone_id: ZoneId,
    pub keys: HashMap<[u8; 8], ZoneKey>,
    pub active: [u8; 8],
}

impl ZoneKeyRing {
    pub fn get(&self, zone_key_id: &[u8; 8]) -> Option<&ZoneKey> {
        self.keys.get(zone_key_id)
    }

    pub fn active_key(&self) -> Option<&ZoneKey> {
        self.keys.get(&self.active)
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

        // ACL rules: defense-in-depth via zone membership port-gating.
        //
        // DESIGN RATIONALE:
        // - Tailscale tags are per-node, not per-connector-process.
        // - A node participating in multiple zones breaks any simple "src/dst lattice = data flow" assumption.
        // - Integrity/confidentiality lattice is enforced cryptographically + by capability checks.
        // - ACLs should reduce attack surface by ensuring only zone members can send zone traffic at all.
        //
        // NORMATIVE: MeshNode MUST expose per-zone ports for symbol/gossip/control traffic.
        for zone in &self.zones {
            let sym = zone.symbol_port;
            let ctl = zone.control_port;
            acl.acls.push(AclRule {
                action: "accept".into(),
                src: vec![zone.tailscale_tag.clone()],
                dst: vec![
                    format!("{}:{}", zone.tailscale_tag, sym),
                    format!("{}:{}", zone.tailscale_tag, ctl),
                ],
            });
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

**Port-Gating Rationale (NORMATIVE):**

The previous lattice-based ACL approach attempted to encode both integrity and confidentiality axes
in network reachability. This had several problems:
- It contradicted the invariants (confidentiality allows "up" flow, but ACL logic blocked it)
- Tailscale tags are per-node, not per-process; a node in multiple zones breaks the lattice assumption

Port-gating provides defense-in-depth without overreaching:
- Each zone gets reserved mesh ports (symbol + gossip/control)
- ACL allows traffic **only** between nodes tagged for that zone on those ports
- Funnel/public ingress is restricted to low-trust zones' ports only
- The real security (integrity, confidentiality, taint, authority) is enforced cryptographically

### 5.5 Zone Group Key Agreement (RECOMMENDED for z:owner, z:private)

FCP V2 supports an optional group key agreement mode for zones using MLS-style TreeKEM.
When enabled, zone membership changes produce a new epoch of group secrets with post-compromise security (PCS).

**Why this matters:**
- **Post-compromise security (PCS):** After removal/commit, an attacker who stole past keys loses access to future traffic
- **Asynchronous membership changes:** Fits the mesh/offline story—devices don't need to be online simultaneously
- **Strongest guarantees for z:owner:** Where you want maximum protection

**NORMATIVE:**
- Implementations MAY omit MLS support, but if supported it MUST be selectable per-zone.
- When MLS is enabled for a zone, `ZoneKeyManifest` objects distribute **epoch secrets** (or MLS commit secrets), not long-lived static symmetric zone keys.
- The baseline `ManifestDistributed` mode remains the default for all zones.

```rust
/// Zone key distribution mode (NORMATIVE when MLS supported)
pub enum ZoneKeyMode {
    /// Baseline: symmetric keys distributed via owner-signed manifests
    /// Keys are randomly generated and sealed to each node's X25519 key
    ManifestDistributed,

    /// Optional upgrade: MLS/TreeKEM group key agreement for post-compromise security
    /// Epoch secrets rotate on membership changes
    MlsTreeKem,
}

/// Zone security profile (NORMATIVE when present)
pub struct ZoneSecurityProfile {
    pub zone_id: ZoneId,
    pub key_mode: ZoneKeyMode,
    /// Require PCS for this zone (default true for z:owner if MLS enabled)
    pub require_pcs: bool,
    /// Maximum epoch duration (bounds exposure window)
    pub max_epoch_secs: u64,
}

impl Default for ZoneSecurityProfile {
    fn default() -> Self {
        Self {
            zone_id: ZoneId::private(),
            key_mode: ZoneKeyMode::ManifestDistributed,
            require_pcs: false,
            max_epoch_secs: 86400, // 24 hours
        }
    }
}
```

**Migration Path:**
- Zones start with `ManifestDistributed` (current behavior)
- Owner can upgrade to `MlsTreeKem` for sensitive zones
- Downgrade requires explicit owner action and re-sealing all zone data

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

    /// Current zone (NORMATIVE): updated on every zone crossing
    pub current_zone: ZoneId,

    /// Integrity/confidentiality labels inherited from origin (NORMATIVE)
    pub origin_integrity: u8,
    pub origin_confidentiality: u8,

    /// Principal who introduced the data
    pub origin_principal: Option<PrincipalId>,

    /// Taint flags (compositional)
    pub taint: TaintFlags,

    /// Taint reductions, each justified by a verifiable attestation (NORMATIVE)
    /// Allows specific taints to be cleared with proof (e.g., URL scan, malware check)
    pub taint_reductions: Vec<TaintReduction>,

    /// Crossed zones (audit trail)
    pub zone_crossings: Vec<ZoneCrossing>,

    /// Timestamp of creation
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
    ///
    /// Compositional: merged via OR across inputs.
    pub struct TaintFlags: u32 {
        const NONE            = 0;
        const PUBLIC_INPUT    = 1 << 0;  // e.g. z:public messages, web
        const EXTERNAL_INPUT  = 1 << 1;  // e.g. paired external identities
        const UNVERIFIED_LINK = 1 << 2;  // URLs / attachments not scanned
        const USER_SUPPLIED   = 1 << 3;  // direct human input
        const PROMPT_SURFACE  = 1 << 4;  // content interpreted by an LLM
    }
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

    /// Compute taint when crossing zones
    pub fn cross_zone(&self, target: &Zone) -> Self {
        let mut new = self.clone();

        // Record crossing (NORMATIVE: use current_zone, not origin_zone)
        new.zone_crossings.push(ZoneCrossing {
            from_zone: self.current_zone.clone(),
            to_zone: target.id.clone(),
            crossed_at: current_timestamp(),
            authorized_by: None,
        });

        // Update current zone (NORMATIVE)
        new.current_zone = target.id.clone();

        new
    }

    /// Merge provenance from multiple inputs (NORMATIVE)
    ///
    /// Used when an operation consumes multiple data sources.
    pub fn merge(inputs: &[Provenance]) -> Provenance {
        let mut out = inputs[0].clone();
        for p in inputs.iter().skip(1) {
            out.taint |= p.taint;
            out.zone_crossings.extend_from_slice(&p.zone_crossings);
        }
        out
    }

    /// Check if operation is allowed given taint (NORMATIVE)
    ///
    /// Uses effective_taint() which accounts for taint reductions.
    pub fn can_invoke(&self, operation: &Operation, target_zone: &Zone) -> TaintDecision {
        let effective = self.effective_taint();

        // Rule 1: Public inputs cannot directly drive Dangerous ops
        if effective.contains(TaintFlags::PUBLIC_INPUT)
            && operation.safety_tier >= SafetyTier::Dangerous
        {
            return TaintDecision::Deny("Public-tainted input cannot invoke dangerous operations");
        }

        // Rule 2: Integrity uphill for risky ops requires elevation
        if effective != TaintFlags::NONE
            && operation.safety_tier >= SafetyTier::Risky
            && target_zone.integrity_level > self.origin_integrity
        {
            return TaintDecision::RequireElevation;
        }

        TaintDecision::Allow
    }
}
```

### 6.3 Elevation Protocol

Elevation (integrity uphill for tainted operations) now uses the unified `ApprovalToken` (§5.2) with `ApprovalScope::Elevation`.

```rust
/// Create an elevation approval (NORMATIVE)
impl ApprovalToken {
    pub fn create_elevation(
        operation: OperationId,
        provenance: &Provenance,
        approver: &Identity,
        justification: &str,
        ttl: Option<u64>,
    ) -> Self {
        let now = current_timestamp();
        let expires_at = now + ttl.unwrap_or(Self::DEFAULT_TTL_SECS);

        let mut token = Self {
            token_id: ObjectId::default(),
            scope: ApprovalScope::Elevation {
                operation,
                original_provenance: provenance.clone(),
            },
            justification: justification.to_string(),
            approved_by: approver.principal_id(),
            approved_at: now,
            expires_at,
            signature: Signature::default(),
        };

        let signable = token.signable_bytes();
        token.signature = approver.sign(&signable);
        token.token_id = ObjectId::from_bytes(&signable);

        token
    }

    pub fn create_declassification(
        from_zone: ZoneId,
        to_zone: ZoneId,
        object_ids: Vec<ObjectId>,
        approver: &Identity,
        justification: &str,
        ttl: Option<u64>,
    ) -> Self {
        let now = current_timestamp();
        let expires_at = now + ttl.unwrap_or(Self::DEFAULT_TTL_SECS);

        let mut token = Self {
            token_id: ObjectId::default(),
            scope: ApprovalScope::Declassification {
                from_zone,
                to_zone,
                object_ids,
            },
            justification: justification.to_string(),
            approved_by: approver.principal_id(),
            approved_at: now,
            expires_at,
            signature: Signature::default(),
        };

        let signable = token.signable_bytes();
        token.signature = approver.sign(&signable);
        token.token_id = ObjectId::from_bytes(&signable);

        token
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
    /// Requires ApprovalToken (elevation or other scope)
    ApprovalRequired,
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
    /// Optional network/TLS constraints (NORMATIVE when network.outbound is used)
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
    /// Required connector must be available (installed or fetchable)
    ConnectorAvailable { connector_id: ConnectorId, min_version: Option<Version> },
    /// Secret must be reconstructable under current policy
    SecretReconstructable { secret_id: SecretId, min_nodes: u8 },
    /// Must have sufficient quota headroom in the target zone store
    ZoneQuotaHeadroom { zone_id: ZoneId, min_free_mb: u32 },
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
    pub iss_zone: ZoneId,

    /// Issuing node (signer) - the node that minted this token
    pub iss_node: TailscaleNodeId,

    /// Issuer key id (for rotation)
    pub kid: [u8; 8],

    /// Intended audience (connector)
    pub aud: ConnectorId,

    /// Bind token to a specific connector binary or manifest (NORMATIVE for Risky/Dangerous)
    /// Prevents replay across upgrades or swapped binaries with the same ConnectorId.
    pub aud_binary: Option<ObjectId>,

    /// Optional connector instance binding
    pub instance: Option<InstanceId>,

    /// Issued at (Unix timestamp)
    pub iat: u64,

    /// Expires at (Unix timestamp)
    pub exp: u64,

    /// CapabilityObjects that authorize this token (NORMATIVE)
    /// Verifiers MUST fetch/verify these objects and ensure token grants ⊆ object grants.
    /// This makes authority mechanically verifiable, not "trust the issuer".
    pub grant_object_ids: Vec<ObjectId>,

    /// Granted capabilities (MUST be subset of union of grant_object_ids)
    pub caps: Vec<CapabilityGrant>,

    /// Optional attenuation applied by the issuer (MUST ONLY RESTRICT, never expand)
    pub attenuation: Option<CapabilityConstraints>,

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

        // NORMATIVE: Verify presented CapabilityObjects
        // - Fetch each grant_object_id
        // - Verify signature chain (owner → CapabilityObject)
        // - Verify validity windows cover (iat..exp)
        // - Verify not revoked
        // - Ensure union(grant caps/constraints) authorizes `caps` and `attenuation`
        trust_anchors.verify_token_grants(self)?;

        Ok(())
    }
}
```

**Provable Authority (NORMATIVE):**

Authority MUST be derivable from stored objects. Any verifier should be able to say
"this operation was permitted because of these object IDs," not "because I trust the issuer node."

If a node's issuance key is compromised, it can only mint tokens that reference
existing CapabilityObjects—it cannot create authority out of thin air. This is the
core of "explicit authority" and makes the system auditable.

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

    /// Zone keyrings (for deterministic decryption by zone_key_id)
    pub zone_keyrings: HashMap<ZoneId, ZoneKeyRing>,

    /// Revocation registry
    pub revocations: RevocationRegistry,

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

        // Get keyring and select key by zone_key_id (deterministic, no trial-decrypt)
        let keyring = self.zone_keyrings.get(&frame.zone_id)
            .ok_or(Error::UnknownZone)?;
        let zone_key = keyring.get(&frame.zone_key_id)
            .ok_or(Error::UnknownZoneKey)?;

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
        request.capability_token.verify(&self.trust_anchors)?;

        // 1b. Verify holder proof for sender-constrained tokens (NORMATIVE)
        request.verify_holder_proof(&self.trust_anchors)?;

        // 1c. Enforce revocations (token, capability objects, issuer keys, connector version)
        self.revocations.enforce(&request)?;

        // 2. Check provenance/taint
        let decision = request.provenance.can_invoke(
            &request.operation,
            self.get_zone(&request.capability_token.iss_zone)?,
        );
        match decision {
            TaintDecision::Deny(reason) => return Err(Error::TaintViolation(reason)),
            TaintDecision::RequireElevation => {
                // Find an elevation approval in the approval_tokens
                let elevation = request.approval_tokens.iter()
                    .find(|t| matches!(t.scope, ApprovalScope::Elevation { .. }))
                    .ok_or(Error::ElevationRequired)?;
                elevation.verify(&self.trust_anchors)?;
            }
            TaintDecision::Allow => {}
        }

        // 2d. Enforce confidentiality downgrades (NORMATIVE)
        // If the operation produces outputs into a zone with lower confidentiality than
        // the data label, require a valid declassification ApprovalToken.
        if self.operation_writes_to_lower_confidentiality(&request).await? {
            let declass = request.approval_tokens.iter()
                .find(|t| matches!(t.scope, ApprovalScope::Declassification { .. }))
                .ok_or(Error::DeclassificationRequired)?;
            declass.verify(&self.trust_anchors)?;
        }

        // 2e. Acquire or validate execution lease (NORMATIVE)
        // For Risky/Dangerous operations, execution MUST require a valid lease.
        let operation = self.get_operation(&request.operation)?;
        if operation.safety_tier >= SafetyTier::Risky {
            let lease = self.acquire_execution_lease(&request).await?;
            self.verify_execution_lease(&lease, &request).await?;
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

Efficient discovery with convergent anti-entropy:

```rust
/// Gossip layer for symbol and object discovery (NORMATIVE)
pub struct MeshGossip {
    /// Fast membership hint (XOR filter - low false positive, replaceable)
    pub object_xor_filter: XorFilter,

    /// Symbol availability filter
    pub symbol_xor_filter: XorFilter,

    /// IBLT state for precise set reconciliation
    pub iblt_state: IbltState,

    /// Known peer states
    pub peer_states: HashMap<TailscaleNodeId, PeerGossipState>,
}

impl MeshGossip {
    /// Announce local symbol availability
    pub async fn announce_symbol(&mut self, object_id: &ObjectId, esi: u32) {
        self.object_xor_filter.insert(object_id.as_bytes());
        self.symbol_xor_filter.insert(&symbol_key(object_id, esi));
        self.iblt_state.note_local_change(object_id, esi);
    }

    /// Find peers that might have symbols for an object
    pub fn find_symbol_sources(&self, object_id: &ObjectId) -> Vec<TailscaleNodeId> {
        self.peer_states
            .iter()
            .filter(|(_, state)| state.object_xor_filter.contains(object_id.as_bytes()))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Signed gossip summary for anti-entropy (NORMATIVE)
pub struct GossipSummary {
    /// Source node
    pub from: TailscaleNodeId,
    /// Current epoch
    pub epoch_id: EpochId,
    /// Digest of object filter
    pub object_filter_digest: [u8; 32],
    /// Digest of symbol filter
    pub symbol_filter_digest: [u8; 32],
    /// Compact IBLT encoding for precise delta reconciliation
    pub iblt: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Node signature (for authentication and rate limiting)
    pub signature: Signature,
}
```

**Why XOR Filters + IBLT instead of Bloom Filters:**
- Bloom filters are good for "might contain" but terrible for reconciling exact differences
- XOR filters: faster membership queries, lower false positive rates
- IBLT (Invertible Bloom Lookup Table): precise delta reconciliation
- Dramatically reduces wasted symbol requests at scale
- Faster convergence after offline periods
- Signed summaries make gossip a defendable surface (auth + rate limits)

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

### 8.4 Admission Control and DoS Resistance (NORMATIVE)

Without explicit admission control, the mesh layer becomes the largest attack surface:
symbol floods, garbage ObjectIds, expensive decode attempts, gossip reconciliation abuse,
reflection/amplification via symbol_request.

MeshNodes MUST implement admission control for:
- Per-peer inbound bytes/symbols
- Failed decrypt/MAC counters
- Bounded concurrent decodes
- Bounded gossip reconciliation work

```rust
/// Per-peer resource budget (NORMATIVE)
pub struct PeerBudget {
    pub max_bytes_per_min: u64,         // default: 64MB/min
    pub max_symbols_per_min: u32,       // default: 200_000/min
    pub max_failed_auth_per_min: u32,   // default: 100/min
    pub max_inflight_decodes: u32,      // default: 32
    pub max_decode_cpu_ms_per_min: u64, // default: 5_000ms/min
}

/// Admission policy (NORMATIVE)
pub struct AdmissionPolicy {
    pub per_peer: PeerBudget,
    /// If true, unauthenticated SymbolRequest is rejected
    /// (default: true except z:public ingress)
    pub require_authenticated_requests: bool,
}

impl MeshNode {
    /// Check peer budget before processing (NORMATIVE)
    fn check_admission(&self, peer: &TailscaleNodeId, bytes: u64) -> Result<(), AdmissionError> {
        let budget = self.peer_budgets.get_or_default(peer);
        budget.check_bytes(bytes)?;
        budget.check_rate_limits()?;
        Ok(())
    }
}
```

**Anti-Amplification Rule (NORMATIVE):**

MeshNodes MUST NOT send more than `N` symbols in response to a request unless the requester:
1. Is authenticated (session MAC or node signature), AND
2. The request includes a bounded missing-hint (e.g., `DecodeStatus.missing_hint`) or comparable proof-of-need

This prevents reflection/amplification attacks where an attacker spoofs requests to flood victims.

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
| `decode_status` | Any → Any | Feedback: how many symbols received / still needed |
| `symbol_ack` | Any → Any | Stop condition for delivery (object reconstructed) |

### 9.3 Control Plane Object Model (NORMATIVE)

All control-plane message types MUST have a canonical CBOR object representation with SchemaId/ObjectId.
This makes all operations auditable, replayable, and content-addressed.

**Storage is governed by retention class:**

| Must Be Stored | May Be Ephemeral |
|----------------|------------------|
| invoke, response | health |
| receipts | handshake, handshake_ack |
| approvals (elevation, declassification) | decode_status |
| secret access | symbol_ack |
| revocations | introspect |
| audit events/heads | configure |

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

**Transport Options:**
1. **Direct (local)**: Canonical CBOR bytes over local connector transport
2. **Mesh**: Encoded to symbols and sent inside FCPS frames with `FrameFlags::CONTROL_PLANE` set

When `FrameFlags::CONTROL_PLANE` is set, receivers MUST:
1. Verify checksum
2. Decrypt symbols
3. Reconstruct the object payload (RAW chunking or RaptorQ)
4. Verify schema
5. Store object if retention class is Required; otherwise MAY discard after processing

### 9.4 Invoke Request/Response

```rust
/// Distributed trace context for end-to-end observability (NORMATIVE when present)
pub struct TraceContext {
    /// 16-byte trace id (unique per logical request)
    pub trace_id: [u8; 16],
    /// 8-byte span id (unique per span within trace)
    pub span_id: [u8; 8],
    /// Sampling/flags (W3C Trace Context compatible)
    pub flags: u8,
}

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

    /// Distributed trace context (NORMATIVE when present)
    /// Enables end-to-end correlation across MeshNodes, connectors, receipts, and audit.
    pub trace_context: Option<TraceContext>,

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

/// Operation receipt object (NORMATIVE)
///
/// Operations with SafetyTier::Dangerous MUST be IdempotencyClass::Strict.
/// Operations with SafetyTier::Risky SHOULD be Strict unless there is a clear reason.
pub struct OperationReceipt {
    pub header: ObjectHeader,
    /// ObjectId of the original request
    pub request_object_id: ObjectId,
    /// Idempotency key (if provided)
    pub idempotency_key: Option<String>,
    /// ObjectIds of outcome objects
    pub outcome_object_ids: Vec<ObjectId>,
    /// Resource URIs created/modified
    pub resource_uris: Vec<String>,
    /// When execution completed
    pub executed_at: u64,
    /// Node that executed the operation
    pub executed_by: TailscaleNodeId,
    /// Signature by executing node's signing key
    pub signature: Signature,
}

impl OperationReceipt {
    /// Verify receipt authenticity
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), ReceiptError> {
        let node_pubkey = trust_anchors.get_node_sig_pubkey(&self.executed_by)?;
        node_pubkey.verify(&self.signable_bytes(), &self.signature)
    }
}

/// Operation intent - pre-commit for exactly-once semantics (NORMATIVE for Strict + Risky/Dangerous)
///
/// Closes the crash window between "side effect happened" and "receipt stored".
/// Written BEFORE executing an external side effect.
pub struct OperationIntent {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub capability_token_jti: Uuid,
    pub idempotency_key: Option<String>,
    pub planned_at: u64,
    pub planned_by: TailscaleNodeId,
    /// Optional upstream idempotency handle (e.g., Stripe idempotency key)
    pub upstream_idempotency: Option<String>,
    pub signature: Signature,
}
```

**Execution Rule for Strict/Risky/Dangerous Operations (NORMATIVE):**
1. MeshNode MUST store OperationIntent (Required retention) BEFORE invoking the connector operation
2. OperationReceipt MUST reference the OperationIntent via `ObjectHeader.refs`
3. On crash recovery, check for intents without corresponding receipts to detect incomplete operations

**Idempotency Enforcement:**
- On retry with same `idempotency_key`, mesh returns prior receipt instead of re-executing (for Strict)
- Receipts are stored in symbol store (RetentionClass::Lease or Pinned for critical ones)
- Makes "best-effort vs strict idempotency" enforceable, not advisory
- Intents + receipts form the "exactly-once" spine for dangerous operations

### 9.5 Event Streaming

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

### 10.2 Connector Lifecycle

```
DISCOVERED → VERIFIED → INSTALLED → CONFIGURED → ACTIVE
         ↘ rejected                          ↘ FAILED
                                              ↘ PAUSED
                                              ↘ STOPPED
```

### 10.3 Standard Methods

Connectors MUST implement:

### 10.4 Connector State (NORMATIVE)

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

**State Snapshots (NORMATIVE when state chains exceed thresholds):**

Append-only state chains grow forever and become a performance drag for cold start, migration,
GC traversal, and debugging. Periodic snapshots bound replay cost.

```rust
/// Periodic snapshot to bound replay cost (NORMATIVE when chains exceed thresholds)
pub struct ConnectorStateSnapshot {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub instance_id: Option<InstanceId>,
    pub zone_id: ZoneId,
    /// Latest state object included in this snapshot
    pub covers_head: ObjectId,
    pub covers_seq: u64,
    /// Full canonical state at covers_head
    pub state_cbor: Vec<u8>,
    pub snapshotted_at: u64,
    pub signature: Signature,
}
```

**Compaction Rule (NORMATIVE):**
- MeshNode SHOULD create a snapshot every N updates or M bytes (configurable)
- After snapshot is replicated to placement targets, MeshNode MAY GC older state objects
  that are strictly before `covers_head`, unless required by audit/policy pins

**Fork Detection (NORMATIVE for singleton_writer):**

If `singleton_writer = true` and two different `ConnectorStateObject` share the same `prev`
(i.e., competing seq), nodes MUST treat this as a safety incident:
1. Pause connector execution
2. Require manual resolution OR automated "choose-by-lease" recovery
3. Log the fork event for audit

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
# Sandbox profile (NORMATIVE)
profile = "strict"           # "strict", "strict_plus", "moderate", or "permissive"
memory_mb = 256              # Maximum memory
cpu_percent = 50             # Maximum CPU percentage
wall_clock_timeout_ms = 30000 # Maximum execution time per operation
fs_readonly_paths = ["/usr", "/lib"]  # Paths connector can read
fs_writable_paths = ["$CONNECTOR_STATE"]  # Paths connector can write
deny_exec = true             # Deny spawning child processes
deny_ptrace = true           # Deny debugging/tracing

[signatures]
# Threshold signing: single leaked key doesn't instantly end you
publisher_signatures = [
  { kid = "pubkey1", sig = "base64:..." },
  { kid = "pubkey2", sig = "base64:..." },
]
publisher_threshold = "2-of-3"
registry_signature = { kid = "registry1", sig = "base64:..." }
# Optional but RECOMMENDED: reference to transparency log entry
transparency_log_entry = "objectid:..."

[supply_chain]
# First-class provenance attestations (RECOMMENDED)
# Makes provenance machine-checkable, not just "signature valid"
# e.g., in-toto statements with SLSA provenance predicates
attestations = [
  { type = "in-toto", object_id = "objectid:..." },
  { type = "reproducible-build", object_id = "objectid:..." },
]

[policy]
# Owner policy can require attestations and pin publisher roots
require_transparency_log = true
require_attestation_types = ["in-toto"]
min_slsa_level = 2
trusted_builders = ["github-actions", "internal-ci"]
```

### 11.2 Sandbox Profiles (NORMATIVE)

MeshNode uses the `[sandbox]` section to construct OS sandbox (seccomp/seatbelt/AppContainer)
and enforce resource budgets. This dramatically cuts blast radius for compromised connectors.

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
    /// Use for browser automation, universal adapters, or connectors parsing adversarial content.
    StrictPlus,
    /// Balanced restrictions (default)
    Moderate,
    /// Minimal restrictions (only for highly trusted connectors)
    Permissive,
}

/// NORMATIVE: In Strict and Moderate profiles, connectors MUST NOT be granted raw socket syscalls.
/// Network capabilities are implemented by a MeshNode-owned **egress proxy** enforcing NetworkConstraints.
///
/// This makes "no cross-connector calling" and "least privilege egress" mechanically enforceable:
/// - Connectors talk to the proxy over capability-gated IPC
/// - Proxy enforces host_allow, port_allow, cidr_deny, SNI, SPKI pins
/// - No SSRF into localhost/tailnet/RFC1918 unless explicitly allowed
/// - DNS resolution goes through proxy with policy checks

impl SandboxConfig {
    /// Create OS-specific sandbox
    pub fn create_sandbox(&self) -> Result<Box<dyn Sandbox>> {
        #[cfg(target_os = "linux")]
        return Ok(Box::new(SeccompSandbox::from_config(self)?));

        #[cfg(target_os = "macos")]
        return Ok(Box::new(SeatbeltSandbox::from_config(self)?));

        #[cfg(target_os = "windows")]
        return Ok(Box::new(AppContainerSandbox::from_config(self)?));
    }
}
```

**Sandbox Enforcement:**
- Resource limits (memory, CPU, time) are enforced by OS
- Filesystem access is limited to declared paths
- Network access is limited to declared capabilities
- Child process spawning can be denied
- Debugging/tracing can be denied

### 11.3 Manifest Embedding

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

Registries are **SOURCES, not dependencies** (NORMATIVE).

This aligns with the digital sovereignty vision: your mesh can mirror and pin connectors
as content-addressed objects so installs/updates work offline and without upstream dependency.

Implementations MUST support at least one of:
1. **Remote registry** (HTTP) — Public registry like registry.flywheel.dev
2. **Self-hosted registry** (HTTP) — Enterprise/private registry
3. **Mesh mirror registry** — Objects pinned in z:owner or z:private

Connector binaries MUST be content-addressed objects and MAY be distributed via the symbol layer.

```
┌───────────────────────────────────────────────────────────┐
│                    REGISTRY SOURCES                        │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  1. Remote Registry (optional)                            │
│     └── registry.flywheel.dev (public)                    │
│     └── registry.enterprise.com (private)                 │
│                                                           │
│  2. Self-Hosted Registry (optional)                       │
│     └── HTTP server with signed manifests                 │
│                                                           │
│  3. Mesh Mirror Registry (recommended)                    │
│     └── Connectors as pinned objects in z:owner           │
│     └── Full offline capability                           │
│     └── Symbol-layer distribution                         │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

```rust
/// Registry source configuration (NORMATIVE)
pub enum RegistrySource {
    /// Remote HTTP registry
    Remote {
        url: Url,
        trusted_keys: Vec<Ed25519PublicKey>,
    },
    /// Self-hosted registry
    SelfHosted {
        url: Url,
        trusted_keys: Vec<Ed25519PublicKey>,
    },
    /// Mesh-native (connectors are objects)
    MeshMirror {
        zone: ZoneId,
        index_object_id: ObjectId,
    },
}

impl RegistrySource {
    /// Fetch connector binary
    pub async fn fetch(&self, connector_id: &ConnectorId) -> Result<ConnectorBinary> {
        match self {
            Self::Remote { url, trusted_keys } | Self::SelfHosted { url, trusted_keys } => {
                let manifest = self.fetch_manifest(url, connector_id).await?;
                manifest.verify_signature(trusted_keys)?;
                let binary = self.fetch_binary(url, &manifest).await?;
                binary.verify_checksum(&manifest)?;
                Ok(binary)
            }
            Self::MeshMirror { zone, index_object_id } => {
                // Reconstruct from local/mesh symbols
                let index = self.mesh_node.reconstruct_object(index_object_id).await?;
                let binary_object_id = index.lookup(connector_id)?;
                let binary = self.mesh_node.reconstruct_object(&binary_object_id).await?;
                Ok(binary)
            }
        }
    }
}

/// Append-only transparency log entry (NORMATIVE if transparency is enabled)
///
/// Provides:
/// - Downgrade detection (someone serves you an older binary)
/// - Equivocation detection (registry serves different binaries to different nodes)
/// - Stable anchor for "what did I install when?"
pub struct ConnectorTransparencyLogEntry {
    pub header: ObjectHeader,
    pub connector_id: ConnectorId,
    pub version: Version,
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub prev: Option<ObjectId>,
    pub published_at: u64,
    /// Signature by publisher quorum or owner
    pub signature: Signature,
}

/// Supply chain attestation (NORMATIVE when policy requires attestations)
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
    /// in-toto provenance statement (SLSA-compatible)
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

**Sovereignty Benefits:**
- Offline installs from mesh-mirrored connectors
- No upstream dependency for air-gapped deployments
- Pin known-good versions and ignore upstream
- Enterprise can point at internal registry

### 13.2 Verification Chain

Before execution, verify (NORMATIVE):
1. Manifest signature (registry or trusted publisher quorum)
2. Binary checksum matches manifest
3. Binary signature matches trusted key
4. Platform/arch match
5. Requested capabilities ⊆ zone ceilings
6. If `policy.require_transparency_log`: release is present in ConnectorTransparencyLog
7. If `policy.require_attestation_types`: all required attestations present and valid
8. If `policy.min_slsa_level > 0`: SLSA provenance meets minimum level
9. If `policy.trusted_builders` non-empty: attestation from trusted builder

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

### 14.3 Revocation (NORMATIVE)

Revocations are mesh objects distributed like any other object and MUST be enforced before use.
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

    /// Enforce revocations for an invoke request
    pub fn enforce(&self, request: &InvokeRequest) -> Result<(), RevocationError> {
        // Check capability token
        if self.is_revoked(&request.capability_token.to_object_id()) {
            return Err(RevocationError::TokenRevoked);
        }

        // Check issuer node attestation
        if self.is_node_revoked(&request.capability_token.iss_node) {
            return Err(RevocationError::IssuerRevoked);
        }

        // Check connector binary
        if let Some(connector_id) = &request.connector_id {
            if self.is_connector_revoked(connector_id) {
                return Err(RevocationError::ConnectorRevoked);
            }
        }

        Ok(())
    }
}
```

**Enforcement Points (NORMATIVE):**
1. Before accepting a capability token
2. Before executing an operation
3. Before accepting symbols for audit head updates
4. Before using zone keys
5. On connector startup

---

## 15. Device-Aware Execution

### 15.1 Execution Leases

Execution leases prevent duplicate side effects and "thrash-migrate" loops:

```rust
/// Execution lease (NORMATIVE)
///
/// Prevents duplicate execution and stabilizes computation migration.
/// A short-lived, renewable lock that says "node X owns execution of request R until time T."
pub struct ExecutionLease {
    pub header: ObjectHeader,
    /// The request/computation being leased
    pub request_object_id: ObjectId,
    /// Which node currently owns execution
    pub owner_node: TailscaleNodeId,
    /// Lease issued at
    pub iat: u64,
    /// Lease expires at (short-lived; renewable)
    pub exp: u64,
    /// Deterministic coordinator for this lease (NORMATIVE)
    /// Selected via HRW/Rendezvous hashing over (zone_id, request_object_id).
    pub coordinator: TailscaleNodeId,
    /// Quorum signatures (NORMATIVE for Risky/Dangerous)
    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
}

/// Lease acquisition request (NORMATIVE)
pub struct LeaseRequest {
    pub header: ObjectHeader,
    pub request_object_id: ObjectId,
    pub desired_owner: TailscaleNodeId,
    pub requested_at: u64,
    pub exp: u64,
    /// Signature by requester node signing key
    pub signature: Signature,
}
```

**Distributed Lease Issuance (NORMATIVE):**

Coordinator selection uses HRW (Rendezvous) hashing:
```rust
fn select_coordinator(zone_id: &ZoneId, request_id: &ObjectId, nodes: &[TailscaleNodeId]) -> TailscaleNodeId {
    nodes.iter()
        .max_by_key(|n| hrw_hash(zone_id, request_id, n))
        .cloned()
        .unwrap()
}
```

**Quorum Rules (NORMATIVE):**
- **Safe ops:** Single coordinator signature MAY be sufficient
- **Risky ops:** Require f+1 signatures (prevents 1 compromised node from unilaterally leasing)
- **Dangerous ops:** Require n-f signatures (matches CriticalWrite default)

**Conflict Rule (NORMATIVE):**

If two valid leases overlap for the same `request_object_id`, nodes MUST:
1. For **Dangerous ops:** Refuse execution and alert owner for manual resolution
2. For **Risky ops:** Pick the lease with higher `(exp, coordinator_id)` and log the fork

**Lease Semantics:**
- For Risky/Dangerous operations, execution MUST require a valid lease
- The executing node must present the lease to run the connector operation
- If the node dies, lease expires and someone else can acquire
- This is a mesh-native way to coordinate without a central coordinator

### 15.2 Device Profiles

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
                DevicePreference::DataLocality { object_ids, weight } => {
                    // Score based on how many required symbols are already local
                    score += weight * device.local_coverage_score(object_ids);
                }
                _ => {}
            }
        }

        // NORMATIVE: Subtract costs that affect real-world execution
        // Secret reconstruction cost (how many peers needed to reconstruct secrets)
        score -= device.estimated_secret_reconstruction_cost(policy) as f64;

        // DERP penalty (prefer direct connections over relay)
        score -= device.derp_penalty() as f64;

        // Symbol locality bonus (fewer symbols to fetch = faster execution)
        score += device.symbol_locality_bonus(policy) as f64;

        score
    }
}

impl DeviceProfile {
    /// Calculate how many required symbols are already local
    fn local_coverage_score(&self, object_ids: &[ObjectId]) -> f64 {
        if object_ids.is_empty() {
            return 1.0;
        }
        let local_count = object_ids.iter()
            .filter(|id| self.symbol_store.has_complete_object(id))
            .count();
        local_count as f64 / object_ids.len() as f64
    }

    /// Estimate cost of reconstructing secrets required by this operation
    fn estimated_secret_reconstruction_cost(&self, policy: &PlacementPolicy) -> u32 {
        // Count how many peer round-trips needed to gather k shares
        let mut cost = 0u32;
        for req in &policy.requires {
            if let DeviceRequirement::SecretReconstructable { secret_id, min_nodes } = req {
                let local_shares = self.count_local_secret_shares(secret_id);
                if local_shares < *min_nodes {
                    cost += (*min_nodes - local_shares) as u32;
                }
            }
        }
        cost
    }

    /// Penalty for using DERP relay instead of direct connection
    fn derp_penalty(&self) -> u32 {
        match &self.current_state.connection_type {
            ConnectionType::Direct => 0,
            ConnectionType::DerpRelay { relay_latency_ms } => relay_latency_ms / 10,
            ConnectionType::Unknown => 50,
        }
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

        // 4. Transfer execution lease ownership (NORMATIVE)
        // Prevents duplicate execution during migration
        mesh.transfer_execution_lease(self.computation_id, &target).await?;

        // 5. Target reconstructs and resumes
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
    /// Verify diversity at frame granularity (not symbol)
    pub fn verify(&self, frames: &[SignedFcpsFrame]) -> Result<()> {
        let nodes: HashSet<_> = frames.iter().map(|f| &f.source_id).collect();
        if nodes.len() < self.min_nodes as usize {
            return Err(Error::InsufficientNodeDiversity);
        }
        Ok(())
    }
}
```

### 17.3 Threshold Secrets

Secrets use real cryptographic secret sharing (Shamir), not just RaptorQ symbols.
RaptorQ symbols are NOT a secret sharing scheme—a single symbol can leak structure.

```rust
/// Secret object (NORMATIVE)
pub struct SecretObject {
    pub header: ObjectHeader,
    /// Unique secret identifier
    pub secret_id: SecretId,
    /// Zone this secret belongs to
    pub zone_id: ZoneId,
    /// Threshold (need k shares to reconstruct)
    pub k: u8,
    /// Total shares distributed
    pub n: u8,
    /// Secret sharing scheme
    pub scheme: SecretSharingScheme,
    /// Wrapped shares (node MUST be unable to decrypt other nodes' shares)
    pub wrapped_shares: HashMap<TailscaleNodeId, Vec<u8>>,
    /// Rotation policy
    pub rotation: SecretRotationPolicy,
}

pub enum SecretSharingScheme {
    /// Shamir's Secret Sharing over GF(2^8)
    ShamirGf256,
}

pub struct SecretRotationPolicy {
    /// Rotate after this many seconds
    pub rotate_after_secs: u64,
    /// Overlap period during rotation (both old and new valid)
    pub overlap_secs: u64,
}

/// Short-lived authorization to reconstruct/use a secret (NORMATIVE)
pub struct SecretAccessToken {
    /// Unique token ID
    pub jti: Uuid,
    /// Which secret can be accessed
    pub secret_id: SecretId,
    /// Purpose of access (for audit)
    pub purpose: String,
    /// Who requested access
    pub requested_by: PrincipalId,
    /// Issued at
    pub iat: u64,
    /// Expires at (short-lived)
    pub exp: u64,
    /// Approver signature (owner or delegated approver)
    pub signature: Signature,
}

impl SecretObject {
    /// Use secret ephemerally (NORMATIVE)
    pub async fn use_secret<F, R>(&self, access_token: &SecretAccessToken, f: F) -> Result<R>
    where F: FnOnce(&[u8]) -> R
    {
        // NORMATIVE: reconstruction requires SecretAccessToken and audit event
        access_token.verify()?;
        self.audit_secret_access(access_token).await?;

        // Collect k wrapped shares from peers
        let shares = self.collect_k_wrapped_shares(access_token).await?;

        // Reconstruct using Shamir
        let secret = reconstruct_shamir_secure(&shares)?;

        let result = f(&secret);

        // Zeroize immediately after use
        secure_zero(secret);

        Ok(result)
    }
}
```

**Why Shamir instead of RaptorQ for secrets:**
- RaptorQ symbols can leak structure (not semantically secure)
- Single RaptorQ symbol may reveal partial information
- Shamir shares reveal nothing until k shares collected
- Wrapped shares ensure a node cannot decrypt other nodes' shares

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

### 19.4 Device Enrollment and Removal (NORMATIVE)

Tailscale gives authenticated transport, but you still need mesh membership semantics.

```rust
/// Device enrollment object (NORMATIVE)
pub struct DeviceEnrollment {
    pub header: ObjectHeader,
    /// Tailscale node being enrolled
    pub node_id: TailscaleNodeId,
    /// Node's signing public key
    pub node_sig_pubkey: Ed25519PublicKey,
    /// Zones this device can participate in
    pub allowed_zones: Vec<ZoneId>,
    /// Storage permissions (what this device can store)
    pub storage_permissions: Vec<StoragePermission>,
    /// When enrollment was issued
    pub issued_at: u64,
    /// Optional expiry
    pub expires_at: Option<u64>,
    /// Owner signature
    pub signature: Signature,
}

pub enum StoragePermission {
    /// Can store symbols for specified zones
    StoreSymbols { zones: Vec<ZoneId> },
    /// Can store secret shares
    StoreSecretShares,
    /// Can store audit events
    StoreAuditEvents,
}
```

**Enrollment Workflow:**
1. New device joins Tailscale tailnet
2. Owner issues `DeviceEnrollment` object (signed)
3. Owner issues `NodeKeyAttestation` binding node to signing key
4. Device receives enrollment and attestation via mesh gossip
5. Other nodes accept the new device as peer

**Removal Workflow:**
On removal, owner MUST publish `RevocationObject` for:
1. `DeviceEnrollment` for the device
2. `NodeKeyAttestation` for the device
3. Any issuer keys bound to the device

And SHOULD trigger:
- Zone key rotation (publish new zone keys)
- Secret resharing (exclude removed device from distribution)

```rust
impl MeshNode {
    /// Remove a device from the mesh
    pub async fn remove_device(&self, node_id: &TailscaleNodeId) -> Result<()> {
        // 1. Revoke device enrollment
        let revocation = RevocationObject {
            revoked: vec![self.get_enrollment_object_id(node_id)?],
            scope: RevocationScope::NodeAttestation,
            reason: "Device removed from mesh".into(),
            ..Default::default()
        };
        self.publish_revocation(revocation).await?;

        // 2. Revoke node attestation
        self.revoke_node_attestation(node_id).await?;

        // 3. Rotate zone keys (required)
        for zone in &self.affected_zones(node_id) {
            self.rotate_zone_key(zone).await?;
        }

        // 4. Reshare secrets (recommended)
        for secret in &self.secrets_with_shares_on(node_id) {
            self.reshare_secret_excluding(secret, node_id).await?;
        }

        Ok(())
    }
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

### 21.3 Background Repair (NORMATIVE)

Nodes MUST periodically evaluate symbol coverage against `ObjectPlacementPolicy` and initiate repair.
Without a placement/repair loop, symbol distribution drifts over time as devices churn.

```rust
/// Background repair controller (NORMATIVE)
pub struct RepairController {
    /// How often to run repair evaluation
    pub interval: Duration,
    /// Maximum symbols to repair per cycle (rate limiting)
    pub max_repairs_per_cycle: u32,
}

impl RepairController {
    /// Evaluate and repair symbol coverage (NORMATIVE)
    pub async fn run_repair_cycle(&self, mesh: &MeshNode) -> RepairResult {
        let mut repaired = 0;

        for zone_id in mesh.active_zones() {
            for object_id in mesh.objects_with_placement_policy(&zone_id) {
                let policy = mesh.get_placement_policy(&object_id)?;
                let coverage = mesh.evaluate_coverage(&object_id).await?;

                // Check if repair needed
                if coverage.distinct_nodes < policy.min_nodes as usize {
                    // Fetch missing symbols from peers
                    mesh.fetch_symbols_for_repair(&object_id).await?;
                    repaired += 1;
                }

                if coverage.max_node_fraction > policy.max_node_fraction {
                    // Re-distribute symbols to reduce concentration
                    mesh.rebalance_symbols(&object_id, &policy).await?;
                    repaired += 1;
                }

                if coverage.ratio < policy.target_coverage {
                    // Generate and distribute repair symbols
                    mesh.distribute_repair_symbols(&object_id, &policy).await?;
                    repaired += 1;
                }

                if repaired >= self.max_repairs_per_cycle {
                    break;
                }
            }
        }

        RepairResult { repaired }
    }
}

/// Symbol coverage evaluation result
pub struct CoverageEvaluation {
    pub object_id: ObjectId,
    /// Number of distinct nodes holding symbols
    pub distinct_nodes: usize,
    /// Highest fraction of symbols on any single node
    pub max_node_fraction: f64,
    /// Coverage ratio: symbols_available / symbols_needed
    pub ratio: f64,
    /// Can object be reconstructed with current coverage?
    pub is_available: bool,
}
```

This is what turns "offline resilience" from a slogan into a quantifiable SLO.

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

### 23.4 Audit Chain (NORMATIVE)

Audit is an append-only, hash-linked object chain per zone. This makes "tamper-evident by construction" a testable, interoperable mechanism.

```rust
/// Audit event (NORMATIVE)
pub struct AuditEvent {
    pub header: ObjectHeader,
    /// Correlation ID for request tracing
    pub correlation_id: [u8; 16],
    /// Optional full trace context (NORMATIVE when present in InvokeRequest)
    /// Enables stitching mesh routing, connector execution, receipts, and audit together.
    pub trace_context: Option<TraceContext>,
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
```

**Quorum Rule (default):** CriticalWrite requires n - f signatures (see §18).
Nodes MUST refuse to advance AuditHead if quorum is not satisfied, unless in explicit degraded mode.

```rust
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

**Fork Detection:** Nodes discovering multiple heads for the same epoch MUST:
1. Log the fork event
2. Refuse to advance until reconciled
3. Alert owner for manual resolution

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
    /// If object size exceeds this threshold, it MUST use ChunkedObjectManifest
    pub max_chunk_threshold: u32, // Default: 256KB
    /// Chunk size for ChunkedObjectManifest
    pub chunk_size: u32,          // Default: 64KB
}
```

### Chunked Objects (RECOMMENDED; NORMATIVE for objects above max_chunk_threshold)

Large objects SHOULD be represented as a manifest that references fixed-size chunk objects.
This enables partial retrieval, bounded memory reconstruction, and targeted repair.

RaptorQ is great for "any K′ symbols reconstruct the whole object", but it forces all-or-nothing
reconstruction and can cause memory spikes for large objects (binaries, attachments, big audit epochs).

Chunking enables:
- Partial retrieval (first chunks first)
- Targeted repair (repair the missing chunk, not the whole object)
- Dedupe across versions (chunk-level content addressing)
- Smoother streaming and bounded memory

```rust
/// Chunked object manifest (NORMATIVE for objects above max_chunk_threshold)
pub struct ChunkedObjectManifest {
    pub header: ObjectHeader,
    /// Total byte length of the original payload
    pub total_len: u64,
    /// Chunk size in bytes (except last)
    pub chunk_size: u32,
    /// Ordered chunk object ids (each chunk is a normal StoredObject)
    pub chunks: Vec<ObjectId>,
    /// BLAKE3 hash of the full payload for end-to-end verification
    pub payload_hash: [u8; 32],
}

/// A chunk is just a normal object with a standard schema and raw bytes body.
pub struct RawChunk {
    pub header: ObjectHeader,
    pub bytes: Vec<u8>,
}
```

**Two Fast Paths Matter Most for Performance:**

1. **Small control-plane requests/responses (<MTU):** Avoid RaptorQ overhead; use direct, authenticated frames.
2. **Large objects/binaries:** Chunking + targeted repair beats "reconstruct monolith" in real systems.

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


# RFC: Mesh-Native Protocol v2 — The Sovereign Compute Fabric

## Abstract

This RFC presents a comprehensive, unified vision for the Flywheel Connector Protocol that synthesizes the foundational ideas from:
- `RFC_Mesh_Native_Protocol.md` — The mesh-native paradigm shift
- `RFC_Universal_Fungibility.md` — Symbol-first data architecture
- `RFC_Sovereign_Mesh.md` — Tailscale deep integration
- `RFC_RaptorQ_Integration.md` — RaptorQ as fundamental primitive

The result is a **Sovereign Compute Fabric**: your devices ARE the cloud, the mesh IS the Hub, and RaptorQ symbols ARE the substrate. All coordination derives from **Tailscale CLI state**, while all data movement uses **RaptorQ symbols**.

---

## 1. The Three Axioms

This protocol is built on three non-negotiable axioms:

### Axiom 1: Universal Fungibility

All data exists as RaptorQ-encoded symbols. Any K' symbols (where K' ≈ K × 1.002) from anywhere can reconstruct the original data. There is no "primary" or "replica"—just symbols distributed across the mesh.

### Axiom 2: Authenticated Mesh

All devices are connected via Tailscale with cryptographic device authentication. Every node is identified by its WireGuard key. All traffic is encrypted. NAT traversal is solved. Discovery is automatic.

**Critical distinction:** Tailscale authenticates the *device*, not the device's integrity. A compromised device still has valid Tailscale credentials. This is why Axiom 3 exists.

### Axiom 3: Explicit Authority

Reconstruction alone is NEVER authority. A reconstructed object is only *valid* if:
- It carries a valid signature from an authorized issuer
- The issuer is trusted per the current PolicyObject
- No RevocationObject invalidates it
- TTL has not expired

This decouples data availability from authority. The mesh makes data available; cryptographic policy makes it authoritative.

---

## 2. Goals and Non-Goals

### 2.1 Goals

- **Single integrated architecture**: One canonical protocol unifying mesh, fungibility, and RaptorQ
- **Zero bespoke control plane**: Use Tailscale CLI surface area as the control plane
- **Explicit authority**: Cryptographic, verifiable, and mesh-aware
- **End-to-end sovereignty**: No external services required to operate the mesh
- **Practical execution**: A spec that can actually be built

### 2.2 Non-Goals

- Replacing Tailscale with a custom identity/ACL system
- Making JSON-RPC the canonical wire protocol (it is compatibility-only)
- Building a hub that re-centralizes orchestration
- Designing for hypothetical future requirements

---

## 3. Layer Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         APPLICATION LAYER                                    │
│   Capabilities • Invocations • Events • Audit • Secrets                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                         OBJECT LAYER                                         │
│   ObjectId • EpochId • SchemaId • Control Objects • Data Objects             │
├─────────────────────────────────────────────────────────────────────────────┤
│                         SYMBOL LAYER                                         │
│   RaptorQ encoding • SymbolEnvelope • Reconstruction • Source Diversity      │
├─────────────────────────────────────────────────────────────────────────────┤
│                         TAILSCALE MESH                                       │
│   Identity • Discovery • ACLs • Certs • Encrypted Transport • DERP • Funnel  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Foundational Primitives

### 4.1 ObjectId: The Universal Address

Everything in FCP is an **Object** with a content-derived **ObjectId**:

```rust
/// Content-addressed object identifier (NORMATIVE)
/// This is THE addressing primitive in FCP
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Derive ObjectId from content with zone and schema binding (NORMATIVE)
    ///
    /// This hybrid model enables:
    /// - Zone binding: Same plaintext in different zones has different ObjectIds
    /// - Schema versioning: Enables canonical serialization migration
    /// - Plaintext-based: Enables deduplication within a zone
    /// - Domain separation: Prevents hash collision attacks
    pub fn derive(
        plaintext: &[u8],
        zone_id: &ZoneId,
        schema_id: &SchemaId,
    ) -> Self {
        let mut hasher = Sha256::new();

        // Domain separation
        hasher.update(b"FCP-OBJECT-ID-V1\x00");

        // Zone binding (prevents cross-zone correlation without zone key)
        hasher.update(zone_id.as_bytes());

        // Schema ID (enables migration, 32 bytes)
        hasher.update(schema_id.as_bytes());

        // Content
        hasher.update(plaintext);

        Self(hasher.finalize().into())
    }

    /// Simple derivation for zone-local objects
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(sha256(data))
    }
}
```

**Critical invariant:** The same plaintext in `z:owner` and `z:work` has DIFFERENT ObjectIds and DIFFERENT encryption keys. Cross-zone correlation requires explicit bridging with provenance tracking.

### 4.2 EpochId: The Universal Temporal Unit

Time in FCP is discrete **Epochs**, not continuous streams:

```rust
/// Epoch identifier (NORMATIVE)
/// Time bucket for temporal ordering
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct EpochId(pub u64);

impl EpochId {
    /// Standard epoch duration: 1 second (configurable per zone)
    pub const DURATION_MS: u64 = 1000;

    /// Current epoch
    pub fn now() -> Self {
        Self(unix_ms() / Self::DURATION_MS)
    }

    /// Epoch from timestamp
    pub fn from_timestamp(ts_ms: u64) -> Self {
        Self(ts_ms / Self::DURATION_MS)
    }

    /// Next epoch
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}
```

**Key semantics:**
- Within an epoch, there is **no ordering**. Events are reconstructed together as a set.
- Ordering only exists **between** epochs.
- Replay operates at epoch granularity.
- For strict ordering, use SequenceObjects (see Section 11.4).

### 4.3 SchemaId: Type-Safe Content Addressing

Every object type has a schema ID derived from its definition:

```rust
/// Schema identification (NORMATIVE)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaId([u8; 32]);

impl SchemaId {
    /// Derive schema ID from schema definition
    pub fn derive(schema_name: &str, version: u32, fields: &[FieldDef]) -> Self {
        let mut hasher = Sha256::new();

        hasher.update(b"FCP-SCHEMA-V1\x00");
        hasher.update(schema_name.as_bytes());
        hasher.update(&version.to_le_bytes());

        for field in fields {
            hasher.update(field.name.as_bytes());
            hasher.update(&[field.field_type as u8]);
            hasher.update(&[if field.optional { 1 } else { 0 }]);
        }

        Self(hasher.finalize().into())
    }
}

/// Standard schema IDs (NORMATIVE)
pub mod schemas {
    use super::SchemaId;

    pub const POLICY_OBJECT: SchemaId = /* derived */;
    pub const ZONE_KEY_EPOCH: SchemaId = /* derived */;
    pub const ISSUER_SET: SchemaId = /* derived */;
    pub const CAPABILITY_OBJECT: SchemaId = /* derived */;
    pub const INVOKE_OBJECT: SchemaId = /* derived */;
    pub const RESPONSE_OBJECT: SchemaId = /* derived */;
    pub const EVENT_EPOCH_OBJECT: SchemaId = /* derived */;
    pub const AUDIT_HEAD_OBJECT: SchemaId = /* derived */;
    pub const REVOCATION_OBJECT: SchemaId = /* derived */;
}
```

### 4.4 ZoneId: Cryptographic Namespace

Zones are not network segments—they are **cryptographic symbol namespaces**:

```rust
/// Zone identifier (NORMATIVE)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ZoneId(pub String);

impl ZoneId {
    pub fn owner() -> Self { Self("z:owner".into()) }
    pub fn private() -> Self { Self("z:private".into()) }
    pub fn work() -> Self { Self("z:work".into()) }
    pub fn community() -> Self { Self("z:community".into()) }
    pub fn public() -> Self { Self("z:public".into()) }

    /// Derive zone from Tailscale tag
    pub fn from_tailscale_tag(tag: &str) -> Option<Self> {
        tag.strip_prefix("tag:fcp-")
            .map(|zone| Self(format!("z:{}", zone)))
    }
}

/// Zone as a cryptographic namespace for symbols (NORMATIVE)
pub struct ZoneNamespace {
    pub zone_id: ZoneId,

    /// Zone encryption key (derived from zone hierarchy + epoch)
    pub zone_key: ZoneKey,

    /// Required sources for reconstruction (source diversity)
    pub min_sources: u8,

    /// Symbol distribution policy
    pub distribution: DistributionPolicy,

    /// Trust level (0-100)
    pub trust_level: u8,
}

pub struct DistributionPolicy {
    /// Minimum devices that should hold symbols
    pub min_devices: u8,

    /// Maximum devices (to limit exposure)
    pub max_devices: u8,

    /// Preferred K value for this zone
    pub preferred_k: u16,

    /// Repair symbol ratio (extra symbols beyond K)
    pub repair_ratio: f32,
}
```

**Zone isolation is cryptographic, not topological.** A device not in a zone cannot decrypt its symbols even if it receives them.

### 4.5 Canonical Serialization

For content-addressing to work, serialization MUST be deterministic. FCP uses **deterministic CBOR** (RFC 8949 Core Deterministic Encoding).

```rust
/// Canonical serialization (NORMATIVE)
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    /// Serialize to canonical bytes
    pub fn serialize<T: Serialize>(value: &T, schema_id: &SchemaId) -> Vec<u8> {
        let mut output = Vec::new();

        // Header: magic + version + schema
        output.extend_from_slice(b"FCP\x00");  // Magic
        output.extend_from_slice(&1u16.to_le_bytes());  // Version
        output.extend_from_slice(schema_id.as_bytes());  // Schema ID (32 bytes)

        // Body: Deterministic CBOR (RFC 8949 Section 4.2)
        ciborium::ser::into_writer_canonical(value, &mut output)
            .expect("serialization must succeed");

        output
    }

    /// Deserialize with schema validation
    pub fn deserialize<T: DeserializeOwned>(
        bytes: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        // Validate header
        if &bytes[0..4] != b"FCP\x00" {
            return Err(SerializationError::InvalidMagic);
        }

        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        if version != 1 {
            return Err(SerializationError::UnsupportedVersion(version));
        }

        let schema_id = SchemaId::from_bytes(&bytes[6..38]);
        if schema_id != *expected_schema {
            return Err(SerializationError::SchemaMismatch {
                expected: expected_schema.clone(),
                actual: schema_id,
            });
        }

        // Deserialize body
        ciborium::de::from_reader(&bytes[38..])
            .map_err(SerializationError::Cbor)
    }
}
```

**Deterministic CBOR Rules (RFC 8949 Section 4.2):**
1. Integer encoding: Smallest possible encoding
2. Map key ordering: Lexicographic by encoded key bytes
3. Floating point: Prefer smallest accurate representation
4. No indefinite-length: All arrays/maps/strings have explicit length
5. No duplicate keys: Maps MUST NOT contain duplicate keys
6. UTF-8 strings: All text strings MUST be valid UTF-8

---

## 5. Symbol Layer

### 5.1 SymbolEnvelope: The Universal Transmission Unit

The fundamental unit of transmission is the **SymbolEnvelope**:

```rust
/// The atomic unit of FCP transmission (NORMATIVE)
/// Everything travels as symbol envelopes
#[derive(Clone, Serialize, Deserialize)]
pub struct SymbolEnvelope {
    // ═══════════════════════════════════════════════════════════════════════
    // OBJECT IDENTITY
    // ═══════════════════════════════════════════════════════════════════════

    /// Which object this symbol belongs to
    pub object_id: ObjectId,

    /// Encoding Symbol ID (unique within object)
    pub esi: u32,

    // ═══════════════════════════════════════════════════════════════════════
    // RECONSTRUCTION PARAMETERS
    // ═══════════════════════════════════════════════════════════════════════

    /// Source symbols needed for reconstruction (K)
    pub k: u16,

    /// Bytes per symbol
    pub symbol_size: u16,

    /// Original object size in bytes
    pub object_size: u32,

    // ═══════════════════════════════════════════════════════════════════════
    // TEMPORAL AND SPATIAL CONTEXT
    // ═══════════════════════════════════════════════════════════════════════

    /// Which epoch this symbol belongs to
    pub epoch_id: EpochId,

    /// Zone namespace
    pub zone_id: ZoneId,

    /// Origin of this symbol (for source diversity verification)
    pub source_id: SourceId,

    // ═══════════════════════════════════════════════════════════════════════
    // THE ACTUAL DATA
    // ═══════════════════════════════════════════════════════════════════════

    /// Symbol data (encrypted with zone key)
    pub data: Vec<u8>,

    /// Authentication tag (AEAD)
    pub auth_tag: [u8; 16],
}
```

### 5.2 Encrypted Symbol Model

ObjectId is derived from plaintext (for deduplication), but symbols are encrypted (for confidentiality):

```rust
/// Encrypted symbol (NORMATIVE)
pub struct EncryptedSymbol {
    /// Object identity (derived from plaintext + zone + schema)
    pub object_id: ObjectId,

    /// Encoding Symbol ID
    pub esi: u32,

    /// Nonce (unique per symbol)
    pub nonce: [u8; 12],

    /// Encrypted symbol data (ChaCha20-Poly1305)
    pub ciphertext: Vec<u8>,

    /// Authentication tag (from AEAD)
    pub auth_tag: [u8; 16],
}

impl EncryptedSymbol {
    /// Encrypt a symbol with zone key
    pub fn encrypt(
        symbol_data: &[u8],
        object_id: ObjectId,
        esi: u32,
        zone_key: &ZoneKey,
    ) -> Self {
        let nonce = generate_unique_nonce(object_id, esi);

        // Additional authenticated data (AAD) binds symbol to object
        let aad = concat!(object_id.as_bytes(), &esi.to_le_bytes());

        let (ciphertext, auth_tag) = zone_key.encrypt(&nonce, symbol_data, &aad);

        Self { object_id, esi, nonce, ciphertext, auth_tag }
    }

    /// Decrypt a symbol with zone key
    pub fn decrypt(&self, zone_key: &ZoneKey) -> Result<Vec<u8>, CryptoError> {
        let aad = concat!(self.object_id.as_bytes(), &self.esi.to_le_bytes());
        zone_key.decrypt(&self.nonce, &self.ciphertext, &self.auth_tag, &aad)
    }
}
```

### 5.3 Cross-Zone Re-encryption

When data crosses zones, it MUST be re-encrypted:

```rust
/// Cross-zone re-encryption (NORMATIVE)
pub fn bridge_to_zone(
    plaintext: &[u8],
    source_zone: &ZoneId,
    target_zone: &ZoneId,
    target_key: &ZoneKey,
    schema_id: &SchemaId,
) -> (ObjectId, Vec<EncryptedSymbol>, Provenance) {
    // New ObjectId for target zone (different due to zone binding)
    let new_object_id = ObjectId::derive(plaintext, target_zone, schema_id);

    // Encode as symbols
    let symbols = encode(plaintext);

    // Encrypt with target zone key
    let encrypted: Vec<_> = symbols.iter()
        .map(|s| EncryptedSymbol::encrypt(&s.data, new_object_id, s.esi, target_key))
        .collect();

    // Mark provenance as tainted
    let provenance = Provenance::zone_crossing(source_zone.clone(), target_zone.clone());

    (new_object_id, encrypted, provenance)
}

/// Provenance tracks data origin and transformations (NORMATIVE)
pub struct Provenance {
    /// Original zone
    pub origin_zone: ZoneId,

    /// Current zone
    pub current_zone: ZoneId,

    /// Zone crossings (audit trail)
    pub crossings: Vec<ZoneCrossing>,

    /// Taint level (increases with each crossing)
    pub taint_level: u8,
}
```

### 5.4 Frame Format (Symbol-Native)

**FCP Symbol Frame Format (FCPS):**

```
┌──────────────────────────────────────────────────────────────────┐
│                    FCP SYMBOL FRAME FORMAT                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Bytes 0-3:   Magic (0x46 0x43 0x50 0x53 = "FCPS")              │
│  Bytes 4-5:   Frame flags (u16 LE)                               │
│  Bytes 6-7:   Symbol count (u16 LE)                              │
│  Bytes 8-15:  Frame timestamp (u64 LE)                           │
│  Bytes 16-47: Frame ID (ObjectId, 32 bytes)                      │
│  Bytes 48+:   [SymbolEnvelope] × symbol_count                    │
│  Final 8:     Checksum (XXH3-64)                                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

```rust
bitflags! {
    pub struct FrameFlags: u16 {
        /// Frame contains RaptorQ symbols
        const RAPTORQ = 0b0000_0000_0001;

        /// Frame is compressed (zstd)
        const COMPRESSED = 0b0000_0000_0010;

        /// Frame contains control objects
        const CONTROL = 0b0000_0000_0100;

        /// Frame requires acknowledgment
        const ACK_REQUIRED = 0b0000_0000_1000;

        /// Frame is a retransmission
        const RETRANSMIT = 0b0000_0001_0000;

        /// Frame contains epoch seal
        const EPOCH_SEAL = 0b0000_0010_0000;
    }
}
```

### 5.5 Multipath by Default

Symbols can be delivered over any mix of paths. All paths contribute simultaneously:

```rust
/// Multipath transport using RaptorQ symbol aggregation (NORMATIVE)
pub struct MultipathTransport {
    /// All available transport paths
    paths: Vec<TransportPath>,

    /// Pending object reconstructions
    pending_objects: HashMap<ObjectId, ObjectDecoder>,

    /// Symbol aggregator
    aggregator: SymbolAggregator,
}

pub enum TransportPath {
    /// Tailscale direct (same LAN)
    TailscaleDirect(TailscaleDirectPath),

    /// Tailscale mesh (NAT traversal)
    TailscaleMesh(TailscaleMeshPath),

    /// Tailscale DERP relay
    TailscaleRelay(DerpPath),

    /// WiFi
    Wifi(UdpSocket),

    /// Cellular
    Cellular(UdpSocket),

    /// Bluetooth
    Bluetooth(BluetoothSocket),
}

impl MultipathTransport {
    /// Latency = min(path latencies)
    /// Bandwidth = sum(path bandwidths)
    pub async fn recv(&mut self) -> Result<ReconstructedObject> {
        loop {
            // Race all paths for next symbol
            let symbol = futures::select_biased! {
                s = self.paths[0].recv_symbol() => s?,
                s = self.paths[1].recv_symbol() => s?,
                // ... for all paths
            };

            // Add to aggregator
            if let Some(object) = self.aggregator.add_symbol(symbol)? {
                return Ok(object);
            }
        }
    }
}
```

**Key insight:** There's no failover logic because there's nothing to fail over from. All paths contribute. Any path can drop symbols—just need K' from the union.

---

## 6. Control Plane (Tailscale-Driven)

### 6.1 Policy Epoch

All nodes compute a **policy epoch** from Tailscale CLI state:

```bash
tailscale status --json > /tmp/ts_status.json
```

Canonicalize a stable subset (tailnet, node IDs, tags, user IDs, expiry) and hash it:

```rust
/// Policy epoch derivation (NORMATIVE)
pub struct PolicyEpoch {
    /// Epoch ID (hash of Tailscale state subset)
    pub epoch_id: [u8; 32],

    /// Tailnet name
    pub tailnet: String,

    /// Online nodes and their tags
    pub nodes: Vec<NodeInfo>,

    /// When this epoch was computed
    pub computed_at: u64,
}

impl PolicyEpoch {
    /// Derive policy epoch from Tailscale status
    pub fn derive(status: &TailscaleStatus) -> Self {
        let mut hasher = Sha256::new();

        hasher.update(b"FCP-POLICY-EPOCH-V1\x00");
        hasher.update(status.tailnet.as_bytes());

        // Sort nodes for determinism
        let mut nodes: Vec<_> = status.peers.iter()
            .map(|(id, peer)| (id, &peer.tags))
            .collect();
        nodes.sort_by_key(|(id, _)| *id);

        for (id, tags) in &nodes {
            hasher.update(id.as_bytes());
            for tag in *tags {
                hasher.update(tag.as_bytes());
            }
        }

        Self {
            epoch_id: hasher.finalize().into(),
            tailnet: status.tailnet.clone(),
            nodes: nodes.into_iter().map(|(id, tags)| NodeInfo {
                node_id: id.clone(),
                tags: tags.clone(),
            }).collect(),
            computed_at: now(),
        }
    }
}
```

**A mesh change == new policy epoch.** Objects authorized under the old epoch may not be valid under the new epoch.

### 6.2 Identity from Tailscale

Identity IS Tailscale identity:

```rust
/// Mesh identity (NORMATIVE)
pub struct MeshIdentity {
    /// Tailscale node ID (derived from WireGuard key)
    pub node_id: TailscaleNodeId,

    /// Tailscale node key (WireGuard public key)
    pub node_key: WireGuardPublicKey,

    /// Tailscale user (who owns this node)
    pub user: TailscaleUser,

    /// Tags from Tailscale ACLs (determine zone membership)
    pub tags: Vec<String>,

    /// Current IP on tailnet
    pub tailnet_ip: IpAddr,

    /// Hostname (e.g., "laptop.tail1234.ts.net")
    pub hostname: String,
}

impl MeshIdentity {
    /// Zone membership is derived from Tailscale tags
    pub fn zones(&self) -> Vec<ZoneId> {
        self.tags.iter()
            .filter_map(|tag| ZoneId::from_tailscale_tag(tag))
            .collect()
    }

    /// Trust level is derived from tags
    pub fn trust_level(&self) -> u8 {
        if self.tags.contains(&"tag:fcp-owner".to_string()) {
            100
        } else if self.tags.contains(&"tag:fcp-private".to_string()) {
            80
        } else if self.tags.contains(&"tag:fcp-work".to_string()) {
            60
        } else if self.tags.contains(&"tag:fcp-community".to_string()) {
            40
        } else {
            0
        }
    }
}
```

### 6.3 Zone-to-Tag Mapping

Tags map directly to zones with defense-in-depth:

```rust
/// Zone-to-tag mapping (NORMATIVE)
pub const ZONE_TAG_MAPPING: &[(&str, &str, u8)] = &[
    ("z:owner",     "tag:fcp-owner",     100),
    ("z:private",   "tag:fcp-private",   80),
    ("z:work",      "tag:fcp-work",      60),
    ("z:community", "tag:fcp-community", 40),
    ("z:public",    /* via Funnel */     0),
];
```

**Tailscale ACL Policy (Auto-Generated):**

```json
{
  "tagOwners": {
    "tag:fcp-owner": ["autogroup:admin"],
    "tag:fcp-private": ["autogroup:admin"],
    "tag:fcp-work": ["autogroup:admin"],
    "tag:fcp-community": ["autogroup:admin"]
  },

  "acls": [
    {
      "action": "accept",
      "src": ["tag:fcp-owner"],
      "dst": ["tag:fcp-owner:*", "tag:fcp-private:*", "tag:fcp-work:*"]
    },
    {
      "action": "accept",
      "src": ["tag:fcp-private"],
      "dst": ["tag:fcp-private:*", "tag:fcp-work:*"]
    },
    {
      "action": "accept",
      "src": ["tag:fcp-work"],
      "dst": ["tag:fcp-work:*"]
    },
    {
      "action": "accept",
      "src": ["autogroup:internet"],
      "dst": ["tag:fcp-community:443"]
    }
  ]
}
```

**Key insight:** Zone isolation is enforced at the NETWORK LEVEL. A compromised work device literally cannot send packets to owner devices. This is defense-in-depth on top of FCP's application-level enforcement.

### 6.4 ACL Generator

```rust
/// Generate Tailscale ACLs from FCP zone configuration (NORMATIVE)
pub struct AclGenerator {
    zones: Vec<ZoneConfig>,
}

impl AclGenerator {
    /// Generate complete Tailscale ACL policy
    pub fn generate(&self) -> TailscaleAclPolicy {
        let mut policy = TailscaleAclPolicy::new();

        // Tag owners (admin controls all FCP tags)
        for zone in &self.zones {
            let tag = self.zone_to_tag(&zone.id);
            policy.tag_owners.insert(tag, vec!["autogroup:admin".into()]);
        }

        // ACL rules based on zone data flow policies
        for zone in &self.zones {
            let src_tag = self.zone_to_tag(&zone.id);

            // Zone can access itself
            policy.acls.push(AclRule {
                action: AclAction::Accept,
                src: vec![src_tag.clone()],
                dst: vec![format!("{}:*", src_tag)],
            });

            // Outbound access per data flow policy
            for target_zone in &zone.data_flow.outbound_to {
                let dst_tag = self.zone_to_tag(target_zone);
                policy.acls.push(AclRule {
                    action: AclAction::Accept,
                    src: vec![src_tag.clone()],
                    dst: vec![format!("{}:9473", dst_tag)],  // FCP port
                });
            }
        }

        policy
    }

    fn zone_to_tag(&self, zone: &ZoneId) -> String {
        format!("tag:fcp-{}", zone.0.strip_prefix("z:").unwrap_or(&zone.0))
    }
}
```

---

## 7. The Mesh as Compute Fabric

### 7.1 MeshNode: Every Device IS the Hub

There is no separate "Hub" process. Every device runs a MeshNode, and together they form the distributed Hub:

```rust
/// Every device runs a MeshNode (NORMATIVE)
/// Together, they form the distributed Hub
pub struct MeshNode {
    // ═══════════════════════════════════════════════════════════════════════
    // IDENTITY (from Tailscale)
    // ═══════════════════════════════════════════════════════════════════════

    /// My Tailscale node identity
    pub identity: MeshIdentity,

    /// My current policy epoch
    pub policy_epoch: PolicyEpoch,

    // ═══════════════════════════════════════════════════════════════════════
    // PEER AWARENESS
    // ═══════════════════════════════════════════════════════════════════════

    /// Known peers (discovered via Tailscale)
    pub peers: HashMap<TailscaleNodeId, PeerInfo>,

    /// Gossip state (what peers have what)
    pub gossip: MeshGossip,

    // ═══════════════════════════════════════════════════════════════════════
    // DISTRIBUTED STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// Mesh state as symbols (distributed across all nodes)
    pub mesh_state: DistributedSymbolStore,

    /// Local symbol cache
    pub local_symbols: SymbolStore,

    // ═══════════════════════════════════════════════════════════════════════
    // LOCAL EXECUTION
    // ═══════════════════════════════════════════════════════════════════════

    /// Local capability executor
    pub executor: CapabilityExecutor,

    /// Active computations on this node
    pub active_computations: HashMap<ComputationId, ActiveComputation>,

    /// Device profile (hardware capabilities)
    pub device_profile: DeviceProfile,
}

impl MeshNode {
    /// Any MeshNode can handle any request
    pub async fn handle_request(&self, request: InvokeObject) -> Result<ResponseObject> {
        // 1. What capability is being invoked?
        let capability_id = request.capability_object_id;

        // 2. Reconstruct the capability definition
        let capability = self.reconstruct_capability(capability_id).await?;

        // 3. Validate authority
        capability.validate(&self.trust_anchors())?;

        // 4. Who can execute this?
        let executors = self.gossip.who_can_execute(capability.capability_id);

        if executors.is_empty() {
            // No one can execute—spawn the capability
            return self.spawn_and_execute(capability, request).await;
        }

        // 5. Choose best executor based on scoring
        let best = self.execution_planner.choose(&capability, &request);

        // 6. Execute (locally or forward via Tailscale)
        if best == self.identity.node_id {
            self.execute_local(capability, request).await
        } else {
            self.forward_to_peer(best, request).await
        }
    }
}
```

### 7.2 MeshCapability: Executable Objects

Capabilities are objects in symbol space that can execute anywhere:

```rust
/// A capability is not a running process—it's an executable object (NORMATIVE)
pub struct MeshCapability {
    // ═══════════════════════════════════════════════════════════════════════
    // IDENTITY
    // ═══════════════════════════════════════════════════════════════════════

    /// Capability definition
    pub capability_id: CapabilityId,

    /// Content-addressed (THE identity)
    pub object_id: ObjectId,

    // ═══════════════════════════════════════════════════════════════════════
    // EXECUTABLE COMPONENTS (all as objects in symbol space)
    // ═══════════════════════════════════════════════════════════════════════

    /// The binary (WASM or native)
    pub binary_object_id: ObjectId,

    /// Configuration
    pub config_object_id: ObjectId,

    /// Current state (distributed as symbols)
    pub state: DistributedState,

    // ═══════════════════════════════════════════════════════════════════════
    // EXECUTION CONSTRAINTS
    // ═══════════════════════════════════════════════════════════════════════

    /// Where can this execute?
    pub placement: PlacementPolicy,

    /// Zone requirements
    pub required_zones: Vec<ZoneId>,

    /// Operations this capability allows
    pub operations: Vec<OperationSpec>,

    /// Authority constraints
    pub constraints: CapabilityConstraints,
}

/// Placement policy for capability execution (NORMATIVE)
pub struct PlacementPolicy {
    /// Required Tailscale tags
    pub required_tags: Vec<String>,

    /// Required hardware capabilities
    pub required_hardware: Vec<HardwareRequirement>,

    /// Allowed zones for execution
    pub allowed_zones: Vec<ZoneId>,

    /// Excluded devices (blocklist)
    pub excluded_devices: Vec<TailscaleNodeId>,

    /// Require user presence?
    pub requires_user_presence: bool,

    /// Require plugged-in power?
    pub requires_power: bool,
}

pub enum HardwareRequirement {
    Gpu,
    Browser,
    Display,
    TrustedEnclave,
    MinMemoryGb(u32),
    MinCpuCores(u32),
}
```

### 7.3 DistributedState: State IS Symbol Distribution

There is no "database" or "storage" in the traditional sense. State IS the symbol distribution:

```rust
/// State doesn't "live" anywhere—it IS the mesh (NORMATIVE)
pub struct DistributedState {
    /// The state object
    pub object_id: ObjectId,

    /// Symbol distribution across mesh
    pub symbol_locations: HashMap<SymbolId, Vec<TailscaleNodeId>>,

    /// Reconstruction parameters
    pub k: u16,  // Symbols needed to reconstruct
}

impl DistributedState {
    /// Current coverage (ratio of online symbols to K)
    pub fn coverage(&self) -> f64 {
        let online_symbols = self.count_symbols_on_online_nodes();
        online_symbols as f64 / self.k as f64
    }

    /// Probability of successful reconstruction right now
    pub fn reconstruction_probability(&self) -> f64 {
        let online = self.count_symbols_on_online_nodes();
        if online >= self.k as usize {
            1.0  // Guaranteed
        } else {
            // Probability of getting remaining symbols
            self.estimate_availability(self.k as usize - online)
        }
    }

    /// Materialize state on demand
    pub async fn materialize(&self) -> Result<Vec<u8>> {
        let symbols = self.collect_symbols().await?;
        reconstruct(symbols)
    }

    /// Update state (creates new object, distributes new symbols)
    pub async fn update(&mut self, new_data: &[u8]) -> Result<()> {
        let new_object_id = ObjectId::from_bytes(new_data);
        let symbols = encode(new_data);
        self.distribute_symbols(symbols).await?;
        self.object_id = new_object_id;
        Ok(())
    }
}
```

### 7.4 The Gossip Layer

Nodes gossip about what they have and what they can do:

```rust
/// Mesh-wide gossip for discovery and coordination (NORMATIVE)
pub struct MeshGossip {
    // ═══════════════════════════════════════════════════════════════════════
    // WHAT I HAVE
    // ═══════════════════════════════════════════════════════════════════════

    /// Objects I have symbols for (bloom filter for efficiency)
    pub objects_known: BloomFilter<ObjectId>,

    /// Symbols I hold locally
    pub symbols_held: BloomFilter<SymbolId>,

    // ═══════════════════════════════════════════════════════════════════════
    // WHAT I CAN DO
    // ═══════════════════════════════════════════════════════════════════════

    /// Capabilities I can execute
    pub capabilities: Vec<CapabilityId>,

    /// My hardware profile
    pub hardware: HardwareProfile,

    /// Current resource availability
    pub availability: ResourceAvailability,

    // ═══════════════════════════════════════════════════════════════════════
    // MESH STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// Peer gossip states (what I know about others)
    pub peer_states: HashMap<TailscaleNodeId, PeerGossipState>,

    /// Vector clock (for consistency)
    pub vector_clock: VectorClock,
}

impl MeshGossip {
    /// Gossip to peers periodically
    pub async fn gossip_round(&mut self, peers: &[TailscaleNodeId]) {
        let my_state = self.to_gossip_message();

        for peer in peers {
            // Send my state
            let their_state = peer.exchange_gossip(my_state.clone()).await;

            // Merge their state
            self.merge_peer_state(peer, their_state);
        }
    }

    /// Find who has symbols for an object
    pub fn who_has(&self, object_id: ObjectId) -> Vec<TailscaleNodeId> {
        self.peer_states.iter()
            .filter(|(_, state)| state.objects_known.may_contain(&object_id))
            .map(|(node, _)| node.clone())
            .collect()
    }

    /// Find who can execute a capability
    pub fn who_can_execute(&self, capability_id: CapabilityId) -> Vec<TailscaleNodeId> {
        self.peer_states.iter()
            .filter(|(_, state)| state.capabilities.contains(&capability_id))
            .map(|(node, _)| node.clone())
            .collect()
    }
}
```

---

## 8. Device-Aware Execution

### 8.1 Device Profiles

Different devices are suited for different tasks:

```rust
/// Device profiles for execution planning (NORMATIVE)
pub struct DeviceProfile {
    pub node_id: TailscaleNodeId,

    /// Hardware capabilities
    pub gpu: Option<GpuInfo>,
    pub cpu_cores: u32,
    pub memory_gb: u32,
    pub storage_gb: u32,

    /// Current state
    pub power_source: PowerSource,  // Battery or PluggedIn
    pub battery_level: Option<u8>,
    pub current_load: f64,

    /// Context
    pub has_display: bool,
    pub has_browser: bool,
    pub user_active: bool,
    pub has_secure_enclave: bool,

    /// Network
    pub connection_type: ConnectionType,  // Direct, DERP, etc.
    pub latency_ms: HashMap<TailscaleNodeId, u32>,
}

pub enum PowerSource {
    Battery,
    PluggedIn,
}

impl DeviceProfile {
    /// Can this device execute a capability with given placement policy?
    pub fn can_execute(&self, placement: &PlacementPolicy) -> bool {
        // Check hardware requirements
        for req in &placement.required_hardware {
            match req {
                HardwareRequirement::Gpu => if self.gpu.is_none() { return false; }
                HardwareRequirement::Browser => if !self.has_browser { return false; }
                HardwareRequirement::Display => if !self.has_display { return false; }
                HardwareRequirement::TrustedEnclave => if !self.has_secure_enclave { return false; }
                HardwareRequirement::MinMemoryGb(min) => if self.memory_gb < *min { return false; }
                HardwareRequirement::MinCpuCores(min) => if self.cpu_cores < *min { return false; }
            }
        }

        // Check power requirement
        if placement.requires_power && self.power_source == PowerSource::Battery {
            return false;
        }

        // Check user presence
        if placement.requires_user_presence && !self.user_active {
            return false;
        }

        true
    }
}
```

### 8.2 Execution Planner

The execution planner chooses the optimal device:

```rust
/// Execution planner chooses optimal device (NORMATIVE)
pub struct ExecutionPlanner {
    pub mesh: Arc<MeshNode>,
}

impl ExecutionPlanner {
    /// Choose best device for a capability invocation
    pub fn choose(&self, capability: &MeshCapability, request: &InvokeObject) -> TailscaleNodeId {
        let viable: Vec<_> = self.mesh.peers.keys()
            .filter(|p| self.can_execute(p, &capability.placement))
            .collect();

        if viable.is_empty() {
            panic!("No viable execution host!");
        }

        viable.into_iter()
            .max_by_key(|p| self.score(p, capability, request))
            .unwrap()
            .clone()
    }

    fn score(
        &self,
        node: &TailscaleNodeId,
        capability: &MeshCapability,
        request: &InvokeObject,
    ) -> i64 {
        let profile = self.mesh.get_profile(node);
        let mut score = 0i64;

        // Lower latency is better (weight: -1 per ms)
        let latency = profile.latency_ms
            .get(&self.mesh.identity.node_id)
            .copied()
            .unwrap_or(1000);
        score -= latency as i64;

        // Lower load is better
        score -= (profile.current_load * 1000.0) as i64;

        // Plugged in is better for heavy work (+500)
        if profile.power_source == PowerSource::PluggedIn {
            score += 500;
        }

        // GPU bonus if capability needs GPU (+1000)
        if capability.placement.required_hardware.contains(&HardwareRequirement::Gpu)
            && profile.gpu.is_some()
        {
            score += 1000;
        }

        // Data locality bonus (+300 per object)
        for object_id in &capability.data_affinity {
            if self.mesh.gossip.node_has_symbols(node, object_id) {
                score += 300;
            }
        }

        // User presence bonus if required (+500)
        if capability.placement.requires_user_presence && profile.user_active {
            score += 500;
        }

        score
    }
}
```

**Execution Examples:**
- **Gmail OAuth**: Run on device with browser and user presence
- **Heavy ML inference**: Run on desktop with GPU, plugged in
- **Quick lookup**: Run on nearest device with lowest latency
- **Background sync**: Run on always-on server
- **Sensitive operation**: Run on device with secure enclave

---

## 9. Computation Migration

### 9.1 Migratable Computation

Long-running computations can checkpoint and migrate:

```rust
/// Computation migration across mesh (NORMATIVE)
pub struct MigratableComputation {
    /// Computation identity
    pub computation_id: ComputationId,

    /// What capability is being computed
    pub capability_id: CapabilityId,

    /// Current state (as symbols)
    pub state: DistributedState,

    /// Current host
    pub current_host: TailscaleNodeId,

    /// Checkpoint interval
    pub checkpoint_interval: Duration,

    /// Last checkpoint
    pub last_checkpoint: Option<CheckpointObject>,
}

impl MigratableComputation {
    /// Migrate to a different host
    pub async fn migrate(&mut self, new_host: TailscaleNodeId) -> Result<()> {
        // 1. Checkpoint current state
        let checkpoint = self.checkpoint().await?;

        // 2. Encode checkpoint as symbols and send to new host
        let symbols = encode(&checkpoint);
        new_host.receive_symbols(symbols).await?;

        // 3. Resume on new host
        new_host.resume_computation(self.computation_id, checkpoint).await?;

        // 4. Stop local execution
        self.stop_local();

        // 5. Update current host
        self.current_host = new_host;

        info!("Migrated computation {} to {}", self.computation_id, new_host);

        Ok(())
    }

    /// Proactive migration when better host available
    pub async fn consider_migration(&mut self, mesh: &MeshNode) -> Result<()> {
        let current_score = self.score_host(&self.current_host);

        for (peer, info) in &mesh.peers {
            let peer_score = self.score_host(peer);

            // Migrate if significantly better (with hysteresis to avoid flapping)
            if peer_score > current_score * 1.5 {
                info!("Migrating computation {} to {} (score {} > {})",
                    self.computation_id, peer, peer_score, current_score);
                return self.migrate(peer.clone()).await;
            }
        }

        Ok(())
    }
}
```

### 9.2 Checkpoint Objects

```rust
/// Checkpoint for computation migration (NORMATIVE)
pub struct CheckpointObject {
    pub header: ObjectHeader,

    /// Computation being checkpointed
    pub computation_id: ComputationId,

    /// Serialized computation state
    pub state: Vec<u8>,

    /// Input cursor (how much input consumed)
    pub input_cursor: u64,

    /// Output cursor (how much output produced)
    pub output_cursor: u64,

    /// Pending operations
    pub pending_ops: Vec<PendingOperation>,

    /// Checkpoint timestamp
    pub checkpointed_at: u64,
}
```

**Use case:** You're running a long computation on your laptop. You need to leave. The computation migrates to your desktop and continues. When you get home, results are waiting.

---

## 10. Security Model

### 10.1 Control Plane vs Data Plane

Everything being a symbol is elegant but risky for governance. The protocol separates control and data planes with different authority requirements:

```rust
/// Control object types (require signature verification) (NORMATIVE)
pub enum ControlObject {
    /// Root policy (signed by Owner Root Key only)
    Policy(PolicyObject),

    /// Zone key epochs (signed by Owner Root Key)
    ZoneKeyEpoch(ZoneKeyEpoch),

    /// Issuer set (who may sign capabilities)
    IssuerSet(IssuerSet),

    /// Capability definitions (signed by IssuerSet member)
    Capability(CapabilityObject),

    /// Principal claims (principal-device binding)
    PrincipalClaim(PrincipalClaim),

    /// Revocations (invalidate earlier objects)
    Revocation(RevocationObject),

    /// Audit chain heads (quorum-signed)
    AuditHead(AuditHeadObject),
}

/// Data object types (authorized by control objects) (NORMATIVE)
pub enum DataObject {
    /// Capability invocation
    Invoke(InvokeObject),

    /// Invocation response
    Response(ResponseObject),

    /// Event epochs
    EventEpoch(EventEpochObject),

    /// Health snapshots
    Health(HealthObject),
}
```

**The Critical Rule:** Reconstruction ≠ Authority. A control object reconstructed from symbols is merely *available*, not *valid*. Validity requires:
1. Signature verification against trusted issuer
2. Issuer authorization per PolicyObject
3. No superseding RevocationObject
4. TTL not expired

### 10.2 Concrete Object Schemas

#### 10.2.1 ObjectHeader (All Objects)

```rust
/// Common header for all mesh objects (NORMATIVE)
pub struct ObjectHeader {
    /// Schema identifier (e.g., "fcp.obj.capability.v2")
    pub schema_id: SchemaId,

    /// Content-addressed object ID
    /// = sha256(canonical_serialize(body) || zone_id || schema_id)
    pub object_id: ObjectId,

    /// Cryptographic zone namespace
    pub zone_id: ZoneId,

    /// Temporal bucket
    pub epoch_id: EpochId,

    /// Creation timestamp (advisory)
    pub created_at_ms: u64,

    /// Who signed this object
    pub issuer: IssuerId,

    /// Signature over canonical body
    pub signature: Signature,
}
```

#### 10.2.2 PolicyObject (Root Authority)

```rust
/// Root policy object (NORMATIVE)
/// Authority: signed by Owner Root Key ONLY
pub struct PolicyObject {
    pub header: ObjectHeader,

    /// Stable policy identifier
    pub policy_id: String,

    /// Zone policies
    pub zones: Vec<ZonePolicy>,

    /// Who may issue capabilities
    pub issuers: Vec<IssuerPolicy>,

    /// Principal authorization rules
    pub principal_rules: Vec<PrincipalRule>,

    /// Revocation policy
    pub revocation_policy: RevocationPolicy,

    /// Audit quorum requirement
    pub audit_quorum: u8,

    /// When this policy takes effect
    pub effective_from_epoch: EpochId,

    /// Optional expiry
    pub expires_at_epoch: Option<EpochId>,
}

pub struct ZonePolicy {
    pub zone_id: ZoneId,
    pub trust_level: u8,
    pub capability_allow: Vec<GlobPattern>,
    pub capability_deny: Vec<GlobPattern>,
    pub flow_rules: Vec<FlowRule>,
}

pub struct IssuerPolicy {
    pub issuer_id: IssuerId,
    pub allowed_capabilities: Vec<GlobPattern>,
    pub min_quorum: u8,
}

pub struct RevocationPolicy {
    pub max_ttl_epochs: u64,
    pub require_revocation_objects: bool,
}
```

#### 10.2.3 ZoneKeyEpoch (Zone Encryption Lifecycle)

```rust
/// Zone encryption key epoch (NORMATIVE)
/// Authority: signed by Owner Root Key
pub struct ZoneKeyEpoch {
    pub header: ObjectHeader,

    /// Which zone
    pub zone_id: ZoneId,

    /// Epoch range for this key
    pub epoch_start: EpochId,
    pub epoch_end: EpochId,

    /// Key identifier
    pub key_id: String,

    /// Key material (encrypted to authorized devices)
    pub key_material_encrypted: Vec<u8>,

    /// Why rotated (if applicable)
    pub rotation_reason: Option<String>,
}
```

#### 10.2.4 IssuerSet (Capability Issuer Authority)

```rust
/// Issuer set definition (NORMATIVE)
/// Authority: signed by Owner Root Key
pub struct IssuerSet {
    pub header: ObjectHeader,

    /// Stable issuer set ID
    pub issuer_set_id: String,

    /// Device or service keys allowed to issue
    pub allowed_issuers: Vec<IssuerId>,

    /// Quorum requirement (optional)
    pub threshold: u8,

    /// Validity range
    pub effective_from_epoch: EpochId,
    pub expires_at_epoch: Option<EpochId>,
}
```

#### 10.2.5 CapabilityObject (with PlacementPolicy)

```rust
/// Capability definition (NORMATIVE)
/// Authority: signed by member of authorized IssuerSet
pub struct CapabilityObject {
    pub header: ObjectHeader,

    /// Capability identity
    pub capability_id: CapabilityId,

    /// Operations this capability allows
    pub operations: Vec<OperationSpec>,

    /// Authorization constraints
    pub constraints: CapabilityConstraints,

    /// WHERE this capability may execute
    pub placement: PlacementPolicy,

    /// Short-lived by default
    pub ttl_epochs: u64,

    /// Which issuer set authorized this
    pub issuer_set_id: String,
}

pub struct OperationSpec {
    pub operation_id: OperationId,
    pub risk_level: RiskLevel,
    pub safety_tier: SafetyTier,
    pub idempotency: IdempotencyClass,
    pub input_schema: SchemaId,
    pub output_schema: SchemaId,
}
```

#### 10.2.6 AuditHeadObject (Quorum-Anchored)

```rust
/// Audit chain head (NORMATIVE)
/// Authority: signed by quorum of owner/admin devices
pub struct AuditHeadObject {
    pub header: ObjectHeader,

    /// Which epoch this head covers
    pub epoch_id: EpochId,

    /// Merkle root of audit entries
    pub merkle_root: [u8; 32],

    /// Previous audit head
    pub prev_audit_head_id: ObjectId,

    /// Quorum signatures (multiple devices)
    pub quorum_signatures: Vec<QuorumSignature>,
}

pub struct QuorumSignature {
    pub signer_id: IssuerId,
    pub signature: Signature,
    pub signed_at: u64,
}

impl AuditHeadObject {
    /// Verify quorum requirement met
    pub fn verify_quorum(&self, trust_anchors: &TrustAnchors) -> Result<()> {
        let policy = trust_anchors.current_policy();
        let required_quorum = policy.audit_quorum;

        let valid_sigs = self.quorum_signatures.iter()
            .filter(|sig| self.verify_signer(sig, trust_anchors).is_ok())
            .count();

        if valid_sigs < required_quorum as usize {
            return Err(Error::InsufficientQuorum {
                required: required_quorum,
                actual: valid_sigs as u8,
            });
        }

        Ok(())
    }
}
```

### 10.3 Source Diversity as Distributed Trust

Critical objects require symbols from multiple sources:

```rust
/// Require source diversity for reconstruction (NORMATIVE)
pub struct DiversityPolicy {
    /// Minimum distinct Tailscale nodes
    pub min_nodes: u8,

    /// Minimum distinct zones
    pub min_zones: u8,

    /// No single node can contribute more than this fraction
    pub max_node_fraction: f64,
}

impl DiversityPolicy {
    /// Verify diversity before allowing reconstruction
    pub fn verify(&self, symbols: &[SymbolEnvelope]) -> Result<()> {
        let nodes: HashSet<_> = symbols.iter().map(|s| &s.source_id).collect();
        let zones: HashSet<_> = symbols.iter().map(|s| &s.zone_id).collect();

        if nodes.len() < self.min_nodes as usize {
            return Err(Error::InsufficientNodeDiversity {
                required: self.min_nodes,
                actual: nodes.len() as u8,
            });
        }

        if zones.len() < self.min_zones as usize {
            return Err(Error::InsufficientZoneDiversity {
                required: self.min_zones,
                actual: zones.len() as u8,
            });
        }

        // Check concentration
        let counts: HashMap<_, usize> = symbols.iter()
            .fold(HashMap::new(), |mut m, s| {
                *m.entry(&s.source_id).or_insert(0) += 1;
                m
            });

        let max_from_one = counts.values().max().copied().unwrap_or(0);
        let max_fraction = max_from_one as f64 / symbols.len() as f64;

        if max_fraction > self.max_node_fraction {
            return Err(Error::ExcessiveConcentration {
                max_allowed: self.max_node_fraction,
                actual: max_fraction,
            });
        }

        Ok(())
    }
}
```

**Key insight:** Requiring symbols from multiple nodes means no single compromised node can forge data. This is distributed trust enforced by reconstruction semantics.

### 10.4 Threshold Secrets

Secrets are distributed as k-of-n symbol sets—they never exist complete on any device:

```rust
/// Secret distributed as symbols—never exists complete on any device (NORMATIVE)
pub struct ThresholdSecret {
    /// Secret identity
    pub secret_id: SecretId,
    pub object_id: ObjectId,

    /// Threshold parameters
    pub k: u8,  // Need k symbols
    pub n: u8,  // Distributed across n devices

    /// Symbol distribution (each device has at most 1 symbol)
    pub distribution: HashMap<TailscaleNodeId, SymbolId>,

    /// Zone requirements
    pub required_zone: ZoneId,
}

impl ThresholdSecret {
    /// Create a new threshold secret
    pub async fn create(
        secret: &[u8],
        k: u8,
        devices: &[TailscaleNodeId],
    ) -> Result<Self> {
        let n = devices.len() as u8;
        assert!(k <= n, "k must be <= n");

        let object_id = ObjectId::from_bytes(secret);

        // Encode as symbols
        let symbols = encode(secret, k as u16);

        // Distribute one symbol per device
        let mut distribution = HashMap::new();
        for (i, device) in devices.iter().enumerate() {
            let symbol = &symbols[i % symbols.len()];
            device.store_secret_symbol(symbol).await?;
            distribution.insert(device.clone(), symbol.id());
        }

        // The secret itself is now zeroed—only symbols exist

        Ok(Self {
            secret_id: SecretId::new(),
            object_id,
            k,
            n,
            distribution,
            required_zone: ZoneId::owner(),
        })
    }

    /// Use the secret (reconstruct ephemerally)
    pub async fn use_secret<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Collect k symbols from online devices
        let symbols = self.collect_k_symbols().await?;

        // Verify source diversity
        self.verify_diversity(&symbols)?;

        // Reconstruct in secure memory
        let secret = reconstruct_secure(&symbols)?;

        // Use it
        let result = f(&secret);

        // Zero immediately
        secure_zero(secret);

        Ok(result)
    }
}
```

**Key insight:** Your API keys, OAuth tokens, private keys—NONE of them exist complete on any device. A stolen laptop is useless. You need k devices to reconstruct.

---

## 11. Trust Model and Byzantine Assumptions

### 11.1 Threat Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              THREAT MODEL                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TRUSTED:                                                                   │
│  - Tailscale identity (WireGuard keys are unforgeable)                     │
│  - Cryptographic primitives (ChaCha20, Ed25519, SHA256)                    │
│  - Owner's root key (assumed not compromised)                              │
│                                                                             │
│  ASSUMED POSSIBLE (must defend against):                                   │
│  - Compromised device (attacker has full device access)                    │
│  - Malicious peer (valid Tailscale identity, malicious behavior)           │
│  - Symbol injection (attacker injects malformed symbols)                   │
│  - Replay attacks (attacker replays old valid symbols)                     │
│  - Denial of service (attacker floods with symbols)                        │
│  - Offline attacks (attacker captures encrypted symbols)                   │
│                                                                             │
│  OUT OF SCOPE:                                                              │
│  - Tailscale control plane compromise                                       │
│  - Quantum cryptanalysis                                                    │
│  - Physical device extraction (side channels)                               │
│  - Owner key compromise                                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 Byzantine Fault Tolerance

**Core assumption:** Up to f of n devices may be compromised, where f < n/3 for critical operations.

```rust
/// Byzantine fault tolerance model (NORMATIVE)
pub struct ByzantineModel {
    /// Total devices in mesh
    pub n: u8,

    /// Maximum compromised devices
    pub f: u8,
}

impl ByzantineModel {
    /// Invariant: f < n/3 for safety
    pub fn is_safe(&self) -> bool {
        3 * self.f < self.n
    }
}

/// Operation classification by required quorum (NORMATIVE)
pub enum OperationClass {
    /// Read-only, single device sufficient
    ReadOnly,

    /// Normal write, majority sufficient
    /// Quorum: (n + f + 1) / 2
    NormalWrite,

    /// Critical operation, supermajority required
    /// Example: capability issuance, revocation
    /// Quorum: n - f
    CriticalWrite,

    /// Unanimous, all devices must agree
    /// Example: owner key rotation
    Unanimous,
}

impl OperationClass {
    pub fn required_quorum(&self, n: u8, f: u8) -> u8 {
        match self {
            Self::ReadOnly => 1,
            Self::NormalWrite => (n + f + 1) / 2,
            Self::CriticalWrite => n - f,
            Self::Unanimous => n,
        }
    }
}
```

### 11.3 Defense-in-Depth Model

```
Layer 1: Tailscale ACLs     → Network-level isolation (can't even send packets)
Layer 2: Zone Encryption    → Cryptographic isolation (can't decrypt symbols)
Layer 3: Policy Objects     → Authority isolation (can't forge valid objects)
Layer 4: Capability Signing → Operation isolation (can't execute unauthorized ops)
```

Each layer adds protection. Compromise of one layer doesn't compromise all.

### 11.4 Ordering and Consistency

#### 11.4.1 Epoch Model (Default)

By default, FCP uses epoch-based ordering:
- Events in the same epoch have no defined order
- Ordering exists only between epochs
- This enables parallel processing and natural batching

#### 11.4.2 SequenceObjects (Strict Ordering)

For operations requiring strict ordering:

```rust
/// Sequence object for strict ordering (NORMATIVE)
pub struct SequenceObject {
    /// Sequence identity
    pub sequence_id: SequenceId,

    /// What zone owns this sequence
    pub zone_id: ZoneId,

    /// Current sequence number
    pub current_seq: u64,

    /// Previous sequence object (forms chain)
    pub previous: ObjectId,
}

/// Sequenced operation wrapper
pub struct SequencedOperation<T> {
    /// The operation
    pub operation: T,

    /// Sequence number (MUST be exactly previous + 1)
    pub seq: u64,

    /// Reference to previous operation
    pub previous_op: ObjectId,
}

impl<T> SequencedOperation<T> {
    /// Verify sequence integrity
    pub fn verify_sequence(&self, previous: &SequencedOperation<T>) -> Result<()> {
        if self.seq != previous.seq + 1 {
            return Err(SequenceError::Gap {
                expected: previous.seq + 1,
                actual: self.seq,
            });
        }

        if self.previous_op != previous.object_id() {
            return Err(SequenceError::BrokenChain);
        }

        Ok(())
    }
}
```

#### 11.4.3 Consistency Levels

```rust
/// Consistency level for operations (NORMATIVE)
pub enum ConsistencyLevel {
    /// Eventual: operation succeeds locally, propagates eventually
    /// Use for: non-critical writes, caching, telemetry
    Eventual,

    /// Epoch: operation included in current epoch, ordered between epochs
    /// Use for: most operations
    Epoch,

    /// Sequenced: operation has strict order within a sequence
    /// Use for: financial transactions, ordered edits
    Sequenced,

    /// Linearizable: operation appears to execute atomically at one point
    /// Use for: distributed locks, leader election
    /// Requires quorum acknowledgment
    Linearizable,
}
```

---

## 12. Revocation, Expiry, and Garbage Collection

### 12.1 Revocation Model

In a symbol-native world, you cannot "delete" data—symbols may exist on offline devices. Revocation is a protocol mechanism, not a storage mechanism.

```rust
/// Revocation object (NORMATIVE)
pub struct RevocationObject {
    pub header: ObjectHeader,

    /// What is being revoked
    pub target: RevocationTarget,

    /// Cutoff epoch (revocation effective after this epoch)
    pub cutoff_epoch: EpochId,

    /// Reason (for audit)
    pub reason: RevocationReason,
}

pub enum RevocationTarget {
    /// Revoke a specific object
    Object(ObjectId),

    /// Revoke a capability
    Capability(CapabilityId),

    /// Revoke a key (admin key, device key)
    Key(KeyId),

    /// Revoke all capabilities for a principal
    Principal(PrincipalId),

    /// Revoke a device
    Device(TailscaleNodeId),
}

/// Revocation checking (NORMATIVE)
impl RevocationChecker {
    /// Check if target is revoked
    pub fn is_revoked(&self, target: &RevocationTarget, at_epoch: EpochId) -> bool {
        for revocation in &self.revocations {
            if revocation.target == *target && at_epoch >= revocation.cutoff_epoch {
                return true;
            }
        }
        false
    }

    /// MUST check revocation before any of:
    /// - Using a capability
    /// - Accepting a symbol from a source
    /// - Trusting an admin delegation
    pub fn guard<T>(&self, target: &RevocationTarget, action: impl FnOnce() -> T) -> Result<T> {
        if self.is_revoked(target, current_epoch()) {
            return Err(Error::Revoked);
        }
        Ok(action())
    }
}
```

### 12.2 Expiry Model

Everything has a TTL:

```rust
/// Expiry requirements (NORMATIVE)
pub struct ExpiryPolicy {
    /// Capabilities MUST have TTL
    pub capability_max_ttl: Duration,  // Default: 90 days

    /// Admin delegations MUST have TTL
    pub delegation_max_ttl: Duration,  // Default: 90 days

    /// Symbols MUST have retention period
    pub symbol_retention: Duration,  // Default: 30 days

    /// Audit data has separate retention
    pub audit_retention: Duration,  // Default: 7 years
}

/// Every object SHOULD include expiry
pub trait Expirable {
    fn expires_at(&self) -> Option<u64>;

    fn is_expired(&self) -> bool {
        self.expires_at()
            .map(|exp| exp < now())
            .unwrap_or(false)
    }
}
```

### 12.3 Garbage Collection

```rust
/// Garbage collection protocol (NORMATIVE)
pub struct GarbageCollector {
    /// Zone policy defines retention
    pub policy: GcPolicy,

    /// Tombstones for intentionally deleted objects
    pub tombstones: HashMap<ObjectId, Tombstone>,
}

pub struct GcPolicy {
    /// Minimum retention for all symbols
    pub min_retention: Duration,

    /// Maximum storage per zone
    pub max_storage_bytes: u64,

    /// GC priority (what to delete first when over quota)
    pub priority: GcPriority,
}

pub enum GcPriority {
    /// Delete oldest first (FIFO)
    Oldest,

    /// Delete least accessed first (LRU)
    LeastRecentlyUsed,

    /// Delete lowest priority objects first
    ByObjectPriority,
}

/// Tombstone (marks intentional deletion)
pub struct Tombstone {
    pub object_id: ObjectId,
    pub deleted_at: EpochId,
    pub deleted_by: PrincipalId,
    pub reason: Option<String>,
    pub signature: Signature,
}
```

---

## 13. Rate Limiting and DoS Protection

### 13.1 Rate Limiting Model

```rust
/// Rate limiting (NORMATIVE)
pub struct RateLimiter {
    /// Limits by source
    pub source_limits: HashMap<SourceId, TokenBucket>,

    /// Limits by zone
    pub zone_limits: HashMap<ZoneId, TokenBucket>,

    /// Limits by object type
    pub type_limits: HashMap<SchemaId, TokenBucket>,

    /// Global limit
    pub global_limit: TokenBucket,
}

pub struct TokenBucket {
    /// Maximum tokens
    pub capacity: u64,

    /// Current tokens
    pub tokens: AtomicU64,

    /// Refill rate (tokens per second)
    pub refill_rate: u64,
}

impl RateLimiter {
    /// Check if symbol should be accepted
    pub fn check(&self, symbol: &SignedSymbolEnvelope) -> RateLimitResult {
        let source_ok = self.source_limits
            .get(&symbol.source)
            .map(|b| b.try_consume(1))
            .unwrap_or(true);

        let zone_ok = self.zone_limits
            .get(&symbol.symbol.zone_id)
            .map(|b| b.try_consume(1))
            .unwrap_or(true);

        let global_ok = self.global_limit.try_consume(1);

        if !global_ok {
            RateLimitResult::Rejected(RateLimitReason::Global)
        } else if !zone_ok {
            RateLimitResult::Rejected(RateLimitReason::Zone)
        } else if !source_ok {
            RateLimitResult::Rejected(RateLimitReason::Source)
        } else {
            RateLimitResult::Accepted
        }
    }
}
```

### 13.2 Drop Policies

```rust
/// Drop policy (NORMATIVE)
pub enum DropPolicy {
    /// Drop and log (silent)
    DropSilent,

    /// Drop and emit audit event
    DropWithAudit,

    /// Drop and notify sender
    DropWithNack,

    /// Never drop (queue, may OOM)
    NeverDrop,
}

/// Object priority for overload shedding
pub enum ObjectPriority {
    /// Control plane objects (highest)
    ControlPlane = 100,

    /// Audit objects
    Audit = 90,

    /// Capability objects
    Capability = 80,

    /// Response objects
    Response = 70,

    /// Request objects
    Request = 60,

    /// Event objects
    Event = 50,

    /// Other (lowest)
    Other = 0,
}
```

---

## 14. Tailscale Integration

### 14.1 Tailscale Client

```rust
/// Tailscale local API client (NORMATIVE)
pub struct TailscaleClient {
    socket_path: PathBuf,  // /var/run/tailscale/tailscaled.sock
    http_client: reqwest::Client,
}

impl TailscaleClient {
    /// Get current Tailscale status
    pub async fn status(&self) -> Result<TailscaleStatus> {
        self.get("/localapi/v0/status").await
    }

    /// Get peer list with connection info
    pub async fn peers(&self) -> Result<Vec<TailscalePeer>> {
        let status = self.status().await?;
        Ok(status.peer.into_values().collect())
    }

    /// Check if peer is directly reachable (not via DERP)
    pub async fn is_direct(&self, peer_ip: IpAddr) -> Result<bool> {
        let status = self.status().await?;
        Ok(status.peer.values()
            .find(|p| p.tailscale_ips.contains(&peer_ip))
            .map(|p| p.cur_addr.is_some())
            .unwrap_or(false))
    }

    /// Get node identity from IP
    pub async fn whois(&self, ip: IpAddr) -> Result<NodeIdentity> {
        self.get(&format!("/localapi/v0/whois?addr={}", ip)).await
    }
}

pub struct TailscalePeer {
    pub id: String,
    pub hostname: String,
    pub tailscale_ips: Vec<IpAddr>,
    pub tags: Vec<String>,
    pub online: bool,
    pub cur_addr: Option<SocketAddr>,  // Direct address if available
    pub relay: Option<String>,          // DERP relay if used
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_seen: DateTime<Utc>,
}
```

### 14.2 Peer Discovery

```rust
/// FCP peer discovery over Tailscale (NORMATIVE)
pub struct TailscalePeerDiscovery {
    client: TailscaleClient,
    fcp_port: u16,
}

impl TailscalePeerDiscovery {
    /// Discover FCP-capable peers on the tailnet
    pub async fn discover(&self) -> Result<Vec<FcpPeer>> {
        let peers = self.client.peers().await?;

        let mut fcp_peers = Vec::new();

        for peer in peers {
            if !peer.online {
                continue;
            }

            // Probe for FCP service
            for ip in &peer.tailscale_ips {
                if let Ok(caps) = self.probe_fcp(*ip).await {
                    fcp_peers.push(FcpPeer {
                        tailscale_id: peer.id.clone(),
                        hostname: peer.hostname.clone(),
                        ip: *ip,
                        tags: peer.tags.clone(),
                        zone: ZoneId::from_tailscale_tag(&peer.tags.first().unwrap_or(&String::new())),
                        capabilities: caps,
                        direct: peer.cur_addr.is_some(),
                        latency_ms: self.measure_latency(*ip).await.ok(),
                    });
                    break;
                }
            }
        }

        Ok(fcp_peers)
    }
}
```

### 14.3 Symbol Routing Over Tailscale

```rust
/// Route RaptorQ symbols across Tailscale mesh (NORMATIVE)
pub struct TailscaleSymbolRouter {
    client: TailscaleClient,
    peers: RwLock<HashMap<String, FcpPeer>>,
    local_store: SymbolStore,
    config: RaptorQConfig,
}

impl TailscaleSymbolRouter {
    /// Distribute symbols across tailnet with zone awareness
    pub async fn distribute(
        &self,
        object_id: ObjectId,
        symbols: Vec<EncodedSymbol>,
        zone: &ZoneId,
    ) -> Result<SymbolDistribution> {
        let peers = self.peers.read().await;

        // Filter peers by zone (only distribute to same or lower trust)
        let eligible: Vec<_> = peers.values()
            .filter(|p| self.can_store_for_zone(p, zone))
            .collect();

        if eligible.is_empty() {
            return Err(Error::NoPeersAvailable);
        }

        // Sort by: direct connection > lower latency > more storage
        let mut ranked = eligible.clone();
        ranked.sort_by(|a, b| {
            match (a.direct, b.direct) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => a.latency_ms.cmp(&b.latency_ms)
            }
        });

        // Distribute symbols
        let mut distribution = SymbolDistribution::new(object_id);
        let total_peers = ranked.len() + 1; // +1 for local

        for (i, symbol) in symbols.into_iter().enumerate() {
            let target_idx = i % total_peers;

            if target_idx == 0 {
                // Store locally
                self.local_store.store(symbol.clone()).await?;
                distribution.record_local(symbol.esi);
            } else {
                // Send to peer
                let peer = &ranked[target_idx - 1];
                self.send_symbol_to_peer(peer, symbol.clone()).await?;
                distribution.record_peer(symbol.esi, &peer.tailscale_id);
            }
        }

        Ok(distribution)
    }

    /// Reconstruct object from symbols across tailnet
    pub async fn reconstruct(
        &self,
        object_id: ObjectId,
    ) -> Result<Vec<u8>> {
        let mut decoder = RaptorQDecoder::new();

        // 1. Local symbols (fastest)
        for symbol in self.local_store.get(object_id).await? {
            if let Some(data) = decoder.add_symbol(symbol) {
                return Ok(data);
            }
        }

        // 2. Direct peers (low latency)
        let peers = self.peers.read().await;
        let direct_peers: Vec<_> = peers.values()
            .filter(|p| p.online && p.direct)
            .collect();

        for peer in direct_peers {
            let symbols = self.fetch_symbols_from_peer(peer, object_id).await?;
            for symbol in symbols {
                if let Some(data) = decoder.add_symbol(symbol) {
                    return Ok(data);
                }
            }
        }

        // 3. Relayed peers (higher latency but still trusted)
        let relayed_peers: Vec<_> = peers.values()
            .filter(|p| p.online && !p.direct)
            .collect();

        // Fetch in parallel from all relayed peers
        let symbol_streams: Vec<_> = relayed_peers.iter()
            .map(|p| self.fetch_symbols_from_peer(p, object_id))
            .collect();

        let mut combined = futures::stream::select_all(
            symbol_streams.into_iter().map(|f| f.into_stream())
        );

        while let Some(result) = combined.next().await {
            if let Ok(symbol) = result {
                if let Some(data) = decoder.add_symbol(symbol) {
                    return Ok(data);
                }
            }
        }

        Err(Error::InsufficientSymbols {
            needed: decoder.symbols_needed(),
            received: decoder.symbols_received(),
        })
    }
}
```

### 14.4 Funnel Gateway (Public Ingress)

```rust
/// Expose FCP services via Tailscale Funnel (NORMATIVE)
pub struct FunnelGateway {
    client: TailscaleClient,
    mesh: Arc<MeshNode>,
    policy: FunnelPolicy,
}

pub struct FunnelPolicy {
    /// Funnel ONLY allowed for these zones
    pub allowed_zones: Vec<ZoneId>,  // Typically only z:public, z:community

    /// NEVER allow these zones via Funnel
    pub blocked_zones: Vec<ZoneId>,  // z:owner, z:private

    /// Maximum request rate via Funnel
    pub rate_limit_per_minute: u32,

    /// Require additional auth for Funnel requests?
    pub require_auth_token: bool,
}

impl FunnelGateway {
    /// Handle incoming Funnel request (from public internet)
    pub async fn handle(&self, req: hyper::Request<Body>) -> Result<hyper::Response<Body>> {
        // All Funnel traffic is z:public or z:community
        let zone = self.classify_request(&req)?;

        if !self.policy.allowed_zones.contains(&zone) {
            return Ok(Response::builder()
                .status(403)
                .body("Zone not accessible via Funnel".into())?);
        }

        // Apply heavy taint (Funnel origin = untrusted)
        let provenance = Provenance::highly_tainted(zone.clone());

        // Parse FCP request
        let fcp_req = self.parse_fcp_request(req, provenance).await?;

        // Forward to mesh with zone restrictions
        let response = self.mesh.handle_request(fcp_req).await?;

        Ok(self.to_http_response(response)?)
    }
}
```

---

## 15. RaptorQ Deep Integration

### 15.1 Epoch-Based Event Buffer

Events are batched into epochs and encoded as symbols:

```rust
/// Epoch-based RaptorQ event buffer (NORMATIVE)
pub struct RaptorQEventBuffer {
    /// Duration of each epoch
    epoch_duration: Duration,

    /// Current epoch being written
    current_epoch: RwLock<EpochWriter>,

    /// Finalized epochs (symbols distributed)
    finalized_epochs: RwLock<HashMap<u64, EpochMetadata>>,

    /// Local symbol storage
    local_symbols: RwLock<HashMap<(u64, u32), Vec<u8>>>,

    /// Peer connections for symbol distribution/retrieval
    peers: Vec<PeerConnection>,
}

struct EpochMetadata {
    epoch_id: u64,
    start_time: DateTime<Utc>,
    event_count: u32,
    object_id: ObjectId,
    original_size: u32,
    symbol_count: u32,
}

impl RaptorQEventBuffer {
    /// Finalize current epoch and distribute symbols
    pub async fn finalize_epoch(&self) -> Result<()> {
        let epoch = self.current_epoch.write().await.take();
        let events_cbor = CanonicalSerializer::serialize(&epoch.events, &schemas::EVENT_EPOCH);
        let object_id = ObjectId::from_bytes(&events_cbor);

        // Encode to symbols
        let encoder = RaptorQEncoder::new(&events_cbor, SYMBOL_SIZE);
        let symbols: Vec<_> = encoder.get_encoded_packets(REPAIR_RATIO).collect();

        // Distribute symbols across self + peers (round-robin)
        for (i, symbol) in symbols.iter().enumerate() {
            let target = i % (self.peers.len() + 1);
            if target == 0 {
                self.local_symbols.write().await
                    .insert((epoch.id, symbol.esi), symbol.data.clone());
            } else {
                self.peers[target - 1]
                    .store_symbol(epoch.id, symbol.esi, &symbol.data)
                    .await?;
            }
        }

        // Record metadata
        self.finalized_epochs.write().await.insert(epoch.id, EpochMetadata {
            epoch_id: epoch.id,
            object_id,
            symbol_count: symbols.len() as u32,
            event_count: epoch.events.len() as u32,
            original_size: events_cbor.len() as u32,
            start_time: epoch.start_time,
        });

        Ok(())
    }

    /// Replay events from a cursor
    pub async fn replay(&self, since_epoch: u64) -> impl Stream<Item = EventEnvelope> {
        stream::iter(since_epoch..)
            .then(|epoch_id| self.reconstruct_epoch(epoch_id))
            .flat_map(|events| stream::iter(events))
    }

    /// Reconstruct an epoch from distributed symbols
    async fn reconstruct_epoch(&self, epoch_id: u64) -> Vec<EventEnvelope> {
        let meta = match self.finalized_epochs.read().await.get(&epoch_id).cloned() {
            Some(m) => m,
            None => return vec![],
        };

        let mut decoder = RaptorQDecoder::new(meta.original_size as usize);

        // Fetch from local first
        for (key, data) in self.local_symbols.read().await.iter() {
            if key.0 == epoch_id {
                decoder.add_symbol(key.1, data);
                if let Some(decoded) = decoder.try_decode() {
                    return CanonicalSerializer::deserialize(&decoded, &schemas::EVENT_EPOCH)
                        .unwrap_or_default();
                }
            }
        }

        // Fetch from peers in parallel
        let peer_symbols = futures::future::join_all(
            self.peers.iter().map(|p| p.fetch_symbols(epoch_id))
        ).await;

        for symbols in peer_symbols {
            for (esi, data) in symbols {
                decoder.add_symbol(esi, &data);
                if let Some(decoded) = decoder.try_decode() {
                    return CanonicalSerializer::deserialize(&decoded, &schemas::EVENT_EPOCH)
                        .unwrap_or_default();
                }
            }
        }

        vec![]
    }
}
```

### 15.2 Connector Binary Distribution

```rust
/// Connector update client using RaptorQ (NORMATIVE)
pub struct ConnectorUpdater {
    sources: Vec<SymbolSource>,
    local_cache: PathBuf,
}

pub enum SymbolSource {
    Cdn { base_url: String },
    Peer { addr: SocketAddr },
    Multicast { group: Ipv4Addr, port: u16 },
}

impl ConnectorUpdater {
    /// Fetch connector binary from all sources in parallel
    pub async fn fetch(&self, manifest: &UpdateManifest) -> Result<Vec<u8>> {
        let mut decoder = RaptorQDecoder::new(manifest.size);

        // Start fetching from all sources in parallel
        let symbol_streams: Vec<_> = self.sources.iter()
            .map(|s| s.fetch_symbols(manifest.object_id))
            .collect();

        let mut combined = futures::stream::select_all(symbol_streams);

        while let Some(symbol) = combined.next().await {
            decoder.add_symbol(symbol.esi, &symbol.data);

            if let Some(data) = decoder.try_decode() {
                // Verify hash
                if ObjectId::from_bytes(&data) != manifest.object_id {
                    return Err(Error::HashMismatch);
                }
                return Ok(data);
            }
        }

        Err(Error::InsufficientSymbols)
    }
}
```

**Benefits:**
- Parallel download from CDN + P2P + multicast
- No specific symbols required—any symbols help
- Resumable without bookmarks
- DoS resistant (can't block specific critical symbols)

### 15.3 Distributed Audit Log

```rust
/// Archive audit logs using RaptorQ for distributed redundancy (NORMATIVE)
pub struct RaptorQAuditArchive {
    /// Storage nodes for symbol distribution
    storage_nodes: Vec<StorageNode>,

    /// Archive metadata
    archives: HashMap<ArchiveId, ArchiveMetadata>,
}

struct ArchiveMetadata {
    id: ArchiveId,
    time_range: (DateTime<Utc>, DateTime<Utc>),
    merkle_root: [u8; 32],
    object_id: ObjectId,
    symbol_distribution: HashMap<NodeId, Vec<u32>>,
}

impl RaptorQAuditArchive {
    /// Archive a batch of audit entries
    pub async fn archive(&mut self, entries: Vec<AuditEntry>) -> Result<ArchiveId> {
        // Build Merkle tree for tamper evidence
        let merkle_tree = MerkleTree::from_entries(&entries);
        let data = serialize_with_merkle(&entries, &merkle_tree)?;
        let object_id = ObjectId::from_bytes(&data);

        // Encode to symbols
        let encoder = RaptorQEncoder::new(&data, SYMBOL_SIZE);
        let symbols: Vec<_> = encoder
            .get_encoded_packets(ARCHIVE_REPAIR_RATIO)
            .collect();

        // Distribute to storage nodes (ensuring k-of-n can recover)
        let distribution = self.distribute_symbols(&symbols).await?;

        let archive_id = ArchiveId::new();
        self.archives.insert(archive_id, ArchiveMetadata {
            id: archive_id,
            merkle_root: merkle_tree.root(),
            object_id,
            symbol_distribution: distribution,
            time_range: (entries.first().unwrap().timestamp, entries.last().unwrap().timestamp),
        });

        Ok(archive_id)
    }

    /// Retrieve and verify archived audit log
    pub async fn retrieve(&self, archive_id: ArchiveId) -> Result<Vec<AuditEntry>> {
        let meta = self.archives.get(&archive_id)
            .ok_or(Error::ArchiveNotFound)?;

        let mut decoder = RaptorQDecoder::new(meta.original_size);

        // Fetch symbols from available nodes
        for (node_id, esis) in &meta.symbol_distribution {
            if let Ok(symbols) = self.fetch_from_node(*node_id, esis).await {
                for (esi, data) in symbols {
                    decoder.add_symbol(esi, &data);
                    if let Some(data) = decoder.try_decode() {
                        // Verify Merkle root
                        let (entries, tree) = deserialize_with_merkle(&data)?;
                        if tree.root() != meta.merkle_root {
                            return Err(Error::TamperDetected);
                        }
                        return Ok(entries);
                    }
                }
            }
        }

        Err(Error::InsufficientSymbols)
    }
}
```

---

## 16. Offline Access and Predictive Pre-staging

### 16.1 Offline Capability

Offline doesn't mean no access—it means reduced probability:

```rust
/// Offline capability tracking (NORMATIVE)
pub struct OfflineCapability {
    /// What objects can I access offline?
    pub accessible: HashMap<ObjectId, OfflineAccess>,
}

pub struct OfflineAccess {
    pub object_id: ObjectId,

    /// Symbols cached locally
    pub local_symbols: usize,

    /// Symbols needed for reconstruction
    pub k: usize,
}

impl OfflineAccess {
    /// Can I reconstruct?
    pub fn can_access(&self) -> bool {
        self.local_symbols >= self.k
    }

    /// How close am I? (0.0 to 1.0+)
    pub fn coverage(&self) -> f64 {
        self.local_symbols as f64 / self.k as f64
    }
}

impl OfflineCapability {
    /// Pre-cache important objects for offline access
    pub async fn prepare_for_offline(&mut self, important_objects: &[ObjectId]) {
        for object_id in important_objects {
            // Fetch all symbols for this object
            let symbols = fetch_all_symbols(*object_id).await;

            // Store enough locally for reconstruction
            let k = symbols.first().map(|s| s.k).unwrap_or(0);
            let to_store = symbols.into_iter().take(k as usize * 2); // 2x for safety

            for symbol in to_store {
                self.store_local(symbol);
            }

            self.accessible.insert(*object_id, OfflineAccess {
                object_id: *object_id,
                local_symbols: k as usize * 2,
                k: k as usize,
            });
        }
    }
}
```

### 16.2 Predictive Pre-staging

Based on user patterns, pre-stage symbols before they're needed:

```rust
/// Predictive symbol pre-staging (NORMATIVE)
pub struct PredictiveStager {
    /// User behavior model
    pub behavior_model: UserBehaviorModel,

    /// Predicted needs
    pub predictions: Vec<Prediction>,
}

pub struct Prediction {
    pub object_id: ObjectId,
    pub probability: f64,
    pub likely_device: TailscaleNodeId,
    pub expected_time: DateTime<Utc>,
}

impl PredictiveStager {
    /// Run prediction and pre-stage symbols
    pub async fn pre_stage(&mut self) {
        // Update predictions
        self.predictions = self.behavior_model.predict_next_hour();

        for prediction in &self.predictions {
            if prediction.probability < STAGING_THRESHOLD {
                continue;
            }

            // Time until expected need
            let time_until = prediction.expected_time - Utc::now();

            if time_until < Duration::minutes(10) {
                // Urgent: ensure full reconstruction capability
                self.ensure_full_coverage(prediction).await;
            } else if time_until < Duration::minutes(30) {
                // Soon: start pre-fetching
                self.start_prefetch(prediction).await;
            }
        }
    }

    async fn ensure_full_coverage(&self, prediction: &Prediction) {
        let device = &prediction.likely_device;
        let object_id = prediction.object_id;

        // Check current symbol count on device
        let current = device.symbol_count(object_id).await;
        let needed = get_k(object_id);

        if current < needed {
            // Fetch remaining symbols from other nodes
            let missing = needed - current;
            info!("Pre-staging {} symbols for {} to {}", missing, object_id, device);

            let symbols = fetch_symbols_from_mesh(object_id, missing).await;
            device.receive_symbols(symbols).await;
        }
    }
}
```

**Use case:** You check email every morning at 9am on your phone. At 8:50am, email symbols are pre-staged to your phone. By 9am, everything loads instantly even on a slow connection.

---

## 17. Device Loss Response

```rust
/// Device loss protocol (NORMATIVE)
pub async fn handle_device_loss(
    lost_device: TailscaleNodeId,
    mesh: &mut MeshNode,
) -> Result<()> {
    info!("Handling device loss: {}", lost_device);

    // 1. Immediately issue RevocationObject for device's keys
    let revocation = RevocationObject {
        header: ObjectHeader::new(
            &schemas::REVOCATION_OBJECT,
            mesh.identity.zone(),
        ),
        target: RevocationTarget::Device(lost_device.clone()),
        cutoff_epoch: current_epoch(),
        reason: RevocationReason::DeviceLoss,
    };
    mesh.distribute_control_object(revocation).await?;

    // 2. Rotate zone keys if device had access
    for zone in mesh.zones_with_access(&lost_device) {
        mesh.rotate_zone_key(zone, "Device loss").await?;
    }

    // 3. Revoke any capabilities issued TO the device
    for cap in mesh.capabilities_for_device(&lost_device) {
        mesh.revoke_capability(cap.capability_id).await?;
    }

    // 4. Emergency symbol redistribution
    // Ensure coverage doesn't drop below threshold
    let affected_objects = mesh.objects_with_symbols_on(&lost_device);
    for object_id in affected_objects {
        let coverage = mesh.coverage_without(&object_id, &lost_device);
        if coverage < COVERAGE_THRESHOLD {
            warn!("Object {} coverage dropped to {:.1}%, redistributing",
                object_id, coverage * 100.0);
            mesh.redistribute_symbols(object_id).await?;
        }
    }

    // 5. Alert remaining devices
    mesh.broadcast_security_alert(SecurityAlert::DeviceLoss {
        device: lost_device,
        action_taken: vec!["revoked", "key_rotated", "redistributed"],
    }).await?;

    Ok(())
}
```

---

## 18. Protocol Messages

### 18.1 Mesh Object Types

All messages are objects encoded as symbols:

```rust
/// Mesh-native message types (NORMATIVE)
pub enum MeshObject {
    // ─────────────────────────────────────────────────────────────────────
    // LIFECYCLE
    // ─────────────────────────────────────────────────────────────────────

    /// Node joining the mesh
    JoinAnnouncement(JoinAnnouncement),

    /// Node leaving the mesh
    LeaveAnnouncement(LeaveAnnouncement),

    /// Gossip exchange
    GossipMessage(GossipMessage),

    // ─────────────────────────────────────────────────────────────────────
    // INVOCATION
    // ─────────────────────────────────────────────────────────────────────

    /// Capability invocation
    Invoke(InvokeObject),

    /// Invocation response
    Response(ResponseObject),

    // ─────────────────────────────────────────────────────────────────────
    // EVENTS
    // ─────────────────────────────────────────────────────────────────────

    /// Event epoch (batch of events)
    EventEpoch(EventEpochObject),

    /// Subscribe to events
    Subscribe(SubscribeObject),

    /// Epoch seal (finalizes epoch)
    EpochSeal(EpochSealObject),

    // ─────────────────────────────────────────────────────────────────────
    // SYMBOLS
    // ─────────────────────────────────────────────────────────────────────

    /// Symbol request
    SymbolRequest(SymbolRequest),

    /// Symbol delivery
    SymbolDelivery(SymbolDelivery),

    /// Symbol redistribution
    Redistribute(RedistributeRequest),

    // ─────────────────────────────────────────────────────────────────────
    // COMPUTATION
    // ─────────────────────────────────────────────────────────────────────

    /// Migrate computation
    MigrateComputation(MigrateRequest),

    /// Computation checkpoint
    Checkpoint(CheckpointObject),

    // ─────────────────────────────────────────────────────────────────────
    // CONTROL
    // ─────────────────────────────────────────────────────────────────────

    /// Policy update
    Policy(PolicyObject),

    /// Capability definition
    Capability(CapabilityObject),

    /// Revocation
    Revocation(RevocationObject),

    /// Audit head
    AuditHead(AuditHeadObject),
}
```

### 18.2 Symbol Request/Delivery

```rust
/// Request symbols for an object (NORMATIVE)
pub struct SymbolRequest {
    /// Which object?
    pub object_id: ObjectId,

    /// How many symbols do I need?
    pub symbols_needed: u16,

    /// Which symbols do I already have? (ESIs)
    pub already_have: Vec<u32>,

    /// Deadline
    pub deadline: u64,

    /// Priority
    pub priority: ObjectPriority,
}

/// Deliver symbols (NORMATIVE)
pub struct SymbolDelivery {
    /// For which request?
    pub request_id: ObjectId,

    /// The symbols
    pub symbols: Vec<SymbolEnvelope>,
}
```

### 18.3 Protocol Negotiation

```rust
/// Transport capabilities (NORMATIVE)
pub struct TransportCaps {
    /// Protocol versions supported
    pub protocol_versions: Vec<ProtocolVersion>,

    /// Symbol mode support
    pub symbol_native: bool,

    /// RaptorQ support (MUST be true in mesh-native)
    pub raptorq: bool,

    /// Compression algorithms
    pub compression: Vec<CompressionAlgorithm>,

    /// Maximum frame size
    pub max_frame_size: u32,

    /// Maximum symbols per frame
    pub max_symbols_per_frame: u16,

    /// Preferred symbol size
    pub preferred_symbol_size: u16,
}

pub enum ProtocolVersion {
    /// Original FCP (JSON-RPC frames) - compatibility only
    Fcp1,

    /// Symbol-native FCP (mesh-native) - canonical
    Fcp2Sym,
}

/// Protocol negotiation (NORMATIVE)
impl Negotiation {
    pub fn negotiate(&mut self, peer_caps: TransportCaps) -> NegotiatedProtocol {
        // Prefer highest common version (symbol-native)
        let version = if self.my_caps.protocol_versions.contains(&ProtocolVersion::Fcp2Sym)
            && peer_caps.protocol_versions.contains(&ProtocolVersion::Fcp2Sym)
        {
            ProtocolVersion::Fcp2Sym
        } else {
            ProtocolVersion::Fcp1
        };

        // Symbol mode requires both sides
        let symbol_native = self.my_caps.symbol_native && peer_caps.symbol_native;

        // Common compression
        let compression = self.my_caps.compression.iter()
            .find(|c| peer_caps.compression.contains(c))
            .cloned();

        // Minimum frame size
        let max_frame_size = self.my_caps.max_frame_size.min(peer_caps.max_frame_size);

        NegotiatedProtocol {
            version,
            symbol_native,
            compression,
            max_frame_size,
        }
    }
}
```

---

## 19. Crate Structure

### 19.1 fcp-raptorq

```
crates/fcp-raptorq/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public API
    ├── object.rs        # ObjectId, SymbolId types
    ├── encoder.rs       # RaptorQ encoding wrapper
    ├── decoder.rs       # RaptorQ decoding wrapper
    ├── frame.rs         # FCPS frame format
    ├── transport.rs     # RaptorQ transport layer
    ├── buffer.rs        # Epoch-based event buffer
    ├── store.rs         # Distributed symbol storage
    └── update.rs        # Connector update protocol
```

### 19.2 fcp-tailscale

```
crates/fcp-tailscale/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public API
    ├── client.rs        # Tailscale local API client
    ├── discovery.rs     # Peer discovery on tailnet
    ├── transport.rs     # Tailscale-aware transport
    ├── acl.rs           # Zone-to-ACL generation
    ├── funnel.rs        # Public ingress via Funnel
    └── identity.rs      # Tailscale identity integration
```

### 19.3 fcp-mesh

```
crates/fcp-mesh/
├── Cargo.toml
└── src/
    ├── lib.rs           # SovereignMesh public API
    ├── node.rs          # MeshNode implementation
    ├── capability.rs    # MeshCapability
    ├── gossip.rs        # MeshGossip layer
    ├── router.rs        # TailscaleSymbolRouter
    ├── planner.rs       # ExecutionPlanner
    ├── migration.rs     # Computation migration
    ├── state.rs         # DistributedState
    └── security.rs      # Trust anchors, revocation
```

---

## 20. Implementation Phases

### Phase 1: Core Mesh (MVP)

**Goal:** Basic mesh operation with capability invocation.

**Components:**
- MeshNode with Tailscale discovery
- Symbol request/delivery protocol
- CapabilityObject signed by owner key directly
- InvokeObject and ResponseObject
- RaptorQ encoding for objects > 1KB
- Basic zone isolation

**NOT in Phase 1:**
- Epoch streaming
- Threshold secrets
- Source diversity enforcement
- IssuerSet delegation
- PlacementPolicy enforcement

### Phase 2: Events and Lifecycle

**Goal:** Add streaming and lifecycle management.

**Components:**
- Epoch-based event streaming
- Subscription management
- RevocationObject (key, capability, device)
- Tombstone objects for intentional deletion
- Garbage collection per zone policy
- Basic audit chain (single-node signed)

**NOT in Phase 2:**
- Quorum-signed audit heads
- Full source diversity
- Threshold secrets

### Phase 3: Full Security Model

**Goal:** Complete authority model with distributed trust.

**Components:**
- Full PolicyObject with zone/issuer/principal rules
- IssuerSet with quorum delegation
- PrincipalClaim for principal-device binding
- Quorum-signed audit heads
- Threshold secrets (k-of-n distribution)
- Source diversity enforcement
- PlacementPolicy enforcement
- Device loss response protocol

---

## 21. Compatibility

### 21.1 FCP1 Compatibility

FCP1 remains valid for legacy connectors. The HybridTranslator enables gradual migration:

```rust
/// Hybrid mode translator (FCP1 <-> FCP2-SYM) (NORMATIVE)
pub struct HybridTranslator {
    pub peer_protocol: ProtocolVersion,
    pub local_protocol: ProtocolVersion,
}

impl HybridTranslator {
    /// Translate outgoing message
    pub fn translate_outgoing(&self, msg: MeshObject) -> OutgoingFrame {
        match self.peer_protocol {
            ProtocolVersion::Fcp1 => self.to_json_rpc(msg),
            ProtocolVersion::Fcp2Sym => self.to_symbol_frame(msg),
        }
    }

    /// Translate incoming frame
    pub fn translate_incoming(&self, frame: IncomingFrame) -> MeshObject {
        match frame {
            IncomingFrame::JsonRpc(json) => self.from_json_rpc(json),
            IncomingFrame::SymbolBatch(symbols) => self.from_symbols(symbols),
        }
    }
}
```

### 21.2 Migration Path

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FCP1 → MESH-NATIVE MIGRATION                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Step 1: Add Tailscale to all nodes                                        │
│  Step 2: Deploy MeshNode alongside existing Hub                            │
│  Step 3: Enable hybrid mode (FCP1 <-> symbol translation)                  │
│  Step 4: Migrate capabilities one by one                                   │
│  Step 5: Enable zone encryption for migrated capabilities                  │
│  Step 6: Disable FCP1 endpoints                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 22. Conformance Requirements

Every mesh-native implementation MUST pass these test vectors:

1. **Canonical serialization**: Given input, produce exact byte output
2. **ObjectId derivation**: Given content + zone + schema, produce exact ObjectId
3. **Symbol encoding**: Given content, produce valid RaptorQ symbols
4. **Symbol reconstruction**: Given K' symbols, reconstruct original
5. **Signature verification**: Given signed object, verify correctly
6. **Revocation checking**: Given revocation list, correctly reject revoked items
7. **Source diversity**: Verify diversity requirements are enforced
8. **Epoch ordering**: Verify no ordering within epoch, ordering between epochs

Cross-implementation interop tests:
1. Handshake negotiation
2. Symbol exchange
3. Object reconstruction
4. Capability verification
5. Cross-zone bridging

---

## 23. Summary

### What This Enables

| Traditional FCP | Mesh-Native FCP |
|-----------------|-----------------|
| Hub process | Mesh IS the Hub |
| Connectors on machines | Capabilities anywhere |
| Sessions on nodes | Mesh-wide contexts |
| Storage on devices | Symbol distribution |
| Sync between devices | Symbol flow |
| Offline = no access | Offline = reduced probability |
| Identity per service | Tailscale identity |
| Zones as policy | Zones as Tailscale tags + crypto |
| Secrets on devices | Threshold secrets (k-of-n) |
| Audit on nodes | Distributed audit chain |
| Single execution location | Optimal device selection |
| Static placement | Migration-aware |
| Connection-oriented | Symbol-oriented |

### The Vision

Your personal AI runs on YOUR devices. Your data exists as symbols across YOUR mesh. Any subset of YOUR devices can reconstruct anything. Computation happens wherever optimal. Secrets are never complete anywhere. History is tamper-evident by construction.

This is not a cloud alternative. This is **digital sovereignty**.

---

## Appendix A: RaptorQ Configuration

```rust
/// Configuration for RaptorQ operations (NORMATIVE)
#[derive(Clone)]
pub struct RaptorQConfig {
    /// Symbol size in bytes (default: 1024)
    pub symbol_size: u16,

    /// Repair symbol ratio (default: 0.05 = 5% extra)
    pub repair_ratio: f32,

    /// Maximum object size (default: 64MB)
    pub max_object_size: u32,

    /// Decoder timeout (default: 30s)
    pub decode_timeout: Duration,
}

impl Default for RaptorQConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1024,
            repair_ratio: 0.05,
            max_object_size: 64 * 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
        }
    }
}
```

## Appendix B: Performance Characteristics

### Encoding/Decoding Overhead

| Operation | Complexity | Typical Throughput |
|-----------|------------|-------------------|
| Encode | O(K) | ~1 GB/s per core |
| Decode | O(K) | ~500 MB/s per core |
| Symbol generation | O(1) per symbol | Millions/sec |

### Space Overhead

| Redundancy | Symbol Overhead | Storage Overhead |
|------------|-----------------|------------------|
| k-of-k (no redundancy) | 0.2% | 0.2% |
| k-of-n where n=1.5k | 50% repair | 50% per node, k nodes survive |
| k-of-n where n=2k | 100% repair | 50% per node, any k of 2k survive |

### Network Efficiency

For a 1MB object over 10% loss network:

| Approach | Bytes Transmitted | Round Trips |
|----------|-------------------|-------------|
| TCP retransmit | ~1.2MB | 10-20 |
| RaptorQ (5% repair) | ~1.05MB | 1 |

## Appendix C: Security Considerations

1. **Object ID Verification**: Always verify `SHA256(decoded) == object_id`
2. **Symbol Authentication**: AEAD (ChaCha20-Poly1305) per symbol
3. **Replay Protection**: Epoch ID included in symbol envelope
4. **Resource Limits**: Cap decoder memory, timeout stale decoders
5. **Source Diversity**: Require symbols from multiple nodes for critical objects
6. **Zone Isolation**: Cryptographic (zone key) + Network (Tailscale ACLs)

## Appendix D: Transport Priority

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRANSPORT PRIORITY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Priority 1: Tailscale Direct (same LAN)                                   │
│   ├── Latency: <1ms                                                         │
│   ├── Trust: Maximum (same tailnet, direct path)                            │
│   └── Zone: Can carry z:owner traffic                                       │
│                                                                             │
│   Priority 2: Tailscale Mesh (different networks)                           │
│   ├── Latency: 10-100ms                                                     │
│   ├── Trust: High (same tailnet, NAT traversal)                             │
│   └── Zone: Can carry z:owner traffic                                       │
│                                                                             │
│   Priority 3: Tailscale DERP Relay                                          │
│   ├── Latency: 50-200ms                                                     │
│   ├── Trust: High (encrypted, but relayed)                                  │
│   └── Zone: Can carry z:private and below                                   │
│                                                                             │
│   Priority 4: Tailscale Funnel (public ingress)                             │
│   ├── Latency: Variable                                                     │
│   ├── Trust: Low (public internet)                                          │
│   └── Zone: z:community and z:public only                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```


# RFC: Universal Fungibility — Reimagining FCP from First Principles

## Abstract

This RFC proposes a fundamental reconceptualization of FCP based on the axiom of **universal fungibility**: all data in FCP exists as RaptorQ-encoded symbols, always and everywhere. This is not an optimization layer but the foundational primitive upon which the entire protocol is built.

When fungibility is axiomatic rather than optional, profound simplifications and new capabilities emerge. This document explores the full implications and proposes concrete protocol changes to exploit this magical property.

---

## Part 1: The Paradigm Shift

### What Fungibility Actually Means

In RaptorQ, any K' symbols (where K' ≈ K × 1.002) can reconstruct the original K source symbols. The symbols are perfectly interchangeable—symbol #1 is no more valuable than symbol #47,293. They're all equally capable of contributing to reconstruction.

Traditional systems are built on **specificity**:
- TCP needs specific packets (retransmit packet #42)
- Databases need specific replicas (read from primary)
- Consensus needs specific nodes (wait for 2f+1 responses)
- Streams need specific ordering (event 5 comes after event 4)

With universal fungibility, **none of this is true**:
- Any sufficient subset of symbols works
- There is no "primary" or "replica"—just symbols
- There is no "ordering"—just epochs
- There is no "destination"—just object IDs

### The Inversion

Traditional architecture: **Location-first, content-derived**
```
"Send message M to node N at address A"
```

Fungible architecture: **Content-first, location-irrelevant**
```
"I need object O (any K' symbols from anywhere)"
```

This inversion propagates through every layer of the system.

---

## Part 2: Foundational Primitives

### 2.1 ObjectId: The Universal Address

Everything in FCP is an **Object** with a content-derived **ObjectId**:

```rust
/// Content-addressed object identifier
/// This is THE addressing primitive in FCP
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Derive ObjectId from content with zone and schema binding (NORMATIVE)
    ///
    /// This is a hybrid model that enables:
    /// - Zone binding: Same plaintext in different zones has different ObjectIds
    /// - Schema versioning: Enables canonical serialization migration
    /// - Plaintext-based: Enables deduplication within a zone
    /// - Domain separation: Prevents hash collision attacks
    pub fn derive(
        plaintext: &[u8],
        zone_id: &ZoneId,
        schema_version: u32,
    ) -> Self {
        let mut hasher = Sha256::new();

        // Domain separation
        hasher.update(b"FCP-OBJECT-ID-V1\x00");

        // Zone binding (prevents cross-zone correlation without zone key)
        hasher.update(zone_id.as_bytes());

        // Schema version (enables migration)
        hasher.update(&schema_version.to_le_bytes());

        // Content
        hasher.update(plaintext);

        Self(hasher.finalize().into())
    }

    /// Simple derivation for zone-local objects
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(sha256(data))
    }

    /// Derive from any serializable value
    pub fn from<T: Serialize>(value: &T) -> Self {
        Self::from_bytes(&canonical_serialize(value))
    }
}
```

**Critical invariant:** The same plaintext in z:owner and z:work has DIFFERENT ObjectIds and DIFFERENT encryption keys. Cross-zone correlation requires explicit bridging with provenance tracking.

#### 2.1.1 Symbol Encryption Model

ObjectId is derived from plaintext (for deduplication), but symbols are encrypted (for confidentiality). A node without the zone key cannot decrypt symbols but CAN verify ObjectId if it obtains the plaintext through legitimate means.

```rust
/// Encrypted symbol (NORMATIVE)
pub struct EncryptedSymbol {
    /// Object identity (derived from plaintext + zone + version)
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
}
```

#### 2.1.2 Cross-Zone Re-encryption

When data crosses zones, it MUST be re-encrypted:

```rust
/// Cross-zone re-encryption (NORMATIVE)
pub fn bridge_to_zone(
    plaintext: &[u8],
    source_zone: &ZoneId,
    target_zone: &ZoneId,
    target_key: &ZoneKey,
    schema_version: u32,
) -> (ObjectId, Vec<EncryptedSymbol>) {
    // New ObjectId for target zone (different due to zone binding)
    let new_object_id = ObjectId::derive(plaintext, target_zone, schema_version);

    // Encode as symbols
    let symbols = encode(plaintext);

    // Encrypt with target zone key
    let encrypted: Vec<_> = symbols.iter()
        .map(|s| EncryptedSymbol::encrypt(&s.data, new_object_id, s.esi, target_key))
        .collect();

    (new_object_id, encrypted)
}
```

There are no "endpoints" or "addresses" in the traditional sense. You don't send to a destination—you request an object. The network is a **symbol soup** where objects materialize from sufficient symbol density.

### 2.2 EpochId: The Universal Temporal Unit

Time in FCP is not a continuous stream but discrete **Epochs**:

```rust
/// Epoch identifier (time bucket)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord)]
pub struct EpochId(u64);

impl EpochId {
    /// Standard epoch duration: 1 second
    pub const DURATION_MS: u64 = 1000;

    /// Current epoch
    pub fn now() -> Self {
        Self(unix_ms() / Self::DURATION_MS)
    }

    /// Epoch from timestamp
    pub fn from_timestamp(ts_ms: u64) -> Self {
        Self(ts_ms / Self::DURATION_MS)
    }
}
```

Within an epoch, there is **no ordering**. Events in the same epoch are reconstructed together as a set. Ordering only exists **between** epochs.

This is not a limitation—it's a feature. It enables:
- Parallel processing of all events in an epoch
- Natural batching at epoch boundaries
- Simplified replay (epoch granularity)
- Causal ordering via epoch dependencies

### 2.3 SymbolEnvelope: The Universal Transmission Unit

The fundamental unit of transmission is the **SymbolEnvelope**:

```rust
/// The atomic unit of FCP transmission
/// Everything travels as symbol envelopes
#[derive(Clone, Serialize, Deserialize)]
pub struct SymbolEnvelope {
    // ═══════════════════════════════════════════════════════════════
    // OBJECT IDENTITY
    // ═══════════════════════════════════════════════════════════════

    /// Which object this symbol belongs to
    pub object_id: ObjectId,

    /// Encoding Symbol ID (unique within object)
    pub esi: u32,

    // ═══════════════════════════════════════════════════════════════
    // RECONSTRUCTION PARAMETERS
    // ═══════════════════════════════════════════════════════════════

    /// Source symbols needed for reconstruction (K)
    pub k: u16,

    /// Bytes per symbol
    pub symbol_size: u16,

    /// Original object size in bytes
    pub object_size: u32,

    // ═══════════════════════════════════════════════════════════════
    // TEMPORAL AND SPATIAL CONTEXT
    // ═══════════════════════════════════════════════════════════════

    /// Which epoch this symbol belongs to
    pub epoch_id: EpochId,

    /// Zone namespace (encrypted with zone key)
    pub zone_id: ZoneId,

    /// Origin of this symbol (for source diversity verification)
    pub source_id: SourceId,

    // ═══════════════════════════════════════════════════════════════
    // THE ACTUAL DATA
    // ═══════════════════════════════════════════════════════════════

    /// Symbol data (encrypted with zone key)
    pub data: Vec<u8>,

    /// Authentication tag (HMAC or signature)
    pub auth_tag: [u8; 16],
}
```

There is **no distinction** between "data frames" and "control frames". Everything is symbol envelopes. Handshakes, invocations, responses, events, health checks—all are objects, all travel as symbols.

### 2.4 Zone as Symbol Namespace

Zones are not network segments or process boundaries—they are **cryptographic symbol namespaces**:

```rust
/// Zone as a cryptographic namespace for symbols
pub struct ZoneNamespace {
    pub zone_id: ZoneId,

    /// Zone encryption key (derived from zone hierarchy)
    /// Symbols are encrypted with this key
    pub zone_key: ZoneKey,

    /// Required sources for reconstruction
    /// Symbols must come from at least this many distinct sources
    pub min_sources: u8,

    /// Symbol distribution policy
    pub distribution: DistributionPolicy,
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

Zone isolation is **cryptographic**, not topological. z:owner symbols are encrypted with z:owner's zone key. Even if a z:public node somehow receives z:owner symbols, it cannot decrypt them.

### 2.5 Canonical Serialization: The Foundation of Content-Addressing

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

        // Body: Deterministic CBOR
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

#### 2.5.1 Schema Registry

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
    pub const HANDSHAKE_OBJECT: SchemaId = /* derived */;
    pub const INVOKE_OBJECT: SchemaId = /* derived */;
    pub const CAPABILITY_OBJECT: SchemaId = /* derived */;
    pub const RESPONSE_OBJECT: SchemaId = /* derived */;
    pub const EVENT_EPOCH_OBJECT: SchemaId = /* derived */;
    // ... etc
}
```

#### 2.5.2 Deterministic CBOR Rules

Following RFC 8949 Section 4.2:

1. **Integer encoding:** Smallest possible encoding
2. **Map key ordering:** Lexicographic by encoded key bytes
3. **Floating point:** Prefer smallest accurate representation
4. **No indefinite-length:** All arrays/maps/strings have explicit length
5. **No duplicate keys:** Maps MUST NOT contain duplicate keys
6. **UTF-8 strings:** All text strings MUST be valid UTF-8

**Test vectors MUST be provided** for every object type to ensure cross-implementation compatibility.

---

## Part 3: The Radical Implications

### 3.1 Elimination of Endpoint Addressing

**Traditional FCP:**
```
ConnectorId("telegram") + InstanceId("inst_xyz") + Address("192.168.1.5:9473")
```

**Fungible FCP:**
```
CapabilityObjectId("sha256:abc...")
```

You don't invoke "the Telegram connector on my server". You invoke "capability telegram.send_message"—an object with an ID. The symbols for that capability exist somewhere in the network. Collect enough symbols, reconstruct the capability, execute.

```rust
/// Capability invocation in a fungible world
pub struct InvokeObject {
    /// Content-addressed request ID
    pub request_id: ObjectId,

    /// The capability we're invoking (as an object reference)
    pub capability_object_id: ObjectId,

    /// The operation within that capability
    pub operation: OperationId,

    /// Parameters (as object references—they're all symbols too)
    pub param_object_ids: Vec<ObjectId>,

    /// Response routing hints (where to emit response symbols)
    pub response_zone: ZoneId,
    pub response_epoch: EpochId,
}
```

### 3.2 Elimination of Connections

**Traditional:** Connections are established, maintained, and can fail.

**Fungible:** There are no connections. Just symbol flows.

```
Traditional:
  Client ────[TCP Connection]──── Server
             (can fail)

Fungible:
  Symbols ~~~~~~ float ~~~~~~ everywhere
  (reconstruction succeeds when K' symbols arrive from ANY sources)
```

You emit symbols with object IDs. Anyone who wants that object collects symbols. When they have K', they reconstruct. There's no "connection" to fail, no "stream" to reset.

```rust
/// There are no connections—just symbol aggregators
pub struct SymbolAggregator {
    object_id: ObjectId,
    k_needed: u16,

    /// Symbols from ALL sources accumulate here
    received: HashMap<u32, (SymbolData, SourceId)>,  // ESI -> (data, source)

    /// Try reconstruction whenever we get a new symbol
    pub fn add_symbol(&mut self, sym: SymbolEnvelope) -> Option<Vec<u8>> {
        self.received.insert(sym.esi, (sym.data, sym.source_id));

        if self.received.len() >= self.k_needed as usize {
            self.try_reconstruct()
        } else {
            None
        }
    }
}
```

### 3.3 Multipath by Default, Not by Configuration

**Traditional:** Primary path, failover paths, load balancing decisions.

**Fungible:** ALL paths are primary. ALL paths contribute. First K' symbols to arrive wins.

```rust
/// All transports contribute to the same aggregator
pub struct MultipathAggregator {
    object_id: ObjectId,
    aggregator: SymbolAggregator,

    /// ALL these contribute simultaneously
    sources: Vec<SymbolSource>,
    // - WiFi
    // - Cellular
    // - Tailscale mesh
    // - Bluetooth
    // - USB
    // - Carrier pigeon (if it delivers symbols)
}
```

This means:
- No failover logic (nothing to fail over from)
- No load balancing decisions (all paths are used)
- Latency = min(path latencies), not max
- Bandwidth = sum(path bandwidths)
- Any path can drop any symbols—just need K' from the union

### 3.4 State IS Symbol Distribution

**Traditional:** State lives in databases, files, memory at specific locations.

**Fungible:** State IS the current distribution of symbols across the network.

There is no "primary database" to fail. There is no "replication" to lag. The state is the emergent property of symbol distribution.

```rust
/// State doesn't "live" anywhere—it IS the symbol distribution
pub struct DistributedState {
    state_object_id: ObjectId,

    /// Current symbol distribution
    symbol_locations: HashMap<SymbolId, Vec<NodeId>>,

    /// Reconstruction probability given current distribution
    pub fn reconstruction_probability(&self) -> f64 {
        // P(can reconstruct) = f(symbol distribution, node availability)
        calculate_reconstruction_probability(&self.symbol_locations)
    }

    /// The state isn't "stored"—it's reconstructed on demand
    pub async fn materialize(&self) -> Option<StateData> {
        let symbols = self.collect_symbols().await;
        reconstruct(symbols)
    }
}
```

### 3.5 Probabilistic State and Computation

Instead of binary "I have this data" or "I don't", you have a continuous probability.

```rust
/// Probabilistic data availability
pub struct ProbabilisticObject {
    object_id: ObjectId,
    k_needed: u16,

    symbols_held: u16,

    /// Probability of successful reconstruction
    pub fn availability(&self) -> f64 {
        if self.symbols_held >= self.k_needed {
            1.0
        } else {
            // Probability of getting remaining symbols
            estimate_availability(self.k_needed - self.symbols_held)
        }
    }
}
```

This enables:
- **Graceful degradation**: Operate with 80% confidence instead of failing
- **Risk-aware scheduling**: Prioritize high-confidence operations
- **Natural load shedding**: Low-symbol objects naturally deprioritized

For **monotonic computations** (where more data only adds, never subtracts), you can compute over partial symbol sets:

```rust
/// Compute over partial reconstruction
pub struct IncrementalComputation<T: Monoid> {
    partial_result: T,
    symbols_processed: HashSet<SymbolId>,

    /// Process each symbol as it arrives
    pub fn process_symbol(&mut self, sym: SymbolEnvelope) -> T {
        if self.symbols_processed.insert(sym.id()) {
            // Decode what we can from this symbol
            if let Some(partial_data) = partial_decode(&sym) {
                // Monotonic merge
                self.partial_result = self.partial_result.merge(compute(&partial_data));
            }
        }
        self.partial_result.clone()
    }
}
```

Example: Aggregating transaction sums. Each symbol contributes to the sum. You don't need ALL symbols to start computing.

### 3.6 Anonymous and Untraceable Contribution

Because symbols are fungible, you cannot determine which specific symbol "completed" the reconstruction. This enables **anonymous contribution**.

```rust
/// Anonymous symbol contribution
pub struct AnonymousContribution {
    /// Symbol is encrypted with object's zone key
    encrypted_symbol: EncryptedSymbol,

    /// Zero-knowledge proof that this is a valid symbol
    /// (proves membership without revealing which symbol)
    validity_proof: ZKProof,

    /// Optional: onion-routed through other nodes
    routing_layers: Vec<RoutingLayer>,
}
```

A whistleblower could contribute symbols to an audit object without revealing which symbols they contributed. The reconstruction succeeds, the data is revealed, but the specific contributor is protected by fungibility.

### 3.7 Threshold Everything

With fungibility as a primitive, threshold cryptography becomes natural:

```rust
/// Secret distributed as symbols—never exists complete on any device
pub struct DistributedSecret {
    secret_object_id: ObjectId,

    /// k-of-n threshold
    k: u8,
    n: u8,

    /// Symbol holders (each has at most 1 symbol)
    holders: HashMap<DeviceId, SymbolId>,

    /// Reconstruct secret ephemerally when needed
    pub async fn use_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Collect k symbols from k devices
        let symbols = self.collect_k_symbols().await;

        // Reconstruct in secure memory
        let secret = reconstruct_in_secure_memory(symbols);

        // Use it
        let result = f(&secret);

        // Zero the memory
        secure_zero(&secret);

        result
    }
}
```

Private keys, API tokens, OAuth secrets—none of them need to exist complete on any device. They're reconstructed from symbols on demand and immediately zeroed.

---

## Part 4: New Protocol Primitives

### 4.1 Symbol Query (replacing Request-Response)

Instead of sending a request to an endpoint, you **query for symbols**:

```rust
/// Query the network for symbols
pub struct SymbolQuery {
    /// What object do I need?
    object_id: ObjectId,

    /// How confident do I need to be?
    confidence_target: f64,  // 0.0 to 1.0

    /// Maximum time to wait
    deadline: Duration,

    /// Zone requirements (must come from these zones)
    allowed_zones: Vec<ZoneId>,

    /// Source diversity requirements
    min_distinct_sources: u8,
}

/// Query response is a stream of symbols
impl SymbolQuery {
    pub fn execute(&self) -> impl Stream<Item = SymbolEnvelope> {
        // Query all known sources in parallel
        // Stream symbols as they arrive
        // Stop when confidence_target reached or deadline expires
    }
}
```

### 4.2 Epoch-Based Event Streaming

Events don't have sequence numbers. They have epochs.

```rust
/// Subscribe to event epochs
pub struct EpochSubscription {
    topic: TopicId,

    /// Start from this epoch (inclusive)
    since_epoch: EpochId,

    /// Receive future epochs as they complete
    follow: bool,
}

/// Epoch delivery (all events in the epoch as one object)
pub struct EpochDelivery {
    topic: TopicId,
    epoch_id: EpochId,

    /// The epoch's events (as an object)
    epoch_object_id: ObjectId,

    /// Symbol stream for this epoch
    symbols: Vec<SymbolEnvelope>,
}
```

Replay is epoch-granular: "Give me epochs 1000 through 1050." Each epoch is an object, reconstructed from symbols.

### 4.3 Capability as Reconstructable Object

Capabilities are objects. To use a capability, you must first reconstruct it.

```rust
/// Capability definition as an object
pub struct CapabilityObject {
    /// Capability identity
    pub capability_id: CapabilityId,
    pub object_id: ObjectId,  // = hash(self)

    /// What this capability allows
    pub operations: Vec<OperationSpec>,
    pub constraints: CapabilityConstraints,

    /// Reconstruction requirements (security properties!)
    pub min_sources: u8,           // Symbols must come from N distinct sources
    pub required_zones: Vec<ZoneId>,  // Symbols must come from these zones
}
```

**Security insight**: By requiring symbols from multiple zones/sources to reconstruct a capability, you get distributed authorization. No single compromised node can forge a capability—you need to compromise enough sources to get K' symbols.

### 4.4 Zone Bridging as Re-encoding

When data crosses zones, it's not "copied"—it's re-encoded:

```rust
/// Cross-zone data movement as symbol re-encoding
pub struct ZoneBridge {
    source_zone: ZoneId,
    target_zone: ZoneId,

    /// Bridge an object from source to target zone
    pub async fn bridge(&self, object_id: ObjectId) -> BridgeResult {
        // 1. Reconstruct from source zone symbols
        let data = self.reconstruct_from_zone(object_id, self.source_zone).await?;

        // 2. Create new object ID for target zone
        let new_object_id = ObjectId::from_bytes(&data);

        // 3. Encode for target zone (with target zone's key)
        let new_symbols = encode_for_zone(&data, self.target_zone);

        // 4. Mark provenance (tainted by zone crossing)
        let provenance = Provenance::tainted(self.source_zone, self.target_zone);

        // 5. Distribute new symbols, invalidate old
        self.distribute_new_symbols(new_symbols).await?;
        self.invalidate_source_symbols(object_id).await?;

        Ok(BridgeResult {
            new_object_id,
            provenance,
        })
    }
}
```

### 4.5 Symbol Gossip for Discovery

Discovery is not a registry lookup—it's gossip about symbol availability:

```rust
/// Gossip about what symbols you have
pub struct SymbolGossip {
    /// Bloom filter of object IDs I have symbols for
    objects_known: BloomFilter<ObjectId>,

    /// Bloom filter of symbol IDs I hold
    symbols_held: BloomFilter<SymbolId>,

    /// My reconstruction capabilities
    capabilities: Vec<ReconstructionCapability>,
}

/// When you need an object, gossip query
pub struct GossipQuery {
    object_id: ObjectId,

    /// Response: which peers have symbols for this object?
    pub async fn query(&self, peers: &[Peer]) -> Vec<SymbolSource> {
        futures::join_all(peers.iter().map(|p| p.check_availability(self.object_id)))
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .collect()
    }
}
```

### 4.6 Speculative Pre-distribution

If you know what objects will be needed, pre-distribute symbols:

```rust
/// Predictive symbol distribution
pub struct SpeculativeDistributor {
    /// Prediction model (what objects will be needed?)
    predictor: ObjectPredictor,

    /// Pre-distribute symbols before they're requested
    pub async fn speculate(&self) {
        let predictions = self.predictor.predict_next_epoch();

        for (object_id, probability) in predictions {
            if probability > SPECULATION_THRESHOLD {
                // Pre-fetch symbols to likely consumers
                let symbols = self.fetch_symbols(object_id).await;
                self.pre_distribute(symbols, self.predict_consumers(object_id)).await;
            }
        }
    }
}
```

Example: User checks email every day at 9am. At 8:55am, pre-distribute email symbols to their phone. By 9am, reconstruction is instant.

---

## Part 5: Audit and Integrity

### 5.1 Audit as Symbol Chain

The audit log is not a file or database—it's a chain of epoch objects:

```rust
/// Audit chain as linked epoch objects
pub struct AuditChain {
    /// Current epoch being written
    current_epoch: EpochWriter,

    /// Finalized epochs (each is an object in symbol space)
    finalized: Vec<AuditEpochRef>,
}

pub struct AuditEpochRef {
    epoch_id: EpochId,
    object_id: ObjectId,

    /// Link to previous epoch (forms chain)
    previous: ObjectId,

    /// Merkle root of events in this epoch
    merkle_root: [u8; 32],
}

impl AuditChain {
    /// Verify chain integrity by reconstruction
    pub async fn verify(&self) -> VerificationResult {
        let mut prev_id = GENESIS_OBJECT_ID;

        for epoch_ref in &self.finalized {
            // Reconstruct the epoch from symbols
            let epoch = self.reconstruct_epoch(epoch_ref.object_id).await?;

            // Verify chain link
            if epoch.previous != prev_id {
                return VerificationResult::ChainBroken(epoch_ref.epoch_id);
            }

            // Verify merkle root
            if epoch.compute_merkle_root() != epoch_ref.merkle_root {
                return VerificationResult::TamperedEpoch(epoch_ref.epoch_id);
            }

            prev_id = epoch_ref.object_id;
        }

        VerificationResult::Valid
    }
}
```

Tampering is detected by reconstruction failure or chain breakage. Deletion is detected by missing symbols.

### 5.2 Source Diversity as Security

Reconstruction can require symbols from multiple distinct sources:

```rust
/// Require source diversity for reconstruction
pub struct DiversityRequirement {
    /// Minimum distinct sources needed
    min_sources: u8,

    /// Sources must come from these zones
    required_zones: Vec<ZoneId>,

    /// No single source can contribute more than this fraction
    max_single_source_fraction: f64,
}

impl DiversityRequirement {
    pub fn satisfied(&self, symbols: &[SymbolEnvelope]) -> bool {
        let sources: HashSet<_> = symbols.iter().map(|s| &s.source_id).collect();
        let zones: HashSet<_> = symbols.iter().map(|s| &s.zone_id).collect();

        // Check source count
        if sources.len() < self.min_sources as usize {
            return false;
        }

        // Check zone coverage
        if !self.required_zones.iter().all(|z| zones.contains(z)) {
            return false;
        }

        // Check concentration
        let max_from_one = symbols.iter()
            .fold(HashMap::new(), |mut m, s| {
                *m.entry(&s.source_id).or_insert(0) += 1;
                m
            })
            .values()
            .max()
            .unwrap_or(&0);

        (*max_from_one as f64 / symbols.len() as f64) <= self.max_single_source_fraction
    }
}
```

This provides **distributed trust**: Even if one node is compromised, it can't forge data that requires symbols from multiple honest sources.

### 5.3 Trust Model and Byzantine Assumptions

FCP operates under a well-defined threat model:

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

#### 5.3.1 Byzantine Fault Tolerance

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

/// Operation classification by required quorum
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

#### 5.3.2 Trust Boundaries

```rust
/// Trust boundary definitions (NORMATIVE)
pub enum TrustBoundary {
    /// Same device, same process
    Local,

    /// Same device, different process (IPC)
    Process,

    /// Same zone, different device (Tailscale mesh)
    Zone,

    /// Different zone, requires bridging
    CrossZone,

    /// External (Funnel, public internet)
    External,
}

impl TrustBoundary {
    /// Required verification at each boundary
    pub fn required_verification(&self) -> VerificationLevel {
        match self {
            Self::Local => VerificationLevel::None,
            Self::Process => VerificationLevel::ProcessIsolation,
            Self::Zone => VerificationLevel::TailscaleIdentity,
            Self::CrossZone => VerificationLevel::ZonePolicyAndCapability,
            Self::External => VerificationLevel::Full,
        }
    }
}
```

### 5.4 Ordering and Consistency

#### 5.4.1 Epoch Model Refinement

**Decision: Epochs are logical, not wall-clock.**

```rust
/// Epoch definition (NORMATIVE)
pub struct Epoch {
    /// Epoch ID (monotonically increasing)
    pub id: EpochId,

    /// Epoch proposer (device that finalized this epoch)
    pub proposer: TailscaleNodeId,

    /// Epoch seal (signature from proposer)
    pub seal: EpochSeal,

    /// Wall-clock hint (advisory, not authoritative)
    pub timestamp_hint: u64,
}

impl EpochAssigner {
    /// Assign event to epoch
    /// Events received during epoch N go into epoch N
    /// Epoch boundaries are defined by epoch seals, not wall clock
    pub fn assign(&self, event: &Event) -> EpochId {
        self.current_epoch
    }

    /// Seal current epoch and start new one
    /// This creates an ordering point
    pub async fn seal_epoch(&mut self) -> Result<Epoch> {
        let epoch = Epoch {
            id: self.current_epoch,
            proposer: self.my_node_id,
            seal: self.sign_epoch_seal(),
            timestamp_hint: now(),
        };

        // Distribute epoch seal
        self.distribute_epoch_seal(&epoch).await?;

        // Start new epoch
        self.current_epoch = EpochId(self.current_epoch.0 + 1);

        Ok(epoch)
    }
}
```

#### 5.4.2 Ordering-Sensitive Operations

For operations that require strict ordering, use a SequenceObject:

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

#### 5.4.3 Consistency Levels

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

### 5.5 Revocation, Expiry, and Garbage Collection

#### 5.5.1 Revocation Model

**Key insight:** In a symbol-native world, you cannot "delete" data—symbols may exist on offline devices. Revocation is a protocol mechanism, not a storage mechanism.

```rust
/// Revocation object (NORMATIVE)
pub struct RevocationObject {
    /// What is being revoked (ObjectId, CapabilityId, KeyId)
    pub target: RevocationTarget,

    /// Cutoff epoch (revocation effective after this epoch)
    pub cutoff_epoch: EpochId,

    /// Reason (for audit)
    pub reason: RevocationReason,

    /// Signed by authority (Owner or Admin)
    pub signature: Signature,
    pub signer: KeyId,
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

#### 5.5.2 Expiry Model

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

#### 5.5.3 Garbage Collection

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

impl GarbageCollector {
    fn should_delete(&self, symbol: &StoredSymbol) -> bool {
        // Expired?
        if symbol.age() > self.policy.min_retention {
            return true;
        }

        // Tombstoned?
        if self.tombstones.contains_key(&symbol.object_id) {
            return true;
        }

        // Revoked?
        if self.is_revoked(&symbol.object_id) {
            return true;
        }

        false
    }
}
```

### 5.6 Backpressure and DoS Protection

#### 5.6.1 Rate Limiting Model

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

#### 5.6.2 Drop Policies

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
    ControlPlane,

    /// Audit objects
    Audit,

    /// Capability objects
    Capability,

    /// Response objects
    Response,

    /// Request objects
    Request,

    /// Event objects
    Event,

    /// Other (lowest)
    Other,
}
```

---

## Part 6: Concrete Specification Changes

### 6.1 New Section: Symbol Layer (Section 9.X)

Add to FCP Specification:

```markdown
### 9.X Symbol Layer (Fundamental)

FCP operates on the **Symbol Layer**: all data exists as RaptorQ-encoded symbols.
This is not an optimization but the foundational primitive.

#### 9.X.1 SymbolEnvelope

The atomic unit of FCP transmission:

| Field | Type | Description |
|-------|------|-------------|
| object_id | [u8; 32] | SHA256 hash of canonical object serialization |
| esi | u32 | Encoding Symbol ID (unique within object) |
| k | u16 | Source symbols needed for reconstruction |
| symbol_size | u16 | Bytes per symbol |
| object_size | u32 | Original object size |
| epoch_id | u64 | Epoch this symbol belongs to |
| zone_id | ZoneId | Cryptographic zone namespace |
| source_id | SourceId | Origin of this symbol |
| data | bytes | Symbol data (encrypted with zone key) |
| auth_tag | [u8; 16] | Authentication tag |

#### 9.X.2 Reconstruction Semantics

- Reconstruction MAY begin upon receiving any symbol
- Reconstruction succeeds when K' symbols received (K' ≈ K × 1.002)
- Symbols MAY arrive from any combination of sources and paths
- Source diversity requirements MAY be enforced per-object

#### 9.X.3 Epoch Semantics

- All FCP objects belong to an epoch
- Epoch duration: 1 second (configurable)
- Within an epoch, no ordering is defined
- Ordering exists only BETWEEN epochs
- Replay operates at epoch granularity

#### 9.X.4 Zone Encryption

- Each zone has a derived zone key
- Symbol data is encrypted with the zone key
- Zone isolation is cryptographic, not topological
- Cross-zone data movement requires re-encoding
```

### 6.2 Modify Section 9.3: Frame Format

Replace current frame format with symbol-based format:

```markdown
### 9.3 Frame Format (FCP1-SYM)

FCP frames are batches of SymbolEnvelopes:

```
┌──────────────────────────────────────────────────────────────────┐
│                    FCP SYMBOL FRAME FORMAT                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Bytes 0-3:   Magic (0x46 0x43 0x50 0x53 = "FCPS")              │
│  Bytes 4-5:   Frame flags (u16 LE)                               │
│  Bytes 6-7:   Symbol count (u16 LE)                              │
│  Bytes 8-15:  Frame timestamp (u64 LE)                           │
│  Bytes 16+:   [SymbolEnvelope] × symbol_count                    │
│  Final 8:     Checksum (XXH3-64)                                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

Frames are transparent batches. The "message" concept is replaced by
"object reconstruction from symbols".
```

### 6.3 New Section: Object Types

Replace "Message Types" with "Object Types":

```markdown
### 9.X Object Types

All FCP messages are objects encoded as symbols:

| Object Type | ObjectId Derivation | Purpose |
|-------------|---------------------|---------|
| HandshakeObject | hash(canonical) | Session establishment |
| InvokeObject | hash(canonical) | Capability invocation |
| ResponseObject | hash(canonical) | Invocation result |
| EventEpochObject | hash(epoch_events) | Batch of events in epoch |
| HealthObject | hash(snapshot) | Health status |
| CapabilityObject | hash(capability_def) | Capability definition |
| AuditEpochObject | hash(audit_events) | Audit entries for epoch |

Objects are not "sent to destinations"—they are encoded as symbols
and distributed. Reconstruction occurs at any node with sufficient symbols.
```

### 6.4 Zone Namespace Specification

Add to Zone section:

```markdown
### 3.X Zone as Symbol Namespace

Zones define cryptographic namespaces for symbols:

| Property | Description |
|----------|-------------|
| zone_key | Derived encryption key for symbol data |
| min_sources | Minimum distinct sources for reconstruction |
| distribution_policy | How symbols should be spread across devices |

Zone isolation is CRYPTOGRAPHIC:
- Symbols are encrypted with zone key
- A node without zone key cannot decode symbols
- This is defense-in-depth on top of ACL enforcement

Zone crossing requires re-encoding:
1. Reconstruct object from source zone symbols
2. Re-encode with target zone key
3. Distribute new symbols
4. Mark provenance as tainted
```

---

## Part 7: Implementation Implications

### 7.1 fcp-core Changes

```rust
// fcp-core becomes symbol-native

pub mod symbol {
    pub struct SymbolEnvelope { /* as defined */ }
    pub struct ObjectId(pub [u8; 32]);
    pub struct EpochId(pub u64);
}

pub mod reconstruction {
    pub struct Reconstructor { /* RaptorQ decoder */ }
    pub struct PartialObject { /* symbols received so far */ }
}

pub mod zone {
    pub struct ZoneKey { /* derived encryption key */ }
    pub struct ZoneNamespace { /* zone symbol config */ }
}

// Message types become object types
pub mod objects {
    pub struct HandshakeObject { /* ... */ }
    pub struct InvokeObject { /* ... */ }
    pub struct ResponseObject { /* ... */ }
    pub struct EventEpochObject { /* ... */ }
}
```

### 7.2 Wire Protocol Changes

```rust
// Frame is just a symbol batch
pub struct Frame {
    pub magic: [u8; 4],  // "FCPS"
    pub flags: FrameFlags,
    pub symbols: Vec<SymbolEnvelope>,
    pub checksum: u64,
}

// No distinction between "data" and "control" frames
// Everything is symbols
```

### 7.3 Transport Layer Changes

```rust
// All transports implement SymbolTransport
pub trait SymbolTransport {
    /// Emit symbols (to network, storage, wherever)
    async fn emit(&self, symbols: Vec<SymbolEnvelope>) -> Result<()>;

    /// Receive symbols (from any source)
    async fn receive(&self) -> Result<SymbolEnvelope>;
}

// MultipathTransport uses ALL available transports
pub struct MultipathTransport {
    transports: Vec<Box<dyn SymbolTransport>>,

    async fn emit(&self, symbols: Vec<SymbolEnvelope>) -> Result<()> {
        // Distribute symbols across all transports
        // (e.g., round-robin, or duplicate for redundancy)
    }

    async fn receive(&self) -> Result<SymbolEnvelope> {
        // Race all transports, return first symbol
        futures::select_all(self.transports.iter().map(|t| t.receive())).await
    }
}
```

---

## Part 8: Summary

Universal fungibility transforms FCP from a message-passing protocol into a **symbol-flow protocol**. The key shifts:

| Traditional | Fungible |
|-------------|----------|
| Send to address | Request object by ID |
| Establish connection | Aggregate symbols |
| Primary + replicas | Just symbols |
| Sequential events | Epoch-grouped events |
| Store at location | Distribute as symbols |
| Trust specific nodes | Require source diversity |
| Binary availability | Probabilistic reconstruction |
| Failover paths | All paths contribute |

This is not incremental—it's a paradigm shift. But it's the right paradigm for a distributed, resilient, sovereign AI infrastructure where:

- Any device can fail
- Any network path can fail
- Any subset of your devices should be sufficient
- Secrets should never exist complete anywhere
- History should be tamper-evident by construction

**Universal fungibility gives us all of this for free.** We just have to build on it instead of around it.

---

## Appendix: Migration Considerations

Existing FCP concepts map to fungible equivalents:

| Current | Fungible Equivalent |
|---------|---------------------|
| `ConnectorId` | `CapabilityObjectId` |
| `InstanceId` | Reconstructed at any node |
| `SessionId` | Epoch-scoped correlation |
| `InvokeRequest` | `InvokeObject` (as symbols) |
| `InvokeResponse` | `ResponseObject` (as symbols) |
| `EventEnvelope` | Part of `EventEpochObject` |
| `HealthSnapshot` | `HealthObject` |
| Connection | Symbol aggregation |
| Retry logic | Collect more symbols |
| Failover | Automatic (any source helps) |

The wire format changes, but the semantic operations (handshake, invoke, subscribe, health) remain. They're just expressed as object reconstruction instead of request-response.

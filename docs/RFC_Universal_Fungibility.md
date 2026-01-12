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
    /// Derive ObjectId from canonical serialization
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(sha256(data))
    }

    /// Everything is an object
    pub fn from<T: Serialize>(value: &T) -> Self {
        Self::from_bytes(&canonical_serialize(value))
    }
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

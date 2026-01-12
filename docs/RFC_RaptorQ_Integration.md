# RFC: RaptorQ Deep Integration into FCP

## Abstract

This RFC proposes integrating RaptorQ (RFC 6330) fountain codes as a fundamental primitive throughout the Flywheel Connector Protocol. RaptorQ's unique property of **data fungibility** - where any K' symbols (K' ≈ K + 0.2% overhead) can reconstruct K source symbols - enables powerful capabilities for fault tolerance, multipath transport, distributed storage, and efficient multicast.

## Motivation

### The Magic of RaptorQ

RaptorQ is a rateless erasure code with remarkable properties:

1. **Fountain Property**: Generate unlimited encoding symbols from source data
2. **Symbol Fungibility**: ANY K' symbols can decode - no specific symbols required
3. **Systematic Encoding**: First K symbols ARE the original data (zero overhead if no loss)
4. **Linear Complexity**: O(n) encoding and decoding
5. **Low Overhead**: ~0.2% extra symbols needed beyond source size

```
Traditional: Need packets [1,2,3,4,5] specifically
RaptorQ:     Need ANY 5+ symbols from [1,2,3,4,5,6,7,8,...]
```

### Why This Matters for FCP

FCP's architecture has several areas where RaptorQ's fungibility transforms the design:

| FCP Component | Current Approach | With RaptorQ |
|---------------|------------------|--------------|
| Large frame transport | Retransmit lost segments | Collect ANY symbols from ANY source |
| Event replay buffer | Sequential log on single node | Distributed symbols across nodes |
| Connector distribution | HTTP download with resume | Parallel from CDN + P2P + multicast |
| Audit log archival | Replicated storage | k-of-n redundancy with minimal overhead |
| Multipath transport | Primary + failover | Aggregate bandwidth from ALL paths |

---

## Design

### Core Concept: Object-Symbol Model

Instead of treating data as indivisible blobs, FCP-RQ (RaptorQ mode) treats data as **objects** that can be encoded into fungible **symbols**.

```
┌─────────────────────────────────────────────────────────────┐
│                    OBJECT-SYMBOL MODEL                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Object (e.g., FCP Message, Event Batch, Binary)          │
│   ┌─────────────────────────────────────────────┐          │
│   │  Original Data (K source symbols worth)     │          │
│   └─────────────────────────────────────────────┘          │
│                        │                                    │
│                   RaptorQ Encode                            │
│                        │                                    │
│                        ▼                                    │
│   ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐       │
│   │ S₀  │ S₁  │ S₂  │ ... │ Sₖ  │Sₖ₊₁ │ ... │ Sₙ  │       │
│   └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘       │
│     ▲                       ▲                               │
│     │                       │                               │
│     │    Systematic         │    Repair symbols             │
│     │    (= original)       │    (unlimited)                │
│                                                             │
│   ANY K' symbols (K' ≈ K × 1.002) → Decode → Original      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Object Identifier

Every object has a content-addressed identifier:

```rust
/// Object identifier (content-addressed)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]); // SHA256(canonical_bytes)

impl ObjectId {
    pub fn from_data(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        Self(Sha256::digest(data).into())
    }
}

/// Symbol identifier within an object
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolId {
    pub object_id: ObjectId,
    pub encoding_symbol_id: u32, // ESI from RaptorQ
}
```

### Encoded Symbol

```rust
/// A single encoded symbol
#[derive(Clone, Serialize, Deserialize)]
pub struct EncodedSymbol {
    /// Which object this symbol belongs to
    pub object_id: ObjectId,

    /// Encoding Symbol ID (ESI) - uniquely identifies this symbol
    pub esi: u32,

    /// The encoded data
    pub data: Vec<u8>,
}
```

---

## Integration Points

### 1. Wire Protocol: RaptorQ Frame Mode (FCP1-RQ)

Add a new frame flag and frame type for RaptorQ-encoded messages:

```rust
bitflags! {
    pub struct FrameFlags: u16 {
        // ... existing flags ...

        /// Frame contains RaptorQ symbol(s), not complete message
        const RAPTORQ = 0b0100_0000_0000;
    }
}
```

**RaptorQ Frame Format:**

```
┌────────────────────────────────────────────────────────────────┐
│                  FCP RAPTORQ FRAME FORMAT                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Bytes 0-3:   Magic (0x46 0x43 0x50 0x31 = "FCP1")            │
│  Bytes 4-5:   Version (u16 LE)                                 │
│  Bytes 6-7:   Flags (u16 LE) - RAPTORQ bit set                │
│  Bytes 8-11:  Sequence (u32 LE)                                │
│  Bytes 12-15: Payload Length (u32 LE)                          │
│  Bytes 16-23: Timestamp (u64 LE)                               │
│  Bytes 24-39: Correlation ID (UUID)                            │
│  ────────────────────────────────────────────────────────────  │
│  Bytes 40-71: Object ID (32 bytes, SHA256)                     │
│  Bytes 72-75: Object Size (u32 LE, original bytes)             │
│  Bytes 76-77: Symbol Size (u16 LE)                             │
│  Bytes 78-79: Symbols in Frame (u16 LE, count)                 │
│  Bytes 80+:   Symbol entries: [ESI (u32) + Data (symbol_size)] │
│  Final 8:     Checksum (XXH3-64)                               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**Usage: Large Message Transport**

For messages larger than a threshold (e.g., 64KB), the sender encodes to symbols:

```rust
impl RaptorQTransport {
    pub fn send_large(&mut self, message: &FcpMessage) -> Result<()> {
        let bytes = serialize(message)?;
        let object_id = ObjectId::from_data(&bytes);

        // Encode to symbols (systematic + repair)
        let encoder = Encoder::new(&bytes, SYMBOL_SIZE);
        let symbols: Vec<EncodedSymbol> = encoder
            .get_encoded_packets(REPAIR_SYMBOL_COUNT)
            .map(|p| EncodedSymbol {
                object_id,
                esi: p.encoding_symbol_id(),
                data: p.data().to_vec(),
            })
            .collect();

        // Send symbols (can be over multiple paths/connections)
        for symbol in symbols {
            self.send_symbol_frame(symbol)?;
        }
        Ok(())
    }
}
```

**Receiver Reconstruction:**

```rust
impl RaptorQTransport {
    pub fn receive(&mut self) -> Result<Option<FcpMessage>> {
        let frame = self.recv_frame()?;

        if frame.flags.contains(FrameFlags::RAPTORQ) {
            let symbols = parse_symbols(&frame);
            for symbol in symbols {
                let decoder = self.decoders
                    .entry(symbol.object_id)
                    .or_insert_with(|| Decoder::new(frame.object_size));

                decoder.add_symbol(symbol.esi, &symbol.data);

                if let Some(data) = decoder.try_decode() {
                    self.decoders.remove(&symbol.object_id);
                    return Ok(Some(deserialize(&data)?));
                }
            }
            Ok(None) // Need more symbols
        } else {
            // Regular frame
            Ok(Some(deserialize(&frame.payload)?))
        }
    }
}
```

**Benefits:**
- Lossy transport tolerance (UDP, unreliable networks)
- Multipath aggregation (combine WiFi + cellular + wired)
- No retransmission protocol needed
- Natural congestion response (send more symbols if loss detected)

---

### 2. Event Streaming: Epoch-Based RaptorQ Buffers

Transform the event replay buffer from a sequential log to a distributed symbol store:

```
┌─────────────────────────────────────────────────────────────────┐
│              EPOCH-BASED RAPTORQ EVENT BUFFER                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Event Stream:  E₁ → E₂ → E₃ │ E₄ → E₅ → E₆ │ E₇ → E₈ → ...  │
│                 └─────────────┘ └─────────────┘                 │
│                    Epoch 1         Epoch 2                      │
│                        │               │                        │
│                   RaptorQ          RaptorQ                      │
│                   Encode           Encode                       │
│                        │               │                        │
│                        ▼               ▼                        │
│                   [S₁₁..S₁ₙ]     [S₂₁..S₂ₙ]                    │
│                        │               │                        │
│              ┌─────────┼───────────────┼─────────┐             │
│              ▼         ▼               ▼         ▼             │
│           Node A    Node B          Node C    Node D           │
│           [S₁₁,S₂₃] [S₁₂,S₂₁]     [S₁₃,S₂₂] [S₁₄,S₂₄]        │
│                                                                 │
│  Replay: Collect K' symbols for epoch → Decode → Events        │
│          Can fetch from ANY subset of nodes!                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```rust
/// Epoch-based RaptorQ event buffer
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
    async fn finalize_epoch(&self) -> Result<()> {
        let epoch = self.current_epoch.write().await.take();
        let events_cbor = serialize_events(&epoch.events)?;
        let object_id = ObjectId::from_data(&events_cbor);

        // Encode to symbols
        let encoder = Encoder::new(&events_cbor, SYMBOL_SIZE);
        let symbols: Vec<_> = encoder.get_encoded_packets(REPAIR_RATIO)
            .collect();

        // Distribute symbols across self + peers (round-robin or hash-based)
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
            // ...
        });

        Ok(())
    }

    /// Replay events from a cursor
    pub async fn replay(&self, since: &str) -> impl Stream<Item = EventEnvelope> {
        let start_epoch = parse_cursor_epoch(since);

        stream::iter(start_epoch..)
            .then(|epoch_id| self.reconstruct_epoch(epoch_id))
            .flat_map(|events| stream::iter(events))
    }

    /// Reconstruct an epoch from distributed symbols
    async fn reconstruct_epoch(&self, epoch_id: u64) -> Vec<EventEnvelope> {
        let meta = self.finalized_epochs.read().await.get(&epoch_id).cloned();
        let meta = match meta {
            Some(m) => m,
            None => return vec![],
        };

        let mut decoder = Decoder::new(meta.original_size as usize);

        // Fetch from local first
        for (key, data) in self.local_symbols.read().await.iter() {
            if key.0 == epoch_id {
                decoder.add_symbol(key.1, data);
                if let Some(decoded) = decoder.try_decode() {
                    return deserialize_events(&decoded);
                }
            }
        }

        // Fetch from peers in parallel (race for K' symbols)
        let peer_symbols = futures::future::join_all(
            self.peers.iter().map(|p| p.fetch_symbols(epoch_id))
        ).await;

        for symbols in peer_symbols {
            for (esi, data) in symbols {
                decoder.add_symbol(esi, &data);
                if let Some(decoded) = decoder.try_decode() {
                    return deserialize_events(&decoded);
                }
            }
        }

        vec![] // Insufficient symbols
    }
}
```

**Benefits:**
- **Fault tolerance**: Any k-of-n nodes can reconstruct
- **Load balancing**: Fetch symbols from least-loaded nodes
- **Bandwidth efficiency**: ~0.2% overhead for erasure coding
- **Flexible replication**: Adjust symbol distribution for different redundancy levels
- **No coordination**: Nodes don't need to agree on which symbols to store

---

### 3. Connector Binary Distribution

Connector binaries (< 20MB target) are perfect for RaptorQ distribution:

```
┌─────────────────────────────────────────────────────────────────┐
│            RAPTORQ CONNECTOR DISTRIBUTION                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Binary (20MB)                                                 │
│        │                                                        │
│        ▼                                                        │
│   RaptorQ Encode (1KB symbols)                                  │
│        │                                                        │
│        ▼                                                        │
│   ~20,500 symbols (20,000 systematic + 500 repair)             │
│        │                                                        │
│        ▼                                                        │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                   DISTRIBUTION                           │  │
│   │                                                          │  │
│   │   CDN Edge ──────┐                                       │  │
│   │   (symbols 0-5000)│                                      │  │
│   │                   │                                      │  │
│   │   P2P Peers ─────┼────► Connector fetches from ALL      │  │
│   │   (random symbols)│      First 20,100+ symbols wins!    │  │
│   │                   │                                      │  │
│   │   Multicast ─────┘                                       │  │
│   │   (repair symbols)                                       │  │
│   │                                                          │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│   Verification: SHA256(decoded) == expected_hash               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```rust
/// Connector update client using RaptorQ
pub struct ConnectorUpdater {
    sources: Vec<SymbolSource>,
    local_cache: PathBuf,
}

enum SymbolSource {
    Cdn { base_url: String },
    Peer { addr: SocketAddr },
    Multicast { group: Ipv4Addr, port: u16 },
}

impl ConnectorUpdater {
    pub async fn fetch(&self, manifest: &UpdateManifest) -> Result<Vec<u8>> {
        let mut decoder = Decoder::new(manifest.size);

        // Start fetching from all sources in parallel
        let mut symbol_streams: Vec<_> = self.sources.iter()
            .map(|s| s.fetch_symbols(manifest.object_id))
            .collect();

        let mut combined = futures::stream::select_all(symbol_streams);

        while let Some(symbol) = combined.next().await {
            decoder.add_symbol(symbol.esi, &symbol.data);

            // Progress: symbols_received / symbols_needed
            let progress = decoder.symbols_received() as f64
                / decoder.symbols_needed() as f64;

            if let Some(data) = decoder.try_decode() {
                // Verify hash
                if ObjectId::from_data(&data) != manifest.object_id {
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
- **Parallel download**: All sources contribute simultaneously
- **Heterogeneous sources**: CDN + P2P + multicast all help
- **Resumable**: No bookmark needed - any symbols help
- **Efficient multicast**: One broadcast, all receivers decode
- **DoS resistance**: Can't block specific critical symbols

---

### 4. Distributed Audit Log Archival

Audit logs require durable, tamper-evident storage:

```rust
/// Archive audit logs using RaptorQ for distributed redundancy
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
    symbol_distribution: HashMap<NodeId, Vec<u32>>, // node -> ESIs
}

impl RaptorQAuditArchive {
    /// Archive a batch of audit entries
    pub async fn archive(&mut self, entries: Vec<AuditEntry>) -> Result<ArchiveId> {
        // Build Merkle tree for tamper evidence
        let merkle_tree = MerkleTree::from_entries(&entries);
        let data = serialize_with_merkle(&entries, &merkle_tree)?;
        let object_id = ObjectId::from_data(&data);

        // Encode to symbols
        let encoder = Encoder::new(&data, SYMBOL_SIZE);
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
            // ...
        });

        Ok(archive_id)
    }

    /// Retrieve and verify archived audit log
    pub async fn retrieve(&self, archive_id: ArchiveId) -> Result<Vec<AuditEntry>> {
        let meta = self.archives.get(&archive_id)
            .ok_or(Error::ArchiveNotFound)?;

        let mut decoder = Decoder::new(meta.original_size);

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

### 5. Multipath Transport Layer

For connectors in challenging network environments (IoT, mobile, edge):

```rust
/// Multipath transport using RaptorQ symbol aggregation
pub struct MultipathTransport {
    paths: Vec<TransportPath>,
    pending_objects: HashMap<ObjectId, ObjectDecoder>,
}

enum TransportPath {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Quic(QuicConnection),
    WebSocket(WsStream),
}

impl MultipathTransport {
    /// Send message over all available paths
    pub async fn send(&mut self, msg: &FcpMessage) -> Result<()> {
        let data = serialize(msg)?;
        let object_id = ObjectId::from_data(&data);

        let encoder = Encoder::new(&data, SYMBOL_SIZE);
        let symbols: Vec<_> = encoder.get_encoded_packets(REPAIR_COUNT).collect();

        // Distribute symbols across paths
        for (i, symbol) in symbols.iter().enumerate() {
            let path_idx = i % self.paths.len();
            self.paths[path_idx].send_symbol(object_id, symbol).await?;
        }

        Ok(())
    }

    /// Receive from all paths, reconstruct when K' symbols arrive
    pub async fn recv(&mut self) -> Result<FcpMessage> {
        loop {
            // Race all paths for next symbol
            let symbol = futures::select_biased! {
                s = self.paths[0].recv_symbol() => s?,
                s = self.paths[1].recv_symbol() => s?,
                // ... for all paths
            };

            let decoder = self.pending_objects
                .entry(symbol.object_id)
                .or_insert_with(|| ObjectDecoder::new(symbol.object_size));

            decoder.add_symbol(symbol.esi, &symbol.data);

            if let Some(data) = decoder.try_decode() {
                self.pending_objects.remove(&symbol.object_id);
                return Ok(deserialize(&data)?);
            }
        }
    }
}
```

**Benefits:**
- Aggregate bandwidth from all network interfaces
- Automatic failover (paths can die, symbols still arrive)
- Latency optimization (first K' arrivals win)
- No complex multipath coordination protocol

---

## New Crate: `fcp-raptorq`

### Module Structure

```
crates/fcp-raptorq/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public API
    ├── object.rs        # ObjectId, SymbolId types
    ├── encoder.rs       # RaptorQ encoding wrapper
    ├── decoder.rs       # RaptorQ decoding wrapper
    ├── frame.rs         # FCP1-RQ frame format
    ├── transport.rs     # RaptorQ transport layer
    ├── buffer.rs        # Epoch-based event buffer
    ├── store.rs         # Distributed symbol storage
    └── update.rs        # Connector update protocol
```

### Dependencies

```toml
[dependencies]
raptorq = "2.0"          # Core RaptorQ implementation
sha2 = "0.10"            # Object ID hashing
fcp-core = { path = "../fcp-core" }
tokio = { version = "1", features = ["full"] }
futures = "0.3"
bytes = "1"
```

### Public API

```rust
// crates/fcp-raptorq/src/lib.rs

pub mod object;
pub mod encoder;
pub mod decoder;
pub mod frame;
pub mod transport;
pub mod buffer;
pub mod store;
pub mod update;

// Re-exports
pub use object::{ObjectId, SymbolId, EncodedSymbol};
pub use encoder::RaptorQEncoder;
pub use decoder::RaptorQDecoder;
pub use frame::{RaptorQFrame, parse_rq_frame, build_rq_frame};
pub use transport::RaptorQTransport;
pub use buffer::RaptorQEventBuffer;
pub use store::DistributedSymbolStore;
pub use update::ConnectorUpdater;

/// Configuration for RaptorQ operations
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

---

## Protocol Extensions

### Handshake Configuration

RaptorQ is fundamental to FCP - all data flows as fungible symbols. Handshake includes symbol configuration:

```json
{
  "protocol_version": "1.0.0",
  "transport_caps": {
    "compression": ["zstd"],
    "max_frame_size": 65536,
    "raptorq": {
      "symbol_sizes": [512, 1024, 2048],
      "preferred_symbol_size": 1024,
      "max_object_size": 67108864
    }
  }
}
```

### Subscribe Configuration

Event subscriptions include epoch configuration for symbol buffering:

```json
{
  "type": "subscribe",
  "id": "sub_123",
  "topics": ["connector.events"],
  "raptorq": {
    "epoch_duration_ms": 1000,
    "symbol_size": 1024
  }
}
```

### Frame Flag

The `RAPTORQ` frame flag is set on all data frames:

```rust
bitflags! {
    pub struct FrameFlags: u16 {
        // ... existing ...
        const RAPTORQ = 0b0100_0000_0000;  // RaptorQ symbols (always set for data frames)
    }
}
```

---

## Performance Characteristics

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

---

## Security Considerations

1. **Object ID Verification**: Always verify `SHA256(decoded) == object_id`
2. **Symbol Authentication**: Consider HMAC per symbol for untrusted sources
3. **Replay Protection**: Include nonce/timestamp in object data
4. **Resource Limits**: Cap decoder memory, timeout stale decoders

---

## Implementation Phases

1. **Phase 1**: Add `fcp-raptorq` crate with core types
2. **Phase 2**: Implement RaptorQ frame mode in wire protocol
3. **Phase 3**: Add epoch-based event buffer infrastructure
4. **Phase 4**: Implement connector update protocol
5. **Phase 5**: Add multipath transport support

RaptorQ capabilities are declared during handshake via `transport_caps.raptorq`. See FCP Specification Section 9.4 (Frame Flags) and Section 9.9 (Streaming, Replay, and Backpressure) for protocol integration.

---

## Conclusion

RaptorQ is not an optional feature but the foundational primitive of FCP. The protocol operates on **fungible symbol flows**, not discrete messages. This fundamental design choice enables:

- **Fault tolerance without coordination** (any k-of-n symbols work)
- **Multipath without complexity** (all paths contribute equally)
- **Distribution without assignment** (no need to track who has what)
- **Efficiency without waste** (~0.2% overhead)
- **Universal resilience** (every data flow is inherently erasure-coded)

By making RaptorQ fundamental rather than optional, FCP achieves true data fungibility everywhere - enabling the sovereign mesh architecture where any subset of devices can reconstruct any data.

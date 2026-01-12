# RFC: Sovereign AI Mesh - Tailscale + RaptorQ Deep Integration

## Abstract

This RFC proposes combining Tailscale's trusted mesh networking with RaptorQ's fungible data encoding to create a **Sovereign AI Mesh** - a distributed, self-healing, zero-cloud personal AI infrastructure that runs entirely on YOUR devices.

The key insight: **Tailscale provides the trusted identity mesh. RaptorQ provides coordination-free data distribution. Together, they enable true digital sovereignty.**

---

## The Vision

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                        SOVEREIGN AI MESH                                    │
│                                                                             │
│    Your Tailscale identity = Root of trust                                  │
│    Your devices = Distributed infrastructure                                │
│    RaptorQ symbols = Coordination-free resilience                           │
│    FCP zones = Capability-controlled access                                 │
│                                                                             │
│    ┌─────────────────────────────────────────────────────────────────┐     │
│    │                                                                 │     │
│    │     Laptop ◄────────────► Desktop ◄────────────► Server        │     │
│    │        │                     │                      │          │     │
│    │        └─────────┬───────────┴───────────┬──────────┘          │     │
│    │                  │                       │                     │     │
│    │               Phone                   Tablet                   │     │
│    │                                                                 │     │
│    │     ALL your devices. ALL authenticated. ALL encrypted.        │     │
│    │     Data exists as fungible symbols across the mesh.           │     │
│    │     Any k-of-n devices can reconstruct anything.               │     │
│    │                                                                 │     │
│    └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│    ZERO cloud dependency. ZERO single point of failure. YOUR data.         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why This Combination Is Profound

### Tailscale's Properties

| Property | Benefit for FCP |
|----------|-----------------|
| **Identity-based networking** | Every node cryptographically authenticated |
| **Zero-config mesh** | Devices auto-discover, NAT traversal solved |
| **WireGuard encryption** | All traffic encrypted end-to-end |
| **ACL system with tags** | Network-level zone enforcement |
| **MagicDNS** | `laptop.yourtailnet.ts.net` just works |
| **DERP relays** | Always reachable, even behind strict NAT |
| **Funnel** | Controlled exposure to public internet |

### RaptorQ's Properties

| Property | Benefit for FCP |
|----------|-----------------|
| **Symbol fungibility** | ANY k' symbols reconstruct data |
| **No coordination** | Nodes don't need to agree on who stores what |
| **Fountain codes** | Generate unlimited repair symbols |
| **O(n) complexity** | Fast encoding/decoding |
| **0.2% overhead** | Near-optimal efficiency |

### The Synergy

| Combined Property | What It Enables |
|-------------------|-----------------|
| **Authenticated symbol routing** | Know exactly which trusted devices have which symbols |
| **Encrypted symbol transport** | Symbols flow securely without additional crypto layer |
| **Coordination-free resilience** | Devices join/leave, symbols automatically redistribute |
| **Network-level zone isolation** | Tailscale ACLs enforce FCP zones at wire level |
| **Identity = Capability root** | Tailscale identity anchors FCP capability chain |

---

## Architecture

### Layer Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         APPLICATION LAYER                                    │
│                                                                             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│   │    Gmail    │  │   Discord   │  │   GitHub    │  │   Files     │       │
│   │  Connector  │  │  Connector  │  │  Connector  │  │  Connector  │       │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │
│          │                │                │                │               │
├──────────┴────────────────┴────────────────┴────────────────┴───────────────┤
│                           FCP PROTOCOL LAYER                                 │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  Distributed Hub │ Zone Enforcer │ Capability Minter │ Audit   │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│                                    │                                        │
├────────────────────────────────────┴────────────────────────────────────────┤
│                         RAPTORQ SYMBOL LAYER                                 │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  Encoder │ Decoder │ Symbol Router │ Collective Store           │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│                                    │                                        │
├────────────────────────────────────┴────────────────────────────────────────┤
│                        TAILSCALE MESH LAYER                                  │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  Peer Discovery │ ACL Enforcement │ Encrypted Transport │ DERP  │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│                                    │                                        │
├────────────────────────────────────┴────────────────────────────────────────┤
│                          DEVICE LAYER                                        │
│                                                                             │
│      Laptop            Desktop            Server            Phone           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Zone-to-Tag Mapping (Defense-in-Depth)

FCP zones map directly to Tailscale tags, providing network-level enforcement that layers on top of FCP's mechanical zone checks:

```
FCP Zone          Tailscale Tag         Trust Level
─────────────────────────────────────────────────────
z:owner      →    tag:fcp-owner         Highest (100)
z:private    →    tag:fcp-private       High (80)
z:work       →    tag:fcp-work          Medium (60)
z:project:*  →    tag:fcp-proj-*        Variable
z:community  →    tag:fcp-community     Low (40)
z:public     →    (via Funnel)          Lowest (0)
```

**CRITICAL:** Tailscale ACLs provide defense-in-depth but do NOT replace FCP zone checks. The security model is layered:

1. **Network layer (Tailscale)**: ACLs prevent unauthorized network access between zones
2. **Protocol layer (FCP)**: Zone enforcement, capability verification, and provenance tracking
3. **Both layers are required**: A request must pass both Tailscale ACLs AND FCP zone checks

### Tailscale ACL Policy (Auto-Generated)

```json
{
  "tagOwners": {
    "tag:fcp-owner": ["autogroup:admin"],
    "tag:fcp-private": ["autogroup:admin"],
    "tag:fcp-work": ["autogroup:admin"],
    "tag:fcp-community": ["autogroup:admin"]
  },

  "acls": [
    // Owner zone: full mesh access
    {
      "action": "accept",
      "src": ["tag:fcp-owner"],
      "dst": ["tag:fcp-owner:*"]
    },

    // Private can reach owner (for symbol reconstruction)
    {
      "action": "accept",
      "src": ["tag:fcp-private"],
      "dst": ["tag:fcp-owner:9473"]  // FCP port only
    },

    // Work zone isolated
    {
      "action": "accept",
      "src": ["tag:fcp-work"],
      "dst": ["tag:fcp-work:*"]
    },

    // Community via Funnel only
    {
      "action": "accept",
      "src": ["autogroup:internet"],
      "dst": ["tag:fcp-community:443"]  // Funnel port
    }
  ],

  "tests": [
    // Owner devices can talk to each other
    {"src": "tag:fcp-owner", "accept": ["tag:fcp-owner:9473"]},

    // Community cannot reach owner directly
    {"src": "tag:fcp-community", "deny": ["tag:fcp-owner:9473"]}
  ]
}
```

**This means FCP zone isolation is enforced at the NETWORK LEVEL**, not just application level. A compromised connector literally cannot reach higher-trust zones.

---

## Core Concepts

### 1. Collective Memory

Every piece of state in your flywheel becomes RaptorQ symbols distributed across your tailnet:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           COLLECTIVE MEMORY                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Event/State                                                               │
│       │                                                                     │
│       ▼                                                                     │
│   RaptorQ Encode (k source symbols)                                         │
│       │                                                                     │
│       ▼                                                                     │
│   Symbols [S₁, S₂, S₃, ..., Sₙ] (n = k × 1.5 for redundancy)               │
│       │                                                                     │
│       ├──► Laptop stores symbols  {1, 4, 7, 10, ...}                       │
│       ├──► Desktop stores symbols {2, 5, 8, 11, ...}                       │
│       ├──► Server stores symbols  {3, 6, 9, 12, ...}                       │
│       └──► Phone stores symbols   {overflow/repair}                        │
│                                                                             │
│   Reconstruction: ANY k' ≈ k symbols from ANY devices                       │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  Laptop dies?    Desktop + Server + Phone have enough symbols   │       │
│   │  Server offline? Laptop + Desktop + Phone have enough symbols   │       │
│   │  Only phone?     Wait for another device, or fetch via DERP     │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Distributed Hub

The FCP Hub itself runs as a distributed system across your devices:

```rust
/// Distributed Hub running across tailnet
pub struct DistributedHub {
    /// Local node's hub instance
    local: HubInstance,

    /// Peer hub instances (discovered via Tailscale)
    peers: HashMap<TailscaleNodeId, PeerHub>,

    /// Hub state as RaptorQ-encoded symbols
    state_symbols: SymbolStore,

    /// Consensus: Leader election via Tailscale node ordering
    leader: Option<TailscaleNodeId>,
}

impl DistributedHub {
    /// Any hub instance can handle requests
    pub async fn handle_request(&self, req: FcpRequest) -> FcpResult<FcpResponse> {
        // Reconstruct current state from symbols
        let state = self.reconstruct_state().await?;

        // Process request
        let (response, state_delta) = self.local.process(req, &state)?;

        // Encode state delta as symbols, distribute
        if let Some(delta) = state_delta {
            self.distribute_state_update(delta).await?;
        }

        Ok(response)
    }

    /// Reconstruct state from symbols across tailnet
    async fn reconstruct_state(&self) -> FcpResult<HubState> {
        let mut decoder = RaptorQDecoder::new();

        // Local symbols first
        for sym in self.state_symbols.local_symbols() {
            if let Some(state) = decoder.add_symbol(sym) {
                return Ok(state);
            }
        }

        // Fetch from peers via Tailscale
        for (_, peer) in &self.peers {
            if peer.online {
                let symbols = peer.fetch_state_symbols().await?;
                for sym in symbols {
                    if let Some(state) = decoder.add_symbol(sym) {
                        return Ok(state);
                    }
                }
            }
        }

        Err(FcpError::InsufficientSymbols)
    }
}
```

### 3. Tiered Transport Priority

Requests route through the most trusted available path:

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
│   Priority 5: Public Internet (fallback)                                    │
│   ├── Latency: Variable                                                     │
│   ├── Trust: Minimal (requires full capability verification)                │
│   └── Zone: z:public only, heavy validation                                 │
│                                                                             │
│   RaptorQ symbols route via highest-priority available path                 │
│   Multiple paths = aggregate bandwidth (any symbols help!)                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4. Sovereign Secret Distribution

Secrets never exist complete on any single device:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SOVEREIGN SECRET DISTRIBUTION                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Secret (e.g., API key, private key, OAuth token)                          │
│       │                                                                     │
│       ▼                                                                     │
│   RaptorQ Encode with k=3, n=5                                              │
│   (Need any 3 symbols to reconstruct)                                       │
│       │                                                                     │
│       ├──► Symbol 1 → Laptop (memory only, never disk)                     │
│       ├──► Symbol 2 → Desktop (memory only)                                │
│       ├──► Symbol 3 → Server (memory only)                                 │
│       ├──► Symbol 4 → Phone (memory only)                                  │
│       └──► Symbol 5 → HSM/secure enclave (if available)                    │
│                                                                             │
│   Properties:                                                               │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  • No single device has complete secret                         │       │
│   │  • Any 3 devices can reconstruct                                │       │
│   │  • Laptop stolen? Only 1 symbol, useless alone                  │       │
│   │  • Device dies? 4 remaining symbols, still recoverable          │       │
│   │  • All in memory, never touches disk                            │       │
│   │  • Tailscale ensures only YOUR devices participate              │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│                                                                             │
│   Reconstruction (when needed):                                             │
│   1. Request symbols from k online devices via Tailscale                    │
│   2. Reconstruct secret in secure memory                                    │
│   3. Use secret for operation                                               │
│   4. Zero memory immediately after use                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5. Connector Placement Strategy

Different connectors run on optimal devices:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CONNECTOR PLACEMENT STRATEGY                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Server (always-on, tag:fcp-owner)                                         │
│   ├── Discord connector (needs persistent WebSocket)                        │
│   ├── GitHub connector (webhook receiver)                                   │
│   ├── Telegram connector (polling)                                          │
│   └── Hub primary instance                                                  │
│                                                                             │
│   Laptop (interactive, tag:fcp-owner)                                       │
│   ├── Gmail connector (browser OAuth flow)                                  │
│   ├── Browser connector (local browser CDP)                                 │
│   ├── VSCode connector (local editor)                                       │
│   └── Hub secondary instance                                                │
│                                                                             │
│   Desktop (powerful, tag:fcp-owner)                                         │
│   ├── Local AI connector (GPU inference)                                    │
│   ├── Files connector (local filesystem)                                    │
│   ├── Database connector (local PostgreSQL)                                 │
│   └── Hub secondary instance                                                │
│                                                                             │
│   Phone (mobile, tag:fcp-private)                                           │
│   ├── Location connector                                                    │
│   ├── Camera connector                                                      │
│   ├── Notification connector                                                │
│   └── Symbol storage (for k-of-n reconstruction)                            │
│                                                                             │
│   ALL connectors reachable from ANY device via Tailscale!                   │
│   Events flow as RaptorQ symbols across the mesh.                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### New Crate: `fcp-tailscale`

```
crates/fcp-tailscale/
├── Cargo.toml
└── src/
    ├── lib.rs              # Public API
    ├── client.rs           # Tailscale local API client
    ├── discovery.rs        # Peer discovery on tailnet
    ├── transport.rs        # Tailscale-aware transport
    ├── acl.rs              # Zone-to-ACL generation
    ├── funnel.rs           # Public ingress via Funnel
    └── integration.rs      # fcp-raptorq integration
```

### Tailscale Client

```rust
/// Tailscale local API client
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
            .map(|p| p.cur_addr.is_some())  // Has direct address
            .unwrap_or(false))
    }
}

pub struct TailscaleStatus {
    pub backend_state: String,      // "Running"
    pub self_node: TailscaleNode,
    pub peer: HashMap<String, TailscalePeer>,
    pub current_tailnet: Option<TailnetInfo>,
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

### Peer Discovery

```rust
/// FCP peer discovery over Tailscale
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
                        zone: self.zone_from_tags(&peer.tags),
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

    /// Probe a peer for FCP capabilities
    async fn probe_fcp(&self, ip: IpAddr) -> Result<PeerCapabilities> {
        let addr = SocketAddr::new(ip, self.fcp_port);
        let mut conn = TcpStream::connect(addr).await?;

        // Send FCP probe
        let probe = FcpProbe {
            protocol_version: "1.0".into(),
            request_capabilities: true,
        };

        send_frame(&mut conn, &probe).await?;
        let response: FcpProbeResponse = recv_frame(&mut conn).await?;

        Ok(response.capabilities)
    }

    /// Map Tailscale tags to FCP zone
    fn zone_from_tags(&self, tags: &[String]) -> Option<ZoneId> {
        for tag in tags {
            if let Some(zone) = tag.strip_prefix("tag:fcp-") {
                return Some(ZoneId(format!("z:{}", zone)));
            }
        }
        None
    }
}

pub struct FcpPeer {
    pub tailscale_id: String,
    pub hostname: String,
    pub ip: IpAddr,
    pub tags: Vec<String>,
    pub zone: Option<ZoneId>,
    pub capabilities: PeerCapabilities,
    pub direct: bool,
    pub latency_ms: Option<u32>,
}

pub struct PeerCapabilities {
    pub hub: bool,                      // Can act as hub
    pub connectors: Vec<ConnectorId>,   // Available connectors
    pub storage_mb: u64,                // Symbol storage capacity
    pub raptorq: bool,                  // Supports RaptorQ
    pub zones: Vec<ZoneId>,             // Zones this peer serves
}
```

### Symbol Routing Over Tailscale

```rust
/// Route RaptorQ symbols across Tailscale mesh
pub struct TailscaleSymbolRouter {
    client: TailscaleClient,
    peers: RwLock<HashMap<String, FcpPeer>>,
    local_store: SymbolStore,
    raptorq_config: RaptorQConfig,
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
        expected_size: usize,
    ) -> Result<Vec<u8>> {
        let mut decoder = RaptorQDecoder::new(expected_size);

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

    /// Check if peer can store symbols for a zone
    fn can_store_for_zone(&self, peer: &FcpPeer, zone: &ZoneId) -> bool {
        // Peer must be in same or higher trust zone
        peer.zone.as_ref()
            .map(|pz| self.zone_trust(pz) >= self.zone_trust(zone))
            .unwrap_or(false)
    }
}
```

### ACL Generation

```rust
/// Generate Tailscale ACLs from FCP zone configuration
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

        // Default deny (implicit in Tailscale)

        policy
    }

    fn zone_to_tag(&self, zone: &ZoneId) -> String {
        // z:owner -> tag:fcp-owner
        format!("tag:fcp-{}", zone.0.strip_prefix("z:").unwrap_or(&zone.0))
    }
}

#[derive(Serialize)]
pub struct TailscaleAclPolicy {
    #[serde(rename = "tagOwners")]
    pub tag_owners: HashMap<String, Vec<String>>,
    pub acls: Vec<AclRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<AclTest>,
}

#[derive(Serialize)]
pub struct AclRule {
    pub action: AclAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
}
```

### Funnel Gateway (Public Ingress)

```rust
/// Expose FCP services via Tailscale Funnel
pub struct FunnelGateway {
    client: TailscaleClient,
    zone_enforcer: ZoneEnforcer,
    hub: Arc<DistributedHub>,
}

impl FunnelGateway {
    /// Handle incoming Funnel request (from public internet)
    pub async fn handle(&self, req: hyper::Request<Body>) -> Result<hyper::Response<Body>> {
        // All Funnel traffic is z:public or z:community
        let zone = self.classify_request(&req)?;

        if !matches!(zone, ZoneId::Public | ZoneId::Community(_)) {
            return Ok(Response::builder()
                .status(403)
                .body("Zone not accessible via Funnel".into())?);
        }

        // Apply taint (Funnel origin = untrusted)
        let provenance = Provenance::highly_tainted(zone.clone());

        // Parse FCP request
        let fcp_req = self.parse_fcp_request(req, provenance).await?;

        // Forward to hub with zone restrictions
        let response = self.hub.handle_request(fcp_req).await?;

        Ok(self.to_http_response(response)?)
    }

    /// Classify incoming request to zone
    fn classify_request(&self, req: &hyper::Request<Body>) -> Result<ZoneId> {
        // Check authentication headers
        if let Some(api_key) = req.headers().get("X-FCP-API-Key") {
            // Authenticated community access
            if self.verify_community_key(api_key)? {
                return Ok(ZoneId::community());
            }
        }

        // Default to public
        Ok(ZoneId::public())
    }
}
```

---

## Integration: `fcp-mesh` Crate

Combines `fcp-tailscale` and `fcp-raptorq` into a unified mesh layer:

```rust
// crates/fcp-mesh/src/lib.rs

pub struct SovereignMesh {
    /// Tailscale client
    tailscale: TailscaleClient,

    /// Peer discovery
    discovery: TailscalePeerDiscovery,

    /// Symbol routing
    router: TailscaleSymbolRouter,

    /// Distributed hub
    hub: DistributedHub,

    /// Zone configuration
    zones: Vec<ZoneConfig>,
}

impl SovereignMesh {
    /// Initialize the sovereign mesh
    pub async fn init(config: MeshConfig) -> Result<Self> {
        // Connect to local Tailscale
        let tailscale = TailscaleClient::new(&config.tailscale_socket)?;

        // Verify Tailscale is running and authenticated
        let status = tailscale.status().await?;
        if status.backend_state != "Running" {
            return Err(Error::TailscaleNotRunning);
        }

        info!(
            tailnet = %status.current_tailnet.as_ref().map(|t| &t.name).unwrap_or(&"unknown".into()),
            hostname = %status.self_node.hostname,
            "Connected to Tailscale"
        );

        // Discover FCP peers
        let discovery = TailscalePeerDiscovery::new(tailscale.clone(), config.fcp_port);
        let peers = discovery.discover().await?;

        info!(peer_count = peers.len(), "Discovered FCP peers");

        // Initialize symbol router
        let router = TailscaleSymbolRouter::new(
            tailscale.clone(),
            peers,
            config.raptorq,
        );

        // Initialize distributed hub
        let hub = DistributedHub::new(router.clone(), config.hub).await?;

        // Generate and apply ACLs
        let acl_gen = AclGenerator::new(&config.zones);
        let acls = acl_gen.generate();

        info!("Sovereign mesh initialized");

        Ok(Self {
            tailscale,
            discovery,
            router,
            hub,
            zones: config.zones,
        })
    }

    /// Store data with automatic symbol distribution
    pub async fn store(&self, data: &[u8], zone: &ZoneId) -> Result<ObjectId> {
        let object_id = ObjectId::from_data(data);

        // Encode to RaptorQ symbols
        let encoder = RaptorQEncoder::new(&self.router.config);
        let symbols = encoder.encode(data)?;

        // Distribute across tailnet
        let distribution = self.router.distribute(object_id, symbols, zone).await?;

        debug!(
            object_id = %object_id,
            symbol_count = distribution.total_symbols(),
            peer_count = distribution.peer_count(),
            "Data stored across mesh"
        );

        Ok(object_id)
    }

    /// Retrieve data from symbols across mesh
    pub async fn retrieve(&self, object_id: ObjectId) -> Result<Vec<u8>> {
        self.router.reconstruct(object_id, usize::MAX).await
    }

    /// Get the distributed hub
    pub fn hub(&self) -> &DistributedHub {
        &self.hub
    }
}
```

---

## Usage Example

```rust
use fcp_mesh::{SovereignMesh, MeshConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize sovereign mesh
    let mesh = SovereignMesh::init(MeshConfig {
        tailscale_socket: "/var/run/tailscale/tailscaled.sock".into(),
        fcp_port: 9473,
        zones: vec![
            ZoneConfig::owner(),
            ZoneConfig::private(),
            ZoneConfig::work(),
        ],
        raptorq: RaptorQConfig::default(),
        hub: HubConfig::distributed(),
    }).await?;

    // Store sensitive data (distributed as symbols)
    let api_key = b"sk-secret-key-12345";
    let object_id = mesh.store(api_key, &ZoneId::owner()).await?;

    // Later, on any device in your tailnet...
    let recovered = mesh.retrieve(object_id).await?;
    assert_eq!(recovered, api_key);

    // Handle FCP requests via distributed hub
    let hub = mesh.hub();
    let response = hub.handle_request(request).await?;

    Ok(())
}
```

---

## Security Properties

### What You Get

| Property | How It's Achieved |
|----------|-------------------|
| **Authentication** | Tailscale identity (WireGuard keys) |
| **Encryption** | WireGuard (transport) + optional ChaCha20 (at rest) |
| **Zone isolation** | Tailscale ACLs + FCP capability system |
| **No SPOF** | RaptorQ symbols across multiple devices |
| **Secret protection** | k-of-n distribution, no complete secret on any device |
| **Audit** | Distributed audit log as RaptorQ symbols |
| **Offline resilience** | Any k-of-n online devices can operate |

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Device stolen | Only has partial symbols, useless alone |
| Network MITM | WireGuard encryption end-to-end |
| Cloud compromise | No cloud, all data on your devices |
| Single device hack | Compromised device can only access its zone |
| Tailscale compromise | Symbols still encrypted, need k-of-n devices |

---

## Implementation Phases

1. **Phase 1**: `fcp-tailscale` crate - Tailscale local API integration
2. **Phase 2**: Peer discovery and transport prioritization
3. **Phase 3**: Zone-to-ACL mapping with defense-in-depth enforcement
4. **Phase 4**: `fcp-mesh` integration with `fcp-raptorq` (symbol routing over tailnet)
5. **Phase 5**: Distributed hub implementation
6. **Phase 6**: Sovereign secret distribution with k-of-n recovery

See FCP Specification Section 9.2 (Transport Options) for Tailscale integration in the core protocol.

---

## Conclusion

The combination of **Tailscale** (trusted identity mesh) + **RaptorQ** (fungible data) + **FCP** (capability-controlled connectors) creates something unprecedented:

**True Digital Sovereignty**

- Your AI runs on YOUR devices
- Your data exists as fungible symbols across YOUR mesh
- Any subset of YOUR devices can reconstruct anything
- Network-level isolation enforced by Tailscale ACLs
- Application-level isolation enforced by FCP zones/capabilities
- ZERO cloud dependency
- ZERO single point of failure

This is the foundation for a **Personal AI Flywheel** that is truly yours - running on your hardware, encrypted by your keys, accessible only by your identity.

# RFC: Mesh-Native Protocol — FCP Reimagined for Tailscale + Universal Fungibility

## Abstract

This RFC proposes a fundamental reconceptualization of FCP based on two axiomatic assumptions:

1. **Universal Fungibility**: All data exists as RaptorQ-encoded symbols
2. **Trusted Mesh**: All nodes are connected via Tailscale in a mutually-authenticated, encrypted mesh

Together, these create something unprecedented: a **Sovereign Compute Fabric** where your devices form a single coherent system. There is no "Hub" in the traditional sense—the mesh IS the Hub. There are no "connectors on machines"—there are capabilities that execute wherever optimal. There is no "storage on devices"—there is symbol distribution across the fabric.

This document explores the full implications and proposes a mesh-native protocol design.

---

## Part 1: The Paradigm Shift

### What We're Actually Building

Traditional cloud architecture:
```
Your Devices ──── (Internet) ──── Cloud Services ──── (APIs) ──── External Services
                   untrusted         not yours           rate-limited
```

Mesh-native architecture:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       YOUR SOVEREIGN COMPUTE FABRIC                          │
│                                                                             │
│    Laptop ◄────────────► Desktop ◄────────────► Server ◄────────────► Phone │
│       │                     │                      │                    │    │
│       └─────────────────────┴──────────────────────┴────────────────────┘    │
│                                                                             │
│    All authenticated (Tailscale)     All encrypted (WireGuard)              │
│    All fungible (RaptorQ)            All sovereign (YOUR devices)           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                          External Services (connectors)
```

The mesh IS the system. Your devices ARE the cloud. Symbols flow everywhere.

### The Two Axioms

**Axiom 1: Universal Fungibility**
All data exists as RaptorQ symbols. Any K' symbols from anywhere can reconstruct. There is no "primary" or "replica"—just symbols.

**Axiom 2: Trusted Mesh**
All devices are connected via Tailscale. Every node is cryptographically authenticated. All traffic is encrypted. NAT is solved. Discovery is automatic.

### What This Enables

| Traditional Assumption | Mesh-Native Reality |
|------------------------|---------------------|
| Hub is a single process | Mesh IS the Hub |
| Connectors run on specific machines | Capabilities execute anywhere |
| State lives in databases | State IS symbol distribution |
| Connections can fail | Paths are fungible too |
| Offline means no access | Offline means reduced probability |
| Sync is explicit | Sync is just symbol flow |
| Security is perimeter-based | Security is cryptographic and distributed |
| Scaling requires more servers | Scaling is adding your own devices |

---

## Part 2: The Mesh as Compute Fabric

### 2.1 No Hub — The Mesh IS the Hub

Traditional FCP has a Hub that orchestrates connectors. In mesh-native FCP, there is no Hub—or rather, every device IS the Hub.

```rust
/// Every device runs a MeshNode
/// Together, they form the distributed Hub
pub struct MeshNode {
    // ═══════════════════════════════════════════════════════════════════
    // IDENTITY (from Tailscale)
    // ═══════════════════════════════════════════════════════════════════

    /// My Tailscale node identity
    pub identity: TailscaleIdentity,

    /// My current IP on the tailnet
    pub tailscale_ip: IpAddr,

    /// Tags from Tailscale ACLs (determine zone membership)
    pub tags: Vec<String>,

    // ═══════════════════════════════════════════════════════════════════
    // PEER AWARENESS
    // ═══════════════════════════════════════════════════════════════════

    /// Known peers (discovered via Tailscale)
    pub peers: HashMap<TailscaleNodeId, PeerInfo>,

    /// Gossip state (what peers have what)
    pub gossip: MeshGossip,

    // ═══════════════════════════════════════════════════════════════════
    // DISTRIBUTED STATE
    // ═══════════════════════════════════════════════════════════════════

    /// Mesh state as symbols (distributed across all nodes)
    pub mesh_state: DistributedSymbolStore,

    /// Local symbol cache
    pub local_symbols: SymbolStore,

    // ═══════════════════════════════════════════════════════════════════
    // LOCAL EXECUTION
    // ═══════════════════════════════════════════════════════════════════

    /// Local capability executor
    pub executor: CapabilityExecutor,

    /// Active computations on this node
    pub active_computations: HashMap<ComputationId, ActiveComputation>,
}
```

**Key insight**: Any MeshNode can handle any request. They're all equivalent because:
- All have access to the same symbols (via the mesh)
- All can reconstruct any state (from symbols)
- All can forward to better-suited nodes (via Tailscale)

### 2.2 Capabilities, Not Connectors

Traditional connectors are processes on machines. Mesh-native capabilities are **objects in symbol space** that can execute anywhere.

```rust
/// A capability is not a running process—it's an executable object
pub struct MeshCapability {
    // ═══════════════════════════════════════════════════════════════════
    // IDENTITY
    // ═══════════════════════════════════════════════════════════════════

    /// Capability definition
    pub capability_id: CapabilityId,

    /// Content-addressed (THE identity)
    pub object_id: ObjectId,

    // ═══════════════════════════════════════════════════════════════════
    // EXECUTABLE COMPONENTS (all as objects in symbol space)
    // ═══════════════════════════════════════════════════════════════════

    /// The binary (WASM or native)
    pub binary_object_id: ObjectId,

    /// Configuration
    pub config_object_id: ObjectId,

    /// Current state (distributed as symbols)
    pub state: DistributedState,

    // ═══════════════════════════════════════════════════════════════════
    // EXECUTION CONSTRAINTS
    // ═══════════════════════════════════════════════════════════════════

    /// Where can this execute?
    pub execution_hints: ExecutionHints,

    /// Zone requirements
    pub required_zones: Vec<ZoneId>,
}

/// Execution hints guide placement
pub struct ExecutionHints {
    /// Hardware requirements
    pub requires_gpu: bool,
    pub min_memory_gb: u32,
    pub min_cpu_cores: u32,

    /// Context requirements
    pub requires_browser: bool,
    pub requires_display: bool,
    pub requires_user_presence: bool,

    /// Network requirements
    pub requires_low_latency: bool,
    pub requires_high_bandwidth: bool,
    pub requires_direct_internet: bool,  // Not via exit node

    /// Power requirements
    pub prefer_plugged_in: bool,
    pub allow_battery: bool,

    /// Device preferences
    pub preferred_devices: Vec<TailscaleNodeId>,
    pub excluded_devices: Vec<TailscaleNodeId>,

    /// Affinity (prefer to run near certain data)
    pub data_affinity: Vec<ObjectId>,
}
```

When you invoke a capability:

```rust
impl MeshCapability {
    /// Invoke this capability on the optimal node
    pub async fn invoke(&self, request: InvokeObject) -> Result<ResponseObject> {
        // 1. Find viable hosts (have required hardware, zones, etc.)
        let viable = self.find_viable_hosts().await;

        // 2. Score and choose the best
        let host = self.choose_best_host(&viable, &request);

        // 3. Ensure host has the binary (as symbols)
        host.ensure_object(self.binary_object_id).await?;

        // 4. Ensure host has config
        host.ensure_object(self.config_object_id).await?;

        // 5. Ensure host can reconstruct state
        host.ensure_state(&self.state).await?;

        // 6. Execute (locally or remotely via Tailscale)
        if host.is_local() {
            self.execute_local(request).await
        } else {
            self.execute_remote(host, request).await
        }
    }

    fn choose_best_host(&self, viable: &[TailscaleNodeId], request: &InvokeObject) -> TailscaleNodeId {
        viable.iter()
            .map(|h| (h, self.score_host(h, request)))
            .max_by_key(|(_, score)| *score)
            .map(|(h, _)| h.clone())
            .expect("at least one viable host")
    }

    fn score_host(&self, host: &TailscaleNodeId, request: &InvokeObject) -> i64 {
        let mut score = 0i64;

        // Latency to requester (lower is better)
        score -= self.latency_to(host) as i64;

        // Symbol locality (do they have state symbols?)
        score += self.symbol_locality(host) * 100;

        // Resource availability
        score += self.available_resources(host) * 10;

        // Power state (plugged in is better for heavy work)
        if self.execution_hints.prefer_plugged_in && host.is_plugged_in() {
            score += 500;
        }

        // Data affinity (prefer hosts near related data)
        for affinity_object in &self.execution_hints.data_affinity {
            if host.has_symbols_for(affinity_object) {
                score += 200;
            }
        }

        score
    }
}
```

### 2.3 State IS the Mesh

There is no "database" or "storage" in the traditional sense. State IS the symbol distribution across your mesh.

```rust
/// State doesn't "live" anywhere—it IS the mesh
pub struct DistributedState {
    /// The state object
    pub object_id: ObjectId,

    /// Symbol distribution across mesh
    pub symbol_locations: HashMap<SymbolId, Vec<TailscaleNodeId>>,

    /// Reconstruction parameters
    pub k: u16,  // Symbols needed to reconstruct

    /// Current coverage
    pub fn coverage(&self) -> f64 {
        let unique_symbols = self.symbol_locations.len();
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
        // Collect symbols from across mesh
        let symbols = self.collect_symbols().await?;

        // Reconstruct
        reconstruct(symbols)
    }

    /// Update state (creates new object, distributes new symbols)
    pub async fn update(&mut self, new_data: &[u8]) -> Result<()> {
        // New state = new object
        let new_object_id = ObjectId::from_bytes(new_data);

        // Encode as symbols
        let symbols = encode(new_data);

        // Distribute across mesh
        self.distribute_symbols(symbols).await?;

        // Update reference
        self.object_id = new_object_id;

        Ok(())
    }
}
```

**Key insight**: When you "write" data, you're encoding symbols and distributing them. When you "read" data, you're collecting symbols and reconstructing. There's no "sync"—it's just symbol flow.

### 2.4 The Gossip Layer

Nodes gossip about what they have and what they can do:

```rust
/// Mesh-wide gossip for discovery and coordination
pub struct MeshGossip {
    // ═══════════════════════════════════════════════════════════════════
    // WHAT I HAVE
    // ═══════════════════════════════════════════════════════════════════

    /// Objects I have symbols for (bloom filter for efficiency)
    pub objects_known: BloomFilter<ObjectId>,

    /// Symbols I hold locally
    pub symbols_held: BloomFilter<SymbolId>,

    // ═══════════════════════════════════════════════════════════════════
    // WHAT I CAN DO
    // ═══════════════════════════════════════════════════════════════════

    /// Capabilities I can execute
    pub capabilities: Vec<CapabilityId>,

    /// My hardware profile
    pub hardware: HardwareProfile,

    /// Current resource availability
    pub availability: ResourceAvailability,

    // ═══════════════════════════════════════════════════════════════════
    // MESH STATE
    // ═══════════════════════════════════════════════════════════════════

    /// Peer gossip states (what I know about others)
    pub peer_states: HashMap<TailscaleNodeId, PeerGossipState>,

    /// My clock (for consistency)
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

### 2.5 Request Routing

Requests don't go to specific endpoints—they go to the mesh:

```rust
/// Route a request through the mesh
pub async fn route_request(
    mesh: &MeshNode,
    request: InvokeObject,
) -> Result<ResponseObject> {
    // 1. What capability is being invoked?
    let capability_id = request.capability_object_id;

    // 2. Reconstruct the capability definition
    let capability = mesh.reconstruct_capability(capability_id).await?;

    // 3. Who can execute this?
    let executors = mesh.gossip.who_can_execute(capability.capability_id);

    if executors.is_empty() {
        // No one can execute—might need to "spawn" the capability
        return mesh.spawn_and_execute(capability, request).await;
    }

    // 4. Choose best executor
    let best = capability.choose_best_host(&executors, &request);

    // 5. Execute (locally or forward via Tailscale)
    if best == mesh.identity.node_id {
        mesh.execute_local(capability, request).await
    } else {
        mesh.forward_to_peer(best, request).await
    }
}

impl MeshNode {
    /// "Spawn" a capability that isn't running anywhere
    async fn spawn_and_execute(
        &self,
        capability: MeshCapability,
        request: InvokeObject,
    ) -> Result<ResponseObject> {
        // Find best host for this capability
        let host = capability.choose_spawn_host(&self.peers);

        // Ensure host has the binary
        host.ensure_object(capability.binary_object_id).await?;

        // Host now knows it can execute this capability
        host.register_capability(capability.capability_id).await;

        // Execute
        host.execute(capability, request).await
    }
}
```

---

## Part 3: Identity and Security

### 3.1 Identity IS Tailscale Identity

There is no separate FCP identity. Your Tailscale node key IS your identity:

```rust
/// Identity is Tailscale identity
pub struct MeshIdentity {
    /// Tailscale node ID (derived from WireGuard key)
    pub node_id: TailscaleNodeId,

    /// Tailscale node key (WireGuard public key)
    pub node_key: WireGuardPublicKey,

    /// Tailscale user (who owns this node)
    pub user: TailscaleUser,

    /// Tags from Tailscale ACLs
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
            .filter_map(|tag| {
                if let Some(zone) = tag.strip_prefix("tag:fcp-") {
                    Some(ZoneId(format!("z:{}", zone)))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Trust level is derived from tags
    pub fn trust_level(&self) -> TrustLevel {
        if self.tags.contains(&"tag:fcp-owner".to_string()) {
            TrustLevel::Owner
        } else if self.tags.contains(&"tag:fcp-private".to_string()) {
            TrustLevel::Private
        } else if self.tags.contains(&"tag:fcp-work".to_string()) {
            TrustLevel::Work
        } else {
            TrustLevel::Community
        }
    }
}
```

### 3.2 Zones ARE Tailscale Tags

Zone membership is enforced by Tailscale ACLs at the network level:

```rust
/// Zone mapping to Tailscale
pub struct ZoneMapping {
    pub zone_id: ZoneId,
    pub tailscale_tag: String,
    pub trust_level: TrustLevel,
}

/// Standard zone mappings
pub const ZONE_MAPPINGS: &[ZoneMapping] = &[
    ZoneMapping {
        zone_id: ZoneId("z:owner"),
        tailscale_tag: "tag:fcp-owner",
        trust_level: TrustLevel::Owner,
    },
    ZoneMapping {
        zone_id: ZoneId("z:private"),
        tailscale_tag: "tag:fcp-private",
        trust_level: TrustLevel::Private,
    },
    ZoneMapping {
        zone_id: ZoneId("z:work"),
        tailscale_tag: "tag:fcp-work",
        trust_level: TrustLevel::Work,
    },
    ZoneMapping {
        zone_id: ZoneId("z:community"),
        tailscale_tag: "tag:fcp-community",
        trust_level: TrustLevel::Community,
    },
];
```

**Tailscale ACL enforcement:**

```json
{
  "acls": [
    // Owner zone: full mesh access
    {
      "action": "accept",
      "src": ["tag:fcp-owner"],
      "dst": ["tag:fcp-owner:*", "tag:fcp-private:*", "tag:fcp-work:*"]
    },

    // Private zone: can reach work, not owner
    {
      "action": "accept",
      "src": ["tag:fcp-private"],
      "dst": ["tag:fcp-private:*", "tag:fcp-work:*"]
    },

    // Work zone: isolated
    {
      "action": "accept",
      "src": ["tag:fcp-work"],
      "dst": ["tag:fcp-work:*"]
    },

    // Community: via Funnel only
    {
      "action": "accept",
      "src": ["autogroup:internet"],
      "dst": ["tag:fcp-community:443"]
    }
  ]
}
```

**Key insight**: Zone isolation is enforced at the NETWORK LEVEL. A compromised work device literally cannot send packets to owner devices. This is defense-in-depth on top of FCP's application-level enforcement.

### 3.3 Symbol Encryption by Zone

Each zone has a derived key. Symbols are encrypted with zone key:

```rust
/// Zone key derivation
pub struct ZoneKey {
    pub zone_id: ZoneId,

    /// Derived from: zone hierarchy + your Tailscale identity + time
    pub key: ChaCha20Poly1305Key,

    /// Key rotation epoch
    pub epoch: u64,
}

impl ZoneKey {
    /// Derive zone key
    pub fn derive(
        zone_id: &ZoneId,
        tailscale_identity: &MeshIdentity,
        epoch: u64,
    ) -> Self {
        let ikm = concat!(
            zone_id.as_bytes(),
            tailscale_identity.node_key.as_bytes(),
            &epoch.to_le_bytes(),
        );

        let key = hkdf_derive::<ChaCha20Poly1305Key>(
            ikm,
            b"fcp-zone-key-v1",
        );

        Self { zone_id: zone_id.clone(), key, epoch }
    }

    /// Encrypt symbol data
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
        self.key.encrypt(nonce, plaintext)
    }

    /// Decrypt symbol data
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        self.key.decrypt(nonce, ciphertext)
    }
}
```

**Key insight**: A device not in a zone cannot decrypt its symbols even if it receives them. Cryptographic isolation is absolute.

### 3.4 Source Diversity as Distributed Trust

Critical objects require symbols from multiple sources:

```rust
/// Require source diversity for reconstruction
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

**Key insight**: Requiring symbols from multiple nodes means no single compromised node can forge data. This is distributed trust enforced by reconstruction semantics.

### 3.5 Threshold Secrets

Secrets are distributed as k-of-n symbol sets across your mesh:

```rust
/// Secret that never exists complete on any device
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

    async fn collect_k_symbols(&self) -> Result<Vec<SymbolEnvelope>> {
        let mut symbols = Vec::new();

        for (device, symbol_id) in &self.distribution {
            if symbols.len() >= self.k as usize {
                break;
            }

            if device.is_online().await {
                if let Ok(symbol) = device.fetch_secret_symbol(symbol_id).await {
                    symbols.push(symbol);
                }
            }
        }

        if symbols.len() < self.k as usize {
            return Err(Error::InsufficientOnlineDevices {
                required: self.k,
                available: symbols.len() as u8,
            });
        }

        Ok(symbols)
    }
}
```

**Key insight**: Your API keys, OAuth tokens, private keys—NONE of them exist complete on any device. A stolen laptop is useless. You need k devices to reconstruct.

### 3.6 Authority Flow and Capability Signing

There is no hub, but there IS authority. The authority model is hierarchical:

```
Owner Root Key
      │
      ├──► Zone Policy Objects (signed by Owner)
      │
      ├──► Admin Keys (delegated by Owner)
      │         │
      │         └──► Capability Objects (signed by Admin or Owner)
      │
      └──► Device Keys (Tailscale identity, approved by Owner)
```

#### 3.6.1 Owner Root Key

```rust
/// Owner root key (NORMATIVE)
/// This is the ultimate authority. MUST be protected.
pub struct OwnerRootKey {
    /// Ed25519 signing key
    keypair: Ed25519Keypair,

    /// Key ID (hash of public key)
    pub key_id: KeyId,

    /// Creation timestamp
    pub created_at: u64,
}

impl OwnerRootKey {
    /// Sign a policy object
    pub fn sign_policy(&self, policy: &PolicyObject) -> SignedPolicy {
        let canonical = CanonicalSerializer::serialize(policy, &schemas::POLICY_OBJECT);
        let signature = self.keypair.sign(&canonical);

        SignedPolicy {
            policy: policy.clone(),
            signature,
            signer: self.key_id,
        }
    }

    /// Delegate to admin key
    pub fn delegate_admin(
        &self,
        admin_pubkey: &Ed25519PublicKey,
        scope: AdminScope,
    ) -> SignedDelegation {
        let delegation = AdminDelegation {
            admin_key: admin_pubkey.clone(),
            scope,
            delegated_at: now(),
            expires_at: now() + Duration::days(90),
            delegated_by: self.key_id,
        };

        let canonical = CanonicalSerializer::serialize(&delegation, &schemas::ADMIN_DELEGATION);
        let signature = self.keypair.sign(&canonical);

        SignedDelegation { delegation, signature }
    }
}
```

#### 3.6.2 Capability Signing

**Invariant:** Every CapabilityObject MUST be signed by Owner or delegated Admin.

```rust
/// Signed capability (NORMATIVE)
pub struct SignedCapability {
    /// The capability definition
    pub capability: CapabilityObject,

    /// Signature (Ed25519)
    pub signature: Signature,

    /// Who signed (Owner key ID or Admin key ID)
    pub signer: KeyId,

    /// If signed by Admin, include delegation chain
    pub delegation_chain: Option<Vec<SignedDelegation>>,
}

impl SignedCapability {
    /// Verify capability authenticity
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), VerificationError> {
        // 1. Check expiry
        if self.capability.expires_at < now() {
            return Err(VerificationError::Expired);
        }

        // 2. Get signer's public key
        let signer_key = if self.signer == trust_anchors.owner_key_id {
            // Signed by owner
            trust_anchors.owner_public_key.clone()
        } else if let Some(chain) = &self.delegation_chain {
            // Signed by admin—verify delegation chain
            self.verify_delegation_chain(chain, trust_anchors)?
        } else {
            return Err(VerificationError::UnknownSigner);
        };

        // 3. Verify signature
        let canonical = CanonicalSerializer::serialize(
            &self.capability,
            &schemas::CAPABILITY_OBJECT,
        );

        if !signer_key.verify(&canonical, &self.signature) {
            return Err(VerificationError::InvalidSignature);
        }

        Ok(())
    }
}
```

#### 3.6.3 Trust Anchors Distribution

```rust
/// Trust anchors (distributed to all devices)
pub struct TrustAnchors {
    /// Owner's public key
    pub owner_public_key: Ed25519PublicKey,

    /// Owner key ID
    pub owner_key_id: KeyId,

    /// Current admin delegations (signed by owner)
    pub admin_delegations: Vec<SignedDelegation>,

    /// Current zone policies (signed by owner)
    pub zone_policies: Vec<SignedPolicy>,

    /// Revoked keys/capabilities (signed by owner)
    pub revocations: Vec<SignedRevocation>,

    /// Last update epoch
    pub epoch: EpochId,
}
```

### 3.7 Principal vs Device Identity

**Key insight:** Tailscale authenticates DEVICES. FCP still needs PRINCIPAL identity (user, agent, service).

```rust
/// Principal identity (NORMATIVE)
pub struct PrincipalId(pub String);  // e.g., "user:alice@example.com"

/// Device identity (from Tailscale)
pub struct DeviceId(pub TailscaleNodeId);

/// Principal-Device binding
pub struct PrincipalDeviceBinding {
    /// The principal
    pub principal: PrincipalId,

    /// Devices this principal can use
    pub devices: Vec<DeviceId>,

    /// Binding constraints
    pub constraints: BindingConstraints,

    /// Signed by authority
    pub signature: Signature,
    pub signer: KeyId,
}

pub struct BindingConstraints {
    /// Valid time range
    pub valid_from: u64,
    pub valid_until: u64,

    /// Zone restrictions
    pub allowed_zones: Vec<ZoneId>,

    /// Capability restrictions
    pub allowed_capabilities: Option<Vec<CapabilityId>>,
}
```

#### 3.7.1 Request Attribution

Every request has both device AND principal:

```rust
/// Request context (NORMATIVE)
pub struct RequestContext {
    /// Which device made the request
    pub device: DeviceId,

    /// Which principal is acting
    pub principal: PrincipalId,

    /// Principal-device binding proof
    pub binding_proof: PrincipalDeviceBinding,

    /// Capability token
    pub capability_token: SignedCapability,

    /// Zone context
    pub zone: ZoneId,
}

impl RequestContext {
    /// Verify request authorization
    pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<()> {
        // 1. Verify principal-device binding
        self.binding_proof.verify(trust_anchors)?;

        // 2. Check device is in binding
        if !self.binding_proof.devices.contains(&self.device) {
            return Err(Error::DeviceNotBound);
        }

        // 3. Verify capability
        self.capability_token.verify(trust_anchors)?;

        // 4. Check capability grants operation to principal
        if !self.capability_token.capability.allows(&self.principal) {
            return Err(Error::PrincipalNotAuthorized);
        }

        // 5. Check zone policy
        if !self.binding_proof.constraints.allowed_zones.contains(&self.zone) {
            return Err(Error::ZoneNotAllowed);
        }

        Ok(())
    }
}
```

### 3.8 Source Identity and Symbol Signing

Every symbol MUST be signed by its source:

```rust
/// Source identity (NORMATIVE)
pub struct SourceId {
    /// Tailscale node ID (stable identity)
    pub tailscale_node_id: TailscaleNodeId,

    /// Ephemeral signing key (rotated frequently)
    pub ephemeral_key: Ed25519PublicKey,

    /// Ephemeral key attestation (signed by Tailscale node key)
    pub attestation: EphemeralKeyAttestation,
}

pub struct EphemeralKeyAttestation {
    /// The ephemeral public key
    pub ephemeral_key: Ed25519PublicKey,

    /// When this key becomes valid
    pub valid_from: u64,

    /// When this key expires
    pub valid_until: u64,

    /// Signed by the device's long-term key
    pub signature: Signature,
}

impl SourceId {
    /// Verify source identity
    pub fn verify(&self, tailscale_public_key: &WireGuardPublicKey) -> Result<()> {
        // 1. Verify ephemeral key is attested by Tailscale identity
        let attestation_bytes = canonical_serialize(&self.attestation);

        if !verify_tailscale_signature(
            tailscale_public_key,
            &attestation_bytes,
            &self.attestation.signature,
        ) {
            return Err(Error::InvalidAttestation);
        }

        // 2. Check ephemeral key validity window
        let now = current_time();
        if now < self.attestation.valid_from || now > self.attestation.valid_until {
            return Err(Error::EphemeralKeyExpired);
        }

        Ok(())
    }
}

/// Signed symbol envelope (NORMATIVE)
pub struct SignedSymbolEnvelope {
    /// The symbol
    pub symbol: SymbolEnvelope,

    /// Source identity
    pub source: SourceId,

    /// Signature over (symbol || source)
    pub signature: Signature,
}

impl SignedSymbolEnvelope {
    /// Create signed symbol
    pub fn sign(symbol: SymbolEnvelope, source: &SourceId, key: &Ed25519Keypair) -> Self {
        let to_sign = concat!(
            canonical_serialize(&symbol),
            canonical_serialize(source),
        );

        let signature = key.sign(&to_sign);

        Self { symbol, source: source.clone(), signature }
    }

    /// Verify symbol authenticity
    pub fn verify(&self) -> Result<()> {
        // 1. Verify source identity
        self.source.verify(&get_tailscale_key(&self.source.tailscale_node_id)?)?;

        // 2. Verify symbol signature
        let to_verify = concat!(
            canonical_serialize(&self.symbol),
            canonical_serialize(&self.source),
        );

        if !self.source.ephemeral_key.verify(&to_verify, &self.signature) {
            return Err(Error::InvalidSymbolSignature);
        }

        Ok(())
    }
}
```

---

## Part 4: Computation and Execution

### 4.1 Computation Follows the User

Your "system" is wherever you are. Computation follows you:

```rust
/// Computation migration across mesh
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
}

impl MigratableComputation {
    /// Migrate to a different host
    pub async fn migrate(&mut self, new_host: TailscaleNodeId) -> Result<()> {
        // 1. Checkpoint current state
        let checkpoint = self.checkpoint().await?;

        // 2. Encode as symbols and send to new host
        let symbols = encode(&checkpoint);
        new_host.receive_symbols(symbols).await?;

        // 3. Resume on new host
        new_host.resume_computation(self.computation_id, checkpoint).await?;

        // 4. Stop local execution
        self.stop_local();

        // 5. Update current host
        self.current_host = new_host;

        Ok(())
    }

    /// Proactive migration when better host available
    pub async fn consider_migration(&mut self, mesh: &MeshNode) -> Result<()> {
        let current_score = self.score_host(&self.current_host);

        // Find better hosts
        for (peer, info) in &mesh.peers {
            let peer_score = self.score_host(peer);

            // Migrate if significantly better (with hysteresis)
            if peer_score > current_score * 1.5 {
                info!("Migrating computation {} to {}", self.computation_id, peer);
                return self.migrate(peer.clone()).await;
            }
        }

        Ok(())
    }
}
```

**Use case**: You're running a long computation on your laptop. You need to leave. The computation migrates to your desktop and continues. When you get home, results are waiting.

### 4.2 Device-Aware Execution

Different devices are suited for different tasks:

```rust
/// Device profiles for execution planning
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

    /// Network
    pub connection_type: ConnectionType,  // Direct, DERP, etc.
    pub latency_ms: HashMap<TailscaleNodeId, u32>,
}

impl DeviceProfile {
    /// Can this device execute a capability with given hints?
    pub fn can_execute(&self, hints: &ExecutionHints) -> bool {
        // Check GPU requirement
        if hints.requires_gpu && self.gpu.is_none() {
            return false;
        }

        // Check memory requirement
        if self.memory_gb < hints.min_memory_gb {
            return false;
        }

        // Check display requirement
        if hints.requires_display && !self.has_display {
            return false;
        }

        // Check browser requirement
        if hints.requires_browser && !self.has_browser {
            return false;
        }

        // Check power requirement
        if !hints.allow_battery && self.power_source == PowerSource::Battery {
            return false;
        }

        true
    }
}

/// Execution planner chooses optimal device
pub struct ExecutionPlanner {
    pub mesh: Arc<MeshNode>,
}

impl ExecutionPlanner {
    /// Choose best device for a capability invocation
    pub fn choose(&self, capability: &MeshCapability, request: &InvokeObject) -> TailscaleNodeId {
        let viable: Vec<_> = self.mesh.peers.keys()
            .filter(|p| self.can_execute(p, &capability.execution_hints))
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

        // Lower latency is better
        let latency = profile.latency_ms.get(&self.mesh.identity.node_id).copied().unwrap_or(1000);
        score -= latency as i64;

        // Lower load is better
        score -= (profile.current_load * 1000.0) as i64;

        // Plugged in is better for heavy work
        if profile.power_source == PowerSource::PluggedIn {
            score += 500;
        }

        // GPU bonus if capability uses GPU
        if capability.execution_hints.requires_gpu && profile.gpu.is_some() {
            score += 1000;
        }

        // Data locality bonus
        for object_id in &capability.execution_hints.data_affinity {
            if self.mesh.gossip.node_has_symbols(node, object_id) {
                score += 300;
            }
        }

        // User presence bonus if required
        if capability.execution_hints.requires_user_presence && profile.user_active {
            score += 500;
        }

        score
    }
}
```

**Examples:**
- **Gmail OAuth**: Run on device with browser and user presence
- **Heavy ML inference**: Run on desktop with GPU, plugged in
- **Quick lookup**: Run on nearest device with lowest latency
- **Background sync**: Run on always-on server
- **Sensitive operation**: Run on device with secure enclave

### 4.3 Parallel Execution Across Mesh

For large operations, parallelize across multiple devices:

```rust
/// Parallel execution across mesh devices
pub struct ParallelExecution {
    /// The overall operation
    pub operation_id: ObjectId,

    /// Partitions (each executed on different device)
    pub partitions: Vec<ExecutionPartition>,

    /// How to combine results
    pub combiner: Combiner,
}

pub struct ExecutionPartition {
    /// Partition identity
    pub partition_id: u32,

    /// Input data (as symbols)
    pub input_object_id: ObjectId,

    /// Which device executes this
    pub executor: TailscaleNodeId,

    /// Output (when complete)
    pub output_object_id: Option<ObjectId>,
}

impl ParallelExecution {
    /// Execute partitions in parallel across mesh
    pub async fn execute(&mut self) -> Result<ObjectId> {
        // Launch all partitions in parallel
        let futures: Vec<_> = self.partitions.iter()
            .map(|p| self.execute_partition(p))
            .collect();

        // Wait for all to complete
        let results = futures::future::join_all(futures).await;

        // Combine results
        let combined = self.combiner.combine(&results)?;

        // Store result as symbols
        let result_object_id = ObjectId::from_bytes(&combined);
        distribute_symbols(&combined).await?;

        Ok(result_object_id)
    }

    async fn execute_partition(&self, partition: &ExecutionPartition) -> Result<Vec<u8>> {
        // Ensure executor has input symbols
        partition.executor.ensure_object(partition.input_object_id).await?;

        // Execute
        let output = partition.executor.execute_partition(
            self.operation_id,
            partition.partition_id,
        ).await?;

        Ok(output)
    }
}
```

**Use case**: Processing a large dataset. Split across your laptop, desktop, and server. Each processes their partition. Results combine automatically.

---

## Part 5: Presence and Lifecycle

### 5.1 Device Presence

The mesh is aware of which devices are online:

```rust
/// Mesh presence tracking
pub struct MeshPresence {
    /// Online devices (from Tailscale status)
    pub online: HashSet<TailscaleNodeId>,

    /// Device health
    pub health: HashMap<TailscaleNodeId, DeviceHealth>,

    /// Last seen timestamps
    pub last_seen: HashMap<TailscaleNodeId, Instant>,
}

impl MeshPresence {
    /// Update from Tailscale status
    pub async fn update(&mut self) -> Result<()> {
        let status = tailscale::status().await?;

        let new_online: HashSet<_> = status.peers.iter()
            .filter(|p| p.online)
            .map(|p| p.node_id.clone())
            .collect();

        // Detect changes
        let came_online: Vec<_> = new_online.difference(&self.online).cloned().collect();
        let went_offline: Vec<_> = self.online.difference(&new_online).cloned().collect();

        // Handle changes
        for node in came_online {
            self.on_device_online(node).await?;
        }

        for node in went_offline {
            self.on_device_offline(node).await?;
        }

        self.online = new_online;
        Ok(())
    }

    async fn on_device_online(&self, node: TailscaleNodeId) -> Result<()> {
        info!("Device came online: {}", node);

        // 1. Exchange gossip state
        exchange_gossip(&node).await?;

        // 2. Rebalance symbols to include new device
        rebalance_symbols(&node).await?;

        // 3. Consider migrating computations to this device
        consider_migrations(&node).await?;

        // 4. Speculatively pre-fetch symbols this device might need
        speculative_prefetch(&node).await?;

        Ok(())
    }

    async fn on_device_offline(&self, node: TailscaleNodeId) -> Result<()> {
        info!("Device went offline: {}", node);

        // 1. Check symbol coverage
        let coverage = check_coverage_without(&node).await;

        if coverage < COVERAGE_THRESHOLD {
            // 2. Emergency redistribution
            warn!("Coverage dropped to {:.1}%, redistributing", coverage * 100.0);
            emergency_redistribution(&node).await?;
        }

        // 3. Migrate any computations that were running there
        migrate_computations_from(&node).await?;

        Ok(())
    }
}
```

### 5.2 Mesh Bootstrap

When the first device comes online:

```rust
/// Bootstrap the mesh from cold start
pub async fn bootstrap_mesh(my_identity: MeshIdentity) -> Result<MeshNode> {
    info!("Bootstrapping mesh node: {}", my_identity.hostname);

    // 1. Connect to Tailscale
    let tailscale = TailscaleClient::connect().await?;

    // 2. Discover peers
    let status = tailscale.status().await?;
    let peers: Vec<_> = status.peers.iter()
        .filter(|p| p.online)
        .cloned()
        .collect();

    info!("Found {} online peers", peers.len());

    if peers.is_empty() {
        // I'm the first device—initialize empty mesh state
        return MeshNode::new_primary(my_identity);
    }

    // 3. Join existing mesh
    // Find peer with most symbols (most complete state)
    let best_peer = peers.iter()
        .max_by_key(|p| p.symbol_count_estimate)
        .unwrap();

    // 4. Fetch current mesh state as symbols
    let state_symbols = best_peer.fetch_mesh_state_symbols().await?;

    // 5. Also fetch from other peers (for diversity)
    let additional_symbols = fetch_symbols_from_peers(&peers, state_symbols.object_id).await?;

    // 6. Reconstruct mesh state
    let all_symbols = [state_symbols.symbols, additional_symbols].concat();
    let mesh_state = reconstruct(all_symbols)?;

    // 7. Create mesh node
    let mut node = MeshNode::new_joining(my_identity, mesh_state);

    // 8. Announce ourselves via gossip
    node.announce_to_mesh().await?;

    // 9. Receive symbol redistribution (other nodes will send us symbols)
    node.receive_redistributed_symbols().await?;

    info!("Successfully joined mesh with {} peers", peers.len());

    Ok(node)
}
```

### 5.3 Graceful Shutdown

When a device is intentionally shutting down:

```rust
/// Graceful shutdown of a mesh node
pub async fn shutdown_gracefully(node: &mut MeshNode) -> Result<()> {
    info!("Initiating graceful shutdown");

    // 1. Stop accepting new work
    node.stop_accepting_requests();

    // 2. Migrate active computations
    for computation in node.active_computations.values() {
        let new_host = find_migration_target(computation).await?;
        computation.migrate(new_host).await?;
    }

    // 3. Announce departure (peers will rebalance symbols)
    node.announce_departure().await?;

    // 4. Wait for symbol redistribution to complete
    let mut retries = 0;
    while node.has_unique_symbols() && retries < MAX_RETRIES {
        info!("Waiting for symbol redistribution...");
        tokio::time::sleep(Duration::from_secs(1)).await;
        retries += 1;
    }

    if node.has_unique_symbols() {
        warn!("Still have unique symbols after shutdown timeout—data may be at risk");
    }

    // 5. Final gossip to confirm departure
    node.gossip.final_goodbye().await?;

    info!("Graceful shutdown complete");
    Ok(())
}
```

---

## Part 6: Storage and Sync

### 6.1 There Is No Sync

Traditional systems "sync" files between devices. In mesh-native FCP, there is no sync—only symbol flow.

```rust
/// "Storage" is just symbol distribution
pub struct MeshStorage {
    /// Objects we care about
    pub objects: HashMap<ObjectId, ObjectMetadata>,

    /// Local symbol cache
    pub local_cache: SymbolStore,

    /// Symbol distribution across mesh
    pub distribution: SymbolDistribution,
}

impl MeshStorage {
    /// "Read" a file = reconstruct from symbols
    pub async fn read(&self, object_id: ObjectId) -> Result<Vec<u8>> {
        // 1. Check local cache first
        if let Some(data) = self.try_reconstruct_local(object_id) {
            return Ok(data);
        }

        // 2. Collect symbols from mesh
        let symbols = self.collect_symbols(object_id).await?;

        // 3. Reconstruct
        let data = reconstruct(symbols)?;

        // 4. Cache locally for next time
        self.cache_locally(object_id, &data);

        Ok(data)
    }

    /// "Write" a file = encode and distribute symbols
    pub async fn write(&self, data: &[u8]) -> Result<ObjectId> {
        let object_id = ObjectId::from_bytes(data);

        // 1. Encode as symbols
        let symbols = encode(data);

        // 2. Distribute across mesh
        self.distribute_symbols(object_id, symbols).await?;

        // 3. Also cache locally
        self.cache_locally(object_id, data);

        Ok(object_id)
    }

    /// "Delete" = remove symbols (reduces availability)
    pub async fn delete(&self, object_id: ObjectId) -> Result<()> {
        // Request all nodes to delete their symbols
        self.distribution.request_deletion(object_id).await?;

        // Remove from local cache
        self.local_cache.remove(object_id);

        Ok(())
    }
}
```

### 6.2 Offline Access

Offline doesn't mean no access—it means reduced probability:

```rust
/// Offline capability tracking
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

    /// Can I reconstruct?
    pub fn can_access(&self) -> bool {
        self.local_symbols >= self.k
    }

    /// How close am I?
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

### 6.3 Predictive Pre-staging

Based on user patterns, pre-stage symbols:

```rust
/// Predictive symbol pre-staging
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

**Use case**: You check email every morning at 9am on your phone. At 8:50am, email symbols are pre-staged to your phone. By 9am, everything loads instantly even on a slow connection.

---

## Part 7: Audit and Observability

### 7.1 Distributed Audit

Audit is not a log file—it's a symbol chain across the mesh:

```rust
/// Distributed audit across mesh
pub struct MeshAudit {
    /// Audit epochs (each is an object)
    pub epochs: Vec<AuditEpochRef>,

    /// Symbol distribution for audit data
    pub distribution: SymbolDistribution,

    /// Required source diversity for audit verification
    pub diversity: DiversityPolicy,
}

pub struct AuditEpochRef {
    pub epoch_id: EpochId,
    pub object_id: ObjectId,
    pub previous_object_id: ObjectId,  // Chain link
    pub merkle_root: [u8; 32],
}

impl MeshAudit {
    /// Write an audit entry
    pub async fn write(&mut self, entry: AuditEntry) -> Result<()> {
        // Entry goes into current epoch
        self.current_epoch.add(entry);

        // If epoch is complete, finalize and distribute
        if self.current_epoch.should_finalize() {
            self.finalize_current_epoch().await?;
        }

        Ok(())
    }

    async fn finalize_current_epoch(&mut self) -> Result<()> {
        let epoch = std::mem::take(&mut self.current_epoch);

        // Compute merkle root
        let merkle_root = epoch.compute_merkle_root();

        // Serialize and encode as symbols
        let data = serialize(&epoch);
        let object_id = ObjectId::from_bytes(&data);
        let symbols = encode(&data);

        // Distribute symbols across mesh (with high redundancy for audit data)
        self.distribution.distribute_with_redundancy(symbols, 3.0).await?;

        // Record epoch reference
        self.epochs.push(AuditEpochRef {
            epoch_id: epoch.id,
            object_id,
            previous_object_id: self.epochs.last().map(|e| e.object_id).unwrap_or(GENESIS),
            merkle_root,
        });

        Ok(())
    }

    /// Verify audit chain integrity
    pub async fn verify(&self) -> Result<VerificationResult> {
        let mut prev_id = GENESIS;

        for epoch_ref in &self.epochs {
            // 1. Collect symbols from diverse sources
            let symbols = self.collect_diverse_symbols(epoch_ref.object_id).await?;

            // 2. Verify source diversity
            self.diversity.verify(&symbols)?;

            // 3. Reconstruct epoch
            let epoch: AuditEpoch = reconstruct(symbols)?;

            // 4. Verify chain link
            if epoch.previous_object_id != prev_id {
                return Ok(VerificationResult::ChainBroken {
                    epoch_id: epoch_ref.epoch_id,
                    expected: prev_id,
                    actual: epoch.previous_object_id,
                });
            }

            // 5. Verify merkle root
            if epoch.compute_merkle_root() != epoch_ref.merkle_root {
                return Ok(VerificationResult::MerkleViolation {
                    epoch_id: epoch_ref.epoch_id,
                });
            }

            prev_id = epoch_ref.object_id;
        }

        Ok(VerificationResult::Valid)
    }
}
```

**Key insight**: Audit data requires symbols from multiple sources to reconstruct. No single device can tamper with history without detection.

### 7.2 Mesh Observability

Aggregate health and metrics across the mesh:

```rust
/// Mesh-wide observability
pub struct MeshObservability {
    /// Per-device metrics
    pub device_metrics: HashMap<TailscaleNodeId, DeviceMetrics>,

    /// Mesh-level metrics
    pub mesh_metrics: MeshMetrics,
}

pub struct MeshMetrics {
    /// How many devices are online?
    pub online_devices: usize,

    /// What's our symbol coverage?
    pub symbol_coverage: f64,

    /// Reconstruction probability for critical objects
    pub critical_object_probability: HashMap<ObjectId, f64>,

    /// Aggregate throughput
    pub total_throughput: ThroughputMetrics,

    /// Weakest links (devices that are single points of failure)
    pub weak_links: Vec<WeakLink>,
}

pub struct WeakLink {
    pub node_id: TailscaleNodeId,
    pub unique_symbols: usize,  // Symbols only this node has
    pub risk_level: RiskLevel,
}

impl MeshObservability {
    /// Compute mesh health score
    pub fn health_score(&self) -> f64 {
        let mut score = 1.0;

        // Penalize low device count
        if self.mesh_metrics.online_devices < 3 {
            score *= 0.8;
        }

        // Penalize low symbol coverage
        score *= self.mesh_metrics.symbol_coverage;

        // Penalize weak links
        for weak_link in &self.mesh_metrics.weak_links {
            match weak_link.risk_level {
                RiskLevel::Critical => score *= 0.5,
                RiskLevel::High => score *= 0.8,
                RiskLevel::Medium => score *= 0.9,
                RiskLevel::Low => {}
            }
        }

        score
    }

    /// Generate recommendations
    pub fn recommendations(&self) -> Vec<Recommendation> {
        let mut recs = Vec::new();

        if self.mesh_metrics.online_devices < 3 {
            recs.push(Recommendation::AddDevice {
                reason: "Fewer than 3 devices—limited redundancy".into(),
            });
        }

        for weak_link in &self.mesh_metrics.weak_links {
            if weak_link.risk_level >= RiskLevel::High {
                recs.push(Recommendation::RedistributeFromNode {
                    node_id: weak_link.node_id.clone(),
                    unique_symbols: weak_link.unique_symbols,
                });
            }
        }

        if self.mesh_metrics.symbol_coverage < 0.9 {
            recs.push(Recommendation::IncreaseRedundancy {
                current: self.mesh_metrics.symbol_coverage,
                target: 0.95,
            });
        }

        recs
    }
}
```

---

## Part 8: External Connectivity

### 8.1 Funnel Gateway

Public internet access via Tailscale Funnel:

```rust
/// Public gateway via Tailscale Funnel
pub struct FunnelGateway {
    /// Tailscale client
    pub tailscale: TailscaleClient,

    /// Mesh node
    pub mesh: Arc<MeshNode>,

    /// Funnel configuration
    pub config: FunnelConfig,
}

impl FunnelGateway {
    /// Handle incoming Funnel request
    pub async fn handle(&self, req: hyper::Request<Body>) -> Result<hyper::Response<Body>> {
        // 1. All Funnel traffic is z:public or z:community
        let zone = self.classify_zone(&req)?;

        if !matches!(zone, ZoneId::Public | ZoneId::Community) {
            return self.forbidden("Zone not accessible via Funnel");
        }

        // 2. Apply heavy taint (untrusted source)
        let provenance = Provenance::highly_tainted(zone.clone());

        // 3. Parse FCP request
        let fcp_req = self.parse_request(req, provenance).await?;

        // 4. Route through mesh
        let response = route_request(&self.mesh, fcp_req).await?;

        // 5. Return HTTP response
        self.to_http_response(response)
    }
}
```

### 8.2 External Service Connectors

Connectors to external services (Gmail, Discord, etc.) run on the mesh:

```rust
/// External service capability
pub struct ExternalServiceCapability {
    /// Which service (Gmail, Discord, Telegram, etc.)
    pub service: ServiceId,

    /// Base capability definition
    pub capability: MeshCapability,

    /// Credentials (as a threshold secret!)
    pub credentials: ThresholdSecret,

    /// Which devices can connect to this service?
    pub allowed_devices: Vec<TailscaleNodeId>,
}

impl ExternalServiceCapability {
    /// Invoke an operation on the external service
    pub async fn invoke(&self, request: InvokeObject) -> Result<ResponseObject> {
        // 1. Choose device to execute (must be allowed)
        let host = self.choose_allowed_host(&request);

        // 2. Reconstruct credentials on that device
        let creds = self.credentials.use_secret(|creds| creds.to_vec()).await?;

        // 3. Execute the operation
        let response = host.execute_with_creds(
            self.capability.capability_id,
            request,
            &creds,
        ).await?;

        // Credentials are zeroed automatically after use

        Ok(response)
    }

    fn choose_allowed_host(&self, request: &InvokeObject) -> TailscaleNodeId {
        self.allowed_devices.iter()
            .filter(|d| d.is_online())
            .min_by_key(|d| self.latency_to(d))
            .cloned()
            .expect("at least one allowed device online")
    }
}
```

---

## Part 9: Protocol Messages

### 9.1 Mesh Message Types

All messages are objects in symbol space:

```rust
/// Mesh-native message types
pub enum MeshObject {
    // ─────────────────────────────────────────────────────────────────
    // LIFECYCLE
    // ─────────────────────────────────────────────────────────────────

    /// Node joining the mesh
    JoinAnnouncement(JoinAnnouncement),

    /// Node leaving the mesh
    LeaveAnnouncement(LeaveAnnouncement),

    /// Gossip exchange
    GossipMessage(GossipMessage),

    // ─────────────────────────────────────────────────────────────────
    // INVOCATION
    // ─────────────────────────────────────────────────────────────────

    /// Capability invocation
    Invoke(InvokeObject),

    /// Invocation response
    Response(ResponseObject),

    // ─────────────────────────────────────────────────────────────────
    // EVENTS
    // ─────────────────────────────────────────────────────────────────

    /// Event epoch (batch of events)
    EventEpoch(EventEpochObject),

    /// Subscribe to events
    Subscribe(SubscribeObject),

    // ─────────────────────────────────────────────────────────────────
    // SYMBOLS
    // ─────────────────────────────────────────────────────────────────

    /// Symbol request
    SymbolRequest(SymbolRequest),

    /// Symbol delivery
    SymbolDelivery(SymbolDelivery),

    /// Symbol redistribution
    Redistribute(RedistributeRequest),

    // ─────────────────────────────────────────────────────────────────
    // COMPUTATION
    // ─────────────────────────────────────────────────────────────────

    /// Migrate computation
    MigrateComputation(MigrateRequest),

    /// Computation checkpoint
    Checkpoint(CheckpointObject),
}
```

### 9.2 Symbol Request/Delivery

The core primitive: requesting and delivering symbols:

```rust
/// Request symbols for an object
pub struct SymbolRequest {
    /// Which object?
    pub object_id: ObjectId,

    /// How many symbols do I need?
    pub symbols_needed: u16,

    /// Which symbols do I already have?
    pub already_have: Vec<u32>,  // ESIs

    /// Deadline
    pub deadline: Instant,
}

/// Deliver symbols
pub struct SymbolDelivery {
    /// For which request?
    pub request_id: ObjectId,

    /// The symbols
    pub symbols: Vec<SymbolEnvelope>,
}
```

### 9.3 Protocol Negotiation

Nodes negotiate protocol capabilities during mesh join:

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
}

pub enum ProtocolVersion {
    /// Original FCP (JSON-RPC frames)
    Fcp1,

    /// Symbol-native FCP (mesh-native)
    Fcp2Sym,
}
```

#### 9.3.1 Negotiation Protocol

```rust
/// Protocol negotiation (NORMATIVE)
pub struct Negotiation {
    /// My capabilities
    pub my_caps: TransportCaps,

    /// Peer's capabilities
    pub peer_caps: Option<TransportCaps>,

    /// Negotiated protocol
    pub negotiated: Option<NegotiatedProtocol>,
}

pub struct NegotiatedProtocol {
    /// Which version
    pub version: ProtocolVersion,

    /// Symbol mode
    pub symbol_native: bool,

    /// Compression
    pub compression: Option<CompressionAlgorithm>,

    /// Frame size
    pub max_frame_size: u32,
}

impl Negotiation {
    /// Negotiate protocol with peer
    pub fn negotiate(&mut self, peer_caps: TransportCaps) -> NegotiatedProtocol {
        self.peer_caps = Some(peer_caps.clone());

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

        let negotiated = NegotiatedProtocol {
            version,
            symbol_native,
            compression,
            max_frame_size,
        };

        self.negotiated = Some(negotiated.clone());
        negotiated
    }
}
```

#### 9.3.2 Hybrid Mode (Migration Support)

For backward compatibility during migration from FCP1 to mesh-native:

```rust
/// Hybrid mode translator (FCP1 <-> FCP2-SYM)
pub struct HybridTranslator {
    /// Negotiated protocol with peer
    pub peer_protocol: ProtocolVersion,

    /// Local preference
    pub local_protocol: ProtocolVersion,
}

impl HybridTranslator {
    /// Translate outgoing message
    pub fn translate_outgoing(&self, msg: MeshObject) -> OutgoingFrame {
        match self.peer_protocol {
            ProtocolVersion::Fcp1 => {
                // Convert symbol object to JSON-RPC frame
                self.to_json_rpc(msg)
            }
            ProtocolVersion::Fcp2Sym => {
                // Send as symbol batch
                self.to_symbol_frame(msg)
            }
        }
    }

    /// Translate incoming frame
    pub fn translate_incoming(&self, frame: IncomingFrame) -> MeshObject {
        match frame {
            IncomingFrame::JsonRpc(json) => {
                // Parse JSON-RPC, convert to object
                self.from_json_rpc(json)
            }
            IncomingFrame::SymbolBatch(symbols) => {
                // Reconstruct object from symbols
                self.from_symbols(symbols)
            }
        }
    }
}
```

### 9.4 Conformance Requirements

Every mesh-native implementation MUST pass these test vectors:

1. **Canonical serialization**: Given input, produce exact byte output
2. **ObjectId derivation**: Given content + zone + version, produce exact ObjectId
3. **Symbol encoding**: Given content, produce valid RaptorQ symbols
4. **Symbol reconstruction**: Given K' symbols, reconstruct original
5. **Signature verification**: Given signed object, verify correctly
6. **Revocation checking**: Given revocation list, correctly reject revoked items
7. **Source diversity**: Verify diversity requirements are enforced

Cross-implementation interop tests:

1. Handshake negotiation
2. Symbol exchange
3. Object reconstruction
4. Capability verification
5. Cross-zone bridging

---

## Part 10: Summary

### The Mesh-Native Protocol

By assuming:
1. **Universal fungibility** (all data as RaptorQ symbols)
2. **Trusted mesh** (all devices connected via Tailscale)

We get a fundamentally different protocol:

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

### What This Enables

1. **True sovereignty**: Your devices ARE the cloud
2. **No single point of failure**: Any k-of-n devices work
3. **Secrets never exist complete**: Threshold distribution everywhere
4. **Computation follows you**: Work happens where optimal
5. **Offline-first**: Graceful degradation, not hard failure
6. **Zero-config**: Tailscale handles discovery, NAT, encryption
7. **Defense-in-depth**: Network + crypto + application isolation
8. **Tamper-evident audit**: Distributed chain with diversity requirements
9. **Predictive performance**: Pre-stage symbols before needed
10. **Device-aware execution**: Right device for the job

### The Vision

Your personal AI runs on YOUR devices. Your data exists as symbols across YOUR mesh. Any subset of YOUR devices can reconstruct anything. Computation happens wherever optimal. Secrets are never complete anywhere. History is tamper-evident by construction.

This is not a cloud alternative. This is **digital sovereignty**.

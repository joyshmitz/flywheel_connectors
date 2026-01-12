# Flywheel Connector Protocol (FCP)

<div align="center">
  <img src="illustration.webp" alt="FCP - Secure connectors for AI agents with zone-based isolation and capability tokens">
</div>

A mesh-native protocol for secure, distributed AI assistant operations across personal device meshes — plus a growing library of production-ready Rust connectors implementing that protocol.

---

## TL;DR

**This project is two things:**

1. **The FCP Protocol** — A mesh-native specification for how AI agents securely interact with external services through zone-isolated, capability-gated connectors distributed across your personal device mesh

2. **Connector Implementations** — Production Rust binaries for Twitter, Linear, Stripe, Telegram, Discord, Gmail, GitHub, browser automation, and more

**The Vision**: Your personal AI runs on YOUR devices. Your data exists as symbols across YOUR mesh. Any subset of YOUR devices can reconstruct anything. Computation happens wherever optimal. Secrets are never complete anywhere. History is tamper-evident by construction.

**This is not a cloud alternative. This is digital sovereignty.**

**Registry Note**: Registries are just sources of signed manifests/binaries. Your mesh can mirror and pin connectors as content-addressed objects so installs/updates work offline and without upstream dependency.

### Three Foundational Axioms

| Axiom | Principle |
|-------|-----------|
| **Universal Fungibility** | All data flows as RaptorQ symbols. Any K' symbols reconstruct the original. No symbol is special. |
| **Authenticated Mesh** | Tailscale IS the transport AND the identity layer. Every node has unforgeable WireGuard keys. |
| **Explicit Authority** | No ambient authority. All capabilities flow from owner key through cryptographic chains. |

### Why Use FCP?

| Feature | What It Does |
|---------|--------------|
| **Mesh-Native Architecture** | Every device IS the Hub. No central coordinator. |
| **Symbol-First Protocol** | RaptorQ fountain codes enable multipath aggregation and offline resilience |
| **Zone Isolation** | Cryptographic namespaces with HKDF-derived keys and Tailscale ACL enforcement |
| **Capability Tokens** | Cryptographically-scoped authorization signed by attested node keys |
| **Threshold Secrets** | Shamir secret sharing with k-of-n across devices—never complete anywhere |
| **Computation Migration** | Operations execute on the optimal device automatically |
| **Offline Access** | Reduced probability, not binary unavailability |
| **Tamper-Evident Audit** | Hash-linked audit chain with quorum-signed checkpoints |
| **Revocation** | First-class revocation objects for tokens, keys, and devices |

### Quick Example

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PERSONAL MESH                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐                      │
│   │ Desktop  │◄────►│  Laptop  │◄────►│  Phone   │  ← Tailscale mesh    │
│   │ MeshNode │      │ MeshNode │      │ MeshNode │                      │
│   └────┬─────┘      └────┬─────┘      └────┬─────┘                      │
│        │                 │                 │                             │
│        ▼                 ▼                 ▼                             │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                    SYMBOL DISTRIBUTION                           │   │
│   │  Object: gmail-inbox-2026-01   K=100 symbols distributed        │   │
│   │  Desktop: [1,5,12,23,...]  Laptop: [2,8,15,...]  Phone: [3,9,...]│   │
│   │  Any 100 symbols → full reconstruction                          │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│   Agent Request                                                          │
│       │                                                                  │
│       ▼                                                                  │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│   │ Zone Check  │────►│  Cap Check  │────►│  Connector  │               │
│   │ z:private?  │     │ gmail.read? │     │   Gmail     │               │
│   │ (crypto+ACL)│     │ (signed)    │     │ (sandboxed) │               │
│   └─────────────┘     └─────────────┘     └─────────────┘               │
│         │                   │                   │                        │
│         ▼                   ▼                   ▼                        │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  Revocation Check → Receipt Generation → Audit Event Logged     │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                  │                       │
│                                                  ▼                       │
│                                           Gmail API                      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Origins & Motivation

This project emerged from the Agent Flywheel ecosystem, where AI coding agents coordinate across multiple external services. Existing approaches to multi-service integration suffer from critical security flaws:

1. **Trust Commingling**: A message from a public Discord channel could trigger operations on private Gmail
2. **Prompt-Based Security**: "Don't read private emails" is trivially bypassed by prompt injection
3. **Centralized Architecture**: Single points of failure, cloud dependency, vendor lock-in
4. **Binary Offline**: No connectivity = no access

FCP addresses these through:
- **Zones as cryptographic universes**—if the Gmail-read capability doesn't exist in a zone, it cannot be invoked, regardless of what an agent says
- **Mesh-native architecture**—your devices collectively ARE the system
- **Symbol-first protocol**—data availability is probabilistic, not binary
- **Revocation as first-class primitive**—compromised devices can be removed and keys rotated

---

## Core Concepts

### Terminology

| Term | Definition |
|------|------------|
| **Symbol** | A RaptorQ-encoded fragment; any K' symbols reconstruct the original |
| **Object** | Content-addressed data with ObjectHeader (refs, retention, provenance) |
| **Zone** | A cryptographic namespace with HKDF-derived encryption key |
| **Epoch** | A logical time unit; no ordering within, ordering between |
| **MeshNode** | A device participating in the FCP mesh |
| **Capability** | An authorized operation with cryptographic proof |
| **Connector** | A sandboxed binary that bridges external services to FCP |
| **Receipt** | Signed proof of operation execution for idempotency |
| **Revocation** | First-class object that invalidates tokens, keys, or devices |

### Key Architecture

FCP uses three distinct cryptographic key roles:

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| **Owner Key** | Ed25519 | Root trust anchor; signs attestations and revocations |
| **Node Signing Key** | Ed25519 | Per-device; signs symbols, gossip, receipts, tokens |
| **Zone Encryption Key** | ChaCha20-Poly1305 | HKDF-derived from owner secret; encrypts zone data |

Every node has a **NodeKeyAttestation** signed by the owner, binding the Tailscale node ID to its signing key.

### Security Invariants

These are **hard requirements** that FCP enforces mechanically:

1. **Single-Zone Binding**: A connector instance MUST bind to exactly one zone for its lifetime
2. **Default Deny**: If a capability is not explicitly granted to a zone, it MUST be impossible to invoke
3. **No Cross-Connector Calling**: Connectors MUST NOT call other connectors directly; all composition happens through the mesh
4. **Threshold Secret Distribution**: Secrets use Shamir sharing—never complete on any single device
5. **Revocation Enforcement**: Tokens, keys, and operations MUST check revocation before use
6. **Auditable Everything**: Every operation produces a signed receipt and audit event
7. **Cryptographic Authority Chain**: All authority flows from owner key through verifiable signature chains

---

## Zone Architecture

Zones are **cryptographic boundaries**, not labels. Each zone has its own encryption key derived from the owner's secret key using HKDF with domain separation.

### Zone Hierarchy with Tailscale Mapping

```
z:owner        [Trust: 100]  Direct owner control, most privileged
    │                        Tailscale tag: tag:fcp-owner
    ▼
z:private      [Trust: 80]   Personal data, high sensitivity
    │                        Tailscale tag: tag:fcp-private
    ▼
z:work         [Trust: 60]   Professional context, medium sensitivity
    │                        Tailscale tag: tag:fcp-work
    ▼
z:community    [Trust: 40]   Trusted external (paired users)
    │                        Tailscale tag: tag:fcp-community
    ▼
z:public       [Trust: 20]   Public/anonymous inputs
                             Tailscale tag: tag:fcp-public

INVARIANT: Data can flow DOWN (higher → lower trust) freely.
           Data flowing UP requires explicit elevation + approval.
```

### Defense-in-Depth

```
Layer 1: Tailscale ACLs     → Network-level isolation
Layer 2: Zone Encryption    → Cryptographic isolation (HKDF-derived keys)
Layer 3: Policy Objects     → Authority isolation
Layer 4: Capability Signing → Operation isolation (node-signed tokens)
Layer 5: Revocation Check   → Continuous validity enforcement
```

---

## Symbol Layer

All data in FCP flows as RaptorQ fountain-coded symbols.

### Why Symbols?

```
Traditional Approach:
  File: 100KB → Must transfer complete file
  Lost packet → Retransmit specific data
  Single path → Bandwidth limited

Symbol Approach:
  File: 100KB → 100 symbols (1KB each)
  Any 100 symbols → Full reconstruction
  No symbol is special → No retransmit coordination
  Multipath aggregation → Symbols from any source contribute equally
```

### Symbol Properties

| Property | Benefit |
|----------|---------|
| **Fungibility** | Any K' symbols reconstruct; no coordination needed |
| **Multipath** | Aggregate bandwidth across all network paths |
| **Resumable** | No bookkeeping; just collect more symbols |
| **DoS Resistant** | Attackers can't target "important" symbols |
| **Offline Resilient** | Partial availability = partial reconstruction |
| **Key Rotation Safe** | zone_key_id in each symbol enables seamless rotation |

### Frame Format (FCPS)

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
│  Bytes 58-73:  Zone ID hash (16 bytes)                                      │
│  Bytes 74-81:  Epoch ID (u64 LE)                                            │
│  Bytes 82+:    Symbol payloads (encrypted, concatenated)                    │
│  Final 8:      Checksum (XXH3-64)                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Mesh Architecture

Every device is a MeshNode—collectively, they ARE the Hub.

### MeshNode Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MESHNODE                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Tailscale Identity                                                  │    │
│  │  • Stable node ID (unforgeable WireGuard keys)                      │    │
│  │  • Node signing key (Ed25519) with owner-signed attestation         │    │
│  │  • ACL tags for zone mapping                                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Symbol Store                                                        │    │
│  │  • Local symbol storage with retention classes                       │    │
│  │  • XOR filters + IBLT for efficient gossip reconciliation           │    │
│  │  • Reachability-based garbage collection                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Capability & Revocation Registry                                    │    │
│  │  • Zone keys (HKDF-derived) for encryption/decryption               │    │
│  │  • Trust anchors (owner key, attested node keys)                    │    │
│  │  • Revocation checking before every operation                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Execution Planner                                                   │    │
│  │  • Device profiles (CPU, GPU, memory, battery)                       │    │
│  │  • Connector availability and version requirements                   │    │
│  │  • Secret reconstruction cost estimation                             │    │
│  │  • Symbol locality scoring                                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Audit Chain                                                         │    │
│  │  • Hash-linked audit events per zone                                 │    │
│  │  • Quorum-signed audit heads for tamper evidence                    │    │
│  │  • Operation receipts for idempotency                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Transport Priority

```
Priority 1: Tailscale Direct (same LAN)     - <1ms, z:owner OK
Priority 2: Tailscale Mesh (NAT traversal)  - 10-100ms, z:owner OK
Priority 3: Tailscale DERP Relay            - 50-200ms, z:private and below
Priority 4: Tailscale Funnel (public)       - Variable, z:community/public only
```

### Device Enrollment

New devices join the mesh through owner-signed enrollment:

1. Device joins Tailscale tailnet
2. Owner issues `DeviceEnrollment` object (signed)
3. Owner issues `NodeKeyAttestation` binding node to signing key
4. Device receives enrollment via mesh gossip
5. Other nodes accept the new device as peer

Device removal triggers revocation + zone key rotation + secret resharing.

---

## Connector Binary Structure

Every FCP connector is a single executable with embedded metadata:

```
┌────────────────────────────────────────────────────────────────┐
│                        FCP BINARY                               │
├────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    MANIFEST SECTION                       │  │
│  │  ┌─────────────────┐  ┌─────────────────┐                │  │
│  │  │  Metadata       │  │  Capabilities   │                │  │
│  │  │  - Name         │  │  - Required     │                │  │
│  │  │  - Version      │  │  - Optional     │                │  │
│  │  │  - Author       │  │  - Forbidden    │                │  │
│  │  └─────────────────┘  └─────────────────┘                │  │
│  │  ┌─────────────────┐  ┌─────────────────┐                │  │
│  │  │  Zone Policy    │  │  Sandbox Config │                │  │
│  │  │  - Home zone    │  │  - Memory limit │                │  │
│  │  │  - Allowed      │  │  - CPU limit    │                │  │
│  │  │  - Tailscale tag│  │  - FS access    │                │  │
│  │  └─────────────────┘  └─────────────────┘                │  │
│  │  ┌─────────────────┐                                      │  │
│  │  │  AI Hints       │  ← Agent-readable operation docs     │  │
│  │  │  - Operations   │                                      │  │
│  │  │  - Examples     │                                      │  │
│  │  │  - Safety notes │                                      │  │
│  │  └─────────────────┘                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    CODE SECTION                           │  │
│  │  - FCP protocol implementation                            │  │
│  │  - Capability negotiation                                 │  │
│  │  - External API clients                                   │  │
│  │  - State management                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   SIGNATURE SECTION                       │  │
│  │  - Ed25519 signature over manifest + code                 │  │
│  │  - Reproducible build attestation                         │  │
│  │  - Registry provenance chain                              │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### Sandbox Enforcement

Connectors run in OS-level sandboxes (seccomp/seatbelt/AppContainer):

| Constraint | Purpose |
|------------|---------|
| Memory limit | Prevent resource exhaustion |
| CPU limit | Prevent runaway computation |
| Wall clock timeout | Bound operation duration |
| FS readonly paths | Limit filesystem access |
| FS writable paths | Explicit state directory |
| deny_exec | Prevent child process spawning |
| deny_ptrace | Prevent debugging/tracing |

---

## Security Model

### Threat Model

FCP defends against:

| Threat | Mitigation |
|--------|------------|
| Compromised device | Threshold secrets (Shamir), revocation, zone key rotation |
| Malicious connector binary | Ed25519 signature verification, OS sandboxing |
| Compromised external service | Zone isolation, capability limits |
| Prompt injection via messages | Protocol-level filtering, taint tracking, no code execution |
| Privilege escalation | Static capability allocation, no runtime grants |
| Replay attacks | Epoch binding, nonce verification, receipts |
| Key compromise | Revocation objects, key rotation with zone_key_id |
| Supply chain attacks | Reproducible builds, provenance attestation, mesh mirroring |

### Threshold Secrets

Secrets use **Shamir's Secret Sharing** (not RaptorQ symbols—those can leak structure):

```
Secret: API_KEY
Scheme: Shamir over GF(2^8), k=3, n=5

Distribution:
  Desktop: share_1 (wrapped for Desktop's public key)
  Laptop:  share_2 (wrapped for Laptop's public key)
  Phone:   share_3 (wrapped for Phone's public key)
  Tablet:  share_4 (wrapped for Tablet's public key)
  Server:  share_5 (wrapped for Server's public key)

To use secret:
  1. Obtain SecretAccessToken (signed by approver)
  2. Collect any 3 wrapped shares
  3. Unwrap and reconstruct using Shamir
  4. Use in memory only
  5. Zeroize immediately after use
  6. Log audit event

No single device ever has the complete secret.
A node cannot decrypt other nodes' shares.
```

### Operation Receipts

Operations with side effects produce signed receipts:

```
OperationReceipt {
  request_object_id    → What was requested
  idempotency_key      → For deduplication
  outcome_object_ids   → What was produced
  executed_at          → When
  executed_by          → Which node
  signature            → Node's signing key
}
```

On retry with same idempotency key, mesh returns prior receipt instead of re-executing.

### Revocation

First-class revocation objects can invalidate:

| Scope | Effect |
|-------|--------|
| Capability | Token becomes invalid |
| IssuerKey | Node can no longer mint tokens |
| NodeAttestation | Device removed from mesh |
| ZoneKey | Forces key rotation |
| ConnectorBinary | Supply chain incident response |

Revocations are owner-signed and enforced before every operation.

### Audit Chain

Every zone maintains a hash-linked audit chain:

```
AuditEvent_1 → AuditEvent_2 → AuditEvent_3 → ... → AuditHead
     ↑              ↑              ↑                   ↑
  signed         signed         signed         quorum-signed
```

- Events are hash-linked (tamper-evident)
- AuditHead checkpoints are quorum-signed (n-f nodes)
- Fork detection triggers alerts
- Required events: secret access, risky operations, elevations, zone transitions

---

## Connectors

### Tier 1: Critical Infrastructure (Build First)

These unlock entire categories of autonomous agent work.

| Connector | Value | Archetype | Why Critical |
|-----------|-------|-----------|--------------|
| `fcp.twitter` | 98 | Request-Response + Streaming | Real-time information layer; social listening, posting, DMs |
| `fcp.linear` | 97 | Request-Response + Webhook | Human↔agent task handoff; bi-directional Beads sync |
| `fcp.stripe` | 96 | Request-Response + Webhook | Financial operations; invoicing, subscriptions, analytics |
| `fcp.youtube` | 95 | Request-Response | Video transcripts, channel analytics, content research |
| `fcp.browser` | 95 | Browser Automation | Universal adapter for any web service without API |
| `fcp.telegram` | 94 | Bidirectional + Webhook | Real-time messaging, bot automation |
| `fcp.discord` | 93 | Bidirectional + Webhook | Community management, server automation |

### Tier 2: Productivity & Workspace

| Connector | Archetype | Use Case |
|-----------|-----------|----------|
| `fcp.gmail` | Polling + Request-Response | Email automation, inbox management |
| `fcp.google_calendar` | Request-Response + Polling | Scheduling, availability |
| `fcp.notion` | Request-Response | Knowledge base, documentation |
| `fcp.github` | Request-Response + Webhook | Code review, issue management, CI/CD |
| `fcp.slack` | Bidirectional | Team communication |

### Tier 3: Infrastructure & Data

| Connector | Archetype | Use Case |
|-----------|-----------|----------|
| `fcp.s3` | File/Blob | Cloud storage operations |
| `fcp.postgresql` | Database | Direct database queries |
| `fcp.elasticsearch` | Database | Search and analytics |
| `fcp.redis` | Queue/Pub-Sub | Caching, message queues |
| `fcp.whisper` | CLI/Process | Voice transcription |

---

## Registry Architecture

Registries are **sources, not dependencies**:

| Type | Description |
|------|-------------|
| **Remote Registry** | Public (registry.flywheel.dev) or private HTTP registry |
| **Self-Hosted Registry** | Enterprise internal registry |
| **Mesh Mirror** | Connectors as pinned objects in z:owner (recommended) |

Connector binaries are content-addressed objects distributed via the symbol layer.
Your mesh can install/update connectors fully offline from mirrored objects.

---

## Performance Targets

| Metric | Target | Enforcement |
|--------|--------|-------------|
| Cold start | < 50ms | Binary preloading |
| Message latency | < 1ms | Zero-copy IPC |
| Memory overhead | < 10MB per connector | Sandbox limits |
| CPU overhead | < 1% idle | Event-driven architecture |
| Symbol reconstruction | < 10ms for 1MB object | Optimized RaptorQ |
| Secret reconstruction | < 100ms | Parallel share collection |

---

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64, aarch64 | Tier 1 |
| macOS | x86_64, aarch64 | Tier 1 |
| Windows | x86_64 | Tier 2 |
| FreeBSD | x86_64 | Tier 3 |

---

## Project Structure

```
flywheel_connectors/
├── crates/
│   ├── fcp-core/          # Core types: zones, capabilities, provenance, errors
│   ├── fcp-protocol/      # Wire protocol: FCPS framing, symbol encoding
│   ├── fcp-mesh/          # Mesh implementation: MeshNode, gossip, routing
│   ├── fcp-raptorq/       # RaptorQ integration: encoding, decoding, distribution
│   ├── fcp-tailscale/     # Tailscale integration: identity, ACLs, routing
│   ├── fcp-secrets/       # Shamir secret sharing, SecretAccessToken
│   ├── fcp-audit/         # Audit chain, receipts, quorum signing
│   ├── fcp-manifest/      # Manifest parsing and validation
│   ├── fcp-sandbox/       # OS sandbox integration (seccomp, seatbelt, AppContainer)
│   ├── fcp-sdk/           # SDK for building connectors
│   └── fcp-cli/           # CLI tools (fcp install, fcp doctor, etc.)
│
├── connectors/            # Individual connector implementations
│   ├── twitter/
│   ├── linear/
│   ├── stripe/
│   ├── telegram/
│   ├── discord/
│   └── ...
│
├── FCP_Specification_V2.md   # Protocol specification
├── AGENTS.md                 # AI coding agent guidelines
└── README.md
```

---

## Related Flywheel Components

FCP integrates with the broader Agent Flywheel ecosystem:

| Component | Purpose | Interaction |
|-----------|---------|-------------|
| **Tailscale** | Mesh networking, identity | Transport and ACL layer |
| **MCP Agent Mail** | Inter-agent messaging | Coordinate connector operations |
| **Beads (bd/bv)** | Issue tracking | Track connector development |
| **CASS** | Memory/context system | Store connector interaction history |
| **UBS** | Bug scanning | Validate connector code |
| **dcg** | Command guard | Protect during development |

---

## Development

### Prerequisites

- Rust nightly (2024 edition)
- Cargo
- Tailscale (for mesh features)

### Building

```bash
# Build all connectors
cargo build --release

# Build specific connector
cargo build --release -p fcp-telegram

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets -- -D warnings
```

### Creating a New Connector

1. Create connector crate: `cargo new connectors/myservice --lib`
2. Add FCP SDK dependency
3. Implement `FcpConnector` trait
4. Define manifest with capabilities, zone policy, and sandbox config
5. Add archetype-specific traits
6. Write tests with mocked external service
7. Document AI hints for each operation

---

## Contributing

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT

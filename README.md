# Flywheel Connectors

Secure, high-performance Rust connectors for integrating external services into AI agent ecosystems.

This project implements the **Flywheel Connector Protocol (FCP)** — a protocol specification plus a growing library of production-ready connectors that enable AI coding agents to safely interact with messaging platforms, cloud services, APIs, and databases while maintaining strict security boundaries.

---

## TL;DR

**What we're building**: A comprehensive suite of Rust connectors for AI agents — Twitter, Linear, Stripe, YouTube, Telegram, Discord, Gmail, GitHub, browser automation, and more.

**Why it matters**: Current multi-service integrations commingle trust levels (a public Discord message could trigger Gmail operations), rely on prompt-based security (trivially bypassed), or require custom integration code per service.

**The approach**: Self-contained Rust binaries with:
- **Zone isolation**: Each connector binds to exactly one trust domain
- **Capability tokens**: Cryptographically-scoped authorization for every operation
- **Mechanical security**: Enforced by type system and binary boundaries, not prompts
- **Agent-native design**: Every operation is introspectable with AI hints

### Why Use FCP?

| Feature | What It Does |
|---------|--------------|
| **Zone-First Security** | Mechanical isolation between trust domains (public/private/team) |
| **Capability Tokens** | Cryptographically-scoped authorization for every operation |
| **10 Connector Archetypes** | Patterns for REST, WebSocket, polling, webhooks, queues, and more |
| **Self-Contained Binaries** | Single executable per connector with embedded manifest |
| **Ed25519 Signatures** | Reproducible builds with cryptographic verification |
| **Agent-Native Design** | Built for AI ergonomics: introspectable, predictable, recoverable |

### Quick Example

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          FLYWHEEL GATEWAY                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Agent Request                                                          │
│       │                                                                  │
│       ▼                                                                  │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│   │ Zone Check  │────▶│  Cap Check  │────▶│  Connector  │               │
│   │ z:public?   │     │ gmail.read? │     │   Gmail     │               │
│   └─────────────┘     └─────────────┘     └─────────────┘               │
│                                                  │                       │
│                                                  ▼                       │
│                                           ┌───────────┐                  │
│                                           │  Sandbox  │                  │
│                                           │ • Isolated FS               │
│                                           │ • Filtered net              │
│                                           │ • IPC only                  │
│                                           └───────────┘                  │
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
3. **Monolithic Architecture**: All integrations share credentials, context, and failure modes

FCP addresses these by treating **zones as capability universes**—if the Gmail-read capability doesn't exist in a zone, it cannot be invoked, regardless of what an agent says or what prompt injection occurs.

---

## Core Concepts

### Terminology

| Term | Definition |
|------|------------|
| **Connector** | A self-contained binary implementing the FCP interface for one external service |
| **Zone** | A security boundary defining trust level, allowed principals, and capability ceiling |
| **Capability** | A specific permission (e.g., `gmail.read`, `telegram.send`) with constraints |
| **Manifest** | Embedded metadata describing connector properties, requirements, and AI hints |
| **Gateway** | The Flywheel component that orchestrates connectors and enforces policy |
| **Principal** | An identity (user, agent, or service) making requests |
| **FCT (Flywheel Capability Token)** | Cryptographically-scoped authorization for operations |

### Security Invariants

These are **hard requirements** that FCP enforces mechanically:

1. **Single-Zone Binding**: A connector instance MUST bind to exactly one zone for its lifetime
2. **Default Deny**: If a capability is not explicitly granted to a zone, it MUST be impossible to invoke
3. **No Cross-Connector Calling**: Connectors MUST NOT call other connectors directly; all composition happens through the Gateway
4. **No Credential Custody by Host**: The Gateway MUST NOT store raw OAuth tokens or API keys; connectors manage their own credentials
5. **Strong Ingress Provenance**: Every ingress event MUST include principal identity and origin attributes
6. **Auditable Everything**: Every operation invocation MUST produce auditable records with correlation IDs

---

## Zone Architecture

Zones are **security boundaries**, not labels. They define capability universes.

### Standard Zone Hierarchy

```
z:system        → Internal Flywheel operations (most privileged)
    │
    ├── z:owner         → Full owner access (personal private data)
    │       │
    │       └── z:team          → Team-level access (shared workspaces)
    │               │
    │               └── z:public        → Public-facing operations (external users)
    │                       │
    │                       └── z:untrusted     → Minimal sandbox (prompt injection territory)
```

### Zone Configuration

```rust
pub struct ZoneConfig {
    /// Unique zone identifier
    pub id: ZoneId,

    /// Trust level (0-100, higher = more trusted)
    pub trust_level: u8,

    /// Parent zone for hierarchical inheritance
    pub parent: Option<ZoneId>,

    /// Maximum capabilities grantable in this zone
    pub capability_ceiling: CapabilitySet,

    /// Allowed connectors (allowlist)
    pub allowed_connectors: Vec<ConnectorId>,

    /// Data flow policy (inbound/outbound zones)
    pub data_flow: DataFlowPolicy,
}
```

### Zone Rules

| Rule | Enforcement |
|------|-------------|
| Single-zone binding | Connector process receives zone at startup; cannot change |
| Capability ceiling | Gateway rejects capability grants exceeding zone ceiling |
| Data flow | Gateway blocks cross-zone data unless explicitly allowed |
| Principal filtering | Zone defines which principals can access it |

---

## Connector Archetypes

FCP defines 10 fundamental data flow patterns. Each connector implements one or more archetypes.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FCP CONNECTOR ARCHETYPES                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ REQUEST-RESPONSE│  │    STREAMING    │  │  BIDIRECTIONAL  │              │
│  │                 │  │                 │  │                 │              │
│  │   Agent ──────► │  │   Agent ◄───── │  │   Agent ◄─────► │              │
│  │          ◄───── │  │         Server  │  │          Server │              │
│  │         Service │  │                 │  │                 │              │
│  │                 │  │                 │  │                 │              │
│  │ Examples:       │  │ Examples:       │  │ Examples:       │              │
│  │ • REST APIs     │  │ • WebSocket     │  │ • Chat protocols│              │
│  │ • GraphQL       │  │ • SSE           │  │ • Collaborative │              │
│  │ • gRPC unary    │  │ • Log tailing   │  │ • Game state    │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │     POLLING     │  │     WEBHOOK     │  │   QUEUE/PUBSUB  │              │
│  │                 │  │                 │  │                 │              │
│  │   Agent ──────► │  │   Agent ◄───── │  │   Agent ◄─────► │              │
│  │   (periodic)    │  │    (push)       │  │          Broker │              │
│  │         Service │  │         Service │  │                 │              │
│  │                 │  │                 │  │                 │              │
│  │ Examples:       │  │ Examples:       │  │ Examples:       │              │
│  │ • Email (IMAP)  │  │ • GitHub hooks  │  │ • Redis Pub/Sub │              │
│  │ • RSS feeds     │  │ • Stripe events │  │ • NATS          │              │
│  │ • Status checks │  │ • Slack events  │  │ • Kafka         │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │   FILE/BLOB     │  │ DATABASE/QUERY  │  │  CLI/PROCESS    │              │
│  │                 │  │                 │  │                 │              │
│  │   Agent ──────► │  │   Agent ──────► │  │   Agent ──────► │              │
│  │   (upload/dl)   │  │   (query)       │  │   (spawn)       │              │
│  │         Storage │  │         DB      │  │         Process │              │
│  │                 │  │                 │  │                 │              │
│  │ Examples:       │  │ Examples:       │  │ Examples:       │              │
│  │ • S3            │  │ • PostgreSQL    │  │ • git           │              │
│  │ • GCS           │  │ • Vector DBs    │  │ • kubectl       │              │
│  │ • Local FS      │  │ • Elasticsearch │  │ • terraform     │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
│                                                                              │
│  ┌─────────────────┐                                                         │
│  │    BROWSER      │  ← Combines multiple patterns                           │
│  │   AUTOMATION    │                                                         │
│  │                 │                                                         │
│  │   Agent ──────► │                                                         │
│  │   (CDP)         │                                                         │
│  │         Browser │                                                         │
│  └─────────────────┘                                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Archetype Selection Guide

| Use Case | Primary Archetype | Secondary |
|----------|-------------------|-----------|
| REST API integration | Request-Response | — |
| Real-time chat (Telegram, Discord) | Bidirectional | Webhook |
| Email inbox monitoring | Polling | Request-Response |
| GitHub/Stripe webhooks | Webhook | — |
| S3/GCS file operations | File/Blob | — |
| Database queries | Database | — |
| Running git/kubectl | CLI/Process | — |
| Message queue processing | Queue/Pub-Sub | — |
| Web scraping | Browser | Request-Response |

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
│  │  │  - License      │  │                 │                │  │
│  │  └─────────────────┘  └─────────────────┘                │  │
│  │  ┌─────────────────┐  ┌─────────────────┐                │  │
│  │  │  Zone Policy    │  │  Config Schema  │                │  │
│  │  │  - Home zone    │  │  - JSON Schema  │                │  │
│  │  │  - Allowed      │  │  - Defaults     │                │  │
│  │  │  - Denied       │  │  - Secrets ref  │                │  │
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

---

## Security Model

### Threat Model

FCP defends against:

| Threat | Mitigation |
|--------|------------|
| Malicious connector binary | Ed25519 signature verification, sandboxing |
| Compromised external service | Zone isolation, capability limits |
| Prompt injection via messages | Protocol-level filtering, no code execution |
| Privilege escalation | Static capability allocation, no runtime grants |
| Side-channel leaks | Memory isolation, timing-safe operations |
| Supply chain attacks | Reproducible builds, provenance attestation |

### Capability Token Structure

```rust
pub struct CapabilityToken {
    /// Unique token identifier
    pub jti: Uuid,
    /// Principal identifier
    pub sub: PrincipalId,
    /// Issuing zone
    pub iss: ZoneId,
    /// Intended audience (connector)
    pub aud: ConnectorId,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Expires at (Unix timestamp)
    pub exp: u64,
    /// Granted capabilities with constraints
    pub caps: Vec<CapabilityGrant>,
    /// Ed25519 signature
    pub sig: [u8; 64],
}
```

### Sandbox Architecture

Each connector runs in isolation:

```
┌────────────────────────────────────────────────────────────────┐
│                      HOST SYSTEM                                │
├────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   GATEWAY PROCESS                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │  │
│  │  │ Supervisor  │  │  IPC Hub    │  │ Capability  │       │  │
│  │  │             │  │             │  │  Verifier   │       │  │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │  │
│  └─────────┼────────────────┼────────────────┼──────────────┘  │
│            │                │                │                  │
│  ┌─────────▼────────────────▼────────────────▼──────────────┐  │
│  │                   SANDBOX BOUNDARY                        │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │              CONNECTOR SANDBOX                      │  │  │
│  │  │  ┌──────────────────────────────────────────────┐  │  │  │
│  │  │  │  Filesystem: /fcp/<connector>/               │  │  │  │
│  │  │  │    ├── config/   (read-only)                 │  │  │  │
│  │  │  │    ├── data/     (read-write, encrypted)     │  │  │  │
│  │  │  │    ├── cache/    (read-write, ephemeral)     │  │  │  │
│  │  │  │    └── tmp/      (read-write, tmpfs)         │  │  │  │
│  │  │  └──────────────────────────────────────────────┘  │  │  │
│  │  │  ┌──────────────────────────────────────────────┐  │  │  │
│  │  │  │  Network: Filtered by capability             │  │  │  │
│  │  │  │    - Allowed: api.telegram.org:443           │  │  │  │
│  │  │  │    - Denied: *                               │  │  │  │
│  │  │  └──────────────────────────────────────────────┘  │  │  │
│  │  │  ┌──────────────────────────────────────────────┐  │  │  │
│  │  │  │  IPC: Unix socket only                       │  │  │  │
│  │  │  │    /fcp/ipc/<connector>.sock                 │  │  │  │
│  │  │  └──────────────────────────────────────────────┘  │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### Secret Management

```
┌────────────────────────────────────────────────────────────────┐
│                    SECRET LIFECYCLE                             │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. PROVISIONING                                                │
│     User → Gateway (seal) → Vault (store)                       │
│                                                                 │
│  2. INJECTION                                                   │
│     Vault (unseal) → Gateway (inject) → Connector (memory only) │
│                                                                 │
│  3. USAGE                                                       │
│     - Secrets exist only in memory                              │
│     - Never logged, never serialized                            │
│     - Zeroized on connector termination                         │
│                                                                 │
│  4. ROTATION                                                    │
│     - Automatic per schedule                                    │
│     - Hot-reload without connector restart                      │
│     - Full audit trail                                          │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

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

## Performance Targets

| Metric | Target | Enforcement |
|--------|--------|-------------|
| Cold start | < 50ms | Binary preloading |
| Message latency | < 1ms | Zero-copy IPC |
| Memory overhead | < 10MB per connector | Static allocation |
| CPU overhead | < 1% idle | Event-driven architecture |

---

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64, aarch64 | Tier 1 |
| macOS | x86_64, aarch64 | Tier 1 |
| Windows | x86_64 | Tier 2 |
| FreeBSD | x86_64 | Tier 3 |

---

## Project Structure (Planned)

```
flywheel_connectors/
├── crates/
│   ├── fcp-core/          # Core types: zones, capabilities, provenance, errors
│   ├── fcp-protocol/      # Wire protocol: CBOR framing, JSON-RPC compat
│   ├── fcp-manifest/      # Manifest parsing and validation
│   ├── fcp-sdk/           # SDK for building connectors
│   ├── fcp-host/          # Hub/Gateway implementation
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
├── FCP_Specification_V1.md   # Protocol specification
├── AGENTS.md                 # AI coding agent guidelines
└── README.md
```

---

## Related Flywheel Components

FCP integrates with the broader Agent Flywheel ecosystem:

| Component | Purpose | Interaction |
|-----------|---------|-------------|
| **Flywheel Gateway** | HTTP/WS API for agents | Orchestrates connectors |
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
4. Define manifest with capabilities and zone policy
5. Add archetype-specific traits
6. Write tests with mocked external service
7. Document AI hints for each operation

---

## Contributing

Contributions are evaluated via GitHub issues. Please file issues for:
- Bug reports
- Security vulnerabilities (via private disclosure)
- Feature requests
- Documentation improvements

PRs may be submitted to illustrate proposed fixes but will be reviewed and potentially re-implemented rather than merged directly.

---

## License

MIT

# Flywheel Connector Protocol (FCP)

## Version 1.0.0 — Specification Document

> **Classification**: Public Specification
> **Status**: Draft
> **Last Updated**: January 2026
> **Authors**: Flywheel Core Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Design Principles](#3-design-principles)
4. [System Architecture](#4-system-architecture)
5. [Security Model](#5-security-model)
6. [Zone Architecture](#6-zone-architecture)
7. [Provenance and Taint Tracking](#7-provenance-and-taint-tracking)
8. [Capability System](#8-capability-system)
9. [Wire Protocol](#9-wire-protocol)
10. [Connector Manifest](#10-connector-manifest)
11. [Automation Recipes](#11-automation-recipes)
12. [Registry and Supply Chain](#12-registry-and-supply-chain)
13. [Lifecycle Management](#13-lifecycle-management)
14. [Agent Integration](#14-agent-integration)
15. [Observability and Audit](#15-observability-and-audit)
16. [Error Taxonomy](#16-error-taxonomy)
17. [Migration Strategy](#17-migration-strategy)
18. [Appendices](#appendices)

---

## 1. Executive Summary

### 1.1 Purpose

The Flywheel Connector Protocol (FCP) defines a secure, modular, high-performance framework for integrating external services into the Agent Flywheel ecosystem. FCP enables AI coding agents to safely interact with messaging platforms, cloud services, productivity tools, and other external systems while maintaining strict security boundaries.

### 1.2 Core Problem

If a public-facing integration (Discord, webhooks, social DMs) and a private integration (email, calendar, files) share a process or trust domain, a single prompt injection or parsing bug can lead to catastrophic cross-domain access.

FCP prevents this by enforcing **mechanical isolation** and **topological security**:

1. **Connectors are isolated binaries** — No shared memory; sandboxed execution
2. **Zones define trust topology** — Where things may run and how data may flow
3. **Capabilities define permissions** — What a connector or agent may do
4. **Provenance tracks causal origin** — Where an instruction came from
5. **Approvals gate high-risk actions** — Humans or policy must explicitly elevate
6. **Everything is self-describing** — Manifests, schemas, AI hints, recovery maps

### 1.3 Key Innovations

| Innovation | Description |
|------------|-------------|
| **Zone-Based Security** | Mechanical, protocol-level isolation between trust domains |
| **Provenance/Taint Tracking** | Prevents "untrusted input → privileged action" chains |
| **Capability-Based Access** | Fine-grained permissions enforced at the binary level |
| **Self-Contained Binaries** | Single-binary connectors with embedded manifests |
| **Cryptographic Verification** | Ed25519-signed connectors with reproducible builds |
| **Automation Recipes** | First-class setup/teardown workflows |
| **Agent-Native Design** | Purpose-built for AI agent ergonomics and introspection |

### 1.4 Non-Goals

FCP explicitly does NOT:

- Support interpreted language runtimes (Python venvs, Node.js, etc.)
- Allow dynamic code execution within connectors
- Use "prompt security" as a primary security mechanism
- Require Docker as the unit of distribution
- Support connectors requiring root/administrator privileges for normal operation

### 1.5 Terminology

| Term | Definition |
|------|------------|
| **Connector** | A self-contained binary implementing the FCP interface |
| **Connector Instance** | A running connector process bound to exactly one zone |
| **Zone** | A security boundary defining trust level and capabilities |
| **Capability** | A specific permission granted to a connector |
| **Manifest** | Embedded metadata describing connector properties |
| **Hub/Gateway** | The Flywheel component orchestrating connectors |
| **Principal** | An identity (user, agent, or service) making requests |
| **Ingress** | External input entering the Hub (messages, webhooks, polls) |
| **Egress** | Outbound action from the Hub/connector to an external service |
| **Operation** | A named connector function (e.g., `gmail.search`) |
| **Resource URI** | Canonical identifier for connector resources (e.g., `fcp://...`) |
| **Cursor** | Opaque position token for event stream replay/resume |
| **Provenance** | Metadata describing the causal origin of a request |
| **Taint** | A label indicating origin from a less-trusted zone |
| **Elevation** | Explicit approval to cross trust boundaries |

### 1.6 Normative Language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as described in RFC 2119.

---

## 2. Problem Statement

### 2.1 The Commingled Access Failure

The core failure mode looks like:

```
Public Input (Discord) ──► Agent Context ──► Gmail Capability (Catastrophe)
```

Even if each tool is "permissioned," the agent reasoning substrate can accidentally route untrusted instructions into privileged tools. This can happen via:

- Prompt injection
- Social engineering
- Parsing ambiguity
- Bugs in tool routers
- Model misbehavior under pressure

### 2.2 Why Prompts Are Not Security

"Don't read private emails" is trivially bypassed. Security must be **mechanical**—enforced by the protocol, type system, and binary boundaries—not rhetorical.

### 2.3 Goals

| Goal | Description |
|------|-------------|
| **Mechanical Isolation** | Connectors MUST be isolated processes with sandboxing |
| **Topology Over Discretion** | Zones MUST define allowed data/control flows |
| **Least Privilege by Construction** | Undeclared capabilities MUST NOT be usable |
| **Provenance-Aware Safety** | Requests MUST carry causal origin; tainted → privileged MUST be blocked |
| **Agent-Native Ergonomics** | Connectors MUST be introspectable with actionable recovery hints |
| **Operational Excellence** | Standard metrics, logging, tracing, audit, retries, circuit breakers |
| **Ecosystem Scalability** | Registry with signatures, attestations, SBOM, conformance tests |

---

## 3. Design Principles

### 3.1 Security is Mechanical, Not Rhetorical

FCP assumes adversarial inputs. Prompting alone MUST NOT be considered a security boundary. All security enforcement happens at the protocol level through:

1. **Type System**: Rust's ownership model prevents capability leaks
2. **Binary Boundaries**: Connectors cannot share memory
3. **Protocol Validation**: All messages validated against schemas
4. **Cryptographic Attestation**: Capabilities bound to signed tokens

### 3.2 Topology is the Real Permission System

Capabilities answer: "What can you do?"
Zones answer: "Where are you allowed to do it, and where can data go?"

Both are required. A capability without zone authorization is useless.

### 3.3 Provenance Prevents Cross-Domain Attacks

The Hub MUST track the causal origin of actions and enforce rules like:
- "Untrusted origin cannot cause privileged writes without explicit elevation."

### 3.4 Boring by Default, Optimized Where It Matters

We prefer:
- Standard process boundaries
- Explicit schemas
- Debuggable transports

...and add performance optimizations (binary encoding, zero-copy) behind stable contracts.

### 3.5 Humans-in-the-Loop for High-Risk Edges

High-risk capabilities MUST be gated by either:
- Explicit policy allowlists
- Explicit human approval (interactive)
- Time-bounded elevation tokens

### 3.6 Performance Guarantees

| Metric | Target | Enforcement |
|--------|--------|-------------|
| Cold start | < 50ms | Binary preloading |
| Message latency | < 1ms | Zero-copy IPC |
| Memory overhead | < 10MB | Static allocation |
| CPU overhead | < 1% idle | Event-driven architecture |

### 3.7 Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64, aarch64 | Tier 1 |
| macOS | x86_64, aarch64 | Tier 1 |
| Windows | x86_64 | Tier 2 |
| FreeBSD | x86_64 | Tier 3 |

---

## 4. System Architecture

### 4.1 Hub and Spoke Model

```
                ┌─────────────────────────────────────┐
                │               HUB                   │
                │  ┌───────────────────────────────┐  │
                │  │  Policy Engine | Audit Log    │  │
                │  │  Zone Enforcer | Cap Minter   │  │
                │  │  Provenance Tracker | Router  │  │
                │  └───────────────────────────────┘  │
                └──────────┬─────────────┬────────────┘
                           │             │
              (isolated)   │             │   (isolated)
                           │             │
          ┌────────────────▼───┐     ┌───▼────────────────┐
          │   Connector A      │     │   Connector B      │
          │   (z:community)    │     │   (z:private)      │
          │   Discord Bot      │     │   Gmail/Calendar   │
          └────────┬───────────┘     └───────────┬────────┘
                   │                             │
             External Service              External Service
```

### 4.2 Component Responsibilities

**Hub (FCP Host / Gateway)** — A long-running daemon that acts as:

| Role | Responsibility |
|------|----------------|
| **Shepherd** | Spawns and supervises connectors (health checks, restarts, throttling) |
| **Airlock** | Routes all messages; enforces validation, zones, capabilities, provenance |
| **Keymaster** | Issues capability tokens; enforces approval requirements |
| **Auditor** | Records immutable audit events for sensitive operations |

**Connectors** — Isolated binaries implementing the FCP interface:

- Provide operations and events
- Maintain optional local state (encrypted, scoped)
- MUST NOT directly communicate with other connectors except through the Hub

**Registry** — Discovery, distribution, and provenance:

- Git-indexed manifests + signatures (transparent, reviewable)
- HTTP/CDN binaries (fast)
- Attestations + SBOM for supply-chain safety

**Vault / Secret Store** — Stores secrets, supports rotation, injects ephemeral credentials at runtime. The Hub process MUST delegate secret custody here (or connector-local encrypted storage) and MUST NOT persist raw secrets in its own config or database

**Approval Broker** — Human/policy approval for high-risk actions (UI, CLI, or policy engine)

### 4.3 Deployment Modes

FCP MUST support:
- **Local single-user**: Hub on workstation, connectors local
- **Server multi-project**: Hub in controlled environment; connectors per project/tenant

FCP MAY support:
- **Remote connectors**: Over TCP + mTLS for secure cross-host execution

### 4.4 Connector Archetypes

FCP recognizes a small set of data-flow archetypes. Connectors MAY declare one or more `archetypes` in their manifest; the Hub SHOULD use this to set sensible defaults (buffer sizes, backpressure, polling cadence).

| Archetype | Pattern | Examples | Default Expectations |
|----------|---------|----------|----------------------|
| **Request-Response** | Agent → Service → Agent | REST, GraphQL, gRPC unary | Idempotency keys for retries |
| **Streaming** | Service → Agent | WebSocket, SSE, log tail | `subscribe` + replay/resume |
| **Bidirectional** | Agent ↔ Service | Chat, collaborative tools | Ack + backpressure |
| **Polling** | Agent → Service (periodic) | IMAP, RSS, status checks | Explicit poll interval |
| **Webhook** | Service → Agent (push) | GitHub, Stripe | Signature verification |
| **Queue/Pub-Sub** | Agent ↔ Broker | Redis, NATS, Kafka | Cursor + consumer groups |
| **File/Blob** | Agent → Storage | S3, GCS, local FS | Resource URI scoping |
| **Database** | Agent → DB | Postgres, vector DBs | Query constraints + timeouts |
| **CLI/Process** | Agent → spawn | git, kubectl, terraform | Command normalization + guardrails |
| **Browser** | Agent → CDP → Browser | Automation, scraping | Session isolation + screenshots |

### 4.5 Layered Model (FCP-Pack / FCP-Core / FCP-Policy)

FCP is intentionally layered to keep distribution, runtime, and policy concerns separable:

- **FCP-Pack (Packaging & Trust)** — Manifests, signatures, SBOM, and registry metadata
- **FCP-Core (Runtime Protocol)** — Handshake, invoke, events, health, shutdown
- **FCP-Policy (Zones & Capabilities)** — Zone definitions, provenance/taint, approvals, and constraints

---

## 5. Security Model

### 5.1 Threat Model

FCP assumes the following adversaries:

| Threat | Mitigation |
|--------|------------|
| Prompt injection causing privileged tool use | Zones + provenance (taint) + approval gates |
| Malicious connector binary | Signatures + attestations + sandbox + least privilege |
| Compromised external service | Schema validation + taint propagation + output constraints |
| Data exfiltration | Zone egress rules + network allowlists + audit |
| Supply chain attacks | SBOM + reproducible builds + provenance chain |
| Abuse / DoS | Rate limits + circuit breakers + resource quotas |
| Accidental privilege mixing | Default deny + explicit zone configuration |

### 5.2 Security Invariants

These are **hard requirements** that FCP enforces mechanically:

1. **Single-Zone Binding**: A connector instance MUST bind to exactly one zone for its lifetime
2. **Default Deny**: If a capability is not explicitly granted to a zone, it MUST be impossible to invoke
3. **No Cross-Connector Calling**: Connectors MUST NOT call other connectors directly; all composition happens through the Hub
4. **No Credential Custody by Hub Process**: The Hub process MUST NOT persist raw OAuth tokens, API keys, or provider secrets. Secrets MUST be stored in a dedicated secret store or connector-local encrypted storage, and only ephemeral credentials may be injected at runtime
5. **Strong Provenance on Ingress**: Every ingress event MUST include principal identity and origin attributes
6. **Auditable Everything**: Every operation invocation MUST produce auditable records with correlation IDs

### 5.3 Minimum Isolation Guarantees (All Platforms)

The Hub MUST guarantee:
- No shared memory between connectors
- Connector filesystem access scoped to connector-owned directories
- Network access is default-deny and capability-driven
- Secrets are never written to logs or config files

Stronger isolation SHOULD be used when available:

| Platform | Mechanisms |
|----------|------------|
| Linux | namespaces + seccomp + landlock + cgroups |
| macOS | sandbox profiles (seatbelt) + hardened runtime |
| Windows | job objects + restricted tokens + AppContainer |

### 5.4 Principal Hierarchy

```
OWNER (Root Trust)
  │
  ├── ADMINISTRATOR
  │     │
  │     ├── SERVICE_ACCOUNT
  │     │     │
  │     │     └── CONNECTOR
  │     │
  │     └── AGENT
  │           │
  │           └── SUB_AGENT
  │
  └── EXTERNAL_USER
        │
        ├── AUTHENTICATED_USER
        │
        └── ANONYMOUS_USER
```

### 5.5 Sandbox Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      HOST SYSTEM                               │
├────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                   HUB PROCESS                             │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │ │
│  │  │ Supervisor  │  │  IPC Hub    │  │ Capability  │       │ │
│  │  │             │  │             │  │  Verifier   │       │ │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │ │
│  └─────────┼────────────────┼────────────────┼──────────────┘ │
│            │                │                │                 │
│  ┌─────────▼────────────────▼────────────────▼──────────────┐ │
│  │                   SANDBOX BOUNDARY                        │ │
│  │  ┌────────────────────────────────────────────────────┐  │ │
│  │  │              CONNECTOR SANDBOX                      │  │ │
│  │  │  ┌──────────────────────────────────────────────┐  │  │ │
│  │  │  │  Filesystem: /fcp/<connector>/               │  │  │ │
│  │  │  │    ├── config/   (read-only)                 │  │  │ │
│  │  │  │    ├── data/     (read-write, encrypted)     │  │  │ │
│  │  │  │    ├── cache/    (read-write, ephemeral)     │  │  │ │
│  │  │  │    └── tmp/      (read-write, tmpfs)         │  │  │ │
│  │  │  └──────────────────────────────────────────────┘  │  │ │
│  │  │  ┌──────────────────────────────────────────────┐  │  │ │
│  │  │  │  Network: Filtered by capability             │  │  │ │
│  │  │  │    - Allowed: api.telegram.org:443           │  │  │ │
│  │  │  │    - Denied: * (default)                     │  │  │ │
│  │  │  └──────────────────────────────────────────────┘  │  │ │
│  │  │  ┌──────────────────────────────────────────────┐  │  │ │
│  │  │  │  IPC: Unix socket only                       │  │  │ │
│  │  │  │    /fcp/ipc/<connector>.sock                 │  │  │ │
│  │  │  └──────────────────────────────────────────────┘  │  │ │
│  │  └────────────────────────────────────────────────────┘  │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

---

## 6. Zone Architecture

### 6.1 Zone Definition

A **Zone** is a security boundary that defines:

1. What principals can access resources within it
2. What capabilities are available within it
3. What connectors can operate within it
4. How data flows in and out of it

Zones are **capability universes**. If the Gmail-read capability does not exist in a zone, it cannot be invoked—no matter what an agent says, no matter what prompt injection occurs.

### 6.2 Standard Zone Hierarchy

| Zone ID | Trust Level | Description |
|---------|-------------|-------------|
| `z:owner` | 100 | Root trust / owner console |
| `z:private` | 90 | Personal email, calendar, files |
| `z:work` | 70 | Work services, internal systems |
| `z:project:<name>` | 60 | Per-project isolation |
| `z:community` | 30 | Semi-trusted communities (Discord servers) |
| `z:public` | 10 | Public/untrusted inputs |

```
┌─────────────────────────────────────────────────────────────────┐
│                        ZONE HIERARCHY                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    OWNER ZONE (z:owner)                  │   │
│  │  Trust: 100 | Full access to everything                  │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │              PRIVATE ZONE (z:private)              │  │   │
│  │  │  Trust: 90 | Personal data, email, calendar        │  │   │
│  │  │  ┌─────────────────────────────────────────────┐  │  │   │
│  │  │  │           WORK ZONE (z:work)                │  │  │   │
│  │  │  │  Trust: 70 | Work-related services          │  │  │   │
│  │  │  │  ┌───────────────────────────────────────┐  │  │  │   │
│  │  │  │  │     PROJECT ZONE (z:project:<name>)   │  │  │  │   │
│  │  │  │  │  Trust: 60 | Per-project isolation    │  │  │  │   │
│  │  │  │  └───────────────────────────────────────┘  │  │  │   │
│  │  │  └─────────────────────────────────────────────┘  │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │            COMMUNITY ZONE (z:community)            │  │   │
│  │  │  Trust: 30 | Discord servers, public forums        │  │   │
│  │  │  ┌─────────────────────────────────────────────┐  │  │   │
│  │  │  │         PUBLIC ZONE (z:public)              │  │  │   │
│  │  │  │  Trust: 10 | Anonymous/untrusted access     │  │  │   │
│  │  │  └─────────────────────────────────────────────┘  │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.3 Zone Configuration

```rust
/// Zone configuration
pub struct ZoneConfig {
    /// Unique zone identifier
    pub id: ZoneId,

    /// Human-readable name
    pub name: String,

    /// Trust level (0-100)
    pub trust_level: u8,

    /// Optional trust grade (named default profile)
    pub trust_grade: Option<TrustGrade>, // local_owner | trusted_remote | public | automation

    /// Parent zone (for hierarchical inheritance)
    pub parent: Option<ZoneId>,

    /// Allowed principals
    pub principals: PrincipalPolicy,

    /// Capability ceiling (max capabilities grantable)
    pub capability_ceiling: CapabilitySet,

    /// Connector allowlist
    pub allowed_connectors: ConnectorPolicy,

    /// Data flow policy
    pub data_flow: DataFlowPolicy,

    /// Audit policy
    pub audit: AuditPolicy,
}
```

Optional trust grades provide default policy presets:

| Grade | Meaning |
|-------|---------|
| `local_owner` | Local UI only (most permissive) |
| `trusted_remote` | Remote users after pairing/allowlisting |
| `public` | Untrusted internet; default-deny private data |
| `automation` | Webhook/schedule; no interactive surfaces by default |

### 6.4 Zone Policy Example: Discord Moderator Bot

```yaml
zone:
  id: "z:community:discord:flywheel-hub"
  name: "Flywheel Hub Discord"
  trust_level: 25

principals:
  allow:
    - type: "authenticated_user"
      source: "discord"
      guild_id: "1234567890"
  deny:
    - type: "*"

capability_ceiling:
  allow:
    - "discord.read_messages"
    - "discord.send_messages"
    - "discord.moderate"
    - "flywheel.query_docs"
    - "web.search"
  deny:
    - "email.*"
    - "calendar.*"
    - "files.*"
    - "messaging.private.*"
    - "system.*"

data_flow:
  inbound:
    - source: "discord:1234567890"
      allowed: true
  outbound:
    - destination: "discord:1234567890"
      allowed: true
    - destination: "*"
      allowed: false
```

### 6.5 Ingress Bindings

Ingress bindings map external surfaces to zones. **Every ingress event MUST reference a binding**, which defines how principals are derived and what trust defaults apply.

Required fields:
- Connector instance id
- Selector(s) (guild/channel/chat/webhook id)
- Principal extraction rules
- Default trust policy (paired/allowlist/open)

Trust levels SHOULD use a shared vocabulary:

| Level | Meaning |
|-------|---------|
| `owner` | Root trust |
| `admin` | Elevated but not root |
| `paired` | Explicitly approved external user |
| `untrusted` | Authenticated but not approved |
| `anonymous` | Unauthenticated |
| `blocked` | Explicitly denied |

Example binding:

```yaml
ingress_binding:
  id: "discord:flywheel-hub"
  connector_instance: "inst_discord_public"
  selector:
    guild_id: "1234567890"
    channel_ids: ["123", "456"]
  principal:
    kind: "discord"
    trust_default: "untrusted"
    allowlist: ["user_987", "user_654"]
```

For public-capable connectors, principals SHOULD default to `untrusted` unless explicitly paired/allowlisted.

### 6.6 Zone Isolation Guarantees

| Property | Guarantee |
|----------|-----------|
| Memory | No shared memory between zones |
| Filesystem | Separate encrypted storage per zone |
| Network | Zone-specific network policy (namespaces/firewalls where available) |
| Credentials | Credentials bound to source zone |
| Data | Data tagged with origin zone, enforced on egress |

### 6.7 Principal and Zone Mapping

Principal trust does not override zone policy. A principal MAY only act within a zone if:
- The zone explicitly allows that principal (or principal class)
- The capability ceiling grants the required operation

By default, external principals MUST NOT access high-trust zones (`z:private`, `z:owner`) unless explicitly configured.

### 6.8 Zone Transition Protocol

When data or control crosses zone boundaries, the Hub MUST enforce an explicit transition check:

1. **Source capability** — Is the requested capability granted in the source zone?
2. **Target allowlist** — Does the target zone allow this capability and principal class?
3. **Data flow policy** — Does the source zone allow outbound flow to the target zone?
4. **Provenance/taint** — If tainted, require elevation or deny
5. **Audit + token** — Record audit event and mint a scoped capability token (if approved)

If any check fails, the Hub MUST deny the transition and return a structured error (`FCP-4001` or `FCP-4002`).

### 6.9 Messaging Connector Requirements

Messaging connectors MUST:
- Provide stable principal identity (user id)
- Provide channel/thread/chat identifiers
- Enforce allowlist/pairing policy **or** emit sufficient metadata for the Hub to enforce it
- Support reply routing so outbound replies are constrained to the originating context

### 6.10 Zone Policy Format (FZPF)

The Hub MUST support a deterministic, auditable policy file format for zones and flow rules. The **Flywheel Zone Policy Format (FZPF)** is the canonical format.

**Policy header (required):**
- `format = "fzpf"`
- `schema_version = "0.1"`
- `default_deny = true|false` (recommended `true`)

**Zones (required):** each zone MAY define:
- `principals_allow` / `principals_deny`
- `connectors_allow` / `connectors_deny`
- `cap_allow` / `cap_deny`

**Flows (optional):** ordered rules for cross-zone data movement:
- `from`, `to` (pattern strings)
- `kind` one of `ingress`, `egress`, `both`
- `allow` boolean
- `transform` optional identifier (e.g., `redact_secrets`)
- `audit` optional (default true)

**Taint rules (optional):** ordered rules for provenance-aware gating:
- `min_taint`: `Untainted` | `Tainted` | `HighlyTainted`
- `min_risk`: `low` | `medium` | `high` | `critical`
- filters: origin/target zone patterns, capability patterns
- `action`: `deny` | `require_elevation` | `require_approval`

**Pattern matching:** anchored glob with `*` wildcard, case-sensitive. `*` matches zero or more characters, including `:` and `.`.

**Determinism rules:**
- Deny overrides allow.
- Rule order matters (first match wins) for `flows` and `taint_rules`.

**Brief example (FZPF v0.1):**

```toml
[policy]
format = "fzpf"
schema_version = "0.1"
default_deny = true

[defaults.taint]
require_elevation_min_risk = "medium"
require_interactive_approval_min_risk = "high"

[[zones]]
id = "z:public"
trust_level = 10
principals_allow = ["*"]
connectors_allow = ["fcp.discord", "fcp.web"]
cap_allow = ["discord.*", "web.*"]
cap_deny  = ["email.*", "calendar.*", "files.*"]

[[zones]]
id = "z:private"
trust_level = 90
principals_allow = ["p:owner:*", "p:agent:*"]
connectors_allow = ["fcp.gmail"]
cap_allow = ["email.*"]
cap_deny  = ["system.exec"]

[[flows]]
from = "z:private"
to = "z:public"
kind = "egress"
allow = true
transform = "redact_secrets"
audit = true

[[taint_rules]]
name = "public_to_private_email_requires_elevation"
min_taint = "Tainted"
min_risk = "medium"
when_origin_trust_lt_target = true
origin_zone_patterns = ["z:public", "z:community"]
target_zone_patterns = ["z:private"]
capability_patterns = ["email.*"]
action = { type = "require_elevation", ttl_seconds = 300 }
```

Appendix H specifies the evaluation algorithms.

---

## 7. Provenance and Taint Tracking

### 7.1 The Waterfall Problem

Without provenance tracking, this attack succeeds:

1. Public Discord user sends: "Delete my important emails"
2. Agent receives message, has Gmail capability available
3. Agent calls `gmail.delete` without understanding the request origin
4. Catastrophic data loss

### 7.2 Provenance Envelope

Every request handled by the Hub MUST carry a provenance envelope:

```rust
pub struct Provenance {
    /// Origin zone of the triggering input
    pub origin_zone: ZoneId,

    /// Monotonic chain of causal steps
    pub chain: Vec<ProvenanceStep>,

    /// Highest taint severity observed in the chain
    pub taint: TaintLevel,
}

pub struct ProvenanceStep {
    pub timestamp_ms: u64,
    pub zone: ZoneId,
    pub actor: ActorId,       // agent/user/connector id
    pub action: String,       // e.g., "discord.message", "tool.invoke"
    pub resource: String,     // resource URI or capability identifier
}

pub enum TaintLevel {
    Untainted,      // Trusted source only
    Tainted,        // Untrusted input present
    HighlyTainted,  // Direct untrusted instruction
}
```

Ingress events, invoke requests, and connector responses MUST carry a `correlation_id` and SHOULD include `resource_uris` when applicable to enable end-to-end audit chains.

Connectors MUST NOT be able to forge or strip provenance; only the Hub may set/modify it.

### 7.3 Topology Rules (The "Waterfall")

FCP distinguishes **data ascension** and **command descent**:

#### Data Ascension (Upstream)

Data from lower-trust zones MAY flow "up" into higher-trust reasoning contexts, but MUST be tagged with provenance and taint:

```
z:public → z:work     (allowed, tainted)
z:public → z:private  (allowed, tainted)
```

#### Command Descent (Downstream)

Commands that would act in a higher-trust zone MUST be blocked if they are causally derived from tainted inputs, unless explicitly elevated:

```
tainted(z:public) ─X→ gmail.send (z:private)
tainted(z:public) ─X→ calendar.delete (z:private)
```

### 7.4 Elevation Mechanism

To permit a tainted-origin action in a high-trust zone, the Hub MUST require explicit **Elevation**:

| Elevation Method | Description |
|------------------|-------------|
| Human approval | "Approve sending this email?" |
| Policy allowlist | "This webhook may create GitHub issues, nothing else" |
| Elevation token | Time-bounded, single-use, scoped |

Elevation MUST be:
- Explicit
- Auditable
- Scoped (capability + zone + constraints)
- Time-bounded

### 7.5 No-Commingling Guarantee (Messaging Safety)

For any public-facing messaging connector, it MUST be mechanically impossible for an untrusted inbound message to access private tools unless explicitly elevated. The Hub MUST enforce this by:

1. Binding the ingress event to a zone (via ingress bindings)
2. Spawning the agent session in that zone
3. Minting capability tokens only for capabilities allowed in that zone
4. Blocking tainted-origin commands that target higher-trust zones unless explicitly elevated

This is a **protocol-level** guarantee, not a prompt-based policy.

### 7.6 Messaging Connector Requirements

Messaging connectors MUST:
- Provide stable principal identity (user ID) and trust level
- Provide channel/thread/chat identifiers on ingress
- Support allowlist/pairing policy enforcement **or** emit enough metadata for the Hub to enforce it
- Support reply routing so outbound replies are constrained to the originating context

### 7.7 Example: Public Discord → Gmail Delete (Blocked)

1. Input enters Hub in `z:public` → provenance tainted
2. Agent decides to call `gmail.delete`
3. Hub sees: origin `z:public` + high-risk capability in `z:private` → **BLOCKED**
4. Hub returns structured error `FCP_TAINT_VIOLATION` with remediation:
   - "This action requires elevation. Ask owner to approve or move workflow to a trusted zone."

---

## 8. Capability System

### 8.1 Capability Taxonomy

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

### 8.2 Capability Definition

```rust
pub struct Capability {
    /// Capability identifier (e.g., "telegram.send_message")
    pub id: CapabilityId,

    /// Human-readable name
    pub name: String,

    /// Detailed description
    pub description: String,

    /// Risk level
    pub risk_level: RiskLevel,  // low | medium | high | critical

    /// Safety tier (enforcement)
    pub safety_tier: SafetyTier,  // safe | risky | dangerous | forbidden

    /// Parent capability (hierarchy)
    pub parent: Option<CapabilityId>,

    /// Implied capabilities (auto-granted)
    pub implies: Vec<CapabilityId>,

    /// Mutually exclusive capabilities
    pub conflicts_with: Vec<CapabilityId>,

    /// Idempotency expectation
    pub idempotency: IdempotencyClass,  // none | best_effort | strict

    /// Rate limit
    pub rate_limit: Option<RateLimit>,

    /// Requires human approval
    pub requires_approval: ApprovalMode,  // none | policy | interactive | elevation_token

    /// Audit level when used
    pub audit_level: AuditLevel,

    /// Agent documentation
    pub agent_hint: AgentHint,
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

Optional `parent`/`implies`/`conflicts_with` fields define capability relationships. The Hub SHOULD expand implied capabilities during grant. The Hub MUST reject any policy or manifest that attempts to grant conflicting capabilities in the same zone.

### 8.3 Safety Tiers

Safety tiers are the **enforcement** axis for approvals:

| Tier | Meaning | Default Approval |
|------|---------|------------------|
| `safe` | Read-only or non-sensitive | none |
| `risky` | Private data exposure or public posting | policy or warning |
| `dangerous` | Destructive or high-blast actions | interactive approval |
| `forbidden` | Never allowed | hard deny |

`risk_level` is for UX and prioritization; `safety_tier` is normative. If they disagree, enforcement MUST follow `safety_tier`.

Idempotency classes:
- `none`: duplicates may cause repeated side effects
- `best_effort`: connector attempts dedupe within a short window
- `strict`: connector MUST enforce dedupe using `idempotency_key`

Dangerous operations MUST pass an explicit approval workflow. For CLI-related connectors, destructive commands SHOULD be guarded by a command-safety layer and operations MUST provide:
- normalized command representation
- parsed tokens
- execution context (cwd, env keys, not values)

### 8.4 Capability Token (FCT)

Every operation invocation requires an FCT minted by the Hub:

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
```

```rust
pub struct CapabilityGrant {
    /// Granted capability
    pub capability: CapabilityId,
    /// Optional operation-level restriction
    pub operation: Option<OperationId>,
}
```

If `operation` is present, the token is valid only for that operation. If absent, any operation bound to the granted capability is allowed.

Default token TTL is 300 seconds (5 minutes) unless policy overrides it.

### 8.5 Capability Constraints and Resource Scopes

Constraints are how FCP prevents cross-domain data leaks even within a granted capability:

Resource URIs MUST use the canonical format:

```
fcp://<connector_id>/<resource_type>/<resource_id>
```

```rust
pub struct CapabilityConstraints {
    /// Allowed resource URI prefixes (allowlist)
    pub resource_allow: Vec<String>,
    /// Explicitly denied resource URI prefixes
    pub resource_deny: Vec<String>,
    /// Max calls allowed within token lifetime
    pub max_calls: Option<u32>,
    /// Max bytes allowed (request + response)
    pub max_bytes: Option<u64>,
    /// Optional idempotency key scope
    pub idempotency_key: Option<String>,
}
```

If a capability targets resources, the connector MUST enforce `resource_allow`/`resource_deny` on every invocation.

### 8.6 Capability Verification Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Registry   │────▶│     Hub      │────▶│  Connector   │
│  (Root CA)   │     │  (Issuer)    │     │  (Subject)   │
└──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │
       │   Sign manifest    │                    │
       │───────────────────▶│                    │
       │                    │   Issue token      │
       │                    │───────────────────▶│
       │                    │                    │
       │              ┌─────▼─────┐              │
       │              │  Verify:  │              │
       │              │  1. Sig   │              │
       │              │  2. Caps  │              │
       │              │  3. Zones │              │
       │              │  4. Taint │              │
       │              └───────────┘              │
```

---

## 9. Wire Protocol

FCP defines a transport-agnostic message model with two interoperable modes:

### 9.1 Protocol Modes

| Mode | Encoding | Use Case |
|------|----------|----------|
| **FCP Framed (Production)** | CBOR + length-prefixed frames | High performance, streaming |
| **JSON-RPC Compat (Debug)** | JSON-RPC 2.0 over stdio | Debugging, tooling |

JSON-RPC compat mode MUST use LSP-style framing over stdio:

```
Content-Length: <n>\r\n
Content-Type: application/json\r\n
\r\n
<n bytes of JSON>
```

The JSON-RPC payload SHOULD include a `meta` object with `correlation_id`, `zone_id`, `principal`, and `deadline_ms`.

### 9.2 Transport Options

Every connector MUST implement at least one transport and MUST support stdio (LSP framing) in JSON-RPC compat mode for local debugging and tooling. The Hub MUST support:
- **stdio**: Connector launched as child process; communication via pipes
- **Unix domain sockets**: For local, high-throughput, long-lived connectors

The Hub MAY support:
- **TCP with mTLS**: For remote connectors
- **HTTP/2 or gRPC**: For heavy streaming use cases

Connectors MUST NOT expose unauthenticated network listeners by default.

mTLS requirements (if enabled):
- Hub and connector MUST present client certificates
- Trust roots MUST be explicitly configured (registry CA or admin-provided)
- Certificates SHOULD be short-lived and rotated automatically
- Self-signed certs MAY be allowed only in explicit dev mode

### 9.3 Frame Format (FCP1)

```
┌────────────────────────────────────────────────────────────────┐
│                      FCP FRAME FORMAT                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Bytes 0-3:   Magic (0x46 0x43 0x50 0x31 = "FCP1")            │
│  Bytes 4-5:   Version (u16 LE)                                 │
│  Bytes 6-7:   Flags (u16 LE)                                   │
│  Bytes 8-11:  Sequence (u32 LE)                                │
│  Bytes 12-15: Payload Length (u32 LE)                          │
│  Bytes 16-23: Timestamp (u64 LE, nanoseconds since epoch)      │
│  Bytes 24-39: Correlation ID (UUID)                            │
│  Bytes 40-(40+len-1): Payload (CBOR or JSON)                   │
│  Bytes N..N+7: Checksum (XXH3-64, 8 bytes)                     │
│                                                                │
│  Fixed header: 40 bytes                                        │
│  Total overhead: 48 bytes including checksum (40 + 8)          │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 9.4 Frame Flags

```rust
bitflags! {
    pub struct FrameFlags: u16 {
        const REQUIRES_ACK  = 0b0000_0001;  // Message requires acknowledgment
        const COMPRESSED    = 0b0000_0010;  // Compressed (zstd)
        const ENCRYPTED     = 0b0000_0100;  // Encrypted (ChaCha20-Poly1305)
        const RESPONSE      = 0b0000_1000;  // Response to a request
        const ERROR         = 0b0001_0000;  // Error response
        const STREAMING     = 0b0010_0000;  // Part of a stream
        const STREAM_END    = 0b0100_0000;  // Final frame in stream
        const HAS_CAP_TOKEN = 0b1000_0000;  // Contains capability token
        const ZONE_CROSSING = 0b0001_0000_0000;  // Result of a zone transition
        const PRIORITY      = 0b0010_0000_0000;  // High-priority frame (skip queue)
    }
}
```

`ZONE_CROSSING` MUST be set by the Hub when a request or response is routed across zones (including elevation). `PRIORITY` MAY be used for shutdown, health, or approval-critical frames; receivers MAY bypass normal queues but MUST preserve ordering within a stream.

### 9.5 Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `handshake` | Hub → Connector | Establish connection, negotiate protocol |
| `handshake_ack` | Connector → Hub | Confirm connection, report capabilities |
| `introspect` | Hub → Connector | Query available operations |
| `configure` | Hub → Connector | Apply configuration |
| `invoke` | Hub → Connector | Execute operation |
| `response` | Connector → Hub | Operation result |
| `subscribe` | Hub → Connector | Subscribe to event streams |
| `unsubscribe` | Hub → Connector | Unsubscribe from event streams |
| `event` | Connector → Hub | Asynchronous event |
| `ack` | Hub → Connector | Acknowledge event receipt |
| `health` | Hub ↔ Connector | Health check |
| `shutdown` | Hub → Connector | Graceful shutdown |
| `shutdown_ack` | Connector → Hub | Shutdown accepted / drained |
| `error` | Either | Error with recovery hints |

### 9.6 Standard Methods (Required Set)

Connectors MUST implement the following baseline methods:

| Method | Purpose |
|--------|---------|
| `handshake` | Bind instance to zone, negotiate protocol |
| `introspect` | Return operations, events, resource types, auth/event caps |
| `configure` | Apply validated configuration |
| `invoke` | Execute an operation |
| `health` | Report readiness and dependency status |
| `subscribe` / `unsubscribe` | Event stream control (if streaming) |
| `shutdown` | Graceful termination |

`introspect` MUST include:
- Operations (id, schemas, safety tier, idempotency, AI hints)
- Event types emitted (schemas)
- Resource types supported
- `auth_caps` and `event_caps`

In JSON-RPC compat mode, the methods MUST be exposed as `fcp.handshake`, `fcp.introspect`, `fcp.configure`, `fcp.invoke`, `fcp.subscribe`, `fcp.unsubscribe`, `fcp.health`, and `fcp.shutdown`.
Events MUST be emitted as JSON-RPC notifications with method `fcp.event` and `params` containing the event envelope. Acknowledgments MUST be sent with method `fcp.ack` and MUST include `topic` + `seq` (and `cursor` if present).

### 9.7 Invoke Request/Response Shape

Invoke requests MUST be structured and capability-bound:

```json
{
  "type": "invoke",
  "id": "req_123",
  "operation": "gmail.search",
  "input": { "query": "from:alerts@example.com" },
  "capability_token": "<FCT>",
  "context": { "locale": "en-US" },
  "idempotency_key": "idem_abc123"
}
```

Invoke responses MUST include structured outputs and SHOULD reference resources:

```json
{
  "type": "response",
  "id": "req_123",
  "result": { "messages": [/* ... */] },
  "resource_uris": ["fcp://fcp.gmail/message/17c9a..."],
  "next_cursor": "cursor_01JH..."
}
```

Connector MUST validate:
- Token signature and expiry
- Token `iss` zone matches connector instance zone
- Token `instance` matches connector instance (if present)
- Token grants include the requested operation
- Token constraints (resource allow/deny, rate limits, idempotency)

If `idempotency` is `strict`, the connector MUST treat `(operation, resource, idempotency_key)` as a unique request and return the same result on retries within the token lifetime.

### 9.8 Event Model

Events MUST use a consistent envelope with replay/resume support:

```json
{
  "type": "event",
  "topic": "connector.message.inbound",
  "timestamp": "2026-01-11T12:34:56.789Z",
  "seq": 39120,
  "cursor": "cursor_01JH...",
  "requires_ack": true,
  "ack_deadline_ms": 5000,
  "data": {
    "connector_id": "fcp.telegram",
    "instance_id": "inst_01JH...",
    "zone_id": "z:private",
    "principal": { "kind": "telegram", "id": "tg_user_123", "trust": "paired" },
    "payload": { "chat_id": "tg_chat_456", "text": "hello" }
  }
}
```

Connectors SHOULD use standard event classes such as:
- `connector.message.inbound` / `connector.message.outbound`
- `connector.file.changed` / `connector.sync.completed`
- `connector.auth.state_changed` / `connector.auth.action_required`

### 9.9 Streaming, Replay, and Backpressure

- Each `topic` MUST have a monotonically increasing `seq`
- Connectors MUST maintain a per-topic replay buffer (default minimum: 10,000 events or 10 minutes)
- `subscribe` MAY include `since` (cursor) to request replay
- If replay is not possible, connector MUST emit `connector.stream.reset` with a best-effort snapshot and a new cursor
- `subscribe` MAY specify `max_events_per_sec`, `batch_ms`, and `window_size`; connectors MUST honor backpressure
- If buffers fill, connectors MUST apply an explicit policy: pause, drop non-critical events (with audit), or emit `connector.stream.reset`
- Critical events MUST NOT be silently dropped; if loss is unavoidable, emit a drop audit event or `connector.stream.reset`
- If `requires_ack` is true, the Hub MUST send `ack` before `ack_deadline_ms` or the connector MAY retry or drop according to policy

### 9.10 Handshake Protocol

```
Hub                                        Connector
 │                                             │
 │  1. TCP Connect / Spawn                     │
 │────────────────────────────────────────────▶│
 │                                             │
 │  2. Handshake Request                       │
 │  {                                          │
 │    protocol_version: "1.0.0",               │
 │    zone: "z:community",                     │
 │    zone_dir: "/var/lib/fcp/zones/z:community",│
 │    capabilities_requested: [...],           │
 │    nonce: <random 32 bytes>                 │
 │  }                                          │
 │────────────────────────────────────────────▶│
 │                                             │
 │  3. Handshake Response                      │
 │  {                                          │
 │    status: "accepted",                      │
 │    capabilities_granted: [...],             │
 │    session_id: <uuid>,                      │
 │    manifest_hash: "sha256:...",             │
 │    nonce: <echoed 32 bytes>                 │
 │  }                                          │
 │◀────────────────────────────────────────────│
 │                                             │
 │  4. Channel Established                     │
 │◀───────────────────────────────────────────▶│
 │                                             │
 │  5. Heartbeat Loop (every 30s)              │
 │◀───────────────────────────────────────────▶│
```

The connector MUST echo the nonce in `handshake_ack` to bind the response and prevent replay. The Hub MUST reject mismatched or reused nonces.

Handshake SHOULD include:
- `host_public_key` for capability token verification
- `transport_caps` (compression, max frame size)
- `requested_instance_id` (optional)
- `zone_dir` (required for connectors that persist state)
- `host` metadata (name/version/build)

Handshake response SHOULD include:
- `event_caps` (replay support, buffer size)
- `auth_caps` (supported auth methods)
- `op_catalog_hash` (integrity hash of operations list)

Connector MUST reject handshake if:
- Protocol version is incompatible
- `host_public_key` is missing while capability verification is required
- A persistent-storage connector is missing a valid `zone_dir`

### 9.11 Error Response Format

Errors MUST be structured and SHOULD include agent-usable remediation:

```json
{
  "type": "error",
  "id": "req_123",
  "error": {
    "code": "FCP_TAINT_VIOLATION",
    "message": "Tainted origin cannot invoke gmail.send in z:private without elevation.",
    "retryable": false,
    "details": {
      "origin_zone": "z:public",
      "target_zone": "z:private",
      "capability": "gmail.send"
    },
    "ai_recovery_hint": "Ask the owner to approve this action, or move the workflow to a trusted zone."
  }
}
```

### 9.12 Shutdown Sequence

`shutdown` requests MUST include a deadline and drain policy:

```json
{
  "type": "shutdown",
  "deadline_ms": 10000,
  "drain": true
}
```

Connectors SHOULD:
- Stop accepting new invokes
- Finish in-flight requests within `deadline_ms`
- Flush pending events if `drain` is true
- Reply with `shutdown_ack` when safe to terminate

If `shutdown_ack` is not received before the deadline, the Hub MAY force-kill the process.

### 9.13 Health Check Protocol

Health checks are Hub-initiated unless the connector advertises push health.

```json
{
  "type": "health",
  "status": "ready",
  "uptime_ms": 123456,
  "load": { "cpu": 0.05, "mem_mb": 42 },
  "details": { "last_error": null },
  "rate_limit": { "remaining": 120, "reset_ms": 60000 }
}
```

Valid status values: `starting`, `ready`, `degraded`, `error`.

The Hub MUST treat missing/late responses as unhealthy according to `timeout_ms` and `unhealthy_threshold`.

---

## 10. Connector Manifest

### 10.1 Manifest Requirements

Each connector MUST have a manifest that is:
- Machine-readable
- Cryptographically verifiable
- Extractable without executing connector logic (`--manifest` has no side effects)

Format: **TOML** for authoring, embedded binary section for runtime.

Connector distribution artifacts SHOULD include:

```
fcp.telegram/
  connector.fcp.toml
  bin/
    fcp-telegram_<os>_<arch>
  sbom/
    sbom.spdx.json
  signatures/
    bin.<target>.sha256
    bin.<target>.sig
    manifest.sig
```

### 10.2 Manifest Structure

```toml
[manifest]
format = "fcp-connector-manifest"
schema_version = "1.0"

[connector]
id = "fcp.telegram"
name = "Telegram Connector"
version = "2026.1.0"
description = "Secure Telegram Bot API integration"
authors = ["Flywheel Core Team <core@flywheel.dev>"]
license = "MIT"
repository = "https://github.com/flywheel/fcp-telegram"
documentation = "https://docs.flywheel.dev/connectors/telegram"
archetypes = ["bidirectional", "streaming"]

[connector.binaries.linux-x86_64]
url = "https://registry.flywheel.dev/v1/connectors/telegram/2026.1.0/linux-x86_64"
sha256 = "abc123..."
size = 4500000

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
forbidden = ["system.exec", "network.inbound", "filesystem.root"]

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
common_mistakes = ["Sending secrets", "Responding to tainted inputs with privileged actions"]

[provides.events.telegram_message_received]
description = "Emitted when a message is received"
topic = "telegram.message_received"
payload_schema = { type = "object" }

[event_caps]
streaming = true
replay = true
min_buffer_events = 10000
requires_ack = true

[auth_caps]
methods = ["bot_token"]

[config.schema]
type = "object"
required = ["bot_token"]

[config.schema.properties.bot_token]
type = "string"
secret = true

[config.schema.properties.allowed_chats]
type = "array"
items = { type = "integer" }
default = []

[resources]
types = ["telegram.chat", "telegram.message"]
max_memory_mb = 128
max_cpu_percent = 15
max_connections = 20
max_file_handles = 64

[health]
interval_ms = 30000
timeout_ms = 3000
unhealthy_threshold = 3

[telemetry]
metrics_enabled = true
metrics_prefix = "fcp_telegram_"
log_level = "info"
trace_sampling = 0.01

[automation]
setup_recipe = "recipe://telegram/setup"
teardown_recipe = "recipe://telegram/teardown"
requires_approval = true

[signatures]
publisher_ed25519 = "base64:..."
registry_ed25519 = "base64:..."
attestation = "attestation://fcp.telegram/2026.1.0"
sbom = "sbom://fcp.telegram/2026.1.0"
```

Operations MUST declare `capability`, `risk_level`, `safety_tier`, and `idempotency`. Enforcement uses `safety_tier`; `risk_level` is for UI/triage.

### 10.3 Event/Auth Capabilities and Resource Types

If a connector emits events, it MUST declare `event_caps` and support replay/ack behavior accordingly. If a connector requires authentication, it MUST declare `auth_caps` and implement the provisioning interface (Section 11.4).

If a connector exposes resources, it SHOULD declare `resources.types` and return canonical `resource_uris` in responses.

`auth_caps.methods` MAY include `device_code`, `browser_oauth`, `api_key`, or connector-specific flows.

### 10.4 `--manifest` Contract

Running:
```bash
./fcp-telegram --manifest --format toml
```

MUST print the manifest without performing network calls.

### 10.5 Rate Limit Format

`rate_limit` MAY be expressed as a string or structured object.

String form:
- `"<N>/<unit>"` where unit is `s`, `sec`, `min`, `h`, or `day`

Example:
```toml
rate_limit = "60/min"
```

Object form:
```toml
rate_limit = { max = 60, per_ms = 60000, burst = 10, scope = "per_principal" }
```

Valid `scope` values: `per_connector`, `per_zone`, `per_principal`. If unspecified, the default is `per_connector`.

### 10.6 Telemetry Configuration

Connectors MAY declare a telemetry block to guide metrics and log behavior:

```toml
[telemetry]
metrics_enabled = true
metrics_prefix = "fcp_telegram_"
log_level = "info"
trace_sampling = 0.01
```

`trace_sampling` is a value in `[0.0, 1.0]`. Telemetry settings MUST NOT disable required audit events or secret redaction.

### 10.7 Manifest Embedding

Manifests MUST be extractable without executing connector logic. Acceptable methods:
- Embedded manifest section in the binary
- `--manifest` mode that performs no network calls and no side effects

If embedded, the manifest SHOULD be stored in a named section:
- ELF: `.fcp_manifest`
- Mach-O: `__FCP,__manifest`
- PE: `.fcpmanifest`

Embedded manifests SHOULD use a deterministic header to allow extraction without execution:
- Magic bytes: `FCP\0\1\0`
- Length: `u32` little-endian (compressed payload size)
- Payload: zstd-compressed CBOR (preferred) or MessagePack (acceptable)

The Hub MUST be able to extract the manifest by scanning for the magic bytes, reading the length, decompressing, and verifying the manifest signature. No connector code may execute during extraction.

### 10.8 Manifest Versioning Strategy

`schema_version` follows semantic versioning:
- Unknown **major** versions: Hub MUST reject
- Unknown **minor** versions: Hub SHOULD warn and MAY attempt best-effort parsing
- Patch versions MUST be backward compatible

---

## 11. Automation Recipes

Connector setup is where systems lose users. FCP makes setup a first-class, auditable workflow.

### 11.1 Recipe Model

A recipe is a deterministic step list executed by the Hub, not by the connector.

Recipe steps MUST be:
- Typed (no arbitrary shell)
- Parameterized via explicit inputs
- Capable of requiring approval per-step
- Auditable

### 11.2 Example Recipe

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
note = "Follow instructions to create the bot and obtain the token."

[[steps]]
type = "prompt_secret"
id = "bot_token"
message = "Paste the Telegram bot token"

[[steps]]
type = "validate"
input_from = "bot_token"
pattern = "^[0-9]+:[A-Za-z0-9_-]+$"
error_message = "Invalid Telegram bot token format"

[[steps]]
type = "store_secret"
key = "telegram.bot_token"
value_from = "bot_token"
scope = "connector:fcp.telegram"

[[steps]]
type = "test_connection"
operation = "telegram.get_me"
success_message = "Bot connected successfully!"
```

### 11.3 Recipe Security

Automation recipes MUST NOT:
- Execute arbitrary shell commands
- Exfiltrate secrets
- Write secrets into plaintext config files

The Hub MUST:
- Record audit events for recipe execution
- Require approvals for marked steps
- Store secrets only in Vault or connector-local encrypted storage

### 11.4 Provisioning Interface

Connectors that require authentication MUST expose a standard provisioning workflow:

| Operation | Purpose |
|-----------|---------|
| `fcp.provision.start` | Begin auth flow, return action required (device code, browser URL, API key prompt) |
| `fcp.provision.poll` | Check status for long-running auth flows |
| `fcp.provision.complete` | Finalize and store credentials |
| `fcp.provision.abort` | Cancel and clean up |

Provisioning MUST be automation-first:
- The Hub controls UI/UX and stores secrets
- Connectors receive only the credentials they need at runtime
- Secrets MUST NOT be written to plaintext config
- If full automation is impossible, connectors MUST guide users through the minimum manual steps, validate the result, and remain disabled until verified

### 11.5 Zone-Local Storage Rules

Connectors MUST treat `zone_dir` as their persistent root and MUST NOT write secrets outside it. Secrets SHOULD reside under `zone_dir/secrets/` with OS permissions enforced. Connectors SHOULD support credential fingerprinting (hash + timestamp) for audit/health reporting without exposing secret material.

---

## 12. Registry and Supply Chain

### 12.1 Registry Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    PRIMARY REGISTRY                        │
│                  registry.flywheel.dev                     │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Components:                                         │  │
│  │  ├── Git-backed manifest index (transparent, PRs)   │  │
│  │  ├── Binary storage (S3-compatible)                 │  │
│  │  ├── Signature verifier                             │  │
│  │  ├── Reproducible build attestor                    │  │
│  │  └── CDN (global edge distribution)                 │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
                            │
                            │ Sync
                            ▼
┌───────────────────────────────────────────────────────────┐
│                    MIRROR REGISTRIES                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Mirror    │  │   Mirror    │  │   Private   │        │
│  │   (EU)      │  │   (Asia)    │  │   Mirror    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└───────────────────────────────────────────────────────────┘
```

### 12.2 Verification Chain

The Hub MUST verify before execution:

1. Manifest signature (registry or trusted publisher)
2. Binary checksum matches manifest
3. Binary signature matches trusted key
4. Platform/arch match
5. Requested capabilities ⊆ zone ceilings and local policy

The Hub MUST refuse to execute unsigned or untrusted connectors unless an explicit development override is enabled with loud warnings.

### 12.3 Conformance Gating

Registry SHOULD require CI to pass:
- Build reproducibility (where feasible)
- Conformance tests against Hub harness
- SBOM generation
- Basic vulnerability scan

### 12.4 SBOM Format

SBOMs MUST be provided in one of:
- SPDX (JSON)
- CycloneDX (JSON)

Registries MAY require both for critical connectors.

---

## 13. Lifecycle Management

### 13.1 Connector States

```
DISCOVERED → VERIFIED → INSTALLED → CONFIGURED → ACTIVE
         ↘ rejected                          ↘ FAILED
                                              ↘ PAUSED
                                              ↘ STOPPED
```

### 13.2 State Transitions

| From | To | Trigger |
|------|-----|---------|
| DISCOVERED | VERIFIED | Signature verification passes |
| DISCOVERED | (rejected) | Signature verification fails |
| VERIFIED | INSTALLED | Download complete, checksum verified |
| INSTALLED | CONFIGURED | Config validated, secrets stored |
| CONFIGURED | ACTIVE | Handshake complete, health OK |
| ACTIVE | FAILED | Health checks fail, crash loop |
| ACTIVE | PAUSED | Manual pause or rate limit |
| ACTIVE | STOPPED | Graceful shutdown |
| FAILED | ACTIVE | Auto-recovery or manual restart |

### 13.3 Activation Requirements

On activation, Hub MUST:
1. Create sandbox (best available on platform)
2. Inject secrets ephemerally (memory/env; never on disk)
3. Negotiate handshake
4. Issue capability tokens
5. Start health checks and metrics collection

### 13.4 Updates and Rollback

Hub SHOULD support:
- Staged updates
- Automatic rollback on crash loops or health failures
- Explicit pinning to known-good versions

---

## 14. Agent Integration

### 14.1 Introspection is Mandatory

Agents MUST be able to query:
- Operations (id, schemas, risk levels)
- Approval requirements
- Rate limits
- Common errors + recovery hints

### 14.2 Standard Tool Invocation

Agents call `tool.invoke` with `{ operation, args }`.

The Hub MUST enforce:
1. Capability checks
2. Zone topology checks
3. Provenance/taint checks
4. Approval gates

### 14.3 MCP Integration

The Hub SHOULD map connector operations into MCP-compatible tools, including:
- Schemas
- Risk annotations
- Examples
- Rate limits

---

## 15. Observability and Audit

### 15.1 Metrics

The Hub MUST generate a `correlation_id` for every ingress chain and every operation invocation. Connectors MUST include that `correlation_id` in logs, events, and error responses.

Connectors and Hub MUST expose:
- Request counts, latencies, error rates
- Resource usage
- Rate-limit denials
- Zone/taint denials

Connectors SHOULD expose at least:
- connector_starts, connector_stops, connector_errors
- operation_requests, operation_errors, operation_duration
- ipc_messages_sent/received, ipc_message_size, ipc_latency
- memory_used_bytes, cpu_usage_percent, file_handles, network_connections
- capability_checks, capability_denials
- zone_transitions, zone_transition_denials

Connectors SHOULD expose metrics via:
- `fcp.metrics.snapshot` RPC
- or OpenTelemetry exporters (optional)

### 15.2 Structured Logs

Logs MUST be structured (JSON), redact secrets, and be emitted to stderr or a configured sink.

If trace context is present, logs MUST include `trace_id` and `span_id` and SHOULD propagate W3C `traceparent`/`tracestate` via message metadata.

Required fields:
- timestamp
- level
- correlation_id
- zone_id
- connector_id / instance_id
- principal_id (if present)
- resource_uri(s) (if present)
- event_seq / topic (for streaming events)
- error classification (if applicable)
- upstream_request_id (if present)

### 15.3 Audit Events

Hub MUST record immutable audit events for:
- Secret access
- High-risk capability use
- Approvals/elevations
- Zone transition attempts
- Security violations
- Provisioning start/complete/abort
- Stream resets (replay buffer overflow)

### 15.4 `fcp doctor`

Tooling MUST include a diagnostics command that checks:
- Signature verification
- Connectivity and auth validity
- Capability and zone mismatches
- Health check status
- Common misconfigurations

---

## 16. Error Taxonomy

### 16.1 Error Code Ranges

```
FCP-1000..1999  Protocol errors
FCP-2000..2999  Auth/Identity errors
FCP-3000..3999  Capability errors
FCP-4000..4999  Zone/Topology/Provenance errors
FCP-5000..5999  Connector lifecycle/health errors
FCP-6000..6999  Resource errors
FCP-7000..7999  External service errors
FCP-9000..9999  Internal errors
```

### 16.2 Common Error Codes

| Code | Name | Description |
|------|------|-------------|
| FCP-1001 | INVALID_REQUEST | Malformed request |
| FCP-1003 | MALFORMED_FRAME | Frame structure invalid |
| FCP-1004 | CHECKSUM_MISMATCH | Frame checksum failed |
| FCP-2001 | UNAUTHORIZED | Missing or invalid auth |
| FCP-3001 | CAPABILITY_DENIED | Capability not granted |
| FCP-3002 | RATE_LIMITED | Rate limit exceeded |
| FCP-4001 | ZONE_VIOLATION | Cross-zone access denied |
| FCP-4002 | TAINT_VIOLATION | Tainted origin blocked |
| FCP-4003 | ELEVATION_REQUIRED | Needs explicit approval |
| FCP-5001 | CONNECTOR_UNAVAILABLE | Connector not running |
| FCP-5002 | HEALTH_CHECK_FAILED | Connector unhealthy |
| FCP-7001 | UPSTREAM_ERROR | External service error |
| FCP-7002 | UPSTREAM_TIMEOUT | External service timeout |

### 16.3 Error Response Structure

```rust
pub struct FcpError {
    /// Error code (e.g., "FCP-4002")
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Whether retry might succeed
    pub retryable: bool,
    /// Suggested retry delay
    pub retry_after_ms: Option<u64>,
    /// Structured details
    pub details: Option<serde_json::Value>,
    /// Agent-friendly recovery hint
    pub ai_recovery_hint: Option<String>,
}
```

### 16.4 Canonical Error Names (String Codes)

Some transports (JSON-RPC compat) use string error codes. Implementations SHOULD use the following canonical names and map them to the numeric families above:

| Canonical Name | Meaning | Numeric Family |
|---------------|---------|----------------|
| `FCP_INVALID_REQUEST` | Malformed or missing fields | FCP-1000 |
| `FCP_UNAUTHORIZED` | Connector auth missing/invalid | FCP-2000 |
| `FCP_FORBIDDEN` | Capability denied | FCP-3000 |
| `FCP_NOT_FOUND` | Resource missing | FCP-6000 |
| `FCP_CONFLICT` | State conflict / optimistic concurrency | FCP-6000 |
| `FCP_RATE_LIMITED` | Rate limit exceeded | FCP-3000 / FCP-6000 |
| `FCP_DEPENDENCY_UNAVAILABLE` | Upstream dependency down | FCP-7000 |
| `FCP_TIMEOUT` | Upstream timeout | FCP-7000 |
| `FCP_INTERNAL` | Internal connector failure | FCP-9000 |

Connectors SHOULD map upstream provider errors into these stable codes to improve automation and recovery behavior.

---

## 17. Migration Strategy

Migration must deliver security wins early using a strangler-fig approach.

### Phase 1: Kernel

- Deploy Hub with no risky connectors
- Add one low-risk connector (e.g., web search) to validate tooling
- Establish CI/CD and conformance testing

### Phase 2: Public-Facing Isolation

- Move public Discord/Telegram ingestion into dedicated `z:community` connectors
- Ensure provenance/taint enforcement is active
- Validate that public inputs cannot reach private tools

### Phase 3: Private Tools with Strict Gating

- Add Gmail/Calendar/Drive in `z:private` with approvals for writes
- Validate that tainted-origin commands cannot reach these tools
- Implement elevation workflows

### Phase 4: Decommission Legacy

- Once feature parity is achieved, retire legacy integration paths
- Archive old code; do not maintain parallel systems

---

## Appendices

### Appendix A: Conformance Checklist

**Connector MUST:**
- [ ] Implement `--manifest` flag
- [ ] Implement handshake, introspect, configure, invoke, health, shutdown
- [ ] Implement `subscribe`/`unsubscribe` if emitting events
- [ ] Support event cursors + replay or emit `connector.stream.reset`
- [ ] Declare required/optional/forbidden capabilities
- [ ] Validate inputs against schemas
- [ ] Never log secrets
- [ ] Include AI hints for all operations
- [ ] Return `resource_uris` when applicable
- [ ] Implement provisioning interface if authentication is required

**Hub MUST:**
- [ ] Verify signatures/checksums before execution
- [ ] Enforce zones, capabilities, provenance/taint rules
- [ ] Enforce resource constraints in capability tokens
- [ ] Provide audit events for sensitive actions
- [ ] Implement resource limits + sandboxing
- [ ] Support elevation workflows

### Appendix B: Recommended Defaults

1. Default deny on network; allowlist host:port
2. No inbound listening unless explicitly declared and approved
3. All storage encrypted-at-rest for persistent connector state
4. High/critical operations require approvals or elevation tokens
5. Tainted provenance blocks privileged writes by default
6. Capability tokens expire after 5 minutes by default
7. Health checks every 30 seconds
8. Event replay buffers retain at least 10,000 events or 10 minutes
9. Retryable operations SHOULD require idempotency keys

### Appendix C: Reference Connector Patterns

| Pattern | Description | Examples |
|---------|-------------|----------|
| **Unified Messaging** | Maps channel IDs to zones; normalizes identities | Telegram, Discord, Slack |
| **Workspace** | Local caching for read-heavy APIs; strict write gating | Gmail, Calendar, Drive |
| **Knowledge** | Filesystem watch + local search index | Obsidian, Notion, Notes |
| **Sense** | Screenshots/voice with privacy masking | Whisper, Screenshot |
| **DevOps** | Typed wrappers around CLIs (no arbitrary exec) | gh, gcloud, kubectl |
| **Network** | Just-in-time access with TTL and auto-teardown | Tailscale, Cloudflare |

### Appendix D: SDK Crates (Planned)

| Crate | Purpose |
|-------|---------|
| `fcp-core` | Core types, traits, error taxonomy |
| `fcp-sdk` | Connector development kit |
| `fcp-host` | Hub implementation library |
| `fcp-protocol` | Wire protocol implementation |
| `fcp-manifest` | Manifest parsing and validation |
| `fcp-cli` | Command-line tools (`fcp install`, `fcp doctor`, etc.) |

### Appendix E: Conformance Levels and Tests

**Conformance Levels**

| Level | Requirement |
|-------|-------------|
| **Level 1 (Core)** | handshake, health, introspect, invoke, error model |
| **Level 2 (Streaming)** | subscribe, event envelope, seq/replay/reset semantics |
| **Level 3 (Provisioning)** | provisioning state machine, secret storage rules |
| **Level 4 (Zone-hardening)** | capability enforcement, resource constraint enforcement |

**Mandatory Tests**

- Manifest + schema validation
- Handshake negotiation
- Capability signature validation
- Token expiry behavior
- Replay/resume tests (if streaming)
- Request parsing fuzz tests (strongly recommended)

### Appendix F: Implementation Guidance (Non-Normative)

**Performance budgets (targets):**
- Host→connector invoke overhead (local stdio): p50 < 1ms, p99 < 5ms (excluding upstream API time)
- Connector event emission overhead: < 200 microseconds per event typical
- Connector cold start (no network handshake): < 100ms target
- Health check execution: < 10ms typical

**Reliability rules of thumb:**
- All upstream calls MUST be bounded by timeouts
- Retries SHOULD use jittered backoff with caps
- Circuit breakers SHOULD be used for flaky dependencies
- Auth flows MUST have explicit state machines (no implicit fallthrough)
- Avoid panics on user input; no `unwrap()` on parse paths

### Appendix G: Reference Flows (Non-Normative)

**Private Telegram “owner bot” (safe)**

- Zone: `z:owner` (trust grade `trusted_remote`)
- Telegram connector instance bound to that zone
- Policy: only principals with trust `owner` or `paired` can invoke agent sessions
- Allowed capabilities: Gmail/Calendar in `z:owner`

Flow:
1. Telegram inbound event arrives with `principal.id = tg_user_me`
2. Hub verifies principal is paired/owner → allowed
3. Hub spawns agent with Gmail/Calendar tools
4. Response sent with `telegram.send_message` constrained to that chat

**Public Discord “help bot” (safe)**

- Zone: `z:public` (trust grade `public`)
- Allowed capabilities: public docs/search, `discord.send_message` constrained to server/channel list
- Explicitly denied: Gmail/Drive/Calendar/DevOps CLIs

Flow:
1. Discord inbound event arrives with `principal.trust = untrusted`
2. Hub spawns restricted public agent (no sensitive tools)
3. Agent responds; outbound message is constrained to the originating channel

**Reliability rules of thumb:**
- Every upstream call: timeouts, retries with bounded jitter, circuit breakers
- Explicit auth state machine (no implicit credential states)
- Explicit shutdown behavior (no orphaned inflight operations)
- Never panic on user input; avoid `unwrap` on parse paths

### Appendix H: Policy Evaluation (FZPF v0.1)

**Pattern Language (anchored glob)**
- `*` matches zero or more characters (including `.` and `:`)
- Matching is case-sensitive and anchored (entire value must match)

**Invoke Authorization (deterministic)**
1. Resolve target zone; if missing, deny.
2. Enforce principals allow/deny (deny overrides allow; empty allowlist follows `default_deny`).
3. Enforce connectors allow/deny.
4. Enforce capability allow/deny.
5. Apply ordered `taint_rules` (first match wins): may deny or require elevation/approval.
6. If no taint rule matched, apply default taint thresholds (if configured).
7. If all checks pass, allow.

**Flow Authorization (data movement)**
1. Evaluate ordered `flows` (first match wins).
2. If a rule matches, allow/deny and apply `transform`/`audit` settings.
3. If no rule matched:
   - same-zone flow: allow (audit true)
   - cross-zone flow: follow `default_deny`

Hubs SHOULD emit structured audit events for denials, elevation/approval requirements, and flow decisions (including applied transforms).

### Appendix I: FZPF v0.1 JSON Schema (Formal)

This schema validates the FZPF policy file after parsing (TOML → JSON object).

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://flywheel.dev/schemas/fzpf-0.1.schema.json",
  "title": "Flywheel Zone Policy Format (FZPF) v0.1",
  "type": "object",
  "additionalProperties": false,
  "required": ["policy", "zones"],
  "properties": {
    "policy": { "$ref": "#/$defs/policy_header" },
    "defaults": { "$ref": "#/$defs/defaults" },
    "zones": {
      "type": "array",
      "minItems": 1,
      "items": { "$ref": "#/$defs/zone" }
    },
    "flows": {
      "type": "array",
      "default": [],
      "items": { "$ref": "#/$defs/flow_rule" }
    },
    "taint_rules": {
      "type": "array",
      "default": [],
      "items": { "$ref": "#/$defs/taint_rule" }
    }
  },
  "$defs": {
    "nonempty_string": { "type": "string", "minLength": 1 },
    "glob_string": { "type": "string", "minLength": 1, "maxLength": 512 },
    "zone_id": {
      "type": "string",
      "pattern": "^z:[a-z][a-z0-9:-]*$",
      "minLength": 3,
      "maxLength": 128
    },
    "risk_level": {
      "type": "string",
      "enum": ["low", "medium", "high", "critical"]
    },
    "taint_level": {
      "type": "string",
      "enum": ["Untainted", "Tainted", "HighlyTainted"]
    },
    "policy_header": {
      "type": "object",
      "additionalProperties": false,
      "required": ["format", "schema_version", "default_deny"],
      "properties": {
        "format": { "const": "fzpf" },
        "schema_version": { "const": "0.1" },
        "policy_id": { "$ref": "#/$defs/nonempty_string" },
        "last_updated": { "$ref": "#/$defs/nonempty_string" },
        "default_deny": { "type": "boolean" }
      }
    },
    "defaults": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "taint": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "require_elevation_min_risk": { "$ref": "#/$defs/risk_level" },
            "require_interactive_approval_min_risk": { "$ref": "#/$defs/risk_level" }
          }
        }
      }
    },
    "zone": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "trust_level"],
      "properties": {
        "id": { "$ref": "#/$defs/zone_id" },
        "name": { "$ref": "#/$defs/nonempty_string" },
        "description": { "$ref": "#/$defs/nonempty_string" },
        "trust_level": { "type": "integer", "minimum": 0, "maximum": 100 },
        "principals_allow": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "principals_deny": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "connectors_allow": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "connectors_deny": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "cap_allow": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "cap_deny": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "metadata": { "type": "object", "additionalProperties": true }
      }
    },
    "flow_kind": {
      "type": "string",
      "enum": ["ingress", "egress", "both"]
    },
    "flow_rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["from", "to", "kind", "allow"],
      "properties": {
        "name": { "$ref": "#/$defs/nonempty_string" },
        "from": { "$ref": "#/$defs/glob_string" },
        "to": { "$ref": "#/$defs/glob_string" },
        "kind": { "$ref": "#/$defs/flow_kind" },
        "allow": { "type": "boolean" },
        "transform": { "$ref": "#/$defs/nonempty_string" },
        "audit": { "type": "boolean", "default": true }
      }
    },
    "approval_mode": {
      "type": "string",
      "enum": ["interactive", "policy"]
    },
    "taint_action_type": {
      "type": "string",
      "enum": ["deny", "require_elevation", "require_approval"]
    },
    "taint_action": {
      "type": "object",
      "additionalProperties": false,
      "required": ["type"],
      "properties": {
        "type": { "$ref": "#/$defs/taint_action_type" },
        "ttl_seconds": { "type": "integer", "minimum": 0, "maximum": 86400 },
        "mode": { "$ref": "#/$defs/approval_mode" },
        "reason": { "$ref": "#/$defs/nonempty_string" }
      }
    },
    "taint_rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "action"],
      "properties": {
        "name": { "$ref": "#/$defs/nonempty_string" },
        "min_taint": { "$ref": "#/$defs/taint_level" },
        "min_risk": { "$ref": "#/$defs/risk_level" },
        "when_origin_trust_lt_target": { "type": "boolean", "default": false },
        "origin_zone_patterns": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "target_zone_patterns": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "capability_patterns": { "type": "array", "default": [], "items": { "$ref": "#/$defs/glob_string" } },
        "action": { "$ref": "#/$defs/taint_action" }
      }
    }
  }
}
```

### Appendix J: Golden Decision Test Vectors (FZPF v0.1)

These vectors assume the example policy in Section 6.10 and the algorithm in Appendix H.

**Vector 1: public web search (allow)**
```
principal = "p:public:user_1"
connector_id = "fcp.web"
capability = "web.search"
operation_risk = "low"
origin_zone = "z:public"
origin_taint = "Tainted"
target_zone = "z:public"
has_elevation = false
has_interactive_approval = false
has_policy_approval = false
→ ALLOW
```

**Vector 2: public → private email send without elevation (require elevation)**
```
principal = "p:public:user_1"
connector_id = "fcp.gmail"
capability = "email.send"
operation_risk = "medium"
origin_zone = "z:public"
origin_taint = "Tainted"
target_zone = "z:private"
has_elevation = false
has_interactive_approval = false
has_policy_approval = false
→ REQUIRE_ELEVATION (ttl_seconds = 300)
```

**Vector 3: public → private email send with elevation (allow)**
```
principal = "p:owner:me"
connector_id = "fcp.gmail"
capability = "email.send"
operation_risk = "medium"
origin_zone = "z:public"
origin_taint = "Tainted"
target_zone = "z:private"
has_elevation = true
has_interactive_approval = false
has_policy_approval = false
→ ALLOW
```

**Vector 4: public → private system.exec (deny by cap_deny)**
```
principal = "p:owner:me"
connector_id = "fcp.gmail"
capability = "system.exec"
operation_risk = "critical"
origin_zone = "z:public"
origin_taint = "HighlyTainted"
target_zone = "z:private"
has_elevation = true
has_interactive_approval = true
has_policy_approval = true
→ DENY (cap_deny)
```

**Vector 5: private → public flow with redaction (allow + transform)**
```
from_zone = "z:private"
to_zone = "z:public"
kind = "egress"
→ ALLOW (audit=true, transform="redact_secrets")
```

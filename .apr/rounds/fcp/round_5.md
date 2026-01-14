Below are my strongest revisions to make the plan **more correct, more interoperable, more secure, more operable, and more realistically shippable**—while keeping the original “mesh-native + zones + explicit authority” vision intact.

For each change you’ll see:

1. **What I’d change**
2. **Why it’s better** (security/reliability/perf/operability)
3. A **git-diff style patch** against your current `README.md` and/or `FCP_Specification_V2.md` (and a couple of new files where it materially improves robustness).

---

## Change 1: Fix README ↔ Spec wire-format mismatch and make the Spec the explicit source of truth

### What to change

Your README’s FCPS frame header currently disagrees with the spec (Zone ID hash length + byte offsets + header size). This is the kind of mismatch that causes **two independent implementations to “both follow the docs” and still fail interop**.

### Why it’s better

* **Interop & correctness**: eliminates accidental divergent implementations.
* **Security**: incorrect offsets can become parsing bugs → exploitable surfaces.
* **Operational clarity**: “Spec is authoritative” is a strong norm for protocol projects.

### Patch

```diff
diff --git a/README.md b/README.md
index 1111111..2222222 100644
--- a/README.md
+++ b/README.md
@@ -1,6 +1,14 @@
 # Flywheel Connector Protocol (FCP)

 <div align="center">
   <img src="illustration.webp" alt="FCP - Secure connectors for AI agents with zone-based isolation and capability tokens">
 </div>

+A note on specifications:
+- `FCP_Specification_V2.md` is the *authoritative* interoperability contract.
+- This README is a high-level overview; when diagrams conflict, implement the Spec.
+
@@ -146,26 +154,30 @@
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
-│  Bytes 58-73:  Zone ID hash (16 bytes)                                      │
-│  Bytes 74-81:  Epoch ID (u64 LE)                                            │
-│  Bytes 82-89:  Frame Seq (u64 LE, per-sender monotonic counter)             │
-│  Bytes 90+:    Symbol payloads (encrypted, concatenated)                    │
+│  Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; see Spec §3.4)               │
+│  Bytes 90-97:  Epoch ID (u64 LE)                                            │
+│  Bytes 98-105: Frame Seq (u64 LE, per-sender monotonic counter)             │
+│  Bytes 106+:   Symbol payloads (encrypted, concatenated)                    │
│  Final 8:      Checksum (XXH3-64)                                           │
│                                                                             │
-│  Fixed header: 90 bytes                                                     │
+│  Fixed header: 106 bytes                                                    │
│  Per-symbol nonce: derived as frame_seq || esi_le (deterministic)           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

```
```

---

## Change 2: Add MTU-safe framing rules and negotiated datagram limits

### What to change

You implicitly assume “~1 symbol per frame near MTU,” but you never **normatively** define:

* a safe default datagram size,
* what happens when a peer wants larger symbols,
* how to avoid IP fragmentation (a major real-world reliability killer).

### Why it’s better

* **Reliability**: avoiding IP fragmentation is one of the biggest practical wins.
* **Performance**: stable loss characteristics and less retransmission.
* **DoS resistance**: bounded frame sizes bound parsing and allocation.

### Patch

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index 3333333..4444444 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -412,6 +412,45 @@
 ### 4.3 FCPS Frame Format
 Symbol-native frame format:

+### 4.3.1 MTU Safety and Frame Size Limits (NORMATIVE)
+FCP nodes MUST avoid IP fragmentation in default configurations.
+
+**Baseline rule:**
+- Implementations MUST support sending FCPS frames that fit within a UDP payload of **≤ 1200 bytes**
+  (QUIC’s widely-used minimum datagram size) without relying on path MTU discovery.
+
+**Negotiated limits (RECOMMENDED; NORMATIVE when used):**
+- During MeshSession establishment, peers MAY negotiate `max_datagram_bytes`.
+- If negotiated, senders MUST NOT exceed the negotiated limit for FCPS datagrams.
+
+**Symbol sizing rule (NORMATIVE):**
+- A sender MUST choose `symbol_size` and `symbol_count` so that:
+  `len(FCPS_header) + Σ(len(symbol_records)) + len(checksum) ≤ max_datagram_bytes`.
+- Receivers MUST reject frames exceeding their configured maximum (to prevent allocation DoS).
+
+**Interoperability defaults:**
+- `max_datagram_bytes` default: **1200**
+- `symbol_size` default: **1024**
+- senders SHOULD default to **1 symbol per FCPS frame** unless the negotiated limit safely permits more.
+
@@ -492,6 +531,24 @@
 pub struct MeshSessionHello {
@@
     /// Supported crypto suites (ordered by preference)
     pub suites: Vec<SessionCryptoSuite>,
+
+    /// Optional transport limits (NORMATIVE when present)
+    /// Used to keep FCPS frames MTU-safe and avoid fragmentation.
+    pub transport_limits: Option<TransportLimits>,
@@
 }
+
+/// Negotiated transport limits (NORMATIVE when used)
+pub struct TransportLimits {
+    /// Maximum UDP payload bytes the sender will transmit for FCPS frames to this peer.
+    /// Default if absent: 1200.
+    pub max_datagram_bytes: u16,
+}
```

---

## Change 3: Standardize “sealed_key” blobs to HPKE (RFC 9180) for zone keys, ObjectIdKey, owner shares, and secret shares

### What to change

Right now, several structs contain `sealed_key: Vec<u8>` with “sealed to node_enc_pubkey” but no normative format. That’s risky: every implementer will choose a slightly different “sealed box” scheme and you’ll get **incompatibility + crypto footguns**.

Make HPKE the normative “sealed container” everywhere you currently say “sealed”.

### Why it’s better

* **Interop**: HPKE is standardized and already has multi-language implementations.
* **Crypto agility**: explicit KEM/KDF/AEAD identifiers.
* **Security**: avoids ad-hoc “X25519 + some AEAD + homemade transcript”.

### Patch

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index 4444444..5555555 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -332,6 +332,55 @@
 ### 3.6 ObjectHeader
 All mesh-stored objects MUST begin with an ObjectHeader (NORMATIVE):

+### 3.6.1 HPKE Sealed Boxes (NORMATIVE)
+Whenever the spec says an object is "sealed to node_enc_pubkey", the encoding MUST use HPKE
+(RFC 9180) to avoid implementation divergence.
+
+**Baseline profile (MUST implement):**
+- KEM: DHKEM(X25519, HKDF-SHA256)
+- KDF: HKDF-SHA256
+- AEAD: ChaCha20-Poly1305
+
+```rust
+/// Standard sealed container (NORMATIVE)
+pub struct HpkeSealedBox {
+    /// RFC9180 identifiers for algorithm agility.
+    pub kem_id: u16,
+    pub kdf_id: u16,
+    pub aead_id: u16,
+    /// HPKE encapsulated key (enc)
+    pub enc: Vec<u8>,
+    /// AEAD ciphertext (includes auth tag per HPKE)
+    pub ct: Vec<u8>,
+}
+```
+
+**Associated data (NORMATIVE):**
+- Seal operations MUST include AAD that binds the sealed payload to:
+  - `zone_id_hash` (or zone_id if not available),
+  - `recipient_node_id`,
+  - `purpose` string (e.g., "FCP2-ZONE-KEY", "FCP2-OBJECTID-KEY", "FCP2-OWNER-SHARE", "FCP2-SECRET-SHARE"),
+  - and `issued_at`.
+
@@ -900,7 +949,7 @@
 pub struct WrappedZoneKey {
     pub node_id: TailscaleNodeId,
     /// Which node_enc_pubkey was used (supports node key rotation)
     pub node_enc_kid: [u8; 8],
-    /// Sealed box containing the 32-byte zone symmetric key
-    pub sealed_key: Vec<u8>,
+    /// HPKE sealed box containing the 32-byte zone symmetric key (NORMATIVE)
+    pub sealed_key: HpkeSealedBox,
 }
@@ -908,9 +957,9 @@
 pub struct WrappedObjectIdKey {
     pub node_id: TailscaleNodeId,
     pub node_enc_kid: [u8; 8],
-    /// Sealed box containing the 32-byte ObjectIdKey
-    pub sealed_key: Vec<u8>,
+    /// HPKE sealed box containing the 32-byte ObjectIdKey (NORMATIVE)
+    pub sealed_key: HpkeSealedBox,
 }
@@ -235,9 +235,9 @@
 pub struct OwnerKeyShare {
@@
-    /// Sealed to node_enc_pubkey
-    pub sealed_share: Vec<u8>,
+    /// Sealed to node_enc_pubkey using HPKE (NORMATIVE)
+    pub sealed_share: HpkeSealedBox,
@@
 }
````

(If you later add MLS/TreeKEM, HPKE still remains useful for sealing MLS Welcome / epoch secrets to devices.)

---

## Change 4: Standardize signature encoding & multi-signature ordering across *all* signed objects

### What to change

You’ve done the right thing for CapabilityTokens (COSE_Sign1 + deterministic CBOR), but almost every other signed object still hand-waves `signable_bytes()`.

You should define one consistent rule:

* **All signatures are Ed25519 over deterministic CBOR of the object with `signature` omitted**, and
* all vectors of signatures are **sorted deterministically**.

### Why it’s better

* **Interop**: removes the #1 cause of “works in Rust, fails in Go/TS”.
* **Security**: avoids subtle canonicalization differences leading to acceptance of forged/incorrectly verified objects.
* **Testability**: golden vectors become straightforward.

### Patch

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index 5555555..6666666 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -276,6 +276,63 @@
 ### 3.5 Canonical Serialization
 Deterministic serialization for content addressing:

+### 3.5.1 Signature Canonicalization (NORMATIVE)
+For any mesh object that includes a `signature: Signature` field, verification MUST follow a single,
+deterministic procedure to prevent cross-language divergence.
+
+**Rule:**
+1. Define an “unsigned view” of the object equal to the object with its `signature` field removed
+   (and for multi-signature objects, with `quorum_signatures` removed).
+2. Serialize the unsigned view using **deterministic CBOR** (RFC 8949 canonical encoding),
+   prefixed by the SchemaHash as described in §3.5.
+3. The signature MUST be Ed25519 over those bytes.
+
+**Multi-signature ordering (NORMATIVE):**
+Vectors of signatures (e.g., `quorum_signatures: Vec<(TailscaleNodeId, Signature)>`) MUST be sorted
+lexicographically by `TailscaleNodeId` (byte order) before hashing, signing, or verifying.
+
+**Why this is required:**
+- Prevents “same semantic content, different byte encoding” bugs.
+- Prevents malleability via reordering signature arrays.
+
@@ -1610,7 +1667,10 @@
 pub struct AuditHead {
@@
-    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
+    /// MUST be sorted by node_id (NORMATIVE; see §3.5.1)
+    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
 }
@@ -1188,7 +1248,10 @@
 pub struct RevocationHead {
@@
-    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
+    /// MUST be sorted by node_id (NORMATIVE; see §3.5.1)
+    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
 }
```

---

## Change 5: Make Zone definitions and policies first-class mesh objects (versioned, auditable, pin-able)

### What to change

Right now zone definitions are described as structs; policies exist as structs; but the plan never clearly states “this is stored, signed, gossiped, and pinned like everything else”.

Make:

* `ZoneDefinitionObject` (signed by owner) the canonical zone config,
* `ZonePolicyObject` (signed by owner) the canonical policy,
* Nodes derive runtime `Zone` config from the latest pinned `ZoneDefinitionObject`.

### Why it’s better

* **Reliability**: every node converges on the same zone config offline.
* **Auditability**: policy changes and zone changes are first-class events, not hidden in config files.
* **Revocation & rollback**: you can roll back zone config just like connectors.

### Patch

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index 6666666..7777777 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -840,6 +840,86 @@
 ### 5.2 Zone Definition
 ```rust
 /// Zone with cryptographic properties (NORMATIVE)
 pub struct Zone {
@@
     pub policy: ZonePolicy,
@@
 }
````

*

+### 5.2.1 ZoneDefinitionObject and ZonePolicyObject (NORMATIVE)
+Zones and policies MUST be representable as mesh objects so that:
+- configuration is authenticated (owner-signed),
+- distributed (symbol layer),
+- auditable (hash-linked via audit),
+- and rollback-able.
+
+```rust
+/// Owner-signed zone definition (NORMATIVE)
+pub struct ZoneDefinitionObject {

* pub header: ObjectHeader,
* pub zone_id: ZoneId,
* pub name: String,
* pub integrity_level: u8,
* pub confidentiality_level: u8,
* pub symbol_port: u16,
* pub control_port: u16,
* pub transport_policy: Option<ZoneTransportPolicy>,
*
* /// Reference to the active policy object for this zone (NORMATIVE)
* pub policy_object_id: ObjectId,
*
* /// Optional previous ZoneDefinitionObject for history/rollback
* pub prev: Option<ObjectId>,
*
* /// Owner signature (see §3.5.1)
* pub signature: Signature,
  +}
*

+/// Owner-signed policy object (NORMATIVE)
+pub struct ZonePolicyObject {

* pub header: ObjectHeader,
* pub zone_id: ZoneId,
* pub policy: ZonePolicy,
* pub prev: Option<ObjectId>,
* pub signature: Signature,
  +}
  +```
*

+**Runtime rule (NORMATIVE):**
+- A MeshNode MUST treat the latest pinned ZoneDefinitionObject as the canonical configuration for

* that zone.
  +- Policy evaluation MUST use the ZonePolicyObject referenced by `policy_object_id` unless the node
* is in explicit degraded mode and logs `policy.degraded_mode`.

````

And in the README, you can advertise it (compelling):

```diff
diff --git a/README.md b/README.md
index 2222222..3333333 100644
--- a/README.md
+++ b/README.md
@@ -40,6 +40,7 @@
 | **Zone Isolation** | Cryptographic namespaces with integrity/confidentiality axes and Tailscale ACL enforcement |
+| **Mesh-stored Policy Objects** | Zone definitions + policies are owner-signed mesh objects (auditable + rollbackable) |
 | **Capability Tokens (CWT/COSE)** | Provable authority with grant_object_ids; tokens are canonically CBOR-encoded and COSE-signed for interoperability |
````

---

## Change 6: Add “secretless connectors” via egress-proxy credential injection (connectors never see raw API keys)

### What to change

You already have the correct primitive (network access via **MeshNode-owned egress proxy**). Use it to drastically reduce secret exposure:

* Add a `CredentialObject` that describes how to apply a secret to outbound HTTP (e.g., “Authorization: Bearer …”).
* Add `credential_allow` constraints in CapabilityObjects.
* Egress proxy injects the credential when allowed.

This makes “high-risk connectors” safer **without relying on WASI alone**.

### Why it’s better

* **Big security win**: connector compromise ≠ secret exfiltration by default.
* **Operational simplicity**: rotating a secret updates the proxy-managed secret; connectors keep working.
* **Performance**: avoids repeated “reconstruct secret → hand to connector → zeroize” per call.

### Patch

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index 7777777..8888888 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -1030,6 +1030,88 @@
 pub struct CapabilityConstraints {
@@
     /// Optional network/TLS constraints (NORMATIVE when network.outbound is used)
     pub network: Option<NetworkConstraints>,
+
+    /// Optional credential bindings (NORMATIVE when present)
+    /// If set, the connector may only use the listed credentials via the egress proxy.
+    /// This enables "secretless connectors" where raw secrets never enter connector memory.
+    pub credential_allow: Vec<CredentialId>,
 }
+
+/// Credential identifier (NORMATIVE)
+pub struct CredentialId(pub String); // e.g., "cred:telegram.bot_token"
+
+/// Credential object (NORMATIVE)
+/// A zone-bound, auditable handle describing how to apply a SecretObject to outbound requests.
+pub struct CredentialObject {
+    pub header: ObjectHeader,
+    pub credential_id: CredentialId,
+    pub secret_id: SecretId,
+
+    /// How to apply the credential (NORMATIVE)
+    pub apply: CredentialApply,
+
+    /// Optional host binding for defense-in-depth (NORMATIVE when present)
+    /// If present, the egress proxy MUST reject use on other hosts.
+    pub host_allow: Vec<String>,
+
+    pub created_at: u64,
+    pub signature: Signature,
+}
+
+pub enum CredentialApply {
+    /// Set an HTTP header (e.g., Authorization: Bearer <secret>)
+    HttpHeader { name: String, format: CredentialFormat },
+    /// Set query parameter (rare; discouraged)
+    QueryParam { name: String, format: CredentialFormat },
+}
+
+pub enum CredentialFormat {
+    /// Use the secret bytes as UTF-8
+    Raw,
+    /// Prefix + secret (e.g., "Bearer " + token)
+    Prefix { prefix: String },
+}
+
@@ -640,6 +722,90 @@
  ### Egress Proxy
  Connector network access via capability-gated IPC
@@
  • SNI enforcement, SPKI pinning
+
+### Egress Proxy Credential Injection (NORMATIVE)
+When a connector is running under a sandbox profile that routes network access through the MeshNode
+egress proxy (Strict/Moderate), the proxy MUST support applying credentials without revealing raw
+secret material to the connector process.
+
+```rust
+pub struct EgressHttpRequest {
+    pub method: String,
+    pub url: String,
+    pub headers: Vec<(String, String)>,
+    pub body: Vec<u8>,
+
+    /// Optional credential to apply (NORMATIVE when used)
+    pub credential: Option<CredentialId>,
+}
+```
+
+**Authorization rule (NORMATIVE):**
+- If `credential` is set, the egress proxy MUST:
+  1. Verify the caller’s CapabilityToken and relevant grant objects.
+  2. Verify `credential` ∈ `CapabilityConstraints.credential_allow`.
+  3. Fetch and validate the referenced CredentialObject and SecretObject.
+  4. Require a valid SecretAccessToken for secret materialization, OR use a policy-driven
+     “proxy materialization” mode where the proxy itself is the only process allowed to
+     reconstruct the secret for the request.
+  5. Inject the credential only for allowed hosts and log an audit event.
+```

And add to README’s “Why Use FCP?” (this is compelling in practice):

```diff
diff --git a/README.md b/README.md
index 3333333..4444444 100644
--- a/README.md
+++ b/README.md
@@ -33,6 +33,7 @@
 | **Threshold Secrets** | Shamir secret sharing with k-of-n across devices—never complete anywhere |
+| **Secretless Connectors** | Egress proxy can inject credentials so connectors never see raw API keys by default |
 | **Computation Migration** | Operations execute on the optimal device automatically |
````

---

## Change 7: Fully define SymbolRequest / SymbolDelivery as bounded control-plane objects

### What to change

You list message types like `symbol_request`, `symbol_delivery`, `decode_status`, `symbol_ack`, but you don’t actually define the **request object format** and the **hard bounding fields** necessary to enforce anti-amplification in a deterministic way.

Define:

* `SymbolRequest` (with explicit bounds)
* `SymbolDeliveryHint` (optional)
* Tight rules about max response size

### Why it’s better

* **DoS resistance becomes implementable**, not aspirational.
* **Interop**: everyone requests symbols the same way.
* **Performance**: enables targeted repair using missing-hints without guessing.

### Patch

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index 8888888..9999999 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -1440,6 +1440,112 @@
 ### 9.2 Message Types
 | Type | Direction | Purpose |
@@
 | `symbol_request` | Any → Any | Request symbols (mesh) |
 | `symbol_delivery` | Any → Any | Deliver symbols (mesh) |
@@
 
+### 9.2.1 SymbolRequest and Bounding (NORMATIVE)
+Symbol retrieval is the largest DoS/amplification surface. Requests and responses MUST be explicitly
+bounded and mechanically enforceable.
+
+```rust
+/// Request symbols for an object (NORMATIVE)
+pub struct SymbolRequest {
+    pub header: ObjectHeader,
+    pub object_id: ObjectId,
+    pub zone_id: ZoneId,
+    pub zone_key_id: [u8; 8],
+
+    /// Maximum number of symbol records the requester is willing to accept (NORMATIVE)
+    pub max_symbols: u32,
+
+    /// Optional: request specific ESIs to enable targeted repair (NORMATIVE when present)
+    /// MUST be bounded by max_symbols.
+    pub want_esi: Option<Vec<u32>>,
+
+    /// Optional decode status hint (NORMATIVE when present)
+    pub decode_status: Option<DecodeStatus>,
+
+    /// Anti-replay / correlation
+    pub requested_at: u64,
+    pub requester: TailscaleNodeId,
+    pub signature: Signature,
+}
+
+/// Delivery hint for pacing and batching (NORMATIVE when used)
+pub struct SymbolDeliveryHint {
+    /// Sender should stop after this many symbols unless updated status arrives
+    pub stop_after_symbols: u32,
+    /// Preferred symbol_size (may be ignored if it violates MTU rules)
+    pub preferred_symbol_size: Option<u16>,
+}
+```
+
+**Anti-amplification rule (NORMATIVE, replaces prose-only rule):**
+- A responder MUST NOT send more than `max_symbols` symbols in response to a SymbolRequest.
+- A responder MUST reject unauthenticated requests unless zone policy explicitly allows them.
+- For unauthenticated requests (e.g., z:public ingress), the responder MUST enforce a stricter
+  `max_symbols_unauthenticated` cap (default: 32).
+
+**Accounting rule (NORMATIVE):**
+- Processing a SymbolRequest MUST count against PeerBudget limits (bytes + CPU + inflight decodes).
````

---

## Change 8: Remove floating-point from NORMATIVE data-path fields; use basis points consistently

### What to change

You correctly use basis points in many places, but a few NORMATIVE structs still use `f64` (e.g., `DistributedState.min_coverage`, `DiversityPolicy.max_node_fraction`). Floats create:

* cross-language parsing differences,
* surprising rounding,
* policy comparison bugs.

### Why it’s better

* **Interop stability**: identical logic across Rust/Go/TS.
* **Policy safety**: comparisons remain exact.
* **Easier testing**: deterministic.

### Patch

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index 9999999..aaaaaaa 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -1210,20 +1210,25 @@
 /// State is symbol distribution (NORMATIVE)
 pub struct DistributedState {
     /// Object ID for this state
     pub object_id: ObjectId,
 
     /// Current symbol distribution
     pub distribution: SymbolDistribution,
 
-    /// Minimum coverage for availability
-    pub min_coverage: f64,
+    /// Minimum coverage for availability in basis points (NORMATIVE)
+    /// 10000 = 1.0x (K symbols), 15000 = 1.5x redundancy
+    pub min_coverage_bps: u32,
 }
 
 impl DistributedState {
     /// Current availability
-    pub fn coverage(&self) -> f64 {
+    pub fn coverage_bps(&self) -> u32 {
         let available: HashSet<u32> = self.distribution.node_symbols
             .values()
             .flatten()
             .cloned()
             .collect();
-        available.len() as f64 / self.distribution.k as f64
+        // basis points
+        ((available.len() as u64 * 10000) / self.distribution.k as u64) as u32
     }
 
     /// Is state reconstructable?
     pub fn is_available(&self) -> bool {
-        self.coverage() >= 1.0
+        self.coverage_bps() >= 10000
     }
 }
@@ -2105,10 +2110,13 @@
 pub struct DiversityPolicy {
     pub min_nodes: u8,
     pub min_zones: u8,
-    pub max_node_fraction: f64,
+    /// basis points, 0..=10000 (NORMATIVE)
+    pub max_node_fraction_bps: u16,
 }
```

---

## Change 9: Make QUIC the primary transport substrate for FCPC (streams) and optionally FCPS (datagrams)

### What to change

You currently say FCPC can run over TCP or QUIC, and FCPS is framed as UDP-ish. In practice:

* QUIC gives you **congestion control, backpressure, stream multiplexing**.
* Over Tailscale, QUIC is generally easy to deploy.

Make QUIC the primary MUST-implement for FCPC, and allow FCPS to use QUIC DATAGRAM when available (with UDP fallback).

### Why it’s better

* **Performance**: built-in congestion control beats reinventing pacing.
* **Reliability**: fewer bespoke transport edge cases.
* **Security surface reduction**: less custom state machines.

### Patch

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index aaaaaaa..bbbbbbb 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -1520,10 +1520,21 @@
 ### 9.4 FCPC: Control Plane Framing (NORMATIVE)
 FCPC provides a reliable, backpressured framing for control-plane objects (invoke/simulate/configure/response/etc).
 It is carried over a stream transport (TCP or QUIC) inside the tailnet.
 
+**Transport requirement (NORMATIVE):**
+- Implementations MUST support FCPC over QUIC streams.
+- Implementations MAY support FCPC over TCP as a fallback.
+
+**Rationale:**
+- QUIC provides multiplexing, flow control, and congestion control with fewer bespoke edge cases.
+
@@ -420,6 +431,18 @@
 ### 4.3 FCPS Frame Format
 Symbol-native frame format:
+
+**Transport recommendation (RECOMMENDED):**
+- When QUIC DATAGRAM is available between peers, FCPS frames SHOULD be carried as QUIC datagrams.
+- Otherwise FCPS frames MAY be carried over UDP directly.
+
+**NORMATIVE invariant:**
+- Regardless of carrier, the FCPS on-wire frame format and authentication rules remain the same.
```

---

## Change 10: Add a machine-readable CBOR schema layer (CDDL) + golden vectors as a first-class conformance artifact

### What to change

You reference “golden decision vectors” and a fuzz harness (good), but you’re missing the thing that most makes interop real:

* A **CDDL** file describing the canonical CBOR maps/arrays for each NORMATIVE object.
* A directory of **golden vectors**: bytes + expected parse + expected ObjectId.

### Why it’s better

* **Interop**: other languages can implement confidently.
* **Security**: avoids ambiguous parsing rules.
* **Fuzzing**: CDDL can generate structured fuzz inputs.

### Patch (new files)

```diff
diff --git a/FCP_CDDL_V2.cddl b/FCP_CDDL_V2.cddl
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/FCP_CDDL_V2.cddl
@@ -0,0 +1,58 @@
+; Flywheel Connector Protocol (FCP) - CDDL (Draft)
+; Version: 2.0.0
+; This file defines canonical CBOR structures for NORMATIVE objects.
+
+; NOTE: This is a scaffold. Expand per-object as the spec stabilizes.
+
+ObjectId = bytes .size 32
+SchemaHash = bytes .size 32
+ZoneId = tstr
+ZoneKeyId = bytes .size 8
+EpochId = uint
+
+; Example: ApprovalToken (shape only; fill in exact fields as spec finalizes)
+ApprovalToken = {
+  "scope": ApprovalScope,
+  "justification": tstr,
+  "approved_by": tstr,
+  "approved_at": uint,
+  "expires_at": uint,
+  "signature": bstr,
+}
+
+ApprovalScope = Elevation / Declassification / Execution
+Elevation = { "elevation": { "operation": tstr, "original_provenance": any } }
+Declassification = { "declassification": { "from_zone": ZoneId, "to_zone": ZoneId, "object_ids": [* ObjectId] } }
+Execution = { "execution": { "connector_id": tstr, "method_pattern": tstr, "input_constraints": ? tstr } }
+
diff --git a/conformance/golden/README.md b/conformance/golden/README.md
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/conformance/golden/README.md
@@ -0,0 +1,44 @@
+# Golden Vectors
+
+This directory contains byte-level vectors to ensure cross-language interoperability:
+
+- `*.cbor`: canonical CBOR bytes
+- `*.json`: expected decoded representation (debug)
+- `*.objectid`: expected ObjectId (hex/base64)
+
+Minimum required vectors:
+- Canonical serialization + schema hash prefix
+- ObjectId derivation for key object classes
+- COSE_Sign1 capability token encoding/verification
+- HPKE sealed boxes (ZoneKeyManifest / ObjectIdKey distribution)
+- FCPS frame parsing (valid + invalid)
```

And reference it in the spec:

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index bbbbbbb..ccccccc 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -2660,6 +2660,15 @@
 ## 27. Conformance Requirements
@@
 ### 27.3 Fuzzing and Adversarial Tests (NORMATIVE for reference implementation)
@@
+### 27.4 CDDL + Golden Vectors (NORMATIVE for interoperability)
+To ensure cross-language consistency:
+- The project MUST ship a CDDL description of NORMATIVE CBOR objects (`FCP_CDDL_V2.cddl`).
+- The project MUST ship golden byte vectors covering ObjectId derivation and signature verification.
```

---

## Change 11: Strengthen ExecutionLease into a generic lease primitive + require lease fencing on connector state updates

### What to change

Your ExecutionLease is solid, but:

* It only explicitly targets “request execution”.
* Singleton-writer connector state *should* be fenced by the same lease primitive, but currently it’s described more as a pattern than a hard rule.

Make leases generic and require state updates to carry fencing evidence.

### Why it’s better

* **Prevents double-polling and cursor corruption** in the real world.
* **Easier incident response**: you can identify and prove who held the lease when a bad state update happened.
* **Cleaner spec**: one concurrency primitive, many uses.

### Patch

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index ccccccc..ddddddd 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -1810,6 +1810,52 @@
 ### 15.1 Execution Leases
 Execution leases prevent duplicate side effects and "thrash-migrate" loops:
 
 ```rust
-/// Execution lease (NORMATIVE)
-/// ///
-/// Prevents duplicate execution and stabilizes computation migration.
-/// A short-lived, renewable lock that says "node X owns execution of request R until time T."
-pub struct ExecutionLease {
+/// Generic lease (NORMATIVE)
+/// A short-lived, renewable, fenced lock for a subject object.
+pub struct Lease {
     pub header: ObjectHeader,
-    /// The request/computation being leased
-    pub request_object_id: ObjectId,
+    /// Subject being leased (NORMATIVE)
+    /// Examples:
+    /// - InvokeRequest ObjectId (operation execution)
+    /// - ConnectorStateRoot ObjectId (singleton writer state)
+    /// - MigratableComputation ObjectId (migration)
+    pub subject_object_id: ObjectId,
+
+    /// Lease purpose (NORMATIVE)
+    pub purpose: LeasePurpose,
@@
     pub lease_seq: u64,
@@
     pub owner_node: TailscaleNodeId,
@@
     pub coordinator: TailscaleNodeId,
@@
     pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
 }
+
+pub enum LeasePurpose {
+    OperationExecution,
+    ConnectorStateWrite,
+    ComputationMigration,
+}
````

@@ -1325,6 +1371,28 @@
pub struct ConnectorStateObject {
@@
/// Canonical connector-specific state blob
pub state_cbor: Vec<u8>,
pub updated_at: u64,
+

* /// Fencing evidence (NORMATIVE for SingletonWriter)
* /// The state writer MUST include the observed lease_seq used to produce this update.
* pub lease_seq: Option<u64>,
*
* /// Reference to the Lease object that fenced this write (NORMATIVE for SingletonWriter)
* /// MUST be included in ObjectHeader.refs as well (for reachability + audit).
* pub lease_object_id: Option<ObjectId>,
  @@
  pub signature: Signature,
  }
*

+**SingletonWriter rule (NORMATIVE):**
+- If `ConnectorStateModel::SingletonWriter`, then:

* * every ConnectorStateObject MUST include `lease_seq` and `lease_object_id`,
* * and verifiers MUST reject writes whose lease_seq is stale relative to the latest known lease.

````

---

## Change 12: Tighten the roadmap into “MVP profile” vs “Full profile” so it’s actually shippable

### What to change
The spec is extremely ambitious. The risk is not “the ideas are bad,” it’s **shipping never happens** because everything is interdependent.

Add an explicit “MVP Profile” (small set of features that still delivers the core security story) and a “Full Profile”.

### Why it’s better
- **De-risks execution**: you can ship and iterate without cutting principles.
- **More compelling**: people can adopt incrementally.
- **Better engineering**: avoids building 10 subsystems before the first useful connector works.

### Patch
```diff
diff --git a/README.md b/README.md
index 4444444..5555555 100644
--- a/README.md
+++ b/README.md
@@ -420,6 +420,46 @@
 ## Performance Targets
@@
  --- 
+
+## Profiles and Roadmap
+
+### MVP Profile (Ship First)
+Delivers the core safety story ("zones + explicit authority + auditable operations") with minimal moving parts.
+
+- FCPC over QUIC for control plane
+- CapabilityToken (COSE/CWT) + grant_object_ids verification
+- ZoneKeyManifest (HPKE sealing) + per-zone encryption
+- Egress proxy with NetworkConstraints + CIDR deny defaults
+- OperationIntent + OperationReceipt for Risky/Dangerous
+- Revocation objects + freshness policy
+- Basic symbol store + object reconstruction (chunking required for large objects)
+
+### Full Profile (Iterate Toward)
+- XOR filter + IBLT gossip optimization
+- MLS/TreeKEM for post-compromise security in sensitive zones
+- Computation migration + device-aware planner sophistication
+- Advanced repair + predictive pre-staging
+
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
index ddddddd..eeeeeee 100644
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@ -2580,6 +2580,60 @@
 ## 25. Implementation Phases
 
+### 25.0 Profiles (NORMATIVE for conformance targets)
+This spec defines two conformance profiles to enable incremental shipping.
+
+**MVP Profile (MUST implement for initial reference release):**
+- Canonical CBOR + schema hash prefix
+- COSE_Sign1 CapabilityToken with grant_object_ids verification
+- ZoneKeyManifest with HPKE sealed distribution
+- FCPC over QUIC streams
+- Egress proxy enforcing NetworkConstraints
+- OperationIntent + OperationReceipt for Risky/Dangerous
+- Revocation checking + freshness policy
+- ChunkedObjectManifest for objects above threshold
+
+**Full Profile (MAY implement; REQUIRED for “Full” conformance claim):**
+- XOR/IBLT gossip optimization
+- Advanced repair controller with SLO evaluation
+- MLS/TreeKEM option for PCS zones
+- Device-aware execution planner and migration
+
 ### Phase 1: Core Mesh (MVP)
 - MeshNode with Tailscale discovery
 - Symbol request/delivery
 - Basic zone isolation
 - RaptorQ for objects > 1KB
````

---

# Extra “smaller but high-impact” fixes I strongly recommend (no diffs unless you want them)

1. **Clarify epoch usage**: Right now epoch is used in AAD and discussed as replay protection, but replay protection is actually driven by per-session `seq`. I’d explicitly say:

   * epoch is for batching + audit correlation,
   * replay protection is MAC+seq with bounded window.

2. **Make planner scoring non-normative**: You label a lot of execution-planner behavior “NORMATIVE” while using floats and heuristic scoring. That’s a recipe for “different nodes disagree about where to execute” and hard-to-debug behavior. Better:

   * define *inputs* (device profile, constraints) as normative,
   * define *decision algorithm* as implementation-defined.

3. **Define a strict parsing / allocation policy** for FCPS and control-plane objects:

   * maximum symbol_count,
   * maximum object sizes by schema class,
   * hard caps for “bytes to attempt decode before abort”.

4. **Connector identity binding**: you already have `aud_binary`—I’d also require that `OperationReceipt` includes:

   * connector_id,
   * aud_binary,
   * connector instance id,
   * sandbox profile hash,
     so receipts remain meaningful even after upgrades.

---

# If you want the next iteration from me

I can do a second pass where I:

* **tighten the normative language** (MUST/SHOULD) to remove ambiguity,
* **scan for internal inconsistencies** (there are a few more like bps vs floats, some pseudocode using undefined functions, etc.),
* propose a minimal but complete **end-to-end “happy path” sequence diagram** (device enrollment → zone key distribution → install connector → invoke operation → receipt → audit head advance → revocation).

Just paste any additional project docs you consider part of “the plan” (like `docs/fcp_model_connectors_rust.md`), and I’ll fold them into the same style of change list + diffs.

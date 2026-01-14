I’m going to treat the `README.md` that appears inside your `{{SPEC}}` block as the README you referenced in `{{README}}` (since that placeholder wasn’t expanded here).

Below are the highest‑leverage revisions I’d make to improve **correctness, security, interoperability, operational reliability, performance, and “this is actually usable”**—with (1) rationale and (2) a git‑diff style patch for each.

---

## 1) Fix FCPS framing mismatches + make nonce/instance requirements actually implementable (and MTU-safe)

### What’s wrong / risky now

* **README vs Spec disagree** on FCPS header sizes and ZoneId hash length (README uses 16‑byte zone hash and a 90‑byte header; Spec uses 32‑byte zone hash and 106‑byte header). That’s an interop footgun.
* Your **symbol encryption design requires `sender_instance_id`** (for reboot safety and per‑sender subkeys), but **the FCPS on-wire format doesn’t carry it**. Implementers will either:

  * accidentally omit it (breaking reboot safety), or
  * smuggle it elsewhere inconsistently (breaking interop).
* You currently include a **separate checksum (XXH3-64)** even though you already have **per-symbol AEAD tags + per-frame session MAC**. The checksum costs 8 bytes of MTU budget you can repurpose for `sender_instance_id` without increasing frame size.

### Proposed change

* Make ZoneId hash **consistently 32 bytes** everywhere.
* Add `sender_instance_id` (8 bytes) to the FCPS header.
* Remove the redundant XXH3 checksum from FCPS.
* Update pseudocode that referenced `verify_checksum()`.

### Why it’s better

* **Interop correctness**: one frame layout, one truth.
* **Crypto correctness**: reboot-safety field exists on wire.
* **Performance**: no wasted checksum work; keep MTU budget stable.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
- Bytes 50-57:  Zone Key ID (8 bytes, for rotation)
- Bytes 58-73:  Zone ID hash (16 bytes)
- Bytes 74-81:  Epoch ID (u64 LE)
- Bytes 82-89:  Frame Seq (u64 LE, per-sender monotonic counter)
- Bytes 90+:    Symbol payloads (encrypted, concatenated)
- Final 8:      Checksum (XXH3-64)
+ Bytes 50-57:  Zone Key ID (8 bytes, for rotation)
+ Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; fixed-size)
+ Bytes 90-97:  Epoch ID (u64 LE)
+ Bytes 98-105: Sender Instance ID (u64 LE, reboot-safety for deterministic nonces)
+ Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic counter)
+ Bytes 114+:   Symbol payloads (encrypted, concatenated)
@@
- Fixed header: 90 bytes
+ Fixed header: 114 bytes
@@
- Final 8:      Checksum (XXH3-64)
+ NOTE: No separate checksum. Integrity is provided by:
+   • per-symbol AEAD auth tags
+   • per-frame session MAC (AuthenticatedFcpsFrame)
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
-│  Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; see §3.4)                    │
-│  Bytes 90-97:  Epoch ID (u64 LE)                                            │
-│  Bytes 98-105: Frame Seq (u64 LE, per-sender monotonic)                     │
-│  Bytes 106+:   Symbol payloads (concatenated)                               │
-│  Final 8:      Checksum (XXH3-64)                                           │
-│                                                                             │
-│  Fixed header: 106 bytes                                                    │
+│  Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; see §3.4)                    │
+│  Bytes 90-97:  Epoch ID (u64 LE)                                            │
+│  Bytes 98-105: Sender Instance ID (u64 LE)                                  │
+│  Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic)                    │
+│  Bytes 114+:   Symbol payloads (concatenated)                               │
+│                                                                             │
+│  Fixed header: 114 bytes                                                    │
@@
-  Final 8:      Checksum (XXH3-64)
+  NOTE (NORMATIVE): Implementations MUST NOT require a separate checksum.
+  Frame integrity is guaranteed by the MeshSession MAC (data-plane) and the
+  per-symbol AEAD tags (content-plane).
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 impl MeshNode {
     /// Handle incoming symbol frame
     pub async fn handle_symbols(&self, frame: FcpsFrame) -> Result<()> {
-        // Verify frame integrity
-        frame.verify_checksum()?;
+        // NORMATIVE: FCPS datagrams MUST be authenticated at the session layer
+        // (MeshSession MAC) before parsing symbols.
```

---

## 2) Define the actual on-wire FCPS datagram envelope and make MTU rules unambiguous

### What’s wrong / risky now

You specify a 1200-byte “max datagram” rule, but it’s unclear whether that limit applies to:

* FCPS frame bytes alone, or
* FCPS frame bytes **plus** the session MAC envelope.

This ambiguity will cause real-world fragmentation and interop mismatch.

### Proposed change

* Add a **NORMATIVE FCPS datagram envelope** format (session_id/seq/mac + fcps bytes).
* Clarify that `max_datagram_bytes` applies to the **entire UDP payload** (envelope + frame).

### Why it’s better

* Makes the MTU story **actually implementable** and consistent across QUIC DATAGRAM vs UDP.
* Avoids “works on LAN, dies on cellular/DERP” issues.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 4.2 Mesh Session Authentication (NORMATIVE)
@@
 pub struct AuthenticatedFcpsFrame {
     pub frame: FcpsFrame,
     pub source_id: TailscaleNodeId,
     pub session_id: [u8; 16],
     /// Monotonic sequence for anti-replay
     pub seq: u64,
@@
     pub mac: [u8; 16],
 }
+
+#### 4.2.2 FCPS Datagrams on the Wire (NORMATIVE)
+FCPS frames are carried inside an authenticated datagram envelope bound to a
+MeshSession.
+
+FCPS_DATAGRAM (on-wire):
+  Bytes 0-15:   session_id [16]
+  Bytes 16-23:  seq (u64 LE)
+  Bytes 24-39:  mac [16]  (Suite1/Suite2; truncated to 16 bytes)
+  Bytes 40..:   fcps_frame_bytes (exact FCPS frame bytes)
+
+MAC input (NORMATIVE):
+  mac = MAC(k_mac_dir, session_id || direction || seq || fcps_frame_bytes)[:16]
+
+MTU rule (NORMATIVE):
+  len(FCPS_DATAGRAM) MUST be <= max_datagram_bytes (default: 1200).
+  The limit applies to the FULL UDP payload, not just the inner FCPS frame.
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 4.3.1 MTU Safety and Frame Size Limits (NORMATIVE)
@@
-  Implementations MUST support sending FCPS frames that fit within a UDP payload of **≤ 1200 bytes**
+  Implementations MUST support sending FCPS_DATAGRAMs (see §4.2.2) that fit within a UDP payload of **≤ 1200 bytes**
```

---

## 3) Tighten Axiom 1 so it matches the design you actually describe (and prevents “religious” mis-implementations)

### What’s wrong / risky now

You state **“All data flows as RaptorQ symbols”**, but you *also* correctly introduce FCPC (control plane) as reliable stream framing.

Some implementers will take Axiom 1 literally and try to encode **everything** as symbols, causing:

* needless overhead for small control messages
* worse latency and complexity
* divergence from your own intended MVP profile

### Proposed change

Reframe Axiom 1 as:

* “All **durable mesh objects** are symbol-addressable and distributable as symbols.”
* Control-plane traffic may travel via FCPC, but the canonical representation remains a content-addressed object.

### Why it’s better

* Keeps the philosophical model **without harming performance**.
* Makes it clearer what is “symbol-native” vs “symbol-transported”.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
-| **Universal Fungibility** | All data flows as RaptorQ symbols. Any K' symbols reconstruct the original. No symbol is special. |
+| **Universal Fungibility** | All **durable mesh objects** are symbol-addressable: any K' symbols reconstruct the canonical object bytes. Control-plane messages MAY travel over FCPC streams for efficiency, but the canonical representation is still a content-addressed mesh object. |
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
-### 2.1 Axiom 1: Universal Fungibility
-**All data flows as RaptorQ symbols. Symbols are interchangeable.**
+### 2.1 Axiom 1: Universal Fungibility
+**All durable mesh objects are symbol-addressable, and symbols are interchangeable.**
+
+NORMATIVE clarification:
+- Any object that is persisted, audited, cached, mirrored, or pinned MUST have a canonical
+  content-addressed representation that can be distributed as symbols.
+- Control-plane delivery MAY use FCPC streams for small messages, but those messages MUST still
+  be representable as canonical mesh objects (SchemaHash-prefixed deterministic CBOR).
```

---

## 4) Replace `ZoneFrontier` with a quorum-signed `ZoneCheckpoint` that is safe to use for *freshness*, *GC roots*, and *offline policy*

### What’s wrong / risky now

`ZoneFrontier` is doing too many jobs:

* GC root pointer
* “freshness” basis for revocation gating
* fast sync checkpoint

…but it is **only node-signed**, which creates a subtle but real vulnerability in degraded/offline enforcement:

A compromised zone member could publish a “fresh-looking” frontier referencing older revocation state, undermining your stale-frontier gating logic.

### Proposed change

Introduce `ZoneCheckpoint`:

* A **quorum-signed** checkpoint object per zone
* References the heads that define enforceable state:

  * revocation head
  * audit head
  * zone definition head
  * policy head
  * active zone key manifest
* Acts as the **single GC root** (so reachability GC is well-defined)
* Tokens bind to a checkpoint (next change)

### Why it’s better

* Freshness checks become **Byzantine-resilient** under your own n/f model.
* GC roots become **semantically meaningful** (“live system state”), not “whatever last node wrote”.
* Offline behavior is cleaner: “do we have a recent checkpoint quorum?” is a crisp condition.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
-### 3.8 ZoneFrontier as the Root Pointer (NORMATIVE)
-ZoneFrontier is the compact, signed pointer to the current "heads" that define a zone's live object graph.
+### 3.8 ZoneCheckpoint as the Root Pointer (NORMATIVE)
+ZoneCheckpoint is the quorum-signed pointer to the current "heads" that define a zone's enforceable
+state AND its live object graph (GC root).
@@
-pub struct ZoneFrontier {
+pub struct ZoneCheckpoint {
     pub header: ObjectHeader,
     pub zone_id: ZoneId,
-    /// Latest revocation head
-    pub rev_head: ObjectId,
-    pub rev_seq: u64,
-    /// Latest audit head
-    pub audit_head: ObjectId,
-    pub audit_seq: u64,
-    /// Current epoch
-    pub as_of_epoch: EpochId,
-    /// Signature by executing node
-    pub signature: Signature,
+    /// Enforceable heads (NORMATIVE):
+    pub rev_head: ObjectId,
+    pub rev_seq: u64,
+    pub audit_head: ObjectId,
+    pub audit_seq: u64,
+
+    /// Policy/config heads (NORMATIVE):
+    pub zone_definition_head: ObjectId,
+    pub zone_policy_head: ObjectId,
+    pub active_zone_key_manifest: ObjectId,
+
+    /// Monotonic checkpoint sequence (NORMATIVE; per-zone)
+    pub checkpoint_seq: u64,
+    pub as_of_epoch: EpochId,
+
+    /// Quorum signatures (NORMATIVE; sorted by node_id per §3.5.1)
+    pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
 }
@@
-**Implementation Requirements (NORMATIVE):**
-1. Store ZoneFrontier objects as normal mesh objects (content-addressed)
-2. Pin the latest frontier per zone
-3. Refuse to accept tokens/approvals referencing revocation state newer than the latest known frontier (must fetch first)
+**Implementation Requirements (NORMATIVE):**
+1. Store ZoneCheckpoint objects as normal mesh objects (content-addressed)
+2. Pin the latest checkpoint per zone (GC root)
+3. A node MUST NOT accept a checkpoint whose (rev_seq, audit_seq, checkpoint_seq) regresses
+   relative to its current pinned checkpoint.
+4. Tokens/approvals that bind to checkpoint_seq MUST NOT be accepted unless the verifier has
+   checkpoint_seq >= the bound value (or explicitly enters degraded mode).
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
-// NORMATIVE: ZoneFrontier is the canonical zone root pointer.
-// Nodes MUST keep the latest ZoneFrontier pinned for each active zone.
-let mut roots = HashSet::new();
-if let Some(frontier) = self.get_latest_zone_frontier(zone_id) {
-    roots.insert(frontier);
-}
+// NORMATIVE: ZoneCheckpoint is the canonical zone root pointer.
+// Nodes MUST keep the latest ZoneCheckpoint pinned for each active zone.
+let mut roots = HashSet::new();
+if let Some(chk) = self.get_latest_zone_checkpoint(zone_id) {
+    roots.insert(chk);
+}
```

And update README’s mentions:

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
-  • ZoneFrontier checkpoints for fast sync
+  • ZoneCheckpoint quorum checkpoints for fast sync + GC roots + freshness
```

---

## 5) Bind capability tokens to a `ZoneCheckpoint` and fix token field inconsistencies (holder_node, claim types)

### What’s wrong / risky now

* Tokens currently bind to `rev_head`/`rev_seq` only. That’s good for revocation freshness, but:

  * it does **not bind policy/config freshness** (zone definition/policy changes)
  * it does not tie to the specific “enforceable snapshot” you want nodes to rely on
* There’s a **spec inconsistency**: `holder_node` is required in the struct, but optional in the CWT claim table and pseudocode.
* Your CWT example uses `iss` as bytes (`iss_zone.as_bytes()`), which will cause cross-language incompatibility (CWT `iss` is typically a text string). If you want bytes, specify explicitly; better: use the ZoneId string.

### Proposed change

* Replace `rev_head`/`rev_seq` in CapabilityToken with:

  * `chk_id` (ZoneCheckpoint object id)
  * `chk_seq` (checkpoint_seq)
* Make `holder_node` optional:

  * REQUIRED for Risky/Dangerous operations
  * OPTIONAL for Safe operations (reduces ceremony)
* Make CWT claim types explicit:

  * `iss` as text string ZoneId (`"z:private"`, etc)

### Why it’s better

* Tokens become **freshness-correct** across revocations *and* policy/config.
* Eliminates interop mismatches and “optional-but-not” confusion.
* Lets safe/read-only flows be simpler while keeping strictness where it matters.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct CapabilityToken {
@@
-    /// Revocation head the issuer considered (NORMATIVE)
-    /// Verifiers MUST have revocation state >= this head or fetch before acceptance.
-    pub rev_head: ObjectId,
-    /// Monotonic revocation sequence at rev_head (NORMATIVE)
-    /// Enables O(1) freshness checks: verifier compares rev_seq, not chain traversal.
-    pub rev_seq: u64,
+    /// Zone checkpoint the issuer considered (NORMATIVE)
+    /// Verifiers MUST have checkpoint_seq >= this value (or fetch/enter degraded mode).
+    pub chk_id: ObjectId,
+    pub chk_seq: u64,
@@
-    /// The only node allowed to present this token (sender-constrained)
-    pub holder_node: TailscaleNodeId,
+    /// Optional sender constraint (NORMATIVE: REQUIRED for Risky/Dangerous)
+    pub holder_node: Option<TailscaleNodeId>,
@@
 }
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 **CWT Registered Claims (payload map):**
@@
-| `1` | iss | `iss_zone` | Issuing zone identifier |
+| `1` | iss | `iss_zone` | Issuing zone identifier (text string ZoneId, e.g. "z:private") |
@@
 **FCP Private Claims (payload map):**
@@
-| `1005` | `rev_head` | bytes | Revocation chain head |
-| `1006` | `rev_seq` | uint | Revocation sequence number |
+| `1005` | `chk_id` | bytes | ZoneCheckpoint ObjectId (32 bytes) |
+| `1006` | `chk_seq` | uint | ZoneCheckpoint monotonic sequence |
@@
-| `1004` | `holder_node` | bytes | Holder's public key (optional) |
+| `1004` | `holder_node` | bytes | Holder node id (optional; REQUIRED for Risky/Dangerous) |
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 impl CapabilityToken {
@@
-        // Enforce that issuing node is authorized to mint tokens for this zone
+        // Enforce that issuing node is authorized to mint tokens for this zone
         trust_anchors.enforce_token_issuer_policy(&self.iss_zone, &self.iss_node)?;
+
+        // NORMATIVE: Freshness binding via ZoneCheckpoint
+        trust_anchors.require_checkpoint_seq(self.iss_zone.clone(), self.chk_seq)?;
@@
     }
 }
```

---

## 6) Model *external side effects* and *resource visibility* explicitly (confidentiality isn’t only “zone-to-zone”)

### What’s wrong / risky now

Your confidentiality model is strong **inside the mesh**, but many real leaks are **mesh → external world**, e.g.:

* posting to Twitter
* commenting on a public GitHub repo
* sending email to an external recipient
* writing to a public Discord channel

Right now, unless you force those connectors to live in low-confidentiality zones 100% of the time (which isn’t always true), you don’t have a principled mechanism to prevent “private data accidentally written to public external resource”.

### Proposed change

Introduce **Resource classification** that connectors must attach to `ResourceObject`s:

* `resource_integrity_level`
* `resource_confidentiality_level`
* `resource_taint` (e.g., PUBLIC_INPUT)

Then require that operations which write to external resources:

* reference a `ResourceObject` handle (instead of raw IDs/URIs), and
* MeshNode enforces **declassification** if `input_confidentiality > resource_confidentiality_level`.

### Why it’s better

* You close the biggest remaining “practical security gap” without relying on prompt rules.
* It’s also more usable: “public vs private repo/channel” becomes a **mechanical fact**, not a policy guessing game.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct ResourceObject {
     pub header: ObjectHeader,
@@
     /// Original URI (for connector-internal use)
     pub resource_uri: String,
+
+    /// External resource classification (NORMATIVE)
+    /// Used for information-flow enforcement when writing to external systems.
+    pub resource_integrity_level: u8,
+    pub resource_confidentiality_level: u8,
+    pub resource_taint: TaintFlags,
@@
     /// Connector signature over resource metadata
     pub signature: Signature,
 }
```

Update invoke enforcement pseudocode to incorporate sink checks:

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
         // 2d. Enforce confidentiality downgrades (NORMATIVE)
-        // If the operation produces outputs into a zone with lower confidentiality than
-        // the data label, require a valid declassification ApprovalToken.
-        if self.operation_writes_to_lower_confidentiality(&request).await? {
+        // If the operation writes to a lower-confidentiality sink (another zone OR
+        // an external resource classified by ResourceObject), require a valid
+        // declassification ApprovalToken.
+        if self.operation_writes_to_lower_confidentiality(&request).await?
+            || self.operation_writes_to_lower_confidentiality_resource_sink(&request).await? {
             let declass = request.approval_tokens.iter()
                 .find(|t| matches!(t.scope, ApprovalScope::Declassification { .. }))
                 .ok_or(Error::DeclassificationRequired)?;
             declass.verify(&self.trust_anchors)?;
         }
```

Update the manifest example to stop using raw `chat_id` and instead use a resource handle:

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 [provides.operations.telegram_send_message]
 description = "Send a message to a Telegram chat"
 capability = "telegram.send_message"
@@
-input_schema = { type = "object", required = ["chat_id", "text"] }
+input_schema = { type = "object", required = ["chat_resource", "text"] }
 output_schema = { type = "object", required = ["message_id"] }
 network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, spki_pins = ["base64:..."] }
```

And in README, call this out as a core safety feature:

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 | **ResourceObject** | Zone-bound handle for external resources (files, repos, APIs) enabling auditable access control |
+| **Resource Visibility Enforcement** | ResourceObjects carry public/private classification; MeshNode enforces declassification when writing higher-confidentiality data to lower-confidentiality external resources |
```

---

## 7) Make interactive approvals non-confusable by binding them to a specific request/intent + input hash

### What’s wrong / risky now

Your ApprovalToken is good, but `ApprovalScope::Execution` is currently:

* pattern-based (`method_pattern`)
* optionally constraint-based (`input_constraints: Option<String>`)

That’s vulnerable to “approval confusion”:

* user thinks they approved posting “X”
* agent reuses the same approval token to post “Y”

### Proposed change

For interactive approvals:

* ApprovalToken MUST bind to **a specific `InvokeRequest` mesh object id** (or `OperationIntent` id).
* Include `input_hash` (BLAKE3 of canonical input bytes) so even if request ids collide, content doesn’t.

Also: replace free-form `input_constraints: Option<String>` with a small typed constraint grammar (interop-safe).

### Why it’s better

* Prevents TOCTOU and approval replay.
* Makes approval UX safer and simpler: “approve this exact thing.”

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub enum ApprovalScope {
@@
     Execution {
         /// Connector or method being approved
         connector_id: ConnectorId,
         /// Specific method or wildcard
         method_pattern: String,
-        /// Input constraints (JSON-path predicates, etc.)
-        input_constraints: Option<String>,
+        /// NORMATIVE: For Interactive approvals on Risky/Dangerous ops, this MUST be set.
+        request_object_id: Option<ObjectId>,
+        /// NORMATIVE: BLAKE3 hash of canonical input bytes (schema-prefixed CBOR).
+        input_hash: Option<[u8; 32]>,
+        /// Typed constraints (interop-safe)
+        input_constraints: Vec<InputConstraint>,
     },
 }
+
+/// Input constraint (NORMATIVE)
+/// JSON Pointer (RFC 6901) only; JSONPath/regex are forbidden for interop stability.
+pub struct InputConstraint {
+    pub json_pointer: String,
+    pub op: ConstraintOp,
+    pub value: Value,
+}
+pub enum ConstraintOp { Eq, Neq, In, NotIn, Prefix, Suffix, Contains }
```

---

## 8) Add canonical identifier grammar for PrincipalId/ConnectorId/CapabilityId/etc. (prevents confusion attacks and cross-language drift)

### What’s wrong / risky now

ZoneId has strict canonicalization rules; most other identifiers do not.

That opens:

* Unicode confusables (`ρaypal.*` vs `paypal.*`)
* case-folding differences
* delimiter ambiguity
* policy glob mismatch across implementations

### Proposed change

Define NORMATIVE grammar + normalization rules for:

* `PrincipalId`
* `ConnectorId`
* `CapabilityId`
* `OperationId`
* `RoleId`
* `SecretId`
* `CredentialId`
* `InstanceId`

### Why it’s better

* Avoids security policy bypass via string tricks.
* Improves deterministic policy evaluation and hashing.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 3.4 ZoneId
@@
 impl ZoneId {
@@
 }
+
+### 3.4.2 Canonical Identifier Formats (NORMATIVE)
+To prevent confusion attacks and cross-implementation drift, the following identifiers MUST be:
+- ASCII only
+- lowercase only
+- length <= 128 bytes
+- match regex: `^[a-z0-9][a-z0-9._:-]*$`
+
+Identifiers covered:
+- PrincipalId
+- ConnectorId
+- CapabilityId
+- OperationId
+- RoleId
+- SecretId
+- CredentialId
+- InstanceId
+
+Implementations MUST reject non-canonical forms (do not normalize silently).
```

---

## 9) Upgrade the egress proxy from “HTTP helper” to a general **Network Guard** (needed for Postgres/Redis/etc) + harden hostname/DNS rules

### What’s wrong / risky now

You list connectors like `fcp.postgresql`, `fcp.redis`, etc., but the “strict/moderate sandbox” model routes network via an HTTP-shaped proxy (`EgressHttpRequest`). For non-HTTP connectors, implementers will either:

* grant `network.raw_outbound` (undoing your SSRF model), or
* build bespoke proxy hacks per connector.

Also: hostname enforcement must be **canonicalized** (IDNA, trailing dots, IP literals) or you’ll get SSRF bypasses.

### Proposed change

* Define `EgressRequest` with `Http` and `TcpConnect` at minimum (TLS optional).
* Add **NORMATIVE hostname canonicalization** rules and explicit `deny_ip_literals` default.

### Why it’s better

* Makes your “secretless connectors + strict sandbox” story apply to *databases and queues*, not just HTTP APIs.
* Closes real SSRF bypasses.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct NetworkConstraints {
@@
     pub spki_pins: Vec<String>,
+
+    /// NORMATIVE: deny IP literals unless explicitly allowed (default: true)
+    pub deny_ip_literals: bool,
+    /// NORMATIVE: hostnames MUST be canonicalized (lowercase, IDNA2008, no trailing dot)
+    pub require_host_canonicalization: bool,
 }
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct EgressHttpRequest {
     pub method: String,
     pub url: String,
@@
     pub credential: Option<CredentialId>,
 }
+
+/// General egress request (NORMATIVE)
+pub enum EgressRequest {
+    Http(EgressHttpRequest),
+    TcpConnect(EgressTcpConnectRequest),
+}
+
+pub struct EgressTcpConnectRequest {
+    pub host: String,
+    pub port: u16,
+    pub use_tls: bool,
+    pub sni: Option<String>,
+    pub spki_pins: Vec<String>,
+    pub credential: Option<CredentialId>,
+}
```

---

## 10) Add optional device posture / hardware-backed key requirements for sensitive zones (owner/private)

### What’s wrong / risky now

You already have threshold signing and sealed key distribution, but you’re missing a very practical control:

* “Only devices with hardware-backed keys / verified posture can join z:owner.”

Without it, one compromised “weak” device can still become a high-value zone participant (even if the owner key is threshold).

### Proposed change

* Extend `NodeKeyAttestation` and/or `DeviceEnrollment` to optionally carry a `DevicePostureAttestation`.
* Add policy that certain zones require posture class.

### Why it’s better

* Stronger defense for z:owner and secret shares.
* Useful for “laptop is OK, random VM is not”.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct NodeKeyAttestation {
@@
     pub signature: Signature,
+
+    /// Optional device posture proof (NORMATIVE when zone policy requires it)
+    pub device_posture: Option<DevicePostureAttestation>,
 }
+
+pub struct DevicePostureAttestation {
+    pub kind: DevicePostureKind,
+    pub payload: Vec<u8>,
+    pub issued_at: u64,
+}
+
+pub enum DevicePostureKind {
+    TpmQuote,
+    SecureEnclave,
+    AndroidKeystore,
+    Custom(String),
+}
```

---

## 11) Harden registry security with TUF-style anti-rollback + Sigstore/cosign option

### What’s wrong / risky now

You have signatures + transparency logs, which is great. But registries are still vulnerable to classic distribution attacks:

* freeze/rollback (serve an older vulnerable version)
* mix-and-match metadata (serve valid but inconsistent sets)

Transparency logs help detect some of this, but **TUF is purpose-built** for this layer.

### Proposed change

Add an optional registry mode with:

* TUF root metadata pinned in z:owner
* snapshot/timestamp metadata checks
* optional Sigstore/cosign verification for artifacts

### Why it’s better

* Dramatically improves “install/update safely under partial compromise.”
* Matches your sovereignty/offline goals (TUF metadata can be mirrored and pinned too).

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub enum RegistrySource {
@@
 }
+
+/// Optional registry security profile (NORMATIVE when configured)
+pub struct RegistrySecurityProfile {
+    /// If present, registry clients MUST enforce TUF snapshot/timestamp semantics.
+    pub tuf_root_object_id: Option<ObjectId>,
+    /// If true, verify Sigstore/cosign signatures in addition to publisher/registry keys.
+    pub require_sigstore: bool,
+}
```

---

## 12) Add manifest “interface hash” + explicit compatibility gates (prevents silent breakage across upgrades)

### What’s wrong / risky now

You have versions, but you don’t have a **machine-checkable compatibility contract** between:

* connector operation schemas
* capability catalog
* state model expectations

So upgrades can silently break agents or state migration.

### Proposed change

Add:

* `interface_hash` (hash of canonical manifest “API surface”: operations + schemas + capability requirements)
* `min_mesh_version` / `min_protocol_version`
* `state_schema_version` and optional migration hints

### Why it’s better

* Enables safe rollout/rollback.
* Makes “this connector is compatible with this mesh” enforceable.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 [manifest]
 format = "fcp-connector-manifest"
 schema_version = "2.0"
+min_mesh_version = "2.0.0"
+min_protocol = "fcp2-sym"
+interface_hash = "blake3:..."
@@
 [connector]
 id = "fcp.telegram"
 name = "Telegram Connector"
 version = "2026.1.0"
@@
 [connector.state]
 model = "singleton_writer"
+state_schema_version = "1"
+migration_hint = "If upgrading from state_schema_version=0, run telegram/state_migrate_v0_to_v1"
```

---

## 13) Make the project more compelling operationally: add an explicit “Ops & Debugging” toolchain story in README

### What’s missing now

You have a lot of primitives (audit chain, DecisionReceipts, repair controller), but the README doesn’t yet sell the “I can actually run this day-to-day” story:

* How do I know I’m safe?
* How do I see why something was denied?
* How do I see offline coverage and repair status?
* How do I detect forks, drift, degraded mode?

### Proposed change

Add an “Ops & Debugging” section in README with concrete CLI commands and outputs.

### Why it’s better

* Makes the project feel *real* and shippable.
* Converts security primitives into an operational UX.

### Diff

````diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 ## Performance Targets
@@
 The reference implementation ships a `fcp bench` suite that produces machine-readable results (JSON) for regression tracking.
+
+---
+## Ops & Debugging
+FCP is designed to be *operable* without disabling security. The CLI exposes the core safety/availability loops:
+
+```bash
+# Explain why an operation was denied (DecisionReceipt-backed)
+fcp explain --request <objectid>
+
+# Show revocation/checkpoint freshness and degraded mode state
+fcp doctor --zone z:private
+
+# Show offline availability SLOs and symbol coverage by placement policy
+fcp repair status --zone z:work
+
+# Tail audit events (per zone) with trace correlation
+fcp audit tail --zone z:owner
+```
+
+Key principle: **if you can’t explain a denial or quantify offline availability, the system isn’t finished.**
````

---

# If you only adopt 3 changes, make them these

1. **FCPS framing fixes + sender_instance_id on wire (and remove checksum)**
   This is an interop + crypto correctness must-have.

2. **Resource visibility classification + enforcement**
   This closes the “real world exfiltration” gap that otherwise undermines the confidentiality lattice.

3. **Quorum-signed ZoneCheckpoint + token binding to it**
   This turns “freshness policy” into something robust under your stated Byzantine assumptions.

---

If you want, I can also produce a “consolidated patch” that applies all the above as one unified diff (instead of per-change diffs), but the per-change breakdown above is usually easier to integrate round-by-round in APR.

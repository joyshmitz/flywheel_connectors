I reviewed the **README.md** and **FCP_Specification_V2.md** you included in `{{SPEC}}` (the `{{README}}` placeholder appears to correspond to that README.md). The design is already unusually cohesive: “explicit authority” + zones + symbol-first offline resilience + strong revocation/audit primitives is a compelling, differentiable stack.

The biggest opportunities I see are **(a)** removing a few correctness/consistency footguns that could bite implementers, **(b)** hardening the largest DoS surfaces (handshake + unreferenced symbol/object ingestion), and **(c)** making policy/tokens/leases more *deterministic, explainable, and interoperable* without losing the “mesh-native” character.

Below are my best proposed revisions. Each one includes a rationale and a git-diff-style patch against the plan text you posted.

---

## 1) Make zone identity + AEAD algorithm/nonce schedule coherent and fixed-size

### Why this makes the project better

Right now there are two subtle but important problems:

1. **Zone ID hash size + ambiguity:**
   The wire format uses a **16-byte truncated hash** for “Zone ID hash” (in README/spec). That’s *probably* fine statistically, but it creates an avoidable “catastrophic-but-rare” class of bug: a collision could route a frame to the wrong keyring/zone selection logic. When the whole story is cryptographic boundaries and mechanical enforcement, it’s worth spending 16 more bytes to remove that footgun.

2. **Algorithm agility vs nonce derivation mismatch:**
   You list `ZoneKeyAlgorithm::{ChaCha20Poly1305, XChaCha20Poly1305}`, but the symbol nonce derivation is hard-coded to **12 bytes** (`frame_seq || esi`), which is compatible with ChaCha20-Poly1305 but not XChaCha20-Poly1305 (24-byte nonce). That’s an implementer trap.

This change makes wire framing *constant-size and unambiguous*, and makes algorithm agility *actually implementable*, which increases reliability and reduces interop failures.

### Diff

````diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
-│  Bytes 58-73:  Zone ID hash (16 bytes)                                      │
-│  Bytes 74-81:  Epoch ID (u64 LE)                                            │
-│  Bytes 82-89:  Frame Seq (u64 LE, per-sender monotonic counter)             │
-│  Bytes 90+:    Symbol payloads (encrypted, concatenated)                    │
+│  Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3)                              │
+│  Bytes 90-97:  Epoch ID (u64 LE)                                            │
+│  Bytes 98-105: Frame Seq (u64 LE, per-sender monotonic counter)             │
+│  Bytes 106+:   Symbol payloads (encrypted, concatenated)                    │
@@
-│  Fixed header: 90 bytes                                                     │
+│  Fixed header: 106 bytes                                                    │
+│                                                                             │
+│  NOTE: On-wire framing + per-symbol AEAD AAD use fixed-size ZoneIdHash      │
+│  (not variable-length zone strings). This avoids ambiguity and removes      │
+│  a DoS footgun where a malicious peer could force large AADs.               │
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 3.4 ZoneId
 Cryptographic namespace identifier:
 ```rust
 /// Zone identifier (NORMATIVE)
+///
+/// NORMATIVE: ZoneId strings MUST be:
+/// - UTF-8
+/// - <= 64 bytes
+/// - restricted to ASCII `[a-z0-9:_-]` for cross-implementation stability
 #[derive(Clone, PartialEq, Eq, Hash)]
 pub struct ZoneId(String);
 
+/// Fixed-size ZoneId hash (NORMATIVE)
+/// Used for:
+/// - FCPS/FCPC constant-size framing
+/// - AEAD associated data (AAD) to avoid variable-length DoS footguns
+#[derive(Clone, Copy, PartialEq, Eq, Hash)]
+pub struct ZoneIdHash([u8; 32]);
+
+impl ZoneIdHash {
+    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
+}
+
 impl ZoneId {
@@
+    /// Raw bytes of canonical ZoneId string (NORMATIVE)
+    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }
+
+    /// Fixed-size hash of ZoneId (NORMATIVE)
+    pub fn hash(&self) -> ZoneIdHash {
+        let mut h = blake3::Hasher::new();
+        h.update(b"FCP2-ZONE-ID-V1");
+        h.update(self.as_bytes());
+        ZoneIdHash(*h.finalize().as_bytes())
+    }
@@
 ### 4.1 Symbol Envelope
@@
-/// Derive per-symbol nonce from frame_seq and ESI (NORMATIVE)
-///
-/// nonce = frame_seq_le[0..8] || esi_le[0..4]
-/// Combined with per-sender subkeys, this eliminates nonce-collision risk across senders.
-fn derive_nonce(frame_seq: u64, esi: u32) -> [u8; 12] {
-    let mut nonce = [0u8; 12];
-    nonce[0..8].copy_from_slice(&frame_seq.to_le_bytes());
-    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
-    nonce
-}
+/// Derive AEAD nonce deterministically (NORMATIVE).
+///
+/// - ChaCha20-Poly1305 (12-byte): nonce12 = frame_seq_le || esi_le
+/// - XChaCha20-Poly1305 (24-byte): nonce24 = sender_instance_id_le || frame_seq_le || esi_le || 0u32
+fn derive_nonce12(frame_seq: u64, esi: u32) -> [u8; 12] {
+    let mut nonce = [0u8; 12];
+    nonce[0..8].copy_from_slice(&frame_seq.to_le_bytes());
+    nonce[8..12].copy_from_slice(&esi.to_le_bytes());
+    nonce
+}
+fn derive_nonce24(sender_instance_id: u64, frame_seq: u64, esi: u32) -> [u8; 24] {
+    let mut nonce = [0u8; 24];
+    nonce[0..8].copy_from_slice(&sender_instance_id.to_le_bytes());
+    nonce[8..16].copy_from_slice(&frame_seq.to_le_bytes());
+    nonce[16..20].copy_from_slice(&esi.to_le_bytes());
+    nonce[20..24].copy_from_slice(&0u32.to_le_bytes());
+    nonce
+}
@@
 impl SymbolEnvelope {
@@
     pub fn encrypt(
@@
     ) -> Self {
-        // NORMATIVE: derive nonce from frame_seq || esi_le
-        let nonce = derive_nonce(frame_seq, esi);
-
         // Associated data binds symbol to context INCLUDING key_id for rotation safety
         let aad = Self::build_aad(&object_id, esi, k, &zone_key.zone_id, zone_key.key_id, epoch);
 
-        // NORMATIVE: encrypt under a per-sender subkey derived from the zone key.
-        // This prevents nonce collision across different senders.
-        // sender_instance_id ensures reboot-safety: new instance = new subkey.
-        let sender_key = zone_key.derive_sender_subkey(&source_id, sender_instance_id);
-        let (ciphertext, auth_tag) = zone_key.encrypt_with_subkey(&sender_key, plaintext, &nonce, &aad);
+        // NORMATIVE: encrypt under per-sender subkey + algorithm-specific deterministic nonce
+        let sender_key = zone_key.derive_sender_subkey(&source_id, sender_instance_id);
+        let (ciphertext, auth_tag) = match zone_key.algorithm {
+            ZoneKeyAlgorithm::ChaCha20Poly1305 => {
+                let nonce = derive_nonce12(frame_seq, esi);
+                zone_key.encrypt_with_subkey(&sender_key, plaintext, &nonce, &aad)
+            }
+            ZoneKeyAlgorithm::XChaCha20Poly1305 => {
+                let nonce = derive_nonce24(sender_instance_id, frame_seq, esi);
+                zone_key.encrypt_with_subkey(&sender_key, plaintext, &nonce, &aad)
+            }
+        };
@@
     pub fn decrypt(&self, zone_key: &ZoneKey) -> Result<Vec<u8>, CryptoError> {
@@
-        // NORMATIVE: derive nonce from frame_seq || esi_le
-        let nonce = derive_nonce(self.frame_seq, self.esi);
-
         let aad = Self::build_aad(
             &self.object_id,
             self.esi,
             self.k,
             &self.zone_id,
             self.zone_key_id,
             self.epoch_id
         );
 
-        // NORMATIVE: decrypt using per-sender subkey (includes sender_instance_id)
-        let sender_key = zone_key.derive_sender_subkey(&self.source_id, self.sender_instance_id);
-        zone_key.decrypt_with_subkey(&sender_key, &self.data, &nonce, &self.auth_tag, &aad)
+        let sender_key = zone_key.derive_sender_subkey(&self.source_id, self.sender_instance_id);
+        match zone_key.algorithm {
+            ZoneKeyAlgorithm::ChaCha20Poly1305 => {
+                let nonce = derive_nonce12(self.frame_seq, self.esi);
+                zone_key.decrypt_with_subkey(&sender_key, &self.data, &nonce, &self.auth_tag, &aad)
+            }
+            ZoneKeyAlgorithm::XChaCha20Poly1305 => {
+                let nonce = derive_nonce24(self.sender_instance_id, self.frame_seq, self.esi);
+                zone_key.decrypt_with_subkey(&sender_key, &self.data, &nonce, &self.auth_tag, &aad)
+            }
+        }
     }
@@
     fn build_aad(
@@
     ) -> Vec<u8> {
-        let mut aad = Vec::with_capacity(72);
+        let mut aad = Vec::with_capacity(96);
         aad.extend_from_slice(object_id.as_bytes());
         aad.extend_from_slice(&esi.to_le_bytes());
         aad.extend_from_slice(&k.to_le_bytes());
-        aad.extend_from_slice(zone_id.as_bytes());
+        // NORMATIVE: fixed-size zone hash avoids variable-length AAD ambiguity/DoS
+        aad.extend_from_slice(zone_id.hash().as_bytes());
         aad.extend_from_slice(&zone_key_id);  // Binds AAD to specific key version
         aad.extend_from_slice(&epoch.0.to_le_bytes());
         aad
     }
 }
@@
 ### 4.3 FCPS Frame Format
@@
-│  Bytes 58-73:  Zone ID hash (16 bytes, truncated SHA256)                    │
-│  Bytes 74-81:  Epoch ID (u64 LE)                                            │
-│  Bytes 82-89:  Frame Seq (u64 LE, per-sender monotonic)                     │
-│  Bytes 90+:    Symbol payloads (concatenated)                               │
+│  Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; see §3.4)                    │
+│  Bytes 90-97:  Epoch ID (u64 LE)                                            │
+│  Bytes 98-105: Frame Seq (u64 LE, per-sender monotonic)                     │
+│  Bytes 106+:   Symbol payloads (concatenated)                               │
@@
-│  Fixed header: 90 bytes                                                     │
+│  Fixed header: 106 bytes                                                    │
@@
 pub struct ZoneKey {
     pub zone_id: ZoneId,
     pub key_id: [u8; 8],
-    /// Randomly generated 256-bit symmetric key for ChaCha20-Poly1305 AEAD
+    pub algorithm: ZoneKeyAlgorithm,
+    /// Randomly generated 256-bit symmetric key for AEAD
     pub symmetric_key: [u8; 32],
     pub created_at: u64,
     pub expires_at: Option<u64>,
 }
@@
 pub enum ZoneKeyAlgorithm {
     ChaCha20Poly1305,
     XChaCha20Poly1305,
 }
@@
 pub struct RaptorQConfig {
     pub symbol_size: u16,        // Default: 1024
-    pub repair_ratio: f32,       // Default: 0.05
+    /// Repair ratio in basis points (NORMATIVE): 500 = 5%
+    pub repair_ratio_bps: u16,   // Default: 500
     pub max_object_size: u32,    // Default: 64MB
     pub decode_timeout: Duration, // Default: 30s
     /// If object size exceeds this threshold, it MUST use ChunkedObjectManifest
     pub max_chunk_threshold: u32, // Default: 256KB
     /// Chunk size for ChunkedObjectManifest
     pub chunk_size: u32,          // Default: 64KB
 }
````

---

## 2) Standardize capability token encoding using COSE/CWT to reduce signature/canonicalization footguns

### Why this makes the project better

Your “provable authority” idea hinges on tokens being verifiable across nodes and (eventually) languages. Custom token encodings are where interop breaks in practice: subtle differences in “signable bytes,” CBOR canonicalization, UUID encoding, or field ordering cause verification mismatches.

Using **COSE_Sign1** (for signatures) and **CWT** (for claim keys) gives you:

* widely-reviewed encoding rules,
* stable `kid`/`alg` headers,
* straightforward cross-language implementations,
* fewer bespoke cryptographic “gotchas.”

This doesn’t change your authority model; it makes it more robust.

### Diff

````diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
-| **Capability Tokens** | Provable authority with grant_object_ids linking to issuing attestations; mechanically verifiable chains |
+| **Capability Tokens (CWT/COSE)** | Provable authority with grant_object_ids; tokens are canonically CBOR-encoded and COSE-signed for interop and fewer verification footguns |
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 7.5 Capability Token (FCT)
 Short-lived token for operation invocation:
 ```rust
 /// Capability Token for operation invocation (NORMATIVE)
 pub struct CapabilityToken {
@@
     /// Ed25519 signature (by iss_node's issuance key)
     pub sig: [u8; 64],
 }
@@
 impl CapabilityToken {
@@
     pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), TokenError> {
@@
     }
 }
````

*

+#### 7.5.1 Token Encoding: CWT Claims in COSE_Sign1 (NORMATIVE)
+To reduce cross-language signature/canonicalization divergence, CapabilityToken MUST be serialized
+as a COSE_Sign1 structure whose payload is a deterministic CBOR map following CWT conventions.
+
+**COSE (protected headers):**
+- `alg`: EdDSA
+- `kid`: node_iss_kid (8 bytes) or a stable KID encoding chosen by implementation
+
+**CWT claim keys (payload map):**
+- `1` (iss): `iss_zone`
+- `2` (sub): `sub`
+- `3` (aud): `aud`
+- `4` (exp): `exp`
+- `6` (iat): `iat`
+- `7` (cti): `jti` (16-byte UUID)
+
+**FCP private claims (payload map):**
+- `1000`: `iss_node`
+- `1001`: `grant_object_ids` (array of 32-byte ObjectIds)
+- `1002`: `caps`
+- `1003`: `attenuation`
+- `1004`: `holder_node`
+- `1005`: `rev_head`
+- `1006`: `rev_seq`
+- `1007`: `aud_binary`
+
+NORMATIVE: Verification MUST validate the COSE signature using the attested node issuance key and
+then validate the semantic constraints exactly as described in §7.5 (grants ⊆ CapabilityObjects, revocation freshness, etc.).

````

---

## 3) Add an “object admission pipeline” with quarantine/promotion to harden against symbol/object flood DoS

### Why this makes the project better

Your spec already has **reachability GC**, but there’s still a classic distributed-store DoS:

- A malicious/compromised peer can inject vast numbers of **unreferenced ObjectIds** and symbols.
- Even if they are eventually GC’d, they can exhaust disk, gossip filters, and decoder queues in the meantime.
- The mesh needs a first-class distinction between:
  - **Admitted objects** (reachable from pinned roots / policy roots / explicitly requested), and
  - **Quarantined objects** (unknown provenance/reachability, bounded retention, not gossiped globally).

This is a very common real-world reliability requirement for content-addressed systems.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 │  │  Symbol Store                                                        │  │
 │  │  • Local symbol storage with node-local retention classes            │  │
+│  │  • Quarantine store for unreferenced objects (bounded; not gossiped) │  │
 │  │  • XOR filters + IBLT for efficient gossip reconciliation           │  │
 │  │  • Reachability-based garbage collection                             │  │
 │  │  • ObjectPlacementPolicy enforcement for availability SLOs          │  │
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 8.4 Admission Control and DoS Resistance (NORMATIVE)
@@
 **Anti-Amplification Rule (NORMATIVE):**
@@
 This prevents reflection/amplification attacks where an attacker spoofs requests to flood victims.
+
+#### 8.4.1 Unreferenced Object Quarantine (NORMATIVE)
+To prevent disk/memory exhaustion from injected, unreferenced ObjectIds, MeshNodes MUST implement
+an object admission pipeline:
+
+1. **Quarantine by default:** Symbols for unknown/unreferenced ObjectIds MUST be stored in a bounded
+   quarantine store with `RetentionClass::Ephemeral` and strict per-peer + per-zone quotas.
+2. **No global gossip for quarantined objects:** Quarantined ObjectIds MUST NOT be inserted into the
+   primary gossip filters/IBLT state until promoted (prevents filter pollution).
+3. **Promotion rule:** An object may be promoted from quarantine → admitted only if:
+   - It becomes reachable from the zone’s pinned `ZoneFrontier`, OR
+   - It is explicitly requested by an authenticated peer via a bounded request, OR
+   - It is explicitly pinned locally by user action/policy.
+4. **Schema-gated promotion:** Promotion MUST require successful reconstruction of the object header/body
+   and schema verification (prevents “garbage admitted as real objects”).
+
+```rust
+pub enum ObjectAdmissionClass {
+    Quarantined,
+    Admitted,
+}
+
+pub struct ObjectAdmissionPolicy {
+    pub max_quarantine_bytes_per_zone: u64, // default: 256MB
+    pub max_quarantine_objects_per_zone: u32, // default: 100_000
+    pub quarantine_ttl_secs: u64, // default: 3600
+}
+```
````

---

## 4) Fix and formalize ZonePolicy semantics (including a real connector allowlist) and remove invalid Tailscale ACL generation

### Why this makes the project better

There are two concrete issues here:

1. **ZonePolicy evaluation is incomplete:**
   `connectors_allow` exists but is never enforced. That’s a correctness bug: operators will assume allowlists apply.

2. **ACL generator tries to “deny connectors” in Tailscale ACL rules:**
   `dst: [blocked.clone()]` where `blocked` is a connector pattern isn’t a valid Tailscale ACL destination. This will confuse implementers and makes the spec look shaky in a place you want maximum confidence.

Also: pattern matching is underspecified. “String match” semantics vary across languages. You want a single *normative* matcher grammar.

### Diff

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 5.3 Zone Policy
 ```rust
 /// Zone access policy (NORMATIVE)
 pub struct ZonePolicy {
-    /// Allowed principal patterns
+    /// Allowed principal patterns
+    ///
+    /// NORMATIVE pattern syntax:
+    /// - Glob only (regex is forbidden for interop stability)
+    /// - `*` matches any sequence, `?` matches one char
+    /// - ASCII case-sensitive match
+    /// - Pattern length MUST be <= 128 bytes
     pub principals_allow: Vec<String>,
@@
     pub connectors_allow: Vec<String>,
@@
 impl ZonePolicy {
     /// Evaluate access request
     pub fn evaluate(&self, request: &AccessRequest) -> PolicyDecision {
@@
         // Step 2: Check connector
         if self.matches_any(&self.connectors_deny, &request.connector) {
             return PolicyDecision::Deny("Connector denied by policy");
         }
+        if !self.connectors_allow.is_empty()
+            && !self.matches_any(&self.connectors_allow, &request.connector)
+        {
+            if self.default_deny {
+                return PolicyDecision::Deny("Connector not in allow list");
+            }
+        }
@@
         // Step 3: Check capability
         if self.matches_any(&self.cap_deny, &request.capability) {
             return PolicyDecision::Deny("Capability denied by policy");
         }
@@
         PolicyDecision::Allow
     }
 }
````

@@

### 5.4 Zone-to-Tailscale ACL Mapping

```rust
@@
impl AclGenerator {
@@
        // ACL rules: defense-in-depth via zone membership port-gating.
@@
        for zone in &self.zones {
@@
        }
-
-        // Deny rules for explicit blocks
-        for zone in &self.zones {
-            for blocked in &zone.policy.connectors_deny {
-                acl.acls.push(AclRule {
-                    action: "deny".into(),
-                    src: vec![zone.tailscale_tag.clone()],
-                    dst: vec![blocked.clone()],
-                });
-            }
-        }
-
+        // NORMATIVE: Connector allow/deny is enforced by FCP policy + capabilities,
+        // not by Tailscale ACLs. Tailscale remains port-gating defense-in-depth only.
        acl
    }
}
```

````

---

## 5) Harden session establishment against DoS and make time-skew handling explicit

### Why this makes the project better

Handshake is a classic hot DoS surface:

- Signature verification + ECDH are not free, especially on mobile.
- A compromised node inside the tailnet can still hammer handshakes.

A simple **stateless cookie (HelloRetry)** pattern makes the responder do almost no work until the initiator proves it can receive replies. This is standard practice (DTLS/QUIC-style) and pays dividends.

Also, your design uses timestamps for `iat/exp` and handshake timestamps, but doesn’t define a **clock skew policy**. That becomes operational pain fast (mobile devices with drift, VMs paused, etc.).

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 4.2 Mesh Session Authentication (NORMATIVE)
@@
 pub struct MeshSessionHello {
     pub from: TailscaleNodeId,
     pub to: TailscaleNodeId,
     pub eph_pubkey: X25519PublicKey,
@@
     pub nonce: [u8; 16],
+    /// Optional stateless cookie (NORMATIVE when responder requires it)
+    /// Prevents responder resource-exhaustion by deferring expensive work until cookie is validated.
+    pub cookie: Option<[u8; 32]>,
     pub timestamp: u64,
@@
     pub signature: Signature,
 }
+
+/// Optional HelloRetry (NORMATIVE when used)
+/// Responder can send this without allocating session state or verifying hello signature.
+pub struct MeshSessionHelloRetry {
+    pub from: TailscaleNodeId,
+    pub to: TailscaleNodeId,
+    /// Stateless cookie computed by responder:
+    /// cookie = HMAC(cookie_key, from||to||hello.eph_pubkey||hello.nonce||hello.timestamp)[:32]
+    pub cookie: [u8; 32],
+    pub timestamp: u64,
+}
@@
 pub struct SessionReplayPolicy {
@@
 }
+
+/// Time skew handling (NORMATIVE)
+pub struct TimePolicy {
+    /// Max tolerated clock skew when validating iat/exp and handshake timestamps.
+    pub max_skew_secs: u64, // default: 120
+}
@@
 impl CapabilityToken {
@@
     pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), TokenError> {
-        // Check expiry
-        if current_timestamp() > self.exp {
+        let now = current_timestamp();
+        let skew = trust_anchors.time_policy().max_skew_secs;
+        // Check expiry (with skew tolerance)
+        if now > self.exp.saturating_add(skew) {
             return Err(TokenError::Expired);
         }
+        // Reject tokens issued too far in the future (with skew tolerance)
+        if self.iat > now.saturating_add(skew) {
+            return Err(TokenError::IssuedInFuture);
+        }
@@
     }
 }
````

---

## 6) Add lease “fencing tokens” (monotonic lease_seq) and bind intents/receipts to the lease

### Why this makes the project better

Execution leases are the right primitive, but without a fencing token you can still get edge cases like:

* partitioned coordinators issuing overlapping leases,
* stale lease holders writing state after they’ve lost the lease,
* ambiguous resolution rules that depend on wall-clock `exp`.

A monotonic `lease_seq` turns the lease into a true **fencing** mechanism:

* highest `lease_seq` wins, deterministically,
* connectors/state writers can reject stale lease holders even if wall clocks differ.

Binding `OperationIntent` to the lease further closes “exactly-once” gaps and makes forensic reasoning simpler.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 15.1 Execution Leases
@@
 pub struct ExecutionLease {
     pub header: ObjectHeader,
     /// The request/computation being leased
     pub request_object_id: ObjectId,
+    /// Fencing token (NORMATIVE): monotonically increases per (zone_id, request_object_id)
+    /// Used to prevent stale lease holders from executing/writing state.
+    pub lease_seq: u64,
     /// Which node currently owns execution
     pub owner_node: TailscaleNodeId,
@@
     pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
 }
@@
 pub struct OperationIntent {
     pub header: ObjectHeader,
     pub request_object_id: ObjectId,
@@
     pub planned_by: TailscaleNodeId,
+    /// Lease fencing token observed/used for this intent (NORMATIVE for Risky/Dangerous)
+    pub lease_seq: Option<u64>,
     /// Optional upstream idempotency handle (e.g., Stripe idempotency key)
     pub upstream_idempotency: Option<String>,
     pub signature: Signature,
 }
@@
 /// Execution Rule for Strict/Risky/Dangerous Operations (NORMATIVE):
 1. MeshNode MUST store OperationIntent (Required retention) BEFORE invoking the connector operation
-2. OperationReceipt MUST reference the OperationIntent via `ObjectHeader.refs`
+2. OperationIntent MUST reference the ExecutionLease via `ObjectHeader.refs` (Risky/Dangerous)
+3. OperationReceipt MUST reference the OperationIntent via `ObjectHeader.refs`
-3. On crash recovery, check for intents without corresponding receipts to detect incomplete operations
+4. On crash recovery, check for intents without corresponding receipts to detect incomplete operations
```

---

## 7) Support multi-writer connector state models (CRDT deltas) instead of only singleton_writer

### Why this makes the project better

`singleton_writer` is perfect for polling cursors (Gmail), but some connectors are naturally multi-writer:

* local indexing connectors,
* presence/heartbeat-like connectors,
* shared caches or event fan-in components.

Forcing single-writer in those cases either kills performance (unnecessary coordination) or causes “shadow state” hacks (state kept outside the mesh, undermining your core story).

A clean solution is to add an explicit state model:

* `stateless`
* `singleton_writer`
* `crdt` (with well-defined delta + snapshot semantics)

This makes the SDK more expressive and keeps the “authoritative state in the mesh” invariant.

### Diff

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 10.4 Connector State (NORMATIVE)
@@
+/// Connector state model (NORMATIVE)
+pub enum ConnectorStateModel {
+    /// No mesh-persisted state required
+    Stateless,
+    /// Exactly one writer enforced via ExecutionLease
+    SingletonWriter,
+    /// Multi-writer state using CRDT deltas + periodic snapshots
+    Crdt { crdt_type: CrdtType },
+}
+
+pub enum CrdtType {
+    /// Last-write-wins map (requires a clock/seq policy)
+    LwwMap,
+    /// Observed-remove set
+    OrSet,
+}
+
 /// Stable root for connector state (NORMATIVE)
 pub struct ConnectorStateRoot {
     pub header: ObjectHeader,
     pub connector_id: ConnectorId,
     pub instance_id: Option<InstanceId>,
     pub zone_id: ZoneId,
+    pub model: ConnectorStateModel,
     /// Latest ConnectorStateObject (or None if no state yet)
     pub head: Option<ObjectId>,
 }
+
+/// CRDT delta update (NORMATIVE when ConnectorStateModel::Crdt)
+pub struct ConnectorStateDelta {
+    pub header: ObjectHeader,
+    pub connector_id: ConnectorId,
+    pub instance_id: Option<InstanceId>,
+    pub zone_id: ZoneId,
+    pub crdt_type: CrdtType,
+    /// Delta payload (canonical CBOR; type depends on crdt_type)
+    pub delta_cbor: Vec<u8>,
+    pub applied_at: u64,
+    pub applied_by: TailscaleNodeId,
+    pub signature: Signature,
+}
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 11.1 Manifest Structure
 ```toml
 [connector]
 id = "fcp.telegram"
@@
 singleton_writer = true  # Only one node can write state at a time
+
+[connector.state]
+# "stateless" | "singleton_writer" | "crdt"
+model = "singleton_writer"
+# For CRDT models:
+# crdt_type = "lww_map"
+# snapshot_every_updates = 5000
+# snapshot_every_bytes = 1048576
````

````

---

## 8) Add DecisionReceipt objects + `fcp explain` UX to make enforcement explainable (and auditable)

### Why this makes the project better

You’re building a system that will **deny** actions in non-obvious ways (taint merge, revocation freshness, capability constraints, zone policies). If users and developers can’t easily answer:

> “Why was this denied?”  
> “Which object(s) caused it?”  
> “What would I need to change to allow it safely?”

…they’ll bypass security with broad approvals or disable enforcement. Explainability is not “nice to have” here; it’s the difference between a secure system that people keep enabled and one they slowly hollow out.

A `DecisionReceipt` object makes every allow/deny decision:

- reproducible,
- shareable across nodes,
- easy to render in CLI/UI,
- and testable in conformance harnesses.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
  ├── fcp-conformance/   # Interop tests, golden vectors, property tests, fuzz harness
- └── fcp-cli/           # CLI tools (fcp install, fcp doctor, etc.)
+ └── fcp-cli/           # CLI tools (fcp install, fcp doctor, fcp explain, etc.)
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ## 23. Observability and Audit
@@
 ### 23.4 Audit Chain (NORMATIVE)
@@
 pub struct AuditEvent {
@@
 }
+
+/// Decision receipt (NORMATIVE)
+/// Captures "why allowed/denied" in a mechanically verifiable, content-addressed form.
+pub struct DecisionReceipt {
+    pub header: ObjectHeader,
+    /// The request being evaluated
+    pub request_object_id: ObjectId,
+    /// Allow/Deny
+    pub decision: String, // "allow" | "deny"
+    /// Stable, enumerable reason code (NORMATIVE)
+    pub reason_code: String, // e.g., "taint.public_input_dangerous", "revocation.stale_frontier"
+    /// Human-readable explanation (optional)
+    pub message: Option<String>,
+    /// ObjectIds that justify the decision (cap token, grants, approvals, frontier, rev head, etc.)
+    pub evidence: Vec<ObjectId>,
+    pub decided_at: u64,
+    pub decided_by: TailscaleNodeId,
+    pub signature: Signature,
+}
+
+NORMATIVE: MeshNodes MUST emit a DecisionReceipt for all denied Risky/Dangerous operations.
+MeshNodes SHOULD emit DecisionReceipts for allowed Risky/Dangerous operations when `audit_level >= High`.
````

---

## 9) Strengthen supply-chain policy with SBOM + vuln-scan attestations and add optional ObjectIdKey rotation

### Why this makes the project better

You already have a strong provenance story (in-toto/SLSA + transparency). Two pragmatic additions make it much more “production real”:

* **SBOM requirement** (SPDX/CycloneDX): enables deterministic dependency inventory.
* **Vulnerability scan attestation**: you can enforce “no Critical vulns” as a policy gate.

Also: since you distribute an `ObjectIdKey` to zone members, a removed member can keep using it to do dictionary attacks / correlation on low-entropy objects. That’s not catastrophic (since data is encrypted), but it weakens the “sovereignty” story. A simple optional policy to rotate `ObjectIdKey` on membership change improves privacy hygiene.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
-| **Supply Chain Attestations** | in-toto/SLSA provenance verification, transparency logging |
+| **Supply Chain Attestations** | in-toto/SLSA provenance + SBOM + vulnerability-scan attestations, transparency logging |
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub enum AttestationType {
     /// in-toto provenance statement (SLSA-compatible)
     InToto,
     /// Reproducible build attestation
     ReproducibleBuild,
+    /// SPDX or CycloneDX SBOM (policy may require one)
+    Sbom,
+    /// Vulnerability scan attestation (policy may set max severity)
+    VulnerabilityScan,
     /// Code review attestation
     CodeReview,
     /// Custom attestation type
     Custom(String),
 }
@@
 pub struct SupplyChainPolicy {
@@
     /// Minimum SLSA level (0-4)
     pub min_slsa_level: u8,
+    /// Require an SBOM attestation
+    pub require_sbom: bool,
+    /// Maximum allowed vulnerability severity for required scan attestations
+    /// Example values: "none", "low", "medium", "high", "critical"
+    pub max_allowed_vuln_severity: Option<String>,
@@
 }
@@
 pub struct ZoneRekeyPolicy {
@@
     pub rewrap_on_membership_change: bool,
+    /// If true, rotate ObjectIdKey on membership change (privacy hardening)
+    pub rotate_object_id_key_on_membership_change: bool,
 }
```

---

## 10) Make operational targets credible: scope performance numbers, add benchmark harness, and make transport policy-driven

### Why this makes the project better

Some targets as written are likely to be read as “marketing” (e.g., **message latency < 1ms** across a tailnet) and can backfire.

A more compelling approach is:

* specify **p50/p99** and scope (local IPC vs LAN vs DERP),
* add a benchmark harness so improvements are measurable,
* make the “DERP allowed for zone X” rule **policy-driven**, not hard-coded—because real tailnets don’t always get direct paths.

This increases trust and makes the system more adoptable.

### Diff

````diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 ## Performance Targets
-| Metric | Target | Enforcement |
+| Metric | Target (p50/p99) | How Measured |
 |--------|--------|-------------|
-| Cold start | < 50ms | Binary preloading |
-| Message latency | < 1ms | Zero-copy IPC |
-| Memory overhead | < 10MB per connector | Sandbox limits |
-| CPU overhead | < 1% idle | Event-driven architecture |
-| Symbol reconstruction | < 10ms for 1MB object | Optimized RaptorQ |
-| Secret reconstruction | < 100ms | Parallel share collection |
+| Cold start (connector activate) | < 100ms / < 500ms | `fcp bench connector-activate` |
+| Local invoke latency (same node) | < 2ms / < 10ms | `fcp bench invoke-local` |
+| Tailnet invoke latency (LAN) | < 20ms / < 100ms | `fcp bench invoke-mesh --path=direct` |
+| Tailnet invoke latency (DERP) | < 150ms / < 500ms | `fcp bench invoke-mesh --path=derp` |
+| Symbol reconstruction (1MB) | < 50ms / < 250ms | `fcp bench raptorq --size=1mb` |
+| Secret reconstruction (k-of-n) | < 150ms / < 750ms | `fcp bench secrets --k=3 --n=5` |
+
+### Benchmarks
+The reference implementation SHOULD ship a `fcp bench` suite that is runnable offline and produces
+machine-readable results (JSON) for regression tracking.
@@
 ### Transport Priority
-``` Priority 1: Tailscale Direct (same LAN)     - <1ms, z:owner OK
-Priority 2: Tailscale Mesh (NAT traversal)  - 10-100ms, z:owner OK
-Priority 3: Tailscale DERP Relay            - 50-200ms, z:private and below
-Priority 4: Tailscale Funnel (public)       - Variable, z:community/public only ```
+``` Priority 1: Tailscale Direct (same LAN)
+Priority 2: Tailscale Mesh (NAT traversal)
+Priority 3: Tailscale DERP Relay            (policy-controlled per zone)
+Priority 4: Tailscale Funnel (public)       (policy-controlled; low-trust zones only by default) ```
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct Zone {
@@
     /// UDP/TCP port for gossip/control-plane objects in this zone (NORMATIVE for port-gating)
     pub control_port: u16,
+    /// Transport policy for this zone (NORMATIVE when present)
+    /// Keeps "DERP allowed?" and "Funnel allowed?" out of hard-coded tables.
+    pub transport_policy: Option<ZoneTransportPolicy>,
 }
+
+pub struct ZoneTransportPolicy {
+    pub allow_derp: bool,
+    pub allow_funnel: bool,
+    pub allow_lan_broadcast: bool,
+}
````

---

### One meta-observation (not a separate change): tighten “NORMATIVE vs INFORMATIVE” around implementer footguns

You already do this well, but I’d double down in the spots where real systems fail:

* exact matcher semantics for policies,
* exact token encoding/signable bytes,
* admission/quarantine behavior (otherwise DoS happens),
* lease fencing and crash windows,
* clock skew rules.

Those are the “death by edge cases” zones.

---

If you want, I can also produce a **single consolidated mega-diff** that applies all ten changes at once (same content, just merged so it’s easier to apply).

I read the README and the full V2 spec as one system design doc. While doing that, I looked for (a) crypto “catastrophic footguns” (nonce reuse, replay, downgrade), (b) spots where the normative text wouldn’t actually be implementable as-written (GC reachability, token/object-ID derivations), (c) liveness/usability traps in a *small personal mesh* (quorum requirements vs offline devices), and (d) things that would make the system more operable/compelling for real agents (preflight simulation, capability bundles, better connector isolation).

Below are the highest-leverage revisions. Each item includes rationale + a git-style diff you can apply to the docs.

---

## 1) Make AEAD nonce safety *reboot-proof* with `sender_instance_id`

### Why this makes the project better

Right now you rely on a deterministic nonce `nonce = frame_seq || esi` plus “frame_seq monotonic” to avoid ChaCha20-Poly1305 nonce reuse. That’s a classic catastrophic-failure boundary: if any sender ever reuses `(key, nonce)` you lose confidentiality and integrity for those messages, and the failure mode is silent.

On real personal devices, counters reset in practice: crashes, disk rollback, reinstall, “restore from backup,” etc. Even if you *intend* to persist `frame_seq`, you want a second line of defense that makes “counter reset” survivable.

**Revision:** add a random `sender_instance_id` (u64) that is:

* chosen freshly when a node begins sending under a `(zone_id, zone_key_id)` context (or whenever it cannot prove it preserved `frame_seq` continuity),
* included in every FCPS header,
* incorporated into per-sender subkey derivation.

This makes nonce reuse across restarts benign because the *key* changes even if `frame_seq` restarts at 0.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
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
-│  Bytes 82-89:  Frame Seq (u64 LE, per-sender monotonic counter)             │
-│  Bytes 90+:    Symbol payloads (encrypted, concatenated)                    │
+│  Bytes 82-89:  Sender Instance ID (u64 LE, random per sender+zone_key_id)   │
+│  Bytes 90-97:  Frame Seq (u64 LE, monotonic per sender_instance_id)         │
+│  Bytes 98+:    Symbol payloads (encrypted, concatenated)                    │
│  Final 8:      Checksum (XXH3-64)                                           │
│                                                                             │
-│  Fixed header: 90 bytes                                                     │
-│  Per-symbol nonce: derived as frame_seq || esi_le (deterministic)           │
+│  Fixed header: 98 bytes                                                     │
+│  Per-symbol nonce: derived as frame_seq || esi_le (deterministic)           │
+│  Per-sender subkey: derived from (source_node_id, sender_instance_id)       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

```
```

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 4.1 Symbol Envelope
 The universal transmission unit with AEAD encryption:
 ```rust
 /// Full symbol envelope with encryption (NORMATIVE)
 pub struct SymbolEnvelope {
@@
     /// Source node that produced this ciphertext (NORMATIVE)
     /// Needed because symbol encryption uses a per-sender subkey (see below).
     pub source_id: TailscaleNodeId,
+
+    /// Sender instance identifier (NORMATIVE)
+    /// Random u64 chosen by the sender for this (zone_id, zone_key_id) sending lifetime.
+    /// Used to make deterministic nonces reboot-safe: if frame_seq restarts, the sender subkey changes.
+    pub sender_instance_id: u64,
 
-    /// Monotonic frame sequence chosen by source for this zone_key_id (NORMATIVE)
-    pub frame_seq: u64,
+    /// Monotonic frame sequence chosen by source (NORMATIVE)
+    /// Monotonicity scope is (zone_id, zone_key_id, source_id, sender_instance_id).
+    pub frame_seq: u64,
@@
 impl SymbolEnvelope {
     /// Encrypt symbol data with zone key (NORMATIVE)
     pub fn encrypt(
         object_id: ObjectId,
         esi: u32,
         k: u16,
         plaintext: &[u8],
         zone_key: &ZoneKey,
         epoch: EpochId,
         source_id: TailscaleNodeId,
+        sender_instance_id: u64,
         frame_seq: u64,
     ) -> Self {
@@
-        let sender_key = zone_key.derive_sender_subkey(&source_id);
+        let sender_key = zone_key.derive_sender_subkey(&source_id, sender_instance_id);
         let (ciphertext, auth_tag) = zone_key.encrypt_with_subkey(&sender_key, plaintext, &nonce, &aad);
 
         Self {
             object_id,
             esi,
             k,
             data: ciphertext,
             zone_id: zone_key.zone_id.clone(),
             zone_key_id: zone_key.key_id,
             epoch_id: epoch,
             source_id,
+            sender_instance_id,
             frame_seq,
             auth_tag,
         }
     }
@@
     pub fn decrypt(&self, zone_key: &ZoneKey) -> Result<Vec<u8>, CryptoError> {
@@
-        let sender_key = zone_key.derive_sender_subkey(&self.source_id);
+        let sender_key = zone_key.derive_sender_subkey(&self.source_id, self.sender_instance_id);
         zone_key.decrypt_with_subkey(&sender_key, &self.data, &nonce, &self.auth_tag, &aad)
     }
@@
 ### 4.3 FCPS Frame Format
 Symbol-native frame format:
````

@@
│  Bytes 58-73:  Zone ID hash (16 bytes, truncated SHA256)                    │
│  Bytes 74-81:  Epoch ID (u64 LE)                                            │
-│  Bytes 82-89:  Frame Seq (u64 LE, per-sender monotonic)                     │
-│  Bytes 90+:    Symbol payloads (concatenated)                               │
+│  Bytes 82-89:  Sender Instance ID (u64 LE, random per sender+zone_key_id)   │
+│  Bytes 90-97:  Frame Seq (u64 LE, monotonic per sender_instance_id)         │
+│  Bytes 98+:    Symbol payloads (concatenated)                               │
│  Final 8:      Checksum (XXH3-64)                                           │
@@

* Fixed header: 90 bytes

- Fixed header: 98 bytes
  Each symbol: 4 (ESI) + 2 (K) + N (data) + 16 (auth_tag)
  (nonce derived from frame_seq_le || esi_le, NOT stored)
  @@
  impl ZoneKey {
  /// Derive per-sender subkey (NORMATIVE)
  ///
  /// sender_key = HKDF-SHA256(
  ///     ikm = zone_symmetric_key,

* ///     salt = zone_key_id,
* ///     info = "FCP2-SENDER-KEY-V1" || sender_node_id

- ///     salt = zone_key_id || sender_instance_id_le,
- ///     info = "FCP2-SENDER-KEY-V2" || sender_node_id
  /// )

* pub fn derive_sender_subkey(&self, sender: &TailscaleNodeId) -> [u8; 32];

- pub fn derive_sender_subkey(&self, sender: &TailscaleNodeId, sender_instance_id: u64) -> [u8; 32];
  }

```
```

---

## 2) Replace the “epoch ratchet” with a practical, testable `ZoneRekeyPolicy` (rotation + rewrap)

### Why this makes the project better

The current `ZoneRatchetPolicy` claims past secrecy by deleting epoch keys. But in a system where symbols are stored long-term for offline reconstruction, “delete old decryption keys” can accidentally imply “lose offline access,” unless you also define a full re-encryption/rewrap pipeline.

You already have all the primitives to do key hygiene *correctly*: `zone_key_id` is carried in symbols, and you have background repair. The missing piece is a normative policy that:

* rotates zone keys on a cadence (not just incident response),
* rewraps old objects under the new key until coverage is sufficient,
* only then allows retiring the old key.

This yields a bounded key-compromise window **without breaking offline availability**, and it leverages your existing repair controller rather than inventing a separate ratchet mechanism.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 ### Symbol Properties
 | Property | Benefit |
 |----------|---------|
@@
-| **Key Rotation Safe** | zone_key_id in each symbol enables seamless rotation |
+| **Key Rotation Safe** | zone_key_id in each symbol enables seamless rotation + background rewrap so old keys can be retired without losing offline access |
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct ZoneKeyManifest {
@@
-    /// Optional ratchet policy for epoch keys (past secrecy)
-    pub ratchet: Option<ZoneRatchetPolicy>,
+    /// Optional rekey policy (NORMATIVE when present)
+    /// Defines scheduled key rotation + rewrap requirements so old keys can be retired safely.
+    pub rekey_policy: Option<ZoneRekeyPolicy>,
@@
     /// Sealed key material per node
     pub wrapped_keys: Vec<WrappedZoneKey>,
     pub signature: Signature,
 }
@@
-/// Epoch ratchet policy for past secrecy (NORMATIVE when present)
-///
-/// If enabled, nodes MUST derive an epoch key, use it, then delete it after the
-/// epoch window. Past epochs become undecryptable after deletion (past secrecy).
-/// This is not full post-compromise security (for that you'd need MLS/TreeKEM),
-/// but it's a significant improvement with modest complexity.
-pub struct ZoneRatchetPolicy {
-    /// If true, nodes MUST derive and delete epoch keys per policy
-    pub enabled: bool,
-    /// Number of seconds of overlap to tolerate clock skew and delayed frames
-    pub overlap_secs: u64,
-    /// Max epochs to retain for delayed/offline peers (bounded memory)
-    pub retain_epochs: u32,
-}
+/// Zone rekey policy (NORMATIVE when present)
+///
+/// Purpose:
+/// - Bound key-compromise window via scheduled rotation
+/// - Preserve offline access by rewrapping old objects under the new key_id
+/// - Provide a mechanical condition for when old keys may be deleted
+pub struct ZoneRekeyPolicy {
+    /// Rotate the active zone key after this interval
+    pub rotate_after_secs: u64,
+    /// Overlap window where both prev and new key_ids remain valid for decrypt
+    pub overlap_secs: u64,
+    /// What to rewrap under the new key_id
+    pub rewrap: RekeyRewrapStrategy,
+    /// Minimum reconstruction coverage under the NEW key_id before old key deletion is allowed
+    /// Example: 1.25 means keep generating/storing new-key symbols until K'*1.25 are reachable.
+    pub min_new_key_coverage: f64,
+}
+
+pub enum RekeyRewrapStrategy {
+    /// Do not rewrap historical objects automatically (incident-only)
+    None,
+    /// Rewrap objects that are explicitly pinned (recommended default)
+    PinnedOnly,
+    /// Rewrap objects that are within TTL / retention windows
+    RetainedOnly,
+    /// Rewrap everything reachable from ZoneFrontier (expensive; use sparingly)
+    AllReachable,
+}
@@
 **Key Rotation Benefits:**
 - Including `zone_key_id` in frame header enables deterministic key selection
 - No trial-decrypt needed during rotation periods
 - Faster decrypt path, less DoS surface
 - Cleaner auditability (log exactly which key was used)
+
+**Rewrap Semantics (NORMATIVE when ZoneRekeyPolicy is configured):**
+Nodes MUST NOT delete an old `zone_key_id` until:
+1) `ZoneKeyManifest.prev_zone_key_id` overlap window has elapsed, AND
+2) For each object class required by policy (e.g., pinned objects), there exists sufficient symbol coverage
+   encrypted under the NEW key_id to meet `min_new_key_coverage`.
+Rewrapping is implemented by decrypting existing symbols and re-encrypting symbol payloads under the new key_id.
```

---

## 3) Turn approvals + secret access into real mesh objects, and add an `Execution` approval scope to fix offline liveness

### Why this makes the project better

Right now `ApprovalToken` is *not* a first-class mesh object (no `ObjectHeader`), yet it’s used as a critical enforcement input. Worse, the sample creation code uses `ObjectId::from_bytes(&signable)` which implicitly reintroduces the “unscoped hash” footgun you explicitly warned against in §3.1.

Also, your current “Risky/Dangerous requires execution lease quorum” rule can deadlock normal use in a personal mesh where devices are frequently offline. If your laptop is online and your phone is dead, you shouldn’t be unable to do a destructive-but-explicitly-approved action. The ultimate authority is the owner key—make that explicit.

**Revision:**

* Make `ApprovalToken` and `SecretAccessToken` full mesh objects with `ObjectHeader` (content-addressed, auditable, revocable, GC-rootable).
* Add a new `ApprovalScope::Execution` that can explicitly authorize *execution of a specific request* (or operation) when quorum leasing is unavailable (or as an additional gate for Dangerous ops).
* Remove the token-id derivation hack entirely; use normal object derivation.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 /// Unified approval token (NORMATIVE)
 /// 
 /// Consolidates ElevationToken and DeclassificationToken into a single type.
 /// Simplifies: UI prompting, audit, verification code paths, policy.
 pub struct ApprovalToken {
-    pub token_id: ObjectId,
+    pub header: ObjectHeader,
     pub scope: ApprovalScope,
     /// Human-readable justification (UI + audit)
     pub justification: String,
     pub approved_by: PrincipalId,
     pub approved_at: u64,
     pub expires_at: u64,
     pub signature: Signature,
 }
@@
 pub enum ApprovalScope {
     /// Integrity elevation for a specific operation + provenance
     Elevation {
         operation: OperationId,
         original_provenance: Provenance,
     },
     /// Confidentiality downgrade for specific objects
     Declassification {
         from_zone: ZoneId,
         to_zone: ZoneId,
         object_ids: Vec<ObjectId>,
     },
+    /// Explicit permission to EXECUTE a specific request / operation.
+    /// Primary use: maintain liveness when quorum leasing is unavailable (offline devices),
+    /// while keeping owner-in-the-loop for Dangerous operations.
+    Execution {
+        request_object_id: ObjectId,
+        operation: OperationId,
+        /// Optional bound on attempts (default: 1) to prevent “approved once, spam forever”
+        max_attempts: Option<u8>,
+    },
 }
@@
 impl ApprovalToken {
@@
     pub fn verify(&self, trust_anchors: &TrustAnchors) -> Result<(), VerifyError> {
         // Check expiry
         if current_timestamp() > self.expires_at {
             return Err(VerifyError::Expired);
         }
@@
         match &self.scope {
             ApprovalScope::Elevation { .. } => {
                 if !trust_anchors.can_approve_elevation(&self.approved_by) {
                     return Err(VerifyError::InsufficientAuthority);
                 }
             }
             ApprovalScope::Declassification { from_zone, to_zone, .. } => {
                 if !trust_anchors.can_approve_declassification(&self.approved_by, from_zone, to_zone) {
                     return Err(VerifyError::InsufficientAuthority);
                 }
             }
+            ApprovalScope::Execution { .. } => {
+                // NORMATIVE default: execution approvals MUST be owner-authorized unless policy explicitly delegates
+                if !trust_anchors.can_approve_execution(&self.approved_by) {
+                    return Err(VerifyError::InsufficientAuthority);
+                }
+            }
         }
@@
 /// Create an elevation approval (NORMATIVE)
 impl ApprovalToken {
     pub fn create_elevation(
         operation: OperationId,
         provenance: &Provenance,
         approver: &Identity,
         justification: &str,
         ttl: Option<u64>,
     ) -> Self {
         let now = current_timestamp();
         let expires_at = now + ttl.unwrap_or(Self::DEFAULT_TTL_SECS);
 
-        let mut token = Self {
-            token_id: ObjectId::default(),
+        let mut token = Self {
+            header: ObjectHeader {
+                schema: SchemaId { namespace: "fcp.core".into(), name: "ApprovalToken".into(), version: Version::new(2,0,0) },
+                zone_id: provenance.current_zone.clone(),
+                created_at: now,
+                provenance: provenance.clone(),
+                refs: vec![],
+                ttl_secs: Some(expires_at - now),
+                placement: None,
+            },
             scope: ApprovalScope::Elevation {
                 operation,
                 original_provenance: provenance.clone(),
             },
             justification: justification.to_string(),
             approved_by: approver.principal_id(),
             approved_at: now,
             expires_at,
             signature: Signature::default(),
         };
 
         let signable = token.signable_bytes();
         token.signature = approver.sign(&signable);
-        token.token_id = ObjectId::from_bytes(&signable);
         token
     }
@@
     pub fn create_declassification(
@@
-        let mut token = Self {
-            token_id: ObjectId::default(),
+        let mut token = Self {
+            header: ObjectHeader {
+                schema: SchemaId { namespace: "fcp.core".into(), name: "ApprovalToken".into(), version: Version::new(2,0,0) },
+                zone_id: from_zone.clone(),
+                created_at: now,
+                provenance: Provenance { origin_zone: from_zone.clone(), current_zone: from_zone.clone(), origin_integrity: 0, origin_confidentiality: 0, origin_principal: Some(approver.principal_id()), taint: TaintFlags::NONE, taint_reductions: vec![], zone_crossings: vec![], created_at: now },
+                refs: object_ids.clone(),
+                ttl_secs: Some(expires_at - now),
+                placement: None,
+            },
             scope: ApprovalScope::Declassification { from_zone, to_zone, object_ids },
             justification: justification.to_string(),
             approved_by: approver.principal_id(),
             approved_at: now,
             expires_at,
             signature: Signature::default(),
         };
@@
-        token.token_id = ObjectId::from_bytes(&signable);
         token
     }
 }
@@
 impl MeshNode {
@@
     pub async fn invoke(&self, request: InvokeRequest) -> Result<ResponseObject> {
@@
-        // 2e. Acquire or validate execution lease (NORMATIVE)
-        // For Risky/Dangerous operations, execution MUST require a valid lease.
+        // 2e. Acquire or validate execution lease (NORMATIVE)
+        // For Risky operations, execution MUST require a valid lease.
+        // For Dangerous operations, execution MUST require:
+        //   - a valid lease OR
+        //   - an ApprovalToken with ApprovalScope::Execution for this request (liveness when quorum unavailable).
         let operation = self.get_operation(&request.operation)?;
         if operation.safety_tier >= SafetyTier::Risky {
-            let lease = self.acquire_execution_lease(&request).await?;
-            self.verify_execution_lease(&lease, &request).await?;
+            match self.acquire_execution_lease(&request).await {
+                Ok(lease) => self.verify_execution_lease(&lease, &request).await?,
+                Err(e) if operation.safety_tier >= SafetyTier::Dangerous => {
+                    let exec = request.approval_tokens.iter()
+                        .find(|t| matches!(t.scope, ApprovalScope::Execution { request_object_id, operation, .. }
+                            if *request_object_id == request.request_object_id() && *operation == request.operation))
+                        .ok_or(Error::ExecutionApprovalRequired)?;
+                    exec.verify(&self.trust_anchors)?;
+                }
+                Err(e) => return Err(e.into()),
+            }
         }
@@
 }
@@
 /// Short-lived authorization to reconstruct/use a secret (NORMATIVE)
 pub struct SecretAccessToken {
+    pub header: ObjectHeader,
     /// Unique token ID
     pub jti: Uuid,
     /// Which secret can be accessed
     pub secret_id: SecretId,
@@
     /// Approver signature (owner or delegated approver)
     pub signature: Signature,
 }
```

---

## 4) Stop encoding hosts/ports into capability strings; make egress constraints purely data (`NetworkConstraints`)

### Why this makes the project better

Right now the spec taxonomy says one thing (`network.egress`, `network.raw_outbound:*`) and the manifest example does another (`network.outbound:api.telegram.org:443`). Baking hostnames into capability IDs creates:

* an unbounded namespace explosion,
* brittle parsing/policy matching,
* “capabilities as strings” drift between connectors and the policy engine.

You already have `NetworkConstraints` as a structured object and an egress proxy that enforces it. So make that the canonical mechanism: **capability IDs represent *classes of power*, and constraints represent *where/how that power can be used*.**

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 7.1 Capability Taxonomy
 FCP defines a hierarchical capability namespace:
 
```

network.*                Network operations
-├── network.egress       Outbound access via MeshNode egress proxy (DEFAULT in strict/moderate sandboxes)
-├── network.raw_outbound:* Direct sockets (RARE; permissive sandbox only)
-├── network.inbound:*    Listen for connections
-└── network.dns          DNS resolution (explicit capability; policy surface)
+├── network.egress       Outbound access via MeshNode egress proxy (DEFAULT in strict/moderate sandboxes)
+├── network.raw_outbound Direct sockets (RARE; permissive sandbox only; still SHOULD be constrained)
+└── network.inbound      Listen for inbound connections (rare; typically z:public only)

network.tls.*            TLS identity constraints (NORMATIVE for sensitive connectors)
├── network.tls.sni       Enforce SNI hostname match
└── network.tls.spki_pin  Enforce SPKI pin(s) for target host(s)

````
+
+NORMATIVE NOTE:
+Hostnames/ports MUST NOT be encoded into capability IDs. They MUST be expressed via `NetworkConstraints`
+in CapabilityObjects and/or per-operation manifest metadata, and enforced by the MeshNode egress proxy.
@@
### 11.1 Manifest Structure
```toml
@@
[capabilities]
required = [
  "ipc.gateway",
-  "network.dns",
-  "network.outbound:api.telegram.org:443",
+  "network.egress",
  "network.tls.sni",
  "network.tls.spki_pin",
-  "storage.persistent:encrypted",
+  "storage.persistent",
+  "storage.encrypted",
]
optional = ["media.download", "media.upload"]
forbidden = ["system.exec", "network.inbound"]
@@
network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, spki_pins = ["base64:..."] }
````

````

---

## 5) Harden the session handshake: explicit transcript, nonces, and downgrade resistance

### Why this makes the project better
Your session MAC approach is the right performance move, but the handshake as written is underspecified in exactly the places attackers exploit:
- no explicit transcript definition,
- no freshness nonces (timestamp-only replay prevention is brittle),
- downgrade surface if signatures don’t cover the complete negotiation state.

**Revision:** add explicit random nonces, define transcript bytes, and bind HKDF to the negotiated suite + both nonces. This makes replays and suite downgrades mechanically detectable.

### Diff
```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 /// Session handshake: initiator → responder
 pub struct MeshSessionHello {
     pub from: TailscaleNodeId,
     pub to: TailscaleNodeId,
     pub eph_pubkey: X25519PublicKey,
+    /// Random nonce for replay resistance (NORMATIVE)
+    pub hello_nonce: [u8; 32],
     pub timestamp: u64,
     /// Supported crypto suites (ordered by preference)
     pub suites: Vec<SessionCryptoSuite>,
     /// Node signature over transcript
     pub signature: Signature,
 }
@@
 /// Session handshake: responder → initiator
 pub struct MeshSessionAck {
     pub from: TailscaleNodeId,
     pub to: TailscaleNodeId,
     pub eph_pubkey: X25519PublicKey,
     pub session_id: [u8; 16],
     /// Selected crypto suite
     pub suite: SessionCryptoSuite,
+    /// Echo of initiator nonce + responder nonce (NORMATIVE)
+    pub hello_nonce: [u8; 32],
+    pub ack_nonce: [u8; 32],
     pub timestamp: u64,
     /// Node signature over transcript
     pub signature: Signature,
 }
@@
-/// prk = HKDF-SHA256(
-///     ikm = ECDH(initiator_eph, responder_eph),
-///     salt = session_id,
-///     info = "FCP2-SESSION-V1" || initiator_node_id || responder_node_id
-/// )
+/// Transcript (NORMATIVE):
+///   T = "FCP2-SESSION-HELLO-V1" || from || to || eph_pubkey || hello_nonce || suites || timestamp
+///   U = "FCP2-SESSION-ACK-V1"   || from || to || eph_pubkey || session_id || suite || hello_nonce || ack_nonce || timestamp
+///
+/// prk = HKDF-SHA256(
+///     ikm  = ECDH(initiator_eph, responder_eph),
+///     salt = session_id || hello_nonce || ack_nonce,
+///     info = "FCP2-SESSION-V2" || initiator_node_id || responder_node_id || suite_u8
+/// )
````

---

## 6) Fix GC correctness: require “head fields” to be duplicated into `ObjectHeader.refs`

### Why this makes the project better

You define GC as “traverse `ObjectHeader.refs` from ZoneFrontier roots.” But many of your “head pointers” (e.g., `ZoneFrontier.rev_head`, `ZoneFrontier.audit_head`, `AuditHead.head_event`) are *not guaranteed* to appear in `header.refs`. If implementers follow the struct fields but forget to mirror refs, GC will eventually delete live objects, causing silent loss and irrecoverable audit/revocation state.

**Revision:** make it explicit and testable:

* GC follows only `ObjectHeader.refs`.
* Any schema field that is a strong reference MUST be duplicated into `header.refs`.
* Add a conformance test for ZoneFrontier/AuditHead/RevocationHead ref mirroring.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 3.6 ObjectHeader
 All mesh-stored objects MUST begin with an ObjectHeader (NORMATIVE):
@@
 pub struct ObjectHeader {
@@
     /// Strong refs to other objects (object graph for GC + auditability)
     pub refs: Vec<ObjectId>,
@@
 }
+
+/// REF MIRRORING RULE (NORMATIVE):
+/// GC traversal considers ONLY `ObjectHeader.refs`.
+/// Therefore, any schema field that is a strong reference (e.g., `rev_head`, `audit_head`, `head_event`,
+/// `covers_head`, etc.) MUST also be present in `header.refs`.
+/// Implementations MUST treat missing ref mirroring as a conformance failure.
@@
 pub struct ZoneFrontier {
     pub header: ObjectHeader,
     pub zone_id: ZoneId,
     /// Latest revocation head
     pub rev_head: ObjectId,
@@
     pub audit_head: ObjectId,
@@
     pub signature: Signature,
 }
+
+// NORMATIVE: ZoneFrontier.header.refs MUST include [rev_head, audit_head] (and any other zone roots).
```

---

## 7) Add a first-class `simulate` control-plane call for policy + approval preflight

### Why this makes the project better

Agents (and humans) need a deterministic way to ask “will this be allowed, and what approvals would be required?” *without* executing. This:

* reduces accidental side effects,
* reduces approval fatigue (you can batch or pre-authorize),
* makes planning reliable (agents can choose safer alternatives automatically).

This is also highly “compelling/useful” because it turns your policy system into something agents can reason about mechanically rather than by trial.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 ### Why Use FCP?
 | Feature | What It Does |
 |---------|--------------|
@@
 | **Tamper-Evident Audit** | Hash-linked audit chain with monotonic seq and quorum-signed checkpoints |
+| **Policy Preflight** | Deterministic `simulate` call returns allow/deny + required approvals *without executing* |
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 9.2 Message Types
 | Type | Direction | Purpose |
 |------|-----------|---------|
@@
 | `invoke` | Hub → Connector | Execute operation |
+| `simulate` | Any → MeshNode | Preflight: evaluate policy/taint/approvals without executing |
 | `response` | Connector → Hub | Operation result |
+| `simulate_response` | MeshNode → Caller | Preflight decision + required approvals |
@@
 ### 9.4 Invoke Request/Response
@@
+/// Simulation request (NORMATIVE)
+/// Identical surface area to InvokeRequest, but MUST NOT cause side effects.
+pub struct SimulateRequest {
+    pub request: InvokeRequest,
+    /// If true, include suggested target device + placement rationale
+    pub include_placement: bool,
+}
+
+/// Simulation response (NORMATIVE)
+pub struct SimulateResponse {
+    pub allowed: bool,
+    /// If not allowed, a stable reason code + message
+    pub denial: Option<FcpError>,
+    /// Approvals required to make it allowed (elevation/declassification/execution)
+    pub required_approvals: Vec<ApprovalScope>,
+    /// Optional suggested execution target (if include_placement)
+    pub suggested_target: Option<TailscaleNodeId>,
+    /// Human-readable explanation intended for UI + agent planning
+    pub explanation: String,
+}
```

---

## 8) Add `RoleObject` capability bundles to make capability management scalable

### Why this makes the project better

As soon as you have more than a few connectors, “capability objects everywhere” becomes unmanageable:

* tokens get large (lots of `grant_object_ids`),
* humans can’t reason about grants,
* revocation becomes tedious (“revoke 23 objects for ‘gmail read-only’”).

**Revision:** introduce a signed, content-addressed `RoleObject` (capability bundle) that:

* references a set of CapabilityObjects,
* has a stable human name (“gmail.readonly”, “billing.operator”, etc.),
* can itself be referenced in `grant_object_ids` (verifiers expand it).

This adds a “policy ergonomics” layer that makes the system actually usable long-term.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 7.3 Capability Object (Mesh-Native)
@@
 pub struct CapabilityObject {
@@
 }
+
+/// Role / capability bundle object (NORMATIVE)
+/// A signed grouping of capability grants to make policy manageable at scale.
+/// RoleObjects MAY appear in `CapabilityToken.grant_object_ids`; verifiers MUST expand them.
+pub struct RoleObject {
+    pub header: ObjectHeader,
+    /// Stable identifier (e.g., "role:gmail.readonly")
+    pub role_id: String,
+    pub name: String,
+    pub description: String,
+    /// CapabilityObjects included in this role (strong refs; MUST also be in header.refs)
+    pub capability_object_ids: Vec<ObjectId>,
+    pub valid_from: u64,
+    pub valid_until: u64,
+    /// Owner or delegated signer (policy-defined)
+    pub signature: Signature,
+}
@@
 /// Capability Token for operation invocation (NORMATIVE)
 pub struct CapabilityToken {
@@
     /// CapabilityObjects that authorize this token (NORMATIVE)
     /// Verifiers MUST fetch/verify these objects and ensure token grants ⊆ object grants.
     /// This makes authority mechanically verifiable, not "trust the issuer".
     pub grant_object_ids: Vec<ObjectId>,
@@
 }
+
+NORMATIVE: `grant_object_ids` MAY contain:
+- CapabilityObject IDs
+- RoleObject IDs (which expand to multiple CapabilityObject IDs)
+Verifiers MUST expand roles transitively and apply the same validity + revocation checks to all members.
```

---

## 9) Make WASI a first-class “default for high-risk connectors,” especially `fcp.browser`

### Why this makes the project better

You already mention a WASI connector format, and you already have a `StrictPlus` sandbox profile. The strongest way to make the system safer *and* more portable is to explicitly align those:

* **High-risk connectors** (browser automation, universal adapters, parsers of adversarial content) should prefer **WASI** because the sandbox surface is consistent across OSes.
* `StrictPlus` should be defined as “WASI-first (or microVM where available), with hostcalls gated by capabilities.”

This reduces reliance on OS-specific sandboxes (seccomp/seatbelt/AppContainer differences), and it makes the security model more uniform and testable.

### Diff

```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 ## TL;DR
 **This project is two things:**
 1. **The FCP Protocol** — A mesh-native specification for how AI agents securely interact with external services through zone-isolated, capability-gated connectors distributed across your personal device mesh
 2. **Connector Implementations** — Production Rust binaries for Twitter, Linear, Stripe, Telegram, Discord, Gmail, GitHub, browser automation, and more
+
+**Connector Runtime Note:** Connectors may be shipped as native executables *or* WASI modules.
+High-risk connectors (e.g., `fcp.browser`) SHOULD prefer WASI + `StrictPlus` for consistent sandboxing.
```

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub enum ConnectorFormat {
     /// Native executable (ELF/Mach-O/PE)
     Native,
     /// WASI module (WASM) executed under a WASI runtime with hostcalls gated by capabilities
     /// Provides portable, capability-based sandbox consistent across OSes.
     Wasi,
 }
+
+NORMATIVE RECOMMENDATION:
+- Connectors that parse adversarial inputs or provide “universal automation” (e.g., browser automation)
+  SHOULD be delivered as `ConnectorFormat::Wasi` and run under `SandboxProfile::StrictPlus`.
@@
 pub enum SandboxProfile {
@@
     /// Maximum isolation (Linux): microVM-backed sandbox for high-risk connectors (NORMATIVE where available)
     /// Use for browser automation, universal adapters, or connectors parsing adversarial content.
     StrictPlus,
@@
 }
+
+StrictPlus Execution Semantics (NORMATIVE):
+- If connector is WASI: run under a WASI runtime with a minimal hostcall surface.
+- If connector is Native: run under the strongest available isolation (e.g., microVM on Linux where supported).
+- In both cases: no direct sockets; all network egress MUST go through the MeshNode egress proxy enforcing NetworkConstraints.
```

---

If you want one more “big swing” revision after these: I’d unify **RevocationHead + AuditHead + ZoneFrontier** into a single “ZoneCheckpoint” object (with typed sub-heads) to reduce duplication and the chance of reference/GC drift. I didn’t include that patch above because it’s more invasive, but it’s a meaningful simplification once you start implementing.

If you’d like, I can also produce a *single combined* patch that applies all nine changes cleanly in-order (instead of separate diffs).

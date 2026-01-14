I’m going to treat the two documents you included (`README.md` and `FCP_Specification_V2.md`) as “the plan” and review them the way an implementer + attacker would: I looked for (1) spec/plan contradictions that will create security or interop bugs, (2) places where the design is strong but the MVP path is too implicit (risking a stalled implementation), and (3) places where a small structural tweak yields a big reliability/perf win.

Below are the highest-leverage revisions I’d make. Each item has: **analysis/rationale** + a **git-style diff** against your plan docs.

---

## 1) Add explicit conformance language (RFC2119/8174) and a spec convention for “NORMATIVE” code blocks

### Why this makes it better

Right now, you use “NORMATIVE” heavily, but you don’t define the rules of the road. In practice, this causes:

* interop drift (“we thought that code snippet was illustrative, not binding”)
* implementation gaps (“MUST” vs “SHOULD” semantics aren’t consistently enforced)
* security regressions (“this was ‘just a comment’” becomes a bypass)

A small “Conformance Language” section makes it unambiguous what is binding, and it scales as the spec grows.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ## Abstract
 The Flywheel Connector Protocol (FCP) is a mesh-native protocol for secure, distributed AI assistant operations across personal device meshes. FCP V2 fundamentally reimagines the protocol around three axioms: **Universal Fungibility** (RaptorQ symbols as the atomic unit), **Authenticated Mesh** (Tailscale as identity and transport), and **Explicit Authority** (cryptographic capability chains).
 
 This specification defines:
 - The complete wire protocol for symbol-native communication
 - Connector architecture, manifests, and lifecycle management
 - Zone-based security with cryptographic isolation
 - Distributed state, computation migration, and offline access
 - Registry, supply chain, and conformance requirements
+
+## Conformance Language
+This document uses the key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
+**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** as described in RFC 2119
+and RFC 8174.
+
+Text explicitly labeled **(NORMATIVE)** is part of the interoperability and security contract.
+Text labeled **(INFORMATIVE)** is explanatory and non-binding.
+
+Code blocks and structs annotated with `NORMATIVE:` describe **behavioral requirements** and
+validation rules. They are not literal implementation constraints (language, crate layout,
+or exact types are non-normative unless stated otherwise).
 
 ---
 
 ## Table of Contents
```

---

## 2) Fix a major internal contradiction: “host restrictions not encoded in capability IDs” vs the manifest example encoding hosts in capability IDs

### Why this makes it better

In §7.1 you explicitly say **host restrictions are NOT encoded in capability IDs**, and that `NetworkConstraints` is the enforcement surface. But the manifest example in §11.1 does exactly what you warned against:

* `network.outbound:api.telegram.org:443`

This is not just cosmetic: it creates two incompatible policy models, and implementers will pick different ones. Worse, an attacker can exploit “capability ID parsing differences” to bypass constraints (“I have network.outbound, so I’m allowed”).

Fixing the example and aligning IDs prevents an entire class of policy/interop failures.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 [capabilities]
 required = [
   "ipc.gateway",
   "network.dns",
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
 network_constraints = { host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true, spki_pins = ["base64:..."] }
```

---

## 3) Fix a real spec bug: `ApprovalToken` struct doesn’t match the later “create_elevation” code (and the ObjectId derivation is wrong for your own rules)

### Why this makes it better

You define `ApprovalToken` as a mesh object with an `ObjectHeader`. Later (§6.3) you show constructors using `token_id` fields that **do not exist** in the struct, and you compute `token_id = ObjectId::from_bytes(&signable)` which violates your own “ObjectId must be bound to zone+schema+ObjectIdKey for security objects” rule (§3.1).

This is the kind of inconsistency that guarantees:

* divergent implementations
* broken verification logic
* subtle privilege/approval spoofing (because different nodes compute different IDs / signatures)

The revision below makes the ApprovalToken creation path consistent with the object model: header + canonical body + zone ObjectIdKey keyed derivation.

### Diff

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 6.3 Elevation Protocol
 Elevation (integrity uphill for tainted operations) now uses the unified `ApprovalToken` (§5.2) with `ApprovalScope::Elevation`.
 
 ```rust
-/// Create an elevation approval (NORMATIVE)
-impl ApprovalToken {
-    pub fn create_elevation(
-        operation: OperationId,
-        provenance: &Provenance,
-        approver: &Identity,
-        justification: &str,
-        ttl: Option<u64>,
-    ) -> Self {
-        let now = current_timestamp();
-        let expires_at = now + ttl.unwrap_or(Self::DEFAULT_TTL_SECS);
-
-        let mut token = Self {
-            token_id: ObjectId::default(),
-            scope: ApprovalScope::Elevation {
-                operation,
-                original_provenance: provenance.clone(),
-            },
-            justification: justification.to_string(),
-            approved_by: approver.principal_id(),
-            approved_at: now,
-            expires_at,
-            signature: Signature::default(),
-        };
-
-        let signable = token.signable_bytes();
-        token.signature = approver.sign(&signable);
-        token.token_id = ObjectId::from_bytes(&signable);
-
-        token
-    }
-
-    pub fn create_declassification(
-        from_zone: ZoneId,
-        to_zone: ZoneId,
-        object_ids: Vec<ObjectId>,
-        approver: &Identity,
-        justification: &str,
-        ttl: Option<u64>,
-    ) -> Self {
-        let now = current_timestamp();
-        let expires_at = now + ttl.unwrap_or(Self::DEFAULT_TTL_SECS);
-
-        let mut token = Self {
-            token_id: ObjectId::default(),
-            scope: ApprovalScope::Declassification {
-                from_zone,
-                to_zone,
-                object_ids,
-            },
-            justification: justification.to_string(),
-            approved_by: approver.principal_id(),
-            approved_at: now,
-            expires_at,
-            signature: Signature::default(),
-        };
-
-        let signable = token.signable_bytes();
-        token.signature = approver.sign(&signable);
-        token.token_id = ObjectId::from_bytes(&signable);
-
-        token
-    }
-}
+/// Construct an ApprovalToken as a normal mesh object (NORMATIVE)
+///
+/// NORMATIVE RULES:
+/// - ApprovalToken MUST be content-addressed using ObjectId::new(content, zone, schema, ObjectIdKey)
+/// - The approver signature MUST cover the canonical bytes of the token body (excluding signature)
+/// - The token MUST be stored as a mesh object and referenced by its ObjectId, not an embedded token_id
+impl ApprovalToken {
+    pub fn create(
+        zone_id: ZoneId,
+        scope: ApprovalScope,
+        justification: String,
+        approver: &Identity,
+        ttl_secs: Option<u64>,
+        zone_object_id_key: &ObjectIdKey,
+    ) -> (StoredObject, ApprovalToken) {
+        let now = current_timestamp();
+        let expires_at = now + ttl_secs.unwrap_or(Self::DEFAULT_TTL_SECS);
+        let schema = SchemaId { namespace: "fcp.core".into(), name: "ApprovalToken".into(), version: Version::new(2,0,0) };
+
+        let header = ObjectHeader {
+            schema: schema.clone(),
+            zone_id: zone_id.clone(),
+            created_at: now,
+            provenance: Provenance::owner_action(zone_id.clone(), approver.principal_id()),
+            refs: vec![],
+            ttl_secs: Some(expires_at.saturating_sub(now)),
+            placement: None,
+        };
+
+        let mut token = ApprovalToken {
+            header: header.clone(),
+            scope,
+            justification,
+            approved_by: approver.principal_id(),
+            approved_at: now,
+            expires_at,
+            signature: Signature::default(),
+        };
+
+        let signable = token.signable_bytes(); // canonical token bytes excluding signature
+        token.signature = approver.sign(&signable);
+
+        let body = CanonicalSerializer::serialize(&token, &schema);
+        let object_id = StoredObject::derive_id(&header, &body, zone_object_id_key);
+        let stored = StoredObject { object_id, header, body, storage: StorageMeta { retention: RetentionClass::Lease { expires_at } } };
+
+        (stored, token)
+    }
+}
````

````

---

## 4) Fix Provenance merge semantics (current version is an integrity bypass) and make integrity/confidentiality labels proof-carrying like taint reductions

### Why this makes it better
Your current `Provenance::merge(inputs)`:

```rust
let mut out = inputs[0].clone();
for p in inputs.iter().skip(1) {
  out.taint |= p.taint;
  out.zone_crossings.extend_from_slice(&p.zone_crossings);
}
````

This is a direct security bug: if the first input is high-integrity and a later input is low-integrity, `origin_integrity` stays at the first input’s value, and your `can_invoke` “integrity uphill” check can be bypassed by reordering inputs.

More broadly, you already have the correct conceptual model: two axes (integrity/confidentiality) + approvals. The missing piece is to make those axes:

* merge correctly across multiple sources
* *adjustable only via proof* (ApprovalToken), like taint reductions

This change:

* fixes the immediate bypass
* reduces approval fatigue (approved declass/elevation can “stick” to derived objects)
* makes the system more analyzable (“why was this allowed?” is mechanically answerable)

### Diff

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ### 6.1 Provenance Model
 Every piece of data carries its origin:
 
 ```rust
 /// Provenance tracking (NORMATIVE)
 #[derive(Clone)]
 pub struct Provenance {
     /// Origin zone
     pub origin_zone: ZoneId,
 
     /// Current zone (NORMATIVE): updated on every zone crossing
     pub current_zone: ZoneId,
 
-    /// Integrity/confidentiality labels inherited from origin (NORMATIVE)
-    pub origin_integrity: u8,
-    pub origin_confidentiality: u8,
+    /// Data labels (NORMATIVE)
+    ///
+    /// These are properties of the *data*, not the storage location.
+    /// - integrity_label: lower = less trustworthy input (Biba-style)
+    /// - confidentiality_label: higher = more secret (Bell-LaPadula-style)
+    ///
+    /// Merge rule (NORMATIVE):
+    /// - integrity_label = MIN across inputs (worst trust dominates)
+    /// - confidentiality_label = MAX across inputs (most secret dominates)
+    pub integrity_label: u8,
+    pub confidentiality_label: u8,
+
+    /// Proof-carrying label adjustments (NORMATIVE)
+    /// Allows *changing* labels only when you can point to a valid ApprovalToken.
+    pub label_adjustments: Vec<LabelAdjustment>,
 
     /// Principal who introduced the data
     pub origin_principal: Option<PrincipalId>,
 
     /// Taint flags (compositional)
     pub taint: TaintFlags,
@@
     /// Timestamp of creation
     pub created_at: u64,
 }
+
+/// Proof-carrying label adjustment (NORMATIVE)
+#[derive(Clone)]
+pub enum LabelAdjustment {
+    /// Human-approved integrity elevation (e.g., reviewed content)
+    IntegrityElevated { to: u8, by_approval: ObjectId, applied_at: u64 },
+    /// Human-approved declassification (lower secrecy)
+    ConfidentialityDeclassified { to: u8, by_approval: ObjectId, applied_at: u64 },
+}
@@
 impl Provenance {
+    /// Effective integrity after applying label adjustments (NORMATIVE)
+    pub fn effective_integrity(&self) -> u8 {
+        let mut v = self.integrity_label;
+        for a in &self.label_adjustments {
+            if let LabelAdjustment::IntegrityElevated { to, .. } = a {
+                v = v.max(*to);
+            }
+        }
+        v
+    }
+
+    /// Effective confidentiality after applying label adjustments (NORMATIVE)
+    pub fn effective_confidentiality(&self) -> u8 {
+        let mut v = self.confidentiality_label;
+        for a in &self.label_adjustments {
+            if let LabelAdjustment::ConfidentialityDeclassified { to, .. } = a {
+                v = v.min(*to);
+            }
+        }
+        v
+    }
+
@@
     /// Merge provenance from multiple inputs (NORMATIVE)
     ///
     /// Used when an operation consumes multiple data sources.
     pub fn merge(inputs: &[Provenance]) -> Provenance {
-        let mut out = inputs[0].clone();
-        for p in inputs.iter().skip(1) {
-            out.taint |= p.taint;
-            out.zone_crossings.extend_from_slice(&p.zone_crossings);
-        }
-        out
+        let mut out = inputs[0].clone();
+        out.integrity_label = inputs.iter().map(|p| p.effective_integrity()).min().unwrap_or(out.integrity_label);
+        out.confidentiality_label = inputs.iter().map(|p| p.effective_confidentiality()).max().unwrap_or(out.confidentiality_label);
+        out.taint = inputs.iter().fold(TaintFlags::NONE, |acc, p| acc | p.taint);
+        out.zone_crossings = inputs.iter().flat_map(|p| p.zone_crossings.clone()).collect();
+        out.taint_reductions = inputs.iter().flat_map(|p| p.taint_reductions.clone()).collect();
+        out.label_adjustments = inputs.iter().flat_map(|p| p.label_adjustments.clone()).collect();
+        out
     }
@@
     pub fn can_invoke(&self, operation: &Operation, target_zone: &Zone) -> TaintDecision {
         let effective = self.effective_taint();
@@
         // Rule 2: Integrity uphill for risky ops requires elevation
         if effective != TaintFlags::NONE
             && operation.safety_tier >= SafetyTier::Risky
-            && target_zone.integrity_level > self.origin_integrity
+            && target_zone.integrity_level > self.effective_integrity()
         {
             return TaintDecision::RequireElevation;
         }
 
         TaintDecision::Allow
     }
 }
````

---

## 5) Make taint reductions mechanically verifiable by standardizing the attestation schema (`SanitizerReceipt`) and requiring “coverage” checks

### Why this makes it better

Right now `TaintReduction` is “proof-carrying” in name only:

```rust
pub struct TaintReduction {
  pub clears: TaintFlags,
  pub by_attestation: ObjectId,
  pub applied_at: u64,
}
```

But there’s no normative schema for the attestation, nor a requirement that it actually applies to:

* the exact object(s) being reduced
* the exact taints being cleared
* a connector with an appropriate sanitizer capability

So an implementation could accidentally (or maliciously) clear taints with a mismatched receipt, and you’ve lost your “protocol-level filtering” story.

This revision makes taint reduction *as mechanically enforceable as capability checks*.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 /// Proof-carrying taint reduction (NORMATIVE)
 /// ///
 /// Allows clearing specific taints when you can point to a verifiable attestation.
 /// Examples:
 /// - URL scanning cleared UNVERIFIED_LINK
 /// - Malware scan cleared UNVERIFIED_LINK
 /// - Strict schema validation cleared PROMPT_SURFACE for that field
 #[derive(Clone)]
 pub struct TaintReduction {
     /// Which taints are cleared
     pub clears: TaintFlags,
-    /// Attestation/receipt ObjectId that justifies the reduction
-    pub by_attestation: ObjectId,
+    /// SanitizerReceipt ObjectId that justifies the reduction (NORMATIVE)
+    pub by_receipt: ObjectId,
     /// When the reduction was applied
     pub applied_at: u64,
 }
+
+/// Sanitizer receipt (NORMATIVE)
+///
+/// A verifier MUST validate:
+/// - signature (executing node)
+/// - that the sanitizer connector/operation is authorized by capability token / grant objects
+/// - that `clears` is consistent with the sanitizer operation semantics
+/// - that `inputs` includes the object(s) being reduced (coverage)
+pub struct SanitizerReceipt {
+    pub header: ObjectHeader,
+    pub sanitizer_connector: ConnectorId,
+    pub sanitizer_operation: OperationId,
+    pub inputs: Vec<ObjectId>,
+    pub clears: TaintFlags,
+    pub findings: Option<Value>,
+    pub executed_at: u64,
+    pub executed_by: TailscaleNodeId,
+    pub signature: Signature,
+}
@@
 impl Provenance {
@@
     /// Effective taint after applying reductions (NORMATIVE)
     ///
     /// Taint reductions allow specific taints to be cleared with proof.
     /// Without this, taint-only-accumulates leads to "approve everything" fatigue.
     pub fn effective_taint(&self) -> TaintFlags {
         let mut t = self.taint;
         for r in &self.taint_reductions {
-            t.remove(r.clears);
+            // NORMATIVE: reductions only count if the referenced SanitizerReceipt
+            // is valid and covers the relevant inputs. Implementations MUST NOT
+            // apply reductions based on unverified receipts.
+            t.remove(r.clears);
         }
         t
     }
```

(You’d also add a normative verification step where reductions are applied—either at object ingestion or at invocation time.)

---

## 6) Remove floating-point fields from content-addressed / policy-enforced objects (use fixed-point integers)

### Why this makes it better

You use `f64` in multiple NORMATIVE, content-addressed structs (`ObjectPlacementPolicy`, `CoverageEvaluation`, `AuditHead.coverage`, etc.). Even with deterministic CBOR, floats become a long-term interop and “policy footgun”:

* languages differ in float parsing/printing and NaN handling
* policy comparison bugs (“0.1 + 0.2” class issues)
* future schema evolution pain

Fixed-point integers (basis points) make policies stable, comparable, and safe to use in conformance tests.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct ObjectPlacementPolicy {
     /// Minimum distinct nodes that should hold symbols for this object
     pub min_nodes: u8,
-    /// Maximum fraction of total symbols any single node may hold (prevents concentration)
-    pub max_node_fraction: f64,
+    /// Maximum fraction of total symbols any single node may hold in basis points (0..=10000)
+    /// 10000 = 100%
+    pub max_node_fraction_bps: u16,
@@
-    /// Target coverage ratio (symbols held / symbols needed)
-    /// 1.0 = exactly K symbols distributed; 1.5 = 50% redundancy
-    pub target_coverage: f64,
+    /// Target coverage ratio in basis points (10000 = 1.0x, 15000 = 1.5x)
+    pub target_coverage_bps: u32,
 }
@@
 pub struct CoverageEvaluation {
     pub object_id: ObjectId,
@@
-    /// Highest fraction of symbols on any single node
-    pub max_node_fraction: f64,
-    /// Coverage ratio: symbols_available / symbols_needed
-    pub ratio: f64,
+    /// Highest fraction of symbols on any single node (basis points, 0..=10000)
+    pub max_node_fraction_bps: u16,
+    /// Coverage ratio in basis points (10000 = 1.0x)
+    pub coverage_bps: u32,
     /// Can object be reconstructed with current coverage?
     pub is_available: bool,
 }
@@
 pub struct AuditHead {
@@
-    /// Fraction of expected nodes contributing
-    pub coverage: f64,
+    /// Fraction of expected nodes contributing (basis points, 0..=10000)
+    pub coverage_bps: u16,
     /// Epoch this head was checkpointed
     pub epoch_id: EpochId,
     /// Quorum signatures from nodes
     pub quorum_signatures: Vec<(TailscaleNodeId, Signature)>,
 }
```

---

## 7) Add KIDs (key IDs) to NodeKeyAttestation and MeshIdentity so token verification can actually be implemented cleanly

### Why this makes it better

Capability tokens already include `kid: [u8; 8]`, and manifests/ZoneKeyManifests already reference `node_enc_kid`. But `NodeKeyAttestation` and `MeshIdentity` don’t define those kids, so you’re missing a normative mapping.

Without this, implementers will invent:

* “kid = truncated hash(pubkey)” vs “kid = random assigned by owner” vs “kid unused”
* incompatible key rotation semantics
* revocation targeting ambiguity (“revoke issuer key” = which one?)

Adding kids closes that gap and makes rotation/revocation crisp.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 pub struct MeshIdentity {
@@
     /// Node signing public key (used for SignedFcpsFrame, gossip auth, receipts)
     pub node_sig_pubkey: Ed25519PublicKey,
+    /// Node signing key id (kid) for rotation (NORMATIVE)
+    pub node_sig_kid: [u8; 8],
@@
     /// Node encryption public key (X25519) for wrapping zone keys + secret shares
     pub node_enc_pubkey: X25519PublicKey,
+    /// Node encryption key id (kid) for rotation (NORMATIVE)
+    pub node_enc_kid: [u8; 8],
@@
     /// Node issuance public key (Ed25519) used ONLY for minting capability tokens
     pub node_iss_pubkey: Ed25519PublicKey,
+    /// Node issuance key id (kid) for rotation (NORMATIVE)
+    pub node_iss_kid: [u8; 8],
@@
 pub struct NodeKeyAttestation {
@@
     /// Node's signing public key
     pub node_sig_pubkey: Ed25519PublicKey,
+    /// Key id for node_sig_pubkey (NORMATIVE)
+    pub node_sig_kid: [u8; 8],
@@
     /// Node's encryption public key (X25519) for sealed key distribution
     pub node_enc_pubkey: X25519PublicKey,
+    /// Key id for node_enc_pubkey (NORMATIVE)
+    pub node_enc_kid: [u8; 8],
@@
     /// Node's issuance public key for capability token minting
     pub node_iss_pubkey: Ed25519PublicKey,
+    /// Key id for node_iss_pubkey (NORMATIVE)
+    pub node_iss_kid: [u8; 8],
@@
     /// Owner signature (may be produced via threshold signing; verifiable with owner_pubkey)
     pub signature: Signature,
 }
```

---

## 8) Simplify GC and eliminate the cross-zone “back-ref stub” complexity by making refs explicitly same-zone, and adding `foreign_refs` for audit/provenance only

### Why this makes it better

Your current GC section introduces a serious “complexity cliff”:

> **Cross-zone ref mirroring (NORMATIVE):** ... maintain mirrored back-ref stub ... expires when ... communicated via cross-zone epoch sync or explicit unref messages.

That’s a lot of distributed bookkeeping for a feature that is mostly about *auditability metadata*, not live data ownership.

A cleaner model that’s easier to implement correctly:

* `refs`: **strong refs in the same zone only** (participate in GC)
* `foreign_refs`: cross-zone references for audit/provenance **only** (do not affect GC in the foreign zone)

If something in another zone must be retained, that zone’s own frontier/pins/lease retention should keep it alive. This makes per-zone GC independent and dramatically reduces your bug surface.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 /// Universal object header (NORMATIVE)
 /// ///
 /// NORMATIVE: ObjectId is derived from the canonical encoding of (header, body).
 /// The header MUST NOT embed `object_id` to avoid self-referential hashing ambiguity.
 pub struct ObjectHeader {
@@
-    /// Strong refs to other objects (object graph for GC + auditability)
-    pub refs: Vec<ObjectId>,
+    /// Strong refs to other objects in the SAME zone (NORMATIVE)
+    /// These participate in reachability GC.
+    ///
+    /// NORMATIVE: refs MUST NOT contain cross-zone object ids.
+    pub refs: Vec<ObjectId>,
+
+    /// Cross-zone references for audit/provenance only (NORMATIVE when present)
+    /// These MUST NOT participate in GC reachability in the foreign zone.
+    pub foreign_refs: Vec<ObjectId>,
@@
 }
@@
 ### 3.7 Garbage Collection and Pinning
 Nodes MUST implement reachability-based GC per zone (NORMATIVE):
@@
-  **GC Invariants:**
+  **GC Invariants:**
   - Never evict `Pinned` objects without explicit unpin request
   - Respect `Lease` expiry times
   - Enforce per-zone quotas
   - Root set always includes: latest ZoneFrontier (pinned) + all explicitly pinned objects
-  - **Cross-zone ref mirroring (NORMATIVE):** When object A in zone_x holds a ref to object B
-    in zone_y, zone_y MUST maintain a mirrored "back-ref" stub. This prevents B from being
-    GC'd in zone_y even if zone_y's frontier doesn't directly reference B. The back-ref stub
-    expires when zone_x's frontier no longer transitively references A, communicated via
-    cross-zone epoch sync or explicit unref messages.
+  - **Cross-zone refs (NORMATIVE):** Cross-zone references MUST be carried in `foreign_refs`
+    and MUST NOT affect GC in the foreign zone. If a foreign object must be retained, it MUST
+    be retained by that zone’s own frontier/pins/leases/policy.
```

---

## 9) Introduce a reliable control-plane framing (“FCPC”) that uses session `k_ctx` (and keep FCPS for the data plane)

### Why this makes it better

You already acknowledge in Appendix B that two fast paths matter:

1. small control-plane requests/responses should avoid RaptorQ overhead
2. large objects should be chunked

But the core wire section still leans heavily on “CONTROL_PLANE objects can be encoded into symbols.” That’s a high-overhead default and (more importantly) it pushes idempotency, retries, and ordering complexity into the symbol layer.

A better architecture split:

* **FCPS (symbols)**: best-effort, high-throughput dissemination, “any K′ wins”
* **FCPC (control plane)**: reliable, ordered, backpressured stream for invoke/simulate/configure/etc
  (still end-to-end authenticated using the session handshake; use the reserved `k_ctx`)

This improves:

* correctness (invoke/response semantics become stream-robust)
* performance (no RaptorQ for tiny messages)
* DoS resistance (bounded per-connection parsing, no decode CPU spikes)

### Diff

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ## 9. Wire Protocol
@@
 ### 9.3 Control Plane Object Model (NORMATIVE)
 All control-plane message types MUST have a canonical CBOR object representation with SchemaId/ObjectId. This makes all operations auditable, replayable, and content-addressed.
@@
-  **Transport Options:**
-1. **Direct (local)**: Canonical CBOR bytes over local connector transport
-2. **Mesh**: Encoded to symbols and sent inside FCPS frames with `FrameFlags::CONTROL_PLANE` set
+  **Transport Options (NORMATIVE):**
+1. **FCPC (recommended)**: Reliable stream framing for control-plane messages using the mesh session `k_ctx`
+2. **Direct (local)**: Canonical CBOR bytes over local connector transport (may reuse FCPC framing)
+3. **Mesh fallback**: Encoded to symbols and sent inside FCPS frames with `FrameFlags::CONTROL_PLANE` set (for degraded/offline sync)
@@
 When `FrameFlags::CONTROL_PLANE` is set, receivers MUST:
@@
     5. Store object if retention class is Required; otherwise MAY discard after processing
+
+### 9.6 FCPC: Control Plane Framing (NORMATIVE)
+FCPC provides a reliable, backpressured framing for control-plane objects (invoke/simulate/configure/response/etc).
+It is carried over a stream transport (TCP or QUIC) inside the tailnet.
+
+**Security (NORMATIVE):**
+- FCPC messages MUST be bound to an authenticated MeshSession (see §4.2)
+- FCPC payloads MUST be authenticated using `k_ctx` derived from the MeshSession key schedule
+- Implementations SHOULD encrypt FCPC payloads (AEAD) using `k_ctx` to provide end-to-end
+  confidentiality independent of the underlying transport.
+
+```text
+FCPC FRAME (conceptual)
+  magic = "FCPC"
+  version = u16
+  session_id = [16]
+  seq = u64 (per-direction monotonic)
+  flags = u16
+  len = u32
+  ciphertext[len] (AEAD under k_ctx; aad includes session_id||seq||flags)
+  tag = [16]
+```
+
+**Replay protection (NORMATIVE):**
+- Receivers MUST enforce a bounded replay window like SessionReplayPolicy (max_reorder_window)
+- seq MUST be strictly increasing per direction for the authenticated session
````

---

## 10) Replace `resource_uris: Vec<String>` with `ResourceObject` handles so resources are zone-bound, revocable, and auditable

### Why this makes it better

Free-form URIs in responses are an exfiltration channel and a policy bypass waiting to happen:

* a connector can smuggle sensitive data via a “URI” string
* downstream tooling might treat URIs as clickable / fetchable
* you can’t revoke or attach provenance to them cleanly

Instead, make “resource references” into **mesh objects**:

* `ResourceObject` is content-addressed, zone-labeled, and provenance-carrying
* you can require capabilities to dereference resources
* receipts/audit can reference object IDs, not strings

This makes connectors *more useful* (resources become durable handles) and *more secure*.

### Diff

```diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 /// Invoke response (NORMATIVE)
 pub struct InvokeResponse {
     pub id: String,
     pub result: Value,
-    pub resource_uris: Vec<String>,
+    /// Resource handles created/modified by the operation (NORMATIVE)
+    /// Each ResourceObject is a mesh object carrying provenance + zone binding.
+    pub resource_object_ids: Vec<ObjectId>,
     pub next_cursor: Option<String>,
     /// Receipt ObjectId (for operations with side effects)
     pub receipt: Option<ObjectId>,
 }
+
+/// Resource handle object (NORMATIVE)
+///
+/// Replaces free-form resource URIs with zone-bound, auditable handles.
+pub struct ResourceObject {
+    pub header: ObjectHeader,
+    pub connector_id: ConnectorId,
+    pub resource_type: String,
+    pub resource_uri: String,
+    pub created_at: u64,
+    pub expires_at: Option<u64>,
+    pub signature: Signature,
+}
@@
 pub struct OperationReceipt {
@@
     /// ObjectIds of outcome objects
     pub outcome_object_ids: Vec<ObjectId>,
-    /// Resource URIs created/modified
-    pub resource_uris: Vec<String>,
+    /// ResourceObject ids created/modified (NORMATIVE)
+    pub resource_object_ids: Vec<ObjectId>,
     /// When execution completed
     pub executed_at: u64,
```

---

## 11) Make revocation “freshness” an explicit policy with tiered enforcement, and define degraded-mode semantics

### Why this makes it better

You already have the right primitive: `rev_head` + `rev_seq` gives O(1) freshness checks. What’s missing is a clear operational rule for partitions/offline:

* “MUST have revocation state >= token.rev_seq” is great, but *what if you can’t fetch?*
* currently, degraded mode is referenced but not defined, and different implementations will behave differently

Make it explicit:

* Safe ops can run under bounded staleness (configurable)
* Risky/Dangerous ops require fresh revocation state (or interactive override, but logged)
* Degraded mode is a **mode**, not an implicit accident

### Diff

````diff
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ## 14. Lifecycle Management
@@
 ### 14.3 Revocation (NORMATIVE)
 Revocations are mesh objects distributed like any other object and MUST be enforced before use. Without revocation, "compromised device" recovery is mostly imaginary.
+
+#### 14.3.1 Revocation Freshness Policy (NORMATIVE)
+Implementations MUST define a revocation freshness policy that is enforced based on SafetyTier:
+
+```rust
+pub struct RevocationFreshnessPolicy {
+    /// Max allowed age of the latest known ZoneFrontier before we refuse Risky/Dangerous ops
+    pub max_frontier_age_secs: u64,   // default: 300
+    /// If true, Safe ops MAY proceed in degraded mode when frontier is stale/unavailable
+    pub allow_safe_ops_in_degraded_mode: bool, // default: true
+    /// If true, Risky ops MAY proceed only with an interactive ApprovalToken::Execution in degraded mode
+    pub allow_risky_ops_with_interactive_override: bool, // default: false
+}
+```
+
+**Enforcement (NORMATIVE):**
+- For **Dangerous** operations: verifier MUST have revocation state >= token.rev_seq AND frontier age <= max_frontier_age_secs
+- For **Risky** operations: same as Dangerous by default; MAY allow interactive override if policy allows
+- For **Safe** operations: MAY proceed if allow_safe_ops_in_degraded_mode is true, but MUST emit an audit event `revocation.degraded_mode`
+
+This makes offline/partition behavior consistent, auditable, and configurable.
````

---

## 12) Add a first-class conformance + fuzzing surface (crate + checklist updates) to make “mechanically enforced” real

### Why this makes it better

You repeatedly assert “mechanically enforced” invariants. The quickest way for a project like this to fail in practice is for those invariants to exist only in prose.

A dedicated conformance crate + fuzz targets gives you:

* regression-proof security invariants
* interop readiness (golden vectors)
* performance profiling hooks (decode DoS testing)
* a clean “definition of done” per feature

### Diff (README project structure + spec conformance section)

````diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
  ## Project Structure
  ``` flywheel_connectors/
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
+ │   ├── fcp-conformance/   # Interop + golden vectors + property tests + fuzz harness
  │   └── fcp-cli/           # CLI tools (fcp install, fcp doctor, etc.)
  ├── connectors/            # Individual connector implementations
@@
  └── README.md ```
diff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ## 27. Conformance Requirements
 ### 27.1 Mandatory Tests
 
 1. Canonical serialization
 2. ObjectId derivation
 3. Symbol encoding/reconstruction
 4. Signature verification
 5. Revocation checking
 6. Source diversity
 7. Epoch ordering
+
+### 27.3 Fuzzing and Adversarial Tests (NORMATIVE for reference implementation)
+The reference implementation MUST include fuzz targets for:
+1. FCPS frame parsing (invalid lengths, malformed symbol counts, checksum edge cases)
+2. Session handshake transcript verification (replay, splicing, nonce reuse)
+3. CapabilityToken verification (grant_object_ids inconsistencies, revocation staleness)
+4. ZoneKeyManifest parsing and sealed key unwrap behavior
+
+At least one corpus MUST include “decode DoS” adversarial inputs designed to maximize decode CPU.
````

---

## A few additional “quick win” fixes I would absolutely do next (without full diffs yet)

These are smaller but high-signal improvements; if you want, I can produce patch hunks for each as well:

1. **Spec editorial fix**: In §10, `### 10.3 Standard Methods` is currently empty and then the table appears later. Move the table directly under 10.3 and remove the duplicate header so the spec reads cleanly.

2. **Make `ObjectPlacementPolicy.preferred_devices/excluded_devices` typed**: strings like `"class:desktop"` and `"tag:fcp-private"` are fine, but the NORMATIVE spec should define a typed selector grammar (even if it’s small) so implementations don’t diverge.

3. **Bind `OperationIntent` to upstream idempotency more strongly**: make it NORMATIVE that connectors MUST use upstream idempotency primitives (Stripe idempotency keys, etc.) when available for Strict ops, and record the upstream id in the receipt.

4. **Define a canonical “declassification output label” rule**: once you allow declassification, what is the new `confidentiality_label` of the derived object? (My recommendation: set it to the target zone’s confidentiality level and add a LabelAdjustment referencing the ApprovalToken.)

5. **Session rekey triggers**: you have `rekey_after_frames`. Add rekey-after-time and rekey-after-bytes to avoid pathological long-lived sessions.

---

If you want me to push this further in the same format, the next most valuable “bigger” change would be: **formalizing a `PolicyObject` that can express allow/deny as a deterministic expression language (CEL-like) while keeping your current allow/deny lists as a fast path**—that’s where you’ll unlock both “more compelling/useful” and “less policy fatigue” without turning policy into an untestable blob.

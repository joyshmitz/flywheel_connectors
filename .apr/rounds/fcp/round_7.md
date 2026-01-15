Below are **12 high‑impact revisions** that target **security, interoperability, performance, and operational reliability** in the sections you shared. For each, I’ve included:

1. **What’s wrong/risky now**
2. **Proposed change + rationale** (detailed)
3. **Git‑diff style patch** (exact edits to `../../../tmp/fcp_condensed.md`)

---

## Revision 1 — Make canonical encoding & content addressing fully deterministic

### 1) What’s wrong/risky now

* “SchemaHash‑prefixed deterministic CBOR” is **underspecified**. Two correct implementations can still produce **different encodings** (e.g., map key ordering, float encodings, indefinite‑length items), causing **ObjectId mismatches**, audit divergence, cache misses, and signature verification failures.
* Without explicit **domain separation**, the same bytes could be interpreted in multiple contexts (“hash substitution” / cross‑protocol misuse).

### 2) Proposed change + rationale

* Normatively define canonical CBOR constraints (RFC 8949 canonical form, definite‑length only, no duplicate map keys).
* Define **SchemaHash**, **ObjectId**, and **signature preimages** with explicit **domain separation strings**.
* Require implementations to **reject non‑canonical encodings** for persisted/audited objects (fail closed). This prevents subtle interop bugs and signature ambiguity.

### 3) Patch

```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 NORMATIVE clarification:
 - Any object that is persisted, audited, cached, mirrored, or pinned MUST have a canonical content-addressed representation that can be distributed as symbols.
 - Control-plane delivery MAY use FCPC streams for small messages, but those messages MUST still be representable as canonical mesh objects (SchemaHash-prefixed deterministic CBOR).
+
+Additional NORMATIVE requirements (to ensure cross-implementation determinism and signature safety):
+- Canonical CBOR MUST follow RFC 8949 Canonical CBOR rules: definite-length items only, shortest-length integers, sorted map keys by bytewise lexicographic order of their canonical encoding, and no duplicate map keys.
+- Floating point values MUST NOT appear in durable mesh objects unless the schema explicitly allows them; if allowed, NaNs MUST be rejected and floats MUST be encoded in the shortest canonical form.
+- `SchemaHash` MUST be 32 bytes and computed as `BLAKE3-256( "fcp.schema.v2" || schema_descriptor_bytes )`, where `schema_descriptor_bytes` is a canonical CBOR encoding of the schema/interface descriptor.
+- `ObjectId` MUST be `BLAKE3-256( "fcp.object.v2" || (SchemaHash || canonical_cbor_bytes) )`. All signature preimages MUST use the same bytes (domain-separated) to prevent cross-protocol substitution.
+- Implementations MUST reject non-canonical encodings for any object that is persisted, audited, cached, mirrored, or pinned (fail closed).
```

---

## Revision 2 — Bind NodeIdentity to signatures + enforce attestation freshness/expiry

### 1) What’s wrong/risky now

* `NodeIdentity` has **no signature**, so keys/fields can be swapped in transit while still presenting some attestation.
* `NodeKeyAttestation.expires_at` is optional → replayable “forever” attestations.
* `DevicePostureAttestation.payload` is opaque and has no freshness binding; posture can be replayed out of context.
* KIDs are used but not defined (collision handling, derivation, domain separation).

### 2) Proposed change + rationale

* Add `identity_sig` to `NodeIdentity`: a self‑signature binding the identity fields to `node_sig_pubkey`.
* Make `expires_at` mandatory for attestations and require bounded validity windows.
* Add nonces and expiry to posture attestations to prevent replay and stale posture.
* Add normative rules for tag validation and KID derivation.

### 3) Patch

```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 pub struct NodeIdentity {
     pub owner_pubkey: Ed25519PublicKey,
     pub node_id: TailscaleNodeId,
     pub node_sig_pubkey: Ed25519PublicKey,
     pub node_sig_kid: [u8; 8],
     pub node_enc_pubkey: X25519PublicKey,
     pub node_enc_kid: [u8; 8],
     pub node_iss_pubkey: Ed25519PublicKey,
     pub node_iss_kid: [u8; 8],
     pub node_attestation: NodeKeyAttestation,
+    /// Self-signature by `node_sig_pubkey` binding the identity fields (excluding this field).
+    pub identity_sig: Signature,
 }
 
 pub struct NodeKeyAttestation {
     pub node_id: TailscaleNodeId,
+    /// Binds the attestation to the same owner as NodeIdentity.
+    pub owner_pubkey: Ed25519PublicKey,
     pub node_sig_pubkey: Ed25519PublicKey,
     pub node_sig_kid: [u8; 8],
     pub node_enc_pubkey: X25519PublicKey,
     pub node_enc_kid: [u8; 8],
     pub node_iss_pubkey: Ed25519PublicKey,
     pub node_iss_kid: [u8; 8],
     pub tags: Vec<String>,
     pub issued_at: u64,
-    pub expires_at: Option<u64>,
+    pub expires_at: u64,
+    /// Random 32-byte value to ensure freshness and prevent replay across contexts.
+    pub attestation_nonce: [u8; 32],
     pub device_posture: Option<DevicePostureAttestation>,
     pub signature: Signature,
 }
 
 pub struct DevicePostureAttestation {
     pub kind: DevicePostureKind,
     pub payload: Vec<u8>,
     pub issued_at: u64,
+    pub expires_at: u64,
+    pub nonce: [u8; 32],
 }
@@
 pub enum DevicePostureKind {
     TpmQuote,
     SecureEnclave,
     AndroidKeystore,
     Custom(String),
 }
```

*

+NORMATIVE requirements:
+- `NodeIdentity.identity_sig` MUST be an Ed25519 signature created by `node_sig_pubkey` over the canonical serialization of `NodeIdentity` with `identity_sig` set to the empty value.
+- `NodeKeyAttestation.signature` MUST be an Ed25519 signature by `node_iss_pubkey` over the canonical serialization of `NodeKeyAttestation` with `signature` set to the empty value.
+- `expires_at` MUST be present. The validity window SHOULD be short (e.g., ≤ 30 days). Implementations MUST reject attestations with `expires_at <= issued_at`.
+- `DevicePostureAttestation` MUST be treated as time-sensitive: `expires_at - issued_at` SHOULD be ≤ 24 hours. Posture attestations outside this window MUST be rejected.
+- `tags` entries MUST be valid Canonical Identifier Grammar strings and each entry MUST be ≤ 64 bytes.
+- All `*_kid` values MUST be derived via a domain-separated hash, e.g. `kid = first8(BLAKE3-256("fcp.kid.v2" || pubkey_bytes))`.

````

---

## Revision 3 — Move zone membership out of ZoneDefinition + define level semantics

### 1) What’s wrong/risky now
- `ZoneDefinition.allowed_nodes` can become huge, static, and hard to update. That’s a **performance and operational pain** and can create inconsistent membership logic across implementations.
- `integrity_level`/`confidentiality_level` semantics are unspecified. Without clear monotonicity rules, implementers may allow **unsafe downgrades**.

### 2) Proposed change + rationale
- Make `ZoneDefinition` small/stable: remove explicit membership lists; membership belongs in `ZonePolicy` (already referenced by `ZoneCheckpoint.zone_policy_head`).
- Add normative semantics for integrity/confidentiality levels, including **hierarchy monotonicity** (child zones cannot exceed parent protections).

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 pub struct ZoneDefinition {
     pub header: ObjectHeader,
     pub zone_id: ZoneId,
     pub integrity_level: u8,
     pub confidentiality_level: u8,
-    pub allowed_nodes: Vec<TailscaleNodeId>,
     pub parent_zone: Option<ZoneId>,
     pub signature: Signature,
 }
````

-Zone hierarchy: z:owner (integrity=255, confidentiality=255) → z:private → z:work → z:community → z:public
+NORMATIVE clarifications:
+- Zone membership / authorization MUST be defined by the zone policy object referenced by `ZoneCheckpoint.zone_policy_head`, not by embedding potentially-large allowlists in `ZoneDefinition`.
+- `integrity_level` and `confidentiality_level` are ordered from 0 (lowest) to 255 (highest). Child zones MUST NOT exceed the parent zone’s levels (monotonic non-increasing protections down the hierarchy).
+- Zone hierarchy labels (e.g., `z:owner`, `z:private`, …) are conventional examples; implementations MUST enforce semantics based on levels and policy, not names.
+
+Zone hierarchy: z:owner (integrity=255, confidentiality=255) → z:private → z:work → z:community → z:public

````

---

## Revision 4 — Define quorum signature format + add rollback/fork resistance for ZoneCheckpoint

### 1) What’s wrong/risky now
- `QuorumSignature` is referenced but not defined → interop hazard.
- No clear anti‑rollback rule. An attacker could replay an older checkpoint that still has valid signatures unless receivers persist monotonic state.
- No canonical ordering/uniqueness rules for quorum signatures.

### 2) Proposed change + rationale
- Define `QuorumSignature` explicitly.
- Add `prev_checkpoint` backpointer to support chain validation and simplify fork detection.
- Add normative rules: signature preimage, sorting/dedup, threshold binding to zone policy, and rollback rejection.

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 ### 2.4 ZoneCheckpoint (Quorum-Signed)
 ```rust
+pub struct QuorumSignature {
+    /// Signer identity (node) and key identifier used for this signature.
+    pub signer_node: TailscaleNodeId,
+    pub signer_kid: [u8; 8],
+    pub sig: Signature,
+}
+
 pub struct ZoneCheckpoint {
     pub header: ObjectHeader,
     pub zone_id: ZoneId,
+    /// Optional back-pointer to prevent rollback / fork ambiguity.
+    pub prev_checkpoint: Option<ObjectId>,
     pub rev_head: ObjectId,
     pub rev_seq: u64,
     pub audit_head: ObjectId,
     pub audit_seq: u64,
     pub zone_definition_head: ObjectId,
     pub zone_policy_head: ObjectId,
     pub active_zone_key_manifest: ObjectId,
     pub checkpoint_seq: u64,
     pub as_of_epoch: EpochId,
     pub quorum_signatures: Vec<QuorumSignature>,
 }
````

*

+NORMATIVE requirements:
+- The signature preimage for each `QuorumSignature` MUST be a domain-separated hash of the canonical `ZoneCheckpoint` with `quorum_signatures` set to empty (e.g., `BLAKE3-256("fcp.zonecheckpoint.v2" || checkpoint_bytes)`).
+- `quorum_signatures` MUST be sorted by `(signer_node, signer_kid)` and MUST NOT contain duplicates.
+- Receivers MUST enforce rollback protection by persisting the highest accepted `(checkpoint_seq, as_of_epoch)` per zone and rejecting older values, even if signatures verify.
+- The required quorum threshold and eligible signers MUST be defined in zone policy (referenced by `zone_policy_head`); checkpoint validation MUST enforce that threshold.

````

---

## Revision 5 — Specify FCPS cryptographic suite, nonce/AAD, replay rules, and parse-time limits

### 1) What’s wrong/risky now
- “per-symbol AEAD tags + per-frame session MAC” is **not interoperable** without specifying:
  - which AEAD, which tag length, nonce derivation, AAD, and key derivation
  - MAC algorithm and what bytes it covers
- `Symbol Count`, `Symbol Size`, and `Total Payload Length` have no explicit bounds → memory/CPU DoS.
- Replay/reordering behavior is underspecified. Two seq fields (`Datagram seq` and `Frame Seq`) could diverge.

### 2) Proposed change + rationale
- Define a **mandatory-to-implement** cryptographic suite for v2:
  - AEAD: XChaCha20‑Poly1305 (or ChaCha20‑Poly1305 if you insist on 96‑bit nonces; XChaCha is safer for derived nonces)
  - MAC: HMAC‑SHA‑256 truncated to 16 bytes (fast, widely available)
- Define nonce derivation from session_id + sender_instance + frame_seq + symbol_index to guarantee uniqueness.
- Define AAD to include the frame header + symbol_index for integrity of routing metadata.
- Define strict validation bounds to prevent DoS and ambiguous parsing.
- Clarify that datagram `seq` MUST equal frame `Frame Seq` for consistency and early replay filtering.

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 ### 3.1 Frame Format (114-byte header)
````

Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")
Bytes 4-5:    Version (u16 LE)
Bytes 6-7:    Flags (u16 LE)
Bytes 8-11:   Symbol Count (u32 LE)
Bytes 12-15:  Total Payload Length (u32 LE)
Bytes 16-47:  Object ID (32 bytes)
Bytes 48-49:  Symbol Size (u16 LE, default 1024)
Bytes 50-57:  Zone Key ID (8 bytes, for rotation)
Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3)
Bytes 90-97:  Epoch ID (u64 LE)
Bytes 98-105: Sender Instance ID (u64 LE, reboot-safety)
Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic)
Bytes 114+:   Symbol payloads (encrypted, concatenated)

NOTE: No separate checksum. Integrity provided by per-symbol AEAD tags + per-frame session MAC.

```
+
+NORMATIVE requirements (cryptography, replay, and parsing):
+- Versioning: Implementations MUST reject frames with an unsupported `Version`. Unknown/unsupported `Flags` bits MUST cause rejection (fail closed) unless the bit is explicitly marked as ignorable in this spec.
+- Mandatory-to-implement crypto suite for FCP V2:
+  - AEAD: XChaCha20-Poly1305 with a 16-byte tag per symbol.
+  - Session MAC: HMAC-SHA-256 truncated to 16 bytes.
+  - Session key derivation MUST use a standard KDF (e.g., HKDF-SHA-256) over a session secret established out-of-band (session establishment is outside this excerpt).
+- Per-symbol encryption:
+  - For symbol index `i` (0-based), nonce MUST be `BLAKE3-192("fcp.fcps.nonce.v2" || session_id || sender_instance_id_le || frame_seq_le || u32_le(i))` (24 bytes).
+  - AEAD AAD MUST include the 114-byte frame header (bytes 0-113) concatenated with `u32_le(i)`.
+  - `Total Payload Length` MUST equal `SymbolCount * (SymbolSize + 16)` when using XChaCha20-Poly1305.
+- Replay protection:
+  - `Sender Instance ID` MUST be generated randomly at process start (reboot) and MUST change on restart.
+  - Receivers MUST track a replay window keyed by `(session_id, sender_instance_id)` and reject duplicate `Frame Seq` values and excessively-old sequences.
+- Parse-time hard limits (DoS resistance):
+  - Implementations MUST reject frames with `Symbol Count` > 256, `Symbol Size` < 256, or `Symbol Size` > 16384 unless explicitly configured.
+  - Implementations MUST reject frames where `Total Payload Length` exceeds the datagram payload length or where header fields are internally inconsistent.
@@
### 3.2 FCPS Datagram Envelope
```

FCPS_DATAGRAM (on-wire):
Bytes 0-15:   session_id [16]
Bytes 16-23:  seq (u64 LE)
Bytes 24-39:  mac [16]
Bytes 40..:   fcps_frame_bytes

MTU rule: len(FCPS_DATAGRAM) MUST be <= max_datagram_bytes (default: 1200)

```
+
+NORMATIVE requirements (datagram authentication):
+- `mac` MUST be `HMAC-SHA-256(session_mac_key, session_id || seq || fcps_frame_bytes)` truncated to 16 bytes.
+- `seq` MUST equal the frame header `Frame Seq` (bytes 106-113). Receivers MUST reject datagrams where these differ.
+- Receivers MUST verify `mac` before attempting to decrypt or process symbol payloads.
```

---

## Revision 6 — Make CapabilityToken audience unambiguous + support proof‑of‑possession tokens

### 1) What’s wrong/risky now

* `aud_binary` and `aud_connector` are both optional: tokens can end up with **no audience** or **two audiences** depending on implementation.
* Token is effectively **bearer**: if exfiltrated, it can be replayed from anywhere until expiry.
* `checkpoint_ref` optional: capabilities can be interpreted against an unknown or stale policy state, causing authorization drift.

### 2) Proposed change + rationale

* Replace `aud_binary`/`aud_connector` with a single `TokenAudience` enum (exactly one).
* Add `TokenBinding` to support **PoP** (proof-of-possession) binding to a node signature key; bearer tokens remain possible but discouraged.
* Keep `checkpoint_ref` optional structurally, but add normative requirement: MUST be present for non‑public zones and for any token carrying sensitive capabilities.

### 3) Patch

````diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 ### 4.1 CapabilityToken
 ```rust
+pub enum TokenAudience {
+    /// Token is valid only for a specific audited binary/object.
+    Binary(ObjectId),
+    /// Token is valid only for a specific connector identifier.
+    Connector(ConnectorId),
+}
+
+pub enum TokenBinding {
+    /// Bearer token (discouraged for non-public zones).
+    Bearer,
+    /// Proof-of-possession: requests MUST include a signature by the holder's node signature key.
+    NodeSigKey {
+        holder_node: TailscaleNodeId,
+        holder_sig_kid: [u8; 8],
+    },
+}
+
 pub struct CapabilityToken {
     pub jti: Uuid,
     pub sub: PrincipalId,
     pub iss_zone: ZoneId,
     pub iss_node: TailscaleNodeId,
     pub kid: [u8; 8],
+    pub aud: TokenAudience,
+    pub binding: TokenBinding,
     pub caps: Vec<CapabilityId>,
     pub zone_ceiling: ZoneId,
     pub grant_object_ids: Vec<ObjectId>,
     pub checkpoint_ref: Option<ObjectId>,
-    pub aud_binary: Option<ObjectId>,
-    pub aud_connector: Option<ConnectorId>,
     pub iat: u64,
     pub exp: u64,
     pub nbf: u64,
     pub sig: [u8; 64],
 }
````

*

+NORMATIVE requirements:
+- Tokens MUST be serialized canonically (deterministic CBOR) and signatures MUST be verified against the canonical bytes with `sig` set to empty.
+- `aud` MUST be enforced by the recipient: a connector MUST reject tokens whose `aud` does not match its connector id and/or audited binary id as applicable.
+- `checkpoint_ref` MUST be present for any token granting capabilities outside `z:public` and MUST refer to a checkpoint that the verifier has validated (quorum + rollback rules).
+- Token lifetimes SHOULD be short. Implementations SHOULD reject tokens with `exp - iat` > 24h (and SHOULD use much shorter windows for execution/elevation).
+- If `binding` is `NodeSigKey`, each privileged request MUST carry a proof signature by the holder’s node signature key over a domain-separated transcript that includes `(jti, request_object_id, a freshness nonce)`.

````

---

## Revision 7 — Make ApprovalScope.Execution deterministic and resistant to pattern/constraint bypass

### 1) What’s wrong/risky now
- `method_pattern: String` is ambiguous: regex vs glob vs prefix matching differences can create **authorization bypass** across implementations.
- `request_object_id` optional weakens auditability (“what exactly was approved?”).
- `InputConstraint` semantics are underspecified (type handling, canonicalization, missing fields). This leads to divergent enforcement.

### 2) Proposed change + rationale
- Make `request_object_id` mandatory to guarantee auditability and reproducibility.
- Define `method_pattern` grammar as a strict, anchored glob (or you can change to exact match only; glob provides controlled flexibility).
- Define constraint evaluation rules and default‑deny behavior when `input_hash` is absent.

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 pub enum ApprovalScope {
     Elevation {
         operation: OperationId,
         original_provenance: Provenance,
     },
     Declassification {
         from_zone: ZoneId,
         to_zone: ZoneId,
         object_ids: Vec<ObjectId>,
     },
     Execution {
         connector_id: ConnectorId,
         method_pattern: String,
-        request_object_id: Option<ObjectId>,
+        /// MUST reference an audited request object to make approvals reproducible and reviewable.
+        request_object_id: ObjectId,
         input_hash: Option<[u8; 32]>,
         input_constraints: Vec<InputConstraint>,
     },
 }
@@
 pub enum ConstraintOp {
     Eq, Neq, In, NotIn, Prefix, Suffix, Contains,
 }
````

*

+NORMATIVE requirements:
+- `method_pattern` MUST use a restricted, anchored glob syntax over ASCII:

* * Allowed wildcards: `*` (0+ chars) and `?` (exactly 1 char).
* * No regex features, no character classes, no alternation.
* * Patterns MUST be treated as anchored to the full method name (i.e., implicit `^...$`).
* * Max length of `method_pattern` MUST be ≤ 128 bytes; otherwise reject.
    +- `json_pointer` MUST follow RFC 6901 and MUST be validated before evaluation.
    +- If `input_hash` is `None`, then `input_constraints` MUST be non-empty and implementations MUST apply a default-deny rule for unconstrained fields (reject requests that contain fields not covered by constraints, unless the schema explicitly marks them as non-sensitive defaults).
    +- Implementations MUST cap `input_constraints` length (e.g., ≤ 64) and MUST reject constraint values that exceed a configured size limit to avoid DoS.

````

---

## Revision 8 — Define NetworkConstraints evaluation order + add DNS rebinding defenses and timeouts

### 1) What’s wrong/risky now
- `host_allow`, `cidr_deny`, `ip_allow` interactions are not defined → inconsistent behavior and SSRF bypasses.
- DNS rebinding is not addressed (hostnames resolving to internal/private ranges after initial allow).
- HTTP redirects can defeat allowlists if not revalidated.
- No timeouts/budgets: egress can hang indefinitely or download unbounded data → operational instability.

### 2) Proposed change + rationale
- Add explicit evaluation order: canonicalize host → match host allow patterns → resolve DNS → validate all resolved IPs against deny rules and allow rules → pin connection to resolved IP(s).
- Require redirect revalidation and add redirect cap.
- Add timeouts and max response size budgets (reliability + DoS resistance).
- Define SPKI pin format to prevent divergent interpretations.

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 pub struct NetworkConstraints {
     pub host_allow: Vec<String>,
     pub port_allow: Vec<u16>,
     pub ip_allow: Vec<IpAddr>,
     pub cidr_deny: Vec<String>,
     pub deny_localhost: bool,
     pub deny_private_ranges: bool,
     pub deny_tailnet_ranges: bool,
     pub require_sni: bool,
     pub spki_pins: Vec<String>,
     pub deny_ip_literals: bool,
     pub require_host_canonicalization: bool,
+    /// Maximum number of DNS A/AAAA answers permitted for a single resolution.
+    pub dns_max_ips: u16,
+    /// Maximum HTTP redirects permitted (for Http egress).
+    pub max_redirects: u8,
+    /// Connection establishment timeout.
+    pub connect_timeout_ms: u32,
+    /// Overall request budget (connect + transfer).
+    pub total_timeout_ms: u32,
+    /// Maximum bytes permitted in an egress response body (for Http egress).
+    pub max_response_bytes: u64,
 }
````

@@
pub struct EgressTcpConnectRequest {
pub host: String,
pub port: u16,
pub use_tls: bool,
pub sni: Option<String>,
pub spki_pins: Vec<String>,
pub credential: Option<CredentialId>,

* /// Optional per-request overrides (if absent, use NetworkConstraints defaults).
* pub connect_timeout_ms: Option<u32>,
* pub total_timeout_ms: Option<u32>,
  }

```
+
+NORMATIVE requirements:
+- Host canonicalization:
+  - If `require_host_canonicalization` is true, hosts MUST be canonicalized using IDNA2008 to ASCII (A-label), lowercased, and have any trailing dot removed.
+  - `host_allow` entries MUST be compared against the canonicalized host.
+  - Wildcards in `host_allow` MUST be limited to a single left-most `*.` form (e.g., `*.example.com`). Embedded wildcards MUST be rejected.
+- Evaluation order (SSRF & DNS rebinding defense):
+  1) If `deny_ip_literals` is true, reject host inputs that parse as IP literals (v4/v6).
+  2) Enforce `host_allow` and `port_allow` before DNS resolution.
+  3) Resolve DNS and cap answers at `dns_max_ips` (reject if exceeded).
+  4) Apply `deny_localhost`, `deny_private_ranges`, `deny_tailnet_ranges`, and `cidr_deny` against *every* resolved IP; reject if any resolution yields a denied IP.
+  5) If `ip_allow` is non-empty, all resolved IPs MUST be within `ip_allow` (strict allowlist).
+- Redirect handling (Http):
+  - Every redirect target MUST be re-validated under the same constraints.
+  - Implementations MUST enforce `max_redirects`.
+- TLS and pins:
+  - If `use_tls` is true and `require_sni` is true, `sni` MUST be present and MUST match the canonicalized host.
+  - `spki_pins` entries MUST be encoded as `base64(sha256(SPKI_DER))`. If pins are present, the validated chain MUST contain at least one pinned SPKI.
+- Timeouts and budgets MUST be enforced; absence of timeouts MUST be treated as a configuration error (fail closed).
```

---

## Revision 9 — Add ResourceObject digest + caching semantics to prevent TOCTOU and enable safe mirroring

### 1) What’s wrong/risky now

* `resource_uri` alone is not an integrity guarantee. URIs can be mutable (e.g., `https://...`) leading to TOCTOU.
* No digest/size/type metadata limits caching/mirroring and makes audit trails weaker.
* No guidance on when a resource can be pinned/mirrored safely.

### 2) Proposed change + rationale

* Add optional digest + algorithm + size/type + retrieval/expiry timestamps.
* Require digest for persisted/pinned/mirrored resources (matches Axiom 1’s durable-object requirement).
* Improves security (integrity), performance (cacheability), and reliability (expiration controls).

### 3) Patch

````diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 ## 6. ResourceObject Classification
 ```rust
 pub struct ResourceObject {
     pub header: ObjectHeader,
     pub resource_uri: String,
+    /// Optional content digest of the fetched bytes for immutability and safe mirroring.
+    pub resource_digest: Option<[u8; 32]>,
+    /// Digest algorithm identifier (e.g., "blake3-256"). Required if `resource_digest` is present.
+    pub resource_digest_alg: Option<String>,
+    /// Optional size metadata for budgets and caching.
+    pub resource_size_bytes: Option<u64>,
+    /// Optional content type hint (e.g., IANA media type).
+    pub resource_content_type: Option<String>,
+    /// Optional caching timestamps (unix seconds).
+    pub retrieved_at: Option<u64>,
+    pub expires_at: Option<u64>,
     pub resource_integrity_level: u8,
     pub resource_confidentiality_level: u8,
     pub resource_taint: TaintFlags,
     pub signature: Signature,
 }
````

*

+NORMATIVE requirements:
+- If a `ResourceObject` is persisted, audited, cached, mirrored, or pinned, `resource_digest` MUST be present and MUST match the fetched bytes.
+- `resource_uri` MUST be canonicalized according to its scheme (e.g., lowercased host, normalized path). Implementations MUST reject non-canonical URIs when `require_host_canonicalization` is enabled for egress.
+- If `expires_at` is present, implementations MUST NOT serve cached bytes past expiry without revalidation.

````

---

## Revision 10 — Harden registry trust: thresholds + TUF freshness controls + clearer mirror requirements

### 1) What’s wrong/risky now
- Remote registries with only `trusted_keys` but no threshold/freshness are vulnerable to:
  - single key compromise
  - rollback/freeze attacks if TUF is omitted or optional
- `RegistrySecurityProfile` doesn’t specify metadata freshness or thresholds; interop uncertainty.

### 2) Proposed change + rationale
- Add `trusted_keys_threshold` for Remote/SelfHosted sources.
- Add explicit TUF controls: `tuf_required`, threshold, and max metadata age.
- Require MeshMirror indexes to be validated against a policy and (when applicable) upstream TUF metadata.

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 ## 7. Registry & Supply Chain
 ```rust
 pub enum RegistrySource {
-    Remote { url: Url, trusted_keys: Vec<Ed25519PublicKey> },
-    SelfHosted { url: Url, trusted_keys: Vec<Ed25519PublicKey> },
+    Remote { url: Url, trusted_keys: Vec<Ed25519PublicKey>, trusted_keys_threshold: u8 },
+    SelfHosted { url: Url, trusted_keys: Vec<Ed25519PublicKey>, trusted_keys_threshold: u8 },
     MeshMirror { zone: ZoneId, index_object_id: ObjectId },
 }
 
 pub struct RegistrySecurityProfile {
     pub tuf_root_object_id: Option<ObjectId>,
+    /// If true, TUF metadata MUST be present and validated (recommended for all Remote/SelfHosted).
+    pub tuf_required: bool,
+    /// Minimum number of valid signatures required for registry metadata (TUF and/or package sigs).
+    pub signature_threshold: u8,
+    /// Maximum acceptable age for registry metadata (anti-freeze), in seconds.
+    pub max_metadata_age_secs: u64,
     pub require_sigstore: bool,
 }
````

*

+NORMATIVE requirements:
+- For `Remote` and `SelfHosted`, `trusted_keys_threshold` MUST be in `[1, len(trusted_keys)]` and signature verification MUST enforce that threshold.
+- `tuf_required` SHOULD be true for all `Remote` and `SelfHosted` registries. If `tuf_required` is true, `tuf_root_object_id` MUST be present and trusted as an immutable root.
+- Implementations MUST enforce `max_metadata_age_secs` to prevent freeze attacks (fail closed when metadata is stale).
+- For `MeshMirror`, the mirrored `index_object_id` MUST be signed under zone policy and SHOULD include immutable digests for all referenced artifacts.

````

---

## Revision 11 — Clarify manifest negotiation: feature flags, protocol string versioning, and stable interface hash rules

### 1) What’s wrong/risky now
- `min_protocol = "fcp2-sym"` is ambiguous (no versioning semantics).
- No explicit feature negotiation → interop failures when optional capabilities appear (compression, new crypto suites, replay windows).
- `interface_hash = "blake3:..."` lacks domain separation and explicit digest size, risking inconsistent hashing across languages.

### 2) Proposed change + rationale
- Version the protocol string (`fcp2-sym/2.0`) and add `protocol_features`.
- Add `max_datagram_bytes` to align transport constraints at deployment time.
- Make `interface_hash` specify algorithm and domain‑separated context.

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 ## 8. Manifest Compatibility
 ```toml
 [manifest]
 format = "fcp-connector-manifest"
-schema_version = "2.0"
+schema_version = "2.1"
 min_mesh_version = "2.0.0"
-min_protocol = "fcp2-sym"
-interface_hash = "blake3:..."
+min_protocol = "fcp2-sym/2.0"
+protocol_features = [
+  "fcps.aead.xchacha20poly1305",
+  "fcps.session_mac.hmacsha256.trunc16",
+  "egress.dns_rebind_protection",
+]
+max_datagram_bytes = 1200
+interface_hash = "blake3-256:fcp.interface.v2:..."
 
 [connector.state]
 model = "singleton_writer"
 state_schema_version = "1"
+state_migrations = ["1->2"]
````

*

+NORMATIVE requirements:
+- `min_mesh_version` MUST be evaluated using SemVer rules. Implementations MUST NOT compare version strings lexicographically.
+- `min_protocol` MUST include a version component. Receivers MUST reject connectors that require unsupported major protocol versions.
+- `protocol_features` MUST be treated as required capabilities unless explicitly documented as optional; missing required features MUST cause refusal to run (fail closed).
+- `interface_hash` MUST be computed over a canonical, schema-defined connector interface descriptor with explicit domain separation ("fcp.interface.v2") and digest size.

````

---

## Revision 12 — Add a normative observability section: reason codes, metrics, and safe debug signals

### 1) What’s wrong/risky now
- The spec asks “Is it debuggable and observable?” but provides no standard:
  - reason codes for drops/denies
  - required metrics/log points
  - safe redaction rules (avoid leaking secrets)
- Without standardization, ops teams get inconsistent behavior and tooling.

### 2) Proposed change + rationale
- Add a small but normative section that standardizes:
  - minimum counters/events
  - stable error/reason codes
  - requirements for redaction and correlation IDs
- Improves operational reliability, incident response, and cross‑impl comparability.

### 3) Patch
```diff
diff --git a/../../../tmp/fcp_condensed.md b/../../../tmp/fcp_condensed.md
--- a/../../../tmp/fcp_condensed.md
+++ b/../../../tmp/fcp_condensed.md
@@
 ## 9. Canonical Identifier Grammar
 All identifiers (PrincipalId, ConnectorId, CapabilityId, etc.) MUST:
 - Be ASCII-only, lowercase
 - Length ≤ 128 bytes
 - Match: ^[a-z0-9][a-z0-9._:-]*$
+
+## 10. Operational Observability (Normative)
+Implementations MUST be debuggable without compromising secrets.
+
+Minimum requirements:
+- Structured logs MUST be emitted for: authentication failures, capability denials, egress denials, MAC/AEAD failures, replay drops, and checkpoint validation failures.
+- Logs MUST include stable identifiers where available (e.g., `zone_id`, `checkpoint_seq`, `object_id`, `jti`) but MUST NOT include raw secrets, private keys, or decrypted payload bytes by default.
+- Implementations MUST expose counters/metrics at minimum:
+  - `fcps_datagrams_rx_total`, `fcps_datagrams_mac_fail_total`, `fcps_symbols_aead_fail_total`, `fcps_replay_drop_total`
+  - `capability_token_verify_fail_total`, `capability_denied_total`
+  - `egress_allowed_total`, `egress_denied_total`, `egress_timeout_total`
+- Implementations SHOULD support a “diagnostic mode” that records additional reason codes while preserving redaction.
+- Recommended stable reason code set (examples): `FCP_ERR_UNSUPPORTED_VERSION`, `FCP_ERR_BAD_FLAGS`, `FCP_ERR_MAC_INVALID`, `FCP_ERR_AEAD_INVALID`, `FCP_ERR_REPLAY`, `FCP_ERR_TOKEN_EXPIRED`, `FCP_ERR_TOKEN_AUD_MISMATCH`, `FCP_ERR_EGRESS_DENIED`.
 
 ## Key Areas for Review
 1. **Security**: Are there gaps in the capability/approval model?
 2. **Interoperability**: Are wire formats unambiguous enough?
 3. **Performance**: Any obvious bottlenecks or inefficiencies?
 4. **Operational**: Is the system debuggable and observable?
 5. **Cryptography**: Are primitives correctly used?
 6. **Versioning**: Is upgrade/migration path clear?
````

---

### If you want one “apply-all” patch

I can also provide a **single consolidated diff** that merges these cleanly into one file update (instead of 12 independent patches).

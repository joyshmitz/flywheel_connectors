Below are the highest-leverage revisions I’d make to FCP V2 to (a) remove a few internal contradictions, (b) harden the security model against realistic failure modes (compromise + equivocation + downgrade), (c) improve performance without weakening invariants, and (d) make the spec more mechanically implementable + testable.
I’m giving each proposal:


What changes


Why it’s better (detailed rationale)


Git-diff style patch against the plan text you pasted (treat it as FCP_Specification_V2.md)



1) Resolve the biggest spec contradiction: zone keys “HKDF-derived from owner secret” vs “distributed via ZoneKeyManifest”
What changes
Make zone encryption keys randomly generated symmetric keys (rotatable, per-zone), distributed to eligible nodes via ZoneKeyManifest (sealed per-node). Keep HKDF for subkey derivation, not for deriving the zone key from the owner secret.
Why it’s better


Operational reality: Rotating a symmetric zone key should not require the owner secret (and definitely shouldn’t require threshold owner signing online for routine key churn).


Security hygiene: You want the owner key used for attestation/revocation, not as an online KDF root for routine encryption.


Blast-radius clarity: If the owner key participates in deriving zone keys, compromise of any threshold share-custodian becomes tied to data confidentiality in a way you don’t need.


Eliminates ambiguity in implementations: today an implementer could build two incompatible systems that both “conform.”


Patch
diffCopy codediff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
-## 5. Zone Architecture
-Zones are **cryptographic boundaries**, not labels. Each zone has its own encryption key derived from the owner's secret key using HKDF with domain separation.
+## 5. Zone Architecture
+Zones are **cryptographic boundaries**, not labels. Each zone has its own symmetric encryption key material
+that is **randomly generated** and distributed to eligible nodes via `ZoneKeyManifest` objects (sealed to each node).
+HKDF is used for **subkey derivation** (e.g., per-sender subkeys, epoch subkeys), not for deriving the zone key from owner secret material.
@@
-/// Zone encryption key (NORMATIVE)
+/// Zone encryption key (NORMATIVE)
 pub struct ZoneKey {
     pub zone_id: ZoneId,
     pub key_id: [u8; 8],
-    pub symmetric_key: [u8; 32],  // ChaCha20-Poly1305
+    pub symmetric_key: [u8; 32],  // ChaCha20-Poly1305 (randomly generated)
     pub created_at: u64,
     pub expires_at: Option<u64>,
 }
@@
-    /// Zone keys are provisioned via ZoneKeyManifest objects (NORMATIVE).
-    /// Nodes MUST NOT require access to owner secret key material to encrypt/decrypt zone data.
+    /// Zone keys are provisioned via ZoneKeyManifest objects (NORMATIVE).
+    /// Nodes MUST NOT require access to owner secret key material to encrypt/decrypt zone data.
+    /// The owner key signs manifests (authorization), but does not act as an online KDF root for zone encryption keys.


2) Add “Post-compromise security” for zones via MLS/TreeKEM (optional but strongly recommended for z:owner/z:private)
What changes
Introduce an optional Zone Group Key Agreement mode (MLS-style TreeKEM) for zones where post-compromise security matters. Keep current ZoneKeyManifest as baseline; add MLS as an upgrade path.
Why it’s better
Your current model gives good rotation semantics, but if a device is compromised and silently exfiltrates zone keys, you don’t get strong post-compromise guarantees without heavy operational discipline. MLS/TreeKEM gives:


PCS (post-compromise security): after removal/commit, the attacker loses access to future traffic even if they stole past keys.


Asynchronous membership changes that fit your “mesh/offline” story.


A clean story for “z:owner” where you really want strongest properties.


Patch
diffCopy codediff --git a/FCP_Specification_V2.md b/FCP_Specification_V2.md
--- a/FCP_Specification_V2.md
+++ b/FCP_Specification_V2.md
@@
 ## 5. Zone Architecture
@@
+### 5.X Zone Group Key Agreement (RECOMMENDED for z:owner, z:private)
+FCP V2 supports an optional group key agreement mode for zones using MLS-style TreeKEM.
+When enabled, zone membership changes produce a new epoch of group secrets with post-compromise security (PCS).
+
+NORMATIVE:
+- Implementations MAY omit MLS support, but if supported it MUST be selectable per-zone.
+- When MLS is enabled for a zone, `ZoneKeyManifest` objects distribute **epoch secrets** (or MLS commit secrets),
+  not long-lived static symmetric zone keys.
+
+pub enum ZoneKeyMode {
+    /// Baseline: symmetric keys distributed via owner-signed manifests
+    ManifestDistributed,
+    /// Optional upgrade: MLS/TreeKEM group key agreement for post-compromise security
+    MlsTreeKem,
+}
+
+pub struct ZoneSecurityProfile {
+    pub zone_id: ZoneId,
+    pub key_mode: ZoneKeyMode,
+    pub require_pcs: bool,      // default true for z:owner if MLS enabled
+    pub max_epoch_secs: u64,    // bounds exposure window
+}


3) Replace “frame_seq monotonic per sender per zone_key_id” with a formally-defined anti-replay window + persistence requirements
What changes
Right now frame_seq is “monotonic” but you don’t specify:


persistence requirements across restar

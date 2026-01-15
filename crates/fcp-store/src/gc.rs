//! Garbage collection for FCP2 stores (NORMATIVE).
//!
//! Implements reachability-based GC from `FCP_Specification_V2.md` §3.7.

use std::collections::{HashSet, VecDeque};

use fcp_core::{ObjectId, RetentionClass, ZoneId};
use serde::{Deserialize, Serialize};

use crate::error::GcError;
use crate::object_store::ObjectStore;

/// Result of a garbage collection run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcResult {
    /// Number of live (reachable) objects.
    pub live: usize,
    /// Number of objects evicted.
    pub evicted: usize,
    /// Number of objects with expired leases.
    pub expired_leases: usize,
    /// Number of pinned objects (never evicted).
    pub pinned: usize,
}

/// GC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcConfig {
    /// Maximum objects to evict per GC run (prevents long pauses).
    pub max_evictions_per_run: usize,
    /// Whether to respect lease expiry times.
    pub enforce_lease_expiry: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            max_evictions_per_run: 10_000,
            enforce_lease_expiry: true,
        }
    }
}

/// GC root sources.
#[derive(Debug, Clone)]
pub struct GcRoots {
    /// Zone checkpoint object ID (canonical zone root).
    pub zone_checkpoint: Option<ObjectId>,
    /// Locally pinned objects.
    pub pinned: HashSet<ObjectId>,
}

impl GcRoots {
    /// Create empty GC roots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            zone_checkpoint: None,
            pinned: HashSet::new(),
        }
    }

    /// Set the zone checkpoint root.
    pub const fn set_checkpoint(&mut self, checkpoint: ObjectId) {
        self.zone_checkpoint = Some(checkpoint);
    }

    /// Add a pinned root.
    pub fn add_pin(&mut self, object_id: ObjectId) {
        self.pinned.insert(object_id);
    }

    /// Remove a pinned root.
    pub fn remove_pin(&mut self, object_id: &ObjectId) {
        self.pinned.remove(object_id);
    }

    /// Check if an object is a root.
    #[must_use]
    pub fn is_root(&self, object_id: &ObjectId) -> bool {
        self.zone_checkpoint.as_ref() == Some(object_id) || self.pinned.contains(object_id)
    }

    /// Get all root object IDs.
    #[must_use]
    pub fn all_roots(&self) -> HashSet<ObjectId> {
        let mut roots = self.pinned.clone();
        if let Some(checkpoint) = &self.zone_checkpoint {
            roots.insert(*checkpoint);
        }
        roots
    }
}

impl Default for GcRoots {
    fn default() -> Self {
        Self::new()
    }
}

/// Garbage collector for a zone.
pub struct GarbageCollector {
    config: GcConfig,
}

impl GarbageCollector {
    /// Create a new garbage collector.
    #[must_use]
    pub const fn new(config: GcConfig) -> Self {
        Self { config }
    }

    /// Run garbage collection on a zone (NORMATIVE algorithm).
    ///
    /// # Algorithm
    /// 1. Compute root set from zone checkpoint + local pins
    /// 2. Mark phase: traverse refs from roots
    /// 3. Sweep phase: evict unreachable non-pinned objects
    ///
    /// # Errors
    /// Returns error if object store operations fail.
    pub async fn collect(
        &self,
        zone_id: &ZoneId,
        roots: &GcRoots,
        store: &dyn ObjectStore,
        current_time: u64,
    ) -> Result<GcResult, GcError> {
        // 1. Compute root set
        let root_set = roots.all_roots();

        // 2. Mark phase: traverse refs from roots
        let mut live = HashSet::new();
        let mut queue: VecDeque<ObjectId> = root_set.into_iter().collect();

        while let Some(object_id) = queue.pop_front() {
            if live.insert(object_id) {
                if let Ok(header) = store.get_header(&object_id).await {
                    // Follow refs (NOT foreign_refs - those are handled by foreign zone's GC)
                    queue.extend(header.refs.iter().copied());
                }
            }
        }

        // 3. Sweep phase: evict unreachable non-pinned objects
        let mut evicted = 0;
        let mut expired_leases = 0;
        let mut pinned_count = 0;

        let all_objects = store.list_zone(zone_id).await;

        for object_id in all_objects {
            if evicted >= self.config.max_evictions_per_run {
                break; // Limit evictions per run
            }

            if live.contains(&object_id) {
                // Object is reachable, but check lease expiry
                if self.config.enforce_lease_expiry {
                    if let Ok(meta) = store.get_storage_meta(&object_id).await {
                        if let RetentionClass::Lease { expires_at } = meta.retention {
                            if expires_at <= current_time {
                                // Lease expired, evict unless pinned
                                if !roots.pinned.contains(&object_id) {
                                    store.delete(&object_id).await.ok();
                                    expired_leases += 1;
                                    evicted += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }
                continue;
            }

            // Object is unreachable
            if let Ok(meta) = store.get_storage_meta(&object_id).await {
                match meta.retention {
                    RetentionClass::Pinned => {
                        // Never evict pinned objects
                        pinned_count += 1;
                    }
                    RetentionClass::Lease { expires_at } => {
                        if !self.config.enforce_lease_expiry || expires_at <= current_time {
                            store.delete(&object_id).await.ok();
                            evicted += 1;
                            if expires_at <= current_time {
                                expired_leases += 1;
                            }
                        }
                    }
                    RetentionClass::Ephemeral => {
                        store.delete(&object_id).await.ok();
                        evicted += 1;
                    }
                }
            }
        }

        Ok(GcResult {
            live: live.len(),
            evicted,
            expired_leases,
            pinned: pinned_count,
        })
    }

    /// Check if an object would be collected (for debugging/testing).
    pub async fn would_collect(
        &self,
        object_id: &ObjectId,
        zone_id: &ZoneId,
        roots: &GcRoots,
        store: &dyn ObjectStore,
        current_time: u64,
    ) -> bool {
        // Check if object is a root
        if roots.is_root(object_id) {
            return false;
        }

        // Check if pinned
        if let Ok(meta) = store.get_storage_meta(object_id).await {
            if matches!(meta.retention, RetentionClass::Pinned) {
                return false;
            }

            // Check lease
            if let RetentionClass::Lease { expires_at } = meta.retention {
                if self.config.enforce_lease_expiry && expires_at > current_time {
                    // Would not collect if reachable
                    // Need to check reachability
                }
            }
        }

        // Check reachability from roots
        let root_set = roots.all_roots();
        let mut visited = HashSet::new();
        let mut queue: VecDeque<ObjectId> = root_set.into_iter().collect();

        while let Some(id) = queue.pop_front() {
            if &id == object_id {
                return false; // Found path to object
            }

            if visited.insert(id) {
                if let Ok(header) = store.get_header(&id).await {
                    // Only check if in same zone
                    if &header.zone_id == zone_id {
                        queue.extend(header.refs.iter().copied());
                    }
                }
            }
        }

        true // Not reachable, would be collected
    }
}

#[cfg(test)]
mod tests {
    use fcp_cbor::SchemaId;
    use fcp_core::{ObjectHeader, Provenance, StorageMeta, StoredObject};
    use semver::Version;

    use super::*;
    use crate::object_store::{MemoryObjectStore, MemoryObjectStoreConfig};

    fn test_zone() -> ZoneId {
        "z:test".parse().unwrap()
    }

    fn test_object(id: u8, refs: Vec<u8>, retention: RetentionClass) -> StoredObject {
        StoredObject {
            object_id: ObjectId::from_bytes([id; 32]),
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
                zone_id: test_zone(),
                created_at: 1_000_000,
                provenance: Provenance::new(test_zone()),
                refs: refs
                    .into_iter()
                    .map(|r| ObjectId::from_bytes([r; 32]))
                    .collect(),
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            body: vec![0_u8; 100],
            storage: StorageMeta { retention },
        }
    }

    #[tokio::test]
    async fn gc_evicts_unreachable() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let gc = GarbageCollector::new(GcConfig::default());

        // Root -> A -> B (reachable)
        // C (unreachable)
        store
            .put(test_object(1, vec![2], RetentionClass::Ephemeral))
            .await
            .unwrap(); // Root
        store
            .put(test_object(2, vec![3], RetentionClass::Ephemeral))
            .await
            .unwrap(); // A
        store
            .put(test_object(3, vec![], RetentionClass::Ephemeral))
            .await
            .unwrap(); // B
        store
            .put(test_object(4, vec![], RetentionClass::Ephemeral))
            .await
            .unwrap(); // C (unreachable)

        let mut roots = GcRoots::new();
        roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

        let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

        assert_eq!(result.live, 3); // Root + A + B
        assert_eq!(result.evicted, 1); // C

        assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);
        assert!(store.exists(&ObjectId::from_bytes([2; 32])).await);
        assert!(store.exists(&ObjectId::from_bytes([3; 32])).await);
        assert!(!store.exists(&ObjectId::from_bytes([4; 32])).await); // Evicted
    }

    #[tokio::test]
    async fn gc_respects_pinned() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let gc = GarbageCollector::new(GcConfig::default());

        // Unreachable but pinned
        store
            .put(test_object(1, vec![], RetentionClass::Pinned))
            .await
            .unwrap();

        let roots = GcRoots::new(); // No roots

        let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

        assert_eq!(result.pinned, 1);
        assert_eq!(result.evicted, 0);
        assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);
    }

    #[tokio::test]
    async fn gc_respects_lease() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let gc = GarbageCollector::new(GcConfig::default());

        // Unreachable with unexpired lease
        store
            .put(test_object(
                1,
                vec![],
                RetentionClass::Lease { expires_at: 2000 },
            ))
            .await
            .unwrap();
        // Unreachable with expired lease
        store
            .put(test_object(
                2,
                vec![],
                RetentionClass::Lease { expires_at: 500 },
            ))
            .await
            .unwrap();

        let roots = GcRoots::new();

        let result = gc
            .collect(&test_zone(), &roots, &store, 1000)
            .await
            .unwrap();

        assert_eq!(result.evicted, 1);
        assert_eq!(result.expired_leases, 1);
        assert!(store.exists(&ObjectId::from_bytes([1; 32])).await); // Lease not expired
        assert!(!store.exists(&ObjectId::from_bytes([2; 32])).await); // Lease expired
    }

    #[tokio::test]
    async fn gc_respects_max_evictions() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let config = GcConfig {
            max_evictions_per_run: 2,
            ..Default::default()
        };
        let gc = GarbageCollector::new(config);

        // Add 5 unreachable objects
        for i in 1..=5 {
            store
                .put(test_object(i, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();
        }

        let roots = GcRoots::new();

        let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

        assert_eq!(result.evicted, 2); // Limited by max_evictions_per_run
    }

    #[tokio::test]
    async fn gc_roots_management() {
        let mut roots = GcRoots::new();

        let id1 = ObjectId::from_bytes([1; 32]);
        let id2 = ObjectId::from_bytes([2; 32]);
        let id3 = ObjectId::from_bytes([3; 32]);

        roots.set_checkpoint(id1);
        roots.add_pin(id2);
        roots.add_pin(id3);

        assert!(roots.is_root(&id1));
        assert!(roots.is_root(&id2));
        assert!(roots.is_root(&id3));

        let all = roots.all_roots();
        assert_eq!(all.len(), 3);

        roots.remove_pin(&id2);
        assert!(!roots.is_root(&id2));
    }

    #[tokio::test]
    async fn would_collect_unreachable() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let gc = GarbageCollector::new(GcConfig::default());

        store
            .put(test_object(1, vec![], RetentionClass::Ephemeral))
            .await
            .unwrap();
        store
            .put(test_object(2, vec![], RetentionClass::Ephemeral))
            .await
            .unwrap();

        let mut roots = GcRoots::new();
        roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

        // Object 1 is root - would not collect
        assert!(
            !gc.would_collect(
                &ObjectId::from_bytes([1; 32]),
                &test_zone(),
                &roots,
                &store,
                0
            )
            .await
        );

        // Object 2 is unreachable - would collect
        assert!(
            gc.would_collect(
                &ObjectId::from_bytes([2; 32]),
                &test_zone(),
                &roots,
                &store,
                0
            )
            .await
        );
    }
}

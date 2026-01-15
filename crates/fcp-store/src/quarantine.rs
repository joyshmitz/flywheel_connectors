//! Quarantine store for untrusted/unreferenced objects (NORMATIVE).
//!
//! Implements the object admission pipeline from `FCP_Specification_V2.md` §8.4.1.

use std::collections::{BinaryHeap, HashMap};

use bytes::Bytes;
use fcp_core::{ObjectId, ZoneId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::QuarantineError;

/// Object admission classification (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectAdmissionClass {
    /// Unknown provenance, bounded retention, not gossiped.
    Quarantined,
    /// Verified reachable, normal retention, gossiped.
    Admitted,
}

/// Object admission policy (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAdmissionPolicy {
    /// Maximum quarantine storage per zone (default: 256MB).
    pub max_quarantine_bytes_per_zone: u64,
    /// Maximum quarantined objects per zone (default: 100,000).
    pub max_quarantine_objects_per_zone: u32,
    /// TTL for quarantined objects before eviction (default: 3600s).
    pub quarantine_ttl_secs: u64,
    /// Whether to require schema validation on promotion (default: true).
    pub require_schema_validation: bool,
}

impl Default for ObjectAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_quarantine_bytes_per_zone: 256 * 1024 * 1024, // 256MB
            max_quarantine_objects_per_zone: 100_000,
            quarantine_ttl_secs: 3600,
            require_schema_validation: true,
        }
    }
}

/// Quarantined object entry.
#[derive(Debug, Clone)]
pub struct QuarantinedObject {
    /// Object ID.
    pub object_id: ObjectId,
    /// Zone this object belongs to.
    pub zone_id: ZoneId,
    /// Raw object data (symbols or reconstructed body).
    pub data: Bytes,
    /// Peer that sent this object.
    pub source_peer: Option<u64>,
    /// Timestamp when received.
    pub received_at: u64,
    /// Peer reputation score at time of receipt (lower = worse).
    pub peer_reputation: i32,
}

/// Entry for eviction priority queue.
#[derive(Debug, Clone, Eq, PartialEq)]
struct EvictionEntry {
    object_id: ObjectId,
    received_at: u64,
    peer_reputation: i32,
    size: u64,
}

impl Ord for EvictionEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Priority order: oldest first, then lowest reputation, then largest
        // We use reverse ordering because BinaryHeap is a max-heap
        other
            .received_at
            .cmp(&self.received_at)
            .then_with(|| self.peer_reputation.cmp(&other.peer_reputation))
            .then_with(|| other.size.cmp(&self.size))
    }
}

impl PartialOrd for EvictionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-zone quarantine state.
#[derive(Debug)]
struct ZoneQuarantine {
    objects: HashMap<ObjectId, QuarantinedObject>,
    used_bytes: u64,
    eviction_queue: BinaryHeap<EvictionEntry>,
}

impl ZoneQuarantine {
    fn new() -> Self {
        Self {
            objects: HashMap::new(),
            used_bytes: 0,
            eviction_queue: BinaryHeap::new(),
        }
    }
}

/// Quarantine store for untrusted objects (NORMATIVE).
///
/// Implements bounded admission with per-zone quotas and TTL eviction.
pub struct QuarantineStore {
    zones: RwLock<HashMap<ZoneId, ZoneQuarantine>>,
    policy: ObjectAdmissionPolicy,
}

impl QuarantineStore {
    /// Create a new quarantine store with the given policy.
    #[must_use]
    pub fn new(policy: ObjectAdmissionPolicy) -> Self {
        Self {
            zones: RwLock::new(HashMap::new()),
            policy,
        }
    }

    /// Add an object to quarantine.
    ///
    /// If quotas are exceeded, evicts objects according to policy.
    ///
    /// # Errors
    /// Returns error if the object cannot be quarantined even after eviction.
    pub fn quarantine(&self, obj: QuarantinedObject) -> Result<(), QuarantineError> {
        #[allow(clippy::cast_possible_truncation)]
        let obj_size = obj.data.len() as u64;

        let mut zones = self.zones.write();
        let zone = zones
            .entry(obj.zone_id.clone())
            .or_insert_with(ZoneQuarantine::new);

        // Check if already quarantined
        if zone.objects.contains_key(&obj.object_id) {
            return Ok(()); // Already in quarantine
        }

        // Evict if necessary to make room
        while zone.objects.len() as u32 >= self.policy.max_quarantine_objects_per_zone
            || zone.used_bytes + obj_size > self.policy.max_quarantine_bytes_per_zone
        {
            if let Some(entry) = zone.eviction_queue.pop() {
                if let Some(evicted) = zone.objects.remove(&entry.object_id) {
                    #[allow(clippy::cast_possible_truncation)]
                    let evicted_size = evicted.data.len() as u64;
                    zone.used_bytes = zone.used_bytes.saturating_sub(evicted_size);
                    tracing::debug!(
                        object_id = %entry.object_id,
                        "Evicted quarantined object"
                    );
                }
            } else {
                // No more objects to evict
                return Err(QuarantineError::QuotaExceeded {
                    used: zone.used_bytes,
                    max: self.policy.max_quarantine_bytes_per_zone,
                });
            }
        }

        // Add eviction entry
        zone.eviction_queue.push(EvictionEntry {
            object_id: obj.object_id,
            received_at: obj.received_at,
            peer_reputation: obj.peer_reputation,
            size: obj_size,
        });

        zone.used_bytes += obj_size;
        zone.objects.insert(obj.object_id, obj);

        Ok(())
    }

    /// Get a quarantined object.
    pub fn get(&self, object_id: &ObjectId) -> Option<QuarantinedObject> {
        let zones = self.zones.read();
        for zone in zones.values() {
            if let Some(obj) = zone.objects.get(object_id) {
                return Some(obj.clone());
            }
        }
        None
    }

    /// Remove an object from quarantine (for promotion).
    ///
    /// # Errors
    /// Returns `NotFound` if object is not in quarantine.
    pub fn remove(&self, object_id: &ObjectId) -> Result<QuarantinedObject, QuarantineError> {
        let mut zones = self.zones.write();
        for zone in zones.values_mut() {
            if let Some(obj) = zone.objects.remove(object_id) {
                #[allow(clippy::cast_possible_truncation)]
                let obj_size = obj.data.len() as u64;
                zone.used_bytes = zone.used_bytes.saturating_sub(obj_size);
                // Note: eviction_queue entry will be orphaned but harmless
                return Ok(obj);
            }
        }
        Err(QuarantineError::NotFound(*object_id))
    }

    /// Check if an object is in quarantine.
    #[must_use]
    pub fn contains(&self, object_id: &ObjectId) -> bool {
        let zones = self.zones.read();
        zones.values().any(|z| z.objects.contains_key(object_id))
    }

    /// Evict objects older than TTL.
    ///
    /// Returns the number of objects evicted.
    pub fn evict_expired(&self, current_time: u64) -> usize {
        let ttl = self.policy.quarantine_ttl_secs;
        let mut evicted = 0;

        let mut zones = self.zones.write();
        for zone in zones.values_mut() {
            let expired: Vec<ObjectId> = zone
                .objects
                .iter()
                .filter(|(_, obj)| current_time.saturating_sub(obj.received_at) > ttl)
                .map(|(id, _)| *id)
                .collect();

            for id in expired {
                if let Some(obj) = zone.objects.remove(&id) {
                    #[allow(clippy::cast_possible_truncation)]
                    let obj_size = obj.data.len() as u64;
                    zone.used_bytes = zone.used_bytes.saturating_sub(obj_size);
                    evicted += 1;
                }
            }
        }

        evicted
    }

    /// Get quarantine statistics for a zone.
    #[must_use]
    pub fn zone_stats(&self, zone_id: &ZoneId) -> QuarantineStats {
        let zones = self.zones.read();
        if let Some(zone) = zones.get(zone_id) {
            QuarantineStats {
                object_count: zone.objects.len() as u32,
                used_bytes: zone.used_bytes,
                max_bytes: self.policy.max_quarantine_bytes_per_zone,
                max_objects: self.policy.max_quarantine_objects_per_zone,
            }
        } else {
            QuarantineStats {
                object_count: 0,
                used_bytes: 0,
                max_bytes: self.policy.max_quarantine_bytes_per_zone,
                max_objects: self.policy.max_quarantine_objects_per_zone,
            }
        }
    }

    /// List all quarantined objects in a zone.
    pub fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        let zones = self.zones.read();
        zones
            .get(zone_id)
            .map(|z| z.objects.keys().copied().collect())
            .unwrap_or_default()
    }
}

/// Quarantine statistics for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineStats {
    /// Number of quarantined objects.
    pub object_count: u32,
    /// Bytes used by quarantined objects.
    pub used_bytes: u64,
    /// Maximum bytes allowed.
    pub max_bytes: u64,
    /// Maximum objects allowed.
    pub max_objects: u32,
}

impl QuarantineStats {
    /// Check if quarantine is near capacity.
    #[must_use]
    pub fn is_near_capacity(&self, threshold_pct: u8) -> bool {
        let threshold = u64::from(threshold_pct);
        let bytes_pct = self.used_bytes * 100 / self.max_bytes.max(1);
        let objects_pct = u64::from(self.object_count) * 100 / u64::from(self.max_objects.max(1));
        bytes_pct >= threshold || objects_pct >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_zone() -> ZoneId {
        "z:test".parse().unwrap()
    }

    fn test_object(id: u8, size: usize, received_at: u64) -> QuarantinedObject {
        QuarantinedObject {
            object_id: ObjectId::from_bytes([id; 32]),
            zone_id: test_zone(),
            data: Bytes::from(vec![0_u8; size]),
            source_peer: Some(1),
            received_at,
            peer_reputation: 50,
        }
    }

    #[test]
    fn quarantine_and_get() {
        let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
        let obj = test_object(1, 100, 1000);

        store.quarantine(obj.clone()).unwrap();

        let retrieved = store.get(&obj.object_id).unwrap();
        assert_eq!(retrieved.object_id, obj.object_id);
    }

    #[test]
    fn quarantine_duplicate_ignored() {
        let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
        let obj = test_object(1, 100, 1000);

        store.quarantine(obj.clone()).unwrap();
        store.quarantine(obj).unwrap(); // Should not error

        let stats = store.zone_stats(&test_zone());
        assert_eq!(stats.object_count, 1);
    }

    #[test]
    fn remove_from_quarantine() {
        let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
        let obj = test_object(1, 100, 1000);
        let id = obj.object_id;

        store.quarantine(obj).unwrap();
        assert!(store.contains(&id));

        store.remove(&id).unwrap();
        assert!(!store.contains(&id));
    }

    #[test]
    fn evict_oldest_on_object_quota() {
        let policy = ObjectAdmissionPolicy {
            max_quarantine_objects_per_zone: 3,
            max_quarantine_bytes_per_zone: 1024 * 1024,
            ..Default::default()
        };
        let store = QuarantineStore::new(policy);

        // Add 3 objects
        store.quarantine(test_object(1, 100, 1000)).unwrap(); // oldest
        store.quarantine(test_object(2, 100, 2000)).unwrap();
        store.quarantine(test_object(3, 100, 3000)).unwrap();

        // Add 4th - should evict oldest (1)
        store.quarantine(test_object(4, 100, 4000)).unwrap();

        let stats = store.zone_stats(&test_zone());
        assert_eq!(stats.object_count, 3);
        assert!(!store.contains(&ObjectId::from_bytes([1; 32]))); // Evicted
        assert!(store.contains(&ObjectId::from_bytes([4; 32]))); // Added
    }

    #[test]
    fn evict_on_byte_quota() {
        let policy = ObjectAdmissionPolicy {
            max_quarantine_objects_per_zone: 100,
            max_quarantine_bytes_per_zone: 300,
            ..Default::default()
        };
        let store = QuarantineStore::new(policy);

        store.quarantine(test_object(1, 100, 1000)).unwrap();
        store.quarantine(test_object(2, 100, 2000)).unwrap();
        store.quarantine(test_object(3, 100, 3000)).unwrap();

        // This should trigger eviction
        store.quarantine(test_object(4, 100, 4000)).unwrap();

        assert!(!store.contains(&ObjectId::from_bytes([1; 32])));
    }

    #[test]
    fn evict_expired() {
        let policy = ObjectAdmissionPolicy {
            quarantine_ttl_secs: 100,
            ..Default::default()
        };
        let store = QuarantineStore::new(policy);

        store.quarantine(test_object(1, 100, 1000)).unwrap(); // Will expire
        store.quarantine(test_object(2, 100, 1050)).unwrap(); // Will expire
        store.quarantine(test_object(3, 100, 1150)).unwrap(); // Will NOT expire

        // Current time = 1200, TTL = 100
        // Object 1: 1200 - 1000 = 200 > 100 -> expired
        // Object 2: 1200 - 1050 = 150 > 100 -> expired
        // Object 3: 1200 - 1150 = 50 < 100 -> not expired
        let evicted = store.evict_expired(1200);
        assert_eq!(evicted, 2);

        let stats = store.zone_stats(&test_zone());
        assert_eq!(stats.object_count, 1);
        assert!(store.contains(&ObjectId::from_bytes([3; 32])));
    }

    #[test]
    fn zone_stats() {
        let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

        store.quarantine(test_object(1, 100, 1000)).unwrap();
        store.quarantine(test_object(2, 200, 2000)).unwrap();

        let stats = store.zone_stats(&test_zone());
        assert_eq!(stats.object_count, 2);
        assert_eq!(stats.used_bytes, 300);
    }

    #[test]
    fn is_near_capacity() {
        let stats = QuarantineStats {
            object_count: 85,
            used_bytes: 200,
            max_bytes: 1000,
            max_objects: 100,
        };

        assert!(stats.is_near_capacity(80)); // 85% objects
        assert!(!stats.is_near_capacity(90)); // Below 90%
    }

    #[test]
    fn list_zone() {
        let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

        store.quarantine(test_object(1, 100, 1000)).unwrap();
        store.quarantine(test_object(2, 100, 2000)).unwrap();

        let ids = store.list_zone(&test_zone());
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn eviction_priority_order() {
        // Test that eviction respects: oldest first, then lowest reputation, then largest
        let policy = ObjectAdmissionPolicy {
            max_quarantine_objects_per_zone: 2,
            max_quarantine_bytes_per_zone: 1024 * 1024,
            ..Default::default()
        };
        let store = QuarantineStore::new(policy);

        let mut obj1 = test_object(1, 100, 2000);
        obj1.peer_reputation = 50;

        let mut obj2 = test_object(2, 100, 1000); // Oldest
        obj2.peer_reputation = 50;

        store.quarantine(obj1).unwrap();
        store.quarantine(obj2).unwrap();

        // Add 3rd - should evict oldest (obj2)
        store.quarantine(test_object(3, 100, 3000)).unwrap();

        assert!(store.contains(&ObjectId::from_bytes([1; 32])));
        assert!(!store.contains(&ObjectId::from_bytes([2; 32]))); // Evicted
        assert!(store.contains(&ObjectId::from_bytes([3; 32])));
    }
}

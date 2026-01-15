//! Object store interface for FCP2.
//!
//! Provides content-addressed storage for complete mesh objects.

use std::collections::HashMap;

use async_trait::async_trait;
use fcp_core::{ObjectHeader, ObjectId, RetentionClass, StorageMeta, StoredObject, ZoneId};
use parking_lot::RwLock;

use crate::error::ObjectStoreError;

/// Object store interface (NORMATIVE).
///
/// Stores complete, content-addressed objects with retention policies.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Store an object.
    ///
    /// # Errors
    /// Returns error if object already exists or quota exceeded.
    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError>;

    /// Retrieve an object by ID.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError>;

    /// Check if object exists.
    async fn exists(&self, id: &ObjectId) -> bool;

    /// Delete an object.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError>;

    /// Get object header without body.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError>;

    /// Get storage metadata.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError>;

    /// Update retention class for an object.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError>;

    /// List all object IDs in a zone.
    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId>;

    /// Get total storage used in bytes.
    async fn storage_used(&self) -> u64;

    /// Get storage quota in bytes.
    async fn storage_quota(&self) -> u64;
}

/// Configuration for in-memory object store.
#[derive(Debug, Clone)]
pub struct MemoryObjectStoreConfig {
    /// Maximum storage in bytes.
    pub max_bytes: u64,
}

impl Default for MemoryObjectStoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024, // 256MB
        }
    }
}

/// In-memory object store implementation.
///
/// Suitable for testing and single-node deployments.
pub struct MemoryObjectStore {
    objects: RwLock<HashMap<ObjectId, StoredObject>>,
    config: MemoryObjectStoreConfig,
    used_bytes: RwLock<u64>,
}

impl MemoryObjectStore {
    /// Create a new in-memory object store.
    #[must_use]
    pub fn new(config: MemoryObjectStoreConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            used_bytes: RwLock::new(0),
        }
    }

    fn object_size(obj: &StoredObject) -> u64 {
        // Approximate size: body + header overhead
        #[allow(clippy::cast_possible_truncation)]
        let size = obj.body.len() as u64 + 512; // 512 byte header estimate
        size
    }
}

#[async_trait]
impl ObjectStore for MemoryObjectStore {
    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
        let size = Self::object_size(&object);

        {
            let used = *self.used_bytes.read();
            if used + size > self.config.max_bytes {
                return Err(ObjectStoreError::QuotaExceeded {
                    used,
                    max: self.config.max_bytes,
                });
            }
        }

        let mut objects = self.objects.write();
        if objects.contains_key(&object.object_id) {
            return Err(ObjectStoreError::AlreadyExists(object.object_id));
        }

        let id = object.object_id;
        objects.insert(id, object);
        *self.used_bytes.write() += size;

        Ok(())
    }

    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn exists(&self, id: &ObjectId) -> bool {
        self.objects.read().contains_key(id)
    }

    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
        let mut objects = self.objects.write();
        let obj = objects.remove(id).ok_or(ObjectStoreError::NotFound(*id))?;

        let size = Self::object_size(&obj);
        let mut used = self.used_bytes.write();
        *used = used.saturating_sub(size);

        Ok(())
    }

    async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .map(|obj| obj.header.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .map(|obj| obj.storage.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        let mut objects = self.objects.write();
        let obj = objects.get_mut(id).ok_or(ObjectStoreError::NotFound(*id))?;

        obj.storage.retention = retention;
        Ok(())
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.objects
            .read()
            .values()
            .filter(|obj| &obj.header.zone_id == zone_id)
            .map(|obj| obj.object_id)
            .collect()
    }

    async fn storage_used(&self) -> u64 {
        *self.used_bytes.read()
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }
}

#[cfg(test)]
mod tests {
    use fcp_cbor::SchemaId;
    use fcp_core::Provenance;
    use semver::Version;

    use super::*;

    fn test_zone() -> ZoneId {
        "z:test".parse().unwrap()
    }

    fn test_stored_object(id_byte: u8, body: &[u8]) -> StoredObject {
        StoredObject {
            object_id: ObjectId::from_bytes([id_byte; 32]),
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
                zone_id: test_zone(),
                created_at: 1_000_000,
                provenance: Provenance::new(test_zone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            body: body.to_vec(),
            storage: StorageMeta {
                retention: RetentionClass::Ephemeral,
            },
        }
    }

    #[tokio::test]
    async fn put_and_get() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let obj = test_stored_object(1, b"test body");
        let id = obj.object_id;

        store.put(obj.clone()).await.unwrap();

        let retrieved = store.get(&id).await.unwrap();
        assert_eq!(retrieved.body, b"test body");
    }

    #[tokio::test]
    async fn get_not_found() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let id = ObjectId::from_bytes([99_u8; 32]);

        let result = store.get(&id).await;
        assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn put_duplicate_rejected() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let obj = test_stored_object(1, b"body");

        store.put(obj.clone()).await.unwrap();
        let result = store.put(obj).await;
        assert!(matches!(result, Err(ObjectStoreError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn delete_object() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let obj = test_stored_object(1, b"body");
        let id = obj.object_id;

        store.put(obj).await.unwrap();
        assert!(store.exists(&id).await);

        store.delete(&id).await.unwrap();
        assert!(!store.exists(&id).await);
    }

    #[tokio::test]
    async fn quota_enforcement() {
        let config = MemoryObjectStoreConfig { max_bytes: 1000 };
        let store = MemoryObjectStore::new(config);

        // Create an object that will exceed quota
        let obj = test_stored_object(1, &vec![0_u8; 1000]);

        let result = store.put(obj).await;
        assert!(matches!(
            result,
            Err(ObjectStoreError::QuotaExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn set_retention() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let obj = test_stored_object(1, b"body");
        let id = obj.object_id;

        store.put(obj).await.unwrap();

        let meta = store.get_storage_meta(&id).await.unwrap();
        assert!(matches!(meta.retention, RetentionClass::Ephemeral));

        store
            .set_retention(&id, RetentionClass::Pinned)
            .await
            .unwrap();

        let meta = store.get_storage_meta(&id).await.unwrap();
        assert!(matches!(meta.retention, RetentionClass::Pinned));
    }

    #[tokio::test]
    async fn list_zone() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

        store.put(test_stored_object(1, b"a")).await.unwrap();
        store.put(test_stored_object(2, b"b")).await.unwrap();
        store.put(test_stored_object(3, b"c")).await.unwrap();

        let ids = store.list_zone(&test_zone()).await;
        assert_eq!(ids.len(), 3);
    }

    #[tokio::test]
    async fn storage_accounting() {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

        assert_eq!(store.storage_used().await, 0);

        let obj = test_stored_object(1, b"test body content");
        let id = obj.object_id;
        store.put(obj).await.unwrap();

        let used = store.storage_used().await;
        assert!(used > 0);

        store.delete(&id).await.unwrap();
        assert_eq!(store.storage_used().await, 0);
    }
}

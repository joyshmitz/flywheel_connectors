//! Symbol store interface for FCP2.
//!
//! Provides storage for `RaptorQ` symbols to enable partial object availability.

use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;
use fcp_core::{ObjectId, ZoneId};
use parking_lot::RwLock;
use raptorq::ObjectTransmissionInformation;
use serde::{Deserialize, Serialize};

use crate::coverage::SymbolDistribution;
use crate::error::SymbolStoreError;

/// Metadata for a stored symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolMeta {
    /// Object this symbol belongs to.
    pub object_id: ObjectId,
    /// Encoding symbol ID.
    pub esi: u32,
    /// Zone ID for the object.
    pub zone_id: ZoneId,
    /// Node that provided this symbol (for source diversity tracking).
    pub source_node: Option<u64>,
    /// Timestamp when symbol was stored.
    pub stored_at: u64,
}

/// Stored symbol with data and metadata.
#[derive(Debug, Clone)]
pub struct StoredSymbol {
    /// Symbol metadata.
    pub meta: SymbolMeta,
    /// Symbol data.
    pub data: Bytes,
}

/// Serializable object transmission information.
///
/// This is a serializable wrapper around raptorq's `ObjectTransmissionInformation`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ObjectTransmissionInfo {
    /// Transfer length (object size in bytes).
    pub transfer_length: u64,
    /// Symbol size in bytes.
    pub symbol_size: u16,
    /// Number of source blocks.
    pub source_blocks: u8,
    /// Number of sub-blocks.
    pub sub_blocks: u16,
    /// Symbol alignment.
    pub alignment: u8,
}

impl ObjectTransmissionInfo {
    /// Create from raptorq's `ObjectTransmissionInformation`.
    #[must_use]
    pub fn from_oti(oti: ObjectTransmissionInformation) -> Self {
        Self {
            transfer_length: oti.transfer_length(),
            symbol_size: oti.symbol_size(),
            source_blocks: oti.source_blocks(),
            sub_blocks: oti.sub_blocks(),
            alignment: oti.symbol_alignment(),
        }
    }

    /// Convert to raptorq's `ObjectTransmissionInformation`.
    #[must_use]
    pub fn to_oti(self) -> ObjectTransmissionInformation {
        ObjectTransmissionInformation::new(
            self.transfer_length,
            self.symbol_size,
            self.source_blocks,
            self.sub_blocks,
            self.alignment,
        )
    }
}

impl From<ObjectTransmissionInformation> for ObjectTransmissionInfo {
    fn from(oti: ObjectTransmissionInformation) -> Self {
        Self::from_oti(oti)
    }
}

impl From<ObjectTransmissionInfo> for ObjectTransmissionInformation {
    fn from(info: ObjectTransmissionInfo) -> Self {
        info.to_oti()
    }
}

/// Object metadata for symbol reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSymbolMeta {
    /// Object ID.
    pub object_id: ObjectId,
    /// Zone ID.
    pub zone_id: ZoneId,
    /// Object transmission information for `RaptorQ` decoding.
    pub oti: ObjectTransmissionInfo,
    /// Number of source symbols (K).
    pub source_symbols: u32,
    /// Timestamp when first symbol was stored.
    pub first_symbol_at: u64,
}

/// Symbol store interface (NORMATIVE).
///
/// Stores `RaptorQ` symbols for partial object availability.
#[async_trait]
pub trait SymbolStore: Send + Sync {
    /// Store a symbol for an object.
    ///
    /// # Errors
    /// Returns error if quota exceeded.
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError>;

    /// Store object metadata (must be called before storing symbols).
    ///
    /// # Errors
    /// Returns error if quota exceeded.
    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError>;

    /// Get a specific symbol.
    ///
    /// # Errors
    /// Returns `NotFound` if symbol doesn't exist.
    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError>;

    /// Get object metadata.
    ///
    /// # Errors
    /// Returns `ObjectNotFound` if object metadata doesn't exist.
    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError>;

    /// Get all symbols for an object.
    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol>;

    /// Get symbol count for an object.
    async fn symbol_count(&self, object_id: &ObjectId) -> u32;

    /// Delete all symbols for an object.
    ///
    /// # Errors
    /// Returns `ObjectNotFound` if object doesn't exist.
    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError>;

    /// Delete a specific symbol.
    ///
    /// # Errors
    /// Returns `NotFound` if symbol doesn't exist.
    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError>;

    /// Get symbol distribution for an object (for coverage evaluation).
    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution>;

    /// List all object IDs with symbols in a zone.
    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId>;

    /// Get total storage used in bytes.
    async fn storage_used(&self) -> u64;

    /// Get storage quota in bytes.
    async fn storage_quota(&self) -> u64;

    /// Check if object can be reconstructed (has enough symbols).
    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool;
}

/// Configuration for in-memory symbol store.
#[derive(Debug, Clone)]
pub struct MemorySymbolStoreConfig {
    /// Maximum storage in bytes.
    pub max_bytes: u64,
    /// Local node ID for distribution tracking.
    pub local_node_id: u64,
}

impl Default for MemorySymbolStoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024, // 512MB
            local_node_id: 0,
        }
    }
}

/// Per-object symbol storage.
#[derive(Debug)]
struct ObjectSymbols {
    meta: ObjectSymbolMeta,
    symbols: HashMap<u32, StoredSymbol>, // ESI -> Symbol
}

/// In-memory symbol store implementation.
pub struct MemorySymbolStore {
    objects: RwLock<HashMap<ObjectId, ObjectSymbols>>,
    config: MemorySymbolStoreConfig,
    used_bytes: RwLock<u64>,
}

impl MemorySymbolStore {
    /// Create a new in-memory symbol store.
    #[must_use]
    pub fn new(config: MemorySymbolStoreConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            used_bytes: RwLock::new(0),
        }
    }

    const fn symbol_size(symbol: &StoredSymbol) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        let size = symbol.data.len() as u64 + 64; // 64 byte metadata estimate
        size
    }
}

#[async_trait]
impl SymbolStore for MemorySymbolStore {
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError> {
        let size = Self::symbol_size(&symbol);

        {
            let used = *self.used_bytes.read();
            if used + size > self.config.max_bytes {
                return Err(SymbolStoreError::QuotaExceeded {
                    used,
                    max: self.config.max_bytes,
                });
            }
        }

        let mut objects = self.objects.write();
        let obj = objects
            .get_mut(&symbol.meta.object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(symbol.meta.object_id))?;

        // Check for duplicate ESI
        if obj.symbols.contains_key(&symbol.meta.esi) {
            // Already have this symbol, skip
            return Ok(());
        }

        obj.symbols.insert(symbol.meta.esi, symbol);
        *self.used_bytes.write() += size;

        Ok(())
    }

    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();

        // If already exists, just update metadata
        if let Some(obj) = objects.get_mut(&meta.object_id) {
            obj.meta = meta;
            return Ok(());
        }

        objects.insert(
            meta.object_id,
            ObjectSymbols {
                meta,
                symbols: HashMap::new(),
            },
        );

        Ok(())
    }

    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError> {
        let objects = self.objects.read();
        let obj = objects
            .get(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;

        obj.symbols
            .get(&esi)
            .cloned()
            .ok_or(SymbolStoreError::NotFound {
                object_id: *object_id,
                esi,
            })
    }

    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError> {
        self.objects
            .read()
            .get(object_id)
            .map(|obj| obj.meta.clone())
            .ok_or_else(|| SymbolStoreError::ObjectNotFound(*object_id))
    }

    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol> {
        self.objects
            .read()
            .get(object_id)
            .map(|obj| obj.symbols.values().cloned().collect())
            .unwrap_or_default()
    }

    async fn symbol_count(&self, object_id: &ObjectId) -> u32 {
        self.objects
            .read()
            .get(object_id)
            .map_or(0, |obj| obj.symbols.len() as u32)
    }

    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();
        let obj = objects
            .remove(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;

        let total_size: u64 = obj.symbols.values().map(Self::symbol_size).sum();
        let mut used = self.used_bytes.write();
        *used = used.saturating_sub(total_size);

        Ok(())
    }

    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();
        let obj = objects
            .get_mut(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;

        let symbol = obj.symbols.remove(&esi).ok_or(SymbolStoreError::NotFound {
            object_id: *object_id,
            esi,
        })?;

        let size = Self::symbol_size(&symbol);
        let mut used = self.used_bytes.write();
        *used = used.saturating_sub(size);

        Ok(())
    }

    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution> {
        let objects = self.objects.read();
        let obj = objects.get(object_id)?;

        let mut dist = SymbolDistribution::new(obj.meta.source_symbols);

        for symbol in obj.symbols.values() {
            let node_id = symbol.meta.source_node.unwrap_or(self.config.local_node_id);
            #[allow(clippy::cast_possible_truncation)]
            let size = symbol.data.len() as u64;
            dist.add_symbol(node_id, size);
        }

        Some(dist)
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.objects
            .read()
            .values()
            .filter(|obj| &obj.meta.zone_id == zone_id)
            .map(|obj| obj.meta.object_id)
            .collect()
    }

    async fn storage_used(&self) -> u64 {
        *self.used_bytes.read()
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }

    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool {
        let objects = self.objects.read();
        if let Some(obj) = objects.get(object_id) {
            // RaptorQ needs K' ≈ K × 1.002 symbols, we approximate with K
            obj.symbols.len() as u32 >= obj.meta.source_symbols
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_zone() -> ZoneId {
        "z:test".parse().unwrap()
    }

    fn test_object_id() -> ObjectId {
        ObjectId::from_bytes([1_u8; 32])
    }

    fn test_object_meta() -> ObjectSymbolMeta {
        ObjectSymbolMeta {
            object_id: test_object_id(),
            zone_id: test_zone(),
            oti: ObjectTransmissionInfo {
                transfer_length: 1024,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
            },
            source_symbols: 16,
            first_symbol_at: 1_000_000,
        }
    }

    fn test_symbol(esi: u32) -> StoredSymbol {
        StoredSymbol {
            meta: SymbolMeta {
                object_id: test_object_id(),
                esi,
                zone_id: test_zone(),
                source_node: Some(1),
                stored_at: 1_000_000,
            },
            data: Bytes::from(vec![0_u8; 64]),
        }
    }

    #[tokio::test]
    async fn put_and_get_symbol() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        store.put_object_meta(test_object_meta()).await.unwrap();
        store.put_symbol(test_symbol(0)).await.unwrap();

        let symbol = store.get_symbol(&test_object_id(), 0).await.unwrap();
        assert_eq!(symbol.meta.esi, 0);
    }

    #[tokio::test]
    async fn symbol_without_object_meta_rejected() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        let result = store.put_symbol(test_symbol(0)).await;
        assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));
    }

    #[tokio::test]
    async fn duplicate_symbol_ignored() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        store.put_object_meta(test_object_meta()).await.unwrap();
        store.put_symbol(test_symbol(0)).await.unwrap();
        store.put_symbol(test_symbol(0)).await.unwrap(); // Duplicate

        assert_eq!(store.symbol_count(&test_object_id()).await, 1);
    }

    #[tokio::test]
    async fn get_all_symbols() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        store.put_object_meta(test_object_meta()).await.unwrap();
        for esi in 0..5 {
            store.put_symbol(test_symbol(esi)).await.unwrap();
        }

        let symbols = store.get_all_symbols(&test_object_id()).await;
        assert_eq!(symbols.len(), 5);
    }

    #[tokio::test]
    async fn can_reconstruct() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        let mut meta = test_object_meta();
        meta.source_symbols = 10;
        store.put_object_meta(meta).await.unwrap();

        // Not enough symbols
        for esi in 0..5 {
            store.put_symbol(test_symbol(esi)).await.unwrap();
        }
        assert!(!store.can_reconstruct(&test_object_id()).await);

        // Now add more
        for esi in 5..10 {
            store.put_symbol(test_symbol(esi)).await.unwrap();
        }
        assert!(store.can_reconstruct(&test_object_id()).await);
    }

    #[tokio::test]
    async fn get_distribution() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        store.put_object_meta(test_object_meta()).await.unwrap();

        // Add symbols from different nodes
        let mut symbol = test_symbol(0);
        symbol.meta.source_node = Some(1);
        store.put_symbol(symbol).await.unwrap();

        let mut symbol = test_symbol(1);
        symbol.meta.source_node = Some(2);
        store.put_symbol(symbol).await.unwrap();

        let mut symbol = test_symbol(2);
        symbol.meta.source_node = Some(1);
        store.put_symbol(symbol).await.unwrap();

        let dist = store.get_distribution(&test_object_id()).await.unwrap();
        assert_eq!(dist.distinct_nodes(), 2);
        assert_eq!(dist.total_symbols, 3);
    }

    #[tokio::test]
    async fn delete_symbol() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        store.put_object_meta(test_object_meta()).await.unwrap();
        store.put_symbol(test_symbol(0)).await.unwrap();

        store.delete_symbol(&test_object_id(), 0).await.unwrap();

        let result = store.get_symbol(&test_object_id(), 0).await;
        assert!(matches!(result, Err(SymbolStoreError::NotFound { .. })));
    }

    #[tokio::test]
    async fn delete_object() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        store.put_object_meta(test_object_meta()).await.unwrap();
        for esi in 0..5 {
            store.put_symbol(test_symbol(esi)).await.unwrap();
        }

        let used_before = store.storage_used().await;
        assert!(used_before > 0);

        store.delete_object(&test_object_id()).await.unwrap();

        assert_eq!(store.storage_used().await, 0);
    }

    #[tokio::test]
    async fn quota_enforcement() {
        let config = MemorySymbolStoreConfig {
            max_bytes: 100,
            local_node_id: 0,
        };
        let store = MemorySymbolStore::new(config);

        store.put_object_meta(test_object_meta()).await.unwrap();

        // First symbol should fit
        store.put_symbol(test_symbol(0)).await.unwrap();

        // Second should exceed quota
        let result = store.put_symbol(test_symbol(1)).await;
        assert!(matches!(
            result,
            Err(SymbolStoreError::QuotaExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn list_zone() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        store.put_object_meta(test_object_meta()).await.unwrap();

        let mut meta2 = test_object_meta();
        meta2.object_id = ObjectId::from_bytes([2_u8; 32]);
        store.put_object_meta(meta2).await.unwrap();

        let ids = store.list_zone(&test_zone()).await;
        assert_eq!(ids.len(), 2);
    }
}

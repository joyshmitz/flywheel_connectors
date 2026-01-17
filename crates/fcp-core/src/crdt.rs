//! Conflict-free replicated data types (CRDTs) for connector state.
//!
//! These are mesh-friendly, deterministic CRDTs for state replication.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::TailscaleNodeId;
use std::fmt;

/// Actor identifier for CRDT operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CrdtActorId(String);

impl CrdtActorId {
    /// Create a new actor id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CrdtActorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for CrdtActorId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for CrdtActorId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for CrdtActorId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<TailscaleNodeId> for CrdtActorId {
    fn from(value: TailscaleNodeId) -> Self {
        Self(value.as_str().to_string())
    }
}

impl From<&TailscaleNodeId> for CrdtActorId {
    fn from(value: &TailscaleNodeId) -> Self {
        Self(value.as_str().to_string())
    }
}

/// LWW entry with timestamp and actor tie-breaker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwEntry<V> {
    pub value: V,
    pub timestamp: u64,
    pub actor: CrdtActorId,
}

impl<V> LwwEntry<V> {
    fn wins_over(&self, other: &Self) -> bool {
        if self.timestamp == other.timestamp {
            self.actor > other.actor
        } else {
            self.timestamp > other.timestamp
        }
    }
}

/// Last-write-wins map.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "K: Ord + Serialize, V: Serialize",
    deserialize = "K: Ord + Deserialize<'de>, V: Deserialize<'de>"
))]
pub struct LwwMap<K, V> {
    entries: BTreeMap<K, LwwEntry<V>>,
}

impl<K, V> LwwMap<K, V>
where
    K: Ord + Clone,
    V: Clone + PartialEq,
{
    pub fn insert(&mut self, key: K, value: V, timestamp: u64, actor: CrdtActorId) {
        let entry = LwwEntry {
            value,
            timestamp,
            actor,
        };
        match self.entries.get(&key) {
            Some(existing) if !entry.wins_over(existing) => {}
            _ => {
                self.entries.insert(key, entry);
            }
        }
    }

    pub fn merge(&mut self, other: &Self) {
        for (key, entry) in &other.entries {
            match self.entries.get(key) {
                Some(existing) if existing.wins_over(entry) || existing == entry => {}
                _ => {
                    self.entries.insert(key.clone(), entry.clone());
                }
            }
        }
    }

    #[must_use]
    pub fn get(&self, key: &K) -> Option<&LwwEntry<V>> {
        self.entries.get(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Unique tag for OR-Set operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OrSetTag {
    pub actor: CrdtActorId,
    pub nonce: u64,
}

impl OrSetTag {
    #[must_use]
    pub const fn new(actor: CrdtActorId, nonce: u64) -> Self {
        Self { actor, nonce }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct OrSetTags {
    adds: BTreeSet<OrSetTag>,
    removes: BTreeSet<OrSetTag>,
}

/// Observed-remove set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Ord + Serialize",
    deserialize = "T: Ord + Deserialize<'de>"
))]
pub struct OrSet<T> {
    entries: BTreeMap<T, OrSetTags>,
}

impl<T> OrSet<T>
where
    T: Ord + Clone,
{
    pub fn add(&mut self, value: T, tag: OrSetTag) {
        let tags = self.entries.entry(value).or_default();
        if !tags.removes.contains(&tag) {
            tags.adds.insert(tag);
        }
    }

    /// Remove all observed tags for a value.
    pub fn remove_observed(&mut self, value: &T) {
        if let Some(tags) = self.entries.get_mut(value) {
            tags.removes.extend(tags.adds.iter().cloned());
            tags.adds.clear();
        }
    }

    #[must_use]
    pub fn contains(&self, value: &T) -> bool {
        self.entries
            .get(value)
            .is_some_and(|tags| !tags.adds.is_empty())
    }

    pub fn merge(&mut self, other: &Self) {
        for (value, tags) in &other.entries {
            let entry = self.entries.entry(value.clone()).or_default();
            entry.removes.extend(tags.removes.iter().cloned());

            for tag in &tags.adds {
                if !entry.removes.contains(tag) {
                    entry.adds.insert(tag.clone());
                }
            }

            // Cleanup existing adds that are now removed
            entry.adds.retain(|tag| !entry.removes.contains(tag));
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, tags)| !tags.adds.is_empty())
            .count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn values(&self) -> Vec<T> {
        self.entries
            .iter()
            .filter(|(_, tags)| !tags.adds.is_empty())
            .map(|(value, _)| value.clone())
            .collect()
    }
}

/// Grow-only counter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GCounter {
    pub counts: BTreeMap<CrdtActorId, u64>,
}

impl GCounter {
    pub fn increment(&mut self, actor: CrdtActorId, delta: u64) {
        let entry = self.counts.entry(actor).or_insert(0);
        *entry = entry.saturating_add(delta);
    }

    #[must_use]
    pub fn value(&self) -> u64 {
        self.counts
            .values()
            .fold(0, |acc, value| acc.saturating_add(*value))
    }

    pub fn merge(&mut self, other: &Self) {
        for (actor, value) in &other.counts {
            let entry = self.counts.entry(actor.clone()).or_insert(0);
            if *entry < *value {
                *entry = *value;
            }
        }
    }
}

/// PN-Counter (positive-negative).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PnCounter {
    pub positive: GCounter,
    pub negative: GCounter,
}

impl PnCounter {
    pub fn increment(&mut self, actor: CrdtActorId, delta: u64) {
        self.positive.increment(actor, delta);
    }

    pub fn decrement(&mut self, actor: CrdtActorId, delta: u64) {
        self.negative.increment(actor, delta);
    }

    #[must_use]
    pub fn value(&self) -> i64 {
        let pos = i64::try_from(self.positive.value()).unwrap_or(i64::MAX);
        let neg = i64::try_from(self.negative.value()).unwrap_or(i64::MAX);
        pos.saturating_sub(neg)
    }

    pub fn merge(&mut self, other: &Self) {
        self.positive.merge(&other.positive);
        self.negative.merge(&other.negative);
    }
}

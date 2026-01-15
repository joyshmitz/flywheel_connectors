//! Coverage evaluation for symbol distribution.
//!
//! Implements quantifiable offline resilience metrics from `FCP_Specification_V2.md`.

use std::collections::HashMap;

use fcp_core::ObjectId;
use serde::{Deserialize, Serialize};

/// Symbol distribution across nodes.
#[derive(Debug, Clone, Default)]
pub struct SymbolDistribution {
    /// Map of `node_id` -> (symbol count, total bytes).
    pub nodes: HashMap<u64, (u32, u64)>,
    /// Total source symbols (K).
    pub source_symbols: u32,
    /// Total symbols stored across all nodes.
    pub total_symbols: u32,
}

impl SymbolDistribution {
    /// Create a new empty distribution.
    #[must_use]
    pub fn new(source_symbols: u32) -> Self {
        Self {
            nodes: HashMap::new(),
            source_symbols,
            total_symbols: 0,
        }
    }

    /// Record a symbol stored on a node.
    pub fn add_symbol(&mut self, node_id: u64, symbol_bytes: u64) {
        let entry = self.nodes.entry(node_id).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += symbol_bytes;
        self.total_symbols += 1;
    }

    /// Remove a symbol from a node.
    pub fn remove_symbol(&mut self, node_id: u64, symbol_bytes: u64) {
        if let Some(entry) = self.nodes.get_mut(&node_id) {
            entry.0 = entry.0.saturating_sub(1);
            entry.1 = entry.1.saturating_sub(symbol_bytes);
            self.total_symbols = self.total_symbols.saturating_sub(1);
            if entry.0 == 0 {
                self.nodes.remove(&node_id);
            }
        }
    }

    /// Get the number of distinct nodes.
    #[must_use]
    pub fn distinct_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Get the maximum symbol count on any single node.
    #[must_use]
    pub fn max_node_symbols(&self) -> u32 {
        self.nodes
            .values()
            .map(|(count, _)| *count)
            .max()
            .unwrap_or(0)
    }
}

/// Symbol coverage evaluation result (NORMATIVE).
///
/// Uses fixed-point basis points for interop stability across implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEvaluation {
    /// The object being evaluated.
    pub object_id: ObjectId,
    /// Number of distinct nodes holding symbols.
    pub distinct_nodes: usize,
    /// Highest fraction of symbols on any single node (basis points, 0..=10000).
    pub max_node_fraction_bps: u16,
    /// Coverage ratio in basis points (10000 = 1.0x = exactly K symbols).
    pub coverage_bps: u32,
    /// Can object be reconstructed with current coverage?
    pub is_available: bool,
    /// Total symbols stored across all nodes.
    pub total_symbols: u32,
    /// Source symbols required (K).
    pub source_symbols: u32,
}

impl CoverageEvaluation {
    /// Evaluate coverage from a symbol distribution.
    #[must_use]
    pub fn from_distribution(object_id: ObjectId, dist: &SymbolDistribution) -> Self {
        let distinct_nodes = dist.distinct_nodes();
        let max_node_symbols = dist.max_node_symbols();

        // Calculate max node fraction in basis points
        let max_node_fraction_bps = if dist.total_symbols > 0 {
            #[allow(clippy::cast_possible_truncation)]
            let bps = (u64::from(max_node_symbols) * 10000 / u64::from(dist.total_symbols)) as u16;
            bps.min(10000)
        } else {
            0
        };

        // Calculate coverage in basis points
        // coverage_bps = (total_symbols / source_symbols) * 10000
        let coverage_bps = if dist.source_symbols > 0 {
            #[allow(clippy::cast_possible_truncation)]
            let bps =
                (u64::from(dist.total_symbols) * 10000 / u64::from(dist.source_symbols)) as u32;
            bps
        } else {
            0
        };

        // Object is available if we have at least K symbols (coverage >= 10000 bps)
        // RaptorQ actually needs K' ≈ K × 1.002, but we approximate with K
        let is_available = dist.total_symbols >= dist.source_symbols;

        Self {
            object_id,
            distinct_nodes,
            max_node_fraction_bps,
            coverage_bps,
            is_available,
            total_symbols: dist.total_symbols,
            source_symbols: dist.source_symbols,
        }
    }

    /// Check if coverage meets a placement policy's requirements.
    #[must_use]
    pub const fn meets_policy(&self, policy: &fcp_core::ObjectPlacementPolicy) -> bool {
        // Check minimum nodes
        if self.distinct_nodes < policy.min_nodes as usize {
            return false;
        }

        // Check max concentration
        if self.max_node_fraction_bps > policy.max_node_fraction_bps {
            return false;
        }

        // Check target coverage
        if self.coverage_bps < policy.target_coverage_bps {
            return false;
        }

        true
    }

    /// Calculate deficit in basis points from target coverage.
    #[must_use]
    pub const fn coverage_deficit_bps(&self, target_bps: u32) -> u32 {
        target_bps.saturating_sub(self.coverage_bps)
    }

    /// Calculate how many additional symbols needed to reach target coverage.
    #[must_use]
    pub fn symbols_needed(&self, target_bps: u32) -> u32 {
        if self.coverage_bps >= target_bps {
            return 0;
        }

        // target_symbols = source_symbols * target_bps / 10000
        let target_symbols = u64::from(self.source_symbols) * u64::from(target_bps) / 10000;

        #[allow(clippy::cast_possible_truncation)]
        let needed = target_symbols.saturating_sub(u64::from(self.total_symbols)) as u32;
        needed
    }
}

/// Coverage health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageHealth {
    /// Coverage meets or exceeds policy targets.
    Healthy,
    /// Coverage is below target but object is still available.
    Degraded,
    /// Object cannot be reconstructed.
    Unavailable,
}

impl CoverageEvaluation {
    /// Determine health status based on policy.
    #[must_use]
    pub const fn health(&self, policy: &fcp_core::ObjectPlacementPolicy) -> CoverageHealth {
        if !self.is_available {
            CoverageHealth::Unavailable
        } else if self.meets_policy(policy) {
            CoverageHealth::Healthy
        } else {
            CoverageHealth::Degraded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_object_id() -> ObjectId {
        ObjectId::from_bytes([1_u8; 32])
    }

    #[test]
    fn empty_distribution() {
        let dist = SymbolDistribution::new(10);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        assert_eq!(eval.distinct_nodes, 0);
        assert_eq!(eval.coverage_bps, 0);
        assert!(!eval.is_available);
    }

    #[test]
    fn single_node_full_coverage() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        assert_eq!(eval.distinct_nodes, 1);
        assert_eq!(eval.coverage_bps, 10000); // 100%
        assert_eq!(eval.max_node_fraction_bps, 10000); // Single node has all
        assert!(eval.is_available);
    }

    #[test]
    fn distributed_coverage() {
        let mut dist = SymbolDistribution::new(10);
        // 4 symbols on node 1, 3 on node 2, 3 on node 3 = 10 total
        for _ in 0..4 {
            dist.add_symbol(1, 100);
        }
        for _ in 0..3 {
            dist.add_symbol(2, 100);
        }
        for _ in 0..3 {
            dist.add_symbol(3, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        assert_eq!(eval.distinct_nodes, 3);
        assert_eq!(eval.coverage_bps, 10000); // 100%
        assert_eq!(eval.max_node_fraction_bps, 4000); // 40% on node 1
        assert!(eval.is_available);
    }

    #[test]
    fn partial_coverage() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(1, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        assert_eq!(eval.distinct_nodes, 1);
        assert_eq!(eval.coverage_bps, 5000); // 50%
        assert!(!eval.is_available);
    }

    #[test]
    fn overcoverage() {
        let mut dist = SymbolDistribution::new(10);
        // 150% coverage (15 symbols for K=10)
        for _ in 0..15 {
            dist.add_symbol(1, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        assert_eq!(eval.coverage_bps, 15000); // 150%
        assert!(eval.is_available);
    }

    #[test]
    fn meets_policy_all_requirements() {
        let mut dist = SymbolDistribution::new(10);
        // Distribute symbols across 3 nodes: 4, 3, 3
        for _ in 0..4 {
            dist.add_symbol(1, 100);
        }
        for _ in 0..3 {
            dist.add_symbol(2, 100);
        }
        for _ in 0..3 {
            dist.add_symbol(3, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        let policy = fcp_core::ObjectPlacementPolicy {
            min_nodes: 3,
            max_node_fraction_bps: 5000, // Max 50%
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000, // 100%
        };

        assert!(eval.meets_policy(&policy));
    }

    #[test]
    fn fails_min_nodes() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        let policy = fcp_core::ObjectPlacementPolicy {
            min_nodes: 3, // Requires 3 nodes
            max_node_fraction_bps: 10000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000,
        };

        assert!(!eval.meets_policy(&policy)); // Only 1 node
    }

    #[test]
    fn fails_max_concentration() {
        let mut dist = SymbolDistribution::new(10);
        // 7 on node 1, 3 on node 2 = 70% concentration on node 1
        for _ in 0..7 {
            dist.add_symbol(1, 100);
        }
        for _ in 0..3 {
            dist.add_symbol(2, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        let policy = fcp_core::ObjectPlacementPolicy {
            min_nodes: 2,
            max_node_fraction_bps: 5000, // Max 50%
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000,
        };

        assert!(!eval.meets_policy(&policy)); // 70% > 50%
    }

    #[test]
    fn symbols_needed_calculation() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(1, 100);
        }

        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

        // Need 5 more to reach 100% (10000 bps)
        assert_eq!(eval.symbols_needed(10000), 5);

        // Need 10 more to reach 150% (15000 bps)
        assert_eq!(eval.symbols_needed(15000), 10);

        // Already at or above 50% (5000 bps)
        assert_eq!(eval.symbols_needed(5000), 0);
    }

    #[test]
    fn health_status() {
        let policy = fcp_core::ObjectPlacementPolicy {
            min_nodes: 2,
            max_node_fraction_bps: 6000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000,
        };

        // Unavailable: insufficient symbols
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.health(&policy), CoverageHealth::Unavailable);

        // Degraded: available but doesn't meet policy
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.health(&policy), CoverageHealth::Degraded);

        // Healthy: meets all requirements
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..6 {
            dist.add_symbol(1, 100);
        }
        for _ in 0..4 {
            dist.add_symbol(2, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.health(&policy), CoverageHealth::Healthy);
    }

    #[test]
    fn remove_symbol() {
        let mut dist = SymbolDistribution::new(10);
        dist.add_symbol(1, 100);
        dist.add_symbol(1, 100);
        dist.add_symbol(2, 100);

        assert_eq!(dist.distinct_nodes(), 2);
        assert_eq!(dist.total_symbols, 3);

        dist.remove_symbol(1, 100);
        assert_eq!(dist.distinct_nodes(), 2);
        assert_eq!(dist.total_symbols, 2);

        dist.remove_symbol(1, 100);
        assert_eq!(dist.distinct_nodes(), 1); // Node 1 removed
        assert_eq!(dist.total_symbols, 1);
    }
}

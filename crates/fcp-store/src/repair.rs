//! Repair controller for maintaining object coverage (NORMATIVE).
//!
//! Implements bounded, convergent repair from `FCP_Specification_V2.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fcp_core::{ObjectId, ObjectPlacementPolicy, ZoneId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::coverage::{CoverageEvaluation, CoverageHealth};
use crate::symbol_store::SymbolStore;

/// Repair request for an object.
#[derive(Debug, Clone)]
pub struct RepairRequest {
    /// Object to repair.
    pub object_id: ObjectId,
    /// Zone the object belongs to.
    pub zone_id: ZoneId,
    /// Current coverage evaluation.
    pub coverage: CoverageEvaluation,
    /// Target placement policy.
    pub policy: ObjectPlacementPolicy,
    /// Priority (higher = more urgent).
    pub priority: u32,
}

/// Repair result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    /// Object that was repaired.
    pub object_id: ObjectId,
    /// Whether repair was successful.
    pub success: bool,
    /// New coverage after repair.
    pub new_coverage_bps: u32,
    /// Symbols added during repair.
    pub symbols_added: u32,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Repair controller configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairControllerConfig {
    /// Maximum concurrent repair operations.
    pub max_concurrent_repairs: usize,
    /// Maximum repairs per minute (rate limit).
    pub max_repairs_per_minute: u32,
    /// Interval between repair loop iterations.
    pub repair_interval: Duration,
    /// Minimum coverage deficit (bps) to trigger repair.
    pub min_deficit_bps: u32,
    /// Maximum symbols to request per repair.
    pub max_symbols_per_repair: u32,
}

impl Default for RepairControllerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_repairs: 10,
            max_repairs_per_minute: 100,
            repair_interval: Duration::from_secs(60),
            min_deficit_bps: 500, // 5% deficit triggers repair
            max_symbols_per_repair: 100,
        }
    }
}

/// Repair statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepairStats {
    /// Total repairs attempted.
    pub repairs_attempted: u64,
    /// Successful repairs.
    pub repairs_succeeded: u64,
    /// Failed repairs.
    pub repairs_failed: u64,
    /// Total symbols added.
    pub symbols_added: u64,
    /// Current repair queue depth.
    pub queue_depth: usize,
    /// Repairs blocked by rate limit.
    pub rate_limited: u64,
}

/// Rate limiter for repairs.
struct RateLimiter {
    tokens: RwLock<u32>,
    max_tokens: u32,
    last_refill: RwLock<std::time::Instant>,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            tokens: RwLock::new(max_per_minute),
            max_tokens: max_per_minute,
            last_refill: RwLock::new(std::time::Instant::now()),
        }
    }

    fn try_acquire(&self) -> bool {
        // Refill tokens if a minute has passed
        let now = std::time::Instant::now();
        {
            let mut last = self.last_refill.write();
            if now.duration_since(*last) >= Duration::from_secs(60) {
                *self.tokens.write() = self.max_tokens;
                *last = now;
            }
        }

        let mut tokens = self.tokens.write();
        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }

    fn available(&self) -> u32 {
        *self.tokens.read()
    }
}

/// Repair controller for maintaining coverage across the mesh.
///
/// Implements bounded, rate-limited repair with convergent behavior.
pub struct RepairController {
    config: RepairControllerConfig,
    semaphore: Arc<Semaphore>,
    rate_limiter: RateLimiter,
    stats: RwLock<RepairStats>,
    queue: RwLock<Vec<RepairRequest>>,
}

impl RepairController {
    /// Create a new repair controller.
    #[must_use]
    pub fn new(config: RepairControllerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_repairs));
        let rate_limiter = RateLimiter::new(config.max_repairs_per_minute);

        Self {
            config,
            semaphore,
            rate_limiter,
            stats: RwLock::new(RepairStats::default()),
            queue: RwLock::new(Vec::new()),
        }
    }

    /// Queue a repair request.
    pub fn queue_repair(&self, request: RepairRequest) {
        let mut queue = self.queue.write();

        // Check if already queued
        if queue.iter().any(|r| r.object_id == request.object_id) {
            return;
        }

        queue.push(request);

        // Sort by priority (highest first)
        queue.sort_by(|a, b| b.priority.cmp(&a.priority));

        self.stats.write().queue_depth = queue.len();
    }

    /// Get the next repair request if rate limit allows.
    pub fn next_repair(&self) -> Option<RepairRequest> {
        if !self.rate_limiter.try_acquire() {
            self.stats.write().rate_limited += 1;
            return None;
        }

        let mut queue = self.queue.write();
        let request = queue.pop();
        self.stats.write().queue_depth = queue.len();
        request
    }

    /// Try to acquire a repair permit.
    ///
    /// Returns `None` if max concurrent repairs reached.
    pub fn try_acquire_permit(&self) -> Option<RepairPermit> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|permit| RepairPermit { _permit: permit })
    }

    /// Record a repair result.
    pub fn record_result(&self, result: &RepairResult) {
        let mut stats = self.stats.write();
        stats.repairs_attempted += 1;

        if result.success {
            stats.repairs_succeeded += 1;
            stats.symbols_added += u64::from(result.symbols_added);
        } else {
            stats.repairs_failed += 1;
        }
    }

    /// Get current repair statistics.
    #[must_use]
    pub fn stats(&self) -> RepairStats {
        self.stats.read().clone()
    }

    /// Get repair controller configuration.
    #[must_use]
    pub const fn config(&self) -> &RepairControllerConfig {
        &self.config
    }

    /// Check if an object needs repair based on coverage.
    #[must_use]
    pub const fn needs_repair(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> bool {
        let health = coverage.health(policy);

        match health {
            CoverageHealth::Unavailable => true,
            CoverageHealth::Degraded => {
                coverage.coverage_deficit_bps(policy.target_coverage_bps)
                    >= self.config.min_deficit_bps
            }
            CoverageHealth::Healthy => false,
        }
    }

    /// Calculate repair priority for an object.
    #[must_use]
    pub const fn calculate_priority(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> u32 {
        let health = coverage.health(policy);

        match health {
            CoverageHealth::Unavailable => 1000, // Highest priority
            CoverageHealth::Degraded => {
                // Priority based on deficit
                let deficit = coverage.coverage_deficit_bps(policy.target_coverage_bps);
                100 + deficit / 100 // 100-199 range
            }
            CoverageHealth::Healthy => 0,
        }
    }

    /// Evaluate all objects in a zone and queue repairs as needed.
    pub async fn evaluate_zone(
        &self,
        zone_id: &ZoneId,
        symbol_store: &dyn SymbolStore,
        policies: &HashMap<ObjectId, ObjectPlacementPolicy>,
    ) {
        let object_ids = symbol_store.list_zone(zone_id).await;

        for object_id in object_ids {
            let policy = match policies.get(&object_id) {
                Some(p) => p.clone(),
                None => continue, // No policy, skip
            };

            let Some(dist) = symbol_store.get_distribution(&object_id).await else {
                continue;
            };

            let coverage = CoverageEvaluation::from_distribution(object_id, &dist);

            if self.needs_repair(&coverage, &policy) {
                let priority = self.calculate_priority(&coverage, &policy);
                self.queue_repair(RepairRequest {
                    object_id,
                    zone_id: zone_id.clone(),
                    coverage,
                    policy,
                    priority,
                });
            }
        }
    }

    /// Get available rate limit tokens.
    #[must_use]
    pub fn available_rate_tokens(&self) -> u32 {
        self.rate_limiter.available()
    }

    /// Get queue depth.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.read().len()
    }

    /// Clear the repair queue.
    pub fn clear_queue(&self) {
        self.queue.write().clear();
        self.stats.write().queue_depth = 0;
    }
}

/// RAII permit for concurrent repair operations.
pub struct RepairPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Targeted repair request for specific symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetedRepairRequest {
    /// Object to repair.
    pub object_id: ObjectId,
    /// Specific ESIs to request.
    pub esis: Vec<u32>,
    /// Preferred source nodes (for source diversity).
    pub preferred_sources: Vec<u64>,
    /// Nodes to exclude (already have symbols from).
    pub excluded_sources: Vec<u64>,
}

impl TargetedRepairRequest {
    /// Create a new targeted repair request.
    #[must_use]
    pub const fn new(object_id: ObjectId) -> Self {
        Self {
            object_id,
            esis: Vec::new(),
            preferred_sources: Vec::new(),
            excluded_sources: Vec::new(),
        }
    }

    /// Add ESIs to request.
    #[must_use]
    pub fn with_esis(mut self, esis: Vec<u32>) -> Self {
        self.esis = esis;
        self
    }

    /// Set preferred sources.
    #[must_use]
    pub fn with_preferred_sources(mut self, sources: Vec<u64>) -> Self {
        self.preferred_sources = sources;
        self
    }

    /// Set excluded sources.
    #[must_use]
    pub fn with_excluded_sources(mut self, sources: Vec<u64>) -> Self {
        self.excluded_sources = sources;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_coverage(total: u32, source: u32) -> CoverageEvaluation {
        CoverageEvaluation {
            object_id: ObjectId::from_bytes([1; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: if source > 0 {
                total * 10000 / source
            } else {
                0
            },
            is_available: total >= source,
            total_symbols: total,
            source_symbols: source,
        }
    }

    fn test_policy() -> ObjectPlacementPolicy {
        ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000, // 100%
        }
    }

    #[test]
    fn needs_repair_unavailable() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(5, 10); // 50% coverage, unavailable
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_degraded() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500, // 5%
            ..Default::default()
        });

        // 90% coverage = 10% deficit = 1000 bps deficit
        let coverage = test_coverage(9, 10);
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn no_repair_healthy() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // 100% coverage
        let policy = test_policy();

        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn priority_calculation() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let policy = test_policy();

        // Unavailable = highest priority
        let unavailable = test_coverage(5, 10);
        assert_eq!(controller.calculate_priority(&unavailable, &policy), 1000);

        // Degraded = medium priority
        let degraded = test_coverage(9, 10); // 10% deficit
        let priority = controller.calculate_priority(&degraded, &policy);
        assert!(priority >= 100 && priority < 200);

        // Healthy = no priority
        let healthy = test_coverage(10, 10);
        assert_eq!(controller.calculate_priority(&healthy, &policy), 0);
    }

    #[test]
    fn queue_and_dequeue() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let request1 = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        let request2 = RepairRequest {
            object_id: ObjectId::from_bytes([2; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(3, 10),
            policy: test_policy(),
            priority: 1000, // Higher priority
        };

        controller.queue_repair(request1);
        controller.queue_repair(request2);

        assert_eq!(controller.queue_depth(), 2);

        // Should get highest priority first
        let next = controller.next_repair().unwrap();
        assert_eq!(next.priority, 1000);

        let next = controller.next_repair().unwrap();
        assert_eq!(next.priority, 100);
    }

    #[test]
    fn duplicate_queue_ignored() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let request = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        controller.queue_repair(request.clone());
        controller.queue_repair(request); // Duplicate

        assert_eq!(controller.queue_depth(), 1);
    }

    #[test]
    fn record_results() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let success = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        };

        let failure = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        };

        controller.record_result(&success);
        controller.record_result(&failure);

        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 2);
        assert_eq!(stats.repairs_succeeded, 1);
        assert_eq!(stats.repairs_failed, 1);
        assert_eq!(stats.symbols_added, 5);
    }

    #[test]
    fn rate_limiting() {
        let config = RepairControllerConfig {
            max_repairs_per_minute: 2,
            ..Default::default()
        };
        let controller = RepairController::new(config);

        // Queue 5 repairs
        for i in 0..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        // Should only get 2 due to rate limit
        assert!(controller.next_repair().is_some());
        assert!(controller.next_repair().is_some());
        assert!(controller.next_repair().is_none()); // Rate limited

        let stats = controller.stats();
        assert!(stats.rate_limited > 0);
    }

    #[tokio::test]
    async fn concurrent_permits() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 2,
            ..Default::default()
        };
        let controller = RepairController::new(config);

        let permit1 = controller.try_acquire_permit();
        assert!(permit1.is_some());

        let permit2 = controller.try_acquire_permit();
        assert!(permit2.is_some());

        // Third should fail
        let permit3 = controller.try_acquire_permit();
        assert!(permit3.is_none());

        // Drop one permit
        drop(permit1);

        // Now should succeed
        let permit4 = controller.try_acquire_permit();
        assert!(permit4.is_some());
    }

    #[test]
    fn targeted_repair_request() {
        let request = TargetedRepairRequest::new(ObjectId::from_bytes([1; 32]))
            .with_esis(vec![0, 1, 2])
            .with_preferred_sources(vec![100, 200])
            .with_excluded_sources(vec![300]);

        assert_eq!(request.esis.len(), 3);
        assert_eq!(request.preferred_sources.len(), 2);
        assert_eq!(request.excluded_sources.len(), 1);
    }

    #[test]
    fn clear_queue() {
        let controller = RepairController::new(RepairControllerConfig::default());

        for i in 0..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        assert_eq!(controller.queue_depth(), 5);

        controller.clear_queue();
        assert_eq!(controller.queue_depth(), 0);
    }
}

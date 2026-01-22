//! Deterministic multi-node E2E harness scaffolding.
//!
//! This provides the baseline types for the FCP2 system harness described in
//! `flywheel_connectors-1n78.21.4`. The implementation focuses on deterministic
//! orchestration and structured log collection, with placeholders for richer
//! mesh behavior as dependencies mature.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use fcp_mesh::{MeshNode, MeshNodeConfig};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, ObjectStore, QuarantineStore, SymbolStore,
};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};

/// Shared deterministic clock for harness components.
pub type SharedMockClock = Arc<Mutex<MockClock>>;

/// Harness error type (simple, deterministic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessError {
    /// Attempted to start an already running node.
    NodeAlreadyRunning,
    /// Attempted to stop a node that is not running.
    NodeNotRunning,
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeAlreadyRunning => write!(f, "node already running"),
            Self::NodeNotRunning => write!(f, "node not running"),
        }
    }
}

impl std::error::Error for HarnessError {}

/// Deterministic clock for simulation and log timestamps.
#[derive(Debug, Clone)]
pub struct MockClock {
    now_ms: u64,
    timers: BinaryHeap<Timer>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Timer {
    when_ms: u64,
}

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .when_ms
            .cmp(&self.when_ms)
            .then_with(|| self.when_ms.cmp(&other.when_ms))
    }
}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl MockClock {
    /// Create a new clock starting at `start_ms`.
    #[must_use]
    pub const fn new(start_ms: u64) -> Self {
        Self {
            now_ms: start_ms,
            timers: BinaryHeap::new(),
        }
    }

    /// Current simulated time in milliseconds.
    #[must_use]
    pub const fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Current simulated time as a UTC timestamp.
    #[must_use]
    pub fn now_timestamp(&self) -> DateTime<Utc> {
        Self::timestamp_from_ms(self.now_ms)
    }

    /// Advance the clock by a duration.
    pub fn advance(&mut self, duration: Duration) {
        let delta_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.now_ms = self.now_ms.saturating_add(delta_ms);
    }

    /// Schedule a timer at an absolute simulated timestamp (ms).
    pub fn schedule_timer(&mut self, at_ms: u64) {
        self.timers.push(Timer { when_ms: at_ms });
    }

    /// Advance to the next pending timer, returning the delta advanced.
    pub fn advance_to_next_timer(&mut self) -> Option<Duration> {
        let next = self.timers.pop()?;
        let delta_ms = next.when_ms.saturating_sub(self.now_ms);
        self.now_ms = next.when_ms;
        Some(Duration::from_millis(delta_ms))
    }

    fn timestamp_from_ms(ms: u64) -> DateTime<Utc> {
        let ms_i64 = i64::try_from(ms).unwrap_or(i64::MAX);
        Utc.timestamp_millis_opt(ms_i64)
            .single()
            .unwrap_or_else(|| Utc.timestamp_millis_opt(0).single().expect("epoch"))
    }
}

/// Structured log entry for harness runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Simulated timestamp (RFC3339 in UTC).
    pub timestamp: DateTime<Utc>,
    /// Real wall-clock timestamp.
    pub real_time: DateTime<Utc>,
    /// Node identifier.
    pub node_id: String,
    /// Test or scenario name.
    pub test_name: String,
    /// Phase within the scenario.
    pub phase: String,
    /// Correlation identifier for tracing.
    pub correlation_id: String,
    /// Event type (`session_established`, `symbol_routed`, `denial`, etc.).
    pub event_type: String,
    /// Optional structured details.
    #[serde(default)]
    pub details: serde_json::Value,
}

impl LogEntry {
    /// Construct a new log entry with a minimal required set of fields.
    #[must_use]
    pub fn new(
        node_id: impl Into<String>,
        test_name: impl Into<String>,
        phase: impl Into<String>,
        correlation_id: impl Into<String>,
        event_type: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self::new_with_timestamp(
            Utc::now(),
            node_id,
            test_name,
            phase,
            correlation_id,
            event_type,
            details,
        )
    }

    /// Construct a log entry using the simulated clock.
    #[must_use]
    pub fn new_with_clock(
        clock: &SharedMockClock,
        node_id: impl Into<String>,
        test_name: impl Into<String>,
        phase: impl Into<String>,
        correlation_id: impl Into<String>,
        event_type: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        let simulated = clock
            .lock()
            .map_or_else(|_| Utc::now(), |clock| clock.now_timestamp());
        Self::new_with_timestamp(
            simulated,
            node_id,
            test_name,
            phase,
            correlation_id,
            event_type,
            details,
        )
    }

    fn new_with_timestamp(
        simulated: DateTime<Utc>,
        node_id: impl Into<String>,
        test_name: impl Into<String>,
        phase: impl Into<String>,
        correlation_id: impl Into<String>,
        event_type: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            timestamp: simulated,
            real_time: Utc::now(),
            node_id: node_id.into(),
            test_name: test_name.into(),
            phase: phase.into(),
            correlation_id: correlation_id.into(),
            event_type: event_type.into(),
            details,
        }
    }
}

/// In-memory log collector for harness runs.
#[derive(Debug, Clone, Default)]
pub struct LogCollector {
    entries: Arc<Mutex<Vec<LogEntry>>>,
}

impl LogCollector {
    /// Create an empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn push(&self, entry: LogEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(entry);
        }
    }

    /// Snapshot all entries.
    #[must_use]
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .unwrap_or_default()
    }

    /// Filter entries by node.
    #[must_use]
    pub fn for_node(&self, node: &NodeId) -> Vec<LogEntry> {
        let needle = node.as_str();
        self.entries()
            .into_iter()
            .filter(|entry| entry.node_id == needle)
            .collect()
    }

    /// Filter entries by correlation id.
    #[must_use]
    pub fn for_correlation(&self, correlation_id: &str) -> Vec<LogEntry> {
        self.entries()
            .into_iter()
            .filter(|entry| entry.correlation_id == correlation_id)
            .collect()
    }

    /// Return all denial events.
    #[must_use]
    pub fn denials(&self) -> Vec<LogEntry> {
        self.entries()
            .into_iter()
            .filter(|entry| entry.event_type == "denial")
            .collect()
    }

    /// Export entries as JSONL.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let entries = self.entries();
        entries
            .into_iter()
            .filter_map(|entry| serde_json::to_string(&entry).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Message payload exchanged between simulated nodes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkMessage {
    /// Sender node.
    pub from: NodeId,
    /// Recipient node.
    pub to: NodeId,
    /// Raw payload bytes (opaque to the harness).
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct QueuedMessage {
    deliver_at_ms: u64,
    message: NetworkMessage,
}

impl Ord for QueuedMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior by delivery time.
        other
            .deliver_at_ms
            .cmp(&self.deliver_at_ms)
            .then_with(|| self.message.from.as_str().cmp(other.message.from.as_str()))
            .then_with(|| self.message.to.as_str().cmp(other.message.to.as_str()))
    }
}

impl PartialOrd for QueuedMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Deterministic network simulation with latency, loss, and partitions.
#[derive(Debug)]
pub struct SimulatedNetwork {
    latency: HashMap<(NodeId, NodeId), Duration>,
    loss: HashMap<(NodeId, NodeId), f64>,
    partitions: Vec<HashSet<NodeId>>,
    queue: BinaryHeap<QueuedMessage>,
    rng_state: u64,
}

impl SimulatedNetwork {
    /// Create a new simulated network with deterministic seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            latency: HashMap::new(),
            loss: HashMap::new(),
            partitions: Vec::new(),
            queue: BinaryHeap::new(),
            rng_state: seed.max(1),
        }
    }

    /// Set latency between two nodes.
    pub fn set_latency(&mut self, from: &NodeId, to: &NodeId, latency: Duration) {
        self.latency.insert((from.clone(), to.clone()), latency);
    }

    /// Set packet loss rate between two nodes (0.0 - 1.0).
    pub fn set_packet_loss(&mut self, from: &NodeId, to: &NodeId, rate: f64) {
        let clamped = rate.clamp(0.0, 1.0);
        self.loss.insert((from.clone(), to.clone()), clamped);
    }

    /// Partition the network by isolating the given nodes.
    pub fn partition(&mut self, isolated: &[NodeId]) {
        let set = isolated.iter().cloned().collect::<HashSet<_>>();
        self.partitions.push(set);
    }

    /// Heal all network partitions.
    pub fn heal_partitions(&mut self) {
        self.partitions.clear();
    }

    /// Enqueue a message for delivery.
    pub fn send(&mut self, now_ms: u64, message: NetworkMessage) -> bool {
        if self.is_partitioned(&message.from, &message.to) {
            return false;
        }

        let loss_rate = self
            .loss
            .get(&(message.from.clone(), message.to.clone()))
            .copied()
            .unwrap_or(0.0);
        if self.should_drop(loss_rate) {
            return false;
        }

        let latency = self
            .latency
            .get(&(message.from.clone(), message.to.clone()))
            .copied()
            .unwrap_or_default();
        let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        let deliver_at_ms = now_ms.saturating_add(latency_ms);

        self.queue.push(QueuedMessage {
            deliver_at_ms,
            message,
        });
        true
    }

    /// Drain all messages ready for delivery at `now_ms`.
    #[must_use]
    pub fn drain_ready(&mut self, now_ms: u64) -> Vec<NetworkMessage> {
        let mut ready = Vec::new();
        while let Some(top) = self.queue.peek() {
            if top.deliver_at_ms > now_ms {
                break;
            }
            if let Some(queued) = self.queue.pop() {
                ready.push(queued.message);
            }
        }
        ready
    }

    /// Return the number of queued messages.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }

    /// Return the next delivery timestamp, if any.
    #[must_use]
    pub fn next_delivery_ms(&self) -> Option<u64> {
        self.queue.peek().map(|queued| queued.deliver_at_ms)
    }

    fn is_partitioned(&self, from: &NodeId, to: &NodeId) -> bool {
        self.partitions.iter().any(|partition| {
            let from_in = partition.contains(from);
            let to_in = partition.contains(to);
            from_in ^ to_in
        })
    }

    fn should_drop(&mut self, rate: f64) -> bool {
        if rate <= 0.0 {
            return false;
        }
        if rate >= 1.0 {
            return true;
        }
        // Deterministic LCG sampling for reproducible loss.
        self.rng_state = self
            .rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        #[allow(clippy::cast_precision_loss)]
        let sample = (self.rng_state >> 11) as f64 / ((u64::MAX >> 11) as f64);
        sample < rate
    }
}

/// Deterministic mesh node for testing.
pub struct TestMeshNode {
    pub node_id: NodeId,
    pub clock: SharedMockClock,
    pub logs: LogCollector,
    config: MeshNodeConfig,
    object_store: Arc<dyn ObjectStore>,
    symbol_store: Arc<dyn SymbolStore>,
    quarantine_store: Arc<QuarantineStore>,
    mesh: Option<MeshNode>,
    running: bool,
}

impl std::fmt::Debug for TestMeshNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestMeshNode")
            .field("node_id", &self.node_id)
            .field("clock", &self.clock)
            .field("logs", &self.logs)
            .field("config", &self.config)
            .field("running", &self.running)
            .finish_non_exhaustive()
    }
}

impl TestMeshNode {
    /// Create a deterministic test node with in-memory stores.
    #[must_use]
    pub fn new(seed: u64, node_index: u32, clock: SharedMockClock, logs: LogCollector) -> Self {
        let node_id = NodeId::new(format!("test-node-{node_index}-{seed:x}"));
        let sender_instance_id = seed ^ u64::from(node_index);
        let config =
            MeshNodeConfig::new(node_id.as_str()).with_sender_instance_id(sender_instance_id);
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mesh = Some(MeshNode::new(
            config.clone(),
            object_store.clone(),
            symbol_store.clone(),
            quarantine_store.clone(),
        ));

        Self {
            node_id,
            clock,
            logs,
            config,
            object_store,
            symbol_store,
            quarantine_store,
            mesh,
            running: false,
        }
    }

    /// Boot node and join mesh (in-process).
    ///
    /// # Errors
    ///
    /// Returns `HarnessError::NodeAlreadyRunning` if the node is already running.
    pub fn start(&mut self) -> Result<(), HarnessError> {
        if self.running {
            return Err(HarnessError::NodeAlreadyRunning);
        }
        if self.mesh.is_none() {
            self.mesh = Some(MeshNode::new(
                self.config.clone(),
                self.object_store.clone(),
                self.symbol_store.clone(),
                self.quarantine_store.clone(),
            ));
        }
        self.running = true;
        self.logs.push(LogEntry::new_with_clock(
            &self.clock,
            self.node_id.as_str(),
            "test_mesh_boot",
            "execute",
            "bootstrap",
            "node_started",
            serde_json::json!({ "node_id": self.node_id.as_str() }),
        ));
        Ok(())
    }

    /// Graceful shutdown.
    ///
    /// # Errors
    ///
    /// Returns `HarnessError::NodeNotRunning` if the node is not running.
    pub fn stop(&mut self) -> Result<(), HarnessError> {
        if !self.running {
            return Err(HarnessError::NodeNotRunning);
        }
        self.running = false;
        self.logs.push(LogEntry::new_with_clock(
            &self.clock,
            self.node_id.as_str(),
            "test_mesh_shutdown",
            "cleanup",
            "shutdown",
            "node_stopped",
            serde_json::json!({ "node_id": self.node_id.as_str() }),
        ));
        Ok(())
    }

    /// Simulate a crash (drops mesh state).
    pub fn crash(&mut self) {
        self.running = false;
        self.mesh = None;
        self.logs.push(LogEntry::new_with_clock(
            &self.clock,
            self.node_id.as_str(),
            "test_mesh_crash",
            "execute",
            "crash",
            "node_crashed",
            serde_json::json!({ "node_id": self.node_id.as_str() }),
        ));
    }

    /// Check if node is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Access the underlying `MeshNode` (if running).
    #[must_use]
    pub const fn mesh(&self) -> Option<&MeshNode> {
        self.mesh.as_ref()
    }
}

/// Multi-node test harness.
#[derive(Debug)]
pub struct TestHarness {
    pub nodes: Vec<TestMeshNode>,
    pub network: SimulatedNetwork,
    pub clock: SharedMockClock,
    pub logs: LogCollector,
}

/// Timeout error for convergence waits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessTimeout {
    pub waited_ms: u64,
    pub timeout_ms: u64,
}

impl std::fmt::Display for HarnessTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "harness timed out after {}ms (timeout {}ms)",
            self.waited_ms, self.timeout_ms
        )
    }
}

impl std::error::Error for HarnessTimeout {}

impl TestHarness {
    /// Create an N-node mesh with deterministic seed.
    #[must_use]
    pub fn new(node_count: usize, seed: u64) -> Self {
        let clock = Arc::new(Mutex::new(MockClock::new(0)));
        let logs = LogCollector::new();
        #[allow(clippy::cast_possible_truncation)]
        let nodes = (0..node_count)
            .map(|index| TestMeshNode::new(seed, index as u32, clock.clone(), logs.clone()))
            .collect::<Vec<_>>();

        Self {
            nodes,
            network: SimulatedNetwork::new(seed),
            clock,
            logs,
        }
    }

    /// Start all nodes.
    ///
    /// # Errors
    ///
    /// Returns an error if any node fails to start.
    pub fn start_all(&mut self) -> Result<(), HarnessError> {
        for node in &mut self.nodes {
            node.start()?;
        }
        Ok(())
    }

    /// Stop all nodes.
    ///
    /// # Errors
    ///
    /// Returns an error if any running node fails to stop.
    pub fn stop_all(&mut self) -> Result<(), HarnessError> {
        for node in &mut self.nodes {
            if node.is_running() {
                node.stop()?;
            }
        }
        Ok(())
    }

    /// Advance simulated time by duration.
    pub fn advance_time(&self, duration: Duration) {
        if let Ok(mut clock) = self.clock.lock() {
            clock.advance(duration);
        }
    }

    /// Current simulated time in milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock
            .lock()
            .map(|clock| clock.now_ms())
            .unwrap_or_default()
    }

    /// Partition the network by isolating the given nodes.
    pub fn partition(&mut self, isolated: &[NodeId]) {
        self.network.partition(isolated);
    }

    /// Heal all partitions.
    pub fn heal_partition(&mut self) {
        self.network.heal_partitions();
    }

    /// Inject packet loss between two nodes.
    pub fn set_packet_loss(&mut self, from: &NodeId, to: &NodeId, rate: f64) {
        self.network.set_packet_loss(from, to, rate);
    }

    /// Inject latency between two nodes.
    pub fn set_latency(&mut self, from: &NodeId, to: &NodeId, latency: Duration) {
        self.network.set_latency(from, to, latency);
    }

    /// Wait for simulated convergence (queue drained) within a timeout.
    ///
    /// This does not yet drive mesh state; it only advances simulated time until
    /// the network queue is empty.
    ///
    /// # Errors
    ///
    /// Returns `HarnessTimeout` if the simulated timeout expires.
    pub async fn wait_for_convergence(&mut self, timeout: Duration) -> Result<(), HarnessTimeout> {
        std::future::ready(()).await;
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let start_ms = self.now_ms();

        loop {
            if self.network.pending_len() == 0 {
                return Ok(());
            }

            let now_ms = self.now_ms();
            let waited_ms = now_ms.saturating_sub(start_ms);
            if waited_ms >= timeout_ms {
                return Err(HarnessTimeout {
                    waited_ms,
                    timeout_ms,
                });
            }

            let next_ms = self
                .network
                .next_delivery_ms()
                .unwrap_or_else(|| now_ms.saturating_add(1));
            let advance_ms = next_ms.saturating_sub(now_ms).max(1);
            self.advance_time(Duration::from_millis(advance_ms));

            let now_ms = self.now_ms();
            let delivered = self.network.drain_ready(now_ms);
            if !delivered.is_empty() {
                self.logs.push(LogEntry::new_with_clock(
                    &self.clock,
                    "harness",
                    "convergence",
                    "deliver",
                    "network",
                    "network_deliver",
                    serde_json::json!({ "delivered": delivered.len() }),
                ));
            }
        }
    }

    /// Snapshot logs for analysis.
    #[must_use]
    pub fn log_entries(&self) -> Vec<LogEntry> {
        self.logs.entries()
    }

    /// Snapshot logs for analysis (alias).
    #[must_use]
    pub fn logs(&self) -> Vec<LogEntry> {
        self.logs.entries()
    }
}

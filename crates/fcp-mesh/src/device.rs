//! Device profile types for execution planning and capability reporting.
//!
//! This module implements the `DeviceProfile` schema (NORMATIVE) used by the
//! execution planner to make device-aware routing and execution decisions.
//!
//! # Overview
//!
//! - [`DeviceProfile`] - Complete device capability snapshot
//! - [`GpuProfile`] - GPU hardware capabilities
//! - [`TpuProfile`] - TPU hardware capabilities
//! - [`InstalledConnector`] - Connector installation info
//! - [`FitnessScore`] - Execution fitness calculation
//!
//! # Example
//!
//! ```rust
//! use fcp_mesh::device::{DeviceProfile, CpuArch, PowerSource, LatencyClass, AvailabilityProfile};
//! use fcp_tailscale::NodeId;
//!
//! let profile = DeviceProfile::builder(NodeId::new("node-12345"))
//!     .cpu_cores(8)
//!     .cpu_arch(CpuArch::X86_64)
//!     .memory_mb(16384)
//!     .power_source(PowerSource::Mains)
//!     .latency_class(LatencyClass::Lan)
//!     .availability(AvailabilityProfile::AlwaysOn)
//!     .build();
//!
//! assert_eq!(profile.cpu_cores, 8);
//! ```

use fcp_core::{CapabilityGrant, ConnectorId, ObjectId};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};

/// Current schema version for `DeviceProfile`.
pub const DEVICE_PROFILE_VERSION: u32 = 1;

/// Default periodic refresh interval in seconds (5 minutes).
pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 300;

// ============================================================================
// Enums
// ============================================================================

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuArch {
    /// x86-64 (AMD64)
    X86_64,
    /// ARM 64-bit (AArch64)
    Aarch64,
    /// WebAssembly 32-bit
    Wasm32,
    /// RISC-V 64-bit
    Riscv64,
}

impl Default for CpuArch {
    fn default() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
        #[cfg(target_arch = "wasm32")]
        {
            Self::Wasm32
        }
        #[cfg(target_arch = "riscv64")]
        {
            Self::Riscv64
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "wasm32",
            target_arch = "riscv64"
        )))]
        {
            Self::X86_64
        }
    }
}

/// Power source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerSource {
    /// Connected to mains power
    Mains,
    /// Running on battery
    Battery,
    /// Solar powered
    Solar,
    /// Unknown power source
    Unknown,
}

impl Default for PowerSource {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Network latency class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    /// Local (same machine)
    Local,
    /// LAN (same network)
    Lan,
    /// Internet (direct connection)
    Internet,
    /// DERP relay (Tailscale fallback)
    Derp,
}

impl Default for LatencyClass {
    fn default() -> Self {
        Self::Internet
    }
}

/// Device availability profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityProfile {
    /// Always online
    AlwaysOn,
    /// Available on schedule
    Scheduled,
    /// Best effort (may go offline)
    BestEffort,
}

impl Default for AvailabilityProfile {
    fn default() -> Self {
        Self::BestEffort
    }
}

/// GPU vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuVendor {
    /// NVIDIA
    Nvidia,
    /// AMD
    Amd,
    /// Apple Silicon
    Apple,
    /// Intel
    Intel,
    /// Other vendor
    Other,
}

/// TPU vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TpuVendor {
    /// Google TPU
    Google,
    /// Other vendor
    Other,
}

// ============================================================================
// GPU/TPU Profiles
// ============================================================================

/// GPU hardware profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuProfile {
    /// GPU vendor
    pub vendor: GpuVendor,
    /// Model name (e.g., "RTX 4090", "M3 Max")
    pub model: String,
    /// Video RAM in megabytes
    pub vram_mb: u32,
    /// Compute capability (e.g., CUDA version "8.9")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_capability: Option<String>,
}

impl GpuProfile {
    /// Create a new GPU profile.
    #[must_use]
    pub fn new(vendor: GpuVendor, model: impl Into<String>, vram_mb: u32) -> Self {
        Self {
            vendor,
            model: model.into(),
            vram_mb,
            compute_capability: None,
        }
    }

    /// Set compute capability.
    #[must_use]
    pub fn with_compute_capability(mut self, capability: impl Into<String>) -> Self {
        self.compute_capability = Some(capability.into());
        self
    }
}

/// TPU hardware profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpuProfile {
    /// TPU vendor
    pub vendor: TpuVendor,
    /// Model name (e.g., "v4", "v5e")
    pub model: String,
    /// Number of cores
    pub cores: u32,
    /// HBM memory in megabytes
    pub hbm_mb: u32,
}

impl TpuProfile {
    /// Create a new TPU profile.
    #[must_use]
    pub fn new(vendor: TpuVendor, model: impl Into<String>, cores: u32, hbm_mb: u32) -> Self {
        Self {
            vendor,
            model: model.into(),
            cores,
            hbm_mb,
        }
    }
}

// ============================================================================
// Installed Connector
// ============================================================================

/// Installed connector information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledConnector {
    /// Connector identifier
    pub connector_id: ConnectorId,
    /// Semantic version string
    pub version: String,
    /// Binary content hash (ObjectId)
    pub binary_hash: ObjectId,
    /// Capabilities granted to this connector
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityGrant>,
}

impl InstalledConnector {
    /// Create a new installed connector entry.
    #[must_use]
    pub fn new(
        connector_id: ConnectorId,
        version: impl Into<String>,
        binary_hash: ObjectId,
    ) -> Self {
        Self {
            connector_id,
            version: version.into(),
            binary_hash,
            capabilities: Vec::new(),
        }
    }

    /// Add capabilities to this connector.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<CapabilityGrant>) -> Self {
        self.capabilities = capabilities;
        self
    }
}

// ============================================================================
// Device Profile
// ============================================================================

/// Complete device capability profile (NORMATIVE).
///
/// Published by nodes to the mesh for execution planning decisions.
/// Nodes MUST publish `DeviceProfile` on:
/// - Startup
/// - Significant capability change
/// - Connector install/remove
/// - Periodic refresh (every 5 minutes default)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// Tailscale node identifier
    pub node_id: NodeId,
    /// Schema version
    pub profile_version: u32,
    /// Profile creation timestamp (Unix millis)
    pub timestamp: u64,

    // Compute
    /// Number of CPU cores
    pub cpu_cores: u16,
    /// CPU architecture
    pub cpu_arch: CpuArch,
    /// System memory in megabytes
    pub memory_mb: u32,
    /// GPU capabilities (if present)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuProfile>,
    /// TPU capabilities (if present)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpu: Option<TpuProfile>,

    // Storage
    /// Local storage capacity in megabytes
    pub local_storage_mb: u64,
    /// Symbol store quota in megabytes
    pub symbol_store_quota_mb: u32,

    // Power
    /// Current power source
    pub power_source: PowerSource,
    /// Battery percentage (if on battery)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery_percent: Option<u8>,

    // Network
    /// Estimated bandwidth in kilobits per second
    pub bandwidth_estimate_kbps: u32,
    /// Network latency class
    pub latency_class: LatencyClass,
    /// Whether connection is metered
    #[serde(default)]
    pub metered: bool,

    // Availability
    /// Device availability profile
    pub availability: AvailabilityProfile,
    /// Next expected downtime (Unix millis)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_expected_downtime: Option<u64>,

    // Connectors
    /// Installed connectors
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connectors: Vec<InstalledConnector>,
}

impl DeviceProfile {
    /// Create a new profile builder.
    #[must_use]
    pub fn builder(node_id: NodeId) -> DeviceProfileBuilder {
        DeviceProfileBuilder::new(node_id)
    }

    /// Check if the profile has GPU capabilities.
    #[must_use]
    pub fn has_gpu(&self) -> bool {
        self.gpu.is_some()
    }

    /// Check if the profile has TPU capabilities.
    #[must_use]
    pub fn has_tpu(&self) -> bool {
        self.tpu.is_some()
    }

    /// Check if a specific connector is installed.
    #[must_use]
    pub fn has_connector(&self, connector_id: &ConnectorId) -> bool {
        self.connectors
            .iter()
            .any(|c| &c.connector_id == connector_id)
    }

    /// Get an installed connector by ID.
    #[must_use]
    pub fn get_connector(&self, connector_id: &ConnectorId) -> Option<&InstalledConnector> {
        self.connectors
            .iter()
            .find(|c| &c.connector_id == connector_id)
    }

    /// Check if device is on low battery (< 20%).
    #[must_use]
    pub fn is_low_battery(&self) -> bool {
        matches!(self.power_source, PowerSource::Battery)
            && self.battery_percent.map_or(false, |p| p < 20)
    }

    /// Compute execution fitness score for this device.
    #[must_use]
    pub fn compute_fitness(&self, ctx: &FitnessContext) -> FitnessScore {
        FitnessScore::compute(self, ctx)
    }
}

// ============================================================================
// Device Profile Builder
// ============================================================================

/// Builder for `DeviceProfile`.
#[derive(Debug)]
pub struct DeviceProfileBuilder {
    node_id: NodeId,
    profile_version: u32,
    timestamp: u64,
    cpu_cores: u16,
    cpu_arch: CpuArch,
    memory_mb: u32,
    gpu: Option<GpuProfile>,
    tpu: Option<TpuProfile>,
    local_storage_mb: u64,
    symbol_store_quota_mb: u32,
    power_source: PowerSource,
    battery_percent: Option<u8>,
    bandwidth_estimate_kbps: u32,
    latency_class: LatencyClass,
    metered: bool,
    availability: AvailabilityProfile,
    next_expected_downtime: Option<u64>,
    connectors: Vec<InstalledConnector>,
}

impl DeviceProfileBuilder {
    /// Create a new builder with the given node ID.
    #[must_use]
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            profile_version: DEVICE_PROFILE_VERSION,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            cpu_cores: 1,
            cpu_arch: CpuArch::default(),
            memory_mb: 1024,
            gpu: None,
            tpu: None,
            local_storage_mb: 0,
            symbol_store_quota_mb: 0,
            power_source: PowerSource::default(),
            battery_percent: None,
            bandwidth_estimate_kbps: 1000,
            latency_class: LatencyClass::default(),
            metered: false,
            availability: AvailabilityProfile::default(),
            next_expected_downtime: None,
            connectors: Vec::new(),
        }
    }

    /// Set CPU core count.
    #[must_use]
    pub fn cpu_cores(mut self, cores: u16) -> Self {
        self.cpu_cores = cores;
        self
    }

    /// Set CPU architecture.
    #[must_use]
    pub fn cpu_arch(mut self, arch: CpuArch) -> Self {
        self.cpu_arch = arch;
        self
    }

    /// Set memory in megabytes.
    #[must_use]
    pub fn memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set GPU profile.
    #[must_use]
    pub fn gpu(mut self, gpu: GpuProfile) -> Self {
        self.gpu = Some(gpu);
        self
    }

    /// Set TPU profile.
    #[must_use]
    pub fn tpu(mut self, tpu: TpuProfile) -> Self {
        self.tpu = Some(tpu);
        self
    }

    /// Set local storage in megabytes.
    #[must_use]
    pub fn local_storage_mb(mut self, mb: u64) -> Self {
        self.local_storage_mb = mb;
        self
    }

    /// Set symbol store quota in megabytes.
    #[must_use]
    pub fn symbol_store_quota_mb(mut self, mb: u32) -> Self {
        self.symbol_store_quota_mb = mb;
        self
    }

    /// Set power source.
    #[must_use]
    pub fn power_source(mut self, source: PowerSource) -> Self {
        self.power_source = source;
        self
    }

    /// Set battery percentage.
    #[must_use]
    pub fn battery_percent(mut self, percent: u8) -> Self {
        self.battery_percent = Some(percent);
        self
    }

    /// Set bandwidth estimate in kbps.
    #[must_use]
    pub fn bandwidth_estimate_kbps(mut self, kbps: u32) -> Self {
        self.bandwidth_estimate_kbps = kbps;
        self
    }

    /// Set latency class.
    #[must_use]
    pub fn latency_class(mut self, class: LatencyClass) -> Self {
        self.latency_class = class;
        self
    }

    /// Set metered connection flag.
    #[must_use]
    pub fn metered(mut self, metered: bool) -> Self {
        self.metered = metered;
        self
    }

    /// Set availability profile.
    #[must_use]
    pub fn availability(mut self, availability: AvailabilityProfile) -> Self {
        self.availability = availability;
        self
    }

    /// Set next expected downtime.
    #[must_use]
    pub fn next_expected_downtime(mut self, timestamp: u64) -> Self {
        self.next_expected_downtime = Some(timestamp);
        self
    }

    /// Set timestamp.
    #[must_use]
    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Add an installed connector.
    #[must_use]
    pub fn add_connector(mut self, connector: InstalledConnector) -> Self {
        self.connectors.push(connector);
        self
    }

    /// Build the `DeviceProfile`.
    #[must_use]
    pub fn build(self) -> DeviceProfile {
        DeviceProfile {
            node_id: self.node_id,
            profile_version: self.profile_version,
            timestamp: self.timestamp,
            cpu_cores: self.cpu_cores,
            cpu_arch: self.cpu_arch,
            memory_mb: self.memory_mb,
            gpu: self.gpu,
            tpu: self.tpu,
            local_storage_mb: self.local_storage_mb,
            symbol_store_quota_mb: self.symbol_store_quota_mb,
            power_source: self.power_source,
            battery_percent: self.battery_percent,
            bandwidth_estimate_kbps: self.bandwidth_estimate_kbps,
            latency_class: self.latency_class,
            metered: self.metered,
            availability: self.availability,
            next_expected_downtime: self.next_expected_downtime,
            connectors: self.connectors,
        }
    }
}

// ============================================================================
// Fitness Scoring
// ============================================================================

/// Context for fitness score computation.
#[derive(Debug, Clone, Default)]
pub struct FitnessContext {
    /// Whether required symbols are already present locally
    pub symbols_present: bool,
    /// Whether GPU is required for the operation
    pub requires_gpu: bool,
    /// Whether TPU is required for the operation
    pub requires_tpu: bool,
    /// Minimum memory required (MB)
    pub min_memory_mb: Option<u32>,
    /// Required connector ID
    pub required_connector: Option<ConnectorId>,
}

impl FitnessContext {
    /// Create an empty fitness context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set symbols present flag.
    #[must_use]
    pub fn with_symbols_present(mut self, present: bool) -> Self {
        self.symbols_present = present;
        self
    }

    /// Set GPU requirement.
    #[must_use]
    pub fn with_requires_gpu(mut self, required: bool) -> Self {
        self.requires_gpu = required;
        self
    }

    /// Set TPU requirement.
    #[must_use]
    pub fn with_requires_tpu(mut self, required: bool) -> Self {
        self.requires_tpu = required;
        self
    }

    /// Set minimum memory requirement.
    #[must_use]
    pub fn with_min_memory_mb(mut self, mb: u32) -> Self {
        self.min_memory_mb = Some(mb);
        self
    }

    /// Set required connector.
    #[must_use]
    pub fn with_required_connector(mut self, connector_id: ConnectorId) -> Self {
        self.required_connector = Some(connector_id);
        self
    }
}

/// Execution fitness score.
///
/// Higher scores indicate better fitness for execution.
/// A score of 0 means the device cannot execute the operation.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FitnessScore {
    /// The computed score (0.0 = cannot execute, higher = better)
    pub score: f64,
    /// Whether the device meets minimum requirements
    pub eligible: bool,
}

impl FitnessScore {
    /// Base score for eligible devices.
    const BASE_SCORE: f64 = 100.0;
    /// Penalty for using DERP relay.
    const DERP_PENALTY: f64 = 30.0;
    /// Bonus for local symbols.
    const LOCALITY_BONUS: f64 = 25.0;
    /// Penalty for low battery (< 20%).
    const LOW_BATTERY_PENALTY: f64 = 40.0;
    /// Bonus for having required GPU.
    const GPU_BONUS: f64 = 20.0;
    /// Bonus for having required TPU.
    const TPU_BONUS: f64 = 20.0;
    /// Penalty per latency class step.
    const LATENCY_PENALTY_PER_CLASS: f64 = 10.0;
    /// Penalty for metered connection.
    const METERED_PENALTY: f64 = 15.0;
    /// Penalty for best-effort availability.
    const BEST_EFFORT_PENALTY: f64 = 10.0;

    /// Create an ineligible score.
    #[must_use]
    pub const fn ineligible() -> Self {
        Self {
            score: 0.0,
            eligible: false,
        }
    }

    /// Compute fitness score for a device profile.
    #[must_use]
    pub fn compute(profile: &DeviceProfile, ctx: &FitnessContext) -> Self {
        // Check minimum requirements
        if ctx.requires_gpu && !profile.has_gpu() {
            return Self::ineligible();
        }
        if ctx.requires_tpu && !profile.has_tpu() {
            return Self::ineligible();
        }
        if let Some(min_mem) = ctx.min_memory_mb {
            if profile.memory_mb < min_mem {
                return Self::ineligible();
            }
        }
        if let Some(ref connector_id) = ctx.required_connector {
            if !profile.has_connector(connector_id) {
                return Self::ineligible();
            }
        }

        // Start with base score
        let mut score = Self::BASE_SCORE;

        // DERP penalty
        if profile.latency_class == LatencyClass::Derp {
            score -= Self::DERP_PENALTY;
        }

        // Locality bonus
        if ctx.symbols_present {
            score += Self::LOCALITY_BONUS;
        }

        // Battery penalty
        if profile.is_low_battery() {
            score -= Self::LOW_BATTERY_PENALTY;
        }

        // Capability bonuses
        if ctx.requires_gpu && profile.has_gpu() {
            score += Self::GPU_BONUS;
        }
        if ctx.requires_tpu && profile.has_tpu() {
            score += Self::TPU_BONUS;
        }

        // Latency penalty (0 for Local, increasing for each class)
        let latency_penalty = match profile.latency_class {
            LatencyClass::Local => 0.0,
            LatencyClass::Lan => Self::LATENCY_PENALTY_PER_CLASS,
            LatencyClass::Internet => Self::LATENCY_PENALTY_PER_CLASS * 2.0,
            LatencyClass::Derp => Self::LATENCY_PENALTY_PER_CLASS * 3.0,
        };
        score -= latency_penalty;

        // Metered connection penalty
        if profile.metered {
            score -= Self::METERED_PENALTY;
        }

        // Availability penalty
        if profile.availability == AvailabilityProfile::BestEffort {
            score -= Self::BEST_EFFORT_PENALTY;
        }

        Self {
            score: score.max(0.0),
            eligible: true,
        }
    }
}

impl Eq for FitnessScore {}

impl Ord for FitnessScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Eligible devices always rank higher than ineligible
        match (self.eligible, other.eligible) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => self
                .score
                .partial_cmp(&other.score)
                .unwrap_or(std::cmp::Ordering::Equal),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId::new("test-node-12345")
    }

    #[test]
    fn test_device_profile_builder() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .cpu_arch(CpuArch::X86_64)
            .memory_mb(16384)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Lan)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(1000)
            .build();

        assert_eq!(profile.node_id.as_str(), "test-node-12345");
        assert_eq!(profile.cpu_cores, 8);
        assert_eq!(profile.cpu_arch, CpuArch::X86_64);
        assert_eq!(profile.memory_mb, 16384);
        assert_eq!(profile.power_source, PowerSource::Mains);
        assert_eq!(profile.latency_class, LatencyClass::Lan);
        assert_eq!(profile.availability, AvailabilityProfile::AlwaysOn);
        assert_eq!(profile.profile_version, DEVICE_PROFILE_VERSION);
    }

    #[test]
    fn test_device_profile_with_gpu() {
        let gpu =
            GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576).with_compute_capability("8.9");

        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(16)
            .memory_mb(65536)
            .gpu(gpu)
            .build();

        assert!(profile.has_gpu());
        assert!(!profile.has_tpu());

        let gpu = profile.gpu.as_ref().unwrap();
        assert_eq!(gpu.vendor, GpuVendor::Nvidia);
        assert_eq!(gpu.model, "RTX 4090");
        assert_eq!(gpu.vram_mb, 24576);
        assert_eq!(gpu.compute_capability.as_deref(), Some("8.9"));
    }

    #[test]
    fn test_device_profile_with_tpu() {
        let tpu = TpuProfile::new(TpuVendor::Google, "v4", 4, 32768);

        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(96)
            .memory_mb(262144)
            .tpu(tpu)
            .build();

        assert!(!profile.has_gpu());
        assert!(profile.has_tpu());

        let tpu = profile.tpu.as_ref().unwrap();
        assert_eq!(tpu.vendor, TpuVendor::Google);
        assert_eq!(tpu.model, "v4");
        assert_eq!(tpu.cores, 4);
        assert_eq!(tpu.hbm_mb, 32768);
    }

    #[test]
    fn test_low_battery_detection() {
        let profile_mains = DeviceProfile::builder(test_node_id())
            .power_source(PowerSource::Mains)
            .build();
        assert!(!profile_mains.is_low_battery());

        let profile_battery_ok = DeviceProfile::builder(test_node_id())
            .power_source(PowerSource::Battery)
            .battery_percent(50)
            .build();
        assert!(!profile_battery_ok.is_low_battery());

        let profile_battery_low = DeviceProfile::builder(test_node_id())
            .power_source(PowerSource::Battery)
            .battery_percent(15)
            .build();
        assert!(profile_battery_low.is_low_battery());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let gpu = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .cpu_arch(CpuArch::X86_64)
            .memory_mb(16384)
            .gpu(gpu)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Lan)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(1705000000000)
            .build();

        // JSON roundtrip
        let json = serde_json::to_string(&profile).unwrap();
        let decoded: DeviceProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, decoded);
    }

    #[test]
    fn test_fitness_score_basic() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .build();

        let ctx = FitnessContext::new();
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        assert_eq!(score.score, FitnessScore::BASE_SCORE);
    }

    #[test]
    fn test_fitness_score_with_locality_bonus() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .latency_class(LatencyClass::Local)
            .build();

        let ctx = FitnessContext::new().with_symbols_present(true);
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        assert!(score.score > FitnessScore::BASE_SCORE);
    }

    #[test]
    fn test_fitness_score_derp_penalty() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .latency_class(LatencyClass::Derp)
            .build();

        let ctx = FitnessContext::new();
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        // DERP has both DERP_PENALTY and 3x LATENCY_PENALTY_PER_CLASS
        assert!(score.score < FitnessScore::BASE_SCORE);
    }

    #[test]
    fn test_fitness_score_low_battery_penalty() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .power_source(PowerSource::Battery)
            .battery_percent(10)
            .latency_class(LatencyClass::Local)
            .build();

        let ctx = FitnessContext::new();
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        assert!(score.score < FitnessScore::BASE_SCORE);
    }

    #[test]
    fn test_fitness_score_gpu_requirement() {
        let profile_no_gpu = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .build();

        let profile_with_gpu = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .gpu(GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576))
            .build();

        let ctx = FitnessContext::new().with_requires_gpu(true);

        let score_no_gpu = profile_no_gpu.compute_fitness(&ctx);
        let score_with_gpu = profile_with_gpu.compute_fitness(&ctx);

        assert!(!score_no_gpu.eligible);
        assert!(score_with_gpu.eligible);
        assert!(score_with_gpu.score > 0.0);
    }

    #[test]
    fn test_fitness_score_memory_requirement() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(8192)
            .build();

        let ctx_ok = FitnessContext::new().with_min_memory_mb(4096);
        let ctx_fail = FitnessContext::new().with_min_memory_mb(16384);

        let score_ok = profile.compute_fitness(&ctx_ok);
        let score_fail = profile.compute_fitness(&ctx_fail);

        assert!(score_ok.eligible);
        assert!(!score_fail.eligible);
    }

    #[test]
    fn test_fitness_score_ordering() {
        let profile_good = DeviceProfile::builder(test_node_id())
            .cpu_cores(16)
            .memory_mb(32768)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .build();

        let profile_bad = DeviceProfile::builder(test_node_id())
            .cpu_cores(4)
            .memory_mb(8192)
            .power_source(PowerSource::Battery)
            .battery_percent(10)
            .latency_class(LatencyClass::Derp)
            .availability(AvailabilityProfile::BestEffort)
            .metered(true)
            .build();

        let ctx = FitnessContext::new();
        let score_good = profile_good.compute_fitness(&ctx);
        let score_bad = profile_bad.compute_fitness(&ctx);

        // Both eligible but good should score higher
        assert!(score_good.eligible);
        assert!(score_bad.eligible);
        assert!(score_good > score_bad);
    }

    #[test]
    fn test_fitness_score_deterministic() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .latency_class(LatencyClass::Lan)
            .timestamp(1000)
            .build();

        let ctx = FitnessContext::new().with_symbols_present(true);

        // Compute multiple times
        let score1 = profile.compute_fitness(&ctx);
        let score2 = profile.compute_fitness(&ctx);
        let score3 = profile.compute_fitness(&ctx);

        // Should be deterministic
        assert_eq!(score1, score2);
        assert_eq!(score2, score3);
    }

    #[test]
    fn test_cpu_arch_default() {
        let arch = CpuArch::default();
        // Should match current architecture
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, CpuArch::X86_64);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, CpuArch::Aarch64);
    }

    #[test]
    fn test_gpu_profile_builder() {
        let gpu =
            GpuProfile::new(GpuVendor::Apple, "M3 Max", 40960).with_compute_capability("Metal 3");

        assert_eq!(gpu.vendor, GpuVendor::Apple);
        assert_eq!(gpu.model, "M3 Max");
        assert_eq!(gpu.vram_mb, 40960);
        assert_eq!(gpu.compute_capability.as_deref(), Some("Metal 3"));
    }

    #[test]
    fn test_installed_connector() {
        let connector_id = ConnectorId::new("fcp", "test", "1.0.0").unwrap();
        let binary_hash = ObjectId::from_bytes([0u8; 32]);
        let connector = InstalledConnector::new(connector_id.clone(), "1.0.0", binary_hash);

        let profile = DeviceProfile::builder(test_node_id())
            .add_connector(connector)
            .build();

        assert!(profile.has_connector(&connector_id));
        assert!(profile.get_connector(&connector_id).is_some());

        let other_id = ConnectorId::new("fcp", "other", "1.0.0").unwrap();
        assert!(!profile.has_connector(&other_id));
    }
}

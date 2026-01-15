//! Benchmark result types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for benchmark results,
//! enabling regression tracking and CI integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete benchmark report including environment metadata and all results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Environment information for reproducibility.
    pub environment: EnvironmentInfo,

    /// Individual benchmark results.
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkReport {
    /// Create a new benchmark report with the given environment and results.
    #[must_use]
    pub fn new(environment: EnvironmentInfo, results: Vec<BenchmarkResult>) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            environment,
            results,
        }
    }
}

/// Environment information for reproducibility and regression tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    /// Operating system name (e.g., `linux`, `macos`, `windows`).
    pub os: String,

    /// Operating system version.
    pub os_version: String,

    /// CPU architecture (e.g., `x86_64`, `aarch64`).
    pub arch: String,

    /// Number of logical CPUs.
    pub cpu_count: usize,

    /// Total system memory in bytes (if available).
    pub memory_bytes: Option<u64>,

    /// Git commit hash (if in a git repository).
    pub git_commit: Option<String>,

    /// Git branch (if in a git repository).
    pub git_branch: Option<String>,

    /// Whether the working directory is clean (no uncommitted changes).
    pub git_dirty: Option<bool>,

    /// FCP CLI version.
    pub fcp_version: String,

    /// Rust compiler version used to build the CLI.
    pub rustc_version: Option<String>,

    /// Timestamp when the benchmark started.
    pub timestamp: DateTime<Utc>,
}

/// Result of a single benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Unique benchmark name (e.g., "cbor-serialize", "connector-activate").
    pub name: String,

    /// Human-readable description of what was measured.
    pub description: String,

    /// Parameters used for this benchmark run.
    pub parameters: serde_json::Value,

    /// Number of samples taken.
    pub sample_count: u32,

    /// Number of warmup iterations performed.
    pub warmup_count: u32,

    /// Percentile statistics (if benchmark completed successfully).
    pub percentiles: Option<Percentiles>,

    /// Whether this benchmark passed its target thresholds.
    pub passed: Option<bool>,

    /// Target thresholds for pass/fail determination.
    pub targets: Option<Targets>,

    /// Additional notes (e.g., "not yet implemented").
    pub note: Option<String>,

    /// Any outliers detected during measurement.
    pub outliers_detected: u32,
}

impl BenchmarkResult {
    /// Create a new benchmark result with the given measurements.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        sample_count: u32,
        warmup_count: u32,
        percentiles: Percentiles,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::Value::Object(serde_json::Map::new()),
            sample_count,
            warmup_count,
            percentiles: Some(percentiles),
            passed: None,
            targets: None,
            note: None,
            outliers_detected: 0,
        }
    }

    /// Create a placeholder result for unimplemented benchmarks.
    #[must_use]
    pub fn placeholder(name: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: "Not yet implemented".to_string(),
            parameters: serde_json::Value::Object(serde_json::Map::new()),
            sample_count: 0,
            warmup_count: 0,
            percentiles: None,
            passed: None,
            targets: None,
            note: Some(note.into()),
            outliers_detected: 0,
        }
    }

    /// Set parameters for this benchmark.
    #[must_use]
    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = parameters;
        self
    }

    /// Set target thresholds and determine pass/fail.
    #[must_use]
    pub fn with_targets(mut self, targets: Targets) -> Self {
        if let Some(ref p) = self.percentiles {
            self.passed =
                Some(p.p50_ms <= targets.p50_target_ms && p.p99_ms <= targets.p99_target_ms);
        }
        self.targets = Some(targets);
        self
    }
}

/// Percentile statistics for benchmark measurements.
///
/// All fields are in milliseconds. The `_ms` suffix is intentional to indicate units
/// in the JSON output schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct Percentiles {
    /// 50th percentile (median) in milliseconds.
    pub p50_ms: f64,

    /// 90th percentile in milliseconds.
    pub p90_ms: f64,

    /// 99th percentile in milliseconds.
    pub p99_ms: f64,

    /// Minimum measurement in milliseconds.
    pub min_ms: f64,

    /// Maximum measurement in milliseconds.
    pub max_ms: f64,

    /// Mean (average) in milliseconds.
    pub mean_ms: f64,

    /// Standard deviation in milliseconds.
    pub stddev_ms: f64,
}

/// Target thresholds for pass/fail determination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Targets {
    /// Target p50 latency in milliseconds.
    pub p50_target_ms: f64,

    /// Target p99 latency in milliseconds.
    pub p99_target_ms: f64,
}

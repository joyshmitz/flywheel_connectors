//! CBOR canonical serialization benchmarks.
//!
//! Microbenches for hot primitives in fcp-cbor:
//! - Schema hash computation
//! - Canonical CBOR serialization
//! - Canonical CBOR deserialization

use fcp_cbor::{CanonicalSerializer, SchemaId};
use semver::Version;
use serde::{Deserialize, Serialize};

use super::runner::run_benchmark_with_result;
use super::types::{BenchmarkResult, Targets};

/// CBOR benchmark targets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CborTarget {
    SchemaHash,
    Serialize,
    Deserialize,
    All,
}

impl From<super::CborTarget> for CborTarget {
    fn from(t: super::CborTarget) -> Self {
        match t {
            super::CborTarget::SchemaHash => Self::SchemaHash,
            super::CborTarget::Serialize => Self::Serialize,
            super::CborTarget::Deserialize => Self::Deserialize,
            super::CborTarget::All => Self::All,
        }
    }
}

/// Run CBOR benchmarks based on the specified target.
pub fn run_benchmarks(
    target: super::CborTarget,
    iterations: u32,
    warmup: u32,
) -> Vec<BenchmarkResult> {
    let target: CborTarget = target.into();
    let mut results = Vec::new();

    if target == CborTarget::SchemaHash || target == CborTarget::All {
        results.push(bench_schema_hash(iterations, warmup));
    }

    if target == CborTarget::Serialize || target == CborTarget::All {
        results.push(bench_serialize_small(iterations, warmup));
        results.push(bench_serialize_medium(iterations, warmup));
    }

    if target == CborTarget::Deserialize || target == CborTarget::All {
        results.push(bench_deserialize_small(iterations, warmup));
        results.push(bench_deserialize_medium(iterations, warmup));
    }

    results
}

/// Small test struct for serialization benchmarks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SmallObject {
    id: u64,
    name: String,
    active: bool,
}

/// Medium test struct for serialization benchmarks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MediumObject {
    id: u64,
    name: String,
    description: String,
    tags: Vec<String>,
    metadata: std::collections::HashMap<String, String>,
    created_at: i64,
    updated_at: i64,
    version: u32,
    active: bool,
}

fn make_test_schema() -> SchemaId {
    SchemaId::new("fcp.bench", "TestObject", Version::new(1, 0, 0))
}

fn make_small_object() -> SmallObject {
    SmallObject {
        id: 12345,
        name: "benchmark-test".to_string(),
        active: true,
    }
}

fn make_medium_object() -> MediumObject {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("key1".to_string(), "value1".to_string());
    metadata.insert("key2".to_string(), "value2".to_string());
    metadata.insert("key3".to_string(), "value3".to_string());

    MediumObject {
        id: 12345,
        name: "benchmark-test-medium".to_string(),
        description: "This is a medium-sized object for benchmarking canonical CBOR serialization performance. It includes multiple fields of varying types.".to_string(),
        tags: vec![
            "benchmark".to_string(),
            "cbor".to_string(),
            "serialization".to_string(),
            "performance".to_string(),
        ],
        metadata,
        created_at: 1_705_000_000,
        updated_at: 1_705_100_000,
        version: 42,
        active: true,
    }
}

fn bench_schema_hash(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || schema.hash());

    BenchmarkResult::new(
        "cbor-schema-hash",
        "Compute BLAKE3 schema hash from SchemaId",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "schema": format!("{}:{}@{}", schema.namespace, schema.name, schema.version),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.01, // 10 microseconds target.
        p99_target_ms: 0.1,  // 100 microseconds target.
    })
    .with_outliers(outliers)
}

fn bench_serialize_small(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_small_object();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-serialize-small",
        "Serialize small object to canonical CBOR with schema prefix",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "SmallObject",
        "fields": 3,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.05, // 50 microseconds target.
        p99_target_ms: 0.5,  // 500 microseconds target.
    })
    .with_outliers(outliers)
}

fn bench_serialize_medium(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_medium_object();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-serialize-medium",
        "Serialize medium object to canonical CBOR with schema prefix",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "MediumObject",
        "fields": 9,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.1, // 100 microseconds target.
        p99_target_ms: 1.0, // 1 millisecond target.
    })
    .with_outliers(outliers)
}

fn bench_deserialize_small(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_small_object();
    let bytes =
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::deserialize::<SmallObject>(&bytes, &schema)
            .expect("deserialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-deserialize-small",
        "Deserialize small object from canonical CBOR with schema verification",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "SmallObject",
        "fields": 3,
        "bytes": bytes.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.1, // 100 microseconds target.
        p99_target_ms: 1.0, // 1 millisecond target.
    })
    .with_outliers(outliers)
}

fn bench_deserialize_medium(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_medium_object();
    let bytes =
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::deserialize::<MediumObject>(&bytes, &schema)
            .expect("deserialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-deserialize-medium",
        "Deserialize medium object from canonical CBOR with schema verification",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "MediumObject",
        "fields": 9,
        "bytes": bytes.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.2, // 200 microseconds target.
        p99_target_ms: 2.0, // 2 milliseconds target.
    })
    .with_outliers(outliers)
}

trait BenchmarkResultExt {
    fn with_outliers(self, count: u32) -> Self;
}

impl BenchmarkResultExt for BenchmarkResult {
    fn with_outliers(mut self, count: u32) -> Self {
        self.outliers_detected = count;
        self
    }
}

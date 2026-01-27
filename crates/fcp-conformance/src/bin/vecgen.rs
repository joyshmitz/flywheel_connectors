//! Schema hash and canonical CBOR vector generator CLI.
//!
//! Generate deterministic golden vectors for FCP2 conformance testing.
//!
//! # Usage
//!
//! ```bash
//! # Generate all core schema vectors to default output
//! cargo run -p fcp-conformance --bin fcp-vecgen
//!
//! # Generate to specific directory
//! cargo run -p fcp-conformance --bin fcp-vecgen -- --out ./vectors
//!
//! # List available schemas
//! cargo run -p fcp-conformance --bin fcp-vecgen -- --list
//!
//! # Verify vectors against stored baseline (CI mode)
//! cargo run -p fcp-conformance --bin fcp-vecgen -- --verify --baseline tests/vectors/serialization/schema_hash_vectors.json
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use clap::Parser;
use fcp_conformance::vecgen::{
    GeneratedVector, PayloadVector, SchemaRegistration, core_schema_registrations,
    generate_schema_hash, serialize_to_canonical_cbor, write_vectors_to_file,
};
use serde::{Deserialize, Serialize};

/// FCP2 Schema Hash and Vector Generator.
///
/// Generates deterministic golden vectors for conformance testing.
/// Output is stable across runs and platforms.
#[derive(Parser, Debug)]
#[command(name = "fcp-vecgen")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output directory for generated vectors.
    #[arg(short, long, default_value = "generated_vectors")]
    out: PathBuf,

    /// List available schemas without generating.
    #[arg(long, default_value_t = false)]
    list: bool,

    /// Generate only the specified schema (namespace:name@version).
    #[arg(long)]
    schema: Option<String>,

    /// Output format (json or cbor).
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Verify existing vectors instead of generating.
    #[arg(long, default_value_t = false)]
    verify: bool,

    /// Path to baseline vectors file for verification (required with --verify).
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Output JSONL log file for structured CI output.
    #[arg(long)]
    log_jsonl: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Cbor,
}

/// Test struct matching the existing golden vector format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoldenStruct {
    id: u64,
    name: String,
    active: bool,
}

/// Minimal capability for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestCapability {
    id: String,
    zone: String,
    granted_at: String,
    expires_at: String,
}

/// Minimal object header for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestObjectHeader {
    schema_hash: String,
    zone_id: String,
    created_at: String,
}

/// A single difference found during verification.
#[derive(Debug, Clone, Serialize)]
struct VectorDiff {
    schema: String,
    field: String,
    expected: String,
    actual: String,
}

/// Verification result summary.
#[derive(Debug, Clone, Serialize)]
struct VerificationResult {
    passed: bool,
    schemas_checked: usize,
    schemas_matched: usize,
    schemas_missing: Vec<String>,
    schemas_extra: Vec<String>,
    diffs: Vec<VectorDiff>,
}

/// Structured log entry for E2E logging per `STANDARD_Testing_Logging.md`.
#[derive(Debug, Clone, Serialize)]
struct LogEntry {
    timestamp: String,
    level: String,
    test_name: String,
    module: String,
    phase: String,
    correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schemas_checked: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diffs_found: Option<usize>,
}

fn emit_log_entry(entry: &LogEntry, log_file: &mut Option<fs::File>) {
    let json = serde_json::to_string(entry).unwrap_or_default();
    if let Some(f) = log_file {
        use std::io::Write;
        let _ = writeln!(f, "{json}");
    }
    // Also emit to stderr for visibility
    eprintln!(
        "[{}] {}",
        entry.level.to_uppercase(),
        entry.message.as_deref().unwrap_or(&json)
    );
}

/// Verify generated vectors against a baseline file.
#[allow(clippy::too_many_lines)]
fn verify_vectors(
    baseline_path: &PathBuf,
    log_file: &mut Option<fs::File>,
    correlation_id: &str,
) -> Result<VerificationResult, String> {
    // Setup phase
    emit_log_entry(
        &LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: "info".into(),
            test_name: "schema_vector_verification".into(),
            module: "fcp-conformance".into(),
            phase: "setup".into(),
            correlation_id: correlation_id.into(),
            message: Some(format!("Loading baseline from {}", baseline_path.display())),
            result: None,
            schemas_checked: None,
            diffs_found: None,
        },
        log_file,
    );

    // Load baseline
    let baseline_content = fs::read_to_string(baseline_path)
        .map_err(|e| format!("Failed to read baseline file: {e}"))?;
    let baseline: BTreeMap<String, GeneratedVector> = serde_json::from_str(&baseline_content)
        .map_err(|e| format!("Failed to parse baseline JSON: {e}"))?;

    // Execute phase - generate fresh vectors
    emit_log_entry(
        &LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: "info".into(),
            test_name: "schema_vector_verification".into(),
            module: "fcp-conformance".into(),
            phase: "execute".into(),
            correlation_id: correlation_id.into(),
            message: Some("Regenerating vectors for comparison".into()),
            result: None,
            schemas_checked: None,
            diffs_found: None,
        },
        log_file,
    );

    let generated = generate_all_vectors();

    // Verify phase - compare
    let mut result = VerificationResult {
        passed: true,
        schemas_checked: 0,
        schemas_matched: 0,
        schemas_missing: vec![],
        schemas_extra: vec![],
        diffs: vec![],
    };

    // Check for missing schemas (in baseline but not generated)
    for key in baseline.keys() {
        if !generated.contains_key(key) {
            result.schemas_missing.push(key.clone());
            result.passed = false;
        }
    }

    // Check for extra schemas (generated but not in baseline)
    for key in generated.keys() {
        if !baseline.contains_key(key) {
            result.schemas_extra.push(key.clone());
            result.passed = false;
        }
    }

    // Compare matching schemas
    for (key, expected) in &baseline {
        if let Some(actual) = generated.get(key) {
            result.schemas_checked += 1;

            // Compare schema hash (positive branch first for clippy::if_not_else)
            if expected.expected_schema_hash == actual.expected_schema_hash {
                // Compare payloads only if schema hash matches
                let expected_payloads: BTreeMap<_, _> = expected
                    .payloads
                    .iter()
                    .map(|p| (&p.description, p))
                    .collect();
                let actual_payloads: BTreeMap<_, _> = actual
                    .payloads
                    .iter()
                    .map(|p| (&p.description, p))
                    .collect();

                for (desc, exp_payload) in &expected_payloads {
                    if let Some(act_payload) = actual_payloads.get(desc) {
                        if exp_payload.expected_cbor != act_payload.expected_cbor {
                            result.diffs.push(VectorDiff {
                                schema: key.clone(),
                                field: format!("payload[{desc}].cbor"),
                                expected: exp_payload.expected_cbor.clone(),
                                actual: act_payload.expected_cbor.clone(),
                            });
                            result.passed = false;
                        }
                        if exp_payload.expected_payload != act_payload.expected_payload {
                            result.diffs.push(VectorDiff {
                                schema: key.clone(),
                                field: format!("payload[{desc}].full_payload"),
                                expected: exp_payload.expected_payload.clone(),
                                actual: act_payload.expected_payload.clone(),
                            });
                            result.passed = false;
                        }
                    }
                }
                result.schemas_matched += 1;
            } else {
                // Schema hash mismatch
                result.diffs.push(VectorDiff {
                    schema: key.clone(),
                    field: "schema_hash".into(),
                    expected: expected.expected_schema_hash.clone(),
                    actual: actual.expected_schema_hash.clone(),
                });
                result.passed = false;
            }
        }
    }

    // Emit verification result log
    emit_log_entry(
        &LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: if result.passed { "info" } else { "error" }.into(),
            test_name: "schema_vector_verification".into(),
            module: "fcp-conformance".into(),
            phase: "verify".into(),
            correlation_id: correlation_id.into(),
            message: Some(if result.passed {
                "All vectors match baseline".into()
            } else {
                format!(
                    "Vector drift detected: {} diffs, {} missing, {} extra",
                    result.diffs.len(),
                    result.schemas_missing.len(),
                    result.schemas_extra.len()
                )
            }),
            result: Some(if result.passed { "pass" } else { "fail" }.into()),
            schemas_checked: Some(result.schemas_checked),
            diffs_found: Some(result.diffs.len()),
        },
        log_file,
    );

    Ok(result)
}

/// Generate sample data for each registered schema.
fn generate_samples_for_schema(
    reg: &SchemaRegistration,
) -> Option<Vec<(String, serde_json::Value)>> {
    let key = format!("{}:{}", reg.namespace, reg.name);

    match key.as_str() {
        "fcp.test:GoldenStruct" => {
            let samples = vec![
                (
                    "canonical basic".to_string(),
                    serde_json::to_value(GoldenStruct {
                        id: 12345,
                        name: "test".into(),
                        active: true,
                    })
                    .ok()?,
                ),
                (
                    "canonical with unicode".to_string(),
                    serde_json::to_value(GoldenStruct {
                        id: 99999,
                        name: "hello\u{1F600}world".into(),
                        active: false,
                    })
                    .ok()?,
                ),
                (
                    "canonical edge case".to_string(),
                    serde_json::to_value(GoldenStruct {
                        id: 0,
                        name: String::new(),
                        active: false,
                    })
                    .ok()?,
                ),
            ];
            Some(samples)
        }
        "fcp.core:CapabilityObject" => {
            let samples = vec![(
                "basic capability".to_string(),
                serde_json::to_value(TestCapability {
                    id: "cap-001".into(),
                    zone: "z:work".into(),
                    granted_at: "2026-01-01T00:00:00Z".into(),
                    expires_at: "2026-12-31T23:59:59Z".into(),
                })
                .ok()?,
            )];
            Some(samples)
        }
        "fcp.core:ObjectHeader" => {
            let samples = vec![(
                "basic header".to_string(),
                serde_json::to_value(TestObjectHeader {
                    schema_hash: "0".repeat(64),
                    zone_id: "z:work".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                })
                .ok()?,
            )];
            Some(samples)
        }
        _ => None, // No samples for other schemas yet
    }
}

/// Generate vectors for all core schemas.
fn generate_all_vectors() -> BTreeMap<String, GeneratedVector> {
    let mut vectors = BTreeMap::new();

    for reg in core_schema_registrations() {
        let key = format!("{}:{}@{}", reg.namespace, reg.name, reg.version);

        if let Some(samples) = generate_samples_for_schema(&reg) {
            let schema = reg.schema_id();
            let schema_hash = generate_schema_hash(&schema);

            let mut payloads = Vec::new();
            for (desc, value) in samples {
                // Serialize the JSON value to canonical CBOR
                if let Ok((cbor_hex, payload_hex)) = serialize_to_canonical_cbor(&value, &schema) {
                    payloads.push(PayloadVector {
                        description: desc,
                        input_json: value,
                        expected_cbor: cbor_hex,
                        expected_payload: payload_hex,
                    });
                }
            }

            if !payloads.is_empty() {
                vectors.insert(
                    key,
                    GeneratedVector {
                        description: reg.description.clone(),
                        schema_namespace: reg.namespace.clone(),
                        schema_name: reg.name.clone(),
                        schema_version: reg.version.to_string(),
                        expected_schema_hash: schema_hash,
                        payloads,
                    },
                );
            }
        } else {
            // Generate schema hash only vector (no payloads)
            let schema = reg.schema_id();
            let schema_hash = generate_schema_hash(&schema);
            vectors.insert(
                key,
                GeneratedVector {
                    description: reg.description.clone(),
                    schema_namespace: reg.namespace.clone(),
                    schema_name: reg.name.clone(),
                    schema_version: reg.version.to_string(),
                    expected_schema_hash: schema_hash,
                    payloads: vec![],
                },
            );
        }
    }

    vectors
}

#[allow(clippy::too_many_lines)]
fn main() {
    let args = Args::parse();

    if args.list {
        println!("Available schemas:");
        println!();
        for reg in core_schema_registrations() {
            let schema = reg.schema_id();
            let hash = generate_schema_hash(&schema);
            println!("  {}:{}@{}", reg.namespace, reg.name, reg.version);
            println!("    Hash: {hash}");
            println!("    Description: {}", reg.description);
            println!();
        }
        return;
    }

    if args.verify {
        let baseline_path = args.baseline.as_ref().unwrap_or_else(|| {
            eprintln!("Error: --baseline is required with --verify");
            std::process::exit(1);
        });

        // Open log file if specified
        let mut log_file = args.log_jsonl.as_ref().and_then(|p| {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::File::create(p).ok()
        });

        // Generate correlation ID
        let correlation_id = format!(
            "vecgen-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        );

        match verify_vectors(baseline_path, &mut log_file, &correlation_id) {
            Ok(result) => {
                // Output JSON diff summary to stdout for CI artifact capture
                if !result.diffs.is_empty()
                    || !result.schemas_missing.is_empty()
                    || !result.schemas_extra.is_empty()
                {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_default()
                    );
                }

                if result.passed {
                    eprintln!(
                        "✓ All {} schemas verified successfully",
                        result.schemas_checked
                    );
                    std::process::exit(0);
                } else {
                    eprintln!("✗ Verification failed:");
                    if !result.schemas_missing.is_empty() {
                        eprintln!("  Missing schemas: {:?}", result.schemas_missing);
                    }
                    if !result.schemas_extra.is_empty() {
                        eprintln!("  Extra schemas: {:?}", result.schemas_extra);
                    }
                    for diff in &result.diffs {
                        eprintln!(
                            "  {}.{}: expected {} != actual {}",
                            diff.schema,
                            diff.field,
                            &diff.expected[..diff.expected.len().min(32)],
                            &diff.actual[..diff.actual.len().min(32)]
                        );
                    }
                    eprintln!("\nTo update baseline, run:");
                    eprintln!(
                        "  cargo run -p fcp-conformance --bin fcp-vecgen -- --out tests/vectors/serialization"
                    );
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error during verification: {e}");
                std::process::exit(1);
            }
        }
    }

    // Generate vectors
    eprintln!("Generating schema vectors...");
    let vectors = generate_all_vectors();

    // Write output
    let output_file = args.out.join("core_vectors.json");
    match write_vectors_to_file(&vectors, &output_file) {
        Ok(()) => {
            eprintln!(
                "Wrote {} vectors to {}",
                vectors.len(),
                output_file.display()
            );

            // Print summary
            for (key, vector) in &vectors {
                eprintln!(
                    "  {key}: {} payloads, hash={}",
                    vector.payloads.len(),
                    &vector.expected_schema_hash[..16]
                );
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    eprintln!("Done.");
}

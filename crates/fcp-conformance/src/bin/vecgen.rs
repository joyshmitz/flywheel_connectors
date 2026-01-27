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
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

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
        eprintln!("Verification mode not yet implemented");
        std::process::exit(1);
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

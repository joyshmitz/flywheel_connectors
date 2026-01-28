//! Requirements index validation CLI (bd-355n).
//!
//! Parses `docs/STANDARD_Requirements_Index.md` and validates that all referenced
//! bead IDs exist in the project's beads database.
//!
//! # Usage
//!
//! ```bash
//! # Validate requirements index using br list
//! cargo run -p fcp-conformance --bin fcp-reqcheck
//!
//! # Validate using a JSONL export
//! cargo run -p fcp-conformance --bin fcp-reqcheck -- --beads .beads/issues.jsonl
//!
//! # Specify custom requirements file
//! cargo run -p fcp-conformance --bin fcp-reqcheck -- --index docs/STANDARD_Requirements_Index.md
//!
//! # Output JSON report
//! cargo run -p fcp-conformance --bin fcp-reqcheck -- --json
//! ```

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use chrono::Utc;
use clap::Parser;
use fcp_conformance::reqcheck::{
    RequirementsIndexParser, load_beads_from_br_list, load_beads_from_jsonl,
};
use serde_json::json;

/// FCP2 Requirements Index Validator.
///
/// Validates that all bead IDs referenced in the requirements index exist.
#[derive(Parser, Debug)]
#[command(name = "fcp-reqcheck")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the requirements index markdown file.
    #[arg(
        short,
        long,
        default_value = "docs/STANDARD_Requirements_Index.md"
    )]
    index: PathBuf,

    /// Path to beads JSONL export file (alternative to br list).
    #[arg(long)]
    beads: Option<PathBuf>,

    /// Output JSON report.
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Include parsed entries in JSON output.
    #[arg(long, default_value_t = false)]
    include_entries: bool,

    /// Treat warnings as errors.
    #[arg(long, default_value_t = false)]
    strict: bool,

    /// Output JSONL log file for structured CI output.
    #[arg(long)]
    log_jsonl: Option<PathBuf>,
}

#[allow(clippy::too_many_lines)]
fn main() -> ExitCode {
    let args = Args::parse();

    // Load known beads
    let known_beads: HashSet<String> = match &args.beads {
        Some(path) => {
            match load_beads_from_jsonl(path) {
                Ok(beads) => beads,
                Err(e) => {
                    eprintln!("Error loading beads from {}: {e}", path.display());
                    return ExitCode::from(2);
                }
            }
        }
        None => {
            match load_beads_from_br_list() {
                Ok(beads) => beads,
                Err(e) => {
                    eprintln!("Error running br list: {e}");
                    eprintln!("Hint: Use --beads <path> to specify a JSONL export file");
                    return ExitCode::from(2);
                }
            }
        }
    };

    if !args.json {
        eprintln!(
            "Loaded {} beads from {}",
            known_beads.len(),
            args.beads
                .as_ref()
                .map_or_else(|| "br list".to_string(), |p| p.display().to_string())
        );
    }

    // Parse requirements index
    let mut parser = RequirementsIndexParser::new();
    if let Err(e) = parser.parse_file(&args.index) {
        eprintln!("Error parsing {}: {e}", args.index.display());
        return ExitCode::from(2);
    }

    // Validate
    let mut report = parser.validate(&known_beads);

    if args.include_entries {
        report.entries = Some(parser.entries().to_vec());
    }

    // Determine exit status
    let has_errors = !report.errors.is_empty();
    let has_warnings = !report.warnings.is_empty();
    let failed = has_errors || (args.strict && has_warnings);

    // Output report
    if args.json {
        let output = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "index_path": args.index.display().to_string(),
            "beads_source": args.beads.as_ref().map_or("br list", |_| "jsonl"),
            "known_beads_count": known_beads.len(),
            "valid": report.is_valid(),
            "report": report
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        // Human-readable output
        println!("\nRequirements Index Validation Report");
        println!("=====================================");
        println!("Index: {}", args.index.display());
        println!("Entries parsed: {}", report.total_entries);
        println!("Unique bead references: {}", report.unique_beads);
        println!("Known beads: {}", known_beads.len());
        println!();

        if report.errors.is_empty() {
            println!("OK: No errors found.");
        } else {
            println!("ERRORS ({}):", report.errors.len());
            for err in &report.errors {
                println!(
                    "  [{}:{}] {}: {}",
                    err.section,
                    err.line_number.map_or_else(|| "?".to_string(), |n| n.to_string()),
                    err.error_type,
                    err.message
                );
            }
        }

        if !report.warnings.is_empty() {
            println!("\nWARNINGS ({}):", report.warnings.len());
            for warn in &report.warnings {
                println!(
                    "  [{}:{}] {}: {}",
                    warn.section,
                    warn.line_number.map_or_else(|| "?".to_string(), |n| n.to_string()),
                    warn.warning_type,
                    warn.message
                );
            }
        }

        if !report.missing_beads.is_empty() {
            println!("\nMISSING BEADS ({}):", report.missing_beads.len());
            for bead in &report.missing_beads {
                println!("  - {bead}");
            }
        }

        println!();
        if failed {
            println!("FAILED: Validation did not pass.");
        } else {
            println!("PASSED: All referenced beads exist.");
        }
    }

    // Write JSONL log if requested
    if let Some(log_path) = &args.log_jsonl {
        let log_entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "tool": "fcp-reqcheck",
            "phase": "verify",
            "result": if failed { "fail" } else { "pass" },
            "details": {
                "index_path": args.index.display().to_string(),
                "entries_parsed": report.total_entries,
                "unique_beads": report.unique_beads,
                "errors": report.errors.len(),
                "warnings": report.warnings.len(),
                "missing_beads": report.missing_beads.len()
            }
        });
        if let Err(e) = std::fs::write(log_path, format!("{log_entry}\n")) {
            eprintln!("Warning: Could not write log file: {e}");
        }
    }

    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

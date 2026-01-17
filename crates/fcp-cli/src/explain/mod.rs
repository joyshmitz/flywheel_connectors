//! `fcp explain` command implementation.
//!
//! Renders the mechanical evidence behind an allow/deny decision by loading
//! and displaying the `DecisionReceipt` for a given request object ID.
//!
//! # Usage
//!
//! ```text
//! # Human-readable output
//! fcp explain --request <object-id>
//!
//! # JSON output for tooling
//! fcp explain --request <object-id> --json
//! ```

pub mod types;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Args;

use types::{
    DecisionOutcome, EvidenceItem, EvidenceType, ExplainError, ExplainReport, SignerInfo,
    reason_code_description,
};

/// Arguments for the `fcp explain` command.
#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// Request object ID to explain (hex-encoded, 64 characters).
    #[arg(long, short = 'r')]
    pub request: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Zone to query (defaults to local zone).
    #[arg(long, short = 'z')]
    pub zone: Option<String>,
}

/// Run the explain command.
///
/// # Errors
///
/// Returns an error if the decision receipt cannot be loaded or rendered.
pub fn run(args: &ExplainArgs) -> Result<()> {
    // Validate object ID format
    if let Err(e) = validate_object_id(&args.request) {
        let error = ExplainError::invalid_object_id(&args.request, &e);
        return output_error(&error, args.json);
    }

    // TODO: In a full implementation, this would load the DecisionReceipt from
    // the object store. For now, we demonstrate the output format with a
    // simulated lookup that returns "not found" or a demo receipt.
    //
    // Full implementation would:
    // 1. Connect to the mesh node for the specified zone
    // 2. Query the object store for a DecisionReceipt with request_object_id == args.request
    // 3. If found, render it; if not found, return ExplainError::receipt_not_found

    // For demonstration, check if this is a known test object ID
    match load_decision_receipt(&args.request, args.zone.as_deref()) {
        Ok(report) => output_report(&report, args.json),
        Err(error) => output_error(&error, args.json),
    }
}

/// Validate an object ID string.
fn validate_object_id(id: &str) -> Result<(), String> {
    // Object IDs are 32 bytes = 64 hex characters
    if id.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", id.len()));
    }

    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("contains non-hexadecimal characters".to_string());
    }

    Ok(())
}

/// Load a decision receipt (stub implementation).
///
/// In a full implementation, this would query the object store.
fn load_decision_receipt(
    request_id: &str,
    _zone: Option<&str>,
) -> Result<ExplainReport, ExplainError> {
    // Stub: Return demo data for specific test IDs, otherwise "not found"
    //
    // Test IDs for demonstration:
    // - "0000...0001" (64 chars with trailing 1) -> Allow receipt
    // - "0000...0002" (64 chars with trailing 2) -> Deny receipt (revoked)
    // - "0000...0003" (64 chars with trailing 3) -> Deny receipt (zone violation)
    // - anything else -> not found

    let suffix = &request_id[60..]; // Last 4 chars

    match suffix {
        "0001" => Ok(create_demo_allow_receipt(request_id)),
        "0002" => Ok(create_demo_deny_revoked_receipt(request_id)),
        "0003" => Ok(create_demo_deny_zone_violation_receipt(request_id)),
        _ => Err(ExplainError::receipt_not_found(request_id)),
    }
}

fn create_demo_allow_receipt(request_id: &str) -> ExplainReport {
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.to_string(),
        decision: DecisionOutcome::Allow,
        reason_code: "FCP-0000".to_string(),
        reason_description: reason_code_description("FCP-0000").to_string(),
        evidence: vec![
            EvidenceItem {
                object_id: "a".repeat(64),
                evidence_type: EvidenceType::CapabilityToken,
                description: "Valid capability token with required permissions".to_string(),
            },
            EvidenceItem {
                object_id: "b".repeat(64),
                evidence_type: EvidenceType::ZoneCheckpoint,
                description: "Current zone checkpoint (seq=42)".to_string(),
            },
        ],
        explanation: None,
        zone_id: "z:work".to_string(),
        signed_by: SignerInfo {
            node_id: "node-mesh-1".to_string(),
            signed_at: current_timestamp(),
        },
    }
}

/// Get the current Unix timestamp.
#[allow(clippy::cast_sign_loss)] // Timestamps after 1970 are positive
fn current_timestamp() -> u64 {
    Utc::now().timestamp() as u64
}

fn create_demo_deny_revoked_receipt(request_id: &str) -> ExplainReport {
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.to_string(),
        decision: DecisionOutcome::Deny,
        reason_code: "FCP-4030".to_string(),
        reason_description: reason_code_description("FCP-4030").to_string(),
        evidence: vec![
            EvidenceItem {
                object_id: "c".repeat(64),
                evidence_type: EvidenceType::CapabilityToken,
                description: "Capability token (jti: 550e8400-e29b-41d4-a716-446655440000)"
                    .to_string(),
            },
            EvidenceItem {
                object_id: "d".repeat(64),
                evidence_type: EvidenceType::Revocation,
                description: "Revocation entry added at epoch 37".to_string(),
            },
        ],
        explanation: Some(
            "Token was revoked by zone administrator due to credential rotation".to_string(),
        ),
        zone_id: "z:work".to_string(),
        signed_by: SignerInfo {
            node_id: "node-mesh-1".to_string(),
            signed_at: current_timestamp(),
        },
    }
}

fn create_demo_deny_zone_violation_receipt(request_id: &str) -> ExplainReport {
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.to_string(),
        decision: DecisionOutcome::Deny,
        reason_code: "FCP-4001".to_string(),
        reason_description: reason_code_description("FCP-4001").to_string(),
        evidence: vec![
            EvidenceItem {
                object_id: "e".repeat(64),
                evidence_type: EvidenceType::Request,
                description: "Request originated from zone z:external".to_string(),
            },
            EvidenceItem {
                object_id: "f".repeat(64),
                evidence_type: EvidenceType::Policy,
                description: "Zone policy denies access from z:external to z:sensitive".to_string(),
            },
        ],
        explanation: Some(
            "Cross-zone access denied: z:external cannot invoke operations in z:sensitive"
                .to_string(),
        ),
        zone_id: "z:sensitive".to_string(),
        signed_by: SignerInfo {
            node_id: "node-mesh-2".to_string(),
            signed_at: current_timestamp(),
        },
    }
}

/// Output the explain report.
fn output_report(report: &ExplainReport, json: bool) -> Result<()> {
    if json {
        let output =
            serde_json::to_string_pretty(report).context("failed to serialize report to JSON")?;
        println!("{output}");
    } else {
        print_human_readable(report);
    }
    Ok(())
}

/// Output an error.
fn output_error(error: &ExplainError, json: bool) -> Result<()> {
    if json {
        let output =
            serde_json::to_string_pretty(error).context("failed to serialize error to JSON")?;
        println!("{output}");
        // Return Ok since we successfully output the error as JSON
        // (this allows scripting to parse the error)
        Ok(())
    } else {
        print_human_error(error);
        // Return an error for non-JSON mode to signal failure to callers
        anyhow::bail!("{}: {}", error.code, error.message)
    }
}

/// Print human-readable report to stdout.
fn print_human_readable(report: &ExplainReport) {
    let reset = DecisionOutcome::ansi_reset();

    // Header
    println!();
    println!("Decision Explanation");
    println!("====================");
    println!();

    // Decision with color
    let color = report.decision.ansi_color();
    let symbol = report.decision.symbol();
    let decision_str = match report.decision {
        DecisionOutcome::Allow => "ALLOW",
        DecisionOutcome::Deny => "DENY",
    };
    println!("Decision:     {color}{symbol} {decision_str}{reset}");
    println!("Reason Code:  {}", report.reason_code);
    println!("Reason:       {}", report.reason_description);
    println!();

    // Request info
    println!("Request:      {}", truncate_id(&report.request_object_id));
    println!("Zone:         {}", report.zone_id);
    println!();

    // Explanation (if present)
    if let Some(ref explanation) = report.explanation {
        println!("Explanation:");
        for line in textwrap::wrap(explanation, 70) {
            println!("  {line}");
        }
        println!();
    }

    // Evidence
    if !report.evidence.is_empty() {
        println!("Evidence ({} items):", report.evidence.len());
        println!();
        for (i, item) in report.evidence.iter().enumerate() {
            println!(
                "  {}. {} ({})",
                i + 1,
                item.evidence_type.label(),
                truncate_id(&item.object_id)
            );
            println!("     {}", item.description);
        }
        println!();
    }

    // Signature info
    #[allow(clippy::cast_possible_wrap)] // Timestamps fit in i64 until year 292 billion
    let signed_at_i64 = report.signed_by.signed_at as i64;
    let signed_at_str = chrono::DateTime::from_timestamp(signed_at_i64, 0).map_or_else(
        || report.signed_by.signed_at.to_string(),
        |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );
    println!(
        "Signed by:    {} at {}",
        report.signed_by.node_id, signed_at_str
    );
    println!();
}

/// Print human-readable error to stderr.
fn print_human_error(error: &ExplainError) {
    eprintln!();
    eprintln!("\x1b[31mError: {}\x1b[0m", error.code);
    eprintln!("{}", error.message);

    if !error.hints.is_empty() {
        eprintln!();
        eprintln!("Hints:");
        for hint in &error.hints {
            eprintln!("  - {hint}");
        }
    }
    eprintln!();
}

/// Truncate a hex ID for display (show first 8 and last 8 chars).
fn truncate_id(id: &str) -> String {
    if id.len() <= 20 {
        id.to_string()
    } else {
        format!("{}...{}", &id[..8], &id[id.len() - 8..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_object_id_valid() {
        let valid_id = "a".repeat(64);
        assert!(validate_object_id(&valid_id).is_ok());
    }

    #[test]
    fn validate_object_id_too_short() {
        let short_id = "abc123";
        let result = validate_object_id(short_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 64"));
    }

    #[test]
    fn validate_object_id_non_hex() {
        let bad_id = "g".repeat(64); // 'g' is not hex
        let result = validate_object_id(&bad_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-hexadecimal"));
    }

    #[test]
    fn truncate_id_short() {
        assert_eq!(truncate_id("abc123"), "abc123");
    }

    #[test]
    fn truncate_id_long() {
        let long_id = "a".repeat(64);
        let truncated = truncate_id(&long_id);
        assert_eq!(truncated, "aaaaaaaa...aaaaaaaa");
    }

    #[test]
    fn load_demo_allow_receipt() {
        let request_id = format!("{}0001", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.decision, DecisionOutcome::Allow);
        assert_eq!(report.reason_code, "FCP-0000");
    }

    #[test]
    fn load_demo_deny_revoked_receipt() {
        let request_id = format!("{}0002", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.decision, DecisionOutcome::Deny);
        assert_eq!(report.reason_code, "FCP-4030");
    }

    #[test]
    fn load_demo_deny_zone_violation_receipt() {
        let request_id = format!("{}0003", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.decision, DecisionOutcome::Deny);
        assert_eq!(report.reason_code, "FCP-4001");
    }

    #[test]
    fn load_receipt_not_found() {
        let request_id = format!("{}9999", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, "FCP-6001");
    }
}

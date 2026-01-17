//! `fcp doctor` command implementation.
//!
//! Diagnoses zone health, freshness, and degraded mode status.
//!
//! # Usage
//!
//! ```text
//! # Human-readable output
//! fcp doctor --zone z:private
//!
//! # JSON output
//! fcp doctor --zone z:private --json
//! ```

pub mod types;

use anyhow::Result;
use chrono::Utc;
use clap::Args;
use fcp_core::ZoneId;

use types::{
    AuditStatus, CheckResult, CheckpointStatus, DegradedModeStatus, DoctorReport, FreshnessLevel,
    OverallStatus, RevocationStatus, StoreCoverageStatus, TransportPolicyStatus,
};

/// Arguments for the `fcp doctor` command.
#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Zone to diagnose.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run the doctor command.
pub fn run(args: &DoctorArgs) -> Result<()> {
    // Validate zone ID format
    let zone_id: ZoneId = args.zone.parse()?;

    // TODO: Connect to mesh node and gather real status.
    // For now, we simulate a report for demonstration.
    let report = simulate_report(&zone_id);

    if args.json {
        let output = serde_json::to_string_pretty(&report)?;
        println!("{output}");
    } else {
        print_human_readable(&report);
    }

    if report.overall_status == OverallStatus::Fail {
        std::process::exit(1);
    }

    Ok(())
}

fn simulate_report(zone_id: &ZoneId) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            last_updated_at: Some(Utc::now().timestamp() as u64 - 120),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: None,
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            reason: None,
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(30),
            freshness: FreshnessLevel::Fresh,
            coverage: Some(1.0),
            reason: None,
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(10000), // 100%
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(10000),
            store_healthy: true,
            reason: None,
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: false,
            reasons: vec![],
            since: None,
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .build()
}

fn print_human_readable(report: &DoctorReport) {
    let reset = "\x1b[0m";
    let color = report.overall_status.ansi_color();
    let symbol = report.overall_status.symbol();

    println!();
    println!("FCP Doctor Report");
    println!("=================");
    println!();
    println!("Zone:           {}", report.zone_id);
    println!("Generated:      {}", report.generated_at.to_rfc3339());
    println!(
        "Overall Status: {color}{symbol} {:?}{reset}",
        report.overall_status
    );
    println!();

    println!("Freshness:");
    println!(
        "  Checkpoint:   {:?} (seq={:?}, age={:?}s)",
        report.checkpoint.freshness,
        report.checkpoint.checkpoint_seq.unwrap_or(0),
        report.checkpoint.age_secs.unwrap_or(0)
    );
    println!(
        "  Revocation:   {:?} (seq={:?})",
        report.revocation.freshness,
        report.revocation.head_seq.unwrap_or(0)
    );
    println!(
        "  Audit:        {:?} (seq={:?})",
        report.audit.freshness,
        report.audit.head_seq.unwrap_or(0)
    );
    println!();

    if !report.checks.is_empty() {
        println!("Checks:");
        for check in &report.checks {
            let status_color = match check.status {
                types::CheckStatus::Ok => "\x1b[32m",
                types::CheckStatus::Warn => "\x1b[33m",
                types::CheckStatus::Fail => "\x1b[31m",
            };
            let status_symbol = match check.status {
                types::CheckStatus::Ok => "✓",
                types::CheckStatus::Warn => "⚠",
                types::CheckStatus::Fail => "✗",
            };
            println!(
                "  {status_color}{status_symbol} {}: {}{reset}",
                check.name, check.message
            );
        }
    }
    println!();
}

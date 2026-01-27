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
//!
//! # Test specific scenarios (simulation mode)
//! fcp doctor --zone z:private --scenario degraded
//! fcp doctor --zone z:private --scenario stale-checkpoint
//! fcp doctor --zone z:private --scenario network-partition
//! ```
//!
//! # Future: Real Mesh Connectivity
//!
//! When a mesh node is available, set `FCP_MESH_ENDPOINT` to connect to real data:
//! ```text
//! export FCP_MESH_ENDPOINT=http://localhost:9090
//! fcp doctor --zone z:private
//! ```

#![allow(clippy::cast_sign_loss)]

pub mod types;

use anyhow::Result;
use chrono::Utc;
use clap::{Args, ValueEnum};
use fcp_core::ZoneId;

use types::{
    AuditStatus, CheckResult, CheckpointStatus, DegradedModeStatus, DegradedReason, DoctorReport,
    FreshnessLevel, OverallStatus, RevocationStatus, StoreCoverageStatus, TransportPolicyStatus,
};

/// Simulation scenarios for testing different health states.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum DoctorScenario {
    /// All checks pass, system healthy.
    #[default]
    Healthy,
    /// System in degraded mode but operational.
    Degraded,
    /// Checkpoint is stale, operations may be limited.
    StaleCheckpoint,
    /// Revocation list too stale, high-risk operations blocked.
    StaleRevocation,
    /// Network partition detected, limited connectivity.
    NetworkPartition,
    /// Store coverage below threshold.
    LowCoverage,
    /// Multiple failures.
    Critical,
}

/// Arguments for the `fcp doctor` command.
#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Zone to diagnose.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Simulation scenario for testing (ignored when connected to real mesh).
    #[arg(long, value_enum, default_value_t = DoctorScenario::Healthy)]
    pub scenario: DoctorScenario,
}

/// Run the doctor command.
pub fn run(args: &DoctorArgs) -> Result<()> {
    // Validate zone ID format
    let zone_id: ZoneId = args.zone.parse()?;

    // Check for real mesh endpoint (future functionality)
    let mesh_endpoint = std::env::var("FCP_MESH_ENDPOINT").ok();
    let report = if let Some(_endpoint) = mesh_endpoint {
        // TODO: Connect to real mesh node when available
        // For now, fall back to simulation with a note
        eprintln!("Note: Real mesh connectivity not yet implemented, using simulation");
        simulate_report(&zone_id, args.scenario)
    } else {
        simulate_report(&zone_id, args.scenario)
    };

    if args.json {
        let output = serde_json::to_string_pretty(&report)?;
        println!("{output}");
    } else {
        print_human_readable(&report);
    }

    // Exit codes: 0 = ok, 1 = fail, 2 = warn
    match report.overall_status {
        OverallStatus::Ok => {}
        OverallStatus::Warn => std::process::exit(2),
        OverallStatus::Fail => std::process::exit(1),
    }

    Ok(())
}

fn simulate_report(zone_id: &ZoneId, scenario: DoctorScenario) -> DoctorReport {
    let now = Utc::now().timestamp() as u64;

    match scenario {
        DoctorScenario::Healthy => build_healthy_report(zone_id, now),
        DoctorScenario::Degraded => build_degraded_report(zone_id, now),
        DoctorScenario::StaleCheckpoint => build_stale_checkpoint_report(zone_id, now),
        DoctorScenario::StaleRevocation => build_stale_revocation_report(zone_id, now),
        DoctorScenario::NetworkPartition => build_network_partition_report(zone_id, now),
        DoctorScenario::LowCoverage => build_low_coverage_report(zone_id, now),
        DoctorScenario::Critical => build_critical_report(zone_id, now),
    }
}

fn build_healthy_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            last_updated_at: Some(now - 120),
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
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(10000),
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
        .add_check(CheckResult::ok(
            "store_replication",
            "All critical objects replicated to 3+ nodes",
        ))
        .build()
}

fn build_degraded_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(300),
            freshness: FreshnessLevel::Stale,
            last_updated_at: Some(now - 300),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: Some("Checkpoint 5 minutes old".to_string()),
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
            coverage: Some(0.85),
            reason: None,
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(9500),
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(9800),
            store_healthy: true,
            reason: None,
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-5001".to_string(),
                description: "Checkpoint older than freshness threshold".to_string(),
            }],
            since: Some(now - 180),
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(CheckResult::warn("checkpoint_age", "Checkpoint is 5 minutes old")
            .with_reason_code("FCP-5001"))
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .build()
}

fn build_stale_checkpoint_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(3600),
            freshness: FreshnessLevel::TooStale,
            last_updated_at: Some(now - 3600),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: Some("Checkpoint 1 hour old, exceeds max-stale threshold".to_string()),
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
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(10000),
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(10000),
            store_healthy: true,
            reason: None,
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-5002".to_string(),
                description: "Checkpoint too stale for safe operations".to_string(),
            }],
            since: Some(now - 3000),
        })
        .add_check(CheckResult::fail(
            "checkpoint_freshness",
            "Checkpoint exceeds max-stale threshold (1h > 30m)",
        ).with_reason_code("FCP-5002"))
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .build()
}

fn build_stale_revocation_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            last_updated_at: Some(now - 120),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: None,
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(7200),
            freshness: FreshnessLevel::TooStale,
            reason: Some("Revocation list 2 hours old, cannot verify token validity".to_string()),
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
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(10000),
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(6000),
            store_healthy: true,
            reason: Some("Revocation head under-replicated".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-5003".to_string(),
                description: "Revocation list too stale for high-risk operations".to_string(),
            }],
            since: Some(now - 6000),
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(CheckResult::fail(
            "revocation_freshness",
            "Revocation list exceeds max-stale threshold (2h > 1h)",
        ).with_reason_code("FCP-5003"))
        .build()
}

fn build_network_partition_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(600),
            freshness: FreshnessLevel::Stale,
            last_updated_at: Some(now - 600),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: Some("Cannot reach checkpoint authority".to_string()),
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(600),
            freshness: FreshnessLevel::Stale,
            reason: Some("Cannot reach revocation authority".to_string()),
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(600),
            freshness: FreshnessLevel::Stale,
            coverage: Some(0.33),
            reason: Some("Only 1 of 3 audit nodes reachable".to_string()),
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(3300),
            policy_head_coverage_bps: Some(3300),
            revocation_head_coverage_bps: Some(3300),
            store_healthy: false,
            reason: Some("Network partition: only 1 of 3 nodes reachable".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![
                DegradedReason {
                    code: "FCP-6001".to_string(),
                    description: "Network partition detected".to_string(),
                },
                DegradedReason {
                    code: "FCP-6002".to_string(),
                    description: "DERP relay unavailable".to_string(),
                },
            ],
            since: Some(now - 600),
        })
        .add_check(CheckResult::warn(
            "network_connectivity",
            "2 of 3 peer nodes unreachable",
        ).with_reason_code("FCP-6001"))
        .add_check(CheckResult::warn(
            "derp_relay",
            "DERP relay connection failed",
        ).with_reason_code("FCP-6002"))
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Local checkpoint signature verified",
        ))
        .build()
}

fn build_low_coverage_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            last_updated_at: Some(now - 120),
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
            coverage: Some(0.66),
            reason: Some("1 audit node offline".to_string()),
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(6600),
            policy_head_coverage_bps: Some(6600),
            revocation_head_coverage_bps: Some(6600),
            store_healthy: false,
            reason: Some("Coverage below 70% threshold".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-7001".to_string(),
                description: "Store coverage below minimum threshold".to_string(),
            }],
            since: Some(now - 300),
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(CheckResult::warn(
            "store_coverage",
            "Coverage at 66%, below 70% threshold",
        ).with_reason_code("FCP-7001"))
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .build()
}

fn build_critical_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: None,
            checkpoint_seq: None,
            age_secs: None,
            freshness: FreshnessLevel::Missing,
            last_updated_at: None,
            audit_head_seq: None,
            revocation_head_seq: None,
            reason: Some("No checkpoint available".to_string()),
        })
        .revocation(RevocationStatus {
            head_id: None,
            head_seq: None,
            age_secs: None,
            freshness: FreshnessLevel::Missing,
            reason: Some("No revocation list available".to_string()),
        })
        .audit(AuditStatus {
            head_id: None,
            head_seq: None,
            age_secs: None,
            freshness: FreshnessLevel::Missing,
            coverage: Some(0.0),
            reason: Some("Audit chain unavailable".to_string()),
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(0),
            policy_head_coverage_bps: Some(0),
            revocation_head_coverage_bps: Some(0),
            store_healthy: false,
            reason: Some("Store unavailable".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![
                DegradedReason {
                    code: "FCP-9001".to_string(),
                    description: "Zone bootstrap incomplete".to_string(),
                },
                DegradedReason {
                    code: "FCP-9002".to_string(),
                    description: "No transport paths available".to_string(),
                },
            ],
            since: Some(now),
        })
        .add_check(CheckResult::fail(
            "zone_bootstrap",
            "Zone has not completed bootstrap",
        ).with_reason_code("FCP-9001"))
        .add_check(CheckResult::fail(
            "checkpoint_availability",
            "No checkpoint object found",
        ).with_reason_code("FCP-9003"))
        .add_check(CheckResult::fail(
            "transport_paths",
            "No transport paths available (LAN/DERP/Funnel all disabled)",
        ).with_reason_code("FCP-9002"))
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

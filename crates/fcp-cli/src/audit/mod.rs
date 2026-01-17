//! `fcp audit` command implementation.
//!
//! Provides audit chain operations for incident response and debugging.
//!
//! # Commands
//!
//! ## `fcp audit tail`
//!
//! Stream audit events from a zone's audit chain with optional filtering.
//!
//! ```text
//! # Tail all events in a zone
//! fcp audit tail --zone z:work
//!
//! # Filter by connector
//! fcp audit tail --zone z:work --connector fcp.telegram:base:v1
//!
//! # Filter by correlation ID for incident investigation
//! fcp audit tail --zone z:work --correlation abc123...
//!
//! # JSON output for piping to jq/tools
//! fcp audit tail --zone z:work --json
//! ```

pub mod types;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Args, Subcommand};

use types::{AuditEventOutput, AuditFilter, AuditTailError};

/// Arguments for the `fcp audit` command.
#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,
}

/// Audit subcommands.
#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// Tail audit events from a zone's audit chain.
    ///
    /// Streams audit events in order (by seq) with optional filtering.
    /// Useful for incident response and debugging.
    Tail(TailArgs),
}

/// Arguments for the `fcp audit tail` command.
#[derive(Args, Debug)]
pub struct TailArgs {
    /// Zone to tail audit events from.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Filter by connector ID.
    #[arg(long, short = 'c')]
    pub connector: Option<String>,

    /// Filter by operation ID.
    #[arg(long, short = 'o')]
    pub operation: Option<String>,

    /// Filter by correlation ID (hex, 32 chars).
    #[arg(long)]
    pub correlation: Option<String>,

    /// Filter by trace ID (hex, 32 chars).
    #[arg(long)]
    pub trace: Option<String>,

    /// Filter by event type (e.g., "capability.invoke", "secret.access").
    #[arg(long, short = 'e')]
    pub event_type: Option<String>,

    /// Filter by actor (e.g., "user:alice").
    #[arg(long, short = 'a')]
    pub actor: Option<String>,

    /// Number of events to show (0 = stream indefinitely until interrupted).
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,

    /// Starting sequence number (default: latest minus limit).
    #[arg(long)]
    pub since: Option<u64>,

    /// Follow mode: continue streaming new events (like tail -f).
    #[arg(long, short = 'f', default_value_t = false)]
    pub follow: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run the audit command.
///
/// # Errors
///
/// Returns an error if the audit operation fails.
pub fn run(args: AuditArgs) -> Result<()> {
    match args.command {
        AuditCommands::Tail(tail_args) => run_tail(&tail_args),
    }
}

/// Run the audit tail command.
fn run_tail(args: &TailArgs) -> Result<()> {
    let filter = AuditFilter {
        connector_id: args.connector.clone(),
        operation_id: args.operation.clone(),
        correlation_id: args.correlation.clone(),
        trace_id: args.trace.clone(),
        event_type: args.event_type.clone(),
        actor: args.actor.clone(),
    };

    // TODO: In a full implementation, this would:
    // 1. Connect to the mesh node for the specified zone
    // 2. Load the audit head to get the current chain tip
    // 3. Walk backwards from the tip (or from --since) to retrieve events
    // 4. Stream events that match the filter
    // 5. If --follow, poll for new events
    //
    // For now, we demonstrate the output format with simulated events.

    // Simulate loading audit events
    let events = load_audit_events(&args.zone, args.since, args.limit, &filter)?;

    if events.is_empty() {
        if args.json {
            let error = AuditTailError::chain_unavailable(&args.zone);
            let output =
                serde_json::to_string_pretty(&error).context("failed to serialize error")?;
            println!("{output}");
            return Ok(());
        }
        eprintln!(
            "No audit events found in zone '{}' matching filters.",
            args.zone
        );
        if !filter.is_empty() {
            eprintln!("Try removing filters to see all events.");
        }
        return Ok(());
    }

    if args.json {
        output_json(&events)?;
    } else {
        output_human(&events, &args.zone, &filter);
    }

    Ok(())
}

/// Load audit events (stub implementation).
#[allow(clippy::too_many_lines)]
fn load_audit_events(
    zone: &str,
    since: Option<u64>,
    limit: usize,
    filter: &AuditFilter,
) -> Result<Vec<AuditEventOutput>, AuditTailError> {
    // Stub: Return demo data for the "z:work" zone, otherwise "zone not found"
    if !zone.starts_with("z:") {
        return Err(AuditTailError::zone_not_found(zone));
    }

    if zone != "z:work" && zone != "z:demo" {
        // For unknown zones, return empty to simulate no events
        return Ok(vec![]);
    }

    let base_seq = since.unwrap_or(100);
    #[allow(clippy::cast_sign_loss)] // Timestamps after 1970 are positive
    let now = Utc::now().timestamp() as u64;

    // Generate sample events
    let all_events = vec![
        AuditEventOutput {
            seq: base_seq,
            occurred_at: now - 300,
            occurred_at_iso: format_timestamp(now - 300),
            event_type: "capability.invoke".to_string(),
            actor: "user:alice".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "a".repeat(32),
            trace_id: Some("t".repeat(32)),
            span_id: Some("s".repeat(16)),
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            prev: None,
        },
        AuditEventOutput {
            seq: base_seq + 1,
            occurred_at: now - 240,
            occurred_at_iso: format_timestamp(now - 240),
            event_type: "secret.access".to_string(),
            actor: "user:alice".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "b".repeat(32),
            trace_id: Some("t".repeat(32)),
            span_id: Some("s".repeat(16)),
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("get_api_key".to_string()),
            prev: Some("prev1".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 2,
            occurred_at: now - 180,
            occurred_at_iso: format_timestamp(now - 180),
            event_type: "capability.invoke".to_string(),
            actor: "user:bob".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "c".repeat(32),
            trace_id: None,
            span_id: None,
            connector_id: Some("fcp.discord:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            prev: Some("prev2".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 3,
            occurred_at: now - 120,
            occurred_at_iso: format_timestamp(now - 120),
            event_type: "elevation.granted".to_string(),
            actor: "user:admin".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "d".repeat(32),
            trace_id: Some("u".repeat(32)),
            span_id: Some("v".repeat(16)),
            connector_id: None,
            operation_id: None,
            prev: Some("prev3".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 4,
            occurred_at: now - 60,
            occurred_at_iso: format_timestamp(now - 60),
            event_type: "revocation.issued".to_string(),
            actor: "user:admin".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "e".repeat(32),
            trace_id: Some("u".repeat(32)),
            span_id: Some("w".repeat(16)),
            connector_id: None,
            operation_id: None,
            prev: Some("prev4".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 5,
            occurred_at: now - 30,
            occurred_at_iso: format_timestamp(now - 30),
            event_type: "security.violation".to_string(),
            actor: "user:mallory".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "f".repeat(32),
            trace_id: None,
            span_id: None,
            connector_id: Some("fcp.github:base:v1".to_string()),
            operation_id: Some("delete_repo".to_string()),
            prev: Some("prev5".to_string()),
        },
    ];

    // Apply filter and limit
    let events: Vec<_> = all_events
        .into_iter()
        .filter(|e| filter.matches(e))
        .take(limit)
        .collect();

    Ok(events)
}

/// Format a Unix timestamp as ISO-8601.
fn format_timestamp(ts: u64) -> String {
    #[allow(clippy::cast_possible_wrap)] // Timestamps fit in i64 until year 292 billion
    let ts_i64 = ts as i64;
    Utc.timestamp_opt(ts_i64, 0).single().map_or_else(
        || ts.to_string(),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

/// Output events as JSON.
fn output_json(events: &[AuditEventOutput]) -> Result<()> {
    for event in events {
        let json = serde_json::to_string(event).context("failed to serialize event")?;
        println!("{json}");
    }
    Ok(())
}

/// Output events in human-readable format.
fn output_human(events: &[AuditEventOutput], zone: &str, filter: &AuditFilter) {
    let reset = AuditEventOutput::ansi_reset();

    // Header
    println!();
    println!("Audit Events for zone: {zone}");
    if !filter.is_empty() {
        print!("Filters:");
        if let Some(ref c) = filter.connector_id {
            print!(" connector={c}");
        }
        if let Some(ref o) = filter.operation_id {
            print!(" operation={o}");
        }
        if let Some(ref corr) = filter.correlation_id {
            print!(" correlation={}...", &corr[..8.min(corr.len())]);
        }
        if let Some(ref t) = filter.trace_id {
            print!(" trace={}...", &t[..8.min(t.len())]);
        }
        if let Some(ref e) = filter.event_type {
            print!(" event_type={e}");
        }
        if let Some(ref a) = filter.actor {
            print!(" actor={a}");
        }
        println!();
    }
    println!("{}", "─".repeat(80));
    println!();

    for event in events {
        let color = event.event_type_color();
        let symbol = event.event_type_symbol();

        // Timestamp and seq
        print!("\x1b[90m[{}]\x1b[0m ", event.occurred_at_iso);
        print!("\x1b[90mseq={:<6}\x1b[0m ", event.seq);

        // Event type with color
        print!("{color}{symbol} {:<26}{reset} ", event.event_type);

        // Actor
        print!("actor={:<16} ", truncate(&event.actor, 16));

        // Connector/operation if present
        if let Some(ref cid) = event.connector_id {
            print!("connector={} ", truncate(cid, 20));
        }
        if let Some(ref oid) = event.operation_id {
            print!("op={} ", truncate(oid, 15));
        }

        println!();

        // Second line: correlation/trace IDs
        if event.trace_id.is_some() || !event.correlation_id.is_empty() {
            print!("    ");
            print!("correlation={} ", truncate(&event.correlation_id, 12));
            if let Some(ref tid) = event.trace_id {
                print!("trace={} ", truncate(tid, 12));
            }
            if let Some(ref sid) = event.span_id {
                print!("span={} ", truncate(sid, 8));
            }
            println!();
        }
    }

    println!();
    println!("{}", "─".repeat(80));
    println!("Showing {} events", events.len());
    println!();
}

/// Truncate a string and add "..." if needed.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s[..max_len].to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_valid() {
        let ts = 1_700_000_000;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2023"));
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("abcdefghij", 6), "abc...");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
    }

    #[test]
    fn load_events_valid_zone() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 10, &filter);
        assert!(events.is_ok());
        let events = events.unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn load_events_invalid_zone_format() {
        let filter = AuditFilter::default();
        let events = load_audit_events("invalid", None, 10, &filter);
        assert!(events.is_err());
        let err = events.unwrap_err();
        assert_eq!(err.code, "FCP-4001");
    }

    #[test]
    fn load_events_unknown_zone_empty() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:unknown", None, 10, &filter);
        assert!(events.is_ok());
        assert!(events.unwrap().is_empty());
    }

    #[test]
    fn load_events_respects_limit() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 2, &filter).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn load_events_respects_filter() {
        let filter = AuditFilter {
            actor: Some("user:admin".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(events.iter().all(|e| e.actor == "user:admin"));
    }

    #[test]
    fn load_events_filter_by_event_type() {
        let filter = AuditFilter {
            event_type: Some("capability.invoke".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(events.iter().all(|e| e.event_type == "capability.invoke"));
    }
}

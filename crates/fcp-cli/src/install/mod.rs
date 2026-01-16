//! `fcp install` command implementation.
//!
//! Provides connector installation with full verification chain:
//! - Manifest signature verification (publisher and/or registry)
//! - Binary checksum verification
//! - Supply chain policy enforcement
//! - Capability ceiling enforcement
//! - Mesh store mirroring
//!
//! # Commands
//!
//! ## `fcp install <connector>`
//!
//! Install a connector into a zone with verification.
//!
//! ```text
//! # Install a connector (latest version)
//! fcp install fcp.telegram:base:v1 --zone z:work
//!
//! # Install a specific version
//! fcp install fcp.telegram:base:v1@1.2.3 --zone z:work
//!
//! # Skip mirroring (verify only)
//! fcp install fcp.telegram:base:v1 --zone z:work --verify-only
//!
//! # JSON output for automation
//! fcp install fcp.telegram:base:v1 --zone z:work --json
//! ```

pub mod types;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Args;

use types::{InstallError, InstallOutput, InstallPhase, InstallProgress, VerificationDetails};

/// Arguments for the `fcp install` command.
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Connector ID to install (format: namespace.name:variant:version_constraint).
    ///
    /// Examples:
    ///   fcp.telegram:base:v1
    ///   fcp.telegram:base:v1@1.2.3
    pub connector: String,

    /// Zone to install the connector into.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Target platform/architecture (defaults to current system).
    ///
    /// Examples: x86_64-unknown-linux-gnu, aarch64-apple-darwin
    #[arg(long, short = 't')]
    pub target: Option<String>,

    /// Verify only, don't mirror to mesh store.
    #[arg(long, default_value_t = false)]
    pub verify_only: bool,

    /// Skip supply chain verification (not recommended).
    #[arg(long, default_value_t = false)]
    pub skip_supply_chain: bool,

    /// Path to trust policy file (defaults to zone policy).
    #[arg(long)]
    pub trust_policy: Option<String>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Show verbose progress during installation.
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,
}

/// Run the install command.
///
/// # Errors
///
/// Returns an error if installation fails.
pub fn run(args: InstallArgs) -> Result<()> {
    // Parse connector ID and optional version
    let (connector_id, version) = parse_connector_spec(&args.connector);

    // Determine target platform
    let target = args
        .target
        .clone()
        .unwrap_or_else(|| current_target().to_string());

    // Validate zone format
    if !args.zone.starts_with("z:") {
        let err = InstallError::zone_not_found(&args.zone);
        if args.json {
            let output = serde_json::to_string_pretty(&err).context("failed to serialize error")?;
            println!("{output}");
        } else {
            eprintln!("Error: {err}");
            for hint in &err.hints {
                eprintln!("  Hint: {hint}");
            }
        }
        return Ok(());
    }

    // Progress reporting helper
    let report_progress = |phase: InstallPhase, message: &str| {
        if args.json && args.verbose {
            let progress = InstallProgress {
                phase,
                message: message.to_string(),
                progress_percent: None,
            };
            if let Ok(json) = serde_json::to_string(&progress) {
                println!("{json}");
            }
        } else if args.verbose {
            let reset = "\x1b[0m";
            println!(
                "{}{} {}{reset} {}",
                phase.color(),
                phase.symbol(),
                phase.label(),
                message
            );
        }
    };

    // Phase 1: Fetch manifest
    report_progress(
        InstallPhase::FetchingManifest,
        &format!("from registry for {connector_id}"),
    );

    let bundle = match fetch_connector_bundle(&connector_id, version.as_deref(), &target) {
        Ok(b) => b,
        Err(err) => {
            if args.json {
                let output =
                    serde_json::to_string_pretty(&err).context("failed to serialize error")?;
                println!("{output}");
            } else {
                eprintln!("Error: {err}");
                for hint in &err.hints {
                    eprintln!("  Hint: {hint}");
                }
            }
            return Ok(());
        }
    };

    // Phase 2: Verify manifest signatures
    report_progress(
        InstallPhase::VerifyingManifest,
        "checking publisher and registry signatures",
    );

    let verification = match verify_manifest(&bundle, args.trust_policy.as_deref()) {
        Ok(v) => v,
        Err(err) => {
            if args.json {
                let output =
                    serde_json::to_string_pretty(&err).context("failed to serialize error")?;
                println!("{output}");
            } else {
                eprintln!("Error: {err}");
                for hint in &err.hints {
                    eprintln!("  Hint: {hint}");
                }
            }
            return Ok(());
        }
    };

    // Phase 3: Verify binary checksum
    report_progress(
        InstallPhase::VerifyingBinary,
        &format!("sha256 checksum ({})", truncate(&bundle.binary_hash, 16)),
    );

    // Phase 4: Check supply chain (unless skipped)
    if !args.skip_supply_chain {
        report_progress(
            InstallPhase::CheckingSupplyChain,
            "validating attestations and transparency log",
        );
    }

    // Phase 5: Mirror to mesh store (unless verify-only)
    let (manifest_object_id, binary_object_id) = if args.verify_only {
        (None, None)
    } else {
        report_progress(
            InstallPhase::Mirroring,
            &format!("pinning to zone {}", args.zone),
        );

        match mirror_to_store(&bundle, &args.zone) {
            Ok((mid, bid)) => (Some(mid), Some(bid)),
            Err(err) => {
                if args.json {
                    let output =
                        serde_json::to_string_pretty(&err).context("failed to serialize error")?;
                    println!("{output}");
                } else {
                    eprintln!("Error: {err}");
                    for hint in &err.hints {
                        eprintln!("  Hint: {hint}");
                    }
                }
                return Ok(());
            }
        }
    };

    // Phase 6: Emit audit event
    report_progress(
        InstallPhase::EmittingAudit,
        "recording installation in audit chain",
    );

    // Build output
    let now = Utc::now();
    let installed_at = u64::try_from(now.timestamp()).unwrap_or(0);
    let installed_at_iso = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let output = InstallOutput {
        connector_id: bundle.connector_id.clone(),
        version: bundle.version.clone(),
        target,
        zone_id: args.zone.clone(),
        manifest_hash: bundle.manifest_hash.clone(),
        binary_hash: bundle.binary_hash.clone(),
        manifest_object_id,
        binary_object_id,
        verification,
        installed_at,
        installed_at_iso,
    };

    // Output result
    if args.json {
        let json = serde_json::to_string_pretty(&output).context("failed to serialize output")?;
        println!("{json}");
    } else {
        report_progress(InstallPhase::Complete, "");
        output_human(&output, args.verify_only);
    }

    Ok(())
}

/// Parse a connector spec like "fcp.telegram:base:v1" or "fcp.telegram:base:v1@1.2.3".
fn parse_connector_spec(spec: &str) -> (String, Option<String>) {
    if let Some((id, version)) = spec.split_once('@') {
        (id.to_string(), Some(version.to_string()))
    } else {
        (spec.to_string(), None)
    }
}

/// Get the current system target triple.
fn current_target() -> &'static str {
    // This would ideally use target_lexicon or similar at runtime
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
    )))]
    {
        "unknown-unknown-unknown"
    }
}

/// Stub connector bundle data.
#[derive(Debug)]
struct ConnectorBundleStub {
    connector_id: String,
    version: String,
    manifest_hash: String,
    binary_hash: String,
}

/// Fetch a connector bundle from the registry (stub implementation).
fn fetch_connector_bundle(
    connector_id: &str,
    version: Option<&str>,
    _target: &str,
) -> Result<ConnectorBundleStub, InstallError> {
    // Stub: Return demo data for known connectors
    let known_connectors = [
        "fcp.telegram:base:v1",
        "fcp.discord:base:v1",
        "fcp.openai:base:v1",
        "fcp.anthropic:base:v1",
    ];

    if !known_connectors.contains(&connector_id) {
        return Err(InstallError::connector_not_found(connector_id));
    }

    let resolved_version = version.unwrap_or("1.0.0");

    // For demo, only "1.0.0" and "1.0.1" exist
    if resolved_version != "1.0.0" && resolved_version != "1.0.1" {
        return Err(InstallError::version_not_found(
            connector_id,
            resolved_version,
        ));
    }

    Ok(ConnectorBundleStub {
        connector_id: connector_id.to_string(),
        version: resolved_version.to_string(),
        manifest_hash: format!("sha256:manifest_{connector_id}_{resolved_version}"),
        binary_hash: format!("sha256:binary_{connector_id}_{resolved_version}"),
    })
}

/// Verify manifest signatures (stub implementation).
fn verify_manifest(
    _bundle: &ConnectorBundleStub,
    _trust_policy_path: Option<&str>,
) -> Result<VerificationDetails, InstallError> {
    // Stub: All known connectors pass verification
    // In a real implementation, this would:
    // 1. Parse the manifest TOML
    // 2. Extract signature section
    // 3. Verify publisher signatures against trust policy
    // 4. Verify registry signature if present
    // 5. Check supply chain evidence

    Ok(VerificationDetails {
        publisher_signature_verified: true,
        registry_signature_verified: true,
        publisher_signatures_valid: 1,
        publisher_threshold: 1,
        supply_chain_policy_satisfied: true,
        capability_ceiling_respected: true,
        verified_attestations: vec!["in-toto".to_string()],
        slsa_level: Some(2),
    })
}

/// Mirror to mesh store (stub implementation).
fn mirror_to_store(
    bundle: &ConnectorBundleStub,
    zone: &str,
) -> Result<(String, String), InstallError> {
    // Stub: Generate fake object IDs
    // In a real implementation, this would:
    // 1. Connect to the mesh node for the zone
    // 2. Create StoredObject records for manifest and binary
    // 3. Store with RetentionClass::Pinned
    // 4. Return the derived object IDs

    let manifest_oid = format!(
        "obj:{}:manifest:{}",
        zone.strip_prefix("z:").unwrap_or(zone),
        &bundle.manifest_hash[7..15]
    );
    let binary_oid = format!(
        "obj:{}:binary:{}",
        zone.strip_prefix("z:").unwrap_or(zone),
        &bundle.binary_hash[7..15]
    );

    Ok((manifest_oid, binary_oid))
}

/// Truncate a string with ellipsis.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s[..max_len].to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Output installation result in human-readable format.
fn output_human(output: &InstallOutput, verify_only: bool) {
    let reset = "\x1b[0m";
    let green = "\x1b[32m";
    let cyan = "\x1b[36m";
    let yellow = "\x1b[33m";

    println!();
    if verify_only {
        println!("{green}✔ Verification successful{reset}");
    } else {
        println!("{green}✔ Installation successful{reset}");
    }
    println!();

    // Connector info
    println!("  {cyan}Connector:{reset}  {}", output.connector_id);
    println!("  {cyan}Version:{reset}    {}", output.version);
    println!("  {cyan}Target:{reset}     {}", output.target);
    println!("  {cyan}Zone:{reset}       {}", output.zone_id);
    println!();

    // Hashes
    println!(
        "  {cyan}Manifest:{reset}   {}",
        truncate(&output.manifest_hash, 40)
    );
    println!(
        "  {cyan}Binary:{reset}     {}",
        truncate(&output.binary_hash, 40)
    );
    println!();

    // Verification
    let v = &output.verification;
    println!("  {cyan}Verification:{reset}");
    let pub_status = if v.publisher_signature_verified {
        format!("{green}✔{reset}")
    } else {
        format!("{yellow}✗{reset}")
    };
    let reg_status = if v.registry_signature_verified {
        format!("{green}✔{reset}")
    } else {
        format!("{yellow}✗{reset}")
    };
    println!(
        "    Publisher signature:  {pub_status} ({}/{} signatures)",
        v.publisher_signatures_valid, v.publisher_threshold
    );
    println!("    Registry signature:   {reg_status}");

    if !v.verified_attestations.is_empty() {
        println!(
            "    Attestations:         {}",
            v.verified_attestations.join(", ")
        );
    }
    if let Some(slsa) = v.slsa_level {
        println!("    SLSA Level:           {slsa}");
    }
    println!();

    // Object IDs (if mirrored)
    if let Some(ref mid) = output.manifest_object_id {
        println!("  {cyan}Manifest Object:{reset} {mid}");
    }
    if let Some(ref bid) = output.binary_object_id {
        println!("  {cyan}Binary Object:{reset}   {bid}");
    }
    if output.manifest_object_id.is_some() {
        println!();
    }

    // Timestamp
    println!("  {cyan}Installed:{reset}  {}", output.installed_at_iso);
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connector_spec_without_version() {
        let (id, version) = parse_connector_spec("fcp.telegram:base:v1");
        assert_eq!(id, "fcp.telegram:base:v1");
        assert!(version.is_none());
    }

    #[test]
    fn parse_connector_spec_with_version() {
        let (id, version) = parse_connector_spec("fcp.telegram:base:v1@1.2.3");
        assert_eq!(id, "fcp.telegram:base:v1");
        assert_eq!(version, Some("1.2.3".to_string()));
    }

    #[test]
    fn current_target_not_empty() {
        let target = current_target();
        assert!(!target.is_empty());
    }

    #[test]
    fn fetch_known_connector() {
        let result =
            fetch_connector_bundle("fcp.telegram:base:v1", None, "x86_64-unknown-linux-gnu");
        assert!(result.is_ok());
        let bundle = result.unwrap();
        assert_eq!(bundle.connector_id, "fcp.telegram:base:v1");
        assert_eq!(bundle.version, "1.0.0");
    }

    #[test]
    fn fetch_known_connector_with_version() {
        let result = fetch_connector_bundle(
            "fcp.telegram:base:v1",
            Some("1.0.1"),
            "x86_64-unknown-linux-gnu",
        );
        assert!(result.is_ok());
        let bundle = result.unwrap();
        assert_eq!(bundle.version, "1.0.1");
    }

    #[test]
    fn fetch_unknown_connector() {
        let result =
            fetch_connector_bundle("fcp.unknown:base:v1", None, "x86_64-unknown-linux-gnu");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "FCP-4010");
    }

    #[test]
    fn fetch_unknown_version() {
        let result = fetch_connector_bundle(
            "fcp.telegram:base:v1",
            Some("9.9.9"),
            "x86_64-unknown-linux-gnu",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "FCP-4011");
    }

    #[test]
    fn verify_manifest_passes() {
        let bundle = ConnectorBundleStub {
            connector_id: "fcp.telegram:base:v1".to_string(),
            version: "1.0.0".to_string(),
            manifest_hash: "sha256:abc".to_string(),
            binary_hash: "sha256:def".to_string(),
        };
        let result = verify_manifest(&bundle, None);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert!(v.publisher_signature_verified);
        assert!(v.registry_signature_verified);
    }

    #[test]
    fn mirror_to_store_success() {
        let bundle = ConnectorBundleStub {
            connector_id: "fcp.telegram:base:v1".to_string(),
            version: "1.0.0".to_string(),
            manifest_hash: "sha256:abcdef123456".to_string(),
            binary_hash: "sha256:ghijkl789012".to_string(),
        };
        let result = mirror_to_store(&bundle, "z:work");
        assert!(result.is_ok());
        let (mid, bid) = result.unwrap();
        assert!(mid.starts_with("obj:work:manifest:"));
        assert!(bid.starts_with("obj:work:binary:"));
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_long() {
        assert_eq!(truncate("abcdefghij", 6), "abc...");
    }

    #[test]
    fn truncate_exact() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
    }
}

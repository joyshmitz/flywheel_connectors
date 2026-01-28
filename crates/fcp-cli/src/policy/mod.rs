//! `fcp policy` command implementation.
//!
//! Provides a policy simulation CLI for `DecisionReceipt` previews.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use fcp_cbor::SchemaId;
use fcp_core::{
    DecisionReceipt, DecisionReceiptPolicy, InvokeRequest, PolicySimulationError,
    PolicySimulationInput, Provenance, ZonePolicyObject,
};
use semver::Version;

/// Arguments for the `fcp policy` command.
#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,
}

/// Policy subcommands.
#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Simulate a policy decision for an invoke request.
    Simulate(SimulateArgs),
}

/// Arguments for `fcp policy simulate`.
#[derive(Args, Debug)]
pub struct SimulateArgs {
    /// Policy simulation input (JSON). Use "-" for stdin.
    ///
    /// Accepts either:
    /// 1) `PolicySimulationInput` JSON (with `zone_policy` + `invoke_request`)
    /// 2) `InvokeRequest` JSON (a permissive zone policy is synthesized)
    #[arg(long)]
    pub input: PathBuf,

    /// Output JSON (`DecisionReceipt`). Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Run the policy command.
pub fn run(args: &PolicyArgs) -> Result<()> {
    match &args.command {
        PolicyCommands::Simulate(sim_args) => run_simulate(sim_args),
    }
}

fn run_simulate(args: &SimulateArgs) -> Result<()> {
    let raw = read_input(&args.input)?;
    let input = parse_simulation_input(&raw)?;
    match fcp_core::simulate_policy_decision(&input) {
        Ok(receipt) => output_receipt(&receipt, args.json),
        Err(err) => output_error(&err, args.json),
    }
}

fn read_input(path: &PathBuf) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read stdin")?;
        return Ok(buf);
    }

    fs::read_to_string(path).with_context(|| format!("failed to read input {}", path.display()))
}

fn parse_simulation_input(raw: &str) -> Result<PolicySimulationInput> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("policy simulation input is empty");
    }

    if let Ok(input) = serde_json::from_str::<PolicySimulationInput>(trimmed) {
        return Ok(input);
    }

    let invoke = serde_json::from_str::<InvokeRequest>(trimmed)
        .context("failed to parse input as PolicySimulationInput or InvokeRequest")?;
    let zone_policy = default_zone_policy(&invoke);

    Ok(PolicySimulationInput {
        zone_policy,
        invoke_request: invoke,
        transport: fcp_core::TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: None,
        safety_tier: fcp_core::SafetyTier::Safe,
        principal: None,
        capability_id: None,
        provenance_record: None,
        now_ms: None,
        posture_attestation: None,
    })
}

fn default_zone_policy(invoke: &InvokeRequest) -> ZonePolicyObject {
    let schema = SchemaId::new("fcp.core", "ZonePolicy", Version::new(1, 0, 0));
    let header = fcp_core::ObjectHeader {
        schema,
        zone_id: invoke.zone_id.clone(),
        created_at: u64::try_from(fcp_core::Utc::now().timestamp()).unwrap_or(0),
        provenance: Provenance::new(invoke.zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    };

    ZonePolicyObject {
        header,
        zone_id: invoke.zone_id.clone(),
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: fcp_core::ZoneTransportPolicy::default(),
        decision_receipts: DecisionReceiptPolicy::default(),
        requires_posture: None,
    }
}

fn output_receipt(receipt: &DecisionReceipt, json: bool) -> Result<()> {
    if json {
        let payload =
            serde_json::to_string_pretty(receipt).context("failed to serialize DecisionReceipt")?;
        println!("{payload}");
        return Ok(());
    }

    println!();
    println!("Decision: {:?}", receipt.decision);
    println!("Reason: {}", receipt.reason_code);
    if !receipt.evidence.is_empty() {
        println!("Evidence:");
        for id in &receipt.evidence {
            println!("  - {id}");
        }
    }
    if let Some(ref explanation) = receipt.explanation {
        println!("Explanation: {explanation}");
    }
    println!();
    Ok(())
}

fn output_error(err: &PolicySimulationError, json: bool) -> Result<()> {
    if json {
        let payload = serde_json::json!({
            "error": err.to_string(),
            "code": "policy.simulation_failed",
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    Err(anyhow::anyhow!(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_simulation_input_direct() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: fcp_core::ZoneId::work(),
            input: serde_json::json!({"k": "v"}),
            capability_token: fcp_core::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let raw = serde_json::to_string(&invoke).unwrap();
        let input = parse_simulation_input(&raw).unwrap();
        assert_eq!(input.invoke_request.zone_id, fcp_core::ZoneId::work());
    }
}

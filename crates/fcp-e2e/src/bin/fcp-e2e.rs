//! Minimal CLI for fcp-e2e JSONL output.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::{env, io, process};

use fcp_core::CorrelationId;
use fcp_e2e::{
    AssertionsSummary, ConnectorProcessRunner, E2eLogEntry, E2eLogger, E2eReport, E2eRunner,
};

#[derive(Debug, Default)]
struct CliArgs {
    interop: bool,
    output: Option<PathBuf>,
    module: String,
    test_name: String,
    connector_cmd: Option<String>,
    connector_args: Vec<String>,
    requests: Vec<serde_json::Value>,
    help: bool,
}

fn usage() -> &'static str {
    "Usage:
  fcp-e2e --interop [--output <file>] [--test-name <name>] [--module <name>]
  fcp-e2e --connector-cmd <path> --request <json> [--request <json> ...] \\
         [--connector-arg <arg> ...] [--output <file>] [--test-name <name>] [--module <name>]
"
}

fn parse_args() -> Result<CliArgs, String> {
    let mut args = env::args().skip(1);
    let mut parsed = CliArgs {
        interop: false,
        output: None,
        module: "fcp-e2e".to_string(),
        test_name: "fcp-e2e".to_string(),
        connector_cmd: None,
        connector_args: Vec::new(),
        requests: Vec::new(),
        help: false,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                parsed.help = true;
            }
            "--interop" => {
                parsed.interop = true;
            }
            "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output requires a value".to_string())?;
                parsed.output = Some(PathBuf::from(value));
            }
            "--module" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--module requires a value".to_string())?;
                parsed.module = value;
            }
            "--test-name" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--test-name requires a value".to_string())?;
                parsed.test_name = value;
            }
            "--connector-cmd" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--connector-cmd requires a value".to_string())?;
                parsed.connector_cmd = Some(value);
            }
            "--connector-arg" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--connector-arg requires a value".to_string())?;
                parsed.connector_args.push(value);
            }
            "--request" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--request requires a value".to_string())?;
                let json = serde_json::from_str(&value)
                    .map_err(|err| format!("--request JSON invalid: {err}"))?;
                parsed.requests.push(json);
            }
            unknown => {
                return Err(format!("Unknown argument: {unknown}"));
            }
        }
    }

    if parsed.help {
        return Ok(parsed);
    }

    if parsed.interop && parsed.connector_cmd.is_some() {
        return Err("Choose only one of --interop or --connector-cmd".to_string());
    }

    if !parsed.interop && parsed.connector_cmd.is_none() {
        return Err("Missing mode: use --interop or --connector-cmd".to_string());
    }

    if parsed.connector_cmd.is_some() && parsed.requests.is_empty() {
        return Err("At least one --request is required for connector mode".to_string());
    }

    Ok(parsed)
}

fn write_report(report: &E2eReport, output: Option<PathBuf>) -> io::Result<()> {
    if let Some(path) = output {
        report.write_json_lines(path)
    } else {
        println!("{}", report.to_json_lines());
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{err}");
            eprintln!("{}", usage());
            process::exit(2);
        }
    };

    if args.help {
        println!("{}", usage());
        return Ok(());
    }

    if args.interop {
        let mut runner = E2eRunner::new(args.module);
        let report = runner.run_interop_suite(args.test_name);
        write_report(&report, args.output)?;
        return Ok(());
    }

    let connector_cmd = match args.connector_cmd {
        Some(cmd) => cmd,
        None => {
            eprintln!("No connector command provided.");
            eprintln!("{}", usage());
            process::exit(2);
        }
    };

    let arg_refs: Vec<&str> = args.connector_args.iter().map(String::as_str).collect();
    let mut runner = ConnectorProcessRunner::spawn(&connector_cmd, &arg_refs, &[]).await?;

    let mut logger = E2eLogger::new();
    let correlation_id = CorrelationId::new().to_string();
    let start = std::time::Instant::now();
    let mut passed = true;
    let mut assertions_passed = 0_u32;
    let mut assertions_failed = 0_u32;

    for (index, request) in args.requests.iter().enumerate() {
        let request_start = std::time::Instant::now();
        let response = runner.request(request).await;
        let duration_ms = request_start.elapsed().as_millis() as u64;

        let (level, result, context) = match response {
            Ok(response) => {
                assertions_passed += 1;
                (
                    "info",
                    "pass",
                    serde_json::json!({
                        "operation": "ipc_request",
                        "request_index": index,
                        "request": request,
                        "response": response,
                    }),
                )
            }
            Err(err) => {
                assertions_failed += 1;
                passed = false;
                (
                    "error",
                    "fail",
                    serde_json::json!({
                        "operation": "ipc_request",
                        "request_index": index,
                        "request": request,
                        "error": err.to_string(),
                    }),
                )
            }
        };

        let entry = E2eLogEntry::new(
            level,
            args.test_name.clone(),
            args.module.clone(),
            "execute",
            correlation_id.clone(),
            result,
            duration_ms,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            context,
        );
        logger.push(entry);

        let stderr_lines = runner.drain_stderr_lines().await;
        for line in stderr_lines {
            let entry = E2eLogEntry::new(
                "warn",
                args.test_name.clone(),
                args.module.clone(),
                "observe",
                correlation_id.clone(),
                "pass",
                0,
                AssertionsSummary::new(assertions_passed, assertions_failed),
                serde_json::json!({
                    "operation": "stderr",
                    "line": line,
                }),
            );
            logger.push(entry);
        }
    }

    runner.terminate().await?;
    let stderr_lines = runner.drain_stderr_lines().await;
    for line in stderr_lines {
        let entry = E2eLogEntry::new(
            "warn",
            args.test_name.clone(),
            args.module.clone(),
            "observe",
            correlation_id.clone(),
            "pass",
            0,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            serde_json::json!({
                "operation": "stderr",
                "line": line,
            }),
        );
        logger.push(entry);
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let summary_entry = E2eLogEntry::new(
        "info",
        args.test_name.clone(),
        args.module.clone(),
        "teardown",
        correlation_id,
        if passed { "pass" } else { "fail" },
        duration_ms,
        AssertionsSummary::new(assertions_passed, assertions_failed),
        serde_json::json!({
            "connector_cmd": connector_cmd,
            "connector_args": args.connector_args,
            "request_count": args.requests.len(),
        }),
    );
    logger.push(summary_entry);

    let report = E2eReport {
        test_name: args.test_name,
        passed,
        duration_ms,
        logs: logger.drain(),
    };
    write_report(&report, args.output)?;
    Ok(())
}

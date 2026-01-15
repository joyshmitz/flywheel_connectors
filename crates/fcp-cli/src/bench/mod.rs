//! FCP2 performance benchmark suite.
//!
//! This module implements the `fcp bench` command with subcommands for various
//! benchmark targets. All benchmarks emit machine-readable JSON output with
//! environment metadata for regression tracking.
//!
//! ## Canonical Targets (README-aligned)
//!
//! - Cold start (connector activate): p50 < 100ms / p99 < 500ms
//! - Local invoke latency (same node): p50 < 2ms / p99 < 10ms
//! - Tailnet invoke latency (LAN/direct): p50 < 20ms / p99 < 100ms
//! - Tailnet invoke latency (DERP): p50 < 150ms / p99 < 500ms
//! - Symbol reconstruction (1MB): p50 < 50ms / p99 < 250ms
//! - Secret reconstruction (k-of-n): p50 < 150ms / p99 < 750ms
//! - Memory overhead: < 10MB per connector (idle)
//! - CPU overhead: < 1% idle (event-driven)
//! - Binary size: < 20MB compressed

mod cbor;
mod environment;
mod runner;
mod types;

pub use types::{BenchmarkReport, BenchmarkResult};

use clap::{Args, Subcommand};

/// Arguments for the `fcp bench` command.
#[derive(Args)]
pub struct BenchArgs {
    #[command(subcommand)]
    command: BenchCommand,

    /// Output format: json (machine-readable) or human (pretty-printed).
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Number of iterations for each benchmark.
    #[arg(long, default_value = "100")]
    iterations: u32,

    /// Number of warmup iterations before measurement.
    #[arg(long, default_value = "10")]
    warmup: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Human,
}

#[derive(Subcommand)]
enum BenchCommand {
    /// Benchmark connector cold start time.
    ///
    /// Target: p50 < 100ms / p99 < 500ms (stretch goal: p50 < 50ms)
    ConnectorActivate {
        /// Path to connector binary.
        #[arg(long)]
        connector: Option<String>,
    },

    /// Benchmark local invoke latency (same node).
    ///
    /// Target: p50 < 2ms / p99 < 10ms
    InvokeLocal,

    /// Benchmark mesh invoke latency.
    ///
    /// Target (direct/LAN): p50 < 20ms / p99 < 100ms
    /// Target (DERP): p50 < 150ms / p99 < 500ms
    InvokeMesh {
        /// Network path: direct (LAN) or derp (relay).
        #[arg(long)]
        path: MeshPath,
    },

    /// Benchmark `RaptorQ` symbol encoding/decoding.
    ///
    /// Target (1MB): p50 < 50ms / p99 < 250ms
    Raptorq {
        /// Payload size (e.g., "1mb", "100kb").
        #[arg(long, default_value = "1mb")]
        size: String,
    },

    /// Benchmark secret reconstruction (Shamir k-of-n).
    ///
    /// Target: p50 < 150ms / p99 < 750ms
    Secrets {
        /// Threshold (k) for reconstruction.
        #[arg(long, default_value = "3")]
        k: u32,

        /// Total shares (n).
        #[arg(long, default_value = "5")]
        n: u32,
    },

    /// Benchmark canonical CBOR serialization.
    ///
    /// Microbenches for hot primitives in fcp-cbor.
    Cbor {
        /// Specific sub-benchmark (schema-hash, serialize, deserialize, all).
        #[arg(long, default_value = "all")]
        target: CborTarget,
    },

    /// Run all benchmarks and produce a complete report.
    All,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum MeshPath {
    Direct,
    Derp,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CborTarget {
    SchemaHash,
    Serialize,
    Deserialize,
    All,
}

/// Run the benchmark command.
pub fn run(args: BenchArgs) -> anyhow::Result<()> {
    let env = environment::collect();

    let results = match args.command {
        BenchCommand::ConnectorActivate { connector: _ } => {
            // TODO: Implement connector activation benchmarks once fcp-sdk is ready.
            tracing::warn!("connector-activate benchmark not yet implemented (fcp-sdk pending)");
            vec![BenchmarkResult::placeholder(
                "connector-activate",
                "fcp-sdk not yet implemented",
            )]
        }
        BenchCommand::InvokeLocal => {
            // TODO: Implement local invoke benchmarks once fcp-mesh is ready.
            tracing::warn!("invoke-local benchmark not yet implemented (fcp-mesh pending)");
            vec![BenchmarkResult::placeholder(
                "invoke-local",
                "fcp-mesh not yet implemented",
            )]
        }
        BenchCommand::InvokeMesh { path } => {
            let path_name = match path {
                MeshPath::Direct => "direct",
                MeshPath::Derp => "derp",
            };
            // TODO: Implement mesh invoke benchmarks once fcp-mesh is ready.
            tracing::warn!(
                "invoke-mesh --path={} benchmark not yet implemented (fcp-mesh pending)",
                path_name
            );
            vec![BenchmarkResult::placeholder(
                format!("invoke-mesh-{path_name}"),
                "fcp-mesh not yet implemented",
            )]
        }
        BenchCommand::Raptorq { size } => {
            // TODO: Implement RaptorQ benchmarks once fcp-raptorq is ready.
            tracing::warn!(
                "raptorq --size={} benchmark not yet implemented (fcp-raptorq pending)",
                size
            );
            vec![BenchmarkResult::placeholder(
                format!("raptorq-{size}"),
                "fcp-raptorq not yet implemented",
            )]
        }
        BenchCommand::Secrets { k, n } => {
            // TODO: Implement secrets benchmarks once fcp-crypto Shamir is ready.
            tracing::warn!(
                "secrets --k={} --n={} benchmark not yet implemented (fcp-crypto pending)",
                k,
                n
            );
            vec![BenchmarkResult::placeholder(
                format!("secrets-{k}-of-{n}"),
                "fcp-crypto Shamir not yet implemented",
            )]
        }
        BenchCommand::Cbor { target } => cbor::run_benchmarks(target, args.iterations, args.warmup),
        BenchCommand::All => {
            let mut all_results = Vec::new();

            // Run CBOR benchmarks (the only ones currently implemented).
            all_results.extend(cbor::run_benchmarks(
                CborTarget::All,
                args.iterations,
                args.warmup,
            ));

            // Add placeholders for unimplemented benchmarks.
            all_results.push(BenchmarkResult::placeholder(
                "connector-activate",
                "fcp-sdk not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "invoke-local",
                "fcp-mesh not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "invoke-mesh-direct",
                "fcp-mesh not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "invoke-mesh-derp",
                "fcp-mesh not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "raptorq-1mb",
                "fcp-raptorq not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "secrets-3-of-5",
                "fcp-crypto Shamir not yet implemented",
            ));

            all_results
        }
    };

    let report = BenchmarkReport::new(env, results);

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Human => {
            print_human_report(&report);
        }
    }

    Ok(())
}

fn print_human_report(report: &BenchmarkReport) {
    println!("FCP2 Benchmark Report");
    println!("=====================");
    println!();
    println!("Environment:");
    println!(
        "  OS:      {} {}",
        report.environment.os, report.environment.os_version
    );
    println!("  Arch:    {}", report.environment.arch);
    println!("  CPUs:    {}", report.environment.cpu_count);
    if let Some(ref commit) = report.environment.git_commit {
        println!("  Commit:  {commit}");
    }
    println!("  Time:    {}", report.environment.timestamp);
    println!();

    for result in &report.results {
        println!("{}:", result.name);
        if let Some(note) = &result.note {
            println!("  Note: {note}");
        }
        if let Some(ref p) = result.percentiles {
            println!("  p50:  {:>10.3} ms", p.p50_ms);
            println!("  p90:  {:>10.3} ms", p.p90_ms);
            println!("  p99:  {:>10.3} ms", p.p99_ms);
            println!("  min:  {:>10.3} ms", p.min_ms);
            println!("  max:  {:>10.3} ms", p.max_ms);
        }
        println!("  Samples: {}", result.sample_count);
        println!();
    }
}

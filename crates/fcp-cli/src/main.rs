//! FCP2 developer/operator CLI entrypoint.
//!
//! This CLI provides tooling for FCP2 operators and developers:
//! - `fcp audit` - Audit chain operations for incident response
//! - `fcp bench` - Performance benchmarking suite
//! - `fcp explain` - Operation decision explanations
//! - `fcp install` - Connector installation with verification

#![forbid(unsafe_code)]

mod audit;
mod bench;
mod explain;
mod install;

use clap::{Parser, Subcommand};

/// FCP2 developer/operator CLI.
#[derive(Parser)]
#[command(name = "fcp")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit chain operations for incident response and debugging.
    ///
    /// Stream audit events from a zone's audit chain with filtering.
    Audit(audit::AuditArgs),

    /// Performance benchmark suite.
    ///
    /// Run benchmarks to measure and track FCP2 performance characteristics.
    /// Outputs machine-readable JSON with environment metadata for regression tracking.
    Bench(bench::BenchArgs),

    /// Explain an allow/deny decision by rendering the `DecisionReceipt`.
    ///
    /// Load and display the mechanical evidence behind an operation decision.
    Explain(explain::ExplainArgs),

    /// Install a connector with full verification chain.
    ///
    /// Verify manifest signatures, binary checksums, and supply chain policy,
    /// then mirror the connector to the mesh store.
    Install(install::InstallArgs),
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber for structured logging.
    // Write logs to stderr so stdout is clean for JSON output.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Audit(args) => audit::run(args),
        Commands::Bench(args) => bench::run(args),
        Commands::Explain(args) => explain::run(&args),
        Commands::Install(args) => install::run(args),
    }
}

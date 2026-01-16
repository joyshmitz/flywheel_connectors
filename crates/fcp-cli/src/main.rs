//! FCP2 developer/operator CLI entrypoint.
//!
//! This CLI provides tooling for FCP2 operators and developers:
//! - `fcp audit` - Audit event streaming and investigation
//! - `fcp bench` - Performance benchmarking suite
//! - `fcp doctor` - System health checks (planned)
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
    /// Audit event streaming and investigation.
    ///
    /// Stream and filter audit events from a zone's audit chain for incident
    /// response and debugging. Supports filtering by connector, operation,
    /// correlation ID, and more.
    ///
    /// Example: fcp audit tail --zone z:work --connector fcp.telegram:base:v1
    Audit(audit::AuditArgs),

    /// Performance benchmark suite.
    ///
    /// Run benchmarks to measure and track FCP2 performance characteristics.
    /// Outputs machine-readable JSON with environment metadata for regression tracking.
    Bench(bench::BenchArgs),

    /// Explain a decision receipt.
    ///
    /// Render the mechanical evidence behind an allow/deny decision by loading
    /// and displaying the DecisionReceipt for a given request object ID.
    ///
    /// Example: fcp explain --request <object-id>
    Explain(explain::ExplainArgs),

    /// Install a connector into a zone.
    ///
    /// Fetches, verifies, and mirrors a connector from the registry into the
    /// specified zone's mesh store. Runs the full verification chain:
    /// - Manifest signature(s) (publisher and/or registry)
    /// - Binary checksum and signature
    /// - Platform/arch compatibility
    /// - Supply chain policy requirements
    ///
    /// Example: fcp install fcp.telegram:base:v1 --zone z:work
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
        Commands::Explain(args) => explain::run(args),
        Commands::Install(args) => install::run(args),
    }
}

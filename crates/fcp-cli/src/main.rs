//! FCP2 developer/operator CLI entrypoint.
//!
//! This CLI provides tooling for FCP2 operators and developers:
//! - `fcp bench` - Performance benchmarking suite
//! - `fcp doctor` - System health checks (planned)
//! - `fcp explain` - Operation decision explanations

#![forbid(unsafe_code)]

mod bench;
mod explain;

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
        Commands::Bench(args) => bench::run(args),
        Commands::Explain(args) => explain::run(args),
    }
}

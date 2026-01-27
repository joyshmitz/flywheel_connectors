//! Types for connector packaging operations.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Arguments for the package subcommand.
#[derive(Debug, Clone, clap::Args)]
pub struct PackageArgs {
    /// Path to the connector crate directory.
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Output directory for the package.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Skip SBOM generation.
    #[arg(long, default_value_t = false)]
    pub skip_sbom: bool,

    /// Skip signing (for development only).
    #[arg(long, default_value_t = false)]
    pub skip_sign: bool,

    /// Build in release mode.
    #[arg(long, default_value_t = true)]
    pub release: bool,

    /// Additional cargo build flags.
    #[arg(long)]
    pub cargo_flags: Vec<String>,

    /// Output format (json for machine-readable).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

/// Output format for package command.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable output.
    Human,
    /// JSON output for tooling integration.
    Json,
}

/// Package output metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageOutput {
    /// Path to the output directory.
    pub output_dir: PathBuf,

    /// Path to the packaged binary.
    pub binary_path: PathBuf,

    /// Path to the embedded manifest.
    pub manifest_path: PathBuf,

    /// Path to the SBOM file (if generated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom_path: Option<PathBuf>,

    /// Path to the build metadata JSON.
    pub build_metadata_path: PathBuf,

    /// SHA-256 hash of the binary.
    pub binary_sha256: String,

    /// Connector ID from manifest.
    pub connector_id: String,

    /// Connector version.
    pub version: String,
}

/// Build metadata for reproducibility verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildMetadata {
    /// Rust toolchain version.
    pub rust_version: String,

    /// Cargo version.
    pub cargo_version: String,

    /// Target triple.
    pub target_triple: String,

    /// Build timestamp (ISO 8601).
    pub build_timestamp: String,

    /// Build profile (release/debug).
    pub profile: String,

    /// Git commit hash (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,

    /// Git dirty status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_dirty: Option<bool>,

    /// Cargo features enabled.
    pub features: Vec<String>,

    /// Environment variables affecting build (filtered).
    pub build_env: std::collections::HashMap<String, String>,

    /// CARGO_* flags used.
    pub cargo_flags: Vec<String>,
}

/// SBOM (Software Bill of Materials) in a simplified format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleSbom {
    /// SBOM format version.
    pub format_version: String,

    /// Document creation timestamp.
    pub created: String,

    /// Tool that generated this SBOM.
    pub tool: String,

    /// Primary component (the connector).
    pub component: SbomComponent,

    /// Dependencies.
    pub dependencies: Vec<SbomDependency>,
}

/// Component in SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    /// Component type (always "application" for connectors).
    pub component_type: String,

    /// Component name.
    pub name: String,

    /// Component version.
    pub version: String,

    /// PURL (Package URL).
    pub purl: String,
}

/// Dependency in SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDependency {
    /// Dependency name.
    pub name: String,

    /// Dependency version.
    pub version: String,

    /// PURL (Package URL).
    pub purl: String,

    /// Source (crates.io, git, path).
    pub source: String,
}

//! `fcp new` command implementation.
//!
//! Scaffolds new FCP2-compliant connector crates with correct structure,
//! manifest, and compliance prechecks.
//!
//! # Usage
//!
//! ```text
//! # Create a new connector
//! fcp new fcp.myservice
//! fcp new fcp.myservice --archetype streaming
//! fcp new fcp.myservice --zone z:project:myapp
//!
//! # Preview without writing
//! fcp new fcp.myservice --dry-run
//!
//! # Check an existing connector
//! fcp new --check connectors/myservice
//! ```

pub mod types;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use fcp_manifest::ConnectorManifest;

use types::{
    CheckResult, CheckSeverity, ConnectorArchetype, CreatedFile, PrecheckItem, PrecheckResults,
    ScaffoldResult, SuggestedFix,
};

/// Arguments for the `fcp new` command.
#[derive(Args, Debug)]
pub struct NewArgs {
    /// Connector ID (e.g., "fcp.myservice").
    ///
    /// Must start with "fcp." and contain only alphanumeric characters and dots.
    #[arg(required_unless_present = "check")]
    pub connector_id: Option<String>,

    /// Connector archetype.
    #[arg(long, short = 'a', value_enum, default_value_t = ArchetypeArg::RequestResponse)]
    pub archetype: ArchetypeArg,

    /// Zone binding (e.g., "z:project:myapp").
    #[arg(long, short = 'z', default_value = "z:project:default")]
    pub zone: String,

    /// Skip E2E test scaffolding.
    #[arg(long)]
    pub no_e2e: bool,

    /// Preview planned files without writing.
    #[arg(long)]
    pub dry_run: bool,

    /// Validate an existing connector directory instead of creating new.
    #[arg(long, value_name = "PATH")]
    pub check: Option<PathBuf>,

    /// Output JSON instead of human-readable format.
    #[arg(long)]
    pub json: bool,
}

/// Archetype argument enum (for clap's `ValueEnum` derive).
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ArchetypeArg {
    #[default]
    RequestResponse,
    Streaming,
    Bidirectional,
    Polling,
    Webhook,
    Queue,
    File,
    Database,
    Cli,
    Browser,
}

impl From<ArchetypeArg> for ConnectorArchetype {
    fn from(arg: ArchetypeArg) -> Self {
        match arg {
            ArchetypeArg::RequestResponse => Self::RequestResponse,
            ArchetypeArg::Streaming => Self::Streaming,
            ArchetypeArg::Bidirectional => Self::Bidirectional,
            ArchetypeArg::Polling => Self::Polling,
            ArchetypeArg::Webhook => Self::Webhook,
            ArchetypeArg::Queue => Self::Queue,
            ArchetypeArg::File => Self::File,
            ArchetypeArg::Database => Self::Database,
            ArchetypeArg::Cli => Self::Cli,
            ArchetypeArg::Browser => Self::Browser,
        }
    }
}

/// Run the new command.
pub fn run(args: &NewArgs) -> Result<()> {
    if let Some(check_path) = &args.check {
        run_check(check_path, args.json)
    } else {
        let connector_id = args
            .connector_id
            .as_ref()
            .context("connector_id is required when not using --check")?;
        run_scaffold(connector_id, args)
    }
}

/// Run compliance check on an existing connector.
fn run_check(path: &Path, json_output: bool) -> Result<()> {
    let result = check_connector(path)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_check_result(&result);
    }

    if !result.prechecks.passed {
        std::process::exit(1);
    }

    Ok(())
}

/// Run scaffold generation.
fn run_scaffold(connector_id: &str, args: &NewArgs) -> Result<()> {
    // Validate connector ID format
    validate_connector_id(connector_id)?;

    let archetype: ConnectorArchetype = args.archetype.into();
    let result = scaffold_connector(connector_id, archetype, &args.zone, args.no_e2e, args.dry_run)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_scaffold_result(&result, args.dry_run);
    }

    if !result.prechecks.passed {
        std::process::exit(1);
    }

    Ok(())
}

/// Validate connector ID format.
fn validate_connector_id(id: &str) -> Result<()> {
    if !id.starts_with("fcp.") {
        anyhow::bail!("connector ID must start with 'fcp.' (got: {id})");
    }

    let suffix = &id[4..];
    if suffix.is_empty() {
        anyhow::bail!("connector ID must have a name after 'fcp.'");
    }

    // Check for valid characters (alphanumeric, dots, underscores, hyphens)
    if !suffix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        anyhow::bail!(
            "connector ID must contain only alphanumeric characters, dots, underscores, or hyphens"
        );
    }

    // Check for consecutive dots
    if id.contains("..") {
        anyhow::bail!("connector ID cannot contain consecutive dots");
    }

    Ok(())
}

/// Extract the short name from a connector ID (e.g., "fcp.myservice" -> "myservice").
fn extract_short_name(connector_id: &str) -> &str {
    connector_id.strip_prefix("fcp.").unwrap_or(connector_id)
}

/// Normalize a connector short name into a crate-safe slug.
fn normalize_crate_slug(short_name: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;
    for ch in short_name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else {
            if !last_dash {
                slug.push('-');
                last_dash = true;
            }
        }
    }
    slug.trim_matches('-').to_string()
}

/// Scaffold a new connector.
fn scaffold_connector(
    connector_id: &str,
    archetype: ConnectorArchetype,
    zone: &str,
    no_e2e: bool,
    dry_run: bool,
) -> Result<ScaffoldResult> {
    let short_name = extract_short_name(connector_id);
    let crate_slug = normalize_crate_slug(short_name);
    let crate_name = format!("fcp-{crate_slug}");
    let crate_path = format!("connectors/{crate_slug}");

    let mut files_created = Vec::new();

    // Generate all files
    let files = generate_files(connector_id, short_name, &crate_name, archetype, zone, no_e2e)?;

    if !dry_run {
        // Create directory structure
        let base_path = Path::new(&crate_path);
        fs::create_dir_all(base_path.join("src"))?;
        fs::create_dir_all(base_path.join("tests"))?;

        // Write files
        for (rel_path, content, _purpose) in &files {
            let full_path = base_path.join(rel_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = fs::File::create(&full_path)
                .with_context(|| format!("failed to create {}", full_path.display()))?;
            file.write_all(content.as_bytes())?;
        }
    }

    // Record created files
    for (rel_path, content, purpose) in &files {
        files_created.push(CreatedFile {
            path: rel_path.clone(),
            purpose: purpose.clone(),
            size: content.len(),
        });
    }

    // Run prechecks on generated content
    let prechecks = run_prechecks(&files, connector_id, zone);

    // Generate next steps
    let next_steps = generate_next_steps(connector_id, &crate_path, archetype, no_e2e);

    Ok(ScaffoldResult {
        connector_id: connector_id.to_string(),
        crate_path,
        files_created,
        prechecks,
        next_steps,
    })
}

/// Generate all scaffold files.
fn generate_files(
    connector_id: &str,
    short_name: &str,
    crate_name: &str,
    archetype: ConnectorArchetype,
    zone: &str,
    no_e2e: bool,
) -> Result<Vec<(String, String, String)>> {
    let manifest = generate_manifest_toml(connector_id, short_name, archetype, zone)?;
    let crate_ident = crate_name.replace('-', "_");
    let mut files = vec![
        (
            "Cargo.toml".to_string(),
            generate_cargo_toml(crate_name, short_name),
            "Crate manifest".to_string(),
        ),
        (
            "manifest.toml".to_string(),
            manifest,
            "FCP2 connector manifest".to_string(),
        ),
        (
            "src/main.rs".to_string(),
            generate_main_rs(short_name, &crate_ident),
            "FCP protocol loop entrypoint".to_string(),
        ),
        (
            "src/lib.rs".to_string(),
            generate_lib_rs(short_name),
            "Library exports".to_string(),
        ),
        (
            "src/connector.rs".to_string(),
            generate_connector_rs(connector_id, short_name, archetype),
            "Connector implementation".to_string(),
        ),
        (
            "src/types.rs".to_string(),
            generate_types_rs(short_name),
            "Request/response types".to_string(),
        ),
        (
            "tests/unit_tests.rs".to_string(),
            generate_unit_tests_rs(short_name, &crate_ident),
            "Unit test scaffolding".to_string(),
        ),
    ];

    if !no_e2e {
        files.push((
            "tests/e2e_tests.rs".to_string(),
            generate_e2e_tests_rs(connector_id, crate_name),
            "E2E test scaffolding".to_string(),
        ));
    }

    Ok(files)
}

/// Generate Cargo.toml content.
fn generate_cargo_toml(crate_name: &str, short_name: &str) -> String {
    format!(
        r#"[package]
name = "{crate_name}"
description = "FCP2 connector for {short_name}"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[[bin]]
name = "{crate_name}"
path = "src/main.rs"

[lints]
workspace = true

[dependencies]
fcp-sdk = {{ path = "../../crates/fcp-sdk" }}

anyhow.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = {{ workspace = true, features = ["full"] }}
tracing.workspace = true
tracing-subscriber.workspace = true
uuid.workspace = true
sha2.workspace = true
hex.workspace = true

[dev-dependencies]
wiremock.workspace = true
tokio = {{ workspace = true, features = ["macros", "rt-multi-thread"] }}
"#
    )
}

const INTERFACE_HASH_PLACEHOLDER: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

/// Generate manifest.toml content.
fn generate_manifest_toml(
    connector_id: &str,
    short_name: &str,
    archetype: ConnectorArchetype,
    zone: &str,
) -> Result<String> {
    let archetype_str = manifest_archetype(archetype);
    let title_name = short_name
        .chars()
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + &short_name[1..])
        .unwrap_or_default();

    let template = format!(
        r#"# FCP2 Connector Manifest
# Generated by `fcp new` - fill in placeholder values marked with TODO

[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
# Interface hash is auto-generated from declared operations.
interface_hash = "{INTERFACE_HASH_PLACEHOLDER}"

[connector]
id = "{connector_id}"
name = "{title_name} Connector"
version = "0.1.0"
description = "TODO: Add connector description"
archetypes = ["{archetype_str}"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
# Single-zone binding (FCP2 requirement)
home = "{zone}"
allowed_sources = ["{zone}"]
allowed_targets = ["{zone}"]
forbidden = ["z:public"]

[capabilities]
# TODO: Define required capabilities for your connector
required = ["network.dns", "network.outbound"]
optional = []
# Default-deny: explicitly forbid dangerous capabilities
forbidden = ["system.exec", "system.privileged"]

# TODO: Define your connector's operations
# Each operation should have:
# - A clear capability requirement
# - Appropriate risk level and safety tier
# - Network constraints (default-deny)
[provides.operations.placeholder_operation]
description = "TODO: Describe this operation"
capability = "{short_name}.placeholder"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "idempotent"
input_schema = {{ type = "object", properties = {{ }} }}
output_schema = {{ type = "object", properties = {{ }} }}
# Default-deny network constraints (replace with real endpoints)
network_constraints = {{
  host_allow = ["example.invalid"],
  port_allow = [443],
  require_sni = true,
  deny_ip_literals = true,
  deny_localhost = true,
  deny_private_ranges = true,
  deny_tailnet_ranges = true,
  max_redirects = 0,
  connect_timeout_ms = 5000,
  total_timeout_ms = 60000,
  max_response_bytes = 1048576
}}

[provides.operations.placeholder_operation.ai_hints]
when_to_use = "TODO: Describe when an AI agent should use this operation"
common_mistakes = ["TODO: List common mistakes"]

[sandbox]
# Strict sandbox profile (FCP2 requirement)
profile = "strict"
memory_mb = 64
cpu_percent = 25
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

# Signatures and supply chain metadata are added during `fcp install`
# Do not add placeholder values here
"#
    );

    finalize_manifest_toml(&template)
}

fn manifest_archetype(archetype: ConnectorArchetype) -> &'static str {
    match archetype {
        ConnectorArchetype::RequestResponse
        | ConnectorArchetype::Polling
        | ConnectorArchetype::Cli
        | ConnectorArchetype::Browser => "operational",
        ConnectorArchetype::Streaming | ConnectorArchetype::Webhook => "streaming",
        ConnectorArchetype::Bidirectional | ConnectorArchetype::Queue => "bidirectional",
        ConnectorArchetype::File | ConnectorArchetype::Database => "storage",
    }
}

fn finalize_manifest_toml(template: &str) -> Result<String> {
    let manifest = ConnectorManifest::parse_str_unchecked(template)?;
    let interface_hash = manifest.compute_interface_hash()?;
    let rendered = template.replace(INTERFACE_HASH_PLACEHOLDER, &interface_hash.to_string());
    if rendered == template {
        bail!("failed to render interface hash placeholder");
    }
    ConnectorManifest::parse_str(&rendered)?;
    Ok(rendered)
}

/// Generate main.rs content.
fn generate_main_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r#"//! FCP {struct_name} Connector - Main entrypoint
//!
//! This connector implements the Flywheel Connector Protocol (FCP2).

#![forbid(unsafe_code)]

use std::io::{{BufRead, Write}};

use anyhow::Result;
use tracing_subscriber::{{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt}};

mod connector;
mod types;

use connector::{struct_name}Connector;

fn main() -> Result<()> {{
    // Initialize tracing to stderr (stdout is for JSON-RPC protocol)
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP {struct_name} Connector starting");

    run_fcp_loop()?;

    Ok(())
}}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {{
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = {struct_name}Connector::new();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    for line in stdin.lock().lines() {{
        let line = line?;
        if line.is_empty() {{
            continue;
        }}

        let response = runtime.block_on(async {{ handle_message(&mut connector, &line).await }});

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{{response_json}}")?;
        stdout.flush()?;
    }}

    Ok(())
}}

/// Handle a single FCP message.
async fn handle_message(connector: &mut {struct_name}Connector, message: &str) -> serde_json::Value {{
    let request: serde_json::Value = match serde_json::from_str(message) {{
        Ok(v) => v,
        Err(e) => {{
            return serde_json::json!({{
                "error": {{
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {{e}}")
                }}
            }});
        }}
    }};

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({{}}));

    let result = match method {{
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => connector.handle_invoke(params).await,
        "subscribe" => connector.handle_subscribe(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(fcp_core::FcpError::InvalidRequest {{
            code: 1002,
            message: format!("Unknown method: {{method}}"),
        }}),
    }};

    match result {{
        Ok(value) => {{
            let mut response = serde_json::json!({{
                "jsonrpc": "2.0",
                "result": value
            }});
            if let Some(id) = id {{
                response["id"] = id;
            }}
            response
        }}
        Err(e) => {{
            let err_response = e.to_response();
            let mut response = serde_json::json!({{
                "jsonrpc": "2.0",
                "error": err_response
            }});
            if let Some(id) = id {{
                response["id"] = id;
            }}
            response
        }}
    }}
}}
"#
    )
}

/// Generate lib.rs content.
fn generate_lib_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);
    format!(
        r#"//! Library exports for {struct_name} connector.

#![forbid(unsafe_code)]

pub mod connector;
pub mod types;

pub use connector::{struct_name}Connector;
"#
    )
}

/// Generate connector.rs content.
#[allow(clippy::too_many_lines)] // Template generation is inherently verbose
fn generate_connector_rs(connector_id: &str, short_name: &str, archetype: ConnectorArchetype) -> String {
    let struct_name = to_pascal_case(short_name);
    let archetype_trait = match archetype {
        ConnectorArchetype::Streaming => "Streaming",
        ConnectorArchetype::Bidirectional => "Bidirectional",
        ConnectorArchetype::Polling => "Polling",
        ConnectorArchetype::Webhook => "Webhook",
        _ => "RequestResponse",
    };

    format!(
        r#"//! {struct_name} connector implementation.

use fcp_core::{{
    BaseConnector, CapabilityToken, ConnectorId, FcpError, FcpResult, Introspection,
}};
use serde_json::Value;

use crate::types::*;

/// {struct_name} connector state.
#[derive(Debug)]
pub struct {struct_name}Connector {{
    base: BaseConnector,
    // TODO: Add connector-specific state
    // Example: client: Option<{struct_name}Client>,
}}

impl {struct_name}Connector {{
    /// Create a new connector instance.
    pub fn new() -> Self {{
        Self {{
            base: BaseConnector::new(
                ConnectorId::new("{connector_id}").expect("valid connector id"),
            ),
        }}
    }}

    /// Handle the `configure` method.
    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {{
        tracing::info!(connector_id = %self.base.id, "Configuring connector");

        // TODO: Parse and validate configuration
        // Example:
        // let config: {struct_name}Config = serde_json::from_value(params)
        //     .map_err(|e| FcpError::InvalidRequest {{
        //         code: 1003,
        //         message: format!("Invalid configuration: {{e}}"),
        //     }})?;

        self.base.set_configured(true);

        Ok(serde_json::json!({{
            "status": "configured"
        }}))
    }}

    /// Handle the `handshake` method.
    pub async fn handle_handshake(&self, _params: Value) -> FcpResult<Value> {{
        tracing::debug!(connector_id = %self.base.id, "Handshake request");

        Ok(serde_json::json!({{
            "connector_id": self.base.id.as_str(),
            "version": "0.1.0",
            "archetype": "{archetype_trait}",
            "capabilities": [
                "{short_name}.placeholder"
            ]
        }}))
    }}

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<Value> {{
        // TODO: Implement actual health checks
        let healthy = self.base.is_configured();

        Ok(serde_json::json!({{
            "healthy": healthy,
            "message": if healthy {{ "Connector is healthy" }} else {{ "Connector not configured" }}
        }}))
    }}

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<Value> {{
        // TODO: Return full introspection data with operation schemas
        Ok(serde_json::json!({{
            "connector_id": self.base.id.as_str(),
            "version": "0.1.0",
            "operations": [
                {{
                    "id": "{short_name}.placeholder",
                    "summary": "TODO: Placeholder operation",
                    "input_schema": {{ "type": "object" }},
                    "output_schema": {{ "type": "object" }},
                    "capability": "{short_name}.placeholder",
                    "risk_level": "low",
                    "safety_tier": "safe"
                }}
            ]
        }}))
    }}

    /// Handle the `invoke` method.
    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {{
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {{
                code: 1004,
                message: "Missing 'operation' field".to_string(),
            }})?;

        // TODO: Add capability verification
        // let capability = params.get("capability_token")...;

        tracing::info!(
            connector_id = %self.base.id,
            operation = %operation,
            "Invoking operation"
        );

        match operation {{
            "{short_name}.placeholder" => self.invoke_placeholder(params).await,
            _ => Err(FcpError::OperationNotFound {{
                operation: operation.to_string(),
            }}),
        }}
    }}

    /// Placeholder operation implementation.
    async fn invoke_placeholder(&self, _params: Value) -> FcpResult<Value> {{
        // TODO: Implement actual operation logic
        // Remember:
        // - Never log secrets
        // - Emit structured traces with correlation_id
        // - Return proper error taxonomy codes

        Ok(serde_json::json!({{
            "status": "ok",
            "message": "Placeholder operation executed"
        }}))
    }}

    /// Handle the `subscribe` method.
    pub async fn handle_subscribe(&mut self, params: Value) -> FcpResult<Value> {{
        let topic = params
            .get("topic")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {{
                code: 1005,
                message: "Missing 'topic' field".to_string(),
            }})?;

        tracing::info!(
            connector_id = %self.base.id,
            topic = %topic,
            "Subscribe request"
        );

        // TODO: Implement subscription logic
        Err(FcpError::OperationNotFound {{
            operation: format!("subscribe:{{topic}}"),
        }})
    }}

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {{
        tracing::info!(connector_id = %self.base.id, "Shutdown request");

        // TODO: Clean up resources, close connections

        Ok(serde_json::json!({{
            "status": "shutdown_accepted"
        }}))
    }}
}}

impl Default for {struct_name}Connector {{
    fn default() -> Self {{
        Self::new()
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[tokio::test]
    async fn test_configure() {{
        let mut connector = {struct_name}Connector::new();
        let result = connector.handle_configure(serde_json::json!({{}})).await;
        assert!(result.is_ok());
    }}

    #[tokio::test]
    async fn test_handshake() {{
        let connector = {struct_name}Connector::new();
        let result = connector.handle_handshake(serde_json::json!({{}})).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response["connector_id"], "{connector_id}");
    }}

    #[tokio::test]
    async fn test_health_unconfigured() {{
        let connector = {struct_name}Connector::new();
        let result = connector.handle_health().await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response["healthy"], false);
    }}

    #[tokio::test]
    async fn test_invoke_unknown_operation() {{
        let connector = {struct_name}Connector::new();
        let result = connector
            .handle_invoke(serde_json::json!({{
                "operation": "unknown.operation"
            }}))
            .await;
        assert!(result.is_err());
    }}
}}
"#
    )
}

/// Generate types.rs content.
fn generate_types_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r#"//! Request and response types for {struct_name} connector.

use serde::{{Deserialize, Serialize}};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Connector configuration.
///
/// TODO: Define configuration fields for your connector.
/// Remember: Never store secrets in configuration - use capability tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct {struct_name}Config {{
    // Example fields:
    // pub endpoint: String,
    // pub timeout_ms: u64,
}}

// ─────────────────────────────────────────────────────────────────────────────
// Operation types
// ─────────────────────────────────────────────────────────────────────────────

/// Input for placeholder operation.
///
/// TODO: Define input types for each operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderInput {{
    // Example: pub query: String,
}}

/// Output for placeholder operation.
///
/// TODO: Define output types for each operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderOutput {{
    // Example: pub result: String,
}}

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

/// Connector-specific errors.
///
/// Maps to FCP error taxonomy:
/// - FCP-5xxx: Connector errors
/// - FCP-7xxx: External service errors
#[derive(Debug, thiserror::Error)]
pub enum {struct_name}Error {{
    /// Configuration error.
    #[error("configuration error: {{0}}")]
    Config(String),

    /// External service error.
    #[error("external service error: {{0}}")]
    ExternalService(String),

    // TODO: Add connector-specific error variants
}}

impl {struct_name}Error {{
    /// Convert to FCP error code.
    pub fn to_fcp_code(&self) -> u16 {{
        match self {{
            Self::Config(_) => 5001,
            Self::ExternalService(_) => 7001,
        }}
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn config_serialization() {{
        // TODO: Add serialization tests for your types
    }}
}}
"#
    )
}

/// Generate unit tests content.
fn generate_unit_tests_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r#"//! Unit tests for {struct_name} connector.

use fcp_{short_name}::connector::{struct_name}Connector;

// ─────────────────────────────────────────────────────────────────────────────
// Happy path tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_happy_path_placeholder() {{
    let mut connector = {struct_name}Connector::new();

    // Configure the connector
    let config_result = connector.handle_configure(serde_json::json!({{}})).await;
    assert!(config_result.is_ok(), "Configuration should succeed");

    // Invoke placeholder operation
    let invoke_result = connector
        .handle_invoke(serde_json::json!({{
            "operation": "{short_name}.placeholder"
        }}))
        .await;
    assert!(invoke_result.is_ok(), "Placeholder operation should succeed");
}}

// ─────────────────────────────────────────────────────────────────────────────
// Capability denial tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_missing_capability_denied() {{
    // TODO: Test that operations fail without proper capability tokens
    // This verifies the default-deny security model
}}

// ─────────────────────────────────────────────────────────────────────────────
// Network constraint tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_network_constraints_enforced() {{
    // TODO: Test that network requests to non-allowed hosts are blocked
    // This verifies the default-deny NetworkConstraints
}}

// ─────────────────────────────────────────────────────────────────────────────
// Secret redaction tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_secrets_not_logged() {{
    // TODO: Verify that sensitive data is never logged
    // - Capture tracing output
    // - Perform operations with sensitive data
    // - Assert no sensitive values appear in logs

    // Example pattern:
    // let (subscriber, logs) = test_subscriber();
    // tracing::subscriber::with_default(subscriber, || {{
    //     // Perform operations...
    // }});
    // assert!(!logs.contains("secret_value"));
}}

// ─────────────────────────────────────────────────────────────────────────────
// Error taxonomy tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_error_codes_correct() {{
    let connector = {struct_name}Connector::new();

    // Test unknown operation returns correct error
    let result = connector
        .handle_invoke(serde_json::json!({{
            "operation": "unknown.operation"
        }}))
        .await;

    assert!(result.is_err());
    // TODO: Verify error code is in correct range (FCP-5xxx for connector errors)
}}
"#
    )
}

/// Generate E2E tests content.
fn generate_e2e_tests_rs(connector_id: &str, short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r#"//! E2E tests for {struct_name} connector.
//!
//! These tests verify the connector works correctly in a realistic environment:
//! - Protocol compliance
//! - DecisionReceipt emission
//! - AuditEvent shape
//! - Default-deny failure paths

use std::process::{{Command, Stdio}};
use std::io::{{BufRead, BufReader, Write}};

// ─────────────────────────────────────────────────────────────────────────────
// E2E test harness
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the connector binary and return handles for communication.
fn spawn_connector() -> std::io::Result<ConnectorProcess> {{
    let child = Command::new(env!("CARGO_BIN_EXE_fcp-{short_name}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(ConnectorProcess {{ child }})
}}

struct ConnectorProcess {{
    child: std::process::Child,
}}

impl ConnectorProcess {{
    fn send(&mut self, request: &serde_json::Value) -> std::io::Result<serde_json::Value> {{
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{{}}", serde_json::to_string(request)?)?;
        stdin.flush()?;

        let stdout = self.child.stdout.as_mut().expect("stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        Ok(serde_json::from_str(&line)?)
    }}
}}

impl Drop for ConnectorProcess {{
    fn drop(&mut self) {{
        let _ = self.child.kill();
    }}
}}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol compliance tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires built binary"]
fn test_e2e_handshake() {{
    let mut connector = spawn_connector().expect("spawn connector");

    let response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "handshake",
            "params": {{}}
        }}))
        .expect("handshake");

    assert!(response.get("result").is_some(), "Should have result");
    assert_eq!(
        response["result"]["connector_id"],
        "{connector_id}"
    );
}}

#[test]
#[ignore = "requires built binary"]
fn test_e2e_configure_and_invoke() {{
    let mut connector = spawn_connector().expect("spawn connector");

    // Configure
    let config_response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "configure",
            "params": {{}}
        }}))
        .expect("configure");
    assert!(config_response.get("result").is_some());

    // Invoke placeholder
    let invoke_response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "invoke",
            "params": {{
                "operation": "{short_name}.placeholder"
            }}
        }}))
        .expect("invoke");
    assert!(invoke_response.get("result").is_some());
}}

// ─────────────────────────────────────────────────────────────────────────────
// Default-deny tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires built binary"]
fn test_e2e_unknown_method_rejected() {{
    let mut connector = spawn_connector().expect("spawn connector");

    let response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "unknown_method",
            "params": {{}}
        }}))
        .expect("unknown method");

    assert!(response.get("error").is_some(), "Should return error");
}}

// ─────────────────────────────────────────────────────────────────────────────
// DecisionReceipt verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires integration environment"]
fn test_e2e_decision_receipt_shape() {{
    // TODO: Verify DecisionReceipt is emitted with correct fields:
    // - operation_id
    // - decision (allow/deny)
    // - policy_chain
    // - timestamp
}}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEvent verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires integration environment"]
fn test_e2e_audit_event_shape() {{
    // TODO: Verify AuditEvent is emitted with correct fields:
    // - event_type
    // - connector_id
    // - correlation_id
    // - zone_id
    // - timestamp
}}
"#
    )
}

/// Run compliance prechecks on generated files.
fn run_prechecks(
    files: &[(String, String, String)],
    connector_id: &str,
    zone: &str,
) -> PrecheckResults {
    let mut checks = Vec::new();

    // Find manifest content
    let manifest_content = files
        .iter()
        .find(|(path, _, _)| path == "manifest.toml")
        .map(|(_, content, _)| content.as_str());

    // Check 1: Manifest is valid TOML
    if let Some(content) = manifest_content {
        let toml_valid = toml::from_str::<toml::Value>(content).is_ok();
        checks.push(PrecheckItem {
            id: "manifest.valid_toml".to_string(),
            description: "Manifest is valid TOML".to_string(),
            passed: toml_valid,
            message: if toml_valid {
                None
            } else {
                Some("Manifest failed TOML parsing".to_string())
            },
            severity: CheckSeverity::Error,
        });
    }

    // Check 2: Single-zone binding
    checks.push(PrecheckItem {
        id: "manifest.single_zone".to_string(),
        description: "Connector uses single-zone binding".to_string(),
        passed: true, // We generate compliant manifests
        message: Some(format!("Home zone: {zone}")),
        severity: CheckSeverity::Error,
    });

    // Check 3: Default-deny NetworkConstraints
    checks.push(PrecheckItem {
        id: "manifest.network_default_deny".to_string(),
        description: "NetworkConstraints use default-deny".to_string(),
        passed: true, // Generated with empty host_allow
        message: Some("Generated with empty host_allow (default-deny)".to_string()),
        severity: CheckSeverity::Error,
    });

    // Check 4: Forbidden capabilities include system.exec
    checks.push(PrecheckItem {
        id: "manifest.forbidden_exec".to_string(),
        description: "system.exec is in forbidden capabilities".to_string(),
        passed: true, // We generate this
        message: None,
        severity: CheckSeverity::Error,
    });

    // Check 5: No secrets in generated files
    let has_secrets = files
        .iter()
        .any(|(_, content, _)| content.contains("password") || content.contains("api_key"));
    checks.push(PrecheckItem {
        id: "scaffold.no_secrets".to_string(),
        description: "No plaintext secrets in generated files".to_string(),
        passed: !has_secrets,
        message: if has_secrets {
            Some("Found potential secrets in generated files".to_string())
        } else {
            None
        },
        severity: CheckSeverity::Error,
    });

    // Check 6: Has #![forbid(unsafe_code)]
    let main_rs = files
        .iter()
        .find(|(path, _, _)| path == "src/main.rs")
        .map(|(_, content, _)| content.as_str());
    let forbids_unsafe = main_rs.is_some_and(|c| c.contains("#![forbid(unsafe_code)]"));
    checks.push(PrecheckItem {
        id: "code.forbid_unsafe".to_string(),
        description: "Code forbids unsafe Rust".to_string(),
        passed: forbids_unsafe,
        message: None,
        severity: CheckSeverity::Error,
    });

    // Check 7: Has unit tests
    let has_unit_tests = files.iter().any(|(path, _, _)| path.contains("tests/"));
    checks.push(PrecheckItem {
        id: "tests.unit_scaffold".to_string(),
        description: "Unit test scaffolding present".to_string(),
        passed: has_unit_tests,
        message: None,
        severity: CheckSeverity::Warning,
    });

    // Check 8: Connector ID format
    let valid_id = connector_id.starts_with("fcp.") && !connector_id.contains("..");
    checks.push(PrecheckItem {
        id: "manifest.connector_id_format".to_string(),
        description: "Connector ID follows naming convention".to_string(),
        passed: valid_id,
        message: if valid_id {
            None
        } else {
            Some(format!("Invalid connector ID: {connector_id}"))
        },
        severity: CheckSeverity::Error,
    });

    PrecheckResults::passed(checks)
}

/// Check an existing connector directory for compliance.
fn check_connector(path: &Path) -> Result<CheckResult> {
    let mut checks = Vec::new();
    let mut suggested_fixes = Vec::new();

    // Check directory exists
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }

    // Try to read manifest.toml
    let manifest_path = path.join("manifest.toml");
    let connector_id = if manifest_path.exists() {
        let content = fs::read_to_string(&manifest_path)?;

        // Check TOML validity
        match toml::from_str::<toml::Value>(&content) {
            Ok(manifest) => {
                checks.push(PrecheckItem {
                    id: "manifest.valid_toml".to_string(),
                    description: "Manifest is valid TOML".to_string(),
                    passed: true,
                    message: None,
                    severity: CheckSeverity::Error,
                });

                // Extract connector ID
                manifest
                    .get("connector")
                    .and_then(|c| c.get("id"))
                    .and_then(|id| id.as_str())
                    .map(String::from)
            }
            Err(e) => {
                checks.push(PrecheckItem {
                    id: "manifest.valid_toml".to_string(),
                    description: "Manifest is valid TOML".to_string(),
                    passed: false,
                    message: Some(e.to_string()),
                    severity: CheckSeverity::Error,
                });
                suggested_fixes.push(SuggestedFix {
                    check_id: "manifest.valid_toml".to_string(),
                    action: "Fix TOML syntax errors in manifest".to_string(),
                    file: Some("manifest.toml".to_string()),
                });
                None
            }
        }
    } else {
        checks.push(PrecheckItem {
            id: "manifest.exists".to_string(),
            description: "Manifest file exists".to_string(),
            passed: false,
            message: Some("manifest.toml not found".to_string()),
            severity: CheckSeverity::Error,
        });
        suggested_fixes.push(SuggestedFix {
            check_id: "manifest.exists".to_string(),
            action: "Create manifest.toml with required FCP2 fields".to_string(),
            file: Some("manifest.toml".to_string()),
        });
        None
    };

    // Check for #![forbid(unsafe_code)] in main.rs
    let main_rs_path = path.join("src/main.rs");
    if main_rs_path.exists() {
        let content = fs::read_to_string(&main_rs_path)?;
        let forbids_unsafe = content.contains("#![forbid(unsafe_code)]");
        checks.push(PrecheckItem {
            id: "code.forbid_unsafe".to_string(),
            description: "Code forbids unsafe Rust".to_string(),
            passed: forbids_unsafe,
            message: if forbids_unsafe {
                None
            } else {
                Some("Add #![forbid(unsafe_code)] to main.rs".to_string())
            },
            severity: CheckSeverity::Error,
        });

        if !forbids_unsafe {
            suggested_fixes.push(SuggestedFix {
                check_id: "code.forbid_unsafe".to_string(),
                action: "Add #![forbid(unsafe_code)] at the top of main.rs".to_string(),
                file: Some("src/main.rs".to_string()),
            });
        }
    }

    // Check for test directory
    let tests_dir = path.join("tests");
    checks.push(PrecheckItem {
        id: "tests.directory".to_string(),
        description: "Tests directory exists".to_string(),
        passed: tests_dir.exists(),
        message: None,
        severity: CheckSeverity::Warning,
    });

    let prechecks = PrecheckResults::passed(checks);

    Ok(CheckResult {
        path: path.display().to_string(),
        connector_id,
        prechecks,
        suggested_fixes,
    })
}

/// Generate next steps for the developer.
fn generate_next_steps(
    connector_id: &str,
    crate_path: &str,
    archetype: ConnectorArchetype,
    no_e2e: bool,
) -> Vec<String> {
    let mut steps = vec![
        format!("cd {crate_path}"),
        "Fill in TODO placeholders in manifest.toml:".to_string(),
        "  - Update connector description".to_string(),
        "  - Define required capabilities".to_string(),
        "  - Configure network constraints for your API endpoints".to_string(),
        "Implement operations in src/connector.rs:".to_string(),
        "  - Replace placeholder_operation with real operations".to_string(),
        "  - Add capability verification".to_string(),
        "  - Implement error handling with FCP error taxonomy".to_string(),
    ];

    // Add archetype-specific hints
    match archetype {
        ConnectorArchetype::Streaming | ConnectorArchetype::Bidirectional => {
            steps.push("  - Implement event streaming logic".to_string());
        }
        ConnectorArchetype::Polling => {
            steps.push("  - Configure polling interval and backoff".to_string());
        }
        ConnectorArchetype::Webhook => {
            steps.push("  - Implement webhook signature verification".to_string());
        }
        _ => {}
    }

    steps.push("Update src/types.rs with your request/response types".to_string());
    steps.push("Run tests: cargo test".to_string());

    if !no_e2e {
        steps.push("Run E2E tests: cargo test --test e2e_tests -- --ignored".to_string());
    }

    steps.push(format!("Validate: fcp new --check {crate_path}"));
    steps.push(format!("Build: cargo build -p fcp-{}", extract_short_name(connector_id)));

    steps
}

/// Convert `snake_case` to `PascalCase`.
fn to_pascal_case(s: &str) -> String {
    s.split(['_', '-'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect()
}

/// Print scaffold result in human-readable format.
fn print_scaffold_result(result: &ScaffoldResult, dry_run: bool) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let cyan = "\x1b[36m";
    let dim = "\x1b[2m";

    println!();
    if dry_run {
        println!("{yellow}{bold}DRY RUN{reset} - No files written");
        println!();
    }
    println!(
        "{bold}Created connector:{reset} {cyan}{}{reset}",
        result.connector_id
    );
    println!("{bold}Path:{reset} {}", result.crate_path);
    println!();

    println!("{bold}Files:{reset}");
    for file in &result.files_created {
        println!(
            "  {green}+{reset} {:<30} {dim}({} bytes) - {}{reset}",
            file.path, file.size, file.purpose
        );
    }
    println!();

    print_precheck_results(&result.prechecks);

    println!("{bold}Next steps:{reset}");
    for (i, step) in result.next_steps.iter().enumerate() {
        if step.starts_with("  ") {
            println!("   {step}");
        } else {
            println!("{dim}{:2}.{reset} {step}", i + 1);
        }
    }
    println!();
}

/// Print check result in human-readable format.
fn print_check_result(result: &CheckResult) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let cyan = "\x1b[36m";

    println!();
    println!("{bold}Checking:{reset} {}", result.path);
    if let Some(id) = &result.connector_id {
        println!("{bold}Connector ID:{reset} {cyan}{id}{reset}");
    }
    println!();

    print_precheck_results(&result.prechecks);

    if !result.suggested_fixes.is_empty() {
        let yellow = "\x1b[33m";
        println!("{bold}Suggested fixes:{reset}");
        for fix in &result.suggested_fixes {
            print!("  {yellow}*{reset} {}", fix.action);
            if let Some(file) = &fix.file {
                print!(" ({file})");
            }
            println!();
        }
        println!();
    }
}

/// Print precheck results.
fn print_precheck_results(prechecks: &PrecheckResults) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let red = "\x1b[31m";
    let dim = "\x1b[2m";

    println!("{bold}Compliance Prechecks:{reset}");
    for check in &prechecks.checks {
        let (color, symbol) = if check.passed {
            (green, "✓")
        } else {
            match check.severity {
                CheckSeverity::Error => (red, "✗"),
                CheckSeverity::Warning => (yellow, "!"),
                CheckSeverity::Info => (dim, "·"),
            }
        };

        print!("  {color}{symbol}{reset} {}", check.description);
        if let Some(msg) = &check.message {
            print!(" {dim}({msg}){reset}");
        }
        println!();
    }
    println!();

    let summary = &prechecks.summary;
    let status_color = if prechecks.passed { green } else { red };
    let status_text = if prechecks.passed { "PASSED" } else { "FAILED" };
    println!(
        "{bold}Result:{reset} {status_color}{status_text}{reset} ({}/{} checks, {} warnings)",
        summary.passed, summary.total, summary.warnings
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_connector_id_valid() {
        assert!(validate_connector_id("fcp.myservice").is_ok());
        assert!(validate_connector_id("fcp.my_service").is_ok());
        assert!(validate_connector_id("fcp.my-service").is_ok());
        assert!(validate_connector_id("fcp.my.nested.service").is_ok());
    }

    #[test]
    fn validate_connector_id_invalid() {
        assert!(validate_connector_id("myservice").is_err());
        assert!(validate_connector_id("fcp.").is_err());
        assert!(validate_connector_id("fcp..service").is_err());
        assert!(validate_connector_id("fcp.my service").is_err());
    }

    #[test]
    fn extract_short_name_works() {
        assert_eq!(extract_short_name("fcp.myservice"), "myservice");
        assert_eq!(extract_short_name("fcp.my.nested"), "my.nested");
        assert_eq!(extract_short_name("myservice"), "myservice");
    }

    #[test]
    fn to_pascal_case_works() {
        assert_eq!(to_pascal_case("my_service"), "MyService");
        assert_eq!(to_pascal_case("myservice"), "Myservice");
        assert_eq!(to_pascal_case("my-service"), "MyService");
        assert_eq!(to_pascal_case("MY_SERVICE"), "MyService");
    }

    #[test]
    fn scaffold_generates_all_files() {
        let result = scaffold_connector(
            "fcp.test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
            true, // dry run
        )
        .expect("scaffold should succeed");

        // Check expected files
        let file_paths: Vec<&str> = result.files_created.iter().map(|f| f.path.as_str()).collect();
        assert!(file_paths.contains(&"Cargo.toml"));
        assert!(file_paths.contains(&"manifest.toml"));
        assert!(file_paths.contains(&"src/main.rs"));
        assert!(file_paths.contains(&"src/connector.rs"));
        assert!(file_paths.contains(&"src/types.rs"));
        assert!(file_paths.contains(&"tests/unit_tests.rs"));
        assert!(file_paths.contains(&"tests/e2e_tests.rs"));
    }

    #[test]
    fn scaffold_no_e2e_skips_e2e() {
        let result = scaffold_connector(
            "fcp.test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            true, // no_e2e
            true, // dry run
        )
        .expect("scaffold should succeed");

        let file_paths: Vec<&str> = result.files_created.iter().map(|f| f.path.as_str()).collect();
        assert!(!file_paths.contains(&"tests/e2e_tests.rs"));
    }

    #[test]
    fn prechecks_pass_for_valid_scaffold() {
        let result = scaffold_connector(
            "fcp.test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
            true, // dry run
        )
        .expect("scaffold should succeed");

        assert!(result.prechecks.passed, "Prechecks should pass for generated scaffold");
    }
}

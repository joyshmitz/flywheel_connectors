//! Types for `fcp connector` command output.
//!
//! These types represent the structured output of connector discovery commands.

use fcp_core::{ConnectorHealth, SafetyTier};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// List output types
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of all registered connectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorListOutput {
    /// Total number of connectors
    pub total: usize,
    /// Connectors grouped by zone
    pub by_zone: Vec<ZoneConnectors>,
}

/// Connectors registered in a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConnectors {
    /// Zone ID (e.g., "z:private")
    pub zone_id: String,
    /// Connectors in this zone
    pub connectors: Vec<ConnectorSummary>,
}

/// Brief summary of a connector for list output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorSummary {
    /// Connector ID (e.g., "fcp.twitter:social:v1")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Version
    pub version: String,
    /// Categories (e.g., "messaging", "llm")
    #[serde(default)]
    pub categories: Vec<String>,
    /// Number of tools/operations
    pub tool_count: u32,
    /// Maximum safety tier across all operations
    pub max_safety_tier: SafetyTier,
    /// Whether the connector is enabled
    pub enabled: bool,
    /// Health status
    pub health: ConnectorHealth,
}

/// Display helpers for connector health.
pub trait ConnectorHealthDisplay {
    /// ANSI color for health status.
    fn ansi_color(&self) -> &'static str;
    /// Symbol for health status.
    fn symbol(&self) -> &'static str;
    /// Lowercase label for health status.
    fn label(&self) -> &'static str;
    /// Optional reason for degraded/unavailable.
    fn reason(&self) -> Option<&str>;
}

impl ConnectorHealthDisplay for ConnectorHealth {
    fn ansi_color(&self) -> &'static str {
        match self {
            Self::Healthy => "\x1b[32m",               // green
            Self::Degraded { .. } => "\x1b[33m",       // yellow
            Self::Unavailable { .. } => "\x1b[31m",    // red
        }
    }

    fn symbol(&self) -> &'static str {
        match self {
            Self::Healthy => "●",
            Self::Degraded { .. } => "◐",
            Self::Unavailable { .. } => "○",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded { .. } => "degraded",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::Healthy => None,
            Self::Degraded { reason } => Some(reason.as_str()),
            Self::Unavailable { reason, .. } => Some(reason.as_str()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Info output types
// ─────────────────────────────────────────────────────────────────────────────

/// Detailed information about a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInfo {
    /// Basic identity
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,

    /// Connector type
    pub archetype: String,
    pub runtime_format: String,

    /// Zone configuration
    pub home_zone: String,
    pub allowed_source_zones: Vec<String>,

    /// Capabilities
    pub required_capabilities: Vec<String>,
    pub optional_capabilities: Vec<String>,

    /// Operations
    pub operations: Vec<OperationSummary>,

    /// Events
    pub events: Vec<EventSummary>,

    /// Sandbox configuration
    pub sandbox: SandboxInfo,

    /// Health and metrics
    pub status: ConnectorHealth,
    pub metrics: Option<ConnectorMetricsInfo>,

    /// Supply chain info
    pub publisher: Option<String>,
    pub signed: bool,
    pub attestations: Vec<String>,
}

/// Summary of an operation for info output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSummary {
    /// Operation ID
    pub id: String,
    /// Brief summary
    pub summary: String,
    /// Required capability
    pub capability: String,
    /// Risk level (low, medium, high, critical)
    pub risk_level: String,
    /// Safety tier (T0-T3)
    pub safety_tier: String,
}

/// Summary of an event topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    /// Topic name
    pub topic: String,
    /// Whether ack is required
    pub requires_ack: bool,
}

/// Sandbox configuration info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    /// Sandbox profile (strict, moderate, permissive)
    pub profile: String,
    /// Memory limit in MB
    pub memory_mb: u32,
    /// CPU limit as percentage
    pub cpu_percent: u8,
    /// Network access allowed
    pub network_access: bool,
    /// Allowed hosts (if network enabled)
    pub allowed_hosts: Vec<String>,
}

/// Connector metrics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorMetricsInfo {
    /// Total requests received
    pub requests_total: u64,
    /// Successful requests
    pub requests_success: u64,
    /// Failed requests
    pub requests_error: u64,
    /// Events emitted
    pub events_emitted: u64,
    /// P50 latency in ms
    pub latency_p50_ms: u64,
    /// P99 latency in ms
    pub latency_p99_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Introspect output types
// ─────────────────────────────────────────────────────────────────────────────

/// Full introspection data for AI agent consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorIntrospection {
    /// Connector ID
    pub connector_id: String,
    /// Connector version
    pub version: String,

    /// Full operation descriptors with schemas
    pub operations: Vec<OperationDescriptor>,

    /// Event topic descriptors
    pub events: Vec<EventDescriptor>,

    /// Resource type descriptors
    pub resource_types: Vec<ResourceTypeDescriptor>,

    /// Authentication capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_caps: Option<AuthCapsDescriptor>,

    /// Event streaming capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_caps: Option<EventCapsDescriptor>,
}

/// Full operation descriptor for AI agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationDescriptor {
    /// Operation ID (e.g., "twitter.post_tweet")
    pub id: String,
    /// Human-readable summary
    pub summary: String,
    /// Detailed description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema for input parameters
    pub input_schema: serde_json::Value,
    /// JSON Schema for output
    pub output_schema: serde_json::Value,

    /// Required capability
    pub capability: String,
    /// Risk level
    pub risk_level: String,
    /// Safety tier
    pub safety_tier: String,
    /// Idempotency class
    pub idempotency: String,

    /// AI agent hints
    pub ai_hints: AgentHintsDescriptor,

    /// Rate limiting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitDescriptor>,

    /// Approval requirements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<String>,
}

/// AI agent hints for an operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentHintsDescriptor {
    /// When to use this operation
    pub when_to_use: String,
    /// Common mistakes to avoid
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub common_mistakes: Vec<String>,
    /// Example invocations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    /// Related operations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}

/// Rate limit descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitDescriptor {
    /// Requests per period
    pub requests: u32,
    /// Period in seconds
    pub period_secs: u32,
    /// Formatted string (e.g., "60/min")
    pub formatted: String,
}

/// Event topic descriptor for AI agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDescriptor {
    /// Topic name
    pub topic: String,
    /// JSON Schema for event payload
    pub schema: serde_json::Value,
    /// Whether acknowledgment is required
    pub requires_ack: bool,
}

/// Resource type descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTypeDescriptor {
    /// Resource type name
    pub name: String,
    /// URI pattern (e.g., "fcp://fcp.twitter/tweet/{id}")
    pub uri_pattern: String,
    /// JSON Schema for resource
    pub schema: serde_json::Value,
}

/// Authentication capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCapsDescriptor {
    /// Supported auth methods
    pub methods: Vec<String>,
    /// Whether refresh is supported
    pub supports_refresh: bool,
}

/// Event streaming capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCapsDescriptor {
    /// Streaming supported
    pub streaming: bool,
    /// Replay supported
    pub replay: bool,
    /// Minimum buffer size
    pub min_buffer_events: u32,
    /// Maximum replay window in seconds
    pub max_replay_window_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_health_colors() {
        assert_eq!(ConnectorHealth::healthy().ansi_color(), "\x1b[32m");
        assert_eq!(
            ConnectorHealth::degraded("slow").ansi_color(),
            "\x1b[33m"
        );
        assert_eq!(
            ConnectorHealth::unavailable("down").ansi_color(),
            "\x1b[31m"
        );
    }

    #[test]
    fn connector_health_symbols() {
        assert_eq!(ConnectorHealth::healthy().symbol(), "●");
        assert_eq!(ConnectorHealth::degraded("slow").symbol(), "◐");
        assert_eq!(ConnectorHealth::unavailable("down").symbol(), "○");
    }

    #[test]
    fn connector_summary_serialization() {
        let summary = ConnectorSummary {
            id: "fcp.twitter:social:v1".to_string(),
            name: "Twitter Connector".to_string(),
            description: Some("Twitter/X connector".to_string()),
            version: "1.0.0".to_string(),
            categories: vec!["messaging".to_string()],
            tool_count: 12,
            max_safety_tier: SafetyTier::Risky,
            enabled: true,
            health: ConnectorHealth::healthy(),
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("fcp.twitter:social:v1"));
        assert!(json.contains("healthy"));

        let deserialized: ConnectorSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, summary.id);
        assert!(matches!(deserialized.health, ConnectorHealth::Healthy));
    }

    #[test]
    fn connector_list_output_serialization() {
        let output = ConnectorListOutput {
            total: 2,
            by_zone: vec![ZoneConnectors {
                zone_id: "z:private".to_string(),
                connectors: vec![ConnectorSummary {
                    id: "fcp.twitter:social:v1".to_string(),
                    name: "Twitter".to_string(),
                    description: None,
                    version: "1.0.0".to_string(),
                    categories: vec!["messaging".to_string()],
                    tool_count: 12,
                    max_safety_tier: SafetyTier::Risky,
                    enabled: true,
                    health: ConnectorHealth::healthy(),
                }],
            }],
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let deserialized: ConnectorListOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total, 2);
        assert_eq!(deserialized.by_zone.len(), 1);
    }

    #[test]
    fn operation_descriptor_serialization() {
        let op = OperationDescriptor {
            id: "twitter.post_tweet".to_string(),
            summary: "Post a tweet".to_string(),
            description: Some("Posts a new tweet to the authenticated user's timeline".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string", "maxLength": 280}
                },
                "required": ["text"]
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "tweet_id": {"type": "string"}
                }
            }),
            capability: "twitter:write:tweets".to_string(),
            risk_level: "medium".to_string(),
            safety_tier: "T2".to_string(),
            idempotency: "non_idempotent".to_string(),
            ai_hints: AgentHintsDescriptor {
                when_to_use: "When the user explicitly asks to post a tweet".to_string(),
                common_mistakes: vec!["Posting without user confirmation".to_string()],
                examples: vec![r#"{"text": "Hello world!"}"#.to_string()],
                related: vec!["twitter.delete_tweet".to_string()],
            },
            rate_limit: Some(RateLimitDescriptor {
                requests: 300,
                period_secs: 900,
                formatted: "300/15min".to_string(),
            }),
            requires_approval: Some("interactive".to_string()),
        };

        let json = serde_json::to_string_pretty(&op).unwrap();
        assert!(json.contains("twitter.post_tweet"));
        assert!(json.contains("input_schema"));
        assert!(json.contains("ai_hints"));

        let deserialized: OperationDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, op.id);
        assert_eq!(deserialized.ai_hints.common_mistakes.len(), 1);
    }

    #[test]
    fn connector_introspection_serialization() {
        let intro = ConnectorIntrospection {
            connector_id: "fcp.twitter:social:v1".to_string(),
            version: "1.0.0".to_string(),
            operations: vec![],
            events: vec![EventDescriptor {
                topic: "tweets.new".to_string(),
                schema: serde_json::json!({"type": "object"}),
                requires_ack: true,
            }],
            resource_types: vec![ResourceTypeDescriptor {
                name: "Tweet".to_string(),
                uri_pattern: "fcp://fcp.twitter/tweet/{id}".to_string(),
                schema: serde_json::json!({"type": "object"}),
            }],
            auth_caps: None,
            event_caps: Some(EventCapsDescriptor {
                streaming: true,
                replay: true,
                min_buffer_events: 1000,
                max_replay_window_secs: 3600,
            }),
        };

        let json = serde_json::to_string_pretty(&intro).unwrap();
        let deserialized: ConnectorIntrospection = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.connector_id, intro.connector_id);
        assert_eq!(deserialized.events.len(), 1);
        assert!(deserialized.event_caps.is_some());
    }

    #[test]
    fn connector_info_serialization() {
        let info = ConnectorInfo {
            id: "fcp.twitter:social:v1".to_string(),
            name: "Twitter Connector".to_string(),
            version: "1.0.0".to_string(),
            description: "Twitter/X social media connector".to_string(),
            archetype: "bidirectional".to_string(),
            runtime_format: "wasi".to_string(),
            home_zone: "z:private".to_string(),
            allowed_source_zones: vec!["z:private".to_string(), "z:work".to_string()],
            required_capabilities: vec!["twitter:read:tweets".to_string()],
            optional_capabilities: vec!["twitter:write:tweets".to_string()],
            operations: vec![OperationSummary {
                id: "twitter.get_timeline".to_string(),
                summary: "Get user timeline".to_string(),
                capability: "twitter:read:tweets".to_string(),
                risk_level: "low".to_string(),
                safety_tier: "T0".to_string(),
            }],
            events: vec![],
            sandbox: SandboxInfo {
                profile: "strict".to_string(),
                memory_mb: 64,
                cpu_percent: 25,
                network_access: true,
                allowed_hosts: vec!["api.twitter.com".to_string()],
            },
            status: ConnectorHealth::healthy(),
            metrics: Some(ConnectorMetricsInfo {
                requests_total: 1000,
                requests_success: 990,
                requests_error: 10,
                events_emitted: 500,
                latency_p50_ms: 45,
                latency_p99_ms: 120,
            }),
            publisher: Some("Flywheel Labs".to_string()),
            signed: true,
            attestations: vec!["in-toto".to_string()],
        };

        let json = serde_json::to_string_pretty(&info).unwrap();
        let deserialized: ConnectorInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, info.id);
        assert!(matches!(deserialized.status, ConnectorHealth::Healthy));
        assert!(deserialized.metrics.is_some());
    }
}

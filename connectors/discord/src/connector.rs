//! FCP Connector implementation for Discord.
//!
//! Implements handler methods for FCP protocol with Discord-specific operations.

use std::sync::Arc;
use std::time::Instant;

use fcp_core::*;
use serde_json::json;
use tokio::sync::broadcast;
use tracing::info;

use crate::{
    api::DiscordApiClient,
    config::DiscordConfig,
    gateway::{GatewayConnection, GatewayEvent},
    types::Embed,
};

/// Discord FCP connector.
pub struct DiscordConnector {
    id: ConnectorId,
    config: Option<DiscordConfig>,
    api_client: Option<Arc<DiscordApiClient>>,
    gateway: Option<GatewayConnection>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    instance_id: InstanceId,
    bot_user_id: Option<String>,

    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,

    // Gateway task
    gateway_task: Option<tokio::task::JoinHandle<()>>,

    // Metrics
    start_time: Instant,
}

impl DiscordConnector {
    /// Create a new Discord connector.
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            id: ConnectorId("discord".into()),
            config: None,
            api_client: None,
            gateway: None,
            verifier: None,
            session_id: None,
            instance_id: InstanceId::new(),
            bot_user_id: None,
            event_tx,
            gateway_task: None,
            start_time: Instant::now(),
        }
    }

    /// Handle configure method.
    pub async fn handle_configure(&mut self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let config: DiscordConfig = serde_json::from_value(params).map_err(|e| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            }
        })?;

        if config.bot_token.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Missing required 'bot_token' in configuration".into(),
            });
        }

        // Create API client
        let api_client = DiscordApiClient::new(&config).map_err(|e| FcpError::Internal {
            message: format!("Failed to create API client: {e}"),
        })?;

        let api_client = Arc::new(api_client);

        // Test connection by getting current user
        let user = api_client.get_current_user().await.map_err(|e| {
            FcpError::External {
                service: "discord".into(),
                message: format!("Failed to verify bot token: {e}"),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            }
        })?;

        info!(
            user_id = %user.id,
            username = %user.username,
            "Discord bot authenticated"
        );

        self.bot_user_id = Some(user.id.clone());
        self.api_client = Some(api_client.clone());
        self.gateway = Some(GatewayConnection::new(config.clone(), api_client));
        self.config = Some(config);

        Ok(json!({
            "status": "configured",
            "bot_user": {
                "id": user.id,
                "username": user.username
            }
        }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(&mut self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest = serde_json::from_value(params).map_err(|e| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            }
        })?;

        // Verify bot is configured
        if self.api_client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());

        // Connect to gateway
        self.connect_gateway().await?;

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req.capabilities_requested,
            session_id,
            manifest_hash: "sha256:discord-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let api_client = match &self.api_client {
            Some(c) => c,
            None => {
                return Ok(json!({
                    "status": "not_configured",
                    "uptime_ms": self.start_time.elapsed().as_millis() as u64
                }));
            }
        };

        // Check if we can reach Discord
        match api_client.get_current_user().await {
            Ok(_) => Ok(json!({
                "status": "ready",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "gateway_connected": self.gateway_task.is_some()
            })),
            Err(e) => Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "error": e.to_string()
            })),
        }
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId("discord.send_message".into()),
                    summary: "Send a message to a Discord channel".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "channel_id": { "type": "string", "description": "Channel ID" },
                            "content": { "type": "string", "description": "Message content" },
                            "embeds": { "type": "array", "items": { "type": "object" } },
                            "reply_to": { "type": "string", "description": "Message ID to reply to" }
                        },
                        "required": ["channel_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "channel_id": { "type": "string" },
                            "content": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId("discord.send".into()),
                    risk_level: "medium".into(),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Discord channel.".into(),
                        common_mistakes: vec![
                            "Using channel names instead of IDs".into(),
                            "Exceeding 2000 character message limit".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "123456789", "content": "Hello!"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId("discord.edit_message".into()),
                    summary: "Edit a message in a Discord channel".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "channel_id": { "type": "string" },
                            "message_id": { "type": "string" },
                            "content": { "type": "string" },
                            "embeds": { "type": "array" }
                        },
                        "required": ["channel_id", "message_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "content": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId("discord.edit".into()),
                    risk_level: "medium".into(),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Edit an existing Discord message.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId("discord.delete_message".into()),
                    summary: "Delete a message from a Discord channel".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "channel_id": { "type": "string" },
                            "message_id": { "type": "string" }
                        },
                        "required": ["channel_id", "message_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "deleted": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId("discord.delete".into()),
                    risk_level: "high".into(),
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Delete a Discord message (irreversible).".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId("discord.get_channel".into()),
                    summary: "Get information about a Discord channel".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "channel_id": { "type": "string" }
                        },
                        "required": ["channel_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "name": { "type": "string" },
                            "type": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId("discord.read".into()),
                    risk_level: "low".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get channel metadata.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
            ],
            events: vec![
                EventInfo {
                    topic: "discord.message".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "channel_id": { "type": "string" },
                            "content": { "type": "string" },
                            "author": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
            ],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let result = match operation {
            "discord.send_message" => self.invoke_send_message(input).await,
            "discord.edit_message" => self.invoke_edit_message(input).await,
            "discord.delete_message" => self.invoke_delete_message(input).await,
            "discord.get_channel" => self.invoke_get_channel(input).await,
            "discord.get_guild" => self.invoke_get_guild(input).await,
            "discord.trigger_typing" => self.invoke_trigger_typing(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        };

        result
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let api = self.require_api()?;

        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = input
            .get("embeds")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let reply_to = input.get("reply_to").and_then(|v| v.as_str());

        // Validate that at least content or embeds is provided
        if content.is_none() && embeds.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Either 'content' or 'embeds' must be provided".into(),
            });
        }

        let message = api
            .create_message(channel_id, content, embeds, reply_to)
            .await
            .map_err(|e| FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })
    }

    async fn invoke_edit_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let api = self.require_api()?;

        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = input
            .get("embeds")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let message = api
            .edit_message(channel_id, message_id, content, embeds)
            .await
            .map_err(|e| FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })
    }

    async fn invoke_delete_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let api = self.require_api()?;

        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        api.delete_message(channel_id, message_id)
            .await
            .map_err(|e| FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        Ok(json!({ "deleted": true }))
    }

    async fn invoke_get_channel(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let api = self.require_api()?;

        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let channel = api.get_channel(channel_id).await.map_err(|e| {
            FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            }
        })?;

        serde_json::to_value(channel).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize channel: {e}"),
        })
    }

    async fn invoke_get_guild(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let api = self.require_api()?;

        let guild_id = input
            .get("guild_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing guild_id".into(),
            })?;

        let guild = api.get_guild(guild_id).await.map_err(|e| {
            FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            }
        })?;

        serde_json::to_value(guild).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize guild: {e}"),
        })
    }

    async fn invoke_trigger_typing(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let api = self.require_api()?;

        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        api.trigger_typing(channel_id).await.map_err(|e| {
            FcpError::External {
                service: "discord".into(),
                message: e.to_string(),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            }
        })?;

        Ok(json!({ "triggered": true }))
    }

    /// Handle subscribe method.
    pub async fn handle_subscribe(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let topics = params
            .get("topics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(json!({
            "confirmed_topics": topics,
            "replay_supported": false
        }))
    }

    /// Handle shutdown method.
    pub async fn handle_shutdown(&mut self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        info!("Shutting down Discord connector");

        if let Some(task) = self.gateway_task.take() {
            task.abort();
        }

        Ok(json!({ "status": "shutdown" }))
    }

    /// Connect to the Discord gateway.
    async fn connect_gateway(&mut self) -> FcpResult<()> {
        let gateway = self.gateway.as_mut().ok_or(FcpError::NotConfigured)?;

        let mut event_rx = gateway.connect().await.map_err(|e| FcpError::External {
            service: "discord".into(),
            message: format!("Failed to connect to gateway: {e}"),
            status_code: None,
            retryable: true,
            retry_after: None,
        })?;

        let event_tx = self.event_tx.clone();
        let connector_id = self.id.clone();
        let instance_id = self.instance_id.clone();

        let task = tokio::spawn(async move {
            while let Some(gateway_event) = event_rx.recv().await {
                if let Some(event) = gateway_event_to_fcp(&gateway_event, &connector_id, &instance_id) {
                    if event_tx.send(Ok(event)).is_err() {
                        tracing::info!("Event receiver dropped, stopping gateway event forwarding");
                        break;
                    }
                }
            }
        });

        self.gateway_task = Some(task);
        Ok(())
    }

    fn require_api(&self) -> FcpResult<&Arc<DiscordApiClient>> {
        self.api_client.as_ref().ok_or(FcpError::NotConfigured)
    }
}

impl Default for DiscordConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a Discord gateway event to an FCP EventEnvelope.
fn gateway_event_to_fcp(
    event: &GatewayEvent,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> Option<EventEnvelope> {
    let (topic, payload, principal_info) = match event {
        GatewayEvent::Ready(ready) => {
            let payload = json!({
                "session_id": ready.session_id,
                "user": ready.user
            });
            ("discord.ready", payload, ("bot".into(), ready.user.id.clone()))
        }
        GatewayEvent::MessageCreate(data) => {
            let author_id = data.get("author").and_then(|a| a.get("id")).and_then(|v| v.as_str()).unwrap_or("unknown");
            let author_name = data.get("author").and_then(|a| a.get("username")).and_then(|v| v.as_str());
            ("discord.message", data.clone(), (author_name.unwrap_or("unknown").into(), author_id.into()))
        }
        GatewayEvent::MessageUpdate(data) => {
            let author_id = data.get("author").and_then(|a| a.get("id")).and_then(|v| v.as_str()).unwrap_or("unknown");
            ("discord.message_update", data.clone(), ("unknown".into(), author_id.into()))
        }
        GatewayEvent::MessageDelete(data) => {
            ("discord.message_delete", data.clone(), ("unknown".into(), "unknown".into()))
        }
        GatewayEvent::GuildCreate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            ("discord.guild_create", data.clone(), ("system".into(), guild_id.into()))
        }
        GatewayEvent::GuildUpdate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            ("discord.guild_update", data.clone(), ("system".into(), guild_id.into()))
        }
        GatewayEvent::ChannelCreate(data) => {
            ("discord.channel_create", data.clone(), ("system".into(), "unknown".into()))
        }
        GatewayEvent::ChannelUpdate(data) => {
            ("discord.channel_update", data.clone(), ("system".into(), "unknown".into()))
        }
        GatewayEvent::TypingStart(data) => {
            let user_id = data.get("user_id").and_then(|v| v.as_str()).unwrap_or("unknown");
            ("discord.typing", data.clone(), ("unknown".into(), user_id.into()))
        }
        GatewayEvent::Unknown { event_name, data } => {
            let topic = format!("discord.{}", event_name.to_lowercase());
            return Some(EventEnvelope::new(
                topic,
                EventData::new(
                    connector_id.clone(),
                    instance_id.clone(),
                    ZoneId::community(),
                    Principal {
                        kind: "discord".into(),
                        id: "unknown".into(),
                        trust: TrustLevel::Untrusted,
                        display: None,
                    },
                    data.clone(),
                ),
            ));
        }
    };

    let (display, id) = principal_info;
    let principal = Principal {
        kind: "discord_user".into(),
        id,
        trust: TrustLevel::Untrusted,
        display: Some(display),
    };

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::community(),
        principal,
        payload,
    );

    Some(EventEnvelope::new(topic, event_data))
}

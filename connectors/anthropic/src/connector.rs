//! FCP Anthropic Connector implementation.

use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, CapabilityId, FcpError, FcpResult, IdempotencyClass, Introspection, OperationId,
    OperationInfo, SafetyTier,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::AnthropicClient,
    error::AnthropicError,
    types::{Message, Model, Role, Tool, ToolChoice, Usage},
};

/// FCP Anthropic Connector.
pub struct AnthropicConnector {
    client: Option<AnthropicClient>,
    requests_total: AtomicU64,
    requests_error: AtomicU64,
    total_cost: std::sync::atomic::AtomicU64, // Store as fixed-point (cost * 1_000_000)
}

impl AnthropicConnector {
    /// Create a new Anthropic connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: None,
            requests_total: AtomicU64::new(0),
            requests_error: AtomicU64::new(0),
            total_cost: AtomicU64::new(0),
        }
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Get total errors.
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.requests_error.load(Ordering::Relaxed)
    }

    /// Get total cost in dollars.
    #[must_use]
    pub fn total_cost(&self) -> f64 {
        self.total_cost.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    /// Track cost from usage.
    fn track_cost(&self, usage: &Usage, model: Model) {
        let cost = usage.calculate_cost(model);
        let cost_fixed = (cost * 1_000_000.0) as u64;
        self.total_cost.fetch_add(cost_fixed, Ordering::Relaxed);
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing api_key in configuration".into(),
            })?;

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str());

        let mut client = AnthropicClient::new(api_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        info!("Anthropic connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.anthropic",
            "connector_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": "1.0",
            "capabilities": ["messages", "streaming", "tool_use", "vision"]
        }))
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": self.total_requests(),
                "requests_error": self.total_errors(),
                "total_cost_usd": self.total_cost()
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId("anthropic.message".into()),
                    summary: "Send a message to Claude".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["claude-opus-4-5-20251101", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"],
                                "default": "claude-sonnet-4-20250514"
                            },
                            "messages": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "role": { "type": "string", "enum": ["user", "assistant"] },
                                        "content": { "type": "string" }
                                    },
                                    "required": ["role", "content"]
                                }
                            },
                            "system": { "type": "string" },
                            "max_tokens": { "type": "integer", "default": 4096 },
                            "temperature": { "type": "number", "minimum": 0, "maximum": 1 }
                        },
                        "required": ["messages"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "content": { "type": "string" },
                            "model": { "type": "string" },
                            "stop_reason": { "type": "string" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "input_tokens": { "type": "integer" },
                                    "output_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId("anthropic.messages".into()),
                    risk_level: "medium".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to Claude and get a response.".into(),
                        common_mistakes: vec![
                            "Not providing messages array".into(),
                            "Exceeding context length".into(),
                        ],
                        examples: vec![
                            r#"{"messages": [{"role": "user", "content": "Hello!"}]}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId("anthropic.chat".into()),
                    summary: "Simple chat with Claude (single message)".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["claude-opus-4-5-20251101", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"],
                                "default": "claude-sonnet-4-20250514"
                            },
                            "message": { "type": "string" },
                            "system": { "type": "string" },
                            "max_tokens": { "type": "integer", "default": 4096 }
                        },
                        "required": ["message"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "response": { "type": "string" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "input_tokens": { "type": "integer" },
                                    "output_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId("anthropic.messages".into()),
                    risk_level: "medium".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Simple single-turn chat with Claude.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"message": "What is 2+2?"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId("anthropic.get_usage".into()),
                    summary: "Get current usage and cost statistics".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {}
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "total_input_tokens": { "type": "integer" },
                            "total_output_tokens": { "type": "integer" },
                            "total_cost_usd": { "type": "number" },
                            "requests_total": { "type": "integer" },
                            "requests_error": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId("anthropic.messages".into()),
                    risk_level: "low".into(),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Check usage and costs for this session.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let result = match operation {
            "anthropic.message" => self.invoke_message(input).await,
            "anthropic.chat" => self.invoke_chat(input).await,
            "anthropic.get_usage" => self.invoke_get_usage().await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        };

        if result.is_err() {
            self.requests_error.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    async fn invoke_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("claude-sonnet-4-20250514");

        let model = match model_str {
            "claude-opus-4-5-20251101" => Model::ClaudeOpus4_5,
            "claude-sonnet-4-20250514" => Model::ClaudeSonnet4,
            "claude-3-5-haiku-20241022" => Model::Claude3_5Haiku,
            "claude-3-5-sonnet-20241022" => Model::Claude3_5Sonnet,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown model: {model_str}"),
                })
            }
        };

        // Parse messages
        let messages_json = input.get("messages").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing messages".into(),
        })?;

        let messages: Vec<Message> =
            serde_json::from_value(messages_json.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid messages format: {e}"),
            })?;

        if messages.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Messages array cannot be empty".into(),
            });
        }

        let system = input.get("system").and_then(|v| v.as_str());
        let max_tokens = input
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(4096);
        let temperature = input.get("temperature").and_then(|v| v.as_f64());

        // Parse tools if provided
        let tools: Option<Vec<Tool>> = input
            .get("tools")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tools format: {e}"),
            })?;

        let tool_choice: Option<ToolChoice> = input
            .get("tool_choice")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tool_choice format: {e}"),
            })?;

        let response = client
            .message(model, messages, max_tokens, system, temperature, tools, tool_choice)
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;

        let cost = response.usage.calculate_cost(model);
        self.track_cost(&response.usage, model);

        // Extract text content
        let text_content: String = response
            .content
            .iter()
            .filter_map(|b| b.as_text())
            .collect::<Vec<_>>()
            .join("");

        Ok(json!({
            "id": response.id,
            "content": text_content,
            "model": response.model,
            "stop_reason": response.stop_reason,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            },
            "cost_usd": cost
        }))
    }

    async fn invoke_chat(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("claude-sonnet-4-20250514");

        let model = match model_str {
            "claude-opus-4-5-20251101" => Model::ClaudeOpus4_5,
            "claude-sonnet-4-20250514" => Model::ClaudeSonnet4,
            "claude-3-5-haiku-20241022" => Model::Claude3_5Haiku,
            "claude-3-5-sonnet-20241022" => Model::Claude3_5Sonnet,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown model: {model_str}"),
                })
            }
        };

        let message = input
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message".into(),
            })?;

        let system = input.get("system").and_then(|v| v.as_str());
        let max_tokens = input
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(4096);

        // Build messages
        let messages = vec![Message {
            role: Role::User,
            content: message.into(),
        }];

        let response = client
            .message(model, messages, max_tokens, system, None, None, None)
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;

        let cost = response.usage.calculate_cost(model);
        self.track_cost(&response.usage, model);

        // Extract text content
        let text_content: String = response
            .content
            .iter()
            .filter_map(|b| b.as_text())
            .collect::<Vec<_>>()
            .join("");

        Ok(json!({
            "response": text_content,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            },
            "cost_usd": cost
        }))
    }

    async fn invoke_get_usage(&self) -> FcpResult<serde_json::Value> {
        let (input_tokens, output_tokens) = if let Some(client) = &self.client {
            (client.total_input_tokens(), client.total_output_tokens())
        } else {
            (0, 0)
        };

        Ok(json!({
            "total_input_tokens": input_tokens,
            "total_output_tokens": output_tokens,
            "total_cost_usd": self.total_cost(),
            "requests_total": self.total_requests(),
            "requests_error": self.total_errors()
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        info!("Anthropic connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for AnthropicConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handshake() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_handshake(json!({})).await.unwrap();

        assert_eq!(result["connector_id"], "fcp.anthropic");
        assert!(result["capabilities"].as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn test_health_not_configured() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_health().await.unwrap();

        assert_eq!(result["status"], "not_configured");
    }

    #[tokio::test]
    async fn test_invoke_without_config() {
        let connector = AnthropicConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "anthropic.chat",
                "input": {
                    "message": "Hello"
                }
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[tokio::test]
    async fn test_invoke_missing_message() {
        let mut connector = AnthropicConnector::new();
        // Configure with fake key
        connector.client = Some(
            AnthropicClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "anthropic.message",
                "input": {}
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("messages"));
            }
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_usage() {
        let connector = AnthropicConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "anthropic.get_usage",
                "input": {}
            }))
            .await
            .unwrap();

        assert_eq!(result["total_input_tokens"], 0);
        assert_eq!(result["total_output_tokens"], 0);
        assert_eq!(result["requests_total"], 1);
    }
}

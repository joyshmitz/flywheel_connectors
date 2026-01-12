//! OpenAI API types.

use serde::{Deserialize, Serialize};

/// Available OpenAI models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Model {
    /// GPT-4o - Most capable multimodal model
    #[serde(rename = "gpt-4o")]
    Gpt4o,
    /// GPT-4o mini - Smaller, faster GPT-4o
    #[serde(rename = "gpt-4o-mini")]
    Gpt4oMini,
    /// GPT-4 Turbo - Previous generation
    #[serde(rename = "gpt-4-turbo")]
    Gpt4Turbo,
    /// GPT-4 - Original GPT-4
    #[serde(rename = "gpt-4")]
    Gpt4,
    /// GPT-3.5 Turbo - Fast and cost-effective
    #[serde(rename = "gpt-3.5-turbo")]
    Gpt35Turbo,
}

impl Model {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Gpt4o => "gpt-4o",
            Self::Gpt4oMini => "gpt-4o-mini",
            Self::Gpt4Turbo => "gpt-4-turbo",
            Self::Gpt4 => "gpt-4",
            Self::Gpt35Turbo => "gpt-3.5-turbo",
        }
    }

    /// Get input price per million tokens.
    #[must_use]
    pub const fn input_price_per_million(&self) -> f64 {
        match self {
            Self::Gpt4o => 2.50,
            Self::Gpt4oMini => 0.15,
            Self::Gpt4Turbo => 10.0,
            Self::Gpt4 => 30.0,
            Self::Gpt35Turbo => 0.50,
        }
    }

    /// Get output price per million tokens.
    #[must_use]
    pub const fn output_price_per_million(&self) -> f64 {
        match self {
            Self::Gpt4o => 10.0,
            Self::Gpt4oMini => 0.60,
            Self::Gpt4Turbo => 30.0,
            Self::Gpt4 => 60.0,
            Self::Gpt35Turbo => 1.50,
        }
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::Gpt4o
    }
}

/// A message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message sender.
    pub role: Role,
    /// Content of the message.
    pub content: MessageContent,
    /// Optional name for the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool calls made by the assistant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// ID of the tool call this message is responding to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    /// Create a user message.
    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// Create an assistant message.
    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// Create a system message.
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: MessageContent::Text(content.into()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System message
    System,
    /// User message
    User,
    /// Assistant message
    Assistant,
    /// Tool message (function result)
    Tool,
}

/// Content of a message (can be text or multimodal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    /// Complex content with multiple parts (for vision)
    Parts(Vec<ContentPart>),
}

impl From<&str> for MessageContent {
    fn from(s: &str) -> Self {
        Self::Text(s.to_string())
    }
}

impl From<String> for MessageContent {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

/// A content part for multimodal messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// Text content
    Text { text: String },
    /// Image URL
    ImageUrl { image_url: ImageUrl },
}

/// Image URL for vision requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    /// URL of the image (can be data: URL for base64)
    pub url: String,
    /// Detail level for the image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<ImageDetail>,
}

/// Detail level for image processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageDetail {
    /// Automatic detail level
    Auto,
    /// Low detail (faster, cheaper)
    Low,
    /// High detail (more accurate)
    High,
}

/// Request to the Chat Completions API.
#[derive(Debug, Clone, Serialize)]
pub struct ChatCompletionRequest {
    /// Model to use
    pub model: String,
    /// Messages in the conversation
    pub messages: Vec<Message>,
    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Temperature for sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Top-p sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Number of completions to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Stop sequences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Presence penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f64>,
    /// Frequency penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,
    /// User identifier for abuse detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Tools available to the model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// How to choose which tool to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Response format (for JSON mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// Seed for deterministic outputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
}

/// A tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Type of tool (always "function" for now)
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition
    pub function: FunctionDefinition,
}

/// Function definition for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// Function name
    pub name: String,
    /// Function description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parameters schema (JSON Schema)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

/// How to choose which tool to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolChoice {
    /// String choice: "none", "auto", or "required"
    String(String),
    /// Specific tool choice
    Specific {
        #[serde(rename = "type")]
        choice_type: String,
        function: ToolChoiceFunction,
    },
}

/// Function choice for specific tool selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChoiceFunction {
    /// Name of the function to call
    pub name: String,
}

/// Response format specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFormat {
    /// Type of response format
    #[serde(rename = "type")]
    pub format_type: String,
}

/// A tool call made by the assistant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique ID for this tool call
    pub id: String,
    /// Type of tool (always "function")
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function call details
    pub function: FunctionCall,
}

/// Function call details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    /// Name of the function to call
    pub name: String,
    /// Arguments as a JSON string
    pub arguments: String,
}

/// Response from the Chat Completions API.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatCompletionResponse {
    /// Response ID
    pub id: String,
    /// Object type (always "chat.completion")
    pub object: String,
    /// Unix timestamp of creation
    pub created: i64,
    /// Model used
    pub model: String,
    /// Choices (completions)
    pub choices: Vec<Choice>,
    /// Usage statistics
    pub usage: Option<Usage>,
    /// System fingerprint
    pub system_fingerprint: Option<String>,
}

/// A completion choice.
#[derive(Debug, Clone, Deserialize)]
pub struct Choice {
    /// Index of this choice
    pub index: u32,
    /// The message
    pub message: ResponseMessage,
    /// Finish reason
    pub finish_reason: Option<FinishReason>,
}

/// Message in a response.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMessage {
    /// Role (always "assistant")
    pub role: Role,
    /// Text content
    pub content: Option<String>,
    /// Tool calls made by the assistant
    pub tool_calls: Option<Vec<ToolCall>>,
}

/// Reason the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural end of message
    Stop,
    /// Hit max tokens
    Length,
    /// Model wants to use a tool
    ToolCalls,
    /// Content was filtered
    ContentFilter,
}

/// Token usage statistics.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub struct Usage {
    /// Prompt tokens used
    pub prompt_tokens: u32,
    /// Completion tokens used
    pub completion_tokens: u32,
    /// Total tokens used
    pub total_tokens: u32,
}

impl Usage {
    /// Calculate cost for this usage with a given model.
    #[must_use]
    pub fn calculate_cost(&self, model: Model) -> f64 {
        let input_cost =
            (f64::from(self.prompt_tokens) / 1_000_000.0) * model.input_price_per_million();
        let output_cost =
            (f64::from(self.completion_tokens) / 1_000_000.0) * model.output_price_per_million();
        input_cost + output_cost
    }
}

/// Streaming chunk from the Chat Completions API.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatCompletionChunk {
    /// Chunk ID
    pub id: String,
    /// Object type (always "chat.completion.chunk")
    pub object: String,
    /// Unix timestamp of creation
    pub created: i64,
    /// Model used
    pub model: String,
    /// Choices (partial completions)
    pub choices: Vec<ChunkChoice>,
    /// System fingerprint
    pub system_fingerprint: Option<String>,
    /// Usage (only in final chunk if requested)
    pub usage: Option<Usage>,
}

/// A choice in a streaming chunk.
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkChoice {
    /// Index of this choice
    pub index: u32,
    /// Delta (incremental content)
    pub delta: ChunkDelta,
    /// Finish reason (only in final chunk)
    pub finish_reason: Option<FinishReason>,
}

/// Delta content in a streaming chunk.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChunkDelta {
    /// Role (only in first chunk)
    pub role: Option<Role>,
    /// Content delta
    pub content: Option<String>,
    /// Tool calls delta
    pub tool_calls: Option<Vec<ToolCallDelta>>,
}

/// Tool call delta in streaming.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallDelta {
    /// Index of the tool call
    pub index: u32,
    /// ID (only in first chunk for this tool call)
    pub id: Option<String>,
    /// Type (only in first chunk)
    #[serde(rename = "type")]
    pub tool_type: Option<String>,
    /// Function delta
    pub function: Option<FunctionCallDelta>,
}

/// Function call delta in streaming.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionCallDelta {
    /// Name (only in first chunk)
    pub name: Option<String>,
    /// Arguments delta (incremental JSON string)
    pub arguments: Option<String>,
}

/// API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    /// Error details
    pub error: ApiErrorDetails,
}

/// API error details.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetails {
    /// Error message
    pub message: String,
    /// Error type
    #[serde(rename = "type")]
    pub error_type: String,
    /// Parameter that caused the error
    pub param: Option<String>,
    /// Error code
    pub code: Option<String>,
}

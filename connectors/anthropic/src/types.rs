//! Anthropic API types.

use serde::{Deserialize, Serialize};

/// Available Claude models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Model {
    /// Claude Opus 4.5 - Most capable model
    #[serde(rename = "claude-opus-4-5-20251101")]
    ClaudeOpus4_5,
    /// Claude Sonnet 4 - Balanced performance
    #[serde(rename = "claude-sonnet-4-20250514")]
    ClaudeSonnet4,
    /// Claude 3.5 Haiku - Fast and efficient
    #[serde(rename = "claude-3-5-haiku-20241022")]
    Claude3_5Haiku,
    /// Claude 3.5 Sonnet - Previous generation
    #[serde(rename = "claude-3-5-sonnet-20241022")]
    Claude3_5Sonnet,
}

impl Model {
    /// Get the model string for API requests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ClaudeOpus4_5 => "claude-opus-4-5-20251101",
            Self::ClaudeSonnet4 => "claude-sonnet-4-20250514",
            Self::Claude3_5Haiku => "claude-3-5-haiku-20241022",
            Self::Claude3_5Sonnet => "claude-3-5-sonnet-20241022",
        }
    }

    /// Get input price per million tokens.
    #[must_use]
    pub const fn input_price_per_million(&self) -> f64 {
        match self {
            Self::ClaudeOpus4_5 => 15.0,
            Self::ClaudeSonnet4 => 3.0,
            Self::Claude3_5Haiku => 0.25,
            Self::Claude3_5Sonnet => 3.0,
        }
    }

    /// Get output price per million tokens.
    #[must_use]
    pub const fn output_price_per_million(&self) -> f64 {
        match self {
            Self::ClaudeOpus4_5 => 75.0,
            Self::ClaudeSonnet4 => 15.0,
            Self::Claude3_5Haiku => 1.25,
            Self::Claude3_5Sonnet => 15.0,
        }
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::ClaudeSonnet4
    }
}

/// A message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message sender.
    pub role: Role,
    /// Content of the message.
    pub content: MessageContent,
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// User message
    User,
    /// Assistant message
    Assistant,
}

/// Content of a message (can be text or multimodal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    /// Complex content with multiple blocks
    Blocks(Vec<ContentBlock>),
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

/// A content block in a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Text content
    Text { text: String },
    /// Image content
    Image { source: ImageSource },
    /// Tool use request from assistant
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// Tool result from user
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

/// Image source for vision requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImageSource {
    /// Base64-encoded image data
    Base64 { media_type: String, data: String },
    /// URL to an image
    Url { url: String },
}

/// Request to the Messages API.
#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    /// Model to use
    pub model: String,
    /// Messages in the conversation
    pub messages: Vec<Message>,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// System prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Temperature for sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Tools available to the model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// How to choose which tool to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Stop sequences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
}

/// A tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Input schema (JSON Schema)
    pub input_schema: serde_json::Value,
}

/// How to choose which tool to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolChoice {
    /// Let the model decide
    Auto,
    /// Force the model to use a tool
    Any,
    /// Force the model to use a specific tool
    Tool { name: String },
}

/// Response from the Messages API.
#[derive(Debug, Clone, Deserialize)]
pub struct MessagesResponse {
    /// Response ID
    pub id: String,
    /// Type of response (always "message")
    #[serde(rename = "type")]
    pub response_type: String,
    /// Role (always "assistant")
    pub role: Role,
    /// Content blocks
    pub content: Vec<ResponseContentBlock>,
    /// Model used
    pub model: String,
    /// Stop reason
    pub stop_reason: Option<StopReason>,
    /// Stop sequence that was hit (if any)
    pub stop_sequence: Option<String>,
    /// Usage statistics
    pub usage: Usage,
}

/// Content block in a response.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseContentBlock {
    /// Text content
    Text { text: String },
    /// Tool use request
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

impl ResponseContentBlock {
    /// Extract text content if this is a text block.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } => Some(text),
            Self::ToolUse { .. } => None,
        }
    }
}

/// Reason the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Hit end of turn
    EndTurn,
    /// Hit max tokens
    MaxTokens,
    /// Hit a stop sequence
    StopSequence,
    /// Model wants to use a tool
    ToolUse,
}

/// Token usage statistics.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Usage {
    /// Input tokens used
    pub input_tokens: u32,
    /// Output tokens used
    pub output_tokens: u32,
    /// Cache creation tokens (if using caching)
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    /// Cache read tokens (if using caching)
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

impl Usage {
    /// Calculate total tokens used.
    #[must_use]
    pub const fn total_tokens(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }

    /// Calculate cost for this usage with a given model.
    #[must_use]
    pub fn calculate_cost(&self, model: Model) -> f64 {
        let base_input_price = model.input_price_per_million();
        let output_price = model.output_price_per_million();

        // Anthropic pricing for caching:
        // Cache writes are 25% more expensive than base input
        // Cache reads are 90% cheaper than base input (0.1x multiplier)
        let creation_price = base_input_price * 1.25;
        let read_price = base_input_price * 0.10;

        // input_tokens includes creation and read tokens, so we must subtract them
        // to get the uncached input count
        let uncached_input = self
            .input_tokens
            .saturating_sub(self.cache_creation_input_tokens)
            .saturating_sub(self.cache_read_input_tokens);

        let input_cost = (f64::from(uncached_input) / 1_000_000.0) * base_input_price
            + (f64::from(self.cache_creation_input_tokens) / 1_000_000.0) * creation_price
            + (f64::from(self.cache_read_input_tokens) / 1_000_000.0) * read_price;

        let output_cost = (f64::from(self.output_tokens) / 1_000_000.0) * output_price;

        input_cost + output_cost
    }
}

/// Streaming event from the Messages API.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// Start of message
    MessageStart { message: MessageStartData },
    /// Start of content block
    ContentBlockStart {
        index: u32,
        content_block: ContentBlockStartData,
    },
    /// Delta for content block
    ContentBlockDelta { index: u32, delta: ContentDelta },
    /// End of content block
    ContentBlockStop { index: u32 },
    /// Delta for message (usage updates)
    MessageDelta {
        delta: MessageDeltaData,
        usage: Usage,
    },
    /// End of message
    MessageStop,
    /// Ping event (keepalive)
    Ping,
    /// Error event
    Error { error: ApiError },
}

/// Data at message start.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageStartData {
    /// Message ID
    pub id: String,
    /// Role
    pub role: Role,
    /// Model
    pub model: String,
    /// Initial usage
    pub usage: Usage,
}

/// Data at content block start.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlockStartData {
    /// Text block starting
    Text { text: String },
    /// Tool use starting (input starts as empty object)
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

/// Delta for content.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentDelta {
    /// Text delta
    TextDelta { text: String },
    /// Tool input delta (JSON string)
    InputJsonDelta { partial_json: String },
}

/// Delta data for message.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageDeltaData {
    /// Stop reason
    pub stop_reason: Option<StopReason>,
    /// Stop sequence
    pub stop_sequence: Option<String>,
}

/// API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    /// Error type
    #[serde(rename = "type")]
    pub error_type: String,
    /// Error message
    pub message: String,
}

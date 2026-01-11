//! Discord API types.

use serde::{Deserialize, Serialize};

/// Discord user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: String,

    /// Username
    pub username: String,

    /// Discriminator (legacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<String>,

    /// Global display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_name: Option<String>,

    /// Avatar hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,

    /// Whether this is a bot
    #[serde(default)]
    pub bot: bool,
}

/// Discord guild (server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guild {
    /// Guild ID
    pub id: String,

    /// Guild name
    pub name: String,

    /// Icon hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// Owner ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
}

/// Discord channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    /// Channel ID
    pub id: String,

    /// Channel type
    #[serde(rename = "type")]
    pub channel_type: i32,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,

    /// Channel name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Topic
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

/// Discord message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message ID
    pub id: String,

    /// Channel ID
    pub channel_id: String,

    /// Author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<User>,

    /// Message content
    pub content: String,

    /// Timestamp
    pub timestamp: String,

    /// Whether this message is TTS
    #[serde(default)]
    pub tts: bool,

    /// Whether this mentions everyone
    #[serde(default)]
    pub mention_everyone: bool,

    /// Attachments
    #[serde(default)]
    pub attachments: Vec<Attachment>,

    /// Embeds
    #[serde(default)]
    pub embeds: Vec<Embed>,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
}

/// Discord attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Attachment ID
    pub id: String,

    /// Filename
    pub filename: String,

    /// File size
    pub size: u64,

    /// URL
    pub url: String,

    /// Proxy URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,

    /// Content type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Discord embed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Embed {
    /// Title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Color
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<u32>,

    /// Fields
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<EmbedField>,

    /// Footer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<EmbedFooter>,

    /// Image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<EmbedImage>,

    /// Thumbnail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<EmbedThumbnail>,

    /// Author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<EmbedAuthor>,
}

/// Embed field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedField {
    /// Field name
    pub name: String,

    /// Field value
    pub value: String,

    /// Inline display
    #[serde(default)]
    pub inline: bool,
}

/// Embed footer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedFooter {
    /// Footer text
    pub text: String,

    /// Icon URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// Embed image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedImage {
    /// Image URL
    pub url: String,
}

/// Embed thumbnail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedThumbnail {
    /// Thumbnail URL
    pub url: String,
}

/// Embed author.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedAuthor {
    /// Author name
    pub name: String,

    /// Author URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Icon URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// Gateway event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayPayload {
    /// Opcode
    pub op: i32,

    /// Event data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<serde_json::Value>,

    /// Sequence number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<u64>,

    /// Event name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
}

/// Gateway identify payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayIdentify {
    /// Bot token
    pub token: String,

    /// Gateway intents
    pub intents: u64,

    /// Connection properties
    pub properties: GatewayProperties,

    /// Shard info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard: Option<[u32; 2]>,
}

/// Gateway connection properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProperties {
    /// OS
    pub os: String,

    /// Browser
    pub browser: String,

    /// Device
    pub device: String,
}

/// Gateway ready event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayReady {
    /// API version
    pub v: i32,

    /// Bot user
    pub user: User,

    /// Session ID
    pub session_id: String,

    /// Resume gateway URL
    pub resume_gateway_url: String,

    /// Guilds (unavailable)
    #[serde(default)]
    pub guilds: Vec<serde_json::Value>,
}

/// Gateway hello event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayHello {
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval: u64,
}

/// Create message request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateMessage {
    /// Message content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// TTS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tts: Option<bool>,

    /// Embeds
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embeds: Vec<Embed>,

    /// Message reference (for replies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_reference: Option<MessageReference>,
}

/// Message reference for replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReference {
    /// Message ID to reply to
    pub message_id: String,

    /// Channel ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
}

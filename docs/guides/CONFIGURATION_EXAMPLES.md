# FCP Configuration Examples

This document provides complete configuration examples for each available connector.

---

## Directory Structure

```
~/.fcp/
├── config.toml              # Global FCP configuration
└── connectors/
    ├── twitter.toml         # Twitter connector config
    ├── telegram.toml        # Telegram connector config
    ├── discord.toml         # Discord connector config
    ├── openai.toml          # OpenAI connector config
    └── anthropic.toml       # Anthropic connector config
```

---

## Global Configuration

File: `~/.fcp/config.toml`

```toml
# FCP Global Configuration
# Version: 2.0.0

[general]
# Log level: trace, debug, info, warn, error
log_level = "info"

# Default zone for operations
default_zone = "z:work"

[zones]
# Zone definitions
# Format: zone_name = trust_level (0-100)
owner = 100
private = 80
work = 60
community = 40
public = 20

[tailscale]
# Tailscale configuration (usually auto-detected)
# Uncomment to override
# socket_path = "/var/run/tailscale/tailscaled.sock"

[audit]
# Audit log retention
retention_days = 30

# Audit log location
# log_path = "~/.fcp/audit/"
```

---

## Twitter Connector

### How to Get Credentials

1. Go to https://developer.twitter.com/
2. Create a Developer Account (if you don't have one)
3. Create a new Project and App
4. Enable OAuth 1.0a with Read and Write permissions
5. Generate Consumer Keys and Access Tokens

### Configuration File

File: `~/.fcp/connectors/twitter.toml`

```toml
# Twitter Connector Configuration
# Connector ID: twitter:social:v1

[connector]
name = "twitter"
version = "0.1.0"
zone = "z:work"

# Available archetypes: Operational, Streaming, Bidirectional
archetypes = ["Operational", "Streaming", "Bidirectional"]

[credentials]
# OAuth 1.0a credentials
# SECURITY: Store these securely in production!
consumer_key = "your_consumer_key_here"
consumer_secret = "your_consumer_secret_here"
access_token = "your_access_token_here"
access_token_secret = "your_access_token_secret_here"

[options]
# Request timeout in seconds
timeout_secs = 30

# Rate limit handling
respect_rate_limits = true

# Streaming options
stream_reconnect_delay_secs = 5
stream_max_reconnects = 10

[capabilities]
# Capabilities this connector can use
# These must be granted by the zone administrator
required = [
    "twitter.read",      # Read tweets
]
optional = [
    "twitter.write",     # Post tweets
    "twitter.dm.read",   # Read direct messages
    "twitter.dm.write",  # Send direct messages
    "twitter.stream",    # Access streaming API
]
```

### Available Operations

| Operation | Required Capability | Description |
|-----------|---------------------|-------------|
| `get_me` | `twitter.read` | Get authenticated user info |
| `get_user` | `twitter.read` | Get user by ID or username |
| `post_tweet` | `twitter.write` | Post a new tweet |
| `delete_tweet` | `twitter.write` | Delete a tweet |
| `search_tweets` | `twitter.read` | Search tweets |
| `get_dm_conversations` | `twitter.dm.read` | List DM conversations |
| `send_dm` | `twitter.dm.write` | Send a direct message |
| `start_filtered_stream` | `twitter.stream` | Start streaming tweets |

---

## Telegram Connector

### How to Get Credentials

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` command
3. Follow the prompts to create your bot
4. Copy the token provided

### Configuration File

File: `~/.fcp/connectors/telegram.toml`

```toml
# Telegram Connector Configuration
# Connector ID: telegram

[connector]
name = "telegram"
version = "0.1.0"
zone = "z:work"

archetypes = ["Operational", "Bidirectional"]

[credentials]
# Bot token from @BotFather
# Format: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz
token = "your_bot_token_here"

[options]
# Custom API base URL (optional, for local Bot API server)
# base_url = "http://localhost:8081"

# Long polling timeout in seconds
poll_timeout = 30

# Allowed update types (empty = all)
# Options: message, edited_message, channel_post, callback_query, etc.
allowed_updates = ["message", "callback_query"]

[capabilities]
required = [
    "telegram.read",     # Receive messages
]
optional = [
    "telegram.write",    # Send messages
    "telegram.media",    # Send media files
    "telegram.admin",    # Admin operations
]
```

### Available Operations

| Operation | Required Capability | Description |
|-----------|---------------------|-------------|
| `get_me` | `telegram.read` | Get bot info |
| `get_updates` | `telegram.read` | Get incoming updates |
| `send_message` | `telegram.write` | Send a text message |
| `send_photo` | `telegram.media` | Send a photo |
| `send_document` | `telegram.media` | Send a document |
| `delete_message` | `telegram.admin` | Delete a message |
| `ban_chat_member` | `telegram.admin` | Ban a user |

---

## Discord Connector

### How to Get Credentials

1. Go to https://discord.com/developers/applications
2. Click "New Application"
3. Go to "Bot" section
4. Click "Add Bot"
5. Copy the Token (click "Reset Token" if needed)
6. Enable required Intents (Message Content, etc.)

### Configuration File

File: `~/.fcp/connectors/discord.toml`

```toml
# Discord Connector Configuration
# Connector ID: discord

[connector]
name = "discord"
version = "0.1.0"
zone = "z:community"

archetypes = ["Operational", "Streaming", "Bidirectional"]

[credentials]
# Bot token from Discord Developer Portal
token = "your_bot_token_here"

[options]
# Gateway intents
# See: https://discord.com/developers/docs/topics/gateway#gateway-intents
intents = [
    "GUILDS",
    "GUILD_MESSAGES",
    "DIRECT_MESSAGES",
    "MESSAGE_CONTENT",
]

# Reconnection settings
reconnect_delay_secs = 5
max_reconnect_attempts = 10

[capabilities]
required = [
    "discord.read",      # Read messages
]
optional = [
    "discord.write",     # Send messages
    "discord.manage",    # Manage channels/roles
    "discord.moderate",  # Moderation actions
]
```

### Available Operations

| Operation | Required Capability | Description |
|-----------|---------------------|-------------|
| `get_user` | `discord.read` | Get user info |
| `get_guild` | `discord.read` | Get server info |
| `get_channel` | `discord.read` | Get channel info |
| `send_message` | `discord.write` | Send a message |
| `create_channel` | `discord.manage` | Create a channel |
| `delete_message` | `discord.moderate` | Delete a message |
| `ban_member` | `discord.moderate` | Ban a user |

---

## OpenAI Connector

### How to Get Credentials

1. Go to https://platform.openai.com/
2. Sign in or create an account
3. Go to API Keys section
4. Create a new API key
5. Copy the key (it won't be shown again)

### Configuration File

File: `~/.fcp/connectors/openai.toml`

```toml
# OpenAI Connector Configuration
# Connector ID: openai

[connector]
name = "openai"
version = "0.1.0"
zone = "z:work"

archetypes = ["Operational"]

[credentials]
# API key from OpenAI Platform
api_key = "sk-your_api_key_here"

# Organization ID (optional)
# organization = "org-..."

[options]
# Default model
default_model = "gpt-4"

# Request timeout in seconds
timeout_secs = 120

# Maximum tokens (0 = model default)
max_tokens = 0

# Temperature (0.0 - 2.0)
temperature = 1.0

[capabilities]
required = [
    "openai.chat",       # Chat completions
]
optional = [
    "openai.embeddings", # Text embeddings
    "openai.images",     # Image generation
    "openai.audio",      # Audio transcription
]
```

### Available Operations

| Operation | Required Capability | Description |
|-----------|---------------------|-------------|
| `chat_completion` | `openai.chat` | Generate chat response |
| `create_embedding` | `openai.embeddings` | Create text embedding |
| `create_image` | `openai.images` | Generate image |
| `transcribe_audio` | `openai.audio` | Transcribe audio file |

---

## Anthropic Connector

### How to Get Credentials

1. Go to https://console.anthropic.com/
2. Sign in or create an account
3. Go to API Keys section
4. Create a new API key
5. Copy the key

### Configuration File

File: `~/.fcp/connectors/anthropic.toml`

```toml
# Anthropic Connector Configuration
# Connector ID: anthropic

[connector]
name = "anthropic"
version = "0.1.0"
zone = "z:work"

archetypes = ["Operational"]

[credentials]
# API key from Anthropic Console
api_key = "sk-ant-your_api_key_here"

[options]
# Default model
default_model = "claude-3-5-sonnet-20241022"

# Request timeout in seconds
timeout_secs = 120

# Maximum tokens
max_tokens = 4096

[capabilities]
required = [
    "anthropic.messages", # Message API
]
optional = []
```

### Available Operations

| Operation | Required Capability | Description |
|-----------|---------------------|-------------|
| `create_message` | `anthropic.messages` | Generate Claude response |

---

## Security Best Practices

### Do NOT

- Store credentials in version control
- Share configuration files with credentials
- Use production credentials for testing

### DO

- Use environment variables for credentials in production
- Use separate credentials for development/testing
- Rotate credentials regularly
- Use the minimum required capabilities

### Environment Variables (Recommended for Production)

Instead of storing credentials in files, use environment variables:

```bash
# Twitter
export FCP_TWITTER_CONSUMER_KEY="..."
export FCP_TWITTER_CONSUMER_SECRET="..."
export FCP_TWITTER_ACCESS_TOKEN="..."
export FCP_TWITTER_ACCESS_TOKEN_SECRET="..."

# Telegram
export FCP_TELEGRAM_TOKEN="..."

# Discord
export FCP_DISCORD_TOKEN="..."

# OpenAI
export FCP_OPENAI_API_KEY="..."

# Anthropic
export FCP_ANTHROPIC_API_KEY="..."
```

Then reference in config:

```toml
[credentials]
token = "${FCP_TELEGRAM_TOKEN}"
```

---

## Verifying Configuration

After creating configuration files:

```bash
# Check syntax
./target/release/fcp connector validate telegram

# Test connectivity
./target/release/fcp connector test telegram

# View parsed configuration
./target/release/fcp connector show telegram
```

---

*Last updated: 2026-01-27*

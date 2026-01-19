# Study: Clawdbot Discord Connector Implementation

**Bead**: `flywheel_connectors-v6w`
**Status**: Complete
**Date**: 2026-01-18

## Executive Summary

This document analyzes the existing Discord connector implementation (`connectors/discord/`) to extract patterns, anti-patterns, and reusable components for FCP2 connector design. The implementation demonstrates a well-structured bidirectional connector with Gateway WebSocket streaming and REST API operations.

---

## 1. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DiscordConnector                                │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    BaseConnector<DiscordConfig>                 │ │
│  │  - connector_id: ConnectorId                                    │ │
│  │  - capabilities: HashMap<String, CapabilityBinding>             │ │
│  │  - metrics: ConnectorMetrics                                    │ │
│  │  - health: HealthReport                                         │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│           ┌──────────────────┼──────────────────┐                   │
│           ▼                  ▼                  ▼                   │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────┐         │
│  │ DiscordConfig  │  │DiscordApi   │  │GatewayConnection│         │
│  │                │  │Client       │  │                 │         │
│  │ - bot_token    │  │             │  │ - session_id    │         │
│  │ - api_url      │  │ - client    │  │ - resume_url    │         │
│  │ - intents      │  │ - base_url  │  │ - sequence      │         │
│  │ - retry cfg    │  │ - token     │  │                 │         │
│  │ - shard cfg    │  │             │  │                 │         │
│  └────────────────┘  └──────┬──────┘  └────────┬────────┘         │
│                             │                   │                   │
│                             ▼                   ▼                   │
│                    ┌────────────────┐  ┌─────────────────┐         │
│                    │  REST API      │  │ WebSocket       │         │
│                    │  (reqwest)     │  │ (tungstenite)   │         │
│                    └────────────────┘  └─────────────────┘         │
│                             │                   │                   │
│                             ▼                   ▼                   │
│                    ┌─────────────────────────────────────┐         │
│                    │         Discord API v10             │         │
│                    │  - api.discord.com (REST)           │         │
│                    │  - gateway.discord.gg (WS)          │         │
│                    └─────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────────┘

Event Flow:
┌──────────────┐    ┌───────────────┐    ┌──────────────────┐
│ Gateway      │───▶│ GatewayEvent  │───▶│ broadcast::      │
│ WebSocket    │    │ enum          │    │ Sender<Event>    │
└──────────────┘    └───────────────┘    └────────┬─────────┘
                                                  │
                    ┌─────────────────────────────┘
                    ▼
        ┌─────────────────────┐
        │ EventEnvelope (FCP) │
        │ - event_type        │
        │ - payload           │
        │ - metadata          │
        └─────────────────────┘
```

---

## 2. Pattern Catalog

### P1: Base Connector Composition

**Location**: `connector.rs:25-31`

```rust
pub struct DiscordConnector {
    base: BaseConnector<DiscordConfig>,
    config: DiscordConfig,
    api_client: Arc<DiscordApiClient>,
    gateway: Arc<tokio::sync::Mutex<Option<GatewayConnection>>>,
    event_tx: Arc<tokio::sync::Mutex<Option<broadcast::Sender<GatewayEvent>>>>,
}
```

**Pattern**: Wrap the `BaseConnector<T>` generic with platform-specific state. Use `Arc<Mutex<Option<T>>>` for lazy-initialized components (gateway, event channels).

**Reusability**: HIGH - All FCP connectors should follow this composition pattern.

---

### P2: Early Input Validation

**Location**: `connector.rs:178-196`

```rust
// Validate before proceeding
let content = params.get("content").and_then(|v| v.as_str());
let embeds = params.get("embeds").and_then(|v| v.as_array());

if content.is_none() && embeds.is_none() {
    return Err(FcpError::InvalidParameter {
        name: "content or embeds".into(),
        reason: "Either content or embeds must be provided".into(),
    });
}

// Discord limits
if let Some(c) = content {
    if c.len() > 2000 {
        return Err(FcpError::InvalidParameter {
            name: "content".into(),
            reason: "Message content exceeds 2000 characters".into(),
        });
    }
}
```

**Pattern**: Validate all inputs BEFORE capability verification and API calls. Check platform-specific limits (2000 chars, 10 embeds, 6000 total embed chars).

**Reusability**: HIGH - Extract into a validation trait/module.

---

### P3: Supervisor Reconnection Loop

**Location**: `gateway.rs:142-205`

```rust
tokio::spawn(async move {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        // ... connect logic ...
        match connect_result {
            Ok((ws_stream, _)) => {
                backoff = Duration::from_secs(1);  // Reset on success
                match run_gateway_loop(...).await {
                    Ok(new_state) => {
                        state = new_state;  // Preserve session for resume
                        info!("Gateway loop ended, reconnecting immediately");
                    }
                    Err(e) => {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
            }
            Err(e) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
});
```

**Pattern**: Spawn a supervisor task that:
1. Maintains connection state across reconnects (session_id, sequence)
2. Uses exponential backoff with cap (1s initial, 60s max)
3. Resets backoff on successful connection
4. Preserves state for session resumption

**Reusability**: HIGH - Extract as `SupervisedConnection<S: ConnectionState>` trait.

---

### P4: Gateway Session Resumption

**Location**: `gateway.rs:256-305`

```rust
if let (Some(sess_id), Some(seq)) = (&state.session_id, state.sequence) {
    // Resume existing session
    let resume = GatewayResume { token, session_id, seq };
    write.send(WsMessage::Text(serde_json::to_string(&resume_payload)?)).await?;
} else {
    // Fresh Identify
    let identify = GatewayIdentify { token, intents, properties, shard };
    write.send(WsMessage::Text(serde_json::to_string(&identify_payload)?)).await?;
}
```

**Pattern**: Track session state (`session_id`, `resume_url`, `sequence`) and attempt Resume before falling back to Identify. This minimizes missed events during reconnection.

**Reusability**: MEDIUM - Pattern applies to any platform with resumable sessions.

---

### P5: Heartbeat with Zombie Detection

**Location**: `gateway.rs:308-331`

```rust
let mut heartbeat_acked = true;
loop {
    tokio::select! {
        _ = heartbeat_interval_timer.tick() => {
            if !heartbeat_acked {
                warn!("Heartbeat not acknowledged, connection zombied");
                return Err(DiscordError::Gateway("Heartbeat timeout (zombied)".into()));
            }
            write.send(WsMessage::Text(heartbeat.to_string())).await?;
            heartbeat_acked = false;
        }
        // ... message handling sets heartbeat_acked = true on HeartbeatAck ...
    }
}
```

**Pattern**: Track heartbeat acknowledgment. If a heartbeat fires before the previous was acknowledged, the connection is "zombied" and should be dropped.

**Reusability**: HIGH - Common pattern for any WebSocket with heartbeats.

---

### P6: Error Classification with Retryability

**Location**: `error.rs:40-62`

```rust
impl DiscordError {
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::WebSocket(_) => true,
            Self::Api { code, .. } => *code >= 500 || *code == 429,
            Self::RateLimited { .. } => true,
            Self::Gateway(_) => true,
            _ => false,
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(Duration::from_secs_f64(*retry_after)),
            Self::Api { retry_after, .. } => retry_after.map(Duration::from_secs_f64),
            _ => None,
        }
    }
}
```

**Pattern**: Classify errors as retryable/non-retryable and extract retry delays. Convert to FCP error types for protocol compliance.

**Reusability**: HIGH - Every connector needs this pattern.

---

### P7: Broadcast Channel for Event Distribution

**Location**: `connector.rs:134-138, 452-464`

```rust
// Create broadcast channel
let (tx, _) = broadcast::channel::<GatewayEvent>(256);
self.event_tx.lock().await.replace(tx.clone());

// In subscribe():
let rx = tx.subscribe();
tokio::spawn(async move {
    while let Ok(event) = rx.recv().await {
        let envelope = convert_to_fcp_event(event);
        if callback_tx.send(envelope).await.is_err() { break; }
    }
});
```

**Pattern**: Use `tokio::sync::broadcast` for multi-subscriber event distribution. Each subscriber gets independent copies.

**Reusability**: HIGH - Standard pattern for streaming connectors.

---

### P8: Configuration with Sensible Defaults

**Location**: `config.rs:42-145`

```rust
fn default_timeout() -> Duration { Duration::from_secs(30) }
fn default_intents() -> u64 { (1 << 0) | (1 << 9) | (1 << 15) | (1 << 12) }

#[derive(Default)]
pub struct RetryConfig {
    max_attempts: u32,      // 3
    initial_delay_ms: u64,  // 500
    max_delay_ms: u64,      // 30_000
    jitter: f64,            // 0.1
}
```

**Pattern**: Use `#[serde(default = "fn")]` for all optional config with sensible production defaults. Separate retry config into its own struct.

**Reusability**: HIGH - Extract `RetryConfig` as shared type.

---

### P9: API Client with Token Normalization

**Location**: `api.rs:25-38`

```rust
impl DiscordApiClient {
    pub fn new(config: &DiscordConfig) -> Self {
        let token = if config.bot_token.starts_with("Bot ") {
            config.bot_token.clone()
        } else {
            format!("Bot {}", config.bot_token)
        };
        // ...
    }
}
```

**Pattern**: Normalize authentication tokens at client construction time. Accept both "raw" and "prefixed" formats.

**Reusability**: MEDIUM - Pattern varies by platform auth scheme.

---

### P10: Structured Types over Raw JSON

**Location**: `types.rs` (entire file)

```rust
pub struct Message {
    pub id: String,
    pub channel_id: String,
    pub author: Option<User>,
    pub content: String,
    // ...
}
```

**Pattern**: Define explicit Rust structs for all API types rather than using `serde_json::Value` everywhere. Use `#[serde(skip_serializing_if = "Option::is_none")]` for optional fields.

**Reusability**: HIGH - Improves type safety and IDE support.

---

## 3. Anti-Pattern Notes

### AP1: Unbounded serde_json::Value in Events

**Location**: `gateway.rs:82-101`

```rust
pub enum GatewayEvent {
    MessageCreate(serde_json::Value),  // Not typed!
    MessageUpdate(serde_json::Value),
    // ...
}
```

**Problem**: Some events use raw `serde_json::Value` instead of typed structs. This loses type safety and makes pattern matching verbose.

**Recommendation**: Define typed event data structs for all known events. Use `Unknown(Value)` only for truly unknown events.

---

### AP2: Gateway State Mutation in Event Handler

**Location**: `gateway.rs:356-364`

```rust
"READY" => {
    let ready: GatewayReady = serde_json::from_value(data)?;
    state.session_id = Some(ready.session_id.clone());
    state.resume_url = Some(ready.resume_gateway_url.clone());
    // ...
}
```

**Problem**: State mutation happens inline in the event dispatch match. This mixes concerns and makes testing harder.

**Recommendation**: Return state changes from event handler, apply in dedicated state update function.

---

### AP3: Manual Embed Character Counting

**Location**: `connector.rs:208-218`

```rust
let total_embed_chars: usize = embeds.iter().map(|e| {
    // Count all string fields...
}).sum();
if total_embed_chars > 6000 {
    return Err(...);
}
```

**Problem**: Manual character counting is error-prone and needs updating when Discord changes limits.

**Recommendation**: Create `EmbedValidator` trait with platform-specific implementations.

---

### AP4: Hardcoded Magic Numbers

**Location**: Various

- `2000` - max message length
- `10` - max embeds
- `6000` - max total embed chars
- `256` - broadcast channel capacity

**Recommendation**: Define these as constants, preferably in a shared `limits.rs` module:

```rust
pub mod limits {
    pub const MAX_MESSAGE_LENGTH: usize = 2000;
    pub const MAX_EMBEDS: usize = 10;
    pub const MAX_EMBED_CHARS: usize = 6000;
}
```

---

### AP5: No Graceful Shutdown Handling

**Problem**: The gateway supervisor loop runs forever with no clean shutdown path. Dropping the connector doesn't cleanly close the WebSocket.

**Recommendation**: Add shutdown signal handling:

```rust
tokio::select! {
    _ = shutdown_rx.recv() => {
        write.send(WsMessage::Close(None)).await?;
        break;
    }
    // ... other branches ...
}
```

---

## 4. Reusable Components List

| Component | Location | Reusability | Notes |
|-----------|----------|-------------|-------|
| `BaseConnector<T>` | fcp-core | Direct use | Generic connector foundation |
| `RetryConfig` | config.rs | Extract | Exponential backoff configuration |
| Supervisor pattern | gateway.rs | Extract | `SupervisedConnection` trait |
| Error classification | error.rs | Extract | `RetryableError` trait |
| Heartbeat loop | gateway.rs | Extract | `HeartbeatManager` struct |
| Broadcast events | connector.rs | Pattern | tokio::sync::broadcast usage |
| Duration serde | config.rs | Extract | `duration_secs` module |
| Input validation | connector.rs | Extract | `Validator` trait |

### Extraction Priority

1. **HIGH**: `RetryConfig`, Error classification, Duration serde helpers
2. **MEDIUM**: Supervisor pattern, Heartbeat manager
3. **LOW**: Input validation (platform-specific limits vary)

---

## 5. Recommendations for FCP Connector Design

### R1: Standardize Connector Structure

All FCP connectors should follow this module layout:

```
connectors/<platform>/src/
├── lib.rs           # Re-exports, archetype declaration
├── connector.rs     # Main Connector impl
├── config.rs        # Configuration types
├── error.rs         # Platform-specific errors
├── types.rs         # API types
├── api.rs           # REST client (if applicable)
└── stream.rs        # WebSocket/streaming (if applicable)
```

### R2: Create `fcp-connector-kit` Crate

Extract common patterns into a shared crate:

```rust
// fcp-connector-kit/src/lib.rs
pub mod retry;       // RetryConfig, RetryPolicy
pub mod error;       // RetryableError trait
pub mod heartbeat;   // HeartbeatManager
pub mod supervisor;  // SupervisedConnection
pub mod validation;  // Input validation helpers
pub mod serde_ext;   // Duration serializers, etc.
```

### R3: Define Connector Compliance Checklist

Based on this study, connectors must:

- [ ] Implement `Connector` trait from fcp-core
- [ ] Validate inputs before capability verification
- [ ] Classify errors as retryable/non-retryable
- [ ] Use exponential backoff for retries (1s initial, 60s max)
- [ ] Handle rate limits with Retry-After headers
- [ ] For streaming: implement heartbeat with zombie detection
- [ ] For streaming: support session resumption where platform allows
- [ ] Use broadcast channels for multi-subscriber events
- [ ] Convert platform events to FCP EventEnvelope
- [ ] Provide sensible configuration defaults
- [ ] Define typed structs for all API types
- [ ] Include mock-based unit tests (no network in CI)

### R4: Improve Event Type Safety

Replace `serde_json::Value` with typed event payloads:

```rust
pub enum GatewayEvent {
    MessageCreate(MessageCreateEvent),
    MessageUpdate(MessageUpdateEvent),
    Unknown { event_name: String, data: serde_json::Value },
}

pub struct MessageCreateEvent {
    pub message: Message,
    pub guild_id: Option<String>,
}
```

### R5: Add Structured Logging

The current implementation uses tracing but could benefit from more structured fields:

```rust
#[instrument(
    skip(self),
    fields(
        connector_id = %self.base.connector_id(),
        channel_id = %channel_id,
        message_len = content.len(),
    )
)]
pub async fn send_message(&self, channel_id: &str, content: &str) -> Result<Message>
```

### R6: Consider Connection Pooling

For high-throughput scenarios, the REST client should support connection pooling:

```rust
let client = reqwest::Client::builder()
    .pool_max_idle_per_host(10)
    .pool_idle_timeout(Duration::from_secs(90))
    .build()?;
```

---

## Questions Answered

### How does clawdbot handle Discord's rate limits?

**Answer**: Rate limits are handled in `api.rs` through the retry mechanism. When a 429 response is received, the `retry_after` value is extracted and the request is retried after that delay. The `DiscordError::RateLimited` variant captures this, and `is_retryable()` returns true for rate-limited errors.

### What reconnection strategy is used for the gateway?

**Answer**: The gateway uses a supervisor pattern with exponential backoff:
- Initial delay: 1 second
- Maximum delay: 60 seconds
- Multiplier: 2x per failure
- Backoff resets to 1s on successful connection
- Session state (session_id, sequence) is preserved for Resume

### How are slash commands registered and handled?

**Answer**: The current implementation does NOT include slash command support. It handles:
- REST operations: send/edit/delete messages, get channel/guild
- Gateway events: MESSAGE_CREATE, MESSAGE_UPDATE, GUILD_CREATE, etc.

Slash commands would require additional implementation.

### How is state synchronized across restarts?

**Answer**: Currently, state is NOT persisted across process restarts. The `GatewayState` struct (session_id, resume_url, sequence) only lives in memory. For true persistence, this would need to be written to disk or a database.

### What logging/observability patterns are used?

**Answer**: The connector uses the `tracing` crate with:
- `#[instrument]` macros on key functions
- Structured logging with field captures
- Log levels: debug, info, warn, error
- No explicit metrics emission (relies on `ConnectorMetrics` from BaseConnector)

---

## Appendix: File Summary

| File | Lines | Purpose |
|------|-------|---------|
| lib.rs | 25 | Module exports, archetype declaration |
| connector.rs | 1297 | Main connector implementation |
| gateway.rs | 442 | WebSocket gateway client |
| api.rs | 762 | REST API client + tests |
| config.rs | 146 | Configuration types |
| types.rs | 351 | Discord API type definitions |
| error.rs | 125 | Error types and conversion |
| **Total** | **3148** | |

//! Discord Gateway (WebSocket) client.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async, tungstenite::protocol::Message as WsMessage,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    api::DiscordApiClient,
    config::DiscordConfig,
    error::{DiscordError, DiscordResult},
    types::{
        GatewayHello, GatewayIdentify, GatewayPayload, GatewayProperties, GatewayReady,
        GatewayResume,
    },
};

/// Discord Gateway opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GatewayOpcode {
    /// Receive: An event was dispatched.
    Dispatch = 0,
    /// Send/Receive: Fired periodically to keep the connection alive.
    Heartbeat = 1,
    /// Send: Starts a new session.
    Identify = 2,
    /// Send: Update presence.
    PresenceUpdate = 3,
    /// Send: Join/leave or move between voice channels.
    VoiceStateUpdate = 4,
    /// Send: Resume a previous session.
    Resume = 6,
    /// Receive: Reconnect to the gateway.
    Reconnect = 7,
    /// Send: Request guild members.
    RequestGuildMembers = 8,
    /// Receive: Session invalidated.
    InvalidSession = 9,
    /// Receive: Sent after connecting.
    Hello = 10,
    /// Receive: Heartbeat acknowledged.
    HeartbeatAck = 11,
}

impl TryFrom<i32> for GatewayOpcode {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(GatewayOpcode::Dispatch),
            1 => Ok(GatewayOpcode::Heartbeat),
            2 => Ok(GatewayOpcode::Identify),
            3 => Ok(GatewayOpcode::PresenceUpdate),
            4 => Ok(GatewayOpcode::VoiceStateUpdate),
            6 => Ok(GatewayOpcode::Resume),
            7 => Ok(GatewayOpcode::Reconnect),
            8 => Ok(GatewayOpcode::RequestGuildMembers),
            9 => Ok(GatewayOpcode::InvalidSession),
            10 => Ok(GatewayOpcode::Hello),
            11 => Ok(GatewayOpcode::HeartbeatAck),
            _ => Err(()),
        }
    }
}

/// A gateway event received from Discord.
#[derive(Debug, Clone)]
pub enum GatewayEvent {
    /// Ready event - we're connected.
    Ready(GatewayReady),
    /// Resumed event - session successfully resumed.
    Resumed,
    /// Message created.
    MessageCreate(serde_json::Value),
    /// Message updated.
    MessageUpdate(serde_json::Value),
    /// Message deleted.
    MessageDelete(serde_json::Value),
    /// Guild created (we joined or became available).
    GuildCreate(serde_json::Value),
    /// Guild updated.
    GuildUpdate(serde_json::Value),
    /// Channel created.
    ChannelCreate(serde_json::Value),
    /// Channel updated.
    ChannelUpdate(serde_json::Value),
    /// Typing started.
    TypingStart(serde_json::Value),
    /// Unknown or unhandled event.
    Unknown {
        event_name: String,
        data: serde_json::Value,
    },
}

/// Discord Gateway connection.
pub struct GatewayConnection {
    config: DiscordConfig,
    api_client: Arc<DiscordApiClient>,
    session_id: Option<String>,
    resume_url: Option<String>,
    sequence: Option<u64>,
}

impl GatewayConnection {
    /// Create a new gateway connection.
    pub fn new(config: DiscordConfig, api_client: Arc<DiscordApiClient>) -> Self {
        Self {
            config,
            api_client,
            session_id: None,
            resume_url: None,
            sequence: None,
        }
    }

    /// Update session state from a READY event.
    /// Call this when receiving a READY event to enable session resumption.
    pub fn update_session(&mut self, session_id: String, resume_url: String) {
        self.session_id = Some(session_id);
        self.resume_url = Some(resume_url);
    }

    /// Update the sequence number.
    /// Should be called for each dispatch event received.
    pub fn update_sequence(&mut self, sequence: u64) {
        self.sequence = Some(sequence);
    }

    /// Clear session state (e.g., after InvalidSession with resumable=false).
    pub fn clear_session(&mut self) {
        self.session_id = None;
        self.resume_url = None;
        self.sequence = None;
    }

    /// Check if we have a resumable session.
    pub fn can_resume(&self) -> bool {
        self.session_id.is_some() && self.sequence.is_some()
    }

    /// Connect to the gateway and start receiving events.
    /// If we have a previous session, will attempt to resume.
    #[instrument(skip(self))]
    pub async fn connect(&mut self) -> DiscordResult<mpsc::Receiver<GatewayEvent>> {
        // Use resume_url if we have one (from previous READY), otherwise get fresh URL
        let gateway_url = if let Some(ref url) = self.resume_url {
            info!(url = %url, "Using resume gateway URL");
            url.clone()
        } else {
            self.get_gateway_url().await?
        };

        let (event_tx, event_rx) = mpsc::channel(256);

        // Connect to gateway
        let ws_url = format!("{}/?v=10&encoding=json", gateway_url);
        info!(url = %ws_url, resuming = self.session_id.is_some(), "Connecting to Discord gateway");

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| DiscordError::Gateway(format!("Failed to connect: {e}")))?;

        // Spawn the gateway handler task
        let config = self.config.clone();
        let session_id = self.session_id.clone();
        let sequence = self.sequence;
        let resume_url = self.resume_url.clone();

        tokio::spawn(async move {
            if let Err(e) = run_gateway_loop(
                ws_stream, config, event_tx, session_id, sequence, resume_url,
            )
            .await
            {
                error!(error = %e, "Gateway connection error");
            }
        });

        Ok(event_rx)
    }

    async fn get_gateway_url(&self) -> DiscordResult<String> {
        if let Some(url) = &self.config.gateway_url {
            return Ok(url.clone());
        }
        self.api_client.get_gateway().await
    }
}

/// Run the gateway event loop.
async fn run_gateway_loop(
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    config: DiscordConfig,
    event_tx: mpsc::Sender<GatewayEvent>,
    session_id: Option<String>,
    mut sequence: Option<u64>,
    _resume_url: Option<String>,
) -> DiscordResult<()> {
    let (mut write, mut read) = ws_stream.split();
    // Track session state for potential reconnection (used for logging and future reconnection support)
    let mut _tracked_session_id = session_id.clone();
    let mut _tracked_resume_url: Option<String> = None;

    // Wait for Hello
    let hello = match read.next().await {
        Some(Ok(WsMessage::Text(text))) => {
            let payload: GatewayPayload = serde_json::from_str(&text)?;
            if payload.op != GatewayOpcode::Hello as i32 {
                return Err(DiscordError::Gateway("Expected Hello opcode".into()));
            }
            let hello: GatewayHello = serde_json::from_value(payload.d.unwrap_or_default())?;
            hello
        }
        Some(Ok(msg)) => {
            return Err(DiscordError::Gateway(format!(
                "Unexpected message: {msg:?}"
            )));
        }
        Some(Err(e)) => {
            return Err(DiscordError::Gateway(format!("WebSocket error: {e}")));
        }
        None => {
            return Err(DiscordError::Gateway(
                "Connection closed before Hello".into(),
            ));
        }
    };

    let heartbeat_interval = Duration::from_millis(hello.heartbeat_interval);
    debug!(interval_ms = hello.heartbeat_interval, "Received Hello");

    // Send Resume if we have a session, otherwise Identify
    if let (Some(sess_id), Some(seq)) = (&session_id, sequence) {
        // We have a session to resume
        info!(session_id = %sess_id, sequence = seq, "Attempting to resume session");

        let resume = GatewayResume {
            token: config.bot_token.clone(),
            session_id: sess_id.clone(),
            seq,
        };

        let resume_payload = GatewayPayload {
            op: GatewayOpcode::Resume as i32,
            d: Some(serde_json::to_value(&resume)?),
            s: None,
            t: None,
        };

        write
            .send(WsMessage::Text(
                serde_json::to_string(&resume_payload)?.into(),
            ))
            .await
            .map_err(|e| DiscordError::Gateway(format!("Failed to send Resume: {e}")))?;
    } else {
        // Fresh connection - send Identify
        let identify = GatewayIdentify {
            token: config.bot_token.clone(),
            intents: config.intents,
            properties: GatewayProperties {
                os: std::env::consts::OS.into(),
                browser: "fcp-discord".into(),
                device: "fcp-discord".into(),
            },
            shard: config.shard.as_ref().map(|s| [s.shard_id, s.shard_count]),
        };

        let identify_payload = GatewayPayload {
            op: GatewayOpcode::Identify as i32,
            d: Some(serde_json::to_value(&identify)?),
            s: None,
            t: None,
        };

        write
            .send(WsMessage::Text(
                serde_json::to_string(&identify_payload)?.into(),
            ))
            .await
            .map_err(|e| DiscordError::Gateway(format!("Failed to send Identify: {e}")))?;
    }

    // Main event loop
    let mut heartbeat_acked = true;
    let mut heartbeat_interval_timer = tokio::time::interval(heartbeat_interval);
    // Skip the first tick which fires immediately
    heartbeat_interval_timer.tick().await;

    loop {
        tokio::select! {
            // Handle heartbeat timer
            _ = heartbeat_interval_timer.tick() => {
                if !heartbeat_acked {
                    warn!("Heartbeat not acknowledged, connection may be zombied");
                }
                let heartbeat = json!({
                    "op": GatewayOpcode::Heartbeat as i32,
                    "d": sequence
                });
                if let Err(e) = write.send(WsMessage::Text(heartbeat.to_string().into())).await {
                    error!(error = %e, "Failed to send heartbeat");
                    break;
                }
                heartbeat_acked = false;
                debug!("Sent heartbeat");
            }

            // Handle incoming messages
            msg = read.next() => {
                match msg {
                    Some(Ok(WsMessage::Text(text))) => {
                        let payload: GatewayPayload = match serde_json::from_str(&text) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error = %e, "Failed to parse gateway payload");
                                continue;
                            }
                        };

                        // Update sequence
                        if let Some(s) = payload.s {
                            sequence = Some(s);
                        }

                        match GatewayOpcode::try_from(payload.op) {
                            Ok(GatewayOpcode::Dispatch) => {
                                let event_name = payload.t.clone().unwrap_or_default();
                                let data = payload.d.clone().unwrap_or_default();

                                let event = match event_name.as_str() {
                                    "READY" => {
                                        let ready: GatewayReady = serde_json::from_value(data)?;
                                        _tracked_session_id = Some(ready.session_id.clone());
                                        _tracked_resume_url = Some(ready.resume_gateway_url.clone());
                                        info!(
                                            user = ?ready.user.username,
                                            session_id = %ready.session_id,
                                            "Gateway ready"
                                        );
                                        GatewayEvent::Ready(ready)
                                    }
                                    "RESUMED" => {
                                        info!("Session resumed successfully");
                                        GatewayEvent::Resumed
                                    }
                                    "MESSAGE_CREATE" => GatewayEvent::MessageCreate(data),
                                    "MESSAGE_UPDATE" => GatewayEvent::MessageUpdate(data),
                                    "MESSAGE_DELETE" => GatewayEvent::MessageDelete(data),
                                    "GUILD_CREATE" => GatewayEvent::GuildCreate(data),
                                    "GUILD_UPDATE" => GatewayEvent::GuildUpdate(data),
                                    "CHANNEL_CREATE" => GatewayEvent::ChannelCreate(data),
                                    "CHANNEL_UPDATE" => GatewayEvent::ChannelUpdate(data),
                                    "TYPING_START" => GatewayEvent::TypingStart(data),
                                    _ => GatewayEvent::Unknown { event_name, data },
                                };

                                if event_tx.send(event).await.is_err() {
                                    info!("Event receiver dropped, closing gateway");
                                    break;
                                }
                            }
                            Ok(GatewayOpcode::HeartbeatAck) => {
                                heartbeat_acked = true;
                                debug!("Heartbeat acknowledged");
                            }
                            Ok(GatewayOpcode::Reconnect) => {
                                info!("Received reconnect request");
                                break;
                            }
                            Ok(GatewayOpcode::InvalidSession) => {
                                let resumable = payload.d.and_then(|v| v.as_bool()).unwrap_or(false);
                                warn!(resumable, "Session invalidated");
                                if !resumable {
                                    // Clear session state - must re-identify
                                    _tracked_session_id = None;
                                    _tracked_resume_url = None;
                                }
                                // TODO: Implement automatic reconnection with resume if resumable
                                break;
                            }
                            Ok(GatewayOpcode::Heartbeat) => {
                                // Immediately send heartbeat
                                let heartbeat = json!({
                                    "op": GatewayOpcode::Heartbeat as i32,
                                    "d": sequence
                                });
                                if let Err(e) = write.send(WsMessage::Text(heartbeat.to_string().into())).await {
                                    error!(error = %e, "Failed to send heartbeat response");
                                    break;
                                }
                            }
                            _ => {
                                debug!(op = payload.op, "Unhandled opcode");
                            }
                        }
                    }
                    Some(Ok(WsMessage::Close(frame))) => {
                        info!(frame = ?frame, "Gateway connection closed");
                        break;
                    }
                    Some(Ok(_)) => {
                        // Ignore other message types (ping, pong, binary)
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "WebSocket error");
                        break;
                    }
                    None => {
                        info!("Gateway connection ended");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

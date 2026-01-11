//! Discord REST API client.

use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use crate::{
    config::DiscordConfig,
    error::{DiscordError, DiscordResult},
    types::{Channel, Guild, Message, User},
};

/// Discord REST API client.
#[derive(Debug, Clone)]
pub struct DiscordApiClient {
    client: Client,
    base_url: String,
    bot_token: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
}

impl DiscordApiClient {
    /// Create a new API client from configuration.
    pub fn new(config: &DiscordConfig) -> DiscordResult<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(format!("fcp-discord/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        // Normalize token (remove "Bot " prefix if present)
        let bot_token = config
            .bot_token
            .strip_prefix("Bot ")
            .unwrap_or(&config.bot_token)
            .to_string();

        Ok(Self {
            client,
            base_url: config.api_url.trim_end_matches('/').to_string(),
            bot_token,
            max_retries: config.retry.max_attempts,
            initial_delay_ms: config.retry.initial_delay_ms,
            max_delay_ms: config.retry.max_delay_ms,
        })
    }

    /// Make a GET request.
    #[instrument(skip(self))]
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> DiscordResult<T> {
        self.request("GET", endpoint, None::<&()>).await
    }

    /// Make a POST request.
    #[instrument(skip(self, body))]
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> DiscordResult<T> {
        self.request("POST", endpoint, Some(body)).await
    }

    /// Make a PATCH request.
    #[instrument(skip(self, body))]
    pub async fn patch<T: DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> DiscordResult<T> {
        self.request("PATCH", endpoint, Some(body)).await
    }

    /// Make a DELETE request.
    #[instrument(skip(self))]
    pub async fn delete(&self, endpoint: &str) -> DiscordResult<()> {
        self.request_no_response("DELETE", endpoint).await
    }

    /// Make a request that expects no response body (e.g., DELETE returning 204).
    async fn request_no_response(&self, method: &str, endpoint: &str) -> DiscordResult<()> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, method, endpoint, "Making Discord API request (no response expected)");

            let req = match method {
                "DELETE" => self.client.delete(&url),
                "POST" => self.client.post(&url),
                _ => self.client.get(&url),
            };

            let req = req.header("Authorization", format!("Bot {}", self.bot_token));
            let result = req.send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    // Handle rate limiting
                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<f64>().ok())
                            .unwrap_or(30.0);

                        if attempts < self.max_retries {
                            delay = Duration::from_secs_f64(retry_after);
                            warn!(attempt = attempts, delay_ms = delay.as_millis(), "Rate limited, retrying");
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return Err(DiscordError::RateLimited { retry_after });
                    }

                    if status.is_success() {
                        return Ok(());
                    }

                    // Try to parse error from body
                    let bytes = response.bytes().await?;
                    #[derive(Deserialize)]
                    struct DiscordApiError {
                        code: Option<i32>,
                        message: Option<String>,
                    }
                    let error: DiscordApiError = serde_json::from_slice(&bytes).unwrap_or(DiscordApiError {
                        code: Some(status.as_u16() as i32),
                        message: Some(String::from_utf8_lossy(&bytes).into_owned()),
                    });

                    let err = DiscordError::Api {
                        code: error.code.unwrap_or(status.as_u16() as i32),
                        message: error.message.unwrap_or_else(|| "Unknown error".into()),
                        retry_after: None,
                    };

                    if err.is_retryable() && attempts < self.max_retries {
                        warn!(attempt = attempts, delay_ms = delay.as_millis(), error = %err, "Retrying");
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                        continue;
                    }
                    return Err(err);
                }
                Err(e) if e.is_timeout() || e.is_connect() => {
                    if attempts < self.max_retries {
                        warn!(attempt = attempts, delay_ms = delay.as_millis(), error = %e, "Retrying after connection error");
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    } else {
                        return Err(DiscordError::Http(e));
                    }
                }
                Err(e) => return Err(DiscordError::Http(e)),
            }
        }
    }

    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
    ) -> DiscordResult<T> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(attempt = attempts, method, endpoint, "Making Discord API request");

            let mut req = match method {
                "GET" => self.client.get(&url),
                "POST" => self.client.post(&url),
                "PATCH" => self.client.patch(&url),
                "DELETE" => self.client.delete(&url),
                _ => self.client.get(&url),
            };

            req = req.header("Authorization", format!("Bot {}", self.bot_token));

            if let Some(b) = body {
                req = req.json(b);
            }

            let result = req.send().await;

            match result {
                Ok(response) => {
                    match self.handle_response(response).await {
                        Ok(data) => return Ok(data),
                        Err(e) if e.is_retryable() && attempts < self.max_retries => {
                            if let Some(retry_after) = e.retry_after() {
                                delay = retry_after;
                            }
                            warn!(
                                attempt = attempts,
                                delay_ms = delay.as_millis(),
                                error = %e,
                                "Retrying Discord API request"
                            );
                            tokio::time::sleep(delay).await;
                            delay = std::cmp::min(
                                delay * 2,
                                Duration::from_millis(self.max_delay_ms),
                            );
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.is_timeout() || e.is_connect() => {
                    if attempts < self.max_retries {
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying after connection error"
                        );
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(
                            delay * 2,
                            Duration::from_millis(self.max_delay_ms),
                        );
                    } else {
                        return Err(DiscordError::Http(e));
                    }
                }
                Err(e) => return Err(DiscordError::Http(e)),
            }
        }
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> DiscordResult<T> {
        let status = response.status();

        // Handle rate limiting
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(30.0);

            return Err(DiscordError::RateLimited { retry_after });
        }

        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(DiscordError::from)
        } else {
            // Try to parse Discord error
            #[derive(Deserialize)]
            struct DiscordApiError {
                code: Option<i32>,
                message: Option<String>,
                retry_after: Option<f64>,
            }

            let error: DiscordApiError =
                serde_json::from_slice(&bytes).unwrap_or(DiscordApiError {
                    code: Some(status.as_u16() as i32),
                    message: Some(String::from_utf8_lossy(&bytes).into_owned()),
                    retry_after: None,
                });

            Err(DiscordError::Api {
                code: error.code.unwrap_or(status.as_u16() as i32),
                message: error.message.unwrap_or_else(|| "Unknown error".into()),
                retry_after: error.retry_after,
            })
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the current bot user.
    pub async fn get_current_user(&self) -> DiscordResult<User> {
        self.get("/users/@me").await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Channel endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a channel by ID.
    pub async fn get_channel(&self, channel_id: &str) -> DiscordResult<Channel> {
        self.get(&format!("/channels/{channel_id}")).await
    }

    /// Create a message in a channel.
    pub async fn create_message(
        &self,
        channel_id: &str,
        content: Option<&str>,
        embeds: Option<Vec<crate::types::Embed>>,
        reply_to: Option<&str>,
    ) -> DiscordResult<Message> {
        #[derive(Serialize)]
        struct CreateMessageRequest<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            content: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            embeds: Option<Vec<crate::types::Embed>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            message_reference: Option<MessageReference<'a>>,
        }

        #[derive(Serialize)]
        struct MessageReference<'a> {
            message_id: &'a str,
        }

        let request = CreateMessageRequest {
            content,
            embeds,
            message_reference: reply_to.map(|id| MessageReference { message_id: id }),
        };

        self.post(&format!("/channels/{channel_id}/messages"), &request)
            .await
    }

    /// Edit a message.
    pub async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        content: Option<&str>,
        embeds: Option<Vec<crate::types::Embed>>,
    ) -> DiscordResult<Message> {
        #[derive(Serialize)]
        struct EditMessageRequest<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            content: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            embeds: Option<Vec<crate::types::Embed>>,
        }

        self.patch(
            &format!("/channels/{channel_id}/messages/{message_id}"),
            &EditMessageRequest { content, embeds },
        )
        .await
    }

    /// Delete a message.
    pub async fn delete_message(&self, channel_id: &str, message_id: &str) -> DiscordResult<()> {
        self.delete(&format!("/channels/{channel_id}/messages/{message_id}"))
            .await
    }

    /// Trigger typing indicator.
    pub async fn trigger_typing(&self, channel_id: &str) -> DiscordResult<()> {
        let _: serde_json::Value = self
            .post(&format!("/channels/{channel_id}/typing"), &serde_json::json!({}))
            .await?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Guild endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a guild by ID.
    pub async fn get_guild(&self, guild_id: &str) -> DiscordResult<Guild> {
        self.get(&format!("/guilds/{guild_id}")).await
    }

    /// Get guild channels.
    pub async fn get_guild_channels(&self, guild_id: &str) -> DiscordResult<Vec<Channel>> {
        self.get(&format!("/guilds/{guild_id}/channels")).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gateway
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the gateway URL.
    pub async fn get_gateway(&self) -> DiscordResult<String> {
        #[derive(Deserialize)]
        struct GatewayResponse {
            url: String,
        }

        let resp: GatewayResponse = self.get("/gateway/bot").await?;
        Ok(resp.url)
    }
}

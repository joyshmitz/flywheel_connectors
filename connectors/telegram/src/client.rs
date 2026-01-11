//! Telegram Bot API client.
//!
//! Implements the core Telegram Bot API methods using reqwest.
//! Based on patterns from clawdbot's Telegram integration.

use std::time::Duration;

use reqwest::Client;
use tracing::{instrument, warn};

use crate::types::*;

/// Telegram Bot API client.
#[derive(Debug, Clone)]
pub struct TelegramClient {
    token: String,
    client: Client,
    base_url: String,
}

impl TelegramClient {
    /// Create a new Telegram client.
    ///
    /// # Errors
    /// Returns an error if the HTTP client fails to build.
    pub fn new(token: impl Into<String>) -> Result<Self, TelegramError> {
        let token = token.into();
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(TelegramError::Http)?;

        Ok(Self {
            token,
            client,
            base_url: "https://api.telegram.org".into(),
        })
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Build the API URL for a method.
    fn api_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base_url, self.token, method)
    }

    /// Get bot information.
    #[instrument(skip(self))]
    pub async fn get_me(&self) -> Result<BotInfo, TelegramError> {
        let response: TelegramResponse<BotInfo> = self
            .client
            .get(self.api_url("getMe"))
            .send()
            .await?
            .json()
            .await?;

        if response.ok {
            response.result.ok_or_else(|| TelegramError::Api {
                code: 0,
                description: "Empty result".into(),
            })
        } else {
            Err(TelegramError::Api {
                code: response.error_code.unwrap_or(0),
                description: response.description.unwrap_or_default(),
            })
        }
    }

    /// Get updates using long polling.
    #[instrument(skip(self))]
    pub async fn get_updates(&self, request: GetUpdatesRequest) -> Result<Vec<Update>, TelegramError> {
        let response: TelegramResponse<Vec<Update>> = self
            .client
            .post(self.api_url("getUpdates"))
            .json(&request)
            .timeout(Duration::from_secs(
                u64::try_from(request.timeout.unwrap_or(30)).unwrap_or(30) + 10,
            ))
            .send()
            .await?
            .json()
            .await?;

        if response.ok {
            Ok(response.result.unwrap_or_default())
        } else {
            Err(TelegramError::Api {
                code: response.error_code.unwrap_or(0),
                description: response.description.unwrap_or_default(),
            })
        }
    }

    /// Send a text message.
    #[instrument(skip_all)]
    pub async fn send_message(
        &self,
        chat_id: impl Into<String>,
        text: impl Into<String>,
        options: SendMessageOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMessageRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            text: text.into(),
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };

        let response: TelegramResponse<Message> = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        if response.ok {
            response.result.ok_or_else(|| TelegramError::Api {
                code: 0,
                description: "Empty result".into(),
            })
        } else {
            // Check for parse errors and retry without parse mode
            let desc = response.description.as_deref().unwrap_or("");
            if is_parse_error(desc) && request.parse_mode.is_some() {
                warn!("Parse mode error, retrying without formatting");
                let retry_request = SendMessageRequest {
                    parse_mode: None,
                    ..request
                };
                let retry_response: TelegramResponse<Message> = self
                    .client
                    .post(self.api_url("sendMessage"))
                    .json(&retry_request)
                    .send()
                    .await?
                    .json()
                    .await?;

                if retry_response.ok {
                    return retry_response.result.ok_or_else(|| TelegramError::Api {
                        code: 0,
                        description: "Empty result".into(),
                    });
                }
            }

            Err(TelegramError::Api {
                code: response.error_code.unwrap_or(0),
                description: response.description.unwrap_or_default(),
            })
        }
    }

    /// Get file information for downloading.
    #[instrument(skip_all)]
    pub async fn get_file(&self, file_id: impl Into<String>) -> Result<File, TelegramError> {
        let file_id = file_id.into();
        let response: TelegramResponse<File> = self
            .client
            .get(self.api_url("getFile"))
            .query(&[("file_id", &file_id)])
            .send()
            .await?
            .json()
            .await?;

        if response.ok {
            response.result.ok_or_else(|| TelegramError::Api {
                code: 0,
                description: "Empty result".into(),
            })
        } else {
            Err(TelegramError::Api {
                code: response.error_code.unwrap_or(0),
                description: response.description.unwrap_or_default(),
            })
        }
    }

    /// Download a file by its path.
    pub fn file_download_url(&self, file_path: &str) -> String {
        format!("{}/file/bot{}/{}", self.base_url, self.token, file_path)
    }

    /// Answer a callback query (acknowledge button press).
    #[instrument(skip_all)]
    pub async fn answer_callback_query(
        &self,
        callback_query_id: impl Into<String>,
        text: Option<&str>,
    ) -> Result<bool, TelegramError> {
        let mut params = vec![("callback_query_id", callback_query_id.into())];
        if let Some(t) = text {
            params.push(("text", t.to_string()));
        }

        let response: TelegramResponse<bool> = self
            .client
            .post(self.api_url("answerCallbackQuery"))
            .form(&params)
            .send()
            .await?
            .json()
            .await?;

        if response.ok {
            Ok(response.result.unwrap_or(true))
        } else {
            Err(TelegramError::Api {
                code: response.error_code.unwrap_or(0),
                description: response.description.unwrap_or_default(),
            })
        }
    }
}

/// Options for sending messages.
#[derive(Debug, Default)]
pub struct SendMessageOptions {
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
    pub message_thread_id: Option<i64>,
}

impl SendMessageOptions {
    /// Use HTML parse mode.
    #[must_use]
    pub fn html(mut self) -> Self {
        self.parse_mode = Some("HTML".into());
        self
    }

    /// Use Markdown parse mode.
    #[must_use]
    pub fn markdown(mut self) -> Self {
        self.parse_mode = Some("MarkdownV2".into());
        self
    }

    /// Reply to a specific message.
    #[must_use]
    pub fn reply_to(mut self, message_id: i64) -> Self {
        self.reply_to_message_id = Some(message_id);
        self
    }

    /// Set forum topic thread.
    #[must_use]
    pub fn in_thread(mut self, thread_id: i64) -> Self {
        self.message_thread_id = Some(thread_id);
        self
    }
}

/// Telegram API errors.
#[derive(Debug, thiserror::Error)]
pub enum TelegramError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Telegram API error ({code}): {description}")]
    Api { code: i32, description: String },

    #[error("Invalid chat ID: {0}")]
    InvalidChatId(String),
}

impl TelegramError {
    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::Api { code, .. } => {
                // 429 = rate limited, 500+ = server errors
                *code == 429 || *code >= 500
            }
            Self::InvalidChatId(_) => false,
        }
    }
}

/// Normalize chat ID, handling various formats.
fn normalize_chat_id(id: &str) -> Result<String, TelegramError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(TelegramError::InvalidChatId("Empty chat ID".into()));
    }

    // Strip common prefixes
    let normalized = trimmed
        .strip_prefix("telegram:")
        .or_else(|| trimmed.strip_prefix("tg:"))
        .unwrap_or(trimmed);

    // Strip group: prefix
    let normalized = normalized
        .strip_prefix("group:")
        .unwrap_or(normalized);

    // Handle t.me links
    if let Some(username) = normalized
        .strip_prefix("https://t.me/")
        .or_else(|| normalized.strip_prefix("http://t.me/"))
        .or_else(|| normalized.strip_prefix("t.me/"))
    {
        // Skip invite links (start with +)
        if username.starts_with('+') {
            return Err(TelegramError::InvalidChatId(
                "Cannot use invite links as chat ID".into(),
            ));
        }
        return Ok(format!("@{username}"));
    }

    // If it starts with @, it's a username
    if normalized.starts_with('@') {
        return Ok(normalized.to_string());
    }

    // If it's numeric (with optional leading - for groups), use as-is
    // Valid: "123456", "-100123456" (group IDs start with -)
    let is_valid_numeric = if let Some(rest) = normalized.strip_prefix('-') {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    } else {
        !normalized.is_empty() && normalized.chars().all(|c| c.is_ascii_digit())
    };
    if is_valid_numeric {
        return Ok(normalized.to_string());
    }

    // Assume it's a username without @
    if normalized.len() >= 5 && normalized.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Ok(format!("@{normalized}"));
    }

    Err(TelegramError::InvalidChatId(format!(
        "Cannot parse chat ID: {trimmed}"
    )))
}

/// Check if an error message indicates a parse mode error.
fn is_parse_error(description: &str) -> bool {
    let lower = description.to_lowercase();
    lower.contains("can't parse entities")
        || lower.contains("parse entities")
        || lower.contains("find end of the entity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_normalize_chat_id() {
        // Valid numeric IDs
        assert_eq!(normalize_chat_id("123456").unwrap(), "123456");
        assert_eq!(normalize_chat_id("-100123456").unwrap(), "-100123456");

        // Username formats
        assert_eq!(normalize_chat_id("@username").unwrap(), "@username");
        assert_eq!(normalize_chat_id("myusername").unwrap(), "@myusername");

        // Prefixed formats
        assert_eq!(normalize_chat_id("telegram:123456").unwrap(), "123456");
        assert_eq!(normalize_chat_id("tg:group:-100123456").unwrap(), "-100123456");

        // t.me links
        assert_eq!(normalize_chat_id("t.me/username").unwrap(), "@username");
        assert_eq!(normalize_chat_id("https://t.me/mybot").unwrap(), "@mybot");

        // Invalid inputs
        assert!(normalize_chat_id("").is_err());
        assert!(normalize_chat_id("t.me/+abc123").is_err()); // Invite links not allowed
        assert!(normalize_chat_id("---").is_err()); // Invalid numeric
        assert!(normalize_chat_id("1-2-3").is_err()); // Invalid numeric
        assert!(normalize_chat_id("-").is_err()); // Just a dash
    }

    #[test]
    fn test_is_parse_error() {
        assert!(is_parse_error("can't parse entities"));
        assert!(is_parse_error("Can't Parse Entities: some detail"));
        assert!(is_parse_error("find end of the entity starting"));
        assert!(!is_parse_error("some other error"));
        assert!(!is_parse_error(""));
    }

    // Helper to create a mock server with a test client
    async fn setup_mock_client() -> (MockServer, TelegramClient) {
        let mock_server = MockServer::start().await;
        let client = TelegramClient::new("test_token_12345")
            .unwrap()
            .with_base_url(mock_server.uri());
        (mock_server, client)
    }

    #[tokio::test]
    async fn test_get_me_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/bottest_token_12345/getMe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        let bot_info = client.get_me().await.unwrap();
        assert_eq!(bot_info.id, 123456789);
        assert!(bot_info.is_bot);
        assert_eq!(bot_info.first_name, "Test Bot");
        assert_eq!(bot_info.username.as_deref(), Some("test_bot"));
    }

    #[tokio::test]
    async fn test_get_me_unauthorized() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/bottest_token_12345/getMe"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 401,
                "description": "Unauthorized"
            })))
            .mount(&mock_server)
            .await;

        let result = client.get_me().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            TelegramError::Api { code, description } => {
                assert_eq!(code, 401);
                assert_eq!(description, "Unauthorized");
            }
            _ => panic!("Expected Api error, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_send_message_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 42,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "text": "Hello, World!"
                }
            })))
            .mount(&mock_server)
            .await;

        let message = client
            .send_message("123456", "Hello, World!", SendMessageOptions::default())
            .await
            .unwrap();

        assert_eq!(message.message_id, 42);
        assert_eq!(message.chat.id, 123456);
        assert_eq!(message.text.as_deref(), Some("Hello, World!"));
    }

    #[tokio::test]
    async fn test_send_message_with_html_parse_mode() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 43,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "text": "Bold text"
                }
            })))
            .mount(&mock_server)
            .await;

        let options = SendMessageOptions::default().html();
        let message = client
            .send_message("123456", "<b>Bold text</b>", options)
            .await
            .unwrap();

        assert_eq!(message.message_id, 43);
    }

    #[tokio::test]
    async fn test_send_message_rate_limited() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/sendMessage"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 429,
                "description": "Too Many Requests: retry after 30"
            })))
            .mount(&mock_server)
            .await;

        let result = client
            .send_message("123456", "Test", SendMessageOptions::default())
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_retryable());
        match err {
            TelegramError::Api { code, .. } => {
                assert_eq!(code, 429);
            }
            _ => panic!("Expected Api error"),
        }
    }

    #[tokio::test]
    async fn test_get_updates_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/getUpdates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": [
                    {
                        "update_id": 100,
                        "message": {
                            "message_id": 1,
                            "chat": {
                                "id": 12345,
                                "type": "private",
                                "first_name": "User"
                            },
                            "date": 1234567890,
                            "text": "Hello"
                        }
                    },
                    {
                        "update_id": 101,
                        "message": {
                            "message_id": 2,
                            "chat": {
                                "id": 12345,
                                "type": "private",
                                "first_name": "User"
                            },
                            "date": 1234567891,
                            "text": "World"
                        }
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let request = GetUpdatesRequest {
            offset: None,
            limit: Some(10),
            timeout: Some(5),
            allowed_updates: None,
        };

        let updates = client.get_updates(request).await.unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].update_id, 100);
        assert_eq!(updates[1].update_id, 101);
    }

    #[tokio::test]
    async fn test_get_updates_empty() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("POST"))
            .and(path("/bottest_token_12345/getUpdates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let request = GetUpdatesRequest {
            offset: Some(100),
            limit: Some(10),
            timeout: Some(5),
            allowed_updates: None,
        };

        let updates = client.get_updates(request).await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn test_get_file_success() {
        let (mock_server, client) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/bottest_token_12345/getFile"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "file_id": "AgACAgIAAxkBAAI",
                    "file_unique_id": "AQADAgATqRkyGw",
                    "file_size": 12345,
                    "file_path": "photos/file_0.jpg"
                }
            })))
            .mount(&mock_server)
            .await;

        let file = client.get_file("AgACAgIAAxkBAAI").await.unwrap();
        assert_eq!(file.file_id, "AgACAgIAAxkBAAI");
        assert_eq!(file.file_unique_id, "AQADAgATqRkyGw");
        assert_eq!(file.file_size, Some(12345));
        assert_eq!(file.file_path.as_deref(), Some("photos/file_0.jpg"));
    }

    #[tokio::test]
    async fn test_file_download_url() {
        let client = TelegramClient::new("my_bot_token").unwrap();
        let url = client.file_download_url("photos/file_0.jpg");
        assert_eq!(
            url,
            "https://api.telegram.org/file/botmy_bot_token/photos/file_0.jpg"
        );
    }

    #[tokio::test]
    async fn test_telegram_error_is_retryable() {
        // Rate limited errors should be retryable
        let rate_limited = TelegramError::Api {
            code: 429,
            description: "Too Many Requests".into(),
        };
        assert!(rate_limited.is_retryable());

        // Server errors should be retryable
        let server_error = TelegramError::Api {
            code: 500,
            description: "Internal Server Error".into(),
        };
        assert!(server_error.is_retryable());

        // Client errors should not be retryable
        let bad_request = TelegramError::Api {
            code: 400,
            description: "Bad Request".into(),
        };
        assert!(!bad_request.is_retryable());

        // Invalid chat ID should not be retryable
        let invalid_chat = TelegramError::InvalidChatId("bad".into());
        assert!(!invalid_chat.is_retryable());
    }
}

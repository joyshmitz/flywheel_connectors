//! Twitter FCP Connector implementation.
//!
//! Implements the Flywheel Connector Protocol for Twitter/X API.
//! Supports Operational, Streaming, and Bidirectional archetypes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use fcp_core::{
    BaseConnector, CapabilityGrant, CapabilityVerifier, FcpError, Introspection, OperationInfo,
    SafetyTier,
};
use serde_json::{Value, json};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, instrument};

use crate::{
    client::TwitterApiClient,
    config::TwitterConfig,
    stream::{FilteredStream, StreamEvent},
    types::{CreateTweetRequest, SearchTweetsParams, StreamRule, TweetReply, User},
};

/// Twitter FCP Connector.
pub struct TwitterConnector {
    /// Base connector with metrics
    base: BaseConnector,

    /// Configuration (set via configure)
    config: Option<TwitterConfig>,

    /// API client (created after configure)
    client: Option<Arc<TwitterApiClient>>,

    /// Authenticated user info
    authenticated_user: Option<User>,

    /// Event broadcast sender for subscriptions
    event_tx: broadcast::Sender<Value>,

    /// Active stream handle
    stream_active: Arc<RwLock<bool>>,

    /// Capability verifier
    capability_verifier: Option<Arc<CapabilityVerifier>>,

    /// Stream subscriber count
    stream_subscribers: Arc<AtomicU64>,
}

impl TwitterConnector {
    /// Create a new Twitter connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            base: BaseConnector::new("twitter", env!("CARGO_PKG_VERSION")),
            config: None,
            client: None,
            authenticated_user: None,
            event_tx,
            stream_active: Arc::new(RwLock::new(false)),
            capability_verifier: None,
            stream_subscribers: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Handle the configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> Result<Value, FcpError> {
        info!("Configuring Twitter connector");

        let config: TwitterConfig =
            serde_json::from_value(params).map_err(|e| FcpError::ConfigurationError {
                code: 3001,
                message: format!("Invalid configuration: {e}"),
            })?;

        // Validate required fields
        if config.consumer_key.is_empty() {
            return Err(FcpError::ConfigurationError {
                code: 3002,
                message: "consumer_key is required".into(),
            });
        }
        if config.consumer_secret.is_empty() {
            return Err(FcpError::ConfigurationError {
                code: 3002,
                message: "consumer_secret is required".into(),
            });
        }
        if config.access_token.is_empty() {
            return Err(FcpError::ConfigurationError {
                code: 3002,
                message: "access_token is required".into(),
            });
        }
        if config.access_token_secret.is_empty() {
            return Err(FcpError::ConfigurationError {
                code: 3002,
                message: "access_token_secret is required".into(),
            });
        }

        // Create API client
        let client =
            TwitterApiClient::new(&config).map_err(|e| FcpError::ConfigurationError {
                code: 3003,
                message: format!("Failed to create API client: {e}"),
            })?;

        self.config = Some(config);
        self.client = Some(Arc::new(client));

        Ok(json!({
            "status": "configured"
        }))
    }

    /// Handle the handshake method.
    #[instrument(skip(self, params))]
    pub async fn handle_handshake(&mut self, params: Value) -> Result<Value, FcpError> {
        info!("Performing Twitter connector handshake");

        let client = self.require_client()?;

        // Get authenticated user to verify credentials
        let response = client.get_me().await.map_err(|e| e.to_fcp_error())?;

        let user = response.data.ok_or_else(|| FcpError::Authentication {
            code: 4001,
            message: "Failed to get authenticated user".into(),
        })?;

        info!(username = %user.username, user_id = %user.id, "Authenticated as user");
        self.authenticated_user = Some(user.clone());

        // Set up capability verifier if provided
        if let Some(capabilities) = params.get("capabilities") {
            if let Ok(caps) = serde_json::from_value::<Vec<ConnectorCapability>>(capabilities.clone()) {
                self.capability_verifier = Some(Arc::new(CapabilityVerifier::new(caps)));
            }
        }

        self.base.set_ready(true);

        Ok(json!({
            "status": "ready",
            "user": {
                "id": user.id,
                "name": user.name,
                "username": user.username
            }
        }))
    }

    /// Handle the health method.
    #[instrument(skip(self))]
    pub async fn handle_health(&self) -> Result<Value, FcpError> {
        let metrics = self.base.metrics();

        Ok(json!({
            "status": if self.base.is_ready() { "healthy" } else { "not_ready" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_success": metrics.requests_success,
                "requests_failed": metrics.requests_failed,
                "latency_avg_ms": metrics.latency_avg_ms
            },
            "stream_active": *self.stream_active.read().await,
            "stream_subscribers": self.stream_subscribers.load(Ordering::Relaxed)
        }))
    }

    /// Handle the introspect method.
    #[instrument(skip(self))]
    pub async fn handle_introspect(&self) -> Result<Value, FcpError> {
        let info = IntrospectionInfo {
            name: "fcp-twitter".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: "X/Twitter API connector for the Flywheel Connector Protocol".into(),
            archetypes: vec![
                "operational".into(),
                "streaming".into(),
                "bidirectional".into(),
            ],
            state_model: "singleton_writer".into(),
            operations: vec![
                // Read operations (Safe)
                OperationInfo {
                    name: "twitter.user.me".into(),
                    description: "Get the authenticated user".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.read.account".into()),
                },
                OperationInfo {
                    name: "twitter.user.get".into(),
                    description: "Get a user by ID".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.read.public".into()),
                },
                OperationInfo {
                    name: "twitter.user.by_username".into(),
                    description: "Get a user by username".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.read.public".into()),
                },
                OperationInfo {
                    name: "twitter.tweet.get".into(),
                    description: "Get a tweet by ID".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.read.public".into()),
                },
                OperationInfo {
                    name: "twitter.tweet.search".into(),
                    description: "Search recent tweets".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.read.public".into()),
                },
                OperationInfo {
                    name: "twitter.user.timeline".into(),
                    description: "Get a user's tweets".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.read.public".into()),
                },
                OperationInfo {
                    name: "twitter.user.mentions".into(),
                    description: "Get the authenticated user's mentions".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.read.account".into()),
                },
                // Write operations (Dangerous)
                OperationInfo {
                    name: "twitter.tweet.create".into(),
                    description: "Create a new tweet".into(),
                    safety_tier: SafetyTier::Dangerous,
                    required_capability: Some("twitter.write.tweets".into()),
                },
                OperationInfo {
                    name: "twitter.tweet.reply".into(),
                    description: "Reply to a tweet".into(),
                    safety_tier: SafetyTier::Dangerous,
                    required_capability: Some("twitter.write.tweets".into()),
                },
                OperationInfo {
                    name: "twitter.tweet.delete".into(),
                    description: "Delete a tweet".into(),
                    safety_tier: SafetyTier::Dangerous,
                    required_capability: Some("twitter.write.tweets".into()),
                },
                // Stream operations (Safe for read, Dangerous for rules)
                OperationInfo {
                    name: "twitter.stream.rules.list".into(),
                    description: "List current stream filter rules".into(),
                    safety_tier: SafetyTier::Safe,
                    required_capability: Some("twitter.stream.read".into()),
                },
                OperationInfo {
                    name: "twitter.stream.rules.add".into(),
                    description: "Add stream filter rules".into(),
                    safety_tier: SafetyTier::Dangerous,
                    required_capability: Some("twitter.stream.rules".into()),
                },
                OperationInfo {
                    name: "twitter.stream.rules.delete".into(),
                    description: "Delete stream filter rules".into(),
                    safety_tier: SafetyTier::Dangerous,
                    required_capability: Some("twitter.stream.rules".into()),
                },
            ],
            network_constraints: json!({
                "host_allow": [
                    "api.twitter.com",
                    "upload.twitter.com",
                    "stream.twitter.com"
                ],
                "port_allow": [443],
                "deny_localhost": true,
                "deny_private_ranges": true
            }),
        };

        Ok(serde_json::to_value(info).unwrap_or_default())
    }

    /// Handle the invoke method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&mut self, params: Value) -> Result<Value, FcpError> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing 'operation' field".into(),
            })?;

        let args = params.get("args").cloned().unwrap_or(json!({}));

        debug!(operation = %operation, "Invoking Twitter operation");
        self.base.increment_requests();

        let start = std::time::Instant::now();
        let result = self.dispatch_operation(operation, args).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        self.base.record_latency(latency_ms);

        match &result {
            Ok(_) => self.base.increment_success(),
            Err(_) => self.base.increment_failed(),
        }

        result
    }

    /// Handle the subscribe method.
    #[instrument(skip(self, params))]
    pub async fn handle_subscribe(&mut self, params: Value) -> Result<Value, FcpError> {
        let event_type = params
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("stream");

        if event_type != "stream" {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown event type: {event_type}"),
            });
        }

        // Check capability
        if let Some(verifier) = &self.capability_verifier {
            verifier.require_capability("twitter.stream.read")?;
        }

        let config = self.config.as_ref().ok_or_else(|| FcpError::ConfigurationError {
            code: 3001,
            message: "Connector not configured".into(),
        })?;

        // Start stream if not already active
        let mut stream_active = self.stream_active.write().await;
        if !*stream_active {
            let stream = FilteredStream::new(config.clone()).map_err(|e| e.to_fcp_error())?;

            let mut event_rx = stream.connect().await.map_err(|e| e.to_fcp_error())?;

            let event_tx = self.event_tx.clone();
            let stream_active_flag = self.stream_active.clone();

            tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    let value = match &event {
                        StreamEvent::Tweet(tweet) => {
                            json!({
                                "type": "tweet",
                                "data": tweet
                            })
                        }
                        StreamEvent::Connected => {
                            json!({
                                "type": "connected"
                            })
                        }
                        StreamEvent::Disconnected { reason } => {
                            json!({
                                "type": "disconnected",
                                "reason": reason
                            })
                        }
                        StreamEvent::Heartbeat => {
                            json!({
                                "type": "heartbeat"
                            })
                        }
                        StreamEvent::Error(msg) => {
                            json!({
                                "type": "error",
                                "message": msg
                            })
                        }
                    };

                    if event_tx.send(value).is_err() {
                        // No subscribers
                        break;
                    }
                }

                let mut active = stream_active_flag.write().await;
                *active = false;
            });

            *stream_active = true;
        }

        self.stream_subscribers.fetch_add(1, Ordering::Relaxed);

        Ok(json!({
            "status": "subscribed",
            "event_type": "stream"
        }))
    }

    /// Handle the shutdown method.
    #[instrument(skip(self, _params))]
    pub async fn handle_shutdown(&mut self, _params: Value) -> Result<Value, FcpError> {
        info!("Shutting down Twitter connector");

        // Mark stream as inactive
        let mut stream_active = self.stream_active.write().await;
        *stream_active = false;

        self.base.set_ready(false);

        Ok(json!({
            "status": "shutdown"
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn require_client(&self) -> Result<Arc<TwitterApiClient>, FcpError> {
        self.client.clone().ok_or_else(|| FcpError::ConfigurationError {
            code: 3001,
            message: "Connector not configured".into(),
        })
    }

    fn check_capability(&self, capability: &str) -> Result<(), FcpError> {
        if let Some(verifier) = &self.capability_verifier {
            verifier.require_capability(capability)?;
        }
        Ok(())
    }

    async fn dispatch_operation(&self, operation: &str, args: Value) -> Result<Value, FcpError> {
        match operation {
            // User operations
            "twitter.user.me" => self.op_user_me().await,
            "twitter.user.get" => self.op_user_get(args).await,
            "twitter.user.by_username" => self.op_user_by_username(args).await,

            // Tweet operations
            "twitter.tweet.get" => self.op_tweet_get(args).await,
            "twitter.tweet.search" => self.op_tweet_search(args).await,
            "twitter.tweet.create" => self.op_tweet_create(args).await,
            "twitter.tweet.reply" => self.op_tweet_reply(args).await,
            "twitter.tweet.delete" => self.op_tweet_delete(args).await,

            // Timeline operations
            "twitter.user.timeline" => self.op_user_timeline(args).await,
            "twitter.user.mentions" => self.op_user_mentions(args).await,

            // Stream rule operations
            "twitter.stream.rules.list" => self.op_stream_rules_list().await,
            "twitter.stream.rules.add" => self.op_stream_rules_add(args).await,
            "twitter.stream.rules.delete" => self.op_stream_rules_delete(args).await,

            _ => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_user_me(&self) -> Result<Value, FcpError> {
        self.check_capability("twitter.read.account")?;
        let client = self.require_client()?;

        let response = client.get_me().await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    async fn op_user_get(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.read.public")?;
        let client = self.require_client()?;

        let user_id = args
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument".into(),
            })?;

        let response = client.get_user(user_id).await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    async fn op_user_by_username(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.read.public")?;
        let client = self.require_client()?;

        let username = args
            .get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'username' argument".into(),
            })?;

        // Strip @ if present
        let username = username.trim_start_matches('@');

        let response = client
            .get_user_by_username(username)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tweet operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_tweet_get(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.read.public")?;
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let response = client.get_tweet(tweet_id).await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": response.data,
            "includes": response.includes
        }))
    }

    async fn op_tweet_search(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.read.public")?;
        let client = self.require_client()?;

        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'query' argument".into(),
            })?;

        let params = SearchTweetsParams {
            query: query.to_string(),
            max_results: args.get("max_results").and_then(|v| v.as_u64()).map(|v| v as u32),
            next_token: args.get("next_token").and_then(|v| v.as_str()).map(String::from),
            since_id: args.get("since_id").and_then(|v| v.as_str()).map(String::from),
            sort_order: args.get("sort_order").and_then(|v| v.as_str()).map(String::from),
            ..Default::default()
        };

        let response = client.search_recent(&params).await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_tweet_create(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.write.tweets")?;
        let client = self.require_client()?;

        let text = args
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'text' argument".into(),
            })?;

        // Validate tweet length (280 characters max)
        if text.chars().count() > 280 {
            return Err(FcpError::InvalidRequest {
                code: 1007,
                message: "Tweet exceeds 280 character limit".into(),
            });
        }

        let request = CreateTweetRequest {
            text: Some(text.to_string()),
            ..Default::default()
        };

        let response = client.create_tweet(&request).await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": {
                "id": response.data.id,
                "text": response.data.text
            }
        }))
    }

    async fn op_tweet_reply(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.write.tweets")?;
        let client = self.require_client()?;

        let text = args
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'text' argument".into(),
            })?;

        let reply_to = args
            .get("reply_to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'reply_to' argument".into(),
            })?;

        // Validate tweet length
        if text.chars().count() > 280 {
            return Err(FcpError::InvalidRequest {
                code: 1007,
                message: "Tweet exceeds 280 character limit".into(),
            });
        }

        let request = CreateTweetRequest {
            text: Some(text.to_string()),
            reply: Some(TweetReply {
                in_reply_to_tweet_id: reply_to.to_string(),
                exclude_reply_user_ids: None,
            }),
            ..Default::default()
        };

        let response = client.create_tweet(&request).await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": {
                "id": response.data.id,
                "text": response.data.text
            }
        }))
    }

    async fn op_tweet_delete(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.write.tweets")?;
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let response = client.delete_tweet(tweet_id).await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "deleted": response.data.deleted
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Timeline operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_user_timeline(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.read.public")?;
        let client = self.require_client()?;

        let user_id = args
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument".into(),
            })?;

        let max_results = args.get("max_results").and_then(|v| v.as_u64()).map(|v| v as u32);
        let pagination_token = args.get("pagination_token").and_then(|v| v.as_str());

        let response = client
            .get_user_tweets(user_id, max_results, pagination_token)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_user_mentions(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.read.account")?;
        let client = self.require_client()?;

        // Use authenticated user ID if not provided
        let user_id = if let Some(id) = args.get("user_id").and_then(|v| v.as_str()) {
            id.to_string()
        } else if let Some(user) = &self.authenticated_user {
            user.id.clone()
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument and no authenticated user".into(),
            });
        };

        let max_results = args.get("max_results").and_then(|v| v.as_u64()).map(|v| v as u32);
        let pagination_token = args.get("pagination_token").and_then(|v| v.as_str());

        let response = client
            .get_user_mentions(&user_id, max_results, pagination_token)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stream rule operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_stream_rules_list(&self) -> Result<Value, FcpError> {
        self.check_capability("twitter.stream.read")?;
        let client = self.require_client()?;

        let response = client.get_stream_rules().await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "rules": response.data,
            "meta": response.meta
        }))
    }

    async fn op_stream_rules_add(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.stream.rules")?;
        let client = self.require_client()?;

        let rules_value = args.get("rules").ok_or_else(|| FcpError::InvalidRequest {
            code: 1006,
            message: "Missing 'rules' argument".into(),
        })?;

        let rules: Vec<StreamRule> =
            serde_json::from_value(rules_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid rules format: {e}"),
            })?;

        let response = client.add_stream_rules(&rules).await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "rules": response.data,
            "meta": response.meta,
            "errors": response.errors
        }))
    }

    async fn op_stream_rules_delete(&self, args: Value) -> Result<Value, FcpError> {
        self.check_capability("twitter.stream.rules")?;
        let client = self.require_client()?;

        let ids_value = args.get("ids").ok_or_else(|| FcpError::InvalidRequest {
            code: 1006,
            message: "Missing 'ids' argument".into(),
        })?;

        let ids: Vec<String> =
            serde_json::from_value(ids_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid ids format: {e}"),
            })?;

        let ids_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let response = client
            .delete_stream_rules(&ids_refs)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "meta": response.meta,
            "errors": response.errors
        }))
    }
}

impl Default for TwitterConnector {
    fn default() -> Self {
        Self::new()
    }
}

//! OAuth token types and management.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{OAuthError, OAuthResult, DEFAULT_REFRESH_THRESHOLD};

/// OAuth token response from provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,

    /// Token type (usually "Bearer").
    pub token_type: String,

    /// Lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,

    /// Refresh token (if provided).
    #[serde(default)]
    pub refresh_token: Option<String>,

    /// Granted scopes (space-separated).
    #[serde(default)]
    pub scope: Option<String>,

    /// ID token (OpenID Connect).
    #[serde(default)]
    pub id_token: Option<String>,
}

/// Stored OAuth tokens with metadata.
#[derive(Debug, Clone, Serialize)]
pub struct OAuthTokens {
    /// The access token.
    access_token: String,

    /// Token type (usually "Bearer").
    token_type: String,

    /// When the token expires.
    expires_at: Option<DateTime<Utc>>,

    /// Refresh token for obtaining new access tokens.
    refresh_token: Option<String>,

    /// Granted scopes.
    scopes: Vec<String>,

    /// ID token (OpenID Connect).
    id_token: Option<String>,

    /// When the tokens were issued.
    issued_at: DateTime<Utc>,
}

impl OAuthTokens {
    /// Create tokens from a token response.
    #[must_use]
    pub fn from_response(response: TokenResponse) -> Self {
        let now = Utc::now();
        let expires_at = response
            .expires_in
            .map(|secs| now + chrono::Duration::seconds(secs as i64));

        let scopes = response
            .scope
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default();

        Self {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_at,
            refresh_token: response.refresh_token,
            scopes,
            id_token: response.id_token,
            issued_at: now,
        }
    }

    /// Get the access token.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Get the token type.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Get the refresh token if available.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Get the granted scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Get the ID token if available.
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    /// Check if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() >= exp)
            .unwrap_or(false)
    }

    /// Check if the token needs refresh (within threshold of expiry).
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh_within(DEFAULT_REFRESH_THRESHOLD)
    }

    /// Check if the token needs refresh within a given threshold.
    #[must_use]
    pub fn needs_refresh_within(&self, threshold: Duration) -> bool {
        self.expires_at
            .map(|exp| {
                // Use saturating conversion to avoid panic on extreme durations
                let threshold_chrono = chrono::Duration::from_std(threshold)
                    .unwrap_or(chrono::TimeDelta::MAX);
                let threshold_time = Utc::now() + threshold_chrono;
                threshold_time >= exp
            })
            .unwrap_or(false)
    }

    /// Get time until expiration.
    #[must_use]
    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.expires_at.and_then(|exp| {
            let now = Utc::now();
            if exp > now {
                (exp - now).to_std().ok()
            } else {
                None
            }
        })
    }

    /// Get the authorization header value.
    #[must_use]
    pub fn authorization_header(&self) -> String {
        format!("{} {}", self.token_type, self.access_token)
    }

    /// Update tokens from a refresh response.
    pub fn update_from_response(&mut self, response: TokenResponse) {
        let now = Utc::now();

        self.access_token = response.access_token;
        self.token_type = response.token_type;
        self.expires_at = response
            .expires_in
            .map(|secs| now + chrono::Duration::seconds(secs as i64));
        self.issued_at = now;

        // Only update refresh token if a new one is provided
        if let Some(rt) = response.refresh_token {
            self.refresh_token = Some(rt);
        }

        // Update scopes if provided
        if let Some(scope) = response.scope {
            self.scopes = scope.split_whitespace().map(String::from).collect();
        }

        // Update ID token if provided
        if let Some(id) = response.id_token {
            self.id_token = Some(id);
        }
    }
}

/// In-memory token storage with automatic cleanup.
#[derive(Debug, Clone)]
pub struct TokenStore {
    tokens: Arc<RwLock<HashMap<String, StoredToken>>>,
    /// Time of last cleanup.
    last_cleanup: Arc<RwLock<Instant>>,
    /// Cleanup interval.
    cleanup_interval: Duration,
}

#[derive(Debug)]
struct StoredToken {
    tokens: OAuthTokens,
    /// Optional metadata for the stored token.
    metadata: HashMap<String, String>,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    /// Create a new token store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
            cleanup_interval: Duration::from_secs(60), // Cleanup every minute
        }
    }

    /// Create with custom cleanup interval.
    #[must_use]
    pub const fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// Store tokens with a key.
    pub fn store(&self, key: &str, tokens: OAuthTokens) {
        self.maybe_cleanup();
        let mut store = self.tokens.write();
        store.insert(
            key.to_string(),
            StoredToken {
                tokens,
                metadata: HashMap::new(),
            },
        );
    }

    /// Store tokens with metadata.
    pub fn store_with_metadata(
        &self,
        key: &str,
        tokens: OAuthTokens,
        metadata: HashMap<String, String>,
    ) {
        self.maybe_cleanup();
        let mut store = self.tokens.write();
        store.insert(key.to_string(), StoredToken { tokens, metadata });
    }

    /// Get tokens by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<OAuthTokens> {
        let store = self.tokens.read();
        store.get(key).map(|s| s.tokens.clone())
    }

    /// Get tokens with metadata.
    #[must_use]
    pub fn get_with_metadata(&self, key: &str) -> Option<(OAuthTokens, HashMap<String, String>)> {
        let store = self.tokens.read();
        store.get(key).map(|s| (s.tokens.clone(), s.metadata.clone()))
    }

    /// Check if tokens exist and are valid.
    #[must_use]
    pub fn has_valid_token(&self, key: &str) -> bool {
        self.get(key).map(|t| !t.is_expired()).unwrap_or(false)
    }

    /// Remove tokens by key.
    pub fn remove(&self, key: &str) -> Option<OAuthTokens> {
        let mut store = self.tokens.write();
        store.remove(key).map(|s| s.tokens)
    }

    /// Update tokens (used after refresh).
    pub fn update(&self, key: &str, tokens: OAuthTokens) -> OAuthResult<()> {
        let mut store = self.tokens.write();
        if let Some(stored) = store.get_mut(key) {
            stored.tokens = tokens;
            Ok(())
        } else {
            Err(OAuthError::TokenNotFound(key.to_string()))
        }
    }

    /// Get all stored keys.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.tokens.read().keys().cloned().collect()
    }

    /// Clear all tokens.
    pub fn clear(&self) {
        self.tokens.write().clear();
    }

    /// Cleanup expired tokens.
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.read();
            last.elapsed() >= self.cleanup_interval
        };

        if should_cleanup {
            let mut store = self.tokens.write();
            store.retain(|_, v| !v.tokens.is_expired());
            *self.last_cleanup.write() = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_token_response(expires_in: Option<u64>) -> TokenResponse {
        TokenResponse {
            access_token: "test_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some("test_refresh_token".to_string()),
            scope: Some("read write".to_string()),
            id_token: None,
        }
    }

    #[test]
    fn test_token_from_response() {
        let response = mock_token_response(Some(3600));
        let tokens = OAuthTokens::from_response(response);

        assert_eq!(tokens.access_token(), "test_access_token");
        assert_eq!(tokens.token_type(), "Bearer");
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));
        assert_eq!(tokens.scopes(), &["read", "write"]);
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_token_expiration() {
        // Token that expires immediately
        let response = TokenResponse {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(0),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(response);
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_token_needs_refresh() {
        // Token that expires in 2 minutes (below default 5 minute threshold)
        let response = mock_token_response(Some(120));
        let tokens = OAuthTokens::from_response(response);
        assert!(tokens.needs_refresh());

        // Token that expires in 10 minutes (above threshold)
        let response = mock_token_response(Some(600));
        let tokens = OAuthTokens::from_response(response);
        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn test_authorization_header() {
        let response = mock_token_response(Some(3600));
        let tokens = OAuthTokens::from_response(response);
        assert_eq!(tokens.authorization_header(), "Bearer test_access_token");
    }

    #[test]
    fn test_token_store() {
        let store = TokenStore::new();
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));

        // Store and retrieve
        store.store("user1", tokens.clone());
        assert!(store.has_valid_token("user1"));

        let retrieved = store.get("user1").unwrap();
        assert_eq!(retrieved.access_token(), tokens.access_token());

        // Remove
        store.remove("user1");
        assert!(!store.has_valid_token("user1"));
    }
}

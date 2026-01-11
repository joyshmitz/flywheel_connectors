//! OAuth 2.0 implementation.
//!
//! Supports authorization code flow (with PKCE) and client credentials flow.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    GrantType, OAuthError, OAuthResult, OAuthTokens, Pkce, PkceMethod, ResponseMode, TokenResponse,
};

/// OAuth 2.0 configuration.
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// Client ID.
    pub client_id: String,
    /// Client secret (optional for public clients).
    pub client_secret: Option<String>,
    /// Authorization endpoint URL.
    pub authorization_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Redirect URI for authorization code flow.
    pub redirect_uri: Option<String>,
    /// Default scopes to request.
    pub default_scopes: Vec<String>,
    /// Whether to use PKCE.
    pub use_pkce: bool,
    /// PKCE method.
    pub pkce_method: PkceMethod,
    /// Response mode for authorization.
    pub response_mode: ResponseMode,
    /// Additional authorization parameters.
    pub extra_auth_params: HashMap<String, String>,
    /// Additional token parameters.
    pub extra_token_params: HashMap<String, String>,
    /// HTTP client timeout.
    pub timeout: Duration,
}

impl OAuth2Config {
    /// Create a new OAuth 2.0 configuration.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            redirect_uri: None,
            default_scopes: Vec::new(),
            use_pkce: true,
            pkce_method: PkceMethod::S256,
            response_mode: ResponseMode::Query,
            extra_auth_params: HashMap::new(),
            extra_token_params: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Create configuration for a public client (no secret).
    #[must_use]
    pub fn public_client(
        client_id: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            redirect_uri: None,
            default_scopes: Vec::new(),
            use_pkce: true, // PKCE is required for public clients
            pkce_method: PkceMethod::S256,
            response_mode: ResponseMode::Query,
            extra_auth_params: HashMap::new(),
            extra_token_params: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the redirect URI.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Set default scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.default_scopes = scopes;
        self
    }

    /// Enable or disable PKCE.
    #[must_use]
    pub const fn with_pkce(mut self, enabled: bool) -> Self {
        self.use_pkce = enabled;
        self
    }

    /// Set PKCE method.
    #[must_use]
    pub const fn with_pkce_method(mut self, method: PkceMethod) -> Self {
        self.pkce_method = method;
        self
    }

    /// Set response mode.
    #[must_use]
    pub const fn with_response_mode(mut self, mode: ResponseMode) -> Self {
        self.response_mode = mode;
        self
    }

    /// Add extra authorization parameter.
    #[must_use]
    pub fn with_auth_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_auth_params.insert(key.into(), value.into());
        self
    }

    /// Add extra token parameter.
    #[must_use]
    pub fn with_token_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_token_params.insert(key.into(), value.into());
        self
    }

    /// Set timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// OAuth 2.0 client.
#[derive(Debug, Clone)]
pub struct OAuth2Client {
    config: OAuth2Config,
    http_client: Client,
}

impl OAuth2Client {
    /// Create a new OAuth 2.0 client.
    #[must_use]
    pub fn new(config: OAuth2Config) -> Self {
        let http_client = Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
        }
    }

    /// Create with a custom HTTP client.
    #[must_use]
    pub const fn with_http_client(config: OAuth2Config, http_client: Client) -> Self {
        Self {
            config,
            http_client,
        }
    }

    /// Generate authorization URL without PKCE.
    ///
    /// Returns (authorization_url, state).
    pub fn authorization_url(&self, scopes: &[&str]) -> OAuthResult<(String, String)> {
        let state = generate_state();
        let url = self.build_auth_url(scopes, &state, None)?;
        Ok((url, state))
    }

    /// Generate authorization URL with PKCE.
    ///
    /// Returns (authorization_url, state, pkce).
    pub fn authorization_url_with_pkce(
        &self,
        scopes: &[&str],
    ) -> OAuthResult<(String, String, Pkce)> {
        let state = generate_state();
        let pkce = Pkce::with_method(self.config.pkce_method);
        let url = self.build_auth_url(scopes, &state, Some(&pkce))?;
        Ok((url, state, pkce))
    }

    /// Build the authorization URL.
    fn build_auth_url(
        &self,
        scopes: &[&str],
        state: &str,
        pkce: Option<&Pkce>,
    ) -> OAuthResult<String> {
        let mut url = Url::parse(&self.config.authorization_url)?;

        {
            let mut params = url.query_pairs_mut();

            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.config.client_id);
            params.append_pair("state", state);

            if let Some(redirect_uri) = &self.config.redirect_uri {
                params.append_pair("redirect_uri", redirect_uri);
            }

            // Combine default scopes with requested scopes
            let all_scopes: Vec<&str> = self
                .config
                .default_scopes
                .iter()
                .map(String::as_str)
                .chain(scopes.iter().copied())
                .collect();

            if !all_scopes.is_empty() {
                params.append_pair("scope", &all_scopes.join(" "));
            }

            // PKCE parameters
            if let Some(pkce) = pkce {
                params.append_pair("code_challenge", pkce.challenge());
                params.append_pair("code_challenge_method", &pkce.method().to_string());
            }

            // Response mode (if not default)
            if self.config.response_mode != ResponseMode::Query {
                params.append_pair("response_mode", &self.config.response_mode.to_string());
            }

            // Extra parameters
            for (key, value) in &self.config.extra_auth_params {
                params.append_pair(key, value);
            }
        }

        Ok(url.to_string())
    }

    /// Exchange authorization code for tokens.
    pub async fn exchange_code(&self, code: &str) -> OAuthResult<OAuthTokens> {
        self.exchange_code_internal(code, None).await
    }

    /// Exchange authorization code for tokens with PKCE verification.
    pub async fn exchange_code_with_pkce(
        &self,
        code: &str,
        pkce: &Pkce,
    ) -> OAuthResult<OAuthTokens> {
        self.exchange_code_internal(code, Some(pkce)).await
    }

    /// Internal code exchange implementation.
    async fn exchange_code_internal(
        &self,
        code: &str,
        pkce: Option<&Pkce>,
    ) -> OAuthResult<OAuthTokens> {
        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::AuthorizationCode.to_string());
        params.insert("code", code.to_string());
        params.insert("client_id", self.config.client_id.clone());

        if let Some(secret) = &self.config.client_secret {
            params.insert("client_secret", secret.clone());
        }

        if let Some(redirect_uri) = &self.config.redirect_uri {
            params.insert("redirect_uri", redirect_uri.clone());
        }

        if let Some(pkce) = pkce {
            params.insert("code_verifier", pkce.verifier().to_string());
        }

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        self.token_request(params).await
    }

    /// Get tokens using client credentials flow.
    pub async fn client_credentials(&self, scopes: &[&str]) -> OAuthResult<OAuthTokens> {
        let secret = self.config.client_secret.as_ref().ok_or_else(|| {
            OAuthError::InvalidConfig("Client secret required for client credentials flow".into())
        })?;

        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::ClientCredentials.to_string());
        params.insert("client_id", self.config.client_id.clone());
        params.insert("client_secret", secret.clone());

        let all_scopes: Vec<&str> = self
            .config
            .default_scopes
            .iter()
            .map(String::as_str)
            .chain(scopes.iter().copied())
            .collect();

        if !all_scopes.is_empty() {
            params.insert("scope", all_scopes.join(" "));
        }

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        self.token_request(params).await
    }

    /// Refresh tokens using a refresh token.
    pub async fn refresh_tokens(&self, refresh_token: &str) -> OAuthResult<OAuthTokens> {
        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::RefreshToken.to_string());
        params.insert("refresh_token", refresh_token.to_string());
        params.insert("client_id", self.config.client_id.clone());

        if let Some(secret) = &self.config.client_secret {
            params.insert("client_secret", secret.clone());
        }

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        self.token_request(params).await
    }

    /// Make a token request.
    async fn token_request(&self, params: HashMap<&str, String>) -> OAuthResult<OAuthTokens> {
        let response = self
            .http_client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error: TokenErrorResponse = response.json().await.unwrap_or_else(|_| {
                TokenErrorResponse {
                    error: "unknown_error".to_string(),
                    error_description: None,
                    error_uri: None,
                }
            });

            return Err(OAuthError::TokenExchangeFailed(format!(
                "{}: {}",
                error.error,
                error.error_description.unwrap_or_default()
            )));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(OAuthTokens::from_response(token_response))
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &OAuth2Config {
        &self.config
    }
}

/// OAuth 2.0 error response.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    error_description: Option<String>,
    #[allow(dead_code)] // Part of OAuth spec, kept for debugging/future use
    error_uri: Option<String>,
}

/// Authorization callback parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCallback {
    /// Authorization code.
    pub code: Option<String>,
    /// State parameter.
    pub state: Option<String>,
    /// Error code.
    pub error: Option<String>,
    /// Error description.
    pub error_description: Option<String>,
    /// Error URI.
    pub error_uri: Option<String>,
}

impl AuthorizationCallback {
    /// Parse callback from query string.
    pub fn from_query(query: &str) -> OAuthResult<Self> {
        serde_urlencoded::from_str(query)
            .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))
    }

    /// Parse callback from URL.
    pub fn from_url(url: &str) -> OAuthResult<Self> {
        let parsed = Url::parse(url)?;
        let query = parsed.query().unwrap_or("");
        Self::from_query(query)
    }

    /// Validate the callback and extract the code.
    pub fn validate(&self, expected_state: &str) -> OAuthResult<String> {
        // Check for errors first
        if let Some(error) = &self.error {
            return Err(OAuthError::AuthorizationError {
                error: error.clone(),
                description: self.error_description.clone().unwrap_or_default(),
                error_uri: self.error_uri.clone(),
            });
        }

        // Validate state
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing state parameter".into()))?;

        if state != expected_state {
            return Err(OAuthError::StateMismatch {
                expected: expected_state.to_string(),
                actual: state.clone(),
            });
        }

        // Extract code
        self.code
            .clone()
            .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing authorization code".into()))
    }
}

/// Generate a cryptographically random state parameter.
fn generate_state() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::Rng;

    let bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().r#gen()).collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OAuth2Config {
        OAuth2Config::new(
            "test_client_id",
            "test_client_secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://localhost:3000/callback")
    }

    #[test]
    fn test_authorization_url() {
        let config = test_config();
        let client = OAuth2Client::new(config);

        let (url, state) = client.authorization_url(&["read", "write"]).unwrap();

        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains(&format!("state={state}")));
        assert!(url.contains("scope=read+write"));
        assert!(url.contains("redirect_uri="));
    }

    #[test]
    fn test_authorization_url_with_pkce() {
        let config = test_config();
        let client = OAuth2Client::new(config);

        let (url, _state, pkce) = client.authorization_url_with_pkce(&["read"]).unwrap();

        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(!pkce.verifier().is_empty());
    }

    #[test]
    fn test_callback_validation() {
        let callback = AuthorizationCallback {
            code: Some("auth_code_123".to_string()),
            state: Some("expected_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let code = callback.validate("expected_state").unwrap();
        assert_eq!(code, "auth_code_123");
    }

    #[test]
    fn test_callback_state_mismatch() {
        let callback = AuthorizationCallback {
            code: Some("auth_code_123".to_string()),
            state: Some("wrong_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let result = callback.validate("expected_state");
        assert!(matches!(result, Err(OAuthError::StateMismatch { .. })));
    }

    #[test]
    fn test_callback_error() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".to_string()),
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
            error_uri: None,
        };

        let result = callback.validate("state");
        assert!(matches!(result, Err(OAuthError::AuthorizationError { .. })));
    }

    #[test]
    fn test_public_client_config() {
        let config = OAuth2Config::public_client(
            "public_client",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );

        assert!(config.client_secret.is_none());
        assert!(config.use_pkce); // PKCE should be enabled by default for public clients
    }
}

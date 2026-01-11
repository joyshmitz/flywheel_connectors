//! Test fixtures for common FCP types.
//!
//! Provides pre-built test data and factory functions.

use fcp_core::{CapabilityToken, ConnectorId, HealthSnapshot};

// ─────────────────────────────────────────────────────────────────────────────
// Connector Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Create a test connector ID.
#[must_use]
pub fn test_connector_id() -> ConnectorId {
    ConnectorId::new("test-connector", "test", "1.0.0")
}

/// Create a connector ID with custom values.
#[must_use]
pub fn connector_id(name: &str, archetype: &str, version: &str) -> ConnectorId {
    ConnectorId::new(name, archetype, version)
}

// ─────────────────────────────────────────────────────────────────────────────
// Token Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Create a test capability token.
#[must_use]
pub fn test_token() -> CapabilityToken {
    CapabilityToken::test_token()
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Create a healthy/ready status snapshot.
#[must_use]
pub fn healthy_snapshot() -> HealthSnapshot {
    HealthSnapshot::ready()
}

/// Create an unhealthy/error status snapshot.
#[must_use]
pub fn unhealthy_snapshot(message: &str) -> HealthSnapshot {
    HealthSnapshot::error(message)
}

/// Create a degraded status snapshot.
#[must_use]
pub fn degraded_snapshot(message: &str) -> HealthSnapshot {
    HealthSnapshot::degraded(message)
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Common test JSON values.
pub mod json {
    use serde_json::json;

    /// Empty object.
    #[must_use]
    pub fn empty() -> serde_json::Value {
        json!({})
    }

    /// Simple success response.
    #[must_use]
    pub fn success() -> serde_json::Value {
        json!({"success": true})
    }

    /// Simple error response.
    #[must_use]
    pub fn error(code: &str, message: &str) -> serde_json::Value {
        json!({
            "error": {
                "code": code,
                "message": message
            }
        })
    }

    /// Paginated response.
    #[must_use]
    pub fn paginated<T: serde::Serialize>(items: Vec<T>, total: usize, page: usize) -> serde_json::Value {
        json!({
            "items": items,
            "total": total,
            "page": page,
            "has_more": (page + 1) * items.len() < total
        })
    }

    /// Rate limit error response.
    #[must_use]
    pub fn rate_limited(retry_after: u64) -> serde_json::Value {
        json!({
            "error": {
                "code": "RATE_LIMITED",
                "message": "Too many requests",
                "retry_after": retry_after
            }
        })
    }

    /// Authentication error response.
    #[must_use]
    pub fn auth_error() -> serde_json::Value {
        json!({
            "error": {
                "code": "UNAUTHORIZED",
                "message": "Invalid or expired token"
            }
        })
    }

    /// Not found error response.
    #[must_use]
    pub fn not_found(resource: &str) -> serde_json::Value {
        json!({
            "error": {
                "code": "NOT_FOUND",
                "message": format!("{} not found", resource)
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Common test configuration values.
pub mod config {
    use serde_json::json;

    /// Empty configuration.
    #[must_use]
    pub fn empty() -> serde_json::Value {
        json!({})
    }

    /// API key configuration.
    #[must_use]
    pub fn api_key(key: &str) -> serde_json::Value {
        json!({
            "api_key": key
        })
    }

    /// OAuth configuration.
    #[must_use]
    pub fn oauth(client_id: &str, client_secret: &str) -> serde_json::Value {
        json!({
            "client_id": client_id,
            "client_secret": client_secret
        })
    }

    /// OAuth with tokens.
    #[must_use]
    pub fn oauth_with_tokens(
        client_id: &str,
        client_secret: &str,
        access_token: &str,
        refresh_token: &str,
    ) -> serde_json::Value {
        json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "access_token": access_token,
            "refresh_token": refresh_token
        })
    }

    /// Bot token configuration (for chat platforms).
    #[must_use]
    pub fn bot_token(token: &str) -> serde_json::Value {
        json!({
            "token": token
        })
    }

    /// Database configuration.
    #[must_use]
    pub fn database(host: &str, port: u16, database: &str, user: &str, password: &str) -> serde_json::Value {
        json!({
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "password": password
        })
    }
}

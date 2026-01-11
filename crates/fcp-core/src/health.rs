//! Health types for FCP - health checks and status.
//!
//! Based on FCP Specification Section 13 (Lifecycle Management).

use serde::{Deserialize, Serialize};

/// Health snapshot for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    /// Current health state
    pub status: HealthState,

    /// Uptime in milliseconds
    pub uptime_ms: u64,

    /// Current load (0.0 to 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<f32>,

    /// Additional health details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// Rate limit status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitStatus>,
}

impl Default for HealthSnapshot {
    fn default() -> Self {
        Self {
            status: HealthState::Starting,
            uptime_ms: 0,
            load: None,
            details: None,
            rate_limit: None,
        }
    }
}

impl HealthSnapshot {
    /// Create a healthy snapshot.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            status: HealthState::Ready,
            ..Default::default()
        }
    }

    /// Create a degraded snapshot.
    #[must_use]
    pub fn degraded(reason: impl Into<String>) -> Self {
        Self {
            status: HealthState::Degraded {
                reason: reason.into(),
            },
            ..Default::default()
        }
    }

    /// Create an error snapshot.
    #[must_use]
    pub fn error(reason: impl Into<String>) -> Self {
        Self {
            status: HealthState::Error {
                reason: reason.into(),
            },
            ..Default::default()
        }
    }

    /// Check if the connector is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self.status, HealthState::Ready)
    }

    /// Check if the connector is healthy (ready or degraded).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, HealthState::Ready | HealthState::Degraded { .. })
    }
}

/// Health state enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum HealthState {
    /// Connector is starting up
    Starting,

    /// Connector is ready to accept requests
    Ready,

    /// Connector is operational but with issues
    Degraded {
        /// Reason for degradation
        reason: String,
    },

    /// Connector is in error state
    Error {
        /// Reason for error
        reason: String,
    },

    /// Connector is shutting down
    Stopping,
}

/// Rate limit status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatus {
    /// Maximum requests per window
    pub limit: u32,

    /// Remaining requests in current window
    pub remaining: u32,

    /// Window reset timestamp (Unix seconds)
    pub reset_at: u64,

    /// Window duration in seconds
    pub window_seconds: u32,
}

impl RateLimitStatus {
    /// Check if rate limited.
    #[must_use]
    pub fn is_limited(&self) -> bool {
        self.remaining == 0
    }

    /// Get seconds until reset.
    #[must_use]
    pub fn seconds_until_reset(&self) -> u64 {
        // Use try_from to safely handle negative timestamps (before Unix epoch)
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        self.reset_at.saturating_sub(now)
    }
}

/// Liveness check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessResponse {
    /// Whether the connector is alive
    pub alive: bool,

    /// Timestamp of the check
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for LivenessResponse {
    fn default() -> Self {
        Self {
            alive: true,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Readiness check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessResponse {
    /// Whether the connector is ready
    pub ready: bool,

    /// Components and their readiness
    #[serde(default)]
    pub components: std::collections::HashMap<String, bool>,

    /// Timestamp of the check
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for ReadinessResponse {
    fn default() -> Self {
        Self {
            ready: true,
            components: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now(),
        }
    }
}

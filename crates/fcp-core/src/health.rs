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
    pub const fn is_ready(&self) -> bool {
        matches!(self.status, HealthState::Ready)
    }

    /// Check if the connector is healthy (ready or degraded).
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(
            self.status,
            HealthState::Ready | HealthState::Degraded { .. }
        )
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
    pub const fn is_limited(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ─────────────────────────────────────────────────────────────────────────────
    // HealthState tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_state_starting_serialization() {
        let state = HealthState::Starting;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#"{"state":"starting"}"#);

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HealthState::Starting));
    }

    #[test]
    fn health_state_ready_serialization() {
        let state = HealthState::Ready;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#"{"state":"ready"}"#);

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HealthState::Ready));
    }

    #[test]
    fn health_state_degraded_serialization() {
        let state = HealthState::Degraded {
            reason: "high latency".to_string(),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains(r#""state":"degraded""#));
        assert!(json.contains(r#""reason":"high latency""#));

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        if let HealthState::Degraded { reason } = parsed {
            assert_eq!(reason, "high latency");
        } else {
            panic!("expected Degraded state");
        }
    }

    #[test]
    fn health_state_error_serialization() {
        let state = HealthState::Error {
            reason: "connection failed".to_string(),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains(r#""state":"error""#));
        assert!(json.contains(r#""reason":"connection failed""#));

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        if let HealthState::Error { reason } = parsed {
            assert_eq!(reason, "connection failed");
        } else {
            panic!("expected Error state");
        }
    }

    #[test]
    fn health_state_stopping_serialization() {
        let state = HealthState::Stopping;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#"{"state":"stopping"}"#);

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HealthState::Stopping));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HealthSnapshot tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_snapshot_default() {
        let snapshot = HealthSnapshot::default();

        assert!(matches!(snapshot.status, HealthState::Starting));
        assert_eq!(snapshot.uptime_ms, 0);
        assert!(snapshot.load.is_none());
        assert!(snapshot.details.is_none());
        assert!(snapshot.rate_limit.is_none());
    }

    #[test]
    fn health_snapshot_ready() {
        let snapshot = HealthSnapshot::ready();

        assert!(matches!(snapshot.status, HealthState::Ready));
        assert!(snapshot.is_ready());
        assert!(snapshot.is_healthy());
    }

    #[test]
    fn health_snapshot_degraded() {
        let snapshot = HealthSnapshot::degraded("upstream slow");

        if let HealthState::Degraded { reason } = &snapshot.status {
            assert_eq!(reason, "upstream slow");
        } else {
            panic!("expected Degraded state");
        }
        assert!(!snapshot.is_ready());
        assert!(snapshot.is_healthy());
    }

    #[test]
    fn health_snapshot_error() {
        let snapshot = HealthSnapshot::error("database down");

        if let HealthState::Error { reason } = &snapshot.status {
            assert_eq!(reason, "database down");
        } else {
            panic!("expected Error state");
        }
        assert!(!snapshot.is_ready());
        assert!(!snapshot.is_healthy());
    }

    #[test]
    fn health_snapshot_is_ready_variants() {
        assert!(HealthSnapshot::ready().is_ready());
        assert!(!HealthSnapshot::degraded("x").is_ready());
        assert!(!HealthSnapshot::error("x").is_ready());
        assert!(!HealthSnapshot::default().is_ready()); // Starting
    }

    #[test]
    fn health_snapshot_is_healthy_variants() {
        assert!(HealthSnapshot::ready().is_healthy());
        assert!(HealthSnapshot::degraded("x").is_healthy());
        assert!(!HealthSnapshot::error("x").is_healthy());
        assert!(!HealthSnapshot::default().is_healthy()); // Starting
    }

    #[test]
    fn health_snapshot_serialization_minimal() {
        let snapshot = HealthSnapshot::ready();
        let json = serde_json::to_string(&snapshot).unwrap();

        // Optional fields should be omitted
        assert!(!json.contains("load"));
        assert!(!json.contains("details"));
        assert!(!json.contains("rate_limit"));
    }

    #[test]
    fn health_snapshot_serialization_roundtrip() {
        let mut snapshot = HealthSnapshot::ready();
        snapshot.uptime_ms = 3_600_000;
        snapshot.load = Some(0.75);
        snapshot.details = Some(json!({"connections": 42}));

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: HealthSnapshot = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.status, HealthState::Ready));
        assert_eq!(parsed.uptime_ms, 3_600_000);
        assert!((parsed.load.unwrap() - 0.75).abs() < f32::EPSILON);
        assert_eq!(parsed.details.unwrap()["connections"], 42);
    }

    #[test]
    fn health_snapshot_with_rate_limit() {
        let mut snapshot = HealthSnapshot::ready();
        snapshot.rate_limit = Some(RateLimitStatus {
            limit: 1000,
            remaining: 500,
            reset_at: 1_700_000_000,
            window_seconds: 3600,
        });

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: HealthSnapshot = serde_json::from_str(&json).unwrap();

        let rl = parsed.rate_limit.unwrap();
        assert_eq!(rl.limit, 1000);
        assert_eq!(rl.remaining, 500);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // RateLimitStatus tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_status_is_limited() {
        let limited = RateLimitStatus {
            limit: 100,
            remaining: 0,
            reset_at: 1_700_000_000,
            window_seconds: 60,
        };
        assert!(limited.is_limited());

        let not_limited = RateLimitStatus {
            limit: 100,
            remaining: 50,
            reset_at: 1_700_000_000,
            window_seconds: 60,
        };
        assert!(!not_limited.is_limited());
    }

    #[test]
    fn rate_limit_status_seconds_until_reset_future() {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        let status = RateLimitStatus {
            limit: 100,
            remaining: 0,
            reset_at: now + 300, // 5 minutes in future
            window_seconds: 3600,
        };

        let seconds = status.seconds_until_reset();
        // Should be approximately 300 (allow some slack for test execution)
        assert!((298..=302).contains(&seconds));
    }

    #[test]
    fn rate_limit_status_seconds_until_reset_past() {
        let status = RateLimitStatus {
            limit: 100,
            remaining: 0,
            reset_at: 0, // Way in the past
            window_seconds: 3600,
        };

        // Should saturate to 0, not underflow
        assert_eq!(status.seconds_until_reset(), 0);
    }

    #[test]
    fn rate_limit_status_serialization_roundtrip() {
        let status = RateLimitStatus {
            limit: 500,
            remaining: 123,
            reset_at: 1_700_000_000,
            window_seconds: 3600,
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: RateLimitStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.limit, 500);
        assert_eq!(parsed.remaining, 123);
        assert_eq!(parsed.reset_at, 1_700_000_000);
        assert_eq!(parsed.window_seconds, 3600);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // LivenessResponse tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn liveness_response_default() {
        let resp = LivenessResponse::default();

        assert!(resp.alive);
        // Timestamp should be recent (within last second)
        let now = chrono::Utc::now();
        let diff = (now - resp.timestamp).num_seconds();
        assert!(diff.abs() < 2);
    }

    #[test]
    fn liveness_response_serialization_roundtrip() {
        let resp = LivenessResponse::default();

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: LivenessResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.alive, resp.alive);
        assert_eq!(parsed.timestamp, resp.timestamp);
    }

    #[test]
    fn liveness_response_not_alive() {
        let resp = LivenessResponse {
            alive: false,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: LivenessResponse = serde_json::from_str(&json).unwrap();

        assert!(!parsed.alive);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ReadinessResponse tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn readiness_response_default() {
        let resp = ReadinessResponse::default();

        assert!(resp.ready);
        assert!(resp.components.is_empty());
    }

    #[test]
    fn readiness_response_with_components() {
        let mut components = std::collections::HashMap::new();
        components.insert("database".to_string(), true);
        components.insert("cache".to_string(), true);
        components.insert("queue".to_string(), false);

        let resp = ReadinessResponse {
            ready: false, // Not ready due to queue
            components,
            timestamp: chrono::Utc::now(),
        };

        assert!(!resp.ready);
        assert_eq!(resp.components.len(), 3);
        assert!(resp.components["database"]);
        assert!(!resp.components["queue"]);
    }

    #[test]
    fn readiness_response_serialization_roundtrip() {
        let mut components = std::collections::HashMap::new();
        components.insert("api".to_string(), true);
        components.insert("auth".to_string(), true);

        let resp = ReadinessResponse {
            ready: true,
            components,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ReadinessResponse = serde_json::from_str(&json).unwrap();

        assert!(parsed.ready);
        assert_eq!(parsed.components.len(), 2);
        assert!(parsed.components["api"]);
        assert!(parsed.components["auth"]);
    }

    #[test]
    fn readiness_response_components_default_empty() {
        // Verify the #[serde(default)] annotation works
        let json = r#"{
            "ready": true,
            "timestamp": "2024-01-01T00:00:00Z"
        }"#;

        let resp: ReadinessResponse = serde_json::from_str(json).unwrap();
        assert!(resp.components.is_empty());
    }
}

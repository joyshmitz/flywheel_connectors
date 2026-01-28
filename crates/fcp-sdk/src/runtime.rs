//! Runtime supervision utilities for streaming and polling connectors.
//!
//! This module provides:
//! - [`SupervisorConfig`]: Configuration for backoff, retry budgets, and lifecycle management
//! - [`StreamingSession`]: Trait for streaming connectors to manage session state
//! - [`PollingCursor`]: Trait for polling connectors to manage cursor/offset state
//! - [`HealthTracker`]: Health state machine with transition rules
//!
//! # Design Principles
//!
//! 1. **Config defaults align with study docs** (1s base backoff, 60s cap, jitter on)
//! 2. **Traits are minimal** - connectors provide persistence, SDK provides supervision logic
//! 3. **Health transitions are explicit** - state changes require evidence
//!
//! # Example
//!
//! ```ignore
//! use fcp_sdk::runtime::{SupervisorConfig, HealthTracker, HealthTransition};
//!
//! let config = SupervisorConfig::default();
//! let mut health = HealthTracker::new();
//!
//! // Report failures
//! health.record_failure("connection timeout");
//!
//! // Health degrades after threshold
//! if health.consecutive_failures() >= config.max_consecutive_failures {
//!     health.transition(HealthTransition::ToUnhealthy { reason: "too many failures".into() });
//! }
//! ```

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use fcp_core::{HealthSnapshot, HealthState};

// ─────────────────────────────────────────────────────────────────────────────
// SupervisorConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for connector supervisors (streaming or polling).
///
/// These settings control backoff behavior, retry budgets, and lifecycle
/// management. Defaults align with FCP2 study recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorConfig {
    /// Base delay for exponential backoff (milliseconds).
    ///
    /// After a failure, wait `base_backoff_ms * 2^attempt` before retrying.
    /// Default: 1000ms (1 second).
    pub base_backoff_ms: u64,

    /// Maximum backoff delay (milliseconds).
    ///
    /// Backoff will not exceed this value regardless of attempt count.
    /// Default: 60000ms (60 seconds).
    pub max_backoff_ms: u64,

    /// Whether to add random jitter to backoff delays.
    ///
    /// When enabled, actual delay is `delay * (0.5 + random(0..0.5))`.
    /// Default: true.
    pub jitter_enabled: bool,

    /// Maximum consecutive failures before declaring unhealthy.
    ///
    /// After this many failures in a row without success, the supervisor
    /// should transition to `HealthState::Error`.
    /// Default: 5.
    pub max_consecutive_failures: u32,

    /// Cooldown period after max failures (milliseconds).
    ///
    /// After hitting `max_consecutive_failures`, wait this long before
    /// attempting recovery. This prevents rapid retry storms.
    /// Default: 300000ms (5 minutes).
    pub cooldown_after_failure_ms: u64,

    /// Graceful shutdown timeout (milliseconds).
    ///
    /// Maximum time to wait for in-flight operations during shutdown.
    /// Default: 30000ms (30 seconds).
    pub shutdown_timeout_ms: u64,

    /// Heartbeat interval for streaming sessions (milliseconds).
    ///
    /// How often to send/expect heartbeats. Zero disables heartbeats.
    /// Default: 30000ms (30 seconds).
    pub heartbeat_interval_ms: u64,

    /// Heartbeat timeout multiplier.
    ///
    /// If no heartbeat received within `heartbeat_interval_ms * heartbeat_timeout_multiplier`,
    /// consider the connection dead.
    /// Default: 2.5.
    pub heartbeat_timeout_multiplier: f64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            base_backoff_ms: 1000,
            max_backoff_ms: 60_000,
            jitter_enabled: true,
            max_consecutive_failures: 5,
            cooldown_after_failure_ms: 300_000,
            shutdown_timeout_ms: 30_000,
            heartbeat_interval_ms: 30_000,
            heartbeat_timeout_multiplier: 2.5,
        }
    }
}

impl SupervisorConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set base backoff.
    #[must_use]
    pub const fn with_base_backoff_ms(mut self, ms: u64) -> Self {
        self.base_backoff_ms = ms;
        self
    }

    /// Builder: set max backoff.
    #[must_use]
    pub const fn with_max_backoff_ms(mut self, ms: u64) -> Self {
        self.max_backoff_ms = ms;
        self
    }

    /// Builder: enable/disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, enabled: bool) -> Self {
        self.jitter_enabled = enabled;
        self
    }

    /// Builder: set max consecutive failures.
    #[must_use]
    pub const fn with_max_consecutive_failures(mut self, count: u32) -> Self {
        self.max_consecutive_failures = count;
        self
    }

    /// Compute backoff delay for a given attempt number (0-indexed).
    ///
    /// Returns the delay in milliseconds, capped at `max_backoff_ms`.
    #[must_use]
    pub fn compute_backoff(&self, attempt: u32) -> u64 {
        let exp = attempt.min(30); // Prevent overflow
        let delay = self.base_backoff_ms.saturating_mul(1u64 << exp);
        delay.min(self.max_backoff_ms)
    }

    /// Compute backoff delay with optional jitter.
    ///
    /// If jitter is enabled, returns delay * (0.5 + random factor).
    /// The `jitter_factor` should be in range [0.0, 1.0].
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn compute_backoff_with_jitter(&self, attempt: u32, jitter_factor: f64) -> u64 {
        let base = self.compute_backoff(attempt);
        if self.jitter_enabled {
            let factor = jitter_factor.clamp(0.0, 1.0).mul_add(0.5, 0.5);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let jittered = (base as f64 * factor) as u64;
            jittered
        } else {
            base
        }
    }

    /// Get shutdown timeout as a Duration.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        Duration::from_millis(self.shutdown_timeout_ms)
    }

    /// Get cooldown period as a Duration.
    #[must_use]
    pub const fn cooldown_duration(&self) -> Duration {
        Duration::from_millis(self.cooldown_after_failure_ms)
    }

    /// Get heartbeat interval as a Duration (or None if disabled).
    #[must_use]
    pub const fn heartbeat_interval(&self) -> Option<Duration> {
        if self.heartbeat_interval_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.heartbeat_interval_ms))
        }
    }

    /// Get heartbeat timeout as a Duration (or None if disabled).
    #[must_use]
    pub fn heartbeat_timeout(&self) -> Option<Duration> {
        self.heartbeat_interval().map(|interval| {
            Duration::from_secs_f64(interval.as_secs_f64() * self.heartbeat_timeout_multiplier)
        })
    }

    /// Validate configuration, returning errors for invalid values.
    ///
    /// # Errors
    ///
    /// Returns error strings for any invalid configuration values.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.base_backoff_ms == 0 {
            errors.push("base_backoff_ms must be > 0".to_string());
        }
        if self.max_backoff_ms < self.base_backoff_ms {
            errors.push("max_backoff_ms must be >= base_backoff_ms".to_string());
        }
        if self.max_consecutive_failures == 0 {
            errors.push("max_consecutive_failures must be > 0".to_string());
        }
        if self.heartbeat_timeout_multiplier <= 1.0 {
            errors.push("heartbeat_timeout_multiplier must be > 1.0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamingSession trait
// ─────────────────────────────────────────────────────────────────────────────

/// Session state for streaming connectors (e.g., WebSocket-based).
///
/// Connectors implement this trait to enable session resumption, sequence
/// tracking, and heartbeat management. The supervisor uses these hooks
/// to maintain connection health.
pub trait StreamingSession: Send + Sync {
    /// Get the current resume token (opaque string for session resumption).
    ///
    /// Returns `None` if no session has been established yet.
    fn resume_token(&self) -> Option<String>;

    /// Set the resume token after successful connection.
    fn set_resume_token(&mut self, token: String);

    /// Clear the resume token (e.g., when session is invalidated).
    fn clear_resume_token(&mut self);

    /// Get the current sequence number for ordered message delivery.
    fn sequence(&self) -> u64;

    /// Update the sequence number after processing a message.
    fn set_sequence(&mut self, seq: u64);

    /// Increment and return the next sequence number.
    fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence();
        self.set_sequence(seq.saturating_add(1));
        seq
    }

    /// Record that a heartbeat was sent.
    fn record_heartbeat_sent(&mut self, at: Instant);

    /// Record that a heartbeat acknowledgment was received.
    fn record_heartbeat_ack(&mut self, at: Instant);

    /// Get the timestamp of the last sent heartbeat.
    fn last_heartbeat_sent(&self) -> Option<Instant>;

    /// Get the timestamp of the last received heartbeat acknowledgment.
    fn last_heartbeat_ack(&self) -> Option<Instant>;

    /// Check if heartbeats have timed out.
    ///
    /// Returns `true` if the last ack is older than the configured timeout.
    fn is_heartbeat_timeout(&self, timeout: Duration) -> bool {
        match (self.last_heartbeat_sent(), self.last_heartbeat_ack()) {
            (Some(sent), Some(ack)) => ack < sent && sent.elapsed() > timeout,
            (Some(sent), None) => sent.elapsed() > timeout,
            _ => false,
        }
    }

    /// Persist session state to storage (connector-specific).
    ///
    /// Called periodically and before shutdown to preserve state.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Restore session state from storage (connector-specific).
    ///
    /// Called during startup to resume from previous session.
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails.
    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory implementation of [`StreamingSession`] for testing.
#[derive(Debug, Default)]
pub struct InMemoryStreamingSession {
    resume_token: Option<String>,
    sequence: u64,
    last_heartbeat_sent: Option<Instant>,
    last_heartbeat_ack: Option<Instant>,
}

impl InMemoryStreamingSession {
    /// Create a new in-memory session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl StreamingSession for InMemoryStreamingSession {
    fn resume_token(&self) -> Option<String> {
        self.resume_token.clone()
    }

    fn set_resume_token(&mut self, token: String) {
        self.resume_token = Some(token);
    }

    fn clear_resume_token(&mut self) {
        self.resume_token = None;
    }

    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn set_sequence(&mut self, seq: u64) {
        self.sequence = seq;
    }

    fn record_heartbeat_sent(&mut self, at: Instant) {
        self.last_heartbeat_sent = Some(at);
    }

    fn record_heartbeat_ack(&mut self, at: Instant) {
        self.last_heartbeat_ack = Some(at);
    }

    fn last_heartbeat_sent(&self) -> Option<Instant> {
        self.last_heartbeat_sent
    }

    fn last_heartbeat_ack(&self) -> Option<Instant> {
        self.last_heartbeat_ack
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: no persistence
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: nothing to restore
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PollingCursor trait
// ─────────────────────────────────────────────────────────────────────────────

/// Cursor state for polling connectors (e.g., getUpdates-style APIs).
///
/// Connectors implement this trait to track the current offset/sequence
/// and persist it across restarts. This enables exactly-once processing
/// of updates via offset deduplication.
pub trait PollingCursor: Send + Sync {
    /// Get the current cursor offset (e.g., Telegram `update_id`).
    ///
    /// Returns `None` if no updates have been processed yet.
    fn offset(&self) -> Option<i64>;

    /// Set the cursor offset after processing updates.
    ///
    /// Typically set to `last_update_id + 1` to acknowledge processed updates.
    fn set_offset(&mut self, offset: i64);

    /// Get the last processing timestamp.
    fn last_poll_at(&self) -> Option<Instant>;

    /// Record that a poll was executed.
    fn record_poll(&mut self, at: Instant, updates_received: usize);

    /// Get the count of updates received in the last poll.
    fn last_poll_count(&self) -> usize;

    /// Advance offset by processing an update with the given ID.
    ///
    /// Sets offset to `update_id + 1` if it's newer than current offset.
    fn advance_if_newer(&mut self, update_id: i64) {
        let new_offset = update_id.saturating_add(1);
        if self.offset().is_none_or(|current| new_offset > current) {
            self.set_offset(new_offset);
        }
    }

    /// Persist cursor state to storage (connector-specific).
    ///
    /// Called after processing updates and before shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Restore cursor state from storage (connector-specific).
    ///
    /// Called during startup to resume from previous cursor position.
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails.
    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory implementation of [`PollingCursor`] for testing.
#[derive(Debug, Default)]
pub struct InMemoryPollingCursor {
    offset: Option<i64>,
    last_poll_at: Option<Instant>,
    last_poll_count: usize,
}

impl InMemoryPollingCursor {
    /// Create a new in-memory cursor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a cursor with an initial offset.
    #[must_use]
    pub const fn with_offset(offset: i64) -> Self {
        Self {
            offset: Some(offset),
            last_poll_at: None,
            last_poll_count: 0,
        }
    }
}

impl PollingCursor for InMemoryPollingCursor {
    fn offset(&self) -> Option<i64> {
        self.offset
    }

    fn set_offset(&mut self, offset: i64) {
        self.offset = Some(offset);
    }

    fn last_poll_at(&self) -> Option<Instant> {
        self.last_poll_at
    }

    fn record_poll(&mut self, at: Instant, updates_received: usize) {
        self.last_poll_at = Some(at);
        self.last_poll_count = updates_received;
    }

    fn last_poll_count(&self) -> usize {
        self.last_poll_count
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: no persistence
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: nothing to restore
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health State Machine
// ─────────────────────────────────────────────────────────────────────────────

/// Valid health state transitions.
///
/// The health state machine enforces these transition rules:
/// - `Starting` → `Healthy` (on successful initialization)
/// - `Starting` → `Unhealthy` (on initialization failure)
/// - `Healthy` → `Degraded` (on recoverable failures)
/// - `Healthy` → `Unhealthy` (on unrecoverable failures)
/// - `Degraded` → `Healthy` (on recovery)
/// - `Degraded` → `Unhealthy` (on continued failures)
/// - `Unhealthy` → `Healthy` (on recovery after cooldown)
/// - `Unhealthy` → `Degraded` (on partial recovery)
#[derive(Debug, Clone)]
pub enum HealthTransition {
    /// Transition to healthy state (successful operation).
    ToHealthy,
    /// Transition to degraded state (recoverable issue).
    ToDegraded {
        /// Reason for degradation.
        reason: String,
    },
    /// Transition to unhealthy/error state (unrecoverable issue).
    ToUnhealthy {
        /// Reason for error.
        reason: String,
    },
    /// Transition to starting state (reset).
    ToStarting,
}

/// Tracks connector health with explicit transition rules.
///
/// The tracker maintains:
/// - Current health state
/// - Consecutive failure count
/// - Timestamps for state changes
/// - Snapshot generation
#[derive(Debug)]
pub struct HealthTracker {
    state: HealthState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_failure_reason: Option<String>,
    started_at: Instant,
    last_state_change: Instant,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

impl HealthTracker {
    /// Create a new health tracker in the `Starting` state.
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: HealthState::Starting,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure_reason: None,
            started_at: now,
            last_state_change: now,
            last_success: None,
            last_failure: None,
        }
    }

    /// Get the current health state.
    #[must_use]
    pub const fn state(&self) -> &HealthState {
        &self.state
    }

    /// Check if currently healthy (Ready state).
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self.state, HealthState::Ready)
    }

    /// Check if currently degraded.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self.state, HealthState::Degraded { .. })
    }

    /// Check if currently unhealthy (Error state).
    #[must_use]
    pub const fn is_unhealthy(&self) -> bool {
        matches!(self.state, HealthState::Error { .. })
    }

    /// Get consecutive failure count.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Get consecutive success count.
    #[must_use]
    pub const fn consecutive_successes(&self) -> u32 {
        self.consecutive_successes
    }

    /// Record a successful operation.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        self.last_success = Some(Instant::now());
    }

    /// Record a failed operation.
    pub fn record_failure(&mut self, reason: &str) {
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure = Some(Instant::now());
        self.last_failure_reason = Some(reason.to_string());
    }

    /// Apply a health state transition.
    ///
    /// Returns `true` if the transition was valid and applied.
    pub fn transition(&mut self, transition: HealthTransition) -> bool {
        let valid = self.is_valid_transition(&transition);
        if valid {
            self.apply_transition(transition);
        }
        valid
    }

    /// Check if a transition is valid from the current state.
    ///
    /// Valid transitions:
    /// - `Starting` can transition to any state
    /// - Any state can transition to `Starting` (reset), except `Stopping`
    /// - `Ready` can transition to `Degraded` or `Error`
    /// - `Degraded` can transition to `Ready` or `Error`
    /// - `Error` can transition to `Ready` or `Degraded`
    /// - `Stopping` is terminal (no transitions allowed)
    #[must_use]
    #[allow(clippy::match_same_arms)] // Keep separate arms for documentation clarity
    pub const fn is_valid_transition(&self, transition: &HealthTransition) -> bool {
        match (&self.state, transition) {
            // Stopping is terminal - no transitions allowed
            (HealthState::Stopping, _) => false,
            // Starting can go anywhere
            (HealthState::Starting, _) => true,
            // Restart is always valid (except from Stopping, handled above)
            (_, HealthTransition::ToStarting) => true,
            // Ready can degrade or fail
            (
                HealthState::Ready,
                HealthTransition::ToDegraded { .. } | HealthTransition::ToUnhealthy { .. },
            ) => true,
            // Degraded can recover or fail
            (
                HealthState::Degraded { .. },
                HealthTransition::ToHealthy | HealthTransition::ToUnhealthy { .. },
            ) => true,
            // Error can recover (partially or fully)
            (
                HealthState::Error { .. },
                HealthTransition::ToHealthy | HealthTransition::ToDegraded { .. },
            ) => true,
            _ => false,
        }
    }

    fn apply_transition(&mut self, transition: HealthTransition) {
        self.last_state_change = Instant::now();
        match transition {
            HealthTransition::ToHealthy => {
                self.state = HealthState::Ready;
                self.consecutive_failures = 0;
            }
            HealthTransition::ToDegraded { reason } => {
                self.state = HealthState::Degraded { reason };
            }
            HealthTransition::ToUnhealthy { reason } => {
                self.state = HealthState::Error { reason };
            }
            HealthTransition::ToStarting => {
                self.state = HealthState::Starting;
                self.consecutive_failures = 0;
                self.consecutive_successes = 0;
            }
        }
    }

    /// Generate a health snapshot for the current state.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn snapshot(&self) -> HealthSnapshot {
        let uptime_ms = self.started_at.elapsed().as_millis() as u64;

        // Compute load as a proxy from failure rate (max 10 failures = 1.0 load)
        let load = if self.consecutive_failures > 0 {
            #[allow(clippy::cast_precision_loss)]
            let failure_ratio = self.consecutive_failures.min(10) as f32 / 10.0;
            Some(failure_ratio.min(1.0))
        } else {
            Some(0.0)
        };

        // Include failure reason in details if present
        let details = self.last_failure_reason.as_ref().map(|reason| {
            serde_json::json!({
                "last_error": reason,
                "consecutive_failures": self.consecutive_failures,
            })
        });

        HealthSnapshot {
            status: self.state.clone(),
            uptime_ms,
            load,
            details,
            rate_limit: None,
        }
    }

    /// Check if enough time has passed in unhealthy state for cooldown.
    #[must_use]
    pub fn cooldown_elapsed(&self, cooldown: Duration) -> bool {
        if !self.is_unhealthy() {
            return true;
        }
        self.last_state_change.elapsed() >= cooldown
    }

    /// Evaluate health based on config thresholds and auto-transition.
    ///
    /// Call this after `record_success` or `record_failure` to automatically
    /// transition between states based on configured thresholds.
    pub fn evaluate(&mut self, config: &SupervisorConfig) {
        match &self.state {
            HealthState::Starting => {
                // Auto-transition to Ready after first success
                if self.consecutive_successes > 0 {
                    self.transition(HealthTransition::ToHealthy);
                } else if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "initialization failed".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                }
            }
            HealthState::Ready => {
                // Degrade after some failures, fail after max
                if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "too many failures".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                } else if self.consecutive_failures > 0 {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "recoverable error".to_string());
                    self.transition(HealthTransition::ToDegraded { reason });
                }
            }
            HealthState::Degraded { .. } => {
                // Recover after some successes, fail after max failures
                if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "too many failures".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                } else if self.consecutive_successes >= 3 {
                    // Require 3 consecutive successes to recover
                    self.transition(HealthTransition::ToHealthy);
                }
            }
            HealthState::Error { .. } => {
                // Recover only after cooldown and successes
                if self.cooldown_elapsed(config.cooldown_duration())
                    && self.consecutive_successes > 0
                {
                    self.transition(HealthTransition::ToHealthy);
                }
            }
            HealthState::Stopping => {
                // No auto-transitions from Stopping - it's terminal
            }
        }
    }
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_config_defaults() {
        let config = SupervisorConfig::default();
        assert_eq!(config.base_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60_000);
        assert!(config.jitter_enabled);
        assert_eq!(config.max_consecutive_failures, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn supervisor_config_validation() {
        let config = SupervisorConfig {
            base_backoff_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = SupervisorConfig {
            max_backoff_ms: 500, // Less than base
            base_backoff_ms: 1000,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn backoff_exponential() {
        let config = SupervisorConfig::default().with_jitter(false);
        assert_eq!(config.compute_backoff(0), 1000);
        assert_eq!(config.compute_backoff(1), 2000);
        assert_eq!(config.compute_backoff(2), 4000);
        assert_eq!(config.compute_backoff(3), 8000);
        // Should cap at max
        assert_eq!(config.compute_backoff(10), 60_000);
    }

    #[test]
    fn backoff_with_jitter() {
        let config = SupervisorConfig::default();
        let delay0 = config.compute_backoff_with_jitter(0, 0.0); // Min jitter
        let delay1 = config.compute_backoff_with_jitter(0, 1.0); // Max jitter
        assert!((500..=1000).contains(&delay0));
        assert!((500..=1000).contains(&delay1));
    }

    #[test]
    fn streaming_session_in_memory() {
        let mut session = InMemoryStreamingSession::new();
        assert!(session.resume_token().is_none());
        assert_eq!(session.sequence(), 0);

        session.set_resume_token("token123".to_string());
        assert_eq!(session.resume_token(), Some("token123".to_string()));

        let seq = session.next_sequence();
        assert_eq!(seq, 0);
        assert_eq!(session.sequence(), 1);

        session.clear_resume_token();
        assert!(session.resume_token().is_none());
    }

    #[test]
    fn polling_cursor_advance() {
        let mut cursor = InMemoryPollingCursor::new();
        assert!(cursor.offset().is_none());

        cursor.advance_if_newer(100);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(50); // Older, should not change
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(200);
        assert_eq!(cursor.offset(), Some(201));
    }

    #[test]
    fn health_tracker_transitions() {
        let mut tracker = HealthTracker::new();
        assert!(matches!(tracker.state(), HealthState::Starting));

        // Starting -> Ready
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Degraded
        tracker.record_failure("timeout");
        tracker.transition(HealthTransition::ToDegraded {
            reason: "timeout".to_string(),
        });
        assert!(tracker.is_degraded());

        // Degraded -> Healthy
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Unhealthy
        tracker.transition(HealthTransition::ToUnhealthy {
            reason: "fatal".to_string(),
        });
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_tracker_auto_evaluate() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(3);
        let mut tracker = HealthTracker::new();

        // Starting -> Ready after first success
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());

        // Ready -> Degraded after 1 failure
        tracker.record_failure("err1");
        tracker.evaluate(&config);
        assert!(tracker.is_degraded());

        // Degraded -> Unhealthy after 3 failures
        tracker.record_failure("err2");
        tracker.record_failure("err3");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_snapshot_generation() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);

        let snapshot = tracker.snapshot();
        assert!(matches!(snapshot.status, HealthState::Ready));
        // uptime_ms is always >= 0 for u64, so just verify it exists
        let _ = snapshot.uptime_ms;
        assert_eq!(snapshot.load, Some(0.0));
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Healthy is invalid (already healthy)
        assert!(!tracker.transition(HealthTransition::ToHealthy));

        // Ready -> Starting is always valid (reset)
        assert!(tracker.transition(HealthTransition::ToStarting));
        assert!(matches!(tracker.state(), HealthState::Starting));
    }
}

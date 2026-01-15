//! FCP-specific glue for rate limiting.
//!
//! This module bridges `fcp-core` rate limit declarations (`fcp_core::RateLimit`) with the
//! enforcement algorithms in this crate and produces platform-facing artifacts like
//! `ThrottleViolation` and `BackpressureSignal`.

#![forbid(unsafe_code)]

use std::time::Duration;

use crate::{RateLimitConfig, RateLimitError, RateLimitState, RateLimiter};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Backpressure thresholds expressed in basis points (bps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureThresholds {
    pub warning_bps: u16,
    pub soft_limit_bps: u16,
    pub hard_limit_bps: u16,
}

impl BackpressureThresholds {
    /// Default thresholds:
    /// - warning: 80%
    /// - soft limit: 95%
    /// - hard limit: 100%
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            warning_bps: 8_000,
            soft_limit_bps: 9_500,
            hard_limit_bps: 10_000,
        }
    }
}

impl Default for BackpressureThresholds {
    fn default() -> Self {
        Self::standard()
    }
}

/// Token/quota cost breakdown for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCost {
    pub base_tokens: u32,
    pub bytes_tokens: u32,
    pub compute_tokens: u32,
}

impl TokenCost {
    #[must_use]
    pub const fn total(self) -> u32 {
        self.base_tokens + self.bytes_tokens + self.compute_tokens
    }
}

/// Compute a token cost from base + payload bytes + compute tokens.
///
/// `bytes_per_token` is a ceiling division unit; e.g. `bytes=1001` with `bytes_per_token=1000`
/// results in `bytes_tokens=2`.
///
/// # Errors
/// Returns an error if `bytes_per_token == 0` or arithmetic overflows.
pub fn compute_token_cost(
    base_tokens: u32,
    bytes: u64,
    bytes_per_token: u64,
    compute_tokens: u32,
) -> Result<TokenCost, RateLimitError> {
    if bytes_per_token == 0 {
        return Err(RateLimitError::InvalidConfig(
            "bytes_per_token must be > 0".into(),
        ));
    }

    let bytes_tokens_u64 = if bytes == 0 {
        0
    } else {
        let div = bytes / bytes_per_token;
        let rem = bytes % bytes_per_token;
        div + u64::from(rem != 0)
    };
    let bytes_tokens = u32::try_from(bytes_tokens_u64)
        .map_err(|_| RateLimitError::InvalidConfig("bytes too large".into()))?;

    let _total = base_tokens
        .checked_add(bytes_tokens)
        .and_then(|v| v.checked_add(compute_tokens))
        .ok_or_else(|| RateLimitError::InvalidConfig("token cost overflow".into()))?;

    Ok(TokenCost {
        base_tokens,
        bytes_tokens,
        compute_tokens,
    })
}

/// Context used to annotate a rate limit decision.
#[derive(Debug, Clone)]
pub struct ThrottleContext {
    pub zone_id: fcp_core::ZoneId,
    pub connector_id: Option<fcp_core::ConnectorId>,
    pub operation_id: Option<fcp_core::OperationId>,
    pub limit_type: fcp_core::LimitType,
}

/// Result of a rate limit enforcement check.
#[derive(Debug, Clone)]
pub struct EnforcementOutcome {
    pub allowed: bool,
    pub state: RateLimitState,
    pub backpressure: fcp_core::BackpressureSignal,
    pub violation: Option<fcp_core::ThrottleViolation>,
}

impl EnforcementOutcome {
    #[must_use]
    pub fn as_rate_limited_error(&self) -> Option<fcp_core::FcpError> {
        if self.allowed {
            return None;
        }

        let retry_after_ms = self
            .backpressure
            .retry_after_ms
            .or_else(|| self.violation.as_ref().map(|v| v.retry_after_ms))
            .unwrap_or(0);

        Some(fcp_core::FcpError::RateLimited {
            retry_after_ms,
            violation: self.violation.clone().map(Box::new),
        })
    }
}

/// Concurrency limiter for "max in-flight operations" style constraints.
#[derive(Debug, Clone)]
pub struct ConcurrencyLimiter {
    semaphore: Arc<Semaphore>,
    max: u32,
}

impl ConcurrencyLimiter {
    /// Create a new limiter.
    ///
    /// # Errors
    /// Returns an error if `max_concurrent == 0` or exceeds platform limits.
    pub fn new(max_concurrent: u32) -> Result<Self, RateLimitError> {
        if max_concurrent == 0 {
            return Err(RateLimitError::InvalidConfig(
                "max_concurrent must be > 0".into(),
            ));
        }
        let permits = usize::try_from(max_concurrent)
            .map_err(|_| RateLimitError::InvalidConfig("max_concurrent exceeds usize".into()))?;
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            max: max_concurrent,
        })
    }

    #[must_use]
    pub const fn max_concurrent(&self) -> u32 {
        self.max
    }

    #[must_use]
    pub fn in_flight(&self) -> u32 {
        let available = u32::try_from(self.semaphore.available_permits()).unwrap_or(0);
        self.max.saturating_sub(available)
    }

    #[must_use]
    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.semaphore).try_acquire_owned().ok()
    }

    /// Try to acquire, returning a structured `FcpError::RateLimited` with `ThrottleViolation`.
    pub fn try_acquire_or_violation(
        &self,
        ctx: &ThrottleContext,
    ) -> Result<OwnedSemaphorePermit, fcp_core::FcpError> {
        self.try_acquire().ok_or_else(|| {
            let timestamp_ms = now_timestamp_ms();
            let in_flight = self.in_flight().saturating_add(1);
            let violation = fcp_core::ThrottleViolation::new(fcp_core::ThrottleViolationInput {
                timestamp_ms,
                zone_id: ctx.zone_id.clone(),
                connector_id: ctx.connector_id.clone(),
                operation_id: ctx.operation_id.clone(),
                limit_type: ctx.limit_type,
                limit_value: self.max,
                current_value: in_flight,
                retry_after_ms: 0,
            });

            fcp_core::FcpError::RateLimited {
                retry_after_ms: 0,
                violation: Some(Box::new(violation)),
            }
        })
    }
}

/// Convert a structured `fcp_core::RateLimit` into a concrete algorithm configuration.
///
/// Semantics:
/// - `max` → requests per window
/// - `per_ms` → window duration
/// - `burst` (if present) is interpreted as *additional* burst allowance above `max`.
///
/// # Errors
/// Returns an error if `max == 0`, `per_ms == 0`, or burst math overflows.
pub fn config_from_core(rate: &fcp_core::RateLimit) -> Result<RateLimitConfig, RateLimitError> {
    if rate.max == 0 {
        return Err(RateLimitError::InvalidConfig(
            "RateLimit.max must be > 0".into(),
        ));
    }
    if rate.per_ms == 0 {
        return Err(RateLimitError::InvalidConfig(
            "RateLimit.per_ms must be > 0".into(),
        ));
    }

    let window = Duration::from_millis(rate.per_ms);
    let mut cfg = RateLimitConfig::new(rate.max, window);

    if let Some(burst) = rate.burst {
        let capacity = rate
            .max
            .checked_add(burst)
            .ok_or_else(|| RateLimitError::InvalidConfig("burst overflow".into()))?;
        cfg = cfg.with_burst(capacity);
    }

    Ok(cfg)
}

/// Enforce a limiter, producing `BackpressureSignal` and (when rejected) `ThrottleViolation`.
pub async fn enforce(
    limiter: &dyn RateLimiter,
    permits: u32,
    ctx: &ThrottleContext,
    thresholds: BackpressureThresholds,
) -> EnforcementOutcome {
    let timestamp_ms = now_timestamp_ms();

    // Attempt to acquire permits; if the limiter does not support multi-permit acquisition,
    // it will conservatively deny.
    let allowed = limiter.try_acquire_n(permits).await;
    let state = limiter.state();
    let backpressure = backpressure_from_state(&state, thresholds);

    let violation = if allowed {
        None
    } else {
        let retry_after_ms = backpressure.retry_after_ms.unwrap_or(0);
        let current_value = state
            .limit
            .saturating_sub(state.remaining)
            .saturating_add(permits);

        Some(fcp_core::ThrottleViolation::new(
            fcp_core::ThrottleViolationInput {
                timestamp_ms,
                zone_id: ctx.zone_id.clone(),
                connector_id: ctx.connector_id.clone(),
                operation_id: ctx.operation_id.clone(),
                limit_type: ctx.limit_type,
                limit_value: state.limit,
                current_value,
                retry_after_ms,
            },
        ))
    };

    EnforcementOutcome {
        allowed,
        state,
        backpressure,
        violation,
    }
}

fn now_timestamp_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn backpressure_from_state(
    state: &RateLimitState,
    thresholds: BackpressureThresholds,
) -> fcp_core::BackpressureSignal {
    let utilization_bps = utilization_bps(state.limit, state.remaining);
    let mut level = fcp_core::BackpressureLevel::Normal;

    if utilization_bps >= thresholds.warning_bps {
        level = fcp_core::BackpressureLevel::Warning;
    }
    if utilization_bps >= thresholds.soft_limit_bps {
        level = fcp_core::BackpressureLevel::SoftLimit;
    }
    if utilization_bps >= thresholds.hard_limit_bps || state.is_limited {
        level = fcp_core::BackpressureLevel::HardLimit;
    }

    let retry_after_ms = match level {
        fcp_core::BackpressureLevel::SoftLimit | fcp_core::BackpressureLevel::HardLimit => {
            Some(u64::try_from(state.reset_after.as_millis()).unwrap_or(u64::MAX))
        }
        fcp_core::BackpressureLevel::Normal | fcp_core::BackpressureLevel::Warning => None,
    };

    fcp_core::BackpressureSignal {
        level,
        utilization_bps,
        retry_after_ms,
    }
}

fn utilization_bps(limit: u32, remaining: u32) -> u16 {
    if limit == 0 {
        return 0;
    }
    let used = limit.saturating_sub(remaining);
    let bps = (u64::from(used) * 10_000_u64) / u64::from(limit);
    u16::try_from(bps).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenBucket;

    #[test]
    fn token_cost_ceil_div_bytes() {
        let cost = compute_token_cost(1, 1001, 1000, 0).unwrap();
        assert_eq!(
            cost,
            TokenCost {
                base_tokens: 1,
                bytes_tokens: 2,
                compute_tokens: 0
            }
        );
        assert_eq!(cost.total(), 3);
    }

    #[test]
    fn token_cost_rejects_zero_bytes_per_token() {
        let err = compute_token_cost(1, 10, 0, 0).unwrap_err();
        assert!(err.to_string().contains("bytes_per_token"));
    }

    #[tokio::test]
    async fn config_from_core_maps_burst_as_additional_capacity() {
        let core = fcp_core::RateLimit {
            max: 100,
            per_ms: 60_000,
            burst: Some(10),
            scope: None,
        };

        let cfg = config_from_core(&core).unwrap();
        assert_eq!(cfg.requests_per_window, 100);
        assert_eq!(cfg.window, Duration::from_secs(60));
        assert_eq!(cfg.burst_size, Some(110));
    }

    #[tokio::test]
    async fn enforce_emits_soft_backpressure_without_rejecting() {
        // Create a limiter with small capacity so we can push utilization > 95% without full
        // rejection.
        let limiter = TokenBucket::new(20, Duration::from_secs(60));
        // Leave headroom for the `enforce()` call to consume one more token without exhausting.
        for _ in 0..18 {
            assert!(limiter.try_acquire().await);
        }

        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("fcp.test:request_response:0.0.1".parse().unwrap()),
            operation_id: Some("test.op".parse().unwrap()),
            limit_type: fcp_core::LimitType::Rpm,
        };

        let out = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
        assert!(out.allowed);
        assert!(matches!(
            out.backpressure.level,
            fcp_core::BackpressureLevel::SoftLimit
        ));
        assert!(out.backpressure.retry_after_ms.is_some());
        assert!(out.violation.is_none());
    }

    #[tokio::test]
    async fn enforce_rejects_and_emits_throttle_violation_at_hard_limit() {
        let limiter = TokenBucket::new(2, Duration::from_secs(60));
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);

        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: fcp_core::LimitType::Rpm,
        };

        let out = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
        assert!(!out.allowed);
        assert!(matches!(
            out.backpressure.level,
            fcp_core::BackpressureLevel::HardLimit
        ));
        assert!(out.violation.is_some());

        let err = out.as_rate_limited_error().unwrap();
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-3002");
        assert!(resp.details.is_some());
        assert!(resp.details.unwrap().get("throttle_violation").is_some());
    }

    #[test]
    fn concurrency_limiter_emits_throttle_violation_when_exhausted() {
        let limiter = ConcurrencyLimiter::new(2).unwrap();
        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: fcp_core::LimitType::Concurrent,
        };

        let _p1 = limiter.try_acquire_or_violation(&ctx).unwrap();
        let _p2 = limiter.try_acquire_or_violation(&ctx).unwrap();
        let err = limiter.try_acquire_or_violation(&ctx).unwrap_err();

        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-3002");
        assert!(resp.details.is_some());
        let details = resp.details.unwrap();
        assert_eq!(details["throttle_violation"]["limit_type"], "concurrent");
    }
}

//! Retry policy helpers.

use std::time::Duration;

use rand::Rng;

use crate::error::GraphqlClientError;

/// Retry decision result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry after a delay.
    RetryAfter(Duration),
    /// Do not retry.
    DoNotRetry,
}

/// Retry strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryStrategy {
    /// Never retry.
    Never,
    /// Retry only for idempotent operations.
    IdempotentOnly,
    /// Retry regardless of idempotency.
    Always,
}

/// Retry policy configuration.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the initial attempt).
    pub max_attempts: usize,
    /// Base delay for exponential backoff.
    pub base_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Maximum jitter to add to delays.
    pub max_jitter: Duration,
    /// Retry strategy.
    pub strategy: RetryStrategy,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
            max_jitter: Duration::from_millis(150),
            strategy: RetryStrategy::IdempotentOnly,
        }
    }
}

impl RetryPolicy {
    /// Decide whether to retry based on the error and attempt count.
    #[must_use]
    pub fn decide(
        &self,
        error: &GraphqlClientError,
        attempt: usize,
        idempotent: bool,
    ) -> RetryDecision {
        if attempt >= self.max_attempts {
            return RetryDecision::DoNotRetry;
        }
        if !error.is_retryable() {
            return RetryDecision::DoNotRetry;
        }

        match self.strategy {
            RetryStrategy::Never => RetryDecision::DoNotRetry,
            RetryStrategy::IdempotentOnly if !idempotent => RetryDecision::DoNotRetry,
            _ => {
                let base_ms = u64::try_from(self.base_delay.as_millis()).unwrap_or(u64::MAX);
                let exp = 2_u64
                    .saturating_pow(u32::try_from(attempt.saturating_sub(1)).unwrap_or(u32::MAX));
                let mut delay_ms = base_ms.saturating_mul(exp);
                let max_ms = u64::try_from(self.max_delay.as_millis()).unwrap_or(u64::MAX);
                if delay_ms > max_ms {
                    delay_ms = max_ms;
                }
                let jitter_ms = if self.max_jitter.as_millis() > 0 {
                    let mut rng = rand::thread_rng();
                    let jitter_max = u64::try_from(self.max_jitter.as_millis()).unwrap_or(u64::MAX);
                    rng.gen_range(0..=jitter_max)
                } else {
                    0
                };
                RetryDecision::RetryAfter(Duration::from_millis(delay_ms + jitter_ms))
            }
        }
    }
}

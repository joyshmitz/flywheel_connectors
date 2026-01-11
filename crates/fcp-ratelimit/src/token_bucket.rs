//! Token bucket rate limiter implementation.
//!
//! Classic token bucket algorithm with burst support.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::time::sleep;

use async_trait::async_trait;

use crate::{RateLimitConfig, RateLimitError, RateLimitState, RateLimiter};

/// Token bucket rate limiter.
///
/// Tokens are added at a fixed rate up to a maximum bucket size.
/// Each request consumes one token.
pub struct TokenBucket {
    /// Maximum tokens (bucket capacity).
    capacity: u32,

    /// Tokens added per refill.
    refill_amount: u32,

    /// Time between refills.
    refill_interval: Duration,

    /// Current token count.
    tokens: AtomicU32,

    /// Last refill time.
    last_refill: Mutex<Instant>,
}

impl TokenBucket {
    /// Create a new token bucket rate limiter.
    ///
    /// # Arguments
    ///
    /// * `requests_per_window` - Maximum requests allowed per window
    /// * `window` - Duration of the rate limit window
    #[must_use]
    pub fn new(requests_per_window: u32, window: Duration) -> Self {
        Self {
            capacity: requests_per_window,
            refill_amount: requests_per_window,
            refill_interval: window,
            tokens: AtomicU32::new(requests_per_window),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Create from configuration.
    #[must_use]
    pub fn from_config(config: &RateLimitConfig) -> Self {
        let capacity = config.burst_size.unwrap_or(config.requests_per_window);
        Self {
            capacity,
            refill_amount: config.requests_per_window,
            refill_interval: config.window,
            tokens: AtomicU32::new(capacity),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Create with burst capacity.
    #[must_use]
    pub fn with_burst(requests_per_window: u32, window: Duration, burst: u32) -> Self {
        Self {
            capacity: burst,
            refill_amount: requests_per_window,
            refill_interval: window,
            tokens: AtomicU32::new(burst),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&self) {
        let mut last_refill = self.last_refill.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);

        if elapsed >= self.refill_interval {
            // Calculate how many refill periods have passed
            // Use saturating conversion to avoid overflow with large elapsed times
            let periods = (elapsed.as_nanos() / self.refill_interval.as_nanos())
                .try_into()
                .unwrap_or(u32::MAX);
            let tokens_to_add = periods.saturating_mul(self.refill_amount);

            // Add tokens up to capacity using compare_exchange to avoid race with try_acquire
            loop {
                let current = self.tokens.load(Ordering::Acquire);
                let new_tokens = current.saturating_add(tokens_to_add).min(self.capacity);

                // If already at or above capacity after adding, just break
                if new_tokens == current {
                    break;
                }

                if self
                    .tokens
                    .compare_exchange(current, new_tokens, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
                // CAS failed, retry with fresh value
            }

            // Update last refill time
            *last_refill = now;
        }
    }

    /// Calculate time until next token is available.
    fn time_until_token(&self) -> Duration {
        let last_refill = *self.last_refill.lock();
        let elapsed = Instant::now().duration_since(last_refill);

        if elapsed >= self.refill_interval {
            Duration::ZERO
        } else {
            self.refill_interval - elapsed
        }
    }
}

#[async_trait]
impl RateLimiter for TokenBucket {
    async fn try_acquire(&self) -> bool {
        self.refill();

        // Try to consume a token
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current == 0 {
                return false;
            }

            if self
                .tokens
                .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    async fn acquire(&self, max_wait: Duration) -> Result<Duration, RateLimitError> {
        let start = Instant::now();

        loop {
            if self.try_acquire().await {
                return Ok(start.elapsed());
            }

            let wait_time = self.wait_time().await;
            let total_waited = start.elapsed();

            if total_waited + wait_time > max_wait {
                return Err(RateLimitError::WaitExceeded {
                    wait_time: total_waited + wait_time,
                    max_wait,
                });
            }

            sleep(wait_time).await;
        }
    }

    fn remaining(&self) -> u32 {
        self.tokens.load(Ordering::Acquire)
    }

    async fn wait_time(&self) -> Duration {
        if self.tokens.load(Ordering::Acquire) > 0 {
            Duration::ZERO
        } else {
            self.time_until_token()
        }
    }

    async fn reset(&self) {
        self.tokens.store(self.capacity, Ordering::Release);
        *self.last_refill.lock() = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        self.refill();
        let remaining = self.tokens.load(Ordering::Acquire);

        RateLimitState {
            limit: self.capacity,
            remaining,
            reset_after: self.time_until_token(),
            is_limited: remaining == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_basic() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }

        // 6th should fail
        assert!(!limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let limiter = TokenBucket::new(2, Duration::from_millis(100));

        // Consume all tokens
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // Wait for refill
        sleep(Duration::from_millis(150)).await;

        // Should have tokens again
        assert!(limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn test_token_bucket_state() {
        let limiter = TokenBucket::new(10, Duration::from_secs(1));

        let state = limiter.state();
        assert_eq!(state.limit, 10);
        assert_eq!(state.remaining, 10);
        assert!(!state.is_limited);

        // Consume some tokens
        for _ in 0..7 {
            limiter.try_acquire().await;
        }

        let state = limiter.state();
        assert_eq!(state.remaining, 3);
    }

    #[tokio::test]
    async fn test_token_bucket_acquire_with_wait() {
        let limiter = TokenBucket::new(1, Duration::from_millis(50));

        // First request succeeds immediately
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(10));

        // Second request should wait
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited >= Duration::from_millis(40));
    }
}

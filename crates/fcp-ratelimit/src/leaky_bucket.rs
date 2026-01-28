//! Leaky bucket rate limiter implementation.
//!
//! Provides smooth request pacing with queue support.

use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::time::sleep;

use async_trait::async_trait;

use crate::{RateLimitError, RateLimitState, RateLimiter};

/// Leaky bucket rate limiter.
///
/// Requests "leak" out at a constant rate. New requests are added to the bucket.
/// If the bucket is full, requests are rejected or queued.
pub struct LeakyBucket {
    /// Bucket capacity.
    capacity: u32,

    /// Leak rate (requests per second).
    leak_rate: f64,

    /// Current water level.
    level: Mutex<f64>,

    /// Last leak time.
    last_leak: Mutex<Instant>,
}

impl LeakyBucket {
    /// Create a new leaky bucket rate limiter.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum bucket size
    /// * `leak_rate` - Requests leaked per second
    #[must_use]
    pub fn new(capacity: u32, leak_rate: f64) -> Self {
        Self {
            capacity,
            leak_rate,
            level: Mutex::new(0.0),
            last_leak: Mutex::new(Instant::now()),
        }
    }

    /// Create from requests per window.
    #[must_use]
    pub fn from_window(requests_per_window: u32, window: Duration) -> Self {
        let leak_rate = f64::from(requests_per_window) / window.as_secs_f64();
        Self::new(requests_per_window, leak_rate)
    }

    /// Leak water based on elapsed time.
    fn leak(&self) {
        let now = Instant::now();
        let mut last_leak = self.last_leak.lock();
        let mut level = self.level.lock();

        let elapsed = now.duration_since(*last_leak);
        let leaked = elapsed.as_secs_f64() * self.leak_rate;

        if leaked > 0.0 {
            *level = (*level - leaked).max(0.0);
            drop(level);
            *last_leak = now;
        }
    }

    /// Calculate time until bucket has room.
    fn time_until_room(&self) -> Duration {
        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);

        if level < capacity {
            Duration::ZERO
        } else {
            let overflow = level - capacity + 1.0;
            Duration::from_secs_f64(overflow / self.leak_rate)
        }
    }
}

#[async_trait]
impl RateLimiter for LeakyBucket {
    async fn try_acquire(&self) -> bool {
        self.leak();

        let mut level = self.level.lock();
        let capacity = f64::from(self.capacity);

        if *level < capacity {
            *level += 1.0;
            true
        } else {
            false
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

            sleep(wait_time.min(Duration::from_millis(10))).await;
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn remaining(&self) -> u32 {
        self.leak();
        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);
        (capacity - level).max(0.0) as u32
    }

    async fn wait_time(&self) -> Duration {
        self.leak();
        self.time_until_room()
    }

    async fn reset(&self) {
        // Acquire locks in same order as leak() to prevent deadlock: last_leak then level
        let mut last_leak = self.last_leak.lock();
        let mut level = self.level.lock();
        *level = 0.0;
        *last_leak = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        self.leak();

        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let remaining = (capacity - level).max(0.0) as u32;

        RateLimitState {
            limit: self.capacity,
            remaining,
            reset_after: self.time_until_room(),
            is_limited: level >= capacity,
        }
    }
}

/// Smooth rate limiter for pacing requests.
///
/// Ensures minimum delay between requests.
pub struct SmoothPacer {
    /// Minimum interval between requests.
    min_interval: Duration,

    /// Last request time.
    last_request: Mutex<Option<Instant>>,
}

impl SmoothPacer {
    /// Create a new smooth pacer.
    #[must_use]
    pub const fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            last_request: Mutex::new(None),
        }
    }

    /// Create from requests per second.
    #[must_use]
    pub fn from_rate(requests_per_second: f64) -> Self {
        Self::new(Duration::from_secs_f64(1.0 / requests_per_second))
    }
}

#[async_trait]
impl RateLimiter for SmoothPacer {
    async fn try_acquire(&self) -> bool {
        let mut last = self.last_request.lock();
        let now = Instant::now();

        let last_time_val = *last;
        if let Some(last_time) = last_time_val {
            if now.duration_since(last_time) < self.min_interval {
                return false;
            }
        }

        *last = Some(now);
        true
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
        self.last_request.lock().map_or(1, |last| {
            u32::from(Instant::now().duration_since(last) >= self.min_interval)
        })
    }

    async fn wait_time(&self) -> Duration {
        let last_time_val = *self.last_request.lock();
        if let Some(last) = last_time_val {
            let elapsed = Instant::now().duration_since(last);
            if elapsed < self.min_interval {
                return self
                    .min_interval
                    .checked_sub(elapsed)
                    .unwrap_or(Duration::ZERO);
            }
        }
        Duration::ZERO
    }

    async fn reset(&self) {
        *self.last_request.lock() = None;
    }

    fn state(&self) -> RateLimitState {
        let last_time_val = *self.last_request.lock();
        let (remaining, reset_after) = if let Some(last) = last_time_val {
            let elapsed = Instant::now().duration_since(last);
            if elapsed >= self.min_interval {
                (1, Duration::ZERO)
            } else {
                (
                    0,
                    self.min_interval
                        .checked_sub(elapsed)
                        .unwrap_or(Duration::ZERO),
                )
            }
        } else {
            (1, Duration::ZERO)
        };

        RateLimitState {
            limit: 1,
            remaining,
            reset_after,
            is_limited: remaining == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_leaky_bucket_basic() {
        let limiter = LeakyBucket::new(5, 10.0); // 5 capacity, 10/sec leak

        // Fill bucket
        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }

        // Should be nearly full (may have leaked slightly during test execution)
        let level = *limiter.level.lock();
        assert!(level >= 4.5, "bucket should be nearly full, level={level}");

        // Wait for leak (10/sec means 2 leak in 200ms)
        sleep(Duration::from_millis(200)).await;

        // Should have room after leaking
        assert!(limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn test_smooth_pacer() {
        let pacer = SmoothPacer::new(Duration::from_millis(50));

        // First request succeeds
        assert!(pacer.try_acquire().await);

        // Immediate second request fails
        assert!(!pacer.try_acquire().await);

        // Wait and try again
        sleep(Duration::from_millis(60)).await;
        assert!(pacer.try_acquire().await);
    }
}

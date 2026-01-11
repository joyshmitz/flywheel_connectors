//! Sliding window rate limiter implementation.
//!
//! Provides accurate rate limiting with smooth window transitions.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::time::sleep;

use async_trait::async_trait;

use crate::{RateLimitError, RateLimitState, RateLimiter};

/// Sliding window rate limiter.
///
/// Tracks individual request timestamps for accurate rate limiting.
pub struct SlidingWindow {
    /// Maximum requests per window.
    limit: u32,

    /// Window duration.
    window: Duration,

    /// Request timestamps within the current window.
    timestamps: Mutex<VecDeque<Instant>>,
}

impl SlidingWindow {
    /// Create a new sliding window rate limiter.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            timestamps: Mutex::new(VecDeque::with_capacity(limit as usize)),
        }
    }

    /// Remove expired timestamps.
    fn cleanup(&self) {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock();

        while let Some(front) = timestamps.front() {
            if now.duration_since(*front) > self.window {
                timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Calculate remaining capacity.
    fn calculate_remaining(&self) -> u32 {
        self.cleanup();
        let timestamps = self.timestamps.lock();
        self.limit.saturating_sub(timestamps.len() as u32)
    }
}

#[async_trait]
impl RateLimiter for SlidingWindow {
    async fn try_acquire(&self) -> bool {
        self.cleanup();

        let mut timestamps = self.timestamps.lock();

        if timestamps.len() < self.limit as usize {
            timestamps.push_back(Instant::now());
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

            sleep(wait_time).await;
        }
    }

    fn remaining(&self) -> u32 {
        self.calculate_remaining()
    }

    async fn wait_time(&self) -> Duration {
        self.cleanup();

        let timestamps = self.timestamps.lock();

        if timestamps.len() < self.limit as usize {
            return Duration::ZERO;
        }

        // Wait until the oldest request expires
        if let Some(oldest) = timestamps.front() {
            let elapsed = Instant::now().duration_since(*oldest);
            if elapsed < self.window {
                return self.window - elapsed;
            }
        }

        Duration::ZERO
    }

    async fn reset(&self) {
        self.timestamps.lock().clear();
    }

    fn state(&self) -> RateLimitState {
        self.cleanup();

        let timestamps = self.timestamps.lock();
        let remaining = self.limit.saturating_sub(timestamps.len() as u32);

        let reset_after = if let Some(oldest) = timestamps.front() {
            let elapsed = Instant::now().duration_since(*oldest);
            if elapsed < self.window {
                self.window - elapsed
            } else {
                Duration::ZERO
            }
        } else {
            self.window
        };

        RateLimitState {
            limit: self.limit,
            remaining,
            reset_after,
            is_limited: remaining == 0,
        }
    }
}

/// Fixed window rate limiter (simpler, less accurate).
///
/// Resets counter at fixed intervals.
pub struct FixedWindow {
    /// Maximum requests per window.
    limit: u32,

    /// Window duration.
    window: Duration,

    /// Current request count.
    count: Mutex<u32>,

    /// Window start time.
    window_start: Mutex<Instant>,
}

impl FixedWindow {
    /// Create a new fixed window rate limiter.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            count: Mutex::new(0),
            window_start: Mutex::new(Instant::now()),
        }
    }

    /// Check if we need to reset the window.
    fn maybe_reset(&self) {
        let mut window_start = self.window_start.lock();
        let now = Instant::now();

        if now.duration_since(*window_start) >= self.window {
            *self.count.lock() = 0;
            *window_start = now;
        }
    }
}

#[async_trait]
impl RateLimiter for FixedWindow {
    async fn try_acquire(&self) -> bool {
        self.maybe_reset();

        let mut count = self.count.lock();

        if *count < self.limit {
            *count += 1;
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

            sleep(wait_time).await;
        }
    }

    fn remaining(&self) -> u32 {
        self.maybe_reset();
        let count = self.count.lock();
        self.limit.saturating_sub(*count)
    }

    async fn wait_time(&self) -> Duration {
        self.maybe_reset();

        if *self.count.lock() < self.limit {
            return Duration::ZERO;
        }

        let window_start = *self.window_start.lock();
        let elapsed = Instant::now().duration_since(window_start);

        if elapsed < self.window {
            self.window - elapsed
        } else {
            Duration::ZERO
        }
    }

    async fn reset(&self) {
        *self.count.lock() = 0;
        *self.window_start.lock() = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        self.maybe_reset();

        let count = *self.count.lock();
        let remaining = self.limit.saturating_sub(count);

        let window_start = *self.window_start.lock();
        let elapsed = Instant::now().duration_since(window_start);
        let reset_after = if elapsed < self.window {
            self.window - elapsed
        } else {
            Duration::ZERO
        };

        RateLimitState {
            limit: self.limit,
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
    async fn test_sliding_window_basic() {
        let limiter = SlidingWindow::new(5, Duration::from_secs(1));

        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }
        assert!(!limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn test_sliding_window_expiry() {
        let limiter = SlidingWindow::new(2, Duration::from_millis(100));

        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        sleep(Duration::from_millis(150)).await;

        assert!(limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn test_fixed_window_basic() {
        let limiter = FixedWindow::new(3, Duration::from_secs(1));

        for _ in 0..3 {
            assert!(limiter.try_acquire().await);
        }
        assert!(!limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn test_fixed_window_reset() {
        let limiter = FixedWindow::new(2, Duration::from_millis(100));

        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        sleep(Duration::from_millis(150)).await;

        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
    }
}

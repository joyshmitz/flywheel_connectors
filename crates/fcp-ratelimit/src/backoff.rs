//! Backoff strategies for rate limit handling.
//!
//! Provides various backoff algorithms for retry logic.

use std::time::Duration;

/// Trait for backoff strategies.
pub trait BackoffStrategy: Send + Sync {
    /// Get the next backoff duration.
    fn next_backoff(&mut self, attempt: u32) -> Duration;

    /// Reset the backoff state.
    fn reset(&mut self);

    /// Clone the strategy into a boxed trait object.
    fn clone_box(&self) -> Box<dyn BackoffStrategy>;
}

/// Exponential backoff with optional jitter.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Initial backoff duration.
    pub initial: Duration,

    /// Maximum backoff duration.
    pub max: Duration,

    /// Multiplier for each attempt.
    pub multiplier: f64,

    /// Whether to add jitter.
    pub jitter: Option<f64>,
}

impl ExponentialBackoff {
    /// Create a new exponential backoff.
    #[must_use]
    pub const fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            multiplier: 2.0,
            jitter: Some(0.5),
        }
    }

    /// Set the multiplier.
    #[must_use]
    pub const fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Enable or disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, jitter: Option<f64>) -> Self {
        self.jitter = jitter;
        self
    }

    /// Common preset: 1s initial, 60s max.
    #[must_use]
    pub const fn default_backoff() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(60))
    }

    /// Common preset: aggressive (short delays).
    #[must_use]
    pub const fn aggressive() -> Self {
        Self::new(Duration::from_millis(100), Duration::from_secs(10))
    }

    /// Common preset: conservative (longer delays).
    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(Duration::from_secs(5), Duration::from_secs(300))
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::default_backoff()
    }
}

impl BackoffStrategy for ExponentialBackoff {
    fn next_backoff(&mut self, attempt: u32) -> Duration {
        #[allow(clippy::cast_possible_wrap)]
        let base = self.initial.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped = base.min(self.max.as_secs_f64());

        self.jitter.map_or_else(
            || Duration::from_secs_f64(capped),
            |jitter| {
                let random_float = || rand::random::<f64>();
                let jitter_factor = random_float().mul_add(jitter * 2.0, 1.0 - jitter);
                Duration::from_secs_f64(capped * jitter_factor)
            },
        )
    }

    fn reset(&mut self) {
        // No state to reset for exponential backoff
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Decorrelated jitter backoff.
///
/// Each backoff is randomized independently, reducing thundering herd.
#[derive(Debug, Clone)]
pub struct DecorrelatedJitter {
    /// Base duration.
    pub base: Duration,

    /// Maximum duration.
    pub max: Duration,

    /// Previous backoff (for correlation).
    previous: Duration,
}

impl DecorrelatedJitter {
    /// Create a new decorrelated jitter backoff.
    #[must_use]
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            previous: base,
        }
    }
}

impl BackoffStrategy for DecorrelatedJitter {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        // sleep = min(cap, random_between(base, sleep * 3))
        let base_secs = self.base.as_secs_f64();
        let prev_secs = self.previous.as_secs_f64();
        let max_secs = self.max.as_secs_f64();

        let range = prev_secs.mul_add(3.0, -base_secs);
        let next = if range > 0.0 {
            random_float().mul_add(range, base_secs)
        } else {
            base_secs
        };

        let capped = next.min(max_secs);
        self.previous = Duration::from_secs_f64(capped);
        self.previous
    }

    fn reset(&mut self) {
        self.previous = self.base;
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Linear backoff with cap.
#[derive(Debug, Clone)]
pub struct LinearBackoff {
    /// Initial delay.
    pub initial: Duration,

    /// Increment per attempt.
    pub increment: Duration,

    /// Maximum delay.
    pub max: Duration,
}

impl LinearBackoff {
    /// Create a new linear backoff.
    #[must_use]
    pub const fn new(initial: Duration, increment: Duration, max: Duration) -> Self {
        Self {
            initial,
            increment,
            max,
        }
    }
}

impl BackoffStrategy for LinearBackoff {
    fn next_backoff(&mut self, attempt: u32) -> Duration {
        let delay = self.initial + self.increment * attempt;
        delay.min(self.max)
    }

    fn reset(&mut self) {
        // No state to reset
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Constant backoff (same delay each time).
#[derive(Debug, Clone)]
pub struct ConstantBackoff {
    /// Delay duration.
    pub delay: Duration,
}

impl ConstantBackoff {
    /// Create a new constant backoff.
    #[must_use]
    pub const fn new(delay: Duration) -> Self {
        Self { delay }
    }
}

impl BackoffStrategy for ConstantBackoff {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        self.delay
    }

    fn reset(&mut self) {}

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// No backoff (immediate retry).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBackoff;

impl BackoffStrategy for NoBackoff {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        Duration::ZERO
    }

    fn reset(&mut self) {}

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(*self)
    }
}

/// Retry configuration.
pub struct RetryConfig {
    /// Maximum number of retries.
    pub max_retries: u32,

    /// Maximum total time for all retries.
    pub max_total_time: Option<Duration>,

    /// Backoff strategy.
    backoff: Box<dyn BackoffStrategy>,
}

impl std::fmt::Debug for RetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryConfig")
            .field("max_retries", &self.max_retries)
            .field("max_total_time", &self.max_total_time)
            .field("backoff", &"<BackoffStrategy>")
            .finish()
    }
}

impl RetryConfig {
    /// Create a new retry configuration.
    #[must_use]
    pub fn new(max_retries: u32, backoff: impl BackoffStrategy + 'static) -> Self {
        Self {
            max_retries,
            max_total_time: None,
            backoff: Box::new(backoff),
        }
    }

    /// Set maximum total retry time.
    #[must_use]
    pub const fn with_max_total_time(mut self, duration: Duration) -> Self {
        self.max_total_time = Some(duration);
        self
    }

    /// Get the next backoff duration.
    pub fn next_backoff(&mut self, attempt: u32) -> Duration {
        self.backoff.next_backoff(attempt)
    }

    /// Reset the backoff state.
    pub fn reset(&mut self) {
        self.backoff.reset();
    }
}

impl Clone for RetryConfig {
    fn clone(&self) -> Self {
        Self {
            max_retries: self.max_retries,
            max_total_time: self.max_total_time,
            backoff: self.backoff.clone_box(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::new(3, ExponentialBackoff::default())
    }
}

/// Simple random float generator (0.0 to 1.0).
fn random_float() -> f64 {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(None);

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(2));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(4));
        assert_eq!(backoff.next_backoff(3), Duration::from_secs(8));
        assert_eq!(backoff.next_backoff(10), Duration::from_secs(60)); // Capped
    }

    #[test]
    fn test_linear_backoff() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(10),
        );

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(3));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(10), Duration::from_secs(10)); // Capped
    }

    #[test]
    fn test_constant_backoff() {
        let mut backoff = ConstantBackoff::new(Duration::from_secs(5));

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(100), Duration::from_secs(5));
    }

    #[test]
    fn test_no_backoff() {
        let mut backoff = NoBackoff;

        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(100), Duration::ZERO);
    }

    #[test]
    fn test_retry_config() {
        let mut config = RetryConfig::new(3, ExponentialBackoff::default().with_jitter(None));

        assert_eq!(config.max_retries, 3);

        let d1 = config.next_backoff(0);
        let d2 = config.next_backoff(1);
        assert!(d2 > d1);
    }
}

//! Tracing configuration for test output.
//!
//! Provides utilities for configuring tracing in tests with appropriate
//! output formatting and filtering.

use std::sync::Once;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

static INIT: Once = Once::new();

/// Initialize tracing for tests.
///
/// This should be called at the start of each test or in a test setup function.
/// It's safe to call multiple times; only the first call will initialize tracing.
///
/// Uses the `RUST_LOG` environment variable if set, otherwise defaults to `info`.
///
/// # Example
///
/// ```rust
/// use fcp_testkit::init_test_tracing;
///
/// #[tokio::test]
/// async fn my_test() {
///     init_test_tracing();
///     // ... test code
/// }
/// ```
pub fn init_test_tracing() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,fcp_testkit=debug"));

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_ansi(true)
                    .compact(),
            )
            .init();
    });
}

/// Initialize tracing with a specific filter.
///
/// # Example
///
/// ```rust
/// use fcp_testkit::init_test_tracing_with_filter;
///
/// #[tokio::test]
/// async fn my_verbose_test() {
///     init_test_tracing_with_filter("debug");
///     // ... test code
/// }
/// ```
pub fn init_test_tracing_with_filter(filter: &str) {
    INIT.call_once(|| {
        let filter = EnvFilter::new(filter);

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_ansi(true)
                    .compact(),
            )
            .init();
    });
}

/// Initialize tracing with JSON output (useful for structured log analysis).
///
/// # Example
///
/// ```rust
/// use fcp_testkit::init_test_tracing_json;
///
/// #[tokio::test]
/// async fn my_test() {
///     init_test_tracing_json();
///     // ... test code
/// }
/// ```
pub fn init_test_tracing_json() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,fcp_testkit=debug"));

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_test_writer().json())
            .init();
    });
}

/// Initialize silent tracing (suppresses all output).
///
/// Useful for tests that intentionally trigger errors and don't want log noise.
pub fn init_test_tracing_silent() {
    INIT.call_once(|| {
        let filter = EnvFilter::new("off");

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_test_writer())
            .init();
    });
}

/// Guard that captures tracing events for assertion.
///
/// Note: This is a simplified implementation. For production use,
/// consider using `tracing-test` crate.
#[derive(Debug, Default)]
pub struct TracingCapture {
    events: std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
}

/// A captured tracing event.
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    /// Event level (trace, debug, info, warn, error)
    pub level: String,
    /// Event message
    pub message: String,
    /// Event target (module path)
    pub target: String,
}

impl TracingCapture {
    /// Create a new tracing capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all captured events.
    #[must_use]
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Check if any event contains the given message.
    #[must_use]
    pub fn contains(&self, message: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.message.contains(message))
    }

    /// Check if any error event was logged.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.level == "ERROR")
    }

    /// Check if any warning event was logged.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.level == "WARN")
    }

    /// Assert no errors were logged.
    ///
    /// # Panics
    ///
    /// Panics if any error events were captured.
    pub fn assert_no_errors(&self) {
        let errors: Vec<_> = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.level == "ERROR")
            .cloned()
            .collect();

        assert!(
            errors.is_empty(),
            "Expected no errors but found: {:?}",
            errors
        );
    }

    /// Assert no warnings were logged.
    ///
    /// # Panics
    ///
    /// Panics if any warning events were captured.
    pub fn assert_no_warnings(&self) {
        let warnings: Vec<_> = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.level == "WARN")
            .cloned()
            .collect();

        assert!(
            warnings.is_empty(),
            "Expected no warnings but found: {:?}",
            warnings
        );
    }

    /// Clear all captured events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

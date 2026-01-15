//! FCP Test Kit - Testing framework and mock infrastructure for FCP connectors
//!
//! This crate provides comprehensive testing utilities for building and testing
//! FCP connectors, including:
//!
//! - [`ConnectorTestHarness`] - A test harness that wraps connectors with assertions
//! - [`MockApiServer`] - HTTP mock server with request/response recording
//! - Test fixtures for common FCP types
//! - Assertion helpers for FCP responses
//! - Tracing configuration for test output
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::{ConnectorTestHarness, MockApiServer, fixtures};
//!
//! #[tokio::test]
//! async fn test_my_connector() {
//!     // Initialize test tracing
//!     fcp_testkit::init_test_tracing();
//!
//!     // Create a mock server
//!     let mock = MockApiServer::start().await;
//!
//!     // Set up expected responses
//!     mock.expect_json("/api/messages", serde_json::json!({
//!         "messages": []
//!     })).await;
//!
//!     // Create your connector and wrap it
//!     let connector = MyConnector::new(mock.base_url());
//!     let mut harness = ConnectorTestHarness::new(connector);
//!
//!     // Configure
//!     harness.configure(fixtures::config::api_key("test-key")).await.unwrap();
//!     harness.assert_last_success();
//!
//!     // Verify health
//!     let health = harness.health().await;
//!     assert!(health.is_ready());
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod assertions;
pub mod fixtures;
mod harness;
mod mock_server;
mod tracing_config;

pub use assertions::*;
pub use harness::*;
pub use mock_server::*;
pub use tracing_config::*;

// Re-export core types for convenience
pub use fcp_core::{FcpConnector, FcpError, FcpResult, HealthSnapshot, HealthState};

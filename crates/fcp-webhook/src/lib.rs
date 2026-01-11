//! FCP Webhook - Production webhook handling library
//!
//! This crate provides comprehensive webhook support:
//!
//! - **Signature Verification**: HMAC-SHA256, HMAC-SHA1, Ed25519
//! - **Provider Support**: GitHub, Stripe, Slack, Linear, Discord
//! - **Event Processing**: Type routing, filtering, priority queues
//! - **Delivery Management**: Idempotency, retries, dead letter queues
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_webhook::{WebhookHandler, GitHubSignature};
//!
//! // Create a webhook handler for GitHub
//! let handler = WebhookHandler::new(GitHubSignature::new("webhook_secret"));
//!
//! // Verify and process incoming webhook
//! let event = handler.verify_and_parse(headers, body).await?;
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod signature;
mod provider;
mod event;
mod handler;
mod error;

pub use signature::*;
pub use provider::*;
pub use event::*;
pub use handler::*;
pub use error::*;

use std::time::Duration;

/// Default timestamp tolerance for replay protection.
pub const DEFAULT_TIMESTAMP_TOLERANCE: Duration = Duration::from_secs(300); // 5 minutes

/// Default maximum payload size.
pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 5 * 1024 * 1024; // 5MB

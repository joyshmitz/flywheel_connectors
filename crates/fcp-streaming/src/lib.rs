//! FCP Streaming - Unified streaming library for FCP connectors
//!
//! This crate provides comprehensive streaming support:
//!
//! - **SSE**: Server-Sent Events parsing and client
//! - **WebSocket**: Full WebSocket protocol support
//! - **Stream Processing**: Async stream utilities
//! - **Error Recovery**: Automatic reconnection with backoff
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_streaming::{SseClient, SseEvent};
//!
//! // Create SSE client
//! let client = SseClient::new("https://api.example.com/events");
//!
//! // Stream events
//! let mut stream = client.connect().await?;
//! while let Some(event) = stream.next().await {
//!     println!("Event: {:?}", event?);
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod error;
mod reconnect;
mod sse;
mod stream;
mod websocket;

pub use error::*;
pub use reconnect::*;
pub use sse::*;
pub use stream::*;
pub use websocket::*;

use std::time::Duration;

/// Default reconnection delay.
pub const DEFAULT_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Maximum reconnection delay.
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// Default buffer size for streams.
pub const DEFAULT_BUFFER_SIZE: usize = 8192;

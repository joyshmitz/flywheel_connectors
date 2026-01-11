//! FCP Core - Core types and traits for the Flywheel Connector Protocol
//!
//! This crate provides the foundational types, traits, and error handling for
//! FCP connectors. It implements the canonical structures defined in
//! FCP_Specification_V1.md.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod error;
mod capability;
mod protocol;
mod connector;
mod event;
mod health;

pub use error::*;
pub use capability::*;
pub use protocol::*;
pub use connector::*;
pub use event::*;
pub use health::*;

// Re-export commonly used external types
pub use async_trait::async_trait;
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;

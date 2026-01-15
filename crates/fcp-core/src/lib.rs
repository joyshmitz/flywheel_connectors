//! FCP Core - Core types and traits for the Flywheel Connector Protocol
//!
//! This crate provides the foundational types, traits, and error handling for
//! FCP connectors.
//!
//! This crate is being migrated to the `FCP_Specification_V2.md` contract.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod capability;
mod connector;
mod error;
mod event;
mod health;
mod object;
mod protocol;
mod quorum;
mod ratelimit;
mod revocation;

pub use capability::*;
pub use connector::*;
pub use error::*;
pub use event::*;
pub use health::*;
pub use object::*;
pub use protocol::*;
pub use quorum::*;
pub use ratelimit::*;
pub use revocation::*;

// Re-export commonly used external types
pub use async_trait::async_trait;
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;

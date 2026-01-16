//! FCP Core - Core types and traits for the Flywheel Connector Protocol
//!
//! This crate provides the foundational types, traits, and error handling for
//! FCP connectors.
//!
//! This crate is being migrated to the `FCP_Specification_V2.md` contract.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod audit;
mod capability;
mod connector;
mod error;
mod event;
mod health;
mod lease;
mod object;
mod operation;
mod protocol;
mod provenance;
mod quorum;
mod ratelimit;
mod revocation;

pub use audit::*;
pub use capability::*;
pub use connector::*;
pub use error::*;
pub use event::*;
pub use health::*;
pub use lease::*;
pub use object::*;
pub use operation::*;
pub use protocol::*;
pub use provenance::*;
pub use quorum::*;
pub use ratelimit::*;
pub use revocation::*;

// Re-export commonly used external types
pub use async_trait::async_trait;
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;

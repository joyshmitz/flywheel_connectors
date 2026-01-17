//! FCP2 mesh node orchestration (routing, admission, gossip, leases).
//!
//! This crate provides:
//! - [`admission`] - Admission control with per-peer budgets and anti-amplification
//! - [`device`] - Device profile types for execution planning and capability reporting
//! - [`gossip`] - Gossip protocol for metadata and object announcement
//! - [`session`] - Session layer with authenticated handshake, key schedule, and anti-replay
//! - [`symbol_request`] - Symbol request handling with bounded requests and targeted repair

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod admission;
pub mod device;
pub mod gossip;
pub mod session;
pub mod symbol_request;

pub use admission::*;
pub use device::*;
pub use gossip::*;
pub use session::*;
pub use symbol_request::*;

//! FCP2 mesh node orchestration (routing, admission, gossip, leases).
//!
//! This crate provides:
//! - [`admission`] - Admission control with per-peer budgets and anti-amplification
//! - [`device`] - Device profile types for execution planning and capability reporting
//! - [`session`] - Session layer with authenticated handshake, key schedule, and anti-replay

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod admission;
pub mod device;
pub mod session;

pub use admission::*;
pub use device::*;
pub use session::*;

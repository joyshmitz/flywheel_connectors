//! FCP2 mesh node orchestration (routing, admission, gossip, leases).
//!
//! This crate provides:
//! - [`session`] - Session layer with authenticated handshake, key schedule, and anti-replay

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod session;

pub use session::*;

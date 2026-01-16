//! FCP2 sandbox enforcement (OS sandbox profiles + egress guard).
//!
//! This crate provides the Network Guard (egress proxy), the only outbound network
//! path for connectors under `strict`/`moderate` sandbox profiles.
//!
//! # Core Invariants (NORMATIVE)
//!
//! - Connectors in `strict`/`moderate` profiles MUST NOT open outbound sockets directly.
//! - All outbound network activity MUST be mediated through the Network Guard.
//! - The Network Guard is **deny-by-default**.
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_sandbox::{EgressGuard, EgressRequest, EgressHttpRequest};
//! use fcp_manifest::NetworkConstraints;
//!
//! let guard = EgressGuard::new();
//! let constraints = NetworkConstraints { /* ... */ };
//!
//! let request = EgressRequest::Http(EgressHttpRequest {
//!     url: "https://api.example.com/v1/data".into(),
//!     method: "GET".into(),
//!     headers: vec![],
//!     body: None,
//!     credential_id: None,
//! });
//!
//! match guard.evaluate(&request, &constraints) {
//!     Ok(decision) => { /* proceed with request */ }
//!     Err(e) => { /* deny: log and return error */ }
//! }
//! ```

#![forbid(unsafe_code)]

mod egress;

pub use egress::*;

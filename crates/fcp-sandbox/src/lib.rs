//! FCP2 sandbox enforcement (OS sandbox profiles + egress guard).
//!
//! This crate provides two key security components:
//!
//! 1. **Network Guard** (egress proxy): The only outbound network path for connectors
//!    under `strict`/`moderate` sandbox profiles.
//!
//! 2. **OS Sandboxes**: Platform-specific process isolation using:
//!    - Linux: seccomp-bpf + namespaces (+ Landlock on 5.13+)
//!    - macOS: seatbelt profiles (sandbox-exec)
//!    - Windows: `AppContainer` + job objects
//!
//! # Core Invariants (NORMATIVE)
//!
//! - Connectors in `strict`/`moderate` profiles MUST NOT open outbound sockets directly.
//! - All outbound network activity MUST be mediated through the Network Guard.
//! - The Network Guard is **deny-by-default**.
//! - OS sandboxes enforce filesystem, process, and network restrictions per manifest.
//!
//! # Network Guard Example
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
//!
//! # OS Sandbox Example
//!
//! ```rust,ignore
//! use fcp_sandbox::{CompiledPolicy, create_sandbox};
//! use fcp_manifest::SandboxSection;
//!
//! let manifest_section: SandboxSection = /* ... */;
//! let state_dir = Some("/var/lib/fcp/connectors/my-connector".into());
//!
//! let policy = CompiledPolicy::from_manifest(&manifest_section, state_dir)?;
//! let sandbox = create_sandbox()?;
//!
//! // Apply sandbox early in connector startup (irreversible!)
//! sandbox.apply(&policy)?;
//! ```

// Note: unsafe code allowed via Cargo.toml lints for OS sandbox syscalls
// Allow FFI-related patterns common in OS sandbox implementations
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::borrow_as_ptr)]

mod egress;
mod sandbox;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

pub use egress::*;
pub use sandbox::*;

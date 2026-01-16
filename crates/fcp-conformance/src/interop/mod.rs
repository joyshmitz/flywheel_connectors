//! Interop test suite for FCP2 conformance.
//!
//! This module provides tests that verify interoperability between implementations.
//! Tests are designed to be deterministic and runnable without a real tailnet.
//!
//! # Test Categories
//!
//! ## Sessions / Handshake
//! - `MeshSessionHello`/`Ack` transcript verification
//! - `HelloRetry` cookie flow
//! - `TransportLimits` negotiation and enforcement
//!
//! ## FCPS Data Plane
//! - `FCPS_DATAGRAM` envelope MAC computation and verification
//! - Bounded replay window behavior
//! - MTU enforcement
//! - Per-symbol AEAD verification
//!
//! ## FCPC Control Plane
//! - Frame parsing and ordering
//! - Bounded replay window
//! - `k_ctx` AEAD integrity
//!
//! ## Capability Tokens
//! - `COSE_Sign1` encoding/verification
//! - `grant_object_ids` subset enforcement
//! - `chk_id`/`chk_seq` freshness binding
//! - `holder_node` + `holder_proof` verification
//!
//! ## Cross-Zone Enforcement
//! - Deny cross-zone operations without `ApprovalToken`
//! - Allow with correct `ApprovalToken` evidence
//! - `DecisionReceipt` `reason_code` stability

pub mod capability;
pub mod cross_zone;
pub mod fcpc;
pub mod fcps;
pub mod session;

// Re-export main test runner
pub use capability::CapabilityInteropTests;
pub use cross_zone::CrossZoneInteropTests;
pub use fcpc::FcpcInteropTests;
pub use fcps::FcpsInteropTests;
pub use session::SessionInteropTests;

/// Run all interop tests.
///
/// Returns a summary of passed/failed tests.
#[must_use]
pub fn run_all() -> InteropTestSummary {
    let mut summary = InteropTestSummary::default();

    // Session tests
    summary.merge(session::run_tests());

    // FCPS data plane tests
    summary.merge(fcps::run_tests());

    // FCPC control plane tests
    summary.merge(fcpc::run_tests());

    // Capability token tests
    summary.merge(capability::run_tests());

    // Cross-zone enforcement tests
    summary.merge(cross_zone::run_tests());

    summary
}

/// Summary of interop test results.
#[derive(Debug, Default, Clone)]
pub struct InteropTestSummary {
    /// Total tests run.
    pub total: usize,
    /// Tests that passed.
    pub passed: usize,
    /// Tests that failed.
    pub failed: usize,
    /// Test failures with descriptions.
    pub failures: Vec<TestFailure>,
}

impl InteropTestSummary {
    /// Merge another summary into this one.
    pub fn merge(&mut self, other: Self) {
        self.total += other.total;
        self.passed += other.passed;
        self.failed += other.failed;
        self.failures.extend(other.failures);
    }

    /// Check if all tests passed.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// A single test failure.
#[derive(Debug, Clone)]
pub struct TestFailure {
    /// Test name.
    pub name: String,
    /// Category (session, fcps, fcpc, capability, `cross_zone`).
    pub category: String,
    /// Error message.
    pub message: String,
}

//! FZPF (Flywheel Zone Policy Format) schema validation.
//!
//! This module provides schema validation for FCP2 zone policy documents.
//! It includes the FZPF v0.1 JSON Schema and validation utilities.
//!
//! # Schema Validation
//!
//! The FZPF schema enforces:
//! - Zone definition structure with integrity/confidentiality levels
//! - Zone policy access control rules
//! - Role definitions and assignments
//! - Cross-zone data flow rules
//! - Taint-based policy rules
//! - Approval constraints for elevation/declassification/execution
//!
//! # Normative Requirements
//!
//! - **Patterns**: Only anchored glob patterns (*, ?) are allowed. Regex and `JSONPath` are forbidden.
//! - **JSON Pointers**: RFC 6901 only for input constraints.
//! - **Zone IDs**: Must match `^z:[a-z][a-z0-9_-]*$`
//! - **Integrity/Confidentiality**: 0-100 range, child zones must not exceed parent levels
//!
//! # Example
//!
//! ```ignore
//! use fcp_conformance::schemas::validate_fzpf_policy;
//!
//! let policy_json = r#"{ "policy": { ... }, "zones": [...] }"#;
//! let result = validate_fzpf_policy(policy_json);
//! assert!(result.is_ok());
//! ```

/// The FZPF v0.1 JSON Schema as a string constant.
pub const FZPF_V01_SCHEMA: &str = include_str!("FZPF_v0.1.schema.json");

#[cfg(test)]
mod tests;

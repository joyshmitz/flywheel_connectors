//! Rate limiting primitives for FCP2.
//!
//! This module defines the canonical, platform-facing types used to represent rate limit
//! violations and backpressure signals. Enforcement algorithms live in `fcp-ratelimit`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::{ConnectorId, ObjectId, OperationId, ZoneId};

/// The type of limit that was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitType {
    /// Requests per time window (e.g., RPM/RPS).
    Rpm,
    /// Maximum number of concurrent operations.
    Concurrent,
    /// Burst allowance exceeded (token bucket capacity depleted).
    Burst,
    /// Quota exceeded (tokens/bytes/compute budget).
    Quota,
}

/// Rate limit backpressure level.
///
/// These levels are intended to be computed from utilization and used to drive:
/// - warning logs/metrics (`warning`),
/// - soft shaping (`soft_limit`),
/// - hard rejection (`hard_limit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureLevel {
    Normal,
    Warning,
    SoftLimit,
    HardLimit,
}

/// A platform-facing signal that the caller should slow down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackpressureSignal {
    /// The computed backpressure level.
    pub level: BackpressureLevel,

    /// Utilization in basis points (`0..=10_000`).
    pub utilization_bps: u16,

    /// Suggested delay (if any) to shape traffic proactively.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Input fields for creating a `ThrottleViolation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleViolationInput {
    /// Timestamp (milliseconds since Unix epoch).
    pub timestamp_ms: u64,

    /// Zone where the violation occurred.
    pub zone_id: ZoneId,

    /// Connector (type) implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,

    /// Operation implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,

    /// The limit category.
    pub limit_type: LimitType,

    /// Configured maximum.
    pub limit_value: u32,

    /// Observed current value when the violation was triggered.
    pub current_value: u32,

    /// Suggested retry delay.
    pub retry_after_ms: u64,
}

/// A structured rate limit violation.
///
/// This object is designed to be:
/// - recorded in the audit chain (as an object/event),
/// - returned in structured error details,
/// - used to drive backpressure decisions and metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleViolation {
    /// Unique identifier for the violation record.
    pub violation_id: ObjectId,

    /// Timestamp (milliseconds since Unix epoch).
    pub timestamp_ms: u64,

    /// Zone where the violation occurred.
    pub zone_id: ZoneId,

    /// Connector (type) implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,

    /// Operation implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,

    /// The limit category.
    pub limit_type: LimitType,

    /// Configured maximum.
    pub limit_value: u32,

    /// Observed current value when the violation was triggered.
    pub current_value: u32,

    /// Suggested retry delay.
    pub retry_after_ms: u64,
}

impl ThrottleViolation {
    /// Create a new `ThrottleViolation` and derive a deterministic `violation_id`.
    ///
    /// Note: The `violation_id` is currently derived as an unkeyed, domain-separated digest over
    /// the violation fields for stable correlation. When persisted into the audit object store,
    /// the stored object id MUST follow the object-id derivation rules from `fcp-core::object`.
    #[must_use]
    pub fn new(input: ThrottleViolationInput) -> Self {
        let violation_id = derive_violation_id(&input);

        Self {
            violation_id,
            timestamp_ms: input.timestamp_ms,
            zone_id: input.zone_id,
            connector_id: input.connector_id,
            operation_id: input.operation_id,
            limit_type: input.limit_type,
            limit_value: input.limit_value,
            current_value: input.current_value,
            retry_after_ms: input.retry_after_ms,
        }
    }
}

fn derive_violation_id(input: &ThrottleViolationInput) -> ObjectId {
    // Length-prefixed encoding to avoid ambiguity.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"FCP2-THROTTLE-V1");
    bytes.extend_from_slice(&input.timestamp_ms.to_le_bytes());

    // ZoneId
    let z_bytes = input.zone_id.as_bytes();
    bytes.extend_from_slice(
        &u32::try_from(z_bytes.len())
            .expect("zone_id too long")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(z_bytes);

    if let Some(id) = input.connector_id.as_ref() {
        bytes.push(1);
        let s = id.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(s.len())
                .expect("connector_id too long")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(s);
    } else {
        bytes.push(0);
    }

    if let Some(id) = input.operation_id.as_ref() {
        bytes.push(1);
        let s = id.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(s.len())
                .expect("operation_id too long")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(s);
    } else {
        bytes.push(0);
    }

    bytes.push(match input.limit_type {
        LimitType::Rpm => 1,
        LimitType::Concurrent => 2,
        LimitType::Burst => 3,
        LimitType::Quota => 4,
    });
    bytes.extend_from_slice(&input.limit_value.to_le_bytes());
    bytes.extend_from_slice(&input.current_value.to_le_bytes());
    bytes.extend_from_slice(&input.retry_after_ms.to_le_bytes());

    ObjectId::from_unscoped_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violation_id_determinism() {
        let ts = 1000_u64;
        let zone: ZoneId = "z:work".parse().unwrap();
        let conn: ConnectorId = "test:conn:v1".parse().unwrap();
        let op: OperationId = "test.op".parse().unwrap();

        let v1 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: ts,
            zone_id: zone.clone(),
            connector_id: Some(conn.clone()),
            operation_id: Some(op.clone()),
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });

        let v2 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: ts,
            zone_id: zone,
            connector_id: Some(conn),
            operation_id: Some(op),
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });

        assert_eq!(v1.violation_id, v2.violation_id);
    }

    #[test]
    fn violation_id_sensitivity() {
        let base = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });

        // Change timestamp
        let v2 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1001,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(base.violation_id, v2.violation_id);

        // Change zone
        let v3 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:private".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(base.violation_id, v3.violation_id);

        // Change limit type
        let v4 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Burst,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(base.violation_id, v4.violation_id);
    }
}

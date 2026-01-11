//! Event types for FCP - streaming events and envelopes.
//!
//! Based on FCP Specification Section 9 (Wire Protocol) - Event Messages.

use serde::{Deserialize, Serialize};

use crate::{ConnectorId, CorrelationId, InstanceId, Principal, ZoneId};

/// Event envelope wrapper for streaming events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Message type ("event")
    pub r#type: String,

    /// Event topic
    pub topic: String,

    /// Timestamp when event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Sequence number for ordering
    pub seq: u64,

    /// Cursor for replay
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// Whether acknowledgment is required
    pub requires_ack: bool,

    /// Acknowledgment deadline in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_deadline_ms: Option<u64>,

    /// Event data
    pub data: EventData,
}

impl EventEnvelope {
    /// Create a new event envelope.
    #[must_use]
    pub fn new(topic: impl Into<String>, data: EventData) -> Self {
        Self {
            r#type: "event".into(),
            topic: topic.into(),
            timestamp: chrono::Utc::now(),
            seq: 0,
            cursor: None,
            requires_ack: false,
            ack_deadline_ms: None,
            data,
        }
    }

    /// Set the sequence number.
    #[must_use]
    pub fn with_seq(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    /// Set the cursor.
    #[must_use]
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Require acknowledgment.
    #[must_use]
    pub fn requiring_ack(mut self, deadline_ms: u64) -> Self {
        self.requires_ack = true;
        self.ack_deadline_ms = Some(deadline_ms);
        self
    }
}

/// Event data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    /// Source connector
    pub connector_id: ConnectorId,

    /// Source instance
    pub instance_id: InstanceId,

    /// Zone the event originated from
    pub zone_id: ZoneId,

    /// Principal that caused the event
    pub principal: Principal,

    /// Event payload (JSON)
    pub payload: serde_json::Value,

    /// Correlation ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,

    /// Resource URIs affected by this event
    #[serde(default)]
    pub resource_uris: Vec<String>,
}

impl EventData {
    /// Create new event data.
    #[must_use]
    pub fn new(
        connector_id: ConnectorId,
        instance_id: InstanceId,
        zone_id: ZoneId,
        principal: Principal,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            connector_id,
            instance_id,
            zone_id,
            principal,
            payload,
            correlation_id: None,
            resource_uris: Vec::new(),
        }
    }

    /// Add a correlation ID.
    #[must_use]
    pub fn with_correlation_id(mut self, id: CorrelationId) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Add resource URIs.
    #[must_use]
    pub fn with_resource_uris(mut self, uris: Vec<String>) -> Self {
        self.resource_uris = uris;
        self
    }
}

/// Event acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAck {
    /// Message type ("ack")
    pub r#type: String,

    /// Topic of the event being acknowledged
    pub topic: String,

    /// Sequence numbers being acknowledged
    pub seqs: Vec<u64>,

    /// Cursors being acknowledged
    #[serde(default)]
    pub cursors: Vec<String>,
}

impl EventAck {
    /// Create a new acknowledgment.
    #[must_use]
    pub fn new(topic: impl Into<String>, seqs: Vec<u64>) -> Self {
        Self {
            r#type: "ack".into(),
            topic: topic.into(),
            seqs,
            cursors: Vec::new(),
        }
    }

    /// Add cursors.
    #[must_use]
    pub fn with_cursors(mut self, cursors: Vec<String>) -> Self {
        self.cursors = cursors;
        self
    }
}

/// Negative acknowledgment (for redelivery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventNack {
    /// Message type ("nack")
    pub r#type: String,

    /// Topic of the event
    pub topic: String,

    /// Sequence numbers to redeliver
    pub seqs: Vec<u64>,

    /// Reason for nack
    pub reason: String,

    /// Delay before redelivery in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

impl EventNack {
    /// Create a new negative acknowledgment.
    #[must_use]
    pub fn new(topic: impl Into<String>, seqs: Vec<u64>, reason: impl Into<String>) -> Self {
        Self {
            r#type: "nack".into(),
            topic: topic.into(),
            seqs,
            reason: reason.into(),
            delay_ms: None,
        }
    }

    /// Set the redelivery delay.
    #[must_use]
    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = Some(delay_ms);
        self
    }
}

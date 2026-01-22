//! Streaming helpers for connectors: subscriptions, replay buffers, and acks.
//!
//! These utilities are intentionally in-memory and lightweight. They provide
//! standard replay/cursor semantics and ack tracking without forcing a specific
//! transport or storage backend.

use std::collections::{HashMap, HashSet, VecDeque};

use fcp_core::{
    EventAck, EventCaps, EventData, EventEnvelope, EventNack, ReplayBufferInfo, RequestId,
    SubscribeRequest, SubscribeResponse, SubscribeResult,
};

/// Replay buffer sizing limits.
#[derive(Debug, Clone, Copy)]
pub struct BufferLimits {
    /// Minimum number of events retained for replay.
    pub min_events: usize,
    /// Maximum number of events retained (may be exceeded by pending acks).
    pub max_events: usize,
}

impl BufferLimits {
    /// Create buffer limits ensuring `max_events >= min_events`.
    #[must_use]
    pub fn new(min_events: usize, max_events: usize) -> Self {
        Self {
            min_events,
            max_events: max_events.max(min_events),
        }
    }
}

impl Default for BufferLimits {
    fn default() -> Self {
        Self {
            min_events: 10,
            max_events: 100,
        }
    }
}

/// Errors returned by replay helpers.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ReplayError {
    #[error("unknown topic '{topic}'")]
    UnknownTopic { topic: String },
    #[error("invalid cursor '{cursor}'")]
    InvalidCursor { cursor: String },
    #[error("cursor {cursor_seq} is older than oldest buffered seq {oldest_seq}")]
    CursorStale {
        /// The sequence number from the cursor.
        cursor_seq: u64,
        /// The oldest sequence number in the buffer.
        oldest_seq: u64,
    },
}

/// Result of applying an EventAck.
#[derive(Debug, Clone)]
pub struct AckResult {
    /// Sequence numbers that were successfully acknowledged.
    pub acked: Vec<u64>,
    /// Sequence numbers that were not found in pending acks.
    pub missing: Vec<u64>,
}

/// Result of applying an EventNack.
#[derive(Debug, Clone)]
pub struct NackResult {
    /// Events to redeliver from the buffer.
    pub redeliver: Vec<EventEnvelope>,
    /// Sequence numbers that were not found in the buffer.
    pub missing: Vec<u64>,
}

/// Outcome of handling a SubscribeRequest.
#[derive(Debug, Clone)]
pub struct SubscribeOutcome {
    /// The subscribe response to send to the client.
    pub response: SubscribeResponse,
    /// Events to replay per topic (if replay was requested).
    pub replay_events: HashMap<String, Vec<EventEnvelope>>,
}

#[derive(Debug, Default)]
struct TopicState {
    next_seq: u64,
    buffer: VecDeque<EventEnvelope>,
    pending_acks: HashSet<u64>,
}

impl TopicState {
    fn record_event(
        &mut self,
        mut envelope: EventEnvelope,
        caps: &EventCaps,
        limits: BufferLimits,
    ) -> EventEnvelope {
        if envelope.seq == 0 {
            envelope.seq = self.next_seq;
        }
        if envelope.seq >= self.next_seq {
            self.next_seq = envelope.seq.saturating_add(1);
        }

        if envelope.cursor.is_empty() {
            envelope.cursor = envelope.seq.to_string();
        }

        if caps.requires_ack {
            envelope.requires_ack = true;
        }

        if envelope.requires_ack {
            self.pending_acks.insert(envelope.seq);
        }

        self.buffer.push_back(envelope.clone());
        self.trim_buffer(limits);
        envelope
    }

    fn trim_buffer(&mut self, limits: BufferLimits) {
        while self.buffer.len() > limits.max_events {
            let Some(front) = self.buffer.front() else {
                break;
            };
            if self.pending_acks.contains(&front.seq) {
                break;
            }
            self.buffer.pop_front();
        }
    }

    fn latest_cursor(&self) -> Option<String> {
        self.buffer.back().map(|env| env.cursor.clone())
    }

    fn replay_from_cursor(&self, cursor: &str) -> Result<Vec<EventEnvelope>, ReplayError> {
        if cursor.is_empty() {
            return Ok(self.buffer.iter().cloned().collect());
        }

        let cursor_seq = cursor
            .parse::<u64>()
            .map_err(|_| ReplayError::InvalidCursor {
                cursor: cursor.to_string(),
            })?;

        let Some(oldest) = self.buffer.front() else {
            return Ok(Vec::new());
        };
        if cursor_seq < oldest.seq {
            return Err(ReplayError::CursorStale {
                cursor_seq,
                oldest_seq: oldest.seq,
            });
        }

        Ok(self
            .buffer
            .iter()
            .filter(|env| env.seq > cursor_seq)
            .cloned()
            .collect())
    }

    fn apply_ack(&mut self, ack: &EventAck, limits: BufferLimits) -> AckResult {
        let mut acked = Vec::new();
        let mut missing = Vec::new();

        for seq in &ack.seqs {
            if self.pending_acks.remove(seq) {
                acked.push(*seq);
            } else {
                missing.push(*seq);
            }
        }

        self.trim_buffer(limits);

        AckResult { acked, missing }
    }

    fn apply_nack(&self, nack: &EventNack) -> NackResult {
        let mut redeliver = Vec::new();
        let mut missing = Vec::new();

        for seq in &nack.seqs {
            match self.buffer.iter().find(|env| env.seq == *seq) {
                Some(env) => redeliver.push(env.clone()),
                None => missing.push(*seq),
            }
        }

        NackResult { redeliver, missing }
    }
}

/// In-memory manager for streaming event topics.
#[derive(Debug, Default)]
pub struct EventStreamManager {
    caps: EventCaps,
    limits: BufferLimits,
    topics: HashMap<String, TopicState>,
}

impl EventStreamManager {
    /// Create a manager from connector event capabilities.
    #[must_use]
    pub fn new(caps: EventCaps) -> Self {
        let min_events = caps.min_buffer_events as usize;
        let limits = BufferLimits::new(min_events, min_events.max(1));
        Self {
            caps,
            limits,
            topics: HashMap::new(),
        }
    }

    /// Create a manager with explicit buffer limits.
    #[must_use]
    pub fn with_limits(caps: EventCaps, limits: BufferLimits) -> Self {
        Self {
            caps,
            limits,
            topics: HashMap::new(),
        }
    }

    /// Emit a new event for a topic (auto-assigns seq + cursor).
    pub fn emit(&mut self, topic: &str, data: EventData) -> EventEnvelope {
        let envelope = EventEnvelope::new(topic, data);
        self.record(envelope)
    }

    /// Emit a new event with a caller-provided seq.
    pub fn emit_with_seq(&mut self, topic: &str, seq: u64, data: EventData) -> EventEnvelope {
        let envelope = EventEnvelope::new(topic, data).with_seq(seq).with_cursor_seq(seq);
        self.record(envelope)
    }

    /// Record an already-constructed event (fills missing cursor/ack flags).
    pub fn record(&mut self, envelope: EventEnvelope) -> EventEnvelope {
        let topic = envelope.topic.clone();
        let state = self.topics.entry(topic).or_default();
        state.record_event(envelope, &self.caps, self.limits)
    }

    /// Handle a SubscribeRequest and compute replay responses if requested.
    pub fn handle_subscribe(
        &mut self,
        req: &SubscribeRequest,
    ) -> Result<SubscribeOutcome, ReplayError> {
        let mut confirmed = Vec::new();
        let mut cursors = HashMap::new();

        for topic in &req.topics {
            let state = self.topics.entry(topic.clone()).or_default();
            confirmed.push(topic.clone());
            if let Some(cursor) = state.latest_cursor() {
                if !cursor.is_empty() {
                    cursors.insert(topic.clone(), cursor);
                }
            }
        }

        let buffer = if self.caps.replay {
            Some(ReplayBufferInfo {
                min_events: self.limits.min_events as u32,
                overflow: "drop_oldest".to_string(),
            })
        } else {
            None
        };

        let response = SubscribeResponse {
            r#type: "response".to_string(),
            id: RequestId(req.id.0.clone()),
            result: SubscribeResult {
                confirmed_topics: confirmed.clone(),
                cursors,
                replay_supported: self.caps.replay,
                buffer,
            },
        };

        let mut replay_events = HashMap::new();
        if self.caps.replay {
            if let Some(ref since) = req.since {
                for topic in &confirmed {
                    let events = self.replay_from(topic, since)?;
                    if !events.is_empty() {
                        replay_events.insert(topic.clone(), events);
                    }
                }
            }
        }

        Ok(SubscribeOutcome {
            response,
            replay_events,
        })
    }

    /// Remove subscriptions for topics and return how many were removed.
    pub fn unsubscribe(&mut self, topics: &[String]) -> usize {
        let mut removed = 0;
        for topic in topics {
            if self.topics.remove(topic).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Replay buffered events for a topic from a cursor.
    pub fn replay_from(&self, topic: &str, cursor: &str) -> Result<Vec<EventEnvelope>, ReplayError> {
        match self.topics.get(topic) {
            Some(state) => state.replay_from_cursor(cursor),
            None => Err(ReplayError::UnknownTopic {
                topic: topic.to_string(),
            }),
        }
    }

    /// Apply an EventAck to update pending-ack state.
    pub fn handle_ack(&mut self, ack: &EventAck) -> AckResult {
        match self.topics.get_mut(&ack.topic) {
            Some(state) => state.apply_ack(ack, self.limits),
            None => AckResult {
                acked: Vec::new(),
                missing: ack.seqs.clone(),
            },
        }
    }

    /// Apply an EventNack and return events to redeliver.
    pub fn handle_nack(&self, nack: &EventNack) -> NackResult {
        match self.topics.get(&nack.topic) {
            Some(state) => state.apply_nack(nack),
            None => NackResult {
                redeliver: Vec::new(),
                missing: nack.seqs.clone(),
            },
        }
    }

    /// Pending ack count for a topic.
    #[must_use]
    pub fn pending_acks(&self, topic: &str) -> usize {
        self.topics
            .get(topic)
            .map(|state| state.pending_acks.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{ConnectorId, InstanceId, Principal, TrustLevel, ZoneId};
    use serde_json::json;

    fn sample_event_data() -> EventData {
        EventData::new(
            ConnectorId::from_static("test:streaming:v1"),
            InstanceId::new(),
            ZoneId::work(),
            Principal {
                kind: "user".to_string(),
                id: "alice".to_string(),
                trust: TrustLevel::Paired,
                display: Some("Alice".to_string()),
            },
            json!({"message": "hi"}),
        )
    }

    fn caps(replay: bool, requires_ack: bool, min_buffer_events: u32) -> EventCaps {
        EventCaps {
            streaming: true,
            replay,
            min_buffer_events,
            requires_ack,
        }
    }

    #[test]
    fn cursor_monotonicity() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        let e1 = manager.emit("events.test", sample_event_data());
        let e2 = manager.emit("events.test", sample_event_data());
        let e3 = manager.emit("events.test", sample_event_data());

        assert_eq!(e1.seq, 0);
        assert_eq!(e2.seq, 1);
        assert_eq!(e3.seq, 2);
        assert_eq!(e1.cursor, "0");
        assert_eq!(e2.cursor, "1");
        assert_eq!(e3.cursor, "2");
    }

    #[test]
    fn ack_required_tracks_pending() {
        let mut manager = EventStreamManager::new(caps(true, true, 2));
        let e1 = manager.emit("events.ack", sample_event_data());
        let e2 = manager.emit("events.ack", sample_event_data());

        assert!(e1.requires_ack);
        assert!(e2.requires_ack);
        assert_eq!(manager.pending_acks("events.ack"), 2);

        let ack = EventAck::new("events.ack", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
        let result = manager.handle_ack(&ack);
        assert_eq!(result.acked, vec![e1.seq]);
        assert_eq!(manager.pending_acks("events.ack"), 1);
    }

    #[test]
    fn subscribe_replay_ack_flow() {
        let mut manager = EventStreamManager::new(caps(true, true, 3));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-1"),
            topics: vec!["events.flow".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(outcome.response.result.replay_supported);

        let e1 = manager.emit("events.flow", sample_event_data());
        let e2 = manager.emit("events.flow", sample_event_data());

        let ack = EventAck::new("events.flow", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
        manager.handle_ack(&ack);

        let replayed = manager.replay_from("events.flow", &e1.cursor).unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].seq, e2.seq);
    }
}

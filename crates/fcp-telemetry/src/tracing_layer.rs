//! Distributed tracing with span creation and context propagation.
//!
//! Provides W3C Trace Context compliant distributed tracing.

use std::collections::HashMap;

use opentelemetry::{
    global,
    trace::{Span, SpanKind, Status, Tracer},
    KeyValue,
};

/// W3C Trace Context header names.
pub const TRACEPARENT_HEADER: &str = "traceparent";
pub const TRACESTATE_HEADER: &str = "tracestate";

/// Extract trace context from headers (W3C Trace Context format).
#[must_use]
pub fn extract_trace_context(headers: &HashMap<String, String>) -> Option<TraceContext> {
    let traceparent = headers.get(TRACEPARENT_HEADER)?;
    TraceContext::from_traceparent(traceparent)
}

/// Inject trace context into headers.
pub fn inject_trace_context(ctx: &TraceContext, headers: &mut HashMap<String, String>) {
    headers.insert(TRACEPARENT_HEADER.to_string(), ctx.to_traceparent());
    if let Some(ref state) = ctx.trace_state {
        headers.insert(TRACESTATE_HEADER.to_string(), state.clone());
    }
}

/// W3C Trace Context representation.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace ID (32 hex chars).
    pub trace_id: String,

    /// Parent span ID (16 hex chars).
    pub parent_span_id: String,

    /// Trace flags.
    pub trace_flags: u8,

    /// Optional trace state.
    pub trace_state: Option<String>,
}

impl TraceContext {
    /// Create a new trace context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trace_id: generate_trace_id(),
            parent_span_id: generate_span_id(),
            trace_flags: 0x01, // Sampled
            trace_state: None,
        }
    }

    /// Parse from traceparent header value.
    ///
    /// Format: `{version}-{trace_id}-{parent_span_id}-{trace_flags}`
    #[must_use]
    pub fn from_traceparent(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        if version != "00" {
            return None; // Only support version 00
        }

        let trace_id = parts[1];
        let parent_span_id = parts[2];
        let trace_flags = u8::from_str_radix(parts[3], 16).ok()?;

        if trace_id.len() != 32 || parent_span_id.len() != 16 {
            return None;
        }

        Some(Self {
            trace_id: trace_id.to_string(),
            parent_span_id: parent_span_id.to_string(),
            trace_flags,
            trace_state: None,
        })
    }

    /// Convert to traceparent header value.
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.parent_span_id, self.trace_flags
        )
    }

    /// Check if this trace is sampled.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }

    /// Create a child context with a new span ID.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            parent_span_id: generate_span_id(),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
        }
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random trace ID (32 hex chars).
fn generate_trace_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let random: u64 = rand_u64();
    format!("{:016x}{:016x}", timestamp as u64, random)
}

/// Generate a random span ID (16 hex chars).
fn generate_span_id() -> String {
    format!("{:016x}", rand_u64())
}

/// Simple random u64 using system time as entropy source.
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut hasher = DefaultHasher::new();
    now.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    hasher.finish()
}

/// FCP operation span builder.
pub struct FcpSpan {
    name: String,
    kind: SpanKind,
    attributes: Vec<KeyValue>,
}

impl FcpSpan {
    /// Create a new span builder.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: SpanKind::Internal,
            attributes: Vec::new(),
        }
    }

    /// Set span kind.
    #[must_use]
    pub const fn kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set as client span.
    #[must_use]
    pub const fn client(mut self) -> Self {
        self.kind = SpanKind::Client;
        self
    }

    /// Set as server span.
    #[must_use]
    pub const fn server(mut self) -> Self {
        self.kind = SpanKind::Server;
        self
    }

    /// Add an attribute.
    #[must_use]
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push(KeyValue::new(key.into(), value.into()));
        self
    }

    /// Set connector ID attribute.
    #[must_use]
    pub fn connector_id(self, id: impl Into<String>) -> Self {
        self.attribute("fcp.connector_id", id)
    }

    /// Set operation attribute.
    #[must_use]
    pub fn operation(self, op: impl Into<String>) -> Self {
        self.attribute("fcp.operation", op)
    }

    /// Set request ID attribute.
    #[must_use]
    pub fn request_id(self, id: impl Into<String>) -> Self {
        self.attribute("fcp.request_id", id)
    }

    /// Start the span and return a guard.
    #[must_use]
    pub fn start(self) -> SpanGuard {
        let tracer = global::tracer("fcp-telemetry");

        let mut span_builder = tracer.span_builder(self.name);
        span_builder.span_kind = Some(self.kind);

        let mut span = span_builder.start(&tracer);

        for attr in &self.attributes {
            span.set_attribute(attr.clone());
        }

        SpanGuard { span: Some(span) }
    }
}

/// RAII guard for a span.
pub struct SpanGuard {
    span: Option<opentelemetry::global::BoxedSpan>,
}

impl SpanGuard {
    /// Set an attribute on the span.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        if let Some(ref mut span) = self.span {
            span.set_attribute(KeyValue::new(key.into(), value.into()));
        }
    }

    /// Record an error on the span.
    pub fn record_error(&mut self, error: &str) {
        if let Some(ref mut span) = self.span {
            span.set_status(Status::error(error.to_string()));
        }
    }

    /// Mark the span as successful.
    pub fn set_ok(&mut self) {
        if let Some(ref mut span) = self.span {
            span.set_status(Status::Ok);
        }
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        if let Some(mut span) = self.span.take() {
            span.end();
        }
    }
}

/// Create a tracing span with FCP context.
#[macro_export]
macro_rules! fcp_span {
    ($name:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::info_span!(
            $name,
            $($key = %$value,)*
            otel.kind = "internal",
        )
    };
}

/// Create a client span.
#[macro_export]
macro_rules! fcp_client_span {
    ($name:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::info_span!(
            $name,
            $($key = %$value,)*
            otel.kind = "client",
        )
    };
}

/// Create a server span.
#[macro_export]
macro_rules! fcp_server_span {
    ($name:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::info_span!(
            $name,
            $($key = %$value,)*
            otel.kind = "server",
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_roundtrip() {
        let ctx = TraceContext::new();
        let traceparent = ctx.to_traceparent();
        let parsed = TraceContext::from_traceparent(&traceparent).unwrap();

        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.parent_span_id, parsed.parent_span_id);
        assert_eq!(ctx.trace_flags, parsed.trace_flags);
    }

    #[test]
    fn test_parse_traceparent() {
        let value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::from_traceparent(value).unwrap();

        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_span_id, "00f067aa0ba902b7");
        assert_eq!(ctx.trace_flags, 0x01);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_child_context() {
        let parent = TraceContext::new();
        let child = parent.child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.parent_span_id, child.parent_span_id);
    }

    #[test]
    fn test_inject_extract() {
        let ctx = TraceContext::new();
        let mut headers = HashMap::new();
        inject_trace_context(&ctx, &mut headers);

        let extracted = extract_trace_context(&headers).unwrap();
        assert_eq!(ctx.trace_id, extracted.trace_id);
    }
}

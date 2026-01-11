//! Telemetry context for correlation and field injection.
//!
//! Provides context propagation for correlation IDs, zone IDs, connector IDs,
//! and request IDs across log entries and trace spans.

use std::sync::Arc;

use parking_lot::RwLock;
use tracing::Span;
use uuid::Uuid;

tokio::task_local! {
    static CONTEXT: Arc<TelemetryContext>;
}

/// Telemetry context containing correlation fields.
#[derive(Debug, Default)]
pub struct TelemetryContext {
    /// Unique correlation ID for request tracing.
    pub correlation_id: Option<String>,

    /// Zone ID from FCP capability token.
    pub zone_id: Option<String>,

    /// Connector ID.
    pub connector_id: Option<String>,

    /// Current request ID.
    pub request_id: Option<Uuid>,

    /// Principal ID (user/service making the request).
    pub principal_id: Option<String>,

    /// Additional custom fields.
    fields: RwLock<Vec<(String, String)>>,
}

impl Clone for TelemetryContext {
    fn clone(&self) -> Self {
        Self {
            correlation_id: self.correlation_id.clone(),
            zone_id: self.zone_id.clone(),
            connector_id: self.connector_id.clone(),
            request_id: self.request_id,
            principal_id: self.principal_id.clone(),
            fields: RwLock::new(self.fields.read().clone()),
        }
    }
}

impl TelemetryContext {
    /// Create a new empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a context with a new correlation ID.
    #[must_use]
    pub fn with_correlation_id() -> Self {
        Self {
            correlation_id: Some(Uuid::new_v4().to_string()),
            ..Default::default()
        }
    }

    /// Set the correlation ID.
    #[must_use]
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, id: impl Into<String>) -> Self {
        self.zone_id = Some(id.into());
        self
    }

    /// Set the connector ID.
    #[must_use]
    pub fn connector_id(mut self, id: impl Into<String>) -> Self {
        self.connector_id = Some(id.into());
        self
    }

    /// Set the request ID.
    #[must_use]
    pub const fn request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Set the principal ID.
    #[must_use]
    pub fn principal_id(mut self, id: impl Into<String>) -> Self {
        self.principal_id = Some(id.into());
        self
    }

    /// Add a custom field.
    pub fn add_field(&self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.write().push((key.into(), value.into()));
    }

    /// Get all fields as key-value pairs.
    #[must_use]
    pub fn all_fields(&self) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        if let Some(ref id) = self.correlation_id {
            fields.push(("correlation_id".to_string(), id.clone()));
        }
        if let Some(ref id) = self.zone_id {
            fields.push(("zone_id".to_string(), id.clone()));
        }
        if let Some(ref id) = self.connector_id {
            fields.push(("connector_id".to_string(), id.clone()));
        }
        if let Some(id) = self.request_id {
            fields.push(("request_id".to_string(), id.to_string()));
        }
        if let Some(ref id) = self.principal_id {
            fields.push(("principal_id".to_string(), id.clone()));
        }

        fields.extend(self.fields.read().clone());
        fields
    }

    /// Apply context fields to the current tracing span.
    pub fn apply_to_span(&self) {
        let span = Span::current();

        if let Some(ref id) = self.correlation_id {
            span.record("correlation_id", id.as_str());
        }
        if let Some(ref id) = self.zone_id {
            span.record("zone_id", id.as_str());
        }
        if let Some(ref id) = self.connector_id {
            span.record("connector_id", id.as_str());
        }
        if let Some(id) = self.request_id {
            span.record("request_id", id.to_string().as_str());
        }
        if let Some(ref id) = self.principal_id {
            span.record("principal_id", id.as_str());
        }
    }
}

/// Run a future with the given telemetry context.
pub async fn with_context<F, T>(ctx: TelemetryContext, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    CONTEXT.scope(Arc::new(ctx), f).await
}

/// Get a clone of the current telemetry context.
///
/// Returns `None` if no context is set.
pub fn current_context() -> Option<Arc<TelemetryContext>> {
    CONTEXT.try_with(Arc::clone).ok()
}

/// Get the current correlation ID.
pub fn current_correlation_id() -> Option<String> {
    current_context().and_then(|ctx| ctx.correlation_id.clone())
}

/// Get the current connector ID.
pub fn current_connector_id() -> Option<String> {
    current_context().and_then(|ctx| ctx.connector_id.clone())
}

/// Get the current request ID.
pub fn current_request_id() -> Option<Uuid> {
    current_context().and_then(|ctx| ctx.request_id)
}

/// Context guard for RAII-style context management.
pub struct ContextGuard {
    _span: tracing::span::EnteredSpan,
}

impl ContextGuard {
    /// Create a new context guard with a span.
    #[must_use]
    pub fn new(ctx: &TelemetryContext, operation: &str) -> Self {
        let span = tracing::info_span!(
            "fcp_operation",
            operation = operation,
            correlation_id = tracing::field::Empty,
            zone_id = tracing::field::Empty,
            connector_id = tracing::field::Empty,
            request_id = tracing::field::Empty,
            principal_id = tracing::field::Empty,
        );

        let entered = span.entered();
        ctx.apply_to_span();

        Self { _span: entered }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = TelemetryContext::new()
            .correlation_id("test-123")
            .zone_id("work")
            .connector_id("my-connector");

        assert_eq!(ctx.correlation_id, Some("test-123".to_string()));
        assert_eq!(ctx.zone_id, Some("work".to_string()));
        assert_eq!(ctx.connector_id, Some("my-connector".to_string()));
    }

    #[test]
    fn test_all_fields() {
        let ctx = TelemetryContext::new()
            .correlation_id("corr-123")
            .connector_id("conn-456");

        ctx.add_field("custom", "value");

        let fields = ctx.all_fields();
        assert!(fields.iter().any(|(k, v)| k == "correlation_id" && v == "corr-123"));
        assert!(fields.iter().any(|(k, v)| k == "connector_id" && v == "conn-456"));
        assert!(fields.iter().any(|(k, v)| k == "custom" && v == "value"));
    }
}

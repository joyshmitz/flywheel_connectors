//! Structured logging with JSON output and sensitive data redaction.

use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

use crate::{TelemetryConfig, TelemetryError};

/// Initialize the logging subsystem.
pub(crate) fn init_logging(config: &TelemetryConfig) -> Result<(), TelemetryError> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    if config.json_logs {
        let json_layer = fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_target(true)
            .with_span_events(FmtSpan::CLOSE);

        subscriber
            .with(json_layer)
            .try_init()
            .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;
    } else {
        let pretty_layer = fmt::layer()
            .with_ansi(true)
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .with_span_events(FmtSpan::CLOSE);

        subscriber
            .with(pretty_layer)
            .try_init()
            .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;
    }

    Ok(())
}

/// Redact sensitive fields from a JSON value.
#[must_use]
pub fn redact_sensitive(value: &serde_json::Value, fields: &[String]) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                if fields.iter().any(|f| key.to_lowercase().contains(&f.to_lowercase())) {
                    result.insert(key.clone(), serde_json::Value::String("[REDACTED]".to_string()));
                } else {
                    result.insert(key.clone(), redact_sensitive(val, fields));
                }
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| redact_sensitive(v, fields)).collect())
        }
        other => other.clone(),
    }
}

/// Log a structured event with automatic field injection.
#[macro_export]
macro_rules! log_event {
    ($level:ident, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::$level!(
            message = $message,
            $($key = %$value,)*
        );
    };
}

/// Log an error with context.
#[macro_export]
macro_rules! log_error {
    ($err:expr, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::error!(
            error = %$err,
            error_type = %std::any::type_name_of_val(&$err),
            message = $message,
            $($key = %$value,)*
        );
    };
}

/// Log a request/response pair.
pub fn log_request_response(
    operation: &str,
    request: &serde_json::Value,
    response: &serde_json::Value,
    duration_ms: u64,
    success: bool,
) {
    let redact_fields = vec![
        "password".to_string(),
        "api_key".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "authorization".to_string(),
    ];

    let redacted_request = redact_sensitive(request, &redact_fields);
    let redacted_response = redact_sensitive(response, &redact_fields);

    if success {
        tracing::info!(
            operation = operation,
            request = %redacted_request,
            response = %redacted_response,
            duration_ms = duration_ms,
            "Request completed successfully"
        );
    } else {
        tracing::warn!(
            operation = operation,
            request = %redacted_request,
            response = %redacted_response,
            duration_ms = duration_ms,
            "Request completed with error"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_sensitive() {
        let value = json!({
            "user": "john",
            "password": "secret123",
            "api_key": "key-abc",
            "data": {
                "token": "tok-xyz",
                "name": "test"
            }
        });

        let redacted = redact_sensitive(&value, &[
            "password".to_string(),
            "api_key".to_string(),
            "token".to_string(),
        ]);

        assert_eq!(redacted["user"], "john");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["data"]["token"], "[REDACTED]");
        assert_eq!(redacted["data"]["name"], "test");
    }

    #[test]
    fn test_redact_nested_array() {
        let value = json!({
            "users": [
                {"name": "john", "password": "pass1"},
                {"name": "jane", "password": "pass2"}
            ]
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["users"][0]["name"], "john");
        assert_eq!(redacted["users"][0]["password"], "[REDACTED]");
        assert_eq!(redacted["users"][1]["name"], "jane");
        assert_eq!(redacted["users"][1]["password"], "[REDACTED]");
    }
}

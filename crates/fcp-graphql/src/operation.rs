//! Operation types and typed GraphQL traits.

use serde::{Deserialize, Serialize};

use crate::error::GraphqlError;

/// GraphQL query wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlQuery {
    query: String,
}

impl GraphqlQuery {
    /// Create a new query from a string.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
        }
    }

    /// Create a new query from a static string.
    #[must_use]
    pub fn from_static(query: &'static str) -> Self {
        Self::new(query)
    }

    /// Return the query text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.query
    }
}

/// Typed GraphQL operation definition.
///
/// Implement this trait for each query/mutation/subscription.
pub trait GraphqlOperation {
    /// Variables type.
    type Variables: Serialize + Send + Sync;
    /// Response data type.
    type ResponseData: Serialize + for<'de> Deserialize<'de> + Send + Sync;

    /// GraphQL query text.
    const QUERY: &'static str;
    /// Operation name (used for observability and routing).
    const OPERATION_NAME: &'static str;

    /// Optional JSON Schema for variables.
    fn variables_schema() -> Option<&'static str> {
        None
    }

    /// Optional JSON Schema for response data.
    fn response_schema() -> Option<&'static str> {
        None
    }

    /// Whether this operation is safe to retry on transport errors.
    fn is_idempotent() -> bool {
        true
    }
}

/// GraphQL request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlRequest<V> {
    /// Query text.
    pub query: GraphqlQuery,
    /// Variables.
    pub variables: V,
    /// Optional operation name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

impl<V> GraphqlRequest<V> {
    /// Create a new request.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(query: GraphqlQuery, variables: V) -> Self {
        Self {
            query,
            variables,
            operation_name: None,
        }
    }

    /// Attach an operation name.
    #[must_use]
    pub fn with_operation_name(mut self, name: impl Into<String>) -> Self {
        self.operation_name = Some(name.into());
        self
    }
}

/// GraphQL batch item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlBatchItem<V> {
    /// Query text.
    pub query: GraphqlQuery,
    /// Variables payload.
    pub variables: V,
    /// Optional operation name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

impl<V> GraphqlBatchItem<V> {
    /// Create a batch item.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(query: GraphqlQuery, variables: V) -> Self {
        Self {
            query,
            variables,
            operation_name: None,
        }
    }

    /// Attach an operation name.
    #[must_use]
    pub fn with_operation_name(mut self, name: impl Into<String>) -> Self {
        self.operation_name = Some(name.into());
        self
    }
}

/// GraphQL response container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct GraphqlResponse<T> {
    /// Response data.
    #[serde(default)]
    pub data: Option<T>,
    /// GraphQL errors.
    #[serde(default)]
    pub errors: Vec<GraphqlError>,
    /// Extensions payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl<T> GraphqlResponse<T> {
    /// Returns `true` if no GraphQL errors were returned.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::time::Instant;

use chrono::Utc;
use fcp_testkit::LogCapture;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use fcp_graphql::{
    CursorPage, CursorPageInfo, GraphqlClientBuilder, GraphqlClientError, GraphqlOperation,
    GraphqlSubscriptionClient, OffsetPage, PageLimit, PaginationError, RetryPolicy, RetryStrategy,
    SchemaValidationMode, paginate_cursor, paginate_offset,
};

#[derive(Debug, Serialize)]
struct EmptyVars {}

#[derive(Debug, Serialize, Deserialize)]
struct ViewerResponse {
    viewer: Viewer,
}

#[derive(Debug, Serialize, Deserialize)]
struct Viewer {
    id: String,
}

#[derive(Debug, Serialize)]
struct IdVars {
    id: String,
}

#[derive(Debug, Serialize)]
struct BadVars {
    id: u64,
}

struct ViewerQuery;

impl GraphqlOperation for ViewerQuery {
    type Variables = EmptyVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = "query Viewer { viewer { id } }";
    const OPERATION_NAME: &'static str = "Viewer";

    fn response_schema() -> Option<&'static str> {
        Some(
            r#"{
                "type": "object",
                "required": ["viewer"],
                "properties": {
                    "viewer": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string"}
                        }
                    }
                }
            }"#,
        )
    }
}

struct ViewerByIdQuery;

impl GraphqlOperation for ViewerByIdQuery {
    type Variables = IdVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = "query ViewerById($id: ID!) { viewer { id } }";
    const OPERATION_NAME: &'static str = "ViewerById";

    fn variables_schema() -> Option<&'static str> {
        Some(
            r#"{
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string" }
                }
            }"#,
        )
    }

    fn response_schema() -> Option<&'static str> {
        ViewerQuery::response_schema()
    }
}

struct BadVarsQuery;

impl GraphqlOperation for BadVarsQuery {
    type Variables = BadVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = ViewerByIdQuery::QUERY;
    const OPERATION_NAME: &'static str = ViewerByIdQuery::OPERATION_NAME;

    fn variables_schema() -> Option<&'static str> {
        ViewerByIdQuery::variables_schema()
    }
}

struct MutationQuery;

impl GraphqlOperation for MutationQuery {
    type Variables = IdVars;
    type ResponseData = ViewerResponse;

    const QUERY: &'static str = "mutation UpdateViewer($id: ID!) { viewer { id } }";
    const OPERATION_NAME: &'static str = "UpdateViewer";

    fn variables_schema() -> Option<&'static str> {
        ViewerByIdQuery::variables_schema()
    }

    fn response_schema() -> Option<&'static str> {
        ViewerQuery::response_schema()
    }

    fn is_idempotent() -> bool {
        false
    }
}

struct ViewerSchemaQuery;

impl GraphqlOperation for ViewerSchemaQuery {
    type Variables = EmptyVars;
    type ResponseData = serde_json::Value;

    const QUERY: &'static str = ViewerQuery::QUERY;
    const OPERATION_NAME: &'static str = ViewerQuery::OPERATION_NAME;

    fn response_schema() -> Option<&'static str> {
        ViewerQuery::response_schema()
    }
}

struct SequenceResponder {
    counter: Arc<AtomicUsize>,
}

impl Respond for SequenceResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let attempt = self.counter.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "fail"}))
        } else {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"viewer": {"id": "user-2"}}
            }))
        }
    }
}

struct CountingResponder {
    counter: Arc<AtomicUsize>,
    body: serde_json::Value,
    delay: Option<Duration>,
}

impl Respond for CountingResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let mut response = ResponseTemplate::new(200).set_body_json(self.body.clone());
        if let Some(delay) = self.delay {
            response = response.set_delay(delay);
        }
        response
    }
}

struct TestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl TestContext {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-graphql::client".to_string(),
            correlation_id: format!("graphql-{}", std::process::id()),
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    fn assert_true(&mut self, condition: bool, msg: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{}", msg);
        }
    }

    fn assert_eq<T: std::fmt::Debug + PartialEq>(&mut self, actual: T, expected: T, msg: &str) {
        if actual == expected {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}: expected {expected:?}, got {actual:?}");
        }
    }

    fn finalize(&self, result: &str, details: Option<serde_json::Value>) {
        let duration_ms = u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": self.test_name,
            "module": self.module,
            "phase": "verify",
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });

        if let Some(extra) = details {
            entry["details"] = extra;
        }

        self.capture
            .push_value(&entry)
            .expect("structured test log entry");
        self.capture.assert_valid();
    }
}

#[tokio::test]
async fn execute_query_success() {
    let mut ctx = TestContext::new("execute_query_success");
    let server = MockServer::start().await;

    let expected_body = serde_json::json!({
        "query": ViewerQuery::QUERY,
        "operationName": ViewerQuery::OPERATION_NAME,
        "variables": {},
    });

    let response_body = serde_json::json!({
        "data": {
            "viewer": {
                "id": "user-1"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_service_name("test")
        .build()
        .expect("client");

    let response = client
        .execute::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query should succeed");

    ctx.assert_true(response.errors.is_empty(), "expected no GraphQL errors");
    let viewer = response.data.expect("missing data");
    ctx.assert_eq(viewer.viewer.id, "user-1".to_string(), "viewer id mismatch");
    ctx.finalize("pass", Some(serde_json::json!({"status": "ok"})));
}

#[tokio::test]
async fn execute_query_with_variables() {
    let mut ctx = TestContext::new("execute_query_with_variables");
    let server = MockServer::start().await;

    let expected_body = serde_json::json!({
        "query": ViewerByIdQuery::QUERY,
        "operationName": ViewerByIdQuery::OPERATION_NAME,
        "variables": { "id": "user-42" },
    });

    let response_body = serde_json::json!({
        "data": {
            "viewer": {
                "id": "user-42"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
        .build()
        .expect("client");

    let response = client
        .execute::<ViewerByIdQuery>(IdVars {
            id: "user-42".to_string(),
        })
        .await
        .expect("query should succeed");

    ctx.assert_true(response.errors.is_empty(), "expected no GraphQL errors");
    let viewer = response.data.expect("missing data");
    ctx.assert_eq(
        viewer.viewer.id,
        "user-42".to_string(),
        "viewer id mismatch",
    );
    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation": "variables_and_response"})),
    );
}

#[tokio::test]
async fn execute_query_rejects_invalid_variables() {
    let mut ctx = TestContext::new("execute_query_rejects_invalid_variables");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!({"data": {"viewer": {"id": "unused"}}}),
            delay: None,
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::VariablesAndResponse)
        .build()
        .expect("client");

    let err = client
        .execute::<BadVarsQuery>(BadVars { id: 123 })
        .await
        .expect_err("should reject invalid variables");

    ctx.assert_true(
        matches!(err, GraphqlClientError::SchemaValidation { .. }),
        "expected schema validation error",
    );
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        0_usize,
        "expected no request",
    );
    ctx.finalize("pass", Some(serde_json::json!({"validation": "variables"})));
}

#[tokio::test]
async fn execute_batch_success() {
    let mut ctx = TestContext::new("execute_batch_success");
    let server = MockServer::start().await;

    let items = vec![
        fcp_graphql::GraphqlBatchItem::new(
            fcp_graphql::GraphqlQuery::from_static(ViewerByIdQuery::QUERY),
            IdVars {
                id: "user-1".to_string(),
            },
        )
        .with_operation_name(ViewerByIdQuery::OPERATION_NAME),
        fcp_graphql::GraphqlBatchItem::new(
            fcp_graphql::GraphqlQuery::from_static(ViewerByIdQuery::QUERY),
            IdVars {
                id: "user-2".to_string(),
            },
        )
        .with_operation_name(ViewerByIdQuery::OPERATION_NAME),
    ];

    let expected_body = serde_json::to_value(&items).expect("serialize batch");

    let response_body = serde_json::json!([
        {"data": {"viewer": {"id": "user-1"}}},
        {"data": {"viewer": {"id": "user-2"}}}
    ]);

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let responses = client
        .execute_batch::<ViewerByIdQuery>(vec![
            IdVars {
                id: "user-1".to_string(),
            },
            IdVars {
                id: "user-2".to_string(),
            },
        ])
        .await
        .expect("batch should succeed");

    ctx.assert_eq(responses.len(), 2_usize, "expected two responses");
    let first = responses[0].data.as_ref().expect("missing data");
    let second = responses[1].data.as_ref().expect("missing data");
    ctx.assert_eq(
        first.viewer.id.clone(),
        "user-1".to_string(),
        "first viewer id",
    );
    ctx.assert_eq(
        second.viewer.id.clone(),
        "user-2".to_string(),
        "second viewer id",
    );

    ctx.finalize("pass", Some(serde_json::json!({"batch_size": 2})));
}

#[tokio::test]
async fn execute_query_dedup_in_flight() {
    let mut ctx = TestContext::new("execute_query_dedup_in_flight");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CountingResponder {
            counter: counter.clone(),
            body: serde_json::json!({
                "data": {
                    "viewer": {"id": "user-1"}
                }
            }),
            delay: Some(Duration::from_millis(50)),
        })
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_dedup_in_flight(true)
        .build()
        .expect("client");

    let (first, second) = tokio::join!(
        client.execute::<ViewerQuery>(EmptyVars {}),
        client.execute::<ViewerQuery>(EmptyVars {})
    );

    let first = first.expect("first response");
    let second = second.expect("second response");

    ctx.assert_true(first.errors.is_empty(), "first response errors");
    ctx.assert_true(second.errors.is_empty(), "second response errors");
    ctx.assert_eq(
        counter.load(Ordering::SeqCst),
        1_usize,
        "expected one HTTP request",
    );
    ctx.finalize("pass", Some(serde_json::json!({"dedup": true})));
}

#[tokio::test]
async fn execute_query_graphql_errors() {
    let mut ctx = TestContext::new("execute_query_graphql_errors");
    let server = MockServer::start().await;

    let response_body = serde_json::json!({
        "errors": [
            {"message": "boom"}
        ]
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_service_name("test")
        .build()
        .expect("client");

    let err = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect_err("should return GraphQL errors");

    let error_len = match err {
        GraphqlClientError::GraphqlErrors { errors } => {
            ctx.assert_eq(errors.len(), 1_usize, "expected one GraphQL error");
            ctx.assert_eq(
                errors[0].message.clone(),
                "boom".to_string(),
                "error message mismatch",
            );
            errors.len()
        }
        other => panic!("unexpected error: {other:?}"),
    };

    ctx.finalize("pass", Some(serde_json::json!({ "errors": error_len })));
}

#[tokio::test]
async fn execute_query_retries_on_500() {
    let mut ctx = TestContext::new("execute_query_retries_on_500");
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SequenceResponder {
            counter: counter_clone,
        })
        .mount(&server)
        .await;

    let retry = RetryPolicy {
        max_attempts: 2,
        base_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(20),
        max_jitter: Duration::from_millis(0),
        strategy: fcp_graphql::RetryStrategy::Always,
    };

    let client = GraphqlClientBuilder::new(server.uri())
        .with_retry_policy(retry)
        .build()
        .expect("client");

    let response = client
        .execute_strict::<ViewerQuery>(EmptyVars {})
        .await
        .expect("query should succeed after retry");

    ctx.assert_eq(
        response.viewer.id,
        "user-2".to_string(),
        "viewer id mismatch",
    );
    let attempts = counter.load(Ordering::SeqCst);
    ctx.assert_eq(attempts, 2_usize, "unexpected retry attempts");
    ctx.finalize("pass", Some(serde_json::json!({ "attempts": attempts })));
}

#[tokio::test]
async fn schema_validation_rejects_invalid_response() {
    let mut ctx = TestContext::new("schema_validation_rejects_invalid_response");
    let server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "viewer": {
                "id": 123
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = GraphqlClientBuilder::new(server.uri())
        .with_validation_mode(SchemaValidationMode::ResponseOnly)
        .build()
        .expect("client");

    let err = client
        .execute::<ViewerSchemaQuery>(EmptyVars {})
        .await
        .expect_err("should fail schema validation");

    ctx.assert_true(
        matches!(err, GraphqlClientError::SchemaValidation { .. }),
        "expected schema validation error",
    );
    ctx.finalize(
        "pass",
        Some(serde_json::json!({"validation_mode": "response"})),
    );
}

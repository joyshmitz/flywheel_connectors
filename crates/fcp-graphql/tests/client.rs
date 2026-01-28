use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_graphql::{
    GraphqlClientBuilder, GraphqlClientError, GraphqlOperation, RetryPolicy,
    SchemaValidationMode,
};

#[derive(Debug, Serialize)]
struct EmptyVars {}

#[derive(Debug, Deserialize)]
struct ViewerResponse {
    viewer: Viewer,
}

#[derive(Debug, Deserialize)]
struct Viewer {
    id: String,
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

#[tokio::test]
async fn execute_query_success() {
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
        .execute::<ViewerQuery>(EmptyVars)
        .await
        .expect("query should succeed");

    assert!(response.errors.is_empty());
    assert_eq!(response.data.unwrap().viewer.id, "user-1");
}

#[tokio::test]
async fn execute_query_graphql_errors() {
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
        .execute_strict::<ViewerQuery>(EmptyVars)
        .await
        .expect_err("should return GraphQL errors");

    match err {
        GraphqlClientError::GraphqlErrors { errors } => {
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].message, "boom");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn execute_query_retries_on_500() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(move |_req| {
            let attempt = counter_clone.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "fail"}))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {"viewer": {"id": "user-2"}}
                }))
            }
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
        .execute_strict::<ViewerQuery>(EmptyVars)
        .await
        .expect("query should succeed after retry");

    assert_eq!(response.viewer.id, "user-2");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn schema_validation_rejects_invalid_response() {
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
        .execute::<ViewerQuery>(EmptyVars)
        .await
        .expect_err("should fail schema validation");

    match err {
        GraphqlClientError::SchemaValidation { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

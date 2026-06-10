//! Proxy integration tests (UTS rest/integration/proxy/rest_fallback.md).
//!
//! These run the SDK's real HTTP client through the programmable uts-proxy
//! against the Ably nonprod sandbox, verifying fallback classification and
//! error surfacing end-to-end. The proxy binary is auto-downloaded and
//! spawned by `crate::proxy::ensure_proxy`.
//!
//! Run serially: `cargo test --lib tests_proxy -- --test-threads=1`

use std::sync::Arc;

use crate::auth::{AuthCallback, AuthToken, TokenParams};
use crate::error::Result;
use crate::options::ClientOptions;
use crate::proxy::{allocate_port, ProxySession, Rule};
use crate::rest::Rest;
use crate::tests_rest_integration::{get_sandbox, random_id};

/// UTS "Token Auth Helper": obtains tokens directly from the sandbox
/// (bypassing the proxy) so token requests are never intercepted by
/// fault-injection rules.
struct SandboxTokenCallback {
    api_key: String,
}

impl AuthCallback for SandboxTokenCallback {
    fn token<'a>(
        &'a self,
        params: &'a TokenParams,
    ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
        Box::pin(async move {
            let inner = ClientOptions::new(&self.api_key)
                .endpoint("nonprod:sandbox")
                .unwrap()
                .rest()
                .unwrap();
            let td = inner.auth().request_token(Some(params), None).await?;
            Ok(AuthToken::Details(td))
        })
    }
}

async fn proxy_session(rules: Vec<Rule>) -> (ProxySession, u16) {
    let port = allocate_port();
    let session = ProxySession::create(
        &ProxySession::proxy_base_url(),
        "nonprod:sandbox",
        port,
        rules,
    )
    .await
    .expect("failed to create proxy session — is the uts-proxy available?");
    (session, port)
}

/// A client routed through the proxy with fallback enabled: the primary and
/// the single fallback are both "localhost" on the proxy port; `times: 1`
/// rules ensure only the first request is faulted.
fn proxied_client(api_key: &str, port: u16, with_fallback: bool) -> Rest {
    let mut opts = ClientOptions::with_auth_callback(Arc::new(SandboxTokenCallback {
        api_key: api_key.to_string(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false);
    if with_fallback {
        opts = opts.fallback_hosts(vec!["localhost".to_string()]);
    }
    opts.rest().unwrap()
}

fn rule(match_condition: serde_json::Value, action: serde_json::Value, comment: &str) -> Rule {
    Rule {
        match_condition,
        action,
        times: Some(1),
        comment: Some(comment.to_string()),
    }
}

async fn count_time_requests(session: &ProxySession) -> usize {
    let log = session.get_log().await.expect("proxy log");
    log.iter()
        .filter(|e| {
            e["type"] == "http_request"
                && e["path"].as_str().map(|p| p.contains("/time")).unwrap_or(false)
        })
        .count()
}

// ============================================================================
// UTS: rest/proxy/RSC15l2/timeout-triggers-fallback-0
// ============================================================================

#[tokio::test]
async fn rsc15l2_timeout_triggers_fallback() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/time"}),
        serde_json::json!({"type": "http_delay", "delayMs": 20000}),
        "RSC15l2: Delay first /time request beyond httpRequestTimeout",
    )])
    .await;

    let client = ClientOptions::with_auth_callback(Arc::new(SandboxTokenCallback {
        api_key: app.full_access_key().to_string(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .fallback_hosts(vec!["localhost".to_string()])
    .http_request_timeout(std::time::Duration::from_secs(3))
    .rest()
    .unwrap();

    // Succeeds via fallback retry after the first attempt times out
    let result = client.time().await.expect("time() should succeed via fallback");
    assert!(result.timestamp_millis() > 0);

    assert!(
        count_time_requests(&session).await >= 2,
        "expected at least two /time requests through the proxy"
    );
    let _ = session.close().await;
}

// ============================================================================
// UTS: rest/proxy/RSC15l4/cloudfront-header-fallback-0
// ============================================================================

#[tokio::test]
async fn rsc15l4_cloudfront_header_triggers_fallback() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/time"}),
        serde_json::json!({
            "type": "http_respond",
            "status": 403,
            "body": {"error": {"message": "Forbidden", "code": 40300, "statusCode": 403}},
            "headers": {"Server": "CloudFront"}
        }),
        "RSC15l4: CloudFront 403 on first /time request",
    )])
    .await;

    let client = proxied_client(app.full_access_key(), port, true);
    let result = client.time().await.expect("time() should succeed via fallback");
    assert!(result.timestamp_millis() > 0);

    assert!(count_time_requests(&session).await >= 2);

    // The first response was the injected CloudFront 403
    let log = session.get_log().await.unwrap();
    let first_response = log
        .iter()
        .find(|e| e["type"] == "http_response")
        .expect("an http_response event");
    assert_eq!(first_response["status"], 403);
    let _ = session.close().await;
}

// ============================================================================
// UTS: rest/proxy/RSC15l/unreachable-endpoint-error-0 (no proxy)
// ============================================================================

#[tokio::test]
async fn rsc15l_unreachable_endpoint_error() {
    let app = get_sandbox().await;
    // Nothing listens on this port
    let client = proxied_client(app.full_access_key(), 19999, false);

    let err = client
        .time()
        .await
        .expect_err("time() against a dead endpoint must fail");
    assert!(
        err.status_code.is_some() || err.code.is_some(),
        "error must carry a programmatically usable status/code: {:?}",
        err
    );
}

// ============================================================================
// UTS: rest/proxy/RSC15l/connection-drop-fallback-1
// ============================================================================

#[tokio::test]
async fn rsc15l_connection_drop_retried_on_fallback() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/time"}),
        serde_json::json!({"type": "http_drop"}),
        "Drop TCP connection on first /time request (ECONNRESET)",
    )])
    .await;

    let client = proxied_client(app.full_access_key(), port, true);
    let result = client.time().await.expect("time() should succeed via fallback");
    assert!(result.timestamp_millis() > 0);

    assert!(count_time_requests(&session).await >= 2);
    let _ = session.close().await;
}

// ============================================================================
// UTS: rest/proxy/RSC15l/http-5xx-json-error-parsed-0
// ============================================================================

#[tokio::test]
async fn rsc15l_http_5xx_json_error_parsed() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/time"}),
        serde_json::json!({
            "type": "http_respond",
            "status": 503,
            "body": {"error": {"code": 50300, "statusCode": 503, "message": "Service temporarily unavailable"}}
        }),
        "Return 503 with JSON error body on first /time request",
    )])
    .await;

    // No fallback hosts: endpoint "localhost" disables fallback (REC2c2)
    let client = proxied_client(app.full_access_key(), port, false);
    let err = client.time().await.expect_err("503 with no fallbacks must fail");
    assert_eq!(err.code, Some(50300));
    assert_eq!(err.status_code, Some(503));
    assert!(
        err.message
            .as_deref()
            .unwrap_or("")
            .contains("Service temporarily unavailable"),
        "parsed message expected, got {:?}",
        err.message
    );
    let _ = session.close().await;
}

// ============================================================================
// UTS: rest/proxy/RSC15l/http-5xx-no-json-synthesized-1
// ============================================================================

#[tokio::test]
async fn rsc15l_http_5xx_without_error_body_synthesized() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/time"}),
        serde_json::json!({"type": "http_respond", "status": 503, "body": {}}),
        "Return 503 with empty JSON body on first /time request",
    )])
    .await;

    let client = proxied_client(app.full_access_key(), port, false);
    let err = client.time().await.expect_err("503 with no fallbacks must fail");
    assert_eq!(err.status_code, Some(503));
    let _ = session.close().await;
}

// ============================================================================
// UTS: rest/proxy/RSC15l/http-4xx-not-retried-0
// ============================================================================

#[tokio::test]
async fn rsc15l_http_4xx_not_retried() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/time"}),
        serde_json::json!({
            "type": "http_respond",
            "status": 403,
            "body": {"error": {"code": 40300, "statusCode": 403, "message": "Forbidden"}}
        }),
        "Return 403 with JSON error body on first /time request",
    )])
    .await;

    // Fallback hosts ARE configured — but a 4xx must not trigger fallback
    let client = proxied_client(app.full_access_key(), port, true);
    let err = client.time().await.expect_err("403 must propagate");
    assert_eq!(err.code, Some(40300));
    assert_eq!(err.status_code, Some(403));

    assert_eq!(
        count_time_requests(&session).await,
        1,
        "a 4xx must not be retried on fallback hosts"
    );
    let _ = session.close().await;
}

// ============================================================================
// UTS: rest/proxy/RSL1k4/idempotent-retry-dedup-0
// ============================================================================

#[tokio::test]
async fn rsl1k4_idempotent_publish_retry_dedup() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "method": "POST", "pathContains": "/channels/"}),
        serde_json::json!({
            "type": "http_replace_response",
            "status": 503,
            "body": {"error": {"code": 50300, "statusCode": 503, "message": "Service temporarily unavailable"}}
        }),
        "RSL1k4: Forward first publish to server, then return fake 503 to client",
    )])
    .await;

    let client = proxied_client(app.full_access_key(), port, true);
    let channel_name = format!("test-RSL1k4-idempotent-{}", random_id());
    let channel = client.channels().get(&channel_name);

    // First attempt succeeds server-side but the client sees a 503, retries,
    // and the server deduplicates by the library-generated message id
    channel
        .publish()
        .name("test")
        .string("data")
        .send()
        .await
        .expect("publish should succeed after retry");

    // Verify via history (direct to sandbox, not via proxy) that exactly one
    // copy exists, polling until the result is stable
    let direct = ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .rest()
        .unwrap();
    let direct_channel = direct.channels().get(&channel_name);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut last_len = usize::MAX;
    let matching = loop {
        let history = direct_channel.history().send().await.unwrap();
        let matching: Vec<_> = history
            .items()
            .iter()
            .filter(|m| m.name.as_deref() == Some("test"))
            .cloned()
            .collect();
        if !matching.is_empty() && matching.len() == last_len {
            break matching;
        }
        last_len = matching.len();
        assert!(
            std::time::Instant::now() < deadline,
            "history did not stabilise within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    assert_eq!(
        matching.len(),
        1,
        "server must deduplicate the retried publish by message id"
    );

    // The proxy saw at least two POSTs to /channels/
    let log = session.get_log().await.unwrap();
    let posts = log
        .iter()
        .filter(|e| {
            e["type"] == "http_request"
                && e["method"] == "POST"
                && e["path"].as_str().map(|p| p.contains("/channels/")).unwrap_or(false)
        })
        .count();
    assert!(posts >= 2, "expected the publish to be retried, got {} POSTs", posts);
    let _ = session.close().await;
}

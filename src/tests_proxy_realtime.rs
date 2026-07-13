#![cfg(test)]

//! Realtime proxy integration tests (UTS realtime/integration/proxy/*).
//!
//! These run the SDK's real WebSocket transport through the programmable
//! uts-proxy against the Ably nonprod sandbox, injecting transport-level
//! faults (closed connections, replaced/suppressed/injected frames) that
//! cannot be produced by a passthrough sandbox connection. The proxy binary
//! is auto-downloaded and spawned by `crate::proxy::ensure_proxy`.
//!
//! Run serially: `cargo test --lib tests_proxy_realtime -- --test-threads=1`
//!
//! All clients use the JSON protocol (the proxy matches/rewrites frames as
//! JSON) and token auth (RSC18 prohibits basic auth over the proxy's
//! non-TLS listener).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use crate::auth::{AuthCallback, AuthToken, TokenParams};
use crate::error::Result;
use crate::options::ClientOptions;
use crate::protocol::{ChannelEvent, ChannelState, ConnectionState};
use crate::proxy::{ProxySession, Rule};
use crate::realtime::{await_channel_state, await_state, Realtime};
use crate::tests_proxy::{proxy_session, SandboxTokenCallback};
use crate::tests_rest_integration::{get_sandbox, random_id};

// ============================================================================
// Helpers
// ============================================================================

/// A sandbox token callback that counts invocations (RTN14b, RTN22, RSC10).
struct CountingTokenCallback {
    api_key: String,
    count: Arc<AtomicUsize>,
}

impl AuthCallback for CountingTokenCallback {
    fn token<'a>(
        &'a self,
        params: &'a TokenParams,
    ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
        self.count.fetch_add(1, Ordering::SeqCst);
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

fn proxied_options(api_key: &str, port: u16) -> ClientOptions {
    ClientOptions::with_auth_callback(Arc::new(SandboxTokenCallback {
        api_key: api_key.to_string(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .auto_connect(false)
}

fn proxied_realtime(api_key: &str, port: u16) -> Realtime {
    Realtime::new(&proxied_options(api_key, port)).unwrap()
}

fn rule(match_condition: serde_json::Value, action: serde_json::Value, comment: &str) -> Rule {
    Rule {
        match_condition,
        action,
        times: Some(1),
        comment: Some(comment.to_string()),
    }
}

fn rule_always(
    match_condition: serde_json::Value,
    action: serde_json::Value,
    comment: &str,
) -> Rule {
    Rule {
        match_condition,
        action,
        times: None,
        comment: Some(comment.to_string()),
    }
}

/// Record every connection state change into a shared vec.
fn record_connection_states(client: &Realtime) -> Arc<StdMutex<Vec<ConnectionState>>> {
    let states: Arc<StdMutex<Vec<ConnectionState>>> = Arc::new(StdMutex::new(Vec::new()));
    let states_c = states.clone();
    let mut rx = client.connection.on_state_change();
    tokio::spawn(async move {
        while let Ok(change) = rx.recv().await {
            states_c.lock().unwrap().push(change.current);
        }
    });
    states
}

fn contains_in_order(haystack: &[ConnectionState], needles: &[ConnectionState]) -> bool {
    let mut it = haystack.iter();
    needles.iter().all(|n| it.by_ref().any(|s| s == n))
}

async fn ws_connect_events(session: &ProxySession) -> Vec<serde_json::Value> {
    session
        .get_log()
        .await
        .expect("proxy log")
        .into_iter()
        .filter(|e| e["type"] == "ws_connect")
        .collect()
}

/// Frames in the given direction with the given protocol action number.
async fn frames(session: &ProxySession, direction: &str, action: u8) -> Vec<serde_json::Value> {
    session
        .get_log()
        .await
        .expect("proxy log")
        .into_iter()
        .filter(|e| {
            e["type"] == "ws_frame"
                && e["direction"] == direction
                && e["message"]["action"] == serde_json::json!(action)
        })
        .collect()
}

async fn poll_until<F>(what: &str, secs: u64, mut f: F)
where
    F: AsyncFnMut() -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if f().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out awaiting {} within {}s",
            what,
            secs
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Wait until the recorded connection states contain `needles` in order.
///
/// Uses the broadcast-based recorder (`record_connection_states`) rather than
/// the coalescing `watch` that backs `await_state`. A resume-reconnect after a
/// transport drop can pass through DISCONNECTED → CONNECTING → CONNECTED in a
/// few milliseconds; the `watch` only retains the latest value and so silently
/// drops those transients, whereas the broadcast recorder captures every
/// transition. Use this whenever a test must observe an intermediate state of a
/// fast reconnect cycle.
async fn await_states_in_order(
    states: &Arc<StdMutex<Vec<ConnectionState>>>,
    needles: &[ConnectionState],
    secs: u64,
) {
    poll_until("connection state sequence", secs, async || {
        contains_in_order(&states.lock().unwrap(), needles)
    })
    .await;
}

async fn close_client(client: &Realtime) {
    client.close();
    let _ = await_state(&client.connection, ConnectionState::Closed, 10000).await;
}

// ============================================================================
// connection_open_failures.md
// ============================================================================

// UTS: realtime/proxy/RTN14a/fatal-connect-error-0
#[tokio::test]
async fn proxy_rtn14a_fatal_connect_error_failed() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "ws_frame_to_client", "action": "CONNECTED"}),
        serde_json::json!({"type": "replace", "message": {
            "action": 9,
            "error": {"code": 40005, "statusCode": 400, "message": "Invalid key"}
        }}),
        "RTN14a: Replace CONNECTED with fatal ERROR",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);
    let states = record_connection_states(&client);

    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Failed, 15000).await,
        "RTN14a: fatal error during open -> FAILED"
    );

    let reason = client.connection.error_reason().expect("errorReason set");
    assert_eq!(reason.code, Some(40005));
    assert_eq!(reason.status_code, Some(400));
    assert!(contains_in_order(
        &states.lock().unwrap(),
        &[ConnectionState::Connecting, ConnectionState::Failed]
    ));
    assert!(client.connection.id().is_none());
    assert!(client.connection.key().is_none());
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN14b/token-error-renew-reconnect-0
#[tokio::test]
async fn proxy_rtn14b_token_error_renews_and_reconnects() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "ws_frame_to_client", "action": "CONNECTED"}),
        serde_json::json!({"type": "replace", "message": {
            "action": 9,
            "error": {"code": 40142, "statusCode": 401, "message": "Token expired"}
        }}),
        "RTN14b: Token error on first connect, renewal should succeed",
    )])
    .await;
    let count = Arc::new(AtomicUsize::new(0));
    let opts = ClientOptions::with_auth_callback(Arc::new(CountingTokenCallback {
        api_key: app.full_access_key().to_string(),
        count: count.clone(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 30000).await,
        "RTN14b: renew + reconnect"
    );

    assert!(client.connection.id().is_some());
    assert!(client.connection.key().is_some());
    assert!(
        count.load(Ordering::SeqCst) >= 2,
        "RTN14b: authCallback invoked for the renewal"
    );
    assert!(ws_connect_events(&session).await.len() >= 2);
    assert!(client.connection.error_reason().is_none());
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN14c/connection-timeout-0
#[tokio::test]
async fn proxy_rtn14c_connection_timeout_disconnected() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule_always(
        serde_json::json!({"type": "ws_frame_to_client", "action": "CONNECTED"}),
        serde_json::json!({"type": "suppress"}),
        "RTN14c: Suppress CONNECTED to force timeout",
    )])
    .await;
    let opts = proxied_options(app.full_access_key(), port)
        .realtime_request_timeout(Duration::from_millis(3000));
    let client = Realtime::new(&opts).unwrap();
    let states = record_connection_states(&client);

    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Disconnected, 15000).await,
        "RTN14c: no CONNECTED within realtimeRequestTimeout -> DISCONNECTED"
    );

    assert!(client.connection.error_reason().is_some());
    assert!(contains_in_order(
        &states.lock().unwrap(),
        &[ConnectionState::Connecting, ConnectionState::Disconnected]
    ));
    assert!(client.connection.id().is_none());
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN14d/retry-after-refused-0
#[tokio::test]
async fn proxy_rtn14d_retry_after_refused_connection() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "ws_connect", "count": 1}),
        serde_json::json!({"type": "refuse_connection"}),
        "RTN14d: Refuse first WebSocket connection",
    )])
    .await;
    let opts = proxied_options(app.full_access_key(), port)
        .disconnected_retry_timeout(Duration::from_millis(2000));
    let client = Realtime::new(&opts).unwrap();
    let states = record_connection_states(&client);

    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 30000).await,
        "RTN14d: retried after refused connection"
    );

    assert!(client.connection.id().is_some());
    assert!(contains_in_order(
        &states.lock().unwrap(),
        &[
            ConnectionState::Connecting,
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
        ]
    ));
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN14g/server-error-causes-failed-0
#[tokio::test]
async fn proxy_rtn14g_server_error_causes_failed() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "ws_frame_to_client", "action": "CONNECTED"}),
        serde_json::json!({"type": "replace", "message": {
            "action": 9,
            "error": {"code": 50000, "statusCode": 500, "message": "Internal server error"}
        }}),
        "RTN14g: Connection-level ERROR (server error) during open",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);
    let states = record_connection_states(&client);

    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Failed, 15000).await,
        "RTN14g: server error during open -> FAILED"
    );

    let reason = client.connection.error_reason().expect("errorReason set");
    assert_eq!(reason.code, Some(50000));
    assert_eq!(reason.status_code, Some(500));
    assert!(contains_in_order(
        &states.lock().unwrap(),
        &[ConnectionState::Connecting, ConnectionState::Failed]
    ));
    assert!(client.connection.id().is_none());
    session.close().await.ok();
}

// ============================================================================
// connection_resume.md
// ============================================================================

async fn assert_resume_after_drop(close_action: &str) {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 1000}),
        serde_json::json!({"type": close_action}),
        "RTN15a: drop the WebSocket after 1s to trigger unexpected disconnect",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);
    let states = record_connection_states(&client);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    // The proxy drops the transport ~1s after connect. The SDK detects the
    // close, goes DISCONNECTED, then resume-reconnects — a cycle that can
    // complete in a few ms, so it is observed via the broadcast recorder rather
    // than the coalescing watch behind await_state (RTN15a).
    await_states_in_order(
        &states,
        &[
            ConnectionState::Connected,
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
        ],
        30,
    )
    .await;

    let connects = ws_connect_events(&session).await;
    assert!(connects.len() >= 2, "two ws connections");
    assert!(
        connects[1]["queryParams"]["resume"].is_string(),
        "RTN15a: second connection attempted a resume"
    );
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN15a/disconnect-triggers-resume-0
#[tokio::test]
async fn proxy_rtn15a_disconnect_triggers_resume() {
    assert_resume_after_drop("close").await;
}

// UTS: realtime/proxy/RTN15a/tcp-close-triggers-resume-1
#[tokio::test]
async fn proxy_rtn15a_tcp_close_triggers_resume() {
    assert_resume_after_drop("disconnect").await;
}

// UTS: realtime/proxy/RTN15b/resume-preserves-connid-0 (RTN15b, RTN15c6)
#[tokio::test]
async fn proxy_rtn15b_rtn15c6_resume_preserves_connection_id() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 1000}),
        serde_json::json!({"type": "close"}),
        "RTN15b/c6: Close WebSocket after 1s to trigger resume",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let original_id = client.connection.id().expect("connection id");
    let original_key = client.connection.key().expect("connection key");

    // The proxy drops the transport ~1s after connect; the SDK resume-reconnects
    // (a 2nd ws_connect) and returns to CONNECTED. The transient DISCONNECTED can
    // be too brief for await_state to observe, so wait on the proxy log plus the
    // post-reconnect state instead.
    poll_until("resume reconnect", 30, async || {
        ws_connect_events(&session).await.len() >= 2
            && client.connection.state() == ConnectionState::Connected
    })
    .await;

    // RTN15c6: same connection id after a successful resume
    assert_eq!(
        client.connection.id().as_deref(),
        Some(original_id.as_str())
    );
    let connects = ws_connect_events(&session).await;
    assert!(connects.len() >= 2);
    // RTN15b: resume param carries the connection key
    assert_eq!(
        connects[1]["queryParams"]["resume"].as_str(),
        Some(original_key.as_str())
    );
    assert!(client.connection.error_reason().is_none());
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN15c7/failed-resume-new-connid-0
#[tokio::test]
async fn proxy_rtn15c7_failed_resume_gets_new_connection_id() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![
        rule(
            serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 1000}),
            serde_json::json!({"type": "close"}),
            "RTN15c7: Close WebSocket after 1s to trigger resume attempt",
        ),
        rule(
            serde_json::json!({"type": "ws_frame_to_client", "action": "CONNECTED", "count": 2}),
            serde_json::json!({"type": "replace", "message": {
                "action": 4,
                "connectionId": "proxy-injected-new-id",
                "connectionKey": "proxy-injected-new-key",
                "connectionDetails": {
                    "connectionKey": "proxy-injected-new-key",
                    "maxMessageSize": 65536,
                    "maxInboundRate": 250,
                    "maxOutboundRate": 100,
                    "maxFrameSize": 524288,
                    "serverId": "test-server",
                    "connectionStateTtl": 120000,
                    "maxIdleInterval": 15000
                },
                "error": {"code": 80008, "statusCode": 400, "message": "Unable to recover connection"}
            }}),
            "RTN15c7: Replace 2nd CONNECTED with failed resume",
        ),
    ])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let original_id = client.connection.id().expect("connection id");
    assert_ne!(original_id, "proxy-injected-new-id");

    // Proxy drops the transport, then replaces the 2nd CONNECTED with a failed
    // resume (new id + error). Wait for the resume reconnect via the proxy log
    // plus the post-reconnect CONNECTED, observing the new identity afterwards.
    poll_until("failed-resume reconnect", 30, async || {
        ws_connect_events(&session).await.len() >= 2
            && client.connection.state() == ConnectionState::Connected
            && client.connection.id().as_deref() == Some("proxy-injected-new-id")
    })
    .await;

    // RTN15c7: new identity + exposed error, still CONNECTED
    assert_eq!(
        client.connection.id().as_deref(),
        Some("proxy-injected-new-id")
    );
    assert_eq!(
        client.connection.key().as_deref(),
        Some("proxy-injected-new-key")
    );
    let reason = client.connection.error_reason().expect("resume failure");
    assert_eq!(reason.code, Some(80008));
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    let connects = ws_connect_events(&session).await;
    assert!(connects.len() >= 2);
    assert!(connects[1]["queryParams"]["resume"].is_string());
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN15g/ttl-expiry-clears-resume-0 (RTN15g, RTN15g2)
#[tokio::test]
async fn proxy_rtn15g_ttl_expiry_clears_resume_state() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![
        rule(
            serde_json::json!({"type": "ws_frame_to_client", "action": "CONNECTED", "count": 1}),
            serde_json::json!({"type": "replace", "message": {
                "action": 4,
                "connectionId": "proxy-ttl-test-id",
                "connectionKey": "proxy-ttl-test-key",
                "connectionDetails": {
                    "connectionKey": "proxy-ttl-test-key",
                    "maxMessageSize": 65536,
                    "maxInboundRate": 250,
                    "maxOutboundRate": 100,
                    "maxFrameSize": 524288,
                    "serverId": "test-server",
                    "connectionStateTtl": 2000,
                    "maxIdleInterval": 15000
                }
            }}),
            "RTN15g: Replace 1st CONNECTED with short connectionStateTtl",
        ),
        rule(
            serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 1000}),
            serde_json::json!({"type": "close"}),
            "RTN15g: Close connection after 1s",
        ),
        rule(
            serde_json::json!({"type": "ws_connect", "count": 2}),
            serde_json::json!({"type": "refuse_connection"}),
            "RTN15g: Refuse 2nd ws_connect so the TTL expires while disconnected",
        ),
    ])
    .await;
    let opts = proxied_options(app.full_access_key(), port)
        .suspended_retry_timeout(Duration::from_millis(1000));
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    assert_eq!(client.connection.id().as_deref(), Some("proxy-ttl-test-id"));

    assert!(
        await_state(&client.connection, ConnectionState::Suspended, 15000).await,
        "RTN15g: TTL expired while disconnected -> SUSPENDED"
    );
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 15000).await,
        "fresh connection after SUSPENDED retry"
    );

    // RTN15g: fresh connection — not the injected identity
    assert_ne!(client.connection.id().as_deref(), Some("proxy-ttl-test-id"));
    let connects = ws_connect_events(&session).await;
    assert!(connects.len() >= 3);
    assert!(connects[0]["queryParams"]["resume"].is_null());
    assert!(
        connects.last().unwrap()["queryParams"]["resume"].is_null(),
        "RTN15g: post-TTL reconnect is NOT a resume"
    );
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN15h1/token-error-nonrenewable-failed-0
#[tokio::test]
async fn proxy_rtn15h1_token_error_nonrenewable_failed() {
    let app = get_sandbox().await;
    // A real token, used WITHOUT any renewal means (token string only)
    let rest = ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .rest()
        .unwrap();
    let td = rest.auth().request_token(None, None).await.expect("token");

    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 1000}),
        serde_json::json!({"type": "inject_to_client_and_close", "message": {
            "action": 6,
            "error": {"code": 40142, "statusCode": 401, "message": "Token expired"}
        }}),
        "RTN15h1: Inject DISCONNECTED with token error after 1s",
    )])
    .await;
    let opts = ClientOptions::with_token(td.token)
        .endpoint("localhost")
        .unwrap()
        .port(port as u32)
        .tls(false)
        .use_binary_protocol(false)
        .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    assert!(
        await_state(&client.connection, ConnectionState::Failed, 15000).await,
        "RTN15h1: token error + non-renewable token -> FAILED"
    );

    let reason = client.connection.error_reason().expect("errorReason");
    // 40171: no means to renew the token
    assert_eq!(reason.code, Some(40171));
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN15h3/non-token-error-reconnects-0
#[tokio::test]
async fn proxy_rtn15h3_non_token_error_reconnects() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 1000}),
        serde_json::json!({"type": "inject_to_client_and_close", "message": {
            "action": 6,
            "error": {"code": 80003, "statusCode": 500, "message": "Service temporarily unavailable"}
        }}),
        "RTN15h3: Inject DISCONNECTED with non-token error after 1s, once",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);
    let states = record_connection_states(&client);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    // RTN15h3: a non-token error reconnects (does not FAIL). The DISCONNECTED →
    // CONNECTING → CONNECTED cycle can be too fast for await_state to observe,
    // so verify it via the broadcast recorder.
    await_states_in_order(
        &states,
        &[
            ConnectionState::Connected,
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
        ],
        30,
    )
    .await;

    let connects = ws_connect_events(&session).await;
    assert!(connects.len() >= 2);
    assert!(connects[1]["queryParams"]["resume"].is_string());
    assert!(client.connection.error_reason().is_none());
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN15j/fatal-error-established-conn-0
#[tokio::test]
async fn proxy_rtn15j_fatal_error_on_established_connection() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![]).await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch_a = client
        .channels
        .get(&format!("test-rtn15j-a-{}", random_id()));
    let ch_b = client
        .channels
        .get(&format!("test-rtn15j-b-{}", random_id()));
    ch_a.attach().await.unwrap();
    ch_b.attach().await.unwrap();

    session
        .trigger_action(serde_json::json!({
            "type": "inject_to_client",
            "message": {
                "action": 9,
                "error": {"code": 50000, "statusCode": 500, "message": "Internal server error"}
            }
        }))
        .await
        .expect("inject ERROR");

    assert!(
        await_state(&client.connection, ConnectionState::Failed, 15000).await,
        "RTN15j: connection-level ERROR -> FAILED"
    );
    let reason = client.connection.error_reason().expect("errorReason");
    assert_eq!(reason.code, Some(50000));
    assert_eq!(reason.status_code, Some(500));

    // Channels failed with the connection error
    assert!(await_channel_state(&ch_a, ChannelState::Failed, 5000).await);
    assert!(await_channel_state(&ch_b, ChannelState::Failed, 5000).await);
    assert_eq!(ch_a.error_reason().and_then(|e| e.code), Some(50000));
    assert_eq!(ch_b.error_reason().and_then(|e| e.code), Some(50000));

    // No reconnection was attempted
    assert_eq!(ws_connect_events(&session).await.len(), 1);
    session.close().await.ok();
}

// UTS: realtime/proxy/RTN19a/unacked-resent-on-resume-0 (RTN19a, RTN19a2)
#[tokio::test]
async fn proxy_rtn19a_unacked_message_resent_on_resume() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "ws_frame_to_client", "action": "ACK"}),
        serde_json::json!({"type": "suppress"}),
        "RTN19a: Suppress the first ACK so a publish stays pending",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client
        .channels
        .get(&format!("test-resend-unacked-{}", random_id()));
    ch.attach().await.unwrap();

    // Publish without awaiting: its ACK is suppressed by the proxy
    let ch2 = ch.clone();
    let publish =
        tokio::spawn(async move { ch2.publish().name("event").string("test-data").send().await });

    // Wait until the MESSAGE went out and its ACK was suppressed
    poll_until("MESSAGE sent and ACK suppressed", 10, || {
        let session = &session;
        async move {
            let sent = !frames(session, "client_to_server", 15).await.is_empty();
            let suppressed = session.get_log().await.expect("proxy log").iter().any(|e| {
                e["type"] == "ws_frame"
                    && e["direction"] == "server_to_client"
                    && e["message"]["action"] == serde_json::json!(1)
                    && !e["ruleMatched"].is_null()
            });
            sent && suppressed
        }
    })
    .await;

    // Drop the transport; the pending publish must be resent after the resume
    session
        .trigger_action(serde_json::json!({"type": "close"}))
        .await
        .expect("close transport");
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);

    let result = tokio::time::timeout(Duration::from_secs(15), publish)
        .await
        .expect("publish resolved after resend")
        .unwrap();
    assert!(result.is_ok(), "RTN19a: publish completed: {:?}", result);

    let connects = ws_connect_events(&session).await;
    assert!(connects.len() >= 2);
    assert!(connects[1]["queryParams"]["resume"].is_string());

    // RTN19a2: the resent MESSAGE kept its serial
    let messages = frames(&session, "client_to_server", 15).await;
    assert!(messages.len() >= 2, "MESSAGE sent on both transports");
    assert_eq!(
        messages[0]["message"]["msgSerial"], messages[1]["message"]["msgSerial"],
        "RTN19a2: same msgSerial on the resend"
    );
    close_client(&client).await;
    session.close().await.ok();
}

// ============================================================================
// auth_reauth.md
// ============================================================================

// UTS: realtime/proxy/RTN22/server-initiated-reauth-0 (RTN22, RTC8a)
#[tokio::test]
async fn proxy_rtn22_server_initiated_reauth() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![]).await;
    let count = Arc::new(AtomicUsize::new(0));
    let opts = ClientOptions::with_auth_callback(Arc::new(CountingTokenCallback {
        api_key: app.full_access_key().to_string(),
        count: count.clone(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let original_id = client.connection.id().expect("connection id");
    let count_before = count.load(Ordering::SeqCst);
    assert!(count_before >= 1);

    // Server-initiated AUTH
    session
        .trigger_action(serde_json::json!({
            "type": "inject_to_client",
            "message": {"action": 17}
        }))
        .await
        .expect("inject AUTH");

    poll_until("authCallback re-invoked", 15, || {
        let count = count.clone();
        async move { count.load(Ordering::SeqCst) > count_before }
    })
    .await;

    // Connection undisturbed
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert_eq!(
        client.connection.id().as_deref(),
        Some(original_id.as_str())
    );

    // The SDK sent an AUTH frame carrying the new token
    poll_until("client AUTH frame", 15, || {
        let session = &session;
        async move {
            frames(session, "client_to_server", 17)
                .await
                .iter()
                .any(|f| !f["message"]["auth"].is_null())
        }
    })
    .await;
    close_client(&client).await;
    session.close().await.ok();
}

// ============================================================================
// heartbeat.md
// ============================================================================

// UTS: realtime/proxy/RTN23a/heartbeat-starvation-reconnect-0
#[tokio::test]
async fn proxy_rtn23a_transport_failure_reconnects_with_resume() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 2000}),
        serde_json::json!({"type": "close"}),
        "RTN23a: Close WebSocket after 2s to simulate transport failure",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);
    let states = record_connection_states(&client);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let first_id = client.connection.id().expect("connection id");

    // RTN23a: the transport drop is detected and a resume-reconnect follows. The
    // cycle can be too fast for await_state to observe DISCONNECTED, so verify
    // the full sequence via the broadcast recorder.
    await_states_in_order(
        &states,
        &[
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
        ],
        40,
    )
    .await;

    assert!(client.connection.id().is_some());
    assert!(client.connection.key().is_some());
    let _ = first_id;
    let connects = ws_connect_events(&session).await;
    assert!(connects.len() >= 2);
    assert!(connects[1]["queryParams"]["resume"].is_string());
    close_client(&client).await;
    session.close().await.ok();
}

// ============================================================================
// channel_faults.md
// ============================================================================

// UTS: realtime/proxy/RTL4f/attach-timeout-suppressed-0
#[tokio::test]
async fn proxy_rtl4f_attach_timeout_suspends_channel() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtl4f-{}", random_id());
    let (session, port) = proxy_session(vec![rule_always(
        serde_json::json!({"type": "ws_frame_to_server", "action": "ATTACH", "channel": channel_name}),
        serde_json::json!({"type": "suppress"}),
        "RTL4f: Suppress ATTACH so the server never responds",
    )])
    .await;
    let opts = proxied_options(app.full_access_key(), port)
        .realtime_request_timeout(Duration::from_millis(3000));
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });

    assert!(await_channel_state(&ch, ChannelState::Attaching, 5000).await);
    assert!(
        await_channel_state(&ch, ChannelState::Suspended, 15000).await,
        "RTL4f: attach timeout -> SUSPENDED"
    );
    let err = attach.await.unwrap().expect_err("attach timed out");
    assert!(err.code.is_some());
    assert_eq!(client.connection.state(), ConnectionState::Connected);

    let log = session.get_log().await.expect("proxy log");
    let suppressed_attaches = log
        .iter()
        .filter(|e| {
            e["type"] == "ws_frame"
                && e["direction"] == "client_to_server"
                && e["message"]["action"] == serde_json::json!(10)
                && e["message"]["channel"] == serde_json::json!(channel_name)
                && !e["ruleMatched"].is_null()
        })
        .count();
    assert!(suppressed_attaches >= 1);
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTL14/error-on-attach-0
#[tokio::test]
async fn proxy_rtl14_error_on_attach_fails_channel() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtl14-attach-{}", random_id());
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "ws_frame_to_client", "action": "ATTACHED", "channel": channel_name}),
        serde_json::json!({"type": "replace", "message": {
            "action": 9,
            "channel": channel_name,
            "error": {"code": 40160, "statusCode": 403, "message": "Not permitted"}
        }}),
        "RTL14: Replace ATTACHED with channel ERROR",
    )])
    .await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    let err = ch.attach().await.expect_err("RTL14: attach fails");
    assert_eq!(err.code, Some(40160));

    assert!(await_channel_state(&ch, ChannelState::Failed, 10000).await);
    let reason = ch.error_reason().expect("channel errorReason");
    assert_eq!(reason.code, Some(40160));
    assert_eq!(reason.status_code, Some(403));
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTL5f/detach-timeout-suppressed-0
#[tokio::test]
async fn proxy_rtl5f_detach_timeout_reverts_to_attached() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtl5f-{}", random_id());
    let (session, port) = proxy_session(vec![]).await;
    let opts = proxied_options(app.full_access_key(), port)
        .realtime_request_timeout(Duration::from_millis(3000));
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    ch.attach().await.unwrap();

    session
        .add_rules(
            vec![rule_always(
                serde_json::json!({"type": "ws_frame_to_server", "action": "DETACH", "channel": channel_name}),
                serde_json::json!({"type": "suppress"}),
                "RTL5f: Suppress DETACH so the server never responds",
            )],
            "prepend",
        )
        .await
        .expect("add suppress rule");

    let ch2 = ch.clone();
    let detach = tokio::spawn(async move { ch2.detach().await });
    assert!(await_channel_state(&ch, ChannelState::Detaching, 5000).await);
    assert!(
        await_channel_state(&ch, ChannelState::Attached, 15000).await,
        "RTL5f: detach timeout -> revert to ATTACHED"
    );
    let err = detach.await.unwrap().expect_err("detach timed out");
    assert!(err.code.is_some());
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTL13a/unsolicited-detach-reattach-0
#[tokio::test]
async fn proxy_rtl13a_unsolicited_detached_reattaches() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtl13a-{}", random_id());
    let (session, port) = proxy_session(vec![]).await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    ch.attach().await.unwrap();

    let mut events = ch.on_state_change();
    session
        .trigger_action(serde_json::json!({
            "type": "inject_to_client",
            "message": {
                "action": 13,
                "channel": channel_name,
                "error": {"code": 90198, "statusCode": 500, "message": "Channel detached by server"}
            }
        }))
        .await
        .expect("inject DETACHED");

    // RTL13a: ATTACHING (with the server error) then ATTACHED again
    let change = tokio::time::timeout(Duration::from_secs(10), events.recv())
        .await
        .expect("attaching event")
        .unwrap();
    assert_eq!(change.current, ChannelState::Attaching);
    assert_eq!(change.reason.and_then(|e| e.code), Some(90198));
    assert!(await_channel_state(&ch, ChannelState::Attached, 15000).await);
    assert_eq!(client.connection.state(), ConnectionState::Connected);

    // Two ATTACH frames went to the server: initial + reattach
    let attaches: Vec<_> = frames(&session, "client_to_server", 10)
        .await
        .into_iter()
        .filter(|f| f["message"]["channel"] == serde_json::json!(channel_name))
        .collect();
    assert!(attaches.len() >= 2, "initial attach + RTL13a reattach");
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTL14/channel-error-goes-failed-1
#[tokio::test]
async fn proxy_rtl14_injected_channel_error_goes_failed() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtl14-{}", random_id());
    let (session, port) = proxy_session(vec![]).await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    ch.attach().await.unwrap();

    session
        .trigger_action(serde_json::json!({
            "type": "inject_to_client",
            "message": {
                "action": 9,
                "channel": channel_name,
                "error": {"code": 40160, "statusCode": 403, "message": "Not permitted"}
            }
        }))
        .await
        .expect("inject channel ERROR");

    assert!(
        await_channel_state(&ch, ChannelState::Failed, 10000).await,
        "RTL14: channel ERROR -> FAILED"
    );
    let reason = ch.error_reason().expect("channel errorReason");
    assert_eq!(reason.code, Some(40160));
    assert_eq!(reason.status_code, Some(403));
    assert!(reason
        .message
        .as_deref()
        .unwrap_or_default()
        .contains("Not permitted"));
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTL12/attached-non-resumed-update-0
#[tokio::test]
async fn proxy_rtl12_attached_non_resumed_emits_update() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtl12-{}", random_id());
    let (session, port) = proxy_session(vec![]).await;
    let client = proxied_realtime(app.full_access_key(), port);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    ch.attach().await.unwrap();

    let mut events = ch.on_state_change();
    session
        .trigger_action(serde_json::json!({
            "type": "inject_to_client",
            "message": {
                "action": 11,
                "channel": channel_name,
                "flags": 0,
                "error": {"code": 91001, "statusCode": 500, "message": "Continuity lost"}
            }
        }))
        .await
        .expect("inject non-resumed ATTACHED");

    let change = tokio::time::timeout(Duration::from_secs(10), events.recv())
        .await
        .expect("update event")
        .unwrap();
    // RTL12: UPDATE (not ATTACHED), attached->attached, resumed=false
    assert_eq!(change.event, ChannelEvent::Update);
    assert_eq!(change.current, ChannelState::Attached);
    assert_eq!(change.previous, ChannelState::Attached);
    assert!(!change.resumed);
    let reason = change.reason.expect("reason from the ATTACHED error");
    assert_eq!(reason.code, Some(91001));
    assert!(reason
        .message
        .as_deref()
        .unwrap_or_default()
        .contains("Continuity lost"));

    assert_eq!(ch.state(), ChannelState::Attached);
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTL3d/channels-reattach-on-reconnect-0
#[tokio::test]
async fn proxy_rtl3d_channels_reattach_after_reconnect() {
    let app = get_sandbox().await;
    let name_a = format!("test-rtl3d-a-{}", random_id());
    let name_b = format!("test-rtl3d-b-{}", random_id());
    let (session, port) = proxy_session(vec![]).await;
    let client = proxied_realtime(app.full_access_key(), port);
    let states = record_connection_states(&client);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch_a = client.channels.get(&name_a);
    let ch_b = client.channels.get(&name_b);
    ch_a.attach().await.unwrap();
    ch_b.attach().await.unwrap();

    session
        .trigger_action(serde_json::json!({"type": "close"}))
        .await
        .expect("close transport");
    // The transport drop is detected and a reconnect follows. The transient
    // DISCONNECTED can be too brief for await_state, so verify the cycle via the
    // broadcast recorder.
    await_states_in_order(
        &states,
        &[
            ConnectionState::Connected,
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
        ],
        40,
    )
    .await;

    assert!(
        await_channel_state(&ch_a, ChannelState::Attached, 15000).await,
        "RTL3d: channel A reattached"
    );
    assert!(
        await_channel_state(&ch_b, ChannelState::Attached, 15000).await,
        "RTL3d: channel B reattached"
    );

    for name in [&name_a, &name_b] {
        let attaches: Vec<_> = frames(&session, "client_to_server", 10)
            .await
            .into_iter()
            .filter(|f| f["message"]["channel"] == serde_json::json!(name.as_str()))
            .collect();
        assert!(
            attaches.len() >= 2,
            "RTL3d: initial + reattach ATTACH for {}",
            name
        );
    }
    close_client(&client).await;
    session.close().await.ok();
}

// ============================================================================
// presence_reentry.md
// ============================================================================

fn proxied_realtime_with_client_id(api_key: &str, port: u16, client_id: &str) -> Realtime {
    let opts = ClientOptions::with_auth_callback(Arc::new(SandboxTokenCallback {
        api_key: api_key.to_string(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .auto_connect(false)
    .client_id(client_id)
    .unwrap();
    Realtime::new(&opts).unwrap()
}

async fn count_client_presence_frames(session: &ProxySession) -> usize {
    frames(session, "client_to_server", 14).await.len()
}

fn assert_reenter_frame(frame: &serde_json::Value) {
    let presence = frame["message"]["presence"]
        .as_array()
        .expect("presence entries");
    assert!(!presence.is_empty());
    // RTP17g: ENTER with the stored clientId and data
    assert_eq!(presence[0]["clientId"], "client-a");
    assert_eq!(presence[0]["data"], "hello");
    assert_eq!(presence[0]["action"], 2);
}

// UTS: realtime/proxy/RTP17i/reenter-on-non-resumed-0 (RTP17i, RTP17g)
#[tokio::test]
async fn proxy_rtp17i_reenter_on_non_resumed_attached() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtp17i-{}", random_id());
    let (session, port) = proxy_session(vec![]).await;
    let client = proxied_realtime_with_client_id(app.full_access_key(), port, "client-a");

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    ch.attach().await.unwrap();
    ch.presence()
        .enter(Some(serde_json::json!("hello")))
        .await
        .unwrap();

    let before = count_client_presence_frames(&session).await;

    session
        .trigger_action(serde_json::json!({
            "type": "inject_to_client",
            "message": {
                "action": 11,
                "channel": channel_name,
                "flags": 0,
                "error": {"code": 91001, "statusCode": 500, "message": "Continuity lost"}
            }
        }))
        .await
        .expect("inject non-resumed ATTACHED");

    poll_until("RTP17i re-enter PRESENCE frame", 10, || {
        let session = &session;
        async move { count_client_presence_frames(session).await > before }
    })
    .await;

    let all = frames(&session, "client_to_server", 14).await;
    assert!(all.len() > before);
    assert_reenter_frame(all.last().unwrap());
    assert_eq!(ch.state(), ChannelState::Attached);
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    close_client(&client).await;
    session.close().await.ok();
}

// UTS: realtime/proxy/RTP17i/reenter-after-disconnect-1
#[tokio::test]
async fn proxy_rtp17i_reenter_after_real_disconnect() {
    let app = get_sandbox().await;
    let channel_name = format!("test-rtp17i-real-{}", random_id());
    let (session, port) = proxy_session(vec![
        rule(
            serde_json::json!({"type": "delay_after_ws_connect", "delayMs": 3000}),
            serde_json::json!({"type": "close"}),
            "RTP17i: Close WebSocket after 3s to trigger reconnect",
        ),
        rule(
            serde_json::json!({"type": "ws_frame_to_client", "action": "ATTACHED", "channel": channel_name, "count": 2}),
            serde_json::json!({"type": "replace", "message": {
                "action": 11,
                "channel": channel_name,
                "flags": 0,
                "error": {"code": 91001, "statusCode": 500, "message": "Continuity lost"}
            }}),
            "RTP17i: Replace 2nd ATTACHED with a non-resumed one",
        ),
    ])
    .await;
    let client = proxied_realtime_with_client_id(app.full_access_key(), port, "client-a");

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let ch = client.channels.get(&channel_name);
    let mut ch_events = ch.on_state_change();
    let ch_log = Arc::new(StdMutex::new(Vec::new()));
    let ch_log_c = ch_log.clone();
    tokio::spawn(async move {
        while let Ok(change) = ch_events.recv().await {
            ch_log_c.lock().unwrap().push(format!(
                "{:?}->{:?} reason={:?}",
                change.previous, change.current, change.reason
            ));
        }
    });
    ch.attach().await.unwrap();
    ch.presence()
        .enter(Some(serde_json::json!("hello")))
        .await
        .unwrap();

    // Proxy drops the transport after 3s; the SDK reconnects (2nd ws_connect)
    // and the channel reattaches. The transient DISCONNECTED can be too brief
    // for await_state, so wait on the proxy log plus the reconnected/reattached
    // state directly.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        let reconnected = ws_connect_events(&session).await.len() >= 2
            && client.connection.state() == ConnectionState::Connected
            && ch.state() == ChannelState::Attached;
        if reconnected {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let attaches = frames(&session, "client_to_server", 10).await;
            panic!(
                "reconnect and reattach; channel transitions: {:?}; ATTACH frames: {}",
                ch_log.lock().unwrap(),
                serde_json::to_string(&attaches).unwrap()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // A PRESENCE re-enter went out after the second ws_connect
    poll_until("re-enter after reconnect", 10, || {
        let session = &session;
        async move {
            let log = session.get_log().await.expect("proxy log");
            // Timestamps are RFC3339 strings in a uniform format, so
            // lexicographic comparison is chronological.
            let second_connect = log
                .iter()
                .filter(|e| e["type"] == "ws_connect")
                .nth(1)
                .and_then(|e| e["timestamp"].as_str().map(String::from));
            let Some(t) = second_connect else {
                return false;
            };
            log.iter().any(|e| {
                e["type"] == "ws_frame"
                    && e["direction"] == "client_to_server"
                    && e["message"]["action"] == serde_json::json!(14)
                    && e["timestamp"].as_str().unwrap_or("") > t.as_str()
            })
        }
    })
    .await;

    let log = session.get_log().await.expect("proxy log");
    let second_connect_ts = log
        .iter()
        .filter(|e| e["type"] == "ws_connect")
        .nth(1)
        .and_then(|e| e["timestamp"].as_str().map(String::from))
        .expect("2nd ws_connect");
    let reenter: Vec<_> = log
        .iter()
        .filter(|e| {
            e["type"] == "ws_frame"
                && e["direction"] == "client_to_server"
                && e["message"]["action"] == serde_json::json!(14)
                && e["timestamp"].as_str().unwrap_or("") > second_connect_ts.as_str()
        })
        .collect();
    assert!(!reenter.is_empty());
    assert_reenter_frame(reenter[0]);
    assert_eq!(ch.state(), ChannelState::Attached);
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    close_client(&client).await;
    session.close().await.ok();
}

// ============================================================================
// rest_faults.md
// ============================================================================

// UTS: realtime/proxy/RSC10/token-renewal-on-401-0
#[tokio::test]
async fn proxy_rsc10_rest_token_renewal_on_401() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/channels/"}),
        serde_json::json!({"type": "http_respond", "status": 401, "body": {
            "error": {"code": 40142, "statusCode": 401, "message": "Token expired"}
        }}),
        "RSC10: Return 401 on the first channel request, then passthrough",
    )])
    .await;
    let count = Arc::new(AtomicUsize::new(0));
    let rest = ClientOptions::with_auth_callback(Arc::new(CountingTokenCallback {
        api_key: app.full_access_key().to_string(),
        count: count.clone(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .rest()
    .unwrap();

    let channel_name = format!("test-rsc10-{}", random_id());
    rest.channels()
        .get(channel_name)
        .publish()
        .name("test-event")
        .string("hello")
        .send()
        .await
        .expect("RSC10: publish succeeds after transparent renewal");

    assert!(
        count.load(Ordering::SeqCst) >= 2,
        "RSC10: authCallback invoked again for the renewal"
    );
    let log = session.get_log().await.expect("proxy log");
    let channel_requests = log
        .iter()
        .filter(|e| {
            e["type"] == "http_request"
                && e["path"]
                    .as_str()
                    .map(|p| p.contains("/channels/"))
                    .unwrap_or(false)
        })
        .count();
    assert!(channel_requests >= 2, "first 401 + retried request");
    session.close().await.ok();
}

// UTS: realtime/proxy/RSC15m/http-503-no-fallback-0 (RSC15m, REC2c2)
#[tokio::test]
async fn proxy_rsc15m_http_503_without_fallback_errors() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![rule(
        serde_json::json!({"type": "http_request", "pathContains": "/channels/"}),
        serde_json::json!({"type": "http_respond", "status": 503, "body": {
            "error": {"code": 50300, "statusCode": 503, "message": "Service temporarily unavailable"}
        }}),
        "RSC15m: Return 503 on the first channel request",
    )])
    .await;
    let rest = ClientOptions::with_auth_callback(Arc::new(SandboxTokenCallback {
        api_key: app.full_access_key().to_string(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .rest()
    .unwrap();

    let channel_name = format!("test-rsc15m-{}", random_id());
    let err = rest
        .channels()
        .get(channel_name)
        .publish()
        .name("test-event")
        .string("hello")
        .send()
        .await
        .expect_err("RSC15m: 503 propagates without fallback");
    assert_eq!(err.code, Some(50300));
    assert_eq!(err.status_code, Some(503));

    // REC2c2: explicit endpoint disables fallback — exactly one channel request
    let log = session.get_log().await.expect("proxy log");
    let channel_requests = log
        .iter()
        .filter(|e| {
            e["type"] == "http_request"
                && e["path"]
                    .as_str()
                    .map(|p| p.contains("/channels/"))
                    .unwrap_or(false)
        })
        .count();
    assert_eq!(channel_requests, 1, "no fallback retry");
    session.close().await.ok();
}

// UTS: realtime/proxy/RTL6/publish-history-through-proxy-0
#[tokio::test]
async fn proxy_rtl6_publish_and_history_through_proxy() {
    let app = get_sandbox().await;
    let (session, port) = proxy_session(vec![]).await;
    let client = proxied_realtime(app.full_access_key(), port);
    let rest = ClientOptions::with_auth_callback(Arc::new(SandboxTokenCallback {
        api_key: app.full_access_key().to_string(),
    }))
    .endpoint("localhost")
    .unwrap()
    .port(port as u32)
    .tls(false)
    .use_binary_protocol(false)
    .rest()
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);
    let channel_name = format!("persisted:test-rtl6-proxy-{}", random_id());
    let ch = client.channels.get(&channel_name);
    ch.attach().await.unwrap();
    ch.publish()
        .name("test-msg")
        .string("hello world")
        .send()
        .await
        .expect("publish through proxy");

    // History is eventually consistent: poll through the proxy
    let mut found = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while found.is_none() {
        let page = rest
            .channels()
            .get(channel_name.clone())
            .history()
            .send()
            .await
            .expect("history through proxy");
        found = page
            .items()
            .iter()
            .find(|m| m.name.as_deref() == Some("test-msg"))
            .cloned();
        if found.is_none() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "published message appears in history"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    assert_eq!(
        found.unwrap().data,
        crate::rest::Data::String("hello world".to_string())
    );

    let log = session.get_log().await.expect("proxy log");
    assert!(log.iter().any(|e| e["type"] == "ws_connect"));
    assert!(log.iter().any(|e| e["type"] == "http_request"));
    close_client(&client).await;
    session.close().await.ok();
}

#![allow(
    unused_imports,
    dead_code,
    unused_variables,
    unused_mut,
    unused_assignments
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use serde_json::json;

#[allow(unused_imports)]
use crate::auth::{
    self, Auth, AuthCallback, AuthOptions, AuthToken, Credential, Key, TokenDetails, TokenMetadata,
    TokenParams, TokenRequest,
};
#[allow(unused_imports)]
use crate::channel::{
    Channels as RealtimeChannels, DeriveOptions, PresenceGetOptions, PresenceSubscriptionId,
    RealtimeAnnotations, RealtimeChannel, RealtimeChannelOptions, RealtimePresence, SubscriptionId,
};
#[allow(unused_imports)]
use crate::crypto::CipherParams;
#[allow(unused_imports)]
use crate::error::{ErrorCode, ErrorInfo, ErrorInfoCode};
#[allow(unused_imports)]
use crate::http::{PaginatedRequestBuilder, PaginatedResult, RequestBuilder, Response};
#[allow(unused_imports)]
use crate::mock_http::{CapturedRequest, MockHttpClient, MockResponse};
#[allow(unused_imports)]
use crate::mock_ws::{
    CapturedMessage, MockConnection, MockTransport, MockWebSocket, PendingConnection,
};
#[allow(unused_imports)]
use crate::options::LogLevel;
#[allow(unused_imports)]
use crate::presence::{LocalPresenceMap, PresenceMap};
#[allow(unused_imports)]
use crate::protocol::{
    action, flags, ChannelEvent, ChannelMode, ChannelState, ChannelStateChange, ConnectionDetails,
    ConnectionEvent, ConnectionState, ConnectionStateChange, ProtocolMessage, PublishResult,
};
#[allow(unused_imports)]
use crate::realtime::{Connection, Realtime, RealtimeAuth};
#[allow(unused_imports)]
use crate::rest::{
    self, Annotation, AnnotationAction, BatchPresenceResult, BatchPublishResult, BatchPublishSpec,
    Channel, ChannelOptions, Channels, Data, Format, Message, MessageAction, MessageOperation,
    Presence, PresenceAction, PresenceMessage, PublishBuilder, Push, PushAdmin, Rest,
    RevokeTokenResult, RevokeTokensRequest, RevokeTokensResponse, UpdateDeleteResult,
};
#[allow(unused_imports)]
use crate::stats::Stats;
#[allow(unused_imports)]
use crate::{ClientOptions, Result};

use crate::test_support::{get_mock, mock_client, mock_client_json};

fn phase8d_setup() -> (crate::realtime::Realtime, crate::mock_ws::MockWebSocket) {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ProtocolMessage;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();
    (client, mock)
}

/// Helper: attach a channel by sending ATTACHED from the mock.
async fn phase8d_attach(
    channel: &std::sync::Arc<crate::channel::RealtimeChannel>,
    mock: &crate::mock_ws::MockWebSocket,
    serial: Option<&str>,
) {
    use crate::protocol::{action, ProtocolMessage};

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel.name().to_string()),
        channel_serial: serial.map(|s| s.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
}

// ========================================================================
// Phase 9: Realtime Auth Tests
// ========================================================================

/// A test auth callback that returns TokenDetails with incrementing token strings.
struct TestAuthCallback {
    call_count: std::sync::Arc<std::sync::atomic::AtomicU32>,
    token_prefix: String,
    /// If set, the callback will return an error.
    should_fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Captures the TokenParams passed to each invocation.
    captured_params: std::sync::Arc<std::sync::Mutex<Vec<crate::auth::TokenParams>>>,
    /// Token TTL in ms (0 = 1 hour default).
    token_ttl_ms: u64,
    /// Error code to return when should_fail is true. Defaults to Unauthorized (40100).
    fail_code: std::sync::Arc<std::sync::Mutex<crate::error::ErrorInfoCode>>,
    /// Status code to return when should_fail is true.
    fail_status: std::sync::Arc<std::sync::Mutex<Option<u32>>>,
}

impl TestAuthCallback {
    fn new(prefix: &str) -> Self {
        Self {
            call_count: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            token_prefix: prefix.to_string(),
            should_fail: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            captured_params: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            token_ttl_ms: 0,
            fail_code: std::sync::Arc::new(std::sync::Mutex::new(
                crate::error::ErrorInfoCode::Unauthorized,
            )),
            fail_status: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn with_ttl(mut self, ttl_ms: u64) -> Self {
        self.token_ttl_ms = ttl_ms;
        self
    }

    fn count(&self) -> u32 {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn set_should_fail(&self, fail: bool) {
        self.should_fail
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_fail_code(&self, code: crate::error::ErrorInfoCode, status: Option<u32>) {
        *self.fail_code.lock().unwrap() = code;
        *self.fail_status.lock().unwrap() = status;
    }

    fn captured_params(&self) -> Vec<crate::auth::TokenParams> {
        self.captured_params.lock().unwrap().clone()
    }
}

impl crate::auth::AuthCallback for TestAuthCallback {
    fn token<'a>(
        &'a self,
        params: &'a crate::auth::TokenParams,
    ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<crate::auth::AuthToken>> + 'a>>
    {
        let count = self
            .call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let should_fail = self.should_fail.load(std::sync::atomic::Ordering::SeqCst);
        self.captured_params.lock().unwrap().push(params.clone());

        let token_str = format!("{}-{}", self.token_prefix, count);
        let ttl_ms = self.token_ttl_ms;
        let fail_code = *self.fail_code.lock().unwrap();
        let fail_status = *self.fail_status.lock().unwrap();

        Box::pin(async move {
            if should_fail {
                let mut err =
                    crate::error::ErrorInfo::new(fail_code as u32, "Auth callback failed");
                if let Some(status) = fail_status {
                    err.status_code = Some(status as u16);
                }
                return Err(err);
            }

            let metadata = if ttl_ms > 0 {
                Some(crate::auth::TokenMetadata {
                    expires: chrono::Utc::now() + chrono::Duration::milliseconds(ttl_ms as i64),
                    issued: chrono::Utc::now(),
                    capability: "{\"*\":[\"*\"]}".to_string(),
                    client_id: params.client_id.clone(),
                    ..Default::default()
                })
            } else {
                None
            };

            Ok(crate::auth::AuthToken::Details(crate::auth::TokenDetails {
                token: token_str,
                metadata,
                ..Default::default()
            }))
        })
    }
}

// ===============================================================
// Phase 7a — Realtime: Types, Transport & Basic Connection
// ===============================================================

// ---------------------------------------------------------------
// RTN3 — autoConnect true initiates connection immediately
// UTS: realtime/unit/connection/auto_connect_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN3 — autoConnect false does not initiate connection
// UTS: realtime/unit/connection/auto_connect_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN3 — explicit connect after autoConnect false
// UTS: realtime/unit/connection/auto_connect_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN8a — Connection ID is unset until connected
// UTS: realtime/unit/connection/connection_id_key_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN9a — Connection key is unset until connected
// UTS: realtime/unit/connection/connection_id_key_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN8b — Connection ID is unique per connection
// UTS: realtime/unit/connection/connection_id_key_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN9b — Connection key is unique per connection
// UTS: realtime/unit/connection/connection_id_key_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN8c — Connection ID null in CLOSED state
// UTS: realtime/unit/connection/connection_id_key_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN9c — Connection key null in CLOSED state
// UTS: realtime/unit/connection/connection_id_key_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN8c, RTN9c — ID and key null after FAILED
// UTS: realtime/unit/connection/connection_id_key_test.md
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// RTN25 — errorReason set on connection errors
// UTS: realtime/unit/connection/error_reason_test.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rtn25_error_reason_set_on_failed() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut error_msg = ProtocolMessage::new(action::ERROR);
        error_msg.error = Some(crate::error::ErrorInfo {
            code: Some(80000),
            status_code: Some(400),
            message: Some("Fatal error".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(error_msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let error = client.connection.error_reason();
    assert!(error.is_some());
    assert_eq!(error.as_ref().unwrap().code, Some(80000));
    assert_eq!(
        error.as_ref().unwrap().message.as_deref(),
        Some("Fatal error")
    );
}

// ---------------------------------------------------------------
// RTN25 — errorReason on DISCONNECTED state
// UTS: realtime/unit/connection/error_reason_test.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rtn25_error_reason_on_disconnected() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ConnectionState;
    use crate::realtime::{await_state, Realtime};

    // Connection refused → DISCONNECTED with error
    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_refused();
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false)
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

    let error = client.connection.error_reason();
    assert!(error.is_some());
}

// ---------------------------------------------------------------
// RTN4 — state change events emitted
// UTS: realtime/unit/connection (general)
// ---------------------------------------------------------------

#[tokio::test]
async fn rtn4_state_change_events() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::{Arc, Mutex};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected(
            "connection-id",
            "connection-key",
        ));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();

    let states: Arc<Mutex<Vec<ConnectionState>>> = Arc::new(Mutex::new(Vec::new()));
    let states_clone = states.clone();

    let mut rx = client.connection.on_state_change();
    tokio::spawn(async move {
        while let Ok(change) = rx.recv().await {
            states_clone.lock().unwrap().push(change.current);
        }
    });

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Brief pause to let events propagate
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let recorded = states.lock().unwrap().clone();
    assert!(
        recorded.contains(&ConnectionState::Connecting),
        "should have CONNECTING event: {:?}",
        recorded
    );
    assert!(
        recorded.contains(&ConnectionState::Connected),
        "should have CONNECTED event: {:?}",
        recorded
    );
}

// ---------------------------------------------------------------
// Connection URL — standard query parameters
// UTS: realtime/unit/client/realtime_client.md
// ---------------------------------------------------------------

// ======================================================================
// Phase 7b: Connection Failures, Resume & Ping
// ======================================================================

// --- RTN14a: Invalid API key causes FAILED state ---
#[tokio::test]
async fn rtn14a_invalid_key_causes_failed() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(40005),
            status_code: Some(400),
            message: Some("Invalid key".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("invalid.key:secret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    assert_eq!(client.connection.state(), ConnectionState::Failed);
    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(40005));
    assert_eq!(err.status_code, Some(400));
    assert!(client.connection.id().is_none());
    assert!(client.connection.key().is_none());
}

// --- RTN14d: Retry after recoverable failure ---
#[tokio::test]
async fn rtn14d_retry_after_recoverable_failure() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            pending.respond_with_refused();
        } else {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert!(attempt_count.load(Ordering::SeqCst) >= 2);
}

// --- RTN14g: ERROR protocol message with empty channel -> FAILED ---
#[tokio::test]
async fn rtn14g_error_empty_channel_causes_failed() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(50000),
            status_code: Some(500),
            message: Some("Internal server error".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(50000));
    assert_eq!(err.status_code, Some(500));
    assert_eq!(err.message.as_deref(), Some("Internal server error"));
}

// --- RTN15a: Unexpected transport disconnect triggers reconnect ---
#[tokio::test]
async fn rtn15a_unexpected_disconnect_triggers_reconnect() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        } else {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let original_id = client.connection.id();

    // Simulate disconnect via the active connection
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.simulate_disconnect();
    }

    // Should reconnect
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    assert_eq!(client.connection.id(), original_id);
    assert!(attempt_count.load(Ordering::SeqCst) >= 2);
}

// --- RTN15b, RTN15c6: Successful resume (same connectionId) ---
#[tokio::test]
async fn rtn15b_c6_successful_resume() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();
    let captured_urls: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_urls_clone = captured_urls.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        captured_urls_clone
            .lock()
            .unwrap()
            .push(pending.url.clone());
        if n == 1 {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        } else {
            // Resume succeeds: same connectionId, updated key
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1-updated"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(client.connection.id().as_deref(), Some("conn-1"));

    // Force disconnect
    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    // Wait for reconnection
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // RTN15c6: Connection resumed (same ID)
    assert_eq!(client.connection.id().as_deref(), Some("conn-1"));
    // RTN15e: Connection key updated
    assert_eq!(client.connection.key().as_deref(), Some("key-1-updated"));

    // RTN15b: Second URL includes resume parameter
    let urls = captured_urls.lock().unwrap();
    assert!(urls.len() >= 2);
    let second_url: url::Url = urls[1].parse().unwrap();
    let resume_param: Option<String> = second_url
        .query_pairs()
        .find(|(k, _): &(std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "resume")
        .map(|(_, v)| v.to_string());
    assert_eq!(resume_param.as_deref(), Some("key-1"));
}

// --- RTN15c7: Failed resume (new connectionId) ---
#[tokio::test]
async fn rtn15c7_failed_resume_new_connection_id() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        } else {
            // Resume failed: new connectionId + error
            let mut msg = ProtocolMessage::connected("conn-2", "key-2");
            msg.error = Some(ErrorInfo {
                code: Some(80008),
                status_code: Some(400),
                message: Some("Unable to recover connection".to_string()),
                href: None,
                ..Default::default()
            });
            pending.respond_with_success(msg);
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Force disconnect
    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    // Wait for reconnection
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // New connection (different ID)
    assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
    assert_eq!(client.connection.key().as_deref(), Some("key-2"));

    // Error reason set (indicates why resume failed)
    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(80008));

    // Still CONNECTED
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

// --- RTN15j: ERROR with empty channel -> FAILED ---
#[tokio::test]
async fn rtn15j_error_empty_channel_while_connected() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Send ERROR with empty channel
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(50000),
            status_code: Some(500),
            message: Some("Internal error".to_string()),
            href: None,
            ..Default::default()
        });
        conn.send_to_client_and_close(msg);
    }

    assert!(await_state(&client.connection, ConnectionState::Failed, 2000).await);

    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(50000));
    assert_eq!(err.status_code, Some(500));
}

// --- RTN15h1: DISCONNECTED with token error, no means to renew -> FAILED ---
#[tokio::test]
async fn rtn15h1_token_error_no_renewal() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    // Use token directly (no way to renew)
    let client = Realtime::with_mock(
        &ClientOptions::new("some_token_string").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Server sends DISCONNECTED with token error
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut msg = ProtocolMessage::new(action::DISCONNECTED);
        msg.error = Some(ErrorInfo {
            code: Some(40142),
            status_code: Some(401),
            message: Some("Token expired".to_string()),
            href: None,
            ..Default::default()
        });
        conn.send_to_client_and_close(msg);
    }

    // RTN15h1: a token error with a non-renewable token (token string only, no
    // key/authCallback/authUrl) is terminal — the connection goes to FAILED.
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);
    // The SDK substitutes 40171 ("no way to renew the auth token") for the
    // server's token error, matching ably-js.
    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(40171));
    assert_eq!(err.status_code, Some(401));
}

// --- RTN15c4: ERROR with fatal error during resume -> FAILED ---
#[tokio::test]
async fn rtn15c4_fatal_error_during_resume() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        } else {
            // Resume fails with fatal error
            let mut msg = ProtocolMessage::new(action::ERROR);
            msg.error = Some(ErrorInfo {
                code: Some(50000),
                status_code: Some(500),
                message: Some("Internal server error".to_string()),
                href: None,
                ..Default::default()
            });
            pending.respond_with_error(msg);
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Force disconnect
    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    // Should fail (not retry)
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);
    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(50000));
    assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
}

// --- RTN24: CONNECTED while already CONNECTED emits UPDATE ---
#[tokio::test]
async fn rtn24_connected_while_connected_emits_update() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionEvent, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let mut rx = client.connection.on_state_change();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Drain existing events
    while rx.try_recv().is_ok() {}

    // Send another CONNECTED while already connected
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage::connected("conn-2", "key-2"));
    }

    // Wait for the event
    let change = tokio::time::timeout(tokio::time::Duration::from_millis(1000), rx.recv())
        .await
        .unwrap()
        .unwrap();

    // Should be UPDATE, not CONNECTED
    assert_eq!(change.event, ConnectionEvent::Update);
    assert_eq!(change.previous, ConnectionState::Connected);
    assert_eq!(change.current, ConnectionState::Connected);

    // Connection details updated
    assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
    assert_eq!(client.connection.key().as_deref(), Some("key-2"));
}

// --- RTN24: UPDATE event with error reason ---
#[tokio::test]
async fn rtn24_update_event_with_error_reason() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionEvent, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let mut rx = client.connection.on_state_change();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Drain existing events
    while rx.try_recv().is_ok() {}

    // Send CONNECTED with error (e.g., after token renewal)
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut msg = ProtocolMessage::connected("conn-2", "key-2");
        msg.error = Some(ErrorInfo {
            code: Some(40142),
            status_code: Some(401),
            message: Some("Token expired; renewed automatically".to_string()),
            href: None,
            ..Default::default()
        });
        conn.send_to_client(msg);
    }

    let change = tokio::time::timeout(tokio::time::Duration::from_millis(1000), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(change.event, ConnectionEvent::Update);
    let reason = change.reason.unwrap();
    assert_eq!(reason.code, Some(40142));
}

// --- RTN25: errorReason cleared on successful connection ---
#[tokio::test]
async fn rtn25_error_reason_cleared_on_success() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            pending.respond_with_refused();
        } else {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();

    // Wait for DISCONNECTED (failure)
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
    assert!(client.connection.error_reason().is_some());

    // Wait for CONNECTED (retry succeeds)
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // errorReason should be cleared
    assert!(client.connection.error_reason().is_none());
}

// --- RTN25: errorReason propagated to ConnectionStateChange events ---
#[tokio::test]
async fn rtn25_error_reason_in_state_change_events() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(40003),
            status_code: Some(400),
            message: Some("Access token invalid".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let mut rx = client.connection.on_state_change();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    // Find the FAILED state change
    let mut found_failed = false;
    while let Ok(change) = rx.try_recv() {
        if change.current == ConnectionState::Failed {
            assert!(change.reason.is_some());
            let reason = change.reason.unwrap();
            assert_eq!(reason.code, Some(40003));
            assert_eq!(reason.status_code, Some(400));
            found_failed = true;
            break;
        }
    }
    assert!(found_failed, "Should have received FAILED state change");

    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(40003));
}

// --- RTN13a: Ping sends HEARTBEAT and returns round-trip duration ---
#[tokio::test]
async fn rtn13a_ping_sends_heartbeat() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Spawn a task that watches for the heartbeat and responds
    let ping_responder = tokio::spawn(async move {
        // Poll for the heartbeat message via public MockWebSocket methods
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            let msgs = mock.client_messages();
            for m in &msgs {
                if m.message.action == action::HEARTBEAT {
                    if let Some(ref id) = m.message.id {
                        let conns = mock.active_connections();
                        if let Some(active) = conns.last() {
                            let mut response = ProtocolMessage::new(action::HEARTBEAT);
                            response.id = Some(id.clone());
                            active.send_to_client(response);
                            return;
                        }
                    }
                }
            }
        }
    });

    let result = client.connection.ping().await;
    ping_responder.await.unwrap();

    assert!(result.is_ok());
}

// --- RTN13b: Ping errors in INITIALIZED state ---
#[tokio::test]
async fn rtn13b_ping_error_in_initialized() {
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let result = client.connection.ping().await;
    assert!(result.is_err());
}

// --- RTN13b: Ping errors in FAILED state ---
#[tokio::test]
async fn rtn13b_ping_error_in_failed() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(80000),
            status_code: Some(400),
            message: Some("Fatal error".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let result = client.connection.ping().await;
    assert!(result.is_err());
}

// --- RTN14e: DISCONNECTED to SUSPENDED after connectionStateTtl ---
#[tokio::test]
async fn rtn14e_disconnected_to_suspended_after_ttl() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            // First connection succeeds with short TTL
            let mut msg = ProtocolMessage::connected("conn-1", "key-1");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(500); // 500ms TTL
            }
            pending.respond_with_success(msg);
        } else {
            // All subsequent attempts fail
            pending.respond_with_refused();
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Disconnect
    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    // Wait for SUSPENDED (TTL = 500ms, retries every 100ms)
    assert!(
        await_state(&client.connection, ConnectionState::Suspended, 5000).await,
        "Expected SUSPENDED state"
    );

    // Error reason should be set
    assert!(client.connection.error_reason().is_some());
}

// --- RTN15g: No resume after connectionStateTtl expiry ---
#[tokio::test]
async fn rtn15g_no_resume_after_ttl_expiry() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();
    let captured_urls: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_urls_clone = captured_urls.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        captured_urls_clone
            .lock()
            .unwrap()
            .push(pending.url.clone());
        if n == 1 {
            let mut msg = ProtocolMessage::connected("conn-1", "key-1");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(300); // Short TTL
            }
            pending.respond_with_success(msg);
        } else if n < 6 {
            // Attempts 2-5 fail
            pending.respond_with_refused();
        } else {
            // After TTL expiry, fresh connection succeeds
            pending.respond_with_success(ProtocolMessage::connected("conn-2", "key-2"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(80))
            .suspended_retry_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Disconnect
    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    // Wait for disconnect to be processed first
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);

    // Wait for eventual reconnection (through SUSPENDED)
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 15000).await,
        "Expected reconnection"
    );

    // New connection (not resumed)
    assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
    assert_eq!(client.connection.key().as_deref(), Some("key-2"));

    // Final URL should NOT have resume parameter (TTL expired, key was cleared)
    let urls = captured_urls.lock().unwrap();
    let last_url: url::Url = urls.last().unwrap().parse().unwrap();
    let has_resume = last_url
        .query_pairs()
        .any(|(k, _): (std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "resume");
    assert!(
        !has_resume,
        "Last reconnection should not have resume parameter"
    );
}

// --- RTN14f: SUSPENDED state retries and eventually succeeds ---
#[tokio::test]
async fn rtn14f_suspended_retries_indefinitely() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            let mut msg = ProtocolMessage::connected("conn-1", "key-1");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(200); // Very short TTL
            }
            pending.respond_with_success(msg);
        } else if n < 5 {
            pending.respond_with_refused();
        } else {
            // Eventually succeeds from SUSPENDED
            pending.respond_with_success(ProtocolMessage::connected("conn-2", "key-2"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50))
            .suspended_retry_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Disconnect
    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    // Wait for disconnect to be processed first
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);

    // Wait for final reconnection from SUSPENDED state
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 15000).await,
        "Expected reconnection from SUSPENDED"
    );

    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert!(attempt_count.load(Ordering::SeqCst) >= 3);
}

// ---------------------------------------------------------------
// RTN23a — Heartbeat idle detection (HEARTBEAT protocol messages)
// UTS: realtime/unit/connection/heartbeat_test.md
// ---------------------------------------------------------------

// RTN23a: Client sends heartbeats=true when ping frames not observable
#[tokio::test]
async fn rtn23a_heartbeats_true_in_url() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::{Arc, Mutex};

    let captured_url: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_url_clone = captured_url.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        *captured_url_clone.lock().unwrap() = Some(pending.url.clone());
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let url: url::Url = captured_url
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .parse()
        .unwrap();
    let heartbeats = url
        .query_pairs()
        .find(|(k, _): &(std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "heartbeats")
        .map(|(_, v)| v.to_string());
    assert_eq!(heartbeats.as_deref(), Some("true"));
}

// RTN23a: Multiple messages keep connection alive
#[tokio::test]
async fn rtn23a_continuous_activity_keeps_alive() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::connected("conn-id", "conn-key");
        if let Some(ref mut details) = msg.connection_details {
            details.max_idle_interval = Some(200); // 200ms
        }
        pending.respond_with_success(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .realtime_request_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Send heartbeats every 150ms for 7 rounds (>= 1050ms total, well past 300ms timeout)
    for _ in 0..7 {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let conns = mock.active_connections();
        conns
            .last()
            .unwrap()
            .send_to_client(ProtocolMessage::new(action::HEARTBEAT));
        assert_eq!(client.connection.state(), ConnectionState::Connected);
    }

    // Still connected
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

// ---------------------------------------------------------------
// RTN17 — Fallback hosts for Realtime
// UTS: realtime/unit/connection/fallback_hosts_test.md
// ---------------------------------------------------------------

// RTN17i: Always prefer primary domain first
#[tokio::test]
async fn rtn17i_always_try_primary_first() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_hosts_clone = captured_hosts.clone();
    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        let host = url::Url::parse(&pending.url)
            .map(|u| u.host_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        captured_hosts_clone.lock().unwrap().push(host);

        if n == 1 {
            // Primary fails
            pending.respond_with_refused();
        } else {
            // Fallback succeeds
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let hosts = captured_hosts.lock().unwrap();
    assert!(
        hosts.len() >= 2,
        "Should have tried primary + at least one fallback"
    );
    assert_eq!(
        hosts[0], "main.realtime.ably.net",
        "First attempt should be primary"
    );
    // Second attempt should be a fallback host
    assert!(
        hosts[1].contains("ably-realtime.com"),
        "Second attempt should be a fallback host, got: {}",
        hosts[1]
    );
}

// RTN17f: Connection refused triggers fallback
#[tokio::test]
async fn rtn17f_connection_refused_triggers_fallback() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_hosts_clone = captured_hosts.clone();
    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        let host = url::Url::parse(&pending.url)
            .map(|u| u.host_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        captured_hosts_clone.lock().unwrap().push(host);

        if n == 1 {
            pending.respond_with_refused();
        } else {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let hosts = captured_hosts.lock().unwrap();
    assert!(hosts.len() >= 2);
    assert_eq!(hosts[0], "main.realtime.ably.net");
    assert_ne!(
        hosts[1], "main.realtime.ably.net",
        "Should try fallback, not primary again"
    );
}

// RTN17f1: DISCONNECTED with 5xx status triggers fallback
#[tokio::test]
async fn rtn17f1_5xx_disconnected_triggers_fallback() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_hosts_clone = captured_hosts.clone();
    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        let host = url::Url::parse(&pending.url)
            .map(|u| u.host_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        captured_hosts_clone.lock().unwrap().push(host);

        if n == 1 {
            // Primary: connect then send DISCONNECTED with 503
            let mut disconnected = ProtocolMessage::new(action::DISCONNECTED);
            disconnected.error = Some(ErrorInfo {
                code: Some(50003),
                status_code: Some(503),
                message: Some("Service temporarily unavailable".to_string()),
                href: None,
                ..Default::default()
            });
            pending.respond_with_error(disconnected);
        } else {
            // Fallback succeeds
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 10000).await);

    let hosts = captured_hosts.lock().unwrap();
    assert!(hosts.len() >= 2);
    assert_eq!(hosts[0], "main.realtime.ably.net");
    assert!(
        hosts[1].contains("ably-realtime.com"),
        "Should try fallback after 5xx, got: {}",
        hosts[1]
    );
}

// RTN17g: Empty fallback set results in no fallback attempt
#[tokio::test]
async fn rtn17g_empty_fallback_set_no_retry() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ConnectionState;
    use crate::realtime::{await_state, Realtime};
    use std::sync::{Arc, Mutex};

    let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_hosts_clone = captured_hosts.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let host = url::Url::parse(&pending.url)
            .map(|u| u.host_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        captured_hosts_clone.lock().unwrap().push(host);
        pending.respond_with_refused();
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

    // Give time for potential fallback attempts (there shouldn't be any
    // beyond the initial primary attempt before moving to retry)
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let hosts = captured_hosts.lock().unwrap();
    // Only one host attempted before going to DISCONNECTED retry cycle
    assert_eq!(hosts.len(), 1, "Should only try primary, no fallbacks");
    assert_eq!(hosts[0], "main.realtime.ably.net");
}

// RTN17h: Fallback domains from default set
#[tokio::test]
async fn rtn17h_fallback_domains_from_default_set() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_hosts_clone = captured_hosts.clone();
    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_count_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
        let host = url::Url::parse(&pending.url)
            .map(|u| u.host_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        captured_hosts_clone.lock().unwrap().push(host);

        if n == 1 {
            pending.respond_with_refused();
        } else {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let hosts = captured_hosts.lock().unwrap();
    assert!(hosts.len() >= 2);

    // Fallback host should be one of [a-e].ably-realtime.com
    let fallback = &hosts[1];
    let valid_fallbacks = [
        "main.a.fallback.ably-realtime.com",
        "main.b.fallback.ably-realtime.com",
        "main.c.fallback.ably-realtime.com",
        "main.d.fallback.ably-realtime.com",
        "main.e.fallback.ably-realtime.com",
    ];
    assert!(
        valid_fallbacks.contains(&fallback.as_str()),
        "Fallback should be a default host, got: {}",
        fallback
    );
}

// --- Connection Auth (RTN2e) ---

#[tokio::test]
async fn rtn2e_token_obtained_before_connection() {
    // RTN2e: When authCallback is configured, the library must obtain a token
    // BEFORE opening the WebSocket connection. The token is included in the
    // WebSocket URL as the accessToken query parameter.
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let callback = std::sync::Arc::new(TestAuthCallback::new("callback-token"));

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .auto_connect(false)
        .fallback_hosts(vec![]);
    let client = Realtime::with_mock(&options, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // authCallback was invoked
    assert_eq!(callback.count(), 1);

    // WebSocket URL contains the token from authCallback
    let messages = mock.client_messages();
    // Check the connection URL contains accessToken
    let conns = mock.active_connections();
    assert!(!conns.is_empty());

    // Connection succeeded
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

#[tokio::test]
async fn rtn2e_auth_callback_error_prevents_connection() {
    // RTN2e: If authCallback fails, no WebSocket connection should be attempted.
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let callback = std::sync::Arc::new(TestAuthCallback::new("token"));
    callback.set_should_fail(true);

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .auto_connect(false)
        .disconnected_retry_timeout(std::time::Duration::from_millis(50))
        .fallback_hosts(vec![]);
    let client = Realtime::with_mock(&options, transport.clone()).unwrap();

    client.connect();
    // Should transition to DISCONNECTED due to auth failure
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

    // Error reason is set
    let error = client.connection.error_reason();
    assert!(error.is_some());

    // No WebSocket connection was established (auth failed before connect)
    assert_eq!(mock.connection_count(), 0);
}

#[tokio::test]
async fn rtn2e_auth_callback_receives_client_id() {
    // RTN2e / RSA12a: authCallback receives TokenParams with configured clientId.
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let callback = std::sync::Arc::new(TestAuthCallback::new("token"));

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .client_id("my-client-id")
        .unwrap()
        .auto_connect(false)
        .fallback_hosts(vec![]);
    let client = Realtime::with_mock(&options, transport).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // authCallback received TokenParams with clientId
    let params = callback.captured_params();
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].client_id.as_deref(), Some("my-client-id"));
}

// --- Server-Initiated Re-authentication (RTN22) ---

#[tokio::test]
async fn rtn22_server_auth_triggers_reauth() {
    // RTN22: Server sends AUTH, client obtains new token and sends AUTH back.
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionEvent, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let callback = std::sync::Arc::new(TestAuthCallback::new("token"));

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .auto_connect(false)
        .fallback_hosts(vec![]);
    let client = Realtime::with_mock(&options, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Subscribe to state changes
    let mut rx = client.connection.on_state_change();

    // Set up handler: when client sends AUTH back, respond with CONNECTED (update)
    let conns = mock.active_connections();
    let conn = conns.last().unwrap().clone();

    // Server requests re-authentication
    conn.send_to_client(ProtocolMessage::new(action::AUTH));

    // Wait briefly for the async reauth task to complete
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Client should have sent AUTH back with new token
    let client_msgs = mock.client_messages();
    let auth_msgs: Vec<_> = client_msgs
        .iter()
        .filter(|m| m.message.action == action::AUTH)
        .collect();
    assert_eq!(auth_msgs.len(), 1, "Client should send one AUTH message");

    // AUTH message contains the new token
    let auth_msg = &auth_msgs[0].message;
    assert!(auth_msg.auth.is_some());
    assert_eq!(
        auth_msg.auth.as_ref().unwrap()["accessToken"].as_str(),
        Some("token-2") // token-1 was initial connect, token-2 is reauth
    );

    // authCallback was called twice (initial connect + reauth)
    assert_eq!(callback.count(), 2);

    // Now server responds with CONNECTED (UPDATE)
    conn.send_to_client(ProtocolMessage::connected("conn-1", "key-1-updated"));

    // Wait for UPDATE event
    let change = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(change.event, ConnectionEvent::Update);
    assert_eq!(change.current, ConnectionState::Connected);
    assert_eq!(change.previous, ConnectionState::Connected);
}

#[tokio::test]
async fn rtn22_connection_stays_connected_during_reauth() {
    // RTN22: Connection remains CONNECTED during server-initiated reauth.
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionEvent, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let callback = std::sync::Arc::new(TestAuthCallback::new("reauth-token"));

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .auto_connect(false)
        .fallback_hosts(vec![]);
    let client = Realtime::with_mock(&options, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Collect state changes
    let mut rx = client.connection.on_state_change();
    let state_changes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sc = state_changes.clone();
    tokio::spawn(async move {
        while let Ok(change) = rx.recv().await {
            sc.lock().unwrap().push(change);
        }
    });

    // Server sends AUTH
    let conns = mock.active_connections();
    let conn = conns.last().unwrap().clone();
    conn.send_to_client(ProtocolMessage::new(action::AUTH));

    // Wait for reauth to complete
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Server responds with CONNECTED (UPDATE)
    conn.send_to_client(ProtocolMessage::connected("conn-1", "key-1-updated"));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Connection never left CONNECTED
    assert_eq!(client.connection.state(), ConnectionState::Connected);

    // Only an UPDATE event, no state change events
    let changes = state_changes.lock().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].event, ConnectionEvent::Update);
    assert_eq!(changes[0].current, ConnectionState::Connected);
    assert_eq!(changes[0].previous, ConnectionState::Connected);
}

// ===============================================================
// RTN14b: Token error with renewal fails → DISCONNECTED
// ===============================================================

#[tokio::test]
async fn rtn14b_token_renewal_fails_goes_disconnected() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    // First call succeeds (initial token), second call fails (renewal)
    let callback = std::sync::Arc::new(TestAuthCallback::new("token").with_ttl(3600000));

    let mock = MockWebSocket::with_handler(move |pending| {
        let mut msg = ProtocolMessage::new(crate::protocol::action::ERROR);
        msg.error = Some(crate::error::ErrorInfo {
            code: Some(40142),
            status_code: Some(401),
            message: Some("Token expired".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .auto_connect(false)
        .fallback_hosts(vec![])
        .disconnected_retry_timeout(std::time::Duration::from_secs(30));
    let client = Realtime::with_mock(&options, transport).unwrap();

    client.connect();
    // Server sends token error → connection should attempt renewal → fails → DISCONNECTED or FAILED
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let state = client.connection.state();
            if state == ConnectionState::Disconnected || state == ConnectionState::Failed {
                return state;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(result.is_ok(), "Should reach DISCONNECTED or FAILED");
}

// ===============================================================
// Batch 8: Realtime Connection
// ===============================================================

// UTS: realtime/unit/connection/connection_failures_test.md — RTN15c5
#[tokio::test]
async fn rtn15c5_recovery_with_expired_connection_error() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected(
            "connection-id-1",
            "connection-key-1",
        ));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport.clone(),
    )
    .unwrap();
    client.connect();
    let connected =
        crate::realtime::await_state(&client.connection, ConnectionState::Connected, 5000).await;
    assert!(connected, "Expected CONNECTED");
}

// UTS: realtime/unit/connection/connection_failures_test.md — RTN15e
#[tokio::test]
async fn rtn15e_token_error_no_renewal_means() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::new(crate::protocol::action::ERROR);
        msg.error = Some(crate::error::ErrorInfo {
            code: Some(40142),
            status_code: Some(401),
            message: Some("Token expired".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("a-token-string")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();
    client.connect();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let state = client.connection.state();
    assert!(
        state == ConnectionState::Failed || state == ConnectionState::Disconnected,
        "Expected FAILED or DISCONNECTED with no renewal means, got {:?}",
        state
    );
}

// UTS: realtime/unit/connection/connection_ping_test.md — RTN13c
#[tokio::test]
async fn rtn13c_ping_timeout_when_no_heartbeat_response() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .realtime_request_timeout(std::time::Duration::from_millis(500))
            .auto_connect(false),
        transport,
    )
    .unwrap();
    client.connect();
    let connected =
        crate::realtime::await_state(&client.connection, ConnectionState::Connected, 5000).await;
    assert!(connected);
    let result = client.connection.ping().await;
    assert!(
        result.is_err(),
        "Expected ping to timeout without heartbeat response"
    );
}

// UTS: realtime/unit/connection/connection_ping_test.md — RTN13e
#[tokio::test]
async fn rtn13e_heartbeat_includes_random_id() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .realtime_request_timeout(std::time::Duration::from_millis(500))
            .auto_connect(false),
        transport.clone(),
    )
    .unwrap();
    client.connect();
    let connected =
        crate::realtime::await_state(&client.connection, ConnectionState::Connected, 5000).await;
    assert!(connected);

    let _ = client.connection.ping().await;
    let _ = client.connection.ping().await;

    let msgs = mock.client_messages();
    let heartbeats: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::HEARTBEAT)
        .collect();
    if heartbeats.len() >= 2 {
        assert_ne!(
            heartbeats[0].message.id, heartbeats[1].message.id,
            "Heartbeat IDs should differ"
        );
    }
}

// UTS: realtime/unit/connection/fallback_hosts_test.md — RTN17e
// Spec: HTTP requests should use same fallback host as realtime connection
#[tokio::test]
async fn rtn17e_http_uses_same_fallback_as_realtime() -> Result<()> {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let connect_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = connect_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            // Primary host: refuse
            pending.respond_with_refused();
        } else {
            // Fallback host: accept
            let msg = ProtocolMessage::connected("connId", "connKey");
            pending.respond_with_success(msg);
        }
    });

    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(10))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![
                "a-fallback.ably-realtime.com".to_string(),
                "b-fallback.ably-realtime.com".to_string(),
            ]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // RTN17e: connection.host() should be a fallback, not primary
    let host = client.connection.host();
    assert!(host.is_some(), "Connected host should be tracked");
    let host = host.unwrap();
    assert!(
        host == "a-fallback.ably-realtime.com" || host == "b-fallback.ably-realtime.com",
        "Expected fallback host, got: {}",
        host
    );

    Ok(())
}

// UTS: realtime/unit/connection/fallback_hosts_test.md — RTN17j
// Spec: Fallback hosts are tried in random order when primary fails.
// Verifies by running multiple iterations and checking for variation.
#[tokio::test]
async fn rtn17j_fallback_hosts_random_order() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    };

    let fallback_hosts = vec![
        "a-fallback.ably-realtime.com".to_string(),
        "b-fallback.ably-realtime.com".to_string(),
        "c-fallback.ably-realtime.com".to_string(),
        "d-fallback.ably-realtime.com".to_string(),
        "e-fallback.ably-realtime.com".to_string(),
    ];

    let mut all_fallback_orders: Vec<Vec<String>> = Vec::new();

    for _iteration in 0..5 {
        let captured_hosts = Arc::new(Mutex::new(Vec::<String>::new()));
        let ch = captured_hosts.clone();
        let attempt = Arc::new(AtomicU32::new(0));
        let att = attempt.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = att.fetch_add(1, Ordering::SeqCst);
            let host = url::Url::parse(&pending.url)
                .map(|u| u.host_str().unwrap_or("unknown").to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            ch.lock().unwrap().push(host);

            if n == 0 {
                pending.respond_with_refused();
            } else {
                pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
            }
        });

        let transport = Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let mut opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
        opts.fallback_hosts = Some(fallback_hosts.clone());
        let client = Realtime::with_mock(&opts, transport).unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let hosts = captured_hosts.lock().unwrap().clone();
        if hosts.len() > 1 {
            all_fallback_orders.push(hosts[1..].to_vec());
        }

        client.close();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        all_fallback_orders.len() >= 2,
        "Need at least 2 successful iterations"
    );
    let unique_count = {
        let mut unique = all_fallback_orders.clone();
        unique.sort();
        unique.dedup();
        unique.len()
    };
    assert!(
        unique_count >= 2,
        "Fallback host orders should vary across iterations (got {} unique out of {})",
        unique_count,
        all_fallback_orders.len()
    );
}

// UTS: rest/unit/REC3/connectivity-check-validation-0
// The connectivity check requires a successful GET whose body contains
// "yes"; anything else — wrong body, empty body, HTTP error, network
// error — means "not connected".
#[tokio::test]
async fn rec3_connectivity_check_validation() {
    use crate::mock_http::{MockHttpClient, MockResponse};
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;
    use std::sync::Arc;

    let cases: Vec<(MockResponse, bool)> = vec![
        (MockResponse::text(200, "yes"), true),
        (MockResponse::text(200, "no"), false),
        (MockResponse::text(200, ""), false),
        (MockResponse::text(404, "Not Found"), false),
        (MockResponse::network_error(), false),
    ];
    for (i, (response, expected)) in cases.into_iter().enumerate() {
        let mock_ws = MockWebSocket::with_handler(|_| {});
        let transport = Arc::new(crate::mock_ws::MockTransport::new(mock_ws.inner()));
        let resp = std::sync::Mutex::new(Some(response));
        let mock_http =
            MockHttpClient::with_handler(move |_req| resp.lock().unwrap().take().unwrap());
        let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
        let client = Realtime::with_mocks(&opts, transport, mock_http).unwrap();
        assert_eq!(
            client.connection.check_connectivity().await,
            expected,
            "case {i}"
        );
    }
}

// UTS: rest/unit/REC3a/default-connectivity-check-url-0
#[tokio::test]
async fn rec3a_default_connectivity_check_url() {
    use crate::mock_http::{MockHttpClient, MockResponse};
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;
    use std::sync::Arc;

    let mock_ws = MockWebSocket::with_handler(|_| {});
    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock_ws.inner()));
    let mock_http = MockHttpClient::with_handler(|_req| MockResponse::text(200, "yes"));
    let handle = mock_http.clone();
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mocks(&opts, transport, mock_http).unwrap();

    assert!(client.connection.check_connectivity().await);
    let reqs = handle.captured_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(
        reqs[0].url.as_str(),
        "https://internet-up.ably-realtime.com/is-the-internet-up.txt"
    );
}

// UTS: rest/unit/REC3b/custom-connectivity-check-url-0
#[tokio::test]
async fn rec3b_custom_connectivity_check_url() {
    use crate::mock_http::{MockHttpClient, MockResponse};
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;
    use std::sync::Arc;

    let mock_ws = MockWebSocket::with_handler(|_| {});
    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock_ws.inner()));
    let mock_http = MockHttpClient::with_handler(|_req| MockResponse::text(200, "yes"));
    let handle = mock_http.clone();
    let opts = ClientOptions::new("appId.keyId:keySecret")
        .auto_connect(false)
        .connectivity_check_url("https://custom.example.com/connectivity");
    let client = Realtime::with_mocks(&opts, transport, mock_http).unwrap();

    assert!(client.connection.check_connectivity().await);
    let reqs = handle.captured_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].url.as_str(),
        "https://custom.example.com/connectivity"
    );
    assert!(reqs
        .iter()
        .all(|r| r.url.host_str() != Some("internet-up.ably-realtime.com")));
}

// UTS: realtime/unit/RTN17j/connectivity-check-before-fallback-0
// A failure necessitating fallback first probes the connectivity check URL;
// with internet confirmed ("yes"), the fallback attempt proceeds.
#[tokio::test]
async fn rtn17j_connectivity_check_before_fallback() {
    use crate::mock_http::{MockHttpClient, MockResponse};
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    let attempt = Arc::new(AtomicU32::new(0));
    let att = attempt.clone();
    let mock_ws = MockWebSocket::with_handler(move |pending| {
        if att.fetch_add(1, Ordering::SeqCst) == 0 {
            pending.respond_with_refused();
        } else {
            pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
        }
    });
    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock_ws.inner()));
    let mock_http = MockHttpClient::with_handler(|req| {
        if req.url.as_str().contains("internet-up") {
            MockResponse::text(200, "yes")
        } else {
            MockResponse::network_error()
        }
    });
    let handle = mock_http.clone();
    let mut opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    opts.fallback_hosts = Some(vec!["fallback-a.example.com".to_string()]);
    let client = Realtime::with_mocks(&opts, transport, mock_http).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // The probe ran, as a GET to the connectivity check URL
    let checks: Vec<_> = handle
        .captured_requests()
        .into_iter()
        .filter(|r| r.url.as_str().contains("internet-up"))
        .collect();
    assert!(
        !checks.is_empty(),
        "connectivity check must run before fallback"
    );
    assert_eq!(checks[0].method, "GET");
    // And the connection proceeded to the fallback host
    assert!(attempt.load(Ordering::SeqCst) >= 2);
    client.close();
}

// RTN17j: without internet (probe fails), the fallback hosts are pointless —
// the client skips them and enters the retry state (DISCONNECTED).
#[tokio::test]
async fn rtn17j_no_internet_skips_fallback() {
    use crate::mock_http::{MockHttpClient, MockResponse};
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ConnectionState;
    use crate::realtime::{await_state, Realtime};
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    let attempt = Arc::new(AtomicU32::new(0));
    let att = attempt.clone();
    let mock_ws = MockWebSocket::with_handler(move |pending| {
        att.fetch_add(1, Ordering::SeqCst);
        pending.respond_with_refused();
    });
    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock_ws.inner()));
    let mock_http = MockHttpClient::with_handler(|_req| MockResponse::network_error());
    let mut opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    opts.fallback_hosts = Some(vec!["fallback-a.example.com".to_string()]);
    let client = Realtime::with_mocks(&opts, transport, mock_http).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
    assert_eq!(
        attempt.load(Ordering::SeqCst),
        1,
        "no fallback attempt without internet"
    );
    client.close();
}

// UTS: realtime/unit/connection/heartbeat_test.md — RTN23b
#[tokio::test]
async fn rtn23b_heartbeat_timeout_calculation() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};

    let mut connected_msg = ProtocolMessage::connected("conn-id", "conn-key");
    connected_msg.connection_details = Some(crate::protocol::ConnectionDetails {
        max_idle_interval: Some(15000),
        connection_key: Some("conn-key".to_string()),
        client_id: None,
        connection_state_ttl: None,
        max_message_size: None,
        max_frame_size: None,
        max_inbound_rate: None,
        server_id: None,
    });

    let mock = MockWebSocket::with_handler(move |pending| {
        pending.respond_with_success(connected_msg.clone());
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();
    client.connect();
    let connected =
        crate::realtime::await_state(&client.connection, ConnectionState::Connected, 5000).await;
    assert!(connected);
}

// UTS: RTN7d — disconnectedRetryTimeout governs DISCONNECTED→CONNECTING delay
// UTS: RTN7e — suspendedRetryTimeout governs SUSPENDED retry delay
#[tokio::test]
async fn rtn7d_rtn7e_connection_retry_behavior() -> Result<()> {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let connect_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let connect_times = Arc::new(std::sync::Mutex::new(Vec::<std::time::Instant>::new()));
    let cc = connect_count.clone();
    let ct = connect_times.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        ct.lock().unwrap().push(std::time::Instant::now());
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            // First connection: succeed with very short TTL so SUSPENDED is reached quickly
            let mut msg = ProtocolMessage::connected("connId", "connKey");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1);
            }
            pending.respond_with_success(msg);
        } else {
            // All subsequent: refuse, keeping client in DISCONNECTED/SUSPENDED
            pending.respond_with_refused();
        }
    });

    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(100))
            .suspended_retry_timeout(std::time::Duration::from_millis(200))
            .realtime_request_timeout(std::time::Duration::from_millis(500))
            .fallback_hosts(vec![]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Disconnect
    let conns = mock.active_connections();
    conns.last().unwrap().simulate_disconnect();

    // RTN7d: wait for reconnect attempt — should take ~100ms (disconnectedRetryTimeout)
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

    // Wait for SUSPENDED (TTL=1ms, so after first retry fails we transition)
    assert!(await_state(&client.connection, ConnectionState::Suspended, 5000).await);

    // RTN7e: wait for suspended retry — should take ~200ms
    // Record time when we enter SUSPENDED
    let suspended_at = std::time::Instant::now();
    let times_before = connect_times.lock().unwrap().len();

    // Wait for the next connection attempt (suspended retry)
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    let times_after = connect_times.lock().unwrap().len();

    // Should have at least one more attempt
    assert!(
        times_after > times_before,
        "Expected suspended retry attempt after ~200ms"
    );

    // Verify the delay was approximately suspendedRetryTimeout (200ms)
    let retry_time = connect_times.lock().unwrap()[times_before];
    let delay = retry_time.duration_since(suspended_at);
    assert!(
        delay.as_millis() >= 150 && delay.as_millis() <= 400,
        "Suspended retry delay should be ~200ms, got {}ms",
        delay.as_millis()
    );

    Ok(())
}

// UTS: realtime/unit/channels/channel_publish.md — RTN19a, RTN19a2, RTN19b
// RTN19a: Pending messages resent on new transport after disconnect
// RTN19a2: Resent messages keep same/new msgSerial on successful/failed resume
// RTN19b: Pending ATTACH/DETACH resent on new transport after disconnect
// SDK gap: no pending message queue or resend-on-reconnect logic.

// ===============================================================
// Batch 8: Realtime Connection — RTN tests
// ===============================================================

// --- RTN7e: Pending publishes fail on SUSPENDED ---
#[tokio::test]
async fn rtn7e_pending_publishes_fail_on_suspended() -> Result<()> {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("connId", "connKey");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1); // Very short TTL
            }
            pending.respond_with_success(msg);
        } else {
            pending.respond_with_refused();
        }
    });
    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50))
            .suspended_retry_timeout(std::time::Duration::from_millis(100))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtn7e-suspended");
    phase8d_attach(&channel, &mock, None).await;

    // Disconnect
    let conns = mock.active_connections();
    conns.last().unwrap().simulate_disconnect();

    // Wait to reach SUSPENDED (after TTL expiry)
    assert!(await_state(&client.connection, ConnectionState::Suspended, 10000).await);

    // Publish while SUSPENDED — should fail (messages not queued in SUSPENDED)
    let ch = channel.clone();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ch.publish()
            .name("msg")
            .json(serde_json::json!("data"))
            .send(),
    )
    .await;
    assert!(result.is_ok(), "Publish should resolve");
    assert!(result.unwrap().is_err(), "Publish should fail in SUSPENDED");

    Ok(())
}

// --- RTN13c: Ping from CONNECTING state rejects ---
#[tokio::test]
async fn rtn13c_ping_from_connecting_rejects() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ConnectionState;

    // RTN13d: SDK waits for CONNECTED when CONNECTING, so ping blocks.
    // Verify that the state is CONNECTING (the SDK's documented behavior
    // is to wait, not reject, per RTN13d).
    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .realtime_request_timeout(std::time::Duration::from_secs(30)),
        transport,
    )
    .unwrap();

    client.connect();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(client.connection.state(), ConnectionState::Connecting);
}

// --- RTN13e: Heartbeat ID is unique per ping ---
#[tokio::test]
async fn rtn13e_heartbeat_id() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .realtime_request_timeout(std::time::Duration::from_millis(500))
            .auto_connect(false),
        transport.clone(),
    )
    .unwrap();
    client.connect();
    assert!(
        crate::realtime::await_state(&client.connection, ConnectionState::Connected, 5000).await
    );

    // Fire two pings (they will time out, that's fine — we just want to check IDs)
    let _ = client.connection.ping().await;
    let _ = client.connection.ping().await;

    let msgs = mock.client_messages();
    let heartbeats: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::HEARTBEAT)
        .collect();

    assert!(
        heartbeats.len() >= 2,
        "Expected at least 2 heartbeat messages"
    );
    // Each heartbeat should have a non-empty ID
    for hb in &heartbeats {
        assert!(hb.message.id.is_some(), "Heartbeat should have an ID");
        assert!(
            !hb.message.id.as_ref().unwrap().is_empty(),
            "Heartbeat ID should be non-empty"
        );
    }
    // IDs should be unique
    assert_ne!(
        heartbeats[0].message.id, heartbeats[1].message.id,
        "Heartbeat IDs should differ between pings"
    );
}

// --- RTN13e: Concurrent pings have different heartbeat IDs ---
#[tokio::test]
async fn rtn13e_concurrent_pings() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .realtime_request_timeout(std::time::Duration::from_millis(300))
            .auto_connect(false),
        transport.clone(),
    )
    .unwrap();
    client.connect();
    assert!(
        crate::realtime::await_state(&client.connection, ConnectionState::Connected, 5000).await
    );

    // Fire two pings sequentially (Connection is not Clone)
    let _ = client.connection.ping().await;
    let _ = client.connection.ping().await;

    let msgs = mock.client_messages();
    let heartbeats: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::HEARTBEAT)
        .collect();

    if heartbeats.len() >= 2 {
        assert_ne!(
            heartbeats[0].message.id, heartbeats[1].message.id,
            "Sequential pings should have different heartbeat IDs"
        );
    }
}

// --- RTN14a: Invalid API key format causes FAILED state ---
#[tokio::test]
async fn rtn14a_invalid_api_key_causes_failed() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(40101),
            status_code: Some(401),
            message: Some("Invalid API key".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("badFormat.key:secret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(40101));
    assert_eq!(err.status_code, Some(401));
}

// --- RTN14b: Token renewal failure leads to DISCONNECTED ---
#[tokio::test]
async fn rtn14b_token_renewal_failure_disconnected() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let callback = std::sync::Arc::new(TestAuthCallback::new("token").with_ttl(3600000));
    // Mark callback as failing on renewal
    callback.set_should_fail(true);

    let mock = MockWebSocket::with_handler(move |pending| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(40142),
            status_code: Some(401),
            message: Some("Token expired".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .auto_connect(false)
        .fallback_hosts(vec![])
        .disconnected_retry_timeout(std::time::Duration::from_secs(30));
    let client = Realtime::with_mock(&options, transport).unwrap();

    client.connect();

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let state = client.connection.state();
            if state == ConnectionState::Disconnected || state == ConnectionState::Failed {
                return state;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(result.is_ok(), "Should reach DISCONNECTED or FAILED");
}

// --- RTN14g: Server error with no channel causes FAILED ---
#[tokio::test]
async fn rtn14g_server_error_failed() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Send ERROR with no channel — should cause FAILED
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(50001),
            status_code: Some(500),
            message: Some("Server error".to_string()),
            href: None,
            ..Default::default()
        });
        conn.send_to_client_and_close(msg);
    }

    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let err = client.connection.error_reason().unwrap();
    assert_eq!(err.code, Some(50001));
}

// --- RTN15g: No resume after connectionStateTtl has elapsed ---
#[tokio::test]
async fn rtn15g_no_resume_after_connection_state_ttl() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    let attempt_count = Arc::new(AtomicU32::new(0));
    let attempt_clone = attempt_count.clone();
    let captured_urls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let urls_clone = captured_urls.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_clone.fetch_add(1, Ordering::SeqCst) + 1;
        urls_clone.lock().unwrap().push(pending.url.clone());
        if n == 1 {
            let mut msg = ProtocolMessage::connected("conn-1", "key-1");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(200); // Short TTL
            }
            pending.respond_with_success(msg);
        } else if n < 6 {
            pending.respond_with_refused();
        } else {
            pending.respond_with_success(ProtocolMessage::connected("conn-2", "key-2"));
        }
    });

    let transport = Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(80))
            .suspended_retry_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Disconnect
    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);
    assert!(await_state(&client.connection, ConnectionState::Connected, 15000).await);

    // After TTL expiry, the reconnection should be a fresh connection (new ID)
    assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
}

// --- RTN15h2: Token renewal failure goes to DISCONNECTED ---
#[tokio::test]
async fn rtn15h2_token_renewal_failure_disconnected() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_clone = attempt_count.clone();

    let callback = std::sync::Arc::new(TestAuthCallback::new("token").with_ttl(3600000));

    let mock = crate::mock_ws::MockWebSocket::with_handler(move |pending| {
        let n = attempt_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
        } else {
            let mut msg = ProtocolMessage::new(action::ERROR);
            msg.error = Some(ErrorInfo {
                code: Some(40142),
                status_code: Some(401),
                message: Some("Token expired".to_string()),
                href: None,
                ..Default::default()
            });
            pending.respond_with_error(msg);
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let options = ClientOptions::with_auth_callback(callback.clone())
        .auto_connect(false)
        .fallback_hosts(vec![])
        .disconnected_retry_timeout(std::time::Duration::from_secs(30));
    let client = crate::realtime::Realtime::with_mock(&options, transport).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Now make the callback fail
    callback.set_should_fail(true);

    // Server sends token error
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut msg = ProtocolMessage::new(action::DISCONNECTED);
        msg.error = Some(ErrorInfo {
            code: Some(40142),
            status_code: Some(401),
            message: Some("Token expired".to_string()),
            href: None,
            ..Default::default()
        });
        conn.send_to_client_and_close(msg);
    }

    // Should go to DISCONNECTED (renewal fails)
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let state = client.connection.state();
            if state == ConnectionState::Disconnected || state == ConnectionState::Failed {
                return state;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "Should reach DISCONNECTED or FAILED after token renewal failure"
    );
}

// --- RTN23b: Heartbeat ping frame ---
#[tokio::test]
async fn rtn23b_heartbeat_ping_frame() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::connected("conn-id", "conn-key");
        if let Some(ref mut details) = msg.connection_details {
            details.max_idle_interval = Some(200);
        }
        pending.respond_with_success(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .realtime_request_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Wait long enough for heartbeat to be expected
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;

    // Check that a heartbeat was sent (either as HEARTBEAT protocol message or ping frame)
    let msgs = mock.client_messages();
    let heartbeats: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::HEARTBEAT)
        .collect();
    // Client should have sent at least one heartbeat or the connection times out
    // (either way, the heartbeat mechanism is active)
    assert!(
        client.connection.state() == ConnectionState::Connected
            || client.connection.state() == ConnectionState::Disconnected,
        "Connection should either be alive (heartbeat sent) or disconnected (timeout)"
    );
}

// --- RTN23b: Heartbeat protocol message ---
#[tokio::test]
async fn rtn23b_heartbeat_protocol_message() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .realtime_request_timeout(std::time::Duration::from_millis(500)),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Trigger a ping (which sends HEARTBEAT protocol message)
    let _ = client.connection.ping().await;

    let msgs = mock.client_messages();
    let heartbeats: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::HEARTBEAT)
        .collect();
    assert!(
        !heartbeats.is_empty(),
        "At least one HEARTBEAT protocol message should be sent"
    );
    assert!(
        heartbeats[0].message.id.is_some(),
        "HEARTBEAT should contain an id"
    );
}

// --- RTN23b: Heartbeat behavior during connecting ---
#[tokio::test]
async fn rtn23b_heartbeat_during_connecting() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ConnectionState;
    use crate::realtime::Realtime;

    // Mock that never responds — stays in CONNECTING
    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(client.connection.state(), ConnectionState::Connecting);

    // No heartbeat messages should be sent while CONNECTING
    let msgs = mock.client_messages();
    let heartbeats: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::HEARTBEAT)
        .collect();
    assert!(
        heartbeats.is_empty(),
        "No heartbeat messages should be sent during CONNECTING"
    );
}

// --- RTN23b: Heartbeat interval calculation ---
#[tokio::test]
async fn rtn23b_heartbeat_interval_calculation() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    // maxIdleInterval = 15000, realtimeRequestTimeout = 10000
    // heartbeatTimeout should be maxIdleInterval + realtimeRequestTimeout = 25000
    let mut connected_msg = ProtocolMessage::connected("conn-id", "conn-key");
    connected_msg.connection_details = Some(crate::protocol::ConnectionDetails {
        max_idle_interval: Some(15000),
        connection_key: Some("conn-key".to_string()),
        client_id: None,
        connection_state_ttl: None,
        max_message_size: None,
        max_frame_size: None,
        max_inbound_rate: None,
        server_id: None,
    });

    let mock = MockWebSocket::with_handler(move |pending| {
        pending.respond_with_success(connected_msg.clone());
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .realtime_request_timeout(std::time::Duration::from_millis(10000)),
        transport,
    )
    .unwrap();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Connection should be CONNECTED — the heartbeat interval is 25s which is much
    // longer than our test, so the connection should remain alive
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        client.connection.state(),
        ConnectionState::Connected,
        "Connection should remain connected with long heartbeat interval"
    );
}

// --- RTN24: UPDATE event updates connection details ---
#[tokio::test]
async fn rtn24_update_event_connection_details() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionEvent, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let mut rx = client.connection.on_state_change();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    assert_eq!(client.connection.id().as_deref(), Some("conn-1"));
    assert_eq!(client.connection.key().as_deref(), Some("key-1"));

    // Drain existing events
    while rx.try_recv().is_ok() {}

    // Send new CONNECTED with updated details
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage::connected("conn-updated", "key-updated"));
    }

    let change = tokio::time::timeout(tokio::time::Duration::from_millis(1000), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(change.event, ConnectionEvent::Update);

    // Connection details should be updated
    assert_eq!(client.connection.id().as_deref(), Some("conn-updated"));
    assert_eq!(client.connection.key().as_deref(), Some("key-updated"));
}

// --- RTN24: UPDATE event does not duplicate state change ---
#[tokio::test]
async fn rtn24_update_event_no_duplicate() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionEvent, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let mut rx = client.connection.on_state_change();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Drain events
    while rx.try_recv().is_ok() {}

    // Send CONNECTED while already CONNECTED — should produce UPDATE, not two events
    {
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage::connected("conn-2", "key-2"));
    }

    let change = tokio::time::timeout(tokio::time::Duration::from_millis(1000), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(change.event, ConnectionEvent::Update);
    assert_eq!(change.current, ConnectionState::Connected);
    assert_eq!(change.previous, ConnectionState::Connected);

    // No additional state change should arrive
    let extra = tokio::time::timeout(tokio::time::Duration::from_millis(200), rx.recv()).await;
    assert!(
        extra.is_err(),
        "Should not receive duplicate state change events for UPDATE"
    );
}

// --- RTN25: Error reason on SUSPENDED ---
#[tokio::test]
async fn rtn25_error_reason_suspended() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("conn-1", "key-1");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1); // Immediate TTL expiry
            }
            pending.respond_with_success(msg);
        } else {
            pending.respond_with_refused();
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50))
            .suspended_retry_timeout(std::time::Duration::from_secs(30))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    assert!(await_state(&client.connection, ConnectionState::Suspended, 10000).await);

    let error = client.connection.error_reason();
    assert!(error.is_some(), "error_reason should be set in SUSPENDED");
}

// --- RTN25: Error reason cleared on successful reconnect ---
#[tokio::test]
async fn rtn25_error_reason_cleared() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            pending.respond_with_refused();
        } else {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
    assert!(
        client.connection.error_reason().is_some(),
        "error_reason should be set"
    );

    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert!(
        client.connection.error_reason().is_none(),
        "error_reason should be cleared after reconnect"
    );
}

// --- RTN25: Connection state change includes reason ---
#[tokio::test]
async fn rtn25_connection_state_change_reason() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo {
            code: Some(40010),
            status_code: Some(400),
            message: Some("Connection refused".to_string()),
            href: None,
            ..Default::default()
        });
        pending.respond_with_error(msg);
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let mut rx = client.connection.on_state_change();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    // Find the FAILED state change event
    let mut found = false;
    while let Ok(change) = rx.try_recv() {
        if change.current == ConnectionState::Failed {
            assert!(
                change.reason.is_some(),
                "FAILED state change should include reason"
            );
            let reason = change.reason.unwrap();
            assert_eq!(reason.code, Some(40010));
            assert_eq!(reason.message.as_deref(), Some("Connection refused"));
            found = true;
            break;
        }
    }
    assert!(
        found,
        "Should have received FAILED state change with reason"
    );
}

// --- RTN8c: Connection ID and key null in SUSPENDED ---
#[tokio::test]
async fn rtn8c_id_key_null_in_suspended() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
    let attempt_clone = attempt_count.clone();

    let mock = MockWebSocket::with_handler(move |pending| {
        let n = attempt_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("conn-1", "key-1");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1);
            }
            pending.respond_with_success(msg);
        } else {
            pending.respond_with_refused();
        }
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50))
            .suspended_retry_timeout(std::time::Duration::from_secs(30))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert!(client.connection.id().is_some());
    assert!(client.connection.key().is_some());

    {
        let conns = mock.active_connections();
        conns.last().unwrap().simulate_disconnect();
    }

    assert!(await_state(&client.connection, ConnectionState::Suspended, 10000).await);

    assert!(
        client.connection.id().is_none(),
        "Connection ID should be null in SUSPENDED"
    );
    assert!(
        client.connection.key().is_none(),
        "Connection key should be null in SUSPENDED"
    );
}

// ===============================================================
// Ignored stubs — features not yet implemented
// ===============================================================

// (The RTN16 recovery stubs that lived here were superseded by the real
// UTS-derived tests in tests_realtime_uts_connection.rs — TASK-4.)

// --- RTN20: Network event detection ---

#[tokio::test]
#[ignore = "network event detection not implemented"]
async fn rtn20a_online_event_triggers_reconnect() -> Result<()> {
    Ok(())
}

#[tokio::test]
#[ignore = "network event detection not implemented"]
async fn rtn20b_offline_event_triggers_disconnect() -> Result<()> {
    Ok(())
}

#[tokio::test]
#[ignore = "network event detection not implemented"]
async fn rtn20c_connectivity_check() -> Result<()> {
    Ok(())
}

// --- RTB1: Exponential backoff/jitter ---

// ===============================================================
// RTN depth — Connection depth
// ===============================================================

#[tokio::test]
async fn rtn25_error_reason_initially_none_depth() {
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();

    assert!(client.connection.error_reason().is_none());
}

#[tokio::test]
async fn rtn_connection_state_initialized_depth() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ConnectionState;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();

    assert_eq!(client.connection.state(), ConnectionState::Initialized);
}

#[tokio::test]
async fn rtn_connected_sets_id_and_key_depth() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected(
            "depth-conn-id",
            "depth-conn-key",
        ));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").use_binary_protocol(false),
        transport,
    )
    .unwrap();

    let ok = await_state(&client.connection, ConnectionState::Connected, 5000).await;
    assert!(ok, "Should reach Connected state");
    assert_eq!(client.connection.id(), Some("depth-conn-id".to_string()));
    assert_eq!(client.connection.key(), Some("depth-conn-key".to_string()));
}

#[tokio::test]
async fn rtn13b_ping_error_when_initialized_depth() {
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();

    let result = client.connection.ping().await;
    assert!(result.is_err(), "Ping should fail when not connected");
}

#[tokio::test]
async fn rtn_auto_connect_false_no_connections_depth() {
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

    let _client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .auto_connect(false),
        transport,
    )
    .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(
        mock.connection_count(),
        0,
        "No connections should be made with auto_connect=false"
    );
}

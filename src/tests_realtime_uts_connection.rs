#![cfg(test)]

//! Stage 5.1 connection-foundation tests, derived from the UTS specs
//! (DESIGN.md Realtime §12: tests are written from the uts/realtime/unit
//! pseudo-code; ported tests are a cross-check/quarry only).
//!
//! Sources:
//! - uts/realtime/unit/connection/auto_connect_test.md (RTN3)
//! - uts/realtime/unit/connection/connection_id_key_test.md (RTN8/RTN9)
//! - uts/realtime/unit/connection/when_state_test.md (RTN26)
//! - uts/realtime/unit/connection/error_reason_test.md (RTN25 — FAILED case)
//! - features spec RTN4/RTN11/RTN12 for the core lifecycle sequences

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::error::ErrorInfo;
use crate::mock_ws::{MockTransport, MockWebSocket};
use crate::options::ClientOptions;
use crate::protocol::{action, ConnectionState, ConnectionStateChange, ProtocolMessage};
use crate::realtime::{await_state, Realtime};

fn connected_msg(id: &str, key: &str) -> ProtocolMessage {
    ProtocolMessage::connected(id, key)
}

fn client_with(mock: &MockWebSocket, opts: ClientOptions) -> Realtime {
    let transport = Arc::new(MockTransport::new(mock.inner()));
    Realtime::with_mock(&opts, transport).unwrap()
}

fn default_opts() -> ClientOptions {
    ClientOptions::new("appId.keyId:keySecret")
}

// ============================================================================
// RTN3 — autoConnect
// ============================================================================

// UTS: realtime/unit/RTN3/auto-connect-true-0
#[tokio::test]
async fn rtn3_auto_connect_true_connects_immediately() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("connection-id", "connection-key"));
    });
    // Default autoConnect (true); connect() is NOT called
    let client = client_with(&mock, default_opts());

    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(client.connection.id().as_deref(), Some("connection-id"));
    client.close();
}

// UTS: realtime/unit/RTN3/auto-connect-false-1
#[tokio::test]
async fn rtn3_auto_connect_false_does_not_connect() {
    let attempted = Arc::new(AtomicBool::new(false));
    let attempted_c = attempted.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        attempted_c.store(true, Ordering::SeqCst);
        conn.respond_with_success(connected_msg("connection-id", "connection-key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    assert!(
        !attempted.load(Ordering::SeqCst),
        "no connection attempt expected"
    );
    assert_eq!(client.connection.state(), ConnectionState::Initialized);
    client.close();
}

// UTS: realtime/unit/RTN3 (explicit connect after autoConnect: false)
#[tokio::test]
async fn rtn3_explicit_connect_after_auto_connect_false() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("connection-id", "connection-key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(mock.connection_count(), 1);
    client.close();
}

// ============================================================================
// RTN8/RTN9 — connection id and key
// ============================================================================

// UTS: realtime/unit/RTN8a/id-unset-until-connected-0
// UTS: realtime/unit/RTN9a/key-unset-until-connected-0
#[tokio::test]
async fn rtn8a_rtn9a_id_and_key_unset_until_connected() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("the-id", "the-key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    // Before connecting: both unset
    assert!(client.connection.id().is_none());
    assert!(client.connection.key().is_none());

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(client.connection.id().as_deref(), Some("the-id"));
    assert_eq!(client.connection.key().as_deref(), Some("the-key"));
    client.close();
}

// UTS: realtime/unit/RTN8b/id-unique-per-connection-0
// UTS: realtime/unit/RTN9b/key-unique-per-connection-0
#[tokio::test]
async fn rtn8b_rtn9b_id_and_key_unique_per_connection() {
    let count = Arc::new(AtomicU32::new(0));
    let count_c = count.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = count_c.fetch_add(1, Ordering::SeqCst) + 1;
        conn.respond_with_success(connected_msg(
            &format!("conn-id-{}", n),
            &format!("conn-key-{}", n),
        ));
    });
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let client1 =
        Realtime::with_mock(&default_opts().auto_connect(false), transport.clone()).unwrap();
    let client2 = Realtime::with_mock(&default_opts().auto_connect(false), transport).unwrap();

    client1.connect();
    assert!(await_state(&client1.connection, ConnectionState::Connected, 5000).await);
    client2.connect();
    assert!(await_state(&client2.connection, ConnectionState::Connected, 5000).await);

    assert_ne!(client1.connection.id(), client2.connection.id());
    assert_eq!(client1.connection.id().as_deref(), Some("conn-id-1"));
    assert_eq!(client2.connection.id().as_deref(), Some("conn-id-2"));
    assert_ne!(client1.connection.key(), client2.connection.key());
    assert_eq!(client1.connection.key().as_deref(), Some("conn-key-1"));
    assert_eq!(client2.connection.key().as_deref(), Some("conn-key-2"));
    client1.close();
    client2.close();
}

// UTS: realtime/unit/RTN8c/id-null-after-closed-0
// UTS: realtime/unit/RTN9c/key-null-after-closed-0
#[tokio::test]
async fn rtn8c_rtn9c_id_and_key_null_after_closed() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("the-id", "the-key"));
        // keep the server handle alive in the closure; CLOSE is answered below
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    client.close();
    // The server answers CLOSE with CLOSED
    let conn = mock.active_connection();
    conn.send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

    assert!(
        client.connection.id().is_none(),
        "RTN8c: id null after CLOSED"
    );
    assert!(
        client.connection.key().is_none(),
        "RTN9c: key null after CLOSED"
    );
}

// UTS: realtime/unit/RTN8c/id-key-null-after-failed-1
#[tokio::test]
async fn rtn8c_rtn9c_id_and_key_null_after_failed() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("the-id", "the-key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // A connection-level ERROR is fatal
    let conn = mock.active_connection();
    let mut error_msg = ProtocolMessage::new(action::ERROR);
    error_msg.error = Some(ErrorInfo::with_status(40400, 404, "fatal"));
    conn.send_to_client_and_close(error_msg);
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    assert!(client.connection.id().is_none());
    assert!(client.connection.key().is_none());
}

// ============================================================================
// RTN25 — errorReason
// ============================================================================

// UTS: realtime/unit/RTN25/error-reason-on-failed-0
#[tokio::test]
async fn rtn25_error_reason_set_on_failed() {
    let mock = MockWebSocket::with_handler(|conn| {
        let mut error_msg = ProtocolMessage::new(action::ERROR);
        error_msg.error = Some(ErrorInfo::with_status(40171, 401, "no way to renew"));
        conn.respond_with_error(error_msg);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    assert!(client.connection.error_reason().is_none());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let reason = client.connection.error_reason().expect("errorReason set");
    assert_eq!(reason.code, Some(40171));
    // RTN4f-shaped: the state-change event carried the same reason — checked
    // in the lifecycle test below.
}

// ============================================================================
// RTN26 — whenState
// ============================================================================

// UTS: realtime/unit/RTN26a/immediate-callback-current-state-0
#[tokio::test]
async fn rtn26a_when_state_immediate_if_in_state() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let invoked = Arc::new(AtomicBool::new(false));
    let invoked_c = invoked.clone();
    client
        .connection
        .when_state(ConnectionState::Connected, move |change| {
            assert_eq!(change.current, ConnectionState::Connected);
            invoked_c.store(true, Ordering::SeqCst);
        });
    // RTN26a: fires synchronously when already in the target state
    assert!(invoked.load(Ordering::SeqCst));
    client.close();
}

// UTS: realtime/unit/RTN26b/deferred-callback-future-state-0
#[tokio::test]
async fn rtn26b_when_state_deferred_until_transition() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    assert_eq!(client.connection.state(), ConnectionState::Initialized);

    let invoked = Arc::new(AtomicBool::new(false));
    let captured: Arc<StdMutex<Option<ConnectionStateChange>>> = Arc::new(StdMutex::new(None));
    let (invoked_c, captured_c) = (invoked.clone(), captured.clone());
    client
        .connection
        .when_state(ConnectionState::Connected, move |change| {
            *captured_c.lock().unwrap() = Some(change);
            invoked_c.store(true, Ordering::SeqCst);
        });
    assert!(
        !invoked.load(Ordering::SeqCst),
        "must not fire before the transition"
    );

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert!(invoked.load(Ordering::SeqCst));
    let change = captured.lock().unwrap().take().expect("change delivered");
    assert!(matches!(
        change.previous,
        ConnectionState::Initialized | ConnectionState::Connecting
    ));
    assert_eq!(change.current, ConnectionState::Connected);
    client.close();
}

// UTS: realtime/unit/RTN26b/fires-only-once-1
#[tokio::test]
async fn rtn26b_when_state_fires_only_once() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    let count = Arc::new(AtomicU32::new(0));
    let count_c = count.clone();
    client
        .connection
        .when_state(ConnectionState::Connected, move |_| {
            count_c.fetch_add(1, Ordering::SeqCst);
        });

    // Connect → CONNECTED (fires), close → CLOSED, connect → CONNECTED again
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    client.close();
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert_eq!(count.load(Ordering::SeqCst), 1, "whenState is one-shot");
    client.close();
}

// UTS: realtime/unit/RTN26a/multiple-whenstate-calls-1
#[tokio::test]
async fn rtn26a_multiple_when_state_listeners_all_fire() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    let count = Arc::new(AtomicU32::new(0));
    for _ in 0..3 {
        let count_c = count.clone();
        client
            .connection
            .when_state(ConnectionState::Connected, move |_| {
                count_c.fetch_add(1, Ordering::SeqCst);
            });
    }

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(count.load(Ordering::SeqCst), 3, "every listener fires");
    client.close();
}

// UTS: realtime/unit/RTN26a/no-fire-for-past-state-2
#[tokio::test]
async fn rtn26a_no_fire_for_state_passed_through_earlier() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // CONNECTING was passed through; a listener registered NOW must not fire
    let invoked = Arc::new(AtomicBool::new(false));
    let invoked_c = invoked.clone();
    client
        .connection
        .when_state(ConnectionState::Connecting, move |_| {
            invoked_c.store(true, Ordering::SeqCst);
        });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(!invoked.load(Ordering::SeqCst), "past states must not fire");
    client.close();
}

// UTS: realtime/unit/RTN26/whenstate-different-states-0
#[tokio::test]
async fn rtn26_when_state_different_states() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    let connected = Arc::new(AtomicBool::new(false));
    let closed = Arc::new(AtomicBool::new(false));
    let (connected_c, closed_c) = (connected.clone(), closed.clone());
    client
        .connection
        .when_state(ConnectionState::Connected, move |_| {
            connected_c.store(true, Ordering::SeqCst);
        });
    client
        .connection
        .when_state(ConnectionState::Closed, move |_| {
            closed_c.store(true, Ordering::SeqCst);
        });

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(connected.load(Ordering::SeqCst));
    assert!(!closed.load(Ordering::SeqCst));

    client.close();
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(closed.load(Ordering::SeqCst));
}

// ============================================================================
// RTN4/RTN11/RTN12 — lifecycle sequences (features spec; UTS mock conventions)
// ============================================================================

// RTN4a/RTN4b/RTN4d/RTN4e: the connect lifecycle emits ordered state changes
#[tokio::test]
async fn rtn4_connect_lifecycle_event_sequence() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    let changes: Arc<StdMutex<Vec<ConnectionState>>> = Arc::new(StdMutex::new(Vec::new()));
    let changes_c = changes.clone();
    let mut events = client.connection.on_state_change();
    let recorder = tokio::spawn(async move {
        while let Ok(change) = events.recv().await {
            changes_c.lock().unwrap().push(change.current);
            if change.current == ConnectionState::Closed {
                break;
            }
        }
    });

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    client.close();
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(1), recorder).await;

    // RTN4: connecting → connected → closing → closed, in order
    let seq = changes.lock().unwrap().clone();
    assert_eq!(
        seq,
        vec![
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Closing,
            ConnectionState::Closed,
        ],
        "ordered lifecycle events"
    );
}

// RTN12a: close() sends CLOSE on the wire and resolves on the server's CLOSED
#[tokio::test]
async fn rtn12a_close_sends_close_protocol_message() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closing, 5000).await);

    // The client sent CLOSE on the wire
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::CLOSE)
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "CLOSE was never sent");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
}

// RTN12d: close() from a non-active state goes directly to CLOSED
#[tokio::test]
async fn rtn12d_close_from_initialized_goes_to_closed() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    assert_eq!(client.connection.state(), ConnectionState::Initialized);
    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
    assert_eq!(
        mock.connection_count(),
        0,
        "no connection was ever attempted"
    );
}

// RTN11: connect() after CLOSED starts a fresh connection
#[tokio::test]
async fn rtn11_reconnect_after_close() {
    let count = Arc::new(AtomicU32::new(0));
    let count_c = count.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = count_c.fetch_add(1, Ordering::SeqCst) + 1;
        let c =
            conn.respond_with_success(connected_msg(&format!("id-{}", n), &format!("key-{}", n)));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    client.close();
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(client.connection.id().as_deref(), Some("id-2"));
    assert_eq!(mock.connection_count(), 2);
    client.close();
}

// RTN4h: an additional CONNECTED while connected emits UPDATE, not a
// state change, and refreshes id/key
#[tokio::test]
async fn rtn4h_additional_connected_emits_update() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("first-id", "first-key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let mut events = client.connection.on_state_change();
    mock.active_connection()
        .send_to_client(connected_msg("second-id", "second-key"));

    let change = tokio::time::timeout(tokio::time::Duration::from_secs(2), events.recv())
        .await
        .expect("update event within 2s")
        .expect("event stream open");
    assert_eq!(change.event, crate::protocol::ConnectionEvent::Update);
    assert_eq!(change.current, ConnectionState::Connected);
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert_eq!(client.connection.id().as_deref(), Some("second-id"));
    assert_eq!(client.connection.key().as_deref(), Some("second-key"));
    client.close();
}

// RTN2: the connection URL carries v=6, the format, and the credentials
#[tokio::test]
async fn rtn2_connection_url_params() {
    let captured_url: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
    let captured_c = captured_url.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        *captured_c.lock().unwrap() = Some(conn.url.clone());
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let url = captured_url.lock().unwrap().clone().expect("url captured");
    let parsed = url::Url::parse(&url).unwrap();
    let q: std::collections::HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(q.get("v").map(String::as_str), Some("6")); // RTN2f
    assert_eq!(q.get("format").map(String::as_str), Some("msgpack")); // RTN2a
    assert_eq!(
        q.get("key").map(String::as_str),
        Some("appId.keyId:keySecret") // RTN2e: basic clients send the key
    );
    client.close();
}

// ============================================================================
// Live integration: the real WebSocket transport against the nonprod sandbox
// (per-stage discipline: at least one live proof per stage)
// ============================================================================

#[tokio::test]
async fn live_connect_and_close_against_sandbox() {
    let app = crate::tests_rest_integration::get_sandbox().await;
    let opts = ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 10000).await,
        "must reach CONNECTED against the live sandbox"
    );
    assert!(
        client.connection.id().is_some(),
        "live connection id assigned"
    );
    assert!(
        client.connection.key().is_some(),
        "live connection key assigned"
    );

    // RTN13 live: ping over the real connection
    let rtt = client.connection.ping().await.expect("live ping");
    assert!(rtt < std::time::Duration::from_secs(10));

    client.close();
    assert!(
        await_state(&client.connection, ConnectionState::Closed, 10000).await,
        "must reach CLOSED after close()"
    );
    assert!(client.connection.id().is_none(), "RTN8c live");
}

// ============================================================================
// Stage 5.2 — failures, retries, suspension, resume, ping, heartbeat
// Sources: uts/realtime/unit/connection/{connection_open_failures,
// connection_failures, backoff_jitter, connection_ping, heartbeat}_test.md
// ============================================================================

use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenParams};
use std::sync::atomic::AtomicUsize;

/// A renewable token source that never touches the network.
struct SeqTokenCb {
    count: Arc<AtomicUsize>,
}
impl AuthCallback for SeqTokenCb {
    fn token<'a>(
        &'a self,
        _params: &'a TokenParams,
    ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = crate::error::Result<AuthToken>> + 'a>>
    {
        let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            Ok(AuthToken::Details(TokenDetails {
                token: format!("token-{}", n),
                expires: Some(chrono::Utc::now().timestamp_millis() + 3_600_000),
                ..Default::default()
            }))
        })
    }
}

fn token_client(mock: &MockWebSocket, count: Arc<AtomicUsize>) -> Realtime {
    let opts =
        ClientOptions::with_auth_callback(Arc::new(SeqTokenCb { count })).auto_connect(false);
    client_with(mock, opts)
}

fn token_error_msg() -> ProtocolMessage {
    let mut msg = ProtocolMessage::new(action::ERROR);
    msg.error = Some(ErrorInfo::with_status(40142, 401, "Token expired"));
    msg
}

/// Await the mock seeing the nth connection attempt — used to step past
/// transient reconnect states without racing them (per the UTS mock doc).
async fn await_connection_count(mock: &MockWebSocket, n: u32, timeout_ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
    while mock.connection_count() < n {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    true
}

// UTS: realtime/unit/RTB1a/backoff-coefficient-sequence-0
#[test]
fn rtb1a_backoff_coefficient_sequence() {
    use crate::connection::backoff_coefficient;
    assert_eq!(backoff_coefficient(1), 1.0);
    assert_eq!(backoff_coefficient(2), 4.0 / 3.0);
    assert_eq!(backoff_coefficient(3), 5.0 / 3.0);
    for n in 4..=10 {
        assert_eq!(backoff_coefficient(n), 2.0, "n={} capped at 2", n);
    }
}

// UTS: realtime/unit/RTB1b/jitter-coefficient-range-0
#[test]
fn rtb1b_jitter_coefficient_range() {
    use crate::connection::jitter_coefficient;
    let samples: Vec<f64> = (0..1000).map(|_| jitter_coefficient()).collect();
    for j in &samples {
        assert!((0.8..=1.0).contains(j), "jitter {} out of range", j);
    }
    let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
    assert!((0.85..=0.95).contains(&mean), "mean {} not ~0.9", mean);
    let (min, max) = samples
        .iter()
        .fold((f64::MAX, f64::MIN), |(lo, hi), &v| (lo.min(v), hi.max(v)));
    assert!(max - min > 0.05, "degenerate jitter distribution");
}

// UTS: realtime/unit/RTN14a/invalid-key-failed-0
#[tokio::test]
async fn rtn14a_fatal_error_during_connect_goes_failed() {
    let mock = MockWebSocket::with_handler(|conn| {
        let mut msg = ProtocolMessage::new(action::ERROR);
        msg.error = Some(ErrorInfo::with_status(40400, 404, "No such app/key"));
        conn.respond_with_error(msg);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);
    assert_eq!(
        client.connection.error_reason().and_then(|e| e.code),
        Some(40400)
    );
    // FAILED is terminal: no retry
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert_eq!(mock.connection_count(), 1);
}

// UTS: realtime/unit/RTN14b/token-error-with-renewal-0
#[tokio::test]
async fn rtn14b_token_error_during_connect_renews_and_retries() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let urls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let urls_c = urls.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        urls_c.lock().unwrap().push(conn.url.clone());
        if n == 1 {
            conn.respond_with_error(token_error_msg());
        } else {
            conn.respond_with_success(connected_msg("id", "key"));
        }
    });
    let tokens = Arc::new(AtomicUsize::new(0));
    let client = token_client(&mock, tokens.clone());

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "renewed and retried once"
    );
    assert_eq!(
        tokens.load(Ordering::SeqCst),
        2,
        "a fresh token was acquired"
    );
    let urls = urls.lock().unwrap();
    assert!(urls[0].contains("accessToken=token-1"));
    assert!(
        urls[1].contains("accessToken=token-2"),
        "retry uses the new token"
    );
    client.close();
}

// UTS: realtime/unit/RSA4a/token-error-no-renewal-0
#[tokio::test]
async fn rsa4a_token_error_without_renewal_goes_failed() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_error(token_error_msg());
    });
    // A static token cannot be renewed
    let opts = ClientOptions::with_token("static-token".to_string()).auto_connect(false);
    let client = client_with(&mock, opts);
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);
    assert_eq!(
        client.connection.error_reason().and_then(|e| e.code),
        Some(40142)
    );
}

// UTS: realtime/unit/RTN14c/connection-timeout-0
#[tokio::test(start_paused = true)]
async fn rtn14c_connect_attempt_times_out() {
    // The handler never responds: the attempt must time out
    let mock = MockWebSocket::with_handler(|conn| {
        std::mem::forget(conn);
    });
    let opts = default_opts()
        .auto_connect(false)
        .fallback_hosts(vec![]) // isolate RTN14 retry from RTN17 cycling
        .realtime_request_timeout(std::time::Duration::from_secs(2));
    let client = client_with(&mock, opts);
    client.connect();

    // Paused clock auto-advances when idle: the timeout fires
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 10000).await);
    let reason = client.connection.error_reason().expect("timeout reason");
    assert_eq!(
        reason.code,
        Some(crate::error::ErrorCode::ConnectionTimedOut.code())
    );
}

// UTS: realtime/unit/RTN14d/retry-recoverable-failure-0
#[tokio::test(start_paused = true)]
async fn rtn14d_retries_after_recoverable_failure() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            conn.respond_with_refused();
        } else {
            conn.respond_with_success(connected_msg("id", "key"));
        }
    });
    let opts = default_opts()
        .auto_connect(false)
        .fallback_hosts(vec![]) // isolate RTN14 retry from RTN17 cycling
        .disconnected_retry_timeout(std::time::Duration::from_secs(1));
    let client = client_with(&mock, opts);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
    // The retry timer fires (paused clock auto-advances)
    assert!(await_state(&client.connection, ConnectionState::Connected, 10000).await);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    client.close();
}

// UTS: realtime/unit/RTN14e/disconnected-to-suspended-0
#[tokio::test(start_paused = true)]
async fn rtn14e_disconnected_becomes_suspended_after_ttl() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_refused();
    });
    let opts = default_opts()
        .auto_connect(false)
        .fallback_hosts(vec![]) // isolate RTN14 from RTN17 cycling
        .disconnected_retry_timeout(std::time::Duration::from_secs(1))
        .connection_state_ttl(std::time::Duration::from_secs(5));
    let client = client_with(&mock, opts);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
    // After connectionStateTtl the connection rests at SUSPENDED
    assert!(await_state(&client.connection, ConnectionState::Suspended, 20000).await);
    assert!(client.connection.error_reason().is_some());
    client.close();
}

// UTS: realtime/unit/RTN14f/suspended-retries-indefinitely-0
#[tokio::test(start_paused = true)]
async fn rtn14f_suspended_keeps_retrying_then_connects() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        if n < 6 {
            conn.respond_with_refused();
        } else {
            conn.respond_with_success(connected_msg("id", "key"));
        }
    });
    let opts = default_opts()
        .auto_connect(false)
        .fallback_hosts(vec![]) // isolate RTN14 from RTN17 cycling
        .disconnected_retry_timeout(std::time::Duration::from_secs(1))
        .suspended_retry_timeout(std::time::Duration::from_secs(3))
        .connection_state_ttl(std::time::Duration::from_secs(4));
    let client = client_with(&mock, opts);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Suspended, 30000).await);
    // Suspended retries continue until the server accepts
    assert!(await_state(&client.connection, ConnectionState::Connected, 60000).await);
    assert!(attempts.load(Ordering::SeqCst) >= 6);
    client.close();
}

// UTS: realtime/unit/RTN15a/unexpected-transport-disconnect-0
// UTS: realtime/unit/RTN15b/successful-resume-0 (+RTN15c6, RTN15e)
#[tokio::test]
async fn rtn15a_rtn15b_unexpected_disconnect_resumes_immediately() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let urls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let urls_c = urls.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        urls_c.lock().unwrap().push(conn.url.clone());
        if n == 1 {
            let c = conn.respond_with_success(connected_msg("connection-1", "key-1"));
            std::mem::forget(c);
        } else {
            // Resume succeeds: same connectionId, updated key (RTN15e)
            let c = conn.respond_with_success(connected_msg("connection-1", "key-1-updated"));
            std::mem::forget(c);
        }
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    let changes: Arc<StdMutex<Vec<ConnectionState>>> = Arc::new(StdMutex::new(Vec::new()));
    let changes_c = changes.clone();
    let mut events = client.connection.on_state_change();
    tokio::spawn(async move {
        while let Ok(change) = events.recv().await {
            changes_c.lock().unwrap().push(change.current);
        }
    });

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(client.connection.id().as_deref(), Some("connection-1"));

    mock.active_connection().simulate_disconnect();
    assert!(
        await_connection_count(&mock, 2, 5000).await,
        "reconnect attempt expected"
    );
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // RTN15c6: resumed — same id; RTN15e: key updated
    assert_eq!(client.connection.id().as_deref(), Some("connection-1"));
    assert_eq!(client.connection.key().as_deref(), Some("key-1-updated"));
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    // RTN15b1: the second attempt carried resume=<old key>
    let urls = urls.lock().unwrap();
    assert!(
        !urls[0].contains("resume="),
        "first attempt has no resume param"
    );
    assert!(
        urls[1].contains("resume=key-1"),
        "resume with previous key: {}",
        urls[1]
    );

    // The state sequence passed through disconnected→connecting
    let seq = changes.lock().unwrap().clone();
    let expected = [
        ConnectionState::Connecting,
        ConnectionState::Connected,
        ConnectionState::Disconnected,
        ConnectionState::Connecting,
        ConnectionState::Connected,
    ];
    let mut it = seq.iter();
    for want in expected {
        assert!(
            it.any(|&s| s == want),
            "sequence {:?} missing {:?} in order",
            seq,
            want
        );
    }
    client.close();
}

// UTS: realtime/unit/RTN15c7/failed-resume-new-id-0
#[tokio::test]
async fn rtn15c7_failed_resume_gets_new_connection_id() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            let c = conn.respond_with_success(connected_msg("connection-1", "key-1"));
            std::mem::forget(c);
        } else {
            // Resume failed: the server assigns a NEW connection id
            let mut msg = connected_msg("connection-2", "key-2");
            msg.error = Some(ErrorInfo::with_status(
                80008,
                400,
                "Unable to recover connection",
            ));
            let c = conn.respond_with_success(msg);
            std::mem::forget(c);
        }
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    mock.active_connection().simulate_disconnect();
    assert!(
        await_connection_count(&mock, 2, 5000).await,
        "reconnect attempt expected"
    );
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // RTN15c7: connected with the new id; the failure reason is surfaced
    assert_eq!(client.connection.id().as_deref(), Some("connection-2"));
    assert_eq!(
        client.connection.error_reason().and_then(|e| e.code),
        Some(80008)
    );
    client.close();
}

// UTS: realtime/unit/RTN15h1/token-error-no-renew-0
#[tokio::test]
async fn rtn15h1_disconnected_token_error_without_renewal_fails() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let opts = ClientOptions::with_token("static-token".to_string()).auto_connect(false);
    let client = client_with(&mock, opts);
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let mut msg = ProtocolMessage::new(action::DISCONNECTED);
    msg.error = Some(ErrorInfo::with_status(40142, 401, "Token expired"));
    mock.active_connection().send_to_client_and_close(msg);

    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);
    // 40171 ("no way to renew the auth token"), not the server's 40142: the SDK
    // detects it has no renewal means and substitutes the specific code,
    // matching ably-js and the proxy integration spec (connection_resume.md
    // RTN15h1 note). The unit spec's 40142 assertion contradicts this —
    // recorded as an upstream spec issue (TASK-9).
    assert_eq!(
        client.connection.error_reason().and_then(|e| e.code),
        Some(40171)
    );
}

// UTS: realtime/unit/RTN15h2/token-error-renew-success-0
#[tokio::test]
async fn rtn15h2_disconnected_token_error_renews_and_reconnects() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let urls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let urls_c = urls.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        attempts_c.fetch_add(1, Ordering::SeqCst);
        urls_c.lock().unwrap().push(conn.url.clone());
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let tokens = Arc::new(AtomicUsize::new(0));
    let client = token_client(&mock, tokens.clone());

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(tokens.load(Ordering::SeqCst), 1);

    let mut msg = ProtocolMessage::new(action::DISCONNECTED);
    msg.error = Some(ErrorInfo::with_status(40142, 401, "Token expired"));
    mock.active_connection().send_to_client_and_close(msg);

    assert!(
        await_connection_count(&mock, 2, 5000).await,
        "reconnect attempt expected"
    );
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(tokens.load(Ordering::SeqCst), 2, "the token was renewed");
    let urls = urls.lock().unwrap();
    assert!(urls[1].contains("accessToken=token-2"));
    client.close();
}

// UTS: realtime/unit/RTN15h3/non-token-error-resume-0
#[tokio::test]
async fn rtn15h3_disconnected_non_token_error_resumes() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let urls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let urls_c = urls.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        attempts_c.fetch_add(1, Ordering::SeqCst);
        urls_c.lock().unwrap().push(conn.url.clone());
        let c = conn.respond_with_success(connected_msg("id", "the-key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let mut msg = ProtocolMessage::new(action::DISCONNECTED);
    msg.error = Some(ErrorInfo::with_status(80003, 400, "Server going away"));
    mock.active_connection().send_to_client_and_close(msg);

    assert!(
        await_connection_count(&mock, 2, 5000).await,
        "reconnect attempt expected"
    );
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(urls.lock().unwrap()[1].contains("resume=the-key"));
    client.close();
}

// UTS: realtime/unit/RTN15g/state-cleared-after-ttl-0
#[tokio::test(start_paused = true)]
async fn rtn15g_resume_state_cleared_after_ttl() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let urls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let urls_c = urls.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        urls_c.lock().unwrap().push(conn.url.clone());
        if n == 1 {
            let c = conn.respond_with_success(connected_msg("id-1", "key-1"));
            std::mem::forget(c);
        } else if n < 4 {
            conn.respond_with_refused();
        } else {
            let c = conn.respond_with_success(connected_msg("id-2", "key-2"));
            std::mem::forget(c);
        }
    });
    let opts = default_opts()
        .auto_connect(false)
        .fallback_hosts(vec![]) // isolate RTN15g from RTN17 cycling
        .disconnected_retry_timeout(std::time::Duration::from_secs(2))
        .suspended_retry_timeout(std::time::Duration::from_secs(2))
        .connection_state_ttl(std::time::Duration::from_secs(3));
    let client = client_with(&mock, opts);

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    mock.active_connection().simulate_disconnect();

    // Retries fail until the TTL passes and the connection suspends...
    assert!(await_state(&client.connection, ConnectionState::Suspended, 60000).await);
    // ...then a retry succeeds with a clean (resume-free) connection
    assert!(await_state(&client.connection, ConnectionState::Connected, 60000).await);

    let urls = urls.lock().unwrap();
    let last = urls.last().unwrap();
    assert!(
        !last.contains("resume="),
        "RTN15g: no resume after the TTL passed, got {}",
        last
    );
    client.close();
}

// UTS: realtime/unit/RTN13a/ping-heartbeat-roundtrip-0
// UTS: realtime/unit/RTN13e/heartbeat-random-id-0
#[tokio::test]
async fn rtn13a_ping_sends_heartbeat_and_resolves_roundtrip() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let connection = client.connection.clone();
    let ping = tokio::spawn(async move { connection.ping().await });

    // The client sent HEARTBEAT with a random id (RTN13e)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let sent = loop {
        if let Some(m) = mock
            .client_messages()
            .into_iter()
            .find(|m| m.action == action::HEARTBEAT)
        {
            break m;
        }
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };
    let id = sent
        .message
        .id
        .clone()
        .expect("ping HEARTBEAT carries an id");
    assert!(!id.is_empty());

    // The server echoes the HEARTBEAT with the same id
    let mut reply = ProtocolMessage::new(action::HEARTBEAT);
    reply.id = Some(id);
    mock.active_connection().send_to_client(reply);

    let rtt = ping.await.unwrap().expect("ping resolves");
    assert!(rtt >= std::time::Duration::ZERO);
    client.close();
}

// UTS: realtime/unit/RTN13e/no-id-heartbeat-ignored-1 + RTN13c timeout
#[tokio::test(start_paused = true)]
async fn rtn13c_rtn13e_idless_heartbeat_ignored_and_ping_times_out() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let opts = default_opts()
        .auto_connect(false)
        .realtime_request_timeout(std::time::Duration::from_secs(2));
    let client = client_with(&mock, opts);
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let connection = client.connection.clone();
    let ping = tokio::spawn(async move { connection.ping().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // An id-less HEARTBEAT must NOT resolve the ping (RTN13e)
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::HEARTBEAT));

    // ...and with no matching response, the ping times out (RTN13c)
    let result = ping.await.unwrap();
    let err = result.expect_err("ping must time out");
    assert_eq!(err.status_code, Some(408));
    client.close();
}

// UTS: realtime/unit/RTN13e/concurrent-pings-unique-ids-2
#[tokio::test]
async fn rtn13e_concurrent_pings_resolve_independently() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let c1 = client.connection.clone();
    let c2 = client.connection.clone();
    let ping1 = tokio::spawn(async move { c1.ping().await });
    let ping2 = tokio::spawn(async move { c2.ping().await });

    // Collect the two HEARTBEAT ids
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let ids = loop {
        let ids: Vec<String> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.action == action::HEARTBEAT)
            .filter_map(|m| m.message.id)
            .collect();
        if ids.len() == 2 {
            break ids;
        }
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };
    assert_ne!(ids[0], ids[1], "concurrent pings use unique ids");

    // Answer in reverse order: each ping resolves on its own id
    for id in ids.iter().rev() {
        let mut reply = ProtocolMessage::new(action::HEARTBEAT);
        reply.id = Some(id.clone());
        mock.active_connection().send_to_client(reply);
    }
    assert!(ping1.await.unwrap().is_ok());
    assert!(ping2.await.unwrap().is_ok());
    client.close();
}

// RTN13b: ping outside CONNECTED errors (INITIALIZED and CLOSED)
#[tokio::test]
async fn rtn13b_ping_in_non_connected_state_errors() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    assert_eq!(client.connection.state(), ConnectionState::Initialized);
    let err = client.connection.ping().await.expect_err("ping must fail");
    assert!(err.message.unwrap_or_default().contains("Initialized"));

    // ...and in CLOSED
    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
    let err = client
        .connection
        .ping()
        .await
        .expect_err("ping must fail when closed");
    assert!(err.message.unwrap_or_default().contains("Closed"));
}

// UTS: realtime/unit/RTN23a/heartbeats-true-query-param-0
#[tokio::test]
async fn rtn23a_url_carries_heartbeats_true() {
    let captured: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
    let captured_c = captured.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        *captured_c.lock().unwrap() = Some(conn.url.clone());
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    let url = captured.lock().unwrap().clone().unwrap();
    assert!(url.contains("heartbeats=true"), "got {}", url);
    client.close();
}

// UTS: realtime/unit/RTN23a/idle-timeout-reconnect-1 (+reconnect-uses-resume-5)
#[tokio::test(start_paused = true)]
async fn rtn23a_idle_timeout_triggers_resume_reconnect() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let urls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let urls_c = urls.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        attempts_c.fetch_add(1, Ordering::SeqCst);
        urls_c.lock().unwrap().push(conn.url.clone());
        // ConnectionDetails carries maxIdleInterval=15000 (template default);
        // the server then goes silent
        let c = conn.respond_with_success(connected_msg("id", "idle-key"));
        std::mem::forget(c);
    });
    let opts = default_opts()
        .auto_connect(false)
        .realtime_request_timeout(std::time::Duration::from_secs(5));
    let client = client_with(&mock, opts);
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // No traffic: after maxIdleInterval + realtimeRequestTimeout the client
    // declares the transport dead and reconnects (paused clock auto-advances)
    assert!(
        await_state(&client.connection, ConnectionState::Disconnected, 60000).await
            || client.connection.state() == ConnectionState::Connected
    );
    assert!(await_state(&client.connection, ConnectionState::Connected, 60000).await);
    assert!(
        attempts.load(Ordering::SeqCst) >= 2,
        "reconnected after idle timeout"
    );
    assert!(
        urls.lock()
            .unwrap()
            .last()
            .unwrap()
            .contains("resume=idle-key"),
        "idle reconnect uses resume"
    );
    client.close();
}

// UTS: realtime/unit/RTN23a/heartbeat-resets-timer-2
#[tokio::test]
async fn rtn23a_heartbeat_traffic_keeps_connection_alive() {
    let mock = MockWebSocket::with_handler(|conn| {
        // A short maxIdleInterval so the test runs in real time
        let mut msg = connected_msg("id", "key");
        if let Some(details) = &mut msg.connection_details {
            details.max_idle_interval = Some(200);
        }
        let c = conn.respond_with_success(msg);
        std::mem::forget(c);
    });
    let opts = default_opts()
        .auto_connect(false)
        .realtime_request_timeout(std::time::Duration::from_millis(300));
    let client = client_with(&mock, opts);
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Heartbeats every 100ms keep resetting the (500ms) idle deadline
    for _ in 0..10 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        mock.active_connection()
            .send_to_client(ProtocolMessage::new(action::HEARTBEAT));
    }
    assert_eq!(
        client.connection.state(),
        ConnectionState::Connected,
        "regular heartbeats must keep the connection alive"
    );
    assert_eq!(mock.connection_count(), 1, "no reconnect happened");
    client.close();
}

// RTN12b: if the server never answers CLOSE with CLOSED, the connection
// closes anyway after realtimeRequestTimeout
#[tokio::test(start_paused = true)]
async fn rtn12b_close_times_out_without_closed() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c); // the server will never answer CLOSE
    });
    let opts = default_opts()
        .auto_connect(false)
        .realtime_request_timeout(std::time::Duration::from_secs(2));
    let client = client_with(&mock, opts);
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closed, 10000).await);
}

// RTC1a/RTN2b: echo=true by default, echo=false when echoMessages disabled
#[tokio::test]
async fn rtn2b_echo_param() {
    let urls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let urls_c = urls.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        urls_c.lock().unwrap().push(conn.url.clone());
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let transport = Arc::new(MockTransport::new(mock.inner()));

    let c1 = Realtime::with_mock(&default_opts().auto_connect(false), transport.clone()).unwrap();
    c1.connect();
    assert!(await_state(&c1.connection, ConnectionState::Connected, 5000).await);

    let c2 = Realtime::with_mock(
        &default_opts().auto_connect(false).echo_messages(false),
        transport,
    )
    .unwrap();
    c2.connect();
    assert!(await_state(&c2.connection, ConnectionState::Connected, 5000).await);

    let urls = urls.lock().unwrap();
    assert!(
        urls[0].contains("echo=true"),
        "RTC1a: echo=true by default, got {}",
        urls[0]
    );
    assert!(
        urls[1].contains("echo=false"),
        "echo=false when disabled, got {}",
        urls[1]
    );
    c1.close();
    c2.close();
}

// ============================================================================
// Stage 5.3 — server-initiated reauth (RTN22) and in-place authorize (RTC8)
// Source: uts/realtime/unit/connection/server_initiated_reauth_test.md
// ============================================================================

// UTS: realtime/unit/RTN22/server-auth-triggers-reauth-0 (+stays-connected-1)
#[tokio::test]
async fn rtn22_server_auth_triggers_reauth() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("connection-id", "connection-key"));
        std::mem::forget(c);
    });
    let tokens = Arc::new(AtomicUsize::new(0));
    let client = token_client(&mock, tokens.clone());

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(tokens.load(Ordering::SeqCst), 1);

    // Record events from here on
    let changes: Arc<StdMutex<Vec<ConnectionStateChange>>> = Arc::new(StdMutex::new(Vec::new()));
    let changes_c = changes.clone();
    let mut events = client.connection.on_state_change();
    tokio::spawn(async move {
        while let Ok(change) = events.recv().await {
            changes_c.lock().unwrap().push(change);
        }
    });

    // The server requests re-authentication
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::AUTH));

    // The client obtains a fresh token and sends AUTH back
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let auth_msg = loop {
        if let Some(m) = mock
            .client_messages()
            .into_iter()
            .find(|m| m.action == action::AUTH)
        {
            break m;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "client never sent AUTH"
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };
    let auth = auth_msg.message.auth.expect("AUTH carries an auth payload");
    assert_eq!(auth["accessToken"], "token-2", "fresh token used");
    assert_eq!(
        tokens.load(Ordering::SeqCst),
        2,
        "token source consulted again"
    );

    // The server acknowledges with an updated CONNECTED → UPDATE event
    mock.active_connection()
        .send_to_client(connected_msg("connection-id", "connection-key-2"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let snapshot = changes.lock().unwrap().clone();
        if snapshot
            .iter()
            .any(|c| c.event == crate::protocol::ConnectionEvent::Update)
        {
            // The connection never left CONNECTED
            assert!(
                snapshot
                    .iter()
                    .all(|c| c.current == ConnectionState::Connected),
                "reauth must not change the connection state: {:?}",
                snapshot.iter().map(|c| c.current).collect::<Vec<_>>()
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no UPDATE event observed"
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    assert_eq!(client.connection.key().as_deref(), Some("connection-key-2"));
    client.close();
}

// RTC8: RealtimeAuth::authorize() applies the new token to the live
// connection via AUTH, without a reconnect
#[tokio::test]
async fn rtc8_authorize_reauths_in_place() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_success(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let tokens = Arc::new(AtomicUsize::new(0));
    let client = token_client(&mock, tokens.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // RTC8a3: authorize resolves only once the server confirms the AUTH
    let auth = client.auth();
    let authorize = tokio::spawn(async move { auth.authorize().await });
    answer_next_auth(&mock, "key-2").await;
    let td = authorize.await.unwrap().expect("authorize");
    assert_eq!(td.token, "token-2");

    // The new token went out as an AUTH protocol message
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(m) = mock
            .client_messages()
            .into_iter()
            .find(|m| m.action == action::AUTH)
        {
            let auth = m.message.auth.expect("auth payload");
            assert_eq!(auth["accessToken"], "token-2");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "AUTH never sent");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        client.connection.state(),
        ConnectionState::Connected,
        "authorize is in-place: still connected"
    );
    assert_eq!(mock.connection_count(), 1, "no reconnect");
    client.close();
}

// RTN17 live cross-check: Connection::host() reports the connected host
#[tokio::test]
async fn rtn17_host_reported_when_connected() {
    let mock = MockWebSocket::with_handler(|conn| {
        conn.respond_with_success(connected_msg("id", "key"));
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    assert!(client.connection.host().is_none());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(
        client.connection.host().as_deref(),
        Some("main.realtime.ably.net")
    );
    client.close();
}

// ============================================================================
// RTN13d — deferred pings (UTS connection_ping_test.md)
// ============================================================================

// UTS: realtime/unit/RTN13d/ping-deferred-connecting-0
#[tokio::test]
async fn rtn13d_ping_deferred_while_connecting_runs_on_connected() {
    let gate: Arc<StdMutex<Option<crate::mock_ws::PendingConnection>>> =
        Arc::new(StdMutex::new(None));
    let gate_c = gate.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        *gate_c.lock().unwrap() = Some(conn);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    assert_eq!(client.connection.state(), ConnectionState::Connecting);

    let conn_handle = client.connection.clone();
    let ping = tokio::spawn(async move { conn_handle.ping().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    // RTN13d: nothing sent while CONNECTING
    assert!(mock.client_messages().is_empty());
    assert!(!ping.is_finished());

    // Complete the connection: the deferred ping goes out
    let pending = gate.lock().unwrap().take().expect("parked attempt");
    let conn = pending.respond_with_success(connected_msg("id", "key"));
    let hb = mock.await_message_from_client().await;
    assert_eq!(hb.action, crate::protocol::action::HEARTBEAT);
    let mut reply = ProtocolMessage::new(crate::protocol::action::HEARTBEAT);
    reply.id = hb.id.clone();
    conn.send_to_client(reply);

    let rtt = ping.await.unwrap().expect("deferred ping resolves");
    assert!(rtt >= std::time::Duration::ZERO);
}

// UTS: realtime/unit/RTN13d/ping-deferred-disconnected-1
#[tokio::test]
async fn rtn13d_ping_deferred_while_disconnected_runs_on_reconnect() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(
        &mock,
        default_opts()
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
    );
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    await_connection_count(&mock, 1, 5000).await;

    // Drop the transport, then ping during the gap before reconnection
    mock.active_connection().simulate_disconnect();
    let conn_handle = client.connection.clone();
    let ping = tokio::spawn(async move { conn_handle.ping().await });

    // The reconnect completes and the deferred ping goes out
    await_connection_count(&mock, 2, 5000).await;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    let hb = loop {
        if let Some(m) = mock
            .client_messages()
            .into_iter()
            .find(|m| m.action == crate::protocol::action::HEARTBEAT)
        {
            break m;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no deferred HEARTBEAT"
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };
    let mut reply = ProtocolMessage::new(crate::protocol::action::HEARTBEAT);
    reply.id = hb.message.id.clone();
    mock.active_connection().send_to_client(reply);
    let rtt = ping
        .await
        .unwrap()
        .expect("deferred ping resolves after reconnect");
    assert!(rtt >= std::time::Duration::ZERO);
}

// UTS: realtime/unit/RTN13b/deferred-ping-error-failed-4
#[tokio::test]
async fn rtn13b_deferred_ping_fails_on_failed() {
    let gate: Arc<StdMutex<Option<crate::mock_ws::PendingConnection>>> =
        Arc::new(StdMutex::new(None));
    let gate_c = gate.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        *gate_c.lock().unwrap() = Some(conn);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    let conn_handle = client.connection.clone();
    let ping = tokio::spawn(async move { conn_handle.ping().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // The attempt resolves to a fatal ERROR instead of CONNECTED
    let mut err_msg = ProtocolMessage::new(crate::protocol::action::ERROR);
    err_msg.error = Some(ErrorInfo::with_status(40400, 404, "Fatal error"));
    gate.lock()
        .unwrap()
        .take()
        .unwrap()
        .respond_with_error(err_msg);
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let err = ping
        .await
        .unwrap()
        .expect_err("deferred ping fails on FAILED");
    assert_eq!(err.code, Some(40400));
}

// UTS: realtime/unit/RTN13b/deferred-ping-error-suspended-5
#[tokio::test(start_paused = true)]
async fn rtn13b_deferred_ping_fails_on_suspended() {
    let mock = MockWebSocket::with_handler(|conn| conn.respond_with_refused());
    let client = client_with(
        &mock,
        default_opts()
            .auto_connect(false)
            .fallback_hosts(vec![])
            .disconnected_retry_timeout(std::time::Duration::from_secs(1))
            .connection_state_ttl(std::time::Duration::from_secs(5)),
    );
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

    let conn_handle = client.connection.clone();
    let ping = tokio::spawn(async move { conn_handle.ping().await });
    tokio::task::yield_now().await;

    assert!(await_state(&client.connection, ConnectionState::Suspended, 60000).await);
    let err = ping
        .await
        .unwrap()
        .expect_err("deferred ping fails on SUSPENDED");
    assert!(err
        .message
        .unwrap_or_default()
        .to_lowercase()
        .contains("suspended"));
}

// UTS: realtime/unit/RTN13c/deferred-ping-timeout-1 — the timeout runs from
// when the HEARTBEAT is sent (on CONNECTED), not from the ping() call
#[tokio::test(start_paused = true)]
async fn rtn13c_deferred_ping_times_out_after_send() {
    let gate: Arc<StdMutex<Option<crate::mock_ws::PendingConnection>>> =
        Arc::new(StdMutex::new(None));
    let gate_c = gate.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        *gate_c.lock().unwrap() = Some(conn);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    client.connect();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    let conn_handle = client.connection.clone();
    let ping = tokio::spawn(async move { conn_handle.ping().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // Connect; the server never answers the HEARTBEAT
    let pending = gate.lock().unwrap().take().unwrap();
    let _conn = pending.respond_with_success(connected_msg("id", "key"));
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let err = ping
        .await
        .unwrap()
        .expect_err("deferred ping must time out");
    assert!(err
        .message
        .unwrap_or_default()
        .to_lowercase()
        .contains("timed out"));
}

// ============================================================================
// RTC8 — authorize() (UTS realtime/unit/auth/realtime_authorize.md)
// ============================================================================

/// A connected token client whose mock answers every AUTH with a fresh
/// CONNECTED (successful in-band reauth).
fn auth_confirming_mock() -> MockWebSocket {
    MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("conn-id", "conn-key"));
        std::mem::forget(c);
    })
}

async fn answer_next_auth(mock: &MockWebSocket, key: &str) {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::AUTH)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "no AUTH observed");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    mock.active_connection()
        .send_to_client(connected_msg("conn-id", key));
}

// UTS: realtime/unit/RTC8a/authorize-connected-sends-auth-0
#[tokio::test]
async fn rtc8a_authorize_connected_sends_auth() {
    let count = Arc::new(AtomicUsize::new(0));
    let mock = auth_confirming_mock();
    let client = token_client(&mock, count.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    let mut events = client.connection.on_state_change();
    let auth = client.auth();
    let authorize = tokio::spawn(async move { auth.authorize().await });
    answer_next_auth(&mock, "conn-key-2").await;
    let td = authorize.await.unwrap().expect("authorize resolves");

    // The callback ran twice and the AUTH carried the new token
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(td.token, "token-2");
    let auth_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.action == action::AUTH)
        .collect();
    assert_eq!(auth_msgs.len(), 1);
    assert_eq!(
        auth_msgs[0].message.auth.as_ref().unwrap()["accessToken"],
        "token-2"
    );

    // No state transitions occurred (UPDATE only)
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    while let Ok(change) = events.try_recv() {
        assert_eq!(change.previous, change.current, "no state transition");
    }
}

// UTS: realtime/unit/RTC8a1/successful-reauth-update-event-0
#[tokio::test]
async fn rtc8a1_successful_reauth_update_event() {
    let count = Arc::new(AtomicUsize::new(0));
    let mock = auth_confirming_mock();
    let client = token_client(&mock, count.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let mut events = client.connection.on_state_change();
    let auth = client.auth();
    let authorize = tokio::spawn(async move { auth.authorize().await });
    answer_next_auth(&mock, "conn-key-2").await;
    authorize.await.unwrap().expect("authorize resolves");

    // Exactly one UPDATE, no CONNECTED state event; details refreshed
    let mut updates = 0;
    while let Ok(change) = events.try_recv() {
        assert_eq!(
            change.event,
            crate::protocol::ConnectionEvent::Update,
            "RTN4h: UPDATE only"
        );
        assert_eq!(change.previous, ConnectionState::Connected);
        assert_eq!(change.current, ConnectionState::Connected);
        updates += 1;
    }
    assert_eq!(updates, 1);
    assert_eq!(
        client.connection.key().as_deref(),
        Some("conn-key-2"),
        "RTN21"
    );
}

// UTS: realtime/unit/RTC8a1/capability-downgrade-channel-failed-1
#[tokio::test]
async fn rtc8a1_capability_downgrade_channel_failed() {
    let count = Arc::new(AtomicUsize::new(0));
    let mock = auth_confirming_mock();
    let client = token_client(&mock, count.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Attach a channel
    let ch = client.channels.get("private-channel");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::ATTACH)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    let mut attached = ProtocolMessage::new(action::ATTACHED);
    attached.channel = Some("private-channel".to_string());
    mock.active_connection().send_to_client(attached);
    attach.await.unwrap().unwrap();

    // Reauth succeeds at the connection level...
    let auth = client.auth();
    let authorize = tokio::spawn(async move { auth.authorize().await });
    answer_next_auth(&mock, "conn-key-2").await;
    authorize.await.unwrap().expect("authorize resolves");

    // ...then the downgraded capability fails the channel
    let mut chan_err = ProtocolMessage::new(action::ERROR);
    chan_err.channel = Some("private-channel".to_string());
    chan_err.error = Some(ErrorInfo::with_status(40160, 401, "Capability downgrade"));
    mock.active_connection().send_to_client(chan_err);

    assert!(
        crate::realtime::await_channel_state(&ch, crate::protocol::ChannelState::Failed, 5000)
            .await
    );
    assert_eq!(ch.error_reason().and_then(|e| e.code), Some(40160));
    assert_eq!(
        client.connection.state(),
        ConnectionState::Connected,
        "the connection itself stays CONNECTED"
    );
}

// UTS: realtime/unit/RTC8a2/failed-reauth-connection-failed-0
#[tokio::test]
async fn rtc8a2_failed_reauth_connection_failed() {
    let count = Arc::new(AtomicUsize::new(0));
    let mock = auth_confirming_mock();
    let client = token_client(&mock, count.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let auth = client.auth();
    let authorize = tokio::spawn(async move { auth.authorize().await });
    // The server refuses the new token: connection-level ERROR
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::AUTH)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.error = Some(ErrorInfo::with_status(40101, 401, "Incompatible clientId"));
    mock.active_connection().send_to_client_and_close(err_msg);

    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);
    let err = authorize.await.unwrap().expect_err("authorize fails");
    assert_eq!(err.code, Some(40101));
}

// UTS: realtime/unit/RTC8a3/authorize-completes-after-response-0
#[tokio::test]
async fn rtc8a3_authorize_completes_after_response() {
    let count = Arc::new(AtomicUsize::new(0));
    let mock = auth_confirming_mock();
    let client = token_client(&mock, count.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let auth = client.auth();
    let authorize = tokio::spawn(async move { auth.authorize().await });
    // The AUTH is on the wire but unanswered: authorize must not resolve
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::AUTH)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(
        !authorize.is_finished(),
        "RTC8a3: not before the server responds"
    );

    mock.active_connection()
        .send_to_client(connected_msg("conn-id", "conn-key-2"));
    let td = authorize.await.unwrap().expect("resolves after CONNECTED");
    assert_eq!(td.token, "token-2");
}

// UTS: realtime/unit/RTC8b/authorize-connecting-halts-attempt-0
#[tokio::test]
async fn rtc8b_authorize_connecting_halts_attempt() {
    let count = Arc::new(AtomicUsize::new(0));
    // Park the FIRST attempt forever; answer subsequent attempts
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        if attempts_c.fetch_add(1, Ordering::SeqCst) == 0 {
            std::mem::forget(conn); // parked: never completes
        } else {
            let c = conn.respond_with_connection();
            c.send_to_client(connected_msg("conn-id", "conn-key"));
            std::mem::forget(c);
        }
    });
    let client = token_client(&mock, count.clone());
    client.connect();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert_eq!(client.connection.state(), ConnectionState::Connecting);

    let td = client.auth().authorize().await.expect("authorize resolves");
    assert_eq!(td.token, "token-2");
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert_eq!(count.load(Ordering::SeqCst), 2, "two token acquisitions");
    assert_eq!(
        mock.connection_count(),
        2,
        "RTC8b: a fresh attempt was made"
    );
}

// UTS: realtime/unit/RTC8b1/authorize-connecting-fails-on-failed-0
#[tokio::test]
async fn rtc8b1_authorize_connecting_fails_on_failed() {
    let count = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        if attempts_c.fetch_add(1, Ordering::SeqCst) == 0 {
            std::mem::forget(conn);
        } else {
            // The reconnect with the new token is fatally refused
            let mut err = ProtocolMessage::new(action::ERROR);
            err.error = Some(ErrorInfo::with_status(40101, 401, "Invalid credentials"));
            conn.respond_with_error(err);
        }
    });
    let client = token_client(&mock, count.clone());
    client.connect();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    let err = client
        .auth()
        .authorize()
        .await
        .expect_err("authorize fails");
    assert_eq!(err.code, Some(40101));
    assert_eq!(client.connection.state(), ConnectionState::Failed);
}

// UTS: realtime/unit/RTC8c/authorize-disconnected-initiates-connection-0
// (from INITIALIZED, per the spec's setup)
#[tokio::test]
async fn rtc8c_authorize_from_initialized_initiates_connection() {
    let count = Arc::new(AtomicUsize::new(0));
    let mock = auth_confirming_mock();
    let client = token_client(&mock, count.clone());
    assert_eq!(client.connection.state(), ConnectionState::Initialized);

    let mut events = client.connection.on_state_change();
    let td = client.auth().authorize().await.expect("authorize connects");
    assert_eq!(td.token, "token-1");
    assert_eq!(client.connection.state(), ConnectionState::Connected);

    let mut seen = Vec::new();
    while let Ok(change) = events.try_recv() {
        seen.push(change.current);
    }
    assert_eq!(
        seen,
        vec![ConnectionState::Connecting, ConnectionState::Connected],
        "RTC8c: connecting then connected"
    );
}

// UTS: realtime/unit/RTC8c/authorize-failed-initiates-connection-1
#[tokio::test]
async fn rtc8c_authorize_from_failed_recovers() {
    let count = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        if attempts_c.fetch_add(1, Ordering::SeqCst) == 0 {
            // First attempt fails fatally
            let mut err = ProtocolMessage::new(action::ERROR);
            err.error = Some(ErrorInfo::with_status(40400, 404, "Fatal"));
            conn.respond_with_error(err);
        } else {
            let c = conn.respond_with_connection();
            c.send_to_client(connected_msg("conn-id", "conn-key"));
            std::mem::forget(c);
        }
    });
    let client = token_client(&mock, count.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let td = client.auth().authorize().await.expect("authorize recovers");
    assert_eq!(td.token, "token-2");
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

// UTS: realtime/unit/RTC8c/authorize-closed-initiates-connection-2
#[tokio::test]
async fn rtc8c_authorize_from_closed_reconnects() {
    let count = Arc::new(AtomicUsize::new(0));
    let mock = auth_confirming_mock();
    let client = token_client(&mock, count.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    client.close();
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

    let td = client
        .auth()
        .authorize()
        .await
        .expect("authorize reconnects");
    assert_eq!(td.token, "token-2");
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

// ============================================================================
// Forwards compatibility / misc backfill (coverage audit, 2026-06-10)
// ============================================================================

// UTS: realtime/unit/RTF1/unknown-action-handled-1
#[tokio::test]
async fn rtf1_unknown_action_ignored() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));
    let mut events = client.connection.on_state_change();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // A protocol message from the future: unknown action value
    let mut unknown = ProtocolMessage::new(254);
    unknown.channel = Some("whatever".to_string());
    mock.active_connection().send_to_client(unknown);
    // Liveness probe: a heartbeat still round-trips afterwards
    mock.active_connection()
        .send_to_client(ProtocolMessage::new(action::HEARTBEAT));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert_eq!(client.connection.state(), ConnectionState::Connected);
    while let Ok(change) = events.try_recv() {
        assert!(
            !matches!(
                change.current,
                ConnectionState::Disconnected | ConnectionState::Failed
            ),
            "RTF1: unknown action must not disturb the connection"
        );
    }
}

// UTS: realtime/unit/RTN22a/forced-disconnect-reauth-failure-0
#[tokio::test]
async fn rtn22a_forced_disconnect_carries_reason() {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("id", "key"));
        std::mem::forget(c);
    });
    let tokens = Arc::new(AtomicUsize::new(0));
    let client = token_client(&mock, tokens.clone());
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Subscribe BEFORE the disconnect: the DISCONNECTED state is transient
    // (the client renews and reconnects), so the event stream is the witness
    let mut events = client.connection.on_state_change();
    let mut msg = ProtocolMessage::new(action::DISCONNECTED);
    msg.error = Some(ErrorInfo::with_status(40142, 401, "Token expired"));
    mock.active_connection().send_to_client(msg);

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let change = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("DISCONNECTED change must arrive")
            .expect("stream open");
        if change.current == ConnectionState::Disconnected {
            assert_eq!(
                change.reason.and_then(|e| e.code),
                Some(40142),
                "RTN22a: the forced disconnect carries the token error"
            );
            break;
        }
    }
    // ...and the client recovers with a renewed token
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    assert!(tokens.load(Ordering::SeqCst) >= 2, "token was renewed");
}

// UTS: realtime/unit/RSA4f/callback-oversized-token-format-1
#[tokio::test]
async fn rsa4f_oversized_token_disconnects() {
    struct OversizedCb;
    impl AuthCallback for OversizedCb {
        fn token<'a>(
            &'a self,
            _params: &'a TokenParams,
        ) -> std::pin::Pin<
            Box<dyn Send + futures::Future<Output = crate::error::Result<AuthToken>> + 'a>,
        > {
            Box::pin(async move { Ok(AuthToken::Token("x".repeat(200 * 1024))) })
        }
    }
    let mock = MockWebSocket::new();
    let opts = ClientOptions::with_auth_callback(Arc::new(OversizedCb))
        .auto_connect(false)
        .fallback_hosts(vec![]);
    let client = client_with(&mock, opts);
    client.connect();

    assert!(
        await_state(&client.connection, ConnectionState::Disconnected, 5000).await,
        "RSA4f: oversized token leaves the connection DISCONNECTED"
    );
    let err = client.connection.error_reason().expect("errorReason set");
    assert_eq!(err.code, Some(80019));
    assert_eq!(err.status_code, Some(401));
    assert_eq!(mock.connection_count(), 0, "nothing was dialed");
}

// UTS: realtime/unit/RSA4a1/non-renewable-token-logs-warning-0
#[tokio::test]
async fn rsa4a1_non_renewable_token_logs_warning() {
    let lines: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let lines_c = lines.clone();
    let mock = MockWebSocket::new();
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let opts = ClientOptions::with_token("non-renewable-token")
        .auto_connect(false)
        .log_level(crate::options::LogLevel::Major)
        .log_handler(move |_level, msg| {
            lines_c.lock().unwrap().push(msg.to_string());
        });
    let _client = Realtime::with_mock(&opts, transport).unwrap();

    let lines = lines.lock().unwrap();
    assert!(
        lines.iter().any(|l| l.contains("40171")),
        "RSA4a1: a warning mentioning 40171, got {:?}",
        *lines
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("https://help.ably.io/error/40171")),
        "RSA4a1: the help URL is included"
    );
}

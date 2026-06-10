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
    assert!(!attempted.load(Ordering::SeqCst), "no connection attempt expected");
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
    let client1 = Realtime::with_mock(&default_opts().auto_connect(false), transport.clone()).unwrap();
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

    assert!(client.connection.id().is_none(), "RTN8c: id null after CLOSED");
    assert!(client.connection.key().is_none(), "RTN9c: key null after CLOSED");
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
    client.connection.when_state(ConnectionState::Connected, move |change| {
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
    client.connection.when_state(ConnectionState::Connected, move |change| {
        *captured_c.lock().unwrap() = Some(change);
        invoked_c.store(true, Ordering::SeqCst);
    });
    assert!(!invoked.load(Ordering::SeqCst), "must not fire before the transition");

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
    client.connection.when_state(ConnectionState::Connected, move |_| {
        count_c.fetch_add(1, Ordering::SeqCst);
    });

    // Connect → CONNECTED (fires), close → CLOSED, connect → CONNECTED again
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    client.close();
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
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
        client.connection.when_state(ConnectionState::Connected, move |_| {
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
    client.connection.when_state(ConnectionState::Connecting, move |_| {
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
    client.connection.when_state(ConnectionState::Connected, move |_| {
        connected_c.store(true, Ordering::SeqCst);
    });
    client.connection.when_state(ConnectionState::Closed, move |_| {
        closed_c.store(true, Ordering::SeqCst);
    });

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(connected.load(Ordering::SeqCst));
    assert!(!closed.load(Ordering::SeqCst));

    client.close();
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
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
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
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
        if mock.client_messages().iter().any(|m| m.action == action::CLOSE) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "CLOSE was never sent");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
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
    assert_eq!(mock.connection_count(), 0, "no connection was ever attempted");
}

// RTN11: connect() after CLOSED starts a fresh connection
#[tokio::test]
async fn rtn11_reconnect_after_close() {
    let count = Arc::new(AtomicU32::new(0));
    let count_c = count.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = count_c.fetch_add(1, Ordering::SeqCst) + 1;
        let c = conn.respond_with_success(connected_msg(&format!("id-{}", n), &format!("key-{}", n)));
        std::mem::forget(c);
    });
    let client = client_with(&mock, default_opts().auto_connect(false));

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    client.close();
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
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
    assert!(client.connection.id().is_some(), "live connection id assigned");
    assert!(client.connection.key().is_some(), "live connection key assigned");

    client.close();
    assert!(
        await_state(&client.connection, ConnectionState::Closed, 10000).await,
        "must reach CLOSED after close()"
    );
    assert!(client.connection.id().is_none(), "RTN8c live");
}

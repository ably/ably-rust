#![cfg(test)]

//! Stage 5.4 channel-lifecycle tests, derived from the UTS specs
//! (DESIGN.md Realtime §12). Sources:
//! - uts/realtime/unit/channels/channels_collection.md (RTS)
//! - uts/realtime/unit/channels/channel_attach.md (RTL4)
//! - uts/realtime/unit/channels/channel_detach.md (RTL5)
//! - uts/realtime/unit/channels/channel_connection_state.md (RTL3)
//! - uts/realtime/unit/channels/channel_state_events.md (RTL2)

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::channel::RealtimeChannelOptions;
use crate::error::ErrorInfo;
use crate::mock_ws::{MockTransport, MockWebSocket};
use crate::options::ClientOptions;
use crate::protocol::{
    action, flags, ChannelMode, ChannelState, ConnectionState, ProtocolMessage,
};
use crate::realtime::{await_state, Realtime};

fn connected_msg(id: &str, key: &str) -> ProtocolMessage {
    ProtocolMessage::connected(id, key)
}

fn attached_msg(channel: &str) -> ProtocolMessage {
    let mut msg = ProtocolMessage::new(action::ATTACHED);
    msg.channel = Some(channel.to_string());
    msg
}

fn detached_msg(channel: &str) -> ProtocolMessage {
    let mut msg = ProtocolMessage::new(action::DETACHED);
    msg.channel = Some(channel.to_string());
    msg
}

/// A client whose mock auto-confirms the connection and every ATTACH/DETACH.
fn auto_serving_client() -> (MockWebSocket, Realtime) {
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("conn-id", "conn-key"));
        std::mem::forget(c);
    });
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();
    (mock, client)
}

/// Serve ATTACH/DETACH confirmations in the background.
fn spawn_channel_server(mock: &MockWebSocket) -> tokio::task::JoinHandle<()> {
    let mock2 = mock.clone();
    tokio::spawn(async move {
        let mut served = 0usize;
        loop {
            let msgs = mock2.client_messages();
            for m in msgs.iter().skip(served) {
                match m.action {
                    a if a == action::ATTACH => {
                        let mut reply = attached_msg(m.channel.as_deref().unwrap());
                        reply.channel_serial = Some(format!("serial-{}", m.channel.as_deref().unwrap()));
                        mock2.active_connection().send_to_client(reply);
                    }
                    a if a == action::DETACH => {
                        mock2
                            .active_connection()
                            .send_to_client(detached_msg(m.channel.as_deref().unwrap()));
                    }
                    _ => {}
                }
            }
            served = msgs.len();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    })
}

/// Await a captured client message with the given action, returning it.
async fn await_client_action(
    mock: &MockWebSocket,
    wanted: u8,
    timeout_ms: u64,
) -> crate::mock_ws::CapturedMessage {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
    loop {
        if let Some(m) = mock.client_messages().into_iter().find(|m| m.action == wanted) {
            return m;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "client never sent action {}",
            wanted
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
}

async fn connect(client: &Realtime) {
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
}

// ============================================================================
// RTS — channels collection
// ============================================================================

// UTS: RTS3a get-creates / get-returns-existing / RTS2 exists+iterate
#[tokio::test]
async fn rts2_rts3a_collection_semantics() {
    let (_mock, client) = auto_serving_client();

    assert!(!client.channels.exists("alpha"));
    let ch1 = client.channels.get("alpha");
    assert!(client.channels.exists("alpha")); // RTS2
    let ch2 = client.channels.get("alpha");
    // RTS3a: the same instance
    assert!(Arc::ptr_eq(&ch1, &ch2));

    client.channels.get("beta");
    let mut names = client.channels.names();
    names.sort();
    assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
}

// UTS: RTS4a release detaches and removes; get-after-release is new
#[tokio::test]
async fn rts4a_release_detaches_and_removes() {
    let (mock, client) = auto_serving_client();
    let server = spawn_channel_server(&mock);
    connect(&client).await;

    let ch = client.channels.get("to-release");
    ch.attach().await.expect("attach");
    assert_eq!(ch.state(), ChannelState::Attached);

    client.channels.release("to-release").await;
    assert!(!client.channels.exists("to-release"));
    // RTS4a: the release sent a DETACH on the wire
    await_client_action(&mock, action::DETACH, 2000).await;

    // RTS3a: a fresh get creates a new instance
    let again = client.channels.get("to-release");
    assert!(!Arc::ptr_eq(&ch, &again));
    assert_eq!(again.state(), ChannelState::Initialized);
    server.abort();
}

// UTS: RTS4a release on a non-existent channel is a no-op
#[tokio::test]
async fn rts4a_release_nonexistent_noop() {
    let (_mock, client) = auto_serving_client();
    client.channels.release("never-created").await;
    assert!(!client.channels.exists("never-created"));
}

// ============================================================================
// RTL2 — channel state and events
// ============================================================================

// UTS: RTL2b initial state
#[tokio::test]
async fn rtl2b_initial_state_is_initialized() {
    let (_mock, client) = auto_serving_client();
    let ch = client.channels.get("fresh");
    assert_eq!(ch.state(), ChannelState::Initialized);
    assert!(ch.error_reason().is_none());
}

// UTS: RTL2a ordered events for every state change (+RTL2d structure)
#[tokio::test]
async fn rtl2a_rtl2d_state_change_events() {
    let (mock, client) = auto_serving_client();
    let server = spawn_channel_server(&mock);
    connect(&client).await;

    let ch = client.channels.get("evented");
    let changes: Arc<StdMutex<Vec<(ChannelState, ChannelState)>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let changes_c = changes.clone();
    let mut events = ch.on_state_change();
    tokio::spawn(async move {
        while let Ok(change) = events.recv().await {
            changes_c.lock().unwrap().push((change.previous, change.current));
        }
    });

    ch.attach().await.expect("attach");
    ch.detach().await.expect("detach");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let seq = changes.lock().unwrap().clone();
    assert_eq!(
        seq,
        vec![
            (ChannelState::Initialized, ChannelState::Attaching),
            (ChannelState::Attaching, ChannelState::Attached),
            (ChannelState::Attached, ChannelState::Detaching),
            (ChannelState::Detaching, ChannelState::Detached),
        ],
        "RTL2a: every transition emitted in order with correct previous/current"
    );
    server.abort();
}

// ============================================================================
// RTL4 — attach
// ============================================================================

// UTS: RTL4c sends ATTACH + transitions; RTL4a attached no-op
#[tokio::test]
async fn rtl4c_rtl4a_attach_flow_and_noop() {
    let (mock, client) = auto_serving_client();
    let server = spawn_channel_server(&mock);
    connect(&client).await;

    let ch = client.channels.get("basic");
    ch.attach().await.expect("attach");
    assert_eq!(ch.state(), ChannelState::Attached);
    let attach_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::ATTACH)
        .count();
    assert_eq!(attach_count, 1);

    // RTL4a: attach when attached is an immediate no-op (no new ATTACH)
    ch.attach().await.expect("attach again");
    let attach_count_after = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::ATTACH)
        .count();
    assert_eq!(attach_count_after, 1, "no second ATTACH sent");
    server.abort();
}

// UTS: RTL4h attach while attaching shares the outcome
#[tokio::test]
async fn rtl4h_attach_while_attaching_waits() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("inflight");
    let ch2 = ch.clone();
    let first = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    assert_eq!(ch.state(), ChannelState::Attaching);

    let ch3 = ch.clone();
    let second = tokio::spawn(async move { ch3.attach().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // One ATTACHED resolves both
    mock.active_connection().send_to_client(attached_msg("inflight"));
    assert!(first.await.unwrap().is_ok());
    assert!(second.await.unwrap().is_ok());
    let attach_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::ATTACH)
        .count();
    assert_eq!(attach_count, 1, "only one ATTACH for both calls");
}

// UTS: RTL4b attach fails for closed/failed/suspended connections
#[tokio::test]
async fn rtl4b_attach_fails_in_invalid_connection_states() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;
    let ch = client.channels.get("invalid");

    // Close the connection
    client.close();
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

    let err = ch.attach().await.expect_err("attach while closed must fail");
    assert_eq!(err.code, Some(90001));
}

// UTS: RTL4i attach queued while connecting, completes on connected
#[tokio::test]
async fn rtl4i_attach_queued_until_connected() {
    let gate: Arc<StdMutex<Option<crate::mock_ws::PendingConnection>>> =
        Arc::new(StdMutex::new(None));
    let gate_c = gate.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        // Park the connection attempt; the test completes it later
        *gate_c.lock().unwrap() = Some(conn);
    });
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    let ch = client.channels.get("queued");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // RTL4i: the channel is ATTACHING but nothing was sent yet
    assert_eq!(ch.state(), ChannelState::Attaching);
    assert!(mock.client_messages().is_empty());

    // Complete the connection: the queued ATTACH goes out
    let pending = gate.lock().unwrap().take().expect("parked attempt");
    let conn = pending.respond_with_success(connected_msg("id", "key"));
    let attach_msg = await_client_action(&mock, action::ATTACH, 2000).await;
    conn.send_to_client(attached_msg(attach_msg.channel.as_deref().unwrap()));

    assert!(attach.await.unwrap().is_ok());
    assert_eq!(ch.state(), ChannelState::Attached);
}

// UTS: RTL4f attach timeout → SUSPENDED with the error
#[tokio::test(start_paused = true)]
async fn rtl4f_attach_timeout_suspends_channel() {
    let (mock, client) = auto_serving_client(); // no channel server: ATTACH unanswered
    let _ = &mock;
    connect(&client).await;

    let ch = client.channels.get("timeout");
    let err = ch.attach().await.expect_err("attach must time out");
    assert_eq!(err.status_code, Some(408));
    assert_eq!(ch.state(), ChannelState::Suspended);
    assert!(ch.error_reason().is_some());
}

// UTS: RTL4c1/RTL4j reattach carries channelSerial + ATTACH_RESUME
#[tokio::test]
async fn rtl4c1_rtl4j_reattach_serial_and_resume_flag() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("resume-ch");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    let mut reply = attached_msg("resume-ch");
    reply.channel_serial = Some("serial-123".to_string());
    mock.active_connection().send_to_client(reply);
    assert!(attach.await.unwrap().is_ok());
    assert_eq!(ch.channel_serial().as_deref(), Some("serial-123"));

    // Drop and resume the connection: the reattach must carry the serial
    // and the ATTACH_RESUME flag
    mock.active_connection().simulate_disconnect();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    let reattach = loop {
        let attaches: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.action == action::ATTACH)
            .collect();
        if attaches.len() >= 2 {
            break attaches[1].clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "no reattach observed");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };
    assert_eq!(
        reattach.message.channel_serial.as_deref(),
        Some("serial-123"),
        "RTL4c1"
    );
    assert!(
        reattach.message.flags.unwrap_or(0) & flags::ATTACH_RESUME != 0,
        "RTL4j: ATTACH_RESUME set on reattach"
    );
}

// UTS: RTL4k params + RTL4l modes on ATTACH; RTL4m modes from ATTACHED
#[tokio::test]
async fn rtl4k_rtl4l_rtl4m_params_and_modes() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    let options = RealtimeChannelOptions {
        params: Some(params),
        modes: Some(vec![ChannelMode::Publish, ChannelMode::Subscribe]),
        ..Default::default()
    };
    let ch = client.channels.get_with_options("modal", options).unwrap();
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });

    let sent = await_client_action(&mock, action::ATTACH, 2000).await;
    // RTL4k: params travel in the ATTACH
    assert_eq!(sent.message.params.as_ref().unwrap()["rewind"], "1");
    // RTL4l: modes travel as flags
    let sent_flags = sent.message.flags.unwrap_or(0);
    assert!(sent_flags & flags::PUBLISH != 0);
    assert!(sent_flags & flags::SUBSCRIBE != 0);
    assert!(sent_flags & flags::PRESENCE == 0);

    // RTL4m: the server's granted modes are exposed
    let mut reply = attached_msg("modal");
    reply.flags = Some(flags::PUBLISH | flags::SUBSCRIBE);
    mock.active_connection().send_to_client(reply);
    assert!(attach.await.unwrap().is_ok());
    assert_eq!(
        ch.modes(),
        Some(vec![ChannelMode::Publish, ChannelMode::Subscribe])
    );
}

// UTS: RTL4g attach from FAILED proceeds and clears errorReason (RTL4c)
#[tokio::test]
async fn rtl4g_attach_from_failed_proceeds() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("fail-then-attach");
    let ch2 = ch.clone();
    let attach1 = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    // The server refuses the attach: channel ERROR
    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.channel = Some("fail-then-attach".to_string());
    err_msg.error = Some(ErrorInfo::with_status(90001, 400, "attach refused"));
    mock.active_connection().send_to_client(err_msg);
    assert!(attach1.await.unwrap().is_err());
    assert_eq!(ch.state(), ChannelState::Failed);
    assert!(ch.error_reason().is_some());

    // RTL4g: a fresh attach proceeds and clears errorReason
    let ch3 = ch.clone();
    let attach2 = tokio::spawn(async move { ch3.attach().await });
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        let count = mock
            .client_messages()
            .iter()
            .filter(|m| m.action == action::ATTACH)
            .count();
        if count >= 2 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    mock.active_connection().send_to_client(attached_msg("fail-then-attach"));
    assert!(attach2.await.unwrap().is_ok());
    assert_eq!(ch.state(), ChannelState::Attached);
    assert!(ch.error_reason().is_none(), "RTL4c: errorReason cleared");
}

// ============================================================================
// RTL5 — detach
// ============================================================================

// UTS: RTL5a detach when initialized/detached is a no-op
#[tokio::test]
async fn rtl5a_detach_noop_states() {
    let (mock, client) = auto_serving_client();
    let server = spawn_channel_server(&mock);
    connect(&client).await;

    let ch = client.channels.get("noop");
    ch.detach().await.expect("detach initialized is ok");
    assert_eq!(ch.state(), ChannelState::Initialized);

    ch.attach().await.unwrap();
    ch.detach().await.unwrap();
    assert_eq!(ch.state(), ChannelState::Detached);
    let detaches = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::DETACH)
        .count();
    ch.detach().await.expect("detach when detached is ok");
    let detaches_after = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::DETACH)
        .count();
    assert_eq!(detaches, detaches_after, "no extra DETACH sent");
    server.abort();
}

// UTS: RTL5d normal detach flow
#[tokio::test]
async fn rtl5d_normal_detach_flow() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("detachable");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    mock.active_connection().send_to_client(attached_msg("detachable"));
    attach.await.unwrap().unwrap();

    let ch3 = ch.clone();
    let detach = tokio::spawn(async move { ch3.detach().await });
    await_client_action(&mock, action::DETACH, 2000).await;
    assert_eq!(ch.state(), ChannelState::Detaching);
    mock.active_connection().send_to_client(detached_msg("detachable"));
    assert!(detach.await.unwrap().is_ok());
    assert_eq!(ch.state(), ChannelState::Detached);
}

// UTS: RTL5b detach from FAILED errors
#[tokio::test]
async fn rtl5b_detach_from_failed_errors() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("failed-detach");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.channel = Some("failed-detach".to_string());
    err_msg.error = Some(ErrorInfo::with_status(90001, 400, "nope"));
    mock.active_connection().send_to_client(err_msg);
    let _ = attach.await.unwrap();
    assert_eq!(ch.state(), ChannelState::Failed);

    let err = ch.detach().await.expect_err("detach from failed errors");
    assert_eq!(err.code, Some(90001));
}

// UTS: RTL5f detach timeout returns to the previous state
#[tokio::test(start_paused = true)]
async fn rtl5f_detach_timeout_reverts() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("revert");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    mock.active_connection().send_to_client(attached_msg("revert"));
    attach.await.unwrap().unwrap();

    // DETACH is never answered: it times out and the channel reverts
    let err = ch.detach().await.expect_err("detach must time out");
    assert_eq!(err.status_code, Some(408));
    assert_eq!(ch.state(), ChannelState::Attached, "RTL5f: reverted");
}

// UTS: RTL5k ATTACHED while detaching is answered with a fresh DETACH
#[tokio::test]
async fn rtl5k_attached_while_detaching_sends_new_detach() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("sticky");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    mock.active_connection().send_to_client(attached_msg("sticky"));
    attach.await.unwrap().unwrap();

    let ch3 = ch.clone();
    let detach = tokio::spawn(async move { ch3.detach().await });
    await_client_action(&mock, action::DETACH, 2000).await;

    // The server sends ATTACHED instead (e.g. a crossed wire)
    mock.active_connection().send_to_client(attached_msg("sticky"));

    // RTL5k: a second DETACH goes out
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        let count = mock
            .client_messages()
            .iter()
            .filter(|m| m.action == action::DETACH)
            .count();
        if count >= 2 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "no second DETACH");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    mock.active_connection().send_to_client(detached_msg("sticky"));
    assert!(detach.await.unwrap().is_ok());
    assert_eq!(ch.state(), ChannelState::Detached);
}

// UTS: RTL5l detach of an ATTACHING (queued) channel while the connection
// is still CONNECTING goes straight to DETACHED, nothing on the wire
#[tokio::test]
async fn rtl5l_detach_while_connecting_is_immediate() {
    // Park every connection attempt: the connection never completes
    let mock = MockWebSocket::with_handler(|conn| std::mem::forget(conn));
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();
    client.connect();

    let ch = client.channels.get("connecting-detach");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(ch.state(), ChannelState::Attaching, "RTL4i: queued attach");

    ch.detach().await.expect("RTL5l: immediate detach");
    assert_eq!(ch.state(), ChannelState::Detached);
    assert!(
        attach.await.unwrap().is_err(),
        "the abandoned attach is rejected"
    );
    assert!(mock.client_messages().is_empty(), "nothing on the wire");
}

// UTS: RTL5l detach with no live connection transitions immediately
#[tokio::test]
async fn rtl5l_detach_without_connection_is_immediate() {
    let (mock, client) = auto_serving_client();
    let server = spawn_channel_server(&mock);
    connect(&client).await;

    let ch = client.channels.get("offline-detach");
    ch.attach().await.unwrap();
    server.abort();

    // Kill the connection (no reconnect succeeds: handler keeps connecting,
    // but we detach while DISCONNECTED/CONNECTING)
    client.close();
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

    // RTL3b already detached it on CLOSED; verify the no-op path
    assert_eq!(ch.state(), ChannelState::Detached);
    ch.detach().await.expect("detach offline is immediate");
}

// ============================================================================
// RTL3 — connection state effects
// ============================================================================

async fn attached_channel(
    mock: &MockWebSocket,
    client: &Realtime,
    name: &str,
) -> Arc<crate::channel::RealtimeChannel> {
    let ch = client.channels.get(name);
    let ch2 = ch.clone();
    let name2 = name.to_string();
    let attach = tokio::spawn(async move { ch2.attach().await });
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::ATTACH && m.channel.as_deref() == Some(&name2))
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    mock.active_connection().send_to_client(attached_msg(name));
    attach.await.unwrap().unwrap();
    ch
}

// UTS: RTL3a FAILED connection fails attached channels
#[tokio::test]
async fn rtl3a_connection_failed_fails_channels() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;
    let ch = attached_channel(&mock, &client, "doomed").await;

    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.error = Some(ErrorInfo::with_status(40400, 404, "fatal"));
    mock.active_connection().send_to_client_and_close(err_msg);
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    assert_eq!(ch.state(), ChannelState::Failed);
    assert_eq!(ch.error_reason().and_then(|e| e.code), Some(40400));
}

// UTS: RTL3b CLOSED connection detaches attached channels
#[tokio::test]
async fn rtl3b_connection_closed_detaches_channels() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;
    let ch = attached_channel(&mock, &client, "closing").await;

    // RTL3b also applies to a channel still ATTACHING at close time
    let pending = client.channels.get("closing-pending");
    let pending2 = pending.clone();
    let pending_attach = tokio::spawn(async move { pending2.attach().await });
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::ATTACH && m.channel.as_deref() == Some("closing-pending"))
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    assert_eq!(pending.state(), ChannelState::Attaching);

    client.close();
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

    assert_eq!(ch.state(), ChannelState::Detached);
    assert_eq!(pending.state(), ChannelState::Detached);
    assert!(
        pending_attach.await.unwrap().is_err(),
        "in-flight attach fails when the connection closes"
    );
}

// UTS: RTL3c SUSPENDED connection suspends attached channels
#[tokio::test(start_paused = true)]
async fn rtl3c_connection_suspended_suspends_channels() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            let c = conn.respond_with_connection();
            c.send_to_client(connected_msg("id", "key"));
            std::mem::forget(c);
        } else {
            conn.respond_with_refused();
        }
    });
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret")
        .auto_connect(false)
        .fallback_hosts(vec![])
        .disconnected_retry_timeout(std::time::Duration::from_secs(1))
        .connection_state_ttl(std::time::Duration::from_secs(3));
    let client = Realtime::with_mock(&opts, transport).unwrap();
    connect(&client).await;
    let ch = attached_channel(&mock, &client, "suspendable").await;

    // Kill the transport; all reconnects fail until suspension
    mock.active_connection().simulate_disconnect();
    assert!(await_state(&client.connection, ConnectionState::Suspended, 60000).await);

    assert_eq!(ch.state(), ChannelState::Suspended, "RTL3c");
}

// UTS: RTL3d CONNECTED re-attaches suspended/attached channels;
// initialized/detached channels are untouched
#[tokio::test]
async fn rtl3d_reattach_on_connected() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;
    let attached = attached_channel(&mock, &client, "live").await;
    let attached_second = attached_channel(&mock, &client, "live2").await;
    let untouched = client.channels.get("idle");
    assert_eq!(untouched.state(), ChannelState::Initialized);

    // Drop the transport: the connection resumes and ALL attached channels
    // re-attach (RTL3d covers every attached channel, not just one)
    mock.active_connection().simulate_disconnect();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let reattached = ["live", "live2"].iter().all(|name| {
            mock.client_messages()
                .iter()
                .filter(|m| m.action == action::ATTACH && m.channel.as_deref() == Some(*name))
                .count()
                >= 2
        });
        if reattached {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "no reattach");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    mock.active_connection().send_to_client(attached_msg("live"));
    mock.active_connection().send_to_client(attached_msg("live2"));
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while attached.state() != ChannelState::Attached
        || attached_second.state() != ChannelState::Attached
    {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    // RTL3d: untouched channels stay untouched
    assert_eq!(untouched.state(), ChannelState::Initialized);
    assert_eq!(
        mock.client_messages()
            .iter()
            .filter(|m| m.action == action::ATTACH && m.channel.as_deref() == Some("idle"))
            .count(),
        0
    );
}

// UTS: RTL3e DISCONNECTED has no effect on channel state
#[tokio::test(start_paused = true)]
async fn rtl3e_disconnected_leaves_channels_untouched() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_c = attempts.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let n = attempts_c.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            let c = conn.respond_with_connection();
            c.send_to_client(connected_msg("id", "key"));
            std::mem::forget(c);
        } else {
            // Park further attempts: the connection stays DISCONNECTED/CONNECTING
            std::mem::forget(conn);
        }
    });
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret")
        .auto_connect(false)
        .fallback_hosts(vec![])
        .connection_state_ttl(std::time::Duration::from_secs(3600));
    let client = Realtime::with_mock(&opts, transport).unwrap();
    connect(&client).await;
    let ch = attached_channel(&mock, &client, "stable").await;

    // A second channel still ATTACHING when the transport drops
    let pending = client.channels.get("stable-pending");
    let pending2 = pending.clone();
    let _pending_attach = tokio::spawn(async move { pending2.attach().await });
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        if mock
            .client_messages()
            .iter()
            .any(|m| m.action == action::ATTACH && m.channel.as_deref() == Some("stable-pending"))
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    mock.active_connection().simulate_disconnect();
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // RTL3e: channel states are untouched while the connection is down
    assert_eq!(ch.state(), ChannelState::Attached);
    assert_eq!(pending.state(), ChannelState::Attaching);
}

// ============================================================================
// RTL2 — event details (UPDATE, resumed, hasBacklog)
// ============================================================================

// UTS: RTL2g UPDATE for additional ATTACHED (resumed=false); RESUMED
// suppresses it (RTL12); never a duplicate state event
#[tokio::test]
async fn rtl2g_update_event_and_no_duplicates() {
    use crate::protocol::ChannelEvent;
    let (mock, client) = auto_serving_client();
    connect(&client).await;
    let ch = attached_channel(&mock, &client, "updates").await;

    let events: Arc<StdMutex<Vec<crate::protocol::ChannelStateChange>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let events_c = events.clone();
    let mut rx = ch.on_state_change();
    tokio::spawn(async move {
        while let Ok(change) = rx.recv().await {
            events_c.lock().unwrap().push(change);
        }
    });

    // Additional ATTACHED without RESUMED: loss of continuity → UPDATE
    mock.active_connection().send_to_client(attached_msg("updates"));
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    {
        let seen = events.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "exactly one event for the extra ATTACHED");
        assert_eq!(seen[0].event, ChannelEvent::Update, "RTL2g: UPDATE");
        assert_eq!(seen[0].previous, ChannelState::Attached);
        assert_eq!(seen[0].current, ChannelState::Attached);
        assert!(!seen[0].resumed);
    }
    assert_eq!(ch.state(), ChannelState::Attached, "state unchanged");

    // Additional ATTACHED with RESUMED: continuity preserved → no event
    let mut resumed_msg = attached_msg("updates");
    resumed_msg.flags = Some(flags::RESUMED);
    mock.active_connection().send_to_client(resumed_msg);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(
        events.lock().unwrap().len(),
        1,
        "RTL12: RESUMED suppresses the UPDATE"
    );
}

// UTS: RTL2i/TH6 hasBacklog reflects the HAS_BACKLOG flag
#[tokio::test]
async fn rtl2i_has_backlog_flag() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    for (name, msg_flags, expect) in [
        ("backlog", Some(flags::HAS_BACKLOG), true),
        ("no-backlog", None, false),
    ] {
        let ch = client.channels.get(name);
        let mut events = ch.on_state_change();
        let ch2 = ch.clone();
        let attach = tokio::spawn(async move { ch2.attach().await });
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
        loop {
            if mock
                .client_messages()
                .iter()
                .any(|m| m.action == action::ATTACH && m.channel.as_deref() == Some(name))
            {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
        let mut reply = attached_msg(name);
        reply.flags = msg_flags;
        mock.active_connection().send_to_client(reply);
        attach.await.unwrap().unwrap();

        // Find the ATTACHING→ATTACHED change
        let change = loop {
            let c = events.recv().await.expect("state change");
            if c.current == ChannelState::Attached {
                break c;
            }
        };
        assert_eq!(change.has_backlog, expect, "RTL2i for {}", name);
    }
}

// UTS: RTL2d resumed flag propagated from the RESUMED flag on ATTACHED
#[tokio::test]
async fn rtl2d_resumed_flag_propagated() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("resumed-flag");
    let mut events = ch.on_state_change();
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    let mut reply = attached_msg("resumed-flag");
    reply.flags = Some(flags::RESUMED);
    mock.active_connection().send_to_client(reply);
    attach.await.unwrap().unwrap();

    let change = loop {
        let c = events.recv().await.expect("state change");
        if c.current == ChannelState::Attached {
            break c;
        }
    };
    assert!(change.resumed, "RTL2d: resumed propagated");
}

// ============================================================================
// RTL4h/RTL5i — pending-state continuations
// ============================================================================

// UTS: RTL4h attach while detaching waits, then attaches
#[tokio::test]
async fn rtl4h_attach_while_detaching_waits_then_attaches() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;
    let ch = attached_channel(&mock, &client, "flip").await;

    let ch2 = ch.clone();
    let detach = tokio::spawn(async move { ch2.detach().await });
    await_client_action(&mock, action::DETACH, 2000).await;
    assert_eq!(ch.state(), ChannelState::Detaching);

    let ch3 = ch.clone();
    let attach = tokio::spawn(async move { ch3.attach().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    mock.active_connection().send_to_client(detached_msg("flip"));
    assert!(detach.await.unwrap().is_ok());

    // The queued attach goes out now (second ATTACH overall)
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        let count = mock
            .client_messages()
            .iter()
            .filter(|m| m.action == action::ATTACH)
            .count();
        if count >= 2 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "no queued ATTACH");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    mock.active_connection().send_to_client(attached_msg("flip"));
    assert!(attach.await.unwrap().is_ok());
    assert_eq!(ch.state(), ChannelState::Attached);
}

// UTS: RTL5i detach while detaching shares the in-flight operation
#[tokio::test]
async fn rtl5i_detach_while_detaching_waits() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;
    let ch = attached_channel(&mock, &client, "shared-detach").await;

    let ch2 = ch.clone();
    let first = tokio::spawn(async move { ch2.detach().await });
    await_client_action(&mock, action::DETACH, 2000).await;
    let ch3 = ch.clone();
    let second = tokio::spawn(async move { ch3.detach().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    mock.active_connection().send_to_client(detached_msg("shared-detach"));
    assert!(first.await.unwrap().is_ok());
    assert!(second.await.unwrap().is_ok());
    assert_eq!(ch.state(), ChannelState::Detached);
    let detach_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::DETACH)
        .count();
    assert_eq!(detach_count, 1, "RTL5i: only one DETACH sent");
}

// UTS: RTL5i detach while attaching waits for the attach, then detaches
#[tokio::test]
async fn rtl5i_detach_while_attaching_waits_then_detaches() {
    let (mock, client) = auto_serving_client();
    connect(&client).await;

    let ch = client.channels.get("attach-then-detach");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_client_action(&mock, action::ATTACH, 2000).await;
    let ch3 = ch.clone();
    let detach = tokio::spawn(async move { ch3.detach().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // Attach completes; the queued detach then proceeds
    mock.active_connection().send_to_client(attached_msg("attach-then-detach"));
    assert!(attach.await.unwrap().is_ok());
    await_client_action(&mock, action::DETACH, 2000).await;
    mock.active_connection().send_to_client(detached_msg("attach-then-detach"));
    assert!(detach.await.unwrap().is_ok());
    assert_eq!(ch.state(), ChannelState::Detached);

    // Wire order: ATTACH then DETACH
    let actions: Vec<u8> = mock.client_messages().iter().map(|m| m.action).collect();
    let attach_pos = actions.iter().position(|&a| a == action::ATTACH).unwrap();
    let detach_pos = actions.iter().position(|&a| a == action::DETACH).unwrap();
    assert!(attach_pos < detach_pos);
}

// UTS: RTL5j detach from SUSPENDED is an immediate local transition
#[tokio::test(start_paused = true)]
async fn rtl5j_detach_from_suspended_transitions_to_detached() {
    let (mock, client) = auto_serving_client(); // ATTACH never answered
    connect(&client).await;

    let ch = client.channels.get("suspended-detach");
    ch.attach().await.expect_err("attach times out");
    assert_eq!(ch.state(), ChannelState::Suspended);

    ch.detach().await.expect("detach from suspended succeeds");
    assert_eq!(ch.state(), ChannelState::Detached);
    let detach_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::DETACH)
        .count();
    assert_eq!(detach_count, 0, "RTL5j: no DETACH on the wire");
}

// ============================================================================
// RTL25 — whenState
// ============================================================================

// UTS: RTL25a fires immediately when already in the state
#[tokio::test]
async fn rtl25a_when_state_fires_immediately() {
    let (_mock, client) = auto_serving_client();
    let ch = client.channels.get("immediate");

    let (tx, rx) = tokio::sync::oneshot::channel();
    ch.when_state(ChannelState::Initialized, move |change| {
        let _ = tx.send(change);
    });
    let change = tokio::time::timeout(tokio::time::Duration::from_secs(1), rx)
        .await
        .expect("fired")
        .unwrap();
    assert_eq!(change.current, ChannelState::Initialized);
}

// UTS: RTL25b waits for the transition and fires exactly once
#[tokio::test]
async fn rtl25b_when_state_waits_and_fires_once() {
    let (mock, client) = auto_serving_client();
    let server = spawn_channel_server(&mock);
    connect(&client).await;

    let ch = client.channels.get("eventual");
    let fired = Arc::new(AtomicU32::new(0));
    let fired_c = fired.clone();
    ch.when_state(ChannelState::Attached, move |change| {
        assert_eq!(change.current, ChannelState::Attached);
        fired_c.fetch_add(1, Ordering::SeqCst);
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    assert_eq!(fired.load(Ordering::SeqCst), 0, "not fired before transition");

    ch.attach().await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(fired.load(Ordering::SeqCst), 1);

    // A second attach cycle must not re-fire the one-shot callback
    ch.detach().await.unwrap();
    ch.attach().await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(fired.load(Ordering::SeqCst), 1, "RTL25b: fires only once");
    server.abort();
}

// ============================================================================
// RTL23 / RTL15 — attributes and properties
// ============================================================================

// UTS: RTL23 name attribute (channel_attributes.md)
#[tokio::test]
async fn rtl23_name_attribute() {
    let (_mock, client) = auto_serving_client();
    assert_eq!(client.channels.get("my-channel").name(), "my-channel");
    assert_eq!(
        client.channels.get("namespace:channel-name").name(),
        "namespace:channel-name"
    );
}

// UTS: RTL15a/RTL15b serials from ATTACHED; RTL15b1 cleared on DETACHED
#[tokio::test]
async fn rtl15b1_channel_serial_cleared_on_detached() {
    let (mock, client) = auto_serving_client();
    let server = spawn_channel_server(&mock); // replies with serial-<name>
    connect(&client).await;

    let ch = client.channels.get("serial-ch");
    ch.attach().await.unwrap();
    assert_eq!(ch.channel_serial().as_deref(), Some("serial-serial-ch"));
    assert_eq!(ch.attach_serial().as_deref(), Some("serial-serial-ch"));

    ch.detach().await.unwrap();
    assert_eq!(ch.state(), ChannelState::Detached);
    assert!(ch.channel_serial().is_none(), "RTL15b1: cleared on DETACHED");
    server.abort();
}

// ============================================================================
// Live sandbox — channel attach/detach over a real connection
// ============================================================================

#[tokio::test]
async fn live_channel_attach_detach_against_sandbox() {
    let app = crate::tests_rest_integration::get_sandbox().await;
    let opts = crate::options::ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();

    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 10000).await,
        "must reach CONNECTED against the live sandbox"
    );

    let ch = client.channels.get("uts-live-channel");
    ch.attach().await.expect("live attach");
    assert_eq!(ch.state(), ChannelState::Attached);
    assert!(ch.attach_serial().is_some(), "live attachSerial assigned");

    ch.detach().await.expect("live detach");
    assert_eq!(ch.state(), ChannelState::Detached);

    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closed, 10000).await);
}

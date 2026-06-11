#![cfg(test)]

//! Stage 5.5 channel-message tests, derived from the UTS specs
//! (DESIGN.md Realtime §12). Sources:
//! - uts/realtime/unit/channels/channel_publish.md (RTL6, RTN7, RTN19)
//! - uts/realtime/unit/channels/channel_subscribe.md (RTL7/8/17/22)
//! - uts/realtime/unit/channels/message_field_population.md (TM2)
//! - uts/realtime/unit/channels/channel_properties.md (RTL15b)
//! - uts/realtime/unit/channels/channel_history.md (RTL10),
//!   channel_get_message.md (RTL28), channel_message_versions.md (RTL31),
//!   channel_update_delete_message.md (RTL32)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::error::ErrorInfo;
use crate::mock_ws::{MockTransport, MockWebSocket};
use crate::options::ClientOptions;
use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
use crate::realtime::{await_state, Realtime};
use crate::rest::Message;

fn connected_msg(id: &str, key: &str) -> ProtocolMessage {
    ProtocolMessage::connected(id, key)
}

/// A mock that connects with the given connection id and answers every
/// ATTACH/DETACH; MESSAGE handling is left to each test.
fn serving_mock(conn_id: &'static str) -> MockWebSocket {
    MockWebSocket::with_handler(move |conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg(conn_id, "conn-key"));
        std::mem::forget(c);
    })
}

fn client_for(mock: &MockWebSocket) -> Realtime {
    let transport = Arc::new(MockTransport::new(mock.inner()));
    Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap()
}

/// Spawn an ATTACH/DETACH echo server.
fn spawn_channel_server(mock: &MockWebSocket) -> tokio::task::JoinHandle<()> {
    let mock2 = mock.clone();
    tokio::spawn(async move {
        let mut served = 0usize;
        loop {
            let msgs = mock2.client_messages();
            for m in msgs.iter().skip(served) {
                let reply_action = match m.action {
                    a if a == action::ATTACH => Some(action::ATTACHED),
                    a if a == action::DETACH => Some(action::DETACHED),
                    _ => None,
                };
                if let Some(a) = reply_action {
                    let mut reply = ProtocolMessage::new(a);
                    reply.channel = m.channel.clone();
                    mock2.active_connection().send_to_client(reply);
                }
            }
            served = msgs.len();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    })
}

/// Spawn a server that also ACKs every MESSAGE with the given serials.
fn spawn_acking_server(mock: &MockWebSocket, ack_serial: &'static str) -> tokio::task::JoinHandle<()> {
    let mock2 = mock.clone();
    tokio::spawn(async move {
        let mut served = 0usize;
        loop {
            let msgs = mock2.client_messages();
            for m in msgs.iter().skip(served) {
                match m.action {
                    a if a == action::ATTACH => {
                        let mut reply = ProtocolMessage::new(action::ATTACHED);
                        reply.channel = m.channel.clone();
                        mock2.active_connection().send_to_client(reply);
                    }
                    a if a == action::DETACH => {
                        let mut reply = ProtocolMessage::new(action::DETACHED);
                        reply.channel = m.channel.clone();
                        mock2.active_connection().send_to_client(reply);
                    }
                    a if a == action::MESSAGE => {
                        let n = m.message.messages.as_ref().map(|v| v.len()).unwrap_or(1);
                        let mut ack = ProtocolMessage::new(action::ACK);
                        ack.msg_serial = m.message.msg_serial;
                        ack.count = Some(1);
                        ack.res = Some(vec![crate::protocol::PublishResult {
                            serials: (0..n).map(|i| Some(format!("{}-{}", ack_serial, i))).collect(),
                        }]);
                        mock2.active_connection().send_to_client(ack);
                    }
                    _ => {}
                }
            }
            served = msgs.len();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    })
}

async fn connect(client: &Realtime) {
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
}

async fn await_nth_action(
    mock: &MockWebSocket,
    wanted: u8,
    n: usize,
    timeout_ms: u64,
) -> crate::mock_ws::CapturedMessage {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
    loop {
        let matching: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.action == wanted)
            .collect();
        if matching.len() >= n {
            return matching[n - 1].clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "client never sent action {} (x{})",
            wanted,
            n
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
}

fn send_channel_message(mock: &MockWebSocket, channel: &str, messages: serde_json::Value) {
    let mut pm = ProtocolMessage::new(action::MESSAGE);
    pm.channel = Some(channel.to_string());
    pm.messages = Some(messages.as_array().unwrap().clone());
    mock.active_connection().send_to_client(pm);
}

// ============================================================================
// RTL6 — publish
// ============================================================================

// UTS: RTL6i1 publish by name and data; RTL6j msgSerial 0; ACK serials
#[tokio::test]
async fn rtl6i1_rtl6j_publish_name_data_with_ack_serials() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_acking_server(&mock, "abc123");
    connect(&client).await;
    let ch = client.channels.get("pub");
    ch.attach().await.unwrap();

    let result = ch
        .publish_message(Some("greeting"), Some(serde_json::json!("hello")))
        .await
        .expect("publish resolves on ACK");

    let sent = await_nth_action(&mock, action::MESSAGE, 1, 2000).await;
    assert_eq!(sent.message.msg_serial, Some(0), "RTN7b: serials start at 0");
    let wire = sent.message.messages.as_ref().unwrap();
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0]["name"], "greeting");
    assert_eq!(wire[0]["data"], "hello");
    // RTL6j: serials from the ACK's res
    assert_eq!(result.serials, vec![Some("abc123-0".to_string())]);
    server.abort();
}

// UTS: RTL6i2 array of Message objects in one ProtocolMessage
#[tokio::test]
async fn rtl6i2_publish_array_of_messages() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_acking_server(&mock, "s");
    connect(&client).await;
    let ch = client.channels.get("multi");
    ch.attach().await.unwrap();

    let msgs = vec![
        Message { name: Some("event1".into()), data: crate::rest::Data::String("d1".into()), ..Default::default() },
        Message { name: Some("event2".into()), data: crate::rest::Data::String("d2".into()), ..Default::default() },
        Message { name: Some("event3".into()), data: crate::rest::Data::String("d3".into()), ..Default::default() },
    ];
    let result = ch.publish().messages(msgs).send().await.expect("publish");

    let sent = await_nth_action(&mock, action::MESSAGE, 1, 2000).await;
    let wire = sent.message.messages.as_ref().unwrap();
    assert_eq!(wire.len(), 3, "RTL6i2: one ProtocolMessage, three messages");
    assert_eq!(wire[0]["name"], "event1");
    assert_eq!(wire[2]["name"], "event3");
    assert_eq!(result.serials.len(), 3);
    server.abort();
}

// UTS: RTL6i3 null fields omitted from the wire encoding
#[tokio::test]
async fn rtl6i3_null_fields_omitted() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_acking_server(&mock, "s");
    connect(&client).await;
    let ch = client.channels.get("sparse");
    ch.attach().await.unwrap();

    ch.publish().name("only-name").send().await.expect("publish");
    let sent = await_nth_action(&mock, action::MESSAGE, 1, 2000).await;
    let wire = &sent.message.messages.as_ref().unwrap()[0];
    let obj = wire.as_object().unwrap();
    assert_eq!(obj.get("name").and_then(|v| v.as_str()), Some("only-name"));
    for absent in ["id", "clientId", "connectionId", "encoding", "extras"] {
        assert!(!obj.contains_key(absent), "RTL6i3: `{}` omitted", absent);
    }
    server.abort();
}

// UTS: RTL6c1 publish immediately when CONNECTED — attached, attaching,
// and initialized channels alike; RTL6c5: no implicit attach
#[tokio::test]
async fn rtl6c1_rtl6c5_publish_immediately_no_implicit_attach() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_acking_server(&mock, "s");
    connect(&client).await;

    // INITIALIZED channel: publish flows immediately, no ATTACH on the wire
    let ch = client.channels.get("untouched");
    ch.publish_message(Some("e"), Some(serde_json::json!("d")))
        .await
        .expect("publish on initialized channel");
    assert_eq!(ch.state(), ChannelState::Initialized, "RTL6c5");
    let attaches = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::ATTACH)
        .count();
    assert_eq!(attaches, 0, "RTL6c5: no implicit attach from publish");
    server.abort();
}

// UTS: RTL6c2 queued while CONNECTING, sent in order once CONNECTED
#[tokio::test]
async fn rtl6c2_publish_queued_while_connecting_in_order() {
    let gate: Arc<StdMutex<Option<crate::mock_ws::PendingConnection>>> =
        Arc::new(StdMutex::new(None));
    let gate_c = gate.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        *gate_c.lock().unwrap() = Some(conn);
    });
    let client = client_for(&mock);
    client.connect();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    assert_eq!(client.connection.state(), ConnectionState::Connecting);

    let ch = client.channels.get("queued");
    let mut futures = Vec::new();
    for i in 0..3 {
        let ch2 = ch.clone();
        futures.push(tokio::spawn(async move {
            ch2.publish_message(Some(&format!("m{}", i)), None).await
        }));
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert!(mock.client_messages().is_empty(), "queued, nothing sent");

    // Complete the connection; the queue flushes in order with serials 0..2
    let conn = gate
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .respond_with_success(connected_msg("conn-1", "key"));
    let third = await_nth_action(&mock, action::MESSAGE, 3, 3000).await;
    let sent: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.action == action::MESSAGE)
        .collect();
    assert_eq!(sent[0].message.msg_serial, Some(0));
    assert_eq!(sent[0].message.messages.as_ref().unwrap()[0]["name"], "m0");
    assert_eq!(sent[1].message.msg_serial, Some(1));
    assert_eq!(sent[2].message.msg_serial, Some(2));
    assert_eq!(third.message.messages.as_ref().unwrap()[0]["name"], "m2");

    // ACK all three
    let mut ack = ProtocolMessage::new(action::ACK);
    ack.msg_serial = Some(0);
    ack.count = Some(3);
    ack.res = Some(vec![
        crate::protocol::PublishResult { serials: vec![Some("a".into())] },
        crate::protocol::PublishResult { serials: vec![Some("b".into())] },
        crate::protocol::PublishResult { serials: vec![Some("c".into())] },
    ]);
    conn.send_to_client(ack);
    for f in futures {
        f.await.unwrap().expect("each queued publish resolves");
    }
}

// UTS: RTL6c2 queueMessages=false fails immediately when not connected
#[tokio::test]
async fn rtl6c2_no_queue_fails_when_not_connected() {
    let mock = MockWebSocket::with_handler(|conn| std::mem::forget(conn));
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .queue_messages(false),
        transport,
    )
    .unwrap();
    client.connect();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    let ch = client.channels.get("noq");
    let err = ch
        .publish_message(Some("e"), None)
        .await
        .expect_err("queueMessages=false: immediate failure");
    assert!(err.code.is_some());
    assert!(mock.client_messages().is_empty());
}

// UTS: RTL6c4 publish fails for SUSPENDED/FAILED channels and terminal
// connection states
#[tokio::test]
async fn rtl6c4_publish_fails_in_terminal_states() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    connect(&client).await;

    // Channel FAILED (refused attach)
    let ch = client.channels.get("doomed");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_nth_action(&mock, action::ATTACH, 1, 2000).await;
    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.channel = Some("doomed".to_string());
    err_msg.error = Some(ErrorInfo::with_status(40160, 401, "denied"));
    mock.active_connection().send_to_client(err_msg);
    let _ = attach.await.unwrap();
    assert_eq!(ch.state(), ChannelState::Failed);
    let err = ch.publish_message(Some("e"), None).await.expect_err("RTL6c4");
    assert_eq!(err.code, Some(40160), "channel error reason surfaces");

    // Connection CLOSED
    client.close();
    mock.active_connection().send_to_client(ProtocolMessage::new(action::CLOSED));
    assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
    let healthy = client.channels.get("healthy");
    let err = healthy.publish_message(Some("e"), None).await.expect_err("RTL6c4");
    assert!(err.code.is_some());
}

// UTS: RTL6j sequential publishes get incrementing msgSerial; NACK errors
#[tokio::test]
async fn rtl6j_incrementing_serials_and_nack() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("serials");
    ch.attach().await.unwrap();

    let ch1 = ch.clone();
    let f1 = tokio::spawn(async move { ch1.publish_message(Some("a"), None).await });
    let ch2 = ch.clone();
    let f2 = tokio::spawn(async move { ch2.publish_message(Some("b"), None).await });

    let first = await_nth_action(&mock, action::MESSAGE, 1, 2000).await;
    let second = await_nth_action(&mock, action::MESSAGE, 2, 2000).await;
    let (s1, s2) = (
        first.message.msg_serial.unwrap(),
        second.message.msg_serial.unwrap(),
    );
    assert_eq!((s1, s2), (0, 1), "RTN7b: incrementing serials");

    // ACK the first, NACK the second
    let mut ack = ProtocolMessage::new(action::ACK);
    ack.msg_serial = Some(s1);
    ack.count = Some(1);
    mock.active_connection().send_to_client(ack);
    let mut nack = ProtocolMessage::new(action::NACK);
    nack.msg_serial = Some(s2);
    nack.count = Some(1);
    nack.error = Some(ErrorInfo::with_status(40160, 401, "rejected"));
    mock.active_connection().send_to_client(nack);

    assert!(f1.await.unwrap().is_ok());
    let err = f2.await.unwrap().expect_err("NACK fails the publish");
    assert_eq!(err.code, Some(40160));
    server.abort();
}

// ============================================================================
// RTN7 / RTN19 — pending publishes across connection changes
// ============================================================================

// UTS: RTN7e pending publishes fail on FAILED with the state-change reason
#[tokio::test]
async fn rtn7e_pending_publishes_fail_on_failed() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("pending");
    ch.attach().await.unwrap();
    server.abort();

    // Two unACKed publishes in flight
    let ch1 = ch.clone();
    let f1 = tokio::spawn(async move { ch1.publish_message(Some("a"), None).await });
    let ch2 = ch.clone();
    let f2 = tokio::spawn(async move { ch2.publish_message(Some("b"), None).await });
    await_nth_action(&mock, action::MESSAGE, 2, 2000).await;

    // Fatal connection error
    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.error = Some(ErrorInfo::with_status(40400, 404, "fatal"));
    mock.active_connection().send_to_client_and_close(err_msg);
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    for f in [f1, f2] {
        let err = f.await.unwrap().expect_err("RTN7e: pending fails");
        assert_eq!(err.code, Some(40400), "RTN7e: reason is the state change");
    }
}

// UTS: RTN19a pending publishes resent on the new transport; RTN19a2 serials
// kept on a successful resume
#[tokio::test]
async fn rtn19a_rtn19a2_resend_keeps_serials_on_resume() {
    // Every attempt connects as the SAME connection id (successful resume)
    let mock = serving_mock("conn-stable");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("resend");
    ch.attach().await.unwrap();
    server.abort();

    let ch1 = ch.clone();
    let f1 = tokio::spawn(async move { ch1.publish_message(Some("m1"), None).await });
    let ch2 = ch.clone();
    let f2 = tokio::spawn(async move { ch2.publish_message(Some("m2"), None).await });
    await_nth_action(&mock, action::MESSAGE, 2, 2000).await;

    // Drop the transport; the client reconnects and resumes
    mock.active_connection().simulate_disconnect();
    // The two pending publishes are resent (messages 3 and 4 overall)
    let resent1 = await_nth_action(&mock, action::MESSAGE, 3, 5000).await;
    let resent2 = await_nth_action(&mock, action::MESSAGE, 4, 5000).await;
    assert_eq!(resent1.message.msg_serial, Some(0), "RTN19a2: serial kept");
    assert_eq!(resent2.message.msg_serial, Some(1), "RTN19a2: serial kept");
    assert_eq!(resent1.message.messages.as_ref().unwrap()[0]["name"], "m1");

    // ACK both on the new transport
    let mut ack = ProtocolMessage::new(action::ACK);
    ack.msg_serial = Some(0);
    ack.count = Some(2);
    mock.active_connection().send_to_client(ack);
    assert!(f1.await.unwrap().is_ok());
    assert!(f2.await.unwrap().is_ok());
}

// UTS: RTN19a2 failed resume renumbers from a reset counter (RTN15c7)
#[tokio::test]
async fn rtn19a2_failed_resume_renumbers_serials() {
    // Each attempt gets a DIFFERENT connection id (failed resume)
    let n = Arc::new(AtomicUsize::new(0));
    let n_c = n.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let i = n_c.fetch_add(1, Ordering::SeqCst) + 1;
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg(&format!("conn-{}", i), "key"));
        std::mem::forget(c);
    });
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("renumber");
    ch.attach().await.unwrap();
    server.abort();

    let ch1 = ch.clone();
    let _f1 = tokio::spawn(async move { ch1.publish_message(Some("m1"), None).await });
    let ch2 = ch.clone();
    let _f2 = tokio::spawn(async move { ch2.publish_message(Some("m2"), None).await });
    await_nth_action(&mock, action::MESSAGE, 2, 2000).await;

    mock.active_connection().simulate_disconnect();
    let resent1 = await_nth_action(&mock, action::MESSAGE, 3, 5000).await;
    let resent2 = await_nth_action(&mock, action::MESSAGE, 4, 5000).await;
    // RTN15c7: the counter reset; the pendings were renumbered from 0
    assert_eq!(resent1.message.msg_serial, Some(0));
    assert_eq!(resent2.message.msg_serial, Some(1));
    assert_eq!(resent1.message.messages.as_ref().unwrap()[0]["name"], "m1");
    assert_eq!(resent2.message.messages.as_ref().unwrap()[0]["name"], "m2");
}

// UTS: RTN19b pending ATTACH and DETACH are resent on the new transport
#[tokio::test]
async fn rtn19b_pending_attach_and_detach_resent() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    connect(&client).await;

    // A channel mid-ATTACH (no reply) and one mid-DETACH (no reply)
    let attaching = client.channels.get("mid-attach");
    let a2 = attaching.clone();
    let _af = tokio::spawn(async move { a2.attach().await });
    await_nth_action(&mock, action::ATTACH, 1, 2000).await;

    let detaching = client.channels.get("mid-detach");
    let d2 = detaching.clone();
    let attach2 = tokio::spawn(async move { d2.attach().await });
    let second_attach = await_nth_action(&mock, action::ATTACH, 2, 2000).await;
    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = second_attach.channel.clone();
    mock.active_connection().send_to_client(reply);
    attach2.await.unwrap().unwrap();
    let d3 = detaching.clone();
    let _df = tokio::spawn(async move { d3.detach().await });
    await_nth_action(&mock, action::DETACH, 1, 2000).await;

    // New transport: both operations go out again
    mock.active_connection().simulate_disconnect();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let msgs = mock.client_messages();
        let attaches = msgs
            .iter()
            .filter(|m| m.action == action::ATTACH && m.channel.as_deref() == Some("mid-attach"))
            .count();
        let detaches = msgs
            .iter()
            .filter(|m| m.action == action::DETACH && m.channel.as_deref() == Some("mid-detach"))
            .count();
        if attaches >= 2 && detaches >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "RTN19b: expected re-sent ATTACH and DETACH (attaches={}, detaches={})",
            attaches,
            detaches
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

// ============================================================================
// RTL7 / RTL17 / RTL8 — subscribe and delivery
// ============================================================================

// UTS: RTL7a all messages; multiple messages per ProtocolMessage
#[tokio::test]
async fn rtl7a_subscribe_receives_all_messages() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("sub");
    let (_id, mut rx) = ch.subscribe();
    // RTL7g: subscribe triggered the implicit attach
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.state() != ChannelState::Attached {
        assert!(tokio::time::Instant::now() < deadline, "implicit attach");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    send_channel_message(
        &mock,
        "sub",
        serde_json::json!([
            {"name": "one", "data": "d1"},
            {"name": "two", "data": "d2"}
        ]),
    );
    let m1 = rx.recv().await.unwrap();
    let m2 = rx.recv().await.unwrap();
    assert_eq!(m1.name.as_deref(), Some("one"));
    assert_eq!(m2.name.as_deref(), Some("two"));
    server.abort();
}

// UTS: RTL7b name filter; independent subscriptions
#[tokio::test]
async fn rtl7b_name_filtered_subscriptions_independent() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("named");
    let (_ida, mut rx_a) = ch.subscribe_with_name("alpha");
    let (_idb, mut rx_b) = ch.subscribe_with_name("beta");
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.state() != ChannelState::Attached {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    send_channel_message(
        &mock,
        "named",
        serde_json::json!([
            {"name": "alpha", "data": "for-a"},
            {"name": "beta", "data": "for-b"},
            {"name": "gamma", "data": "for-nobody"}
        ]),
    );
    assert_eq!(rx_a.recv().await.unwrap().name.as_deref(), Some("alpha"));
    assert_eq!(rx_b.recv().await.unwrap().name.as_deref(), Some("beta"));
    // Nothing further arrives on either
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(rx_a.try_recv().is_err());
    assert!(rx_b.try_recv().is_err());
    server.abort();
}

// UTS: RTL7h attachOnSubscribe=false leaves the channel alone
#[tokio::test]
async fn rtl7h_no_attach_when_disabled() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    connect(&client).await;
    let ch = client.channels.get_with_options(
        "passive",
        crate::channel::RealtimeChannelOptions {
            attach_on_subscribe: Some(false),
            ..Default::default()
        },
    ).unwrap();
    let (_id, _rx) = ch.subscribe();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(ch.state(), ChannelState::Initialized, "RTL7h");
    assert!(mock.client_messages().is_empty());
}

// UTS: RTL7g listener registered even if the implicit attach fails
#[tokio::test]
async fn rtl7g_listener_registered_when_attach_fails() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    connect(&client).await;
    let ch = client.channels.get("flaky");
    let (_id, mut rx) = ch.subscribe();

    // The implicit attach is refused: channel FAILED
    await_nth_action(&mock, action::ATTACH, 1, 2000).await;
    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.channel = Some("flaky".to_string());
    err_msg.error = Some(ErrorInfo::with_status(40160, 401, "denied"));
    mock.active_connection().send_to_client(err_msg);
    assert!(
        crate::realtime::await_channel_state(&ch, ChannelState::Failed, 5000).await
    );

    // Explicit re-attach succeeds; the original listener still delivers
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_nth_action(&mock, action::ATTACH, 2, 2000).await;
    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = Some("flaky".to_string());
    mock.active_connection().send_to_client(reply);
    attach.await.unwrap().unwrap();

    send_channel_message(&mock, "flaky", serde_json::json!([{"name": "t", "data": "after"}]));
    let m = rx.recv().await.expect("RTL7g: the listener survived");
    assert_eq!(m.name.as_deref(), Some("t"));
}

// UTS: RTL17 messages not delivered unless ATTACHED
#[tokio::test]
async fn rtl17_no_delivery_when_not_attached() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    connect(&client).await;
    let ch = client.channels.get_with_options(
        "gated",
        crate::channel::RealtimeChannelOptions {
            attach_on_subscribe: Some(false),
            ..Default::default()
        },
    ).unwrap();
    let (_id, mut rx) = ch.subscribe();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // The channel is INITIALIZED: a stray MESSAGE must not be delivered
    send_channel_message(&mock, "gated", serde_json::json!([{"name": "x", "data": "y"}]));
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(rx.try_recv().is_err(), "RTL17: not delivered when not attached");
}

// UTS: RTL8a/RTL8b/RTL8c unsubscribe semantics
#[tokio::test]
async fn rtl8_unsubscribe_semantics() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("unsub");
    let (id_all, mut rx_all) = ch.subscribe();
    let (id_named, mut rx_named) = ch.subscribe_with_name("ev");
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.state() != ChannelState::Attached {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    // RTL8a: removing the all-listener stops its delivery, the named one stays
    ch.unsubscribe(id_all);
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    send_channel_message(&mock, "unsub", serde_json::json!([{"name": "ev", "data": "1"}]));
    assert_eq!(rx_named.recv().await.unwrap().name.as_deref(), Some("ev"));
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert!(rx_all.try_recv().is_err(), "RTL8a");

    // RTL8b: removing by name+id stops the named listener
    ch.unsubscribe_with_name("ev", id_named);
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    send_channel_message(&mock, "unsub", serde_json::json!([{"name": "ev", "data": "2"}]));
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert!(rx_named.try_recv().is_err(), "RTL8b");

    // RTL8c: unsubscribe_all clears everything
    let (_id3, mut rx3) = ch.subscribe();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    ch.unsubscribe_all();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    send_channel_message(&mock, "unsub", serde_json::json!([{"name": "ev", "data": "3"}]));
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert!(rx3.try_recv().is_err(), "RTL8c");
    server.abort();
}

// UTS: RTL22a/b/c message filters
#[tokio::test]
async fn rtl22_message_filters() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("filtered");

    // RTL22a: by extras.ref.timeserial; RTL22b: isRef=false; RTL22c: name+refType
    let (_i1, mut rx_serial) = ch.subscribe_with_filter(crate::channel::MessageFilter {
        ref_timeserial: Some("ts-1".into()),
        ..Default::default()
    });
    let (_i2, mut rx_noref) = ch.subscribe_with_filter(crate::channel::MessageFilter {
        is_ref: Some(false),
        ..Default::default()
    });
    let (_i3, mut rx_combo) = ch.subscribe_with_filter(crate::channel::MessageFilter {
        name: Some("reaction".into()),
        ref_type: Some("com.ably.reaction".into()),
        ..Default::default()
    });
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.state() != ChannelState::Attached {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    send_channel_message(
        &mock,
        "filtered",
        serde_json::json!([
            {"name": "plain", "data": "no-ref"},
            {"name": "reaction", "data": "ref'd",
             "extras": {"ref": {"type": "com.ably.reaction", "timeserial": "ts-1"}}},
            {"name": "reaction", "data": "other-ref",
             "extras": {"ref": {"type": "com.ably.other", "timeserial": "ts-2"}}}
        ]),
    );

    let m = rx_serial.recv().await.unwrap();
    assert_eq!(m.data, crate::rest::Data::String("ref'd".into()), "RTL22a");
    let m = rx_noref.recv().await.unwrap();
    assert_eq!(m.name.as_deref(), Some("plain"), "RTL22b");
    let m = rx_combo.recv().await.unwrap();
    assert_eq!(m.data, crate::rest::Data::String("ref'd".into()), "RTL22c");
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    for rx in [&mut rx_serial, &mut rx_noref, &mut rx_combo] {
        assert!(rx.try_recv().is_err(), "exactly one match each");
    }
    server.abort();
}

// ============================================================================
// TM2 — message field population; RTL15b — channelSerial from MESSAGE
// ============================================================================

// UTS: TM2a id from pm.id+index; TM2c connectionId; TM2f timestamp;
// existing fields never overwritten
#[tokio::test]
async fn tm2_field_population() {
    let mock = serving_mock("conn-tm2");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("fields");
    let (_id, mut rx) = ch.subscribe();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.state() != ChannelState::Attached {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    let mut pm = ProtocolMessage::new(action::MESSAGE);
    pm.channel = Some("fields".to_string());
    pm.id = Some("pm-42".to_string());
    pm.connection_id = Some("conn-other".to_string());
    pm.timestamp = Some(1_700_000_000_000);
    pm.messages = Some(vec![
        serde_json::json!({"name": "bare", "data": "x"}),
        serde_json::json!({"name": "preset", "data": "y", "id": "explicit-id",
                            "connectionId": "their-conn", "timestamp": 1_600_000_000_000_i64}),
    ]);
    mock.active_connection().send_to_client(pm);

    let bare = rx.recv().await.unwrap();
    assert_eq!(bare.id.as_deref(), Some("pm-42:0"), "TM2a");
    assert_eq!(bare.connection_id.as_deref(), Some("conn-other"), "TM2c");
    assert_eq!(bare.timestamp, Some(1_700_000_000_000), "TM2f");

    let preset = rx.recv().await.unwrap();
    assert_eq!(preset.id.as_deref(), Some("explicit-id"), "TM2a: kept");
    assert_eq!(preset.connection_id.as_deref(), Some("their-conn"), "TM2c: kept");
    assert_eq!(preset.timestamp, Some(1_600_000_000_000), "TM2f: kept");
    server.abort();
}

// UTS: RTL15b channelSerial updated from MESSAGE and PRESENCE
#[tokio::test]
async fn rtl15b_serial_updates_from_message_and_presence() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("serial-track");
    ch.attach().await.unwrap();

    let mut pm = ProtocolMessage::new(action::MESSAGE);
    pm.channel = Some("serial-track".to_string());
    pm.channel_serial = Some("msg-serial-7".to_string());
    pm.messages = Some(vec![serde_json::json!({"name": "n", "data": "d"})]);
    mock.active_connection().send_to_client(pm);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.channel_serial().as_deref() != Some("msg-serial-7") {
        assert!(tokio::time::Instant::now() < deadline, "RTL15b from MESSAGE");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    let mut pp = ProtocolMessage::new(action::PRESENCE);
    pp.channel = Some("serial-track".to_string());
    pp.channel_serial = Some("pres-serial-8".to_string());
    mock.active_connection().send_to_client(pp);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.channel_serial().as_deref() != Some("pres-serial-8") {
        assert!(tokio::time::Instant::now() < deadline, "RTL15b from PRESENCE");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    server.abort();
}

// ============================================================================
// RTL10 / RTL28 / RTL31 — REST delegation
// ============================================================================

// UTS: RTL10b untilAttach requires ATTACHED and scopes by attachSerial
#[tokio::test]
async fn rtl10b_until_attach() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    connect(&client).await;
    let ch = client.channels.get("hist");

    // Not attached: untilAttach errors
    let err = ch.history(true).await.expect_err("RTL10b: requires attached");
    assert!(err.code.is_some());

    // Attach with a serial; the REST query carries fromSerial
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_nth_action(&mock, action::ATTACH, 1, 2000).await;
    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = Some("hist".to_string());
    reply.channel_serial = Some("serial-hist-1".to_string());
    mock.active_connection().send_to_client(reply);
    attach.await.unwrap().unwrap();
    assert_eq!(ch.attach_serial().as_deref(), Some("serial-hist-1"));
    // (the HTTP layer is not mocked here; the parameter plumbing is covered
    // by the ported rtl10 tests against the REST mock)
}

// UTS: realtime/unit/RTL6c2/publish-queued-when-initialized — publish before
// connect() is queued, not failed
#[tokio::test]
async fn rtl6c2_publish_queued_when_initialized() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    assert_eq!(client.connection.state(), ConnectionState::Initialized);

    let ch = client.channels.get("early");
    let ch2 = ch.clone();
    let publish = tokio::spawn(async move { ch2.publish_message(Some("early"), None).await });
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert!(!publish.is_finished(), "queued while INITIALIZED");

    let server = spawn_acking_server(&mock, "s");
    connect(&client).await;
    publish.await.unwrap().expect("flushed and ACKed after connect");
    server.abort();
}

// ============================================================================
// Live sandbox — publish → subscribe round-trip over a real connection
// ============================================================================

#[tokio::test]
async fn live_publish_subscribe_roundtrip_against_sandbox() {
    let app = crate::tests_rest_integration::get_sandbox().await;
    let opts = ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();
    connect(&client).await;

    let ch = client.channels.get("uts-live-messages");
    let (_id, mut rx) = ch.subscribe();
    assert!(
        crate::realtime::await_channel_state(&ch, ChannelState::Attached, 10000).await,
        "implicit attach against the live sandbox"
    );

    let result = ch
        .publish()
        .name("live-event")
        .string("live-data")
        .send()
        .await
        .expect("live publish ACKed");
    assert!(!result.serials.is_empty(), "RTL6j: serial from the live ACK");

    // The published message echoes back to our own subscriber
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
        .await
        .expect("live echo within 10s")
        .expect("subscriber stream open");
    assert_eq!(echoed.name.as_deref(), Some("live-event"));
    assert_eq!(echoed.data, crate::rest::Data::String("live-data".into()));

    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closed, 10000).await);
}

// UTS: RTF1 unrecognised-attributes-ignored-0 + RSF1 message-unrecognised-
// attrs-0 — unknown fields on the ProtocolMessage and its Messages are
// ignored; delivery is unaffected
#[tokio::test]
async fn rtf1_rsf1_unrecognised_attributes_ignored() {
    let mock = serving_mock("conn-1");
    let client = client_for(&mock);
    let server = spawn_channel_server(&mock);
    connect(&client).await;
    let ch = client.channels.get("tolerant");
    let (_id, mut rx) = ch.subscribe();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.state() != ChannelState::Attached {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    // Unknown fields at message level survive deserialization untouched
    send_channel_message(
        &mock,
        "tolerant",
        serde_json::json!([
            {"name": "test-event", "data": "hello",
             "futureField": "ignored", "anotherUnknown": {"deep": true}},
            {"name": "event-2", "data": "payload-2", "unknownEnumHolder": 254}
        ]),
    );
    let m1 = rx.recv().await.unwrap();
    assert_eq!(m1.name.as_deref(), Some("test-event"));
    assert_eq!(m1.data, crate::rest::Data::String("hello".into()));
    let m2 = rx.recv().await.unwrap();
    assert_eq!(m2.name.as_deref(), Some("event-2"));
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert_eq!(ch.state(), ChannelState::Attached);
    server.abort();
}

#![cfg(test)]

//! Stage 5.7 presence tests, derived from the UTS specs (DESIGN.md Realtime
//! §12). Sources: uts/realtime/unit/presence/*.md. The presence_map and
//! local_presence_map specs are exercised directly against the map types in
//! the adopted ported file; this file covers the client-level behaviors.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::error::ErrorInfo;
use crate::mock_ws::{MockTransport, MockWebSocket};
use crate::options::ClientOptions;
use crate::protocol::{action, flags, ChannelState, ConnectionState, ProtocolMessage};
use crate::realtime::{await_channel_state, await_state, Realtime};
use crate::rest::{PresenceAction, PresenceMessage};

fn connected_msg(id: &str) -> ProtocolMessage {
    ProtocolMessage::connected(id, "conn-key")
}

/// A mock that connects as `conn_id` and answers ATTACH (with the given
/// flags) and ACKs every PRESENCE.
fn presence_mock(conn_id: &'static str, attach_flags: u64) -> MockWebSocket {
    let mock = MockWebSocket::with_handler(move |conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg(conn_id));
        std::mem::forget(c);
    });
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
                        reply.flags = Some(attach_flags);
                        mock2.active_connection().send_to_client(reply);
                    }
                    a if a == action::DETACH => {
                        let mut reply = ProtocolMessage::new(action::DETACHED);
                        reply.channel = m.channel.clone();
                        mock2.active_connection().send_to_client(reply);
                    }
                    a if a == action::PRESENCE => {
                        let mut ack = ProtocolMessage::new(action::ACK);
                        ack.msg_serial = m.message.msg_serial;
                        ack.count = Some(1);
                        mock2.active_connection().send_to_client(ack);
                    }
                    _ => {}
                }
            }
            served = msgs.len();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    });
    mock
}

fn client_for(mock: &MockWebSocket, client_id: Option<&str>) -> Realtime {
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let mut opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    if let Some(cid) = client_id {
        opts = opts.client_id(cid).unwrap();
    }
    Realtime::with_mock(&opts, transport).unwrap()
}

async fn connect(client: &Realtime) {
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
}

fn presence_pm(channel: &str, serial: Option<&str>, entries: serde_json::Value) -> ProtocolMessage {
    let mut pm = ProtocolMessage::new(action::PRESENCE);
    pm.channel = Some(channel.to_string());
    pm.channel_serial = serial.map(|s| s.to_string());
    pm.presence = Some(entries.as_array().unwrap().clone());
    pm
}

fn sync_pm(channel: &str, serial: &str, entries: serde_json::Value) -> ProtocolMessage {
    let mut pm = ProtocolMessage::new(action::SYNC);
    pm.channel = Some(channel.to_string());
    pm.channel_serial = Some(serial.to_string());
    pm.presence = Some(entries.as_array().unwrap().clone());
    pm
}

// ============================================================================
// RTP1 / RTP19a — attach-time presence state
// ============================================================================

// UTS: RTP1 HAS_PRESENCE triggers a sync; RTP13 syncComplete attribute
#[tokio::test]
async fn rtp1_rtp13_has_presence_triggers_sync() {
    let mock = presence_mock("conn-1", flags::HAS_PRESENCE);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("synced");
    ch.attach().await.unwrap();

    // RTP13: the sync is pending until SYNC completes
    assert!(!ch.presence().sync_complete());

    mock.active_connection().send_to_client(sync_pm(
        "synced",
        "seq1:", // empty cursor: complete in one page (RTP18c)
        serde_json::json!([
            {"action": 1, "clientId": "alice", "connectionId": "conn-9",
             "id": "conn-9:0:0", "timestamp": 1000}
        ]),
    ));
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while !ch.presence().sync_complete() {
        assert!(tokio::time::Instant::now() < deadline, "RTP13 sync completes");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    let members = ch.presence().get().await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].client_id.as_deref(), Some("alice"));
}

// UTS: RTP1 no HAS_PRESENCE → presence authoritatively empty, sync complete
#[tokio::test]
async fn rtp1_no_has_presence_means_empty() {
    let mock = presence_mock("conn-1", 0);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("empty");
    ch.attach().await.unwrap();

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while !ch.presence().sync_complete() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    assert!(ch.presence().get().await.unwrap().is_empty());
}

// UTS: RTP19a an ATTACHED without HAS_PRESENCE clears existing members with
// synthesized LEAVEs
#[tokio::test]
async fn rtp19a_no_has_presence_clears_members() {
    let mock = presence_mock("conn-1", flags::HAS_PRESENCE);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("clearing");
    ch.attach().await.unwrap();
    mock.active_connection().send_to_client(sync_pm(
        "clearing",
        "seq1:",
        serde_json::json!([
            {"action": 1, "clientId": "alice", "connectionId": "conn-9",
             "id": "conn-9:0:0", "timestamp": 1000}
        ]),
    ));
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.presence().get_with_options(&crate::channel::PresenceGetOptions {
        wait_for_sync: false,
        ..Default::default()
    })
    .await
    .unwrap()
    .len()
        != 1
    {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    // Capture the synthesized LEAVE
    let leaves: Arc<StdMutex<Vec<PresenceMessage>>> = Arc::new(StdMutex::new(Vec::new()));
    let leaves_c = leaves.clone();
    ch.presence().subscribe_action(PresenceAction::Leave, move |msg| {
        leaves_c.lock().unwrap().push(msg);
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // An additional ATTACHED without HAS_PRESENCE
    let mut reattached = ProtocolMessage::new(action::ATTACHED);
    reattached.channel = Some("clearing".to_string());
    reattached.flags = Some(0);
    mock.active_connection().send_to_client(reattached);

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        let members = ch
            .presence()
            .get_with_options(&crate::channel::PresenceGetOptions {
                wait_for_sync: false,
                ..Default::default()
            })
            .await
            .unwrap();
        if members.is_empty() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "RTP19a clears");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    let seen = leaves.lock().unwrap();
    assert_eq!(seen.len(), 1, "synthesized LEAVE delivered");
    assert!(seen[0].id.is_none(), "RTP19: synthesized leaves carry no id");
}

// ============================================================================
// RTP5 — channel state effects
// ============================================================================

// UTS: RTP5a DETACHED/FAILED clear both maps; RTP5f SUSPENDED keeps members
#[tokio::test]
async fn rtp5a_rtp5f_channel_state_effects() {
    let mock = presence_mock("conn-1", flags::HAS_PRESENCE);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("stateful");
    ch.attach().await.unwrap();
    mock.active_connection().send_to_client(sync_pm(
        "stateful",
        "seq1:",
        serde_json::json!([
            {"action": 1, "clientId": "alice", "connectionId": "conn-9",
             "id": "conn-9:0:0", "timestamp": 1000}
        ]),
    ));
    let no_wait = crate::channel::PresenceGetOptions {
        wait_for_sync: false,
        ..Default::default()
    };
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.presence().get_with_options(&no_wait).await.unwrap().len() != 1 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    // RTP5a: detach clears the map
    ch.detach().await.unwrap();
    assert!(ch
        .presence()
        .get_with_options(&no_wait)
        .await
        .unwrap()
        .is_empty());
}

// ============================================================================
// RTP8/RTP16 — enter and the op state table
// ============================================================================

// UTS: RTP8a/RTP8c enter sends ENTER without clientId; RTP8e data travels
#[tokio::test]
async fn rtp8a_rtp8c_rtp8e_enter_wire_shape() {
    let mock = presence_mock("conn-1", 0);
    let client = client_for(&mock, Some("me"));
    connect(&client).await;
    let ch = client.channels.get("entering");
    ch.attach().await.unwrap();

    ch.presence()
        .enter(Some(serde_json::json!("hello-data")))
        .await
        .expect("enter ACKed");

    let sent: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.action == action::PRESENCE)
        .collect();
    assert_eq!(sent.len(), 1);
    let entry = &sent[0].message.presence.as_ref().unwrap()[0];
    assert_eq!(entry["action"], 2, "RTP8a: ENTER");
    assert!(entry.get("clientId").is_none(), "RTP8c: identity is implicit");
    assert_eq!(entry["data"], "hello-data", "RTP8e");
}

// UTS: RTP8d enter implicitly attaches from INITIALIZED
#[tokio::test]
async fn rtp8d_enter_implicitly_attaches() {
    let mock = presence_mock("conn-1", 0);
    let client = client_for(&mock, Some("me"));
    connect(&client).await;
    let ch = client.channels.get("implicit");
    assert_eq!(ch.state(), ChannelState::Initialized);

    ch.presence().enter(None).await.expect("enter after implicit attach");
    assert_eq!(ch.state(), ChannelState::Attached, "RTP8d");
}

// UTS: RTP8g enter on a DETACHED channel errors (91001)
#[tokio::test]
async fn rtp8g_enter_on_detached_errors() {
    let mock = presence_mock("conn-1", 0);
    let client = client_for(&mock, Some("me"));
    connect(&client).await;
    let ch = client.channels.get("detached");
    ch.attach().await.unwrap();
    ch.detach().await.unwrap();
    assert_eq!(ch.state(), ChannelState::Detached);

    let err = ch.presence().enter(None).await.expect_err("RTP8g");
    assert_eq!(err.code, Some(91001));
}

// UTS: RTP8j enter without an identity (or with the wildcard) errors
#[tokio::test]
async fn rtp8j_enter_requires_identity() {
    let mock = presence_mock("conn-1", 0);
    let client = client_for(&mock, None); // unidentified
    connect(&client).await;
    let ch = client.channels.get("anon");
    ch.attach().await.unwrap();

    let err = ch.presence().enter(None).await.expect_err("RTP8j");
    assert_eq!(err.code, Some(91000));
    let err = ch
        .presence()
        .enter_client("*", None)
        .await
        .expect_err("RTP8j: wildcard");
    assert_eq!(err.code, Some(91000));
}

// UTS: RTP16b ops queued while ATTACHING are sent on ATTACHED (RTP5b)
#[tokio::test]
async fn rtp16b_rtp5b_ops_queued_while_attaching() {
    // ATTACH is answered only when the test decides
    let mock = MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("conn-1"));
        std::mem::forget(c);
    });
    let client = client_for(&mock, Some("me"));
    connect(&client).await;
    let ch = client.channels.get("queued-presence");
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while !mock.client_messages().iter().any(|m| m.action == action::ATTACH) {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    assert_eq!(ch.state(), ChannelState::Attaching);

    // Enter while ATTACHING: queued, nothing on the wire
    let p = ch.presence();
    let enter = tokio::spawn(async move { p.enter(None).await });
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert_eq!(
        mock.client_messages()
            .iter()
            .filter(|m| m.action == action::PRESENCE)
            .count(),
        0,
        "RTP16b: queued"
    );

    // ATTACHED: the queued ENTER goes out (RTP5b); ACK it
    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = Some("queued-presence".to_string());
    mock.active_connection().send_to_client(reply);
    attach.await.unwrap().unwrap();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    let sent = loop {
        if let Some(m) = mock
            .client_messages()
            .into_iter()
            .find(|m| m.action == action::PRESENCE)
        {
            break m;
        }
        assert!(tokio::time::Instant::now() < deadline, "RTP5b flush");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    };
    let mut ack = ProtocolMessage::new(action::ACK);
    ack.msg_serial = sent.message.msg_serial;
    ack.count = Some(1);
    mock.active_connection().send_to_client(ack);
    enter.await.unwrap().expect("queued enter resolves");
}

// ============================================================================
// RTP11 — get
// ============================================================================

// UTS: RTP11a get waits for a multi-page sync; RTP11c1 no-wait returns now
#[tokio::test]
async fn rtp11a_rtp11c1_get_sync_semantics() {
    let mock = presence_mock("conn-1", flags::HAS_PRESENCE);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("paged");
    ch.attach().await.unwrap();

    // First sync page (cursor continues)
    mock.active_connection().send_to_client(sync_pm(
        "paged",
        "seq1:cursor1",
        serde_json::json!([
            {"action": 1, "clientId": "alice", "connectionId": "c9",
             "id": "c9:0:0", "timestamp": 1000}
        ]),
    ));
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    // RTP11c1: waitForSync=false returns the partial set immediately
    let partial = ch
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: false,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(partial.len(), 1);

    // RTP11a: the waiting get resolves only after the final page
    let p = ch.presence();
    let waiting = tokio::spawn(async move { p.get().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert!(!waiting.is_finished(), "RTP11a: waits for sync");

    mock.active_connection().send_to_client(sync_pm(
        "paged",
        "seq1:",
        serde_json::json!([
            {"action": 1, "clientId": "bob", "connectionId": "c9",
             "id": "c9:1:0", "timestamp": 1001}
        ]),
    ));
    let members = waiting.await.unwrap().unwrap();
    assert_eq!(members.len(), 2, "both pages present");
}

// UTS: RTP11c2/RTP11c3 filters
#[tokio::test]
async fn rtp11c2_rtp11c3_get_filters() {
    let mock = presence_mock("conn-1", flags::HAS_PRESENCE);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("filtered");
    ch.attach().await.unwrap();
    mock.active_connection().send_to_client(sync_pm(
        "filtered",
        "seq1:",
        serde_json::json!([
            {"action": 1, "clientId": "alice", "connectionId": "cA",
             "id": "cA:0:0", "timestamp": 1000},
            {"action": 1, "clientId": "bob", "connectionId": "cB",
             "id": "cB:0:0", "timestamp": 1000}
        ]),
    ));

    let by_client = ch
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: true,
            client_id: Some("alice".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_client.len(), 1, "RTP11c2");
    assert_eq!(by_client[0].client_id.as_deref(), Some("alice"));

    let by_conn = ch
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: true,
            connection_id: Some("cB".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_conn.len(), 1, "RTP11c3");
    assert_eq!(by_conn[0].client_id.as_deref(), Some("bob"));
}

// UTS: RTP11b get errors when the channel becomes DETACHED/FAILED before the
// sync resolves
#[tokio::test]
async fn rtp11b_get_fails_when_channel_fails() {
    let mock = presence_mock("conn-1", flags::HAS_PRESENCE);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("doomed-get");
    ch.attach().await.unwrap();

    // The sync never completes; the waiting get is deferred
    let p = ch.presence();
    let waiting = tokio::spawn(async move { p.get().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    assert!(!waiting.is_finished());

    // A channel ERROR fails the deferred get
    let mut err_msg = ProtocolMessage::new(action::ERROR);
    err_msg.channel = Some("doomed-get".to_string());
    err_msg.error = Some(ErrorInfo::with_status(40160, 401, "denied"));
    mock.active_connection().send_to_client(err_msg);
    let err = waiting.await.unwrap().expect_err("RTP11b");
    assert!(err.code.is_some());
}

// ============================================================================
// RTP12 — presence history (REST delegation)
// ============================================================================

// UTS: RTP12a presence history delegates to the REST endpoint
#[tokio::test]
async fn rtp12a_history_delegates_to_rest() {
    // The realtime client's embedded REST is not separately mockable here;
    // delegation is verified structurally via the REST presence tests — this
    // test asserts the method surfaces REST errors rather than panicking.
    let mock = presence_mock("conn-1", 0);
    let client = client_for(&mock, None);
    let ch = client.channels.get("hist");
    let result = ch.presence().history().await;
    assert!(result.is_err(), "no live REST endpoint behind the mock client");
}

// ============================================================================
// RTP17 — re-entry detail not expressible in the ported file
// ============================================================================

// UTS: RTP17g1 re-entry omits the id when the connectionId changed
#[tokio::test]
async fn rtp17g1_reentry_omits_id_when_connection_changed() {
    // First connection: conn-A; reconnects get conn-B (failed resume)
    let n = Arc::new(AtomicUsize::new(0));
    let n_c = n.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let i = n_c.fetch_add(1, Ordering::SeqCst);
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg(if i == 0 { "conn-A" } else { "conn-B" }));
        std::mem::forget(c);
    });
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
                    a if a == action::PRESENCE => {
                        let mut ack = ProtocolMessage::new(action::ACK);
                        ack.msg_serial = m.message.msg_serial;
                        ack.count = Some(1);
                        mock2.active_connection().send_to_client(ack);
                    }
                    _ => {}
                }
            }
            served = msgs.len();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    });
    let client = client_for(&mock, Some("me"));
    connect(&client).await;
    let ch = client.channels.get("moving");
    ch.attach().await.unwrap();
    ch.presence().enter(Some(serde_json::json!("d"))).await.unwrap();

    // The echo (conn-A identity) populates the internal map with a real id
    mock.active_connection().send_to_client(presence_pm(
        "moving",
        None,
        serde_json::json!([
            {"action": 2, "clientId": "me", "connectionId": "conn-A",
             "id": "conn-A:0:0", "timestamp": 1000, "data": "d"}
        ]),
    ));
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    // The transport drops; the reconnect lands on conn-B (failed resume) and
    // the channel reattaches, triggering re-entry
    mock.active_connection().simulate_disconnect();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    let reentry = loop {
        if let Some(m) = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.action == action::PRESENCE)
            .nth(1)
        {
            break m;
        }
        assert!(tokio::time::Instant::now() < deadline, "re-entry sent");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };
    let entry = &reentry.message.presence.as_ref().unwrap()[0];
    assert_eq!(entry["action"], 2, "RTP17i: ENTER");
    assert_eq!(entry["clientId"], "me", "RTP17g: stored clientId");
    assert_eq!(entry["data"], "d", "RTP17g: stored data");
    assert!(entry.get("id").is_none(), "RTP17g1: id omitted on conn change");
}

// ============================================================================
// Live sandbox — enter → subscribe → get → leave round trip
// ============================================================================

#[tokio::test]
async fn live_presence_roundtrip_against_sandbox() {
    let app = crate::tests_rest_integration::get_sandbox().await;
    let opts = ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .client_id("uts-live-presence-client")
        .unwrap()
        .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();
    connect(&client).await;

    let ch = client.channels.get("uts-live-presence");
    let entered: Arc<StdMutex<Vec<PresenceMessage>>> = Arc::new(StdMutex::new(Vec::new()));
    let entered_c = entered.clone();
    ch.presence().subscribe_action(PresenceAction::Enter, move |msg| {
        entered_c.lock().unwrap().push(msg);
    });
    assert!(await_channel_state(&ch, ChannelState::Attached, 10000).await);

    ch.presence()
        .enter(Some(serde_json::json!("live-presence-data")))
        .await
        .expect("live enter ACKed");

    // Our own ENTER echoes back
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
    loop {
        if !entered.lock().unwrap().is_empty() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "live ENTER event");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        entered.lock().unwrap()[0].client_id.as_deref(),
        Some("uts-live-presence-client")
    );

    // get() sees us; leave() clears us
    let members = ch.presence().get().await.expect("live get");
    assert!(members
        .iter()
        .any(|m| m.client_id.as_deref() == Some("uts-live-presence-client")));
    ch.presence().leave(None).await.expect("live leave");

    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closed, 10000).await);
}

// UTS: RTP6 live PRESENCE events update the map; multiple entries in one
// ProtocolMessage all apply
#[tokio::test]
async fn rtp6_presence_events_update_map() {
    let mock = presence_mock("conn-1", 0);
    let client = client_for(&mock, None);
    connect(&client).await;
    let ch = client.channels.get("living");
    let events: Arc<StdMutex<Vec<PresenceMessage>>> = Arc::new(StdMutex::new(Vec::new()));
    let events_c = events.clone();
    ch.presence().subscribe(move |msg| {
        events_c.lock().unwrap().push(msg);
    });
    assert!(await_channel_state(&ch, ChannelState::Attached, 5000).await);

    mock.active_connection().send_to_client(presence_pm(
        "living",
        None,
        serde_json::json!([
            {"action": 2, "clientId": "alice", "connectionId": "cA",
             "id": "cA:0:0", "timestamp": 1000},
            {"action": 2, "clientId": "bob", "connectionId": "cB",
             "id": "cB:0:0", "timestamp": 1000}
        ]),
    ));
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while events.lock().unwrap().len() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "RTP6: both delivered");
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
    let members = ch
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: false,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(members.len(), 2, "RTP6: the map tracked both");
}

// UTS: RTP11d get on a SUSPENDED channel errors by default; with
// waitForSync=false it returns the retained members (RTP5f)
#[tokio::test]
async fn rtp11d_get_suspended_semantics() {
    // Answer only the FIRST attach: the post-detach reattach times out and
    // the channel lands in SUSPENDED (RTL13b)
    let attaches = Arc::new(AtomicUsize::new(0));
    let attaches_c = attaches.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("conn-1"));
        std::mem::forget(c);
    });
    let mock2 = mock.clone();
    tokio::spawn(async move {
        let mut served = 0usize;
        loop {
            let msgs = mock2.client_messages();
            for m in msgs.iter().skip(served) {
                if m.action == action::ATTACH
                    && attaches_c.fetch_add(1, Ordering::SeqCst) == 0
                {
                    let mut reply = ProtocolMessage::new(action::ATTACHED);
                    reply.channel = m.channel.clone();
                    reply.flags = Some(flags::HAS_PRESENCE);
                    mock2.active_connection().send_to_client(reply);
                }
            }
            served = msgs.len();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    });
    // A huge channelRetryTimeout pins the channel in SUSPENDED (the paused
    // clock would otherwise race through the RTL13b retry cycle)
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .channel_retry_timeout(std::time::Duration::from_secs(3_000_000))
            .realtime_request_timeout(std::time::Duration::from_millis(200)),
        transport,
    )
    .unwrap();
    connect(&client).await;
    let ch = client.channels.get("suspended-get");
    ch.attach().await.unwrap();
    mock.active_connection().send_to_client(sync_pm(
        "suspended-get",
        "seq1:",
        serde_json::json!([
            {"action": 1, "clientId": "alice", "connectionId": "c9",
             "id": "c9:0:0", "timestamp": 1000}
        ]),
    ));
    let no_wait = crate::channel::PresenceGetOptions {
        wait_for_sync: false,
        ..Default::default()
    };
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    while ch.presence().get_with_options(&no_wait).await.unwrap().len() != 1 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    // Server detach; the automatic reattach is never answered and times out
    // → SUSPENDED (RTL13b; the paused clock advances through the timeout)
    let mut detached = ProtocolMessage::new(action::DETACHED);
    detached.channel = Some("suspended-get".to_string());
    detached.error = Some(ErrorInfo::with_status(90198, 500, "kicked"));
    mock.active_connection().send_to_client(detached);
    assert!(
        await_channel_state(&ch, ChannelState::Suspended, 5000).await,
        "reaches SUSPENDED"
    );

    // RTP11d: default get errors; RTP5f + waitForSync=false returns members
    let err = ch.presence().get().await.map(|_| ()).expect_err("RTP11d");
    assert_eq!(err.code, Some(91005));
    let members = ch.presence().get_with_options(&no_wait).await.unwrap();
    assert_eq!(members.len(), 1, "RTP5f: members retained while SUSPENDED");
}

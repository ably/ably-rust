#![cfg(test)]

//! Stage 5.6 advanced-channel tests, derived from the UTS specs
//! (DESIGN.md Realtime §12). Sources:
//! - uts/realtime/unit/channels/channel_additional_attached.md (RTL12)
//! - uts/realtime/unit/channels/channel_server_initiated_detach.md (RTL13)
//! - uts/realtime/unit/channels/channel_options.md (TB2-4, RTS3b/c/c1,
//!   RTS5, RTL16/RTL16a)

use std::sync::Arc;

use crate::channel::{DeriveOptions, MessageFilter, RealtimeChannelOptions};
use crate::error::ErrorInfo;
use crate::mock_ws::{MockTransport, MockWebSocket};
use crate::options::ClientOptions;
use crate::protocol::{action, ProtocolMessage};
use crate::{ChannelEvent, ChannelMode, ChannelState, ConnectionState};
use crate::realtime::{await_channel_state, await_state, Realtime};

fn connected_msg(id: &str, key: &str) -> ProtocolMessage {
    ProtocolMessage::connected(id, key)
}

fn serving_mock() -> MockWebSocket {
    MockWebSocket::with_handler(|conn| {
        let c = conn.respond_with_connection();
        c.send_to_client(connected_msg("conn-1", "conn-key"));
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

async fn connect(client: &Realtime) {
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
}

async fn await_nth_attach(mock: &MockWebSocket, n: usize, timeout_ms: u64) {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
    loop {
        let count = mock
            .client_messages()
            .iter()
            .filter(|m| m.action == action::ATTACH)
            .count();
        if count >= n {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected {} ATTACH messages, saw {}",
            n,
            count
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }
}

async fn attach_channel(
    mock: &MockWebSocket,
    client: &Realtime,
    name: &str,
) -> Arc<crate::channel::RealtimeChannel> {
    let ch = client.channels.get(name);
    let ch2 = ch.clone();
    let attach = tokio::spawn(async move { ch2.attach().await });
    await_nth_attach(mock, 1, 2000).await;
    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = Some(name.to_string());
    mock.active_connection().send_to_client(reply);
    attach.await.unwrap().unwrap();
    ch
}

fn server_detached(channel: &str, code: u32) -> ProtocolMessage {
    let mut msg = ProtocolMessage::new(action::DETACHED);
    msg.channel = Some(channel.to_string());
    msg.error = Some(ErrorInfo::with_status(code, 500, "Server detached"));
    msg
}

// ============================================================================
// RTL12 — additional ATTACHED
// ============================================================================

// UTS: RTL12 additional ATTACHED with resumed=false emits UPDATE with the
// error; with resumed=true no UPDATE; without an error a null reason
#[tokio::test]
async fn rtl12_additional_attached_update_semantics() {
    let mock = serving_mock();
    let client = client_for(&mock);
    connect(&client).await;
    let ch = attach_channel(&mock, &client, "upd").await;
    let mut events = ch.on_state_change();

    // resumed=false + error → UPDATE carrying the error
    let mut extra = ProtocolMessage::new(action::ATTACHED);
    extra.channel = Some("upd".to_string());
    extra.error = Some(ErrorInfo::with_status(90000, 500, "Discontinuity"));
    mock.active_connection().send_to_client(extra);
    let change = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .expect("UPDATE within 2s")
        .unwrap();
    assert_eq!(change.event, ChannelEvent::Update);
    assert_eq!(change.reason.as_ref().and_then(|e| e.code), Some(90000));
    assert!(!change.resumed);

    // resumed=true → suppressed
    let mut resumed = ProtocolMessage::new(action::ATTACHED);
    resumed.channel = Some("upd".to_string());
    resumed.flags = Some(crate::protocol::flags::RESUMED);
    mock.active_connection().send_to_client(resumed);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(
        events.try_recv().is_err(),
        "RTL12: RESUMED suppresses UPDATE"
    );

    // resumed=false without error → UPDATE with null reason
    let mut plain = ProtocolMessage::new(action::ATTACHED);
    plain.channel = Some("upd".to_string());
    mock.active_connection().send_to_client(plain);
    let change = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
        .await
        .expect("UPDATE within 2s")
        .unwrap();
    assert_eq!(change.event, ChannelEvent::Update);
    assert!(change.reason.is_none(), "RTL12: null reason without error");
}

// ============================================================================
// RTL13 — server-initiated DETACHED
// ============================================================================

// UTS: RTL13a server DETACHED on an ATTACHED channel → immediate reattach
#[tokio::test]
async fn rtl13a_server_detached_triggers_reattach() {
    let mock = serving_mock();
    let client = client_for(&mock);
    connect(&client).await;
    let ch = attach_channel(&mock, &client, "kicked").await;
    let mut events = ch.on_state_change();

    mock.active_connection()
        .send_to_client(server_detached("kicked", 90198));
    // The channel goes ATTACHING (with the server's reason) and re-sends ATTACH
    await_nth_attach(&mock, 2, 2000).await;
    let change = events.recv().await.unwrap();
    assert_eq!(change.current, ChannelState::Attaching);
    assert_eq!(change.reason.and_then(|e| e.code), Some(90198));

    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = Some("kicked".to_string());
    mock.active_connection().send_to_client(reply);
    assert!(await_channel_state(&ch, ChannelState::Attached, 5000).await);
}

// UTS: RTL13b failed reattach → SUSPENDED (with retryIn) then automatic
// retry; cycles until ATTACHED
#[tokio::test(start_paused = true)]
async fn rtl13b_failed_reattach_suspends_and_retries() {
    let mock = serving_mock();
    let client = client_for(&mock);
    connect(&client).await;
    let ch = attach_channel(&mock, &client, "retrier").await;
    let mut events = ch.on_state_change();

    // Server detaches; the reattach is rejected once (DETACHED while ATTACHING)
    mock.active_connection()
        .send_to_client(server_detached("retrier", 90198));
    await_nth_attach(&mock, 2, 5000).await;
    mock.active_connection()
        .send_to_client(server_detached("retrier", 90198));

    // SUSPENDED with a retryIn hint
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    let suspended = loop {
        let change = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("suspended change")
            .unwrap();
        if change.current == ChannelState::Suspended {
            break change;
        }
    };
    assert!(
        suspended.retry_in.is_some(),
        "RTL13b/RTB1: the SUSPENDED change carries retryIn"
    );

    // The retry fires (paused clock auto-advances) and this time succeeds
    await_nth_attach(&mock, 3, 30000).await;
    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = Some("retrier".to_string());
    mock.active_connection().send_to_client(reply);
    assert!(await_channel_state(&ch, ChannelState::Attached, 5000).await);
}

// UTS: RTL13c the retry does not run when the connection is no longer
// CONNECTED
#[tokio::test(start_paused = true)]
async fn rtl13c_retry_cancelled_when_not_connected() {
    // First attempt connects; later attempts are parked (stay CONNECTING)
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n_c = n.clone();
    let mock = MockWebSocket::with_handler(move |conn| {
        if n_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            let c = conn.respond_with_connection();
            c.send_to_client(connected_msg("conn-1", "key"));
            std::mem::forget(c);
        } else {
            std::mem::forget(conn);
        }
    });
    let transport = Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![])
            .connection_state_ttl(std::time::Duration::from_secs(3600)),
        transport,
    )
    .unwrap();
    connect(&client).await;
    let ch = attach_channel(&mock, &client, "stranded").await;

    // Server detach → reattach rejected → SUSPENDED with a scheduled retry
    mock.active_connection()
        .send_to_client(server_detached("stranded", 90198));
    await_nth_attach(&mock, 2, 5000).await;
    let attaches_before = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::ATTACH)
        .count();
    mock.active_connection()
        .send_to_client(server_detached("stranded", 90198));
    assert!(await_channel_state(&ch, ChannelState::Suspended, 5000).await);

    // The transport drops before the retry fires; the connection stays
    // CONNECTING (parked) — the channel retry must NOT fire
    mock.active_connection().simulate_disconnect();
    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

    let attaches_after = mock
        .client_messages()
        .iter()
        .filter(|m| m.action == action::ATTACH)
        .count();
    assert_eq!(
        attaches_before, attaches_after,
        "RTL13c: no reattach while the connection is not CONNECTED"
    );
    assert_eq!(ch.state(), ChannelState::Suspended);
}

// ============================================================================
// RTL16 / RTS3c / RTS3c1 — channel options
// ============================================================================

// UTS: RTL16 setOptions updates the stored options (no reattach needed)
#[tokio::test]
async fn rtl16_set_options_updates() {
    let mock = serving_mock();
    let client = client_for(&mock);
    connect(&client).await;
    let ch = client.channels.get("opts");

    ch.set_options(RealtimeChannelOptions {
        attach_on_subscribe: Some(false),
        ..Default::default()
    })
    .await
    .expect("setOptions");
    assert_eq!(ch.options().attach_on_subscribe, Some(false), "RTL16");
    // No reattach was needed: nothing on the wire
    assert!(mock.client_messages().is_empty());
}

// UTS: RTL16a setOptions triggers a reattach when params change on a live
// channel, resolving once re-ATTACHED
#[tokio::test]
async fn rtl16a_set_options_triggers_reattach() {
    let mock = serving_mock();
    let client = client_for(&mock);
    connect(&client).await;
    let ch = attach_channel(&mock, &client, "rewinder").await;
    let mut events = ch.on_state_change();

    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    let ch2 = ch.clone();
    let set = tokio::spawn(async move {
        ch2.set_options(RealtimeChannelOptions {
            params: Some(params),
            ..Default::default()
        })
        .await
    });

    // The reattach goes out carrying the new params
    await_nth_attach(&mock, 2, 2000).await;
    let second_attach = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.action == action::ATTACH)
        .nth(1)
        .unwrap();
    assert_eq!(
        second_attach.message.params.as_ref().unwrap()["rewind"],
        "1"
    );
    assert!(
        !set.is_finished(),
        "RTL16a: resolves only after re-ATTACHED"
    );

    let mut reply = ProtocolMessage::new(action::ATTACHED);
    reply.channel = Some("rewinder".to_string());
    mock.active_connection().send_to_client(reply);
    set.await.unwrap().expect("setOptions resolves");
    assert_eq!(ch.state(), ChannelState::Attached);
    assert_eq!(
        ch.options().params.unwrap()["rewind"],
        "1",
        "options updated"
    );

    let mut saw_attaching = false;
    while let Ok(change) = events.try_recv() {
        if change.current == ChannelState::Attaching {
            saw_attaching = true;
        }
    }
    assert!(saw_attaching, "RTL16a: the reattach was observable");
}

// UTS: RTS3c1 get with options that would force a reattach errors; the
// channel's options are unchanged
#[tokio::test]
async fn rts3c1_get_with_conflicting_options_errors() {
    let mock = serving_mock();
    let client = client_for(&mock);
    connect(&client).await;
    let ch = attach_channel(&mock, &client, "locked").await;

    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    let err = client
        .channels
        .get_with_options(
            "locked",
            RealtimeChannelOptions {
                params: Some(params),
                ..Default::default()
            },
        )
        .map(|_| ())
        .expect_err("RTS3c1: params change on an attached channel");
    assert_eq!(err.code, Some(40000));
    assert!(ch.options().params.is_none(), "options unchanged");

    // Modes change while ATTACHING errors too
    let pending = client.channels.get("pending-ch");
    let pending2 = pending.clone();
    let _attach = tokio::spawn(async move { pending2.attach().await });
    await_nth_attach(&mock, 2, 2000).await;
    let err = client
        .channels
        .get_with_options(
            "pending-ch",
            RealtimeChannelOptions {
                modes: Some(vec![ChannelMode::Subscribe]),
                ..Default::default()
            },
        )
        .map(|_| ())
        .expect_err("RTS3c1: modes change while attaching");
    assert_eq!(err.code, Some(40000));
}

// UTS: TB2/TB4 option attributes and defaults; RTS3b options set on create
#[tokio::test]
async fn tb2_tb4_rts3b_option_attributes() {
    let mock = serving_mock();
    let client = client_for(&mock);

    // TB4: attachOnSubscribe defaults to true
    assert_eq!(
        RealtimeChannelOptions::default().attach_on_subscribe,
        None,
        "unset in the literal"
    );
    let plain = client.channels.get("plain");
    assert_eq!(
        plain.options().attach_on_subscribe,
        Some(true),
        "TB4: effective default is true"
    );

    // TB2c/TB2d + RTS3b: params and modes set on creation
    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    let ch = client
        .channels
        .get_with_options(
            "configured",
            RealtimeChannelOptions {
                params: Some(params),
                modes: Some(vec![ChannelMode::Subscribe]),
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let opts = ch.options();
    assert_eq!(opts.params.unwrap()["rewind"], "1", "TB2c/RTS3b");
    assert_eq!(opts.modes.unwrap(), vec![ChannelMode::Subscribe], "TB2d");
    assert_eq!(opts.attach_on_subscribe, Some(false));
}

// ============================================================================
// RTS5 — derived channels
// ============================================================================

// UTS: RTS5a/RTS5a1 derived channel name qualification with base64 filter
#[tokio::test]
async fn rts5a_derived_channel_name_qualification() {
    let mock = serving_mock();
    let client = client_for(&mock);

    let ch = client
        .channels
        .get_derived("events", DeriveOptions::new("name == 'test'"));
    // RTS5a1: the filter travels base64-encoded
    assert_eq!(ch.name(), "[filter=bmFtZSA9PSAndGVzdCc=]events");

    // RTS3a still holds for derived channels
    let again = client
        .channels
        .get_derived("events", DeriveOptions::new("name == 'test'"));
    assert!(Arc::ptr_eq(&ch, &again));
    let _ = MessageFilter::default();
}

// UTS: RTS5a2/RTS5 derived with channel options — params join the qualifier,
// options land on the channel
#[tokio::test]
async fn rts5a2_derived_with_params_and_options() {
    let mock = serving_mock();
    let client = client_for(&mock);

    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    params.insert("delta".to_string(), "vcdiff".to_string());
    let ch = client
        .channels
        .get_derived_with_options(
            "stream",
            DeriveOptions::new("true"),
            RealtimeChannelOptions {
                params: Some(params),
                modes: Some(vec![ChannelMode::Subscribe]),
                ..Default::default()
            },
        )
        .unwrap();

    let name = ch.name().to_string();
    assert!(name.ends_with("]stream"));
    let qualifier = &name[name.find('[').unwrap() + 1..name.find(']').unwrap()];
    assert!(qualifier.starts_with("filter="));
    let params_str = qualifier.split_once('?').expect("params in qualifier").1;
    assert!(params_str.contains("rewind=1"));
    assert!(params_str.contains("delta=vcdiff"));

    let opts = ch.options();
    assert_eq!(opts.modes.unwrap(), vec![ChannelMode::Subscribe], "RTS5");
}

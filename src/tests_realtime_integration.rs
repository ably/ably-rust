#![cfg(test)]

//! Realtime integration tests against the LIVE nonprod sandbox, derived from
//! uts/realtime/integration/ (TASK-11). Like the REST integration tests,
//! these share the sandbox app — run with --test-threads=1 when isolating.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::auth::{AuthCallback, AuthToken, TokenParams};
use crate::options::ClientOptions;
use crate::protocol::{ChannelState, ConnectionState};
use crate::realtime::{await_channel_state, await_state, Realtime};
use crate::rest::{Data, PresenceAction};
use crate::tests_rest_integration::{get_sandbox, random_id, SandboxApp};

fn live_opts(key: &str) -> ClientOptions {
    ClientOptions::new(key)
        .endpoint("nonprod:sandbox")
        .unwrap()
        .auto_connect(false)
}

async fn connected_client(app: &SandboxApp) -> Realtime {
    let client = Realtime::new(&live_opts(app.full_access_key())).unwrap();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 10000).await);
    client
}

/// Await a captured-message predicate with a live-network deadline.
async fn await_live<F: FnMut() -> bool>(what: &str, secs: u64, mut f: F) {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(secs);
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out awaiting {} within {}s",
            what,
            secs
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

// ============================================================================
// Connection lifecycle (connection_lifecycle_test.md)
// ============================================================================

// UTS: RTN4b successful-connection, RTN4c graceful-close, RTN11 reconnect
#[tokio::test]
async fn rtn4b_rtn4c_rtn11_connection_lifecycle() {
    let app = get_sandbox().await;
    let client = Realtime::new(&live_opts(app.full_access_key())).unwrap();
    let mut events = client.connection.on_state_change();

    // RTN4b: connecting then connected, with id and key assigned
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 10000).await);
    assert!(client.connection.id().is_some());
    assert!(client.connection.key().is_some());
    let mut seen = Vec::new();
    while let Ok(change) = events.try_recv() {
        seen.push(change.current);
    }
    assert_eq!(
        seen,
        vec![ConnectionState::Connecting, ConnectionState::Connected],
        "RTN4b: ordered lifecycle events"
    );

    // RTN4c: graceful close
    client.close();
    assert!(await_state(&client.connection, ConnectionState::Closed, 10000).await);
    assert!(client.connection.id().is_none(), "RTN8c after close");

    // RTN11: connect again from CLOSED
    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 10000).await,
        "RTN11: reconnect cycle"
    );
    client.close();
}

// UTS: RTN14a invalid key → FAILED with 40005/40101
#[tokio::test]
async fn rtn14a_invalid_key_failed() {
    let _app = get_sandbox().await; // ensure the sandbox exists / warms DNS
    let client = Realtime::new(&live_opts("not-an-app.not-a-key:bogus")).unwrap();
    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Failed, 15000).await,
        "RTN14a: invalid key must FAIL the connection"
    );
    let err = client.connection.error_reason().expect("errorReason set");
    assert!(
        matches!(err.code, Some(40005) | Some(40101) | Some(40400)),
        "auth-shaped failure, got {:?}",
        err.code
    );
}

// ============================================================================
// Channel attach/detach + capability (channels/channel_attach_test.md)
// ============================================================================

// UTS: RTL4c attach-succeeds + RTL5d detach-succeeds are covered live by
// tests_realtime_uts_channels::live_channel_attach_detach_against_sandbox.

// UTS: RTL14 insufficient capability — attach with a subscribe-only key
// succeeds, publish fails with 40160 and the connection survives
#[tokio::test]
async fn rtl14_insufficient_capability_publish_fails() {
    let app = get_sandbox().await;
    let client = Realtime::new(&live_opts(app.subscribe_only_key())).unwrap();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 10000).await);

    let ch = client
        .channels
        .get(format!("test-RTL14-{}", random_id()).as_str());
    ch.attach()
        .await
        .expect("subscribe capability allows attach");

    let err = ch
        .publish_message(Some("ev"), Some(serde_json::json!("nope")))
        .await
        .expect_err("RTL14: publish without capability");
    assert_eq!(err.code, Some(40160));
    assert_eq!(
        client.connection.state(),
        ConnectionState::Connected,
        "the connection survives"
    );
    client.close();
}

// ============================================================================
// Publish round-trips (channels/channel_publish_test.md)
// ============================================================================

// UTS: RTL6 string/json/binary roundtrips, RTL6f connectionId, RSL6a2 extras
#[tokio::test]
async fn rtl6_data_roundtrips_with_metadata() {
    let app = get_sandbox().await;
    let client = connected_client(app).await;
    let name = format!("test-RTL6-{}", random_id());
    let ch = client.channels.get(&name);
    let (_id, mut rx) = ch.subscribe();
    assert!(await_channel_state(&ch, ChannelState::Attached, 10000).await);

    // string
    ch.publish().name("s").string("plain").send().await.unwrap();
    // json object with extras (RSL6a2)
    ch.publish()
        .name("j")
        .json(serde_json::json!({"k": "v", "n": 7}))
        .extras(serde_json::json!({"headers": {"tag": "x"}}))
        .send()
        .await
        .unwrap();
    // binary
    ch.publish()
        .name("b")
        .binary(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .send()
        .await
        .unwrap();

    let own_connection = client.connection.id();
    let mut got = std::collections::HashMap::new();
    for _ in 0..3 {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("echo within 10s")
            .unwrap();
        // RTL6f: the echoed message carries the publisher's connectionId
        assert_eq!(msg.connection_id, own_connection, "RTL6f");
        got.insert(msg.name.clone().unwrap(), msg);
    }
    assert_eq!(got["s"].data, Data::String("plain".into()), "RTL6 string");
    assert!(
        matches!(&got["j"].data, Data::JSON(v) if v["k"] == "v" && v["n"] == 7),
        "RTL6 json, got {:?}",
        got["j"].data
    );
    assert!(
        matches!(&got["b"].data, Data::Binary(b) if b.as_ref() == [0xDE, 0xAD, 0xBE, 0xEF]),
        "RTL6 binary, got {:?}",
        got["b"].data
    );
    // RSL6a2: extras round-trip
    assert_eq!(got["j"].extras.as_ref().unwrap()["headers"]["tag"], "x");
    client.close();
}

// ============================================================================
// Subscribe flows (channels/channel_subscribe_test.md)
// ============================================================================

// UTS: RTL7a all-messages, RTL7b name filter, RTL7 bidirectional flow
#[tokio::test]
async fn rtl7_subscribe_flows_between_clients() {
    let app = get_sandbox().await;
    let a = connected_client(app).await;
    let b = connected_client(app).await;
    let name = format!("test-RTL7-{}", random_id());

    let ch_a = a.channels.get(&name);
    let ch_b = b.channels.get(&name);
    let (_i1, mut rx_all_b) = ch_b.subscribe();
    let (_i2, mut rx_named_b) = ch_b.subscribe_with_name("wanted");
    let (_i3, mut rx_all_a) = ch_a.subscribe();
    assert!(await_channel_state(&ch_a, ChannelState::Attached, 10000).await);
    assert!(await_channel_state(&ch_b, ChannelState::Attached, 10000).await);

    // A -> B (two names; the filter sees only one)
    ch_a.publish()
        .name("wanted")
        .string("w")
        .send()
        .await
        .unwrap();
    ch_a.publish()
        .name("other")
        .string("o")
        .send()
        .await
        .unwrap();
    // B -> A (RTL7: bidirectional)
    ch_b.publish()
        .name("reply")
        .string("r")
        .send()
        .await
        .unwrap();

    let mut all_b = Vec::new();
    for _ in 0..3 {
        // B sees its own echo too
        let m = tokio::time::timeout(std::time::Duration::from_secs(10), rx_all_b.recv())
            .await
            .expect("B delivery")
            .unwrap();
        all_b.push(m.name.unwrap());
    }
    assert!(all_b.contains(&"wanted".to_string()), "RTL7a");
    assert!(all_b.contains(&"other".to_string()), "RTL7a");

    let named = tokio::time::timeout(std::time::Duration::from_secs(10), rx_named_b.recv())
        .await
        .expect("named delivery")
        .unwrap();
    assert_eq!(named.name.as_deref(), Some("wanted"), "RTL7b");
    assert_eq!(named.data, Data::String("w".into()));

    await_live(
        "A receiving B's reply",
        10,
        || matches!(rx_all_a.try_recv(), Ok(m) if m.name.as_deref() == Some("reply")),
    )
    .await;
    a.close();
    b.close();
}

// ============================================================================
// Auth (auth.md, token_request_test.md, token_renewal_test.md)
// ============================================================================

// UTS: RSA8 token-auth-connect, RSA9/RSA9a token request accepted by the
// server, RSA7 matching clientId succeeds
#[tokio::test]
async fn rsa8_rsa9_rsa7_token_auth_connect() {
    let app = get_sandbox().await;
    let rest = live_opts(app.full_access_key()).rest().unwrap();
    let client_id = format!("rt-token-{}", random_id());

    // RSA9: a signed TokenRequest carrying a clientId, accepted by the server
    let tr = rest
        .auth()
        .create_token_request(
            Some(&TokenParams {
                client_id: Some(client_id.clone()),
                ..Default::default()
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(tr.client_id.as_deref(), Some(client_id.as_str()), "RSA9");
    // RSA9a: exchange the signed request for a token at the server
    let td = rest.exchange_token_request(&tr).await.unwrap();
    assert_eq!(td.client_id.as_deref(), Some(client_id.as_str()), "RSA9a");

    // RSA8/RSA7: connect over token auth with the matching clientId
    let opts = ClientOptions::with_token(&td.token)
        .endpoint("nonprod:sandbox")
        .unwrap()
        .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();
    client.connect();
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 10000).await,
        "RSA8: token auth connects"
    );
    client.close();
}

// UTS: RSA4b token renewal on expiry — a short-TTL callback token is renewed
// and the connection stays usable
#[tokio::test]
async fn rsa4b_token_renewal_on_expiry() {
    let app = get_sandbox().await;
    struct ShortTtl {
        rest: crate::rest::Rest,
        count: Arc<AtomicUsize>,
    }
    impl AuthCallback for ShortTtl {
        fn token<'a>(
            &'a self,
            _params: &'a TokenParams,
        ) -> std::pin::Pin<
            Box<dyn Send + futures::Future<Output = crate::error::Result<AuthToken>> + 'a>,
        > {
            Box::pin(async move {
                self.count.fetch_add(1, Ordering::SeqCst);
                let td = self
                    .rest
                    .auth()
                    .request_token(
                        Some(&TokenParams {
                            ttl: Some(5_000), // expires almost immediately
                            ..Default::default()
                        }),
                        None,
                    )
                    .await?;
                Ok(AuthToken::Details(td))
            })
        }
    }
    let rest = live_opts(app.full_access_key()).rest().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let opts = ClientOptions::with_auth_callback(Arc::new(ShortTtl {
        rest,
        count: count.clone(),
    }))
    .endpoint("nonprod:sandbox")
    .unwrap()
    .auto_connect(false);
    let client = Realtime::new(&opts).unwrap();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 10000).await);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // The 5s token expires; the server forces renewal; the callback runs
    // again and the connection returns to CONNECTED
    await_live("token renewal (callback count >= 2)", 30, || {
        count.load(Ordering::SeqCst) >= 2
    })
    .await;
    assert!(
        await_state(&client.connection, ConnectionState::Connected, 15000).await,
        "RSA4b: connected after renewal"
    );
    client.close();
}

// UTS: RTC8a in-band reauth while connected; RTC8c authorize initiates a
// connection
#[tokio::test]
async fn rtc8_authorize_live() {
    let app = get_sandbox().await;

    // RTC8c: authorize() from INITIALIZED brings the connection up
    let client = Realtime::new(&live_opts(app.full_access_key())).unwrap();
    let td1 = client.auth().authorize().await.expect("RTC8c authorize");
    assert!(!td1.token.is_empty());
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    let id_before = client.connection.id();

    // RTC8a: in-band reauth; the connection stays CONNECTED throughout
    let td2 = client.auth().authorize().await.expect("RTC8a reauth");
    assert_ne!(td1.token, td2.token, "a fresh token was issued");
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert_eq!(client.connection.id(), id_before, "no reconnect");
    client.close();
}

// ============================================================================
// History across clients (channel_history_test.md)
// ============================================================================

// UTS: RTL10d history-cross-client
#[tokio::test]
async fn rtl10d_history_cross_client() {
    let app = get_sandbox().await;
    let name = format!("persisted:test-RTL10d-{}", random_id());

    let publisher = connected_client(app).await;
    let ch = publisher.channels.get(&name);
    ch.attach().await.unwrap();
    for i in 0..3 {
        ch.publish()
            .name("ev")
            .string(format!("m{}", i))
            .send()
            .await
            .unwrap();
    }
    publisher.close();

    // A different client reads the same history
    let reader = connected_client(app).await;
    let ch_b = reader.channels.get(&name);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(16);
    loop {
        let page = ch_b.history(false).await.unwrap();
        if page.items().len() >= 3 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "RTL10d: history visible cross-client"
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
    reader.close();
}

// ============================================================================
// Mutable messages + annotations (mutable_messages_test.md)
// ============================================================================

// UTS: RTL32 update/delete/append observed + full lifecycle; RTL28 get
#[tokio::test]
async fn rtl32_rtl28_mutation_lifecycle_observed() {
    let app = get_sandbox().await;
    let client = connected_client(app).await;
    let name = format!("mutable:test-RTL32-{}", random_id());
    let ch = client.channels.get(&name);
    let (_id, mut rx) = ch.subscribe();
    assert!(await_channel_state(&ch, ChannelState::Attached, 10000).await);

    let publish = ch.publish().name("doc").string("v1").send().await.unwrap();
    let serial = publish.serials[0].clone().expect("serial");
    let created = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
        .await
        .expect("create echo")
        .unwrap();
    assert_eq!(created.data, Data::String("v1".into()));

    // RTL32: update observed by the subscriber
    let mut msg = created.clone();
    msg.serial = Some(serial.clone());
    msg.data = Data::String("v2".into());
    let upd = ch
        .update_message(&msg, &crate::rest::MessageOperation::default(), None)
        .await
        .expect("update ACKed");
    assert!(upd.version_serial.is_some(), "RTL32d");
    let updated = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
        .await
        .expect("update observed")
        .unwrap();
    assert_eq!(
        updated.action,
        Some(crate::rest::MessageAction::Update),
        "RTL32: UPDATE observed"
    );
    assert_eq!(updated.data, Data::String("v2".into()));

    // RTL28: get the message via the realtime channel
    let fetched = ch.get_message(&serial).await.expect("RTL28 get_message");
    assert_eq!(fetched.data, Data::String("v2".into()));
    let versions = ch.message_versions(&serial).await.expect("RTL28 versions");
    assert!(versions.items().len() >= 2, "create + update versions");

    // RTL32: delete observed
    ch.delete_message(&msg, &crate::rest::MessageOperation::default(), None)
        .await
        .expect("delete ACKed");
    let deleted = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
        .await
        .expect("delete observed")
        .unwrap();
    assert_eq!(deleted.action, Some(crate::rest::MessageAction::Delete));
    client.close();
}

// UTS: RTAN1 annotation publish+delete observed; RTAN4c type filter;
// RTAN4d implicit attach
#[tokio::test]
async fn rtan_annotations_live() {
    let app = get_sandbox().await;
    let client = connected_client(app).await;
    let name = format!("mutable:test-RTAN-{}", random_id());
    // RTAN4e: annotations are only delivered on a channel attached with the
    // ANNOTATION_SUBSCRIBE mode
    let ch = client
        .channels
        .get_with_options(
            &name,
            crate::channel::RealtimeChannelOptions {
                modes: Some(vec![
                    crate::protocol::ChannelMode::Publish,
                    crate::protocol::ChannelMode::Subscribe,
                    crate::protocol::ChannelMode::AnnotationPublish,
                    crate::protocol::ChannelMode::AnnotationSubscribe,
                ]),
                ..Default::default()
            },
        )
        .unwrap();

    let all: Arc<StdMutex<Vec<crate::rest::Annotation>>> = Arc::new(StdMutex::new(Vec::new()));
    let all_c = all.clone();
    ch.annotations().subscribe(move |a| {
        all_c.lock().unwrap().push(a);
    });
    let filtered: Arc<StdMutex<Vec<crate::rest::Annotation>>> = Arc::new(StdMutex::new(Vec::new()));
    let filtered_c = filtered.clone();
    ch.annotations()
        .subscribe_with_type("reaction:multiple.v1", move |a| {
            filtered_c.lock().unwrap().push(a);
        });
    // RTAN4d: the subscribes implicitly attached
    assert!(
        await_channel_state(&ch, ChannelState::Attached, 10000).await,
        "RTAN4d"
    );

    let publish = ch
        .publish()
        .name("target")
        .string("annotate-me")
        .send()
        .await
        .unwrap();
    let serial = publish.serials[0].clone().expect("serial");

    let ann = crate::rest::Annotation {
        annotation_type: Some("reaction:multiple.v1".into()),
        name: Some("+1".into()),
        ..Default::default()
    };
    ch.annotations()
        .publish(&serial, &ann)
        .await
        .expect("RTAN1 publish ACKed");

    await_live("annotation observed", 10, || {
        !all.lock().unwrap().is_empty()
    })
    .await;
    {
        let seen = all.lock().unwrap();
        assert_eq!(
            seen[0].annotation_type.as_deref(),
            Some("reaction:multiple.v1")
        );
        assert_eq!(seen[0].message_serial.as_deref(), Some(serial.as_str()));
    }
    // RTAN4c: the type filter saw it too
    await_live("filtered annotation", 10, || {
        !filtered.lock().unwrap().is_empty()
    })
    .await;

    ch.annotations()
        .delete(&serial, &ann)
        .await
        .expect("RTAN1 delete ACKed");
    await_live("delete observed", 10, || all.lock().unwrap().len() >= 2).await;
    client.close();
}

// ============================================================================
// Presence (presence_lifecycle_test.md, presence/presence_sync_test.md)
// ============================================================================

// UTS: RTP8 enter/update/leave lifecycle observed by a second client
#[tokio::test]
async fn rtp8_presence_lifecycle_observed() {
    let app = get_sandbox().await;
    let name = format!("test-RTP8-int-{}", random_id());

    let observer = connected_client(app).await;
    let ch_obs = observer.channels.get(&name);
    let events: Arc<StdMutex<Vec<crate::rest::PresenceMessage>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let events_c = events.clone();
    ch_obs.presence().subscribe(move |m| {
        events_c.lock().unwrap().push(m);
    });
    assert!(await_channel_state(&ch_obs, ChannelState::Attached, 10000).await);

    let opts = live_opts(app.full_access_key())
        .client_id("rtp8-member")
        .unwrap();
    let member = Realtime::new(&opts).unwrap();
    member.connect();
    assert!(await_state(&member.connection, ConnectionState::Connected, 10000).await);
    let ch_m = member.channels.get(&name);
    ch_m.attach().await.unwrap();
    ch_m.presence()
        .enter(Some(serde_json::json!("in")))
        .await
        .unwrap();
    ch_m.presence()
        .update(Some(serde_json::json!("changed")))
        .await
        .unwrap();
    ch_m.presence().leave(None).await.unwrap();

    await_live("enter+update+leave observed", 15, || {
        let seen = events.lock().unwrap();
        let actions: Vec<_> = seen.iter().filter_map(|m| m.action).collect();
        actions.contains(&PresenceAction::Enter)
            && actions.contains(&PresenceAction::Update)
            && actions.contains(&PresenceAction::Leave)
    })
    .await;
    member.close();
    observer.close();
}

// UTS: RTP4 bulk enter observed; RTP2 sync delivers members to a late joiner
#[tokio::test]
async fn rtp4_rtp2_bulk_enter_and_sync() {
    let app = get_sandbox().await;
    let name = format!("test-RTP4-int-{}", random_id());
    let member_count = 20usize;

    // Client A enters many members (key auth: enterClient allowed)
    let a = connected_client(app).await;
    let ch_a = a.channels.get(&name);
    ch_a.attach().await.unwrap();
    for i in 0..member_count {
        ch_a.presence()
            .enter_client(
                &format!("user-{}", i),
                Some(serde_json::json!(format!("data-{}", i))),
            )
            .await
            .unwrap();
    }

    // Client B attaches AFTERWARDS: the sync must deliver all members (RTP2)
    let b = connected_client(app).await;
    let ch_b = b.channels.get(&name);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(20);
    loop {
        let members = ch_b.presence().get().await.unwrap();
        if members.len() == member_count {
            // every clientId with its data
            for i in 0..member_count {
                let cid = format!("user-{}", i);
                let m = members
                    .iter()
                    .find(|m| m.client_id.as_deref() == Some(cid.as_str()))
                    .unwrap_or_else(|| panic!("member {} present", cid));
                assert_eq!(m.data, Data::String(format!("data-{}", i)));
            }
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "RTP2/RTP4: sync delivered {}/{} members",
            members.len(),
            member_count
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
    a.close();
    b.close();
}

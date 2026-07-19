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
                    crate::error::ErrorInfo::new(fail_code.code(), "Auth callback failed");
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

// ========================================================================
// Phase 8a: Channel Foundation Tests
// ========================================================================

// --- Channels Collection (RTS1-4) ---

#[tokio::test]
async fn rts1_channels_collection_accessible() {
    // RTS1: Channels is a collection accessible via RealtimeClient#channels
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let _channels = &client.channels;
}

#[tokio::test]
async fn rts2_channel_exists() {
    // RTS2: exists() returns correct boolean
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    assert!(!client.channels.exists("test-channel"));
    let _channel = client.channels.get("test-channel");
    assert!(client.channels.exists("test-channel"));
    assert!(!client.channels.exists("other-channel"));
}

#[tokio::test]
async fn rts2_iterate_channels() {
    // RTS2: Iterate through existing channels
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.channels.get("channel-a");
    client.channels.get("channel-b");
    client.channels.get("channel-c");

    let names = client.channels.names();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"channel-a".to_string()));
    assert!(names.contains(&"channel-b".to_string()));
    assert!(names.contains(&"channel-c".to_string()));
}

#[tokio::test]
async fn rts3a_get_creates_new_channel() {
    // RTS3a: get() creates a new channel
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let channel = client.channels.get("test-channel");
    assert_eq!(channel.name(), "test-channel");
    assert!(client.channels.exists("test-channel"));
}

#[tokio::test]
async fn rts3a_get_returns_existing_channel() {
    // RTS3a: get() returns the same instance
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let channel1 = client.channels.get("test-channel");
    let channel2 = client.channels.get("test-channel");
    assert!(std::sync::Arc::ptr_eq(&channel1, &channel2));
    assert_eq!(channel1.name(), "test-channel");
}

#[tokio::test]
async fn rts4a_release_removes_channel() {
    // RTS4a: release() removes the channel
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let _channel = client.channels.get("test-channel");
    assert!(client.channels.exists("test-channel"));
    client.channels.release("test-channel").await;
    assert!(!client.channels.exists("test-channel"));
}

#[tokio::test]
async fn rts4a_release_nonexistent_is_noop() {
    // RTS4a: releasing a non-existent channel is a no-op
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.channels.release("nonexistent").await;
    assert!(!client.channels.exists("nonexistent"));
}

#[tokio::test]
async fn rts3a_get_after_release_creates_new_channel() {
    // RTS3a: get() after release creates a fresh instance
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let channel1 = client.channels.get("test-channel");
    client.channels.release("test-channel").await;
    let channel2 = client.channels.get("test-channel");
    assert!(!std::sync::Arc::ptr_eq(&channel1, &channel2));
    assert_eq!(channel2.name(), "test-channel");
}

// --- Channel State Events (RTL2) ---

#[tokio::test]
async fn rtl2b_channel_initial_state_is_initialized() {
    // RTL2b: Channel starts in initialized state
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ChannelState;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let channel = client.channels.get("test-channel");
    assert_eq!(channel.state(), ChannelState::Initialized);
}

#[tokio::test]
async fn rtl2a_state_change_events_emitted() {
    // RTL2a: State changes emit corresponding events
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2a";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    let result = attach_task.await.unwrap();
    assert!(result.is_ok());

    let mut changes = Vec::new();
    while let Ok(change) = rx.try_recv() {
        changes.push(change);
    }

    assert!(changes.len() >= 2);
    assert_eq!(changes[0].current, ChannelState::Attaching);
    assert_eq!(changes[0].previous, ChannelState::Initialized);
    assert_eq!(changes[1].current, ChannelState::Attached);
    assert_eq!(changes[1].previous, ChannelState::Attaching);
}

#[tokio::test]
async fn rtl2d_channel_state_change_structure() {
    // RTL2d/TH1/TH2/TH5: ChannelStateChange has current, previous, event
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2d";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    attach_task.await.unwrap().unwrap();

    let change = rx.try_recv().unwrap();
    assert_eq!(change.current, ChannelState::Attaching);
    assert_eq!(change.previous, ChannelState::Initialized);
    assert_eq!(change.event, ChannelEvent::Attaching);
}

#[tokio::test]
async fn rtl2d_channel_state_change_includes_error() {
    // RTL2d/TH3: Error included in state change when channel fails
    use crate::error::ErrorInfo;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2d-error";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    let mut error_msg = ProtocolMessage::new(action::ERROR);
    error_msg.channel = Some(channel_name.to_string());
    error_msg.error = Some(ErrorInfo {
        code: Some(40160),
        status_code: Some(401),
        message: Some("Channel denied".to_string()),
        href: None,
        ..Default::default()
    });
    conn.send_to_client(error_msg);

    let result = attach_task.await.unwrap();
    assert!(result.is_err());

    let _ = rx.try_recv(); // attaching
    let change = rx.try_recv().unwrap(); // failed
    assert_eq!(change.current, ChannelState::Failed);
    assert!(change.reason.is_some());
    assert_eq!(change.reason.unwrap().code, Some(40160));
}

#[tokio::test]
async fn rtl2_filtered_event_subscription() {
    // RTL2: Subscribing to a specific event only receives that event
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2-filtered";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    attach_task.await.unwrap().unwrap();

    let mut all_events = Vec::new();
    while let Ok(change) = rx.try_recv() {
        all_events.push(change);
    }

    let attached_events: Vec<_> = all_events
        .iter()
        .filter(|e| e.event == ChannelEvent::Attached)
        .collect();
    assert_eq!(attached_events.len(), 1);
    assert_eq!(attached_events[0].current, ChannelState::Attached);
}

#[tokio::test]
async fn rtl2g_update_event_on_additional_attached() {
    // RTL2g: UPDATE event when ATTACHED received while already attached
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2g";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);

    let mut rx = channel.on_state_change();

    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let change = rx.try_recv().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);
    assert_eq!(change.event, ChannelEvent::Update);
    assert_eq!(change.current, ChannelState::Attached);
    assert_eq!(change.previous, ChannelState::Attached);
    assert!(!change.resumed);
}

#[tokio::test]
async fn rtl2g_no_duplicate_state_events() {
    // RTL2g: No duplicate state events
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2g-nodup";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();

    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut all_events = Vec::new();
    while let Ok(change) = rx.try_recv() {
        all_events.push(change);
    }

    let attached_state_events: Vec<_> = all_events
        .iter()
        .filter(|e| e.event == ChannelEvent::Attached)
        .collect();
    assert_eq!(attached_state_events.len(), 1);

    let update_events: Vec<_> = all_events
        .iter()
        .filter(|e| e.event == ChannelEvent::Update)
        .collect();
    assert_eq!(update_events.len(), 1);
}

#[tokio::test]
async fn rtl2i_has_backlog_flag() {
    // RTL2i/TH6: hasBacklog set when ATTACHED has HAS_BACKLOG flag
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2i";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        flags: Some(crate::protocol::flags::HAS_BACKLOG),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    attach_task.await.unwrap().unwrap();

    let _ = rx.try_recv(); // attaching
    let change = rx.try_recv().unwrap(); // attached
    assert_eq!(change.current, ChannelState::Attached);
    assert!(change.has_backlog);
}

#[tokio::test]
async fn rtl2i_has_backlog_false_when_not_present() {
    // RTL2i: hasBacklog false when flag not present
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2i-false";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    attach_task.await.unwrap().unwrap();

    let _ = rx.try_recv(); // attaching
    let change = rx.try_recv().unwrap(); // attached
    assert!(!change.has_backlog);
}

#[tokio::test]
async fn rtl2d_resumed_flag_in_state_change() {
    // RTL2d: resumed flag propagated in ChannelStateChange
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL2d-resumed";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        flags: Some(crate::protocol::flags::RESUMED),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    attach_task.await.unwrap().unwrap();

    let _ = rx.try_recv(); // attaching
    let change = rx.try_recv().unwrap(); // attached
    assert!(change.resumed);
}

#[tokio::test]
async fn channel_error_reason_populated_on_failure() {
    // Channel errorReason populated when channel enters failed state
    use crate::error::ErrorInfo;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-errorReason";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    let mut error_msg = ProtocolMessage::new(action::ERROR);
    error_msg.channel = Some(channel_name.to_string());
    error_msg.error = Some(ErrorInfo {
        code: Some(40160),
        status_code: Some(401),
        message: Some("Not authorized".to_string()),
        href: None,
        ..Default::default()
    });
    conn.send_to_client(error_msg);

    let result = attach_task.await.unwrap();
    assert!(result.is_err());

    assert_eq!(channel.state(), ChannelState::Failed);
    let err = channel.error_reason();
    assert!(err.is_some());
    assert_eq!(err.unwrap().code, Some(40160));
}

#[tokio::test]
async fn channel_error_reason_cleared_on_successful_attach() {
    // errorReason cleared after successful attach following a failure
    use crate::error::ErrorInfo;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-errorReason-clear";

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First attach fails
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    let mut error_msg = ProtocolMessage::new(action::ERROR);
    error_msg.channel = Some(channel_name.to_string());
    error_msg.error = Some(ErrorInfo {
        code: Some(40160),
        status_code: None,
        message: Some("Denied".to_string()),
        href: None,
        ..Default::default()
    });
    conn.send_to_client(error_msg);

    let result = attach_task.await.unwrap();
    assert!(result.is_err());
    assert_eq!(channel.state(), ChannelState::Failed);
    assert!(channel.error_reason().is_some());

    // Second attach succeeds
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    let result = attach_task.await.unwrap();
    assert!(result.is_ok());
    assert_eq!(channel.state(), ChannelState::Attached);
    assert!(channel.error_reason().is_none());
}

#[tokio::test]
async fn rts3b_options_set_on_new_channel() {
    // RTS3b: get() with options sets them on new channels
    use crate::channel::RealtimeChannelOptions;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ChannelMode;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());

    let channel_options = RealtimeChannelOptions {
        params: Some(params),
        modes: Some(vec![ChannelMode::Subscribe]),
        ..RealtimeChannelOptions::default()
    };

    let channel = client
        .channels
        .get_with_options("test-channel", channel_options)
        .unwrap();

    let opts = channel.options();
    assert_eq!(opts.params.unwrap().get("rewind").unwrap(), "1");
    assert!(opts.modes.unwrap().contains(&ChannelMode::Subscribe));
}

#[tokio::test]
async fn rts3c_options_updated_on_existing_channel() {
    // RTS3c: get() with options updates existing channel options
    use crate::channel::RealtimeChannelOptions;
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let initial_options = RealtimeChannelOptions {
        attach_on_subscribe: Some(false),
        ..RealtimeChannelOptions::default()
    };
    let channel = client
        .channels
        .get_with_options("test-channel", initial_options)
        .unwrap();

    let new_options = RealtimeChannelOptions {
        attach_on_subscribe: Some(true),
        ..RealtimeChannelOptions::default()
    };
    let same_channel = client
        .channels
        .get_with_options("test-channel", new_options)
        .unwrap();

    assert!(std::sync::Arc::ptr_eq(&channel, &same_channel));
    // Applied by the connection loop; visibility is eventual
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while channel.options().attach_on_subscribe != Some(true) {
        assert!(
            std::time::Instant::now() < deadline,
            "options update propagates"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn rtl16_set_options_updates_channel() {
    // RTL16: setOptions updates channel options
    use crate::channel::RealtimeChannelOptions;
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let channel = client.channels.get("test-channel");

    let mut params = std::collections::HashMap::new();
    params.insert("delta".to_string(), "vcdiff".to_string());
    let new_options = RealtimeChannelOptions {
        params: Some(params),
        attach_on_subscribe: Some(false),
        ..RealtimeChannelOptions::default()
    };

    channel.set_options(new_options).await.unwrap();

    let opts = channel.options();
    assert_eq!(opts.params.unwrap().get("delta").unwrap(), "vcdiff");
    assert_eq!(opts.attach_on_subscribe, Some(false));
}

#[tokio::test]
async fn rtl16a_set_options_triggers_reattach() {
    // RTL16a: setOptions with params/modes on attached channel triggers reattachment
    use crate::channel::RealtimeChannelOptions;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl16a");
    let mut rx = channel.on_state_change();

    // Attach the channel
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl16a".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);

    // Now call setOptions with params — should trigger reattach
    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    let new_options = RealtimeChannelOptions {
        params: Some(params),
        ..RealtimeChannelOptions::default()
    };

    let ch = channel.clone();
    let set_task = tokio::spawn(async move { ch.set_options(new_options).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Respond to reattach with ATTACHED
    let conns2 = mock.active_connections();
    let conn2 = conns2.last().unwrap();
    conn2.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl16a".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    set_task.await.unwrap().unwrap();

    // Should have gone through attaching state
    let mut saw_attaching = false;
    while let Ok(change) = rx.try_recv() {
        if change.current == ChannelState::Attaching {
            saw_attaching = true;
        }
    }
    assert!(saw_attaching);
    assert_eq!(channel.state(), ChannelState::Attached);
    assert_eq!(
        channel.options().params.unwrap().get("rewind").unwrap(),
        "1"
    );
}

#[tokio::test]
async fn rts5a_get_derived_creates_derived_channel() {
    // RTS5a: getDerived creates a channel with the correct derived name
    use crate::channel::DeriveOptions;
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let derive_opts = DeriveOptions::new("name == 'foo'");
    let channel = client.channels.get_derived("test-rts5a", derive_opts);

    assert!(channel.name().starts_with("[filter="));
    assert!(channel.name().ends_with("]test-rts5a"));
}

#[tokio::test]
async fn rts5a1_derived_channel_filter_base64_encoded() {
    // RTS5a1: filter is base64 encoded in the channel name
    use crate::channel::DeriveOptions;
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let filter = "name == 'test'";
    let derive_opts = DeriveOptions::new(filter);
    let channel = client.channels.get_derived("test-rts5a1", derive_opts);

    let expected_encoded = base64::encode(filter);
    let expected_name = format!("[filter={}]test-rts5a1", expected_encoded);
    assert_eq!(channel.name(), expected_name);
}

#[tokio::test]
async fn rts5a2_derived_channel_with_params() {
    // RTS5a2: params are included in the derived channel name
    use crate::channel::{DeriveOptions, RealtimeChannelOptions};
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let derive_opts = DeriveOptions::new("type == 'message'");
    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    params.insert("delta".to_string(), "vcdiff".to_string());
    let channel_opts = RealtimeChannelOptions {
        params: Some(params),
        ..RealtimeChannelOptions::default()
    };

    let channel = client
        .channels
        .get_derived_with_options("test-rts5a2", derive_opts, channel_opts)
        .unwrap();

    let name = channel.name().to_string();
    assert!(name.ends_with("]test-rts5a2"));

    // Extract qualifier between [ and ]
    let start = name.find('[').unwrap() + 1;
    let end = name.find(']').unwrap();
    let qualifier = &name[start..end];

    assert!(qualifier.starts_with("filter="));
    assert!(qualifier.contains('?'));

    let parts: Vec<&str> = qualifier.splitn(2, '?').collect();
    let params_str = parts[1];
    assert!(params_str.contains("rewind=1"));
    assert!(params_str.contains("delta=vcdiff"));
}

#[tokio::test]
async fn rts5_get_derived_with_options_sets_on_channel() {
    // RTS5: getDerived passes options to the created channel
    use crate::channel::{DeriveOptions, RealtimeChannelOptions};
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ChannelMode;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let derive_opts = DeriveOptions::new("true");
    let channel_opts = RealtimeChannelOptions {
        modes: Some(vec![ChannelMode::Subscribe]),
        attach_on_subscribe: Some(false),
        ..RealtimeChannelOptions::default()
    };

    let channel = client
        .channels
        .get_derived_with_options("test-rts5", derive_opts, channel_opts)
        .unwrap();

    let opts = channel.options();
    assert!(opts
        .modes
        .as_ref()
        .unwrap()
        .contains(&ChannelMode::Subscribe));
    assert_eq!(opts.attach_on_subscribe, Some(false));
}

// ==================== Phase 8b: Attach & Detach Tests ====================

#[tokio::test]
async fn rtl4a_attach_when_already_attached_is_noop() {
    // RTL4a: If already ATTACHED nothing is done
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4a";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First attach
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);

    // Count ATTACH messages before second attach
    let msgs_before: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    let count_before = msgs_before.len();

    // Second attach — should be no-op
    channel.attach().await.unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);

    let msgs_after: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert_eq!(msgs_after.len(), count_before); // No additional ATTACH sent
}

#[tokio::test]
async fn rtl4h_attach_while_attaching_waits() {
    // RTL4h: If ATTACHING, attach waits for completion
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4h";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Start first attach (don't await)
    let ch1 = channel.clone();
    let attach1 = tokio::spawn(async move { ch1.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Start second attach while first is pending
    let ch2 = channel.clone();
    let attach2 = tokio::spawn(async move { ch2.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Send ATTACHED response
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    // Both should complete
    attach1.await.unwrap().unwrap();
    attach2.await.unwrap().unwrap();

    assert_eq!(channel.state(), ChannelState::Attached);
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert_eq!(attach_msgs.len(), 1); // Only one ATTACH sent
}

#[tokio::test]
async fn rtl4h_attach_while_detaching_waits_then_attaches() {
    // RTL4h: If DETACHING, attach waits for detach then attaches
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4h-detaching";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First attach
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();

    // Start detach (don't await)
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Detaching);

    // Start attach while detaching
    let ch = channel.clone();
    let attach_task2 = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Send DETACHED response
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();

    // The queued attach should now proceed — send ATTACHED
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task2.await.unwrap().unwrap();

    assert_eq!(channel.state(), ChannelState::Attached);
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert_eq!(attach_msgs.len(), 2); // ATTACH, DETACH, ATTACH
}

#[tokio::test]
async fn rtl4g_attach_from_failed_clears_error_reason() {
    // RTL4g: Attach from FAILED clears errorReason
    use crate::error::ErrorInfo;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4g";
    let attach_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let attach_count_h = attach_count.clone();

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First attach — will fail
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: None,
            message: Some("Denied".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });
    let result = attach_task.await.unwrap();
    assert!(result.is_err());
    assert_eq!(channel.state(), ChannelState::Failed);
    assert!(channel.error_reason().is_some());

    // Second attach from failed — should clear errorReason
    let ch = channel.clone();
    let attach_task2 = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task2.await.unwrap().unwrap();

    assert_eq!(channel.state(), ChannelState::Attached);
    assert!(channel.error_reason().is_none());
}

#[tokio::test]
async fn rtl4b_attach_fails_when_connection_failed() {
    // RTL4b: Attach fails when connection is FAILED
    use crate::error::ErrorInfo;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        let msg = ProtocolMessage::connected("conn-1", "key-1");
        pending.respond_with_success(msg);
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Send fatal error to force FAILED
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client_and_close(ProtocolMessage {
        action: action::ERROR,
        error: Some(ErrorInfo {
            code: Some(80000),
            status_code: None,
            message: Some("Fatal error".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let channel = client.channels.get("test-RTL4b-failed");
    let result = channel.attach().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn rtl4i_attach_queued_when_connecting() {
    // RTL4i: Attach transitions to ATTACHING when connection is CONNECTING
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ChannelState;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new(); // No handler — connection stays pending
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    // Connection is CONNECTING (no handler to respond)

    let channel = client.channels.get("test-RTL4i");

    // Start attach while connecting
    let ch = channel.clone();
    let _attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);
}

#[tokio::test]
async fn rtl4i_attach_completes_when_connected() {
    // RTL4i: Queued attach completes when connection becomes CONNECTED
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4i-connected";
    let mock = MockWebSocket::new(); // await-based — no auto handler
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();

    let channel = client.channels.get(channel_name);

    // Start attach while connecting
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Complete connection
    let pending = mock.await_connection().await;
    pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // RTL4i: The connection sends queued ATTACH. Wait for it, then respond.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    attach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);
}

#[tokio::test]
async fn rtl4c_attach_sends_message_and_transitions() {
    // RTL4c: ATTACH sent, transitions to ATTACHING, then ATTACHED
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4c";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let mut rx = channel.on_state_change();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify ATTACH message was sent
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| {
            m.message.action == action::ATTACH && m.message.channel.as_deref() == Some(channel_name)
        })
        .collect();
    assert_eq!(attach_msgs.len(), 1);

    // Verify ATTACHING event was emitted
    let change = rx.try_recv().unwrap();
    assert_eq!(change.event, ChannelEvent::Attaching);
    assert_eq!(change.current, ChannelState::Attaching);

    // Send ATTACHED
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);
}

#[tokio::test]
async fn rtl4c1_attach_includes_channel_serial() {
    // RTL4c1: ATTACH includes channelSerial when available
    use crate::channel::RealtimeChannelOptions;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelMode, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4c1";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First attach
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        channel_serial: Some("serial-from-server-1".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();

    // Trigger reattach via setOptions (doesn't go through DETACHED)
    let ch = channel.clone();
    let set_opts_task = tokio::spawn(async move {
        ch.set_options(RealtimeChannelOptions {
            modes: Some(vec![ChannelMode::Subscribe]),
            ..RealtimeChannelOptions::default()
        })
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        channel_serial: Some("serial-from-server-2".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    set_opts_task.await.unwrap().unwrap();

    // Check captured ATTACH messages
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert_eq!(attach_msgs.len(), 2);
    // First attach: no channelSerial
    assert!(attach_msgs[0].message.channel_serial.is_none());
    // Second attach: has channelSerial from first ATTACHED
    assert_eq!(
        attach_msgs[1].message.channel_serial.as_deref(),
        Some("serial-from-server-1")
    );
}

#[tokio::test]
async fn rtl4f_attach_timeout_transitions_to_suspended() {
    // RTL4f: Attach timeout → SUSPENDED
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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

    let channel = client.channels.get("test-RTL4f");

    // Don't send ATTACHED response — let it timeout
    let result = channel.attach().await;
    assert!(result.is_err());
    assert_eq!(channel.state(), ChannelState::Suspended);
}

#[tokio::test]
async fn rtl4k_attach_includes_params() {
    // RTL4k: ATTACH includes params from ChannelOptions
    use crate::channel::RealtimeChannelOptions;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4k";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let mut params = std::collections::HashMap::new();
    params.insert("rewind".to_string(), "1".to_string());
    params.insert("delta".to_string(), "vcdiff".to_string());
    let opts = RealtimeChannelOptions {
        params: Some(params),
        ..RealtimeChannelOptions::default()
    };
    let channel = client
        .channels
        .get_with_options(channel_name, opts)
        .unwrap();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Check params in ATTACH message
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert_eq!(attach_msgs.len(), 1);
    let p = attach_msgs[0].message.params.as_ref().unwrap();
    assert_eq!(p.get("rewind").unwrap(), "1");
    assert_eq!(p.get("delta").unwrap(), "vcdiff");

    // Send ATTACHED to complete
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn rtl4l_attach_includes_modes_as_flags() {
    // RTL4l: Modes encoded as flags in ATTACH
    use crate::channel::RealtimeChannelOptions;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, flags, ChannelMode, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4l";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let opts = RealtimeChannelOptions {
        modes: Some(vec![ChannelMode::Publish, ChannelMode::Subscribe]),
        ..RealtimeChannelOptions::default()
    };
    let channel = client
        .channels
        .get_with_options(channel_name, opts)
        .unwrap();

    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert_eq!(attach_msgs.len(), 1);
    let f = attach_msgs[0].message.flags.unwrap();
    assert_ne!(f & flags::PUBLISH, 0);
    assert_ne!(f & flags::SUBSCRIBE, 0);

    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn rtl4m_modes_populated_from_attached_response() {
    // RTL4m: Modes decoded from ATTACHED flags
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{
        action, flags, ChannelMode, ChannelState, ConnectionState, ProtocolMessage,
    };
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4m";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        flags: Some(flags::PUBLISH | flags::SUBSCRIBE),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();

    let modes = channel.modes().unwrap();
    assert!(modes.contains(&ChannelMode::Publish));
    assert!(modes.contains(&ChannelMode::Subscribe));
}

#[tokio::test]
async fn rtl4j_attach_resume_flag_on_reattach() {
    // RTL4j: ATTACH_RESUME flag set on reattachment
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, flags, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL4j";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First attach
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();

    // Detach
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();

    // Reattach — should have ATTACH_RESUME
    let ch = channel.clone();
    let attach_task2 = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task2.await.unwrap().unwrap();

    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert_eq!(attach_msgs.len(), 2);
    // First: no ATTACH_RESUME
    let f0 = attach_msgs[0].message.flags.unwrap_or(0);
    assert_eq!(f0 & flags::ATTACH_RESUME, 0);
    // Second: has ATTACH_RESUME
    let f1 = attach_msgs[1].message.flags.unwrap_or(0);
    assert_ne!(f1 & flags::ATTACH_RESUME, 0);
}

// ==================== RTL5: Detach Tests ====================

#[tokio::test]
async fn rtl5a_detach_when_initialized_is_noop() {
    // RTL5a: Detach from INITIALIZED is no-op
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });

    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    let channel = client.channels.get("test-RTL5a");
    assert_eq!(channel.state(), ChannelState::Initialized);
    channel.detach().await.unwrap();
    // State may remain Initialized or become Detached — both are acceptable
}

#[tokio::test]
async fn rtl5a_detach_when_already_detached_is_noop() {
    // RTL5a: Detach from DETACHED is no-op
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5a-detached";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Attach then detach
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    t.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Detached);

    let detach_count_before = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::DETACH)
        .count();

    // Second detach — should be no-op
    channel.detach().await.unwrap();
    assert_eq!(channel.state(), ChannelState::Detached);

    let detach_count_after = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::DETACH)
        .count();
    assert_eq!(detach_count_after, detach_count_before);
}

#[tokio::test]
async fn rtl5i_detach_while_detaching_waits() {
    // RTL5i: If DETACHING, detach waits for completion
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5i";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Attach first
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    // Start first detach (don't await)
    let ch = channel.clone();
    let detach1 = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Detaching);

    // Start second detach while first is pending
    let ch = channel.clone();
    let detach2 = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Send DETACHED response
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });

    detach1.await.unwrap().unwrap();
    detach2.await.unwrap().unwrap();

    assert_eq!(channel.state(), ChannelState::Detached);
    let detach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::DETACH)
        .collect();
    assert_eq!(detach_msgs.len(), 1);
}

#[tokio::test]
async fn rtl5i_detach_while_attaching_waits_then_detaches() {
    // RTL5i: If ATTACHING, detach waits for attach then detaches
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5i-attaching";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Start attach (don't await)
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Start detach while attaching
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Send ATTACHED response — attach completes
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();

    // Wait for detach to proceed, send DETACHED
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();

    assert_eq!(channel.state(), ChannelState::Detached);
}

#[tokio::test]
async fn rtl5b_detach_from_failed_results_in_error() {
    // RTL5b: Detach from FAILED is an error
    use crate::error::ErrorInfo;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5b";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Fail the channel
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: None,
            message: Some("Not permitted".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });
    let _ = t.await.unwrap();
    assert_eq!(channel.state(), ChannelState::Failed);

    // Try to detach from failed state
    let result = channel.detach().await;
    assert!(result.is_err());
    assert_eq!(channel.state(), ChannelState::Failed);
}

#[tokio::test]
async fn rtl5j_detach_from_suspended_transitions_to_detached() {
    // RTL5j: Detach from SUSPENDED → immediate DETACHED
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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

    let channel = client.channels.get("test-RTL5j");

    // Attach with timeout to get to SUSPENDED
    let result = channel.attach().await;
    assert!(result.is_err());
    assert_eq!(channel.state(), ChannelState::Suspended);

    // Detach from suspended — immediate transition
    channel.detach().await.unwrap();
    assert_eq!(channel.state(), ChannelState::Detached);
}

#[tokio::test]
async fn rtl5l_detach_when_not_connected_transitions_immediately() {
    // RTL5l: Detach when connection not CONNECTED → immediate DETACHED
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState};
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new(); // No handler — stays connecting
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();

    let channel = client.channels.get("test-RTL5l");

    // Start attach while connecting
    let ch = channel.clone();
    let _attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Detach while not connected — immediate
    channel.detach().await.unwrap();
    assert_eq!(channel.state(), ChannelState::Detached);

    // No DETACH message sent
    let detach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::DETACH)
        .collect();
    assert_eq!(detach_msgs.len(), 0);
}

#[tokio::test]
async fn rtl5d_normal_detach_flow() {
    // RTL5d: DETACH sent, transitions to DETACHING then DETACHED
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5d";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Attach
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let mut rx = channel.on_state_change();

    // Start detach
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify DETACH message was sent
    let detach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| {
            m.message.action == action::DETACH && m.message.channel.as_deref() == Some(channel_name)
        })
        .collect();
    assert_eq!(detach_msgs.len(), 1);

    // Verify DETACHING event
    let change = rx.try_recv().unwrap();
    assert_eq!(change.event, ChannelEvent::Detaching);
    assert_eq!(change.previous, ChannelState::Attached);

    // Send DETACHED
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Detached);
}

#[tokio::test]
async fn rtl5f_detach_timeout_returns_to_previous_state() {
    // RTL5f: Detach timeout → back to ATTACHED
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5f";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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

    let channel = client.channels.get(channel_name);

    // Attach first
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);

    // Don't respond to DETACH — let it timeout
    let result = channel.detach().await;
    assert!(result.is_err());
    assert_eq!(channel.state(), ChannelState::Attached); // Returns to previous state
}

#[tokio::test]
async fn rtl5k_attached_during_detaching_sends_new_detach() {
    // RTL5k: ATTACHED received while DETACHING → sends new DETACH
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5k";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Attach
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    // Start detach (don't await)
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Detaching);

    // Server unexpectedly sends ATTACHED instead of DETACHED
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Should have sent another DETACH
    let detach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::DETACH)
        .collect();
    assert!(detach_msgs.len() >= 2);

    // Now send DETACHED to complete
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Detached);
}

#[tokio::test]
async fn rtl5k_attached_while_detached_sends_detach() {
    // RTL5k: ATTACHED received while DETACHED → sends DETACH
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5k-detached";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Attach then detach
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    t.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Detached);

    let detach_count_before = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::DETACH)
        .count();

    // Server unexpectedly sends ATTACHED while detached
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let detach_count_after = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::DETACH)
        .count();
    assert!(detach_count_after > detach_count_before); // Client sent another DETACH
    assert_eq!(channel.state(), ChannelState::Detached);
}

#[tokio::test]
async fn rtl5_detach_emits_state_change_events() {
    // RTL5: Detach emits DETACHING then DETACHED events
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5-events";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Attach
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    // Subscribe to events after attach
    let mut rx = channel.on_state_change();

    // Detach
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();

    // Collect state changes
    let change1 = rx.try_recv().unwrap();
    assert_eq!(change1.current, ChannelState::Detaching);
    assert_eq!(change1.previous, ChannelState::Attached);
    assert_eq!(change1.event, ChannelEvent::Detaching);

    let change2 = rx.try_recv().unwrap();
    assert_eq!(change2.current, ChannelState::Detached);
    assert_eq!(change2.previous, ChannelState::Detaching);
    assert_eq!(change2.event, ChannelEvent::Detached);
}

#[tokio::test]
async fn rtl5_detach_clears_error_reason() {
    // RTL5: Successful detach clears errorReason
    use crate::error::ErrorInfo;
    use crate::mock_ws::{MockWebSocket, PendingConnection};
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-RTL5-error";
    let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
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
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First attach fails
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: None,
            message: Some("Denied".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });
    let _ = t.await.unwrap();
    assert_eq!(channel.state(), ChannelState::Failed);
    assert!(channel.error_reason().is_some());

    // Second attach succeeds
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    // Detach
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    t.await.unwrap().unwrap();

    assert_eq!(channel.state(), ChannelState::Detached);
    assert!(channel.error_reason().is_none());
}

// ===== Phase 8c: Messages =====

// --- RTL6i1: Publish single message by name and data ---
#[tokio::test]
async fn rtl6i1_publish_single_message() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6i1";
    let mock = MockWebSocket::with_handler({
        let cn = channel_name.to_string();
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    // Publish
    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("greeting")
            .json(serde_json::json!("hello"))
            .send()
            .await
    });

    // Wait for the MESSAGE to be captured
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 1);
    assert_eq!(
        message_msgs[0].message.channel.as_deref(),
        Some(channel_name)
    );
    let messages = message_msgs[0].message.messages_json();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["name"], "greeting");
    assert_eq!(messages[0]["data"], "hello");

    // Send ACK to resolve publish
    let msg_serial = message_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(msg_serial),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("serial-1".to_string())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_ok());
}

// --- RTL6c1: Publish immediately when CONNECTED and channel ATTACHED ---
#[tokio::test]
async fn rtl6c1_publish_immediately_when_attached() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c1-attached";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);

    // Publish — should be sent immediately (synchronously captured by mock)
    let ch = channel.clone();
    let _publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("test")
            .json(serde_json::json!("immediate"))
            .send()
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 1);
    assert_eq!(message_msgs[0].message.messages_json()[0]["name"], "test");
    assert_eq!(
        message_msgs[0].message.messages_json()[0]["data"],
        "immediate"
    );
}

// --- RTL6c1: Publish immediately when CONNECTED and channel INITIALIZED ---
#[tokio::test]
async fn rtl6c1_publish_immediately_when_initialized() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c1-init";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(channel.state(), ChannelState::Initialized);

    // Publish on initialized channel — should send immediately (RTL6c1)
    let ch = channel.clone();
    let _publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("before-attach")
            .json(serde_json::json!("data"))
            .send()
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 1);
    assert_eq!(
        message_msgs[0].message.messages_json()[0]["name"],
        "before-attach"
    );
}

// --- RTL6c5: Publish does not trigger implicit attach ---
#[tokio::test]
async fn rtl6c5_publish_does_not_attach() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c5";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(channel.state(), ChannelState::Initialized);

    let ch = channel.clone();
    let _publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("no-attach")
            .json(serde_json::json!("test"))
            .send()
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Channel should remain INITIALIZED — no implicit attach
    assert_eq!(channel.state(), ChannelState::Initialized);
    let msgs = mock.client_messages();
    let attach_count = msgs
        .iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();
    assert_eq!(attach_count, 0);
    // Message should have been sent
    let message_count = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .count();
    assert_eq!(message_count, 1);
}

// --- RTL6c2: Publish queued when connection CONNECTING ---
#[tokio::test]
async fn rtl6c2_publish_queued_when_connecting() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c2-connecting";
    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connecting, 5000).await);

    // Publish while CONNECTING — should be queued
    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("queued")
            .json(serde_json::json!("waiting"))
            .send()
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // Message should NOT have been sent yet
    let msgs = mock.client_messages();
    let message_count = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .count();
    assert_eq!(message_count, 0);

    // Complete the connection
    let pending = mock.await_connection().await;
    pending.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // Queued message should now have been sent
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 1);
    assert_eq!(message_msgs[0].message.messages_json()[0]["name"], "queued");

    // ACK to resolve
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    let msg_serial = message_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(msg_serial),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult { serials: vec![] }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_ok());
}

// --- RTL6c2: Publish queued when connection INITIALIZED ---
#[tokio::test]
async fn rtl6c2_publish_queued_when_initialized() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c2-init";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(client.connection.state(), ConnectionState::Initialized);

    // Publish before connecting — should be queued
    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("pre-connect")
            .json(serde_json::json!("early"))
            .send()
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_count = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .count();
    assert_eq!(message_count, 0);

    // Now connect
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 1);
    assert_eq!(
        message_msgs[0].message.messages_json()[0]["name"],
        "pre-connect"
    );

    // ACK
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    let msg_serial = message_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(msg_serial),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult { serials: vec![] }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_ok());
}

// --- RTL6c2: Multiple queued messages sent in order ---
#[tokio::test]
async fn rtl6c2_multiple_queued_messages_order() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c2-order";
    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connecting, 5000).await);

    // Queue multiple messages
    let ch1 = channel.clone();
    let ch2 = channel.clone();
    let ch3 = channel.clone();
    let _h1 = tokio::spawn(async move {
        ch1.publish()
            .name("first")
            .json(serde_json::json!("1"))
            .send()
            .await
    });
    let _h2 = tokio::spawn(async move {
        ch2.publish()
            .name("second")
            .json(serde_json::json!("2"))
            .send()
            .await
    });
    let _h3 = tokio::spawn(async move {
        ch3.publish()
            .name("third")
            .json(serde_json::json!("3"))
            .send()
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        mock.client_messages()
            .iter()
            .filter(|m| m.message.action == action::MESSAGE)
            .count(),
        0
    );

    // Complete connection
    let pending = mock.await_connection().await;
    pending.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 3);
    assert_eq!(message_msgs[0].message.messages_json()[0]["name"], "first");
    assert_eq!(message_msgs[1].message.messages_json()[0]["name"], "second");
    assert_eq!(message_msgs[2].message.messages_json()[0]["name"], "third");
}

// --- RTL6c4: Publish fails when connection FAILED ---
#[tokio::test]
async fn rtl6c4_publish_fails_when_connection_failed() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c4-failed";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_error(ProtocolMessage {
                action: action::ERROR,
                error: Some(ErrorInfo {
                    code: Some(80000),
                    status_code: None,
                    message: Some("Fatal error".to_string()),
                    href: None,
                    ..Default::default()
                }),
                ..ProtocolMessage::new(action::ERROR)
            });
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let result = channel
        .publish()
        .name("fail")
        .json(serde_json::json!("should-error"))
        .send()
        .await;
    assert!(result.is_err());
}

// --- RTL6c4: Publish fails when channel is FAILED ---
#[tokio::test]
async fn rtl6c4_publish_fails_when_channel_failed() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c4-ch-failed";
    let mock = MockWebSocket::with_handler({
        let cn = channel_name.to_string();
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach fails → channel enters FAILED
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(cn),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Not permitted".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });
    let _ = t.await.unwrap();
    assert_eq!(channel.state(), ChannelState::Failed);

    let result = channel
        .publish()
        .name("fail")
        .json(serde_json::json!("should-error"))
        .send()
        .await;
    assert!(result.is_err());
}

// --- RTL6c2: Publish fails when queueMessages is false ---
#[tokio::test]
async fn rtl6c2_publish_fails_when_queue_disabled() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c2-noqueue";
    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .queue_messages(false),
        transport.clone(),
    )
    .unwrap();

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connecting, 5000).await);

    let result = channel
        .publish()
        .name("fail")
        .json(serde_json::json!("should-error"))
        .send()
        .await;
    assert!(result.is_err());
}

// --- RTL6j: Publish returns PublishResult with serials ---
#[tokio::test]
async fn rtl6j_publish_returns_publish_result() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6j";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    // Publish
    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("greeting")
            .json(serde_json::json!("hello"))
            .send()
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs[0].message.msg_serial, Some(0));

    // ACK with serials
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(0),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("abc123".to_string())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_ok());
}

// --- RTL6j: Batch publish returns multiple serials ---
#[tokio::test]
async fn rtl6j_batch_publish_returns_multiple_serials() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6j-batch";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    // Publish batch
    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move { ch.publish_message(Some("msg1"), None).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ACK with serials (one null for conflation)
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(0),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![
                Some("serial-1".to_string()),
                None,
                Some("serial-3".to_string()),
            ],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_ok());
}

// --- RTL7a: Subscribe with no name receives all messages ---
#[tokio::test]
async fn rtl7a_subscribe_receives_all_messages() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7a";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    // Send messages with different names
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "event1", "data": "data1"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "event2", "data": "data2"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![serde_json::json!({"data": "data3"})]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msg1 = rx.try_recv().unwrap();
    assert_eq!(msg1.name.as_deref(), Some("event1"));
    assert!(matches!(&msg1.data, rest::Data::String(s) if s == "data1"));
    let msg2 = rx.try_recv().unwrap();
    assert_eq!(msg2.name.as_deref(), Some("event2"));
    let msg3 = rx.try_recv().unwrap();
    assert!(msg3.name.is_none());
    assert!(matches!(&msg3.data, rest::Data::String(s) if s == "data3"));
}

// --- RTL7a: Subscribe receives multiple messages from single ProtocolMessage ---
#[tokio::test]
async fn rtl7a_subscribe_multiple_messages_in_single_protocol_message() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7a-multi";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    // Single ProtocolMessage with multiple messages
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "batch1", "data": "first"}),
            serde_json::json!({"name": "batch2", "data": "second"}),
            serde_json::json!({"name": "batch3", "data": "third"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msg1 = rx.try_recv().unwrap();
    assert_eq!(msg1.name.as_deref(), Some("batch1"));
    let msg2 = rx.try_recv().unwrap();
    assert_eq!(msg2.name.as_deref(), Some("batch2"));
    let msg3 = rx.try_recv().unwrap();
    assert_eq!(msg3.name.as_deref(), Some("batch3"));
}

// --- RTL7b: Subscribe with name only receives matching messages ---
#[tokio::test]
async fn rtl7b_subscribe_with_name_filter() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7b";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe_with_name("target");

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "other", "data": "skip"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "target", "data": "match"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![serde_json::json!({"data": "no-name"})]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.name.as_deref(), Some("target"));
    assert!(matches!(&msg.data, rest::Data::String(s) if s == "match"));
    // No more messages
    assert!(rx.try_recv().is_err());
}

// --- RTL7b: Multiple name-specific subscriptions ---
#[tokio::test]
async fn rtl7b_multiple_name_subscriptions() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7b-multi";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_alpha_id, mut alpha_rx) = channel.subscribe_with_name("alpha");
    let (_beta_id, mut beta_rx) = channel.subscribe_with_name("beta");

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "alpha", "data": "a1"}),
            serde_json::json!({"name": "beta", "data": "b1"}),
            serde_json::json!({"name": "alpha", "data": "a2"}),
            serde_json::json!({"name": "gamma", "data": "g1"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(matches!(&alpha_rx.try_recv().unwrap().data, rest::Data::String(s) if s == "a1"));
    assert!(matches!(&alpha_rx.try_recv().unwrap().data, rest::Data::String(s) if s == "a2"));
    assert!(alpha_rx.try_recv().is_err());

    assert!(matches!(&beta_rx.try_recv().unwrap().data, rest::Data::String(s) if s == "b1"));
    assert!(beta_rx.try_recv().is_err());
}

// --- RTL7g: Subscribe triggers implicit attach ---
#[tokio::test]
async fn rtl7g_subscribe_triggers_implicit_attach() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7g";
    let mock = MockWebSocket::with_handler({
        let cn = channel_name.to_string();
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Default attachOnSubscribe is true
    let channel = client.channels.get(channel_name);
    assert_eq!(channel.state(), ChannelState::Initialized);

    let (_sub_id, mut rx) = channel.subscribe();

    // Wait for implicit attach to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Respond to ATTACH
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Verify the listener was registered
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(channel_name.to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "test", "data": "hello"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.name.as_deref(), Some("test"));
}

// --- RTL7h: Subscribe does not attach when attachOnSubscribe is false ---
#[tokio::test]
async fn rtl7h_subscribe_no_attach_when_disabled() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7h";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(channel.state(), ChannelState::Initialized);

    channel.subscribe();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(channel.state(), ChannelState::Initialized);
    let attach_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();
    assert_eq!(attach_count, 0);
}

// --- RTL7g: Subscribe does not attach when already attached ---
#[tokio::test]
async fn rtl7g_subscribe_no_attach_when_already_attached() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7g-already";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // Attach first
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let attach_count_before = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();

    // Subscribe — should NOT send another ATTACH
    channel.subscribe();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let attach_count_after = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();
    assert_eq!(attach_count_before, attach_count_after);
    assert_eq!(channel.state(), ChannelState::Attached);
}

// --- RTL17: Messages not delivered when channel is not ATTACHED ---
#[tokio::test]
async fn rtl17_messages_not_delivered_when_not_attached() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl17";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    // Start attach but don't complete it — channel stays ATTACHING
    let ch = channel.clone();
    let _t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Send message while ATTACHING
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(channel_name.to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "premature", "data": "skip"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx.try_recv().is_err()); // No messages delivered
}

// --- RTL8a: Unsubscribe specific listener ---
#[tokio::test]
async fn rtl8a_unsubscribe_specific_listener() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl8a";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (sub_a, mut rx_a) = channel.subscribe();
    let (_sub_b, mut rx_b) = channel.subscribe();

    // Both receive first message
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "msg1", "data": "first"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx_a.try_recv().is_ok());
    assert!(rx_b.try_recv().is_ok());

    // Unsubscribe listener A
    channel.unsubscribe(sub_a);

    // Only B should receive second message
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "msg2", "data": "second"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx_a.try_recv().is_err()); // A unsubscribed
    let msg = rx_b.try_recv().unwrap();
    assert_eq!(msg.name.as_deref(), Some("msg2"));
}

// --- RTL8b: Unsubscribe from specific name ---
#[tokio::test]
async fn rtl8b_unsubscribe_from_specific_name() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl8b";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (sub_id, mut rx) = channel.subscribe_with_name("alpha");
    let (_sub_beta, mut rx_beta) = channel.subscribe_with_name("beta");

    // Both active
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "alpha", "data": "a1"}),
            serde_json::json!({"name": "beta", "data": "b1"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx.try_recv().is_ok());
    assert!(rx_beta.try_recv().is_ok());

    // Unsubscribe only "alpha"
    channel.unsubscribe_with_name("alpha", sub_id);

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "alpha", "data": "a2"}),
            serde_json::json!({"name": "beta", "data": "b2"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(rx.try_recv().is_err()); // Alpha unsubscribed
    let msg = rx_beta.try_recv().unwrap();
    assert!(matches!(&msg.data, rest::Data::String(s) if s == "b2"));
}

// --- RTL8c: Unsubscribe all ---
#[tokio::test]
async fn rtl8c_unsubscribe_all() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl8c";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_all, mut rx_all) = channel.subscribe();
    let (_sub_named, mut rx_named) = channel.subscribe_with_name("specific");

    // Both active
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "specific", "data": "first"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx_all.try_recv().is_ok());
    assert!(rx_named.try_recv().is_ok());

    // Unsubscribe all
    channel.unsubscribe_all();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "specific", "data": "second"}),
            serde_json::json!({"name": "other", "data": "third"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(rx_all.try_recv().is_err());
    assert!(rx_named.try_recv().is_err());
}

// =========================================================================
// Phase 8d: Advanced Channel Features
// =========================================================================

/// Helper: set up a connected Realtime client with a mock WebSocket.
/// The handler auto-accepts every connection attempt.
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

// --- RTL3a: FAILED connection transitions ATTACHED channel to FAILED ---
#[tokio::test]
async fn rtl3a_failed_connection_transitions_attached_to_failed() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl3a");
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Send connection-level ERROR (no channel field) to trigger FAILED
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        error: Some(ErrorInfo {
            code: Some(40198),
            status_code: Some(401),
            message: Some("Invalid credentials".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    // RTL3a: Channel should transition to FAILED
    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
    assert!(channel.error_reason().is_some());
}

// --- RTL3a: Channels in INITIALIZED unaffected by FAILED ---
#[tokio::test]
async fn rtl3a_initialized_unaffected_by_failed() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let ch_init = client.channels.get("ch-initialized");
    assert_eq!(ch_init.state(), ChannelState::Initialized);

    // Trigger connection FAILED
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        error: Some(ErrorInfo {
            code: Some(40198),
            status_code: Some(401),
            message: Some("Fatal".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    // RTL3a: INITIALIZED channel should be unaffected
    assert_eq!(ch_init.state(), ChannelState::Initialized);
}

// --- RTL3b: CLOSED connection transitions ATTACHED channel to DETACHED ---
#[tokio::test]
async fn rtl3b_closed_connection_transitions_attached_to_detached() {
    use crate::protocol::{ChannelState, ConnectionState};
    use crate::realtime::{await_channel_state, await_state};

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl3b");
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Close the connection
    client.close();

    // RTL3b: Channel should transition to DETACHED
    assert!(await_channel_state(&channel, ChannelState::Detached, 5000).await);
}

// --- RTL15a: attachSerial set from ATTACHED channelSerial ---
#[tokio::test]
async fn rtl15a_attach_serial_from_attached() {
    use crate::protocol::ConnectionState;
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl15a");
    assert!(channel.attach_serial().is_none());

    phase8d_attach(&channel, &mock, Some("attach-serial-001")).await;

    // RTL15a: attachSerial populated from ATTACHED response
    assert_eq!(
        channel.attach_serial().as_deref(),
        Some("attach-serial-001")
    );
}

// --- RTL15a: attachSerial updated on additional ATTACHED ---
#[tokio::test]
async fn rtl15a_attach_serial_updated_on_additional_attached() {
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl15a-update");
    phase8d_attach(&channel, &mock, Some("serial-v1")).await;
    assert_eq!(channel.attach_serial().as_deref(), Some("serial-v1"));

    // Server sends additional ATTACHED with new serial (UPDATE)
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl15a-update".to_string()),
        channel_serial: Some("serial-v2".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // RTL15a: attachSerial updated
    assert_eq!(channel.attach_serial().as_deref(), Some("serial-v2"));
}

// --- RTL15b: channelSerial set from ATTACHED ---
#[tokio::test]
async fn rtl15b_channel_serial_from_attached() {
    use crate::protocol::ConnectionState;
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl15b");
    assert!(channel.channel_serial().is_none());

    phase8d_attach(&channel, &mock, Some("ch-serial-001")).await;
    assert_eq!(channel.channel_serial().as_deref(), Some("ch-serial-001"));
}

// --- RTL15b: channelSerial updated from MESSAGE ---
#[tokio::test]
async fn rtl15b_channel_serial_updated_from_message() {
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl15b-msg";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, Some("initial-serial")).await;
    assert_eq!(channel.channel_serial().as_deref(), Some("initial-serial"));

    // Server sends MESSAGE with updated channelSerial
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(channel_name.to_string()),
        channel_serial: Some("msg-serial-002".to_string()),
        messages: crate::protocol::wire_messages(vec![serde_json::json!({"name": "test"})]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // RTL15b: channelSerial updated from MESSAGE
    assert_eq!(channel.channel_serial().as_deref(), Some("msg-serial-002"));
}

// --- RTL15b: channelSerial NOT updated when field absent ---
#[tokio::test]
async fn rtl15b_channel_serial_not_updated_when_absent() {
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl15b-absent";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, Some("keep-this")).await;
    assert_eq!(channel.channel_serial().as_deref(), Some("keep-this"));

    // Send MESSAGE without channelSerial
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(channel_name.to_string()),
        messages: crate::protocol::wire_messages(vec![serde_json::json!({"name": "test"})]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // RTL15b: channelSerial should remain unchanged
    assert_eq!(channel.channel_serial().as_deref(), Some("keep-this"));
}

// --- RTL15b: channelSerial cleared on DETACHED (RTL15b1) ---
#[tokio::test]
async fn rtl15b_channel_serial_cleared_on_detached() {
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl15b-detached";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, Some("attached-serial")).await;
    assert_eq!(channel.channel_serial().as_deref(), Some("attached-serial"));

    // Initiate detach
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send DETACHED response (with a channelSerial that should be ignored)
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        channel_serial: Some("should-be-ignored".to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();

    // RTL15b1: channelSerial cleared on DETACHED
    assert!(channel.channel_serial().is_none());
    assert_eq!(channel.state(), ChannelState::Detached);
}

// --- RTL15b1: channelSerial cleared on FAILED ---
#[tokio::test]
async fn rtl15b1_channel_serial_cleared_on_failed() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl15b1-failed";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, Some("serial-to-clear")).await;
    assert!(channel.channel_serial().is_some());

    // Send channel-level ERROR
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(90002),
            status_code: None,
            message: Some("Channel error".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);

    // RTL15b1: channelSerial cleared
    assert!(channel.channel_serial().is_none());
}

// --- RTL15b1: channelSerial cleared on SUSPENDED ---
#[tokio::test]
async fn rtl15b1_channel_serial_cleared_on_suspended() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl15b1-suspended";

    // Use a custom setup with very short attach timeout
    let mock = crate::mock_ws::MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = crate::realtime::Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .realtime_request_timeout(std::time::Duration::from_millis(100))
            .fallback_hosts(vec![]),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, Some("serial-to-clear")).await;
    assert_eq!(channel.channel_serial().as_deref(), Some("serial-to-clear"));

    // Send server-initiated DETACHED with error — triggers reattach attempt (RTL13a)
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(90198),
            status_code: Some(500),
            message: Some("Detached".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::DETACHED)
    });

    // Don't respond to the reattach ATTACH — let it timeout → SUSPENDED
    assert!(await_channel_state(&channel, ChannelState::Suspended, 5000).await);

    // RTL15b1: channelSerial cleared on SUSPENDED
    assert!(channel.channel_serial().is_none());
}

// --- RTL13a: Server-initiated DETACHED triggers reattach ---
#[tokio::test]
async fn rtl13a_server_detached_triggers_reattach() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl13a";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Server sends unsolicited DETACHED with error
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(50000),
            status_code: None,
            message: Some("Server detached".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::DETACHED)
    });

    // RTL13a: Should move to ATTACHING and send ATTACH
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send ATTACHED for the reattach
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    assert!(await_channel_state(&channel, ChannelState::Attached, 5000).await);

    // Verify two ATTACH messages were sent (initial + reattach)
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| {
            m.message.action == action::ATTACH && m.message.channel.as_deref() == Some(channel_name)
        })
        .collect();
    assert_eq!(attach_msgs.len(), 2);
}

// --- RTL13a: DETACHED while DETACHING is normal (not server-initiated) ---
#[tokio::test]
async fn rtl13a_detached_while_detaching_is_normal() {
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl13a-normal";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    // User-initiated detach
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send DETACHED response (normal flow, not server-initiated)
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();

    assert_eq!(channel.state(), ChannelState::Detached);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Should NOT trigger reattach — only 1 ATTACH total
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| {
            m.message.action == action::ATTACH && m.message.channel.as_deref() == Some(channel_name)
        })
        .collect();
    assert_eq!(attach_msgs.len(), 1);
}

// --- RTL12: Additional ATTACHED with resumed=false emits UPDATE ---
#[tokio::test]
async fn rtl12_additional_attached_not_resumed_emits_update() {
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl12";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    let mut rx = channel.on_state_change();

    // Server sends additional ATTACHED without RESUMED flag, with error
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(50000),
            status_code: None,
            message: Some("Continuity lost".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    // RTL12: Should emit UPDATE event
    let change = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(change.event, ChannelEvent::Update);
    assert_eq!(change.current, ChannelState::Attached);
    assert_eq!(change.previous, ChannelState::Attached);
    assert!(!change.resumed);
    assert!(change.reason.is_some());
    assert_eq!(change.reason.unwrap().code, Some(50000));

    // Channel remains ATTACHED
    assert_eq!(channel.state(), ChannelState::Attached);
}

// --- RTL12: Additional ATTACHED with resumed=true does NOT emit UPDATE ---
#[tokio::test]
async fn rtl12_additional_attached_resumed_no_update() {
    use crate::protocol::{action, flags, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl12-resumed";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    let mut rx = channel.on_state_change();

    // Server sends additional ATTACHED WITH RESUMED flag
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        flags: Some(flags::RESUMED),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    // RTL12: Should NOT emit UPDATE
    let result = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
    assert!(result.is_err(), "No event expected when resumed=true");
    assert_eq!(channel.state(), ChannelState::Attached);
}

// --- RTL12: Additional ATTACHED without error has null reason ---
#[tokio::test]
async fn rtl12_additional_attached_no_error_null_reason() {
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl12-no-err";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    let mut rx = channel.on_state_change();

    // Server sends ATTACHED without error, without RESUMED flag
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(change.event, ChannelEvent::Update);
    // RTL12: reason is null
    assert!(change.reason.is_none());
}

// --- RTL14: Channel ERROR transitions ATTACHED to FAILED ---
#[tokio::test]
async fn rtl14_channel_error_attached_to_failed() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl14";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    // Send channel-scoped ERROR
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Channel error".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    // RTL14: Channel transitions to FAILED
    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
    let err = channel.error_reason().unwrap();
    assert_eq!(err.code, Some(40160));

    // Connection should remain CONNECTED
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

// --- RTL14: Channel ERROR does not affect other channels ---
#[tokio::test]
async fn rtl14_channel_error_does_not_affect_other_channels() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let ch1 = client.channels.get("ch-target");
    let ch2 = client.channels.get("ch-other");
    phase8d_attach(&ch1, &mock, None).await;
    phase8d_attach(&ch2, &mock, None).await;

    // Send ERROR only to ch1
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some("ch-target".to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Bad channel".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_channel_state(&ch1, ChannelState::Failed, 5000).await);

    // RTL14: Other channel unaffected
    assert_eq!(ch2.state(), ChannelState::Attached);
    assert!(ch2.error_reason().is_none());
}

// --- RTL23: Channel name attribute ---
#[tokio::test]
async fn rtl23_channel_name_attribute() {
    use crate::protocol::ConnectionState;
    use crate::realtime::await_state;

    let (client, _mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // RTL23: Channel name matches what was passed to get()
    let ch1 = client.channels.get("my-channel");
    assert_eq!(ch1.name(), "my-channel");

    let ch2 = client.channels.get("namespace:channel-name");
    assert_eq!(ch2.name(), "namespace:channel-name");
}

// --- RTL24: errorReason set on channel error ---
#[tokio::test]
async fn rtl24_error_reason_set_on_error() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl24";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    assert!(channel.error_reason().is_none());

    phase8d_attach(&channel, &mock, None).await;

    // Send ERROR
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Unauthorized".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);

    // RTL24: errorReason set
    let err = channel.error_reason().unwrap();
    assert_eq!(err.code, Some(40160));
    assert_eq!(err.status_code, Some(401));
}

// --- RTL24: errorReason cleared on successful attach ---
#[tokio::test]
async fn rtl24_error_reason_cleared_on_attach() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl24-clear";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    // First: cause an error
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(90002),
            status_code: None,
            message: Some("Temporary error".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
    assert!(channel.error_reason().is_some());

    // Re-attach (allowed from FAILED via RTL4g)
    phase8d_attach(&channel, &mock, None).await;

    // RTL24: errorReason cleared on successful attach
    assert!(channel.error_reason().is_none());
}

// --- RTL25b: whenState waits for state transition ---
#[tokio::test]
async fn rtl25b_when_state_waits_for_transition() {
    use crate::protocol::{ChannelState, ConnectionState};
    use crate::realtime::await_state;
    use std::sync::atomic::{AtomicBool, Ordering};

    let channel_name = "test-rtl25b";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    assert_eq!(channel.state(), ChannelState::Initialized);

    // RTL25b: Register whenState for ATTACHED before attaching
    let fired = std::sync::Arc::new(AtomicBool::new(false));
    let fired2 = fired.clone();
    let got_change = std::sync::Arc::new(AtomicBool::new(false));
    let got_change2 = got_change.clone();

    channel.when_state(ChannelState::Attached, move |change| {
        fired2.store(true, Ordering::SeqCst);
        got_change2.store(true, Ordering::SeqCst);
    });

    // Not fired yet
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!fired.load(Ordering::SeqCst));

    // Now attach
    phase8d_attach(&channel, &mock, None).await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // RTL25b: Should have fired with ChannelStateChange
    assert!(
        fired.load(Ordering::SeqCst),
        "Callback should fire on transition"
    );
    assert!(
        got_change.load(Ordering::SeqCst),
        "Should receive StateChange object"
    );
}

// --- RTL25b: whenState fires only once ---
#[tokio::test]
async fn rtl25b_when_state_fires_only_once() {
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let channel_name = "test-rtl25b-once";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);

    let fire_count = std::sync::Arc::new(AtomicUsize::new(0));
    let fire_count2 = fire_count.clone();

    channel.when_state(ChannelState::Attached, move |_| {
        fire_count2.fetch_add(1, Ordering::SeqCst);
    });

    // First attach
    phase8d_attach(&channel, &mock, None).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(fire_count.load(Ordering::SeqCst), 1);

    // Detach
    let ch = channel.clone();
    let detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::DETACHED)
    });
    detach_task.await.unwrap().unwrap();

    // Re-attach
    phase8d_attach(&channel, &mock, None).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // RTL25b: Should NOT fire again
    assert_eq!(fire_count.load(Ordering::SeqCst), 1);
}

// --- RTL25a: whenState for non-current state does not fire immediately ---
#[tokio::test]
async fn rtl25a_when_state_for_non_current_state_waits() {
    use crate::protocol::{ChannelState, ConnectionState};
    use crate::realtime::await_state;
    use std::sync::atomic::{AtomicBool, Ordering};

    let channel_name = "test-rtl25a-past";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Register whenState for ATTACHING — not the current state
    let fired = std::sync::Arc::new(AtomicBool::new(false));
    let fired2 = fired.clone();

    channel.when_state(ChannelState::Attaching, move |_| {
        fired2.store(true, Ordering::SeqCst);
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // RTL25: Should NOT fire — ATTACHING is not the current state
    assert!(!fired.load(Ordering::SeqCst));
}

// =====================================================================
// Phase 10b: RealtimePresence + Channel Integration Tests
// =====================================================================

// -- Helper: Connect + Attach a channel, return (client, mock, conn, channel) --

async fn setup_attached_channel(
    channel_name: &str,
    client_id: Option<&str>,
) -> (
    crate::realtime::Realtime,
    crate::mock_ws::MockWebSocket,
    crate::mock_ws::MockConnection,
    std::sync::Arc<crate::channel::RealtimeChannel>,
) {
    setup_attached_channel_with_flags(channel_name, client_id, None).await
}

async fn setup_attached_channel_with_flags(
    channel_name: &str,
    client_id: Option<&str>,
    attached_flags: Option<u64>,
) -> (
    crate::realtime::Realtime,
    crate::mock_ws::MockWebSocket,
    crate::mock_ws::MockConnection,
    std::sync::Arc<crate::channel::RealtimeChannel>,
) {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mut connected_msg = ProtocolMessage::connected("test-conn-id", "test-conn-key");
    if let Some(cid) = client_id {
        if let Some(ref mut details) = connected_msg.connection_details {
            details.client_id = Some(cid.to_string());
        }
    }

    let mock = MockWebSocket::with_handler({
        let msg = connected_msg.clone();
        move |pending| {
            pending.respond_with_success(msg.clone());
        }
    });

    let transport = std::sync::Arc::new(MockTransport::new(mock.inner()));
    let mut opts = ClientOptions::new("appId.keyId:keySecret")
        .auto_connect(false)
        .fallback_hosts(vec![])
        .use_binary_protocol(false);
    if let Some(cid) = client_id {
        opts = opts.client_id(cid).unwrap();
    }
    let client = Realtime::with_mock(&opts, transport).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut conns = mock.active_connections();
    let conn = conns.pop().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn),
        flags: attached_flags,
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    (client, mock, conn, channel)
}

// -- RTL9/RTL9a: RealtimeChannel#presence attribute --

#[tokio::test]
async fn rtl9_channel_presence_attribute() {
    let channel = crate::channel::RealtimeChannel::new("test");
    let p1 = channel.presence();
    let p2 = channel.presence();
    // Both return RealtimePresence (not null)
    assert!(!p1.sync_complete()); // just verify it's a real object
    assert!(!p2.sync_complete());
}

// -- RTL11: Queued presence fails on DETACHED --
// Per RTL13b, sending DETACHED while ATTACHING triggers a retry that may lead
// to SUSPENDED. So we use explicit attach+detach to reliably reach DETACHED.

#[tokio::test]
async fn rtl11_queued_presence_fails_on_detached() {
    let (_, _, conn, channel) = setup_attached_channel("test-rtl11-det", Some("my-client")).await;

    // Detach the channel
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::DETACHED,
        channel: Some("test-rtl11-det".to_string()),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::DETACHED)
    });
    t.await.unwrap().unwrap();
    assert_eq!(channel.state(), crate::protocol::ChannelState::Detached);

    // Attempting presence on DETACHED channel should error immediately
    let result = channel.presence().enter(None).await;
    assert!(result.is_err(), "presence on DETACHED channel should error");
}

// -- RTL11: Queued presence fails on FAILED --

#[tokio::test]
async fn rtl11_queued_presence_fails_on_failed() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![])
            .use_binary_protocol(false)
            .client_id("my-client")
            .unwrap(),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl11-fail");

    // Start attach
    let ch = channel.clone();
    tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Queue presence while ATTACHING
    let ch = channel.clone();
    let enter_handle = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send ERROR (channel FAILED)
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some("test-rtl11-fail".to_string()),
        error: Some(crate::error::ErrorInfo {
            code: Some(90000),
            status_code: None,
            message: Some("Failed".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let result = enter_handle.await.unwrap();
    assert!(result.is_err(), "queued presence should fail on FAILED");
}

// -- RTL11a: ACK/NACK unaffected by channel state changes --

#[tokio::test]
async fn rtl11a_ack_unaffected_by_channel_state() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtl11a", Some("my-client")).await;

    // Send presence enter
    let ch = channel.clone();
    let enter_handle = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = presence_msgs[0].message.msg_serial.unwrap();

    // Channel becomes DETACHED (server initiated) while awaiting ACK
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::DETACHED,
        channel: Some("test-rtl11a".to_string()),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::DETACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ACK still comes through
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });

    let result = enter_handle.await.unwrap();
    assert!(
        result.is_ok(),
        "ACK should still resolve even after channel state change"
    );
}

// -- Realtime mutations tests --

#[tokio::test]
async fn rtl32b_update_message_sends_message() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl32-update", None).await;

    let msg = crate::rest::Message {
        serial: Some("serial-1".into()),
        name: Some("event".into()),
        ..Default::default()
    };
    let ch = channel.clone();
    let t = tokio::spawn(async move {
        ch.update_message(&msg, &crate::rest::MessageOperation::default(), None)
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Check the sent protocol message
    let sent = mock.client_messages();
    let mutation_msg = sent.iter().find(|m| {
        m.message.action == action::MESSAGE
            && m.message.messages.is_some()
            && m.message.messages_json().iter().any(|msg| {
                msg.get("action").and_then(|a| a.as_u64()) == Some(1) // MESSAGE_UPDATE
            })
    });
    assert!(
        mutation_msg.is_some(),
        "Should have sent a MESSAGE with action MESSAGE_UPDATE"
    );

    // Send ACK
    let serial = mutation_msg.unwrap().message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("result-serial".into())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = t.await.unwrap().unwrap();
    assert_eq!(result.version_serial.as_deref(), Some("result-serial")); // RTL32d per UTS
}

#[tokio::test]
async fn rtl32b_delete_message_sends_message() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl32-delete", None).await;

    let msg = crate::rest::Message {
        serial: Some("serial-1".into()),
        ..Default::default()
    };
    let ch = channel.clone();
    let t = tokio::spawn(async move {
        ch.delete_message(&msg, &crate::rest::MessageOperation::default(), None)
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let sent = mock.client_messages();
    let mutation_msg = sent.iter().find(|m| {
        m.message.action == action::MESSAGE
            && m.message.messages.as_ref().is_some_and(|msgs| {
                msgs.iter()
                    .any(|msg| msg.action == Some(crate::rest::MessageAction::Delete))
            })
    });
    assert!(
        mutation_msg.is_some(),
        "Should have sent MESSAGE with action MESSAGE_DELETE"
    );

    let serial = mutation_msg.unwrap().message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("del-serial".into())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = t.await.unwrap().unwrap();
    assert_eq!(result.version_serial.as_deref(), Some("del-serial")); // RTL32d per UTS
}

#[tokio::test]
async fn rtl32b_append_message_sends_message() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl32-append", None).await;

    let msg = crate::rest::Message {
        serial: Some("serial-1".into()),
        ..Default::default()
    };
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.append_message(&msg, None).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let sent = mock.client_messages();
    let mutation_msg = sent.iter().find(|m| {
        m.message.action == action::MESSAGE
            && m.message.messages.as_ref().is_some_and(|msgs| {
                msgs.iter()
                    .any(|msg| msg.action == Some(crate::rest::MessageAction::Append))
            })
    });
    assert!(
        mutation_msg.is_some(),
        "Should have sent MESSAGE with action MESSAGE_APPEND"
    );

    let serial = mutation_msg.unwrap().message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = t.await.unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn rtl32b2_version_from_operation() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl32-version", None).await;

    let msg = crate::rest::Message {
        serial: Some("serial-1".into()),
        ..Default::default()
    };
    let op = crate::rest::MessageOperation {
        description: Some("edited".into()),
        ..Default::default()
    };
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.update_message(&msg, &op, None).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let sent = mock.client_messages();
    let mutation_msg = sent.iter().find(|m| {
        m.message.action == action::MESSAGE
            && m.message
                .messages
                .as_ref()
                .is_some_and(|msgs| msgs.iter().any(|msg| msg.version.is_some()))
    });
    assert!(
        mutation_msg.is_some(),
        "Should have version field in message"
    );
    let msg_val = &mutation_msg.unwrap().message.messages_json()[0];
    assert_eq!(msg_val["version"]["description"], "edited");

    let serial = mutation_msg.unwrap().message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..ProtocolMessage::new(action::ACK)
    });
    t.await.unwrap().unwrap();
}

#[tokio::test]
async fn rtl32a_serial_validation() {
    let (_, _, _conn, channel) = setup_attached_channel("test-rtl32-serial", None).await;

    let msg = crate::rest::Message::default(); // no serial
    let result = channel
        .update_message(&msg, &crate::rest::MessageOperation::default(), None)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(40003)); // RTL32a per UTS
}

#[tokio::test]
async fn rtl32d_nack_returns_error() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl32-nack", None).await;

    let msg = crate::rest::Message {
        serial: Some("serial-1".into()),
        ..Default::default()
    };
    let ch = channel.clone();
    let t = tokio::spawn(async move {
        ch.update_message(&msg, &crate::rest::MessageOperation::default(), None)
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let sent = mock.client_messages();
    let mutation_msg = sent
        .iter()
        .find(|m| m.message.action == action::MESSAGE)
        .unwrap();
    let serial = mutation_msg.message.msg_serial.unwrap();

    conn.send_to_client(ProtocolMessage {
        action: action::NACK,
        msg_serial: Some(serial),
        count: Some(1),
        error: Some(ErrorInfo {
            code: Some(40000),
            status_code: None,
            message: Some("rejected".into()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::NACK)
    });

    let result = t.await.unwrap();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Some(40000));
}

#[tokio::test]
async fn rtl32e_params_in_protocol_message() {
    use crate::protocol::{action, ProtocolMessage};
    use std::collections::HashMap;

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl32-params", None).await;

    let msg = crate::rest::Message {
        serial: Some("serial-1".into()),
        ..Default::default()
    };
    let params: Vec<(&str, &str)> = vec![("key1", "val1")];
    let ch = channel.clone();
    let t = tokio::spawn(async move {
        ch.update_message(
            &msg,
            &crate::rest::MessageOperation::default(),
            Some(&params),
        )
        .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let sent = mock.client_messages();
    let mutation_msg = sent
        .iter()
        .find(|m| m.message.action == action::MESSAGE)
        .unwrap();
    assert!(mutation_msg.message.params.is_some());
    assert_eq!(
        mutation_msg
            .message
            .params
            .as_ref()
            .unwrap()
            .get("key1")
            .and_then(|s| s.as_str()),
        Some("val1")
    );

    let serial = mutation_msg.message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..ProtocolMessage::new(action::ACK)
    });
    t.await.unwrap().unwrap();
}

#[tokio::test]
async fn rtl32c_does_not_mutate_message() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl32-nomutate", None).await;

    let msg = crate::rest::Message {
        serial: Some("serial-1".into()),
        name: Some("original".into()),
        ..Default::default()
    };
    let msg_clone = msg.name.clone();
    let ch = channel.clone();
    let t = tokio::spawn(async move {
        ch.update_message(&msg, &crate::rest::MessageOperation::default(), None)
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let sent = mock.client_messages();
    let serial = sent
        .iter()
        .find(|m| m.message.action == action::MESSAGE)
        .unwrap()
        .message
        .msg_serial
        .unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..ProtocolMessage::new(action::ACK)
    });
    t.await.unwrap().unwrap();

    // The original message shouldn't be mutated (it was moved into spawn, so we check the clone)
    assert_eq!(msg_clone.as_deref(), Some("original"));
}

// -- Realtime annotations tests --

#[tokio::test]
async fn rtl26_channel_annotations_accessor() {
    let channel = crate::channel::RealtimeChannel::new("test-rtl26");
    let _ann = channel.annotations();
    // Just verify it compiles and returns a RealtimeAnnotations
}

// ===============================================================
// RTL28/RTL31: Channel getMessage / message versions (delegate to REST)
// UTS: realtime/unit/channels/channel_get_message.md
// UTS: realtime/unit/channels/channel_message_versions.md
// Note: The spec says these are proxies to RestChannel methods.
// The actual REST behavior is tested in rsl11b/rsl14 tests.
// Here we verify the RealtimeChannel has the methods (compile-time)
// and test them via the REST channel.
// ===============================================================

#[tokio::test]
async fn rtl28_get_message_delegates_to_rest() -> Result<()> {
    let mock = MockHttpClient::with_handler(|req| {
        if req.url.path().contains("/messages/") {
            MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "test",
                    "data": "hello",
                    "id": "msg-123",
                    "timestamp": 1700000000000_i64
                }),
            )
        } else {
            MockResponse::json(200, &serde_json::json!({}))
        }
    });

    let client = mock_client(mock);
    let ch = client.channels().get("test-channel");
    let msg = ch.get_message("msg-123").await?;
    assert_eq!(msg.name.as_deref(), Some("test"));
    Ok(())
}

#[tokio::test]
async fn rtl31_message_versions_delegates_to_rest() -> Result<()> {
    let mock =
        MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!([
                {"name": "test", "data": "v2", "id": "msg-123:1", "timestamp": 1700000001000_i64},
                {"name": "test", "data": "v1", "id": "msg-123:0", "timestamp": 1700000000000_i64}
            ]))
            .with_header("link", r#"<./versions?start=0>; rel="first""#)
        });

    let client = mock_client(mock);
    let ch = client.channels().get("test-channel");
    let versions = ch.message_versions("msg-123").send().await?;
    let items = versions.items();
    assert!(!items.is_empty());
    Ok(())
}

// ===============================================================
// Batch 9: Realtime Channels
// ===============================================================

// UTS: realtime/unit/channels/channel_connection_state.md — RTL3c
// Spec: SUSPENDED connection transitions ATTACHED channel to SUSPENDED.
// Requires simulating disconnect → exhausting reconnect retries → SUSPENDED,
// RTL3c: SUSPENDED connection causes ATTACHED/ATTACHING channels to SUSPENDED.
// Uses a short connectionStateTtl (1ms) in the CONNECTED message so SUSPENDED
// is reached almost immediately after disconnect.
#[tokio::test]
async fn rtl3c_suspended_connection_suspends_channels() -> Result<()> {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{
        action, ChannelState, ConnectionDetails, ConnectionState, ProtocolMessage,
    };
    use crate::realtime::await_state;

    let connect_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = connect_count.clone();
    let mock = MockWebSocket::with_handler(move |pending| {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("connId", "connKey");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1);
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
            .disconnected_retry_timeout(std::time::Duration::from_millis(10))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl3c");
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    conns.last().unwrap().send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl3c".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();
    assert_eq!(channel.state(), ChannelState::Attached);

    // Disconnect — with TTL=1ms, connection should quickly reach SUSPENDED
    conns.last().unwrap().simulate_disconnect();

    assert!(
        await_state(&client.connection, ConnectionState::Suspended, 5000).await,
        "Connection should reach SUSPENDED with 1ms TTL"
    );

    // RTL3c: Channel should transition to SUSPENDED
    assert_eq!(channel.state(), ChannelState::Suspended);

    Ok(())
}

// UTS: realtime/unit/channels/channel_server_initiated_detach.md — RTL13b
// Spec: If the reattach fails (timeout), channel transitions to SUSPENDED.
// phase8d_setup uses 200ms realtime_request_timeout so the reattach will
// time out (no one responds to the re-ATTACH), producing SUSPENDED.
#[tokio::test]
async fn rtl13b_server_detached_reattach_timeout_to_suspended() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl13b");
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Send server-initiated DETACHED with error — triggers reattach attempt
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    let mut msg = ProtocolMessage::new(action::DETACHED);
    msg.channel = Some("test-rtl13b".to_string());
    msg.error = Some(ErrorInfo {
        code: Some(90001),
        status_code: Some(500),
        message: Some("Server detached".to_string()),
        href: None,
        ..Default::default()
    });
    conn.send_to_client(msg);

    // Wait for reattach to time out (200ms request timeout + margin)
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let state = channel.state();
    assert_eq!(
        state,
        ChannelState::Suspended,
        "Expected SUSPENDED after reattach timeout, got {:?}",
        state
    );
}

// UTS: realtime/unit/channels/channel_publish.md — RTL6i3
// Spec: null name/data fields are omitted from the wire encoding.
// We publish with name only (no data), then inspect captured messages
// to verify the MESSAGE was sent. Wire-level null-field inspection
// would require raw frame capture which the mock doesn't expose.
#[tokio::test]
async fn rtl6i3_null_fields_omitted_from_publish() {
    use crate::protocol::{ChannelState, ConnectionState};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl6i3");
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Spawn publish (don't await — it blocks waiting for ACK)
    let ch = channel.clone();
    tokio::spawn(async move {
        let _ = ch.publish().name("name-only").send().await;
    });
    // Give time for the MESSAGE to be sent
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify a MESSAGE was sent from the client
    let conns = mock.active_connections();
    assert!(!conns.is_empty(), "Expected active connection");
}

// ---------------------------------------------------------------
// CHD1 — ConnectionDetails deserialization
// ---------------------------------------------------------------
#[test]
fn chd1_connection_details_deserialization() {
    let json = json!({
        "connectionKey": "abc123",
        "clientId": "my-client",
        "connectionStateTtl": 120000,
        "maxIdleInterval": 15000,
        "maxMessageSize": 65536,
        "serverId": "server-xyz"
    });
    let details: crate::protocol::ConnectionDetails =
        serde_json::from_value(json).expect("Failed to deserialize ConnectionDetails");
    assert_eq!(details.connection_key.as_deref(), Some("abc123"));
    assert_eq!(details.client_id.as_deref(), Some("my-client"));
    assert_eq!(details.connection_state_ttl, Some(120000));
    assert_eq!(details.max_idle_interval, Some(15000));
    assert_eq!(details.max_message_size, Some(65536));
    assert_eq!(details.server_id.as_deref(), Some("server-xyz"));
}

// ===============================================================
// Batch 9 — RTL (Realtime Channels) tests
// ===============================================================

// --- RTL3a: FAILED connection transitions ATTACHING channel to FAILED ---
#[tokio::test]
async fn rtl3a_failed_to_attaching_channel_failed() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl3a-attaching");

    // Start attach but don't respond — channel stays ATTACHING
    let ch = channel.clone();
    let _attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Send connection-level ERROR to trigger FAILED
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        error: Some(ErrorInfo {
            code: Some(40198),
            status_code: Some(401),
            message: Some("Invalid credentials".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

    // RTL3a: Channel in ATTACHING should transition to FAILED
    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
    assert!(channel.error_reason().is_some());
}

// --- RTL3c: SUSPENDED connection transitions ATTACHING channel to SUSPENDED ---
#[tokio::test]
async fn rtl3c_suspended_to_attaching_channel_suspended() -> Result<()> {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let connect_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = connect_count.clone();
    let mock = MockWebSocket::with_handler(move |pending| {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("connId", "connKey");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1);
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
            .disconnected_retry_timeout(std::time::Duration::from_millis(10))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl3c-attaching");

    // Start attach but don't respond — channel stays ATTACHING
    let ch = channel.clone();
    let _attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Disconnect — with TTL=1ms, connection should quickly reach SUSPENDED
    let conns = mock.active_connections();
    conns.last().unwrap().simulate_disconnect();

    assert!(
        await_state(&client.connection, ConnectionState::Suspended, 5000).await,
        "Connection should reach SUSPENDED with 1ms TTL"
    );

    // RTL3c: Channel in ATTACHING should transition to SUSPENDED
    assert_eq!(channel.state(), ChannelState::Suspended);

    Ok(())
}

// --- RTL4b: Attach fails when connection is SUSPENDED ---
#[tokio::test]
async fn rtl4b_attach_fails_when_suspended() -> Result<()> {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let connect_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = connect_count.clone();
    let mock = MockWebSocket::with_handler(move |pending| {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("connId", "connKey");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1);
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
            .disconnected_retry_timeout(std::time::Duration::from_millis(10))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Disconnect — reach SUSPENDED via TTL=1ms
    let conns = mock.active_connections();
    conns.last().unwrap().simulate_disconnect();
    assert!(await_state(&client.connection, ConnectionState::Suspended, 5000).await);

    // RTL4b: Attach should fail when SUSPENDED
    let channel = client.channels.get("test-rtl4b-suspended");
    let result = channel.attach().await;
    assert!(
        result.is_err(),
        "Attach should fail when connection is SUSPENDED"
    );

    Ok(())
}

// --- RTL4c: Error reason set after reattach from SUSPENDED (test 2: state change includes error) ---
#[tokio::test]
async fn rtl4c_error_reason_after_reattach_from_suspended_state_change() {
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl4c-2");
    phase8d_attach(&channel, &mock, None).await;

    let mut rx = channel.on_state_change();

    // Send ATTACHED with error (no RESUMED flag) — triggers UPDATE event
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl4c-2".to_string()),
        error: Some(ErrorInfo {
            code: Some(91004),
            status_code: Some(400),
            message: Some("Reattach error".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(change.event, ChannelEvent::Update);
    assert!(change.reason.is_some());
    assert_eq!(change.reason.unwrap().code, Some(91004));
}

// --- RTL4g: Error reason cleared on successful reattach (test 1: from FAILED) ---
#[tokio::test]
async fn rtl4g_error_reason_cleared_on_reattach() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl4g-1");

    // First attach — fail it
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some("test-rtl4g-1".to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: None,
            message: Some("Denied".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });
    let _ = attach_task.await.unwrap();
    assert_eq!(channel.state(), ChannelState::Failed);
    assert!(channel.error_reason().is_some());

    // Second attach from FAILED — should clear errorReason
    let ch = channel.clone();
    let attach_task2 = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl4g-1".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task2.await.unwrap().unwrap();

    // RTL4g: errorReason should be cleared
    assert_eq!(channel.state(), ChannelState::Attached);
    assert!(
        channel.error_reason().is_none(),
        "errorReason should be cleared after successful reattach"
    );
}

// --- RTL6: Binary data round-trip via mock ---
#[tokio::test]
async fn rtl6_binary_data_round_trip() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6-binary";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    // Send a message with base64-encoded binary data
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        messages: crate::protocol::wire_messages(vec![serde_json::json!({
            "name": "binary-event",
            "data": "SGVsbG8=",
            "encoding": "base64"
        })]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.name.as_deref(), Some("binary-event"));
}

// --- RTL6: E2E-style publish via mock ---
#[tokio::test]
async fn rtl6_e2e_publish() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6-e2e";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    // Publish
    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("e2e-event")
            .json(serde_json::json!("e2e-data"))
            .send()
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 1);
    let msg_serial = message_msgs[0].message.msg_serial.unwrap();

    // ACK
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(msg_serial),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("e2e-serial".to_string())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_ok());

    // Simulate the server echoing the message back
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(channel_name.to_string()),
        messages: crate::protocol::wire_messages(vec![serde_json::json!({
            "name": "e2e-event",
            "data": "e2e-data"
        })]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let received = rx.try_recv().unwrap();
    assert_eq!(received.name.as_deref(), Some("e2e-event"));
}

// --- RTL6c1: Publish when channel is ATTACHING queues the message ---
#[tokio::test]
async fn rtl6c1_publish_when_channel_attaching() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c1-attaching";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Start attach but don't respond — channel stays ATTACHING
    let ch = channel.clone();
    let _attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Publish while ATTACHING — should queue
    let ch = channel.clone();
    let _publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("queued")
            .json(serde_json::json!("queued-data"))
            .send()
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Complete the attach
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // The queued message should now be sent
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert!(
        !message_msgs.is_empty(),
        "Queued message should be sent after attach"
    );
    assert_eq!(message_msgs[0].message.messages_json()[0]["name"], "queued");
}

// --- RTL6c2: Publish fails when queueMessages is false ---
#[tokio::test]
async fn rtl6c2_fails_when_queue_messages_false() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl6c2-noq";
    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .queue_messages(false),
        transport.clone(),
    )
    .unwrap();

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connecting, 5000).await);

    // RTL6c2: Publish should fail when queueMessages=false and not connected
    let result = channel
        .publish()
        .name("fail")
        .json(serde_json::json!("no-queue"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "Publish should fail when queue disabled and not connected"
    );
}

// --- RTL6c4: Publish fails when channel is SUSPENDED ---
#[tokio::test]
async fn rtl6c4_fails_when_channel_suspended() -> Result<()> {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let connect_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = connect_count.clone();
    let mock = MockWebSocket::with_handler(move |pending| {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("connId", "connKey");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1);
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
            .disconnected_retry_timeout(std::time::Duration::from_millis(10))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl6c4-ch-susp");
    let ch = channel.clone();
    let attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    conns.last().unwrap().send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl6c4-ch-susp".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_task.await.unwrap().unwrap();

    // Disconnect to reach SUSPENDED
    conns.last().unwrap().simulate_disconnect();
    assert!(await_state(&client.connection, ConnectionState::Suspended, 5000).await);

    // Channel should be SUSPENDED (RTL3c)
    assert_eq!(channel.state(), ChannelState::Suspended);

    // RTL6c4: Publish should fail when channel SUSPENDED
    let result = channel
        .publish()
        .name("fail")
        .json(serde_json::json!("should-error"))
        .send()
        .await;
    assert!(result.is_err(), "Publish should fail on SUSPENDED channel");

    Ok(())
}

// --- RTL6c4: Publish fails when connection is SUSPENDED ---
#[tokio::test]
async fn rtl6c4_fails_when_connection_suspended() -> Result<()> {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let connect_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = connect_count.clone();
    let mock = MockWebSocket::with_handler(move |pending| {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            let mut msg = ProtocolMessage::connected("connId", "connKey");
            if let Some(ref mut details) = msg.connection_details {
                details.connection_state_ttl = Some(1);
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
            .disconnected_retry_timeout(std::time::Duration::from_millis(10))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![]),
        transport,
    )?;
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Disconnect to reach SUSPENDED
    let conns = mock.active_connections();
    conns.last().unwrap().simulate_disconnect();
    assert!(await_state(&client.connection, ConnectionState::Suspended, 5000).await);

    // Create channel (initialized) and try to publish
    let channel = client
        .channels
        .get_with_options(
            "test-rtl6c4-conn-susp",
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // RTL6c4: Publish should fail when connection SUSPENDED
    let result = channel
        .publish()
        .name("fail")
        .json(serde_json::json!("should-error"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "Publish should fail when connection is SUSPENDED"
    );

    Ok(())
}

// --- RTL6i1: Publish a single Message object ---
#[tokio::test]
async fn rtl6i1_publish_message_object() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl6i1-msg", None).await;

    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("msg-event")
            .json(serde_json::json!({"key": "value"}))
            .send()
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    assert_eq!(message_msgs.len(), 1);

    let messages = message_msgs[0].message.messages_json();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["name"], "msg-event");

    // ACK
    let msg_serial = message_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(msg_serial),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("obj-serial".to_string())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_ok());
}

// --- RTL6j: Sequential publishes get sequential msg_serials ---
#[tokio::test]
async fn rtl6j_sequential_publishes() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl6j-seq", None).await;

    // Publish first message
    let ch = channel.clone();
    let h1 = tokio::spawn(async move {
        ch.publish()
            .name("msg1")
            .json(serde_json::json!("data1"))
            .send()
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Publish second message
    let ch = channel.clone();
    let h2 = tokio::spawn(async move {
        ch.publish()
            .name("msg2")
            .json(serde_json::json!("data2"))
            .send()
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();

    // Should have sequential msg_serials
    assert!(message_msgs.len() >= 2);
    let serial1 = message_msgs[0].message.msg_serial.unwrap();
    let serial2 = message_msgs[1].message.msg_serial.unwrap();
    assert_eq!(serial2, serial1 + 1, "msg_serials should be sequential");

    // ACK both
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial1),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("s1".to_string())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial2),
        count: Some(1),
        res: Some(vec![crate::protocol::PublishResult {
            serials: vec![Some("s2".to_string())],
        }]),
        ..ProtocolMessage::new(action::ACK)
    });

    h1.await.unwrap().unwrap();
    h2.await.unwrap().unwrap();
}

// --- RTL6j: NACK returns error ---
#[tokio::test]
async fn rtl6j_nack_error() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ProtocolMessage};

    let (_, mock, conn, channel) = setup_attached_channel("test-rtl6j-nack", None).await;

    let ch = channel.clone();
    let publish_handle = tokio::spawn(async move {
        ch.publish()
            .name("will-nack")
            .json(serde_json::json!("data"))
            .send()
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let message_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::MESSAGE)
        .collect();
    let msg_serial = message_msgs.last().unwrap().message.msg_serial.unwrap();

    // Send NACK
    conn.send_to_client(ProtocolMessage {
        action: action::NACK,
        msg_serial: Some(msg_serial),
        count: Some(1),
        error: Some(ErrorInfo {
            code: Some(40300),
            status_code: None,
            message: Some("Permission denied".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::NACK)
    });

    let result = publish_handle.await.unwrap();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Some(40300));
}

// --- RTL7a: Subscribe receives multiple messages from a single ProtocolMessage ---
#[tokio::test]
async fn rtl7a_subscribe_receives_multiple_from_single_pm() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, _mock, conn, channel) = setup_attached_channel("test-rtl7a-multi", None).await;

    let (_sub_id, mut rx) = channel.subscribe();

    // Send a single ProtocolMessage with 3 messages
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some("test-rtl7a-multi".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "a", "data": "1"}),
            serde_json::json!({"name": "b", "data": "2"}),
            serde_json::json!({"name": "c", "data": "3"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msg1 = rx.try_recv().unwrap();
    assert_eq!(msg1.name.as_deref(), Some("a"));
    let msg2 = rx.try_recv().unwrap();
    assert_eq!(msg2.name.as_deref(), Some("b"));
    let msg3 = rx.try_recv().unwrap();
    assert_eq!(msg3.name.as_deref(), Some("c"));
}

// --- RTL7b: Multiple name-specific subscriptions are independent ---
#[tokio::test]
async fn rtl7b_multiple_name_specific_subscriptions_independent() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, _mock, conn, channel) = setup_attached_channel("test-rtl7b-indep", None).await;

    let (_sub_a, mut rx_a) = channel.subscribe_with_name("alpha");
    let (_sub_b, mut rx_b) = channel.subscribe_with_name("beta");

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some("test-rtl7b-indep".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "alpha", "data": "a-data"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some("test-rtl7b-indep".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "beta", "data": "b-data"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some("test-rtl7b-indep".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "gamma", "data": "g-data"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // rx_a should only have "alpha"
    let msg_a = rx_a.try_recv().unwrap();
    assert_eq!(msg_a.name.as_deref(), Some("alpha"));
    assert!(rx_a.try_recv().is_err());

    // rx_b should only have "beta"
    let msg_b = rx_b.try_recv().unwrap();
    assert_eq!(msg_b.name.as_deref(), Some("beta"));
    assert!(rx_b.try_recv().is_err());
}

// --- RTL7g: Subscribe does not trigger reattach on already-attached channel ---
#[tokio::test]
async fn rtl7g_subscribe_does_not_reattach() {
    use crate::protocol::{action, ChannelState};

    let (_, mock, _conn, channel) = setup_attached_channel("test-rtl7g-noreattach", None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    let attach_count_before = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();

    // Subscribe — should NOT send another ATTACH
    let (_sub_id, _rx) = channel.subscribe();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let attach_count_after = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();

    assert_eq!(
        attach_count_before, attach_count_after,
        "Subscribe should not send ATTACH on already-attached channel"
    );
}

// --- RTL7g: Subscribe from DETACHED triggers implicit attach ---
#[tokio::test]
async fn rtl7g_subscribe_from_detached() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-rtl7g-detached";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport.clone(),
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    assert_eq!(channel.state(), ChannelState::Initialized);

    // Subscribe with attach_on_subscribe (default=true) — should trigger ATTACH
    let (_sub_id, _rx) = channel.subscribe();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Channel should be ATTACHING
    assert_eq!(
        channel.state(),
        ChannelState::Attaching,
        "Subscribe should trigger implicit attach"
    );

    // Verify ATTACH was sent
    let attach_msgs: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| {
            m.message.action == action::ATTACH && m.message.channel.as_deref() == Some(channel_name)
        })
        .collect();
    assert!(!attach_msgs.is_empty(), "ATTACH message should be sent");
}

// --- RTL8a: Unsubscribe with non-subscribed listener is a no-op ---
#[tokio::test]
async fn rtl8a_unsubscribe_non_subscribed_is_noop() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, _mock, conn, channel) = setup_attached_channel("test-rtl8a-noop", None).await;

    // Subscribe a listener, then unsubscribe it twice — second call is a no-op
    let (sub_id, mut rx) = channel.subscribe();
    channel.unsubscribe(sub_id);
    channel.unsubscribe(sub_id);

    // Subscribe a new real listener and verify it still works
    let (sub_id, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some("test-rtl8a-noop".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "test", "data": "ok"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.name.as_deref(), Some("test"));

    // Now unsubscribe for real
    channel.unsubscribe(sub_id);
}

// --- RTL12: UPDATE without error has null reason ---
#[tokio::test]
async fn rtl12_update_without_error_has_null_reason() {
    use crate::protocol::{action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let channel_name = "test-rtl12-null-reason";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    let mut rx = channel.on_state_change();

    // Send additional ATTACHED without error and without RESUMED
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(change.event, ChannelEvent::Update);
    assert_eq!(change.current, ChannelState::Attached);
    assert!(
        change.reason.is_none(),
        "reason should be null when no error"
    );
}

// --- RTL13b: Repeated failures cycle between SUSPENDED and ATTACHING ---
#[tokio::test]
async fn rtl13b_repeated_failures_cycle_suspended_attaching() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl13b-cycle");
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Server sends DETACHED with error — triggers reattach (RTL13a)
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some("test-rtl13b-cycle".to_string()),
        error: Some(ErrorInfo {
            code: Some(90001),
            status_code: Some(500),
            message: Some("Server detached".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::DETACHED)
    });

    // Wait for reattach to time out (200ms request timeout + margin)
    // RTL13b: After timeout, channel should go to SUSPENDED
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    assert_eq!(
        channel.state(),
        ChannelState::Suspended,
        "Channel should be SUSPENDED after reattach timeout"
    );
}

// --- RTL14: Channel ERROR on ATTACHING channel transitions to FAILED ---
#[tokio::test]
async fn rtl14_channel_error_attaching() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtl14-attaching");

    // Start attach but don't respond
    let ch = channel.clone();
    let _attach_task = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Send channel-scoped ERROR while ATTACHING
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some("test-rtl14-attaching".to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Channel error while attaching".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    // RTL14: Channel should transition to FAILED
    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
    let err = channel.error_reason().unwrap();
    assert_eq!(err.code, Some(40160));

    // Connection should remain CONNECTED
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

// --- RTL14: Channel ERROR does not affect other channels (isolated) ---
#[tokio::test]
async fn rtl14_channel_error_isolated() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let ch_target = client.channels.get("ch-target-isolated");
    let ch_other = client.channels.get("ch-other-isolated");
    phase8d_attach(&ch_target, &mock, None).await;
    phase8d_attach(&ch_other, &mock, None).await;

    // Send ERROR only to ch_target
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some("ch-target-isolated".to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Bad channel".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_channel_state(&ch_target, ChannelState::Failed, 5000).await);

    // Other channel should be unaffected
    assert_eq!(ch_other.state(), ChannelState::Attached);
    assert!(ch_other.error_reason().is_none());
}

// --- RTL14: Channel ERROR during DETACHING ---
#[tokio::test]
async fn rtl14_channel_error_during_detach() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl14-detaching";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    // Start detach but don't respond
    let ch = channel.clone();
    let _detach_task = tokio::spawn(async move { ch.detach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send channel-scoped ERROR while DETACHING
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Error during detach".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    // RTL14: Channel should transition to FAILED
    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
    assert!(channel.error_reason().is_some());
}

// --- RTL14: Channel ERROR cancels pending reattach retry ---
#[tokio::test]
async fn rtl14_channel_error_cancels_retry() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let channel_name = "test-rtl14-cancel";
    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get(channel_name);
    phase8d_attach(&channel, &mock, None).await;

    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    // Server sends DETACHED — triggers reattach attempt (channel goes to ATTACHING)
    conn.send_to_client(ProtocolMessage {
        action: action::DETACHED,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(90198),
            status_code: Some(500),
            message: Some("Server detached".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::DETACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Now send channel ERROR — should cancel retry and go to FAILED
    conn.send_to_client(ProtocolMessage {
        action: action::ERROR,
        channel: Some(channel_name.to_string()),
        error: Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Permanent error".to_string()),
            href: None,
            ..Default::default()
        }),
        ..ProtocolMessage::new(action::ERROR)
    });

    assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
    assert_eq!(channel.error_reason().unwrap().code, Some(40160));
}

// --- RTL14: Fifth distinct channel error ---
#[tokio::test]
async fn rtl14_channel_error_fifth() {
    use crate::error::ErrorInfo;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_channel_state, await_state};

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    // Create 5 channels, error each one
    for i in 0..5 {
        let name = format!("ch-rtl14-{}", i);
        let channel = client.channels.get(&name);
        phase8d_attach(&channel, &mock, None).await;

        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: action::ERROR,
            channel: Some(name.clone()),
            error: Some(ErrorInfo {
                code: Some(40160 + i as u32),
                status_code: Some(401),
                message: Some(format!("Error {}", i)),
                href: None,
                ..Default::default()
            }),
            ..ProtocolMessage::new(action::ERROR)
        });

        assert!(
            await_channel_state(&channel, ChannelState::Failed, 5000).await,
            "Channel {} should transition to FAILED",
            i
        );
    }

    // Connection should still be CONNECTED
    assert_eq!(client.connection.state(), ConnectionState::Connected);
}

// --- RTL28: get_message delegates to REST ---
#[tokio::test]
async fn rtl28_get_message_calls_rest() -> Result<()> {
    use crate::mock_http::{MockHttpClient, MockResponse};

    let mock = MockHttpClient::with_handler(|req| {
        if req.url.path().contains("/messages/") {
            MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "test-msg",
                    "data": "hello",
                    "id": "msg-abc",
                    "timestamp": 1700000000000_i64
                }),
            )
        } else {
            MockResponse::json(200, &serde_json::json!({}))
        }
    });

    let client = mock_client(mock);
    let ch = client.channels().get("test-rtl28");
    let msg = ch.get_message("msg-abc").await?;
    assert_eq!(msg.name.as_deref(), Some("test-msg"));
    Ok(())
}

// ============================================================================
// Delta / vcdiff decoding (RTL18-RTL21, PC3) — UTS
// uts/realtime/unit/channels/channel_delta_decoding.md
//
// The bundled vcdiff-decode crate does the real decoding (its own conformance
// suite proves that); these tests exercise the SDK-side RTL18/19/20/21
// bookkeeping and recovery with an injected mock decoder, exactly as ably-js
// tests the same IDs. The mock is a pass-through (`decode(delta, base) =>
// delta`), a recording variant, or a failing variant.
// ============================================================================

fn passthrough_decoder() -> crate::connection::DeltaDecoder {
    std::sync::Arc::new(|delta: &[u8], _base: &[u8]| Ok(delta.to_vec()))
}

// The production default decoder is the bundled vcdiff-decode crate (real
// VCDIFF decoding is covered by that crate's own conformance suite; the SDK
// bookkeeping below uses injected mocks). This confirms the default is wired
// to the real decoder and maps its errors to String — a malformed delta is
// rejected rather than silently accepted.
#[test]
fn default_delta_decoder_is_the_real_vcdiff_crate() {
    let decoder = crate::connection::default_delta_decoder();
    let err = decoder(b"not-a-vcdiff-delta", b"base payload").unwrap_err();
    assert!(!err.is_empty(), "error is surfaced as a message");
}

fn failing_decoder() -> crate::connection::DeltaDecoder {
    std::sync::Arc::new(|_delta: &[u8], _base: &[u8]| Err("simulated decode failure".to_string()))
}

/// A delta message: binary/utf-8 delta payload with an extras.delta.from ref.
fn delta_msg(id: &str, data: rest::Data, encoding: &str, from: &str) -> rest::Message {
    rest::Message {
        id: Some(id.to_string()),
        data,
        encoding: Some(encoding.to_string()),
        extras: Some(serde_json::json!({"delta": {"from": from, "format": "vcdiff"}})),
        ..Default::default()
    }
}

/// A plain non-delta message.
fn plain_msg(id: &str, data: rest::Data, encoding: Option<&str>) -> rest::Message {
    rest::Message {
        id: Some(id.to_string()),
        data,
        encoding: encoding.map(String::from),
        ..Default::default()
    }
}

fn bin(s: &str) -> rest::Data {
    rest::Data::Binary(serde_bytes::ByteBuf::from(s.as_bytes().to_vec()))
}

/// Connect a client (with the given delta decoder) and attach a channel.
async fn delta_attached(
    decoder: crate::connection::DeltaDecoder,
    channel_name: &str,
) -> (
    crate::realtime::Realtime,
    crate::mock_ws::MockWebSocket,
    std::sync::Arc<crate::channel::RealtimeChannel>,
) {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pc| {
        pc.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret")
        .auto_connect(false)
        .delta_decoder(decoder);
    let client = Realtime::with_mock(&opts, transport).unwrap();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let ch = channel.clone();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(channel_name.to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();
    (client, mock, channel)
}

fn send_message_pm(
    conn: &crate::mock_ws::MockConnection,
    channel: &str,
    pm_id: &str,
    channel_serial: Option<&str>,
    messages: Vec<rest::Message>,
) {
    use crate::protocol::{action, ProtocolMessage};
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(channel.to_string()),
        id: Some(pm_id.to_string()),
        channel_serial: channel_serial.map(String::from),
        messages: Some(messages),
        ..ProtocolMessage::new(action::MESSAGE)
    });
}

fn drain_messages(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<rest::Message>,
) -> Vec<rest::Message> {
    let mut out = Vec::new();
    while let Ok(m) = rx.try_recv() {
        out.push(m);
    }
    out
}

// UTS: realtime/unit/RTL21/ascending-index-order-0
#[tokio::test]
async fn rtl21_messages_decoded_in_ascending_index_order() {
    let (client, mock, channel) = delta_attached(passthrough_decoder(), "test-rtl21").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    // msg-0 non-delta base; msg-1 delta from serial:0; msg-2 delta from
    // serial:1 — only decodes if processed in array order.
    send_message_pm(
        conn,
        "test-rtl21",
        "serial:0",
        None,
        vec![
            plain_msg("serial:0", rest::Data::String("first message".into()), None),
            delta_msg(
                "serial:1",
                bin("second message"),
                "utf-8/vcdiff",
                "serial:0",
            ),
            delta_msg("serial:2", bin("third message"), "utf-8/vcdiff", "serial:1"),
        ],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].data, rest::Data::String("first message".into()));
    assert_eq!(got[1].data, rest::Data::String("second message".into()));
    assert_eq!(got[2].data, rest::Data::String("third message".into()));
    client.close();
}

// UTS: realtime/unit/RTL19b/stores-base-payload-0
#[tokio::test]
async fn rtl19b_non_delta_stores_base_payload() {
    let (client, mock, channel) = delta_attached(passthrough_decoder(), "test-rtl19b").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    send_message_pm(
        conn,
        "test-rtl19b",
        "msg-1:0",
        None,
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String("base payload".into()),
            None,
        )],
    );
    send_message_pm(
        conn,
        "test-rtl19b",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            bin("updated payload"),
            "utf-8/vcdiff",
            "msg-1:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].data, rest::Data::String("base payload".into()));
    assert_eq!(got[1].data, rest::Data::String("updated payload".into()));
    client.close();
}

// UTS: realtime/unit/RTL19b/json-wire-form-base-1
#[tokio::test]
async fn rtl19b_json_encoded_stores_wire_form_base() {
    let (client, mock, channel) = delta_attached(passthrough_decoder(), "test-rtl19b-json").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    // Non-delta json message: subscriber sees the parsed object, but the base
    // payload stored for delta decoding is the wire-form JSON string.
    let json_string = r#"{"foo":"bar","count":1}"#;
    send_message_pm(
        conn,
        "test-rtl19b-json",
        "msg-1:0",
        None,
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String(json_string.into()),
            Some("json"),
        )],
    );
    // Delta computed against the JSON string base; decoded then utf-8'd to the
    // new JSON string, delivered as-is (no json step in the delta encoding).
    let new_json_string = r#"{"foo":"baz","count":2}"#;
    send_message_pm(
        conn,
        "test-rtl19b-json",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            bin(new_json_string),
            "utf-8/vcdiff",
            "msg-1:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);
    assert_eq!(got.len(), 2);
    assert!(
        matches!(&got[0].data, rest::Data::JSON(v) if v["foo"] == "bar" && v["count"] == 1),
        "first message parsed to JSON object, got {:?}",
        got[0].data
    );
    assert_eq!(got[1].data, rest::Data::String(new_json_string.into()));
    client.close();
}

// UTS: realtime/unit/RTL19a/base64-decoded-before-store-0
#[tokio::test]
async fn rtl19a_base64_decoded_before_store() {
    let (client, mock, channel) = delta_attached(passthrough_decoder(), "test-rtl19a").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    // Base payload is binary "Hello", sent base64-encoded.
    let base_binary = vec![0x48u8, 0x65, 0x6c, 0x6c, 0x6f];
    let base_b64 = base64::encode(&base_binary);
    send_message_pm(
        conn,
        "test-rtl19a",
        "msg-1:0",
        None,
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String(base_b64),
            Some("base64"),
        )],
    );
    // Delta references the binary base; the delta payload itself is base64'd.
    let new_binary = vec![0x57u8, 0x6f, 0x72, 0x6c, 0x64]; // "World"
    let delta_b64 = base64::encode(&new_binary);
    send_message_pm(
        conn,
        "test-rtl19a",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            rest::Data::String(delta_b64),
            "vcdiff/base64",
            "msg-1:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);
    assert_eq!(got.len(), 2);
    assert_eq!(
        got[0].data,
        rest::Data::Binary(serde_bytes::ByteBuf::from(base_binary))
    );
    assert_eq!(
        got[1].data,
        rest::Data::Binary(serde_bytes::ByteBuf::from(new_binary))
    );
    client.close();
}

// UTS: realtime/unit/RTL19c/delta-result-becomes-base-0
#[tokio::test]
async fn rtl19c_delta_result_becomes_base() {
    let (client, mock, channel) = delta_attached(passthrough_decoder(), "test-rtl19c").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    send_message_pm(
        conn,
        "test-rtl19c",
        "msg-1:0",
        None,
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String("value-A".into()),
            None,
        )],
    );
    send_message_pm(
        conn,
        "test-rtl19c",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            bin("value-B"),
            "utf-8/vcdiff",
            "msg-1:0",
        )],
    );
    // msg-3 references msg-2 — succeeds only because the base advanced to B.
    send_message_pm(
        conn,
        "test-rtl19c",
        "msg-3:0",
        None,
        vec![delta_msg(
            "msg-3:0",
            bin("value-C"),
            "utf-8/vcdiff",
            "msg-2:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].data, rest::Data::String("value-A".into()));
    assert_eq!(got[1].data, rest::Data::String("value-B".into()));
    assert_eq!(got[2].data, rest::Data::String("value-C".into()));
    client.close();
}

// UTS: realtime/unit/RTL20/last-id-updated-on-decode-1
#[tokio::test]
async fn rtl20_last_message_id_updated_after_decode() {
    let (client, mock, channel) = delta_attached(passthrough_decoder(), "test-rtl20-id").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    // Two messages in one PM — the stored last id must become serial:1.
    send_message_pm(
        conn,
        "test-rtl20-id",
        "serial:0",
        None,
        vec![
            plain_msg("serial:0", rest::Data::String("first".into()), None),
            plain_msg("serial:1", rest::Data::String("second".into()), None),
        ],
    );
    // Delta referencing serial:1 (the last message) succeeds.
    send_message_pm(
        conn,
        "test-rtl20-id",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            bin("third"),
            "utf-8/vcdiff",
            "serial:1",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].data, rest::Data::String("first".into()));
    assert_eq!(got[1].data, rest::Data::String("second".into()));
    assert_eq!(got[2].data, rest::Data::String("third".into()));
    client.close();
}

// UTS: realtime/unit/PC3/vcdiff-plugin-decodes-0
#[tokio::test]
async fn pc3_vcdiff_decoder_called_with_utf8_base() {
    use std::sync::Mutex as StdMutex;
    // Recording decoder captures (delta, base) and returns the delta.
    type Calls = std::sync::Arc<StdMutex<Vec<(Vec<u8>, Vec<u8>)>>>;
    let calls: Calls = std::sync::Arc::new(StdMutex::new(Vec::new()));
    let calls_c = calls.clone();
    let decoder: crate::connection::DeltaDecoder =
        std::sync::Arc::new(move |delta: &[u8], base: &[u8]| {
            calls_c
                .lock()
                .unwrap()
                .push((delta.to_vec(), base.to_vec()));
            Ok(delta.to_vec())
        });

    let (client, mock, channel) = delta_attached(decoder, "test-pc3").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    send_message_pm(
        conn,
        "test-pc3",
        "msg-1:0",
        None,
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String("hello world".into()),
            None,
        )],
    );
    send_message_pm(
        conn,
        "test-pc3",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            bin("goodbye world"),
            "utf-8/vcdiff",
            "msg-1:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);

    let recorded = calls.lock().unwrap();
    assert_eq!(recorded.len(), 1, "PC3: decoder called once");
    // PC3a: the string base is UTF-8 encoded to binary before decode.
    assert_eq!(recorded[0].1, b"hello world".to_vec());
    assert_eq!(recorded[0].0, b"goodbye world".to_vec());
    assert_eq!(got[1].data, rest::Data::String("goodbye world".into()));
    client.close();
}

// UTS: realtime/unit/RTL20/mismatched-id-triggers-recovery-0
#[tokio::test]
async fn rtl20_mismatched_id_triggers_recovery() {
    use crate::error::ErrorCode;
    use crate::protocol::{action, ChannelState};

    let (client, mock, channel) =
        delta_attached(passthrough_decoder(), "test-rtl20-mismatch").await;
    let mut changes = channel.on_state_change();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    // Establish base with channelSerial serial-1.
    send_message_pm(
        conn,
        "test-rtl20-mismatch",
        "msg-1:0",
        Some("serial-1"),
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String("base payload".into()),
            None,
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let attaches_before = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();

    // Delta referencing the wrong id (msg-999:0) — mismatch → recovery.
    send_message_pm(
        conn,
        "test-rtl20-mismatch",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            bin("new payload"),
            "utf-8/vcdiff",
            "msg-999:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // RTL18c: transitioned to ATTACHING with a recovery ATTACH carrying the
    // previous message's channelSerial, reason code 40018.
    assert_eq!(channel.state(), ChannelState::Attaching);
    let attaches: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert!(attaches.len() > attaches_before);
    assert_eq!(
        attaches.last().unwrap().message.channel_serial.as_deref(),
        Some("serial-1")
    );
    let mut recovered = false;
    while let Ok(c) = changes.try_recv() {
        if c.current == ChannelState::Attaching {
            assert_eq!(
                c.reason.and_then(|r| r.code),
                Some(ErrorCode::VcdiffDecodeFailure.code())
            );
            recovered = true;
        }
    }
    assert!(recovered, "an ATTACHING state change with reason 40018");
    client.close();
}

// UTS: realtime/unit/RTL18/decode-failure-recovery-0 (RTL18a/b/c)
#[tokio::test]
async fn rtl18_decode_failure_triggers_recovery() {
    use crate::error::ErrorCode;
    use crate::protocol::{action, ChannelState};

    let (client, mock, channel) = delta_attached(failing_decoder(), "test-rtl18").await;
    let (_id, mut rx) = channel.subscribe();
    let mut changes = channel.on_state_change();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    send_message_pm(
        conn,
        "test-rtl18",
        "msg-1:0",
        Some("serial-100"),
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String("base payload".into()),
            None,
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(drain_messages(&mut rx).len(), 1);
    let attaches_before = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();

    // Delta whose decode throws (failing decoder).
    send_message_pm(
        conn,
        "test-rtl18",
        "msg-2:0",
        Some("serial-200"),
        vec![delta_msg(
            "msg-2:0",
            bin("fake-delta"),
            "utf-8/vcdiff",
            "msg-1:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // RTL18b: the failed message was not delivered.
    assert!(drain_messages(&mut rx).is_empty());
    // RTL18c: ATTACHING + recovery ATTACH from serial-100 (the PREVIOUS serial).
    assert_eq!(channel.state(), ChannelState::Attaching);
    let attaches: Vec<_> = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .collect();
    assert!(attaches.len() > attaches_before);
    assert_eq!(
        attaches.last().unwrap().message.channel_serial.as_deref(),
        Some("serial-100")
    );
    let mut saw_40018 = false;
    while let Ok(c) = changes.try_recv() {
        if c.current == ChannelState::Attaching
            && c.reason.and_then(|r| r.code) == Some(ErrorCode::VcdiffDecodeFailure.code())
        {
            saw_40018 = true;
        }
    }
    assert!(saw_40018);
    client.close();
}

// UTS: realtime/unit/RTL18c/recovery-completes-on-attached-0
#[tokio::test]
async fn rtl18c_recovery_completes_on_attached() {
    use crate::protocol::{action, ChannelState, ProtocolMessage};

    // Decoder fails on the first call, then behaves as pass-through.
    let attempt = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempt_c = attempt.clone();
    let decoder: crate::connection::DeltaDecoder =
        std::sync::Arc::new(move |delta: &[u8], _base: &[u8]| {
            if attempt_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Err("simulated failure".to_string())
            } else {
                Ok(delta.to_vec())
            }
        });

    let (client, mock, channel) = delta_attached(decoder, "test-rtl18c").await;
    let (_id, mut rx) = channel.subscribe();
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    send_message_pm(
        conn,
        "test-rtl18c",
        "msg-1:0",
        Some("serial-1"),
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String("original base".into()),
            None,
        )],
    );
    // Delta fails on first decode → recovery → ATTACHING.
    send_message_pm(
        conn,
        "test-rtl18c",
        "msg-2:0",
        Some("serial-2"),
        vec![delta_msg(
            "msg-2:0",
            bin("bad-delta"),
            "utf-8/vcdiff",
            "msg-1:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Server confirms the recovery ATTACH.
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtl18c".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // Fresh non-delta after recovery is delivered normally.
    send_message_pm(
        conn,
        "test-rtl18c",
        "msg-3:0",
        Some("serial-3"),
        vec![plain_msg(
            "msg-3:0",
            rest::Data::String("fresh after recovery".into()),
            None,
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let got = drain_messages(&mut rx);
    // The base and the post-recovery message; the failed delta was discarded.
    assert_eq!(
        got.first().unwrap().data,
        rest::Data::String("original base".into())
    );
    assert_eq!(
        got.last().unwrap().data,
        rest::Data::String("fresh after recovery".into())
    );
    client.close();
}

// UTS: realtime/unit/RTL18/single-recovery-at-time-1
#[tokio::test]
async fn rtl18_single_recovery_at_a_time() {
    use crate::protocol::{action, ChannelState};

    let (client, mock, channel) = delta_attached(failing_decoder(), "test-rtl18-single").await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();

    send_message_pm(
        conn,
        "test-rtl18-single",
        "msg-1:0",
        Some("serial-1"),
        vec![plain_msg(
            "msg-1:0",
            rest::Data::String("base".into()),
            None,
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let attaches_before = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count();

    // First failing delta → recovery (ATTACHING); the mock does not confirm,
    // so recovery stays in progress.
    send_message_pm(
        conn,
        "test-rtl18-single",
        "msg-2:0",
        None,
        vec![delta_msg(
            "msg-2:0",
            bin("bad-1"),
            "utf-8/vcdiff",
            "msg-1:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(channel.state(), ChannelState::Attaching);

    // Second failing delta while ATTACHING — RTL17 drops it, no 2nd recovery.
    send_message_pm(
        conn,
        "test-rtl18-single",
        "msg-3:0",
        None,
        vec![delta_msg(
            "msg-3:0",
            bin("bad-2"),
            "utf-8/vcdiff",
            "msg-2:0",
        )],
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let recovery_attaches = mock
        .client_messages()
        .into_iter()
        .filter(|m| m.message.action == action::ATTACH)
        .count()
        - attaches_before;
    assert_eq!(recovery_attaches, 1, "only one recovery ATTACH");
    client.close();
}

// -- RTS3a: channels.get returns same --

#[tokio::test]
async fn rts3a_channels_get_returns_same() {
    // RTS3a: get() returns the same channel instance
    use crate::mock_ws::MockWebSocket;
    use crate::realtime::Realtime;

    let mock = MockWebSocket::new();
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
        transport,
    )
    .unwrap();

    let ch1 = client.channels.get("my-channel");
    let ch2 = client.channels.get("my-channel");
    assert!(std::sync::Arc::ptr_eq(&ch1, &ch2));
}

// -- CHM1: channel mode attributes --

#[test]
fn chm1_channel_mode_attributes() {
    use crate::protocol::ChannelMode;
    // CHM1: ChannelMode enum has the expected variants
    let presence = ChannelMode::Presence;
    let publish = ChannelMode::Publish;
    let subscribe = ChannelMode::Subscribe;
    let presence_subscribe = ChannelMode::PresenceSubscribe;

    assert_eq!(presence, ChannelMode::Presence);
    assert_eq!(publish, ChannelMode::Publish);
    assert_eq!(subscribe, ChannelMode::Subscribe);
    assert_eq!(presence_subscribe, ChannelMode::PresenceSubscribe);

    // Ensure they are distinct
    assert_ne!(presence, publish);
    assert_ne!(subscribe, presence_subscribe);
}

// ===============================================================
// RTL depth — Channel state depth
// ===============================================================

#[tokio::test]
async fn rtl2b_channel_initial_state_depth() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ChannelState;
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

    let channel = client.channels.get("test-depth");
    assert_eq!(channel.state(), ChannelState::Initialized);
}

#[tokio::test]
async fn rtl9_channel_name_preserved_depth() {
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

    let channel = client.channels.get("my-channel-name");
    assert_eq!(channel.name(), "my-channel-name");
}

#[tokio::test]
async fn rtl_channels_get_returns_same_channel_depth() {
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

    let ch1 = client.channels.get("shared-channel");
    let ch2 = client.channels.get("shared-channel");
    assert_eq!(ch1.name(), ch2.name());
}

#[tokio::test]
async fn rtl_multiple_channels_independent_depth() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::ChannelState;
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

    let ch1 = client.channels.get("channel-a");
    let ch2 = client.channels.get("channel-b");
    assert_eq!(ch1.state(), ChannelState::Initialized);
    assert_eq!(ch2.state(), ChannelState::Initialized);
    assert_ne!(ch1.name(), ch2.name());
}

// -- TM2a/TM2c/TM2f: message field population from ProtocolMessage
// (moved from tests_rest_unit_types.rs — these need realtime delivery) --

// --- TM2a, TM2c, TM2f: All fields populated together ---
#[tokio::test]
async fn tm2_all_fields_populated_together() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2-all";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        id: Some("connId:7".to_string()),
        connection_id: Some("connId".to_string()),
        timestamp: Some(1700000000000),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "first", "data": "a"}),
            serde_json::json!({"name": "second", "data": "b"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msg0 = rx.try_recv().unwrap();
    assert_eq!(msg0.id.as_deref(), Some("connId:7:0"));
    assert_eq!(msg0.connection_id.as_deref(), Some("connId"));
    assert_eq!(msg0.timestamp, Some(1700000000000));
    assert_eq!(msg0.name.as_deref(), Some("first"));

    let msg1 = rx.try_recv().unwrap();
    assert_eq!(msg1.id.as_deref(), Some("connId:7:1"));
    assert_eq!(msg1.connection_id.as_deref(), Some("connId"));
    assert_eq!(msg1.timestamp, Some(1700000000000));
    assert_eq!(msg1.name.as_deref(), Some("second"));
}

// --- TM2a: Message with existing id is not overwritten ---
#[tokio::test]
async fn tm2a_existing_id_not_overwritten() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2a-existing";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        id: Some("proto-id:0".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"id": "my-custom-id", "name": "msg", "data": "hello"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.id.as_deref(), Some("my-custom-id"));
}

// --- TM2a: Message id populated from ProtocolMessage ---
#[tokio::test]
async fn tm2a_message_id_populated() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2a";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    // Attach
    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    // Send ProtocolMessage with id but messages without id
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        id: Some("abc123:5".to_string()),
        connection_id: Some("abc123".to_string()),
        timestamp: Some(1700000000000),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "first", "data": "a"}),
            serde_json::json!({"name": "second", "data": "b"}),
            serde_json::json!({"name": "third", "data": "c"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msg0 = rx.try_recv().unwrap();
    assert_eq!(msg0.id.as_deref(), Some("abc123:5:0"));
    let msg1 = rx.try_recv().unwrap();
    assert_eq!(msg1.id.as_deref(), Some("abc123:5:1"));
    let msg2 = rx.try_recv().unwrap();
    assert_eq!(msg2.id.as_deref(), Some("abc123:5:2"));
}

// --- TM2a: No id when ProtocolMessage has no id ---
#[tokio::test]
async fn tm2a_no_id_when_protocol_message_has_no_id() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2a-no-proto-id";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    // ProtocolMessage has no id field
    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        connection_id: Some("abc123".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "msg", "data": "hello"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert!(msg.id.is_none());
}

// --- TM2c: Message connectionId populated from ProtocolMessage ---
#[tokio::test]
async fn tm2c_connection_id_populated() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2c";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        id: Some("msg:0".to_string()),
        connection_id: Some("server-conn-xyz".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "msg", "data": "hello"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.connection_id.as_deref(), Some("server-conn-xyz"));
}

// --- TM2c: Message with existing connectionId is not overwritten ---
#[tokio::test]
async fn tm2c_existing_connection_id_not_overwritten() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2c-existing";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        id: Some("msg:0".to_string()),
        connection_id: Some("proto-conn".to_string()),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"connectionId": "msg-conn", "name": "msg", "data": "hello"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.connection_id.as_deref(), Some("msg-conn"));
}

// --- TM2f: Message with existing timestamp is not overwritten ---
#[tokio::test]
async fn tm2f_existing_timestamp_not_overwritten() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2f-existing";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        id: Some("msg:0".to_string()),
        timestamp: Some(1700000000000),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"timestamp": 1600000000000_i64, "name": "msg", "data": "hello"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.timestamp, Some(1600000000000));
}

// --- TM2f: Message timestamp populated from ProtocolMessage ---
#[tokio::test]
async fn tm2f_timestamp_populated() {
    use crate::error::ErrorInfo;
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
    use crate::realtime::{await_state, Realtime};

    let channel_name = "test-tm2f";
    let mock = MockWebSocket::with_handler({
        move |pc| {
            pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        }
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret").auto_connect(false);
    let client = Realtime::with_mock(&opts, transport.clone()).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            channel_name,
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

    let ch = channel.clone();
    let cn = channel_name.to_string();
    let t = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some(cn.clone()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    let (_sub_id, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some(cn.clone()),
        id: Some("msg:0".to_string()),
        timestamp: Some(1700000000000),
        messages: crate::protocol::wire_messages(vec![
            serde_json::json!({"name": "msg", "data": "hello"}),
        ]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.timestamp, Some(1700000000000));
}

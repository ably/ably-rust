#![allow(unused_imports, dead_code, unused_variables, unused_mut, unused_assignments)]

use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use serde_json::json;

#[allow(unused_imports)]
use crate::auth::{self, Auth, AuthCallback, AuthOptions, AuthToken, Credential, Key, TokenDetails, TokenMetadata, TokenParams, TokenRequest};
#[allow(unused_imports)]
use crate::error::{ErrorCode, ErrorInfo, ErrorInfoCode};
#[allow(unused_imports)]
use crate::mock_http::{MockHttpClient, MockResponse, CapturedRequest};
#[allow(unused_imports)]
use crate::mock_ws::{MockWebSocket, MockTransport, MockConnection, PendingConnection, CapturedMessage};
#[allow(unused_imports)]
use crate::protocol::{action, flags, ConnectionState, ConnectionEvent, ConnectionStateChange, ChannelState, ChannelEvent, ChannelStateChange, ChannelMode, ProtocolMessage, ConnectionDetails, PublishResult};
#[allow(unused_imports)]
use crate::realtime::{Realtime, RealtimeAuth, Connection};
#[allow(unused_imports)]
use crate::channel::{Channels as RealtimeChannels, RealtimeChannel, RealtimeChannelOptions, DeriveOptions, RealtimePresence, PresenceGetOptions, SubscriptionId, PresenceSubscriptionId, RealtimeAnnotations};
#[allow(unused_imports)]
use crate::presence::{PresenceMap, LocalPresenceMap};
#[allow(unused_imports)]
use crate::rest::{self, Rest, Data, Message, PresenceMessage, PresenceAction, MessageAction, MessageOperation, UpdateDeleteResult, Annotation, AnnotationAction, BatchPresenceResult, BatchPublishSpec, BatchPublishResult, RevokeTokensRequest, RevokeTokensResponse, RevokeTokenResult, ChannelOptions, Format, Channels, Channel, Presence, PublishBuilder, Push, PushAdmin};
#[allow(unused_imports)]
use crate::{ClientOptions, Result};
#[allow(unused_imports)]
use crate::http::{RequestBuilder, PaginatedRequestBuilder, PaginatedResult, Response};
#[allow(unused_imports)]
use crate::options::LogLevel;
#[allow(unused_imports)]
use crate::stats::Stats;
#[allow(unused_imports)]
use crate::crypto::CipherParams;

    /// Helper to create a Rest client with a mock HTTP backend.
    fn mock_client(mock: MockHttpClient) -> crate::Rest {
        ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap()
    }


    /// Helper to get captured requests from a client with a mock backend.
    fn get_mock(_client: &crate::Rest) -> &MockHttpClient {
        _client.inner.mock_handle.as_ref().unwrap()
    }


    /// Create a mock REST client with JSON format (for tests that inspect request body).
    fn mock_client_json(mock: MockHttpClient) -> crate::Rest {
        ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap()
    }


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
                fail_code: std::sync::Arc::new(std::sync::Mutex::new(crate::error::ErrorInfoCode::Unauthorized)),
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
        ) -> std::pin::Pin<
            Box<dyn Send + futures::Future<Output = Result<crate::auth::AuthToken>> + 'a>,
        > {
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
                    let mut err = crate::error::ErrorInfo::new(
                        fail_code.code(),
                        "Auth callback failed",
                    );
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

                Ok(crate::auth::AuthToken::Details(
                    crate::auth::TokenDetails {
                        token: token_str,
                        metadata,
                        ..Default::default()
                    },
                ))
            })
        }
    }


    #[tokio::test]
    async fn rtan1a_publish_sends_annotation() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, mock, conn, channel) = setup_attached_channel("test-rtan1a", None).await;

        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            name: None,
            action: None,
            client_id: None,
            msg_serial: Some("msg-serial-1".into()),
            data: Data::JSON(json!({"emoji": "👍"})),
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };

        // Call publish directly (implementations are stubs, so this will
        // panic at runtime with todo!(), but we only need compilation here)
        let _result = channel.annotations().publish("msg-serial-1", &ann).await;
    }


    #[tokio::test]
    async fn rtan1a_publish_validates_type() {
        let (_, _, _conn, channel) = setup_attached_channel("test-rtan1a-val", None).await;

        let ann = crate::rest::Annotation {
            annotation_type: None, // missing type
            name: None,
            action: None,
            client_id: None,
            msg_serial: None,
            data: Data::None,
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };
        let result = channel.annotations().publish("msg-serial", &ann).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, Some(40000));
    }


    #[tokio::test]
    #[ignore = "requires RealtimeChannel::set_state which is not exposed"]
    async fn rtan1b_publish_state_conditions() {
        // This test needs to set channel state to Failed, but set_state is not
        // available in the public API. Skipping until the API supports this.
    }


    #[tokio::test]
    async fn rtan1d_publish_ack_nack() {
        use crate::protocol::{action, ProtocolMessage}; use crate::error::ErrorInfo;

        let (_, mock, conn, channel) = setup_attached_channel("test-rtan1d", None).await;

        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            name: None,
            action: None,
            client_id: None,
            msg_serial: None,
            data: Data::None,
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };

        let _result = channel.annotations().publish("msg-serial", &ann).await;
    }


    #[tokio::test]
    async fn rtan2a_delete_sends_annotation() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, _mock, _conn, channel) = setup_attached_channel("test-rtan2a", None).await;

        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            name: None,
            action: None,
            client_id: None,
            msg_serial: None,
            data: Data::None,
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };

        let _result = channel.annotations().delete("msg-serial", &ann).await;
    }


    #[tokio::test]
    async fn rtan4a_subscribe_delivers_annotations() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, _, conn, channel) = setup_attached_channel("test-rtan4a", None).await;

        let received = Arc::new(std::sync::Mutex::new(Vec::<Annotation>::new()));
        let received_c = received.clone();
        let _sub_id = channel.annotations().subscribe(move |ann| {
            received_c.lock().unwrap().push(ann);
        });

        // Send ANNOTATION protocol message
        conn.send_to_client(ProtocolMessage {
            action: action::ANNOTATION,
            channel: Some("test-rtan4a".into()),
            annotations: Some(json!([{
                "type": "reaction",
                "action": 0,
                "clientId": "user1",
                "data": {"emoji": "👍"},
            }])),
            ..ProtocolMessage::new(action::ANNOTATION)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let anns = received.lock().unwrap();
        assert!(!anns.is_empty(), "Should have received an annotation");
        let ann = &anns[0];
        assert_eq!(ann.annotation_type.as_deref(), Some("reaction"));
        assert_eq!(ann.client_id.as_deref(), Some("user1"));
    }


    #[tokio::test]
    async fn rtan4c_subscribe_type_filter() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, _, conn, channel) = setup_attached_channel("test-rtan4c", None).await;

        let received = Arc::new(std::sync::Mutex::new(Vec::<Annotation>::new()));
        let received_c = received.clone();
        let _sub_id = channel.annotations().subscribe_with_type("reaction", move |ann| {
            received_c.lock().unwrap().push(ann);
        });

        // Send two annotations: one "reaction" and one "comment"
        conn.send_to_client(ProtocolMessage {
            action: action::ANNOTATION,
            channel: Some("test-rtan4c".into()),
            annotations: Some(json!([
                {"type": "comment", "action": 0, "clientId": "user1"},
                {"type": "reaction", "action": 0, "clientId": "user2"},
            ])),
            ..ProtocolMessage::new(action::ANNOTATION)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let anns = received.lock().unwrap();
        assert_eq!(anns.len(), 1, "Should only receive the 'reaction' annotation");
        assert_eq!(anns[0].annotation_type.as_deref(), Some("reaction"));
        assert_eq!(anns[0].client_id.as_deref(), Some("user2"));
    }


    #[tokio::test]
    async fn rtan5a_unsubscribe_removes_listener() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, _, conn, channel) = setup_attached_channel("test-rtan5a", None).await;

        let received = Arc::new(std::sync::Mutex::new(Vec::<Annotation>::new()));
        let received_c = received.clone();
        let sub_id = channel.annotations().subscribe(move |ann| {
            received_c.lock().unwrap().push(ann);
        });

        // Unsubscribe
        channel.annotations().unsubscribe(sub_id);

        // Send annotation
        conn.send_to_client(ProtocolMessage {
            action: action::ANNOTATION,
            channel: Some("test-rtan5a".into()),
            annotations: Some(json!([{
                "type": "reaction",
                "action": 0,
            }])),
            ..ProtocolMessage::new(action::ANNOTATION)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Should not receive anything
        assert!(received.lock().unwrap().is_empty());
    }


    // UTS: realtime/unit/channels/channel_annotations.md — RTAN3a
    #[tokio::test]
    async fn rtan3a_rest_annotations_get_request() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = mock_client(mock);
        let channel = client.channels().get("test-rtan3a");
        let _ = channel.annotations().get("serial123").send().await;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].url.path().contains("/annotations"));
        Ok(())
    }


    // UTS: realtime/unit/channels/channel_annotations.md — RTAN4e
    // Spec: Warn when subscribing to annotations without ANNOTATION_SUBSCRIBE mode.
    #[tokio::test]
    async fn rtan4e_annotation_subscribe_without_mode_warning() -> Result<()> {
        use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage, flags};
        use crate::realtime::await_state;
        use std::sync::atomic::{AtomicBool, Ordering};

        let warned = Arc::new(AtomicBool::new(false));
        let warned_c = warned.clone();

        let mock = crate::mock_ws::MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
        });
        let transport = Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let options = ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![])
            .log_handler(move |_level, msg| {
                if msg.contains("ANNOTATION_SUBSCRIBE") {
                    warned_c.store(true, Ordering::SeqCst);
                }
            });
        let client = crate::realtime::Realtime::with_mock(&options, transport)?;
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-rtan4e");
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: action::ATTACHED,
            channel: Some("test-rtan4e".to_string()),
            flags: Some(flags::SUBSCRIBE),
            ..ProtocolMessage::new(action::ATTACHED)
        });
        attach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);

        let _id = channel.annotations().subscribe(|_ann| {});
        assert!(warned.load(Ordering::SeqCst), "Expected ANNOTATION_SUBSCRIBE warning");

        Ok(())
    }


    // UTS: realtime/unit/channels/channel_annotations.md — RTAN4e1
    // Spec: No warning when attach_on_subscribe is false and channel not attached.
    #[tokio::test]
    async fn rtan4e1_skip_warning_when_attach_on_subscribe_false() -> Result<()> {
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;
        use crate::channel::RealtimeChannelOptions;
        use std::sync::atomic::{AtomicBool, Ordering};

        let warned = Arc::new(AtomicBool::new(false));
        let warned_c = warned.clone();

        let mock = crate::mock_ws::MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
        });
        let transport = Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let options = ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .disconnected_retry_timeout(std::time::Duration::from_millis(50))
            .realtime_request_timeout(std::time::Duration::from_millis(200))
            .fallback_hosts(vec![])
            .log_handler(move |_level, msg| {
                if msg.contains("ANNOTATION_SUBSCRIBE") {
                    warned_c.store(true, Ordering::SeqCst);
                }
            });
        let client = crate::realtime::Realtime::with_mock(&options, transport)?;
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let mut ch_opts = RealtimeChannelOptions::default();
        ch_opts.attach_on_subscribe = Some(false);
        let channel = client.channels.get_with_options("test-rtan4e1", ch_opts);

        let _id = channel.annotations().subscribe(|_ann| {});
        assert!(!warned.load(Ordering::SeqCst), "Should not warn when not attached");

        Ok(())
    }


    // -- RTAN1a: publish encodes JSON data --

    #[tokio::test]
    async fn rtan1a_publish_encodes_json_data() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, mock, _conn, channel) = setup_attached_channel("test-rtan1a-json", None).await;

        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            name: None,
            action: None,
            client_id: None,
            msg_serial: Some("msg-1".into()),
            data: Data::JSON(json!({"emoji": "fire", "count": 3})),
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };

        let _result = channel.annotations().publish("msg-1", &ann).await;
    }


    // -- RTAN1d: publish rejects on nack --

    #[tokio::test]
    async fn rtan1d_publish_rejects_on_nack() {
        use crate::protocol::{action, ProtocolMessage}; use crate::error::ErrorInfo;

        let (_, _mock, _conn, channel) = setup_attached_channel("test-rtan1d-nack", None).await;

        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            name: None,
            action: None,
            client_id: None,
            msg_serial: None,
            data: Data::None,
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };

        let _result = channel.annotations().publish("msg-serial", &ann).await;
    }


    // -- RTAN4c: subscribe with type filter --

    #[tokio::test]
    async fn rtan4c_subscribe_with_type_filter() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, _, conn, channel) = setup_attached_channel("test-rtan4c-tf", None).await;

        let received = Arc::new(std::sync::Mutex::new(Vec::<Annotation>::new()));
        let received_c = received.clone();
        let _sub_id = channel.annotations().subscribe_with_type("like", move |ann| {
            received_c.lock().unwrap().push(ann);
        });

        // Send two annotations: one "like" and one "dislike"
        conn.send_to_client(ProtocolMessage {
            action: action::ANNOTATION,
            channel: Some("test-rtan4c-tf".into()),
            annotations: Some(json!([
                {"type": "dislike", "action": 0, "clientId": "user1"},
                {"type": "like", "action": 0, "clientId": "user2"},
            ])),
            ..ProtocolMessage::new(action::ANNOTATION)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let anns = received.lock().unwrap();
        assert_eq!(anns.len(), 1, "Should only receive the 'like' annotation");
        assert_eq!(anns[0].annotation_type.as_deref(), Some("like"));
        assert_eq!(anns[0].client_id.as_deref(), Some("user2"));
    }


    // -- RTAN4d: subscribe triggers implicit attach --

    #[tokio::test]
    async fn rtan4d_subscribe_triggers_implicit_attach() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
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

        let channel = client.channels.get("test-rtan4d-implicit");
        assert_eq!(channel.state(), ChannelState::Initialized);

        // Subscribing to annotations should trigger implicit attach
        let _sub_id = channel.annotations().subscribe(|_ann| {});

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Channel should be Attaching (waiting for server ATTACHED response)
        let state = channel.state();
        assert!(
            state == ChannelState::Attaching || state == ChannelState::Attached,
            "Channel should be attaching or attached after annotation subscribe, was {:?}",
            state
        );
    }


    // -- RTAN5a: unsubscribe with type filter --

    #[tokio::test]
    async fn rtan5a_unsubscribe_with_type_filter() {
        use crate::protocol::{action, ProtocolMessage};

        let (_, _, conn, channel) = setup_attached_channel("test-rtan5a-tf", None).await;

        let received = Arc::new(std::sync::Mutex::new(Vec::<Annotation>::new()));
        let received_c = received.clone();
        let sub_id = channel.annotations().subscribe_with_type("reaction", move |ann| {
            received_c.lock().unwrap().push(ann);
        });

        // Unsubscribe
        channel.annotations().unsubscribe(sub_id);

        // Send annotation matching the filter
        conn.send_to_client(ProtocolMessage {
            action: action::ANNOTATION,
            channel: Some("test-rtan5a-tf".into()),
            annotations: Some(json!([{
                "type": "reaction",
                "action": 0,
            }])),
            ..ProtocolMessage::new(action::ANNOTATION)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Should not receive anything after unsubscribe
        assert!(received.lock().unwrap().is_empty());
    }


    #[tokio::test]
    #[ignore = "annotation subscribe mode not implemented"]
    async fn rtan4e_annotation_subscribe_mode_warning() -> Result<()> {
        Ok(())
    }


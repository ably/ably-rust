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

    // (duplicate imports removed)

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


    // ---------------------------------------------------------------
    // Mock infrastructure smoke test
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn mock_time_returns_response() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.url.path(), "/time");
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        let time = client.time().await?;

        assert_eq!(time.timestamp_millis(), 1234567890000);
        Ok(())
    }


    // --- Channel Options (TB2-4, RTS3b/c) ---

    #[test]
    fn tb2_channel_options_defaults() {
        // TB2/TB4: ChannelOptions has correct default values
        use crate::channel::RealtimeChannelOptions;

        let options = RealtimeChannelOptions::new();
        assert!(options.params.is_none());
        assert!(options.modes.is_none());
        assert!(options.attach_on_subscribe != Some(false));
    }


    #[test]
    fn tb2c_channel_options_with_params() {
        // TB2c: ChannelOptions with params
        use crate::channel::RealtimeChannelOptions;

        let mut params = std::collections::HashMap::new();
        params.insert("rewind".to_string(), "1".to_string());
        params.insert("delta".to_string(), "vcdiff".to_string());

        let options = RealtimeChannelOptions {
            params: Some(params),
            ..RealtimeChannelOptions::default()
        };

        let p = options.params.unwrap();
        assert_eq!(p.get("rewind").unwrap(), "1");
        assert_eq!(p.get("delta").unwrap(), "vcdiff");
    }


    #[test]
    fn tb2d_channel_options_with_modes() {
        // TB2d: ChannelOptions with modes
        use crate::channel::RealtimeChannelOptions;
        use crate::protocol::ChannelMode;

        let options = RealtimeChannelOptions {
            modes: Some(vec![ChannelMode::Publish, ChannelMode::Subscribe]),
            ..RealtimeChannelOptions::default()
        };

        let modes = options.modes.unwrap();
        assert!(modes.contains(&ChannelMode::Publish));
        assert!(modes.contains(&ChannelMode::Subscribe));
        assert_eq!(modes.len(), 2);
    }


    #[test]
    fn tb4_attach_on_subscribe_default() {
        // TB4: attachOnSubscribe defaults to true
        use crate::channel::RealtimeChannelOptions;

        let options1 = RealtimeChannelOptions::new();
        assert!(options1.attach_on_subscribe != Some(false));

        let options2 = RealtimeChannelOptions {
            attach_on_subscribe: Some(false),
            ..RealtimeChannelOptions::default()
        };
        assert_eq!(options2.attach_on_subscribe, Some(false));
    }


    #[test]
    fn do2a_derive_options_filter_attribute() {
        // DO2a: DeriveOptions has a filter attribute
        use crate::channel::DeriveOptions;

        let opts = DeriveOptions::new("name == 'event' && data.count > 10");
        // filter is private, just verify construction succeeds
        let _ = opts;
    }


    // ---------------------------------------------------------------
    // Data msgpack round-trip preserves types
    // Regression test for custom Deserialize impl
    // ---------------------------------------------------------------

    #[test]
    fn data_msgpack_round_trip_preserves_types() {
        // String data: must stay String after msgpack round-trip
        let data = crate::rest::Data::String("hello".to_string());
        let packed = rmp_serde::to_vec_named(&data).unwrap();
        let unpacked: crate::rest::Data = rmp_serde::from_slice(&packed).unwrap();
        assert_eq!(unpacked, crate::rest::Data::String("hello".to_string()));

        // Binary data (valid UTF-8): must stay Binary, NOT become String
        let data = crate::rest::Data::Binary(serde_bytes::ByteBuf::from(b"hello".to_vec()));
        let packed = rmp_serde::to_vec_named(&data).unwrap();
        let unpacked: crate::rest::Data = rmp_serde::from_slice(&packed).unwrap();
        assert_eq!(
            unpacked,
            crate::rest::Data::Binary(serde_bytes::ByteBuf::from(b"hello".to_vec()))
        );

        // Binary data (non-UTF-8)
        let data =
            crate::rest::Data::Binary(serde_bytes::ByteBuf::from(vec![0x01, 0x02, 0x03, 0x04]));
        let packed = rmp_serde::to_vec_named(&data).unwrap();
        let unpacked: crate::rest::Data = rmp_serde::from_slice(&packed).unwrap();
        assert_eq!(
            unpacked,
            crate::rest::Data::Binary(serde_bytes::ByteBuf::from(vec![0x01, 0x02, 0x03, 0x04]))
        );

        // JSON data round-trip (through JSON serializer, not msgpack, since
        // Data::JSON serializes as a JSON string in msgpack)
        let data = crate::rest::Data::String("test".to_string());
        let json_str = serde_json::to_string(&data).unwrap();
        let unpacked: crate::rest::Data = serde_json::from_str(&json_str).unwrap();
        assert_eq!(unpacked, crate::rest::Data::String("test".to_string()));
    }


    #[test]
    fn tan2_annotation_type_fields() {
        use crate::rest::{Annotation, AnnotationAction};
        assert_eq!(AnnotationAction::Create as u8, 0);
        assert_eq!(AnnotationAction::Delete as u8, 1);

        let ann = Annotation {
            annotation_type: Some("reaction".into()),
            name: None,
            action: Some(AnnotationAction::Create),
            client_id: Some("user1".into()),
            message_serial: Some("serial1".into()),
            data: crate::rest::Data::JSON(json!({"emoji": "👍"})),
            serial: None,
            version: None,
            timestamp: Some(1000),
            encoding: None,
            id: Some("ann-1".into()),
            extras: None,
            ..Default::default()
        };
        let v = serde_json::to_value(&ann).unwrap();
        assert_eq!(v["type"], "reaction");
        assert_eq!(v["action"], 0);
        assert_eq!(v["clientId"], "user1");
    }


    // UTS: realtime/unit/channels/channel_options.md — TB3
    #[test]
    fn tb3_cipher_key_channel_options() {
        use crate::crypto::CipherParams;
        let key = base64::encode(&[0u8; 32]);
        let result = CipherParams::builder().string(&key);
        assert!(result.is_ok(), "CipherParams should accept base64 key");
    }


    // -- TAN1: annotation type field --

    #[test]
    fn tan1_annotation_type_field() {
        // TAN1: Annotation has a type field
        let ann = crate::rest::Annotation {
            annotation_type: Some("com.example.reaction".into()),
            ..Default::default()
        };
        assert_eq!(ann.annotation_type.as_deref(), Some("com.example.reaction"));

        let json = serde_json::to_value(&ann).unwrap();
        assert_eq!(json["type"], "com.example.reaction");
    }


    // -- TAN2: annotation summary field --

    #[test]
    fn tan2_annotation_summary_field() {
        // TAN2: Annotation action enum values and serialization
        use crate::rest::{Annotation, AnnotationAction};

        let ann = Annotation {
            annotation_type: Some("vote".into()),
            name: Some("option-a".into()),
            action: Some(AnnotationAction::Create),
            client_id: Some("voter-1".into()),
            message_serial: Some("msg-serial-1".into()),
            data: crate::rest::Data::JSON(json!({"weight": 1})),
            serial: Some("ann-serial-1".into()),
            timestamp: Some(1700000000000),
            id: Some("ann-id-1".into()),
            ..Default::default()
        };

        let json = serde_json::to_value(&ann).unwrap();
        assert_eq!(json["type"], "vote");
        assert_eq!(json["name"], "option-a");
        assert_eq!(json["action"], 0); // AnnotationCreate = 0
        assert_eq!(json["clientId"], "voter-1");
        assert_eq!(json["messageSerial"], "msg-serial-1");
        assert_eq!(json["data"]["weight"], 1);
        assert_eq!(json["timestamp"], 1700000000000_i64);

        // AnnotationDelete = 1
        assert_eq!(AnnotationAction::Delete as u8, 1);
    }



    // ===============================================================
    // NONE-tagged tests — General depth gaps with no spec tag
    // ===============================================================

    // --- Paginated result depth ---

    #[tokio::test]
    async fn none_paginated_single_item() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{"name": "only", "data": "one"}]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let res = client.channels().get("test").history().send().await?;
        let items = res.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, Some("only".to_string()));
        Ok(())
    }


    #[tokio::test]
    async fn none_paginated_ten_items() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            let msgs: Vec<serde_json::Value> = (0..10)
                .map(|i| json!({"name": format!("msg{}", i), "data": "x"}))
                .collect();
            MockResponse::json(200, &json!(msgs))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let res = client.channels().get("test").history().send().await?;
        let items = res.items();
        assert_eq!(items.len(), 10);
        assert_eq!(items[9].name, Some("msg9".to_string()));
        Ok(())
    }


    #[tokio::test]
    async fn none_paginated_error_response() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(500, &json!({
                "error": {"code": 50000, "statusCode": 500, "message": "Internal error", "href": ""}
            }))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let result = client.channels().get("test").history().send().await;
        assert!(result.is_err());
    }


    #[tokio::test]
    async fn none_paginated_auth_header_sent() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").history().send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "authorization"),
            "Paginated request should include Authorization header");
        Ok(())
    }


    #[tokio::test]
    async fn none_paginated_url_contains_channel() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("my-chan").history().send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs[0].url.path().contains("/channels/my-chan/"),
            "URL should contain channel name");
        Ok(())
    }


    #[tokio::test]
    async fn none_paginated_presence_url() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("pres-chan").presence().get().send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs[0].url.path().contains("/channels/pres-chan/presence"));
        assert!(!reqs[0].url.path().contains("/history"));
        Ok(())
    }


    #[tokio::test]
    async fn none_paginated_presence_history_url() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("pres-hist").presence().history().send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs[0].url.path().contains("/channels/pres-hist/presence/history"));
        Ok(())
    }


    // --- Error depth ---

    #[test]
    fn none_error_new_sets_code_and_message() {
        let err = crate::error::ErrorInfo::new(
            crate::error::ErrorCode::NotFound.code(),
            "Resource not found",
        );
        assert_eq!(err.code, Some(crate::error::ErrorCode::NotFound.code()));
        assert_eq!(err.message.as_deref(), Some("Resource not found"));
        assert!(err.status_code.is_none());
    }


    #[test]
    fn none_error_with_status_sets_all_fields() {
        let err = crate::error::ErrorInfo::with_status(
            crate::error::ErrorCode::Forbidden.code(),
            403,
            "Access denied",
        );
        assert_eq!(err.code, Some(crate::error::ErrorCode::Forbidden.code()));
        assert_eq!(err.status_code, Some(403));
        assert_eq!(err.message.as_deref(), Some("Access denied"));
        assert!(err.href.as_deref().unwrap().contains("40300"));
    }


    #[test]
    fn none_error_with_cause_preserves_source() {
        let inner = crate::error::ErrorInfo::new(0, "refused");
        let err = crate::error::ErrorInfo::with_cause(
            crate::error::ErrorCode::ConnectionFailed.code(),
            "Connection failed",
            inner,
        );
        assert_eq!(err.code, Some(crate::error::ErrorCode::ConnectionFailed.code()));
        assert!(err.cause.is_some());
    }


    #[test]
    fn none_error_implements_display() {
        let err = crate::error::ErrorInfo::new(
            crate::error::ErrorCode::BadRequest.code(),
            "Invalid payload",
        );
        let display = format!("{}", err);
        assert!(!display.is_empty());
    }


    #[test]
    fn none_error_implements_debug() {
        let err = crate::error::ErrorInfo::new(
            crate::error::ErrorCode::InternalError.code(),
            "Server error",
        );
        let debug = format!("{:?}", err);
        assert!(debug.contains("50000") || debug.contains("Server error"));
    }


    #[test]
    fn none_error_implements_std_error() {
        let err = crate::error::ErrorInfo::new(
            crate::error::ErrorCode::Unauthorized.code(),
            "Unauthorized",
        );
        // Verify it implements std::error::Error trait
        let _: &dyn std::error::Error = &err;
    }


    #[test]
    fn none_error_href_format() {
        let err = crate::error::ErrorInfo::new(
            crate::error::ErrorCode::TokenExpired.code(),
            "Token expired",
        );
        assert_eq!(err.href.as_deref(), Some("https://help.ably.io/error/40142"));
    }


    #[test]
    fn none_error_deserialized_from_json_with_missing_fields() {
        let json_str = r#"{"code":40000,"message":"Bad request","href":""}"#;
        let err: crate::error::ErrorInfo = serde_json::from_str(json_str).unwrap();
        assert_eq!(err.code, Some(crate::error::ErrorCode::BadRequest.code()));
        assert!(err.status_code.is_none());
    }


    #[test]
    fn none_error_deserialized_unknown_code() {
        let json_str = r#"{"code":99999,"message":"Unknown","href":""}"#;
        let err: crate::error::ErrorInfo = serde_json::from_str(json_str).unwrap();
        assert_eq!(err.code, Some(99999));
    }


    #[test]
    fn none_errorcode_roundtrip() {
        use crate::error::ErrorInfoCode;
        let code = ErrorCode::ChannelOperationFailed;
        assert_eq!(code.code(), 90000);
        let restored = ErrorCode::new(90000).unwrap();
        assert_eq!(restored, code);
    }


    #[test]
    fn none_errorcode_new_invalid_returns_none() {
        let result = crate::error::ErrorCode::new(12345);
        assert!(result.is_none());
    }


    #[test]
    fn none_errorcode_display() {
        let code = crate::error::ErrorCode::TokenRevoked;
        let s = format!("{}", code);
        assert_eq!(s, "TokenRevoked");
    }


    // --- Protocol ErrorInfo depth ---

    #[test]
    fn none_protocol_errorinfo_all_fields() {
        let ei = crate::error::ErrorInfo {
            code: Some(40100),
            status_code: Some(401_u16),
            message: Some("Unauthorized".to_string()),
            href: Some("https://help.ably.io/error/40100".to_string()),
            ..Default::default()
        };
        assert_eq!(ei.code, Some(40100));
        assert_eq!(ei.status_code, Some(401_u16));
        assert_eq!(ei.message.as_deref(), Some("Unauthorized"));
        assert_eq!(ei.href.as_deref(), Some("https://help.ably.io/error/40100"));
    }


    #[test]
    fn none_protocol_errorinfo_minimal() {
        let ei = crate::error::ErrorInfo {
            code: None,
            status_code: None,
            message: None,
            href: None,
            ..Default::default()
        };
        assert!(ei.code.is_none());
        assert!(ei.message.is_none());
    }


    #[test]
    fn none_protocol_errorinfo_json_roundtrip() {
        let ei = crate::error::ErrorInfo {
            code: Some(50000),
            status_code: Some(500_u16),
            message: Some("Internal error".to_string()),
            href: None,
            ..Default::default()
        };
        let json_val = serde_json::to_value(&ei).unwrap();
        assert_eq!(json_val["code"], 50000);
        assert_eq!(json_val["statusCode"], 500);
        assert_eq!(json_val["message"], "Internal error");
        // href is None so it should be omitted
        assert!(json_val.get("href").is_none());
    }


    #[test]
    fn none_protocol_errorinfo_deserialized() {
        let json_str = r#"{"code":40160,"statusCode":403,"message":"Capability not permitted"}"#;
        let ei: crate::error::ErrorInfo = serde_json::from_str(json_str).unwrap();
        assert_eq!(ei.code, Some(40160));
        assert_eq!(ei.status_code, Some(403_u16));
    }


    // --- Presence action values ---

    #[test]
    fn none_presence_action_absent_value() {
        assert_eq!(crate::rest::PresenceAction::Absent as u8, 0);
    }


    #[test]
    fn none_presence_action_present_value() {
        assert_eq!(crate::rest::PresenceAction::Present as u8, 1);
    }


    #[test]
    fn none_presence_action_enter_value() {
        assert_eq!(crate::rest::PresenceAction::Enter as u8, 2);
    }


    #[test]
    fn none_presence_action_leave_value() {
        assert_eq!(crate::rest::PresenceAction::Leave as u8, 3);
    }


    #[test]
    fn none_presence_action_update_value() {
        assert_eq!(crate::rest::PresenceAction::Update as u8, 4);
    }


    // --- TokenDetails depth ---

    #[test]
    fn none_token_details_minimal() {
        let td = crate::auth::TokenDetails {
            token: "minimal-token".to_string(),
            metadata: None,
            ..Default::default()
        };
        assert_eq!(td.token, "minimal-token");
        assert!(td.metadata.is_none());
    }


    #[test]
    fn none_token_details_from_token_constructor() {
        let td = crate::auth::TokenDetails::token("constructed-token".into());
        assert_eq!(td.token, "constructed-token");
    }


    #[test]
    fn none_token_details_full_metadata() {
        use crate::auth::{TokenDetails, TokenMetadata};
        use chrono::Utc;
        let now = Utc::now();
        let td = TokenDetails {
            token: "full-token".to_string(),
            metadata: Some(TokenMetadata {
                expires: now + chrono::Duration::hours(1),
                issued: now,
                capability: r#"{"ch1":["subscribe"]}"#.to_string(),
                client_id: Some("my-client".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let meta = td.metadata.unwrap();
        assert!(meta.expires > meta.issued);
        assert_eq!(meta.client_id.as_deref(), Some("my-client"));
        assert!(meta.capability.contains("subscribe"));
    }


    #[test]
    fn none_token_details_json_deserialize_no_client_id() {
        let json_str = r#"{"token":"tok1","expires":1700000000000,"issued":1699999000000,"capability":"{\"*\":[\"*\"]}"}"#;
        let td: crate::auth::TokenDetails = serde_json::from_str(json_str).unwrap();
        assert_eq!(td.token, "tok1");
        assert!(td.client_id.is_none());
    }


    // --- HTTP request depth ---

    #[tokio::test]
    async fn none_http_get_method() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.request("GET", "/test-path").send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, "GET");
        Ok(())
    }


    #[tokio::test]
    async fn none_http_post_method() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(201, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.request("POST", "/test-post")
            .body(&json!({"key": "value"}))
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, "POST");
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["key"], "value");
        Ok(())
    }


    #[tokio::test]
    async fn none_http_404_response_is_error() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(404, &json!({
                "error": {"code": 40400, "statusCode": 404, "message": "Not found", "href": ""}
            }))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        // Typed methods propagate HTTP errors as Err
        let err = client.channels().get("missing").history().send().await.unwrap_err();
        assert_eq!(err.error_code(), crate::error::ErrorCode::NotFound);
        // request() returns the error status for inspection (HP4/HP5)
        let resp = client.request("GET", "/missing").send().await.unwrap();
        assert_eq!(resp.status_code(), 404);
        assert!(!resp.success());
    }


    #[tokio::test]
    async fn none_http_500_response_is_error() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(500, &json!({
                "error": {"code": 50000, "statusCode": 500, "message": "Internal error", "href": ""}
            }))
        });
        let client = mock_client(mock);
        let err = client.channels().get("err-ch").history().send().await.unwrap_err();
        assert_eq!(err.error_code(), crate::error::ErrorCode::InternalError);
    }


    #[tokio::test]
    async fn none_http_delete_method() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.request("DELETE", "/resource/123").send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, "DELETE");
        assert!(reqs[0].url.path().contains("/resource/123"));
        Ok(())
    }


    #[tokio::test]
    async fn none_http_patch_method() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.request("PATCH", "/resource/456")
            .body(&json!({"update": true}))
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, "PATCH");
        Ok(())
    }


    // --- REST auth depth ---

    #[tokio::test]
    async fn none_rest_basic_auth_header_format() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = mock_client(mock);
        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0].headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).unwrap();
        assert!(auth.starts_with("Basic "), "Expected Basic auth, got: {}", auth);
        let decoded = base64::decode(auth.trim_start_matches("Basic ")).unwrap();
        let cred = String::from_utf8(decoded).unwrap();
        assert_eq!(cred, "appId.keyId:keySecret");
        Ok(())
    }


    #[tokio::test]
    async fn none_rest_token_auth_bearer_header() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_token("my-test-token".to_string())
            .rest_with_mock(mock)
            .unwrap();
        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0].headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).unwrap();
        assert!(auth.starts_with("Bearer "), "Expected Bearer auth, got: {}", auth);
        assert!(auth.contains("my-test-token"));
        Ok(())
    }


    // --- Channel name depth ---

    #[test]
    fn none_channel_name_with_unicode() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let channel = client.channels().get("channel-\u{1F600}-emoji");
        assert_eq!(channel.name, "channel-\u{1F600}-emoji");
    }


    #[test]
    fn none_channel_name_empty_string() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let channel = client.channels().get("");
        assert_eq!(channel.name, "");
    }


    #[test]
    fn none_channel_name_with_slashes() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let channel = client.channels().get("namespace/sub/channel");
        assert_eq!(channel.name, "namespace/sub/channel");
    }


    // --- Data enum depth ---

    #[test]
    fn none_data_string_variant() {
        let d = crate::rest::Data::String("hello".to_string());
        match d {
            crate::rest::Data::String(s) => assert_eq!(s, "hello"),
            _ => panic!("Expected String variant"),
        }
    }


    #[test]
    fn none_data_json_variant() {
        let d = crate::rest::Data::JSON(json!({"key": 42}));
        match d {
            crate::rest::Data::JSON(v) => assert_eq!(v["key"], 42),
            _ => panic!("Expected JSON variant"),
        }
    }


    #[test]
    fn none_data_binary_variant() {
        let d = crate::rest::Data::Binary(serde_bytes::ByteBuf::from(vec![0x01u8, 0x02, 0x03]));
        match &d {
            crate::rest::Data::Binary(v) => assert_eq!(v.as_ref(), &[0x01u8, 0x02, 0x03]),
            _ => panic!("Expected Binary variant"),
        }
    }


    // --- Message default depth ---

    #[test]
    fn none_message_default_fields() {
        let msg = crate::rest::Message::default();
        assert!(msg.id.is_none());
        assert!(msg.name.is_none());
        assert!(msg.client_id.is_none());
        assert!(msg.connection_id.is_none());
        assert!(matches!(msg.encoding, None));
        assert!(msg.extras.is_none());
        assert!(msg.serial.is_none());
        assert!(msg.version.is_none());
    }


    #[test]
    fn none_message_json_omits_null_fields() {
        let msg = crate::rest::Message {
            id: Some("msg-1".to_string()),
            ..Default::default()
        };
        let val = serde_json::to_value(&msg).unwrap();
        assert_eq!(val["id"], "msg-1");
        assert!(val.get("name").is_none());
        assert!(val.get("clientId").is_none());
        assert!(val.get("connectionId").is_none());
    }


    // --- ClientOptions depth ---

    #[test]
    fn none_client_options_tls_default_true() {
        let opts = ClientOptions::new("appId.keyId:keySecret");
        assert!(opts.tls);
    }


    #[test]
    fn none_client_options_idempotent_default_true() {
        let opts = ClientOptions::new("appId.keyId:keySecret");
        // TO3n: defaults to true for >= 1.2
        assert_eq!(opts.idempotent_rest_publishing, true);
    }


    #[test]
    fn none_client_options_with_environment() {
        let opts = ClientOptions::new("appId.keyId:keySecret")
            .environment("sandbox")
            .unwrap();
        // Environment set successfully — cannot directly read it, but rest creation works
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = opts.rest_with_mock(mock).unwrap();
        // Verify the client was created successfully
        let _auth = client.auth();
    }


    // --- Revoke tokens depth ---

    #[tokio::test]
    async fn none_revoke_tokens_single_target() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{
                "target": "clientId:bob",
                "issuedBefore": 1700000000000_i64,
                "appliesAt": 1700000000000_i64
            }]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();
        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:bob".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };
        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].target, "clientId:bob");
        Ok(())
    }


    #[tokio::test]
    async fn none_revoke_tokens_fails_with_token_auth() {
        let mock = MockHttpClient::new();
        let client = ClientOptions::with_token("some-token".to_string())
            .rest_with_mock(mock)
            .unwrap();
        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:test".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };
        let result = client.auth().revoke_tokens(&request).await;
        assert!(result.is_err());
    }


    // ===============================================================
    // Time endpoint depth
    // ===============================================================

    #[tokio::test]
    async fn none_time_endpoint_path() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.url.path(), "/time");
            MockResponse::json(200, &json!([1700000000000_i64]))
        });
        let client = mock_client(mock);
        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1700000000000);
        Ok(())
    }


    #[tokio::test]
    async fn none_time_uses_get_method() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            MockResponse::json(200, &json!([1700000000000_i64]))
        });
        let client = mock_client(mock);
        client.time().await?;
        Ok(())
    }


    // ===============================================================
    // Fallback depth
    // ===============================================================

    // ===============================================================
    // Additional NONE tests — misc depth
    // ===============================================================

    #[tokio::test]
    async fn none_publish_json_array_data() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish()
            .name("arr")
            .json(&vec!["a", "b", "c"])
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["encoding"], "json");
        let data: serde_json::Value = serde_json::from_str(body["data"].as_str().unwrap()).unwrap();
        assert_eq!(data, json!(["a", "b", "c"]));
        Ok(())
    }


    #[tokio::test]
    async fn none_publish_empty_string_data() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish()
            .name("evt")
            .string("")
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["data"], "");
        Ok(())
    }


    #[tokio::test]
    async fn none_publish_empty_binary_data() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish()
            .name("evt")
            .binary(vec![])
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["encoding"], "base64");
        assert_eq!(body["data"], "");
        Ok(())
    }


    #[tokio::test]
    async fn none_history_empty_result_returns_zero_items() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let res = client.channels().get("empty-ch").history().send().await?;
        let items = res.items();
        assert!(items.is_empty());
        Ok(())
    }


    #[tokio::test]
    async fn none_history_500_error_propagated() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(500, &json!({
                "error": {"code": 50000, "statusCode": 500, "message": "fail", "href": ""}
            }))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let result = client.channels().get("test").history().send().await;
        assert!(result.is_err());
    }


    #[test]
    fn none_client_options_key_parsed() {
        let opts = ClientOptions::new("myApp.myKey:mySecret");
        let client = opts.rest().unwrap();
        // Key was parsed correctly if auth() is available
        let _auth = client.auth();
    }


    #[test]
    fn none_client_options_token_parsed() {
        let client = ClientOptions::with_token("my-token".to_string())
            .rest()
            .unwrap();
        let _auth = client.auth();
    }


    #[tokio::test]
    async fn none_multiple_channels_independent_history() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("channel-a") {
                MockResponse::json(200, &json!([{"name": "a1", "data": "da"}]))
            } else {
                MockResponse::json(200, &json!([{"name": "b1", "data": "db"}]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let res_a = client.channels().get("channel-a").history().send().await?;
        let items_a = res_a.items();
        assert_eq!(items_a[0].name, Some("a1".to_string()));
        Ok(())
    }





    #[tokio::test]
    async fn none_ably_agent_header_present() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = mock_client(mock);
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let agent = reqs[0].headers.iter().find(|(k,_)| k == "ably-agent").map(|(_,v)| v.as_str());
        assert!(agent.is_some(), "Ably-Agent header should be present");
        let agent_str = agent.unwrap();
        assert!(agent_str.contains("ably-rust"), "Ably-Agent should contain SDK identifier");
        Ok(())
    }


    #[test]
    fn none_rest_channels_get_different_names() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch1 = client.channels().get("alpha");
        let ch2 = client.channels().get("beta");
        assert_eq!(ch1.name, "alpha");
        assert_eq!(ch2.name, "beta");
        assert_ne!(ch1.name, ch2.name);
    }


    #[test]
    fn none_errorcode_connection_codes() {
        use crate::error::ErrorInfoCode;
        assert_eq!(ErrorCode::ConnectionFailed.code(), 80000);
        assert_eq!(ErrorCode::ConnectionSuspended.code(), 80002);
        assert_eq!(ErrorCode::Disconnected.code(), 80003);
        assert_eq!(ErrorCode::ConnectionClosed.code(), 80017);
    }


    #[test]
    fn none_errorcode_channel_codes() {
        use crate::error::ErrorInfoCode;
        assert_eq!(ErrorCode::ChannelOperationFailed.code(), 90000);
        assert_eq!(ErrorCode::ChannelOperationFailedInvalidChannelState.code(), 90001);
        assert_eq!(ErrorCode::UnableToEnterPresenceChannelNoClientID.code(), 91000);
    }


    #[tokio::test]
    async fn none_publish_multiple_sequential() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let ch = client.channels().get("test");
        ch.publish().name("e1").string("d1").send().await?;
        ch.publish().name("e2").string("d2").send().await?;
        ch.publish().name("e3").string("d3").send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 3);
        Ok(())
    }


    #[test]
    fn none_presence_action_debug_repr() {
        let action = crate::rest::PresenceAction::Enter;
        let dbg = format!("{:?}", action);
        assert_eq!(dbg, "Enter");
    }


    #[test]
    fn none_data_null_default() {
        let msg = crate::rest::Message::default();
        assert!(matches!(msg.data, crate::rest::Data::None));
    }


    #[test]
    fn none_token_metadata_capability_wildcard() {
        use crate::auth::TokenMetadata;
        use chrono::Utc;
        let meta = TokenMetadata {
            expires: Utc::now(),
            issued: Utc::now(),
            capability: r#"{"*":["*"]}"#.to_string(),
            client_id: None,
            ..Default::default()
        };
        assert!(meta.capability.contains("*"));
        assert!(meta.client_id.is_none());
    }


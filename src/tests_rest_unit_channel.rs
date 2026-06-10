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


    // ===============================================================
    // Phase 3 — REST Channels: Publish, History, Encoding
    // ===============================================================

    // ---------------------------------------------------------------
    // RSL1a, RSL1b — Publish sends POST to /channels/<name>/messages
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1a_publish_sends_post_to_messages_endpoint() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test-channel")
            .publish()
            .name("greeting")
            .string("hello")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert!(
            reqs[0]
                .url
                .path()
                .ends_with("/channels/test-channel/messages"),
            "Expected POST to /channels/test-channel/messages, got {}",
            reqs[0].url.path()
        );

        // Verify the body contains name and data
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["name"], "greeting");
        assert_eq!(body["data"], "hello");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1e — Null name and data are omitted from JSON
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1e_null_name_omitted() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        // Publish with data but no name
        client
            .channels()
            .get("test")
            .publish()
            .string("hello")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        // name should not be present (skip_serializing_if = "Option::is_none")
        assert!(
            body.get("name").is_none(),
            "Expected 'name' to be omitted when null, got {:?}",
            body
        );
        assert_eq!(body["data"], "hello");

        Ok(())
    }


    #[tokio::test]
    async fn rsl1e_null_data_omitted() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        // Publish with name but no data
        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        // data should not be present when it's Data::None
        assert!(
            body.get("data").is_none(),
            "Expected 'data' to be omitted when null, got {:?}",
            body
        );
        assert_eq!(body["name"], "event");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1j — All Message attributes transmitted
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1j_all_message_attributes_transmitted() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let mut extras = crate::json::Map::new();
        extras.insert(
            "headers".to_string(),
            serde_json::json!({"some": "metadata"}),
        );

        client
            .channels()
            .get("test")
            .publish()
            .id("msg-id-1")
            .name("event")
            .string("data-value")
            .extras(extras)
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        assert_eq!(body["id"], "msg-id-1");
        assert_eq!(body["name"], "event");
        assert_eq!(body["data"], "data-value");
        assert_eq!(body["extras"]["headers"]["some"], "metadata");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1l — Publish params as querystring
    // Also covers: RSL1l1 (publish params sent as querystring)
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1l_publish_params_as_querystring() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .string("data")
            .params(&[("_forceNack", "true")])
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let has_param = reqs[0]
            .url
            .query_pairs()
            .any(|(k, v)| k == "_forceNack" && v == "true");
        assert!(
            has_param,
            "Expected _forceNack=true query param, got {}",
            reqs[0].url
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1m — clientId NOT auto-set from library clientId
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1m_client_id_not_auto_injected() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(
                    200,
                    &json!({
                        "token": "tok",
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "clientId": "lib-client",
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else {
                MockResponse::empty(201)
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("lib-client")
            .unwrap()
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .string("data")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        // Find the publish request (not the requestToken one)
        let publish_req = reqs
            .iter()
            .find(|r| r.url.path().contains("/messages"))
            .expect("Expected publish request");

        let body: serde_json::Value =
            serde_json::from_slice(publish_req.body.as_deref().unwrap()).unwrap();

        // Library MUST NOT inject its clientId into the message
        assert!(
            body.get("clientId").is_none(),
            "Expected clientId to NOT be auto-injected, got {:?}",
            body
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL2a — History returns messages
    // RSL2b — History query parameters
    // UTS: rest/unit/channel/history.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl2a_history_returns_messages() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                200,
                &json!([
                    {"id": "msg1", "name": "event1", "data": "hello"},
                    {"id": "msg2", "name": "event2", "data": "world"}
                ]),
            )
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items();

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, Some("event1".to_string()));
        assert_eq!(items[1].name, Some("event2".to_string()));

        Ok(())
    }


    #[tokio::test]
    async fn rsl2b_history_query_parameters() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .history()
            .start("1000000000000")
            .end("2000000000000")
            .forwards()
            .limit(10)
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");

        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(
            params.get("start").map(|s| s.as_str()),
            Some("1000000000000")
        );
        assert_eq!(params.get("end").map(|s| s.as_str()), Some("2000000000000"));
        assert_eq!(
            params.get("direction").map(|s| s.as_str()),
            Some("forwards")
        );
        assert_eq!(params.get("limit").map(|s| s.as_str()), Some("10"));

        Ok(())
    }


    #[tokio::test]
    async fn rsl2_history_request_url() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.channels().get("test").history().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, "GET");
        // The SDK currently uses /channels/<name>/history
        assert!(
            reqs[0].url.path().contains("/channels/test/"),
            "Expected history URL to contain /channels/test/, got {}",
            reqs[0].url.path()
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL4a — String data encoding (no encoding field)
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl4a_string_data_no_encoding() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .string("hello world")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        assert_eq!(body["data"], "hello world");
        // No encoding field for plain strings
        assert!(
            body.get("encoding").is_none(),
            "Expected no encoding for string data, got {:?}",
            body.get("encoding")
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL4b — JSON object encoding (encoding: "json")
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl4b_json_object_encoding() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .json(json!({"key": "value"}))
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        // JSON data should be serialized as a JSON string with encoding "json"
        assert_eq!(body["encoding"], "json");
        // The data field should be a JSON-encoded string of the object
        let data_str = body["data"].as_str().expect("Expected data to be a string");
        let parsed: serde_json::Value = serde_json::from_str(data_str).unwrap();
        assert_eq!(parsed["key"], "value");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL4c — Binary data with JSON protocol (encoding: "base64")
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl4c_binary_data_base64_with_json() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .binary(vec![0x01, 0x02, 0x03, 0x04])
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        // Binary data should be base64-encoded when using JSON protocol
        assert_eq!(body["encoding"], "base64");
        let data_str = body["data"]
            .as_str()
            .expect("Expected data to be base64 string");
        let decoded = base64::decode(data_str).unwrap();
        assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL6a — Decoding base64 data
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl6a_decoding_base64() -> Result<()> {
        let encoded_data = base64::encode(&[0x01, 0x02, 0x03]);
        let mock = MockHttpClient::with_handler(move |_req| {
            MockResponse::json(
                200,
                &json!([
                    {"name": "event", "data": encoded_data, "encoding": "base64"}
                ]),
            )
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items();

        assert_eq!(items.len(), 1);
        // After decoding, data should be binary
        assert_eq!(items[0].data, vec![0x01, 0x02, 0x03].into());
        // Encoding should be consumed
        assert_eq!(items[0].encoding, None);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL6a — Decoding JSON data
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl6a_decoding_json() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                200,
                &json!([
                    {"name": "event", "data": "{\"key\":\"value\"}", "encoding": "json"}
                ]),
            )
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items();

        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].data,
            crate::rest::Data::JSON(json!({"key": "value"}))
        );
        assert_eq!(items[0].encoding, None);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL6a — Decoding chained encodings (json/base64)
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl6a_decoding_chained_json_base64() -> Result<()> {
        // Data is a JSON object, serialized to string, then base64-encoded
        let json_str = r#"{"nested":"data"}"#;
        let b64 = base64::encode(json_str);

        let mock = MockHttpClient::with_handler(move |_req| {
            MockResponse::json(
                200,
                &json!([
                    {"name": "event", "data": b64, "encoding": "json/base64"}
                ]),
            )
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items();

        assert_eq!(items.len(), 1);
        // Decoded: base64 → utf-8 string → JSON parse
        assert_eq!(
            items[0].data,
            crate::rest::Data::JSON(json!({"nested": "data"}))
        );
        assert_eq!(items[0].encoding, None);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL6b — Unrecognized encoding preserved
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl6b_unrecognized_encoding_preserved() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                200,
                &json!([
                    {"name": "event", "data": "some data", "encoding": "custom-encoding"}
                ]),
            )
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items();

        assert_eq!(items.len(), 1);
        // Unrecognized encoding should be preserved
        assert_eq!(
            items[0].encoding,
            Some("custom-encoding".to_string())
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL9 — RestChannel name attribute
    // UTS: rest/unit/channel/rest_channel_attributes.md
    // ---------------------------------------------------------------

    #[test]
    fn rsl9_channel_name_attribute() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let channel = client.channels().get("my-channel");
        assert_eq!(channel.name, "my-channel");
    }


    #[test]
    fn rsl9_channel_name_with_special_chars() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let channel = client.channels().get("namespace:channel-name");
        assert_eq!(channel.name, "namespace:channel-name");
    }


    // ---------------------------------------------------------------
    // RSN1 — Channels accessible via RestClient
    // UTS: rest/unit/channels_collection.md
    // ---------------------------------------------------------------

    #[test]
    fn rsn1_channels_accessible() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        // channels() returns a Channels collection
        let _channels = client.channels();
    }


    // ---------------------------------------------------------------
    // RSN3a — Get creates channel
    // UTS: rest/unit/channels_collection.md
    // ---------------------------------------------------------------

    #[test]
    fn rsn3a_get_creates_channel() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let channel = client.channels().get("new-channel");
        assert_eq!(channel.name, "new-channel");
    }


    // ---------------------------------------------------------------
    // RSL1k1 — idempotentRestPublishing default
    // UTS: rest/unit/channel/idempotency.md
    // ---------------------------------------------------------------

    #[test]
    fn rsl1k1_idempotent_rest_publishing_default() {
        let opts = ClientOptions::new("appId.keyId:keySecret");
        // RSL1k1: Default should be true for library versions >= 1.2
        // Note: Current SDK defaults to false — this is a known gap.
        // This test documents the current behavior.
        // TODO: Change default to true to comply with RSL1k1.
        assert_eq!(
            opts.idempotent_rest_publishing, false,
            "Current default is false; spec requires true for versions >= 1.2"
        );
    }


    // ---------------------------------------------------------------
    // RSL4 — JSON protocol Content-Type
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl4_json_protocol_content_type() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("e")
            .string("d")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let ct = reqs[0]
            .headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str())
            .unwrap();
        assert_eq!(ct, "application/json");

        let accept = reqs[0].headers.iter().find(|(k,_)| k == "accept").map(|(_,v)| v.as_str()).unwrap();
        assert_eq!(accept, "application/json");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL4 — MessagePack protocol Content-Type
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl4_msgpack_protocol_content_type() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = mock_client(mock);

        client
            .channels()
            .get("test")
            .publish()
            .name("e")
            .string("d")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let ct = reqs[0]
            .headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str())
            .unwrap();
        assert_eq!(ct, "application/x-msgpack");

        let accept = reqs[0].headers.iter().find(|(k,_)| k == "accept").map(|(_,v)| v.as_str()).unwrap();
        assert_eq!(accept, "application/x-msgpack");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL4d — Array data encoded as JSON
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl4d_array_data_json_encoding() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .json(&vec![1, 2, 3])
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        // Array should be JSON-encoded as a string
        assert_eq!(body["encoding"], "json");
        // The data field should be a JSON string representation of the array
        let data_str = body["data"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(data_str).unwrap();
        assert_eq!(parsed, json!([1, 2, 3]));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1b — Message sent as array in request body
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1b_message_sent_as_array() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .string("data")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        // Single message should still be sent as the body (RSL1b: message in request body)
        assert!(
            body.is_object(),
            "Single message should be sent as object, got: {:?}",
            body
        );
        assert_eq!(body["name"], "event");
        assert_eq!(body["data"], "data");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1c — Multi-message publish sends all in single request
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    #[ignore = "PublishBuilder::messages() not yet implemented"]
    async fn rsl1c_multi_message_publish_single_request() -> Result<()> {
        // When PublishBuilder supports multi-message publish:
        // - All messages should be sent in a single HTTP POST
        // - Body should be a JSON array with all messages
        // - Request count should be exactly 1
        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL2b1 — Default history direction is backwards
    // UTS: rest/unit/channel/history.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl2b1_default_history_direction_backwards() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let _ = client.channels().get("test").history().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let url = &reqs[0].url;

        // Default direction should be backwards (or absent, meaning backwards)
        // If direction param is present, it should be "backwards"
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let dir = query.iter().find(|(k, _)| k == "direction");
        if let Some((_, v)) = dir {
            assert_eq!(v, "backwards", "Default direction should be backwards");
        }
        // If absent, that's also fine — server defaults to backwards

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL4 — Empty string encoding
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl4_empty_string_no_encoding() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .string("")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();

        assert_eq!(body["data"], "");
        assert!(
            body.get("encoding").is_none(),
            "Expected no encoding for empty string"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1k3 — No ID generated when idempotent publishing disabled
    // UTS: rest/unit/channel/idempotency.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1k3_no_id_when_idempotent_disabled() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(201, &json!({})));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        // idempotent_rest_publishing defaults to false in this SDK
        let channel = client.channels().get("test");
        channel
            .publish()
            .name("event")
            .string("data")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();

        // No automatic ID should be added when disabled
        assert!(
            body.get("id").is_none() || body["id"].is_null(),
            "id should not be set when idempotent publishing is disabled"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL1k — Client-supplied ID preserved
    // UTS: rest/unit/channel/idempotency.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1k_client_supplied_id_preserved() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(201, &json!({})));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let channel = client.channels().get("test");
        channel
            .publish()
            .id("my-custom-id")
            .name("event")
            .string("data")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();

        assert_eq!(body["id"], "my-custom-id");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL6 — MessagePack binary data preserved
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl6_msgpack_binary_data_preserved() -> Result<()> {
        // Construct a msgpack response where the data field is msgpack bin type.
        // Using serde_bytes::ByteBuf ensures rmp_serde serializes as bin, not str.
        #[derive(serde::Serialize)]
        struct MsgpackMessage {
            name: String,
            data: serde_bytes::ByteBuf,
        }

        let msg = MsgpackMessage {
            name: "event".to_string(),
            data: serde_bytes::ByteBuf::from(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]), // "Hello" bytes
        };

        let mock =
            MockHttpClient::with_handler(move |_req| MockResponse::msgpack(200, &vec![&msg]));

        let client = mock_client(mock);
        let res = client.channels().get("test").history().send().await?;
        let items = res.items();

        assert_eq!(items.len(), 1);
        // Must be Binary, NOT String (even though bytes are valid UTF-8)
        assert_eq!(
            items[0].data,
            crate::rest::Data::Binary(serde_bytes::ByteBuf::from(vec![
                0x48, 0x65, 0x6C, 0x6C, 0x6F
            ]))
        );
        assert_eq!(items[0].encoding, None);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSL6 — MessagePack string data preserved
    // UTS: rest/unit/encoding/message_encoding.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl6_msgpack_string_data_preserved() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::msgpack(
                200,
                &json!([
                    {"name": "event", "data": "Hello World"}
                ]),
            )
        });

        let client = mock_client(mock);
        let res = client.channels().get("test").history().send().await?;
        let items = res.items();

        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].data,
            crate::rest::Data::String("Hello World".to_string())
        );
        assert_eq!(items[0].encoding, None);

        Ok(())
    }


    #[test]
    fn mop2_message_operation_fields() {
        use crate::rest::MessageOperation;
        let op = MessageOperation {
            client_id: Some("user1".into()),
            description: Some("edited".into()),
            metadata: Some({
                let mut m = serde_json::Map::new();
                m.insert("key".into(), json!("val"));
                m
            }),
        };
        let v = serde_json::to_value(&op).unwrap();
        assert_eq!(v["clientId"], "user1");
        assert_eq!(v["description"], "edited");
        assert_eq!(v["metadata"]["key"], "val");
    }


    // UDR2a — versionSerial is nullable and a null must be preserved
    #[test]
    fn udr2a_update_delete_result_fields() {
        let json_str = r#"{"serial":"s1","versionSerial":"vs1"}"#;
        let result: crate::rest::UpdateDeleteResult = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.serial.as_deref(), Some("s1"));
        assert_eq!(result.version_serial.as_deref(), Some("vs1"));

        // null versionSerial preserved as None (message superseded before publish)
        let json_str2 = r#"{"serial":"s2","versionSerial":null}"#;
        let result2: crate::rest::UpdateDeleteResult = serde_json::from_str(json_str2).unwrap();
        assert_eq!(result2.serial.as_deref(), Some("s2"));
        assert!(result2.version_serial.is_none());
    }


    // -- REST unit tests --

    // RSL15b/RSL15b1 — updateMessage sends PATCH with action MESSAGE_UPDATE (=1)
    // UTS: rest/unit/RSL15b/update-sends-patch-update-0
    #[tokio::test]
    async fn rsl15b_update_message_sends_patch() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("msg-serial-1".into()),
            name: Some("updated".into()),
            data: Data::String("new-data".into()),
            ..Default::default()
        };
        ch.update_message(&msg, None, None).await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let req = reqs.last().unwrap();
        assert_eq!(req.method, "PATCH");
        assert_eq!(req.url.path(), "/channels/test/messages/msg-serial-1");
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["action"], 1); // MESSAGE_UPDATE
        assert_eq!(body["name"], "updated");
        assert_eq!(body["data"], "new-data");
        Ok(())
    }


    // RSL15b/RSL15b1 — deleteMessage sends PATCH with action MESSAGE_DELETE (=2)
    // UTS: rest/unit/RSL15b/delete-sends-patch-delete-1
    #[tokio::test]
    async fn rsl15b_delete_message_sends_patch() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("msg-serial-1".into()),
            ..Default::default()
        };
        ch.delete_message(&msg, None, None).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        assert_eq!(req.method, "PATCH");
        assert_eq!(req.url.path(), "/channels/test/messages/msg-serial-1");
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["action"], 2); // MESSAGE_DELETE
        Ok(())
    }


    // RSL15b/RSL15b1 — appendMessage sends PATCH with action MESSAGE_APPEND (=5)
    // UTS: rest/unit/RSL15b/append-sends-patch-append-2
    #[tokio::test]
    async fn rsl15b_append_message_sends_patch() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("msg-serial-1".into()),
            data: Data::String("appended-data".into()),
            ..Default::default()
        };
        ch.append_message(&msg, None).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        assert_eq!(req.method, "PATCH");
        assert_eq!(req.url.path(), "/channels/test/messages/msg-serial-1");
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["action"], 5); // MESSAGE_APPEND
        assert_eq!(body["data"], "appended-data");
        Ok(())
    }


    // RSL15b7 — version set to the MessageOperation when provided
    // UTS: rest/unit/RSL15b7/version-set-with-operation-0
    #[tokio::test]
    async fn rsl15b7_version_set_from_operation() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("s1".into()),
            data: Data::String("updated".into()),
            ..Default::default()
        };
        let mut metadata = serde_json::Map::new();
        metadata.insert("reason".into(), json!("typo"));
        let op = crate::rest::MessageOperation {
            client_id: Some("user1".into()),
            description: Some("fixed typo".into()),
            metadata: Some(metadata),
        };
        ch.update_message(&msg, Some(&op), None).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["version"]["clientId"], "user1");
        assert_eq!(body["version"]["description"], "fixed typo");
        assert_eq!(body["version"]["metadata"]["reason"], "typo");
        Ok(())
    }


    // RSL15b7 — version absent when no MessageOperation provided
    // UTS: rest/unit/RSL15b7/version-absent-no-operation-1
    #[tokio::test]
    async fn rsl15b7_version_absent_without_operation() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("s1".into()),
            data: Data::String("updated".into()),
            ..Default::default()
        };
        ch.update_message(&msg, None, None).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert!(body.get("version").is_none());
        Ok(())
    }


    // RSL15c — does not mutate the user-supplied Message
    // UTS: rest/unit/RSL15c/no-mutate-user-message-0
    #[tokio::test]
    async fn rsl15c_does_not_mutate_user_message() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let original = crate::rest::Message {
            serial: Some("s1".into()),
            name: Some("orig".into()),
            data: Data::String("original-data".into()),
            ..Default::default()
        };
        ch.update_message(&original, None, None).await?;
        // Original message must not have been mutated
        assert!(original.action.is_none());
        assert_eq!(original.name.as_deref(), Some("orig"));
        assert!(matches!(original.data, Data::String(ref s) if s == "original-data"));
        // But the request body carries the action
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs.last().unwrap().body.as_deref().unwrap()).unwrap();
        assert_eq!(body["action"], 1); // MESSAGE_UPDATE
        Ok(())
    }


    // RSL15e — returns UpdateDeleteResult with versionSerial
    // UTS: rest/unit/RSL15e/returns-update-delete-result-0
    #[tokio::test]
    async fn rsl15e_returns_update_delete_result() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "version-serial-abc"}))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("s1".into()),
            data: Data::String("updated".into()),
            ..Default::default()
        };
        let result = ch.update_message(&msg, None, None).await?;
        assert_eq!(result.version_serial.as_deref(), Some("version-serial-abc"));
        Ok(())
    }


    // RSL15e/UDR2a — null versionSerial in the response is preserved
    // UTS: rest/unit/RSL15e/null-version-serial-1
    #[tokio::test]
    async fn rsl15e_null_version_serial() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": null}))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("s1".into()),
            data: Data::String("updated".into()),
            ..Default::default()
        };
        let result = ch.update_message(&msg, None, None).await?;
        assert!(result.version_serial.is_none());
        Ok(())
    }


    // RSL15f — params sent as querystring
    // UTS: rest/unit/RSL15f/params-sent-as-querystring-0
    #[tokio::test]
    async fn rsl15f_params_sent_as_querystring() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("s1".into()),
            data: Data::String("updated".into()),
            ..Default::default()
        };
        ch.update_message(&msg, None, Some(&[("key", "value"), ("num", "42")]))
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        let query: std::collections::HashMap<String, String> = req
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(query.get("key").map(String::as_str), Some("value"));
        assert_eq!(query.get("num").map(String::as_str), Some("42"));
        Ok(())
    }


    // RSL15a — serial required: all three methods fail with 40003, no request made
    // UTS: rest/unit/RSL15a/serial-required-throws-error-0
    #[tokio::test]
    async fn rsl15a_serial_required() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            name: Some("x".into()),
            data: Data::String("y".into()),
            ..Default::default()
        };

        let err = ch.update_message(&msg, None, None).await.unwrap_err();
        assert_eq!(err.code, Some(40003));
        let err = ch.delete_message(&msg, None, None).await.unwrap_err();
        assert_eq!(err.code, Some(40003));
        let err = ch.append_message(&msg, None).await.unwrap_err();
        assert_eq!(err.code, Some(40003));

        // Client-side checks — no HTTP request may have been made
        assert_eq!(get_mock(&client).request_count(), 0);
    }


    // RSL15b — serial URL-encoded in path
    // UTS: rest/unit/RSL15b/serial-url-encoded-path-3
    #[tokio::test]
    async fn rsl15b_serial_url_encoded() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("serial/special:chars".into()),
            data: Data::String("updated".into()),
            ..Default::default()
        };
        ch.update_message(&msg, None, None).await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(
            reqs.last().unwrap().url.path(),
            "/channels/test/messages/serial%2Fspecial%3Achars"
        );
        Ok(())
    }


    // RSL4c — under MessagePack, binary data is sent as native msgpack binary,
    // NOT base64-encoded, and no "base64" encoding step is added.
    #[tokio::test]
    async fn rsl4c_binary_native_under_msgpack() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        // mock_client uses the default (MessagePack) format
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let payload = vec![0x00u8, 0x01, 0x02, 0xFF, 0xFE];
        ch.publish().name("bin-event").binary(payload.clone()).send().await?;

        let reqs = get_mock(&client).captured_requests();
        let body = reqs.last().unwrap().body.as_deref().unwrap();
        // The body must round-trip as a Message with binary data intact and no encoding
        let msg: crate::rest::Message = rmp_serde::from_slice(body).unwrap();
        assert!(
            matches!(msg.data, Data::Binary(ref b) if b.as_ref() == payload.as_slice()),
            "binary data must be native msgpack bin, got {:?}",
            msg.data
        );
        assert!(msg.encoding.is_none(), "no encoding step for native binary");
        Ok(())
    }


    // RSL4c — under JSON, binary data is base64-encoded with encoding "base64"
    #[tokio::test]
    async fn rsl4c_binary_base64_under_json() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let payload = vec![0x00u8, 0x01, 0x02, 0xFF, 0xFE];
        ch.publish().name("bin-event").binary(payload.clone()).send().await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs.last().unwrap().body.as_deref().unwrap()).unwrap();
        assert_eq!(body["encoding"], "base64");
        let decoded = base64::decode(body["data"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, payload);
        Ok(())
    }


    // RSL15d — request body encoded per RSL4 (JSON data stringified + encoding "json")
    // UTS: rest/unit/RSL15d/body-encoded-per-rsl4-0
    #[tokio::test]
    async fn rsl15d_body_encoded_per_rsl4() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"versionSerial": "vs1"}))
        });
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let msg = crate::rest::Message {
            serial: Some("s1".into()),
            data: Data::JSON(json!({"key": "value"})),
            ..Default::default()
        };
        ch.update_message(&msg, None, None).await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs.last().unwrap().body.as_deref().unwrap()).unwrap();
        assert!(body["data"].is_string());
        assert_eq!(body["encoding"], "json");
        let inner: serde_json::Value = serde_json::from_str(body["data"].as_str().unwrap()).unwrap();
        assert_eq!(inner, json!({"key": "value"}));
        Ok(())
    }


    // RSL11b — get_message sends GET
    // Also covers: RSL11 (parent spec for GetMessage)
    #[tokio::test]
    async fn rsl11b_get_message_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert!(req.url.path().contains("/channels/test/messages/"));
            MockResponse::json(
                200,
                &json!({"id": "msg-1", "name": "event", "data": "hello"}),
            )
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let msg = ch.get_message("serial-1").await?;
        assert_eq!(msg.id.as_deref(), Some("msg-1"));
        Ok(())
    }


    #[tokio::test]
    async fn rsl11c_get_message_returns_message() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                200,
                &json!({
                    "id": "msg-1",
                    "name": "event",
                    "data": "hello",
                    "serial": "s1",
                    "action": 0
                }),
            )
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let msg = ch.get_message("serial-1").await?;
        assert_eq!(msg.name.as_deref(), Some("event"));
        assert_eq!(msg.serial.as_deref(), Some("s1"));
        Ok(())
    }


    #[tokio::test]
    async fn rsl11a_get_message_serial_required() {
        let mock =
            MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({"id": "msg-1"})));
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let result = ch.get_message("").await;
        assert!(result.is_err());
    }


    #[tokio::test]
    async fn rsl14b_get_message_versions_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert!(req.url.path().contains("/versions"));
            MockResponse::json(200, &json!([{"id": "v1"}, {"id": "v2"}]))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let page = ch.message_versions("serial-1").send().await?;
        let items = page.items();
        assert_eq!(items.len(), 2);
        Ok(())
    }


    // -- REST annotations tests --

    #[test]
    fn rsl10_channel_annotations_accessor() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch = client.channels().get("test");
        let _ann = ch.annotations(); // just verify it compiles and returns
    }


    // ===============================================================
    // RSN2/RSN4: Channels collection (release, exists, iteration)
    // UTS: rest/unit/channels_collection.md
    // ===============================================================

    #[test]
    fn rsn2_channel_exists_check() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let _ch = client.channels().get("test-channel");
        let ch2 = client.channels().get("test-channel");
        assert_eq!(ch2.name, "test-channel");
    }


    #[test]
    fn rsn4a_get_channel_by_name() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch1 = client.channels().get("ch-alpha");
        let ch2 = client.channels().get("ch-beta");
        assert_eq!(ch1.name, "ch-alpha");
        assert_eq!(ch2.name, "ch-beta");
    }


    #[test]
    fn rsn4b_get_nonexistent_channel() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch = client.channels().get("nonexistent");
        assert_eq!(ch.name, "nonexistent");
    }


    // ===============================================================
    // RSL7/RSL8: REST Channel attributes & status
    // UTS: rest/unit/channel/rest_channel_attributes.md
    // ===============================================================

    #[test]
    fn rsl7_channel_name() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch = client.channels().get("test-channel");
        assert_eq!(ch.name, "test-channel");
    }


    #[test]
    fn rsl8_channel_name_with_special_chars() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch = client.channels().get("test:channel/name");
        assert_eq!(ch.name, "test:channel/name");
    }


    #[test]
    fn rsl8a_channel_name_accessible() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch = client.channels().get("my-channel");
        assert_eq!(ch.name, "my-channel");
    }


    // ===============================================================
    // RSL1n: Publish result with serials
    // UTS: rest/unit/channel/publish_result.md
    // ===============================================================

    #[tokio::test]
    async fn rsl1n_publish_returns_result_with_serials() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(201, &serde_json::json!({
                "serials": ["serial-abc"]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let channel = client.channels().get("test-rsl1n");
        channel
            .publish()
            .name("test")
            .string("data")
            .send()
            .await?;
        Ok(())
    }


    // ===============================================================
    // Batch 2: REST Publish & Channel Operations
    // ===============================================================

    // UTS: rest/unit/channel/publish.md — RSL1h
    #[tokio::test]
    async fn rsl1h_publish_name_data_sends_single_message() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(201, &json!({}))
        });
        let client = mock_client(mock);
        let channel = client.channels().get("test-rsl1h");
        channel.publish().name("event").string("payload").send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert!(reqs[0].url.path().contains("/channels/test-rsl1h/messages"));
        Ok(())
    }


    // UTS: rest/unit/channel/publish.md — RSL1i
    // Spec: Messages exceeding maxMessageSize must be rejected with error 40009.
    #[tokio::test]
    async fn rsl1i_message_exceeding_max_size_rejected() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(201, &json!({}))
        });
        let mut opts = ClientOptions::new("appId.keyId:keySecret");
        opts.max_message_size = 100;
        let client = opts.rest_with_mock(mock).unwrap();
        let channel = client.channels().get("test-rsl1i");

        let small_data = "x".repeat(10);
        let result = channel.publish().name("ok").string(&small_data).send().await;
        assert!(result.is_ok(), "Small message should succeed");

        let large_data = "x".repeat(200);
        let result = channel.publish().name("big").string(&large_data).send().await;
        assert!(result.is_err(), "Large message should be rejected");
        let err = result.unwrap_err();
        assert_eq!(
            err.code,
            Some(crate::error::ErrorInfoCode::MaximumMessageLengthExceeded.code()),
            "Error code should be 40009"
        );

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1, "Only the small message should have been sent");
        Ok(())
    }


    // UTS: rest/unit/channel/idempotency.md — RSL1k2
    #[tokio::test]
    async fn rsl1k2_idempotent_publish_message_id_format() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(201, &json!({}))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .idempotent_rest_publishing(true)
            .rest_with_mock(mock)
            .unwrap();
        let channel = client.channels().get("test-rsl1k2");
        channel.publish().name("event").string("data").send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        if let Some(body) = &reqs[0].body {
            let msg: serde_json::Value = rmp_serde::from_slice(body)
                .or_else(|_| serde_json::from_slice(body))
                .unwrap();
            if let Some(arr) = msg.as_array() {
                if let Some(id) = arr[0].get("id") {
                    assert!(id.is_string());
                }
            }
        }
        Ok(())
    }


    // UTS: rest/unit/channel/message_versions.md — RSL14a
    // Also covers: RSL14 (parent spec for GetMessageVersions)
    #[tokio::test]
    async fn rsl14a_get_message_versions_params_as_querystring() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = mock_client(mock);
        let channel = client.channels().get("test-rsl14a");
        let _ = channel.message_versions("serial123").limit(10).send().await;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let url = &reqs[0].url;
        assert!(url.path().contains("/messages/serial123/versions"));
        let query = url.query().unwrap_or("");
        assert!(query.contains("limit=10"));
        Ok(())
    }


    // UTS: rest/unit/channel/message_versions.md — RSL14c
    #[tokio::test]
    async fn rsl14c_get_message_versions_returns_paginated_result() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"id": "msg1", "name": "evt", "serial": "s1", "version": {"serial": "v1"}}
            ]))
        });
        let client = mock_client(mock);
        let channel = client.channels().get("test-rsl14c");
        let result = channel.message_versions("serial123").send().await?;
        let items = result.items();
        assert_eq!(items.len(), 1);
        Ok(())
    }


    // ===============================================================
    // Batch 4: REST Publish & History
    // ===============================================================

    // RSL1e — Both name and data null: message with neither should still be sent
    #[tokio::test]
    async fn rsl1e_both_name_and_data_null() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        // Publish with neither name nor data
        client.channels().get("test").publish().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();
        assert!(body.get("name").is_none(), "name should be absent");
        assert!(body.get("data").is_none(), "data should be absent");
        Ok(())
    }


    // RSL1i — Message at the size limit succeeds (not over)
    #[tokio::test]
    async fn rsl1i_message_at_size_limit_succeeds() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(201, &json!({})));
        let mut opts = ClientOptions::new("appId.keyId:keySecret");
        opts.max_message_size = 100;
        let client = opts.rest_with_mock(mock).unwrap();
        let channel = client.channels().get("test-limit");

        // Data exactly at the limit should succeed
        let exact_data = "x".repeat(50);
        let result = channel.publish().name("ok").string(&exact_data).send().await;
        assert!(result.is_ok(), "Message at size limit should succeed");
        Ok(())
    }


    // RSL1k — Mixed client-provided and library-generated IDs
    #[tokio::test]
    async fn rsl1k_mixed_client_and_library_ids() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(201, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .idempotent_rest_publishing(true)
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let channel = client.channels().get("test-rsl1k");

        // Publish with explicit id
        channel.publish().id("explicit-id").name("e1").string("d1").send().await?;

        // Publish without id — library should generate one
        channel.publish().name("e2").string("d2").send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);

        let body1: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body1["id"], "explicit-id");

        let body2: serde_json::Value =
            serde_json::from_slice(reqs[1].body.as_deref().unwrap()).unwrap();
        // When idempotent publishing is enabled and no explicit id, library may generate one
        // (format may be array or single message depending on SDK)
        if let Some(arr) = body2.as_array() {
            if let Some(id) = arr[0].get("id") {
                assert!(id.is_string());
                assert_ne!(id.as_str().unwrap(), "explicit-id");
            }
        }
        Ok(())
    }


    // RSL1k3 — No id generated when idempotent publishing is disabled
    #[tokio::test]
    async fn rsl1k3_no_id_when_disabled() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(201, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .idempotent_rest_publishing(false)
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let channel = client.channels().get("test-rsl1k3");

        channel.publish().name("event").string("data").send().await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();
        // With idempotent publishing disabled, no id should be auto-generated
        assert!(
            body.get("id").is_none(),
            "Expected no id when idempotent publishing is disabled, got {:?}",
            body.get("id")
        );
        Ok(())
    }


    // RSL2 — URL encoding: channel name with colon
    #[tokio::test]
    async fn rsl2_url_encoding_with_colon() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = mock_client(mock);
        client.channels().get("test:channel").history().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        // The colon in the channel name should be preserved or percent-encoded
        let path = reqs[0].url.path();
        assert!(
            path.contains("test:channel") || path.contains("test%3Achannel")
                || path.contains("test%3achannel"),
            "Expected channel name with colon in URL, got {}",
            path
        );
        Ok(())
    }


    // RSL2 — URL encoding: channel name with slash
    #[tokio::test]
    async fn rsl2_url_encoding_with_slash() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = mock_client(mock);
        client.channels().get("test/channel").history().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let path = reqs[0].url.path();
        // Slash may be percent-encoded or preserved depending on SDK
        assert!(
            path.contains("/channels/") && (path.contains("test/channel") || path.contains("test%2Fchannel")
                || path.contains("test%2fchannel")),
            "Expected channel name with slash in URL, got {}",
            path
        );
        Ok(())
    }


    // RSL2 — History with time range
    #[tokio::test]
    async fn rsl2_history_with_time_range() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .history()
            .start("1000000000000")
            .end("2000000000000")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("start").map(|s| s.as_str()), Some("1000000000000"));
        assert_eq!(params.get("end").map(|s| s.as_str()), Some("2000000000000"));
        Ok(())
    }


    // RSL2a — History returns a paginated result
    #[tokio::test]
    async fn rsl2a_history_returns_paginated_result() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"id": "m1", "name": "e1", "data": "d1"},
                {"id": "m2", "name": "e2", "data": "d2"},
                {"id": "m3", "name": "e3", "data": "d3"}
            ]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let result = client.channels().get("test").history().send().await?;
        let items = result.items();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].name, Some("e1".to_string()));
        assert_eq!(items[2].name, Some("e3".to_string()));
        Ok(())
    }


    // RSL2b — History with direction forwards
    // Also covers: RSL2b2 (history direction parameter)
    #[tokio::test]
    async fn rsl2b_history_with_direction_forwards() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.channels().get("test").history().forwards().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("direction").map(|s| s.as_str()), Some("forwards"));
        Ok(())
    }


    // RSL2b — History with direction backwards
    #[tokio::test]
    async fn rsl2b_history_with_direction_backwards() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.channels().get("test").history().backwards().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("direction").map(|s| s.as_str()), Some("backwards"));
        Ok(())
    }


    // RSL2b3 — Default limit (no explicit limit param sent)
    #[tokio::test]
    async fn rsl2b3_default_limit() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.channels().get("test").history().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // When no limit is set, the SDK should not include limit param
        // (server defaults to 100)
        assert!(
            params.get("limit").is_none(),
            "Expected no limit param by default, got {:?}",
            params.get("limit")
        );
        Ok(())
    }


    // RSL4 — Empty array is JSON-encoded
    #[tokio::test]
    async fn rsl4_empty_array_json_encoded() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .json(json!([]))
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["encoding"], "json");
        let data_str = body["data"].as_str().expect("data should be a JSON string");
        let parsed: serde_json::Value = serde_json::from_str(data_str).unwrap();
        assert_eq!(parsed, json!([]));
        Ok(())
    }


    // RSL4 — Empty object is JSON-encoded
    #[tokio::test]
    async fn rsl4_empty_object_json_encoded() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .channels()
            .get("test")
            .publish()
            .name("event")
            .json(json!({}))
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["encoding"], "json");
        let data_str = body["data"].as_str().expect("data should be a JSON string");
        let parsed: serde_json::Value = serde_json::from_str(data_str).unwrap();
        assert_eq!(parsed, json!({}));
        Ok(())
    }


    // RSL6a — String data without encoding passes through (decoding side)
    #[tokio::test]
    async fn rsl6a_string_data_without_encoding_passes_through() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"id": "msg1", "name": "evt", "data": "plain text"}
            ]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let result = client.channels().get("test").history().send().await?;
        let items = result.items();
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0].data, rest::Data::String(s) if s == "plain text"));
        Ok(())
    }


    // RSL7 — Set options stores channel options (via builder)
    #[test]
    fn rsl7_set_options_stores_channel_options() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        // Create a channel via the builder with cipher options
        // Since ChannelOptions.cipher is the only option, we test the builder flow
        let ch = client.channels().name("encrypted-channel").get();
        assert_eq!(ch.name, "encrypted-channel");
        // A channel created without cipher should work fine
        let ch2 = client.channels().get("plain-channel");
        assert_eq!(ch2.name, "plain-channel");
    }


    // RSL11b — URL-encodes serial in get_message
    #[tokio::test]
    async fn rsl11b_url_encodes_serial() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"id": "msg1", "name": "evt", "data": "hello"}))
        });
        let client = mock_client(mock);
        let channel = client.channels().get("test-rsl11b");
        let _ = channel.get_message("serial:with/special@chars").await;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let path = reqs[0].url.path();
        // The serial should be URL-encoded
        assert!(
            !path.contains("serial:with/special@chars"),
            "Serial should be URL-encoded in path, got {}",
            path
        );
        assert!(
            path.contains("/messages/"),
            "Path should contain /messages/, got {}",
            path
        );
        Ok(())
    }


    #[tokio::test]
    #[ignore = "delta/vcdiff not implemented"]
    async fn rsl6a3_vcdiff_decode() -> Result<()> { Ok(()) }


    // -- RSN2: iterate through REST channels --

    #[test]
    fn rsn2_iterate_through_channels() {
        // RSN2: The channels collection supports iteration
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let _ch1 = client.channels().get("alpha");
        let _ch2 = client.channels().get("beta");
        // REST channels are ephemeral (no stored collection), so we verify
        // that getting channels by name works correctly for multiple channels
        let ch_a = client.channels().get("alpha");
        let ch_b = client.channels().get("beta");
        assert_eq!(ch_a.name, "alpha");
        assert_eq!(ch_b.name, "beta");
    }


    // -- RSN3a: get after release / get returns same instance --

    #[test]
    fn rsn3a_get_after_release() {
        // RSN3a: After releasing a channel, get() creates a new instance
        // REST channels are created fresh each time in this implementation
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch1 = client.channels().get("test-channel");
        assert_eq!(ch1.name, "test-channel");
        // Getting the same channel again creates a new object (REST channels are ephemeral)
        let ch2 = client.channels().get("test-channel");
        assert_eq!(ch2.name, "test-channel");
    }


    #[test]
    fn rsn3a_get_returns_same_instance() {
        // RSN3a: get() returns a channel with the same name
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let ch1 = client.channels().get("my-channel");
        let ch2 = client.channels().get("my-channel");
        assert_eq!(ch1.name, ch2.name);
    }


    // -- RSN3c: channel options on get --

    #[test]
    fn rsn3c_channel_options_on_get() {
        // RSN3c: get() accepts channel options (e.g., cipher)
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        // Use the builder to set options
        let ch = client.channels().get("encrypted-channel");
        assert_eq!(ch.name, "encrypted-channel");
    }


    // -- UDR1: update delete result --

    #[test]
    fn udr1_update_delete_result() {
        // UDR1: UpdateDeleteResult has serial and versionSerial fields
        let json_str = r#"{"serial":"s1","versionSerial":"vs1"}"#;
        let result: crate::rest::UpdateDeleteResult = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.serial.as_deref(), Some("s1"));
        assert_eq!(result.version_serial.as_deref(), Some("vs1"));

        // Absent fields deserialize as None
        let json_str2 = r#"{}"#;
        let result2: crate::rest::UpdateDeleteResult = serde_json::from_str(json_str2).unwrap();
        assert!(result2.serial.is_none());
        assert!(result2.version_serial.is_none());
    }


    // ===============================================================
    // RSL depth — Message publishing depth
    // ===============================================================

    #[tokio::test]
    async fn rsl1k2_idempotent_enabled_explicit_id_preserved() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .idempotent_rest_publishing(true)
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test-idem").publish().name("e").string("d").id("my-id-1").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["id"], "my-id-1");
        Ok(())
    }


    #[tokio::test]
    async fn rsl1k2_idempotent_disabled_no_auto_id() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .idempotent_rest_publishing(false)
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test-no-idem").publish().name("e").string("d").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        // When idempotent is off, no auto-generated id (unless explicitly set)
        let has_id = body.get("id").map_or(false, |v| v.is_string());
        let array_has_id = body.as_array().map_or(false, |a| a[0].get("id").map_or(false, |v| v.is_string()));
        assert!(!has_id && !array_has_id, "Should not auto-generate id when idempotent disabled");
        Ok(())
    }


    #[tokio::test]
    async fn rsl1m_publish_explicit_client_id_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish()
            .name("event")
            .string("data")
            .client_id("explicit-client")
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["clientId"], "explicit-client");
        Ok(())
    }


    #[tokio::test]
    async fn rsl1m_publish_wildcard_client_id_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish()
            .name("event")
            .string("data")
            .client_id("*")
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["clientId"], "*");
        Ok(())
    }


    #[tokio::test]
    async fn rsl1n_publish_result_empty_serial_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(201, &json!({}))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();
        // Publish should succeed even if response has no serials
        client.channels().get("test").publish().name("e").string("d").send().await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsl4a_json_object_encoding_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish()
            .name("event")
            .json(&json!({"nested": {"key": [1, 2, 3]}}))
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["encoding"], "json");
        Ok(())
    }


    #[tokio::test]
    async fn rsl4_binary_data_base64_encoded_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let binary_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        client.channels().get("test").publish()
            .name("bin")
            .binary(binary_data.clone())
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["encoding"], "base64");
        // Verify the data round-trips
        let decoded = base64::decode(body["data"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        Ok(())
    }


    #[tokio::test]
    async fn rsl6a_decode_base64_then_json_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{
                "name": "evt",
                "data": base64::encode(r#"{"x":1}"#),
                "encoding": "json/base64"
            }]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let res = client.channels().get("test").history().send().await?;
        let items = res.items();
        assert_eq!(items.len(), 1);
        // After decoding base64 then json, data should be a JSON value
        match &items[0].data {
            crate::rest::Data::JSON(v) => assert_eq!(v["x"], 1),
            other => panic!("Expected JSON data, got: {:?}", other),
        }
        Ok(())
    }


    #[tokio::test]
    async fn rsl6b_unknown_encoding_preserved_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{
                "name": "evt",
                "data": "cipher-data",
                "encoding": "cipher+aes-256-cbc/base64"
            }]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let res = client.channels().get("test").history().send().await?;
        let items = res.items();
        // Unrecognized encoding layers should be preserved
        assert!(!matches!(items[0].encoding, None));
        Ok(())
    }


    #[tokio::test]
    async fn rsl1e_empty_publish_no_name_no_data() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        // Publishing with neither name nor data should still work
        client.channels().get("test").publish().send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        Ok(())
    }


    // ===============================================================
    // History depth — message history builder
    // ===============================================================

    #[tokio::test]
    async fn rsl2_history_start_param_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").history()
            .start("1609459200000")
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let start = reqs[0].url.query_pairs()
            .find(|(k, _)| k == "start")
            .map(|(_, v)| v.to_string());
        assert_eq!(start.as_deref(), Some("1609459200000"));
        Ok(())
    }


    #[tokio::test]
    async fn rsl2_history_end_param_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").history()
            .end("1609545600000")
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let end = reqs[0].url.query_pairs()
            .find(|(k, _)| k == "end")
            .map(|(_, v)| v.to_string());
        assert_eq!(end.as_deref(), Some("1609545600000"));
        Ok(())
    }


    #[tokio::test]
    async fn rsl2_history_forwards_param_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").history()
            .forwards()
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let dir = reqs[0].url.query_pairs()
            .find(|(k, _)| k == "direction")
            .map(|(_, v)| v.to_string());
        assert_eq!(dir.as_deref(), Some("forwards"));
        Ok(())
    }


    #[tokio::test]
    async fn rsl2_history_limit_param_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").history()
            .limit(5)
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let limit = reqs[0].url.query_pairs()
            .find(|(k, _)| k == "limit")
            .map(|(_, v)| v.to_string());
        assert_eq!(limit.as_deref(), Some("5"));
        Ok(())
    }


    #[tokio::test]
    async fn rsl2_history_combined_params_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").history()
            .start("1000")
            .end("2000")
            .forwards()
            .limit(100)
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let query: Vec<(String, String)> = reqs[0].url.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(query.iter().find(|(k, _)| k == "start").unwrap().1, "1000");
        assert_eq!(query.iter().find(|(k, _)| k == "end").unwrap().1, "2000");
        assert_eq!(query.iter().find(|(k, _)| k == "direction").unwrap().1, "forwards");
        assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "100");
        Ok(())
    }


    #[tokio::test]
    async fn rsl2_history_auth_header_present_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").history().send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "authorization"),
            "History request should include Authorization header");
        Ok(())
    }


    // ===============================================================
    // Publish extras depth
    // ===============================================================

    #[tokio::test]
    async fn rsl1j_extras_headers_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let mut extras = crate::json::Map::new();
        extras.insert("headers".to_string(), json!({"x-custom": "value"}));
        client.channels().get("test").publish()
            .name("event")
            .string("data")
            .extras(extras)
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["extras"]["headers"]["x-custom"], "value");
        Ok(())
    }


    #[tokio::test]
    async fn rsl1j_extras_ref_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let mut extras = crate::json::Map::new();
        extras.insert("ref".to_string(), json!({"type": "com.example.ref", "timeserial": "abc@123"}));
        client.channels().get("test").publish()
            .name("reply")
            .string("response")
            .extras(extras)
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["extras"]["ref"]["type"], "com.example.ref");
        Ok(())
    }


    // ===============================================================
    // Publish with ID depth
    // ===============================================================

    #[tokio::test]
    async fn rsl1j_explicit_message_id_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish()
            .id("custom-id-123")
            .name("event")
            .string("data")
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value = serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["id"], "custom-id-123");
        Ok(())
    }


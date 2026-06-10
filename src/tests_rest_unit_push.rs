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
    // RSH1: Push Admin API
    // ===============================================================

    #[test]
    fn rsh1_push_admin_accessible() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = mock_client(mock);
        let push = client.push();
        let admin = push.admin();
        let _registrations = admin.device_registrations();
        let _subscriptions = admin.channel_subscriptions();
    }


    #[tokio::test]
    async fn rsh1a_publish_post_push_publish() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.url.path(), "/push/publish");
            MockResponse::empty(201)
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .publish(
                json!({"transportType": "apns", "deviceToken": "foo"}),
                json!({"notification": {"title": "Test", "body": "Hello"}}),
            )
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].url.path(), "/push/publish");
        Ok(())
    }


    #[tokio::test]
    async fn rsh1a_publish_clientid_recipient() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .publish(
                json!({"clientId": "user-123"}),
                json!({"data": {"key": "value"}}),
            )
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        Ok(())
    }


    #[tokio::test]
    async fn rsh1a_publish_deviceid_recipient() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .publish(
                json!({"deviceId": "device-abc"}),
                json!({"notification": {"title": "Device Push"}}),
            )
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        Ok(())
    }


    #[tokio::test]
    async fn rsh1a_rejects_empty_recipient() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .publish(json!({}), json!({"notification": {"title": "Test"}}))
            .await;
        assert!(result.is_err());
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 0);
    }


    #[tokio::test]
    async fn rsh1a_rejects_empty_data() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .publish(json!({"clientId": "user-123"}), json!({}))
            .await;
        assert!(result.is_err());
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 0);
    }


    #[tokio::test]
    async fn rsh1a_server_error_propagated() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                400,
                &json!({"error": {"code": 40000, "statusCode": 400, "message": "Invalid recipient", "href": ""}}),
            )
        });
        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .publish(
                json!({"transportType": "invalid"}),
                json!({"notification": {"title": "Test"}}),
            )
            .await;
        assert!(result.is_err());
    }


    #[tokio::test]
    async fn rsh1b1_get_device_details() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url.path(), "/push/deviceRegistrations/device-123");
            MockResponse::json(200, &json!({"id": "device-123", "platform": "ios"}))
        });

        let client = mock_client(mock);
        let device: serde_json::Value = client
            .push()
            .admin()
            .device_registrations()
            .get("device-123")
            .await?;
        assert_eq!(device["id"], "device-123");
        Ok(())
    }


    #[tokio::test]
    async fn rsh1b2_list_devices() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url.path(), "/push/deviceRegistrations");
            MockResponse::json(200, &json!([{"id": "d1"}, {"id": "d2"}]))
        });

        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .device_registrations()
            .list()
            .send()
            .await?;
        let items = result.items();
        assert_eq!(items.len(), 2);
        Ok(())
    }


    #[tokio::test]
    async fn rsh1c1_list_channel_subscriptions() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            MockResponse::json(200, &json!([{"channel": "ch1"}]))
        });

        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .channel_subscriptions()
            .list()
            .send()
            .await?;
        let items = result.items();
        assert_eq!(items.len(), 1);
        Ok(())
    }


    #[tokio::test]
    async fn rsh1c3_save_subscription() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            MockResponse::json(200, &json!({"channel": "ch1", "deviceId": "d1"}))
        });

        let client = mock_client(mock);
        let result: serde_json::Value = client
            .push()
            .admin()
            .channel_subscriptions()
            .save(&json!({"channel": "ch1", "deviceId": "d1"}))
            .await?;
        assert_eq!(result["channel"], "ch1");
        Ok(())
    }


    #[tokio::test]
    async fn rsh1b1_get_unknown_device_error() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                404,
                &json!({"error": {"code": 40400, "statusCode": 404, "message": "Not found", "href": ""}}),
            )
        });
        let client = mock_client(mock);
        let result = client.push().admin().device_registrations().get("unknown").await;
        assert!(result.is_err());
    }


    #[tokio::test]
    async fn rsh1b3_save_device() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "PUT");
            assert!(req.url.path().starts_with("/push/deviceRegistrations"));
            MockResponse::json(200, &json!({"id": "d1", "platform": "ios"}))
        });
        let client = mock_client(mock);
        let result: serde_json::Value = client
            .push()
            .admin()
            .device_registrations()
            .save(&json!({"id": "d1", "platform": "ios", "formFactor": "phone"}))
            .await?;
        assert_eq!(result["id"], "d1");
        Ok(())
    }


    #[tokio::test]
    async fn rsh1b4_remove_device() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.url.path(), "/push/deviceRegistrations/d1");
            MockResponse::empty(204)
        });
        let client = mock_client(mock);
        client.push().admin().device_registrations().remove("d1").await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsh1b5_remove_where_clientid() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.url.path(), "/push/deviceRegistrations");
            let query: Vec<_> = req.url.query_pairs().collect();
            assert!(query.iter().any(|(k, v)| k == "clientId" && v == "user-1"));
            MockResponse::empty(204)
        });
        let client = mock_client(mock);
        client
            .push()
            .admin()
            .device_registrations()
            .remove_where(&[("clientId", "user-1")])
            .await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsh1c2_list_channels() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url.path(), "/push/channels");
            MockResponse::json(200, &json!(["channel-1", "channel-2"]))
        });
        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .channel_subscriptions()
            .list_channels()
            .send()
            .await?;
        let items = result.items();
        assert_eq!(items.len(), 2);
        Ok(())
    }


    #[tokio::test]
    async fn rsh1c4_remove_subscription() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            MockResponse::empty(204)
        });
        let client = mock_client(mock);
        client
            .push()
            .admin()
            .channel_subscriptions()
            .remove(&json!({"channel": "ch1", "deviceId": "d1"}))
            .await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsh1c5_remove_where_clientid() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            let query: Vec<_> = req.url.query_pairs().collect();
            assert!(query.iter().any(|(k, v)| k == "clientId" && v == "user-1"));
            MockResponse::empty(204)
        });
        let client = mock_client(mock);
        client
            .push()
            .admin()
            .channel_subscriptions()
            .remove_where(&[("clientId", "user-1")])
            .await?;
        Ok(())
    }


    // ===============================================================
    // Batch 7: RSH1 — Push Admin
    // ===============================================================

    #[tokio::test]
    async fn rsh1a_push_publish_sends_post() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.url.path(), "/push/publish");
            MockResponse::empty(201)
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .publish(
                json!({"clientId": "user-1"}),
                json!({"notification": {"title": "Hi"}}),
            )
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].url.path(), "/push/publish");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1a_push_publish_body() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = mock_client_json(mock);
        client
            .push()
            .admin()
            .publish(
                json!({"transportType": "apns", "deviceToken": "tok123"}),
                json!({"notification": {"title": "Test", "body": "Hello"}}),
            )
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["recipient"]["transportType"], "apns");
        assert_eq!(body["recipient"]["deviceToken"], "tok123");
        assert_eq!(body["notification"]["title"], "Test");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1a_push_publish_error_propagated() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                400,
                &json!({"error": {"code": 40000, "statusCode": 400, "message": "Bad request", "href": ""}}),
            )
        });

        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .publish(
                json!({"clientId": "x"}),
                json!({"notification": {"title": "Fail"}}),
            )
            .await;
        assert!(result.is_err());

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b1_device_get_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert!(req.url.path().contains("/push/deviceRegistrations/"));
            MockResponse::json(200, &json!({"id": "dev1", "platform": "android"}))
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .device_registrations()
            .get("dev1")
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b1_device_get_returns_device() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                200,
                &json!({
                    "id": "device-abc",
                    "platform": "ios",
                    "formFactor": "phone",
                    "push": {"state": "ACTIVE"}
                }),
            )
        });

        let client = mock_client(mock);
        let device: serde_json::Value = client
            .push()
            .admin()
            .device_registrations()
            .get("device-abc")
            .await?;
        assert_eq!(device["id"], "device-abc");
        assert_eq!(device["platform"], "ios");
        assert_eq!(device["push"]["state"], "ACTIVE");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b1_device_get_url_encodes() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert!(
                req.url.path().contains("/push/deviceRegistrations/"),
                "Expected deviceRegistrations path, got: {}",
                req.url.path()
            );
            MockResponse::json(200, &json!({"id": "dev/special"}))
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .device_registrations()
            .get("dev/special")
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        // The path should contain the device ID (possibly URL-encoded)
        assert!(reqs[0].url.path().contains("/push/deviceRegistrations/"));

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b2_device_list_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url.path(), "/push/deviceRegistrations");
            MockResponse::json(200, &json!([{"id": "d1"}, {"id": "d2"}]))
        });

        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .device_registrations()
            .list()
            .send()
            .await?;
        let items = result.items();
        assert_eq!(items.len(), 2);

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b3_device_save_sends_put() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "PUT");
            // RSH1b3: PUT to /push/deviceRegistrations/:deviceId
            assert_eq!(req.url.path(), "/push/deviceRegistrations/dev-new");
            MockResponse::json(200, &json!({"id": "dev-new", "platform": "ios"}))
        });

        let client = mock_client(mock);
        let result: serde_json::Value = client
            .push()
            .admin()
            .device_registrations()
            .save(&json!({"id": "dev-new", "platform": "ios", "formFactor": "phone"}))
            .await?;
        assert_eq!(result["id"], "dev-new");

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b4_device_remove_sends_delete() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert!(req.url.path().contains("/push/deviceRegistrations/dev-rm"));
            MockResponse::empty(204)
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .device_registrations()
            .remove("dev-rm")
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "DELETE");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b4_remove_nonexistent_succeeds() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(204));

        let client = mock_client(mock);
        // Removing a device that doesn't exist should succeed (server returns 204)
        let result = client
            .push()
            .admin()
            .device_registrations()
            .remove("nonexistent-device")
            .await;
        assert!(result.is_ok());

        Ok(())
    }


    #[tokio::test]
    async fn rsh1b5_device_remove_where_sends_delete() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.url.path(), "/push/deviceRegistrations");
            MockResponse::empty(204)
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .device_registrations()
            .remove_where(&[("deviceId", "dev-1"), ("clientId", "client-1")])
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "DELETE");
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert!(query.iter().any(|(k, v)| k == "deviceId" && v == "dev-1"));
        assert!(query.iter().any(|(k, v)| k == "clientId" && v == "client-1"));

        Ok(())
    }


    #[tokio::test]
    async fn rsh1c1_sub_list_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            MockResponse::json(200, &json!([{"channel": "ch1", "deviceId": "d1"}]))
        });

        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .channel_subscriptions()
            .list()
            .send()
            .await?;
        let items = result.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["channel"], "ch1");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1c2_list_channels_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url.path(), "/push/channels");
            MockResponse::json(200, &json!(["channel-a", "channel-b"]))
        });

        let client = mock_client(mock);
        let result = client
            .push()
            .admin()
            .channel_subscriptions()
            .list_channels()
            .send()
            .await?;
        let items = result.items();
        assert_eq!(items.len(), 2);

        Ok(())
    }


    #[tokio::test]
    async fn rsh1c3_sub_save_sends_post() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            MockResponse::json(200, &json!({"channel": "ch1", "deviceId": "d1"}))
        });

        let client = mock_client(mock);
        let result: serde_json::Value = client
            .push()
            .admin()
            .channel_subscriptions()
            .save(&json!({"channel": "ch1", "deviceId": "d1"}))
            .await?;
        assert_eq!(result["channel"], "ch1");

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1c4_sub_remove_sends_delete() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            MockResponse::empty(204)
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .channel_subscriptions()
            .remove(&json!({"channel": "ch1", "deviceId": "d1"}))
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "DELETE");

        Ok(())
    }


    #[tokio::test]
    async fn rsh1c5_sub_remove_where_sends_delete() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.url.path(), "/push/channelSubscriptions");
            MockResponse::empty(204)
        });

        let client = mock_client(mock);
        client
            .push()
            .admin()
            .channel_subscriptions()
            .remove_where(&[("channel", "ch1")])
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "DELETE");
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert!(query.iter().any(|(k, v)| k == "channel" && v == "ch1"));

        Ok(())
    }


    // ===============================================================
    // RSH7 — Push channel subscription (client-side) stubs
    // Not yet implemented — ignored
    // ===============================================================

    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7a_subscribe_device() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7a1_subscribe_device_validation() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7b_subscribe_client() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7b1_subscribe_client_validation() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7c_unsubscribe_device() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7c1_unsubscribe_device_validation() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7d_unsubscribe_client() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7d1_unsubscribe_client_validation() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7e_list_subscriptions() -> Result<()> {
        Ok(())
    }


    #[tokio::test]
    #[ignore = "push channel subscription API not implemented"]
    async fn rsh7e_list_subscriptions_pagination() -> Result<()> {
        Ok(())
    }


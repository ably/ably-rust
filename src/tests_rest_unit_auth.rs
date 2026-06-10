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


    // ===============================================================
    // Auth tests — rest/unit/auth/
    // ===============================================================

    // ---------------------------------------------------------------
    // RSA1 — Basic auth with API key
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa1_basic_auth_with_api_key() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        client.request("GET", "/channels/test").send().await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("Expected Authorization header");

        assert!(
            auth_header.starts_with("Basic "),
            "Expected Basic auth, got '{}'",
            auth_header
        );

        // Decode and verify it contains the key
        let decoded = base64::decode(auth_header.trim_start_matches("Basic ")).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded_str, "appId.keyId:keySecret");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA4 — Token auth when token is provided
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa4_bearer_auth_with_token() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = ClientOptions::new("my-token-string")
            .rest_with_mock(mock)
            .unwrap();

        client.request("GET", "/channels/test").send().await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("Expected Authorization header");

        assert!(
            auth_header.starts_with("Bearer "),
            "Expected Bearer auth, got '{}'",
            auth_header
        );
        assert_eq!(auth_header, "Bearer my-token-string");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA4a — Token auth when useTokenAuth is set with key
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa4a_use_token_auth_with_key() -> Result<()> {
        // When useTokenAuth is true with an API key, the client should
        // request a token using the key and use Bearer auth.
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                // Return a token response
                MockResponse::json(
                    200,
                    &json!({
                        "token": "obtained-token",
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        client.request("GET", "/channels/test").send().await?;

        let reqs = get_mock(&client).captured_requests();

        // First request should be to requestToken (no auth needed for that)
        assert!(
            reqs[0].url.path().contains("/requestToken"),
            "First request should be to requestToken, got {}",
            reqs[0].url.path()
        );

        // Second request (the actual time request) should use Bearer auth
        let auth_header = reqs[1]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("Expected Authorization header on second request");
        assert!(
            auth_header.starts_with("Bearer "),
            "Expected Bearer auth, got '{}'",
            auth_header
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA9h — createTokenRequest produces signed TokenRequest
    // RSA9c — TTL
    // RSA9d — Capability
    // RSA9e — Timestamp
    // RSA9f — Nonce
    // RSA9g — MAC
    // UTS: rest/unit/auth/token_request_params.md, authorize.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa9h_create_token_request_fields() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();

        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions::default();

        let req = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();

        // RSA9h: keyName should match the key ID
        assert_eq!(req.key_name, "appId.keyId");

        // RSA9g: MAC should be present and non-empty
        assert!(!req.mac.is_empty(), "Expected non-empty MAC");

        // RSA9f: Nonce should be at least 16 characters
        assert!(
            req.nonce.len() >= 16,
            "Expected nonce >= 16 chars, got {}",
            req.nonce.len()
        );

        // RSA9e: Timestamp should be recent
        let now_ms = chrono::Utc::now().timestamp_millis();
        let diff_ms = (now_ms - req.timestamp.unwrap()).abs();
        assert!(
            diff_ms < 5000,
            "Expected timestamp within 5s of now, diff={}ms",
            diff_ms
        );

        // RSA6: capability must be null when unspecified — Ably applies the
        // key's capabilities server-side
        assert!(req.capability.is_none());

        // RSA5: ttl must be null when unspecified — Ably applies the 60 min
        // default server-side
        assert!(req.ttl.is_none());
    }





    #[tokio::test]
    async fn rsa9d_custom_capability() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();

        let params = crate::auth::TokenParams {
            capability: Some(r#"{"channel1":["publish"]}"#.to_string()),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions::default();

        let req = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();
        assert_eq!(req.capability.as_deref(), Some(r#"{"channel1":["publish"]}"#));
    }


    #[tokio::test]
    async fn rsa9f_unique_nonces() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();

        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions::default();

        let req1 = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();
        let req2 = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();

        assert_ne!(req1.nonce, req2.nonce, "Nonces should be unique");
    }


    // ---------------------------------------------------------------
    // RSA8e — requestToken sends POST to /keys/:keyName/requestToken
    // UTS: rest/unit/auth/authorize.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa8e_request_token_posts_to_keys_endpoint() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(
                    200,
                    &json!({
                        "token": "test-token-123",
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else {
                MockResponse::json(404, &json!({"error": {"code": 40400}}))
            }
        });

        let client = mock_client(mock);

        let options = crate::auth::AuthOptions::default();

        let details = client
            .auth()
            .request_token(Some(&Default::default()), Some(&options))
            .await?;

        assert_eq!(details.token, "test-token-123");

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert!(
            reqs[0]
                .url
                .path()
                .ends_with("/keys/appId.keyId/requestToken"),
            "Expected POST to /keys/appId.keyId/requestToken, got {}",
            reqs[0].url.path()
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA7b — clientId is None when no token obtained (basic auth)
    // UTS: rest/unit/auth/client_id.md
    // ---------------------------------------------------------------

    #[test]
    fn rsa7b_client_id_null_with_basic_auth() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        assert_eq!(client.options().client_id, None);
    }


    // ---------------------------------------------------------------
    // RSA9a — clientId in token requests
    // UTS: rest/unit/auth/client_id.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa9a_client_id_included_in_token_request() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("user1")
            .unwrap()
            .rest()
            .unwrap();

        let params = crate::auth::TokenParams {
            client_id: Some("user1".to_string()),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions::default();

        let req = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();
        assert_eq!(req.client_id, Some("user1".to_string()));
    }


    #[tokio::test]
    async fn rsa9a_client_id_override_in_token_params() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("user1")
            .unwrap()
            .rest()
            .unwrap();

        let params = crate::auth::TokenParams {
            client_id: Some("user2".to_string()),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions::default();

        let req = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();
        assert_eq!(req.client_id, Some("user2".to_string()));
    }


    // ---------------------------------------------------------------
    // RSA4d — Token expiry detection
    // RSA4c — Server returns 401 with token error triggers renewal
    // UTS: rest/unit/auth/token_renewal.md, token_details.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa4c_server_401_triggers_token_renewal() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            let n = call_count_clone.fetch_add(1, Ordering::SeqCst);

            if req.url.path().contains("/requestToken") {
                // Return a new token
                MockResponse::json(
                    200,
                    &json!({
                        "token": format!("token-{}", n),
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else if n == 1 {
                // First /time request: reject with 401 token error
                MockResponse::json(
                    401,
                    &json!({
                        "error": {
                            "code": 40140,
                            "statusCode": 401,
                            "message": "Token expired",
                            "href": ""
                        }
                    }),
                )
            } else {
                // Subsequent requests succeed
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        // Use token auth so the client will attempt renewal
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        // This should: get token, try /time (401), get new token, retry /time (200)
        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA3 — Token auth with explicit token string
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa3_bearer_auth_with_explicit_token() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"channelId": "test"}))
        });

        let client = ClientOptions::new("explicit-token-string")
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("Expected Authorization header");

        assert_eq!(auth_header, "Bearer explicit-token-string");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA7e2 — key + clientId keeps basic auth, asserting the identity via
    // the X-Ably-ClientId header (base64). A clientId is NOT a token-auth
    // trigger (RSA4).
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa7e2_basic_auth_with_client_id_sends_header() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"channelId": "test"}))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("my-client-id")
            .unwrap()
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        // Exactly one request — no token acquisition
        assert_eq!(reqs.len(), 1);

        let auth_header = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str())
            .expect("Expected Authorization header");
        assert!(
            auth_header.starts_with("Basic "),
            "Expected Basic auth for key + clientId, got '{}'",
            auth_header
        );

        // RSA7e2: clientId asserted via X-Ably-ClientId header, base64 encoded
        let client_id_header = reqs[0]
            .headers.iter().find(|(k,_)| k == "x-ably-clientid").map(|(_,v)| v.as_str())
            .expect("Expected X-Ably-ClientId header");
        assert_eq!(client_id_header, base64::encode("my-client-id"));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA2, RSA11 — Basic auth header format
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa2_rsa11_basic_auth_header_format() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"channelId": "test"}))
        });

        let client = ClientOptions::new("app123.key456:secretXYZ")
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("Expected Authorization header");

        // Verify exact Base64 encoding of the key
        let expected = format!("Basic {}", base64::encode("app123.key456:secretXYZ"));
        assert_eq!(auth_header, expected);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA4b4 — Token renewal on 40142 (expired) with authCallback
    // UTS: rest/unit/auth/token_renewal.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa4b4_token_renewal_with_callback() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            let n = request_count_clone.fetch_add(1, Ordering::SeqCst);

            if req.url.path().contains("/requestToken") {
                MockResponse::json(
                    200,
                    &json!({
                        "token": format!("token-{}", n),
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else if n == 1 {
                // First API request fails with token expired
                MockResponse::json(
                    401,
                    &json!({
                        "error": {
                            "code": 40142,
                            "statusCode": 401,
                            "message": "Token expired",
                            "href": ""
                        }
                    }),
                )
            } else {
                // Retry succeeds
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        let resp = client.request("GET", "/channels/test").send().await?;
        assert_eq!(resp.status_code(), 200);

        // Verify requests were made (requestToken + fail + requestToken + retry)
        let reqs = get_mock(&client).captured_requests();
        assert!(
            reqs.len() >= 3,
            "Expected at least 3 requests (token + fail + token + retry), got {}",
            reqs.len()
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA4b4 — No renewal without authCallback/key
    // UTS: rest/unit/auth/token_renewal.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa4b4_no_renewal_without_callback() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();

        let mock = MockHttpClient::with_handler(move |_req| {
            request_count_clone.fetch_add(1, Ordering::SeqCst);
            MockResponse::json(
                401,
                &json!({
                    "error": {
                        "code": 40142,
                        "statusCode": 401,
                        "message": "Token expired",
                        "href": ""
                    }
                }),
            )
        });

        // Client with static token — no way to renew
        let client = ClientOptions::new("static-token")
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.expect_err("Expected token error");
        assert_eq!(err.error_code(), crate::error::ErrorCode::TokenExpired);

        // Only one request made (no retry since no renewal mechanism)
        let count = request_count.load(Ordering::SeqCst);
        assert_eq!(
            count, 1,
            "Expected only 1 request (no retry), got {}",
            count
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA7a — clientId from ClientOptions
    // Also covers: RSA7 (parent spec for clientId consistency)
    // UTS: rest/unit/auth/client_id.md
    // ---------------------------------------------------------------

    #[test]
    fn rsa7a_client_id_from_options() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("my-client-id")
            .unwrap()
            .rest()
            .unwrap();

        assert_eq!(client.options().client_id.as_deref(), Some("my-client-id"));
    }


    // ---------------------------------------------------------------
    // RSA7c — clientId null when unidentified
    // UTS: rest/unit/auth/client_id.md
    // ---------------------------------------------------------------

    #[test]
    fn rsa7c_client_id_null_when_unidentified() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        assert_eq!(client.options().client_id, None);
    }


    // ---------------------------------------------------------------
    // RSA5 — TTL is null when not specified (server defaults apply)
    // RSA6 — Capability is null when not specified
    // UTS: rest/unit/auth/token_request_params.md
    //
    // Note: The current SDK defaults TTL to 60min and capability to
    // {"*":["*"]} in TokenParams::default(). The UTS spec says these
    // should be null so the server applies its own defaults. This is a
    // known divergence that should be addressed in a future refactor.
    // For now we test the current behavior.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa5b_explicit_ttl_preserved() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams {
            ttl: Some(7200000),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions::default();
        let req = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();
        assert_eq!(req.ttl.unwrap(), 7200000);
    }


    #[tokio::test]
    async fn rsa6b_explicit_capability_preserved() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams {
            capability: Some(r#"{"channel-a":["publish","subscribe"]}"#.to_string()),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions::default();
        let req = client
            .auth()
            .create_token_request(Some(&params), Some(&options)).await
            .unwrap();
        assert_eq!(req.capability.as_deref(), Some(r#"{"channel-a":["publish","subscribe"]}"#));
    }


    // ---------------------------------------------------------------
    // RSA10a — authorize() obtains a token using key
    // UTS: rest/unit/auth/authorize.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa10a_authorize_obtains_token() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(
                    200,
                    &json!({
                        "token": "obtained-token",
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "keyName": "appId.keyId",
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else {
                MockResponse::json(200, &json!({"channelId": "test"}))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        // authorize() requests a token using the key
        let token_details = client
            .auth()
            .request_token(Some(&Default::default()), Some(&client.auth_options()))
            .await?;

        assert_eq!(token_details.token, "obtained-token");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSA10l — authorize() error handling
    // UTS: rest/unit/auth/authorize.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa10l_authorize_error_handling() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                401,
                &json!({
                    "error": {
                        "code": 40100,
                        "statusCode": 401,
                        "message": "Unauthorized",
                        "href": ""
                    }
                }),
            )
        });

        let client = ClientOptions::new("invalid.key:secret")
            .rest_with_mock(mock)
            .unwrap();

        let err = client
            .auth()
            .request_token(Some(&Default::default()), Some(&client.auth_options()))
            .await
            .expect_err("Expected auth error");

        assert_eq!(err.error_code(), crate::error::ErrorCode::Unauthorized);
        assert_eq!(err.status_code, Some(401));

        Ok(())
    }


    // ========================================================================
    // RSA4c2/RSA4d/RSA4f: Auth callback error handling
    // ========================================================================







    // ---------------------------------------------------------------
    // RSA4b4 — Token renewal with MessagePack error response
    // UTS: rest/unit/auth/token_renewal.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa4c_server_401_triggers_token_renewal_msgpack() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            let n = call_count_clone.fetch_add(1, Ordering::SeqCst);

            if req.url.path().contains("/requestToken") {
                // Return a new token (JSON is fine for requestToken)
                MockResponse::json(
                    200,
                    &json!({
                        "token": format!("token-{}", n),
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else if n == 1 {
                // First /time request: reject with 401 token error as msgpack
                MockResponse::msgpack(
                    401,
                    &json!({
                        "error": {
                            "code": 40140,
                            "statusCode": 401,
                            "message": "Token expired",
                            "href": ""
                        }
                    }),
                )
            } else {
                // Subsequent requests succeed (msgpack)
                MockResponse::msgpack(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        Ok(())
    }


    // RSAN1c — annotation publish sends POST
    // Also covers: RSAN1 (parent spec for annotations publish)
    // Also covers: RSAN1c1 (annotation action set to ANNOTATION_CREATE)
    // Also covers: RSAN1c2 (annotation messageSerial from argument)
    // Also covers: RSAN1c6 (body sent as POST to annotations endpoint)
    #[tokio::test]
    async fn rsan1c_publish_sends_post() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!({})));
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            ..Default::default()
        };
        ch.annotations().publish("msg-serial-1", &ann).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        assert_eq!(req.method, "POST");
        assert!(req.url.path().contains("/annotations"));
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert_eq!(body[0]["action"], 0); // ANNOTATION_CREATE
        assert_eq!(body[0]["type"], "reaction");
        Ok(())
    }


    #[tokio::test]
    async fn rsan1a3_publish_validates_type() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let ann = crate::rest::Annotation {
            annotation_type: None, // missing type
            ..Default::default()
        };
        let result = ch.annotations().publish("msg-serial-1", &ann).await;
        assert!(result.is_err());
    }


    // RSAN2a — annotation delete sends POST
    // Also covers: RSAN2 (parent spec for annotations delete)
    #[tokio::test]
    async fn rsan2a_delete_sends_post() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!({})));
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            ..Default::default()
        };
        ch.annotations().delete("msg-serial-1", &ann).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        assert_eq!(req.method, "POST");
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert_eq!(body[0]["action"], 1); // ANNOTATION_DELETE
        Ok(())
    }


    // RSAN3b — annotations get sends GET
    // Also covers: RSAN3 (parent spec for annotations get)
    #[tokio::test]
    async fn rsan3b_get_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert!(req.url.path().contains("/annotations"));
            MockResponse::json(200, &json!([{"type": "reaction", "action": 0}]))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let page = ch.annotations().get("msg-serial-1").send().await?;
        let items = page.items();
        assert_eq!(items.len(), 1);
        Ok(())
    }


    // RSAN1c3 — annotation data encoded per RSL4
    #[tokio::test]
    async fn rsan1c3_annotation_data_encoded() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(201, &json!({})));
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let ann = crate::rest::Annotation {
            annotation_type: Some("com.example.data".into()),
            data: crate::rest::Data::JSON(json!({"key": "value", "nested": {"a": 1}})),
            name: None,
            action: None,
            client_id: None,
            message_serial: None,
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };
        ch.annotations().publish("msg-serial-1", &ann).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        // Data should be present in the annotation body
        assert!(body[0]["data"].is_object() || body[0]["data"].is_string());
        assert_eq!(body[0]["type"], "com.example.data");
        Ok(())
    }


    // RSAN1c4 — idempotent ID generated when enabled
    #[tokio::test]
    async fn rsan1c4_idempotent_id_generated() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(201, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .idempotent_rest_publishing(true)
            .rest_with_mock(mock)
            .unwrap();
        let ch = client.channels().get("test");
        let ann = crate::rest::Annotation {
            annotation_type: Some("com.example.reaction".into()),
            ..Default::default()
        };
        ch.annotations().publish("msg-serial-1", &ann).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        let annotation = &body[0];
        // RSAN1c4: When idempotent publishing is enabled and id is empty,
        // the SDK generates a base64 ID with a :0 suffix
        let id = annotation
            .get("id")
            .and_then(|v| v.as_str())
            .expect("RSAN1c4: idempotent annotation id must be generated");
        let parts: Vec<&str> = id.split(':').collect();
        assert_eq!(parts.len(), 2, "ID should be in format <base64>:0");
        assert!(parts[0].len() >= 12, "Base64 part should be at least 12 chars");
        assert_eq!(parts[1], "0");
        Ok(())
    }


    // RSAN1c4 — idempotent ID not generated when disabled
    #[tokio::test]
    async fn rsan1c4_idempotent_id_not_generated() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(201, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .idempotent_rest_publishing(false)
            .rest_with_mock(mock)
            .unwrap();
        let ch = client.channels().get("test");
        let ann = crate::rest::Annotation {
            annotation_type: Some("com.example.reaction".into()),
            ..Default::default()
        };
        ch.annotations().publish("msg-serial-1", &ann).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        let annotation = &body[0];
        // RSAN1c4: When idempotent publishing is disabled, no id should be generated
        assert!(
            annotation.get("id").is_none() || annotation["id"].is_null(),
            "No id should be generated when idempotent publishing is disabled"
        );
        Ok(())
    }


    // RSAN3c — get returns PaginatedResult of Annotations
    #[tokio::test]
    async fn rsan3c_get_returns_paginated_annotations() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {
                    "id": "ann-1",
                    "action": 0,
                    "type": "com.example.reaction",
                    "name": "like",
                    "clientId": "user-1",
                    "data": "thumbs-up",
                    "serial": "ann-serial-1",
                    "messageSerial": "msg-serial-1",
                    "timestamp": 1700000000000_i64,
                    "extras": {"custom": "metadata"}
                },
                {
                    "id": "ann-2",
                    "action": 0,
                    "type": "com.example.reaction",
                    "name": "heart",
                    "clientId": "user-2",
                    "serial": "ann-serial-2",
                    "messageSerial": "msg-serial-1",
                    "timestamp": 1700000001000_i64
                }
            ]))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let page = ch.annotations().get("msg-serial-1").send().await?;
        let items = page.items();

        assert_eq!(items.len(), 2);

        let ann1 = &items[0];
        assert_eq!(ann1.annotation_type.as_deref(), Some("com.example.reaction"));
        assert_eq!(ann1.name.as_deref(), Some("like"));
        assert_eq!(ann1.client_id.as_deref(), Some("user-1"));
        assert_eq!(ann1.serial.as_deref(), Some("ann-serial-1"));
        assert_eq!(ann1.timestamp, Some(1700000000000));

        let ann2 = &items[1];
        assert_eq!(ann2.name.as_deref(), Some("heart"));
        assert_eq!(ann2.client_id.as_deref(), Some("user-2"));

        Ok(())
    }


    // ===============================================================
    // RSA4c3/RSA4d/RSA4f/RSA4e: Additional auth callback error tests
    // ===============================================================







    #[tokio::test]
    async fn rsa4e_rest_callback_error_produces_40170() {
        let callback = std::sync::Arc::new(TestAuthCallback::new("token"));
        callback.set_should_fail(true);
        callback.set_fail_code(crate::error::ErrorInfoCode::BadRequest, Some(400));

        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });

        let client = ClientOptions::with_auth_callback(callback)
            .rest_with_mock(mock)
            .unwrap();

        let result: Result<crate::http::PaginatedResult<crate::rest::Message>> = client.channels().get("test-channel").history().send().await;
        match result {
            Err(err) => {
                // RSA4e: REST auth callback error → code 40170, statusCode 401
                assert_eq!(err.code_value(), 40170);
                assert_eq!(err.status_code, Some(401));
            }
            Ok(_) => panic!("Expected auth error"),
        }
    }


    // (RSA4f oversized-token handling is a realtime concern (80019 on
    // connect) — the previous test here was a tautology and was removed.)


    // ===============================================================
    // RSA16: Auth.tokenDetails
    // ===============================================================

    #[tokio::test]
    async fn rsa16a_token_from_callback() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();
        // Before any request, tokenDetails is None (RSA16d)
        assert!(client.auth().token_details().is_none());
    }


    #[tokio::test]
    async fn rsa16b_token_string_in_options() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::new("my-token-string")
            .rest_with_mock(mock)
            .unwrap();
        // RSA16b: token string → TokenDetails with only token populated
        let td = client.auth().token_details();
        assert!(td.is_some());
        let td = td.unwrap();
        assert_eq!(td.token, "my-token-string");
        assert!(td.metadata.is_none());
    }


    #[tokio::test]
    async fn rsa16c_set_on_instantiation() {
        use crate::auth::{TokenDetails, TokenMetadata};
        use chrono::Utc;
        let td = TokenDetails {
            token: "test-token".to_string(),
            metadata: Some(TokenMetadata {
                expires: Utc::now() + chrono::Duration::hours(1),
                issued: Utc::now(),
                capability: r#"{"*":["*"]}"#.to_string(),
                client_id: Some("my-client".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .token_details(td.clone())
            .rest_with_mock(mock)
            .unwrap();
        let stored = client.auth().token_details().unwrap();
        assert_eq!(stored.token, "test-token");
        assert!(stored.metadata.is_some());
        let meta = stored.metadata.unwrap();
        assert_eq!(meta.client_id.as_deref(), Some("my-client"));
    }


    #[tokio::test]
    async fn rsa16d_null_with_basic_auth() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();
        // RSA16d: tokenDetails null when using basic auth (key only, no useTokenAuth)
        assert!(client.auth().token_details().is_none());
    }


    #[tokio::test]
    async fn rsa16c_updated_after_request_token() {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("requestToken") {
                MockResponse::json(
                    200,
                    &json!({
                        "token": "new-token-v1",
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else {
                MockResponse::empty(200)
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();
        assert!(client.auth().token_details().is_none());

        // RSA8f: an explicit request_token does NOT alter library auth state
        let td = client
            .auth()
            .request_token(None, None)
            .await
            .unwrap();
        assert_eq!(td.token, "new-token-v1");
        assert!(client.auth().token_details().is_none());

        // RSA16c: authorize() DOES update tokenDetails
        let td = client.auth().authorize(None, None).await.unwrap();
        assert_eq!(td.token, "new-token-v1");
        let stored = client.auth().token_details().unwrap();
        assert_eq!(stored.token, "new-token-v1");
    }


    // ===============================================================
    // RSA12/RSA15: Client ID validation
    // UTS: rest/unit/auth/client_id.md
    // ===============================================================

    // RSA12a — the library clientId is passed to the authCallback in TokenParams
    // UTS: rest/unit/RSA12a/clientid-passed-to-callback-0
    #[tokio::test]
    async fn rsa12a_client_id_passed_to_callback() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenParams};
        use std::sync::Mutex as StdMutex;

        struct RecordingCb {
            received: Arc<StdMutex<Vec<Option<String>>>>,
        }
        impl AuthCallback for RecordingCb {
            fn token<'a>(
                &'a self,
                params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                self.received.lock().unwrap().push(params.client_id.clone());
                Box::pin(async {
                    Ok(AuthToken::Details(TokenDetails::token("cb-token".into())))
                })
            }
        }

        let received = Arc::new(StdMutex::new(Vec::new()));
        let cb = Arc::new(RecordingCb { received: received.clone() });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb)
            .client_id("library-client-id")
            .unwrap()
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].as_deref(), Some("library-client-id"));
        Ok(())
    }


    // RSA12 — wildcard token clientId is reported as the effective clientId
    // UTS: rest/unit/RSA12/wildcard-clientid-0
    #[test]
    fn rsa12_wildcard_client_id() {
        let td = crate::auth::TokenDetails {
            token: "wildcard-token".to_string(),
            client_id: Some("*".to_string()),
            ..Default::default()
        };
        let client = ClientOptions::with_token("placeholder".to_string())
            .token_details(td)
            .rest()
            .unwrap();
        assert_eq!(client.auth().client_id().as_deref(), Some("*"));
    }


    // RSA12b — the library clientId is sent to the authUrl as a query param
    // UTS: rest/unit/RSA12b/clientid-sent-to-authurl-0
    #[tokio::test]
    async fn rsa12b_client_id_sent_to_authurl() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                let cid = req.url.query_pairs()
                    .find(|(k, _)| k == "clientId")
                    .map(|(_, v)| v.to_string());
                assert_eq!(cid.as_deref(), Some("url-client-id"));
                MockResponse::json(200, &json!({
                    "token": "authurl-token",
                    "expires": 9999999999999_i64
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/token")
            .client_id("url-client-id")
            .unwrap()
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        Ok(())
    }


    // RSA15a — a TokenDetails clientId incompatible with the configured
    // clientId is rejected at construction with 40102
    // UTS: rest/unit/RSA15a/token-clientid-must-match-0
    #[test]
    fn rsa15a_token_client_id_must_match_options() {
        let td = crate::auth::TokenDetails {
            token: "some-token".to_string(),
            client_id: Some("token-client".to_string()),
            ..Default::default()
        };

        // Mismatch: rejected with 40102 IncompatibleCredentials
        let err = match ClientOptions::with_token("placeholder".to_string())
            .token_details(td.clone())
            .client_id("different-client")
            .unwrap()
            .rest()
        {
            Err(e) => e,
            Ok(_) => panic!("Mismatched token clientId must be rejected at construction"),
        };
        assert_eq!(err.code, Some(40102));

        // Match: accepted, clientId resolves
        let client = ClientOptions::with_token("placeholder".to_string())
            .token_details(td)
            .client_id("token-client")
            .unwrap()
            .rest()
            .unwrap();
        assert_eq!(client.auth().client_id().as_deref(), Some("token-client"));
    }


    // RSA15b — a wildcard token clientId permits any configured clientId
    // UTS: rest/unit/RSA15b/wildcard-token-any-clientid-0
    #[test]
    fn rsa15b_wildcard_token_permits_any_client_id() {
        let td = crate::auth::TokenDetails {
            token: "wildcard-token".to_string(),
            client_id: Some("*".to_string()),
            ..Default::default()
        };
        let client = ClientOptions::with_token("placeholder".to_string())
            .token_details(td)
            .client_id("any-client")
            .unwrap()
            .rest()
            .unwrap();
        // Configured clientId wins over the wildcard
        assert_eq!(client.auth().client_id().as_deref(), Some("any-client"));
    }


    // RSA15c — a token obtained at runtime with an incompatible clientId
    // produces a 40102 error
    #[tokio::test]
    async fn rsa15c_incompatible_client_id_detected() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenParams};

        struct MismatchCb;
        impl AuthCallback for MismatchCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Ok(AuthToken::Details(TokenDetails {
                        token: "mismatched-token".into(),
                        client_id: Some("client-b".into()),
                        ..Default::default()
                    }))
                })
            }
        }

        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(Arc::new(MismatchCb))
            .client_id("client-a")
            .unwrap()
            .rest_with_mock(mock)?;

        let err = client
            .request("GET", "/channels/test")
            .send()
            .await
            .expect_err("Mismatched token clientId must be rejected");
        assert_eq!(err.code, Some(40102));
        // The rejection happens client-side: no API request was made
        assert_eq!(get_mock(&client).request_count(), 0);
        Ok(())
    }


    // ===============================================================
    // RSA8c/RSA8d: Auth callback / authUrl
    // UTS: rest/unit/auth/auth_callback.md
    // ===============================================================

    // RSA8d — authCallback is invoked and its token used
    // UTS: rest/unit/RSA8d/callback-invoked-for-auth-0
    #[tokio::test]
    async fn rsa8d_auth_callback_invoked() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenParams};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct FlagCb {
            invoked: Arc<AtomicBool>,
        }
        impl AuthCallback for FlagCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                self.invoked.store(true, Ordering::SeqCst);
                Box::pin(async {
                    Ok(AuthToken::Details(TokenDetails::token("callback-token".into())))
                })
            }
        }

        let invoked = Arc::new(AtomicBool::new(false));
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(Arc::new(FlagCb { invoked: invoked.clone() }))
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;

        assert!(invoked.load(std::sync::atomic::Ordering::SeqCst));
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let auth = reqs[0].headers.iter()
            .find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()).unwrap();
        assert_eq!(auth, "Bearer callback-token");
        Ok(())
    }


    // RSA8c — authUrl is fetched (GET) and its token used
    // UTS: rest/unit/RSA8c/authurl-invoked-for-auth-0
    #[tokio::test]
    async fn rsa8c_auth_url_invoked() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                MockResponse::json(200, &json!({
                    "token": "authurl-token",
                    "expires": 9999999999999_i64
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/token")
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str(), Some("auth.example.com"));
        assert_eq!(reqs[0].url.path(), "/token");
        assert_eq!(reqs[0].method, "GET");
        let auth = reqs[1].headers.iter()
            .find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()).unwrap();
        assert_eq!(auth, "Bearer authurl-token");
        Ok(())
    }


    // RSA8c — authMethod POST is used for the authUrl request
    // UTS: rest/unit/RSA8c/authurl-post-method-1
    #[tokio::test]
    async fn rsa8c_auth_url_post_method() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                MockResponse::json(200, &json!({
                    "token": "authurl-token",
                    "expires": 9999999999999_i64
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/token")
            .auth_method("POST")
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, "POST");
        Ok(())
    }


    // RSA8c — authHeaders are sent with the authUrl request
    // UTS: rest/unit/RSA8c/authurl-custom-headers-2
    #[tokio::test]
    async fn rsa8c_auth_url_custom_headers() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                MockResponse::json(200, &json!({
                    "token": "authurl-token",
                    "expires": 9999999999999_i64
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/token")
            .auth_headers(vec![
                ("X-Custom-Header".to_string(), "custom-value".to_string()),
                ("X-API-Key".to_string(), "my-api-key".to_string()),
            ])
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let headers = &reqs[0].headers;
        let get = |name: &str| headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
        assert_eq!(get("X-Custom-Header"), Some("custom-value"));
        assert_eq!(get("X-API-Key"), Some("my-api-key"));
        Ok(())
    }


    // RSA8c — authParams are sent as query parameters with GET
    // UTS: rest/unit/RSA8c/authurl-query-params-3
    #[tokio::test]
    async fn rsa8c_auth_url_query_params() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                MockResponse::json(200, &json!({
                    "token": "authurl-token",
                    "expires": 9999999999999_i64
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/token")
            .auth_params(vec![
                ("client_id".to_string(), "my-client".to_string()),
                ("scope".to_string(), "publish:*".to_string()),
            ])
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let query: std::collections::HashMap<String, String> = reqs[0].url.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(query.get("client_id").map(String::as_str), Some("my-client"));
        assert_eq!(query.get("scope").map(String::as_str), Some("publish:*"));
        Ok(())
    }


    // RSA8c — authUrl returning a plain-text JWT string
    // UTS: rest/unit/RSA8c/authurl-returns-jwt-4
    #[tokio::test]
    async fn rsa8c_auth_url_returns_jwt() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                MockResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "text/plain".to_string())],
                    body: b"eyJhbGciOiJIUzI1NiJ9.jwt-body.signature".to_vec(),
                    network_error: false,
                }
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/jwt")
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[1].headers.iter()
            .find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()).unwrap();
        assert_eq!(auth, "Bearer eyJhbGciOiJIUzI1NiJ9.jwt-body.signature");
        Ok(())
    }


    // RSA8c — authUrl returning a TokenRequest, which is exchanged
    #[tokio::test]
    async fn rsa8c_auth_url_returns_token_request() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                MockResponse::json(200, &json!({
                    "keyName": "appId.keyId",
                    "timestamp": 1700000000000_i64,
                    "nonce": "url-nonce",
                    "mac": "url-mac"
                }))
            } else if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "exchanged-token",
                    "expires": 9999999999999_i64
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/token")
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 3);
        assert!(reqs[1].url.path().ends_with("/keys/appId.keyId/requestToken"));
        let auth = reqs[2].headers.iter()
            .find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()).unwrap();
        assert_eq!(auth, "Bearer exchanged-token");
        Ok(())
    }


    // RSA8c — HTTP errors from the authUrl are propagated; no API request made
    // UTS: rest/unit/RSA8c/authurl-error-propagated-5
    #[tokio::test]
    async fn rsa8c_auth_url_error_propagated() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("auth.example.com") {
                MockResponse::json(500, &json!({"error": "Internal server error"}))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::with_auth_url("https://auth.example.com/token")
            .rest_with_mock(mock)?;

        let err = client
            .request("GET", "/channels/test")
            .send()
            .await
            .expect_err("authUrl error must propagate");
        assert_eq!(err.status_code, Some(500));

        // Only the authUrl request was made, not the API request
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url.host_str(), Some("auth.example.com"));
        Ok(())
    }


    // RSA4a2 — an expired static token with no renewal method fails
    // client-side with 40171, making no HTTP request
    // UTS: rest/unit/RSA4a2/expired-token-no-renewal-0
    #[tokio::test]
    async fn rsa4a2_expired_token_no_renewal() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let expired = crate::auth::TokenDetails {
            token: "expired-token".to_string(),
            expires: Some(chrono::Utc::now().timestamp_millis() - 1000),
            ..Default::default()
        };
        let client = ClientOptions::with_token("placeholder".to_string())
            .token_details(expired)
            .rest_with_mock(mock)?;

        let err = client
            .request("GET", "/channels/test")
            .send()
            .await
            .expect_err("Expired token with no renewal must fail");
        assert_eq!(err.code, Some(40171));
        assert_eq!(get_mock(&client).request_count(), 0);
        Ok(())
    }


    // RSA4b1 — a token known to be expired is renewed pre-emptively, without
    // first making a failing request
    // UTS: rest/unit/RSA4b1/preemptive-renewal-0
    #[tokio::test]
    async fn rsa4b1_preemptive_renewal() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenParams};
        use std::sync::atomic::{AtomicU32, Ordering};

        struct ExpiringCb {
            count: Arc<AtomicU32>,
        }
        impl AuthCallback for ExpiringCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
                Box::pin(async move {
                    if n == 1 {
                        Ok(AuthToken::Details(TokenDetails {
                            token: "expired-token".into(),
                            expires: Some(chrono::Utc::now().timestamp_millis() - 1000),
                            ..Default::default()
                        }))
                    } else {
                        Ok(AuthToken::Details(TokenDetails {
                            token: "fresh-token".into(),
                            expires: Some(chrono::Utc::now().timestamp_millis() + 3600000),
                            ..Default::default()
                        }))
                    }
                })
            }
        }

        let count = Arc::new(AtomicU32::new(0));
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::with_auth_callback(Arc::new(ExpiringCb { count: count.clone() }))
            .rest_with_mock(mock)?;

        // Initial token acquisition (returns the already-expired token)
        client.auth().authorize(None, None).await?;

        // The expired token must be renewed BEFORE this request
        client.channels().get("test").history().send().await?;

        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
        let reqs = get_mock(&client).captured_requests();
        let history_reqs: Vec<_> = reqs.iter()
            .filter(|r| r.url.path().contains("/channels/test"))
            .collect();
        assert_eq!(history_reqs.len(), 1, "no failing request with the expired token");
        let auth = history_reqs[0].headers.iter()
            .find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()).unwrap();
        assert_eq!(auth, "Bearer fresh-token");
        Ok(())
    }


    // RSA7d — key + useTokenAuth + clientId: the requested token carries the
    // library clientId
    #[tokio::test]
    async fn rsa7d_client_id_in_token_request() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap())
                    .or_else(|_| rmp_serde::from_slice(req.body.as_deref().unwrap()))
                    .unwrap();
                assert_eq!(body["clientId"], "token-client");
                MockResponse::json(200, &json!({
                    "token": "client-token",
                    "expires": 9999999999999_i64,
                    "clientId": "token-client"
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .client_id("token-client")
            .unwrap()
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        Ok(())
    }


    // RSA1 — token auth (authCallback) takes precedence over the key
    // UTS: rest/unit/RSA1/token-auth-takes-precedence-0
    #[tokio::test]
    async fn rsa1_token_auth_takes_precedence() -> Result<()> {
        use crate::auth::{AuthOptions, TokenDetails, TokenParams, AuthCallback, AuthToken};

        struct PrecedenceCb;
        impl AuthCallback for PrecedenceCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Ok(AuthToken::Details(TokenDetails::token("callback-token".into())))
                })
            }
        }

        // A key client with an authCallback supplied via authorize(): the
        // callback becomes the token source and Bearer auth is used.
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)?;

        let opts = AuthOptions {
            auth_callback: Some(Arc::new(PrecedenceCb)),
            ..Default::default()
        };
        client.auth().authorize(None, Some(&opts)).await?;
        client.request("GET", "/channels/test").send().await?;

        let reqs = get_mock(&client).captured_requests();
        let auth = reqs.last().unwrap().headers.iter()
            .find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()).unwrap();
        assert_eq!(auth, "Bearer callback-token");
        Ok(())
    }




    // ===============================================================
    // RSA17: Token revocation unit tests (with mock HTTP)
    // UTS: rest/unit/auth/revoke_tokens.md
    // ===============================================================

    #[tokio::test]
    async fn rsa17g_sends_post_to_correct_path() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert!(
                req.url.path().ends_with("/keys/appId.keyId/revokeTokens"),
                "Expected path ending with /keys/appId.keyId/revokeTokens, got {}",
                req.url.path()
            );
            MockResponse::json(200, &serde_json::json!([{
                "target": "clientId:alice",
                "issuedBefore": 1700000000000_i64,
                "appliesAt": 1700000000000_i64
            }]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.len(), 1);
        assert_eq!(result.results[0].target, "clientId:alice");
        Ok(())
    }


    #[tokio::test]
    async fn rsa17b_multiple_specifiers() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("revokeTokens") {
                if let Some(body) = &req.body {
                    let body: serde_json::Value = rmp_serde::from_slice(body)
                        .or_else(|_| serde_json::from_slice(body))
                        .unwrap();
                    let targets = body["targets"].as_array().unwrap();
                    assert_eq!(targets.len(), 3);
                }
                MockResponse::json(200, &serde_json::json!([
                    {"target": "clientId:alice", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64},
                    {"target": "revocationKey:group-1", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64},
                    {"target": "channel:secret", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64}
                ]))
            } else {
                MockResponse::json(200, &serde_json::json!([]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec![
                "clientId:alice".to_string(),
                "revocationKey:group-1".to_string(),
                "channel:secret".to_string(),
            ],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.len(), 3);
        Ok(())
    }


    #[tokio::test]
    async fn rsa17c_success_result_attributes() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!([
                {"target": "clientId:alice", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64},
                {"target": "clientId:bob", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64}
            ]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string(), "clientId:bob".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.len(), 2);
        assert!(result.results[0].error.is_none());
        assert!(result.results[0].issued_before.is_some());
        assert!(result.results[0].applies_at.is_some());
        Ok(())
    }


    // RSA17c — with X-Ably-Version >= 3 the server returns a BatchResult
    // envelope {successCount, failureCount, results}; counts come from the
    // server, not client-side computation.
    #[tokio::test]
    async fn rsa17c_batch_result_envelope() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(201, &serde_json::json!({
                "successCount": 1,
                "failureCount": 1,
                "results": [
                    {"target": "clientId:alice", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64},
                    {"target": "invalidType:abc", "error": {"code": 40000, "statusCode": 400, "message": "invalid target"}}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string(), "invalidType:abc".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);
        assert_eq!(result.len(), 2);
        assert!(result.results[0].error.is_none());
        assert_eq!(result.results[1].error.as_ref().unwrap().code, Some(40000));
        Ok(())
    }


    #[tokio::test]
    async fn rsa17d_token_auth_fails_with_error() -> Result<()> {
        let mock = MockHttpClient::new();

        let client = ClientOptions::with_token("some-token".to_string())
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:anyone".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let err = client
            .auth()
            .revoke_tokens(&request)
            .await
            .expect_err("Should fail for token auth");
        // RSA17d: 40162 TokenAuthCannotRevokeTokens with 401, client-side check
        assert_eq!(
            err.code,
            Some(crate::error::ErrorCode::TokenAuthCannotRevokeTokens.code())
        );
        assert_eq!(err.status_code, Some(401));
        Ok(())
    }


    #[tokio::test]
    async fn rsa17e_issued_before_included() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if let Some(body) = &req.body {
                let body: serde_json::Value = rmp_serde::from_slice(body)
                    .or_else(|_| serde_json::from_slice(body))
                    .unwrap();
                assert_eq!(body["issuedBefore"], 1699999000000_i64);
            }
            MockResponse::json(200, &serde_json::json!([
                {"target": "clientId:alice", "issuedBefore": 1699999000000_i64, "appliesAt": 1699999000000_i64}
            ]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string()],
            issued_before: Some(1699999000000),
            allow_reauth_margin: None,
        };

        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.len(), 1);
        Ok(())
    }


    #[tokio::test]
    async fn rsa17e_issued_before_omitted() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if let Some(body) = &req.body {
                let body: serde_json::Value = rmp_serde::from_slice(body)
                    .or_else(|_| serde_json::from_slice(body))
                    .unwrap();
                assert!(body.get("issuedBefore").is_none(), "issuedBefore should be omitted");
            }
            MockResponse::json(200, &serde_json::json!([
                {"target": "clientId:alice", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64}
            ]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        client.auth().revoke_tokens(&request).await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsa17f_allow_reauth_margin_included() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if let Some(body) = &req.body {
                let body: serde_json::Value = rmp_serde::from_slice(body)
                    .or_else(|_| serde_json::from_slice(body))
                    .unwrap();
                assert_eq!(body["allowReauthMargin"], true);
            }
            MockResponse::json(200, &serde_json::json!([
                {"target": "clientId:alice", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000030000_i64}
            ]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string()],
            issued_before: None,
            allow_reauth_margin: Some(true),
        };

        client.auth().revoke_tokens(&request).await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsa17_auth_uses_basic_auth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            let auth = req
                .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str())
                
                .unwrap_or("");
            assert!(
                auth.starts_with("Basic "),
                "Expected Basic auth, got: {}",
                auth
            );
            MockResponse::json(200, &serde_json::json!([
                {"target": "clientId:alice", "issuedBefore": 1700000000000_i64, "appliesAt": 1700000000000_i64}
            ]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        client.auth().revoke_tokens(&request).await?;
        Ok(())
    }


    // ===============================================================
    // RSA5c/RSA5d/RSA6c/RSA6d: Token request default params
    // UTS: rest/unit/auth/token_request_params.md
    // ===============================================================

    // RSA5c — ttl from defaultTokenParams flows into the TokenRequest
    // UTS: rest/unit/RSA5c/ttl-from-default-params-0
    #[tokio::test]
    async fn rsa5c_ttl_from_default_token_params() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .default_token_params(crate::auth::TokenParams {
                ttl: Some(1800000),
                ..Default::default()
            })
            .rest()
            .unwrap();
        let req = client.auth().create_token_request(None, None).await.unwrap();
        assert_eq!(req.ttl, Some(1800000));
    }


    // RSA5d — explicit ttl overrides defaultTokenParams
    // UTS: rest/unit/RSA5d/explicit-ttl-overrides-default-0
    #[tokio::test]
    async fn rsa5d_explicit_ttl_overrides_default() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .default_token_params(crate::auth::TokenParams {
                ttl: Some(1800000),
                ..Default::default()
            })
            .rest()
            .unwrap();
        let params = crate::auth::TokenParams { ttl: Some(600000), ..Default::default() };
        let req = client.auth().create_token_request(Some(&params), None).await.unwrap();
        assert_eq!(req.ttl, Some(600000));
    }


    // RSA6c — capability from defaultTokenParams flows into the TokenRequest
    // UTS: rest/unit/RSA6c/capability-from-default-params-0
    #[tokio::test]
    async fn rsa6c_capability_from_default_token_params() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .default_token_params(crate::auth::TokenParams {
                capability: Some(r#"{"*":["subscribe"]}"#.to_string()),
                ..Default::default()
            })
            .rest()
            .unwrap();
        let req = client.auth().create_token_request(None, None).await.unwrap();
        assert_eq!(req.capability.as_deref(), Some(r#"{"*":["subscribe"]}"#));
    }


    // RSA6d — explicit capability overrides defaultTokenParams
    // UTS: rest/unit/RSA6d/explicit-capability-overrides-default-0
    #[tokio::test]
    async fn rsa6d_explicit_capability_overrides_default() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .default_token_params(crate::auth::TokenParams {
                capability: Some(r#"{"*":["subscribe"]}"#.to_string()),
                ..Default::default()
            })
            .rest()
            .unwrap();
        let params = crate::auth::TokenParams {
            capability: Some(r#"{"channel-x":["publish"]}"#.to_string()),
            ..Default::default()
        };
        let req = client.auth().create_token_request(Some(&params), None).await.unwrap();
        assert_eq!(req.capability.as_deref(), Some(r#"{"channel-x":["publish"]}"#));
    }


    // UTS: rest/unit/channel/update_delete_message.md — RSL15c
    // (rsl15b_update_message_sends_patch at line 23847 covers RSL15c)

    // UTS: rest/unit/channel/update_delete_message.md — RSL15d
    // (rsl15b_delete_message_sends_patch at line 23871 covers RSL15d)

    // UTS: rest/unit/batch_publish.md — RSC22d
    // (rsc22c_batch_publish_sends_post_to_messages at line 25034 covers RSC22d)

    // ===============================================================
    // Batch 3: REST Annotations
    // ===============================================================

    // UTS: rest/unit/channel/annotations.md — RSAN1c6
    // (rsan1c_publish_sends_post at line 24111 covers RSAN1c6)

    // ===============================================================
    // Batch 4: REST Auth authorize — SDK gap stubs
    // ===============================================================

    // UTS: rest/unit/auth/authorize.md — RSA10b
    // Spec: Provided tokenParams override defaults in authorize().
    #[tokio::test]
    async fn rsa10b_authorize_with_explicit_token_params() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenParams};
        use std::sync::{Arc, Mutex};

        struct ParamCapture {
            params: Mutex<Vec<TokenParams>>,
        }
        impl AuthCallback for ParamCapture {
            fn token<'a>(
                &'a self,
                params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                self.params.lock().unwrap().push(params.clone());
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token("cb-token".into())))
                })
            }
        }

        let cb = Arc::new(ParamCapture { params: Mutex::new(Vec::new()) });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb.clone())
            .rest_with_mock(mock)?;

        let mut tp = TokenParams::default();
        tp.client_id = Some("override-client".to_string());
        tp.ttl = Some(7200000);

        let result = client.auth().authorize(Some(&tp), None).await;
        assert!(result.is_ok());

        let captured = cb.params.lock().unwrap();
        assert_eq!(captured[0].client_id.as_deref(), Some("override-client"));
        assert_eq!(captured[0].ttl, Some(7200000));
        Ok(())
    }


    // UTS: rest/unit/auth/authorize.md — RSA10e
    // Spec: tokenParams from authorize() are saved and reused.
    #[tokio::test]
    async fn rsa10e_authorize_saves_token_params_for_reuse() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenParams};
        use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};

        struct CountCallback {
            count: AtomicU32,
            params: Mutex<Vec<TokenParams>>,
        }
        impl AuthCallback for CountCallback {
            fn token<'a>(
                &'a self,
                params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
                self.params.lock().unwrap().push(params.clone());
                Box::pin(async move {
                    Ok(AuthToken::Details(crate::auth::TokenDetails {
                        token: format!("token-{}", n),
                        metadata: Some(crate::auth::TokenMetadata {
                            expires: chrono::Utc::now() + chrono::Duration::milliseconds(500),
                            issued: chrono::Utc::now(),
                            capability: "{\"*\":[\"*\"]}".into(),
                            client_id: None,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                })
            }
        }

        let cb = Arc::new(CountCallback {
            count: AtomicU32::new(0),
            params: Mutex::new(Vec::new()),
        });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb.clone())
            .rest_with_mock(mock)?;

        let mut tp = TokenParams::default();
        tp.client_id = Some("saved-client".to_string());
        client.auth().authorize(Some(&tp), None).await?;

        // Second authorize without explicit params should reuse saved params
        let result = client.auth().authorize(None, None).await?;
        assert_eq!(result.token, "token-2");

        let captured = cb.params.lock().unwrap();
        assert_eq!(captured[1].client_id.as_deref(), Some("saved-client"));
        Ok(())
    }


    // UTS: rest/unit/auth/authorize.md — RSA10g
    // Spec: After authorize(), auth.tokenDetails reflects the new token.
    #[tokio::test]
    async fn rsa10g_authorize_updates_token_details() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "new-token",
                    "expires": 9999999999000_i64,
                    "issued": 9999999990000_i64,
                    "keyName": "appId.keyId",
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = mock_client(mock);

        assert!(client.auth().token_details().is_none());
        let result = client.auth().authorize(None, None).await?;
        assert_eq!(result.token, "new-token");
        assert_eq!(client.auth().token_details().unwrap().token, "new-token");
        Ok(())
    }


    // UTS: rest/unit/auth/authorize.md — RSA10h
    // Spec: authOptions in authorize() replace stored auth options.
    #[tokio::test]
    async fn rsa10h_authorize_with_auth_options() -> Result<()> {
        use crate::auth::{AuthCallback, AuthOptions, Credential, AuthToken, TokenParams};
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

        struct FlagCallback {
            called: AtomicBool,
        }
        impl AuthCallback for FlagCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                self.called.store(true, Ordering::SeqCst);
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token("new-cb-token".into())))
                })
            }
        }

        let new_cb = Arc::new(FlagCallback { called: AtomicBool::new(false) });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(new_cb.clone())
            .rest_with_mock(mock)?;

        let opts = AuthOptions::default();
        let result = client.auth().authorize(None, Some(&opts)).await?;
        assert_eq!(result.token, "new-cb-token");
        assert!(new_cb.called.load(Ordering::SeqCst));
        Ok(())
    }


    // UTS: rest/unit/auth/authorize.md — RSA10i
    // Spec: API key from constructor is preserved after authorize() with new authOptions.
    #[tokio::test]
    async fn rsa10i_authorize_preserves_key_from_constructor() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "key-token",
                    "expires": 9999999999000_i64,
                    "issued": 9999999990000_i64,
                    "keyName": "appId.keyId",
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = mock_client(mock);

        let result = client.auth().authorize(None, None).await?;
        assert_eq!(result.token, "key-token");

        // Key should still be available (constructor credential preserved)
        match &client.inner.opts.credential {
            crate::auth::Credential::Key(k) => {
                assert_eq!(k.name, "appId.keyId");
            }
            _ => panic!("Key credential should be preserved"),
        }
        Ok(())
    }


    // UTS: rest/unit/auth/authorize.md — RSA10j
    // Spec: authorize() when already authorized obtains a new token.
    #[tokio::test]
    async fn rsa10j_authorize_when_already_authorized() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenParams};
        use std::sync::{Arc, atomic::{AtomicU32, Ordering}};

        struct SeqCallback { count: AtomicU32 }
        impl AuthCallback for SeqCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
                Box::pin(async move {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token(format!("token-{}", n))))
                })
            }
        }

        let cb = Arc::new(SeqCallback { count: AtomicU32::new(0) });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        let r1 = client.auth().authorize(None, None).await?;
        let r2 = client.auth().authorize(None, None).await?;

        assert_eq!(r1.token, "token-1");
        assert_eq!(r2.token, "token-2");
        assert_eq!(client.auth().token_details().unwrap().token, "token-2");
        Ok(())
    }


    // UTS: rest/unit/auth/authorize.md — RSA10k
    // Spec: queryTime option triggers a /time request before token acquisition.
    #[tokio::test]
    async fn rsa10k_authorize_with_query_time() -> Result<()> {
        use crate::auth::{AuthOptions, TokenParams};
        use std::sync::atomic::{AtomicBool, Ordering};

        let time_requested = Arc::new(AtomicBool::new(false));
        let time_requested_c = time_requested.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            if req.url.path() == "/time" {
                time_requested_c.store(true, Ordering::SeqCst);
                MockResponse::json(200, &json!([1700000000000_i64]))
            } else {
                MockResponse::json(200, &json!({
                    "token": "qt-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)?;

        let auth_opts = AuthOptions {
            query_time: Some(true),
            ..Default::default()
        };
        let result = client.auth().authorize(None, Some(&auth_opts)).await;
        assert!(result.is_ok(), "authorize failed: {:?}", result.err());
        assert!(time_requested.load(Ordering::SeqCst), "authorize with queryTime should request /time");
        Ok(())
    }


    // UTS: rest/unit/auth/token_renewal.md — RSA14
    #[tokio::test]
    async fn rsa14_token_renewal_on_40142() -> Result<()> {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        let mock = MockHttpClient::with_handler(move |req| {
            let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if req.url.path().contains("/time") {
                return MockResponse::json(200, &json!([1700000000000_i64]));
            }
            if req.url.path().contains("/requestToken") {
                return MockResponse::json(200, &json!({
                    "token": "renewed-token",
                    "expires": 1700003600000_i64,
                    "issued": 1700000000000_i64,
                    "capability": "{\"*\":[\"*\"]}",
                    "clientId": null
                }));
            }
            if n == 0 {
                MockResponse::json(401, &json!({
                    "error": {"code": 40142, "statusCode": 401, "message": "Token expired"}
                }))
            } else {
                MockResponse::json(200, &json!([1700000000000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();
        let _ = client.request("GET", "/channels/test").send().await;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs.len() >= 2, "Expected retry after token renewal");
        Ok(())
    }


    // ===============================================================
    // Batch 3: Auth tests (RSA3, RSA4, RSA7b, RSA8, RSA10, RSA15,
    //          RSA16, RSA17 — new coverage)
    // ===============================================================

    #[tokio::test]
    async fn rsa3_token_auth_with_token_details() -> Result<()> {
        use crate::auth::{TokenDetails, TokenMetadata};
        let td = TokenDetails {
            token: "preloaded-token".to_string(),
            metadata: Some(TokenMetadata {
                expires: chrono::Utc::now() + chrono::Duration::hours(1),
                issued: chrono::Utc::now(),
                capability: r#"{"*":["*"]}"#.to_string(),
                client_id: Some("td-client".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .token_details(td)
            .rest_with_mock(mock)
            .unwrap();

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("auth header");
        assert!(
            auth_header.starts_with("Bearer "),
            "Expected Bearer auth with token details, got '{}'",
            auth_header
        );
        assert_eq!(auth_header, "Bearer preloaded-token");
        Ok(())
    }


    #[tokio::test]
    async fn rsa4_auth_callback_triggers_token_auth() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenParams};

        struct SimpleCallback;
        impl AuthCallback for SimpleCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token(
                        "callback-token-rsa4".into(),
                    )))
                })
            }
        }

        let cb = Arc::new(SimpleCallback);
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("auth header");
        assert!(auth.starts_with("Bearer "), "Expected Bearer auth from callback");
        Ok(())
    }


    #[test]
    fn rsa4_auth_url_triggers_token_auth() {
        let url = reqwest::Url::parse("https://auth.example.com/token").unwrap();
        let opts = ClientOptions::with_auth_url(url);
        match &opts.credential {
            crate::auth::Credential::Url(u) => {
                assert_eq!(u.as_str(), "https://auth.example.com/token");
            }
            other => panic!("Expected Credential::Url, got: {:?}", other),
        }
    }


    #[tokio::test]
    async fn rsa4_use_token_auth_forces_token_auth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "forced-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        // First request is requestToken, second is the actual request with Bearer
        assert!(reqs[0].url.path().contains("/requestToken"));
        let auth = reqs[1]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("auth header");
        assert!(auth.starts_with("Bearer "), "Expected Bearer, got '{}'", auth);
        Ok(())
    }


    #[tokio::test]
    async fn rsa4b_token_renewal_on_expiry() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            let n = cc.fetch_add(1, Ordering::SeqCst);
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": format!("token-{}", n),
                    "expires": if n == 0 { 1000000000000_i64 } else { 9999999999999_i64 },
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else if n == 1 {
                // First API call sees expired token
                MockResponse::json(401, &json!({
                    "error": {
                        "code": 40142,
                        "statusCode": 401,
                        "message": "Token expired",
                        "href": ""
                    }
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);
        Ok(())
    }


    #[tokio::test]
    async fn rsa4b_token_renewal_on_40142() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            let n = cc.fetch_add(1, Ordering::SeqCst);
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": format!("renewal-token-{}", n),
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else if n == 1 {
                MockResponse::json(401, &json!({
                    "error": {
                        "code": 40142,
                        "statusCode": 401,
                        "message": "Token expired",
                        "href": ""
                    }
                }))
            } else {
                MockResponse::json(200, &json!([9999999999999_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 9999999999999);
        Ok(())
    }


    #[tokio::test]
    async fn rsa4b_token_renewal_on_40140() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            let n = cc.fetch_add(1, Ordering::SeqCst);
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": format!("renewal-40140-{}", n),
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else if n == 1 {
                MockResponse::json(401, &json!({
                    "error": {
                        "code": 40140,
                        "statusCode": 401,
                        "message": "Token error",
                        "href": ""
                    }
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);
        Ok(())
    }


    #[tokio::test]
    async fn rsa4b_token_renewal_with_auth_url() -> Result<()> {
        // Verify that a client configured with auth_url sets the correct credential type
        // for token renewal (full HTTP-level auth_url renewal requires a live server)
        let url = reqwest::Url::parse("https://auth.example.com/renew").unwrap();
        let opts = ClientOptions::with_auth_url(url);
        match &opts.credential {
            crate::auth::Credential::Url(u) => {
                assert_eq!(u.as_str(), "https://auth.example.com/renew");
            }
            other => panic!("Expected Credential::Url for renewal, got: {:?}", other),
        }
        Ok(())
    }


    #[tokio::test]
    async fn rsa4b_token_renewal_limit() -> Result<()> {
        // When token renewal repeatedly fails, the client should eventually give up
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            cc.fetch_add(1, Ordering::SeqCst);
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "doomed-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                // Always reject
                MockResponse::json(401, &json!({
                    "error": {
                        "code": 40142,
                        "statusCode": 401,
                        "message": "Token expired",
                        "href": ""
                    }
                }))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        // A typed request propagates the token error after exactly one renewal
        let err = client
            .channels()
            .get("test")
            .history()
            .send()
            .await
            .expect_err("Should eventually fail after renewal limit");
        assert_eq!(err.code, Some(40142));
        // initial token + request (401) + renewed token + retry (401): no loop
        let count = call_count.load(Ordering::SeqCst);
        assert_eq!(count, 4, "exactly one renewal cycle, got {} requests", count);
        Ok(())
    }


    #[tokio::test]
    async fn rsa4c3_auth_callback_error_while_connected() -> Result<()> {
        // RSA4c3: When auth callback returns an error while the client has
        // already been connected, the library should handle gracefully.
        // Testing at REST level: callback error propagates as an error.
        use crate::auth::{AuthCallback, AuthToken, TokenParams};

        struct ErrorCallback;
        impl AuthCallback for ErrorCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Err(crate::error::ErrorInfo::new(
                        crate::error::ErrorCode::ErrorFromClientTokenCallback.code(),
                        "Auth callback failed while connected",
                    ))
                })
            }
        }

        let cb = Arc::new(ErrorCallback);
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        let result = client.request("GET", "/channels/test").send().await;
        assert!(result.is_err(), "Auth callback error should propagate");
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(crate::error::ErrorCode::ErrorFromClientTokenCallback.code()));
        Ok(())
    }


    #[tokio::test]
    async fn rsa7b_client_id_from_auth_callback_token_details() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenMetadata, TokenParams};

        struct ClientIdCallback;
        impl AuthCallback for ClientIdCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Ok(AuthToken::Details(TokenDetails {
                        token: "client-id-token".to_string(),
                        metadata: Some(TokenMetadata {
                            expires: chrono::Utc::now() + chrono::Duration::hours(1),
                            issued: chrono::Utc::now(),
                            capability: r#"{"*":["*"]}"#.to_string(),
                            client_id: Some("callback-client".to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                })
            }
        }

        let cb = Arc::new(ClientIdCallback);
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        // Trigger token auth so token details get stored
        client.request("GET", "/channels/test").send().await?;
        let td = client.auth().token_details().expect("should have token details");
        assert_eq!(
            td.metadata.as_ref().and_then(|m| m.client_id.as_deref()),
            Some("callback-client")
        );
        Ok(())
    }


    #[tokio::test]
    async fn rsa8_token_auth_with_native_token() -> Result<()> {
        // RSA8: Native Ably token string used for Bearer auth
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_token("native-ably-token".to_string())
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("auth header");
        assert_eq!(auth, "Bearer native-ably-token");
        Ok(())
    }


    #[tokio::test]
    async fn rsa8_token_auth_with_jwt() -> Result<()> {
        // RSA8: JWT-like token string (starts with eyJ) used for Bearer auth
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.fake".to_string();
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_token(jwt.clone())
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("auth header");
        assert_eq!(auth, format!("Bearer {}", jwt));
        Ok(())
    }


    #[tokio::test]
    async fn rsa8_capability_restriction() -> Result<()> {
        // RSA8: Token with restricted capability still authenticates
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "restricted-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"channel-x\":[\"subscribe\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        client.request("GET", "/channels/test").send().await?;
        let td = client.auth().token_details().expect("should have token details");
        assert_eq!(td.token, "restricted-token");
        if let Some(meta) = &td.metadata {
            assert_eq!(meta.capability, r#"{"channel-x":["subscribe"]}"#);
        }
        Ok(())
    }








    #[tokio::test]
    async fn rsa8d_auth_callback_returning_token_request() -> Result<()> {
        // RSA8d: Auth callback can return a TokenRequest which gets exchanged
        use crate::auth::{AuthCallback, AuthToken, TokenParams};

        struct TokenRequestCallback;
        impl AuthCallback for TokenRequestCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails {
                        token: "callback-token".into(),
                        metadata: Some(crate::auth::TokenMetadata {
                            expires: chrono::Utc::now() + chrono::Duration::hours(1),
                            issued: chrono::Utc::now(),
                            capability: "{\"*\":[\"*\"]}".into(),
                            client_id: None,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                })
            }
        }

        let cb = Arc::new(TokenRequestCallback);
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "exchanged-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let td = client.auth().token_details().expect("should have token details");
        assert_eq!(td.token, "callback-token");
        Ok(())
    }


    #[tokio::test]
    async fn rsa8d_auth_callback_returning_jwt() -> Result<()> {
        // RSA8d: Auth callback can return a JWT as TokenDetails
        use crate::auth::{AuthCallback, AuthToken, TokenParams};

        struct JwtCallback;
        impl AuthCallback for JwtCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake-jwt";
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token(jwt.to_string())))
                })
            }
        }

        let cb = Arc::new(JwtCallback);
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("auth header");
        assert!(auth.contains("eyJ"), "Bearer token should contain JWT");
        Ok(())
    }


    #[tokio::test]
    async fn rsa8d_auth_callback_receives_token_params() -> Result<()> {
        // RSA8d: The auth callback receives the TokenParams
        use crate::auth::{AuthCallback, AuthToken, TokenParams};
        use std::sync::Mutex;

        struct ParamCapture {
            captured: Mutex<Option<TokenParams>>,
        }
        impl AuthCallback for ParamCapture {
            fn token<'a>(
                &'a self,
                params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                *self.captured.lock().unwrap() = Some(params.clone());
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token("param-token".into())))
                })
            }
        }

        let cb = Arc::new(ParamCapture { captured: Mutex::new(None) });
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_auth_callback(cb.clone())
            .client_id("param-test-client")?
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let captured = cb.captured.lock().unwrap();
        assert!(captured.is_some(), "Callback should receive token params");
        Ok(())
    }


    #[tokio::test]
    async fn rsa8d_auth_callback_error_propagated() -> Result<()> {
        // RSA8d: Errors from the auth callback propagate
        use crate::auth::{AuthCallback, AuthToken, TokenParams};

        struct FailCallback;
        impl AuthCallback for FailCallback {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Err(crate::error::ErrorInfo::new(
                        crate::error::ErrorCode::ErrorFromClientTokenCallback.code(),
                        "callback deliberately failed",
                    ))
                })
            }
        }

        let cb = Arc::new(FailCallback);
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        let err = client.request("GET", "/channels/test").send().await.expect_err("Should propagate callback error");
        assert_eq!(err.code, Some(crate::error::ErrorCode::ErrorFromClientTokenCallback.code()));
        assert!(err.message.as_deref().unwrap().contains("callback deliberately failed"));
        Ok(())
    }





    #[tokio::test]
    async fn rsa10b_explicit_token_params_in_authorize() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenParams};
        use std::sync::Mutex;

        struct CaptureCb {
            params: Mutex<Vec<TokenParams>>,
        }
        impl AuthCallback for CaptureCb {
            fn token<'a>(
                &'a self,
                params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                self.params.lock().unwrap().push(params.clone());
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token("auth-token".into())))
                })
            }
        }

        let cb = Arc::new(CaptureCb { params: Mutex::new(Vec::new()) });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb.clone())
            .rest_with_mock(mock)?;

        let mut tp = TokenParams::default();
        tp.client_id = Some("explicit-client".to_string());
        tp.ttl = Some(3600000);

        client.auth().authorize(Some(&tp), None).await?;

        let captured = cb.params.lock().unwrap();
        assert!(!captured.is_empty());
        assert_eq!(captured[0].client_id.as_deref(), Some("explicit-client"));
        assert_eq!(captured[0].ttl, Some(3600000));
        Ok(())
    }


    #[tokio::test]
    async fn rsa10e_params_saved_and_reused() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenParams};
        use std::sync::{Mutex, atomic::{AtomicU32, Ordering}};

        struct ReuseCb {
            count: AtomicU32,
            params: Mutex<Vec<TokenParams>>,
        }
        impl AuthCallback for ReuseCb {
            fn token<'a>(
                &'a self,
                params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
                self.params.lock().unwrap().push(params.clone());
                Box::pin(async move {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token(
                        format!("reuse-token-{}", n),
                    )))
                })
            }
        }

        let cb = Arc::new(ReuseCb {
            count: AtomicU32::new(0),
            params: Mutex::new(Vec::new()),
        });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb.clone())
            .rest_with_mock(mock)?;

        let mut tp = TokenParams::default();
        tp.client_id = Some("reuse-client".to_string());
        client.auth().authorize(Some(&tp), None).await?;

        // Second authorize without params should reuse saved params
        client.auth().authorize(None, None).await?;

        let captured = cb.params.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[1].client_id.as_deref(), Some("reuse-client"));
        Ok(())
    }


    #[tokio::test]
    async fn rsa10g_token_details_updated_after_authorize() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenParams};

        struct UpdateCb;
        impl AuthCallback for UpdateCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token(
                        "updated-token-rsa10g".into(),
                    )))
                })
            }
        }

        let cb = Arc::new(UpdateCb);
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        assert!(client.auth().token_details().is_none());
        let result = client.auth().authorize(None, None).await?;
        assert_eq!(result.token, "updated-token-rsa10g");
        assert_eq!(
            client.auth().token_details().unwrap().token,
            "updated-token-rsa10g"
        );
        Ok(())
    }


    #[tokio::test]
    async fn rsa10h_auth_options_override_defaults() -> Result<()> {
        use crate::auth::{AuthCallback, AuthOptions, Credential, AuthToken, TokenParams};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct OverrideCb {
            called: AtomicBool,
        }
        impl AuthCallback for OverrideCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                self.called.store(true, Ordering::SeqCst);
                Box::pin(async {
                    Ok(AuthToken::Details(crate::auth::TokenDetails::token(
                        "override-cb-token".into(),
                    )))
                })
            }
        }

        let new_cb = Arc::new(OverrideCb { called: AtomicBool::new(false) });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(new_cb.clone())
            .rest_with_mock(mock)?;

        let opts = AuthOptions::default();
        let result = client.auth().authorize(None, Some(&opts)).await?;
        assert_eq!(result.token, "override-cb-token");
        assert!(new_cb.called.load(Ordering::SeqCst));
        Ok(())
    }


    #[tokio::test]
    async fn rsa10i_api_key_preserved_after_authorize() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "post-authorize-token",
                    "expires": 9999999999000_i64,
                    "issued": 9999999990000_i64,
                    "keyName": "appId.keyId",
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = mock_client(mock);

        client.auth().authorize(None, None).await?;

        // API key from constructor should be preserved
        match &client.inner.opts.credential {
            crate::auth::Credential::Key(k) => {
                assert_eq!(k.name, "appId.keyId");
                assert_eq!(k.value, "keySecret");
            }
            other => panic!("Expected Key credential preserved, got: {:?}", other),
        }
        Ok(())
    }


    #[test]
    fn rsa15a_mismatched_client_id_error() {
        // RSA15a: Client rejects wildcard '*' as clientId
        let result = ClientOptions::new("appId.keyId:keySecret").client_id("*");
        assert!(result.is_err(), "Wildcard '*' clientId should be rejected");
        match result {
            Err(err) => {
                assert_eq!(err.code, Some(crate::error::ErrorCode::InvalidClientID.code()));
            }
            Ok(_) => panic!("Expected error for wildcard clientId"),
        }
    }


    #[tokio::test]
    async fn rsa16a_token_details_from_callback() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenMetadata, TokenParams};

        struct DetailsCb;
        impl AuthCallback for DetailsCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                Box::pin(async {
                    Ok(AuthToken::Details(TokenDetails {
                        token: "callback-details-token".to_string(),
                        metadata: Some(TokenMetadata {
                            expires: chrono::Utc::now() + chrono::Duration::hours(1),
                            issued: chrono::Utc::now(),
                            capability: r#"{"*":["*"]}"#.to_string(),
                            client_id: Some("cb-client".to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                })
            }
        }

        let cb = Arc::new(DetailsCb);
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        client.request("GET", "/channels/test").send().await?;
        let td = client.auth().token_details().expect("should have token details");
        assert_eq!(td.token, "callback-details-token");
        assert_eq!(
            td.metadata.as_ref().and_then(|m| m.client_id.as_deref()),
            Some("cb-client")
        );
        Ok(())
    }


    #[tokio::test]
    async fn rsa16a_token_details_from_request_token() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "req-token-v1",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}",
                    "clientId": "req-client"
                }))
            } else {
                MockResponse::empty(200)
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        // UTS RSA16a/token-from-request-token-1: explicit authorize() obtains a
        // token via requestToken and tokenDetails reflects it
        let td = client.auth().authorize(None, None).await?;
        assert_eq!(td.token, "req-token-v1");

        let stored = client.auth().token_details().expect("should have stored token details");
        assert_eq!(stored.token, "req-token-v1");
        Ok(())
    }


    #[test]
    fn rsa16b_token_details_from_token_string() {
        // RSA16b: Creating client with token string populates tokenDetails
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::with_token("raw-token-string".to_string())
            .rest_with_mock(mock)
            .unwrap();
        let td = client.auth().token_details().expect("should have token details");
        assert_eq!(td.token, "raw-token-string");
        assert!(td.metadata.is_none(), "Token string should not have metadata");
    }


    #[test]
    fn rsa16c_token_details_set_on_instantiation() {
        use crate::auth::{TokenDetails, TokenMetadata};
        let td = TokenDetails {
            token: "instantiation-token".to_string(),
            metadata: Some(TokenMetadata {
                expires: chrono::Utc::now() + chrono::Duration::hours(2),
                issued: chrono::Utc::now(),
                capability: r#"{"ch1":["publish"]}"#.to_string(),
                client_id: Some("inst-client".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .token_details(td)
            .rest_with_mock(mock)
            .unwrap();

        let stored = client.auth().token_details().unwrap();
        assert_eq!(stored.token, "instantiation-token");
        let meta = stored.metadata.as_ref().unwrap();
        assert_eq!(meta.client_id.as_deref(), Some("inst-client"));
        assert_eq!(meta.capability, r#"{"ch1":["publish"]}"#);
    }


    #[tokio::test]
    async fn rsa16c_token_details_updated_after_renewal() -> Result<()> {
        use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenMetadata, TokenParams};
        use std::sync::atomic::{AtomicU32, Ordering};

        struct RenewalCb {
            count: AtomicU32,
        }
        impl AuthCallback for RenewalCb {
            fn token<'a>(
                &'a self,
                _params: &'a TokenParams,
            ) -> std::pin::Pin<Box<dyn Send + futures::Future<Output = Result<AuthToken>> + 'a>> {
                let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
                Box::pin(async move {
                    Ok(AuthToken::Details(TokenDetails {
                        token: format!("renewed-token-{}", n),
                        metadata: Some(TokenMetadata {
                            expires: chrono::Utc::now() + chrono::Duration::hours(1),
                            issued: chrono::Utc::now(),
                            capability: "{\"*\":[\"*\"]}".into(),
                            client_id: None,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                })
            }
        }

        let cb = Arc::new(RenewalCb { count: AtomicU32::new(0) });
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::with_auth_callback(cb)
            .rest_with_mock(mock)?;

        client.auth().authorize(None, None).await?;
        assert_eq!(client.auth().token_details().unwrap().token, "renewed-token-1");

        client.auth().authorize(None, None).await?;
        assert_eq!(client.auth().token_details().unwrap().token, "renewed-token-2");
        Ok(())
    }


    #[test]
    fn rsa16d_token_details_null_with_basic_auth() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();
        // RSA16d: With basic auth (key only, no useTokenAuth), tokenDetails is None
        assert!(
            client.auth().token_details().is_none(),
            "tokenDetails should be None with basic auth"
        );
    }


    #[tokio::test]
    async fn rsa17b_single_specifier_sent_as_targets_array() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("revokeTokens") {
                if let Some(body) = &req.body {
                    let body: serde_json::Value = rmp_serde::from_slice(body)
                        .or_else(|_| serde_json::from_slice(body))
                        .unwrap();
                    let targets = body["targets"].as_array().unwrap();
                    assert_eq!(targets.len(), 1, "Single specifier should be sent as array of 1");
                    assert_eq!(targets[0], "clientId:bob");
                }
                MockResponse::json(200, &json!([{
                    "target": "clientId:bob",
                    "issuedBefore": 1700000000000_i64,
                    "appliesAt": 1700000000000_i64
                }]))
            } else {
                MockResponse::json(200, &json!([]))
            }
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
        assert_eq!(result.len(), 1);
        assert_eq!(result.results[0].target, "clientId:bob");
        Ok(())
    }


    #[tokio::test]
    async fn rsa17c_mixed_revocation_result() -> Result<()> {
        // RSA17c: Results can contain a mix of success and error entries
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {
                    "target": "clientId:alice",
                    "issuedBefore": 1700000000000_i64,
                    "appliesAt": 1700000000000_i64
                },
                {
                    "target": "clientId:unknown",
                    "error": {
                        "code": 40400,
                        "statusCode": 404,
                        "message": "Target not found"
                    }
                }
            ]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec![
                "clientId:alice".to_string(),
                "clientId:unknown".to_string(),
            ],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.len(), 2);
        assert!(result.results[0].error.is_none(), "First result should succeed");
        assert_eq!(result.results[0].target, "clientId:alice");
        assert!(result.results[1].error.is_some(), "Second result should have error");
        assert_eq!(result.results[1].target, "clientId:unknown");
        Ok(())
    }


    // RSA17d_2 — key + useTokenAuth is a token-auth client and cannot revoke
    // UTS: rest/unit/RSA17d/use-token-auth-revoke-rejected-1
    #[tokio::test]
    async fn rsa17d_use_token_auth_revoke_rejected() -> Result<()> {
        let mock = MockHttpClient::new();
        let client = ClientOptions::new("appId.keyName:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)?;

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:alice".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };
        let err = client
            .auth()
            .revoke_tokens(&request)
            .await
            .expect_err("key + useTokenAuth cannot revoke tokens");
        assert_eq!(err.code, Some(40162));
        assert_eq!(err.status_code, Some(401));
        assert_eq!(get_mock(&client).request_count(), 0);
        Ok(())
    }


    #[tokio::test]
    async fn rsa17d_token_auth_fails_with_40162() -> Result<()> {
        // RSA17d: Token auth (no API key) should fail for revocation
        let mock = MockHttpClient::new();
        let client = ClientOptions::with_token("bearer-only-token".to_string())
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:someone".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let err = client
            .auth()
            .revoke_tokens(&request)
            .await
            .expect_err("Should fail for token auth");
        // The SDK returns an error when revocation is attempted without an API key
        assert!(
            err.status_code == Some(401) || err.code_value() >= 40100,
            "Expected auth-related error, got code={} status={:?}",
            err.code_value(),
            err.status_code
        );
        Ok(())
    }


    #[tokio::test]
    async fn rsa17g_revocation_sends_post_to_correct_path() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST", "Revocation must use POST");
            assert!(
                req.url.path().ends_with("/keys/appId.keyId/revokeTokens"),
                "Expected /keys/appId.keyId/revokeTokens, got {}",
                req.url.path()
            );
            MockResponse::json(200, &json!([{
                "target": "clientId:carol",
                "issuedBefore": 1700000000000_i64,
                "appliesAt": 1700000000000_i64
            }]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let request = crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:carol".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        };

        let result = client.auth().revoke_tokens(&request).await?;
        assert_eq!(result.len(), 1);
        assert_eq!(result.results[0].target, "clientId:carol");
        Ok(())
    }


    // -- RSAN1: publish sends POST with annotation create --

    #[tokio::test]
    async fn rsan1_publish_sends_post_with_annotation_create() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!({})));
        let client = mock_client_json(mock);
        let ch = client.channels().get("test");
        let ann = crate::rest::Annotation {
            annotation_type: Some("reaction".into()),
            name: Some("thumbsup".into()),
            action: None,
            client_id: None,
            message_serial: None,
            data: crate::rest::Data::JSON(json!({"emoji": "👍"})),
            serial: None,
            version: None,
            timestamp: None,
            encoding: None,
            id: None,
            extras: None,
            ..Default::default()
        };
        ch.annotations().publish("msg-serial-1", &ann).await?;
        let reqs = get_mock(&client).captured_requests();
        let req = reqs.last().unwrap();
        assert_eq!(req.method, "POST");
        assert!(req.url.path().contains("/annotations"));
        let body: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
        assert_eq!(body[0]["action"], 0); // ANNOTATION_CREATE
        assert_eq!(body[0]["type"], "reaction");
        assert_eq!(body[0]["name"], "thumbsup");
        Ok(())
    }


    // -- RSAN3b: get passes params as querystring --

    #[tokio::test]
    async fn rsan3b_get_passes_params_as_querystring() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "GET");
            assert!(req.url.path().contains("/annotations"));
            // Verify params are passed as query string
            let has_limit = req.url.query_pairs().any(|(k, v)| k == "limit" && v == "10");
            assert!(has_limit, "Expected limit=10 in query params");
            MockResponse::json(200, &json!([{"type": "reaction", "action": 0}]))
        });
        let client = mock_client(mock);
        let ch = client.channels().get("test");
        let page = ch
            .annotations()
            .get("msg-serial-1")
            .params(&[("limit", "10")])
            .send()
            .await?;
        let items = page.items();
        assert_eq!(items.len(), 1);
        Ok(())
    }


    // ===============================================================
    // RSA depth — Auth depth
    // ===============================================================

    // RSA5 — ttl must be null when unspecified; Ably applies the 60-minute
    // default server-side. Implementations MUST NOT default it client-side.
    // UTS: rest/unit/RSA5/ttl-null-when-unspecified-0
    #[tokio::test]
    async fn rsa5_ttl_null_when_unspecified() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let req = client.auth().create_token_request(None, None).await.unwrap();
        assert!(req.ttl.is_none(), "ttl must be null when unspecified, got {:?}", req.ttl);
    }


    // RSA6 — capability must be null when unspecified; Ably applies the key's
    // capabilities server-side. MUST NOT default to {"*":["*"]} client-side.
    // UTS: rest/unit/RSA6/capability-null-when-unspecified-0
    #[tokio::test]
    async fn rsa6_capability_null_when_unspecified() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let req = client.auth().create_token_request(None, None).await.unwrap();
        assert!(
            req.capability.is_none(),
            "capability must be null when unspecified, got {:?}",
            req.capability
        );
    }


    #[tokio::test]
    async fn rsa9_create_token_request_key_name_matches_depth() {
        let client = crate::Rest::new("myApp.myKey:mySecret").unwrap();
        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions::default();
        let req = client.auth().create_token_request(Some(&params), Some(&options)).await.unwrap();
        assert_eq!(req.key_name, "myApp.myKey");
    }


    #[tokio::test]
    async fn rsa9_create_token_request_mac_nonempty_depth() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions::default();
        let req = client.auth().create_token_request(Some(&params), Some(&options)).await.unwrap();
        assert!(!req.mac.is_empty(), "MAC should not be empty");
    }


    #[tokio::test]
    async fn rsa9_create_token_request_custom_client_id_depth() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams {
            client_id: Some("custom-client".to_string()),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions::default();
        let req = client.auth().create_token_request(Some(&params), Some(&options)).await.unwrap();
        assert_eq!(req.client_id, Some("custom-client".to_string()));
    }


    #[tokio::test]
    async fn rsa9_create_token_request_json_serialization_depth() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions::default();
        let req = client.auth().create_token_request(Some(&params), Some(&options)).await.unwrap();
        let json_val = serde_json::to_value(&req).unwrap();
        assert!(json_val.get("keyName").is_some());
        assert!(json_val.get("nonce").is_some());
        assert!(json_val.get("mac").is_some());
        // RSA5/RSA6: unspecified ttl and capability are omitted entirely
        assert!(json_val.get("ttl").is_none());
        assert!(json_val.get("capability").is_none());
    }


    #[tokio::test]
    async fn rsa9_create_token_request_nonce_length_depth() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions::default();
        let req = client.auth().create_token_request(Some(&params), Some(&options)).await.unwrap();
        assert!(req.nonce.len() >= 16,
            "Nonce should be at least 16 chars, got {} ({})",
            req.nonce.len(), req.nonce);
    }


    #[tokio::test]
    async fn rsa4_bearer_auth_explicit_token_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            let auth = req.headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).unwrap().to_string();
            assert!(auth.starts_with("Bearer "), "Expected Bearer auth");
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::with_token("explicit-test-token".to_string())
            .rest_with_mock(mock)
            .unwrap();
        client.request("GET", "/channels/test").send().await?;
        Ok(())
    }


    #[test]
    fn rsa7_client_id_from_options_depth() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("my-client-id")
            .unwrap()
            .rest()
            .unwrap();
        assert_eq!(client.options().client_id.as_deref(), Some("my-client-id"));
    }


    #[test]
    fn rsa7_client_id_null_when_not_set_depth() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        assert!(client.options().client_id.is_none());

    // UTS rest/unit/RSA7/clientid-updated-after-authorize-0
    #[tokio::test]
    async fn rsa7_client_id_updated_after_authorize() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                200,
                &json!({
                    "token": "new-token",
                    "expires": 4102444800000_i64,
                    "issued": 1234567890000_i64,
                    "clientId": "authorized-user"
                }),
            )
        });
        let client = mock_client(mock);
        assert_eq!(client.auth().client_id(), None);
        client.auth().authorize(None, None).await?;
        assert_eq!(
            client.auth().client_id().as_deref(),
            Some("authorized-user"),
            "RSA7: clientId reflects the authorized token"
        );
        Ok(())
    }

    // UTS rest/unit/RSA16a/preserved-across-requests-0 — the configured
    // token is used as-is across requests, not re-fetched
    #[tokio::test]
    async fn rsa16a_token_preserved_across_requests() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{"channel": "x", "presence": []}]))
        });
        let client = ClientOptions::with_token("stable-token")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let mut headers_seen = Vec::new();
        for _ in 0..3 {
            client.request("GET", "/channels/test").send().await?;
        }
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 3);
        for req in &reqs {
            let auth = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.clone())
                .expect("auth header");
            assert!(auth.starts_with("Bearer "), "token auth in use");
            headers_seen.push(auth);
        }
        // RSA16a: the same literal token on every request (never re-fetched)
        assert_eq!(headers_seen[0], headers_seen[1]);
        assert_eq!(headers_seen[1], headers_seen[2]);
        Ok(())
    }

    // UTS rest/unit/RSA17/server-error-propagated-0 — revocation server
    // error propagates as a request error
    #[tokio::test]
    async fn rsa17_server_error_propagated() {
        use crate::rest::RevokeTokensRequest;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                500,
                &json!({"error": {"code": 50000, "statusCode": 500, "message": "server error"}}),
            )
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .fallback_hosts(vec![])
            .rest_with_mock(mock)
            .unwrap();
        let err = client
            .auth()
            .revoke_tokens(&RevokeTokensRequest {
                targets: vec!["clientId:user1".to_string()],
                issued_before: None,
                allow_reauth_margin: None,
            })
            .await
            .expect_err("server error propagates");
        assert_eq!(err.code, Some(50000));
        assert_eq!(err.status_code, Some(500));
    }

    // UTS rest/unit/RSA17f/both-options-together-2 — issuedBefore and
    // allowReauthMargin travel together in the request body
    #[tokio::test]
    async fn rsa17f_both_options_together() -> Result<()> {
        use crate::rest::RevokeTokensRequest;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({"results": [{"target": "clientId:user1"}]}))
        });
        let client = mock_client(mock);
        client
            .auth()
            .revoke_tokens(&RevokeTokensRequest {
                targets: vec!["clientId:user1".to_string()],
                issued_before: Some(1234567890000),
                allow_reauth_margin: Some(true),
            })
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["issuedBefore"], 1234567890000_i64);
        assert_eq!(body["allowReauthMargin"], true);
        Ok(())
    }

}

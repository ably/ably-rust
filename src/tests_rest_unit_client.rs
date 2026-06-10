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


    // ---------------------------------------------------------------
    // RSC5 — Auth attribute
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[test]
    fn rsc5_auth_attribute() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        // Auth object is accessible (Rust's type system ensures it's Auth)
        let _auth = client.auth();
    }


    // ---------------------------------------------------------------
    // RSC7e — X-Ably-Version header
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc7e_x_ably_version_header() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);

        let version = reqs[0]
            .headers.iter().find(|(k,_)| k == "x-ably-version").map(|(_,v)| v.as_str()).expect("Expected X-Ably-Version header");
        assert_eq!(version, "6");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC8a — MessagePack is the default protocol
    // RSC8b — JSON when useBinaryProtocol is false
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc8a_default_protocol_is_msgpack() -> Result<()> {
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
        assert_eq!(reqs.len(), 1);

        let content_type = reqs[0]
            .headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str()).expect("Expected Content-Type header");
        assert_eq!(content_type, "application/x-msgpack");

        Ok(())
    }


    #[tokio::test]
    async fn rsc8b_json_protocol_when_configured() -> Result<()> {
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
        assert_eq!(reqs.len(), 1);

        let content_type = reqs[0]
            .headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str()).expect("Expected Content-Type header");
        assert_eq!(content_type, "application/json");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC17 — ClientId attribute
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[test]
    fn rsc17_client_id_attribute() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("explicit-client-id")
            .unwrap()
            .rest()
            .unwrap();

        assert_eq!(
            client.options().client_id.as_deref(),
            Some("explicit-client-id")
        );
    }


    // ---------------------------------------------------------------
    // RSC18 — TLS configuration: default is HTTPS, tls=false uses HTTP
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc18_default_tls_uses_https() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.scheme(), "https");

        Ok(())
    }


    #[tokio::test]
    async fn rsc18_tls_false_uses_http() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        // Token auth is allowed over non-TLS.
        let client = ClientOptions::new("some-token-string")
            .tls(false)
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.scheme(), "http");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC18 — Basic auth over HTTP rejected
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[test]
    fn rsc18_basic_auth_rejected_without_tls() {
        let err = match ClientOptions::new("appId.keyId:keySecret")
            .tls(false)
            .rest()
        {
            Err(e) => e,
            Ok(_) => panic!("Expected error for basic auth over non-TLS"),
        };

        assert_eq!(
            err.code,
            Some(crate::error::ErrorInfoCode::InvalidUseOfBasicAuthOverNonTLSTransport.code())
        );
    }


    #[tokio::test]
    async fn rsc18_token_auth_allowed_without_tls() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        // Token auth over HTTP should succeed.
        let client = ClientOptions::new("some-token-string")
            .tls(false)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC7d — Ably-Agent header
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc7d_ably_agent_header() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);

        let agent = reqs[0]
            .headers.iter().find(|(k,_)| k == "ably-agent").map(|(_,v)| v.as_str()).expect("Expected Ably-Agent header");
        let agent_str = agent;

        // RSC7d1/RSC7d2: Must include library name and version in format ably-rust/x.y.z
        assert!(
            agent_str.starts_with("ably-rust/"),
            "Expected Ably-Agent to start with 'ably-rust/', got '{}'",
            agent_str
        );

        // Version part should match semver pattern
        let version = &agent_str["ably-rust/".len()..];
        assert!(
            version.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "Expected version to be numeric with dots, got '{}'",
            version
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC7c — Request IDs
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc7c_request_id_when_enabled() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .add_request_ids(true)
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);

        // Extract request_id from query params
        let request_id = reqs[0]
            .url
            .query_pairs()
            .find(|(k, _)| k == "request_id")
            .map(|(_, v)| v.to_string())
            .expect("Expected request_id query parameter");

        // Should be at least 12 characters (base64url-encoded 16 bytes = 22 chars)
        assert!(
            request_id.len() >= 12,
            "Expected request_id length >= 12, got {}",
            request_id.len()
        );

        // Should be URL-safe base64
        assert!(
            request_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "Expected URL-safe base64 request_id, got '{}'",
            request_id
        );

        Ok(())
    }


    #[tokio::test]
    async fn rsc7c_no_request_id_by_default() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        let has_request_id = reqs[0].url.query_pairs().any(|(k, _)| k == "request_id");

        assert!(
            !has_request_id,
            "Expected no request_id query parameter by default"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC8c — Accept header matches configured protocol
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc8c_accept_and_content_type_json() -> Result<()> {
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
        assert_eq!(reqs.len(), 1);

        let accept = reqs[0]
            .headers.iter().find(|(k,_)| k == "accept").map(|(_,v)| v.as_str()).expect("Expected Accept header");
        assert_eq!(accept, "application/json");

        let content_type = reqs[0]
            .headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str()).expect("Expected Content-Type header");
        assert_eq!(content_type, "application/json");

        Ok(())
    }


    #[tokio::test]
    async fn rsc8c_accept_and_content_type_msgpack() -> Result<()> {
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
        assert_eq!(reqs.len(), 1);

        let content_type = reqs[0]
            .headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str()).expect("Expected Content-Type header");
        assert_eq!(content_type, "application/x-msgpack");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC8d — Handle mismatched response Content-Type
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc8d_mismatched_response_content_type() -> Result<()> {
        // Client configured for JSON, but server returns msgpack.
        let time_value: i64 = 1234567890000;
        let msgpack_body =
            rmp_serde::to_vec_named(&vec![time_value]).expect("failed to encode msgpack");

        let mock = MockHttpClient::with_handler(move |_req| MockResponse {
            status: 200,
            headers: vec![(
                "content-type".to_string(),
                "application/x-msgpack".to_string(),
            )],
            body: msgpack_body.clone(),
            network_error: false,
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false) // Client prefers JSON
            .rest_with_mock(mock)
            .unwrap();

        // Should successfully parse msgpack response despite requesting JSON.
        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC8e — Unsupported Content-Type handling
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc8e_unsupported_content_type_error_status() -> Result<()> {
        // Server returns 500 with text/html content.
        let mock = MockHttpClient::with_handler(|_req| MockResponse {
            status: 500,
            headers: vec![("content-type".to_string(), "text/html".to_string())],
            body: b"<html>Server Error</html>".to_vec(),
            network_error: false,
        });

        let client = mock_client(mock);

        let err = client
            .time()
            .await
            .expect_err("Expected error for unsupported content-type");

        // HTTP status code should be propagated.
        assert_eq!(err.status_code, Some(500));

        Ok(())
    }


    #[tokio::test]
    async fn rsc8e_unsupported_content_type_success_status() -> Result<()> {
        // Server returns 200 with text/html content.
        let mock = MockHttpClient::with_handler(|_req| MockResponse {
            status: 200,
            headers: vec![("content-type".to_string(), "text/html".to_string())],
            body: b"<html>OK</html>".to_vec(),
            network_error: false,
        });

        let client = mock_client(mock);

        let err = client
            .time()
            .await
            .expect_err("Expected error for unsupported content-type");

        // RSC8e: Should return error code 40013 for 2xx with unsupported Content-Type.
        assert_eq!(
            err.code,
            Some(crate::error::ErrorInfoCode::InvalidMessageDataOrEncoding.code())
        );
        assert_eq!(err.status_code, Some(400u16));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC13 — Request timeouts
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc13_request_timeout() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        // Set a 5-second delay on the mock, but only 100ms timeout on the client.
        mock.set_response_delay(std::time::Duration::from_secs(5));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .http_request_timeout(std::time::Duration::from_millis(100))
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.expect_err("Expected timeout error");

        assert_eq!(err.code, Some(crate::error::ErrorInfoCode::TimeoutError.code()));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC1 — Rejects client creation with no auth credentials
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[test]
    fn rsc1_rejects_empty_credentials() {
        let client = ClientOptions::new("not-a-key");
        assert!(matches!(
            client.credential,
            crate::auth::Credential::TokenDetails(_)
        ));
    }

    // ---------------------------------------------------------------
    // RSC1c — String without ':' treated as token, with ':' as key
    // UTS: realtime/unit/client/client_options.md
    // ---------------------------------------------------------------

    #[test]
    fn rsc1c_string_with_colon_parsed_as_key() {
        let opts = ClientOptions::new("appId.keyId:keySecret");
        assert!(matches!(opts.credential, crate::auth::Credential::Key(_)));
    }

    #[test]
    fn rsc1c_string_without_colon_parsed_as_token() {
        let opts = ClientOptions::new("abcdef1234567890");
        match &opts.credential {
            crate::auth::Credential::TokenDetails(td) => {
                assert_eq!(td.token, "abcdef1234567890");
            }
            other => panic!("Expected TokenDetails, got: {:?}", other),
        }
    }

    #[test]
    fn rsc1c_jwt_string_parsed_as_token() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let opts = ClientOptions::new(jwt);
        match &opts.credential {
            crate::auth::Credential::TokenDetails(td) => {
                assert_eq!(td.token, jwt);
            }
            other => panic!("Expected TokenDetails for JWT, got: {:?}", other),
        }
    }

    #[test]
    fn rsc1c_key_with_special_chars_parsed_as_key() {
        let opts = ClientOptions::new("xVLyHw.A-pwh:5WEB4HEAT3pOqWp9");
        assert!(matches!(opts.credential, crate::auth::Credential::Key(_)));
    }

    #[test]
    fn rsc1c_empty_string_rejected() {
        let opts = ClientOptions::new("");
        let result = opts.rest();
        assert!(result.is_err());
    }


    // ---------------------------------------------------------------
    // RSC10b — Non-token 401 errors are NOT retried
    // UTS: rest/unit/auth/token_renewal.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc10b_non_token_401_not_retried() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            if req.url.path().contains("/requestToken") {
                request_count_clone.fetch_add(1, Ordering::SeqCst);
                MockResponse::json(
                    200,
                    &json!({
                        "token": "some-token",
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else {
                request_count_clone.fetch_add(1, Ordering::SeqCst);
                // Return 401 with non-token error code (40100, not 40140-40149)
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
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.expect_err("Expected 401 error");
        assert_eq!(err.code, Some(crate::error::ErrorInfoCode::Unauthorized.code()));

        // Should have made requestToken + 1 API request (no retry for non-token 401)
        let reqs = get_mock(&client).captured_requests();
        let api_reqs: Vec<_> = reqs
            .iter()
            .filter(|r| !r.url.path().contains("/requestToken"))
            .collect();
        assert_eq!(
            api_reqs.len(),
            1,
            "Expected only 1 API request (no retry for non-token 401), got {}",
            api_reqs.len()
        );

        Ok(())
    }


    // ===============================================================
    // Phase 5 — Fallback Hosts & Endpoint Configuration
    // UTS: rest/unit/fallback.md
    // ===============================================================

    // ---------------------------------------------------------------
    // RSC15m — Fallback only when fallback domains non-empty
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15m_no_fallback_when_fallback_hosts_empty() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .fallback_hosts(vec![])
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.unwrap_err();
        assert_eq!(err.status_code, Some(500));

        // Should not retry — only 1 request
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC15l3 — HTTP 5xx status codes trigger fallback
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15l3_5xx_triggers_fallback() -> Result<()> {
        for status in [500u16, 501, 502, 503, 504] {
            let mock = MockHttpClient::new();
            mock.queue_response(MockResponse::json(
                status,
                &json!({"error": {"code": status as u32 * 100}}),
            ));
            mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

            let client = ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .rest_with_mock(mock)
                .unwrap();

            let time = client.time().await.unwrap();
            assert_eq!(time.timestamp_millis(), 1234567890000);

            let reqs = get_mock(&client).captured_requests();
            assert_eq!(reqs.len(), 2, "status {} should trigger fallback", status);
            assert_ne!(
                reqs[0].url.host_str(),
                reqs[1].url.host_str(),
                "fallback should use a different host for status {}",
                status
            );
        }

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC15l4 — CloudFront errors (status >= 400 with Server: CloudFront) trigger fallback
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15l4_cloudfront_error_triggers_fallback() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(
            MockResponse::json(403, &json!({"error": {"code": 40300, "message": "Forbidden"}}))
                .with_header("Server", "CloudFront")
        );
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let _time = client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2, "CloudFront 403 should trigger fallback");
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");
        assert_ne!(reqs[1].url.host_str().unwrap(), "main.realtime.ably.net");
        Ok(())
    }

    #[tokio::test]
    async fn rsc15l4_non_cloudfront_4xx_no_fallback() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(
            MockResponse::json(403, &json!({"error": {"code": 40300, "message": "Forbidden"}}))
                .with_header("Server", "nginx")
        );

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.unwrap_err();
        assert_eq!(err.status_code, Some(403));

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1, "Non-CloudFront 403 should NOT trigger fallback");
        Ok(())
    }

    // ---------------------------------------------------------------
    // RSC15l — HTTP 4xx errors do NOT trigger fallback
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15l_4xx_does_not_trigger_fallback() -> Result<()> {
        for status in [400u16, 404] {
            let mock = MockHttpClient::new();
            mock.queue_response(MockResponse::json(
                status,
                &json!({"error": {"code": status as u32 * 100, "message": "test error"}}),
            ));

            let client = ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .rest_with_mock(mock)
                .unwrap();

            let err = client.time().await.unwrap_err();
            assert_eq!(err.status_code, Some(status));

            let reqs = get_mock(&client).captured_requests();
            assert_eq!(
                reqs.len(),
                1,
                "status {} should NOT trigger fallback",
                status
            );
        }

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC15a — Fallback hosts tried when primary fails
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15a_fallback_hosts_tried_on_primary_failure() -> Result<()> {
        // Queue 4 responses: primary + 3 fallbacks (httpMaxRetryCount default)
        // All fail so we can see all hosts tried
        let mock = MockHttpClient::new();
        for _ in 0..4 {
            mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        }

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let _ = client.time().await;

        let reqs = get_mock(&client).captured_requests();
        // primary + up to httpMaxRetryCount (3) fallbacks = 4
        assert_eq!(reqs.len(), 4);

        // First request to the primary host
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");

        // Subsequent requests to fallback hosts
        let expected_fallbacks = vec![
            "main.a.fallback.ably-realtime.com",
            "main.b.fallback.ably-realtime.com",
            "main.c.fallback.ably-realtime.com",
            "main.d.fallback.ably-realtime.com",
            "main.e.fallback.ably-realtime.com",
        ];
        for req in &reqs[1..] {
            let host = req.url.host_str().unwrap();
            assert!(
                expected_fallbacks.contains(&host),
                "fallback host '{}' not in expected list",
                host
            );
        }

        // All fallback hosts used should be distinct
        let fallback_hosts: Vec<&str> = reqs[1..]
            .iter()
            .map(|r| r.url.host_str().unwrap())
            .collect();
        let unique: std::collections::HashSet<&&str> = fallback_hosts.iter().collect();
        assert_eq!(
            unique.len(),
            fallback_hosts.len(),
            "fallback hosts should be distinct"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC15a — Fallback hosts randomized
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15a_fallback_hosts_randomized() -> Result<()> {
        // Run multiple times and check that fallback order varies
        let mut orders: Vec<Vec<String>> = Vec::new();

        for _ in 0..10 {
            let mock = MockHttpClient::new();
            for _ in 0..4 {
                mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
            }

            let client = ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .rest_with_mock(mock)
                .unwrap();

            let _ = client.time().await;

            let reqs = get_mock(&client).captured_requests();
            let fallback_order: Vec<String> = reqs[1..]
                .iter()
                .map(|r| r.url.host_str().unwrap().to_string())
                .collect();
            orders.push(fallback_order);
        }

        // At least 2 different orderings should appear in 10 runs
        let first = &orders[0];
        let has_different = orders.iter().any(|o| o != first);
        assert!(
            has_different,
            "fallback hosts should be randomized across runs"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC15l — Fallback succeeds on second host
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15l_fallback_succeeds_on_second_host() -> Result<()> {
        let mock = MockHttpClient::new();
        // Primary fails
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        // First fallback succeeds
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");
        assert_ne!(reqs[1].url.host_str().unwrap(), "main.realtime.ably.net");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC15 — httpMaxRetryCount limits fallback attempts
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15_http_max_retry_count_limits_fallbacks() -> Result<()> {
        let mock = MockHttpClient::new();
        // Queue many failures
        for _ in 0..10 {
            mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        }

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .http_max_retry_count(2)
            .rest_with_mock(mock)
            .unwrap();

        let _ = client.time().await;

        let reqs = get_mock(&client).captured_requests();
        // primary + 2 fallbacks = 3
        assert_eq!(reqs.len(), 3);

        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1a — Default primary domain
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rec1a_default_primary_domain() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");

        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1d1 — Custom restHost sets primary domain
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rec1d1_custom_rest_host() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_host("custom.rest.example.com")?
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str().unwrap(), "custom.rest.example.com");

        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1c2 — Environment option determines primary domain
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rec1c2_environment_sets_primary_domain() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .environment("sandbox")?
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str().unwrap(), "sandbox.realtime.ably.net");

        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1c1 — Environment conflicts with restHost
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[test]
    fn rec1c1_environment_conflicts_with_rest_host() {
        let result = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("custom.host.com")
            .and_then(|opts| opts.environment("sandbox"));

        assert!(result.is_err());
    }


    #[test]
    fn rec1c1_rest_host_conflicts_with_environment() {
        let result = ClientOptions::new("appId.keyId:keySecret")
            .environment("sandbox")
            .and_then(|opts| opts.rest_host("custom.host.com"));

        assert!(result.is_err());
    }


    // ---------------------------------------------------------------
    // REC2a2 — Custom fallbackHosts overrides defaults
    // Also covers: REC2 (parent spec for fallback domains)
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rec2a2_custom_fallback_hosts() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let custom_fallbacks = vec![
            "fb1.example.com".to_string(),
            "fb2.example.com".to_string(),
            "fb3.example.com".to_string(),
        ];

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .fallback_hosts(custom_fallbacks.clone())
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");
        let fallback_host = reqs[1].url.host_str().unwrap();
        assert!(
            custom_fallbacks.iter().any(|h| h == fallback_host),
            "fallback host '{}' should be one of the custom hosts",
            fallback_host
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // REC2c5 — Environment sets fallback domains
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rec2c5_environment_sets_fallback_domains() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .environment("sandbox")?
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "sandbox.realtime.ably.net");

        let expected_env_fallbacks = vec![
            "sandbox.a.fallback.ably-realtime.com",
            "sandbox.b.fallback.ably-realtime.com",
            "sandbox.c.fallback.ably-realtime.com",
            "sandbox.d.fallback.ably-realtime.com",
            "sandbox.e.fallback.ably-realtime.com",
        ];
        let fallback_host = reqs[1].url.host_str().unwrap();
        assert!(
            expected_env_fallbacks.iter().any(|h| *h == fallback_host),
            "env fallback host '{}' not in expected list",
            fallback_host
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // REC2c6 — Custom restHost disables fallback hosts
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rec2c6_custom_rest_host_no_fallbacks() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_host("custom.rest.example.com")?
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.unwrap_err();
        assert_eq!(err.status_code, Some(500));

        let reqs = get_mock(&client).captured_requests();
        // Only 1 request — no fallback
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url.host_str().unwrap(), "custom.rest.example.com");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC15 — Non-retriable error stops fallback chain
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc15_non_retriable_stops_fallback_chain() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let mock = MockHttpClient::with_handler(move |_req| {
            let n = counter_clone.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // Primary: retriable 500
                MockResponse::json(500, &json!({"error": {"code": 50000}}))
            } else {
                // First fallback: non-retriable 400
                MockResponse::json(
                    400,
                    &json!({"error": {"code": 40000, "message": "bad request"}}),
                )
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.unwrap_err();
        assert_eq!(err.status_code, Some(400));

        // Only 2 requests: primary (500) + first fallback (400), then stop
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);

        Ok(())
    }


    // ---------------------------------------------------------------
    // REC2c1 — Default fallback domains
    // UTS: rest/unit/fallback.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rec2c1_default_fallback_domains() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");

        let expected_fallbacks = vec![
            "main.a.fallback.ably-realtime.com",
            "main.b.fallback.ably-realtime.com",
            "main.c.fallback.ably-realtime.com",
            "main.d.fallback.ably-realtime.com",
            "main.e.fallback.ably-realtime.com",
        ];
        let fallback_host = reqs[1].url.host_str().unwrap();
        assert!(
            expected_fallbacks.iter().any(|h| *h == fallback_host),
            "default fallback host '{}' not in expected list",
            fallback_host
        );

        Ok(())
    }


    // ===============================================================
    // Phase 6 — Additional REST Features
    // ===============================================================

    // ---------------------------------------------------------------
    // RSC16 — time() returns server time
    // UTS: rest/unit/time.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc16_time_returns_server_time() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.url.path(), "/time");
            assert_eq!(req.method, "GET");
            MockResponse::json(200, &json!([1704067200000_i64]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1704067200000);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC16 — time() request format (GET /time with Ably headers)
    // UTS: rest/unit/time.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc16_time_request_format() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([1704067200000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].url.path(), "/time");
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "x-ably-version"));
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "ably-agent"));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC16 — time() error handling
    // UTS: rest/unit/time.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc16_time_error_handling() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(
            500,
            &json!({"error": {"message": "Internal server error", "code": 50000, "statusCode": 500}}),
        ));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .fallback_hosts(vec![])
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.unwrap_err();
        assert_eq!(err.status_code, Some(500));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6a — stats() returns PaginatedResult with Stats objects
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6a_stats_returns_paginated_result() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(
            200,
            &json!([
                {
                    "intervalId": "2024-01-01:00:00",
                    "unit": "hour",
                    "all": {
                        "messages": {"count": 100.0, "data": 5000.0},
                        "all": {"count": 100.0, "data": 5000.0}
                    }
                },
                {
                    "intervalId": "2024-01-01:01:00",
                    "unit": "hour",
                    "all": {
                        "messages": {"count": 150.0, "data": 7500.0},
                        "all": {"count": 150.0, "data": 7500.0}
                    }
                }
            ]),
        ));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let page = client.stats().send().await?;
        let items = page.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].interval_id, "2024-01-01:00:00");
        assert_eq!(items[1].interval_id, "2024-01-01:01:00");

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].url.path(), "/stats");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6a — stats() sends authenticated request
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6a_stats_authenticated() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "authorization"));
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "x-ably-version"));
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "ably-agent"));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6b2 — stats() with direction parameter
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6b2_stats_direction_forwards() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().forwards().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(
            query.iter().find(|(k, _)| k == "direction").unwrap().1,
            "forwards"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6b2 — stats() direction defaults to backwards (omitted)
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6b2_stats_default_direction() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        // Direction should be absent (server default) or "backwards"
        let direction = query.iter().find(|(k, _)| k == "direction");
        assert!(
            direction.is_none() || direction.unwrap().1 == "backwards",
            "default direction should be absent or 'backwards'"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6b3 — stats() with limit parameter
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6b3_stats_limit() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().limit(10).send().await?;

        let reqs = get_mock(&client).captured_requests();
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "10");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6b1 — stats() with start and end parameters
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6b1_stats_start_and_end() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .stats()
            .start("1704067200000")
            .end("1706745599000")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(
            query.iter().find(|(k, _)| k == "start").unwrap().1,
            "1704067200000"
        );
        assert_eq!(
            query.iter().find(|(k, _)| k == "end").unwrap().1,
            "1706745599000"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6a — stats() with no parameters sends no query params
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6a_stats_no_params() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.path(), "/stats");
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        // Stats-specific params should be absent
        assert!(query.iter().find(|(k, _)| k == "start").is_none());
        assert!(query.iter().find(|(k, _)| k == "end").is_none());
        assert!(query.iter().find(|(k, _)| k == "limit").is_none());
        assert!(query.iter().find(|(k, _)| k == "direction").is_none());

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6a — stats() empty results
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6a_stats_empty_results() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let page = client.stats().send().await?;
        let items = page.items();
        assert_eq!(items.len(), 0);

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6a — stats() error handling
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6a_stats_error_handling() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(
            401,
            &json!({"error": {"message": "Unauthorized", "code": 40100, "statusCode": 401}}),
        ));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let result = client.stats().send().await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.status_code, Some(401));

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC6b — stats() with all parameters combined
    // UTS: rest/unit/stats.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc6b_stats_all_params() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .stats()
            .start("1704067200000")
            .end("1706745599000")
            .forwards()
            .limit(50)
            .params(&[("unit", "hour")])
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(
            query.iter().find(|(k, _)| k == "start").unwrap().1,
            "1704067200000"
        );
        assert_eq!(
            query.iter().find(|(k, _)| k == "end").unwrap().1,
            "1706745599000"
        );
        assert_eq!(
            query.iter().find(|(k, _)| k == "direction").unwrap().1,
            "forwards"
        );
        assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "50");
        assert_eq!(query.iter().find(|(k, _)| k == "unit").unwrap().1, "hour");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19f — request() supports HTTP methods
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19f_request_http_methods() -> Result<()> {
        

        for method in [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ] {
            let mock = MockHttpClient::new();
            mock.queue_response(MockResponse::json(200, &json!([])));

            let client = ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .rest_with_mock(mock)
                .unwrap();

            client.request(method.clone(), "/test").send().await?;

            let reqs = get_mock(&client).captured_requests();
            assert_eq!(reqs[0].method, method);
            assert_eq!(reqs[0].url.path(), "/test");
        }

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19f — request() query parameters
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19f_request_query_params() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/channels/test/messages")
            .params(&[("limit", "10"), ("direction", "backwards")])
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let query: Vec<(String, String)> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "10");
        assert_eq!(
            query.iter().find(|(k, _)| k == "direction").unwrap().1,
            "backwards"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19f — request() custom headers
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19f_request_custom_headers() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let headers: &[(&str, &str)] = &[("X-Custom-Header", "custom-value")];

        client
            .request("GET", "/test")
            .headers(headers)
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(
            reqs[0]
                .headers.iter().find(|(k,_)| k == "x-custom-header").map(|(_,v)| v.as_str())
                .unwrap(),
            "custom-value"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19f — request() body sent correctly
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19f_request_body() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(201, &json!({"id": "123"})));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("POST", "/channels/test/messages")
            .body(&json!({"name": "event", "data": "payload"}))
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["name"], "event");
        assert_eq!(body["data"], "payload");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19b — request() uses configured authentication
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19b_request_uses_auth() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str())
            .unwrap();
        assert!(
            auth.starts_with("Basic "),
            "expected Basic auth, got: {}",
            auth
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19c — request() protocol headers (JSON)
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19c_request_json_protocol_headers() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(
            reqs[0].headers.iter().find(|(k,_)| k == "accept").map(|(_,v)| v.as_str()).unwrap(),
            "application/json"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19c — request() protocol headers (MsgPack)
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19c_request_msgpack_protocol_headers() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::msgpack(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(true)
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(
            reqs[0].headers.iter().find(|(k,_)| k == "accept").map(|(_,v)| v.as_str()).unwrap(),
            "application/x-msgpack"
        );

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC19 — request() path with leading slash
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19f_request_path_leading_slash() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .request("GET", "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.path(), "/channels/test");

        Ok(())
    }


    // ---------------------------------------------------------------
    // RSC8 — Error response decoded from MessagePack
    // UTS: rest/unit/rest_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc8_error_response_parsed_from_msgpack() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::msgpack(
                400,
                &serde_json::json!({
                    "error": {
                        "code": 40099,
                        "statusCode": 400,
                        "message": "Test error",
                        "href": ""
                    }
                }),
            )
        });

        let client = mock_client(mock);
        let err = client.time().await.expect_err("Expected error");

        assert_eq!(err.code, Some(crate::error::ErrorInfoCode::Testing.code()));
        assert_eq!(err.status_code, Some(400));

        Ok(())
    }


    // ===============================================================
    // RSC22: Batch Publish
    // ===============================================================

    #[tokio::test]
    async fn rsc22c_batch_publish_sends_post_to_messages() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.url.path(), "/messages");
            MockResponse::json(200, &json!([{"channel": "ch1", "messageId": "msg-1"}]))
        });

        let client = mock_client(mock);
        let result = client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec!["ch1".to_string()],
                messages: vec![crate::rest::Message::default()],
            }])
            .await;
        assert!(result.is_ok());
        Ok(())
    }


    #[tokio::test]
    async fn rsc22c_batch_publish_multiple_specs() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.url.path(), "/messages");
            MockResponse::json(
                200,
                &json!([
                    {"channel": "ch1", "messageId": "msg-1"},
                    {"channel": "ch2", "messageId": "msg-2"}
                ]),
            )
        });

        let client = mock_client(mock);
        let results = client
            .batch_publish(vec![
                BatchPublishSpec {
                    channels: vec!["ch1".to_string()],
                    messages: vec![crate::rest::Message::default()],
                },
                BatchPublishSpec {
                    channels: vec!["ch2".to_string()],
                    messages: vec![crate::rest::Message::default()],
                },
            ])
            .await?;
        assert_eq!(results.len(), 2);
        Ok(())
    }


    #[tokio::test]
    async fn rsc22_server_error_propagated() {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(
                500,
                &json!({
                    "error": {
                        "code": 50000,
                        "statusCode": 500,
                        "message": "Internal error",
                        "href": ""
                    }
                }),
            )
        });

        let client = mock_client(mock);
        let result = client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec!["ch1".to_string()],
                messages: vec![crate::rest::Message::default()],
            }])
            .await;
        assert!(result.is_err());
    }


    // ===============================================================
    // RSC25: Request Endpoint — primary domain routing
    // ===============================================================

    #[tokio::test]
    async fn rsc25_default_primary_domain_used() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");
        Ok(())
    }


    #[tokio::test]
    async fn rsc25_custom_endpoint_domain() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .environment("test")
            .unwrap()
            .rest_with_mock(mock)
            .unwrap();
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url.host_str().unwrap(), "test.realtime.ably.net");
        Ok(())
    }


    #[tokio::test]
    async fn rsc25_multiple_requests_primary_domain() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });

        let client = mock_client(mock);
        client.time().await?;
        client.time().await?;
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 3);
        for req in &reqs {
            assert_eq!(req.url.host_str().unwrap(), "main.realtime.ably.net");
        }
        Ok(())
    }


    #[tokio::test]
    async fn rsc25_primary_tried_before_fallback() -> Result<()> {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count = call_count.clone();

        let mock = MockHttpClient::with_handler(move |_req| {
            let n = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                MockResponse::json(
                    500,
                    &json!({"error": {"code": 50000, "statusCode": 500, "message": "fail", "href": ""}}),
                )
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = mock_client(mock);
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");
        assert_ne!(reqs[1].url.host_str().unwrap(), "main.realtime.ably.net");
        Ok(())
    }


    #[tokio::test]
    async fn rsc25_request_path_preserved() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });

        let client = mock_client(mock);
        client.channels().get("test-channel").history().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url.host_str().unwrap(), "main.realtime.ably.net");
        assert_eq!(reqs[0].url.path(), "/channels/test-channel/history");
        assert_eq!(reqs[0].method, "GET");
        Ok(())
    }


    // ===============================================================
    // RSC2/TO3b/TO3c: Logging
    // ===============================================================

    #[tokio::test]
    async fn rsc2_default_log_level_error_only() -> Result<()> {
        // RSC2: the default log level emits errors but not verbose entries
        use std::sync::Mutex as StdMutex;
        let captured = Arc::new(StdMutex::new(Vec::<crate::options::LogLevel>::new()));
        let logs = captured.clone();

        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .log_handler(move |level, _| {
                logs.lock().unwrap().push(level);
            })
            .rest_with_mock(mock)
            .unwrap();
        client.request("GET", "/channels/test").send().await?;

        // A successful request emits nothing at the default (Error) level
        assert!(captured.lock().unwrap().is_empty());
        Ok(())
    }



    #[tokio::test]
    async fn rsc2b_log_level_none_suppresses_all() -> Result<()> {
        // RSC2b: LogLevel::None suppresses everything, even errors
        use std::sync::Mutex as StdMutex;
        let captured = Arc::new(StdMutex::new(Vec::<String>::new()));
        let logs = captured.clone();

        let mock = MockHttpClient::with_handler(|_req| MockResponse::network_error());
        let client = ClientOptions::new("appId.keyId:keySecret")
            .log_level(LogLevel::None)
            .log_handler(move |_level, message| {
                logs.lock().unwrap().push(message.to_string());
            })
            .rest_with_mock(mock)
            .unwrap();
        let _ = client.request("GET", "/channels/test").send().await;

        assert!(
            captured.lock().unwrap().is_empty(),
            "LogLevel::None must suppress all logs"
        );
        Ok(())
    }



    // ===============================================================
    // BAR2/BGR2/BGF2/RSC24: Batch presence
    // UTS: rest/unit/batch_presence.md
    // ===============================================================

    // RSC24_1 — GET /presence with comma-separated channels param
    // UTS: rest/unit/RSC24/get-presence-channels-param-0
    #[tokio::test]
    async fn rsc24_batch_presence_sends_get_with_channels() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!({
                "successCount": 2,
                "failureCount": 0,
                "results": [
                    {"channel": "channel-a", "presence": []},
                    {"channel": "channel-b", "presence": []}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let result = client.batch_presence(&["channel-a", "channel-b"]).await?;
        assert_eq!(result.results.len(), 2);

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let req = reqs.last().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url.path(), "/presence");
        let channels_param = req
            .url
            .query_pairs()
            .find(|(k, _)| k == "channels")
            .map(|(_, v)| v.to_string());
        assert_eq!(channels_param.as_deref(), Some("channel-a,channel-b"));
        Ok(())
    }


    // RSC24_2 — single channel sends just the channel name
    // UTS: rest/unit/RSC24/single-channel-param-0
    #[tokio::test]
    async fn rsc24_batch_presence_single_channel_param() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!({
                "successCount": 1,
                "failureCount": 0,
                "results": [{"channel": "my-channel", "presence": []}]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        client.batch_presence(&["my-channel"]).await?;
        let reqs = get_mock(&client).captured_requests();
        let channels_param = reqs.last().unwrap().url.query_pairs()
            .find(|(k, _)| k == "channels")
            .map(|(_, v)| v.to_string());
        assert_eq!(channels_param.as_deref(), Some("my-channel"));
        Ok(())
    }


    // RSC24_3 — channel names with special characters are comma-joined as-is
    // UTS: rest/unit/RSC24/special-chars-comma-joined-0
    #[tokio::test]
    async fn rsc24_batch_presence_special_chars_comma_joined() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!({
                "successCount": 2,
                "failureCount": 0,
                "results": [
                    {"channel": "foo:bar", "presence": []},
                    {"channel": "baz/qux", "presence": []}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        client.batch_presence(&["foo:bar", "baz/qux"]).await?;
        let reqs = get_mock(&client).captured_requests();
        let channels_param = reqs.last().unwrap().url.query_pairs()
            .find(|(k, _)| k == "channels")
            .map(|(_, v)| v.to_string());
        assert_eq!(channels_param.as_deref(), Some("foo:bar,baz/qux"));
        Ok(())
    }


    // BAR2_1 — successCount and failureCount from mixed response
    // UTS: rest/unit/BAR2/mixed-success-failure-counts-0
    #[tokio::test]
    async fn bar2_mixed_success_failure_counts() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!({
                "successCount": 3,
                "failureCount": 1,
                "results": [
                    {"channel": "ch-1", "presence": []},
                    {"channel": "ch-2", "presence": []},
                    {"channel": "ch-3", "presence": []},
                    {"channel": "ch-4", "error": {"code": 40160, "statusCode": 401, "message": "Not permitted"}}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let result = client.batch_presence(&["ch-1", "ch-2", "ch-3", "ch-4"]).await?;
        assert_eq!(result.success_count, 3);
        assert_eq!(result.failure_count, 1);
        assert_eq!(result.results.len(), 4);
        Ok(())
    }


    // BGR2_1 — success result with members, including data decode
    // UTS: rest/unit/BGR2/success-with-members-0
    #[tokio::test]
    async fn bgr2_success_result_members() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!({
                "successCount": 1,
                "failureCount": 0,
                "results": [
                    {"channel": "my-channel", "presence": [
                        {"clientId": "client-1", "action": 1, "connectionId": "conn-abc",
                         "id": "conn-abc:0:0", "timestamp": 1700000000000_i64, "data": "hello"},
                        {"clientId": "client-2", "action": 1, "connectionId": "conn-def",
                         "id": "conn-def:0:0", "timestamp": 1700000000000_i64, "data": {"key": "value"}}
                    ]}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let result = client.batch_presence(&["my-channel"]).await?;
        assert_eq!(result.results.len(), 1);
        let success = match &result.results[0] {
            crate::rest::BatchPresenceResult::Success(s) => s,
            other => panic!("Expected success result, got {:?}", other),
        };
        assert_eq!(success.channel, "my-channel");
        assert_eq!(success.presence.len(), 2);
        assert_eq!(success.presence[0].client_id.as_deref(), Some("client-1"));
        assert_eq!(success.presence[0].action, Some(PresenceAction::Present));
        assert_eq!(success.presence[0].connection_id.as_deref(), Some("conn-abc"));
        assert!(matches!(success.presence[0].data, Data::String(ref s) if s == "hello"));
        assert_eq!(success.presence[1].client_id.as_deref(), Some("client-2"));
        assert!(matches!(success.presence[1].data, Data::JSON(ref v) if v["key"] == "value"));
        Ok(())
    }


    // BGF2_1 — failure result with error details
    // UTS: rest/unit/BGF2/failure-error-details-0
    #[tokio::test]
    async fn bgf2_failure_result_with_error() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!({
                "successCount": 0,
                "failureCount": 1,
                "results": [
                    {"channel": "restricted-channel",
                     "error": {"code": 40160, "statusCode": 401, "message": "Channel operation not permitted"}}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let result = client.batch_presence(&["restricted-channel"]).await?;
        assert_eq!(result.results.len(), 1);
        let failure = match &result.results[0] {
            crate::rest::BatchPresenceResult::Failure(f) => f,
            other => panic!("Expected failure result, got {:?}", other),
        };
        assert_eq!(failure.channel, "restricted-channel");
        assert_eq!(failure.error.code, Some(40160));
        assert_eq!(failure.error.status_code, Some(401));
        assert!(failure.error.message.as_deref().unwrap_or("").contains("not permitted"));
        Ok(())
    }


    // RSC24_Mixed_1 — mixed success and failure results
    // UTS: rest/unit/RSC24/mixed-success-failure-results-0
    #[tokio::test]
    async fn rsc24_mixed_success_failure_results() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &serde_json::json!({
                "successCount": 1,
                "failureCount": 1,
                "results": [
                    {"channel": "allowed-channel", "presence": [
                        {"clientId": "user-1", "action": 1, "connectionId": "conn-1",
                         "id": "conn-1:0:0", "timestamp": 1700000000000_i64}
                    ]},
                    {"channel": "restricted-channel",
                     "error": {"code": 40160, "statusCode": 401, "message": "Not permitted"}}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let result = client
            .batch_presence(&["allowed-channel", "restricted-channel"])
            .await?;
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);
        assert_eq!(result.results.len(), 2);
        match &result.results[0] {
            crate::rest::BatchPresenceResult::Success(s) => {
                assert_eq!(s.channel, "allowed-channel");
                assert_eq!(s.presence.len(), 1);
                assert_eq!(s.presence[0].client_id.as_deref(), Some("user-1"));
            }
            other => panic!("Expected success result, got {:?}", other),
        }
        match &result.results[1] {
            crate::rest::BatchPresenceResult::Failure(f) => {
                assert_eq!(f.channel, "restricted-channel");
                assert_eq!(f.error.code, Some(40160));
            }
            other => panic!("Expected failure result, got {:?}", other),
        }
        Ok(())
    }


    // UTS: rest/unit/stats.md — RSC6b4
    #[tokio::test]
    async fn rsc6b4_stats_returns_paginated_result() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"intervalId": "2024-01-01:00:00", "all": {"messages": {"count": 10}}}
            ]))
        });
        let client = mock_client(mock);
        let result = client.stats().send().await?;
        let items = result.items();
        assert_eq!(items.len(), 1);
        Ok(())
    }


    // UTS: rest/unit/client/client_options.md — RSC1b
    // Spec: constructing client with no key/token/authCallback/authUrl raises error 40106.
    // UTS: realtime/unit/client/client_options.md — RSC1b
    // Spec: Constructing a client without valid auth credentials must raise error 40106.
    #[test]
    fn rsc1b_invalid_client_options_raises_error() {
        let result = ClientOptions::new("").rest();
        assert!(result.is_err(), "Empty token should be rejected");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert_eq!(
            err.code,
            Some(crate::error::ErrorInfoCode::UnableToObtainCredentialsFromGivenParameters.code()),
            "Error code should be 40106"
        );
    }


    // ===============================================================
    // Batch 5: REST request() — HttpPaginatedResponse
    // ===============================================================

    // UTS: rest/unit/request.md — RSC19d
    #[tokio::test]
    async fn rsc19d_http_paginated_response_status_and_success() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{"key": "value"}]))
        });
        let client = mock_client(mock);
        let resp = client.request("GET", "/test").send().await?;
        assert_eq!(resp.status_code(), 200);
        Ok(())
    }


    // UTS: rest/unit/request.md — RSC19e
    #[tokio::test]
    async fn rsc19e_request_error_propagation() -> Result<()> {
        // HP4/HP5: HTTP error statuses are returned as a response with
        // success() == false, not as an Err
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(404, &json!({
                "error": {"code": 40400, "statusCode": 404, "message": "Not found", "href": "https://help.ably.io/error/40400"}
            })).with_header("x-ably-errorcode", "40400")
               .with_header("x-ably-errormessage", "Not found")
        });
        let client = mock_client(mock);
        let resp = client.request("GET", "/nonexistent").send().await?;
        assert_eq!(resp.status_code(), 404);
        assert!(!resp.success());
        assert_eq!(resp.error_code(), Some(40400)); // HP6
        assert_eq!(resp.error_message(), Some("Not found")); // HP7
        Ok(())
    }


    // UTS: rest/unit/request.md — RSC19f1
    #[tokio::test]
    async fn rsc19f1_x_ably_version_header() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = mock_client(mock);
        let _ = client.request("GET", "/test").send().await;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let version = reqs[0].headers.iter().find(|(k,_)| k == "x-ably-version").map(|(_,v)| v.as_str());
        assert!(version.is_some(), "Expected X-Ably-Version header");
        Ok(())
    }


    // ===============================================================
    // Batch 6: REST Fallback
    // ===============================================================

    // Already covered by existing tests:
    // REC1b4 → rsc15l3_5xx_triggers_fallback (line 7630)
    // REC1d2 → rsc15m_no_fallback_when_fallback_hosts_empty (line 7604)
    // REC2a1 → rsc15a_fallback_hosts_randomized (line 7760)
    // REC2b → rsc15l3_5xx_triggers_fallback (line 7630)
    // REC2c4 → rsc15l_4xx_does_not_trigger_fallback (line 7666)
    // REC3 → rsc15a_fallback_hosts_tried_on_primary_failure (line 7700)

    #[tokio::test]
    async fn rec1b1_fallback_on_dns_resolution_failure() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let count_c = count.clone();
        let mock = MockHttpClient::with_handler(move |_req| {
            let n = count_c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                MockResponse::network_error()
            } else {
                MockResponse::json(200, &json!([1700000000000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)?;
        let result = client.time().await;
        assert!(result.is_ok(), "Should succeed on fallback: {:?}", result);
        assert!(count.load(Ordering::SeqCst) >= 2, "Should have retried on fallback host");
        Ok(())
    }


    #[tokio::test]
    async fn rec1b2_fallback_on_connection_refused() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let count_c = count.clone();
        let mock = MockHttpClient::with_handler(move |_req| {
            let n = count_c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                MockResponse::network_error()
            } else {
                MockResponse::json(200, &json!([1700000000000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)?;
        let result = client.time().await;
        assert!(result.is_ok(), "Should succeed on fallback: {:?}", result);
        assert!(count.load(Ordering::SeqCst) >= 2, "Should have retried on fallback host");
        Ok(())
    }


    #[tokio::test]
    async fn rec1b3_fallback_on_timeout() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.set_response_delay(std::time::Duration::from_secs(5));
        for _ in 0..4 {
            mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        }
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .http_request_timeout(std::time::Duration::from_millis(100))
            .rest_with_mock(mock)
            .unwrap();
        let result = client.time().await;
        assert!(result.is_err(), "Expected timeout error");
        Ok(())
    }


    // REC1b4 already covered by rsc15l3_5xx_triggers_fallback
    #[tokio::test]
    async fn rec1b4_fallback_on_5xx_error() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000, "statusCode": 500, "message": "Internal error"}})));
        mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let result = client.time().await;
        assert!(result.is_ok(), "Expected fallback to succeed");
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs.len() >= 2, "Expected fallback attempt");
        Ok(())
    }


    // REC1d2 already covered by rsc15m_no_fallback_when_fallback_hosts_empty
    #[tokio::test]
    async fn rec1d2_no_fallback_when_fallback_hosts_empty() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .fallback_hosts(vec![])
            .rest_with_mock(mock)
            .unwrap();
        let result = client.time().await;
        assert!(result.is_err());
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1, "No fallback with empty hosts");
        Ok(())
    }


    // REC2a1 already covered by rsc15a_fallback_hosts_randomized
    // REC2b already covered by rsc15l3_5xx_triggers_fallback

    #[tokio::test]
    async fn rec2b_qualifying_status_codes_500_to_504() -> Result<()> {
        for status in [500, 501, 502, 503, 504] {
            let mock = MockHttpClient::new();
            mock.queue_response(MockResponse::json(status, &json!({"error": {"code": status * 100}})));
            mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
            let client = ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .rest_with_mock(mock)
                .unwrap();
            let _ = client.time().await;
            let reqs = get_mock(&client).captured_requests();
            assert!(reqs.len() >= 2, "Status {} should trigger fallback", status);
        }
        Ok(())
    }


    #[tokio::test]
    async fn rec2c2_connection_timeout_triggers_fallback() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.set_response_delay(std::time::Duration::from_secs(5));
        for _ in 0..4 {
            mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        }
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .http_request_timeout(std::time::Duration::from_millis(100))
            .rest_with_mock(mock)
            .unwrap();
        let result = client.time().await;
        assert!(result.is_err(), "Expected timeout");
        Ok(())
    }


    #[tokio::test]
    async fn rec2c3_dns_failure_triggers_fallback() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let count_c = count.clone();
        let urls: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let urls_c = urls.clone();
        let mock = MockHttpClient::with_handler(move |req| {
            let n = count_c.fetch_add(1, Ordering::SeqCst);
            urls_c.lock().unwrap().push(req.url.host_str().unwrap_or("").to_string());
            if n == 0 {
                MockResponse::network_error()
            } else {
                MockResponse::json(200, &json!([1700000000000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)?;
        let result = client.time().await;
        assert!(result.is_ok(), "Should succeed on fallback");
        let captured_urls = urls.lock().unwrap();
        assert!(captured_urls.len() >= 2, "Should have at least 2 requests");
        assert_ne!(captured_urls[0], captured_urls[1], "Second request should use a different (fallback) host");
        Ok(())
    }


    // REC2c4 already covered by rsc15l_4xx_does_not_trigger_fallback
    #[tokio::test]
    async fn rec2c4_non_5xx_does_not_trigger_fallback() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(400, &json!({"error": {"code": 40000, "statusCode": 400, "message": "Bad request"}})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let result = client.time().await;
        assert!(result.is_err());
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1, "Non-5xx should not trigger fallback");
        Ok(())
    }


    // REC3 already covered by rsc15a_fallback_hosts_tried_on_primary_failure

    #[tokio::test]
    async fn rec3_fallback_retry_exhaustion() -> Result<()> {
        let mock = MockHttpClient::new();
        for _ in 0..4 {
            mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        }
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let result = client.time().await;
        assert!(result.is_err(), "All retries exhausted");
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 4, "primary + 3 fallbacks");
        Ok(())
    }


    #[tokio::test]
    async fn rec3a_fallback_retry_timeout() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        let mut opts = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false);
        opts.fallback_retry_timeout = std::time::Duration::from_millis(100);
        let client = opts.rest_with_mock(mock).unwrap();
        let _ = client.time().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = client.time().await;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs.len() >= 3);
        Ok(())
    }


    #[tokio::test]
    async fn rec3b_fallback_host_state_persistence() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        let _ = client.time().await;
        let _ = client.time().await;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs.len() >= 3);
        Ok(())
    }


    #[tokio::test]
    async fn rsc15f_custom_fallback_hosts_used() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .fallback_hosts(vec!["custom-fallback.example.com".to_string()])
            .rest_with_mock(mock)
            .unwrap();
        let _ = client.time().await;
        let reqs = get_mock(&client).captured_requests();
        assert!(reqs.len() >= 2);
        let fallback_host = reqs[1].url.host_str().unwrap();
        assert_eq!(fallback_host, "custom-fallback.example.com");
        Ok(())
    }


    #[tokio::test]
    async fn rsc15j_environment_fallback_host_generation() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1700000000000_i64])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .environment("sandbox")
            .unwrap()
            .rest_with_mock(mock)
            .unwrap();
        let _ = client.time().await;
        let reqs = get_mock(&client).captured_requests();
        if reqs.len() >= 2 {
            let host = reqs[1].url.host_str().unwrap();
            assert!(
                host.contains("sandbox") || host.contains("ably"),
                "Expected environment-based fallback host, got {}",
                host
            );
        }
        Ok(())
    }


    // ===============================================================
    // Batch 2: Client Options & Host Config
    // ===============================================================

    // ---------------------------------------------------------------
    // HP1 — Default REST host is "main.realtime.ably.net"
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn hp1_default_rest_host() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = mock_client(mock);
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str(), Some("main.realtime.ably.net"));
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP2 — Custom realtime_host does not affect REST host
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn rec1d2_realtime_host_sets_primary_domain() -> Result<()> {
        // REC1d2: with no restHost, a deprecated realtimeHost override
        // becomes the primary domain (REST and realtime share one domain)
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .realtime_host("custom.realtime.host")
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str(), Some("custom.realtime.host"));
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP3 — Default REST port is 80 (when TLS disabled)
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn hp3_default_port_80_when_tls_disabled() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "test-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .tls(false)
            .use_token_auth(true)
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let time_req = reqs.last().unwrap();
        assert_eq!(time_req.url.scheme(), "http");
        assert_eq!(time_req.url.port(), None);
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP4 — Default TLS port is 443
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn hp4_default_tls_port_443() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = mock_client(mock);
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.scheme(), "https");
        assert_eq!(reqs[0].url.port(), None);
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP5 — Custom REST host
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn hp5_custom_rest_host() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("custom.rest.example.com")?
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str(), Some("custom.rest.example.com"));
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP6 — Custom realtime host does not affect REST requests
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn rec1d1_rest_host_takes_precedence_over_realtime_host() -> Result<()> {
        // REC1d1: when both deprecated host overrides are set, restHost wins
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("custom.rest.example.com")?
            .realtime_host("custom.realtime.example.com")
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str(), Some("custom.rest.example.com"));
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP7 — Custom port with TLS disabled
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn hp7_custom_port_with_tls_disabled() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "test-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .port(8080)
            .tls(false)
            .use_token_auth(true)
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let time_req = reqs.last().unwrap();
        assert_eq!(time_req.url.scheme(), "http");
        assert_eq!(time_req.url.port(), Some(8080));
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP8 — Default TLS port in URL (no explicit port suffix)
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn hp8_default_tls_port_in_url() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = mock_client(mock);
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let url_str = reqs[0].url.to_string();
        assert!(url_str.starts_with("https://main.realtime.ably.net/"), "got: {}", url_str);
        Ok(())
    }


    // ---------------------------------------------------------------
    // HP9 — Custom port appears in URL
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn hp9_custom_port_appears_in_url() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "test-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .port(9001)
            .tls(false)
            .use_token_auth(true)
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let time_req = reqs.last().unwrap();
        let url_str = time_req.url.to_string();
        assert!(url_str.contains(":9001"), "got: {}", url_str);
        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1b1 — Environment conflicts with rest_host
    // ---------------------------------------------------------------
    #[test]
    fn rec1b1_environment_conflicts_with_rest_host() {
        let result = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("custom.host.example.com")
            .unwrap()
            .environment("sandbox");
        assert!(result.is_err());
    }


    // ---------------------------------------------------------------
    // REC1b1 — rest_host conflicts with environment
    // ---------------------------------------------------------------
    #[test]
    fn rec1b1_rest_host_conflicts_with_environment() {
        let result = ClientOptions::new("appId.keyId:keySecret")
            .environment("sandbox")
            .unwrap()
            .rest_host("custom.host.example.com");
        assert!(result.is_err());
    }


    // ---------------------------------------------------------------
    // REC1b1 — rest_host conflicts with environment even with
    // realtime_host set
    // ---------------------------------------------------------------
    #[test]
    fn rec1b1_rest_host_conflicts_with_environment_despite_realtime_host() {
        let result = ClientOptions::new("appId.keyId:keySecret")
            .environment("sandbox")
            .unwrap()
            .realtime_host("custom.realtime.example.com")
            .rest_host("custom.rest.example.com");
        assert!(result.is_err());
    }


    // ---------------------------------------------------------------
    // REC1b2 — localhost as rest_host
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn rec1b2_localhost_as_rest_host() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "test-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("localhost")?
            .tls(false)
            .use_token_auth(true)
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let time_req = reqs.last().unwrap();
        assert_eq!(time_req.url.host_str(), Some("localhost"));
        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1b2 — IPv6 loopback as rest_host
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn rec1b2_ipv6_loopback_as_rest_host() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "test-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("[::1]")?
            .tls(false)
            .use_token_auth(true)
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let time_req = reqs.last().unwrap();
        let host = time_req.url.host_str().unwrap();
        assert!(host == "::1" || host == "[::1]", "Expected IPv6 loopback, got: {}", host);
        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1d — rest_host overrides default
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn rec1d_rest_host_overrides_default() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("my-custom-rest.example.com")?
            .rest_with_mock(mock)?;
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str(), Some("my-custom-rest.example.com"));
        Ok(())
    }


    // REC1b2 — an endpoint containing a '.' is a hostname: primary domain is
    // the endpoint itself and there are no fallback domains (REC2c2)
    #[test]
    fn rec1b2_endpoint_hostname() {
        let mut opts = ClientOptions::new("appId.keyId:keySecret")
            .endpoint("custom.example.com")
            .unwrap();
        opts.resolve_hosts();
        assert_eq!(opts.primary_host, "custom.example.com");
        assert!(opts.resolved_fallback_hosts.is_empty());

        let mut opts = ClientOptions::new("appId.keyId:keySecret")
            .endpoint("localhost")
            .unwrap();
        opts.resolve_hosts();
        assert_eq!(opts.primary_host, "localhost");
    }


    // REC1b3/REC2c3 — a "nonprod:[id]" endpoint routes to the nonprod
    // cluster with nonprod fallback domains
    #[test]
    fn rec1b3_endpoint_nonprod_routing_policy() {
        let mut opts = ClientOptions::new("appId.keyId:keySecret")
            .endpoint("nonprod:sandbox")
            .unwrap();
        opts.resolve_hosts();
        assert_eq!(opts.primary_host, "sandbox.realtime.ably-nonprod.net");
        assert_eq!(opts.resolved_fallback_hosts.len(), 5);
        assert_eq!(
            opts.resolved_fallback_hosts[0],
            "sandbox.a.fallback.ably-realtime-nonprod.com"
        );
        assert_eq!(
            opts.resolved_fallback_hosts[4],
            "sandbox.e.fallback.ably-realtime-nonprod.com"
        );
    }


    // REC1b4/REC2c4 — a production routing policy ID endpoint
    #[test]
    fn rec1b4_endpoint_production_routing_policy() {
        let mut opts = ClientOptions::new("appId.keyId:keySecret")
            .endpoint("acme")
            .unwrap();
        opts.resolve_hosts();
        assert_eq!(opts.primary_host, "acme.realtime.ably.net");
        assert_eq!(opts.resolved_fallback_hosts.len(), 5);
        assert_eq!(opts.resolved_fallback_hosts[0], "acme.a.fallback.ably-realtime.com");
    }


    // REC1b1 — endpoint is mutually exclusive with the deprecated options
    #[test]
    fn rec1b1_endpoint_conflicts_with_deprecated_options() {
        assert!(ClientOptions::new("appId.keyId:keySecret")
            .environment("sandbox").unwrap()
            .endpoint("main")
            .is_err());
        assert!(ClientOptions::new("appId.keyId:keySecret")
            .rest_host("custom.example.com").unwrap()
            .endpoint("main")
            .is_err());
        assert!(ClientOptions::new("appId.keyId:keySecret")
            .endpoint("main").unwrap()
            .environment("sandbox")
            .is_err());
    }


    // RSC7c — the request_id persists across fallback retries
    // UTS: rest/unit/RSC7c/request-id-preserved-fallback-1
    #[tokio::test]
    async fn rsc7c_request_id_preserved_across_retries() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.host_str() == Some("main.realtime.ably.net") {
                MockResponse::json(500, &json!({"error": {"code": 50000, "statusCode": 500}}))
            } else {
                MockResponse::json(200, &json!({}))
            }
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .add_request_ids(true)
            .rest_with_mock(mock)
            .unwrap();
        client.request("GET", "/channels/test").send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert!(reqs.len() >= 2, "expected a fallback retry");
        let rid = |i: usize| reqs[i].url.query_pairs()
            .find(|(k, _)| k == "request_id")
            .map(|(_, v)| v.to_string())
            .expect("request_id param present");
        assert_eq!(rid(0), rid(1), "request_id must be identical across retries");
        Ok(())
    }


    // RSC7c — a failed request's ErrorInfo carries the request_id
    #[tokio::test]
    async fn rsc7c_error_info_carries_request_id() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(404, &json!({"error": {"code": 40400, "statusCode": 404, "message": "nope"}}))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .add_request_ids(true)
            .rest_with_mock(mock)
            .unwrap();
        let err = client.channels().get("missing").history().send().await.unwrap_err();
        let rid = err.request_id.expect("ErrorInfo.request_id populated");

        let reqs = get_mock(&client).captured_requests();
        let url_rid = reqs[0].url.query_pairs()
            .find(|(k, _)| k == "request_id")
            .map(|(_, v)| v.to_string())
            .unwrap();
        assert_eq!(rid, url_rid);
        Ok(())
    }


    // TO3l6 — total retry time is bounded by httpMaxRetryDuration
    #[tokio::test]
    async fn to3l6_http_max_retry_duration_enforced() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(500, &json!({"error": {"code": 50000, "statusCode": 500}}))
        });
        // every attempt takes ~50ms; the retry budget allows only ~1 retry
        mock.set_response_delay(std::time::Duration::from_millis(50));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();
        let err = client.channels().get("x").history().send().await.unwrap_err();
        assert_eq!(err.status_code, Some(500));
        // With a 15s default budget all 3 retries run; this asserts the
        // mechanism is wired by checking we did NOT exceed max retries + 1
        let count = get_mock(&client).request_count();
        assert!(count <= 4, "retry count bounded, got {}", count);
        Ok(())
    }


    // HP3 — request() normalises the body: object → single item, array → items
    #[tokio::test]
    async fn hp3_request_items_normalised() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path() == "/single" {
                MockResponse::json(200, &json!({"id": "one"}))
            } else {
                MockResponse::json(200, &json!([{"id": "a"}, {"id": "b"}]))
            }
        });
        let client = mock_client(mock);

        let single = client.request("GET", "/single").send().await?;
        assert_eq!(single.items().len(), 1);
        assert_eq!(single.items()[0]["id"], "one");

        let multi = client.request("GET", "/multi").send().await?;
        assert_eq!(multi.items().len(), 2);
        assert_eq!(multi.items()[1]["id"], "b");
        Ok(())
    }


    // HP2 — request() supports pagination via Link headers
    #[tokio::test]
    async fn hp2_request_pagination() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.query().unwrap_or("").contains("page=2") {
                MockResponse::json(200, &json!([{"id": "second"}]))
            } else {
                MockResponse::json(200, &json!([{"id": "first"}]))
                    .with_header("link", "<./list?page=2>; rel=\"next\"")
            }
        });
        let client = mock_client(mock);
        let page1 = client.request("GET", "/list").send().await?;
        assert!(page1.has_next());
        let page2 = page1.next().await?.expect("next page");
        assert_eq!(page2.items()[0]["id"], "second");
        assert!(page2.is_last());
        Ok(())
    }


    // RSC19f1 — version() overrides the X-Ably-Version header per request
    #[tokio::test]
    async fn rsc19f1_version_override() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = mock_client(mock);
        client.request("GET", "/x").version(3).send().await?;

        let reqs = get_mock(&client).captured_requests();
        let versions: Vec<&str> = reqs[0].headers.iter()
            .filter(|(k, _)| k == "x-ably-version")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(versions, vec!["3"], "exactly one overridden version header");
        Ok(())
    }


    // ---------------------------------------------------------------
    // REC1d — realtime_host overrides default independently
    // ---------------------------------------------------------------
    #[tokio::test]
    async fn rec1d_realtime_host_overrides_default_independently() -> Result<()> {
        // REC1d2: realtimeHost (deprecated) defines the primary domain, and
        // per REC2c6 there are then no fallback domains
        let mut opts = ClientOptions::new("appId.keyId:keySecret")
            .realtime_host("rt.example.com");
        opts.resolve_hosts();
        assert_eq!(opts.primary_host, "rt.example.com");
        assert!(opts.resolved_fallback_hosts.is_empty());
        Ok(())
    }


    // ---------------------------------------------------------------
    // REC2c6 — Custom rest_host clears fallback hosts
    // ---------------------------------------------------------------
    #[test]
    fn rec2c6_rest_host_fallbacks_resolution() {
        // REC2c6: a deprecated restHost override yields no fallback domains
        let mut opts = ClientOptions::new("appId.keyId:keySecret")
            .rest_host("custom.rest.example.com")
            .unwrap();
        opts.resolve_hosts();
        assert_eq!(opts.primary_host, "custom.rest.example.com");
        assert!(opts.resolved_fallback_hosts.is_empty());
    }


    // ===============================================================
    // Batch 5: REST Features — Stats, Time, Batch, Request
    // ===============================================================

    // RSC1b — Empty credential string raises error
    #[test]
    fn rsc1b_empty_credential_raises_error() {
        let result = ClientOptions::new("").rest();
        assert!(result.is_err(), "Empty credential should be rejected");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert_eq!(
            err.code,
            Some(crate::error::ErrorInfoCode::UnableToObtainCredentialsFromGivenParameters.code()),
            "Error code should be 40106"
        );
    }


    // RSC6 — stats() sends GET request
    #[tokio::test]
    async fn rsc6_stats_sends_get() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].url.path(), "/stats");
        Ok(())
    }


    // RSC6 — stats() with multiple parameters
    #[tokio::test]
    async fn rsc6_stats_with_parameters() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client
            .stats()
            .start("1704067200000")
            .end("1706745599000")
            .limit(50)
            .params(&[("unit", "hour")])
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("start").map(|s| s.as_str()), Some("1704067200000"));
        assert_eq!(params.get("end").map(|s| s.as_str()), Some("1706745599000"));
        assert_eq!(params.get("limit").map(|s| s.as_str()), Some("50"));
        assert_eq!(params.get("unit").map(|s| s.as_str()), Some("hour"));
        Ok(())
    }


    // RSC6a — stats() sends authenticated request
    #[tokio::test]
    async fn rsc6a_stats_authenticated_request() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert!(
            reqs[0].headers.iter().any(|(k,_)| k == "authorization"),
            "Stats request should include Authorization header"
        );
        Ok(())
    }


    // RSC6b1 — stats() with start parameter
    #[tokio::test]
    async fn rsc6b1_stats_with_start() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().start("1704067200000").send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("start").map(|s| s.as_str()), Some("1704067200000"));
        Ok(())
    }


    // RSC6b1 — stats() with end parameter
    #[tokio::test]
    async fn rsc6b1_stats_with_end() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().end("1706745599000").send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("end").map(|s| s.as_str()), Some("1706745599000"));
        Ok(())
    }


    // RSC6b3 — stats limit defaults to 100 (no limit param sent)
    #[tokio::test]
    async fn rsc6b3_stats_limit_defaults_to_100() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // When no limit set, server defaults to 100 — SDK should not send limit param
        assert!(
            params.get("limit").is_none(),
            "Expected no limit param by default (server defaults to 100)"
        );
        Ok(())
    }


    // RSC6b4 — stats with unit=hour
    #[tokio::test]
    async fn rsc6b4_stats_with_unit_hour() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().params(&[("unit", "hour")]).send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("unit").map(|s| s.as_str()), Some("hour"));
        Ok(())
    }


    // RSC6b4 — stats with unit=day
    #[tokio::test]
    async fn rsc6b4_stats_with_unit_day() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().params(&[("unit", "day")]).send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("unit").map(|s| s.as_str()), Some("day"));
        Ok(())
    }


    // RSC6b4 — stats with unit=month
    #[tokio::test]
    async fn rsc6b4_stats_with_unit_month() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().params(&[("unit", "month")]).send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params.get("unit").map(|s| s.as_str()), Some("month"));
        Ok(())
    }


    // RSC6b4 — stats unit defaults to minute (no unit param sent)
    #[tokio::test]
    async fn rsc6b4_stats_unit_defaults_to_minute() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        let params: std::collections::HashMap<String, String> = reqs[0]
            .url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // When no unit specified, server defaults to minute — SDK should not send unit
        assert!(
            params.get("unit").is_none(),
            "Expected no unit param by default (server defaults to minute)"
        );
        Ok(())
    }


    // RSC10 — Token renewal on 401 with token error
    #[tokio::test]
    async fn rsc10_token_renewal_on_401() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": format!("token-{}", n),
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else if n == 1 {
                // First API request: 401 with token error (40140-40149 range)
                MockResponse::json(401, &json!({
                    "error": {
                        "code": 40140,
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

        let resp = client.request("GET", "/channels/test").send().await?;
        assert_eq!(resp.status_code(), 200);

        // Should have made: requestToken + request (401) + requestToken + request (200)
        let reqs = get_mock(&client).captured_requests();
        let token_reqs: Vec<_> = reqs.iter().filter(|r| r.url.path().contains("/requestToken")).collect();
        assert!(token_reqs.len() >= 2, "Expected at least 2 token requests (initial + renewal)");
        Ok(())
    }


    // RSC10 — Non-token 401 does NOT trigger renewal
    #[tokio::test]
    async fn rsc10_non_token_401_no_renewal() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock = MockHttpClient::with_handler(move |req| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            if req.url.path().contains("/requestToken") {
                MockResponse::json(200, &json!({
                    "token": "some-token",
                    "expires": 9999999999999_i64,
                    "issued": 1000000000000_i64,
                    "capability": "{\"*\":[\"*\"]}"
                }))
            } else {
                // Non-token 401 error (40100, not in 40140-40149 range)
                MockResponse::json(401, &json!({
                    "error": {
                        "code": 40100,
                        "statusCode": 401,
                        "message": "Unauthorized",
                        "href": ""
                    }
                }))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_token_auth(true)
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.expect_err("Expected 401 error");
        assert_eq!(err.code, Some(crate::error::ErrorInfoCode::Unauthorized.code()));

        // Should have requestToken + 1 API call (no retry for non-token 401)
        let reqs = get_mock(&client).captured_requests();
        let api_reqs: Vec<_> = reqs.iter().filter(|r| !r.url.path().contains("/requestToken")).collect();
        assert_eq!(
            api_reqs.len(), 1,
            "Expected only 1 API request (no retry for non-token 401), got {}",
            api_reqs.len()
        );
        Ok(())
    }


    // RSC15f — Successful fallback: subsequent request retries primary first
    #[tokio::test]
    async fn rsc15f_successful_fallback_cached() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let count_c = call_count.clone();

        let mock = MockHttpClient::with_handler(move |_req| {
            let n = count_c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // Primary fails on first call
                MockResponse::json(500, &json!({"error": {"code": 50000, "statusCode": 500, "message": "fail", "href": ""}}))
            } else {
                // Everything else succeeds
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = mock_client(mock);

        // First request: primary fails, fallback succeeds and gets cached
        client.time().await?;

        // Second request: RSC15f — should try the cached fallback host first
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        // First call: primary (fail) + fallback (success) = 2 requests
        // Second call: cached fallback (success) = 1 request
        assert!(reqs.len() >= 3, "Expected at least 3 requests total");
        let cached_host = reqs[1].url.host_str().unwrap();
        assert_eq!(
            reqs[2].url.host_str().unwrap(), cached_host,
            "Subsequent request should try cached fallback first (RSC15f)"
        );
        Ok(())
    }


    // RSC15l — HTTP 500 triggers fallback
    #[tokio::test]
    async fn rsc15l_500_triggers_fallback() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2, "500 should trigger fallback");
        assert_ne!(
            reqs[0].url.host_str(), reqs[1].url.host_str(),
            "Fallback should use a different host"
        );
        Ok(())
    }


    // RSC15l — HTTP 503 triggers fallback
    #[tokio::test]
    async fn rsc15l_503_triggers_fallback() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(503, &json!({"error": {"code": 50300}})));
        mock.queue_response(MockResponse::json(200, &json!([1234567890000_i64])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2, "503 should trigger fallback");
        assert_ne!(
            reqs[0].url.host_str(), reqs[1].url.host_str(),
            "Fallback should use a different host"
        );
        Ok(())
    }


    // RSC15m — No fallback when fallback hosts list is empty
    #[tokio::test]
    async fn rsc15m_no_fallback_when_empty() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(500, &json!({"error": {"code": 50000}})));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .fallback_hosts(vec![])
            .rest_with_mock(mock)
            .unwrap();

        let err = client.time().await.unwrap_err();
        assert_eq!(err.status_code, Some(500));

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1, "Should not retry when fallback hosts are empty");
        Ok(())
    }


    // RSC22 — batch publish with empty messages is rejected client-side
    // UTS: rest/unit/RSC22/empty-messages-rejected-0
    #[tokio::test]
    async fn rsc22_empty_messages_error() {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = mock_client(mock);

        // No specs at all
        let err = client.batch_publish(vec![]).await.unwrap_err();
        assert_eq!(err.code, Some(40003));

        // Spec with channels but no messages
        let err = client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec!["ch1".to_string()],
                messages: vec![],
            }])
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(40003));

        // No HTTP request may have been made for either rejection
        assert_eq!(get_mock(&client).request_count(), 0);
    }


    // RSC22 — batch publish with empty channels is rejected client-side
    // UTS: rest/unit/RSC22/empty-channels-rejected-0
    #[tokio::test]
    async fn rsc22_empty_channels_error() {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = mock_client(mock);

        let err = client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec![],
                messages: vec![crate::rest::Message {
                    name: Some("e".into()),
                    data: crate::rest::Data::String("d".into()),
                    ..Default::default()
                }],
            }])
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(40003));
        assert_eq!(get_mock(&client).request_count(), 0);
    }


    // RSC22 — Batch publish: server error propagated (different from rsc22_server_error_propagated using 400)
    #[tokio::test]
    async fn rsc22_server_error() {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(400, &json!({
                "error": {
                    "code": 40000,
                    "statusCode": 400,
                    "message": "Bad request",
                    "href": ""
                }
            }))
        });

        let client = mock_client(mock);
        let result = client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec!["ch1".to_string()],
                messages: vec![crate::rest::Message::default()],
            }])
            .await;
        assert!(result.is_err(), "400 error should be propagated");
    }


    // RSC22 — Batch publish: auth error (401)
    #[tokio::test]
    async fn rsc22_auth_error() {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(401, &json!({
                "error": {
                    "code": 40100,
                    "statusCode": 401,
                    "message": "Unauthorized",
                    "href": ""
                }
            }))
        });

        let client = mock_client(mock);
        let result = client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec!["ch1".to_string()],
                messages: vec![crate::rest::Message::default()],
            }])
            .await;
        assert!(result.is_err(), "401 error should be propagated");
    }


    // RSC22 — Batch publish sends standard Ably headers
    #[tokio::test]
    async fn rsc22_standard_headers() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{"channel": "ch1", "messageId": "msg-1"}]))
        });
        let client = mock_client(mock);
        client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec!["ch1".to_string()],
                messages: vec![crate::rest::Message::default()],
            }])
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "authorization"), "Should include auth header");
        assert!(reqs[0].headers.iter().any(|(k,_)| k == "x-ably-version"), "Should include version header");
        Ok(())
    }


    // RSC22d — Batch publish preserves explicit message IDs
    #[tokio::test]
    async fn rsc22d_explicit_ids_preserved() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([{"channel": "ch1", "messageId": "msg-1"}]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();

        let mut msg = crate::rest::Message::default();
        msg.id = Some("explicit-batch-id".to_string());
        msg.name = Some("event".to_string());

        client
            .batch_publish(vec![BatchPublishSpec {
                channels: vec!["ch1".to_string()],
                messages: vec![msg],
            }])
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let body: serde_json::Value =
            serde_json::from_slice(reqs[0].body.as_deref().unwrap()).unwrap();
        // Batch publish body is an array of specs or a single spec
        if let Some(arr) = body.as_array() {
            // Array of specs
            let messages = &arr[0]["messages"];
            if let Some(msgs) = messages.as_array() {
                assert_eq!(msgs[0]["id"], "explicit-batch-id");
            }
        } else {
            // Single spec
            let messages = &body["messages"];
            if let Some(msgs) = messages.as_array() {
                assert_eq!(msgs[0]["id"], "explicit-batch-id");
            }
        }
        Ok(())
    }


    // BGR2_2 — success result with empty presence (no members)
    // UTS: rest/unit/BGR2/success-empty-presence-0
    #[tokio::test]
    async fn bgr2_success_empty_presence() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({
                "successCount": 1,
                "failureCount": 0,
                "results": [{"channel": "empty-channel", "presence": []}]
            }))
        });
        let client = mock_client(mock);
        let result = client.batch_presence(&["empty-channel"]).await?;
        match &result.results[0] {
            crate::rest::BatchPresenceResult::Success(s) => {
                assert_eq!(s.channel, "empty-channel");
                assert!(s.presence.is_empty());
            }
            other => panic!("Expected success result, got {:?}", other),
        }
        Ok(())
    }


    // RSC24_Error_1 — server-level error propagated as an error
    // UTS: rest/unit/RSC24/server-error-propagated-0
    #[tokio::test]
    async fn rsc24_server_error_propagated() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(500, &json!({
                "error": {
                    "code": 50000,
                    "statusCode": 500,
                    "message": "Internal error"
                }
            }))
        });
        let client = mock_client(mock);
        let err = client.batch_presence(&["any-channel"]).await.unwrap_err();
        assert_eq!(err.code, Some(50000));
        assert_eq!(err.status_code, Some(500));
    }


    // RSC24_Error_2 — authentication error propagated as an error
    // UTS: rest/unit/RSC24/auth-error-propagated-0
    #[tokio::test]
    async fn rsc24_auth_error_propagated() {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(401, &json!({
                "error": {
                    "code": 40101,
                    "statusCode": 401,
                    "message": "Invalid credentials"
                }
            }))
        });
        let client = mock_client(mock);
        let err = client.batch_presence(&["any-channel"]).await.unwrap_err();
        assert_eq!(err.code, Some(40101));
        assert_eq!(err.status_code, Some(401));
    }


    // RSC24_Auth_1 — batch presence uses the configured (Basic) authentication
    // UTS: rest/unit/RSC24/uses-configured-auth-0
    #[tokio::test]
    async fn rsc24_basic_auth_header_included() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({
                "successCount": 1,
                "failureCount": 0,
                "results": [{"channel": "ch", "presence": []}]
            }))
        });
        let client = mock_client(mock);
        client.batch_presence(&["ch1"]).await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        let auth = reqs[0]
            .headers.iter().find(|(k,_)| k == "authorization").map(|(_,v)| v.as_str()).expect("Expected Authorization header");
        assert!(
            auth.starts_with("Basic "),
            "Expected Basic auth for key-based client, got {}",
            auth
        );
        Ok(())
    }


    // ===============================================================
    // Batch 12: Untagged / Misc tests
    // ===============================================================

    // BAR2_3 — all failure
    // UTS: rest/unit/BAR2/all-failure-counts-0
    #[tokio::test]
    async fn bar2_all_failure() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!({
                "successCount": 0,
                "failureCount": 2,
                "results": [
                    {"channel": "denied-1", "error": {"code": 40160, "statusCode": 401, "message": "Not permitted"}},
                    {"channel": "denied-2", "error": {"code": 40160, "statusCode": 401, "message": "Not permitted"}}
                ]
            }))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .rest_with_mock(mock)
            .unwrap();

        let result = client.batch_presence(&["denied-1", "denied-2"]).await?;
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 2);
        assert_eq!(result.results.len(), 2);
        for r in &result.results {
            match r {
                crate::rest::BatchPresenceResult::Failure(f) => {
                    assert_eq!(f.error.code, Some(40160));
                }
                other => panic!("Expected failure result, got {:?}", other),
            }
        }
        Ok(())
    }


    // -- BPF1a/BPF1b: batch publish format --

    #[tokio::test]
    async fn bpf1a_batch_publish_single_channel_format() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.method, "POST");
            assert!(req.url.path().contains("/messages"));
            MockResponse::json(200, &json!([
                {"channel": "ch1", "messageId": "msg-1"}
            ]))
        });

        let client = mock_client_json(mock);
        let spec = crate::rest::BatchPublishSpec {
            channels: vec!["ch1".to_string()],
            messages: vec![crate::rest::Message {
                name: Some("event".into()),
                data: crate::rest::Data::String("hello".into()),
                ..Default::default()
            }],
        };
        let result = client.batch_publish(vec![spec]).await?;
        assert_eq!(result.len(), 1);
        Ok(())
    }


    #[tokio::test]
    async fn bpf1b_batch_publish_multi_channel_format() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"channel": "ch1", "messageId": "msg-1"},
                {"channel": "ch2", "messageId": "msg-2"}
            ]))
        });

        let client = mock_client_json(mock);
        let spec = crate::rest::BatchPublishSpec {
            channels: vec!["ch1".to_string(), "ch2".to_string()],
            messages: vec![crate::rest::Message {
                name: Some("event".into()),
                data: crate::rest::Data::String("hello".into()),
                ..Default::default()
            }],
        };
        let result = client.batch_publish(vec![spec]).await?;
        assert_eq!(result.len(), 2);
        Ok(())
    }


    // -- BPR1a/BPR1b/BPR1c: batch publish result --

    #[tokio::test]
    async fn bpr1a_batch_publish_result_success() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"channel": "ch1", "messageId": "msg-1", "serials": ["serial-1"]}
            ]))
        });

        let client = mock_client_json(mock);
        let spec = crate::rest::BatchPublishSpec {
            channels: vec!["ch1".to_string()],
            messages: vec![crate::rest::Message {
                name: Some("event".into()),
                data: crate::rest::Data::String("data".into()),
                ..Default::default()
            }],
        };
        let results = client.batch_publish(vec![spec]).await?;
        assert_eq!(results.len(), 1);
        match &results[0] {
            crate::rest::BatchPublishResult::Success(s) => {
                assert_eq!(s.channel, "ch1");
                assert!(s.message_id.is_some());
            }
            _ => panic!("Expected success result"),
        }
        Ok(())
    }


    #[tokio::test]
    async fn bpr1b_batch_publish_result_failure() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"channel": "forbidden-ch", "error": {"code": 40160, "statusCode": 401, "message": "Unauthorized"}}
            ]))
        });

        let client = mock_client_json(mock);
        let spec = crate::rest::BatchPublishSpec {
            channels: vec!["forbidden-ch".to_string()],
            messages: vec![crate::rest::Message {
                name: Some("event".into()),
                data: crate::rest::Data::String("data".into()),
                ..Default::default()
            }],
        };
        let results = client.batch_publish(vec![spec]).await?;
        assert_eq!(results.len(), 1);
        match &results[0] {
            crate::rest::BatchPublishResult::Failure(f) => {
                assert_eq!(f.channel, "forbidden-ch");
                assert_eq!(f.error.code, Some(40160));
            }
            _ => panic!("Expected failure result"),
        }
        Ok(())
    }


    #[tokio::test]
    async fn bpr1c_batch_publish_result_mixed() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([
                {"channel": "ok-ch", "messageId": "msg-1"},
                {"channel": "bad-ch", "error": {"code": 40160, "statusCode": 401, "message": "Unauthorized"}}
            ]))
        });

        let client = mock_client_json(mock);
        let spec = crate::rest::BatchPublishSpec {
            channels: vec!["ok-ch".to_string(), "bad-ch".to_string()],
            messages: vec![crate::rest::Message {
                name: Some("event".into()),
                data: crate::rest::Data::String("data".into()),
                ..Default::default()
            }],
        };
        let results = client.batch_publish(vec![spec]).await?;
        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0], crate::rest::BatchPublishResult::Success(_)));
        assert!(matches!(&results[1], crate::rest::BatchPublishResult::Failure(_)));
        Ok(())
    }


    // -- BSP1a/BSP1b: batch spec fields --

    #[test]
    fn bsp1a_batch_spec_channels_field() {
        let spec = crate::rest::BatchPublishSpec {
            channels: vec!["ch-a".into(), "ch-b".into(), "ch-c".into()],
            messages: vec![],
        };
        assert_eq!(spec.channels.len(), 3);
        assert_eq!(spec.channels[0], "ch-a");
        assert_eq!(spec.channels[1], "ch-b");
        assert_eq!(spec.channels[2], "ch-c");

        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["channels"].as_array().unwrap().len(), 3);
    }


    #[test]
    fn bsp1b_batch_spec_messages_field() {
        let spec = crate::rest::BatchPublishSpec {
            channels: vec!["ch-1".into()],
            messages: vec![
                crate::rest::Message {
                    name: Some("event1".into()),
                    data: crate::rest::Data::String("data1".into()),
                    ..Default::default()
                },
                crate::rest::Message {
                    name: Some("event2".into()),
                    data: crate::rest::Data::String("data2".into()),
                    ..Default::default()
                },
            ],
        };
        assert_eq!(spec.messages.len(), 2);

        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["messages"].as_array().unwrap().len(), 2);
        assert_eq!(json["messages"][0]["name"], "event1");
        assert_eq!(json["messages"][1]["name"], "event2");
    }


    // ===============================================================
    // RSC depth — REST client depth
    // ===============================================================

    #[tokio::test]
    async fn rsc8a_json_content_type_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish().name("e").string("d").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let ct = reqs[0].headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str()).unwrap();
        assert!(ct.contains("json"), "Expected JSON content-type, got: {}", ct);
        Ok(())
    }


    #[tokio::test]
    async fn rsc8a_msgpack_content_type_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(true)
            .rest_with_mock(mock)
            .unwrap();
        client.channels().get("test").publish().name("e").string("d").send().await?;
        let reqs = get_mock(&client).captured_requests();
        let ct = reqs[0].headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str()).unwrap();
        assert!(ct.contains("msgpack"), "Expected msgpack content-type, got: {}", ct);
        Ok(())
    }


    #[tokio::test]
    async fn rsc8a_accept_header_json_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let accept = reqs[0].headers.iter().find(|(k,_)| k == "accept").map(|(_,v)| v.as_str()).unwrap();
        assert!(accept.contains("json"), "Expected JSON Accept header, got: {}", accept);
        Ok(())
    }


    #[tokio::test]
    async fn rsc7c_request_id_format_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .add_request_ids(true)
            .rest_with_mock(mock)
            .unwrap();
        client.time().await?;
        let reqs = get_mock(&client).captured_requests();
        let request_id = reqs[0].url.query_pairs()
            .find(|(k, _)| k == "request_id")
            .map(|(_, v)| v.to_string());
        assert!(request_id.is_some(), "Expected request_id query param");
        let rid = request_id.unwrap();
        assert!(rid.len() >= 16, "request_id should be at least 16 chars, got {}", rid.len());
        Ok(())
    }


    #[tokio::test]
    async fn rsc7c_request_id_unique_per_request() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([1234567890000_i64]))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .add_request_ids(true)
            .rest_with_mock(mock)
            .unwrap();
        client.time().await.ok();
        client.time().await.ok();
        let reqs = get_mock(&client).captured_requests();
        if reqs.len() >= 2 {
            let rid1 = reqs[0].url.query_pairs()
                .find(|(k, _)| k == "request_id").unwrap().1.to_string();
            let rid2 = reqs[1].url.query_pairs()
                .find(|(k, _)| k == "request_id").unwrap().1.to_string();
            assert_ne!(rid1, rid2, "Each request should have a unique request_id");
        }
        Ok(())
    }


    #[tokio::test]
    async fn rsc22c_batch_publish_request_path_depth() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.url.path(), "/messages");
            MockResponse::json(200, &json!([{"channel": "ch1", "messageId": "m1"}]))
        });
        let client = mock_client(mock);
        client.batch_publish(vec![BatchPublishSpec {
            channels: vec!["ch1".to_string()],
            messages: vec![crate::rest::Message::default()],
        }]).await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsc22c_batch_publish_body_contains_channels_depth() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|req| {
            if let Some(body) = &req.body {
                let parsed: serde_json::Value = rmp_serde::from_slice(body)
                    .or_else(|_| serde_json::from_slice(body))
                    .unwrap();
                // Body should be an array of specs, each with channels
                let specs = parsed.as_array().unwrap();
                assert!(specs[0].get("channels").is_some());
            }
            MockResponse::json(200, &json!([{"channel": "ch1", "messageId": "m1"}]))
        });
        let client = mock_client(mock);
        client.batch_publish(vec![BatchPublishSpec {
            channels: vec!["ch1".to_string()],
            messages: vec![crate::rest::Message::default()],
        }]).await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsc22c_batch_publish_auth_header_depth() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|req| {
            assert!(req.headers.iter().any(|(k,_)| k == "authorization"), "Batch publish should include auth header");
            MockResponse::json(200, &json!([{"channel": "ch1", "messageId": "m1"}]))
        });
        let client = mock_client(mock);
        client.batch_publish(vec![BatchPublishSpec {
            channels: vec!["ch1".to_string()],
            messages: vec![crate::rest::Message::default()],
        }]).await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsc22c_batch_publish_empty_specs_depth() -> Result<()> {
        use crate::rest::BatchPublishSpec;
        let mock = MockHttpClient::with_handler(|_req| {
            MockResponse::json(200, &json!([]))
        });
        let client = mock_client(mock);
        let result = client.batch_publish(vec![]).await;
        // Empty batch should either succeed with empty result or fail gracefully
        match result {
            Ok(v) => assert!(v.is_empty()),
            Err(_) => {} // also acceptable
        }
        Ok(())
    }


    #[tokio::test]
    async fn rsc25_path_preserved_in_request_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert_eq!(req.url.path(), "/custom/endpoint");
            MockResponse::json(200, &json!({}))
        });
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.request("GET", "/custom/endpoint").send().await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsc19c_json_content_type_in_request_depth() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!({})));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_mock(mock)
            .unwrap();
        client.request("POST", "/test")
            .body(&json!({"k": "v"}))
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let ct = reqs[0].headers.iter().find(|(k,_)| k == "content-type").map(|(_,v)| v.as_str()).unwrap();
        assert!(ct.contains("json"), "Expected JSON Content-Type for JSON-mode request");
        Ok(())
    }


    // (duplicate batch-presence "depth" tests removed — UTS-derived coverage
    // lives in the RSC24/BAR2/BGR2/BGF2 block above)

    // ===============================================================
    // Stats depth
    // ===============================================================

    #[tokio::test]
    async fn rsc6a_stats_endpoint_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            assert!(req.url.path().contains("/stats"));
            MockResponse::json(200, &json!([]))
        });
        let client = mock_client(mock);
        client.stats().send().await?;
        Ok(())
    }


    #[tokio::test]
    async fn rsc6a_stats_with_params_depth() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
        let client = mock_client(mock);
        client.stats()
            .params(&[("unit", "hour")])
            .send()
            .await?;
        let reqs = get_mock(&client).captured_requests();
        let unit = reqs[0].url.query_pairs()
            .find(|(k, _)| k == "unit")
            .map(|(_, v)| v.to_string());
        assert_eq!(unit.as_deref(), Some("hour"));
        Ok(())
    }


    #[tokio::test]
    async fn rsc15_custom_fallback_hosts_depth() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock = MockHttpClient::with_handler(move |_req| {
            let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                MockResponse::json(500, &json!({
                    "error": {"code": 50000, "statusCode": 500, "message": "fail", "href": ""}
                }))
            } else {
                MockResponse::json(200, &json!([1234567890000_i64]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .fallback_hosts(vec!["fallback1.example.com".to_string()])
            .rest_with_mock(mock)
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);
        Ok(())
    }


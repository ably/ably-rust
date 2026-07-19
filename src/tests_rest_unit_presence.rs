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

// ===============================================================
// Phase 4: REST Presence
// ===============================================================

// ---------------------------------------------------------------
// RSP1a, RSL3 — Presence accessible via channel.presence
// Also covers: RSP1 (presence associated with channel)
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[test]
fn rsp1a_presence_accessible_via_channel() {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    // Accessing channel.presence should work without error
    let channel = client.channels().get("test");
    let _presence = &channel.presence();
    // If this compiles and doesn't panic, the test passes
}

// ---------------------------------------------------------------
// RSP3a — Presence get sends GET to /channels/<name>/presence
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp3a_presence_get_sends_get_to_presence_endpoint() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([
                {"action": 1, "clientId": "client1", "data": "hello"},
                {"action": 1, "clientId": "client2", "data": "world"}
            ]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test-rsp3")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    let reqs = get_mock(&client).captured_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert!(
        reqs[0].url.path().contains("/channels/test-rsp3/presence"),
        "URL should contain /channels/test-rsp3/presence, got: {}",
        reqs[0].url.path()
    );
    // Should not contain /history
    assert!(
        !reqs[0].url.path().contains("/history"),
        "Presence get URL should not contain /history"
    );

    assert_eq!(items.len(), 2);

    Ok(())
}

// ---------------------------------------------------------------
// RSP3b — Presence get returns PresenceMessage objects with fields
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp3b_presence_get_returns_presence_messages() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "user123",
                "connectionId": "conn456",
                "data": "status data",
                "timestamp": 1234567890000u64
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].action, Some(crate::rest::PresenceAction::Present));
    assert_eq!(items[0].client_id, Some("user123".to_string()));
    assert_eq!(items[0].connection_id, Some("conn456".to_string()));
    assert_eq!(
        items[0].data,
        crate::rest::Data::String("status data".to_string())
    );
    assert_eq!(items[0].timestamp, Some(1234567890000));

    Ok(())
}

// ---------------------------------------------------------------
// RSP3c — Presence get with no members returns empty list
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp3c_presence_get_empty_returns_empty_list() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(items.len(), 0);

    Ok(())
}

// ---------------------------------------------------------------
// RSP3a1a — Presence get with limit parameter
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp3a1a_presence_get_with_limit() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    client
        .channels()
        .get("test")
        .presence()
        .get()
        .limit(50)
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let limit = query.iter().find(|(k, _)| k == "limit");
    assert_eq!(limit.unwrap().1, "50");

    Ok(())
}

// ---------------------------------------------------------------
// RSP3a2 — Presence get with clientId filter
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp3a2_presence_get_with_client_id_filter() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    client
        .channels()
        .get("test")
        .presence()
        .get()
        .client_id("specific-client")
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let cid = query.iter().find(|(k, _)| k == "clientId");
    assert_eq!(cid.unwrap().1, "specific-client");

    Ok(())
}

// ---------------------------------------------------------------
// RSP3a3 — Presence get with connectionId filter
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp3a3_presence_get_with_connection_id_filter() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    client
        .channels()
        .get("test")
        .presence()
        .get()
        .connection_id("conn123")
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let cid = query.iter().find(|(k, _)| k == "connectionId");
    assert_eq!(cid.unwrap().1, "conn123");

    Ok(())
}

// ---------------------------------------------------------------
// RSP4a — Presence history sends GET to /channels/<name>/presence/history
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp4a_presence_history_endpoint() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([
                {"action": 2, "clientId": "client1", "data": "entered"},
                {"action": 4, "clientId": "client1", "data": "left"}
            ]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test-rsp4");
    let result = channel.presence().history().send().await?;
    let items = result.items();

    let reqs = get_mock(&client).captured_requests();
    assert_eq!(reqs[0].method, "GET");
    assert!(
        reqs[0]
            .url
            .path()
            .contains("/channels/test-rsp4/presence/history"),
        "URL should contain /channels/test-rsp4/presence/history, got: {}",
        reqs[0].url.path()
    );

    assert_eq!(items.len(), 2);

    Ok(())
}

// ---------------------------------------------------------------
// RSP4a — Presence history returns PresenceMessage with action types
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp4a_presence_history_returns_action_types() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([
                {"action": 2, "clientId": "user1", "data": "d1", "timestamp": 1000},
                {"action": 3, "clientId": "user1", "data": "d2", "timestamp": 2000},
                {"action": 4, "clientId": "user1", "data": "d3", "timestamp": 3000}
            ]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test");
    let result = channel.presence().history().send().await?;
    let items = result.items();

    assert_eq!(items.len(), 3);
    // PresenceAction: Absent=0, Present=1, Enter=2, Leave=3, Update=4
    assert_eq!(items[0].action, Some(crate::rest::PresenceAction::Enter)); // action 2
    assert_eq!(items[1].action, Some(crate::rest::PresenceAction::Leave)); // action 3
    assert_eq!(items[2].action, Some(crate::rest::PresenceAction::Update)); // action 4

    Ok(())
}

// ---------------------------------------------------------------
// RSP4 — Presence history with all parameters
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp4_presence_history_with_all_params() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test");
    channel
        .presence()
        .history()
        .start("1609459200000")
        .end("1609545600000")
        .forwards()
        .limit(50)
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    assert_eq!(
        query.iter().find(|(k, _)| k == "start").unwrap().1,
        "1609459200000"
    );
    assert_eq!(
        query.iter().find(|(k, _)| k == "end").unwrap().1,
        "1609545600000"
    );
    assert_eq!(
        query.iter().find(|(k, _)| k == "direction").unwrap().1,
        "forwards"
    );
    assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "50");

    Ok(())
}

// ---------------------------------------------------------------
// RSP4b2a — Presence history default direction backwards
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp4b2a_presence_history_default_direction_backwards() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test");
    channel.presence().history().send().await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
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
// RSP5a — String data decoded as string (presence get)
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp5a_presence_string_data_decoded() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{"action": 1, "clientId": "c1", "data": "plain string data"}]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::String("plain string data".to_string())
    );

    Ok(())
}

// ---------------------------------------------------------------
// RSP5b — JSON encoded data decoded to object (presence)
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp5b_presence_json_data_decoded() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "c1",
                "data": r#"{"status":"online","count":42}"#,
                "encoding": "json"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::JSON(json!({"status": "online", "count": 42}))
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

// ---------------------------------------------------------------
// RSP5c — Base64 encoded data decoded to binary (presence)
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp5c_presence_base64_data_decoded() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "c1",
                "data": "SGVsbG8gV29ybGQ=",
                "encoding": "base64"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::Binary(serde_bytes::ByteBuf::from(b"Hello World".to_vec()))
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

// ---------------------------------------------------------------
// RSP5d — UTF-8/base64 chained encoding decoded (presence)
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp5d_presence_utf8_base64_decoded() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "c1",
                "data": "SGVsbG8gV29ybGQ=",
                "encoding": "utf-8/base64"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::String("Hello World".to_string())
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

// ---------------------------------------------------------------
// RSP5e — Chained json/base64 encoding decoded (presence)
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp5e_presence_chained_json_base64_decoded() -> Result<()> {
    // base64 of {"key":"value"}
    let b64 = base64::encode(r#"{"key":"value"}"#);

    let mock = MockHttpClient::with_handler(move |_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "c1",
                "data": b64,
                "encoding": "json/base64"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::JSON(json!({"key": "value"}))
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

// ---------------------------------------------------------------
// RSP5f — History messages also decoded (presence)
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp5f_presence_history_messages_decoded() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 2,
                "clientId": "c1",
                "data": r#"{"event":"entered"}"#,
                "encoding": "json"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test");
    let result = channel.presence().history().send().await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::JSON(json!({"event": "entered"}))
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

// ---------------------------------------------------------------
// RSP3 — Presence get with multiple filters combined
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp3_presence_get_with_multiple_filters() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    client
        .channels()
        .get("test")
        .presence()
        .get()
        .limit(25)
        .client_id("user1")
        .connection_id("conn1")
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "25");
    assert_eq!(
        query.iter().find(|(k, _)| k == "clientId").unwrap().1,
        "user1"
    );
    assert_eq!(
        query.iter().find(|(k, _)| k == "connectionId").unwrap().1,
        "conn1"
    );

    Ok(())
}

// ---------------------------------------------------------------
// RSP4b2b — Presence history with direction forwards
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp4b2b_presence_history_direction_forwards() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test");
    channel.presence().history().forwards().send().await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(
        query.iter().find(|(k, _)| k == "direction").unwrap().1,
        "forwards"
    );

    Ok(())
}

// ---------------------------------------------------------------
// RSP5 — Presence binary data decoded from MessagePack
// UTS: rest/unit/presence/rest_presence.md
// ---------------------------------------------------------------

#[tokio::test]
async fn rsp5_presence_msgpack_binary_data_preserved() -> Result<()> {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct MsgpackPresence {
        action: u8,
        client_id: String,
        data: serde_bytes::ByteBuf,
    }

    let msg = MsgpackPresence {
        action: 1, // present
        client_id: "client1".to_string(),
        data: serde_bytes::ByteBuf::from(b"some data".to_vec()),
    };

    let mock = MockHttpClient::with_handler(move |_req| MockResponse::msgpack(200, &vec![&msg]));

    let client = mock_client(mock);
    let res = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = res.items();

    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].data,
        crate::rest::Data::Binary(serde_bytes::ByteBuf::from(b"some data".to_vec()))
    );

    Ok(())
}

// ===============================================================
// Batch 6: RSP3-RSP5 — REST Presence
// ===============================================================

#[tokio::test]
async fn rsp3_get_with_404() -> Result<()> {
    let mock = MockHttpClient::with_handler(|req| {
        assert!(req.url.path().contains("/presence"));
        MockResponse::json(
            404,
            &json!({"error": {"code": 40400, "statusCode": 404, "message": "Not found", "href": ""}}),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("nonexistent")
        .presence()
        .get()
        .send()
        .await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn rsp3_get_with_combined_filters() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    client
        .channels()
        .get("test")
        .presence()
        .get()
        .client_id("user-abc")
        .connection_id("conn-xyz")
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(
        query.iter().find(|(k, _)| k == "clientId").unwrap().1,
        "user-abc"
    );
    assert_eq!(
        query.iter().find(|(k, _)| k == "connectionId").unwrap().1,
        "conn-xyz"
    );

    Ok(())
}

#[tokio::test]
async fn rsp3a1_get_limit_query_param() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    client
        .channels()
        .get("test")
        .presence()
        .get()
        .limit(25)
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "25");

    Ok(())
}

#[tokio::test]
async fn rsp4_history_with_all_params() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test-hist");
    channel
        .presence()
        .history()
        .start("1700000000000")
        .end("1700100000000")
        .forwards()
        .limit(10)
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    assert!(reqs[0]
        .url
        .path()
        .contains("/channels/test-hist/presence/history"));
    let query: Vec<(String, String)> = reqs[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(
        query.iter().find(|(k, _)| k == "start").unwrap().1,
        "1700000000000"
    );
    assert_eq!(
        query.iter().find(|(k, _)| k == "end").unwrap().1,
        "1700100000000"
    );
    assert_eq!(
        query.iter().find(|(k, _)| k == "direction").unwrap().1,
        "forwards"
    );
    assert_eq!(query.iter().find(|(k, _)| k == "limit").unwrap().1, "10");

    Ok(())
}

#[tokio::test]
async fn rsp4_history_auth_header() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    client
        .channels()
        .get("test")
        .presence()
        .history()
        .send()
        .await?;

    let reqs = get_mock(&client).captured_requests();
    assert_eq!(reqs.len(), 1);
    let auth_header = reqs[0]
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .expect("Expected Authorization header");
    let auth_str = auth_header;
    assert!(
        auth_str.starts_with("Basic "),
        "Expected Basic auth, got: {}",
        auth_str
    );

    Ok(())
}

#[tokio::test]
async fn rsp5_decode_utf8_presence_data() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "c1",
                "data": "SGVsbG8gV29ybGQ=",
                "encoding": "utf-8/base64"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::String("Hello World".to_string())
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

#[tokio::test]
async fn rsp5_decode_base64_presence_data() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "c1",
                "data": "AQIDBA==",
                "encoding": "base64"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::Binary(serde_bytes::ByteBuf::from(vec![1, 2, 3, 4]))
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

#[tokio::test]
async fn rsp5_decode_json_presence_data() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "c1",
                "data": r#"{"key":"value","num":99}"#,
                "encoding": "json"
            }]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let result = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = result.items();

    assert_eq!(
        items[0].data,
        crate::rest::Data::JSON(json!({"key": "value", "num": 99}))
    );
    assert_eq!(items[0].encoding, None);

    Ok(())
}

// ===============================================================
// RSP depth — Presence depth
// ===============================================================

#[tokio::test]
async fn rsp3a1b_default_limit_not_set_depth() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let reqs = get_mock(&client).captured_requests();
    let has_limit = reqs[0].url.query_pairs().any(|(k, _)| k == "limit");
    assert!(
        !has_limit,
        "Default presence get should not include limit param"
    );
    Ok(())
}

#[tokio::test]
async fn rsp4b1_history_start_param_depth() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    client
        .channels()
        .get("test")
        .presence()
        .history()
        .start("1609459200000")
        .send()
        .await?;
    let reqs = get_mock(&client).captured_requests();
    let start = reqs[0]
        .url
        .query_pairs()
        .find(|(k, _)| k == "start")
        .map(|(_, v)| v.to_string());
    assert_eq!(start.as_deref(), Some("1609459200000"));
    Ok(())
}

#[tokio::test]
async fn rsp4b2_history_end_param_depth() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    client
        .channels()
        .get("test")
        .presence()
        .history()
        .end("1609545600000")
        .send()
        .await?;
    let reqs = get_mock(&client).captured_requests();
    let end = reqs[0]
        .url
        .query_pairs()
        .find(|(k, _)| k == "end")
        .map(|(_, v)| v.to_string());
    assert_eq!(end.as_deref(), Some("1609545600000"));
    Ok(())
}

#[tokio::test]
async fn rsp4b3_history_backwards_param_depth() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    client
        .channels()
        .get("test")
        .presence()
        .history()
        .backwards()
        .send()
        .await?;
    let reqs = get_mock(&client).captured_requests();
    let dir = reqs[0]
        .url
        .query_pairs()
        .find(|(k, _)| k == "direction")
        .map(|(_, v)| v.to_string());
    assert_eq!(dir.as_deref(), Some("backwards"));
    Ok(())
}

#[tokio::test]
async fn rsp4b4_history_limit_param_depth() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    client
        .channels()
        .get("test")
        .presence()
        .history()
        .limit(25)
        .send()
        .await?;
    let reqs = get_mock(&client).captured_requests();
    let limit = reqs[0]
        .url
        .query_pairs()
        .find(|(k, _)| k == "limit")
        .map(|(_, v)| v.to_string());
    assert_eq!(limit.as_deref(), Some("25"));
    Ok(())
}

#[tokio::test]
async fn rsp_presence_message_with_string_data_depth() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 1,
                "clientId": "user-1",
                "data": "plain-text-data"
            }]),
        )
    });
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    let res = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = res.items();
    assert_eq!(
        items[0].data,
        crate::rest::Data::String("plain-text-data".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn rsp_presence_message_with_json_data_depth() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([{
                "action": 2,
                "clientId": "user-2",
                "data": "{\"status\":\"online\"}",
                "encoding": "json"
            }]),
        )
    });
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    let res = client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await?;
    let items = res.items();
    match &items[0].data {
        crate::rest::Data::JSON(v) => assert_eq!(v["status"], "online"),
        other => panic!("Expected JSON data, got: {:?}", other),
    }
    Ok(())
}

#[tokio::test]
async fn rsp_server_error_depth() {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            500,
            &json!({
                "error": {"code": 50000, "statusCode": 500, "message": "Server failure", "href": ""}
            }),
        )
    });
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    let result = client.channels().get("test").presence().get().send().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn rsp_auth_error_depth() {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            401,
            &json!({
                "error": {"code": 40100, "statusCode": 401, "message": "Unauthorized", "href": ""}
            }),
        )
    });
    let client = ClientOptions::with_token("expired-token".to_string())
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();
    let result = client.channels().get("test").presence().get().send().await;
    assert!(result.is_err());
}

// RSP5g — presence data with cipher encoding is decrypted using the
// channel cipher options (canonical ably-common fixture)
// UTS: rest/unit/RSP5/decode-cipher-channel-7
#[tokio::test]
async fn rsp5g_presence_decode_cipher_channel() -> Result<()> {
    let key = base64::decode("WUP6u0K7MXI5Zeo0VppPwg==").unwrap();
    let cipher = crate::crypto::CipherParams::builder().key(key).build()?;

    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([
                {
                    "action": 1,
                    "clientId": "c1",
                    "data": "HO4cYSP8LybPYBPZPHQOtuD53yrD3YV3NBoTEYBh4U0N1QXHbtkfsDfTspKeLQFt",
                    "encoding": "json/utf-8/cipher+aes-128-cbc/base64"
                }
            ]),
        )
    });
    let client = mock_client_json(mock);
    let ch = client.channels().name("test-rsp5g").cipher(cipher).get();
    let result = ch.presence().get().send().await?;
    let items = result.items();
    assert_eq!(items.len(), 1);
    assert!(items[0].encoding.is_none(), "fully decoded");
    assert!(
        matches!(items[0].data, Data::JSON(ref v) if v["example"]["json"] == "Object"),
        "expected decrypted JSON, got {:?}",
        items[0].data
    );
    Ok(())
}

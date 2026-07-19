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

/// Helper to create a Rest client with a no-op mock for auth-only tests.
fn test_client_for_auth() -> crate::Rest {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
    ClientOptions::new("aaaaaa.bbbbbb:cccccc")
        .rest_with_mock(mock)
        .unwrap()
}

// ---------------------------------------------------------------
// TG1 — PaginatedResult items
// UTS: rest/unit/types/paginated_result.md
// ---------------------------------------------------------------

#[tokio::test]
async fn tg1_paginated_result_items() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([
                {"name": "msg1", "data": "a"},
                {"name": "msg2", "data": "b"},
                {"name": "msg3", "data": "c"}
            ]),
        )
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let res = client.channels().get("test").history().send().await?;
    let items = res.items();

    assert_eq!(items.len(), 3);
    assert_eq!(items[0].name, Some("msg1".to_string()));
    assert_eq!(items[1].name, Some("msg2".to_string()));
    assert_eq!(items[2].name, Some("msg3".to_string()));

    Ok(())
}

// ---------------------------------------------------------------
// TG — Empty result
// UTS: rest/unit/types/paginated_result.md
// ---------------------------------------------------------------

#[tokio::test]
async fn tg_empty_paginated_result() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let res = client.channels().get("test").history().send().await?;
    let items = res.items();

    assert_eq!(items.len(), 0);

    Ok(())
}

// ---------------------------------------------------------------
// TM3 — Message deserialization from JSON
// UTS: rest/unit/types/message_types.md
// ---------------------------------------------------------------

#[test]
fn tm3_message_from_json() {
    let json = json!({
        "id": "msg-123",
        "name": "greeting",
        "data": "hello",
        "clientId": "user1",
        "connectionId": "conn-456",
        "extras": {"headers": {"key": "val"}}
    });

    let msg: crate::rest::Message = serde_json::from_value(json).unwrap();
    assert_eq!(msg.id, Some("msg-123".to_string()));
    assert_eq!(msg.name, Some("greeting".to_string()));
    assert_eq!(msg.data, crate::rest::Data::String("hello".to_string()));
    assert_eq!(msg.client_id, Some("user1".to_string()));
    assert_eq!(msg.connection_id, Some("conn-456".to_string()));
    assert!(msg.extras.is_some());
}

// ---------------------------------------------------------------
// TM4 — Message serialization to JSON
// UTS: rest/unit/types/message_types.md
// ---------------------------------------------------------------

#[test]
fn tm4_message_to_json() {
    let msg = crate::rest::Message {
        id: Some("msg-123".to_string()),
        name: Some("greeting".to_string()),
        data: crate::rest::Data::String("hello".to_string()),
        client_id: Some("user1".to_string()),
        ..Default::default()
    };

    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["id"], "msg-123");
    assert_eq!(json["name"], "greeting");
    assert_eq!(json["data"], "hello");
    assert_eq!(json["clientId"], "user1");

    // Optional fields not set should be absent
    assert!(json.get("connectionId").is_none());
    assert!(json.get("extras").is_none());
}

// ---------------------------------------------------------------
// TM — Null/missing attributes omitted
// UTS: rest/unit/types/message_types.md
// ---------------------------------------------------------------

#[test]
fn tm_null_attributes_omitted() {
    let msg = crate::rest::Message {
        name: Some("event".to_string()),
        ..Default::default()
    };

    let json = serde_json::to_value(&msg).unwrap();

    // Only name should be present; all None/empty fields omitted
    assert_eq!(json["name"], "event");
    assert!(json.get("id").is_none());
    assert!(json.get("data").is_none());
    assert!(json.get("clientId").is_none());
    assert!(json.get("connectionId").is_none());
    assert!(json.get("encoding").is_none());
    assert!(json.get("extras").is_none());
}

// ---------------------------------------------------------------
// TG2 — Pagination Link header parsing
// UTS: rest/unit/types/paginated_result.md
// ---------------------------------------------------------------

#[tokio::test]
async fn tg2_pagination_with_link_header() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let page_count = Arc::new(AtomicUsize::new(0));
    let page_count_clone = page_count.clone();

    let mock = MockHttpClient::with_handler(move |_req| {
        let page = page_count_clone.fetch_add(1, Ordering::SeqCst);
        if page == 0 {
            MockResponse::json(200, &json!([{"name": "msg1", "data": "a"}])).with_header(
                "Link",
                "</channels/test/history?start=0&end=1&direction=forwards&limit=1>; rel=\"next\"",
            )
        } else {
            MockResponse::json(200, &json!([{"name": "msg2", "data": "b"}]))
        }
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    // Get first page
    let page1 = client
        .channels()
        .get("test")
        .history()
        .limit(1)
        .send()
        .await?;

    assert!(page1.has_next());

    let items1 = page1.items();
    assert_eq!(items1.len(), 1);
    assert_eq!(items1[0].name, Some("msg1".to_string()));

    Ok(())
}

// ---------------------------------------------------------------
// TG — Pagination preserves auth headers
// UTS: rest/unit/types/paginated_result.md
// ---------------------------------------------------------------

#[tokio::test]
async fn tg_pagination_preserves_auth() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let page_count = Arc::new(AtomicUsize::new(0));
    let page_count_clone = page_count.clone();

    let mock = MockHttpClient::with_handler(move |_req| {
        let page = page_count_clone.fetch_add(1, Ordering::SeqCst);
        if page == 0 {
            MockResponse::json(200, &json!([{"name": "msg1"}])).with_header(
                "Link",
                "</channels/test/history?start=0&end=1>; rel=\"next\"",
            )
        } else {
            MockResponse::json(200, &json!([{"name": "msg2"}]))
        }
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let page1 = client.channels().get("test").history().send().await?;
    let _page2 = page1.next().await?;

    // Both requests should have Authorization header
    let reqs = get_mock(&client).captured_requests();
    assert!(
        reqs.len() >= 2,
        "Expected at least 2 requests for pagination"
    );
    for req in &reqs {
        assert!(
            req.headers.iter().any(|(k, _)| k == "authorization"),
            "Expected Authorization header on all paginated requests"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------
// TG3 — Navigating to next page via Stream
// UTS: rest/unit/types/paginated_result.md
// ---------------------------------------------------------------

#[tokio::test]
async fn tg3_pagination_next_page() -> Result<()> {
    use futures::TryStreamExt;

    use std::sync::atomic::{AtomicUsize, Ordering};

    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_clone = call_count.clone();

    let mock = MockHttpClient::with_handler(move |req| {
        let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
        match n {
            0 => {
                // First page with Link: next header
                let mut resp = MockResponse::json(
                    200,
                    &json!([
                        {"name": "msg1", "data": "a"},
                        {"name": "msg2", "data": "b"}
                    ]),
                );
                let next_url = format!(
                    "{}?page=2",
                    req.url
                        .as_str()
                        .split('?')
                        .next()
                        .unwrap_or(req.url.as_str())
                );
                resp.headers
                    .push(("Link".to_string(), format!("<{}>; rel=\"next\"", next_url)));
                resp
            }
            1 => {
                // Second page, no next link
                MockResponse::json(
                    200,
                    &json!([
                        {"name": "msg3", "data": "c"}
                    ]),
                )
            }
            _ => MockResponse::empty(200),
        }
    });

    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap();

    let channel = client.channels().get("test");

    // First page
    let page1 = channel.history().send().await?;
    let items1 = page1.items();
    assert_eq!(items1.len(), 2);
    assert_eq!(items1[0].name, Some("msg1".to_string()));
    assert_eq!(items1[1].name, Some("msg2".to_string()));

    // Second page (navigating to next)
    let page2 = page1.next().await?.expect("Expected page 2");
    let items2 = page2.items();
    assert_eq!(items2.len(), 1);
    assert_eq!(items2[0].name, Some("msg3".to_string()));

    // No more pages
    let page3 = page2.next().await?;
    assert!(page3.is_none(), "Expected no more pages");

    Ok(())
}

// ---------------------------------------------------------------
// TP2 — PresenceAction enum values
// UTS: rest/unit/types/presence_message_types.md
// ---------------------------------------------------------------

#[test]
fn tp2_presence_action_enum_values() {
    assert_eq!(crate::rest::PresenceAction::Absent as u8, 0);
    assert_eq!(crate::rest::PresenceAction::Present as u8, 1);
    assert_eq!(crate::rest::PresenceAction::Enter as u8, 2);
    assert_eq!(crate::rest::PresenceAction::Leave as u8, 3);
    assert_eq!(crate::rest::PresenceAction::Update as u8, 4);
}

// ---------------------------------------------------------------
// TP3 — PresenceMessage from JSON (wire format)
// UTS: rest/unit/types/presence_message_types.md
// ---------------------------------------------------------------

#[test]
fn tp3_presence_message_from_json() {
    let json = json!({
        "id": "pm-123",
        "action": 2,
        "clientId": "user-1",
        "connectionId": "conn-1",
        "data": "hello",
        "timestamp": 1234567890000u64,
        "extras": {"headers": {"x-key": "x-value"}}
    });

    let msg: crate::rest::PresenceMessage = serde_json::from_value(json).unwrap();
    assert_eq!(msg.id, Some("pm-123".to_string()));
    assert_eq!(msg.action, Some(crate::rest::PresenceAction::Enter));
    assert_eq!(msg.client_id, Some("user-1".to_string()));
    assert_eq!(msg.connection_id, Some("conn-1".to_string()));
    assert_eq!(msg.data, crate::rest::Data::String("hello".to_string()));
    assert_eq!(msg.timestamp, Some(1234567890000));
    assert!(msg.extras.is_some());
}

// ---------------------------------------------------------------
// TP3 — PresenceMessage to JSON (wire format)
// UTS: rest/unit/types/presence_message_types.md
// ---------------------------------------------------------------

#[test]
fn tp3_presence_message_to_json() {
    let msg = crate::rest::PresenceMessage {
        action: Some(crate::rest::PresenceAction::Enter),
        client_id: Some("user-1".to_string()),
        data: crate::rest::Data::String("hello".to_string()),
        ..Default::default()
    };

    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["action"], 2);
    assert_eq!(json["clientId"], "user-1");
    assert_eq!(json["data"], "hello");
    // Optional fields not set should be absent
    assert!(json.get("id").is_none());
    assert!(json.get("connectionId").is_none());
    assert!(json.get("timestamp").is_none());
    assert!(json.get("extras").is_none());
}

// ---------------------------------------------------------------
// TP3 — Null/missing attributes omitted from serialization
// UTS: rest/unit/types/presence_message_types.md
// ---------------------------------------------------------------

#[test]
fn tp3_presence_null_attributes_omitted() {
    let msg = crate::rest::PresenceMessage {
        action: Some(crate::rest::PresenceAction::Enter),
        client_id: Some("user-1".to_string()),
        ..Default::default()
    };

    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["action"], 2);
    assert_eq!(json["clientId"], "user-1");
    assert!(json.get("data").is_none());
    assert!(json.get("encoding").is_none());
    assert!(json.get("extras").is_none());
    assert!(json.get("id").is_none());
    assert!(json.get("timestamp").is_none());
    assert!(json.get("connectionId").is_none());
}

// ---------------------------------------------------------------
// TP3h — memberKey combines connectionId and clientId
// UTS: rest/unit/types/presence_message_types.md
// ---------------------------------------------------------------

#[test]
fn tp3h_member_key() {
    let msg1 = crate::rest::PresenceMessage {
        connection_id: Some("conn-1".to_string()),
        client_id: Some("user-1".to_string()),
        ..Default::default()
    };
    assert_eq!(msg1.member_key(), "conn-1:user-1".to_string());

    let msg2 = crate::rest::PresenceMessage {
        connection_id: Some("conn-2".to_string()),
        client_id: Some("user-1".to_string()),
        ..Default::default()
    };
    assert_eq!(msg2.member_key(), "conn-2:user-1".to_string());

    // Same clientId, different connectionId — different memberKey
    assert_ne!(msg1.member_key(), msg2.member_key());

    // Missing fields — returns empty string for missing parts
    let msg3 = crate::rest::PresenceMessage {
        client_id: Some("user-1".to_string()),
        ..Default::default()
    };
    assert_eq!(msg3.member_key(), ":user-1".to_string());
}

// ---------------------------------------------------------------
// TP2 — PresenceAction serde round-trip (numeric values)
// UTS: rest/unit/types/presence_message_types.md
// ---------------------------------------------------------------

#[test]
fn tp2_presence_action_serde_roundtrip() {
    // Serialize: action should be numeric
    let msg = crate::rest::PresenceMessage {
        action: Some(crate::rest::PresenceAction::Enter),
        client_id: Some("u".to_string()),
        ..Default::default()
    };
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["action"], 2, "Enter should serialize as 2");

    // Deserialize: numeric action should parse
    let json = json!({"action": 4, "clientId": "u"});
    let msg: crate::rest::PresenceMessage = serde_json::from_value(json).unwrap();
    assert_eq!(msg.action, Some(crate::rest::PresenceAction::Update));

    // All actions deserialize correctly
    for (num, expected) in [
        (0, Some(crate::rest::PresenceAction::Absent)),
        (1, Some(crate::rest::PresenceAction::Present)),
        (2, Some(crate::rest::PresenceAction::Enter)),
        (3, Some(crate::rest::PresenceAction::Leave)),
        (4, Some(crate::rest::PresenceAction::Update)),
    ] {
        let json = json!({"action": num});
        let msg: crate::rest::PresenceMessage = serde_json::from_value(json).unwrap();
        assert_eq!(
            msg.action, expected,
            "Action {} should deserialize correctly",
            num
        );
    }
}

// ---------------------------------------------------------------
// ===============================================================
// Phase 13: Mutable Messages & Annotations
// ===============================================================

// -- Type tests --

// TM5 — Message Action enum values in order from zero:
// MESSAGE_CREATE, MESSAGE_UPDATE, MESSAGE_DELETE, META, MESSAGE_SUMMARY, MESSAGE_APPEND
// UTS: rest/unit/TM5/message-action-enum-values-0
#[test]
fn tm5_message_action_values() {
    use crate::rest::MessageAction;
    assert_eq!(MessageAction::Create as u8, 0);
    assert_eq!(MessageAction::Update as u8, 1);
    assert_eq!(MessageAction::Delete as u8, 2);
    assert_eq!(MessageAction::Meta as u8, 3);
    assert_eq!(MessageAction::Summary as u8, 4);
    assert_eq!(MessageAction::Append as u8, 5);

    // Round-trip through the wire representation
    let from_zero: MessageAction = serde_json::from_value(serde_json::json!(0)).unwrap();
    assert_eq!(from_zero, MessageAction::Create);
    let from_five: MessageAction = serde_json::from_value(serde_json::json!(5)).unwrap();
    assert_eq!(from_five, MessageAction::Append);
    assert_eq!(
        serde_json::json!(MessageAction::Update),
        serde_json::json!(1)
    );
}

#[test]
fn tm2j_tm2r_message_action_serial_fields() {
    let msg = crate::rest::Message {
        action: Some(crate::rest::MessageAction::Update),
        serial: Some("01726232498871-001@abcdefghij:0".to_string()),
        ..Default::default()
    };
    assert_eq!(msg.action, Some(crate::rest::MessageAction::Update));
    assert_eq!(
        msg.serial.as_deref(),
        Some("01726232498871-001@abcdefghij:0")
    );
}

#[test]
fn tm2s_message_version_populated() {
    // When present on wire, version is a JSON object
    let json_str = r#"{"serial":"s1","version":{"serial":"v1","timestamp":1000,"clientId":"c1","description":"desc","metadata":{"k":"v"}}}"#;
    let msg: crate::rest::Message = serde_json::from_str(json_str).unwrap();
    assert!(msg.version.is_some());
    let v = msg.version.unwrap();
    assert_eq!(v["serial"], "v1");
    assert_eq!(v["timestamp"], 1000);
    assert_eq!(v["clientId"], "c1");

    // Default message has None version
    let default_msg = crate::rest::Message::default();
    assert!(default_msg.version.is_none());
}

#[test]
fn tm2u_tm8a_message_annotations_default() {
    let msg = crate::rest::Message::default();
    assert!(msg.annotations.is_none());

    let json_str = r#"{"annotations":{"likes":{"total":5}}}"#;
    let msg: crate::rest::Message = serde_json::from_str(json_str).unwrap();
    assert!(msg.annotations.is_some());
    assert_eq!(msg.annotations.unwrap()["likes"]["total"], 5);
}

#[tokio::test]
async fn to3b_log_level_changeable() -> Result<()> {
    // TO3b: raising logLevel to Micro emits request-level logs
    use std::sync::Mutex as StdMutex;
    let captured = Arc::new(StdMutex::new(
        Vec::<(crate::options::LogLevel, String)>::new(),
    ));
    let logs = captured.clone();

    let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!({})));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .log_level(crate::options::LogLevel::Micro)
        .log_handler(move |level, message| {
            logs.lock().unwrap().push((level, message.to_string()));
        })
        .rest_with_mock(mock)
        .unwrap();
    client.request("GET", "/channels/test").send().await?;

    let logs = captured.lock().unwrap();
    assert!(!logs.is_empty(), "Micro level must emit request logs");
    // TO3c2: HTTP request logs carry method, host and path
    let req_log = logs
        .iter()
        .find(|(_, m)| m.contains("HTTP request"))
        .expect("expected an HTTP request log entry");
    assert!(req_log.1.contains("method=GET"));
    assert!(req_log.1.contains("host="));
    assert!(req_log.1.contains("path=/channels/test"));
    Ok(())
}

#[tokio::test]
async fn to3c_custom_handler_receives_events() -> Result<()> {
    // TO3c: a custom handler receives (level, message) log events
    use std::sync::Mutex as StdMutex;
    let captured = Arc::new(StdMutex::new(Vec::<crate::options::LogLevel>::new()));
    let logs = captured.clone();

    // A request that fails entirely emits an Error-level log
    let mock = MockHttpClient::with_handler(|_req| MockResponse::network_error());
    let client = ClientOptions::new("appId.keyId:keySecret")
        .log_handler(move |level, _message| {
            logs.lock().unwrap().push(level);
        })
        .rest_with_mock(mock)
        .unwrap();
    let _ = client.request("GET", "/channels/test").send().await;

    let logs = captured.lock().unwrap();
    assert!(
        logs.contains(&crate::options::LogLevel::Error),
        "failed request must emit an Error log, got {:?}",
        *logs
    );
    Ok(())
}

// ===============================================================
// TI: ErrorInfo type validation
// ===============================================================

#[test]
fn ti1_errorinfo_has_code() {
    let err =
        crate::error::ErrorInfo::new(crate::error::ErrorCode::BadRequest.code(), "test error");
    assert_eq!(err.code, Some(40000));
}

#[test]
fn ti2_errorinfo_has_status_code() {
    let err = crate::error::ErrorInfo::with_status(
        crate::error::ErrorCode::BadRequest.code(),
        400,
        "test error",
    );
    assert_eq!(err.status_code, Some(400));
}

#[test]
fn ti3_errorinfo_has_message() {
    let err = crate::error::ErrorInfo::new(
        crate::error::ErrorCode::BadRequest.code(),
        "test error message",
    );
    assert_eq!(err.message.as_deref(), Some("test error message"));
}

#[test]
fn ti4_errorinfo_has_href() {
    let err = crate::error::ErrorInfo::new(crate::error::ErrorCode::BadRequest.code(), "test");
    assert!(err.href.as_deref().unwrap_or("").contains("40000"));
}

#[test]
fn ti5_errorinfo_has_cause() {
    let inner =
        crate::error::ErrorInfo::new(crate::error::ErrorCode::InternalError.code(), "inner error");
    let outer = crate::error::ErrorInfo {
        code: Some(crate::error::ErrorCode::BadRequest.code()),
        message: Some("outer error".to_string()),
        status_code: None,
        href: Some(String::new()),
        cause: Some(Box::new(inner)),
        ..Default::default()
    };
    assert!(outer.cause.is_some());
    // ErrorInfo implements Error but not necessarily Source
    let _display = format!("{}", outer);
}

#[test]
fn ti_errorinfo_from_json() {
    let json_str = r#"{"code":40100,"statusCode":401,"message":"Unauthorized","href":"https://help.ably.io/error/40100"}"#;
    let err: crate::error::ErrorInfo = serde_json::from_str(json_str).unwrap();
    assert_eq!(err.code, Some(40100));
    assert_eq!(err.status_code, Some(401));
    assert_eq!(err.message.as_deref(), Some("Unauthorized"));
}

#[test]
fn ti_common_error_codes() {
    use crate::error::ErrorInfoCode;
    assert_eq!(ErrorCode::BadRequest.code(), 40000);
    assert_eq!(ErrorCode::Unauthorized.code(), 40100);
    assert_eq!(ErrorCode::InvalidCredentials.code(), 40101);
    assert_eq!(ErrorCode::TokenErrorUnspecified.code(), 40140);
    assert_eq!(ErrorCode::TokenExpired.code(), 40142);
    assert_eq!(
        ErrorCode::OperationNotPermittedWithProvidedCapability.code(),
        40160
    );
    assert_eq!(ErrorCode::Forbidden.code(), 40300);
    assert_eq!(ErrorCode::NotFound.code(), 40400);
    assert_eq!(ErrorCode::InternalError.code(), 50000);
    assert_eq!(ErrorCode::TimeoutError.code(), 50003);
}

#[test]
fn ti_error_string_representation() {
    let err = crate::error::ErrorInfo::with_status(
        crate::error::ErrorCode::InvalidCredentials.code(),
        401,
        "Invalid credentials",
    );
    let s = format!("{}", err);
    assert!(s.contains("40101"), "should contain error code");
    assert!(s.contains("Invalid credentials"), "should contain message");
}

// ===============================================================
// TD: TokenDetails type validation
// ===============================================================

// TD1 — TokenDetails attributes
// Also covers: TD5 (TokenDetails clientId attribute)
#[test]
fn td1_token_details_attributes() {
    use crate::auth::{TokenDetails, TokenMetadata};
    use chrono::Utc;
    let td = TokenDetails {
        token: "test-token".to_string(),
        metadata: Some(TokenMetadata {
            expires: Utc::now(),
            issued: Utc::now(),
            capability: r#"{"*":["*"]}"#.to_string(),
            client_id: Some("client-1".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(td.token, "test-token");
    let meta = td.metadata.unwrap();
    assert_eq!(meta.client_id.as_deref(), Some("client-1"));
    assert!(meta.capability.contains("*"));
}

#[test]
fn td_token_details_from_json() {
    let json_str = r#"{"token":"xVLyHw.token","expires":1700000000000,"issued":1699999000000,"capability":"{\"*\":[\"*\"]}","clientId":"test"}"#;
    let td: crate::auth::TokenDetails = serde_json::from_str(json_str).unwrap();
    assert_eq!(td.token, "xVLyHw.token");
    let meta = td.metadata.unwrap();
    assert_eq!(meta.client_id.as_deref(), Some("test"));
}

// ===============================================================
// TK: TokenParams type validation
// ===============================================================

#[test]
fn tk1_token_params_attributes() {
    use crate::auth::TokenParams;
    let params = TokenParams {
        ttl: Some(3600000),
        capability: Some(r#"{"channel":["publish"]}"#.to_string()),
        client_id: Some("test-client".to_string()),
        timestamp: None,
        nonce: None,
    };
    assert_eq!(params.ttl, Some(3600000));
    assert_eq!(params.client_id.as_deref(), Some("test-client"));
    assert!(params.capability.as_deref().unwrap().contains("publish"));
}

// ===============================================================
// TE: TokenRequest type validation
// ===============================================================

#[test]
fn te1_token_request_attributes() {
    use crate::auth::TokenRequest;
    let tr = TokenRequest {
        key_name: "appId.keyId".to_string(),
        ttl: Some(3600000),
        capability: Some(r#"{"*":["*"]}"#.to_string()),
        client_id: None,
        timestamp: None,
        nonce: "unique-nonce".to_string(),
        mac: "signature-here".to_string(),
    };
    assert_eq!(tr.key_name, "appId.keyId");
    assert_eq!(tr.ttl, Some(3600000));
    assert_eq!(tr.nonce, "unique-nonce");
    assert!(!tr.mac.is_empty());
}

#[test]
fn te_token_request_to_json() {
    use crate::auth::TokenRequest;
    let tr = TokenRequest {
        key_name: "appId.keyId".to_string(),
        ttl: Some(3600000),
        capability: Some(r#"{"*":["*"]}"#.to_string()),
        client_id: None,
        timestamp: Some(1700000000000),
        nonce: "nonce-1".to_string(),
        mac: "mac-1".to_string(),
    };
    let json_val = serde_json::to_value(&tr).unwrap();
    assert_eq!(json_val["keyName"], "appId.keyId");
    assert_eq!(json_val["nonce"], "nonce-1");
    assert_eq!(json_val["mac"], "mac-1");
}

// ===============================================================
// TO: ClientOptions type validation
// ===============================================================

#[test]
fn to3_client_options_defaults() {
    let opts = ClientOptions::new("appId.keyId:keySecret");
    assert!(opts.tls);
    // TO3n: idempotentRestPublishing defaults to true for >= 1.2
    assert!(opts.idempotent_rest_publishing);
    assert_eq!(
        opts.http_request_timeout,
        std::time::Duration::from_secs(10)
    );
    assert_eq!(opts.http_max_retry_count, 3);
}

#[test]
fn to3_client_options_custom_hosts() {
    let opts = ClientOptions::new("appId.keyId:keySecret")
        .rest_host("custom.ably.io")
        .unwrap()
        .fallback_hosts(vec!["fb1.ably.io".to_string(), "fb2.ably.io".to_string()]);
    let mut opts = opts;
    opts.resolve_hosts();
    assert_eq!(opts.primary_host, "custom.ably.io");
    // REC2a2: explicit fallbackHosts win
    assert_eq!(opts.resolved_fallback_hosts.len(), 2);
}

#[test]
fn to_endpoint_affects_host() {
    let opts = ClientOptions::new("appId.keyId:keySecret")
        .environment("sandbox")
        .unwrap();
    assert_eq!(opts.environment.as_deref(), Some("sandbox"));
}

#[test]
fn trs2_success_result_attributes() {
    let json_str =
        r#"{"target":"clientId:alice","issuedBefore":1700000000000,"appliesAt":1700000000000}"#;
    let result: crate::rest::RevokeTokenResult = serde_json::from_str(json_str).unwrap();
    assert_eq!(result.target, "clientId:alice");
    assert!(result.issued_before.is_some());
    assert!(result.applies_at.is_some());
    assert!(result.error.is_none());
}

#[test]
fn trf2_failure_result_attributes() {
    let json_str = r#"{"target":"invalidType:abc","error":{"code":40000,"statusCode":400,"message":"Invalid target type"}}"#;
    let result: crate::rest::RevokeTokenResult = serde_json::from_str(json_str).unwrap();
    assert_eq!(result.target, "invalidType:abc");
    assert!(result.error.is_some());
    let err = result.error.unwrap();
    assert_eq!(err.code, Some(40000));
    assert_eq!(err.status_code, Some(400));
}

// UTS: rest/unit/types/presence_message_types.md — TP3a
#[test]
fn tp3a_presence_message_id_attribute() {
    let pm = crate::rest::PresenceMessage {
        id: Some("unique-id-1".to_string()),
        action: Some(crate::rest::PresenceAction::Present),
        client_id: Some("client1".to_string()),
        connection_id: Some("conn1".to_string()),
        data: crate::rest::Data::None,
        encoding: None,
        timestamp: Some(1700000000000),
        extras: None,
    };
    assert_eq!(pm.id.as_deref(), Some("unique-id-1"));

    let pm2 = crate::rest::PresenceMessage {
        id: Some("unique-id-2".to_string()),
        ..pm.clone()
    };
    assert_ne!(pm.id, pm2.id);
}

// UTS: rest/unit/types/presence_message_types.md — TP3d
#[test]
fn tp3d_presence_message_connection_id() {
    let pm = crate::rest::PresenceMessage {
        id: None,
        action: Some(crate::rest::PresenceAction::Present),
        client_id: Some("client1".to_string()),
        connection_id: Some("connection-abc".to_string()),
        data: crate::rest::Data::None,
        encoding: None,
        timestamp: None,
        extras: None,
    };
    assert_eq!(pm.connection_id.as_deref(), Some("connection-abc"));
}

// UTS: rest/unit/types/presence_message_types.md — TP3g
#[test]
fn tp3g_presence_message_timestamp_millis() {
    let pm = crate::rest::PresenceMessage {
        id: None,
        action: Some(crate::rest::PresenceAction::Present),
        client_id: None,
        connection_id: None,
        data: crate::rest::Data::None,
        encoding: None,
        timestamp: Some(1700000000000),
        extras: None,
    };
    assert_eq!(pm.timestamp, Some(1700000000000));
    assert!(pm.timestamp.unwrap() > 1_000_000_000_000);
}

// UTS: rest/unit/types/paginated_result.md — TG4
// Spec: PaginatedResult first() returns first page.
#[tokio::test]
async fn tg4_paginated_result_first_page() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let count = Arc::new(AtomicUsize::new(0));
    let count_c = count.clone();

    let mock = MockHttpClient::with_handler(move |_req| {
        let n = count_c.fetch_add(1, Ordering::SeqCst);
        match n {
            0 => MockResponse::json(200, &json!([{"name": "e1", "data": "d1"}]))
                .with_header(
                    "link",
                    r#"</channels/test/messages?cursor=next>; rel="next""#,
                )
                .with_header("link", r#"</channels/test/messages>; rel="first""#),
            1 => MockResponse::json(200, &json!([{"name": "e2", "data": "d2"}]))
                .with_header("link", r#"</channels/test/messages>; rel="first""#),
            _ => MockResponse::json(200, &json!([{"name": "e1", "data": "d1"}])).with_header(
                "link",
                r#"</channels/test/messages?cursor=next>; rel="next""#,
            ),
        }
    });

    let client = mock_client(mock);
    let channel = client.channels().get("test");

    let page1 = channel.history().send().await?;
    assert!(page1.has_next());
    let page2 = page1.next().await?.expect("should have next page");
    assert!(page2.is_last());
    let first_page = page2.first().await?.expect("should have first page");
    let items = first_page.items();
    assert_eq!(items[0].name.as_deref(), Some("e1"));
    Ok(())
}

// UTS: rest/unit/types/paginated_result.md — TG5
// Spec: PaginatedResult navigation across pages with has_next/is_last.
#[tokio::test]
async fn tg5_paginated_result_page_navigation() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let count = Arc::new(AtomicUsize::new(0));
    let count_c = count.clone();

    let mock = MockHttpClient::with_handler(move |_req| {
        let n = count_c.fetch_add(1, Ordering::SeqCst);
        match n {
            0 => MockResponse::json(
                200,
                &json!([{"name": "page1-item1"}, {"name": "page1-item2"}]),
            )
            .with_header(
                "link",
                r#"</channels/test/messages?cursor=abc123>; rel="next""#,
            ),
            _ => MockResponse::json(200, &json!([{"name": "page2-item1"}])),
        }
    });

    let client = mock_client(mock);
    let channel = client.channels().get("test");

    let page1 = channel.history().send().await?;
    assert!(page1.has_next());
    assert!(!page1.is_last());

    let page2 = page1.next().await?.expect("should have next page");
    assert!(!page2.has_next());
    assert!(page2.is_last());

    let no_next = page2.next().await?;
    assert!(no_next.is_none());

    Ok(())
}

// ---------------------------------------------------------------
// TM2a — Message id attribute
// ---------------------------------------------------------------
#[test]
fn tm2a_channel_message_id_attribute() {
    let msg = crate::Message {
        id: Some("msg-001".to_string()),
        name: Some("test".to_string()),
        data: Data::None,
        encoding: None,
        connection_id: None,
        timestamp: None,
        client_id: None,
        extras: None,
        action: None,
        serial: None,
        version: None,
        annotations: None,
    };
    assert_eq!(msg.id.as_deref(), Some("msg-001"));
}

// ---------------------------------------------------------------
// TM2c — data attribute (object) via rest::Message
// ---------------------------------------------------------------
#[test]
fn tm2c_rest_message_data_object() -> Result<()> {
    let json_val = json!({
        "name": "event",
        "data": "{\"key\":\"value\"}",
        "encoding": "json"
    });
    let msg: rest::Message = serde_json::from_value(json_val)?;
    // When encoding is "json" the data is stored as a string; after
    // from_encoded it would be decoded. Here we just verify it round-trips.
    assert!(matches!(msg.data, rest::Data::String(_)));
    if let rest::Data::String(s) = &msg.data {
        let parsed: serde_json::Value = serde_json::from_str(s)?;
        assert_eq!(parsed["key"], "value");
    }
    Ok(())
}

// ---------------------------------------------------------------
// TM2d — clientId from ProtocolMessage (Message)
// ---------------------------------------------------------------
#[test]
fn tm2d_channel_message_client_id() {
    let msg = crate::Message {
        id: None,
        name: Some("chat".to_string()),
        data: Data::None,
        encoding: None,
        connection_id: None,
        timestamp: None,
        client_id: Some("user-42".to_string()),
        extras: None,
        action: None,
        serial: None,
        version: None,
        annotations: None,
    };
    assert_eq!(msg.client_id.as_deref(), Some("user-42"));
}

// ---------------------------------------------------------------
// TM2e — encoding attribute via rest::Message serde
// ---------------------------------------------------------------
#[test]
fn tm2e_rest_message_encoding_serde() -> Result<()> {
    let msg = rest::Message {
        encoding: Some("utf-8/cipher+aes-128-cbc/base64".to_string()),
        ..Default::default()
    };
    let serialized = serde_json::to_value(&msg)?;
    assert_eq!(serialized["encoding"], "utf-8/cipher+aes-128-cbc/base64");
    // Deserialize back
    let deserialized: rest::Message = serde_json::from_value(serialized)?;
    assert_eq!(
        deserialized.encoding,
        Some("utf-8/cipher+aes-128-cbc/base64".to_string())
    );
    Ok(())
}

// ---------------------------------------------------------------
// TM2g — extras from ProtocolMessage (Message)
// ---------------------------------------------------------------
#[test]
fn tm2g_channel_message_extras() {
    let extras = json!({"push": {"notification": {"title": "Hello"}}});
    let msg = crate::Message {
        id: None,
        name: Some("push-event".to_string()),
        data: Data::None,
        encoding: None,
        connection_id: None,
        timestamp: None,
        client_id: None,
        extras: Some(extras.clone()),
        action: None,
        serial: None,
        version: None,
        annotations: None,
    };
    assert_eq!(msg.extras.unwrap(), extras);
}

// ---------------------------------------------------------------
// TM2h — serial attribute on rest::Message
// ---------------------------------------------------------------
#[test]
fn tm2h_rest_message_serial() -> Result<()> {
    let msg = rest::Message {
        serial: Some("01234567890".to_string()),
        ..Default::default()
    };
    let serialized = serde_json::to_value(&msg)?;
    assert_eq!(serialized["serial"], "01234567890");
    let deserialized: rest::Message = serde_json::from_value(serialized)?;
    assert_eq!(deserialized.serial.as_deref(), Some("01234567890"));
    Ok(())
}

// ---------------------------------------------------------------
// TM2i — version attribute on rest::Message
// ---------------------------------------------------------------
#[test]
fn tm2i_rest_message_version() -> Result<()> {
    let msg = rest::Message {
        version: Some(json!("v1.0")),
        ..Default::default()
    };
    let serialized = serde_json::to_value(&msg)?;
    assert_eq!(serialized["version"], "v1.0");
    let deserialized: rest::Message = serde_json::from_value(serialized)?;
    assert_eq!(deserialized.version, Some(json!("v1.0")));
    Ok(())
}

// ---------------------------------------------------------------
// TM3 — from_encoded with all fields
// ---------------------------------------------------------------
#[test]
fn tm3_from_encoded_all_fields() -> Result<()> {
    let json_val = json!({
        "id": "msg-abc",
        "name": "greeting",
        "data": "hello world",
        "clientId": "client-1",
        "connectionId": "conn-1",
        "extras": {"headers": {"key": "val"}},
        "action": 1,
        "serial": "serial-001",
        "version": "v2",
        "annotations": {"likes": 5}
    });
    let msg = rest::Message::from_encoded(json_val, None)?;
    assert_eq!(msg.id.as_deref(), Some("msg-abc"));
    assert_eq!(msg.name.as_deref(), Some("greeting"));
    assert!(matches!(msg.data, rest::Data::String(ref s) if s == "hello world"));
    assert_eq!(msg.client_id.as_deref(), Some("client-1"));
    assert_eq!(msg.connection_id.as_deref(), Some("conn-1"));
    assert!(msg.extras.is_some());
    // TM5: wire value 1 = MESSAGE_UPDATE
    assert_eq!(msg.action, Some(rest::MessageAction::Update));
    assert_eq!(msg.serial.as_deref(), Some("serial-001"));
    assert_eq!(msg.version, Some(json!("v2")));
    assert_eq!(msg.annotations, Some(json!({"likes": 5})));
    Ok(())
}

// ---------------------------------------------------------------
// TM3 — from_encoded with base64-encoded data
// ---------------------------------------------------------------
#[test]
fn tm3_from_encoded_base64_data() -> Result<()> {
    // base64 encode "binary payload"
    let encoded = base64::encode(b"binary payload");
    let json_val = json!({
        "name": "bin-msg",
        "data": encoded,
        "encoding": "base64"
    });
    let msg = rest::Message::from_encoded(json_val, None)?;
    assert_eq!(msg.name.as_deref(), Some("bin-msg"));
    // After decoding, data should be binary
    match &msg.data {
        rest::Data::Binary(buf) => {
            assert_eq!(buf.as_ref(), b"binary payload");
        }
        other => panic!("Expected binary data, got {:?}", other),
    }
    // Encoding should be consumed (None)
    assert_eq!(msg.encoding, None);
    Ok(())
}

// ---------------------------------------------------------------
// TM4 — constructor(name, data) as string
// ---------------------------------------------------------------
#[test]
fn tm4_message_constructor_name_data() {
    let msg = rest::Message {
        name: Some("event-name".to_string()),
        data: rest::Data::String("payload".to_string()),
        ..Default::default()
    };
    assert_eq!(msg.name.as_deref(), Some("event-name"));
    assert!(matches!(msg.data, rest::Data::String(ref s) if s == "payload"));
}

// ---------------------------------------------------------------
// TM4 — constructor with name, data, clientId
// ---------------------------------------------------------------
#[test]
fn tm4_message_constructor_name_data_client_id() {
    let msg = rest::Message {
        name: Some("chat-msg".to_string()),
        data: rest::Data::String("hello".to_string()),
        client_id: Some("user-x".to_string()),
        ..Default::default()
    };
    assert_eq!(msg.name.as_deref(), Some("chat-msg"));
    assert!(matches!(msg.data, rest::Data::String(ref s) if s == "hello"));
    assert_eq!(msg.client_id.as_deref(), Some("user-x"));
}

// (duplicate TM5 test removed — see tm5_message_action_values)

// ---------------------------------------------------------------
// TP3 — timestamp as number in PresenceMessage deserialization
// ---------------------------------------------------------------
#[test]
fn tp3_presence_message_timestamp_number() -> Result<()> {
    let json_val = json!({
        "action": 1,
        "clientId": "user-1",
        "timestamp": 1700000000000_u64
    });
    let pm: rest::PresenceMessage = serde_json::from_value(json_val)?;
    assert_eq!(pm.timestamp, Some(1700000000000));
    assert_eq!(pm.action, Some(rest::PresenceAction::Present));
    Ok(())
}

// ---------------------------------------------------------------
// TP3a — id attribute in PresenceMessage deserialization
// ---------------------------------------------------------------
#[test]
fn tp3a_presence_message_id_from_json() -> Result<()> {
    let json_val = json!({
        "id": "pres-id-001",
        "action": 2,
        "clientId": "user-2"
    });
    let pm: rest::PresenceMessage = serde_json::from_value(json_val)?;
    assert_eq!(pm.id.as_deref(), Some("pres-id-001"));
    assert_eq!(pm.action, Some(rest::PresenceAction::Enter));
    Ok(())
}

// ---------------------------------------------------------------
// TP3b — connectionId attribute in PresenceMessage
// ---------------------------------------------------------------
#[test]
fn tp3b_presence_message_connection_id() {
    let pm = rest::PresenceMessage {
        connection_id: Some("conn-abc".to_string()),
        ..Default::default()
    };
    assert_eq!(pm.connection_id.as_deref(), Some("conn-abc"));
}

// ---------------------------------------------------------------
// TP3c — data attribute in PresenceMessage
// ---------------------------------------------------------------
#[test]
fn tp3c_presence_message_data() {
    let pm = rest::PresenceMessage {
        data: rest::Data::String("presence-data".to_string()),
        ..Default::default()
    };
    assert!(matches!(pm.data, rest::Data::String(ref s) if s == "presence-data"));
}

// ---------------------------------------------------------------
// TP3e — clientId attribute in PresenceMessage
// ---------------------------------------------------------------
#[test]
fn tp3e_presence_message_client_id() {
    let pm = rest::PresenceMessage {
        client_id: Some("client-abc".to_string()),
        action: Some(rest::PresenceAction::Enter),
        ..Default::default()
    };
    assert_eq!(pm.client_id.as_deref(), Some("client-abc"));
}

// ---------------------------------------------------------------
// TP3e — clientId serde round-trip
// ---------------------------------------------------------------
#[test]
fn tp3e_presence_message_client_id_serde() -> Result<()> {
    let pm = rest::PresenceMessage {
        client_id: Some("user-serde".to_string()),
        action: Some(rest::PresenceAction::Present),
        ..Default::default()
    };
    let serialized = serde_json::to_value(&pm)?;
    assert_eq!(serialized["clientId"], "user-serde");
    let deserialized: rest::PresenceMessage = serde_json::from_value(serialized)?;
    assert_eq!(deserialized.client_id.as_deref(), Some("user-serde"));
    Ok(())
}

// ---------------------------------------------------------------
// TP3f — encoding attribute in PresenceMessage
// ---------------------------------------------------------------
#[test]
fn tp3f_presence_message_encoding() -> Result<()> {
    let pm = rest::PresenceMessage {
        encoding: Some("json".to_string()),
        action: Some(rest::PresenceAction::Update),
        ..Default::default()
    };
    let serialized = serde_json::to_value(&pm)?;
    assert_eq!(serialized["encoding"], "json");
    let deserialized: rest::PresenceMessage = serde_json::from_value(serialized)?;
    assert_eq!(deserialized.encoding, Some("json".to_string()));
    Ok(())
}

// ---------------------------------------------------------------
// TP3g — timestamp defaults from ProtocolMessage
// ---------------------------------------------------------------
#[test]
fn tp3g_presence_message_timestamp_from_json() -> Result<()> {
    let json_val = json!({
        "action": 3,
        "timestamp": 1600000000000_u64
    });
    let pm: rest::PresenceMessage = serde_json::from_value(json_val)?;
    assert_eq!(pm.timestamp, Some(1600000000000));
    assert_eq!(pm.action, Some(rest::PresenceAction::Leave));
    Ok(())
}

// ---------------------------------------------------------------
// TP3i — extras attribute in PresenceMessage
// ---------------------------------------------------------------
#[test]
fn tp3i_presence_message_extras() -> Result<()> {
    let mut extras_map = serde_json::Map::new();
    extras_map.insert("ref".to_string(), json!({"type": "com.example"}));
    let pm = rest::PresenceMessage {
        extras: Some(serde_json::Value::Object(extras_map.clone())),
        action: Some(rest::PresenceAction::Present),
        ..Default::default()
    };
    let serialized = serde_json::to_value(&pm)?;
    assert!(serialized["extras"]["ref"]["type"].as_str() == Some("com.example"));
    let deserialized: rest::PresenceMessage = serde_json::from_value(serialized)?;
    assert_eq!(deserialized.extras.unwrap()["ref"]["type"], "com.example");
    Ok(())
}

// ---------------------------------------------------------------
// TP4 — PresenceMessage from JSON deserialization (fromEncoded analog)
// ---------------------------------------------------------------
#[test]
fn tp4_presence_message_from_json() -> Result<()> {
    let json_val = json!({
        "id": "pres-full",
        "action": 4,
        "clientId": "user-full",
        "connectionId": "conn-full",
        "data": "state-data",
        "timestamp": 1700000000000_u64,
        "extras": {"key": "val"}
    });
    let pm: rest::PresenceMessage = serde_json::from_value(json_val)?;
    assert_eq!(pm.id.as_deref(), Some("pres-full"));
    assert_eq!(pm.action, Some(rest::PresenceAction::Update));
    assert_eq!(pm.client_id.as_deref(), Some("user-full"));
    assert_eq!(pm.connection_id.as_deref(), Some("conn-full"));
    assert!(matches!(pm.data, rest::Data::String(ref s) if s == "state-data"));
    assert_eq!(pm.timestamp, Some(1700000000000));
    assert!(pm.extras.is_some());
    assert_eq!(pm.extras.unwrap()["key"], "val");
    Ok(())
}

// ---------------------------------------------------------------
// TE1 — keyName derived from API key
// ---------------------------------------------------------------
#[tokio::test]
async fn te1_key_name_in_token_request() -> Result<()> {
    let client = test_client_for_auth();
    let params = TokenParams {
        capability: Some(r#"{"*":["*"]}"#.to_string()),
        client_id: Some("test@ably.com".to_string()),
        nonce: None,
        timestamp: None,
        ttl: Some(3600000),
    };
    let options = AuthOptions::default();
    let req = client
        .auth()
        .create_token_request(Some(&params), Some(&options))
        .await?;
    // The key used is "aaaaaa.bbbbbb:cccccc", so key_name should be "aaaaaa.bbbbbb"
    assert_eq!(req.key_name, "aaaaaa.bbbbbb");
    Ok(())
}

// ---------------------------------------------------------------
// TE5 — timestamp auto-generation when not specified
// ---------------------------------------------------------------
#[tokio::test]
async fn te5_timestamp_auto_generation() -> Result<()> {
    let client = test_client_for_auth();
    let params = TokenParams {
        capability: Some(r#"{"*":["*"]}"#.to_string()),
        client_id: None,
        nonce: None,
        timestamp: None, // not specified
        ttl: Some(3600000),
    };
    let options = AuthOptions::default();
    let req = client
        .auth()
        .create_token_request(Some(&params), Some(&options))
        .await?;
    // Timestamp should be auto-generated
    assert!(req.timestamp.is_some());
    Ok(())
}

// ---------------------------------------------------------------
// TE6 — nonce auto-generation when not specified
// ---------------------------------------------------------------
#[tokio::test]
async fn te6_nonce_auto_generation() -> Result<()> {
    let client = test_client_for_auth();
    let params = TokenParams {
        capability: Some(r#"{"*":["*"]}"#.to_string()),
        client_id: None,
        nonce: None, // not specified
        timestamp: None,
        ttl: Some(3600000),
    };
    let options = AuthOptions::default();
    let req = client
        .auth()
        .create_token_request(Some(&params), Some(&options))
        .await?;
    // Nonce should be auto-generated and non-empty
    assert!(!req.nonce.is_empty());
    // Generate another request and verify nonces differ (randomness)
    let req2 = client
        .auth()
        .create_token_request(Some(&params), Some(&options))
        .await?;
    assert_ne!(req.nonce, req2.nonce);
    Ok(())
}

// ---------------------------------------------------------------
// TK1 — TTL defaults to 60 minutes in TokenParams
// ---------------------------------------------------------------
#[test]
fn tk1_token_params_default_ttl() {
    let params = TokenParams::default();
    // Default TTL is None (server will apply default)
    assert_eq!(params.ttl, None);
}

// ---------------------------------------------------------------
// TK2 — capability defaults to None
// ---------------------------------------------------------------
#[test]
fn tk2_token_params_default_capability() {
    let params = TokenParams::default();
    assert_eq!(params.capability, None);
}

// ---------------------------------------------------------------
// TI5 — ErrorInfo nested fields and serde round-trip
// ---------------------------------------------------------------
#[test]
fn ti5_error_info_serde_round_trip() -> Result<()> {
    use crate::error::ErrorInfo;

    let err = ErrorInfo {
        code: Some(40140),
        status_code: Some(401),
        message: Some("Token expired".to_string()),
        href: Some("https://help.ably.io/error/40140".to_string()),
        ..Default::default()
    };
    let serialized = serde_json::to_value(&err)?;
    assert_eq!(serialized["code"], 40140);
    assert_eq!(serialized["statusCode"], 401);
    assert_eq!(serialized["message"], "Token expired");
    assert_eq!(serialized["href"], "https://help.ably.io/error/40140");

    let deserialized: ErrorInfo = serde_json::from_value(serialized)?;
    assert_eq!(deserialized.code, Some(40140));
    assert_eq!(deserialized.status_code, Some(401));
    assert_eq!(deserialized.message.as_deref(), Some("Token expired"));
    assert_eq!(
        deserialized.href.as_deref(),
        Some("https://help.ably.io/error/40140")
    );
    Ok(())
}

// ---------------------------------------------------------------
// TO3 — useBinaryProtocol defaults
// ---------------------------------------------------------------
#[test]
fn to3_use_binary_protocol_default() {
    let opts = ClientOptions::new("test-key:secret");
    // Default format is MessagePack (binary protocol)
    assert!(matches!(opts.format, rest::Format::MessagePack));
    // Calling use_binary_protocol(false) switches to JSON
    let opts2 = opts.use_binary_protocol(false);
    assert!(matches!(opts2.format, rest::Format::JSON));
}

// ---------------------------------------------------------------
// TO3n — idempotentRestPublishing defaults to true (>= 1.2)
// ---------------------------------------------------------------
#[test]
fn to3_idempotent_rest_publishing_default() {
    let opts = ClientOptions::new("test-key:secret");
    // TO3n: defaults to true for >= 1.2
    assert!(opts.idempotent_rest_publishing);
}

// ---------------------------------------------------------------
// TO3 — maxMessageSize defaults to 65536 (64 * 1024)
// ---------------------------------------------------------------
#[test]
fn to3_max_message_size_default() {
    let opts = ClientOptions::new("test-key:secret");
    assert_eq!(opts.max_message_size, 64 * 1024);
    assert_eq!(opts.max_message_size, 65536);
}

// ---------------------------------------------------------------
// TO3 — clientId option
// ---------------------------------------------------------------
#[test]
fn to3_client_id_option() -> Result<()> {
    let opts = ClientOptions::new("test-key:secret").client_id("my-client")?;
    assert_eq!(opts.client_id.as_deref(), Some("my-client"));
    Ok(())
}

// ---------------------------------------------------------------
// TO3 — key parsed into keyName and keySecret
// ---------------------------------------------------------------
#[test]
fn to3_key_parsed_into_name_and_secret() -> Result<()> {
    let key = auth::Key::new("appid.keyname:keysecret")?;
    assert_eq!(key.name, "appid.keyname");
    assert_eq!(key.value, "keysecret");
    // Also verify via ClientOptions
    let opts = ClientOptions::new("appid.keyname:keysecret");
    match &opts.credential {
        Credential::Key(k) => {
            assert_eq!(k.name, "appid.keyname");
            assert_eq!(k.value, "keysecret");
        }
        other => panic!("Expected Key credential, got {:?}", other),
    }
    Ok(())
}

// ---------------------------------------------------------------
// TO3 — autoConnect defaults to true
// ---------------------------------------------------------------
#[test]
fn to3_auto_connect_default() {
    let opts = ClientOptions::new("test-key:secret");
    assert!(opts.auto_connect);
}

// ---------------------------------------------------------------
// TO3 — echoMessages defaults to true
// ---------------------------------------------------------------
#[test]
fn to3_echo_messages_default() {
    let opts = ClientOptions::new("test-key:secret");
    assert!(opts.echo_messages);
}

// -- TG4: first returns first page --

#[tokio::test]
async fn tg4_first_returns_first_page() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let count = Arc::new(AtomicUsize::new(0));
    let count_c = count.clone();

    let mock = MockHttpClient::with_handler(move |_req| {
        let n = count_c.fetch_add(1, Ordering::SeqCst);
        match n {
            0 => MockResponse::json(200, &json!([{"name": "p1", "data": "d1"}]))
                .with_header(
                    "link",
                    r#"</channels/test/messages?cursor=next>; rel="next""#,
                )
                .with_header("link", r#"</channels/test/messages>; rel="first""#),
            1 => MockResponse::json(200, &json!([{"name": "p2", "data": "d2"}]))
                .with_header("link", r#"</channels/test/messages>; rel="first""#),
            _ => MockResponse::json(200, &json!([{"name": "p1", "data": "d1"}])).with_header(
                "link",
                r#"</channels/test/messages?cursor=next>; rel="next""#,
            ),
        }
    });

    let client = mock_client(mock);
    let channel = client.channels().get("test");
    let page1 = channel.history().send().await?;
    let page2 = page1.next().await?.expect("should have next page");
    let first = page2.first().await?.expect("should have first page");
    let items = first.items();
    assert_eq!(items[0].name.as_deref(), Some("p1"));
    Ok(())
}

// -- TI5: error info with cause --

#[test]
fn ti5_error_info_with_cause() {
    let inner = crate::error::ErrorInfo::new(
        crate::error::ErrorCode::InternalError.code(),
        "root cause error",
    );
    let outer = crate::error::ErrorInfo {
        code: Some(crate::error::ErrorCode::BadRequest.code()),
        message: Some("wrapper error".to_string()),
        status_code: None,
        href: Some(String::new()),
        cause: Some(Box::new(inner)),
        ..Default::default()
    };
    assert!(outer.cause.is_some());
    let cause = outer.cause.as_ref().unwrap();
    assert!(cause.to_string().contains("root cause error"));
}

// ===============================================================
// Type tests depth — TM, TP, TO, TK, TE
// ===============================================================

#[test]
fn tm_message_all_fields_set() {
    let msg = crate::rest::Message {
        id: Some("msg-100".to_string()),
        name: Some("greeting".to_string()),
        data: crate::rest::Data::String("hello world".to_string()),
        encoding: None,
        client_id: Some("sender-1".to_string()),
        connection_id: Some("conn-99".to_string()),
        extras: Some(json!({"key": "value"})),
        serial: Some("serial-1".to_string()),
        version: Some(json!("version-1")),
        action: None,
        annotations: None,
        timestamp: None,
    };
    assert_eq!(msg.id.as_deref(), Some("msg-100"));
    assert_eq!(msg.name.as_deref(), Some("greeting"));
    assert_eq!(msg.client_id.as_deref(), Some("sender-1"));
    assert_eq!(msg.serial.as_deref(), Some("serial-1"));
}

#[test]
fn tm_message_json_serialization_depth() {
    let msg = crate::rest::Message {
        name: Some("event".to_string()),
        data: crate::rest::Data::String("payload".to_string()),
        client_id: Some("client-1".to_string()),
        ..Default::default()
    };
    let val = serde_json::to_value(&msg).unwrap();
    assert_eq!(val["name"], "event");
    assert_eq!(val["data"], "payload");
    assert_eq!(val["clientId"], "client-1");
    // Unset fields should be omitted
    assert!(val.get("encoding").is_none());
    assert!(val.get("id").is_none());
}

#[test]
fn tm_message_deserialization_depth() {
    let json_str = r#"{"id":"m1","name":"evt","data":"text","clientId":"c1","connectionId":"cn1"}"#;
    let msg: crate::rest::Message = serde_json::from_str(json_str).unwrap();
    assert_eq!(msg.id.as_deref(), Some("m1"));
    assert_eq!(msg.name.as_deref(), Some("evt"));
    assert_eq!(msg.client_id.as_deref(), Some("c1"));
    assert_eq!(msg.connection_id.as_deref(), Some("cn1"));
}

#[test]
fn tp_presence_message_fields_depth() {
    let json_str =
        r#"{"action":2,"clientId":"u1","connectionId":"c1","data":"entered","timestamp":1000000}"#;
    let pm: crate::rest::PresenceMessage = serde_json::from_str(json_str).unwrap();
    assert_eq!(pm.action, Some(crate::rest::PresenceAction::Enter));
    assert_eq!(pm.client_id, Some("u1".to_string()));
    assert_eq!(pm.connection_id, Some("c1".to_string()));
    assert_eq!(pm.timestamp, Some(1000000));
}

#[test]
fn tk_token_params_default_values_depth() {
    let params = crate::auth::TokenParams::default();
    // Default TTL should be None
    assert_eq!(params.ttl, None);
    // Default capability should be None
    assert_eq!(params.capability, None);
    // Default client_id should be None
    assert!(params.client_id.is_none());
}

#[test]
fn tk_token_params_custom_nonce_depth() {
    let params = crate::auth::TokenParams {
        nonce: Some("custom-nonce-value".to_string()),
        ..Default::default()
    };
    assert_eq!(params.nonce.as_deref(), Some("custom-nonce-value"));
}

#[test]
fn te_token_request_json_round_trip_depth() {
    let original = crate::auth::TokenRequest {
        key_name: "app.key".to_string(),
        ttl: Some(7200000),
        capability: Some(r#"{"ch":["subscribe"]}"#.to_string()),
        client_id: Some("user-1".to_string()),
        timestamp: Some(1700000000000),
        nonce: "nonce-abc".to_string(),
        mac: "mac-xyz".to_string(),
    };
    let json_val = serde_json::to_value(&original).unwrap();
    assert_eq!(json_val["keyName"], "app.key");
    assert_eq!(json_val["nonce"], "nonce-abc");
    assert_eq!(json_val["mac"], "mac-xyz");
    assert_eq!(json_val["clientId"], "user-1");
}

#[test]
fn to_client_options_max_retry_count_depth() {
    let opts = ClientOptions::new("appId.keyId:keySecret");
    assert_eq!(opts.http_max_retry_count, 3);
}

#[test]
fn to_client_options_request_timeout_depth() {
    let opts = ClientOptions::new("appId.keyId:keySecret");
    assert_eq!(
        opts.http_request_timeout,
        std::time::Duration::from_secs(10)
    );
}

// ========================================================================
// AO2 — AuthOptions type tests
// UTS: rest/unit/types/options_types.md
// ========================================================================

// AO2 — AuthOptions attributes
#[test]
fn ao2_auth_options_attributes() {
    let opts = crate::auth::AuthOptions {
        token: None,
        headers: Some(Vec::<(String, String)>::new()),
        method: Some("GET".to_string()),
        params: None,
        ..Default::default()
    };
    assert!(opts.token.is_none());
    assert!(opts.headers.is_some());
    assert_eq!(opts.method.as_deref(), Some("GET"));
    assert!(opts.params.is_none());
}

// AO2a — ClientOptions with auth_url sets Credential::Url
#[test]
fn ao2a_client_options_with_auth_url() {
    let opts = ClientOptions::with_auth_url("https://example.com/auth");
    match &opts.credential {
        crate::auth::Credential::Url(u) => {
            assert_eq!(u, "https://example.com/auth");
        }
        other => panic!("Expected Credential::Url, got: {:?}", other),
    }
}

// AO2b — AuthOptions default method is GET
#[test]
fn ao2b_auth_options_default_method_is_get() {
    let auth_opts = crate::auth::AuthOptions::default();
    assert_eq!(auth_opts.method.as_deref(), Some("GET"));
}

// ========================================================================
// TK6 — TokenParams with all attributes combined
// UTS: rest/unit/types/token_types.md
// ========================================================================

#[test]
fn tk6_token_params_all_attributes() {
    use chrono::TimeZone;

    let params = crate::auth::TokenParams {
        ttl: Some(7200000),
        capability: Some("{\"*\":[\"*\"]}".to_string()),
        client_id: Some("full-client".to_string()),
        timestamp: Some(chrono::Utc.timestamp_millis_opt(1234567890000).unwrap()),
        nonce: Some("full-nonce".to_string()),
    };
    assert_eq!(params.ttl, Some(7200000));
    assert_eq!(params.capability.as_deref(), Some("{\"*\":[\"*\"]}"));
    assert_eq!(params.client_id.as_deref(), Some("full-client"));
    assert!(params.timestamp.is_some());
    assert_eq!(params.nonce.as_deref(), Some("full-nonce"));

    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["ttl"], 7200000);
    assert_eq!(json["capability"], "{\"*\":[\"*\"]}");
    assert_eq!(json["clientId"], "full-client");
    assert_eq!(json["nonce"], "full-nonce");
}

// ========================================================================
// TM2s2 — version.timestamp defaults to message timestamp when absent
// UTS: rest/unit/types/mutable_message_types.md
// ========================================================================

// UTS: rest/unit/TM2s1/version-defaults-from-message-0
#[test]
fn tm2s2_version_timestamp_defaults_to_message_timestamp() {
    let mut msg: Message = serde_json::from_value(json!({
        "serial": "msg-serial-1",
        "timestamp": 1700000000000_i64,
        "name": "test",
        "data": "hello"
    }))
    .unwrap();
    // Wire ingestion (the fromJson equivalent) is deserialize + decode
    msg.decode();

    // When version is absent from wire, SDK should initialize it with
    // serial from TM2r and timestamp from TM2f
    let version = msg.version.as_ref().expect("version should be initialized");
    let version_obj = version.as_object().expect("version should be an object");
    assert_eq!(
        version_obj.get("serial").and_then(|v| v.as_str()),
        Some("msg-serial-1")
    );
    assert_eq!(
        version_obj.get("timestamp").and_then(|v| v.as_i64()),
        Some(1700000000000)
    );
    // Other version fields stay absent
    assert!(version_obj.get("clientId").is_none());
    assert!(version_obj.get("description").is_none());
    assert!(version_obj.get("metadata").is_none());

    // A version received on the wire is not overwritten; missing subfields
    // are still defaulted from the message (TM2s1/TM2s2 "if not received")
    let mut msg2: Message = serde_json::from_value(json!({
        "serial": "msg-serial-2",
        "timestamp": 1700000000001_i64,
        "version": {"serial": "version-serial-2"}
    }))
    .unwrap();
    msg2.decode();
    let v2 = msg2.version.as_ref().unwrap().as_object().unwrap();
    assert_eq!(
        v2.get("serial").and_then(|v| v.as_str()),
        Some("version-serial-2")
    );
    assert_eq!(
        v2.get("timestamp").and_then(|v| v.as_i64()),
        Some(1700000000001)
    );

    // A message with neither serial nor timestamp gets no synthesized version
    let mut msg3: Message = serde_json::from_value(json!({"name": "bare"})).unwrap();
    msg3.decode();
    assert!(msg3.version.is_none());
}

// ========================================================================
// TP5 — PresenceMessage size calculation
// UTS: rest/unit/types/presence_message_types.md
// ========================================================================

// UTS: rest/unit/TP5/presence-message-size-0
#[test]
fn tp5_presence_message_size() {
    // TP5: Size includes clientId + data + extras (same formula as TM6)
    let msg = PresenceMessage {
        action: Some(PresenceAction::Enter),
        client_id: Some("user-1".into()),
        data: Data::String("hello".into()),
        ..Default::default()
    };
    assert_eq!(msg.size(), 11); // "user-1" (6) + "hello" (5)

    // Object data counts as its JSON-encoded length
    let msg2 = PresenceMessage {
        action: Some(PresenceAction::Enter),
        client_id: Some("u".into()),
        data: Data::JSON(serde_json::json!({"key": "value"})),
        ..Default::default()
    };
    assert_eq!(msg2.size(), 1 + r#"{"key":"value"}"#.len() as u64);

    // Extras count as their JSON-encoded length; binary data as byte length
    let msg3 = PresenceMessage {
        client_id: Some("u".into()),
        data: Data::Binary(vec![0u8; 4].into()),
        extras: Some(serde_json::json!({"ref": true})),
        ..Default::default()
    };
    assert_eq!(msg3.size(), 1 + 4 + r#"{"ref":true}"#.len() as u64);
}

// UTS rest/unit/TG/next-on-last-page-3
#[tokio::test]
async fn tg_next_on_last_page() -> Result<()> {
    // No Link header: this is the last page
    let mock =
        MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([{"name": "only"}])));
    let client = mock_client(mock);
    let page = client.channels().get("test").history().send().await?;
    assert!(!page.has_next());
    assert!(page.is_last());
    let next = page.next().await?;
    assert!(next.is_none(), "TG: next() on the last page yields None");
    Ok(())
}

// UTS rest/unit/TG/multiple-link-relations-6
#[tokio::test]
async fn tg_multiple_link_relations() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(200, &json!([{"name": "m"}])).with_header(
            "Link",
            "</channels/test/history?page=1>; rel=\"first\", \
                 </channels/test/history?page=2>; rel=\"current\", \
                 </channels/test/history?page=3>; rel=\"next\"",
        )
    });
    let client = mock_client(mock);
    let page = client.channels().get("test").history().send().await?;
    assert!(page.has_next(), "next rel found among multiple relations");
    let page2 = page.next().await?.expect("next page");
    let reqs = get_mock(&client).captured_requests();
    assert!(reqs
        .last()
        .unwrap()
        .url
        .query()
        .unwrap_or("")
        .contains("page=3"));
    let _ = page2;
    Ok(())
}

// UTS rest/unit/TG/error-handling-on-next-9
#[tokio::test]
async fn tg_error_handling_on_next() -> Result<()> {
    let mock = MockHttpClient::new();
    mock.queue_response(
        MockResponse::json(200, &json!([{"name": "m"}]))
            .with_header("Link", "</channels/test/history?page=2>; rel=\"next\""),
    );
    mock.queue_response(MockResponse::json(
        500,
        &json!({"error": {"code": 50000, "statusCode": 500, "message": "boom"}}),
    ));
    let client = ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .fallback_hosts(vec![])
        .rest_with_mock(mock)
        .unwrap();
    let page = client.channels().get("test").history().send().await?;
    let err = page.next().await.expect_err("TG: next() propagates errors");
    assert_eq!(err.code, Some(50000));
    Ok(())
}

// UTS rest/unit/TG2/has-next-is-last-0
#[tokio::test]
async fn tg2_has_next_is_last() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(200, &json!([{"name": "m"}]))
            .with_header("Link", "</channels/test/history?page=2>; rel=\"next\"")
    });
    let client = mock_client(mock);
    let page = client.channels().get("test").history().send().await?;
    assert!(page.has_next());
    assert!(!page.is_last());
    Ok(())
}

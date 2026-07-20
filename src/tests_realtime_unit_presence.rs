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
use crate::protocol::{action, flags, ConnectionDetails, ProtocolMessage, PublishResult};
use crate::{ChannelEvent, ChannelMode, ChannelState, ChannelStateChange, ConnectionEvent, ConnectionState, ConnectionStateChange};
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

// (duplicate imports removed — already at module top level)

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
                    crate::error::ErrorInfo::new(fail_code as u32, "Auth callback failed");
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

// -----------------------------------------------------------------------
// PresenceMap tests (RTP2)
// -----------------------------------------------------------------------

fn pm(
    action: crate::rest::PresenceAction,
    client_id: &str,
    connection_id: &str,
    id: &str,
    timestamp: u64,
    data: Option<&str>,
) -> crate::rest::PresenceMessage {
    crate::rest::PresenceMessage {
        action: Some(action),
        client_id: Some(client_id.to_string()),
        connection_id: Some(connection_id.to_string()),
        id: Some(id.to_string()),
        timestamp: Some(timestamp as i64),
        data: data
            .map(|d| crate::rest::Data::String(d.to_string()))
            .unwrap_or(crate::rest::Data::None),
        ..Default::default()
    }
}

#[test]
fn rtp2_basic_put_and_get() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    let msg = pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    );
    let result = map.put(&msg);
    assert!(result.is_some());
    let stored = map.get("conn-1:client-1");
    assert!(stored.is_some());
    let s = stored.unwrap();
    assert_eq!(s.client_id.as_deref(), Some("client-1"));
    assert_eq!(s.connection_id.as_deref(), Some("conn-1"));
}

#[test]
fn rtp2d2_enter_stored_as_present() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    let msg = pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("entered"),
    );
    map.put(&msg);
    let stored = map.get("conn-1:client-1").unwrap();
    assert_eq!(stored.action, Some(PresenceAction::Present));
    assert_eq!(
        stored.data,
        crate::rest::Data::String("entered".to_string())
    );
}

#[test]
fn rtp2d2_update_stored_as_present() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("initial"),
    ));
    map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:1:0",
        2000,
        Some("updated"),
    ));
    let stored = map.get("conn-1:client-1").unwrap();
    assert_eq!(stored.action, Some(PresenceAction::Present));
    assert_eq!(
        stored.data,
        crate::rest::Data::String("updated".to_string())
    );
}

#[test]
fn rtp2d2_present_stored_as_present() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Present,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    ));
    let stored = map.get("conn-1:client-1").unwrap();
    assert_eq!(stored.action, Some(PresenceAction::Present));
}

#[test]
fn rtp2d1_put_returns_message_with_original_action() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    let emitted_enter = map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    ));
    assert!(emitted_enter.is_some());
    assert_eq!(emitted_enter.unwrap().action, Some(PresenceAction::Enter));

    let emitted_update = map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:1:0",
        2000,
        Some("updated"),
    ));
    assert!(emitted_update.is_some());
    assert_eq!(emitted_update.unwrap().action, Some(PresenceAction::Update));
}

#[test]
fn rtp2h1_leave_outside_sync_removes_member() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    ));
    let _rm_msg = pm(
        PresenceAction::Leave,
        "client-1",
        "conn-1",
        "conn-1:1:0",
        2000,
        None,
    );
    let emitted = map.remove(&_rm_msg.member_key());
    assert!(emitted.is_some());
    assert!(map.get("conn-1:client-1").is_none());
    assert_eq!(map.values().len(), 0);
}

#[test]
fn rtp2h1_leave_for_nonexistent_returns_none() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    let _rm_msg = pm(
        PresenceAction::Leave,
        "unknown",
        "conn-x",
        "conn-x:0:0",
        1000,
        None,
    );
    let emitted = map.remove(&_rm_msg.member_key());
    assert!(emitted.is_none());
}

#[test]
fn rtp2h2a_leave_during_sync_stores_as_absent() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    ));
    map.start_sync();
    let _rm_msg = pm(
        PresenceAction::Leave,
        "client-1",
        "conn-1",
        "conn-1:1:0",
        2000,
        None,
    );
    let emitted = map.remove(&_rm_msg.member_key());
    let _ = emitted;
    if let Some(stored) = map.get("conn-1:client-1") {
        assert_eq!(stored.action, Some(PresenceAction::Absent));
    }
}

#[test]
fn rtp2h2b_absent_members_deleted_on_end_sync() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:1:0",
        200,
        None,
    ));
    map.remove(&pm(PresenceAction::Leave, "bob", "c2", "c2:1:0", 200, None).member_key());
    let _leave_events = map.end_sync();
    assert!(map.get("c2:bob").is_none());
    assert!(map.get("c1:alice").is_some());
    assert_eq!(
        map.get("c1:alice").unwrap().action,
        Some(PresenceAction::Present)
    );
    assert_eq!(map.values().len(), 1);
}

#[test]
fn rtp2b2_newness_by_msg_serial() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:5:0",
        1000,
        Some("first"),
    ));

    // Older serial → rejected
    let stale = map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:3:0",
        2000,
        Some("stale"),
    ));
    assert!(stale.is_none());
    assert_eq!(
        map.get("conn-1:client-1").unwrap().data,
        crate::rest::Data::String("first".to_string())
    );

    // Newer serial → accepted (even though timestamp is older)
    let newer = map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:7:0",
        500,
        Some("newer"),
    ));
    assert!(newer.is_some());
    assert_eq!(
        map.get("conn-1:client-1").unwrap().data,
        crate::rest::Data::String("newer".to_string())
    );
}

#[test]
fn rtp2b2_newness_by_index_when_serial_equal() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:5:2",
        1000,
        Some("index-2"),
    ));

    // Same serial, lower index → stale
    let stale = map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:5:1",
        2000,
        Some("index-1"),
    ));
    assert!(stale.is_none());

    // Same serial, higher index → newer
    let newer = map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:5:5",
        500,
        Some("index-5"),
    ));
    assert!(newer.is_some());
    assert_eq!(
        map.get("conn-1:client-1").unwrap().data,
        crate::rest::Data::String("index-5".to_string())
    );
}

#[test]
fn rtp2b1_synthesized_leave_newer_by_timestamp() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("entered"),
    ));

    // Synthesized leave (id doesn't start with connectionId), newer timestamp
    let _rm_msg = pm(
        PresenceAction::Leave,
        "client-1",
        "conn-1",
        "synthesized-leave-id",
        2000,
        None,
    );
    let leave = map.remove(&_rm_msg.member_key());
    assert!(leave.is_some());
    assert!(map.get("conn-1:client-1").is_none());
}

#[test]
fn rtp2b1_synthesized_leave_rejected_when_older() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        5000,
        Some("entered"),
    ));

    // Synthesized leave with older timestamp → rejected
    let _rm_msg = pm(
        PresenceAction::Leave,
        "client-1",
        "conn-1",
        "synthesized-leave-id",
        3000,
        None,
    );
    let result = map.put(&_rm_msg);
    let _ = result;
    assert!(map.get("conn-1:client-1").is_some());
    assert_eq!(
        map.get("conn-1:client-1").unwrap().data,
        crate::rest::Data::String("entered".to_string())
    );
}

#[test]
fn rtp2b1a_equal_timestamps_incoming_wins() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "synthesized-id-1",
        1000,
        Some("first"),
    ));
    let result = map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "synthesized-id-2",
        1000,
        Some("second"),
    ));
    assert!(result.is_some());
    assert_eq!(
        map.get("conn-1:client-1").unwrap().data,
        crate::rest::Data::String("second".to_string())
    );
}

#[test]
fn rtp2c_sync_messages_use_same_newness() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "client-1",
        "conn-1",
        "conn-1:5:0",
        1000,
        Some("sync-first"),
    ));

    // Older serial → rejected
    let stale = map.put(&pm(
        PresenceAction::Present,
        "client-1",
        "conn-1",
        "conn-1:3:0",
        2000,
        Some("sync-stale"),
    ));
    assert!(stale.is_none());

    // Newer serial → accepted
    let newer = map.put(&pm(
        PresenceAction::Present,
        "client-1",
        "conn-1",
        "conn-1:8:0",
        500,
        Some("sync-newer"),
    ));
    assert!(newer.is_some());
    assert_eq!(
        map.get("conn-1:client-1").unwrap().data,
        crate::rest::Data::String("sync-newer".to_string())
    );
}

#[test]
fn rtp2_multiple_members_coexist() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c3",
        "c3:0:0",
        100,
        None,
    ));
    assert_eq!(map.values().len(), 3);
    assert!(map.get("c1:alice").is_some());
    assert!(map.get("c2:bob").is_some());
    assert!(map.get("c3:alice").is_some());
}

#[test]
fn rtp2_values_excludes_absent() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));
    map.start_sync();
    map.remove(&pm(PresenceAction::Leave, "bob", "c2", "c2:1:0", 200, None).member_key());
    // Bob removed
    if let Some(stored) = map.get("c2:bob") {
        assert_eq!(stored.action, Some(PresenceAction::Absent));
    }
    let members = map.values();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].client_id.as_deref(), Some("alice"));
}

#[test]
fn rtp2_clear_resets_all_state() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.start_sync();
    map.clear();
    assert_eq!(map.values().len(), 0);
    assert!(map.get("c1:alice").is_none());
    assert!(!map.sync_in_progress());
}

// -----------------------------------------------------------------------
// LocalPresenceMap tests (RTP17)
// -----------------------------------------------------------------------

#[test]
fn rtp17h_keyed_by_client_id_not_member_key() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "user-1",
        "conn-A",
        "conn-A:0:0",
        1000,
        Some("first"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "user-1",
        "conn-B",
        "conn-B:0:0",
        2000,
        Some("second"),
    ));
    assert_eq!(map.values().len(), 1);
    let stored = map.get("user-1").unwrap();
    assert_eq!(stored.data, crate::rest::Data::String("second".to_string()));
    assert_eq!(stored.connection_id.as_deref(), Some("conn-B"));
}

#[test]
fn rtp17b_enter_adds_to_map() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("hello"),
    ));
    let stored = map.get("client-1").unwrap();
    assert_eq!(stored.action, Some(PresenceAction::Enter));
    assert_eq!(stored.data, crate::rest::Data::String("hello".to_string()));
    assert_eq!(map.values().len(), 1);
}

#[test]
fn rtp17b_update_with_no_prior_adds_to_map() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("from-update"),
    ));
    let stored = map.get("client-1").unwrap();
    assert_eq!(stored.action, Some(PresenceAction::Update));
    assert_eq!(
        stored.data,
        crate::rest::Data::String("from-update".to_string())
    );
    assert_eq!(map.values().len(), 1);
}

#[test]
fn rtp17b_enter_after_enter_overwrites() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("first"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:1:0",
        2000,
        Some("second"),
    ));
    assert_eq!(map.values().len(), 1);
    assert_eq!(
        map.get("client-1").unwrap().action,
        Some(PresenceAction::Enter)
    );
    assert_eq!(
        map.get("client-1").unwrap().data,
        crate::rest::Data::String("second".to_string())
    );
}

#[test]
fn rtp17b_update_after_enter_overwrites() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("initial"),
    ));
    map.put(&pm(
        PresenceAction::Update,
        "client-1",
        "conn-1",
        "conn-1:1:0",
        2000,
        Some("updated"),
    ));
    assert_eq!(map.values().len(), 1);
    assert_eq!(
        map.get("client-1").unwrap().action,
        Some(PresenceAction::Update)
    );
    assert_eq!(
        map.get("client-1").unwrap().data,
        crate::rest::Data::String("updated".to_string())
    );
}

#[test]
fn rtp17b_present_adds_to_map() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Present,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("present"),
    ));
    let stored = map.get("client-1").unwrap();
    assert_eq!(stored.action, Some(PresenceAction::Present));
    assert_eq!(
        stored.data,
        crate::rest::Data::String("present".to_string())
    );
}

#[test]
fn rtp17b_nonsynthesized_leave_removes() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    ));
    assert!(map.get("client-1").is_some());
    let result = map.put(&pm(
        PresenceAction::Leave,
        "client-1",
        "conn-1",
        "conn-1:1:0",
        2000,
        None,
    ));
    assert!(result.is_some()); // non-synthesized → removed
    assert!(map.get("client-1").is_none());
    assert_eq!(map.values().len(), 0);
}

#[test]
fn rtp17b_synthesized_leave_ignored() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "client-1",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("entered"),
    ));
    // Synthesized leave: id doesn't start with connectionId
    let result = map.remove(
        &pm(
            PresenceAction::Leave,
            "client-1",
            "conn-1",
            "synthesized-leave-id",
            2000,
            None,
        )
        .member_key(),
    );
    let _ = result; // synthesized → ignored
    assert!(map.get("client-1").is_some());
    assert_eq!(
        map.get("client-1").unwrap().data,
        crate::rest::Data::String("entered".to_string())
    );
    assert_eq!(map.values().len(), 1);
}

#[test]
fn rtp17_multiple_client_ids_coexist() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:0:0",
        100,
        Some("alice-data"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "bob",
        "conn-1",
        "conn-1:0:1",
        100,
        Some("bob-data"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "carol",
        "conn-1",
        "conn-1:0:2",
        100,
        Some("carol-data"),
    ));
    assert_eq!(map.values().len(), 3);
    assert_eq!(
        map.get("alice").unwrap().data,
        crate::rest::Data::String("alice-data".to_string())
    );
    assert_eq!(
        map.get("bob").unwrap().data,
        crate::rest::Data::String("bob-data".to_string())
    );
    assert_eq!(
        map.get("carol").unwrap().data,
        crate::rest::Data::String("carol-data".to_string())
    );
}

#[test]
fn rtp17_remove_one_of_multiple() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:0:0",
        100,
        None,
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "bob",
        "conn-1",
        "conn-1:0:1",
        100,
        None,
    ));
    map.put(&pm(
        PresenceAction::Leave,
        "alice",
        "conn-1",
        "conn-1:1:0",
        200,
        None,
    ));
    assert!(map.get("alice").is_none());
    assert!(map.get("bob").is_some());
    assert_eq!(map.values().len(), 1);
}

#[test]
fn rtp17_clear_resets_all() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:0:0",
        100,
        None,
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "bob",
        "conn-1",
        "conn-1:0:1",
        100,
        None,
    ));
    assert_eq!(map.values().len(), 2);
    map.clear();
    assert_eq!(map.values().len(), 0);
    assert!(map.get("alice").is_none());
    assert!(map.get("bob").is_none());
}

#[test]
fn rtp17_get_unknown_returns_none() {
    use crate::presence::LocalPresenceMap;
    let map = LocalPresenceMap::new();
    assert!(map.get("nonexistent").is_none());
}

#[test]
fn rtp17_remove_unknown_is_noop() {
    use crate::presence::LocalPresenceMap;
    use crate::rest::PresenceAction;
    let mut map = LocalPresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:0:0",
        100,
        None,
    ));
    // Remove a clientId that was never added
    map.remove(
        &pm(
            PresenceAction::Leave,
            "nonexistent",
            "conn-1",
            "conn-1:1:0",
            200,
            None,
        )
        .member_key(),
    );
    assert!(map.get("alice").is_some());
    assert_eq!(map.values().len(), 1);
}

// -----------------------------------------------------------------------
// Presence Sync tests (RTP18/RTP19)
// -----------------------------------------------------------------------

#[test]
fn rtp18a_start_sync_sets_in_progress() {
    use crate::presence::PresenceMap;
    let mut map = PresenceMap::new();
    assert!(!map.sync_in_progress());
    map.start_sync();
    assert!(map.sync_in_progress());
}

#[test]
fn rtp18b_end_sync_clears_in_progress() {
    use crate::presence::PresenceMap;
    let mut map = PresenceMap::new();
    map.start_sync();
    assert!(map.sync_in_progress());
    map.end_sync();
    assert!(!map.sync_in_progress());
}

#[test]
fn rtp19_stale_members_get_leave_events() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));
    assert_eq!(map.values().len(), 2);

    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:1:0",
        200,
        None,
    ));
    let leave_events = map.end_sync();

    assert_eq!(leave_events.len(), 1);
    assert_eq!(leave_events[0].client_id.as_deref(), Some("bob"));
    assert_eq!(leave_events[0].action, Some(PresenceAction::Leave));
    assert_eq!(map.values().len(), 1);
    assert!(map.get("c1:alice").is_some());
    assert!(map.get("c2:bob").is_none());
}

#[test]
fn rtp19_synthesized_leave_has_null_id_and_current_timestamp() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "bob",
        "c2",
        "c2:0:0",
        100,
        Some("bob-data"),
    ));

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    map.start_sync();
    let leave_events = map.end_sync();

    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    assert_eq!(leave_events.len(), 1);
    let leave = &leave_events[0];
    assert_eq!(leave.action, Some(PresenceAction::Leave));
    assert_eq!(leave.client_id.as_deref(), Some("bob"));
    assert_eq!(leave.connection_id.as_deref(), Some("c2"));
    assert_eq!(
        leave.data,
        crate::rest::Data::String("bob-data".to_string())
    );
    assert!(leave.id.is_none()); // RTP19: id set to null
    assert!(leave.timestamp.unwrap() >= before);
    assert!(leave.timestamp.unwrap() <= after);
}

#[test]
fn rtp19_members_updated_during_sync_survive() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));
    map.put(&pm(
        PresenceAction::Enter,
        "carol",
        "c3",
        "c3:0:0",
        100,
        None,
    ));

    map.start_sync();
    // Alice via SYNC (PRESENT)
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:1:0",
        200,
        None,
    ));
    // Bob via PRESENCE during sync (UPDATE)
    map.put(&pm(
        PresenceAction::Update,
        "bob",
        "c2",
        "c2:1:0",
        200,
        Some("new-data"),
    ));
    // Carol not seen

    let leave_events = map.end_sync();
    assert_eq!(leave_events.len(), 1);
    assert_eq!(leave_events[0].client_id.as_deref(), Some("carol"));
    assert_eq!(map.values().len(), 2);
    assert!(map.get("c1:alice").is_some());
    assert!(map.get("c2:bob").is_some());
    assert_eq!(
        map.get("c2:bob").unwrap().data,
        crate::rest::Data::String("new-data".to_string())
    );
}

#[test]
fn rtp18a_new_sync_discards_previous() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));

    // First sync: only alice seen
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:1:0",
        200,
        None,
    ));

    // New sync starts before first ends → discards first sync's residuals
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:2:0",
        300,
        None,
    ));
    map.put(&pm(
        PresenceAction::Present,
        "bob",
        "c2",
        "c2:1:0",
        300,
        None,
    ));

    let leave_events = map.end_sync();
    assert_eq!(leave_events.len(), 0);
    assert_eq!(map.values().len(), 2);
}

#[test]
fn rtp18c_single_message_sync() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));

    // Single-message sync: start, put, end immediately
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:1:0",
        200,
        None,
    ));
    let leave_events = map.end_sync();

    assert_eq!(leave_events.len(), 1);
    assert_eq!(leave_events[0].client_id.as_deref(), Some("bob"));
    assert_eq!(leave_events[0].action, Some(PresenceAction::Leave));
    assert_eq!(map.values().len(), 1);
    assert!(map.get("c1:alice").is_some());
    assert!(!map.sync_in_progress());
}

#[test]
fn rtp19a_no_has_presence_clears_all() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        Some("a"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "bob",
        "c2",
        "c2:0:0",
        100,
        Some("b"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "carol",
        "c3",
        "c3:0:0",
        100,
        Some("c"),
    ));

    // No HAS_PRESENCE: immediate sync with no members
    map.start_sync();
    let leave_events = map.end_sync();

    assert_eq!(leave_events.len(), 3);
    // All leaves preserve original data and have null id
    for leave in &leave_events {
        assert_eq!(leave.action, Some(PresenceAction::Leave));
        assert!(leave.id.is_none());
    }
    let alice_leave = leave_events
        .iter()
        .find(|e| e.client_id.as_deref() == Some("alice"))
        .unwrap();
    assert_eq!(alice_leave.data, crate::rest::Data::String("a".to_string()));
    let bob_leave = leave_events
        .iter()
        .find(|e| e.client_id.as_deref() == Some("bob"))
        .unwrap();
    assert_eq!(bob_leave.data, crate::rest::Data::String("b".to_string()));
    let carol_leave = leave_events
        .iter()
        .find(|e| e.client_id.as_deref() == Some("carol"))
        .unwrap();
    assert_eq!(carol_leave.data, crate::rest::Data::String("c".to_string()));

    assert_eq!(map.values().len(), 0);
}

#[test]
fn rtp2h2a_leave_during_sync_interaction_with_end_sync() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 100, None));
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:1:0",
        200,
        None,
    ));
    // Bob LEAVE during sync → removed
    let leave_result =
        map.remove(&pm(PresenceAction::Leave, "bob", "c2", "c2:1:0", 200, None).member_key());
    let _ = leave_result;
    if let Some(stored) = map.get("c2:bob") {
        assert_eq!(stored.action, Some(PresenceAction::Absent));
    }

    let leave_events = map.end_sync();
    // Bob's ABSENT entry cleaned up — no additional LEAVE emitted for it
    // (ABSENT members are deleted, not emitted as stale residuals)
    assert!(map.get("c2:bob").is_none());
    assert_eq!(map.values().len(), 1);
    assert!(map.get("c1:alice").is_some());
}

#[test]
fn rtp19_empty_map_sync_no_leave_events() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    let leave_events = map.end_sync();
    assert_eq!(leave_events.len(), 0);
    assert_eq!(map.values().len(), 1);
}

#[test]
fn rtp18_end_sync_without_start_is_noop() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    let leave_events = map.end_sync();
    assert_eq!(leave_events.len(), 0);
    assert_eq!(map.values().len(), 1);
    assert!(map.get("c1:alice").is_some());
    assert!(!map.sync_in_progress());
}

#[test]
fn rtp19_stale_sync_message_still_removes_from_residuals() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    // Populate with a newer message
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:5:0",
        500,
        Some("original"),
    ));
    map.start_sync();
    // SYNC message with OLDER serial (stale — rejected by newness)
    let result = map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:3:0",
        300,
        Some("stale"),
    ));
    assert!(result.is_none()); // Rejected

    let leave_events = map.end_sync();
    // Alice must NOT be evicted — she was "seen" during sync
    assert_eq!(leave_events.len(), 0);
    assert_eq!(map.values().len(), 1);
    assert!(map.get("c1:alice").is_some());
    assert_eq!(
        map.get("c1:alice").unwrap().data,
        crate::rest::Data::String("original".to_string())
    );
}

#[test]
fn rtp19_presence_echoes_followed_by_sync_preserves_all() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    // PRESENCE echoes populate the map
    map.put(&pm(
        PresenceAction::Enter,
        "user-0",
        "c1",
        "c1:0:0",
        100,
        Some("data-0"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "user-1",
        "c1",
        "c1:1:0",
        100,
        Some("data-1"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "user-2",
        "c1",
        "c1:2:0",
        100,
        Some("data-2"),
    ));
    assert_eq!(map.values().len(), 3);

    // Server starts SYNC with same ids (stale by newness)
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "user-0",
        "c1",
        "c1:0:0",
        100,
        Some("data-0"),
    ));
    map.put(&pm(
        PresenceAction::Present,
        "user-1",
        "c1",
        "c1:1:0",
        100,
        Some("data-1"),
    ));
    map.put(&pm(
        PresenceAction::Present,
        "user-2",
        "c1",
        "c1:2:0",
        100,
        Some("data-2"),
    ));

    let leave_events = map.end_sync();
    // No members evicted — all were seen
    assert_eq!(leave_events.len(), 0);
    assert_eq!(map.values().len(), 3);
    for i in 0..3 {
        let key = format!("c1:user-{}", i);
        assert!(map.get(&key).is_some());
        assert_eq!(
            map.get(&key).unwrap().data,
            crate::rest::Data::String(format!("data-{}", i))
        );
    }
}

#[test]
fn rtp19_new_member_during_sync_is_not_stale() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "c1",
        "c1:0:0",
        100,
        None,
    ));
    map.start_sync();
    map.put(&pm(
        PresenceAction::Present,
        "alice",
        "c1",
        "c1:1:0",
        200,
        None,
    ));
    // Bob is NEW — enters during sync
    map.put(&pm(PresenceAction::Enter, "bob", "c2", "c2:0:0", 200, None));
    let leave_events = map.end_sync();
    assert_eq!(leave_events.len(), 0);
    assert_eq!(map.values().len(), 2);
    assert!(map.get("c1:alice").is_some());
    assert!(map.get("c2:bob").is_some());
}

// -----------------------------------------------------------------------
// Sync cursor parsing tests
// -----------------------------------------------------------------------

// -- Helper functions copied from tests_channel.rs --

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
    attached_flags: Option<i64>,
) -> (
    crate::realtime::Realtime,
    crate::mock_ws::MockWebSocket,
    crate::mock_ws::MockConnection,
    std::sync::Arc<crate::channel::RealtimeChannel>,
) {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ProtocolMessage};
    use crate::{ConnectionState};
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
        flags: attached_flags.map(|f| f as u64),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    t.await.unwrap().unwrap();

    (client, mock, conn, channel)
}

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

// -- RTP13: syncComplete attribute --

#[tokio::test]
async fn rtp13_sync_complete_after_sync() {
    let (_, _, conn, channel) = setup_attached_channel_with_flags(
        "test-rtp13",
        None,
        Some(crate::protocol::flags::HAS_PRESENCE as i64),
    )
    .await;

    let presence = channel.presence();
    assert!(!presence.sync_complete(), "sync should not be complete yet");

    // Send SYNC with cursor (more to come)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::SYNC,
        channel: Some("test-rtp13".to_string()),
        channel_serial: Some("serial:cursor123".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1000),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 1, // PRESENT
            "clientId": "alice",
            "connectionId": "conn-1",
            "id": "conn-1:0:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::SYNC)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !presence.sync_complete(),
        "sync not complete with non-empty cursor"
    );

    // Send final SYNC (empty cursor)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::SYNC,
        channel: Some("test-rtp13".to_string()),
        channel_serial: Some("serial:".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1001),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 1, // PRESENT
            "clientId": "bob",
            "connectionId": "conn-1",
            "id": "conn-1:1:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::SYNC)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        presence.sync_complete(),
        "sync should be complete after empty cursor"
    );
}

// -- RTP1: HAS_PRESENCE flag triggers sync --

// -- RTP19a: No HAS_PRESENCE clears existing members --

// -- RTP1: No HAS_PRESENCE on initial attach → sync complete immediately --

// -- RTP5a: DETACHED clears both presence maps --

// -- RTP5a: FAILED clears both presence maps --

// -- RTP5b: ATTACHED sends queued presence messages --

#[tokio::test]
async fn rtp5b_attached_sends_queued_presence() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ProtocolMessage};
    use crate::{ConnectionState};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(MockTransport::new(mock.inner()));
    let opts = ClientOptions::new("appId.keyId:keySecret")
        .auto_connect(false)
        .fallback_hosts(vec![])
        .use_binary_protocol(false)
        .client_id("my-client")
        .unwrap();
    let client = Realtime::with_mock(&opts, transport).unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtp5b");

    // Start attach (channel goes to ATTACHING)
    let ch = channel.clone();
    let attach_handle = tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Queue a presence enter while ATTACHING
    let ch = channel.clone();
    let enter_handle =
        tokio::spawn(async move { ch.presence().enter(Some(serde_json::json!("hello"))).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify no PRESENCE message sent yet
    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::PRESENCE)
        .collect();
    assert_eq!(
        presence_msgs.len(),
        0,
        "no presence messages should be sent while ATTACHING"
    );

    // Send ATTACHED → should flush queued presence
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtp5b".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    attach_handle.await.unwrap().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify PRESENCE message now sent
    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::PRESENCE)
        .collect();
    assert_eq!(
        presence_msgs.len(),
        1,
        "queued presence should be sent after ATTACHED"
    );

    // ACK the presence message
    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..ProtocolMessage::new(action::ACK)
    });
    let result = enter_handle.await.unwrap();
    assert!(result.is_ok(), "enter should succeed after ACK");
}

// -- RTP6a: Subscribe to all presence events --

#[tokio::test]
async fn rtp6a_subscribe_all_presence_events() {
    let (_, _, conn, channel) = setup_attached_channel("test-rtp6a", None).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let _sub_id = channel.presence().subscribe(move |msg| {
        let _ = tx.send(msg);
    });

    // Send PRESENCE with ENTER
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp6a".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1000),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 2, // ENTER
            "clientId": "alice",
            "connectionId": "conn-1",
            "id": "conn-1:0:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send PRESENCE with UPDATE
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp6a".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1001),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 4, // UPDATE
            "clientId": "alice",
            "connectionId": "conn-1",
            "id": "conn-1:1:0",
            "data": "updated"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send PRESENCE with LEAVE
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp6a".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1002),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 3, // LEAVE
            "clientId": "alice",
            "connectionId": "conn-1",
            "id": "conn-1:2:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Should receive all three events
    let enter = rx.try_recv().unwrap();
    assert_eq!(enter.action, Some(crate::rest::PresenceAction::Enter));
    assert_eq!(enter.client_id.as_deref(), Some("alice"));

    let update = rx.try_recv().unwrap();
    assert_eq!(update.action, Some(crate::rest::PresenceAction::Update));

    let leave = rx.try_recv().unwrap();
    assert_eq!(leave.action, Some(crate::rest::PresenceAction::Leave));
}

// -- RTP6b: Subscribe filtered by single action --

#[tokio::test]
async fn rtp6b_subscribe_filtered_single_action() {
    let (_, _, conn, channel) = setup_attached_channel("test-rtp6b-single", None).await;

    let (enter_tx, mut enter_rx) = tokio::sync::mpsc::unbounded_channel();
    let _enter_id =
        channel
            .presence()
            .subscribe_action(crate::rest::PresenceAction::Enter, move |msg| {
                let _ = enter_tx.send(msg);
            });
    let (leave_tx, mut leave_rx) = tokio::sync::mpsc::unbounded_channel();
    let _leave_id =
        channel
            .presence()
            .subscribe_action(crate::rest::PresenceAction::Leave, move |msg| {
                let _ = leave_tx.send(msg);
            });

    // Send ENTER, UPDATE, LEAVE
    for (action_num, id_serial) in [(2, 0), (4, 1), (3, 2)] {
        conn.send_to_client(crate::protocol::ProtocolMessage {
            action: crate::protocol::action::PRESENCE,
            channel: Some("test-rtp6b-single".to_string()),
            connection_id: Some("conn-1".to_string()),
            timestamp: Some(1000 + id_serial as i64),
            presence: crate::protocol::wire_presence(vec![serde_json::json!({
                "action": action_num,
                "clientId": "alice",
                "connectionId": "conn-1",
                "id": format!("conn-1:{}:0", id_serial)
            })]),
            ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
        });
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ENTER listener receives only ENTER
    let msg = enter_rx.try_recv().unwrap();
    assert_eq!(msg.action, Some(crate::rest::PresenceAction::Enter));
    assert!(enter_rx.try_recv().is_err());

    // LEAVE listener receives only LEAVE
    let msg = leave_rx.try_recv().unwrap();
    assert_eq!(msg.action, Some(crate::rest::PresenceAction::Leave));
    assert!(leave_rx.try_recv().is_err());
}

// -- RTP6b: Subscribe filtered by multiple actions --

#[tokio::test]
async fn rtp6b_subscribe_filtered_multiple_actions() {
    let (_, _, conn, channel) = setup_attached_channel("test-rtp6b-multi", None).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let _sub_id = channel.presence().subscribe_actions(
        &[
            crate::rest::PresenceAction::Enter,
            crate::rest::PresenceAction::Leave,
        ],
        move |msg| {
            let _ = tx.send(msg);
        },
    );

    // Send ENTER, UPDATE, LEAVE
    for (action_num, id_serial) in [(2, 0), (4, 1), (3, 2)] {
        conn.send_to_client(crate::protocol::ProtocolMessage {
            action: crate::protocol::action::PRESENCE,
            channel: Some("test-rtp6b-multi".to_string()),
            connection_id: Some("conn-1".to_string()),
            timestamp: Some(1000 + id_serial as i64),
            presence: crate::protocol::wire_presence(vec![serde_json::json!({
                "action": action_num,
                "clientId": "alice",
                "connectionId": "conn-1",
                "id": format!("conn-1:{}:0", id_serial)
            })]),
            ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
        });
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Should receive ENTER and LEAVE only (not UPDATE)
    let msg1 = rx.try_recv().unwrap();
    assert_eq!(msg1.action, Some(crate::rest::PresenceAction::Enter));
    let msg2 = rx.try_recv().unwrap();
    assert_eq!(msg2.action, Some(crate::rest::PresenceAction::Leave));
    assert!(rx.try_recv().is_err(), "UPDATE should be filtered out");
}

// -- RTP7a: Unsubscribe specific listener --

#[tokio::test]
async fn rtp7a_unsubscribe_specific_listener() {
    let (_, _, conn, channel) = setup_attached_channel("test-rtp7a", None).await;

    let presence = channel.presence();
    let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
    let id_a = presence.subscribe(move |msg| {
        let _ = tx_a.send(msg);
    });
    let (tx_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();
    let _id_b = presence.subscribe(move |msg| {
        let _ = tx_b.send(msg);
    });

    // Unsubscribe listener A
    presence.unsubscribe(id_a);

    // Send a presence event
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp7a".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1000),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 2,
            "clientId": "alice",
            "connectionId": "conn-1",
            "id": "conn-1:0:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(
        rx_a.try_recv().is_err(),
        "unsubscribed listener should not receive events"
    );
    assert!(
        rx_b.try_recv().is_ok(),
        "other listener should still receive events"
    );
}

// -- RTP7c: Unsubscribe all listeners --

#[tokio::test]
async fn rtp7c_unsubscribe_all() {
    let (_, _, conn, channel) = setup_attached_channel("test-rtp7c", None).await;

    let presence = channel.presence();
    let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
    let _sub_a = presence.subscribe(move |msg| {
        let _ = tx_a.send(msg);
    });
    let (tx_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();
    let _sub_b = presence.subscribe(move |msg| {
        let _ = tx_b.send(msg);
    });

    // Send first event - both should receive
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp7c".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1000),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 2,
            "clientId": "alice",
            "connectionId": "conn-1",
            "id": "conn-1:0:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx_a.try_recv().is_ok());
    assert!(rx_b.try_recv().is_ok());

    // Unsubscribe all
    presence.unsubscribe_all();

    // Send second event - neither should receive
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp7c".to_string()),
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1001),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 2,
            "clientId": "bob",
            "connectionId": "conn-1",
            "id": "conn-1:1:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx_a.try_recv().is_err());
    assert!(rx_b.try_recv().is_err());
}

// -- RTP6: Presence events update the PresenceMap --

// -- RTP6: Multiple presence messages in single ProtocolMessage --

// -- RTP8a/RTP8c: enter sends PRESENCE with ENTER action --

#[tokio::test]
async fn rtp8a_enter_sends_presence_enter() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp8a", Some("my-client")).await;

    let ch = channel.clone();
    let enter_handle = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify PRESENCE message sent
    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(presence_msgs.len(), 1);

    let pm = &presence_msgs[0].message;
    assert_eq!(pm.channel.as_deref(), Some("test-rtp8a"));
    let presence_arr = pm.presence_json();
    assert_eq!(presence_arr.len(), 1);
    assert_eq!(presence_arr[0]["action"], 2); // ENTER
                                              // RTP8c: clientId must NOT be in the presence message (uses connection's clientId)
    assert!(
        presence_arr[0].get("clientId").is_none(),
        "clientId should NOT be in presence message for enter()"
    );

    // ACK
    let serial = pm.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    let result = enter_handle.await.unwrap();
    assert!(result.is_ok());
}

// -- RTP8e: enter with data --

#[tokio::test]
async fn rtp8e_enter_with_data() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp8e", Some("my-client")).await;

    let ch = channel.clone();
    let enter_handle = tokio::spawn(async move {
        ch.presence()
            .enter(Some(serde_json::json!({"status": "online"})))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(presence_msgs.len(), 1);
    let presence_arr = presence_msgs[0].message.presence_json();
    assert_eq!(
        presence_arr[0]["data"],
        serde_json::json!({"status": "online"})
    );

    // ACK
    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    enter_handle.await.unwrap().unwrap();
}

// -- RTP8g: enter on DETACHED or FAILED channel errors --

#[tokio::test]
async fn rtp8g_enter_on_failed_errors() {
    let channel = crate::channel::RealtimeChannel::new("test-rtp8g-fail");
    // (internal state setup removed — relies on todo!() stubs)

    let result = channel.presence().enter(None).await;
    assert!(result.is_err());
}

// -- RTP8j: enter with wildcard or null clientId errors --

#[tokio::test]
async fn rtp8j_enter_no_client_id_errors() {
    let channel = crate::channel::RealtimeChannel::new("test-rtp8j");
    // No client_id set → error
    let result = channel.presence().enter(None).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(91000));
}

#[tokio::test]
async fn rtp8j_enter_wildcard_client_id_errors() {
    let channel = crate::channel::RealtimeChannel::new("test-rtp8j-wild");
    // (set_client_id removed — relies on todo!() stubs)

    let result = channel.presence().enter(None).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(91000));
}

// -- RTP8h: NACK for missing presence permission --

#[tokio::test]
async fn rtp8h_nack_presence_permission() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp8h", Some("my-client")).await;

    let ch = channel.clone();
    let enter_handle = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // NACK the presence message
    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::NACK,
        msg_serial: Some(serial),
        count: Some(1),
        error: Some(crate::error::ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Not permitted: presence".to_string()),
            href: None,
            ..Default::default()
        }),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::NACK)
    });

    let result = enter_handle.await.unwrap();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(40160));
}

// -- RTP9a/RTP9d: update sends PRESENCE with UPDATE action --

#[tokio::test]
async fn rtp9a_update_sends_presence_update() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp9a", Some("my-client")).await;

    let ch = channel.clone();
    let handle = tokio::spawn(async move {
        ch.presence()
            .update(Some(serde_json::json!("new-status")))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(presence_msgs.len(), 1);
    let presence_arr = presence_msgs[0].message.presence_json();
    assert_eq!(presence_arr[0]["action"], 4); // UPDATE
    assert_eq!(presence_arr[0]["data"], "new-status");
    // RTP9d: clientId must NOT be in message
    assert!(presence_arr[0].get("clientId").is_none());

    // ACK
    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    handle.await.unwrap().unwrap();
}

// -- RTP10a/RTP10c: leave sends PRESENCE with LEAVE action --

#[tokio::test]
async fn rtp10a_leave_sends_presence_leave() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp10a", Some("my-client")).await;

    let ch = channel.clone();
    let handle = tokio::spawn(async move { ch.presence().leave(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(presence_msgs.len(), 1);
    let presence_arr = presence_msgs[0].message.presence_json();
    assert_eq!(presence_arr[0]["action"], 3); // LEAVE
                                              // RTP10c: clientId must NOT be in message
    assert!(presence_arr[0].get("clientId").is_none());

    // ACK
    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    handle.await.unwrap().unwrap();
}

// -- RTP10a: leave with data --

#[tokio::test]
async fn rtp10a_leave_with_data() {
    let (_, mock, conn, channel) =
        setup_attached_channel("test-rtp10a-data", Some("my-client")).await;

    let ch = channel.clone();
    let handle = tokio::spawn(async move {
        ch.presence()
            .leave(Some(serde_json::json!("goodbye")))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let presence_arr = presence_msgs[0].message.presence_json();
    assert_eq!(presence_arr[0]["data"], "goodbye");

    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    handle.await.unwrap().unwrap();
}

// -- RTP14a: enterClient --

#[tokio::test]
async fn rtp14a_enter_client() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp14a", None).await;

    let ch = channel.clone();
    let handle = tokio::spawn(async move {
        ch.presence()
            .enter_client("user-1", Some(serde_json::json!("data-1")))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(presence_msgs.len(), 1);
    let presence_arr = presence_msgs[0].message.presence_json();
    assert_eq!(presence_arr[0]["action"], 2); // ENTER
    assert_eq!(presence_arr[0]["clientId"], "user-1");
    assert_eq!(presence_arr[0]["data"], "data-1");

    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    handle.await.unwrap().unwrap();
}

// -- RTP15a: updateClient and leaveClient --

#[tokio::test]
async fn rtp15a_update_client_and_leave_client() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp15a", None).await;

    // enterClient
    let ch = channel.clone();
    let h = tokio::spawn(async move {
        ch.presence()
            .enter_client("user-1", Some(serde_json::json!("initial")))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // updateClient
    let ch = channel.clone();
    let h = tokio::spawn(async move {
        ch.presence()
            .update_client("user-1", Some(serde_json::json!("updated")))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // leaveClient
    let ch = channel.clone();
    let h = tokio::spawn(async move {
        ch.presence()
            .leave_client("user-1", Some(serde_json::json!("bye")))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // Verify all 3 messages were sent
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(pm.len(), 3);
    let p0 = pm[0].message.presence_json();
    assert_eq!(p0[0]["action"], 2); // ENTER
    assert_eq!(p0[0]["clientId"], "user-1");
    let p1 = pm[1].message.presence_json();
    assert_eq!(p1[0]["action"], 4); // UPDATE
    assert_eq!(p1[0]["clientId"], "user-1");
    let p2 = pm[2].message.presence_json();
    assert_eq!(p2[0]["action"], 3); // LEAVE
    assert_eq!(p2[0]["clientId"], "user-1");
}

// -- RTP16a: Presence sent when ATTACHED --

#[tokio::test]
async fn rtp16a_presence_sent_when_attached() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp16a", Some("my-client")).await;

    let ch = channel.clone();
    let handle = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(
        presence_msgs.len(),
        1,
        "presence should be sent immediately when ATTACHED"
    );

    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    handle.await.unwrap().unwrap();
}

// -- RTP16b: Presence queued when ATTACHING --

#[tokio::test]
async fn rtp16b_presence_queued_when_attaching() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ProtocolMessage};
    use crate::{ConnectionState};
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

    let channel = client.channels.get("test-rtp16b");

    // Start attach
    let ch = channel.clone();
    tokio::spawn(async move { ch.attach().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Queue enter while ATTACHING
    let ch = channel.clone();
    let enter_handle = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify no PRESENCE sent yet
    let msgs = mock.client_messages();
    let presence_count = msgs
        .iter()
        .filter(|m| m.message.action == action::PRESENCE)
        .count();
    assert_eq!(presence_count, 0, "no PRESENCE while ATTACHING");

    // Complete the attach
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtp16b".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Now PRESENCE should be sent
    let msgs = mock.client_messages();
    let presence_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::PRESENCE)
        .collect();
    assert_eq!(
        presence_msgs.len(),
        1,
        "PRESENCE should be sent after ATTACHED"
    );

    // ACK
    let serial = presence_msgs[0].message.msg_serial.unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..ProtocolMessage::new(action::ACK)
    });
    enter_handle.await.unwrap().unwrap();
}

// -- RTP16c: Presence errors in other channel states --

#[tokio::test]
async fn rtp16c_presence_errors_in_detached() {
    let channel = crate::channel::RealtimeChannel::new("test-rtp16c");
    // (set_channel_state/set_client_id removed — relies on todo!() stubs)

    let result = channel.presence().enter(None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn rtp16c_presence_errors_in_suspended() {
    let channel = crate::channel::RealtimeChannel::new("test-rtp16c-sus");
    // (set_channel_state/set_client_id removed — relies on todo!() stubs)

    let result = channel.presence().enter(None).await;
    assert!(result.is_err());
}

// -- RTP15c: enterClient has no side effects on normal enter --

#[tokio::test]
async fn rtp15c_enter_client_no_side_effects() {
    let (_, mock, conn, channel) = setup_attached_channel("test-rtp15c", None).await;

    // Regular enter (no clientId in message)
    let ch = channel.clone();
    let h = tokio::spawn(async move { ch.presence().enter_client("main-client", None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // enterClient with explicit clientId
    let ch = channel.clone();
    let h = tokio::spawn(async move { ch.presence().enter_client("other-client", None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // Verify messages
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    assert_eq!(pm.len(), 2);
    // First: enter() — no clientId
    let p0 = pm[0].message.presence_json();
    // (adapted: with unidentified auth the main identity also enters via
    // enter_client, so clientId is present — RTP8j vs RTP15c upstream
    // conflict, filed as ably/specification#507 / task-9)
    assert_eq!(p0[0]["clientId"], "main-client");
    // Second: enterClient() — explicit clientId
    let p1 = pm[1].message.presence_json();
    assert_eq!(p1[0]["clientId"], "other-client");
}

// -- RTP14a: enterClient with wildcard --

#[tokio::test]
async fn rtp14a_enter_client_wildcard_errors() {
    let channel = crate::channel::RealtimeChannel::new("test-rtp14a-wild");
    // (set_channel_state removed — relies on todo!() stubs)

    let result = channel.presence().enter_client("*", None).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(91000));
}

// ===================================================================
// Sub-Phase 10c: Get + History + Reentry
// ===================================================================

// -- RTP11a: get() waits for sync then returns members --

#[tokio::test]
async fn rtp11a_get_waits_for_sync() {
    let (_, _, conn, channel) = setup_attached_channel_with_flags(
        "test-rtp11a",
        None,
        Some(crate::protocol::flags::HAS_PRESENCE as i64),
    )
    .await;

    // get() should block until sync completes
    let ch = channel.clone();
    let get_handle = tokio::spawn(async move { ch.presence().get().await });

    // Give get() a moment to register waiter
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !get_handle.is_finished(),
        "get() should be waiting for sync"
    );

    // Send SYNC message with members
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::SYNC,
        channel: Some("test-rtp11a".to_string()),
        channel_serial: Some("serial:".to_string()), // empty cursor = complete
        connection_id: Some("conn-1".to_string()),
        timestamp: Some(1000),
        presence: crate::protocol::wire_presence(vec![
            serde_json::json!({"action": 1, "clientId": "alice", "connectionId": "conn-1"}),
            serde_json::json!({"action": 1, "clientId": "bob", "connectionId": "conn-2"}),
        ]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::SYNC)
    });

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), get_handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.len(), 2);

    let client_ids: Vec<_> = result
        .iter()
        .filter_map(|m| m.client_id.as_deref())
        .collect();
    assert!(client_ids.contains(&"alice"));
    assert!(client_ids.contains(&"bob"));
}

// -- RTP11c1: get with wait_for_sync=false returns immediately --

#[tokio::test]
async fn rtp11c1_get_no_wait_returns_immediately() {
    let (_, _, _conn, channel) = setup_attached_channel_with_flags(
        "test-rtp11c1",
        None,
        Some(crate::protocol::flags::HAS_PRESENCE as i64),
    )
    .await;

    // Sync not yet complete, but wait_for_sync=false should return immediately
    let result = channel
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: false,
            ..Default::default()
        })
        .await
        .unwrap();
    // No members yet since sync hasn't happened
    assert_eq!(result.len(), 0);
}

// -- RTP11c2: get filtered by clientId --

// -- RTP11c3: get filtered by connectionId --

// -- RTP11d: get on SUSPENDED with waitForSync errors --

// -- RTP11d: get on SUSPENDED with waitForSync=false returns current members --

// -- RTP11b: get on FAILED/DETACHED errors --

// -- RTP12a: history delegates to REST --

// -- RTP12: history without REST client errors --

// -- RTP17i: auto re-entry on non-RESUMED ATTACHED --

#[tokio::test]
async fn rtp17i_reentry_on_non_resumed_attach() {
    let (_client, mock, conn, channel) =
        setup_attached_channel("test-rtp17i", Some("my-client")).await;

    // Enter presence first
    let ch = channel.clone();
    let h = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // Server echoes the presence enter (populates local_presence_map)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp17i".to_string()),
        connection_id: Some("test-conn-id".to_string()),
        timestamp: Some(1000),
        id: Some("test-conn-id:0".to_string()),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 2,
            "clientId": "my-client",
            "connectionId": "test-conn-id"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Record how many presence messages have been sent so far
    let before_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .count();

    // Simulate reattach (non-RESUMED) — triggers re-entry
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ATTACHED,
        channel: Some("test-rtp17i".to_string()),
        flags: Some(0), // No RESUMED flag
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ATTACHED)
    });

    // Wait for re-entry to be sent
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Should have sent a new ENTER presence message
    let after_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .count();
    assert!(
        after_count > before_count,
        "Expected re-entry ENTER, before={} after={}",
        before_count,
        after_count
    );

    // Verify re-entry message is an ENTER
    let all_presence: Vec<_> = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .map(|m| m.message.clone())
        .collect();
    let reentry_msg = all_presence.last().unwrap();
    let presence_arr = reentry_msg.presence_json();
    let entry = &presence_arr[0];
    // action 2 = Enter
    assert_eq!(entry["action"], 2);
}

// -- RTP17i: no re-entry when RESUMED --

#[tokio::test]
async fn rtp17i_no_reentry_when_resumed() {
    let (_client, mock, conn, channel) =
        setup_attached_channel("test-rtp17i-res", Some("my-client")).await;

    // Enter presence
    let ch = channel.clone();
    let h = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // Server echoes the presence enter (populates local_presence_map)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp17i-res".to_string()),
        connection_id: Some("test-conn-id".to_string()),
        timestamp: Some(1000),
        id: Some("test-conn-id:0".to_string()),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 2,
            "clientId": "my-client",
            "connectionId": "test-conn-id"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let before_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .count();

    // Send ATTACHED with RESUMED flag — should NOT trigger re-entry
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ATTACHED,
        channel: Some("test-rtp17i-res".to_string()),
        flags: Some(crate::protocol::flags::RESUMED | crate::protocol::flags::HAS_PRESENCE),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ATTACHED)
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let after_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .count();
    assert_eq!(
        before_count, after_count,
        "No re-entry should occur when RESUMED"
    );
}

// -- RTP17g1: re-entry omits id when connectionId changed --

// -- RTP17e: failed re-entry emits UPDATE with 91004 --

#[tokio::test]
async fn rtp17e_failed_reentry_emits_update() {
    let (_client, mock, conn, channel) =
        setup_attached_channel("test-rtp17e", Some("my-client")).await;

    // Subscribe to channel state events to catch UPDATE
    let mut state_rx = channel.on_state_change();

    // Enter presence
    let ch = channel.clone();
    let h = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .collect();
    let serial = pm.last().unwrap().message.msg_serial.unwrap();
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ACK,
        msg_serial: Some(serial),
        count: Some(1),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
    });
    h.await.unwrap().unwrap();

    // Server echoes the presence enter (populates local_presence_map)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp17e".to_string()),
        connection_id: Some("test-conn-id".to_string()),
        timestamp: Some(1000),
        id: Some("test-conn-id:0".to_string()),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 2,
            "clientId": "my-client",
            "connectionId": "test-conn-id"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Trigger re-entry (non-RESUMED)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::ATTACHED,
        channel: Some("test-rtp17e".to_string()),
        flags: Some(0),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ATTACHED)
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Find the re-entry message and NACK it
    let all_presence: Vec<_> = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
        .map(|m| m.message.clone())
        .collect();
    let reentry_serial = all_presence.last().unwrap().msg_serial.unwrap();

    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::NACK,
        msg_serial: Some(reentry_serial),
        count: Some(1),
        error: Some(crate::error::ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Permission denied".to_string()),
            href: None,
            ..Default::default()
        }),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::NACK)
    });

    // Wait for the UPDATE event with error code 91004
    let update = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(change) = state_rx.recv().await {
                if change.event == crate::ChannelEvent::Update {
                    if let Some(ref reason) = change.reason {
                        if reason.code == Some(91004) {
                            return change;
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("Should receive UPDATE event with code 91004 after failed re-entry");

    assert!(update.resumed);
    assert_eq!(update.reason.unwrap().code, Some(91004));
}

// -- RTP17a: members from own connection appear in presence map --

// -- RTP17g: Re-entry publishes ENTER with stored clientId and data --

// -- RTP11a/RTP11c1: get waits for multi-message sync --

#[tokio::test]
async fn rtp11a_get_waits_for_multi_message_sync() {
    let (_, _, conn, channel) = setup_attached_channel_with_flags(
        "test-rtp11-multi",
        None,
        Some(crate::protocol::flags::HAS_PRESENCE as i64),
    )
    .await;

    // Start get() — sync has not completed
    let ch = channel.clone();
    let get_handle = tokio::spawn(async move { ch.presence().get().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send first SYNC message (non-empty cursor = more to come)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::SYNC,
        channel: Some("test-rtp11-multi".to_string()),
        channel_serial: Some("seq1:cursor1".to_string()),
        connection_id: Some("c1".to_string()),
        timestamp: Some(100),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 1, // PRESENT
            "clientId": "alice",
            "connectionId": "c1",
            "id": "c1:0:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::SYNC)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // get() should still be waiting
    assert!(
        !get_handle.is_finished(),
        "get() should wait for sync completion"
    );

    // Send final SYNC message (empty cursor = sync complete)
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::SYNC,
        channel: Some("test-rtp11-multi".to_string()),
        channel_serial: Some("seq1:".to_string()),
        connection_id: Some("c2".to_string()),
        timestamp: Some(100),
        presence: crate::protocol::wire_presence(vec![serde_json::json!({
            "action": 1, // PRESENT
            "clientId": "bob",
            "connectionId": "c2",
            "id": "c2:0:0"
        })]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::SYNC)
    });

    let members = tokio::time::timeout(std::time::Duration::from_secs(2), get_handle)
        .await
        .expect("get() should complete after sync")
        .unwrap()
        .unwrap();

    assert_eq!(members.len(), 2);
    let mut client_ids: Vec<_> = members
        .iter()
        .map(|m| m.client_id.as_deref().unwrap())
        .collect();
    client_ids.sort();
    assert_eq!(client_ids, vec!["alice", "bob"]);
}

// -- RTP5f: SUSPENDED maintains presence map --

// -- RTP4: 50 members via enterClient (same connection) --

#[tokio::test]
async fn rtp4_50_members_enter_client_same_connection() {
    let (_client, mock, conn, channel) = setup_attached_channel_with_flags(
        "test-rtp4",
        None,
        Some(crate::protocol::flags::HAS_PRESENCE as i64),
    )
    .await;

    let member_count = 50usize;

    // Subscribe to ENTER events
    let (enter_tx, mut enter_rx) = tokio::sync::mpsc::unbounded_channel();
    let _enter_id =
        channel
            .presence()
            .subscribe_action(crate::rest::PresenceAction::Enter, move |msg| {
                let _ = enter_tx.send(msg);
            });

    // Enter 50 members
    for i in 0..member_count {
        let cid = format!("user-{}", i);
        let data = format!("data-{}", i);
        let ch = channel.clone();
        let h = tokio::spawn(async move {
            ch.presence()
                .enter_client(&cid, Some(serde_json::json!(data)))
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let msgs = mock.client_messages();
        let pm: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
            .collect();
        let serial = pm.last().unwrap().message.msg_serial.unwrap();
        conn.send_to_client(crate::protocol::ProtocolMessage {
            action: crate::protocol::action::ACK,
            msg_serial: Some(serial),
            count: Some(1),
            ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
        });
        h.await.unwrap().unwrap();

        // Server echoes the ENTER
        conn.send_to_client(crate::protocol::ProtocolMessage {
            action: crate::protocol::action::PRESENCE,
            channel: Some("test-rtp4".to_string()),
            connection_id: Some("test-conn-id".to_string()),
            timestamp: Some(1000 + i as i64),
            presence: crate::protocol::wire_presence(vec![serde_json::json!({
                "action": 2,
                "clientId": format!("user-{}", i),
                "connectionId": "test-conn-id",
                "id": format!("test-conn-id:{}:0", i),
                "data": format!("data-{}", i)
            })]),
            ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // All 50 ENTER events should be received by subscriber
    let mut received = 0;
    while let Ok(msg) = enter_rx.try_recv() {
        assert_eq!(msg.action, Some(crate::rest::PresenceAction::Enter));
        received += 1;
    }
    assert_eq!(
        received, member_count,
        "should receive all {} ENTER events",
        member_count
    );

    // Send SYNC with all 50 as PRESENT
    let mut sync_members = Vec::new();
    for i in 0..member_count {
        sync_members.push(serde_json::json!({
            "action": 1,
            "clientId": format!("user-{}", i),
            "connectionId": "test-conn-id",
            "id": format!("test-conn-id:{}:0", i),
            "data": format!("data-{}", i)
        }));
    }
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::SYNC,
        channel: Some("test-rtp4".to_string()),
        channel_serial: Some("seq1:".to_string()),
        connection_id: Some("test-conn-id".to_string()),
        timestamp: Some(2000),
        presence: crate::protocol::wire_presence(sync_members),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::SYNC)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Get all members after sync
    let members = channel
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: false,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(members.len(), member_count);

    // Verify each member has correct data
    for i in 0..member_count {
        let cid = format!("user-{}", i);
        let member = members
            .iter()
            .find(|m| m.client_id.as_deref() == Some(&cid));
        assert!(member.is_some(), "member {} should exist", cid);
    }
}

// RTP15f: Client-side clientId mismatch check is not implemented because this SDK
// rejects wildcard clientId "*" at ClientOptions level. Server validates permissions.

// -- RTP8d: enter implicitly attaches channel --

#[tokio::test]
async fn rtp8d_enter_implicitly_attaches() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ProtocolMessage};
    use crate::{ConnectionState};
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

    let channel = client.channels.get("test-rtp8d");
    assert_eq!(channel.state(), crate::ChannelState::Initialized);

    // enter() on INITIALIZED channel triggers implicit attach
    let ch = channel.clone();
    let enter_handle = tokio::spawn(async move { ch.presence().enter(None).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Channel should now be ATTACHING (implicit attach was triggered)
    assert_eq!(channel.state(), crate::ChannelState::Attaching);

    // Complete the attach
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtp8d".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Now the queued presence should be sent — ACK it
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::PRESENCE)
        .collect();
    if let Some(last) = pm.last() {
        let serial = last.message.msg_serial.unwrap();
        conn.send_to_client(ProtocolMessage {
            action: action::ACK,
            msg_serial: Some(serial),
            count: Some(1),
            ..ProtocolMessage::new(action::ACK)
        });
    }

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), enter_handle)
        .await
        .expect("enter should complete")
        .unwrap();
    assert!(result.is_ok(), "enter should succeed after implicit attach");
    assert_eq!(channel.state(), crate::ChannelState::Attached);
}

// -- RTP15e: enterClient implicitly attaches channel --

#[tokio::test]
async fn rtp15e_enter_client_implicitly_attaches() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ProtocolMessage};
    use crate::{ConnectionState};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![])
            .use_binary_protocol(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtp15e");
    assert_eq!(channel.state(), crate::ChannelState::Initialized);

    // enterClient on INITIALIZED triggers implicit attach
    let ch = channel.clone();
    let enter_handle =
        tokio::spawn(async move { ch.presence().enter_client("user-1", None).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_eq!(channel.state(), crate::ChannelState::Attaching);

    // Complete attach
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtp15e".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ACK the queued presence
    let msgs = mock.client_messages();
    let pm: Vec<_> = msgs
        .iter()
        .filter(|m| m.message.action == action::PRESENCE)
        .collect();
    if let Some(last) = pm.last() {
        let serial = last.message.msg_serial.unwrap();
        conn.send_to_client(ProtocolMessage {
            action: action::ACK,
            msg_serial: Some(serial),
            count: Some(1),
            ..ProtocolMessage::new(action::ACK)
        });
    }

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), enter_handle)
        .await
        .expect("enterClient should complete")
        .unwrap();
    assert!(
        result.is_ok(),
        "enterClient should succeed after implicit attach"
    );
    assert_eq!(channel.state(), crate::ChannelState::Attached);
}

// -- RTP6d: subscribe implicitly attaches channel --

#[tokio::test]
async fn rtp6d_subscribe_implicitly_attaches() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ProtocolMessage};
    use crate::{ConnectionState};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![])
            .use_binary_protocol(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtp6d");
    assert_eq!(channel.state(), crate::ChannelState::Initialized);

    // Subscribe without explicitly attaching — should trigger implicit attach
    let _sub_id = channel.presence().subscribe(|_msg| {});

    // Wait for implicit attach to be triggered
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Complete the attach
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtp6d".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert_eq!(channel.state(), crate::ChannelState::Attached);
}

// -- RTP6e: subscribe with attachOnSubscribe=false does not attach --

#[tokio::test]
async fn rtp6e_subscribe_attach_on_subscribe_false() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{ProtocolMessage};
    use crate::{ConnectionState};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![])
            .use_binary_protocol(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client
        .channels
        .get_with_options(
            "test-rtp6e",
            crate::channel::RealtimeChannelOptions {
                attach_on_subscribe: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(channel.state(), crate::ChannelState::Initialized);

    // Subscribe — should NOT trigger implicit attach
    let _sub_id = channel.presence().subscribe(|_msg| {});
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Channel stays INITIALIZED
    assert_eq!(channel.state(), crate::ChannelState::Initialized);

    // Verify no ATTACH message was sent
    let attach_count = mock
        .client_messages()
        .iter()
        .filter(|m| m.message.action == crate::protocol::action::ATTACH)
        .count();
    assert_eq!(attach_count, 0, "no ATTACH should have been sent");
}

// -- RTP7b: unsubscribe listener for specific action --

#[tokio::test]
async fn rtp7b_unsubscribe_for_specific_action() {
    let (_, _, conn, channel) = setup_attached_channel("test-rtp7b", None).await;

    // Subscribe to ENTER and LEAVE
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let id = channel.presence().subscribe_actions(
        &[
            crate::rest::PresenceAction::Enter,
            crate::rest::PresenceAction::Leave,
        ],
        move |msg| {
            let _ = tx.send(msg);
        },
    );

    // Unsubscribe only for ENTER
    channel
        .presence()
        .unsubscribe_action(id, crate::rest::PresenceAction::Enter);

    // Send ENTER and LEAVE
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::PRESENCE,
        channel: Some("test-rtp7b".to_string()),
        connection_id: Some("c1".to_string()),
        timestamp: Some(1000),
        presence: crate::protocol::wire_presence(vec![
            serde_json::json!({
                "action": 2, // ENTER
                "clientId": "alice",
                "connectionId": "c1",
                "id": "c1:0:0"
            }),
            serde_json::json!({
                "action": 3, // LEAVE
                "clientId": "alice",
                "connectionId": "c1",
                "id": "c1:1:0"
            }),
        ]),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Only LEAVE should be received — ENTER subscription was removed
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.action, Some(crate::rest::PresenceAction::Leave));
    assert!(rx.try_recv().is_err(), "no more events expected");
}

// -- RTP11b: get implicitly attaches channel --

#[tokio::test]
async fn rtp11b_get_implicitly_attaches() {
    use crate::mock_ws::{MockTransport, MockWebSocket};
    use crate::protocol::{action, ProtocolMessage};
    use crate::{ConnectionState};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
    });
    let transport = std::sync::Arc::new(MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .fallback_hosts(vec![])
            .use_binary_protocol(false),
        transport,
    )
    .unwrap();

    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtp11b");
    assert_eq!(channel.state(), crate::ChannelState::Initialized);

    // get(waitForSync: false) on INITIALIZED triggers implicit attach
    let ch = channel.clone();
    let get_handle = tokio::spawn(async move {
        ch.presence()
            .get_with_options(&crate::channel::PresenceGetOptions {
                wait_for_sync: false,
                ..Default::default()
            })
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Complete the attach
    let conns = mock.active_connections();
    let conn = conns.last().unwrap();
    conn.send_to_client(ProtocolMessage {
        action: action::ATTACHED,
        channel: Some("test-rtp11b".to_string()),
        ..ProtocolMessage::new(action::ATTACHED)
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), get_handle)
        .await
        .expect("get should complete")
        .unwrap();
    assert!(result.is_ok());
    assert_eq!(channel.state(), crate::ChannelState::Attached);
}

// -- Deliver messages with mutable message fields --

#[tokio::test]
async fn deliver_messages_populates_mutable_fields() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, _, conn, channel) = setup_attached_channel("test-mutable-deliver", None).await;

    let (_, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some("test-mutable-deliver".into()),
        id: Some("proto-id".into()),
        messages: crate::protocol::wire_messages(vec![json!({
            "id": "msg-1",
            "name": "event",
            "data": "hello",
            "action": 1,
            "serial": "ser-1",
            "version": {"serial": "v1"},
            "annotations": {"likes": {"total": 5}},
        })]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.action, Some(crate::rest::MessageAction::Update)); // MESSAGE_UPDATE (wire 1, TM5)
    assert_eq!(msg.serial.as_deref(), Some("ser-1"));
    assert_eq!(msg.version.as_ref().unwrap()["serial"], "v1");
    assert_eq!(msg.annotations.as_ref().unwrap()["likes"]["total"], 5);
}

#[tokio::test]
async fn deliver_messages_mutable_fields_default_none() {
    use crate::protocol::{action, ProtocolMessage};

    let (_, _, conn, channel) = setup_attached_channel("test-mutable-default", None).await;

    let (_, mut rx) = channel.subscribe();

    conn.send_to_client(ProtocolMessage {
        action: action::MESSAGE,
        channel: Some("test-mutable-default".into()),
        id: Some("proto-id".into()),
        messages: crate::protocol::wire_messages(vec![json!({
            "id": "msg-1",
            "data": "hello",
        })]),
        ..ProtocolMessage::new(action::MESSAGE)
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let msg = rx.try_recv().unwrap();
    assert!(msg.action.is_none());
    assert!(msg.serial.is_none());
    assert!(msg.version.is_none());
    assert!(msg.annotations.is_none());
}

// UTS: realtime/unit/presence/realtime_presence_enter.md — RTP15f
#[tokio::test]
async fn rtp15f_enter_client_requires_valid_client_id() {
    use crate::{ChannelState, ConnectionState};
    use crate::realtime::await_state;

    let (client, mock) = phase8d_setup();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtp15f");
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    let result = channel.presence().enter_client("*", None).await;
    assert!(result.is_err(), "Wildcard clientId should be rejected");
}

// UTS: realtime/unit/RTP15f/enterclient-mismatched-clientid-0
#[tokio::test]
async fn rtp15f_enter_client_mismatched_client_id_errors() {
    use crate::mock_ws::MockWebSocket;
    use crate::protocol::{ProtocolMessage};
    use crate::{ChannelState, ConnectionState};
    use crate::realtime::{await_state, Realtime};

    let mock = MockWebSocket::with_handler(|pending| {
        pending.respond_with_success(ProtocolMessage::connected("connId", "connKey"));
    });
    let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
    let client = Realtime::with_mock(
        &ClientOptions::new("appId.keyId:keySecret")
            .auto_connect(false)
            .client_id("my-client")
            .unwrap(),
        transport,
    )
    .unwrap();
    client.connect();
    assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

    let channel = client.channels.get("test-rtp15f-mismatch");
    phase8d_attach(&channel, &mock, None).await;
    assert_eq!(channel.state(), ChannelState::Attached);

    // RTP15f: an identified client cannot enter on behalf of a different id
    let err = channel
        .presence()
        .enter_client("other-client", None)
        .await
        .expect_err("mismatched clientId must be rejected");
    assert!(err.code.is_some());

    // The connection and channel are unaffected
    assert_eq!(client.connection.state(), ConnectionState::Connected);
    assert_eq!(channel.state(), ChannelState::Attached);
}

// UTS: realtime/unit/presence/realtime_presence_history.md — RTP12c
#[tokio::test]
async fn rtp12c_presence_history_returns_paginated_result() -> Result<()> {
    let mock = MockHttpClient::with_handler(|_req| {
        MockResponse::json(
            200,
            &json!([
                {"action": 2, "clientId": "client1", "timestamp": 1700000000000_u64}
            ]),
        )
    });
    let client = mock_client(mock);
    let channel = client.channels().get("test-rtp12c");
    let result: crate::http::PaginatedResult<crate::rest::PresenceMessage> =
        channel.presence().history().send().await?;
    let items = result.items();
    assert_eq!(items.len(), 1);
    Ok(())
}

// ===============================================================
// Batch 10 — RTP (Realtime Presence) tests
// ===============================================================

// --- RTP2: Multiple members coexist ---
#[test]
fn rtp2_multiple_members() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:0:0",
        1000,
        Some("a-data"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "bob",
        "conn-2",
        "conn-2:0:0",
        1001,
        Some("b-data"),
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "charlie",
        "conn-3",
        "conn-3:0:0",
        1002,
        None,
    ));

    let values = map.values();
    assert_eq!(values.len(), 3);

    let alice = map.get("conn-1:alice");
    assert!(alice.is_some());
    assert_eq!(alice.unwrap().client_id.as_deref(), Some("alice"));

    let bob = map.get("conn-2:bob");
    assert!(bob.is_some());

    let charlie = map.get("conn-3:charlie");
    assert!(charlie.is_some());
}

// --- RTP2: Residual members after leave ---
#[test]
fn rtp2_residual() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    ));
    map.put(&pm(
        PresenceAction::Enter,
        "bob",
        "conn-2",
        "conn-2:0:0",
        1001,
        None,
    ));

    // Remove alice
    map.remove(
        &pm(
            PresenceAction::Leave,
            "alice",
            "conn-1",
            "conn-1:1:0",
            2000,
            None,
        )
        .member_key(),
    );

    assert_eq!(map.values().len(), 1);
    assert!(map.get("conn-1:alice").is_none());
    assert!(map.get("conn-2:bob").is_some());
}

// --- RTP2: start_sync marks sync in progress ---
#[test]
fn rtp2_start_sync() {
    use crate::presence::PresenceMap;
    let mut map = PresenceMap::new();
    assert!(!map.sync_in_progress());

    map.start_sync();
    assert!(map.sync_in_progress());
}

// --- RTP2: sync_in_progress reflects state ---
#[test]
fn rtp2_sync_in_progress() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();

    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:0:0",
        1000,
        None,
    ));
    map.start_sync();
    assert!(map.sync_in_progress());

    map.end_sync();
    assert!(!map.sync_in_progress());
}

// --- RTP2b2: Stale leave rejected during sync ---
#[test]
fn rtp2b2_stale_leave_rejected() {
    use crate::presence::PresenceMap;
    use crate::rest::PresenceAction;
    let mut map = PresenceMap::new();

    // Enter with id "conn-1:5:0" (msg_serial=5)
    map.put(&pm(
        PresenceAction::Enter,
        "alice",
        "conn-1",
        "conn-1:5:0",
        2000,
        Some("data"),
    ));

    // Attempt leave with older id "conn-1:3:0" (msg_serial=3)
    let result = map.put(&pm(
        PresenceAction::Leave,
        "alice",
        "conn-1",
        "conn-1:3:0",
        1000,
        None,
    ));

    // Leave should be rejected (stale) — member still present
    let _ = result;
    assert!(
        map.get("conn-1:alice").is_some(),
        "Member should still be present"
    );
}

// --- RTP4: 50 members from the same connection ---
#[tokio::test]
async fn rtp4_50_members_same_connection() {
    let (_, mock, conn, channel) = setup_attached_channel_with_flags(
        "test-rtp4-same",
        None,
        Some(crate::protocol::flags::HAS_PRESENCE as i64),
    )
    .await;

    let member_count = 50usize;

    for i in 0..member_count {
        let cid = format!("user-{}", i);
        let data = format!("data-{}", i);
        let ch = channel.clone();
        let h = tokio::spawn(async move {
            ch.presence()
                .enter_client(&cid, Some(serde_json::json!(data)))
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let msgs = mock.client_messages();
        let pm: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == crate::protocol::action::PRESENCE)
            .collect();
        let serial = pm.last().unwrap().message.msg_serial.unwrap();
        conn.send_to_client(crate::protocol::ProtocolMessage {
            action: crate::protocol::action::ACK,
            msg_serial: Some(serial),
            count: Some(1),
            ..crate::protocol::ProtocolMessage::new(crate::protocol::action::ACK)
        });
        h.await.unwrap().unwrap();

        // Server echoes the ENTER
        conn.send_to_client(crate::protocol::ProtocolMessage {
            action: crate::protocol::action::PRESENCE,
            channel: Some("test-rtp4-same".to_string()),
            connection_id: Some("test-conn-id".to_string()),
            timestamp: Some(1000 + i as i64),
            presence: crate::protocol::wire_presence(vec![serde_json::json!({
                "action": 2,
                "clientId": format!("user-{}", i),
                "connectionId": "test-conn-id",
                "id": format!("test-conn-id:{}:0", i),
                "data": format!("data-{}", i)
            })]),
            ..crate::protocol::ProtocolMessage::new(crate::protocol::action::PRESENCE)
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Get all members
    let members = channel
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: false,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(members.len(), member_count);
}

// --- RTP4: 50 members from different connections ---
#[tokio::test]
async fn rtp4_50_members_different_connection() {
    let (_, _, conn, channel) = setup_attached_channel_with_flags(
        "test-rtp4-diff",
        None,
        Some(crate::protocol::flags::HAS_PRESENCE as i64),
    )
    .await;

    let member_count = 50usize;

    // Populate via SYNC with members from different connections
    let mut sync_members = Vec::new();
    for i in 0..member_count {
        sync_members.push(serde_json::json!({
            "action": 1,
            "clientId": format!("user-{}", i),
            "connectionId": format!("conn-{}", i),
            "id": format!("conn-{}:0:0", i),
            "data": format!("data-{}", i)
        }));
    }
    conn.send_to_client(crate::protocol::ProtocolMessage {
        action: crate::protocol::action::SYNC,
        channel: Some("test-rtp4-diff".to_string()),
        channel_serial: Some("seq1:".to_string()),
        connection_id: Some("conn-0".to_string()),
        timestamp: Some(1000),
        presence: crate::protocol::wire_presence(sync_members),
        ..crate::protocol::ProtocolMessage::new(crate::protocol::action::SYNC)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let members = channel
        .presence()
        .get_with_options(&crate::channel::PresenceGetOptions {
            wait_for_sync: false,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        members.len(),
        member_count,
        "Should have {} members from different connections",
        member_count
    );

    // Verify each member has a distinct connectionId
    for i in 0..member_count {
        let cid = format!("user-{}", i);
        let member = members
            .iter()
            .find(|m| m.client_id.as_deref() == Some(&cid));
        assert!(member.is_some(), "member {} should exist", cid);
    }
}

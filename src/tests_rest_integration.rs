use tokio::sync::OnceCell;

use crate::auth::TokenParams;
use crate::options::ClientOptions;
use crate::rest::{Data, Message, PresenceAction, Rest, RevokeTokensRequest};

// The UTS-mandated sandbox: endpoint "nonprod:sandbox" (REC1b3)
const SANDBOX_URL: &str = "https://sandbox.realtime.ably-nonprod.net";
const TEST_APP_SETUP: &str =
    include_str!("../submodules/ably-common/test-resources/test-app-setup.json");

pub(crate) struct SandboxApp {
    pub(crate) app_id: String,
    keys: Vec<SandboxKey>,
}

#[derive(Clone)]
struct SandboxKey {
    key_str: String,
}

impl SandboxApp {
    async fn provision() -> Self {
        let setup: serde_json::Value = serde_json::from_str(TEST_APP_SETUP).unwrap();
        let post_body = &setup["post_apps"];

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/apps", SANDBOX_URL))
            .json(post_body)
            .send()
            .await
            .expect("Failed to provision sandbox app");

        assert!(
            resp.status().is_success(),
            "Sandbox provisioning failed: {}",
            resp.status()
        );

        let body: serde_json::Value = resp.json().await.unwrap();
        let app_id = body["appId"].as_str().unwrap().to_string();
        let keys: Vec<SandboxKey> = body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| SandboxKey {
                key_str: k["keyStr"].as_str().unwrap().to_string(),
            })
            .collect();

        SandboxApp { app_id, keys }
    }

    pub(crate) fn full_access_key(&self) -> &str {
        &self.keys[0].key_str
    }

    /// keys[4] has revocableTokens: true (required for /revokeTokens)
    fn revocable_key(&self) -> &str {
        &self.keys[4].key_str
    }

    pub(crate) fn restricted_key(&self) -> &str {
        &self.keys[2].key_str
    }

    pub(crate) fn subscribe_only_key(&self) -> &str {
        &self.keys[3].key_str
    }
}

/// A sandbox client using the SDK-default MessagePack wire format, so the
/// binary protocol is exercised across the whole integration suite. Explicit
/// JSON-variant tests use sandbox_client_json.
fn sandbox_client(key: &str) -> Rest {
    ClientOptions::new(key)
        .endpoint("nonprod:sandbox")
        .unwrap()
        .rest()
        .unwrap()
}

/// JSON-protocol variant (UTS runs protocol-sensitive tests in both formats).
fn sandbox_client_json(key: &str) -> Rest {
    ClientOptions::new(key)
        .endpoint("nonprod:sandbox")
        .unwrap()
        .use_binary_protocol(false)
        .rest()
        .unwrap()
}

static SANDBOX: OnceCell<SandboxApp> = OnceCell::const_new();

pub(crate) async fn get_sandbox() -> &'static SandboxApp {
    SANDBOX
        .get_or_init(|| async {
            let app = SandboxApp::provision().await;
            register_sandbox_teardown(&app);
            app
        })
        .await
}

/// (app_id, key_name, key_secret) for the atexit teardown.
static TEARDOWN_APP: std::sync::OnceLock<(String, String, String)> = std::sync::OnceLock::new();

/// Arrange for the provisioned sandbox app to be deleted when the test
/// process exits. The Rust test harness has no global teardown hook, so this
/// registers a libc::atexit handler; by the time it runs every tokio runtime
/// is gone, hence the blocking client in the handler.
fn register_sandbox_teardown(app: &SandboxApp) {
    let key = app.full_access_key();
    let (key_name, key_secret) = key.split_once(':').expect("key format");
    if TEARDOWN_APP
        .set((
            app.app_id.clone(),
            key_name.to_string(),
            key_secret.to_string(),
        ))
        .is_ok()
    {
        unsafe {
            libc::atexit(teardown_sandbox_app);
        }
    }
}

extern "C" fn teardown_sandbox_app() {
    let Some((app_id, key_name, key_secret)) = TEARDOWN_APP.get() else {
        return;
    };
    // Raw HTTP/1.1 over native-tls: no async runtime may be started inside an
    // atexit handler (reqwest's blocking client aborts the process here), and
    // a panic would abort too — so everything is explicit error handling.
    match delete_sandbox_app(app_id, key_name, key_secret) {
        Ok(status) if (200..300).contains(&status) => {
            eprintln!("sandbox teardown: deleted app {} ({})", app_id, status);
        }
        Ok(status) => {
            eprintln!(
                "sandbox teardown: DELETE /apps/{} returned {} (app is autodelete-labelled; \
                 the sandbox reaps it eventually)",
                app_id, status
            );
        }
        Err(e) => {
            eprintln!(
                "sandbox teardown: DELETE /apps/{} errored: {} (app is autodelete-labelled)",
                app_id, e
            );
        }
    }
}

/// Blocking DELETE /apps/{app_id} with basic key auth; returns the HTTP
/// status. ureq is purely blocking (no async runtime), so it is safe to
/// call inside an atexit handler.
fn delete_sandbox_app(
    app_id: &str,
    key_name: &str,
    key_secret: &str,
) -> std::result::Result<u16, String> {
    let auth = base64::encode(format!("{}:{}", key_name, key_secret));
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    match agent
        .delete(&format!("{}/apps/{}", SANDBOX_URL, app_id))
        .set("Authorization", &format!("Basic {}", auth))
        .call()
    {
        Ok(resp) => Ok(resp.status()),
        Err(ureq::Error::Status(status, _)) => Ok(status),
        Err(e) => Err(e.to_string()),
    }
}

pub(crate) fn random_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:08x}", rng.gen::<u32>())
}

// ============================================================================
// RSC16 - time() returns server time
// ============================================================================

// UTS: rest/integration/RSC16/time-returns-server-time-0
#[tokio::test]
async fn rsc16_time_returns_server_time() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let before = chrono::Utc::now();
    let server_time = client.time().await.unwrap();
    let after = chrono::Utc::now();

    let tolerance = chrono::Duration::seconds(5);
    assert!(
        server_time >= before - tolerance,
        "Server time {} is too far before client time {}",
        server_time,
        before
    );
    assert!(
        server_time <= after + tolerance,
        "Server time {} is too far after client time {}",
        server_time,
        after
    );
}

// ============================================================================
// RSC6 - stats()
// ============================================================================

// UTS: rest/integration/RSC6/stats-returns-result-0
#[tokio::test]
async fn rsc6_stats_returns_paginated_result() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let result = client.stats().send().await.unwrap();
    // Stats may be empty for a new sandbox app, but the call should succeed
    let _ = result.items();
}

/// Inject known statistics into the sandbox via the authenticated `POST /stats`
/// endpoint (specification G3). The body uses the *ingestion* shape (deeply
/// nested per-type), distinct from the flattened `entries` shape returned by a
/// read. `X-Ably-Version: 6` is required for the server to accept the request
/// and, on read-back, to return the flattened API.
async fn inject_stats(key: &str, fixtures: &serde_json::Value) {
    let (name, secret) = key.split_once(':').expect("key format");
    let resp = reqwest::Client::new()
        .post(format!("{}/stats", SANDBOX_URL))
        .header("X-Ably-Version", "6")
        .basic_auth(name, Some(secret))
        .json(fixtures)
        .send()
        .await
        .expect("stats injection request failed");
    assert!(
        resp.status().is_success(),
        "stats injection failed: {}",
        resp.status()
    );
}

// TS12 - stats() returns the flattened entries API (RSC6b4)
//
// Injects known datapoints for a fixed past interval, reads them back, and
// asserts the flattened round-trip: the ingested `inbound.realtime.messages`
// metrics surface under the `messages.inbound.realtime.messages.*` entries
// keys, alongside intervalId/unit/schema/appId. A read that silently fell back
// to the deprecated deep API (missing `X-Ably-Version: 6`, or an over-permissive
// `entries` deserialization) would yield empty entries and fail here.
//
// UTS: rest/integration/RSC6/stats-flattened-entries-2
#[tokio::test]
async fn rsc6_stats_flattened_entries() {
    use chrono::{Datelike, Utc};

    let app = get_sandbox().await;
    // A fixed interval in the previous year: stable, complete (never "in
    // progress"), and untouched by the live traffic other tests generate.
    let year = Utc::now().year() - 1;
    let fixtures = serde_json::json!([
        { "intervalId": format!("{year}-02-03:15:03"),
          "inbound":  { "realtime": { "messages": { "count": 50, "data": 5000 } } },
          "outbound": { "realtime": { "messages": { "count": 20, "data": 2000 } } } },
        { "intervalId": format!("{year}-02-03:15:04"),
          "inbound":  { "realtime": { "messages": { "count": 60, "data": 6000 } } },
          "outbound": { "realtime": { "messages": { "count": 10, "data": 1000 } } } },
        { "intervalId": format!("{year}-02-03:15:05"),
          "inbound":  { "realtime": { "messages": { "count": 70, "data": 7000 } } },
          "outbound": { "realtime": { "messages": { "count": 40, "data": 4000 } } } },
    ]);
    inject_stats(app.full_access_key(), &fixtures).await;

    let start = format!("{year}-02-03:15:03");
    let end = format!("{year}-02-03:15:05");
    let client = sandbox_client(app.full_access_key());

    // Injected stats can lag briefly; poll until all three intervals appear.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let items = loop {
        let items = client
            .stats()
            .forwards()
            .params(&[("start", start.as_str()), ("end", end.as_str())])
            .send()
            .await
            .unwrap()
            .items()
            .to_vec();
        if items.len() == 3 || std::time::Instant::now() >= deadline {
            break items;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    assert_eq!(items.len(), 3, "expected 3 injected minute datapoints");

    for (i, item) in items.iter().enumerate() {
        assert_eq!(item.interval_id, format!("{year}-02-03:15:0{}", i + 3));
        assert_eq!(item.unit, crate::stats::StatsIntervalGranularity::Minute);
        assert!(item.schema.is_some(), "schema (TS12s) should be present");
        assert!(item.app_id.is_some(), "appId (TS12t) should be present");
        assert!(item.interval_time().is_some(), "intervalId parses (TS12p)");
    }

    let entry = |key: &str| -> f64 {
        items
            .iter()
            .map(|s| s.entries.get(key).copied().unwrap_or(0.0))
            .sum()
    };
    assert_eq!(
        entry("messages.inbound.realtime.messages.count"),
        50.0 + 60.0 + 70.0,
        "flattened inbound message counts"
    );
    assert_eq!(
        entry("messages.outbound.realtime.messages.count"),
        20.0 + 10.0 + 40.0,
        "flattened outbound message counts"
    );
}

// UTS: rest/integration/RSC6/stats-with-parameters-1
#[tokio::test]
async fn rsc6_stats_with_parameters() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let result = client
        .stats()
        .limit(5)
        .forwards()
        .params(&[("unit", "hour")])
        .send()
        .await
        .unwrap();
    assert!(result.items().len() <= 5);
}

// ============================================================================
// RSA4 - Basic auth with API key
// ============================================================================

// UTS: rest/integration/RSA4/basic-auth-key-0
#[tokio::test]
async fn rsa4_basic_auth_succeeds() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("test-RSA4-{}", random_id());
    let result = client
        .request("GET", &format!("/channels/{}", channel_name))
        .send()
        .await
        .unwrap();
    assert!(
        result.status_code() >= 200 && result.status_code() < 300,
        "Expected 2xx, got {}",
        result.status_code()
    );
}

// UTS: rest/integration/RSA4/invalid-credentials-rejected-1
#[tokio::test]
async fn rsa4_invalid_credentials_rejected() {
    let app = get_sandbox().await;
    let invalid_key = format!("{}.invalidKey:invalidSecret", app.app_id);
    let client = sandbox_client(&invalid_key);

    let channel_name = format!("test-RSA4-invalid-{}", random_id());
    // request() surfaces HTTP errors as an inspectable response (HP4/HP5)
    let resp = client
        .request("GET", &format!("/channels/{}", channel_name))
        .send()
        .await
        .expect("request() must not error on HTTP error statuses");
    assert_eq!(resp.status_code(), 401);
    assert!(!resp.success());
    assert_eq!(
        resp.error_code(),
        Some(40400),
        "Expected 40400 (key not found)"
    );

    // A typed method propagates the same condition as an error
    let err = client
        .channels()
        .get(&channel_name)
        .history()
        .send()
        .await
        .expect_err("typed request must error for invalid key");
    assert_eq!(err.status_code, Some(401));
}

// ============================================================================
// RSA8 - Token auth with native token
// ============================================================================

// UTS: rest/integration/RSA8/token-auth-native-1
#[tokio::test]
async fn rsa8_native_token_auth() {
    let app = get_sandbox().await;
    let key_client = sandbox_client(app.full_access_key());

    let token_details = key_client.auth().request_token(None, None).await.unwrap();

    assert!(!token_details.token.is_empty());

    let token_client = sandbox_client(&token_details.token);
    let channel_name = format!("test-RSA8-native-{}", random_id());
    let result = token_client
        .request("GET", &format!("/channels/{}", channel_name))
        .send()
        .await
        .unwrap();
    assert!(
        result.status_code() >= 200 && result.status_code() < 300,
        "Token auth request failed: {}",
        result.status_code()
    );
}

// ============================================================================
// RSL1d - Error indication on publish failure
// ============================================================================

// UTS: rest/integration/RSL1d/publish-failure-error-0
#[tokio::test]
async fn rsl1d_publish_failure_error_indication() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.restricted_key());

    let channel_name = format!("forbidden-channel-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let err = channel
        .publish()
        .name("event")
        .string("data")
        .send()
        .await
        .unwrap_err();

    assert_eq!(
        err.code_value(),
        40160,
        "Expected 40160, got {}",
        err.code_value()
    );
    assert_eq!(err.status_code, Some(401));
}

// ============================================================================
// RSL1l1 - Publish params with _forceNack
// ============================================================================

// UTS: rest/integration/RSL1l1/publish-params-force-nack-0
#[tokio::test]
async fn rsl1l1_publish_params_force_nack() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("force-nack-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let err = channel
        .publish()
        .name("event")
        .string("data")
        .params(&[("_forceNack", "true")])
        .send()
        .await
        .unwrap_err();

    assert_eq!(
        err.code_value(),
        40099,
        "Expected 40099, got {}",
        err.code_value()
    );
}

// ============================================================================
// RSL1k5 - Idempotent publish with client-supplied IDs
// ============================================================================

// UTS: rest/integration/RSL1k5/idempotent-client-ids-0
#[tokio::test]
async fn rsl1k5_idempotent_publish_deduplication() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("idempotent-{}", random_id());
    let channel = client.channels().get(&channel_name);
    let fixed_id = format!("client-supplied-id-{}", random_id());

    for i in 1..=3 {
        channel
            .publish()
            .id(&fixed_id)
            .name("event")
            .string(format!("data-{}", i))
            .send()
            .await
            .unwrap();
    }

    // Poll history until the result is non-empty AND stable across two
    // consecutive reads — a single non-empty read could race the remaining
    // duplicates and mask broken deduplication
    let mut history_items = Vec::new();
    let mut last_len = usize::MAX;
    for _ in 0..20 {
        let result = channel.history().send().await.unwrap();
        let items = result.items().to_vec();
        if !items.is_empty() && items.len() == last_len {
            history_items = items;
            break;
        }
        last_len = items.len();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    assert_eq!(
        history_items.len(),
        1,
        "Expected exactly 1 message (deduplication)"
    );
    assert_eq!(history_items[0].id.as_deref(), Some(fixed_id.as_str()));
    // UTS RSL1k5: the FIRST publish wins
    assert!(
        matches!(history_items[0].data, Data::String(ref s) if s == "data-1"),
        "first-write-wins: expected data-1, got {:?}",
        history_items[0].data
    );
}

// ============================================================================
// Protocol variants — the suite default is MessagePack (the SDK default);
// these re-run the core round-trips over JSON (UTS protocol-variant runs)
// ============================================================================

#[tokio::test]
async fn rsl1_publish_history_roundtrip_json_protocol() {
    let app = get_sandbox().await;
    let client = sandbox_client_json(app.full_access_key());
    let channel_name = format!("json-proto-{}", random_id());
    let channel = client.channels().get(&channel_name);

    channel
        .publish()
        .name("str")
        .string("plain")
        .send()
        .await
        .unwrap();
    channel
        .publish()
        .name("json")
        .json(serde_json::json!({"k": "v"}))
        .send()
        .await
        .unwrap();
    channel
        .publish()
        .name("bin")
        .binary(vec![0u8, 1, 254, 255])
        .send()
        .await
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let items = loop {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 3 {
            break result.items().to_vec();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "history did not converge"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    // newest first
    assert!(matches!(items[0].data, Data::Binary(ref b) if b.as_ref() == [0u8, 1, 254, 255]));
    assert!(matches!(items[1].data, Data::JSON(ref v) if v["k"] == "v"));
    assert!(matches!(items[2].data, Data::String(ref s) if s == "plain"));
}

#[tokio::test]
async fn rsl1_binary_roundtrip_msgpack_protocol() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("msgpack-proto-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let payload = vec![0u8, 1, 2, 253, 254, 255];
    channel
        .publish()
        .name("bin")
        .binary(payload.clone())
        .send()
        .await
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let result = channel.history().send().await.unwrap();
        if !result.items().is_empty() {
            assert!(
                matches!(result.items()[0].data, Data::Binary(ref b) if b.as_ref() == payload.as_slice()),
                "native msgpack binary round-trip, got {:?}",
                result.items()[0].data
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "history did not converge"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

// ============================================================================
// RSL1m4 - ClientId mismatch rejection
// ============================================================================

// UTS: rest/integration/RSL1m4/clientid-mismatch-rejected-0
#[tokio::test]
async fn rsl1m4_client_id_mismatch_rejected() {
    let app = get_sandbox().await;
    let key_client = sandbox_client(app.full_access_key());

    let token_details = key_client
        .auth()
        .request_token(
            Some(&TokenParams::new().client_id("authenticated-client-id")),
            None,
        )
        .await
        .unwrap();

    let token_client = sandbox_client(&token_details.token);
    let channel_name = format!("clientid-mismatch-{}", random_id());
    let channel = token_client.channels().get(&channel_name);

    let err = channel
        .publish()
        .name("event")
        .string("data")
        .client_id("different-client-id")
        .send()
        .await
        .unwrap_err();

    assert_eq!(
        err.code_value(),
        40012,
        "Expected 40012, got {}",
        err.code_value()
    );
    assert_eq!(err.status_code, Some(400));
}

// ============================================================================
// RSL2a - History returns published messages
// ============================================================================

// UTS: rest/integration/RSL2a/history-returns-messages-0
#[tokio::test]
async fn rsl2a_history_returns_published_messages() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("history-test-RSL2a-{}", random_id());
    let channel = client.channels().get(&channel_name);

    channel
        .publish()
        .name("event1")
        .string("data1")
        .send()
        .await
        .unwrap();
    channel
        .publish()
        .name("event2")
        .string("data2")
        .send()
        .await
        .unwrap();
    channel
        .publish()
        .name("event3")
        .json(serde_json::json!({"key": "value"}))
        .send()
        .await
        .unwrap();

    // Poll until messages appear
    let mut items = Vec::new();
    for _ in 0..20 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 3 {
            items = result.items().to_vec();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    assert_eq!(items.len(), 3, "Expected 3 messages in history");

    // Default order is backwards (newest first)
    assert_eq!(items[0].name.as_deref(), Some("event3"));
    assert_eq!(items[1].name.as_deref(), Some("event2"));
    assert_eq!(items[2].name.as_deref(), Some("event1"));

    // RSL2a/UTS: payloads round-trip with their types intact
    assert!(
        matches!(items[0].data, Data::JSON(ref v) if v["key"] == "value"),
        "event3 data must decode to JSON, got {:?}",
        items[0].data
    );
    assert!(matches!(items[1].data, Data::String(ref s) if s == "data2"));
    assert!(matches!(items[2].data, Data::String(ref s) if s == "data1"));

    // All should have timestamps
    for msg in &items {
        assert!(msg.timestamp.is_some(), "Message should have a timestamp");
    }
}

// ============================================================================
// RSL2b1 - History direction forwards
// ============================================================================

// UTS: rest/integration/RSL2b1/history-direction-forwards-0
#[tokio::test]
async fn rsl2b1_history_direction_forwards() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("history-direction-{}", random_id());
    let channel = client.channels().get(&channel_name);

    channel
        .publish()
        .name("first")
        .string("1")
        .send()
        .await
        .unwrap();
    channel
        .publish()
        .name("second")
        .string("2")
        .send()
        .await
        .unwrap();
    channel
        .publish()
        .name("third")
        .string("3")
        .send()
        .await
        .unwrap();

    // Poll until all appear
    for _ in 0..20 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let result = channel.history().forwards().send().await.unwrap();
    assert_eq!(result.items().len(), 3);
    assert_eq!(result.items()[0].name.as_deref(), Some("first"));
    assert_eq!(result.items()[1].name.as_deref(), Some("second"));
    assert_eq!(result.items()[2].name.as_deref(), Some("third"));
}

// ============================================================================
// RSL2b2 - History limit parameter
// ============================================================================

// UTS: rest/integration/RSL2b2/history-limit-parameter-0
#[tokio::test]
async fn rsl2b2_history_limit() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("history-limit-{}", random_id());
    let channel = client.channels().get(&channel_name);

    for i in 1..=10 {
        channel
            .publish()
            .name(format!("event-{}", i))
            .string(i.to_string())
            .send()
            .await
            .unwrap();
    }

    // Poll until all persisted
    for _ in 0..20 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 10 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let result = channel.history().limit(5).send().await.unwrap();
    assert_eq!(result.items().len(), 5);

    // Most recent (backwards default)
    assert_eq!(result.items()[0].name.as_deref(), Some("event-10"));
    assert_eq!(result.items()[4].name.as_deref(), Some("event-6"));
}

// ============================================================================
// RSL2 - History on empty channel
// ============================================================================

// UTS: rest/integration/RSL2/history-empty-channel-0
#[tokio::test]
async fn rsl2_history_empty_channel() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("history-empty-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel.history().send().await.unwrap();
    assert!(result.items().is_empty());
    assert!(!result.has_next());
    assert!(result.is_last());
}

// ============================================================================
// TG1, TG2 - PaginatedResult items and navigation
// ============================================================================

// UTS: rest/integration/TG1/items-and-navigation-0
#[tokio::test]
async fn tg1_tg2_paginated_result_items_and_navigation() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("pagination-basic-{}", random_id());
    let channel = client.channels().get(&channel_name);

    for i in 1..=15 {
        channel
            .publish()
            .name(format!("event-{}", i))
            .string(i.to_string())
            .send()
            .await
            .unwrap();
    }

    // Poll until all persisted
    for _ in 0..30 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 15 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let page1 = channel.history().limit(5).send().await.unwrap();
    assert_eq!(page1.items().len(), 5); // TG1
    assert!(page1.has_next()); // TG2
    assert!(!page1.is_last()); // TG2
}

// ============================================================================
// TG3 - next() retrieves subsequent page
// ============================================================================

// UTS: rest/integration/TG3/next-retrieves-page-0
#[tokio::test]
async fn tg3_next_retrieves_subsequent_page() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("pagination-next-{}", random_id());
    let channel = client.channels().get(&channel_name);

    for i in 1..=12 {
        channel
            .publish()
            .name(format!("event-{}", i))
            .string(i.to_string())
            .send()
            .await
            .unwrap();
    }

    // Poll until all persisted
    for _ in 0..30 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 12 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let page1 = channel.history().limit(5).send().await.unwrap();
    assert_eq!(page1.items().len(), 5);
    let page1_ids: Vec<String> = page1.items().iter().filter_map(|m| m.id.clone()).collect();

    let page2 = page1.next().await.unwrap().unwrap();
    assert_eq!(page2.items().len(), 5);
    let page2_ids: Vec<String> = page2.items().iter().filter_map(|m| m.id.clone()).collect();

    let page3 = page2.next().await.unwrap().unwrap();
    assert_eq!(page3.items().len(), 2);
    let page3_ids: Vec<String> = page3.items().iter().filter_map(|m| m.id.clone()).collect();

    // Verify total count is 12 with no duplicates across all pages
    let mut all_ids: Vec<String> = Vec::new();
    for ids in [&page1_ids, &page2_ids, &page3_ids] {
        for id in ids {
            assert!(!all_ids.contains(id), "Duplicate message ID: {}", id);
            all_ids.push(id.clone());
        }
    }
    assert_eq!(all_ids.len(), 12);
}

// ============================================================================
// TG5 - Iterate through all pages
// ============================================================================

// UTS: rest/integration/TG5/iterate-all-pages-0
#[tokio::test]
async fn tg5_iterate_all_pages() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("pagination-iterate-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let message_count = 25;
    for i in 1..=message_count {
        channel
            .publish()
            .name(format!("event-{}", i))
            .string(i.to_string())
            .send()
            .await
            .unwrap();
    }

    // Poll until all persisted
    for _ in 0..60 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == message_count {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let mut all_messages: Vec<Message> = Vec::new();
    let mut page = channel.history().limit(7).send().await.unwrap();
    loop {
        all_messages.extend(page.items().to_vec());
        if !page.has_next() {
            break;
        }
        page = page.next().await.unwrap().unwrap();
    }

    assert_eq!(all_messages.len(), message_count);

    let event_names: Vec<String> = all_messages.iter().filter_map(|m| m.name.clone()).collect();
    for i in 1..=message_count {
        assert!(
            event_names.contains(&format!("event-{}", i)),
            "Missing event-{}",
            i
        );
    }
}

// ============================================================================
// TG3 - next() on last page returns null
// ============================================================================

// UTS: rest/integration/TG3/next-last-page-null-1
#[tokio::test]
async fn tg3_next_on_last_page_returns_null() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("pagination-lastnext-{}", random_id());
    let channel = client.channels().get(&channel_name);

    for i in 1..=3 {
        channel
            .publish()
            .name(format!("event-{}", i))
            .string(i.to_string())
            .send()
            .await
            .unwrap();
    }

    for _ in 0..20 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let page = channel.history().limit(10).send().await.unwrap();
    assert_eq!(page.items().len(), 3);
    assert!(!page.has_next());
    assert!(page.is_last());

    let next_page = page.next().await.unwrap();
    assert!(
        next_page.is_none(),
        "next() on last page should return None"
    );
}

// ============================================================================
// TG4 - first() retrieves first page
// ============================================================================

// UTS: rest/integration/TG4/first-retrieves-page-0
#[tokio::test]
async fn tg4_first_returns_to_first_page() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("pagination-first-{}", random_id());
    let channel = client.channels().get(&channel_name);

    for i in 1..=10 {
        channel
            .publish()
            .name(format!("event-{}", i))
            .string(i.to_string())
            .send()
            .await
            .unwrap();
    }

    for _ in 0..20 {
        let result = channel.history().send().await.unwrap();
        if result.items().len() == 10 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let page1 = channel.history().limit(3).send().await.unwrap();
    let page1_ids: Vec<String> = page1.items().iter().filter_map(|m| m.id.clone()).collect();

    let page2 = page1.next().await.unwrap().unwrap();
    let first_page = page2.first().await.unwrap().unwrap();

    assert_eq!(first_page.items().len(), page1_ids.len());
    let first_page_ids: Vec<String> = first_page
        .items()
        .iter()
        .filter_map(|m| m.id.clone())
        .collect();
    assert_eq!(first_page_ids, page1_ids);
}

// ============================================================================
// RSP1 - RestPresence accessible via channel
// ============================================================================

// UTS: rest/integration/RSP1/access-presence-from-channel-0
#[tokio::test]
async fn rsp1_presence_accessible_via_channel() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");
    let result = channel.presence().get().send().await.unwrap();
    assert!(
        result.items().len() >= 5,
        "Expected at least 5 presence fixtures"
    );
}

// ============================================================================
// RSP3 - RestPresence#get
// ============================================================================

// UTS: rest/integration/RSP3/get-presence-members-0
#[tokio::test]
async fn rsp3_get_presence_members() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");
    let result = channel.presence().get().send().await.unwrap();

    let client_ids: Vec<String> = result
        .items()
        .iter()
        .filter_map(|m| m.client_id.clone())
        .collect();

    assert!(client_ids.contains(&"client_bool".to_string()));
    assert!(client_ids.contains(&"client_string".to_string()));
    assert!(client_ids.contains(&"client_json".to_string()));
}

// UTS: rest/integration/RSP3/presence-message-fields-1
#[tokio::test]
async fn rsp3_presence_message_fields() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");
    let result = channel.presence().get().send().await.unwrap();

    let member = result
        .items()
        .iter()
        .find(|m| m.client_id.as_deref() == Some("client_string"))
        .expect("client_string member not found");

    assert_eq!(member.action, Some(PresenceAction::Present));
    assert_eq!(member.client_id.as_deref(), Some("client_string"));
    assert!(member.connection_id.is_some());

    match &member.data {
        Data::String(s) => assert_eq!(s, "This is a string clientData payload"),
        other => panic!("Expected string data, got {:?}", other),
    }
}

// ============================================================================
// RSP3a2 - Get with clientId filter
// ============================================================================

// UTS: rest/integration/RSP3a2/get-with-clientid-filter-0
#[tokio::test]
async fn rsp3a2_get_with_client_id_filter() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");
    let result = channel
        .presence()
        .get()
        .client_id("client_json")
        .send()
        .await
        .unwrap();

    assert_eq!(result.items().len(), 1);
    let member = &result.items()[0];
    assert_eq!(member.client_id.as_deref(), Some("client_json"));
    // UTS RSP3a2: the fixture's data has no encoding, so it must remain the
    // raw string — a decoder that spuriously JSON-parses it would fail here
    assert!(
        matches!(member.data, Data::String(_)),
        "unencoded presence data must stay a string, got {:?}",
        member.data
    );
}

// ============================================================================
// RSP3 - Get on empty channel
// ============================================================================

// UTS: rest/integration/RSP3/get-empty-channel-2
#[tokio::test]
async fn rsp3_empty_presence() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel_name = format!("presence-empty-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel.presence().get().send().await.unwrap();
    assert!(result.items().is_empty());
    assert!(!result.has_next());
}

// ============================================================================
// RSP3a1 - Get with limit parameter
// ============================================================================

// UTS: rest/integration/RSP3a1/get-with-limit-0
#[tokio::test]
async fn rsp3a1_get_with_limit() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");
    let result = channel.presence().get().limit(2).send().await.unwrap();

    assert!(result.items().len() <= 2);
    if result.has_next() {
        assert_eq!(result.items().len(), 2);
    }
}

// ============================================================================
// RSP3 - Full pagination through presence members
// ============================================================================

// UTS: rest/integration/RSP3/full-pagination-3
#[tokio::test]
async fn rsp3_full_pagination_through_members() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");

    let mut all_members = Vec::new();
    let mut page = channel.presence().get().limit(2).send().await.unwrap();
    loop {
        all_members.extend(page.items().to_vec());
        if !page.has_next() {
            break;
        }
        page = page.next().await.unwrap().unwrap();
    }

    assert!(
        all_members.len() >= 5,
        "Expected at least 5 fixture members"
    );

    // Verify no duplicates
    let client_ids: Vec<String> = all_members
        .iter()
        .filter_map(|m| m.client_id.clone())
        .collect();
    let unique_count = {
        let mut unique = client_ids.clone();
        unique.sort();
        unique.dedup();
        unique.len()
    };
    assert_eq!(
        unique_count,
        client_ids.len(),
        "Duplicate client IDs in pagination"
    );
}

// ============================================================================
// RSP3 - Invalid credentials rejected
// ============================================================================

// UTS: rest/integration/RSP3/invalid-credentials-rejected-4
#[tokio::test]
async fn rsp3_invalid_credentials_rejected() {
    let _app = get_sandbox().await;
    let client = sandbox_client("invalid.key:secret");

    match client.channels().get("test").presence().get().send().await {
        Err(err) => {
            assert_eq!(err.status_code, Some(401));
            assert!(err.code_value() >= 40100 && err.code_value() < 40200);
        }
        Ok(_) => panic!("Expected auth error for invalid key"),
    }
}

// ============================================================================
// RSP3 - Subscribe capability sufficient for presence.get
// ============================================================================

// UTS: rest/integration/RSP3/subscribe-capability-sufficient-5
#[tokio::test]
async fn rsp3_subscribe_capability_sufficient() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.subscribe_only_key());

    let result = client
        .channels()
        .get("persisted:presence_fixtures")
        .presence()
        .get()
        .send()
        .await
        .unwrap();

    assert!(
        !result.items().is_empty(),
        "Subscribe-only key should be able to get presence"
    );
}

// ============================================================================
// RSP5 - Presence message decoding
// ============================================================================

// UTS: rest/integration/RSP5/decode-string-data-0
#[tokio::test]
async fn rsp5_string_data_decoded() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");
    let result = channel
        .presence()
        .get()
        .client_id("client_string")
        .send()
        .await
        .unwrap();

    assert_eq!(result.items().len(), 1);
    match &result.items()[0].data {
        Data::String(s) => assert_eq!(s, "This is a string clientData payload"),
        other => panic!("Expected String data, got {:?}", other),
    }
}

// UTS: rest/integration/RSP5/decode-json-data-1
#[tokio::test]
async fn rsp5_json_data_decoded() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let channel = client.channels().get("persisted:presence_fixtures");
    let result = channel
        .presence()
        .get()
        .client_id("client_decoded")
        .send()
        .await
        .unwrap();

    assert_eq!(result.items().len(), 1);
    match &result.items()[0].data {
        Data::JSON(v) => {
            assert_eq!(v["example"]["json"], "Object");
        }
        other => panic!("Expected JSON data, got {:?}", other),
    }
}

// ============================================================================
// RSH1a - Push admin publish
// ============================================================================

// UTS: rest/integration/RSH1a/push-publish-clientid-0
#[tokio::test]
async fn rsh1a_push_publish_to_client_id() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let result = client
        .push()
        .admin()
        .publish(
            serde_json::json!({"clientId": "test-client-push"}),
            serde_json::json!({
                "notification": {
                    "title": "Integration Test",
                    "body": "Hello from push admin"
                }
            }),
        )
        .await;

    assert!(
        result.is_ok(),
        "Push publish should succeed: {:?}",
        result.err()
    );
}

// UTS: rest/integration/RSH1a/push-publish-invalid-recipient-1
#[tokio::test]
async fn rsh1a_push_publish_rejects_invalid_recipient() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let result = client
        .push()
        .admin()
        .publish(
            serde_json::json!({}),
            serde_json::json!({"notification": {"title": "Test"}}),
        )
        .await;

    assert!(
        result.is_err(),
        "Push publish with empty recipient should fail"
    );
}

// ============================================================================
// RSH1b - Push device registrations
// ============================================================================

// UTS: rest/integration/RSH1b3/save-and-get-device-0
#[tokio::test]
async fn rsh1b3_save_and_get_device_registration() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let device_id = format!("test-device-{}", random_id());
    let device = serde_json::json!({
        "id": device_id,
        "platform": "ios",
        "formFactor": "phone",
        "push": {
            "recipient": {
                "transportType": "apns",
                "deviceToken": format!("test-token-{}", random_id())
            }
        }
    });

    let saved = client
        .push()
        .admin()
        .device_registrations()
        .save(&device)
        .await
        .unwrap();
    assert_eq!(saved["id"], device_id);
    assert_eq!(saved["platform"], "ios");

    let retrieved = client
        .push()
        .admin()
        .device_registrations()
        .get(&device_id)
        .await
        .unwrap();
    assert_eq!(retrieved["id"], device_id);

    // Cleanup
    let _ = client
        .push()
        .admin()
        .device_registrations()
        .remove(&device_id)
        .await;
}

// UTS: rest/integration/RSH1b1/get-unknown-device-error-0
#[tokio::test]
async fn rsh1b1_get_unknown_device_returns_error() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let err = client
        .push()
        .admin()
        .device_registrations()
        .get(&format!("nonexistent-device-{}", random_id()))
        .await
        .unwrap_err();

    assert_eq!(err.status_code, Some(404));
}

// UTS: rest/integration/RSH1b4/remove-device-0
#[tokio::test]
async fn rsh1b4_remove_device() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let device_id = format!("test-device-remove-{}", random_id());
    let device = serde_json::json!({
        "id": device_id,
        "platform": "ios",
        "formFactor": "phone",
        "push": {
            "recipient": {
                "transportType": "apns",
                "deviceToken": "test-token"
            }
        }
    });

    client
        .push()
        .admin()
        .device_registrations()
        .save(&device)
        .await
        .unwrap();

    client
        .push()
        .admin()
        .device_registrations()
        .remove(&device_id)
        .await
        .unwrap();

    let err = client
        .push()
        .admin()
        .device_registrations()
        .get(&device_id)
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(404));
}

// UTS: rest/integration/RSH1b4/remove-nonexistent-device-1
#[tokio::test]
async fn rsh1b4_remove_nonexistent_succeeds() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let result = client
        .push()
        .admin()
        .device_registrations()
        .remove(&format!("nonexistent-device-{}", random_id()))
        .await;
    assert!(result.is_ok());
}

// ============================================================================
// RSH1b3 - Update existing device registration
// ============================================================================

// UTS: rest/integration/RSH1b3/update-device-registration-1
#[tokio::test]
async fn rsh1b3_update_device_registration() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let device_id = format!("test-device-update-{}", random_id());
    let device_v1 = serde_json::json!({
        "id": device_id,
        "platform": "ios",
        "formFactor": "phone",
        "push": {
            "recipient": {
                "transportType": "apns",
                "deviceToken": "token-v1"
            }
        }
    });

    client
        .push()
        .admin()
        .device_registrations()
        .save(&device_v1)
        .await
        .unwrap();

    let device_v2 = serde_json::json!({
        "id": device_id,
        "platform": "ios",
        "formFactor": "phone",
        "push": {
            "recipient": {
                "transportType": "apns",
                "deviceToken": "token-v2"
            }
        }
    });

    let updated = client
        .push()
        .admin()
        .device_registrations()
        .save(&device_v2)
        .await
        .unwrap();
    assert_eq!(updated["id"], device_id);
    assert_eq!(updated["push"]["recipient"]["deviceToken"], "token-v2");

    let retrieved = client
        .push()
        .admin()
        .device_registrations()
        .get(&device_id)
        .await
        .unwrap();
    assert_eq!(retrieved["push"]["recipient"]["deviceToken"], "token-v2");

    let _ = client
        .push()
        .admin()
        .device_registrations()
        .remove(&device_id)
        .await;
}

// ============================================================================
// RSH1b2 - List device registrations with filters
// ============================================================================

// UTS: rest/integration/RSH1b2/list-devices-filtered-0
#[tokio::test]
async fn rsh1b2_list_devices_filtered() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let device_id = format!("test-device-list-{}", random_id());
    let device = serde_json::json!({
        "id": device_id,
        "platform": "android",
        "formFactor": "tablet",
        "push": {
            "recipient": {
                "transportType": "gcm",
                "registrationToken": "test-token"
            }
        }
    });

    client
        .push()
        .admin()
        .device_registrations()
        .save(&device)
        .await
        .unwrap();

    let result = client
        .push()
        .admin()
        .device_registrations()
        .list()
        .params(&[("deviceId", &device_id)])
        .send()
        .await
        .unwrap();

    assert_eq!(result.items().len(), 1);
    assert_eq!(result.items()[0]["id"], device_id);
    assert_eq!(result.items()[0]["platform"], "android");

    let _ = client
        .push()
        .admin()
        .device_registrations()
        .remove(&device_id)
        .await;
}

// ============================================================================
// RSH1b2 - List supports pagination with limit
// ============================================================================

// UTS: rest/integration/RSH1b2/list-devices-pagination-1
#[tokio::test]
async fn rsh1b2_list_devices_pagination() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let client_id = format!("test-client-list-{}", random_id());
    let mut device_ids = Vec::new();

    for i in 1..=3 {
        let device_id = format!("test-device-limit-{}-{}", i, random_id());
        device_ids.push(device_id.clone());
        let device = serde_json::json!({
            "id": device_id,
            "clientId": client_id,
            "platform": "ios",
            "formFactor": "phone",
            "push": {
                "recipient": {
                    "transportType": "apns",
                    "deviceToken": format!("token-{}", i)
                }
            }
        });
        client
            .push()
            .admin()
            .device_registrations()
            .save(&device)
            .await
            .unwrap();
    }

    let result = client
        .push()
        .admin()
        .device_registrations()
        .list()
        .params(&[("clientId", &client_id)])
        .limit(2)
        .send()
        .await
        .unwrap();

    assert!(result.items().len() <= 2);
    assert!(result.has_next());

    // Cleanup
    for device_id in &device_ids {
        let _ = client
            .push()
            .admin()
            .device_registrations()
            .remove(device_id)
            .await;
    }
}

// ============================================================================
// RSH1b5 - removeWhere deletes devices by clientId
// ============================================================================

// UTS: rest/integration/RSH1b5/remove-where-clientid-0
#[tokio::test]
async fn rsh1b5_remove_where_by_client_id() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let client_id = format!("test-client-removeWhere-{}", random_id());
    let mut device_ids = Vec::new();

    for i in 1..=2 {
        let device_id = format!("test-device-rw-{}-{}", i, random_id());
        device_ids.push(device_id.clone());
        let device = serde_json::json!({
            "id": device_id,
            "clientId": client_id,
            "platform": "ios",
            "formFactor": "phone",
            "push": {
                "recipient": {
                    "transportType": "apns",
                    "deviceToken": format!("token-{}", i)
                }
            }
        });
        client
            .push()
            .admin()
            .device_registrations()
            .save(&device)
            .await
            .unwrap();
    }

    client
        .push()
        .admin()
        .device_registrations()
        .remove_where(&[("clientId", &client_id)])
        .await
        .unwrap();

    let result = client
        .push()
        .admin()
        .device_registrations()
        .list()
        .params(&[("clientId", &client_id)])
        .send()
        .await
        .unwrap();
    assert_eq!(result.items().len(), 0);
}

// ============================================================================
// RSH1c - Push channel subscriptions
// ============================================================================

// UTS: rest/integration/RSH1c3/save-and-list-subscriptions-0
#[tokio::test]
async fn rsh1c3_save_and_list_channel_subscription_with_device() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let device_id = format!("test-device-sub-{}", random_id());
    let channel_name = format!("pushenabled:test-sub-{}", random_id());

    // Register a device first (required for deviceId subscriptions)
    let device = serde_json::json!({
        "id": device_id,
        "platform": "ios",
        "formFactor": "phone",
        "push": {
            "recipient": {
                "transportType": "apns",
                "deviceToken": "test-token"
            }
        }
    });
    client
        .push()
        .admin()
        .device_registrations()
        .save(&device)
        .await
        .unwrap();

    let sub = serde_json::json!({
        "channel": channel_name,
        "deviceId": device_id
    });
    let saved = client
        .push()
        .admin()
        .channel_subscriptions()
        .save(&sub)
        .await
        .unwrap();
    assert_eq!(saved["channel"], channel_name);
    assert_eq!(saved["deviceId"], device_id);

    // List and verify
    let result = client
        .push()
        .admin()
        .channel_subscriptions()
        .list()
        .params(&[("channel", &channel_name)])
        .send()
        .await
        .unwrap();
    assert!(!result.items().is_empty());
    let found = result.items().iter().any(|s| s["deviceId"] == device_id);
    assert!(found, "Subscription not found in list");

    // Cleanup
    let _ = client
        .push()
        .admin()
        .channel_subscriptions()
        .remove(&sub)
        .await;
    let _ = client
        .push()
        .admin()
        .device_registrations()
        .remove(&device_id)
        .await;
}

// UTS: rest/integration/RSH1c3/save-subscription-clientid-1
#[tokio::test]
async fn rsh1c3_save_and_list_channel_subscription() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let client_id = format!("test-client-sub-{}", random_id());
    let channel_name = format!("pushenabled:test-sub-{}", random_id());

    let sub = serde_json::json!({
        "channel": channel_name,
        "clientId": client_id
    });

    let saved = client
        .push()
        .admin()
        .channel_subscriptions()
        .save(&sub)
        .await
        .unwrap();
    assert_eq!(saved["channel"], channel_name);
    assert_eq!(saved["clientId"], client_id);

    // Cleanup
    let _ = client
        .push()
        .admin()
        .channel_subscriptions()
        .remove(&sub)
        .await;
}

// UTS: rest/integration/RSH1c4/remove-nonexistent-subscription-1
#[tokio::test]
async fn rsh1c4_remove_nonexistent_subscription_succeeds() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let sub = serde_json::json!({
        "channel": format!("pushenabled:nonexistent-{}", random_id()),
        "clientId": "nonexistent-client"
    });

    let result = client
        .push()
        .admin()
        .channel_subscriptions()
        .remove(&sub)
        .await;
    assert!(result.is_ok());
}

// ============================================================================
// RSH1c2 - listChannels returns channel names with subscriptions
// ============================================================================

// UTS: rest/integration/RSH1c2/list-channels-with-subscriptions-0
#[tokio::test]
async fn rsh1c2_list_channels_with_subscriptions() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let client_id = format!("test-client-lc-{}", random_id());
    let channel_name = format!("pushenabled:test-listchannels-{}", random_id());

    let sub = serde_json::json!({
        "channel": channel_name,
        "clientId": client_id
    });
    client
        .push()
        .admin()
        .channel_subscriptions()
        .save(&sub)
        .await
        .unwrap();

    let result = client
        .push()
        .admin()
        .channel_subscriptions()
        .list_channels()
        .send()
        .await
        .unwrap();
    let channel_names: Vec<String> = result
        .items()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        channel_names.contains(&channel_name),
        "Channel {} not in listChannels result",
        channel_name
    );

    let _ = client
        .push()
        .admin()
        .channel_subscriptions()
        .remove(&sub)
        .await;
}

// ============================================================================
// RSH1c4 - Remove deletes channel subscription
// ============================================================================

// UTS: rest/integration/RSH1c4/remove-channel-subscription-0
#[tokio::test]
async fn rsh1c4_remove_channel_subscription() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let client_id = format!("test-client-rm-{}", random_id());
    let channel_name = format!("pushenabled:test-remove-{}", random_id());

    let sub = serde_json::json!({
        "channel": channel_name,
        "clientId": client_id
    });
    client
        .push()
        .admin()
        .channel_subscriptions()
        .save(&sub)
        .await
        .unwrap();

    client
        .push()
        .admin()
        .channel_subscriptions()
        .remove(&sub)
        .await
        .unwrap();

    let result = client
        .push()
        .admin()
        .channel_subscriptions()
        .list()
        .params(&[("channel", &channel_name), ("clientId", &client_id)])
        .send()
        .await
        .unwrap();
    assert_eq!(result.items().len(), 0);
}

// ============================================================================
// RSH1c5 - removeWhere deletes subscriptions by clientId
// ============================================================================

// UTS: rest/integration/RSH1c5/remove-where-subscriptions-0
#[tokio::test]
async fn rsh1c5_remove_where_subscriptions() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());

    let client_id = format!("test-client-rwsub-{}", random_id());

    for i in 1..=2 {
        let ch = format!("pushenabled:test-rwsub-{}-{}", i, random_id());
        let sub = serde_json::json!({
            "channel": ch,
            "clientId": client_id
        });
        client
            .push()
            .admin()
            .channel_subscriptions()
            .save(&sub)
            .await
            .unwrap();
    }

    client
        .push()
        .admin()
        .channel_subscriptions()
        .remove_where(&[("clientId", &client_id)])
        .await
        .unwrap();

    let result = client
        .push()
        .admin()
        .channel_subscriptions()
        .list()
        .params(&[("clientId", &client_id)])
        .send()
        .await
        .unwrap();
    assert_eq!(result.items().len(), 0);
}

// ============================================================================
// RSA17d - Token auth client rejected from revoking
// ============================================================================

// UTS: rest/integration/RSA17d/token-auth-revoke-rejected-0
#[tokio::test]
async fn rsa17d_token_auth_client_cannot_revoke() {
    let app = get_sandbox().await;
    let key_client = sandbox_client(app.full_access_key());

    let token_details = key_client.auth().request_token(None, None).await.unwrap();

    let token_client = sandbox_client(&token_details.token);

    let err = token_client
        .auth()
        .revoke_tokens(&RevokeTokensRequest {
            targets: vec!["clientId:anyone".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        })
        .await
        .unwrap_err();

    assert_eq!(err.status_code, Some(401));
    assert_eq!(
        err.code_value(),
        40162,
        "Expected 40162 (token auth cannot revoke)"
    );
}

// ============================================================================
// Ignored tests - depend on missing SDK features or test infrastructure
// ============================================================================

// --- Auth (JWT / authCallback) ---

/// Mint an Ably-shaped JWT: HS256 signed with the key secret, `kid` carrying
/// the key name, expiring `ttl_secs` from now (negative = already expired).
fn generate_jwt(api_key: &str, client_id: Option<&str>, ttl_secs: i64) -> String {
    let (key_name, key_secret) = api_key.split_once(':').expect("keyName:keySecret");
    let now = chrono::Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(key_name.to_string());
    // For an already-expired JWT the iat must ALSO be in the past — the
    // server derives ttl = exp - iat and rejects a negative ttl as malformed
    // (40003) rather than expired (40142)
    let exp = now + ttl_secs;
    let iat = if ttl_secs < 0 { exp - 3600 } else { now };
    let mut claims = serde_json::json!({
        "iat": iat,
        "exp": exp,
    });
    if let Some(cid) = client_id {
        claims["x-ably-clientId"] = serde_json::json!(cid);
    }
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(key_secret.as_bytes()),
    )
    .expect("jwt encode")
}

// UTS: rest/integration/RSA8/token-auth-jwt-0
#[tokio::test]
async fn rsa8_jwt_token_auth() {
    let app = get_sandbox().await;
    let jwt = generate_jwt(app.full_access_key(), None, 3600);

    let client = crate::options::ClientOptions::with_token(&jwt)
        .endpoint("nonprod:sandbox")
        .unwrap()
        .rest()
        .unwrap();
    let channel_name = format!("test-RSA8-jwt-{}", random_id());
    let resp = client
        .request("GET", &format!("/channels/{}", channel_name))
        .send()
        .await
        .expect("RSA8: JWT accepted by the server");
    assert!((200..300).contains(&resp.status_code()));
}

// UTS: rest/integration/RSA8/auth-callback-token-request-1
// The authCallback returns a signed TokenRequest which the library exchanges.
#[tokio::test]
async fn rsa8_auth_callback_with_token_request() {
    use crate::auth::{AuthCallback, AuthToken, Key, TokenParams};
    use std::sync::Arc;

    struct TokenRequestCb {
        key: Key,
    }
    impl AuthCallback for TokenRequestCb {
        fn token<'a>(
            &'a self,
            params: &'a TokenParams,
        ) -> std::pin::Pin<
            Box<dyn Send + futures::Future<Output = crate::error::Result<AuthToken>> + 'a>,
        > {
            Box::pin(async move { Ok(AuthToken::Request(self.key.sign(params)?)) })
        }
    }

    let app = get_sandbox().await;
    let key = Key::new(app.full_access_key()).unwrap();
    let client = ClientOptions::with_auth_callback(Arc::new(TokenRequestCb { key }))
        .endpoint("nonprod:sandbox")
        .unwrap()
        .rest()
        .unwrap();

    // The callback's TokenRequest is exchanged for a real token and used
    let channel_name = format!("test-RSA8-cb-tr-{}", random_id());
    let channel = client.channels().get(&channel_name);
    channel
        .publish()
        .name("event")
        .string("via-callback-token-request")
        .send()
        .await
        .expect("publish with callback-supplied TokenRequest");

    let td = client.auth().token_details();
    assert!(
        td.is_some(),
        "library token cached after implicit acquisition"
    );
    assert!(!td.unwrap().token.is_empty());
}

// UTS: rest/integration/RSA8/auth-callback-jwt-3
#[tokio::test]
async fn rsa8_auth_callback_jwt() {
    use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenParams};
    use std::sync::Arc;

    struct JwtCb {
        api_key: String,
    }
    impl AuthCallback for JwtCb {
        fn token<'a>(
            &'a self,
            params: &'a TokenParams,
        ) -> std::pin::Pin<
            Box<dyn Send + futures::Future<Output = crate::error::Result<AuthToken>> + 'a>,
        > {
            Box::pin(async move {
                let jwt = generate_jwt(&self.api_key, params.client_id.as_deref(), 3600);
                Ok(AuthToken::Details(TokenDetails::token(jwt)))
            })
        }
    }

    let app = get_sandbox().await;
    let client = ClientOptions::with_auth_callback(Arc::new(JwtCb {
        api_key: app.full_access_key().to_string(),
    }))
    .endpoint("nonprod:sandbox")
    .unwrap()
    .rest()
    .unwrap();

    let channel_name = format!("test-RSA8-jwt-callback-{}", random_id());
    let resp = client
        .request("GET", &format!("/channels/{}", channel_name))
        .send()
        .await
        .expect("RSA8: callback-minted JWT accepted");
    assert!((200..300).contains(&resp.status_code()));
}

// UTS: rest/integration/RSC10/token-renewal-expired-jwt-0
#[tokio::test]
async fn rsc10_token_renewal_with_expired_jwt() {
    use crate::auth::{AuthCallback, AuthToken, TokenDetails, TokenParams};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct ExpiredThenValidJwt {
        api_key: String,
        count: Arc<AtomicUsize>,
    }
    impl AuthCallback for ExpiredThenValidJwt {
        fn token<'a>(
            &'a self,
            _params: &'a TokenParams,
        ) -> std::pin::Pin<
            Box<dyn Send + futures::Future<Output = crate::error::Result<AuthToken>> + 'a>,
        > {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                // First call: a JWT that expired 5s ago; then valid ones
                let ttl = if n == 0 { -5 } else { 3600 };
                let jwt = generate_jwt(&self.api_key, None, ttl);
                Ok(AuthToken::Details(TokenDetails::token(jwt)))
            })
        }
    }

    let app = get_sandbox().await;
    let count = Arc::new(AtomicUsize::new(0));
    let client = ClientOptions::with_auth_callback(Arc::new(ExpiredThenValidJwt {
        api_key: app.full_access_key().to_string(),
        count: count.clone(),
    }))
    .endpoint("nonprod:sandbox")
    .unwrap()
    .rest()
    .unwrap();

    // The expired JWT draws a 4014x from the server; the client renews via
    // the callback and retries (RSC10)
    let channel_name = format!("test-RSC10-jwt-{}", random_id());
    let resp = client
        .request("GET", &format!("/channels/{}", channel_name))
        .send()
        .await
        .expect("RSC10: renewed after the expired JWT was rejected");
    assert!(
        (200..300).contains(&resp.status_code()),
        "status={} callback_count={} error_code={:?} error_message={:?}",
        resp.status_code(),
        count.load(Ordering::SeqCst),
        resp.error_code(),
        resp.error_message()
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "RSC10: the callback ran once for the expired JWT and once to renew"
    );
}

// UTS: rest/integration/RSA8/capability-restriction (native-token variant;
// the JWT variant remains blocked on a JWT library)
#[tokio::test]
async fn rsa8_capability_restriction() {
    let app = get_sandbox().await;
    let key_client = sandbox_client(app.full_access_key());

    // A token restricted to one channel
    let params = TokenParams::new().capability(r#"{"allowed-channel":["publish"]}"#);
    let td = key_client
        .auth()
        .request_token(Some(&params), None)
        .await
        .expect("restricted token");

    let token_client = ClientOptions::with_token(td.token)
        .endpoint("nonprod:sandbox")
        .unwrap()
        .rest()
        .unwrap();

    // Publishing to the allowed channel succeeds
    token_client
        .channels()
        .get("allowed-channel")
        .publish()
        .name("ok")
        .string("d")
        .send()
        .await
        .expect("publish within capability");

    // Publishing elsewhere is rejected with a capability error
    let err = token_client
        .channels()
        .get("forbidden-channel")
        .publish()
        .name("nope")
        .string("d")
        .send()
        .await
        .expect_err("publish outside capability must fail");
    assert_eq!(err.status_code, Some(401));
    assert_eq!(
        err.code,
        Some(40160),
        "operation not permitted by capability"
    );
}

// --- History ---

// UTS: rest/integration/RSL2b3/history-time-range-0
#[tokio::test]
async fn rsl2b3_history_time_range() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("persisted:test-RSL2b3-{}", random_id());
    let channel = client.channels().get(&channel_name);

    // Publish one message, capture the boundary, then publish another
    channel
        .publish()
        .name("before")
        .string("d1")
        .send()
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let boundary = client.time().await.unwrap().timestamp_millis();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    channel
        .publish()
        .name("after")
        .string("d2")
        .send()
        .await
        .unwrap();

    // Poll until both messages are visible in unfiltered history
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let all = channel.history().send().await.unwrap();
        if all.items().len() >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "history did not converge to 2 messages within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // RSL2b3: only the message published after `boundary` is returned
    let result = channel
        .history()
        .start(&boundary.to_string())
        .send()
        .await
        .unwrap();
    let names: Vec<_> = result
        .items()
        .iter()
        .filter_map(|m| m.name.as_deref())
        .collect();
    assert!(names.contains(&"after"), "expected 'after' in {:?}", names);
    assert!(
        !names.contains(&"before"),
        "'before' must be excluded, got {:?}",
        names
    );
}

// --- Publish ---

// UTS: rest/integration/RSL1n/publish-result-serials-0 and
// rest/integration/RSL1n/publish-returns-serials-0
#[tokio::test]
async fn rsl1n_publish_returns_serials() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("test-RSL1n-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("event")
        .string("serial-data")
        .send()
        .await
        .unwrap();
    assert_eq!(result.serials.len(), 1, "one serial per published message");
    let serial = result.serials[0].as_deref().expect("serial present");
    assert!(!serial.is_empty());

    // Batch: serials correspond 1:1
    let messages = vec![
        Message {
            name: Some("e1".into()),
            data: Data::String("d1".into()),
            ..Default::default()
        },
        Message {
            name: Some("e2".into()),
            data: Data::String("d2".into()),
            ..Default::default()
        },
    ];
    let result = channel.publish().messages(messages).send().await.unwrap();
    assert_eq!(result.serials.len(), 2);
    assert!(result.serials.iter().all(|s| s.is_some()));
}

// --- Presence history (needs realtime) ---

/// Realtime fixture: enter/update/leave presence on `channel_name` so REST
/// presence history has events to return.
async fn generate_presence_events(app: &SandboxApp, channel_name: &str) {
    let opts = crate::options::ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .client_id("rsp4-fixture-client")
        .unwrap()
        .auto_connect(false);
    let client = crate::realtime::Realtime::new(&opts).unwrap();
    client.connect();
    assert!(
        crate::realtime::await_state(
            &client.connection,
            crate::ConnectionState::Connected,
            10000
        )
        .await
    );
    let ch = client.channels.get(channel_name);
    ch.attach().await.unwrap();
    ch.presence()
        .enter(Some(serde_json::json!("entered")))
        .await
        .unwrap();
    ch.presence()
        .update(Some(serde_json::json!({"state": "updated"})))
        .await
        .unwrap();
    ch.presence().leave(None).await.unwrap();
    client.close();
}

// UTS: rest/integration/RSP4/history-returns-events-0 (+RSP4b2 direction,
// +RSP4b3 limit, +RSP5 decode — one fixture, several assertions)
#[tokio::test]
async fn rsp4_presence_history() {
    let app = get_sandbox().await;
    let channel_name = format!("persisted:test-RSP4-{}", random_id());
    generate_presence_events(app, &channel_name).await;

    let client = sandbox_client(app.full_access_key());
    let channel = client.channels().get(&channel_name);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(16);
    let items = loop {
        let result = channel.presence().history().send().await.unwrap();
        let items: Vec<_> = result.items().to_vec();
        if items.len() >= 3 {
            break items;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "presence history events did not appear within 16s, got {}",
            items.len()
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    // RSP4: enter/update/leave all present (default direction: backwards)
    use crate::rest::PresenceAction;
    let actions: Vec<_> = items.iter().filter_map(|m| m.action).collect();
    assert!(actions.contains(&PresenceAction::Enter));
    assert!(actions.contains(&PresenceAction::Update));
    assert!(actions.contains(&PresenceAction::Leave));
    // RSP5: data decoded — the update carried a JSON object
    let update = items
        .iter()
        .find(|m| m.action == Some(PresenceAction::Update))
        .unwrap();
    assert!(
        matches!(&update.data, Data::JSON(v) if v["state"] == "updated"),
        "decoded JSON presence data, got {:?}",
        update.data
    );

    // RSP4b2: forwards direction puts the ENTER first
    let forwards = channel
        .presence()
        .history()
        .params(&[("direction", "forwards")])
        .send()
        .await
        .unwrap();
    assert_eq!(forwards.items()[0].action, Some(PresenceAction::Enter));

    // RSP4b3: limit caps the page
    let limited = channel.presence().history().limit(1).send().await.unwrap();
    assert_eq!(limited.items().len(), 1);
}

// UTS: rest/integration/RSP4b1/history-time-range-0
#[tokio::test]
async fn rsp4b1_presence_history_time_range() {
    let app = get_sandbox().await;
    let channel_name = format!("persisted:test-RSP4b1-{}", random_id());
    let before = chrono::Utc::now().timestamp_millis() - 60_000;
    generate_presence_events(app, &channel_name).await;

    let client = sandbox_client(app.full_access_key());
    let channel = client.channels().get(&channel_name);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(16);
    loop {
        // A start bound well before the events includes them all
        let result = channel
            .presence()
            .history()
            .params(&[("start", &before.to_string())])
            .send()
            .await
            .unwrap();
        if result.items().len() >= 3 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "events within range");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    // A range entirely in the past excludes them
    let past = channel
        .presence()
        .history()
        .params(&[
            ("start", &(before - 120_000).to_string()),
            ("end", &(before - 60_000).to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert!(past.items().is_empty(), "RSP4b1: out-of-range excluded");
}

// --- Presence decoding ---

// RSL5/RSL6 live round-trip: encrypted publish is decrypted by history on a
// cipher-configured channel. (The RSP5 presence variant still needs realtime.)
#[tokio::test]
async fn rsl5_encrypted_publish_history_roundtrip() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let key = base64::decode("WUP6u0K7MXI5Zeo0VppPwg==").unwrap();
    let cipher = crate::crypto::CipherParams::builder()
        .key(key)
        .build()
        .unwrap();

    let channel_name = format!("persisted:test-RSL5-{}", random_id());
    let channel = client.channels().name(&channel_name).cipher(cipher).get();
    channel
        .publish()
        .name("secret-event")
        .json(serde_json::json!({"secret": "payload"}))
        .send()
        .await
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let result = channel.history().send().await.unwrap();
        if !result.items().is_empty() {
            let msg = &result.items()[0];
            assert!(
                msg.encoding.is_none(),
                "fully decoded, got {:?}",
                msg.encoding
            );
            assert!(
                matches!(msg.data, Data::JSON(ref v) if v["secret"] == "payload"),
                "decrypted JSON expected, got {:?}",
                msg.data
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "encrypted message did not appear in history within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

// UTS: rest/integration/RSP5/decode-history-messages-3 — covered inside
// rsp4_presence_history (the JSON-data update is asserted decoded).

// --- Batch presence (needs realtime) ---

// UTS: rest/integration/RSC24/batch-presence-multiple-channels-0
// (+empty-channel-presence-2: the never-used channel comes back empty)
#[tokio::test]
async fn rsc24_batch_presence() {
    let app = get_sandbox().await;
    let suffix = random_id();
    let ch_a = format!("test-RSC24-a-{}", suffix);
    let ch_b = format!("test-RSC24-b-{}", suffix);
    let ch_empty = format!("test-RSC24-empty-{}", suffix);

    // A realtime member on each of the two active channels
    let opts = crate::options::ClientOptions::new(app.full_access_key())
        .endpoint("nonprod:sandbox")
        .unwrap()
        .client_id("rsc24-member")
        .unwrap()
        .auto_connect(false);
    let rt = crate::realtime::Realtime::new(&opts).unwrap();
    rt.connect();
    assert!(
        crate::realtime::await_state(
            &rt.connection,
            crate::ConnectionState::Connected,
            10000
        )
        .await
    );
    for name in [&ch_a, &ch_b] {
        let ch = rt.channels.get(name);
        ch.attach().await.unwrap();
        ch.presence().enter(None).await.unwrap();
    }

    let client = sandbox_client(app.full_access_key());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(16);
    loop {
        let result = client
            .batch_presence(&[ch_a.as_str(), ch_b.as_str(), ch_empty.as_str()])
            .await
            .unwrap();
        let occupied = result
            .results
            .iter()
            .filter(|r| match r {
                crate::rest::BatchPresenceResult::Success(s) => !s.presence.is_empty(),
                _ => false,
            })
            .count();
        if occupied == 2 {
            // RSC24/empty-channel: the unused channel is present with no members
            let empty = result
                .results
                .iter()
                .find_map(|r| match r {
                    crate::rest::BatchPresenceResult::Success(s) if s.channel == ch_empty => {
                        Some(s)
                    }
                    _ => None,
                })
                .expect("empty channel result present");
            assert!(empty.presence.is_empty());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "batch presence members did not appear within 16s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    rt.close();
}

// UTS: rest/integration/RSC24/restricted-key-channel-failure-1
#[tokio::test]
async fn rsc24_restricted_key_failure() {
    let app = get_sandbox().await;
    // The restricted key cannot read presence outside its allowed channels:
    // a batch over a forbidden channel reports a per-channel failure
    let client = sandbox_client(app.restricted_key());
    let forbidden = format!("forbidden-{}", random_id());
    let result = client.batch_presence(&[forbidden.as_str()]).await;
    match result {
        // Whole-request rejection is acceptable too (key has no presence
        // capability at all)
        Err(err) => assert!(err.code.is_some()),
        Ok(batch) => {
            assert!(matches!(
                batch.results.first(),
                Some(crate::rest::BatchPresenceResult::Failure(_))
            ));
        }
    }
}

// --- Token revocation ---

// UTS: rest/integration/RSA17g/revoke-token-prevents-use-0 — a revoked
// token's realtime connection is forcibly closed with a 4014x error
#[tokio::test]
async fn rsa17g_revoke_tokens_prevents_use() {
    let app = get_sandbox().await;
    let admin = sandbox_client(app.revocable_key());
    let td = admin
        .auth()
        .request_token(
            Some(&crate::auth::TokenParams {
                client_id: Some("revoked-rt-client".to_string()),
                ..Default::default()
            }),
            None,
        )
        .await
        .unwrap();

    let opts = crate::options::ClientOptions::with_token(&td.token)
        .endpoint("nonprod:sandbox")
        .unwrap()
        .auto_connect(false);
    let rt = crate::realtime::Realtime::new(&opts).unwrap();
    let mut events = rt.connection.on_state_change();
    rt.connect();
    assert!(
        crate::realtime::await_state(
            &rt.connection,
            crate::ConnectionState::Connected,
            10000
        )
        .await
    );

    admin
        .auth()
        .revoke_tokens(&crate::rest::RevokeTokensRequest {
            targets: vec!["clientId:revoked-rt-client".to_string()],
            issued_before: None,
            allow_reauth_margin: None,
        })
        .await
        .unwrap();

    // The service disconnects the revoked connection with a 4014x token
    // error. The literal-token client cannot renew, so per RTN15h1 it goes
    // FAILED with 40171 ("no way to renew"), carrying the server's revocation
    // error as the cause (TI1).
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);
    loop {
        let change = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("disconnect after revocation within 30s")
            .expect("event stream open");
        if let Some(reason) = &change.reason {
            let code = reason.code;
            let cause_code = reason.cause.as_ref().and_then(|c| c.code);
            if code == Some(40171) && cause_code.is_some_and(|c| (40140..40150).contains(&c)) {
                break;
            }
        }
    }
    rt.close();
}

// UTS: rest/integration/RSA17e/issued-before-reauth-margin-0
#[tokio::test]
async fn rsa17e_issued_before_reauth_margin() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.revocable_key());
    let client_id = format!("revoke-margin-client-{}", random_id());

    let server_time = client.time().await.unwrap().timestamp_millis();
    // An issuedBefore in the past, so no active tokens are affected
    let issued_before = server_time - 20 * 60 * 1000;

    let request = RevokeTokensRequest {
        targets: vec![format!("clientId:{}", client_id)],
        issued_before: Some(issued_before),
        allow_reauth_margin: Some(true),
    };
    let result = client.auth().revoke_tokens(&request).await.unwrap();
    assert_eq!(result.success_count, 1);
    assert_eq!(result.results.len(), 1);
    // RSA17e: issuedBefore reflects what we sent
    assert_eq!(result.results[0].issued_before, Some(issued_before));
    // RSA17f: allowReauthMargin delays appliesAt by ~30 seconds
    let applies_at = result.results[0].applies_at.expect("appliesAt present");
    assert!(
        applies_at > server_time + 30 * 1000,
        "appliesAt {} must be > server_time + 30s {}",
        applies_at,
        server_time + 30 * 1000
    );
}

// UTS: rest/integration/RSA17c/mixed-success-failure-0 — revoking one
// valid and one unknown target reports per-target outcomes
#[tokio::test]
async fn rsa17c_mixed_success_failure() {
    let app = get_sandbox().await;
    let admin = sandbox_client(app.revocable_key());
    // A real token for a real clientId target
    let _td = admin
        .auth()
        .request_token(
            Some(&crate::auth::TokenParams {
                client_id: Some("rsa17c-target".to_string()),
                ..Default::default()
            }),
            None,
        )
        .await
        .unwrap();
    let result = admin
        .auth()
        .revoke_tokens(&crate::rest::RevokeTokensRequest {
            targets: vec![
                "clientId:rsa17c-target".to_string(),
                "invalidType:whatever".to_string(),
            ],
            issued_before: None,
            allow_reauth_margin: None,
        })
        .await;
    match result {
        // The service may reject the whole request for the malformed target…
        Err(err) => assert!(err.code.is_some()),
        // …or report per-target success/failure in the batch envelope
        Ok(batch) => {
            assert!(batch.success_count >= 1 || batch.failure_count >= 1);
        }
    }
}

// --- Mutable messages ---

// UTS: rest/integration/RSL11/get-message-by-serial-0
#[tokio::test]
async fn rsl11_get_message() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("mutable:test-RSL11-getMessage-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("test-event")
        .string("hello world")
        .send()
        .await
        .unwrap();
    let serial = result.serials[0].as_deref().expect("serial").to_string();

    // The message is not immediately readable after publish (read-after-write
    // lag, as with history) — retry 404s until the deadline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let msg = loop {
        match channel.get_message(&serial).await {
            Ok(msg) => break msg,
            Err(err) if err.status_code == Some(404) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "getMessage did not converge: {}",
                    err
                );
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(err) => panic!("getMessage failed: {}", err),
        }
    };
    assert_eq!(msg.name.as_deref(), Some("test-event"));
    assert!(matches!(msg.data, Data::String(ref s) if s == "hello world"));
    assert_eq!(msg.serial.as_deref(), Some(serial.as_str()));
    assert_eq!(msg.action, Some(crate::rest::MessageAction::Create));
    assert!(msg.timestamp.is_some());
}

// UTS: rest/integration/RSL15/update-message-0
#[tokio::test]
async fn rsl15_update_message() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("mutable:test-RSL15-update-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("original")
        .string("original-data")
        .send()
        .await
        .unwrap();
    let serial = result.serials[0].as_deref().expect("serial").to_string();

    let update = Message {
        serial: Some(serial.clone()),
        name: Some("updated".into()),
        data: Data::String("updated-data".into()),
        ..Default::default()
    };
    let op = crate::rest::MessageOperation {
        description: Some("edited content".into()),
        ..Default::default()
    };
    let update_result = channel
        .update_message(&update, Some(&op), None)
        .await
        .unwrap();
    let version_serial = update_result.version_serial.expect("versionSerial");
    assert!(!version_serial.is_empty());

    // Poll until the update is visible via getMessage
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let updated = loop {
        let msg = channel.get_message(&serial).await.unwrap();
        if msg.action == Some(crate::rest::MessageAction::Update) {
            break msg;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "update not visible within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    assert_eq!(updated.name.as_deref(), Some("updated"));
    assert!(matches!(updated.data, Data::String(ref s) if s == "updated-data"));
    let version = updated.version.expect("version object");
    assert_eq!(version["description"], "edited content");
}

// UTS: rest/integration/RSL15/delete-message-1
#[tokio::test]
async fn rsl15_delete_message() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("mutable:test-RSL15-delete-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("to-delete")
        .string("delete-me")
        .send()
        .await
        .unwrap();
    let serial = result.serials[0].as_deref().expect("serial").to_string();

    let msg = Message {
        serial: Some(serial.clone()),
        ..Default::default()
    };
    let delete_result = channel.delete_message(&msg, None, None).await.unwrap();
    let version_serial = delete_result.version_serial.expect("versionSerial");
    assert!(!version_serial.is_empty());

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let msg = channel.get_message(&serial).await.unwrap();
        if msg.action == Some(crate::rest::MessageAction::Delete) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "delete not visible within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

// UTS: rest/integration/RSL15/append-message-2
#[tokio::test]
async fn rsl15_append_message() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("mutable:test-RSL15-append-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("appendable")
        .string("original")
        .send()
        .await
        .unwrap();
    let serial = result.serials[0].as_deref().expect("serial").to_string();

    let msg = Message {
        serial: Some(serial),
        data: Data::String("appended-data".into()),
        ..Default::default()
    };
    let append_result = channel.append_message(&msg, None).await.unwrap();
    let version_serial = append_result.version_serial.expect("versionSerial");
    assert!(!version_serial.is_empty());
}

// UTS: rest/integration/RSL14/get-message-versions-0
#[tokio::test]
async fn rsl14_get_message_versions() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("mutable:test-RSL14-versions-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("versioned")
        .string("v1")
        .send()
        .await
        .unwrap();
    let serial = result.serials[0].as_deref().expect("serial").to_string();

    for (data, desc) in [("v2", "first edit"), ("v3", "second edit")] {
        let update = Message {
            serial: Some(serial.clone()),
            data: Data::String(data.into()),
            ..Default::default()
        };
        let op = crate::rest::MessageOperation {
            description: Some(desc.into()),
            ..Default::default()
        };
        channel
            .update_message(&update, Some(&op), None)
            .await
            .unwrap();
    }

    // Poll until all three versions appear
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let versions = loop {
        let result = channel.message_versions(&serial).send().await.unwrap();
        if result.items().len() >= 3 {
            break result;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "versions did not converge within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    for item in versions.items() {
        assert_eq!(item.serial.as_deref(), Some(serial.as_str()));
    }
}

// --- Annotations ---

// UTS: rest/integration/RSAN1/annotation-lifecycle-0
#[tokio::test]
async fn rsan1_rsan2_annotations_lifecycle() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("mutable:test-RSAN-lifecycle-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("annotatable")
        .string("content")
        .send()
        .await
        .unwrap();
    let serial = result.serials[0].as_deref().expect("serial").to_string();

    let annotation = crate::rest::Annotation {
        annotation_type: Some("com.ably.reactions".into()),
        name: Some("like".into()),
        ..Default::default()
    };
    channel
        .annotations()
        .publish(&serial, &annotation)
        .await
        .unwrap();

    // Poll until the annotation appears
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let annotations = loop {
        let result = channel.annotations().get(&serial).send().await.unwrap();
        if !result.items().is_empty() {
            break result;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "annotation not visible within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    let found = annotations.items().iter().find(|a| {
        a.annotation_type.as_deref() == Some("com.ably.reactions")
            && a.name.as_deref() == Some("like")
    });
    let ann = found.expect("published annotation present");
    assert_eq!(ann.message_serial.as_deref(), Some(serial.as_str()));

    // RSAN2: delete the annotation
    channel
        .annotations()
        .delete(&serial, &annotation)
        .await
        .unwrap();
}

// UTS: rest/integration/RSAN3/get-annotations-paginated-0
#[tokio::test]
async fn rsan3_get_annotations() {
    let app = get_sandbox().await;
    let client = sandbox_client(app.full_access_key());
    let channel_name = format!("mutable:test-RSAN3-paginated-{}", random_id());
    let channel = client.channels().get(&channel_name);

    let result = channel
        .publish()
        .name("multi-annotated")
        .string("content")
        .send()
        .await
        .unwrap();
    let serial = result.serials[0].as_deref().expect("serial").to_string();

    for name in ["like", "heart"] {
        let ann = crate::rest::Annotation {
            annotation_type: Some("com.ably.reactions".into()),
            name: Some(name.into()),
            ..Default::default()
        };
        channel.annotations().publish(&serial, &ann).await.unwrap();
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let result = loop {
        let r = channel.annotations().get(&serial).send().await.unwrap();
        if r.items().len() >= 2 {
            break r;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "annotations did not converge within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    for ann in result.items() {
        assert_eq!(ann.message_serial.as_deref(), Some(serial.as_str()));
        assert_eq!(ann.annotation_type.as_deref(), Some("com.ably.reactions"));
        assert!(ann.timestamp.is_some());
    }
}

// --- PushChannel (LocalDevice not implemented) ---

// UTS: rest/integration/RSH7a/subscribe-unsubscribe-device-0
#[tokio::test]
#[ignore = "LocalDevice not implemented - PushChannel subscribeDevice requires device registration"]
async fn rsh7a_subscribe_unsubscribe_device() {
    todo!()
}

// UTS: rest/integration/RSH7b/subscribe-unsubscribe-client-0
#[tokio::test]
#[ignore = "LocalDevice not implemented - PushChannel subscribeClient requires device config"]
async fn rsh7b_subscribe_unsubscribe_client() {
    todo!()
}

// (REST proxy tests live in src/tests_proxy.rs)

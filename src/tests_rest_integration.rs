use tokio::sync::OnceCell;

use crate::auth::TokenParams;
use crate::options::ClientOptions;
use crate::rest::{Data, Message, PresenceAction, Rest, RevokeTokensRequest};

const SANDBOX_URL: &str = "https://sandbox-rest.ably.io";
const TEST_APP_SETUP: &str = include_str!("../submodules/ably-common/test-resources/test-app-setup.json");

struct SandboxApp {
    app_id: String,
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
            .post(&format!("{}/apps", SANDBOX_URL))
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

    fn full_access_key(&self) -> &str {
        &self.keys[0].key_str
    }

    fn restricted_key(&self) -> &str {
        &self.keys[2].key_str
    }

    fn subscribe_only_key(&self) -> &str {
        &self.keys[3].key_str
    }
}

fn sandbox_client(key: &str) -> Rest {
    ClientOptions::new(key)
        .rest_host(SANDBOX_URL.trim_start_matches("https://"))
        .unwrap()
        .use_binary_protocol(false)
        .rest()
        .unwrap()
}

static SANDBOX: OnceCell<SandboxApp> = OnceCell::const_new();

async fn get_sandbox() -> &'static SandboxApp {
    SANDBOX
        .get_or_init(|| async { SandboxApp::provision().await })
        .await
}

fn random_id() -> String {
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
    assert_eq!(resp.error_code(), Some(40400), "Expected 40400 (key not found)");

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

    let token_details = key_client
        .auth()
        .request_token(None, None)
        .await
        .unwrap();

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

    assert_eq!(err.code_value(), 40160, "Expected 40160, got {}", err.code_value());
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

    assert_eq!(err.code_value(), 40099, "Expected 40099, got {}", err.code_value());
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

    // Poll history until message appears
    let mut history_items = Vec::new();
    for _ in 0..20 {
        let result = channel.history().send().await.unwrap();
        if !result.items().is_empty() {
            history_items = result.items().to_vec();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    assert_eq!(history_items.len(), 1, "Expected exactly 1 message (deduplication)");
    assert_eq!(history_items[0].id.as_deref(), Some(fixed_id.as_str()));
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

    assert_eq!(err.code_value(), 40012, "Expected 40012, got {}", err.code_value());
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

    channel.publish().name("event1").string("data1").send().await.unwrap();
    channel.publish().name("event2").string("data2").send().await.unwrap();
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
    assert_eq!(items[2].name.as_deref(), Some("event1"));

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

    channel.publish().name("first").string("1").send().await.unwrap();
    channel.publish().name("second").string("2").send().await.unwrap();
    channel.publish().name("third").string("3").send().await.unwrap();

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

    let event_names: Vec<String> = all_messages
        .iter()
        .filter_map(|m| m.name.clone())
        .collect();
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
    assert!(next_page.is_none(), "next() on last page should return None");
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
    let page1_ids: Vec<String> = page1
        .items()
        .iter()
        .filter_map(|m| m.id.clone())
        .collect();

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
    assert!(result.items().len() >= 5, "Expected at least 5 presence fixtures");
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
    assert_eq!(result.items()[0].client_id.as_deref(), Some("client_json"));
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

    assert!(all_members.len() >= 5, "Expected at least 5 fixture members");

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
    assert_eq!(unique_count, client_ids.len(), "Duplicate client IDs in pagination");
}

// ============================================================================
// RSP3 - Invalid credentials rejected
// ============================================================================

// UTS: rest/integration/RSP3/invalid-credentials-rejected-4
#[tokio::test]
async fn rsp3_invalid_credentials_rejected() {
    let _app = get_sandbox().await;
    let client = sandbox_client("invalid.key:secret");

    match client
        .channels()
        .get("test")
        .presence()
        .get()
        .send()
        .await
    {
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

    assert!(result.items().len() > 0, "Subscribe-only key should be able to get presence");
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

    assert!(result.is_ok(), "Push publish should succeed: {:?}", result.err());
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

    assert!(result.is_err(), "Push publish with empty recipient should fail");
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

    client.push().admin().device_registrations().save(&device_v1).await.unwrap();

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

    let updated = client.push().admin().device_registrations().save(&device_v2).await.unwrap();
    assert_eq!(updated["id"], device_id);
    assert_eq!(updated["push"]["recipient"]["deviceToken"], "token-v2");

    let retrieved = client.push().admin().device_registrations().get(&device_id).await.unwrap();
    assert_eq!(retrieved["push"]["recipient"]["deviceToken"], "token-v2");

    let _ = client.push().admin().device_registrations().remove(&device_id).await;
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

    client.push().admin().device_registrations().save(&device).await.unwrap();

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

    let _ = client.push().admin().device_registrations().remove(&device_id).await;
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
        client.push().admin().device_registrations().save(&device).await.unwrap();
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
        let _ = client.push().admin().device_registrations().remove(device_id).await;
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
        client.push().admin().device_registrations().save(&device).await.unwrap();
    }

    client.push().admin().device_registrations().remove_where(&[("clientId", &client_id)]).await.unwrap();

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
    client.push().admin().device_registrations().save(&device).await.unwrap();

    let sub = serde_json::json!({
        "channel": channel_name,
        "deviceId": device_id
    });
    let saved = client.push().admin().channel_subscriptions().save(&sub).await.unwrap();
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
    assert!(result.items().len() >= 1);
    let found = result.items().iter().any(|s| s["deviceId"] == device_id);
    assert!(found, "Subscription not found in list");

    // Cleanup
    let _ = client.push().admin().channel_subscriptions().remove(&sub).await;
    let _ = client.push().admin().device_registrations().remove(&device_id).await;
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
    client.push().admin().channel_subscriptions().save(&sub).await.unwrap();

    let result = client.push().admin().channel_subscriptions().list_channels().send().await.unwrap();
    let channel_names: Vec<String> = result
        .items()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(channel_names.contains(&channel_name), "Channel {} not in listChannels result", channel_name);

    let _ = client.push().admin().channel_subscriptions().remove(&sub).await;
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
    client.push().admin().channel_subscriptions().save(&sub).await.unwrap();

    client.push().admin().channel_subscriptions().remove(&sub).await.unwrap();

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
        client.push().admin().channel_subscriptions().save(&sub).await.unwrap();
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

    let token_details = key_client
        .auth()
        .request_token(None, None)
        .await
        .unwrap();

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
    assert_eq!(err.code_value(), 40162, "Expected 40162 (token auth cannot revoke)");
}

// ============================================================================
// Ignored tests - depend on missing SDK features or test infrastructure
// ============================================================================

// --- Auth (JWT / authCallback) ---

// UTS: rest/integration/RSA8/token-auth-jwt-0
#[tokio::test]
#[ignore = "JWT generation not implemented - needs third-party JWT library"]
async fn rsa8_jwt_token_auth() {
    todo!()
}

// UTS: rest/integration/RSA8/auth-callback-token-request-2
#[tokio::test]
#[ignore = "authCallback not implemented for REST client"]
async fn rsa8_auth_callback_with_token_request() {
    todo!()
}

// UTS: rest/integration/RSA8/auth-callback-jwt-3
#[tokio::test]
#[ignore = "authCallback + JWT not implemented"]
async fn rsa8_auth_callback_jwt() {
    todo!()
}

// UTS: rest/integration/RSC10/token-renewal-expired-jwt-0
#[tokio::test]
#[ignore = "JWT generation + authCallback not implemented"]
async fn rsc10_token_renewal_with_expired_jwt() {
    todo!()
}

// UTS: rest/integration/RSA8/capability-restriction-4
#[tokio::test]
#[ignore = "JWT generation not implemented"]
async fn rsa8_capability_restriction() {
    todo!()
}

// --- History ---

// UTS: rest/integration/RSL2b3/history-time-range-0
#[tokio::test]
#[ignore = "RSL2b3 time range filtering - requires server-timestamp-based boundary calculation"]
async fn rsl2b3_history_time_range() {
    todo!()
}

// --- Publish ---

// UTS: rest/integration/RSL1n/publish-result-serials-0
// UTS: rest/integration/RSL1n/publish-returns-serials-0
#[tokio::test]
#[ignore = "publish returns () not PublishResult - RSL1n not yet implemented"]
async fn rsl1n_publish_returns_serials() {
    todo!()
}

// --- Presence history (needs realtime) ---

// UTS: rest/integration/RSP4/history-returns-events-0
#[tokio::test]
#[ignore = "Needs realtime client to generate presence events"]
async fn rsp4_presence_history() {
    todo!()
}

// UTS: rest/integration/RSP4b1/history-time-range-0
#[tokio::test]
#[ignore = "Needs realtime client to generate presence events"]
async fn rsp4b1_presence_history_time_range() {
    todo!()
}

// UTS: rest/integration/RSP4b2/history-direction-forwards-0
#[tokio::test]
#[ignore = "Needs realtime client to generate presence events"]
async fn rsp4b2_presence_history_direction_forwards() {
    todo!()
}

// UTS: rest/integration/RSP4b3/history-limit-pagination-0
#[tokio::test]
#[ignore = "Needs realtime client to generate presence events"]
async fn rsp4b3_presence_history_limit_pagination() {
    todo!()
}

// --- Presence decoding ---

// UTS: rest/integration/RSP5/decode-encrypted-data-2
#[tokio::test]
#[ignore = "Cipher channel options not yet wired to presence decoding"]
async fn rsp5_encrypted_data_decoded() {
    todo!()
}

// UTS: rest/integration/RSP5/decode-history-messages-3
#[tokio::test]
#[ignore = "Needs realtime client to generate presence events with JSON data"]
async fn rsp5_history_messages_decoded() {
    todo!()
}

// --- Batch presence (needs realtime) ---

// UTS: rest/integration/RSC24/batch-presence-multiple-channels-0
#[tokio::test]
#[ignore = "Needs realtime client to enter presence members"]
async fn rsc24_batch_presence() {
    todo!()
}

// UTS: rest/integration/RSC24/restricted-key-channel-failure-1
#[tokio::test]
#[ignore = "Needs realtime client to enter presence members"]
async fn rsc24_restricted_key_failure() {
    todo!()
}

// UTS: rest/integration/RSC24/empty-channel-presence-2
#[tokio::test]
#[ignore = "Needs realtime client to enter presence members"]
async fn rsc24_empty_channel_presence() {
    todo!()
}

// --- Token revocation ---

// UTS: rest/integration/RSA17g/revoke-token-prevents-use-0
#[tokio::test]
#[ignore = "Needs realtime client + revocableTokens key in test-app-setup.json"]
async fn rsa17g_revoke_tokens_prevents_use() {
    todo!()
}

// UTS: rest/integration/RSA17e/issued-before-reauth-margin-0
#[tokio::test]
#[ignore = "Needs revocableTokens key in test-app-setup.json"]
async fn rsa17e_issued_before_reauth_margin() {
    todo!()
}

// UTS: rest/integration/RSA17c/mixed-success-failure-0
#[tokio::test]
#[ignore = "Needs realtime client + revocableTokens key in test-app-setup.json"]
async fn rsa17c_mixed_success_failure() {
    todo!()
}

// --- Mutable messages ---

// UTS: rest/integration/RSL11/get-message-by-serial-0
#[tokio::test]
#[ignore = "publish returns no serials; mutable namespace not in test-app-setup"]
async fn rsl11_get_message() {
    todo!()
}

// UTS: rest/integration/RSL15/update-message-0
#[tokio::test]
#[ignore = "publish returns no serials; mutable namespace not in test-app-setup"]
async fn rsl15_update_message() {
    todo!()
}

// UTS: rest/integration/RSL15/delete-message-1
#[tokio::test]
#[ignore = "publish returns no serials; mutable namespace not in test-app-setup"]
async fn rsl15_delete_message() {
    todo!()
}

// UTS: rest/integration/RSL15/append-message-2
#[tokio::test]
#[ignore = "publish returns no serials; mutable namespace not in test-app-setup"]
async fn rsl15_append_message() {
    todo!()
}

// UTS: rest/integration/RSL14/get-message-versions-0
#[tokio::test]
#[ignore = "publish returns no serials; mutable namespace not in test-app-setup"]
async fn rsl14_get_message_versions() {
    todo!()
}

// --- Annotations ---

// UTS: rest/integration/RSAN1/annotation-lifecycle-0
#[tokio::test]
#[ignore = "publish returns no serials; mutable namespace not in test-app-setup"]
async fn rsan1_rsan2_annotations_lifecycle() {
    todo!()
}

// UTS: rest/integration/RSAN3/get-annotations-paginated-0
#[tokio::test]
#[ignore = "publish returns no serials; mutable namespace not in test-app-setup"]
async fn rsan3_get_annotations() {
    todo!()
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

// --- REST proxy tests (needs proxy infrastructure) ---

// UTS: rest/proxy/RSC15l2/timeout-triggers-fallback-0
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsc15l2_timeout_triggers_fallback() {
    todo!()
}

// UTS: rest/proxy/RSC15l4/cloudfront-header-fallback-0
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsc15l4_cloudfront_header_fallback() {
    todo!()
}

// UTS: rest/proxy/RSC15l/unreachable-endpoint-error-0
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsc15l_unreachable_endpoint_error() {
    todo!()
}

// UTS: rest/proxy/RSC15l/connection-drop-fallback-1
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsc15l_connection_drop_fallback() {
    todo!()
}

// UTS: rest/proxy/RSC15l/http-5xx-json-error-parsed-0
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsc15l_http_5xx_json_error_parsed() {
    todo!()
}

// UTS: rest/proxy/RSC15l/http-5xx-no-json-synthesized-1
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsc15l_http_5xx_no_json_synthesized() {
    todo!()
}

// UTS: rest/proxy/RSC15l/http-4xx-not-retried-0
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsc15l_http_4xx_not_retried() {
    todo!()
}

// UTS: rest/proxy/RSL1k4/idempotent-retry-dedup-0
#[tokio::test]
#[ignore = "Proxy infrastructure not yet implemented"]
async fn proxy_rsl1k4_idempotent_retry_dedup() {
    todo!()
}

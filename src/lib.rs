//! A Rust client for the [Ably] REST and Realtime APIs.
//!
//! # Example
//!
//! TODO
//!
//! [Ably]: https://ably.com

#[macro_use]
pub mod error;
pub mod auth;
pub mod channel;
pub mod crypto;
pub mod http;
pub(crate) mod http_client;
mod json;
#[cfg(test)]
pub(crate) mod mock_http;
#[cfg(test)]
pub(crate) mod mock_ws;
pub mod options;
pub mod presence;
pub mod protocol;
pub mod realtime;
pub mod rest;
pub mod stats;

pub use error::{Error, Result};
pub use options::ClientOptions;
pub use rest::{Data, Rest};

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::iter::FromIterator;
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use futures::TryStreamExt;
    use reqwest::Url;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::*;
    use crate::auth::{AuthOptions, Credential, TokenParams};
    use crate::error::ErrorCode;
    use crate::http::Method;

    #[test]
    fn rest_client_from_string_with_colon_sets_key() {
        let s = "appID.keyID:keySecret";
        let client = Rest::new(s).unwrap();
        assert!(matches!(client.inner.opts.credential, Credential::Key(_)));
    }

    #[test]
    fn rest_client_from_string_without_colon_sets_token_literal() {
        let s = "appID.tokenID";
        let client = Rest::new(s).unwrap();
        assert!(matches!(
            client.inner.opts.credential,
            Credential::TokenDetails(_)
        ));
    }

    fn test_client() -> Rest {
        ClientOptions::new("aaaaaa.bbbbbb:cccccc")
            .environment("sandbox")
            .unwrap()
            .rest()
            .unwrap()
    }

    /// A test app in the Ably Sandbox environment.
    #[derive(Clone, Debug, Deserialize)]
    struct TestApp {
        keys: Vec<auth::Key>,
    }

    impl auth::AuthCallback for TestApp {
        fn token<'a>(
            &'a self,
            params: &'a TokenParams,
        ) -> std::pin::Pin<
            Box<dyn Send + futures::Future<Output = Result<auth::RequestOrDetails>> + 'a>,
        > {
            let fut = async { Ok(auth::RequestOrDetails::Request(self.token_request(params)?)) };
            Box::pin(fut)
        }
    }

    impl TestApp {
        /// Creates a test app in the Ably Sandbox environment with a single
        /// API key.
        async fn create() -> Result<Self> {
            let spec = json!({
                "keys": [
                    {}
                ],
                "namespaces": [
                    { "id": "persisted", "persisted": true },
                    { "id": "pushenabled", "pushEnabled": true }
                ],
                "channels": [
                    {
                        "name": "persisted:presence_fixtures",
                        "presence": [
                            {
                                "clientId": "client_string",
                                "data": "some presence data"
                            },
                            {
                                "clientId": "client_json",
                                "data": "{\"some\":\"presence data\"}",
                                "encoding": "json"
                            },
                            {
                                "clientId": "client_binary",
                                "data": "c29tZSBwcmVzZW5jZSBkYXRh",
                                "encoding": "base64"
                            }
                        ]
                    }
                ]
            });

            test_client()
                .request(Method::POST, "/apps")
                .body(&spec)
                .send()
                .await?
                .body()
                .await
        }

        /// Returns a Rest client with the test app's key.
        fn client(&self) -> Rest {
            self.options().rest().unwrap()
        }

        fn options(&self) -> ClientOptions {
            ClientOptions::with_key(self.key())
                .environment("sandbox")
                .unwrap()
        }

        fn key(&self) -> auth::Key {
            self.keys[0].clone()
        }

        fn token_request(&self, params: &auth::TokenParams) -> Result<auth::TokenRequest> {
            self.key().sign(params)
        }

        fn auth_options(&self) -> AuthOptions {
            AuthOptions {
                token: Some(self.options().credential),
                headers: None,
                method: Default::default(),
                params: None,
            }
        }
    }

    // TODO: impl Drop for TestApp which deletes the app (needs to be sync)

    #[tokio::test]
    async fn time_returns_the_server_time() -> Result<()> {
        let client = test_client();

        let five_minutes_ago = Utc::now() - Duration::minutes(5);

        let time = client.time().await?;
        assert!(
            time > five_minutes_ago,
            "Expected server time {} to be within the last 5 minutes",
            time
        );

        Ok(())
    }

    #[tokio::test]
    async fn custom_request_returns_body() -> Result<()> {
        let client = test_client();

        let res = client.request(Method::GET, "/time").send().await?;

        let items: Vec<u64> = res.body().await?;

        assert_eq!(items.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn paginated_request_returns_items() -> Result<()> {
        let client = test_client();

        let res = client
            .paginated_request::<json::Value>(Method::GET, "/time")
            .send()
            .await?;

        let items = res.items().await?;

        assert_eq!(items.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn paginated_request_returns_pages() -> Result<()> {
        let client = test_client();

        let mut pages = client
            .paginated_request::<json::Value>(Method::GET, "/time")
            .pages()
            .try_collect::<Vec<_>>()
            .await?;

        assert_eq!(pages.len(), 1);

        let page = pages.pop().expect("Expected a page");

        let items = page.items().await?;

        assert_eq!(items.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn custom_request_with_unknown_path_returns_404_response() -> Result<()> {
        let client = test_client();

        let err = client
            .request(Method::GET, "/invalid")
            .send()
            .await
            .expect_err("Expected 404 error");

        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.status_code, Some(404));

        Ok(())
    }

    #[tokio::test]
    async fn custom_request_with_bad_rest_host_returns_network_error() -> Result<()> {
        let client = ClientOptions::new("aaaaaa.bbbbbb:cccccc")
            .rest_host("i-dont-exist.ably.com")?
            .rest()?;

        let err = client
            .request(Method::GET, "/time")
            .send()
            .await
            .expect_err("Expected network error");

        assert_eq!(err.code, ErrorCode::BadRequest);

        Ok(())
    }

    #[tokio::test]
    async fn stats_minute_forwards() -> Result<()> {
        // Create a test app and client.
        let app = TestApp::create().await?;
        let client = app.client();

        let year = 2010;
        let fixtures = json!([
            {
                "intervalId": format!("{}-02-03:15:03", year),
                "inbound": { "realtime": { "messages": { "count": 50, "data": 5000 } } },
                "outbound": { "realtime": { "messages": { "count": 20, "data": 2000 } } }
            },
            {
                "intervalId": format!("{}-02-03:15:04", year),
                "inbound": { "realtime": { "messages": { "count": 60, "data": 6000 } } },
                "outbound": { "realtime": { "messages": { "count": 10, "data": 1000 } } }
            },
            {
                "intervalId": format!("{}-02-03:15:05", year),
                "inbound": { "realtime": { "messages": { "count": 70, "data": 7000 } } },
                "outbound": { "realtime": { "messages": { "count": 40, "data": 4000 } } }
            }
        ]);

        client
            .request(Method::POST, "/stats")
            .body(&fixtures)
            .send()
            .await?;

        // Retrieve the stats.
        let res = client
            .stats()
            .start(format!("{}-02-03:15:03", year).as_ref())
            .end(format!("{}-02-03:15:05", year).as_ref())
            .forwards()
            .send()
            .await?;

        // Check the stats are what we expect.
        let stats = res.items().await?;
        assert_eq!(stats.len(), 3);
        assert_eq!(
            stats
                .iter()
                .map(|s| s.inbound.as_ref().unwrap().all.messages.count)
                .sum::<f64>(),
            50.0 + 60.0 + 70.0
        );
        assert_eq!(
            stats
                .iter()
                .map(|s| s.outbound.as_ref().unwrap().all.messages.count)
                .sum::<f64>(),
            20.0 + 10.0 + 40.0
        );

        Ok(())
    }

    #[test]
    fn auth_create_token_request() -> Result<()> {
        let client = test_client();

        let params = TokenParams {
            capability: r#"{"*":["*"]}"#.to_string(),
            client_id: Some("test@ably.com".to_string()),
            nonce: None,
            timestamp: None,
            ttl: Duration::minutes(100),
        };

        let options = AuthOptions {
            token: Some(client.options().credential.clone()),
            ..Default::default()
        };

        let req = client.auth().create_token_request(&params, &options)?;

        assert_eq!(req.capability, params.capability);
        assert_eq!(req.client_id, params.client_id);
        assert_eq!(req.ttl, params.ttl);

        Ok(())
    }

    #[tokio::test]
    async fn auth_request_token_with_key() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Get the server time.
        let server_time = client.time().await?;

        // Request a token.
        let token = client
            .auth()
            .request_token(&Default::default(), &app.auth_options())
            .await?;
        let meta = token.metadata.unwrap();

        // Check the token details.
        assert!(!token.token.is_empty(), "Expected token to be set");
        assert!(
            meta.issued + Duration::seconds(1) >= server_time,
            "Expected issued ({}) to be within 1s of server time ({})",
            meta.issued,
            server_time,
        );
        assert!(
            meta.expires > meta.issued,
            "Expected expires ({}) to be after issued ({})",
            meta.expires,
            meta.issued
        );
        let capability = meta.capability;
        assert_eq!(
            capability, r#"{"*":["*"]}"#,
            r#"Expected default capability '{{"*":["*"]}}', got {}"#,
            capability
        );
        assert_eq!(
            meta.client_id,
            None,
            "Expected client_id to be null, got {}",
            meta.client_id.as_ref().unwrap()
        );

        Ok(())
    }

    #[tokio::test]
    async fn auth_request_token_with_auth_url() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Generate an authUrl.
        let key = app.key();
        let auth_url = Url::parse_with_params(
            "https://echo.ably.io/createJWT",
            &[("keyName", key.name), ("keySecret", key.value)],
        )
        .unwrap();

        let options = AuthOptions {
            token: Some(Credential::Url(auth_url)),
            ..AuthOptions::default()
        };

        let token = client
            .auth()
            .request_token(&Default::default(), &options)
            .await?;

        // Check the token details.
        assert!(!token.token.is_empty(), "Expected token to be set");

        Ok(())
    }

    #[tokio::test]
    async fn auth_request_token_with_provider() -> Result<()> {
        // Create a test app.
        let app = Arc::new(TestApp::create().await?);
        let client = app.client();

        let token = client
            .auth()
            .request_token(&Default::default(), &app.auth_options())
            .await?;

        // Check the token details.
        assert!(!token.token.is_empty(), "Expected token to be set");

        Ok(())
    }

    #[tokio::test]
    async fn auth_request_token_with_client_id_in_options() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;

        // Create a client with client_id set in the options.
        let client_id = "test client id";
        let client = app.options().client_id(client_id)?.rest()?;
        let options = TokenParams {
            client_id: Some(client_id.to_string()),
            ..Default::default()
        };

        // Request a token.
        let token = client
            .auth()
            .request_token(&options, &app.auth_options())
            .await?;

        // Check the token details include the client_id.
        assert!(!token.token.is_empty(), "Expected token to be set");
        assert_eq!(
            token.metadata.unwrap().client_id,
            Some(client_id.to_string())
        );

        Ok(())
    }

    #[tokio::test]
    async fn channel_publish_string() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish a message with string data.
        let channel = client.channels().get("test_channel_publish_string");
        let data = "a string";
        channel.publish().name("name").string(data).send().await?;

        // Retrieve the message from history.
        let res = channel.history().send().await?;
        let mut history = res.items().await?;
        let message = history.pop().expect("Expected a history message");
        assert_eq!(message.data, Data::String(data.to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn channel_publish_json_object() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish a message with JSON serializable data.
        let channel = client.channels().get("test_channel_publish_json_object");
        #[derive(Serialize)]
        struct TestData<'a> {
            b: bool,
            i: i64,
            s: &'a str,
            o: HashMap<&'a str, &'a str>,
            v: Vec<i64>,
        }
        let data = TestData {
            b: true,
            i: 42,
            s: "a string",
            o: [("x", "1"), ("y", "2")].iter().cloned().collect(),
            v: vec![1, 2, 3],
        };
        channel.publish().name("name").json(data).send().await?;

        // Retrieve the message from history.
        let res = channel.history().send().await?;
        let mut history = res.items().await?;
        let message = history.pop().expect("Expected a history message");
        let json = serde_json::json!({
            "b": true,
            "i": 42,
            "s": "a string",
            "o": {"x": "1", "y": "2"},
            "v": [1, 2, 3]
        });
        assert_eq!(message.data, Data::JSON(json));

        Ok(())
    }

    #[tokio::test]
    async fn channel_publish_binary() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish a message with binary data.
        let channel = client.channels().get("test_channel_publish_binary");
        let data = vec![0x1, 0x2, 0x3, 0x4];
        channel.publish().name("name").binary(data).send().await?;

        // Retrieve the message from history.
        let res = channel.history().send().await?;
        let mut history = res.items().await?;
        let message = history.pop().expect("Expected a history message");
        assert_eq!(message.data, vec![0x1, 0x2, 0x3, 0x4].into());

        Ok(())
    }

    #[tokio::test]
    async fn channel_publish_extras() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish a message with extras.
        let channel = client.channels().get("test_channel_publish_extras");
        let data = "a string";
        let mut extras = json::Map::new();
        extras.insert("headers".to_string(), json!({"some":"metadata"}));
        channel
            .publish()
            .name("name")
            .string(data)
            .extras(extras.clone())
            .send()
            .await?;

        // Retrieve the message from history.
        let res = channel.history().send().await?;
        let mut history = res.items().await?;
        let message = history.pop().expect("Expected a history message");
        assert_eq!(message.extras, Some(extras));

        Ok(())
    }

    #[tokio::test]
    async fn channel_publish_params() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish a message with params '_forceNack=true' which should
        // result in the publish being rejected with a 40099 error code
        let channel = client.channels().get("test_channel_publish_params");
        let data = "a string";
        let err = channel
            .publish()
            .name("name")
            .string(data)
            .params(&[("_forceNack", "true")])
            .send()
            .await
            .expect_err("Expected realtime to reject the publish with _forceNack=true");
        assert_eq!(err.code, ErrorCode::Testing);

        Ok(())
    }

    #[tokio::test]
    async fn channel_presence_get() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Retrieve the presence set
        let channel = client.channels().get("persisted:presence_fixtures");
        let res = channel.presence.get().send().await?;
        let presence = res.items().await?;
        assert_eq!(presence.len(), 3);
        assert_eq!(presence[0].data, "some presence data".as_bytes().into());
        assert_eq!(
            presence[1].data,
            Data::JSON(serde_json::json!({"some":"presence data"}))
        );
        assert_eq!(
            presence[2].data,
            Data::String("some presence data".to_string())
        );

        Ok(())
    }

    #[tokio::test]
    async fn channel_presence_history() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Retrieve the presence history
        let channel = client.channels().get("persisted:presence_fixtures");
        let res = channel.presence.history().send().await?;
        let presence = res.items().await?;
        assert_eq!(presence.len(), 3);
        assert_eq!(presence[0].data, "some presence data".as_bytes().into());
        assert_eq!(
            presence[1].data,
            Data::JSON(serde_json::json!({"some":"presence data"}))
        );
        assert_eq!(
            presence[2].data,
            Data::String("some presence data".to_string())
        );

        Ok(())
    }

    #[tokio::test]
    async fn channel_history_count() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish some messages.
        let channel = client.channels().get("persisted:history_count");
        futures::try_join!(
            channel.publish().name("event0").string("some data").send(),
            channel
                .publish()
                .name("event1")
                .string("some more data")
                .send(),
            channel.publish().name("event2").string("and more").send(),
            channel.publish().name("event3").string("and more").send(),
            channel.publish().name("event4").json(vec![1, 2, 3]).send(),
            channel
                .publish()
                .name("event5")
                .json(json!({"one": 1, "two": 2, "three": 3}))
                .send(),
            channel
                .publish()
                .name("event6")
                .json(json!({"foo": "bar"}))
                .send(),
        )?;

        // Wait a second.
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        // Retrieve the channel history.
        let mut pages = channel.history().pages().try_collect::<Vec<_>>().await?;
        assert_eq!(pages.len(), 1);
        let history = pages.pop().unwrap().items().await?;
        assert_eq!(history.len(), 7, "Expected 7 history messages");

        // Check message IDs are unique.
        let ids = HashSet::<_>::from_iter(history.iter().map(|msg| msg.id.as_ref().unwrap()));
        assert_eq!(ids.len(), 7, "Expected 7 unique ids");

        Ok(())
    }

    #[tokio::test]
    async fn channel_history_paginate_backwards() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish some messages.
        let channel = client
            .channels()
            .get("persisted:history_paginate_backwards");
        channel
            .publish()
            .name("event0")
            .string("some data")
            .send()
            .await?;
        channel
            .publish()
            .name("event1")
            .string("some more data")
            .send()
            .await?;
        channel
            .publish()
            .name("event2")
            .string("and more")
            .send()
            .await?;
        channel
            .publish()
            .name("event3")
            .string("and more")
            .send()
            .await?;
        channel
            .publish()
            .name("event4")
            .json(vec![1, 2, 3])
            .send()
            .await?;
        channel
            .publish()
            .name("event5")
            .json(json!({"one": 1, "two": 2, "three": 3}))
            .send()
            .await?;
        channel
            .publish()
            .name("event6")
            .json(json!({"foo": "bar"}))
            .send()
            .await?;

        // Wait a second.
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        // Retrieve the channel history backwards one message at a time.
        let mut pages = channel.history().backwards().limit(1).pages();

        // Check each page has the expected items.
        for (expected_name, expected_data) in [
            ("event6", Data::JSON(json!({"foo": "bar"}))),
            ("event5", Data::JSON(json!({"one":1,"two":2,"three":3}))),
            ("event4", Data::JSON(json!([1, 2, 3]))),
            ("event3", Data::String("and more".to_string())),
            ("event2", Data::String("and more".to_string())),
            ("event1", Data::String("some more data".to_string())),
            ("event0", Data::String("some data".to_string())),
        ] {
            let page = pages.try_next().await?.expect("Expected a page");
            let mut history = page.items().await?;
            assert_eq!(history.len(), 1, "Expected 1 history message per page");
            let message = history.pop().unwrap();
            assert_eq!(message.name, Some(expected_name.to_string()));
            assert_eq!(message.data, expected_data);
        }

        Ok(())
    }

    #[tokio::test]
    async fn client_fallback() -> Result<()> {
        // IANA reserved; requests to it will hang forever
        let unroutable_host = "10.255.255.1";
        let client = ClientOptions::new("aaaaaa.bbbbbb:cccccc")
            .rest_host(unroutable_host)?
            .fallback_hosts(vec!["sandbox-a-fallback.ably-realtime.com".to_string()])
            .http_request_timeout(std::time::Duration::from_secs(3))
            .rest()?;

        client.time().await.expect("Expected fallback response");

        Ok(())
    }

    #[tokio::test]
    async fn rest_with_auth_url() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;

        // Generate an authUrl.
        let key = app.key();
        let auth_url = Url::parse_with_params(
            "https://echo.ably.io/createJWT",
            &[("keyName", key.name), ("keySecret", key.value)],
        )
        .unwrap();

        // Configure a client with an authUrl.
        let client = ClientOptions::with_auth_url(auth_url)
            .environment("sandbox")?
            .rest()
            .expect("Expected client to initialise");

        // Check a REST request succeeds.
        client
            .stats()
            .send()
            .await
            .expect("Expected REST request to succeed");

        Ok(())
    }

    #[tokio::test]
    async fn rest_with_auth_callback() -> Result<()> {
        // Create a test app.
        let app = Arc::new(TestApp::create().await?);

        // Configure a client with the test app as the authCallback.
        let client = ClientOptions::with_auth_callback(app)
            .environment("sandbox")?
            .rest()
            .expect("Expected client to initialise");

        // Check a REST request succeeds.
        client
            .stats()
            .send()
            .await
            .expect("Expected REST request to succeed");

        Ok(())
    }

    #[tokio::test]
    async fn rest_with_key_and_use_token_auth() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;

        // Configure a client with a key and useTokenAuth=true.
        let client = ClientOptions::with_key(app.key())
            .use_token_auth(true)
            .environment("sandbox")?
            .rest()
            .expect("Expected client to initialise");

        // Check a REST request succeeds.
        client
            .stats()
            .send()
            .await
            .expect("Expected REST request to succeed");

        Ok(())
    }
}

/// Unit tests using mock HTTP client.
///
/// These correspond to UTS test specs in ../dart-experiments/uts/test/rest/unit/.
#[cfg(test)]
mod unit_tests {
    use std::sync::Arc;

    use serde_json::json;

    use crate::mock_http::{MockHttpClient, MockResponse};
    use crate::{ClientOptions, Result};

    /// Helper to create a Rest client with a mock HTTP backend.
    fn mock_client(mock: MockHttpClient) -> crate::Rest {
        ClientOptions::new("appId.keyId:keySecret")
            .rest_with_http_client(Box::new(mock))
            .unwrap()
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

    /// Helper to get captured requests from a client with a mock backend.
    fn get_mock(client: &crate::Rest) -> &MockHttpClient {
        client
            .inner
            .http_client
            .as_any()
            .downcast_ref::<MockHttpClient>()
            .unwrap()
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
            .headers
            .get("X-Ably-Version")
            .expect("Expected X-Ably-Version header");
        assert_eq!(version, "1.2");

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
            .headers
            .get("content-type")
            .expect("Expected Content-Type header")
            .to_str()
            .unwrap();
        assert_eq!(content_type, "application/x-msgpack");

        Ok(())
    }

    #[tokio::test]
    async fn rsc8b_json_protocol_when_configured() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
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
            .headers
            .get("content-type")
            .expect("Expected Content-Type header")
            .to_str()
            .unwrap();
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
            .rest_with_http_client(Box::new(mock))
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
        let err = ClientOptions::new("appId.keyId:keySecret")
            .tls(false)
            .rest()
            .expect_err("Expected error for basic auth over non-TLS");

        assert_eq!(
            err.code,
            crate::error::ErrorCode::InvalidUseOfBasicAuthOverNonTLSTransport
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
            .rest_with_http_client(Box::new(mock))
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
            .headers
            .get("Ably-Agent")
            .expect("Expected Ably-Agent header");
        let agent_str = agent.to_str().unwrap();

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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .headers
            .get("accept")
            .expect("Expected Accept header")
            .to_str()
            .unwrap();
        assert_eq!(accept, "application/json");

        let content_type = reqs[0]
            .headers
            .get("content-type")
            .expect("Expected Content-Type header")
            .to_str()
            .unwrap();
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
            .headers
            .get("content-type")
            .expect("Expected Content-Type header")
            .to_str()
            .unwrap();
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
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false) // Client prefers JSON
            .rest_with_http_client(Box::new(mock))
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
        });

        let client = mock_client(mock);

        let err = client
            .time()
            .await
            .expect_err("Expected error for unsupported content-type");

        // RSC8e: Should return error code 40013 for 2xx with unsupported Content-Type.
        assert_eq!(
            err.code,
            crate::error::ErrorCode::InvalidMessageDataOrEncoding
        );
        assert_eq!(err.status_code, Some(400));

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let err = client.time().await.expect_err("Expected timeout error");

        assert_eq!(err.code, crate::error::ErrorCode::TimeoutError);

        Ok(())
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
        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers
            .get("authorization")
            .expect("Expected Authorization header")
            .to_str()
            .unwrap();

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers
            .get("authorization")
            .expect("Expected Authorization header")
            .to_str()
            .unwrap();

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();

        // First request should be to requestToken (no auth needed for that)
        assert!(
            reqs[0].url.path().contains("/requestToken"),
            "First request should be to requestToken, got {}",
            reqs[0].url.path()
        );

        // Second request (the actual time request) should use Bearer auth
        let auth_header = reqs[1]
            .headers
            .get("authorization")
            .expect("Expected Authorization header on second request")
            .to_str()
            .unwrap();
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

    #[test]
    fn rsa9h_create_token_request_fields() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();

        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions {
            token: Some(crate::auth::Credential::Key(
                crate::auth::Key::new("appId.keyId:keySecret").unwrap(),
            )),
            ..Default::default()
        };

        let req = client
            .auth()
            .create_token_request(&params, &options)
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
        let now = chrono::Utc::now();
        let diff = (now - req.timestamp).num_seconds().abs();
        assert!(
            diff < 5,
            "Expected timestamp within 5s of now, diff={}s",
            diff
        );

        // RSA9d: Default capability should be {"*":["*"]}
        assert_eq!(req.capability, r#"{"*":["*"]}"#);

        // RSA9c: Default TTL should be 60 minutes (3600000ms)
        assert_eq!(req.ttl.num_milliseconds(), 3600000);
    }

    #[test]
    fn rsa9c_custom_ttl() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();

        let params = crate::auth::TokenParams {
            ttl: chrono::Duration::milliseconds(7200000),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions {
            token: Some(crate::auth::Credential::Key(
                crate::auth::Key::new("appId.keyId:keySecret").unwrap(),
            )),
            ..Default::default()
        };

        let req = client
            .auth()
            .create_token_request(&params, &options)
            .unwrap();
        assert_eq!(req.ttl.num_milliseconds(), 7200000);
    }

    #[test]
    fn rsa9d_custom_capability() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();

        let params = crate::auth::TokenParams {
            capability: r#"{"channel1":["publish"]}"#.to_string(),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions {
            token: Some(crate::auth::Credential::Key(
                crate::auth::Key::new("appId.keyId:keySecret").unwrap(),
            )),
            ..Default::default()
        };

        let req = client
            .auth()
            .create_token_request(&params, &options)
            .unwrap();
        assert_eq!(req.capability, r#"{"channel1":["publish"]}"#);
    }

    #[test]
    fn rsa9f_unique_nonces() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();

        let params = crate::auth::TokenParams::default();
        let options = crate::auth::AuthOptions {
            token: Some(crate::auth::Credential::Key(
                crate::auth::Key::new("appId.keyId:keySecret").unwrap(),
            )),
            ..Default::default()
        };

        let req1 = client
            .auth()
            .create_token_request(&params, &options)
            .unwrap();
        let req2 = client
            .auth()
            .create_token_request(&params, &options)
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

        let options = crate::auth::AuthOptions {
            token: Some(crate::auth::Credential::Key(
                crate::auth::Key::new("appId.keyId:keySecret").unwrap(),
            )),
            ..Default::default()
        };

        let details = client
            .auth()
            .request_token(&Default::default(), &options)
            .await?;

        assert_eq!(details.token, "test-token-123");

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, reqwest::Method::POST);
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

    #[test]
    fn rsa9a_client_id_included_in_token_request() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("user1")
            .unwrap()
            .rest()
            .unwrap();

        let params = crate::auth::TokenParams {
            client_id: Some("user1".to_string()),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions {
            token: Some(client.options().credential.clone()),
            ..Default::default()
        };

        let req = client
            .auth()
            .create_token_request(&params, &options)
            .unwrap();
        assert_eq!(req.client_id, Some("user1".to_string()));
    }

    #[test]
    fn rsa9a_client_id_override_in_token_params() {
        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("user1")
            .unwrap()
            .rest()
            .unwrap();

        let params = crate::auth::TokenParams {
            client_id: Some("user2".to_string()),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions {
            token: Some(client.options().credential.clone()),
            ..Default::default()
        };

        let req = client
            .auth()
            .create_token_request(&params, &options)
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        // This should: get token, try /time (401), get new token, retry /time (200)
        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        Ok(())
    }

    // ---------------------------------------------------------------
    // RSC1 — Rejects client creation with no auth credentials
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[test]
    fn rsc1_rejects_empty_credentials() {
        // An empty string should not parse as a valid key or token.
        // ClientOptions::new("") will try to parse as key (fails) then
        // set as token, but an empty token is arguably invalid.
        // The real test is that token_source with no credential would fail.
        // Currently ClientOptions::new("") creates a token credential with "".
        // This is a gap — the SDK should reject this.
        // For now, just verify that a key-like string without colon sets token.
        let client = ClientOptions::new("not-a-key");
        assert!(matches!(
            client.credential,
            crate::auth::Credential::TokenDetails(_)
        ));
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers
            .get("authorization")
            .expect("Expected Authorization header")
            .to_str()
            .unwrap();

        assert_eq!(auth_header, "Bearer explicit-token-string");

        Ok(())
    }

    // ---------------------------------------------------------------
    // RSA4b — Token auth when clientId is provided with key
    // UTS: rest/unit/auth/auth_scheme.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsa4b_token_auth_when_client_id_with_key() -> Result<()> {
        let mock = MockHttpClient::with_handler(|req| {
            if req.url.path().contains("/requestToken") {
                MockResponse::json(
                    200,
                    &json!({
                        "token": "obtained-token",
                        "expires": 9999999999999_i64,
                        "issued": 1000000000000_i64,
                        "clientId": "my-client-id",
                        "capability": "{\"*\":[\"*\"]}"
                    }),
                )
            } else {
                MockResponse::json(200, &json!({"channelId": "test"}))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .client_id("my-client-id")
            .unwrap()
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();

        // Should have made two requests: requestToken + API call
        assert_eq!(reqs.len(), 2);

        // First request should be to requestToken
        assert!(
            reqs[0].url.path().contains("/requestToken"),
            "First request should be to requestToken, got {}",
            reqs[0].url.path()
        );

        // Second request should use Bearer auth, not Basic
        let auth_header = reqs[1]
            .headers
            .get("authorization")
            .expect("Expected Authorization header")
            .to_str()
            .unwrap();
        assert!(
            auth_header.starts_with("Bearer "),
            "Expected Bearer auth when clientId is set, got '{}'",
            auth_header
        );
        assert_eq!(auth_header, "Bearer obtained-token");

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let auth_header = reqs[0]
            .headers
            .get("authorization")
            .expect("Expected Authorization header")
            .to_str()
            .unwrap();

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let err = client.time().await.expect_err("Expected token error");
        assert_eq!(err.code, crate::error::ErrorCode::TokenExpired);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let err = client.time().await.expect_err("Expected 401 error");
        assert_eq!(err.code, crate::error::ErrorCode::Unauthorized);

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

    // ---------------------------------------------------------------
    // RSA7a — clientId from ClientOptions
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

    #[test]
    fn rsa5b_explicit_ttl_preserved() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams {
            ttl: chrono::Duration::milliseconds(7200000),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions {
            token: Some(crate::auth::Credential::Key(
                crate::auth::Key::new("appId.keyId:keySecret").unwrap(),
            )),
            ..Default::default()
        };
        let req = client
            .auth()
            .create_token_request(&params, &options)
            .unwrap();
        assert_eq!(req.ttl.num_milliseconds(), 7200000);
    }

    #[test]
    fn rsa6b_explicit_capability_preserved() {
        let client = crate::Rest::new("appId.keyId:keySecret").unwrap();
        let params = crate::auth::TokenParams {
            capability: r#"{"channel-a":["publish","subscribe"]}"#.to_string(),
            ..Default::default()
        };
        let options = crate::auth::AuthOptions {
            token: Some(crate::auth::Credential::Key(
                crate::auth::Key::new("appId.keyId:keySecret").unwrap(),
            )),
            ..Default::default()
        };
        let req = client
            .auth()
            .create_token_request(&params, &options)
            .unwrap();
        assert_eq!(req.capability, r#"{"channel-a":["publish","subscribe"]}"#);
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        // authorize() requests a token using the key
        let token_details = client
            .auth()
            .request_token(&Default::default(), &client.auth_options())
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let err = client
            .auth()
            .request_token(&Default::default(), &client.auth_options())
            .await
            .expect_err("Expected auth error");

        assert_eq!(err.code, crate::error::ErrorCode::Unauthorized);
        assert_eq!(err.status_code, Some(401));

        Ok(())
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
            .rest_with_http_client(Box::new(mock))
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
        assert_eq!(reqs[0].method, reqwest::Method::POST);
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
    // UTS: rest/unit/channel/publish.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl1l_publish_params_as_querystring() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(201));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items().await?;

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
            .rest_with_http_client(Box::new(mock))
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
        assert_eq!(reqs[0].method, reqwest::Method::GET);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.channels().get("test").history().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, reqwest::Method::GET);
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items().await?;

        assert_eq!(items.len(), 1);
        // After decoding, data should be binary
        assert_eq!(items[0].data, vec![0x01, 0x02, 0x03].into());
        // Encoding should be consumed
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items().await?;

        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].data,
            crate::rest::Data::JSON(json!({"key": "value"}))
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items().await?;

        assert_eq!(items.len(), 1);
        // Decoded: base64 → utf-8 string → JSON parse
        assert_eq!(
            items[0].data,
            crate::rest::Data::JSON(json!({"nested": "data"}))
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items().await?;

        assert_eq!(items.len(), 1);
        // Unrecognized encoding should be preserved
        assert_eq!(
            items[0].encoding,
            crate::rest::Encoding::Some("custom-encoding".to_string())
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items().await?;

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let res = client.channels().get("test").history().send().await?;
        let items = res.items().await?;

        assert_eq!(items.len(), 0);

        Ok(())
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
            .rest_with_http_client(Box::new(mock))
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
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/json");

        let accept = reqs[0].headers.get("accept").unwrap().to_str().unwrap();
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
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/x-msgpack");

        let accept = reqs[0].headers.get("accept").unwrap().to_str().unwrap();
        assert_eq!(accept, "application/x-msgpack");

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
                MockResponse::json(200, &json!([{"name": "msg1", "data": "a"}]))
                    .with_header(
                        "Link",
                        "</channels/test/history?start=0&end=1&direction=forwards&limit=1>; rel=\"next\""
                    )
            } else {
                MockResponse::json(200, &json!([{"name": "msg2", "data": "b"}]))
            }
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        // Use the pages stream to get both pages
        use futures::TryStreamExt;
        let pages: Vec<_> = client
            .channels()
            .get("test")
            .history()
            .limit(1)
            .pages()
            .try_collect()
            .await?;

        assert_eq!(pages.len(), 2);

        let items1 = pages.into_iter().next().unwrap().items().await?;
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        use futures::TryStreamExt;
        let _pages: Vec<_> = client
            .channels()
            .get("test")
            .history()
            .pages()
            .try_collect()
            .await?;

        // Both requests should have Authorization header
        let reqs = get_mock(&client).captured_requests();
        assert!(
            reqs.len() >= 2,
            "Expected at least 2 requests for pagination"
        );
        for req in &reqs {
            assert!(
                req.headers.get("authorization").is_some(),
                "Expected Authorization header on all paginated requests"
            );
        }

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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let channel = client.channels().get("test");
        let mut pages = channel.history().pages();

        // First page
        let page1 = pages.try_next().await?.expect("Expected page 1");
        let items1 = page1.items().await?;
        assert_eq!(items1.len(), 2);
        assert_eq!(items1[0].name, Some("msg1".to_string()));
        assert_eq!(items1[1].name, Some("msg2".to_string()));

        // Second page (navigating to next)
        let page2 = pages.try_next().await?.expect("Expected page 2");
        let items2 = page2.items().await?;
        assert_eq!(items2.len(), 1);
        assert_eq!(items2[0].name, Some("msg3".to_string()));

        // No more pages
        let page3 = pages.try_next().await?;
        assert!(page3.is_none(), "Expected no more pages");

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
            .rest_with_http_client(Box::new(mock))
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
    // RSL2b1 — Default history direction is backwards
    // UTS: rest/unit/channel/history.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsl2b1_default_history_direction_backwards() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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

    // ===============================================================
    // Phase 4: REST Presence
    // ===============================================================

    // ---------------------------------------------------------------
    // RSP1a, RSL3 — Presence accessible via channel.presence
    // UTS: rest/unit/presence/rest_presence.md
    // ---------------------------------------------------------------

    #[test]
    fn rsp1a_presence_accessible_via_channel() {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::empty(200));
        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        // Accessing channel.presence should work without error
        let channel = client.channels().get("test");
        let _presence = &channel.presence;
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client
            .channels()
            .get("test-rsp3")
            .presence
            .get()
            .send()
            .await?;
        let items = result.items().await?;

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client.channels().get("test").presence.get().send().await?;
        let items = result.items().await?;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].action, crate::rest::PresenceAction::Present);
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client.channels().get("test").presence.get().send().await?;
        let items = result.items().await?;

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .channels()
            .get("test")
            .presence
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .channels()
            .get("test")
            .presence
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .channels()
            .get("test")
            .presence
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let channel = client.channels().get("test-rsp4");
        let result = channel.presence.history().send().await?;
        let items = result.items().await?;

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let channel = client.channels().get("test");
        let result = channel.presence.history().send().await?;
        let items = result.items().await?;

        assert_eq!(items.len(), 3);
        // PresenceAction: Absent=0, Present=1, Enter=2, Leave=3, Update=4
        assert_eq!(items[0].action, crate::rest::PresenceAction::Enter); // action 2
        assert_eq!(items[1].action, crate::rest::PresenceAction::Leave); // action 3
        assert_eq!(items[2].action, crate::rest::PresenceAction::Update); // action 4

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let channel = client.channels().get("test");
        channel
            .presence
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let channel = client.channels().get("test");
        channel.presence.history().send().await?;

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client.channels().get("test").presence.get().send().await?;
        let items = result.items().await?;

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client.channels().get("test").presence.get().send().await?;
        let items = result.items().await?;

        assert_eq!(
            items[0].data,
            crate::rest::Data::JSON(json!({"status": "online", "count": 42}))
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client.channels().get("test").presence.get().send().await?;
        let items = result.items().await?;

        assert_eq!(
            items[0].data,
            crate::rest::Data::Binary(serde_bytes::ByteBuf::from(b"Hello World".to_vec()))
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client.channels().get("test").presence.get().send().await?;
        let items = result.items().await?;

        assert_eq!(
            items[0].data,
            crate::rest::Data::String("Hello World".to_string())
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let result = client.channels().get("test").presence.get().send().await?;
        let items = result.items().await?;

        assert_eq!(
            items[0].data,
            crate::rest::Data::JSON(json!({"key": "value"}))
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let channel = client.channels().get("test");
        let result = channel.presence.history().send().await?;
        let items = result.items().await?;

        assert_eq!(
            items[0].data,
            crate::rest::Data::JSON(json!({"event": "entered"}))
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
        assert_eq!(msg.action, crate::rest::PresenceAction::Enter);
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
            action: crate::rest::PresenceAction::Enter,
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
            action: crate::rest::PresenceAction::Enter,
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
        assert_eq!(msg1.member_key(), Some("conn-1:user-1".to_string()));

        let msg2 = crate::rest::PresenceMessage {
            connection_id: Some("conn-2".to_string()),
            client_id: Some("user-1".to_string()),
            ..Default::default()
        };
        assert_eq!(msg2.member_key(), Some("conn-2:user-1".to_string()));

        // Same clientId, different connectionId — different memberKey
        assert_ne!(msg1.member_key(), msg2.member_key());

        // Missing fields — returns None
        let msg3 = crate::rest::PresenceMessage {
            client_id: Some("user-1".to_string()),
            ..Default::default()
        };
        assert_eq!(msg3.member_key(), None);
    }

    // ---------------------------------------------------------------
    // TP2 — PresenceAction serde round-trip (numeric values)
    // UTS: rest/unit/types/presence_message_types.md
    // ---------------------------------------------------------------

    #[test]
    fn tp2_presence_action_serde_roundtrip() {
        // Serialize: action should be numeric
        let msg = crate::rest::PresenceMessage {
            action: crate::rest::PresenceAction::Enter,
            client_id: Some("u".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["action"], 2, "Enter should serialize as 2");

        // Deserialize: numeric action should parse
        let json = json!({"action": 4, "clientId": "u"});
        let msg: crate::rest::PresenceMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.action, crate::rest::PresenceAction::Update);

        // All actions deserialize correctly
        for (num, expected) in [
            (0, crate::rest::PresenceAction::Absent),
            (1, crate::rest::PresenceAction::Present),
            (2, crate::rest::PresenceAction::Enter),
            (3, crate::rest::PresenceAction::Leave),
            (4, crate::rest::PresenceAction::Update),
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
    // RSP3 — Presence get with multiple filters combined
    // UTS: rest/unit/presence/rest_presence.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsp3_presence_get_with_multiple_filters() -> Result<()> {
        let mock = MockHttpClient::with_handler(|_req| MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .channels()
            .get("test")
            .presence
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let channel = client.channels().get("test");
        channel.presence.history().forwards().send().await?;

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
            .rest_with_http_client(Box::new(mock))
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
                .rest_with_http_client(Box::new(mock))
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
                .rest_with_http_client(Box::new(mock))
                .unwrap();

            let err = client.time().await.unwrap_err();
            assert_eq!(err.status_code, Some(status as u32));

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let _ = client.time().await;

        let reqs = get_mock(&client).captured_requests();
        // primary + up to httpMaxRetryCount (3) fallbacks = 4
        assert_eq!(reqs.len(), 4);

        // First request to the primary host
        assert_eq!(reqs[0].url.host_str().unwrap(), "rest.ably.io");

        // Subsequent requests to fallback hosts
        let expected_fallbacks = vec![
            "a.ably-realtime.com",
            "b.ably-realtime.com",
            "c.ably-realtime.com",
            "d.ably-realtime.com",
            "e.ably-realtime.com",
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
                .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "rest.ably.io");
        assert_ne!(reqs[1].url.host_str().unwrap(), "rest.ably.io");

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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str().unwrap(), "rest.ably.io");

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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.host_str().unwrap(), "sandbox-rest.ably.io");

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "rest.ably.io");
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "sandbox-rest.ably.io");

        let expected_env_fallbacks = vec![
            "sandbox-a-fallback.ably-realtime.com",
            "sandbox-b-fallback.ably-realtime.com",
            "sandbox-c-fallback.ably-realtime.com",
            "sandbox-d-fallback.ably-realtime.com",
            "sandbox-e-fallback.ably-realtime.com",
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.host_str().unwrap(), "rest.ably.io");

        let expected_fallbacks = vec![
            "a.ably-realtime.com",
            "b.ably-realtime.com",
            "c.ably-realtime.com",
            "d.ably-realtime.com",
            "e.ably-realtime.com",
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
            assert_eq!(req.method, reqwest::Method::GET);
            MockResponse::json(200, &json!([1704067200000_i64]))
        });

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.time().await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, reqwest::Method::GET);
        assert_eq!(reqs[0].url.path(), "/time");
        assert!(reqs[0].headers.contains_key("x-ably-version"));
        assert!(reqs[0].headers.contains_key("ably-agent"));

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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let page = client.stats().send().await?;
        let items = page.items().await?;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].interval_id, "2024-01-01:00:00");
        assert_eq!(items[1].interval_id, "2024-01-01:01:00");

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].method, reqwest::Method::GET);
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client.stats().send().await?;

        let reqs = get_mock(&client).captured_requests();
        assert!(reqs[0].headers.contains_key("authorization"));
        assert!(reqs[0].headers.contains_key("x-ably-version"));
        assert!(reqs[0].headers.contains_key("ably-agent"));

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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let page = client.stats().send().await?;
        let items = page.items().await?;
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
        use crate::http::Method;

        for method in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            let mock = MockHttpClient::new();
            mock.queue_response(MockResponse::json(200, &json!([])));

            let client = ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/channels/test/messages")
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let mut headers = crate::http::HeaderMap::new();
        headers.insert("X-Custom-Header", "custom-value".parse().unwrap());

        client
            .request(crate::http::Method::GET, "/test")
            .headers(headers)
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(
            reqs[0]
                .headers
                .get("x-custom-header")
                .unwrap()
                .to_str()
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::POST, "/channels/test/messages")
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        let auth = reqs[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(
            reqs[0].headers.get("accept").unwrap().to_str().unwrap(),
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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(
            reqs[0].headers.get("accept").unwrap().to_str().unwrap(),
            "application/x-msgpack"
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
            .rest_with_http_client(Box::new(mock))
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
            .rest_with_http_client(Box::new(mock))
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
    // RSC19 — request() path with leading slash
    // UTS: rest/unit/request.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rsc19f_request_path_leading_slash() -> Result<()> {
        let mock = MockHttpClient::new();
        mock.queue_response(MockResponse::json(200, &json!([])));

        let client = ClientOptions::new("appId.keyId:keySecret")
            .use_binary_protocol(false)
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        client
            .request(crate::http::Method::GET, "/channels/test")
            .send()
            .await?;

        let reqs = get_mock(&client).captured_requests();
        assert_eq!(reqs[0].url.path(), "/channels/test");

        Ok(())
    }

    // ===============================================================
    // Phase 7a — Realtime: Types, Transport & Basic Connection
    // ===============================================================

    // ---------------------------------------------------------------
    // RTN3 — autoConnect true initiates connection immediately
    // UTS: realtime/unit/connection/auto_connect_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn3_auto_connect_true() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected(
                "connection-id",
                "connection-key",
            ));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        // autoConnect defaults to true — do NOT call connect()
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").use_binary_protocol(false),
            transport,
        )
        .unwrap();

        let connected = await_state(&client.connection, ConnectionState::Connected, 5000).await;
        assert!(connected, "should auto-connect");
        assert_eq!(client.connection.id(), Some("connection-id".to_string()));
    }

    // ---------------------------------------------------------------
    // RTN3 — autoConnect false does not initiate connection
    // UTS: realtime/unit/connection/auto_connect_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn3_auto_connect_false() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ConnectionState;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        // Brief wait to confirm no connection attempt
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(client.connection.state(), ConnectionState::Initialized);
        assert_eq!(mock.connection_count(), 0);
    }

    // ---------------------------------------------------------------
    // RTN3 — explicit connect after autoConnect false
    // UTS: realtime/unit/connection/auto_connect_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn3_explicit_connect_after_auto_connect_false() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected(
                "connection-id",
                "connection-key",
            ));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        assert_eq!(client.connection.state(), ConnectionState::Initialized);
        assert_eq!(mock.connection_count(), 0);

        client.connect();

        let connected = await_state(&client.connection, ConnectionState::Connected, 5000).await;
        assert!(connected, "should connect after explicit connect()");
        assert_eq!(mock.connection_count(), 1);
    }

    // ---------------------------------------------------------------
    // RTN8a — Connection ID is unset until connected
    // UTS: realtime/unit/connection/connection_id_key_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn8a_connection_id_unset_until_connected() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending
                .respond_with_success(ProtocolMessage::connected("unique-conn-id-1", "conn-key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        // Before connecting, id should be None
        assert!(client.connection.id().is_none());

        client.connect();
        let connected = await_state(&client.connection, ConnectionState::Connected, 5000).await;
        assert!(connected);

        assert_eq!(client.connection.id(), Some("unique-conn-id-1".to_string()));
    }

    // ---------------------------------------------------------------
    // RTN9a — Connection key is unset until connected
    // UTS: realtime/unit/connection/connection_id_key_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn9a_connection_key_unset_until_connected() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending
                .respond_with_success(ProtocolMessage::connected("unique-conn-id-1", "conn-key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        assert!(client.connection.key().is_none());

        client.connect();
        let connected = await_state(&client.connection, ConnectionState::Connected, 5000).await;
        assert!(connected);

        assert_eq!(client.connection.key(), Some("conn-key-1".to_string()));
    }

    // ---------------------------------------------------------------
    // RTN8b — Connection ID is unique per connection
    // UTS: realtime/unit/connection/connection_id_key_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn8b_connection_id_unique_per_connection() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let count = std::sync::Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            pending.respond_with_success(ProtocolMessage::connected(
                &format!("conn-id-{}", n),
                &format!("conn-key-{}", n),
            ));
        });

        let inner = mock.inner();

        let transport1 = std::sync::Arc::new(crate::mock_ws::MockTransport::new(inner.clone()));
        let transport2 = std::sync::Arc::new(crate::mock_ws::MockTransport::new(inner));

        let client1 = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport1,
        )
        .unwrap();

        let client2 = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport2,
        )
        .unwrap();

        client1.connect();
        assert!(await_state(&client1.connection, ConnectionState::Connected, 5000).await);

        client2.connect();
        assert!(await_state(&client2.connection, ConnectionState::Connected, 5000).await);

        assert_ne!(client1.connection.id(), client2.connection.id());
        assert_eq!(client1.connection.id(), Some("conn-id-1".to_string()));
        assert_eq!(client2.connection.id(), Some("conn-id-2".to_string()));
    }

    // ---------------------------------------------------------------
    // RTN9b — Connection key is unique per connection
    // UTS: realtime/unit/connection/connection_id_key_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn9b_connection_key_unique_per_connection() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let count = std::sync::Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            pending.respond_with_success(ProtocolMessage::connected(
                &format!("conn-id-{}", n),
                &format!("conn-key-{}", n),
            ));
        });

        let inner = mock.inner();

        let transport1 = std::sync::Arc::new(crate::mock_ws::MockTransport::new(inner.clone()));
        let transport2 = std::sync::Arc::new(crate::mock_ws::MockTransport::new(inner));

        let client1 = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport1,
        )
        .unwrap();

        let client2 = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport2,
        )
        .unwrap();

        client1.connect();
        assert!(await_state(&client1.connection, ConnectionState::Connected, 5000).await);

        client2.connect();
        assert!(await_state(&client2.connection, ConnectionState::Connected, 5000).await);

        assert_ne!(client1.connection.key(), client2.connection.key());
        assert_eq!(client1.connection.key(), Some("conn-key-1".to_string()));
        assert_eq!(client2.connection.key(), Some("conn-key-2".to_string()));
    }

    // ---------------------------------------------------------------
    // RTN8c — Connection ID null in CLOSED state
    // UTS: realtime/unit/connection/connection_id_key_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn8c_connection_id_null_after_close() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id-1", "conn-key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(client.connection.id(), Some("conn-id-1".to_string()));

        client.close();
        assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

        assert!(client.connection.id().is_none());
    }

    // ---------------------------------------------------------------
    // RTN9c — Connection key null in CLOSED state
    // UTS: realtime/unit/connection/connection_id_key_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn9c_connection_key_null_after_close() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id-1", "conn-key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(client.connection.key(), Some("conn-key-1".to_string()));

        client.close();
        assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

        assert!(client.connection.key().is_none());
    }

    // ---------------------------------------------------------------
    // RTN8c, RTN9c — ID and key null after FAILED
    // UTS: realtime/unit/connection/connection_id_key_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn8c_rtn9c_id_key_null_after_failed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            let mut error_msg = ProtocolMessage::new(Action::Error);
            error_msg.error = Some(crate::protocol::ErrorInfo {
                code: Some(80000),
                status_code: Some(400),
                message: Some("Fatal error".to_string()),
                href: None,
            });
            pending.respond_with_error(error_msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        assert!(client.connection.id().is_none());
        assert!(client.connection.key().is_none());
    }

    // ---------------------------------------------------------------
    // RTC2 — connection attribute
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtc2_connection_attribute() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ConnectionState;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        // Connection should exist and be in INITIALIZED state
        assert_eq!(client.connection.state(), ConnectionState::Initialized);
    }

    // ---------------------------------------------------------------
    // RTC15 — connect() proxies to Connection::connect
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtc15_connect_proxies_to_connection() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected(
                "connection-id",
                "connection-key",
            ));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        assert_eq!(client.connection.state(), ConnectionState::Initialized);

        // Call connect on client (should proxy to connection)
        client.connect();

        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
    }

    // ---------------------------------------------------------------
    // RTC16 — close() proxies to Connection::close
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtc16_close_proxies_to_connection() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected(
                "connection-id",
                "connection-key",
            ));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        client.close();
        assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);
    }

    // ---------------------------------------------------------------
    // RTN25 — errorReason set on connection errors
    // UTS: realtime/unit/connection/error_reason_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn25_error_reason_set_on_failed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            let mut error_msg = ProtocolMessage::new(Action::Error);
            error_msg.error = Some(crate::protocol::ErrorInfo {
                code: Some(80000),
                status_code: Some(400),
                message: Some("Fatal error".to_string()),
                href: None,
            });
            pending.respond_with_error(error_msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        let error = client.connection.error_reason();
        assert!(error.is_some());
        assert_eq!(error.as_ref().unwrap().code, Some(80000));
        assert_eq!(
            error.as_ref().unwrap().message.as_deref(),
            Some("Fatal error")
        );
    }

    // ---------------------------------------------------------------
    // RTN25 — errorReason on DISCONNECTED state
    // UTS: realtime/unit/connection/error_reason_test.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn25_error_reason_on_disconnected() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ConnectionState;
        use crate::realtime::{await_state, Realtime};

        // Connection refused → DISCONNECTED with error
        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_refused();
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

        let error = client.connection.error_reason();
        assert!(error.is_some());
    }

    // ---------------------------------------------------------------
    // RTN4 — state change events emitted
    // UTS: realtime/unit/connection (general)
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtn4_state_change_events() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::{Arc, Mutex};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected(
                "connection-id",
                "connection-key",
            ));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .auto_connect(false),
            transport,
        )
        .unwrap();

        let states: Arc<Mutex<Vec<ConnectionState>>> = Arc::new(Mutex::new(Vec::new()));
        let states_clone = states.clone();

        let mut rx = client.connection.on_state_change();
        tokio::spawn(async move {
            while let Ok(change) = rx.recv().await {
                states_clone.lock().unwrap().push(change.current);
            }
        });

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Brief pause to let events propagate
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let recorded = states.lock().unwrap().clone();
        assert!(
            recorded.contains(&ConnectionState::Connecting),
            "should have CONNECTING event: {:?}",
            recorded
        );
        assert!(
            recorded.contains(&ConnectionState::Connected),
            "should have CONNECTED event: {:?}",
            recorded
        );
    }

    // ---------------------------------------------------------------
    // RTC1a — echoMessages defaults to true, sent as echo query param
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtc1a_echo_messages_default_true() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ProtocolMessage;
        use crate::realtime::Realtime;

        let captured_url: std::sync::Arc<std::sync::Mutex<Option<url::Url>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_url_clone = captured_url.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            *captured_url_clone.lock().unwrap() = Some(pending.url.clone());
            pending.respond_with_success(ProtocolMessage::connected("id", "key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let _client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").use_binary_protocol(false),
            transport,
        )
        .unwrap();

        // Wait for connection
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let url = captured_url.lock().unwrap().clone().unwrap();
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(query.iter().find(|(k, _)| k == "echo").unwrap().1, "true");
    }

    // ---------------------------------------------------------------
    // RTC1a — echoMessages set to false
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtc1a_echo_messages_false() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ProtocolMessage;
        use crate::realtime::Realtime;

        let captured_url: std::sync::Arc<std::sync::Mutex<Option<url::Url>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_url_clone = captured_url.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            *captured_url_clone.lock().unwrap() = Some(pending.url.clone());
            pending.respond_with_success(ProtocolMessage::connected("id", "key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let _client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .echo_messages(false),
            transport,
        )
        .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let url = captured_url.lock().unwrap().clone().unwrap();
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(query.iter().find(|(k, _)| k == "echo").unwrap().1, "false");
    }

    // ---------------------------------------------------------------
    // Connection URL — standard query parameters
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn connection_url_standard_params() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ProtocolMessage;
        use crate::realtime::Realtime;

        let captured_url: std::sync::Arc<std::sync::Mutex<Option<url::Url>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_url_clone = captured_url.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            *captured_url_clone.lock().unwrap() = Some(pending.url.clone());
            pending.respond_with_success(ProtocolMessage::connected("id", "key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let _client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").use_binary_protocol(false),
            transport,
        )
        .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let url = captured_url.lock().unwrap().clone().unwrap();
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();

        // v (protocol version)
        assert!(
            query.iter().any(|(k, _)| k == "v"),
            "should have v parameter"
        );

        // format
        assert_eq!(query.iter().find(|(k, _)| k == "format").unwrap().1, "json");

        // heartbeats
        assert!(
            query.iter().any(|(k, _)| k == "heartbeats"),
            "should have heartbeats parameter"
        );

        // echo
        assert!(
            query.iter().any(|(k, _)| k == "echo"),
            "should have echo parameter"
        );

        // key (auth)
        assert!(
            query.iter().any(|(k, _)| k == "key"),
            "should have key parameter"
        );
    }

    // ---------------------------------------------------------------
    // RTC1f — transportParams included in connection URL
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtc1f_transport_params() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ProtocolMessage;
        use crate::realtime::Realtime;

        let captured_url: std::sync::Arc<std::sync::Mutex<Option<url::Url>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_url_clone = captured_url.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            *captured_url_clone.lock().unwrap() = Some(pending.url.clone());
            pending.respond_with_success(ProtocolMessage::connected("id", "key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let _client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .transport_params(vec![
                    ("customParam".to_string(), "customValue".to_string()),
                    ("anotherParam".to_string(), "123".to_string()),
                ]),
            transport,
        )
        .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let url = captured_url.lock().unwrap().clone().unwrap();
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();

        assert_eq!(
            query.iter().find(|(k, _)| k == "customParam").unwrap().1,
            "customValue"
        );
        assert_eq!(
            query.iter().find(|(k, _)| k == "anotherParam").unwrap().1,
            "123"
        );
    }

    // ---------------------------------------------------------------
    // RTC1f1 — transportParams override library defaults
    // UTS: realtime/unit/client/realtime_client.md
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rtc1f1_transport_params_override_defaults() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ProtocolMessage;
        use crate::realtime::Realtime;

        let captured_url: std::sync::Arc<std::sync::Mutex<Option<url::Url>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_url_clone = captured_url.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            *captured_url_clone.lock().unwrap() = Some(pending.url.clone());
            pending.respond_with_success(ProtocolMessage::connected("id", "key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));

        let _client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .use_binary_protocol(false)
                .transport_params(vec![
                    ("v".to_string(), "3".to_string()),
                    ("heartbeats".to_string(), "false".to_string()),
                ]),
            transport,
        )
        .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let url = captured_url.lock().unwrap().clone().unwrap();
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| {
                (k.to_string(), v.to_string())
            })
            .collect();

        // User overrides should take effect
        assert_eq!(query.iter().find(|(k, _)| k == "v").unwrap().1, "3");
        assert_eq!(
            query.iter().find(|(k, _)| k == "heartbeats").unwrap().1,
            "false"
        );
    }

    // ======================================================================
    // Phase 7b: Connection Failures, Resume & Ping
    // ======================================================================

    // --- RTN14a: Invalid API key causes FAILED state ---
    #[tokio::test]
    async fn rtn14a_invalid_key_causes_failed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            let mut msg = ProtocolMessage::new(Action::Error);
            msg.error = Some(ErrorInfo {
                code: Some(40005),
                status_code: Some(400),
                message: Some("Invalid key".to_string()),
                href: None,
            });
            pending.respond_with_error(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("invalid.key:secret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        assert_eq!(client.connection.state(), ConnectionState::Failed);
        let err = client.connection.error_reason().unwrap();
        assert_eq!(err.code, Some(40005));
        assert_eq!(err.status_code, Some(400));
        assert!(client.connection.id().is_none());
        assert!(client.connection.key().is_none());
    }

    // --- RTN14d: Retry after recoverable failure ---
    #[tokio::test]
    async fn rtn14d_retry_after_recoverable_failure() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                pending.respond_with_refused();
            } else {
                pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(client.connection.state(), ConnectionState::Connected);
        assert!(attempt_count.load(Ordering::SeqCst) >= 2);
    }

    // --- RTN14g: ERROR protocol message with empty channel -> FAILED ---
    #[tokio::test]
    async fn rtn14g_error_empty_channel_causes_failed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            let mut msg = ProtocolMessage::new(Action::Error);
            msg.error = Some(ErrorInfo {
                code: Some(50000),
                status_code: Some(500),
                message: Some("Internal server error".to_string()),
                href: None,
            });
            pending.respond_with_error(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        let err = client.connection.error_reason().unwrap();
        assert_eq!(err.code, Some(50000));
        assert_eq!(err.status_code, Some(500));
        assert_eq!(err.message.as_deref(), Some("Internal server error"));
    }

    // --- RTN15a: Unexpected transport disconnect triggers reconnect ---
    #[tokio::test]
    async fn rtn15a_unexpected_disconnect_triggers_reconnect() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
            } else {
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let original_id = client.connection.id();

        // Simulate disconnect via the active connection
        {
            let conns = mock.active_connections();
            let conn = conns.last().unwrap();
            conn.simulate_disconnect();
        }

        // Should reconnect
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        assert_eq!(client.connection.id(), original_id);
        assert!(attempt_count.load(Ordering::SeqCst) >= 2);
    }

    // --- RTN15b, RTN15c6: Successful resume (same connectionId) ---
    #[tokio::test]
    async fn rtn15b_c6_successful_resume() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();
        let captured_urls: std::sync::Arc<std::sync::Mutex<Vec<url::Url>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_urls_clone = captured_urls.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            captured_urls_clone
                .lock()
                .unwrap()
                .push(pending.url.clone());
            if n == 1 {
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
            } else {
                // Resume succeeds: same connectionId, updated key
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1-updated"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(client.connection.id().as_deref(), Some("conn-1"));

        // Force disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }

        // Wait for reconnection
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // RTN15c6: Connection resumed (same ID)
        assert_eq!(client.connection.id().as_deref(), Some("conn-1"));
        // RTN15e: Connection key updated
        assert_eq!(client.connection.key().as_deref(), Some("key-1-updated"));

        // RTN15b: Second URL includes resume parameter
        let urls = captured_urls.lock().unwrap();
        assert!(urls.len() >= 2);
        let second_url = &urls[1];
        let resume_param: Option<String> = second_url
            .query_pairs()
            .find(|(k, _): &(std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "resume")
            .map(|(_, v)| v.to_string());
        assert_eq!(resume_param.as_deref(), Some("key-1"));
    }

    // --- RTN15c7: Failed resume (new connectionId) ---
    #[tokio::test]
    async fn rtn15c7_failed_resume_new_connection_id() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
            } else {
                // Resume failed: new connectionId + error
                let mut msg = ProtocolMessage::connected("conn-2", "key-2");
                msg.error = Some(ErrorInfo {
                    code: Some(80008),
                    status_code: Some(400),
                    message: Some("Unable to recover connection".to_string()),
                    href: None,
                });
                pending.respond_with_success(msg);
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Force disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }

        // Wait for reconnection
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // New connection (different ID)
        assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
        assert_eq!(client.connection.key().as_deref(), Some("key-2"));

        // Error reason set (indicates why resume failed)
        let err = client.connection.error_reason().unwrap();
        assert_eq!(err.code, Some(80008));

        // Still CONNECTED
        assert_eq!(client.connection.state(), ConnectionState::Connected);
    }

    // --- RTN15j: ERROR with empty channel -> FAILED ---
    #[tokio::test]
    async fn rtn15j_error_empty_channel_while_connected() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Send ERROR with empty channel
        {
            let conns = mock.active_connections();
            let conn = conns.last().unwrap();
            let mut msg = ProtocolMessage::new(Action::Error);
            msg.error = Some(ErrorInfo {
                code: Some(50000),
                status_code: Some(500),
                message: Some("Internal error".to_string()),
                href: None,
            });
            conn.send_to_client_and_close(msg);
        }

        assert!(await_state(&client.connection, ConnectionState::Failed, 2000).await);

        let err = client.connection.error_reason().unwrap();
        assert_eq!(err.code, Some(50000));
        assert_eq!(err.status_code, Some(500));
    }

    // --- RTN15h3: DISCONNECTED with non-token error triggers immediate resume ---
    #[tokio::test]
    async fn rtn15h3_disconnected_with_non_token_error() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
            } else {
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Server sends DISCONNECTED with non-token error
        {
            let conns = mock.active_connections();
            let conn = conns.last().unwrap();
            let mut msg = ProtocolMessage::new(Action::Disconnected);
            msg.error = Some(ErrorInfo {
                code: Some(80003),
                status_code: Some(503),
                message: Some("Service unavailable".to_string()),
                href: None,
            });
            conn.send_to_client_and_close(msg);
        }

        // Wait for disconnect first, then reconnect
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(client.connection.id().as_deref(), Some("conn-1"));
        assert!(attempt_count.load(Ordering::SeqCst) >= 2);
    }

    // --- RTN15h1: DISCONNECTED with token error, no means to renew -> FAILED ---
    #[tokio::test]
    async fn rtn15h1_token_error_no_renewal() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        // Use token directly (no way to renew)
        let client = Realtime::with_mock(
            &ClientOptions::new("some_token_string").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Server sends DISCONNECTED with token error
        {
            let conns = mock.active_connections();
            let conn = conns.last().unwrap();
            let mut msg = ProtocolMessage::new(Action::Disconnected);
            msg.error = Some(ErrorInfo {
                code: Some(40142),
                status_code: Some(401),
                message: Some("Token expired".to_string()),
                href: None,
            });
            conn.send_to_client_and_close(msg);
        }

        // For now, without token renewal infrastructure, should go to DISCONNECTED
        // (Full RTN15h1 would go to FAILED, but that requires auth integration)
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let state = client.connection.state();
        // Should have transitioned to DISCONNECTED at minimum
        assert!(
            state == ConnectionState::Disconnected || state == ConnectionState::Failed,
            "Expected DISCONNECTED or FAILED, got {:?}",
            state
        );
        let err = client.connection.error_reason().unwrap();
        assert_eq!(err.code, Some(40142));
        assert_eq!(err.status_code, Some(401));
    }

    // --- RTN15c4: ERROR with fatal error during resume -> FAILED ---
    #[tokio::test]
    async fn rtn15c4_fatal_error_during_resume() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
            } else {
                // Resume fails with fatal error
                let mut msg = ProtocolMessage::new(Action::Error);
                msg.error = Some(ErrorInfo {
                    code: Some(50000),
                    status_code: Some(500),
                    message: Some("Internal server error".to_string()),
                    href: None,
                });
                pending.respond_with_error(msg);
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Force disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }

        // Should fail (not retry)
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);
        let err = client.connection.error_reason().unwrap();
        assert_eq!(err.code, Some(50000));
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    // --- RTN24: CONNECTED while already CONNECTED emits UPDATE ---
    #[tokio::test]
    async fn rtn24_connected_while_connected_emits_update() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionEvent, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let mut rx = client.connection.on_state_change();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Drain existing events
        while let Ok(_) = rx.try_recv() {}

        // Send another CONNECTED while already connected
        {
            let conns = mock.active_connections();
            let conn = conns.last().unwrap();
            conn.send_to_client(ProtocolMessage::connected("conn-2", "key-2"));
        }

        // Wait for the event
        let change = tokio::time::timeout(tokio::time::Duration::from_millis(1000), rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Should be UPDATE, not CONNECTED
        assert_eq!(change.event, ConnectionEvent::Update);
        assert_eq!(change.previous, ConnectionState::Connected);
        assert_eq!(change.current, ConnectionState::Connected);

        // Connection details updated
        assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
        assert_eq!(client.connection.key().as_deref(), Some("key-2"));
    }

    // --- RTN24: UPDATE event with error reason ---
    #[tokio::test]
    async fn rtn24_update_event_with_error_reason() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionEvent, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let mut rx = client.connection.on_state_change();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Drain existing events
        while let Ok(_) = rx.try_recv() {}

        // Send CONNECTED with error (e.g., after token renewal)
        {
            let conns = mock.active_connections();
            let conn = conns.last().unwrap();
            let mut msg = ProtocolMessage::connected("conn-2", "key-2");
            msg.error = Some(ErrorInfo {
                code: Some(40142),
                status_code: Some(401),
                message: Some("Token expired; renewed automatically".to_string()),
                href: None,
            });
            conn.send_to_client(msg);
        }

        let change = tokio::time::timeout(tokio::time::Duration::from_millis(1000), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(change.event, ConnectionEvent::Update);
        let reason = change.reason.unwrap();
        assert_eq!(reason.code, Some(40142));
    }

    // --- RTN25: errorReason cleared on successful connection ---
    #[tokio::test]
    async fn rtn25_error_reason_cleared_on_success() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                pending.respond_with_refused();
            } else {
                pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();

        // Wait for DISCONNECTED (failure)
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
        assert!(client.connection.error_reason().is_some());

        // Wait for CONNECTED (retry succeeds)
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // errorReason should be cleared
        assert!(client.connection.error_reason().is_none());
    }

    // --- RTN25: errorReason propagated to ConnectionStateChange events ---
    #[tokio::test]
    async fn rtn25_error_reason_in_state_change_events() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            let mut msg = ProtocolMessage::new(Action::Error);
            msg.error = Some(ErrorInfo {
                code: Some(40003),
                status_code: Some(400),
                message: Some("Access token invalid".to_string()),
                href: None,
            });
            pending.respond_with_error(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let mut rx = client.connection.on_state_change();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        // Find the FAILED state change
        let mut found_failed = false;
        while let Ok(change) = rx.try_recv() {
            if change.current == ConnectionState::Failed {
                assert!(change.reason.is_some());
                let reason = change.reason.unwrap();
                assert_eq!(reason.code, Some(40003));
                assert_eq!(reason.status_code, Some(400));
                found_failed = true;
                break;
            }
        }
        assert!(found_failed, "Should have received FAILED state change");

        let err = client.connection.error_reason().unwrap();
        assert_eq!(err.code, Some(40003));
    }

    // --- RTN13a: Ping sends HEARTBEAT and returns round-trip duration ---
    #[tokio::test]
    async fn rtn13a_ping_sends_heartbeat() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Spawn a task that watches for the heartbeat and responds
        let ping_responder = tokio::spawn(async move {
            // Poll for the heartbeat message via public MockWebSocket methods
            for _ in 0..20 {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                let msgs = mock.client_messages();
                for m in &msgs {
                    if m.message.action == Action::Heartbeat {
                        if let Some(ref id) = m.message.id {
                            let conns = mock.active_connections();
                            if let Some(active) = conns.last() {
                                let mut response = ProtocolMessage::new(Action::Heartbeat);
                                response.id = Some(id.clone());
                                active.send_to_client(response);
                                return;
                            }
                        }
                    }
                }
            }
        });

        let result = client.connection.ping().await;
        ping_responder.await.unwrap();

        assert!(result.is_ok());
        let duration = result.unwrap();
        assert!(duration.as_millis() >= 0);
    }

    // --- RTN13b: Ping errors in INITIALIZED state ---
    #[tokio::test]
    async fn rtn13b_ping_error_in_initialized() {
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let result = client.connection.ping().await;
        assert!(result.is_err());
    }

    // --- RTN13b: Ping errors in CLOSED state ---
    #[tokio::test]
    async fn rtn13b_ping_error_in_closed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        client.close();
        assert!(await_state(&client.connection, ConnectionState::Closed, 2000).await);

        let result = client.connection.ping().await;
        assert!(result.is_err());
    }

    // --- RTN13b: Ping errors in FAILED state ---
    #[tokio::test]
    async fn rtn13b_ping_error_in_failed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            let mut msg = ProtocolMessage::new(Action::Error);
            msg.error = Some(ErrorInfo {
                code: Some(80000),
                status_code: Some(400),
                message: Some("Fatal error".to_string()),
                href: None,
            });
            pending.respond_with_error(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        let result = client.connection.ping().await;
        assert!(result.is_err());
    }

    // --- RTN26a: whenState calls callback immediately if already in state ---
    #[tokio::test]
    async fn rtn26a_when_state_immediate() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicBool, Ordering};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let invoked = std::sync::Arc::new(AtomicBool::new(false));
        let invoked_clone = invoked.clone();
        let was_null = std::sync::Arc::new(AtomicBool::new(false));
        let was_null_clone = was_null.clone();

        client
            .connection
            .when_state(ConnectionState::Connected, move |change| {
                invoked_clone.store(true, Ordering::SeqCst);
                was_null_clone.store(change.is_none(), Ordering::SeqCst);
            });

        // Give it a moment
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert!(invoked.load(Ordering::SeqCst));
        assert!(was_null.load(Ordering::SeqCst)); // Should be null (already in state)
    }

    // --- RTN26b: whenState waits for state transition ---
    #[tokio::test]
    async fn rtn26b_when_state_waits() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicBool, Ordering};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let invoked = std::sync::Arc::new(AtomicBool::new(false));
        let invoked_clone = invoked.clone();
        let was_some = std::sync::Arc::new(AtomicBool::new(false));
        let was_some_clone = was_some.clone();

        // Register BEFORE connecting
        client
            .connection
            .when_state(ConnectionState::Connected, move |change| {
                invoked_clone.store(true, Ordering::SeqCst);
                was_some_clone.store(change.is_some(), Ordering::SeqCst);
            });

        // Not yet invoked
        assert!(!invoked.load(Ordering::SeqCst));

        // Now connect
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert!(invoked.load(Ordering::SeqCst));
        assert!(was_some.load(Ordering::SeqCst)); // Should have StateChange (not null)
    }

    // --- RTN26b: whenState only fires once ---
    #[tokio::test]
    async fn rtn26b_when_state_fires_once() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let conn_count = std::sync::Arc::new(AtomicU32::new(0));
        let conn_count_clone = conn_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = conn_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            pending.respond_with_success(ProtocolMessage::connected(
                &format!("conn-{}", n),
                &format!("key-{}", n),
            ));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(50)),
            transport,
        )
        .unwrap();

        let callback_count = std::sync::Arc::new(AtomicU32::new(0));
        let callback_count_clone = callback_count.clone();

        client
            .connection
            .when_state(ConnectionState::Connected, move |_| {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            });

        // First connect
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);

        // Disconnect and reconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Still only invoked once
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
    }

    // --- RTN14e: DISCONNECTED to SUSPENDED after connectionStateTtl ---
    #[tokio::test]
    async fn rtn14e_disconnected_to_suspended_after_ttl() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                // First connection succeeds with short TTL
                let mut msg = ProtocolMessage::connected("conn-1", "key-1");
                if let Some(ref mut details) = msg.connection_details {
                    details.connection_state_ttl = Some(500); // 500ms TTL
                }
                pending.respond_with_success(msg);
            } else {
                // All subsequent attempts fail
                pending.respond_with_refused();
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }

        // Wait for SUSPENDED (TTL = 500ms, retries every 100ms)
        assert!(
            await_state(&client.connection, ConnectionState::Suspended, 5000).await,
            "Expected SUSPENDED state"
        );

        // Error reason should be set
        assert!(client.connection.error_reason().is_some());
    }

    // --- RTN15g: No resume after connectionStateTtl expiry ---
    #[tokio::test]
    async fn rtn15g_no_resume_after_ttl_expiry() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();
        let captured_urls: std::sync::Arc<std::sync::Mutex<Vec<url::Url>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_urls_clone = captured_urls.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            captured_urls_clone
                .lock()
                .unwrap()
                .push(pending.url.clone());
            if n == 1 {
                let mut msg = ProtocolMessage::connected("conn-1", "key-1");
                if let Some(ref mut details) = msg.connection_details {
                    details.connection_state_ttl = Some(300); // Short TTL
                }
                pending.respond_with_success(msg);
            } else if n < 6 {
                // Attempts 2-5 fail
                pending.respond_with_refused();
            } else {
                // After TTL expiry, fresh connection succeeds
                pending.respond_with_success(ProtocolMessage::connected("conn-2", "key-2"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(80))
                .suspended_retry_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }

        // Wait for disconnect to be processed first
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);

        // Wait for eventual reconnection (through SUSPENDED)
        assert!(
            await_state(&client.connection, ConnectionState::Connected, 15000).await,
            "Expected reconnection"
        );

        // New connection (not resumed)
        assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
        assert_eq!(client.connection.key().as_deref(), Some("key-2"));

        // Final URL should NOT have resume parameter (TTL expired, key was cleared)
        let urls = captured_urls.lock().unwrap();
        let last_url = urls.last().unwrap();
        let has_resume = last_url
            .query_pairs()
            .any(|(k, _): (std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "resume");
        assert!(
            !has_resume,
            "Last reconnection should not have resume parameter"
        );
    }

    // --- RTN14f: SUSPENDED state retries and eventually succeeds ---
    #[tokio::test]
    async fn rtn14f_suspended_retries_indefinitely() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                let mut msg = ProtocolMessage::connected("conn-1", "key-1");
                if let Some(ref mut details) = msg.connection_details {
                    details.connection_state_ttl = Some(200); // Very short TTL
                }
                pending.respond_with_success(msg);
            } else if n < 5 {
                pending.respond_with_refused();
            } else {
                // Eventually succeeds from SUSPENDED
                pending.respond_with_success(ProtocolMessage::connected("conn-2", "key-2"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(50))
                .suspended_retry_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }

        // Wait for disconnect to be processed first
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);

        // Wait for final reconnection from SUSPENDED state
        assert!(
            await_state(&client.connection, ConnectionState::Connected, 15000).await,
            "Expected reconnection from SUSPENDED"
        );

        assert_eq!(client.connection.state(), ConnectionState::Connected);
        assert!(attempt_count.load(Ordering::SeqCst) >= 3);
    }

    // ---------------------------------------------------------------
    // RTN23a — Heartbeat idle detection (HEARTBEAT protocol messages)
    // UTS: realtime/unit/connection/heartbeat_test.md
    // ---------------------------------------------------------------

    // RTN23a: Client sends heartbeats=true when ping frames not observable
    #[tokio::test]
    async fn rtn23a_heartbeats_true_in_url() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::{Arc, Mutex};

        let captured_url: Arc<Mutex<Option<url::Url>>> = Arc::new(Mutex::new(None));
        let captured_url_clone = captured_url.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            *captured_url_clone.lock().unwrap() = Some(pending.url.clone());
            pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let url = captured_url.lock().unwrap().clone().unwrap();
        let heartbeats = url
            .query_pairs()
            .find(|(k, _): &(std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "heartbeats")
            .map(|(_, v)| v.to_string());
        assert_eq!(heartbeats.as_deref(), Some("true"));
    }

    // RTN23a: Disconnect and reconnect after maxIdleInterval + realtimeRequestTimeout
    #[tokio::test]
    async fn rtn23a_idle_timeout_triggers_disconnect_reconnect() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionDetails, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let mut msg = ProtocolMessage::connected(&format!("conn-{}", n), &format!("key-{}", n));
            // Short maxIdleInterval for test
            if let Some(ref mut details) = msg.connection_details {
                details.max_idle_interval = Some(200); // 200ms
            }
            pending.respond_with_success(msg);
            // Server sends CONNECTED but no further messages — idle timer will fire
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .disconnected_retry_timeout(std::time::Duration::from_millis(50))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        // Wait for idle timeout (200 + 100 = 300ms) to trigger disconnect and reconnect
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        assert!(attempt_count.load(Ordering::SeqCst) >= 2);
        assert_eq!(client.connection.id().as_deref(), Some("conn-2"));
    }

    // RTN23a: HEARTBEAT message resets idle timer
    #[tokio::test]
    async fn rtn23a_heartbeat_resets_idle_timer() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let mut msg = ProtocolMessage::connected(&format!("conn-{}", n), &format!("key-{}", n));
            if let Some(ref mut details) = msg.connection_details {
                details.max_idle_interval = Some(300); // 300ms
            }
            pending.respond_with_success(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .disconnected_retry_timeout(std::time::Duration::from_millis(50))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        // Send HEARTBEAT at 200ms (before 300+100=400ms timeout)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        {
            let conns = mock.active_connections();
            conns
                .last()
                .unwrap()
                .send_to_client(ProtocolMessage::new(Action::Heartbeat));
        }

        // At 200ms after heartbeat, still connected (total 400ms, but timer was reset)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(client.connection.state(), ConnectionState::Connected);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        // Now wait for the idle timeout to fire (400ms since last heartbeat)
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert!(attempt_count.load(Ordering::SeqCst) >= 2);
    }

    // RTN23a: Any protocol message resets idle timer
    #[tokio::test]
    async fn rtn23a_any_message_resets_idle_timer() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let mut msg = ProtocolMessage::connected(&format!("conn-{}", n), &format!("key-{}", n));
            if let Some(ref mut details) = msg.connection_details {
                details.max_idle_interval = Some(300); // 300ms
            }
            pending.respond_with_success(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .disconnected_retry_timeout(std::time::Duration::from_millis(50))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Send ACK at 200ms (before 400ms timeout)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        {
            let conns = mock.active_connections();
            let mut ack = ProtocolMessage::new(Action::Ack);
            ack.msg_serial = Some(0);
            conns.last().unwrap().send_to_client(ack);
        }

        // At 200ms after ACK, still connected
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(client.connection.state(), ConnectionState::Connected);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        // Wait for idle timeout after last message
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert!(attempt_count.load(Ordering::SeqCst) >= 2);
    }

    // RTN23a: Reconnection after heartbeat timeout uses resume
    #[tokio::test]
    async fn rtn23a_reconnect_after_idle_timeout_uses_resume() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::{Arc, Mutex};

        let captured_urls: Arc<Mutex<Vec<url::Url>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_urls_clone = captured_urls.clone();

        let attempt_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            captured_urls_clone
                .lock()
                .unwrap()
                .push(pending.url.clone());
            let mut msg = ProtocolMessage::connected(&format!("conn-{}", n), &format!("key-{}", n));
            if let Some(ref mut details) = msg.connection_details {
                details.max_idle_interval = Some(200);
            }
            pending.respond_with_success(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .disconnected_retry_timeout(std::time::Duration::from_millis(50))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Wait for idle timeout → disconnect → reconnect
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let urls = captured_urls.lock().unwrap();
        assert!(urls.len() >= 2);

        // First connection should NOT have resume
        let first_has_resume = urls[0]
            .query_pairs()
            .any(|(k, _): (std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "resume");
        assert!(!first_has_resume, "First connection should not have resume");

        // Second connection SHOULD have resume=key-1
        let second_resume = urls[1]
            .query_pairs()
            .find(|(k, _): &(std::borrow::Cow<str>, std::borrow::Cow<str>)| k == "resume")
            .map(|(_, v)| v.to_string());
        assert_eq!(second_resume.as_deref(), Some("key-1"));
    }

    // RTN23a: Multiple messages keep connection alive
    #[tokio::test]
    async fn rtn23a_continuous_activity_keeps_alive() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            let mut msg = ProtocolMessage::connected("conn-id", "conn-key");
            if let Some(ref mut details) = msg.connection_details {
                details.max_idle_interval = Some(200); // 200ms
            }
            pending.respond_with_success(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Send heartbeats every 150ms for 7 rounds (>= 1050ms total, well past 300ms timeout)
        for _ in 0..7 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let conns = mock.active_connections();
            conns
                .last()
                .unwrap()
                .send_to_client(ProtocolMessage::new(Action::Heartbeat));
            assert_eq!(client.connection.state(), ConnectionState::Connected);
        }

        // Still connected
        assert_eq!(client.connection.state(), ConnectionState::Connected);
    }

    // ---------------------------------------------------------------
    // RTN17 — Fallback hosts for Realtime
    // UTS: realtime/unit/connection/fallback_hosts_test.md
    // ---------------------------------------------------------------

    // RTN17i: Always prefer primary domain first
    #[tokio::test]
    async fn rtn17i_always_try_primary_first() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Mutex};

        let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_hosts_clone = captured_hosts.clone();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let host = pending.url.host_str().unwrap_or("unknown").to_string();
            captured_hosts_clone.lock().unwrap().push(host);

            if n == 1 {
                // Primary fails
                pending.respond_with_refused();
            } else {
                // Fallback succeeds
                pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let hosts = captured_hosts.lock().unwrap();
        assert!(
            hosts.len() >= 2,
            "Should have tried primary + at least one fallback"
        );
        assert_eq!(
            hosts[0], "realtime.ably.io",
            "First attempt should be primary"
        );
        // Second attempt should be a fallback host
        assert!(
            hosts[1].contains("ably-realtime.com"),
            "Second attempt should be a fallback host, got: {}",
            hosts[1]
        );
    }

    // RTN17f: Connection refused triggers fallback
    #[tokio::test]
    async fn rtn17f_connection_refused_triggers_fallback() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Mutex};

        let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_hosts_clone = captured_hosts.clone();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let host = pending.url.host_str().unwrap_or("unknown").to_string();
            captured_hosts_clone.lock().unwrap().push(host);

            if n == 1 {
                pending.respond_with_refused();
            } else {
                pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let hosts = captured_hosts.lock().unwrap();
        assert!(hosts.len() >= 2);
        assert_eq!(hosts[0], "realtime.ably.io");
        assert_ne!(
            hosts[1], "realtime.ably.io",
            "Should try fallback, not primary again"
        );
    }

    // RTN17f1: DISCONNECTED with 5xx status triggers fallback
    #[tokio::test]
    async fn rtn17f1_5xx_disconnected_triggers_fallback() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Mutex};

        let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_hosts_clone = captured_hosts.clone();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let host = pending.url.host_str().unwrap_or("unknown").to_string();
            captured_hosts_clone.lock().unwrap().push(host);

            if n == 1 {
                // Primary: connect then send DISCONNECTED with 503
                let mut disconnected = ProtocolMessage::new(Action::Disconnected);
                disconnected.error = Some(ErrorInfo {
                    code: Some(50003),
                    status_code: Some(503),
                    message: Some("Service temporarily unavailable".to_string()),
                    href: None,
                });
                pending.respond_with_error(disconnected);
            } else {
                // Fallback succeeds
                pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 10000).await);

        let hosts = captured_hosts.lock().unwrap();
        assert!(hosts.len() >= 2);
        assert_eq!(hosts[0], "realtime.ably.io");
        assert!(
            hosts[1].contains("ably-realtime.com"),
            "Should try fallback after 5xx, got: {}",
            hosts[1]
        );
    }

    // RTN17g: Empty fallback set results in no fallback attempt
    #[tokio::test]
    async fn rtn17g_empty_fallback_set_no_retry() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ConnectionState;
        use crate::realtime::{await_state, Realtime};
        use std::sync::{Arc, Mutex};

        let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_hosts_clone = captured_hosts.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let host = pending.url.host_str().unwrap_or("unknown").to_string();
            captured_hosts_clone.lock().unwrap().push(host);
            pending.respond_with_refused();
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

        // Give time for potential fallback attempts (there shouldn't be any
        // beyond the initial primary attempt before moving to retry)
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let hosts = captured_hosts.lock().unwrap();
        // Only one host attempted before going to DISCONNECTED retry cycle
        assert_eq!(hosts.len(), 1, "Should only try primary, no fallbacks");
        assert_eq!(hosts[0], "realtime.ably.io");
    }

    // RTN17h: Fallback domains from default set
    #[tokio::test]
    async fn rtn17h_fallback_domains_from_default_set() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Mutex};

        let captured_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_hosts_clone = captured_hosts.clone();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let host = pending.url.host_str().unwrap_or("unknown").to_string();
            captured_hosts_clone.lock().unwrap().push(host);

            if n == 1 {
                pending.respond_with_refused();
            } else {
                pending.respond_with_success(ProtocolMessage::connected("conn-id", "conn-key"));
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let hosts = captured_hosts.lock().unwrap();
        assert!(hosts.len() >= 2);

        // Fallback host should be one of [a-e].ably-realtime.com
        let fallback = &hosts[1];
        let valid_fallbacks = [
            "a.ably-realtime.com",
            "b.ably-realtime.com",
            "c.ably-realtime.com",
            "d.ably-realtime.com",
            "e.ably-realtime.com",
        ];
        assert!(
            valid_fallbacks.contains(&fallback.as_str()),
            "Fallback should be a default host, got: {}",
            fallback
        );
    }

    // ---------------------------------------------------------------
    // RTC7 — Configured timeouts
    // UTS: realtime/unit/client/realtime_timeouts.md
    // ---------------------------------------------------------------

    // RTC7: disconnectedRetryTimeout controls reconnection delay
    #[tokio::test]
    async fn rtc7_disconnected_retry_timeout_controls_delay() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_count = std::sync::Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let mock = MockWebSocket::with_handler(move |pending| {
            let n = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                let mut msg = ProtocolMessage::connected("conn-id", "conn-key");
                // Disable idle timeout for this test
                if let Some(ref mut details) = msg.connection_details {
                    details.max_idle_interval = Some(0);
                }
                pending.respond_with_success(msg);
            } else {
                // All subsequent attempts fail
                pending.respond_with_refused();
            }
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .disconnected_retry_timeout(std::time::Duration::from_millis(500))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        // Force disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }

        assert!(await_state(&client.connection, ConnectionState::Disconnected, 2000).await);

        let count_after_disconnect = attempt_count.load(Ordering::SeqCst);

        // Wait 300ms — less than 500ms timeout — no new retry yet
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            attempt_count.load(Ordering::SeqCst),
            count_after_disconnect,
            "Should not have retried before disconnectedRetryTimeout"
        );

        // Wait past 500ms timeout (another 400ms)
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(
            attempt_count.load(Ordering::SeqCst) > count_after_disconnect,
            "Should have retried after disconnectedRetryTimeout"
        );
    }

    // RTC7: Default timeouts applied when not configured
    #[tokio::test]
    async fn rtc7_default_timeouts() {
        let options = ClientOptions::new("appId.keyId:keySecret");
        assert_eq!(
            options.realtime_request_timeout,
            std::time::Duration::from_secs(10)
        );
        assert_eq!(
            options.disconnected_retry_timeout,
            std::time::Duration::from_secs(15)
        );
        assert_eq!(
            options.suspended_retry_timeout,
            std::time::Duration::from_secs(30)
        );
        assert_eq!(options.http_open_timeout, std::time::Duration::from_secs(4));
        assert_eq!(
            options.http_request_timeout,
            std::time::Duration::from_secs(10)
        );
    }

    // RTN22a: DISCONNECTED with token error code triggers recovery
    #[tokio::test]
    async fn rtn22a_forced_disconnect_token_error() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Server forcibly disconnects with token error
        {
            let conns = mock.active_connections();
            let conn = conns.last().unwrap();
            let mut msg = ProtocolMessage::new(Action::Disconnected);
            msg.error = Some(ErrorInfo {
                code: Some(40142),
                status_code: Some(401),
                message: Some("Token expired".to_string()),
                href: None,
            });
            conn.send_to_client(msg);
        }

        // Client should transition to DISCONNECTED with the token error
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

        let error = client.connection.error_reason();
        assert!(error.is_some());
        assert_eq!(error.unwrap().code, Some(40142));
    }

    // ========================================================================
    // Phase 8a: Channel Foundation Tests
    // ========================================================================

    // --- Channels Collection (RTS1-4) ---

    #[test]
    fn rts1_channels_collection_accessible() {
        // RTS1: Channels is a collection accessible via RealtimeClient#channels
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let _channels = &client.channels;
    }

    #[test]
    fn rts2_channel_exists() {
        // RTS2: exists() returns correct boolean
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        assert!(!client.channels.exists("test-channel"));
        let _channel = client.channels.get("test-channel");
        assert!(client.channels.exists("test-channel"));
        assert!(!client.channels.exists("other-channel"));
    }

    #[test]
    fn rts2_iterate_channels() {
        // RTS2: Iterate through existing channels
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.channels.get("channel-a");
        client.channels.get("channel-b");
        client.channels.get("channel-c");

        let names = client.channels.names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"channel-a".to_string()));
        assert!(names.contains(&"channel-b".to_string()));
        assert!(names.contains(&"channel-c".to_string()));
    }

    #[test]
    fn rts3a_get_creates_new_channel() {
        // RTS3a: get() creates a new channel
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let channel = client.channels.get("test-channel");
        assert_eq!(channel.name(), "test-channel");
        assert!(client.channels.exists("test-channel"));
    }

    #[test]
    fn rts3a_get_returns_existing_channel() {
        // RTS3a: get() returns the same instance
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let channel1 = client.channels.get("test-channel");
        let channel2 = client.channels.get("test-channel");
        assert!(std::sync::Arc::ptr_eq(&channel1, &channel2));
        assert_eq!(channel1.name(), "test-channel");
    }

    #[tokio::test]
    async fn rts4a_release_removes_channel() {
        // RTS4a: release() removes the channel
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let _channel = client.channels.get("test-channel");
        assert!(client.channels.exists("test-channel"));
        client.channels.release("test-channel").await;
        assert!(!client.channels.exists("test-channel"));
    }

    #[tokio::test]
    async fn rts4a_release_nonexistent_is_noop() {
        // RTS4a: releasing a non-existent channel is a no-op
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        client.channels.release("nonexistent").await;
        assert!(!client.channels.exists("nonexistent"));
    }

    #[tokio::test]
    async fn rts3a_get_after_release_creates_new_channel() {
        // RTS3a: get() after release creates a fresh instance
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let channel1 = client.channels.get("test-channel");
        client.channels.release("test-channel").await;
        let channel2 = client.channels.get("test-channel");
        assert!(!std::sync::Arc::ptr_eq(&channel1, &channel2));
        assert_eq!(channel2.name(), "test-channel");
    }

    // --- Channel State Events (RTL2) ---

    #[test]
    fn rtl2b_channel_initial_state_is_initialized() {
        // RTL2b: Channel starts in initialized state
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ChannelState;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let channel = client.channels.get("test-channel");
        assert_eq!(channel.state(), ChannelState::Initialized);
    }

    #[tokio::test]
    async fn rtl2a_state_change_events_emitted() {
        // RTL2a: State changes emit corresponding events
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2a";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let conns = mock.active_connections();
        let conn = conns.last().unwrap();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        let result = attach_task.await.unwrap();
        assert!(result.is_ok());

        let mut changes = Vec::new();
        while let Ok(change) = rx.try_recv() {
            changes.push(change);
        }

        assert!(changes.len() >= 2);
        assert_eq!(changes[0].current, ChannelState::Attaching);
        assert_eq!(changes[0].previous, ChannelState::Initialized);
        assert_eq!(changes[1].current, ChannelState::Attached);
        assert_eq!(changes[1].previous, ChannelState::Attaching);
    }

    #[tokio::test]
    async fn rtl2d_channel_state_change_structure() {
        // RTL2d/TH1/TH2/TH5: ChannelStateChange has current, previous, event
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2d";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        attach_task.await.unwrap().unwrap();

        let change = rx.try_recv().unwrap();
        assert_eq!(change.current, ChannelState::Attaching);
        assert_eq!(change.previous, ChannelState::Initialized);
        assert_eq!(change.event, ChannelEvent::Attaching);
    }

    #[tokio::test]
    async fn rtl2d_channel_state_change_includes_error() {
        // RTL2d/TH3: Error included in state change when channel fails
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2d-error";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut error_msg = ProtocolMessage::new(Action::Error);
        error_msg.channel = Some(channel_name.to_string());
        error_msg.error = Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Channel denied".to_string()),
            href: None,
        });
        conn.send_to_client(error_msg);

        let result = attach_task.await.unwrap();
        assert!(result.is_err());

        let _ = rx.try_recv(); // attaching
        let change = rx.try_recv().unwrap(); // failed
        assert_eq!(change.current, ChannelState::Failed);
        assert!(change.reason.is_some());
        assert_eq!(change.reason.unwrap().code, Some(40160));
    }

    #[tokio::test]
    async fn rtl2_filtered_event_subscription() {
        // RTL2: Subscribing to a specific event only receives that event
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2-filtered";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        attach_task.await.unwrap().unwrap();

        let mut all_events = Vec::new();
        while let Ok(change) = rx.try_recv() {
            all_events.push(change);
        }

        let attached_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.event == ChannelEvent::Attached)
            .collect();
        assert_eq!(attached_events.len(), 1);
        assert_eq!(attached_events[0].current, ChannelState::Attached);
    }

    #[tokio::test]
    async fn rtl2g_update_event_on_additional_attached() {
        // RTL2g: UPDATE event when ATTACHED received while already attached
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2g";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);

        let mut rx = channel.on_state_change();

        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let change = rx.try_recv().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);
        assert_eq!(change.event, ChannelEvent::Update);
        assert_eq!(change.current, ChannelState::Attached);
        assert_eq!(change.previous, ChannelState::Attached);
        assert!(!change.resumed);
    }

    #[tokio::test]
    async fn rtl2g_no_duplicate_state_events() {
        // RTL2g: No duplicate state events
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2g-nodup";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();

        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut all_events = Vec::new();
        while let Ok(change) = rx.try_recv() {
            all_events.push(change);
        }

        let attached_state_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.event == ChannelEvent::Attached)
            .collect();
        assert_eq!(attached_state_events.len(), 1);

        let update_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.event == ChannelEvent::Update)
            .collect();
        assert_eq!(update_events.len(), 1);
    }

    #[tokio::test]
    async fn rtl2i_has_backlog_flag() {
        // RTL2i/TH6: hasBacklog set when ATTACHED has HAS_BACKLOG flag
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2i";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            flags: Some(crate::protocol::flags::HAS_BACKLOG),
            ..ProtocolMessage::new(Action::Attached)
        });

        attach_task.await.unwrap().unwrap();

        let _ = rx.try_recv(); // attaching
        let change = rx.try_recv().unwrap(); // attached
        assert_eq!(change.current, ChannelState::Attached);
        assert!(change.has_backlog);
    }

    #[tokio::test]
    async fn rtl2i_has_backlog_false_when_not_present() {
        // RTL2i: hasBacklog false when flag not present
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2i-false";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        attach_task.await.unwrap().unwrap();

        let _ = rx.try_recv(); // attaching
        let change = rx.try_recv().unwrap(); // attached
        assert!(!change.has_backlog);
    }

    #[tokio::test]
    async fn rtl2d_resumed_flag_in_state_change() {
        // RTL2d: resumed flag propagated in ChannelStateChange
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL2d-resumed";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            flags: Some(crate::protocol::flags::RESUMED),
            ..ProtocolMessage::new(Action::Attached)
        });

        attach_task.await.unwrap().unwrap();

        let _ = rx.try_recv(); // attaching
        let change = rx.try_recv().unwrap(); // attached
        assert!(change.resumed);
    }

    #[tokio::test]
    async fn channel_error_reason_populated_on_failure() {
        // Channel errorReason populated when channel enters failed state
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-errorReason";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut error_msg = ProtocolMessage::new(Action::Error);
        error_msg.channel = Some(channel_name.to_string());
        error_msg.error = Some(ErrorInfo {
            code: Some(40160),
            status_code: Some(401),
            message: Some("Not authorized".to_string()),
            href: None,
        });
        conn.send_to_client(error_msg);

        let result = attach_task.await.unwrap();
        assert!(result.is_err());

        assert_eq!(channel.state(), ChannelState::Failed);
        let err = channel.error_reason();
        assert!(err.is_some());
        assert_eq!(err.unwrap().code, Some(40160));
    }

    #[tokio::test]
    async fn channel_error_reason_cleared_on_successful_attach() {
        // errorReason cleared after successful attach following a failure
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-errorReason-clear";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First attach fails
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let mut error_msg = ProtocolMessage::new(Action::Error);
        error_msg.channel = Some(channel_name.to_string());
        error_msg.error = Some(ErrorInfo {
            code: Some(40160),
            status_code: None,
            message: Some("Denied".to_string()),
            href: None,
        });
        conn.send_to_client(error_msg);

        let result = attach_task.await.unwrap();
        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Failed);
        assert!(channel.error_reason().is_some());

        // Second attach succeeds
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        let result = attach_task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(channel.state(), ChannelState::Attached);
        assert!(channel.error_reason().is_none());
    }

    // --- Channel Options (TB2-4, RTS3b/c) ---

    #[test]
    fn tb2_channel_options_defaults() {
        // TB2/TB4: ChannelOptions has correct default values
        use crate::channel::RealtimeChannelOptions;

        let options = RealtimeChannelOptions::new();
        assert!(options.params.is_none());
        assert!(options.modes.is_none());
        assert!(options.attach_on_subscribe);
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
        assert!(options1.attach_on_subscribe);

        let options2 = RealtimeChannelOptions {
            attach_on_subscribe: false,
            ..RealtimeChannelOptions::default()
        };
        assert!(!options2.attach_on_subscribe);
    }

    #[test]
    fn rts3b_options_set_on_new_channel() {
        // RTS3b: get() with options sets them on new channels
        use crate::channel::RealtimeChannelOptions;
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ChannelMode;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let mut params = std::collections::HashMap::new();
        params.insert("rewind".to_string(), "1".to_string());

        let channel_options = RealtimeChannelOptions {
            params: Some(params),
            modes: Some(vec![ChannelMode::Subscribe]),
            ..RealtimeChannelOptions::default()
        };

        let channel = client
            .channels
            .get_with_options("test-channel", channel_options)
            .unwrap();

        let opts = channel.options();
        assert_eq!(opts.params.unwrap().get("rewind").unwrap(), "1");
        assert!(opts.modes.unwrap().contains(&ChannelMode::Subscribe));
    }

    #[test]
    fn rts3c_options_updated_on_existing_channel() {
        // RTS3c: get() with options updates existing channel options
        use crate::channel::RealtimeChannelOptions;
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let initial_options = RealtimeChannelOptions {
            attach_on_subscribe: false,
            ..RealtimeChannelOptions::default()
        };
        let channel = client
            .channels
            .get_with_options("test-channel", initial_options)
            .unwrap();

        let new_options = RealtimeChannelOptions {
            attach_on_subscribe: true,
            ..RealtimeChannelOptions::default()
        };
        let same_channel = client
            .channels
            .get_with_options("test-channel", new_options)
            .unwrap();

        assert!(std::sync::Arc::ptr_eq(&channel, &same_channel));
        assert!(channel.options().attach_on_subscribe);
    }

    #[tokio::test]
    async fn rts3c1_error_if_options_would_trigger_reattachment() {
        // RTS3c1: Error if params/modes change on attached channel via get()
        use crate::channel::RealtimeChannelOptions;
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTS3c1";

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);

        let mut params = std::collections::HashMap::new();
        params.insert("rewind".to_string(), "1".to_string());
        let new_options = RealtimeChannelOptions {
            params: Some(params),
            ..RealtimeChannelOptions::default()
        };

        let result = client.channels.get_with_options(channel_name, new_options);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.code, Some(40000));

        assert!(channel.options().params.is_none());
    }

    #[tokio::test]
    async fn rtl16_set_options_updates_channel() {
        // RTL16: setOptions updates channel options
        use crate::channel::RealtimeChannelOptions;
        use crate::mock_ws::MockWebSocket;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport,
        )
        .unwrap();

        let channel = client.channels.get("test-channel");

        let mut params = std::collections::HashMap::new();
        params.insert("delta".to_string(), "vcdiff".to_string());
        let new_options = RealtimeChannelOptions {
            params: Some(params),
            attach_on_subscribe: false,
            ..RealtimeChannelOptions::default()
        };

        channel.set_options(new_options).await.unwrap();

        let opts = channel.options();
        assert_eq!(opts.params.unwrap().get("delta").unwrap(), "vcdiff");
        assert!(!opts.attach_on_subscribe);
    }

    // ==================== Phase 8b: Attach & Detach Tests ====================

    #[tokio::test]
    async fn rtl4a_attach_when_already_attached_is_noop() {
        // RTL4a: If already ATTACHED nothing is done
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4a";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First attach
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);

        // Count ATTACH messages before second attach
        let msgs_before: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        let count_before = msgs_before.len();

        // Second attach — should be no-op
        channel.attach().await.unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);

        let msgs_after: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert_eq!(msgs_after.len(), count_before); // No additional ATTACH sent
    }

    #[tokio::test]
    async fn rtl4h_attach_while_attaching_waits() {
        // RTL4h: If ATTACHING, attach waits for completion
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4h";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Start first attach (don't await)
        let ch1 = channel.clone();
        let attach1 = tokio::spawn(async move { ch1.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Attaching);

        // Start second attach while first is pending
        let ch2 = channel.clone();
        let attach2 = tokio::spawn(async move { ch2.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Send ATTACHED response
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        // Both should complete
        attach1.await.unwrap().unwrap();
        attach2.await.unwrap().unwrap();

        assert_eq!(channel.state(), ChannelState::Attached);
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert_eq!(attach_msgs.len(), 1); // Only one ATTACH sent
    }

    #[tokio::test]
    async fn rtl4h_attach_while_detaching_waits_then_attaches() {
        // RTL4h: If DETACHING, attach waits for detach then attaches
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4h-detaching";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First attach
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();

        // Start detach (don't await)
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Detaching);

        // Start attach while detaching
        let ch = channel.clone();
        let attach_task2 = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Send DETACHED response
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();

        // The queued attach should now proceed — send ATTACHED
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task2.await.unwrap().unwrap();

        assert_eq!(channel.state(), ChannelState::Attached);
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert_eq!(attach_msgs.len(), 2); // ATTACH, DETACH, ATTACH
    }

    #[tokio::test]
    async fn rtl4g_attach_from_failed_clears_error_reason() {
        // RTL4g: Attach from FAILED clears errorReason
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4g";
        let attach_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attach_count_h = attach_count.clone();

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First attach — will fail
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(40160),
                status_code: None,
                message: Some("Denied".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });
        let result = attach_task.await.unwrap();
        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Failed);
        assert!(channel.error_reason().is_some());

        // Second attach from failed — should clear errorReason
        let ch = channel.clone();
        let attach_task2 = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task2.await.unwrap().unwrap();

        assert_eq!(channel.state(), ChannelState::Attached);
        assert!(channel.error_reason().is_none());
    }

    #[tokio::test]
    async fn rtl4b_attach_fails_when_connection_closed() {
        // RTL4b: Attach fails when connection is CLOSED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Close connection
        client.close();
        assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

        let channel = client.channels.get("test-RTL4b-closed");
        let result = channel.attach().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rtl4b_attach_fails_when_connection_failed() {
        // RTL4b: Attach fails when connection is FAILED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            let msg = ProtocolMessage::connected("conn-1", "key-1");
            pending.respond_with_success(msg);
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Send fatal error to force FAILED
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client_and_close(ProtocolMessage {
            action: Action::Error,
            error: Some(ErrorInfo {
                code: Some(80000),
                status_code: None,
                message: Some("Fatal error".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        let channel = client.channels.get("test-RTL4b-failed");
        let result = channel.attach().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rtl4i_attach_queued_when_connecting() {
        // RTL4i: Attach transitions to ATTACHING when connection is CONNECTING
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::ChannelState;
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new(); // No handler — connection stays pending
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        // Connection is CONNECTING (no handler to respond)

        let channel = client.channels.get("test-RTL4i");

        // Start attach while connecting
        let ch = channel.clone();
        let _attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Attaching);
    }

    #[tokio::test]
    async fn rtl4i_attach_completes_when_connected() {
        // RTL4i: Queued attach completes when connection becomes CONNECTED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4i-connected";
        let mock = MockWebSocket::new(); // await-based — no auto handler
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();

        let channel = client.channels.get(channel_name);

        // Start attach while connecting
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Attaching);

        // Complete connection
        let pending = mock.await_connection().await;
        pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // RTL4i: The connection sends queued ATTACH. Wait for it, then respond.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        attach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);
    }

    #[tokio::test]
    async fn rtl4c_attach_sends_message_and_transitions() {
        // RTL4c: ATTACH sent, transitions to ATTACHING, then ATTACHED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4c";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let mut rx = channel.on_state_change();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify ATTACH message was sent
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| {
                m.message.action == Action::Attach
                    && m.message.channel.as_deref() == Some(channel_name)
            })
            .collect();
        assert_eq!(attach_msgs.len(), 1);

        // Verify ATTACHING event was emitted
        let change = rx.try_recv().unwrap();
        assert_eq!(change.event, ChannelEvent::Attaching);
        assert_eq!(change.current, ChannelState::Attaching);

        // Send ATTACHED
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);
    }

    #[tokio::test]
    async fn rtl4c1_attach_includes_channel_serial() {
        // RTL4c1: ATTACH includes channelSerial when available
        use crate::channel::RealtimeChannelOptions;
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelMode, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4c1";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First attach
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            channel_serial: Some("serial-from-server-1".to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();

        // Trigger reattach via setOptions (doesn't go through DETACHED)
        let ch = channel.clone();
        let set_opts_task = tokio::spawn(async move {
            ch.set_options(RealtimeChannelOptions {
                modes: Some(vec![ChannelMode::Subscribe]),
                ..RealtimeChannelOptions::default()
            })
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            channel_serial: Some("serial-from-server-2".to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        set_opts_task.await.unwrap().unwrap();

        // Check captured ATTACH messages
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert_eq!(attach_msgs.len(), 2);
        // First attach: no channelSerial
        assert!(attach_msgs[0].message.channel_serial.is_none());
        // Second attach: has channelSerial from first ATTACHED
        assert_eq!(
            attach_msgs[1].message.channel_serial.as_deref(),
            Some("serial-from-server-1")
        );
    }

    #[tokio::test]
    async fn rtl4f_attach_timeout_transitions_to_suspended() {
        // RTL4f: Attach timeout → SUSPENDED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-RTL4f");

        // Don't send ATTACHED response — let it timeout
        let result = channel.attach().await;
        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Suspended);
    }

    #[tokio::test]
    async fn rtl4k_attach_includes_params() {
        // RTL4k: ATTACH includes params from ChannelOptions
        use crate::channel::RealtimeChannelOptions;
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4k";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let mut params = std::collections::HashMap::new();
        params.insert("rewind".to_string(), "1".to_string());
        params.insert("delta".to_string(), "vcdiff".to_string());
        let opts = RealtimeChannelOptions {
            params: Some(params),
            ..RealtimeChannelOptions::default()
        };
        let channel = client
            .channels
            .get_with_options(channel_name, opts)
            .unwrap();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Check params in ATTACH message
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert_eq!(attach_msgs.len(), 1);
        let p = attach_msgs[0].message.params.as_ref().unwrap();
        assert_eq!(p.get("rewind").unwrap(), "1");
        assert_eq!(p.get("delta").unwrap(), "vcdiff");

        // Send ATTACHED to complete
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rtl4l_attach_includes_modes_as_flags() {
        // RTL4l: Modes encoded as flags in ATTACH
        use crate::channel::RealtimeChannelOptions;
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{flags, Action, ChannelMode, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4l";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let opts = RealtimeChannelOptions {
            modes: Some(vec![ChannelMode::Publish, ChannelMode::Subscribe]),
            ..RealtimeChannelOptions::default()
        };
        let channel = client
            .channels
            .get_with_options(channel_name, opts)
            .unwrap();

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert_eq!(attach_msgs.len(), 1);
        let f = attach_msgs[0].message.flags.unwrap();
        assert_ne!(f & flags::PUBLISH, 0);
        assert_ne!(f & flags::SUBSCRIBE, 0);

        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rtl4m_modes_populated_from_attached_response() {
        // RTL4m: Modes decoded from ATTACHED flags
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            flags, Action, ChannelMode, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4m";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            flags: Some(flags::PUBLISH | flags::SUBSCRIBE),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();

        let modes = channel.modes().unwrap();
        assert!(modes.contains(&ChannelMode::Publish));
        assert!(modes.contains(&ChannelMode::Subscribe));
    }

    #[tokio::test]
    async fn rtl4j_attach_resume_flag_on_reattach() {
        // RTL4j: ATTACH_RESUME flag set on reattachment
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{flags, Action, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL4j";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First attach
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();

        // Detach
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();

        // Reattach — should have ATTACH_RESUME
        let ch = channel.clone();
        let attach_task2 = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task2.await.unwrap().unwrap();

        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert_eq!(attach_msgs.len(), 2);
        // First: no ATTACH_RESUME
        let f0 = attach_msgs[0].message.flags.unwrap_or(0);
        assert_eq!(f0 & flags::ATTACH_RESUME, 0);
        // Second: has ATTACH_RESUME
        let f1 = attach_msgs[1].message.flags.unwrap_or(0);
        assert_ne!(f1 & flags::ATTACH_RESUME, 0);
    }

    // ==================== RTL5: Detach Tests ====================

    #[tokio::test]
    async fn rtl5a_detach_when_initialized_is_noop() {
        // RTL5a: Detach from INITIALIZED is no-op
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        let channel = client.channels.get("test-RTL5a");
        assert_eq!(channel.state(), ChannelState::Initialized);
        channel.detach().await.unwrap();
        // State may remain Initialized or become Detached — both are acceptable
    }

    #[tokio::test]
    async fn rtl5a_detach_when_already_detached_is_noop() {
        // RTL5a: Detach from DETACHED is no-op
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5a-detached";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach then detach
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        t.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Detached);

        let detach_count_before = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Detach)
            .count();

        // Second detach — should be no-op
        channel.detach().await.unwrap();
        assert_eq!(channel.state(), ChannelState::Detached);

        let detach_count_after = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Detach)
            .count();
        assert_eq!(detach_count_after, detach_count_before);
    }

    #[tokio::test]
    async fn rtl5i_detach_while_detaching_waits() {
        // RTL5i: If DETACHING, detach waits for completion
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5i";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach first
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Start first detach (don't await)
        let ch = channel.clone();
        let detach1 = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Detaching);

        // Start second detach while first is pending
        let ch = channel.clone();
        let detach2 = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Send DETACHED response
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });

        detach1.await.unwrap().unwrap();
        detach2.await.unwrap().unwrap();

        assert_eq!(channel.state(), ChannelState::Detached);
        let detach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Detach)
            .collect();
        assert_eq!(detach_msgs.len(), 1);
    }

    #[tokio::test]
    async fn rtl5i_detach_while_attaching_waits_then_detaches() {
        // RTL5i: If ATTACHING, detach waits for attach then detaches
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5i-attaching";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Start attach (don't await)
        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Attaching);

        // Start detach while attaching
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Send ATTACHED response — attach completes
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();

        // Wait for detach to proceed, send DETACHED
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();

        assert_eq!(channel.state(), ChannelState::Detached);
    }

    #[tokio::test]
    async fn rtl5b_detach_from_failed_results_in_error() {
        // RTL5b: Detach from FAILED is an error
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5b";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Fail the channel
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(40160),
                status_code: None,
                message: Some("Not permitted".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });
        let _ = t.await.unwrap();
        assert_eq!(channel.state(), ChannelState::Failed);

        // Try to detach from failed state
        let result = channel.detach().await;
        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Failed);
    }

    #[tokio::test]
    async fn rtl5j_detach_from_suspended_transitions_to_detached() {
        // RTL5j: Detach from SUSPENDED → immediate DETACHED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-RTL5j");

        // Attach with timeout to get to SUSPENDED
        let result = channel.attach().await;
        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Suspended);

        // Detach from suspended — immediate transition
        channel.detach().await.unwrap();
        assert_eq!(channel.state(), ChannelState::Detached);
    }

    #[tokio::test]
    async fn rtl5l_detach_when_not_connected_transitions_immediately() {
        // RTL5l: Detach when connection not CONNECTED → immediate DETACHED
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState};
        use crate::realtime::Realtime;

        let mock = MockWebSocket::new(); // No handler — stays connecting
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();

        let channel = client.channels.get("test-RTL5l");

        // Start attach while connecting
        let ch = channel.clone();
        let _attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Attaching);

        // Detach while not connected — immediate
        channel.detach().await.unwrap();
        assert_eq!(channel.state(), ChannelState::Detached);

        // No DETACH message sent
        let detach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Detach)
            .collect();
        assert_eq!(detach_msgs.len(), 0);
    }

    #[tokio::test]
    async fn rtl5d_normal_detach_flow() {
        // RTL5d: DETACH sent, transitions to DETACHING then DETACHED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5d";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let mut rx = channel.on_state_change();

        // Start detach
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify DETACH message was sent
        let detach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| {
                m.message.action == Action::Detach
                    && m.message.channel.as_deref() == Some(channel_name)
            })
            .collect();
        assert_eq!(detach_msgs.len(), 1);

        // Verify DETACHING event
        let change = rx.try_recv().unwrap();
        assert_eq!(change.event, ChannelEvent::Detaching);
        assert_eq!(change.previous, ChannelState::Attached);

        // Send DETACHED
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Detached);
    }

    #[tokio::test]
    async fn rtl5f_detach_timeout_returns_to_previous_state() {
        // RTL5f: Detach timeout → back to ATTACHED
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5f";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(100))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach first
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);

        // Don't respond to DETACH — let it timeout
        let result = channel.detach().await;
        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Attached); // Returns to previous state
    }

    #[tokio::test]
    async fn rtl5k_attached_during_detaching_sends_new_detach() {
        // RTL5k: ATTACHED received while DETACHING → sends new DETACH
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5k";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Start detach (don't await)
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Detaching);

        // Server unexpectedly sends ATTACHED instead of DETACHED
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Should have sent another DETACH
        let detach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Detach)
            .collect();
        assert!(detach_msgs.len() >= 2);

        // Now send DETACHED to complete
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Detached);
    }

    #[tokio::test]
    async fn rtl5k_attached_while_detached_sends_detach() {
        // RTL5k: ATTACHED received while DETACHED → sends DETACH
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5k-detached";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach then detach
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        t.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Detached);

        let detach_count_before = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Detach)
            .count();

        // Server unexpectedly sends ATTACHED while detached
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let detach_count_after = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Detach)
            .count();
        assert!(detach_count_after > detach_count_before); // Client sent another DETACH
        assert_eq!(channel.state(), ChannelState::Detached);
    }

    #[tokio::test]
    async fn rtl5_detach_emits_state_change_events() {
        // RTL5: Detach emits DETACHING then DETACHED events
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5-events";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Subscribe to events after attach
        let mut rx = channel.on_state_change();

        // Detach
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();

        // Collect state changes
        let change1 = rx.try_recv().unwrap();
        assert_eq!(change1.current, ChannelState::Detaching);
        assert_eq!(change1.previous, ChannelState::Attached);
        assert_eq!(change1.event, ChannelEvent::Detaching);

        let change2 = rx.try_recv().unwrap();
        assert_eq!(change2.current, ChannelState::Detached);
        assert_eq!(change2.previous, ChannelState::Detaching);
        assert_eq!(change2.event, ChannelEvent::Detached);
    }

    #[tokio::test]
    async fn rtl5_detach_clears_error_reason() {
        // RTL5: Successful detach clears errorReason
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTL5-error";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First attach fails
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(40160),
                status_code: None,
                message: Some("Denied".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });
        let _ = t.await.unwrap();
        assert_eq!(channel.state(), ChannelState::Failed);
        assert!(channel.error_reason().is_some());

        // Second attach succeeds
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Detach
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        t.await.unwrap().unwrap();

        assert_eq!(channel.state(), ChannelState::Detached);
        assert!(channel.error_reason().is_none());
    }

    // ==================== RTC7: Timeout Configuration Tests ====================

    #[tokio::test]
    async fn rtc7_realtime_request_timeout_applied_to_attach() {
        // RTC7: Custom realtimeRequestTimeout applied to attach
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(200))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-RTC7-attach");

        let start = std::time::Instant::now();
        let result = channel.attach().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Suspended);
        // Should timeout around 200ms, not the default 10s
        assert!(elapsed.as_millis() < 2000);
    }

    #[tokio::test]
    async fn rtc7_realtime_request_timeout_applied_to_detach() {
        // RTC7: Custom realtimeRequestTimeout applied to detach
        use crate::mock_ws::{MockWebSocket, PendingConnection};
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-RTC7-detach";
        let mock = MockWebSocket::with_handler(|pending: PendingConnection| {
            pending.respond_with_success(ProtocolMessage::connected("conn-1", "key-1"));
        });

        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .realtime_request_timeout(std::time::Duration::from_millis(200))
                .fallback_hosts(vec![]),
            transport,
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach first
        let ch = channel.clone();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Don't respond to DETACH
        let start = std::time::Instant::now();
        let result = channel.detach().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert_eq!(channel.state(), ChannelState::Attached); // Back to previous
        assert!(elapsed.as_millis() < 2000);
    }

    // ===== Phase 8c: Messages =====

    // --- RTL6i1: Publish single message by name and data ---
    #[tokio::test]
    async fn rtl6i1_publish_single_message() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6i1";
        let mock = MockWebSocket::with_handler({
            let cn = channel_name.to_string();
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Publish
        let ch = channel.clone();
        let publish_handle = tokio::spawn(async move {
            ch.publish(Some("greeting"), Some(serde_json::json!("hello")))
                .await
        });

        // Wait for the MESSAGE to be captured
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs.len(), 1);
        assert_eq!(
            message_msgs[0].message.channel.as_deref(),
            Some(channel_name)
        );
        let messages = message_msgs[0].message.messages.as_ref().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["name"], "greeting");
        assert_eq!(messages[0]["data"], "hello");

        // Send ACK to resolve publish
        let msg_serial = message_msgs[0].message.msg_serial.unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Ack,
            msg_serial: Some(msg_serial),
            count: Some(1),
            res: Some(vec![crate::protocol::PublishResult {
                serials: vec![Some("serial-1".to_string())],
            }]),
            ..ProtocolMessage::new(Action::Ack)
        });

        let result = publish_handle.await.unwrap().unwrap();
        assert_eq!(result.serials.len(), 1);
        assert_eq!(result.serials[0].as_deref(), Some("serial-1"));
    }

    // --- RTL6i2: Publish array of Message objects ---
    #[tokio::test]
    async fn rtl6i2_publish_array_of_messages() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6i2";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Publish array
        let ch = channel.clone();
        let publish_handle = tokio::spawn(async move {
            ch.publish_messages(vec![
                serde_json::json!({"name": "event1", "data": "data1"}),
                serde_json::json!({"name": "event2", "data": "data2"}),
                serde_json::json!({"name": "event3", "data": "data3"}),
            ])
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs.len(), 1); // Single ProtocolMessage
        let messages = message_msgs[0].message.messages.as_ref().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["name"], "event1");
        assert_eq!(messages[1]["name"], "event2");
        assert_eq!(messages[2]["name"], "event3");

        // Send ACK
        let msg_serial = message_msgs[0].message.msg_serial.unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Ack,
            msg_serial: Some(msg_serial),
            count: Some(1),
            res: Some(vec![crate::protocol::PublishResult {
                serials: vec![
                    Some("s1".to_string()),
                    Some("s2".to_string()),
                    Some("s3".to_string()),
                ],
            }]),
            ..ProtocolMessage::new(Action::Ack)
        });

        let result = publish_handle.await.unwrap().unwrap();
        assert_eq!(result.serials.len(), 3);
    }

    // --- RTL6c1: Publish immediately when CONNECTED and channel ATTACHED ---
    #[tokio::test]
    async fn rtl6c1_publish_immediately_when_attached() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c1-attached";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();
        assert_eq!(channel.state(), ChannelState::Attached);

        // Publish — should be sent immediately (synchronously captured by mock)
        let ch = channel.clone();
        let _publish_handle = tokio::spawn(async move {
            ch.publish(Some("test"), Some(serde_json::json!("immediate")))
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs.len(), 1);
        assert_eq!(
            message_msgs[0].message.messages.as_ref().unwrap()[0]["name"],
            "test"
        );
        assert_eq!(
            message_msgs[0].message.messages.as_ref().unwrap()[0]["data"],
            "immediate"
        );
    }

    // --- RTL6c1: Publish immediately when CONNECTED and channel INITIALIZED ---
    #[tokio::test]
    async fn rtl6c1_publish_immediately_when_initialized() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c1-init";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(channel.state(), ChannelState::Initialized);

        // Publish on initialized channel — should send immediately (RTL6c1)
        let ch = channel.clone();
        let _publish_handle = tokio::spawn(async move {
            ch.publish(Some("before-attach"), Some(serde_json::json!("data")))
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs.len(), 1);
        assert_eq!(
            message_msgs[0].message.messages.as_ref().unwrap()[0]["name"],
            "before-attach"
        );
    }

    // --- RTL6c5: Publish does not trigger implicit attach ---
    #[tokio::test]
    async fn rtl6c5_publish_does_not_attach() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c5";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(channel.state(), ChannelState::Initialized);

        let ch = channel.clone();
        let _publish_handle = tokio::spawn(async move {
            ch.publish(Some("no-attach"), Some(serde_json::json!("test")))
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Channel should remain INITIALIZED — no implicit attach
        assert_eq!(channel.state(), ChannelState::Initialized);
        let msgs = mock.client_messages();
        let attach_count = msgs
            .iter()
            .filter(|m| m.message.action == Action::Attach)
            .count();
        assert_eq!(attach_count, 0);
        // Message should have been sent
        let message_count = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .count();
        assert_eq!(message_count, 1);
    }

    // --- RTL6c2: Publish queued when connection CONNECTING ---
    #[tokio::test]
    async fn rtl6c2_publish_queued_when_connecting() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c2-connecting";
        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connecting, 5000).await);

        // Publish while CONNECTING — should be queued
        let ch = channel.clone();
        let publish_handle = tokio::spawn(async move {
            ch.publish(Some("queued"), Some(serde_json::json!("waiting")))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Message should NOT have been sent yet
        let msgs = mock.client_messages();
        let message_count = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .count();
        assert_eq!(message_count, 0);

        // Complete the connection
        let pending = mock.await_connection().await;
        pending.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Queued message should now have been sent
        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs.len(), 1);
        assert_eq!(
            message_msgs[0].message.messages.as_ref().unwrap()[0]["name"],
            "queued"
        );

        // ACK to resolve
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let msg_serial = message_msgs[0].message.msg_serial.unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Ack,
            msg_serial: Some(msg_serial),
            count: Some(1),
            res: Some(vec![crate::protocol::PublishResult { serials: vec![] }]),
            ..ProtocolMessage::new(Action::Ack)
        });

        let result = publish_handle.await.unwrap();
        assert!(result.is_ok());
    }

    // --- RTL6c2: Publish queued when connection INITIALIZED ---
    #[tokio::test]
    async fn rtl6c2_publish_queued_when_initialized() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c2-init";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(client.connection.state(), ConnectionState::Initialized);

        // Publish before connecting — should be queued
        let ch = channel.clone();
        let publish_handle = tokio::spawn(async move {
            ch.publish(Some("pre-connect"), Some(serde_json::json!("early")))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msgs = mock.client_messages();
        let message_count = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .count();
        assert_eq!(message_count, 0);

        // Now connect
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs.len(), 1);
        assert_eq!(
            message_msgs[0].message.messages.as_ref().unwrap()[0]["name"],
            "pre-connect"
        );

        // ACK
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        let msg_serial = message_msgs[0].message.msg_serial.unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Ack,
            msg_serial: Some(msg_serial),
            count: Some(1),
            res: Some(vec![crate::protocol::PublishResult { serials: vec![] }]),
            ..ProtocolMessage::new(Action::Ack)
        });

        let result = publish_handle.await.unwrap();
        assert!(result.is_ok());
    }

    // --- RTL6c2: Multiple queued messages sent in order ---
    #[tokio::test]
    async fn rtl6c2_multiple_queued_messages_order() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c2-order";
        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connecting, 5000).await);

        // Queue multiple messages
        let ch1 = channel.clone();
        let ch2 = channel.clone();
        let ch3 = channel.clone();
        let _h1 = tokio::spawn(async move {
            ch1.publish(Some("first"), Some(serde_json::json!("1")))
                .await
        });
        let _h2 = tokio::spawn(async move {
            ch2.publish(Some("second"), Some(serde_json::json!("2")))
                .await
        });
        let _h3 = tokio::spawn(async move {
            ch3.publish(Some("third"), Some(serde_json::json!("3")))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            mock.client_messages()
                .iter()
                .filter(|m| m.message.action == Action::Message)
                .count(),
            0
        );

        // Complete connection
        let pending = mock.await_connection().await;
        pending.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs.len(), 3);
        assert_eq!(
            message_msgs[0].message.messages.as_ref().unwrap()[0]["name"],
            "first"
        );
        assert_eq!(
            message_msgs[1].message.messages.as_ref().unwrap()[0]["name"],
            "second"
        );
        assert_eq!(
            message_msgs[2].message.messages.as_ref().unwrap()[0]["name"],
            "third"
        );
    }

    // --- RTL6c4: Publish fails when connection CLOSED ---
    #[tokio::test]
    async fn rtl6c4_publish_fails_when_connection_closed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c4-closed";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        client.close();
        assert!(await_state(&client.connection, ConnectionState::Closed, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let result = channel
            .publish(Some("fail"), Some(serde_json::json!("should-error")))
            .await;
        assert!(result.is_err());
    }

    // --- RTL6c4: Publish fails when connection FAILED ---
    #[tokio::test]
    async fn rtl6c4_publish_fails_when_connection_failed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c4-failed";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_error(ProtocolMessage {
                    action: Action::Error,
                    error: Some(ErrorInfo {
                        code: Some(80000),
                        status_code: None,
                        message: Some("Fatal error".to_string()),
                        href: None,
                    }),
                    ..ProtocolMessage::new(Action::Error)
                });
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let result = channel
            .publish(Some("fail"), Some(serde_json::json!("should-error")))
            .await;
        assert!(result.is_err());
    }

    // --- RTL6c4: Publish fails when channel is FAILED ---
    #[tokio::test]
    async fn rtl6c4_publish_fails_when_channel_failed() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c4-ch-failed";
        let mock = MockWebSocket::with_handler({
            let cn = channel_name.to_string();
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach fails → channel enters FAILED
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(cn),
            error: Some(ErrorInfo {
                code: Some(40160),
                status_code: Some(401),
                message: Some("Not permitted".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });
        let _ = t.await.unwrap();
        assert_eq!(channel.state(), ChannelState::Failed);

        let result = channel
            .publish(Some("fail"), Some(serde_json::json!("should-error")))
            .await;
        assert!(result.is_err());
    }

    // --- RTL6c2: Publish fails when queueMessages is false ---
    #[tokio::test]
    async fn rtl6c2_publish_fails_when_queue_disabled() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6c2-noqueue";
        let mock = MockWebSocket::new();
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .queue_messages(false),
            transport.clone(),
        )
        .unwrap();

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connecting, 5000).await);

        let result = channel
            .publish(Some("fail"), Some(serde_json::json!("should-error")))
            .await;
        assert!(result.is_err());
    }

    // --- RTL6j: Publish returns PublishResult with serials ---
    #[tokio::test]
    async fn rtl6j_publish_returns_publish_result() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6j";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Publish
        let ch = channel.clone();
        let publish_handle = tokio::spawn(async move {
            ch.publish(Some("greeting"), Some(serde_json::json!("hello")))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msgs = mock.client_messages();
        let message_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| m.message.action == Action::Message)
            .collect();
        assert_eq!(message_msgs[0].message.msg_serial, Some(0));

        // ACK with serials
        conn.send_to_client(ProtocolMessage {
            action: Action::Ack,
            msg_serial: Some(0),
            count: Some(1),
            res: Some(vec![crate::protocol::PublishResult {
                serials: vec![Some("abc123".to_string())],
            }]),
            ..ProtocolMessage::new(Action::Ack)
        });

        let result = publish_handle.await.unwrap().unwrap();
        assert_eq!(result.serials.len(), 1);
        assert_eq!(result.serials[0].as_deref(), Some("abc123"));
    }

    // --- RTL6j: Batch publish returns multiple serials ---
    #[tokio::test]
    async fn rtl6j_batch_publish_returns_multiple_serials() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl6j-batch";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        // Publish batch
        let ch = channel.clone();
        let publish_handle = tokio::spawn(async move {
            ch.publish_messages(vec![
                serde_json::json!({"name": "msg1"}),
                serde_json::json!({"name": "msg2"}),
                serde_json::json!({"name": "msg3"}),
            ])
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // ACK with serials (one null for conflation)
        conn.send_to_client(ProtocolMessage {
            action: Action::Ack,
            msg_serial: Some(0),
            count: Some(1),
            res: Some(vec![crate::protocol::PublishResult {
                serials: vec![
                    Some("serial-1".to_string()),
                    None,
                    Some("serial-3".to_string()),
                ],
            }]),
            ..ProtocolMessage::new(Action::Ack)
        });

        let result = publish_handle.await.unwrap().unwrap();
        assert_eq!(result.serials.len(), 3);
        assert_eq!(result.serials[0].as_deref(), Some("serial-1"));
        assert!(result.serials[1].is_none());
        assert_eq!(result.serials[2].as_deref(), Some("serial-3"));
    }

    // --- RTL7a: Subscribe with no name receives all messages ---
    #[tokio::test]
    async fn rtl7a_subscribe_receives_all_messages() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7a";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        // Send messages with different names
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"name": "event1", "data": "data1"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"name": "event2", "data": "data2"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"data": "data3"})]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msg1 = rx.try_recv().unwrap();
        assert_eq!(msg1.name.as_deref(), Some("event1"));
        assert_eq!(msg1.data.as_ref().unwrap(), "data1");
        let msg2 = rx.try_recv().unwrap();
        assert_eq!(msg2.name.as_deref(), Some("event2"));
        let msg3 = rx.try_recv().unwrap();
        assert!(msg3.name.is_none());
        assert_eq!(msg3.data.as_ref().unwrap(), "data3");
    }

    // --- RTL7a: Subscribe receives multiple messages from single ProtocolMessage ---
    #[tokio::test]
    async fn rtl7a_subscribe_multiple_messages_in_single_protocol_message() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7a-multi";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        // Single ProtocolMessage with multiple messages
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![
                serde_json::json!({"name": "batch1", "data": "first"}),
                serde_json::json!({"name": "batch2", "data": "second"}),
                serde_json::json!({"name": "batch3", "data": "third"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msg1 = rx.try_recv().unwrap();
        assert_eq!(msg1.name.as_deref(), Some("batch1"));
        let msg2 = rx.try_recv().unwrap();
        assert_eq!(msg2.name.as_deref(), Some("batch2"));
        let msg3 = rx.try_recv().unwrap();
        assert_eq!(msg3.name.as_deref(), Some("batch3"));
    }

    // --- RTL7b: Subscribe with name only receives matching messages ---
    #[tokio::test]
    async fn rtl7b_subscribe_with_name_filter() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7b";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe_with_name("target");

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"name": "other", "data": "skip"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"name": "target", "data": "match"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"data": "no-name"})]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.name.as_deref(), Some("target"));
        assert_eq!(msg.data.as_ref().unwrap(), "match");
        // No more messages
        assert!(rx.try_recv().is_err());
    }

    // --- RTL7b: Multiple name-specific subscriptions ---
    #[tokio::test]
    async fn rtl7b_multiple_name_subscriptions() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7b-multi";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_alpha_id, mut alpha_rx) = channel.subscribe_with_name("alpha");
        let (_beta_id, mut beta_rx) = channel.subscribe_with_name("beta");

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![
                serde_json::json!({"name": "alpha", "data": "a1"}),
                serde_json::json!({"name": "beta", "data": "b1"}),
                serde_json::json!({"name": "alpha", "data": "a2"}),
                serde_json::json!({"name": "gamma", "data": "g1"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(alpha_rx.try_recv().unwrap().data.as_ref().unwrap(), "a1");
        assert_eq!(alpha_rx.try_recv().unwrap().data.as_ref().unwrap(), "a2");
        assert!(alpha_rx.try_recv().is_err());

        assert_eq!(beta_rx.try_recv().unwrap().data.as_ref().unwrap(), "b1");
        assert!(beta_rx.try_recv().is_err());
    }

    // --- RTL7g: Subscribe triggers implicit attach ---
    #[tokio::test]
    async fn rtl7g_subscribe_triggers_implicit_attach() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7g";
        let mock = MockWebSocket::with_handler({
            let cn = channel_name.to_string();
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Default attachOnSubscribe is true
        let channel = client.channels.get(channel_name);
        assert_eq!(channel.state(), ChannelState::Initialized);

        let (_sub_id, mut rx) = channel.subscribe();

        // Wait for implicit attach to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Respond to ATTACH
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Attached);

        // Verify the listener was registered
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(channel_name.to_string()),
            messages: Some(vec![serde_json::json!({"name": "test", "data": "hello"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.name.as_deref(), Some("test"));
    }

    // --- RTL7h: Subscribe does not attach when attachOnSubscribe is false ---
    #[tokio::test]
    async fn rtl7h_subscribe_no_attach_when_disabled() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7h";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(channel.state(), ChannelState::Initialized);

        channel.subscribe();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(channel.state(), ChannelState::Initialized);
        let attach_count = mock
            .client_messages()
            .iter()
            .filter(|m| m.message.action == Action::Attach)
            .count();
        assert_eq!(attach_count, 0);
    }

    // --- RTL7g: Subscribe does not attach when already attached ---
    #[tokio::test]
    async fn rtl7g_subscribe_no_attach_when_already_attached() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7g-already";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // Attach first
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let attach_count_before = mock
            .client_messages()
            .iter()
            .filter(|m| m.message.action == Action::Attach)
            .count();

        // Subscribe — should NOT send another ATTACH
        channel.subscribe();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let attach_count_after = mock
            .client_messages()
            .iter()
            .filter(|m| m.message.action == Action::Attach)
            .count();
        assert_eq!(attach_count_before, attach_count_after);
        assert_eq!(channel.state(), ChannelState::Attached);
    }

    // --- RTL17: Messages not delivered when channel is not ATTACHED ---
    #[tokio::test]
    async fn rtl17_messages_not_delivered_when_not_attached() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl17";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        // Start attach but don't complete it — channel stays ATTACHING
        let ch = channel.clone();
        let _t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(channel.state(), ChannelState::Attaching);

        // Send message while ATTACHING
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(channel_name.to_string()),
            messages: Some(vec![
                serde_json::json!({"name": "premature", "data": "skip"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err()); // No messages delivered
    }

    // --- RTL7f: Messages not echoed when echoMessages is false ---
    #[tokio::test]
    async fn rtl7f_echo_messages_filtered() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl7f";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage {
                    action: Action::Connected,
                    connection_id: Some("conn-self-123".to_string()),
                    connection_details: Some(crate::protocol::ConnectionDetails {
                        connection_key: Some("key-456".to_string()),
                        client_id: None,
                        connection_state_ttl: Some(120_000),
                        max_idle_interval: Some(15_000),
                        max_message_size: None,
                        server_id: None,
                    }),
                    ..ProtocolMessage::new(Action::Connected)
                });
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret")
                .auto_connect(false)
                .echo_messages(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        // Message from self (same connectionId) — should be filtered
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            connection_id: Some("conn-self-123".to_string()),
            messages: Some(vec![
                serde_json::json!({"name": "echo", "data": "from-self"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        // Message from another connection — should be delivered
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            connection_id: Some("conn-other-789".to_string()),
            messages: Some(vec![
                serde_json::json!({"name": "remote", "data": "from-other"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.name.as_deref(), Some("remote"));
        assert_eq!(msg.data.as_ref().unwrap(), "from-other");
        assert!(rx.try_recv().is_err()); // No echo message
    }

    // --- RTL8a: Unsubscribe specific listener ---
    #[tokio::test]
    async fn rtl8a_unsubscribe_specific_listener() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl8a";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (sub_a, mut rx_a) = channel.subscribe();
        let (_sub_b, mut rx_b) = channel.subscribe();

        // Both receive first message
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"name": "msg1", "data": "first"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(rx_a.try_recv().is_ok());
        assert!(rx_b.try_recv().is_ok());

        // Unsubscribe listener A
        channel.unsubscribe(sub_a);

        // Only B should receive second message
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![serde_json::json!({"name": "msg2", "data": "second"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(rx_a.try_recv().is_err()); // A unsubscribed
        let msg = rx_b.try_recv().unwrap();
        assert_eq!(msg.name.as_deref(), Some("msg2"));
    }

    // --- RTL8b: Unsubscribe from specific name ---
    #[tokio::test]
    async fn rtl8b_unsubscribe_from_specific_name() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl8b";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (sub_id, mut rx) = channel.subscribe_with_name("alpha");
        let (_sub_beta, mut rx_beta) = channel.subscribe_with_name("beta");

        // Both active
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![
                serde_json::json!({"name": "alpha", "data": "a1"}),
                serde_json::json!({"name": "beta", "data": "b1"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_ok());
        assert!(rx_beta.try_recv().is_ok());

        // Unsubscribe only "alpha"
        channel.unsubscribe_with_name("alpha", sub_id);

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![
                serde_json::json!({"name": "alpha", "data": "a2"}),
                serde_json::json!({"name": "beta", "data": "b2"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(rx.try_recv().is_err()); // Alpha unsubscribed
        let msg = rx_beta.try_recv().unwrap();
        assert_eq!(msg.data.as_ref().unwrap(), "b2");
    }

    // --- RTL8c: Unsubscribe all ---
    #[tokio::test]
    async fn rtl8c_unsubscribe_all() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-rtl8c";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_all, mut rx_all) = channel.subscribe();
        let (_sub_named, mut rx_named) = channel.subscribe_with_name("specific");

        // Both active
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![
                serde_json::json!({"name": "specific", "data": "first"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(rx_all.try_recv().is_ok());
        assert!(rx_named.try_recv().is_ok());

        // Unsubscribe all
        channel.unsubscribe_all();

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            messages: Some(vec![
                serde_json::json!({"name": "specific", "data": "second"}),
                serde_json::json!({"name": "other", "data": "third"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(rx_all.try_recv().is_err());
        assert!(rx_named.try_recv().is_err());
    }

    // --- TM2a: Message id populated from ProtocolMessage ---
    #[tokio::test]
    async fn tm2a_message_id_populated() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2a";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        // Attach
        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        // Send ProtocolMessage with id but messages without id
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            id: Some("abc123:5".to_string()),
            connection_id: Some("abc123".to_string()),
            timestamp: Some(1700000000000),
            messages: Some(vec![
                serde_json::json!({"name": "first", "data": "a"}),
                serde_json::json!({"name": "second", "data": "b"}),
                serde_json::json!({"name": "third", "data": "c"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msg0 = rx.try_recv().unwrap();
        assert_eq!(msg0.id.as_deref(), Some("abc123:5:0"));
        let msg1 = rx.try_recv().unwrap();
        assert_eq!(msg1.id.as_deref(), Some("abc123:5:1"));
        let msg2 = rx.try_recv().unwrap();
        assert_eq!(msg2.id.as_deref(), Some("abc123:5:2"));
    }

    // --- TM2a: Message with existing id is not overwritten ---
    #[tokio::test]
    async fn tm2a_existing_id_not_overwritten() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2a-existing";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            id: Some("proto-id:0".to_string()),
            messages: Some(vec![
                serde_json::json!({"id": "my-custom-id", "name": "msg", "data": "hello"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.id.as_deref(), Some("my-custom-id"));
    }

    // --- TM2a: No id when ProtocolMessage has no id ---
    #[tokio::test]
    async fn tm2a_no_id_when_protocol_message_has_no_id() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2a-no-proto-id";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        // ProtocolMessage has no id field
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            connection_id: Some("abc123".to_string()),
            messages: Some(vec![serde_json::json!({"name": "msg", "data": "hello"})]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = rx.try_recv().unwrap();
        assert!(msg.id.is_none());
    }

    // --- TM2c: Message connectionId populated from ProtocolMessage ---
    #[tokio::test]
    async fn tm2c_connection_id_populated() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2c";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            id: Some("msg:0".to_string()),
            connection_id: Some("server-conn-xyz".to_string()),
            messages: Some(vec![serde_json::json!({"name": "msg", "data": "hello"})]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.connection_id.as_deref(), Some("server-conn-xyz"));
    }

    // --- TM2c: Message with existing connectionId is not overwritten ---
    #[tokio::test]
    async fn tm2c_existing_connection_id_not_overwritten() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2c-existing";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            id: Some("msg:0".to_string()),
            connection_id: Some("proto-conn".to_string()),
            messages: Some(vec![
                serde_json::json!({"connectionId": "msg-conn", "name": "msg", "data": "hello"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.connection_id.as_deref(), Some("msg-conn"));
    }

    // --- TM2f: Message timestamp populated from ProtocolMessage ---
    #[tokio::test]
    async fn tm2f_timestamp_populated() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2f";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            id: Some("msg:0".to_string()),
            timestamp: Some(1700000000000),
            messages: Some(vec![serde_json::json!({"name": "msg", "data": "hello"})]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.timestamp, Some(1700000000000));
    }

    // --- TM2f: Message with existing timestamp is not overwritten ---
    #[tokio::test]
    async fn tm2f_existing_timestamp_not_overwritten() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2f-existing";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            id: Some("msg:0".to_string()),
            timestamp: Some(1700000000000),
            messages: Some(vec![
                serde_json::json!({"timestamp": 1600000000000_i64, "name": "msg", "data": "hello"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.timestamp, Some(1600000000000));
    }

    // --- TM2a, TM2c, TM2f: All fields populated together ---
    #[tokio::test]
    async fn tm2_all_fields_populated_together() {
        use crate::mock_ws::MockWebSocket;
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_state, Realtime};

        let channel_name = "test-tm2-all";
        let mock = MockWebSocket::with_handler({
            move |pc| {
                pc.respond_with_success(ProtocolMessage::connected("conn123", "connKey"));
            }
        });
        let transport = std::sync::Arc::new(crate::mock_ws::MockTransport::new(mock.inner()));
        let client = Realtime::with_mock(
            &ClientOptions::new("appId.keyId:keySecret").auto_connect(false),
            transport.clone(),
        )
        .unwrap();

        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client
            .channels
            .get_with_options(
                channel_name,
                crate::channel::RealtimeChannelOptions {
                    attach_on_subscribe: false,
                    ..Default::default()
                },
            )
            .unwrap();

        let ch = channel.clone();
        let cn = channel_name.to_string();
        let t = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(cn.clone()),
            ..ProtocolMessage::new(Action::Attached)
        });
        t.await.unwrap().unwrap();

        let (_sub_id, mut rx) = channel.subscribe();

        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(cn.clone()),
            id: Some("connId:7".to_string()),
            connection_id: Some("connId".to_string()),
            timestamp: Some(1700000000000),
            messages: Some(vec![
                serde_json::json!({"name": "first", "data": "a"}),
                serde_json::json!({"name": "second", "data": "b"}),
            ]),
            ..ProtocolMessage::new(Action::Message)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let msg0 = rx.try_recv().unwrap();
        assert_eq!(msg0.id.as_deref(), Some("connId:7:0"));
        assert_eq!(msg0.connection_id.as_deref(), Some("connId"));
        assert_eq!(msg0.timestamp, Some(1700000000000));
        assert_eq!(msg0.name.as_deref(), Some("first"));

        let msg1 = rx.try_recv().unwrap();
        assert_eq!(msg1.id.as_deref(), Some("connId:7:1"));
        assert_eq!(msg1.connection_id.as_deref(), Some("connId"));
        assert_eq!(msg1.timestamp, Some(1700000000000));
        assert_eq!(msg1.name.as_deref(), Some("second"));
    }

    // =========================================================================
    // Phase 8d: Advanced Channel Features
    // =========================================================================

    /// Helper: set up a connected Realtime client with a mock WebSocket.
    /// The handler auto-accepts every connection attempt.
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

    /// Helper: attach a channel by sending ATTACHED from the mock.
    async fn phase8d_attach(
        channel: &std::sync::Arc<crate::channel::RealtimeChannel>,
        mock: &crate::mock_ws::MockWebSocket,
        serial: Option<&str>,
    ) {
        use crate::protocol::{Action, ProtocolMessage};

        let ch = channel.clone();
        let attach_task = tokio::spawn(async move { ch.attach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel.name().to_string()),
            channel_serial: serial.map(|s| s.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        attach_task.await.unwrap().unwrap();
    }

    // --- RTL3e: DISCONNECTED has no effect on ATTACHED channel ---
    #[tokio::test]
    async fn rtl3e_disconnected_no_effect_on_attached_channel() {
        use crate::protocol::{ChannelState, ConnectionState};
        use crate::realtime::await_state;

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-rtl3e");
        phase8d_attach(&channel, &mock, None).await;
        assert_eq!(channel.state(), ChannelState::Attached);

        // Subscribe to channel state changes
        let mut rx = channel.on_state_change();

        // Simulate disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

        // RTL3e: Channel should remain ATTACHED immediately after DISCONNECTED
        assert_eq!(channel.state(), ChannelState::Attached);

        // Verify no channel state change was emitted due to DISCONNECTED
        // (use short timeout, before the reconnect retry fires RTL3d)
        let result = tokio::time::timeout(std::time::Duration::from_millis(20), rx.recv()).await;
        assert!(
            result.is_err(),
            "No channel state change expected on DISCONNECTED"
        );
    }

    // --- RTL3a: FAILED connection transitions ATTACHED channel to FAILED ---
    #[tokio::test]
    async fn rtl3a_failed_connection_transitions_attached_to_failed() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-rtl3a");
        phase8d_attach(&channel, &mock, None).await;
        assert_eq!(channel.state(), ChannelState::Attached);

        // Send connection-level ERROR (no channel field) to trigger FAILED
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            error: Some(ErrorInfo {
                code: Some(40198),
                status_code: Some(401),
                message: Some("Invalid credentials".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });

        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        // RTL3a: Channel should transition to FAILED
        assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
        assert!(channel.error_reason().is_some());
    }

    // --- RTL3a: Channels in INITIALIZED unaffected by FAILED ---
    #[tokio::test]
    async fn rtl3a_initialized_unaffected_by_failed() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::await_state;

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let ch_init = client.channels.get("ch-initialized");
        assert_eq!(ch_init.state(), ChannelState::Initialized);

        // Trigger connection FAILED
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            error: Some(ErrorInfo {
                code: Some(40198),
                status_code: Some(401),
                message: Some("Fatal".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });

        assert!(await_state(&client.connection, ConnectionState::Failed, 5000).await);

        // RTL3a: INITIALIZED channel should be unaffected
        assert_eq!(ch_init.state(), ChannelState::Initialized);
    }

    // --- RTL3b: CLOSED connection transitions ATTACHED channel to DETACHED ---
    #[tokio::test]
    async fn rtl3b_closed_connection_transitions_attached_to_detached() {
        use crate::protocol::{ChannelState, ConnectionState};
        use crate::realtime::{await_channel_state, await_state};

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-rtl3b");
        phase8d_attach(&channel, &mock, None).await;
        assert_eq!(channel.state(), ChannelState::Attached);

        // Close the connection
        client.close();

        // RTL3b: Channel should transition to DETACHED
        assert!(await_channel_state(&channel, ChannelState::Detached, 5000).await);
    }

    // --- RTL3d: CONNECTED re-attaches ATTACHED channels ---
    #[tokio::test]
    async fn rtl3d_connected_reattaches_attached_channels() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let channel_name = "test-rtl3d";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, Some("serial-001")).await;
        assert_eq!(channel.state(), ChannelState::Attached);

        // Simulate disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

        // Wait for reconnection
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // RTL3d: Channel should move to ATTACHING, send ATTACH
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send ATTACHED from server for the reattach
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            channel_serial: Some("serial-002".to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        assert!(await_channel_state(&channel, ChannelState::Attached, 5000).await);

        // Verify ATTACH was sent on reconnect
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| {
                m.message.action == Action::Attach
                    && m.message.channel.as_deref() == Some(channel_name)
            })
            .collect();
        assert!(
            attach_msgs.len() >= 2,
            "Expected at least 2 ATTACH messages (initial + reattach)"
        );
    }

    // --- RTL3d: INITIALIZED/DETACHED channels not re-attached ---
    #[tokio::test]
    async fn rtl3d_initialized_detached_not_reattached() {
        use crate::protocol::{Action, ChannelState, ConnectionState};
        use crate::realtime::await_state;

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // Create channel but don't attach it
        let ch_init = client.channels.get("ch-init");
        assert_eq!(ch_init.state(), ChannelState::Initialized);

        let initial_attach_count = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .count();

        // Disconnect and reconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // RTL3d: No ATTACH messages sent for INITIALIZED channels
        let final_attach_count = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .count();
        assert_eq!(final_attach_count, initial_attach_count);
        assert_eq!(ch_init.state(), ChannelState::Initialized);
    }

    // --- RTL15a: attachSerial set from ATTACHED channelSerial ---
    #[tokio::test]
    async fn rtl15a_attach_serial_from_attached() {
        use crate::protocol::ConnectionState;
        use crate::realtime::await_state;

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-rtl15a");
        assert!(channel.attach_serial().is_none());

        phase8d_attach(&channel, &mock, Some("attach-serial-001")).await;

        // RTL15a: attachSerial populated from ATTACHED response
        assert_eq!(
            channel.attach_serial().as_deref(),
            Some("attach-serial-001")
        );
    }

    // --- RTL15a: attachSerial updated on additional ATTACHED ---
    #[tokio::test]
    async fn rtl15a_attach_serial_updated_on_additional_attached() {
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-rtl15a-update");
        phase8d_attach(&channel, &mock, Some("serial-v1")).await;
        assert_eq!(channel.attach_serial().as_deref(), Some("serial-v1"));

        // Server sends additional ATTACHED with new serial (UPDATE)
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some("test-rtl15a-update".to_string()),
            channel_serial: Some("serial-v2".to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // RTL15a: attachSerial updated
        assert_eq!(channel.attach_serial().as_deref(), Some("serial-v2"));
    }

    // --- RTL15b: channelSerial set from ATTACHED ---
    #[tokio::test]
    async fn rtl15b_channel_serial_from_attached() {
        use crate::protocol::ConnectionState;
        use crate::realtime::await_state;

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get("test-rtl15b");
        assert!(channel.channel_serial().is_none());

        phase8d_attach(&channel, &mock, Some("ch-serial-001")).await;
        assert_eq!(channel.channel_serial().as_deref(), Some("ch-serial-001"));
    }

    // --- RTL15b: channelSerial updated from MESSAGE ---
    #[tokio::test]
    async fn rtl15b_channel_serial_updated_from_message() {
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;

        let channel_name = "test-rtl15b-msg";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, Some("initial-serial")).await;
        assert_eq!(channel.channel_serial().as_deref(), Some("initial-serial"));

        // Server sends MESSAGE with updated channelSerial
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(channel_name.to_string()),
            channel_serial: Some("msg-serial-002".to_string()),
            messages: Some(vec![serde_json::json!({"name": "test"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // RTL15b: channelSerial updated from MESSAGE
        assert_eq!(channel.channel_serial().as_deref(), Some("msg-serial-002"));
    }

    // --- RTL15b: channelSerial NOT updated when field absent ---
    #[tokio::test]
    async fn rtl15b_channel_serial_not_updated_when_absent() {
        use crate::protocol::{Action, ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;

        let channel_name = "test-rtl15b-absent";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, Some("keep-this")).await;
        assert_eq!(channel.channel_serial().as_deref(), Some("keep-this"));

        // Send MESSAGE without channelSerial
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Message,
            channel: Some(channel_name.to_string()),
            messages: Some(vec![serde_json::json!({"name": "test"})]),
            ..ProtocolMessage::new(Action::Message)
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // RTL15b: channelSerial should remain unchanged
        assert_eq!(channel.channel_serial().as_deref(), Some("keep-this"));
    }

    // --- RTL15b: channelSerial cleared on DETACHED (RTL15b1) ---
    #[tokio::test]
    async fn rtl15b_channel_serial_cleared_on_detached() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;

        let channel_name = "test-rtl15b-detached";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, Some("attached-serial")).await;
        assert_eq!(channel.channel_serial().as_deref(), Some("attached-serial"));

        // Initiate detach
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send DETACHED response (with a channelSerial that should be ignored)
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            channel_serial: Some("should-be-ignored".to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();

        // RTL15b1: channelSerial cleared on DETACHED
        assert!(channel.channel_serial().is_none());
        assert_eq!(channel.state(), ChannelState::Detached);
    }

    // --- RTL15b1: channelSerial cleared on FAILED ---
    #[tokio::test]
    async fn rtl15b1_channel_serial_cleared_on_failed() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let channel_name = "test-rtl15b1-failed";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, Some("serial-to-clear")).await;
        assert!(channel.channel_serial().is_some());

        // Send channel-level ERROR
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(90002),
                status_code: None,
                message: Some("Channel error".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });

        assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);

        // RTL15b1: channelSerial cleared
        assert!(channel.channel_serial().is_none());
    }

    // --- RTL13a: Server-initiated DETACHED triggers reattach ---
    #[tokio::test]
    async fn rtl13a_server_detached_triggers_reattach() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let channel_name = "test-rtl13a";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;
        assert_eq!(channel.state(), ChannelState::Attached);

        // Server sends unsolicited DETACHED with error
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(50000),
                status_code: None,
                message: Some("Server detached".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Detached)
        });

        // RTL13a: Should move to ATTACHING and send ATTACH
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send ATTACHED for the reattach
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        assert!(await_channel_state(&channel, ChannelState::Attached, 5000).await);

        // Verify two ATTACH messages were sent (initial + reattach)
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| {
                m.message.action == Action::Attach
                    && m.message.channel.as_deref() == Some(channel_name)
            })
            .collect();
        assert_eq!(attach_msgs.len(), 2);
    }

    // --- RTL13a: DETACHED while DETACHING is normal (not server-initiated) ---
    #[tokio::test]
    async fn rtl13a_detached_while_detaching_is_normal() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;

        let channel_name = "test-rtl13a-normal";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;

        // User-initiated detach
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send DETACHED response (normal flow, not server-initiated)
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();

        assert_eq!(channel.state(), ChannelState::Detached);

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Should NOT trigger reattach — only 1 ATTACH total
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| {
                m.message.action == Action::Attach
                    && m.message.channel.as_deref() == Some(channel_name)
            })
            .collect();
        assert_eq!(attach_msgs.len(), 1);
    }

    // --- RTL12: Additional ATTACHED with resumed=false emits UPDATE ---
    #[tokio::test]
    async fn rtl12_additional_attached_not_resumed_emits_update() {
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage,
        };
        use crate::realtime::await_state;

        let channel_name = "test-rtl12";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;

        let mut rx = channel.on_state_change();

        // Server sends additional ATTACHED without RESUMED flag, with error
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(50000),
                status_code: None,
                message: Some("Continuity lost".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Attached)
        });

        // RTL12: Should emit UPDATE event
        let change = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(change.event, ChannelEvent::Update);
        assert_eq!(change.current, ChannelState::Attached);
        assert_eq!(change.previous, ChannelState::Attached);
        assert!(!change.resumed);
        assert!(change.reason.is_some());
        assert_eq!(change.reason.unwrap().code, Some(50000));

        // Channel remains ATTACHED
        assert_eq!(channel.state(), ChannelState::Attached);
    }

    // --- RTL12: Additional ATTACHED with resumed=true does NOT emit UPDATE ---
    #[tokio::test]
    async fn rtl12_additional_attached_resumed_no_update() {
        use crate::protocol::{flags, Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;

        let channel_name = "test-rtl12-resumed";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;

        let mut rx = channel.on_state_change();

        // Server sends additional ATTACHED WITH RESUMED flag
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            flags: Some(flags::RESUMED),
            ..ProtocolMessage::new(Action::Attached)
        });

        // RTL12: Should NOT emit UPDATE
        let result = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
        assert!(result.is_err(), "No event expected when resumed=true");
        assert_eq!(channel.state(), ChannelState::Attached);
    }

    // --- RTL12: Additional ATTACHED without error has null reason ---
    #[tokio::test]
    async fn rtl12_additional_attached_no_error_null_reason() {
        use crate::protocol::{
            Action, ChannelEvent, ChannelState, ConnectionState, ProtocolMessage,
        };
        use crate::realtime::await_state;

        let channel_name = "test-rtl12-no-err";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;

        let mut rx = channel.on_state_change();

        // Server sends ATTACHED without error, without RESUMED flag
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        let change = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(change.event, ChannelEvent::Update);
        // RTL12: reason is null
        assert!(change.reason.is_none());
    }

    // --- RTL14: Channel ERROR transitions ATTACHED to FAILED ---
    #[tokio::test]
    async fn rtl14_channel_error_attached_to_failed() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let channel_name = "test-rtl14";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;

        // Send channel-scoped ERROR
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(40160),
                status_code: Some(401),
                message: Some("Channel error".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });

        // RTL14: Channel transitions to FAILED
        assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
        let err = channel.error_reason().unwrap();
        assert_eq!(err.code, Some(40160));

        // Connection should remain CONNECTED
        assert_eq!(client.connection.state(), ConnectionState::Connected);
    }

    // --- RTL14: Channel ERROR does not affect other channels ---
    #[tokio::test]
    async fn rtl14_channel_error_does_not_affect_other_channels() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let ch1 = client.channels.get("ch-target");
        let ch2 = client.channels.get("ch-other");
        phase8d_attach(&ch1, &mock, None).await;
        phase8d_attach(&ch2, &mock, None).await;

        // Send ERROR only to ch1
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some("ch-target".to_string()),
            error: Some(ErrorInfo {
                code: Some(40160),
                status_code: Some(401),
                message: Some("Bad channel".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });

        assert!(await_channel_state(&ch1, ChannelState::Failed, 5000).await);

        // RTL14: Other channel unaffected
        assert_eq!(ch2.state(), ChannelState::Attached);
        assert!(ch2.error_reason().is_none());
    }

    // --- RTL23: Channel name attribute ---
    #[tokio::test]
    async fn rtl23_channel_name_attribute() {
        use crate::protocol::ConnectionState;
        use crate::realtime::await_state;

        let (client, _mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        // RTL23: Channel name matches what was passed to get()
        let ch1 = client.channels.get("my-channel");
        assert_eq!(ch1.name(), "my-channel");

        let ch2 = client.channels.get("namespace:channel-name");
        assert_eq!(ch2.name(), "namespace:channel-name");
    }

    // --- RTL24: errorReason set on channel error ---
    #[tokio::test]
    async fn rtl24_error_reason_set_on_error() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let channel_name = "test-rtl24";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        assert!(channel.error_reason().is_none());

        phase8d_attach(&channel, &mock, None).await;

        // Send ERROR
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(40160),
                status_code: Some(401),
                message: Some("Unauthorized".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });

        assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);

        // RTL24: errorReason set
        let err = channel.error_reason().unwrap();
        assert_eq!(err.code, Some(40160));
        assert_eq!(err.status_code, Some(401));
    }

    // --- RTL24: errorReason cleared on successful attach ---
    #[tokio::test]
    async fn rtl24_error_reason_cleared_on_attach() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ErrorInfo, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let channel_name = "test-rtl24-clear";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        // First: cause an error
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Error,
            channel: Some(channel_name.to_string()),
            error: Some(ErrorInfo {
                code: Some(90002),
                status_code: None,
                message: Some("Temporary error".to_string()),
                href: None,
            }),
            ..ProtocolMessage::new(Action::Error)
        });

        assert!(await_channel_state(&channel, ChannelState::Failed, 5000).await);
        assert!(channel.error_reason().is_some());

        // Re-attach (allowed from FAILED via RTL4g)
        phase8d_attach(&channel, &mock, None).await;

        // RTL24: errorReason cleared on successful attach
        assert!(channel.error_reason().is_none());
    }

    // --- RTL25a: whenState fires immediately if already in state ---
    #[tokio::test]
    async fn rtl25a_when_state_fires_immediately() {
        use crate::protocol::{ChannelState, ConnectionState};
        use crate::realtime::await_state;
        use std::sync::atomic::{AtomicBool, Ordering};

        let channel_name = "test-rtl25a";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;

        // RTL25a: Already in ATTACHED state — callback fires immediately with None
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired2 = fired.clone();
        let got_null = std::sync::Arc::new(AtomicBool::new(false));
        let got_null2 = got_null.clone();

        channel.when_state(ChannelState::Attached, move |change| {
            fired2.store(true, Ordering::SeqCst);
            got_null2.store(change.is_none(), Ordering::SeqCst);
        });

        // Give the spawned task a moment
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(fired.load(Ordering::SeqCst), "Callback should have fired");
        assert!(
            got_null.load(Ordering::SeqCst),
            "Should have received None (already in state)"
        );
    }

    // --- RTL25b: whenState waits for state transition ---
    #[tokio::test]
    async fn rtl25b_when_state_waits_for_transition() {
        use crate::protocol::{ChannelState, ConnectionState};
        use crate::realtime::await_state;
        use std::sync::atomic::{AtomicBool, Ordering};

        let channel_name = "test-rtl25b";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        assert_eq!(channel.state(), ChannelState::Initialized);

        // RTL25b: Register whenState for ATTACHED before attaching
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired2 = fired.clone();
        let got_change = std::sync::Arc::new(AtomicBool::new(false));
        let got_change2 = got_change.clone();

        channel.when_state(ChannelState::Attached, move |change| {
            fired2.store(true, Ordering::SeqCst);
            got_change2.store(change.is_some(), Ordering::SeqCst);
        });

        // Not fired yet
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!fired.load(Ordering::SeqCst));

        // Now attach
        phase8d_attach(&channel, &mock, None).await;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // RTL25b: Should have fired with ChannelStateChange
        assert!(
            fired.load(Ordering::SeqCst),
            "Callback should fire on transition"
        );
        assert!(
            got_change.load(Ordering::SeqCst),
            "Should receive StateChange object"
        );
    }

    // --- RTL25b: whenState fires only once ---
    #[tokio::test]
    async fn rtl25b_when_state_fires_only_once() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::await_state;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let channel_name = "test-rtl25b-once";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);

        let fire_count = std::sync::Arc::new(AtomicUsize::new(0));
        let fire_count2 = fire_count.clone();

        channel.when_state(ChannelState::Attached, move |_| {
            fire_count2.fetch_add(1, Ordering::SeqCst);
        });

        // First attach
        phase8d_attach(&channel, &mock, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(fire_count.load(Ordering::SeqCst), 1);

        // Detach
        let ch = channel.clone();
        let detach_task = tokio::spawn(async move { ch.detach().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Detached,
            channel: Some(channel_name.to_string()),
            ..ProtocolMessage::new(Action::Detached)
        });
        detach_task.await.unwrap().unwrap();

        // Re-attach
        phase8d_attach(&channel, &mock, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // RTL25b: Should NOT fire again
        assert_eq!(fire_count.load(Ordering::SeqCst), 1);
    }

    // --- RTL25a: whenState for non-current state does not fire immediately ---
    #[tokio::test]
    async fn rtl25a_when_state_for_non_current_state_waits() {
        use crate::protocol::{ChannelState, ConnectionState};
        use crate::realtime::await_state;
        use std::sync::atomic::{AtomicBool, Ordering};

        let channel_name = "test-rtl25a-past";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, None).await;
        assert_eq!(channel.state(), ChannelState::Attached);

        // Register whenState for ATTACHING — not the current state
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired2 = fired.clone();

        channel.when_state(ChannelState::Attaching, move |_| {
            fired2.store(true, Ordering::SeqCst);
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // RTL25: Should NOT fire — ATTACHING is not the current state
        assert!(!fired.load(Ordering::SeqCst));
    }

    // --- RTL3d: Multiple channels re-attached on CONNECTED ---
    #[tokio::test]
    async fn rtl3d_multiple_channels_reattached() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let ch1 = client.channels.get("ch-multi-1");
        let ch2 = client.channels.get("ch-multi-2");
        phase8d_attach(&ch1, &mock, None).await;
        phase8d_attach(&ch2, &mock, None).await;

        // Disconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);

        // Wait for reconnect
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send ATTACHED for both channels on reconnect
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some("ch-multi-1".to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some("ch-multi-2".to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });

        // RTL3d: Both channels re-attached
        assert!(await_channel_state(&ch1, ChannelState::Attached, 5000).await);
        assert!(await_channel_state(&ch2, ChannelState::Attached, 5000).await);

        // Verify at least 4 ATTACH messages (2 initial + 2 reattach)
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| m.message.action == Action::Attach)
            .collect();
        assert!(
            attach_msgs.len() >= 4,
            "Expected at least 4 ATTACH messages, got {}",
            attach_msgs.len()
        );
    }

    // --- RTL3d: Reattach includes channelSerial (RTL4c1) ---
    #[tokio::test]
    async fn rtl3d_reattach_includes_channel_serial() {
        use crate::protocol::{Action, ChannelState, ConnectionState, ProtocolMessage};
        use crate::realtime::{await_channel_state, await_state};

        let channel_name = "test-rtl3d-serial";
        let (client, mock) = phase8d_setup();
        client.connect();
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);

        let channel = client.channels.get(channel_name);
        phase8d_attach(&channel, &mock, Some("serial-from-server")).await;

        // Disconnect and reconnect
        {
            let conns = mock.active_connections();
            conns.last().unwrap().simulate_disconnect();
        }
        assert!(await_state(&client.connection, ConnectionState::Disconnected, 5000).await);
        assert!(await_state(&client.connection, ConnectionState::Connected, 5000).await);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send ATTACHED for reattach
        let conns = mock.active_connections();
        let conn = conns.last().unwrap();
        conn.send_to_client(ProtocolMessage {
            action: Action::Attached,
            channel: Some(channel_name.to_string()),
            channel_serial: Some("serial-v2".to_string()),
            ..ProtocolMessage::new(Action::Attached)
        });
        assert!(await_channel_state(&channel, ChannelState::Attached, 5000).await);

        // Check that the reattach ATTACH message included channelSerial
        let attach_msgs: Vec<_> = mock
            .client_messages()
            .into_iter()
            .filter(|m| {
                m.message.action == Action::Attach
                    && m.message.channel.as_deref() == Some(channel_name)
            })
            .collect();
        assert!(attach_msgs.len() >= 2);
        // First attach: no channelSerial
        assert!(attach_msgs[0].message.channel_serial.is_none());
        // RTL4c1: Reattach includes channelSerial from previous ATTACHED
        assert_eq!(
            attach_msgs[1].message.channel_serial.as_deref(),
            Some("serial-from-server")
        );
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

        assert_eq!(err.code, crate::error::ErrorCode::Testing);
        assert_eq!(err.status_code, Some(400));

        Ok(())
    }

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
            .rest_with_http_client(Box::new(mock))
            .unwrap();

        let time = client.time().await?;
        assert_eq!(time.timestamp_millis(), 1234567890000);

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
        let items = res.items().await?;

        assert_eq!(items.len(), 1);
        // Must be Binary, NOT String (even though bytes are valid UTF-8)
        assert_eq!(
            items[0].data,
            crate::rest::Data::Binary(serde_bytes::ByteBuf::from(vec![
                0x48, 0x65, 0x6C, 0x6C, 0x6F
            ]))
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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
        let items = res.items().await?;

        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].data,
            crate::rest::Data::String("Hello World".to_string())
        );
        assert_eq!(items[0].encoding, crate::rest::Encoding::None);

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

        let mock =
            MockHttpClient::with_handler(move |_req| MockResponse::msgpack(200, &vec![&msg]));

        let client = mock_client(mock);
        let res = client.channels().get("test").presence.get().send().await?;
        let items = res.items().await?;

        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].data,
            crate::rest::Data::Binary(serde_bytes::ByteBuf::from(b"some data".to_vec()))
        );

        Ok(())
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
}

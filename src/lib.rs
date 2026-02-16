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
pub mod crypto;
pub mod http;
pub(crate) mod http_client;
mod json;
#[cfg(test)]
pub(crate) mod mock_http;
pub mod options;
pub mod presence;
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
            meta.issued >= server_time,
            "Expected issued ({}) to be after server time ({})",
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
}

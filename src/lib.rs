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
pub mod base64;
pub mod history;
pub mod http;
pub mod json;
pub mod options;
pub mod presence;
pub mod rest;
pub mod stats;

pub use error::ErrorInfo;
pub use options::ClientOptions;
pub use rest::Rest;

/// A `Result` alias where the `Err` variant contains an `ably::ErrorInfo`.
pub type Result<T> = std::result::Result<T, ErrorInfo>;

#[cfg(test)]
mod tests {
    use super::http::Method;
    use super::options::ClientOptions;
    use super::rest::{Data, Rest};
    use super::*;
    use chrono::prelude::*;
    use chrono::Duration;
    use futures::TryStreamExt;
    use reqwest::Url;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::convert::TryFrom;
    use std::fs;
    use std::iter::FromIterator;

    #[test]
    fn rest_client_from_sets_key_credential_with_string_with_colon() {
        let s = "appID.keyID:keySecret";
        let client = Rest::from(s);
        assert!(client.auth.credential.is_key());
    }

    #[test]
    fn rest_client_from_sets_token_credential_with_string_without_colon() {
        let s = "appID.tokenID";
        let client = Rest::from(s);
        assert!(client.auth.credential.is_token());
    }

    #[test]
    fn client_options_errors_with_no_key_or_token() {
        let err = ClientOptions::new()
            .client()
            .expect_err("Expected 40106 error");
        assert_eq!(err.code, 40106);
    }

    fn test_client_options() -> ClientOptions {
        ClientOptions::from("aaaaaa.bbbbbb:cccccc").environment("sandbox")
    }

    fn test_client() -> Rest {
        test_client_options().client().unwrap()
    }

    /// A test app in the Ably Sandbox environment.
    #[derive(Deserialize)]
    struct TestApp {
        keys: Vec<auth::Key>,
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
            ClientOptions::new()
                .key(self.key())
                .environment("sandbox")
                .client()
                .unwrap()
        }

        fn key(&self) -> auth::Key {
            self.keys[0].clone()
        }

        async fn token_request(&self, params: auth::TokenParams) -> Result<auth::TokenResponse> {
            let req = params.sign(&self.key())?;

            Ok(auth::TokenResponse::Request(req))
        }
    }

    impl auth::TokenProvider for TestApp {
        fn provide_token<'a>(&'a self, params: auth::TokenParams) -> auth::TokenProviderFuture<'a> {
            Box::pin(self.token_request(params))
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
            .paginated_request(Method::GET, "/time")
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
            .paginated_request(Method::GET, "/time")
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

        assert_eq!(err.code, 40400);
        assert_eq!(err.status_code, Some(404));

        Ok(())
    }

    #[tokio::test]
    async fn custom_request_with_bad_rest_host_returns_network_error() -> Result<()> {
        let client = ClientOptions::from("aaaaaa.bbbbbb:cccccc")
            .rest_host("i-dont-exist.ably.com")
            .client()?;

        let err = client
            .request(Method::GET, "/time")
            .send()
            .await
            .expect_err("Expected network error");

        assert_eq!(err.code, 40000);

        Ok(())
    }

    #[tokio::test]
    async fn stats_minute_forwards() -> Result<()> {
        // Create a test app and client.
        let app = TestApp::create().await?;
        let client = app.client();

        // Create some stats for 3rd Feb last year.
        let last_year = (Utc::today() - Duration::days(365)).year();
        let fixtures = json!([
            {
                "intervalId": format!("{}-02-03:15:03", last_year),
                "inbound": { "realtime": { "messages": { "count": 50, "data": 5000 } } },
                "outbound": { "realtime": { "messages": { "count": 20, "data": 2000 } } }
            },
            {
                "intervalId": format!("{}-02-03:15:04", last_year),
                "inbound": { "realtime": { "messages": { "count": 60, "data": 6000 } } },
                "outbound": { "realtime": { "messages": { "count": 10, "data": 1000 } } }
            },
            {
                "intervalId": format!("{}-02-03:15:05", last_year),
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
            .start(format!("{}-02-03:15:03", last_year).as_ref())
            .end(format!("{}-02-03:15:05", last_year).as_ref())
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
    fn auth_create_token_request_no_options() -> Result<()> {
        let client = test_client();

        let req = client.auth.create_token_request().sign()?;

        assert!(
            req.mac.unwrap().len() > 0,
            "expected tokenRequest.mac to be set"
        );
        assert!(req.nonce.len() > 0, "expected tokenRequest.nonce to be set");
        assert!(
            req.ttl.is_none(),
            "expected tokenRequest.ttl to not be set by default"
        );
        assert!(
            req.capability.is_none(),
            "expected tokenRequest.capability to not be set by default"
        );
        assert!(
            req.client_id.is_none(),
            "expected tokenRequest.client_id to not be set by default"
        );
        assert_eq!(req.key_name, client.auth.credential.key().unwrap().name);

        Ok(())
    }

    #[test]
    fn auth_create_token_request_with_capability() -> Result<()> {
        let client = test_client();

        let capability = r#"{"*":["*"]}"#;

        let req = client
            .auth
            .create_token_request()
            .capability(capability)
            .sign()?;

        assert_eq!(req.capability, Some(capability.to_string()));

        Ok(())
    }

    #[test]
    fn auth_create_token_request_with_client_id() -> Result<()> {
        let client = test_client();

        let client_id = "test@ably.com";

        let req = client
            .auth
            .create_token_request()
            .client_id(client_id)
            .sign()?;

        assert_eq!(req.client_id, Some(client_id.to_string()));

        Ok(())
    }

    #[test]
    fn auth_create_token_request_with_ttl() -> Result<()> {
        let client = test_client();

        let ttl = 60000;

        let req = client.auth.create_token_request().ttl(ttl).sign()?;

        assert_eq!(req.ttl, Some(ttl));

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
        let token = client.auth.request_token().send().await?;

        // Check the token details.
        assert!(token.token.len() > 0, "Expected token to be set");
        let issued = token.issued.expect("Expected issued to be set");
        let expires = token.expires.expect("Expected expires to be set");
        assert!(
            issued >= server_time,
            "Expected issued ({}) to be after server time ({})",
            issued,
            server_time
        );
        assert!(
            expires > issued,
            "Expected expires ({}) to be after issued ({})",
            expires,
            issued
        );
        let capability = token.capability.unwrap();
        assert_eq!(
            capability, r#"{"*":["*"]}"#,
            r#"Expected default capability '{{"*":["*"]}}', got {}"#,
            capability
        );
        assert_eq!(
            token.client_id,
            None,
            "Expected client_id to be null, got {}",
            token.client_id.as_ref().unwrap()
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

        // Request a token from the authUrl.
        let token = client
            .auth
            .request_token()
            .auth_url(auth_url)
            .send()
            .await?;

        // Check the token details.
        assert!(token.token.len() > 0, "Expected token to be set");

        Ok(())
    }

    #[tokio::test]
    async fn auth_request_token_with_provider() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Request a token with a custom provider.
        let token = client.auth.request_token().provider(app).send().await?;

        // Check the token details.
        assert!(token.token.len() > 0, "Expected token to be set");

        Ok(())
    }

    #[tokio::test]
    async fn channel_publish_string() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Publish a message with string data.
        let channel = client.channels.get("test_channel_publish_string");
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
        let channel = client.channels.get("test_channel_publish_json_object");
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
        let channel = client.channels.get("test_channel_publish_binary");
        let data = vec![0x1, 0x2, 0x3, 0x4];
        channel.publish().name("name").binary(data).send().await?;

        // Retrieve the message from history.
        let res = channel.history().send().await?;
        let mut history = res.items().await?;
        let message = history.pop().expect("Expected a history message");
        assert_eq!(message.data, Data::Binary(vec![0x1, 0x2, 0x3, 0x4]));

        Ok(())
    }

    #[tokio::test]
    async fn channel_presence_get() -> Result<()> {
        // Create a test app.
        let app = TestApp::create().await?;
        let client = app.client();

        // Retrieve the presence set
        let channel = client.channels.get("persisted:presence_fixtures");
        let res = channel.presence.get().send().await?;
        let presence = res.items().await?;
        assert_eq!(presence.len(), 3);
        assert_eq!(
            presence[0].data,
            Data::Binary("some presence data".as_bytes().into())
        );
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
        let channel = client.channels.get("persisted:presence_fixtures");
        let res = channel.presence.history().send().await?;
        let presence = res.items().await?;
        assert_eq!(presence.len(), 3);
        assert_eq!(
            presence[0].data,
            Data::Binary("some presence data".as_bytes().into())
        );
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
        let channel = client.channels.get("persisted:history_count");
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
        let channel = client.channels.get("persisted:history_paginate_backwards");
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

    #[derive(Deserialize)]
    struct CryptoData {
        key:   String,
        items: Vec<CryptoFixture>,
    }

    #[derive(Deserialize)]
    struct CryptoFixture {
        encoded:   json::Value,
        encrypted: json::Value,
    }

    #[tokio::test]
    async fn decrypt_message_128() -> Result<()> {
        let file = fs::File::open("submodules/ably-common/test-resources/crypto-data-128.json")
            .expect("Expected crypto-data-128.json to open");
        let data: CryptoData =
            serde_json::from_reader(file).expect("Expected JSON data in crypto-data-128.json");
        let opts = rest::ChannelOptions::from(rest::CipherParams {
            key: rest::CipherKey::try_from(data.key).expect("Expected base64 encoded cipher key"),
        });
        for item in data.items.iter() {
            let msg = rest::Message::from_encoded(item.encrypted.clone(), Some(&opts))?;
            assert_eq!(msg.encoding, None);
            let expected = rest::Message::from_encoded(item.encoded.clone(), None)?;
            assert_eq!(msg.data, expected.data);
        }
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_message_256() -> Result<()> {
        let file = fs::File::open("submodules/ably-common/test-resources/crypto-data-256.json")
            .expect("Expected crypto-data-256.json to open");
        let data: CryptoData =
            serde_json::from_reader(file).expect("Expected JSON data in crypto-data-256.json");
        let opts = rest::ChannelOptions::from(rest::CipherParams {
            key: rest::CipherKey::try_from(data.key).expect("Expected base64 encoded cipher key"),
        });
        for item in data.items.iter() {
            let msg = rest::Message::from_encoded(item.encrypted.clone(), Some(&opts))?;
            assert_eq!(msg.encoding, None);
            let expected = rest::Message::from_encoded(item.encoded.clone(), None)?;
            assert_eq!(msg.data, expected.data);
        }
        Ok(())
    }

    #[tokio::test]
    async fn client_fallback() -> Result<()> {
        // IANA reserved; requests to it will hang forever
        let unroutable_host = "10.255.255.1";
        let client = ClientOptions::from("aaaaaa.bbbbbb:cccccc")
            .rest_host(unroutable_host)
            .fallback_hosts(vec!["sandbox-a-fallback.ably-realtime.com".to_string()])
            .http_request_timeout(std::time::Duration::from_secs(3))
            .client()
            .unwrap();

        client.time().await.expect("Expected fallback response");

        Ok(())
    }
}

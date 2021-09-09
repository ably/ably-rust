//! A Rust client for the [Ably] REST and Realtime APIs.
//!
//! # Example
//!
//! TODO
//!
//! [Ably]: https://ably.com

#[macro_use]
pub mod error;
pub mod stats;

use crate::error::*;
use chrono::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// A `Result` alias where the `Err` variant contains an `ably::ErrorInfo`.
pub type Result<T> = std::result::Result<T, ErrorInfo>;

/// A client for the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Clone, Debug)]
pub struct RestClient {
    pub options: ClientOptions,
    client:      reqwest::Client,
    url:         reqwest::Url,
}

impl RestClient {
    /// Start building a GET request to /stats.
    ///
    /// Returns a StatsBuilder which is used to set parameters before sending
    /// the stats request.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// use ably::stats::Stats;
    ///
    /// let client = ably::RestClient::from("<api_key>");
    ///
    /// let res = client
    ///     .stats()
    ///     .start("2021-09-09:15:00")
    ///     .end("2021-09-09:15:05")
    ///     .send()
    ///     .await?;
    ///
    /// let stats: Vec<Stats> = res.items().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn stats(&self) -> stats::StatsBuilder {
        stats::StatsBuilder::new(self.clone())
    }

    /// Sends a GET request to /time and returns the server time in UTC.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// let client = ably::RestClient::from("<api_key>");
    ///
    /// let time = client.time().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn time(&self) -> Result<DateTime<Utc>> {
        let mut res: Vec<i64> = self
            .request(http::Method::GET, "/time", None::<()>, None::<()>, None)
            .await?
            .json()
            .await?;

        match res.pop() {
            Some(time) => Ok(Utc.timestamp(time / 1000, time as u32 % 1000)),
            None => Err(error!(40000, "Invalid response from /time")),
        }
    }

    /// Sends a custom HTTP request to the Ably REST API.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// let client = ably::RestClient::from("<api_key>");
    ///
    /// let params = [("key1", "val1"), ("key2", "val2")];
    ///
    /// let body = r#"{"json":"body"}"#;
    ///
    /// let mut headers = ably::http::HeaderMap::new();
    /// headers.insert("Foo", "Bar".parse().unwrap());
    ///
    /// let response = client.request(
    ///     ably::http::Method::POST,
    ///     "/some/custom/path",
    ///     Some(params),
    ///     Some(body),
    ///     Some(headers),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn request<T, U>(
        &self,
        method: http::Method,
        path: &str,
        params: Option<T>,
        body: Option<U>,
        headers: Option<http::HeaderMap>,
    ) -> Result<Response>
    where
        T: Serialize + Sized,
        U: Serialize + Sized,
    {
        let mut url = self.url.clone();
        url.set_path(path);

        let mut req = self.client.request(method, url);

        // Set the Authorization header
        match &self.options.credential {
            Some(auth::Key(key)) => {
                let mut iter = key.splitn(2, ':');
                req = req.basic_auth(iter.next().unwrap(), Some(iter.next().unwrap()));
            }
            Some(auth::Token(token)) => {
                req = req.bearer_auth(token);
            }
            None => {
                return Err(error!(40106, "must provide either an API key or a token"));
            }
        }

        if let Some(params) = params {
            req = req.query(&params);
        }

        if let Some(body) = body {
            req = req.json(&body);
        }

        if let Some(headers) = headers {
            req = req.headers(headers);
        }

        req.send().await.map(Response::new).map_err(Into::into)
    }

    /// Returns the API key from the ClientOptions.
    pub fn key(&self) -> Option<String> {
        match &self.options.credential {
            Some(auth::Key(s)) => Some(s.to_string()),
            _ => None,
        }
    }

    /// Returns the token from the ClientOptions.
    pub fn token(&self) -> Option<String> {
        match &self.options.credential {
            Some(auth::Token(s)) => Some(s.to_string()),
            _ => None,
        }
    }
}

/// A Response from the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Debug)]
pub struct Response {
    inner: reqwest::Response,
}

impl Response {
    fn new(response: reqwest::Response) -> Response {
        Response { inner: response }
    }

    /// Returns the list of items from the body of a paginated response.
    pub async fn items<T: DeserializeOwned>(self) -> Result<Vec<T>> {
        self.inner.json().await.map_err(Into::into)
    }

    /// Deserialize the response body as JSON.
    pub async fn json<T: DeserializeOwned>(self) -> Result<T> {
        self.inner.json().await.map_err(Into::into)
    }

    /// Returns the ErrorInfo from the body of the response.
    ///
    /// This is typically called after checking that success() is false.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// # let client = ably::RestClient::from("aaaaaa.bbbbbb:cccccc");
    /// let res = client.request(ably::http::Method::GET, "/invalid", None::<()>, None::<()>, None).await?;
    /// if !res.success() {
    ///     let err = res.error().await.unwrap();
    ///     assert_eq!(err.code, 404);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn error(self) -> Option<ErrorInfo> {
        self.json::<WrappedError>().await.ok().map(|e| e.error)
    }

    /// Returns the HTTP status code.
    pub fn status_code(&self) -> http::StatusCode {
        self.inner.status()
    }

    /// Returns true if the HTTP status code is within 200-299.
    pub fn success(&self) -> bool {
        self.status_code().is_success()
    }

    /// Returns the error code from the X-Ably-ErrorCode HTTP header.
    pub fn error_code(&self) -> Option<u32> {
        self.header(http::header::ERROR_CODE)
            .map(|v| v.parse().ok())
            .flatten()
    }

    /// Returns the error message from the X-Ably-ErrorMessage HTTP header.
    pub fn error_message(&self) -> Option<&str> {
        self.header(http::header::ERROR_MESSAGE)
    }

    fn header(&self, key: &str) -> Option<&str> {
        self.inner
            .headers()
            .get(key)
            .map(|v| v.to_str().ok())
            .flatten()
    }
}

impl From<&str> for RestClient {
    /// Returns a RestClient initialised with an API key or token contained
    /// in the given string.
    ///
    /// # Example
    ///
    /// ```
    /// // Initialise a RestClient with an API key.
    /// let client = ably::RestClient::from("<api_key>");
    /// ```
    ///
    /// ```
    /// // Initialise a RestClient with a token.
    /// let client = ably::RestClient::from("<token>");
    /// ```
    fn from(s: &str) -> Self {
        // unwrap the result since we're guaranteed to have a valid client when
        // it's initialised with an API key or token.
        ClientOptions::from(s).client().unwrap()
    }
}

/// [Ably client options] for initialising a REST or Realtime client.
///
/// [Ably client options]: https://ably.com/documentation/rest/types#client-options
#[derive(Clone, Debug)]
pub struct ClientOptions {
    /// Holds either an API key or a token.
    credential: Option<auth::Credential>,

    /// An optional custom environment used to construct the endpoint URLs.
    environment: Option<String>,

    /// Override the hostname used in the REST API URL.
    rest_host: Option<String>,

    /// The REST API URL which is constructed as options are set. Any error
    /// encountered when updating rest_url will be returned from client().
    rest_url: Result<reqwest::Url>,
}

impl ClientOptions {
    /// Returns ClientOptions with default values.
    pub fn new() -> Self {
        ClientOptions {
            credential:  None,
            environment: None,
            rest_host:   None,
            rest_url:    Ok(reqwest::Url::parse("https://rest.ably.io").unwrap()),
        }
    }

    /// Sets the API key.
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .key("aaaaaa.bbbbbb:cccccc")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn key(mut self, key: &str) -> Self {
        self.credential = Some(auth::Key(String::from(key)));
        self
    }

    /// Sets the token.
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .token("aaaaaa.dddddddddddd")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn token(mut self, token: &str) -> Self {
        self.credential = Some(auth::Token(String::from(token)));
        self
    }

    /// Sets the environment. See [TO3k1].
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .key("aaaaaa.bbbbbb:cccccc")
    ///     .environment("sandbox")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails if rest_host is already set or if the environment cannot be used
    /// in the REST API URL.
    ///
    /// [T03k1]: https://docs.ably.io/client-lib-development-guide/features/#TO3k1
    pub fn environment(mut self, environment: &str) -> Self {
        // Only allow the environment to be set if rest_host isn't set.
        if self.rest_host.is_some() {
            self.rest_url = Err(error!(40000, "Cannot set both environment and rest_host"));
            return self;
        }

        // Update the host in the URL if we haven't yet encountered an error.
        if let Ok(ref mut url) = self.rest_url {
            let host = format!("{}-rest.ably.io", environment);

            if let Err(err) = url.set_host(Some(host.as_ref())) {
                self.rest_url = Err(error!(
                    40000,
                    format!("Invalid environment '{}' ({})", environment, err)
                ));
                return self;
            }
        }

        // Track that the environment was set.
        self.environment = Some(String::from(environment));

        self
    }

    /// Sets the rest_host. See [TO3k2].
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .key("aaaaaa.bbbbbb:cccccc")
    ///     .rest_host("sandbox-rest.ably.io")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails if environment is already set or if the rest_host cannot be used
    /// in the REST API URL.
    ///
    /// [T03k2]: https://docs.ably.io/client-lib-development-guide/features/#TO3k2
    pub fn rest_host(mut self, rest_host: &str) -> Self {
        // Only allow the rest_host to be set if environment isn't set.
        if self.environment.is_some() {
            self.rest_url = Err(error!(40000, "Cannot set both environment and rest_host"));
            return self;
        }

        // Update the host in the URL if we haven't yet encountered an error.
        if let Ok(ref mut url) = self.rest_url {
            if let Err(err) = url.set_host(Some(rest_host)) {
                self.rest_url = Err(error!(
                    40000,
                    format!("Invalid rest_host '{}' ({})", rest_host, err)
                ));
                return self;
            }
        }

        // Track that the rest_host was set.
        self.rest_host = Some(String::from(rest_host));

        self
    }

    /// Returns a RestClient using the ClientOptions.
    ///
    /// # Errors
    ///
    /// This method fails if the ClientOptions are not valid:
    ///
    /// - a credential must be provided ([RSC1b])
    /// - the REST API URL must be valid
    ///
    /// [RSC1b]: https://docs.ably.io/client-lib-development-guide/features/#RSC1b
    pub fn client(self) -> Result<RestClient> {
        if let None = self.credential {
            return Err(error!(40106, "must provide either an API key or a token"));
        }
        let url = self.rest_url.clone()?;

        Ok(RestClient {
            options: self,
            client: reqwest::Client::new(),
            url,
        })
    }
}

impl From<&str> for ClientOptions {
    /// Returns ClientOptions initialised with an API key or token contained
    /// in the given string.
    ///
    /// If the string contains a colon, then the string is assumed to contain
    /// an API key, otherwise it's treated as a token (see [RSC1a]).
    ///
    /// # Example
    ///
    /// ```
    /// // Initialise ClientOptions with an API key.
    /// let client = ably::ClientOptions::from("uTNfLQ.ms51fw:****************");
    /// ```
    ///
    /// ```
    /// // Initialise ClientOptions with a token.
    /// let client = ably::ClientOptions::from("uTNfLQ.Gup2lu*********PYcwUb");
    /// ```
    ///
    /// [RSC1a]: https://docs.ably.io/client-lib-development-guide/features/#RSC1a
    fn from(s: &str) -> Self {
        ClientOptions {
            credential:  Some(match s.find(':') {
                Some(_) => auth::Key(String::from(s)),
                None => auth::Token(String::from(s)),
            }),
            environment: None,
            rest_host:   None,
            rest_url:    Ok(reqwest::Url::parse("https://rest.ably.io").unwrap()),
        }
    }
}

mod auth {
    /// An enum representing either an API key or a token.
    #[derive(Clone, Debug, PartialEq)]
    pub enum Credential {
        Key(String),
        Token(String),
    }
    pub use Credential::*;
}

/// Encapsulate HTTP related types in the http module.
pub mod http {
    pub use reqwest::header::{HeaderMap, HeaderName};
    pub use reqwest::{Method, Response, StatusCode};

    pub mod header {
        pub const ERROR_CODE: &str = "x-ably-errorcode";
        pub const ERROR_MESSAGE: &str = "x-ably-errormessage";
    }
}

#[cfg(test)]
mod tests {
    use super::http::Method;
    use super::stats::Stats;
    use super::*;
    use chrono::Duration;
    use serde::Deserialize;
    use serde_json::json;

    #[test]
    fn rest_client_from_sets_key_credential_with_string_with_colon() {
        let s = "appID.keyID:keySecret";
        let client = RestClient::from(s);
        assert_eq!(client.key(), Some(s.to_string()));
        assert_eq!(client.token(), None);
    }

    #[test]
    fn rest_client_from_sets_token_credential_with_string_without_colon() {
        let s = "appID.tokenID";
        let client = RestClient::from(s);
        assert_eq!(client.token(), Some(s.to_string()));
        assert_eq!(client.key(), None);
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

    fn test_client() -> RestClient {
        test_client_options().client().unwrap()
    }

    /// A test app in the Ably Sandbox environment.
    #[derive(Deserialize)]
    struct TestApp {
        keys: Vec<TestKey>,
    }

    /// A test key associated with a test app.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestKey {
        key_str: String,
    }

    impl TestApp {
        /// Creates a test app in the Ably Sandbox environment with a single
        /// API key.
        async fn create() -> Result<Self> {
            let spec = json!({"keys":[{}]});

            test_client()
                .request(Method::POST, "/apps", None::<()>, Some(spec), None)
                .await?
                .json()
                .await
        }

        /// Returns a RestClient with the test app's key.
        fn client(&self) -> RestClient {
            ClientOptions::from(self.keys[0].key_str.as_ref())
                .environment("sandbox")
                .client()
                .unwrap()
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
    async fn custom_request_returns_items() -> Result<()> {
        let client = test_client();

        let res = client
            .request(Method::GET, "/time", None::<()>, None::<()>, None)
            .await?;

        let items: Vec<u64> = res.items().await?;

        assert_eq!(items.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn custom_request_with_unknown_path_returns_404_response() -> Result<()> {
        let client = test_client();

        let res = client
            .request(Method::GET, "/invalid", None::<()>, None::<()>, None)
            .await?;

        assert!(!res.success());
        assert_eq!(res.status_code(), 404);
        assert_eq!(res.error_code(), Some(40400));
        assert!(res.error_message().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn custom_request_with_bad_rest_host_returns_network_error() -> Result<()> {
        let client = ClientOptions::from("aaaaaa.bbbbbb:cccccc")
            .rest_host("i-dont-exist.ably.com")
            .client()?;

        let err = client
            .request(Method::GET, "/time", None::<()>, None::<()>, None)
            .await
            .expect_err("Expected network error");

        assert_eq!(err.code, 40000);
        println!("{}", err.message);

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

        let res = client
            .request(Method::POST, "/stats", None::<()>, Some(fixtures), None)
            .await?;

        assert!(
            res.success(),
            "Failed to POST stats, error = {:?}",
            res.error().await
        );

        // Retrieve the stats.
        let res = client
            .stats()
            .start(format!("{}-02-03:15:03", last_year).as_ref())
            .end(format!("{}-02-03:15:05", last_year).as_ref())
            .forwards()
            .send()
            .await?;

        assert!(
            res.success(),
            "Failed to GET stats, error = {:?}",
            res.error().await
        );

        // Check the stats are what we expect.
        let stats: Vec<Stats> = res.items().await?;
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
}

//! A Rust client for the [Ably] REST and Realtime APIs.
//!
//! # Example
//!
//! TODO
//!
//! [Ably]: https://ably.com

#[macro_use]
mod error;

use error::*;
use chrono::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// A `Result` alias where the `Err` variant contains an `ably::ErrorInfo`.
pub type Result<T> = std::result::Result<T, ErrorInfo>;

/// A client for the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Debug)]
pub struct RestClient {
    pub options: ClientOptions,
    client: reqwest::Client,
}

impl RestClient {
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
        let url = format!("{}{}", self.options.rest_url(), path);

        let mut req = self.client.request(method, &url);

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
#[derive(Debug)]
pub struct ClientOptions {
    /// Holds either an API key or a token.
    credential: Option<auth::Credential>,

    /// An optional custom environment used to construct the endpoint URLs.
    environment: Option<String>,

    /// Override the hostname used in the REST API URL.
    rest_host: Option<String>,
}

impl ClientOptions {
    /// Returns ClientOptions with default values.
    pub fn new() -> Self {
        ClientOptions {
            credential: None,
            environment: None,
            rest_host: None,
        }
    }

    /// Sets the API key.
    pub fn key(mut self, key: &str) -> Self {
        self.credential = Some(auth::Key(String::from(key)));
        self
    }

    /// Sets the token.
    pub fn token(mut self, token: &str) -> Self {
        self.credential = Some(auth::Token(String::from(token)));
        self
    }

    /// Sets the environment.
    pub fn environment(mut self, environment: &str) -> Self {
        self.environment = Some(String::from(environment));
        self
    }

    /// Sets the rest_host.
    pub fn rest_host(mut self, rest_host: &str) -> Self {
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
    ///
    /// [RSC1b]: https://docs.ably.io/client-lib-development-guide/features/#RSC1b
    pub fn client(self) -> Result<RestClient> {
        if let None = self.credential {
            return Err(error!(40106, "must provide either an API key or a token"));
        }
        Ok(RestClient {
            options: self,
            client: reqwest::Client::new(),
        })
    }

    /// Returns the REST URL, taking into account the rest_host and environment
    /// options.
    fn rest_url(&self) -> String {
        if let Some(host) = &self.rest_host {
            return format!("https://{}", host);
        }
        if let Some(env) = &self.environment {
            return format!("https://{}-rest.ably.io", env);
        }
        String::from("https://rest.ably.io")
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
            credential: Some(match s.find(':') {
                Some(_) => auth::Key(String::from(s)),
                None => auth::Token(String::from(s)),
            }),
            environment: None,
            rest_host: None,
        }
    }
}

mod auth {
    /// An enum representing either an API key or a token.
    #[derive(Debug, PartialEq)]
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
    use super::*;
    use chrono::Duration;

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
        let client = test_client_options()
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
}

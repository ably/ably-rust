use super::error::{ErrorInfo, WrappedError};
use super::Result;
use super::{auth, rest};
pub use reqwest::header::{HeaderMap, HeaderValue};
pub use reqwest::Method;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// A low-level HTTP client for the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Clone, Debug)]
pub struct Client {
    inner:    reqwest::Client,
    rest_url: reqwest::Url,
}

impl Client {
    pub fn new(rest_url: reqwest::Url) -> Self {
        Self {
            inner: reqwest::Client::new(),
            rest_url,
        }
    }

    /// Start building a HTTP request to the Ably REST API.
    ///
    /// Returns a RequestBuilder which can be used to set query params, headers
    /// and the request body before sending the request.
    pub fn request(&self, method: Method, path: impl Into<String>) -> RequestBuilder {
        let mut url = self.rest_url.clone();
        url.set_path(&path.into());
        self.request_url(method, url)
    }

    /// Start building a HTTP request to the given URL.
    ///
    /// Returns a RequestBuilder which can be used to set query params, headers
    /// and the request body before sending the request.
    pub fn request_url(&self, method: Method, url: impl reqwest::IntoUrl) -> RequestBuilder {
        RequestBuilder::new(self.inner.request(method, url))
    }
}

/// A builder to construct a HTTP request to the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
pub struct RequestBuilder {
    inner:  Result<reqwest::RequestBuilder>,
    auth:   Option<auth::Auth>,
    format: rest::Format,
}

impl RequestBuilder {
    fn new(inner: reqwest::RequestBuilder) -> Self {
        Self {
            inner:  Ok(inner),
            auth:   None,
            format: rest::DEFAULT_FORMAT,
        }
    }

    /// Set the request format.
    pub fn format(mut self, format: rest::Format) -> Self {
        self.format = format;
        self
    }

    /// Modify the query params of the request, adding the parameters provided.
    pub fn params<T: Serialize + ?Sized>(mut self, params: &T) -> Self {
        if let Ok(req) = self.inner {
            self.inner = Ok(req.query(params));
        }
        self
    }

    /// Set the request body.
    pub fn body<T: Serialize + ?Sized>(self, body: &T) -> Self {
        match self.format {
            rest::Format::MessagePack => self.msgpack(body),
            rest::Format::JSON => self.json(body),
        }
    }

    /// Set the JSON request body.
    fn json<T: Serialize + ?Sized>(mut self, body: &T) -> Self {
        if let Ok(req) = self.inner {
            self.inner = Ok(req.json(body));
        }
        self
    }

    /// Set the MessagePack request body.
    fn msgpack<T: Serialize + ?Sized>(mut self, body: &T) -> Self {
        if let Ok(req) = self.inner {
            self.inner = rmp_serde::to_vec_named(body)
                .map(|data| {
                    req.header(
                        reqwest::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/x-msgpack"),
                    )
                    .body(data)
                })
                .map_err(Into::into)
        }
        self
    }

    /// Add a set of HTTP headers to the request.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        if let Ok(req) = self.inner {
            self.inner = Ok(req.headers(headers));
        }
        self
    }

    pub fn auth(mut self, auth: auth::Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Send the request to the Ably REST API.
    pub async fn send(self) -> Result<Response> {
        let mut req = self.inner?;

        // Set the Authorization header.
        if let Some(auth) = self.auth {
            match auth.credential {
                auth::Credential::Key(key) => {
                    req = req.basic_auth(&key.name, Some(&key.value));
                }
                auth::Credential::Token(token) => {
                    req = req.bearer_auth(&token);
                }
            }
        }

        // Send the request.
        let res = req.send().await?;

        // Return the response if it was successful, otherwise try to decode a
        // JSON error from the response body, falling back to a generic error
        // if decoding fails.
        if res.status().is_success() {
            return Ok(Response::new(res));
        }

        let status_code: u32 = res.status().as_u16().into();
        Err(res
            .json::<WrappedError>()
            .await
            .map(|e| e.error)
            .unwrap_or_else(|err| {
                error!(
                    50000,
                    format!("Unexpected error: {}", err),
                    Some(status_code)
                )
            }))
    }
}

/// A successful Response from the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Debug)]
pub struct Response {
    inner: reqwest::Response,
}

impl Response {
    fn new(response: reqwest::Response) -> Self {
        Self { inner: response }
    }

    /// Returns the response Content-Type.
    pub fn content_type(&self) -> Option<mime::Mime> {
        self.inner
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .map(|v| v.to_str().ok())
            .flatten()
            .map(|v| v.parse().ok())
            .flatten()
    }

    /// Returns the list of items from the body of a paginated response.
    pub async fn items<T: DeserializeOwned>(self) -> Result<Vec<T>> {
        self.body().await.map_err(Into::into)
    }

    /// Deserialize the response body.
    pub async fn body<T: DeserializeOwned>(self) -> Result<T> {
        let content_type = self
            .content_type()
            .ok_or(error!(40001, "missing content-type"))?;

        match content_type.essence_str() {
            "application/json" => self.json().await,
            "application/x-msgpack" => self.msgpack().await,
            _ => Err(error!(
                40001,
                format!("invalid response content-type: {}", content_type)
            )),
        }
    }

    /// Deserialize the response body as JSON.
    pub async fn json<T: DeserializeOwned>(self) -> Result<T> {
        self.inner.json().await.map_err(Into::into)
    }

    /// Deserialize the response body as MessagePack.
    pub async fn msgpack<T: DeserializeOwned>(self) -> Result<T> {
        let data = self.inner.bytes().await?;

        rmp_serde::from_read(&*data).map_err(Into::into)
    }

    /// Return the response body as a String.
    pub async fn text(self) -> Result<String> {
        self.inner.text().await.map_err(Into::into)
    }

    /// Returns the HTTP status code.
    pub fn status_code(&self) -> reqwest::StatusCode {
        self.inner.status()
    }
}

use super::error::{ErrorInfo, WrappedError};
use super::Result;
use super::{auth, rest};
use regex::Regex;
pub use reqwest::header::{HeaderMap, HeaderValue};
pub use reqwest::Method;
use std::convert::TryFrom;

use futures::future::FutureExt;
use futures::stream::{self, Stream};

use lazy_static::lazy_static;

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
        RequestBuilder::new(self.inner.clone(), self.inner.request(method, url))
    }
}

/// A builder to construct a HTTP request to the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
pub struct RequestBuilder {
    client: reqwest::Client,
    inner:  Result<reqwest::RequestBuilder>,
    auth:   Option<auth::Auth>,
    format: rest::Format,
}

impl RequestBuilder {
    fn new(client: reqwest::Client, inner: reqwest::RequestBuilder) -> Self {
        Self {
            client,
            inner: Ok(inner),
            auth: None,
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

    /// Request a stream of pages from the Ably REST API.
    pub fn pages(self) -> impl Stream<Item = Result<Response>> {
        // Use stream::unfold to create a Stream of pages where the internal
        // state is an Option<Result<Request>> representing a potential Request
        // for the next page, and the closure sends the Request and returns
        // both the Response and a Request for the next page if the Response
        // has a 'Link: ...; rel="next"' header.
        stream::unfold(Some(self.build()), |req| {
            async {
                // If there is no request in the state, we're done, so unwrap
                // the request to a Result<Request>.
                let req = req?;

                // If there was an error constructing the next Request, yield
                // that error and set the next state to None to end the stream.
                let req = match req {
                    Err(err) => return Some((Err(err), None)),
                    Ok(req) => req,
                };

                // Clone the request first so we can maintain the same headers
                // for the next request before we consume the current request
                // by sending it.
                //
                // If the Request is not cloneable, for example because it has
                // a streamed body, map it to an error which will be yielded on
                // the next iteration of the stream.
                let mut next_req = req
                    .try_clone()
                    .ok_or(error!(40000, "not a pageable request"));

                // Send the request, and if there's an error, yield it and set
                // the next state to None to end the stream.
                let res = match req.send().await {
                    Err(err) => return Some((Err(err), None)),
                    Ok(res) => res,
                };

                // If there's a next link in the response, merge its params
                // into the next Request if we have one and use it as the next
                // state, otherwise set the next state to None to end the
                // stream.
                let mut next_state = None;
                if let Some(link) = res.next_link() {
                    if let Ok(req) = &mut next_req {
                        req.url_mut().set_query(Some(&link.params));
                    }
                    next_state = Some(next_req)
                };

                // Yield the successful Response and the next state.
                Some((Ok(res), next_state))
            }
            .boxed()
        })
    }

    /// Send the request to the Ably REST API.
    pub async fn send(self) -> Result<Response> {
        self.build()?.send().await
    }

    fn build(self) -> Result<Request> {
        let mut req = self.inner?;

        req = req.header("X-Ably-Version", "1.2");

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

        // Build the request.
        let req = req.build()?;

        Ok(Request::new(self.client.clone(), req))
    }
}

pub struct Request {
    client: reqwest::Client,
    inner:  reqwest::Request,
}

impl Request {
    fn new(client: reqwest::Client, req: reqwest::Request) -> Self {
        Self { client, inner: req }
    }

    fn url_mut(&mut self) -> &mut reqwest::Url {
        self.inner.url_mut()
    }

    async fn send(self) -> Result<Response> {
        let res = self.client.execute(self.inner).await?;

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

    fn try_clone(&self) -> Option<Self> {
        self.inner
            .try_clone()
            .map(|req| Self::new(self.client.clone(), req))
    }
}

/// A Link HTTP header.
struct Link {
    rel:    String,
    params: String,
}

lazy_static! {
    /// A static regular expression to extract the rel and params fields
    /// from a Link header, which looks something like:
    ///
    /// Link: <./messages?limit=10&direction=forwards&cont=true&format=json&firstStart=0&end=1635552598723>; rel="next"
    static ref LINK_RE: Regex = Regex::new(r#"^\s*<[^?]+\?(?P<params>.+)>;\s*rel="(?P<rel>\w+)"$"#).unwrap();
}

impl TryFrom<&reqwest::header::HeaderValue> for Link {
    type Error = ErrorInfo;

    /// Try and extract a Link object from a Link HTTP header.
    fn try_from(v: &reqwest::header::HeaderValue) -> Result<Link> {
        // Check we have a valid utf-8 string.
        let link = v
            .to_str()
            .map_err(|_| error!(40004, "Invalid Link header"))?;

        // Extract the rel and params from the header using the LINK_RE regular
        // expression.
        let caps = LINK_RE
            .captures(link)
            .ok_or(error!(40004, "Invalid Link header"))?;
        let rel = caps
            .name("rel")
            .ok_or(error!(40004, "Invalid Link header; missing rel"))?;
        let params = caps
            .name("params")
            .ok_or(error!(40004, "Invalid Link header; missing params"))?;

        Ok(Self {
            rel:    rel.as_str().to_string(),
            params: params.as_str().to_string(),
        })
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

    fn next_link(&self) -> Option<Link> {
        self.inner
            .headers()
            .get_all(reqwest::header::LINK)
            .iter()
            .map(Link::try_from)
            .flatten()
            .find(|l| l.rel == "next")
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

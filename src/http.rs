use super::error::{ErrorInfo, WrappedError};
use super::Result;
use super::rest;
use crate::options::ClientOptions;
use regex::Regex;
pub use reqwest::header::{HeaderMap, HeaderValue};
pub use reqwest::Method;
use std::convert::TryFrom;
use std::fmt::Display;
use std::marker::PhantomData;

use futures::future::FutureExt;
use futures::stream::{self, Stream, StreamExt};

use lazy_static::lazy_static;

use rand::seq::SliceRandom;
use rand::thread_rng;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// A low-level HTTP client for the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Clone, Debug)]
pub struct Client {
    inner: reqwest::Client,
    opts:  ClientOptions,
    url:   reqwest::Url,
}

impl Client {
    pub fn new(inner: reqwest::Client, opts: ClientOptions, url: reqwest::Url) -> Self {
        Self { inner, opts, url }
    }

    /// Start building a HTTP request to the Ably REST API.
    ///
    /// Returns a RequestBuilder which can be used to set query params, headers
    /// and the request body before sending the request.
    pub fn request(&self, method: Method, path: impl Into<String>) -> RequestBuilder {
        let mut url = self.url.clone();
        url.set_path(&path.into());
        self.request_url(method, url).use_fallbacks()
    }

    pub fn paginated_request<T: PaginatedItem, U: PaginatedItemHandler<T>>(
        &self,
        method: Method,
        path: impl Into<String>,
        handler: Option<U>,
    ) -> PaginatedRequestBuilder<T, U> {
        PaginatedRequestBuilder::new(self.request(method, path), handler)
    }

    /// Start building a HTTP request to the given URL.
    ///
    /// Returns a RequestBuilder which can be used to set query params, headers
    /// and the request body before sending the request.
    pub fn request_url(&self, method: Method, url: impl reqwest::IntoUrl) -> RequestBuilder {
        RequestBuilder::new(self.clone(), self.inner.request(method, url))
    }

    /// Send the given request, retrying against fallback hosts if
    /// req.use_fallbacks is true.
    pub async fn send(&self, req: Request) -> Result<Response> {
        // Executing the request will consume it, so clone it first for a
        // potential retry later.
        let mut next_req = None;
        if req.use_fallbacks {
            next_req = req.try_clone();
        }

        // Execute the request, and return the response if it succeeds.
        let mut err = match self.execute(req).await {
            Ok(res) => return Ok(res),
            Err(err) => err,
        };

        // Return the error if we're unable to retry against fallback hosts.
        if next_req.is_none() || !Self::is_retriable(&err) {
            return Err(err);
        }

        // Create a randomised list of fallback hosts if they're set.
        let mut hosts = match &self.opts.fallback_hosts {
            None => return Err(err),
            Some(hosts) => hosts.clone(),
        };
        hosts.shuffle(&mut thread_rng());

        // Try sending the request to the fallback hosts.
        // TODO: take(httpMaxRetryCount)
        for host in hosts.iter() {
            // Check we have a next request to send.
            let mut req = match next_req {
                Some(req) => req,
                None => break,
            };

            // Update the request host and prepare the next request.
            next_req = req.try_clone();
            req.url_mut().set_host(Some(host)).map_err(|err| {
                error!(40000, format!("invalid fallback host '{}': {}", host, err))
            })?;

            // Execute the request, and return the response if it succeeds.
            err = match self.execute(req).await {
                Ok(res) => return Ok(res),
                Err(err) => err,
            };

            // Continue only if the request can be retried.
            if !Self::is_retriable(&err) {
                break;
            }
        }

        Err(err)
    }

    async fn execute(&self, req: Request) -> Result<Response> {
        let res = self.inner.execute(req.inner).await?;

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

    /// Return whether a request can be retried based on the error which
    /// resulted from attempting to send it.
    fn is_retriable(err: &ErrorInfo) -> bool {
        match err.status_code {
            Some(code) => (500..=504).contains(&code),
            None => true,
        }
    }
}

/// A builder to construct a HTTP request to the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
pub struct RequestBuilder {
    client:        Client,
    inner:         Result<reqwest::RequestBuilder>,
    format:        rest::Format,
    use_fallbacks: bool,
}

impl RequestBuilder {
    fn new(client: Client, inner: reqwest::RequestBuilder) -> Self {
        Self {
            client,
            inner: Ok(inner),
            format: rest::DEFAULT_FORMAT,
            use_fallbacks: false,
        }
    }

    /// Set the request format.
    pub fn format(mut self, format: rest::Format) -> Self {
        self.format = format;
        self
    }

    pub fn use_fallbacks(mut self) -> Self {
        self.use_fallbacks = true;
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

    pub fn basic_auth<U: Display, P: Display>(mut self, username: U, password: Option<P>) -> Self {
        if let Ok(req) = self.inner {
            self.inner = Ok(req.basic_auth(username, password));
        }
        self
    }

    pub fn bearer_auth<T: Display>(mut self, token: T) -> Self {
        if let Ok(req) = self.inner {
            self.inner = Ok(req.bearer_auth(token));
        }
        self
    }

    /// Send the request to the Ably REST API.
    pub async fn send(self) -> Result<Response> {
        let client = self.client.clone();

        let req = self.build()?;

        client.send(req).await
    }

    fn build(self) -> Result<Request> {
        let req = self.inner?.build()?;

        Ok(Request {
            inner:         req,
            use_fallbacks: self.use_fallbacks,
        })
    }
}

/// Internal state used with [stream::unfold] to construct a pagination stream.
///
/// The state holds the request for the next page in the stream, and an
/// optional item handler which is passed to each PaginatedResult.
///
/// [stream::unfold]: https://docs.rs/futures/latest/futures/stream/fn.unfold.html
struct PaginatedState<T, U: PaginatedItemHandler<T>> {
    next_req: Option<Result<Request>>,
    client:   Client,
    handler:  Option<U>,
    phantom:  PhantomData<T>,
}

/// A builder to construct a paginated REST request.
pub struct PaginatedRequestBuilder<T: PaginatedItem, U: PaginatedItemHandler<T> = ()> {
    inner:   RequestBuilder,
    handler: Option<U>,
    phantom: PhantomData<T>,
}

impl<T: PaginatedItem, U: PaginatedItemHandler<T>> PaginatedRequestBuilder<T, U> {
    pub fn new(inner: RequestBuilder, handler: Option<U>) -> Self {
        Self {
            inner,
            handler,
            phantom: PhantomData,
        }
    }

    pub fn start(self, interval: &str) -> Self {
        self.params(&[("start", interval)])
    }

    pub fn end(self, interval: &str) -> Self {
        self.params(&[("end", interval)])
    }

    pub fn forwards(self) -> Self {
        self.params(&[("direction", "forwards")])
    }

    pub fn backwards(self) -> Self {
        self.params(&[("direction", "backwards")])
    }

    pub fn limit(self, limit: u32) -> Self {
        self.params(&[("limit", limit.to_string())])
    }

    /// Modify the query params of the request, adding the parameters provided.
    pub fn params<P: Serialize + ?Sized>(mut self, params: &P) -> Self {
        self.inner = self.inner.params(params);
        self
    }

    /// Request a stream of pages from the Ably REST API.
    pub fn pages(self) -> impl Stream<Item = Result<PaginatedResult<T, U>>> {
        // Use stream::unfold to create a stream of pages where the internal
        // state holds the request for the next page, and the closure sends the
        // request and returns both a PaginatedResult and the request for the
        // next page if the response has a 'Link: ...; rel="next"' header.
        let client = self.inner.client.clone();
        let seed_state = PaginatedState {
            next_req: Some(self.inner.build()),
            client:   client,
            handler:  self.handler,
            phantom:  PhantomData,
        };
        stream::unfold(seed_state, |mut state| {
            async {
                // If there is no request in the state, we're done, so unwrap
                // the request to a Result<Request>.
                let req = state.next_req?;

                // If there was an error constructing the next request, yield
                // that error and set the next request to None to end the
                // stream on the next iteration.
                let req = match req {
                    Err(err) => {
                        state.next_req = None;
                        return Some((Err(err), state));
                    }
                    Ok(req) => req,
                };

                // Clone the request first so we can maintain the same headers
                // for the next request before we consume the current request
                // by sending it.
                //
                // If the request is not cloneable, for example because it has
                // a streamed body, map it to an error which will be yielded on
                // the next iteration of the stream.
                let mut next_req = req
                    .try_clone()
                    .ok_or(error!(40000, "not a pageable request"));

                // Send the request and wrap the response in a PaginatedResult.
                //
                // If there's an error, yield the error and set the next
                // request to None to end the stream on the next iteration.
                let res = match state.client.send(req).await {
                    Err(err) => {
                        state.next_req = None;
                        return Some((Err(err), state));
                    }
                    Ok(res) => PaginatedResult::new(res, state.handler.clone()),
                };

                // If there's a next link in the response, merge its params
                // into the next request if we have one, otherwise set the next
                // request to None to end the stream on the next iteration.
                state.next_req = None;
                if let Some(link) = res.next_link() {
                    if let Ok(req) = &mut next_req {
                        req.url_mut().set_query(Some(&link.params));
                    }
                    state.next_req = Some(next_req)
                };

                // Yield the PaginatedResult and the next state.
                Some((Ok(res), state))
            }
            .boxed()
        })
    }

    /// Retrieve the first page of the paginated response.
    pub async fn send(self) -> Result<PaginatedResult<T, U>> {
        // The pages stream always returns at least one non-None value, even if
        // the first request returns an error which would be Some(Err(err)), so
        // we unwrap the Option with a generic error which we don't expect to
        // be encountered by the caller.
        self.pages()
            .next()
            .await
            .unwrap_or(Err(error!(40000, "Unexpected error retrieving first page")))
    }
}

pub struct Request {
    inner:         reqwest::Request,
    use_fallbacks: bool,
}

impl Request {
    fn url_mut(&mut self) -> &mut reqwest::Url {
        self.inner.url_mut()
    }

    fn try_clone(&self) -> Option<Self> {
        self.inner.try_clone().map(|req| Self {
            inner:         req,
            use_fallbacks: self.use_fallbacks,
        })
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

    pub fn status(&self) -> reqwest::StatusCode {
        self.inner.status()
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

/// A handler for items in a paginated response, typically used to decode
/// history messages before returning them to the caller.
pub trait PaginatedItemHandler<T>: Send + Clone + 'static {
    fn handle(&self, item: &mut T) -> ();
}

/// Provide a no-op implementation of PaginatedItemHandler for the unit type
/// which is used as the default type for paginated responses which don't
/// require a handler (e.g. paginated stats responses).
impl<T> PaginatedItemHandler<T> for () {
    fn handle(&self, _: &mut T) -> () {}
}

/// An item in a paginated response.
///
/// An item can be any type which can be deserialized and sent between threads,
/// and this trait just provides a convenient alias for those traits.
pub trait PaginatedItem: DeserializeOwned + Send + 'static {}

/// Indicate to the compiler that any type which implements DeserializeOwned
/// and Send can be used as a PaginatedItem.
impl<T> PaginatedItem for T where T: DeserializeOwned + Send + 'static {}

/// A page of items from a paginated response.
pub struct PaginatedResult<T: PaginatedItem, U: PaginatedItemHandler<T> = ()> {
    res:     Response,
    handler: Option<U>,
    phantom: PhantomData<T>,
}

impl<T: PaginatedItem, U: PaginatedItemHandler<T>> PaginatedResult<T, U> {
    pub fn new(res: Response, handler: Option<U>) -> Self {
        Self {
            res,
            handler,
            phantom: PhantomData,
        }
    }

    /// Returns the page's list of items, running them through the item handler
    /// if set.
    pub async fn items(self) -> Result<Vec<T>> {
        let mut items: Vec<T> = self.res.body().await?;

        if let Some(handler) = self.handler {
            items.iter_mut().for_each(|item| handler.handle(item));
        }

        Ok(items)
    }

    fn next_link(&self) -> Option<Link> {
        self.res
            .inner
            .headers()
            .get_all(reqwest::header::LINK)
            .iter()
            .map(Link::try_from)
            .flatten()
            .find(|l| l.rel == "next")
    }
}

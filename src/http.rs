pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
pub use reqwest::Method;

use std::convert::TryFrom;
use std::fmt::Display;
use std::marker::PhantomData;

use futures::future::FutureExt;
use futures::stream::{self, Stream, StreamExt};
use lazy_static::lazy_static;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::ErrorInfo;
use crate::{rest, Result};

pub type UrlQuery = Box<[(String, String)]>;

/// A builder to construct a HTTP request to the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
pub struct RequestBuilder {
    client: rest::Client,
    inner:  Result<reqwest::RequestBuilder>,
    format: rest::Format,
}

impl RequestBuilder {
    pub fn new(client: rest::Client, inner: reqwest::RequestBuilder, format: rest::Format) -> Self {
        Self {
            client,
            inner: Ok(inner),
            format,
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

    fn build(self) -> Result<reqwest::Request> {
        self.inner?.build().map_err(Into::into)
    }
}

/// Internal state used with [stream::unfold] to construct a pagination stream.
///
/// The state holds the request for the next page in the stream, and an
/// optional item handler which is passed to each PaginatedResult.
///
/// [stream::unfold]: https://docs.rs/futures/latest/futures/stream/fn.unfold.html
struct PaginatedState<T, U: PaginatedItemHandler<T>> {
    next_req: Option<Result<reqwest::Request>>,
    client:   rest::Client,
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

    /// Set the start interval of the request.
    pub fn start(self, interval: &str) -> Self {
        self.params(&[("start", interval)])
    }

    /// Set the end interval of the request.
    pub fn end(self, interval: &str) -> Self {
        self.params(&[("end", interval)])
    }

    /// Paginate forwards.
    pub fn forwards(self) -> Self {
        self.params(&[("direction", "forwards")])
    }

    /// Paginate backwards.
    pub fn backwards(self) -> Self {
        self.params(&[("direction", "backwards")])
    }

    /// Limit the number of results per page.
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
            client,
            handler:  self.handler,
            phantom:  PhantomData,
        };
        stream::unfold(seed_state, |mut state| {
            async {
                // If there is no request in the state, we're done, so unwrap
                // the request to a Result<reqwest::Request>.
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
    pub fn new(response: reqwest::Response) -> Self {
        Self { inner: response }
    }

    /// The HTTP status code of the response.
    pub fn status(&self) -> reqwest::StatusCode {
        self.inner.status()
    }

    /// The value of the Content-Type header.
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

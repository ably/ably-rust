//! Mock HTTP client for unit testing.
//!
//! Implements the UTS Mock HTTP Infrastructure specification, providing a
//! handler-based pattern for intercepting and controlling HTTP requests
//! in tests.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::http_client::HttpClient;

/// A captured HTTP request, storing the details needed for test assertions.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: reqwest::Method,
    pub url: reqwest::Url,
    pub headers: reqwest::header::HeaderMap,
    pub body: Option<Vec<u8>>,
}

impl CapturedRequest {
    fn from_request(req: &reqwest::Request) -> Self {
        Self {
            method: req.method().clone(),
            url: req.url().clone(),
            headers: req.headers().clone(),
            body: req.body().and_then(|b| b.as_bytes()).map(|b| b.to_vec()),
        }
    }
}

/// A mock HTTP response to return from the mock client.
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MockResponse {
    /// Create a mock response with the given status and JSON body.
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: serde_json::to_vec(body).expect("failed to serialize mock JSON body"),
        }
    }

    /// Create a mock response with the given status and MessagePack body.
    pub fn msgpack(status: u16, body: &impl serde::Serialize) -> Self {
        Self {
            status,
            headers: vec![(
                "content-type".to_string(),
                "application/x-msgpack".to_string(),
            )],
            body: rmp_serde::to_vec_named(body).expect("failed to serialize mock msgpack body"),
        }
    }

    /// Create a mock response with the given status and no body.
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: vec![],
        }
    }

    /// Add a header to this response.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Convert to a `reqwest::Response`.
    fn into_reqwest_response(self) -> reqwest::Response {
        let mut builder = http::Response::builder().status(self.status);

        for (name, value) in &self.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        let http_response = builder
            .body(self.body)
            .expect("failed to build mock HTTP response");

        reqwest::Response::from(http_response)
    }
}

/// The type for request handler callbacks.
///
/// The handler receives a `CapturedRequest` and returns a `MockResponse`.
pub type RequestHandler = Box<dyn Fn(&CapturedRequest) -> MockResponse + Send + Sync>;

/// Shared mutable state for the mock client.
struct MockState {
    /// All captured requests in order.
    captured_requests: Vec<CapturedRequest>,
    /// Queued responses (FIFO) — used when no handler is set.
    queued_responses: Vec<MockResponse>,
    /// Request count (for handler-based patterns that vary by count).
    request_count: usize,
    /// Default headers to merge into captured requests (mimicking reqwest's
    /// default_headers behavior, which normally happens during execute).
    default_headers: reqwest::header::HeaderMap,
    /// Optional delay to apply before returning responses.
    response_delay: Option<std::time::Duration>,
}

/// A mock HTTP client for unit testing.
///
/// Matches the UTS `MockHttpClient` handler-based pattern. Supports:
///
/// - **Handler pattern**: provide a callback via `on_request()` that
///   receives each request and returns a response.
/// - **Queue pattern**: pre-queue responses via `queue_response()` that
///   are returned in FIFO order.
/// - **Request capture**: all requests are captured and available via
///   `captured_requests()` for assertions.
pub struct MockHttpClient {
    /// Handler called for each request. If None, uses queued responses.
    handler: Option<RequestHandler>,
    /// Shared mutable state.
    state: Arc<Mutex<MockState>>,
    /// A real reqwest::Client used only for building RequestBuilder instances.
    /// Requests built with this client are never actually executed — they're
    /// intercepted by our `execute()` implementation.
    builder_client: reqwest::Client,
}

impl fmt::Debug for MockHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap();
        f.debug_struct("MockHttpClient")
            .field("request_count", &state.request_count)
            .field("captured_requests", &state.captured_requests.len())
            .field("queued_responses", &state.queued_responses.len())
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

impl MockHttpClient {
    /// Create a new mock HTTP client with no handler.
    pub fn new() -> Self {
        Self {
            handler: None,
            state: Arc::new(Mutex::new(MockState {
                captured_requests: Vec::new(),
                queued_responses: Vec::new(),
                request_count: 0,
                default_headers: reqwest::header::HeaderMap::new(),
                response_delay: None,
            })),
            builder_client: reqwest::Client::new(),
        }
    }

    /// Create a new mock HTTP client with a request handler.
    ///
    /// The handler is called for every request and must return a
    /// `MockResponse`. This matches the UTS `onRequest` handler pattern.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mock = MockHttpClient::with_handler(|req| {
    ///     if req.url.path() == "/time" {
    ///         MockResponse::json(200, &serde_json::json!([1234567890000_i64]))
    ///     } else {
    ///         MockResponse::json(404, &serde_json::json!({"error": {"code": 40400}}))
    ///     }
    /// });
    /// ```
    pub fn with_handler(
        handler: impl Fn(&CapturedRequest) -> MockResponse + Send + Sync + 'static,
    ) -> Self {
        Self {
            handler: Some(Box::new(handler)),
            state: Arc::new(Mutex::new(MockState {
                captured_requests: Vec::new(),
                queued_responses: Vec::new(),
                request_count: 0,
                default_headers: reqwest::header::HeaderMap::new(),
                response_delay: None,
            })),
            builder_client: reqwest::Client::new(),
        }
    }

    /// Set the default headers to merge into captured requests.
    ///
    /// This is called by `rest_with_http_client` to match the headers that
    /// `ClientOptions` would normally set on the production reqwest client.
    /// In production, reqwest merges default_headers during `execute()`.
    /// Since we intercept `execute()`, we merge them ourselves.
    pub fn set_default_headers(&mut self, headers: reqwest::header::HeaderMap) {
        self.state.lock().unwrap().default_headers = headers;
    }

    /// Set a delay to apply before returning responses.
    ///
    /// This is used to test timeout behavior (RSC13).
    pub fn set_response_delay(&self, delay: std::time::Duration) {
        self.state.lock().unwrap().response_delay = Some(delay);
    }

    /// Queue a response to be returned for the next request.
    ///
    /// Queued responses are consumed in FIFO order. Panics if a request
    /// arrives and the queue is empty (and no handler is set).
    pub fn queue_response(&self, response: MockResponse) {
        self.state.lock().unwrap().queued_responses.push(response);
    }

    /// Return a snapshot of all captured requests.
    pub fn captured_requests(&self) -> Vec<CapturedRequest> {
        self.state.lock().unwrap().captured_requests.clone()
    }

    /// Return the number of requests that have been made.
    pub fn request_count(&self) -> usize {
        self.state.lock().unwrap().request_count
    }

    /// Clear all captured requests and reset the request count.
    pub fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.captured_requests.clear();
        state.queued_responses.clear();
        state.request_count = 0;
    }
}

impl HttpClient for MockHttpClient {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Response, reqwest::Error>> + Send>> {
        // Capture the request details, merging in default headers
        // (reqwest normally merges default_headers during execute,
        // but since we intercept, we do it ourselves).
        let mut captured = CapturedRequest::from_request(&request);

        // Update state and get response + delay.
        let (response, delay) = {
            let mut state = self.state.lock().unwrap();

            // Merge default headers (don't override headers already set on the request).
            for (key, value) in &state.default_headers {
                if !captured.headers.contains_key(key) {
                    captured.headers.insert(key.clone(), value.clone());
                }
            }

            state.request_count += 1;
            state.captured_requests.push(captured.clone());

            let delay = state.response_delay;

            // Get the response from handler or queue.
            let resp = if let Some(handler) = &self.handler {
                handler(&captured)
            } else if !state.queued_responses.is_empty() {
                state.queued_responses.remove(0)
            } else {
                panic!(
                    "MockHttpClient: no handler set and no queued responses for {} {}",
                    captured.method, captured.url
                );
            };

            (resp, delay)
        };

        let reqwest_response = response.into_reqwest_response();
        Box::pin(async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            Ok(reqwest_response)
        })
    }

    fn request(&self, method: reqwest::Method, url: reqwest::Url) -> reqwest::RequestBuilder {
        self.builder_client.request(method, url)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

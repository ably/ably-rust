//! HTTP client abstraction for dependency injection.
//!
//! This module provides the `HttpClient` trait which abstracts over HTTP
//! request execution, allowing the REST client to be tested with a mock
//! HTTP backend.

use std::any::Any;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

/// A trait abstracting HTTP request execution.
///
/// The production implementation wraps `reqwest::Client`. Tests can provide
/// a `MockHttpClient` that intercepts requests and returns controlled
/// responses.
pub trait HttpClient: Send + Sync + Debug {
    /// Execute a fully-built HTTP request and return the response.
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Response, reqwest::Error>> + Send>>;

    /// Create a new `reqwest::RequestBuilder` for the given method and URL.
    ///
    /// This is needed because `reqwest::RequestBuilder` is tied to a
    /// `reqwest::Client` instance.
    fn request(&self, method: reqwest::Method, url: reqwest::Url) -> reqwest::RequestBuilder;

    /// Downcast support for tests to access the concrete mock type.
    fn as_any(&self) -> &dyn Any;

    /// Mutable downcast support for tests.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Production HTTP client backed by `reqwest::Client`.
#[derive(Debug, Clone)]
pub struct ReqwestHttpClient {
    inner: reqwest::Client,
}

impl ReqwestHttpClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self { inner: client }
    }
}

impl HttpClient for ReqwestHttpClient {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<reqwest::Response, reqwest::Error>> + Send>> {
        let client = self.inner.clone();
        Box::pin(async move { client.execute(request).await })
    }

    fn request(&self, method: reqwest::Method, url: reqwest::Url) -> reqwest::RequestBuilder {
        self.inner.request(method, url)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

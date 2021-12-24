use futures::stream::Stream;

use crate::{http, rest, Result};

pub type PaginatedRequestBuilder =
    http::PaginatedRequestBuilder<rest::PresenceMessage, rest::MessageItemHandler>;

pub type PaginatedResult = http::PaginatedResult<rest::PresenceMessage, rest::MessageItemHandler>;

/// A builder to construct a REST presence request.
pub struct RequestBuilder {
    inner: PaginatedRequestBuilder,
}

impl RequestBuilder {
    pub fn new(inner: PaginatedRequestBuilder) -> Self {
        Self { inner }
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    pub fn client_id(mut self, client_id: &str) -> Self {
        self.inner = self.inner.params(&[("clientId", client_id.to_string())]);
        self
    }

    pub fn connection_id(mut self, connection_id: &str) -> Self {
        self.inner = self
            .inner
            .params(&[("connectionId", connection_id.to_string())]);
        self
    }

    /// Request a stream of pages from the Ably REST API.
    pub fn pages(self) -> impl Stream<Item = Result<PaginatedResult>> {
        self.inner.pages()
    }

    pub async fn send(self) -> Result<PaginatedResult> {
        self.inner.send().await
    }
}

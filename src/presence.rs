use futures::stream::Stream;

use crate::{http, rest, Result};

/// A type alias for a PaginatedRequestBuilder which uses a MessageItemHandler
/// to handle pages of presence messages returned from a presence request.
pub type PaginatedRequestBuilder<'a> =
    http::PaginatedRequestBuilder<'a, rest::PresenceMessage, rest::MessageItemHandler>;

/// A type alias for a PaginatedResult which uses a MessageItemHandler to
/// handle pages of presence messages returned from a presence request.
pub type PaginatedResult = http::PaginatedResult<rest::PresenceMessage, rest::MessageItemHandler>;

/// A builder to construct a REST presence request.
pub struct RequestBuilder<'a> {
    inner: PaginatedRequestBuilder<'a>,
}

impl<'a> RequestBuilder<'a> {
    pub fn new(inner: PaginatedRequestBuilder<'a>) -> Self {
        Self { inner }
    }

    /// Limit the number of results per page.
    pub fn limit(mut self, limit: u32) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    /// Set the client_id query param.
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.inner = self.inner.params(&[("clientId", client_id.to_string())]);
        self
    }

    /// Set the connection_id query param.
    pub fn connection_id(mut self, connection_id: &str) -> Self {
        self.inner = self
            .inner
            .params(&[("connectionId", connection_id.to_string())]);
        self
    }

    /// Request a stream of pages of presence messages.
    pub fn pages(self) -> impl Stream<Item = Result<PaginatedResult>> + 'a {
        self.inner.pages()
    }

    /// Retrieve the first page of presence messages.
    pub async fn send(self) -> Result<PaginatedResult> {
        self.inner.send().await
    }
}

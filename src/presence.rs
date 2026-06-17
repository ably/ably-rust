use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::channel::ChannelOptions;
use crate::rest::{Encoding, Rest};
use crate::Result;
use crate::{http, Data};

/// A type alias for a PaginatedRequestBuilder which uses a MessageItemHandler
/// to handle pages of presence messages returned from a presence request.
pub type PaginatedRequestBuilder<'a> = http::PaginatedRequestBuilder<'a, PresenceMessage>;

/// A type alias for a PaginatedResult which uses a MessageItemHandler to
/// handle pages of presence messages returned from a presence request.
pub type PaginatedResult = http::PaginatedResult<PresenceMessage>;

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

#[derive(Clone, Debug)]
pub struct Presence {
    rest: Rest,
    name: String,
}

impl Presence {
    pub(crate) fn new(rest: Rest, name: String) -> Self {
        Self { rest, name }
    }

    /// Start building a presence request for the channel.
    pub async fn get(&self) -> RequestBuilder {
        let req = self.rest.paginated_request_with_options(
            http::Method::GET,
            &format!("/channels/{}/presence", self.name),
            self.options().await,
        );
        RequestBuilder::new(req)
    }

    /// Start building a presence history request for the channel.
    ///
    /// Returns a history::RequestBuilder which is used to set parameters
    /// before sending the history request.
    pub async fn history(&self) -> crate::http::PaginatedRequestBuilder<PresenceMessage> {
        self.rest.paginated_request_with_options(
            http::Method::GET,
            &format!("/channels/{}/presence/history", self.name),
            self.options().await,
        )
    }

    pub async fn options(&self) -> Option<ChannelOptions> {
        // TODO maybe error when missing options instead of returning none
        self.rest
            .inner
            .channels
            .lock()
            .await
            .get(&self.name)
            .and_then(|c| c.options.clone())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceMessage {
    pub action: PresenceAction,
    pub client_id: String,
    pub connection_id: String,
    #[serde(skip_serializing_if = "Data::is_none")]
    pub data: Data,
    #[serde(default, skip_serializing_if = "Encoding::is_none")]
    pub encoding: Encoding,
}

#[derive(Clone, Debug, Deserialize_repr, PartialEq, Eq, Serialize_repr)]
#[serde(untagged)]
#[repr(u8)]
pub enum PresenceAction {
    Absent,
    Present,
    Enter,
    Leave,
    Update,
}

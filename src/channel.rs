use crate::crypto::CipherParams;
use crate::http::{self, PaginatedRequestBuilder};
use crate::presence::Presence;
use crate::rest::{Message, PublishBuilder};
use crate::Rest;

/// Options for publishing messages on a channel.
#[derive(Clone, Debug)]
pub struct ChannelOptions {
    pub(crate) cipher: Option<CipherParams>,
}

impl ChannelOptions {
    pub fn from_cipher(cipher: CipherParams) -> Self {
        Self {
            cipher: Some(cipher),
        }
    }
}

/// A collection of Channels.
#[derive(Clone, Debug)]
pub struct Channels {
    rest: Rest,
}

impl Channels {
    pub(crate) fn new(rest: Rest) -> Self {
        Self { rest }
    }

    pub fn rest(&self) -> &Rest {
        &self.rest
    }

    pub async fn get(&self, name: impl Into<String>) -> Channel {
        self.get_with_options(name, None).await
    }

    /// Build and return a Channel with the given name.
    pub async fn get_with_options(
        &self,
        name: impl Into<String>,
        options: Option<ChannelOptions>,
    ) -> Channel {
        let name = name.into();
        self.rest()
            .inner
            .channels
            .lock()
            .await
            .entry(name.clone())
            .or_insert(InnerChannel { options });
        Channel {
            channels: self.clone(),
            name,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InnerChannel {
    // maybe this should be it's own Arc<Mutex<T>>. This would mean we don't need to lock the main
    // channels vec whenever we read channel options. But it would mean we have 2 levels of locks
    // and allocations.
    pub options: Option<ChannelOptions>,
}

/// An Ably Channel to publish messages to or retrieve history or presence for.
#[derive(Clone, Debug)]
pub struct Channel {
    pub channels: Channels,
    pub name: String,
}

impl Channel {
    pub fn rest(&self) -> &Rest {
        self.channels().rest()
    }

    pub fn channels(&self) -> &Channels {
        &self.channels
    }

    pub async fn set_options(&self, options: Option<ChannelOptions>) {
        if let Some(channel) = self.rest().inner.channels.lock().await.get_mut(&self.name) {
            channel.options = options;
        }
    }

    pub async fn options(&self) -> Option<ChannelOptions> {
        // TODO maybe error when missing options instead of returning none
        self.rest()
            .inner
            .channels
            .lock()
            .await
            .get(&self.name)
            .and_then(|c| c.options.clone())
    }

    pub fn presence(&self) -> Presence {
        Presence::new(self.rest().clone(), self.name.clone())
    }

    /// Start building a request to publish a message on the channel.
    pub async fn publish(&self) -> PublishBuilder {
        let mut builder = PublishBuilder::new(self.rest(), self.name.clone());

        if let Some(opts) = self.options().await {
            if let Some(cipher) = &opts.cipher {
                builder = builder.cipher(cipher.clone());
            }
        }

        builder
    }

    /// Start building a history request for the channel.
    ///
    /// Returns a history::RequestBuilder which is used to set parameters
    /// before sending the history request.
    pub async fn history(&self) -> PaginatedRequestBuilder<Message> {
        self.rest().paginated_request_with_options(
            http::Method::GET,
            &format!("/channels/{}/history", self.name),
            self.options().await,
        )
    }
}

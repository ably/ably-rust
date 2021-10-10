use crate::error::*;
use crate::options::ClientOptions;
use crate::{auth, http, stats, Result};

use chrono::prelude::*;
use serde::Serialize;

/// A client for the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Debug)]
pub struct Rest {
    pub auth:     auth::Auth,
    pub channels: Channels,
    pub client:   Client,
}

impl Rest {
    /// Start building a GET request to /stats.
    ///
    /// Returns a StatsBuilder which is used to set parameters before sending
    /// the stats request.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// use ably::stats::Stats;
    ///
    /// let client = ably::Rest::from("<api_key>");
    ///
    /// let res = client
    ///     .stats()
    ///     .start("2021-09-09:15:00")
    ///     .end("2021-09-09:15:05")
    ///     .send()
    ///     .await?;
    ///
    /// let stats: Vec<Stats> = res.items().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn stats(&self) -> stats::StatsBuilder {
        let req = self.client.request(http::Method::GET, "/stats");
        stats::StatsBuilder::new(req)
    }

    /// Sends a GET request to /time and returns the server time in UTC.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// let client = ably::Rest::from("<api_key>");
    ///
    /// let time = client.time().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn time(&self) -> Result<DateTime<Utc>> {
        let mut res: Vec<i64> = self
            .client
            .request(http::Method::GET, "/time")
            .send()
            .await?
            .json()
            .await?;

        let time = res
            .pop()
            .ok_or(error!(40000, "Invalid response from /time"))?;

        Ok(Utc.timestamp(time / 1000, time as u32 % 1000))
    }

    /// Start building a HTTP request to the Ably REST API.
    ///
    /// Returns a RequestBuilder which can be used to set query params, headers
    /// and the request body before sending the request.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// use ably::http::{HeaderMap,Method};
    ///
    /// let client = ably::Rest::from("<api_key>");
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("Foo", "Bar".parse().unwrap());
    ///
    /// let response = client
    ///     .request(Method::POST, "/some/custom/path")
    ///     .params(&[("key1", "val1"), ("key2", "val2")])
    ///     .body(r#"{"json":"body"}"#)
    ///     .headers(headers)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if sending the request fails or if the resulting
    /// response is unsuccessful (i.e. the status code is not in the 200-299
    /// range).
    pub fn request(&self, method: http::Method, path: &str) -> http::RequestBuilder {
        self.client.request(method, path)
    }
}

impl From<&str> for Rest {
    /// Returns a Rest client initialised with an API key or token contained
    /// in the given string.
    ///
    /// # Example
    ///
    /// ```
    /// // Initialise a Rest client with an API key.
    /// let client = ably::Rest::from("<api_key>");
    /// ```
    ///
    /// ```
    /// // Initialise a Rest client with a token.
    /// let client = ably::Rest::from("<token>");
    /// ```
    fn from(s: &str) -> Self {
        // unwrap the result since we're guaranteed to have a valid client when
        // it's initialised with an API key or token.
        ClientOptions::from(s).client().unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    auth: auth::Auth,
    http: http::Client,
}

impl Client {
    pub fn new(auth: auth::Auth, http: http::Client) -> Self {
        Self { auth, http }
    }

    pub fn request(&self, method: http::Method, path: impl Into<String>) -> http::RequestBuilder {
        let mut req = self.http.request(method, path);
        req = req.auth(self.auth.clone());
        req
    }
}

#[derive(Clone, Debug)]
pub struct Channels {
    client: Client,
}

impl Channels {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn get(&self, name: impl Into<String>) -> Channel {
        Channel {
            name:   name.into(),
            client: self.client.clone(),
        }
    }
}

pub struct Channel {
    pub name: String,
    client:   Client,
}

impl Channel {
    pub fn publish(&self) -> ChannelPublishBuilder {
        ChannelPublishBuilder::new(self.client.clone(), self.name.clone())
    }
}

pub struct ChannelPublishBuilder {
    client:  Client,
    channel: String,
    event:   Option<String>,
    data:    Option<String>,
}

impl ChannelPublishBuilder {
    fn new(client: Client, channel: String) -> Self {
        Self {
            client,
            channel,
            event: None,
            data: None,
        }
    }

    pub fn event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    pub async fn send(self) -> Result<()> {
        let data = self
            .data
            .ok_or(error!(40013, "message data must be provided"))?;

        let msg = Message {
            event: self.event,
            data,
        };

        self.client
            .request(
                http::Method::POST,
                format!("/channels/{}/messages", self.channel),
            )
            .body(&msg)
            .send()
            .await
            .map(|_| ())
    }
}

#[derive(Serialize)]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<String>,
    data:  String,
}

use crate::error::*;
use crate::options::ClientOptions;
use crate::{auth, base64, history, http, stats, Result};

use chrono::prelude::*;
use serde::{Deserialize, Serialize};

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
    /// Returns a stats::RequestBuilder which is used to set parameters before
    /// sending the stats request.
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
    pub fn stats(&self) -> stats::RequestBuilder {
        let req = self.client.request(http::Method::GET, "/stats");
        stats::RequestBuilder::new(req)
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
    pub fn publish(&self) -> PublishBuilder {
        PublishBuilder::new(self.client.clone(), self.name.clone())
    }

    /// Start building a history request for the channel.
    ///
    /// Returns a history::RequestBuilder which is used to set parameters
    /// before sending the history request.
    ///
    pub fn history(&self) -> history::RequestBuilder {
        let req = self.client.request(
            http::Method::GET,
            format!("/channels/{}/history", self.name),
        );
        history::RequestBuilder::new(req)
    }
}

pub struct PublishBuilder {
    client:   Client,
    channel:  String,
    data:     Result<Data>,
    encoding: Encoding,
    event:    Option<String>,
}

impl PublishBuilder {
    fn new(client: Client, channel: String) -> Self {
        Self {
            client,
            channel,
            data: Ok(Data::None),
            encoding: Encoding::None,
            event: None,
        }
    }

    pub fn event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    pub fn string(mut self, data: impl Into<String>) -> Self {
        self.data = Ok(Data::String(data.into()));
        self
    }

    pub fn json(mut self, data: impl serde::Serialize) -> Self {
        self.data = data
            .serialize(serde_json::value::Serializer)
            .map(Into::into)
            .map_err(|err| error!(40013, format!("invalid message data: {}", err)));
        self.encoding = Encoding::JSON;
        self
    }

    pub fn binary(mut self, data: Vec<u8>) -> Self {
        self.data = Ok(data.into());
        self.encoding = Encoding::Base64;
        self
    }

    pub async fn send(self) -> Result<()> {
        let msg = Message {
            event:    self.event,
            raw_data: self.data?,
            encoding: self.encoding,
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

/// Data is the payload of a message which can either be a utf-8 encoded
/// string, a JSON serializable object, or a binary array.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Data {
    String(String),
    JSON(serde_json::Value),
    #[serde(with = "base64")]
    Binary(Vec<u8>),
    None,
}

impl Data {
    fn is_none(&self) -> bool {
        match self {
            Self::None => true,
            _ => false,
        }
    }
}

impl From<String> for Data {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Self::Binary(v)
    }
}

impl From<serde_json::Value> for Data {
    fn from(v: serde_json::Value) -> Self {
        Self::JSON(v)
    }
}

#[derive(Deserialize, Serialize)]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Data::is_none")]
    #[serde(rename = "data")]
    raw_data:  Data,
    #[serde(skip_serializing_if = "Encoding::is_none")]
    #[serde(default = "Encoding::none")]
    encoding:  Encoding,
}

impl Message {
    /// Returns the decoded message data.
    pub fn data(&self) -> Result<Data> {
        match self.encoding {
            Encoding::None => match &self.raw_data {
                Data::None => Ok(Data::None),
                Data::String(_) => Ok(self.raw_data.clone()),
                _ => Err(error!(40013, "invalid message encoding")),
            },
            Encoding::JSON => match &self.raw_data {
                Data::JSON(_) => Ok(self.raw_data.clone()),
                _ => Err(error!(40013, "invalid JSON message data")),
            },
            Encoding::Base64 => match &self.raw_data {
                Data::String(s) => base64::decode(s).map(Into::into).map_err(Into::into),
                _ => Err(error!(40013, "invalid base64 message data")),
            },
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Encoding {
    JSON,
    Base64,
    None,
}

impl Encoding {
    fn is_none(&self) -> bool {
        match self {
            Self::None => true,
            _ => false,
        }
    }

    fn none() -> Self {
        Self::None
    }
}

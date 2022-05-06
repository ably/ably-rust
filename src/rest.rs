use chrono::prelude::*;
use lazy_static::lazy_static;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::error::*;
use crate::options::ClientOptions;
use crate::{auth, crypto, history, http, json, presence, stats, Result};

/// A client for the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Debug)]
pub struct Rest {
    pub auth:     auth::Auth,
    pub channels: Channels,
    pub client:   Client,
    pub opts:     ClientOptions,
}

impl Rest {
    pub(crate) fn new(auth: auth::Auth, client: Client, opts: ClientOptions) -> Self {
        Self {
            auth,
            channels: Channels::new(client.clone()),
            client,
            opts,
        }
    }

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
    /// let stats = res.items().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn stats(&self) -> http::PaginatedRequestBuilder<stats::Stats> {
        self.client
            .paginated_request(http::Method::GET, "/stats", None)
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
            .body()
            .await?;

        let time = res
            .pop()
            .ok_or_else(|| error!(40000, "Invalid response from /time"))?;

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

    /// Start building a paginated HTTP request to the Ably REST API.
    ///
    /// Returns a PaginatedRequestBuilder which can be used to set query
    /// params before sending the request.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// use futures::TryStreamExt;
    /// use ably::http::Method;
    ///
    /// let client = ably::Rest::from("<api_key>");
    ///
    /// let mut pages = client
    ///     .paginated_request(Method::GET, "/time")
    ///     .forwards()
    ///     .limit(1)
    ///     .pages();
    ///
    /// let page = pages.try_next().await?.expect("Expected a page");
    ///
    /// let items = page.items().await?;
    ///
    /// assert_eq!(items.len(), 1);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if sending the request fails or if the resulting
    /// response is unsuccessful (i.e. the status code is not in the 200-299
    /// range).
    pub fn paginated_request(
        &self,
        method: http::Method,
        path: &str,
    ) -> http::PaginatedRequestBuilder<json::Value> {
        self.client.paginated_request(method, path, None)
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

impl From<String> for Rest {
    fn from(s: String) -> Self {
        Rest::from(s.as_str())
    }
}

#[derive(Clone, Debug)]
/// An internal client which is shared by both rest::Rest and auth::Auth to
/// send HTTP requests to the Ably REST API.
pub struct Client {
    inner: reqwest::Client,
    opts:  ClientOptions,
    url:   reqwest::Url,
    auth:  Option<Box<auth::Auth>>,
}

impl Client {
    pub fn new(inner: reqwest::Client, opts: ClientOptions, url: reqwest::Url) -> Self {
        Self {
            inner,
            opts,
            url,
            auth: None,
        }
    }

    pub fn new_with_auth(
        inner: reqwest::Client,
        opts: ClientOptions,
        url: reqwest::Url,
        auth: auth::Auth,
    ) -> Self {
        Self {
            inner,
            opts,
            url,
            auth: Some(Box::new(auth)),
        }
    }

    pub fn request(&self, method: http::Method, path: impl Into<String>) -> http::RequestBuilder {
        let mut url = self.url.clone();
        url.set_path(&path.into());
        self.request_url(method, url)
    }

    pub fn request_url(
        &self,
        method: http::Method,
        url: impl reqwest::IntoUrl,
    ) -> http::RequestBuilder {
        http::RequestBuilder::new(
            self.clone(),
            self.inner.request(method, url),
            self.opts.format.clone(),
        )
    }

    pub fn paginated_request<T: http::PaginatedItem, U: http::PaginatedItemHandler<T>>(
        &self,
        method: http::Method,
        path: impl Into<String>,
        handler: Option<U>,
    ) -> http::PaginatedRequestBuilder<T, U> {
        http::PaginatedRequestBuilder::new(self.request(method, path), handler)
    }

    /// Send the given request, retrying against fallback hosts if it fails.
    pub async fn send(&self, req: reqwest::Request) -> Result<http::Response> {
        // Executing the request will consume it, so clone it first for a
        // potential retry later.
        let mut next_req = req.try_clone();

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

        // Try sending the request to the fallback hosts, capped at
        // ClientOptions.httpMaxRetryCount.
        for host in hosts.iter().take(self.opts.http_max_retry_count) {
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

    async fn execute(&self, mut req: reqwest::Request) -> Result<http::Response> {
        if let Some(auth) = &self.auth {
            auth.with_auth_headers(&mut req).await?;
        }

        let res = self.inner.execute(req).await?;

        // Return the response if it was successful, otherwise try to decode a
        // JSON error from the response body, falling back to a generic error
        // if decoding fails.
        if res.status().is_success() {
            return Ok(http::Response::new(res));
        }

        let status_code: u32 = res.status().as_u16().into();
        Err(res
            .json::<WrappedError>()
            .await
            .map(|e| e.error)
            .unwrap_or_else(|err| error!(50000, format!("Unexpected error: {}", err), status_code)))
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

/// Options for publishing messages on a channel.
#[derive(Clone)]
pub struct ChannelOptions {
    cipher: Option<CipherParams>,
}

impl From<CipherParams> for ChannelOptions {
    fn from(cipher: CipherParams) -> Self {
        Self {
            cipher: Some(cipher),
        }
    }
}

/// Parameters for encrypting and decrypting channel messages.
///
/// # Example
///
/// Initialize cipher params with a random 256 bit key.
///
/// ```
/// use ably::crypto::*;
///
/// let key = generate_random_key::<Key256>();
///
/// let params = ably::rest::CipherParams::from(key);
/// ```
#[derive(Clone)]
pub struct CipherParams {
    key: crypto::Key,
    iv:  Option<crypto::IV>,
}

impl CipherParams {
    fn encoding(&self) -> String {
        format!("cipher+{}", self.algorithm())
    }

    fn algorithm(&self) -> String {
        format!("aes-{}-cbc", self.key.len())
    }

    /// Set an IV rather than using a random one. This is for testing purposes
    /// only.
    #[allow(dead_code)]
    pub(crate) fn set_iv(mut self, iv: crypto::IV) -> Self {
        self.iv = Some(iv);
        self
    }

    /// Encrypt the data using AES-CBC with PKCS7 padding, returning the
    /// ciphertext prefixed with the IV.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // generate a random IV if one isn't provided.
        let iv = match self.iv {
            Some(iv) => iv,
            None => thread_rng().gen(),
        };

        // create a buffer big enough to store the data + padding.
        let blocks = data.len() / aes::BLOCK_SIZE + 1;
        let mut buf = vec![0u8; blocks * aes::BLOCK_SIZE];

        // copy the data into the buffer.
        buf[..data.len()].copy_from_slice(data);

        // encrypt the data.
        let encrypted = self.key.encrypt(&iv, &mut buf, data.len())?;

        // return the encrypted data prefixed with the IV.
        Ok([&iv[..], encrypted].concat())
    }

    /// Decrypt the data using AES-CBC with PKCS7 padding.
    pub fn decrypt(&self, data: &mut [u8]) -> Result<Vec<u8>> {
        if data.len() % aes::BLOCK_SIZE != 0 || data.len() < aes::BLOCK_SIZE {
            return Err(error!(
                40013,
                format!(
                    "invalid cipher message data; unexpected length: {}",
                    data.len()
                )
            ));
        }
        let (iv, buf) = data.split_at_mut(aes::BLOCK_SIZE);
        let decrypted = self.key.decrypt(iv, buf)?;
        Ok(decrypted.to_vec())
    }
}

impl From<crypto::Key> for CipherParams {
    fn from(key: crypto::Key) -> Self {
        CipherParams { key, iv: None }
    }
}

/// Start building a Channel to publish a message.
pub struct ChannelBuilder {
    client: Client,
    name:   String,
    cipher: Option<CipherParams>,
}

impl ChannelBuilder {
    fn new(client: Client, name: String) -> Self {
        Self {
            client,
            name,
            cipher: None,
        }
    }

    /// Set the channel cipher parameters.
    pub fn cipher(mut self, cipher: CipherParams) -> Self {
        self.cipher = Some(cipher);
        self
    }

    /// Build the Channel.
    pub fn get(self) -> Channel {
        let opts = self.cipher.map(Into::into);
        Channel {
            name:     self.name.clone(),
            presence: Presence::new(self.name.clone(), self.client.clone(), opts.clone()),
            client:   self.client,
            opts,
        }
    }
}

/// A collection of Channels.
#[derive(Clone, Debug)]
pub struct Channels {
    client: Client,
}

impl Channels {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Start building a Channel with the given name.
    pub fn name(&self, name: impl Into<String>) -> ChannelBuilder {
        ChannelBuilder::new(self.client.clone(), name.into())
    }

    /// Build and return a Channel with the given name.
    pub fn get(&self, name: impl Into<String>) -> Channel {
        self.name(name).get()
    }
}

/// An Ably Channel to publish messages to or retrieve history or presence for.
pub struct Channel {
    pub name:     String,
    pub presence: Presence,
    client:       Client,
    opts:         Option<ChannelOptions>,
}

impl Channel {
    /// Start building a request to publish a message on the channel.
    pub fn publish(&self) -> PublishBuilder {
        let mut builder = PublishBuilder::new(self.client.clone(), self.name.clone());

        if let Some(opts) = &self.opts {
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
    pub fn history(&self) -> history::PaginatedRequestBuilder<Message> {
        self.client.paginated_request(
            http::Method::GET,
            format!("/channels/{}/history", self.name),
            Some(MessageItemHandler::new(self.opts.clone())),
        )
    }
}

pub struct Presence {
    name:   String,
    client: Client,
    opts:   Option<ChannelOptions>,
}

impl Presence {
    fn new(name: String, client: Client, opts: Option<ChannelOptions>) -> Self {
        Self { name, client, opts }
    }

    /// Start building a presence request for the channel.
    pub fn get(&self) -> presence::RequestBuilder {
        let req = self.client.paginated_request(
            http::Method::GET,
            format!("/channels/{}/presence", self.name),
            Some(MessageItemHandler::new(self.opts.clone())),
        );
        presence::RequestBuilder::new(req)
    }

    /// Start building a presence history request for the channel.
    ///
    /// Returns a history::RequestBuilder which is used to set parameters
    /// before sending the history request.
    pub fn history(&self) -> history::PaginatedRequestBuilder<PresenceMessage> {
        self.client.paginated_request(
            http::Method::GET,
            format!("/channels/{}/presence/history", self.name),
            Some(MessageItemHandler::new(self.opts.clone())),
        )
    }
}

/// A request to publish a message to a channel.
pub struct PublishBuilder {
    req:    http::RequestBuilder,
    msg:    Result<Message>,
    format: Format,
    cipher: Option<CipherParams>,
}

impl PublishBuilder {
    fn new(client: Client, channel: String) -> Self {
        let req = client.request(
            http::Method::POST,
            format!("/channels/{}/messages", channel),
        );

        Self {
            req,
            msg: Ok(Message::default()),
            format: client.opts.format,
            cipher: None,
        }
    }

    /// Set the message ID.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.id = Some(id.into());
        }
        self
    }

    /// Set the message name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.name = Some(name.into());
        }
        self
    }

    /// Set the message data to the given string.
    pub fn string(mut self, data: impl Into<String>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.data = Data::String(data.into());
        }
        self
    }

    /// Set the message data to the JSON encoding of the given data.
    pub fn json(mut self, data: impl serde::Serialize) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            let data = data
                .serialize(serde_json::value::Serializer)
                .map(Into::into)
                .map_err(|err| error!(40013, format!("invalid message data: {}", err)));

            match data {
                Ok(data) => {
                    msg.data = data;
                }
                Err(err) => self.msg = Err(err),
            }
        }
        self
    }

    /// Set the message data to the given binary data.
    pub fn binary(mut self, data: Vec<u8>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.data = data.into();
        }
        self
    }

    /// Set the message extras.
    pub fn extras(mut self, extras: json::Map) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.extras = Some(extras);
        }
        self
    }

    /// Set the params to include in the publish request.
    pub fn params<T: Serialize + ?Sized>(mut self, params: &T) -> Self {
        self.req = self.req.params(params);
        self
    }

    /// Set the cipher to use to encrypt the message.
    pub fn cipher(mut self, cipher: CipherParams) -> Self {
        self.cipher = Some(cipher);
        self
    }

    /// Publish the message.
    pub async fn send(self) -> Result<()> {
        let mut msg = self.msg?;

        msg.encode(&self.format, self.cipher.as_ref())?;

        self.req.body(&msg).send().await.map(|_| ())
    }
}

/// Data is the payload of a message which can either be a utf-8 encoded
/// string, a JSON serializable object, or a binary array.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Data {
    String(String),
    JSON(serde_json::Value),
    Binary(serde_bytes::ByteBuf),
    None,
}

impl Data {
    fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl Serialize for Data {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::String(s) => return s.serialize(serializer),
            Self::JSON(v) => serde_json::to_string(v).map_err(serde::ser::Error::custom)?,
            Self::Binary(v) => return v.serialize(serializer),
            Self::None => String::from(""),
        };
        s.serialize(serializer)
    }
}

impl Default for Data {
    fn default() -> Self {
        Self::None
    }
}

impl From<String> for Data {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for Data {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Self::Binary(serde_bytes::ByteBuf::from(v))
    }
}

impl From<&[u8]> for Data {
    fn from(v: &[u8]) -> Self {
        Self::Binary(serde_bytes::ByteBuf::from(v))
    }
}

impl From<serde_json::Value> for Data {
    fn from(v: serde_json::Value) -> Self {
        Self::JSON(v)
    }
}

/// The encoding of a message, which is either unset or is a list of data
/// encodings separated by the '/' character.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Encoding {
    None,
    Some(String),
}

impl Encoding {
    fn is_none(&self) -> bool {
        match self {
            Self::None => true,
            Self::Some(_) => false,
        }
    }

    /// Append the given encoding to the current list of encodings.
    fn push(&mut self, value: impl Into<String>) {
        *self = Self::Some(match self {
            Self::None => value.into(),
            Self::Some(s) => format!("{}/{}", s, value.into()),
        })
    }

    /// Pop the last encoding from the list of encodings, leaving the list
    /// unset if the popped encoding was the only one in the list.
    fn pop(&mut self) -> Option<String> {
        let mut encodings = match self {
            Self::Some(s) => s.split('/').collect::<Vec<&str>>(),
            Self::None => return None,
        };
        let last = encodings.pop()?.to_string();
        *self = if encodings.is_empty() {
            Self::None
        } else {
            Self::Some(encodings.join("/"))
        };
        Some(last)
    }
}

impl Default for Encoding {
    fn default() -> Self {
        Self::None
    }
}

/// A message which is published to a channel or returned by a history request.
#[derive(Default, Deserialize, Serialize)]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id:            Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:          Option<String>,
    #[serde(skip_serializing_if = "Data::is_none")]
    pub data:          Data,
    #[serde(default, skip_serializing_if = "Encoding::is_none")]
    pub encoding:      Encoding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id:     Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras:        Option<json::Map>,
}

impl Message {
    /// Initialize a Message from the given JSON serialized data.
    pub fn from_encoded(v: json::Value, opts: Option<&ChannelOptions>) -> Result<Message> {
        let mut msg: Message = serde_json::from_value(v)?;

        msg.decode(opts);

        Ok(msg)
    }

    /// Encode the message ready to be sent in the body of a HTTP request.
    ///
    /// If the cipher is set, then use it to encrypt the message.
    pub fn encode(&mut self, format: &Format, cipher: Option<&CipherParams>) -> Result<()> {
        match &self.data {
            Data::String(data) => {
                if let Some(cipher) = cipher {
                    let data = data.as_bytes();
                    self.data = cipher.encrypt(data)?.into();
                    self.encoding.push("utf-8");
                    self.encoding.push(cipher.encoding());
                }
            }
            Data::Binary(data) => {
                if let Some(cipher) = cipher {
                    self.data = cipher.encrypt(data)?.into();
                    self.encoding.push(cipher.encoding());
                }
            }
            Data::JSON(data) => {
                let json_str = serde_json::to_string(data)?;

                if let Some(cipher) = cipher {
                    let data = json_str.as_bytes();
                    self.data = cipher.encrypt(data)?.into();
                    self.encoding.push("json");
                    self.encoding.push("utf-8");
                    self.encoding.push(cipher.encoding());
                } else {
                    self.data = json_str.into();
                    self.encoding.push("json");
                }
            }
            Data::None => (),
        }

        // If we have binary data but JSON format, base64 encode the data.
        if let Data::Binary(data) = &self.data {
            if format.is_json() {
                self.data = base64::encode(data).into();
                self.encoding.push("base64");
            }
        };

        Ok(())
    }
}

impl Decode for Message {
    fn decode(&mut self, opts: Option<&ChannelOptions>) {
        decode(&mut self.data, &mut self.encoding, opts);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceMessage {
    pub action:        PresenceAction,
    pub client_id:     String,
    pub connection_id: String,
    #[serde(skip_serializing_if = "Data::is_none")]
    pub data:          Data,
    #[serde(default, skip_serializing_if = "Encoding::is_none")]
    pub encoding:      Encoding,
}

impl Decode for PresenceMessage {
    fn decode(&mut self, opts: Option<&ChannelOptions>) {
        decode(&mut self.data, &mut self.encoding, opts);
    }
}

pub trait Decode {
    fn decode(&mut self, opts: Option<&ChannelOptions>);
}

/// Iteratively decode the given data based on the given list of encodings.
fn decode(data: &mut Data, encoding: &mut Encoding, opts: Option<&ChannelOptions>) {
    while let Some(enc) = encoding.pop() {
        *data = match decode_once(data, &enc, opts) {
            Ok(data) => data,
            Err(_) => {
                encoding.push(enc);
                return;
            }
        }
    }
}

lazy_static! {
    /// A regular expression to split a data encoding into its format and params.
    static ref ENCODING_RE: Regex =
        Regex::new(r#"^(?P<format>[\-\w]+)(?:\+(?P<params>[\-\w]+))?"#).unwrap();
}

fn decode_once(data: &mut Data, encoding: &str, opts: Option<&ChannelOptions>) -> Result<Data> {
    let caps = ENCODING_RE
        .captures(encoding)
        .ok_or_else(|| error!(40004, "Invalid encoding"))?;
    let format = caps
        .name("format")
        .ok_or_else(|| error!(40004, "Invalid encoding; missing format"))?
        .as_str();

    match format {
        "utf-8" => match data {
            Data::String(s) => Ok(Data::String(s.to_string())),
            Data::Binary(data) => std::str::from_utf8(data)
                .map(Into::into)
                .map_err(Into::into),
            _ => Err(error!(40013, "invalid utf-8 message data")),
        },
        "json" => match data {
            Data::String(s) => serde_json::from_str::<serde_json::Value>(s)
                .map(Into::into)
                .map_err(Into::into),
            _ => Err(error!(40013, "invalid JSON message data")),
        },
        "base64" => match data {
            Data::String(s) => base64::decode(s).map(Into::into).map_err(Into::into),
            _ => Err(error!(40013, "invalid base64 message data")),
        },
        "cipher" => match data {
            Data::Binary(ref mut data) => {
                let opts = opts.ok_or_else(|| error!(
                    40000,
                    "unable to decrypt message, no channel options"
                ))?;
                let cipher = opts
                    .cipher
                    .as_ref()
                    .ok_or_else(|| error!(40000, "unable to decrypt message, no cipher params"))?;
                let params = caps
                    .name("params")
                    .ok_or_else(|| error!(40004, "Invalid encoding; missing params"))?;
                if params.as_str() != cipher.algorithm() {
                    return Err(error!(
                        40000,
                        "unable to decrypt message, incompatible cipher params"
                    ));
                }
                cipher.decrypt(data).map(Into::into)
            }
            _ => Err(error!(40013, "invalid cipher message data")),
        },
        _ => Err(error!(40013, "invalid message encoding")),
    }
}

#[derive(Clone, Debug, Deserialize_repr, PartialEq, Serialize_repr)]
#[serde(untagged)]
#[repr(u8)]
pub enum PresenceAction {
    Absent,
    Present,
    Enter,
    Leave,
    Update,
}

#[derive(Clone, Debug)]
pub enum Format {
    MessagePack,
    JSON,
}

impl Format {
    fn is_json(&self) -> bool {
        match self {
            Self::MessagePack => false,
            Self::JSON => true,
        }
    }
}

pub const DEFAULT_FORMAT: Format = Format::MessagePack;

/// A pagination item handler which decodes each message.
#[derive(Clone)]
pub struct MessageItemHandler {
    opts: Option<ChannelOptions>,
}

impl MessageItemHandler {
    pub fn new(opts: Option<ChannelOptions>) -> Self {
        Self { opts }
    }
}

impl<T: Decode> http::PaginatedItemHandler<T> for MessageItemHandler {
    fn handle(&self, msg: &mut T) {
        msg.decode(self.opts.as_ref());
    }
}

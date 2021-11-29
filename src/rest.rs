use crate::error::*;
use crate::options::ClientOptions;
use crate::{auth, base64, history, http, json, presence, stats, Result};

use aes::{Aes128, Aes256};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use chrono::prelude::*;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::convert::TryFrom;

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
    pub(crate) fn new(http: http::Client, opts: ClientOptions) -> Self {
        let client = Client::new(http.clone(), opts.clone());
        Self {
            auth: auth::Auth::new(http.clone(), opts.clone()),
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

#[derive(Clone, Debug)]
pub struct Client {
    http: http::Client,
    opts: ClientOptions,
}

impl Client {
    pub fn new(http: http::Client, opts: ClientOptions) -> Self {
        Self { http, opts }
    }

    pub fn request(&self, method: http::Method, path: impl Into<String>) -> http::RequestBuilder {
        let mut req = self.http.request(method, path);

        if let Some(ref key) = self.opts.key {
            req = req.basic_auth(&key.name, Some(&key.value))
        } else if let Some(auth::Token::Literal(ref token)) = self.opts.token {
            req = req.bearer_auth(&token)
        }

        req
    }

    pub fn paginated_request<T: http::PaginatedItem, U: http::PaginatedItemHandler<T>>(
        &self,
        method: http::Method,
        path: impl Into<String>,
        handler: Option<U>,
    ) -> http::PaginatedRequestBuilder<T, U> {
        http::PaginatedRequestBuilder::new(self.request(method, path), handler)
    }
}

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

const CIPHER_ALGORITHM: &str = "aes";
const CIPHER_MODE: &str = "cbc";

#[derive(Clone)]
pub struct CipherParams {
    pub key: CipherKey,
}

#[derive(Clone)]
pub enum CipherKey {
    Key128(Vec<u8>),
    Key256(Vec<u8>),
}

impl CipherKey {
    fn len(&self) -> usize {
        match self {
            Self::Key128(key) => key.len(),
            Self::Key256(key) => key.len(),
        }
    }
}

impl TryFrom<Vec<u8>> for CipherKey {
    type Error = ErrorInfo;

    fn try_from(v: Vec<u8>) -> Result<Self> {
        match v.len() {
            16 => Ok(Self::Key128(v)),
            32 => Ok(Self::Key256(v)),
            _ => Err(error!(
                40000,
                format!(
                    "invalid cipher key length {}, must be 128 or 256 bits",
                    v.len()
                )
            )),
        }
    }
}

impl TryFrom<String> for CipherKey {
    type Error = ErrorInfo;

    fn try_from(s: String) -> Result<Self> {
        Self::try_from(base64::decode(s)?)
    }
}

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

    pub fn cipher(mut self, cipher: CipherParams) -> Self {
        self.cipher = Some(cipher);
        self
    }

    pub fn get(self) -> Channel {
        let opts = self.cipher.map(Into::into);
        Channel {
            name:     self.name.clone(),
            presence: Presence::new(self.name.clone(), self.client.clone(), opts.clone()),
            client:   self.client.clone(),
            opts:     opts,
        }
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

    pub fn name(&self, name: impl Into<String>) -> ChannelBuilder {
        ChannelBuilder::new(self.client.clone(), name.into())
    }

    pub fn get(&self, name: impl Into<String>) -> Channel {
        self.name(name).get()
    }
}

pub struct Channel {
    pub name:     String,
    pub presence: Presence,
    client:       Client,
    opts:         Option<ChannelOptions>,
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
    ///
    pub fn history(&self) -> history::PaginatedRequestBuilder<PresenceMessage> {
        self.client.paginated_request(
            http::Method::GET,
            format!("/channels/{}/presence/history", self.name),
            Some(MessageItemHandler::new(self.opts.clone())),
        )
    }
}

pub struct PublishBuilder {
    client:  Client,
    channel: String,
    msg:     Result<Message>,
}

impl PublishBuilder {
    fn new(client: Client, channel: String) -> Self {
        Self {
            client,
            channel,
            msg: Ok(Message::default()),
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.id = Some(id.into());
        }
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.name = Some(name.into());
        }
        self
    }

    pub fn string(mut self, data: impl Into<String>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.data = Data::String(data.into());
        }
        self
    }

    pub fn json(mut self, data: impl serde::Serialize) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            let data = data
                .serialize(serde_json::value::Serializer)
                .map(Into::into)
                .map_err(|err| error!(40013, format!("invalid message data: {}", err)));

            match data {
                Ok(data) => {
                    msg.data = data;
                    msg.encoding = Some(String::from("json"));
                }
                Err(err) => self.msg = Err(err),
            }
        }
        self
    }

    pub fn binary(mut self, data: Vec<u8>) -> Self {
        if let Ok(msg) = self.msg.as_mut() {
            msg.data = data.into();
            msg.encoding = Some(String::from("base64"));
        }
        self
    }

    pub async fn send(self) -> Result<()> {
        let msg = self.msg?;

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
#[derive(Clone, Debug, Deserialize, PartialEq)]
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

impl Serialize for Data {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::String(s) => return s.serialize(serializer),
            Self::JSON(v) => serde_json::to_string(v).map_err(serde::ser::Error::custom)?,
            Self::Binary(v) => base64::encode(v),
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
        Self::Binary(v)
    }
}

impl From<serde_json::Value> for Data {
    fn from(v: serde_json::Value) -> Self {
        Self::JSON(v)
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id:       Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:     Option<String>,
    #[serde(skip_serializing_if = "Data::is_none")]
    pub data:     Data,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

impl Message {
    pub fn from_encoded(v: json::Value, opts: Option<&ChannelOptions>) -> Result<Message> {
        let mut msg: Message = serde_json::from_value(v)?;

        msg.decode(opts);

        Ok(msg)
    }
}

impl Decode for Message {
    fn decode(&mut self, opts: Option<&ChannelOptions>) -> () {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding:      Option<String>,
}

impl Decode for PresenceMessage {
    fn decode(&mut self, opts: Option<&ChannelOptions>) -> () {
        decode(&mut self.data, &mut self.encoding, opts);
    }
}

pub trait Decode {
    fn decode(&mut self, opts: Option<&ChannelOptions>) -> ();
}

fn decode(data: &mut Data, encoding_opt: &mut Option<String>, opts: Option<&ChannelOptions>) -> () {
    let encoding = match encoding_opt.take() {
        Some(enc) => enc,
        None => return (),
    };

    let mut encodings = encoding.split('/').collect::<Vec<&str>>();

    while let Some(enc) = encodings.pop() {
        *data = match decode_once(data, &enc, opts) {
            Ok(data) => data,
            Err(_) => {
                encodings.push(enc);
                *encoding_opt = Some(encodings.join("/"));
                return ();
            }
        }
    }
}

lazy_static! {
    static ref ENCODING_RE: Regex =
        Regex::new(r#"^(?P<format>[\-\w]+)(?:\+(?P<params>[\-\w]+))?"#).unwrap();
}

fn decode_once(data: &mut Data, encoding: &str, opts: Option<&ChannelOptions>) -> Result<Data> {
    let caps = ENCODING_RE
        .captures(encoding)
        .ok_or(error!(40004, "Invalid encoding"))?;
    let format = caps
        .name("format")
        .ok_or(error!(40004, "Invalid encoding; missing format"))?
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
                let opts = opts.ok_or(error!(
                    40000,
                    "unable to decrypt message, no channel options"
                ))?;
                let cipher = opts
                    .cipher
                    .as_ref()
                    .ok_or(error!(40000, "unable to decrypt message, no cipher params"))?;
                let params = caps
                    .name("params")
                    .ok_or(error!(40004, "Invalid encoding; missing params"))?;
                if params.as_str().to_string()
                    != format!(
                        "{}-{}-{}",
                        CIPHER_ALGORITHM,
                        cipher.key.len() * 8,
                        CIPHER_MODE
                    )
                {
                    return Err(error!(
                        40000,
                        "unable to decrypt message, incompatible cipher params"
                    ));
                }
                decrypt(data, &cipher.key)
            }
            _ => Err(error!(40013, "invalid cipher message data")),
        },
        _ => Err(error!(40013, "invalid message encoding")),
    }
}

fn decrypt(data: &mut Vec<u8>, key: &CipherKey) -> Result<Data> {
    if data.len() % aes::BLOCK_SIZE != 0 || data.len() < aes::BLOCK_SIZE {
        return Err(error!(
            40013,
            format!(
                "invalid cipher message data; unexpected length: {}",
                data.len()
            )
        ));
    }
    let iv = &data[..aes::BLOCK_SIZE];
    let decrypted = match key {
        CipherKey::Key128(key) => {
            let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv)?;
            cipher.decrypt(&mut data[aes::BLOCK_SIZE..])?
        }
        CipherKey::Key256(key) => {
            let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(key, iv)?;
            cipher.decrypt(&mut data[aes::BLOCK_SIZE..])?
        }
    };
    Ok(Data::Binary(decrypted.to_vec()))
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

pub const DEFAULT_FORMAT: Format = Format::MessagePack;

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
    fn handle(&self, msg: &mut T) -> () {
        msg.decode(self.opts.as_ref());
    }
}

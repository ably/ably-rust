use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin;

use crate::error::ErrorInfo;
use crate::http;
use crate::Result;
use chrono::prelude::*;
use hmac::{Hmac, Mac, NewMac};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// An enum representing either an API key or a token.
#[derive(Clone, Debug, PartialEq)]
pub enum Credential {
    Key(Key),
    Token(String),
}

impl Credential {
    pub fn is_key(&self) -> bool {
        match self {
            Self::Key(_) => true,
            _ => false,
        }
    }

    pub fn is_token(&self) -> bool {
        match self {
            Self::Token(_) => true,
            _ => false,
        }
    }

    /// Returns the API key if the credential is a Credential::Key
    pub fn key(&self) -> Option<Key> {
        match self {
            Self::Key(key) => Some(key.clone()),
            _ => None,
        }
    }
}

/// An API Key used to authenticate with the REST API using HTTP Basic Auth.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Key {
    #[serde(rename(deserialize = "keyName"))]
    pub name:  String,
    pub value: String,
}

impl TryFrom<&str> for Key {
    type Error = ErrorInfo;

    /// Parse an API Key from a string of the form '<keyName>:<keySecret>'.
    fn try_from(s: &str) -> Result<Self> {
        if let [name, value] = s.splitn(2, ':').collect::<Vec<&str>>()[..] {
            Ok(Key {
                name:  name.to_string(),
                value: value.to_string(),
            })
        } else {
            Err(error!(40000, "Invalid key"))
        }
    }
}

impl Key {
    async fn sign(&self, params: TokenParams) -> Result<TokenResponse> {
        let req = params.sign(self)?;

        Ok(TokenResponse::Request(req))
    }
}

impl TokenProvider for Key {
    fn provide_token<'a>(&'a self, params: TokenParams) -> TokenProviderFuture<'a> {
        Box::pin(self.sign(params))
    }
}

/// Provides functions relating to Ably API authentication.
#[derive(Clone, Debug)]
pub struct Auth {
    pub credential: Credential,
    client:         http::Client,
}

impl Auth {
    pub fn new(credential: Credential, client: http::Client) -> Auth {
        Auth { credential, client }
    }

    /// Start building a TokenRequest to be signed by a local API key.
    pub fn create_token_request(&self) -> CreateTokenRequestBuilder {
        let mut builder = CreateTokenRequestBuilder::new();

        if let Some(key) = self.credential.key() {
            builder = builder.key(key);
        }

        builder
    }

    /// Start building a request for a token.
    pub fn request_token(&self) -> RequestTokenBuilder {
        let mut builder = RequestTokenBuilder::new(self.client.clone());

        if let Some(key) = self.credential.key() {
            builder = builder.key(key);
        }

        builder
    }

    /// Generate a random 16 character nonce to use in a TokenRequest.
    fn generate_nonce() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect()
    }

    /// Use the given API key to compute the HMAC of the canonicalised
    /// representation of the given TokenRequest.
    ///
    /// See the [REST API Token Request Spec] for further details.
    ///
    /// [REST API Token Request Spec]: https://docs.ably.io/rest-api/token-request-spec/
    fn compute_mac(key: &Key, req: &TokenRequest) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.value.as_bytes())?;

        mac.update(key.name.as_bytes());
        mac.update(b"\n");

        mac.update(
            req.ttl
                .map(|t| t.to_string())
                .unwrap_or(String::from(""))
                .as_bytes(),
        );
        mac.update(b"\n");

        mac.update(
            req.capability
                .as_ref()
                .unwrap_or(&String::from(""))
                .as_bytes(),
        );
        mac.update(b"\n");

        mac.update(
            req.client_id
                .as_ref()
                .unwrap_or(&String::from(""))
                .as_bytes(),
        );
        mac.update(b"\n");

        let timestamp_ms =
            req.timestamp.timestamp() * 1000 + req.timestamp.timestamp_subsec_millis() as i64;
        mac.update(timestamp_ms.to_string().as_bytes());
        mac.update(b"\n");

        mac.update(req.nonce.as_bytes());
        mac.update(b"\n");

        Ok(base64::encode(mac.finalize().into_bytes()))
    }
}

/// A builder to create a signed TokenRequest.
pub struct CreateTokenRequestBuilder {
    key:    Option<Key>,
    params: TokenParams,
}

impl CreateTokenRequestBuilder {
    fn new() -> CreateTokenRequestBuilder {
        CreateTokenRequestBuilder {
            key:    None,
            params: TokenParams::default(),
        }
    }

    /// Set the key to use to sign the TokenRequest.
    pub fn key(mut self, key: Key) -> CreateTokenRequestBuilder {
        self.key = Some(key);
        self
    }

    /// Set the desired capability.
    pub fn capability(mut self, capability: &str) -> CreateTokenRequestBuilder {
        self.params.capability = Some(capability.to_string());
        self
    }

    /// Set the desired client_id.
    pub fn client_id(mut self, client_id: &str) -> CreateTokenRequestBuilder {
        self.params.client_id = Some(client_id.to_string());
        self
    }

    /// Set the desired TTL.
    pub fn ttl(mut self, ttl: i64) -> CreateTokenRequestBuilder {
        self.params.ttl = Some(ttl);
        self
    }

    /// Sign and return the TokenRequest.
    pub fn sign(self) -> Result<TokenRequest> {
        let key = self.key.as_ref().ok_or(error!(
            40106,
            "API key is required to create signed token requests"
        ))?;
        self.params.sign(key)
    }
}

/// A builder to request a token.
pub struct RequestTokenBuilder {
    client:   http::Client,
    provider: Option<Box<dyn TokenProvider>>,
    params:   TokenParams,
}

impl RequestTokenBuilder {
    fn new(client: http::Client) -> RequestTokenBuilder {
        RequestTokenBuilder {
            client,
            provider: None,
            params: TokenParams::default(),
        }
    }

    /// Use a key as the TokenProvider.
    pub fn key(self, key: Key) -> RequestTokenBuilder {
        self.provider(key)
    }

    /// Use a URL as the TokenProvider.
    pub fn auth_url(self, url: reqwest::Url) -> RequestTokenBuilder {
        let provider = UrlTokenProvider::new(self.client.clone(), url);
        self.provider(provider)
    }

    /// Use a custom TokenProvider.
    pub fn provider(mut self, provider: impl TokenProvider + 'static) -> RequestTokenBuilder {
        self.provider = Some(Box::new(provider));
        self
    }

    /// Set the desired capability.
    pub fn capability(mut self, capability: &str) -> RequestTokenBuilder {
        self.params.capability = Some(capability.to_string());
        self
    }

    /// Set the desired client_id.
    pub fn client_id(mut self, client_id: &str) -> RequestTokenBuilder {
        self.params.client_id = Some(client_id.to_string());
        self
    }

    /// Set the desired TTL.
    pub fn ttl(mut self, ttl: i64) -> RequestTokenBuilder {
        self.params.ttl = Some(ttl);
        self
    }

    /// Request a response from the configured TokenProvider.
    ///
    /// If the response is a TokenRequest, exchange it for a token.
    pub async fn send(self) -> Result<TokenDetails> {
        let provider = self
            .provider
            .as_ref()
            .ok_or(error!(40171, "no means provided to renew auth token"))?;

        // The provider may either:
        // - return a TokenRequest which we'll exchange for a TokenDetails
        // - return a token string which we'll wrap in a TokenDetails
        // - return a TokenDetails which we'll just return as is
        match provider.provide_token(self.params.clone()).await? {
            TokenResponse::Request(req) => self.exchange(&req).await,
            TokenResponse::Token(token) => Ok(TokenDetails::from(token)),
            TokenResponse::Details(details) => Ok(details),
        }
    }

    /// Exchange a TokenRequest for a token by making a HTTP request to the
    /// [requestToken endpoint] in the Ably REST API.
    ///
    /// [requestToken endpoint]: https://docs.ably.io/rest-api/#request-token
    async fn exchange(&self, req: &TokenRequest) -> Result<TokenDetails> {
        self.client
            .request(
                http::Method::POST,
                format!("/keys/{}/requestToken", req.key_name),
            )
            .body(req)
            .send()
            .await?
            .json()
            .await
            .map_err(Into::into)
    }
}

/// A TokenProvider which requests tokens from a URL.
pub struct UrlTokenProvider {
    client: http::Client,
    url:    reqwest::Url,
}

impl UrlTokenProvider {
    fn new(client: http::Client, url: reqwest::Url) -> UrlTokenProvider {
        UrlTokenProvider { client, url }
    }

    /// Request a token from the URL.
    async fn request(&self, _params: TokenParams) -> Result<TokenResponse> {
        let res = self
            .client
            .request_url(http::Method::GET, self.url.clone())
            .send()
            .await?;

        // Parse the token response based on the Content-Type header.
        let content_type = res.content_type().ok_or(error!(
            40170,
            "authUrl response is missing a content-type header"
        ))?;
        match content_type.essence_str() {
            "application/json" => {
                // Expect a JSON encoded TokenRequest or TokenDetails, and just
                // let serde figure out which TokenResponse variant to decode
                // the JSON response into.
                res.json().await
            },

            "text/plain" | "application/jwt" => {
                // Expect a literal token string.
                let token = res.text().await?;
                Ok(TokenResponse::Token(token))
            },

            // Anything else is an error.
            _ => Err(error!(40170, format!("authUrl responded with unacceptable content-type {}, should be either text/plain, application/jwt or application/json", content_type))),
        }
    }
}

impl TokenProvider for UrlTokenProvider {
    fn provide_token<'a>(&'a self, params: TokenParams) -> TokenProviderFuture<'a> {
        Box::pin(self.request(params))
    }
}

/// An Ably [TokenParams] object.
///
/// [TokenParams]: https://docs.ably.io/realtime/types/#token-params
#[derive(Clone, Default)]
pub struct TokenParams {
    pub capability: Option<String>,
    pub client_id:  Option<String>,
    pub nonce:      Option<String>,
    pub timestamp:  Option<DateTime<Utc>>,
    pub ttl:        Option<i64>,
}

impl TokenParams {
    /// Generate a signed TokenRequest for these TokenParams using the steps
    /// described in the [REST API Token Request Spec].
    ///
    /// [REST API Token Request Spec]: https://ably.com/documentation/rest-api/token-request-spec
    pub fn sign(self, key: &Key) -> Result<TokenRequest> {
        // if client_id is set, it must be a non-empty string
        if let Some(ref client_id) = self.client_id {
            if client_id.is_empty() {
                return Err(error!(40012, "client_id can’t be an empty string"));
            }
        }

        let mut req = TokenRequest {
            key_name:   key.name.clone(),
            timestamp:  self.timestamp.unwrap_or_else(Utc::now),
            capability: self.capability,
            client_id:  self.client_id,
            nonce:      self.nonce.unwrap_or_else(Auth::generate_nonce),
            ttl:        self.ttl,
            mac:        None,
        };

        req.mac = Some(Auth::compute_mac(key, &req)?);

        Ok(req)
    }
}

/// An Ably [TokenRequest] object.
///
/// [TokenRequest]: https://docs.ably.io/realtime/types/#token-request
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    pub key_name:   String,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp:  DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac:        Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub nonce:      String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl:        Option<i64>,
}

/// The token details returned in a successful response from the [REST
/// requestToken endpoint].
///
/// [REST requestToken endpoint]: https://docs.ably.io/rest-api/#request-token
#[derive(Default, Deserialize)]
pub struct TokenDetails {
    pub token:      String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "chrono::serde::ts_milliseconds_option")]
    pub expires:    Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "chrono::serde::ts_milliseconds_option")]
    pub issued:     Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id:  Option<String>,
}

impl From<String> for TokenDetails {
    fn from(token: String) -> Self {
        TokenDetails {
            token,
            ..Default::default()
        }
    }
}

/// A future returned from a TokenProvider which resolves to a TokenResponse.
pub type TokenProviderFuture<'a> = Pin<Box<dyn Future<Output = Result<TokenResponse>> + Send + 'a>>;

/// A TokenProvider is used to provide a TokenResponse during a call to
/// auth::request_token.
pub trait TokenProvider {
    fn provide_token<'a>(&'a self, params: TokenParams) -> TokenProviderFuture<'a>;
}

/// A response from requesting a token from a TokenProvider.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum TokenResponse {
    Request(TokenRequest),
    Details(TokenDetails),
    Token(String),
}

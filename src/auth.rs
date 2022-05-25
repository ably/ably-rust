use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::ErrorInfo;
use crate::rest::RestInner;
use crate::{http, rest, Result};

/// The maximum length of a valid token. Tokens with a length longer than this
/// are rejected with a 40170 error code.
const MAX_TOKEN_LENGTH: usize = 128 * 1024;

mod duration {
    use std::fmt;

    use super::*;
    use serde::{de, Deserializer, Serializer};

    #[derive(Debug)]
    pub struct MilliSecondsTimestampVisitor;

    impl<'de> de::Visitor<'de> for MilliSecondsTimestampVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a duration in milliseconds")
        }

        /// Deserialize a timestamp in milliseconds since the epoch
        fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Duration::milliseconds(value))
        }
    }

    pub fn deserialize<'de, D>(d: D) -> std::result::Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        d.deserialize_u64(MilliSecondsTimestampVisitor)
    }

    pub fn serialize<S>(d: &Duration, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let n = d.num_milliseconds();
        serializer.serialize_i64(n)
    }
}

#[derive(Clone)]
pub enum TokenSource {
    TokenDetails(TokenDetails),
    TokenRequest(TokenRequest),
    Callback(Arc<dyn AuthCallback>),
    Key(Key),
    Url(reqwest::Url),
}

impl std::fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenDetails(arg0) => f.debug_tuple("TokenDetails").field(arg0).finish(),
            Self::TokenRequest(arg0) => f.debug_tuple("TokenRequest").field(arg0).finish(),
            Self::Key(arg0) => f.debug_tuple("Key").field(arg0).finish(),
            Self::Callback(_) => f.debug_tuple("Callback").field(&"Fn").finish(),
            Self::Url(arg0) => f.debug_tuple("Url").field(arg0).finish(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuthOptions {
    pub token: Option<TokenSource>,
    pub headers: Option<http::HeaderMap>,
    pub method: http::Method,
    pub params: Option<http::UrlQuery>,
}

/// An API Key used to authenticate with the REST API using HTTP Basic Auth.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Key {
    #[serde(rename(deserialize = "keyName"))]
    pub name: String,
    pub value: String,
}

impl Key {
    pub fn new(s: &str) -> Result<Self> {
        if let [name, value] = s.splitn(2, ':').collect::<Vec<&str>>()[..] {
            Ok(Key {
                name: name.to_string(),
                value: value.to_string(),
            })
        } else {
            Err(error!(40000, "Invalid key"))
        }
    }
}

impl TryFrom<&str> for Key {
    type Error = ErrorInfo;

    /// Parse an API Key from a string of the form '<keyName>:<keySecret>'.
    ///
    /// # Example
    ///
    /// ```
    /// use std::convert::TryFrom;
    /// use ably::auth;
    ///
    /// let res = auth::Key::try_from("ABC123.DEF456:XXXXXXXXXXXX");
    /// assert!(res.is_ok());
    ///
    /// let res = auth::Key::try_from("not-a-valid-key");
    /// assert!(res.is_err());
    /// ```
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl Key {
    /// Use the API key to sign the given TokenParams, returning a signed
    /// TokenRequest which can be exchanged for a token.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> ably::Result<()> {
    /// use std::convert::TryFrom;
    /// use ably::auth;
    ///
    /// let key = auth::Key::try_from("ABC123.DEF456:XXXXXXXXXXXX").unwrap();
    ///
    /// let mut params = auth::TokenParams::default();
    /// params.client_id = Some("test@example.com".to_string());
    ///
    /// let req = key.sign(&params).unwrap();
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign(&self, params: &TokenParams) -> Result<TokenRequest> {
        params.sign(self)
    }
}

/// Provides functions relating to Ably API authentication.
#[derive(Clone, Debug)]
pub struct Auth<'a> {
    pub(crate) rest: &'a rest::Rest,
}

impl<'a> Auth<'a> {
    pub fn new(rest: &'a rest::Rest) -> Self {
        Self { rest }
    }

    fn inner(&self) -> &RestInner {
        &self.rest.inner
    }

    /// Start building a TokenRequest to be signed by a local API key.
    pub fn create_token_request(
        &self,
        params: &TokenParams,
        options: &AuthOptions,
    ) -> Result<TokenRequest> {
        let key = match &options.token {
            Some(TokenSource::Key(k)) => k,
            _ => {
                return Err(error!(
                    40106,
                    "API key is required to create signed token requests"
                ))
            }
        };
        params.sign(key)
    }

    /// Exchange a TokenRequest for a token by making a HTTP request to the
    /// [requestToken endpoint] in the Ably REST API.
    ///
    /// Returns a boxed future rather than using async since this is both
    /// called from and calls out to RequestBuilder.send, and recursive
    /// async functions are not supported.
    ///
    /// [requestToken endpoint]: https://docs.ably.io/rest-api/#request-token
    pub(crate) fn exchange(
        &self,
        req: &TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenDetails>> + Send + 'a>> {
        let req = self
            .rest
            .request(
                http::Method::POST,
                &format!("/keys/{}/requestToken", req.key_name),
            )
            .authenticate(false)
            .body(req);

        Box::pin(async move { req.send().await?.body().await.map_err(Into::into) })
    }

    /// Request a token from the URL.
    fn request_url<'b>(
        &'b self,
        url: &'b reqwest::Url,
    ) -> Pin<Box<dyn Future<Output = Result<TokenDetails>> + Send + 'b>> {
        let fut = async move {
            let res = self
                .rest
                .request_url(Default::default(), url.clone())
                .authenticate(false)
                .send()
                .await?;

            // Parse the token response based on the Content-Type header.
            let content_type = res.content_type().ok_or_else(|| {
                error!(40170, "authUrl response is missing a content-type header")
            })?;
            match content_type.essence_str() {
            "application/json" => {
                // Expect a JSON encoded TokenRequest or TokenDetails, and just
                // let serde figure out which Token variant to decode the JSON
                // response into.
                let token: RequestOrDetails = res.json().await?;
                match token {
                    RequestOrDetails::Request(r) => self.exchange(&r).await,
                    RequestOrDetails::Details(d) => Ok(d),
                }
            },

            "text/plain" | "application/jwt" => {
                // Expect a literal token string.
                let token = res.text().await?;
                Ok(TokenDetails::from(token))
            },

            // Anything else is an error.
            _ => Err(error!(40170, format!("authUrl responded with unacceptable content-type {}, should be either text/plain, application/jwt or application/json", content_type))),
        }
        };

        Box::pin(fut)
    }

    pub async fn request_token(
        &self,
        params: &TokenParams,
        options: &AuthOptions,
    ) -> Result<TokenDetails> {
        let token = options
            .token
            .as_ref()
            .ok_or_else(|| error!(40171, "no means provided to renew auth token"))?;

        let mut details = match token {
            TokenSource::TokenDetails(token) => Ok(token.clone()),
            TokenSource::TokenRequest(r) => self.exchange(r).await,
            TokenSource::Callback(f) => match f.token(params).await {
                Ok(token) => token.into_details(self).await,
                Err(e) => Err(e),
            },
            TokenSource::Key(k) => self.exchange(&params.sign(k)?).await,
            TokenSource::Url(url) => self.request_url(url).await,
        };

        if matches!(token, TokenSource::Callback(_) | TokenSource::Url(_)) {
            if let Err(ref mut err) = details {
                // Normalise auth error according to RSA4e.
                if err.code == 40000 {
                    err.code = 40170;
                    err.status_code = Some(401);
                }
            };
        }

        let details = details?;

        // Reject tokens with size greater than 128KiB (RSA4f).
        if details.token.len() > MAX_TOKEN_LENGTH {
            return Err(error!(
                40170,
                format!(
                    "Token string exceeded max permitted length (was {} bytes)",
                    details.token.len()
                ),
                401
            ));
        }

        Ok(details)
    }

    /// Set the Authorization header in the given request.
    pub(crate) async fn with_auth_headers(&self, req: &mut reqwest::Request) -> Result<()> {
        if let TokenSource::Key(k) = &self.inner().opts.token {
            return Self::set_basic_auth(req, k);
        }

        let options = AuthOptions {
            token: Some(self.inner().opts.token.clone()),
            ..Default::default()
        };

        // TODO defaults
        let res = self.request_token(&Default::default(), &options).await?;
        Self::set_bearer_auth(req, &res.token)
    }

    fn set_bearer_auth(req: &mut reqwest::Request, token: &str) -> Result<()> {
        Self::set_header(
            req,
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token),
        )
    }

    fn set_basic_auth(req: &mut reqwest::Request, key: &Key) -> Result<()> {
        let encoded = base64::encode(format!("{}:{}", key.name, key.value));
        Self::set_header(
            req,
            reqwest::header::AUTHORIZATION,
            format!("Basic {}", encoded),
        )
    }

    fn set_header(req: &mut reqwest::Request, key: http::HeaderName, value: String) -> Result<()> {
        req.headers_mut().append(key, value.parse()?);
        Ok(())
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
    fn compute_mac(
        key: &Key,
        ttl: Duration,
        capability: &str,
        client_id: Option<&str>,
        timestamp: DateTime<Utc>,
        nonce: &str,
    ) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.value.as_bytes())?;

        mac.update(key.name.as_bytes());
        mac.update(b"\n");

        mac.update(ttl.num_milliseconds().to_string().as_bytes());
        mac.update(b"\n");

        mac.update(capability.as_bytes());
        mac.update(b"\n");

        mac.update(client_id.map(|c| c.as_bytes()).unwrap_or_default());
        mac.update(b"\n");

        mac.update(timestamp.timestamp_millis().to_string().as_bytes());
        mac.update(b"\n");

        mac.update(nonce.as_bytes());
        mac.update(b"\n");

        Ok(base64::encode(mac.finalize().into_bytes()))
    }
}

/// An Ably [TokenParams] object.
///
/// [TokenParams]: https://docs.ably.io/realtime/types/#token-params
#[derive(Clone, Debug)]
pub struct TokenParams {
    pub capability: String,
    pub client_id: Option<String>,
    pub nonce: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub ttl: Duration,
}

impl Default for TokenParams {
    fn default() -> Self {
        Self {
            capability: "{\"*\":[\"*\"]}".to_string(),
            client_id: Default::default(),
            nonce: Default::default(),
            timestamp: Default::default(),
            ttl: Duration::minutes(60),
        }
    }
}

impl TokenParams {
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the desired capability.
    pub fn capability(mut self, capability: &str) -> Self {
        self.capability = capability.to_string();
        self
    }

    /// Set the desired client_id.
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self
    }

    /// Set the desired TTL.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set the timestamp.
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Generate a signed TokenRequest for these TokenParams using the steps
    /// described in the [REST API Token Request Spec].
    ///
    /// [REST API Token Request Spec]: https://ably.com/documentation/rest-api/token-request-spec
    fn sign(&self, key: &Key) -> Result<TokenRequest> {
        // if client_id is set, it must be a non-empty string
        if let Some(ref client_id) = self.client_id {
            if client_id.is_empty() {
                return Err(error!(40012, "client_id can’t be an empty string"));
            }
        }

        let nonce = self.nonce.clone().unwrap_or_else(Auth::generate_nonce);
        let timestamp = self.timestamp.unwrap_or_else(Utc::now);
        let key_name = key.name.clone();

        let req = TokenRequest {
            mac: Auth::compute_mac(
                key,
                self.ttl,
                &self.capability,
                self.client_id.as_deref(),
                timestamp,
                &nonce,
            )?,
            key_name,
            timestamp,
            capability: self.capability.clone(),
            client_id: self.client_id.clone(),
            nonce,
            ttl: self.ttl,
        };

        Ok(req)
    }
}

/// An Ably [TokenRequest] object.
///
/// [TokenRequest]: https://docs.ably.io/realtime/types/#token-request
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    pub key_name: String,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    pub capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub mac: String,
    pub nonce: String,
    #[serde(with = "duration")]
    pub ttl: Duration,
}

/// The token details returned in a successful response from the [REST
/// requestToken endpoint].
///
/// [REST requestToken endpoint]: https://docs.ably.io/rest-api/#request-token
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenDetails {
    pub token: String,
    #[serde(flatten)]
    pub metadata: Option<TokenMetadata>,
}

impl TokenDetails {
    pub fn token(s: String) -> Self {
        Self {
            token: s,
            metadata: None,
        }
    }
}

impl From<String> for TokenDetails {
    fn from(token: String) -> Self {
        TokenDetails {
            token,
            metadata: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenMetadata {
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub expires: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub issued: DateTime<Utc>,
    pub capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum RequestOrDetails {
    Request(TokenRequest),
    Details(TokenDetails),
}

impl RequestOrDetails {
    async fn into_details(self, auth: &Auth<'_>) -> Result<TokenDetails> {
        match self {
            RequestOrDetails::Request(r) => auth.exchange(&r).await,
            RequestOrDetails::Details(d) => Ok(d),
        }
    }
}

pub trait AuthCallback: Send + Sync {
    fn token<'a>(
        &'a self,
        params: &'a TokenParams,
    ) -> Pin<Box<dyn Send + Future<Output = Result<RequestOrDetails>> + 'a>>;
}

use std::convert::TryFrom;

use crate::error::ErrorInfo;
use crate::Result;
use chrono::prelude::*;
use hmac::{Hmac, Mac, NewMac};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use sha2::Sha256;

/// An enum representing either an API key or a token.
#[derive(Clone, Debug, PartialEq)]
pub enum Credential {
    Key(Key),
    Token(String),
}

impl Credential {
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

/// Provides functions relating to Ably API authentication.
#[derive(Clone, Debug)]
pub struct Auth {
    key: Option<Key>,
}

impl Auth {
    pub fn new(key: Option<Key>) -> Auth {
        Auth { key }
    }

    /// Start building a TokenRequest to be signed by a local API key.
    pub fn create_token_request(&self) -> CreateTokenRequestBuilder {
        let mut builder = CreateTokenRequestBuilder::new();

        if let Some(ref key) = self.key {
            builder = builder.key(key.clone());
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
        let key = self.key.ok_or(error!(
            40106,
            "API key is required to create signed token requests"
        ))?;
        self.params.sign(key)
    }
}

/// An Ably [TokenParams] object.
///
/// [TokenParams]: https://docs.ably.io/realtime/types/#token-params
#[derive(Default)]
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
    pub fn sign(self, key: Key) -> Result<TokenRequest> {
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

        req.mac = Some(Auth::compute_mac(&key, &req)?);

        Ok(req)
    }
}

/// An Ably [TokenRequest] object.
///
/// [TokenRequest]: https://docs.ably.io/realtime/types/#token-request
pub struct TokenRequest {
    pub key_name:   String,
    pub timestamp:  DateTime<Utc>,
    pub capability: Option<String>,
    pub client_id:  Option<String>,
    pub mac:        Option<String>,
    pub nonce:      String,
    pub ttl:        Option<i64>,
}

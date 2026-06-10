use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ErrorInfo, Result};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Key {
    #[serde(rename = "keyName")]
    pub name: String,
    pub value: String,
}

impl Key {
    pub fn new(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Invalid key",
            ));
        }
        Ok(Self {
            name: parts[0].to_string(),
            value: parts[1].to_string(),
        })
    }

    pub fn sign(&self, params: &TokenParams) -> Result<TokenRequest> {
        let timestamp = params.timestamp
            .map(|t| t.timestamp_millis())
            .unwrap_or_else(|| Utc::now().timestamp_millis());

        let ttl = params.ttl.unwrap_or(3600000); // 1 hour default
        let capability = params.capability.as_deref().unwrap_or(r#"{"*":["*"]}"#);
        let client_id = params.client_id.as_deref().unwrap_or("");

        // Generate nonce
        let mut nonce_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = base64::encode(&nonce_bytes);

        // Build the string to sign
        let sign_text = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n",
            self.name,
            ttl,
            capability,
            client_id,
            timestamp,
            nonce,
        );

        // HMAC-SHA256
        let mut mac = HmacSha256::new_from_slice(self.value.as_bytes())?;
        mac.update(sign_text.as_bytes());
        let result = mac.finalize();
        let mac_bytes = result.into_bytes();
        let mac_b64 = base64::encode(&mac_bytes);

        Ok(TokenRequest {
            key_name: self.name.clone(),
            ttl: Some(ttl),
            capability: Some(capability.to_string()),
            client_id: if client_id.is_empty() { None } else { Some(client_id.to_string()) },
            timestamp: Some(timestamp),
            nonce,
            mac: mac_b64,
        })
    }
}

impl TryFrom<&str> for Key {
    type Error = ErrorInfo;
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, self.value)
    }
}

pub struct Auth<'a> {
    pub(crate) rest: &'a crate::rest::Rest,
}

impl<'a> Auth<'a> {
    pub(crate) fn new(rest: &'a crate::rest::Rest) -> Self {
        Self { rest }
    }

    pub fn token_details(&self) -> Option<TokenDetails> {
        let state = self.rest.inner.auth_state.lock().unwrap();
        state.cached_token.clone()
    }

    pub fn create_token_request(
        &self,
        params: &TokenParams,
        _options: &AuthOptions,
    ) -> Result<TokenRequest> {
        let key = match &self.rest.inner.opts.credential {
            Credential::Key(k) => k,
            _ => {
                return Err(ErrorInfo::new(
                    ErrorCode::InvalidCredential.code(),
                    "API key required to create token request",
                ));
            }
        };

        key.sign(params)
    }

    pub async fn request_token(
        &self,
        params: &TokenParams,
        _options: &AuthOptions,
    ) -> Result<TokenDetails> {
        let td = self.rest.obtain_token(params, &AuthOptions::default()).await?;
        // Cache the token
        {
            let mut state = self.rest.inner.auth_state.lock().unwrap();
            state.cached_token = Some(td.clone());
        }
        Ok(td)
    }

    pub async fn authorize(
        &self,
        params: &TokenParams,
        options: &AuthOptions,
    ) -> Result<TokenDetails> {
        // Merge with saved params: if new params have values, use them; otherwise use saved
        let mut effective_params = {
            let mut state = self.rest.inner.auth_state.lock().unwrap();
            let effective = if let Some(saved) = &state.saved_token_params {
                TokenParams {
                    ttl: params.ttl.or(saved.ttl),
                    capability: params.capability.clone().or_else(|| saved.capability.clone()),
                    client_id: params.client_id.clone().or_else(|| saved.client_id.clone()),
                    timestamp: params.timestamp.or(saved.timestamp),
                    nonce: params.nonce.clone().or_else(|| saved.nonce.clone()),
                }
            } else {
                params.clone()
            };
            state.saved_token_params = Some(effective.clone());
            effective
        };
        // RSA10k: authorize queries server time for key-based auth
        if effective_params.timestamp.is_none() {
            if let Credential::Key(_) = &self.rest.inner.opts.credential {
                if let Ok(server_time) = self.rest.time().await {
                    effective_params.timestamp = Some(server_time);
                }
            }
        }
        self.request_token(&effective_params, options).await
    }

    pub async fn revoke_tokens(
        &self,
        request: &crate::rest::RevokeTokensRequest,
    ) -> Result<crate::rest::RevokeTokensResponse> {
        let key = match &self.rest.inner.opts.credential {
            Credential::Key(k) => k.clone(),
            _ => {
                return Err(ErrorInfo::with_status(
                    ErrorCode::TokenAuthCannotRevokeTokens.code(),
                    401,
                    "API key required to revoke tokens".to_string(),
                ));
            }
        };

        let path = format!("/keys/{}/revokeTokens", key.name);
        let body = self.rest.serialize_body(request)?;
        let resp = self.rest.do_request("POST", &path, &[], &[], Some(body)).await?;
        // With X-Ably-Version >= 3 the server returns a BatchResult envelope
        // {successCount, failureCount, results}; a plain array is the legacy
        // (no version header) format, still accepted for robustness.
        let value: serde_json::Value = self.rest.deserialize_response(&resp)?;
        if value.is_array() {
            let results: Vec<crate::rest::RevokeTokenResult> = serde_json::from_value(value)?;
            let failure_count = results.iter().filter(|r| r.error.is_some()).count() as u32;
            let success_count = results.len() as u32 - failure_count;
            Ok(crate::rest::RevokeTokensResponse {
                success_count,
                failure_count,
                results,
            })
        } else {
            Ok(serde_json::from_value(value)?)
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl TokenParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn capability(mut self, capability: &str) -> Self {
        self.capability = Some(capability.to_string());
        self
    }

    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self
    }

    pub fn ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl = Some(ttl.as_millis() as i64);
        self
    }

    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    pub key_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    pub nonce: String,
    pub mac: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenMetadata {
    pub expires: chrono::DateTime<chrono::Utc>,
    pub issued: chrono::DateTime<chrono::Utc>,
    pub capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenDetails {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TokenMetadata>,
}

impl<'de> serde::Deserialize<'de> for TokenDetails {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            #[serde(default)]
            token: String,
            expires: Option<i64>,
            issued: Option<i64>,
            capability: Option<String>,
            client_id: Option<String>,
            metadata: Option<TokenMetadata>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let mut td = TokenDetails {
            token: raw.token,
            expires: raw.expires,
            issued: raw.issued,
            capability: raw.capability,
            client_id: raw.client_id,
            metadata: raw.metadata,
        };
        td.populate_metadata();
        Ok(td)
    }
}

impl TokenDetails {
    pub fn token(s: String) -> Self {
        Self { token: s, ..Default::default() }
    }

    /// Build metadata from flat fields if metadata is not already set.
    pub fn populate_metadata(&mut self) {
        if self.metadata.is_some() {
            return;
        }
        // Only populate if we have at least expires or issued
        if self.expires.is_some() || self.issued.is_some() {
            let expires = self.expires
                .and_then(|ms| chrono::DateTime::from_timestamp_millis(ms))
                .unwrap_or_else(|| chrono::Utc::now());
            let issued = self.issued
                .and_then(|ms| chrono::DateTime::from_timestamp_millis(ms))
                .unwrap_or_else(|| chrono::Utc::now());
            let capability = self.capability.clone().unwrap_or_default();
            let client_id = self.client_id.clone();
            self.metadata = Some(TokenMetadata {
                expires,
                issued,
                capability,
                client_id,
                connection_id: None,
            });
        }
    }
}

impl From<String> for TokenDetails {
    fn from(s: String) -> Self {
        Self::token(s)
    }
}

#[derive(Clone, Debug)]
pub struct AuthOptions {
    pub token: Option<String>,
    pub headers: Option<Vec<(String, String)>>,
    pub method: Option<String>,
    pub params: Option<Vec<(String, String)>>,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self {
            token: None,
            headers: None,
            // AO2d/TO3j7: authMethod defaults to GET
            method: Some("GET".to_string()),
            params: None,
        }
    }
}

pub enum AuthToken {
    Details(TokenDetails),
    Request(TokenRequest),
}

pub trait AuthCallback: Send + Sync {
    fn token<'a>(
        &'a self,
        params: &'a TokenParams,
    ) -> Pin<Box<dyn Send + Future<Output = Result<AuthToken>> + 'a>>;
}

pub(crate) enum Credential {
    Key(Key),
    TokenDetails(TokenDetails),
    TokenRequest(TokenRequest),
    Callback(Arc<dyn AuthCallback>),
    Url(String),
}

impl Clone for Credential {
    fn clone(&self) -> Self {
        match self {
            Self::Key(k) => Self::Key(k.clone()),
            Self::TokenDetails(t) => Self::TokenDetails(t.clone()),
            Self::TokenRequest(r) => Self::TokenRequest(r.clone()),
            Self::Callback(c) => Self::Callback(c.clone()),
            Self::Url(u) => Self::Url(u.clone()),
        }
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(k) => f.debug_tuple("Key").field(k).finish(),
            Self::TokenDetails(t) => f.debug_tuple("TokenDetails").field(t).finish(),
            Self::TokenRequest(r) => f.debug_tuple("TokenRequest").field(r).finish(),
            Self::Callback(_) => f.debug_tuple("Callback").finish(),
            Self::Url(u) => f.debug_tuple("Url").field(u).finish(),
        }
    }
}

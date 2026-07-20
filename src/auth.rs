use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::http_client::HttpRequest;
use crate::rest::Rest;

#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    #[serde(rename = "keyName")]
    pub name: String,
    pub value: String,
}

impl Key {
    pub fn new(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ErrorInfo::new(ErrorCode::BadRequest.code(), "Invalid key"));
        }
        Ok(Self {
            name: parts[0].to_string(),
            value: parts[1].to_string(),
        })
    }
}

impl TryFrom<&str> for Key {
    type Error = ErrorInfo;
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

// The key secret must not leak into logs or error chains.
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({}:[REDACTED])", self.name)
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:[REDACTED]", self.name)
    }
}

pub struct Auth<'a> {
    pub(crate) rest: &'a crate::rest::Rest,
}

impl<'a> Auth<'a> {
    pub(crate) fn new(rest: &'a crate::rest::Rest) -> Self {
        Self { rest }
    }

    /// RSA10g: the library's current token, if any.
    pub fn token_details(&self) -> Option<TokenDetails> {
        let state = self.rest.inner.auth_state.lock().unwrap();
        state.cached_token.clone()
    }

    /// RSA7/RSA12: the effective clientId — from ClientOptions, or from the
    /// current token (which may be the wildcard "*"). None when unidentified.
    pub fn client_id(&self) -> Option<String> {
        if let Some(cid) = &self.rest.inner.opts.client_id {
            return Some(cid.clone());
        }
        let state = self.rest.inner.auth_state.lock().unwrap();
        state
            .cached_token
            .as_ref()
            .and_then(|td| td.client_id.clone())
    }

    /// RSA9: create a signed TokenRequest. Async because `queryTime` may
    /// require querying the server clock (RSA9d/RSA10k).
    pub async fn create_token_request(
        &self,
        params: Option<&TokenParams>,
        options: Option<&AuthOptions>,
    ) -> Result<TokenRequest> {
        let cfg = self.rest.auth_config_with(options);
        let key = cfg.key.clone().ok_or_else(|| {
            ErrorInfo::new(
                ErrorCode::InvalidCredential.code(),
                "API key required to create token request",
            )
        })?;
        let effective = self.rest.effective_token_params(params);
        let timestamp = self.rest.token_request_timestamp(&effective, &cfg).await?;
        key.sign_with_timestamp(&effective, timestamp)
    }

    /// RSA8e: request a token from Ably. Does NOT change the library's
    /// authentication state (RSA8f / RSA4d1).
    pub async fn request_token(
        &self,
        params: Option<&TokenParams>,
        options: Option<&AuthOptions>,
    ) -> Result<TokenDetails> {
        let cfg = self.rest.auth_config_with(options);
        let effective = self.rest.effective_token_params(params);
        self.rest.acquire_token(&effective, &cfg).await
    }

    /// RSA10: obtain a new token unconditionally and use token auth for all
    /// subsequent requests (RSA10a). Provided params/options replace the
    /// stored ones for future renewals (RSA10g/RSA10h), except `timestamp`,
    /// which is never stored (RSA10g).
    pub async fn authorize(
        &self,
        params: Option<&TokenParams>,
        options: Option<&AuthOptions>,
    ) -> Result<TokenDetails> {
        {
            let mut state = self.rest.inner.auth_state.lock().unwrap();
            if let Some(p) = params {
                let mut saved = p.clone();
                saved.timestamp = None; // RSA10g: timestamp must not be stored
                state.saved_token_params = Some(saved);
            }
            if let Some(o) = options {
                state.saved_auth_options = Some(o.clone());
            }
            state.forced_token_auth = true; // RSA10a
        }
        let cfg = self.rest.auth_config();
        // Use the provided params (incl. any explicit timestamp) for this
        // authorization; fall back to previously-saved params (RSA10e).
        let saved = self
            .rest
            .inner
            .auth_state
            .lock()
            .unwrap()
            .saved_token_params
            .clone();
        let effective = self.rest.effective_token_params(params.or(saved.as_ref()));
        let td = self.rest.acquire_token(&effective, &cfg).await?;
        self.rest.check_client_id_compat(&td)?; // RSA15
        {
            let mut state = self.rest.inner.auth_state.lock().unwrap();
            state.cached_token = Some(td.clone()); // RSA10g
        }
        Ok(td)
    }

    pub async fn revoke_tokens(
        &self,
        request: &crate::rest::RevokeTokensRequest,
    ) -> Result<crate::rest::RevokeTokensResponse> {
        // RSA17d: token-auth clients (including key + useTokenAuth, RSA17d_2)
        // cannot revoke tokens. Client-side check, no HTTP request.
        let key = match &self.rest.inner.opts.credential {
            Credential::Key(k) if !self.rest.inner.opts.use_token_auth => k.clone(),
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
        let resp = self
            .rest
            .do_request("POST", &path, &[], &[], Some(body))
            .await?;
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
        Self {
            token: s,
            ..Default::default()
        }
    }

    /// Whether this token is known to have expired by `now_ms` (RSA4b1).
    /// Tokens with no expiry information are never considered expired locally.
    pub(crate) fn is_expired(&self, now_ms: i64) -> bool {
        matches!(self.expires, Some(expires) if expires <= now_ms)
    }

    /// Build metadata from flat fields if metadata is not already set.
    pub fn populate_metadata(&mut self) {
        if self.metadata.is_some() {
            return;
        }
        // Only populate if we have at least expires or issued
        if self.expires.is_some() || self.issued.is_some() {
            let expires = self
                .expires
                .and_then(chrono::DateTime::from_timestamp_millis)
                .unwrap_or_else(chrono::Utc::now);
            let issued = self
                .issued
                .and_then(chrono::DateTime::from_timestamp_millis)
                .unwrap_or_else(chrono::Utc::now);
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

/// Authentication options (AO2). May be passed per-call to
/// `create_token_request`/`request_token`/`authorize`; options passed to
/// `authorize` are stored and replace the client's auth configuration for
/// subsequent renewals (RSA10h), except the API key, which is preserved
/// (RSA10i).
#[derive(Clone)]
pub struct AuthOptions {
    /// AO2a: API key for signing token requests.
    pub key: Option<String>,
    /// AO2: literal token string.
    pub token: Option<String>,
    /// AO2: literal TokenDetails.
    pub token_details: Option<TokenDetails>,
    /// AO2b: callback to obtain a token.
    pub auth_callback: Option<Arc<dyn AuthCallback>>,
    /// AO2c: URL to fetch a token from.
    pub auth_url: Option<String>,
    /// AO2d: HTTP method for the authUrl request. Defaults to GET.
    pub method: Option<String>,
    /// AO2e: headers sent with the authUrl request.
    pub headers: Option<Vec<(String, String)>>,
    /// AO2f: params merged into the authUrl request (RSA8c1a/RSA8c1b).
    pub params: Option<Vec<(String, String)>>,
    /// AO2g: query the server clock for token request timestamps (RSA9d).
    pub query_time: Option<bool>,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self {
            key: None,
            token: None,
            token_details: None,
            auth_callback: None,
            auth_url: None,
            // AO2d/TO3j7: authMethod defaults to GET
            method: Some("GET".to_string()),
            headers: None,
            params: None,
            query_time: None,
        }
    }
}

impl AuthOptions {
    /// The effective authMethod (AO2d): defaults to GET.
    pub fn effective_method(&self) -> &str {
        self.method.as_deref().unwrap_or("GET")
    }
}

impl std::fmt::Debug for AuthOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthOptions")
            .field("key", &self.key.as_ref().map(|_| "[REDACTED]"))
            .field("token", &self.token)
            .field("token_details", &self.token_details)
            .field(
                "auth_callback",
                &self.auth_callback.as_ref().map(|_| "<callback>"),
            )
            .field("auth_url", &self.auth_url)
            .field("method", &self.method)
            .field("headers", &self.headers)
            .field("params", &self.params)
            .field("query_time", &self.query_time)
            .finish()
    }
}

/// What an auth callback can return (RSA8d): a TokenDetails, a TokenRequest
/// to be exchanged, or a raw token/JWT string.
pub enum AuthToken {
    Details(TokenDetails),
    Request(TokenRequest),
    Token(String),
}

impl From<String> for AuthToken {
    fn from(s: String) -> Self {
        AuthToken::Token(s)
    }
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

/// The resolved authentication configuration for token acquisition: the
/// client's credential overlaid with stored authorize() options (RSA10h)
/// and/or per-call AuthOptions.
pub(crate) struct AuthConfig {
    pub key: Option<Key>,
    pub callback: Option<Arc<dyn AuthCallback>>,
    pub url: Option<String>,
    pub token_request: Option<TokenRequest>,
    pub static_token: Option<TokenDetails>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub params: Vec<(String, String)>,
    pub query_time: bool,
}

impl AuthConfig {
    /// Overlay AuthOptions onto this configuration. When the options carry a
    /// token source, it replaces the existing sources as a set (RSA10h) —
    /// except the API key, which is preserved when the options don't carry
    /// one (RSA10i). Options without any token source (e.g. only queryTime)
    /// leave the existing sources untouched.
    pub(crate) fn apply(&mut self, options: &AuthOptions) {
        let has_source = options.auth_callback.is_some()
            || options.auth_url.is_some()
            || options.key.is_some()
            || options.token.is_some()
            || options.token_details.is_some();
        if has_source {
            self.callback = options.auth_callback.clone();
            self.url = options.auth_url.clone();
            self.token_request = None;
            self.static_token = options
                .token_details
                .clone()
                .or_else(|| options.token.clone().map(TokenDetails::token));
            if let Some(key_str) = &options.key {
                if let Ok(k) = Key::new(key_str) {
                    self.key = Some(k);
                }
            }
        }
        if options.method.is_some() {
            self.method = options.effective_method().to_string();
        }
        if let Some(h) = &options.headers {
            self.headers = h.clone();
        }
        if let Some(p) = &options.params {
            self.params = p.clone();
        }
        if let Some(qt) = options.query_time {
            self.query_time = qt;
        }
    }
}

pub(crate) struct AuthState {
    pub(crate) cached_token: Option<TokenDetails>,
    /// RSA10e/RSA10g: token params saved by authorize() for future renewals.
    pub(crate) saved_token_params: Option<TokenParams>,
    /// RSA10h: auth options saved by authorize(), replacing the client's
    /// auth configuration for future renewals.
    pub(crate) saved_auth_options: Option<AuthOptions>,
    /// RSA10a: once authorize() has been called, token auth is used for all
    /// subsequent requests even on a basic-auth (key) client.
    pub(crate) forced_token_auth: bool,
    /// RSA10k: cached offset between the server clock and the local clock,
    /// captured when queryTime triggers a /time query.
    pub(crate) time_offset_ms: Option<i64>,
}

/// Resolved Authorization header for a request. Basic vs Bearer matters
/// beyond the header value: X-Ably-ClientId is only sent with basic auth
/// (RSA7e2).
#[derive(Clone, Debug)]
pub(crate) enum AuthHeader {
    Basic(String),
    Bearer(String),
}

impl AuthHeader {
    pub(crate) fn value(&self) -> String {
        match self {
            AuthHeader::Basic(v) => format!("Basic {}", v),
            AuthHeader::Bearer(v) => format!("Bearer {}", v),
        }
    }
}

impl Rest {
    /// The local clock adjusted by any cached server-time offset.
    pub(crate) fn adjusted_now_ms(&self) -> i64 {
        let offset = self
            .inner
            .auth_state
            .lock()
            .unwrap()
            .time_offset_ms
            .unwrap_or(0);
        Utc::now().timestamp_millis() + offset
    }

    /// Invalidate the cached library token so the next acquisition renews it
    /// (used by realtime token-error recovery, RTN14b/RTN15h2; called from
    /// spawned connect tasks, never the connection loop).
    pub(crate) fn invalidate_cached_token(&self) {
        self.inner.auth_state.lock().unwrap().cached_token = None;
    }

    /// Resolve the auth configuration: the client's credential plus any
    /// options stored by authorize() (RSA10h).
    pub(crate) fn auth_config(&self) -> AuthConfig {
        let opts = &self.inner.opts;
        let mut cfg = AuthConfig {
            key: None,
            callback: None,
            url: None,
            token_request: None,
            static_token: None,
            method: opts
                .auth_method
                .clone()
                .unwrap_or_else(|| "GET".to_string()),
            headers: opts.auth_headers.clone(),
            params: opts.auth_params.clone(),
            query_time: opts.query_time,
        };
        match &opts.credential {
            Credential::Key(k) => cfg.key = Some(k.clone()),
            Credential::Callback(cb) => cfg.callback = Some(cb.clone()),
            Credential::Url(u) => cfg.url = Some(u.clone()),
            Credential::TokenRequest(tr) => cfg.token_request = Some(tr.clone()),
            Credential::TokenDetails(_) => {}
        }
        let state = self.inner.auth_state.lock().unwrap();
        if let Some(saved) = &state.saved_auth_options {
            cfg.apply(saved);
        }
        cfg
    }

    /// Auth configuration with per-call AuthOptions applied on top.
    pub(crate) fn auth_config_with(&self, options: Option<&AuthOptions>) -> AuthConfig {
        let mut cfg = self.auth_config();
        if let Some(o) = options {
            cfg.apply(o);
        }
        cfg
    }

    /// Merge explicit token params with defaultTokenParams (RSA5c/RSA6c) and
    /// the client's clientId (RSA7d).
    pub(crate) fn effective_token_params(&self, params: Option<&TokenParams>) -> TokenParams {
        let defaults = self.inner.opts.default_token_params.as_ref();
        let p = params.cloned().unwrap_or_default();
        TokenParams {
            ttl: p.ttl.or_else(|| defaults.and_then(|d| d.ttl)),
            capability: p
                .capability
                .or_else(|| defaults.and_then(|d| d.capability.clone())),
            client_id: p
                .client_id
                .or_else(|| defaults.and_then(|d| d.client_id.clone()))
                .or_else(|| self.inner.opts.client_id.clone()),
            timestamp: p.timestamp,
            nonce: p.nonce,
        }
    }

    /// Obtain a token from the configured source. Precedence (RSA1): an
    /// authCallback, then an authUrl, then a literal TokenRequest, then the
    /// API key. Does not touch the cached library token.
    pub(crate) async fn acquire_token(
        &self,
        params: &TokenParams,
        cfg: &AuthConfig,
    ) -> Result<TokenDetails> {
        if let Some(cb) = &cfg.callback {
            let token_result = cb.token(params).await.map_err(|e| {
                let mut err = ErrorInfo::with_cause(
                    ErrorCode::ErrorFromClientTokenCallback.code(),
                    format!(
                        "Auth callback error: {}",
                        e.message.as_deref().unwrap_or("unknown")
                    ),
                    e,
                );
                err.status_code = Some(401);
                err
            })?;
            // RSA4f: a token exceeding 128KiB is invalid output from the
            // callback
            const MAX_TOKEN_LENGTH: usize = 128 * 1024;
            let oversized = |t: &str| t.len() > MAX_TOKEN_LENGTH;
            return match token_result {
                AuthToken::Details(td) if oversized(&td.token) => Err(ErrorInfo::with_status(
                    ErrorCode::ClientConfiguredAuthenticationProviderRequestFailed.code(),
                    401,
                    "Token from authCallback exceeds the maximum token length",
                )),
                AuthToken::Token(s) if oversized(&s) => Err(ErrorInfo::with_status(
                    ErrorCode::ClientConfiguredAuthenticationProviderRequestFailed.code(),
                    401,
                    "Token from authCallback exceeds the maximum token length",
                )),
                AuthToken::Details(td) => Ok(td),
                AuthToken::Token(s) => Ok(TokenDetails::token(s)),
                AuthToken::Request(tr) => self.exchange_token_request(&tr).await,
            };
        }

        if let Some(url) = &cfg.url {
            return self.fetch_token_from_url(url, params, cfg).await;
        }

        if let Some(tr) = &cfg.token_request {
            return self.exchange_token_request(tr).await;
        }

        if let Some(key) = &cfg.key {
            let timestamp = self.token_request_timestamp(params, cfg).await?;
            let tr = key.sign_with_timestamp(params, timestamp)?;
            return self.exchange_token_request(&tr).await;
        }

        if let Some(td) = &cfg.static_token {
            return Ok(td.clone());
        }

        Err(ErrorInfo::with_status(
            ErrorCode::NoWayToRenewAuthToken.code(),
            401,
            "No way to obtain or renew auth token",
        ))
    }

    /// RSA8c: fetch a token from the authUrl. The TokenParams and authParams
    /// are merged: appended as query params for GET (RSA8c1a), form-encoded
    /// in the body for POST (RSA8c1b). The response is interpreted by
    /// Content-Type: JSON is a TokenRequest (exchanged) or TokenDetails;
    /// anything else is a literal token string.
    async fn fetch_token_from_url(
        &self,
        auth_url: &str,
        params: &TokenParams,
        cfg: &AuthConfig,
    ) -> Result<TokenDetails> {
        let mut url = url::Url::parse(auth_url).map_err(|e| {
            ErrorInfo::new(
                ErrorCode::ErrorFromClientTokenCallback.code(),
                format!("Invalid authUrl: {}", e),
            )
        })?;

        // RSA8c1: merge TokenParams and authParams
        let mut pairs: Vec<(String, String)> = Vec::new();
        if let Some(ttl) = params.ttl {
            pairs.push(("ttl".to_string(), ttl.to_string()));
        }
        if let Some(cap) = &params.capability {
            pairs.push(("capability".to_string(), cap.clone()));
        }
        if let Some(cid) = &params.client_id {
            pairs.push(("clientId".to_string(), cid.clone()));
        }
        if let Some(ts) = params.timestamp {
            pairs.push(("timestamp".to_string(), ts.timestamp_millis().to_string()));
        }
        pairs.extend(cfg.params.iter().cloned());

        let method = cfg.method.to_uppercase();
        let mut headers = cfg.headers.clone();
        let body = if method == "POST" {
            headers.push((
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ));
            let encoded: String = pairs
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            Some(encoded.into_bytes())
        } else {
            for (k, v) in &pairs {
                url.query_pairs_mut().append_pair(k, v);
            }
            None
        };

        let req = HttpRequest {
            method,
            url: url.to_string(),
            headers,
            body,
        };
        let result = tokio::time::timeout(
            self.inner.opts.http_request_timeout,
            self.inner.http_client.execute(req),
        )
        .await;
        let resp = match result {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                return Err(ErrorInfo::with_status(
                    ErrorCode::ErrorFromClientTokenCallback.code(),
                    401,
                    format!("authUrl request failed: {}", e),
                ));
            }
            Err(_) => {
                return Err(ErrorInfo::with_status(
                    ErrorCode::ErrorFromClientTokenCallback.code(),
                    401,
                    "authUrl request timed out",
                ));
            }
        };
        if !(200..300).contains(&resp.status) {
            return Err(ErrorInfo::with_status(
                ErrorCode::ErrorFromClientTokenCallback.code(),
                resp.status,
                format!("authUrl returned status {}", resp.status),
            ));
        }

        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if ct.contains("application/json") {
            let v: serde_json::Value = serde_json::from_slice(&resp.body)?;
            if v.get("mac").is_some() && v.get("keyName").is_some() {
                let tr: TokenRequest = serde_json::from_value(v)?;
                self.exchange_token_request(&tr).await
            } else {
                Ok(serde_json::from_value(v)?)
            }
        } else {
            // text/plain, application/jwt, or unspecified: a literal token
            let token = String::from_utf8(resp.body).map_err(|e| {
                ErrorInfo::new(
                    ErrorCode::ErrorFromClientTokenCallback.code(),
                    format!("Invalid token string from authUrl: {}", e),
                )
            })?;
            Ok(TokenDetails::token(token))
        }
    }

    /// RSA15: an obtained token's clientId must be compatible with the
    /// client's configured clientId ("*" is compatible with anything).
    pub(crate) fn check_client_id_compat(&self, td: &TokenDetails) -> Result<()> {
        if let (Some(opt_cid), Some(tok_cid)) = (&self.inner.opts.client_id, &td.client_id) {
            if tok_cid != "*" && tok_cid != opt_cid {
                return Err(ErrorInfo::with_status(
                    ErrorCode::IncompatibleCredentials.code(),
                    401,
                    format!(
                        "Token clientId '{}' is incompatible with configured clientId '{}'",
                        tok_cid, opt_cid
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Is token auth in effect (RSA4)? Token auth is triggered by
    /// useTokenAuth, any token-bearing credential, or a previous authorize()
    /// (RSA10a). Only a key-only client uses basic auth.
    fn token_auth_in_effect(&self) -> bool {
        if self.inner.opts.use_token_auth {
            return true;
        }
        if self.inner.auth_state.lock().unwrap().forced_token_auth {
            return true;
        }
        !matches!(self.inner.opts.credential, Credential::Key(_))
    }

    /// Resolve the Authorization header for a request: basic auth for a
    /// key-only client (RSA2/RSA11), otherwise the cached token, with
    /// pre-emptive renewal when it is known to be expired (RSA4b1) or a
    /// client-side 40171 when it cannot be renewed (RSA4a2).
    pub(crate) async fn get_auth_header(&self) -> Result<AuthHeader> {
        if !self.token_auth_in_effect() {
            if let Credential::Key(key) = &self.inner.opts.credential {
                return Ok(AuthHeader::Basic(base64::encode(format!(
                    "{}:{}",
                    key.name, key.value
                ))));
            }
        }

        // Token auth
        let cached = self.inner.auth_state.lock().unwrap().cached_token.clone();
        let cfg = self.auth_config();
        let can_renew = cfg.callback.is_some() || cfg.url.is_some() || cfg.key.is_some();
        if let Some(td) = cached {
            if !td.token.is_empty() {
                if !td.is_expired(self.adjusted_now_ms()) {
                    return Ok(AuthHeader::Bearer(td.token));
                }
                // RSA4a2: expired with no way to renew — fail client-side
                if !can_renew {
                    return Err(ErrorInfo::with_status(
                        ErrorCode::NoWayToRenewAuthToken.code(),
                        401,
                        "Token expired and no way to renew it",
                    ));
                }
            }
        }

        // Acquire a (new) library token using saved params (RSA10e) merged
        // with defaults.
        let saved = self
            .inner
            .auth_state
            .lock()
            .unwrap()
            .saved_token_params
            .clone();
        let params = self.effective_token_params(saved.as_ref());
        let td = self.acquire_token(&params, &cfg).await?;
        self.check_client_id_compat(&td)?; // RSA15
        self.inner.auth_state.lock().unwrap().cached_token = Some(td.clone());
        Ok(AuthHeader::Bearer(td.token))
    }
}

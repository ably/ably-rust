use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::auth::{self, Auth, Credential, TokenDetails};
use crate::crypto::CipherParams;
use crate::error::{ErrorCode, ErrorInfo, Result, WrappedError};
use crate::http::{Decodable, PaginatedRequestBuilder, PaginatedResult, RequestBuilder};
use crate::http_client::{HttpClient, HttpRequest, HttpResponse};
use crate::options::ClientOptions;
use crate::stats::Stats;

#[derive(Clone, Copy, Debug, PartialEq, Default)]
#[allow(clippy::upper_case_acronyms)] // Format::JSON matches the API's Data::JSON
pub(crate) enum Format {
    #[default]
    MessagePack,
    JSON,
}

pub struct Rest {
    pub(crate) inner: Arc<RestInner>,
}

pub(crate) struct RestInner {
    pub(crate) opts: ClientOptions,
    pub(crate) http_client: Box<dyn HttpClient>,
    pub(crate) auth_state: Mutex<AuthState>,
    pub(crate) fallback_state: Mutex<Option<CachedFallback>>,
    #[cfg(test)]
    pub(crate) mock_handle: Option<crate::mock_http::MockHttpClient>,
}

pub(crate) struct AuthState {
    pub(crate) cached_token: Option<TokenDetails>,
    /// RSA10e/RSA10g: token params saved by authorize() for future renewals.
    pub(crate) saved_token_params: Option<auth::TokenParams>,
    /// RSA10h: auth options saved by authorize(), replacing the client's
    /// auth configuration for future renewals.
    pub(crate) saved_auth_options: Option<auth::AuthOptions>,
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
    fn value(&self) -> String {
        match self {
            AuthHeader::Basic(v) => format!("Basic {}", v),
            AuthHeader::Bearer(v) => format!("Bearer {}", v),
        }
    }
}

pub(crate) struct CachedFallback {
    pub(crate) host: String,
    pub(crate) expires: std::time::Instant,
}

impl Rest {
    pub fn new(key: &str) -> Result<Self> {
        ClientOptions::new(key).rest()
    }

    pub fn auth(&self) -> Auth<'_> {
        Auth::new(self)
    }

    pub fn channels(&self) -> Channels<'_> {
        Channels { rest: self }
    }

    pub fn push(&self) -> Push<'_> {
        Push { rest: self }
    }

    pub fn options(&self) -> &ClientOptions {
        &self.inner.opts
    }

    pub fn stats(&self) -> PaginatedRequestBuilder<'_, Stats> {
        PaginatedRequestBuilder {
            rest: self,
            path: "/stats".to_string(),
            params: Vec::new(),
            cipher: None,
            _marker: std::marker::PhantomData,
        }
    }

    /// RSC16: query the server time. No authentication is required, and an
    /// unauthenticated request avoids triggering token acquisition (which may
    /// itself need the server time via queryTime).
    pub async fn time(&self) -> Result<DateTime<Utc>> {
        let ts = self.server_time_ms().await?;
        DateTime::from_timestamp_millis(ts).ok_or_else(|| {
            ErrorInfo::new(
                ErrorCode::InternalError.code(),
                "Invalid timestamp from server",
            )
        })
    }

    /// Fetch the server time in epoch milliseconds and cache the offset from
    /// the local clock (RSA10k).
    pub(crate) async fn server_time_ms(&self) -> Result<i64> {
        let resp = self
            .do_request_internal("GET", "/time", &[], &[], None, None)
            .await?;
        let timestamps: Vec<i64> = self.deserialize_response(&resp)?;
        let ts = *timestamps.first().ok_or_else(|| {
            ErrorInfo::new(
                ErrorCode::InternalError.code(),
                "Empty time response from server",
            )
        })?;
        let offset = ts - Utc::now().timestamp_millis();
        self.inner.auth_state.lock().unwrap().time_offset_ms = Some(offset);
        Ok(ts)
    }

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

    /// RSC24: batch presence. Channel names are joined as a single
    /// comma-separated `channels` query parameter; the server responds with a
    /// BatchResult envelope (successCount/failureCount/results).
    pub async fn batch_presence(&self, channels: &[&str]) -> Result<BatchPresenceResponse> {
        let joined = channels.join(",");
        let resp = self
            .do_request("GET", "/presence", &[], &[("channels", &joined)], None)
            .await?;
        let mut response: BatchPresenceResponse = self.deserialize_response(&resp)?;
        for result in &mut response.results {
            if let BatchPresenceResult::Success(s) = result {
                for pm in &mut s.presence {
                    pm.decode();
                }
            }
        }
        Ok(response)
    }

    pub async fn batch_publish(
        &self,
        specs: Vec<BatchPublishSpec>,
    ) -> Result<Vec<BatchPublishResult>> {
        // RSC22: reject empty input client-side
        if specs.is_empty() {
            return Err(ErrorInfo::new(
                ErrorCode::InvalidParameterValue.code(),
                "Batch publish requires at least one BatchPublishSpec",
            ));
        }
        for spec in &specs {
            if spec.channels.is_empty() || spec.messages.is_empty() {
                return Err(ErrorInfo::new(
                    ErrorCode::InvalidParameterValue.code(),
                    "Each BatchPublishSpec requires at least one channel and one message",
                ));
            }
        }
        // RSC22c6: encode messages per RSL4; RSC22d: idempotent ids applied
        // to each BatchPublishSpec separately
        let format = self.inner.opts.format;
        let idempotent = self.inner.opts.idempotent_rest_publishing;
        let wire_specs: Vec<BatchPublishSpec> = specs
            .iter()
            .map(|spec| {
                let mut messages = spec.messages.clone();
                if idempotent {
                    let base = idempotent_id_base();
                    for (i, msg) in messages.iter_mut().enumerate() {
                        if msg.id.is_none() {
                            msg.id = Some(format!("{}:{}", base, i));
                        }
                    }
                }
                BatchPublishSpec {
                    channels: spec.channels.clone(),
                    messages: messages.iter().map(|m| m.encode_for_wire(format)).collect(),
                }
            })
            .collect();
        let body = self.serialize_body(&wire_specs)?;
        let resp = self
            .do_request("POST", "/messages", &[], &[], Some(body))
            .await?;
        // The server returns a single result object for a single-channel spec,
        // or an array of per-channel results (RSC22c3/RSC22c4).
        let value: serde_json::Value = self.deserialize_response(&resp)?;
        if value.is_array() {
            serde_json::from_value(value).map_err(ErrorInfo::from)
        } else {
            let single: BatchPublishResult = serde_json::from_value(value)?;
            Ok(vec![single])
        }
    }

    pub fn request(&self, method: &str, path: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            rest: self,
            method: method.to_string(),
            path: path.to_string(),
            params: Vec::new(),
            headers: Vec::new(),
            body: None,
            build_error: None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))] // test-facing
    pub(crate) fn auth_options(&self) -> crate::auth::AuthOptions {
        crate::auth::AuthOptions::default()
    }

    #[allow(dead_code)]
    pub(crate) fn from_inner(inner: Arc<RestInner>) -> Self {
        Self { inner }
    }

    // ---- Internal request pipeline ----

    fn content_type(&self) -> &'static str {
        match self.inner.opts.format {
            Format::JSON => "application/json",
            Format::MessagePack => "application/x-msgpack",
        }
    }

    fn accept_type(&self) -> &'static str {
        self.content_type()
    }

    pub(crate) fn serialize_body<T: Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        match self.inner.opts.format {
            Format::JSON => Ok(serde_json::to_vec(value)?),
            Format::MessagePack => Ok(rmp_serde::to_vec_named(value)?),
        }
    }

    pub(crate) fn deserialize_response<T: DeserializeOwned>(
        &self,
        resp: &HttpResponse,
    ) -> Result<T> {
        // Check response content-type to determine deserializer
        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        if ct.contains("application/x-msgpack") {
            Ok(rmp_serde::from_slice(&resp.body)?)
        } else if ct.contains("application/json") {
            Ok(serde_json::from_slice(&resp.body)?)
        } else {
            serde_json::from_slice(&resp.body).or_else(|_| {
                rmp_serde::from_slice(&resp.body).map_err(|e| {
                    ErrorInfo::new(
                        ErrorCode::InvalidMessageDataOrEncoding.code(),
                        format!(
                            "Failed to deserialize response (content-type '{}'): {}",
                            ct, e
                        ),
                    )
                })
            })
        }
    }

    /// RTN17e: remember a fallback host that the realtime connection
    /// succeeded on, so REST requests prefer it too (RSC15f semantics).
    pub(crate) fn cache_fallback_host(&self, host: &str) {
        let mut fb = self.inner.fallback_state.lock().unwrap();
        *fb = Some(CachedFallback {
            host: host.to_string(),
            expires: std::time::Instant::now() + self.inner.opts.fallback_retry_timeout,
        });
    }

    /// Invalidate the cached library token so the next acquisition renews it
    /// (used by realtime token-error recovery, RTN14b/RTN15h2; called from
    /// spawned connect tasks, never the connection loop).
    pub(crate) fn invalidate_cached_token(&self) {
        self.inner.auth_state.lock().unwrap().cached_token = None;
    }

    /// Resolve the auth configuration: the client's credential plus any
    /// options stored by authorize() (RSA10h).
    pub(crate) fn auth_config(&self) -> auth::AuthConfig {
        let opts = &self.inner.opts;
        let mut cfg = auth::AuthConfig {
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
    pub(crate) fn auth_config_with(&self, options: Option<&auth::AuthOptions>) -> auth::AuthConfig {
        let mut cfg = self.auth_config();
        if let Some(o) = options {
            cfg.apply(o);
        }
        cfg
    }

    /// Merge explicit token params with defaultTokenParams (RSA5c/RSA6c) and
    /// the client's clientId (RSA7d).
    pub(crate) fn effective_token_params(
        &self,
        params: Option<&auth::TokenParams>,
    ) -> auth::TokenParams {
        let defaults = self.inner.opts.default_token_params.as_ref();
        let p = params.cloned().unwrap_or_default();
        auth::TokenParams {
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

    /// The timestamp for a token request (RSA9d): an explicit timestamp wins;
    /// with queryTime the server clock is used (cached offset if available);
    /// otherwise the local clock.
    pub(crate) async fn token_request_timestamp(
        &self,
        params: &auth::TokenParams,
        cfg: &auth::AuthConfig,
    ) -> Result<i64> {
        if let Some(ts) = params.timestamp {
            return Ok(ts.timestamp_millis());
        }
        if cfg.query_time {
            let cached_offset = self.inner.auth_state.lock().unwrap().time_offset_ms;
            return Ok(match cached_offset {
                Some(offset) => Utc::now().timestamp_millis() + offset,
                None => self.server_time_ms().await?,
            });
        }
        Ok(Utc::now().timestamp_millis())
    }

    /// Obtain a token from the configured source. Precedence (RSA1): an
    /// authCallback, then an authUrl, then a literal TokenRequest, then the
    /// API key. Does not touch the cached library token.
    pub(crate) async fn acquire_token(
        &self,
        params: &auth::TokenParams,
        cfg: &auth::AuthConfig,
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
                auth::AuthToken::Details(td) if oversized(&td.token) => {
                    Err(ErrorInfo::with_status(
                        ErrorCode::ClientConfiguredAuthenticationProviderRequestFailed.code(),
                        401,
                        "Token from authCallback exceeds the maximum token length",
                    ))
                }
                auth::AuthToken::Token(s) if oversized(&s) => Err(ErrorInfo::with_status(
                    ErrorCode::ClientConfiguredAuthenticationProviderRequestFailed.code(),
                    401,
                    "Token from authCallback exceeds the maximum token length",
                )),
                auth::AuthToken::Details(td) => Ok(td),
                auth::AuthToken::Token(s) => Ok(TokenDetails::token(s)),
                auth::AuthToken::Request(tr) => self.exchange_token_request(&tr).await,
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

    /// POST a signed TokenRequest to /keys/{keyName}/requestToken. The signed
    /// request is self-authenticating; no Authorization header is sent.
    pub(crate) async fn exchange_token_request(
        &self,
        tr: &auth::TokenRequest,
    ) -> Result<TokenDetails> {
        let body = self.serialize_body(tr)?;
        let path = format!("/keys/{}/requestToken", tr.key_name);
        let resp = self
            .do_request_internal("POST", &path, &[], &[], Some(body), None)
            .await?;
        self.deserialize_response(&resp)
    }

    /// RSA8c: fetch a token from the authUrl. The TokenParams and authParams
    /// are merged: appended as query params for GET (RSA8c1a), form-encoded
    /// in the body for POST (RSA8c1b). The response is interpreted by
    /// Content-Type: JSON is a TokenRequest (exchanged) or TokenDetails;
    /// anything else is a literal token string.
    async fn fetch_token_from_url(
        &self,
        auth_url: &str,
        params: &auth::TokenParams,
        cfg: &auth::AuthConfig,
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
                let tr: auth::TokenRequest = serde_json::from_value(v)?;
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

    /// Build the base URL for a request.
    fn build_url(
        &self,
        host: &str,
        path: &str,
        params: &[(&str, &str)],
        request_id: Option<&str>,
    ) -> Result<url::Url> {
        let scheme = if self.inner.opts.tls { "https" } else { "http" };
        let port = if self.inner.opts.tls {
            self.inner.opts.tls_port
        } else {
            self.inner.opts.port
        };

        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };

        let url_str =
            if (self.inner.opts.tls && port == 443) || (!self.inner.opts.tls && port == 80) {
                format!("{}://{}{}", scheme, host, path)
            } else {
                format!("{}://{}:{}{}", scheme, host, port, path)
            };

        let mut url = url::Url::parse(&url_str)?;

        // Add params
        for (k, v) in params {
            url.query_pairs_mut().append_pair(k, v);
        }

        // RSC7c: the request_id is generated once per logical request and
        // remains the same across fallback retries
        if let Some(rid) = request_id {
            url.query_pairs_mut().append_pair("request_id", rid);
        }

        Ok(url)
    }

    /// RSC7c: a fresh request id — url-safe base64 of random bytes.
    fn generate_request_id() -> String {
        let mut buf = [0u8; 12];
        rand::thread_rng().fill(&mut buf);
        base64::encode_config(buf, base64::URL_SAFE_NO_PAD)
    }

    /// Internal do_request that adds auth automatically.
    pub(crate) async fn do_request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        params: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse> {
        let auth_header = self.get_auth_header().await?;
        let result = self
            .do_request_internal(
                method,
                path,
                headers,
                params,
                body.clone(),
                Some(&auth_header),
            )
            .await;

        // RSA4b: on a token error (401 with 40140-40149), renew once and retry
        match &result {
            Err(e) if e.status_code == Some(401) => {
                let code = e.code.unwrap_or(0);
                let cfg = self.auth_config();
                let can_renew = cfg.callback.is_some() || cfg.url.is_some() || cfg.key.is_some();
                if (40140..=40149).contains(&code) && can_renew {
                    // Clear cached token and try to get a new one
                    {
                        let mut state = self.inner.auth_state.lock().unwrap();
                        state.cached_token = None;
                    }
                    let new_auth = self.get_auth_header().await?;
                    return self
                        .do_request_internal(method, path, headers, params, body, Some(&new_auth))
                        .await;
                }
                result
            }
            _ => result,
        }
    }

    /// Internal request method with retry/fallback logic.
    async fn do_request_internal(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        params: &[(&str, &str)],
        body: Option<Vec<u8>>,
        auth_header: Option<&AuthHeader>,
    ) -> Result<HttpResponse> {
        self.execute_request(
            method,
            path,
            extra_headers,
            params,
            body,
            auth_header,
            false,
        )
        .await
    }

    /// As do_request, but returns non-2xx responses as Ok for inspection
    /// (HP4/HP5 semantics for Rest::request()). Token renewal on a 401 token
    /// error still applies (RSA4b), as does fallback (RSC19e).
    pub(crate) async fn do_request_raw(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        params: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse> {
        let auth_header = self.get_auth_header().await?;
        let resp = self
            .execute_request(
                method,
                path,
                extra_headers,
                params,
                body.clone(),
                Some(&auth_header),
                true,
            )
            .await?;
        if resp.status == 401 {
            let code = self
                .parse_error_body(&resp)
                .and_then(|e| e.code)
                .unwrap_or(0);
            let cfg = self.auth_config();
            let can_renew = cfg.callback.is_some() || cfg.url.is_some() || cfg.key.is_some();
            if (40140..=40149).contains(&code) && can_renew {
                {
                    let mut state = self.inner.auth_state.lock().unwrap();
                    state.cached_token = None;
                }
                let new_auth = self.get_auth_header().await?;
                return self
                    .execute_request(
                        method,
                        path,
                        extra_headers,
                        params,
                        body,
                        Some(&new_auth),
                        true,
                    )
                    .await;
            }
        }
        Ok(resp)
    }

    /// Parse an Ably error body ({"error": {...}}) if present.
    fn parse_error_body(&self, resp: &HttpResponse) -> Option<ErrorInfo> {
        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let parsed: Option<WrappedError> = if ct.contains("application/x-msgpack") {
            rmp_serde::from_slice(&resp.body).ok()
        } else {
            serde_json::from_slice(&resp.body).ok()
        };
        parsed.map(|w| w.error)
    }

    /// The request pipeline: standard headers, fallback rotation bounded by
    /// httpMaxRetryCount (RSC15a) and httpMaxRetryDuration (TO3l6), cached
    /// fallback host (RSC15f), and a stable request_id across retries (RSC7c).
    /// In `raw` mode, HTTP error statuses are returned as Ok responses.
    #[allow(clippy::too_many_arguments)]
    async fn execute_request(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        params: &[(&str, &str)],
        body: Option<Vec<u8>>,
        auth_header: Option<&AuthHeader>,
        raw: bool,
    ) -> Result<HttpResponse> {
        // Build standard headers; extra headers override same-named standard
        // ones (e.g. a per-request X-Ably-Version, RSC19f1)
        let mut all_headers: Vec<(String, String)> = vec![
            ("x-ably-version".to_string(), "6".to_string()),
            (
                "ably-agent".to_string(),
                format!("ably-rust/{}", env!("CARGO_PKG_VERSION")),
            ),
            ("accept".to_string(), self.accept_type().to_string()),
        ];

        if body.is_some() {
            all_headers.push(("content-type".to_string(), self.content_type().to_string()));
        }

        if let Some(auth) = auth_header {
            all_headers.push(("authorization".to_string(), auth.value()));
            // RSA7e2: with basic auth an identified client asserts its
            // clientId via the X-Ably-ClientId header (base64 encoded).
            // With token auth the token itself carries the clientId.
            if matches!(auth, AuthHeader::Basic(_)) {
                if let Some(ref client_id) = self.inner.opts.client_id {
                    all_headers.push(("x-ably-clientid".to_string(), base64::encode(client_id)));
                }
            }
        }

        for (k, v) in extra_headers {
            let k = k.to_lowercase();
            if let Some(existing) = all_headers.iter_mut().find(|(name, _)| *name == k) {
                existing.1 = v.to_string();
            } else {
                all_headers.push((k, v.to_string()));
            }
        }

        // RSC7c: one request id for the whole logical request
        let request_id = if self.inner.opts.add_request_ids {
            Some(Self::generate_request_id())
        } else {
            None
        };
        let attach_request_id = |mut err: ErrorInfo| -> ErrorInfo {
            if err.request_id.is_none() {
                err.request_id = request_id.clone();
            }
            err
        };

        let primary_host = self.inner.opts.primary_host.clone();

        // RSC15f: a valid cached fallback host is tried first
        let first_host = {
            let fb = self.inner.fallback_state.lock().unwrap();
            match &*fb {
                Some(cached) if cached.expires > std::time::Instant::now() => cached.host.clone(),
                _ => primary_host.clone(),
            }
        };

        let timeout_duration = self.inner.opts.http_request_timeout;
        let started = std::time::Instant::now();
        let retry_budget = self.inner.opts.http_max_retry_duration;

        let url = self.build_url(&first_host, path, params, request_id.as_deref())?;
        self.inner.opts.log(
            crate::options::LogLevel::Micro,
            &format!(
                "HTTP request: method={} host={} path={}",
                method, first_host, path
            ),
        );
        let req = HttpRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: all_headers.clone(),
            body: body.clone(),
        };

        let mut last_error;
        let result =
            tokio::time::timeout(timeout_duration, self.inner.http_client.execute(req)).await;
        match result {
            Ok(Ok(resp)) => {
                let retriable = Self::is_retriable_response(&resp);
                if raw && !retriable {
                    return Ok(resp);
                }
                match self.check_response(resp) {
                    Ok(outcome) => return Ok(outcome),
                    Err(e) => {
                        if !retriable && !Self::is_retriable_error(&e) {
                            return Err(attach_request_id(e));
                        }
                        last_error = e;
                    }
                }
            }
            Ok(Err(network_err)) => {
                last_error = ErrorInfo::with_status(
                    ErrorCode::InternalError.code(),
                    500,
                    format!("Network error: {}", network_err),
                );
            }
            Err(_elapsed) => {
                last_error = ErrorInfo::with_status(
                    ErrorCode::TimeoutError.code(),
                    408,
                    "Request timed out".to_string(),
                );
            }
        }

        // Build the retry host list. If the cached fallback was tried first,
        // clear the cache and retry the primary first (RSC15f).
        let fallback_hosts = &self.inner.opts.resolved_fallback_hosts;
        use rand::seq::SliceRandom;
        let mut retry_hosts: Vec<String> = Vec::new();
        if first_host != primary_host {
            {
                let mut fb = self.inner.fallback_state.lock().unwrap();
                *fb = None;
            }
            retry_hosts.push(primary_host.clone());
        }
        // When the first attempt used a cached fallback host, don't try that
        // same host again in the rotation. A fallback host that merely equals
        // the primary (e.g. proxy test configs) is still tried.
        let used_cached_fallback = first_host != primary_host;
        let mut remaining: Vec<&String> = fallback_hosts
            .iter()
            .filter(|h| !used_cached_fallback || h.as_str() != first_host)
            .collect();
        remaining.shuffle(&mut rand::thread_rng());
        retry_hosts.extend(remaining.into_iter().cloned());

        if retry_hosts.is_empty() {
            return Err(attach_request_id(last_error));
        }

        let max_retries = self.inner.opts.http_max_retry_count.min(retry_hosts.len());

        for host in retry_hosts.iter().take(max_retries) {
            // TO3l6: the total time spent on retries must not exceed
            // httpMaxRetryDuration
            if started.elapsed() >= retry_budget {
                break;
            }

            self.inner.opts.log(
                crate::options::LogLevel::Minor,
                &format!(
                    "Retrying against fallback host: method={} host={} path={}",
                    method, host, path
                ),
            );
            let url = self.build_url(host, path, params, request_id.as_deref())?;
            let req = HttpRequest {
                method: method.to_string(),
                url: url.to_string(),
                headers: all_headers.clone(),
                body: body.clone(),
            };

            let result =
                tokio::time::timeout(timeout_duration, self.inner.http_client.execute(req)).await;
            match result {
                Ok(Ok(resp)) => {
                    let retriable = Self::is_retriable_response(&resp);
                    if raw && !retriable {
                        return Ok(resp);
                    }
                    match self.check_response(resp) {
                        Ok(resp) => {
                            // RSC15f: remember a successful fallback host
                            // (the primary is not a fallback)
                            if host.as_str() != primary_host {
                                let mut fb = self.inner.fallback_state.lock().unwrap();
                                *fb = Some(CachedFallback {
                                    host: host.to_string(),
                                    expires: std::time::Instant::now()
                                        + self.inner.opts.fallback_retry_timeout,
                                });
                            }
                            return Ok(resp);
                        }
                        Err(e) => {
                            if !retriable && !Self::is_retriable_error(&e) {
                                return Err(attach_request_id(e));
                            }
                            last_error = e;
                        }
                    }
                }
                Ok(Err(_)) => {
                    // Network error on fallback, continue trying
                    continue;
                }
                Err(_elapsed) => {
                    last_error = ErrorInfo::with_status(
                        ErrorCode::TimeoutError.code(),
                        408,
                        "Request timed out".to_string(),
                    );
                    continue;
                }
            }
        }

        self.inner.opts.log(
            crate::options::LogLevel::Error,
            &format!(
                "HTTP request failed: method={} path={} error={}",
                method, path, last_error
            ),
        );
        Err(attach_request_id(last_error))
    }

    /// Check an HTTP response, returning Ok(resp) for success or Err for errors.
    fn check_response(&self, resp: HttpResponse) -> Result<HttpResponse> {
        if resp.status >= 200 && resp.status < 300 {
            // Check for unsupported content type on success
            let ct = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            if !resp.body.is_empty()
                && !ct.is_empty()
                && !ct.contains("application/json")
                && !ct.contains("application/x-msgpack")
            {
                return Err(ErrorInfo {
                    code: Some(ErrorCode::InvalidMessageDataOrEncoding.code()),
                    status_code: Some(400),
                    message: Some(format!("Unsupported content type: {}", ct)),
                    ..Default::default()
                });
            }
            return Ok(resp);
        }

        // Error response - try to parse error body
        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        if ct.contains("application/json") || ct.contains("application/x-msgpack") {
            let parsed: std::result::Result<WrappedError, _> =
                if ct.contains("application/x-msgpack") {
                    rmp_serde::from_slice(&resp.body).map_err(|e| e.to_string())
                } else {
                    serde_json::from_slice(&resp.body).map_err(|e| e.to_string())
                };

            if let Ok(wrapped) = parsed {
                let mut err = wrapped.error;
                if err.status_code.is_none() {
                    err.status_code = Some(resp.status);
                }
                return Err(err);
            }
        }

        // Couldn't parse error body
        Err(ErrorInfo::with_status(
            resp.status as u32 * 100,
            resp.status,
            format!("Unexpected error response (status {})", resp.status),
        ))
    }

    fn is_retriable_response(resp: &HttpResponse) -> bool {
        // RSC15l3: 500 <= status <= 504 qualifies for fallback
        if (500..=504).contains(&resp.status) {
            return true;
        }
        // RSC15l4: CloudFront errors (status >= 400 with Server: CloudFront) are retriable
        if resp.status >= 400 {
            let is_cloudfront = resp
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("server") && v.contains("CloudFront"));
            if is_cloudfront {
                return true;
            }
        }
        false
    }

    fn is_retriable_error(err: &ErrorInfo) -> bool {
        if let Some(status) = err.status_code {
            // RSC15l3 (and 408 for our internal timeout marker)
            (500..=504).contains(&status) || status == 408
        } else {
            false
        }
    }
}

impl Clone for Rest {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// --- Channels ---

pub struct Channels<'a> {
    rest: &'a Rest,
}

impl<'a> Channels<'a> {
    pub fn name(&self, _name: impl Into<String>) -> ChannelBuilder<'a> {
        ChannelBuilder {
            rest: self.rest,
            name: _name.into(),
            cipher: None,
        }
    }

    pub fn get(&self, name: impl Into<String>) -> Channel<'a> {
        Channel {
            name: name.into(),
            rest: self.rest,
            cipher: None,
        }
    }
}

pub struct ChannelBuilder<'a> {
    rest: &'a Rest,
    name: String,
    cipher: Option<CipherParams>,
}

impl<'a> ChannelBuilder<'a> {
    pub fn cipher(mut self, cipher: CipherParams) -> Self {
        self.cipher = Some(cipher);
        self
    }

    pub fn get(self) -> Channel<'a> {
        Channel {
            name: self.name,
            rest: self.rest,
            cipher: self.cipher,
        }
    }
}

pub struct Channel<'a> {
    pub name: String,
    pub(crate) rest: &'a Rest,
    pub(crate) cipher: Option<CipherParams>,
}

impl<'a> Channel<'a> {
    pub fn publish(&self) -> PublishBuilder<'_> {
        PublishBuilder {
            channel: self,
            id: None,
            name: None,
            data: Data::None,
            extras: None,
            client_id: None,
            params: None,
            messages: None,
            cipher: None,
        }
    }

    pub fn history(&self) -> PaginatedRequestBuilder<'_, Message> {
        let path = format!("/channels/{}/history", urlencoding::encode(&self.name));
        PaginatedRequestBuilder {
            rest: self.rest,
            path,
            params: Vec::new(),
            cipher: self.cipher.clone(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn get_message(&self, serial: &str) -> Result<Message> {
        if serial.is_empty() {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Message serial is required",
            ));
        }
        let path = format!(
            "/channels/{}/messages/{}",
            urlencoding::encode(&self.name),
            urlencoding::encode(serial)
        );
        let resp = self.rest.do_request("GET", &path, &[], &[], None).await?;
        let mut msg: Message = self.rest.deserialize_response(&resp)?;
        msg.decode_with_cipher(self.cipher.as_ref());
        Ok(msg)
    }

    pub fn message_versions(&self, serial: &str) -> PaginatedRequestBuilder<'_, Message> {
        let path = format!(
            "/channels/{}/messages/{}/versions",
            urlencoding::encode(&self.name),
            urlencoding::encode(serial)
        );
        PaginatedRequestBuilder {
            rest: self.rest,
            path,
            params: Vec::new(),
            cipher: self.cipher.clone(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn update_message(
        &self,
        msg: &Message,
        op: Option<&MessageOperation>,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        self.send_message_patch(msg, MessageAction::Update, op, params)
            .await
    }

    pub async fn delete_message(
        &self,
        msg: &Message,
        op: Option<&MessageOperation>,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        self.send_message_patch(msg, MessageAction::Delete, op, params)
            .await
    }

    pub async fn append_message(
        &self,
        msg: &Message,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        self.send_message_patch(msg, MessageAction::Append, None, params)
            .await
    }

    /// RSL15: PATCH /channels/{name}/messages/{serial} with the message encoded
    /// per RSL4, the given action, and `version` set to the MessageOperation
    /// when provided (RSL15b7). The user-supplied message is not mutated (RSL15c).
    async fn send_message_patch(
        &self,
        msg: &Message,
        action: MessageAction,
        op: Option<&MessageOperation>,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        let serial = msg.serial.as_deref().unwrap_or("");
        if serial.is_empty() {
            // RSL15a
            return Err(ErrorInfo::new(
                ErrorCode::InvalidParameterValue.code(),
                "Message serial is required",
            ));
        }
        let path = format!(
            "/channels/{}/messages/{}",
            urlencoding::encode(&self.name),
            urlencoding::encode(serial)
        );
        let mut wire = msg.encode_for_wire(self.rest.inner.opts.format);
        wire.action = Some(action);
        wire.serial = None; // the serial travels in the URL path
        if let Some(op) = op {
            wire.version = Some(serde_json::to_value(op)?);
        }
        let body = self.rest.serialize_body(&wire)?;
        let params: Vec<(&str, &str)> = params.unwrap_or(&[]).to_vec();
        let resp = self
            .rest
            .do_request("PATCH", &path, &[], &params, Some(body))
            .await?;
        self.rest.deserialize_response(&resp)
    }

    pub fn annotations(&self) -> RestAnnotations<'_> {
        RestAnnotations { channel: self }
    }

    pub fn presence(&self) -> Presence<'_> {
        Presence { channel: self }
    }

    /// RSL7: set or update the stored channel options on this handle.
    pub fn set_options(&mut self, options: ChannelOptions) {
        self.cipher = options.cipher;
    }

    /// RSL8: fetch the channel's lifecycle status and occupancy from
    /// GET /channels/<channelId>, returning a ChannelDetails (RSL8a).
    pub async fn status(&self) -> Result<ChannelDetails> {
        let path = format!("/channels/{}", urlencoding::encode(&self.name));
        let resp = self.rest.do_request("GET", &path, &[], &[], None).await?;
        self.rest.deserialize_response(&resp)
    }
}

/// CHD2: the details of a channel returned by RestChannel::status (RSL8a).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDetails {
    /// CHD2a
    pub channel_id: String,
    /// CHD2b
    #[serde(default)]
    pub status: ChannelStatus,
}

/// CHS2: a channel's lifecycle status.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStatus {
    /// CHS2a
    #[serde(default)]
    pub is_active: bool,
    /// CHS2b
    #[serde(default)]
    pub occupancy: ChannelOccupancy,
}

/// CHO2: a channel's occupancy.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelOccupancy {
    /// CHO2a
    #[serde(default)]
    pub metrics: ChannelMetrics,
}

/// CHM2: a channel's occupancy metrics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMetrics {
    /// CHM2a
    #[serde(default)]
    pub connections: u64,
    /// CHM2b
    #[serde(default)]
    pub presence_connections: u64,
    /// CHM2c
    #[serde(default)]
    pub presence_members: u64,
    /// CHM2d
    #[serde(default)]
    pub presence_subscribers: u64,
    /// CHM2e
    #[serde(default)]
    pub publishers: u64,
    /// CHM2f
    #[serde(default)]
    pub subscribers: u64,
    /// CHM2g — None when the server omits it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_publishers: Option<u64>,
    /// CHM2h — None when the server omits it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_subscribers: Option<u64>,
}

// --- Presence ---

pub struct Presence<'a> {
    channel: &'a Channel<'a>,
}

impl<'a> Presence<'a> {
    pub fn get(&self) -> PresenceRequestBuilder<'_> {
        let path = format!(
            "/channels/{}/presence",
            urlencoding::encode(&self.channel.name)
        );
        PresenceRequestBuilder {
            rest: self.channel.rest,
            path,
            params: Vec::new(),
            cipher: self.channel.cipher.clone(),
        }
    }

    pub fn history(&self) -> PaginatedRequestBuilder<'_, PresenceMessage> {
        let path = format!(
            "/channels/{}/presence/history",
            urlencoding::encode(&self.channel.name)
        );
        PaginatedRequestBuilder {
            rest: self.channel.rest,
            path,
            params: Vec::new(),
            cipher: self.channel.cipher.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

pub struct PresenceRequestBuilder<'a> {
    rest: &'a Rest,
    path: String,
    params: Vec<(String, String)>,
    cipher: Option<CipherParams>,
}

impl<'a> PresenceRequestBuilder<'a> {
    pub fn limit(mut self, limit: u32) -> Self {
        self.params.push(("limit".to_string(), limit.to_string()));
        self
    }
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.params
            .push(("clientId".to_string(), client_id.to_string()));
        self
    }
    pub fn connection_id(mut self, connection_id: &str) -> Self {
        self.params
            .push(("connectionId".to_string(), connection_id.to_string()));
        self
    }
    pub async fn send(self) -> Result<PaginatedResult<PresenceMessage>> {
        let params: Vec<(&str, &str)> = self
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let resp = self
            .rest
            .do_request("GET", &self.path, &[], &params, None)
            .await?;
        let (next_rel_url, first_rel_url) = crate::http::parse_link_headers(&resp.headers);
        let mut items: Vec<PresenceMessage> = self.rest.deserialize_response(&resp)?;
        for item in &mut items {
            item.decode_with_cipher(self.cipher.as_ref());
        }
        Ok(PaginatedResult {
            items,
            rest: self.rest.clone(),
            next_rel_url,
            first_rel_url,
            base_path: self.path,
            cipher: self.cipher,
        })
    }
}

// --- Annotations ---

pub struct RestAnnotations<'a> {
    channel: &'a Channel<'a>,
}

impl<'a> RestAnnotations<'a> {
    pub async fn publish(&self, msg_serial: &str, annotation: &Annotation) -> Result<()> {
        // Validate type is present
        if annotation.annotation_type.is_none() {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Annotation type is required",
            ));
        }
        let path = format!(
            "/channels/{}/messages/{}/annotations",
            urlencoding::encode(&self.channel.name),
            urlencoding::encode(msg_serial),
        );
        let mut ann = annotation.clone();
        ann.action = Some(AnnotationAction::Create);
        // RSAN1c2: messageSerial set from the identifier argument
        ann.message_serial = Some(msg_serial.to_string());
        // RSAN1c3: annotation data is encoded per RSL4 (annotations are not
        // encrypted, so no cipher applies)
        let (data, encoding) = encode_data_for_wire(
            ann.data,
            ann.encoding,
            self.channel.rest.inner.opts.format,
            None,
        )?;
        ann.data = data;
        ann.encoding = encoding;
        // RSAN1c4: idempotent publishing applies to annotations too
        if self.channel.rest.inner.opts.idempotent_rest_publishing && ann.id.is_none() {
            ann.id = Some(format!("{}:0", idempotent_id_base()));
        }
        let body = self.channel.rest.serialize_body(&vec![ann])?;
        self.channel
            .rest
            .do_request("POST", &path, &[], &[], Some(body))
            .await?;
        Ok(())
    }

    pub async fn delete(&self, msg_serial: &str, annotation: &Annotation) -> Result<()> {
        let path = format!(
            "/channels/{}/messages/{}/annotations",
            urlencoding::encode(&self.channel.name),
            urlencoding::encode(msg_serial),
        );
        let mut ann = annotation.clone();
        ann.action = Some(AnnotationAction::Delete);
        ann.message_serial = Some(msg_serial.to_string());
        // RSAN1c3 applies to deletes too — the body is an annotation
        let (data, encoding) = encode_data_for_wire(
            ann.data,
            ann.encoding,
            self.channel.rest.inner.opts.format,
            None,
        )?;
        ann.data = data;
        ann.encoding = encoding;
        let body = self.channel.rest.serialize_body(&vec![ann])?;
        self.channel
            .rest
            .do_request("POST", &path, &[], &[], Some(body))
            .await?;
        Ok(())
    }

    pub fn get(&self, msg_serial: &str) -> PaginatedRequestBuilder<'_, Annotation> {
        let path = format!(
            "/channels/{}/messages/{}/annotations",
            urlencoding::encode(&self.channel.name),
            urlencoding::encode(msg_serial),
        );
        PaginatedRequestBuilder {
            rest: self.channel.rest,
            path,
            params: Vec::new(),
            cipher: None,
            _marker: std::marker::PhantomData,
        }
    }
}

// --- PublishBuilder ---

pub struct PublishBuilder<'a> {
    channel: &'a Channel<'a>,
    id: Option<String>,
    name: Option<String>,
    data: Data,
    extras: Option<serde_json::Map<String, serde_json::Value>>,
    client_id: Option<String>,
    params: Option<Vec<(String, String)>>,
    messages: Option<Vec<Message>>,
    cipher: Option<CipherParams>,
}

impl<'a> PublishBuilder<'a> {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn string(mut self, data: impl Into<String>) -> Self {
        self.data = Data::String(data.into());
        self
    }

    pub fn json(mut self, data: impl Serialize) -> Self {
        self.data = Data::JSON(serde_json::to_value(data).unwrap_or_default());
        self
    }

    pub fn binary(mut self, data: Vec<u8>) -> Self {
        self.data = Data::Binary(serde_bytes::ByteBuf::from(data));
        self
    }

    pub fn extras(mut self, extras: serde_json::Map<String, serde_json::Value>) -> Self {
        self.extras = Some(extras);
        self
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn params(mut self, params: &[(&str, &str)]) -> Self {
        self.params = Some(
            params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        self
    }

    /// RSL5: encrypt the payload(s) with these cipher params, overriding any
    /// cipher configured on the channel.
    pub fn cipher(mut self, cipher: CipherParams) -> Self {
        self.cipher = Some(cipher);
        self
    }

    /// RSL1a/RSL1c: publish multiple messages in a single request. When set,
    /// the single-message builder fields (name/data/...) are ignored.
    pub fn messages(mut self, messages: Vec<Message>) -> Self {
        self.messages = Some(messages);
        self
    }

    pub async fn send(self) -> Result<PublishResult> {
        let rest = self.channel.rest;
        let path = format!(
            "/channels/{}/messages",
            urlencoding::encode(&self.channel.name)
        );

        let single = self.messages.is_none();
        let mut messages = match self.messages {
            Some(msgs) => msgs,
            None => vec![Message {
                id: self.id,
                name: self.name,
                data: self.data,
                client_id: self.client_id,
                extras: self.extras.map(serde_json::Value::Object),
                ..Default::default()
            }],
        };

        // RSL4a: only string, binary, and JSON object/array payloads are valid
        for msg in &messages {
            if let Data::JSON(v) = &msg.data {
                if !(v.is_object() || v.is_array()) {
                    return Err(ErrorInfo::new(
                        ErrorCode::InvalidMessageDataOrEncoding.code(),
                        "Message data must be a string, binary, or JSON object/array",
                    ));
                }
            }
        }

        // RSL1i: message size per TM6 — sum over messages of name, clientId,
        // stringified extras, and data lengths — measured before encoding
        let total_size: u64 = messages.iter().map(message_size).sum();
        let max_size = rest.inner.opts.max_message_size;
        if total_size > max_size {
            return Err(ErrorInfo::new(
                ErrorCode::MaximumMessageLengthExceeded.code(),
                format!("Message size {} exceeds maximum {}", total_size, max_size),
            ));
        }

        // RSL1k1: library-generated idempotent ids — one random base per
        // publish, message index as the serial suffix. Client-supplied ids
        // are preserved (RSL1k).
        if rest.inner.opts.idempotent_rest_publishing {
            let base = idempotent_id_base();
            for (i, msg) in messages.iter_mut().enumerate() {
                if msg.id.is_none() {
                    msg.id = Some(format!("{}:{}", base, i));
                }
            }
        }

        // RSL5: cipher from the builder, falling back to the channel's
        let cipher = self.cipher.as_ref().or(self.channel.cipher.as_ref());
        let format = rest.inner.opts.format;
        let wire: Vec<Message> = messages
            .iter()
            .map(|m| m.encode_for_wire_with(format, cipher))
            .collect::<Result<_>>()?;

        // A single message is sent as an object, multiple as an array
        let body = if single {
            rest.serialize_body(&wire[0])?
        } else {
            rest.serialize_body(&wire)?
        };

        let params: Vec<(&str, &str)> = self
            .params
            .as_ref()
            .map(|p| p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
            .unwrap_or_default();

        let resp = rest
            .do_request("POST", &path, &[], &params, Some(body))
            .await?;
        // RSL1n: the response carries the serials of the published messages
        if resp.body.is_empty() {
            return Ok(PublishResult::default());
        }
        Ok(rest.deserialize_response(&resp).unwrap_or_default())
    }
}

/// RSL1k1: the random base for library-generated message ids — at least
/// 9 bytes of entropy, base64url encoded.
pub(crate) fn idempotent_id_base() -> String {
    let mut buf = [0u8; 9];
    rand::thread_rng().fill(&mut buf);
    base64::encode_config(buf, base64::URL_SAFE_NO_PAD)
}

/// TM6: the size of a message is the sum of its name, clientId,
/// JSON-stringified extras, and data lengths.
pub(crate) fn message_size(msg: &Message) -> u64 {
    let name = msg.name.as_deref().map(str::len).unwrap_or(0);
    let client_id = msg.client_id.as_deref().map(str::len).unwrap_or(0);
    (name + client_id + extras_size(msg.extras.as_ref()) + data_size(&msg.data)) as u64
}

fn extras_size(extras: Option<&serde_json::Value>) -> usize {
    extras
        .map(|e| serde_json::to_string(e).map(|s| s.len()).unwrap_or(0))
        .unwrap_or(0)
}

fn data_size(data: &Data) -> usize {
    match data {
        Data::String(s) => s.len(),
        Data::Binary(b) => b.len(),
        Data::JSON(v) => serde_json::to_string(v).map(|s| s.len()).unwrap_or(0),
        Data::None => 0,
    }
}

/// Result of a REST publish (RSL1n/PBR2): one serial per published message,
/// in order. A serial is None if the message was discarded by a conflation
/// rule.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishResult {
    #[serde(default)]
    pub serials: Vec<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

// --- Push ---

pub struct Push<'a> {
    rest: &'a Rest,
}

impl<'a> Push<'a> {
    pub fn admin(&self) -> PushAdmin<'a> {
        PushAdmin { rest: self.rest }
    }
}

pub struct PushAdmin<'a> {
    rest: &'a Rest,
}

impl<'a> PushAdmin<'a> {
    pub async fn publish(
        &self,
        recipient: serde_json::Value,
        data: serde_json::Value,
    ) -> Result<()> {
        // Validate recipient
        if let serde_json::Value::Object(ref map) = recipient {
            if map.is_empty() {
                return Err(ErrorInfo::new(
                    ErrorCode::BadRequest.code(),
                    "Push recipient must not be empty",
                ));
            }
        } else {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Push recipient must be a JSON object",
            ));
        }
        // Validate data
        if let serde_json::Value::Object(ref map) = data {
            if map.is_empty() {
                return Err(ErrorInfo::new(
                    ErrorCode::BadRequest.code(),
                    "Push data must not be empty",
                ));
            }
        }

        let mut payload = serde_json::Map::new();
        payload.insert("recipient".to_string(), recipient);
        // Merge data keys into payload
        if let serde_json::Value::Object(map) = data {
            for (k, v) in map {
                payload.insert(k, v);
            }
        }

        let body = self.rest.serialize_body(&payload)?;
        self.rest
            .do_request("POST", "/push/publish", &[], &[], Some(body))
            .await?;
        Ok(())
    }

    pub fn device_registrations(&self) -> PushDeviceRegistrations<'a> {
        PushDeviceRegistrations { rest: self.rest }
    }

    pub fn channel_subscriptions(&self) -> PushChannelSubscriptions<'a> {
        PushChannelSubscriptions { rest: self.rest }
    }
}

pub struct PushDeviceRegistrations<'a> {
    rest: &'a Rest,
}

impl<'a> PushDeviceRegistrations<'a> {
    pub async fn get(&self, device_id: &str) -> Result<serde_json::Value> {
        let path = format!(
            "/push/deviceRegistrations/{}",
            urlencoding::encode(device_id)
        );
        let resp = self.rest.do_request("GET", &path, &[], &[], None).await?;
        self.rest.deserialize_response(&resp)
    }

    pub fn list(&self) -> PaginatedRequestBuilder<'_, serde_json::Value> {
        PaginatedRequestBuilder {
            rest: self.rest,
            path: "/push/deviceRegistrations".to_string(),
            params: Vec::new(),
            cipher: None,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn save(&self, device: &serde_json::Value) -> Result<serde_json::Value> {
        let device_id = device["id"]
            .as_str()
            .ok_or_else(|| ErrorInfo::new(ErrorCode::BadRequest.code(), "Device id is required"))?;
        let path = format!(
            "/push/deviceRegistrations/{}",
            urlencoding::encode(device_id)
        );
        let body = self.rest.serialize_body(device)?;
        let resp = self
            .rest
            .do_request("PUT", &path, &[], &[], Some(body))
            .await?;
        self.rest.deserialize_response(&resp)
    }

    pub async fn remove(&self, device_id: &str) -> Result<()> {
        let path = format!(
            "/push/deviceRegistrations/{}",
            urlencoding::encode(device_id)
        );
        self.rest
            .do_request("DELETE", &path, &[], &[], None)
            .await?;
        Ok(())
    }

    pub async fn remove_where(&self, filter: &[(&str, &str)]) -> Result<()> {
        self.rest
            .do_request("DELETE", "/push/deviceRegistrations", &[], filter, None)
            .await?;
        Ok(())
    }
}

pub struct PushChannelSubscriptions<'a> {
    rest: &'a Rest,
}

impl<'a> PushChannelSubscriptions<'a> {
    pub fn list(&self) -> PaginatedRequestBuilder<'_, serde_json::Value> {
        PaginatedRequestBuilder {
            rest: self.rest,
            path: "/push/channelSubscriptions".to_string(),
            params: Vec::new(),
            cipher: None,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn list_channels(&self) -> PaginatedRequestBuilder<'_, serde_json::Value> {
        PaginatedRequestBuilder {
            rest: self.rest,
            path: "/push/channels".to_string(),
            params: Vec::new(),
            cipher: None,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn save(&self, sub: &serde_json::Value) -> Result<serde_json::Value> {
        let body = self.rest.serialize_body(sub)?;
        let resp = self
            .rest
            .do_request("POST", "/push/channelSubscriptions", &[], &[], Some(body))
            .await?;
        self.rest.deserialize_response(&resp)
    }

    pub async fn remove(&self, sub: &serde_json::Value) -> Result<()> {
        let mut params: Vec<(&str, &str)> = Vec::new();
        let channel = sub["channel"].as_str().unwrap_or("");
        let device_id = sub["deviceId"].as_str().unwrap_or("");
        let client_id = sub["clientId"].as_str().unwrap_or("");
        if !channel.is_empty() {
            params.push(("channel", channel));
        }
        if !device_id.is_empty() {
            params.push(("deviceId", device_id));
        }
        if !client_id.is_empty() {
            params.push(("clientId", client_id));
        }
        self.rest
            .do_request("DELETE", "/push/channelSubscriptions", &[], &params, None)
            .await?;
        Ok(())
    }

    pub async fn remove_where(&self, filter: &[(&str, &str)]) -> Result<()> {
        self.rest
            .do_request("DELETE", "/push/channelSubscriptions", &[], filter, None)
            .await?;
        Ok(())
    }
}

// --- Data types ---

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
#[derive(Default)]
#[allow(clippy::upper_case_acronyms)] // Data::JSON is the established API name
pub enum Data {
    String(String),
    JSON(serde_json::Value),
    Binary(serde_bytes::ByteBuf),
    #[default]
    None,
}

impl<'de> serde::Deserialize<'de> for Data {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct DataVisitor;

        impl<'de> de::Visitor<'de> for DataVisitor {
            type Value = Data;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string, JSON value, bytes, or null")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Data, E> {
                Ok(Data::String(v.to_owned()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Data, E> {
                Ok(Data::String(v))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<Data, E> {
                Ok(Data::Binary(serde_bytes::ByteBuf::from(v.to_vec())))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> std::result::Result<Data, E> {
                Ok(Data::Binary(serde_bytes::ByteBuf::from(v)))
            }

            fn visit_none<E: de::Error>(self) -> std::result::Result<Data, E> {
                Ok(Data::None)
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Data, E> {
                Ok(Data::None)
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Data, E> {
                Ok(Data::JSON(serde_json::Value::Bool(v)))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Data, E> {
                Ok(Data::JSON(serde_json::json!(v)))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Data, E> {
                Ok(Data::JSON(serde_json::json!(v)))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Data, E> {
                Ok(Data::JSON(serde_json::json!(v)))
            }

            fn visit_map<A: de::MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<Data, A::Error> {
                let value =
                    serde_json::Value::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(Data::JSON(value))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> std::result::Result<Data, A::Error> {
                let value =
                    serde_json::Value::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(Data::JSON(value))
            }
        }

        deserializer.deserialize_any(DataVisitor)
    }
}

impl Data {
    pub fn is_none(&self) -> bool {
        matches!(self, Data::None)
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Data::Binary(serde_bytes::ByteBuf::from(v))
    }
}

impl From<&[u8]> for Data {
    fn from(v: &[u8]) -> Self {
        Data::Binary(serde_bytes::ByteBuf::from(v.to_vec()))
    }
}

/// Message action (TM5). Numeric values are the wire-protocol values, in order
/// from zero: MESSAGE_CREATE, MESSAGE_UPDATE, MESSAGE_DELETE, META,
/// MESSAGE_SUMMARY, MESSAGE_APPEND.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
pub enum MessageAction {
    Create = 0,
    Update = 1,
    Delete = 2,
    Meta = 3,
    Summary = 4,
    Append = 5,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MessageOperation {
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Result of an update/delete/append message operation (RSL15e, UDR2).
/// `version_serial` is None if the message was superseded by a subsequent
/// update before it could be published (UDR2a).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateDeleteResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(
        rename = "versionSerial",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub version_serial: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum AnnotationAction {
    Create = 0,
    Delete = 1,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Annotation {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub annotation_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<AnnotationAction>,
    /// TAN2j: the serial of the message being annotated.
    #[serde(rename = "messageSerial", skip_serializing_if = "Option::is_none")]
    pub message_serial: Option<String>,
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Data::is_none")]
    pub data: Data,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Data::is_none")]
    pub data: Data,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<MessageAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

/// Append one encoding step to an existing encoding chain (RSL4).
pub(crate) fn append_encoding(existing: Option<String>, enc: &str) -> String {
    match existing {
        Some(e) if !e.is_empty() => format!("{}/{}", e, enc),
        _ => enc.to_string(),
    }
}

/// RSL4/RSL5: encode a payload for the wire. JSON data is stringified with
/// "json" appended (RSL4d); with a cipher the payload is encrypted, appending
/// "utf-8" (for string data) and "cipher+<algorithm>" (RSL5b/RSL5c); binary
/// data is base64-encoded only under the JSON wire format (RSL4c).
pub(crate) fn encode_data_for_wire(
    data: Data,
    encoding: Option<String>,
    format: Format,
    cipher: Option<&CipherParams>,
) -> Result<(Data, Option<String>)> {
    let mut data = data;
    let mut encoding = encoding;

    // RSL4a: payloads must be binary, strings, or JSON objects/arrays. A
    // JSON string is a string payload; null is an empty payload; numbers
    // and booleans are not permitted.
    if let Data::JSON(v) = &data {
        match v {
            serde_json::Value::String(st) => data = Data::String(st.clone()),
            serde_json::Value::Null => data = Data::None,
            serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
                return Err(ErrorInfo::with_status(
                    ErrorCode::InvalidMessageDataOrEncoding.code(),
                    400,
                    "Message data must be a string, binary, or a JSON object or array",
                ));
            }
            _ => {}
        }
    }
    if let Data::JSON(v) = &data {
        let s = serde_json::to_string(v).unwrap_or_default();
        data = Data::String(s);
        encoding = Some(append_encoding(encoding, "json"));
    }

    if let Some(cipher) = cipher {
        let plain: Option<Vec<u8>> = match &data {
            Data::String(s) => {
                let bytes = s.as_bytes().to_vec();
                encoding = Some(append_encoding(encoding, "utf-8"));
                Some(bytes)
            }
            Data::Binary(b) => Some(b.to_vec()),
            Data::None => None,
            Data::JSON(_) => unreachable!("JSON data stringified above"),
        };
        if let Some(plain) = plain {
            let ciphertext = cipher.encrypt(None, &plain)?;
            data = Data::Binary(serde_bytes::ByteBuf::from(ciphertext));
            encoding = Some(append_encoding(encoding, &cipher.encoding()));
        }
    }

    if format == Format::JSON {
        if let Data::Binary(b) = &data {
            let encoded = base64::encode(b.as_ref());
            data = Data::String(encoded);
            encoding = Some(append_encoding(encoding, "base64"));
        }
    }

    Ok((data, encoding))
}

/// RSL6: decode an encoding chain, rightmost step first. On an unrecognised
/// or failed step, processing stops and the *unprocessed* prefix of the chain
/// remains in the returned encoding (RSL6b) — already-applied right-hand
/// steps are not restored.
pub(crate) fn decode_data(
    data: Data,
    encoding: Option<String>,
    cipher: Option<&CipherParams>,
) -> (Data, Option<String>) {
    let encoding_str = match encoding {
        Some(e) if !e.is_empty() => e,
        _ => return (data, None),
    };
    let parts: Vec<&str> = encoding_str.split('/').collect();
    let mut current = data;
    let mut idx = parts.len();
    while idx > 0 {
        let step = parts[idx - 1];
        let applied: Option<Data> = match step {
            "base64" => match &current {
                Data::String(s) => base64::decode(s)
                    .ok()
                    .map(|b| Data::Binary(serde_bytes::ByteBuf::from(b))),
                _ => None,
            },
            "json" => match &current {
                Data::String(s) => serde_json::from_str(s).ok().map(Data::JSON),
                Data::Binary(b) => std::str::from_utf8(b)
                    .ok()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .map(Data::JSON),
                _ => None,
            },
            "utf-8" => match &current {
                Data::Binary(b) => String::from_utf8(b.to_vec()).ok().map(Data::String),
                // Already a string (e.g. delivered natively over msgpack)
                Data::String(_) => Some(current.clone()),
                _ => None,
            },
            s if s.starts_with("cipher+") => match (cipher, &current) {
                (Some(c), Data::Binary(b)) => {
                    let mut buf = b.to_vec();
                    c.decrypt(&mut buf)
                        .ok()
                        .map(|plain| Data::Binary(serde_bytes::ByteBuf::from(plain)))
                }
                _ => None,
            },
            _ => None,
        };
        match applied {
            Some(d) => {
                current = d;
                idx -= 1;
            }
            None => break,
        }
    }
    let residual = if idx == 0 {
        None
    } else {
        Some(parts[..idx].join("/"))
    };
    (current, residual)
}

impl Message {
    /// RSL4: produce the wire form of this message, leaving `self` untouched.
    pub(crate) fn encode_for_wire(&self, format: Format) -> Message {
        self.encode_for_wire_with(format, None)
            .expect("encoding without a cipher cannot fail")
    }

    /// RSL4/RSL5: wire form with optional encryption.
    pub(crate) fn encode_for_wire_with(
        &self,
        format: Format,
        cipher: Option<&CipherParams>,
    ) -> Result<Message> {
        let mut msg = self.clone();
        let (data, encoding) = encode_data_for_wire(
            std::mem::take(&mut msg.data),
            msg.encoding.take(),
            format,
            cipher,
        )?;
        msg.data = data;
        msg.encoding = encoding;
        Ok(msg)
    }

    pub fn from_encoded(
        data: serde_json::Value,
        cipher: Option<&crate::crypto::CipherParams>,
    ) -> Result<Self> {
        let mut msg: Message = serde_json::from_value(data)?;
        msg.decode_with_cipher(cipher);
        Ok(msg)
    }

    /// Decode the message data according to the encoding chain (RSL6).
    pub fn decode(&mut self) {
        self.decode_with_cipher(None);
    }

    /// RSL6: decode, decrypting cipher steps with the given params.
    pub fn decode_with_cipher(&mut self, cipher: Option<&CipherParams>) {
        let (data, encoding) =
            decode_data(std::mem::take(&mut self.data), self.encoding.take(), cipher);
        self.data = data;
        self.encoding = encoding;
        self.default_version();
    }

    /// TM2s: a received message without a complete `version` gets one
    /// initialized from its own fields — `version.serial` from the TM2r
    /// serial (TM2s1) and `version.timestamp` from the TM2f timestamp
    /// (TM2s2), each only when set. Runs after TM2 field inheritance, so
    /// inherited timestamps participate.
    fn default_version(&mut self) {
        let serial = self.serial.clone();
        let timestamp = self.timestamp;
        if serial.is_none() && timestamp.is_none() && self.version.is_none() {
            return;
        }
        let version = self
            .version
            .get_or_insert_with(|| serde_json::Value::Object(Default::default()));
        if let Some(map) = version.as_object_mut() {
            if !map.contains_key("serial") {
                if let Some(s) = serial {
                    map.insert("serial".into(), serde_json::Value::String(s));
                }
            }
            if !map.contains_key("timestamp") {
                if let Some(t) = timestamp {
                    map.insert("timestamp".into(), t.into());
                }
            }
        }
    }
}

impl Decodable for Message {
    fn decode_item(&mut self, cipher: Option<&CipherParams>) {
        self.decode_with_cipher(cipher);
    }
}

impl Decodable for PresenceMessage {
    fn decode_item(&mut self, cipher: Option<&CipherParams>) {
        self.decode_with_cipher(cipher);
    }
}
impl Decodable for Annotation {
    fn decode_item(&mut self, _cipher: Option<&CipherParams>) {
        // RSL6-style decode; annotations are not encrypted, so no cipher
        let (data, encoding) =
            decode_data(std::mem::take(&mut self.data), self.encoding.take(), None);
        self.data = data;
        self.encoding = encoding;
    }
}
impl Decodable for Stats {}
impl Decodable for serde_json::Value {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<PresenceAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Data::is_none")]
    pub data: Data,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Value>,
}

impl PresenceMessage {
    pub fn member_key(&self) -> String {
        format!(
            "{}:{}",
            self.connection_id.as_deref().unwrap_or(""),
            self.client_id.as_deref().unwrap_or("")
        )
    }

    /// TP5: the size of a presence message, calculated as for Message (TM6) —
    /// the sum of its clientId, JSON-stringified extras, and data lengths.
    pub fn size(&self) -> u64 {
        let client_id = self.client_id.as_deref().map(str::len).unwrap_or(0);
        (client_id + extras_size(self.extras.as_ref()) + data_size(&self.data)) as u64
    }

    /// Decode the presence message data according to the encoding chain (RSL6).
    pub fn decode(&mut self) {
        self.decode_with_cipher(None);
    }

    /// RSL6: decode, decrypting cipher steps with the given params.
    pub fn decode_with_cipher(&mut self, cipher: Option<&CipherParams>) {
        let (data, encoding) =
            decode_data(std::mem::take(&mut self.data), self.encoding.take(), cipher);
        self.data = data;
        self.encoding = encoding;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum PresenceAction {
    Absent = 0,
    Present = 1,
    Enter = 2,
    Leave = 3,
    Update = 4,
}

pub struct ChannelOptions {
    pub cipher: Option<CipherParams>,
}

/// Response to a batch presence request (RSC24, BAR2): a BatchResult envelope
/// with server-provided counts and per-channel results.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPresenceResponse {
    pub success_count: u32,
    pub failure_count: u32,
    pub results: Vec<BatchPresenceResult>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum BatchPresenceResult {
    Success(BatchPresenceSuccessResult),
    Failure(BatchPresenceFailureResult),
}

// A per-channel result is a failure iff it carries an `error` member (BGF2);
// serde's untagged matching can't make that distinction reliably, so
// discriminate explicitly.
impl<'de> serde::Deserialize<'de> for BatchPresenceResult {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        if v.get("error").is_some() {
            serde_json::from_value(v)
                .map(BatchPresenceResult::Failure)
                .map_err(serde::de::Error::custom)
        } else {
            serde_json::from_value(v)
                .map(BatchPresenceResult::Success)
                .map_err(serde::de::Error::custom)
        }
    }
}

/// Successful per-channel batch presence result (BGR2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchPresenceSuccessResult {
    pub channel: String,
    #[serde(default)]
    pub presence: Vec<PresenceMessage>,
}

/// Failed per-channel batch presence result (BGF2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchPresenceFailureResult {
    pub channel: String,
    pub error: ErrorInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchPublishSpec {
    pub channels: Vec<String>,
    pub messages: Vec<Message>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum BatchPublishResult {
    Success(BatchPublishSuccessResult),
    Failure(BatchPublishFailureResult),
}

// Failure iff the result carries an `error` member (BPF2) — see
// BatchPresenceResult for why untagged deserialization is not used.
impl<'de> serde::Deserialize<'de> for BatchPublishResult {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        if v.get("error").is_some() {
            serde_json::from_value(v)
                .map(BatchPublishResult::Failure)
                .map_err(serde::de::Error::custom)
        } else {
            serde_json::from_value(v)
                .map(BatchPublishResult::Success)
                .map_err(serde::de::Error::custom)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPublishSuccessResult {
    pub channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serials: Option<Vec<Option<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchPublishFailureResult {
    pub channel: String,
    pub error: ErrorInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeTokensRequest {
    pub targets: Vec<String>,
    #[serde(rename = "issuedBefore", skip_serializing_if = "Option::is_none")]
    pub issued_before: Option<i64>,
    #[serde(rename = "allowReauthMargin", skip_serializing_if = "Option::is_none")]
    pub allow_reauth_margin: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeTokensResponse {
    pub success_count: u32,
    pub failure_count: u32,
    pub results: Vec<RevokeTokenResult>,
}

impl RevokeTokensResponse {
    pub fn len(&self) -> usize {
        self.results.len()
    }

    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeTokenResult {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applies_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

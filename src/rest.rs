use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::auth::{self, Auth, Credential, TokenDetails};
use crate::crypto::CipherParams;
use crate::error::{ErrorCode, ErrorInfo, Result, WrappedError};
use crate::http::{Decodable, PaginatedRequestBuilder, RequestBuilder, PaginatedResult, Response};
use crate::http_client::{HttpClient, HttpRequest, HttpResponse};
use crate::options::ClientOptions;
use crate::stats::Stats;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Format {
    MessagePack,
    JSON,
}

impl Default for Format {
    fn default() -> Self {
        Format::MessagePack
    }
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
    pub(crate) saved_token_params: Option<auth::TokenParams>,
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
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn time(&self) -> Result<DateTime<Utc>> {
        let resp = self.do_request("GET", "/time", &[], &[], None).await?;
        let timestamps: Vec<i64> = self.deserialize_response(&resp)?;
        if let Some(&ts) = timestamps.first() {
            DateTime::from_timestamp_millis(ts).ok_or_else(|| {
                ErrorInfo::new(ErrorCode::InternalError.code(), "Invalid timestamp from server")
            })
        } else {
            Err(ErrorInfo::new(
                ErrorCode::InternalError.code(),
                "Empty time response from server",
            ))
        }
    }

    pub async fn batch_presence(&self, channels: &[&str]) -> Result<Vec<BatchPresenceResult>> {
        let params: Vec<(&str, &str)> = channels.iter().map(|c| ("channels", *c)).collect();
        let resp = self.do_request("GET", "/presence", &[], &params, None).await?;
        self.deserialize_response(&resp)
    }

    pub async fn batch_publish(
        &self,
        specs: Vec<BatchPublishSpec>,
    ) -> Result<Vec<BatchPublishResult>> {
        let body = self.serialize_body(&specs)?;
        let resp = self.do_request("POST", "/messages", &[], &[], Some(body)).await?;
        self.deserialize_response(&resp)
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

    pub(crate) fn auth_options(&self) -> crate::auth::AuthOptions {
        crate::auth::AuthOptions::default()
    }

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

    pub(crate) fn deserialize_response<T: DeserializeOwned>(&self, resp: &HttpResponse) -> Result<T> {
        // Check response content-type to determine deserializer
        let ct = resp.headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        if ct.contains("application/x-msgpack") {
            Ok(rmp_serde::from_slice(&resp.body)?)
        } else if ct.contains("application/json") {
            Ok(serde_json::from_slice(&resp.body)?)
        } else {
            serde_json::from_slice(&resp.body)
                .or_else(|_| rmp_serde::from_slice(&resp.body).map_err(|e| ErrorInfo::new(
                    ErrorCode::InvalidMessageDataOrEncoding.code(),
                    format!("Failed to deserialize response (content-type '{}'): {}", ct, e),
                )))
        }
    }

    /// Get authorization header value for the current request.
    /// This handles basic auth vs token auth, and token acquisition.
    pub(crate) async fn get_auth_header(&self) -> Result<String> {
        let opts = &self.inner.opts;
        match &opts.credential {
            Credential::Key(key) if !opts.use_token_auth && opts.client_id.is_none() => {
                // Basic auth
                Ok(format!("Basic {}", base64::encode(format!("{}:{}", key.name, key.value))))
            }
            Credential::TokenDetails(td) => {
                Ok(format!("Bearer {}", td.token))
            }
            _ => {
                // Token auth: check for cached token first
                {
                    let state = self.inner.auth_state.lock().unwrap();
                    if let Some(ref td) = state.cached_token {
                        if !td.token.is_empty() {
                            return Ok(format!("Bearer {}", td.token));
                        }
                    }
                }
                // Need to obtain a token
                let td = self.obtain_token(&auth::TokenParams::default(), &auth::AuthOptions::default()).await?;
                {
                    let mut state = self.inner.auth_state.lock().unwrap();
                    state.cached_token = Some(td.clone());
                }
                Ok(format!("Bearer {}", td.token))
            }
        }
    }

    /// Obtain a token via the configured auth mechanism.
    pub(crate) async fn obtain_token(&self, params: &auth::TokenParams, _options: &auth::AuthOptions) -> Result<TokenDetails> {
        match &self.inner.opts.credential {
            Credential::Key(key) => {
                // Create a token request locally, then POST it
                let token_request = self.auth().create_token_request(params, &auth::AuthOptions::default())?;
                let body = self.serialize_body(&token_request)?;
                let path = format!("/keys/{}/requestToken", key.name);
                // Make the request with basic auth for the requestToken call
                let auth_header = format!("Basic {}", base64::encode(format!("{}:{}", key.name, key.value)));
                let resp = self.do_request_with_auth("POST", &path, &[], &[], Some(body), &auth_header).await?;
                let td: TokenDetails = self.deserialize_response(&resp)?;
                Ok(td)
            }
            Credential::Callback(cb) => {
                let token_result = cb.token(params).await.map_err(|e| {
                    let mut err = ErrorInfo::with_cause(
                        ErrorCode::ErrorFromClientTokenCallback.code(),
                        format!("Auth callback error: {}", e.message.as_deref().unwrap_or("unknown")),
                        e,
                    );
                    err.status_code = Some(401);
                    err
                })?;
                match token_result {
                    auth::AuthToken::Details(td) => Ok(td),
                    auth::AuthToken::Request(tr) => {
                        // POST the token request
                        let body = self.serialize_body(&tr)?;
                        let path = format!("/keys/{}/requestToken", tr.key_name);
                        let resp = self.do_request_internal("POST", &path, &[], &[], Some(body), None).await?;
                        let td: TokenDetails = self.deserialize_response(&resp)?;
                        Ok(td)
                    }
                }
            }
            Credential::TokenDetails(td) => {
                Ok(td.clone())
            }
            _ => {
                Err(ErrorInfo::new(
                    ErrorCode::NoWayToRenewAuthToken.code(),
                    "No way to renew auth token",
                ))
            }
        }
    }

    /// Can the client renew its token?
    fn can_renew_token(&self) -> bool {
        matches!(&self.inner.opts.credential, Credential::Key(_) | Credential::Callback(_))
    }

    /// Build the base URL for a request.
    fn build_url(&self, host: &str, path: &str, params: &[(&str, &str)]) -> Result<url::Url> {
        let scheme = if self.inner.opts.tls { "https" } else { "http" };
        let port = if self.inner.opts.tls {
            self.inner.opts.tls_port
        } else {
            self.inner.opts.port
        };

        let path = if path.starts_with('/') { path.to_string() } else { format!("/{}", path) };

        let url_str = if (self.inner.opts.tls && port == 443) || (!self.inner.opts.tls && port == 80) {
            format!("{}://{}{}", scheme, host, path)
        } else {
            format!("{}://{}:{}{}", scheme, host, port, path)
        };

        let mut url = url::Url::parse(&url_str)?;

        // Add params
        for (k, v) in params {
            url.query_pairs_mut().append_pair(k, v);
        }

        // Add request_id if configured
        if self.inner.opts.add_request_ids {
            let mut buf = [0u8; 16];
            rand::thread_rng().fill(&mut buf);
            let request_id = base64::encode_config(&buf, base64::URL_SAFE_NO_PAD);
            url.query_pairs_mut().append_pair("request_id", &request_id);
        }

        Ok(url)
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
        let result = self.do_request_with_auth(method, path, headers, params, body.clone(), &auth_header).await;

        // Handle token errors (401 with 40140-40149)
        match &result {
            Err(e) if e.status_code == Some(401) => {
                let code = e.code.unwrap_or(0);
                if code >= 40140 && code <= 40149 && self.can_renew_token() {
                    // Clear cached token and try to get a new one
                    {
                        let mut state = self.inner.auth_state.lock().unwrap();
                        state.cached_token = None;
                    }
                    let new_auth = self.get_auth_header().await?;
                    return self.do_request_with_auth(method, path, headers, params, body, &new_auth).await;
                }
                result
            }
            _ => result,
        }
    }

    /// do_request with explicit auth header (used for requestToken calls).
    async fn do_request_with_auth(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        params: &[(&str, &str)],
        body: Option<Vec<u8>>,
        auth_header: &str,
    ) -> Result<HttpResponse> {
        self.do_request_internal(method, path, headers, params, body, Some(auth_header)).await
    }

    /// Internal request method with retry/fallback logic.
    async fn do_request_internal(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        params: &[(&str, &str)],
        body: Option<Vec<u8>>,
        auth_header: Option<&str>,
    ) -> Result<HttpResponse> {
        // Build standard headers
        let mut all_headers: Vec<(String, String)> = vec![
            ("x-ably-version".to_string(), "6".to_string()),
            ("ably-agent".to_string(), format!("ably-rust/{}", env!("CARGO_PKG_VERSION"))),
            ("accept".to_string(), self.accept_type().to_string()),
        ];

        if body.is_some() {
            all_headers.push(("content-type".to_string(), self.content_type().to_string()));
        }

        if let Some(auth) = auth_header {
            all_headers.push(("authorization".to_string(), auth.to_string()));
        }

        // Add X-Ably-ClientId if set (RSC17)
        if let Some(ref client_id) = self.inner.opts.client_id {
            all_headers.push(("x-ably-clientid".to_string(), base64::encode(client_id)));
        }

        // Add extra headers (lowercase names for consistency)
        for (k, v) in extra_headers {
            all_headers.push((k.to_lowercase(), v.to_string()));
        }

        let primary_host = self.inner.opts.rest_host.clone();

        // RSC15f: Check for a cached successful fallback host
        let first_host = {
            let fb = self.inner.fallback_state.lock().unwrap();
            match &*fb {
                Some(cached) if cached.expires > std::time::Instant::now() => cached.host.clone(),
                _ => primary_host.clone(),
            }
        };

        let url = self.build_url(&first_host, path, params)?;
        let req = HttpRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: all_headers.clone(),
            body: body.clone(),
        };

        let mut last_error;
        let timeout_duration = self.inner.opts.http_request_timeout;
        let result = tokio::time::timeout(
            timeout_duration,
            self.inner.http_client.execute(req),
        ).await;
        match result {
            Ok(Ok(resp)) => {
                let retriable = Self::is_retriable_response(&resp);
                match self.check_response(resp) {
                    Ok(outcome) => return Ok(outcome),
                    Err(e) => {
                        if !retriable && !Self::is_retriable_error(&e) {
                            return Err(e);
                        }
                        last_error = e;
                    }
                }
            }
            Ok(Err(network_err)) => {
                // Network error - fall through to fallback
                last_error = ErrorInfo::with_status(
                    ErrorCode::InternalError.code(),
                    500,
                    format!("Network error: {}", network_err),
                );
            }
            Err(_elapsed) => {
                // Timeout - fall through to fallback
                last_error = ErrorInfo::with_status(
                    ErrorCode::TimeoutError.code(),
                    408,
                    "Request timed out".to_string(),
                );
            }
        }

        // Build the retry host list.
        // If we used a cached fallback as first_host, include primary in the retry list.
        let fallback_hosts = &self.inner.opts.fallback_hosts;
        use rand::seq::SliceRandom;
        let mut retry_hosts: Vec<String> = Vec::new();
        if first_host != primary_host {
            // Cached fallback failed — clear the cache and try primary first
            {
                let mut fb = self.inner.fallback_state.lock().unwrap();
                *fb = None;
            }
            retry_hosts.push(primary_host.clone());
        }
        let mut remaining: Vec<&String> = fallback_hosts.iter()
            .filter(|h| h.as_str() != first_host)
            .collect();
        remaining.shuffle(&mut rand::thread_rng());
        retry_hosts.extend(remaining.into_iter().cloned());

        if retry_hosts.is_empty() {
            return Err(last_error);
        }

        let max_retries = self.inner.opts.http_max_retry_count.min(retry_hosts.len());

        for host in retry_hosts.iter().take(max_retries) {
            let url = self.build_url(host, path, params)?;
            let req = HttpRequest {
                method: method.to_string(),
                url: url.to_string(),
                headers: all_headers.clone(),
                body: body.clone(),
            };

            let result = tokio::time::timeout(
                timeout_duration,
                self.inner.http_client.execute(req),
            ).await;
            match result {
                Ok(Ok(resp)) => {
                    let retriable = Self::is_retriable_response(&resp);
                    match self.check_response(resp) {
                        Ok(resp) => {
                            // Cache successful fallback host
                            let mut fb = self.inner.fallback_state.lock().unwrap();
                            *fb = Some(CachedFallback {
                                host: host.to_string(),
                                expires: std::time::Instant::now() + self.inner.opts.fallback_retry_timeout,
                            });
                            return Ok(resp);
                        }
                        Err(e) => {
                            if !retriable && !Self::is_retriable_error(&e) {
                                return Err(e);
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
                    // Timeout on fallback, continue trying
                    last_error = ErrorInfo::with_status(
                        ErrorCode::TimeoutError.code(),
                        408,
                        "Request timed out".to_string(),
                    );
                    continue;
                }
            }
        }

        Err(last_error)
    }

    /// Check an HTTP response, returning Ok(resp) for success or Err for errors.
    fn check_response(&self, resp: HttpResponse) -> Result<HttpResponse> {
        if resp.status >= 200 && resp.status < 300 {
            // Check for unsupported content type on success
            let ct = resp.headers.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            if !resp.body.is_empty() && !ct.is_empty()
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
        let ct = resp.headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        if ct.contains("application/json") || ct.contains("application/x-msgpack") {
            let parsed: std::result::Result<WrappedError, _> = if ct.contains("application/x-msgpack") {
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
        if resp.status >= 500 {
            return true;
        }
        // RSC15l4: CloudFront errors (status >= 400 with Server: CloudFront) are retriable
        if resp.status >= 400 {
            let is_cloudfront = resp.headers.iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("server") && v.contains("CloudFront"));
            if is_cloudfront {
                return true;
            }
        }
        false
    }

    fn is_retriable_error(err: &ErrorInfo) -> bool {
        if let Some(status) = err.status_code {
            status >= 500
        } else {
            false
        }
    }
}

impl Clone for Rest {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
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
        }
    }

    pub fn history(&self) -> PaginatedRequestBuilder<'_, Message> {
        let path = format!("/channels/{}/history", urlencoding::encode(&self.name));
        PaginatedRequestBuilder {
            rest: self.rest,
            path,
            params: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn get_message(&self, serial: &str) -> Result<Message> {
        if serial.is_empty() {
            return Err(ErrorInfo::new(ErrorCode::BadRequest.code(), "Message serial is required"));
        }
        let path = format!("/channels/{}/messages/{}", urlencoding::encode(&self.name), urlencoding::encode(serial));
        let resp = self.rest.do_request("GET", &path, &[], &[], None).await?;
        let mut msg: Message = self.rest.deserialize_response(&resp)?;
        msg.decode();
        Ok(msg)
    }

    pub fn message_versions(&self, serial: &str) -> PaginatedRequestBuilder<'_, Message> {
        let path = format!("/channels/{}/messages/{}/versions", urlencoding::encode(&self.name), urlencoding::encode(serial));
        PaginatedRequestBuilder {
            rest: self.rest,
            path,
            params: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn update_message(
        &self,
        msg: &Message,
        op: &MessageOperation,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        let serial = msg.serial.as_deref().unwrap_or("");
        if serial.is_empty() {
            return Err(ErrorInfo::new(ErrorCode::BadRequest.code(), "Message serial is required"));
        }
        let path = format!("/channels/{}/messages/{}", urlencoding::encode(&self.name), urlencoding::encode(serial));
        let mut body_map = serde_json::Map::new();
        body_map.insert("action".to_string(), serde_json::json!(MessageAction::Update));
        // Include version only if operation has non-default fields
        let op_value = serde_json::to_value(op).unwrap_or_default();
        if let Some(obj) = op_value.as_object() {
            if !obj.is_empty() && obj.values().any(|v| !v.is_null()) {
                body_map.insert("version".to_string(), op_value);
            }
        }
        let body = self.rest.serialize_body(&body_map)?;
        let params: Vec<(&str, &str)> = params.unwrap_or(&[]).to_vec();
        let resp = self.rest.do_request("PATCH", &path, &[], &params, Some(body)).await?;
        self.rest.deserialize_response(&resp)
    }

    pub async fn delete_message(
        &self,
        msg: &Message,
        op: &MessageOperation,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        let serial = msg.serial.as_deref().unwrap_or("");
        if serial.is_empty() {
            return Err(ErrorInfo::new(ErrorCode::BadRequest.code(), "Message serial is required"));
        }
        let path = format!("/channels/{}/messages/{}", urlencoding::encode(&self.name), urlencoding::encode(serial));
        let mut body_map = serde_json::Map::new();
        body_map.insert("action".to_string(), serde_json::json!(MessageAction::Delete));
        let op_value = serde_json::to_value(op).unwrap_or_default();
        if let Some(obj) = op_value.as_object() {
            if !obj.is_empty() && obj.values().any(|v| !v.is_null()) {
                body_map.insert("version".to_string(), op_value);
            }
        }
        let body = self.rest.serialize_body(&body_map)?;
        let params: Vec<(&str, &str)> = params.unwrap_or(&[]).to_vec();
        let resp = self.rest.do_request("PATCH", &path, &[], &params, Some(body)).await?;
        self.rest.deserialize_response(&resp)
    }

    pub async fn append_message(
        &self,
        msg: &Message,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        let serial = msg.serial.as_deref().unwrap_or("");
        let path = format!("/channels/{}/messages/{}", urlencoding::encode(&self.name), urlencoding::encode(serial));
        let mut body_map = serde_json::Map::new();
        body_map.insert("action".to_string(), serde_json::json!(MessageAction::MetaOccupancy));
        let body = self.rest.serialize_body(&body_map)?;
        let params: Vec<(&str, &str)> = params.unwrap_or(&[]).to_vec();
        let resp = self.rest.do_request("PATCH", &path, &[], &params, Some(body)).await?;
        self.rest.deserialize_response(&resp)
    }

    pub fn annotations(&self) -> RestAnnotations<'_> {
        RestAnnotations { channel: self }
    }

    pub fn presence(&self) -> Presence<'_> {
        Presence { channel: self }
    }
}

// --- Presence ---

pub struct Presence<'a> {
    channel: &'a Channel<'a>,
}

impl<'a> Presence<'a> {
    pub fn get(&self) -> PresenceRequestBuilder<'_> {
        let path = format!("/channels/{}/presence", urlencoding::encode(&self.channel.name));
        PresenceRequestBuilder {
            rest: self.channel.rest,
            path,
            params: Vec::new(),
        }
    }

    pub fn history(&self) -> PaginatedRequestBuilder<'_, PresenceMessage> {
        let path = format!("/channels/{}/presence/history", urlencoding::encode(&self.channel.name));
        PaginatedRequestBuilder {
            rest: self.channel.rest,
            path,
            params: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }
}

pub struct PresenceRequestBuilder<'a> {
    rest: &'a Rest,
    path: String,
    params: Vec<(String, String)>,
}

impl<'a> PresenceRequestBuilder<'a> {
    pub fn limit(mut self, limit: u32) -> Self {
        self.params.push(("limit".to_string(), limit.to_string()));
        self
    }
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.params.push(("clientId".to_string(), client_id.to_string()));
        self
    }
    pub fn connection_id(mut self, connection_id: &str) -> Self {
        self.params.push(("connectionId".to_string(), connection_id.to_string()));
        self
    }
    pub async fn send(self) -> Result<PaginatedResult<PresenceMessage>> {
        let params: Vec<(&str, &str)> = self.params.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let resp = self.rest.do_request("GET", &self.path, &[], &params, None).await?;
        let (next_rel_url, first_rel_url) = crate::http::parse_link_headers(&resp.headers);
        let mut items: Vec<PresenceMessage> = self.rest.deserialize_response(&resp)?;
        for item in &mut items {
            item.decode();
        }
        Ok(PaginatedResult {
            items,
            rest: self.rest.clone(),
            next_rel_url,
            first_rel_url,
            base_path: self.path,
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
        let body = self.channel.rest.serialize_body(&vec![ann])?;
        self.channel.rest.do_request("POST", &path, &[], &[], Some(body)).await?;
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
        let body = self.channel.rest.serialize_body(&vec![ann])?;
        self.channel.rest.do_request("POST", &path, &[], &[], Some(body)).await?;
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
        self.params = Some(params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
        self
    }

    pub fn cipher(self, _cipher: CipherParams) -> Self {
        self
    }

    pub async fn send(self) -> Result<()> {
        let path = format!("/channels/{}/messages", urlencoding::encode(&self.channel.name));

        // Build message body
        let mut msg = serde_json::Map::new();
        if let Some(id) = &self.id {
            msg.insert("id".to_string(), serde_json::Value::String(id.clone()));
        }
        if let Some(name) = &self.name {
            msg.insert("name".to_string(), serde_json::Value::String(name.clone()));
        }
        match &self.data {
            Data::String(s) => {
                msg.insert("data".to_string(), serde_json::Value::String(s.clone()));
            }
            Data::JSON(v) => {
                // RSL4b: JSON objects are serialized as a JSON string with encoding "json"
                let json_str = serde_json::to_string(v).unwrap_or_default();
                msg.insert("data".to_string(), serde_json::Value::String(json_str));
                msg.insert("encoding".to_string(), serde_json::Value::String("json".to_string()));
            }
            Data::Binary(b) => {
                let encoded = base64::encode(b.as_ref());
                msg.insert("data".to_string(), serde_json::Value::String(encoded));
                msg.insert("encoding".to_string(), serde_json::Value::String("base64".to_string()));
            }
            Data::None => {}
        }
        if let Some(extras) = &self.extras {
            msg.insert("extras".to_string(), serde_json::Value::Object(extras.clone()));
        }
        if let Some(client_id) = &self.client_id {
            msg.insert("clientId".to_string(), serde_json::Value::String(client_id.clone()));
        }

        let body = self.channel.rest.serialize_body(&msg)?;

        // RSL1i: Check message size against max
        let max_size = self.channel.rest.inner.opts.max_message_size;
        if body.len() as u64 > max_size {
            return Err(ErrorInfo::new(
                ErrorCode::MaximumMessageLengthExceeded.code(),
                format!("Message size {} exceeds maximum {}", body.len(), max_size),
            ));
        }

        let params: Vec<(&str, &str)> = self.params.as_ref()
            .map(|p| p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
            .unwrap_or_default();

        self.channel.rest.do_request("POST", &path, &[], &params, Some(body)).await?;
        Ok(())
    }
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
        self.rest.do_request("POST", "/push/publish", &[], &[], Some(body)).await?;
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
        let path = format!("/push/deviceRegistrations/{}", urlencoding::encode(device_id));
        let resp = self.rest.do_request("GET", &path, &[], &[], None).await?;
        self.rest.deserialize_response(&resp)
    }

    pub fn list(&self) -> PaginatedRequestBuilder<'_, serde_json::Value> {
        PaginatedRequestBuilder {
            rest: self.rest,
            path: "/push/deviceRegistrations".to_string(),
            params: Vec::new(),
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
        let resp = self.rest.do_request("PUT", &path, &[], &[], Some(body)).await?;
        self.rest.deserialize_response(&resp)
    }

    pub async fn remove(&self, device_id: &str) -> Result<()> {
        let path = format!("/push/deviceRegistrations/{}", urlencoding::encode(device_id));
        self.rest.do_request("DELETE", &path, &[], &[], None).await?;
        Ok(())
    }

    pub async fn remove_where(&self, filter: &[(&str, &str)]) -> Result<()> {
        self.rest.do_request("DELETE", "/push/deviceRegistrations", &[], filter, None).await?;
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
            _marker: std::marker::PhantomData,
        }
    }

    pub fn list_channels(&self) -> PaginatedRequestBuilder<'_, serde_json::Value> {
        PaginatedRequestBuilder {
            rest: self.rest,
            path: "/push/channels".to_string(),
            params: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn save(&self, sub: &serde_json::Value) -> Result<serde_json::Value> {
        let body = self.rest.serialize_body(sub)?;
        let resp = self.rest.do_request("POST", "/push/channelSubscriptions", &[], &[], Some(body)).await?;
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
        self.rest.do_request("DELETE", "/push/channelSubscriptions", &[], &params, None).await?;
        Ok(())
    }

    pub async fn remove_where(&self, filter: &[(&str, &str)]) -> Result<()> {
        self.rest.do_request("DELETE", "/push/channelSubscriptions", &[], filter, None).await?;
        Ok(())
    }
}

// --- Data types ---

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Data {
    String(String),
    JSON(serde_json::Value),
    Binary(serde_bytes::ByteBuf),
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

            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> std::result::Result<Data, A::Error> {
                let value = serde_json::Value::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(Data::JSON(value))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, seq: A) -> std::result::Result<Data, A::Error> {
                let value = serde_json::Value::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(Data::JSON(value))
            }
        }

        deserializer.deserialize_any(DataVisitor)
    }
}

impl Default for Data {
    fn default() -> Self {
        Data::None
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

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
pub enum MessageAction {
    Unset = 0,
    Create = 1,
    Update = 2,
    Delete = 3,
    Annotation = 4,
    MetaOccupancy = 5,
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

fn deserialize_null_string<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    Ok(opt.unwrap_or_default())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateDeleteResult {
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub serial: String,
    #[serde(rename = "versionSerial", default, deserialize_with = "deserialize_null_string")]
    pub version_serial: String,
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
    #[serde(rename = "msgSerial", skip_serializing_if = "Option::is_none")]
    pub msg_serial: Option<String>,
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

impl Message {
    pub fn from_encoded(
        data: serde_json::Value,
        _cipher: Option<&crate::crypto::CipherParams>,
    ) -> Result<Self> {
        let mut msg: Message = serde_json::from_value(data)?;
        msg.decode();
        Ok(msg)
    }

    /// Decode the message data according to the encoding chain.
    /// Processes encodings in reverse order (rightmost first): base64, json, utf-8, etc.
    pub fn decode(&mut self) {
        if let Some(encoding) = self.encoding.take() {
            let parts: Vec<&str> = encoding.split('/').collect();
            let mut current_data = std::mem::take(&mut self.data);

            for enc in parts.iter().rev() {
                match *enc {
                    "base64" => {
                        if let Data::String(s) = &current_data {
                            if let Ok(bytes) = base64::decode(s) {
                                current_data = Data::Binary(serde_bytes::ByteBuf::from(bytes));
                            }
                        }
                    }
                    "json" => {
                        match &current_data {
                            Data::String(s) => {
                                if let Ok(v) = serde_json::from_str(s) {
                                    current_data = Data::JSON(v);
                                }
                            }
                            Data::Binary(b) => {
                                if let Ok(s) = String::from_utf8(b.to_vec()) {
                                    if let Ok(v) = serde_json::from_str(&s) {
                                        current_data = Data::JSON(v);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    "utf-8" => {
                        if let Data::Binary(b) = &current_data {
                            if let Ok(s) = String::from_utf8(b.to_vec()) {
                                current_data = Data::String(s);
                            }
                        }
                    }
                    _ => {
                        // Unknown encoding - put it back and stop
                        self.encoding = Some(encoding.clone());
                        break;
                    }
                }
            }

            self.data = current_data;
        }
    }
}

impl Decodable for Message {
    fn decode_item(&mut self) {
        self.decode();
    }
}

impl Decodable for PresenceMessage {
    fn decode_item(&mut self) {
        self.decode();
    }
}
impl Decodable for Annotation {}
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

    /// Decode the presence message data according to the encoding chain.
    pub fn decode(&mut self) {
        if let Some(encoding) = self.encoding.take() {
            let parts: Vec<&str> = encoding.split('/').collect();
            let mut current_data = std::mem::take(&mut self.data);

            for enc in parts.iter().rev() {
                match *enc {
                    "base64" => {
                        if let Data::String(s) = &current_data {
                            if let Ok(bytes) = base64::decode(s) {
                                current_data = Data::Binary(serde_bytes::ByteBuf::from(bytes));
                            }
                        }
                    }
                    "json" => {
                        match &current_data {
                            Data::String(s) => {
                                if let Ok(v) = serde_json::from_str(s) {
                                    current_data = Data::JSON(v);
                                }
                            }
                            Data::Binary(b) => {
                                if let Ok(s) = String::from_utf8(b.to_vec()) {
                                    if let Ok(v) = serde_json::from_str(&s) {
                                        current_data = Data::JSON(v);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    "utf-8" => {
                        if let Data::Binary(b) = &current_data {
                            if let Ok(s) = String::from_utf8(b.to_vec()) {
                                current_data = Data::String(s);
                            }
                        }
                    }
                    _ => {
                        self.encoding = Some(encoding.clone());
                        break;
                    }
                }
            }

            self.data = current_data;
        }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchPresenceResult {
    pub channel: String,
    #[serde(default)]
    pub presence: Vec<PresenceMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchPublishSpec {
    pub channels: Vec<String>,
    pub messages: Vec<Message>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BatchPublishResult {
    Success(BatchPublishSuccessResult),
    Failure(BatchPublishFailureResult),
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

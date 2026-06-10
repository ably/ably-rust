use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{ErrorInfo, ErrorCode, Result};
use crate::http_client::HttpResponse;
use crate::rest::Rest;

pub(crate) trait Decodable {
    fn decode_item(&mut self, _cipher: Option<&crate::crypto::CipherParams>) {}
}

pub struct RequestBuilder<'a> {
    pub(crate) rest: &'a Rest,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) params: Vec<(String, String)>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) build_error: Option<ErrorInfo>,
}

impl<'a> RequestBuilder<'a> {
    pub fn params(mut self, params: &[(&str, &str)]) -> Self {
        for (k, v) in params {
            self.params.push((k.to_string(), v.to_string()));
        }
        self
    }

    pub fn body(mut self, body: &impl Serialize) -> Self {
        match self.rest.serialize_body(body) {
            Ok(b) => self.body = Some(b),
            Err(e) => self.build_error = Some(e),
        }
        self
    }

    pub fn headers(mut self, headers: &[(&str, &str)]) -> Self {
        for (k, v) in headers {
            self.headers.push((k.to_lowercase(), v.to_string()));
        }
        self
    }

    /// RSC19f1: override the protocol version sent with this request.
    pub fn version(mut self, version: u32) -> Self {
        self.headers
            .push(("x-ably-version".to_string(), version.to_string()));
        self
    }

    /// RSC19: execute the request, returning an HttpPaginatedResponse. HTTP
    /// error statuses are returned as a response with `success() == false`
    /// (HP4/HP5), not as an Err; only request failures (network, auth
    /// resolution) produce an Err.
    pub async fn send(self) -> Result<HttpPaginatedResponse> {
        if let Some(err) = self.build_error {
            return Err(err);
        }
        let params: Vec<(&str, &str)> = self.params.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let headers: Vec<(&str, &str)> = self.headers.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let resp = self.rest.do_request_raw(
            &self.method,
            &self.path,
            &headers,
            &params,
            self.body,
        ).await?;

        HttpPaginatedResponse::from_http_response(resp, self.rest.clone(), self.path)
    }
}

/// RSC19d/HP1-HP8: the response to Rest::request() — items decoded from the
/// body, pagination via Link headers, and status/error attributes.
pub struct HttpPaginatedResponse {
    pub(crate) items: Vec<serde_json::Value>,
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) error_code: Option<u32>,
    pub(crate) error_message: Option<String>,
    pub(crate) rest: Rest,
    pub(crate) next_rel_url: Option<String>,
    pub(crate) first_rel_url: Option<String>,
    pub(crate) base_path: String,
}

impl std::fmt::Debug for HttpPaginatedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPaginatedResponse")
            .field("status", &self.status)
            .field("items", &self.items.len())
            .field("error_code", &self.error_code)
            .field("error_message", &self.error_message)
            .finish()
    }
}

impl HttpPaginatedResponse {
    fn from_http_response(resp: HttpResponse, rest: Rest, base_path: String) -> Result<Self> {
        let (next_rel_url, first_rel_url) = parse_link_headers(&resp.headers);

        // HP6/HP7: error details from X-Ably-Errorcode/X-Ably-Errormessage
        let header = |name: &str| {
            resp.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let error_code = header("x-ably-errorcode").and_then(|v| v.parse().ok());
        let error_message = header("x-ably-errormessage");

        // HP3: the body is normalised to an array of items
        let items = if resp.body.is_empty() {
            Vec::new()
        } else {
            let value: serde_json::Value = rest.deserialize_response(&resp)?;
            match value {
                serde_json::Value::Array(items) => items,
                serde_json::Value::Null => Vec::new(),
                other => vec![other],
            }
        };

        Ok(Self {
            items,
            status: resp.status,
            headers: resp.headers,
            error_code,
            error_message,
            rest,
            next_rel_url,
            first_rel_url,
            base_path,
        })
    }

    /// HP3: the decoded items.
    pub fn items(&self) -> &[serde_json::Value] {
        &self.items
    }

    /// HP4: the HTTP status code.
    pub fn status_code(&self) -> u16 {
        self.status
    }

    /// HP5: whether the status code indicates success (2xx).
    pub fn success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// HP6: the Ably error code from the X-Ably-Errorcode header.
    pub fn error_code(&self) -> Option<u32> {
        self.error_code
    }

    /// HP7: the error message from the X-Ably-Errormessage header.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// HP8: the response headers.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn has_next(&self) -> bool {
        self.next_rel_url.is_some()
    }

    pub fn is_last(&self) -> bool {
        self.next_rel_url.is_none()
    }

    /// HP2: fetch the next page, if any.
    pub async fn next(self) -> Result<Option<HttpPaginatedResponse>> {
        let url = match &self.next_rel_url {
            Some(url) => url.clone(),
            None => return Ok(None),
        };
        self.fetch_page(&url).await.map(Some)
    }

    /// HP2: fetch the first page.
    pub async fn first(self) -> Result<Option<HttpPaginatedResponse>> {
        let url = match &self.first_rel_url {
            Some(url) => url.clone(),
            None => return Ok(None),
        };
        self.fetch_page(&url).await.map(Some)
    }

    async fn fetch_page(self, url: &str) -> Result<HttpPaginatedResponse> {
        let (path, params) = resolve_pagination_url(url, &self.base_path)?;
        let param_refs: Vec<(&str, &str)> = params.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let resp = self
            .rest
            .do_request_raw("GET", &path, &[], &param_refs, None)
            .await?;
        Self::from_http_response(resp, self.rest, self.base_path)
    }
}

pub struct PaginatedRequestBuilder<'a, T> {
    pub(crate) rest: &'a Rest,
    pub(crate) path: String,
    pub(crate) params: Vec<(String, String)>,
    /// Channel cipher for decoding encrypted payloads (RSL6/RSL5).
    pub(crate) cipher: Option<crate::crypto::CipherParams>,
    pub(crate) _marker: std::marker::PhantomData<T>,
}

impl<'a, T> PaginatedRequestBuilder<'a, T> {
    pub fn start(mut self, interval: &str) -> Self {
        self.params.push(("start".to_string(), interval.to_string()));
        self
    }

    pub fn end(mut self, interval: &str) -> Self {
        self.params.push(("end".to_string(), interval.to_string()));
        self
    }

    pub fn forwards(mut self) -> Self {
        self.params.push(("direction".to_string(), "forwards".to_string()));
        self
    }

    pub fn backwards(mut self) -> Self {
        self.params.push(("direction".to_string(), "backwards".to_string()));
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.params.push(("limit".to_string(), limit.to_string()));
        self
    }

    pub fn params(mut self, params: &[(&str, &str)]) -> Self {
        for (k, v) in params {
            self.params.push((k.to_string(), v.to_string()));
        }
        self
    }
}

impl<'a, T: DeserializeOwned + Decodable + 'a> PaginatedRequestBuilder<'a, T> {
    pub async fn send(self) -> Result<PaginatedResult<T>> {
        let params: Vec<(&str, &str)> = self.params.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let resp = self.rest.do_request("GET", &self.path, &[], &params, None).await?;

        // Parse link headers for pagination
        let (next_rel_url, first_rel_url) = parse_link_headers(&resp.headers);

        let mut items: Vec<T> = self.rest.deserialize_response(&resp)?;
        for item in &mut items {
            item.decode_item(self.cipher.as_ref());
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

#[derive(Debug)]
pub struct Response {
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    fn from_http_response(resp: HttpResponse) -> Self {
        let content_type = resp.headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());

        Self {
            status: resp.status,
            content_type,
            headers: resp.headers,
            body: resp.body,
        }
    }

    pub fn status_code(&self) -> u16 {
        self.status
    }

    pub fn content_type(&self) -> Option<String> {
        self.content_type.clone()
    }

    pub async fn body<T: DeserializeOwned>(self) -> Result<T> {
        let ct = self.content_type.as_deref().unwrap_or("");
        if ct.contains("application/x-msgpack") {
            Ok(rmp_serde::from_slice(&self.body)?)
        } else {
            Ok(serde_json::from_slice(&self.body)?)
        }
    }

    pub async fn text(self) -> Result<String> {
        Ok(String::from_utf8(self.body).map_err(|e| {
            ErrorInfo::new(ErrorCode::InternalError.code(), format!("Invalid UTF-8: {}", e))
        })?)
    }
}

pub struct PaginatedResult<T> {
    pub(crate) items: Vec<T>,
    pub(crate) rest: Rest,
    pub(crate) next_rel_url: Option<String>,
    pub(crate) first_rel_url: Option<String>,
    pub(crate) base_path: String,
    pub(crate) cipher: Option<crate::crypto::CipherParams>,
}

impl<T> std::fmt::Debug for PaginatedResult<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaginatedResult")
            .field("items", &self.items.len())
            .field("has_next", &self.next_rel_url.is_some())
            .finish()
    }
}

impl<T> PaginatedResult<T> {
    pub fn items(&self) -> &[T] {
        &self.items
    }

    pub fn has_next(&self) -> bool {
        self.next_rel_url.is_some()
    }

    pub fn is_last(&self) -> bool {
        self.next_rel_url.is_none()
    }
}

impl<T: DeserializeOwned + Decodable> PaginatedResult<T> {
    pub async fn next(self) -> Result<Option<PaginatedResult<T>>> {
        let url = match &self.next_rel_url {
            Some(url) => url.clone(),
            None => return Ok(None),
        };
        self.fetch_page(&url).await.map(Some)
    }

    pub async fn first(self) -> Result<Option<PaginatedResult<T>>> {
        let url = match &self.first_rel_url {
            Some(url) => url.clone(),
            None => return Ok(None),
        };
        self.fetch_page(&url).await.map(Some)
    }

    async fn fetch_page(self, url: &str) -> Result<PaginatedResult<T>> {
        let (path, params) = resolve_pagination_url(url, &self.base_path)?;
        let param_refs: Vec<(&str, &str)> = params.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let base_path = self.base_path.clone();
        let resp = self.rest.do_request("GET", &path, &[], &param_refs, None).await?;
        let (next_rel_url, first_rel_url) = parse_link_headers(&resp.headers);
        let mut items: Vec<T> = self.rest.deserialize_response(&resp)?;
        for item in &mut items {
            item.decode_item(self.cipher.as_ref());
        }

        Ok(PaginatedResult {
            items,
            rest: self.rest,
            next_rel_url,
            first_rel_url,
            base_path,
            cipher: self.cipher,
        })
    }
}

/// Resolve a Link-header URL (absolute or relative) against the original
/// request path, returning (path, query params).
pub(crate) fn resolve_pagination_url(
    url: &str,
    base_path: &str,
) -> Result<(String, Vec<(String, String)>)> {
    let parsed = url::Url::parse(url).or_else(|_| {
        let base_dir = if base_path.ends_with('/') {
            base_path.to_string()
        } else {
            match base_path.rfind('/') {
                Some(idx) => base_path[..=idx].to_string(),
                None => "/".to_string(),
            }
        };
        let base_url = format!("https://placeholder.invalid{}", base_dir);
        let base = url::Url::parse(&base_url).unwrap();
        base.join(url)
    }).map_err(|e| {
        ErrorInfo::new(ErrorCode::InternalError.code(), format!("Invalid pagination URL: {}", e))
    })?;
    let path = parsed.path().to_string();
    let params: Vec<(String, String)> = parsed.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Ok((path, params))
}

pub(crate) fn parse_link_headers(headers: &[(String, String)]) -> (Option<String>, Option<String>) {
    let mut next = None;
    let mut first = None;

    for (k, v) in headers {
        if k.eq_ignore_ascii_case("link") {
            for part in v.split(',') {
                let part = part.trim();
                if part.contains("rel=\"next\"") {
                    if let Some(url) = extract_link_url(part) {
                        next = Some(url);
                    }
                } else if part.contains("rel=\"first\"") {
                    if let Some(url) = extract_link_url(part) {
                        first = Some(url);
                    }
                }
            }
        }
    }

    (next, first)
}

fn extract_link_url(link: &str) -> Option<String> {
    let start = link.find('<')?;
    let end = link.find('>')?;
    if end > start {
        Some(link[start + 1..end].to_string())
    } else {
        None
    }
}

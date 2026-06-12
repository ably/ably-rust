#![cfg(test)]

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use crate::http_client::{HttpClient, HttpRequest, HttpResponse};

#[derive(Clone)]
pub(crate) struct CapturedRequest {
    pub method: String,
    pub url: url::Url,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

pub(crate) struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub network_error: bool,
}

impl MockResponse {
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: serde_json::to_vec(body).unwrap(),
            network_error: false,
        }
    }

    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            network_error: false,
        }
    }

    pub fn network_error() -> Self {
        Self {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
            network_error: true,
        }
    }

    pub fn msgpack(status: u16, body: &impl serde::Serialize) -> Self {
        Self {
            status,
            headers: vec![(
                "content-type".to_string(),
                "application/x-msgpack".to_string(),
            )],
            body: rmp_serde::to_vec_named(body).unwrap_or_default(),
            network_error: false,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

type Handler = Box<dyn Fn(&CapturedRequest) -> MockResponse + Send + Sync>;

struct MockHttpClientInner {
    handler: Option<Handler>,
    queue: Mutex<Vec<MockResponse>>,
    requests: Mutex<Vec<CapturedRequest>>,
    response_delay: Mutex<Option<std::time::Duration>>,
}

pub(crate) struct MockHttpClient {
    inner: Arc<MockHttpClientInner>,
}

impl Clone for MockHttpClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl MockHttpClient {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MockHttpClientInner {
                handler: None,
                queue: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
                response_delay: Mutex::new(None),
            }),
        }
    }

    pub fn with_handler(
        handler: impl Fn(&CapturedRequest) -> MockResponse + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(MockHttpClientInner {
                handler: Some(Box::new(handler)),
                queue: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
                response_delay: Mutex::new(None),
            }),
        }
    }

    pub fn queue_response(&self, response: MockResponse) {
        self.inner.queue.lock().unwrap().push(response);
    }

    pub fn captured_requests(&self) -> Vec<CapturedRequest> {
        self.inner.requests.lock().unwrap().clone()
    }

    pub fn request_count(&self) -> usize {
        self.inner.requests.lock().unwrap().len()
    }

    #[allow(dead_code)] // UTS mock surface, not yet exercised
    pub fn reset(&self) {
        self.inner.requests.lock().unwrap().clear();
        self.inner.queue.lock().unwrap().clear();
    }

    pub fn set_response_delay(&self, delay: std::time::Duration) {
        *self.inner.response_delay.lock().unwrap() = Some(delay);
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn execute(
        &self,
        request: HttpRequest,
    ) -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        let delay = *self.inner.response_delay.lock().unwrap();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }

        let captured = CapturedRequest {
            method: request.method.clone(),
            url: url::Url::parse(&request.url)
                .unwrap_or_else(|_| url::Url::parse("http://invalid").unwrap()),
            headers: request.headers.clone(),
            body: request.body.clone(),
        };

        let response = if let Some(handler) = &self.inner.handler {
            handler(&captured)
        } else {
            let mut queue = self.inner.queue.lock().unwrap();
            if queue.is_empty() {
                MockResponse::empty(200)
            } else {
                queue.remove(0)
            }
        };

        self.inner.requests.lock().unwrap().push(captured);

        if response.network_error {
            return Err("simulated network error".into());
        }

        Ok(HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

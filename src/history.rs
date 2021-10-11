use crate::http;
use crate::Result;

/// A builder to construct a REST history request.
pub struct RequestBuilder {
    req: http::RequestBuilder,
}

impl RequestBuilder {
    pub fn new(req: http::RequestBuilder) -> Self {
        Self { req }
    }

    pub fn start(mut self, interval: &str) -> Self {
        self.req = self.req.params(&[("start", interval)]);
        self
    }

    pub fn end(mut self, interval: &str) -> Self {
        self.req = self.req.params(&[("end", interval)]);
        self
    }

    pub fn forwards(mut self) -> Self {
        self.req = self.req.params(&[("direction", "forwards")]);
        self
    }

    pub fn backwards(mut self) -> Self {
        self.req = self.req.params(&[("direction", "backwards")]);
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.req = self.req.params(&[("limit", limit.to_string())]);
        self
    }

    pub async fn send(self) -> Result<http::Response> {
        self.req.send().await
    }
}

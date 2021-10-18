use crate::http;
use crate::Result;

/// A builder to construct a REST presence request.
pub struct RequestBuilder {
    req: http::RequestBuilder,
}

impl RequestBuilder {
    pub fn new(req: http::RequestBuilder) -> Self {
        Self { req }
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.req = self.req.params(&[("limit", limit.to_string())]);
        self
    }

    pub fn client_id(mut self, client_id: &str) -> Self {
        self.req = self.req.params(&[("clientId", client_id.to_string())]);
        self
    }

    pub fn connection_id(mut self, connection_id: &str) -> Self {
        self.req = self
            .req
            .params(&[("connectionId", connection_id.to_string())]);
        self
    }

    pub async fn send(self) -> Result<http::Response> {
        self.req.send().await
    }
}

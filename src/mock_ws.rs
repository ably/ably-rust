#![cfg(test)]

use std::sync::Arc;

use crate::protocol::ProtocolMessage;
use crate::transport::{Transport, TransportConnection, TransportEvent};

pub(crate) struct PendingConnection {
    pub url: String,
}

impl PendingConnection {
    pub fn respond_with_success(self, _msg: ProtocolMessage) { todo!() }
    pub fn respond_with_refused(self) { todo!() }
    pub fn respond_with_error(self, _msg: ProtocolMessage) { todo!() }
}

pub(crate) struct MockConnection {}

impl MockConnection {
    pub fn send_to_client(&self, _msg: ProtocolMessage) { todo!() }
    pub fn send_to_client_and_close(&self, _msg: ProtocolMessage) { todo!() }
    pub fn simulate_disconnect(&self) { todo!() }
}

pub(crate) struct CapturedMessage {
    pub channel: Option<String>,
    pub action: u8,
    pub message: ProtocolMessage,
}

pub(crate) struct MockWebSocketInner {}

pub(crate) struct MockWebSocket {
    inner: Arc<MockWebSocketInner>,
}

impl MockWebSocket {
    pub fn new() -> Self {
        Self { inner: Arc::new(MockWebSocketInner {}) }
    }
    pub fn with_handler(
        _handler: impl Fn(PendingConnection) + Send + Sync + 'static,
    ) -> Self {
        Self { inner: Arc::new(MockWebSocketInner {}) }
    }
    pub fn inner(&self) -> Arc<MockWebSocketInner> {
        self.inner.clone()
    }
    pub fn connection_count(&self) -> u32 { 0 }
    pub fn client_messages(&self) -> Vec<CapturedMessage> { Vec::new() }
    pub fn active_connections(&self) -> Vec<MockConnection> { Vec::new() }
    pub async fn await_connection(&self) -> PendingConnection { todo!() }
}

pub(crate) struct MockTransport {
    _inner: Arc<MockWebSocketInner>,
}

impl MockTransport {
    pub fn new(inner: Arc<MockWebSocketInner>) -> Self {
        Self { _inner: inner }
    }
}

#[async_trait::async_trait]
impl Transport for MockTransport {
    async fn connect(
        &self,
        _url: &str,
    ) -> crate::error::Result<Box<dyn TransportConnection>> {
        todo!()
    }
}

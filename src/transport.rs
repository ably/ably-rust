use async_trait::async_trait;

use crate::error::Result;
use crate::protocol::ProtocolMessage;

pub(crate) enum TransportEvent {
    Message(ProtocolMessage),
    Disconnected,
}

#[async_trait]
pub(crate) trait Transport: Send + Sync {
    async fn connect(&self, url: &str) -> Result<Box<dyn TransportConnection>>;
}

#[async_trait]
pub(crate) trait TransportConnection: Send {
    async fn send(&mut self, msg: ProtocolMessage) -> Result<()>;
    async fn recv(&mut self) -> Option<TransportEvent>;
    async fn close(&mut self);
}

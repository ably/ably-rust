use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use crate::auth::TokenDetails;
use crate::channel::Channels;
use crate::error::{ErrorInfo, Result};
use crate::options::ClientOptions;
use crate::protocol::{ConnectionEvent, ConnectionState, ConnectionStateChange};
use crate::rest::Push;
use crate::transport::Transport;

pub struct Realtime {
    pub connection: Connection,
    pub channels: Channels,
}

impl Realtime {
    pub fn new(_options: &ClientOptions) -> Result<Self> {
        todo!()
    }

    pub fn with_mock(
        _options: &ClientOptions,
        _transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        todo!()
    }

    pub fn connect(&self) {
        todo!()
    }

    pub fn close(&self) {
        todo!()
    }

    pub fn auth(&self) -> &RealtimeAuth {
        todo!()
    }

    pub fn push(&self) -> Option<Push<'_>> {
        todo!()
    }

    pub fn rest(&self) -> &crate::rest::Rest {
        todo!()
    }
}

pub struct RealtimeAuth {}

impl RealtimeAuth {
    pub async fn authorize(&self) -> Result<TokenDetails> {
        todo!()
    }

    pub fn client_id(&self) -> Option<String> {
        todo!()
    }
}

pub struct Connection {}

impl Connection {
    pub fn state(&self) -> ConnectionState {
        todo!()
    }

    pub fn id(&self) -> Option<String> {
        todo!()
    }

    pub fn key(&self) -> Option<String> {
        todo!()
    }

    pub fn host(&self) -> Option<String> {
        todo!()
    }

    pub fn error_reason(&self) -> Option<ErrorInfo> {
        todo!()
    }

    pub fn on_state_change(&self) -> broadcast::Receiver<ConnectionStateChange> {
        todo!()
    }

    pub fn connect(&self) {
        todo!()
    }

    pub fn close(&self) {
        todo!()
    }

    pub async fn ping(&self) -> Result<Duration> {
        todo!()
    }

    pub fn when_state(
        &self,
        _target: ConnectionState,
        _callback: impl FnOnce(ConnectionStateChange) + Send + 'static,
    ) {
        todo!()
    }
}

#[cfg(test)]
pub(crate) async fn await_state(
    _connection: &Connection,
    _target: ConnectionState,
    _timeout_ms: u64,
) -> bool {
    todo!()
}

#[cfg(test)]
pub(crate) async fn await_channel_state(
    _channel: &Arc<crate::channel::RealtimeChannel>,
    _target: crate::protocol::ChannelState,
    _timeout_ms: u64,
) -> bool {
    todo!()
}

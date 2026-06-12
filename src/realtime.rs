//! Realtime client handles. These are thin: all protocol state is owned by
//! the connection loop (src/connection.rs, DESIGN.md "Realtime State &
//! Concurrency"); handles send commands and observe watch/broadcast outputs.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, watch};

use crate::auth::TokenDetails;
use crate::channel::Channels;
use crate::connection::{spawn_connection_loop, Command, ConnectionSnapshot, LoopInput};
use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::options::ClientOptions;
use crate::protocol::{ConnectionEvent, ConnectionState, ConnectionStateChange};
use crate::rest::{Push, Rest};
use crate::transport::Transport;

pub struct Realtime {
    pub connection: Connection,
    pub channels: Channels,
    rest: Rest,
}

impl Realtime {
    /// RTC1: create a realtime client. RTN3: connects immediately unless
    /// `auto_connect(false)`.
    pub fn new(options: &ClientOptions) -> Result<Self> {
        let transport: Arc<dyn Transport> = Arc::new(crate::ws_transport::WsTransport::new(
            options.format,
            options.logger(),
        ));
        Self::with_transport(options, transport)
    }

    /// Test injection: a realtime client over a mock transport.
    #[cfg_attr(not(test), allow(dead_code))] // test injection
    pub(crate) fn with_mock(
        options: &ClientOptions,
        transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        Self::with_transport(options, transport)
    }

    fn with_transport(options: &ClientOptions, transport: Arc<dyn Transport>) -> Result<Self> {
        let auto_connect = options.auto_connect;
        let rest = options.clone_for_realtime().rest()?;
        // RSA4a1: a literal token with no renewal means gets a warning —
        // when it expires the connection cannot recover by itself
        {
            let cfg = rest.auth_config();
            let token_only = matches!(
                &rest.inner.opts.credential,
                crate::auth::Credential::TokenDetails(_)
            );
            if token_only && cfg.key.is_none() && cfg.callback.is_none() && cfg.url.is_none() {
                rest.inner.opts.log(
                    crate::options::LogLevel::Major,
                    "Warning (code 40171): the client was supplied a literal token with no means to renew it;                      when it expires the client will be unable to authenticate.                      See https://help.ably.io/error/40171",
                );
            }
        }
        let (input_tx, snapshot_rx, events_tx) = spawn_connection_loop(rest.clone(), transport);

        let connection = Connection {
            input_tx: input_tx.clone(),
            snapshot_rx,
            events_tx,
            logger: rest.inner.opts.logger(),
        };
        let realtime = Self {
            connection,
            channels: Channels::new(input_tx, rest.clone()),
            rest,
        };
        if auto_connect {
            realtime.connect();
        }
        Ok(realtime)
    }

    /// RTC15/RTN11: initiate the connection.
    pub fn connect(&self) {
        self.connection.connect();
    }

    /// RTC16/RTN12: close the connection.
    pub fn close(&self) {
        self.connection.close();
    }

    pub fn auth(&self) -> RealtimeAuth {
        RealtimeAuth {
            rest: self.rest.clone(),
            input_tx: self.connection.input_tx.clone(),
        }
    }

    pub fn push(&self) -> Option<Push<'_>> {
        Some(self.rest.push())
    }

    /// RTC2-adjacent: the embedded REST client (shared options and auth).
    pub fn rest(&self) -> &Rest {
        &self.rest
    }
}

pub struct RealtimeAuth {
    rest: Rest,
    input_tx: mpsc::UnboundedSender<LoopInput>,
}

impl RealtimeAuth {
    /// RTC8: obtain a new token and apply it to the connection. While
    /// CONNECTED this is an in-band AUTH (the connection stays CONNECTED);
    /// while CONNECTING the attempt restarts with the new token (RTC8b);
    /// from any other state a connection is initiated (RTC8c). Resolves only
    /// once the server has confirmed or refused the new token (RTC8a3).
    pub async fn authorize(&self) -> Result<TokenDetails> {
        let td = self.rest.auth().authorize(None, None).await?;
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::Authorize {
                access_token: td.token.clone(),
                reply,
            }))
            .map_err(|_| {
                ErrorInfo::new(
                    ErrorCode::ConnectionClosed.code(),
                    "Connection loop has terminated",
                )
            })?;
        rx.await.map_err(|_| {
            ErrorInfo::new(
                ErrorCode::ConnectionClosed.code(),
                "Connection loop dropped the authorize",
            )
        })??;
        Ok(td)
    }

    pub fn client_id(&self) -> Option<String> {
        self.rest.auth().client_id()
    }
}

/// The connection handle: snapshot reads, event subscription, and commands.
/// Cheap to clone; holds no protocol state (DESIGN.md §4).
pub struct Connection {
    pub(crate) input_tx: mpsc::UnboundedSender<LoopInput>,
    pub(crate) snapshot_rx: watch::Receiver<ConnectionSnapshot>,
    pub(crate) events_tx: broadcast::Sender<ConnectionStateChange>,
    pub(crate) logger: crate::options::Logger,
}

impl Connection {
    fn snapshot(&self) -> ConnectionSnapshot {
        self.snapshot_rx.borrow().clone()
    }

    /// RTN4d: the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.snapshot().state
    }

    /// RTN8: the connection id (only while CONNECTED, RTN8c).
    pub fn id(&self) -> Option<String> {
        self.snapshot().id
    }

    /// RTN9: the connection key (only while CONNECTED, RTN9c).
    pub fn key(&self) -> Option<String> {
        self.snapshot().key
    }

    /// RTN17: the host serving the current connection (None unless CONNECTED).
    pub fn host(&self) -> Option<String> {
        self.snapshot().host
    }

    /// RTN25: the last error that affected the connection.
    pub fn error_reason(&self) -> Option<ErrorInfo> {
        self.snapshot().error_reason
    }

    /// RTN4a/RTN4d: subscribe to connection state changes.
    pub fn on_state_change(&self) -> broadcast::Receiver<ConnectionStateChange> {
        self.events_tx.subscribe()
    }

    /// RTN11: explicitly initiate connecting.
    pub fn connect(&self) {
        self.logger.micro(|| "API: Connection::connect".to_string());
        let _ = self.input_tx.send(LoopInput::Cmd(Command::Connect));
    }

    /// RTN12: close the connection.
    pub fn close(&self) {
        self.logger.micro(|| "API: Connection::close".to_string());
        let _ = self.input_tx.send(LoopInput::Cmd(Command::Close));
    }

    /// RTN13: heartbeat ping over the live connection; resolves with the
    /// round-trip time.
    pub async fn ping(&self) -> Result<Duration> {
        self.logger.micro(|| "API: Connection::ping".to_string());
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::Ping { reply }))
            .map_err(|_| {
                ErrorInfo::new(
                    ErrorCode::ConnectionClosed.code(),
                    "Connection loop has terminated",
                )
            })?;
        rx.await.map_err(|_| {
            ErrorInfo::new(
                ErrorCode::ConnectionClosed.code(),
                "Connection loop dropped the ping",
            )
        })?
    }

    /// RTN26: invoke `callback` once when the connection is (or next
    /// becomes) `target`. RTN26a: fires immediately if already in `target`;
    /// RTN26b: otherwise waits for the next transition into it.
    pub fn when_state(
        &self,
        target: ConnectionState,
        callback: impl FnOnce(ConnectionStateChange) + Send + 'static,
    ) {
        // Subscribe BEFORE reading the snapshot so a transition between the
        // two cannot be missed.
        let mut events = self.events_tx.subscribe();
        let current = self.snapshot();
        if current.state == target {
            // RTN26a: synthesize a change describing the current state
            callback(ConnectionStateChange {
                previous: current.state,
                current: current.state,
                event: state_to_event(current.state),
                reason: current.error_reason,
            });
            return;
        }
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(change) if change.current == target => {
                        callback(change);
                        return;
                    }
                    Ok(_) => continue,
                    // Lagged: keep listening; the next matching transition
                    // still fires the callback
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Self {
            input_tx: self.input_tx.clone(),
            snapshot_rx: self.snapshot_rx.clone(),
            events_tx: self.events_tx.clone(),
            logger: self.logger.clone(),
        }
    }
}

pub(crate) fn state_to_event(state: ConnectionState) -> ConnectionEvent {
    match state {
        ConnectionState::Initialized => ConnectionEvent::Initialized,
        ConnectionState::Connecting => ConnectionEvent::Connecting,
        ConnectionState::Connected => ConnectionEvent::Connected,
        ConnectionState::Disconnected => ConnectionEvent::Disconnected,
        ConnectionState::Suspended => ConnectionEvent::Suspended,
        ConnectionState::Closing => ConnectionEvent::Closing,
        ConnectionState::Closed => ConnectionEvent::Closed,
        ConnectionState::Failed => ConnectionEvent::Failed,
    }
}

/// Test helper: await a connection state via the snapshot watch.
#[cfg(test)]
pub(crate) async fn await_state(
    connection: &Connection,
    target: ConnectionState,
    timeout_ms: u64,
) -> bool {
    let mut rx = connection.snapshot_rx.clone();
    let deadline = tokio::time::Duration::from_millis(timeout_ms);
    tokio::time::timeout(deadline, async {
        loop {
            if rx.borrow().state == target {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await
    .is_ok()
        && connection.snapshot_rx.borrow().state == target
}

/// Test helper: await a channel state via the snapshot watch.
#[cfg(test)]
pub(crate) async fn await_channel_state(
    channel: &Arc<crate::channel::RealtimeChannel>,
    target: crate::protocol::ChannelState,
    timeout_ms: u64,
) -> bool {
    let mut rx = channel.snapshot_rx.clone();
    let deadline = tokio::time::Duration::from_millis(timeout_ms);
    tokio::time::timeout(deadline, async {
        loop {
            if rx.borrow().state == target {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await
    .is_ok()
        && channel.snapshot_rx.borrow().state == target
}

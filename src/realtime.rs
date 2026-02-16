//! Ably Realtime client implementation.
//!
//! Provides the `Realtime` client with WebSocket-based connection management,
//! state machine, and event system.

use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::auth::Credential;
use crate::protocol::{
    Action, ConnectionEvent, ConnectionState, ConnectionStateChange, ErrorInfo, ProtocolMessage,
};
use crate::rest;
use crate::ClientOptions;

#[cfg(test)]
use crate::mock_ws::{MockTransport, MockTransportConnection, ServerAction};

/// The Ably Realtime client.
///
/// Wraps a REST client and adds a WebSocket connection for real-time messaging.
pub struct Realtime {
    /// The connection object managing the WebSocket lifecycle.
    pub connection: Connection,
}

impl Realtime {
    /// Create a new Realtime client with a mock WebSocket transport.
    /// If `auto_connect` is true (default), a connection is initiated immediately.
    #[cfg(test)]
    pub(crate) fn with_mock(
        options: &ClientOptions,
        transport: Arc<MockTransport>,
    ) -> crate::Result<Self> {
        let auto_connect = options.auto_connect;
        let connection = Connection::new(options, transport);

        let client = Self { connection };

        if auto_connect {
            client.connect();
        }

        Ok(client)
    }

    /// Initiate a connection (proxies to Connection::connect). RTN11, RTC15.
    pub fn connect(&self) {
        self.connection.connect();
    }

    /// Close the connection (proxies to Connection::close). RTN12, RTC16.
    pub fn close(&self) {
        self.connection.close();
    }
}

/// The Connection object managing the WebSocket lifecycle.
///
/// Tracks connection state, ID, key, and emits state change events.
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    /// Current connection state.
    state: Mutex<ConnectionState>,

    /// Connection ID (set by server in CONNECTED message).
    id: Mutex<Option<String>>,

    /// Connection key (set by server in CONNECTED message).
    key: Mutex<Option<String>>,

    /// Last error reason.
    error_reason: Mutex<Option<ErrorInfo>>,

    /// Broadcast channel for state change events.
    state_tx: broadcast::Sender<ConnectionStateChange>,

    /// The WebSocket URL base.
    ws_url: url::Url,

    /// Query parameters for the WebSocket URL.
    ws_params: Vec<(String, String)>,

    /// Mock transport for testing.
    #[cfg(test)]
    transport: Arc<MockTransport>,

    /// Handle to the connection task (so we can check if running).
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Connection {
    #[cfg(test)]
    fn new(options: &ClientOptions, transport: Arc<MockTransport>) -> Self {
        let host = &options.realtime_host;

        let scheme = if options.tls { "wss" } else { "ws" };

        let ws_url =
            url::Url::parse(&format!("{}://{}/?", scheme, host)).expect("valid WebSocket URL");

        let mut ws_params = Vec::new();

        // Protocol version
        ws_params.push(("v".to_string(), "2".to_string()));

        // Format
        let format = match options.format {
            rest::Format::MessagePack => "msgpack",
            rest::Format::JSON => "json",
        };
        ws_params.push(("format".to_string(), format.to_string()));

        // Heartbeats
        ws_params.push(("heartbeats".to_string(), "true".to_string()));

        // Echo (RTC1a)
        ws_params.push(("echo".to_string(), options.echo_messages.to_string()));

        // Auth: key or token
        if let Credential::Key(ref key) = options.credential {
            ws_params.push(("key".to_string(), format!("{}:{}", key.name, key.value)));
        }

        // Transport params (RTC1f) — override defaults
        if let Some(ref params) = options.transport_params {
            for (k, v) in params {
                // Remove any existing param with the same key
                ws_params.retain(|(existing_k, _)| existing_k != k);
                ws_params.push((k.clone(), v.clone()));
            }
        }

        let (state_tx, _) = broadcast::channel(64);

        Self {
            inner: Arc::new(ConnectionInner {
                state: Mutex::new(ConnectionState::Initialized),
                id: Mutex::new(None),
                key: Mutex::new(None),
                error_reason: Mutex::new(None),
                state_tx,
                ws_url,
                ws_params,
                transport,
                task_handle: Mutex::new(None),
            }),
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        *self.inner.state.lock().unwrap()
    }

    /// Get the connection ID (set after CONNECTED).
    pub fn id(&self) -> Option<String> {
        self.inner.id.lock().unwrap().clone()
    }

    /// Get the connection key (set after CONNECTED).
    pub fn key(&self) -> Option<String> {
        self.inner.key.lock().unwrap().clone()
    }

    /// Get the last error reason.
    pub fn error_reason(&self) -> Option<ErrorInfo> {
        self.inner.error_reason.lock().unwrap().clone()
    }

    /// Subscribe to all connection state changes.
    pub fn on_state_change(&self) -> broadcast::Receiver<ConnectionStateChange> {
        self.inner.state_tx.subscribe()
    }

    /// Initiate a connection. RTN11.
    pub fn connect(&self) {
        let current = self.state();
        match current {
            ConnectionState::Initialized
            | ConnectionState::Closed
            | ConnectionState::Failed
            | ConnectionState::Disconnected => {
                self.set_state(ConnectionState::Connecting, None);
                self.spawn_connect_task();
            }
            // Already connecting or connected — no-op
            _ => {}
        }
    }

    /// Close the connection. RTN12.
    pub fn close(&self) {
        let current = self.state();
        match current {
            ConnectionState::Connected => {
                self.set_state(ConnectionState::Closing, None);
                self.spawn_close_task();
            }
            ConnectionState::Connecting => {
                self.set_state(ConnectionState::Closing, None);
                self.set_state(ConnectionState::Closed, None);
            }
            ConnectionState::Initialized | ConnectionState::Disconnected => {
                self.set_state(ConnectionState::Closed, None);
            }
            _ => {}
        }
    }

    /// Set the connection state and emit a state change event.
    fn set_state(&self, new_state: ConnectionState, reason: Option<ErrorInfo>) {
        Connection::set_state_inner(&self.inner, new_state, reason);
    }

    /// Spawn the async task that performs the WebSocket connection.
    #[cfg(test)]
    fn spawn_connect_task(&self) {
        let inner = Arc::clone(&self.inner);

        let handle = tokio::spawn(async move {
            // Build the connection URL
            let mut url = inner.ws_url.clone();
            {
                let mut pairs = url.query_pairs_mut();
                for (k, v) in &inner.ws_params {
                    pairs.append_pair(k, v);
                }
            }

            // Attempt to connect via the mock transport
            match inner.transport.connect(url).await {
                Ok(mut conn) => {
                    Connection::handle_connection(&inner, &mut conn).await;
                }
                Err(_err) => {
                    let error = ErrorInfo {
                        code: Some(80000),
                        status_code: Some(400),
                        message: Some("Connection refused".to_string()),
                        href: None,
                    };
                    Connection::set_state_inner(&inner, ConnectionState::Disconnected, Some(error));
                }
            }
        });

        *self.inner.task_handle.lock().unwrap() = Some(handle);
    }

    #[cfg(not(test))]
    fn spawn_connect_task(&self) {
        todo!("Real WebSocket transport not yet implemented")
    }

    #[cfg(not(test))]
    fn spawn_close_task(&self) {
        todo!("Real WebSocket transport not yet implemented")
    }

    #[cfg(test)]
    fn spawn_close_task(&self) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            Connection::set_state_inner(&inner, ConnectionState::Closed, None);
        });
    }

    /// Process messages on an established connection.
    #[cfg(test)]
    async fn handle_connection(inner: &ConnectionInner, conn: &mut MockTransportConnection) {
        while let Some(action) = conn.recv().await {
            match action {
                ServerAction::Message(msg) => {
                    Connection::handle_protocol_message(inner, msg);
                }
                ServerAction::MessageThenClose(msg) => {
                    Connection::handle_protocol_message(inner, msg);
                    break;
                }
                ServerAction::Disconnect => {
                    let error = ErrorInfo {
                        code: Some(80003),
                        status_code: None,
                        message: Some("Connection disconnected".to_string()),
                        href: None,
                    };
                    Connection::set_state_inner(inner, ConnectionState::Disconnected, Some(error));
                    break;
                }
            }
        }
    }

    /// Handle a single protocol message from the server.
    fn handle_protocol_message(inner: &ConnectionInner, msg: ProtocolMessage) {
        match msg.action {
            Action::Connected => {
                if let Some(ref id) = msg.connection_id {
                    *inner.id.lock().unwrap() = Some(id.clone());
                }
                if let Some(ref details) = msg.connection_details {
                    if let Some(ref key) = details.connection_key {
                        *inner.key.lock().unwrap() = Some(key.clone());
                    }
                }
                Connection::set_state_inner(inner, ConnectionState::Connected, None);
            }
            Action::Disconnected => {
                let reason = msg.error.clone();
                Connection::set_state_inner(inner, ConnectionState::Disconnected, reason);
            }
            Action::Closed => {
                Connection::set_state_inner(inner, ConnectionState::Closed, None);
            }
            Action::Error => {
                let reason = msg.error.clone();
                // Connection-level error (no channel) → FAILED
                if msg.channel.is_none() {
                    Connection::set_state_inner(inner, ConnectionState::Failed, reason);
                }
            }
            _ => {
                // Other messages handled by channel layer (Phase 8)
            }
        }
    }

    /// Static version of set_state that works with ConnectionInner directly.
    fn set_state_inner(
        inner: &ConnectionInner,
        new_state: ConnectionState,
        reason: Option<ErrorInfo>,
    ) {
        let previous = {
            let mut state = inner.state.lock().unwrap();
            let prev = *state;
            *state = new_state;
            prev
        };

        // Clear id/key in terminal states (RTN8c, RTN9c)
        match new_state {
            ConnectionState::Closed
            | ConnectionState::Failed
            | ConnectionState::Suspended
            | ConnectionState::Closing => {
                *inner.id.lock().unwrap() = None;
                *inner.key.lock().unwrap() = None;
            }
            _ => {}
        }

        // Set error reason if provided (RTN25)
        if reason.is_some() {
            *inner.error_reason.lock().unwrap() = reason.clone();
        }

        let event = ConnectionEvent::from(new_state);
        let change = ConnectionStateChange {
            previous,
            current: new_state,
            event,
            reason,
        };

        let _ = inner.state_tx.send(change);
    }
}

/// Helper to wait for a specific connection state.
pub async fn await_state(conn: &Connection, target: ConnectionState, timeout_ms: u64) -> bool {
    if conn.state() == target {
        return true;
    }

    let mut rx = conn.on_state_change();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);

    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(change)) => {
                if change.current == target {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

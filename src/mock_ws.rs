//! Mock WebSocket infrastructure for Realtime unit tests.
//!
//! Provides a mock WebSocket that can intercept connection attempts,
//! inject server messages, and capture client messages.

use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::protocol::ProtocolMessage;

/// A pending connection attempt that tests can respond to.
pub struct PendingConnection {
    pub url: url::Url,
    responder: oneshot::Sender<ConnectionResponse>,
}

impl PendingConnection {
    /// Accept the connection and send a CONNECTED message.
    pub fn respond_with_success(self, connected_message: ProtocolMessage) {
        let _ = self
            .responder
            .send(ConnectionResponse::Success(connected_message));
    }

    /// Reject the connection (connection refused).
    pub fn respond_with_refused(self) {
        let _ = self.responder.send(ConnectionResponse::Refused);
    }

    /// Reject with a protocol ERROR then close.
    pub fn respond_with_error(self, error_message: ProtocolMessage) {
        let _ = self
            .responder
            .send(ConnectionResponse::Error(error_message));
    }
}

/// How the mock should respond to a connection attempt.
pub enum ConnectionResponse {
    Success(ProtocolMessage),
    Refused,
    Error(ProtocolMessage),
}

/// A mock WebSocket connection that has been established.
/// Tests use this to inject messages and simulate disconnects.
pub struct MockConnection {
    to_client_tx: mpsc::UnboundedSender<ServerAction>,
}

impl MockConnection {
    /// Send a protocol message to the client.
    pub fn send_to_client(&self, msg: ProtocolMessage) {
        let _ = self.to_client_tx.send(ServerAction::Message(msg));
    }

    /// Send a protocol message then close the connection.
    pub fn send_to_client_and_close(&self, msg: ProtocolMessage) {
        let _ = self.to_client_tx.send(ServerAction::MessageThenClose(msg));
    }

    /// Simulate an unexpected disconnect.
    pub fn simulate_disconnect(&self) {
        let _ = self.to_client_tx.send(ServerAction::Disconnect);
    }
}

/// Actions the mock server can take on an established connection.
pub enum ServerAction {
    Message(ProtocolMessage),
    MessageThenClose(ProtocolMessage),
    Disconnect,
}

/// A captured message sent by the client over the WebSocket.
#[derive(Debug, Clone)]
pub struct CapturedMessage {
    pub message: ProtocolMessage,
}

/// Handler called when a connection attempt is made.
pub type ConnectionHandler = Box<dyn Fn(PendingConnection) + Send + Sync>;

/// The mock WebSocket server that intercepts connection attempts.
pub struct MockWebSocket {
    inner: Arc<MockWebSocketInner>,
}

pub(crate) struct MockWebSocketInner {
    /// Handler for connection attempts (handler-based pattern).
    connection_handler: Mutex<Option<ConnectionHandler>>,

    /// Channel for await-based connection attempts.
    connection_tx: mpsc::UnboundedSender<PendingConnection>,
    connection_rx: Mutex<Option<mpsc::UnboundedReceiver<PendingConnection>>>,

    /// Track connection attempt count.
    connection_count: Mutex<u32>,

    /// Messages sent by clients.
    client_messages: Mutex<Vec<CapturedMessage>>,

    /// Active connections (for sending messages to clients).
    active_connections: Mutex<Vec<MockConnection>>,

    /// Broadcast channel for state change notifications (used by tests).
    state_tx: broadcast::Sender<()>,
}

impl MockWebSocket {
    /// Create a new mock WebSocket with no handler (use await pattern).
    pub fn new() -> Self {
        let (connection_tx, connection_rx) = mpsc::unbounded_channel();
        let (state_tx, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(MockWebSocketInner {
                connection_handler: Mutex::new(None),
                connection_tx,
                connection_rx: Mutex::new(Some(connection_rx)),
                connection_count: Mutex::new(0),
                client_messages: Mutex::new(Vec::new()),
                active_connections: Mutex::new(Vec::new()),
                state_tx,
            }),
        }
    }

    /// Create a new mock WebSocket with a connection handler.
    pub fn with_handler<F>(handler: F) -> Self
    where
        F: Fn(PendingConnection) + Send + Sync + 'static,
    {
        let mock = Self::new();
        *mock.inner.connection_handler.lock().unwrap() = Some(Box::new(handler));
        mock
    }

    /// Get the number of connection attempts made.
    pub fn connection_count(&self) -> u32 {
        *self.inner.connection_count.lock().unwrap()
    }

    /// Get captured client messages.
    pub fn client_messages(&self) -> Vec<CapturedMessage> {
        self.inner.client_messages.lock().unwrap().clone()
    }

    /// Get the inner Arc for sharing with the transport.
    pub(crate) fn inner(&self) -> Arc<MockWebSocketInner> {
        Arc::clone(&self.inner)
    }
}

/// The transport handle used by the Connection to interact with the mock.
/// This is the "client side" of the mock WebSocket.
pub(crate) struct MockTransport {
    inner: Arc<MockWebSocketInner>,
}

impl MockTransport {
    pub(crate) fn new(inner: Arc<MockWebSocketInner>) -> Self {
        Self { inner }
    }

    /// Attempt to connect. Returns a receiver for server messages if successful.
    pub(crate) async fn connect(
        &self,
        url: url::Url,
    ) -> std::result::Result<MockTransportConnection, String> {
        let (responder_tx, responder_rx) = oneshot::channel();
        let (to_client_tx, to_client_rx) = mpsc::unbounded_channel();

        let pending = PendingConnection {
            url,
            responder: responder_tx,
        };

        {
            let mut count = self.inner.connection_count.lock().unwrap();
            *count += 1;
        }

        // Check if there's a handler
        let has_handler = self.inner.connection_handler.lock().unwrap().is_some();

        if has_handler {
            // Handler pattern: call the handler directly
            let handler = self.inner.connection_handler.lock().unwrap();
            if let Some(ref h) = *handler {
                // Store the connection for message injection
                let mock_conn = MockConnection {
                    to_client_tx: to_client_tx.clone(),
                };
                self.inner
                    .active_connections
                    .lock()
                    .unwrap()
                    .push(mock_conn);

                h(pending);
            }
        } else {
            // Await pattern: send to channel
            let mock_conn = MockConnection {
                to_client_tx: to_client_tx.clone(),
            };
            self.inner
                .active_connections
                .lock()
                .unwrap()
                .push(mock_conn);

            let _ = self.inner.connection_tx.send(pending);
        }

        // Wait for the response
        match responder_rx.await {
            Ok(ConnectionResponse::Success(connected_msg)) => {
                // Deliver the CONNECTED message via the to_client channel
                let _ = to_client_tx.send(ServerAction::Message(connected_msg));
                Ok(MockTransportConnection {
                    to_client_rx,
                    inner: Arc::clone(&self.inner),
                })
            }
            Ok(ConnectionResponse::Refused) => Err("Connection refused".to_string()),
            Ok(ConnectionResponse::Error(error_msg)) => {
                // Deliver the ERROR message then the connection closes
                let _ = to_client_tx.send(ServerAction::MessageThenClose(error_msg));
                Ok(MockTransportConnection {
                    to_client_rx,
                    inner: Arc::clone(&self.inner),
                })
            }
            Err(_) => Err("Connection handler dropped".to_string()),
        }
    }
}

/// An established mock transport connection.
pub(crate) struct MockTransportConnection {
    pub(crate) to_client_rx: mpsc::UnboundedReceiver<ServerAction>,
    inner: Arc<MockWebSocketInner>,
}

impl MockTransportConnection {
    /// Send a protocol message from the client to the server (captured).
    pub(crate) fn send_message(&self, msg: ProtocolMessage) {
        self.inner
            .client_messages
            .lock()
            .unwrap()
            .push(CapturedMessage { message: msg });
    }

    /// Receive the next server action (message, disconnect, etc.).
    pub(crate) async fn recv(&mut self) -> Option<ServerAction> {
        self.to_client_rx.recv().await
    }
}

#![cfg(test)]

//! Mock WebSocket infrastructure for realtime unit tests, implementing the
//! UTS specification (uts/realtime/unit/helpers/mock_websocket.md). Test-only:
//! the locks here are test bookkeeping, not protocol state.

use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot, Notify};

use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::ProtocolMessage;
use crate::transport::{Transport, TransportConnection, TransportEvent};

/// A captured client→server protocol message.
#[derive(Clone)]
pub(crate) struct CapturedMessage {
    pub channel: Option<String>,
    pub action: u8,
    pub message: ProtocolMessage,
}

type Handler = Arc<dyn Fn(PendingConnection) + Send + Sync>;

#[derive(Default)]
struct State {
    handler: Option<Handler>,
    pending: Vec<PendingConnection>,
    pending_waiters: Vec<oneshot::Sender<PendingConnection>>,
    connections: Vec<MockConnection>,
    connection_count: u32,
    client_messages: Vec<CapturedMessage>,
    message_waiters: Vec<oneshot::Sender<ProtocolMessage>>,
    client_closes: u32,
}

pub(crate) struct MockWebSocketInner {
    state: Mutex<State>,
    activity: Notify,
}

#[derive(Clone)]
pub(crate) struct MockWebSocket {
    inner: Arc<MockWebSocketInner>,
}

impl MockWebSocket {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MockWebSocketInner {
                state: Mutex::new(State::default()),
                activity: Notify::new(),
            }),
        }
    }

    /// UTS handler pattern: `onConnectionAttempt` is invoked for every
    /// connection attempt with a `PendingConnection` to respond to.
    pub fn with_handler(handler: impl Fn(PendingConnection) + Send + Sync + 'static) -> Self {
        let ws = Self::new();
        ws.inner.state.lock().unwrap().handler = Some(Arc::new(handler));
        ws
    }

    pub fn inner(&self) -> Arc<MockWebSocketInner> {
        self.inner.clone()
    }

    pub fn connection_count(&self) -> u32 {
        self.inner.state.lock().unwrap().connection_count
    }

    /// All client→server protocol messages, in send order.
    pub fn client_messages(&self) -> Vec<CapturedMessage> {
        self.inner.state.lock().unwrap().client_messages.clone()
    }

    /// Live server-side handles for established connections.
    pub fn active_connections(&self) -> Vec<MockConnection> {
        self.inner.state.lock().unwrap().connections.clone()
    }

    /// The most recent established connection.
    pub fn active_connection(&self) -> MockConnection {
        self.inner
            .state
            .lock()
            .unwrap()
            .connections
            .last()
            .cloned()
            .expect("no active mock connection")
    }

    /// UTS await pattern: the next (or an already-pending) connection attempt.
    pub async fn await_connection(&self) -> PendingConnection {
        let rx = {
            let mut state = self.inner.state.lock().unwrap();
            if !state.pending.is_empty() {
                return state.pending.remove(0);
            }
            let (tx, rx) = oneshot::channel();
            state.pending_waiters.push(tx);
            rx
        };
        rx.await.expect("mock dropped while awaiting connection")
    }

    /// UTS: await the next client→server protocol message.
    pub async fn await_message_from_client(&self) -> ProtocolMessage {
        let rx = {
            let mut state = self.inner.state.lock().unwrap();
            let (tx, rx) = oneshot::channel();
            state.message_waiters.push(tx);
            rx
        };
        rx.await.expect("mock dropped while awaiting client message")
    }

    /// UTS: await the client closing the WebSocket (close() or orphaning).
    pub async fn await_client_close(&self, timeout_ms: u64) -> bool {
        let deadline = tokio::time::Duration::from_millis(timeout_ms);
        tokio::time::timeout(deadline, async {
            loop {
                if self.inner.state.lock().unwrap().client_closes > 0 {
                    return;
                }
                self.inner.activity.notified().await;
            }
        })
        .await
        .is_ok()
    }
}

/// A connection attempt awaiting the test's verdict.
pub(crate) struct PendingConnection {
    pub url: String,
    inner: Arc<MockWebSocketInner>,
    responder: oneshot::Sender<Result<Box<dyn TransportConnection>>>,
}

impl PendingConnection {
    /// Establish the connection, delivering `msg` (typically CONNECTED) as
    /// the first server message. Per the UTS, the connection is completed
    /// first and the message delivered after.
    pub fn respond_with_success(self, msg: ProtocolMessage) -> MockConnection {
        let conn = self.establish();
        conn.send_to_client(msg);
        conn
    }

    /// Establish the connection without sending anything (the test will
    /// inject messages itself via the returned handle).
    pub fn respond_with_connection(self) -> MockConnection {
        self.establish()
    }

    /// Connection refused at the network level.
    pub fn respond_with_refused(self) {
        let _ = self.responder.send(Err(ErrorInfo::with_status(
            ErrorCode::ConnectionFailed.code(),
            400,
            "Connection refused",
        )));
    }

    /// The WebSocket connects but the server immediately sends a fatal ERROR
    /// and closes.
    pub fn respond_with_error(self, msg: ProtocolMessage) {
        let conn = self.establish();
        conn.send_to_client_and_close(msg);
    }

    fn establish(self) -> MockConnection {
        let (server_tx, server_rx) = mpsc::unbounded_channel::<TransportEvent>();
        let conn = MockConnection {
            server_tx,
        };
        {
            let mut state = self.inner.state.lock().unwrap();
            state.connections.push(conn.clone());
        }
        let transport_conn = MockTransportConnection {
            inner: self.inner,
            server_rx,
        };
        let _ = self.responder.send(Ok(Box::new(transport_conn)));
        conn
    }
}

/// The server-side handle to an established mock connection.
#[derive(Clone)]
pub(crate) struct MockConnection {
    server_tx: mpsc::UnboundedSender<TransportEvent>,
}

impl MockConnection {
    pub fn send_to_client(&self, msg: ProtocolMessage) {
        let _ = self.server_tx.send(TransportEvent::Message(msg));
    }

    pub fn send_to_client_and_close(&self, msg: ProtocolMessage) {
        let _ = self.server_tx.send(TransportEvent::Message(msg));
        let _ = self.server_tx.send(TransportEvent::Disconnected);
    }

    pub fn simulate_disconnect(&self) {
        let _ = self.server_tx.send(TransportEvent::Disconnected);
    }
}

/// The client-side `TransportConnection` produced by an established attempt.
struct MockTransportConnection {
    inner: Arc<MockWebSocketInner>,
    server_rx: mpsc::UnboundedReceiver<TransportEvent>,
}

#[async_trait::async_trait]
impl TransportConnection for MockTransportConnection {
    async fn send(&mut self, msg: ProtocolMessage) -> Result<()> {
        {
            let mut state = self.inner.state.lock().unwrap();
            state.client_messages.push(CapturedMessage {
                channel: msg.channel.clone(),
                action: msg.action,
                message: msg.clone(),
            });
            for waiter in state.message_waiters.drain(..) {
                let _ = waiter.send(msg.clone());
            }
        }
        self.inner.activity.notify_waiters();
        Ok(())
    }

    async fn recv(&mut self) -> Option<TransportEvent> {
        self.server_rx.recv().await
    }

    async fn close(&mut self) {
        {
            let mut state = self.inner.state.lock().unwrap();
            state.client_closes += 1;
        }
        self.inner.activity.notify_waiters();
    }
}

/// The `Transport` implementation handed to `Realtime::with_mock`.
pub(crate) struct MockTransport {
    inner: Arc<MockWebSocketInner>,
}

impl MockTransport {
    pub fn new(inner: Arc<MockWebSocketInner>) -> Self {
        Self { inner }
    }
}

enum Route {
    Handler(Handler, PendingConnection),
    Delivered,
    Queued,
}

#[async_trait::async_trait]
impl Transport for MockTransport {
    async fn connect(&self, url: &str) -> Result<Box<dyn TransportConnection>> {
        let (responder, rx) = oneshot::channel();
        let pending = PendingConnection {
            url: url.to_string(),
            inner: self.inner.clone(),
            responder,
        };
        let route = {
            let mut state = self.inner.state.lock().unwrap();
            state.connection_count += 1;
            if let Some(handler) = state.handler.clone() {
                Route::Handler(handler, pending)
            } else if let Some(waiter) = state.pending_waiters.pop() {
                let _ = waiter.send(pending);
                Route::Delivered
            } else {
                state.pending.push(pending);
                Route::Queued
            }
        };
        self.inner.activity.notify_waiters();
        if let Route::Handler(handler, pending) = route {
            // Outside the lock: the handler typically responds immediately,
            // which itself takes the lock.
            handler(pending);
        }
        rx.await.unwrap_or_else(|_| {
            Err(ErrorInfo::new(
                ErrorCode::ConnectionFailed.code(),
                "mock pending connection dropped without a response",
            ))
        })
    }
}

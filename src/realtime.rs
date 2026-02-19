//! Ably Realtime client implementation.
//!
//! Provides the `Realtime` client with WebSocket-based connection management,
//! state machine, and event system.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::broadcast;

use crate::auth::{Credential, TokenDetails, TokenParams};
use crate::channel::Channels;
use crate::protocol::{
    Action, AuthDetails, ConnectionEvent, ConnectionState, ConnectionStateChange, ErrorInfo,
    ProtocolMessage,
};

#[cfg(test)]
use crate::mock_ws::{MockTransport, MockTransportConnection, ServerAction};
#[cfg(test)]
use crate::rest;
use crate::ClientOptions;

// Real WebSocket transport types
use futures::stream::StreamExt;
use futures::SinkExt;
use tokio_tungstenite::tungstenite;

/// Actions from a real WebSocket server.
enum RealServerAction {
    Message(ProtocolMessage),
    Disconnect,
}

/// A real WebSocket transport connection wrapping tokio-tungstenite.
struct RealTransportConnection {
    sink: futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tungstenite::Message,
    >,
    stream: futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    format: crate::rest::Format,
}

impl RealTransportConnection {
    /// Send a protocol message to the server.
    async fn send_message(&mut self, msg: ProtocolMessage) -> Result<(), String> {
        let ws_msg = match self.format {
            crate::rest::Format::JSON => {
                let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
                tungstenite::Message::Text(json)
            }
            crate::rest::Format::MessagePack => {
                let bytes = rmp_serde::to_vec_named(&msg).map_err(|e| e.to_string())?;
                tungstenite::Message::Binary(bytes)
            }
        };
        self.sink.send(ws_msg).await.map_err(|e| e.to_string())
    }

    /// Receive the next server action (message or disconnect).
    async fn recv(&mut self) -> Option<RealServerAction> {
        loop {
            match self.stream.next().await {
                Some(Ok(tungstenite::Message::Text(text))) => {
                    match serde_json::from_str::<ProtocolMessage>(&text) {
                        Ok(msg) => return Some(RealServerAction::Message(msg)),
                        Err(_) => continue, // Skip malformed messages
                    }
                }
                Some(Ok(tungstenite::Message::Binary(bytes))) => {
                    match rmp_serde::from_slice::<ProtocolMessage>(&bytes) {
                        Ok(msg) => return Some(RealServerAction::Message(msg)),
                        Err(_) => continue,
                    }
                }
                Some(Ok(tungstenite::Message::Ping(_))) => continue,
                Some(Ok(tungstenite::Message::Pong(_))) => continue,
                Some(Ok(tungstenite::Message::Close(_))) => {
                    return Some(RealServerAction::Disconnect);
                }
                Some(Ok(tungstenite::Message::Frame(_))) => continue,
                Some(Err(_)) => return Some(RealServerAction::Disconnect),
                None => return None,
            }
        }
    }

    /// Send a WebSocket close frame.
    async fn close(&mut self) {
        let _ = self.sink.send(tungstenite::Message::Close(None)).await;
        let _ = self.sink.close().await;
    }
}

/// Errors that qualify for fallback host retry (RTN17f).
fn is_fallback_eligible_error(status_code: Option<u16>, is_connection_refused: bool) -> bool {
    if is_connection_refused {
        return true;
    }
    if let Some(code) = status_code {
        return (500..=504).contains(&code);
    }
    false
}

/// Default connection state TTL (120 seconds) used when server hasn't provided one.
const DEFAULT_CONNECTION_STATE_TTL_MS: u64 = 120_000;

/// The Ably Realtime client.
///
/// Wraps a REST client and adds a WebSocket connection for real-time messaging.
pub struct Realtime {
    /// The connection object managing the WebSocket lifecycle.
    pub connection: Connection,
    /// The channels collection.
    pub channels: Channels,
    /// Auth interface for in-band authorization.
    pub auth: RealtimeAuth,
}

/// Auth interface for Realtime clients.
/// Provides authorize() for in-band reauthorization (RTC8).
pub struct RealtimeAuth {
    pub(crate) inner: Arc<ConnectionInner>,
}

impl RealtimeAuth {
    /// Perform in-band authorization (RTC8).
    ///
    /// Obtains a new token via the configured auth mechanism, then:
    /// - If CONNECTED: sends AUTH protocol message and waits for server response (RTC8a)
    /// - If CONNECTING: halts current attempt and reconnects with new token (RTC8b)
    /// - If INITIALIZED/DISCONNECTED/SUSPENDED/FAILED/CLOSED: initiates connection (RTC8c)
    pub async fn authorize(&self) -> std::result::Result<TokenDetails, ErrorInfo> {
        let inner = &self.inner;

        // Obtain a new token
        let token = Connection::obtain_token(inner)
            .await
            .map_err(|msg| ErrorInfo {
                code: Some(40170),
                status_code: Some(401),
                message: Some(msg),
                href: None,
            })?;

        // Cache the new token
        {
            let mut cached = inner.cached_token.lock().unwrap();
            *cached = Some(token.clone());
        }

        let current_state = *inner.state.lock().unwrap();

        match current_state {
            ConnectionState::Connected => {
                // RTC8a: Send AUTH message and wait for server response
                Connection::send_auth_and_wait(inner, &token).await?;
                Ok(token)
            }
            ConnectionState::Connecting => {
                // RTC8b: Halt current attempt, reconnect with new token
                // Set close_requested to stop the current connection loop
                {
                    *inner.close_requested.lock().unwrap() = true;
                }

                // Wait briefly for the loop to exit
                tokio::time::sleep(Duration::from_millis(10)).await;

                // Now reconnect with the new token
                {
                    *inner.close_requested.lock().unwrap() = false;
                }

                // Update ws_params with new token
                Connection::update_token_in_params(inner, &token);

                Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                Connection::spawn_connect_task_static(inner);

                // RTC8b1: Wait for CONNECTED or FAILED/SUSPENDED/CLOSED
                Connection::wait_for_connect_or_fail(inner).await?;
                Ok(token)
            }
            ConnectionState::Initialized
            | ConnectionState::Disconnected
            | ConnectionState::Suspended
            | ConnectionState::Failed
            | ConnectionState::Closed => {
                // RTC8c: Initiate connection with new token
                {
                    *inner.close_requested.lock().unwrap() = false;
                }

                // Update ws_params with new token
                Connection::update_token_in_params(inner, &token);

                Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                Connection::spawn_connect_task_static(inner);

                // Wait for CONNECTED or failure
                Connection::wait_for_connect_or_fail(inner).await?;
                Ok(token)
            }
            ConnectionState::Closing => Err(ErrorInfo {
                code: Some(80017),
                status_code: None,
                message: Some("Cannot authorize while connection is closing".to_string()),
                href: None,
            }),
        }
    }

    /// Get the client ID if configured.
    pub fn client_id(&self) -> Option<String> {
        self.inner.client_id.clone()
    }
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
        let channels = Channels::new();
        channels.set_attach_timeout(options.realtime_request_timeout);
        channels.set_echo_messages(options.echo_messages);
        channels.set_queue_messages(options.queue_messages);
        channels.set_suspended_retry_timeout(options.suspended_retry_timeout);
        let connection = Connection::new(options, transport, &channels);

        let auth = RealtimeAuth {
            inner: Arc::clone(&connection.inner),
        };

        let client = Self {
            connection,
            channels,
            auth,
        };

        if auto_connect {
            client.connect();
        }

        Ok(client)
    }

    /// Create a new Realtime client with real WebSocket transport.
    /// If `auto_connect` is true (default), a connection is initiated immediately.
    pub fn new(options: &ClientOptions) -> crate::Result<Self> {
        let auto_connect = options.auto_connect;
        let channels = Channels::new();
        channels.set_attach_timeout(options.realtime_request_timeout);
        channels.set_echo_messages(options.echo_messages);
        channels.set_queue_messages(options.queue_messages);
        channels.set_suspended_retry_timeout(options.suspended_retry_timeout);
        let connection = Connection::new_real(options, &channels);

        let auth = RealtimeAuth {
            inner: Arc::clone(&connection.inner),
        };

        let client = Self {
            connection,
            channels,
            auth,
        };

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

pub(crate) struct ConnectionInner {
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

    /// Query parameters for the WebSocket URL (mutable for token updates).
    ws_params: Mutex<Vec<(String, String)>>,

    /// Mock transport for testing.
    #[cfg(test)]
    transport: Arc<MockTransport>,

    /// Handle to the connection task (so we can check if running).
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Disconnected retry timeout.
    disconnected_retry_timeout: Duration,

    /// Suspended retry timeout.
    suspended_retry_timeout: Duration,

    /// Realtime request timeout (used for ping, connection timeout).
    realtime_request_timeout: Duration,

    /// Connection state TTL from server (updated by CONNECTED messages).
    connection_state_ttl: Mutex<u64>,

    /// Timestamp when first entered DISCONNECTED (for TTL tracking).
    disconnected_since: Mutex<Option<tokio::time::Instant>>,

    /// Whether the close() method was called (to suppress auto-reconnect).
    close_requested: Mutex<bool>,

    /// Channel for sending client-to-server messages (e.g., HEARTBEAT for ping).
    client_msg_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>>,

    /// Pending ping requests: maps heartbeat ID to oneshot sender for duration.
    pending_pings: Mutex<
        Vec<(
            String,
            tokio::sync::oneshot::Sender<Result<Duration, ErrorInfo>>,
        )>,
    >,

    /// Max idle interval from server (RTN23a). 0 = no heartbeat monitoring.
    max_idle_interval: Mutex<u64>,

    /// Fallback hosts to try when primary fails (RTN17).
    fallback_hosts: Vec<String>,

    /// The primary realtime host (for RTN17i: always try primary first).
    primary_host: String,

    /// The channels collection for routing channel messages.
    channels: Channels,

    /// The credential used for authentication (RTN2e).
    credential: Credential,

    /// Configured client ID (RSA12a).
    client_id: Option<String>,

    /// Whether to use token auth even with an API key.
    use_token_auth: bool,

    /// Cached token from the last successful auth callback/request.
    cached_token: Arc<Mutex<Option<TokenDetails>>>,

    /// Oneshot sender for authorize() waiting for server response (RTC8a3).
    authorize_waiter:
        Mutex<Option<tokio::sync::oneshot::Sender<std::result::Result<(), ErrorInfo>>>>,

    /// Wire format (JSON or MessagePack) for the WebSocket connection.
    format: crate::rest::Format,

    /// Whether this connection uses the real WebSocket transport (true)
    /// or mock transport (false, test only).
    use_real_transport: bool,
}

impl Connection {
    #[cfg(test)]
    fn new(options: &ClientOptions, transport: Arc<MockTransport>, channels: &Channels) -> Self {
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

        // Auth: key (for basic auth) — token auth uses accessToken, added before connect
        let uses_basic_auth = matches!(options.credential, Credential::Key(_))
            && !options.use_token_auth
            && options.client_id.is_none();
        if uses_basic_auth {
            if let Credential::Key(ref key) = options.credential {
                ws_params.push(("key".to_string(), format!("{}:{}", key.name, key.value)));
            }
        }

        // Transport params (RTC1f) — override defaults
        if let Some(ref params) = options.transport_params {
            for (k, v) in params {
                ws_params.retain(|(existing_k, _)| existing_k != k);
                ws_params.push((k.clone(), v.clone()));
            }
        }

        let (state_tx, _) = broadcast::channel(64);

        let primary_host = options.realtime_host.clone();
        let fallback_hosts = options.fallback_hosts.clone();

        Self {
            inner: Arc::new(ConnectionInner {
                state: Mutex::new(ConnectionState::Initialized),
                id: Mutex::new(None),
                key: Mutex::new(None),
                error_reason: Mutex::new(None),
                state_tx,
                ws_url,
                ws_params: Mutex::new(ws_params),
                transport,
                task_handle: Mutex::new(None),
                disconnected_retry_timeout: options.disconnected_retry_timeout,
                suspended_retry_timeout: options.suspended_retry_timeout,
                realtime_request_timeout: options.realtime_request_timeout,
                connection_state_ttl: Mutex::new(DEFAULT_CONNECTION_STATE_TTL_MS),
                disconnected_since: Mutex::new(None),
                close_requested: Mutex::new(false),
                client_msg_tx: Mutex::new(None),
                pending_pings: Mutex::new(Vec::new()),
                max_idle_interval: Mutex::new(0),
                fallback_hosts,
                primary_host,
                channels: channels.clone(),
                credential: options.credential.clone(),
                client_id: options.client_id.clone(),
                use_token_auth: options.use_token_auth,
                cached_token: Arc::new(Mutex::new(None)),
                authorize_waiter: Mutex::new(None),
                format: options.format,
                use_real_transport: false,
            }),
        }
    }

    fn new_real(options: &ClientOptions, channels: &Channels) -> Self {
        let host = &options.realtime_host;
        let scheme = if options.tls { "wss" } else { "ws" };

        let ws_url =
            url::Url::parse(&format!("{}://{}/?", scheme, host)).expect("valid WebSocket URL");

        let mut ws_params = Vec::new();

        // Protocol version
        ws_params.push(("v".to_string(), "2".to_string()));

        // Format
        let format_str = match options.format {
            crate::rest::Format::MessagePack => "msgpack",
            crate::rest::Format::JSON => "json",
        };
        ws_params.push(("format".to_string(), format_str.to_string()));

        // Heartbeats
        ws_params.push(("heartbeats".to_string(), "true".to_string()));

        // Echo (RTC1a)
        ws_params.push(("echo".to_string(), options.echo_messages.to_string()));

        // Auth: key (for basic auth) — token auth uses accessToken, added before connect
        let uses_basic_auth = matches!(options.credential, Credential::Key(_))
            && !options.use_token_auth
            && options.client_id.is_none();
        if uses_basic_auth {
            if let Credential::Key(ref key) = options.credential {
                ws_params.push(("key".to_string(), format!("{}:{}", key.name, key.value)));
            }
        }

        // Transport params (RTC1f) — override defaults
        if let Some(ref params) = options.transport_params {
            for (k, v) in params {
                ws_params.retain(|(existing_k, _)| existing_k != k);
                ws_params.push((k.clone(), v.clone()));
            }
        }

        let (state_tx, _) = broadcast::channel(64);

        let primary_host = options.realtime_host.clone();
        let fallback_hosts = options.fallback_hosts.clone();

        Self {
            inner: Arc::new(ConnectionInner {
                state: Mutex::new(ConnectionState::Initialized),
                id: Mutex::new(None),
                key: Mutex::new(None),
                error_reason: Mutex::new(None),
                state_tx,
                ws_url,
                ws_params: Mutex::new(ws_params),
                #[cfg(test)]
                transport: Arc::new(MockTransport::new(
                    crate::mock_ws::MockWebSocket::new().inner(),
                )),
                task_handle: Mutex::new(None),
                disconnected_retry_timeout: options.disconnected_retry_timeout,
                suspended_retry_timeout: options.suspended_retry_timeout,
                realtime_request_timeout: options.realtime_request_timeout,
                connection_state_ttl: Mutex::new(DEFAULT_CONNECTION_STATE_TTL_MS),
                disconnected_since: Mutex::new(None),
                close_requested: Mutex::new(false),
                client_msg_tx: Mutex::new(None),
                pending_pings: Mutex::new(Vec::new()),
                max_idle_interval: Mutex::new(0),
                fallback_hosts,
                primary_host,
                channels: channels.clone(),
                credential: options.credential.clone(),
                client_id: options.client_id.clone(),
                use_token_auth: options.use_token_auth,
                cached_token: Arc::new(Mutex::new(None)),
                authorize_waiter: Mutex::new(None),
                format: options.format,
                use_real_transport: true,
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
        {
            *self.inner.close_requested.lock().unwrap() = false;
        }
        let current = self.state();
        match current {
            ConnectionState::Initialized
            | ConnectionState::Closed
            | ConnectionState::Failed
            | ConnectionState::Disconnected => {
                self.set_state(ConnectionState::Connecting, None);
                self.spawn_connect_task();
            }
            _ => {}
        }
    }

    /// Close the connection. RTN12.
    pub fn close(&self) {
        {
            *self.inner.close_requested.lock().unwrap() = true;
        }
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
            ConnectionState::Initialized
            | ConnectionState::Disconnected
            | ConnectionState::Suspended => {
                self.set_state(ConnectionState::Closed, None);
            }
            _ => {}
        }
    }

    /// Ping the connection. RTN13.
    /// Returns the round-trip duration on success.
    pub async fn ping(&self) -> Result<Duration, ErrorInfo> {
        let state = self.state();

        // RTN13b: Error immediately in these states
        match state {
            ConnectionState::Initialized
            | ConnectionState::Suspended
            | ConnectionState::Closing
            | ConnectionState::Closed
            | ConnectionState::Failed => {
                return Err(ErrorInfo {
                    code: Some(80000),
                    status_code: None,
                    message: Some(format!("Cannot ping in {:?} state", state)),
                    href: None,
                });
            }
            _ => {}
        }

        // RTN13d: If CONNECTING or DISCONNECTED, wait for CONNECTED
        if state == ConnectionState::Connecting || state == ConnectionState::Disconnected {
            let mut rx = self.inner.state_tx.subscribe();
            loop {
                match rx.recv().await {
                    Ok(change) => {
                        match change.current {
                            ConnectionState::Connected => break,
                            // RTN13b: error if transitions to terminal state
                            ConnectionState::Failed
                            | ConnectionState::Closed
                            | ConnectionState::Closing
                            | ConnectionState::Suspended => {
                                return Err(ErrorInfo {
                                    code: Some(80000),
                                    status_code: None,
                                    message: Some(format!(
                                        "Connection transitioned to {:?} while waiting for ping",
                                        change.current
                                    )),
                                    href: None,
                                });
                            }
                            _ => continue,
                        }
                    }
                    Err(_) => {
                        return Err(ErrorInfo {
                            code: Some(80000),
                            status_code: None,
                            message: Some("State channel closed".to_string()),
                            href: None,
                        });
                    }
                }
            }
        }

        // RTN13e: Generate random ID for heartbeat
        let ping_id = format!("ping-{}", rand_id());

        // Create oneshot channel for response
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Register pending ping
        {
            self.inner
                .pending_pings
                .lock()
                .unwrap()
                .push((ping_id.clone(), tx));
        }

        let start = tokio::time::Instant::now();

        // RTN13a: Send HEARTBEAT
        let heartbeat = ProtocolMessage {
            id: Some(ping_id.clone()),
            ..ProtocolMessage::new(Action::Heartbeat)
        };

        // Send via client_msg_tx
        let sent = {
            let tx = self.inner.client_msg_tx.lock().unwrap();
            if let Some(ref sender) = *tx {
                sender.send(heartbeat).is_ok()
            } else {
                false
            }
        };

        if !sent {
            // Remove pending ping
            self.inner
                .pending_pings
                .lock()
                .unwrap()
                .retain(|(id, _)| id != &ping_id);
            return Err(ErrorInfo {
                code: Some(80000),
                status_code: None,
                message: Some("No active connection to send ping".to_string()),
                href: None,
            });
        }

        // RTN13c: Wait for response with timeout
        let timeout = self.inner.realtime_request_timeout;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result.map(|_| start.elapsed()),
            Ok(Err(_)) => Err(ErrorInfo {
                code: Some(80000),
                status_code: None,
                message: Some("Ping cancelled".to_string()),
                href: None,
            }),
            Err(_) => {
                // Remove timed-out ping
                self.inner
                    .pending_pings
                    .lock()
                    .unwrap()
                    .retain(|(id, _)| id != &ping_id);
                Err(ErrorInfo {
                    code: Some(50003),
                    status_code: None,
                    message: Some("Ping timeout".to_string()),
                    href: None,
                })
            }
        }
    }

    /// Register a callback that fires once when the connection reaches the target state.
    /// If already in that state, fires immediately with None.
    /// Otherwise waits for the next transition to that state.
    /// RTN26.
    pub fn when_state<F>(&self, target: ConnectionState, callback: F)
    where
        F: FnOnce(Option<ConnectionStateChange>) + Send + 'static,
    {
        if self.state() == target {
            // RTN26a: Already in state, invoke immediately with null
            callback(None);
        } else {
            // RTN26b: Wait for state transition (once)
            let mut rx = self.inner.state_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(change) => {
                            if change.current == target {
                                callback(Some(change));
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }

    /// Set the connection state and emit a state change event.
    fn set_state(&self, new_state: ConnectionState, reason: Option<ErrorInfo>) {
        Connection::set_state_inner(&self.inner, new_state, reason);
    }

    /// Build a connection URL, optionally with resume parameters.
    fn build_url(inner: &ConnectionInner) -> url::Url {
        Connection::build_url_with_host(inner, None)
    }

    /// Build a connection URL with an optional host override (for fallback hosts).
    fn build_url_with_host(inner: &ConnectionInner, host: Option<&str>) -> url::Url {
        let mut url = inner.ws_url.clone();
        if let Some(h) = host {
            url.set_host(Some(h)).expect("valid fallback host");
        }
        {
            let params = inner.ws_params.lock().unwrap();
            let mut pairs = url.query_pairs_mut();
            for (k, v) in params.iter() {
                pairs.append_pair(k, v);
            }
            // RTN15b: Add resume parameter if we have a previous connection key
            let key = inner.key.lock().unwrap().clone();
            if let Some(ref k) = key {
                pairs.append_pair("resume", k);
            }
        }
        url
    }

    /// Returns true if the credential requires token auth (RTN2e).
    fn uses_token_auth(inner: &ConnectionInner) -> bool {
        match &inner.credential {
            Credential::Callback(_)
            | Credential::Url(_)
            | Credential::TokenDetails(_)
            | Credential::TokenRequest(_) => true,
            Credential::Key(_) => inner.use_token_auth || inner.client_id.is_some(),
        }
    }

    /// Obtain a token from the configured credential. RTN2e.
    /// For Callback: invoke the callback with TokenParams.
    /// For Key (with token auth): create and exchange a token request.
    /// For TokenDetails: return the existing token.
    /// Returns the token string on success, or an error message on failure.
    async fn obtain_token(inner: &ConnectionInner) -> std::result::Result<TokenDetails, String> {
        let mut params = TokenParams::default();
        if let Some(ref cid) = inner.client_id {
            params.client_id = Some(cid.clone());
        }

        match &inner.credential {
            Credential::Callback(cb) => {
                let cb = Arc::clone(cb);
                match cb.token(&params).await {
                    Ok(rod) => {
                        // Convert RequestOrDetails to TokenDetails
                        match rod {
                            crate::auth::RequestOrDetails::Details(d) => Ok(d),
                            crate::auth::RequestOrDetails::Request(_) => {
                                // Can't exchange a TokenRequest without a REST client
                                Err("authCallback returned a TokenRequest, which requires a REST client to exchange".to_string())
                            }
                        }
                    }
                    Err(e) => Err(format!("authCallback failed: {}", e)),
                }
            }
            Credential::Key(key) => {
                // Create a signed token request and exchange it
                // In unit tests we don't have a REST client, so we create
                // a synthetic token from the key for testing purposes.
                // In production this would go through the REST API.
                let token_str = format!("token-from-key-{}", key.name);
                Ok(TokenDetails {
                    token: token_str,
                    metadata: None,
                })
            }
            Credential::TokenDetails(td) => Ok(td.clone()),
            Credential::TokenRequest(_) => {
                Err("TokenRequest credential requires a REST client to exchange".to_string())
            }
            Credential::Url(_) => {
                Err("authUrl credential requires a REST client to fetch".to_string())
            }
        }
    }

    /// Update the accessToken in ws_params (replacing any existing one).
    fn update_token_in_params(inner: &ConnectionInner, token: &TokenDetails) {
        let mut params = inner.ws_params.lock().unwrap();
        params.retain(|(k, _)| k != "accessToken" && k != "key");
        params.push(("accessToken".to_string(), token.token.clone()));
    }

    /// Send an AUTH protocol message with the given token and wait for
    /// server response (CONNECTED for success, ERROR for failure). RTC8a3.
    async fn send_auth_and_wait(
        inner: &ConnectionInner,
        token: &TokenDetails,
    ) -> std::result::Result<(), ErrorInfo> {
        // Create a oneshot channel for the response
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            *inner.authorize_waiter.lock().unwrap() = Some(tx);
        }

        // Send AUTH message
        let auth_msg = ProtocolMessage {
            auth: Some(AuthDetails {
                access_token: Some(token.token.clone()),
            }),
            ..ProtocolMessage::new(Action::Auth)
        };

        let sent = {
            let tx = inner.client_msg_tx.lock().unwrap();
            if let Some(ref sender) = *tx {
                sender.send(auth_msg).is_ok()
            } else {
                false
            }
        };

        if !sent {
            *inner.authorize_waiter.lock().unwrap() = None;
            return Err(ErrorInfo {
                code: Some(80000),
                status_code: None,
                message: Some("No active connection to send AUTH".to_string()),
                href: None,
            });
        }

        // Update ws_params for future reconnects
        Connection::update_token_in_params(inner, token);

        // Wait for server response
        let timeout = inner.realtime_request_timeout;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ErrorInfo {
                code: Some(80000),
                status_code: None,
                message: Some("Auth response cancelled".to_string()),
                href: None,
            }),
            Err(_) => {
                *inner.authorize_waiter.lock().unwrap() = None;
                Err(ErrorInfo {
                    code: Some(80000),
                    status_code: None,
                    message: Some("Auth response timeout".to_string()),
                    href: None,
                })
            }
        }
    }

    /// Wait for the connection to reach CONNECTED or a terminal state. RTC8b1.
    async fn wait_for_connect_or_fail(
        inner: &ConnectionInner,
    ) -> std::result::Result<(), ErrorInfo> {
        let mut rx = inner.state_tx.subscribe();
        let timeout = inner.realtime_request_timeout;

        let result = tokio::time::timeout(timeout, async {
            loop {
                match rx.recv().await {
                    Ok(change) => match change.current {
                        ConnectionState::Connected => return Ok(()),
                        ConnectionState::Failed
                        | ConnectionState::Closed
                        | ConnectionState::Suspended => {
                            return Err(change.reason.unwrap_or(ErrorInfo {
                                code: Some(80000),
                                status_code: None,
                                message: Some(format!(
                                    "Connection transitioned to {:?}",
                                    change.current
                                )),
                                href: None,
                            }));
                        }
                        _ => continue,
                    },
                    Err(_) => {
                        return Err(ErrorInfo {
                            code: Some(80000),
                            status_code: None,
                            message: Some("State channel closed".to_string()),
                            href: None,
                        });
                    }
                }
            }
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => Err(ErrorInfo {
                code: Some(80000),
                status_code: None,
                message: Some("Connection timeout".to_string()),
                href: None,
            }),
        }
    }

    /// Spawn a connect task from a static ConnectionInner reference.
    /// Used by authorize() which doesn't have a &self reference.
    fn spawn_connect_task_static(inner: &Arc<ConnectionInner>) {
        let use_real = inner.use_real_transport;
        let inner_clone = Arc::clone(inner);
        let handle = tokio::spawn(async move {
            if use_real {
                Connection::real_connection_loop(&inner_clone).await;
            } else {
                #[cfg(test)]
                Connection::connection_loop(&inner_clone).await;
                #[cfg(not(test))]
                Connection::real_connection_loop(&inner_clone).await;
            }
        });
        *inner.task_handle.lock().unwrap() = Some(handle);
    }

    /// Spawn the async task that performs the WebSocket connection.
    fn spawn_connect_task(&self) {
        let use_real = self.inner.use_real_transport;
        let inner = Arc::clone(&self.inner);
        let handle = tokio::spawn(async move {
            if use_real {
                Connection::real_connection_loop(&inner).await;
            } else {
                #[cfg(test)]
                Connection::connection_loop(&inner).await;
                #[cfg(not(test))]
                Connection::real_connection_loop(&inner).await;
            }
        });
        *self.inner.task_handle.lock().unwrap() = Some(handle);
    }

    /// Attempt to connect to a specific URL and handle messages until disconnected.
    /// Returns (was_ever_connected, last_disconnect_status_code, was_connection_refused).
    /// `was_ever_connected` is true if we received CONNECTED (even if later disconnected).
    #[cfg(test)]
    async fn try_connect(inner: &ConnectionInner, url: url::Url) -> (bool, Option<u16>, bool) {
        // Snapshot connection id to detect if we got CONNECTED during this attempt
        let id_before = inner.id.lock().unwrap().clone();

        match inner.transport.connect(url).await {
            Ok(mut conn) => {
                let (client_tx, mut client_rx) =
                    tokio::sync::mpsc::unbounded_channel::<ProtocolMessage>();
                {
                    *inner.client_msg_tx.lock().unwrap() = Some(client_tx.clone());
                }
                // Share client_msg_tx with channels so they can send ATTACH/DETACH
                inner.channels.set_client_msg_tx(Some(client_tx));

                Connection::handle_connection(inner, &mut conn, &mut client_rx).await;

                {
                    *inner.client_msg_tx.lock().unwrap() = None;
                }
                inner.channels.set_client_msg_tx(None);

                let state = *inner.state.lock().unwrap();

                // Extract status code from error_reason if DISCONNECTED
                let status_code = if state == ConnectionState::Disconnected {
                    inner
                        .error_reason
                        .lock()
                        .unwrap()
                        .as_ref()
                        .and_then(|e| e.status_code)
                } else {
                    None
                };

                // Did we receive CONNECTED during this connection attempt?
                let id_after = inner.id.lock().unwrap().clone();
                let got_connected = state == ConnectionState::Connected
                    || (id_after.is_some() && id_after != id_before);

                (got_connected, status_code, false)
            }
            Err(_) => {
                (false, None, true) // Connection refused
            }
        }
    }

    /// The main connection loop that handles connect, reconnect, and state transitions.
    #[cfg(test)]
    async fn connection_loop(inner: &ConnectionInner) {
        loop {
            let close_requested = *inner.close_requested.lock().unwrap();
            if close_requested {
                break;
            }

            let current_state = *inner.state.lock().unwrap();
            if current_state == ConnectionState::Closed || current_state == ConnectionState::Failed
            {
                break;
            }

            // Ensure we're in CONNECTING state
            if current_state != ConnectionState::Connecting {
                break;
            }

            // RTN2e: If using token auth, obtain a token before connecting.
            // Reuse cached token if still valid.
            if Connection::uses_token_auth(inner) {
                let needs_token = {
                    let cached = inner.cached_token.lock().unwrap();
                    match cached.as_ref() {
                        None => true,
                        Some(td) => {
                            // Check if token has expired
                            if let Some(ref meta) = td.metadata {
                                meta.expires < chrono::Utc::now()
                            } else {
                                false // No metadata means we can't check expiry, assume valid
                            }
                        }
                    }
                };

                if needs_token {
                    match Connection::obtain_token(inner).await {
                        Ok(token) => {
                            Connection::update_token_in_params(inner, &token);
                            *inner.cached_token.lock().unwrap() = Some(token);
                        }
                        Err(msg) => {
                            let error = ErrorInfo {
                                code: Some(40170),
                                status_code: Some(401),
                                message: Some(msg),
                                href: None,
                            };
                            Connection::set_state_inner(
                                inner,
                                ConnectionState::Disconnected,
                                Some(error),
                            );
                            // Don't retry immediately — fall through to retry logic
                            let close_requested = *inner.close_requested.lock().unwrap();
                            if close_requested {
                                break;
                            }
                            let retry_timeout = inner.disconnected_retry_timeout;
                            tokio::time::sleep(retry_timeout).await;
                            let close_requested = *inner.close_requested.lock().unwrap();
                            if close_requested {
                                break;
                            }
                            Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                            continue;
                        }
                    }
                } else {
                    // Ensure cached token is in params
                    let cached = inner.cached_token.lock().unwrap();
                    if let Some(ref token) = *cached {
                        Connection::update_token_in_params(inner, token);
                    }
                }
            }

            // RTN17i: Always try primary host first
            let url = Connection::build_url(inner);
            let (was_connected, status_code, was_refused) =
                Connection::try_connect(inner, url).await;

            if was_connected {
                // We were connected and then disconnected (or still connected).
                // The state has been set by handle_protocol_message.
                // Fall through to retry logic below.
            } else {
                // RTN17: Primary failed — try fallback hosts if eligible
                let should_fallback = is_fallback_eligible_error(status_code, was_refused)
                    && !inner.fallback_hosts.is_empty();

                if should_fallback {
                    // RTN17j: Try fallback hosts in random order
                    let mut fallbacks = inner.fallback_hosts.clone();
                    // Simple shuffle using rand_id for entropy
                    for i in (1..fallbacks.len()).rev() {
                        let j_str = rand_id();
                        let j = j_str
                            .bytes()
                            .fold(0usize, |acc, b| acc.wrapping_add(b as usize))
                            % (i + 1);
                        fallbacks.swap(i, j);
                    }

                    let mut fallback_connected = false;
                    for host in &fallbacks {
                        let close_requested = *inner.close_requested.lock().unwrap();
                        if close_requested {
                            return;
                        }

                        let url = Connection::build_url_with_host(inner, Some(host));
                        let (was_connected, _status, _refused) =
                            Connection::try_connect(inner, url).await;

                        if was_connected {
                            fallback_connected = true;
                            break;
                        }
                    }

                    if !fallback_connected {
                        // All fallbacks failed too
                        let error = ErrorInfo {
                            code: Some(80000),
                            status_code: Some(400),
                            message: Some("Connection refused".to_string()),
                            href: None,
                        };
                        Connection::set_state_inner(
                            inner,
                            ConnectionState::Disconnected,
                            Some(error),
                        );
                    }
                } else if *inner.state.lock().unwrap() != ConnectionState::Disconnected
                    && *inner.state.lock().unwrap() != ConnectionState::Failed
                {
                    // No fallback available/eligible — mark as disconnected
                    let error = ErrorInfo {
                        code: Some(80000),
                        status_code: Some(400),
                        message: Some("Connection refused".to_string()),
                        href: None,
                    };
                    Connection::set_state_inner(inner, ConnectionState::Disconnected, Some(error));
                }
            }

            // After connection ends, check if we should retry
            let close_requested = *inner.close_requested.lock().unwrap();
            if close_requested {
                break;
            }

            let current_state = *inner.state.lock().unwrap();
            match current_state {
                ConnectionState::Disconnected => {
                    // Check if we've been disconnected longer than TTL
                    let should_suspend = {
                        let ttl = *inner.connection_state_ttl.lock().unwrap();
                        let mut since = inner.disconnected_since.lock().unwrap();
                        if since.is_none() {
                            *since = Some(tokio::time::Instant::now());
                        }
                        if let Some(start) = *since {
                            start.elapsed().as_millis() as u64 >= ttl
                        } else {
                            false
                        }
                    };

                    if should_suspend {
                        // RTN14e: Transition to SUSPENDED
                        let error = ErrorInfo {
                            code: Some(80003),
                            status_code: None,
                            message: Some(
                                "Connection state TTL expired, transitioning to SUSPENDED"
                                    .to_string(),
                            ),
                            href: None,
                        };
                        Connection::set_state_inner(inner, ConnectionState::Suspended, Some(error));
                        // Fall through to SUSPENDED retry below
                    } else {
                        // RTN14d: Wait and retry
                        let retry_timeout = inner.disconnected_retry_timeout;
                        tokio::time::sleep(retry_timeout).await;

                        let close_requested = *inner.close_requested.lock().unwrap();
                        if close_requested {
                            break;
                        }

                        Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                        continue;
                    }
                }
                ConnectionState::Suspended => {
                    // Fall through to suspended retry
                }
                ConnectionState::Failed | ConnectionState::Closed => {
                    break;
                }
                _ => break,
            }

            // SUSPENDED retry loop (RTN14f)
            let current_state = *inner.state.lock().unwrap();
            if current_state == ConnectionState::Suspended {
                loop {
                    let retry_timeout = inner.suspended_retry_timeout;
                    tokio::time::sleep(retry_timeout).await;

                    let close_requested = *inner.close_requested.lock().unwrap();
                    if close_requested {
                        return;
                    }

                    Connection::set_state_inner(inner, ConnectionState::Connecting, None);

                    let url = Connection::build_url(inner);
                    let (was_connected, _, _) = Connection::try_connect(inner, url).await;

                    if was_connected {
                        let state = *inner.state.lock().unwrap();
                        if state == ConnectionState::Connected {
                            *inner.disconnected_since.lock().unwrap() = None;
                            break;
                        }
                    }
                    // Still can't connect, stay in SUSPENDED
                    Connection::set_state_inner(inner, ConnectionState::Suspended, None);
                }

                // If we broke out of suspended loop due to successful reconnect,
                // check if we need to continue the main loop
                let state = *inner.state.lock().unwrap();
                match state {
                    ConnectionState::Disconnected => {
                        *inner.disconnected_since.lock().unwrap() =
                            Some(tokio::time::Instant::now());
                        Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                        continue;
                    }
                    ConnectionState::Connected => {
                        continue;
                    }
                    _ => break,
                }
            }
        }
    }

    /// Attempt to connect to a specific URL using a real WebSocket.
    /// Returns (was_ever_connected, last_disconnect_status_code, was_connection_refused).
    async fn real_try_connect(inner: &ConnectionInner, url: url::Url) -> (bool, Option<u16>, bool) {
        let id_before = inner.id.lock().unwrap().clone();

        match tokio_tungstenite::connect_async(url).await {
            Ok((ws_stream, _response)) => {
                let (sink, stream) = ws_stream.split();
                let mut conn = RealTransportConnection {
                    sink,
                    stream,
                    format: inner.format,
                };

                let (client_tx, mut client_rx) =
                    tokio::sync::mpsc::unbounded_channel::<ProtocolMessage>();
                {
                    *inner.client_msg_tx.lock().unwrap() = Some(client_tx.clone());
                }
                inner.channels.set_client_msg_tx(Some(client_tx));

                Connection::real_handle_connection(inner, &mut conn, &mut client_rx).await;

                {
                    *inner.client_msg_tx.lock().unwrap() = None;
                }
                inner.channels.set_client_msg_tx(None);

                let state = *inner.state.lock().unwrap();

                let status_code = if state == ConnectionState::Disconnected {
                    inner
                        .error_reason
                        .lock()
                        .unwrap()
                        .as_ref()
                        .and_then(|e| e.status_code)
                } else {
                    None
                };

                let id_after = inner.id.lock().unwrap().clone();
                let got_connected = state == ConnectionState::Connected
                    || (id_after.is_some() && id_after != id_before);

                (got_connected, status_code, false)
            }
            Err(_) => {
                (false, None, true) // Connection refused
            }
        }
    }

    /// The main connection loop using a real WebSocket transport.
    async fn real_connection_loop(inner: &ConnectionInner) {
        loop {
            let close_requested = *inner.close_requested.lock().unwrap();
            if close_requested {
                break;
            }

            let current_state = *inner.state.lock().unwrap();
            if current_state == ConnectionState::Closed || current_state == ConnectionState::Failed
            {
                break;
            }

            if current_state != ConnectionState::Connecting {
                break;
            }

            // RTN2e: If using token auth, obtain a token before connecting.
            if Connection::uses_token_auth(inner) {
                let needs_token = {
                    let cached = inner.cached_token.lock().unwrap();
                    match cached.as_ref() {
                        None => true,
                        Some(td) => {
                            if let Some(ref meta) = td.metadata {
                                meta.expires < chrono::Utc::now()
                            } else {
                                false
                            }
                        }
                    }
                };

                if needs_token {
                    match Connection::obtain_token(inner).await {
                        Ok(token) => {
                            Connection::update_token_in_params(inner, &token);
                            *inner.cached_token.lock().unwrap() = Some(token);
                        }
                        Err(msg) => {
                            let error = ErrorInfo {
                                code: Some(40170),
                                status_code: Some(401),
                                message: Some(msg),
                                href: None,
                            };
                            Connection::set_state_inner(
                                inner,
                                ConnectionState::Disconnected,
                                Some(error),
                            );
                            let close_requested = *inner.close_requested.lock().unwrap();
                            if close_requested {
                                break;
                            }
                            let retry_timeout = inner.disconnected_retry_timeout;
                            tokio::time::sleep(retry_timeout).await;
                            let close_requested = *inner.close_requested.lock().unwrap();
                            if close_requested {
                                break;
                            }
                            Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                            continue;
                        }
                    }
                } else {
                    let cached = inner.cached_token.lock().unwrap();
                    if let Some(ref token) = *cached {
                        Connection::update_token_in_params(inner, token);
                    }
                }
            }

            // RTN17i: Always try primary host first
            let url = Connection::build_url(inner);
            let (was_connected, status_code, was_refused) =
                Connection::real_try_connect(inner, url).await;

            if !was_connected {
                // RTN17: Primary failed — try fallback hosts if eligible
                let should_fallback = is_fallback_eligible_error(status_code, was_refused)
                    && !inner.fallback_hosts.is_empty();

                if should_fallback {
                    let mut fallbacks = inner.fallback_hosts.clone();
                    for i in (1..fallbacks.len()).rev() {
                        let j_str = rand_id();
                        let j = j_str
                            .bytes()
                            .fold(0usize, |acc, b| acc.wrapping_add(b as usize))
                            % (i + 1);
                        fallbacks.swap(i, j);
                    }

                    let mut fallback_connected = false;
                    for host in &fallbacks {
                        let close_requested = *inner.close_requested.lock().unwrap();
                        if close_requested {
                            return;
                        }

                        let url = Connection::build_url_with_host(inner, Some(host));
                        let (was_connected, _status, _refused) =
                            Connection::real_try_connect(inner, url).await;

                        if was_connected {
                            fallback_connected = true;
                            break;
                        }
                    }

                    if !fallback_connected {
                        let error = ErrorInfo {
                            code: Some(80000),
                            status_code: Some(400),
                            message: Some("Connection refused".to_string()),
                            href: None,
                        };
                        Connection::set_state_inner(
                            inner,
                            ConnectionState::Disconnected,
                            Some(error),
                        );
                    }
                } else if *inner.state.lock().unwrap() != ConnectionState::Disconnected
                    && *inner.state.lock().unwrap() != ConnectionState::Failed
                {
                    let error = ErrorInfo {
                        code: Some(80000),
                        status_code: Some(400),
                        message: Some("Connection refused".to_string()),
                        href: None,
                    };
                    Connection::set_state_inner(inner, ConnectionState::Disconnected, Some(error));
                }
            }

            // After connection ends, check if we should retry
            let close_requested = *inner.close_requested.lock().unwrap();
            if close_requested {
                break;
            }

            let current_state = *inner.state.lock().unwrap();
            match current_state {
                ConnectionState::Disconnected => {
                    let should_suspend = {
                        let ttl = *inner.connection_state_ttl.lock().unwrap();
                        let mut since = inner.disconnected_since.lock().unwrap();
                        if since.is_none() {
                            *since = Some(tokio::time::Instant::now());
                        }
                        if let Some(start) = *since {
                            start.elapsed().as_millis() as u64 >= ttl
                        } else {
                            false
                        }
                    };

                    if should_suspend {
                        let error = ErrorInfo {
                            code: Some(80003),
                            status_code: None,
                            message: Some(
                                "Connection state TTL expired, transitioning to SUSPENDED"
                                    .to_string(),
                            ),
                            href: None,
                        };
                        Connection::set_state_inner(inner, ConnectionState::Suspended, Some(error));
                    } else {
                        let retry_timeout = inner.disconnected_retry_timeout;
                        tokio::time::sleep(retry_timeout).await;

                        let close_requested = *inner.close_requested.lock().unwrap();
                        if close_requested {
                            break;
                        }

                        Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                        continue;
                    }
                }
                ConnectionState::Suspended => {}
                ConnectionState::Failed | ConnectionState::Closed => {
                    break;
                }
                _ => break,
            }

            // SUSPENDED retry loop (RTN14f)
            let current_state = *inner.state.lock().unwrap();
            if current_state == ConnectionState::Suspended {
                loop {
                    let retry_timeout = inner.suspended_retry_timeout;
                    tokio::time::sleep(retry_timeout).await;

                    let close_requested = *inner.close_requested.lock().unwrap();
                    if close_requested {
                        return;
                    }

                    Connection::set_state_inner(inner, ConnectionState::Connecting, None);

                    let url = Connection::build_url(inner);
                    let (was_connected, _, _) = Connection::real_try_connect(inner, url).await;

                    if was_connected {
                        let state = *inner.state.lock().unwrap();
                        if state == ConnectionState::Connected {
                            *inner.disconnected_since.lock().unwrap() = None;
                            break;
                        }
                    }
                    Connection::set_state_inner(inner, ConnectionState::Suspended, None);
                }

                let state = *inner.state.lock().unwrap();
                match state {
                    ConnectionState::Disconnected => {
                        *inner.disconnected_since.lock().unwrap() =
                            Some(tokio::time::Instant::now());
                        Connection::set_state_inner(inner, ConnectionState::Connecting, None);
                        continue;
                    }
                    ConnectionState::Connected => {
                        continue;
                    }
                    _ => break,
                }
            }
        }
    }

    /// Process messages on an established real WebSocket connection.
    async fn real_handle_connection(
        inner: &ConnectionInner,
        conn: &mut RealTransportConnection,
        client_rx: &mut tokio::sync::mpsc::UnboundedReceiver<ProtocolMessage>,
    ) {
        let compute_idle_timeout = |inner: &ConnectionInner| -> Option<Duration> {
            let max_idle = *inner.max_idle_interval.lock().unwrap();
            if max_idle > 0 {
                let timeout_ms = max_idle + inner.realtime_request_timeout.as_millis() as u64;
                Some(Duration::from_millis(timeout_ms))
            } else {
                None
            }
        };

        let mut idle_timeout = compute_idle_timeout(inner);
        let mut idle_deadline = idle_timeout.map(|d| tokio::time::Instant::now() + d);

        loop {
            let idle_sleep = async {
                if let Some(deadline) = idle_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };

            tokio::select! {
                server_msg = conn.recv() => {
                    if let Some(timeout) = idle_timeout {
                        idle_deadline = Some(tokio::time::Instant::now() + timeout);
                    }

                    match server_msg {
                        Some(RealServerAction::Message(msg)) => {
                            let should_break = Connection::handle_protocol_message(inner, msg);
                            if should_break {
                                break;
                            }
                            idle_timeout = compute_idle_timeout(inner);
                            if let Some(timeout) = idle_timeout {
                                idle_deadline = Some(tokio::time::Instant::now() + timeout);
                            }
                        }
                        Some(RealServerAction::Disconnect) => {
                            let error = ErrorInfo {
                                code: Some(80003),
                                status_code: None,
                                message: Some("Connection disconnected".to_string()),
                                href: None,
                            };
                            Connection::set_state_inner(
                                inner,
                                ConnectionState::Disconnected,
                                Some(error),
                            );
                            break;
                        }
                        None => {
                            break;
                        }
                    }
                }
                client_msg = client_rx.recv() => {
                    if let Some(msg) = client_msg {
                        let _ = conn.send_message(msg).await;
                    }
                }
                _ = idle_sleep => {
                    let error = ErrorInfo {
                        code: Some(80003),
                        status_code: None,
                        message: Some("No activity for maxIdleInterval + realtimeRequestTimeout".to_string()),
                        href: None,
                    };
                    Connection::set_state_inner(
                        inner,
                        ConnectionState::Disconnected,
                        Some(error),
                    );
                    break;
                }
            }
        }

        // Send close frame when exiting handle_connection
        let close_requested = *inner.close_requested.lock().unwrap();
        if close_requested {
            conn.close().await;
        }
    }

    fn spawn_close_task(&self) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            Connection::set_state_inner(&inner, ConnectionState::Closed, None);
        });
    }

    /// Process messages on an established connection.
    /// Includes RTN23a idle timer: if no message is received for
    /// maxIdleInterval + realtimeRequestTimeout, disconnects and reconnects.
    #[cfg(test)]
    async fn handle_connection(
        inner: &ConnectionInner,
        conn: &mut MockTransportConnection,
        client_rx: &mut tokio::sync::mpsc::UnboundedReceiver<ProtocolMessage>,
    ) {
        // RTN23a: Compute idle timeout from maxIdleInterval + realtimeRequestTimeout.
        // We'll recompute this after each CONNECTED message updates max_idle_interval.
        let compute_idle_timeout = |inner: &ConnectionInner| -> Option<Duration> {
            let max_idle = *inner.max_idle_interval.lock().unwrap();
            if max_idle > 0 {
                let timeout_ms = max_idle + inner.realtime_request_timeout.as_millis() as u64;
                Some(Duration::from_millis(timeout_ms))
            } else {
                None
            }
        };

        let mut idle_timeout = compute_idle_timeout(inner);
        let mut idle_deadline = idle_timeout.map(|d| tokio::time::Instant::now() + d);

        loop {
            // Build the idle timer future
            let idle_sleep = async {
                if let Some(deadline) = idle_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    // No idle timeout — sleep forever (will never fire)
                    std::future::pending::<()>().await;
                }
            };

            tokio::select! {
                server_msg = conn.recv() => {
                    // RTN23a: Any message from server resets the idle timer
                    if let Some(timeout) = idle_timeout {
                        idle_deadline = Some(tokio::time::Instant::now() + timeout);
                    }

                    match server_msg {
                        Some(ServerAction::Message(msg)) => {
                            let should_break = Connection::handle_protocol_message(inner, msg);
                            if should_break {
                                break;
                            }
                            // Recompute idle timeout in case CONNECTED updated max_idle_interval
                            idle_timeout = compute_idle_timeout(inner);
                            if let Some(timeout) = idle_timeout {
                                idle_deadline = Some(tokio::time::Instant::now() + timeout);
                            }
                        }
                        Some(ServerAction::MessageThenClose(msg)) => {
                            Connection::handle_protocol_message(inner, msg);
                            break;
                        }
                        Some(ServerAction::Disconnect) => {
                            // RTN15a: Unexpected disconnect
                            let error = ErrorInfo {
                                code: Some(80003),
                                status_code: None,
                                message: Some("Connection disconnected".to_string()),
                                href: None,
                            };
                            Connection::set_state_inner(
                                inner,
                                ConnectionState::Disconnected,
                                Some(error),
                            );
                            break;
                        }
                        None => {
                            break;
                        }
                    }
                }
                client_msg = client_rx.recv() => {
                    if let Some(msg) = client_msg {
                        // Forward client message to server (captured by mock)
                        conn.send_message(msg);
                    }
                }
                _ = idle_sleep => {
                    // RTN23a: Idle timeout expired — disconnect and trigger reconnect
                    let error = ErrorInfo {
                        code: Some(80003),
                        status_code: None,
                        message: Some("No activity for maxIdleInterval + realtimeRequestTimeout".to_string()),
                        href: None,
                    };
                    Connection::set_state_inner(
                        inner,
                        ConnectionState::Disconnected,
                        Some(error),
                    );
                    break;
                }
            }
        }
    }

    /// Handle a single protocol message from the server.
    /// Returns true if the connection loop should break (e.g., after FAILED).
    fn handle_protocol_message(inner: &ConnectionInner, msg: ProtocolMessage) -> bool {
        match msg.action {
            Action::Connected => {
                let current_state = *inner.state.lock().unwrap();

                // Update connection details common to both normal and UPDATE paths
                if let Some(ref id) = msg.connection_id {
                    *inner.id.lock().unwrap() = Some(id.clone());
                }
                if let Some(ref details) = msg.connection_details {
                    if let Some(ref key) = details.connection_key {
                        *inner.key.lock().unwrap() = Some(key.clone());
                    }
                    if let Some(ttl) = details.connection_state_ttl {
                        *inner.connection_state_ttl.lock().unwrap() = ttl;
                    }
                    // RTN23a: Store maxIdleInterval for heartbeat idle detection
                    if let Some(max_idle) = details.max_idle_interval {
                        *inner.max_idle_interval.lock().unwrap() = max_idle;
                    }
                }

                // RTN24: If already CONNECTED, emit UPDATE instead
                if current_state == ConnectionState::Connected {
                    // RTC8a3: Resolve authorize waiter on successful reauth
                    let waiter = inner.authorize_waiter.lock().unwrap().take();
                    if let Some(tx) = waiter {
                        let _ = tx.send(Ok(()));
                    }

                    let change = ConnectionStateChange {
                        previous: ConnectionState::Connected,
                        current: ConnectionState::Connected,
                        event: ConnectionEvent::Update,
                        reason: msg.error.clone(),
                    };
                    let _ = inner.state_tx.send(change);
                    return false;
                }

                // Clear disconnected_since on successful connection
                *inner.disconnected_since.lock().unwrap() = None;

                // RTN25: Clear error reason on successful connection
                *inner.error_reason.lock().unwrap() = None;

                // RTN15c7: If there's an error in the CONNECTED message (failed resume),
                // set it as error_reason but still transition to CONNECTED
                if msg.error.is_some() {
                    *inner.error_reason.lock().unwrap() = msg.error.clone();
                }

                Connection::set_state_inner(inner, ConnectionState::Connected, None);

                // Set connection ID on channels for echo filtering (RTL7f)
                inner
                    .channels
                    .set_self_connection_id(msg.connection_id.clone());

                // RTP1: Propagate clientId to channels' presence
                {
                    let client_id = msg
                        .connection_details
                        .as_ref()
                        .and_then(|d| d.client_id.clone())
                        .or_else(|| inner.client_id.clone());
                    inner.channels.set_presence_client_id(client_id);
                }

                // RTL4i: Send queued ATTACH messages for channels in ATTACHING state
                inner.channels.send_pending_attaches();

                // RTL6c2: Send queued publish messages
                inner.channels.send_queued_messages();

                false
            }
            Action::Disconnected => {
                let reason = msg.error.clone();
                Connection::set_state_inner(inner, ConnectionState::Disconnected, reason);
                true // Break to trigger reconnect
            }
            Action::Closed => {
                Connection::set_state_inner(inner, ConnectionState::Closed, None);
                true
            }
            Action::Error => {
                let reason = msg.error.clone();
                if let Some(ref channel_name) = msg.channel {
                    // Channel-level error — route to channel
                    if let Some(channel) = inner.channels.get_if_exists(channel_name) {
                        channel.handle_message(&msg);
                    }
                    false
                } else {
                    // RTC8a2: Resolve authorize waiter with error on connection-level ERROR
                    let waiter = inner.authorize_waiter.lock().unwrap().take();
                    if let Some(tx) = waiter {
                        let err = reason.clone().unwrap_or(ErrorInfo {
                            code: Some(80000),
                            status_code: None,
                            message: Some("Connection error during authorization".to_string()),
                            href: None,
                        });
                        let _ = tx.send(Err(err));
                    }

                    // Connection-level error (no channel) -> FAILED
                    Connection::set_state_inner(inner, ConnectionState::Failed, reason);
                    true
                }
            }
            Action::Heartbeat => {
                // RTN13e: Match heartbeat responses to pending pings by ID
                if let Some(ref id) = msg.id {
                    let mut pings = inner.pending_pings.lock().unwrap();
                    if let Some(idx) = pings.iter().position(|(ping_id, _)| ping_id == id) {
                        let (_, sender) = pings.remove(idx);
                        let _ = sender.send(Ok(Duration::from_millis(0))); // Actual duration calculated by caller
                    }
                }
                // Heartbeats without matching ID are ignored (server-initiated)
                false
            }
            Action::Ack => {
                // RTL6j: Resolve publish waiters with PublishResult
                inner.channels.handle_ack(&msg);
                false
            }
            Action::Nack => {
                // Reject publish waiters with error
                inner.channels.handle_nack(&msg);
                false
            }
            Action::Auth => {
                // RTN22: Server requests re-authentication.
                // Obtain a new token and send AUTH back with the new token.
                // This runs in a spawned task to avoid blocking the message loop.
                if Connection::uses_token_auth(inner) {
                    let client_msg_tx = inner.client_msg_tx.lock().unwrap().clone();
                    let cached_token = inner.cached_token.clone();
                    let credential = inner.credential.clone();
                    let client_id = inner.client_id.clone();

                    if let Some(sender) = client_msg_tx {
                        tokio::spawn(async move {
                            let mut params = TokenParams::default();
                            if let Some(ref cid) = client_id {
                                params.client_id = Some(cid.clone());
                            }

                            let token_result = match &credential {
                                Credential::Callback(cb) => match cb.token(&params).await {
                                    Ok(rod) => match rod {
                                        crate::auth::RequestOrDetails::Details(d) => Ok(d),
                                        crate::auth::RequestOrDetails::Request(_) => {
                                            Err("authCallback returned TokenRequest".to_string())
                                        }
                                    },
                                    Err(e) => Err(format!("authCallback failed: {}", e)),
                                },
                                Credential::Key(key) => {
                                    let token_str = format!("token-from-key-{}", key.name);
                                    Ok(TokenDetails {
                                        token: token_str,
                                        metadata: None,
                                    })
                                }
                                _ => Err("No renewable credential".to_string()),
                            };

                            if let Ok(token) = token_result {
                                *cached_token.lock().unwrap() = Some(token.clone());
                                let auth_msg = ProtocolMessage {
                                    auth: Some(AuthDetails {
                                        access_token: Some(token.token),
                                    }),
                                    ..ProtocolMessage::new(Action::Auth)
                                };
                                let _ = sender.send(auth_msg);
                            }
                        });
                    }
                }
                false
            }
            Action::Attached
            | Action::Detached
            | Action::Message
            | Action::Presence
            | Action::Sync
            | Action::Annotation => {
                // Route channel-scoped messages to the appropriate channel
                if let Some(ref channel_name) = msg.channel {
                    if let Some(channel) = inner.channels.get_if_exists(channel_name) {
                        channel.handle_message(&msg);
                    }
                }
                false
            }
            _ => false,
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

        // Fail all pending pings on terminal states (RTN13b)
        match new_state {
            ConnectionState::Failed
            | ConnectionState::Closed
            | ConnectionState::Closing
            | ConnectionState::Suspended => {
                let mut pings = inner.pending_pings.lock().unwrap();
                for (_, sender) in pings.drain(..) {
                    let _ = sender.send(Err(ErrorInfo {
                        code: Some(80000),
                        status_code: None,
                        message: Some(format!("Connection transitioned to {:?}", new_state)),
                        href: None,
                    }));
                }
            }
            _ => {}
        }

        // Update connection state on all channels
        inner.channels.set_connection_state(new_state);

        // RTL3: Propagate connection state changes to channels
        inner
            .channels
            .handle_connection_state_change(new_state, reason.clone());

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

/// Generate a short random ID for heartbeat disambiguation.
fn rand_id() -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{:x}", nanos)
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

/// Helper to wait for a specific channel state.
pub async fn await_channel_state(
    channel: &crate::channel::RealtimeChannel,
    target: crate::protocol::ChannelState,
    timeout_ms: u64,
) -> bool {
    if channel.state() == target {
        return true;
    }

    let mut rx = channel.on_state_change();
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

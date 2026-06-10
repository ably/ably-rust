//! The connection loop — the single owner of all mutable realtime protocol
//! state (DESIGN.md "Realtime State & Concurrency").
//!
//! Invariants enforced here (see DESIGN.md §1/§10):
//! - All state lives in `ConnectionCtx`, plain owned data, no locks.
//! - The loop never awaits I/O: connects happen in spawned tasks that post
//!   `LoopInput::ConnectAttempt`; transport reads happen in a reader task
//!   posting `LoopInput::Transport`; writes go through a writer task fed by
//!   an unbounded queue.
//! - Inputs from superseded transports are discarded via the generation
//!   counter.
//! - `watch` snapshots are updated BEFORE the corresponding broadcast event.

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::auth::Credential;
use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::{action, ConnectionState, ConnectionEvent, ConnectionStateChange, ProtocolMessage};
use crate::rest::{AuthHeader, Format, Rest};
use crate::transport::{Transport, TransportConnection, TransportEvent};

pub(crate) type Generation = u64;

/// Everything the loop reacts to, in one totally-ordered queue.
pub(crate) enum LoopInput {
    Cmd(Command),
    /// Outcome of a spawned connect task.
    ConnectAttempt {
        generation: Generation,
        result: Result<Box<dyn TransportConnection>>,
    },
    /// An event from the active transport's reader task.
    Transport {
        generation: Generation,
        event: TransportInput,
    },
}

pub(crate) enum TransportInput {
    Message(ProtocolMessage),
    /// The transport closed/errored without a protocol-level explanation.
    Closed,
}

pub(crate) enum Command {
    Connect,
    Close,
}

/// The connection-state snapshot observable by handles (DESIGN.md §4).
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionSnapshot {
    pub state: ConnectionState,
    pub id: Option<String>,
    pub key: Option<String>,
    pub error_reason: Option<ErrorInfo>,
}

/// All mutable connection state, owned exclusively by the loop task.
struct ConnectionCtx {
    rest: Rest,
    transport_factory: Arc<dyn Transport>,

    state: ConnectionState,
    id: Option<String>,
    key: Option<String>,
    error_reason: Option<ErrorInfo>,

    /// Stale-transport guard (DESIGN.md §6): inputs tagged with a generation
    /// other than this one are discarded.
    generation: Generation,
    /// Sender feeding the active transport's writer task, if any.
    writer: Option<mpsc::UnboundedSender<ProtocolMessage>>,

    snapshot_tx: watch::Sender<ConnectionSnapshot>,
    events_tx: broadcast::Sender<ConnectionStateChange>,
    /// Handle for spawned tasks to post back into the loop.
    input_tx: mpsc::UnboundedSender<LoopInput>,
}

impl ConnectionCtx {
    /// Transition the connection state machine: update the snapshot first,
    /// then emit the state-change event (DESIGN.md §4 contract).
    fn transition(&mut self, to: ConnectionState, reason: Option<ErrorInfo>) {
        let previous = self.state;
        self.state = to;
        if let Some(err) = &reason {
            // RTN25: errorReason is set when an error causes a transition
            self.error_reason = Some(err.clone());
        }
        // RTN8c/RTN9c: id and key are only available while CONNECTED
        if to != ConnectionState::Connected {
            self.id = None;
            self.key = None;
        }
        self.publish_snapshot();
        let _ = self.events_tx.send(ConnectionStateChange {
            previous,
            current: to,
            event: state_event(to),
            reason,
        });
    }

    /// RTN4h: an event that is not a state change (additional CONNECTED).
    fn emit_update(&mut self, reason: Option<ErrorInfo>) {
        self.publish_snapshot();
        let _ = self.events_tx.send(ConnectionStateChange {
            previous: ConnectionState::Connected,
            current: ConnectionState::Connected,
            event: ConnectionEvent::Update,
            reason,
        });
    }

    fn publish_snapshot(&self) {
        let _ = self.snapshot_tx.send(ConnectionSnapshot {
            state: self.state,
            id: self.id.clone(),
            key: self.key.clone(),
            error_reason: self.error_reason.clone(),
        });
    }

    /// Begin a connection attempt: bump the generation (orphaning any
    /// in-flight attempt or live transport) and spawn the connect task.
    fn start_connect(&mut self) {
        self.generation += 1;
        self.writer = None;
        let generation = self.generation;
        let rest = self.rest.clone();
        let factory = self.transport_factory.clone();
        let input_tx = self.input_tx.clone();
        tokio::spawn(async move {
            let result = connect_task(rest, factory).await;
            let _ = input_tx.send(LoopInput::ConnectAttempt { generation, result });
        });
    }

    /// Drop the active transport (if any) by orphaning its generation.
    fn drop_transport(&mut self) {
        self.generation += 1;
        self.writer = None;
    }

    fn send_protocol(&mut self, msg: ProtocolMessage) {
        if let Some(writer) = &self.writer {
            let _ = writer.send(msg);
        }
    }

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Connect => match self.state {
                // RTN11: connect from a non-active state begins CONNECTING
                ConnectionState::Initialized
                | ConnectionState::Disconnected
                | ConnectionState::Suspended
                | ConnectionState::Closed
                | ConnectionState::Failed => {
                    // RTN11d: connecting from FAILED/terminal clears errorReason
                    self.error_reason = None;
                    self.transition(ConnectionState::Connecting, None);
                    self.start_connect();
                }
                // RTN11b/c: already connecting/connected/closing — no-op
                ConnectionState::Connecting
                | ConnectionState::Connected
                | ConnectionState::Closing => {}
            },
            Command::Close => match self.state {
                // RTN12a: close an established connection — CLOSING, send
                // CLOSE, await CLOSED from the server
                ConnectionState::Connected => {
                    self.transition(ConnectionState::Closing, None);
                    self.send_protocol(ProtocolMessage::new(action::CLOSE));
                }
                // RTN12f: close while connecting abandons the attempt
                ConnectionState::Connecting => {
                    self.drop_transport();
                    self.transition(ConnectionState::Closing, None);
                    self.transition(ConnectionState::Closed, None);
                }
                // RTN12d: close from inactive states goes straight to CLOSED
                ConnectionState::Initialized
                | ConnectionState::Disconnected
                | ConnectionState::Suspended => {
                    self.drop_transport();
                    self.transition(ConnectionState::Closed, None);
                }
                // RTN12c: no-op in CLOSING/CLOSED/FAILED
                ConnectionState::Closing
                | ConnectionState::Closed
                | ConnectionState::Failed => {}
            },
        }
    }

    fn handle_connect_attempt(&mut self, result: Result<Box<dyn TransportConnection>>) {
        match self.state {
            ConnectionState::Connecting => {}
            // The attempt outlived the state that wanted it (e.g. close());
            // the generation check upstream normally catches this, but a
            // same-generation attempt landing in another state is dropped too.
            _ => return,
        }
        match result {
            Ok(conn) => {
                let (writer_tx, reader_generation) = spawn_transport_tasks(
                    conn,
                    self.generation,
                    self.input_tx.clone(),
                );
                debug_assert_eq!(reader_generation, self.generation);
                self.writer = Some(writer_tx);
                // Remain CONNECTING until the server's CONNECTED arrives.
            }
            Err(err) => {
                // 5.1: no retry timers yet (5.2); a failed attempt rests at
                // DISCONNECTED with the error as the reason (RTN14a-shaped).
                self.transition(ConnectionState::Disconnected, Some(err));
            }
        }
    }

    fn handle_transport(&mut self, event: TransportInput) {
        match event {
            TransportInput::Message(pm) => self.handle_protocol_message(pm),
            TransportInput::Closed => match self.state {
                ConnectionState::Closing => {
                    // Server closed the socket during our close handshake
                    self.drop_transport();
                    self.transition(ConnectionState::Closed, None);
                }
                ConnectionState::Connecting | ConnectionState::Connected => {
                    self.drop_transport();
                    let err = ErrorInfo::with_status(
                        ErrorCode::Disconnected.code(),
                        400,
                        "Connection to server unexpectedly closed",
                    );
                    self.transition(ConnectionState::Disconnected, Some(err));
                }
                _ => {}
            },
        }
    }

    fn handle_protocol_message(&mut self, pm: ProtocolMessage) {
        match pm.action {
            action::CONNECTED => {
                let id = pm.connection_id.clone();
                let key = pm
                    .connection_details
                    .as_ref()
                    .and_then(|d| d.connection_key.clone())
                    .or_else(|| pm.connection_key.clone());
                match self.state {
                    ConnectionState::Connecting => {
                        self.id = id;
                        self.key = key;
                        self.transition(ConnectionState::Connected, pm.error);
                    }
                    ConnectionState::Connected => {
                        // RTN4h: an additional CONNECTED is an UPDATE event,
                        // not a state change; id/key/details may change
                        self.id = id;
                        self.key = key;
                        self.emit_update(pm.error);
                    }
                    _ => {}
                }
            }
            action::DISCONNECTED => {
                self.drop_transport();
                self.transition(ConnectionState::Disconnected, pm.error);
            }
            action::CLOSED => {
                self.drop_transport();
                self.transition(ConnectionState::Closed, None);
            }
            action::ERROR if pm.channel.is_none() => {
                // A connection-level ERROR is fatal (RTN15i): FAILED with the
                // error as the reason (RTN25)
                self.drop_transport();
                self.transition(ConnectionState::Failed, pm.error);
            }
            action::HEARTBEAT => {
                // RTN23 activity bookkeeping arrives in 5.2
            }
            _ => {
                // Channel-scoped and other actions arrive in later stages
                // (5.4+). They are ignored, never errors: forwards
                // compatibility (RTN19-shaped).
            }
        }
    }
}

fn state_event(state: ConnectionState) -> ConnectionEvent {
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

/// Obtain credentials and dial the transport. Runs in a spawned task — never
/// in the loop (DESIGN.md §6).
async fn connect_task(rest: Rest, factory: Arc<dyn Transport>) -> Result<Box<dyn TransportConnection>> {
    let url = build_connection_url(&rest).await?;
    factory.connect(&url).await
}

/// RTN2: the realtime connection URL with auth and protocol params.
async fn build_connection_url(rest: &Rest) -> Result<String> {
    let opts = &rest.inner.opts;
    let scheme = if opts.tls { "wss" } else { "ws" };
    let port = if opts.tls { opts.tls_port } else { opts.port };
    let host = &opts.primary_host;

    let mut url = url::Url::parse(&format!("{}://{}:{}/", scheme, host, port))?;
    {
        let mut q = url.query_pairs_mut();
        // RTN2f: protocol version; RTN2a: format
        q.append_pair("v", "6");
        q.append_pair(
            "format",
            match opts.format {
                Format::MessagePack => "msgpack",
                Format::JSON => "json",
            },
        );
        // RTN2d: clientId when configured
        if let Some(client_id) = &opts.client_id {
            q.append_pair("clientId", client_id);
        }
        // RTC1f-adjacent: transport params
        for (k, v) in &opts.transport_params {
            q.append_pair(k, v);
        }
    }
    // RTN2e: credentials — basic clients send the key, token clients a token
    match rest.get_auth_header().await? {
        AuthHeader::Basic(_) => {
            if let Credential::Key(key) = &opts.credential {
                url.query_pairs_mut()
                    .append_pair("key", &format!("{}:{}", key.name, key.value));
            }
        }
        AuthHeader::Bearer(token) => {
            url.query_pairs_mut().append_pair("accessToken", &token);
        }
    }
    Ok(url.to_string())
}

/// Spawn the reader and writer tasks for an established transport
/// (DESIGN.md §6). Returns the writer queue sender.
fn spawn_transport_tasks(
    conn: Box<dyn TransportConnection>,
    generation: Generation,
    input_tx: mpsc::UnboundedSender<LoopInput>,
) -> (mpsc::UnboundedSender<ProtocolMessage>, Generation) {
    let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<ProtocolMessage>();
    tokio::spawn(async move {
        let mut conn = conn;
        loop {
            tokio::select! {
                outbound = writer_rx.recv() => match outbound {
                    Some(pm) => {
                        if conn.send(pm).await.is_err() {
                            let _ = input_tx.send(LoopInput::Transport {
                                generation,
                                event: TransportInput::Closed,
                            });
                            break;
                        }
                    }
                    // Writer sender dropped: the loop orphaned this transport
                    None => {
                        conn.close().await;
                        break;
                    }
                },
                inbound = conn.recv() => match inbound {
                    Some(TransportEvent::Message(pm)) => {
                        let _ = input_tx.send(LoopInput::Transport {
                            generation,
                            event: TransportInput::Message(pm),
                        });
                    }
                    Some(TransportEvent::Disconnected) | None => {
                        let _ = input_tx.send(LoopInput::Transport {
                            generation,
                            event: TransportInput::Closed,
                        });
                        break;
                    }
                },
            }
        }
    });
    (writer_tx, generation)
}

/// Spawn the connection loop. Returns the input sender, the snapshot
/// receiver, and the event sender (handles subscribe to it).
pub(crate) fn spawn_connection_loop(
    rest: Rest,
    transport_factory: Arc<dyn Transport>,
) -> (
    mpsc::UnboundedSender<LoopInput>,
    watch::Receiver<ConnectionSnapshot>,
    broadcast::Sender<ConnectionStateChange>,
) {
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<LoopInput>();
    let (snapshot_tx, snapshot_rx) = watch::channel(ConnectionSnapshot::default());
    let (events_tx, _) = broadcast::channel(64);

    let mut ctx = ConnectionCtx {
        rest,
        transport_factory,
        state: ConnectionState::Initialized,
        id: None,
        key: None,
        error_reason: None,
        generation: 0,
        writer: None,
        snapshot_tx,
        events_tx: events_tx.clone(),
        input_tx: input_tx.clone(),
    };

    tokio::spawn(async move {
        while let Some(input) = input_rx.recv().await {
            match input {
                LoopInput::Cmd(cmd) => ctx.handle_command(cmd),
                LoopInput::ConnectAttempt { generation, result } => {
                    if generation == ctx.generation {
                        ctx.handle_connect_attempt(result);
                    }
                }
                LoopInput::Transport { generation, event } => {
                    if generation == ctx.generation {
                        ctx.handle_transport(event);
                    }
                }
            }
        }
        // All handles dropped: the loop ends with its owned state.
    });

    (input_tx, snapshot_rx, events_tx)
}

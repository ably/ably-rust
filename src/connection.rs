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
//! - All timers are deadlines in the loop's state, driven by one
//!   `sleep_until` in the select (DESIGN.md §5).

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::auth::Credential;
use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::{
    action, flags, ChannelEvent, ChannelMode, ChannelState, ChannelStateChange,
    ConnectionDetails, ConnectionEvent, ConnectionState, ConnectionStateChange,
    ProtocolMessage,
};
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
    /// RTN22: outcome of a server-requested token renewal (spawned task).
    TokenReady {
        generation: Generation,
        result: Result<String>,
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
    /// RTN13: heartbeat ping; replies with the round-trip time.
    Ping {
        reply: oneshot::Sender<Result<Duration>>,
    },
    /// RTC8: apply an externally obtained token to the live connection.
    Reauth { access_token: String },
    /// RTS3a: register a channel's observation channels with the loop.
    EnsureChannel {
        name: String,
        options: ChannelOptionsSpec,
        snapshot_tx: watch::Sender<ChannelSnapshot>,
        events_tx: broadcast::Sender<ChannelStateChange>,
    },
    /// RTL4: attach a channel.
    Attach {
        name: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// RTL5: detach a channel.
    Detach {
        name: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// RTS4a: detach (if needed) and remove a channel.
    ReleaseChannel {
        name: String,
        reply: oneshot::Sender<()>,
    },
}

/// The channel options the loop needs (RTL4k params, RTL4l modes).
#[derive(Clone, Debug, Default)]
pub(crate) struct ChannelOptionsSpec {
    pub params: Vec<(String, String)>,
    pub modes: Vec<ChannelMode>,
}

/// The per-channel snapshot observable by handles (DESIGN.md §4).
#[derive(Clone, Debug, Default)]
pub(crate) struct ChannelSnapshot {
    pub state: ChannelState,
    pub error_reason: Option<ErrorInfo>,
    pub channel_serial: Option<String>,
    pub attach_serial: Option<String>,
    /// RTL4m: the modes granted in ATTACHED.
    pub modes: Option<Vec<ChannelMode>>,
}

/// The connection-state snapshot observable by handles (DESIGN.md §4).
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionSnapshot {
    pub state: ConnectionState,
    pub id: Option<String>,
    pub key: Option<String>,
    pub error_reason: Option<ErrorInfo>,
    /// RTN17: the host serving the current connection.
    pub host: Option<String>,
}

/// RTB1a: backoff coefficient for the nth retry (1-indexed).
pub(crate) fn backoff_coefficient(retry_count: u32) -> f64 {
    ((retry_count as f64 + 2.0) / 3.0).min(2.0)
}

/// RTB1b: jitter coefficient, uniform in [0.8, 1.0].
pub(crate) fn jitter_coefficient() -> f64 {
    rand::thread_rng().gen_range(0.8..=1.0)
}

/// RTB1: the delay before the nth retry of a base timeout.
fn retry_delay(base: Duration, retry_count: u32) -> Duration {
    base.mul_f64(backoff_coefficient(retry_count) * jitter_coefficient())
}

/// An in-flight RTN13 ping awaiting its HEARTBEAT response.
struct PendingPing {
    id: String,
    sent_at: Instant,
    deadline: Instant,
    reply: oneshot::Sender<Result<Duration>>,
}

/// All mutable per-channel state, owned exclusively by the loop task
/// (DESIGN.md §2/§7).
struct ChannelCtx {
    name: String,
    state: ChannelState,
    error_reason: Option<ErrorInfo>,
    channel_serial: Option<String>,
    attach_serial: Option<String>,
    options: ChannelOptionsSpec,
    /// RTL4m: modes granted by the server in ATTACHED.
    attached_modes: Option<Vec<ChannelMode>>,
    /// RTL4j: a previous attach succeeded; reattaches set ATTACH_RESUME.
    has_been_attached: bool,
    /// RTL4h/RTL4i: attach requested while it could not be sent.
    attach_pending: bool,
    /// RTL5i: detach requested while attaching/detaching.
    detach_pending: bool,
    /// RTS4a: remove this channel once the detach completes.
    release_on_detach: bool,
    release_reply: Option<oneshot::Sender<()>>,
    pending_attach: Vec<oneshot::Sender<Result<()>>>,
    pending_detach: Vec<oneshot::Sender<Result<()>>>,
    /// RTL4f/RTL5f: in-flight attach/detach op deadline.
    op_deadline: Option<Instant>,
    /// RTL5f: the state to return to if a detach times out.
    op_revert_state: ChannelState,
    snapshot_tx: watch::Sender<ChannelSnapshot>,
    events_tx: broadcast::Sender<ChannelStateChange>,
}

impl ChannelCtx {
    /// Transition the channel state machine: snapshot first, then the event
    /// (DESIGN.md §4 contract). RTL2g: no event when the state is unchanged.
    fn transition(&mut self, to: ChannelState, reason: Option<ErrorInfo>, resumed: bool, has_backlog: bool) {
        let previous = self.state;
        self.state = to;
        if let Some(err) = &reason {
            self.error_reason = Some(err.clone());
        }
        // RTL15b1: DETACHED/SUSPENDED/FAILED clear the channelSerial
        if matches!(
            to,
            ChannelState::Detached | ChannelState::Suspended | ChannelState::Failed
        ) {
            self.channel_serial = None;
        }
        self.publish_snapshot();
        if previous != to {
            let _ = self.events_tx.send(ChannelStateChange {
                previous,
                current: to,
                event: channel_state_event(to),
                reason,
                resumed,
                has_backlog,
            });
        }
    }

    /// RTL2g: an UPDATE event for condition changes without a state change.
    fn emit_update(&mut self, reason: Option<ErrorInfo>, resumed: bool, has_backlog: bool) {
        self.publish_snapshot();
        let _ = self.events_tx.send(ChannelStateChange {
            previous: self.state,
            current: self.state,
            event: ChannelEvent::Update,
            reason,
            resumed,
            has_backlog,
        });
    }

    fn publish_snapshot(&self) {
        let _ = self.snapshot_tx.send(ChannelSnapshot {
            state: self.state,
            error_reason: self.error_reason.clone(),
            channel_serial: self.channel_serial.clone(),
            attach_serial: self.attach_serial.clone(),
            modes: self.attached_modes.clone(),
        });
    }

    fn resolve_attach(&mut self, result: Result<()>) {
        for replier in self.pending_attach.drain(..) {
            let _ = replier.send(result.clone());
        }
    }

    fn resolve_detach(&mut self, result: Result<()>) {
        for replier in self.pending_detach.drain(..) {
            let _ = replier.send(result.clone());
        }
    }
}

fn channel_state_event(state: ChannelState) -> ChannelEvent {
    match state {
        ChannelState::Initialized => ChannelEvent::Initialized,
        ChannelState::Attaching => ChannelEvent::Attaching,
        ChannelState::Attached => ChannelEvent::Attached,
        ChannelState::Detaching => ChannelEvent::Detaching,
        ChannelState::Detached => ChannelEvent::Detached,
        ChannelState::Suspended => ChannelEvent::Suspended,
        ChannelState::Failed => ChannelEvent::Failed,
    }
}

/// All mutable connection state, owned exclusively by the loop task.
struct ConnectionCtx {
    rest: Rest,
    transport_factory: Arc<dyn Transport>,

    state: ConnectionState,
    id: Option<String>,
    key: Option<String>,
    error_reason: Option<ErrorInfo>,
    details: Option<ConnectionDetails>,

    /// Stale-transport guard (DESIGN.md §6).
    generation: Generation,
    writer: Option<mpsc::UnboundedSender<ProtocolMessage>>,

    /// RTN17: hosts remaining to try in the current connect cycle.
    connect_hosts: Vec<String>,
    /// RTN17: the host of the current attempt/connection.
    current_host: Option<String>,
    /// RTN15b: the connection key used for resume on reconnects.
    resume_key: Option<String>,
    /// The id of the last successful connection (RTN15c6/c7 comparison).
    last_connected_id: Option<String>,
    /// Consecutive failed attempts in the current disconnected cycle (RTB1).
    retry_count: u32,
    /// One token renewal is allowed per connection cycle (RTN14b/RTN15h2).
    renewed_this_cycle: bool,
    /// The next connect task must renew the token first (RTN14b/RTN15h2).
    force_renewal_on_next_connect: bool,

    // --- Timers: deadlines owned by the loop (DESIGN.md §5) ---
    /// Per-attempt connect timeout (realtime_request_timeout, RTN14c).
    connect_deadline: Option<Instant>,
    /// Next automatic reconnect (RTN14d disconnected / RTN14f suspended).
    retry_at: Option<Instant>,
    /// RTN14e: when the DISCONNECTED state becomes SUSPENDED.
    suspend_at: Option<Instant>,
    /// Set once the TTL has passed: failures now rest at SUSPENDED and
    /// resume state is discarded (RTN15g).
    past_ttl: bool,
    /// RTN12b: if the server's CLOSED doesn't arrive in time, close anyway.
    close_deadline: Option<Instant>,
    /// RTN23a: transport inactivity deadline.
    idle_deadline: Option<Instant>,
    /// RTN13 pings in flight.
    pending_pings: Vec<PendingPing>,

    /// All channel state, inside the loop (DESIGN.md §7).
    channels: std::collections::HashMap<String, ChannelCtx>,

    snapshot_tx: watch::Sender<ConnectionSnapshot>,
    events_tx: broadcast::Sender<ConnectionStateChange>,
    input_tx: mpsc::UnboundedSender<LoopInput>,
}

impl ConnectionCtx {
    /// Transition the state machine: snapshot first, then the event.
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
            reason: reason.clone(),
        });
        // RTL3: connection-state effects on channels, atomic with the
        // connection transition (DESIGN.md §7)
        self.apply_connection_effects_to_channels(to, &reason);
        if to == ConnectionState::Connected {
            // RTL3d/RTL4i: (re)attach channels
            self.reattach_channels_on_connected();
        }
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
            host: if self.state == ConnectionState::Connected {
                self.current_host.clone()
            } else {
                None
            },
        });
    }

    /// The connectionStateTtl in effect (server value wins, RTN14e).
    fn connection_state_ttl(&self) -> Duration {
        self.details
            .as_ref()
            .and_then(|d| d.connection_state_ttl)
            .map(Duration::from_millis)
            .unwrap_or(self.rest.inner.opts.connection_state_ttl)
    }

    /// RTN23a: maxIdleInterval (server value, default 15s) + realtimeRequestTimeout.
    fn idle_timeout(&self) -> Duration {
        let max_idle = self
            .details
            .as_ref()
            .and_then(|d| d.max_idle_interval)
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_millis(15000));
        max_idle + self.rest.inner.opts.realtime_request_timeout
    }

    /// RTN17i: begin a fresh connect cycle — the primary domain first, then
    /// the REC2 fallback domains in random order (RTN17j).
    fn start_connect(&mut self) {
        let opts = &self.rest.inner.opts;
        let mut fallbacks: Vec<String> = opts.resolved_fallback_hosts.clone();
        use rand::seq::SliceRandom;
        fallbacks.shuffle(&mut rand::thread_rng());
        self.connect_hosts = fallbacks;
        let primary = opts.primary_host.clone();
        self.start_connect_to(primary);
    }

    /// RTN17: try the next fallback host in the current cycle, if any.
    /// Returns false when the cycle is exhausted (RTN17g).
    fn try_next_host(&mut self) -> bool {
        if let Some(host) = if self.connect_hosts.is_empty() {
            None
        } else {
            Some(self.connect_hosts.remove(0))
        } {
            self.start_connect_to(host);
            true
        } else {
            false
        }
    }

    /// Spawn a connect task for one host: bump the generation (orphaning any
    /// in-flight attempt or live transport).
    fn start_connect_to(&mut self, host: String) {
        self.generation += 1;
        self.writer = None;
        self.connect_deadline =
            Some(Instant::now() + self.rest.inner.opts.realtime_request_timeout);
        self.current_host = Some(host.clone());
        let generation = self.generation;
        let rest = self.rest.clone();
        let factory = self.transport_factory.clone();
        let input_tx = self.input_tx.clone();
        // RTN15b: resume with the previous connection key, unless the TTL has
        // passed (RTN15g) — past_ttl clears resume_key when it fires.
        let resume = self.resume_key.clone();
        let force_renewal = std::mem::take(&mut self.force_renewal_on_next_connect);
        tokio::spawn(async move {
            let result = connect_task(rest, factory, host, resume, force_renewal).await;
            let _ = input_tx.send(LoopInput::ConnectAttempt { generation, result });
        });
    }

    /// Drop the active transport (if any) by orphaning its generation.
    fn drop_transport(&mut self) {
        self.generation += 1;
        self.writer = None;
        self.connect_deadline = None;
        self.close_deadline = None;
        self.idle_deadline = None;
        self.fail_pending_pings("connection is no longer active");
    }

    fn fail_pending_pings(&mut self, why: &str) {
        for ping in self.pending_pings.drain(..) {
            let _ = ping.reply.send(Err(ErrorInfo::new(
                ErrorCode::Disconnected.code(),
                format!("Ping failed: {}", why),
            )));
        }
    }

    fn send_protocol(&mut self, msg: ProtocolMessage) {
        if let Some(writer) = &self.writer {
            let _ = writer.send(msg);
        }
    }

    /// Enter DISCONNECTED (or SUSPENDED once past the TTL) after a failure,
    /// scheduling the next retry (RTN14d/RTN14e/RTN14f).
    fn enter_retry_state(&mut self, err: Option<ErrorInfo>) {
        self.drop_transport();
        let opts = &self.rest.inner.opts;
        if self.past_ttl {
            // RTN14f: suspended retries continue indefinitely
            self.retry_at = Some(Instant::now() + opts.suspended_retry_timeout);
            let reason = err.or_else(|| {
                Some(ErrorInfo::with_status(
                    ErrorCode::ConnectionSuspended.code(),
                    400,
                    "Connection suspended: connectionStateTtl exceeded",
                ))
            });
            self.transition(ConnectionState::Suspended, reason);
        } else {
            self.retry_count += 1;
            // RTN14e: the TTL countdown starts at the first disconnection
            if self.suspend_at.is_none() {
                self.suspend_at = Some(Instant::now() + self.connection_state_ttl());
            }
            self.retry_at = Some(
                Instant::now() + retry_delay(opts.disconnected_retry_timeout, self.retry_count),
            );
            self.transition(ConnectionState::Disconnected, err);
        }
    }

    /// RTN15a: an established connection dropped — retry immediately with resume.
    fn reconnect_immediately(&mut self, err: Option<ErrorInfo>) {
        self.drop_transport();
        if self.suspend_at.is_none() {
            self.suspend_at = Some(Instant::now() + self.connection_state_ttl());
        }
        self.transition(ConnectionState::Disconnected, err);
        self.transition(ConnectionState::Connecting, None);
        self.start_connect();
    }

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Connect => match self.state {
                ConnectionState::Initialized
                | ConnectionState::Disconnected
                | ConnectionState::Suspended
                | ConnectionState::Closed
                | ConnectionState::Failed => {
                    // RTN11d: an explicit connect clears errorReason and retry state
                    self.error_reason = None;
                    self.retry_at = None;
                    self.transition(ConnectionState::Connecting, None);
                    self.start_connect();
                }
                ConnectionState::Connecting
                | ConnectionState::Connected
                | ConnectionState::Closing => {}
            },
            Command::Close => match self.state {
                ConnectionState::Connected => {
                    self.transition(ConnectionState::Closing, None);
                    self.send_protocol(ProtocolMessage::new(action::CLOSE));
                    // RTN12b: don't wait for CLOSED forever
                    self.close_deadline =
                        Some(Instant::now() + self.rest.inner.opts.realtime_request_timeout);
                }
                ConnectionState::Connecting => {
                    self.drop_transport();
                    self.transition(ConnectionState::Closing, None);
                    self.transition(ConnectionState::Closed, None);
                }
                ConnectionState::Initialized
                | ConnectionState::Disconnected
                | ConnectionState::Suspended => {
                    self.drop_transport();
                    self.retry_at = None;
                    self.suspend_at = None;
                    self.transition(ConnectionState::Closed, None);
                }
                ConnectionState::Closing
                | ConnectionState::Closed
                | ConnectionState::Failed => {}
            },
            Command::EnsureChannel { name, options, snapshot_tx, events_tx } => {
                self.channels.entry(name.clone()).or_insert_with(|| ChannelCtx {
                    name,
                    state: ChannelState::Initialized,
                    error_reason: None,
                    channel_serial: None,
                    attach_serial: None,
                    options,
                    attached_modes: None,
                    has_been_attached: false,
                    attach_pending: false,
                    detach_pending: false,
                    release_on_detach: false,
                    release_reply: None,
                    pending_attach: Vec::new(),
                    pending_detach: Vec::new(),
                    op_deadline: None,
                    op_revert_state: ChannelState::Initialized,
                    snapshot_tx,
                    events_tx,
                });
            }
            Command::Attach { name, reply } => self.handle_attach(name, reply),
            Command::Detach { name, reply } => self.handle_detach(name, reply),
            Command::ReleaseChannel { name, reply } => {
                let mut reply = Some(reply);
                let detach_first = match self.channels.get_mut(&name) {
                    Some(ch)
                        if matches!(ch.state, ChannelState::Attached | ChannelState::Attaching)
                            && self.state == ConnectionState::Connected =>
                    {
                        // RTS4a: detach first, remove when the detach resolves
                        ch.release_on_detach = true;
                        ch.release_reply = reply.take();
                        true
                    }
                    _ => false,
                };
                if detach_first {
                    let (tx, _rx) = oneshot::channel();
                    self.handle_detach(name, tx);
                } else {
                    self.channels.remove(&name);
                    if let Some(reply) = reply {
                        let _ = reply.send(());
                    }
                }
            }
            Command::Reauth { access_token } => {
                // RTC8: apply an externally obtained token in place
                if self.state == ConnectionState::Connected {
                    self.send_auth(access_token);
                }
            }
            Command::Ping { reply } => {
                // RTN13b: ping is only valid while CONNECTED
                if self.state != ConnectionState::Connected {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::BadRequest.code(),
                        format!("Cannot ping in state {:?}", self.state),
                    )));
                    return;
                }
                // RTN13e: a random id disambiguates concurrent pings
                let id: String = rand::thread_rng()
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(8)
                    .map(char::from)
                    .collect();
                let mut msg = ProtocolMessage::new(action::HEARTBEAT);
                msg.id = Some(id.clone());
                self.send_protocol(msg);
                let now = Instant::now();
                self.pending_pings.push(PendingPing {
                    id,
                    sent_at: now,
                    // RTN13c: timeout after realtimeRequestTimeout
                    deadline: now + self.rest.inner.opts.realtime_request_timeout,
                    reply,
                });
            }
        }
    }

    fn handle_connect_attempt(&mut self, result: Result<Box<dyn TransportConnection>>) {
        if self.state != ConnectionState::Connecting {
            return;
        }
        match result {
            Ok(conn) => {
                let writer_tx = spawn_transport_tasks(conn, self.generation, self.input_tx.clone());
                self.writer = Some(writer_tx);
                // Remain CONNECTING until the server's CONNECTED arrives;
                // connect_deadline still applies to that wait (RTN14c).
            }
            Err(err) => {
                // RTN17f: a host-unreachable failure tries the next fallback
                // within the same CONNECTING phase
                if !self.try_next_host() {
                    self.enter_retry_state(Some(err));
                }
            }
        }
    }

    fn handle_transport(&mut self, event: TransportInput) {
        // RTN23a: any traffic on the active transport resets the idle clock
        if self.state == ConnectionState::Connected {
            self.idle_deadline = Some(Instant::now() + self.idle_timeout());
        }
        match event {
            TransportInput::Message(pm) => self.handle_protocol_message(pm),
            TransportInput::Closed => match self.state {
                ConnectionState::Closing => {
                    self.drop_transport();
                    self.transition(ConnectionState::Closed, None);
                }
                // RTN15a: unexpected drop while CONNECTED — immediate resume
                ConnectionState::Connected => {
                    let err = ErrorInfo::with_status(
                        ErrorCode::Disconnected.code(),
                        400,
                        "Connection to server unexpectedly closed",
                    );
                    self.reconnect_immediately(Some(err));
                }
                // RTN14/RTN17f: failure while still connecting — next
                // fallback host, then a scheduled retry
                ConnectionState::Connecting => {
                    let err = ErrorInfo::with_status(
                        ErrorCode::Disconnected.code(),
                        400,
                        "Connection to server unexpectedly closed",
                    );
                    self.drop_transport();
                    if !self.try_next_host() {
                        self.enter_retry_state(Some(err));
                    }
                }
                _ => {}
            },
        }
    }

    fn handle_protocol_message(&mut self, pm: ProtocolMessage) {
        match pm.action {
            action::CONNECTED => self.handle_connected(pm),
            action::DISCONNECTED => self.handle_disconnected(pm),
            action::CLOSED => {
                self.drop_transport();
                self.transition(ConnectionState::Closed, None);
            }
            action::ERROR if pm.channel.is_none() => self.handle_error_message(pm),
            action::ERROR => self.handle_channel_error(pm),
            action::ATTACHED => self.handle_attached(pm),
            action::DETACHED => self.handle_detached(pm),
            action::HEARTBEAT => {
                // RTN13e: only a HEARTBEAT carrying a known ping id resolves a
                // ping; id-less heartbeats are server liveness traffic only
                if let Some(id) = &pm.id {
                    if let Some(pos) = self.pending_pings.iter().position(|p| &p.id == id) {
                        let ping = self.pending_pings.remove(pos);
                        let _ = ping.reply.send(Ok(ping.sent_at.elapsed()));
                    }
                }
            }
            action::AUTH => {
                // RTN22: the server requests re-authentication. Obtain a fresh
                // token off-loop and send AUTH back (RTC8); the connection
                // stays CONNECTED throughout.
                let generation = self.generation;
                let rest = self.rest.clone();
                let input_tx = self.input_tx.clone();
                tokio::spawn(async move {
                    rest.invalidate_cached_token();
                    let result = match rest.get_auth_header().await {
                        Ok(AuthHeader::Bearer(token)) => Ok(token),
                        Ok(AuthHeader::Basic(_)) => Err(ErrorInfo::new(
                            ErrorCode::InvalidCredentials.code(),
                            "Server requested reauth but the client uses basic auth",
                        )),
                        Err(e) => Err(e),
                    };
                    let _ = input_tx.send(LoopInput::TokenReady { generation, result });
                });
            }
            _ => {
                // Channel-scoped actions arrive in stages 5.4+; unknown
                // actions are ignored (forwards compatibility)
            }
        }
    }

    /// RTN22/RTC8: a renewed token is ready — send AUTH over the live
    /// transport. On failure, surface the error; the server will disconnect
    /// us if the credentials lapse (RTN22a handles that path).
    fn handle_token_ready(&mut self, result: Result<String>) {
        if self.state != ConnectionState::Connected {
            return;
        }
        match result {
            Ok(token) => self.send_auth(token),
            Err(err) => {
                self.error_reason = Some(err.clone());
                self.emit_update(Some(err));
            }
        }
    }

    fn send_auth(&mut self, access_token: String) {
        let mut msg = ProtocolMessage::new(action::AUTH);
        msg.auth = Some(serde_json::json!({ "accessToken": access_token }));
        self.send_protocol(msg);
    }

    fn handle_connected(&mut self, pm: ProtocolMessage) {
        let new_id = pm.connection_id.clone();
        let new_key = pm
            .connection_details
            .as_ref()
            .and_then(|d| d.connection_key.clone())
            .or_else(|| pm.connection_key.clone());
        match self.state {
            ConnectionState::Connecting => {
                // RTN15c6: resume succeeded iff the server echoes the previous
                // connection id; RTN15c7: a new id means the resume failed and
                // the server's error (if any) becomes the change reason.
                let reason = pm.error.clone();

                self.id = new_id.clone();
                self.key = new_key.clone();
                self.last_connected_id = new_id;
                // RTN15e/RTN16: the key for future resumes is the latest one
                self.resume_key = new_key;
                self.details = pm.connection_details.clone();
                // Fresh cycle: reset failure bookkeeping
                self.retry_count = 0;
                self.suspend_at = None;
                self.past_ttl = false;
                self.retry_at = None;
                self.connect_deadline = None;
                self.renewed_this_cycle = false;
                self.idle_deadline = Some(Instant::now() + self.idle_timeout());
                // RTN17e: REST requests prefer the same fallback host as the
                // realtime connection (brief REST-lock write; never awaited)
                if let Some(host) = &self.current_host {
                    if host != &self.rest.inner.opts.primary_host {
                        self.rest.cache_fallback_host(host);
                    }
                }
                self.transition(ConnectionState::Connected, reason);
            }
            ConnectionState::Connected => {
                // RTN4h: UPDATE event; refresh id/key/details
                self.id = new_id.clone();
                self.key = new_key.clone();
                self.last_connected_id = new_id;
                self.resume_key = new_key;
                if pm.connection_details.is_some() {
                    self.details = pm.connection_details.clone();
                }
                self.emit_update(pm.error);
            }
            _ => {}
        }
    }

    /// RTN15h: DISCONNECTED received over an active transport.
    fn handle_disconnected(&mut self, pm: ProtocolMessage) {
        let is_token_error = pm
            .error
            .as_ref()
            .and_then(|e| e.code)
            .map(|c| (40140..=40149).contains(&c))
            .unwrap_or(false);
        if is_token_error {
            if self.can_renew_token() && !self.renewed_this_cycle {
                // RTN15h2: renew the token and reconnect immediately
                self.renewed_this_cycle = true;
                self.force_renewal_on_next_connect = true;
                self.reconnect_immediately(pm.error);
            } else {
                // RTN15h1: token error with no means to renew is terminal
                self.drop_transport();
                self.transition(ConnectionState::Failed, pm.error);
            }
        } else if self.state == ConnectionState::Connected {
            // RTN15h3: non-token error — immediate resume attempt
            self.reconnect_immediately(pm.error);
        } else {
            // RTN17f1: a 5xx DISCONNECTED while connecting qualifies for
            // fallback; otherwise a scheduled retry (RTN14)
            let is_5xx = pm
                .error
                .as_ref()
                .and_then(|e| e.status_code)
                .map(|s| (500..=504).contains(&s))
                .unwrap_or(false);
            self.drop_transport();
            if is_5xx && self.try_next_host() {
                return;
            }
            self.enter_retry_state(pm.error);
        }
    }

    /// A connection-level ERROR over the transport.
    fn handle_error_message(&mut self, pm: ProtocolMessage) {
        let is_token_error = pm
            .error
            .as_ref()
            .and_then(|e| e.code)
            .map(|c| (40140..=40149).contains(&c))
            .unwrap_or(false);
        if self.state == ConnectionState::Connecting && is_token_error {
            if self.can_renew_token() && !self.renewed_this_cycle {
                // RTN14b: renew once and retry the connection
                self.renewed_this_cycle = true;
                self.force_renewal_on_next_connect = true;
                self.drop_transport();
                self.start_connect();
                return;
            }
            // RSA4a: token error with no way to renew is FAILED
        }
        // RTN14g/RTN15i: a connection-level ERROR is otherwise fatal
        self.drop_transport();
        self.transition(ConnectionState::Failed, pm.error);
    }

    // --- Channel lifecycle (RTL2/RTL3/RTL4/RTL5, DESIGN.md §7) ---

    /// RTL4: attach a channel.
    fn handle_attach(&mut self, name: String, reply: oneshot::Sender<Result<()>>) {
        let conn_state = self.state;
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Err(ErrorInfo::new(
                ErrorCode::ChannelOperationFailed.code(),
                "Channel has been released",
            )));
            return;
        };
        match ch.state {
            // RTL4a: already attached — immediate success
            ChannelState::Attached => {
                let _ = reply.send(Ok(()));
            }
            // RTL4h: attach in progress — share its outcome
            ChannelState::Attaching => {
                ch.pending_attach.push(reply);
            }
            // RTL4h: detaching — attach once the detach completes
            ChannelState::Detaching => {
                ch.attach_pending = true;
                ch.pending_attach.push(reply);
            }
            // RTL4g covers Failed (proceeds, clearing errorReason via RTL4c)
            ChannelState::Initialized
            | ChannelState::Detached
            | ChannelState::Suspended
            | ChannelState::Failed => match conn_state {
                // RTL4b: invalid connection states
                ConnectionState::Closing
                | ConnectionState::Closed
                | ConnectionState::Failed
                | ConnectionState::Suspended => {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Cannot attach while the connection is {:?}", conn_state),
                    )));
                }
                // RTL4i: queue until the connection is CONNECTED
                ConnectionState::Initialized
                | ConnectionState::Connecting
                | ConnectionState::Disconnected => {
                    // RTL4c: a new attach clears errorReason
                    ch.error_reason = None;
                    ch.pending_attach.push(reply);
                    ch.attach_pending = true;
                    ch.transition(ChannelState::Attaching, None, false, false);
                }
                ConnectionState::Connected => {
                    ch.error_reason = None;
                    ch.pending_attach.push(reply);
                    ch.transition(ChannelState::Attaching, None, false, false);
                    ch.op_deadline = Some(Instant::now() + rtt);
                    let msg = attach_message(ch);
                    self.send_protocol(msg);
                }
            },
        }
    }

    /// RTL5: detach a channel.
    fn handle_detach(&mut self, name: String, reply: oneshot::Sender<Result<()>>) {
        let conn_state = self.state;
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Ok(()));
            return;
        };
        match ch.state {
            // RTL5a: nothing to detach
            ChannelState::Initialized | ChannelState::Detached => {
                let _ = reply.send(Ok(()));
            }
            // RTL5b: detach from FAILED is an error
            ChannelState::Failed => {
                let _ = reply.send(Err(ErrorInfo::new(
                    ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                    "Cannot detach a failed channel",
                )));
            }
            // RTL5j: suspended → detached immediately
            ChannelState::Suspended => {
                let _ = reply.send(Ok(()));
                ch.transition(ChannelState::Detached, None, false, false);
            }
            // RTL5i: detach in progress — share its outcome
            ChannelState::Detaching => {
                ch.pending_detach.push(reply);
            }
            // RTL5i: attaching — detach once the attach completes
            ChannelState::Attaching => {
                if conn_state == ConnectionState::Connected {
                    ch.detach_pending = true;
                    ch.pending_detach.push(reply);
                } else {
                    // RTL5l: no live connection — abandon the queued attach
                    // and go straight to DETACHED, nothing on the wire
                    ch.attach_pending = false;
                    ch.op_deadline = None;
                    ch.resolve_attach(Err(ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        "Attach superseded by detach",
                    )));
                    let _ = reply.send(Ok(()));
                    ch.transition(ChannelState::Detached, None, false, false);
                }
            }
            ChannelState::Attached => {
                if conn_state == ConnectionState::Connected {
                    // RTL5d: DETACH on the wire, await DETACHED
                    ch.op_revert_state = ch.state;
                    ch.pending_detach.push(reply);
                    ch.transition(ChannelState::Detaching, None, false, false);
                    ch.op_deadline = Some(Instant::now() + rtt);
                    let mut msg = ProtocolMessage::new(action::DETACH);
                    msg.channel = Some(ch.name.clone());
                    self.send_protocol(msg);
                } else {
                    // RTL5l: no live connection — detached immediately
                    let _ = reply.send(Ok(()));
                    ch.transition(ChannelState::Detached, None, false, false);
                }
            }
        }
    }

    /// ATTACHED received from the server.
    fn handle_attached(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else { return };
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else { return };
        let resumed = pm.flags.map(|f| f & flags::RESUMED != 0).unwrap_or(false);
        let has_backlog = pm.flags.map(|f| f & flags::HAS_BACKLOG != 0).unwrap_or(false);
        match ch.state {
            ChannelState::Attaching => {
                ch.attach_serial = pm.channel_serial.clone();
                ch.channel_serial = pm.channel_serial.clone();
                // RTL4m: modes granted by the server
                ch.attached_modes = pm.flags.map(modes_from_flags);
                ch.has_been_attached = true;
                ch.op_deadline = None;
                ch.resolve_attach(Ok(()));
                ch.transition(ChannelState::Attached, pm.error, resumed, has_backlog);
                // RTL5i: a queued detach proceeds now
                if std::mem::take(&mut ch.detach_pending) {
                    let (tx, _rx) = oneshot::channel();
                    self.handle_detach(name, tx);
                }
            }
            ChannelState::Attached => {
                // RTL12-shaped: an additional ATTACHED is an UPDATE
                ch.attach_serial = pm.channel_serial.clone();
                ch.channel_serial = pm.channel_serial.clone();
                if let Some(f) = pm.flags {
                    ch.attached_modes = Some(modes_from_flags(f));
                }
                // RTL12: RESUMED means continuity was preserved — no UPDATE
                if !resumed {
                    ch.emit_update(pm.error, resumed, has_backlog);
                }
            }
            // RTL5k: an ATTACHED while detaching/detached is answered with DETACH
            ChannelState::Detaching | ChannelState::Detached => {
                ch.op_deadline = Some(Instant::now() + rtt);
                let mut msg = ProtocolMessage::new(action::DETACH);
                msg.channel = Some(name);
                self.send_protocol(msg);
            }
            _ => {}
        }
    }

    /// DETACHED received from the server.
    fn handle_detached(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else { return };
        let Some(ch) = self.channels.get_mut(&name) else { return };
        match ch.state {
            ChannelState::Detaching => {
                ch.op_deadline = None;
                ch.resolve_detach(Ok(()));
                ch.transition(ChannelState::Detached, pm.error, false, false);
                if ch.release_on_detach {
                    if let Some(reply) = ch.release_reply.take() {
                        let _ = reply.send(());
                    }
                    self.channels.remove(&name);
                    return;
                }
                // RTL4h: a queued attach proceeds now
                let attach_now = std::mem::take(&mut self.channels.get_mut(&name).unwrap().attach_pending);
                if attach_now {
                    let (tx, _rx) = oneshot::channel();
                    self.handle_attach(name, tx);
                }
            }
            // Server-initiated DETACHED while attached/attaching → 5.6 (RTL13);
            // minimal: surface as Detached for now? Deferred to 5.6 — ignore.
            _ => {}
        }
    }

    /// ERROR with a channel set: the attach/detach failed (RTL4e/RTL5e-shaped).
    fn handle_channel_error(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else { return };
        let Some(ch) = self.channels.get_mut(&name) else { return };
        ch.op_deadline = None;
        let err = pm.error.clone().unwrap_or_else(|| {
            ErrorInfo::new(ErrorCode::ChannelOperationFailed.code(), "Channel error")
        });
        ch.resolve_attach(Err(err.clone()));
        ch.resolve_detach(Err(err.clone()));
        ch.transition(ChannelState::Failed, Some(err), false, false);
    }

    /// RTL3: connection-state side effects on channels — applied atomically
    /// with the connection transition (DESIGN.md §7).
    fn apply_connection_effects_to_channels(&mut self, conn_state: ConnectionState, reason: &Option<ErrorInfo>) {
        match conn_state {
            // RTL3a: FAILED fails attached/attaching channels
            ConnectionState::Failed => {
                for ch in self.channels.values_mut() {
                    if matches!(ch.state, ChannelState::Attached | ChannelState::Attaching) {
                        ch.op_deadline = None;
                        ch.resolve_attach(Err(reason.clone().unwrap_or_else(|| {
                            ErrorInfo::new(ErrorCode::ConnectionFailed.code(), "Connection failed")
                        })));
                        ch.transition(ChannelState::Failed, reason.clone(), false, false);
                    }
                }
            }
            // RTL3b: CLOSED detaches attached/attaching channels
            ConnectionState::Closed => {
                for ch in self.channels.values_mut() {
                    if matches!(ch.state, ChannelState::Attached | ChannelState::Attaching) {
                        ch.op_deadline = None;
                        ch.resolve_attach(Err(ErrorInfo::new(
                            ErrorCode::ConnectionClosed.code(),
                            "Connection closed",
                        )));
                        ch.transition(ChannelState::Detached, None, false, false);
                    }
                }
            }
            // RTL3c: SUSPENDED suspends attached/attaching channels
            ConnectionState::Suspended => {
                for ch in self.channels.values_mut() {
                    if matches!(ch.state, ChannelState::Attached | ChannelState::Attaching) {
                        ch.op_deadline = None;
                        ch.resolve_attach(Err(reason.clone().unwrap_or_else(|| {
                            ErrorInfo::new(ErrorCode::ConnectionSuspended.code(), "Connection suspended")
                        })));
                        ch.transition(ChannelState::Suspended, reason.clone(), false, false);
                    }
                }
            }
            // RTL3e: DISCONNECTED leaves channel states untouched
            _ => {}
        }
    }

    /// RTL3d: on CONNECTED, (re)attach channels that were attached, attaching,
    /// suspended, or queued (RTL4i).
    fn reattach_channels_on_connected(&mut self) {
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let mut to_send = Vec::new();
        for ch in self.channels.values_mut() {
            let queued = std::mem::take(&mut ch.attach_pending);
            let needs_attach = queued
                || matches!(
                    ch.state,
                    ChannelState::Attached | ChannelState::Attaching | ChannelState::Suspended
                );
            if needs_attach {
                if ch.state != ChannelState::Attaching {
                    ch.transition(ChannelState::Attaching, None, false, false);
                }
                ch.op_deadline = Some(Instant::now() + rtt);
                to_send.push(attach_message(ch));
            }
        }
        for msg in to_send {
            self.send_protocol(msg);
        }
    }

    fn can_renew_token(&self) -> bool {
        let cfg = self.rest.auth_config();
        cfg.callback.is_some() || cfg.url.is_some() || cfg.key.is_some()
    }

    // --- Timers (DESIGN.md §5) ---

    fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut consider = |d: Option<Instant>| {
            if let Some(d) = d {
                next = Some(match next {
                    Some(n) if n <= d => n,
                    _ => d,
                });
            }
        };
        consider(self.connect_deadline);
        consider(self.close_deadline);
        consider(self.retry_at);
        consider(self.suspend_at);
        consider(self.idle_deadline);
        consider(self.pending_pings.iter().map(|p| p.deadline).min());
        consider(self.channels.values().filter_map(|c| c.op_deadline).min());
        next
    }

    fn handle_timers(&mut self) {
        let now = Instant::now();

        // RTN14c: the connect attempt timed out
        if self.connect_deadline.map(|d| d <= now).unwrap_or(false) {
            self.connect_deadline = None;
            if self.state == ConnectionState::Connecting {
                let err = ErrorInfo::with_status(
                    ErrorCode::ConnectionTimedOut.code(),
                    408,
                    "Connection attempt timed out",
                );
                // RTN17f: a timeout qualifies for fallback
                if !self.try_next_host() {
                    self.enter_retry_state(Some(err));
                }
            }
        }

        // RTN12b: the close handshake timed out — close anyway
        if self.close_deadline.map(|d| d <= now).unwrap_or(false) {
            self.close_deadline = None;
            if self.state == ConnectionState::Closing {
                self.drop_transport();
                self.transition(ConnectionState::Closed, None);
            }
        }

        // RTN14e/RTN15g: the disconnected TTL elapsed
        if self.suspend_at.map(|d| d <= now).unwrap_or(false) {
            self.suspend_at = None;
            self.past_ttl = true;
            // RTN15g: resume state is discarded once the TTL passes
            self.resume_key = None;
            self.last_connected_id = None;
            if self.state == ConnectionState::Disconnected {
                let err = ErrorInfo::with_status(
                    ErrorCode::ConnectionSuspended.code(),
                    400,
                    "Connection suspended: connectionStateTtl exceeded",
                );
                self.retry_at =
                    Some(now + self.rest.inner.opts.suspended_retry_timeout);
                self.transition(ConnectionState::Suspended, Some(err));
            }
            // If currently CONNECTING, the next failure lands on SUSPENDED
            // via past_ttl.
        }

        // RTN14d/RTN14f: time to retry
        if self.retry_at.map(|d| d <= now).unwrap_or(false) {
            self.retry_at = None;
            if matches!(
                self.state,
                ConnectionState::Disconnected | ConnectionState::Suspended
            ) {
                self.transition(ConnectionState::Connecting, None);
                self.start_connect();
            }
        }

        // RTN23a: the transport went idle
        if self.idle_deadline.map(|d| d <= now).unwrap_or(false) {
            self.idle_deadline = None;
            if self.state == ConnectionState::Connected {
                let err = ErrorInfo::with_status(
                    ErrorCode::Disconnected.code(),
                    400,
                    "Connection inactive beyond maxIdleInterval; reconnecting",
                );
                self.reconnect_immediately(Some(err));
            }
        }

        // RTL4f/RTL5f: channel attach/detach op timeouts
        let timed_out: Vec<String> = self
            .channels
            .values()
            .filter(|c| c.op_deadline.map(|d| d <= now).unwrap_or(false))
            .map(|c| c.name.clone())
            .collect();
        for name in timed_out {
            if let Some(ch) = self.channels.get_mut(&name) {
                ch.op_deadline = None;
                match ch.state {
                    // RTL4f: attach timeout → SUSPENDED with the error
                    ChannelState::Attaching => {
                        let err = ErrorInfo::with_status(
                            ErrorCode::ChannelOperationFailedNoResponseFromServer.code(),
                            408,
                            "Attach timed out",
                        );
                        ch.resolve_attach(Err(err.clone()));
                        ch.transition(ChannelState::Suspended, Some(err), false, false);
                    }
                    // RTL5f: detach timeout → return to the previous state
                    ChannelState::Detaching => {
                        let err = ErrorInfo::with_status(
                            ErrorCode::ChannelOperationFailedNoResponseFromServer.code(),
                            408,
                            "Detach timed out",
                        );
                        ch.resolve_detach(Err(err.clone()));
                        let revert = ch.op_revert_state;
                        ch.transition(revert, Some(err), false, false);
                    }
                    _ => {}
                }
            }
        }

        // RTN13c: ping timeouts
        let mut idx = 0;
        while idx < self.pending_pings.len() {
            if self.pending_pings[idx].deadline <= now {
                let ping = self.pending_pings.remove(idx);
                let _ = ping.reply.send(Err(ErrorInfo::with_status(
                    ErrorCode::TimeoutError.code(),
                    408,
                    "Ping timed out",
                )));
            } else {
                idx += 1;
            }
        }
    }
}

/// RTL4c/RTL4c1/RTL4k/RTL4l/RTL4j: build the ATTACH message for a channel.
fn attach_message(ch: &ChannelCtx) -> ProtocolMessage {
    let mut msg = ProtocolMessage::new(action::ATTACH);
    msg.channel = Some(ch.name.clone());
    // RTL4c1: include the channelSerial from the previous attachment
    if let Some(serial) = &ch.channel_serial {
        msg.channel_serial = Some(serial.clone());
    }
    // RTL4k: requested channel params
    if !ch.options.params.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = ch
            .options
            .params
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        msg.params = Some(serde_json::Value::Object(map));
    }
    // RTL4l: requested modes as flags; RTL4j: ATTACH_RESUME on reattach
    let mut flag_bits: u64 = ch
        .options
        .modes
        .iter()
        .map(|m| match m {
            ChannelMode::Presence => flags::PRESENCE,
            ChannelMode::Publish => flags::PUBLISH,
            ChannelMode::Subscribe => flags::SUBSCRIBE,
            ChannelMode::PresenceSubscribe => flags::PRESENCE_SUBSCRIBE,
        })
        .fold(0, |acc, f| acc | f);
    if ch.has_been_attached {
        flag_bits |= flags::ATTACH_RESUME;
    }
    if flag_bits != 0 {
        msg.flags = Some(flag_bits);
    }
    msg
}

/// RTL4m: decode the mode flags granted in ATTACHED.
fn modes_from_flags(f: u64) -> Vec<ChannelMode> {
    let mut modes = Vec::new();
    if f & flags::PRESENCE != 0 {
        modes.push(ChannelMode::Presence);
    }
    if f & flags::PUBLISH != 0 {
        modes.push(ChannelMode::Publish);
    }
    if f & flags::SUBSCRIBE != 0 {
        modes.push(ChannelMode::Subscribe);
    }
    if f & flags::PRESENCE_SUBSCRIBE != 0 {
        modes.push(ChannelMode::PresenceSubscribe);
    }
    modes
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
/// in the loop (DESIGN.md §6). Token renewal (when forced by RTN14b/RTN15h2)
/// also happens here, off-loop.
async fn connect_task(
    rest: Rest,
    factory: Arc<dyn Transport>,
    host: String,
    resume: Option<String>,
    force_renewal: bool,
) -> Result<Box<dyn TransportConnection>> {
    if force_renewal {
        rest.invalidate_cached_token();
    }
    let url = build_connection_url(&rest, &host, resume.as_deref()).await?;
    factory.connect(&url).await
}

/// RTN2: the realtime connection URL with auth and protocol params.
async fn build_connection_url(rest: &Rest, host: &str, resume: Option<&str>) -> Result<String> {
    let opts = &rest.inner.opts;
    let scheme = if opts.tls { "wss" } else { "ws" };
    let port = if opts.tls { opts.tls_port } else { opts.port };

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
        // RTN23a: this client consumes HEARTBEAT protocol messages
        q.append_pair("heartbeats", "true");
        // RTN2b: suppress message echo when configured off
        if !opts.echo_messages {
            q.append_pair("echo", "false");
        }
        // RTN2d: clientId when configured
        if let Some(client_id) = &opts.client_id {
            q.append_pair("clientId", client_id);
        }
        // RTN15b1: resume with the previous connection key
        if let Some(resume_key) = resume {
            q.append_pair("resume", resume_key);
        }
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
) -> mpsc::UnboundedSender<ProtocolMessage> {
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
    writer_tx
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
        details: None,
        generation: 0,
        writer: None,
        connect_hosts: Vec::new(),
        current_host: None,
        resume_key: None,
        last_connected_id: None,
        retry_count: 0,
        renewed_this_cycle: false,
        force_renewal_on_next_connect: false,
        connect_deadline: None,
        retry_at: None,
        suspend_at: None,
        past_ttl: false,
        close_deadline: None,
        idle_deadline: None,
        pending_pings: Vec::new(),
        channels: std::collections::HashMap::new(),
        snapshot_tx,
        events_tx: events_tx.clone(),
        input_tx: input_tx.clone(),
    };

    tokio::spawn(async move {
        loop {
            let deadline = ctx.next_deadline();
            tokio::select! {
                input = input_rx.recv() => match input {
                    Some(LoopInput::Cmd(cmd)) => ctx.handle_command(cmd),
                    Some(LoopInput::ConnectAttempt { generation, result }) => {
                        if generation == ctx.generation {
                            ctx.handle_connect_attempt(result);
                        }
                    }
                    Some(LoopInput::Transport { generation, event }) => {
                        if generation == ctx.generation {
                            ctx.handle_transport(event);
                        }
                    }
                    Some(LoopInput::TokenReady { generation, result }) => {
                        if generation == ctx.generation {
                            ctx.handle_token_ready(result);
                        }
                    }
                    None => break,
                },
                _ = async {
                    tokio::time::sleep_until(deadline.expect("guarded by if")).await
                }, if deadline.is_some() => {
                    ctx.handle_timers();
                }
            }
        }
        // All handles dropped: the loop ends with its owned state.
    });

    (input_tx, snapshot_rx, events_tx)
}

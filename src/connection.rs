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
    action, flags, ChannelEvent, ChannelMode, ChannelState, ChannelStateChange, ConnectionDetails,
    ConnectionEvent, ConnectionState, ConnectionStateChange, ProtocolMessage,
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
    /// RTC8: authorize with an already-obtained token. The reply resolves
    /// once the server has confirmed (CONNECTED) or refused (RTC8a3/RTC8b1).
    Authorize {
        access_token: String,
        reply: oneshot::Sender<Result<()>>,
    },
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
    /// RTL6: publish messages on a channel; resolves on ACK/NACK (RTL6j).
    /// RTL32e: message mutations may carry pm-level params.
    Publish {
        name: String,
        messages: Vec<crate::rest::Message>,
        params: Option<serde_json::Value>,
        reply: oneshot::Sender<Result<crate::rest::PublishResult>>,
    },
    /// RTL7: register a message subscriber.
    Subscribe {
        name: String,
        id: u64,
        filter: SubscriberFilter,
        sender: mpsc::UnboundedSender<crate::rest::Message>,
    },
    /// RTL8: remove message subscriber(s).
    Unsubscribe {
        name: String,
        spec: UnsubscribeSpec,
    },
    /// RTL16: set/update channel options; reattaches when needed (RTL16a).
    SetOptions {
        name: String,
        options: ChannelOptionsSpec,
        reply: oneshot::Sender<Result<()>>,
    },
    /// RTP8/9/10/14/15: a presence operation (ENTER/UPDATE/LEAVE).
    PresenceOp {
        name: String,
        message: crate::rest::PresenceMessage,
        reply: oneshot::Sender<Result<()>>,
    },
    /// RTP11: read the presence members.
    PresenceGet {
        name: String,
        wait_for_sync: bool,
        client_id: Option<String>,
        connection_id: Option<String>,
        reply: oneshot::Sender<Result<Vec<crate::rest::PresenceMessage>>>,
    },
    /// RTP6: register a presence subscriber.
    PresenceSubscribe {
        name: String,
        id: u64,
        actions: Option<Vec<crate::rest::PresenceAction>>,
        sender: mpsc::UnboundedSender<crate::rest::PresenceMessage>,
    },
    /// RTP7: remove presence subscriber(s).
    PresenceUnsubscribe {
        name: String,
        id: Option<u64>,
        action: Option<crate::rest::PresenceAction>,
    },
    /// RTP17e (internal): a failed automatic re-entry becomes a channel
    /// UPDATE event carrying the error.
    PresenceReentryFailed {
        name: String,
        error: ErrorInfo,
    },
    /// RTAN1/RTAN2: an annotation publish or delete; resolves via ACK/NACK.
    AnnotationOp {
        name: String,
        annotation: crate::rest::Annotation,
        reply: oneshot::Sender<Result<()>>,
    },
    /// RTAN4: register an annotation subscriber.
    AnnotationSubscribe {
        name: String,
        id: u64,
        type_filter: Option<String>,
        sender: mpsc::UnboundedSender<crate::rest::Annotation>,
    },
    /// RTAN5: remove annotation subscriber(s).
    AnnotationUnsubscribe {
        name: String,
        id: Option<u64>,
    },
}

/// RTL7/RTL22: what a subscriber wants delivered.
#[derive(Clone, Debug)]
pub(crate) enum SubscriberFilter {
    All,
    /// RTL7b: only messages with this name.
    Name(String),
    /// RTL22: a MessageFilter.
    Filter(crate::channel::MessageFilter),
}

/// RTL8 variants.
#[derive(Clone, Debug)]
pub(crate) enum UnsubscribeSpec {
    /// RTL8a: this listener, wherever it is registered.
    Id(u64),
    /// RTL8b: this listener, only its name-specific registration.
    NameAndId(String, u64),
    /// RTL8c: every listener on the channel.
    All,
}

/// The channel options the loop needs (RTL4k params, RTL4l modes).
#[derive(Clone, Debug, Default)]
pub(crate) struct ChannelOptionsSpec {
    pub params: Vec<(String, String)>,
    pub modes: Vec<ChannelMode>,
    /// RSL5/RSL6: message encryption/decryption.
    pub cipher: Option<crate::crypto::CipherParams>,
    /// RTL7g/TB4: implicit attach on subscribe (default true).
    pub attach_on_subscribe: bool,
}

impl ChannelOptionsSpec {
    /// RTS3c1: would switching to `new` force a reattachment?
    pub fn reattach_needed(&self, new: &ChannelOptionsSpec) -> bool {
        self.params != new.params || self.modes != new.modes
    }
}

/// The per-channel snapshot observable by handles (DESIGN.md §4).
#[derive(Clone, Debug, Default)]
pub(crate) struct ChannelSnapshot {
    pub state: ChannelState,
    /// RTS3c/RTL16: the authoritative channel options.
    pub options: ChannelOptionsSpec,
    /// RTP13: whether the initial presence sync has completed.
    pub presence_sync_complete: bool,
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

/// A sent ProtocolMessage awaiting its ACK/NACK (RTN7).
struct PendingPublish {
    msg_serial: i64,
    channel: String,
    /// The wire payload, kept verbatim so an RTN19a resend reconstructs the
    /// SAME kind of ProtocolMessage (MESSAGE, PRESENCE or ANNOTATION).
    payload: PendingPayload,
    reply: oneshot::Sender<Result<crate::rest::PublishResult>>,
}

/// The payload of a publish awaiting ACK; determines the resend pm action.
enum PendingPayload {
    Messages {
        messages: Vec<crate::rest::Message>,
        params: Option<serde_json::Value>,
    },
    Presence(Vec<crate::rest::PresenceMessage>),
    Annotations(Vec<crate::rest::Annotation>),
}

impl PendingPayload {
    /// Rebuild the ProtocolMessage for an RTN19a resend.
    fn to_protocol_message(&self, channel: String, serial: i64) -> ProtocolMessage {
        let mut pm = match self {
            PendingPayload::Messages { messages, params } => {
                let mut pm = ProtocolMessage::new(action::MESSAGE);
                pm.messages = Some(messages.clone());
                pm.params = params.clone();
                pm
            }
            PendingPayload::Presence(entries) => {
                let mut pm = ProtocolMessage::new(action::PRESENCE);
                pm.presence = Some(entries.clone());
                pm
            }
            PendingPayload::Annotations(entries) => {
                let mut pm = ProtocolMessage::new(action::ANNOTATION);
                pm.annotations = Some(entries.clone());
                pm
            }
        };
        pm.channel = Some(channel);
        pm.msg_serial = Some(serial);
        pm
    }
}

/// A publish awaiting a connection (RTL6c2).
struct QueuedPublish {
    channel: String,
    messages: Vec<crate::rest::Message>,
    params: Option<serde_json::Value>,
    reply: oneshot::Sender<Result<crate::rest::PublishResult>>,
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
    /// RTL13b: scheduled reattach retry.
    retry_at: Option<Instant>,
    retry_count: u32,
    /// RTL13b: retryIn for the next SUSPENDED state change event.
    next_retry_in: Option<Duration>,
    /// RTL5f: the state to return to if a detach times out.
    op_revert_state: ChannelState,
    /// RTL7/RTL8: message subscribers (§8 — unbounded, pruned on close).
    subscribers: Vec<Subscriber>,
    /// RTP: the presence engine (DESIGN.md §9).
    presence: PresenceCtx,
    /// RTAN4: annotation subscribers.
    annotation_subscribers: Vec<AnnotationSubscriber>,
    snapshot_tx: watch::Sender<ChannelSnapshot>,
    events_tx: broadcast::Sender<ChannelStateChange>,
    logger: crate::options::Logger,
}

/// One subscribe() registration.
struct Subscriber {
    id: u64,
    filter: SubscriberFilter,
    sender: mpsc::UnboundedSender<crate::rest::Message>,
}

/// DESIGN.md §9: per-channel presence state, loop-owned.
#[derive(Default)]
struct PresenceCtx {
    map: crate::presence::PresenceMap,
    /// RTP17: members entered through this connection, keyed by clientId.
    internal: crate::presence::LocalPresenceMap,
    /// RTP13: whether the initial post-attach sync has completed.
    sync_complete: bool,
    /// RTP6: presence subscribers.
    subscribers: Vec<PresenceSubscriber>,
    /// RTP11: get(waitForSync) replies deferred until the sync completes.
    pending_get: Vec<DeferredPresenceGet>,
    /// RTP16b: ops queued while the channel is ATTACHING.
    queued_ops: Vec<QueuedPresenceOp>,
}

struct AnnotationSubscriber {
    id: u64,
    type_filter: Option<String>,
    sender: mpsc::UnboundedSender<crate::rest::Annotation>,
}

struct PresenceSubscriber {
    id: u64,
    actions: Option<Vec<crate::rest::PresenceAction>>,
    sender: mpsc::UnboundedSender<crate::rest::PresenceMessage>,
}

struct DeferredPresenceGet {
    client_id: Option<String>,
    connection_id: Option<String>,
    reply: oneshot::Sender<Result<Vec<crate::rest::PresenceMessage>>>,
}

struct QueuedPresenceOp {
    message: crate::rest::PresenceMessage,
    reply: oneshot::Sender<Result<()>>,
}

impl ChannelCtx {
    /// Transition the channel state machine: snapshot first, then the event
    /// (DESIGN.md §4 contract). RTL2g: no event when the state is unchanged.
    fn transition(
        &mut self,
        to: ChannelState,
        reason: Option<ErrorInfo>,
        resumed: bool,
        has_backlog: bool,
    ) {
        let previous = self.state;
        if previous != to {
            self.logger.major(|| {
                format!(
                    "Channel '{}': {:?} -> {:?}{}",
                    self.name,
                    previous,
                    to,
                    reason
                        .as_ref()
                        .map(|e| format!(" (reason: {})", e))
                        .unwrap_or_default()
                )
            });
        }
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
        // RTP5a: DETACHED/FAILED clear both presence maps and fail queued
        // presence ops + deferred gets (RTL11); RTP5f: SUSPENDED keeps the
        // map but the sync state is no longer authoritative
        match to {
            ChannelState::Detached | ChannelState::Failed => {
                self.presence.map.clear();
                self.presence.internal.clear();
                self.presence.sync_complete = false;
                let err = reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Channel became {:?}", to),
                    )
                });
                for op in self.presence.queued_ops.drain(..) {
                    let _ = op.reply.send(Err(err.clone()));
                }
                for get in self.presence.pending_get.drain(..) {
                    let _ = get.reply.send(Err(err.clone()));
                }
            }
            ChannelState::Suspended => {
                self.presence.sync_complete = false;
                let err = reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        "Channel suspended",
                    )
                });
                for op in self.presence.queued_ops.drain(..) {
                    let _ = op.reply.send(Err(err.clone()));
                }
                // RTP11d: a deferred waiting get cannot complete once the
                // presence state is out of sync
                for get in self.presence.pending_get.drain(..) {
                    let _ = get.reply.send(Err(ErrorInfo::with_status(
                        91005,
                        400,
                        "Presence state is out of sync (channel suspended)",
                    )));
                }
            }
            _ => {}
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
                retry_in: self.next_retry_in.take(),
            });
        }
    }

    /// RTL2g: an UPDATE event for condition changes without a state change.
    fn emit_update(&mut self, reason: Option<ErrorInfo>, resumed: bool, has_backlog: bool) {
        self.logger.major(|| {
            format!(
                "Channel '{}': UPDATE{}",
                self.name,
                reason
                    .as_ref()
                    .map(|e| format!(" (reason: {})", e))
                    .unwrap_or_default()
            )
        });
        self.publish_snapshot();
        let _ = self.events_tx.send(ChannelStateChange {
            previous: self.state,
            current: self.state,
            event: ChannelEvent::Update,
            reason,
            resumed,
            has_backlog,
            retry_in: None,
        });
    }

    fn publish_snapshot(&self) {
        let _ = self.snapshot_tx.send(ChannelSnapshot {
            state: self.state,
            options: self.options.clone(),
            presence_sync_complete: self.presence.sync_complete,
            error_reason: self.error_reason.clone(),
            channel_serial: self.channel_serial.clone(),
            attach_serial: self.attach_serial.clone(),
            modes: self.attached_modes.clone(),
        });
    }

    /// §8: deliver to matching subscribers; prune closed receivers.
    fn deliver(&mut self, msg: &crate::rest::Message) {
        self.subscribers.retain(|sub| {
            let matches = match &sub.filter {
                SubscriberFilter::All => true,
                SubscriberFilter::Name(n) => msg.name.as_deref() == Some(n.as_str()),
                SubscriberFilter::Filter(f) => f.matches(msg),
            };
            if !matches {
                return true;
            }
            sub.sender.send(msg.clone()).is_ok()
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

/// RTP6a/RTP6b: deliver to matching presence subscribers; prune closed.
fn deliver_presence(
    subscribers: &mut Vec<PresenceSubscriber>,
    event: &crate::rest::PresenceMessage,
) {
    subscribers.retain(|sub| {
        let matches = match &sub.actions {
            None => true,
            Some(actions) => event.action.map(|a| actions.contains(&a)).unwrap_or(false),
        };
        if !matches {
            return true;
        }
        sub.sender.send(event.clone()).is_ok()
    });
}

/// RTP11: resolve deferred gets now that the sync state is settled.
fn resolve_presence_gets(presence: &mut PresenceCtx) {
    for get in std::mem::take(&mut presence.pending_get) {
        let members = presence_members(presence, &get.client_id, &get.connection_id);
        let _ = get.reply.send(Ok(members));
    }
}

/// RTP11c2/c3: the members list with optional clientId/connectionId filters.
fn presence_members(
    presence: &PresenceCtx,
    client_id: &Option<String>,
    connection_id: &Option<String>,
) -> Vec<crate::rest::PresenceMessage> {
    presence
        .map
        .values()
        .into_iter()
        .filter(|m| {
            client_id
                .as_ref()
                .map(|c| m.client_id.as_deref() == Some(c.as_str()))
                .unwrap_or(true)
                && connection_id
                    .as_ref()
                    .map(|c| m.connection_id.as_deref() == Some(c.as_str()))
                    .unwrap_or(true)
        })
        .cloned()
        .collect()
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
    /// RTN13d: pings issued while CONNECTING/DISCONNECTED, executed on
    /// CONNECTED (or failed if a terminal state arrives first, RTN13b).
    deferred_pings: Vec<oneshot::Sender<Result<Duration>>>,
    /// RTC8a3/RTC8b1: authorize() outcomes awaiting the server's verdict.
    pending_authorize: Vec<oneshot::Sender<Result<()>>>,
    /// RTN7b: the next msgSerial; reset on a failed resume (RTN15c7).
    msg_serial: i64,
    /// RTN7: sent MESSAGE ProtocolMessages awaiting ACK/NACK, in serial
    /// order. Resent on a new transport (RTN19a).
    pending_publishes: Vec<PendingPublish>,
    /// RTL6c2: messages awaiting a connection (queueMessages=true).
    queued_publishes: Vec<QueuedPublish>,

    /// All channel state, inside the loop (DESIGN.md §7).
    channels: std::collections::HashMap<String, ChannelCtx>,

    snapshot_tx: watch::Sender<ConnectionSnapshot>,
    events_tx: broadcast::Sender<ConnectionStateChange>,
    input_tx: mpsc::UnboundedSender<LoopInput>,
}

impl ConnectionCtx {
    fn logger(&self) -> crate::options::Logger {
        self.rest.inner.opts.logger()
    }

    /// Transition the state machine: snapshot first, then the event.
    fn transition(&mut self, to: ConnectionState, reason: Option<ErrorInfo>) {
        let previous = self.state;
        if previous != to {
            self.logger().major(|| {
                format!(
                    "Connection: {:?} -> {:?}{}",
                    previous,
                    to,
                    reason
                        .as_ref()
                        .map(|e| format!(" (reason: {})", e))
                        .unwrap_or_default()
                )
            });
        }
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
        // RTN13d/RTN13b: deferred pings execute on CONNECTED, fail on a
        // terminal state
        self.resolve_deferred_pings(to, &reason);
        // RTN7d/RTN7e: publish outcomes follow the connection state
        match to {
            // RTN7d: with queueMessages (default) pending publishes survive
            // DISCONNECTED and are resent on the next transport (RTN19a);
            // without it they fail now
            ConnectionState::Disconnected => {
                if !self.rest.inner.opts.queue_messages {
                    let err = reason.clone().unwrap_or_else(|| {
                        ErrorInfo::new(
                            ErrorCode::Disconnected.code(),
                            "Connection disconnected and queueMessages is disabled",
                        )
                    });
                    self.fail_all_publishes(&err);
                }
            }
            // RTN7e: terminal states fail everything with the state-change
            // reason
            ConnectionState::Suspended
            | ConnectionState::Closed
            | ConnectionState::Failed
            | ConnectionState::Closing => {
                let err = reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ConnectionFailed.code(),
                        format!("Connection became {:?}", to),
                    )
                });
                self.fail_all_publishes(&err);
            }
            _ => {}
        }
        // RTC8a3/RTC8b1: authorize() outcomes follow the connection state
        self.resolve_authorize(to, &reason);
        if to == ConnectionState::Connected {
            // RTL3d/RTL4i: (re)attach channels
            self.reattach_channels_on_connected();
        }
    }

    /// RTL6c: the publish state table. Channel SUSPENDED/FAILED and terminal
    /// connection states fail immediately (RTL6c4); CONNECTED sends now
    /// (RTL6c1, regardless of channel attach state, no implicit attach
    /// RTL6c5); anything else queues per queueMessages (RTL6c2).
    fn handle_publish(
        &mut self,
        name: String,
        messages: Vec<crate::rest::Message>,
        params: Option<serde_json::Value>,
        reply: oneshot::Sender<Result<crate::rest::PublishResult>>,
    ) {
        // RTL6c4: channel state gate
        if let Some(ch) = self.channels.get(&name) {
            if matches!(ch.state, ChannelState::Suspended | ChannelState::Failed) {
                let _ = reply.send(Err(ch.error_reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Cannot publish on a {:?} channel", ch.state),
                    )
                })));
                return;
            }
        }
        match self.state {
            ConnectionState::Connected => self.send_publish(name, messages, params, reply),
            // RTL6c2: queue while a connection is plausible
            ConnectionState::Initialized
            | ConnectionState::Connecting
            | ConnectionState::Disconnected => {
                if self.rest.inner.opts.queue_messages {
                    self.queued_publishes.push(QueuedPublish {
                        channel: name,
                        messages,
                        params,
                        reply,
                    });
                } else {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::Disconnected.code(),
                        "Cannot publish: not connected and queueMessages is disabled",
                    )));
                }
            }
            // RTL6c4: terminal connection states
            _ => {
                let _ = reply.send(Err(self.error_reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ConnectionFailed.code(),
                        format!("Cannot publish in connection state {:?}", self.state),
                    )
                })));
            }
        }
    }

    /// Encode for the wire (RSL4/RSL5 with the channel cipher), assign the
    /// next msgSerial (RTN7b), send, and register the pending ACK (RTN7a).
    fn send_publish(
        &mut self,
        name: String,
        messages: Vec<crate::rest::Message>,
        params: Option<serde_json::Value>,
        reply: oneshot::Sender<Result<crate::rest::PublishResult>>,
    ) {
        let cipher = self
            .channels
            .get(&name)
            .and_then(|ch| ch.options.cipher.clone());
        let format = self.rest.inner.opts.format;
        let mut wire_messages = Vec::with_capacity(messages.len());
        for mut msg in messages {
            let (data, encoding) = match crate::rest::encode_data_for_wire(
                msg.data,
                msg.encoding,
                format,
                cipher.as_ref(),
            ) {
                Ok(de) => de,
                Err(e) => {
                    let _ = reply.send(Err(e));
                    return;
                }
            };
            msg.data = data;
            msg.encoding = encoding;
            wire_messages.push(msg);
        }
        let serial = self.msg_serial;
        self.msg_serial += 1;
        let mut pm = ProtocolMessage::new(action::MESSAGE);
        pm.channel = Some(name.clone());
        pm.msg_serial = Some(serial);
        pm.messages = Some(wire_messages.clone());
        pm.params = params.clone();
        self.send_protocol(pm);
        self.pending_publishes.push(PendingPublish {
            msg_serial: serial,
            channel: name,
            payload: PendingPayload::Messages {
                messages: wire_messages,
                params,
            },
            reply,
        });
    }

    /// Resend a pending publish verbatim (RTN19a) under its (possibly
    /// renumbered) serial.
    fn resend_pending_publishes(&mut self) {
        if !self.pending_publishes.is_empty() {
            self.logger().minor(|| {
                format!(
                    "RTN19a: resending {} pending publish(es) on the new transport",
                    self.pending_publishes.len()
                )
            });
        }
        let resends: Vec<ProtocolMessage> = self
            .pending_publishes
            .iter()
            .map(|p| {
                p.payload
                    .to_protocol_message(p.channel.clone(), p.msg_serial)
            })
            .collect();
        for pm in resends {
            self.send_protocol(pm);
        }
    }

    /// RTL6c2: queued publishes go out in order once CONNECTED.
    fn flush_queued_publishes(&mut self) {
        if !self.queued_publishes.is_empty() {
            self.logger().minor(|| {
                format!(
                    "Flushing {} queued publish(es)",
                    self.queued_publishes.len()
                )
            });
        }
        for q in std::mem::take(&mut self.queued_publishes) {
            self.send_publish(q.channel, q.messages, q.params, q.reply);
        }
    }

    /// RTN7e: fail every pending and queued publish with the given reason.
    fn fail_all_publishes(&mut self, reason: &ErrorInfo) {
        for p in self.pending_publishes.drain(..) {
            let _ = p.reply.send(Err(reason.clone()));
        }
        for q in self.queued_publishes.drain(..) {
            let _ = q.reply.send(Err(reason.clone()));
        }
    }

    /// TR4s/RTL6j: an ACK resolves pending publishes with serials in
    /// [msgSerial, msgSerial+count), pairing them with `res` entries.
    fn handle_ack(&mut self, pm: ProtocolMessage) {
        let first = pm.msg_serial.unwrap_or(0);
        let count = pm.count.unwrap_or(1) as i64;
        let res = pm.res.unwrap_or_default();
        let acked: Vec<PendingPublish> = {
            let mut acked = Vec::new();
            let mut i = 0;
            while i < self.pending_publishes.len() {
                let serial = self.pending_publishes[i].msg_serial;
                if serial >= first && serial < first + count {
                    acked.push(self.pending_publishes.remove(i));
                } else {
                    i += 1;
                }
            }
            acked
        };
        if acked.is_empty() {
            self.logger().error(|| {
                format!(
                    "ACK for unknown msgSerial range [{}, {}) — no pending operation matches",
                    first,
                    first + count
                )
            });
        }
        for p in acked {
            let idx = (p.msg_serial - first) as usize;
            let result = res
                .get(idx)
                .map(|r| crate::rest::PublishResult {
                    serials: r.serials.clone(),
                    message_id: None,
                })
                .unwrap_or_default();
            let _ = p.reply.send(Ok(result));
        }
    }

    /// A NACK fails the addressed pending publishes (RTL6j).
    fn handle_nack(&mut self, pm: ProtocolMessage) {
        let first = pm.msg_serial.unwrap_or(0);
        let count = pm.count.unwrap_or(1) as i64;
        let reason = pm.error.unwrap_or_else(|| {
            ErrorInfo::with_status(ErrorCode::InternalError.code(), 500, "Publish rejected")
        });
        let mut i = 0;
        let mut matched = false;
        while i < self.pending_publishes.len() {
            let serial = self.pending_publishes[i].msg_serial;
            if serial >= first && serial < first + count {
                let p = self.pending_publishes.remove(i);
                self.logger()
                    .minor(|| format!("NACK for msgSerial {}: {}", serial, reason));
                let _ = p.reply.send(Err(reason.clone()));
                matched = true;
            } else {
                i += 1;
            }
        }
        if !matched {
            self.logger().error(|| {
                format!(
                    "NACK for unknown msgSerial range [{}, {}) — no pending operation matches",
                    first,
                    first + count
                )
            });
        }
    }

    /// RTP8/9/10: a presence operation per the RTP16 connection/channel
    /// state table: send when ATTACHED, queue while ATTACHING (or implicit
    /// attach from INITIALIZED, RTP8d), error otherwise (RTP8g/RTP16c).
    fn handle_presence_op(
        &mut self,
        name: String,
        message: crate::rest::PresenceMessage,
        reply: oneshot::Sender<Result<()>>,
    ) {
        let connected = self.state == ConnectionState::Connected;
        let _rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Unknown channel",
            )));
            return;
        };
        match ch.state {
            ChannelState::Attached => {
                if connected {
                    self.send_presence(name, message, reply);
                } else if self.rest.inner.opts.queue_messages
                    && matches!(
                        self.state,
                        ConnectionState::Connecting | ConnectionState::Disconnected
                    )
                {
                    ch.presence
                        .queued_ops
                        .push(QueuedPresenceOp { message, reply });
                } else {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::Disconnected.code(),
                        format!("Cannot send presence in connection state {:?}", self.state),
                    )));
                }
            }
            // RTP16b: queued until the attach completes
            ChannelState::Attaching => {
                ch.presence
                    .queued_ops
                    .push(QueuedPresenceOp { message, reply });
            }
            // RTP8d: an INITIALIZED channel is implicitly attached
            ChannelState::Initialized => {
                ch.presence
                    .queued_ops
                    .push(QueuedPresenceOp { message, reply });
                let (attach_reply, _rx) = oneshot::channel();
                self.handle_attach(name, attach_reply);
            }
            // RTP8g/RTP16c: DETACHED/DETACHING/SUSPENDED/FAILED error
            _ => {
                let _ = reply.send(Err(ErrorInfo::with_status(
                    ErrorCode::UnableToEnterPresenceChannelInvalidChannelState.code(),
                    400,
                    format!("Cannot send presence in channel state {:?}", ch.state),
                )));
            }
        }
    }

    /// Send a PRESENCE ProtocolMessage with the next msgSerial; the ACK/NACK
    /// resolves the reply through the pending-publish machinery (RTL11a:
    /// resolution is unaffected by later channel state changes).
    fn send_presence(
        &mut self,
        name: String,
        message: crate::rest::PresenceMessage,
        reply: oneshot::Sender<Result<()>>,
    ) {
        let serial = self.msg_serial;
        self.msg_serial += 1;
        let mut pm = ProtocolMessage::new(action::PRESENCE);
        pm.channel = Some(name.clone());
        pm.msg_serial = Some(serial);
        pm.presence = Some(vec![message.clone()]);
        self.send_protocol(pm);
        let (ack_reply, ack_rx) = oneshot::channel::<Result<crate::rest::PublishResult>>();
        self.pending_publishes.push(PendingPublish {
            msg_serial: serial,
            channel: name,
            payload: PendingPayload::Presence(vec![message]),
            reply: ack_reply,
        });
        tokio::spawn(async move {
            let outcome = match ack_rx.await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ErrorInfo::new(
                    ErrorCode::Disconnected.code(),
                    "Connection loop dropped the presence op",
                )),
            };
            let _ = reply.send(outcome);
        });
    }

    /// RTP11: presence get with waitForSync semantics.
    fn handle_presence_get(
        &mut self,
        name: String,
        wait_for_sync: bool,
        client_id: Option<String>,
        connection_id: Option<String>,
        reply: oneshot::Sender<Result<Vec<crate::rest::PresenceMessage>>>,
    ) {
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Ok(Vec::new()));
            return;
        };
        // RTP11d: SUSPENDED errors unless waitForSync=false
        if ch.state == ChannelState::Suspended {
            if wait_for_sync {
                let _ = reply.send(Err(ErrorInfo::with_status(
                    91005,
                    400,
                    "Presence state is out of sync (channel suspended)",
                )));
            } else {
                let _ = reply.send(Ok(presence_members(
                    &ch.presence,
                    &client_id,
                    &connection_id,
                )));
            }
            return;
        }
        if !wait_for_sync || ch.presence.sync_complete {
            let _ = reply.send(Ok(presence_members(
                &ch.presence,
                &client_id,
                &connection_id,
            )));
            return;
        }
        // RTP11a/RTP11b: defer until the sync completes (the implicit attach
        // is issued handle-side)
        ch.presence.pending_get.push(DeferredPresenceGet {
            client_id,
            connection_id,
            reply,
        });
    }

    /// RTAN1b: annotation ops share the message-publish state table; the
    /// wire shape is an ANNOTATION ProtocolMessage resolved via ACK/NACK
    /// (RTAN1d).
    fn handle_annotation_op(
        &mut self,
        name: String,
        annotation: crate::rest::Annotation,
        reply: oneshot::Sender<Result<()>>,
    ) {
        // RTL6c4-shaped channel gate
        if let Some(ch) = self.channels.get(&name) {
            if matches!(ch.state, ChannelState::Suspended | ChannelState::Failed) {
                let _ = reply.send(Err(ch.error_reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Cannot publish an annotation on a {:?} channel", ch.state),
                    )
                })));
                return;
            }
        }
        if self.state != ConnectionState::Connected {
            let _ = reply.send(Err(ErrorInfo::new(
                ErrorCode::Disconnected.code(),
                format!(
                    "Cannot publish an annotation in connection state {:?}",
                    self.state
                ),
            )));
            return;
        }
        let serial = self.msg_serial;
        self.msg_serial += 1;
        let mut pm = ProtocolMessage::new(action::ANNOTATION);
        pm.channel = Some(name.clone());
        pm.msg_serial = Some(serial);
        pm.annotations = Some(vec![annotation.clone()]);
        self.send_protocol(pm);
        let (ack_reply, ack_rx) = oneshot::channel::<Result<crate::rest::PublishResult>>();
        self.pending_publishes.push(PendingPublish {
            msg_serial: serial,
            channel: name,
            payload: PendingPayload::Annotations(vec![annotation]),
            reply: ack_reply,
        });
        tokio::spawn(async move {
            let outcome = match ack_rx.await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ErrorInfo::new(
                    ErrorCode::Disconnected.code(),
                    "Connection loop dropped the annotation op",
                )),
            };
            let _ = reply.send(outcome);
        });
    }

    /// RTAN4: inbound ANNOTATION — decode entries and dispatch to matching
    /// subscribers (RTAN4c type filters).
    fn handle_annotation_action(&mut self, pm: ProtocolMessage) {
        self.update_channel_serial(&pm);
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        if ch.state != ChannelState::Attached {
            return;
        }
        let entries = pm.annotations.clone().unwrap_or_default();
        for (index, mut ann) in entries.into_iter().enumerate() {
            if ann.id.is_none() {
                if let Some(pm_id) = &pm.id {
                    ann.id = Some(format!("{}:{}", pm_id, index));
                }
            }
            if ann.timestamp.is_none() {
                ann.timestamp = pm.timestamp;
            }
            ch.annotation_subscribers.retain(|sub| {
                let matches = sub
                    .type_filter
                    .as_ref()
                    .map(|t| ann.annotation_type.as_deref() == Some(t.as_str()))
                    .unwrap_or(true);
                if !matches {
                    return true;
                }
                sub.sender.send(ann.clone()).is_ok()
            });
        }
    }

    /// RTL15b: MESSAGE/PRESENCE/ANNOTATION carrying a channelSerial update the
    /// channel's serial (SYNC is excluded — see handle_presence_action).
    fn update_channel_serial(&mut self, pm: &ProtocolMessage) {
        let Some(name) = &pm.channel else { return };
        let Some(serial) = &pm.channel_serial else {
            return;
        };
        if let Some(ch) = self.channels.get_mut(name) {
            ch.channel_serial = Some(serial.clone());
            ch.publish_snapshot();
        }
    }

    /// A MESSAGE from the server: TM2 field population, RSL6 decode with the
    /// channel cipher, RTL17 attached-only delivery, subscriber dispatch (§8).
    fn handle_message_action(&mut self, pm: ProtocolMessage) {
        self.update_channel_serial(&pm);
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        // RTL17: messages are only delivered while ATTACHED
        if ch.state != ChannelState::Attached {
            ch.logger.minor(|| {
                format!(
                    "RTL17: dropping MESSAGE for channel '{}' in state {:?}",
                    name, ch.state
                )
            });
            return;
        }
        let wire = pm.messages.clone().unwrap_or_default();
        for (index, mut msg) in wire.into_iter().enumerate() {
            // TM2a: id defaults to protocolMessage.id + ":" + index
            if msg.id.is_none() {
                if let Some(pm_id) = &pm.id {
                    msg.id = Some(format!("{}:{}", pm_id, index));
                }
            }
            // TM2c: connectionId inherited unless already present
            if msg.connection_id.is_none() {
                msg.connection_id = pm.connection_id.clone();
            }
            // TM2f: timestamp inherited unless already present
            if msg.timestamp.is_none() {
                msg.timestamp = pm.timestamp;
            }
            // RSL6: decode/decrypt with the channel cipher
            let (data, encoding) =
                crate::rest::decode_data(msg.data, msg.encoding, ch.options.cipher.as_ref());
            msg.data = data;
            msg.encoding = encoding;
            ch.deliver(&msg);
        }
    }

    /// RTP6/RTP17/RTP18/RTP19: inbound PRESENCE or SYNC. Field population
    /// follows TM2 conventions; events are dispatched per RTP2 newness.
    fn handle_presence_action(&mut self, pm: ProtocolMessage, is_sync: bool) {
        // RTL15b: PRESENCE updates the channel serial; SYNC does not — its
        // channelSerial carries the sync cursor ("<sequence>:<cursor>"), which
        // is not a channel serial and would be rejected by the server if sent
        // back in a reattach ATTACH (RTL4c1).
        if !is_sync {
            self.update_channel_serial(&pm);
        }
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let own_connection = self.id.clone();
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };

        if is_sync && !ch.presence.map.sync_in_progress() {
            // RTP18a: a new sync page stream begins
            ch.logger
                .minor(|| format!("Channel '{}': presence SYNC started", name));
            ch.presence.map.start_sync();
            ch.presence.sync_complete = false;
            ch.publish_snapshot();
        }

        let wire = pm.presence.clone().unwrap_or_default();
        for (index, mut msg) in wire.into_iter().enumerate() {
            // TM2-shaped inheritance
            if msg.id.is_none() {
                if let Some(pm_id) = &pm.id {
                    msg.id = Some(format!("{}:{}", pm_id, index));
                }
            }
            if msg.connection_id.is_none() {
                msg.connection_id = pm.connection_id.clone();
            }
            if msg.timestamp.is_none() {
                msg.timestamp = pm.timestamp;
            }
            msg.decode_with_cipher(ch.options.cipher.as_ref());
            // RTP17: members entered through THIS connection feed the
            // internal map
            if own_connection.is_some() && msg.connection_id == own_connection {
                ch.presence.internal.put(&msg);
            }
            if let Some(event) = ch.presence.map.put(&msg) {
                deliver_presence(&mut ch.presence.subscribers, &event);
            }
        }

        // RTP18b/RTP18c: the sync completes when the cursor is exhausted
        if is_sync && !crate::presence::sync_continues(&pm.channel_serial) {
            ch.logger
                .minor(|| format!("Channel '{}': presence SYNC complete", name));
            let leaves = ch.presence.map.end_sync();
            for leave in &leaves {
                deliver_presence(&mut ch.presence.subscribers, leave);
            }
            ch.presence.sync_complete = true;
            ch.publish_snapshot();
            resolve_presence_gets(&mut ch.presence);
        }
    }

    /// RTN13a/RTN13e: send a HEARTBEAT with a fresh random id and track it.
    /// RTN13c: the timeout runs from the send, not from the ping() call.
    fn send_ping(&mut self, reply: oneshot::Sender<Result<Duration>>) {
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
            deadline: now + self.rest.inner.opts.realtime_request_timeout,
            reply,
        });
    }

    /// RTC8a3/RTC8b1: resolve authorize() outcomes. Ok on (re)connection,
    /// Err when the connection lands in FAILED/SUSPENDED/CLOSED instead.
    fn resolve_authorize(&mut self, to: ConnectionState, reason: &Option<ErrorInfo>) {
        match to {
            ConnectionState::Connected => {
                for reply in self.pending_authorize.drain(..) {
                    let _ = reply.send(Ok(()));
                }
            }
            ConnectionState::Failed | ConnectionState::Suspended | ConnectionState::Closed => {
                for reply in self.pending_authorize.drain(..) {
                    let _ = reply.send(Err(reason.clone().unwrap_or_else(|| {
                        ErrorInfo::new(
                            ErrorCode::Forbidden.code(),
                            format!("Authorization failed: connection became {:?}", to),
                        )
                    })));
                }
            }
            _ => {}
        }
    }

    /// RTN13d: execute or fail pings deferred while CONNECTING/DISCONNECTED.
    fn resolve_deferred_pings(&mut self, to: ConnectionState, reason: &Option<ErrorInfo>) {
        match to {
            ConnectionState::Connected => {
                for reply in std::mem::take(&mut self.deferred_pings) {
                    self.send_ping(reply);
                }
            }
            ConnectionState::Connecting | ConnectionState::Disconnected => {}
            // RTN13b: a terminal state fails the deferred pings
            _ => {
                for reply in self.deferred_pings.drain(..) {
                    let _ = reply.send(Err(reason.clone().unwrap_or_else(|| {
                        ErrorInfo::new(
                            ErrorCode::BadRequest.code(),
                            format!("Ping failed: connection became {:?}", to),
                        )
                    })));
                }
            }
        }
    }

    /// RTN4h: an event that is not a state change (additional CONNECTED).
    fn emit_update(&mut self, reason: Option<ErrorInfo>) {
        self.logger().major(|| {
            format!(
                "Connection: UPDATE{}",
                reason
                    .as_ref()
                    .map(|e| format!(" (reason: {})", e))
                    .unwrap_or_default()
            )
        });
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
        self.logger().micro(|| {
            format!(
                "-> action={} channel={} serial={:?}",
                msg.action,
                msg.channel.as_deref().unwrap_or("-"),
                msg.msg_serial
            )
        });
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
            self.logger().minor(|| {
                format!(
                    "Scheduling reconnect attempt {} (disconnectedRetryTimeout backoff)",
                    self.retry_count
                )
            });
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
                ConnectionState::Closing | ConnectionState::Closed | ConnectionState::Failed => {}
            },
            Command::EnsureChannel {
                name,
                options,
                snapshot_tx,
                events_tx,
            } => {
                let logger = self.rest.inner.opts.logger();
                self.channels
                    .entry(name.clone())
                    .or_insert_with(|| ChannelCtx {
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
                        retry_at: None,
                        retry_count: 0,
                        next_retry_in: None,
                        op_revert_state: ChannelState::Initialized,
                        subscribers: Vec::new(),
                        presence: PresenceCtx::default(),
                        annotation_subscribers: Vec::new(),
                        snapshot_tx,
                        events_tx,
                        logger,
                    });
            }
            Command::Attach { name, reply } => self.handle_attach(name, reply),
            Command::PresenceOp {
                name,
                message,
                reply,
            } => {
                self.handle_presence_op(name, message, reply);
            }
            Command::PresenceGet {
                name,
                wait_for_sync,
                client_id,
                connection_id,
                reply,
            } => {
                self.handle_presence_get(name, wait_for_sync, client_id, connection_id, reply);
            }
            Command::PresenceSubscribe {
                name,
                id,
                actions,
                sender,
            } => {
                // RTP6: registration only; implicit attach happens handle-side
                if let Some(ch) = self.channels.get_mut(&name) {
                    ch.presence.subscribers.push(PresenceSubscriber {
                        id,
                        actions,
                        sender,
                    });
                }
            }
            Command::AnnotationOp {
                name,
                annotation,
                reply,
            } => {
                self.handle_annotation_op(name, annotation, reply);
            }
            Command::AnnotationSubscribe {
                name,
                id,
                type_filter,
                sender,
            } => {
                if let Some(ch) = self.channels.get_mut(&name) {
                    ch.annotation_subscribers.push(AnnotationSubscriber {
                        id,
                        type_filter,
                        sender,
                    });
                }
            }
            Command::AnnotationUnsubscribe { name, id } => {
                if let Some(ch) = self.channels.get_mut(&name) {
                    match id {
                        Some(id) => ch.annotation_subscribers.retain(|s| s.id != id),
                        None => ch.annotation_subscribers.clear(),
                    }
                }
            }
            Command::PresenceReentryFailed { name, error } => {
                self.logger().major(|| {
                    format!(
                        "Channel '{}': automatic presence re-entry failed: {}",
                        name, error
                    )
                });
                if let Some(ch) = self.channels.get_mut(&name) {
                    // RTP17e: 91004 wraps the underlying failure
                    let mut wrapped =
                        ErrorInfo::with_cause(91004, "Automatic presence re-entry failed", error);
                    wrapped.status_code = Some(400);
                    // RTP17e: resumed=true — the channel itself was continuous
                    ch.emit_update(Some(wrapped), true, false);
                }
            }
            Command::PresenceUnsubscribe { name, id, action } => {
                if let Some(ch) = self.channels.get_mut(&name) {
                    match (id, action) {
                        // RTP7b: narrow this listener's registration by one
                        // action; drop it only when nothing remains
                        (Some(id), Some(act)) => {
                            for sub in ch.presence.subscribers.iter_mut() {
                                if sub.id == id {
                                    if let Some(actions) = &mut sub.actions {
                                        actions.retain(|a| *a != act);
                                    }
                                }
                            }
                            ch.presence.subscribers.retain(|s| {
                                !(s.id == id && s.actions.as_ref().is_some_and(|a| a.is_empty()))
                            });
                        }
                        // RTP7a: this listener everywhere
                        (Some(id), None) => ch.presence.subscribers.retain(|s| s.id != id),
                        // RTP7c: everyone
                        _ => ch.presence.subscribers.clear(),
                    }
                }
            }
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
            Command::Authorize {
                access_token,
                reply,
            } => match self.state {
                // RTC8a: alter the live connection via an AUTH message; the
                // reply resolves on the server's CONNECTED/ERROR (RTC8a3)
                ConnectionState::Connected => {
                    self.send_auth(access_token);
                    self.pending_authorize.push(reply);
                }
                // RTC8b: halt the in-flight attempt and reconnect with the
                // new token (already cached in the REST auth state)
                ConnectionState::Connecting => {
                    self.pending_authorize.push(reply);
                    self.start_connect();
                }
                // RTC8c: initiate a connection from any other state
                _ => {
                    self.pending_authorize.push(reply);
                    self.error_reason = None;
                    self.retry_at = None;
                    self.transition(ConnectionState::Connecting, None);
                    self.start_connect();
                }
            },
            Command::Publish {
                name,
                messages,
                params,
                reply,
            } => {
                self.handle_publish(name, messages, params, reply);
            }
            Command::Subscribe {
                name,
                id,
                filter,
                sender,
            } => {
                if let Some(ch) = self.channels.get_mut(&name) {
                    ch.subscribers.push(Subscriber { id, filter, sender });
                }
            }
            Command::Unsubscribe { name, spec } => {
                if let Some(ch) = self.channels.get_mut(&name) {
                    match spec {
                        // RTL8a: remove the listener from every registration
                        UnsubscribeSpec::Id(id) => ch.subscribers.retain(|s| s.id != id),
                        // RTL8b: remove only the name-specific registration
                        UnsubscribeSpec::NameAndId(filter_name, id) => {
                            ch.subscribers.retain(|s| {
                                !(s.id == id
                                    && matches!(&s.filter, SubscriberFilter::Name(n) if n == &filter_name))
                            })
                        }
                        // RTL8c: remove everything
                        UnsubscribeSpec::All => ch.subscribers.clear(),
                    }
                }
            }
            Command::SetOptions {
                name,
                options,
                reply,
            } => {
                let connected = self.state == ConnectionState::Connected;
                let rtt = self.rest.inner.opts.realtime_request_timeout;
                let Some(ch) = self.channels.get_mut(&name) else {
                    let _ = reply.send(Ok(()));
                    return;
                };
                let reattach = ch.options.reattach_needed(&options)
                    && matches!(ch.state, ChannelState::Attached | ChannelState::Attaching);
                ch.options = options;
                ch.publish_snapshot();
                if reattach && connected {
                    // RTL16a: reattach with the new options; the reply joins
                    // the attach repliers and resolves on ATTACHED
                    ch.pending_attach.push(reply);
                    if ch.state != ChannelState::Attaching {
                        ch.transition(ChannelState::Attaching, None, false, false);
                    }
                    ch.op_deadline = Some(Instant::now() + rtt);
                    let msg = attach_message(ch);
                    self.send_protocol(msg);
                } else {
                    let _ = reply.send(Ok(()));
                }
            }
            Command::Ping { reply } => match self.state {
                ConnectionState::Connected => self.send_ping(reply),
                // RTN13d: deferred until the connection (re)connects
                ConnectionState::Connecting | ConnectionState::Disconnected => {
                    self.deferred_pings.push(reply);
                }
                // RTN13b: error in INITIALIZED/SUSPENDED/CLOSING/CLOSED/FAILED
                _ => {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::BadRequest.code(),
                        format!("Cannot ping in state {:?}", self.state),
                    )));
                }
            },
        }
    }

    fn handle_connect_attempt(&mut self, result: Result<Box<dyn TransportConnection>>) {
        if self.state != ConnectionState::Connecting {
            return;
        }
        match result {
            Ok(conn) => {
                let writer_tx = spawn_transport_tasks(
                    conn,
                    self.generation,
                    self.input_tx.clone(),
                    self.logger(),
                );
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
        self.logger().micro(|| {
            format!(
                "<- action={} channel={} serial={:?}",
                pm.action,
                pm.channel.as_deref().unwrap_or("-"),
                pm.msg_serial
            )
        });
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
            action::ACK => self.handle_ack(pm),
            action::NACK => self.handle_nack(pm),
            action::MESSAGE => self.handle_message_action(pm),
            action::PRESENCE => self.handle_presence_action(pm, false),
            action::SYNC => self.handle_presence_action(pm, true),
            action::ANNOTATION => self.handle_annotation_action(pm),
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
            // RSA4c3: a failed renewal while CONNECTED has no side effects —
            // no state change, no event, errorReason untouched. The expiry
            // path surfaces the failure later via the state machine.
            Err(err) => {
                self.rest.inner.opts.log(
                    crate::options::LogLevel::Minor,
                    &format!("Token renewal failed while connected: {}", err),
                );
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
                // (was this a resume at all, and did it succeed? RTN19a2)
                let resume_succeeded = self.last_connected_id.is_some()
                    && new_id == self.last_connected_id
                    && reason.is_none();
                if self.last_connected_id.is_some() {
                    self.logger().minor(|| {
                        format!(
                            "Resume {}: connection id {:?} (was {:?}){}",
                            if resume_succeeded {
                                "succeeded"
                            } else {
                                "failed"
                            },
                            new_id,
                            self.last_connected_id,
                            reason
                                .as_ref()
                                .map(|e| format!(", server error: {}", e))
                                .unwrap_or_default()
                        )
                    });
                }

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
                // RTN25 (UTS error-reason-cleared-on-connect-4): a clean
                // CONNECTED clears the previous errorReason
                if reason.is_none() {
                    self.error_reason = None;
                }
                self.transition(ConnectionState::Connected, reason);
                // RTN19a: pending publishes are resent on the new transport.
                // RTN19a2: serials are kept on a successful resume; a failed
                // resume reset the counter (RTN15c7, below), so renumber.
                if !resume_succeeded {
                    self.msg_serial = 0;
                    let mut next = 0;
                    for p in &mut self.pending_publishes {
                        p.msg_serial = next;
                        next += 1;
                    }
                    self.msg_serial = next;
                }
                self.resend_pending_publishes();
                // RTL6c2: queued publishes go out after the resends, in order
                self.flush_queued_publishes();
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
                // RTC8a3: an in-band AUTH confirmed by this CONNECTED
                for reply in self.pending_authorize.drain(..) {
                    let _ = reply.send(Ok(()));
                }
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
                // RTN15h1: a token error with no means to renew (no key,
                // authCallback or authUrl) is terminal. The connection fails
                // with 40171 ("no way to renew the auth token") rather than the
                // server's token error, matching ably-js — the SDK detected it
                // cannot reauth and substitutes the more specific code. The
                // server's error is preserved as the cause (TI1).
                self.drop_transport();
                let mut err = ErrorInfo::with_status(
                    ErrorCode::NoWayToRenewAuthToken.code(),
                    401,
                    "Token error received but the token cannot be renewed \
                     (no key, authCallback or authUrl)"
                        .to_string(),
                );
                err.cause = pm.error.map(Box::new);
                self.transition(ConnectionState::Failed, Some(err));
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
        if self.state == ConnectionState::Connecting
            && is_token_error
            && self.can_renew_token()
            && !self.renewed_this_cycle
        {
            // RTN14b: renew once and retry the connection
            self.renewed_this_cycle = true;
            self.force_renewal_on_next_connect = true;
            self.drop_transport();
            self.start_connect();
            return;
        }
        // RSA4a: token error with no way to renew is FAILED
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
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        let resumed = pm.flags.map(|f| f & flags::RESUMED != 0).unwrap_or(false);
        let has_backlog = pm
            .flags
            .map(|f| f & flags::HAS_BACKLOG != 0)
            .unwrap_or(false);
        match ch.state {
            ChannelState::Attaching => {
                ch.attach_serial = pm.channel_serial.clone();
                ch.channel_serial = pm.channel_serial.clone();
                // RTL4m: modes granted by the server
                ch.attached_modes = pm.flags.map(modes_from_flags);
                ch.has_been_attached = true;
                ch.op_deadline = None;
                // RTL13b: a successful attach ends the retry cycle
                ch.retry_at = None;
                ch.retry_count = 0;
                // RTP1/RTP19a: HAS_PRESENCE announces an incoming sync;
                // without it the presence set is authoritatively empty
                let has_presence = pm
                    .flags
                    .map(|f| f & flags::HAS_PRESENCE != 0)
                    .unwrap_or(false);
                if has_presence {
                    ch.presence.map.start_sync();
                    ch.presence.sync_complete = false;
                } else {
                    ch.presence.map.start_sync();
                    let leaves = ch.presence.map.end_sync();
                    for leave in &leaves {
                        deliver_presence(&mut ch.presence.subscribers, leave);
                    }
                    ch.presence.sync_complete = true;
                    resolve_presence_gets(&mut ch.presence);
                }
                ch.resolve_attach(Ok(()));
                ch.transition(ChannelState::Attached, pm.error, resumed, has_backlog);
                // RTP5b: queued presence ops go out now
                let queued: Vec<QueuedPresenceOp> = ch.presence.queued_ops.drain(..).collect();
                // RTP17i: automatic re-entry of internal members on a
                // non-resumed attach; RTP17g1: the id is omitted when the
                // connectionId changed
                let mut reentries = Vec::new();
                if !resumed {
                    let own = self.id.clone();
                    for member in ch.presence.internal.values() {
                        let mut enter = member.clone();
                        enter.action = Some(crate::rest::PresenceAction::Enter);
                        if enter.connection_id != own {
                            enter.id = None;
                        }
                        enter.connection_id = None;
                        reentries.push(enter);
                    }
                }
                let detach_now = std::mem::take(&mut ch.detach_pending);
                for op in queued {
                    self.send_presence(name.clone(), op.message, op.reply);
                }
                for enter in reentries {
                    let (reply, rx) = oneshot::channel();
                    self.send_presence(name.clone(), enter, reply);
                    // RTP17e: a failed re-entry surfaces as a channel UPDATE
                    // with the error
                    let input_tx = self.input_tx.clone();
                    let chan = name.clone();
                    tokio::spawn(async move {
                        if let Ok(Err(err)) = rx.await {
                            let _ = input_tx.send(LoopInput::Cmd(Command::PresenceReentryFailed {
                                name: chan,
                                error: err,
                            }));
                        }
                    });
                }
                // RTL5i: a queued detach proceeds now
                if detach_now {
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
                    // RTP1/RTP19a: the flagless re-ATTACHED makes the
                    // presence set authoritatively empty; with HAS_PRESENCE a
                    // fresh sync follows
                    let has_presence = pm
                        .flags
                        .map(|f| f & flags::HAS_PRESENCE != 0)
                        .unwrap_or(false);
                    if has_presence {
                        ch.presence.map.start_sync();
                        ch.presence.sync_complete = false;
                        ch.publish_snapshot();
                    } else {
                        ch.presence.map.start_sync();
                        let leaves = ch.presence.map.end_sync();
                        for leave in &leaves {
                            deliver_presence(&mut ch.presence.subscribers, leave);
                        }
                        ch.presence.sync_complete = true;
                        ch.publish_snapshot();
                        resolve_presence_gets(&mut ch.presence);
                    }
                    // RTP17i: continuity was lost — re-enter internal members
                    let own = self.id.clone();
                    let mut reentries = Vec::new();
                    for member in ch.presence.internal.values() {
                        let mut enter = member.clone();
                        enter.action = Some(crate::rest::PresenceAction::Enter);
                        if enter.connection_id != own {
                            enter.id = None; // RTP17g1
                        }
                        enter.connection_id = None;
                        reentries.push(enter);
                    }
                    for enter in reentries {
                        let (reply, rx) = oneshot::channel();
                        self.send_presence(name.clone(), enter, reply);
                        let input_tx = self.input_tx.clone();
                        let chan = name.clone();
                        tokio::spawn(async move {
                            if let Ok(Err(err)) = rx.await {
                                let _ =
                                    input_tx.send(LoopInput::Cmd(Command::PresenceReentryFailed {
                                        name: chan,
                                        error: err,
                                    }));
                            }
                        });
                    }
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
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
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
                let attach_now =
                    std::mem::take(&mut self.channels.get_mut(&name).unwrap().attach_pending);
                if attach_now {
                    let (tx, _rx) = oneshot::channel();
                    self.handle_attach(name, tx);
                }
            }
            // RTL13a: server-initiated DETACHED on an ATTACHED or SUSPENDED
            // channel triggers an immediate reattach
            ChannelState::Attached | ChannelState::Suspended => {
                let rtt = self.rest.inner.opts.realtime_request_timeout;
                let Some(ch) = self.channels.get_mut(&name) else {
                    return;
                };
                ch.transition(ChannelState::Attaching, pm.error, false, false);
                ch.op_deadline = Some(Instant::now() + rtt);
                let msg = attach_message(ch);
                self.send_protocol(msg);
            }
            // RTL13b: DETACHED while ATTACHING is a failed (re)attach — go
            // SUSPENDED and schedule a retry
            ChannelState::Attaching => {
                let reason = pm.error.clone();
                if let Some(ch) = self.channels.get_mut(&name) {
                    ch.op_deadline = None;
                    ch.resolve_attach(Err(reason.clone().unwrap_or_else(|| {
                        ErrorInfo::new(
                            ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                            "Attach rejected by the server",
                        )
                    })));
                }
                self.suspend_channel_with_retry(&name, reason);
            }
            _ => {}
        }
    }

    /// ERROR with a channel set: the attach/detach failed (RTL4e/RTL5e-shaped).
    fn handle_channel_error(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
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
    fn apply_connection_effects_to_channels(
        &mut self,
        conn_state: ConnectionState,
        reason: &Option<ErrorInfo>,
    ) {
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
                            ErrorInfo::new(
                                ErrorCode::ConnectionSuspended.code(),
                                "Connection suspended",
                            )
                        })));
                        ch.transition(ChannelState::Suspended, reason.clone(), false, false);
                    }
                }
            }
            // RTL3e: DISCONNECTED leaves channel states untouched
            _ => {}
        }
        // RTL13c: channel reattach retries only run while CONNECTED
        if conn_state != ConnectionState::Connected {
            for ch in self.channels.values_mut() {
                ch.retry_at = None;
            }
        }
    }

    /// RTL13b: transition a channel to SUSPENDED and schedule the next
    /// reattach retry (RTB1 backoff over channelRetryTimeout), provided the
    /// connection is still CONNECTED (RTL13c).
    fn suspend_channel_with_retry(&mut self, name: &str, reason: Option<ErrorInfo>) {
        let connected = self.state == ConnectionState::Connected;
        let base = self.rest.inner.opts.channel_retry_timeout;
        let Some(ch) = self.channels.get_mut(name) else {
            return;
        };
        if connected {
            let delay = retry_delay(base, ch.retry_count);
            ch.retry_count += 1;
            ch.retry_at = Some(Instant::now() + delay);
            ch.next_retry_in = Some(delay);
            ch.logger.minor(|| {
                format!(
                    "Channel '{}': scheduling reattach retry {} in {:?} (RTL13b)",
                    name, ch.retry_count, delay
                )
            });
        }
        ch.transition(ChannelState::Suspended, reason, false, false);
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
            } else if ch.state == ChannelState::Detaching {
                // RTN19b: a pending DETACH is resent on the new transport
                ch.op_deadline = Some(Instant::now() + rtt);
                let mut msg = ProtocolMessage::new(action::DETACH);
                msg.channel = Some(ch.name.clone());
                to_send.push(msg);
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
        consider(self.channels.values().filter_map(|c| c.retry_at).min());
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
                self.retry_at = Some(now + self.rest.inner.opts.suspended_retry_timeout);
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
                    // RTL4f: attach timeout → SUSPENDED with the error;
                    // RTL13b: with a scheduled reattach retry
                    ChannelState::Attaching => {
                        let err = ErrorInfo::with_status(
                            ErrorCode::ChannelOperationFailedNoResponseFromServer.code(),
                            408,
                            "Attach timed out",
                        );
                        ch.resolve_attach(Err(err.clone()));
                        self.suspend_channel_with_retry(&name, Some(err));
                        continue;
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

        // RTL13b: scheduled channel reattach retries (only while CONNECTED,
        // RTL13c — leaving CONNECTED clears retry_at)
        let retries: Vec<String> = self
            .channels
            .values()
            .filter(|c| c.retry_at.map(|d| d <= now).unwrap_or(false))
            .map(|c| c.name.clone())
            .collect();
        for name in retries {
            let rtt = self.rest.inner.opts.realtime_request_timeout;
            if self.state != ConnectionState::Connected {
                if let Some(ch) = self.channels.get_mut(&name) {
                    ch.retry_at = None;
                }
                continue;
            }
            let Some(ch) = self.channels.get_mut(&name) else {
                continue;
            };
            ch.retry_at = None;
            if ch.state != ChannelState::Suspended {
                continue;
            }
            ch.transition(ChannelState::Attaching, None, false, false);
            ch.op_deadline = Some(Instant::now() + rtt);
            let msg = attach_message(ch);
            self.send_protocol(msg);
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
            ChannelMode::AnnotationPublish => flags::ANNOTATION_PUBLISH,
            ChannelMode::AnnotationSubscribe => flags::ANNOTATION_SUBSCRIBE,
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
    if f & flags::ANNOTATION_PUBLISH != 0 {
        modes.push(ChannelMode::AnnotationPublish);
    }
    if f & flags::ANNOTATION_SUBSCRIBE != 0 {
        modes.push(ChannelMode::AnnotationSubscribe);
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
    let mut params: Vec<(String, String)> = Vec::new();
    // RTN2f: protocol version; RTN2a: format
    params.push(("v".into(), "6".into()));
    params.push((
        "format".into(),
        match opts.format {
            Format::MessagePack => "msgpack",
            Format::JSON => "json",
        }
        .into(),
    ));
    // RTN23a: this client consumes HEARTBEAT protocol messages
    params.push(("heartbeats".into(), "true".into()));
    // RTC1a/RTN2b: message echo, explicit either way
    params.push((
        "echo".into(),
        if opts.echo_messages { "true" } else { "false" }.into(),
    ));
    // RTN2d: clientId when configured
    if let Some(client_id) = &opts.client_id {
        params.push(("clientId".into(), client_id.clone()));
    }
    // RTN15b1: resume with the previous connection key
    if let Some(resume_key) = resume {
        params.push(("resume".into(), resume_key.into()));
    }
    // RTC1f: user transportParams, overriding library defaults (RTC1f1)
    for (k, v) in &opts.transport_params {
        if let Some(existing) = params.iter_mut().find(|(pk, _)| pk == k) {
            existing.1 = v.clone();
        } else {
            params.push((k.clone(), v.clone()));
        }
    }
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in &params {
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
    logger: crate::options::Logger,
) -> mpsc::UnboundedSender<ProtocolMessage> {
    let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<ProtocolMessage>();
    tokio::spawn(async move {
        let mut conn = conn;
        loop {
            tokio::select! {
                outbound = writer_rx.recv() => match outbound {
                    Some(pm) => {
                        if conn.send(pm).await.is_err() {
                            logger.error(|| {
                                "Transport write failed; dropping the transport".to_string()
                            });
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
        deferred_pings: Vec::new(),
        pending_authorize: Vec::new(),
        msg_serial: 0,
        pending_publishes: Vec::new(),
        queued_publishes: Vec::new(),
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

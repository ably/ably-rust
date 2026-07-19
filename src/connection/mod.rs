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

use crate::auth::{AuthHeader, Credential};
use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::{
    action, ChannelMode, ChannelState, ChannelStateChange, ConnectionDetails, ConnectionEvent,
    ConnectionState, ConnectionStateChange, ProtocolMessage,
};
use crate::rest::{Format, Rest};
use crate::transport::{Transport, TransportConnection, TransportEvent};

pub(crate) type Generation = u64;

/// RTL18/PC3: the vcdiff delta decoder — `(delta, base) -> decoded`, matching
/// the VD2 `decode(delta, base)` interface. Bundled: production always uses
/// `vcdiff::decode`; tests inject a mock via `ClientOptions` (behind
/// `#[cfg(test)]`). Wrapping it in an `Arc` keeps the decode path uniform and
/// lets it be cloned out of the loop before borrowing a channel.
pub(crate) type DeltaDecoder =
    Arc<dyn Fn(&[u8], &[u8]) -> std::result::Result<Vec<u8>, String> + Send + Sync>;

/// The production decoder: the bundled `vcdiff-decode` crate.
pub(crate) fn default_delta_decoder() -> DeltaDecoder {
    Arc::new(|delta: &[u8], base: &[u8]| vcdiff::decode(base, delta).map_err(|e| e.to_string()))
}

mod channel_arm;
mod presence_arm;
mod publish_arm;

use channel_arm::*;

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
    /// RTN17j: outcome of a spawned connectivity-check probe.
    Connectivity {
        generation: Generation,
        up: bool,
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
    /// RTN16g: snapshot the recovery key (connectionKey + msgSerial +
    /// attached channels' serials), or None in inactive states (RTN16g2).
    CreateRecoveryKey {
        reply: oneshot::Sender<Option<String>>,
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
    reply: PendingReply,
}

/// The caller waiting on a pending publish's ACK/NACK. Message publishes
/// resolve with the PublishResult; presence and annotation ops only care
/// about success, so their result is collapsed here instead of through a
/// per-op bridging task.
enum PendingReply {
    Publish(oneshot::Sender<Result<crate::rest::PublishResult>>),
    Op(oneshot::Sender<Result<()>>),
}

impl PendingReply {
    fn resolve(self, result: Result<crate::rest::PublishResult>) {
        match self {
            PendingReply::Publish(tx) => {
                let _ = tx.send(result);
            }
            PendingReply::Op(tx) => {
                let _ = tx.send(result.map(|_| ()));
            }
        }
    }
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
    /// RTL19: base payload of the most recent message (wire form, String or
    /// Binary), used to decode subsequent vcdiff deltas.
    delta_base_payload: Option<crate::rest::Data>,
    /// RTL20: id of the most recent message, checked against a delta's
    /// `extras.delta.from`.
    delta_last_message_id: Option<String>,
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

/// All mutable connection state, owned exclusively by the loop task.
struct ConnectionCtx {
    rest: Rest,
    transport_factory: Arc<dyn Transport>,
    /// RTL18/PC3: the bundled vcdiff delta decoder (test-overridable).
    delta_decoder: DeltaDecoder,

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
    /// RTN17j: the connectivity check has already run (and passed) this
    /// connect cycle — later fallback steps in the cycle skip the probe.
    connectivity_checked: bool,
    /// RTN17j: the failure that triggered an in-flight connectivity probe,
    /// reported if the probe finds no internet (or the cycle exhausts).
    pending_fallback_error: Option<ErrorInfo>,
    /// RTN17: the host of the current attempt/connection.
    current_host: Option<String>,
    /// RTN15b: the connection key used for resume on reconnects.
    resume_key: Option<String>,
    /// RTN16: the connectionKey from ClientOptions::recover, consumed by the
    /// first connect attempt (RTN16k).
    recover_key: Option<String>,
    /// RTN16f: the current connect attempt carries a recover param — a clean
    /// CONNECTED then keeps the recovered msgSerial.
    recovering: bool,
    /// RTN16j: channel/channelSerial pairs from the recovery key, seeding
    /// channels as they are first created.
    recover_channel_serials: std::collections::HashMap<String, String>,
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
        self.connectivity_checked = false;
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

    /// RTN17f/RTN17j: handle a failure that qualifies for host fallback.
    /// Before the first fallback attempt of a connect cycle, probe the REC3
    /// connectivity check URL from a spawned task (the loop never awaits
    /// I/O) to distinguish "Ably unreachable" (try the fallbacks) from "no
    /// internet" (skip them and enter the RTN14 retry state).
    fn fallback_or_retry(&mut self, err: Option<ErrorInfo>) {
        if self.connect_hosts.is_empty() {
            self.enter_retry_state(err);
            return;
        }
        if self.connectivity_checked {
            if !self.try_next_host() {
                self.enter_retry_state(err);
            }
            return;
        }
        self.connectivity_checked = true;
        // No attempt is in flight while the probe runs; the probe task owns
        // the timeout (Rest::check_connectivity) and always posts a result.
        self.connect_deadline = None;
        self.pending_fallback_error = err;
        self.logger().minor(|| {
            "RTN17j: probing the connectivity check URL before host fallback".to_string()
        });
        let generation = self.generation;
        let rest = self.rest.clone();
        let input_tx = self.input_tx.clone();
        tokio::spawn(async move {
            let up = rest.check_connectivity().await;
            let _ = input_tx.send(LoopInput::Connectivity { generation, up });
        });
    }

    /// RTN17j: the connectivity probe finished. With internet confirmed the
    /// fallback cycle proceeds; without it the fallbacks are pointless — the
    /// original failure enters the RTN14 retry state directly.
    fn handle_connectivity(&mut self, up: bool) {
        let err = self.pending_fallback_error.take();
        if up {
            if !self.try_next_host() {
                self.enter_retry_state(err);
            }
        } else {
            self.logger().major(|| {
                "RTN17j: connectivity check failed — no viable internet connection, \
                 skipping host fallback"
                    .to_string()
            });
            self.enter_retry_state(err);
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
        // RTN16k: the recover param goes on the first connection attempt only
        // (and never alongside resume) — consumed here so it is never resent.
        let recover = if resume.is_none() {
            self.recover_key.take()
        } else {
            None
        };
        self.recovering = recover.is_some();
        let force_renewal = std::mem::take(&mut self.force_renewal_on_next_connect);
        tokio::spawn(async move {
            let result = connect_task(rest, factory, host, resume, recover, force_renewal).await;
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
                // RTN16j: a channel named in the recovery key starts with its
                // recovered channelSerial, so the first ATTACH carries it
                // (RTL4c1) and the server can resume the channel's continuity
                let recovered_serial = self.recover_channel_serials.remove(&name);
                let seeded = recovered_serial.is_some();
                let ctx = self
                    .channels
                    .entry(name.clone())
                    .or_insert_with(|| ChannelCtx {
                        name,
                        state: ChannelState::Initialized,
                        error_reason: None,
                        channel_serial: recovered_serial,
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
                        delta_base_payload: None,
                        delta_last_message_id: None,
                        snapshot_tx,
                        events_tx,
                        logger,
                    });
                if seeded {
                    ctx.publish_snapshot();
                }
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
                    let mut wrapped = ErrorInfo::with_cause(
                        ErrorCode::UnableToAutomaticallyReEnterPresenceChannel.code(),
                        "Automatic presence re-entry failed",
                        error,
                    );
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
            Command::CreateRecoveryKey { reply } => {
                let _ = reply.send(self.create_recovery_key());
            }
        }
    }

    /// RTN16g: serialize the recovery key — the connectionKey, the current
    /// msgSerial and every attached channel's channelSerial. RTN16g2: None in
    /// CLOSING/CLOSED/FAILED/SUSPENDED or without a connectionKey. RTN16g1:
    /// JSON encodes any unicode channel name.
    fn create_recovery_key(&self) -> Option<String> {
        if matches!(
            self.state,
            ConnectionState::Closing
                | ConnectionState::Closed
                | ConnectionState::Failed
                | ConnectionState::Suspended
        ) {
            return None;
        }
        let key = self.key.as_ref()?;
        let serials: serde_json::Map<String, serde_json::Value> = self
            .channels
            .values()
            .filter(|c| c.state == ChannelState::Attached)
            .map(|c| {
                (
                    c.name.clone(),
                    serde_json::Value::String(c.channel_serial.clone().unwrap_or_default()),
                )
            })
            .collect();
        Some(
            serde_json::json!({
                "connectionKey": key,
                "msgSerial": self.msg_serial,
                "channelSerials": serials,
            })
            .to_string(),
        )
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
                // RSA15c: incompatible credentials (the token's clientId does
                // not match the configured clientId) is a client
                // misconfiguration that no retry can fix — terminal FAILED
                if err.code == Some(ErrorCode::IncompatibleCredentials.code()) {
                    self.drop_transport();
                    self.transition(ConnectionState::Failed, Some(err));
                    return;
                }
                // RTN17f: a host-unreachable failure tries the next fallback
                // within the same CONNECTING phase (after the RTN17j probe)
                self.fallback_or_retry(Some(err));
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
                    self.fallback_or_retry(Some(err));
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
                // RTN16f: a clean CONNECTED on a recover attempt continues the
                // previous instance's msgSerial; an error means the recovery
                // failed and the counter resets (RTN15c7)
                let recovered = std::mem::take(&mut self.recovering) && reason.is_none();
                // (was this a resume at all, and did it succeed? RTN19a2)
                let resume_succeeded = recovered
                    || (self.last_connected_id.is_some()
                        && new_id == self.last_connected_id
                        && reason.is_none());
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
            if is_5xx {
                self.fallback_or_retry(pm.error);
            } else {
                self.enter_retry_state(pm.error);
            }
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
                self.fallback_or_retry(Some(err));
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
    recover: Option<String>,
    force_renewal: bool,
) -> Result<Box<dyn TransportConnection>> {
    if force_renewal {
        rest.invalidate_cached_token();
    }
    let url = build_connection_url(&rest, &host, resume.as_deref(), recover.as_deref()).await?;
    factory.connect(&url).await
}

/// RTN2: the realtime connection URL with auth and protocol params.
async fn build_connection_url(
    rest: &Rest,
    host: &str,
    resume: Option<&str>,
    recover: Option<&str>,
) -> Result<String> {
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
    // RTN16k: recover a previous instance's connection (first attempt only;
    // mutually exclusive with resume — see start_connect_to)
    if let Some(recover_key) = recover {
        params.push(("recover".into(), recover_key.into()));
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
/// RTN16g: the serialized recovery key (JSON, matching the ably-js format).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryKey {
    connection_key: String,
    msg_serial: i64,
    #[serde(default)]
    channel_serials: std::collections::HashMap<String, String>,
}

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

    // RTN16: a recover option primes the loop before the first connect. A
    // malformed key logs an error and connects as if none was given (RTN16f1).
    let recovery = rest.inner.opts.recover.as_ref().and_then(|raw| {
        match serde_json::from_str::<RecoveryKey>(raw) {
            Ok(rk) => Some(rk),
            Err(e) => {
                rest.inner
                    .opts
                    .logger()
                    .error(|| format!("Malformed recovery key ignored (connecting fresh): {}", e));
                None
            }
        }
    });
    let (recover_key, recover_msg_serial, recover_channel_serials) = match recovery {
        Some(rk) => (Some(rk.connection_key), rk.msg_serial, rk.channel_serials),
        None => (None, 0, std::collections::HashMap::new()),
    };

    let delta_decoder = {
        #[cfg(test)]
        {
            rest.inner
                .opts
                .delta_decoder
                .clone()
                .unwrap_or_else(default_delta_decoder)
        }
        #[cfg(not(test))]
        {
            default_delta_decoder()
        }
    };
    let mut ctx = ConnectionCtx {
        rest,
        transport_factory,
        delta_decoder,
        state: ConnectionState::Initialized,
        id: None,
        key: None,
        error_reason: None,
        details: None,
        generation: 0,
        writer: None,
        connect_hosts: Vec::new(),
        connectivity_checked: false,
        pending_fallback_error: None,
        current_host: None,
        resume_key: None,
        recover_key,
        recovering: false,
        recover_channel_serials,
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
        // RTN16f: the msgSerial counter continues from the recovered value
        msg_serial: recover_msg_serial,
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
                    Some(LoopInput::Connectivity { generation, up }) => {
                        if generation == ctx.generation {
                            ctx.handle_connectivity(up);
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

//! Ably Realtime channel implementation.
//!
//! Provides the `RealtimeChannel` type with state machine, event system,
//! and the `Channels` collection for managing channels.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::broadcast;

use crate::protocol::{
    flags, Action, ChannelEvent, ChannelMode, ChannelState, ChannelStateChange, ConnectionState,
    ErrorInfo, ProtocolMessage, PublishResult,
};

/// A message received from a Realtime channel subscription.
#[derive(Debug, Clone)]
pub struct Message {
    pub id: Option<String>,
    pub name: Option<String>,
    pub data: Option<serde_json::Value>,
    pub connection_id: Option<String>,
    pub timestamp: Option<i64>,
    pub client_id: Option<String>,
    pub extras: Option<serde_json::Value>,
}

/// Unique ID for a subscription listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

/// A subscription entry (optional name filter + sender).
struct Subscription {
    id: SubscriptionId,
    name_filter: Option<String>,
    tx: tokio::sync::mpsc::UnboundedSender<Message>,
}

/// Options for a Realtime channel.
#[derive(Debug, Clone)]
pub struct RealtimeChannelOptions {
    /// Channel parameters (e.g., rewind, delta).
    pub params: Option<HashMap<String, String>>,
    /// Channel modes (publish, subscribe, etc.).
    pub modes: Option<Vec<ChannelMode>>,
    /// Whether to automatically attach when subscribing. Defaults to true.
    pub attach_on_subscribe: bool,
}

impl Default for RealtimeChannelOptions {
    fn default() -> Self {
        Self {
            params: None,
            modes: None,
            attach_on_subscribe: true,
        }
    }
}

impl RealtimeChannelOptions {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Encode channel modes as a flags bitmask for ATTACH messages. RTL4l.
fn modes_to_flags(modes: &[ChannelMode]) -> i64 {
    let mut f: i64 = 0;
    for mode in modes {
        f |= match mode {
            ChannelMode::Presence => flags::PRESENCE,
            ChannelMode::Publish => flags::PUBLISH,
            ChannelMode::Subscribe => flags::SUBSCRIBE,
            ChannelMode::PresenceSubscribe => flags::PRESENCE_SUBSCRIBE,
        };
    }
    f
}

/// Decode flags bitmask into channel modes. RTL4m.
fn flags_to_modes(f: i64) -> Vec<ChannelMode> {
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

/// A Realtime channel with state machine and event system.
pub struct RealtimeChannel {
    inner: Arc<ChannelInner>,
}

struct ChannelInner {
    /// The channel name.
    name: String,

    /// Current channel state.
    state: Mutex<ChannelState>,

    /// Last error reason.
    error_reason: Mutex<Option<ErrorInfo>>,

    /// Channel options.
    options: Mutex<RealtimeChannelOptions>,

    /// Broadcast channel for state change events.
    state_tx: broadcast::Sender<ChannelStateChange>,

    /// Sender for client-to-server messages (shared with Connection).
    client_msg_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>>,

    /// Oneshot senders waiting for attach completion.
    attach_waiters: Mutex<Vec<tokio::sync::oneshot::Sender<Result<(), ErrorInfo>>>>,

    /// Oneshot senders waiting for detach completion.
    detach_waiters: Mutex<Vec<tokio::sync::oneshot::Sender<Result<(), ErrorInfo>>>>,

    /// Channel serial from server (RTL15b, RTL4c1).
    channel_serial: Mutex<Option<String>>,

    /// Server-granted modes decoded from ATTACHED flags (RTL4m).
    modes: Mutex<Option<Vec<ChannelMode>>>,

    /// Whether this channel has ever been attached (for ATTACH_RESUME, RTL4j).
    has_been_attached: Mutex<bool>,

    /// Realtime request timeout for attach/detach (RTL4f, RTL5f, RTC7).
    attach_timeout: Mutex<Duration>,

    /// Queued operations to run after current pending state resolves (RTL4h, RTL5i).
    pending_op: Mutex<Option<PendingOp>>,

    /// Current connection state (updated by Channels collection). RTL4b.
    connection_state: Mutex<ConnectionState>,

    /// Message subscriptions (RTL7/RTL8).
    subscriptions: Mutex<Vec<Subscription>>,

    /// Next subscription ID counter.
    next_sub_id: Mutex<u64>,

    /// Whether to echo messages from this client (RTL7f).
    echo_messages: Mutex<bool>,

    /// This client's connection ID (for echo filtering).
    self_connection_id: Mutex<Option<String>>,

    /// Queued messages waiting for connection (RTL6c2).
    queued_messages: Mutex<
        Vec<(
            ProtocolMessage,
            tokio::sync::oneshot::Sender<Result<PublishResult, ErrorInfo>>,
        )>,
    >,

    /// Whether to queue messages when not connected (from ClientOptions). RTO6a.
    queue_messages: Mutex<bool>,

    /// Back-reference to ChannelsInner for msgSerial/ACK coordination.
    channels_inner: Mutex<Option<Arc<ChannelsInner>>>,
}

/// A queued operation to perform after a pending attach/detach completes.
enum PendingOp {
    Attach(tokio::sync::oneshot::Sender<Result<(), ErrorInfo>>),
    Detach(tokio::sync::oneshot::Sender<Result<(), ErrorInfo>>),
}

impl RealtimeChannel {
    /// Create a new channel with the given name and options.
    pub(crate) fn new(name: String, options: RealtimeChannelOptions) -> Self {
        let (state_tx, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(ChannelInner {
                name,
                state: Mutex::new(ChannelState::Initialized),
                error_reason: Mutex::new(None),
                options: Mutex::new(options),
                state_tx,
                client_msg_tx: Mutex::new(None),
                attach_waiters: Mutex::new(Vec::new()),
                detach_waiters: Mutex::new(Vec::new()),
                channel_serial: Mutex::new(None),
                modes: Mutex::new(None),
                has_been_attached: Mutex::new(false),
                attach_timeout: Mutex::new(Duration::from_secs(10)),
                pending_op: Mutex::new(None),
                connection_state: Mutex::new(ConnectionState::Initialized),
                subscriptions: Mutex::new(Vec::new()),
                next_sub_id: Mutex::new(0),
                echo_messages: Mutex::new(true),
                self_connection_id: Mutex::new(None),
                queued_messages: Mutex::new(Vec::new()),
                queue_messages: Mutex::new(true),
                channels_inner: Mutex::new(None),
            }),
        }
    }

    /// Get the channel name.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Get the current channel state.
    pub fn state(&self) -> ChannelState {
        *self.inner.state.lock().unwrap()
    }

    /// Get the last error reason.
    pub fn error_reason(&self) -> Option<ErrorInfo> {
        self.inner.error_reason.lock().unwrap().clone()
    }

    /// Get the current channel options.
    pub fn options(&self) -> RealtimeChannelOptions {
        self.inner.options.lock().unwrap().clone()
    }

    /// Get the server-granted modes (RTL4m). Set after ATTACHED response.
    pub fn modes(&self) -> Option<Vec<ChannelMode>> {
        self.inner.modes.lock().unwrap().clone()
    }

    /// Get the channel serial (RTL15b).
    pub fn channel_serial(&self) -> Option<String> {
        self.inner.channel_serial.lock().unwrap().clone()
    }

    /// Subscribe to all channel state change events.
    pub fn on_state_change(&self) -> broadcast::Receiver<ChannelStateChange> {
        self.inner.state_tx.subscribe()
    }

    /// Set the client message sender (called by Realtime when connection is available).
    pub(crate) fn set_client_msg_tx(
        &self,
        tx: Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>,
    ) {
        *self.inner.client_msg_tx.lock().unwrap() = tx;
    }

    /// Update the connection state (called by Channels when connection state changes).
    pub(crate) fn set_connection_state(&self, state: ConnectionState) {
        *self.inner.connection_state.lock().unwrap() = state;
    }

    /// Set the realtime request timeout (from ClientOptions).
    pub(crate) fn set_attach_timeout(&self, timeout: Duration) {
        *self.inner.attach_timeout.lock().unwrap() = timeout;
    }

    /// Set echo_messages preference (from ClientOptions). RTL7f.
    pub(crate) fn set_echo_messages(&self, echo: bool) {
        *self.inner.echo_messages.lock().unwrap() = echo;
    }

    /// Set this client's connection ID (for echo filtering). RTL7f.
    pub(crate) fn set_self_connection_id(&self, id: Option<String>) {
        *self.inner.self_connection_id.lock().unwrap() = id;
    }

    /// Set queue_messages preference (from ClientOptions). RTO6a.
    pub(crate) fn set_queue_messages(&self, queue: bool) {
        *self.inner.queue_messages.lock().unwrap() = queue;
    }

    /// Set back-reference to ChannelsInner for publish coordination.
    pub(crate) fn set_channels_inner(&self, ci: Arc<ChannelsInner>) {
        *self.inner.channels_inner.lock().unwrap() = Some(ci);
    }

    /// Build the ATTACH protocol message with params, modes, channelSerial, flags.
    fn build_attach_message(&self) -> ProtocolMessage {
        let options = self.inner.options.lock().unwrap().clone();
        let channel_serial = self.inner.channel_serial.lock().unwrap().clone();
        let has_been_attached = *self.inner.has_been_attached.lock().unwrap();

        let mut attach_flags: i64 = 0;

        // RTL4l: Encode modes as flags
        if let Some(ref modes) = options.modes {
            attach_flags |= modes_to_flags(modes);
        }

        // RTL4j: Set ATTACH_RESUME on reattach
        if has_been_attached {
            attach_flags |= flags::ATTACH_RESUME;
        }

        ProtocolMessage {
            channel: Some(self.inner.name.clone()),
            flags: if attach_flags != 0 {
                Some(attach_flags)
            } else {
                None
            },
            params: options.params.clone(), // RTL4k
            channel_serial,                 // RTL4c1
            ..ProtocolMessage::new(Action::Attach)
        }
    }

    /// Send a message via client_msg_tx. Returns true if sent.
    fn send_message(&self, msg: ProtocolMessage) -> bool {
        let tx = self.inner.client_msg_tx.lock().unwrap();
        if let Some(ref sender) = *tx {
            sender.send(msg).is_ok()
        } else {
            false
        }
    }

    /// Attach to this channel. RTL4.
    /// Sends ATTACH to the server and waits for ATTACHED response.
    pub async fn attach(&self) -> Result<(), ErrorInfo> {
        let current_state = self.state();

        // RTL4a: Already attached — no-op
        if current_state == ChannelState::Attached {
            return Ok(());
        }

        // RTL4h: If in a pending state (attaching/detaching), queue and wait
        if current_state == ChannelState::Attaching {
            // Already attaching — just wait for the existing attach to complete
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.inner.attach_waiters.lock().unwrap().push(tx);
            return match rx.await {
                Ok(result) => result,
                Err(_) => Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("Attach waiter dropped".to_string()),
                    href: None,
                }),
            };
        }

        if current_state == ChannelState::Detaching {
            // Wait for detach to complete, then attach
            let (tx, rx) = tokio::sync::oneshot::channel();
            *self.inner.pending_op.lock().unwrap() = Some(PendingOp::Attach(tx));
            return match rx.await {
                Ok(result) => result,
                Err(_) => Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("Pending attach waiter dropped".to_string()),
                    href: None,
                }),
            };
        }

        // RTL4b: Fail immediately if connection is in a terminal state
        let conn_state = *self.inner.connection_state.lock().unwrap();
        match conn_state {
            ConnectionState::Closed
            | ConnectionState::Closing
            | ConnectionState::Failed
            | ConnectionState::Suspended => {
                return Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some(format!(
                        "Cannot attach: connection is in {:?} state",
                        conn_state
                    )),
                    href: None,
                });
            }
            _ => {}
        }

        // RTL4g: Clear errorReason when attaching from Failed
        if current_state == ChannelState::Failed {
            *self.inner.error_reason.lock().unwrap() = None;
        }

        // Transition to Attaching
        self.set_state(ChannelState::Attaching, None, false, false);

        // Try to send ATTACH message
        let msg = self.build_attach_message();
        let sent = self.send_message(msg);

        if !sent {
            // RTL4i: If connection not ready, channel stays in ATTACHING.
            // The connection will send ATTACH when it becomes CONNECTED.
            // We register a waiter and return — the connection layer handles queuing.
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.inner.attach_waiters.lock().unwrap().push(tx);
            return match rx.await {
                Ok(result) => result,
                Err(_) => Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("Attach waiter dropped".to_string()),
                    href: None,
                }),
            };
        }

        // Wait for ATTACHED or ERROR via oneshot, with timeout (RTL4f)
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inner.attach_waiters.lock().unwrap().push(tx);

        let timeout = *self.inner.attach_timeout.lock().unwrap();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some("Attach waiter dropped".to_string()),
                href: None,
            }),
            Err(_) => {
                // RTL4f: Timeout → transition to SUSPENDED
                let err = ErrorInfo {
                    code: Some(90007),
                    status_code: None,
                    message: Some("Attach timed out".to_string()),
                    href: None,
                };
                self.set_state(ChannelState::Suspended, Some(err.clone()), false, false);
                // Drain any remaining waiters
                let waiters: Vec<_> = self
                    .inner
                    .attach_waiters
                    .lock()
                    .unwrap()
                    .drain(..)
                    .collect();
                for w in waiters {
                    let _ = w.send(Err(err.clone()));
                }
                Err(err)
            }
        }
    }

    /// Detach from this channel. RTL5.
    pub async fn detach(&self) -> Result<(), ErrorInfo> {
        let current_state = self.state();

        // RTL5a: Already detached or initialized — no-op
        if current_state == ChannelState::Detached || current_state == ChannelState::Initialized {
            return Ok(());
        }

        // RTL5b: Detach from failed state is an error
        if current_state == ChannelState::Failed {
            return Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some("Cannot detach from FAILED state".to_string()),
                href: None,
            });
        }

        // RTL5j: Detach from suspended → immediate transition to detached
        if current_state == ChannelState::Suspended {
            *self.inner.error_reason.lock().unwrap() = None;
            self.set_state(ChannelState::Detached, None, false, false);
            return Ok(());
        }

        // RTL5i: If in a pending state, queue
        if current_state == ChannelState::Detaching {
            // Already detaching — wait for completion
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.inner.detach_waiters.lock().unwrap().push(tx);
            return match rx.await {
                Ok(result) => result,
                Err(_) => Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("Detach waiter dropped".to_string()),
                    href: None,
                }),
            };
        }

        // RTL5l: If connection is not connected, transition immediately to detached
        let conn_state = *self.inner.connection_state.lock().unwrap();
        let is_connected = conn_state == ConnectionState::Connected;

        if current_state == ChannelState::Attaching {
            if !is_connected {
                // RTL5l: Connection not connected — transition immediately
                // Drain attach waiters with an error since we're aborting the attach
                let waiters: Vec<_> = self
                    .inner
                    .attach_waiters
                    .lock()
                    .unwrap()
                    .drain(..)
                    .collect();
                for w in waiters {
                    let _ = w.send(Err(ErrorInfo {
                        code: Some(90001),
                        status_code: None,
                        message: Some("Attach aborted by detach".to_string()),
                        href: None,
                    }));
                }
                *self.inner.error_reason.lock().unwrap() = None;
                self.set_state(ChannelState::Detached, None, false, false);
                return Ok(());
            }
            // Wait for attach to complete, then detach
            let (tx, rx) = tokio::sync::oneshot::channel();
            *self.inner.pending_op.lock().unwrap() = Some(PendingOp::Detach(tx));
            return match rx.await {
                Ok(result) => result,
                Err(_) => Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("Pending detach waiter dropped".to_string()),
                    href: None,
                }),
            };
        }

        let has_connection = self.inner.client_msg_tx.lock().unwrap().is_some();
        if !has_connection {
            *self.inner.error_reason.lock().unwrap() = None;
            self.set_state(ChannelState::Detached, None, false, false);
            return Ok(());
        }

        // Transition to Detaching
        let prev_state = current_state;
        self.set_state(ChannelState::Detaching, None, false, false);

        // Send DETACH message
        let msg = ProtocolMessage {
            channel: Some(self.inner.name.clone()),
            ..ProtocolMessage::new(Action::Detach)
        };

        let sent = self.send_message(msg);

        if !sent {
            // Connection dropped — transition immediately
            *self.inner.error_reason.lock().unwrap() = None;
            self.set_state(ChannelState::Detached, None, false, false);
            return Ok(());
        }

        // Wait for DETACHED or ERROR, with timeout (RTL5f)
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inner.detach_waiters.lock().unwrap().push(tx);

        let timeout = *self.inner.attach_timeout.lock().unwrap();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => {
                // Clear errorReason on successful detach
                if result.is_ok() {
                    *self.inner.error_reason.lock().unwrap() = None;
                }
                result
            }
            Ok(Err(_)) => Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some("Detach waiter dropped".to_string()),
                href: None,
            }),
            Err(_) => {
                // RTL5f: Timeout → return to previous state
                let err = ErrorInfo {
                    code: Some(90007),
                    status_code: None,
                    message: Some("Detach timed out".to_string()),
                    href: None,
                };
                self.set_state(prev_state, Some(err.clone()), false, false);
                // Drain remaining waiters
                let waiters: Vec<_> = self
                    .inner
                    .detach_waiters
                    .lock()
                    .unwrap()
                    .drain(..)
                    .collect();
                for w in waiters {
                    let _ = w.send(Err(err.clone()));
                }
                Err(err)
            }
        }
    }

    /// Set channel options. RTL16.
    pub async fn set_options(&self, options: RealtimeChannelOptions) -> Result<(), ErrorInfo> {
        let current_state = self.state();
        let needs_reattach =
            current_state == ChannelState::Attached || current_state == ChannelState::Attaching;
        let option_change_needs_reattach = options.params.is_some() || options.modes.is_some();

        // Update options
        *self.inner.options.lock().unwrap() = options;

        // RTL16a: Trigger reattachment if params/modes changed and channel is attached
        if needs_reattach && option_change_needs_reattach {
            // Force re-attach by setting state back to attaching
            self.set_state(ChannelState::Attaching, None, false, false);

            let msg = self.build_attach_message();
            let sent = self.send_message(msg);

            if !sent {
                return Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("No active connection to send ATTACH".to_string()),
                    href: None,
                });
            }

            let (tx, rx) = tokio::sync::oneshot::channel();
            self.inner.attach_waiters.lock().unwrap().push(tx);

            let timeout = *self.inner.attach_timeout.lock().unwrap();
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(result)) => return result,
                Ok(Err(_)) => {
                    return Err(ErrorInfo {
                        code: Some(90001),
                        status_code: None,
                        message: Some("Attach waiter dropped".to_string()),
                        href: None,
                    })
                }
                Err(_) => {
                    let err = ErrorInfo {
                        code: Some(90007),
                        status_code: None,
                        message: Some("Attach timed out".to_string()),
                        href: None,
                    };
                    self.set_state(ChannelState::Suspended, Some(err.clone()), false, false);
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    /// Publish a message on this channel. RTL6.
    /// Returns a PublishResult with message serials from the ACK.
    pub async fn publish(
        &self,
        name: Option<&str>,
        data: Option<serde_json::Value>,
    ) -> Result<PublishResult, ErrorInfo> {
        // RTL6c4: Fail if channel is SUSPENDED or FAILED
        let ch_state = self.state();
        if ch_state == ChannelState::Suspended || ch_state == ChannelState::Failed {
            return Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some(format!(
                    "Cannot publish: channel is in {:?} state",
                    ch_state
                )),
                href: None,
            });
        }

        // Build the message object
        let mut msg_obj = serde_json::Map::new();
        if let Some(n) = name {
            msg_obj.insert("name".to_string(), serde_json::Value::String(n.to_string()));
        }
        if let Some(d) = data {
            msg_obj.insert("data".to_string(), d);
        }

        self.publish_messages(vec![serde_json::Value::Object(msg_obj)])
            .await
    }

    /// Publish an array of messages. RTL6i2.
    pub async fn publish_messages(
        &self,
        messages: Vec<serde_json::Value>,
    ) -> Result<PublishResult, ErrorInfo> {
        // RTL6c4: Fail if channel is SUSPENDED or FAILED
        let ch_state = self.state();
        if ch_state == ChannelState::Suspended || ch_state == ChannelState::Failed {
            return Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some(format!(
                    "Cannot publish: channel is in {:?} state",
                    ch_state
                )),
                href: None,
            });
        }

        let msg = ProtocolMessage {
            action: Action::Message,
            channel: Some(self.inner.name.clone()),
            messages: Some(messages),
            ..ProtocolMessage::new(Action::Message)
        };

        // RTL6c1: Send immediately if connected and channel not SUSPENDED/FAILED
        // RTL6c5: Publish does NOT trigger implicit attach
        let conn_state = *self.inner.connection_state.lock().unwrap();
        let is_connected = conn_state == ConnectionState::Connected;

        if is_connected {
            // Assign msgSerial and register ACK waiter via ChannelsInner
            let (tx, rx) = tokio::sync::oneshot::channel();
            let prepared = {
                let ci = self.inner.channels_inner.lock().unwrap();
                if let Some(ref ci) = *ci {
                    ci.prepare_publish(msg, tx)
                } else {
                    return Err(ErrorInfo {
                        code: Some(90001),
                        status_code: None,
                        message: Some("Internal error: no channels reference".to_string()),
                        href: None,
                    });
                }
            };

            let sent = self.send_message(prepared);
            if !sent {
                return Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("Failed to send message".to_string()),
                    href: None,
                });
            }

            match rx.await {
                Ok(result) => result,
                Err(_) => Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some("Publish waiter dropped".to_string()),
                    href: None,
                }),
            }
        } else {
            // RTL6c2: Queue if connection INITIALIZED/CONNECTING/DISCONNECTED and queueMessages=true
            // RTL6c4: Fail otherwise
            let queue_messages = *self.inner.queue_messages.lock().unwrap();

            let can_queue = queue_messages
                && matches!(
                    conn_state,
                    ConnectionState::Initialized
                        | ConnectionState::Connecting
                        | ConnectionState::Disconnected
                );

            if can_queue {
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.inner.queued_messages.lock().unwrap().push((msg, tx));
                match rx.await {
                    Ok(result) => result,
                    Err(_) => Err(ErrorInfo {
                        code: Some(90001),
                        status_code: None,
                        message: Some("Queued publish waiter dropped".to_string()),
                        href: None,
                    }),
                }
            } else {
                Err(ErrorInfo {
                    code: Some(90001),
                    status_code: None,
                    message: Some(format!(
                        "Cannot publish: connection is in {:?} state",
                        conn_state
                    )),
                    href: None,
                })
            }
        }
    }

    /// Subscribe to all messages on this channel. RTL7a.
    /// Returns a (SubscriptionId, receiver) pair.
    pub fn subscribe(
        &self,
    ) -> (
        SubscriptionId,
        tokio::sync::mpsc::UnboundedReceiver<Message>,
    ) {
        self.subscribe_internal(None)
    }

    /// Subscribe to messages with a specific name. RTL7b.
    pub fn subscribe_with_name(
        &self,
        name: &str,
    ) -> (
        SubscriptionId,
        tokio::sync::mpsc::UnboundedReceiver<Message>,
    ) {
        self.subscribe_internal(Some(name.to_string()))
    }

    /// Internal subscribe implementation.
    fn subscribe_internal(
        &self,
        name_filter: Option<String>,
    ) -> (
        SubscriptionId,
        tokio::sync::mpsc::UnboundedReceiver<Message>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let id = {
            let mut counter = self.inner.next_sub_id.lock().unwrap();
            let id = SubscriptionId(*counter);
            *counter += 1;
            id
        };
        self.inner.subscriptions.lock().unwrap().push(Subscription {
            id,
            name_filter,
            tx,
        });

        // RTL7g: Implicit attach if attachOnSubscribe is true
        let options = self.inner.options.lock().unwrap().clone();
        if options.attach_on_subscribe {
            let state = self.state();
            if state == ChannelState::Initialized
                || state == ChannelState::Detaching
                || state == ChannelState::Detached
            {
                let inner = Arc::clone(&self.inner);
                let channel = RealtimeChannel {
                    inner: Arc::clone(&inner),
                };
                tokio::spawn(async move {
                    let _ = channel.attach().await;
                });
            }
        }

        (id, rx)
    }

    /// Unsubscribe a specific listener. RTL8a.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.inner
            .subscriptions
            .lock()
            .unwrap()
            .retain(|s| s.id != id);
    }

    /// Unsubscribe a specific listener from a specific name. RTL8b.
    pub fn unsubscribe_with_name(&self, name: &str, id: SubscriptionId) {
        self.inner
            .subscriptions
            .lock()
            .unwrap()
            .retain(|s| !(s.id == id && s.name_filter.as_deref() == Some(name)));
    }

    /// Unsubscribe all listeners. RTL8c.
    pub fn unsubscribe_all(&self) {
        self.inner.subscriptions.lock().unwrap().clear();
    }

    /// Deliver messages to subscribers. Called when MESSAGE is received.
    fn deliver_messages(&self, protocol_msg: &ProtocolMessage) {
        // RTL17: Only deliver when channel is ATTACHED
        if self.state() != ChannelState::Attached {
            return;
        }

        // RTL7f: Filter echo messages
        let echo = *self.inner.echo_messages.lock().unwrap();
        if !echo {
            let self_conn_id = self.inner.self_connection_id.lock().unwrap().clone();
            if let Some(ref self_id) = self_conn_id {
                if let Some(ref msg_conn_id) = protocol_msg.connection_id {
                    if self_id == msg_conn_id {
                        return; // Skip — this message is from us
                    }
                }
            }
        }

        if let Some(ref messages) = protocol_msg.messages {
            let subs = self.inner.subscriptions.lock().unwrap();

            for (index, msg_val) in messages.iter().enumerate() {
                let msg_obj = msg_val.as_object();

                // TM2a: Populate id from ProtocolMessage id + index
                let id = if let Some(obj) = msg_obj {
                    if let Some(existing_id) = obj.get("id").and_then(|v| v.as_str()) {
                        Some(existing_id.to_string())
                    } else if let Some(ref proto_id) = protocol_msg.id {
                        Some(format!("{}:{}", proto_id, index))
                    } else {
                        None
                    }
                } else {
                    None
                };

                // TM2c: Populate connectionId from ProtocolMessage
                let connection_id = if let Some(obj) = msg_obj {
                    if let Some(existing) = obj.get("connectionId").and_then(|v| v.as_str()) {
                        Some(existing.to_string())
                    } else {
                        protocol_msg.connection_id.clone()
                    }
                } else {
                    protocol_msg.connection_id.clone()
                };

                // TM2f: Populate timestamp from ProtocolMessage
                let timestamp = if let Some(obj) = msg_obj {
                    if let Some(existing) = obj.get("timestamp").and_then(|v| v.as_i64()) {
                        Some(existing)
                    } else {
                        protocol_msg.timestamp
                    }
                } else {
                    protocol_msg.timestamp
                };

                let name = msg_obj
                    .and_then(|o| o.get("name"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let data = msg_obj.and_then(|o| o.get("data")).cloned();
                let client_id = msg_obj
                    .and_then(|o| o.get("clientId"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let extras = msg_obj.and_then(|o| o.get("extras")).cloned();

                let message = Message {
                    id,
                    name: name.clone(),
                    data,
                    connection_id,
                    timestamp,
                    client_id,
                    extras,
                };

                // Deliver to matching subscribers
                for sub in subs.iter() {
                    let matches = match &sub.name_filter {
                        None => true,                                             // RTL7a: All messages
                        Some(filter) => name.as_deref() == Some(filter.as_str()), // RTL7b
                    };
                    if matches {
                        let _ = sub.tx.send(message.clone());
                    }
                }
            }
        }
    }

    /// Handle a protocol message directed at this channel.
    /// Called by Connection when it receives a channel-scoped message.
    pub(crate) fn handle_message(&self, msg: &ProtocolMessage) {
        match msg.action {
            Action::Attached => {
                let flags_val = msg.flags.unwrap_or(0);
                let resumed = (flags_val & flags::RESUMED) != 0;
                let has_backlog = (flags_val & flags::HAS_BACKLOG) != 0;
                let current_state = self.state();

                // RTL5k: ATTACHED received while DETACHING or DETACHED → send DETACH
                if current_state == ChannelState::Detaching
                    || current_state == ChannelState::Detached
                {
                    let detach_msg = ProtocolMessage {
                        channel: Some(self.inner.name.clone()),
                        ..ProtocolMessage::new(Action::Detach)
                    };
                    self.send_message(detach_msg);
                    return;
                }

                // RTL15b: Store channelSerial from server
                if let Some(ref serial) = msg.channel_serial {
                    *self.inner.channel_serial.lock().unwrap() = Some(serial.clone());
                }

                // RTL4m: Decode modes from ATTACHED flags
                let mode_flags = flags_val
                    & (flags::PRESENCE
                        | flags::PUBLISH
                        | flags::SUBSCRIBE
                        | flags::PRESENCE_SUBSCRIBE);
                if mode_flags != 0 {
                    *self.inner.modes.lock().unwrap() = Some(flags_to_modes(mode_flags));
                }

                if current_state == ChannelState::Attached {
                    // RTL2g/RTL12: Already attached — emit UPDATE if not resumed
                    if !resumed {
                        let change = ChannelStateChange {
                            previous: ChannelState::Attached,
                            current: ChannelState::Attached,
                            event: ChannelEvent::Update,
                            reason: msg.error.clone(),
                            resumed,
                            has_backlog,
                        };
                        let _ = self.inner.state_tx.send(change);
                    }
                    // If resumed, suppress the event per RTL12
                } else {
                    // Clear error reason on successful attach
                    *self.inner.error_reason.lock().unwrap() = None;

                    // Mark as has_been_attached for ATTACH_RESUME (RTL4j)
                    *self.inner.has_been_attached.lock().unwrap() = true;

                    self.set_state(ChannelState::Attached, None, resumed, has_backlog);
                }

                // Resolve attach waiters
                let waiters: Vec<_> = self
                    .inner
                    .attach_waiters
                    .lock()
                    .unwrap()
                    .drain(..)
                    .collect();
                for waiter in waiters {
                    let _ = waiter.send(Ok(()));
                }

                // RTL4h/RTL5i: Execute pending operation
                self.execute_pending_op();
            }
            Action::Detached => {
                // RTL15b1: Clear channelSerial on DETACHED
                *self.inner.channel_serial.lock().unwrap() = None;

                // Clear errorReason on successful detach
                *self.inner.error_reason.lock().unwrap() = None;

                self.set_state(ChannelState::Detached, msg.error.clone(), false, false);

                // Resolve detach waiters
                let waiters: Vec<_> = self
                    .inner
                    .detach_waiters
                    .lock()
                    .unwrap()
                    .drain(..)
                    .collect();
                for waiter in waiters {
                    let _ = waiter.send(Ok(()));
                }

                // RTL4h/RTL5i: Execute pending operation
                self.execute_pending_op();
            }
            Action::Error => {
                // Channel-level error → Failed
                let reason = msg.error.clone();
                self.set_state(ChannelState::Failed, reason.clone(), false, false);

                // Fail attach waiters
                let waiters: Vec<_> = self
                    .inner
                    .attach_waiters
                    .lock()
                    .unwrap()
                    .drain(..)
                    .collect();
                let err = reason.unwrap_or(ErrorInfo {
                    code: Some(90000),
                    status_code: None,
                    message: Some("Channel error".to_string()),
                    href: None,
                });
                for waiter in waiters {
                    let _ = waiter.send(Err(err.clone()));
                }

                // Also fail detach waiters
                let waiters: Vec<_> = self
                    .inner
                    .detach_waiters
                    .lock()
                    .unwrap()
                    .drain(..)
                    .collect();
                for waiter in waiters {
                    let _ = waiter.send(Err(err.clone()));
                }
            }
            Action::Message => {
                // Deliver messages to subscribers (RTL7, RTL17, TM2)
                self.deliver_messages(msg);
            }
            _ => {
                // Other channel messages (PRESENCE, SYNC, etc.)
            }
        }
    }

    /// Execute any pending operation queued via RTL4h/RTL5i.
    fn execute_pending_op(&self) {
        let op = self.inner.pending_op.lock().unwrap().take();
        if let Some(pending) = op {
            let inner = Arc::clone(&self.inner);
            let channel = RealtimeChannel {
                inner: Arc::clone(&inner),
            };
            tokio::spawn(async move {
                match pending {
                    PendingOp::Attach(tx) => {
                        let result = channel.attach().await;
                        let _ = tx.send(result);
                    }
                    PendingOp::Detach(tx) => {
                        let result = channel.detach().await;
                        let _ = tx.send(result);
                    }
                }
            });
        }
    }

    /// Set channel state and emit event.
    fn set_state(
        &self,
        new_state: ChannelState,
        reason: Option<ErrorInfo>,
        resumed: bool,
        has_backlog: bool,
    ) {
        let previous = {
            let mut state = self.inner.state.lock().unwrap();
            let prev = *state;
            *state = new_state;
            prev
        };

        // Set error reason if provided
        if reason.is_some() {
            *self.inner.error_reason.lock().unwrap() = reason.clone();
        }

        let event = ChannelEvent::from(new_state);
        let change = ChannelStateChange {
            previous,
            current: new_state,
            event,
            reason,
            resumed,
            has_backlog,
        };

        let _ = self.inner.state_tx.send(change);
    }
}

/// The Channels collection (RTS1-4).
/// Manages RealtimeChannel instances by name.
#[derive(Clone)]
pub struct Channels {
    inner: Arc<ChannelsInner>,
}

pub(crate) struct ChannelsInner {
    channels: Mutex<HashMap<String, Arc<RealtimeChannel>>>,
    /// Current client message sender (shared with new channels on creation).
    current_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>>,
    /// Realtime request timeout from ClientOptions (shared with new channels).
    attach_timeout: Mutex<Duration>,
    /// Current connection state (shared with new channels on creation).
    connection_state: Mutex<ConnectionState>,
    /// Whether to echo messages (from ClientOptions). RTL7f.
    echo_messages: Mutex<bool>,
    /// This client's connection ID (for echo filtering). RTL7f.
    self_connection_id: Mutex<Option<String>>,
    /// Whether to queue messages when not connected. RTO6a.
    queue_messages: Mutex<bool>,
    /// Next msgSerial for outgoing MESSAGE protocol messages. RTN7b.
    next_msg_serial: Mutex<i64>,
    /// Pending ACK waiters keyed by msgSerial. RTL6j.
    pending_acks:
        Mutex<HashMap<i64, tokio::sync::oneshot::Sender<Result<PublishResult, ErrorInfo>>>>,
}

impl Channels {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ChannelsInner {
                channels: Mutex::new(HashMap::new()),
                current_tx: Mutex::new(None),
                attach_timeout: Mutex::new(Duration::from_secs(10)),
                connection_state: Mutex::new(ConnectionState::Initialized),
                echo_messages: Mutex::new(true),
                self_connection_id: Mutex::new(None),
                queue_messages: Mutex::new(true),
                next_msg_serial: Mutex::new(0),
                pending_acks: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Set the realtime request timeout used for attach/detach on new channels.
    pub(crate) fn set_attach_timeout(&self, timeout: Duration) {
        *self.inner.attach_timeout.lock().unwrap() = timeout;
    }

    /// Get or create a channel by name. RTS3a.
    pub fn get(&self, name: &str) -> Arc<RealtimeChannel> {
        let mut channels = self.inner.channels.lock().unwrap();
        channels
            .entry(name.to_string())
            .or_insert_with(|| {
                let ch = Arc::new(RealtimeChannel::new(
                    name.to_string(),
                    RealtimeChannelOptions::default(),
                ));
                self.configure_new_channel(&ch);
                ch
            })
            .clone()
    }

    /// Get or create a channel with options. RTS3a/RTS3b.
    /// Returns an error if the channel is attached/attaching and options
    /// would change params or modes (RTS3c1).
    pub fn get_with_options(
        &self,
        name: &str,
        options: RealtimeChannelOptions,
    ) -> Result<Arc<RealtimeChannel>, ErrorInfo> {
        let mut channels = self.inner.channels.lock().unwrap();

        if let Some(existing) = channels.get(name) {
            let state = existing.state();
            let needs_reattach = options.params.is_some() || options.modes.is_some();

            // RTS3c1: Error if would trigger reattachment on attached/attaching channel
            if needs_reattach
                && (state == ChannelState::Attached || state == ChannelState::Attaching)
            {
                return Err(ErrorInfo {
                    code: Some(40000),
                    status_code: Some(400),
                    message: Some(
                        "Cannot update params/modes on attached channel via get(); use setOptions()"
                            .to_string(),
                    ),
                    href: None,
                });
            }

            // RTS3c: Update options on existing channel
            *existing.inner.options.lock().unwrap() = options;
            Ok(existing.clone())
        } else {
            let channel = Arc::new(RealtimeChannel::new(name.to_string(), options));
            self.configure_new_channel(&channel);
            channels.insert(name.to_string(), channel.clone());
            Ok(channel)
        }
    }

    /// Check if a channel exists. RTS2.
    pub fn exists(&self, name: &str) -> bool {
        self.inner.channels.lock().unwrap().contains_key(name)
    }

    /// Get the names of all channels. RTS2.
    pub fn names(&self) -> Vec<String> {
        self.inner
            .channels
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    /// Release (remove) a channel. RTS4a.
    pub async fn release(&self, name: &str) {
        self.inner.channels.lock().unwrap().remove(name);
    }

    /// Get a channel by name if it exists (for internal message routing).
    pub(crate) fn get_if_exists(&self, name: &str) -> Option<Arc<RealtimeChannel>> {
        self.inner.channels.lock().unwrap().get(name).cloned()
    }

    /// Update the client message sender on all channels and store for future channels.
    pub(crate) fn set_client_msg_tx(
        &self,
        tx: Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>,
    ) {
        // Store for channels created later
        *self.inner.current_tx.lock().unwrap() = tx.clone();
        // Update all existing channels
        let channels = self.inner.channels.lock().unwrap();
        for channel in channels.values() {
            channel.set_client_msg_tx(tx.clone());
        }
    }

    /// Update the connection state on all channels and store for future channels.
    pub(crate) fn set_connection_state(&self, state: ConnectionState) {
        *self.inner.connection_state.lock().unwrap() = state;
        let channels = self.inner.channels.lock().unwrap();
        for channel in channels.values() {
            channel.set_connection_state(state);
        }
    }

    /// Send queued ATTACH messages for channels in ATTACHING state.
    /// Called when connection becomes CONNECTED (RTL4i).
    pub(crate) fn send_pending_attaches(&self) {
        let channels = self.inner.channels.lock().unwrap();
        for channel in channels.values() {
            if channel.state() == ChannelState::Attaching {
                let msg = channel.build_attach_message();
                channel.send_message(msg);
            }
        }
    }

    /// Configure a newly created channel with current settings.
    fn configure_new_channel(&self, ch: &RealtimeChannel) {
        let tx = self.inner.current_tx.lock().unwrap().clone();
        ch.set_client_msg_tx(tx);
        let timeout = *self.inner.attach_timeout.lock().unwrap();
        ch.set_attach_timeout(timeout);
        let conn_state = *self.inner.connection_state.lock().unwrap();
        ch.set_connection_state(conn_state);
        let echo = *self.inner.echo_messages.lock().unwrap();
        ch.set_echo_messages(echo);
        let conn_id = self.inner.self_connection_id.lock().unwrap().clone();
        ch.set_self_connection_id(conn_id);
        let queue = *self.inner.queue_messages.lock().unwrap();
        ch.set_queue_messages(queue);
        ch.set_channels_inner(Arc::clone(&self.inner));
    }

    /// Set echo_messages on all channels and store for future channels. RTL7f.
    pub(crate) fn set_echo_messages(&self, echo: bool) {
        *self.inner.echo_messages.lock().unwrap() = echo;
        let channels = self.inner.channels.lock().unwrap();
        for channel in channels.values() {
            channel.set_echo_messages(echo);
        }
    }

    /// Set this client's connection ID on all channels. RTL7f.
    pub(crate) fn set_self_connection_id(&self, id: Option<String>) {
        *self.inner.self_connection_id.lock().unwrap() = id.clone();
        let channels = self.inner.channels.lock().unwrap();
        for channel in channels.values() {
            channel.set_self_connection_id(id.clone());
        }
    }

    /// Set queue_messages on all channels and store for future channels. RTO6a.
    pub(crate) fn set_queue_messages(&self, queue: bool) {
        *self.inner.queue_messages.lock().unwrap() = queue;
        let channels = self.inner.channels.lock().unwrap();
        for channel in channels.values() {
            channel.set_queue_messages(queue);
        }
    }

    /// Send all queued messages from all channels. Called when CONNECTED. RTL6c2.
    pub(crate) fn send_queued_messages(&self) {
        let channels = self.inner.channels.lock().unwrap();
        for channel in channels.values() {
            let queued: Vec<_> = channel
                .inner
                .queued_messages
                .lock()
                .unwrap()
                .drain(..)
                .collect();
            for (mut msg, waiter) in queued {
                // Assign msgSerial (RTN7b)
                let serial = {
                    let mut s = self.inner.next_msg_serial.lock().unwrap();
                    let val = *s;
                    *s += 1;
                    val
                };
                msg.msg_serial = Some(serial);

                // Register ACK waiter
                self.inner
                    .pending_acks
                    .lock()
                    .unwrap()
                    .insert(serial, waiter);

                // Send the message
                let tx = self.inner.current_tx.lock().unwrap();
                if let Some(ref sender) = *tx {
                    let _ = sender.send(msg);
                }
            }
        }
    }

    /// Handle ACK protocol message. RTL6j, TR4s.
    pub(crate) fn handle_ack(&self, msg: &ProtocolMessage) {
        if let Some(serial) = msg.msg_serial {
            let count = msg.count.unwrap_or(1) as i64;
            for i in 0..count {
                let target_serial = serial + i;
                if let Some(waiter) = self
                    .inner
                    .pending_acks
                    .lock()
                    .unwrap()
                    .remove(&target_serial)
                {
                    // Extract PublishResult from res array if available
                    let result = if let Some(ref res) = msg.res {
                        if let Some(pr) = res.get(i as usize) {
                            pr.clone()
                        } else {
                            PublishResult { serials: vec![] }
                        }
                    } else {
                        PublishResult { serials: vec![] }
                    };
                    let _ = waiter.send(Ok(result));
                }
            }
        }
    }

    /// Handle NACK protocol message.
    pub(crate) fn handle_nack(&self, msg: &ProtocolMessage) {
        if let Some(serial) = msg.msg_serial {
            let count = msg.count.unwrap_or(1) as i64;
            let err = msg.error.clone().unwrap_or(ErrorInfo {
                code: Some(50000),
                status_code: None,
                message: Some("Message rejected".to_string()),
                href: None,
            });
            for i in 0..count {
                let target_serial = serial + i;
                if let Some(waiter) = self
                    .inner
                    .pending_acks
                    .lock()
                    .unwrap()
                    .remove(&target_serial)
                {
                    let _ = waiter.send(Err(err.clone()));
                }
            }
        }
    }
}

impl ChannelsInner {
    /// Assign msgSerial and register ACK waiter when a channel sends a MESSAGE.
    /// Returns the modified ProtocolMessage with msgSerial set.
    pub(crate) fn prepare_publish(
        &self,
        mut msg: ProtocolMessage,
        waiter: tokio::sync::oneshot::Sender<Result<PublishResult, ErrorInfo>>,
    ) -> ProtocolMessage {
        let serial = {
            let mut s = self.next_msg_serial.lock().unwrap();
            let val = *s;
            *s += 1;
            val
        };
        msg.msg_serial = Some(serial);
        self.pending_acks.lock().unwrap().insert(serial, waiter);
        msg
    }
}

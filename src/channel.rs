//! Ably Realtime channel implementation.
//!
//! Provides the `RealtimeChannel` type with state machine, event system,
//! and the `Channels` collection for managing channels.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::protocol::{
    flags, Action, ChannelEvent, ChannelMode, ChannelState, ChannelStateChange, ErrorInfo,
    ProtocolMessage,
};

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

    /// Attach to this channel. RTL4.
    /// Sends ATTACH to the server and waits for ATTACHED response.
    pub async fn attach(&self) -> Result<(), ErrorInfo> {
        let current_state = self.state();

        // Already attached — no-op
        if current_state == ChannelState::Attached {
            return Ok(());
        }

        // Transition to Attaching
        self.set_state(ChannelState::Attaching, None, false, false);

        // Send ATTACH message
        let msg = ProtocolMessage {
            channel: Some(self.inner.name.clone()),
            ..ProtocolMessage::new(Action::Attach)
        };

        let sent = {
            let tx = self.inner.client_msg_tx.lock().unwrap();
            if let Some(ref sender) = *tx {
                sender.send(msg).is_ok()
            } else {
                false
            }
        };

        if !sent {
            let err = ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some("No active connection to send ATTACH".to_string()),
                href: None,
            };
            self.set_state(ChannelState::Failed, Some(err.clone()), false, false);
            return Err(err);
        }

        // Wait for ATTACHED or ERROR via oneshot
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            self.inner.attach_waiters.lock().unwrap().push(tx);
        }

        match rx.await {
            Ok(result) => result,
            Err(_) => Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some("Attach waiter dropped".to_string()),
                href: None,
            }),
        }
    }

    /// Detach from this channel. RTL5.
    pub async fn detach(&self) -> Result<(), ErrorInfo> {
        let current_state = self.state();

        // Already detached or initialized — no-op
        if current_state == ChannelState::Detached || current_state == ChannelState::Initialized {
            return Ok(());
        }

        // Transition to Detaching
        self.set_state(ChannelState::Detaching, None, false, false);

        // Send DETACH message
        let msg = ProtocolMessage {
            channel: Some(self.inner.name.clone()),
            ..ProtocolMessage::new(Action::Detach)
        };

        let sent = {
            let tx = self.inner.client_msg_tx.lock().unwrap();
            if let Some(ref sender) = *tx {
                sender.send(msg).is_ok()
            } else {
                false
            }
        };

        if !sent {
            return Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some("No active connection to send DETACH".to_string()),
                href: None,
            });
        }

        // Wait for DETACHED or ERROR
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            self.inner.detach_waiters.lock().unwrap().push(tx);
        }

        match rx.await {
            Ok(result) => result,
            Err(_) => Err(ErrorInfo {
                code: Some(90001),
                status_code: None,
                message: Some("Detach waiter dropped".to_string()),
                href: None,
            }),
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
            self.attach().await?;
        }

        Ok(())
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
            }
            Action::Detached => {
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
            _ => {
                // Other channel messages (MESSAGE, PRESENCE, etc.) — Phase 8c
            }
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

struct ChannelsInner {
    channels: Mutex<HashMap<String, Arc<RealtimeChannel>>>,
    /// Current client message sender (shared with new channels on creation).
    current_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>>,
}

impl Channels {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ChannelsInner {
                channels: Mutex::new(HashMap::new()),
                current_tx: Mutex::new(None),
            }),
        }
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
                // Assign current client_msg_tx if connection is active
                let tx = self.inner.current_tx.lock().unwrap().clone();
                ch.set_client_msg_tx(tx);
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
            // Assign current client_msg_tx if connection is active
            let tx = self.inner.current_tx.lock().unwrap().clone();
            channel.set_client_msg_tx(tx);
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
}

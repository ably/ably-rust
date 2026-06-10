use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::crypto::CipherParams;
use crate::error::{ErrorInfo, Result};
use crate::http::{PaginatedRequestBuilder, PaginatedResult};
use crate::protocol::{
    ChannelEvent, ChannelMode, ChannelState, ChannelStateChange,
};
use crate::rest::{
    Annotation, Message, MessageOperation, PresenceAction, PresenceMessage,
    UpdateDeleteResult,
};

// --- Channels collection ---

use crate::connection::{ChannelOptionsSpec, ChannelSnapshot, Command, LoopInput};
use tokio::sync::{oneshot, watch};

/// RTS1: the realtime channels collection. The registry Mutex holds HANDLE
/// objects only — all channel protocol state lives in the connection loop
/// (DESIGN.md §1: this is the one sanctioned realtime lock).
pub struct Channels {
    registry: std::sync::Mutex<HashMap<String, Arc<RealtimeChannel>>>,
    input_tx: mpsc::UnboundedSender<LoopInput>,
}

impl Channels {
    pub(crate) fn new(input_tx: mpsc::UnboundedSender<LoopInput>) -> Self {
        Self {
            registry: Default::default(),
            input_tx,
        }
    }

    /// RTS3a: get-or-create a channel. Repeated gets return the same instance.
    pub fn get(&self, name: &str) -> Arc<RealtimeChannel> {
        self.get_with_options(name, RealtimeChannelOptions::default())
    }

    /// RTS3c: get with options (applied only on first creation here; use
    /// set_options to change an existing channel's options).
    pub fn get_with_options(
        &self,
        name: &str,
        options: RealtimeChannelOptions,
    ) -> Arc<RealtimeChannel> {
        let mut registry = self.registry.lock().unwrap();
        if let Some(existing) = registry.get(name) {
            return existing.clone();
        }
        let spec = ChannelOptionsSpec {
            params: options
                .params
                .clone()
                .map(|m| m.into_iter().collect())
                .unwrap_or_default(),
            modes: options.modes.clone().unwrap_or_default(),
        };
        let (snapshot_tx, snapshot_rx) = watch::channel(ChannelSnapshot::default());
        let (events_tx, _) = broadcast::channel(64);
        let _ = self.input_tx.send(LoopInput::Cmd(Command::EnsureChannel {
            name: name.to_string(),
            options: spec,
            snapshot_tx,
            events_tx: events_tx.clone(),
        }));
        let channel = Arc::new(RealtimeChannel {
            name: name.to_string(),
            options,
            input_tx: self.input_tx.clone(),
            snapshot_rx,
            events_tx,
        });
        registry.insert(name.to_string(), channel.clone());
        channel
    }

    pub fn get_derived(&self, _name: &str, _derive: DeriveOptions) -> Arc<RealtimeChannel> {
        todo!("derived channels arrive in a later stage")
    }

    /// RTS2: whether a channel instance exists in the collection.
    pub fn exists(&self, name: &str) -> bool {
        self.registry.lock().unwrap().contains_key(name)
    }

    /// RTS2: the names of all channel instances.
    pub fn names(&self) -> Vec<String> {
        self.registry.lock().unwrap().keys().cloned().collect()
    }

    /// RTS4a: detach (if needed) and remove the channel.
    pub async fn release(&self, name: &str) {
        let (reply, rx) = oneshot::channel();
        let _ = self.input_tx.send(LoopInput::Cmd(Command::ReleaseChannel {
            name: name.to_string(),
            reply,
        }));
        let _ = rx.await;
        self.registry.lock().unwrap().remove(name);
    }
}

// --- Channel options ---

#[derive(Clone, Debug, Default)]
pub struct RealtimeChannelOptions {
    pub params: Option<HashMap<String, String>>,
    pub modes: Option<Vec<ChannelMode>>,
    pub cipher: Option<CipherParams>,
    pub attach_on_subscribe: Option<bool>,
}

impl RealtimeChannelOptions {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct DeriveOptions {
    filter: String,
}

impl DeriveOptions {
    pub fn new(filter: &str) -> Self {
        Self {
            filter: filter.to_string(),
        }
    }
}

// --- Subscription ---

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub(crate) u64);

// --- RealtimeChannel ---

/// The channel handle: snapshot reads, event subscription, and commands.
/// Holds no protocol state (DESIGN.md §4).
pub struct RealtimeChannel {
    pub(crate) name: String,
    pub(crate) options: RealtimeChannelOptions,
    pub(crate) input_tx: mpsc::UnboundedSender<LoopInput>,
    pub(crate) snapshot_rx: watch::Receiver<ChannelSnapshot>,
    pub(crate) events_tx: broadcast::Sender<ChannelStateChange>,
}

impl RealtimeChannel {
    /// TEST-ONLY: a detached handle with no connection loop behind it.
    /// Ported tests using this pattern cannot be expressed against the
    /// design (channels exist only within a client) and are rewritten from
    /// the UTS in their stages (DESIGN.md Realtime §12); until then this
    /// keeps them compiling as failing stubs.
    #[cfg(test)]
    pub(crate) fn new(name: &str) -> Self {
        let (_input_tx, _input_rx) = mpsc::unbounded_channel();
        let (_snapshot_tx, snapshot_rx) = watch::channel(ChannelSnapshot::default());
        let (events_tx, _) = broadcast::channel(8);
        Self {
            name: name.to_string(),
            options: RealtimeChannelOptions::default(),
            input_tx: _input_tx,
            snapshot_rx,
            events_tx,
        }
    }

    fn snapshot(&self) -> ChannelSnapshot {
        self.snapshot_rx.borrow().clone()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// RTL2b: the current channel state.
    pub fn state(&self) -> ChannelState {
        self.snapshot().state
    }

    /// RTL24-shaped: the last error that affected this channel.
    pub fn error_reason(&self) -> Option<ErrorInfo> {
        self.snapshot().error_reason
    }

    pub fn options(&self) -> RealtimeChannelOptions {
        self.options.clone()
    }

    /// RTL4m: the modes granted by the server on attach.
    pub fn modes(&self) -> Option<Vec<ChannelMode>> {
        self.snapshot().modes
    }

    pub fn channel_serial(&self) -> Option<String> {
        self.snapshot().channel_serial
    }

    pub fn attach_serial(&self) -> Option<String> {
        self.snapshot().attach_serial
    }

    /// RTL4: attach this channel; resolves when the server confirms.
    pub async fn attach(&self) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::Attach {
                name: self.name.clone(),
                reply,
            }))
            .map_err(|_| closed_loop_error())?;
        rx.await.map_err(|_| closed_loop_error())?
    }

    /// RTL5: detach this channel; resolves when the server confirms.
    pub async fn detach(&self) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::Detach {
                name: self.name.clone(),
                reply,
            }))
            .map_err(|_| closed_loop_error())?;
        rx.await.map_err(|_| closed_loop_error())?
    }

    pub async fn set_options(&self, _options: RealtimeChannelOptions) -> Result<()> {
        todo!("set_options arrives with RTL16 in stage 5.6")
    }

    /// RTL2a: subscribe to channel state changes.
    pub fn on_state_change(&self) -> broadcast::Receiver<ChannelStateChange> {
        self.events_tx.subscribe()
    }

    /// Invoke `callback` once when the channel is (or next becomes) `target`.
    pub fn when_state(
        &self,
        target: ChannelState,
        callback: impl FnOnce(ChannelStateChange) + Send + 'static,
    ) {
        let mut events = self.events_tx.subscribe();
        let current = self.snapshot();
        if current.state == target {
            callback(ChannelStateChange {
                previous: current.state,
                current: current.state,
                event: channel_state_to_event(current.state),
                reason: current.error_reason,
                resumed: false,
                has_backlog: false,
            });
            return;
        }
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(change) if change.current == target => {
                        callback(change);
                        return;
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    pub fn publish(&self) -> RealtimePublishBuilder<'_> {
        RealtimePublishBuilder { channel: self }
    }

    pub async fn publish_message(
        &self,
        _name: Option<&str>,
        _data: Option<serde_json::Value>,
    ) -> Result<()> {
        todo!()
    }

    pub fn subscribe(&self) -> (SubscriptionId, mpsc::Receiver<Message>) { todo!() }
    pub fn subscribe_with_name(&self, _name: &str) -> (SubscriptionId, mpsc::Receiver<Message>) { todo!() }
    pub fn unsubscribe(&self, _id: SubscriptionId) { todo!() }
    pub fn unsubscribe_with_name(&self, _name: &str, _id: SubscriptionId) { todo!() }
    pub fn unsubscribe_all(&self) { todo!() }

    pub fn annotations(&self) -> RealtimeAnnotations<'_> { RealtimeAnnotations { channel: self } }

    pub fn presence(&self) -> RealtimePresence { todo!() }
    pub async fn history(&self, _until_attach: bool) -> Result<PaginatedResult<Message>> { todo!() }
    pub async fn get_message(&self, _serial: &str) -> Result<Message> { todo!() }
    pub fn message_versions(&self, _serial: &str) -> PaginatedRequestBuilder<'_, Message> { todo!() }
    pub async fn update_message(
        &self,
        _msg: &Message,
        _op: &MessageOperation,
        _params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> { todo!() }
    pub async fn delete_message(
        &self,
        _msg: &Message,
        _op: &MessageOperation,
        _params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> { todo!() }
    pub async fn append_message(
        &self,
        _msg: &Message,
        _params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> { todo!() }
}

// --- RealtimePublishBuilder ---

pub struct RealtimePublishBuilder<'a> {
    channel: &'a RealtimeChannel,
}

impl<'a> RealtimePublishBuilder<'a> {
    pub fn name(self, _name: impl Into<String>) -> Self { self }
    pub fn string(self, _data: impl Into<String>) -> Self { self }
    pub fn json(self, _data: impl Serialize) -> Self { self }
    pub fn binary(self, _data: Vec<u8>) -> Self { self }
    pub fn id(self, _id: impl Into<String>) -> Self { self }
    pub fn client_id(self, _client_id: impl Into<String>) -> Self { self }
    pub fn extras(self, _extras: serde_json::Value) -> Self { self }
    pub async fn send(self) -> Result<()> { todo!() }
}

// --- RealtimePresence ---

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PresenceSubscriptionId(pub(crate) u64);

#[derive(Clone, Debug, Default)]
pub struct PresenceGetOptions {
    pub wait_for_sync: bool,
    pub client_id: Option<String>,
    pub connection_id: Option<String>,
}

pub struct RealtimePresence {
    pub(crate) inner: Arc<RealtimePresenceInner>,
}

pub(crate) struct RealtimePresenceInner {
    // TEMPORARY (pre-design stub): ~21 ported presence tests poke these maps
    // directly. Per DESIGN.md Realtime §12 they are superseded by UTS-derived
    // tests in stage 5.7, at which point these fields are deleted — presence
    // state lives in the loop-owned PresenceCtx (§9). Whitelisted as temporary
    // in tests_design_conformance.rs; adding any further lock fails the build.
    pub(crate) presence_map: std::sync::Mutex<crate::presence::PresenceMap>,
    pub(crate) local_presence_map: std::sync::Mutex<crate::presence::LocalPresenceMap>,
}

impl RealtimePresence {
    pub fn sync_complete(&self) -> bool { todo!() }
    pub async fn get(&self) -> Result<Vec<PresenceMessage>> { todo!() }
    pub async fn get_with_options(&self, _options: &PresenceGetOptions) -> Result<Vec<PresenceMessage>> { todo!() }
    pub async fn history(&self) -> Result<PaginatedResult<PresenceMessage>> { todo!() }

    pub fn subscribe(
        &self,
        _callback: impl Fn(PresenceMessage) + Send + Sync + 'static,
    ) -> PresenceSubscriptionId { todo!() }
    pub fn subscribe_action(
        &self,
        _action: PresenceAction,
        _callback: impl Fn(PresenceMessage) + Send + Sync + 'static,
    ) -> PresenceSubscriptionId { todo!() }
    pub fn subscribe_actions(
        &self,
        _actions: &[PresenceAction],
        _callback: impl Fn(PresenceMessage) + Send + Sync + 'static,
    ) -> PresenceSubscriptionId { todo!() }
    pub fn unsubscribe(&self, _id: PresenceSubscriptionId) { todo!() }
    pub fn unsubscribe_action(&self, _id: PresenceSubscriptionId, _action: PresenceAction) { todo!() }
    pub fn unsubscribe_all(&self) { todo!() }

    pub async fn enter(&self, _data: Option<serde_json::Value>) -> Result<()> { todo!() }
    pub async fn update(&self, _data: Option<serde_json::Value>) -> Result<()> { todo!() }
    pub async fn leave(&self, _data: Option<serde_json::Value>) -> Result<()> { todo!() }
    pub async fn enter_client(&self, _client_id: &str, _data: Option<serde_json::Value>) -> Result<()> { todo!() }
    pub async fn update_client(&self, _client_id: &str, _data: Option<serde_json::Value>) -> Result<()> { todo!() }
    pub async fn leave_client(&self, _client_id: &str, _data: Option<serde_json::Value>) -> Result<()> { todo!() }
}

// --- RealtimeAnnotations ---

pub struct RealtimeAnnotations<'a> {
    channel: &'a RealtimeChannel,
}

impl<'a> RealtimeAnnotations<'a> {
    pub async fn publish(&self, _msg_serial: &str, _annotation: &Annotation) -> Result<()> { todo!() }
    pub async fn delete(&self, _msg_serial: &str, _annotation: &Annotation) -> Result<()> { todo!() }
    pub async fn get(&self, _msg_serial: &str) -> Result<PaginatedResult<Annotation>> { todo!() }
    pub fn subscribe(
        &self,
        _callback: impl Fn(Annotation) + Send + Sync + 'static,
    ) -> SubscriptionId { todo!() }
    pub fn subscribe_with_type(
        &self,
        _type_filter: &str,
        _callback: impl Fn(Annotation) + Send + Sync + 'static,
    ) -> SubscriptionId { todo!() }
    pub fn unsubscribe(&self, _id: SubscriptionId) { todo!() }
    pub fn unsubscribe_all(&self) { todo!() }
}

fn closed_loop_error() -> ErrorInfo {
    ErrorInfo::new(
        crate::error::ErrorCode::ConnectionClosed.code(),
        "Connection loop has terminated",
    )
}

pub(crate) fn channel_state_to_event(state: ChannelState) -> ChannelEvent {
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

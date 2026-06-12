use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::{broadcast, mpsc};

use crate::crypto::CipherParams;
use crate::error::{ErrorInfo, Result};
use crate::http::PaginatedResult;
use crate::protocol::{ChannelEvent, ChannelMode, ChannelState, ChannelStateChange};
use crate::rest::{
    Annotation, Message, MessageOperation, PresenceAction, PresenceMessage, UpdateDeleteResult,
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
    rest: crate::rest::Rest,
}

impl Channels {
    pub(crate) fn new(input_tx: mpsc::UnboundedSender<LoopInput>, rest: crate::rest::Rest) -> Self {
        Self {
            registry: Default::default(),
            input_tx,
            rest,
        }
    }

    /// RTS3a: get-or-create a channel. Repeated gets return the same
    /// instance; a bare get never modifies an existing channel's options.
    pub fn get(&self, name: &str) -> Arc<RealtimeChannel> {
        if let Some(existing) = self.registry.lock().unwrap().get(name) {
            return existing.clone();
        }
        self.create(name, RealtimeChannelOptions::default())
    }

    /// RTS3c: get with options. Creates the channel with them, or updates an
    /// existing channel's options — unless the change would force a
    /// reattachment (params/modes changed while ATTACHING/ATTACHED), which is
    /// an error (RTS3c1). Use set_options (RTL16) to change options WITH a
    /// reattach.
    pub fn get_with_options(
        &self,
        name: &str,
        options: RealtimeChannelOptions,
    ) -> Result<Arc<RealtimeChannel>> {
        let existing = self.registry.lock().unwrap().get(name).cloned();
        let Some(existing) = existing else {
            return Ok(self.create(name, options));
        };
        let new_spec = options_spec(&options);
        let snapshot = existing.snapshot();
        if snapshot.options.reattach_needed(&new_spec)
            && matches!(
                snapshot.state,
                ChannelState::Attaching | ChannelState::Attached
            )
        {
            // RTS3c1
            return Err(ErrorInfo::new(
                crate::error::ErrorCode::BadRequest.code(),
                "Channel options would trigger a reattachment; use set_options",
            ));
        }
        // RTS3c: safe update, applied by the loop
        let (reply, _rx) = oneshot::channel();
        let _ = self.input_tx.send(LoopInput::Cmd(Command::SetOptions {
            name: name.to_string(),
            options: new_spec,
            reply,
        }));
        Ok(existing)
    }

    fn create(&self, name: &str, options: RealtimeChannelOptions) -> Arc<RealtimeChannel> {
        let mut registry = self.registry.lock().unwrap();
        if let Some(existing) = registry.get(name) {
            return existing.clone();
        }
        let spec = options_spec(&options);
        let (snapshot_tx, snapshot_rx) = watch::channel(ChannelSnapshot {
            options: spec.clone(),
            ..Default::default()
        });
        let (events_tx, _) = broadcast::channel(64);
        let _ = self.input_tx.send(LoopInput::Cmd(Command::EnsureChannel {
            name: name.to_string(),
            options: spec,
            snapshot_tx,
            events_tx: events_tx.clone(),
        }));
        let channel = Arc::new(RealtimeChannel {
            name: name.to_string(),
            input_tx: self.input_tx.clone(),
            snapshot_rx,
            events_tx,
            rest: self.rest.clone(),
        });
        registry.insert(name.to_string(), channel.clone());
        channel
    }

    /// RTS5a: a derived (filtered) channel — the filter expression travels
    /// base64-encoded in the qualified channel name.
    pub fn get_derived(&self, name: &str, derive: DeriveOptions) -> Arc<RealtimeChannel> {
        self.get_derived_with_options(name, derive, RealtimeChannelOptions::default())
            .expect("derived channel creation cannot conflict")
    }

    /// RTS5: derived channel with channel options; RTS5a2: channel params
    /// join the qualifier.
    pub fn get_derived_with_options(
        &self,
        name: &str,
        derive: DeriveOptions,
        options: RealtimeChannelOptions,
    ) -> Result<Arc<RealtimeChannel>> {
        let encoded = base64::encode(derive.filter.as_bytes());
        let mut qualifier = format!("filter={}", encoded);
        if let Some(params) = &options.params {
            if !params.is_empty() {
                let mut kv: Vec<_> = params.iter().collect();
                kv.sort();
                let query: Vec<String> = kv
                    .into_iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect();
                qualifier.push('?');
                qualifier.push_str(&query.join("&"));
            }
        }
        let qualified = format!("[{}]{}", qualifier, name);
        self.get_with_options(&qualified, options)
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

/// RTL22/MFI2: a client-side message filter for subscribe.
#[derive(Clone, Debug, Default)]
pub struct MessageFilter {
    /// MFI2c: match on message name.
    pub name: Option<String>,
    /// MFI2e: match on clientId.
    pub client_id: Option<String>,
    /// MFI2b: whether the message must (true) or must not (false) be a
    /// reference to another message (extras.ref present).
    pub is_ref: Option<bool>,
    /// MFI2d: match on extras.ref.type.
    pub ref_type: Option<String>,
    /// MFI2a: match on extras.ref.timeserial.
    pub ref_timeserial: Option<String>,
}

impl MessageFilter {
    pub(crate) fn matches(&self, msg: &Message) -> bool {
        let msg_ref = msg.extras.as_ref().and_then(|e| e.get("ref"));
        if let Some(name) = &self.name {
            if msg.name.as_deref() != Some(name.as_str()) {
                return false;
            }
        }
        if let Some(client_id) = &self.client_id {
            if msg.client_id.as_deref() != Some(client_id.as_str()) {
                return false;
            }
        }
        if let Some(is_ref) = self.is_ref {
            if msg_ref.is_some() != is_ref {
                return false;
            }
        }
        if let Some(ref_type) = &self.ref_type {
            if msg_ref.and_then(|r| r.get("type")).and_then(|v| v.as_str())
                != Some(ref_type.as_str())
            {
                return false;
            }
        }
        if let Some(ts) = &self.ref_timeserial {
            if msg_ref
                .and_then(|r| r.get("timeserial"))
                .and_then(|v| v.as_str())
                != Some(ts.as_str())
            {
                return false;
            }
        }
        true
    }
}

// --- RealtimeChannel ---

/// The channel handle: snapshot reads, event subscription, and commands.
/// Holds no protocol state (DESIGN.md §4).
pub struct RealtimeChannel {
    pub(crate) name: String,
    pub(crate) input_tx: mpsc::UnboundedSender<LoopInput>,
    pub(crate) snapshot_rx: watch::Receiver<ChannelSnapshot>,
    pub(crate) events_tx: broadcast::Sender<ChannelStateChange>,
    /// RTL10/RTL28/RTL31/RTL32: REST operations on this channel.
    pub(crate) rest: crate::rest::Rest,
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
            input_tx: _input_tx,
            snapshot_rx,
            events_tx,
            rest: crate::options::ClientOptions::new("appId.keyId:keySecret")
                .rest()
                .unwrap(),
        }
    }

    /// The REST view of this channel (shared auth/options/cipher).
    fn rest_channel(&self) -> crate::rest::Channel<'_> {
        let builder = self.rest.channels().name(self.name.clone());
        match self.snapshot().options.cipher {
            Some(c) => builder.cipher(c).get(),
            None => builder.get(),
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

    /// RTS3c/RTL16: the authoritative options, as held by the loop.
    pub fn options(&self) -> RealtimeChannelOptions {
        let spec = self.snapshot().options;
        RealtimeChannelOptions {
            params: if spec.params.is_empty() {
                None
            } else {
                Some(spec.params.into_iter().collect())
            },
            modes: if spec.modes.is_empty() {
                None
            } else {
                Some(spec.modes)
            },
            cipher: spec.cipher,
            attach_on_subscribe: Some(spec.attach_on_subscribe),
        }
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

    /// RTL16: set/update the channel options; RTL16a: reattaches (and waits
    /// for the reattach) when the change requires it.
    pub async fn set_options(&self, options: RealtimeChannelOptions) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::SetOptions {
                name: self.name.clone(),
                options: options_spec(&options),
                reply,
            }))
            .map_err(|_| closed_loop_error())?;
        rx.await.map_err(|_| closed_loop_error())?
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
                retry_in: None,
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
        RealtimePublishBuilder {
            channel: self,
            message: Message::default(),
            messages: None,
        }
    }

    /// RTL6i1: publish a single name/data message.
    pub async fn publish_message(
        &self,
        name: Option<&str>,
        data: Option<serde_json::Value>,
    ) -> Result<crate::rest::PublishResult> {
        let msg = Message {
            name: name.map(|n| n.to_string()),
            data: match data {
                None => crate::rest::Data::None,
                Some(serde_json::Value::String(st)) => crate::rest::Data::String(st),
                Some(v) => crate::rest::Data::JSON(v),
            },
            ..Default::default()
        };
        self.publish_messages(vec![msg]).await
    }

    /// RTL6: send messages through the connection loop; resolves on ACK/NACK.
    pub(crate) async fn publish_messages(
        &self,
        messages: Vec<Message>,
    ) -> Result<crate::rest::PublishResult> {
        self.publish_messages_with_params(messages, None).await
    }

    pub(crate) async fn publish_messages_with_params(
        &self,
        messages: Vec<Message>,
        params: Option<serde_json::Value>,
    ) -> Result<crate::rest::PublishResult> {
        let (reply, rx) = oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::Publish {
                name: self.name.clone(),
                messages,
                params,
                reply,
            }))
            .map_err(|_| closed_loop_error())?;
        rx.await.map_err(|_| closed_loop_error())?
    }

    /// RTL32: send a message mutation over the realtime connection — a
    /// MESSAGE ProtocolMessage with a single Message carrying the action
    /// (RTL32b1), version from the MessageOperation (RTL32b2), and optional
    /// pm-level params (RTL32e). Resolves via ACK with the version serial
    /// (RTL32d). The caller's message is never mutated (RTL32c).
    async fn send_message_mutation(
        &self,
        msg: &Message,
        mutation: crate::rest::MessageAction,
        op: Option<&MessageOperation>,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        // RTL32a: the target serial is required
        if msg.serial.as_deref().unwrap_or("").is_empty() {
            return Err(ErrorInfo::new(
                crate::error::ErrorCode::InvalidParameterValue.code(),
                "Message serial is required",
            ));
        }
        let mut wire = msg.clone();
        wire.action = Some(mutation);
        if let Some(op) = op {
            wire.version = Some(serde_json::to_value(op)?);
        }
        let pm_params = params.map(|kv| {
            serde_json::Value::Object(
                kv.iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                    .collect(),
            )
        });
        let result = self
            .publish_messages_with_params(vec![wire], pm_params)
            .await?;
        Ok(UpdateDeleteResult {
            serial: msg.serial.clone(),
            version_serial: result.serials.into_iter().next().flatten(),
        })
    }

    /// RTL7g: implicit attach on subscribe (unless attachOnSubscribe=false,
    /// RTL7h). Fire-and-forget: a failed implicit attach surfaces via channel
    /// state, never by unregistering the listener.
    fn maybe_implicit_attach(&self) {
        if self.snapshot().options.attach_on_subscribe {
            let (reply, _rx) = oneshot::channel();
            let _ = self.input_tx.send(LoopInput::Cmd(Command::Attach {
                name: self.name.clone(),
                reply,
            }));
        }
    }

    fn register_subscriber(
        &self,
        filter: crate::connection::SubscriberFilter,
    ) -> (SubscriptionId, mpsc::UnboundedReceiver<Message>) {
        let id: u64 = rand::random();
        let (sender, receiver) = mpsc::unbounded_channel();
        let _ = self.input_tx.send(LoopInput::Cmd(Command::Subscribe {
            name: self.name.clone(),
            id,
            filter,
            sender,
        }));
        self.maybe_implicit_attach();
        (SubscriptionId(id), receiver)
    }

    /// RTL7a: receive every message on the channel.
    pub fn subscribe(&self) -> (SubscriptionId, mpsc::UnboundedReceiver<Message>) {
        self.register_subscriber(crate::connection::SubscriberFilter::All)
    }

    /// RTL7b: receive only messages with this name.
    pub fn subscribe_with_name(
        &self,
        name: &str,
    ) -> (SubscriptionId, mpsc::UnboundedReceiver<Message>) {
        self.register_subscriber(crate::connection::SubscriberFilter::Name(name.to_string()))
    }

    /// RTL22: receive only messages matching the filter.
    pub fn subscribe_with_filter(
        &self,
        filter: MessageFilter,
    ) -> (SubscriptionId, mpsc::UnboundedReceiver<Message>) {
        self.register_subscriber(crate::connection::SubscriberFilter::Filter(filter))
    }

    /// RTL8a: remove this listener everywhere on the channel.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        let _ = self.input_tx.send(LoopInput::Cmd(Command::Unsubscribe {
            name: self.name.clone(),
            spec: crate::connection::UnsubscribeSpec::Id(id.0),
        }));
    }

    /// RTL8b: remove only this listener's name-specific registration.
    pub fn unsubscribe_with_name(&self, name: &str, id: SubscriptionId) {
        let _ = self.input_tx.send(LoopInput::Cmd(Command::Unsubscribe {
            name: self.name.clone(),
            spec: crate::connection::UnsubscribeSpec::NameAndId(name.to_string(), id.0),
        }));
    }

    /// RTL8c: remove every listener on the channel.
    pub fn unsubscribe_all(&self) {
        let _ = self.input_tx.send(LoopInput::Cmd(Command::Unsubscribe {
            name: self.name.clone(),
            spec: crate::connection::UnsubscribeSpec::All,
        }));
    }

    pub fn annotations(&self) -> RealtimeAnnotations<'_> {
        RealtimeAnnotations { channel: self }
    }

    /// RTL9: the channel's presence operations.
    pub fn presence(&self) -> RealtimePresence {
        RealtimePresence {
            name: self.name.clone(),
            input_tx: self.input_tx.clone(),
            snapshot_rx: self.snapshot_rx.clone(),
            rest: self.rest.clone(),
        }
    }
    /// RTL10: history via REST. RTL10b: untilAttach scopes the query to
    /// messages before the current attachment (requires ATTACHED).
    pub async fn history(&self, until_attach: bool) -> Result<PaginatedResult<Message>> {
        let rest_channel = self.rest_channel();
        let mut builder = rest_channel.history();
        if until_attach {
            // RTL10b: only meaningful relative to a live attachment
            if self.state() != ChannelState::Attached {
                return Err(ErrorInfo::new(
                    crate::error::ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                    "untilAttach requires the channel to be attached",
                ));
            }
            let serial = self.attach_serial().ok_or_else(|| {
                ErrorInfo::new(
                    crate::error::ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                    "untilAttach requires an attachSerial",
                )
            })?;
            builder = builder.params(&[("fromSerial", serial.as_str())]);
        }
        builder.send().await
    }

    /// RTL28: identical to RestChannel::get_message.
    pub async fn get_message(&self, serial: &str) -> Result<Message> {
        self.rest_channel().get_message(serial).await
    }

    /// RTL31: identical to RestChannel::message_versions.
    pub async fn message_versions(&self, serial: &str) -> Result<PaginatedResult<Message>> {
        self.rest_channel().message_versions(serial).send().await
    }

    /// RTL32b1: update a message over the realtime connection.
    pub async fn update_message(
        &self,
        msg: &Message,
        op: &MessageOperation,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        self.send_message_mutation(msg, crate::rest::MessageAction::Update, Some(op), params)
            .await
    }

    /// RTL32b1: delete a message over the realtime connection.
    pub async fn delete_message(
        &self,
        msg: &Message,
        op: &MessageOperation,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        self.send_message_mutation(msg, crate::rest::MessageAction::Delete, Some(op), params)
            .await
    }

    /// RTL32b1: append to a message over the realtime connection.
    pub async fn append_message(
        &self,
        msg: &Message,
        params: Option<&[(&str, &str)]>,
    ) -> Result<UpdateDeleteResult> {
        self.send_message_mutation(msg, crate::rest::MessageAction::Append, None, params)
            .await
    }
}

// --- RealtimePublishBuilder ---

pub struct RealtimePublishBuilder<'a> {
    channel: &'a RealtimeChannel,
    message: Message,
    messages: Option<Vec<Message>>,
}

impl<'a> RealtimePublishBuilder<'a> {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.message.name = Some(name.into());
        self
    }
    pub fn string(mut self, data: impl Into<String>) -> Self {
        self.message.data = crate::rest::Data::String(data.into());
        self
    }
    pub fn json(mut self, data: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(data) {
            self.message.data = crate::rest::Data::JSON(v);
        }
        self
    }
    pub fn binary(mut self, data: Vec<u8>) -> Self {
        self.message.data = crate::rest::Data::Binary(serde_bytes::ByteBuf::from(data));
        self
    }
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.message.id = Some(id.into());
        self
    }
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.message.client_id = Some(client_id.into());
        self
    }
    pub fn extras(mut self, extras: serde_json::Value) -> Self {
        self.message.extras = Some(extras);
        self
    }
    /// RTL6i2: publish an array of Message objects (replaces the single
    /// message being built).
    pub fn messages(mut self, messages: Vec<Message>) -> Self {
        self.messages = Some(messages);
        self
    }
    /// RTL6i1: publish one prebuilt Message object.
    pub fn message(mut self, message: Message) -> Self {
        self.message = message;
        self
    }
    /// RTL6j: resolves with the PublishResult from the ACK.
    pub async fn send(self) -> Result<crate::rest::PublishResult> {
        let messages = self.messages.unwrap_or_else(|| vec![self.message]);
        self.channel.publish_messages(messages).await
    }
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

/// RTL9: the presence handle — thin like every other handle; all presence
/// state lives in the loop's PresenceCtx (DESIGN.md §9).
pub struct RealtimePresence {
    pub(crate) name: String,
    pub(crate) input_tx: mpsc::UnboundedSender<LoopInput>,
    pub(crate) snapshot_rx: watch::Receiver<ChannelSnapshot>,
    pub(crate) rest: crate::rest::Rest,
}

impl RealtimePresence {
    /// RTP13: whether the initial presence sync has completed.
    pub fn sync_complete(&self) -> bool {
        self.snapshot_rx.borrow().presence_sync_complete
    }

    fn maybe_implicit_attach(&self) {
        if self.snapshot_rx.borrow().options.attach_on_subscribe {
            let (reply, _rx) = oneshot::channel();
            let _ = self.input_tx.send(LoopInput::Cmd(Command::Attach {
                name: self.name.clone(),
                reply,
            }));
        }
    }

    /// RTP11: the current members (waits for the initial sync).
    pub async fn get(&self) -> Result<Vec<PresenceMessage>> {
        self.get_with_options(&PresenceGetOptions {
            wait_for_sync: true,
            ..Default::default()
        })
        .await
    }

    /// RTP11c: get with waitForSync/clientId/connectionId options.
    pub async fn get_with_options(
        &self,
        options: &PresenceGetOptions,
    ) -> Result<Vec<PresenceMessage>> {
        // RTP11b: get implicitly attaches
        self.maybe_implicit_attach();
        let (reply, rx) = oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::PresenceGet {
                name: self.name.clone(),
                wait_for_sync: options.wait_for_sync,
                client_id: options.client_id.clone(),
                connection_id: options.connection_id.clone(),
                reply,
            }))
            .map_err(|_| closed_loop_error())?;
        rx.await.map_err(|_| closed_loop_error())?
    }

    /// RTP12: presence history via REST.
    pub async fn history(&self) -> Result<PaginatedResult<PresenceMessage>> {
        self.rest
            .channels()
            .get(self.name.clone())
            .presence()
            .history()
            .send()
            .await
    }

    fn register(
        &self,
        actions: Option<Vec<PresenceAction>>,
        callback: impl Fn(PresenceMessage) + Send + Sync + 'static,
    ) -> PresenceSubscriptionId {
        let id: u64 = rand::random();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let _ = self
            .input_tx
            .send(LoopInput::Cmd(Command::PresenceSubscribe {
                name: self.name.clone(),
                id,
                actions,
                sender,
            }));
        // RTP6d: subscribe implicitly attaches (RTP6e: unless disabled)
        self.maybe_implicit_attach();
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                callback(msg);
            }
        });
        PresenceSubscriptionId(id)
    }

    /// RTP6a: subscribe to all presence events.
    pub fn subscribe(
        &self,
        callback: impl Fn(PresenceMessage) + Send + Sync + 'static,
    ) -> PresenceSubscriptionId {
        self.register(None, callback)
    }

    /// RTP6b: subscribe to one presence action.
    pub fn subscribe_action(
        &self,
        action: PresenceAction,
        callback: impl Fn(PresenceMessage) + Send + Sync + 'static,
    ) -> PresenceSubscriptionId {
        self.register(Some(vec![action]), callback)
    }

    /// RTP6b: subscribe to a set of presence actions.
    pub fn subscribe_actions(
        &self,
        actions: &[PresenceAction],
        callback: impl Fn(PresenceMessage) + Send + Sync + 'static,
    ) -> PresenceSubscriptionId {
        self.register(Some(actions.to_vec()), callback)
    }

    /// RTP7a: remove this listener.
    pub fn unsubscribe(&self, id: PresenceSubscriptionId) {
        let _ = self
            .input_tx
            .send(LoopInput::Cmd(Command::PresenceUnsubscribe {
                name: self.name.clone(),
                id: Some(id.0),
                action: None,
            }));
    }

    /// RTP7b: remove this listener's registration for one action.
    pub fn unsubscribe_action(&self, id: PresenceSubscriptionId, action: PresenceAction) {
        let _ = self
            .input_tx
            .send(LoopInput::Cmd(Command::PresenceUnsubscribe {
                name: self.name.clone(),
                id: Some(id.0),
                action: Some(action),
            }));
    }

    /// RTP7c: remove every presence listener.
    pub fn unsubscribe_all(&self) {
        let _ = self
            .input_tx
            .send(LoopInput::Cmd(Command::PresenceUnsubscribe {
                name: self.name.clone(),
                id: None,
                action: None,
            }));
    }

    /// RTP8j/RTP14/RTP15f: resolve and validate the clientId for an op.
    fn op_client_id(&self, explicit: Option<&str>) -> Result<String> {
        let own = self.rest.auth().client_id();
        match explicit {
            // RTP8j: the wildcard is never a valid presence identity
            Some("*") => Err(ErrorInfo::with_status(
                crate::error::ErrorCode::UnableToEnterPresenceChannelNoClientID.code(),
                400,
                "The wildcard clientId cannot enter presence",
            )),
            Some(cid) => {
                // RTP15f: an explicit clientId must be compatible
                if let Some(own) = &own {
                    if own != "*" && own != cid {
                        return Err(ErrorInfo::with_status(
                            crate::error::ErrorCode::InvalidClientID.code(),
                            400,
                            "clientId is incompatible with the client's identity",
                        ));
                    }
                }
                Ok(cid.to_string())
            }
            None => match own.as_deref() {
                // RTP8j: an identified, non-wildcard clientId is required
                None | Some("*") => Err(ErrorInfo::with_status(
                    crate::error::ErrorCode::UnableToEnterPresenceChannelNoClientID.code(),
                    400,
                    "Presence operations require a clientId",
                )),
                Some(cid) => Ok(cid.to_string()),
            },
        }
    }

    async fn op(
        &self,
        action: PresenceAction,
        client_id: Option<&str>,
        data: Option<serde_json::Value>,
    ) -> Result<()> {
        let explicit = client_id.is_some();
        let resolved = self.op_client_id(client_id)?;
        let message = PresenceMessage {
            action: Some(action),
            // RTP8c: own-identity ops omit clientId on the wire (the server
            // applies the connection's identity); *_client variants carry it
            client_id: if explicit { Some(resolved) } else { None },
            data: match data {
                None => crate::rest::Data::None,
                Some(serde_json::Value::String(st)) => crate::rest::Data::String(st),
                Some(v) => crate::rest::Data::JSON(v),
            },
            ..Default::default()
        };
        let (reply, rx) = oneshot::channel();
        self.input_tx
            .send(LoopInput::Cmd(Command::PresenceOp {
                name: self.name.clone(),
                message,
                reply,
            }))
            .map_err(|_| closed_loop_error())?;
        rx.await.map_err(|_| closed_loop_error())?
    }

    /// RTP8: enter this client into presence.
    pub async fn enter(&self, data: Option<serde_json::Value>) -> Result<()> {
        self.op(PresenceAction::Enter, None, data).await
    }

    /// RTP9: update this client's presence data.
    pub async fn update(&self, data: Option<serde_json::Value>) -> Result<()> {
        self.op(PresenceAction::Update, None, data).await
    }

    /// RTP10: leave presence.
    pub async fn leave(&self, data: Option<serde_json::Value>) -> Result<()> {
        self.op(PresenceAction::Leave, None, data).await
    }

    /// RTP14/RTP15: enter on behalf of another clientId.
    pub async fn enter_client(
        &self,
        client_id: &str,
        data: Option<serde_json::Value>,
    ) -> Result<()> {
        self.op(PresenceAction::Enter, Some(client_id), data).await
    }

    /// RTP15: update on behalf of another clientId.
    pub async fn update_client(
        &self,
        client_id: &str,
        data: Option<serde_json::Value>,
    ) -> Result<()> {
        self.op(PresenceAction::Update, Some(client_id), data).await
    }

    /// RTP15: leave on behalf of another clientId.
    pub async fn leave_client(
        &self,
        client_id: &str,
        data: Option<serde_json::Value>,
    ) -> Result<()> {
        self.op(PresenceAction::Leave, Some(client_id), data).await
    }
}

// --- RealtimeAnnotations ---

pub struct RealtimeAnnotations<'a> {
    channel: &'a RealtimeChannel,
}

impl<'a> RealtimeAnnotations<'a> {
    /// RTAN1a: the annotation type is required.
    fn validated(
        &self,
        msg_serial: &str,
        annotation: &Annotation,
        action: crate::rest::AnnotationAction,
    ) -> Result<Annotation> {
        if annotation
            .annotation_type
            .as_deref()
            .unwrap_or("")
            .is_empty()
        {
            return Err(ErrorInfo::with_status(
                crate::error::ErrorCode::InvalidParameterValue.code(),
                400,
                "Annotation type is required",
            ));
        }
        let mut wire = annotation.clone();
        wire.action = Some(action);
        // RSAN1c2/TAN2j: the target message serial
        wire.message_serial = Some(msg_serial.to_string());
        Ok(wire)
    }

    async fn op(&self, annotation: Annotation) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.channel
            .input_tx
            .send(LoopInput::Cmd(Command::AnnotationOp {
                name: self.channel.name.clone(),
                annotation,
                reply,
            }))
            .map_err(|_| closed_loop_error())?;
        rx.await.map_err(|_| closed_loop_error())?
    }

    /// RTAN1: publish an annotation (ANNOTATION_CREATE) for a message.
    pub async fn publish(&self, msg_serial: &str, annotation: &Annotation) -> Result<()> {
        let wire = self.validated(
            msg_serial,
            annotation,
            crate::rest::AnnotationAction::Create,
        )?;
        self.op(wire).await
    }

    /// RTAN2: delete an annotation (ANNOTATION_DELETE).
    pub async fn delete(&self, msg_serial: &str, annotation: &Annotation) -> Result<()> {
        let wire = self.validated(
            msg_serial,
            annotation,
            crate::rest::AnnotationAction::Delete,
        )?;
        self.op(wire).await
    }

    /// RTAN3-shaped: read annotations via REST.
    pub async fn get(&self, msg_serial: &str) -> Result<PaginatedResult<Annotation>> {
        self.channel
            .rest
            .channels()
            .get(self.channel.name.clone())
            .annotations()
            .get(msg_serial)
            .send()
            .await
    }

    fn register(
        &self,
        type_filter: Option<String>,
        callback: impl Fn(Annotation) + Send + Sync + 'static,
    ) -> SubscriptionId {
        let id: u64 = rand::random();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let _ = self
            .channel
            .input_tx
            .send(LoopInput::Cmd(Command::AnnotationSubscribe {
                name: self.channel.name.clone(),
                id,
                type_filter,
                sender,
            }));
        // RTAN4e: warn when subscribing on a channel attached without the
        // ANNOTATION_SUBSCRIBE mode; RTAN4e1: silent when not yet attached
        let snapshot = self.channel.snapshot();
        if snapshot.state == ChannelState::Attached {
            let has_mode = snapshot
                .modes
                .as_ref()
                .map(|m| m.contains(&crate::protocol::ChannelMode::AnnotationSubscribe))
                .unwrap_or(false);
            if !has_mode {
                self.channel.rest.inner.opts.log(
                    crate::options::LogLevel::Major,
                    "Warning: subscribing to annotations on a channel attached without the ANNOTATION_SUBSCRIBE mode; no annotations will be delivered",
                );
            }
        }
        // RTAN4d: implicit attach per attachOnSubscribe
        self.channel.maybe_implicit_attach();
        tokio::spawn(async move {
            while let Some(ann) = receiver.recv().await {
                callback(ann);
            }
        });
        SubscriptionId(id)
    }

    /// RTAN4a: subscribe to all annotations.
    pub fn subscribe(
        &self,
        callback: impl Fn(Annotation) + Send + Sync + 'static,
    ) -> SubscriptionId {
        self.register(None, callback)
    }

    /// RTAN4c: subscribe to one annotation type.
    pub fn subscribe_with_type(
        &self,
        type_filter: &str,
        callback: impl Fn(Annotation) + Send + Sync + 'static,
    ) -> SubscriptionId {
        self.register(Some(type_filter.to_string()), callback)
    }

    /// RTAN5a: remove this listener.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        let _ = self
            .channel
            .input_tx
            .send(LoopInput::Cmd(Command::AnnotationUnsubscribe {
                name: self.channel.name.clone(),
                id: Some(id.0),
            }));
    }

    /// RTAN5: remove every annotation listener.
    pub fn unsubscribe_all(&self) {
        let _ = self
            .channel
            .input_tx
            .send(LoopInput::Cmd(Command::AnnotationUnsubscribe {
                name: self.channel.name.clone(),
                id: None,
            }));
    }
}

pub(crate) fn options_spec(options: &RealtimeChannelOptions) -> ChannelOptionsSpec {
    let mut params: Vec<(String, String)> = options
        .params
        .clone()
        .map(|m| m.into_iter().collect())
        .unwrap_or_default();
    params.sort();
    ChannelOptionsSpec {
        params,
        modes: options.modes.clone().unwrap_or_default(),
        cipher: options.cipher.clone(),
        attach_on_subscribe: options.attach_on_subscribe.unwrap_or(true),
    }
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

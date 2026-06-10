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

pub struct Channels {}

impl Channels {
    pub fn get(&self, _name: &str) -> Arc<RealtimeChannel> {
        todo!()
    }

    pub fn get_with_options(
        &self,
        _name: &str,
        _options: RealtimeChannelOptions,
    ) -> Arc<RealtimeChannel> {
        todo!()
    }

    pub fn get_derived(&self, _name: &str, _derive: DeriveOptions) -> Arc<RealtimeChannel> {
        todo!()
    }

    pub fn exists(&self, _name: &str) -> bool {
        todo!()
    }

    pub fn names(&self) -> Vec<String> {
        todo!()
    }

    pub async fn release(&self, _name: &str) {
        todo!()
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

pub struct RealtimeChannel {
    pub(crate) inner: Arc<RealtimeChannelInner>,
}

pub(crate) struct RealtimeChannelInner {}

impl RealtimeChannel {
    pub(crate) fn new(_name: &str) -> Self {
        todo!()
    }

    pub fn name(&self) -> &str { todo!() }
    pub fn state(&self) -> ChannelState { todo!() }
    pub fn error_reason(&self) -> Option<ErrorInfo> { todo!() }
    pub fn options(&self) -> RealtimeChannelOptions { todo!() }
    pub fn modes(&self) -> Option<Vec<ChannelMode>> { todo!() }
    pub fn channel_serial(&self) -> Option<String> { todo!() }
    pub fn attach_serial(&self) -> Option<String> { todo!() }

    pub async fn attach(&self) -> Result<()> { todo!() }
    pub async fn detach(&self) -> Result<()> { todo!() }
    pub async fn set_options(&self, _options: RealtimeChannelOptions) -> Result<()> { todo!() }

    pub fn on_state_change(&self) -> broadcast::Receiver<ChannelStateChange> { todo!() }
    pub fn when_state(
        &self,
        _target: ChannelState,
        _callback: impl FnOnce(ChannelStateChange) + Send + 'static,
    ) {
        todo!()
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

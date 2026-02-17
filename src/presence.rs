use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use futures::stream::Stream;
use serde_json;

use crate::channel::{ChannelInner, ChannelsInner};
use crate::protocol::{
    self, flags, Action, ChannelState, ChannelStateChange, ConnectionState, ErrorInfo,
    ProtocolMessage,
};
use crate::rest::{self, PresenceAction, PresenceMessage, Rest};
use crate::{http, Result};

// ---------------------------------------------------------------------------
// Newness comparison (RTP2b)
// ---------------------------------------------------------------------------

/// Newness metadata extracted from a PresenceMessage id field.
/// Used to determine whether an incoming message supersedes the stored one.
#[derive(Debug, Clone, Default)]
pub struct Newness {
    pub msg_serial: Option<i64>,
    pub index: Option<u32>,
    pub timestamp: Option<u64>,
    /// Whether this is a "synthesized" message — one where the connectionId
    /// is NOT an initial substring of the id. RTP2b1.
    pub is_synthesized: bool,
}

impl Newness {
    /// Extract newness from a PresenceMessage.
    pub fn from_message(msg: &PresenceMessage) -> Self {
        let is_synthesized = is_synthesized_message(msg);
        if !is_synthesized {
            // RTP2b2: Parse id as "connectionId:msgSerial:index"
            if let Some(ref id) = msg.id {
                let parts: Vec<&str> = id.split(':').collect();
                if parts.len() >= 3 {
                    let msg_serial = parts[1].parse::<i64>().ok();
                    let index = parts[2].parse::<u32>().ok();
                    return Newness {
                        msg_serial,
                        index,
                        timestamp: msg.timestamp,
                        is_synthesized: false,
                    };
                }
            }
        }
        // Synthesized or unparseable: fall back to timestamp comparison (RTP2b1)
        Newness {
            msg_serial: None,
            index: None,
            timestamp: msg.timestamp,
            is_synthesized: true,
        }
    }

    /// Returns true if `self` (incoming) is newer than `existing`.
    /// RTP2b1a: Equal timestamps → incoming wins.
    pub fn is_newer_than(&self, existing: &Newness) -> bool {
        // If either side is synthesized, compare by timestamp (RTP2b1)
        if self.is_synthesized || existing.is_synthesized {
            match (self.timestamp, existing.timestamp) {
                (Some(a), Some(b)) => a >= b, // RTP2b1a: equal → incoming wins
                _ => true,
            }
        } else {
            // RTP2b2: Compare by msgSerial then index
            match (self.msg_serial, existing.msg_serial) {
                (Some(a), Some(b)) if a != b => return a > b,
                _ => {}
            }
            match (self.index, existing.index) {
                (Some(a), Some(b)) if a != b => return a > b,
                _ => {}
            }
            // Equal or incomparable → incoming wins (RTP2b1a analogy)
            true
        }
    }
}

/// Check whether a message is "synthesized" — where the connectionId is NOT
/// an initial substring of the id. RTP2b1.
pub fn is_synthesized_message(msg: &PresenceMessage) -> bool {
    match (&msg.connection_id, &msg.id) {
        (Some(conn_id), Some(id)) => !id.starts_with(conn_id),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// PresenceMap (RTP2)
// ---------------------------------------------------------------------------

/// An entry stored in the PresenceMap.
#[derive(Debug, Clone)]
struct PresenceEntry {
    /// The stored message (action set to PRESENT or ABSENT).
    message: PresenceMessage,
    /// Newness metadata for comparison.
    newness: Newness,
}

/// The internal presence map maintaining the current presence set. RTP2.
/// Keyed by memberKey (connectionId:clientId).
pub struct PresenceMap {
    members: HashMap<String, PresenceEntry>,
    sync_in_progress: bool,
    /// Member keys that existed before the current sync started.
    /// Used to detect stale members on endSync. RTP19.
    residuals: HashMap<String, ()>,
}

impl PresenceMap {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            sync_in_progress: false,
            residuals: HashMap::new(),
        }
    }

    /// Insert or update a member. RTP2a.
    ///
    /// Returns the message to emit to subscribers (with original action preserved),
    /// or None if the incoming message is stale.
    ///
    /// During sync, the member is removed from the residuals set regardless of
    /// whether the newness check passes (RTP19 — "seen during sync"). RTP2b.
    pub fn put(&mut self, msg: PresenceMessage) -> Option<PresenceMessage> {
        let member_key = msg.member_key()?;
        let incoming_newness = Newness::from_message(&msg);

        // During sync, mark as seen (remove from residuals) BEFORE newness check.
        // This ensures stale SYNC messages still protect members from eviction. RTP19.
        if self.sync_in_progress {
            self.residuals.remove(&member_key);
        }

        // Check newness against existing entry
        if let Some(existing) = self.members.get(&member_key) {
            if !incoming_newness.is_newer_than(&existing.newness) {
                return None; // Stale — reject
            }
        }

        // RTP2d1: Preserve original action for emission
        let emitted = msg.clone();

        // RTP2d2: Store with action set to PRESENT
        let mut stored = msg;
        stored.action = PresenceAction::Present;

        self.members.insert(
            member_key,
            PresenceEntry {
                message: stored,
                newness: incoming_newness,
            },
        );

        Some(emitted)
    }

    /// Remove a member (LEAVE). RTP2h.
    ///
    /// Outside sync: removes and returns the LEAVE message to emit.
    /// During sync: stores as ABSENT (RTP2h2a), returns None.
    pub fn remove(&mut self, msg: PresenceMessage) -> Option<PresenceMessage> {
        let member_key = msg.member_key()?;
        let incoming_newness = Newness::from_message(&msg);

        // During sync, remove from residuals since we've seen this member
        if self.sync_in_progress {
            self.residuals.remove(&member_key);
        }

        // Check newness
        if let Some(existing) = self.members.get(&member_key) {
            if !incoming_newness.is_newer_than(&existing.newness) {
                return None; // Stale — reject
            }
        } else {
            // RTP2h1: No matching member → nothing to remove
            if !self.sync_in_progress {
                return None;
            }
        }

        if self.sync_in_progress {
            // RTP2h2a: Store as ABSENT during sync
            let mut absent = msg;
            absent.action = PresenceAction::Absent;
            self.members.insert(
                member_key,
                PresenceEntry {
                    message: absent,
                    newness: incoming_newness,
                },
            );
            None
        } else {
            // RTP2h1: Remove and emit LEAVE
            self.members.remove(&member_key);
            Some(msg)
        }
    }

    /// Get a member by memberKey.
    pub fn get(&self, member_key: &str) -> Option<&PresenceMessage> {
        self.members.get(member_key).map(|e| &e.message)
    }

    /// Return all PRESENT members (excludes ABSENT). RTP2.
    pub fn values(&self) -> Vec<PresenceMessage> {
        self.members
            .values()
            .filter(|e| e.message.action != PresenceAction::Absent)
            .map(|e| e.message.clone())
            .collect()
    }

    /// Clear all members and reset sync state.
    pub fn clear(&mut self) {
        self.members.clear();
        self.sync_in_progress = false;
        self.residuals.clear();
    }

    /// Start a new sync. RTP18a.
    /// Marks all current members as residuals. If a sync is already in progress,
    /// the previous sync is discarded (RTP18a).
    pub fn start_sync(&mut self) {
        self.residuals.clear();
        for key in self.members.keys() {
            self.residuals.insert(key.clone(), ());
        }
        self.sync_in_progress = true;
    }

    /// End the current sync. RTP18b, RTP19.
    /// Removes stale residual members (not seen during sync) and returns
    /// synthesized LEAVE events for each.
    /// Also removes ABSENT members (RTP2h2b).
    pub fn end_sync(&mut self) -> Vec<PresenceMessage> {
        if !self.sync_in_progress {
            return Vec::new();
        }

        let mut leave_events = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // RTP19: Remove stale residual members (PRESENT but not seen during sync)
        for (key, _) in self.residuals.drain() {
            if let Some(entry) = self.members.remove(&key) {
                if entry.message.action != PresenceAction::Absent {
                    let mut leave = entry.message;
                    leave.action = PresenceAction::Leave;
                    leave.id = None; // RTP19: id set to null
                    leave.timestamp = Some(now); // RTP19: current timestamp
                    leave_events.push(leave);
                }
            }
        }

        // RTP2h2b: Remove ABSENT members
        self.members
            .retain(|_, e| e.message.action != PresenceAction::Absent);

        self.sync_in_progress = false;
        leave_events
    }

    /// Whether a sync is currently in progress. RTP18.
    pub fn sync_in_progress(&self) -> bool {
        self.sync_in_progress
    }
}

// ---------------------------------------------------------------------------
// LocalPresenceMap (RTP17)
// ---------------------------------------------------------------------------

/// Tracks presence members entered by the current connection. RTP17.
/// Keyed by clientId only (not memberKey). Used for automatic re-entry
/// on channel reattach (RTP17i).
pub struct LocalPresenceMap {
    members: HashMap<String, PresenceMessage>,
}

impl LocalPresenceMap {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    /// Add or update a member. RTP17b.
    /// Stores ENTER, UPDATE, and PRESENT actions. Keyed by clientId (RTP17h).
    pub fn put(&mut self, msg: PresenceMessage) {
        if let Some(ref client_id) = msg.client_id {
            self.members.insert(client_id.clone(), msg);
        }
    }

    /// Remove a member on LEAVE. RTP17b.
    /// Returns true if removed, false if the LEAVE was synthesized (ignored).
    /// A synthesized LEAVE has connectionId NOT as a prefix of id.
    pub fn remove(&mut self, msg: &PresenceMessage) -> bool {
        // Check if this is a synthesized leave
        if is_synthesized_message(msg) {
            return false; // Ignore synthesized leaves
        }

        if let Some(ref client_id) = msg.client_id {
            self.members.remove(client_id);
        }
        true
    }

    /// Get a member by clientId.
    pub fn get(&self, client_id: &str) -> Option<&PresenceMessage> {
        self.members.get(client_id)
    }

    /// Return all locally-entered members.
    pub fn values(&self) -> Vec<PresenceMessage> {
        self.members.values().cloned().collect()
    }

    /// Clear all members.
    pub fn clear(&mut self) {
        self.members.clear();
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Sync cursor parsing (RTP18c)
// ---------------------------------------------------------------------------

/// Parse a channelSerial to determine if the sync is complete.
/// Format: "serial:cursor" — empty or absent cursor means sync complete.
pub fn is_sync_complete(channel_serial: &Option<String>) -> bool {
    match channel_serial {
        None => true,
        Some(s) => {
            if let Some(colon_pos) = s.find(':') {
                // Cursor is everything after the colon
                s[colon_pos + 1..].is_empty()
            } else {
                // No colon — single-message sync, complete
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RealtimePresence (RTP1)
// ---------------------------------------------------------------------------

/// Unique ID for a presence subscription listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PresenceSubscriptionId(u64);

/// A subscription entry for presence events.
struct PresenceSubscription {
    id: PresenceSubscriptionId,
    action_filter: Option<Vec<PresenceAction>>,
    tx: tokio::sync::mpsc::UnboundedSender<PresenceMessage>,
}

/// The public Realtime presence API on a channel. RTP1.
pub struct RealtimePresence {
    pub(crate) inner: Arc<PresenceInner>,
}

/// Internal state for Realtime presence. Shared via Arc.
pub(crate) struct PresenceInner {
    /// The presence map (server's view of all members). RTP2.
    pub(crate) presence_map: Mutex<PresenceMap>,

    /// Local members entered by this connection. RTP17.
    pub(crate) local_presence_map: Mutex<LocalPresenceMap>,

    /// Presence subscriptions. RTP6.
    subscriptions: Mutex<Vec<PresenceSubscription>>,

    /// Next subscription ID counter.
    next_sub_id: Mutex<u64>,

    /// Whether sync has completed at least once. RTP13.
    pub(crate) sync_complete: Mutex<bool>,

    /// Waiters for sync completion (for get()). RTP11.
    pub(crate) sync_waiters: Mutex<Vec<tokio::sync::oneshot::Sender<()>>>,

    /// Queued presence messages to send after attach. RTP16b.
    pub(crate) queued_presence: Mutex<
        Vec<(
            ProtocolMessage,
            tokio::sync::oneshot::Sender<std::result::Result<protocol::PublishResult, ErrorInfo>>,
        )>,
    >,

    /// Channel name.
    pub(crate) channel_name: String,

    /// The client's own client_id. RTP8, RTP9, RTP10.
    pub(crate) client_id: Mutex<Option<String>>,

    /// The client's connection_id (set after CONNECTED).
    pub(crate) connection_id: Mutex<Option<String>>,

    /// Back-reference to ChannelsInner for ACK/NACK coordination.
    pub(crate) channels_inner: Mutex<Option<Arc<ChannelsInner>>>,

    /// Client message sender (for sending PRESENCE protocol messages).
    pub(crate) client_msg_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>>,

    /// Channel state (updated by channel).
    pub(crate) channel_state: Mutex<ChannelState>,

    /// Connection state (updated by channel).
    pub(crate) connection_state: Mutex<ConnectionState>,

    /// Broadcast sender for channel state events (for emitting UPDATE on re-entry failure).
    pub(crate) channel_state_tx: Mutex<Option<tokio::sync::broadcast::Sender<ChannelStateChange>>>,

    /// REST client for history delegation. RTP12.
    pub(crate) rest_client: Mutex<Option<Rest>>,

    /// Weak reference to the owning ChannelInner for implicit attach. RTP8d/RTP15e/RTP6d/RTP11b.
    pub(crate) channel_inner: Mutex<Option<Weak<ChannelInner>>>,
}

impl PresenceInner {
    pub(crate) fn new(channel_name: String) -> Self {
        Self {
            presence_map: Mutex::new(PresenceMap::new()),
            local_presence_map: Mutex::new(LocalPresenceMap::new()),
            subscriptions: Mutex::new(Vec::new()),
            next_sub_id: Mutex::new(0),
            sync_complete: Mutex::new(false),
            sync_waiters: Mutex::new(Vec::new()),
            queued_presence: Mutex::new(Vec::new()),
            channel_name,
            client_id: Mutex::new(None),
            connection_id: Mutex::new(None),
            channels_inner: Mutex::new(None),
            client_msg_tx: Mutex::new(None),
            channel_state: Mutex::new(ChannelState::Initialized),
            connection_state: Mutex::new(ConnectionState::Initialized),
            channel_state_tx: Mutex::new(None),
            rest_client: Mutex::new(None),
            channel_inner: Mutex::new(None),
        }
    }

    /// Set client_id.
    pub(crate) fn set_client_id(&self, id: Option<String>) {
        *self.client_id.lock().unwrap() = id;
    }

    /// Set connection_id.
    pub(crate) fn set_connection_id(&self, id: Option<String>) {
        *self.connection_id.lock().unwrap() = id;
    }

    /// Set the client message sender.
    pub(crate) fn set_client_msg_tx(
        &self,
        tx: Option<tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>,
    ) {
        *self.client_msg_tx.lock().unwrap() = tx;
    }

    /// Set channels_inner for ACK/NACK.
    pub(crate) fn set_channels_inner(&self, ci: Arc<ChannelsInner>) {
        *self.channels_inner.lock().unwrap() = Some(ci);
    }

    /// Set channel state.
    pub(crate) fn set_channel_state(&self, state: ChannelState) {
        *self.channel_state.lock().unwrap() = state;
    }

    /// Set connection state.
    pub(crate) fn set_connection_state(&self, state: ConnectionState) {
        *self.connection_state.lock().unwrap() = state;
    }

    /// Set channel state broadcast sender.
    pub(crate) fn set_channel_state_tx(
        &self,
        tx: tokio::sync::broadcast::Sender<ChannelStateChange>,
    ) {
        *self.channel_state_tx.lock().unwrap() = Some(tx);
    }

    /// Set the REST client for history delegation. RTP12.
    pub(crate) fn set_rest_client(&self, rest: Rest) {
        *self.rest_client.lock().unwrap() = Some(rest);
    }

    /// Set weak reference to owning ChannelInner for implicit attach.
    pub(crate) fn set_channel_inner(&self, inner: Weak<ChannelInner>) {
        *self.channel_inner.lock().unwrap() = Some(inner);
    }

    /// Emit a presence message to matching subscribers.
    fn emit_to_subscribers(&self, msg: &PresenceMessage) {
        let subs = self.subscriptions.lock().unwrap();
        for sub in subs.iter() {
            let matches = match &sub.action_filter {
                None => true,
                Some(actions) => actions.contains(&msg.action),
            };
            if matches {
                let _ = sub.tx.send(msg.clone());
            }
        }
    }

    /// Send a protocol message via client_msg_tx. Returns true if sent.
    fn send_message(&self, msg: ProtocolMessage) -> bool {
        let tx = self.client_msg_tx.lock().unwrap();
        if let Some(ref sender) = *tx {
            sender.send(msg).is_ok()
        } else {
            false
        }
    }
}

/// Options for presence get(). RTP11c.
pub struct PresenceGetOptions {
    /// Filter by clientId. RTP11c2.
    pub client_id: Option<String>,
    /// Filter by connectionId. RTP11c3.
    pub connection_id: Option<String>,
    /// Whether to wait for sync to complete (default true). RTP11c1.
    pub wait_for_sync: bool,
}

impl Default for PresenceGetOptions {
    fn default() -> Self {
        Self {
            client_id: None,
            connection_id: None,
            wait_for_sync: true,
        }
    }
}

impl RealtimePresence {
    /// Whether presence sync has completed. RTP13.
    pub fn sync_complete(&self) -> bool {
        *self.inner.sync_complete.lock().unwrap()
    }

    /// Trigger implicit attach if the channel is INITIALIZED or DETACHED. RTP8d/RTP6d/RTP11b.
    /// Spawns the attach as a background task so it doesn't block the caller.
    fn trigger_implicit_attach(&self) {
        let ch_state = *self.inner.channel_state.lock().unwrap();
        if ch_state == ChannelState::Initialized || ch_state == ChannelState::Detached {
            let weak = self.inner.channel_inner.lock().unwrap().clone();
            if let Some(weak) = weak {
                if let Some(inner) = weak.upgrade() {
                    let channel = crate::channel::RealtimeChannel {
                        inner: Arc::clone(&inner),
                    };
                    tokio::spawn(async move {
                        let _ = channel.attach().await;
                    });
                }
            }
        }
    }

    /// Get the attachOnSubscribe option from the owning channel. RTP6e.
    fn attach_on_subscribe(&self) -> bool {
        let weak = self.inner.channel_inner.lock().unwrap().clone();
        if let Some(weak) = weak {
            if let Some(inner) = weak.upgrade() {
                return inner.options.lock().unwrap().attach_on_subscribe;
            }
        }
        true // default
    }

    // -- Get (RTP11) --

    /// Get current presence members. Waits for sync to complete. RTP11.
    pub async fn get(&self) -> std::result::Result<Vec<PresenceMessage>, ErrorInfo> {
        self.get_with_options(PresenceGetOptions::default()).await
    }

    /// Get current presence members with options. RTP11.
    pub async fn get_with_options(
        &self,
        options: PresenceGetOptions,
    ) -> std::result::Result<Vec<PresenceMessage>, ErrorInfo> {
        let ch_state = *self.inner.channel_state.lock().unwrap();

        // RTP11b: Implicit attach if INITIALIZED
        if ch_state == ChannelState::Initialized {
            self.trigger_implicit_attach();
        }

        // RTP11d: Error on SUSPENDED when waitForSync is true
        if ch_state == ChannelState::Suspended && options.wait_for_sync {
            return Err(ErrorInfo {
                code: Some(91005),
                status_code: None,
                message: Some(
                    "Cannot get presence: channel is SUSPENDED and waitForSync is true".to_string(),
                ),
                href: None,
            });
        }

        // RTP11b: Error on FAILED/DETACHED
        if ch_state == ChannelState::Failed || ch_state == ChannelState::Detached {
            return Err(ErrorInfo {
                code: Some(91005),
                status_code: None,
                message: Some(format!(
                    "Cannot get presence: channel is in {:?} state",
                    ch_state
                )),
                href: None,
            });
        }

        // RTP11c1: Wait for sync unless wait_for_sync is false
        if options.wait_for_sync {
            let sync_done = *self.inner.sync_complete.lock().unwrap();
            if !sync_done {
                let rx = {
                    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                    self.inner.sync_waiters.lock().unwrap().push(tx);
                    rx
                };
                let _ = rx.await;
            }
        }

        // Get values and apply filters
        let members = self.inner.presence_map.lock().unwrap().values();
        let filtered: Vec<PresenceMessage> = members
            .into_iter()
            .filter(|m| {
                if let Some(ref cid) = options.client_id {
                    if m.client_id.as_deref() != Some(cid.as_str()) {
                        return false;
                    }
                }
                if let Some(ref conn_id) = options.connection_id {
                    if m.connection_id.as_deref() != Some(conn_id.as_str()) {
                        return false;
                    }
                }
                true
            })
            .collect();

        Ok(filtered)
    }

    // -- History (RTP12) --

    /// Get presence history. Delegates to REST. RTP12.
    pub async fn history(&self) -> std::result::Result<PaginatedResult, ErrorInfo> {
        let rest = {
            let guard = self.inner.rest_client.lock().unwrap();
            guard.clone().ok_or_else(|| ErrorInfo {
                code: Some(91001),
                status_code: None,
                message: Some("No REST client available for presence history".to_string()),
                href: None,
            })?
        };
        let channel = rest.channels().get(&self.inner.channel_name);
        channel
            .presence
            .history()
            .send()
            .await
            .map_err(|e| ErrorInfo {
                code: Some(40000),
                status_code: None,
                message: Some(format!("Presence history request failed: {}", e)),
                href: None,
            })
    }

    // -- Subscribe / Unsubscribe (RTP6, RTP7) --

    /// Subscribe to all presence events. RTP6a.
    /// Triggers implicit attach if attachOnSubscribe is true.
    pub fn subscribe(
        &self,
    ) -> (
        PresenceSubscriptionId,
        tokio::sync::mpsc::UnboundedReceiver<PresenceMessage>,
    ) {
        self.subscribe_internal(None)
    }

    /// Subscribe to presence events with a single action filter. RTP6b.
    pub fn subscribe_action(
        &self,
        action: PresenceAction,
    ) -> (
        PresenceSubscriptionId,
        tokio::sync::mpsc::UnboundedReceiver<PresenceMessage>,
    ) {
        self.subscribe_internal(Some(vec![action]))
    }

    /// Subscribe to presence events with multiple action filters. RTP6b.
    pub fn subscribe_actions(
        &self,
        actions: Vec<PresenceAction>,
    ) -> (
        PresenceSubscriptionId,
        tokio::sync::mpsc::UnboundedReceiver<PresenceMessage>,
    ) {
        self.subscribe_internal(Some(actions))
    }

    fn subscribe_internal(
        &self,
        action_filter: Option<Vec<PresenceAction>>,
    ) -> (
        PresenceSubscriptionId,
        tokio::sync::mpsc::UnboundedReceiver<PresenceMessage>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let id = {
            let mut counter = self.inner.next_sub_id.lock().unwrap();
            let id = PresenceSubscriptionId(*counter);
            *counter += 1;
            id
        };
        self.inner
            .subscriptions
            .lock()
            .unwrap()
            .push(PresenceSubscription {
                id,
                action_filter,
                tx,
            });

        // RTP6d: Implicit attach if attachOnSubscribe is true
        if self.attach_on_subscribe() {
            self.trigger_implicit_attach();
        }

        (id, rx)
    }

    /// Unsubscribe a specific listener. RTP7a.
    pub fn unsubscribe(&self, id: PresenceSubscriptionId) {
        self.inner
            .subscriptions
            .lock()
            .unwrap()
            .retain(|s| s.id != id);
    }

    /// Unsubscribe a listener for a specific action only. RTP7b.
    /// If the subscription was for multiple actions, it continues receiving the others.
    /// If this was the last action, the subscription is removed entirely.
    pub fn unsubscribe_action(&self, id: PresenceSubscriptionId, action: PresenceAction) {
        let mut subs = self.inner.subscriptions.lock().unwrap();
        subs.retain_mut(|s| {
            if s.id != id {
                return true;
            }
            if let Some(ref mut filter) = s.action_filter {
                filter.retain(|a| *a != action);
                !filter.is_empty() // remove subscription if no actions remain
            } else {
                // Was subscribed to all actions — now subscribe to all except this one
                s.action_filter = Some(
                    [
                        PresenceAction::Enter,
                        PresenceAction::Leave,
                        PresenceAction::Update,
                        PresenceAction::Present,
                        PresenceAction::Absent,
                    ]
                    .into_iter()
                    .filter(|a| *a != action)
                    .collect(),
                );
                true
            }
        });
    }

    /// Unsubscribe all listeners. RTP7c.
    pub fn unsubscribe_all(&self) {
        self.inner.subscriptions.lock().unwrap().clear();
    }

    // -- Enter / Update / Leave (RTP8-10, RTP14-16) --

    /// Enter presence using the client's own clientId. RTP8.
    pub async fn enter(
        &self,
        data: Option<serde_json::Value>,
    ) -> std::result::Result<(), ErrorInfo> {
        let client_id = self.inner.client_id.lock().unwrap().clone();
        let client_id = client_id.ok_or_else(|| ErrorInfo {
            code: Some(91000),
            status_code: None,
            message: Some("Cannot enter presence: no clientId configured".to_string()),
            href: None,
        })?;
        if client_id == "*" {
            return Err(ErrorInfo {
                code: Some(91000),
                status_code: None,
                message: Some("Cannot enter presence with wildcard clientId".to_string()),
                href: None,
            });
        }
        // RTP8c: clientId must NOT be included in the PresenceMessage
        self.send_presence(PresenceAction::Enter, None, data).await
    }

    /// Update presence data using the client's own clientId. RTP9.
    pub async fn update(
        &self,
        data: Option<serde_json::Value>,
    ) -> std::result::Result<(), ErrorInfo> {
        let client_id = self.inner.client_id.lock().unwrap().clone();
        client_id.ok_or_else(|| ErrorInfo {
            code: Some(91000),
            status_code: None,
            message: Some("Cannot update presence: no clientId configured".to_string()),
            href: None,
        })?;
        self.send_presence(PresenceAction::Update, None, data).await
    }

    /// Leave presence using the client's own clientId. RTP10.
    pub async fn leave(
        &self,
        data: Option<serde_json::Value>,
    ) -> std::result::Result<(), ErrorInfo> {
        let client_id = self.inner.client_id.lock().unwrap().clone();
        client_id.ok_or_else(|| ErrorInfo {
            code: Some(91000),
            status_code: None,
            message: Some("Cannot leave presence: no clientId configured".to_string()),
            href: None,
        })?;
        self.send_presence(PresenceAction::Leave, None, data).await
    }

    /// Enter presence on behalf of a specific clientId. RTP14.
    pub async fn enter_client(
        &self,
        client_id: &str,
        data: Option<serde_json::Value>,
    ) -> std::result::Result<(), ErrorInfo> {
        if client_id == "*" {
            return Err(ErrorInfo {
                code: Some(91000),
                status_code: None,
                message: Some("Cannot enter presence with wildcard clientId".to_string()),
                href: None,
            });
        }
        // RTP15f: Client-side clientId mismatch check is skipped because this SDK
        // rejects wildcard clientId "*" at the ClientOptions level. Server-side
        // validation handles permission checks for enterClient.
        self.send_presence(PresenceAction::Enter, Some(client_id), data)
            .await
    }

    /// Update presence on behalf of a specific clientId. RTP15.
    pub async fn update_client(
        &self,
        client_id: &str,
        data: Option<serde_json::Value>,
    ) -> std::result::Result<(), ErrorInfo> {
        self.send_presence(PresenceAction::Update, Some(client_id), data)
            .await
    }

    /// Leave presence on behalf of a specific clientId. RTP15.
    pub async fn leave_client(
        &self,
        client_id: &str,
        data: Option<serde_json::Value>,
    ) -> std::result::Result<(), ErrorInfo> {
        self.send_presence(PresenceAction::Leave, Some(client_id), data)
            .await
    }

    /// Send a presence message. Handles state validation, implicit attach,
    /// message queuing, and ACK/NACK coordination. RTP16.
    async fn send_presence(
        &self,
        action: PresenceAction,
        client_id: Option<&str>,
        data: Option<serde_json::Value>,
    ) -> std::result::Result<(), ErrorInfo> {
        let ch_state = *self.inner.channel_state.lock().unwrap();

        // RTP8g/RTP16c: Error on DETACHED, FAILED, SUSPENDED
        match ch_state {
            ChannelState::Failed | ChannelState::Detached | ChannelState::Suspended => {
                return Err(ErrorInfo {
                    code: Some(91001),
                    status_code: None,
                    message: Some(format!(
                        "Cannot send presence: channel is in {:?} state",
                        ch_state
                    )),
                    href: None,
                });
            }
            _ => {}
        }

        // Build the presence message
        let mut presence_obj = serde_json::Map::new();
        presence_obj.insert(
            "action".to_string(),
            serde_json::Value::Number(serde_json::Number::from(action.clone() as u8)),
        );
        if let Some(cid) = client_id {
            presence_obj.insert(
                "clientId".to_string(),
                serde_json::Value::String(cid.to_string()),
            );
        }
        if let Some(d) = data {
            presence_obj.insert("data".to_string(), d);
        }

        let msg = ProtocolMessage {
            action: Action::Presence,
            channel: Some(self.inner.channel_name.clone()),
            presence: Some(vec![serde_json::Value::Object(presence_obj)]),
            ..ProtocolMessage::new(Action::Presence)
        };

        // RTP8d/RTP15e: Implicit attach if INITIALIZED — trigger attach and queue message
        if ch_state == ChannelState::Initialized {
            self.trigger_implicit_attach();
            let (tx, rx) = tokio::sync::oneshot::channel::<
                std::result::Result<protocol::PublishResult, ErrorInfo>,
            >();
            self.inner.queued_presence.lock().unwrap().push((msg, tx));
            return match rx.await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ErrorInfo {
                    code: Some(91001),
                    status_code: None,
                    message: Some("Presence waiter dropped".to_string()),
                    href: None,
                }),
            };
        }

        // RTP16b: Queue during ATTACHING
        if ch_state == ChannelState::Attaching {
            let (tx, rx) = tokio::sync::oneshot::channel::<
                std::result::Result<protocol::PublishResult, ErrorInfo>,
            >();
            self.inner.queued_presence.lock().unwrap().push((msg, tx));
            return match rx.await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ErrorInfo {
                    code: Some(91001),
                    status_code: None,
                    message: Some("Presence waiter dropped".to_string()),
                    href: None,
                }),
            };
        }

        // RTP16a: Channel is ATTACHED — send immediately
        self.send_presence_immediately(msg).await
    }

    /// Send a presence message immediately (channel is ATTACHED).
    async fn send_presence_immediately(
        &self,
        msg: ProtocolMessage,
    ) -> std::result::Result<(), ErrorInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel::<
            std::result::Result<protocol::PublishResult, ErrorInfo>,
        >();

        // Use ChannelsInner to assign msgSerial and register ACK waiter
        let prepared = {
            let ci = self.inner.channels_inner.lock().unwrap();
            if let Some(ref ci) = *ci {
                ci.prepare_publish(msg, tx)
            } else {
                return Err(ErrorInfo {
                    code: Some(91001),
                    status_code: None,
                    message: Some("Internal error: no channels reference".to_string()),
                    href: None,
                });
            }
        };

        let sent = self.inner.send_message(prepared);
        if !sent {
            return Err(ErrorInfo {
                code: Some(91001),
                status_code: None,
                message: Some("Failed to send presence message".to_string()),
                href: None,
            });
        }

        // Wait for ACK/NACK (map PublishResult → ())
        match rx.await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ErrorInfo {
                code: Some(91001),
                status_code: None,
                message: Some("Presence ACK waiter dropped".to_string()),
                href: None,
            }),
        }
    }

    // -- Protocol message handlers (called by channel) --

    /// Handle incoming PRESENCE protocol message. Deserialize, update map, emit.
    pub(crate) fn handle_presence_message(&self, msg: &ProtocolMessage) {
        if let Some(ref presence_array) = msg.presence {
            for (index, presence_val) in presence_array.iter().enumerate() {
                if let Ok(mut pm) = serde_json::from_value::<PresenceMessage>(presence_val.clone())
                {
                    // Populate connectionId from ProtocolMessage if not set
                    if pm.connection_id.is_none() {
                        pm.connection_id = msg.connection_id.clone();
                    }
                    // Populate timestamp from ProtocolMessage if not set
                    if pm.timestamp.is_none() {
                        pm.timestamp = msg.timestamp.map(|t| t as u64);
                    }
                    // Populate id from ProtocolMessage id + index
                    if pm.id.is_none() {
                        if let Some(ref proto_id) = msg.id {
                            pm.id = Some(format!("{}:{}", proto_id, index));
                        }
                    }

                    self.process_presence_message(pm);
                }
            }
        }
    }

    /// Handle incoming SYNC protocol message.
    pub(crate) fn handle_sync_message(&self, msg: &ProtocolMessage) {
        // Check if this is the first SYNC message (start sync)
        {
            let map = self.inner.presence_map.lock().unwrap();
            if !map.sync_in_progress() {
                drop(map);
                self.inner.presence_map.lock().unwrap().start_sync();
            }
        }

        // Process presence entries in the SYNC message
        if let Some(ref presence_array) = msg.presence {
            for (index, presence_val) in presence_array.iter().enumerate() {
                if let Ok(mut pm) = serde_json::from_value::<PresenceMessage>(presence_val.clone())
                {
                    if pm.connection_id.is_none() {
                        pm.connection_id = msg.connection_id.clone();
                    }
                    if pm.timestamp.is_none() {
                        pm.timestamp = msg.timestamp.map(|t| t as u64);
                    }
                    if pm.id.is_none() {
                        if let Some(ref proto_id) = msg.id {
                            pm.id = Some(format!("{}:{}", proto_id, index));
                        }
                    }

                    self.process_presence_message(pm);
                }
            }
        }

        // Check if sync is complete (RTP18c)
        if is_sync_complete(&msg.channel_serial) {
            let leave_events = self.inner.presence_map.lock().unwrap().end_sync();

            // Emit synthesized LEAVE events
            for leave in &leave_events {
                self.inner.emit_to_subscribers(leave);
            }

            // Mark sync complete and notify waiters
            *self.inner.sync_complete.lock().unwrap() = true;
            let waiters: Vec<_> = self.inner.sync_waiters.lock().unwrap().drain(..).collect();
            for w in waiters {
                let _ = w.send(());
            }
        }
    }

    /// Process a single deserialized PresenceMessage through the map and subscribers.
    fn process_presence_message(&self, pm: PresenceMessage) {
        match pm.action {
            PresenceAction::Leave => {
                let emitted = self.inner.presence_map.lock().unwrap().remove(pm.clone());
                // Update local presence map
                self.inner.local_presence_map.lock().unwrap().remove(&pm);
                if let Some(leave_msg) = emitted {
                    self.inner.emit_to_subscribers(&leave_msg);
                }
            }
            PresenceAction::Enter
            | PresenceAction::Update
            | PresenceAction::Present
            | PresenceAction::Absent => {
                let emitted = self.inner.presence_map.lock().unwrap().put(pm.clone());
                // Update local presence map for ENTER/UPDATE from our connection
                if pm.action == PresenceAction::Enter || pm.action == PresenceAction::Update {
                    let our_conn_id = self.inner.connection_id.lock().unwrap().clone();
                    if let Some(ref our_id) = our_conn_id {
                        if pm.connection_id.as_deref() == Some(our_id) {
                            self.inner
                                .local_presence_map
                                .lock()
                                .unwrap()
                                .put(pm.clone());
                        }
                    }
                }
                if let Some(emitted_msg) = emitted {
                    self.inner.emit_to_subscribers(&emitted_msg);
                }
            }
        }
    }

    /// Handle ATTACHED message effects on presence. RTP1, RTP17i.
    pub(crate) fn handle_attached(&self, flags_val: i64, resumed: bool) {
        let has_presence = (flags_val & flags::HAS_PRESENCE) != 0;

        if has_presence {
            if !resumed {
                // Start sync — server will send SYNC messages
                self.inner.presence_map.lock().unwrap().start_sync();
                *self.inner.sync_complete.lock().unwrap() = false;
            }
        } else {
            // RTP19a: No HAS_PRESENCE — clear all members
            let leave_events = {
                let mut map = self.inner.presence_map.lock().unwrap();
                map.start_sync();
                map.end_sync()
            };
            for leave in &leave_events {
                self.inner.emit_to_subscribers(leave);
            }
            *self.inner.sync_complete.lock().unwrap() = true;
            let waiters: Vec<_> = self.inner.sync_waiters.lock().unwrap().drain(..).collect();
            for w in waiters {
                let _ = w.send(());
            }
        }

        // RTP17i: Auto re-entry on non-RESUMED ATTACHED
        if !resumed {
            let members = self.inner.local_presence_map.lock().unwrap().values();
            if !members.is_empty() {
                let current_conn_id = self.inner.connection_id.lock().unwrap().clone();
                let inner = Arc::clone(&self.inner);
                let reentry_members = members;
                tokio::spawn(async move {
                    let presence = RealtimePresence { inner };
                    for member in reentry_members {
                        // Build ENTER message for re-entry
                        let mut presence_obj = serde_json::Map::new();
                        presence_obj.insert(
                            "action".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(
                                PresenceAction::Enter as u8,
                            )),
                        );
                        if let Some(ref cid) = member.client_id {
                            presence_obj.insert(
                                "clientId".to_string(),
                                serde_json::Value::String(cid.clone()),
                            );
                        }
                        if !matches!(member.data, rest::Data::None) {
                            if let Ok(data_val) = serde_json::to_value(&member.data) {
                                presence_obj.insert("data".to_string(), data_val);
                            }
                        }
                        // RTP17g1: Omit id if connectionId changed
                        let conn_changed =
                            member.connection_id.as_ref() != current_conn_id.as_ref();
                        if !conn_changed {
                            if let Some(ref id) = member.id {
                                presence_obj.insert(
                                    "id".to_string(),
                                    serde_json::Value::String(id.clone()),
                                );
                            }
                        }

                        let msg = ProtocolMessage {
                            action: Action::Presence,
                            channel: Some(presence.inner.channel_name.clone()),
                            presence: Some(vec![serde_json::Value::Object(presence_obj)]),
                            ..ProtocolMessage::new(Action::Presence)
                        };

                        let result = presence.send_presence_immediately(msg).await;
                        if let Err(nack_err) = result {
                            // RTP17e: Emit channel UPDATE with error code 91004
                            let tx = presence.inner.channel_state_tx.lock().unwrap();
                            if let Some(ref sender) = *tx {
                                let ch_state = *presence.inner.channel_state.lock().unwrap();
                                let _ = sender.send(ChannelStateChange {
                                    previous: ch_state,
                                    current: ch_state,
                                    event: crate::protocol::ChannelEvent::Update,
                                    reason: Some(ErrorInfo {
                                        code: Some(91004),
                                        status_code: None,
                                        message: Some(format!(
                                            "Presence re-entry failed: {}",
                                            nack_err.message.as_deref().unwrap_or("unknown error")
                                        )),
                                        href: None,
                                    }),
                                    resumed: true,
                                    has_backlog: false,
                                });
                            }
                        }
                    }
                });
            }
        }
    }

    /// Handle DETACHED or FAILED channel state. RTP5a.
    /// Clears both maps, fails queued presence, resets sync state.
    pub(crate) fn handle_detached_or_failed(&self) {
        self.inner.presence_map.lock().unwrap().clear();
        self.inner.local_presence_map.lock().unwrap().clear();
        *self.inner.sync_complete.lock().unwrap() = false;

        // Fail queued presence messages. RTL11.
        let queued: Vec<_> = self
            .inner
            .queued_presence
            .lock()
            .unwrap()
            .drain(..)
            .collect();
        let err = ErrorInfo {
            code: Some(91001),
            status_code: None,
            message: Some("Channel state prevents presence operation".to_string()),
            href: None,
        };
        for (_, waiter) in queued {
            let _ = waiter.send(Err(err.clone()));
        }
    }

    /// Send queued presence messages after ATTACHED. RTP5b.
    pub(crate) fn send_queued_presence(&self) {
        let queued: Vec<_> = self
            .inner
            .queued_presence
            .lock()
            .unwrap()
            .drain(..)
            .collect();
        for (msg, waiter) in queued {
            // Assign msgSerial and send
            let prepared = {
                let ci = self.inner.channels_inner.lock().unwrap();
                if let Some(ref ci) = *ci {
                    ci.prepare_publish(msg, waiter)
                } else {
                    continue;
                }
            };
            self.inner.send_message(prepared);
        }
    }
}

// ---------------------------------------------------------------------------
// REST presence request builders (existing code)
// ---------------------------------------------------------------------------

/// A type alias for a PaginatedRequestBuilder which uses a MessageItemHandler
/// to handle pages of presence messages returned from a presence request.
pub type PaginatedRequestBuilder<'a> = http::PaginatedRequestBuilder<'a, rest::PresenceMessage>;

/// A type alias for a PaginatedResult which uses a MessageItemHandler to
/// handle pages of presence messages returned from a presence request.
pub type PaginatedResult = http::PaginatedResult<rest::PresenceMessage>;

/// A builder to construct a REST presence request.
pub struct RequestBuilder<'a> {
    inner: PaginatedRequestBuilder<'a>,
}

impl<'a> RequestBuilder<'a> {
    pub fn new(inner: PaginatedRequestBuilder<'a>) -> Self {
        Self { inner }
    }

    /// Limit the number of results per page.
    pub fn limit(mut self, limit: u32) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    /// Set the client_id query param.
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.inner = self.inner.params(&[("clientId", client_id.to_string())]);
        self
    }

    /// Set the connection_id query param.
    pub fn connection_id(mut self, connection_id: &str) -> Self {
        self.inner = self
            .inner
            .params(&[("connectionId", connection_id.to_string())]);
        self
    }

    /// Request a stream of pages of presence messages.
    pub fn pages(self) -> impl Stream<Item = Result<PaginatedResult>> + 'a {
        self.inner.pages()
    }

    /// Retrieve the first page of presence messages.
    pub async fn send(self) -> Result<PaginatedResult> {
        self.inner.send().await
    }
}

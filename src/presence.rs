use std::collections::HashMap;

use futures::stream::Stream;

use crate::rest::{PresenceAction, PresenceMessage};
use crate::{http, rest, Result};

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

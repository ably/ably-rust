//! Presence data structures (RTP2, RTP17, RTP18/19). Pure owned data —
//! embedded in the connection loop's `ChannelCtx` (DESIGN.md §9); the UTS
//! presence_map/local_presence_map specs exercise them directly.

use std::collections::{HashMap, HashSet};

use crate::rest::{PresenceAction, PresenceMessage};

/// RTP2b: is `incoming` newer than `existing`?
///
/// When both ids are "real" (parseable as `connId:msgSerial:index` with the
/// message's own connectionId), compare msgSerial then index (RTP2b2).
/// Otherwise — synthesized leaves and foreign ids — compare timestamps;
/// equal timestamps favour the incoming message (RTP2b1/RTP2b1a).
fn is_newer(incoming: &PresenceMessage, existing: &PresenceMessage) -> bool {
    if let (Some((in_serial, in_index)), Some((ex_serial, ex_index))) =
        (parse_id(incoming), parse_id(existing))
    {
        if incoming.connection_id == existing.connection_id {
            return match in_serial.cmp(&ex_serial) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => in_index > ex_index,
            };
        }
    }
    // RTP2b1: timestamp comparison; equal → incoming wins (RTP2b1a)
    incoming.timestamp.unwrap_or(0) >= existing.timestamp.unwrap_or(0)
}

/// Parse `connId:msgSerial:index` against the message's own connectionId.
/// A mismatch (or unparseable id) marks the message as synthesized (RTP2b1).
pub(crate) fn parse_id(msg: &PresenceMessage) -> Option<(i64, i64)> {
    let id = msg.id.as_deref()?;
    let conn = msg.connection_id.as_deref()?;
    let rest = id.strip_prefix(conn)?.strip_prefix(':')?;
    let (serial, index) = rest.split_once(':')?;
    Some((serial.parse().ok()?, index.parse().ok()?))
}

/// RTP18c: a SYNC cursor "<sequence>:<cursor>" signals more pages while the
/// cursor part is non-empty; no serial or an empty cursor means complete.
pub(crate) fn sync_continues(channel_serial: &Option<String>) -> bool {
    match channel_serial {
        None => false,
        Some(s) => match s.split_once(':') {
            Some((_, cursor)) => !cursor.is_empty(),
            None => false,
        },
    }
}

/// One stored member (stored action PRESENT/ABSENT per RTP2d2).
#[derive(Clone)]
struct Member {
    msg: PresenceMessage,
}

/// RTP2: the channel presence members map.
#[derive(Default)]
pub(crate) struct PresenceMap {
    members: HashMap<String, Member>,
    sync_in_progress: bool,
    /// RTP19: members present before the sync that have not been touched by
    /// it; synthesized-LEAVEd at endSync.
    residuals: HashSet<String>,
}

impl PresenceMap {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            sync_in_progress: false,
            residuals: HashSet::new(),
        }
    }

    /// RTP2: apply a presence message. Returns the event to emit (with its
    /// ORIGINAL action, RTP2d1) when applied, or None when superseded by a
    /// newer existing member (or an irrelevant LEAVE).
    pub fn put(&mut self, msg: &PresenceMessage) -> Option<PresenceMessage> {
        let key = msg.member_key();
        // RTP19/RTP2h2a: any sync-time activity rescues the member from the
        // residual (stale) set — even messages that lose the newness check
        if self.sync_in_progress {
            self.residuals.remove(&key);
        }
        if let Some(existing) = self.members.get(&key) {
            if !is_newer(msg, &existing.msg) {
                return None;
            }
        }
        match msg.action {
            Some(PresenceAction::Leave) | Some(PresenceAction::Absent) => {
                if self.sync_in_progress {
                    // RTP2h2a: a LEAVE during sync is stored as ABSENT so the
                    // newness data survives until endSync
                    let mut stored = msg.clone();
                    stored.action = Some(PresenceAction::Absent);
                    self.members.insert(key, Member { msg: stored });
                    Some(msg.clone())
                } else {
                    // RTP2h1: remove; a LEAVE for an unknown member is no event
                    self.members.remove(&key).map(|_| msg.clone())
                }
            }
            _ => {
                // RTP2d2: ENTER/UPDATE/PRESENT are stored as PRESENT
                let mut stored = msg.clone();
                stored.action = Some(PresenceAction::Present);
                self.members.insert(key, Member { msg: stored });
                Some(msg.clone())
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&PresenceMessage> {
        self.members.get(key).map(|m| &m.msg)
    }

    /// RTP2: current members, excluding ABSENT placeholders.
    pub fn values(&self) -> Vec<&PresenceMessage> {
        self.members
            .values()
            .filter(|m| m.msg.action != Some(PresenceAction::Absent))
            .map(|m| &m.msg)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.values().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        self.members.clear();
        self.sync_in_progress = false;
        self.residuals.clear();
    }

    /// RTP18a: begin a sync. The current membership becomes the residual set
    /// (RTP19); a sync already in progress is discarded and restarted.
    pub fn start_sync(&mut self) {
        self.sync_in_progress = true;
        self.residuals = self.members.keys().cloned().collect();
    }

    /// RTP18b: finish the sync. Returns the synthesized LEAVE events for
    /// stale members (RTP19: id None, current timestamp) after deleting
    /// ABSENT placeholders (RTP2h2b). A no-op without a sync (RTP18).
    pub fn end_sync(&mut self) -> Vec<PresenceMessage> {
        if !self.sync_in_progress {
            return Vec::new();
        }
        self.sync_in_progress = false;
        // RTP2h2b: ABSENT members are deleted on endSync
        self.members
            .retain(|_, m| m.msg.action != Some(PresenceAction::Absent));
        let now = chrono::Utc::now().timestamp_millis();
        let mut leaves = Vec::new();
        for key in std::mem::take(&mut self.residuals) {
            if let Some(member) = self.members.remove(&key) {
                let mut leave = member.msg.clone();
                leave.action = Some(PresenceAction::Leave);
                leave.id = None; // RTP19: synthesized
                leave.timestamp = Some(now);
                leaves.push(leave);
            }
        }
        leaves
    }

    pub fn sync_in_progress(&self) -> bool {
        self.sync_in_progress
    }

    pub fn remove(&mut self, key: &str) -> Option<PresenceMessage> {
        self.members.remove(key).map(|m| m.msg)
    }
}

/// RTP17: the local (this-connection) members map, keyed by clientId
/// (RTP17h).
#[derive(Default)]
pub(crate) struct LocalPresenceMap {
    members: HashMap<String, PresenceMessage>,
}

impl LocalPresenceMap {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    /// RTP17b: ENTER/UPDATE/PRESENT (re)store the member; a non-synthesized
    /// LEAVE removes it; synthesized LEAVEs are ignored.
    pub fn put(&mut self, msg: &PresenceMessage) -> Option<PresenceMessage> {
        let key = msg.client_id.clone().unwrap_or_default();
        match msg.action {
            Some(PresenceAction::Leave) => {
                if parse_id(msg).is_some() {
                    self.members.remove(&key)
                } else {
                    None // RTP17b: synthesized leave ignored
                }
            }
            Some(PresenceAction::Absent) => None,
            _ => self.members.insert(key, msg.clone()),
        }
    }

    pub fn remove(&mut self, client_id: &str) -> Option<PresenceMessage> {
        self.members.remove(client_id)
    }

    pub fn get(&self, client_id: &str) -> Option<&PresenceMessage> {
        self.members.get(client_id)
    }

    pub fn values(&self) -> Vec<&PresenceMessage> {
        self.members.values().collect()
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn clear(&mut self) {
        self.members.clear();
    }
}

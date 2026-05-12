use std::collections::HashMap;

use crate::rest::{PresenceAction, PresenceMessage};

pub(crate) struct PresenceMap {
    pub(crate) members: HashMap<String, PresenceMessage>,
}

impl PresenceMap {
    pub fn new() -> Self {
        Self { members: HashMap::new() }
    }

    pub fn put(&mut self, msg: &PresenceMessage) -> Option<PresenceMessage> {
        let key = msg.member_key();
        match msg.action {
            Some(PresenceAction::Leave | PresenceAction::Absent) => self.members.remove(&key),
            _ => self.members.insert(key, msg.clone()),
        }
    }

    pub fn get(&self, key: &str) -> Option<&PresenceMessage> {
        self.members.get(key)
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

    pub fn start_sync(&mut self) {
        // stub
    }

    pub fn end_sync(&mut self) -> Vec<PresenceMessage> {
        Vec::new()
    }

    pub fn sync_in_progress(&self) -> bool {
        false
    }

    pub fn is_sync_complete_static(_channel_serial: &Option<String>) -> bool {
        // If no channel serial, sync is considered complete
        match _channel_serial {
            None => true,
            Some(s) => !s.contains(':'),
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<PresenceMessage> {
        self.members.remove(key)
    }
}

pub(crate) struct LocalPresenceMap {
    pub(crate) members: HashMap<String, PresenceMessage>,
}

impl LocalPresenceMap {
    pub fn new() -> Self {
        Self { members: HashMap::new() }
    }

    pub fn put(&mut self, msg: &PresenceMessage) -> Option<PresenceMessage> {
        let key = msg.member_key();
        self.members.insert(key, msg.clone())
    }

    pub fn remove(&mut self, key: &str) -> Option<PresenceMessage> {
        self.members.remove(key)
    }

    pub fn get(&self, key: &str) -> Option<&PresenceMessage> {
        self.members.get(key)
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

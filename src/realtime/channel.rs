use std::borrow::Borrow;
use std::collections::HashSet;
use std::hash::Hash;

#[derive(Debug, PartialEq, Eq)]
pub enum ChannelState {
    Initialised,
    Attatching,
    Attatched,
    Detatching,
    Detatched,
    Suspended,
    Failed,
}

pub struct Channels {
    channels: HashSet<Channel>,
}

impl Channels {
    pub(crate) fn new() -> Channels {
        Channels {
            channels: HashSet::new(),
        }
    }
}

#[derive(Debug, Eq)]
pub struct Channel {
    name:  String,
    state: ChannelState,
}

impl PartialEq for Channel {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl PartialOrd for Channel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.name.partial_cmp(&other.name)
    }
}

impl Ord for Channel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl Hash for Channel {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.name.as_bytes())
    }
}

impl Borrow<str> for Channel {
    fn borrow(&self) -> &str {
        &self.name
    }
}

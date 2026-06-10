use serde::{Deserialize, Serialize};

use crate::error::ErrorInfo;

// --- Public state types (re-exported via lib.rs) ---

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    #[default]
    Initialized,
    Connecting,
    Connected,
    Disconnected,
    Suspended,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectionEvent {
    Initialized,
    Connecting,
    Connected,
    Disconnected,
    Suspended,
    Closing,
    Closed,
    Failed,
    Update,
}

#[derive(Clone, Debug)]
pub struct ConnectionStateChange {
    pub previous: ConnectionState,
    pub current: ConnectionState,
    pub event: ConnectionEvent,
    pub reason: Option<ErrorInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChannelState {
    Initialized,
    Attaching,
    Attached,
    Detaching,
    Detached,
    Suspended,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChannelEvent {
    Initialized,
    Attaching,
    Attached,
    Detaching,
    Detached,
    Suspended,
    Failed,
    Update,
}

#[derive(Clone, Debug)]
pub struct ChannelStateChange {
    pub previous: ChannelState,
    pub current: ChannelState,
    pub event: ChannelEvent,
    pub reason: Option<ErrorInfo>,
    pub resumed: bool,
    pub has_backlog: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelMode {
    Presence,
    Publish,
    Subscribe,
    PresenceSubscribe,
}

// --- Internal wire types (pub(crate)) ---

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProtocolMessage {
    pub action: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg_serial: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_details: Option<ConnectionDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res: Option<Vec<PublishResult>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PublishResult {
    #[serde(default)]
    pub serials: Vec<Option<String>>,
}

impl ProtocolMessage {
    pub fn new(action: u8) -> Self {
        Self { action, ..Default::default() }
    }

    pub fn connected(connection_id: &str, connection_key: &str) -> Self {
        Self {
            action: action::CONNECTED,
            connection_id: Some(connection_id.to_string()),
            connection_key: Some(connection_key.to_string()),
            connection_details: Some(ConnectionDetails {
                connection_key: Some(connection_key.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_state_ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_frame_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_inbound_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_message_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_idle_interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
}

pub(crate) mod flags {
    pub const HAS_PRESENCE: u64 = 1 << 0;
    pub const HAS_BACKLOG: u64 = 1 << 1;
    pub const RESUMED: u64 = 1 << 2;
    pub const TRANSIENT: u64 = 1 << 4;
    pub const ATTACH_RESUME: u64 = 1 << 5;
    pub const PRESENCE: u64 = 1 << 16;
    pub const PUBLISH: u64 = 1 << 17;
    pub const SUBSCRIBE: u64 = 1 << 18;
    pub const PRESENCE_SUBSCRIBE: u64 = 1 << 19;
}

#[allow(dead_code)]
pub(crate) mod action {
    pub const HEARTBEAT: u8 = 0;
    pub const ACK: u8 = 1;
    pub const NACK: u8 = 2;
    pub const CONNECT: u8 = 3;
    pub const CONNECTED: u8 = 4;
    pub const DISCONNECT: u8 = 5;
    pub const DISCONNECTED: u8 = 6;
    pub const CLOSE: u8 = 7;
    pub const CLOSED: u8 = 8;
    pub const ERROR: u8 = 9;
    pub const ATTACH: u8 = 10;
    pub const ATTACHED: u8 = 11;
    pub const DETACH: u8 = 12;
    pub const DETACHED: u8 = 13;
    pub const PRESENCE: u8 = 14;
    pub const MESSAGE: u8 = 15;
    pub const SYNC: u8 = 16;
    pub const AUTH: u8 = 17;
    pub const ANNOTATION: u8 = 18;
}

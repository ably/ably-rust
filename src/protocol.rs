//! The Ably realtime wire protocol: `ProtocolMessage` and its supporting types.
//!
//! The public connection/channel state model that used to live here now sits
//! in its owning domain modules (`crate::connection`, `crate::channel`); this
//! module is wire-only.

use serde::{Deserialize, Serialize};

use crate::error::ErrorInfo;

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
    pub messages: Option<Vec<crate::rest::Message>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence: Option<Vec<crate::rest::PresenceMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_details: Option<ConnectionDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<crate::rest::Annotation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res: Option<Vec<PublishResult>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PublishResult {
    #[serde(default)]
    pub serials: Vec<Option<String>>,
}

/// TEST bridge: build typed wire entries from JSON literals (tolerant —
/// unknown fields are ignored exactly as on the real wire).
#[cfg(test)]
pub(crate) fn wire_messages(entries: Vec<serde_json::Value>) -> Option<Vec<crate::rest::Message>> {
    Some(
        entries
            .into_iter()
            .map(|v| serde_json::from_value(v).expect("test wire message"))
            .collect(),
    )
}

#[cfg(test)]
pub(crate) fn wire_presence(
    entries: Vec<serde_json::Value>,
) -> Option<Vec<crate::rest::PresenceMessage>> {
    Some(
        entries
            .into_iter()
            .map(|v| serde_json::from_value(v).expect("test wire presence"))
            .collect(),
    )
}

#[cfg(test)]
pub(crate) fn wire_annotations(
    entries: Vec<serde_json::Value>,
) -> Option<Vec<crate::rest::Annotation>> {
    Some(
        entries
            .into_iter()
            .map(|v| serde_json::from_value(v).expect("test wire annotation"))
            .collect(),
    )
}

impl ProtocolMessage {
    /// TEST bridge: captured wire entries as JSON for assertion ergonomics.
    #[cfg(test)]
    pub(crate) fn messages_json(&self) -> Vec<serde_json::Value> {
        self.messages
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|m| serde_json::to_value(m).unwrap())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn presence_json(&self) -> Vec<serde_json::Value> {
        self.presence
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|m| serde_json::to_value(m).unwrap())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn annotations_json(&self) -> Vec<serde_json::Value> {
        self.annotations
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|m| serde_json::to_value(m).unwrap())
            .collect()
    }

    pub fn new(action: u8) -> Self {
        Self {
            action,
            ..Default::default()
        }
    }

    #[cfg_attr(not(test), allow(dead_code))] // test-facing constructor
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
    #[allow(dead_code)] // documented protocol flag, unused so far
    pub const TRANSIENT: u64 = 1 << 4;
    pub const ATTACH_RESUME: u64 = 1 << 5;
    pub const PRESENCE: u64 = 1 << 16;
    pub const PUBLISH: u64 = 1 << 17;
    pub const SUBSCRIBE: u64 = 1 << 18;
    pub const PRESENCE_SUBSCRIBE: u64 = 1 << 19;
    // NOTE 1 << 20 is the service-internal MAY_HAVE_PRESENCE flag
    pub const ANNOTATION_PUBLISH: u64 = 1 << 21;
    pub const ANNOTATION_SUBSCRIBE: u64 = 1 << 22;
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
    // 18 ACTIVATE (deprecated), 19 OBJECT, 20 OBJECT_SYNC — not implemented
    pub const ANNOTATION: u8 = 21;
}

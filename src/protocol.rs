//! Ably protocol message types for Realtime communication.
//!
//! Defines the wire protocol used over WebSocket connections between
//! the Ably client and server.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Protocol message actions (wire format uses integer values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Action {
    Heartbeat = 0,
    Ack = 1,
    Nack = 2,
    Connect = 3,
    Connected = 4,
    Disconnect = 5,
    Disconnected = 6,
    Close = 7,
    Closed = 8,
    Error = 9,
    Attach = 10,
    Attached = 11,
    Detach = 12,
    Detached = 13,
    Presence = 14,
    Message = 15,
    Sync = 16,
    Auth = 17,
}

/// A protocol message exchanged over the WebSocket connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolMessage {
    pub action: Action,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_serial: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_details: Option<ConnectionDetails>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg_serial: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<serde_json::Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence: Option<Vec<serde_json::Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthDetails>,
}

impl ProtocolMessage {
    /// Create a new protocol message with the given action.
    pub fn new(action: Action) -> Self {
        Self {
            action,
            channel: None,
            connection_id: None,
            connection_key: None,
            connection_serial: None,
            connection_details: None,
            error: None,
            id: None,
            msg_serial: None,
            count: None,
            flags: None,
            messages: None,
            presence: None,
            auth: None,
        }
    }

    /// Create a CONNECTED message with standard test values.
    pub fn connected(connection_id: &str, connection_key: &str) -> Self {
        Self {
            action: Action::Connected,
            connection_id: Some(connection_id.to_string()),
            connection_details: Some(ConnectionDetails {
                connection_key: Some(connection_key.to_string()),
                client_id: None,
                connection_state_ttl: Some(120_000),
                max_idle_interval: Some(15_000),
                max_message_size: None,
                server_id: None,
            }),
            ..Self::new(Action::Connected)
        }
    }
}

/// Connection details provided by the server in CONNECTED messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_state_ttl: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_idle_interval: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_message_size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
}

/// Error information from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

/// Auth details for server-initiated re-authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

/// Connection state for the Realtime connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initialized,
    Connecting,
    Connected,
    Disconnected,
    Suspended,
    Closing,
    Closed,
    Failed,
}

/// Events emitted by the connection, matching ConnectionState plus UPDATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl From<ConnectionState> for ConnectionEvent {
    fn from(state: ConnectionState) -> Self {
        match state {
            ConnectionState::Initialized => ConnectionEvent::Initialized,
            ConnectionState::Connecting => ConnectionEvent::Connecting,
            ConnectionState::Connected => ConnectionEvent::Connected,
            ConnectionState::Disconnected => ConnectionEvent::Disconnected,
            ConnectionState::Suspended => ConnectionEvent::Suspended,
            ConnectionState::Closing => ConnectionEvent::Closing,
            ConnectionState::Closed => ConnectionEvent::Closed,
            ConnectionState::Failed => ConnectionEvent::Failed,
        }
    }
}

/// A state change event emitted when the connection state transitions.
#[derive(Debug, Clone)]
pub struct ConnectionStateChange {
    pub previous: ConnectionState,
    pub current: ConnectionState,
    pub event: ConnectionEvent,
    pub reason: Option<ErrorInfo>,
}

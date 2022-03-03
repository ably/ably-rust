use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

use bitflags::bitflags;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Default)]
pub struct ProtocolFields {
    pub action:             Option<Action>,
    pub id:                 Option<String>,
    pub auth:               Option<AuthDetails>,
    pub channel:            Option<String>,
    pub channel_serial:     Option<String>,
    pub count:              Option<i32>,
    pub connection_id:      Option<String>,
    pub connection_key:     Option<String>,
    pub contection_details: Option<ConectionDetails>,
    pub connection_serial:  Option<i64>,
    pub error:              Option<Error>,
    pub flags:              Option<i32>,
    pub msg_serial:         Option<i64>,
    pub messages:           Vec<Message>,
    pub presence:           Vec<Presence>,
    pub timestamp:          Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActionOnly {
    action: Action,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtocolMessage {
    Heartbeat,
    Ack,
    Nack,
    Connect,
    Connected(ConnectedMessage),
    Disconnect,
    Disconnected,
    Close,
    Closed,
    Error(ErrorMessage),
    Attatch(AttatchMessage),
    Attatched(AttatchedMessage),
    Detatch,
    Detatched,
    Presence,
    Message(MessageMessage),
    Sync(SyncMessage),
    Auth,
}

impl ProtocolMessage {
    pub fn from_json(message: &[u8]) -> Result<Self, serde_json::Error> {
        let action: ActionOnly = serde_json::from_slice(message)?;

        let message = match action.action {
            Action::Heartbeat => ProtocolMessage::Heartbeat,
            Action::Error => ProtocolMessage::Error(serde_json::from_slice(message)?),
            Action::Connected => ProtocolMessage::Connected(serde_json::from_slice(message)?),
            Action::Attatched => ProtocolMessage::Attatched(serde_json::from_slice(message)?),
            Action::Message => ProtocolMessage::Message(serde_json::from_slice(message)?),
            Action::Sync => ProtocolMessage::Sync(serde_json::from_slice(message)?),
            Action::Ack => ProtocolMessage::Ack,
            Action::Nack => todo!(),
            Action::Connect => todo!(),
            Action::Disconnect => todo!(),
            Action::Disconnected => todo!(),
            Action::Close => todo!(),
            Action::Closed => todo!(),
            Action::Attatch => todo!(),
            Action::Detatch => todo!(),
            Action::Detatched => ProtocolMessage::Detatched,
            Action::Presence => todo!(),
            Action::Auth => todo!(),
        };

        Ok(message)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct Tagged<'a> {
            action:  Action,
            #[serde(flatten)]
            message: &'a ProtocolMessage,
        }
        let message = Tagged {
            action:  self.action(),
            message: self,
        };
        serde_json::to_string(&message)
    }

    fn action(&self) -> Action {
        match self {
            Self::Heartbeat => Action::Heartbeat,
            Self::Ack => Action::Ack,
            Self::Nack => Action::Nack,
            Self::Connect => Action::Connect,
            Self::Connected(_) => Action::Connected,
            Self::Disconnect => Action::Disconnect,
            Self::Disconnected => Action::Disconnected,
            Self::Close => Action::Close,
            Self::Closed => Action::Closed,
            Self::Error(_) => Action::Error,
            Self::Attatch(_) => Action::Attatch,
            Self::Attatched(_) => Action::Attatched,
            Self::Detatch => Action::Detatch,
            Self::Detatched => Action::Detatched,
            Self::Presence => Action::Presence,
            Self::Message(_) => Action::Message,
            Self::Sync(_) => Action::Sync,
            Self::Auth => Action::Auth,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConnectedMessage {
    pub action:             Action,
    pub connection_id:      String,
    pub connection_key:     String,
    pub connection_serial:  i64,
    pub connection_details: ConectionDetails,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttatchMessage {
    pub channel: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttatchedMessage {
    pub channel:        String,
    pub error:          Option<Error>,
    pub flags:          Flags,
    pub channel_serial: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ErrorMessage {
    pub action:    Action,
    pub error:     Error,
    pub timestamp: Option<i64>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SyncMessage {}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessageMessage {
    pub id:                String,
    pub connection_id:     String,
    pub connection_serial: i64,
    pub msg_serial:        Option<i64>,
    pub channel:           String,
    pub channel_serial:    String,
    pub timestamp:         Option<i64>,
    pub messages:          Vec<Message>,
}

#[derive(Deserialize_repr, Serialize_repr, Debug)]
#[repr(i32)]
pub enum Action {
    Heartbeat = 0,
    Ack,
    Nack,
    Connect,
    Connected,
    Disconnect,
    Disconnected,
    Close,
    Closed,
    Error,
    Attatch,
    Attatched,
    Detatch,
    Detatched,
    Presence,
    Message,
    Sync,
    Auth,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Error {
    pub status_code: Option<i16>,
    pub code:        i32, // spec says i16 but sends big numbers
    pub reason:      Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Message {
    pub id:            Option<String>, // should get from parent
    pub name:          Option<String>,
    pub client_id:     Option<String>, //should get from parent
    pub timestamp:     Option<i64>,    // should get from parent
    pub data:          String,
    pub encoding:      Option<String>,
    pub connection_id: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Presence {}

#[derive(Deserialize, Serialize, Debug)]
pub struct ConectionDetails {}

#[derive(Deserialize, Serialize, Debug)]
pub struct AuthDetails {}

bitflags! {
pub struct Flags: i32 {
    const HAS_PRESENCE = 0 << 0;
    const HAS_BACKLOG = 0 << 1;
    const RESUMED = 0 << 2;
    const TRANSIENT = 0 << 4;
    const ATTATCH_RESUME = 0 << 5;
    const PRESENCE = 0 << 16;
    const PUBLISH = 0 << 17;
    const SUBSCRIBE = 0 << 18;
    const PRESENCE_SUBSCRIBE = 0 << 19;
}
}
impl Serialize for Flags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.bits().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Flags {
    fn deserialize<D>(deserializer: D) -> Result<Flags, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = i32::deserialize(deserializer)?;
        Ok(Flags::from_bits_truncate(bits))
    }
}

pub mod error;
pub mod auth;
pub mod crypto;
pub mod http;
pub(crate) mod http_client;
pub(crate) mod json;
pub mod options;
pub(crate) mod presence;
pub mod protocol;
pub mod rest;
pub mod stats;
pub(crate) mod transport;

// Realtime modules
pub mod realtime;
pub mod channel;

// Test-only modules
#[cfg(test)]
pub(crate) mod mock_http;
#[cfg(test)]
pub(crate) mod mock_ws;
#[cfg(test)]
pub(crate) mod proxy;

// Crate re-exports
pub use error::{ErrorCode, ErrorInfo, Result};
pub use options::ClientOptions;
pub use rest::{Data, Message, PresenceMessage, PresenceAction, Rest};
pub use rest::{MessageAction, Annotation, AnnotationAction};
pub use protocol::{
    ConnectionState, ConnectionEvent, ConnectionStateChange,
    ChannelState, ChannelEvent, ChannelStateChange,
    ChannelMode,
};

#[cfg(test)]
mod tests_annotations;
#[cfg(test)]
mod tests_auth;
#[cfg(test)]
mod tests_channel;
#[cfg(test)]
mod tests_connection;
#[cfg(test)]
mod tests_misc;
#[cfg(test)]
mod tests_presence_rt;
#[cfg(test)]
mod tests_push;
#[cfg(test)]
mod tests_realtime_misc;
#[cfg(test)]
mod tests_rest_channels;
#[cfg(test)]
mod tests_rest_core;
#[cfg(test)]
mod tests_rest_presence;
#[cfg(test)]
mod tests_types;


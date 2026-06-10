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

// REST unit tests
#[cfg(test)]
mod tests_rest_unit_client;
#[cfg(test)]
mod tests_rest_unit_auth;
#[cfg(test)]
mod tests_rest_unit_channel;
#[cfg(test)]
mod tests_rest_unit_presence;
#[cfg(test)]
mod tests_rest_unit_push;
#[cfg(test)]
mod tests_rest_unit_types;
#[cfg(test)]
mod tests_rest_unit_misc;

// REST integration tests
#[cfg(test)]
mod tests_rest_integration;

// Proxy integration tests (uts-proxy fault injection)
#[cfg(test)]
mod tests_proxy;

// Realtime unit tests
#[cfg(test)]
mod tests_realtime_unit_annotations;
#[cfg(test)]
mod tests_realtime_unit_channel;
#[cfg(test)]
mod tests_realtime_unit_client;
#[cfg(test)]
mod tests_realtime_unit_connection;
#[cfg(test)]
mod tests_realtime_unit_presence;


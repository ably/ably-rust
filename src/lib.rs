// Clippy policy: `ErrorInfo` is deliberately the one rich public error type
// (DESIGN.md Conventions) — we accept large Err variants rather than boxing
// the public API's errors.
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
// Test builds: the ported test corpus carries benign style patterns; the
// production lint bar is enforced by `cargo clippy --lib`.
#![cfg_attr(
    test,
    allow(
        clippy::len_zero,
        clippy::bool_assert_comparison,
        clippy::useless_vec,
        clippy::redundant_clone,
        clippy::field_reassign_with_default,
        clippy::needless_update,
        clippy::search_is_some,
        clippy::redundant_pattern_matching,
        clippy::needless_borrows_for_generic_args,
        clippy::duplicated_attributes,
        clippy::unnecessary_get_then_check,
        clippy::if_same_then_else,
        clippy::nonminimal_bool
    )
)]

pub mod auth;
pub mod crypto;
pub mod error;
pub mod http;
pub(crate) mod http_client;
pub mod options;
pub(crate) mod presence;
pub(crate) mod protocol;
pub mod rest;
pub mod stats;
mod token_request;
pub(crate) mod transport;

// Realtime modules
pub mod channel;
pub(crate) mod connection;
pub mod realtime;
pub(crate) mod ws_transport;

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
pub use channel::{ChannelEvent, ChannelMode, ChannelState, ChannelStateChange};
pub use connection::{ConnectionEvent, ConnectionState, ConnectionStateChange};
pub use rest::{Annotation, AnnotationAction, MessageAction};
pub use rest::{Data, Extras, Message, PresenceAction, PresenceMessage, Rest};

// REST unit tests
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests_rest_unit_auth;
#[cfg(test)]
mod tests_rest_unit_channel;
#[cfg(test)]
mod tests_rest_unit_client;
#[cfg(test)]
mod tests_rest_unit_misc;
#[cfg(test)]
mod tests_rest_unit_presence;
#[cfg(test)]
mod tests_rest_unit_push;
#[cfg(test)]
mod tests_rest_unit_types;

// REST integration tests
#[cfg(test)]
mod tests_rest_integration;

// Proxy integration tests (uts-proxy fault injection)
#[cfg(test)]
mod tests_proxy;
#[cfg(test)]
mod tests_proxy_realtime;

// Design conformance ratchet (DESIGN.md Realtime §14)
#[cfg(test)]
mod tests_design_conformance;
#[cfg(test)]
mod tests_uts_coverage;

// Realtime unit tests (UTS-derived, stage 5.1+)
#[cfg(test)]
mod tests_realtime_integration;
#[cfg(test)]
mod tests_realtime_uts_channels;
#[cfg(test)]
mod tests_realtime_uts_channels_advanced;
#[cfg(test)]
mod tests_realtime_uts_connection;
#[cfg(test)]
mod tests_realtime_uts_messages;
#[cfg(test)]
mod tests_realtime_uts_presence;

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

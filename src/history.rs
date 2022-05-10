use crate::{http, rest};

/// A type alias for a PaginatedRequestBuilder which uses a MessageItemHandler
/// to handle pages of messages returned from a history request.
pub type PaginatedRequestBuilder<'a, T> =
    http::PaginatedRequestBuilder<'a, T, rest::MessageItemHandler>;

/// A type alias for a PaginatedResult which uses a MessageItemHandler to
/// handle pages of messages returned from a history request.
pub type PaginatedResult<T> = http::PaginatedResult<T, rest::MessageItemHandler>;

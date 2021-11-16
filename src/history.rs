use crate::{http, rest};

pub type PaginatedRequestBuilder<T> = http::PaginatedRequestBuilder<T, rest::MessageItemHandler>;

pub type PaginatedResult<T> = http::PaginatedResult<T, rest::MessageItemHandler>;

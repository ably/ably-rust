# ably-rust SDK API Design

This document defines the complete public API surface for the ably-rust SDK rewrite.
Internal types (`pub(crate)`) are listed separately. The goal is a clean separation
between user-facing API and implementation details.

## Module Layout

```
src/
  lib.rs              -- crate root, re-exports
  error.rs            -- ErrorInfo, ErrorCode, Result
  options.rs          -- ClientOptions builder
  rest.rs             -- Rest client, REST Channel, Presence, Push, PublishBuilder
  auth.rs             -- Auth, TokenParams, TokenDetails, TokenRequest, AuthCallback
  http.rs             -- RequestBuilder, PaginatedRequestBuilder, PaginatedResult, Response
  realtime.rs         -- Realtime client, Connection
  channel.rs          -- RealtimeChannel, Channels (realtime), RealtimePresence
  protocol.rs         -- pub(crate) wire types; pub state enums re-exported via lib.rs
  transport.rs        -- pub(crate) Transport trait
  http_client.rs      -- pub(crate) HttpClient trait
  mock_http.rs        -- pub(crate), #[cfg(test)] MockHttpClient
  mock_ws.rs          -- pub(crate), #[cfg(test)] MockWebSocket/MockTransport
  crypto.rs           -- CipherParams (copied verbatim)
  stats.rs            -- Stats types (copied verbatim)
  proxy.rs            -- pub(crate), #[cfg(test)] UTS proxy
  json.rs             -- pub(crate) utility (copied verbatim)
```

## Crate Re-exports (`lib.rs`)

```rust
pub use error::{ErrorCode, ErrorInfo, Result};
pub use options::ClientOptions;
pub use rest::{Data, Message, PresenceMessage, PresenceAction, Rest};
pub use rest::{MessageAction, Annotation, AnnotationAction};

// State enums (defined in protocol.rs, re-exported here)
pub use protocol::{
    ConnectionState, ConnectionEvent, ConnectionStateChange,
    ChannelState, ChannelEvent, ChannelStateChange,
    ChannelMode,
};
```

---

## `error.rs` — Error Type

```rust
pub type Result<T> = std::result::Result<T, ErrorInfo>;

/// Ably error type (TI1). Used everywhere: Result<T>, state changes, error_reason().
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: Option<u32>,           // TI1: Ably error code
    pub status_code: Option<u16>,    // TI1: HTTP status code
    pub message: Option<String>,     // TI1: human-readable message
    pub href: Option<String>,        // TI4: help URL
    pub request_id: Option<String>,  // RSC7c: request identifier
    pub detail: Option<HashMap<String, String>>,  // TI6: structured metadata
    pub cause: Option<Box<ErrorInfo>>,  // TI1: underlying cause
}

/// Enum of known Ably error codes.
pub enum ErrorCode { /* ~100 variants, same as current */ }

impl ErrorInfo {
    pub fn new(code: u32, message: impl Into<String>) -> Self;
    pub fn with_status(code: u32, status_code: u16, message: impl Into<String>) -> Self;
    pub fn with_cause(code: u32, message: impl Into<String>, cause: ErrorInfo) -> Self;
}

impl std::error::Error for ErrorInfo;
impl Display for ErrorInfo;
```

**Key decision:** Single error type for the entire SDK. `ErrorInfo` is used in `Result<T>`, on state changes (`ConnectionStateChange.reason`), and in `error_reason()` accessors. Error chaining uses `cause: Option<Box<ErrorInfo>>` per TI1, not `Box<dyn Error>`.

---

## `options.rs` — Client Configuration

```rust
pub enum LogLevel { None, Error, Major, Minor, Micro }

pub struct ClientOptions { /* all fields pub(crate) */ }

impl ClientOptions {
    // Constructors
    pub fn new(key_or_token: &str) -> Self;
    pub fn with_auth_url(url: impl Into<String>) -> Self;
    pub fn with_auth_callback(callback: Arc<dyn AuthCallback>) -> Self;
    pub fn with_key(key: auth::Key) -> Self;
    pub fn with_token(token: impl Into<String>) -> Self;

    // Builder methods (all return Self or Result<Self>)
    pub fn client_id(self, id: impl Into<String>) -> Result<Self>;
    pub fn use_token_auth(self, v: bool) -> Self;
    pub fn token_details(self, td: auth::TokenDetails) -> Self;
    pub fn environment(self, env: impl Into<String>) -> Result<Self>;
    pub fn use_binary_protocol(self, v: bool) -> Self;
    pub fn idempotent_rest_publishing(self, v: bool) -> Self;
    pub fn default_token_params(self, params: auth::TokenParams) -> Self;
    pub fn rest_host(self, host: impl Into<String>) -> Result<Self>;
    pub fn fallback_hosts(self, hosts: Vec<String>) -> Self;
    pub fn http_request_timeout(self, timeout: Duration) -> Self;
    pub fn http_max_retry_count(self, count: usize) -> Self;
    pub fn add_request_ids(self, v: bool) -> Self;
    pub fn log_level(self, level: LogLevel) -> Self;
    pub fn log_handler(self, handler: impl Fn(LogLevel, &str) + Send + Sync + 'static) -> Self;
    pub fn tls(self, v: bool) -> Self;
    pub fn realtime_host(self, host: impl Into<String>) -> Self;
    pub fn port(self, port: u32) -> Self;
    pub fn auto_connect(self, v: bool) -> Self;
    pub fn echo_messages(self, v: bool) -> Self;
    pub fn queue_messages(self, v: bool) -> Self;
    pub fn transport_params(self, params: Vec<(String, String)>) -> Self;
    pub fn disconnected_retry_timeout(self, timeout: Duration) -> Self;
    pub fn suspended_retry_timeout(self, timeout: Duration) -> Self;
    pub fn realtime_request_timeout(self, timeout: Duration) -> Self;

    // Factory methods
    pub fn rest(self) -> Result<Rest>;
    pub fn realtime(self) -> Result<Realtime>;
}
```

**Removed from public API:**
- `token_source()` — was internal, now `pub(crate)`
- `LogHandlerFn` wrapper struct — replaced by direct closure in `log_handler()`
- `with_auth_url` now takes `impl Into<String>` instead of `reqwest::Url`

---

## `rest.rs` — REST Client

### Rest

```rust
pub struct Rest { /* inner: Arc<RestInner> */ }

impl Rest {
    pub fn new(key: &str) -> Result<Self>;
    pub fn auth(&self) -> Auth<'_>;
    pub fn channels(&self) -> Channels<'_>;       // returns ephemeral accessor
    pub fn push(&self) -> Push<'_>;               // returns ephemeral accessor
    pub fn options(&self) -> &ClientOptions;
    pub fn stats(&self) -> PaginatedRequestBuilder<'_, Stats>;
    pub async fn time(&self) -> Result<DateTime<Utc>>;
    pub async fn batch_presence(&self, channels: &[&str]) -> Result<Vec<BatchPresenceResult>>;
    pub async fn batch_publish(&self, specs: Vec<BatchPublishSpec>) -> Result<Vec<BatchPublishResult>>;
    pub fn request(&self, method: &str, path: &str) -> RequestBuilder<'_>;
}

impl From<&str> for Rest;
```

**Changes:**
- `request()` takes `&str` for method instead of `http::Method` (reqwest type)
- `auth_options()` removed from public API (internal concern)
- `paginated_request()` / `paginated_request_with_options()` become `pub(crate)`

### REST Channels

```rust
pub struct Channels<'a> { /* pub(crate) fields */ }

impl<'a> Channels<'a> {
    pub fn name(&self, name: impl Into<String>) -> ChannelBuilder<'a>;
    pub fn get(&self, name: impl Into<String>) -> Channel<'a>;
}

pub struct ChannelBuilder<'a> { /* private */ }

impl<'a> ChannelBuilder<'a> {
    pub fn cipher(self, cipher: CipherParams) -> Self;
    pub fn get(self) -> Channel<'a>;
}

pub struct Channel<'a> {
    pub name: String,
    pub presence: Presence<'a>,
    // ... other fields pub(crate)
}

impl<'a> Channel<'a> {
    pub fn publish(&self) -> PublishBuilder<'_>;
    pub fn history(&self) -> PaginatedRequestBuilder<'_, Message>;
    pub async fn get_message(&self, serial: &str) -> Result<Message>;
    pub fn message_versions(&self, serial: &str) -> PaginatedRequestBuilder<'_, Message>;
    pub async fn update_message(&self, msg: &Message, op: &MessageOperation, params: Option<&[(&str, &str)]>) -> Result<UpdateDeleteResult>;
    pub async fn delete_message(&self, msg: &Message, op: &MessageOperation, params: Option<&[(&str, &str)]>) -> Result<UpdateDeleteResult>;
    pub async fn append_message(&self, msg: &Message, params: Option<&[(&str, &str)]>) -> Result<UpdateDeleteResult>;
    pub fn annotations(&self) -> RestAnnotations<'_>;
}
```

### REST Presence

```rust
pub struct Presence<'a> { /* pub(crate) fields */ }

impl<'a> Presence<'a> {
    pub fn get(&self) -> PresenceRequestBuilder<'_>;
    pub fn history(&self) -> PaginatedRequestBuilder<'_, PresenceMessage>;
}

pub struct PresenceRequestBuilder<'a> { /* private */ }

impl<'a> PresenceRequestBuilder<'a> {
    pub fn limit(self, limit: u32) -> Self;
    pub fn client_id(self, client_id: &str) -> Self;
    pub fn connection_id(self, connection_id: &str) -> Self;
    pub async fn send(self) -> Result<PaginatedResult<PresenceMessage>>;
    pub fn pages(self) -> impl Stream<Item = Result<PaginatedResult<PresenceMessage>>> + 'a;
}
```

### REST Annotations

```rust
pub struct RestAnnotations<'a> { /* pub(crate) fields */ }

impl<'a> RestAnnotations<'a> {
    pub async fn publish(&self, msg_serial: &str, annotation: &Annotation) -> Result<()>;
    pub async fn delete(&self, msg_serial: &str, annotation: &Annotation) -> Result<()>;
    pub fn get(&self, msg_serial: &str) -> PaginatedRequestBuilder<'_, Annotation>;
}
```

### PublishBuilder (REST)

```rust
pub struct PublishBuilder<'a> { /* private */ }

impl<'a> PublishBuilder<'a> {
    pub fn id(self, id: impl Into<String>) -> Self;
    pub fn name(self, name: impl Into<String>) -> Self;
    pub fn string(self, data: impl Into<String>) -> Self;
    pub fn json(self, data: impl Serialize) -> Self;
    pub fn binary(self, data: Vec<u8>) -> Self;
    pub fn extras(self, extras: serde_json::Map<String, serde_json::Value>) -> Self;
    pub fn client_id(self, client_id: impl Into<String>) -> Self;
    pub fn params(self, params: &[(&str, &str)]) -> Self;
    pub fn cipher(self, cipher: CipherParams) -> Self;
    pub async fn send(self) -> Result<()>;
}
```

### Push Admin

```rust
pub struct Push<'a> { /* pub(crate) */ }
impl<'a> Push<'a> {
    pub fn admin(&self) -> PushAdmin<'a>;
}

pub struct PushAdmin<'a> { /* pub(crate) */ }
impl<'a> PushAdmin<'a> {
    pub async fn publish(&self, recipient: serde_json::Value, data: serde_json::Value) -> Result<()>;
    pub fn device_registrations(&self) -> PushDeviceRegistrations<'a>;
    pub fn channel_subscriptions(&self) -> PushChannelSubscriptions<'a>;
}

pub struct PushDeviceRegistrations<'a> { /* pub(crate) */ }
impl<'a> PushDeviceRegistrations<'a> {
    pub async fn get(&self, device_id: &str) -> Result<serde_json::Value>;
    pub fn list(&self) -> PaginatedRequestBuilder<'_, serde_json::Value>;
    pub async fn save(&self, device: &serde_json::Value) -> Result<serde_json::Value>;
    pub async fn remove(&self, device_id: &str) -> Result<()>;
    pub async fn remove_where(&self, filter: &[(&str, &str)]) -> Result<()>;
}

pub struct PushChannelSubscriptions<'a> { /* pub(crate) */ }
impl<'a> PushChannelSubscriptions<'a> {
    pub fn list(&self) -> PaginatedRequestBuilder<'_, serde_json::Value>;
    pub fn list_channels(&self) -> PaginatedRequestBuilder<'_, serde_json::Value>;
    pub async fn save(&self, subscription: &serde_json::Value) -> Result<serde_json::Value>;
    pub async fn remove(&self, subscription: &serde_json::Value) -> Result<()>;
    pub async fn remove_where(&self, filter: &[(&str, &str)]) -> Result<()>;
}
```

### Data Types (unified, in rest.rs)

```rust
/// Message data payload.
pub enum Data {
    String(String),
    JSON(serde_json::Value),
    Binary(serde_bytes::ByteBuf),
    None,
}

/// Message action for mutable messages.
#[repr(u8)]
pub enum MessageAction {
    Create = 1,
    Update = 2,
    Delete = 3,
    Annotation = 4,
    MetaOccupancy = 5,
}

pub struct MessageOperation {
    pub client_id: Option<String>,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

pub struct UpdateDeleteResult {
    pub serial: String,
    pub version_serial: String,
}

pub enum AnnotationAction { Create, Delete }

pub struct Annotation {
    pub type_: Option<String>,
    pub action: Option<AnnotationAction>,
    pub msg_serial: Option<String>,
    pub client_id: Option<String>,
    pub name: Option<String>,
    pub data: Data,
    pub encoding: Option<String>,
    pub extras: Option<serde_json::Value>,
}

/// Unified Message type for both REST and Realtime.
pub struct Message {
    pub id: Option<String>,
    pub name: Option<String>,
    pub data: Data,
    pub encoding: Option<String>,
    pub client_id: Option<String>,
    pub connection_id: Option<String>,
    pub timestamp: Option<i64>,
    pub extras: Option<serde_json::Value>,
    pub action: Option<MessageAction>,
    pub serial: Option<String>,
    pub version: Option<serde_json::Value>,
    pub annotations: Option<serde_json::Value>,
}

/// Presence message (REST and Realtime).
pub struct PresenceMessage {
    pub id: Option<String>,
    pub action: Option<PresenceAction>,
    pub client_id: Option<String>,
    pub connection_id: Option<String>,
    pub data: Data,
    pub encoding: Option<String>,
    pub timestamp: Option<i64>,
    pub extras: Option<serde_json::Value>,
}

pub enum PresenceAction { Absent, Present, Enter, Leave, Update }

/// Channel options (cipher config).
pub struct ChannelOptions {
    // pub(crate) cipher: Option<CipherParams>,
}

/// Batch types.
pub struct BatchPresenceResult {
    pub channel: String,
    pub presence: Vec<PresenceMessage>,
}

pub struct BatchPublishSpec {
    pub channels: Vec<String>,
    pub messages: Vec<Message>,
}

pub enum BatchPublishResult {
    Success(BatchPublishSuccessResult),
    Failure(BatchPublishFailureResult),
}

pub struct BatchPublishSuccessResult {
    pub channel: String,
    pub message_id: Option<String>,
    pub serials: Option<Vec<Option<String>>>,
}

pub struct BatchPublishFailureResult {
    pub channel: String,
    pub error: ErrorInfo,
}

/// Token revocation types.
pub struct RevokeTokensRequest {
    pub targets: Vec<String>,
    pub issued_before: Option<i64>,
    pub allow_reauth_margin: Option<bool>,
}

pub struct RevokeTokensResponse {
    pub success_count: u32,
    pub failure_count: u32,
    pub results: Vec<RevokeTokenResult>,
}

pub struct RevokeTokenResult {
    pub target: String,
    pub issued_before: Option<i64>,
    pub applies_at: Option<i64>,
    pub error: Option<ErrorInfo>,
}

/// Wire format. pub(crate) — users set this via use_binary_protocol().
// pub(crate) enum Format { MessagePack, JSON }
```

**Key changes from current:**
- `Encoding` enum removed — replaced by `Option<String>` field on Message
- `Format` enum is `pub(crate)` — not user-facing
- `Decode` trait and `DecodeRaw` are `pub(crate)` — pagination internals
- `Message` is the single type used everywhere (REST publish, REST history, Realtime subscribe)
- `PresenceMessage.member_key()` stays as a method

---

## `auth.rs` — Authentication

```rust
pub struct Key {
    pub name: String,
    pub value: String,
}

impl Key {
    pub fn new(s: &str) -> Result<Self>;
    pub fn sign(&self, params: &TokenParams) -> Result<TokenRequest>;
}

impl TryFrom<&str> for Key;

pub struct Auth<'a> { /* pub(crate) rest */ }

impl<'a> Auth<'a> {
    // pub(crate) fn new(rest: &'a Rest) -> Self;  -- NOT pub
    pub fn token_details(&self) -> Option<TokenDetails>;
    pub fn create_token_request(&self, params: &TokenParams, options: &AuthOptions) -> Result<TokenRequest>;
    pub async fn request_token(&self, params: &TokenParams, options: &AuthOptions) -> Result<TokenDetails>;
    pub async fn authorize(&self, params: &TokenParams, options: &AuthOptions) -> Result<TokenDetails>;
    pub async fn revoke_tokens(&self, request: &RevokeTokensRequest) -> Result<RevokeTokensResponse>;
}

pub struct TokenParams {
    pub ttl: Option<i64>,
    pub capability: Option<String>,
    pub client_id: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub nonce: Option<String>,
}

impl TokenParams {
    pub fn new() -> Self;
    pub fn capability(self, capability: &str) -> Self;
    pub fn client_id(self, client_id: &str) -> Self;
    pub fn ttl(self, ttl: Duration) -> Self;
    pub fn timestamp(self, timestamp: DateTime<Utc>) -> Self;
}

pub struct TokenRequest {
    pub key_name: String,
    pub ttl: Option<i64>,
    pub capability: Option<String>,
    pub client_id: Option<String>,
    pub timestamp: Option<i64>,
    pub nonce: String,
    pub mac: String,
}

pub struct TokenDetails {
    pub token: String,
    pub expires: Option<i64>,
    pub issued: Option<i64>,
    pub capability: Option<String>,
    pub client_id: Option<String>,
}

impl TokenDetails {
    pub fn token(s: String) -> Self;
}

impl From<String> for TokenDetails;

pub struct AuthOptions {
    pub token: Option<String>,
    pub headers: Option<Vec<(String, String)>>,   // NOT reqwest::HeaderMap
    pub method: Option<String>,                    // NOT reqwest::Method
    pub params: Option<Vec<(String, String)>>,     // NOT http::UrlQuery
}

/// What an auth callback can return.
pub enum AuthToken {
    Details(TokenDetails),
    Request(TokenRequest),
}

/// Trait for auth callbacks.
pub trait AuthCallback: Send + Sync {
    fn token<'a>(
        &'a self,
        params: &'a TokenParams,
    ) -> Pin<Box<dyn Send + Future<Output = Result<AuthToken>> + 'a>>;
}
```

**Changes:**
- `AuthOptions.headers` is `Option<Vec<(String, String)>>` instead of `Option<http::HeaderMap>`
- `AuthOptions.method` is `Option<String>` instead of `http::Method`
- `RequestOrDetails` renamed to `AuthToken` (clearer name)
- `Credential` enum stays but becomes `pub(crate)` — it's internal routing
- `Auth::new()` becomes `pub(crate)`
- `Auth::authorize()` returns `Result<TokenDetails>` (not `Result<TokenDetails, ErrorInfo>`)

---

## `http.rs` — HTTP Abstractions

```rust
pub struct RequestBuilder<'a> { /* private */ }

impl<'a> RequestBuilder<'a> {
    // pub(crate) fn new(...)  -- NOT pub
    pub fn params(self, params: &[(&str, &str)]) -> Self;
    pub fn body(self, body: &impl Serialize) -> Self;
    pub fn headers(self, headers: &[(&str, &str)]) -> Self;
    pub async fn send(self) -> Result<Response>;
}

pub struct PaginatedRequestBuilder<'a, T> { /* private */ }

impl<'a, T> PaginatedRequestBuilder<'a, T> {
    // pub(crate) fn new(...)  -- NOT pub
    pub fn start(self, interval: &str) -> Self;
    pub fn end(self, interval: &str) -> Self;
    pub fn forwards(self) -> Self;
    pub fn backwards(self) -> Self;
    pub fn limit(self, limit: u32) -> Self;
    pub fn params(self, params: &[(&str, &str)]) -> Self;
    pub fn pages(self) -> impl Stream<Item = Result<PaginatedResult<T>>> + 'a;
    pub async fn send(self) -> Result<PaginatedResult<T>>;
}

pub struct Response { /* private */ }

impl Response {
    // pub(crate) fn new(...)  -- NOT pub
    pub fn status_code(&self) -> u16;              // NOT reqwest::StatusCode
    pub fn content_type(&self) -> Option<String>;  // NOT mime::Mime
    pub async fn body<T: DeserializeOwned>(self) -> Result<T>;
    pub async fn text(self) -> Result<String>;
}

pub struct PaginatedResult<T> { /* private */ }

impl<T> PaginatedResult<T> {
    // pub(crate) fn new(...)  -- NOT pub
    pub fn items(&self) -> &[T];     // borrow, not consume
    pub fn has_next(&self) -> bool;
    pub fn is_last(&self) -> bool;
    pub async fn next(self) -> Result<Option<PaginatedResult<T>>>;
    pub async fn first(self) -> Result<Option<PaginatedResult<T>>>;
}
```

**Changes:**
- No reqwest re-exports
- `Response::status_code()` returns `u16` not `reqwest::StatusCode`
- `Response::content_type()` returns `Option<String>` not `Option<mime::Mime>`
- `RequestBuilder::new()`, `Response::new()`, `PaginatedResult::new()` all `pub(crate)`
- `RequestBuilder::authenticate()`, `basic_auth()`, `bearer_auth()` all `pub(crate)`
- `PaginatedResult::items()` borrows rather than consuming
- `Decode` trait and `DecodeRaw` become `pub(crate)` — pagination decoding internals
- `UrlQuery` type alias removed (use `Vec<(String, String)>` or `&[(&str, &str)]`)
- `RequestBuilder::headers()` takes `&[(&str, &str)]` not `HeaderMap`

---

## `realtime.rs` — Realtime Client

```rust
pub struct Realtime {
    pub connection: Connection,
    pub channels: Channels,
}

impl Realtime {
    pub fn new(options: &ClientOptions) -> Result<Self>;
    pub fn connect(&self);
    pub fn close(&self);
    pub fn auth(&self) -> &RealtimeAuth;
    pub fn push(&self) -> Option<Push<'_>>;
}

pub struct RealtimeAuth { /* pub(crate) inner */ }

impl RealtimeAuth {
    pub async fn authorize(&self) -> Result<TokenDetails>;
    pub fn client_id(&self) -> Option<String>;
}

pub struct Connection { /* private inner */ }

impl Connection {
    pub fn state(&self) -> ConnectionState;
    pub fn id(&self) -> Option<String>;
    pub fn key(&self) -> Option<String>;
    pub fn host(&self) -> Option<String>;
    pub fn error_reason(&self) -> Option<ErrorInfo>;
    pub fn on_state_change(&self) -> broadcast::Receiver<ConnectionStateChange>;
    pub fn connect(&self);
    pub fn close(&self);
    pub async fn ping(&self) -> Result<Duration>;
    pub fn when_state(&self, target: ConnectionState, callback: impl FnOnce(ConnectionStateChange) + Send + 'static);
}
```

**Changes:**
- `Connection::ping()` returns `Result<Duration>` (unified error)
- `await_state()` and `await_channel_state()` become `pub(crate)` — test helpers
- `Realtime::auth()` returns `&RealtimeAuth` instead of exposing field
- `RealtimeAuth::authorize()` returns `Result<TokenDetails>`

---

## `channel.rs` — Realtime Channels

### Channels Collection

```rust
pub struct Channels { /* Arc<ChannelsInner> */ }

impl Channels {
    pub fn get(&self, name: &str) -> Arc<RealtimeChannel>;
    pub fn get_with_options(&self, name: &str, options: RealtimeChannelOptions) -> Arc<RealtimeChannel>;
    pub fn get_derived(&self, name: &str, derive: DeriveOptions) -> Arc<RealtimeChannel>;
    pub fn exists(&self, name: &str) -> bool;
    pub fn names(&self) -> Vec<String>;
    pub async fn release(&self, name: &str);
}
```

### RealtimeChannel

```rust
pub struct RealtimeChannelOptions {
    pub params: Option<HashMap<String, String>>,
    pub modes: Option<Vec<ChannelMode>>,
    pub cipher: Option<CipherParams>,
}

pub struct DeriveOptions { /* private */ }
impl DeriveOptions {
    pub fn new(filter: &str) -> Self;
}

pub struct SubscriptionId(/* pub(crate) */ u64);

pub struct RealtimeChannel { /* Arc<ChannelInner> */ }

impl RealtimeChannel {
    // Accessors
    pub fn name(&self) -> &str;
    pub fn state(&self) -> ChannelState;
    pub fn error_reason(&self) -> Option<ErrorInfo>;
    pub fn options(&self) -> RealtimeChannelOptions;
    pub fn modes(&self) -> Option<Vec<ChannelMode>>;
    pub fn channel_serial(&self) -> Option<String>;
    pub fn attach_serial(&self) -> Option<String>;

    // Lifecycle
    pub async fn attach(&self) -> Result<()>;
    pub async fn detach(&self) -> Result<()>;
    pub async fn set_options(&self, options: RealtimeChannelOptions) -> Result<()>;

    // Events
    pub fn on_state_change(&self) -> broadcast::Receiver<ChannelStateChange>;
    pub fn when_state(&self, target: ChannelState, callback: impl FnOnce(ChannelStateChange) + Send + 'static);

    // Publish (builder pattern, consistent with REST)
    pub fn publish(&self) -> RealtimePublishBuilder<'_>;

    // Also keep the simple publish for convenience
    pub async fn publish_message(&self, name: Option<&str>, data: Option<serde_json::Value>) -> Result<()>;

    // Subscribe
    pub fn subscribe(&self) -> (SubscriptionId, tokio::sync::mpsc::Receiver<Message>);
    pub fn subscribe_with_name(&self, name: &str) -> (SubscriptionId, tokio::sync::mpsc::Receiver<Message>);
    pub fn unsubscribe(&self, id: SubscriptionId);
    pub fn unsubscribe_with_name(&self, name: &str, id: SubscriptionId);
    pub fn unsubscribe_all(&self);

    // Annotations
    pub fn annotations(&self) -> RealtimeAnnotations<'_>;

    // REST operations via realtime
    pub fn presence(&self) -> RealtimePresence;
    pub async fn history(&self, until_attach: bool) -> Result<PaginatedResult<Message>>;
    pub async fn get_message(&self, serial: &str) -> Result<Message>;
    pub fn message_versions(&self, serial: &str) -> PaginatedRequestBuilder<'_, Message>;
    pub async fn update_message(&self, msg: &Message, op: &MessageOperation, params: Option<&[(&str, &str)]>) -> Result<UpdateDeleteResult>;
    pub async fn delete_message(&self, msg: &Message, op: &MessageOperation, params: Option<&[(&str, &str)]>) -> Result<UpdateDeleteResult>;
    pub async fn append_message(&self, msg: &Message, params: Option<&[(&str, &str)]>) -> Result<UpdateDeleteResult>;
}
```

**Changes:**
- `attach()`, `detach()`, `set_options()` return `Result<()>`
- `publish()` returns a builder (consistent with REST)
- `publish_message()` replaces the old positional `publish(name, data)` for convenience
- `subscribe()` returns the unified `Message` type (not `channel::Message`)
- `update_message`/`delete_message`/`append_message` take `Option<&[(&str, &str)]>` (consistent with REST)

### RealtimePublishBuilder

```rust
pub struct RealtimePublishBuilder<'a> { /* private */ }

impl<'a> RealtimePublishBuilder<'a> {
    pub fn name(self, name: impl Into<String>) -> Self;
    pub fn string(self, data: impl Into<String>) -> Self;
    pub fn json(self, data: impl Serialize) -> Self;
    pub fn binary(self, data: Vec<u8>) -> Self;
    pub fn id(self, id: impl Into<String>) -> Self;
    pub fn client_id(self, client_id: impl Into<String>) -> Self;
    pub fn extras(self, extras: serde_json::Value) -> Self;
    pub async fn send(self) -> Result<()>;
}
```

### RealtimePresence

```rust
pub struct PresenceSubscriptionId(/* pub(crate) */ u64);

pub struct PresenceGetOptions {
    pub wait_for_sync: bool,
    pub client_id: Option<String>,
    pub connection_id: Option<String>,
}

pub struct RealtimePresence { /* Arc<PresenceInner> */ }

impl RealtimePresence {
    pub fn sync_complete(&self) -> bool;
    pub async fn get(&self) -> Result<Vec<PresenceMessage>>;
    pub async fn get_with_options(&self, options: &PresenceGetOptions) -> Result<Vec<PresenceMessage>>;
    pub async fn history(&self) -> Result<PaginatedResult<PresenceMessage>>;

    pub fn subscribe(&self, callback: impl Fn(PresenceMessage) + Send + Sync + 'static) -> PresenceSubscriptionId;
    pub fn subscribe_action(&self, action: PresenceAction, callback: impl Fn(PresenceMessage) + Send + Sync + 'static) -> PresenceSubscriptionId;
    pub fn subscribe_actions(&self, actions: &[PresenceAction], callback: impl Fn(PresenceMessage) + Send + Sync + 'static) -> PresenceSubscriptionId;
    pub fn unsubscribe(&self, id: PresenceSubscriptionId);
    pub fn unsubscribe_action(&self, id: PresenceSubscriptionId, action: PresenceAction);
    pub fn unsubscribe_all(&self);

    pub async fn enter(&self, data: Option<serde_json::Value>) -> Result<()>;
    pub async fn update(&self, data: Option<serde_json::Value>) -> Result<()>;
    pub async fn leave(&self, data: Option<serde_json::Value>) -> Result<()>;
    pub async fn enter_client(&self, client_id: &str, data: Option<serde_json::Value>) -> Result<()>;
    pub async fn update_client(&self, client_id: &str, data: Option<serde_json::Value>) -> Result<()>;
    pub async fn leave_client(&self, client_id: &str, data: Option<serde_json::Value>) -> Result<()>;
}
```

**Changes:**
- All methods return `Result<T>`
- `PresenceMap`, `LocalPresenceMap`, `Newness`, `PresenceInner` all `pub(crate)`
- `is_synthesized_message()`, `is_sync_complete()` become `pub(crate)`

### RealtimeAnnotations

```rust
pub struct RealtimeAnnotations<'a> { /* private */ }

impl<'a> RealtimeAnnotations<'a> {
    pub async fn publish(&self, msg_serial: &str, annotation: &Annotation) -> Result<()>;
    pub async fn delete(&self, msg_serial: &str, annotation: &Annotation) -> Result<()>;
    pub async fn get(&self, msg_serial: &str) -> Result<PaginatedResult<Annotation>>;
    pub fn subscribe(&self, callback: impl Fn(Annotation) + Send + Sync + 'static) -> SubscriptionId;
    pub fn subscribe_with_type(&self, type_filter: &str, callback: impl Fn(Annotation) + Send + Sync + 'static) -> SubscriptionId;
    pub fn unsubscribe(&self, id: SubscriptionId);
    pub fn unsubscribe_all(&self);
}
```

---

## `protocol.rs` — State Types (pub) and Wire Types (pub(crate))

### Public (re-exported via lib.rs)

```rust
pub enum ConnectionState {
    Initialized, Connecting, Connected, Disconnected,
    Suspended, Closing, Closed, Failed,
}

pub enum ConnectionEvent {
    Initialized, Connecting, Connected, Disconnected,
    Suspended, Closing, Closed, Failed, Update,
}

pub struct ConnectionStateChange {
    pub previous: ConnectionState,
    pub current: ConnectionState,
    pub event: ConnectionEvent,
    pub reason: Option<ErrorInfo>,
}

pub enum ChannelState {
    Initialized, Attaching, Attached, Detaching,
    Detached, Suspended, Failed,
}

pub enum ChannelEvent {
    Initialized, Attaching, Attached, Detaching,
    Detached, Suspended, Failed, Update,
}

pub struct ChannelStateChange {
    pub previous: ChannelState,
    pub current: ChannelState,
    pub event: ChannelEvent,
    pub reason: Option<ErrorInfo>,
    pub resumed: bool,
    pub has_backlog: bool,
}

pub enum ChannelMode { Presence, Publish, Subscribe, PresenceSubscribe }
```

### Internal (`pub(crate)`)

```rust
pub(crate) enum Action { Heartbeat, Ack, Nack, Connect, Connected, ... }
pub(crate) struct ProtocolMessage { /* wire format */ }
pub(crate) struct ConnectionDetails { /* server metadata */ }
pub(crate) struct AuthDetails { /* re-auth token */ }
pub(crate) struct PublishResult { /* ACK result */ }
pub(crate) mod flags { /* bitmask constants */ }
```

---

## `transport.rs` — Transport Abstraction (`pub(crate)`)

```rust
pub(crate) enum TransportEvent {
    Message(ProtocolMessage),
    Disconnected,
}

#[async_trait]
pub(crate) trait Transport: Send + Sync {
    async fn connect(&self, url: &str) -> Result<Box<dyn TransportConnection>>;
}

#[async_trait]
pub(crate) trait TransportConnection: Send {
    async fn send(&mut self, msg: ProtocolMessage) -> Result<()>;
    async fn recv(&mut self) -> Option<TransportEvent>;
    async fn close(&mut self);
}
```

---

## `http_client.rs` — HTTP Client Abstraction (`pub(crate)`)

```rust
pub(crate) struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[async_trait]
pub(crate) trait HttpClient: Send + Sync {
    async fn execute(&self, request: HttpRequest) -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>;
}
```

No `as_any()`. No reqwest types. Mock and real implementations both implement this trait.

---

## `mock_http.rs` — Test Mock (`pub(crate)`, `#[cfg(test)]`)

```rust
pub(crate) struct CapturedRequest {
    pub method: String,
    pub url: url::Url,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

pub(crate) struct MockResponse { /* status, headers, body, simulate_network_error */ }

impl MockResponse {
    pub fn json(status: u16, body: &serde_json::Value) -> Self;
    pub fn empty(status: u16) -> Self;
    pub fn network_error() -> Self;
    pub fn with_header(self, name: impl Into<String>, value: impl Into<String>) -> Self;
}

pub(crate) struct MockHttpClient { /* handler + captured requests */ }

impl MockHttpClient {
    pub fn new() -> Self;
    pub fn with_handler(handler: impl Fn(&CapturedRequest) -> MockResponse + Send + Sync + 'static) -> Self;
    pub fn queue_response(&self, response: MockResponse);
    pub fn captured_requests(&self) -> Vec<CapturedRequest>;
    pub fn request_count(&self) -> usize;
    pub fn reset(&self);
}

impl HttpClient for MockHttpClient;
```

**Injection:** `ClientOptions` has a `pub(crate)` method:
```rust
impl ClientOptions {
    pub(crate) fn rest_with_http_client(self, client: Box<dyn HttpClient>) -> Result<Rest>;
}
```

---

## `mock_ws.rs` — Test Mock (`pub(crate)`, `#[cfg(test)]`)

```rust
pub(crate) struct PendingConnection { /* ... */ }
impl PendingConnection {
    pub fn respond_with_success(self, msg: ProtocolMessage);
    pub fn respond_with_refused(self);
    pub fn respond_with_error(self, msg: ProtocolMessage);
}

pub(crate) struct MockConnection { /* ... */ }
impl MockConnection {
    pub fn send_to_client(&self, msg: ProtocolMessage);
    pub fn send_to_client_and_close(&self, msg: ProtocolMessage);
    pub fn simulate_disconnect(&self);
}

pub(crate) struct CapturedMessage {
    pub channel: Option<String>,
    pub action: Action,
    pub message: ProtocolMessage,
}

pub(crate) struct MockWebSocket { /* ... */ }
impl MockWebSocket {
    pub fn new() -> Self;
    pub fn with_handler(handler: impl Fn(PendingConnection) + Send + Sync + 'static) -> Self;
    pub fn connection_count(&self) -> u32;
    pub fn client_messages(&self) -> Vec<CapturedMessage>;
    pub fn active_connections(&self) -> Vec<MockConnection>;
    pub async fn await_connection(&self) -> PendingConnection;
}
```

`MockTransport` implements the `Transport` trait from `transport.rs`.

---

## Design Decisions Summary

| Decision | Rationale |
|----------|-----------|
| `Option<String>` for encoding | Simpler than `Encoding::None`/`Some`, no name clash with `Option` |
| `&str` / `&[(&str, &str)]` for methods/headers/params | No dependency on reqwest types |
| Single `ErrorInfo` type | Per TI1 spec. One type for `Result<T>`, state changes, and `cause` chaining. No separate `Error` wrapper |
| `pub(crate)` protocol wire types | Users never construct `ProtocolMessage`; state enums are re-exported |
| `pub(crate)` Decode/DecodeRaw/Format | Pagination internals |
| `Transport` trait | Eliminates ~530 lines of duplicated connection loops |
| `HttpClient` trait without `as_any` | Clean injection, no downcasting |
| Builder for both REST and Realtime publish | Consistent API |
| `publish_message()` convenience method | Migration path for simple positional-arg publish |
| Single `Message` for REST and Realtime | No type conversion needed between the two |

## REST State & Sync Design (Phase 3.0)

### State Layout

```rust
pub struct Rest {
    pub(crate) inner: Arc<RestInner>,
}

pub(crate) struct RestInner {
    pub(crate) opts: ClientOptions,
    pub(crate) http_client: Box<dyn HttpClient>,
    pub(crate) auth_state: Mutex<AuthState>,
    pub(crate) fallback_state: Mutex<Option<CachedFallback>>,
}

pub(crate) struct AuthState {
    pub(crate) cached_token: Option<TokenDetails>,
    pub(crate) saved_token_params: Option<TokenParams>,
}

pub(crate) struct CachedFallback {
    pub(crate) host: String,
    pub(crate) expires: Instant,
}
```

**Rationale:**
- `opts` and `http_client` are immutable after creation — no lock needed.
- `auth_state` holds token cache and saved params from `authorize()` (RSA10j).
- `fallback_state` holds the cached successful fallback host with TTL (RSC15f).
- Separate locks because these are independent concerns on different code
  paths — auth renewal never needs fallback state and vice versa. No lock
  ordering issues since neither lock is ever held while acquiring the other.
- Both locks are held only for short reads/writes (clone token out, swap
  token in, read/write fallback host), never across async `.await` points,
  so `std::sync::Mutex` is fine (no `tokio::sync::Mutex` needed).

### Token Resolution (per-request)

Every REST request needs an `Authorization` header. Resolution:

```
1. Check credential type from ClientOptions:
   ┌─ Key (no useTokenAuth) ─────→ Basic auth header. Done.
   │
   └─ Token auth (any of: useTokenAuth, Callback, Url, TokenDetails, TokenRequest)
      │
      2. Lock auth_state. Read cached_token.
      │
      ├─ cached_token exists and not expired ──→ Bearer <token>. Done.
      │
      └─ cached_token missing or expired
         │
         3. Unlock auth_state (don't hold lock across I/O).
         4. Obtain new token:
            ├─ Key credential ──→ create_token_request() + POST /keys/.../requestToken
            ├─ Callback ────────→ invoke callback → returns TokenDetails or TokenRequest
            ├─ Url ─────────────→ GET/POST auth_url → parse response as TokenDetails/TokenRequest
            └─ TokenRequest ────→ POST /keys/.../requestToken with the signed request
         5. Lock auth_state. Store new token. Unlock.
         6. Bearer <new_token>. Done.
```

**Edge case — concurrent requests during renewal:**
Multiple requests may discover an expired token simultaneously. Each will
attempt renewal independently. The last one to lock wins (stores its token).
This is acceptable because:
- Token requests are idempotent (new token each time, old one still valid until expiry).
- Double-renewal wastes one HTTP call but doesn't cause incorrect behavior.
- Avoiding this would require a "renewal in progress" semaphore that adds
  complexity for negligible benefit in a REST client.

### Request Pipeline

```
rest.request("GET", "/time")
  .params(&[("key", "val")])
  .headers(&[("X-Custom", "value")])
  .send()
    │
    ▼
┌─────────────────────────────────────────────────┐
│  1. Build HttpRequest                           │
│     - method, full URL (scheme + host + path)   │
│     - Standard headers:                         │
│       · X-Ably-Version: 2                       │
│       · Ably-Agent: ably-rust/VERSION           │
│       · Content-Type: application/json          │
│         (or application/x-msgpack)              │
│       · Accept: same as Content-Type            │
│     - Auth header (via token resolution above)  │
│     - request_id if add_request_ids enabled     │
│     - User-provided headers/params              │
│     - Body serialization (JSON or msgpack)      │
└───────────────┬─────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────┐
│  2. Execute with retry loop                     │
│                                                 │
│     if cached_fallback valid:                   │
│       hosts = [cached] + [primary]              │
│              + shuffle(fallback_hosts)           │
│     else:                                       │
│       hosts = [primary]                         │
│              + shuffle(fallback_hosts)           │
│     max_attempts = 1 + http_max_retry_count     │
│                                                 │
│     for attempt in 0..max_attempts:             │
│       host = hosts[attempt % hosts.len()]       │
│       response = http_client.execute(request)   │
│                                                 │
│       match response.status:                    │
│         200-299 → if host != primary:           │
│                     cache fallback (RSC15f)     │
│                   deserialize, return Ok        │
│         401 + code 40140-40149 →                │
│           if can_renew_token():                 │
│             renew_token()                       │
│             retry with NEW auth header          │
│             (counts as 1 attempt, not a         │
│              fallback — same host)              │
│           else: return Err                      │
│         400-499 (non-token) → return Err        │
│         500-599 → continue to next fallback     │
│         network error → continue to next        │
│                         fallback                │
│                                                 │
│     all attempts exhausted → return last Err    │
└─────────────────────────────────────────────────┘
```

**Key behaviors:**
- Token renewal is attempted once per request, before fallback rotation.
  If the renewed token also gets 401, the error is propagated (no infinite loop).
- Fallback hosts are shuffled once at request start, not per-attempt (RSC15a).
- `http_request_timeout` applies per-attempt, not total.
- Fallback is only triggered by 5xx or network errors, never 4xx (RSC15l).
- If `fallback_hosts` is empty, no retries on 5xx (RSC15m).

### Fallback Host State (RSC15f)

When a fallback host succeeds, it is cached with a TTL of
`fallback_retry_timeout` (default 10 minutes). Subsequent requests use the
cached fallback as the **first** host to try (before primary), until the TTL
expires. After expiry, requests revert to trying the primary host first.

```rust
// On successful fallback:
state.cached_fallback_host = Some(CachedFallback {
    host: successful_host.clone(),
    expires: Instant::now() + opts.fallback_retry_timeout,
});

// On request start:
let preferred_host = state.cached_fallback_host
    .as_ref()
    .filter(|c| c.expires > Instant::now())
    .map(|c| c.host.clone());
// If preferred_host is Some, try it first; otherwise try primary.
// If the cached host fails, clear it and fall through to normal fallback rotation.
```

This state lives in `RestInner.fallback_state` behind its own `Mutex`,
independent of auth state.

### Auth Methods

```rust
impl Auth<'_> {
    // RSA8: Create a signed TokenRequest (local operation, no network)
    pub fn create_token_request(&self, params: &TokenParams, options: &AuthOptions) -> Result<TokenRequest> {
        // Requires Key credential
        // Signs with HMAC-SHA256
        // Generates nonce if not provided
        // Uses server time if queryTime set (requires network call)
    }

    // RSA8: Request a token from Ably (network call)
    pub async fn request_token(&self, params: &TokenParams, options: &AuthOptions) -> Result<TokenDetails> {
        // 1. If AuthCallback/AuthUrl: obtain TokenRequest/TokenDetails from callback/url
        // 2. If TokenRequest (from callback or Key): POST /keys/{keyName}/requestToken
        // 3. Cache result in auth_state.cached_token
        // 4. Return TokenDetails
    }

    // RSA10: Authorize — request_token + update saved params
    pub async fn authorize(&self, params: &TokenParams, options: &AuthOptions) -> Result<TokenDetails> {
        // 1. Save params as default for future renewals (RSA10j)
        // 2. Call request_token(params, options)
        // 3. Update cached_token
        // 4. Return TokenDetails
    }
}
```

**`authorize()` saves params (RSA10j):** After `authorize(params, opts)`, any
future automatic token renewal (triggered by 401) uses these saved params
instead of requiring the caller to pass them again. This is stored in
`auth_state.saved_token_params`.

### Response Deserialization

```
Response body → detect format → deserialize
  │
  ├─ Content-Type: application/json → serde_json::from_slice
  ├─ Content-Type: application/x-msgpack → rmp_serde::from_slice
  └─ Missing/unknown → try JSON first, then msgpack (RSC8d)
```

The response format is independent of the request format — the server may
respond in a different format than requested (e.g., error responses are
always JSON). The deserializer checks the Content-Type header.

### Pagination

```rust
pub(crate) struct PaginatedResultInner<T> {
    rest: Rest,           // cloned Arc for follow-up requests
    items: Vec<T>,
    next_url: Option<String>,
    first_url: Option<String>,
}
```

Paginated results hold a `Rest` clone (cheap Arc bump) to make follow-up
requests. The `next()` and `first()` methods use the Link header URLs
directly, going through the same request pipeline (with auth, retry, etc.).

### Thread Safety Summary

| Component | Sync primitive | Reason |
|-----------|---------------|--------|
| `RestInner.opts` | None (immutable) | Set once at creation |
| `RestInner.http_client` | None (trait obj, internally sync) | `HttpClient: Send + Sync` |
| `RestInner.auth_state` | `std::sync::Mutex` | Token cache + saved params |
| `RestInner.fallback_state` | `std::sync::Mutex` | Cached fallback host + TTL |
| `MockHttpClient.queue` | `std::sync::Mutex` | Test response queue |
| `MockHttpClient.requests` | `std::sync::Mutex` | Test request capture |

Total: **2 locks** on the production REST client (auth + fallback, independent).

### ClientOptions → Rest Construction

```rust
impl ClientOptions {
    pub fn rest(self) -> Result<Rest> {
        let http_client = self.http_client.take()
            .unwrap_or_else(|| Box::new(ReqwestHttpClient::new(&self)));
        let auth_state = AuthState {
            cached_token: self.initial_token_details(),
            saved_token_params: None,
        };
        Ok(Rest {
            inner: Arc::new(RestInner {
                opts: self,
                http_client,
                auth_state: Mutex::new(auth_state),
            }),
        })
    }

    // Test injection point
    pub(crate) fn rest_with_http_client(self, client: Box<dyn HttpClient>) -> Result<Rest> {
        // Same as rest() but uses provided client instead of reqwest
    }
}
```

If the user provided a token string or TokenDetails in ClientOptions, it becomes
the initial `cached_token`. If they provided a Key (without `use_token_auth`),
`cached_token` starts as `None` and basic auth is used directly.

---

## Deferred to Later Phases

- Realtime state management / Mutex reduction (Phase 4)
- Connection loop architecture (Phase 5.1)

---

## Phase R Amendments (2026-06-10)

API changes made during REST remediation; supersede earlier sections where they conflict.

### Auth
- `AuthOptions` is the full AO2 shape: key, token, token_details, auth_callback,
  auth_url, method (default "GET"), headers, params, query_time.
- `create_token_request` / `request_token` / `authorize` take
  `(Option<&TokenParams>, Option<&AuthOptions>)`; `create_token_request` is async
  (queryTime may query /time). `request_token` never mutates library auth state
  (RSA8f); `authorize` saves params/options and forces token auth (RSA10a).
- `AuthToken` gains a `Token(String)` variant (JWT strings from callbacks).
- `Auth::client_id()` added (RSA7/RSA12).
- `AuthState` carries saved_auth_options, forced_token_auth, time_offset_ms.
  Still a single Mutex; never held across await.

### Publish
- `PublishBuilder::send()` returns `PublishResult { serials: Vec<Option<String>>,
  message_id }` (RSL1n/PBR2). `messages(Vec<Message>)` enables multi-message
  publish (single → object body, multiple → array). `cipher()` is real (RSL5)
  and overrides the channel cipher.
- Idempotent ids: `base64url(9 random bytes):index` per publish (RSL1k1),
  default on (TO3n).

### request()
- `Rest::request()` returns `HttpPaginatedResponse` (HP1-HP8): items normalised
  to an array, status_code/success/error_code/error_message/headers accessors,
  Link-header pagination, per-request `version()` override (RSC19f1). HTTP error
  statuses are inspectable responses, NOT Err. The old `Response` type remains
  only as an internal shape.

### Hosts (REC1/REC2)
- New `endpoint()` option (hostname | routing policy | "nonprod:[id]").
  `environment()`/`rest_host()`/`realtime_host()` are deprecated overrides and
  mutually exclusive with it. `resolve_hosts()` computes `primary_host` +
  `resolved_fallback_hosts` at build time. Defaults: main.realtime.ably.net,
  main.[a-e].fallback.ably-realtime.com.

### Channel
- `Channel::status()` → `ChannelDetails { channel_id, status: ChannelStatus
  { is_active, occupancy: ChannelOccupancy { metrics: ChannelMetrics } } }`
  (RSL8/CHD2/CHS2/CHO2/CHM2). `Channel::set_options(ChannelOptions)` updates the
  handle's cipher (RSL7).

### Decision: REST channel collection semantics (RSN)
The UTS channels_collection tests assume stored channel instances with identity
semantics (get returns the same instance; release() removes it). This SDK keeps
REST channels as cheap ephemeral accessors (`Channels<'a>::get` returns a value
borrowing `&Rest`): Rust has no object identity to observe, all channel state a
user can set (cipher) lives on the handle, and a stored collection would force
`Arc<RealtimeChannel>`-style sharing onto stateless REST usage. Identity/release
semantics will exist where they matter — the realtime `Channels` collection
(Phase 4/5). The RSN-labelled REST tests assert name consistency only and do not
claim identity coverage.

### Logging (RSC2)
- `log_level(LogLevel)` + `log_handler(Fn(LogLevel, &str))`, severity-filtered
  (None suppresses all). Request logs carry method/host/path; failures log at
  Error. Structured context objects (TO3c) are deferred.

---

# Realtime State & Concurrency (Phase 4)

This section defines how realtime state is owned, mutated, and observed. It exists
because the previous implementation accumulated 18 mutexes on `ConnectionInner` and
25 on `ChannelInner` with no coherent synchronisation concept. This design has
**one concept** and derives everything from it. §14 defines how adherence is
enforced mechanically as implementation proceeds.

## 1. The single synchronisation concept: one event loop owns all state

All mutable realtime state — the connection state machine, every channel's state
machine, presence maps, pending ACKs, queued messages, timers — is owned exclusively
by **one tokio task**, the *connection loop*. It is plain owned data (`&mut self`):
**zero locks on any protocol state**.

Nothing else can read or write that state directly. The world interacts with the
loop through exactly four primitives:

| Primitive | Direction | Used for |
|---|---|---|
| `mpsc::UnboundedSender<LoopInput>` | in | commands from handles, transport events, completions of spawned I/O |
| `oneshot::Sender<Result<T>>` (carried inside commands) | out | request/response replies (attach, publish, ping, …) |
| `tokio::sync::watch` | out | state snapshots (`ConnectionState`, per-channel `ChannelSnapshot`) |
| `tokio::sync::broadcast` | out | ordered state-change event streams |

The loop **never awaits I/O**. Anything that blocks (transport connect, token
acquisition, transport writes) is done by short-lived spawned tasks that post their
outcome back into the loop as a `LoopInput`. The loop's body is therefore pure,
fast state manipulation; every input is processed to completion before the next —
which is what makes every ordering guarantee in §10 hold by construction.

```
                 ┌────────────────────────────────────────────────┐
 Connection ───┐ │            CONNECTION LOOP (one task)          │
 RealtimeChannel─┤ commands │  owns: ConnectionCtx                 │
 RealtimePresence┘ (mpsc)   │    state machine, channels map,      │
                 │          │    presence maps, pending ACKs,      │
 reader task ──── transport │    queues, timers                    │
 spawned conn ─── events    │                                      │
 token task  ──── (same     │  emits: watch snapshots, broadcast   │
                 │  mpsc)   │  events, oneshot replies             │
                 └──────────┴──────────────┬───────────────────────┘
                                           │ try_send (never awaits)
                                     writer task ──► TransportConnection
```

### The one lock that is not protocol state

`Channels` (the public collection) holds `Mutex<HashMap<String, Arc<RealtimeChannel>>>`
— a registry of *handle objects only* (name, command sender, watch receiver). It
exists because `Channels::get/exists/names` are synchronous API. It contains no
protocol state, is held only for map operations, and never across an await. Channel
*state* lives in the loop. This is the entire lock inventory of the realtime client
(plus the two existing REST locks, §13) — see §14 for how this inventory is enforced.

## 2. State inventory

Everything mutable, its owner, and how the outside world sees it:

| State | Lives in | Written by | Observed via |
|---|---|---|---|
| `ConnectionState` + `ConnectionEvent` | `ConnectionCtx` | loop | `watch` snapshot + `broadcast` events |
| connection `id`, `key`, `error_reason`, current host | `ConnectionCtx` | loop | part of connection `watch` snapshot |
| `ConnectionDetails` (clientId, connectionStateTtl, maxIdleInterval, maxMessageSize) | `ConnectionCtx` | loop (CONNECTED) | snapshot fields where public |
| `msg_serial` counter (RTN7b) | `ConnectionCtx` | loop | not observable |
| pending-ACK queue (serial → oneshot repliers) | `ConnectionCtx` | loop | resolves publish/presence futures |
| connection-wide queued messages (RTL6c2, queueMessages) | `ConnectionCtx` | loop | not observable |
| transport generation counter (stale-transport guard) | `ConnectionCtx` | loop | not observable |
| retry bookkeeping (attempt count, fallback host index) | `ConnectionCtx` | loop | not observable |
| per-channel `ChannelState`, `error_reason` | `ChannelCtx` | loop | per-channel `watch` + `broadcast` |
| per-channel options (params, modes, cipher) | `ChannelCtx` | loop | snapshot |
| `attach_serial`, `channel_serial` (RTL15) | `ChannelCtx` | loop | snapshot |
| message subscriber registry (id, name filter, sender) | `ChannelCtx` | loop | delivers into subscriber mpsc |
| presence map + internal (local-member) map, sync state (RTP1/2/17) | `PresenceCtx` in `ChannelCtx` | loop | presence subscriber mpsc; `get` command replies |
| deferred presence `get(wait_for_sync)` repliers | `PresenceCtx` | loop | replied at sync barrier |
| pending attach/detach repliers + op timers | `ChannelCtx` | loop | resolves attach()/detach() futures |
| all timers (§5) | `ConnectionCtx`/`ChannelCtx` | loop | not observable |
| channel **handle** registry | `Channels` (Mutex) | `Channels::get/release` | sync API |
| token cache / auth state | shared `Rest` (existing `AuthState` Mutex) | REST auth layer | `Auth`/`RealtimeAuth` |

`ConnectionCtx` and `ChannelCtx` are plain structs with **no `pub` fields and no
sync primitives inside**; they are moved into the loop task at construction and
cannot be shared.

## 3. Command/response protocol

`LoopInput` is one enum; a single queue gives a total order over everything the
loop reacts to:

```rust
enum LoopInput {
    Cmd(Command),                  // from public handles
    Transport(TransportInput),     // from reader tasks: Message(pm) | Closed(reason)
    ConnectAttempt(Result<Box<dyn TransportConnection>>, Generation),
    TokenReady(Result<TokenDetails>, Generation),
}

enum Command {
    Connect,
    Close,
    Ping { reply: oneshot::Sender<Result<Duration>> },
    Authorize { reply: oneshot::Sender<Result<TokenDetails>> },
    EnsureChannel { name, snapshot_tx: watch::Sender<ChannelSnapshot>,
                    events_tx: broadcast::Sender<ChannelStateChange> },
    ReleaseChannel { name, reply },
    Attach { name, reply: oneshot::Sender<Result<()>> },
    Detach { name, reply: oneshot::Sender<Result<()>> },
    SetChannelOptions { name, options, reply },
    Publish { name, messages: Vec<Message>, reply: oneshot::Sender<Result<()>> },
    Subscribe { name, filter: Option<String>,
                sub: (SubscriptionId, mpsc::UnboundedSender<Message>) },
    Unsubscribe { name, id: SubscriptionId },
    PresenceAction { name, action, data, client_id, reply },  // enter/update/leave
    PresenceGet { name, options, reply: oneshot::Sender<Result<Vec<PresenceMessage>>> },
    PresenceSubscribe / PresenceUnsubscribe { ... },
    AnnotationSubscribe / AnnotationUnsubscribe { ... },
}
```

Public async methods are thin: build command + oneshot, `send`, `await` the reply.
Command semantics per connection state follow the spec tables — e.g. `Publish`
while CONNECTED sends immediately and registers the ACK replier; while
CONNECTING/DISCONNECTED with `queue_messages` it joins the queue (replier retained);
while SUSPENDED/CLOSED/FAILED it replies immediately with the spec error. Every
command has a defined behaviour in every connection state — the match in the loop
is exhaustive, so the compiler enforces that the table is complete.

`Connect`/`Close` are fire-and-forget (per the existing API); their outcomes are
observable via snapshots/events. Commands sent after the loop has terminated
(client dropped) fail fast: the send error maps to an `ErrorInfo` (80017).

## 4. State observation

- **Snapshots**: `Connection::state()/id()/key()/error_reason()` read
  `watch::Receiver::borrow()` — wait-free, never stale-locked, no loop round trip.
  `RealtimeChannel::state()` etc. likewise from `ChannelSnapshot`.
- **Events**: `on_state_change()` returns a `broadcast::Receiver` (existing API).
  `when_state(target, cb)` spawns a tiny listener task over a receiver.
- **Consistency contract**: the loop updates the `watch` snapshot **before**
  emitting the corresponding `broadcast` event. A listener that reads a snapshot
  while handling event N sees the state from transition ≥ N (never < N). Events
  on one stream are delivered in transition order (broadcast preserves order;
  the loop is the only sender). A lagged broadcast receiver (`RecvError::Lagged`)
  misses intermediate *events* but the snapshot is always current — documented.
- Snapshots are values (no torn reads by construction).

## 5. Timers

All timers are deadlines stored in the loop's state; the loop's `select!` waits on
`sleep_until(earliest)` computed each iteration (O(channels) scan; fine for
realistic counts, a heap is a drop-in optimisation if ever needed). No timer
wheels, no timer tasks, no cancellation races: cancelling = setting the field to
`None`, which the next loop iteration observes.

| Timer | Stored | Set on | Fires → |
|---|---|---|---|
| connect attempt timeout (`realtime_request_timeout`) | ConnectionCtx | CONNECTING entry | attempt failed → DISCONNECTED, schedule retry |
| disconnected retry (`disconnected_retry_timeout`, RTN14d) | ConnectionCtx | DISCONNECTED entry | → CONNECTING |
| suspended retry (`suspended_retry_timeout`, RTN14e) | ConnectionCtx | SUSPENDED entry | → CONNECTING |
| connection state TTL (RTN14e/RTN15a boundary) | ConnectionCtx | first DISCONNECTED | → SUSPENDED (resume no longer possible) |
| activity timeout (maxIdleInterval + realtime_request_timeout, RTN23) | ConnectionCtx | every transport input | transport dead → disconnect path |
| heartbeat/ping deadline (RTN13) | ConnectionCtx | ping sent | ping replier gets timeout error |
| attach/detach op timeout (RTL4f/RTL5f) | ChannelCtx | ATTACHING/DETACHING entry | op replier errored, state per spec |
| channel retry (`channel_retry_timeout`, RTL13b) | ChannelCtx | channel SUSPENDED | re-attach |

## 6. Transport integration

`Transport::connect(url)` is called from a **spawned connect task** (never the
loop): the task first obtains auth (token via the shared REST auth layer if token
auth — also off-loop), builds the URL (RTN2 params: v=6, format, resume/recover
keys captured from the loop state at spawn time), calls `connect`, and posts
`ConnectAttempt(result, generation)`.

On success the loop splits the connection: it spawns a **reader task** (pumps
`TransportConnection::recv()` → `LoopInput::Transport`, tagged with the
generation) and a **writer task** (drains an unbounded `mpsc<ProtocolMessage>`
into `send()`). The loop holds only the writer queue sender + abort handles.

**Generation counter**: every connect attempt increments it; every input from a
transport carries its generation; the loop discards inputs whose generation ≠
current (RTN — "operations on superseded transport"). This single integer replaces
all "is this still the active transport?" reasoning.

Resume/recover (RTN15/RTN16) is loop-side bookkeeping: connection key + serial are
in `ConnectionCtx`; the connect task is handed the resume params as values.
CONNECTED processing (fresh vs resumed vs failed-resume) follows RTN15c by
comparing connection ids and surfacing the error per spec.

## 7. Channel multiplexing: all channels inside the connection loop

Considered: one task per channel. Rejected for v1:
- The wire protocol is a single serialized stream per connection; per-channel tasks
  re-serialize at the socket anyway.
- The coupling RTL specifies (connection state changes fan into every channel:
  RTN8c/RTN11/RTL3; ACKs are connection-scoped serials routed to channel publishes)
  becomes inter-task choreography with exactly the ordering hazards this design
  exists to remove.
- Per-channel CPU work is small (decode/decrypt of one message); throughput is
  socket-bound. If profiling ever disagrees, decode can be offloaded per-channel
  behind the same dispatch point without changing ownership.

So: `channels: HashMap<String, ChannelCtx>` inside the loop; connection-state
effects on channels are a plain in-loop iteration — atomic with the connection
transition that caused them (no observable interleaving gap).

## 8. Message routing and backpressure

Inbound path: reader task → `LoopInput::Transport(Message(pm))` → loop:
1. connection-level actions (ACK/NACK → resolve pending repliers; HEARTBEAT;
   CONNECTED/DISCONNECTED/CLOSED/ERROR → state machine);
2. channel-scoped actions dispatch on `pm.channel`: MESSAGE → decode/decrypt
   (channel cipher) → deliver to matching subscribers; PRESENCE/SYNC → presence
   engine; ATTACHED/DETACHED → channel state machine + op repliers.

Subscriber delivery: each `subscribe()` gets an **unbounded** `mpsc` and the
loop `send`s (wait-free). Unbounded is deliberate: dropping messages silently
would violate correctness expectations, and blocking the loop on a slow consumer
would stall the whole client. The server already bounds the inbound rate per
connection; a slow consumer therefore costs memory proportional to its own lag
only. (A bounded mode with an explicit drop policy can be added later without
design change.) `unsubscribe` removes the sender; receiver drop is detected on
next send and the entry pruned.

## 9. Presence

`PresenceCtx` (inside `ChannelCtx`, loop-owned): the members map, the internal
(local-entries) map (RTP17), sync bookkeeping (`sync_in_progress`, expected
serial, residual members set for RTP19), and deferred `get(wait_for_sync=true)`
repliers. The RTP2 newness comparison, SYNC application, RTP17b re-entry on
attach, and RTP19/19a reconciliation are all plain in-loop functions over that
struct. Presence events go to presence subscribers (same unbounded-mpsc pattern;
the public callback API wraps a receiver + spawned dispatch task). `enter/update/
leave` are `PresenceAction` commands: sent as protocol messages with ACK repliers,
and recorded in the internal map per RTP17 on ACK.

## 10. Invariants (each holds by construction of §1)

1. Every state transition (connection and channel) is decided by exactly one
   thread of execution; no transition can be observed "in progress".
2. `watch` snapshot updates precede their `broadcast` events (§4 contract).
3. Events on any one stream are delivered in transition order.
4. ACK/NACK resolution is FIFO over `msg_serial` (RTN7); a publish replier is
   resolved exactly once (ACK, NACK, or connection-level failure per RTN7c).
5. Per channel, message delivery order to every subscriber equals wire arrival
   order; presence events are emitted only after the map mutation they describe.
6. Inputs from superseded transports are inert (generation guard, §6).
7. Connection-state side effects on channels are atomic with the connection
   transition (§7).
8. After `close()`, queued/pending operations resolve with the spec error —
   repliers are never leaked (loop drains them on terminal states).

## 11. Alternatives considered

| Alternative | Why rejected |
|---|---|
| One coarse `Mutex<AllState>` with methods locking it | Locks held across protocol logic invite await-holding bugs; event callbacks re-entering the API deadlock; readers can observe mid-compound-transition state; the Mutex becomes a de-facto event loop with none of its ordering guarantees. |
| Fine-grained locks per field (the previous implementation) | The motivating failure: 18+25 mutexes, transitions composed of multiple independently-locked writes, no serialization of compound transitions, races between connection and channel updates. |
| Actor per channel + connection actor | Maximum parallelism, but RTL/RTP couple channel and connection state tightly; cross-actor invariants (§10.4, §10.7) need message choreography that reintroduces ordering hazards; no profiling evidence the parallelism is needed (socket-bound). Kept as a later optimisation seam at the §8 dispatch point. |
| Shared state + atomics | Doesn't compose: compound transitions (state + error_reason + id + events) can't be made atomic across several atomics. |

## 12. Test sourcing: regenerate from the UTS; ported tests are raw material

**Decision (approved 2026-06-10): realtime tests are derived from the UTS specs,
not reused wholesale from the port.** Phase R demonstrated that tests ported from
an implementation pin that implementation's bugs (rsa9h pinned the RSA5/RSA6
default bug; tm3 pinned the wrong TM5 wire values) — and that the tests we trust
most are the ones derived from UTS pseudo-code.

Per Phase 5 stage:
1. The stage's tests are written from the `uts/realtime/unit/*.md` pseudo-code as
   the authoritative source (same discipline as Phase R: write the test, see it
   fail for the right reason, implement).
2. The 440 ported tests in `tests_realtime_unit_*.rs` serve two subordinate roles:
   - a **coverage cross-check**: the stage is not done until every ported test in
     its spec range is either superseded by a UTS-derived test or explicitly
     adopted; anything the ported tests cover that the UTS does not (the port
     came from 1,232 ably-js tests) is flagged and kept, marked with its
     provenance — never silently lost;
   - a **quarry**: where a ported test already matches the UTS pseudo-code
     faithfully, it is adopted verbatim (cheaper than rewriting, same provenance
     guarantee as derivation, recorded as adopted).
3. Ported tests in the stage's range are deleted only when superseded or adopted;
   until then they remain `todo!()`-failing in the tree, so the count of remaining
   ported tests is a live progress metric.
4. A ported test that cannot be expressed against this design is a design defect
   to raise at review, not a test to drop.

### Mock infrastructure

The mock surface keeps the shapes the ported tests use (so adoption is cheap) and
is what UTS-derived tests use too:

- `MockTransport` implements `Transport`; `MockWebSocket` is the test-facing
  controller. `Transport::connect(url)` (called by the spawned connect task)
  registers a `PendingConnection{url}` and parks on a oneshot —
  `await_connection()` hands it to the test; `respond_with_success(msg)` completes
  it with a `TransportConnection` whose first `recv()` yields `msg`;
  `respond_with_refused/_with_error` complete it with failure.
- `MockConnection::send_to_client(pm)` pushes into the connection's event stream
  → reader task → loop; `simulate_disconnect()` ends the stream.
- `client_messages()` records everything the writer task sends — outbound
  protocol assertions. `Realtime::with_mock(&opts, transport)` and `await_state`
  helpers are kept.
- Determinism: every externally-visible effect flows through the same single
  input queue as production; timer tests use `tokio::time::pause()/advance()`
  (loop timers are `sleep_until`, so virtual time drives them exactly). One loop
  implementation serves mock and real transports — the old code's duplicated
  mock/real connection loops cannot reappear.

## 13. Realtime/REST sharing

`Realtime` owns a `Rest` built from the same `ClientOptions`. All REST-over-
realtime operations (history, REST presence get on a realtime channel, push) call
it directly from handles — they never touch the loop. Auth state (token cache,
saved params, forced token auth) stays in `Rest`'s existing `AuthState` Mutex:
the loop never holds it (token work happens in spawned tasks, §6).
Server-initiated reauth (RTN22/RTC8): AUTH protocol message → loop spawns token
task → `TokenReady` → loop sends AUTH with new token over the writer queue.
`RealtimeAuth::authorize()` delegates to REST authorize, then issues an
`Authorize` command so the loop applies RTC8 (in-place reauth) with the result.

## Stage 5.6 amendments (2026-06-11, approved)

- **Fallible `Channels::get_with_options`** — returns
  `Result<Arc<RealtimeChannel>>`: `Err(40000)` when the supplied options
  would force a reattachment (params/modes changed while ATTACHING/ATTACHED,
  RTS3c1); safe updates (cipher, attachOnSubscribe) are applied via the loop
  (RTS3c) with EVENTUAL visibility — `options()` reads the loop-published
  snapshot. `get(name)` stays infallible and never touches options.
- **Authoritative channel options live in `ChannelCtx`** and are observable
  through `ChannelSnapshot.options`; the handle no longer carries a copy.
- **`ChannelStateChange.retry_in`** added (RTL13b/RTB1): the delay to the
  scheduled reattach retry on SUSPENDED transitions.
- **Derived channels (RTS5)**: name qualification `[filter=<b64>?<params>]`,
  registry semantics unchanged.

## Observability (logging) policy — NORMATIVE

Added 2026-06-12 after review found 6 log call sites in the whole library and
silent-discard paths. This section is binding for all subsequent work; per
CLAUDE.md, instrumentation per this policy is part of every change's
definition of done.

Levels (RSC2 scale) and what belongs at each:

- **Error** — anything discarded or failed that a user would need to diagnose:
  undecodable inbound frames (including tolerant-decode failures), undecodable
  message/presence/annotation entries, ACK/NACK for unknown serials, transport
  write failures, token acquisition failures that surface to state.
- **Major** — material lifecycle events: connection state transitions (with
  reason), channel state transitions (with reason), resume outcome
  (success/failed + why), forced disconnects, re-entry failures, warnings
  (missing modes, non-renewable tokens).
- **Minor** — protocol-event detail: retry scheduling (delay, attempt),
  host-fallback steps, AUTH/token renewal flow, sync start/complete,
  queue/flush of pending operations.
- **Micro** — trace: entry to every public API method (name + key arguments),
  HTTP request/response lines, protocol messages sent/received (action +
  channel + serial; never payloads or credentials).

Rules:
1. **No silent discards.** Every code path that drops data it received or
   abandons an operation MUST log (Error or Major) with enough context to
   diagnose — channel, action, serial as applicable.
2. **Never log secrets or payloads**: no tokens, keys, message data, or
   presence data at any level; ids/serials/names are fine.
3. New public API methods land WITH their Micro entry trace; new state
   machines land WITH their Major transition logs.
4. The default client has no handler installed; library code must not assume
   a sink exists (the `log` helper gates this) — but features SHOULD be
   testable by installing a handler, and discard-path tests assert the log.

## 14. Enforcement: how this design stays adhered to

Prose does not survive implementation pressure; these mechanisms do:

1. **The lock-inventory ratchet (mechanical).** `tests_design_conformance.rs`
   embeds the realtime source files via `include_str!` and fails if any sync
   primitive (`Mutex`, `RwLock`, `Atomic*`, `OnceLock`, …) appears in them beyond
   the whitelist documented here. Steady-state whitelist: exactly one — the
   `Channels` handle registry. (The two temporary pre-design stub presence
   mutexes were deleted in stage 5.7 as planned; the channel.rs allowance is
   1, the steady state.) The ratchet runs on every
   `cargo test`; the first "harmless extra lock" fails the build and forces the
   design conversation at the moment it matters. Changing the whitelist requires
   editing the conformance test AND this section in the same commit — which is
   precisely the review trigger. A companion test rejects `pub` fields on the
   loop-owned state structs (§2).
2. **CLAUDE.md binding contract.** CLAUDE.md (loaded into every working session)
   carries a compact, imperative statement of the invariants with a pointer here.
   Any change to the contract requires changing this document first, with
   explicit human approval, before any code.
3. **Per-stage conformance line.** Every Phase 5 stage's PROGRESS.md entry must
   state: lock inventory unchanged (conformance test passing), tests derived
   from UTS (with adopted/superseded counts for the stage's ported-test range).
4. **Design-change-before-code rule.** If an implementation step appears to need
   a new sync primitive, a new task with shared state, or loop-bypassing access,
   work STOPS on that step; the change is proposed as a DESIGN.md edit and
   reviewed by a human first. A workaround that avoids the conformance test
   (e.g. hiding a lock in another module) is a violation of the same rule.
5. **UTS coverage ratchet (mechanical).** `uts_coverage.txt` is a traceability
   matrix with one line per UTS Test ID (rest/unit + realtime/unit): either
   `id => rust_test_fn[, ...]` (covered by these passing tests) or
   `id !! reason` (deliberately not covered — a future stage or a recorded
   deferral). `tests_uts_coverage.rs` walks the spec tree on every `cargo
   test` and fails on any spec ID the matrix doesn't account for, any matrix
   entry the spec no longer defines, any mapped test fn that no longer
   exists, and any reasonless exclusion. New spec-repo Test IDs therefore
   fail the build until dispositioned, and renaming/deleting a covering test
   breaks the link visibly. Closing a stage means converting that stage's
   exclusions into mappings (bootstrap via `tools/uts_coverage_generate.py`;
   the committed matrix is curated, its diffs are review material). Added
   2026-06-10 after an audit found ~50% ID-level coverage in a spot-checked
   spec file — including a real behavior bug (RTN13d) pinned by a wrong test.

## Implementation order note

Phase 5.1 builds: `LoopInput`/`Command`, `ConnectionCtx`, the loop skeleton with
exhaustive state matching, generation guard, connect/close + mock transport —
then each subsequent stage (5.2–5.8) adds fields to the same two structs and arms
to the same matches. Nothing in later stages introduces a new synchronisation
mechanism (§14.4).

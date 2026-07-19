# Migration guide

The previously published `ably` crate (0.2.0) was **REST-only**. This release is
a from-scratch rewrite: it keeps a REST API — with the breaking changes below —
and adds a full **Realtime** API (connections, channel attach/subscribe,
presence, and vcdiff delta decoding).

This guide covers the changes to the existing REST surface. For the new realtime
API see the [README](./README.md); for the architecture see
[DESIGN.md](./DESIGN.md).

## Construction

Construct clients through `ClientOptions`. The infallible `Rest::from("key")`
shortcut has been removed.

```rust
// before
let client = ably::Rest::from("appId.keyId:secret");

// now
let client = ably::ClientOptions::new("appId.keyId:secret").rest()?;
// or, for a realtime client:
let client = ably::ClientOptions::new("appId.keyId:secret").realtime()?;
```

`ClientOptions::new` still accepts either an API key or a token string;
`with_key` and `with_token` remain. The terminal method is `.rest()` (or the new
`.realtime()`), each returning `Result`.

## Error type

The public error type is renamed `Error` → **`ErrorInfo`** (the TI1 shape), and
`ably::Error` is no longer exported.

```rust
// before
fn f() -> ably::Result<()> { Err(ably::Error::new(code, "msg")) }

// now
fn f() -> ably::Result<()> { Err(ably::ErrorInfo::new(code, "msg")) }
```

`Result<T>` and the `ErrorCode` enum are unchanged.

## Channels and presence access

`rest.channels()` is still a method. Presence is now accessed through a
**method** rather than a field:

```rust
// before
let members = channel.presence.get().send().await?;

// now
let members = channel.presence().get().send().await?;
```

## Publishing

The publish builder is unchanged (`name`/`string`/`json`/`binary`/`extras`/
`send`), but `send()` now returns a `PublishResult` (the per-message serials)
instead of `()`:

```rust
let result = channel.publish().name("event").string("hello").send().await?;
```

## History and presence pagination

`PaginatedResult::items()` is now **synchronous and returns a slice** (it was an
`async` method returning a `Vec`). Iterate pages with `has_next()`/`next()`
instead of the `pages()` stream:

```rust
// before
let page = channel.history().send().await?;
for msg in page.items().await? { /* ... */ }

// now
let mut page = channel.history().send().await?;
loop {
    for msg in page.items() { /* ... */ }
    match page.next().await? {
        Some(next) => page = next,
        None => break,
    }
}
```

## Messages

`Message.encoding` is now `Option<String>` (was a dedicated `Encoding` type).
`Message` also gains fields for the mutable-message features (`action`,
`serial`, `version`, `annotations`). `Data` (`String`/`JSON`/`Binary`/`None`) is
unchanged.

## Authentication and tokens

`rest.auth()` is unchanged as an accessor. `request_token` and
`create_token_request` now take **optional** params/options
(`Option<&TokenParams>`, `Option<&AuthOptions>`) so both can be omitted, and a
new `authorize()` method establishes token auth and caches the token (RSA10):

```rust
// before
let details = client.auth().request_token(&params, &options).await?;

// now
let details = client.auth().request_token(None, None).await?;
// or with arguments:
let details = client.auth().request_token(Some(&params), Some(&options)).await?;
```

## Encryption

Channel cipher params are now built with a builder; the `generate_random_key`
helper and `Key256`/`Key128` key types have been removed. Supply a key as raw
bytes (`.key(Vec<u8>)`) or a base64 string (`.string(&str)`):

```rust
// before
let key = ably::crypto::generate_random_key::<ably::crypto::Key256>();
let params = ably::rest::CipherParams::from(key);

// now
let params = ably::crypto::CipherParams::builder()
    .string("<base64-encoded-key>")?
    .build()?;

let channel = rest.channels().name("my-channel").cipher(params).get();
```

## New: the Realtime API

This is the main addition. `ClientOptions::new(key).realtime()?` returns a
`Realtime` client with a `Connection` (state, events) and `channels` supporting
attach/detach, subscribe, publish, presence, and automatic vcdiff delta
decoding. See the [README](./README.md) for a worked example.

## Developer preview: parity gaps

Some capabilities available in other Ably SDKs are not yet implemented in this
release: push device registration (LocalDevice) and OS network-connectivity
events (RTN20). For production workloads, use a
[generally available Ably SDK](https://ably.com/docs/sdks).

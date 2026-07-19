# [Ably](https://www.ably.com)

[![Check](https://github.com/ably/ably-rust/actions/workflows/check.yml/badge.svg)](https://github.com/ably/ably-rust/actions/workflows/check.yml)
[![Features](https://github.com/ably/ably-rust/actions/workflows/features.yml/badge.svg)](https://github.com/ably/ably-rust/actions/workflows/features.yml)

_[Ably](https://ably.com) is the platform that powers synchronized digital experiences in realtime. Whether attending an event in a virtual venue, receiving realtime financial information, or monitoring live car performance data – consumers simply expect realtime digital experiences as standard. Ably provides a suite of APIs to build, extend, and deliver powerful digital experiences in realtime for more than 250 million devices across 80 countries each month. Organizations like Bloomberg, HubSpot, Verizon, and Hopin depend on Ably’s platform to offload the growing complexity of business-critical realtime data synchronization at global scale. For more information, see the [Ably documentation](https://ably.com/documentation)._

This is a Rust client library for Ably, providing both the **REST** API and the
**Realtime** API (connection management, channel attach/subscribe, presence,
and vcdiff delta decoding).

**NOTE: This SDK is a developer preview and not considered production ready.**

## Installation

Add the `ably` and `tokio` crates to your `Cargo.toml`:

```toml
[dependencies]
ably = "0.2"
tokio = { version = "1", features = ["full"] }
```

The client is built from `ClientOptions`, using an API key or a token. Call
`.rest()` for a REST client or `.realtime()` for a realtime client:

```rust
let rest = ably::ClientOptions::new("xVLyHw.SmDuMg:<secret>").rest()?;
let realtime = ably::ClientOptions::new("xVLyHw.SmDuMg:<secret>").realtime()?;
```

For token authentication, set an auth URL or callback on the options before
building (see [authentication](https://ably.com/docs/auth)).

## Realtime

```rust
let client = ably::ClientOptions::new("xVLyHw.SmDuMg:<secret>").realtime()?;
let channel = client.channels.get("my-channel");
channel.attach().await?;

// Subscribe — each subscription yields a receiver of decoded messages.
let (_sub_id, mut messages) = channel.subscribe();
tokio::spawn(async move {
    while let Some(msg) = messages.recv().await {
        println!("received: {:?}", msg.data);
    }
});

// Publish.
channel.publish().name("greeting").string("hello").send().await?;
```

Connection state is available on `client.connection` (`state()`,
`on_state_change()`, etc.).

### Presence

```rust
let presence = channel.presence();
presence.enter(Some(serde_json::json!({ "status": "online" }))).await?;
let members = presence.get().await?;
```

### Delta compression

Request vcdiff deltas per channel via channel params; the SDK decodes them
automatically (the `vcdiff-decode` decoder is bundled — no plugin required):

```rust
use std::collections::HashMap;
let opts = ably::channel::RealtimeChannelOptions {
    params: Some(HashMap::from([("delta".to_string(), "vcdiff".to_string())])),
    ..Default::default()
};
let channel = client.channels.get_with_options("my-channel", opts)?;
```

## REST

### Publish a message

```rust
let channel = rest.channels().get("my-channel");

// string
channel.publish().string("a string").send().await?;

// JSON
#[derive(serde::Serialize)]
struct Point { x: i32, y: i32 }
channel.publish().json(Point { x: 3, y: 4 }).send().await?;

// binary
channel.publish().binary(vec![0x01, 0x02, 0x03, 0x04]).send().await?;
```

### Retrieve history

```rust
let mut page = rest.channels().get("my-channel").history().send().await?;
loop {
    for msg in page.items() {
        println!("message data = {:?}", msg.data);
    }
    match page.next().await? {
        Some(next) => page = next,
        None => break,
    }
}
```

### Presence

```rust
let members = rest.channels().get("my-channel").presence().get().send().await?;
for member in members.items() {
    println!("present: {:?}", member.client_id);
}
```

### Request a token

```rust
let token = rest.auth().request_token(None, None).await?;
```

## Encrypted message data

When a 128- or 256-bit key is provided to a channel, message `data` is encrypted
and decrypted automatically using that key. The secret key is never transmitted
to Ably. See https://ably.com/docs/realtime/encryption.

```rust
// Provide a base64-encoded 128- or 256-bit key (keep it secret; it is never
// sent to Ably). A raw key can be supplied instead with `.key(bytes)`.
let params = ably::crypto::CipherParams::builder()
    .string("<base64-encoded-key>")?
    .build()?;
let channel = rest.channels().name("my-channel").cipher(params).get();

channel
    .publish()
    .name("name is not encrypted")
    .string("sensitive data is encrypted")
    .send()
    .await?;
```

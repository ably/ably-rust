[![Check](https://github.com/ably/ably-rust/actions/workflows/check.yml/badge.svg)](https://github.com/ably/ably-rust/actions/workflows/check.yml)
[![License](https://img.shields.io/github/license/ably/ably-rust)](https://github.com/ably/ably-rust/blob/main/LICENSE)

# Ably Pub/Sub Rust SDK

Build any realtime experience using Ably’s Pub/Sub Rust SDK.

Ably Pub/Sub provides flexible APIs that deliver features such as pub-sub messaging, message history, presence, and push notifications. Utilizing Ably’s realtime messaging platform, applications benefit from its highly performant, reliable, and scalable infrastructure.

Find out more:

* [Ably Pub/Sub docs.](https://ably.com/docs/basics)
* [Ably Pub/Sub examples.](https://ably.com/examples?product=pubsub)

> [!IMPORTANT]
> This SDK is a developer preview and is not considered production ready.

---

## Getting started

Everything you need to get started with Ably:

* [Getting started with Pub/Sub.](https://ably.com/docs/getting-started/quickstart)
* [Ably Pub/Sub basics.](https://ably.com/docs/basics)

---

## Supported platforms

Ably aims to support a wide range of platforms. If you experience any compatibility issues, open an issue in the repository or contact [Ably support](https://ably.com/support).

The following platforms are supported:

| Platform | Support |
|----------|---------|
| Rust     | Stable toolchain, edition 2021 |

> [!NOTE]
> This SDK works across Linux, macOS, and Windows. An async runtime ([Tokio](https://tokio.rs)) is required.

---

## Installation

The SDK is published to [crates.io](https://crates.io/crates/ably). Add it, together with an async runtime, to your `Cargo.toml`:

```toml
[dependencies]
ably = "0.2"
tokio = { version = "1", features = ["full"] }
```

Instantiate a client from an API key or token. Use `.realtime()` for a realtime client or `.rest()` for a REST-only client:

```rust
use ably::ClientOptions;

let realtime = ClientOptions::new("your-ably-api-key").realtime()?;
```

---

## Usage

The following code connects to Ably's realtime messaging service, subscribes to a channel to receive messages, and publishes a test message to that same channel.

```rust
use ably::ClientOptions;

#[tokio::main]
async fn main() -> ably::Result<()> {
    // Initialize the Ably realtime client (connects automatically)
    let client = ClientOptions::new("your-ably-api-key")
        .client_id("me")?
        .realtime()?;

    // Get a reference to the 'test-channel' channel and attach
    let channel = client.channels.get("test-channel");
    channel.attach().await?;
    println!("Connected to Ably");

    // Subscribe to all messages published to this channel
    let (_subscription, mut messages) = channel.subscribe();
    tokio::spawn(async move {
        while let Some(message) = messages.recv().await {
            println!("Received message: {:?}", message.data);
        }
    });

    // Publish a test message to the channel
    channel
        .publish()
        .name("test-event")
        .string("hello world")
        .send()
        .await?;

    Ok(())
}
```

The SDK also provides the [Ably REST API](https://ably.com/docs/rest) via `ClientOptions::new(key).rest()`, along with presence, message history, symmetric encryption, and vcdiff delta decoding. See the [Ably documentation](https://ably.com/docs) for details.

---

## Contribute

Read the [CONTRIBUTING.md](./CONTRIBUTING.md) guidelines to contribute to Ably.

---

## Releases

You can view all Ably releases on [changelog.ably.com](https://changelog.ably.com), and this SDK's releases on the [crate's version history](https://crates.io/crates/ably/versions).

---

## Support, feedback, and troubleshooting

For help or technical support, visit Ably's [support page](https://ably.com/support) or [GitHub Issues](https://github.com/ably/ably-rust/issues) for community-reported bugs and discussions.

### Developer preview

This SDK is an early developer preview. Some features available in other Ably SDKs — including push device registration (LocalDevice) and OS network-connectivity events — are not yet implemented. For production workloads, use a [generally available Ably SDK](https://ably.com/docs/sdks).

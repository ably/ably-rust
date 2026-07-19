# ably-rust — Design & Architecture

This document explains how the crate is put together, for someone reading or
extending the code. It describes the *current* design; it is not an API
reference (the code and its rustdoc are the source of truth for types and
signatures) and not a changelog (see [MIGRATION.md](./MIGRATION.md) for how the
public API differs from the previous published release).

The crate implements the Ably REST API and the Ably Realtime API. The Ably
protocol version is **6** (`x-ably-version: 6` header on REST, `v=6` query param
on the WebSocket).

## Design principles

- **No third-party types in the public API.** `reqwest`/`tokio-tungstenite`
  types never appear in public signatures; HTTP and WebSocket access sit behind
  the `HttpClient` and `Transport` traits, which also make the client testable
  by injection (no `as_any`/downcasting).
- **One type per concept.** A single `Message`, `PresenceMessage`, and
  `ErrorInfo` are shared by REST and realtime — no conversions between layers.
  `ErrorInfo` is the TI1 error type used for `Result<T>`, state-change reasons,
  and `cause` chains.
- **Wire types are `pub(crate)`.** Users never construct a `ProtocolMessage`;
  only the state enums (`ConnectionState`, `ChannelState`, …) are re-exported.
- **Builder-style publish** for both REST and realtime, for a consistent API.
- **MessagePack is the default** wire format; JSON is opt-in via
  `use_binary_protocol(false)`.

## Module layout

```
src/
  lib.rs              -- crate root, re-exports
  error.rs            -- ErrorInfo, ErrorCode, Result
  options.rs          -- ClientOptions builder
  rest.rs             -- Rest client, REST Channel/Presence/Push, PublishBuilder
  auth.rs             -- durable auth core: state, types (incl. Key/basic auth),
                         header resolution, token acquisition, authURL, revocation
  token_request.rs    -- the (deprecatable) Ably native token mechanism:
                         requestToken exchange + Key signing
  http.rs             -- request pipeline, pagination (PaginatedResult), Response
  http_client.rs      -- pub(crate) HttpClient trait + reqwest impl
  realtime.rs         -- Realtime + Connection handles
  channel.rs          -- Channels, RealtimeChannel, RealtimePresence handles
  connection/         -- the single connection event loop (owns all realtime state)
    mod.rs            -- loop core, ConnectionCtx/ChannelCtx state, connect cycle,
                         timers, command/protocol dispatch, DeltaDecoder
    channel_arm.rs    -- channel lifecycle, connection-state effects, inbound
                         MESSAGE + RTL18/19/20 delta decoding
    presence_arm.rs   -- presence/annotation ops, RTP11 get, inbound PRESENCE/SYNC
    publish_arm.rs    -- RTL6 publish pipeline, RTN19a resend, ACK/NACK
  protocol.rs         -- pub(crate) wire types; pub state enums (re-exported)
  transport.rs        -- pub(crate) Transport trait
  ws_transport.rs     -- pub(crate) WebSocket Transport impl + tolerant decode
  crypto.rs           -- CipherParams (channel encryption, RSL5/RSP)
  stats.rs            -- Stats types
  proxy.rs            -- pub(crate), #[cfg(test)] UTS proxy client
  mock_http.rs        -- pub(crate), #[cfg(test)] MockHttpClient
  mock_ws.rs          -- pub(crate), #[cfg(test)] MockWebSocket/MockTransport
```

Handles (`Rest`, `Realtime`, `Connection`, `RealtimeChannel`, …) are the public
surface; the mutable machinery lives behind them (`RestInner` for REST, the
connection loop for realtime).

## REST client

`Rest` is a cheap-to-clone `Arc<RestInner>`. `RestInner` holds the immutable
`ClientOptions` and `HttpClient` (no lock needed) plus exactly two short-lived
`std::sync::Mutex`es, neither ever held across an `.await`:

- **`auth_state`** — the cached token and the params/options saved by
  `authorize()` (RSA10). Renewal releases the lock before doing I/O; concurrent
  requests may each renew (idempotent, last write wins) rather than serialise
  behind a semaphore.
- **`fallback_state`** — the cached successful fallback host and its TTL
  (RSC15f).

Each request resolves an `Authorization` header (basic auth for a key; a cached
or freshly obtained token otherwise — via key/`authCallback`/`authUrl`/
`TokenRequest`), attaches the standard headers (`x-ably-version`, `Ably-Agent`,
content-type for the chosen format, optional `request_id`), serialises the body,
and runs a fallback/retry loop: a cached fallback host is tried first, otherwise
the primary domain then the REC2 fallback domains in random order, bounded by
`http_max_retry_count`/`http_max_retry_duration`. Pagination is exposed as
`PaginatedResult<T>` with `items()`/`has_next()`/`next()`.

## Realtime client: state & synchronisation

This is the heart of the crate. It has **one** synchronisation concept and
derives everything from it.

### One event loop owns all state

All mutable realtime state — the connection state machine, every channel's
state machine, presence maps, pending ACKs, queued messages, delta base
payloads, and all timers — is owned exclusively by **one tokio task, the
connection loop**, as plain `&mut self` data. There are **zero locks on
protocol state**. `ConnectionCtx` (and the `ChannelCtx`/`PresenceCtx` it owns)
are plain structs with no `pub` fields and no sync primitives; they are moved
into the loop task at construction and cannot be shared.

The outside world interacts with the loop through four primitives only:

| Primitive | Direction | Carries |
|---|---|---|
| `mpsc::UnboundedSender<LoopInput>` | in | commands from handles; transport events; completions of spawned I/O |
| `oneshot::Sender<Result<T>>` (inside commands) | out | request/response replies (attach, publish, ping, …) |
| `tokio::sync::watch` | out | state snapshots (`ConnectionState`, per-channel `ChannelSnapshot`) |
| `tokio::sync::broadcast` | out | ordered state-change event streams |

### The loop never awaits I/O

Anything that blocks — transport connect, token acquisition, transport writes,
the RTN17j connectivity probe — runs in a short-lived spawned task that posts
its outcome back as a `LoopInput`. The loop body is therefore pure, fast state
manipulation, and processes each input to completion before the next. That is
what makes the ordering guarantees below hold by construction.

```
 Connection ──┐  commands  ┌──────────────────────────────────────┐
 RealtimeChannel┤  (mpsc)   │        CONNECTION LOOP (one task)     │
 RealtimePresence┘          │  owns ConnectionCtx: connection +     │
 reader task ──── transport │  channel state machines, presence,    │
 connect task ─── events    │  pending ACKs, queues, delta bases,   │
 token task  ──── (same     │  timers                               │
 probe task  ──── mpsc)     │  emits watch snapshots, broadcast     │
                            │  events, oneshot replies              │
                            └───────────────┬───────────────────────┘
                                            │ try_send (never awaits)
                                      writer task ──► TransportConnection
```

### The one lock that is not protocol state

`Channels` (the public collection) holds a `Mutex<HashMap<String,
Arc<RealtimeChannel>>>` — a registry of *handle objects only* (name, command
sender, watch receiver), needed because `Channels::get/release` are synchronous.
It holds no protocol state and is never locked across an await. That mutex, plus
the two REST locks above, is the **entire** lock inventory of the client;
`tests_design_conformance` enforces it (see [Enforcement](#enforcement)).

### Commands and dispatch

`LoopInput` is a single enum — `Cmd(Command)` from handles, `Transport` events
from the reader task, and the `ConnectAttempt`/`TokenReady`/`Connectivity`
completions from spawned tasks — so one queue gives a total order over
everything the loop reacts to. Public async methods are thin: build a command
with a `oneshot` reply, send it, await the reply. Each command's behaviour is
defined for every connection/channel state per the spec tables; the loop's
`match` is exhaustive, so the compiler enforces completeness. Commands sent
after the loop has terminated (client dropped) fail fast with an `ErrorInfo`.

The loop and its state types live in `connection/`, split into arms purely for
readability — the ownership model is unchanged and the conformance ratchet
scans all of them: `mod.rs` (loop core, state definitions, connect cycle,
timers, dispatch), `channel_arm.rs` (channel lifecycle, connection-state
effects on channels, inbound `MESSAGE` + delta decoding), `presence_arm.rs`
(presence/annotation ops and inbound `PRESENCE`/`SYNC`/`ANNOTATION`), and
`publish_arm.rs` (the publish/ACK pipeline).

### State observation

- **Snapshots** (`Connection::state()`, `RealtimeChannel::state()`, …) read a
  `watch::Receiver` — wait-free, always current, no loop round-trip. Snapshots
  are values, so there are no torn reads.
- **Events** (`on_state_change()`) are `broadcast::Receiver`s.
- **Consistency contract:** the loop updates the `watch` snapshot *before*
  emitting the corresponding `broadcast` event, so a listener that reads a
  snapshot while handling event N sees state from transition ≥ N. A lagged
  broadcast receiver may miss intermediate events, but the snapshot is always
  current.

### Timers

Every timer is a deadline field in the loop's state; the loop's `select!` waits
on `sleep_until(earliest)` recomputed each iteration. Cancelling a timer is
setting its field to `None`, observed on the next iteration — no timer tasks, no
cancellation races. Timers include the connect-attempt timeout, disconnected/
suspended retry, connection-state TTL, the RTN23 activity/idle timeout, the
RTN13 ping deadline, per-channel attach/detach op timeouts, and the RTL13b
channel retry.

### Transport, resume, and the generation guard

`Transport::connect(url)` runs in a spawned connect task (it first obtains a
token off-loop if using token auth, builds the RTN2 URL with resume/recover
params captured from loop state), and posts `ConnectAttempt`. On success the
loop spawns a **reader task** (`recv()` → `LoopInput::Transport`) and a
**writer task** (drains an `mpsc<ProtocolMessage>` into `send()`), holding only
the writer sender and abort handles.

A **generation counter** is incremented on every connect attempt and tagged
onto every transport input; the loop discards inputs whose generation ≠ current.
This one integer replaces all "is this still the active transport?" reasoning
(RTN superseded-transport rules). Resume (RTN15) and recover (RTN16) are
loop-side bookkeeping — the connection key and msgSerial live in `ConnectionCtx`
and are handed to the connect task as values. Before host fallback, the RTN17j
connectivity check is probed from a spawned task to distinguish "Ably
unreachable" from "no internet".

### Presence

`PresenceCtx` (inside `ChannelCtx`) holds the members map, the internal
local-members map (RTP17), sync bookkeeping, and deferred
`get(wait_for_sync=true)` repliers. RTP2 newness comparison, SYNC application,
RTP17 re-entry on attach, and RTP18/19 reconciliation are plain in-loop
functions. `enter`/`update`/`leave` are commands sent as PRESENCE messages that
resolve through the same ACK pipeline as publishes.

### Delta decoding (RTL18–RTL21, PC3)

Delta/vcdiff decoding is bundled, not a user-supplied plugin: the crate depends
on [`vcdiff-decode`](https://crates.io/crates/vcdiff-decode) and calls it
directly. An internal seam `connection::DeltaDecoder` (`Arc<dyn Fn(delta, base)
-> Result<Vec<u8>, String>>`) wraps `vcdiff::decode` in production and is
overridable behind `#[cfg(test)]` so the RTL18/19/20 bookkeeping is unit-tested
with an injected mock (real decoding is covered by `vcdiff-decode`'s own
conformance suite). `ChannelCtx` stores the RTL19 base payload (wire form,
before json/utf-8) and the RTL20 last-message id, both cleared on any transition
out of ATTACHED. On a decode failure or an RTL20 id mismatch the message is
discarded and the channel re-attaches from the previous message's channelSerial
with error 40018 (RTL18 recovery). Delta mode is requested via the existing
channel-option params (`delta = vcdiff`); the SDK never generates deltas.

### Message routing and backpressure

Subscribers receive messages over unbounded `mpsc` channels; the loop never
blocks on a slow consumer (which would stall the whole client). A slow consumer
costs memory proportional to its own lag only; the server bounds the inbound
rate per connection. Receiver drop is detected on the next send and the entry
pruned.

### Invariants (each holds by construction)

1. Every state transition is decided by exactly one thread of execution; none
   can be observed "in progress".
2. `watch` snapshot updates precede their `broadcast` events.
3. Events on any one stream are delivered in transition order.
4. ACK/NACK resolution is FIFO over `msgSerial`; a publish replier resolves
   exactly once (ACK, NACK, or connection-level failure).
5. Per channel, message delivery order to every subscriber equals wire arrival
   order; presence events are emitted only after the map mutation they describe.
6. Inputs from superseded transports are inert (generation guard).
7. Connection-state side effects on channels are atomic with the connection
   transition.
8. After `close()`, queued/pending operations resolve with the spec error —
   repliers are never leaked.

## Observability (logging) policy — NORMATIVE

Every code path is instrumented at a defined level; there are **no silent
discards of data**.

- **Error** — any discarded/undecodable data: undecodable JSON/msgpack frames
  (including the tolerant-decode failure path), undecodable message/presence/
  annotation entries, ACK/NACK for an unknown serial, transport write failures.
  A discard path must have a test asserting it logs at Error.
- **Major** — connection and channel state transitions (with reasons), UPDATE
  events, presence re-entry failures.
- **Minor** — resume outcomes, retry scheduling, queued-publish flush and RTN19a
  resend counts, presence SYNC start/complete, NACK outcomes, RTL17 drops.
- **Micro** — every public realtime API entry, and each wire frame
  (`->`/`<-` with action, channel, serial).

The logger is level-gated and lazily formats; an optional `tracing` cargo
feature bridges these to the `tracing` crate.

## Testing

Tests mirror the UTS (Universal Test Specification) directory structure and are
**derived from the UTS**, not from any prior implementation. Files are named by
layer: `tests_rest_unit_*` (mocked HTTP), `tests_realtime_unit_*` (mocked
WebSocket), `tests_*_integration` (live nonprod sandbox), and `tests_proxy*`
(fault injection over a real transport via the uts-proxy). Integration/proxy
tests share a sandbox app and run serially (`--test-threads=1`).

`uts_coverage.txt` is a curated traceability matrix mapping every UTS Test ID to
the test(s) that cover it, or excluding it with a reason. It is generated by
`tools/uts_coverage_generate.py` from a full serial test run and reviewed by
hand; when a mapping's variant cannot be verified the generator emits
`?? UNRESOLVED`.

## Enforcement

The design stays adhered to mechanically, not by convention:

1. **Lock inventory** — `tests_design_conformance` scans the connection
   submodules and `channel.rs` for synchronisation primitives and fails if the
   count exceeds the allowance (the `Channels` handle registry only). Any new
   lock on protocol state fails the build.
2. **UTS traceability ratchet** — `tests_uts_coverage` fails the build on any
   UTS Test ID that is neither mapped nor excluded-with-reason, any dangling
   test reference, or any unaccounted spec area. Converting an exclusion to a
   mapping must also update the generator's dispositions.
3. **Design-change-before-code** — a change that appears to need a new sync
   primitive, shared state outside the loop, or a loop bypass stops; the change
   is proposed as a DESIGN.md edit first. CLAUDE.md carries the compact,
   imperative form of these invariants for working sessions.

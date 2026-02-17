# Generic Ably SDK Development Plan Using UTS

> This document is a reusable template for building an Ably SDK in any language,
> driven by the Universal Test Specification (UTS). It was developed alongside
> the Rust SDK implementation — each section captures what needs to be done,
> what materials to reference, and what issues were discovered.

## How to Use This Document

1. Read the phase descriptions to understand the recommended order
2. For each phase, follow the "Steps" to implement in your target language
3. Use the "References" to find the relevant specs and UTS test files
4. Check "Findings" for known issues and pitfalls discovered during development

---

## Phase 0: Foundation & Test Infrastructure

### Goal
Before writing any SDK code, establish the test infrastructure that lets you
run UTS-equivalent tests in your target language.

### Steps

1. **Read UTS mock HTTP spec** (`uts/test/rest/unit/helpers/mock_http.md`).
   Understand the `MockHttpClient` interface: handler-based pattern (`onRequest`
   callback), queue-based pattern (`queue_response`), and request capture for
   assertions.

2. **Read existing test code** to understand current patterns, network-dependent
   tests, and what helpers already exist.

3. **Introduce an HTTP client abstraction** that allows swapping the real HTTP
   client for a mock in tests. The abstraction needs:
   - `execute(request) -> Response` — send a built request
   - `request(method, url) -> RequestBuilder` — start building a request
   - A mechanism for tests to access mock-specific methods on the underlying
     implementation (e.g. language-specific downcasting, generics, or a
     test-only accessor).

   Wrap the production HTTP library in a class/struct implementing this
   abstraction. Refactor the REST client to use the abstraction instead of
   the concrete HTTP library. Keep the abstraction internal — it must not
   become part of the public API.

4. **Implement `MockHttpClient`** (test-only):
   - Handler pattern: provide a callback that receives each request and returns
     a response
   - Queue pattern: pre-queue responses that are returned in FIFO order
   - Request capture: stores every request for later assertions
   - `MockResponse` with constructors for JSON, MessagePack, and empty bodies

5. **Wire default headers into the mock.** Many HTTP libraries merge default
   headers (like `X-Ably-Version`) at send time, not at request-build time.
   Since the mock intercepts the send, it may need to merge default headers
   itself. Provide a way to pass the SDK's default headers to the mock so
   captured requests include them.

6. **Define test conventions:**
   - A helper to create a REST client with a mock HTTP backend
   - A helper to access the mock from a client instance for assertions
   - Test naming convention matching spec points (e.g. `rsc7e_...`)

7. **Verify all existing tests still pass** (both old network-dependent tests
   and new mock-based tests).

### References
- `uts/test/rest/unit/helpers/mock_http.md` — Mock HTTP client specification
- `uts/test/realtime/unit/helpers/mock_websocket.md` — Mock WebSocket specification
- `uts/submodules/ably-common/test-resources/test-app-setup.json` — Sandbox app config

### Findings

- **Default header merge timing:** Some HTTP libraries merge default headers
  internally at send time, not at request-build time. Since the mock intercepts
  the send, captured requests won't contain default headers unless the mock
  explicitly merges them. Solution: extract default headers from client options,
  pass them to the mock, and merge them into captured requests.

- **Test access to mock internals:** When the HTTP client is behind an
  abstraction, tests need to access mock-specific methods (e.g.
  `captured_requests()`). Each language has its own pattern for this —
  downcasting, generics, test-only accessors, etc. Choose the idiom that
  keeps the mock out of the public API.

---

## Phase 1: REST Client Core & Types

### Goal
Implement the REST client constructor, options, and fundamental types.
Align existing code with the UTS tests in `rest/unit/rest_client.md`.

### Steps

1. **RSC5 — Auth attribute:** Verify the REST client exposes an `auth` accessor.
   Typically a trivial assertion if the type system enforces it.

2. **RSC7e — X-Ably-Version header:** Add `X-Ably-Version: 1.2` to default
   headers. Write a mock test that asserts the header is present on requests.

3. **RSC7d — Ably-Agent header:** Add `Ably-Agent: ably-<lang>/<version>` to
   default headers. The version should come from the package metadata
   (e.g. `package.json` version field, build-time constants, etc.). Test that
   the header matches the pattern `ably-<lang>/x.y.z`.

4. **RSC7c — Request IDs:** Implement `addRequestIds` option. When enabled,
   generate a URL-safe random identifier and append it as a `request_id` query
   parameter on every request. The ID should be base64url-encoded (at least
   12 characters). Also test that the same ID is preserved on fallback retries.

5. **RSC8a/b — Protocol selection:** Verify that the default protocol is
   MessagePack (Content-Type: `application/x-msgpack`), and that setting
   `useBinaryProtocol: false` switches to JSON (`application/json`).

6. **RSC8c — Accept header:** Ensure the `Accept` header matches the configured
   protocol. This is typically set as a default header alongside Content-Type.

7. **RSC8d — Mismatched response Content-Type:** Verify the client can decode
   responses in either JSON or MessagePack regardless of which was requested.
   The client should use the response's Content-Type to determine decoding.

8. **RSC8e — Unsupported Content-Type:** Verify error handling:
   - Error status (e.g. 500) + unsupported Content-Type → propagate HTTP status
   - Success status (200) + unsupported Content-Type → error code 40013

9. **RSC13 — Request timeouts:** Implement `httpRequestTimeout` option. Apply
   the timeout at the SDK level (wrapping the HTTP execute call) rather than
   relying solely on the HTTP library's built-in timeout. This ensures
   timeouts work consistently with mock clients in tests. Error code: 50003.

10. **RSC17 — ClientId attribute:** Verify the client ID option is accessible
    on the client object and propagated to the Auth object.

11. **RSC18 — TLS configuration:** Verify:
    - Default is HTTPS
    - `tls: false` uses HTTP
    - Basic auth (API key) is rejected when `tls: false` (error 40103)
    - Token auth over HTTP is allowed

### References
- Spec: `RSC1–RSC18`, `TO1–TO3`, `TI1–TI5`
- UTS: `rest/unit/rest_client.md`, `rest/unit/types/`

### Findings

- **Accept header often missing:** Initial SDK implementations often omit the
  `Accept` header. UTS RSC8c requires it to match the configured protocol.
  Add it as a default header alongside `Content-Type`.

- **Ably-Agent header easily overlooked:** SDKs often implement
  `X-Ably-Version` but forget the `Ably-Agent` header. Both are required.

- **Request IDs may be declared but not wired up:** If the `addRequestIds`
  option exists in the options type but isn't actually used in the request
  path, the UTS test will catch it. The implementation needs to generate a
  random ID and append it as a query parameter before each request is sent.

- **Timeout must be SDK-level, not just HTTP-library-level:** HTTP library
  timeouts only apply to real network requests and won't fire with mock
  clients. The SDK should apply its own timeout (e.g. using the language's
  async timeout mechanism) wrapping the HTTP execute call.

- **Basic auth rejection over non-TLS:** This validation is easy to miss.
  It should be checked at client construction time, before any requests are
  made.

- **Error code for unsupported Content-Type:** The spec requires error code
  40013 (`InvalidMessageDataOrEncoding`) for 2xx responses with unsupported
  Content-Type, not a generic "bad request" error.

---

## Phase 2: Auth

### Goal
Complete authentication: basic auth, token auth, token requests, authorize.

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSA1–RSA17`
- UTS: `rest/unit/auth/`, `rest/integration/auth.md`

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 3: REST Channels

### Goal
Publishing, history, message encoding/decoding, pagination.

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSL1–RSL6`, `RSN1–RSN4`, `TM1–TM8`, `TG1–TG7`
- UTS: `rest/unit/channel/`, `rest/unit/encoding/`, `rest/integration/publish.md`

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 4: REST Presence

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSP1–RSP5`, `TP1–TP5`
- UTS: `rest/unit/presence/`, `rest/integration/presence.md`

---

## Phase 5: Fallback Hosts

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `REC1–REC3`, `RSC15`
- UTS: `rest/unit/fallback.md`

---

## Phase 6: Additional REST Features

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSC6`, `RSC16`, `RSC19`, `RSC22`, `RSC24`, `RSH1`
- UTS: `rest/unit/request.md`, `rest/unit/stats.md`, `rest/unit/batch_*.md`, `rest/unit/push/`

---

## Phase 7a: Realtime — Types, Transport & Basic Connection

### Goal
Build the foundation: protocol types, mock WebSocket infrastructure, connection
state machine, and basic connect/close lifecycle.

### Steps

1. **Read UTS mock WebSocket spec** (`uts/test/realtime/unit/helpers/mock_websocket.md`).
   Understand the `MockWebSocket` interface: handler-based and await-based
   connection patterns, `PendingConnection` with response methods, `MockConnection`
   for injecting server messages, and `ServerAction` for message/disconnect events.

2. **Define protocol types:**
   - `Action` enum — integer-encoded protocol actions (Heartbeat=0 through Auth=17)
   - `ProtocolMessage` — action, channel, connectionId, connectionKey,
     connectionDetails, error, id, msgSerial, auth, messages, presence
   - `ConnectionDetails` — connectionKey, maxIdleInterval, connectionStateTtl,
     clientId, maxMessageSize, serverId
   - `ErrorInfo` — code, statusCode, message, href
   - `AuthDetails` — accessToken
   - `ConnectionState` enum — Initialized, Connecting, Connected, Disconnected,
     Suspended, Closing, Closed, Failed
   - `ConnectionEvent` enum — same as ConnectionState plus Update
   - `ConnectionStateChange` — previous, current, event, reason

3. **Implement mock WebSocket infrastructure** (test-only):
   - `MockWebSocket` with handler-based pattern (`onConnectionAttempt` callback)
   - `PendingConnection` with `respond_with_success(msg)`, `respond_with_refused()`,
     `respond_with_error(msg)` — captures URL for test assertions
   - `MockConnection` for injecting server messages: `send_to_client(msg)`,
     `send_to_client_and_close(msg)`, `simulate_disconnect()`
   - `MockTransport` as the client-side transport interface with `connect(url)`
   - Connection counting, client message capture, active connection tracking

4. **Implement `Realtime` client constructor:**
   - Accept `ClientOptions` with `autoConnect` (default true), `echoMessages`,
     `transportParams`
   - Build WebSocket URL from host, scheme (ws/wss), query params (v=2, format,
     heartbeats=true, echo, key/token, custom transport params)
   - `RTC1f`: custom `transportParams` override defaults with same key

5. **Implement `Connection` with state machine:**
   - State broadcast/event channel for state change notifications
   - `connect()` — RTN11: clear close flag, transition to Connecting, spawn
     connection task
   - `close()` — RTN12: set close flag, transition through Closing to Closed
   - `on_state_change()` — subscribe to state change events
   - State accessors: `state()`, `id()`, `key()`, `error_reason()`

6. **Implement connection lifecycle:**
   - Spawn async task for WebSocket connection
   - On CONNECTED message: store connectionId, connectionKey, connectionStateTtl;
     transition to Connected
   - On ERROR message (no channel): transition to Failed
   - On CLOSED message: transition to Closed
   - Auto-connect on construction when `autoConnect: true` (RTN3)

7. **Write tests** for: auto-connect (RTN3), explicit connect, close lifecycle
   (RTC15/RTC16), connection state events (RTN4), connection ID (RTN8a-c),
   connection key (RTN9a-c), URL parameters (RTC1a echo, RTC1f transport params),
   error reason on disconnected/failed (RTN25).

### References
- Spec: `RTN3`, `RTN4`, `RTN8`, `RTN9`, `RTN11`, `RTN12`, `RTN25`, `RTC1`,
  `RTC12`, `RTC15`, `RTC16`
- UTS: `realtime/unit/helpers/mock_websocket.md`,
  `realtime/unit/connection/auto_connect_test.md`,
  `realtime/unit/connection/connection_id_key_test.md`,
  `realtime/unit/connection/error_reason_test.md`,
  `realtime/unit/client/realtime_client.md`

### Findings

- **Mock WebSocket needs cloneable connections.** Tests often need to grab a
  connection handle from the mock and inject messages from outside the handler.
  The `MockConnection` type must be cloneable/shareable (e.g. using channels
  rather than direct socket access).

- **`heartbeats=true` must be in the URL.** For platforms where the WebSocket
  library doesn't surface ping frame events (most platforms), the client must
  request HEARTBEAT protocol messages by sending `heartbeats=true` in the
  connection query parameters.

- **Connection ID/key clearing in terminal states.** When transitioning to
  Closed, Failed, or Suspended, the connection ID and key must be cleared
  (set to null). This is easy to miss and affects resume behavior.

- **`transportParams` override semantics.** Custom transport params with the
  same key as a default param (e.g. `heartbeats`) should replace the default,
  not append. Implement as: remove existing key, then add new value.

---

## Phase 7b: Realtime — Connection Failures, Resume & Ping

### Goal
Robust connection failure handling, resume/recovery, ping, whenState, and
update events.

### Steps

1. **Implement connection retry loop** — the main async loop that manages
   reconnection:
   - On unexpected disconnect: transition to Disconnected, wait
     `disconnectedRetryTimeout`, retry (RTN14d)
   - Track `disconnected_since` timestamp; if elapsed time exceeds
     `connectionStateTtl`, transition to Suspended (RTN14e)
   - In Suspended: wait `suspendedRetryTimeout`, retry indefinitely (RTN14f)
   - On close requested: break out of loop cleanly
   - On Fatal error (ERROR with no channel): transition to Failed, stop

2. **Implement connection resume** (RTN15):
   - Add `resume=<connectionKey>` to URL query when reconnecting with a
     previous connection key
   - Clear connection key in terminal states (Suspended/Closed/Failed) to
     prevent stale resumes
   - Handle CONNECTED with error (failed resume): set error_reason but still
     transition to Connected (RTN15c7)

3. **Implement DISCONNECTED message handling:**
   - Server sends DISCONNECTED → transition to Disconnected with error reason
   - Token error codes (40140-40149): transition to Failed if no means to
     renew token (RTN15h1)
   - Non-token errors: normal reconnect cycle (RTN15h3)

4. **Implement UPDATE events** (RTN24):
   - When CONNECTED received while already Connected, emit an Update event
     (not Connected event)
   - Update connection details (ID, key, TTL) from the new CONNECTED message

5. **Implement ping** (RTN13):
   - Send HEARTBEAT with random ID via client message channel
   - Match responses by ID using pending ping registry
   - Return round-trip duration on success
   - Error immediately in Initialized/Suspended/Closing/Closed/Failed states
   - Defer in Connecting/Disconnected: wait for Connected, then ping
   - Timeout with `realtimeRequestTimeout`
   - Fail pending pings on terminal state transitions

6. **Implement whenState** (RTN26):
   - If already in target state: invoke callback immediately with null
   - Otherwise: spawn listener that fires once on matching state transition

7. **Multiplex server and client messages** using async select/race:
   - Server messages from WebSocket
   - Client messages from internal channel (for ping HEARTBEAT sends)

8. **Write tests** for: RTN14a/d/e/f/g, RTN15a/b/c4/c6/c7/g/h1/h3/j,
   RTN24 update events, RTN25 error reason, RTN13a/b ping, RTN26a/b whenState.

### References
- Spec: `RTN13`, `RTN14`, `RTN15`, `RTN24`, `RTN25`, `RTN26`
- UTS: `realtime/unit/connection/connection_open_failures_test.md`,
  `realtime/unit/connection/connection_failures_test.md`,
  `realtime/unit/connection/connection_ping_test.md`,
  `realtime/unit/connection/when_state_test.md`,
  `realtime/unit/connection/update_events_test.md`

### Findings

- **await_state race condition.** When testing disconnect/reconnect sequences,
  `await_state(Connected)` can return immediately if the state is still
  Connected from the initial connection (before the disconnect message is
  processed). Fix: always `await_state(Disconnected)` first, then
  `await_state(Connected)` for the reconnection.

- **Ping needs multiplexed message handling.** The connection message loop
  must handle both server-to-client messages and client-to-server messages
  (for ping). Use async select/race with an internal channel for client
  messages, not direct WebSocket writes from the ping method.

- **Pending pings must be failed on terminal states.** When the connection
  transitions to Failed/Closed/Closing/Suspended, all pending ping futures
  must be resolved with an error. Otherwise they hang forever.

- **Connection key cleared too eagerly.** The key must only be cleared in
  terminal states (Suspended/Closed/Failed), not in Disconnected. Clearing
  in Disconnected prevents resume on reconnect.

---

## Phase 7c: Realtime — Heartbeats, Fallback & Timeouts

### Goal
Heartbeat idle detection, fallback host handling for initial connections,
and timeout configuration. Features that require channels or auth are
deferred to the phases where their dependencies are satisfied.

### Steps

1. **Implement heartbeat idle timer** (RTN23):
   - Store `maxIdleInterval` from CONNECTED message's `connectionDetails`
   - Compute idle timeout = `maxIdleInterval + realtimeRequestTimeout`
   - Add idle timer as a third branch in the async select/race message loop
   - On any received message (HEARTBEAT, ACK, MESSAGE, etc.): reset the timer
   - On timeout expiry: transition to Disconnected and trigger reconnect
   - Recompute timeout after each CONNECTED message (maxIdleInterval may change)
   - If `maxIdleInterval` is 0 or absent: disable idle monitoring

2. **Choose RTN23a vs RTN23b** based on platform:
   - If your WebSocket library does NOT surface ping frame events (most platforms):
     use RTN23a with HEARTBEAT protocol messages, send `heartbeats=true` in URL
   - If your WebSocket library CAN surface ping frames: use RTN23b, send
     `heartbeats=false` or omit the parameter

3. **Implement fallback hosts for Realtime** (RTN17):
   - Store `fallback_hosts` list and `primary_host` in connection state
   - RTN17i: Always try primary host first on every connection attempt
   - On connection refused or DISCONNECTED with 5xx status (RTN17f/f1):
     try fallback hosts in random order
   - RTN17g: If fallback host list is empty (custom host), skip fallback
   - RTN17h: Default fallback hosts from client options (REC2)
   - Extract a `try_connect(url)` helper to enable retrying across hosts
   - Add `build_url_with_host(host)` for constructing fallback URLs

4. **Verify timeout configuration** (RTC7):
   - Default values: `realtimeRequestTimeout=10s`, `disconnectedRetryTimeout=15s`,
     `suspendedRetryTimeout=30s`, `httpOpenTimeout=4s`, `httpRequestTimeout=10s`
   - Custom `disconnectedRetryTimeout` controls reconnection delay

5. **Update existing tests** that use `respond_with_refused()` for simple
   retry testing: add empty fallback host list to prevent unintended fallback
   attempts consuming mock connection attempts.

6. **Write tests** for: heartbeats=true in URL, idle timeout disconnect/reconnect,
   HEARTBEAT resets timer, any message resets timer, resume after idle timeout,
   continuous activity keeps alive, primary host preference, connection refused
   triggers fallback, 5xx triggers fallback, empty fallback set, default
   fallback domains, disconnected retry timeout, default timeout values.

### Deferred to later phases

These features are listed in the RTN17/RTN22/RTC7 UTS specs but require
channels or auth infrastructure that doesn't exist yet:

- **RTN22** (server-initiated reauth) → **Phase 9** (needs authCallback)
- **RTN7** (ACK/NACK) → **Phase 8** (needs channel publish)
- **RTN17e** (HTTP requests use same fallback host) → **Phase 8** (needs channels)
- **RTN17j** (connectivity check before fallback) → **Phase 8** (needs HTTP in RT)
- **RTC7** attach/detach timeout tests → **Phase 8** (needs channel operations)

### References
- Spec: `RTN23`, `RTN17`, `RTC7`
- UTS: `realtime/unit/connection/heartbeat_test.md`,
  `realtime/unit/connection/fallback_hosts_test.md`,
  `realtime/unit/client/realtime_timeouts.md`

### Findings

- **Fallback hosts break existing retry tests.** When fallback host support is
  added, existing tests that use `respond_with_refused()` for simple retry
  behavior will now also attempt fallback hosts, consuming extra mock connection
  attempts and causing unexpected test failures. Fix: add empty fallback host
  list to all tests that expect simple same-host retry without fallback.

- **Idle timer must not use `sleep` directly.** The idle timer needs to be
  reset on every received message. Use a deadline-based approach (compute
  `now + timeout`, reset deadline on each message) rather than a fixed sleep,
  and integrate it as a branch in the async select/race loop.

- **`maxIdleInterval` of 0 means no idle monitoring.** Some CONNECTED messages
  may have `maxIdleInterval: 0` or omit it entirely. The idle timer should
  only be active when the value is positive. Tests that don't care about
  heartbeats should set `maxIdleInterval: 0` to avoid unexpected idle timeouts.

- **`try_connect` needs to distinguish "never connected" from "connected then
  disconnected".** Fallback should only happen when the initial connection
  fails, not when an established connection later disconnects. Track whether
  CONNECTED was ever received during a connection attempt to make this
  distinction.

- **5xx in DISCONNECTED triggers fallback, but only pre-CONNECTED.** A
  DISCONNECTED with 503 received *before* any CONNECTED message (server
  rejects immediately) should trigger fallback. A DISCONNECTED received
  *after* being CONNECTED (server kicks) should go through normal reconnect.

- **Shuffling fallback hosts.** Use a random shuffle for the fallback host
  list on each connection attempt cycle. The UTS has a probabilistic test
  for randomness (run 5 iterations, check for variation) which is inherently
  flaky — consider using a seeded RNG or documenting as optional.

---

## Phase 8a: Realtime — Channel Foundation

### Goal
Channel collection, state machine, and options infrastructure. Everything else
in Phase 8 depends on being able to create channels and observe state changes.

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTS1–RTS4`, `RTL2`, `TB2–TB4`, `RTS3`, `RTL16`
- UTS: `realtime/unit/channels/channels_collection_test.md`,
  `realtime/unit/channels/channel_state_events_test.md`,
  `realtime/unit/channels/channel_options_test.md`

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 8b: Realtime — Attach & Detach

### Goal
Core channel lifecycle operations. Also absorbs ACK/NACK (RTN7) and RTC7
attach/detach timeouts deferred from Phase 7c.

### Steps
<!-- To be filled in during implementation -->

### Includes deferred items from Phase 7c
- ACK/NACK — `RTN7` (message delivery confirmation, needed for attach)
- RTC7 attach/detach timeouts (needs channel attach/detach operations)

### References
- Spec: `RTL4`, `RTL5`, `RTN7`, `RTC7`
- UTS: `realtime/unit/channels/channel_attach_test.md` (16 tests),
  `realtime/unit/channels/channel_detach_test.md` (13 tests),
  `realtime/unit/client/realtime_timeouts.md` (RTC7 attach/detach tests)

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 8c: Realtime — Messages

### Goal
Publishing and subscribing to messages on channels.

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTL6`, `RTL7`, `RTL8`, `TM2`
- UTS: `realtime/unit/channels/channel_publish_test.md` (23 tests, ~60K),
  `realtime/unit/channels/channel_subscribe_test.md` (16 tests),
  `realtime/unit/channels/message_field_population_test.md` (8 tests)

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 8d: Realtime — Advanced Channel Features

### Goal
Connection-state impact, server-initiated events, history, and edge cases.
Also absorbs RTN17e/j deferred from Phase 7c.

### Steps
<!-- To be filled in during implementation -->

### Includes deferred items from Phase 7c
- RTN17e HTTP requests use same fallback host (needs channel operations)
- RTN17j connectivity check before fallback (needs HTTP client in RT layer)

### References
- Spec: `RTL3`, `RTL10`, `RTL12`, `RTL13`, `RTL14`, `RTL15`, `RTL23–RTL24`,
  `RTL25`, `RTN17e`, `RTN17j`
- UTS: `realtime/unit/channels/channel_connection_state_test.md`,
  `realtime/unit/channels/channel_properties_test.md`,
  `realtime/unit/channels/channel_server_initiated_detach_test.md`,
  `realtime/unit/channels/channel_additional_attached_test.md`,
  `realtime/unit/channels/channel_error_test.md`,
  `realtime/unit/channels/channel_attributes_test.md`,
  `realtime/unit/channels/channel_when_state_test.md`,
  `realtime/unit/channels/channel_history_test.md`,
  `realtime/unit/connection/fallback_hosts_test.md` (RTN17e, RTN17j remainder)

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 9: Realtime Auth

### Goal
Auth integration with Realtime connections, including server-initiated
re-authentication.

### Steps
<!-- To be filled in during implementation -->

### Includes deferred items from Phase 7c
- RTN22 server-initiated reauth (AUTH message, token renewal without
  disconnect, forced disconnect on failure — needs authCallback in RT layer)

### References
- Spec: `RTC8`, `RSA4` (Realtime parts), `RSA8d` (Realtime), `RTN22`
- UTS: `realtime/unit/auth/`,
  `realtime/unit/connection/server_initiated_reauth_test.md` (RTN22)

---

## Phase 10: Realtime Presence

### Goal
Full presence lifecycle over Realtime WebSocket connections: PresenceMap and
LocalPresenceMap data structures, sync protocol, subscribe/unsubscribe,
enter/update/leave, get with sync waiting, auto re-entry on reattach, and
history delegation to REST.

### Steps

1. **Implement PresenceMap** (RTP2) — the internal map tracking all presence
   members on a channel, keyed by `memberKey` (connectionId:clientId):
   - `put(msg, newness)` → stores member as PRESENT action, returns emitted
     message with original action. Newness check: msgSerial > index > timestamp
     (RTP2b). During sync, LEAVE stored as ABSENT (RTP2h2a).
   - `remove(msg, newness)` → LEAVE removes if newer. During sync, stores as
     ABSENT instead.
   - `get(key)`, `values()` (excludes ABSENT), `clear()`
   - `start_sync()` → mark all current members as residuals (RTP18a)
   - `end_sync()` → remove stale residuals, return synthesized LEAVEs with
     id=None (RTP19), clear sync_in_progress (RTP18b)
   - Newness comparison: synthesized leaves use timestamp (RTP2b1); normal
     messages use msgSerial/index (RTP2b2). Equal timestamps → incoming wins.

2. **Implement LocalPresenceMap** (RTP17) — tracks this client's own presence
   entries, keyed by clientId only:
   - `put(msg)` → stores ENTER/UPDATE/PRESENT. Overwrites existing (RTP17h).
   - `remove(client_id)` → only for non-synthesized LEAVE (RTP17b). Synthesized
     LEAVE (connectionId not prefix of id) is ignored.
   - Populated from server echoes (PRESENCE messages with our connectionId),
     NOT from enter() calls directly.

3. **Implement sync cursor parsing** (RTP18c) — parse `channelSerial` as
   `serial:cursor`. Empty cursor after `:` or no `:` means single-message
   sync (complete immediately).

4. **Implement RealtimePresence** struct wrapping `Arc<PresenceInner>`:
   - Subscribe: `subscribe()`, `subscribe_action(action)`, `subscribe_actions(actions)`
     — RTP6a/b. Triggers implicit attach (RTP6d) unless `attachOnSubscribe=false` (RTP6e).
   - Unsubscribe: `unsubscribe(id)` (RTP7a), `unsubscribe_action(id, action)` (RTP7b),
     `unsubscribe_all()` (RTP7c)
   - Enter/update/leave: `enter(data)` (RTP8), `update(data)` (RTP9),
     `leave(data)` (RTP10)
   - Client methods: `enter_client(clientId, data)` (RTP14),
     `update_client(clientId, data)` (RTP15), `leave_client(clientId, data)` (RTP16)
   - Get: `get()`, `get_with_options(opts)` (RTP11) — waits for sync, supports
     `wait_for_sync: false`, triggers implicit attach (RTP11b)
   - History: delegates to REST presence history (RTP12)

5. **Integrate presence into channel** — add presence field to ChannelInner:
   - Route PRESENCE messages to `handle_presence_message()`
   - Route SYNC messages to `handle_sync_message()`
   - On ATTACHED: call `handle_attached(flags, resumed)` — HAS_PRESENCE
     triggers start_sync; no HAS_PRESENCE clears map with synthesized LEAVEs;
     non-RESUMED triggers re-entry (RTP17i)
   - On DETACHED/FAILED: call `handle_detached_or_failed()` — clear both maps,
     fail queued presence, reset sync state (RTP5a)
   - On ATTACHED: flush queued presence (RTP5b)

6. **Implement ACK/NACK for presence** — reuse the same ACK/NACK mechanism
   as MESSAGE. Presence ProtocolMessages go through `prepare_publish()` which
   assigns msgSerial and registers a waiter. The server ACKs them identically.

7. **Implement auto re-entry** (RTP17i) — on non-RESUMED ATTACHED, iterate
   `local_presence_map.values()` and send ENTER for each member with stored
   clientId and data. On NACK, emit channel UPDATE event with error code
   91004 (RTP17e). If connectionId changed, omit `id` from the re-entry
   message (RTP17g1). Re-entry sends sequentially (each waits for ACK).

8. **Implement implicit attach** (RTP8d, RTP15e, RTP6d, RTP11b) — presence
   operations (enter, enterClient, subscribe, get) trigger channel attach if
   channel is in INITIALIZED or DETACHED state. Use a weak back-reference
   to ChannelInner to avoid circular Arc references.

9. **Write tests** — ~105 tests covering PresenceMap newness (RTP2), sync
   protocol (RTP18/RTP19), channel state effects (RTP1/RTP5/RTL11),
   enter/update/leave (RTP8-10/RTP14-16), subscribe (RTP6/RTP7), get with
   sync waiting (RTP11), history (RTP12), re-entry (RTP17), implicit attach
   (RTP8d/RTP15e/RTP6d/RTP11b), bulk enterClient (RTP4).

### References
- Spec: `RTP1–RTP19`
- UTS: `realtime/unit/presence/` (8 files)

### Findings

- **LocalPresenceMap is populated from server echoes, not enter() calls.**
  When the client calls `enter()`, the server echoes back a PRESENCE message
  with the connection's connectionId. The LocalPresenceMap should be populated
  from these echoes (checking that the connectionId matches), not directly
  from the `enter()` call. This ensures the map reflects server-confirmed
  state.

- **Re-entry sends sequentially, not concurrently.** The `send_presence_immediately()`
  call awaits ACK for each member before proceeding to the next. Tests must
  ACK each re-entry message in turn, otherwise only the first member gets
  re-entered. A test that collects all messages after a fixed sleep will only
  see one.

- **RTP15f (clientId mismatch check) may not be implementable.** The spec says
  to reject `enterClient` when the connection's clientId doesn't match the
  argument. However, `enterClient` is specifically designed for privileged
  connections (wildcard `"*"` clientId) to act on behalf of others. If the
  SDK rejects wildcard `"*"` at the ClientOptions level (as the Ably protocol
  reserves it), there's no way to distinguish "privileged" from "unprivileged"
  connections client-side. The UTS spec acknowledges this: "adapt these tests
  to use a concrete clientId and skip the client-side enterClient clientId
  mismatch check (RTP15f)." Server-side validation handles this instead.

- **Implicit attach needs a weak back-reference.** PresenceInner needs to
  trigger `channel.attach()`, but ChannelInner owns PresenceInner. Using
  `Arc<ChannelInner>` creates a reference cycle. Solution: store a
  `Weak<ChannelInner>` in PresenceInner, set after Arc construction.

- **`attachOnSubscribe` option.** The `subscribe()` method should check the
  channel's `attachOnSubscribe` option (default true). When false, subscribe
  does NOT trigger implicit attach (RTP6e). This requires PresenceInner to
  access channel options, which also goes through the weak back-reference.

- **Sync cursor format.** The `channelSerial` field in SYNC messages uses the
  format `serial:cursor`. If the cursor part (after `:`) is empty or the
  field has no `:`, the sync is complete (single message). This is easy to
  get wrong — splitting on `:` must handle the "empty after colon" case.

- **SUSPENDED state preserves presence map.** Unlike DETACHED and FAILED which
  clear both maps (RTP5a), SUSPENDED does NOT clear the presence map (RTP5f).
  The map is preserved so that presence data is still available when the
  channel reattaches.

- **Data::is_none() may be private.** If the SDK's Data type has a private
  `is_none()` method, use `matches!(member.data, Data::None)` instead when
  checking for empty data in re-entry message construction.

---

## Phase 11: Delta/VCDiff

### Goal
Add delta compression support for Realtime messages. When enabled, the server
sends binary diffs (VCDiff, RFC 3284) between consecutive messages instead of
full payloads. The SDK must decode these deltas and handle errors by triggering
channel reattachment.

### Steps

1. **Add VCDiff decoder dependency** as optional, behind a feature flag (e.g.
   `vcdiff-deltas`). This keeps the dependency out of builds that don't need it.

2. **Define a `DeltaDecoder` trait/interface** with a single method:
   `decode(base: bytes, delta: bytes) -> Result<bytes, Error>`. This abstraction
   enables mock decoders for testing without requiring the real VCDiff library.

3. **Implement mock encoder/decoder for tests** following `mock_vcdiff.md`.
   A simple deterministic algorithm works well (e.g. URL-encoding base and value
   separated by `/`). Also implement a `FailingDecoder` that always returns an
   error for testing RTL18 recovery paths.

4. **Add per-channel delta state** — three fields:
   - `delta_base: Option<Vec<u8>>` — last payload as raw bytes (RTL19)
   - `delta_last_msg_id: Option<String>` — last message ID (RTL20)
   - `delta_decoder: Option<Box<dyn DeltaDecoder>>` — decoder instance (PC3)

5. **Clear delta state on state transitions** — clear `delta_base` and
   `delta_last_msg_id` on DETACHED, FAILED, and non-resumed ATTACHED. Do NOT
   clear on SUSPENDED (delta state should persist like presence map).

6. **Implement delta processing in message delivery** — as a preprocessing step
   before subscriber delivery, inside the message loop:
   - Check if message has `encoding` containing `"vcdiff"` → delta message
   - If delta: check decoder exists (PC3: no decoder → FAILED 40019), get
     base payload, decode, store result as new base (RTL19c), replace data
   - If non-delta: store data as base for future deltas (RTL19b)
   - Update `delta_last_msg_id` after each message (RTL20)
   - Messages in an array must be processed in index order (RTL21)

7. **Implement delta recovery** (RTL18) — on decode failure:
   - Discard the message (RTL18b)
   - Clear delta state (RTL18c)
   - Transition to ATTACHING with error code 40018
   - Send ATTACH with channelSerial for resume (RTL18c)

8. **Wire decoder injection** — when the VCDiff feature is enabled, automatically
   set `RealDecoder` on channels during configuration. When disabled, leave
   `delta_decoder` as None (PC3 triggers on delta message arrival).

### Findings

1. **Delta messages identified by encoding, not extras** — UTS tests identify
   delta messages purely by `encoding: "vcdiff"`, not by checking
   `extras.delta.from`. This is simpler and sufficient.

2. **No-decoder behavior** — UTS test 5 says "emit an error event" with code
   40019 but doesn't specify a state transition. The Ably spec PC3 says the
   channel should transition to FAILED. Follow the spec.

3. **Non-delta messages also update base** — every non-delta message must store
   its data as the base payload (RTL19b), not just messages on delta-enabled
   channels. This ensures the base is always available when the server starts
   sending deltas.

4. **JSON data stored as wire-form** — when a non-delta message has JSON object
   data (not a string), store the JSON serialization as bytes for the base.

5. **Base payload is raw bytes** — string data is stored as UTF-8 bytes,
   binary data as raw bytes. Delta decoding operates on bytes, not strings.

6. **SUSPENDED preserves delta state** — unlike DETACHED/FAILED, SUSPENDED
   should keep delta state intact so that if the channel resumes, deltas can
   continue from where they left off.

7. **Recovery sends ATTACH with channelSerial** — reuse the existing
   `build_attach_message()` which includes the stored `channelSerial` for
   the server to resume from the correct position.

### References
- Spec: `PC3`, `PC3a`, `VD1–VD2`, `RTL18a–c`, `RTL19a–c`, `RTL20`, `RTL21`
- UTS: `realtime/unit/channels/channel_delta_decoding.md`, `realtime/unit/helpers/mock_vcdiff.md`

---

## Phase 12: Mutable Messages & Annotations

### Goal
REST and Realtime support for message mutation (update, delete, append) and
annotations on messages.

### Steps

1. **Add protocol extensions** — `Action::Annotation = 18`, `ANNOTATION_SUBSCRIBE`
   flag (`1 << 20`), `annotations` field on ProtocolMessage.

2. **Add new types:**
   - `MessageAction` enum (TM5): MessageCreate=0, MessageUpdate=1, MessageDelete=2,
     Meta=3, MessageSummary=4, MessageAppend=5
   - `MessageOperation` (MOP2a-c): clientId, description, metadata
   - `UpdateDeleteResult` (UDR1, UDR2a): serial, versionSerial
   - `AnnotationAction` enum (TAN2): AnnotationCreate=0, AnnotationDelete=1
   - `Annotation` (TAN1): type, action, clientId, msgSerial, data, serial, version,
     timestamp, encoding, id, extras

3. **Extend Message** with action (TM2j), serial (TM2r), version (TM2s),
   annotations (TM2u/TM8a) fields.

4. **REST channel methods:**
   - `getMessage(serial)` (RSL11): GET `/channels/{name}/messages/{serial}`
   - `messageVersions(serial)` (RSL14): paginated GET `/channels/{name}/messages/{serial}/versions`
   - `updateMessage/deleteMessage/appendMessage` (RSL15): PATCH with serial validation
     (RSL15a), URL encoding (RSL15b), action in body (RSL15b1), version from
     MessageOperation (RSL15b7), no mutation of original (RSL15c), encoding (RSL15d),
     returns UpdateDeleteResult (RSL15e), query params (RSL15f)
   - `RestAnnotations` (RSL10, RSAN1-3): publish (POST with ANNOTATION_CREATE,
     validates type RSAN1a3), delete (POST with ANNOTATION_DELETE), get (paginated GET)

5. **Realtime channel methods:**
   - `getMessage/messageVersions` (RTL28, RTL31): delegate to REST
   - `updateMessage/deleteMessage/appendMessage` (RTL32): MESSAGE ProtocolMessage
     with MessageAction, serial validation (RTL32a), version from operation (RTL32b2),
     no mutation (RTL32c), ACK/NACK (RTL32d), params (RTL32e)
   - `RealtimeAnnotations` (RTL26, RTAN1-5): publish/delete send ANNOTATION
     ProtocolMessage, get delegates to REST, subscribe with type filter (RTAN4c),
     implicit attach (RTAN4d), mode warning (RTAN4e), unsubscribe

6. **Route annotations** — handle Action::Annotation in channel message dispatch
   and protocol message routing. Add deliver_annotations() for subscriber delivery.

7. **Populate mutable fields** — extract action, serial, version, annotations
   from message JSON in deliver_messages().

### References
- Spec: `RSL10–RSL15`, `RSAN1–RSAN3`, `RTL26`, `RTL28`, `RTL31–RTL32`,
  `RTAN1–RTAN5`, `TM2j/r/s/u`, `TM5`, `TM8/8a`, `MOP2a–c`, `UDR1–2a`, `TAN1–2`
- UTS: `rest/unit/channel/update_delete_message.md`, `rest/unit/channel/annotations.md`,
  `rest/unit/channel/get_message.md`, `rest/unit/channel/message_versions.md`,
  `rest/unit/types/mutable_message_types.md`,
  `realtime/unit/channels/channel_annotations.md`,
  `realtime/unit/channels/channel_update_delete_message.md`,
  `realtime/integration/mutable_messages_test.md`

### Findings

- **Request body inspection needs JSON format.** The default mock client uses
  msgpack. Tests that assert on request body content must use JSON format
  (`.use_binary_protocol(false)`) so the body can be parsed with JSON deserializers.

- **Request body not available in handler.** The mock HTTP client's handler may
  receive a request where `body` is `None` (because `reqwest::Body::as_bytes()`
  returns `None` for streamed bodies). Use `captured_requests()` after the call
  for body inspection instead of checking body inside the handler.

- **RealtimeAnnotations follows RealtimePresence pattern.** Subscribe with
  type filter, implicit attach, mode warning (ANNOTATION_SUBSCRIBE flag),
  unsubscribe by ID — all mirror the presence subscription infrastructure.

- **Serial URL-encoding.** Message serials may contain special characters like
  `@` and `:`. These must be URL-encoded in REST paths. Use a URL-encoding
  library (e.g. `urlencoding` crate in Rust).

---

## Phase 13: LiveObjects

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTO1–RTO19`, `RTLM1–RTLM25`, `RTLC1–RTLC14`, `PO1–PO11`
- UTS: `realtime/unit/objects/`

---

## Phase 14: Hardening

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTE1–RTE6`, `RTB1`, `RTN16`, `RTN20`, `RTN27`

---

## Appendix: UTS Findings Log

| Phase | UTS File | Issue | Resolution |
|-------|----------|-------|------------|
| 10 | `realtime_presence_enter.md` | RTP15f clientId mismatch check assumes wildcard `"*"` clientId is accepted at ClientOptions level | Skip client-side check; server validates. UTS spec acknowledges this adaptation. |
| 10 | `realtime_presence_reentry.md` | RTP17g test was missing server PRESENCE echo to populate LocalPresenceMap | Added echo steps to UTS test |
| 10 | `realtime_presence_reentry.md` | RTP17g used wildcard clientId `"*"` which some SDKs reject | Changed to concrete clientId `"admin"` in UTS |
| 10 | `realtime_presence_channel_state.md` | RTL11 DETACHED test sent DETACHED while ATTACHING, triggering SUSPENDED (RTL13b) instead | Changed to explicit attach+detach approach in UTS |
| 10 | `presence_sync.md` | RTP2h2a assertion was ambiguous about what "stored as ABSENT" means | Clarified assertion wording in UTS |
| 11 | `channel_delta_decoding.md` | No explicit test for "no decoder registered → channel FAILED with 40019" (PC3). UTS mentions the concept in notes but not as a test case | Added `pc3_no_decoder_causes_failed` test based on spec PC3 |
| 11 | `channel_delta_decoding.md` | Test 6 (compound encoding `"vcdiff/utf-8"`) requires full encoding pipeline to strip vcdiff layer and process remaining layers | Deferred — current implementation checks `contains("vcdiff")` but doesn't strip or process remaining encoding layers |

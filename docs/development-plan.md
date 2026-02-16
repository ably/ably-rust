# Ably Rust SDK — Development Plan

## Approach

Development is driven by the **Universal Test Specification (UTS)**. Each phase
implements a set of features, validates the corresponding UTS tests, and
records findings in the generic plan template.

The existing ably-rust codebase provides a working REST client with publishing,
history, presence (read-only), auth, and crypto. This gives us a head start on
REST; the main work is aligning it to UTS test coverage and then building
Realtime from scratch.

## Phased Plan

### Phase 0: Foundation & Test Infrastructure

**Goal:** Establish the testing approach that maps UTS pseudo-code to Rust tests.

Tasks:
- [ ] Set up a mock HTTP client infrastructure (matching UTS `MockHttpClient`)
- [ ] Set up sandbox integration test infrastructure (app provisioning/teardown)
- [ ] Define Rust test conventions: naming, module structure, spec-item comments
- [ ] Verify existing tests pass; update dependencies if needed

**UTS references:**
- `test/rest/unit/helpers/mock_http.md`
- `test/rest/integration/` (sandbox setup pattern)

**Why first:** Everything else depends on being able to write and run tests that
correspond to UTS specs. The existing code has integration tests but no mock
HTTP layer — we need both.

---

### Phase 1: REST Client Core & Types

**Goal:** Align the existing REST client with UTS, fill gaps.

Tasks:
- [ ] `ClientOptions` — validate against `TO1–TO3`, `RSC1`
- [ ] `RestClient` attributes — `RSC5`, `RSC7` (headers), `RSC8` (protocol), `RSC13` (timeouts), `RSC17` (clientId), `RSC18` (TLS)
- [ ] `ErrorInfo` type — `TI1–TI5`
- [ ] Logging — `RSC2–RSC4` (may be deferred if low priority)
- [ ] HTTP request/response types — format negotiation, content types

**UTS test specs:**
- `rest/unit/rest_client.md`
- `rest/unit/types/options_types.md`
- `rest/unit/types/error_types.md`

**Existing state:** Most of this is implemented. Primary work is writing mock-based
unit tests to match UTS and fixing any discrepancies.

---

### Phase 2: Auth

**Goal:** Complete auth implementation, fully tested against UTS.

Tasks:
- [ ] Basic auth — `RSA1`, `RSA2`, `RSA11`
- [ ] Token auth selection logic — `RSA3`, `RSA4`
- [ ] Token params — `RSA5` (TTL), `RSA6` (capability)
- [ ] Client ID — `RSA7`, `RSA12`, `RSA15`
- [ ] `requestToken` — `RSA8`
- [ ] `createTokenRequest` — `RSA9`
- [ ] `authorize` — `RSA10`
- [ ] Token renewal on 401 — `RSC10`, `RSA4b4`
- [ ] Token details type — `RSA16`
- [ ] Auth callback / auth URL — `RSA8c`, `RSA8d`
- [ ] Token revocation — `RSA17`
- [ ] `TokenDetails` type — `TD1–TD7`
- [ ] `TokenRequest` type — `TE1–TE6`

**UTS test specs:**
- `rest/unit/auth/` (8 files)
- `rest/unit/types/token_types.md`
- `rest/integration/auth.md`
- `rest/integration/revoke_tokens.md`

**Existing state:** Auth is largely implemented. Need to add `authorize()`,
token revocation, and align unit tests to UTS mock patterns.

---

### Phase 3: REST Channels — Publish, History, Encoding

**Goal:** Complete REST channel operations with full UTS coverage.

Tasks:
- [ ] Publish — `RSL1` (including idempotent publishing `RSL1k`)
- [ ] History — `RSL2`
- [ ] Message encoding/decoding — `RSL4`, `RSL6`
- [ ] Message type — `TM1–TM5`
- [ ] Pagination — `TG1–TG7`
- [ ] Channel collection — `RSN1–RSN4`
- [ ] Channel attributes — `RSL7–RSL9`

**UTS test specs:**
- `rest/unit/channel/` (9 files)
- `rest/unit/encoding/message_encoding.md`
- `rest/unit/types/message_types.md`
- `rest/unit/types/paginated_result.md`
- `rest/unit/channels_collection.md`
- `rest/integration/publish.md`
- `rest/integration/history.md`
- `rest/integration/pagination.md`

**Existing state:** Publish and history work. Need idempotent publishing,
publish result with serials, and full encoding pipeline tests.

---

### Phase 4: REST Presence

**Goal:** Complete REST presence with UTS coverage.

Tasks:
- [ ] Presence get — `RSP3`
- [ ] Presence history — `RSP4`
- [ ] Presence message decoding — `RSP5`
- [ ] PresenceMessage type — `TP1–TP5`

**UTS test specs:**
- `rest/unit/presence/rest_presence.md`
- `rest/unit/types/presence_message_types.md`
- `rest/integration/presence.md`

**Existing state:** Basic presence get/history works. Needs UTS test alignment.

---

### Phase 5: Fallback Hosts & Endpoint Configuration

**Goal:** Robust host fallback behavior.

Tasks:
- [ ] Primary domain determination — `REC1`
- [ ] Fallback domains — `REC2`
- [ ] Connectivity check — `REC3`
- [ ] Fallback behavior — `RSC15`

**UTS test specs:**
- `rest/unit/fallback.md`

**Existing state:** Basic fallback exists. Needs full UTS alignment.

---

### Phase 6: Additional REST Features

**Goal:** Remaining REST features before starting Realtime.

Tasks:
- [ ] `request()` function — `RSC19`
- [ ] `time()` function — `RSC16`
- [ ] `stats()` function — `RSC6`
- [ ] Batch publish — `RSC22`
- [ ] Batch presence — `RSC24`
- [ ] Push admin — `RSH1`
- [ ] Request endpoint — `RSC25`
- [ ] Message encryption — `RSL5`, `RSE1`, `RSE2`
- [ ] Mutable messages — `RSL11`, `RSL14`, `RSL15`
- [ ] Annotations — `RSL10`, `RSAN1–RSAN3`

**UTS test specs:**
- `rest/unit/request.md`, `rest/unit/time.md`, `rest/unit/stats.md`
- `rest/unit/batch_publish.md`, `rest/unit/batch_presence.md`
- `rest/unit/push/` (3 files)
- `rest/unit/request_endpoint.md`
- `rest/unit/channel/annotations.md`
- `rest/unit/channel/get_message.md`, `rest/unit/channel/message_versions.md`
- `rest/unit/channel/update_delete_message.md`
- `rest/integration/` (remaining files)

**Existing state:** time, stats, request partially exist. Batch, push, mutable
messages, annotations are new.

---

### Phase 7a: Realtime — Types, Transport & Basic Connection

**Goal:** Build the foundation: types, mock WebSocket, state machine, basic
connect/close lifecycle.

Tasks:
- [ ] Add `tokio-tungstenite` WebSocket dependency
- [ ] `ConnectionState` enum — INITIALIZED, CONNECTING, CONNECTED, DISCONNECTED,
      SUSPENDED, CLOSING, CLOSED, FAILED
- [ ] `ConnectionStateChange` type — previous, current, event, reason
- [ ] `ProtocolMessage` type — action enum, fields (connectionId, connectionKey,
      connectionSerial, connectionDetails, error, etc.)
- [ ] `ConnectionDetails` type — connectionKey, maxIdleInterval, connectionStateTtl
- [ ] Mock WebSocket infrastructure (matching UTS `MockWebSocket`)
- [ ] `RealtimeClient` constructor — `RTC1`, `RTC12`
- [ ] `Connection` type with state machine — `RTN4`
- [ ] Connect — `RTC15`, `RTN11`
- [ ] Close — `RTC16`, `RTN12`
- [ ] Auto-connect — `RTN3`
- [ ] Connection events (on/once) — `RTN4`
- [ ] Connection ID and key — `RTN8`, `RTN9`
- [ ] Error reason — `RTN25`

**UTS test specs:**
- `realtime/unit/helpers/mock_websocket.md`
- `realtime/unit/connection/auto_connect_test.md` — RTN3 (3 tests)
- `realtime/unit/connection/connection_id_key_test.md` — RTN8, RTN9 (9 tests)
- `realtime/unit/connection/error_reason_test.md` — RTN25 (8 tests)
- `realtime/unit/client/realtime_client.md` — RTC1–RTC17 (subset)
- `realtime/unit/client/client_options.md` — RSC1 (subset)

**Existing state:** Not implemented. This sub-phase establishes all foundational
types and the basic happy-path connection lifecycle.

---

### Phase 7b: Realtime — Connection Failures, Resume & Ping

**Goal:** Robust connection failure handling, resume/recovery, and ping.

Tasks:
- [ ] Connection open failures — `RTN14` (invalid key, timeout, retry,
      DISCONNECTED→SUSPENDED transition)
- [ ] Connection failures while connected — `RTN15` (resume with connectionKey,
      failed resume, token errors, connectionStateTtl expiry)
- [ ] Ping — `RTN13` (HEARTBEAT send/receive, timeout, state-dependent behavior)
- [ ] `whenState` — `RTN26`
- [ ] Update events — `RTN24`

**UTS test specs:**
- `realtime/unit/connection/connection_open_failures_test.md` — RTN14 (8 tests)
- `realtime/unit/connection/connection_failures_test.md` — RTN15 (15 tests)
- `realtime/unit/connection/connection_ping_test.md` — RTN13 (16 tests)
- `realtime/unit/connection/when_state_test.md` — RTN26 (5 tests)
- `realtime/unit/connection/update_events_test.md` — RTN24 (4 tests)

**Depends on:** Phase 7a

---

### Phase 7c: Realtime — Heartbeats, Fallback & Timeouts

**Goal:** Heartbeat idle detection, fallback host handling, and timeout
configuration.

Tasks:
- [ ] Heartbeats / idle detection — `RTN23` (HEARTBEAT protocol or ping frames,
      maxIdleInterval, idle timeout → reconnect)
- [ ] Fallback hosts for Realtime — `RTN17` core (primary domain preference,
      random fallback ordering, error conditions for fallback, empty fallback set)
- [ ] Timeout configuration — `RTC7` (default values, disconnectedRetryTimeout)

**Deferred to later phases (require channels or auth):**
- RTN17e (HTTP requests use same fallback host) → **Phase 8** (needs channels)
- RTN17j (connectivity check before fallback) → **Phase 8** (needs HTTP in RT)
- RTN22 (server-initiated reauth) → **Phase 9** (needs authCallback in RT)
- RTN7 (ACK/NACK) → **Phase 8** (needs channel publish to be meaningful)
- RTC7 attach/detach timeout tests → **Phase 8** (needs channel attach/detach)

**UTS test specs:**
- `realtime/unit/connection/heartbeat_test.md` — RTN23 (16 tests, RTN23a subset)
- `realtime/unit/connection/fallback_hosts_test.md` — RTN17 (core subset)
- `realtime/unit/client/realtime_timeouts.md` — RTC7 (default + retry subset)

**Depends on:** Phase 7b

---

### Phase 8a: Realtime — Channel Foundation

**Goal:** Channel collection, state machine, and options infrastructure.

Tasks:
- [ ] Channels collection — `RTS1–RTS4` (get, release, iteration)
- [ ] Channel state events — `RTL2` (state change EventEmitter)
- [ ] Channel options — `TB2–TB4`, `RTS3`, `RTL16` (modes, params)

**UTS test specs:**
- `realtime/unit/channels/channels_collection_test.md`
- `realtime/unit/channels/channel_state_events_test.md`
- `realtime/unit/channels/channel_options_test.md`

**Why first:** Everything else depends on being able to create channels and
observe state changes. No dependency on attach/detach.

---

### Phase 8b: Realtime — Attach & Detach

**Goal:** Core channel lifecycle operations.

Tasks:
- [ ] Attach — `RTL4` (attach flow, implicit attach, error handling)
- [ ] Detach — `RTL5` (detach flow, error states)
- [ ] RTC7 attach/detach timeouts (deferred from Phase 7c)
- [ ] ACK/NACK — `RTN7` (deferred from Phase 7c, needed for attach confirmations)

**UTS test specs:**
- `realtime/unit/channels/channel_attach_test.md` (16 tests)
- `realtime/unit/channels/channel_detach_test.md` (13 tests)
- `realtime/unit/client/realtime_timeouts.md` — RTC7 attach/detach tests

**Depends on:** Phase 8a

---

### Phase 8c: Realtime — Messages

**Goal:** Publishing and subscribing to messages on channels.

Tasks:
- [ ] Publish — `RTL6` (publish, queuing, encoding, implicit attach)
- [ ] Subscribe/unsubscribe — `RTL7`, `RTL8` (subscribe, filtering)
- [ ] Message field population — `TM2` (id, timestamp, connectionId, etc.)

**UTS test specs:**
- `realtime/unit/channels/channel_publish_test.md` (23 tests, ~60K)
- `realtime/unit/channels/channel_subscribe_test.md` (16 tests)
- `realtime/unit/channels/message_field_population_test.md` (8 tests)

**Depends on:** Phase 8b

---

### Phase 8d: Realtime — Advanced Channel Features

**Goal:** Connection-state impact, server-initiated events, history, and edge
cases.

Tasks:
- [ ] Connection state effects — `RTL3`
- [ ] Channel properties — `RTL15` (attachSerial, channelSerial)
- [ ] Server-initiated detach — `RTL13`
- [ ] Additional ATTACHED — `RTL12` (reattach on updated ATTACHED)
- [ ] Error handling — `RTL14`
- [ ] Channel attributes — `RTL23–RTL24`
- [ ] `whenState` — `RTL25`
- [ ] Channel history — `RTL10`
- [ ] RTN17e HTTP requests use same fallback host (deferred from Phase 7c)
- [ ] RTN17j connectivity check before fallback (deferred from Phase 7c)

**UTS test specs:**
- `realtime/unit/channels/channel_connection_state_test.md`
- `realtime/unit/channels/channel_properties_test.md`
- `realtime/unit/channels/channel_server_initiated_detach_test.md`
- `realtime/unit/channels/channel_additional_attached_test.md`
- `realtime/unit/channels/channel_error_test.md`
- `realtime/unit/channels/channel_attributes_test.md`
- `realtime/unit/channels/channel_when_state_test.md`
- `realtime/unit/channels/channel_history_test.md`
- `realtime/unit/connection/fallback_hosts_test.md` — RTN17e, RTN17j remainder

**Depends on:** Phase 8c

---

### Phase 9: Realtime — Auth

**Goal:** Auth integration with Realtime connections, including server-initiated
re-authentication.

Tasks:
- [ ] Connection auth — `RSA4` Realtime parts
- [ ] Realtime authorize — `RTC8`
- [ ] Token renewal over connection — `RSA8d` Realtime parts
- [ ] Server-initiated reauth — `RTN22` (AUTH message, token renewal without
      disconnect, forced disconnect on failure) — deferred from Phase 7c

**UTS test specs:**
- `realtime/unit/auth/` (2 files)
- `realtime/integration/auth.md`
- `realtime/unit/connection/server_initiated_reauth_test.md` — RTN22 (3 tests)

---

### Phase 10: Realtime — Presence

**Goal:** Full presence lifecycle over Realtime.

Tasks:
- [ ] Presence map — `RTP2`
- [ ] Enter/update/leave — `RTP8–RTP10`
- [ ] Subscribe/unsubscribe — `RTP6–RTP7`
- [ ] Get — `RTP11`
- [ ] History — `RTP12`
- [ ] Sync — `RTP18–RTP19`
- [ ] Channel state effects — `RTP5`, `RTL11`
- [ ] Connection state conditions — `RTP16`
- [ ] Client methods (enterClient etc.) — `RTP14–RTP15`
- [ ] Local presence map — `RTP17`

**UTS test specs:**
- `realtime/unit/presence/` (8 files)
- `realtime/integration/presence_lifecycle_test.md`

**Existing state:** Not implemented.

---

### Phase 11: Delta/VCDiff Decoding

**Goal:** Delta compression support for Realtime messages.

Tasks:
- [ ] VCDiff decoder plugin — `PC3`, `VD1–VD2`
- [ ] Delta decoding in channels — `RTL18–RTL21`

**UTS test specs:**
- `realtime/unit/channels/channel_delta_decoding.md`
- `realtime/unit/helpers/mock_vcdiff.md`
- `realtime/integration/delta_decoding_test.md`

---

### Phase 12: LiveObjects

**Goal:** LiveObjects (Maps, Counters, Path Objects) — if required.

Tasks:
- [ ] Objects pool — `RTO3–RTO10`
- [ ] LiveMap — `RTLM1–RTLM25`
- [ ] LiveCounter — `RTLC1–RTLC14`
- [ ] Path Objects API — `PO1–PO11`
- [ ] Create/batch operations — `RTO11–RTO16`
- [ ] Sync state machine — `RTO17`
- [ ] Subscriptions — `RTO18–RTO19`

**UTS test specs:**
- `realtime/unit/objects/` (11 files)
- `realtime/integration/objects_*.md` (3 files)

**Note:** This is a large, relatively new feature area. May be deferred.

---

### Phase 13: Mutable Messages & Annotations (Realtime)

**Goal:** Realtime support for message mutation and annotations.

Tasks:
- [ ] GetMessage/GetMessageVersions — `RTL28`, `RTL31`
- [ ] Update/Delete/Append — `RTL32`
- [ ] Annotations — `RTL26`, `RTAN1–RTAN5`

**UTS test specs:**
- `realtime/unit/channels/channel_get_message.md`
- `realtime/unit/channels/channel_message_versions.md`
- `realtime/unit/channels/channel_update_delete_message.md`
- `realtime/unit/channels/channel_annotations.md`
- `realtime/integration/mutable_messages_test.md`

---

### Phase 14: Hardening & Completion

**Goal:** Edge cases, robustness, and completeness.

Tasks:
- [ ] EventEmitter — `RTE1–RTE6`
- [ ] Incremental backoff and jitter — `RTB1`
- [ ] Connection recovery — `RTN16`
- [ ] OS network change handling — `RTN20` (platform-specific)
- [ ] Forwards compatibility — `RSF1`, `RTF1`
- [ ] Connection state machine completeness — `RTN27`
- [ ] Push notifications (device-side) — `RSH2–RSH8` (may be out of scope)

---

## Feature Dependency Graph

```
Phase 0: Test Infrastructure
    │
    ├── Phase 1: REST Core & Types
    │       │
    │       ├── Phase 2: Auth
    │       │       │
    │       │       ├── Phase 3: Channels (Publish/History/Encoding)
    │       │       │       │
    │       │       │       ├── Phase 4: Presence (REST)
    │       │       │       │
    │       │       │       └── Phase 5: Fallback Hosts
    │       │       │
    │       │       └── Phase 6: Additional REST
    │       │
    │       └── Phase 7a: Realtime Types & Basic Connection
    │               │
    │               └── Phase 7b: Failures, Resume & Ping
    │                       │
    │                       └── Phase 7c: Heartbeats, Fallback, Timeouts
    │                               │
    │                               └── Phase 8a: Channel Foundation
    │                                       │
    │                                       └── Phase 8b: Attach/Detach (+RTN7, RTC7)
    │                                               │
    │                                               └── Phase 8c: Messages
    │                                                       │
    │                                                       └── Phase 8d: Advanced (+RTN17e/j)
    │                                                               │
    │                                                               ├── Phase 10: Presence
    │                                                               ├── Phase 11: VCDiff
    │                                                               ├── Phase 12: LiveObjects
    │                                                               └── Phase 13: Mutable Messages
    │                               │
    │                               └── Phase 9: RT Auth (+RTN22)
    │
    └── Phase 14: Hardening
```

**Sequencing rationale:** Features that cross-cut connection, channels, and auth
are placed in the phase where their primary dependency is satisfied:
- RTN22 (server reauth) requires authCallback → Phase 9 (RT Auth)
- RTN7 (ACK/NACK), RTN17e (HTTP fallback), RTC7 timeouts → Phase 8 (Channels)
- This avoids partial implementations and deferred items within each phase.

## Notes on UTS Validation

As we implement each phase, track:
- **Ambiguities** — where UTS pseudo-code is unclear about expected behavior
- **Errors** — incorrect assertions or setup in UTS tests
- **Missing coverage** — spec items without UTS tests (visible in completion-status.md)
- **Language assumptions** — UTS patterns that don't map cleanly to Rust

Record these in `docs/uts-findings.md` (created as findings emerge).

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

### Phase 7: Realtime — Connection

**Goal:** WebSocket connection with state machine, the foundation for all Realtime.

Tasks:
- [ ] WebSocket transport layer
- [ ] Connection state machine — `RTN4`, `RTN27`
- [ ] `RealtimeClient` constructor — `RTC1`, `RTC12`
- [ ] Connect/close — `RTC15`, `RTC16`, `RTN11`, `RTN12`
- [ ] Auto-connect — `RTN3`
- [ ] Connection ID and key — `RTN8`, `RTN9`
- [ ] Ping — `RTN13`
- [ ] Heartbeats — `RTN23`
- [ ] Connection open failures — `RTN14`
- [ ] Connection failures while connected — `RTN15`
- [ ] Fallback hosts for Realtime — `RTN17`
- [ ] Error reason — `RTN25`
- [ ] `whenState` — `RTN26`
- [ ] ACK/NACK — `RTN7`
- [ ] Connection events — `RTN4`, `RTN24`
- [ ] Update events — `RTN21`
- [ ] Server-initiated reauth — `RTN22`
- [ ] Mock WebSocket infrastructure

**UTS test specs:**
- `realtime/unit/helpers/mock_websocket.md`
- `realtime/unit/connection/` (11 files)
- `realtime/unit/client/` (5 files)
- `realtime/integration/connection_lifecycle_test.md`

**Existing state:** Not implemented. This is the largest new piece of work.

---

### Phase 8: Realtime — Channels

**Goal:** Channel attach/detach, publish, subscribe over Realtime.

Tasks:
- [ ] Channel state machine — `RTL2`
- [ ] Connection state side effects — `RTL3`
- [ ] Attach — `RTL4`
- [ ] Detach — `RTL5`
- [ ] Publish — `RTL6`
- [ ] Subscribe/unsubscribe — `RTL7`, `RTL8`
- [ ] History — `RTL10`
- [ ] Channel properties — `RTL15`
- [ ] Channel options — `RTL16`, `RTS3`
- [ ] Server-initiated detach — `RTL13`
- [ ] Error handling — `RTL14`
- [ ] Additional ATTACHED — `RTL12`
- [ ] Message ordering — `RTL21`
- [ ] Channels collection — `RTS1–RTS5`
- [ ] Channel attributes — `RTL23–RTL24`
- [ ] `whenState` — `RTL25`

**UTS test specs:**
- `realtime/unit/channels/` (14 files)
- `realtime/integration/channel_history_test.md`

**Existing state:** Not implemented.

---

### Phase 9: Realtime — Auth

**Goal:** Auth integration with Realtime connections.

Tasks:
- [ ] Connection auth — `RSA4` Realtime parts
- [ ] Realtime authorize — `RTC8`
- [ ] Token renewal over connection — `RSA8d` Realtime parts

**UTS test specs:**
- `realtime/unit/auth/` (2 files)
- `realtime/integration/auth.md`

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
    │       └── Phase 7: Realtime Connection ──────────────────┐
    │               │                                          │
    │               ├── Phase 8: Realtime Channels             │
    │               │       │                                  │
    │               │       ├── Phase 10: Realtime Presence    │
    │               │       │                                  │
    │               │       ├── Phase 11: Delta/VCDiff         │
    │               │       │                                  │
    │               │       ├── Phase 12: LiveObjects          │
    │               │       │                                  │
    │               │       └── Phase 13: Mutable Msgs         │
    │               │                                          │
    │               └── Phase 9: Realtime Auth ────────────────┘
    │
    └── Phase 14: Hardening
```

## Notes on UTS Validation

As we implement each phase, track:
- **Ambiguities** — where UTS pseudo-code is unclear about expected behavior
- **Errors** — incorrect assertions or setup in UTS tests
- **Missing coverage** — spec items without UTS tests (visible in completion-status.md)
- **Language assumptions** — UTS patterns that don't map cleanly to Rust

Record these in `docs/uts-findings.md` (created as findings emerge).

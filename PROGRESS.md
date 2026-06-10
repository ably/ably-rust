# Rewrite Progress

## Phase 1: API Design — DONE
- `DESIGN.md` written and reviewed
- Key decisions: single `ErrorInfo` type (TI1 spec, no separate `Error` wrapper),
  no reqwest in public API, `Transport` trait, clean `HttpClient` trait,
  builder publish for REST and Realtime
- Fields added from spec review: `request_id` (RSC7c), `detail` (TI6), `cause` (TI1)

## Phase 2: Branch Setup + Stubs + Test Port — DONE

### 2.1 Branch + Module Skeleton — DONE
- Created `clean-rewrite` branch from `main`
- Files written fresh:
  - `error.rs` — unified `ErrorInfo` with TI1 fields, `ErrorCode` enum, `Result<T>` alias
  - `transport.rs` — `Transport` + `TransportConnection` traits (pub(crate))
  - `http_client.rs` — `HttpClient` trait (pub(crate)), no as_any
  - `protocol.rs` — pub state enums, pub(crate) wire types
  - `realtime.rs` — `Realtime`, `Connection`, `RealtimeAuth` stubs
  - `channel.rs` — `Channels`, `RealtimeChannel`, `RealtimePresence` stubs
  - `mock_http.rs` — `MockHttpClient` implementing `HttpClient` trait
  - `mock_ws.rs` — `MockWebSocket` stubs
- Files adapted from main:
  - `crypto.rs` — updated Error→ErrorInfo references, removed tests (to be ported)
  - `stats.rs` — copied verbatim
  - `json.rs` — copied verbatim
  - `options.rs` — rewritten: no reqwest refs, all fields pub(crate), builder pattern
  - `auth.rs` — rewritten: `AuthToken` enum, `Credential` pub(crate), no reqwest types
  - `rest.rs` — rewritten: unified `Message`/`Data`/`PresenceMessage`, all stubs
  - `http.rs` — rewritten: no reqwest re-exports, `u16` status, `Option<String>` content_type
- Removed `examples/` directory (old API references)
- `Cargo.toml` updated with async-trait, tokio, tokio-tungstenite dependencies
- `cargo check` passes, `cargo test --lib --no-run` passes (0 tests)

### 2.2 Test Port — DONE
- **Source:** `lib.rs.bak` (backup of original monolithic test module, 1,157 test attributes)
- Extracted all tests using Python script (`/tmp/split_tests3.py`)
- Split into 12 thematic test files by spec prefix:
  - `tests_annotations.rs` (20 tests) — RTAN specs
  - `tests_auth.rs` (123 tests) — RSA specs
  - `tests_channel.rs` (196 tests) — RTL, RTS, PC specs
  - `tests_connection.rs` (127 tests) — RTN, RTB specs
  - `tests_misc.rs` (83 tests) — shared/general tests
  - `tests_presence_rt.rs` (119 tests) — RTP specs
  - `tests_push.rs` (44 tests) — RSH specs
  - `tests_realtime_misc.rs` (48 tests) — RTC specs
  - `tests_rest_channels.rs` (101 tests) — RSL, RSN specs
  - `tests_rest_core.rs` (161 tests) — RSC, HP, BAR, etc.
  - `tests_rest_presence.rs` (37 tests) — RSP specs
  - `tests_types.rs` (98 tests) — TM, TP, TE, TK, etc.
- Fixed 1,410 compilation errors across all files using 6 parallel agents
- Each file has shared helper functions (mock_client, get_mock, phase8d_setup, setup_attached_channel)
- 12 test functions have `todo!()` bodies (need APIs like `set_state` that will exist post-implementation)
- `cargo check --tests` passes with 0 errors, 47 warnings
- `cargo test --no-run` passes

### 2.3 Verify Completeness — DONE
- Original backup: 1,157 test attributes → split files: 1,157 test attributes (lossless)
- `cargo test -- --list`: 1,157 tests, 0 benchmarks
- 12 tests have `todo!()` bodies pending real implementation (rtl10a/b, rtp8g, rtp11b/d, rtp14a, rtp16c)
- All tests will panic at runtime (stubs return `todo!()`) — by design for Phase 2

## Phase 3: REST Implementation — DONE

### 3.0 REST State Design — DONE
- Written in DESIGN.md: RestInner with 2 independent Mutex (auth_state, fallback_state)
- Token resolution, request pipeline, fallback host caching (RSC15f) all documented

### 3.1–3.3 REST Core + Auth + Channels + Presence + Push — DONE
- Implemented full request pipeline: URL construction, standard headers, auth resolution,
  retry/fallback logic, token renewal on 401 (40140-40149), fallback host caching (RSC15f)
- Implemented Auth: create_token_request (HMAC-SHA256 signing), request_token, authorize,
  revoke_tokens, token caching, saved_token_params
- Implemented REST channels: publish (builder), history, get_message, message_versions,
  update/delete/append_message, annotations
- Implemented REST presence: get, history
- Implemented Push: admin publish, device registrations CRUD, channel subscriptions CRUD
- Implemented pagination: PaginatedResult with Link header parsing, next/first navigation
- Implemented RequestBuilder, Response with JSON/msgpack deserialization
- HttpClient trait with as_any() for test mock downcasting (pub(crate) only)
- MockHttpClient: captured_requests now returns cloned data
- Files changed: rest.rs, auth.rs, http.rs, http_client.rs, options.rs, mock_http.rs, error.rs
- Test results: 662 passed, 440 failed (all Realtime), 55 ignored
  - tests_rest_core: 161/161 pass
  - tests_rest_channels: 100/100 pass (1 ignored)
  - tests_rest_presence: 37/37 pass
  - tests_push: 44/44 pass
  - tests_misc: 83/83 pass
  - tests_auth: 119/123 pass (4 are Realtime tests)
  - tests_types: 90/98 pass (8 are Realtime tests)

## Source Branch Reference
- Tests and implementations are on `uts-experiments` branch
- Test file: `uts-experiments:src/lib.rs` lines ~4411–40609 (unit_tests module)
- Integration tests: `uts-experiments:src/lib.rs` lines ~35–4410

## Key API Differences (uts-experiments → clean-rewrite)
- `Error` → `ErrorInfo` everywhere
- `error::Error::new(ErrorCode::X, msg)` → `ErrorInfo::new(ErrorCode::X.code(), msg)`
- `rest::Encoding::None` → encoding field is `Option<String>`, None means no encoding
- `rest::Format` → `rest::Format` (same but pub(crate))
- `http::Method::GET` etc → `"GET"` string
- `http::HeaderMap` → `Vec<(String, String)>` or `&[(&str, &str)]`
- `auth::RequestOrDetails` → `auth::AuthToken`
- `auth::Credential` stays but is `pub(crate)`
- `channel::Message` → `rest::Message` (unified)
- `ErrorInfo` (old, limited) → `ErrorInfo` (new, full TI1 spec with cause/detail/request_id)

## Phase R: REST Remediation (plan rev 2)

### R1 Wire-Protocol Correctness — DONE (2026-06-10)
- TM5: MessageAction wire values fixed to spec (CREATE=0, UPDATE=1, DELETE=2, META=3,
  SUMMARY=4, APPEND=5). Previously update_message sent DELETE on the wire.
- RSL15: update/delete/append_message rewritten — op is Option<&MessageOperation>,
  serial-missing errors with 40003, body carries full message fields encoded per RSL4,
  version only when op provided, UpdateDeleteResult fields now Option<String> (UDR2a
  null preserved). New shared send_message_patch.
- RSL4c: new Message::encode_for_wire(format) — JSON data stringified + "json" encoding;
  binary base64 under JSON, native bin under MessagePack. Used by PublishBuilder,
  message PATCH, and batch publish.
- RSC24: batch_presence sends comma-joined channels param; returns BatchPresenceResponse
  envelope (success_count/failure_count/results) with Success/Failure variants.
- Batch result parsing: BatchPublishResult/BatchPresenceResult deserialization
  discriminates on presence of "error" key (fixes untagged-serde bug; bpr1b/c un-ignored).
- RSC22: batch_publish rejects empty specs/channels/messages with 40003 client-side;
  accepts object-or-array responses.
- RSA17: revoke_tokens parses BatchResult envelope (v3+), legacy array fallback.
- AuthOptions::default() method now Some("GET") (AO2d).
- Stale tests fixed: rsa17d (40162), rsh1b3 (path with deviceId), tm3 (action=1 is UPDATE).
- Tests rewritten UTS-faithful: RSL15 block (13 tests incl. new rsl15c no-mutate, rsl15d),
  batch presence block (RSC24_1/2/3, BAR2_1/3, BGR2_1/2, BGF2_1, mixed, error x2),
  rsa17c envelope test, rsl4c x2; legacy-format duplicates deleted.
- Test status: unit 724 pass / 439 fail (realtime stubs) / 92 ignored;
  integration 47/47 pass against sandbox.
- Files: rest.rs, auth.rs, tests_rest_unit_{channel,client,auth,push,types}.rs,
  tests_realtime_unit_channel.rs, CLAUDE.md
- Next: R2 auth layer rewrite.

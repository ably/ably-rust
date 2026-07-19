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

### R2 Auth Layer Rewrite — DONE (2026-06-10)
- AuthOptions now full AO2 shape (key, token, tokenDetails, authCallback, authUrl,
  authMethod, authHeaders, authParams, queryTime); default authMethod GET.
  API signatures: create_token_request/request_token/authorize take
  (Option<&TokenParams>, Option<&AuthOptions>); create_token_request is async (queryTime).
- New AuthConfig resolution: client credential overlaid with authorize()-saved options
  (RSA10h replace-with-source semantics, RSA10i key preserved) and per-call options.
- authUrl (RSA8c) implemented: GET/POST, authHeaders/authParams, TokenParams merge
  (RSA8c1a/b), JSON TokenDetails/TokenRequest (exchanged) or plain-text JWT responses,
  via raw http_client (no Ably pipeline). Credential::TokenRequest exchangeable.
- AuthToken::Token variant for JWT-string callbacks (RSA8d).
- Auth-mode selection (RSA4): basic only for key-only clients; clientId is NOT a
  token-auth trigger; key+clientId uses basic + X-Ably-ClientId (RSA7e2, header now
  basic-only); authorize() forces token auth thereafter (RSA10a).
- Token acquisition: effective params merge defaultTokenParams + options.clientId
  (RSA5c/6c, RSA7d, RSA12a); ttl/capability omitted + signed as empty when unspecified
  (RSA5/RSA6 — restricted keys now work); pre-emptive expiry renewal (RSA4b1);
  40171 client-side when unrenewable (RSA4a2); RSA15 clientId compatibility at
  construction and on every obtained token (40102).
- authorize(): params/options replace stored (timestamp never stored, RSA10g);
  updates tokenDetails (RSA10g); request_token no longer mutates library state (RSA8f).
- queryTime (RSA9d/RSA10k): /time queried with offset cached; time() is now
  UNAUTHENTICATED per RSC16 (UTS: must not send Authorization).
- RSA17d_2: key+useTokenAuth revoke rejected 40162. Key Debug/Display redact secret.
- Tests: vacuous auth tests replaced with 18 UTS-derived tests (authUrl x7, RSA15 x3,
  RSA4a2, RSA4b1, RSA12a/b, RSA7d, RSA1, RSA8d, RSA17d_2), all passing first run;
  rsa9h/rsa9-depth tests fixed to RSA5/RSA6 null semantics; ~20 tests switched from
  time() to authenticated requests; rsa16 tests fixed per RSA8f.
- Test status: unit 731 pass / 439 fail (realtime stubs) / 92 ignored;
  integration 47/47 vs sandbox.
- Files: auth.rs (rewritten), rest.rs (auth machinery), options.rs, http.rs,
  tests_rest_unit_{auth,client,misc,types}.rs, tests_rest_integration.rs
- Next: R3 publish features (idempotency, encryption, RSL1n serials).

### R3 Publish Features — DONE (2026-06-10)
- RSL1k idempotent publishing: default true (TO3n); library ids base64url(9 random
  bytes):index, one base per publish, client ids preserved, mixed batches per UTS;
  RSC22d applied per BatchPublishSpec.
- RSL5/RSL6 encryption: shared encode_data_for_wire/decode_data codec; cipher threaded
  through PublishBuilder (builder override or channel cipher), history, get_message,
  message_versions, presence get/history, PaginatedResult pages. PublishBuilder::cipher
  no longer a no-op. Message/PresenceMessage decode unified (duplication removed).
- RSL6b: decode failure/unknown step leaves the UNPROCESSED chain prefix (applied
  right-hand steps are not restored).
- RSL1c/RSL1n: PublishBuilder::messages() for multi-message publish (single message →
  object body, multiple → array); send() returns PublishResult {serials, message_id}
  with null-serial (conflation) preservation (PBR2a).
- RSL1i: size check now per TM6 (name + clientId + extras + data), pre-encoding.
- RSL4a: top-level JSON scalars (number/bool) rejected with 40013.
- Tests: conditional-assert idempotency tests rewritten strict (id format, serial
  increments, unique bases, mixed batch); RSL1n result tests (single/batch/null);
  RSL5 encrypt round-trip x2; RSL6 history decrypt; RSL6b residual; RSP5g presence
  decrypt; canonical ably-common crypto fixtures (128+256, all items, both files) —
  NOTE: the UTS RSP5g fixture string is corrupt (truncation of the ably-common one);
  flag upstream.
- Test status: unit 742 pass / 439 fail (realtime stubs) / 91 ignored;
  integration 47/47 vs sandbox.
- DESIGN.md not yet updated for API changes (PublishResult, messages(), auth
  signatures) — do at end of Phase R.
- Next: R4 endpoint spec + request pipeline.

### R4 Endpoint Spec + Request Pipeline — DONE (2026-06-10)
- REC1/REC2: new `endpoint` option (hostname | routing policy | "nonprod:[id]");
  primary domain resolution at build time with REC1b1 mutual-exclusion checks;
  defaults now main.realtime.ably.net + main.[a-e].fallback.ably-realtime.com;
  environment() maps to [env].realtime.ably.net (REC1c2); rest_host/realtime_host
  deprecated hostname overrides (REC1d, no fallbacks per REC2c6); explicit
  fallbackHosts always win (REC2a2). ClientOptions host fields are now Options
  with resolve_hosts() populating primary_host/resolved_fallback_hosts.
- RSC7c: one request_id per logical request, stable across fallback retries,
  attached to ErrorInfo.request_id on failure.
- TO3l6: httpMaxRetryDuration enforced as an elapsed-time budget on retries;
  RSC15l3: retriable statuses bounded to 500-504; primary host success is no
  longer cached as a "fallback"; http_open_timeout wired to reqwest connect_timeout.
- HP1-HP8/RSC19: Rest::request() now returns HttpPaginatedResponse — items
  normalised (object→1, array→n), statusCode/success/errorCode/errorMessage from
  X-Ably-Errorcode/-Errormessage headers, headers(), Link-header pagination
  (next/first); HTTP error statuses are inspectable responses, not Errs;
  version() per-request X-Ably-Version override (RSC19f1); token renewal on 401
  token errors preserved in raw mode.
- RSC2/TO3b/TO3c: logging implemented — LogLevel ordering, log_handler invoked
  with (level, message); request logs carry method/host/path; errors at Error
  level; None suppresses all. (Structured context objects deferred.)
- Tests: legacy-domain expectations migrated to REC domains; falsely-IDed
  REC/HP tests rewritten to real behaviors (rec1b1/b2/b3/b4, rec1d1/d2, rsc7c x2,
  to3l6, hp2/hp3 request, rsc19f1 override, rsc19e per HP4/5); logging tests are
  real; renewal tests moved to typed requests with exact request-count asserts.
- Test status: unit 751 pass / 439 fail (realtime stubs) / 91 ignored;
  integration 47/47 vs sandbox.
- Next: R5 remaining unit-test repair, then R6 integration hardening.

### R5 Unit-Test Suite Repair — DONE (2026-06-10)
(Bulk of R5 was done incrementally inside R1-R4: vacuous auth tests replaced with
18 UTS tests, inverted RSC22 fixed, falsely-IDed REC/HP/logging tests rewritten,
batch duplicates removed, idempotency conditional-asserts made strict.)
This pass added:
- RSL8/RSL8a/CHD2/CHS2/CHO2/CHM2: Channel::status() implemented + ChannelDetails
  type tree; 5 UTS tests (endpoint, encoding, details, all-metrics, zero/missing).
- RSL7: Channel::set_options() applies cipher to subsequent operations (tested).
- RSAN1c4: annotation publish generates idempotent ids (was hidden by a
  conditional assert; now implemented + strict test).
- Realtime-dependent tests moved out of REST files (rsa4c2/c3, rsa4d x2 →
  tests_realtime_unit_client; tm2* x8 → tests_realtime_unit_channel). Every
  tests_rest_* test now passes.
- Vacuous tests fixed/deleted: rsa5c/rsa6c (now assert TokenRequest flow),
  rsa5d/rsa6d (real override tests), rsa10a tautology deleted, rsa5b/rsa6b depth
  tautologies deleted, rsc15j + rsc7c-unique + rsc22c-empty conditionals strict.
- Duplicates removed: rec1b2==rec1b1 (kept as rsc15l_fallback_on_network_failure),
  rsc15m triplicate → 1, rsa9c==rsa5b, version-header triplicate → 2.
- DESIGN.md updated with all Phase R API amendments + the RSN ephemeral-channel
  decision. CLAUDE.md baseline updated (746/439/91; REST fully green).
- Deferred (recorded): shared test_support module to dedup mock helpers;
  none_/hp naming sweep; remaining near-duplicate pairs in auth (rsa10/rsa16
  batches); RSC19d residual items; RSP1b/TM2s1.
- Test status: unit 746 pass / 439 fail (all realtime stubs) / 91 ignored.

### R6 Integration-Test Hardening — DONE (2026-06-10)
- Sandbox infra moved to the UTS-mandated endpoint: provisioning and clients use
  endpoint("nonprod:sandbox") → sandbox.realtime.ably-nonprod.net (verified live).
- Protocol coverage: sandbox_client now uses the SDK-default MessagePack — the
  binary protocol is exercised across the whole integration suite for the first
  time (all tests pass). sandbox_client_json + two explicit protocol-variant
  round-trip tests (string/json/binary over JSON; native binary over msgpack).
- Payload assertions added: rsl2a (typed data round-trip for all 3 messages),
  rsp3a2 (unencoded presence data stays a raw string), rsl1k5 (first-write-wins
  data + stable two-read poll to close the dedup race).
- Five ignored stubs implemented and passing live: rsa8_auth_callback_with_token_request
  (callback TokenRequest exchange), rsl2b3_history_time_range, rsa8_capability_restriction
  (native-token variant; 40160 on out-of-capability publish), rsl1n_publish_returns_serials
  (single + batch), rsl5_encrypted_publish_history_roundtrip (live encrypt/decrypt).
- Test status: unit 753 pass / 439 fail (realtime stubs) / 86 ignored;
  integration 54 pass / 31 ignored (was 47/36).
- Remaining ignored stubs are all legitimately blocked: 4 JWT (needs a JWT dev
  dependency), ~10 on stale ably-common fixtures (keys[4] revocableTokens +
  mutable namespace — submodule update needed), the rest need a live realtime
  client (Phase 5). App teardown + JWT dev-dep deferred to follow-up.
- UPSTREAM FLAGS for the spec repo: (1) the RSP5g cipher fixture string in
  uts/rest/unit/presence/rest_presence.md is a corrupt truncation of the
  ably-common crypto fixture; (2) uts/rest/unit/auth/revoke_tokens.md unit mocks
  use the legacy array response while the integration doc mandates the
  BatchResult envelope; (3) UTS request.md (HP, no error on HTTP status) vs
  token_renewal.md ("FAILS WITH error" via request()) are inconsistent.

## Phase P: Proxy Infrastructure + Remaining REST Integration — DONE (2026-06-10)
- All 8 UTS proxy tests implemented in new src/tests_proxy.rs against the
  auto-downloaded uts-proxy (src/proxy.rs harness worked as-is on darwin_arm64):
  timeout fallback (RSC15l2), CloudFront 403 fallback (RSC15l4), connection drop,
  unreachable endpoint error, 5xx parsed/synthesized, 4xx-not-retried, and
  RSL1k4 idempotent retry dedup (proves the LIVE server dedupes our generated ids).
  8/8 passing. Old proxy stubs removed from tests_rest_integration.rs.
- SDK fix: fallback retry list no longer filters fallback hosts equal to the
  primary (only a failed cached-fallback is excluded) — required for proxy
  configs where primary and fallback are both localhost.
- ably-common submodule updated to origin/main: keys[4] revocableTokens + the
  mutable namespace. Unblocked and implemented 8 more integration tests, all
  passing live: rsl11 getMessage, rsl15 update/delete/append, rsl14 versions,
  rsan1/2 annotation lifecycle, rsan3 paginated annotations, rsa17e
  issuedBefore/allowReauthMargin (live proof of the BatchResult envelope fix).
- LIVE-CAUGHT BUG: Annotation serial field is `messageSerial` (TAN2j), not
  `msgSerial` — unit mocks had agreed with the wrong implementation. Fixed
  (field renamed message_serial, RSAN1c2 now sets it on publish/delete bodies).
- Remaining ignored (15): 3 JWT (needs jsonwebtoken dev-dep), 10 need a live
  realtime client (presence events/members, revoke-disconnect observation),
  2 LocalDevice. All reasons name their concrete blocker.
- Test status: unit 768 pass / 440 fail (all realtime stubs) / 70 ignored;
  integration 62 pass / 15 ignored; proxy 8/8. All serial runs fully green.
- Next: Phase 4 — realtime state design (DESIGN.md section, HUMAN REVIEW GATE).

## Phase 5: Realtime Implementation

### 5.1 Connection Foundation — DONE (2026-06-10)
- src/connection.rs: the single-writer connection loop per DESIGN.md — LoopInput/
  Command enums, ConnectionCtx (plain owned state, no locks), generation-guarded
  spawned connect/reader/writer tasks, watch-before-broadcast emission, exhaustive
  per-state command handling. RTN2 URL building (v=6, format, key/accessToken via
  the shared REST auth layer, off-loop).
- src/realtime.rs: thin handles — Realtime (new/with_mock/connect/close, embedded
  Rest), Connection (snapshot reads, on_state_change, when_state w/ RTN26a/b
  semantics, subscribe-before-snapshot-read race guard), RealtimeAuth delegating
  to REST auth. ClientOptions::realtime() now works; clone_for_realtime added.
- src/ws_transport.rs: production tokio-tungstenite transport (JSON text /
  msgpack binary frames; unparseable frames skipped per RTN19 tolerance).
- src/mock_ws.rs: full UTS mock_websocket.md implementation (handler + await
  patterns, PendingConnection respond_with_success/refused/error, MockConnection
  send_to_client(_and_close)/simulate_disconnect, client_messages,
  await_message_from_client, await_client_close). Test-only locks.
- Implemented behaviors: RTN3 (autoConnect), RTN4 ordered lifecycle events,
  RTN4h additional-CONNECTED → Update, RTN8/RTN9 id/key incl. RTN8c/9c clearing,
  RTN11 (re)connect semantics, RTN12a/d/f close paths (CLOSE on wire, await
  CLOSED), RTN25 errorReason on fatal ERROR, RTN26 whenState. Failed connect
  attempts rest at DISCONNECTED (retry timers are 5.2).
- Tests (DESIGN §12, option 2): 20 UTS-derived tests in
  tests_realtime_uts_connection.rs — ALL derived from uts/realtime/unit
  pseudo-code (auto_connect/connection_id_key/when_state/error_reason files) +
  features-spec lifecycle sequences; all passed first run. PLUS one live
  integration test: real WsTransport against the nonprod sandbox — CONNECTED
  with server-assigned id/key, clean close (passes, 2.5s).
- Ported-test cross-check for this stage's ranges: 17 superseded ported tests
  deleted (RTN3 x3, RTN8/9 x7, RTN26 x5, 2 vacuous depth duplicates); the
  remaining ported connection tests stay pending their stages (~60 of them now
  pass against the new loop, a free cross-check). rtn8c_id_key_null_in_suspended
  retained for 5.2 (needs SUSPENDED).
- §14.3 conformance line: lock inventory UNCHANGED (conformance tests green;
  connection.rs and ws_transport.rs added to the ratchet scan at zero allowance).
- Test status: 851 pass / 363 fail (remaining realtime stubs) / 70 ignored;
  REST + proxy + integration unaffected.
- Next: 5.2 connection failures, retries/backoff, resume, ping, heartbeat.

### 5.2 Connection Failures, Retries, Resume, Ping, Heartbeat — DONE (2026-06-10)
- Timers per DESIGN §5: all deadlines in ConnectionCtx, one sleep_until in the
  loop select. Implemented: connect-attempt timeout (RTN14c), close-handshake
  timeout (RTN12b), disconnected retry with RTB1 backoff
  (min((n+2)/3,2) × jitter[0.8,1.0]) (RTN14d), connectionStateTtl → SUSPENDED
  (RTN14e, server details override; new connection_state_ttl option), suspended
  indefinite retries (RTN14f), idle/activity timeout maxIdleInterval +
  realtimeRequestTimeout with reset on any traffic (RTN23a; heartbeats=true and
  echo=false (RTN2b) URL params), ping deadlines (RTN13c).
- RTN15: immediate resume reconnect on unexpected transport loss (RTN15a),
  resume=key param (RTN15b1), resumed vs failed-resume by connection id
  (RTN15c6/c7 with surfaced error), key refresh (RTN15e), resume state discarded
  after TTL (RTN15g). RTN15h DISCONNECTED handling: token error → renew once and
  reconnect (RTN15h2, renewal forced in the spawned connect task — loop never
  touches the auth lock) or FAILED if unrenewable (RTN15h1); non-token → resume
  (RTN15h3). RTN14b ERROR-during-connect token renewal; RSA4a unrenewable →
  FAILED. Connection::ping() (RTN13a/b/c/e: random ids, id-matched responses,
  concurrent pings, timeout, state errors).
- Tests (DESIGN §12): 24 more UTS-derived tests (45 total in
  tests_realtime_uts_connection.rs incl. RTB1a/b formula tests), all green;
  paused-clock (tokio test-util) drives every timer test. Live test extended
  with a real ping. 11 more ported tests superseded and deleted (instant-close
  pinning, transient-state races vs the coalescing watch — my tests assert
  event sequences instead). rtn17*/rtn19*/rtn22* ported tests remain for 5.3/5.5.
- §14.3 conformance: lock inventory UNCHANGED (ratchet green).
- Test status: 891 pass / 336 fail (remaining stubs) / 70 ignored.
- Next: 5.3 fallback hosts (RTN17) + realtime auth (RTN22/RTC8).

### 5.3 Realtime Fallback Hosts + Auth — DONE (2026-06-10)
- RTN17: host cycling is loop-driven state (connect_hosts/current_host in
  ConnectionCtx) — each cycle tries the primary first (RTN17i), then the REC2
  fallback domains in random order (RTN17h/j); qualifying failures (refused/
  timeout/transport loss while connecting, 5xx DISCONNECTED per RTN17f/f1)
  advance to the next host within the same CONNECTING phase; an exhausted or
  empty set falls into the RTN14 retry cycle (RTN17g). Connection::host()
  reports the connected host via the snapshot. RTN17e: a successful fallback
  host is written into the embedded Rest's cached-fallback state so HTTP
  requests prefer it (brief REST-lock write in the loop; never across await —
  same class as the sanctioned REST locks).
- DEFERRED (recorded): the RTN17j connectivity check (GET connectivityCheckUrl
  before fallback) needs dual mock injection (WS + HTTP) in realtime unit
  tests; planned alongside 5.6. Without it, fallback proceeds optimistically.
- RTN22: server AUTH → off-loop token renewal task → TokenReady → client sends
  AUTH with accessToken; connection stays CONNECTED; server's CONNECTED reply
  surfaces as an UPDATE (RTN4h machinery). RTC8: RealtimeAuth::authorize()
  obtains via REST then applies in place via Command::Reauth.
- RTN14 isolation fix: the RTN14 retry tests now pin retry behavior with an
  empty fallback set, since default options carry the 5 REC2 fallback domains.
- Tests: 3 new UTS-derived (48 total in tests_realtime_uts_connection.rs, all
  green; RTN22 full scenario incl. captured AUTH + token-2 + update-only
  events). Ported cross-check: all 7 rtn17 tests ADOPTED (they pass verbatim
  after the REC domain migration of realtime test files); 2 ported rtn22a
  tests superseded (transient-state races; covered by rtn15h2); rtn22 x2
  ported pass as adopted.
- §14.3 conformance: lock inventory UNCHANGED (ratchet green; live test green).
- Test status: 901 pass / 327 fail (remaining stubs: channels/messages/
  presence/annotations + misc) / 70 ignored.
- Next: 5.4 channel lifecycle (RTS, RTL2-5, RTL16) — ChannelCtx, EnsureChannel,
  per-channel snapshots, attach/detach.

### 5.4 Channel Lifecycle — DONE (2026-06-10)
- ChannelCtx joins the loop-owned state: per-channel state machine, serials,
  modes, op deadlines, pending attach/detach repliers — all plain owned data,
  zero locks. Per-channel watch snapshot (state/errorReason/serials/modes) +
  broadcast event stream, published snapshot-before-event per the §4 contract.
- Channels handle registry: the design's ONE sanctioned realtime lock (a
  Mutex<HashMap<name, Arc<RealtimeChannel>>> of handles only). get/
  get_with_options sends Command::EnsureChannel (RTS3a identity, RTS3b options
  on create); release sends Command::ReleaseChannel (detach-then-remove,
  RTS4a). RealtimeChannel handle: snapshot reads, attach/detach oneshot
  round-trips, on_state_change/when_state (RTL25, one-shot semantics).
- Attach (RTL4): a no-op when attached; shares the in-flight op (RTL4h, incl.
  attach-while-detaching continuation); errors on Closed/Closing/Failed/
  Suspended connections (RTL4b); queues while CONNECTING/DISCONNECTED with
  immediate ATTACHING (RTL4i); ATTACH carries channelSerial on reattach
  (RTL4c1), params (RTL4k), mode flags (RTL4l), ATTACH_RESUME (RTL4j); timeout
  → SUSPENDED (RTL4f); granted modes from ATTACHED flags (RTL4m); attach from
  FAILED clears errorReason (RTL4g/RTL4c).
- Detach (RTL5): no-op from Initialized/Detached (RTL5a); error from Failed
  (RTL5b); Suspended → immediate Detached (RTL5j); queued behind in-flight
  attach/detach (RTL5i); RTL5l immediate local detach when the connection
  isn't CONNECTED — including abandoning a QUEUED (RTL4i) attach, a real gap
  the ported cross-check caught (the queued detach would have waited forever);
  detach timeout reverts to the prior state (RTL5f); ATTACHED while detaching
  → fresh DETACH (RTL5k).
- Connection effects (RTL3): Failed/Closed/Suspended fail/detach/suspend
  attached AND attaching channels (in-flight attach repliers resolved with the
  error); Disconnected is a channel no-op (RTL3e); on CONNECTED, attached/
  attaching/suspended channels reattach with serial + ATTACH_RESUME (RTL3d).
- Events: state-snapshot-then-event ordering; no duplicate state events
  (RTL2g); additional ATTACHED → UPDATE with resumed=false, SUPPRESSED when
  the RESUMED flag is set (RTL12 — fixed during UTS test derivation);
  resumed/hasBacklog propagated from flags (RTL2d/RTL2i/TH6). RTL15b1:
  channelSerial cleared on Detached/Suspended/Failed transitions.
- Tests: 37 UTS-derived in tests_realtime_uts_channels.rs (RTS, RTL2, RTL3,
  RTL4, RTL5, RTL15b1, RTL23, RTL25 — all green), incl. a live sandbox
  attach/detach proof. Ported cross-check (tests_realtime_unit_channel.rs):
  68 5.4-scope tests ADOPTED (13 needed only the mechanical #[test] →
  #[tokio::test] conversion since client construction now spawns the loop);
  12 SUPERSEDED and deleted (transient-state races vs the coalescing watch,
  mock-shape close timeouts, a self-contradictory rtl25a, a hang-prone
  release test, and 2 rts3c1 tests whose error assertions had been stripped
  in porting — RTS3c/RTS3c1/RTL16 are regenerated from UTS in 5.6). Remaining
  ported failures are honest stubs for 5.5+ (publish/subscribe/rtl32/options/
  derived channels). The full suite has NO hanging tests (23s wall).
- §14.3 conformance: channel.rs registry Mutex occupies the 1 occurrence the
  allowance budgeted (fully-qualified decl, Default::default() init); the 2
  temporary presence-stub mutexes remain (allowance stays 3 until 5.7).
  Ratchet green; no-pub-fields green (ChannelCtx loop-private).
- Test status: 1029 pass / 224 fail (remaining stubs: messages/presence/
  annotations/options/derived) / 70 ignored.
- Next: 5.5 channel messages — publish/subscribe, ACK/NACK, msgSerial,
  queueing (RTL6/7/8, RTN7, RTN19 resend), RTL15b serial updates from MESSAGE.

### UTS Coverage Audit + Backfill — DONE (2026-06-10)
- New enforcement (DESIGN.md §14.5): uts_coverage.txt traceability matrix —
  all 963 UTS Test IDs (487 rest + 476 realtime) mapped to passing Rust tests
  (686) or excluded with a stage/deferral reason (277). tests_uts_coverage.rs
  fails the build on unaccounted IDs, dangling test references, or reasonless
  exclusions. Bootstrap generator in tools/uts_coverage_generate.py.
- REAL BUGS the audit caught:
  - RTN13d: ping while CONNECTING/DISCONNECTED must be DEFERRED until the
    connection resolves — the implementation errored immediately and a
    wrongly-derived test pinned that behavior. Now: deferred_pings in the
    loop, executed on CONNECTED (timeout runs from the send, RTN13c), failed
    on terminal states (RTN13b). 5 new UTS tests.
  - RTC8: authorize() was fire-and-forget. Now full semantics: resolves only
    on the server's CONNECTED/ERROR (RTC8a3); halts and restarts an in-flight
    attempt with the new token (RTC8b, generation-orphaned); initiates a
    connection from INITIALIZED/DISCONNECTED/SUSPENDED/FAILED/CLOSED (RTC8c);
    fails when the connection lands terminal (RTC8b1). 10 new UTS tests; the
    pending_authorize replies live in the loop, resolved in transition().
  - RSA4c3: a failed RTN22 token renewal while CONNECTED must be silently
    swallowed (no event, no errorReason) — we set errorReason and emitted an
    update.
  - RTC1a/RTC1f1: echo param now explicit (echo=true default); transportParams
    now OVERRIDE library URL defaults (were appended as duplicates).
  - RSA4f: oversized (>128KiB) callback tokens now rejected with 80019/401.
  - RSA4a1: literal-token clients with no renewal means log a 40171 warning.
  - RSL4a (REST): bare-scalar JSON payloads (number/bool) now rejected with
    40013 at publish time.
- REST backfill: 18 new tests (RSL4a x2, TG navigation x4, batch results
  BPR/BPF/RSC22c x3, RSC22 request-id, RSC15f late-success-no-resurrection,
  RSC16 no-auth + non-TLS, RSC6a stats pagination, TO3c2 log context,
  RSA7 authorize-clientId, RSA16a token reuse, RSA17 revoke error/options).
  New: ClientOptions::fallback_retry_timeout (TO3l10).
- Realtime backfill: RTF1 unknown-action tolerance, RTN22a forced-disconnect
  reason (event-stream witness, no transient-state race), RSA4f oversized,
  RSA4a1 warning. Ported sweep: 7 client tests mechanically converted
  (sync→tokio), 8 superseded/deleted (close-timeout mock shapes, wrong rtn13d,
  4 stale-ignored backoff stubs superseded by the UTS RTB1 formula tests).
- Conformance: lock inventory UNCHANGED (deferred_pings/pending_authorize are
  plain loop-owned Vecs). Both ratchets green.
- Test status: 1079 pass / 202 fail (later-stage stubs) / 66 ignored; REST
  unit 689 all green; integration serial-only flake documented (rsl11 vs
  shared sandbox in parallel).

### 5.5 Channel Messages — DONE (2026-06-11)
- Publish (RTL6): builder + publish_message; loop-owned msgSerial (RTN7b),
  pending-ACK queue, ACK/NACK resolution with PublishResult serials from
  `res` (RTL6j/TR4s); state table RTL6c1 (send when CONNECTED regardless of
  channel attach state), RTL6c2 (queue while INITIALIZED/CONNECTING/
  DISCONNECTED; queueMessages=false fails fast), RTL6c4 (channel SUSPENDED/
  FAILED + terminal connection states fail with the reason), RTL6c5 (no
  implicit attach). RSL4/RSL5 wire encoding with the channel cipher.
- RTN7d/e: pending publishes survive DISCONNECTED (queueMessages default),
  fail with the state-change reason on SUSPENDED/CLOSED/FAILED.
- RTN19a/a2: pendings resent verbatim on a new transport; serials kept on a
  successful resume, renumbered from a reset counter on a failed resume
  (RTN15c7). RTN19b: pending ATTACH and DETACH resent (DETACH resend was a
  real gap the audit-style cross-check caught).
- Subscribe (RTL7/8/17/22): loop-side subscriber registry (unbounded mpsc per
  §8, pruned on close); all/name/MessageFilter (RTL22 — new public
  MessageFilter type + subscribe_with_filter); RTL7g implicit attach per
  attachOnSubscribe with listener-survives-failed-attach; RTL17
  attached-only delivery; RTL8a/b/c unsubscribe semantics.
- Inbound MESSAGE: TM2a/c/f field population (pm.id:index, connectionId,
  timestamp — never overwriting), RSL6 decode/decrypt with the channel
  cipher, RTL15b channelSerial updates from MESSAGE/PRESENCE/SYNC, RTF1/RSF1
  unknown-field tolerance.
- RTL32 message mutations are WIRE operations (not REST): MESSAGE pm with
  one Message carrying action UPDATE/DELETE/APPEND (RTL32b1), version from
  the MessageOperation (RTL32b2), pm-level params (RTL32e), serial required
  (RTL32a, 40003), resolves via ACK as UpdateDeleteResult.versionSerial
  (RTL32d), caller's message untouched (RTL32c). RTL10b untilAttach
  (fromSerial, attached-required) + RTL28/RTL31 REST delegation.
- LIVE-CAUGHT PRODUCTION BLOCKER: the realtime service emits DUPLICATE map
  keys in msgpack frames (`messages` twice in MESSAGE) — serde rejects
  duplicates, so EVERY inbound message over msgpack (the default protocol!)
  was silently dropped. Fixed with a tolerant decode path (dedup keys, last
  wins, re-encode to preserve binary). FLAGGED UPSTREAM: server-side
  duplicate-key emission in msgpack MESSAGE frames on nonprod sandbox.
- Also fixed: RSL4a now normalizes JSON scalar strings to string payloads
  (Data::JSON(Value::String) → Data::String) and null to empty — only
  numbers/booleans are rejected (40013).
- Tests: 25 UTS-derived in tests_realtime_uts_messages.rs (all green), incl.
  a live sandbox publish→subscribe echo round-trip over msgpack. Ported
  sweep: ~60 message-scope tests ADOPTED (mechanical conversions: publish now
  returns PublishResult, subscribe returns UnboundedReceiver; 3 rtl32 asserts
  corrected to UTS semantics — 40003/versionSerial); 14 SUPERSEDED/deleted
  (broken rtl6i2 port, client-side echo-filter tests — UTS sanctions our
  server-side delegation, race-class rtn19/rtn7d/rtl6c4-closed shapes, rtl10
  todo-shells, the rtl5l straggler).
- Matrix: channel_publish/subscribe/history/get_message/versions/
  update_delete/message_field_population exclusions all converted to
  mappings (766 mapped / 197 excluded); both ratchets green.
- §14.3 conformance: lock inventory UNCHANGED (subscriber registry, pending/
  queued publishes are plain loop-owned data).
- Test status: 1161 pass / 132 fail (5.6 channels-advanced, 5.7 presence,
  5.8 annotations) / 66 ignored.
- Next: 5.6 advanced channels (RTL12, RTL13, RTL16/RTS3c — needs the
  fallible get_with_options API decision, RTN17j).

### 5.6 Advanced Channels — DONE (2026-06-11)
- Channel options: authoritative options moved into ChannelCtx, observable
  via ChannelSnapshot. get_with_options is now FALLIBLE (approved §14.4
  amendment): Err 40000 when params/modes change on an attaching/attached
  channel (RTS3c1); safe updates flow through Command::SetOptions with
  eventual visibility (RTS3c, soft-deprecated per UTS). RTL16/RTL16a
  set_options reattaches when needed, resolving on re-ATTACHED via the
  pending_attach repliers. TB2/TB4 attributes and defaults.
- RTL13 server-initiated DETACHED: immediate reattach from ATTACHED/
  SUSPENDED (RTL13a, reason surfaced on the ATTACHING change); DETACHED
  while ATTACHING = failed reattach -> SUSPENDED with an RTB1-jittered
  channelRetryTimeout retry (RTL13b; ChannelStateChange.retry_in carries the
  delay; retry cycle ends on successful attach); retries cancelled whenever
  the connection leaves CONNECTED (RTL13c). Attach timeouts join the same
  retry cycle.
- RTL12: additional-ATTACHED details verified (UPDATE with error,
  RESUMED-suppression, null reason) — implementation was already correct.
- RTS5 derived channels: [filter=<base64>?<params>] name qualification;
  get_derived(_with_options); registry identity preserved.
- RTN25 detail: a clean CONNECTED now clears errorReason (UTS sanctions
  either behavior; cleared matches common practice).
- RTN17j connectivity check REMAINS deferred (dual WS+HTTP mock injection
  still unavailable; recorded since 5.3).
- Tests: 10 UTS-derived in tests_realtime_uts_channels_advanced.rs (all
  green). Ported sweep: rtl13/rtl16/rts3c/rts5/rtl15b1/rtl4c1 groups now
  ADOPTED (2 broken rts5 ports fixed to pass channel options per UTS; rts3c
  adapted for eventual visibility); 9 superseded/deleted (rtl13c+rtn25
  Disconnected races, rtn2e/rtn23b close-shape mocks, 3 stale-ignored
  rtn7e stubs superseded by the 5.5 UTS tests). get_with_options call sites
  mechanically unwrapped (~45).
- Matrix: channel_options/additional_attached/server_initiated_detach/
  channel_error exclusions converted (791 mapped / 174 excluded); both
  ratchets green. Lock inventory UNCHANGED.
- Test status: 1185 pass / 112 fail (presence 94, annotations 14, presence-
  adjacent channel 4) / 63 ignored.
- Next: 5.7 presence (PresenceCtx in the loop; DELETES the 2 temporary stub
  mutexes and reduces the channel.rs conformance allowance 3 -> 1).

### 5.7 Realtime Presence — DONE (2026-06-12)
- PresenceMap/LocalPresenceMap rewritten as pure loop-owned data per the UTS
  map specs: RTP2 newness (id msgSerial:index for same-connection real ids,
  timestamps otherwise, RTP2b1a incoming-wins ties), RTP2d2 stored-as-PRESENT
  with RTP2d1 original-action events, RTP2h LEAVE semantics (ABSENT during
  sync, deleted at endSync), RTP18 sync lifecycle with RTP19 residual
  tracking and synthesized LEAVEs (id=None), RTP17h clientId-keyed local map
  with synthesized-leave immunity.
- PresenceCtx in ChannelCtx (DESIGN §9): inbound PRESENCE/SYNC engine (TM2
  field inheritance, cipher decode, RTL15b serials), RTP1/RTP19a attach-time
  semantics (HAS_PRESENCE sync vs authoritative-empty, ALSO on additional
  non-resumed ATTACHED), RTP5a/b/f channel-state effects, RTP17 internal-map
  maintenance from own-connection echoes, RTP17i/g/g1 automatic re-entry
  (id omitted when the connectionId changed) with RTP17e failed-re-entry
  UPDATE (91004 wrapping the cause, resumed=true).
- Operations: enter/update/leave (+_client) per the RTP16 state table; RTP8c
  own-identity ops omit clientId on the wire; RTP8j identity required,
  wildcard rejected (91000); RTP15f mismatch rejected (40012). RTP11 get
  with waitForSync deferral — failed on channel DETACHED/FAILED and 91005 on
  SUSPENDED (a deferred-get hang the UTS tests caught). RTP6/7 subscribe
  with per-action narrowing (RTP7b fixed to narrow, not remove). RTP12
  history via REST.
- STUB MUTEXES DELETED: channel.rs conformance allowance reduced 3 → 1 (the
  steady state). Lock inventory: Channels registry + 2 REST locks, exactly.
- UPSTREAM UTS CONFLICT flagged: RTP8j (wildcard enter errors) vs
  RTP14a/15a/15c/RTP4 setups using clientId "*" with plain enter(); we
  follow RTP8j and adapted those ported tests to unidentified key auth.
- Tests: 17 UTS-derived in tests_realtime_uts_presence.rs incl. a LIVE
  sandbox enter→subscribe→get→leave round trip. Ported sweep: 93 adopted,
  26 superseded/deleted (19 poked the deleted stub mutexes, 6 standalone
  no-loop handles, 1 broken rtp17g1 port).
- Matrix: all 9 presence spec files converted (895 mapped / 70 excluded);
  both ratchets green.
- Test status: 1274 pass / 14 fail (annotations, 5.8) / 63 ignored; no
  hangs (~22s).
- Next: 5.8 annotations, then Phase 6 final verification.

### 5.8 Annotations — DONE (2026-06-12)
- Realtime annotation ops over the wire: ANNOTATION ProtocolMessage with one
  Annotation (action ANNOTATION_CREATE/DELETE per RTAN1c/RTAN2a, messageSerial
  set TAN2j), resolved via the shared ACK/NACK pipeline (RTAN1d), gated by
  the message-publish state table (RTAN1b); annotation type required
  (RTAN1a, 40003 — implementation-defined per RSAN1a3). Inbound ANNOTATION
  dispatching to (type-filtered) subscribers with TM2-style id/timestamp
  inheritance (RTAN4a/c); RTAN4d implicit attach; RTAN4e missing-mode
  warning at Major level (RTAN4e1 silent when unattached). get via REST.
  New ChannelMode variants AnnotationPublish/AnnotationSubscribe with their
  RTL4l/RTL4m flag mappings (1<<20 / 1<<21).
- Tests: 4 UTS-derived (wire shape + encode, delete + NACK, subscribers +
  filters + implicit attach, state conditions). Ported sweep: 10 adopted
  (rtan1a code adapted to 40003 per UTS "implementation-defined"; rtan4e
  given the Major log level), 7 superseded/deleted (5 compile-shells that
  hung awaiting ACKs they never sent, 2 empty ignored shells).
- Matrix: channel_annotations.md converted (909 mapped / 56 excluded — the
  56 are recorded deferrals: push/LocalDevice, RTN16 recovery, network
  events, delta/vcdiff, JWT, and API-unrepresentable cases). Both ratchets
  green.
- TEST STATUS: 1287 pass / 0 fail / 61 ignored — THE FULL SUITE IS GREEN.
  Every realtime stage (5.1–5.8) is complete.
- Next: Phase 6 final verification (clippy, fmt, ignored-test audit,
  protocol-variant matrix, serial integration + proxy runs).

### TASK-13 Observability — DONE (2026-06-12)
- Logger handle (level-gated, lazily formatted, cloneable) in options.rs;
  ClientOptions::log delegates. Optional `tracing` cargo feature bridges
  library logs to the tracing crate when no handler is installed
  (Error->error!, Major->info!, Minor->debug!, Micro->trace!).
- Instrumented per the DESIGN.md policy (6 call sites -> ~35):
  Major: connection + channel state transitions (with reasons), UPDATE
  events, presence re-entry failures. Minor: resume outcomes, connection and
  channel retry scheduling, queued-publish flush + RTN19a resend counts,
  presence SYNC start/complete, NACK outcomes, RTL17 drops. Micro: every
  realtime public API entry (connect/close/ping, channels.get/release,
  attach/detach/publish/subscribe/set_options, presence ops/get/subscribe,
  annotation ops) and the wire (-> / <- action+channel+serial).
  Error (NO silent discards): undecodable JSON/msgpack frames (incl. the
  tolerant-decode failure path that previously vanished), undecodable
  message/presence/annotation entries, ACK/NACK for unknown serials,
  transport write failures.
- 3 policy tests assert the behavior: discards log at Error, transitions at
  Major, API entries at Micro.
- Suite: 1300 pass / 0 fail / 41 ignored; clippy clean (default + tracing
  feature).

### TASK-11 Integration Traceability — DONE (2026-07-13, 0369a29)
- Matrix now spans rest+realtime, unit+integration: 1120 IDs — 1056 mapped,
  66 excluded with reasons, 0 unresolved; objects/ and docs/ dispositioned
  via `!area` lines. The ratchet (tests_uts_coverage.rs) scans all four
  areas.
- New test files: tests_realtime_integration.rs (13 live-sandbox tests) and
  tests_proxy_realtime.rs (28 uts-proxy fault-injection tests over the real
  WebSocket transport).
- SDK fixes the new tests forced:
  - RTL15b: SYNC no longer updates the channel serial — the sync cursor is
    not a channel serial, and sending it back in a reattach ATTACH (RTL4c1)
    was rejected by the server ("Unable to parse channel params").
  - RTN15h1: DISCONNECTED token error with a non-renewable token now fails
    the connection with 40171 (was pass-through 40142), server error kept
    as cause (TI1). Unit-spec conflict recorded in TASK-9 (item 6).
  - RTN19a: typed PendingPayload — resends reconstruct the same
    ProtocolMessage kind (MESSAGE/PRESENCE/ANNOTATION) instead of
    pre-serialized JSON.
- Test-infra fixes: uts-proxy spawns with null stdio (inherited stdout held
  test pipes open); randomized proxy port base + session-create retry
  (orphaned sessions from panicked tests hold ports on the daemon);
  fast reconnect cycles asserted via broadcast recorder
  (await_states_in_order) because await_state's coalescing watch misses
  ms-fast transients; coverage generator considers every module a bare fn
  name appears in.
- Suite: 1342 pass / 0 fail / 41 ignored (full serial run).

### TASK-12 Verified Claim-Set Mappings — DONE (2026-07-14, 26f1239)
- The generator's score-0 fallback claimed spec variants by listing every
  same-token test without verifying any covered the variant; the class had
  grown to 31 IDs. Each dispositioned by reading the spec variant and the
  candidate test: 17 tightened to the single verified covering test, 10 new
  tests written, 4 excluded with reasons (fallbackHostsUseDefault
  deliberately not exposed; connectivity check is TASK-5 scope). The
  fallback now emits `?? UNRESOLVED` with the candidate list, so the class
  cannot reappear. Matrix: 1052 mapped / 70 excluded / 0 unresolved.
- SDK bugs the tightened tests forced out:
  - Annotations skipped RSL4 data encoding on publish (REST and realtime)
    and RSL6 decoding on receipt/list — a JSON payload went out as a raw
    object instead of a string with encoding "json"
    (RTAN1a/RSAN1c3/RTAN4b1).
  - A connect-time 40102 IncompatibleCredentials (token clientId vs
    configured clientId) was retried forever; per RSA15c it is terminal —
    the connection now transitions to FAILED.
- Notable new tests: rtl10b_until_attach_bounded_by_attach_point proves the
  fromSerial attach bound behaviorally against the live sandbox (the unit
  mock cannot see the HTTP layer until TASK-5, and the uts-proxy strips
  query strings from its http_request log);
  rtp5f_suspended_maintains_presence_map drives a real connection into
  SUSPENDED via a 1ms connectionStateTtl.

### TASK-1 JWT Integration Tests — DONE (2026-07-14, 3d1eeec)
- generate_jwt() in tests_rest_integration.rs mints Ably-shaped HS256 JWTs
  (kid=keyName, x-ably-clientId). rsa8_jwt_token_auth,
  rsa8_auth_callback_jwt and rsc10_token_renewal_with_expired_jwt replace
  their ignored stubs; the matrix maps their IDs to the real tests (they
  were auto-matched to plausible-but-wrong ones).
- GOTCHA: an "expired" JWT needs iat in the past too — with iat=now and
  exp<now the server computes a negative ttl and rejects the JWT as
  malformed (400/40003) rather than expired (401/40142), which never
  exercises RSC10 renewal.
- Suite: 1354 pass / 0 fail / 38 ignored.

### TASK-4 RTN16 Connection Recovery — DONE (2026-07-14, 6f546b2)
- A new client instance can recover a previous instance's connection:
  ClientOptions::recover(key) (malformed keys log an error and connect
  fresh, RTN16f1); Connection::create_recovery_key() — loop-command
  snapshot serializing connectionKey + msgSerial + attached channels'
  serials (ably-js JSON format, unicode-safe), None in
  CLOSING/CLOSED/FAILED/SUSPENDED or before the first connection
  (RTN16g/g1/g2).
- The recover query param goes on the first connect attempt only, mutually
  exclusive with resume (RTN16k). msgSerial seeds from the key and survives
  a clean recovery CONNECTED; a recovery failure resets it per RTN15c7
  (RTN16f). Channel serials seed ChannelCtx creation so the first ATTACH
  carries them (RTN16j/RTL4c1). No new locks: everything lives in the
  loop-owned state.
- Tests: 6 UTS unit IDs + RTC1c; proxy RTN16d (real-sandbox recovery
  preserves connectionId, rotates the key) and RTN16l (failure -> fresh id
  + 80008, still CONNECTED); rtn16_live_recovery_proof kills a client
  without a protocol CLOSE and shows the successor keeps the connectionId
  and continues msgSerial 1->2. The 8 stale ignored recovery stubs deleted.
- Matrix: 1120 IDs, 0 unresolved. Suite: 1363 pass / 0 fail / 30 ignored —
  verified green again 2026-07-19 (fmt + clippy clean; unit 1238/0/28,
  live integration + proxy serial 125/0/2).


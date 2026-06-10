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

# CLAUDE.md

## Protocol version

The Ably protocol version is **6** (integer). This is sent as:
- `x-ably-version: 6` header on all REST requests (RSC7e)
- `v=6` query param on WebSocket connections (RTN2f)

These are the same value. The versioning scheme changed from decimal (e.g. "1.2") to integer at v2 (CSV2a). Old docs and code may still reference "1.2" — that's wrong for current SDKs.

## Test baseline

1079 pass / 202 fail / 66 ignored (post UTS coverage audit, 2026-06-10). ALL failures are
unimplemented realtime stubs in tests_realtime_* files — every test in tests_rest_*
and tests_proxy passes. Integration: 62 pass / 15 ignored against the live nonprod
sandbox; proxy: 8/8 via uts-proxy. Run integration/proxy with --test-threads=1
(shared sandbox app; flaky in parallel). If any tests_rest_*/tests_proxy test fails
after a change, something regressed.

Run tests: `cargo test 2>&1 | tail -5`

## Test organization

Tests mirror the UTS (Universal Test Specification) directory structure:
- `tests_rest_unit_*.rs` — REST unit tests (mocked HTTP)
- `tests_rest_integration.rs` — REST integration tests (nonprod sandbox)
- `tests_realtime_unit_*.rs` — Realtime unit tests (mocked WebSocket)
- `tests_realtime_integration.rs` — Realtime integration tests [planned]
- `tests_proxy.rs` — proxy integration tests (uts-proxy, auto-downloaded)

Filter by category: `cargo test tests_rest_unit` or `cargo test tests_realtime_unit`.

UTS specs are at `../specification/uts/`. Each test function should reference its spec ID in the name (e.g. `rsc7e_x_ably_version_header`).

## Mock injection pattern

Tests use `ClientOptions::rest_with_mock(mock)` which:
1. Clones the `MockHttpClient` (Arc-based) to get a handle
2. Boxes the original as `Box<dyn HttpClient>`
3. Stores the cloned handle on `RestInner.mock_handle` (behind `#[cfg(test)]`)

This avoids `as_any()` downcasting on the `HttpClient` trait. The handle is retrieved in tests via `client.inner.mock_handle.as_ref().unwrap()`.

## Spec items that are easy to get wrong

- **RSC15f**: Cached fallback host. When a fallback succeeds, cache it and try it *first* on the next request. On failure, clear cache and include the primary host in the retry list.
- **RSC1b**: Empty token string must be rejected at client construction time.
- **RSC18**: Basic auth (API key without token auth) over non-TLS must be rejected.

## Phased implementation

See `DESIGN.md` for the API surface and the plan in `.claude/plans/noble-strolling-marble.md` for phase tracking. `PROGRESS.md` tracks what's done per phase.

## Conventions

- `pub(crate)` for all internal constructors, wire types, and protocol details
- One `ErrorInfo` type (no separate `Error` vs `ErrorInfo`)
- One `Message` type shared by REST and Realtime
- Builder pattern for publish (both REST and Realtime)
- MessagePack is the default format; JSON is opt-in via `use_binary_protocol(false)`

## Realtime design contract (BINDING — see DESIGN.md "Realtime State & Concurrency")

These are requirements, not guidance. They apply to ALL realtime work (Phase 5+):

1. **One connection loop owns ALL mutable protocol state** (connection state
   machine, channels, presence, ACKs, queues, timers) as plain owned data.
   **No locks on protocol state, ever.** Handles interact with the loop only via
   the LoopInput mpsc, oneshot replies, watch snapshots, and broadcast events.
2. **Complete allowed lock inventory**: the `Channels` handle registry Mutex,
   plus the two REST locks (auth_state, fallback_state). Nothing else.
   `tests_design_conformance.rs` enforces this on every `cargo test` — if it
   fails, STOP and read its message; never weaken or bypass it. (Two stub
   presence-map mutexes are temporarily whitelisted until stage 5.7.)
3. **The loop never awaits I/O.** Blocking work (transport connect, token
   acquisition, writes) happens in spawned tasks posting LoopInput back,
   generation-tagged.
4. **Realtime tests are derived from the UTS specs** (`uts/realtime/unit/*.md`),
   never from old implementations. The 440 ported tests are a coverage
   cross-check and quarry only (adopt verbatim only when they match the UTS
   pseudo-code); each Phase 5 stage records adopted/superseded counts.
   **Per-ID traceability is enforced**: `uts_coverage.txt` maps every UTS
   Test ID (rest + realtime) to the Rust test(s) covering it, or excludes it
   with a stage/deferral reason; `tests_uts_coverage.rs` fails the build on
   any unaccounted ID, dangling test reference, or reasonless exclusion.
   Closing a stage means converting its exclusions into mappings (regenerate
   with `tools/uts_coverage_generate.py`, then review the diff).
5. **Design-change-before-code**: if an implementation step seems to need a new
   sync primitive, shared state outside the loop, or a loop bypass, STOP. Propose
   the change as a DESIGN.md edit and get explicit human approval BEFORE writing
   the code. This includes anything that would dodge the conformance test.

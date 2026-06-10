# CLAUDE.md

## Protocol version

The Ably protocol version is **6** (integer). This is sent as:
- `x-ably-version: 6` header on all REST requests (RSC7e)
- `v=6` query param on WebSocket connections (RTN2f)

These are the same value. The versioning scheme changed from decimal (e.g. "1.2") to integer at v2 (CSV2a). Old docs and code may still reference "1.2" — that's wrong for current SDKs.

## Test baseline

746 pass / 439 fail / 91 ignored (post Phase R5, 2026-06-10). ALL failures are
unimplemented realtime stubs in tests_realtime_* files — every test in tests_rest_*
passes. Integration tests: 47 pass against sandbox (run with --test-threads=1; some
are flaky in parallel), 36 ignored stubs. If any tests_rest_* test fails after a
change, something regressed.

Run tests: `cargo test 2>&1 | tail -5`

## Test organization

Tests mirror the UTS (Universal Test Specification) directory structure:
- `tests_rest_unit_*.rs` — REST unit tests (mocked HTTP)
- `tests_rest_integration.rs` — REST integration tests (Ably sandbox) [planned]
- `tests_realtime_unit_*.rs` — Realtime unit tests (mocked WebSocket)
- `tests_realtime_integration.rs` — Realtime integration tests [planned]
- `tests_proxy.rs` — proxy integration tests [planned]

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

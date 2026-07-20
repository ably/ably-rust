---
id: TASK-5
title: 'Dual WS+HTTP mock injection, then RTN17j connectivity check'
status: Done
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - feature
  - test-infra
  - realtime
dependencies: []
priority: medium
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RTN17j: before host fallback, probe the connectivity check URL to distinguish 'Ably down' from 'no internet'. The implementation is small; the blocker (recorded since 5.3) is test plumbing — Realtime::with_mock injects only the WS transport while the embedded Rest builds its own HTTP client. Add a combined injection path, then implement the probe + UTS tests.
<!-- SECTION:DESCRIPTION:END -->

## Implementation notes (2026-07-19)

- Dual injection: `Realtime::with_mocks(options, transport, http_mock)`
  builds the embedded Rest via rest_with_mock. `Realtime::with_mock`
  (single-mock) now embeds a default MockHttpClient that answers the
  connectivity check URL with 200 "yes" and simulates a network error for
  anything else — every existing fallback test stays hermetic and any
  accidental REST call in a unit test fails loudly. Both constructors are
  #[cfg(test)].
- REC3: ClientOptions::connectivity_check_url (default REC3a URL, REC3b
  builder override). Public probe: Connection::check_connectivity() →
  Rest::check_connectivity() — plain unauthenticated GET (WP6d), timeout
  http_request_timeout, true iff 2xx and body contains "yes".
- RTN17j: all four fallback-qualifying failure sites (connect error,
  transport closed while connecting, RTN17f1 5xx DISCONNECTED, connect
  timeout) now route through fallback_or_retry(): before the FIRST fallback
  attempt of a connect cycle the loop spawns the probe (generation-tagged
  LoopInput::Connectivity; the loop still never awaits I/O); "yes" proceeds
  to the fallback cycle, failure skips the fallbacks and enters the RTN14
  retry state. connectivity_checked resets per cycle in start_connect. Zero
  new locks.
- Tests: rec3_connectivity_check_validation (5 response cases),
  rec3a/rec3b URL tests, rtn17j_connectivity_check_before_fallback,
  rtn17j_no_internet_skips_fallback. Matrix: 3 REC3 exclusions converted;
  RTN17j/connectivity-check-before-fallback-0 retargeted from the
  random-order test to the real probe test.

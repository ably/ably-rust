---
id: TASK-11
title: >-
  Extend UTS traceability to integration specs; write missing
  realtime-integration tests
status: Done
assignee: []
created_date: '2026-06-12 13:47'
updated_date: '2026-07-13 17:45'
labels:
  - tests
  - traceability
  - project
dependencies: []
priority: high
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The coverage matrix only spans rest/unit + realtime/unit (963 IDs). Untraced: rest/integration (84 IDs — ~68 live tests exist with spec-pointed names, likely substantial coverage but unverified per-ID) and realtime/integration (73 IDs — largely UNCOVERED: connection/channel/presence lifecycle suites plus 30 proxy-fault IDs vs our 8 proxy tests and ~6 live proofs). Also record uts/objects (322 LiveObjects IDs) as an explicit out-of-scope exclusion rather than silent absence. Treat as a proper stage: extend tools/uts_coverage_generate.py + tests_uts_coverage.rs to the integration areas, map what exists, then write the missing realtime-integration tests (live sandbox + uts-proxy faults).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Matrix covers rest/integration and realtime/integration; objects/ recorded as out-of-scope with reason
- [x] #2 Every realtime/integration ID mapped to a green test or excluded with a recorded-deferral reason
- [x] #3 Both ratchets green; serial integration + proxy runs green
<!-- AC:END -->

## Outcome

Matrix now spans all four areas: 1120 IDs — 1056 mapped, 66 excluded with
reasons, 0 unresolved; objects/ and docs/ dispositioned via `!area` lines.
New test files: tests_realtime_integration.rs (13 live-sandbox tests),
tests_proxy_realtime.rs (28 uts-proxy fault tests). Full serial suite:
1342 passed / 0 failed / 41 ignored.

SDK bugs found and fixed by the new tests:
- RTL15b: SYNC frames wrongly updated the channel serial with the sync cursor,
  which the server then rejected on reattach ("Unable to parse channel params").
- RTN15h1: token error + non-renewable token now fails with 40171 (was a
  pass-through 40142), the server error preserved as `cause` (TI1). The
  unit-spec/proxy-spec conflict on this is recorded in TASK-9 (item 6).
Test-infra fixes: proxy daemon spawns with null stdio (was holding test pipes
open), randomized proxy port base + session-create retry (orphaned sessions
from panicked tests held fixed ports), await_state cannot observe fast
transients (watch coalescing) — broadcast recorder used instead.

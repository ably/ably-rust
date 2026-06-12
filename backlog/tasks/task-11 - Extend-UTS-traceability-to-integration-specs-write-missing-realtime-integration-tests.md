---
id: TASK-11
title: >-
  Extend UTS traceability to integration specs; write missing
  realtime-integration tests
status: To Do
assignee: []
created_date: '2026-06-12 13:47'
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
- [ ] #1 Matrix covers rest/integration and realtime/integration; objects/ recorded as out-of-scope with reason
- [ ] #2 Every realtime/integration ID mapped to a green test or excluded with a recorded-deferral reason
- [ ] #3 Both ratchets green; serial integration + proxy runs green
<!-- AC:END -->

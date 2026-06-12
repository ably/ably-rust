---
id: TASK-13
title: >-
  Systematic logging pass: level policy, loop instrumentation, no silent
  discards
status: To Do
assignee: []
created_date: '2026-06-12 13:47'
labels:
  - feature
  - observability
dependencies: []
priority: high
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The library has the machinery (5 levels, handler, gating) but only 6 call sites, all REST-skewed. Missing: Micro trace at public API entries; Minor for protocol events (resume outcome, retry scheduling, ACK routing anomalies); Major for connection/channel state transitions and material events; Error for every silent-discard path — most importantly an inbound frame failing even the tolerant msgpack decode currently VANISHES (a real server bug was found exactly there), likewise undecodable message/presence entries and ACKs for unknown serials. Deliver: (1) a documented level policy in DESIGN.md, (2) instrumentation across the loop and handles per that policy, (3) optional integration with the tracing crate (feature flag) and/or a default Error-level stderr sink so errors are visible without a configured handler, (4) tests asserting the discard paths log.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Documented logging policy in DESIGN.md
- [ ] #2 No silent-discard path remains (each logs at Error/Major with enough context to diagnose)
- [ ] #3 Connection + channel state transitions logged; API entries traced at Micro
- [ ] #4 Optional tracing-crate bridge behind a feature flag
<!-- AC:END -->

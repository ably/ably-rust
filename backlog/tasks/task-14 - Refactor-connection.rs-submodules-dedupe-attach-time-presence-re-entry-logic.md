---
id: TASK-14
title: >-
  Refactor connection.rs: submodules + dedupe attach-time presence/re-entry
  logic
status: To Do
assignee: []
created_date: '2026-06-12 13:47'
labels:
  - maintenance
  - refactor
dependencies: []
priority: medium
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
connection.rs is 3,046 lines (handle_command 301, handle_attached 158, handle_timers 156). Split into submodules (loop core / channel arm / publish-ACK arm / presence arm) with ZERO change to the ownership model — the conformance ratchet must keep scanning all of them at allowance 0. Extract the duplicated RTP17i re-entry block and HAS_PRESENCE attach handling (each pasted twice in handle_attached) into helpers. Fold in: replace the per-op spawned oneshot-bridge tasks for presence/annotation ops with a reply enum on PendingPublish; replace raw numeric error codes (91004, 91005) with ErrorCode variants.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 No behavior change: full suite green before and after, both ratchets green
- [ ] #2 tests_design_conformance.rs updated to scan the new submodule files at allowance 0
- [ ] #3 RTP17i/HAS_PRESENCE logic exists exactly once
<!-- AC:END -->

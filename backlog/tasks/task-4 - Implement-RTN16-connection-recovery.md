---
id: TASK-4
title: Implement RTN16 connection recovery
status: To Do
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - feature
  - realtime
dependencies: []
priority: high
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
recover= lets a NEW client instance resume a previous instance's connection from a serialized recovery key. Needs: recovery-key serialization (connection key + msgSerial + channel serials), Connection::recovery_key() snapshot accessor, ClientOptions::recover, connect-time recover= URL param with failure modes (80008 family). Self-contained mini-stage: derive tests from uts/realtime/unit/connection/connection_recovery_test.md (6 IDs) + RTC1c, run the §12 sweep, convert the 8 matrix exclusions.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All 6 connection_recovery_test.md IDs + RTC1c mapped to green UTS-derived tests
- [ ] #2 Live sandbox recovery proof test
- [ ] #3 Lock-inventory ratchet unchanged
<!-- AC:END -->

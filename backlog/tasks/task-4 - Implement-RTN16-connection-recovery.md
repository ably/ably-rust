---
id: TASK-4
title: Implement RTN16 connection recovery
status: Done
assignee: []
created_date: '2026-06-12 13:23'
updated_date: '2026-07-14 06:05'
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
- [x] #1 All 6 connection_recovery_test.md IDs + RTC1c mapped to green UTS-derived tests
- [x] #2 Live sandbox recovery proof test
- [x] #3 Lock-inventory ratchet unchanged
<!-- AC:END -->

## Outcome

Implemented entirely inside the loop-owned state model — zero new locks.
- `ClientOptions::recover(key)`; a malformed key logs an error and connects
  fresh (RTN16f1).
- `Connection::create_recovery_key()` (async, loop-command snapshot): JSON of
  connectionKey + msgSerial + attached channels' serials, ably-js format;
  None in CLOSING/CLOSED/FAILED/SUSPENDED or pre-connect (RTN16g/g1/g2).
- Loop: recover param on the first attempt only (RTN16k, consumed at
  start_connect, mutually exclusive with resume); msgSerial seeded (RTN16f)
  and kept on a clean recovery CONNECTED / reset on failure (RTN15c7);
  channel serials seed ChannelCtx at EnsureChannel so the first ATTACH
  carries them (RTN16j/RTL4c1).
- Tests: 6 UTS unit IDs + RTC1c mapped; 2 uts-proxy tests (RTN16d preserved
  connectionId + rotated key against the REAL sandbox; RTN16l failure →
  fresh id + 80008, still CONNECTED); rtn16_live_recovery_proof drops a
  client without protocol CLOSE and proves the new instance keeps the
  connectionId and continues msgSerial 1→2. The 8 stale ignored stubs were
  deleted. Matrix: all 9 recovery IDs mapped, 0 unresolved.
  Suite: 1363 / 0 / 30.
